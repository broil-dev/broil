#!/usr/bin/env python3
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Configured Broil builder adapter, protocol 1, Ubuntu 24.04/systemd.

This process and the daemon are external private-material consumers. Installed
keys persist for the service. Unlink does not claim memory or device erasure.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import stat
import struct
import subprocess
import sys
import tarfile

ARCHIVE_SHA = 'af8064eca16077b4d6937745988ba2d2dfa439540874cdcd918318315f3ba1d3'
ARCHIVE_SIZE = 87319229
MEMBERS = {
    'bin/buildkitd': (66476450, 'b154375ba70ec98fdfc7c08c9576226c88f3802638900ff5742de0b1668c9fcb'),
    'bin/buildkit-runc': (17272544, '93fd94638b47008278ac31cf81c0a60b2d995acd3e42685478f16e66f4ddb0d3'),
    'bin/buildkit-qemu-aarch64': (11337400, 'cbf6308eb61214bd5df71520b8801fa19a9f0c810fb2a5adb084483da3aa8911'),
}
KEYS = {'protocol', 'action', 'owner', 'operation', 'step', 'scope', 'endpoint', 'account',
        'payload_length', 'generation', 'previous_generation', 'purge', 'arm64_emulation',
        'expected', 'unit', 'manifest', 'ca_sha256', 'upload'}
ACTIONS = {'inspect', 'prepare', 'install', 'certificate', 'key', 'activate', 'reconcile', 'remove'}
OFLAGS = os.O_NOFOLLOW | os.O_CLOEXEC
CONSUMED = b'\nconsumed-v1\n'
SFTP = '/usr/lib/openssh/sftp-server'
PROGRESS_KEYS = {'operation', 'step', 'pending', 'state', 'resources', 'generation',
                 'unit_digest', 'same', 'upload', 'inputs', 'history', 'arm64_emulation', 'intent', 'prior_intents'}


class Refusal(Exception):
    def __init__(self, state='conflict'):
        self.state = state


def require(value, state='conflict'):
    if not value:
        raise Refusal(state)


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result)
        result[key] = value
    return result


def depth(value, level=1):
    require(level <= 16)
    if isinstance(value, dict):
        require(len(value) <= 64)
        for child in value.values():
            depth(child, level + 1)
    elif isinstance(value, list):
        require(len(value) <= 128)
        for child in value:
            depth(child, level + 1)


def parse(data):
    require(len(data) <= 65536)
    value = json.loads(data, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(Refusal()))
    depth(value)
    return value


def read_exact(length):
    require(0 <= length <= 1048576)
    result = bytearray(length)
    pos = 0
    while pos < length:
        count = sys.stdin.buffer.readinto(memoryview(result)[pos:])
        require(count, 'uncertain')
        pos += count
    return result


def hexadecimal(value, length):
    return isinstance(value, str) and len(value) == length and all(c in '0123456789abcdef' for c in value)


def metadata(path):
    try:
        m = os.lstat(path)
    except FileNotFoundError:
        return None
    require(stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode))
    return {'device': m.st_dev, 'inode': m.st_ino, 'mode': m.st_mode,
            'uid': m.st_uid, 'size': m.st_size}


def same(path, expected):
    current = metadata(path)
    require(current is not None and expected is not None)
    require(set(expected) == {'device', 'inode', 'mode', 'uid', 'size'})
    require(all(current[k] == expected[k] for k in ('device', 'inode', 'mode', 'uid')))
    return current


def secure_read(path, limit=65536):
    fd = os.open(path, os.O_RDONLY | OFLAGS)
    with os.fdopen(fd, 'rb') as stream:
        m = os.fstat(stream.fileno())
        require(stat.S_ISREG(m.st_mode) and m.st_size <= limit)
        value = stream.read(limit + 1)
        require(len(value) <= limit)
        return value


def digest(path, size):
    fd = os.open(path, os.O_RDONLY | OFLAGS)
    with os.fdopen(fd, 'rb') as stream:
        m = os.fstat(stream.fileno())
        require(stat.S_ISREG(m.st_mode) and m.st_size == size)
        value = hashlib.sha256()
        count = 0
        while chunk := stream.read(65536):
            count += len(chunk)
            require(count <= size)
            value.update(chunk)
        require(count == size)
        return value.hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | OFLAGS)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def public_file(path, value, exclusive=False):
    depth(value)
    data = json.dumps(value, separators=(',', ':'), sort_keys=True).encode()
    require(len(data) <= 65536)
    destination = path if exclusive else path.with_name(path.name + '.pending')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | OFLAGS, 0o644)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o644)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    if not exclusive:
        os.replace(destination, path)
    sync_directory(path.parent)


def prerequisites():
    require(os.geteuid() == 0)
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu' and release.get('VERSION_ID', '').strip('"') == '24.04')
    require(platform.machine() == 'x86_64' and Path('/run/systemd/system').is_dir())
    require(shutil.which('systemctl') is not None)
    require(os.path.isfile(SFTP) and os.access(SFTP, os.X_OK), 'prerequisite')


def file_identity(value):
    return {'device': value.st_dev, 'inode': value.st_ino, 'mode': value.st_mode,
            'uid': value.st_uid, 'gid': value.st_gid, 'links': value.st_nlink}


def checked_file(path, expected, flags=os.O_RDONLY):
    fd = os.open(path, flags | OFLAGS)
    try:
        opened = file_identity(os.fstat(fd))
        require(opened == expected and file_identity(os.lstat(path)) == expected)
        require(stat.S_ISREG(opened['mode']) and opened['links'] == 1)
        return fd
    except BaseException:
        os.close(fd)
        raise


def public_record(path):
    fd = os.open(path, os.O_RDONLY | OFLAGS)
    with os.fdopen(fd, 'rb') as stream:
        m = os.fstat(stream.fileno())
        require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_nlink == 1)
        require(stat.S_IMODE(m.st_mode) == 0o644 and m.st_size <= 65536)
        value = parse(stream.read(65537))
        require(file_identity(os.lstat(path)) == file_identity(m))
        return value


def public_parent(root):
    for path in [*reversed(root.parents), root]:
        m = os.lstat(path)
        require(stat.S_ISDIR(m.st_mode) and m.st_uid == 0 and m.st_mode & 0o022 == 0)
        require(m.st_mode & 0o001 != 0)


def upload_body(binding):
    value = json.dumps(binding, separators=(',', ':'), sort_keys=True).encode()
    require(len(value) + len(CONSUMED) <= 65536)
    return value


def public_sftp(argv):
    """Consume one root-authorized public reservation, then become its writer."""
    require(len(argv) == 11 and sum(len(a.encode()) + 1 for a in argv) <= 65536)
    owner, operation, step, scope, device, inode, purpose, temporary, final, size, sha = argv
    require(hexadecimal(owner, 32) and hexadecimal(operation, 32) and hexadecimal(scope, 64))
    require(purpose in ('archive', 'ca') and temporary == 'upload.tmp' and final == purpose)
    require(hexadecimal(sha, 64))
    for number in (step, device, inode, size):
        require(number.isascii() and number.isdecimal() and len(number) <= 20 and str(int(number)) == number)
    step, device, inode, size = map(int, (step, device, inode, size))
    require(0 < step < 2**64 and device < 2**64 and 0 < inode < 2**64 and 0 < size <= 268435456)
    root = Path('/var/lib/broil/builders') / owner
    public_parent(root)
    ownership = public_record(root / 'owner.json')
    require(set(ownership) == {'protocol', 'owner', 'scope', 'root', 'lock', 'account', 'uid', 'gid'})
    require(ownership['protocol'] == 1 and ownership['owner'] == owner and ownership['scope'] == scope)
    require(ownership['uid'] == os.geteuid() and ownership['gid'] == os.getegid())
    same(root, ownership['root'])
    lock = checked_file(root / 'mutation.lock', ownership['lock'], os.O_RDWR)
    try:
        require(ownership['lock']['uid'] == os.geteuid() and ownership['lock']['gid'] == os.getegid())
        require(stat.S_IMODE(ownership['lock']['mode']) == 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('busy') from None
        require(public_record(root / 'owner.json') == ownership)
        progress = public_record(root / 'progress.json')
        require(set(progress) == PROGRESS_KEYS)
        require(progress['pending'] is True and progress['operation'] == operation and progress['step'] == step)
        reservation = progress['upload']
        require(set(reservation) == {'binding', 'claim', 'identity', 'length', 'sha256'})
        binding = reservation['binding']
        container = root / 'incoming' / str(step)
        public_parent(container.parent)
        current = file_identity(os.lstat(container))
        require(stat.S_ISDIR(current['mode']) and stat.S_IMODE(current['mode']) == 0o700)
        require(current['uid'] == os.geteuid() and current['gid'] == os.getegid())
        expected = {'protocol': 1, 'owner': owner, 'operation': operation, 'step': step, 'scope': scope,
                    'container': current, 'purpose': purpose, 'temporary': temporary, 'final': final,
                    'size': size, 'sha256': sha}
        require(current['device'] == device and current['inode'] == inode and binding == expected)
        body = upload_body(expected)
        require(reservation['claim'] == f'claim-{step}.json' and reservation['length'] == len(body))
        require(reservation['sha256'] == hashlib.sha256(body).hexdigest())
        identity = reservation['identity']
        require(identity['uid'] == os.geteuid() and identity['gid'] == os.getegid())
        require(stat.S_IMODE(identity['mode']) == 0o600)
        claim_path = root / reservation['claim']
        parent_fd = os.open(root, os.O_PATH | os.O_DIRECTORY | OFLAGS)
        try:
            fd = os.open(reservation['claim'], os.O_RDWR | os.O_APPEND | OFLAGS, dir_fd=parent_fd)
            try:
                require(file_identity(os.fstat(fd)) == identity and file_identity(os.lstat(claim_path)) == identity)
                require(stat.S_ISREG(identity['mode']) and identity['links'] == 1)
                require(os.fstat(fd).st_size == len(body) and os.pread(fd, 65537, 0) == body)
                require(os.path.isfile(SFTP) and os.access(SFTP, os.X_OK), 'prerequisite')
                require(os.write(fd, CONSUMED) == len(CONSUMED), 'uncertain')
                os.fsync(fd)
                require(os.pread(fd, 65537, 0) == body + CONSUMED, 'uncertain')
                require(file_identity(os.fstat(fd)) == identity and file_identity(os.lstat(claim_path)) == identity)
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
        require(file_identity(os.lstat(root / 'mutation.lock')) == ownership['lock'])
        os.set_inheritable(lock, True)
        os.execv(SFTP, ['sftp-server'])
    finally:
        os.close(lock)


class Adapter:
    def __init__(self, request):
        self.r = request
        self.root = Path('/var/lib/broil/builders') / request['owner']
        self.unit = Path('/etc/systemd/system') / ('broil-builder-' + request['owner'] + '.service')
        self.name = self.unit.name
        self.progress = None
        self.owner = None
        self.lock = None
        self.lock_identity = None
        self.state = 'missing'
        self.resumed = False
        self.parts = ['absent', 'absent', 'absent']

    def path(self, name):
        if name == 'root':
            return self.root
        if name == 'unit':
            return self.unit
        require(name not in ('', '.', '..') and not name.startswith('/') and '..' not in name.split('/'))
        result = self.root / name
        for parent in result.parents:
            if parent == self.root.parent:
                break
            m = metadata(parent)
            require(m is not None and stat.S_ISDIR(m['mode']))
            if m['uid'] != 0:
                relative = str(parent.relative_to(self.root))
                require(relative.startswith('incoming/') and relative.count('/') == 1)
                require(self.progress is not None and m['uid'] == self.owner['uid'])
                same(parent, self.progress['resources'].get(relative))
        return result

    def check(self):
        require(self.owner is not None and self.lock is not None)
        same(self.root, self.owner['root'])
        same(self.root / 'mutation.lock', self.lock_identity)
        require(parse(secure_read(self.root / 'owner.json')) == self.owner)

    def load(self):
        root = metadata(self.root)
        if root is None:
            require(metadata(self.unit) is None)
            return False
        require(stat.S_ISDIR(root['mode']) and root['uid'] == 0 and stat.S_IMODE(root['mode']) == 0o711)
        public_parent(self.root)
        self.owner = public_record(self.root / 'owner.json')
        require(set(self.owner) == {'protocol', 'owner', 'scope', 'root', 'lock', 'account', 'uid', 'gid'})
        require(self.owner['protocol'] == 1 and self.owner['owner'] == self.r['owner'] and self.owner['scope'] == self.r['scope'])
        account = pwd.getpwnam(self.r['account'])
        require(self.owner['account'] == self.r['account'] and self.owner['uid'] == account.pw_uid and self.owner['gid'] == account.pw_gid)
        same(self.root, self.owner['root'])
        self.lock = checked_file(self.root / 'mutation.lock', self.owner['lock'], os.O_RDWR)
        self.lock_identity = metadata(self.root / 'mutation.lock')
        require(self.lock_identity['uid'] == account.pw_uid and self.owner['lock']['gid'] == account.pw_gid)
        require(stat.S_IMODE(self.lock_identity['mode']) == 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refusal('busy') from None
        self.progress = public_record(self.root / 'progress.json')
        require(set(self.progress) == PROGRESS_KEYS)
        self.state = self.progress['state']
        self.check()
        return True

    def save(self):
        self.check()
        public_file(self.root / 'progress.json', self.progress)

    def remember(self, name):
        self.check()
        self.progress['resources'][name] = metadata(self.path(name))
        self.save()

    def directory(self, name, mode=0o700, uid=0):
        self.check()
        path = self.path(name)
        if path.exists():
            same(path, self.progress['resources'].get(name))
        else:
            os.mkdir(path, mode)
            os.chown(path, uid, -1, follow_symlinks=False)
            sync_directory(path.parent)
            self.remember(name)
        return path

    def create(self):
        for parent in [Path('/var/lib/broil'), Path('/var/lib/broil/builders')]:
            try:
                os.mkdir(parent, 0o755)
            except FileExistsError:
                pass
            m = metadata(parent)
            require(m is not None and m['uid'] == 0 and stat.S_ISDIR(m['mode']) and m['mode'] & 0o022 == 0)
        os.mkdir(self.root, 0o711)
        self.lock = os.open(self.root / 'mutation.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | OFLAGS, 0o600)
        account = pwd.getpwnam(self.r['account'])
        os.fchown(self.lock, account.pw_uid, account.pw_gid)
        os.fchmod(self.lock, 0o600)
        os.fsync(self.lock)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.lock_identity = metadata(self.root / 'mutation.lock')
        self.owner = {'protocol': 1, 'owner': self.r['owner'], 'scope': self.r['scope'], 'root': metadata(self.root),
                      'lock': file_identity(os.fstat(self.lock)), 'account': self.r['account'], 'uid': account.pw_uid, 'gid': account.pw_gid}
        public_file(self.root / 'owner.json', self.owner, exclusive=True)
        self.progress = {'operation': self.r['operation'], 'step': 0, 'pending': True, 'state': 'prepared',
                         'resources': {}, 'generation': '', 'unit_digest': '', 'same': {}, 'upload': None, 'inputs': {}, 'history': [], 'arm64_emulation': False,
                         'intent': None, 'prior_intents': []}
        public_file(self.root / 'progress.json', self.progress, exclusive=True)
        sync_directory(self.root.parent)

    def begin(self):
        self.check()
        p = self.progress
        if p['pending'] and p['operation'] != self.r['operation']:
            raise Refusal('busy')
        require(self.r['step'] > p['step'])
        require(p['upload'] is None or self.r['action'] == 'reconcile', 'busy')
        if self.r['action'] == 'reconcile' and p['pending'] and p['intent'] is not None:
            require(len(p['prior_intents']) < 32)
            p['prior_intents'].append({'operation': p['operation'], 'step': p['step'], 'intent': p['intent'],
                                       'state_before': p['state'], 'followup_step': self.r['step']})
        p['operation'] = self.r['operation']
        p['step'] = self.r['step']
        p['pending'] = True
        p['intent'] = {'action': self.r['action'], 'purge': self.r['purge']}
        self.save()

    def systemctl(self, *args):
        self.check()
        same(self.unit, self.progress['resources'].get('unit'))
        require(hashlib.sha256(secure_read(self.unit)).hexdigest() == self.progress['unit_digest'])
        result = subprocess.run(['systemctl', *args, self.name], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        return result.returncode, result.stdout

    def inspect(self):
        self.check()
        p = self.progress
        for name, expected in list(p['resources'].items()):
            path = self.path(name)
            if name == 'state':
                same(path, expected)
            elif metadata(path) is None and self.r['action'] == 'reconcile':
                if p['pending'] and p['intent'] is not None and p['intent']['action'] == 'remove':
                    del p['resources'][name]
                continue
            else:
                same(path, expected)
        service = metadata(self.unit)
        if service is not None:
            require('unit' in p['resources'])
            code, output = self.systemctl('is-active')
            self.parts[0] = 'present'
            if code == 0 and output.strip() == b'active':
                self.state = 'ready'
            elif self.state == 'ready':
                self.state = 'installed'
        else:
            require('unit' not in p['resources'])
            if self.state == 'ready':
                self.state = 'installed' if 'bin/buildkitd' in p['resources'] else 'retained'
        self.parts[1] = 'present' if p['generation'] else 'absent'
        self.parts[2] = 'retained' if (self.root / 'state').exists() else 'absent'

    def prepare(self):
        for name in ('bin', 'state', 'tls'):
            self.directory(name)
        self.directory('incoming', mode=0o711)
        if self.r['upload'] is not None:
            self.prepare_upload()
        else:
            self.progress['same'] = {}
        self.state = 'prepared'

    def prepare_upload(self):
        p, r = self.progress, self.r
        require(p['upload'] is None and len(p['history']) < 32)
        upload = r['upload']
        require(set(upload) == {'purpose', 'size', 'sha256', 'temporary', 'final'})
        purpose = upload['purpose']
        require(purpose in ('archive', 'ca') and upload['temporary'] == 'upload.tmp' and upload['final'] == purpose)
        require(type(upload['size']) is int and 0 < upload['size'] <= 268435456 and hexadecimal(upload['sha256'], 64))
        if purpose == 'archive':
            require(upload['size'] == ARCHIVE_SIZE and upload['sha256'] == ARCHIVE_SHA)
        else:
            require(upload['size'] <= 1048576 and upload['sha256'] == r['ca_sha256'])
        relative = 'incoming/' + str(r['step'])
        container = self.path(relative)
        os.mkdir(container, 0o700)
        os.chown(container, self.owner['uid'], self.owner['gid'], follow_symlinks=False)
        sync_directory(container.parent)
        self.remember(relative)
        binding = {'protocol': 1, 'owner': r['owner'], 'operation': r['operation'], 'step': r['step'], 'scope': r['scope'],
                   'container': file_identity(os.lstat(container)), **upload}
        body = upload_body(binding)
        name = f"claim-{r['step']}.json"
        fd = os.open(self.root / name, os.O_RDWR | os.O_CREAT | os.O_EXCL | OFLAGS, 0o600)
        with os.fdopen(fd, 'wb') as output:
            os.fchown(output.fileno(), self.owner['uid'], self.owner['gid'])
            os.fchmod(output.fileno(), 0o600)
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
            identity = file_identity(os.fstat(output.fileno()))
        sync_directory(self.root)
        p['upload'] = {'binding': binding, 'claim': name, 'identity': identity,
                       'length': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        self.remember(name)
        self.save()

    def install(self):
        self.check()
        require(set(self.progress['inputs']) == {'archive', 'ca'})
        archive = self.path(self.progress['inputs']['archive'])
        ca = self.path(self.progress['inputs']['ca'])
        same(archive, self.progress['resources'].get(self.progress['inputs']['archive']))
        same(ca, self.progress['resources'].get(self.progress['inputs']['ca']))
        require(digest(archive, ARCHIVE_SIZE) == ARCHIVE_SHA)
        ca_bytes = secure_read(ca, 1048576)
        require(hashlib.sha256(ca_bytes).hexdigest() == self.r['ca_sha256'])
        selected = dict(MEMBERS)
        if not self.r['arm64_emulation']:
            selected.pop('bin/buildkit-qemu-aarch64')
        names = set()
        expanded = 0
        with tarfile.open(archive, 'r:gz') as source:
            for member in source:
                require(len(names) < 14 and member.name not in names)
                names.add(member.name)
                require(not member.name.startswith('/') and '..' not in member.name.split('/'))
                require(member.isfile() or member.isdir())
                expected = next((m for m in self.r['manifest']['archive_inventory'] if m['name'] == member.name), None)
                require(expected is not None and member.size == expected['size'])
                require(('directory' if member.isdir() else 'file') == expected['type'])
                if member.name not in selected:
                    continue
                size, sha = selected[member.name]
                require(member.size == size)
                expanded += size
                require(expanded <= 536870912)
                path = self.path(member.name)
                if path.exists():
                    same(path, self.progress['resources'].get(member.name))
                    require(digest(path, size) == sha)
                    continue
                self.check()
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | OFLAGS, 0o700)
                self.remember(member.name)
                with os.fdopen(fd, 'wb') as output, source.extractfile(member) as stream:
                    count = 0
                    while chunk := stream.read(65536):
                        count += len(chunk)
                        require(count <= size)
                        output.write(chunk)
                    require(count == size)
                    output.flush()
                    os.fsync(output.fileno())
                require(digest(path, size) == sha)
                self.remember(member.name)
        require(len(names) == 14 and all((self.root / name).exists() for name in selected))
        path = self.path('ca.pem')
        if path.exists():
            same(path, self.progress['resources'].get('ca.pem'))
            require(secure_read(path, 1048576) == ca_bytes)
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | OFLAGS, 0o600)
            self.remember('ca.pem')
            with os.fdopen(fd, 'wb') as output:
                output.write(ca_bytes)
                output.flush()
                os.fsync(output.fileno())
            self.remember('ca.pem')
        self.state = 'installed'

    def reconcile_upload(self):
        p = self.progress
        reservation = p['upload']
        if reservation is None:
            return
        binding = reservation['binding']
        require(binding['owner'] == self.r['owner'] and binding['scope'] == self.r['scope'])
        require(binding['operation'] == self.r['operation'] and binding['step'] < self.r['step'])
        relative = 'incoming/' + str(binding['step'])
        container = self.path(relative)
        require(file_identity(os.lstat(container)) == binding['container'])
        self.no_mounts(container)
        names = []
        with os.scandir(container) as entries:
            for entry in entries:
                require(len(names) < 2 and entry.name in (binding['temporary'], binding['final']))
                names.append(entry.name)
        observed = {}
        for name in names:
            path = container/name
            m = metadata(path)
            require(m is not None and stat.S_ISREG(m['mode']) and m['uid'] == self.owner['uid'])
            require(stat.S_IMODE(m['mode']) == 0o600 and os.lstat(path).st_nlink == 1)
            require(0 <= m['size'] <= binding['size'])
            self.no_mounts(path)
            observed[name] = m
        final = binding['final']
        complete = final in observed and binding['temporary'] not in observed
        if complete:
            require(digest(container/final, binding['size']) == binding['sha256'])
            name = relative + '/' + final
            p['resources'][name] = observed[final]
            p['inputs'][binding['purpose']] = name
        # The original prepared intent stays intact beside the later observation.
        require(len(p['history']) < 32)
        p['history'].append({'reservation': reservation, 'observed': observed,
                             'resolved_step': self.r['step'], 'complete': complete})
        for name, identity in observed.items():
            p['resources'][relative + '/' + name] = identity
        p['upload'] = None
        p['pending'] = False
        self.save()

    def scalar(self, name):
        self.check()
        generation = 'tls/' + self.r['generation']
        self.directory(generation)
        data = read_exact(self.r['payload_length'])
        require(data and sys.stdin.buffer.read(1) == b'', 'uncertain')
        old = self.progress['generation']
        equal = False
        if old:
            old_name = 'tls/' + old + '/' + name
            if metadata(self.path(old_name)) is not None:
                same(self.path(old_name), self.progress['resources'].get(old_name))
                equal = secure_read(self.path(old_name), 1048576) == data
        relative = generation + '/' + name
        path = self.path(relative)
        if path.exists():
            same(path, self.progress['resources'].get(relative))
            require(secure_read(path, 1048576) == data)
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | OFLAGS, 0o600)
            self.remember(relative)
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            self.remember(relative)
        del data
        self.progress['same'][name] = equal

    def activate(self):
        p = self.progress
        generation = self.r['generation']
        for name in ('certificate', 'key'):
            relative = 'tls/' + generation + '/' + name
            m = same(self.path(relative), p['resources'].get(relative))
            require(m['uid'] == 0 and stat.S_IMODE(m['mode']) == 0o600 and m['size'] > 0)
        unchanged = (p['generation'] and p['same'] == {'certificate': True, 'key': True}
                     and metadata(self.unit) is not None and p['arm64_emulation'] == self.r['arm64_emulation'])
        if not unchanged:
            if metadata(self.unit) is not None:
                self.systemctl('stop')
            unit = self.r['unit'].encode()
            self.check()
            if metadata(self.unit) is not None:
                same(self.unit, p['resources'].get('unit'))
            temporary = self.unit.with_name(self.unit.name + '.' + self.r['operation'])
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | OFLAGS, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(unit)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.unit)
            sync_directory(self.unit.parent)
            p['generation'] = generation
            p['arm64_emulation'] = self.r['arm64_emulation']
            p['unit_digest'] = hashlib.sha256(unit).hexdigest()
            self.remember('unit')
            subprocess.run(['systemctl', 'daemon-reload'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=15, check=True)
            require(self.systemctl('enable')[0] == 0)
        require(self.systemctl('start')[0] == 0)
        require(self.systemctl('is-active')[0] == 0)
        self.state = 'ready'
        p['pending'] = False
        for name in list(p['resources']):
            if name.startswith('tls/') and name.count('/') == 1 and name != 'tls/' + p['generation']:
                self.remove_tree(name)

    def no_mounts(self, path):
        for line in Path('/proc/self/mountinfo').read_text().splitlines():
            name = line.split()[4]
            for code, value in [('\\040', ' '), ('\\011', '\t'), ('\\012', '\n'), ('\\134', '\\')]:
                name = name.replace(code, value)
            mount = Path(name)
            require(mount != path and path not in mount.parents)

    def remove_tree(self, name):
        self.check()
        root = self.path(name)
        same(root, self.progress['resources'].get(name))
        self.no_mounts(root)
        device = os.lstat(root).st_dev
        count = 0
        for directory, dirs, files in os.walk(root, topdown=False, followlinks=False):
            require(len(Path(directory).parts) - len(root.parts) < 64)
            for child in files + dirs:
                count += 1
                require(count <= 1000000)
                path = Path(directory) / child
                m = metadata(path)
                require(m is not None and m['device'] == device)
                self.check()
                self.no_mounts(path)
                if name != 'state':
                    same(path, self.progress['resources'].get(str(path.relative_to(self.root))))
                if stat.S_ISDIR(m['mode']):
                    os.rmdir(path)
                else:
                    os.unlink(path)
        self.check()
        os.rmdir(root)
        for key in list(self.progress['resources']):
            if key == name or key.startswith(name + '/'):
                del self.progress['resources'][key]
        self.save()

    def remove(self):
        p = self.progress
        if metadata(self.unit) is not None:
            require(self.systemctl('stop')[0] == 0)
            require(self.systemctl('is-active')[0] != 0)
            require(self.systemctl('disable')[0] == 0)
            self.check()
            same(self.unit, p['resources'].get('unit'))
            os.unlink(self.unit)
            sync_directory(self.unit.parent)
            del p['resources']['unit']
            self.save()
            subprocess.run(['systemctl', 'daemon-reload'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=15, check=True)
        self.parts[0] = 'removed'
        for name in ('bin', 'tls'):
            if metadata(self.path(name)) is not None:
                self.remove_tree(name)
        if metadata(self.path('ca.pem')) is not None:
            same(self.path('ca.pem'), p['resources'].get('ca.pem'))
            os.unlink(self.path('ca.pem'))
            del p['resources']['ca.pem']
        p['generation'] = ''
        p['unit_digest'] = ''
        if metadata(self.path('incoming')) is not None:
            self.remove_tree('incoming')
        for name in list(p['resources']):
            if name.startswith('claim-') and name.endswith('.json'):
                same(self.path(name), p['resources'][name])
                os.unlink(self.path(name))
                del p['resources'][name]
        p['inputs'] = {}
        sync_directory(self.root)
        self.parts[1] = 'removed'
        self.state = 'retained'
        # Cache purge can refuse or lose its response after installation removal.
        # Persist that completed work while keeping the original intent pending.
        p['state'] = self.state
        self.save()
        if self.r['purge']:
            if metadata(self.path('state')) is not None:
                self.remove_tree('state')
            self.parts[2] = 'removed'
            self.state = 'purged'
        else:
            self.parts[2] = 'retained'
        p['pending'] = False

    def execute(self):
        exists = self.load()
        action = self.r['action']
        if not exists:
            if action == 'inspect':
                return
            require(action == 'prepare')
            self.create()
        self.inspect()
        if action == 'inspect':
            return
        self.begin()
        if action == 'prepare':
            self.prepare()
        elif action == 'install':
            self.install()
        elif action in ('certificate', 'key'):
            self.scalar(action)
        elif action == 'activate':
            self.activate()
        elif action == 'remove':
            self.remove()
        elif action == 'reconcile':
            self.reconcile_upload()
            self.resumed = True
            self.progress['pending'] = False
        self.progress['state'] = self.state
        self.save()
        if action != 'remove':
            self.inspect()

    def response(self):
        r = self.r
        result = {name: r[name] for name in ('protocol', 'action', 'owner', 'operation', 'step', 'scope', 'endpoint')}
        resources = []
        if self.owner and self.progress:
            for name in ['root', 'owner.json', *self.progress['resources']]:
                m = metadata(self.path(name))
                if m is not None:
                    resources.append(dict(name=name, **m))
        require(len(resources) <= 128)
        result.update(state=self.state, service=self.parts[0], credentials=self.parts[1], storage=self.parts[2],
                      resources=resources, generation=self.progress['generation'] if self.progress else '',
                      unit_digest=self.progress['unit_digest'] if self.progress else '', resumed=self.resumed,
                      upload=self.progress['upload'] if self.progress else None,
                      pending=self.progress['pending'] if self.progress else False,
                      inputs=self.progress['inputs'] if self.progress else {},
                      arm64_emulation=self.progress['arm64_emulation'] if self.progress else False)
        data = json.dumps(result, separators=(',', ':')).encode()
        require(len(data) <= 65536)
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def main():
    length = struct.unpack('>I', read_exact(4))[0]
    require(length <= 65536)
    r = parse(read_exact(length))
    require(set(r) == KEYS and r['protocol'] == 1 and r['action'] in ACTIONS)
    require(hexadecimal(r['owner'], 32) and hexadecimal(r['operation'], 32) and hexadecimal(r['scope'], 64))
    require(r['generation'] == r['operation'] and (not r['previous_generation'] or hexadecimal(r['previous_generation'], 32)))
    require(type(r['step']) is int and 0 < r['step'] < 2 ** 64 and type(r['payload_length']) is int and 0 <= r['payload_length'] <= 1048576)
    require(type(r['purge']) is bool and type(r['arm64_emulation']) is bool)
    require(r['manifest']['archive_sha256'] == ARCHIVE_SHA and r['manifest']['archive_size'] == ARCHIVE_SIZE)
    require(r['manifest']['version'] == '0.24.0' and r['manifest']['source_commit'] == 'b772c318368090fb2ffc9c0fed92e0a35bf82389')
    require(hexadecimal(r['ca_sha256'], 64))
    if r['action'] not in ('certificate', 'key'):
        require(r['payload_length'] == 0 and sys.stdin.buffer.read(1) == b'')
    prerequisites()
    adapter = Adapter(r)
    try:
        adapter.execute()
    except Refusal as error:
        adapter.state = error.state
    except BaseException:
        adapter.state = 'uncertain'
    adapter.response()


if __name__ == '__main__':
    try:
        if len(sys.argv) > 1 and sys.argv[1] == '--broil-builder-sftp-v1':
            public_sftp(sys.argv[2:])
        else:
            require(len(sys.argv) == 1)
            main()
    except Refusal as error:
        sys.exit({'busy': 75, 'prerequisite': 77}.get(error.state, 76))
    except BaseException:
        sys.exit(76 if len(sys.argv) > 1 else 1)
