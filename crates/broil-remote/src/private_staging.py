# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Fixed Ubuntu staging helper. Private bytes never become diagnostics."""
import fcntl
import hashlib
import json
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import time

MAGIC = b"BROIL-EXEC-STAGING-K3S-2\n"
BODY = "launcher.broil-script-body"
SIDECAR = "launcher.broil-sudo-frame"
MARKER = "marker"
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW
LIMIT = 1048576
BODY_LIMIT = 262144


def require(condition):
    if not condition:
        raise ValueError()


def identity(fd):
    st = os.fstat(fd)
    return [st.st_dev, st.st_ino]


def directory(parent, name, uid, private=False, create=False):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
    fd = os.open(name, DIRECTORY, dir_fd=parent)
    st = os.fstat(fd)
    require(stat.S_ISDIR(st.st_mode))
    if private:
        require(st.st_uid == uid and stat.S_IMODE(st.st_mode) == 0o700)
    else:
        require(st.st_uid in (0, uid) and not st.st_mode & 0o022)
    return fd


def base(account, elevated=False, create=False):
    require(re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", account) is not None)
    user = pwd.getpwnam(account)
    require((account == "root") == (user.pw_uid == 0))
    home = "/root" if account == "root" else "/home/" + account
    require(user.pw_dir == home)
    if elevated and user.pw_uid != 0:
        require(os.getuid() == 0 and os.geteuid() == 0)
        require(os.environ.get("SUDO_UID") == str(user.pw_uid))
        require(os.environ.get("SUDO_USER") == account)
    else:
        require(os.getuid() == user.pw_uid and os.geteuid() == user.pw_uid)
    current = os.open("/", DIRECTORY)
    st = os.fstat(current)
    require(st.st_uid == 0 and not st.st_mode & 0o022)
    for part in home.strip("/").split("/"):
        nxt = directory(current, part, user.pw_uid)
        os.close(current)
        current = nxt
    for part in (".broil", "tmp", "exec"):
        nxt = directory(current, part, user.pw_uid, private=True, create=create)
        os.close(current)
        current = nxt
    return current, user.pw_uid, home


def file_at(parent, name, uid, mode=0o600, create=False, writable=False):
    flags = (os.O_RDWR if create or writable else os.O_RDONLY) | NOFOLLOW
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(name, flags, 0o600, dir_fd=parent)
    st = os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
    require(st.st_uid == uid and stat.S_IMODE(st.st_mode) == mode)
    return fd


def write_all(fd, data):
    offset = 0
    while offset < len(data):
        n = os.write(fd, data[offset:])
        require(n > 0)
        offset += n


def write_marker(fd, record):
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    require(len(raw) <= 4096)
    os.lseek(fd, 0, os.SEEK_SET)
    write_all(fd, raw)
    os.ftruncate(fd, len(raw))


def digest(fd, length):
    require(os.fstat(fd).st_size == length)
    os.lseek(fd, 0, os.SEEK_SET)
    hashed = hashlib.sha256()
    remaining = length
    while remaining:
        data = os.read(fd, min(remaining, 65536))
        require(data)
        hashed.update(data)
        remaining -= len(data)
    require(os.read(fd, 1) == b"" and os.fstat(fd).st_size == length)
    os.lseek(fd, 0, os.SEEK_SET)
    return hashed.hexdigest()


def receive():
    stream = sys.stdin.buffer
    lines = []
    used = 0
    for _ in range(8):
        line = stream.readline(257 - used)
        used += len(line)
        require(used <= 256 and line.endswith(b"\n"))
        lines.append(line)
    require(lines[0] == MAGIC and lines[7] == b"END\n")
    account = lines[1][:-1].decode("ascii")
    nonce = lines[2][:-1].decode("ascii")
    require(re.fullmatch(r"[0-9a-f]{32}", nonce) is not None)
    require(lines[4] in (b"0\n", b"1\n"))
    numbers = []
    for line in (lines[3], lines[5], lines[6]):
        require(re.fullmatch(rb"(?:0|[1-9][0-9]*)\n", line) is not None)
        numbers.append(int(line))
    launcher_len, body_len, sidecar_len = numbers
    require(0 < launcher_len <= 65536 and body_len <= BODY_LIMIT)
    require(lines[4] == b"1\n" or body_len == 0)
    require(sidecar_len in (0, 44) and used + sum(numbers) <= LIMIT)
    parent, uid, home = base(account, create=True)
    name = "k3s." + nonce
    os.mkdir(name, 0o700, dir_fd=parent)  # A collision is never adopted.
    generation = directory(parent, name, uid, private=True)
    record = {"nonce": nonce, "directory": identity(generation),
              "state": "prepared", "files": {}, "sidecar_consumed": False}
    names = [("launcher", launcher_len)]
    if lines[4] == b"1\n":
        names.append((BODY, body_len))
    if sidecar_len:
        names.append((SIDECAR, sidecar_len))
    for filename, length in names:
        fd = file_at(generation, filename, uid, create=True)
        record["files"][filename] = identity(fd) + [length, 0o600, None]
        remaining = length
        while remaining:
            data = stream.read(min(remaining, 65536))
            require(data)
            write_all(fd, data)
            remaining -= len(data)
        if filename != SIDECAR:
            record["files"][filename][4] = digest(fd, length)
        os.close(fd)
    require(stream.read(1) == b"")
    marker = file_at(generation, MARKER, uid, create=True)
    record["marker"] = identity(marker)
    write_marker(marker, record)
    sys.stdout.buffer.write((home + "/.broil/tmp/exec/" + name + "/launcher\n").encode())
    sys.stdout.buffer.flush()


def admitted(account, nonce, elevated=False):
    require(re.fullmatch(r"[0-9a-f]{32}", nonce) is not None)
    parent, uid, _ = base(account, elevated=elevated)
    generation = directory(parent, "k3s." + nonce, uid, private=True)
    marker = file_at(generation, MARKER, uid, writable=True)
    fcntl.flock(marker, fcntl.LOCK_EX | fcntl.LOCK_NB)
    raw = os.read(marker, 4097)
    require(len(raw) <= 4096)
    record = json.loads(raw)
    require(record["nonce"] == nonce and record["directory"] == identity(generation))
    require(record["marker"] == identity(marker))
    expected = set(record["files"]) | {MARKER}
    if record["sidecar_consumed"]:
        expected.remove(SIDECAR)
    require(set(os.listdir(generation)) == expected)
    handles = {}
    for name, bound in record["files"].items():
        require(name in ("launcher", BODY, SIDECAR))
        require(type(bound[2]) is int and 0 <= bound[2] <= (BODY_LIMIT if name == BODY else 65536))
        if name == SIDECAR:
            require(bound[2] == 44)
        if name == SIDECAR and record["sidecar_consumed"]:
            continue
        fd = file_at(generation, name, uid, mode=bound[3])
        require(identity(fd) == bound[:2] and os.fstat(fd).st_size == bound[2])
        if name != SIDECAR:
            require(digest(fd, bound[2]) == bound[4])
        handles[name] = fd
    require("launcher" in handles)
    return parent, generation, marker, record, handles


def arm(account, nonce, executable):
    _, _, marker, record, handles = admitted(account, nonce)
    require(record["state"] == "prepared")
    for name in ("launcher", BODY) if executable else ("launcher",):
        require(name in handles)
        os.fchmod(handles[name], 0o700)
        record["files"][name][3] = 0o700
    record["state"] = "ready"
    write_marker(marker, record)


def group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def use(account, nonce, milliseconds, public=False):
    # The public relay mode runs as the canonical account itself: no sudo,
    # no sidecar and no root requirement.
    _, generation, marker, record, handles = admitted(account, nonce, elevated=not public)
    require(record["state"] == "ready" and BODY in handles)
    require(0 < milliseconds <= 7200000)
    record["state"] = "running"
    write_marker(marker, record)
    home = "/root"
    if public:
        require(SIDECAR not in handles and os.geteuid() == pwd.getpwnam(account).pw_uid)
        home = pwd.getpwnam(account).pw_dir
    elif SIDECAR in handles:
        require(account != "root" and os.geteuid() == 0)
        sidecar = handles[SIDECAR]
        frame = os.read(sidecar, 45)
        require(re.fullmatch(rb"BROIL-SUDO:[0-9a-fA-F]{32}\n", frame) is not None)
        os.unlink(SIDECAR, dir_fd=generation)
        require(os.fstat(sidecar).st_nlink == 0)
        record["sidecar_consumed"] = True
        write_marker(marker, record)
        sys.stderr.buffer.write(frame)
        sys.stderr.buffer.flush()
    else:
        require(account == "root")
    # The original generated launcher retains interpreter, environment and cwd
    # behavior. Its only pathname substitution is the already verified body fd.
    launcher = os.read(handles["launcher"], 65537)
    require(len(launcher) <= 65536)
    original = b"broil_body=$0.broil-script-body\n"
    require(launcher.count(original) == 1)
    body_fd = handles[BODY]
    launcher = launcher.replace(original, ("broil_body=/proc/self/fd/%d\n" % body_fd).encode(), 1)
    child = subprocess.Popen(["/bin/sh", "-c", launcher], pass_fds=(body_fd,), start_new_session=True,
                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": home, "LANG": "C.UTF-8"})
    stopped = False

    def terminate(_signum, _frame):
        nonlocal stopped
        stopped = True
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGHUP, terminate)
    until = time.monotonic() + milliseconds / 1000
    while child.poll() is None and not stopped and time.monotonic() < until:
        time.sleep(0.01)
    if child.poll() is None:
        terminate(0, None)
        try:
            child.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=0.5)
    # Parent exit alone never proves that descendants released their inputs.
    require(not group_exists(child.pid))
    record["state"] = "settled"
    write_marker(marker, record)
    return 124 if stopped else (child.returncode if child.returncode >= 0 else 128 - child.returncode)


def cleanup(account, nonce):
    parent, generation, marker, record, handles = admitted(account, nonce)
    require(record["state"] in ("prepared", "ready", "settled"))
    # All identities are admitted before any unlink. No recursive cleanup or
    # path-based reclamation is permitted, including on a partial creation.
    for name, fd in handles.items():
        require(identity(fd) == record["files"][name][:2])
        os.unlink(name, dir_fd=generation)
        require(os.fstat(fd).st_nlink == 0)
    os.unlink(MARKER, dir_fd=generation)
    require(os.fstat(marker).st_nlink == 0)
    require(identity(generation) == record["directory"])
    st = os.stat("k3s." + nonce, dir_fd=parent, follow_symlinks=False)
    require([st.st_dev, st.st_ino] == record["directory"])
    os.rmdir("k3s." + nonce, dir_fd=parent)


try:
    os.umask(0o077)
    args = sys.argv[1:]
    if args == ["receive"]:
        receive()
    elif len(args) == 4 and args[0] == "arm" and args[3] in ("0", "1"):
        arm(args[1], args[2], args[3] == "1")
    elif len(args) == 4 and args[0] in ("use", "use-public"):
        sys.exit(use(args[1], args[2], int(args[3]), args[0] == "use-public"))
    elif len(args) == 3 and args[0] == "cleanup":
        cleanup(args[1], args[2])
    else:
        raise ValueError()
except Exception:
    # Exceptions may refer to private input; only the fixed exit code escapes.
    os._exit(125)
