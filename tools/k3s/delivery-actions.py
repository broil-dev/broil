#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, profile-bound K3s `delivery` body: the registry replication protocol and the
release delivery protocol."""
import base64
import calendar
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import stat
import struct
import subprocess
import sys
import tarfile
import time
from urllib.parse import quote, urlsplit
from xml.sax.saxutils import escape, quoteattr
import xml.etree.ElementTree as ET

ROOT = "/var/lib/broil/k3s"
PROFILE = ROOT + "/action-profile.json"
K3S = "/usr/local/libexec/broil-k3s"
MAXIMUM = 1048576
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
EFFECTS = False
DEADLINE = time.monotonic() + 7200
WRITERS_SETTLED = True

class Refused(Exception):
    def __init__(self, code):
        self.code = code


def require(condition, code=2):
    if not condition:
        raise Refused(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 4)
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def identity(fd):
    value = os.fstat(fd)
    return [value.st_dev, value.st_ino]


def directory(path):
    require(path.startswith("/") and "\0" not in path)
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    protected = False
    for part in Path(path).parts[1:]:
        require(part not in (".", ".."))
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=current)
        os.close(current)
        current = fd
        value = os.fstat(fd)
        require(value.st_uid == 0 and not value.st_mode & 0o022)
        protected |= not value.st_mode & 0o077
    return current, protected


def read_file(path, maximum=MAXIMUM, private=True):
    parent, protected = directory(str(Path(path).parent))
    fd = os.open(Path(path).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    try:
        value = os.fstat(fd)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1)
        require(not value.st_mode & 0o022 and value.st_size <= maximum)
        require(not private or not value.st_mode & 0o077 or protected)
        result = bytearray()
        while len(result) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
        require(len(result) == value.st_size and len(result) <= maximum)
        return bytes(result)
    finally:
        os.close(fd)
        os.close(parent)


def tool(profile):
    parent, _ = directory(str(Path(K3S).parent))
    fd = os.open(Path(K3S).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    os.close(parent)
    value = os.fstat(fd)
    require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022)
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        digest.update(chunk)
    require(digest.hexdigest() == profile["k3s_sha256"])
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def command(fd, args, input=None, allowed=(0,), limits=(MAXIMUM, MAXIMUM), source=None, mutating=False, seconds=20,
            bound=False, probe=False):
    """Run the pinned executable; a probe returns (exit, stdout, stderr), or None when its own bound expires."""
    global WRITERS_SETTLED
    require(time.monotonic() < DEADLINE, 6)
    process = subprocess.Popen([f"/proc/self/fd/{fd}", *args], executable=f"/proc/self/fd/{fd}", pass_fds=(fd,),
        stdin=source if source is not None else subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/var/empty", "LANG": "C.UTF-8"})
    poll = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        poll.register(stream, selectors.EVENT_READ)
    pending = memoryview(input) if input is not None else None
    if pending is not None:
        os.set_blocking(process.stdin.fileno(), False)
        poll.register(process.stdin, selectors.EVENT_WRITE)
    until = min(DEADLINE, time.monotonic() + seconds)
    completed = False
    try:
        while poll.get_map():
            if time.monotonic() >= until:
                require(probe, 6)
                return None
            for event, _ in poll.select(min(0.05, max(0, until - time.monotonic()))):
                stream = event.fileobj
                if stream is process.stdin:
                    count = os.write(stream.fileno(), pending[:65536])
                    pending = pending[count:]
                    if not pending:
                        poll.unregister(stream)
                        stream.close()
                else:
                    chunk = os.read(stream.fileno(), 65536)
                    if chunk:
                        limit = limits[0] if stream is process.stdout else limits[1]
                        fits = len(streams[stream]) + len(chunk) <= limit
                        # A bounded read's excess refuses `bound`; a probe's is malformed.
                        state_require(fits or not bound or stream is not process.stdout, "bound")
                        require(fits, 4)
                        streams[stream].extend(chunk)
                    else:
                        poll.unregister(stream)
        try:
            process.wait(timeout=max(0.001, until - time.monotonic()))
        except subprocess.TimeoutExpired:
            if probe:
                return None
            raise
        completed = True
        if probe:
            return process.returncode, bytes(streams[process.stdout]), bytes(streams[process.stderr])
        require(process.returncode in allowed, 5)
        return bytes(streams[process.stdout])
    finally:
        # A failed mutating API client can leave server-side work unresolved. A
        # killed dry-run probe is no writer effect.
        if (input is not None or mutating) and not completed and not probe:
            WRITERS_SETTLED = False
        poll.close()
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                if not probe:
                    WRITERS_SETTLED = False
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def opaque(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None


def read_exact(length):
    result = bytearray()
    while len(result) < length:
        chunk = sys.stdin.buffer.read(length - len(result))
        require(chunk, 4)
        result.extend(chunk)
    return bytes(result)


# ---- Writer-admission layer: the control body's rules, carried as a copy ----
STATE_KINDS = {
    "machine-claim": "scope owner member participants_sha256 generation active_attempt root_identity lock_identity",
    "reservation": "binding state members dispatches seal_sha256 retirement_sha256",
    "intent": "binding action payload_sha256 admitted_ms",
    "terminal": "binding action payload_sha256 outcome failure effect writer_ended resource resource_identity completed_ms",
    "seal": "binding dispatches terminal_sha256s sealed_ms",
    "retirement": "binding seals next_generation retired_ms",
}


class StateRefused(Exception):
    def __init__(self, failure, detail=None):
        self.failure = failure
        self.detail = detail


def state_require(value, failure="integrity"):
    if not value:
        raise StateRefused(failure)


def state_check():
    state_require(time.monotonic() < DEADLINE, "timeout")


def state_fields(value, names):
    state_require(isinstance(value, dict) and set(value) == set(names.split()))


def state_hash(label, value):
    return hashlib.sha256(label.encode("ascii") + b"\n" + canonical(value)).hexdigest()


def state_hex(value, length=32):
    state_require(isinstance(value, str) and re.fullmatch("[0-9a-f]{%d}" % length, value) is not None)


def state_uint(value, minimum=0, maximum=18446744073709551615):
    state_require(type(value) is int and minimum <= value <= maximum, "bound")


def state_value(value, depth=0):
    state_require(depth <= 16, "bound")
    if isinstance(value, str):
        state_require("\0" not in value and len(value.encode("utf-8")) <= 4096, "bound")
    elif isinstance(value, (dict, list)):
        state_require(depth < 16 and len(value) <= 4096, "bound")
        if isinstance(value, dict):
            for key, item in value.items():
                state_require(isinstance(key, str))
                state_value(key, depth + 1)
                state_value(item, depth + 1)
        else:
            for item in value:
                state_value(item, depth + 1)
    elif type(value) is int:
        state_uint(value)
    else:
        state_require(value is None or type(value) is bool)


def state_scope(scope):
    state_fields(scope, "project environment target hash")
    state_require(isinstance(scope["project"], str) and scope["project"].startswith("/") and
                  str(Path(scope["project"])) == scope["project"] and ".." not in Path(scope["project"]).parts)
    state_require(isinstance(scope["environment"], str) and scope["environment"] and opaque(scope["target"]))
    state_require(scope["hash"] == state_hash("broil-infra-scope-v1", [scope[k] for k in ("project", "environment", "target")]))


def state_route(route):
    state_fields(route, "address port account host_key_sha256")
    state_require(isinstance(route["address"], str) and route["address"] and isinstance(route["account"], str) and route["account"])
    state_uint(route["port"], 1, 65535)
    state_hex(route["host_key_sha256"], 64)


def state_member(member):
    state_fields(member, "machine member role route jump node_uid")
    state_require(isinstance(member["machine"], str) and member["machine"] and member["role"] in ("server", "agent", "backup"))
    if member["role"] == "backup":
        state_require(member["member"] is None and member["node_uid"] is None)
    else:
        state_require(isinstance(member["member"], str) and member["member"] and (member["node_uid"] is None or opaque(member["node_uid"])))
    state_route(member["route"])
    if member["jump"] is not None:
        state_route(member["jump"])


def state_fingerprints(fingerprints):
    state_fields(fingerprints, "config_sha256 references_sha256 profile_sha256 script_sha256 tools")
    for name in ("config_sha256", "references_sha256", "profile_sha256", "script_sha256"):
        state_hex(fingerprints[name], 64)
    state_require(isinstance(fingerprints["tools"], list) and 1 <= len(fingerprints["tools"]) <= 128, "bound")
    previous = None
    for item in fingerprints["tools"]:
        state_fields(item, "name sha256")
        state_require(opaque(item["name"]) and (previous is None or previous.encode() < item["name"].encode()))
        state_hex(item["sha256"], 64)
        previous = item["name"]


def state_binding(binding):
    state_fields(binding, "scope owner operation attempt step dispatch recipient receiver_generation request_sha256 participants_sha256 fingerprints")
    state_scope(binding["scope"])
    for field in ("owner", "attempt", "dispatch"):
        state_hex(binding[field])
    state_require(isinstance(binding["operation"], str) and binding["operation"].startswith("infra-operation-"))
    state_hex(binding["operation"][16:])
    state_uint(binding["step"], 1, 4294967295)
    state_uint(binding["receiver_generation"])
    for field in ("request_sha256", "participants_sha256"):
        state_hex(binding[field], 64)
    state_member(binding["recipient"])
    state_fingerprints(binding["fingerprints"])


def state_cluster(cluster):
    if cluster is not None:
        state_fields(cluster, "uid ca_sha256")
        state_require(opaque(cluster["uid"]))
        state_hex(cluster["ca_sha256"], 64)


def state_private(fd, is_directory=False):
    value = os.fstat(fd)
    state_require(value.st_uid == 0 and stat.S_IMODE(value.st_mode) == (0o700 if is_directory else 0o600) and
                  (stat.S_ISDIR(value.st_mode) if is_directory else stat.S_ISREG(value.st_mode) and value.st_nlink == 1), "ownership")
    return value


def state_directory(path, create=False):
    state_check()
    parent, _ = directory(str(Path(path).parent))
    try:
        if create:
            try:
                os.mkdir(Path(path).name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
        try:
            state_private(fd, True)
            state_check()
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


def state_names(path, maximum):
    fd = state_directory(path)
    try:
        names = []
        with os.scandir(fd) as entries:
            for entry in entries:
                state_check()
                state_require(len(names) < maximum, "bound")
                names.append(entry.name)
        return sorted(names)
    finally:
        os.close(fd)


def state_read(path, kind=None, schema=1):
    state_check()
    try:
        parent = state_directory(str(Path(path).parent))
    except FileNotFoundError:
        return None
    try:
        try:
            fd = os.open(Path(path).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            st = state_private(fd)
            state_require(st.st_size <= 65536, "bound")
            raw = os.read(fd, 65537)
            state_require(len(raw) == st.st_size and not os.read(fd, 1))
            record = decode(raw)
            state_value(record)
            state_require(raw == canonical(record) + b"\n")
            state_require(record.get("schema") == schema, "unsupported-version" if type(record.get("schema")) is int and record["schema"] > schema else "integrity")
            if kind in STATE_KINDS:
                state_fields(record, "schema kind " + STATE_KINDS[kind])
                state_require(record["kind"] == kind)
                if "binding" in record:
                    state_binding(record["binding"])
            state_check()
            return record
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def state_publish(path, record, expected=None):
    global EFFECTS
    state_value(record)
    raw = canonical(record) + b"\n"
    state_require(len(raw) <= 65536, "bound")
    parent = state_directory(str(Path(path).parent))
    temporary = ".tmp-" + secrets.token_hex(16)
    fd = None
    try:
        state_check()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=parent)
        state_private(fd)
        EFFECTS = True
        offset = 0
        while offset < len(raw):
            state_check()
            count = os.write(fd, raw[offset:])
            state_require(count > 0, "storage")
            offset += count
        os.fsync(fd)
        state_check()
        name = Path(path).name
        if expected is None:
            # link is atomic no-replace publication; until the temporary name is
            # removed a crash leaves multi-link residue, which readers refuse.
            os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent)
        else:
            old = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
            try:
                state_private(old)
                state_require(identity(old) == expected, "ownership")
            finally:
                os.close(old)
            os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        state_check()
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def state_file_identity(path):
    parent = state_directory(str(Path(path).parent))
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
        try:
            state_private(fd)
            return identity(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def state_mkdir(path):
    fd = state_directory(path, True)
    os.close(fd)


def state_now():
    return time.time_ns() // 1000000



def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    value = hashlib.sha256()
    while chunk := os.read(fd, 1048576):
        state_check()
        value.update(chunk)
    return value.hexdigest()



# The ten profile bodies.
BODIES = {"control", "lifecycle", "network", "ingress", "cert_manager", "registry", "node", "delivery", "release",
          "service_guard"}
SYSTEMCTL = "/usr/bin/systemctl"
# The replication host layout, its unit and the runtime identity.
REPLICATION = "/var/lib/broil-k3s-replication"
REPLICATION_UNIT = "/etc/systemd/system/broil-k3s-replication.service"
REGISTRIES = "/etc/rancher/k3s/registries.yaml"
UNIT = "broil-k3s-replication.service"
RUNTIME = 10000
FOLDER = "broil-registry"
IGNORE = b"_uploads\n"
# The replication unit's filesystem restrictions, equal to the network body's traversal probe's.
REPLICATION_RESTRICTIONS = ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes")
SETPRIV = ("/usr/bin/setpriv", "--reuid=10000", "--regid=10000", "--clear-groups")
DEVICE = re.compile(r"[A-Z2-7]{7}(-[A-Z2-7]{7}){7}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/var/empty", "LANG": "C.UTF-8"}
READER = {"broil.dev/managed-by":"broil", "broil.dev/component":"registry-reader"}
SERVICE = {"broil.dev/managed-by":"broil", "broil.dev/component":"registry-service"}
TOKEN = {"broil.dev/managed-by":"broil", "broil.dev/component":"registry-token"}
OWNERSHIP = ("broil.dev/owner", "broil.dev/creation-operation", "broil.dev/cluster-uid", "broil.dev/recipe-sha256",
             "broil.dev/profile-sha256")
SECURE = {"allowPrivilegeEscalation":False, "readOnlyRootFilesystem":True, "capabilities":{"drop":["ALL"]}}
RESOURCES = {"requests":{"cpu":"50m", "memory":"64Mi"}, "limits":{"memory":"256Mi"}}
NODES = '{range .items[*]}{.metadata.name}{"\\t"}{.metadata.uid}{"\\t"}{.spec.unschedulable}{"\\t"}' \
        '{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\\n"}{end}'
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")
ACCEPT = ", ".join(INDEX_TYPES + ("application/vnd.oci.image.manifest.v1+json",
                                  "application/vnd.docker.distribution.manifest.v2+json"))
READS = ("inspect-", "check-", "read-")
ACCESS = re.compile(r'^\S+ \S+ \S+ \[[^\]]*\] "(GET|HEAD) (\S+) HTTP/[0-9.]+" ([0-9]{3}) ([0-9]+|-)')
TARGET = re.compile(r"^/v2/(.+)/(manifests|blobs)/(sha256:[0-9a-f]{64})$")


def pick(render, actual):
    """`actual` restricted to the fields that `render` carries."""
    if isinstance(render, dict) and isinstance(actual, dict):
        return {key:pick(value, actual.get(key)) for key, value in render.items()}
    if isinstance(render, list) and isinstance(actual, list) and len(render) == len(actual):
        return [pick(value, item) for value, item in zip(render, actual)]
    return actual


def systemctl(*args):
    """One `systemctl` call on the replication unit's verbs; any other exit than 0 is a transport failure."""
    done = subprocess.run([SYSTEMCTL, *args], stdin=subprocess.DEVNULL, capture_output=True, env=ENV,
                          timeout=max(1, min(90, DEADLINE - time.monotonic())))
    state_require(done.returncode == 0, "transport")
    return done.stdout


def runtime_dir(parent, name):
    """A directory of the runtime identity, 0700, opened without following links."""
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
    st = os.fstat(fd)
    if not (st.st_uid == st.st_gid == RUNTIME and not st.st_mode & 0o077):
        os.close(fd)
        raise StateRefused("ownership")
    return fd


def runtime_file(parent, name, maximum=1048576):
    """A regular single-link file of the runtime identity without group or other bits, and its bytes."""
    fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    try:
        st = os.fstat(fd)
        state_require(stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == RUNTIME and st.st_nlink == 1 and
                      not st.st_mode & 0o077 and st.st_size <= maximum, "ownership")
        data = os.read(fd, maximum + 1)
        state_require(len(data) == st.st_size, "ownership")
        return data, identity(fd)
    finally:
        os.close(fd)


def write_runtime(parent, name, data, mode=0o600):
    """Create `name` exclusively as the runtime identity's, written and fsynced."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode, dir_fd=parent)
    try:
        os.fchown(fd, RUNTIME, RUNTIME)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def write_root(parent, name, data, mode):
    """Create `name` exclusively as root's, written and fsynced."""
    global EFFECTS
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode, dir_fd=parent)
    EFFECTS = True
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)


def apikey(config):
    """The generated REST API key that `config.xml` holds; it never leaves this process."""
    key = ET.fromstring(config).findtext("gui/apikey")
    state_require(isinstance(key, str) and re.fullmatch(r"[A-Za-z0-9_-]{8,128}", key) is not None, "ownership")
    return key


SYNC_OPTIONS = (("globalAnnounceEnabled", "false"), ("localAnnounceEnabled", "false"), ("relaysEnabled", "false"),
                ("natEnabled", "false"), ("crashReportingEnabled", "false"), ("autoUpgradeIntervalH", "0"),
                ("urAccepted", "-1"), ("startBrowser", "false"))


def settings(config):
    """The compared items of a `config.xml`: Syncthing rewrites the file at start into its current
    schema with every default filled in, so its bytes never stay the render's."""
    root = ET.fromstring(config)

    def field(element, name):
        return element.get(name, element.findtext(name))

    devices = sorted((d.get("id"), tuple(sorted(a.text or "" for a in d.findall("address"))),
                      field(d, "introducer"), field(d, "autoAcceptFolders")) for d in root.findall("device"))
    folders = sorted((f.get("id"), f.get("path"), f.get("type"),
                      tuple(sorted(d.get("id") for d in f.findall("device"))), field(f, "fsWatcherEnabled"), field(f, "rescanIntervalS"), field(f, "ignorePerms"),
                      field(f, "markerName"), tuple(v.get("type", "") for v in f.findall("versioning")))
                     for f in root.findall("folder"))
    return (root.findtext("gui/address"), root.findtext("gui/apikey"),
            tuple(sorted(e.text or "" for e in root.findall("options/listenAddress"))),
            tuple(root.findtext("options/" + name) for name, _ in SYNC_OPTIONS), devices, folders)


def rest(key, method, path, **query):
    """One call to the member's replication API on loopback, with the key only in `X-API-Key`."""
    target = path + ("?" + "&".join("%s=%s" % (k, quote(str(v), safe="")) for k, v in query.items()) if query else "")
    connection = http.client.HTTPConnection("127.0.0.1", 8384, timeout=max(0.2, min(5, DEADLINE - time.monotonic())))
    try:
        connection.request(method, target, headers={"X-API-Key": key})
        response = connection.getresponse()
        body = response.read(1048577)
        state_require(response.status == 200 and len(body) <= 1048576, "readiness")
        return decode(body) if body.strip() else None
    finally:
        connection.close()


def unit_text(path):
    """The unit, with `<path>/data` in systemd's unit-file quoting."""
    data = (path + "/data").replace("%", "%%")
    if re.search(r'[\s"\\]', data):
        data = '"%s"' % data.replace("\\", "\\\\").replace('"', '\\"')
    home = "/var/lib/broil-k3s-replication/home"
    return ("[Unit]\nDescription=Broil K3s registry replication\nAfter=network-online.target\n"
            "Wants=network-online.target\n\n[Service]\nEnvironment=HOME=%s\nExecStart=%s "
            "/var/lib/broil-k3s-replication/bin/syncthing serve --home=%s --no-browser --no-restart --no-upgrade "
            "--no-port-probing --log-file=-\nRestart=always\nRestartSec=5\n%sReadWritePaths=%s %s\n\n[Install]\n"
            "WantedBy=multi-user.target\n" % (home, " ".join(SETPRIV), home,
                                               "".join(x + "\n" for x in REPLICATION_RESTRICTIONS), home,
                                               data)).encode()


def utf8_safe(value):
    return isinstance(value, str) and 0 < len(value.encode()) <= 4096 and "\0" not in value


class Receiver:
    """The receiver framework that both protocols of the body share."""
    FAMILY, KEYS, HOST = None, ("recipe", "expected", "resource", "preflight", "wait_ms", "member"), ()

    def __init__(self, header):
        self.header = header
        self.binding = header["binding"]
        self.member = self.binding["recipient"]
        self.tag = header["action"]
        self.action = "lifecycle:%s-%s" % (self.FAMILY, self.tag)
        self.recipe = header["recipe"]
        self.expected = header["expected"]
        self.payload = {key:header[key] for key in self.KEYS}
        self.root = self.lock = self.executable = None
        self.root_id = self.lock_id = None
        self.claim = self.reservation = self.intent = self.published = None
        self.effect_started = self.partial = False
        self.owner_path = ROOT + "/owners/" + self.binding["owner"]
        self.recipe_hash = state_hash("broil-k3s-%s-recipe-v1" % self.FAMILY, self.recipe)

    def profile(self):
        state_require(os.geteuid() == 0 and
                      os.environ.get("BROIL_MACHINE") == self.member["machine"] and
                      os.environ.get("BROIL_ENV") == self.binding["scope"]["environment"], "ownership")
        raw = read_file(PROFILE, 16384, private=False)
        profile = decode(raw)
        bodies = profile.get("bodies")
        state_require(isinstance(bodies, dict) and set(bodies) == BODIES and
                      hashlib.sha256(raw).hexdigest() == self.binding["fingerprints"]["profile_sha256"] and
                      profile["script_sha256"] == self.binding["fingerprints"]["script_sha256"] == bodies["control"] and
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == bodies["delivery"], "ownership")
        tools = self.binding["fingerprints"]["tools"]
        state_require(len(tools) == 2 and tools[0]["name"] == "bootstrap-index" and
                      tools[1] == {"name":"k3s", "sha256":profile["k3s_sha256"]}, "capability")
        self.host_profile = profile
        self.check(profile)
        self.executable = tool(profile)

    def attempt_path(self):
        return ROOT + "/attempts/" + self.binding["attempt"]

    def dispatch_path(self):
        return ROOT + "/dispatches/" + self.binding["dispatch"]

    def revalidate(self):
        state_check()
        fd = state_directory(ROOT)
        try:
            state_require(identity(fd) == self.root_id and state_file_identity(ROOT + "/mutation.lock") == self.lock_id and
                          identity(self.lock) == self.lock_id, "ownership")
        finally:
            os.close(fd)

    def open(self):
        self.root = state_directory(ROOT)
        self.root_id = identity(self.root)
        self.lock = os.open("mutation.lock", os.O_RDWR | NOFOLLOW, dir_fd=self.root)
        state_require(state_private(self.lock).st_size == 0, "ownership")
        try:
            fcntl.flock(self.lock, (fcntl.LOCK_SH if self.tag.startswith(READS) else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateRefused("busy")
        self.lock_id = identity(self.lock)
        self.revalidate()
        self.claim = state_read(ROOT + "/machine-claim.json", "machine-claim")
        state_require(self.claim is not None and self.claim["scope"] == self.binding["scope"] and
                      self.claim["owner"] == self.binding["owner"] and
                      self.claim["participants_sha256"] == self.binding["participants_sha256"] and
                      self.claim["member"] == self.member and
                      self.claim["root_identity"] == self.root_id and
                      self.claim["lock_identity"] == self.lock_id, "ownership")
        self.reservation = state_read(self.attempt_path() + "/reservation.json", "reservation")
        if self.reservation is not None:
            state_require(self.reservation["binding"]["attempt"] == self.binding["attempt"] and
                          self.reservation["binding"]["operation"] == self.binding["operation"] and
                          self.reservation["binding"]["owner"] == self.binding["owner"], "ownership")

    def owned(self):
        record = state_read(self.owner_path + "/ownership.json")
        state_require(record is not None, "ownership")
        state_fields(record, "schema owner scope machine cluster data")
        state_require(record["owner"] == self.binding["owner"] and
                      record["scope"] == {key:self.binding["scope"][key] for key in ("project", "environment", "target")} and
                      record["machine"] == {key:self.member[key] for key in ("machine", "member", "role", "node_uid")} and
                      record["cluster"] == self.recipe["cluster"], "ownership")

    def active(self):
        self.owned()
        state_require(state_read(self.attempt_path() + "/seal.json", "seal") is None and
                      state_read(self.attempt_path() + "/retirement.json", "retirement") is None and
                      self.reservation is not None and
                      self.reservation["state"] in ("reserved", "active") and
                      self.claim["active_attempt"] == self.binding["attempt"] and
                      self.claim["generation"] == self.binding["receiver_generation"], "ownership")
        original = self.reservation["binding"]
        state_require(all(original[key] == self.binding[key] for key in original if key not in ("step", "dispatch")), "ownership")

    def ledger(self):
        try:
            names = state_names(ROOT + "/dispatches", 1048576)
        except FileNotFoundError:
            return []
        work = []
        total = 0
        for name in names:
            state_hex(name)
            path = ROOT + "/dispatches/" + name
            entries = set(state_names(path, 3)) - {"bootstrap-input.json"}
            state_require(entries in ({"intent.json"}, {"intent.json", "terminal.json"}), "integrity")
            intent = state_read(path + "/intent.json", "intent")
            state_require(intent is not None and intent["binding"]["dispatch"] == name, "ownership")
            terminal = state_read(path + "/terminal.json", "terminal")
            if terminal is not None:
                state_require(terminal["binding"] == intent["binding"] and terminal["action"] == intent["action"] and
                              terminal["payload_sha256"] == intent["payload_sha256"] and terminal["writer_ended"] is True, "ownership")
            if intent["binding"]["attempt"] == self.binding["attempt"]:
                total += len(canonical(intent)) + 1 + (len(canonical(terminal)) + 1 if terminal else 0)
                state_require(total <= 33554432 and len(work) < 1024, "bound")
            elif terminal is None:
                raise StateRefused("busy")
            work.append((name, intent, terminal))
        return work

    def replace(self, path, record):
        self.revalidate()
        state_publish(path, record, state_file_identity(path))

    def previous(self):
        """A repeated dispatch's terminal receipt, read before any precondition."""
        path = self.dispatch_path()
        intent = state_read(path + "/intent.json", "intent")
        if intent is None:
            return None
        state_require(intent["binding"] == self.binding and intent["action"] == self.action and
                      intent["payload_sha256"] == state_hash("broil-infra-step-v1", self.payload), "ownership")
        terminal = state_read(path + "/terminal.json", "terminal")
        state_require(terminal is not None, "busy")
        return terminal

    def begin(self):
        """One-use receiver intent under the active reservation."""
        self.active()
        work = self.ledger()
        state_require(len(work) < 1024 and all(t is not None for _, _, t in work), "busy")
        same = [name for name, intent, _ in work if intent["binding"]["attempt"] == self.binding["attempt"] and
                (intent["action"] in ("reserve-owner", "acquire-writer", "prepare-input", "admit-credential") or
                 intent["action"].startswith(("credential:", "bootstrap:", "lifecycle:")))]
        state_require(set(same) == set(self.reservation["dispatches"]) and
                      len(same) == len(self.reservation["dispatches"]), "ownership")
        state_mkdir(ROOT + "/dispatches")
        parent = state_directory(ROOT + "/dispatches")
        try:
            os.mkdir(self.binding["dispatch"], 0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        self.intent = {"schema":1, "kind":"intent", "binding":self.binding, "action":self.action,
                       "payload_sha256":state_hash("broil-infra-step-v1", self.payload), "admitted_ms":state_now()}
        self.revalidate()
        state_publish(self.dispatch_path() + "/intent.json", self.intent)
        self.reservation["dispatches"].append(self.binding["dispatch"])
        self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        self.revalidate()

    def terminal(self, outcome, failure, resource=None, uid=None):
        state_require(self.intent is not None and self.published is None and WRITERS_SETTLED, "busy")
        value = {"schema":1, "kind":"terminal", "binding":self.binding, "action":self.action,
                 "payload_sha256":self.intent["payload_sha256"], "outcome":outcome, "failure":failure,
                 "effect":"complete" if outcome == "succeeded" else "partial" if self.partial else
                 "unknown" if self.effect_started else "absent",
                 "writer_ended":True, "resource":resource, "resource_identity":uid, "completed_ms":state_now()}
        self.revalidate()
        state_publish(self.dispatch_path() + "/terminal.json", value)
        self.published = value
        return value

    def done(self, result, uid=None):
        result["terminal"] = self.terminal("succeeded", None, self.header["resource"], uid)

    def kubectl(self, *args, input=None, limit=MAXIMUM, seconds=20, probe=False, mutating=False, timeout="10s"):
        kubeconfig = f"{self.owner_path}/admin.yaml"
        read_file(kubeconfig, 65536)
        return command(self.executable, ["kubectl", "--kubeconfig", kubeconfig, "--request-timeout=" + timeout, *args], input,
                       limits=(limit, 65536 if probe else MAXIMUM), seconds=seconds, bound=True, probe=probe,
                       mutating=mutating)

    def runtime(self, *args, **options):
        return command(self.executable, list(args), limits=(MAXIMUM, 65536), **options)

    def counters(self):
        """The member's replication counters `{in_bytes_total, connections}`; null unobserved."""
        try:
            parent, _ = directory(REPLICATION)
            try:
                home = runtime_dir(parent, "home")
            finally:
                os.close(parent)
            try:
                key = apikey(runtime_file(home, "config.xml")[0])
            finally:
                os.close(home)
            value = rest(key, "GET", "/rest/system/connections")
            connected = [c for c in value["connections"].values() if c.get("connected") is True]
            total = value["total"]["inBytesTotal"]
            state_require(type(total) is int)
            return {"in_bytes_total":total, "connections":len(connected)}
        except (OSError, ValueError, TypeError, KeyError, AttributeError, ET.ParseError, Refused, StateRefused):
            return {"in_bytes_total":None, "connections":None}


# ---- The replication protocol ----
REPLICATION_TAGS = ("inspect-replication", "create-replication", "create-replica", "configure-replication",
                    "scan-replica", "revert-replica", "remove-device", "stop-replication", "inspect-objects",
                    "create-object", "configure-reader", "stop-writer", "start-writer")
REPLICATION_HOST = REPLICATION_TAGS[:8]
FACTS = ("record", "service", "device_id", "configuration", "folder", "state", "completion", "need_bytes",
         "need_items", "need_deletes", "local_changes", "peers_connected", "peers_expected", "bytes_received",
         "bytes_sent", "peer_completion")
READER_OBJECTS = (("ConfigMap", "v1", "configmaps"), ("DaemonSet", "apps/v1", "daemonsets.apps"))


class ReplicationReceiver(Receiver):
    FAMILY, LIMIT = "registry-replication", 32768

    @staticmethod
    def admit(header, tag):
        """`expected` and `member`: a host action names its recipient, an API action none."""
        e, member = header["expected"], header["member"]
        state_require(isinstance(e, dict) and set(e) == {"objects", "device", "writer_generation"} and
                      isinstance(e["objects"], list) and len(e["objects"]) == 2 and
                      all(x is None or opaque(x) for x in e["objects"]) and
                      (e["device"] is None or isinstance(e["device"], str) and DEVICE.fullmatch(e["device"])) and
                      (e["writer_generation"] is None or type(e["writer_generation"]) is int and
                       e["writer_generation"] >= 1) and
                      (member is None) != (tag in REPLICATION_HOST), "ownership")

    def check(self, profile):
        """The recipe; host actions on `member`, API actions on the first server."""
        r, b = self.recipe, self.binding
        state_fields(r, "scope owner operation cluster first_server version registry path writer members devices "
                        "detached assets reader tolerations stage origins profile_sha256")
        state_cluster(r["cluster"])
        state_member(r["first_server"])
        members = r["members"]
        state_require(isinstance(members, list) and 0 < len(members) <= 128, "ownership")
        for m in members:
            state_require(isinstance(m, dict) and isinstance(m.get("node_ip"), str) and
                          re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", m["node_ip"]) is not None, "ownership")
            state_member({k:v for k, v in m.items() if k != "node_ip"})
        names = [m["member"] for m in members]
        devices = r["devices"]
        state_require(devices is None or isinstance(devices, list) and len(devices) == len(members) and all(
            isinstance(d, dict) and set(d) == {"member", "device_id"} and d["member"] == n and
            (d["device_id"] is None or isinstance(d["device_id"], str) and DEVICE.fullmatch(d["device_id"]))
            for d, n in zip(devices, names)), "ownership")
        for x in r["assets"] if isinstance(r["assets"], list) else [None]:
            state_fields(x, "generation marker_sha256")
            state_hex(x["generation"])
            state_hex(x["marker_sha256"], 64)
        state_fields(r["reader"], "realm_path service certificate switch_operation")
        state_fields(r["origins"], "replication objects")
        for taint in r["tolerations"] if isinstance(r["tolerations"], list) and len(r["tolerations"]) <= 64 else [None]:
            state_fields(taint, "key value effect")
        path, parts = r["path"], Path(r["path"]).parts[1:] if isinstance(r["path"], str) else ()
        member = self.header["member"]
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      r["version"] == profile["k3s_version"] and opaque(r["registry"]) and
                      len(set(names)) == len(names) and r["writer"] in names and
                      isinstance(r["detached"], list) and all(isinstance(x, str) for x in r["detached"]) and
                      r["stage"] in ("create", "extend", "configure", "observe", "move") and
                      all(utf8_safe(r["reader"][k]) for k in ("realm_path", "service", "certificate")) and
                      path.startswith("/") and str(Path(path)) == path and parts and len(path.encode()) <= 4090 and
                      all(0 < len(p.encode()) <= 255 and p != ".." for p in parts), "ownership")
        if self.tag in REPLICATION_HOST:
            # `stop-replication` runs on a removed member, which the recipe no longer lists.
            state_require(member == self.member["member"] and (member in names or self.tag == "stop-replication"),
                          "ownership")
            self.own = next((m for m in members if m["member"] == member), None)
        else:
            state_require(self.member == r["first_server"], "ownership")

    # ---- Host layout and facts ----
    def classify(self):
        """The record's class, read from the replication directory, and the record."""
        try:
            try:
                root, _ = directory(REPLICATION)
            except FileNotFoundError:
                return "absent", None
            try:
                st = os.fstat(root)
                try:
                    fd = os.open("record.json", os.O_RDONLY | NOFOLLOW, dir_fd=root)
                except FileNotFoundError:
                    return "foreign", None
                try:
                    info = os.fstat(fd)
                    raw = os.read(fd, 4097)
                finally:
                    os.close(fd)
                record = decode(raw)
                if not (isinstance(record, dict) and raw == canonical(record) + b"\n" and set(record) == {
                        "schema", "kind", "scope", "owner", "operation", "member", "device_id", "executable_sha256",
                        "home", "created"} and record["schema"] == 1 and record["kind"] == "registry-replication" and
                        record["scope"] == self.binding["scope"] and record["owner"] == self.binding["owner"] and
                        record["member"] == dict(self.member, node_uid=None) and
                        isinstance(record["device_id"], str) and DEVICE.fullmatch(record["device_id"])):
                    return "foreign", None
                bin_fd = os.open("bin", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=root)
                try:
                    exe = os.open("syncthing", os.O_RDONLY | NOFOLLOW, dir_fd=bin_fd)
                    try:
                        x = os.fstat(exe)
                        sound = stat.S_ISREG(x.st_mode) and x.st_uid == 0 and stat.S_IMODE(x.st_mode) == 0o755 and \
                            digest(exe) == record["executable_sha256"]
                    finally:
                        os.close(exe)
                    y = os.fstat(bin_fd)
                    sound &= y.st_uid == 0 and stat.S_IMODE(y.st_mode) == 0o755
                finally:
                    os.close(bin_fd)
                home = runtime_dir(root, "home")
                try:
                    sound &= identity(home) == record["home"] and stat.S_IMODE(os.fstat(home).st_mode) == 0o700
                finally:
                    os.close(home)
                sound &= st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o755 and info.st_uid == 0 and \
                    stat.S_IMODE(info.st_mode) == 0o600 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                return ("owned" if sound else "owned-drifted"), record
            finally:
                os.close(root)
        except StateRefused as error:
            return ("owned-drifted" if error.failure == "ownership" else "unobservable"), None
        except (OSError, ValueError, TypeError, KeyError, Refused):
            return "unobservable", None

    def config(self):
        """The home's `config.xml` bytes, their identity and the generated API key."""
        parent, _ = directory(REPLICATION)
        try:
            home = runtime_dir(parent, "home")
        finally:
            os.close(parent)
        try:
            raw, ident = runtime_file(home, "config.xml")
            return raw, ident, apikey(raw)
        finally:
            os.close(home)

    def service(self):
        try:
            done = subprocess.run([SYSTEMCTL, "is-active", UNIT], stdin=subprocess.DEVNULL, capture_output=True,
                                  env=ENV, timeout=max(1, min(10, DEADLINE - time.monotonic())))
        except (OSError, subprocess.SubprocessError):
            return "unobservable"
        state = done.stdout.decode("ascii", "replace").strip()
        return "running" if state == "active" else "stopped" if state in ("inactive", "failed", "deactivating") \
            else "unobservable"

    def device_set(self, without=None):
        """The recipient's device set: every other replica member's device, minus the detached ones."""
        r, own = self.recipe, self.header["member"]
        peers = []
        for m, d in zip(r["members"], r["devices"] or [{"device_id":None}] * len(r["members"])):
            if m["member"] == own or m["member"] in r["detached"] or d["device_id"] in r["detached"] or \
                    d["device_id"] == without:
                continue
            peers.append((d["device_id"], m["node_ip"]))
        return peers

    def folder_type(self, own):
        """The folder type; at `move`, send-only exactly on the device that `expected.device` names."""
        if self.recipe["stage"] == "move":
            return "sendonly" if self.expected["device"] == own else "receiveonly"
        return "sendonly" if self.recipe["writer"] == self.header["member"] else "receiveonly"

    def render(self, key, own, kind, peers):
        """The configuration: the options, the own device and the device set, and the one folder."""
        ip, path = self.own["node_ip"], quoteattr(self.recipe["path"] + "/data")
        lines = ['<configuration version="37">',
                 '    <folder id="%s" label="%s" path=%s type="%s" rescanIntervalS="60" fsWatcherEnabled="true" '
                 'fsWatcherDelayS="10" ignorePerms="false" autoNormalize="true">' % (FOLDER, FOLDER, path, kind)]
        lines += ['        <device id="%s" introducedBy=""></device>' % d for d in [own] + [p for p, _ in peers]]
        lines += ['        <minDiskFree unit="%">1</minDiskFree>', "        <versioning></versioning>",
                  "        <markerName>.stfolder</markerName>", "    </folder>"]
        for device, address in [(own, "dynamic")] + [(p, "tcp://%s:22000" % a) for p, a in peers]:
            lines += ['    <device id="%s" name="%s" compression="metadata" introducer="false" '
                      'skipIntroductionRemovals="false" introducedBy="">' % (device, device[:7]),
                      "        <address>%s</address>" % address, "        <paused>false</paused>",
                      "        <autoAcceptFolders>false</autoAcceptFolders>", "    </device>"]
        lines += ['    <gui enabled="true" tls="false" debugging="false">', "        <address>127.0.0.1:8384</address>",
                  "        <apikey>%s</apikey>" % escape(key), "        <theme>default</theme>", "    </gui>",
                  "    <options>", "        <listenAddress>tcp://%s:22000</listenAddress>" % ip,
                  "        <listenAddress>quic://%s:22000</listenAddress>" % ip]
        for name, value in SYNC_OPTIONS:
            lines.append("        <%s>%s</%s>" % (name, value, name))
        return ("\n".join(lines + ["    </options>", "</configuration>"]) + "\n").encode()

    def facts(self):
        """The `inspect-replication` facts, waiting up to `wait_ms` for the peer completion of `expected.device`."""
        f = dict.fromkeys(FACTS)
        f["record"], record = self.classify()
        f["service"] = self.service()
        peers = self.device_set()
        f["peers_expected"] = len(peers)
        key = None
        if f["record"] == "owned":
            f["device_id"] = own = record["device_id"]
            try:
                raw, _, key = self.config()
                # Under `move`, the recipient's actual folder of either type is its own render.
                kinds = ("receiveonly", "sendonly") if self.recipe["stage"] == "move" else (self.folder_type(own),)
                held = settings(raw)
                f["configuration"] = "owned" if any(held == settings(self.render(key, own, k, peers))
                                                    for k in kinds) else "differs"
            except (OSError, ValueError, TypeError, ET.ParseError, Refused, StateRefused):
                f["configuration"] = "differs"
        observed = False
        # For the recipient's own device the wait polls its own state until `in-sync`.
        device = self.expected["device"]
        itself = device is not None and device == f["device_id"]
        until = time.monotonic() + min((self.header["wait_ms"] or 0) / 1000, DEADLINE - time.monotonic() - 2)
        if key is not None and f["service"] == "running":
            try:
                while True:
                    status = rest(key, "GET", "/rest/db/status", folder=FOLDER)
                    completion = rest(key, "GET", "/rest/db/completion", folder=FOLDER)
                    connections = rest(key, "GET", "/rest/system/connections")
                    f["folder"] = rest(key, "GET", "/rest/config/folders/" + FOLDER)["type"]
                    f.update(completion=int(completion["completion"]), need_bytes=completion["needBytes"],
                             need_items=completion["needItems"], need_deletes=completion["needDeletes"],
                             local_changes=status["receiveOnlyChangedFiles"],
                             peers_connected=sum(1 for d, _ in peers if connections["connections"].get(d, {}).get(
                                 "connected") is True),
                             bytes_received=connections["total"]["inBytesTotal"],
                             bytes_sent=connections["total"]["outBytesTotal"])
                    idle = status["state"] == "idle" and f["completion"] == 100 and \
                        f["need_bytes"] == f["need_items"] == f["need_deletes"] == f["local_changes"] == 0
                    f["state"] = "local-changes" if f["folder"] == "receiveonly" and f["local_changes"] else \
                        "in-sync" if idle else "syncing"
                    if not itself or f["state"] == "in-sync" or time.monotonic() + 0.5 > until:
                        break
                    time.sleep(0.5)
                if device is not None and not itself:
                    f["peer_completion"] = self.peer(key)
                observed = True
            except (OSError, ValueError, TypeError, KeyError, AttributeError, Refused, StateRefused):
                f.update(dict.fromkeys(FACTS[4:12] + FACTS[13:]))
        if not observed:
            f["state"] = "stopped" if f["service"] == "stopped" else "unobserved"
        return f

    def peer(self, key):
        """The view of `expected.device`: polled until complete within `wait_ms`, else the last answer."""
        until = time.monotonic() + min((self.header["wait_ms"] or 0) / 1000, DEADLINE - time.monotonic() - 2)
        while True:
            c = rest(key, "GET", "/rest/db/completion", folder=FOLDER, device=self.expected["device"])
            value = {"completion":int(c["completion"]), "need_bytes":c["needBytes"], "need_items":c["needItems"],
                     "need_deletes":c["needDeletes"]}
            if value == {"completion":100, "need_bytes":0, "need_items":0, "need_deletes":0} or \
                    time.monotonic() + 0.5 > until:
                return value
            time.sleep(0.5)

    def idle(self, key, local=False):
        """Wait within `wait_ms` until the folder is idle, and with `local` without local changes."""
        until = time.monotonic() + min((self.header["wait_ms"] or 0) / 1000, DEADLINE - time.monotonic() - 2)
        while True:
            status = rest(key, "GET", "/rest/db/status", folder=FOLDER)
            if status["state"] == "idle" and (not local or status["receiveOnlyChangedFiles"] == 0):
                return
            state_require(time.monotonic() + 0.5 <= until, "timeout")
            time.sleep(0.5)

    def owned_record(self):
        """The recipient's own record `owned` and its device the recipe's, before any effect."""
        kind, record = self.classify()
        state_require(kind != "unobservable", "readiness")
        state_require(kind == "owned", "ownership")
        own = record["device_id"]
        devices = {d["member"]:d["device_id"] for d in self.recipe["devices"] or ()}
        state_require(self.recipe["devices"] is not None and devices.get(self.header["member"]) == own, "ownership")
        return own

    # ---- Host mutations ----
    def content(self):
        """The replica's content root, `<path>/data`, of the runtime identity."""
        parent, _ = directory(self.recipe["path"])
        try:
            return runtime_dir(parent, "data")
        finally:
            os.close(parent)

    def create_replica(self, result):
        """`.stfolder` and `.stignore`, once; an existing entry that is not exactly its own refuses."""
        global EFFECTS
        root = self.content()
        try:
            names = set(os.listdir(root))
            if ".stfolder" in names:
                os.close(runtime_dir(root, ".stfolder"))
            if ".stignore" in names:
                state_require(runtime_file(root, ".stignore", 64)[0] == IGNORE, "ownership")
            self.begin()
            self.effect_started = EFFECTS = True
            if ".stfolder" not in names:
                os.mkdir(".stfolder", 0o700, dir_fd=root)
                marker = os.open(".stfolder", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=root)
                try:
                    os.fchown(marker, RUNTIME, RUNTIME)
                finally:
                    os.close(marker)
            if ".stignore" not in names:
                write_runtime(root, ".stignore", IGNORE)
            os.fsync(root)
        finally:
            os.close(root)
        self.done(result)

    def generation(self):
        """The bound bootstrap generation's verified `syncthing` archive and the
        executable it carries, verified against the profile's pin."""
        r, pin = self.recipe, self.host_profile.get("syncthing") or {}
        entry = r["assets"][[m["member"] for m in r["members"]].index(self.header["member"])]
        path = f"{self.owner_path}/assets/{entry['generation']}"
        name = "syncthing-linux-amd64-%s" % pin.get("version")
        gfd = state_directory(path)
        try:
            marker = state_read(path + "/complete.json")
            state_require(marker is not None and hashlib.sha256(canonical(marker)).hexdigest() == entry["marker_sha256"] and
                          marker.get("kind") == "bootstrap-complete" and marker.get("owner") == self.binding["owner"],
                          "readiness")
            asset = [a for a in marker["assets"] if a.get("id") == "syncthing"]
            fd = os.open(name + ".tar.gz", os.O_RDONLY | NOFOLLOW, dir_fd=gfd)
            try:
                state_require(len(asset) == 1 and identity(fd) == asset[0]["identity"] and
                              digest(fd) == asset[0]["sha256"], "readiness")
                os.lseek(fd, 0, os.SEEK_SET)
                with open(os.dup(fd), "rb") as stream, tarfile.open(fileobj=stream, mode="r:gz") as bundle:
                    member = bundle.getmember(name + "/syncthing")
                    state_require(member.isfile() and member.size <= 134217728, "readiness")
                    data = bundle.extractfile(member).read(member.size + 1)
            finally:
                os.close(fd)
        except (KeyError, OSError, tarfile.TarError):
            raise StateRefused("readiness")
        finally:
            os.close(gfd)
        state_require(hashlib.sha256(data).hexdigest() == pin.get("sha256"), "readiness")
        return data

    def create_replication(self, result):
        """`create-replication`: the directory, the executable, the identity, the record and the unit, once."""
        global EFFECTS
        state_require(not os.path.lexists(REPLICATION) and not os.path.lexists(REPLICATION_UNIT), "ownership")
        data = self.generation()
        self.begin()
        self.effect_started = EFFECTS = True
        parent, _ = directory(str(Path(REPLICATION).parent))
        try:
            os.mkdir(Path(REPLICATION).name, 0o755, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        root, _ = directory(REPLICATION)
        try:
            os.fchmod(root, 0o755)
            os.mkdir("bin", 0o755, dir_fd=root)
            os.mkdir("home", 0o700, dir_fd=root)
            bin_fd = os.open("bin", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=root)
            try:
                os.fchmod(bin_fd, 0o755)
                write_root(bin_fd, "syncthing", data, 0o755)
            finally:
                os.close(bin_fd)
            home = os.open("home", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=root)
            try:
                os.fchown(home, RUNTIME, RUNTIME)
                ident = identity(home)
            finally:
                os.close(home)
            exe, home_path = REPLICATION + "/bin/syncthing", REPLICATION + "/home"
            env = dict(ENV, HOME=home_path)
            for verb in ("generate",):
                done = subprocess.run([*SETPRIV, exe, verb, "--home=" + home_path], stdin=subprocess.DEVNULL,
                                      capture_output=True, env=env, timeout=60)
                state_require(done.returncode == 0, "transport")
            done = subprocess.run([*SETPRIV, exe, "device-id", "--home=" + home_path], stdin=subprocess.DEVNULL,
                                  capture_output=True, env=env, timeout=60)
            device = done.stdout.decode("ascii", "replace").strip()
            state_require(done.returncode == 0 and DEVICE.fullmatch(device), "transport")
            record = {"schema":1, "kind":"registry-replication", "scope":self.binding["scope"],
                      "owner":self.binding["owner"], "operation":self.binding["operation"],
                      "member":dict(self.member, node_uid=None), "device_id":device,
                      "executable_sha256":hashlib.sha256(data).hexdigest(), "home":ident, "created":state_now()}
            write_root(root, "record.json", canonical(record) + b"\n", 0o600)
            directory_identity = identity(root)
        finally:
            os.close(root)
        unit_parent, _ = directory(str(Path(REPLICATION_UNIT).parent))
        try:
            write_root(unit_parent, Path(REPLICATION_UNIT).name, unit_text(self.recipe["path"]), 0o644)
        finally:
            os.close(unit_parent)
        for verb in (("daemon-reload",), ("enable", UNIT), ("start", UNIT)):
            systemctl(*verb)
        result["replication"] = self.facts()
        self.done(result, directory_identity)

    def configure(self, result):
        """`configure-replication` and `remove-device`: the render, the unit stopped, the identity-checked
        replacement, the unit started."""
        global EFFECTS
        own = self.owned_record()
        device = self.expected["device"]
        peers = self.device_set()
        state_require(all(d is not None for d, _ in peers), "readiness")
        if self.tag == "remove-device":
            # An unreachable old writer's device, which the move's recipe already lists detached.
            detached = device in self.recipe["detached"] and device in [d["device_id"] for d in self.recipe["devices"] or []]
            state_require(device is not None and device != own and (device in [d for d, _ in peers] or detached), "ownership")
            peers = self.device_set(device)
        _, ident, key = self.config()
        data = self.render(key, own, self.folder_type(own), peers)
        self.begin()
        self.effect_started = EFFECTS = True
        systemctl("stop", UNIT)
        parent, _ = directory(REPLICATION)
        try:
            home = runtime_dir(parent, "home")
        finally:
            os.close(parent)
        try:
            temporary = ".config-" + secrets.token_hex(8) + ".xml"
            write_runtime(home, temporary, data)
            fd = os.open("config.xml", os.O_RDONLY | NOFOLLOW, dir_fd=home)
            try:
                state_require(identity(fd) == ident, "ownership")
            finally:
                os.close(fd)
            os.replace(temporary, "config.xml", src_dir_fd=home, dst_dir_fd=home)
            os.fsync(home)
        finally:
            os.close(home)
        systemctl("start", UNIT)
        self.done(result)

    def scan(self, result):
        """`scan-replica` and `revert-replica`: one request, then the wait; no file changes directly."""
        global EFFECTS
        own = self.owned_record()
        key = self.config()[2]
        revert = self.tag == "revert-replica"
        if revert:
            # A revert never runs on the writer, and only on reported local changes.
            state_require(self.folder_type(own) == "receiveonly" and
                          rest(key, "GET", "/rest/db/status", folder=FOLDER)["receiveOnlyChangedFiles"] > 0, "ownership")
        self.begin()
        self.effect_started = EFFECTS = True
        rest(key, "POST", "/rest/db/revert" if revert else "/rest/db/scan", folder=FOLDER)
        self.idle(key, revert)
        self.done(result)

    def stop(self, result):
        """`stop-replication`: stop and disable the unit, keeping every file."""
        global EFFECTS
        self.begin()
        self.effect_started = EFFECTS = True
        systemctl("stop", UNIT)
        systemctl("disable", UNIT)
        self.done(result)

    # ---- API facts and mutations ----
    def ownership(self, origin):
        r = self.recipe
        return {"broil.dev/owner":r["owner"], "broil.dev/creation-operation":(origin or r)["operation"],
                "broil.dev/cluster-uid":r["cluster"]["uid"],
                "broil.dev/recipe-sha256":origin["recipe_sha256"] if origin else self.recipe_hash,
                "broil.dev/profile-sha256":r["profile_sha256"]}

    def renders(self):
        """The reader ConfigMap and DaemonSet."""
        r, pin = self.recipe, self.host_profile.get("registry") or {}
        config = ('version: 0.1\nlog:\n  level: error\nstorage:\n  filesystem:\n    rootdirectory: /data\n  delete:\n'
                  '    enabled: false\n  maintenance:\n    uploadpurging:\n      enabled: false\n    readonly:\n'
                  '      enabled: true\nhttp:\n  addr: "127.0.0.1:5599"\nauth:\n  token:\n    realm: %s\n    service: %s\n'
                  '    issuer: "broil-registry-token"\n    rootcertbundle: /config/token.crt\n' % (
                      json.dumps("http://127.0.0.1:5598" + r["reader"]["realm_path"]), json.dumps(r["reader"]["service"])))
        tolerations = [dict({"key":t["key"], "operator":"Equal", "effect":t["effect"]},
                            **({"value":t["value"]} if t["value"] else {})) for t in r["tolerations"]]
        pod = {"hostNetwork":True, "automountServiceAccountToken":False, "enableServiceLinks":False,
               "securityContext":{"runAsNonRoot":True, "runAsUser":RUNTIME, "runAsGroup":RUNTIME,
                                  "seccompProfile":{"type":"RuntimeDefault"}},
               **({"tolerations":tolerations} if tolerations else {}),
               "containers":[{"name":"reader", "image":"%s@sha256:%s" % (pin.get("image"), pin.get("digest")),
                              "imagePullPolicy":"Never", "args":["serve", "/config/config.yml"], "securityContext":SECURE,
                              "resources":RESOURCES,
                              "readinessProbe":{"tcpSocket":{"host":"127.0.0.1", "port":5599}, "periodSeconds":2},
                              "volumeMounts":[{"name":"data", "mountPath":"/data", "readOnly":True},
                                              {"name":"config", "mountPath":"/config", "readOnly":True}]}],
               "volumes":[{"name":"data", "hostPath":{"path":r["path"] + "/data", "type":"Directory"}},
                          {"name":"config", "configMap":{"name":"broil-registry-reader"}}]}
        bodies = ({"data":{"config.yml":config, "token.crt":r["reader"]["certificate"] + "\n"}},
                  {"spec":{"selector":{"matchLabels":READER}, "updateStrategy":{"type":"OnDelete"},
                           "template":{"metadata":{"labels":READER}, "spec":pod}}})
        origins = r["origins"]["objects"] or [None, None]
        return [{"apiVersion":row[1], "kind":row[0], "metadata":{"name":"broil-registry-reader",
                 "namespace":"broil-registry", "labels":READER, "annotations":self.ownership(origins[n])}, **bodies[n]}
                for n, row in enumerate(READER_OBJECTS)]

    def get(self, kind, name):
        """An object read: its JSON, None for the exact `NotFound`, else False."""
        outcome = self.kubectl("get", kind, name, "-n", "broil-registry", "-o", "json", limit=262144, probe=True)
        if outcome is None or outcome[0] and outcome[2] != b'Error from server (NotFound): %s "%s" not found\n' % (
                kind.encode(), name.encode()):
            return False
        return None if outcome[0] else decode(outcome[1])

    def objects(self):
        """The two reader objects' classes."""
        out = []
        for n, render in enumerate(self.renders()):
            record = {"kind":render["kind"], "namespace":"broil-registry", "name":"broil-registry-reader", "uid":None,
                      "class":"unobservable"}
            try:
                obj = self.get(READER_OBJECTS[n][2], "broil-registry-reader")
            except (Refused, StateRefused, ValueError):
                obj = False
            if obj is None:
                record["class"] = "absent"
            elif obj is not False:
                meta = obj.get("metadata") or {}
                notes = meta.get("annotations") or {}
                record["uid"] = meta.get("uid")
                if record["uid"] != self.expected["objects"][n] or \
                        {k:notes.get(k) for k in OWNERSHIP} != render["metadata"]["annotations"]:
                    record["class"] = "foreign"
                else:
                    same = (obj.get("data"), "binaryData" in obj, "immutable" in obj) == (render["data"], False, False) \
                        if n == 0 else meta.get("generation") == 1 and pick(render["spec"], obj.get("spec")) == render["spec"]
                    record["class"] = "owned" if same and meta.get("labels") == READER else "owned-drifted"
            out.append(record)
        return out

    def pods(self, labels):
        """The pods of a component's selector that are not being deleted; None when they cannot be read."""
        try:
            raw = self.kubectl("get", "pods", "-n", "broil-registry", "-l",
                               ",".join("%s=%s" % x for x in labels.items()), "-o", "json", limit=262144)
            return [p for p in decode(raw)["items"] if "deletionTimestamp" not in p["metadata"]]
        except (Refused, StateRefused, ValueError, TypeError, KeyError):
            return None

    def per_member(self, labels):
        """`{member, pod, ready}` per replica member for a DaemonSet's pods."""
        pods = self.pods(labels)
        out = []
        for m in self.recipe["members"]:
            found = [p for p in pods or () if (p.get("spec") or {}).get("nodeName") == m["member"]]
            ready = len(found) == 1 and any(c.get("type") == "Ready" and c.get("status") == "True" for c in
                                            (found[0].get("status") or {}).get("conditions") or ())
            out.append({"member":m["member"], "pod":found[0]["metadata"]["name"] if len(found) == 1 else None,
                        "ready":ready if pods is not None else None})
        return out

    def target(self):
        """The writer's member: the new writer that `expected.device` names at `move`, else the recipe's."""
        r = self.recipe
        for m, d in zip(r["members"], r["devices"] or ()):
            if r["stage"] == "move" and self.expected["device"] is not None and d["device_id"] == self.expected["device"]:
                return m["member"]
        return r["writer"]

    def writer(self):
        """The writer Deployment's class and process, as far as this body reads them."""
        try:
            obj = self.get("deployments.apps", "broil-registry")
        except (Refused, StateRefused, ValueError):
            obj = False
        if obj is None or obj is False:
            return {"class":"absent" if obj is None else "unobservable", "uid":None, "generation":None,
                    "process":{"state":"not-ready", "node":None}}
        meta = obj.get("metadata") or {}
        owned = (meta.get("annotations") or {}).get("broil.dev/owner") == self.recipe["owner"] and \
            meta.get("labels") == SERVICE
        pods = self.pods(SERVICE) or []
        running = [p for p in pods if (p.get("status") or {}).get("phase") == "Running"]
        ready = len(running) == 1 and running[0]["spec"].get("nodeName") == self.target() and any(
            c.get("type") == "Ready" and c.get("status") == "True" for c in running[0]["status"].get("conditions") or ())
        return {"class":"owned" if owned else "foreign", "uid":meta.get("uid"), "generation":meta.get("generation"),
                "process":{"state":"ready" if ready else "not-ready",
                           "node":running[0]["spec"].get("nodeName") if len(running) == 1 else None}}

    def nodes(self):
        """The per-member node facts."""
        try:
            rows = [line.split("\t") for line in self.kubectl("get", "nodes", "-o", "jsonpath=" + NODES,
                                                               limit=524288).decode().splitlines()]
        except (Refused, StateRefused, UnicodeDecodeError) as error:
            state_require(getattr(error, "failure", None) != "bound", "bound")
            rows = None
        found = {row[0]:row for row in rows or () if len(row) == 4}
        return [{"member":m["member"], "node":"unobservable" if rows is None else
                 "not-ready" if m["member"] not in found else
                 "drifted" if found[m["member"]][1] != m["node_uid"] else
                 "ready" if found[m["member"]][3] == "True" and found[m["member"]][2] != "true" else "not-ready"}
                for m in self.recipe["members"]]

    def inspect_objects(self, result):
        """The API facts; with `wait_ms`, the wait for the writer process on its node."""
        until = time.monotonic() + min((self.header["wait_ms"] or 0) / 1000, DEADLINE - time.monotonic() - 5)
        while True:
            writer = self.writer()
            if writer["process"]["state"] == "ready" or time.monotonic() + 2 > until:
                break
            time.sleep(2)
        result.update(objects=self.objects(), readers=self.per_member(READER), tokens=self.per_member(TOKEN),
                      writer=writer, node=self.nodes())

    def create_object(self, result):
        """`create-object`: the selected absent reader object, created once, printing its UID."""
        res = self.header["resource"]
        state_require(isinstance(res, dict) and res.get("id") in ("registry-reader-object-01", "registry-reader-object-02")
                      and res.get("uid") is None, "ownership")
        n = int(res["id"][-1]) - 1
        objects = self.objects()
        state_require("unobservable" not in [x["class"] for x in objects], "readiness")
        state_require(objects[n]["class"] == "absent" and (not n or objects[0]["class"] == "owned"), "ownership")
        state_require(DEADLINE - time.monotonic() >= 50, "timeout")
        self.begin()
        self.effect_started = True
        uid = self.kubectl("create", "-f", "-", "-o", "jsonpath={.metadata.uid}", input=canonical(self.renders()[n]) + b"\n",
                           limit=512, timeout="40s", seconds=45, mutating=True).decode()
        state_require(opaque(uid))
        self.done(result, uid)

    def patch(self, kind, name, operations):
        self.kubectl("patch", kind, name, "-n", "broil-registry", "--type=json", "-p", json.dumps(operations),
                     limit=4096, mutating=True)

    def configure_reader(self, result):
        """The change rule: one read-and-test patch of the ConfigMap's data, then each reader pod's eviction."""
        objects, data = self.objects(), self.renders()[0]["data"]
        state_require(objects[1]["class"] == "owned" and objects[0]["class"] in ("owned", "owned-drifted") and
                      objects[0]["uid"] == self.expected["objects"][0], "ownership")
        pods = self.pods(READER)
        state_require(pods is not None, "readiness")
        self.begin()
        self.effect_started = True
        self.patch("configmaps", "broil-registry-reader", [{"op":"test", "path":"/metadata/uid", "value":objects[0]["uid"]},
                                                           {"op":"replace", "path":"/data", "value":data}])
        for pod in pods:
            name = pod["metadata"]["name"]
            self.kubectl("create", "--raw", "/api/v1/namespaces/broil-registry/pods/%s/eviction" % name, "-f", "-",
                         input=canonical({"apiVersion":"policy/v1", "kind":"Eviction", "metadata":{
                             "name":name, "namespace":"broil-registry"}, "deleteOptions":{"preconditions":{
                                 "uid":pod["metadata"]["uid"]}}}), limit=65536, mutating=True)
        self.done(result)

    def move(self, result):
        """`stop-writer` and `start-writer`: one read-and-test patch testing the UID and the expected generation,
        then the wait for no running writer pod, or the new writer's node selector and one replica."""
        writer, generation = self.writer(), self.expected["writer_generation"]
        state_require(writer["class"] == "owned" and generation is not None, "ownership")
        state_require(writer["generation"] == generation, "ownership")
        tests = [{"op":"test", "path":"/metadata/uid", "value":writer["uid"]},
                 {"op":"test", "path":"/metadata/generation", "value":generation}]
        self.begin()
        self.effect_started = True
        if self.tag == "stop-writer":
            self.patch("deployments.apps", "broil-registry", tests + [{"op":"replace", "path":"/spec/replicas", "value":0}])
            until = time.monotonic() + min((self.header["wait_ms"] or 0) / 1000, DEADLINE - time.monotonic() - 5)
            while [p for p in self.pods(SERVICE) or [None] if p is None or (p.get("status") or {}).get("phase") == "Running"]:
                state_require(time.monotonic() + 2 <= until, "timeout")
                time.sleep(2)
        else:
            self.patch("deployments.apps", "broil-registry", tests + [
                {"op":"replace", "path":"/spec/template/spec/nodeSelector/kubernetes.io~1hostname", "value":self.target()},
                {"op":"replace", "path":"/spec/replicas", "value":1}])
        self.done(result)

    def run(self, result):
        if self.tag == "inspect-replication":
            result["replication"] = self.facts()
            return
        if self.tag == "inspect-objects":
            self.inspect_objects(result)
            return
        previous = self.previous()
        if previous is not None:
            result["terminal"] = previous
            return
        {"create-replication":self.create_replication, "create-replica":self.create_replica,
         "configure-replication":self.configure, "remove-device":self.configure, "scan-replica":self.scan,
         "revert-replica":self.scan, "stop-replication":self.stop, "create-object":self.create_object,
         "configure-reader":self.configure_reader, "stop-writer":self.move, "start-writer":self.move}[self.tag](result)


# ---- The delivery protocol ----
DELIVERY_TAGS = ("inspect-images", "check-closure", "pull-image", "pin-image", "unpin-image", "read-origin-log")
PIN = "io.cri-containerd.pinned=pinned"


class Bearer:
    """One member's local reader through its loopback token service, with the node-pull credentials."""

    def __init__(self, username, password, until):
        self.username, self.password, self.until, self.tokens = username, password, until, {}

    def request(self, port, method, target, headers):
        bound = max(0.2, min(10, self.until - time.monotonic()))
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=bound)
        try:
            connection.request(method, target, headers=headers)
            response = connection.getresponse()
            body = response.read(4194305) if method == "GET" else b""
            return response.status, response, body
        finally:
            connection.close()

    def token(self, challenge, name):
        """A pull-scoped token for `name` from the challenge's loopback realm, or None when refused."""
        fields = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
        realm = fields.get("realm", "")
        if not challenge.startswith("Bearer ") or not realm.startswith("http://127.0.0.1:5598/"):
            return None
        query = "service=%s&scope=%s" % (quote(fields.get("service", ""), safe=""),
                                         quote("repository:%s:pull" % name, safe=""))
        credential = bytearray(self.username.encode() + b":" + self.password)
        try:
            basic = base64.b64encode(bytes(credential)).decode()
        finally:
            credential[:] = b"\0" * len(credential)
        status, _, body = self.request(5598, "GET", urlsplit(realm).path + "?" + query,
                                       {"Authorization":"Basic " + basic})
        if status != 200:
            return None
        value = decode(body)
        return value.get("token") or value.get("access_token")

    def fetch(self, method, name, kind, ref, accept=None):
        """One reader request with the repository's token; 401 after a refused token is `authorization`."""
        target = "/v2/%s/%s/%s" % (name, kind, ref)
        headers = {"Accept":accept} if accept else {}
        for _ in range(2):
            if name in self.tokens:
                headers["Authorization"] = "Bearer " + self.tokens[name]
            status, response, body = self.request(5599, method, target, headers)
            if status != 401 or name in self.tokens:
                return status, response, body
            token = self.token(response.getheader("WWW-Authenticate") or "", name)
            if token is None:
                raise StateRefused("authorization")
            self.tokens[name] = token
        return status, response, body


def descriptor(value):
    state_require(isinstance(value, dict) and isinstance(value.get("digest"), str) and DIGEST.fullmatch(value["digest"])
                  and type(value.get("size")) is int)
    return value["digest"], value["size"]


class DeliveryReceiver(Receiver):
    FAMILY, LIMIT = "delivery", 49152

    @staticmethod
    def admit(header, tag):
        """Every delivery action names its recipient member."""
        state_require(isinstance(header["member"], str) and isinstance(header["expected"], dict), "ownership")

    def recheck(self):
        """An apply or rollback recheck's `inspect-images` under the release recipe, its
        recipient a required member and `expected` at most 32 bound references."""
        r, b, e, tag = self.recipe, self.binding, self.expected, self.tag
        state_fields(r, "scope owner operation cluster action api_server release release_sha256 application namespace "
                        "required excluded objects_sha256 chunks secrets hooks settles version profile_sha256")
        state_cluster(r["cluster"])
        member = self.header["member"]
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      tag == "inspect-images" and isinstance(r["required"], list) and
                      member == self.member["member"] and member in r["required"] and
                      set(e) == {"references"} and isinstance(e["references"], list) and
                      0 < len(e["references"]) <= 32 and len(set(e["references"])) == len(e["references"]) and
                      all(isinstance(x, str) and DIGEST.fullmatch(x.rpartition("@")[2]) for x in e["references"]),
                      "ownership")
        self.platform = None

    def check(self, profile):
        """The recipe; the recipient listed for the action and `expected` exactly the action's."""
        r, b, e, tag = self.recipe, self.binding, self.expected, self.tag
        if isinstance(r, dict) and r.get("action") in ("release-apply", "release-rollback"):
            return self.recheck()
        state_fields(r, "scope owner operation cluster action release release_sha256 writer fallback members excluded "
                        "images unpin profile_sha256")
        state_cluster(r["cluster"])
        for m in r["members"] if isinstance(r["members"], list) else [None]:
            state_fields(m, "member role platform")
        for i in r["images"] if isinstance(r["images"], list) else [None]:
            state_fields(i, "image artifact reference repository root managed platforms")
            for p in i["platforms"] if isinstance(i["platforms"], list) else [None]:
                state_fields(p, "platform manifest config")
        for u in r["unpin"] if isinstance(r["unpin"], list) else [None]:
            state_fields(u, "member references")
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      r["action"] in ("release-deliver", "release-retain") and
                      r["fallback"] in (None, "disabled", "same-origin") and isinstance(r["excluded"], list) and
                      all(i["reference"] == i["repository"] + "@" + i["root"] and DIGEST.fullmatch(i["root"]) and
                          type(i["managed"]) is bool for i in r["images"]), "ownership")
        member, deliver = self.header["member"], r["action"] == "release-deliver"
        listed = {m["member"]:m for m in r["members"]}
        state_require(member == self.member["member"] and (
            member == r["writer"] if tag == "read-origin-log" else member in listed) and
            (deliver or tag in ("inspect-images", "unpin-image")) and (not deliver or tag != "unpin-image"), "ownership")
        self.platform = listed[member]["platform"] if member in listed else None
        images = {i["reference"]:i for i in r["images"]}
        configs = {i["reference"]:{p["platform"]:p for p in i["platforms"]} for i in r["images"]}
        unpinned = [x for u in r["unpin"] if u["member"] == member for x in u["references"]]
        fits = lambda value, names: isinstance(value, dict) and set(value) == set(names.split())
        if tag in ("inspect-images", "unpin-image"):
            wanted = unpinned if tag == "unpin-image" else list(images) + unpinned
            ok = fits(e, "references") and isinstance(e["references"], list) and e["references"] and \
                len(set(e["references"])) == len(e["references"]) and set(e["references"]) <= set(wanted)
        elif tag == "read-origin-log":
            ok = fits(e, "since_ms repositories digests") and type(e["since_ms"]) is int and \
                isinstance(e["repositories"], list) and set(e["repositories"]) <= {i["repository"] for i in r["images"]} \
                and isinstance(e["digests"], list) and all(
                    fits(d, "digest size") and isinstance(d["digest"], str) and DIGEST.fullmatch(d["digest"]) and
                    type(d["size"]) is int and d["size"] >= 0 for d in e["digests"])
        else:
            names = {"check-closure":"platform images", "pull-image":"platform images", "pin-image":"images"}[tag]
            fields = "reference repository root manifest config" if tag == "check-closure" else "reference config"
            platform = e.get("platform", self.platform) if isinstance(e, dict) else None
            ok = fits(e, names) and platform == self.platform and isinstance(e["images"], list) and e["images"] and all(
                fits(x, fields) and x["reference"] in images and platform in configs[x["reference"]] and
                x["config"] == configs[x["reference"]][platform]["config"] and
                (tag != "check-closure" or images[x["reference"]]["managed"] and
                 [x["repository"], x["root"], x["manifest"]] == [images[x["reference"]]["repository"],
                                                                 images[x["reference"]]["root"],
                                                                 configs[x["reference"]][platform]["manifest"]])
                for x in e["images"])
        state_require(ok, "ownership")
        if not tag.startswith(READS):
            state_require(DEADLINE - time.monotonic() >= 30, "timeout")

    # ---- CRI facts and effects ----
    def image(self, reference):
        """`crictl inspecti` of one reference: (image ID, repoDigests match, pinned), or None when absent."""
        out = self.runtime("crictl", "inspecti", "-o", "json", reference, probe=True)
        state_require(out is not None, "transport")
        if out[0]:
            return None
        status = decode(out[1])["status"]
        state_require(isinstance(status.get("id"), str) and isinstance(status.get("repoDigests"), list))
        return status["id"], reference in status["repoDigests"], status.get("pinned") is True

    def label(self, reference, value):
        self.runtime("ctr", "-n", "k8s.io", "images", "label", reference, "io.cri-containerd.pinned=" + value,
                     mutating=True)

    def pinned(self, reference):
        """`crictl images -o json` reports the reference's image `pinned`."""
        images = decode(self.runtime("crictl", "images", "-o", "json"))["images"]
        return any(isinstance(i, dict) and reference in (i.get("repoDigests") or ()) and i.get("pinned") is True
                   for i in images)

    def inspect_images(self, result):
        machine = os.uname().machine
        result["node"] = {"architecture":{"x86_64":"amd64", "aarch64":"arm64"}.get(machine, machine),
                          "counters":self.counters()}
        result["images"] = []
        for reference in self.expected["references"]:
            found = self.image(reference)
            result["images"].append({"reference":reference, "present":found is not None,
                                     "image_id":found[0] if found else None, "repo_digests_match":bool(found and found[1]),
                                     "pinned":bool(found and found[2])})

    def pull(self, result):
        """The pull: at most three attempts 10 seconds apart, then the image ID against the config digest."""
        global EFFECTS
        self.begin()
        result["images"] = []
        for x in self.expected["images"]:
            entry = {"reference":x["reference"], "image_id":None, "attempts":0, "failed":None}
            result["images"].append(entry)
            while True:
                if entry["attempts"]:
                    time.sleep(10)
                entry["attempts"] += 1
                self.effect_started = EFFECTS = True
                out = self.runtime("crictl", "pull", x["reference"], probe=True, mutating=True,
                                   seconds=max(1, DEADLINE - time.monotonic() - 2))
                if out is not None and out[0] == 0:
                    break
                if entry["attempts"] == 3 or DEADLINE - time.monotonic() < 15:
                    entry["failed"] = "pull"
                    raise StateRefused("transport")
            found = self.image(x["reference"])
            entry["image_id"] = found[0] if found else None
            if not found or not found[1] or found[0] != x["config"]:
                # A partial pull leaves only unpinned content.
                entry["failed"], self.partial = "digest", True
                raise StateRefused("integrity")
        self.done(result)

    def pin(self, result):
        """The pin, idempotent; another target refuses `ownership` with no change."""
        global EFFECTS
        found = [self.image(x["reference"]) for x in self.expected["images"]]
        state_require(all(f is not None and f[1] and f[0] == x["config"] for f, x in zip(found, self.expected["images"])),
                      "ownership")
        self.begin()
        for f, x in zip(found, self.expected["images"]):
            if not f[2]:
                self.effect_started = EFFECTS = True
                self.label(x["reference"], "pinned")
            state_require(self.pinned(x["reference"]), "integrity")
        self.done(result)

    def unpin(self, result):
        """Exactly the pin label removed, nothing deleted; an absent or unpinned image is a no-op."""
        global EFFECTS
        self.begin()
        for reference in self.expected["references"]:
            found = self.image(reference)
            if found is not None and found[2]:
                self.effect_started = EFFECTS = True
                self.label(reference, "")
                after = self.image(reference)
                state_require(after is not None and not after[2], "integrity")
        self.done(result)

    # ---- The closure check ----
    def credentials(self):
        """The node-pull username and the current generation's password of the managed origin's entry."""
        authority = self.expected["images"][0]["repository"].split("/", 1)[0]
        record = state_read(self.owner_path + "/node/registries.json")
        entry = ((record or {}).get("entries") or {}).get(authority)
        state_require(isinstance(entry, dict) and isinstance(entry.get("resource"), dict), "readiness")
        g = entry["resource"]
        state_require(opaque(g.get("id")) and isinstance(g.get("generation"), str) and
                      re.fullmatch("[0-9a-f]{32}", g["generation"]) is not None, "readiness")
        try:
            parent = state_directory("%s/resources/%s/%s" % (self.owner_path, g["id"], g["generation"]))
            try:
                fd = os.open("password", os.O_RDONLY | NOFOLLOW, dir_fd=parent)
            finally:
                os.close(parent)
        except FileNotFoundError:
            raise StateRefused("readiness")
        try:
            st = state_private(fd)
            state_require(0 < st.st_size <= 4096, "readiness")
            password = bytearray(os.read(fd, 4097))
        finally:
            os.close(fd)
        username = ""
        try:
            value = decode(read_file(REGISTRIES, 65536))
            username = value["configs"]["127.0.0.1:5599"]["auth"]["username"]
        except (OSError, ValueError, TypeError, KeyError, Refused):
            pass
        return str(username), password

    def closure_one(self, reader, x):
        """For one image: the first missing digest class, or None when replica-ready."""
        os_name, arch = self.platform.split("/")[:2]
        name = x["repository"].split("/", 1)[1]
        try:
            status, response, body = reader.fetch("GET", name, "manifests", x["root"], ACCEPT)
            if status != 200 or len(body) > 4194304 or "sha256:" + hashlib.sha256(body).hexdigest() != x["root"]:
                return "root"
            root = decode(body)
            if isinstance(root.get("manifests"), list) or root.get("mediaType") in INDEX_TYPES:
                chosen = [descriptor(d)[0] for d in root["manifests"] if isinstance(d, dict) and
                          (d.get("platform") or {}).get("os") == os_name and
                          (d.get("platform") or {}).get("architecture") == arch]
                if chosen != [x["manifest"]]:
                    return "root"
                status, response, body = reader.fetch("GET", name, "manifests", x["manifest"], ACCEPT)
                if status != 200 or len(body) > 4194304 or "sha256:" + hashlib.sha256(body).hexdigest() != x["manifest"]:
                    return "manifest"
            elif x["root"] != x["manifest"]:
                return "root"
            manifest = decode(body)
            config = descriptor(manifest["config"])
            if len(manifest["layers"]) > 1024:
                return "layer"
            layers = [descriptor(d) for d in manifest["layers"]]
        except StateRefused as error:
            if error.failure == "authorization":
                return "authorization"
            return "manifest"
        except (OSError, ValueError, TypeError, KeyError, AttributeError, Refused, http.client.HTTPException):
            return "root"
        for kind, (blob, size) in [("config", config)] + [("layer", d) for d in layers]:
            if kind == "config" and blob != x["config"]:
                return "config"
            try:
                status, response, _ = reader.fetch("HEAD", name, "blobs", blob)
            except StateRefused:
                return "authorization"
            except (OSError, http.client.HTTPException):
                return kind
            if status != 200 or response.getheader("Content-Length") != str(size):
                return kind
        return None

    def check_closure(self, result):
        """The replica-ready check, re-checked every 2 seconds until ready or the wait deadline."""
        username, password = self.credentials()
        until = min(time.monotonic() + (self.header["wait_ms"] or 0) / 1000, DEADLINE - 5)
        try:
            while True:
                reader = Bearer(username, password, until)
                missing = [{"reference":x["reference"], "class":c} for x in self.expected["images"]
                           for c in [self.closure_one(reader, x)] if c is not None]
                if not missing or time.monotonic() + 2 > until:
                    break
                time.sleep(2)
        finally:
            password[:] = b"\0" * len(password)
        result["closure"] = {"ready":not missing, "missing":missing, "counters":self.counters()}

    def read_origin_log(self, result):
        """The aggregate of the writer Distribution's counted access-log lines since `since_ms`, never the lines."""
        e = self.expected
        since, sizes = e["since_ms"], {d["digest"]:d["size"] for d in e["digests"]}
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(since // 1000)) + ".%03dZ" % (since % 1000)
        log = {"complete":False, "requests":0, "bytes":0, "all_sized":True, "estimate_bytes":0}
        result["log"] = log
        try:
            raw = self.kubectl("logs", "-n", "broil-registry", "deployment/broil-registry", "--timestamps",
                               "--since-time=" + stamp, limit=4194304, seconds=25)
        except StateRefused as error:
            if error.failure != "bound":
                raise
            return
        for line in raw.decode("utf-8", "replace").splitlines():
            when, _, text = line.partition(" ")
            whole, _, fraction = when.rstrip("Z").partition(".")
            try:
                ms = calendar.timegm(time.strptime(whole, "%Y-%m-%dT%H:%M:%S")) * 1000 + int((fraction + "000")[:3])
            except ValueError:
                continue
            access = ACCESS.match(text)
            path = TARGET.match(access[2]) if access else None
            if ms < since or path is None or path[3] not in sizes or not 200 <= int(access[3]) < 300 or not any(
                    repository.split("/", 1)[-1] == path[1] for repository in e["repositories"]):
                continue
            log["requests"] += 1
            if access[4] == "-":
                log["all_sized"] = False
            else:
                log["bytes"] += int(access[4])
            if access[1] == "GET":
                log["estimate_bytes"] += sizes[path[3]]
        log["complete"] = True

    def run(self, result):
        reads = {"inspect-images":self.inspect_images, "check-closure":self.check_closure,
                 "read-origin-log":self.read_origin_log}
        if self.tag in reads:
            reads[self.tag](result)
            return
        previous = self.previous()
        if previous is not None:
            result["terminal"] = previous
            return
        {"pull-image":self.pull, "pin-image":self.pin, "unpin-image":self.unpin}[self.tag](result)


# Each protocol's receiver, tags, result facts and reply reserve.
PROTOCOLS = {"broil-k3s-registry-replication":(ReplicationReceiver, REPLICATION_TAGS,
                                               ("replication", "objects", "readers", "tokens", "writer", "node",
                                                "cordoned"), 16384),
             "broil-k3s-delivery":(DeliveryReceiver, DELIVERY_TAGS, ("node", "images", "closure", "log"), 8192)}
MAGIC = b"BK3SRRP1\n"


def delivery_request(raw, header):
    """One protocol's header."""
    global DEADLINE
    state_require(isinstance(header, dict) and header.get("protocol") in PROTOCOLS, "integrity")
    kind, tags, _, reserve = PROTOCOLS[header["protocol"]]
    state_require(17 + len(raw) + reserve <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms wait_ms recipe expected resource "
                         "preflight member")
    state_require(canonical(header) == raw, "integrity")
    state_require(type(header["version"]) is int and header["version"] == 1,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
    tag = header["action"]
    state_require(tag in tags, "capability")
    mutation = not tag.startswith(READS)
    state_hex(header["request_id"])
    state_binding(header["binding"])
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation, "ownership")
    state_require(header["wait_ms"] is None or type(header["wait_ms"]) is int and 0 <= header["wait_ms"] <= 7200000,
                  "ownership")
    state_require(header["member"] is None or opaque(header["member"]), "ownership")
    state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(header["recipe"])) <= kind.LIMIT, "bound")
    state_require(isinstance(header["recipe"], dict), "integrity")
    kind.admit(header, tag)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    state_require(sys.stdin.buffer.read(1) == b"", "integrity")


def delivery_main(raw, header):
    protocol = header.get("protocol") if isinstance(header, dict) else None
    kind, _, facts, _ = PROTOCOLS.get(protocol, PROTOCOLS["broil-k3s-registry-replication"])
    receiver = None
    status = "unknown"
    result = {"terminal":None, **dict.fromkeys(facts), "failure":None}
    prefix = MAGIC + struct.pack(">I", len(raw)) + raw
    try:
        delivery_request(raw, header)
        receiver = kind(header)
        receiver.profile()
        receiver.open()
        receiver.owned()
        receiver.run(result)
        status = "ok"
    except Exception as error:
        failure = (error.failure if isinstance(error, StateRefused) else
                   "timeout" if isinstance(error, subprocess.TimeoutExpired) else
                   "transport" if isinstance(error, (subprocess.SubprocessError, http.client.HTTPException)) else
                   "storage" if isinstance(error, OSError) else "integrity")
        result["failure"] = failure
        status = ("unknown" if EFFECTS else "busy" if failure == "busy" else
                  "unsupported-version" if failure == "unsupported-version" else
                  "bound" if failure == "bound" else "refused")
        if receiver is not None and receiver.published is not None:
            result["terminal"] = receiver.published
            status = "unknown"
        elif receiver is not None and receiver.intent is not None:
            try:
                result["terminal"] = receiver.terminal("failed", failure, header["resource"])
                status = "failed"
            except BaseException:
                status = "unknown"
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root, receiver.executable):
                if fd is not None:
                    os.close(fd)
    # A failed mutation keeps its per-image facts; every other non-`ok` reply carries none.
    if status not in ("ok", "failed"):
        result.update(dict.fromkeys(facts))
    body = canonical({"kind":"result", "status":status, **result})
    complete = prefix + struct.pack(">I", len(body)) + body
    if len(complete) > 65536:
        os._exit(125)
    sys.stdout.buffer.write(complete)
    sys.stdout.buffer.flush()


try:
    os.umask(0o077)
    length = struct.unpack(">I", read_exact(4))[0]
    require(0 < length <= 65536, 4)
    raw = read_exact(length)
    header = decode(raw)
    require(isinstance(header, dict) and header.get("protocol") in PROTOCOLS, 4)
    delivery_main(raw, header)
    os._exit(0)
except Exception:
    os._exit(125)
