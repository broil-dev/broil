#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, profile-bound K3s node-operations family receiver."""
import base64
import calendar
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import stat
import struct
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT = "/var/lib/broil/k3s"
PROFILE = ROOT + "/action-profile.json"
K3S = "/usr/local/libexec/broil-k3s"
DATA = "/var/lib/rancher/k3s"
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
            bound=False, probe=False, argv0=None):
    """Run the pinned executable; a probe returns (exit, stdout, stderr), or None when its own bound expires."""
    global WRITERS_SETTLED
    require(time.monotonic() < DEADLINE, 6)
    process = subprocess.Popen([argv0 or f"/proc/self/fd/{fd}", *args], executable=f"/proc/self/fd/{fd}", pass_fds=(fd,),
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
    "node-registries": "owner operation entries",
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


def state_publish(path, record, expected=None, encode=canonical):
    global EFFECTS
    state_value(record)
    raw = encode(record) + b"\n"
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

# The profile bodies.
BODIES = {"control", "lifecycle", "network", "ingress", "cert_manager", "registry", "node", "delivery", "release", "service_guard"}
# The actions: the reads and the one mutation.
READS = ("inspect-member", "observe-node", "observe-drain")
# Each member action and the member recipe actions that may carry it; `start-member` runs
# only under the agent-join recipe.
MEMBER_TAGS = {"cordon":("node-drain",), "uncordon":("node-uncordon",), "observe-drain":("node-drain", "node-remove"),
               "evict":("node-drain",), "delete-node":("node-remove",), "stop-member":("node-remove",),
               "start-member":()}
TAGS = READS + ("restart", "configure-registries", *MEMBER_TAGS)
UNITS = {"server":"broil-k3s.service", "agent":"broil-k3s-agent.service"}
REPLICATION = "broil-k3s-replication.service"
UNIT_DIR = "/etc/systemd/system/"
SYSTEMCTL = "/usr/bin/systemctl"
PYTHON = "/usr/bin/python3"
WAIT_MS = 25000
WITNESS = ("InvocationID", "ActiveState", "SubState", "Result", "NRestarts")
# A Node's fixed projection; labels and taints as the agent view projects them.
NODE_FIELDS = ('{{.metadata.uid}}{{"\\t"}}{{.status.nodeInfo.kubeletVersion}}{{"\\t"}}{{range .status.conditions}}'
               '{{if eq .type "Ready"}}{{.status}}{{end}}{{end}}{{"\\t"}}{{range $k, $v := .metadata.labels}}{{$k}}={{$v}} '
               '{{end}}{{"\\t"}}{{range .spec.taints}}{{.key}}={{with .value}}{{.}}{{end}}:{{.effect}} {{end}}')
SYSTEM_LABELS = ("kubernetes.io/", "node.kubernetes.io/", "beta.kubernetes.io/", "k3s.io/", "node-role.kubernetes.io/")


def named(value):
    """A member name within the declaration's 253 bytes."""
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", value) is not None


# Classification and naming pages of 70 pods, eviction pages of 32.
PAGE, EVICT_PAGE = 70, 32


def pod_key(p, name="pod"):
    """A pod's bytewise `(namespace, pod)` order."""
    return p["namespace"].encode(), p[name].encode()


def node_plan(plan, configure):
    """The plan: servers, then agents, each named once, and the agents chunked into waves of `wave_width`; a
    configure plan's members also carry `registries_sha256`."""
    state_fields(plan, "members wave_width waves profile_sha256")
    members = plan["members"]
    state_require(isinstance(members, list) and 1 <= len(members) <= 128, "bound")
    for m in members:
        state_fields(m, "member role recipe_identity_sha256" + " registries_sha256" * configure)
        state_require(named(m["member"]) and m["role"] in ("server", "agent"))
        state_hex(m["recipe_identity_sha256"], 64)
        if configure:
            state_hex(m["registries_sha256"], 64)
    roles = [m["role"] for m in members]
    servers = roles.count("server")
    names = [m["member"] for m in members]
    state_uint(plan["wave_width"], 1, 16)
    state_hex(plan["profile_sha256"], 64)
    width, agents = plan["wave_width"], names[servers:]
    state_require(servers >= 1 and roles == ["server"] * servers + ["agent"] * len(agents) and len(set(names)) == len(names) and
                  plan["waves"] == [agents[i:i + width] for i in range(0, len(agents), width)], "ownership")


def healthy(seconds):
    """The local kubelet health endpoint answers `ok` within one poll's bound."""
    end, reply = time.monotonic() + seconds, b""
    try:
        with socket.create_connection(("127.0.0.1", 10248), timeout=seconds) as connection:
            connection.sendall(b"GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
            while len(reply) <= 4096 and time.monotonic() < end:
                connection.settimeout(max(0.001, end - time.monotonic()))
                chunk = connection.recv(4097 - len(reply))
                if not chunk:
                    break
                reply += chunk
    except OSError:
        return False
    head, _, body = reply.partition(b"\r\n\r\n")
    return len(reply) <= 4096 and head.split(b" ")[1:2] == [b"200"] and body == b"ok"


def renewed(text, after_ms):
    """A Lease `renewTime` strictly later than any instant of the receipt's millisecond."""
    m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?Z", text)
    if m is None:
        return "not-ready"
    try:
        seconds = calendar.timegm(tuple(int(x) for x in m.groups()[:6]))
    except ValueError:
        return "unobserved"
    micros = seconds * 1000000 + int((m.group(7) or "0").ljust(6, "0")[:6])
    return "ready" if micros >= (after_ms + 1) * 1000 else "not-ready"

# The rendered file, its YAML-safe encoder and its classification.
REGISTRIES = "/etc/rancher/k3s/registries.yaml"
ENTRIES = "broil-k3s-node-registries-v2"
LOOPBACK, LOOPBACK_KEY = "http://127.0.0.1:5599", "127.0.0.1:5599"
LOOPBACKS = {("127.0.0.1", 5599), ("localhost", 5599), ("::1", 5599)}
YAML = {c:"\\u%04x" % c for c in (*range(0x7f, 0xa0), 0x2028, 0x2029, 0xfeff, 0xfffe, 0xffff)}
UNSAFE = frozenset((*range(8), 11, *range(14, 32), 127))
NUMBER = object()


def yaml_safe(value):
    """The encoder: canonical JSON with each code point that a YAML reader refuses or folds escaped."""
    return canonical(value).decode().translate(YAML).encode()


def authority(text):
    """A key's (host, port) as they are compared: lowercase, a trailing dot removed and IPv6 as an address."""
    if text.startswith("["):
        host, _, port = text[1:].partition("]")
        port = port[1:]
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
    else:
        host, port = text, ""
    host = host.lower()[:-1] if host.endswith(".") else host.lower()
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        pass
    return host, int(port) if port.isdigit() else port or None


def endpoint_host(url):
    """An endpoint URL's host as it is compared, or None without an `http` or `https` scheme and a host."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not host:
        return None
    return authority("[%s]" % host if ":" in host else host)[0]


def endpoint_loopback(url):
    """Whether an endpoint URL's authority is the loopback key or its `localhost` or `[::1]` spelling."""
    try:
        port = urlsplit(url).port
    except ValueError:
        return False
    return (endpoint_host(url), port) in LOOPBACKS


def scan(value, depth=0):
    """The first refusal check over a decoded value (`bound`); returns whether a number, a lone surrogate, a key over
    1024 characters or a containerd-unsafe character makes the second refuse `ownership`."""
    state_require(depth <= 16, "bound")
    if isinstance(value, str):
        state_require("\0" not in value and len(value.encode("utf-8", "surrogatepass")) <= 4096, "bound")
        return any(ord(c) in UNSAFE or 0xd800 <= ord(c) < 0xe000 for c in value)
    if not isinstance(value, (dict, list)):
        return value is NUMBER
    state_require(depth < 16 and len(value) <= 4096, "bound")
    found = False
    for key in value if isinstance(value, dict) else ():
        found |= scan(key, depth + 1) or len(key) > 1024
    for item in value.values() if isinstance(value, dict) else value:
        found |= scan(item, depth + 1)
    return found


def node_entries(entries):
    """The member entries: one to eight, each exactly its closed fields, under distinct keys."""
    state_require(isinstance(entries, list) and 1 <= len(entries) <= 8, "bound")
    for e in entries:
        state_fields(e, "registry authority origin managed username fallback principal resource ca")
        for g in (e["resource"],) + (() if e["principal"] is None else (e["principal"],)):
            state_fields(g, "id generation")
            state_require(opaque(g["id"]))
            state_hex(g["generation"])
        state_require(opaque(e["registry"]) and e["resource"]["id"] == "node-registry-" + e["registry"] and
                      all(isinstance(e[k], str) and e[k] for k in ("authority", "origin", "username")) and
                      e["fallback"] in ("disabled", "same-origin") and type(e["ca"]) is bool and
                      type(e["managed"]) is bool)
    state_require(len({e["authority"] for e in entries}) == len(entries))


class NodeReceiver:
    """The node family's receiver framework, copied from the registry body's."""
    FAMILY, KEYS = "node", ("recipe", "expected", "wait_ms")
    render = joining = False

    def __init__(self, header):
        self.header = header
        self.binding = header["binding"]
        self.member = self.binding["recipient"]
        self.tag = header["action"]
        self.action = "lifecycle:%s-%s" % (self.FAMILY, self.tag)
        self.recipe = header["recipe"]
        self.payload = {key:header[key] for key in self.KEYS}
        self.root = self.lock = self.executable = None
        self.root_id = self.lock_id = None
        self.claim = self.reservation = self.intent = self.published = None
        self.effect_started = False
        self.effect = None
        self.owner_path = ROOT + "/owners/" + self.binding["owner"]

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
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == bodies["node"], "ownership")
        tools = self.binding["fingerprints"]["tools"]
        state_require(len(tools) == 2 and tools[0]["name"] == "bootstrap-index" and
                      tools[1] == {"name":"k3s", "sha256":profile["k3s_sha256"]}, "capability")
        self.host_profile = profile
        self.check(profile)
        if self.tag == "observe-node":
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
        exclusive = self.tag not in (*READS, "view", "access")
        try:
            fcntl.flock(self.lock, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateRefused("busy")
        self.lock_id = identity(self.lock)
        self.revalidate()
        self.claim = state_read(ROOT + "/machine-claim.json", "machine-claim")
        state_require(self.claim is not None and self.claim["scope"] == self.binding["scope"] and
                      self.claim["owner"] == self.binding["owner"] and
                      self.claim["participants_sha256"] == self.binding["participants_sha256"] and
                      self.claim["member"] == dict(self.member, **{"node_uid":self.joining} if self.joining else {}) and
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
                      record["machine"] == dict({key:self.member[key] for key in ("machine", "member", "role", "node_uid")},
                                                **{"node_uid":self.joining} if self.joining else {}) and
                      record["cluster"] in (self.recipe["cluster"], *[None] * self.render), "ownership")

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

    def begin(self):
        path = self.dispatch_path()
        previous = state_read(path + "/intent.json", "intent")
        digest_value = state_hash("broil-infra-step-v1", self.payload)
        if previous is not None:
            state_require(previous["binding"] == self.binding and previous["action"] == self.action and
                          previous["payload_sha256"] == digest_value, "ownership")
            terminal = state_read(path + "/terminal.json", "terminal")
            state_require(terminal is not None, "busy")
            return terminal
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
                       "payload_sha256":digest_value, "admitted_ms":state_now()}
        self.revalidate()
        state_publish(path + "/intent.json", self.intent)
        self.reservation["dispatches"].append(self.binding["dispatch"])
        self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        return None

    def terminal(self, outcome, failure, resource=None, uid=None):
        state_require(self.intent is not None and self.published is None and WRITERS_SETTLED, "busy")
        value = {"schema":1, "kind":"terminal", "binding":self.binding, "action":self.action,
                 "payload_sha256":self.intent["payload_sha256"], "outcome":outcome, "failure":failure,
                 "effect":self.effect or ("complete" if outcome == "succeeded" else "unknown" if self.effect_started else "absent"),
                 "writer_ended":True, "resource":resource, "resource_identity":uid, "completed_ms":state_now()}
        self.revalidate()
        state_publish(self.dispatch_path() + "/terminal.json", value)
        self.published = value
        return value

    def kubectl(self, *args, input=None, limit=MAXIMUM, seconds=20, probe=False, mutating=False, timeout="10s"):
        kubeconfig = f"{self.owner_path}/admin.yaml"
        read_file(kubeconfig, 65536)
        return command(self.executable, ["kubectl", "--kubeconfig", kubeconfig, "--request-timeout=" + timeout, *args], input,
                       limits=(limit, 65536 if probe else MAXIMUM), seconds=seconds, bound=True, probe=probe,
                       mutating=mutating)

    @staticmethod
    def admit(header, tag):
        """`expected` and `wait_ms`, non-null exactly for `observe-node`, except a configure recipe's
        `inspect-member` `expected`, exactly the recipient's entries."""
        e = header["expected"]
        if tag in MEMBER_TAGS:
            # The recorded node UID; for `evict`, one page of `{namespace, pod}` entries;
            # for `observe-drain`, the page cursor and the view.
            state_fields(e, "node_uid pods after view")
            state_require(header["wait_ms"] is None and (e["node_uid"] is None or opaque(e["node_uid"])) and
                          (e["pods"] is None) == (tag != "evict") and (e["view"] is None) == (tag != "observe-drain") and
                          e["view"] in (None, "classify", "wait", "remaining") and
                          (e["after"] is None or e["view"] in ("classify", "remaining")) and
                          (e["pods"] is None or isinstance(e["pods"], list) and e["pods"]), "ownership")
            for x in (e["pods"] or []) + [e["after"]] * (e["after"] is not None):
                state_fields(x, "namespace pod")
                state_require(named(x["namespace"]) and named(x["pod"]), "ownership")
            state_require(e["pods"] is None or len({pod_key(x) for x in e["pods"]}) == len(e["pods"]), "ownership")
            state_require(e["pods"] is None or len(e["pods"]) <= EVICT_PAGE, "bound")
            return
        if tag == "inspect-member" and "registries" in header["recipe"]:
            state_fields(e, "registries")
            node_entries(e["registries"])
            state_require(header["wait_ms"] is None, "ownership")
            return
        if tag != "observe-node":
            state_require(e is None and header["wait_ms"] is None, "ownership")
            return
        state_fields(e, "member node_uid labels taints lease_after_ms")
        state_require(header["wait_ms"] == WAIT_MS and named(e["member"]) and opaque(e["node_uid"]) and
                      (e["labels"] is None) == (e["taints"] is None), "ownership")
        for key in ("labels", "taints"):
            state_require(e[key] is None or isinstance(e[key], list) and len(e[key]) <= 1024 and
                          all(isinstance(x, str) for x in e[key]) and e[key] == sorted(e[key]), "ownership")
        state_uint(e["lease_after_ms"])

    def check(self, profile):
        """The recipe and the consistency checks: the plan, the run identity, the member and the recipient."""
        r, b = self.recipe, self.binding
        configure = "registries" in r
        state_fields(r, "scope owner operation cluster first_server version run position plan plan_sha256 member wave_end "
                        "profile_sha256" + " registries" * configure)
        state_require(configure or self.tag != "configure-registries", "ownership")
        state_cluster(r["cluster"])
        node_plan(r["plan"], configure)
        state_member(r["first_server"])
        state_member(r["member"])
        # A replacement join's pre-start render, on the unjoined member under the join.
        self.render = self.tag == "configure-registries" and r["member"]["node_uid"] is None and r["run"] == b["operation"]
        state_require(isinstance(r["run"], str) and r["run"].startswith("infra-operation-"))
        state_hex(r["run"][16:])
        plan = r["plan"]
        state_require(type(r["position"]) is int)
        state_require(0 <= r["position"] < len(plan["members"]), "ownership")
        entry, first = plan["members"][r["position"]], plan["members"][0]
        wave = [w for w in plan["waves"] if entry["member"] in w]
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      r["profile_sha256"] == plan["profile_sha256"] == b["fingerprints"]["profile_sha256"] and r["cluster"] and
                      r["version"] == profile["k3s_version"] and (r["position"] > 0 or r["run"] == r["operation"]) and
                      r["plan_sha256"] == state_hash("broil-k3s-node-%splan-v1" % ("configure-" * configure), plan) and
                      [r["member"]["member"], r["member"]["role"]] == [entry["member"], entry["role"]] and
                      [r["first_server"]["member"], r["first_server"]["role"]] == [first["member"], first["role"]] and
                      (self.render or r["member"]["node_uid"] is not None) and
                      (r["first_server"]["node_uid"] is not None or self.render and r["first_server"] == r["member"]) and
                      r["wave_end"] is (wave != [] and wave[0][-1] == entry["member"]), "ownership")
        if configure:
            node_entries(r["registries"])
            state_require(state_hash(ENTRIES, r["registries"]) == entry["registries_sha256"], "ownership")
        e = self.header["expected"]
        if self.tag == "observe-node":
            state_require(e["member"] == r["member"]["member"] and e["node_uid"] == r["member"]["node_uid"] and
                          (e["labels"] is not None) == (plan["waves"] != []) and
                          self.member == (r["member"] if entry["role"] == "server" else r["first_server"]), "ownership")
        elif self.tag != "inspect-member":
            state_require(self.member == r["member"], "ownership")
        else:
            entry = next((m for m in plan["members"] if [m["member"], m["role"]] == [self.member["member"],
                                                                                     self.member["role"]]), None)
            state_require(entry is not None and (not configure or
                                                 state_hash(ENTRIES, e["registries"]) == entry["registries_sha256"]), "ownership")
        self.entry, self.unit = entry, UNITS[entry["role"]]

    def host(self, path, *args, seconds, bound=False, mutating=False):
        """The host runner: a root-owned host executable bounded by the read's or poll's clock; None when cut off."""
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            value = os.fstat(fd)
            state_require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022, "ownership")
            return command(fd, list(args), limits=(4096, 4096), argv0=path, seconds=seconds, bound=bound, probe=True,
                           mutating=mutating)
        finally:
            os.close(fd)

    def witness(self, seconds, bound=False):
        """The unit witness, or None when unreadable."""
        out = self.host(SYSTEMCTL, "show", *[x for key in WITNESS for x in ("-p", key)], "--", self.unit, seconds=seconds,
                        bound=bound)
        if out is None or out[0] != 0:
            return None
        fields = dict(line.split("=", 1) for line in out[1].decode("ascii", "replace").splitlines() if "=" in line)
        if set(fields) != set(WITNESS) or not re.fullmatch("([0-9a-f]{32})?", fields["InvocationID"]) or not \
                all(re.fullmatch("[a-z-]{1,32}", fields[k]) for k in WITNESS[1:4]) or not re.fullmatch("[0-9]{1,9}", fields["NRestarts"]):
            return None
        return {"name":self.unit, "active":fields["ActiveState"], "sub":fields["SubState"], "result":fields["Result"],
                "invocation":fields["InvocationID"] or None, "previous_invocation":None, "n_restarts":int(fields["NRestarts"])}

    def inspect(self):
        """`inspect-member`: published ownership, the activation's role and identity, the guard's hash, the unit
        witness, and the installed guard run as the unit's `ExecStartPre` runs it."""
        state_require(self.member["node_uid"] is not None, "ownership")
        agent, s = self.entry["role"] == "agent", self.owner_path + "/service"
        try:
            record = state_read(s + "/activation.json", schema=3 if agent else 2)
        except StateRefused:
            # The other role's record is no activation of this role; anything else keeps its class.
            state_read(s + "/activation.json", schema=2 if agent else 3)
            raise StateRefused("ownership")
        state_require(isinstance(record, dict) and record.get("kind") == ("agent-activation" if agent else "server-activation") and
                      record.get("scope") == self.binding["scope"] and record.get("owner") == self.binding["owner"] and
                      record.get("recipe_identity_sha256") == self.entry["recipe_identity_sha256"], "ownership")
        try:
            guard = hashlib.sha256(read_file(s + "/guard.py", 4096)).hexdigest()
        except (Refused, OSError):
            guard = None
        state_require(guard == record.get("guard_sha256") == self.host_profile["bodies"]["service_guard"], "ownership")
        unit = self.witness(min(10, DEADLINE - time.monotonic()), bound=True)
        state_require(unit is not None, "readiness")
        try:
            run = self.host(PYTHON, s + "/guard.py", seconds=min(20, DEADLINE - time.monotonic()))
        except (Refused, StateRefused):
            run = None
        return unit, "pass" if run is not None and run[0] == 0 else "fail"

    def read(self, end, *args, limit):
        """One `observe-node` read under the wait deadline: None when not started, cut off, refused or over its bound."""
        left = end - time.monotonic()
        if left < 0.1:
            return None
        bound = min(10.0, left)
        try:
            return self.kubectl("--server=https://127.0.0.1:6443", *args, limit=limit, seconds=bound, probe=True,
                                timeout="%dms" % int(bound * 1000))
        except (Refused, StateRefused, OSError, subprocess.SubprocessError):
            return None

    def facts(self, end):
        """The `node` facts from one round of reads."""
        e, server = self.header["expected"], self.recipe["member"]["role"] == "server"
        name = e["member"]
        node = dict.fromkeys(("condition", "uid", "kubelet", "labels", "taints", "lease", "api", "etcd"), "unobserved")
        node.update(member=name, present=False, ready=False)
        out = self.read(end, "get", "node", name, "-o", "go-template=" + NODE_FIELDS, limit=65536)
        f = out[1].decode("utf-8", "replace").split("\t") if out is not None and out[0] == 0 else []
        absent = out is not None and out[0] != 0 and out[2] == b'Error from server (NotFound): nodes "%s" not found\n' % (
            name.encode())
        if len(f) == 5 or absent:
            labels = sorted(x for x in f[3].split() if not x.startswith(SYSTEM_LABELS)) if f else None
            seen = {"condition":f and f[2] == "True", "uid":f and f[0] == e["node_uid"],
                    "kubelet":f and f[1] == self.recipe["version"]}
            if e["labels"] is not None:
                seen.update(labels=f and labels == e["labels"], taints=f and sorted(f[4].split()) == e["taints"])
            node.update({k:"ready" if v else "not-ready" for k, v in seen.items()}, present=bool(f))
        out = self.read(end, "get", "lease", name, "-n", "kube-node-lease", "-o", "go-template={{.spec.renewTime}}", limit=512)
        if out is not None and (out[0] == 0 or out[2] == b'Error from server (NotFound): leases.coordination.k8s.io "%s" '
                                                         b'not found\n' % name.encode()):
            node["lease"] = renewed(out[1].decode("ascii", "replace"), e["lease_after_ms"]) if out[0] == 0 else "not-ready"
        if server:
            out = self.read(end, "get", "--raw=/readyz?verbose", limit=16384)
            if out is not None and out[0] == 0:
                text = out[1].decode("ascii", "replace")
                node["api"] = "ready" if text.rstrip("\n").endswith("readyz check passed") else "not-ready"
                node["etcd"] = "ready" if re.search(r"^\[\+\]etcd ok$", text, re.M) and \
                    re.search(r"^\[\+\]etcd-readiness ok$", text, re.M) else "not-ready"
        required = ["condition", "uid", "kubelet", "lease"] + (["api", "etcd"] if server else []) + \
            (["labels", "taints"] if e["labels"] is not None else [])
        node["ready"] = node["present"] and all(node[k] == "ready" for k in required)
        return node

    def observe(self):
        """The body-side wait: re-read every 2 seconds until ready or the wait deadline, then answer the last facts."""
        end = min(time.monotonic() + self.header["wait_ms"] / 1000, DEADLINE - 5)
        node = None
        while end - time.monotonic() >= 0.1:
            node = self.facts(end)
            if node["ready"]:
                break
            time.sleep(max(0, min(2.0, end - time.monotonic())))
        return node or self.facts(end)

    def lookup(self):
        """A duplicate dispatch returns its existing receipt or refuses, before any check or effect."""
        path = self.dispatch_path()
        previous = state_read(path + "/intent.json", "intent")
        if previous is None:
            return None
        state_require(previous["binding"] == self.binding and previous["action"] == self.action and
                      previous["payload_sha256"] == state_hash("broil-infra-step-v1", self.payload), "ownership")
        terminal = state_read(path + "/terminal.json", "terminal")
        state_require(terminal is not None, "busy")
        return terminal

    def restart(self, result):
        """`restart`: the re-checks, one `systemctl restart --no-block`, then the local readiness poll."""
        previous = self.lookup()
        if previous is not None:
            result["terminal"] = previous
            return
        before, guard = self.inspect()
        state_require(guard == "pass", "ownership")
        state_require((before["active"], before["sub"], before["result"]) == ("active", "running", "success") and
                      before["invocation"] is not None, "readiness")
        self.active()
        state_require(DEADLINE - time.monotonic() >= 60, "timeout")
        state_require(self.begin() is None, "ownership")
        self.revalidate()
        self.effect_started = True
        end = DEADLINE - 5
        out = self.host(SYSTEMCTL, "restart", "--no-block", "--", self.unit, seconds=min(10, end - time.monotonic()),
                        mutating=True)
        state_require(out is not None and out[0] == 0, "readiness")
        while True:
            state_require(end - time.monotonic() >= 0.1, "readiness")
            try:
                unit = self.witness(min(10, end - time.monotonic()))
            except (Refused, StateRefused):
                unit = None
            if unit is not None:
                new = unit["invocation"] not in (None, before["invocation"])
                state_require(unit["active"] != "failed" and not (new and unit["sub"] == "auto-restart"), "readiness")
                if new and (unit["active"], unit["sub"]) == ("active", "running") and \
                        healthy(min(10, max(0.001, end - time.monotonic()))):
                    break
            time.sleep(max(0, min(2.0, end - time.monotonic())))
        result["unit"] = dict(unit, previous_invocation=before["invocation"])
        result["terminal"] = self.terminal("succeeded", None)

    def input_path(self, g):
        return "%s/resources/%s/%s" % (self.owner_path, g["id"], g["generation"])

    def copy_path(self, g):
        return "%s/node/%s.%s.crt" % (self.owner_path, g["id"], g["generation"])

    def private(self, path, maximum):
        """A private file's bytes within `maximum`; `ownership` when it is absent, a link, not private or larger."""
        try:
            parent = state_directory(str(Path(path).parent))
        except FileNotFoundError:
            raise StateRefused("ownership")
        try:
            fd = os.open(Path(path).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
        except OSError:
            raise StateRefused("ownership")
        finally:
            os.close(parent)
        try:
            state_require(state_private(fd).st_size <= maximum, "ownership")
            return os.read(fd, maximum + 1)
        finally:
            os.close(fd)

    def password(self, g):
        """A generation's password text: 1 to 4096 bytes of UTF-8 without a containerd-unsafe byte."""
        raw = self.private(self.input_path(g) + "/password", 4096)
        state_require(raw and not UNSAFE.intersection(raw), "ownership")
        try:
            return raw.decode()
        except ValueError:
            raise StateRefused("ownership")

    def generation(self, e):
        """The verification of one current generation: its `binding.json`, password and `ca.crt` exactly when
        `ca`; returns the password text."""
        g, path = e["resource"], self.input_path(e["resource"])
        try:
            fd = state_directory(path)
        except FileNotFoundError:
            raise StateRefused("ownership")
        try:
            record = state_read(path + "/binding.json")
            state_require(record is not None, "ownership")
            state_fields(record, "schema directory projection inactive registration_pending")
            b = record["projection"]["binding"]
            state_require(record["directory"] == identity(fd) and record["inactive"] is True and
                          b["owner"] == self.binding["owner"] and b["origin"] == e["origin"] and
                          b["resource"]["kind"] == "node-registry" and
                          [b["resource"]["id"], b["resource"]["generation"]] == [g["id"], g["generation"]] and
                          b["destination"]["machine"] == self.member["machine"], "ownership")
            state_require(("ca.crt" in os.listdir(fd)) == e["ca"], "ownership")
        finally:
            os.close(fd)
        if e["ca"]:
            self.private(path + "/ca.crt", 262144)
        return self.password(g)

    def config(self, e, g, password):
        """The `configs` entry of generation `g`."""
        value = {"auth":{"username":e["username"], "password":password}}
        if e["ca"]:
            value["tls"] = {"ca_file":self.copy_path(g)}
        return value

    def files(self, e, g, password):
        """The file entries of entry `e` at generation `g` as {(part, key): value}: the managed origin's loopback
        reader first, its origin and its key's `configs` only with `same-origin`."""
        key, same = e["authority"], e["fallback"] == "same-origin"
        if not e["managed"]:
            return {("mirrors", key):{"endpoint":["https://" + key]}, ("configs", key):self.config(e, g, password)}
        files = {("mirrors", key):{"endpoint":[LOOPBACK] + (["https://" + key] if same else [])},
                 ("configs", LOOPBACK_KEY):{"auth":{"username":e["username"], "password":password}}}
        if same:
            files[("configs", key)] = self.config(e, g, password)
        return files

    def registries(self):
        """The file form: (None, None) when absent, otherwise its decoded object and identity, refusing with the
        first matching class."""
        parent = state_directory(str(Path(REGISTRIES).parent))
        try:
            fd = os.open(Path(REGISTRIES).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            return None, None
        except OSError:
            raise StateRefused("ownership")
        finally:
            os.close(parent)
        try:
            st = os.fstat(fd)
            state_require(stat.S_ISREG(st.st_mode), "ownership")
            raw = os.read(fd, 65537)
            state_require(len(raw) <= 65536, "bound")
            duplicates = []

            def pairs(items):
                value = {}
                for key, item in items:
                    if key in value:
                        duplicates.append(key)
                    value[key] = item
                return value
            number = lambda text: NUMBER
            try:
                data = json.loads(raw.decode(), object_pairs_hook=pairs, parse_int=number, parse_float=number,
                                  parse_constant=number)
            except RecursionError:
                raise StateRefused("bound")
            except ValueError:
                raise StateRefused("ownership")
            state_require(not scan(data) and not duplicates and isinstance(data, dict) and
                          set(data) <= {"mirrors", "configs"} and
                          all(isinstance(v, dict) and all(isinstance(x, dict) for x in v.values()) for v in data.values()),
                          "ownership")
            for entry in data.get("mirrors", {}).values():
                urls = entry.get("endpoint", [])
                state_require(isinstance(urls, list) and all(isinstance(u, str) and endpoint_host(u) for u in urls),
                              "ownership")
            state_require(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1, "ownership")
            return data, identity(fd)
        finally:
            os.close(fd)

    def classify(self, entries):
        """Reads with no effect: each current generation, the host record, the file and the would-be file; returns
        the file, its identity, the record, the recorded renderings and the would-be file."""
        keys = {e["authority"]:e for e in entries}
        passwords = {key:self.generation(e) for key, e in keys.items()}
        record = state_read(self.owner_path + "/node/registries.json", "node-registries")
        recorded = record["entries"] if record else {}
        state_require(record is None or record["owner"] == self.binding["owner"] and isinstance(recorded, dict) and
                      set(recorded) <= set(keys), "ownership")
        renders, owned, covered = {}, {}, set()
        for key, r in recorded.items():
            e = keys[key]
            state_fields(r, "registry resource previous")
            renders[key] = []
            covered |= {key, LOOPBACK_KEY} if e["managed"] else {key}
            for g in (r["resource"], r["previous"]):
                if g is not None:
                    state_require(r["registry"] == e["registry"] and g["id"] == e["resource"]["id"], "ownership")
                    if e["ca"]:
                        self.private(self.input_path(g) + "/ca.crt", 262144)
                        self.private(self.copy_path(g), 262144)
                    files = self.files(e, g, self.password(g))
                    renders[key].append((g, files))
                    for part_key, value in files.items():
                        owned.setdefault(part_key, []).append(value)
        data, ident = self.registries()
        protected, hosts = set(), set()
        managed = any(e["managed"] for e in entries)
        for key in keys:
            host, port = authority(key)
            protected |= {(host, None), (host, 443)} if port in (None, 443) else {(host, port)}
            hosts.add(host)
        if managed:
            protected |= LOOPBACKS
        for part, items in (data or {}).items():
            for key, value in items.items():
                urls = value.get("endpoint", []) if part == "mirrors" else []
                broil = value in owned.get((part, key), [])
                state_require(broil or key not in covered and authority(key) not in protected and
                              not {endpoint_host(u) for u in urls} & hosts and
                              not (managed and any(endpoint_loopback(u) for u in urls)), "ownership")
        file = {part:dict((data or {}).get(part, {})) for part in ("mirrors", "configs")}
        for key, e in keys.items():
            for (part, name), value in self.files(e, e["resource"], passwords[key]).items():
                file[part][name] = value
        state_require(len(yaml_safe(file)) < 65536, "bound")
        state_require(not scan(file), "ownership")
        return data, ident, record, renders, file

    def configure(self, result):
        """`configure-registries`: the re-checks and classification, then the CA copies, host record and
        file under one receiver intent."""
        global EFFECTS
        previous = self.lookup()
        if previous is not None:
            result["terminal"] = previous
            return
        self.active()
        entries = self.recipe["registries"]
        data, ident, record, renders, file = self.classify(entries)
        state_require(self.begin() is None, "ownership")
        self.revalidate()
        self.effect_started = True
        node = self.owner_path + "/node"
        state_mkdir(node)
        for e in entries:
            if not e["ca"]:
                continue
            g, raw = e["resource"], self.private(self.input_path(e["resource"]) + "/ca.crt", 262144)
            parent = state_directory(node)
            try:
                try:
                    fd = os.open(Path(self.copy_path(g)).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600,
                                 dir_fd=parent)
                except FileExistsError:
                    state_require(self.private(self.copy_path(g), 262144) == raw, "ownership")
                    continue
                EFFECTS = True
                try:
                    state_private(fd)
                    view = memoryview(raw)
                    while view:
                        count = os.write(fd, view)
                        state_require(count > 0, "storage")
                        view = view[count:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(parent)
            finally:
                os.close(parent)
        held = lambda files: all((data or {}).get(part, {}).get(name) == value
                                 for (part, name), value in files.items() if part == "configs")
        state = {e["authority"]:{"registry":e["registry"], "resource":e["resource"],
                                 "previous":next((g for g, files in renders.get(e["authority"], []) if held(files)),
                                                 None)} for e in entries}
        value = {"schema":1, "kind":"node-registries", "owner":self.binding["owner"], "operation":self.binding["operation"],
                 "entries":state}
        if record is None:
            self.revalidate()
            state_publish(node + "/registries.json", value)
        else:
            self.replace(node + "/registries.json", value)
        self.revalidate()
        state_publish(REGISTRIES, file, ident, yaml_safe)
        result["terminal"] = self.terminal("succeeded", None)

    def run(self, result):
        if self.tag == "inspect-member":
            result["unit"], result["guard"] = self.inspect()
            if "registries" in self.recipe:
                self.classify(self.header["expected"]["registries"])
        elif self.tag == "observe-node":
            result["node"] = self.observe()
        elif self.tag == "restart":
            self.restart(result)
        else:
            self.configure(result)


class NodeMemberReceiver(NodeReceiver):
    """The member actions under the member recipe: the Node actions on the acting first
    server through its managed administrator access, `stop-member` and `start-member` on the member's own host."""

    def check(self, profile):
        r, b, e = self.recipe, self.binding, self.header["expected"]
        if self.tag == "start-member" and r.get("schema") == 3:
            # A same-machine replacement join's start under its agent recipe, for the recipe's unjoined member
            # whose owned installation still holds the published UID `expected` names.
            m = r["member"]
            state_member(m)
            state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                          r["attempt"] == b["attempt"] and r["version"] == profile["k3s_version"] and
                          isinstance(r["members"], list) and m in r["members"] and m["role"] == "agent" and
                          m["node_uid"] is None and e["node_uid"] is not None and self.member == m, "ownership")
            self.joining, self.name, self.unit, self.nodes = e["node_uid"], m["member"], UNITS["agent"], None
            return
        state_fields(r, "scope owner operation cluster first_server version action phase member participants removed "
                        "writer reachability writer_move transition decision_sha256 profile_sha256")
        state_cluster(r["cluster"])
        parts = r["participants"]
        state_require(isinstance(parts, list) and 1 <= len(parts) <= 128 and isinstance(r["removed"], list) and
                      len(r["removed"]) <= 128, "bound")
        for m in parts + [r["first_server"], r["member"]]:
            state_member(m)
        for x in r["removed"]:
            state_fields(x, "member machine operation")
        state_require(r["writer"] is None or isinstance(r["writer"], dict) and set(r["writer"]) == {"member", "operation", "moves"})
        state_require(r["decision_sha256"] is None or isinstance(r["decision_sha256"], str) and
                      re.fullmatch("[0-9a-f]{64}", r["decision_sha256"]) is not None)
        name, local = r["member"]["member"], self.tag in ("stop-member", "start-member")
        # The acting first server; on a one-server target, the drained server itself.
        servers = [m for m in parts if m["role"] == "server" and m["member"] != name] or \
            [m for m in parts if m["role"] == "server"]
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      r["profile_sha256"] == b["fingerprints"]["profile_sha256"] and r["version"] == profile["k3s_version"] and
                      r["action"] in MEMBER_TAGS[self.tag] and r["reachability"] in ("reachable", "unreachable") and
                      (r["phase"] in ("begin", "complete") if r["action"] == "node-replace" else r["phase"] is None) and
                      r["member"] in parts and r["member"]["role"] != "backup" and servers and r["first_server"] == servers[0] and
                      e["node_uid"] == r["member"]["node_uid"] and (local or e["node_uid"] is not None) and
                      self.member == (r["member"] if local else r["first_server"]) and
                      (self.tag != "stop-member" or r["reachability"] == "reachable") and
                      (self.tag != "start-member" or r["member"]["role"] == "agent"), "ownership")
        self.name, self.unit, self.nodes = name, UNITS[r["member"]["role"]], None
        if not local:
            self.executable = tool(profile)

    def kube(self, *args, **options):
        return self.kubectl("--server=https://127.0.0.1:6443", *args, **options)

    def get(self, *args):
        """One read: the decoded object, or None when it does not exist."""
        out = self.kube("get", *args, probe=True)
        state_require(out is not None and (out[0] == 0 or b"(NotFound)" in out[2]), "transport")
        return decode(out[1]) if out[0] == 0 else None

    def node(self):
        return self.get("node", self.name, "-o", "json")

    def bound(self):
        """The `delete-node` wait: whether a pod object in any phase is still bound to the Node's name, from one
        read capped at 10 seconds and by the deadline; a failed, oversized or malformed read counts as bound, so the
        wait retries it."""
        try:
            out = self.kube("get", "pods", "-A", "--field-selector", "spec.nodeName=" + self.name, "-o", "json",
                            probe=True, seconds=max(0.1, min(10, DEADLINE - 5 - time.monotonic())))
            items = decode(out[1]).get("items") if out is not None and out[0] == 0 else None
        except (Refused, StateRefused, ValueError, AttributeError):
            items = None
        return not isinstance(items, list) or bool(items)

    def facts(self, node, pods=(), counted=None, after=None, gone=()):
        """`member`: `pods` and, from the classification `counted`, `total` and `evictable`, without the pods
        that count `gone`; `next` when more of the view's pods sort after this page's."""
        page = list(pods)[:PAGE]
        return {"name":self.name, "present":node is not None, "uid":node["metadata"]["uid"] if node else None,
                "cordoned":bool(node and node["spec"].get("unschedulable")), "pods":page,
                "total":None if counted is None else len(counted),
                "evictable":None if counted is None else sum(p["class"] == "evictable" and pod_key(p) not in gone
                                                             for p in counted),
                "next":{"namespace":page[-1]["namespace"], "pod":page[-1]["pod"]} if len(list(pods)) > PAGE else None}

    def compare(self, node):
        """The selected Node, absent or with the recorded UID; a re-registered Node refuses with no effect."""
        state_require(node is None or node["metadata"]["uid"] == self.recipe["member"]["node_uid"], "ownership")
        return node

    @staticmethod
    def matches(term, labels):
        """One node selector term's expressions (members.rs `term_matches`)."""
        def one(x):
            value, values, op = labels.get(x.get("key")), x.get("values") or [], x.get("operator")
            return (op == "In" and value is not None and value in values or op == "NotIn" and value not in values or
                    op == "Exists" and value is not None or op == "DoesNotExist" and value is None)
        return all(one(x) for x in term.get("matchExpressions") or [])

    def local(self, volume, namespace):
        """A `hostPath` volume, or a claim bound to a PersistentVolume whose node affinity selects only this Node."""
        if volume.get("hostPath") is not None:
            return True
        claim = (volume.get("persistentVolumeClaim") or {}).get("claimName")
        bound = claim and ((self.get("persistentvolumeclaim", claim, "-n", namespace, "-o", "json") or {}).get("spec") or {}).get("volumeName")
        pv = bound and self.get("persistentvolume", bound, "-o", "json")
        terms = pv and (((pv.get("spec") or {}).get("nodeAffinity") or {}).get("required") or {}).get("nodeSelectorTerms")
        if not terms:
            return False
        if self.nodes is None:
            out = self.kube("get", "nodes", "-o", 'jsonpath={range .items[*]}{.metadata.name}{"\\t"}{.metadata.labels}{"\\n"}{end}',
                            probe=True)
            state_require(out is not None and out[0] == 0, "transport")
            self.nodes = [(n, decode(l or "{}")) for n, l in (x.split("\t", 1) for x in out[1].decode().splitlines())]
        return {n for n, labels in self.nodes if any(self.matches(t, labels) for t in terms)} == {self.name}

    def classify(self):
        """The classes of the pods bound to the Node, in phase neither `Succeeded` nor `Failed`."""
        items = self.get("pods", "-A", "--field-selector", "spec.nodeName=" + self.name, "-o", "json")["items"]
        items = [p for p in items if (p.get("status") or {}).get("phase") not in ("Succeeded", "Failed")]
        state_require(len(items) <= 1024, "bound")
        items.sort(key=lambda p: pod_key(p["metadata"], "name"))
        pods, self.owners = [], {}
        for p in items:
            m = p["metadata"]
            refs, labels = [o for o in m.get("ownerReferences") or [] if o.get("controller") is True], m.get("labels") or {}
            self.owners[pod_key(m, "name")] = refs[0] if refs else {}
            if (m.get("annotations") or {}).get("kubernetes.io/config.mirror") is not None or refs and refs[0].get("kind") == "DaemonSet":
                kind = "daemon"
            elif m["namespace"] == "broil-registry" and labels.get("broil.dev/managed-by") == "broil" and \
                    labels.get("broil.dev/component") == "registry-service":
                kind = "writer"
            elif any(self.local(v, m["namespace"]) for v in (p.get("spec") or {}).get("volumes") or []):
                kind = "local-storage"
            else:
                kind = "evictable" if refs else "unmanaged"
            pods.append({"namespace":m["namespace"], "pod":m["name"], "class":kind,
                         "terminating":m.get("deletionTimestamp") is not None})
        return pods

    def gone(self, pods):
        """For the unreachable member only: a terminating evictable pod of a ReplicaSet whose Ready pods
        on other Nodes reach its desired count, or of a Job with a Ready or succeeded pod on another Node, counts
        gone; any other pod, a StatefulSet's included, only when its object is deleted."""
        found, listed = set(), {}
        if self.recipe["reachability"] != "unreachable":
            return found
        for p in pods:
            ref, ns = self.owners.get(pod_key(p), {}), p["namespace"]
            if p["class"] != "evictable" or not p["terminating"] or ref.get("kind") not in ("ReplicaSet", "Job"):
                continue
            if ns not in listed:
                listed[ns] = self.get("pods", "-n", ns, "-o", "json")["items"]
            others = [q for q in listed[ns] if (q.get("spec") or {}).get("nodeName") not in (None, self.name) and
                      q["metadata"].get("deletionTimestamp") is None and
                      any(o.get("controller") is True and o.get("uid") == ref.get("uid")
                          for o in q["metadata"].get("ownerReferences") or [])]
            ready = [q for q in others if any(c.get("type") == "Ready" and c.get("status") == "True"
                                              for c in (q.get("status") or {}).get("conditions") or [])]
            if ref["kind"] == "ReplicaSet":
                owner = self.get("replicaset", ref.get("name", ""), "-n", ns, "-o", "json")
                replaced = owner is not None and owner["metadata"].get("uid") == ref.get("uid") and \
                    len(ready) >= (owner.get("spec") or {}).get("replicas", 1)
            else:
                replaced = bool(ready) or any((q.get("status") or {}).get("phase") == "Succeeded" for q in others)
            if replaced:
                found.add(pod_key(p))
        return found

    def mutate(self):
        self.active()
        state_require(self.begin() is None, "ownership")
        self.revalidate()

    def systemctl(self, *args):
        out = self.host(SYSTEMCTL, *args, seconds=max(0.1, min(120, DEADLINE - 5 - time.monotonic())), mutating=True)
        return out is not None and out[0] == 0

    def evict(self, result, node):
        """One Eviction per named pod in payload order, retrying `429` answers every 5 seconds."""
        global WRITERS_SETTLED
        counted = self.classify()
        pods = {pod_key(p):p for p in counted}
        named_pods = [pods.get(pod_key(x)) for x in self.header["expected"]["pods"]]
        state_require(all(p is None or p["class"] == "evictable" for p in named_pods), "ownership")
        self.mutate()
        waiting, evicted = [p for p in named_pods if p is not None and not p["terminating"]], 0
        while waiting:
            kept = []
            for p in waiting:
                self.effect_started = True
                out = self.kube("create", "--raw", "/api/v1/namespaces/%s/pods/%s/eviction" % (p["namespace"], p["pod"]),
                                "-f", "-", input=canonical({"apiVersion":"policy/v1", "kind":"Eviction",
                                "metadata":{"name":p["pod"], "namespace":p["namespace"]}}), probe=True, mutating=True,
                                seconds=max(0.1, min(20, DEADLINE - 5 - time.monotonic())))
                if out is None:
                    WRITERS_SETTLED = False
                    raise StateRefused("timeout")
                if out[0] == 0 or b"(NotFound)" in out[2]:
                    evicted += 1
                else:
                    state_require(b"(TooManyRequests)" in out[2], "transport")
                    kept.append(p)
            waiting = kept
            if waiting and DEADLINE - time.monotonic() < 16:
                # Drain stops: the kept pods, with effect `absent` or `partial`.
                result["member"] = self.facts(node, waiting, counted)
                self.effect = "partial" if evicted else "absent"
                raise StateRefused("readiness")
            if waiting:
                time.sleep(5)
        result["member"] = self.facts(node, (), counted)

    def run(self, result):
        r = self.recipe
        if self.tag == "observe-drain":
            # The pages: the view's pods sorting after `after`, at most 70, in `(namespace, pod)` byte order. A
            # reachable member's evicted pod counts gone only when deleted; an unreachable one's by `gone`.
            e, node, pods = self.header["expected"], self.node(), self.classify()
            gone = self.gone(pods)
            view = {"classify":pods, "wait":[], "remaining":[p for p in pods if p["class"] == "evictable" and
                                                             pod_key(p) not in gone]}[e["view"]]
            result["member"] = self.facts(node, [p for p in view if e["after"] is None or
                                                 pod_key(p) > pod_key(e["after"])], pods, gone=gone)
            return
        result["terminal"] = self.lookup()
        if result["terminal"] is not None:
            return
        if self.tag in ("cordon", "uncordon"):
            node = self.compare(self.node())
            state_require(node is not None, "readiness")
            value = self.tag == "cordon"
            self.mutate()
            if bool(node["spec"].get("unschedulable")) != value:
                self.effect_started = True
                self.kube("patch", "node", self.name, "--type=json", "-p", json.dumps([
                    {"op":"test", "path":"/metadata/uid", "value":r["member"]["node_uid"]},
                    {"op":"add", "path":"/spec/unschedulable", "value":value}]), mutating=True)
            result["member"] = self.facts(self.node())
        elif self.tag == "evict":
            node = self.compare(self.node())
            state_require(node is not None, "readiness")
            self.evict(result, node)
        elif self.tag == "delete-node":
            node = self.compare(self.node())
            self.mutate()
            if node is not None:
                self.effect_started = True
                self.kube("delete", "--raw", "/api/v1/nodes/" + self.name, "-f", "-", input=canonical({"apiVersion":"v1",
                          "kind":"DeleteOptions", "preconditions":{"uid":r["member"]["node_uid"]}}), mutating=True)
            # Read only, until pod garbage collection has deleted every pod bound to the Node's name; at the
            # bound, `readiness` with effect `complete`, since the Node is deleted.
            while self.bound():
                if DEADLINE - time.monotonic() < 16:
                    self.effect = "complete"
                    result["member"] = self.facts(self.node())
                    raise StateRefused("readiness")
                time.sleep(5)
            result["member"] = self.facts(self.node())
        elif self.tag == "stop-member":
            # The K3s unit, then the replication unit, which a target without a registry never installed.
            self.mutate()
            self.effect_started = True
            for unit in (self.unit, REPLICATION):
                for verb in ("stop", "disable"):
                    state_require(self.systemctl(verb, unit) or unit == REPLICATION and not os.path.exists(UNIT_DIR + unit),
                                  "readiness")
        else:
            # `start-member`: the unchanged agent activation and guard, then enable and one guarded start.
            s = self.owner_path + "/service"
            record = state_read(s + "/activation.json", schema=3)
            state_require(isinstance(record, dict) and record.get("kind") == "agent-activation" and
                          record.get("scope") == self.binding["scope"] and record.get("owner") == self.binding["owner"] and
                          hashlib.sha256(read_file(s + "/guard.py", 4096)).hexdigest() == record.get("guard_sha256") ==
                          self.host_profile["bodies"]["service_guard"], "ownership")
            # The retained installation is stopped: an active unit refuses.
            unit = self.witness(max(0.1, min(10, DEADLINE - 5 - time.monotonic())))
            state_require(unit is not None and unit["active"] == "inactive", "ownership")
            self.mutate()
            self.effect_started = True
            state_require(self.systemctl("enable", self.unit) and self.systemctl("start", "--no-block", self.unit), "readiness")
        if self.tag in ("stop-member", "start-member"):
            # No Node facts on the member's own host; its unit witness instead.
            result["unit"] = self.witness(max(0.1, min(10, DEADLINE - 5 - time.monotonic())))
        result["terminal"] = self.terminal("succeeded", None)


def node_request(raw, header):
    """The header."""
    global DEADLINE
    state_require(17 + len(raw) + 8192 <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms recipe expected wait_ms")
    state_require(canonical(header) == raw, "integrity")
    state_require(type(header["version"]) is int and header["version"] == 1,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
    tag = header["action"]
    state_require(tag in TAGS, "capability")
    mutation = tag not in READS
    state_hex(header["request_id"])
    state_binding(header["binding"])
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation, "ownership")
    state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(header["recipe"])) <= 32768, "bound")
    NodeReceiver.admit(header, tag)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    state_require(sys.stdin.buffer.read(1) == b"", "integrity")


def node_main(raw, header):
    facts = ("unit", "guard", "node", "member")
    receiver = None
    status = "unknown"
    result = {"terminal":None, **dict.fromkeys(facts), "failure":None}
    prefix = b"BK3SNOD1\n" + struct.pack(">I", len(raw)) + raw
    try:
        node_request(raw, header)
        receiver = (NodeMemberReceiver if header["action"] in MEMBER_TAGS else NodeReceiver)(header)
        receiver.profile()
        receiver.open()
        receiver.owned()
        receiver.run(result)
        status = "ok"
    except Exception as error:
        failure = (error.failure if isinstance(error, StateRefused) else
                   "timeout" if isinstance(error, subprocess.TimeoutExpired) else
                   "transport" if isinstance(error, subprocess.SubprocessError) else
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
                result["terminal"] = receiver.terminal("failed", failure)
                status = "failed"
            except BaseException:
                status = "unknown"
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root, receiver.executable):
                if fd is not None:
                    os.close(fd)
    if status != "ok":
        result.update(dict.fromkeys(facts[:3] if status == "failed" else facts))
    body = canonical({"kind":"result", "status":status, **result})
    complete = prefix + struct.pack(">I", len(body)) + body
    if len(complete) > 65536:
        os._exit(125)
    sys.stdout.buffer.write(complete)
    sys.stdout.buffer.flush()


# A separate read grammar. Old tags never decode this recipe.
VIEW_PATHS = {
    "nodes": (("Node", "/api/v1/nodes"),),
    "workloads": (("Pod", "/api/v1/pods"), ("Deployment", "/apis/apps/v1/deployments"),
                  ("StatefulSet", "/apis/apps/v1/statefulsets"), ("DaemonSet", "/apis/apps/v1/daemonsets"),
                  ("Job", "/apis/batch/v1/jobs")),
    "services": (("Service", "/api/v1/services"),),
}


def view_string(value, nullable=False):
    state_require(value is None and nullable or isinstance(value, str) and bool(value) and
                  len(value.encode()) <= 4096 and "\0" not in value, "integrity")
    return value


def view_count(value):
    state_require(value is None or type(value) is int and 0 <= value <= 18446744073709551615, "integrity")
    return value


def view_name(value, label=False):
    view_string(value)
    part = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
    state_require(len(value) <= (63 if label else 253) and
                  re.fullmatch(part if label else part + r"(?:\." + part + ")*", value), "integrity")
    return value


def view_object(value):
    state_require(isinstance(value, dict), "integrity")
    return value


def view_array(value):
    state_require(isinstance(value, list) and len(value) <= 4096, "bound")
    return value


def view_item(kind, item):
    """Project only public fields; raw API objects never leave this function."""
    view_object(item)
    state_require(item.get("kind", kind) == kind, "integrity")
    meta = view_object(item.get("metadata"))
    name, uid = view_name(meta.get("name")), view_string(meta.get("uid"))
    state_require(opaque(uid), "integrity")
    spec, status = view_object(item.get("spec", {})), view_object(item.get("status", {}))
    if kind == "Node":
        labels = view_object(meta.get("labels", {}))
        state_require(all(isinstance(k, str) and isinstance(v, str) for k, v in labels.items()), "integrity")
        taints = []
        for t in view_array(spec.get("taints", [])):
            view_object(t)
            state_require(t.get("effect") in ("NoSchedule", "PreferNoSchedule", "NoExecute") and
                          isinstance(t.get("value", ""), str), "integrity")
            taints.append(view_string(t.get("key")) + "=" + t.get("value", "") + ":" + t["effect"])
        conditions = view_array(status.get("conditions", []))
        state_require(all(isinstance(c, dict) and isinstance(c.get("type"), str) and
                          c.get("status") in ("True", "False", "Unknown") for c in conditions), "integrity")
        return {"name":name, "uid":uid, "version":view_string(view_object(status.get("nodeInfo")).get("kubeletVersion")),
                "ready":any(c["type"] == "Ready" and c["status"] == "True" for c in conditions),
                "roles":["server"] if any(k in labels for k in ("node-role.kubernetes.io/control-plane",
                                                               "node-role.kubernetes.io/master")) else ["agent"],
                "labels":sorted(k + "=" + v for k, v in labels.items() if not k.startswith(SYSTEM_LABELS)),
                "taints":sorted(taints)}
    namespace = view_name(meta.get("namespace"), True)
    identity = {"namespace":namespace, "name":name, "uid":uid}
    if kind == "Service":
        service_type = spec.get("type", "ClusterIP")
        state_require(service_type in ("ClusterIP", "NodePort", "LoadBalancer", "ExternalName"), "integrity")
        ports = []
        for port in view_array(spec.get("ports", [])):
            view_object(port)
            protocol, target = port.get("protocol", "TCP"), port.get("targetPort", port.get("port"))
            state_require(protocol in ("TCP", "UDP", "SCTP"), "integrity")
            state_uint(port.get("port"), 1, 65535)
            if type(target) is int:
                state_uint(target, 1, 65535)
            else:
                state_require(isinstance(target, str) and re.fullmatch(r"[a-z0-9]([-a-z0-9]{0,13}[a-z0-9])?", target),
                              "integrity")
            if port.get("nodePort") is not None:
                state_uint(port["nodePort"], 1, 65535)
            ports.append({"name":view_string(port.get("name"), True), "protocol":protocol, "port":port["port"],
                          "target_port":target, "node_port":port.get("nodePort")})
        def addresses(values, headless=False):
            result = view_array(values)
            for address in result:
                view_string(address)
                state_require(headless and address == "None" or valid_ip(address), "integrity")
            return result
        balancers = []
        for entry in view_array(view_object(status.get("loadBalancer", {})).get("ingress", [])):
            view_object(entry)
            ip, host = entry.get("ip"), entry.get("hostname")
            state_require(ip is not None or host is not None, "integrity")
            if ip is not None:
                state_require(valid_ip(view_string(ip)), "integrity")
            if host is not None:
                state_require(named(view_string(host)), "integrity")
            balancers.append({"ip":ip, "hostname":host})
        return {**identity, "type":service_type, "ports":ports,
                "cluster_ips":addresses(spec.get("clusterIPs", []), True),
                "external_ips":addresses(spec.get("externalIPs", [])), "load_balancer":balancers}
    owners = [o for o in view_array(meta.get("ownerReferences", [])) if view_object(o).get("controller") is True]
    state_require(len(owners) <= 1, "integrity")
    owner = {k:view_string(owners[0].get(k)) for k in ("kind", "name", "uid")} if owners else None
    result = {**identity, "kind":kind, "generation":view_count(meta.get("generation")),
              "observed_generation":view_count(status.get("observedGeneration")), "owner":owner,
              **dict.fromkeys(("phase", "desired", "ready", "available", "succeeded", "failed"))}
    if kind == "Pod":
        phase = status.get("phase")
        state_require(phase in ("Pending", "Running", "Succeeded", "Failed", "Unknown"), "integrity")
        containers = view_array(spec.get("containers"))
        seen = view_array(status.get("containerStatuses", []))
        state_require(all(isinstance(c, dict) and type(c.get("ready")) is bool for c in seen), "integrity")
        result.update(phase=phase, desired=len(containers), ready=sum(c["ready"] for c in seen))
    elif kind == "Job":
        result.update(desired=view_count(spec.get("completions")), ready=view_count(status.get("ready")),
                      succeeded=view_count(status.get("succeeded")), failed=view_count(status.get("failed")))
    elif kind == "DaemonSet":
        result.update(desired=view_count(status.get("desiredNumberScheduled")), ready=view_count(status.get("numberReady")),
                      available=view_count(status.get("numberAvailable")))
    else:
        result.update(desired=view_count(spec.get("replicas")), ready=view_count(status.get("readyReplicas")),
                      available=view_count(status.get("availableReplicas")))
    return result


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class NodeViewReceiver(NodeReceiver):
    KEYS = ("recipe", "query", "limit")

    def check(self, profile):
        r, b = self.recipe, self.binding
        state_fields(r, "scope owner operation cluster member first_server version profile_sha256")
        state_member(r["member"])
        state_member(r["first_server"])
        state_cluster(r["cluster"])
        state_require(r["cluster"] is not None and r["scope"] == b["scope"] and r["owner"] == b["owner"] and
                      r["operation"] == b["operation"] and r["member"] == r["first_server"] == self.member and
                      self.member["role"] == "server" and self.member["node_uid"] is not None and
                      r["version"] == profile["k3s_version"] and
                      r["profile_sha256"] == b["fingerprints"]["profile_sha256"] and
                      b["receiver_generation"] == 0, "ownership")
        self.executable = tool(profile)

    def access(self, snapshot=None):
        """Use only the owned administrator projection, with no refresh or raw fallback."""
        state_require(self.claim["active_attempt"] in (None, self.binding["attempt"]), "busy")
        state_require(all(terminal is not None for _, _, terminal in self.ledger()), "busy")
        path = self.owner_path + "/admin.yaml"
        ident = state_file_identity(path) if snapshot is None else identity(snapshot.fd)
        raw = read_file(path, 65536) if snapshot is None else snapshot.raw
        config = decode(raw)
        state_require(raw == canonical(config) + b"\n", "ownership")
        cluster, user = config["clusters"][0]["cluster"], config["users"][0]["user"]
        activation = state_read(self.owner_path + "/service/activation.json", schema=2)
        state_require(activation is not None and activation.get("kind") == "server-activation" and
                      activation.get("scope") == self.binding["scope"] and activation.get("owner") == self.binding["owner"] and
                      activation.get("guard_sha256") == self.host_profile["bodies"]["service_guard"], "ownership")
        endpoint = activation["api_endpoint"]
        if snapshot is not None:
            state_require(endpoint == self.recipe["api_endpoint"], "ownership")
        expected = {"apiVersion":"v1", "kind":"Config", "preferences":{}, "current-context":"default",
                    "clusters":[{"name":"default", "cluster":{"server":endpoint,
                                 "certificate-authority-data":cluster["certificate-authority-data"]}}],
                    "contexts":[{"name":"default", "context":{"cluster":"default", "user":"default"}}],
                    "users":[{"name":"default", "user":{key:user[key] for key in
                              ("client-certificate-data", "client-key-data")}}]}
        state_require(config == expected and isinstance(endpoint, str) and endpoint.startswith("https://"), "ownership")
        for encoded in (cluster["certificate-authority-data"], *user.values()):
            state_require(isinstance(encoded, str) and 0 < len(encoded) <= 16384, "ownership")
            decoded = base64.b64decode(encoded, validate=True)
            state_require(decoded and base64.b64encode(decoded).decode() == encoded, "ownership")
        ca = hashlib.sha256(base64.b64decode(cluster["certificate-authority-data"], validate=True)).hexdigest()
        state_require(ca == self.recipe["cluster"]["ca_sha256"] ==
                      hashlib.sha256(read_file(DATA + "/server/tls/server-ca.crt", 65536, private=False)).hexdigest(), "ownership")
        data_fd, _ = directory(DATA)
        try:
            data_id = identity(data_fd)
        finally:
            os.close(data_fd)
        owned = state_read(self.owner_path + "/ownership.json")
        state_require(owned["data"] == data_id, "ownership")
        pointer = state_read(self.owner_path + "/service/admin-access.json", schema=2)
        state_fields(pointer, "schema publication")
        state_hex(pointer["publication"])
        records, total = {}, 0
        folder = self.owner_path + "/service/admin-publications"
        for name in state_names(folder, 1024):
            state_require(re.fullmatch(r"[0-9a-f]{32}\.json", name), "ownership")
            publication = state_read(folder + "/" + name, schema=2)
            state_fields(publication, "schema kind binding recipe_identity_sha256 api_endpoint identity previous file")
            bound = publication["binding"]
            state_binding(bound)
            state_fields(publication["identity"], "cluster node_uid data")
            for file_id in (publication["file"], publication["previous"]):
                state_require(file_id is None or isinstance(file_id, list) and len(file_id) == 2 and
                              all(type(n) is int and n >= 0 for n in file_id), "integrity")
            # A past record keeps its own declaration's config, references and tools.
            state_require(publication["kind"] == "admin-publication" and publication["file"] is not None and
                          bound["owner"] == self.binding["owner"] and bound["scope"] == self.binding["scope"] and
                          bound["dispatch"] == name[:-5] and
                          dict(bound["recipient"], node_uid=None) == dict(self.member, node_uid=None) and
                          all(bound["fingerprints"][k] == self.binding["fingerprints"][k] for k in
                              ("profile_sha256", "script_sha256")) and
                          publication["recipe_identity_sha256"] == activation["recipe_identity_sha256"] and
                          publication["api_endpoint"] == endpoint and
                          publication["identity"] == {"cluster":self.recipe["cluster"], "node_uid":self.member["node_uid"],
                                                       "data":data_id}, "ownership")
            total += len(canonical(publication)) + 1
            state_require(total <= 33554432, "bound")
            records[name[:-5]] = publication
        current, seen = pointer["publication"], set()
        state_require(current in records and records[current]["file"] == ident, "ownership")
        while current is not None:
            state_require(current not in seen, "ownership")
            seen.add(current)
            record = records[current]
            previous = record["previous"]
            if previous is None:
                break
            rank = lambda r: (r["binding"]["receiver_generation"], r["binding"]["step"])
            parents = [(rank(r), name) for name, r in records.items() if name not in seen and
                       r["file"] == previous and rank(r) < rank(record)]
            state_require(parents, "ownership")
            current = max(parents)[1]
        state_require(seen == set(records) and not any(name.startswith(".admin-") for name in
                      state_names(self.owner_path, 1024)) and state_file_identity(path) == ident, "ownership")
        for args, expected_uid in ((["namespace", "kube-system"], self.recipe["cluster"]["uid"]),
                                   (["node", self.member["member"]], self.member["node_uid"])):
            actual = self.kubectl("get", *args, "-o", "jsonpath={.metadata.uid}", limit=4096)
            state_require(actual == expected_uid.encode(), "ownership")

    def run(self, result):
        self.access()
        query, limit = self.header["query"], self.header["limit"]
        if query == "api":
            raw = self.kubectl("get", "--raw=/readyz?verbose", limit=16384, probe=True)
            state_require(raw is not None, "timeout")
            state_require(raw[0] == 0, "readiness")
            text = raw[1].decode("ascii", "replace")
            state_require(text.rstrip("\n").endswith(("readyz check passed", "readyz check failed")), "integrity")
            result["data"] = {"api":"ready" if raw[0] == 0 and text.rstrip("\n").endswith("readyz check passed") else "not-ready",
                              "datastore":"ready" if raw[0] == 0 and re.search(r"^\[\+\]etcd ok$", text, re.M) and
                              re.search(r"^\[\+\]etcd-readiness ok$", text, re.M) else "not-ready"}
            return
        rows = []
        for kind, path in VIEW_PATHS[query]:
            raw = self.kubectl("get", "--raw=" + path + "?limit=" + str(limit + 1), limit=262144)
            document = json.loads(raw, object_pairs_hook=unique,
                                  parse_constant=lambda _: state_require(False, "integrity"))
            state_require(not scan(document), "integrity")
            view_object(document)
            state_require(document.get("kind") in ("List", kind + "List"), "integrity")
            metadata = view_object(document.get("metadata"))
            continuation = metadata.get("continue", "")
            state_require(isinstance(continuation, str), "integrity")
            items = view_array(document.get("items"))
            state_require(len(items) <= limit + 1, "bound")
            projected = [view_item(kind, item) for item in items]
            state_require(len({(v.get("namespace"), v["name"]) for v in projected}) == len(projected) and
                          len({v["uid"] for v in projected}) == len(projected), "integrity")
            projected.sort(key=lambda v: (v.get("namespace", ""), v["name"], v["uid"]))
            result["truncated"] |= bool(continuation) or len(rows) + len(projected) > limit
            rows.extend(projected[:max(0, limit - len(rows))])
            result["data"] = {"items":rows}
            state_require(len(canonical(result["data"])) <= 32768, "bound")
        self.revalidate()


class AccessSnapshot:
    """A private double-read with held ancestors; never a path-based tool input."""
    def __init__(self, path, private=True):
        self.path, self.fd, self.dirs, self.raw = path, None, [], None
        try:
            self.dirs.append(os.open("/", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW))
            self.parts = Path(path).parts[1:]
            state_require(self.parts and all(p not in (".", "..") for p in self.parts), "ownership")
            for part in self.parts[:-1]:
                self.dirs.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=self.dirs[-1]))
            for fd in self.dirs:
                m = os.fstat(fd)
                state_require(m.st_uid == 0 and not m.st_mode & 0o022, "ownership")
            self.fd = os.open(self.parts[-1], os.O_RDONLY | os.O_NONBLOCK | NOFOLLOW, dir_fd=self.dirs[-1])
            m = os.fstat(self.fd)
            state_require(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_nlink == 1 and
                          (stat.S_IMODE(m.st_mode) == 0o600 if private else not m.st_mode & 0o022), "ownership")
            state_require(0 < m.st_size <= 65536, "bound")
            self.stamp = self.metadata(m)
            self.raw = self.read()
            self.recheck()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def metadata(m):
        return (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns, m.st_mode, m.st_uid, m.st_nlink)

    def read(self):
        os.lseek(self.fd, 0, os.SEEK_SET)
        out = bytearray()
        while len(out) <= 65536:
            state_check()
            chunk = os.read(self.fd, min(8192, 65537 - len(out)))
            if not chunk:
                break
            out.extend(chunk)
        state_require(len(out) == self.stamp[2], "ownership")
        return bytes(out)

    def recheck(self):
        state_check()
        state_require(self.metadata(os.fstat(self.fd)) == self.stamp and self.read() == self.raw and
                      self.metadata(os.fstat(self.fd)) == self.stamp, "ownership")
        for index, part in enumerate(self.parts):
            expected = self.dirs[index + 1] if index + 1 < len(self.dirs) else self.fd
            found = os.stat(part, dir_fd=self.dirs[index], follow_symlinks=False)
            state_require([found.st_dev, found.st_ino] == identity(expected) and
                          not stat.S_ISLNK(found.st_mode), "ownership")
        for fd in self.dirs:
            m = os.fstat(fd)
            state_require(m.st_uid == 0 and not m.st_mode & 0o022, "ownership")

    def close(self):
        fds, self.dirs = self.dirs, []
        if self.fd is not None:
            fds.append(self.fd)
            self.fd = None
        self.raw = None
        for fd in reversed(fds):
            os.close(fd)


class NodeAccessReceiver(NodeViewReceiver):
    KEYS = ("recipe", "mode")

    def check(self, profile):
        r, b = self.recipe, self.binding
        state_fields(r, "scope owner operation cluster member first_server version profile_sha256 api_endpoint")
        state_require(isinstance(r["api_endpoint"], str) and len(r["api_endpoint"].encode()) <= 4096 and
                      r["api_endpoint"].startswith("https://"), "integrity")
        # Reuse the closed view identity check without widening its recipe schema.
        original = self.recipe
        try:
            self.recipe = {k:v for k, v in original.items() if k != "api_endpoint"}
            super().check(profile)
        finally:
            self.recipe = original
        projection = {"scope":b["scope"], "mode":self.header["mode"], "owner":b["owner"],
                      "cluster":r["cluster"], "member":r["member"], "source_operation":b["operation"],
                      "source_attempt":b["attempt"], "recipe_sha256":state_hash("broil-k3s-node-access-recipe-v1", r)}
        state_require(b["request_sha256"] == state_hash("broil-infra-access-v1", projection), "ownership")

    def kubectl(self, *args, **kwargs):
        self.snapshot.recheck()
        result = command(self.executable, ["kubectl", "--kubeconfig=/dev/stdin", "--request-timeout=10s", *args],
                         input=self.snapshot.raw, limits=(4096, 4096), seconds=10, bound=True, probe=True)
        state_require(result is not None, "timeout")
        state_require(result[0] == 0 and result[2] == b"", "credential")
        self.snapshot.recheck()
        return result[1]

    def verified(self):
        self.snapshot = AccessSnapshot(self.owner_path + "/admin.yaml")
        ca = None
        try:
            ca = AccessSnapshot(DATA + "/server/tls/server-ca.crt", private=False)
            state_require(hashlib.sha256(ca.raw).hexdigest() == self.recipe["cluster"]["ca_sha256"], "ownership")
            self.access(self.snapshot)
            self.revalidate()
            self.snapshot.recheck()
            ca.recheck()
            state_require(WRITERS_SETTLED, "integrity")
            return self.snapshot.raw
        finally:
            self.snapshot.close()
            if ca is not None:
                ca.close()


def node_access_main(raw, header):
    global DEADLINE
    receiver, material, code = None, b"", 0
    failures = (None, "readiness", "ownership", "credential", "bound", "integrity", "timeout",
                "cancelled", "busy", "unsupported-version", "storage")
    try:
        state_require(0 < len(raw) <= 32751, "bound")
        state_value(header)
        state_fields(header, "protocol version action request_id binding remaining_ms recipe mode")
        state_require(canonical(header) == raw and header["action"] == "access", "integrity")
        state_require(type(header["version"]) is int and header["version"] == 1,
                      "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
        state_require(header["mode"] in ("check", "export"), "integrity")
        state_hex(header["request_id"])
        state_binding(header["binding"])
        state_require(header["request_id"] != header["binding"]["dispatch"], "ownership")
        state_uint(header["remaining_ms"], 1, 30000)
        state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(header["recipe"])) <= 32768, "bound")
        state_require(sys.stdin.buffer.read(1) == b"", "integrity")
        DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
        receiver = NodeAccessReceiver(header)
        receiver.profile()
        receiver.open()
        receiver.owned()
        snapshot = receiver.verified()
        if header["mode"] == "export":
            state_require(19 + len(raw) + len(snapshot) <= 65536, "bound")
            material = snapshot
        del snapshot
    except Exception as error:
        failure = error.failure if isinstance(error, StateRefused) else (
            "timeout" if isinstance(error, subprocess.TimeoutExpired) or isinstance(error, Refused) and error.code == 6 else
            "storage" if isinstance(error, OSError) else "integrity")
        code = failures.index(failure) if failure in failures else 5
        material = b""
    finally:
        if receiver is not None:
            try:
                for fd in (receiver.lock, receiver.root, receiver.executable):
                    if fd is not None:
                        os.close(fd)
            except OSError:
                code, material = 10, b""
    if 19 + len(raw) + len(material) > 65536:
        os._exit(125)
    sys.stdout.buffer.write(b"BK3SACC1\n" + struct.pack(">I", len(raw)) + raw +
                            bytes((code, int(bool(material)))) + struct.pack(">I", len(material)) + material)
    sys.stdout.buffer.flush()


def node_view_main(raw, header):
    global DEADLINE
    receiver = None
    result = {"kind":"result", "status":"ok", "failure":None, "data":None, "truncated":False}
    try:
        state_value(header)
        state_fields(header, "protocol version action request_id binding remaining_ms recipe query limit")
        state_require(canonical(header) == raw and header["action"] == "view", "integrity")
        state_require(type(header["version"]) is int and header["version"] == 1,
                      "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
        state_hex(header["request_id"])
        state_binding(header["binding"])
        state_require(header["request_id"] != header["binding"]["dispatch"], "ownership")
        state_uint(header["remaining_ms"], 1, 30000)
        state_uint(header["limit"], 1, 1000)
        state_require(header["query"] in (*VIEW_PATHS, "api") and
                      (header["query"] != "api" or header["limit"] == 1), "integrity")
        state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(header["recipe"])) <= 32768 and
                      17 + len(raw) + 32768 <= 65536, "bound")
        state_require(sys.stdin.buffer.read(1) == b"", "integrity")
        DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
        receiver = NodeViewReceiver(header)
        receiver.profile()
        receiver.open()
        receiver.owned()
        receiver.run(result)
    except Exception as error:
        failure = error.failure if isinstance(error, StateRefused) else (
            "timeout" if isinstance(error, subprocess.TimeoutExpired) or isinstance(error, Refused) and error.code == 6 else
            "transport" if isinstance(error, subprocess.SubprocessError) or isinstance(error, Refused) and error.code == 5 else
            "storage" if isinstance(error, OSError) else "integrity")
        result.update(failure=failure, status=failure if failure in ("busy", "bound", "unsupported-version") else "refused")
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root, receiver.executable):
                if fd is not None:
                    os.close(fd)
    body = canonical(result)
    if len(body) > 32768:
        result.update(status="bound", failure="bound", data=None)
        body = canonical(result)
    complete = b"BK3SNOD1\n" + struct.pack(">I", len(raw)) + raw + struct.pack(">I", len(body)) + body
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
    require(isinstance(header, dict) and header.get("protocol") == "broil-k3s-node", 4)
    (node_access_main if header.get("action") == "access" else
     node_view_main if header.get("action") == "view" else node_main)(raw, header)
    os._exit(0)
except Exception:
    os._exit(125)
