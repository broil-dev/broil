#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, profile-bound K3s managed-registry family receiver."""
import base64
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time
from urllib.parse import quote, urlsplit
import warnings

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


def normalized_origin(endpoint):
    """The control body's origin rule, for `register-input`'s projection check."""
    parsed = urlsplit(endpoint)
    host = parsed.hostname
    if ":" in host:
        host = "[" + host + "]"
    return f"{parsed.scheme}://{host}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"


# The profile bodies.
BODIES = {"control", "lifecycle", "network", "ingress", "cert_manager", "registry", "node", "delivery", "release", "service_guard"}


def name40(value):
    return hashlib.sha256(canonical(value)).hexdigest()[:40]


def quoted(value):
    return '"%s"' % value


class RegistryReceiver:
    """The receiver framework that every registry protocol shares."""
    FAMILY, KEYS, VERSION = None, (), 1

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
        self.owner_path = ROOT + "/owners/" + self.binding["owner"]
        self.recipe_hash = state_hash("broil-k3s-%s-recipe-v%d" % (self.FAMILY, self.VERSION), self.recipe)

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
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == bodies["registry"], "ownership")
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
        exclusive = not self.tag.startswith("inspect-")
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
                 "effect":"complete" if outcome == "succeeded" else "unknown" if self.effect_started else "absent",
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

    def get(self, kind, name, *args):
        """A bounded read's output, None for the exact `NotFound` answer, else False."""
        outcome = self.kubectl("get", kind, name, *args, limit=262144, probe=True)
        if outcome is None or outcome[0] and outcome[2] != b'Error from server (NotFound): %s "%s" not found\n' % (
                kind.encode(), name.encode()):
            return False
        return None if outcome[0] else outcome[1]

    def prerequisite(self):
        """The prerequisite: the Namespace's UID is the recipe's anchor."""
        uid = self.get("namespaces", "broil-registry", "-o", "jsonpath={.metadata.uid}")
        state_require(uid is not False, "readiness")
        state_require(uid == self.recipe["anchor_uid"].encode(), "ownership")

    def ownership(self, origin):
        """The five ownership annotations of an object's creating request: `origin`'s, or this one's."""
        r = self.recipe
        return {"broil.dev/owner":r["owner"], "broil.dev/creation-operation":(origin or r)["operation"],
                "broil.dev/cluster-uid":r["cluster"]["uid"],
                "broil.dev/recipe-sha256":origin["recipe_sha256"] if origin else self.recipe_hash,
                "broil.dev/profile-sha256":r["profile_sha256"]}

    def signing_secret(self, name, generation, uid, annotations, key="signing-key", out=False):
        """The Secret read through the metadata-only template, with the expected data key: class, activation and keys.
        A batched read passes its item's fields as `out`."""
        secret = {"kind":"Secret", "namespace":"broil-registry", "name":name, "uid":None, "class":"absent",
                  "activation":None, "keys":None}
        if out is False:
            out = self.get("secrets", name, "-n", "broil-registry", "-o", "go-template=" + SECRET_FIELDS)
        f = out.decode("utf-8", "replace").split("\t") if out else []
        if out is not None and (len(f) != 18 or not opaque(f[1])):
            secret["class"] = "unobservable"  # possibly the whole Secret: discarded unparsed
        elif out is not None:
            act, keys = f[6][1:-1], f[17]
            owned = uid == f[1] and f[9:14] == [quoted(annotations[k]) for k in OWNERSHIP]
            fits = f[0] == "Opaque" and f[2:4] == KEY_LISTS and act in ("inactive", "active") and f[14:17] == ["", "", ""] and \
                f[4:9] == [quoted(v) for v in (self.recipe["owner"], generation, act, "broil", "registry-auth")] and \
                keys in ("", key + " ") and (act == "inactive" or keys != "")
            if owned and fits:
                secret.update(activation=act, keys=keys.split())
            secret.update(uid=f[1], **{"class":"foreign" if not owned else "owned" if fits else "owned-drifted"})
        return secret


# ---- The auth protocol ----
AUTH_TAGS = ("inspect-objects", "create-object", "register-input", "activate")
LABELED = ("broil.dev/owner", "broil.dev/generation", "broil.dev/activation", "broil.dev/managed-by", "broil.dev/component")
OWNERSHIP = ("broil.dev/owner", "broil.dev/creation-operation", "broil.dev/cluster-uid", "broil.dev/recipe-sha256",
             "broil.dev/profile-sha256")
KEY_LISTS = [" ".join(sorted(LABELED)) + " ", " ".join(sorted(OWNERSHIP)) + " "]
# The eighteen tab-separated fields: no field can fail on a valid Secret or print a data value.
SECRET_FIELDS = '{{"\\t"}}'.join(["{{.type}}", "{{.metadata.uid}}"] + [
    "{{range $k, $v := .metadata.%s}}{{$k}} {{end}}" % x for x in ("labels", "annotations")] + [
    '{{with .metadata.%s}}{{printf "%%q" (index . "%s")}}{{end}}' % (x, key)
    for x, keys in (("labels", LABELED), ("annotations", OWNERSHIP)) for key in keys] + [
    "{{range .metadata.ownerReferences}}x{{end}}", "{{range .metadata.finalizers}}{{.}} {{end}}",
    "{{if .metadata.deletionTimestamp}}deleting{{end}}", "{{range $k, $v := .data}}{{$k}} {{end}}"])
# Each effect's stage row: the Secret's class, activation and keys, and the registration.
ROWS = {"create-object":("absent", None, None, "absent"), "register-input":("owned", "inactive", [], "absent"),
        "activate":("owned", "inactive", "key", "present")}
# A catalog principal name and a principal Resource's id of either form.
NAME = "[A-Za-z0-9][A-Za-z0-9_-]*"
PRINCIPAL_ID = r"registry-auth-object-principal-%s(\.([2-9]|[1-9][0-9]+))?"


class AuthReceiver(RegistryReceiver):
    FAMILY, KEYS = "registry-auth", ("recipe", "expected", "resource", "preflight", "projection")

    @staticmethod
    def admit(header, tag):
        """`expected` and `projection`."""
        state_fields(header["expected"], "secret registration")
        state_require((header["projection"] is None) == (tag != "register-input"), "ownership")

    def check(self, profile):
        """The recipe and the names; the Secret's annotations are its creator's."""
        r, b = self.recipe, self.binding
        state_fields(r, "scope owner operation cluster first_server anchor_uid version registry resource principal stage "
                        "origins profile_sha256")
        res, owner, origin, name = r["resource"], r["owner"], r["origins"]["secret"], r["principal"]
        state_fields(res, "kind id owner generation machine path namespace name uid")
        state_cluster(r["cluster"])
        state_hex(res["generation"])
        self.secret = "broil-input-" + name40([owner, {k:res[k] for k in ("kind", "id", "generation")}])
        state_require(r["scope"] == b["scope"] and owner == b["owner"] and r["operation"] == b["operation"] and
                      r["profile_sha256"] == b["fingerprints"]["profile_sha256"] and r["cluster"] and
                      r["version"] == profile["k3s_version"] and self.member == r["first_server"] and
                      isinstance(r["registry"], str) and r["registry"] and
                      res == dict(res, kind="registry-auth", owner=owner, path=None,
                                  machine=self.member["machine"], namespace="broil-registry", name=self.secret) and
                      (res["id"] == "registry-auth-object-signing" if name is None else isinstance(name, str) and
                       re.fullmatch(NAME, name) and opaque(res["id"]) and
                       re.fullmatch(PRINCIPAL_ID % re.escape(name), res["id"])) and
                      (res["uid"] is None or opaque(res["uid"])), "ownership")
        # The request's Resource fixes the data key.
        self.key = "signing-key" if name is None else "password"
        self.owned_secret = self.ownership(origin)
        self.path = "%s/resources/%s/%s" % (self.owner_path, res["id"], res["generation"])

    def observe(self):
        """The prerequisite, classes and `signing` fact."""
        self.prerequisite()
        expected, res = self.header["expected"], self.recipe["resource"]
        secret = self.signing_secret(self.secret, res["generation"], expected["secret"], self.owned_secret, self.key)
        registration = {"class":"absent", "directory":None, "record_sha256":None}
        try:
            fd = state_directory(self.path)
            try:
                here, record = identity(fd), state_read(self.path + "/binding.json")
            finally:
                os.close(fd)
            sha = hashlib.sha256(canonical(record)).hexdigest()
            present = record and record["directory"] == here and expected["registration"] == {"directory":here, "record_sha256":sha}
            registration.update({"class":"present", "directory":here, "record_sha256":sha} if present else {"class":"foreign"})
        except FileNotFoundError:
            pass
        except (StateRefused, KeyError, TypeError, AttributeError, ValueError) as error:
            failure = getattr(error, "failure", None)
            state_require(failure != "bound", "bound")
            registration["class"] = "unobservable" if failure == "timeout" else "foreign"
        except (Refused, OSError):
            registration["class"] = "unobservable"
        state = ("unobservable" if {secret["class"], registration["class"]} & {"unobservable", "foreign", "owned-drifted"}
                 else secret["activation"] if secret["class"] == "owned" else "absent")
        return [secret], registration, {"state":state, "generation":res["generation"]}

    def register(self, records):
        """The header's projection under the control body's own admission checks."""
        projection, profile, r, b, res = self.header["projection"], self.host_profile, self.recipe, self.binding, \
            self.header["resource"]
        try:
            entry = projection["registries"][projection["declaration"]["registry"]["endpoint"]]
            origin = normalized_origin(entry["declaration"]["endpoint"])
        except (KeyError, TypeError, ValueError, AttributeError):
            origin = None
        state_require(isinstance(projection, dict) and set(projection) == set(
            "schema binding declaration scripts registries secrets references profile".split()) and
                      isinstance(origin, str) and projection["schema"] == 1 and projection["profile"] == profile and
                      projection["binding"] == {
                          **{k:r["scope"][k] for k in ("project", "environment", "target")}, "owner":r["owner"],
                          "operation":b["operation"], "attempt":b["attempt"], "service":r["registry"], "origin":origin,
                          "cluster":r["cluster"], **dict.fromkeys(("source", "issuer", "recovery")),
                          "principal":r["principal"],
                          "destination":{k:r["first_server"][k] for k in ("machine", "member", "role", "node_uid")},
                          "resource":dict({k:res[k] for k in ("kind", "id", "generation")}, uid=records[0]["uid"]),
                          "profile_sha256":b["fingerprints"]["profile_sha256"], "script_sha256":profile["script_sha256"]},
                      "ownership")

    def run(self, result):
        records, registration, signing = self.observe()
        tag, res = self.tag, self.header["resource"]
        if tag == "inspect-objects":
            result.update(objects=records, registration=registration, signing=signing,
                          services="unobserved" if signing["state"] == "active" else "not-ready")
            return
        self.active()
        state_require(res == self.recipe["resource"] and
                      self.header["preflight"] == {"objects":records, "registration":registration, "signing":signing} and
                      (records[0]["class"], records[0]["activation"], records[0]["keys"], registration["class"]) ==
                      tuple([self.key] if x == "key" else x for x in ROWS[tag]),
                      "ownership")
        if tag == "register-input":
            self.register(records)
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        uid = res["uid"]
        self.effect_started = True
        if tag == "create-object":
            uid = self.kubectl("create", "-f", "-", "-o", "jsonpath={.metadata.uid}", limit=512, mutating=True,
                               input=canonical({"apiVersion":"v1", "kind":"Secret", "type":"Opaque", "metadata":{
                                   "name":self.secret, "namespace":"broil-registry", "annotations":self.owned_secret,
                                   "labels":dict(zip(LABELED, (self.recipe["owner"], res["generation"], "inactive",
                                                               "broil", "registry-auth")))}}) + b"\n").decode()
            state_require(opaque(uid))
        elif tag == "activate":
            label = "/metadata/labels/broil.dev~1activation"
            patch = [{"op":"test", "path":"/metadata/uid", "value":uid}, {"op":"test", "path":label, "value":"inactive"},
                     {"op":"replace", "path":label, "value":"active"}]
            state_require(self.kubectl("patch", "secret", self.secret, "-n", "broil-registry", "--type=json", "-p",
                                       canonical(patch).decode(), "-o", "jsonpath={.metadata.uid}", limit=512,
                                       mutating=True) == uid.encode())
        else:
            parent = self.path.rsplit("/", 1)[0]
            state_mkdir(parent.rsplit("/", 1)[0])
            state_mkdir(parent)
            fd = state_directory(parent)
            try:
                os.mkdir(res["generation"], 0o700, dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)
            fd = state_directory(self.path)
            here = identity(fd)
            os.close(fd)
            record = {"schema":1, "directory":here, "projection":self.header["projection"], "inactive":True,
                      "registration_pending":False}
            state_publish(self.path + "/binding.json", record)
            result["registration"] = {"class":"present", "directory":here,
                                      "record_sha256":hashlib.sha256(canonical(record)).hexdigest()}
            uid = None
        result["terminal"] = self.terminal("succeeded", None, res, uid)



# ---- The token protocol ----
TOKEN_TAGS = ("inspect-host", "import-image", "inspect-objects", "create-object", "configure-token", "switch-registry",
              "configure-principals")
TOKEN = {"broil.dev/managed-by":"broil", "broil.dev/component":"registry-token"}
SERVICE = {"broil.dev/managed-by":"broil", "broil.dev/component":"registry-service"}
AUTH = {"image":"broil.invalid/candidate/auth", "digest":"b15a78d2bf9007e75f0aab45f540254ce18451289a4868748b599b5175167591"}
NAMED, DIGESTED, PIN = AUTH["image"] + ":broil-proof", AUTH["image"] + "@sha256:" + AUTH["digest"], \
    "io.cri-containerd.pinned=pinned"
# The registry's 187-byte configuration, and the auth configuration with no user.
BASE = ("version: 0.1\nlog:\n  level: error\nstorage:\n  filesystem:\n    rootdirectory: /data\n  delete:\n"
        "    enabled: false\n  maintenance:\n    uploadpurging:\n      enabled: false\nhttp:\n  addr: \":5000\"\n")
SERVER = ('server:\n  addr: ":5001"\ntoken:\n  issuer: "broil-registry-token"\n  expiration: 300\n  certificate: '
          '/config/signer.crt\n  key: /signing/signing-key\n  disable_legacy_key_id: true\nusers: {}\nacl: []\n')
# The objects in order: kind, API version, `kubectl get` resource and admitted server-written annotations.
OBJECTS = (("NetworkPolicy", "networking.k8s.io/v1", "networkpolicies.networking.k8s.io", {}),
           ("Secret", "v1", "secrets", {}), ("DaemonSet", "apps/v1", "daemonsets.apps",
                                             {"deprecated.daemonset.template.generation":"1"}),
           ("Service", "v1", "services", {}), ("IngressRoute", "traefik.io/v1alpha1", "ingressroutes.traefik.io", {}))
DEFAULTS = {"internalTrafficPolicy":"Cluster", "ipFamilies":["IPv4"], "ipFamilyPolicy":"SingleStack",
            "sessionAffinity":"None"}
SECURE = {"allowPrivilegeEscalation":False, "readOnlyRootFilesystem":True, "capabilities":{"drop":["ALL"]}}
RESOURCES = {"requests":{"cpu":"50m", "memory":"64Mi"}, "limits":{"memory":"256Mi"}}
# The Node rows: name, UID, `spec.unschedulable` and the `Ready` status.
NODES = '{range .items[*]}{.metadata.name}{"\\t"}{.metadata.uid}{"\\t"}{.spec.unschedulable}{"\\t"}' \
        '{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\\n"}{end}'
# The exact action set per purpose, and a repository path without its authority.
PURPOSES = {"publication":["pull", "push"], "node-pull":["pull"], "maintenance":["pull", "delete"]}
COMPONENT = "[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
PATH = "%s(?:/%s)*" % (COMPONENT, COMPONENT)
# The per-item templates: the fact read's name, resourceVersion and eighteen fields, and
# the value read's binding fields with the base64 `password`; a bare object answers one name, a `List` several.
EACH = '{{if eq .kind "List"}}{{range .items}}%s{{end}}{{else}}%s{{end}}'
FACT = '{{.metadata.name}}{{"\\t"}}{{.metadata.resourceVersion}}{{"\\t"}}' + SECRET_FIELDS + '{{"\\n"}}'
VALUE = '{{"\\t"}}'.join(["{{.metadata.name}}", "{{.metadata.uid}}", "{{.metadata.resourceVersion}}",
                         '{{with .metadata.labels}}{{index . "broil.dev/activation"}}{{end}}',
                         '{{with .data}}{{index . "password"}}{{end}}']) + '{{"\\n"}}'
VERIFIER = rb"(\$2b\$10\$[./A-Za-z0-9]{53})"


def listed(value):
    """`principals`, as the recipe and `expected` carry it: null, or a list in name order."""
    if value is None:
        return
    state_require(isinstance(value, list) and 0 < len(value) <= 8, "ownership")
    for p in value:
        state_fields(p, "name purpose repositories actions secret")
        x, paths = p["secret"], p["repositories"]
        state_fields(x, "id generation name uid operation recipe_sha256")
        state_hex(x["generation"])
        state_hex(x["recipe_sha256"], 64)
        state_require(isinstance(p["name"], str) and re.fullmatch(NAME, p["name"]) and len(p["name"]) <= 93 and
                      PURPOSES.get(p["purpose"]) == p["actions"] and isinstance(paths, list) and 0 < len(paths) <= 64 and
                      len(set(map(str, paths))) == len(paths) and
                      all(isinstance(y, str) and len(y) <= 255 and re.fullmatch(PATH, y) for y in paths) and
                      opaque(x["id"]) and re.fullmatch(PRINCIPAL_ID % re.escape(p["name"]), x["id"]) and
                      re.fullmatch("broil-input-[0-9a-f]{40}", str(x["name"])) and opaque(x["uid"]) and
                      str(x["operation"]).startswith("infra-operation-"), "ownership")
    state_require([p["name"] for p in value] == sorted({p["name"] for p in value}), "ownership")


def rendered(principals, verifiers):
    """The principal render: the auth configuration with its users and access-control list."""
    if principals is None:
        return SERVER
    q = json.dumps
    return SERVER[:-len("users: {}\nacl: []\n")] + "users:\n" + "".join(
        "  %s:\n    password: %s\n" % (q(p["name"]), q(v)) for p, v in zip(principals, verifiers)) + "acl:\n" + "".join(
        '  - match: {account: %s, type: "repository", name: %s}\n    actions: [%s]\n' % (
            q(p["name"]), q(path), ", ".join(map(q, p["actions"]))) for p in principals for path in p["repositories"])


def bcrypt():
    """The host `crypt`, its deprecation warning kept off standard error."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            import crypt
        except ImportError:
            raise StateRefused("capability")
    state_require(getattr(getattr(crypt, "METHOD_BLOWFISH", None), "ident", None) == "2b", "capability")
    return crypt


class Framing:
    """The grant-probe response, decoded as it arrives: `feed` returns a 200's body, or `other`, once the framing
    completes and None before. Each chunk is decoded once, never again from the start, and the read stops after
    540672 bytes, the head bound plus twice the body bound."""

    def __init__(self):
        self.data, self.body, self.start, self.length, self.at = bytearray(), bytearray(), None, None, 0

    def feed(self, chunk):
        data = self.data
        data += chunk
        require(len(data) <= 16384 + 2 * 262144)
        if self.start is None:
            end = data.find(b"\r\n\r\n")
            require(0 <= end <= 16380 or end < 0 and len(data) <= 16384)
            if end < 0:
                return None
            lines = bytes(data[:end]).split(b"\r\n")
            if lines[0].split(b" ")[1:2] != [b"200"]:
                return "other"
            fields = [line.partition(b":") for line in lines[1:]]
            named = lambda name: [value.strip() for key, _, value in fields if key.strip().lower() == name]
            length, chunked = named(b"content-length"), named(b"transfer-encoding")
            require((len(length), chunked) in ((1, []), (0, [b"chunked"])))
            if length:
                require(re.fullmatch(rb"[0-9]{1,6}", length[0]) and int(length[0]) <= 262144)
                self.length = int(length[0])
            self.start = self.at = end + 4
        if self.length is not None:
            return bytes(data[self.start:self.start + self.length]) if len(data) - self.start >= self.length else None
        while (line := data.find(b"\r\n", self.at)) >= 0:
            size = bytes(data[self.at:line]).split(b";")[0].strip()
            require(re.fullmatch(rb"[0-9a-fA-F]{1,6}", size) and len(self.body) + int(size, 16) <= 262144)
            if not int(size, 16):
                # Trailers, if any, end at the empty line.
                require(len(data) - line <= 16384)
                return bytes(self.body) if data.find(b"\r\n\r\n", line) >= 0 else None
            at = line + 2 + int(size, 16)
            if len(data) < at + 2:
                return None
            require(data[at:at + 2] == b"\r\n")
            self.body += data[line + 2:at]
            self.at = at + 2
        require(len(data) - self.at <= 4096)


def fetch(context, member, host, request, end):
    """One token request: its framed answer, or the connection's class. The read ends at `end` even while
    the peer keeps sending."""
    left, step = lambda: max(0.001, end - time.monotonic()), "unreachable"
    try:
        with socket.create_connection((member, 443), timeout=left()) as raw:
            raw.settimeout(left())
            step = "untrusted"
            with context.wrap_socket(raw, server_hostname=host) as tls:
                step, answer, done = "unobservable", Framing(), None
                tls.sendall(request)
                while done is None:
                    require(time.monotonic() < end)
                    tls.settimeout(left())
                    chunk = tls.recv(65536)
                    require(chunk)
                    done = answer.feed(chunk)
                return done
    except TimeoutError:
        return "unobservable"
    except OSError:
        return step
    except Exception:
        return "unobservable"


def granted(body, entry, service):
    """`granted`: the token's claims, unverified, grant exactly the declared actions and nothing on the catalog."""
    try:
        part = decode(body)["token"].split(".")[1]
        claims = decode(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        got = {}
        for item in claims["access"]:
            require((item["type"], item["name"]) not in got and isinstance(item["actions"], list))
            got[item["type"], item["name"]] = sorted(item["actions"])
        return (claims["iss"] == "broil-registry-token" and claims["aud"] == service and
                got.pop(("registry", "catalog"), []) == [] and
                got == {("repository", x):sorted(entry["actions"]) for x in entry["repositories"]})
    except (Refused, ValueError, TypeError, KeyError, AttributeError, IndexError):
        return False


def pick(render, actual):
    """`actual` restricted to the fields that `render` carries."""
    if isinstance(render, dict) and isinstance(actual, dict):
        return {key:pick(value, actual.get(key)) for key, value in render.items()}
    if isinstance(render, list) and isinstance(actual, list) and len(render) == len(actual):
        return [pick(value, item) for value, item in zip(render, actual)]
    return actual


def tolerated(error):
    """A failed read is `unobservable`; a read past its bound refuses `bound`."""
    state_require(getattr(error, "failure", None) != "bound", "bound")


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    value = hashlib.sha256()
    while chunk := os.read(fd, 1048576):
        state_check()
        value.update(chunk)
    return value.hexdigest()


def b64(text):
    return base64.b64encode(text.encode()).decode()


def address(value):
    try:
        return isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def exchange(context, member, host, path, end):
    """One request without credentials: the response head, or the connection's failure."""
    left, step = lambda: max(0.001, end - time.monotonic()), "unreachable"
    try:
        with socket.create_connection((member, 443), timeout=left()) as raw:
            raw.settimeout(left())
            step = "untrusted"
            with context.wrap_socket(raw, server_hostname=host) as tls:
                step, head = "unobservable", b""
                tls.sendall(b"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path.encode(), host.encode()))
                while b"\r\n\r\n" not in head and len(head) <= 16384:
                    tls.settimeout(left())
                    chunk = tls.recv(16385 - len(head))
                    if not chunk:
                        break
                    head += chunk
                end = head.find(b"\r\n\r\n")
                return head[:end] if 0 <= end <= 16380 else "unobservable"
    except TimeoutError:
        return "unobservable"
    except OSError:
        return step
    except Exception:
        return "unobservable"


def answer(head):
    """A head's status, its `WWW-Authenticate` values and whether it carries Distribution's API header."""
    lines = head.split(b"\r\n")
    fields = [line.partition(b":") for line in lines[1:]]
    named = lambda name: [value.strip() for key, _, value in fields if key.strip().lower() == name]
    return lines[0].split(b" ")[1:2], named(b"www-authenticate"), b"registry/2.0" in named(
        b"docker-distribution-api-version")


class TokenReceiver(RegistryReceiver):
    FAMILY, KEYS, HOST, VERSION = "registry-token", ("recipe", "expected", "resource", "preflight", "object_ordinal",
                                                     "probe"), ("inspect-host", "import-image"), 2
    crypt, facts, versions, values, malformed = None, {}, {}, {}, False

    def __init__(self, header):
        super().__init__(header)
        # The payload binds `member` too, which the registry request requires in the header.
        self.payload["member"] = header.get("member")

    @staticmethod
    def admit(header, tag):
        """`expected`, `object_ordinal`, `probe` and `member`."""
        expected, ordinal, recipe, member = header["expected"], header["object_ordinal"], header["recipe"], header.get("member")
        state_require((member is None) != (tag in TokenReceiver.HOST), "ownership")
        if member is not None:
            state_member(member)
        state_fields(expected, "objects certificate configuration principals")
        listed(expected["principals"])
        # `probe` only on an `observe` request's read with installed principals.
        state_require(type(header["probe"]) is bool and (not header["probe"] or tag == "inspect-objects" and
                      expected["principals"] is not None and isinstance(recipe, dict) and
                      recipe.get("stage") == "observe"), "ownership")
        state_require(isinstance(expected["objects"], list) and len(expected["objects"]) == 5 and
                      all(uid is None or opaque(uid) for uid in expected["objects"]) and
                      (ordinal is None) != (tag == "create-object"), "ownership")
        for value in (expected["certificate"], expected["configuration"]):
            if value is not None:
                state_hex(value, 64)
        if ordinal is not None:
            state_uint(ordinal, 1, 5)

    def check(self, profile):
        """The recipe against the pins; host actions on `member`, the rest on the first server."""
        r, b, expected = self.recipe, self.binding, self.header["expected"]
        state_fields(r, "scope owner operation cluster first_server members anchor_uid version registry image "
                        "assets tolerations endpoint trust ingress token certificate signing service principals stage "
                        "origins profile_sha256")
        t, c, s, v, o, e = r["token"], r["certificate"], r["signing"], r["service"], r["origins"], r["endpoint"]
        members, assets, member = r["members"], r["assets"], self.header.get("member")
        state_require(isinstance(members, list) and 0 < len(members) <= 64 and isinstance(assets, list) and
                      len(assets) == len(members), "ownership")
        for value, names in ((t, "realm path service issuer"), (c, "pem sha256"),
                             (o, "objects certificate switch principals"),
                             (s, "name uid generation operation recipe_sha256"),
                             (v, "configmap deployment image path writer writer_generation"), (e, "name host port origin"),
                             (r["trust"], "certificates sha256")):
            state_fields(value, names)
        for value in (v["configmap"], v["deployment"]):
            state_fields(value, "uid annotations")
        state_cluster(r["cluster"])
        state_member(r["first_server"])
        for m, x in zip(members, assets):
            state_member(m)
            state_fields(x, "member generation marker_sha256")
            state_hex(x["generation"])
            state_hex(x["marker_sha256"], 64)
            state_require(m["role"] != "backup" and m["node_uid"] is not None and x["member"] == m["member"], "ownership")
        names = [m["member"] for m in members]
        path = v["path"]
        parts = Path(path).parts[1:] if isinstance(path, str) else ()
        state_require(len(set(names)) == len(names) and (member is None or member in members) and
                      path.startswith("/") and str(Path(path)) == path and parts and len(path.encode()) <= 4090 and
                      all(0 < len(p.encode()) <= 255 and p != ".." for p in parts) and v["writer"] in names, "ownership")
        state_uint(v["writer_generation"], 1)
        state_hex(s["generation"])
        for value in (c["sha256"], s["recipe_sha256"], r["trust"]["sha256"]):
            state_hex(value, 64)
        for taint in r["tolerations"] if isinstance(r["tolerations"], list) and len(r["tolerations"]) <= 64 else [None]:
            state_fields(taint, "key value effect")
            state_require(isinstance(taint["key"], str) and isinstance(taint["value"], str) and
                          taint["effect"] in ("NoSchedule", "PreferNoSchedule", "NoExecute"), "ownership")
        objects, create, pin = o["objects"], r["stage"] == "create", profile.get("registry") or {}
        state_require(objects is None or isinstance(objects, list) and len(objects) == 5, "ownership")
        for value, names in [(x, "operation recipe_sha256 uid") for x in objects or ()] + [
                (o["certificate"], "operation sha256"), (o["switch"], "operation configuration_sha256 certificate_sha256"),
                (o["principals"], "operation recipe_sha256 secrets")]:
            if value is not None:
                state_fields(value, names)
        listed(r["principals"])
        # The installed list's secrets, one per recipe entry, in its order.
        installed = (o["principals"] or {}).get("secrets")
        state_require(installed is None or r["principals"] is not None and isinstance(installed, list) and
                      len(installed) == len(r["principals"]), "ownership")
        listed([dict(x, secret=y) for x, y in zip(r["principals"] or [], installed or [])] or None)
        # Each listed Secret's name is its generation's.
        state_require(all(x["secret"]["name"] == "broil-input-" + name40([r["owner"], {"kind":"registry-auth", **{
            k:x["secret"][k] for k in ("id", "generation")}}]) for x in (r["principals"] or []) +
            (expected["principals"] or [])), "ownership")
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      r["profile_sha256"] == b["fingerprints"]["profile_sha256"] and r["cluster"] and
                      r["version"] == profile["k3s_version"] and opaque(r["registry"]) and opaque(r["anchor_uid"]) and
                      r["first_server"]["role"] == "server" and r["first_server"]["node_uid"] is not None and
                      self.member == (member if self.tag in self.HOST else r["first_server"]) and
                      profile.get("auth") == AUTH == r["image"] and
                      v["image"] == "%s@sha256:%s" % (pin.get("image"), pin.get("digest")) and
                      all(opaque(x["uid"]) and isinstance(x["annotations"], dict) and set(x["annotations"]) == set(OWNERSHIP)
                          for x in (v["configmap"], v["deployment"])) and
                      re.fullmatch("broil-input-[0-9a-f]{40}", str(s["name"])) and opaque(s["uid"]) and
                      str(s["operation"]).startswith("infra-operation-") and
                      t["path"] in ("/auth", "/auth/token") and t["issuer"] == "broil-registry-token" and
                      isinstance(t["realm"], str) and t["realm"].endswith(t["path"]) and isinstance(t["service"], str) and
                      t["service"] and not set(t["service"]) & set('"\\') and isinstance(c["pem"], str) and
                      hashlib.sha256((c["pem"] + "\n").encode()).hexdigest() == c["sha256"] and
                      isinstance(e["host"], str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", e["host"]) and
                      e["port"] == 443 and e["origin"] == f"https://{e['host']}:443" and
                      isinstance(r["trust"]["certificates"], list) and r["trust"]["certificates"] and
                      all(isinstance(x, str) for x in r["trust"]["certificates"]) and
                      isinstance(r["ingress"], list) and 0 < len(r["ingress"]) <= 128 and all(map(address, r["ingress"])) and
                      r["stage"] in ("create", "extend", "configure", "switch", "observe", "principals") and
                      (objects is None) == (o["certificate"] is None) == create and (o["switch"] is None or not create) and
                      (o["principals"] is None or o["switch"] is not None) and
                      (r["stage"] != "principals" or r["principals"] is not None and o["switch"] is not None) and
                      (create or expected["objects"] == [x["uid"] for x in objects]), "ownership")
        self.switched = {"config.yml":BASE + 'auth:\n  token:\n    realm: %s\n    service: %s\n    issuer: '
                         '"broil-registry-token"\n    rootcertbundle: /config/token.crt\n' % (
                             json.dumps(t["realm"]), json.dumps(t["service"])), "token.crt":c["pem"] + "\n"}
        self.switched_sha = state_hash("broil-k3s-registry-service-object-v1",
                                       {"data":self.switched, "binaryData":None, "immutable":None})
        self.wanted, self.service = self.renders(), self.service_render()

    # ---- Host facts and the import ----
    def runtime(self, *args, **options):
        return command(self.executable, list(args), limits=(MAXIMUM, 65536), **options)

    def entry(self):
        """The recipient replica member's `assets` entry."""
        return [x for x in self.recipe["assets"] if x["member"] == self.member["member"]][0]

    def assets(self):
        """The recipient member's bound generation Resource and path."""
        machine, generation = self.member["machine"], self.entry()["generation"]
        path = f"{self.owner_path}/assets/{generation}"
        return {"kind":"bootstrap-assets", "id":machine, "owner":self.binding["owner"], "generation":generation,
                "machine":machine, "path":path + "/", "namespace":None, "name":None, "uid":None}, path

    def generation(self):
        """The whole-generation check for `auth`; the held archive, or `readiness`."""
        resource, path = self.assets()
        gfd = archive = None
        try:
            gfd = state_directory(path)
            binding, marker = state_read(path + "/binding.json"), state_read(path + "/complete.json")
            state_require(binding is not None and marker is not None and
                          hashlib.sha256(canonical(marker)).hexdigest() == self.entry()["marker_sha256"],
                          "readiness")
            state_fields(binding, "schema kind recipe_sha256 resource directory")
            state_fields(marker, "schema kind scope owner operation attempt resource recipe_sha256 directory inactive assets")
            here, assets = identity(gfd), marker["assets"]
            state_require(binding["kind"] == "bootstrap-generation" and marker["kind"] == "bootstrap-complete" and
                          binding["resource"] == marker["resource"] == resource and marker["inactive"] is True and
                          binding["directory"] == marker["directory"] == here and
                          marker["owner"] == self.binding["owner"] and binding["recipe_sha256"] == marker["recipe_sha256"] and
                          marker["scope"] == self.binding["scope"] and isinstance(assets, list) and
                          all(isinstance(a, dict) and set(a) == {"id", "size", "sha256", "identity"} for a in assets),
                          "readiness")
            by_identity = {tuple(a["identity"]):a for a in assets}
            state_require(len(by_identity) == len(assets) == len({a["id"] for a in assets}), "readiness")
            seen = set()
            for name in set(state_names(path, 64)) - {"binding.json", "complete.json"}:
                fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=gfd)
                try:
                    asset = by_identity.get(tuple(identity(fd)))
                    state_require(asset is not None and state_private(fd).st_size == asset["size"] and
                                  digest(fd) == asset["sha256"] and (asset["id"] == "auth") == (name == "auth.tar"),
                                  "readiness")
                    seen.add(asset["id"])
                    if name == "auth.tar":
                        archive, fd = fd, None
                finally:
                    if fd is not None:
                        os.close(fd)
            state_require(seen == {a["id"] for a in assets} and archive is not None, "readiness")
            os.lseek(archive, 0, os.SEEK_SET)
            with open(os.dup(archive), "rb") as stream, tarfile.open(fileobj=stream, mode="r:") as bundle:
                member = bundle.getmember("index.json")
                state_require(member.isfile() and member.size <= 4096, "readiness")
                index = decode(bundle.extractfile(member).read(4097))
            manifests = index.get("manifests") if isinstance(index, dict) else None
            state_require(isinstance(manifests, list) and len(manifests) == 1 and isinstance(manifests[0], dict) and
                          manifests[0].get("digest") == "sha256:" + AUTH["digest"] and
                          manifests[0].get("annotations") == {"io.containerd.image.name":NAMED}, "readiness")
            return resource, here, archive
        except BaseException as error:
            if archive is not None:
                os.close(archive)
            # Any failed check, a missing directory or file and an unreadable archive index make the
            # generation `not-ready`.
            if isinstance(error, (StateRefused, OSError, KeyError, ValueError, TypeError, tarfile.TarError)):
                raise StateRefused("readiness")
            raise
        finally:
            if gfd is not None:
                os.close(gfd)

    def records(self):
        """The pinned records present, each with whether it carries the CRI pin label; None for another target."""
        found = {}
        for line in self.runtime("ctr", "-n", "k8s.io", "images", "ls").decode("utf-8").split("\n")[1:]:
            fields = line.split()
            if fields and fields[0] in (NAMED, DIGESTED):
                if fields[2] != "sha256:" + AUTH["digest"]:
                    return None
                found[fields[0]] = PIN in fields[-1].split(",")
        return found

    def image(self):
        """The `image` fact."""
        records, images = self.records(), decode(self.runtime("crictl", "images", "-o", "json"))["images"]
        state_require(isinstance(images, list))
        return "conflicting" if records is None else "ready" if records.get(NAMED) and records.get(DIGESTED) and any(
            isinstance(item, dict) and DIGESTED in (item.get("repoDigests") or ()) and item.get("pinned") is True
            for item in images) else "not-ready"

    def host(self):
        """The three host facts."""
        facts = dict.fromkeys(("generation", "image", "runtime"), "not-ready")
        try:
            os.close(self.generation()[2])
            facts["generation"] = "ready"
        except StateRefused as error:
            if error.failure != "readiness":
                raise
        try:
            facts["image"], facts["runtime"] = self.image(), "ready"
        except (Refused, StateRefused, ValueError, TypeError, KeyError):
            facts["image"] = "unobservable"
        return facts

    def started(self, result):
        """One-use receiver intent under the active reservation; a repeat returns its terminal."""
        self.active()
        previous = self.begin()
        result["terminal"] = previous
        self.revalidate()
        return previous is not None

    def import_image(self, result):
        """`import-image`: intent, the rechecks, then the import, tag and labels."""
        global EFFECTS
        pre = self.header["preflight"]
        state_require(self.recipe["stage"] in ("create", "extend") and self.header["resource"] == self.assets()[0] and
                      isinstance(pre, dict) and set(pre) == {"generation", "image", "runtime"} and
                      pre["generation"] == pre["runtime"] == "ready" and pre["image"] in ("ready", "not-ready"),
                      "ownership")
        if self.started(result):
            return
        resource, directory_id, archive = self.generation()
        try:
            state_require(self.image() != "conflicting", "ownership")
            self.effect_started = EFFECTS = True
            if NAMED not in self.records():
                os.lseek(archive, 0, os.SEEK_SET)
                self.runtime("ctr", "-n", "k8s.io", "images", "import", "-", source=archive, mutating=True, seconds=600)
            if DIGESTED not in self.records():
                self.runtime("ctr", "-n", "k8s.io", "images", "tag", NAMED, DIGESTED, mutating=True)
            for name in (NAMED, DIGESTED):
                self.runtime("ctr", "-n", "k8s.io", "images", "label", name, PIN, mutating=True)
            state_require(self.image() == "ready", "readiness")
            result["terminal"] = self.terminal("succeeded", None, resource, directory_id)
        finally:
            os.close(archive)
        result.update(self.host())

    # ---- API facts ----
    def tolerations(self):
        """The toleration rule; the API returns an empty toleration value omitted."""
        found = [dict({"key":t["key"], "operator":"Equal", "effect":t["effect"]}, **({"value":t["value"]} if t["value"] else {}))
                 for t in self.recipe["tolerations"]]
        return {"tolerations":found} if found else {}

    def renders(self):
        """The five renders, each with its metadata."""
        r, selector = self.recipe, {"matchLabels":TOKEN}
        secret = {"defaultMode":0o440, "secretName":"broil-registry-token"}
        # No node selector: one pod on every replica member's node, published on its loopback only.
        pod = {"automountServiceAccountToken":False, "enableServiceLinks":False, **self.tolerations(),
               "securityContext":{"runAsNonRoot":True, "runAsUser":10000, "runAsGroup":10000, "fsGroup":10000,
                                  "seccompProfile":{"type":"RuntimeDefault"}},
               "containers":[{"name":"token", "image":DIGESTED, "imagePullPolicy":"Never",
                              "args":["-logtostderr=true", "-v=0", "/config/config.yml"],
                              "ports":[{"containerPort":5001, "hostIP":"127.0.0.1", "hostPort":5598, "protocol":"TCP"}],
                              "securityContext":SECURE,
                              "resources":RESOURCES, "readinessProbe":{"tcpSocket":{"port":5001}, "periodSeconds":2},
                              "volumeMounts":[{"name":"config", "mountPath":"/config", "readOnly":True},
                                              {"name":"signing", "mountPath":"/signing", "readOnly":True}]}],
               "volumes":[{"name":"config", "secret":secret}, {"name":"signing", "secret":dict(
                   secret, secretName=r["signing"]["name"], items=[{"key":"signing-key", "path":"signing-key"}])}]}
        bodies = ({"spec":{"podSelector":selector, "policyTypes":["Ingress"], "ingress":[{"from":[{
                      "namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}},
                      "podSelector":{"matchLabels":{"app.kubernetes.io/name":"traefik",
                                                    "app.kubernetes.io/instance":"traefik-kube-system"}}}],
                      "ports":[{"protocol":"TCP", "port":5001}]}]}},
                  {"type":"Opaque", "data":{"config.yml":b64(SERVER), "signer.crt":b64(r["certificate"]["pem"] + "\n")}},
                  {"spec":{"selector":selector, "updateStrategy":{"type":"OnDelete"},
                           "template":{"metadata":{"labels":TOKEN}, "spec":pod}}},
                  {"spec":{"type":"ClusterIP", "selector":TOKEN, "ports":[{"port":5001, "targetPort":5001, "protocol":"TCP"}]}},
                  {"spec":{"entryPoints":["websecure"], "routes":[{"kind":"Rule", "match":"Host(`%s`) && Path(`%s`)" % (
                      r["endpoint"]["host"], r["token"]["path"]), "services":[{"name":"broil-registry-token", "port":5001}]}],
                           "tls":{}}})
        origins = r["origins"]["objects"] or [None] * 5
        return [{"apiVersion":row[1], "kind":row[0], "metadata":{"name":"broil-registry-token", "namespace":"broil-registry",
                 "labels":TOKEN, "annotations":self.ownership(origins[n])}, **bodies[n]} for n, row in enumerate(OBJECTS)]

    def service_render(self):
        """The writer Deployment, which the registry `process` requires `owned`."""
        v = self.recipe["service"]
        pod = {"automountServiceAccountToken":False, "enableServiceLinks":False,
               "nodeSelector":{"kubernetes.io/hostname":v["writer"]}, **self.tolerations(),
               "securityContext":{"runAsNonRoot":True, "runAsUser":10000, "runAsGroup":10000,
                                  "seccompProfile":{"type":"RuntimeDefault"}},
               "containers":[{"name":"distribution", "image":v["image"], "imagePullPolicy":"Never",
                              "args":["serve", "/config/config.yml"], "ports":[{"containerPort":5000, "protocol":"TCP"}],
                              "securityContext":SECURE, "resources":RESOURCES,
                              "readinessProbe":{"tcpSocket":{"port":5000}, "periodSeconds":2},
                              "volumeMounts":[{"name":"data", "mountPath":"/data"},
                                              {"name":"config", "mountPath":"/config", "readOnly":True}]}],
               "volumes":[{"name":"data", "hostPath":{"path":v["path"] + "/data", "type":"Directory"}},
                          {"name":"config", "configMap":{"name":"broil-registry"}}]}
        return {"apiVersion":"apps/v1", "kind":"Deployment", "metadata":{
            "name":"broil-registry", "namespace":"broil-registry", "labels":SERVICE,
            "annotations":v["deployment"]["annotations"]}, "spec":{"replicas":1, "strategy":{"type":"Recreate"},
            "selector":{"matchLabels":SERVICE}, "template":{"metadata":{"labels":SERVICE}, "spec":pod}}}

    def project(self, obj, render):
        """The projection with the render's; the token Secret's checks, never hashed."""
        kind = render["kind"]
        if kind == "Secret":
            data = obj.get("data") or {}
            return ((obj.get("type"), set(data), "immutable" in obj,
                     self.configured(base64.b64decode(data.get("config.yml", ""), validate=True)),
                     hashlib.sha256(base64.b64decode(data.get("signer.crt", ""), validate=True)).hexdigest()),
                    ("Opaque", {"config.yml", "signer.crt"}, False, True, self.header["expected"]["certificate"]))
        if kind == "Service":
            return ({key:value for key, value in obj["spec"].items() if key not in ("clusterIP", "clusterIPs")},
                    {**render["spec"], **DEFAULTS})
        return ({"generation":obj["metadata"].get("generation"), "spec":pick(render["spec"], obj.get("spec"))},
                {"generation":self.recipe["service"]["writer_generation"] if render is self.service else 1,
                 "spec":render["spec"]})

    def configured(self, raw):
        """The auth configuration with no user, or the installed list's render with verified verifiers."""
        listed = self.header["expected"]["principals"]
        if listed is None:
            return raw == SERVER.encode()
        found = re.fullmatch(VERIFIER.join(map(re.escape, rendered(listed, "@" * len(listed)).encode().split(b"@"))), raw)
        if not found:
            return False
        for entry, verifier in zip(listed, found.groups()):
            name = entry["secret"]["name"]
            # Only a read that fails is `unobservable`; any other unusable entry is drift.
            state_require(self.facts[name]["class"] != "unobservable" and self.values is not None, "readiness")
            value = self.values.get(name)
            try:
                if self.facts[name]["activation"] != "active" or value is None or not hmac.compare_digest(
                        self.crypt.crypt(value, verifier.decode()) or "", verifier.decode()):
                    return False
            except (OSError, ValueError):
                return False
        return True

    def batch(self, template, names):
        """The bounded read: each found name's fields, False for an unparsed item; None
        when the read fails."""
        out = self.kubectl("get", "secrets", *names, "-n", "broil-registry", "-o", "go-template=" + EACH % (
            template, template), limit=262144, probe=True)
        if out is None or not out[1].endswith(b"\n") and out[1]:
            return None
        rows = {}
        for line in out[1].decode("utf-8", "replace").split("\n")[:-1]:
            f = line.split("\t")
            if f[0] not in names or f[0] in rows:
                return None
            rows[f[0]] = f
        absent = [name for name in names if name not in rows]
        lines = [b'Error from server (NotFound): secrets "%s" not found\n' % name.encode() for name in absent]
        return rows if out[0] == (1 if absent else 0) and sorted(out[2].splitlines(True)) == sorted(lines) else None

    def principal_reads(self, values):
        """The fact read, then, with `values`, the value read bound to it."""
        entries = {x["secret"]["name"]:x["secret"] for x in (self.recipe["principals"] or []) +
                   (self.header["expected"]["principals"] or [])}
        if not entries:
            return
        rows, self.facts, self.versions, self.values, self.malformed = self.batch(FACT, list(entries)), {}, {}, {}, False
        for name, x in entries.items():
            # An absent name is `absent`; a failed read or an unparsed item is discarded, `unobservable`.
            f = (rows or {}).get(name)
            out = None if rows is not None and f is None else "\t".join(f[2:]).encode() if f and len(f) == 20 else b""
            self.facts[name] = self.signing_secret(name, x["generation"], x["uid"], self.ownership(x), "password", out)
            self.versions[name] = f[1] if f and len(f) == 20 else None
        if not values:
            return
        rows = self.batch(VALUE, list(entries))
        if rows is None:
            self.values = None
            return
        for name, fact in self.facts.items():
            f = rows.get(name, ())
            if len(f) != 5 or fact["class"] != "owned" or fact["activation"] != "active" or f[1:4] != [
                    fact["uid"], self.versions[name], "active"]:
                continue
            try:
                raw = base64.b64decode(f[4], validate=True)
            except ValueError:
                continue
            try:
                self.values[name] = raw.decode("utf-8")
            except UnicodeDecodeError:
                self.malformed = True
            self.malformed |= not 0 < len(raw) <= 72 or b"\0" in raw

    def principal_fact(self):
        """The `principals` fact."""
        return None if self.recipe["principals"] is None else [
            {k:self.facts[x["secret"]["name"]][k] for k in ("class", "activation")} for x in self.recipe["principals"]]

    def read(self, n, mark=TOKEN):
        """The record of token object `n`, or of the writer Deployment for `SERVICE`, with the object itself."""
        # The writer Deployment's revision is `1 + k` after k writer moves.
        row, render = (OBJECTS[n], self.wanted[n]) if mark is TOKEN else (("Deployment", "apps/v1", "deployments.apps", {
            "deployment.kubernetes.io/revision":str(1 + (self.recipe["service"]["writer_generation"] - 1) // 2)}),
            self.service)
        uid = self.header["expected"]["objects"][n] if mark is TOKEN else self.recipe["service"]["deployment"]["uid"]
        wanted = render["metadata"]
        record = {"kind":row[0], "namespace":"broil-registry", "name":wanted["name"], "uid":None, "class":"absent",
                  "spec_sha256":None}
        raw = self.get(row[2], wanted["name"], "-n", "broil-registry", "-o", "json")
        if raw is None:
            return record, None
        try:
            state_require(raw is not False)
            obj = decode(raw)
            meta = obj["metadata"]
            found = meta.get("annotations") or {}
            state_require(obj["kind"] == row[0] and meta["name"] == wanted["name"] and
                          meta.get("namespace") == "broil-registry" and opaque(meta["uid"]))
            projection, expected = self.project(obj, render)
            attributed = uid == meta["uid"] and all(found.get(k) == v for k, v in wanted["annotations"].items())
            exact = meta.get("labels") == mark and {k:v for k, v in found.items() if row[3].get(k) != v} == \
                wanted["annotations"] and not meta.get("finalizers") and not meta.get("ownerReferences") and \
                "deletionTimestamp" not in meta and projection == expected
            record.update(uid=meta["uid"], **{"class":"owned" if attributed and exact else "owned-drifted" if attributed
                                              else "foreign"})
            if n != 1:
                record["spec_sha256"] = state_hash("broil-k3s-registry-token-object-v1", projection)
            state_require(len(canonical(record)) <= 512, "bound")
            return record, obj
        except (Refused, StateRefused, ValueError, TypeError, KeyError, AttributeError) as error:
            tolerated(error)
        record.update(uid=None, spec_sha256=None, **{"class":"unobservable"})
        return record, None

    def configmap(self):
        """`registry.configmap`, the first class that applies, its projection hash and the object."""
        v, alternate = self.recipe["service"]["configmap"], self.header["expected"]["configuration"]
        raw = self.get("configmaps", "broil-registry", "-n", "broil-registry", "-o", "json")
        if raw is None:
            return "absent", None, None
        try:
            state_require(raw is not False)
            obj = decode(raw)
            meta, projection = obj["metadata"], {key:obj.get(key) for key in ("data", "binaryData", "immutable")}
            sha = state_hash("broil-k3s-registry-service-object-v1", projection)
            exact = obj["kind"] == "ConfigMap" and meta["uid"] == v["uid"] and meta.get("labels") == SERVICE and \
                (meta.get("annotations") or {}) == v["annotations"] and not meta.get("finalizers") and \
                not meta.get("ownerReferences") and "deletionTimestamp" not in meta
        except (Refused, StateRefused, ValueError, TypeError, KeyError, AttributeError) as error:
            tolerated(error)
            return "unobservable", None, None
        return ("drifted" if not exact else
                "base" if projection == {"data":{"config.yml":BASE}, "binaryData":None, "immutable":None} else
                "switched" if sha in (alternate, self.switched_sha) else "drifted"), sha, obj

    def pods(self, component):
        """The pods of a component's selector that are not being deleted; None when they cannot be read."""
        try:
            raw = self.kubectl("get", "pods", "-n", "broil-registry", "--selector",
                               "broil.dev/managed-by=broil,broil.dev/component=" + component, "-o", "json", limit=262144)
            return [pod for pod in decode(raw)["items"] if "deletionTimestamp" not in pod["metadata"]]
        except (Refused, StateRefused, ValueError, TypeError, KeyError, AttributeError) as error:
            tolerated(error)

    def pod(self, found, node):
        """One node's pods in order: the reason, node, restart count and readiness."""
        if len(found) != 1:
            return "pods" if found else "absent", None, None, False
        status = found[0].get("status") or {}
        container = (status.get("containerStatuses") or [{}])[0]
        state = container.get("state") or {}
        waiting, at, restarts = state.get("waiting"), found[0]["spec"].get("nodeName"), container.get("restartCount")
        state_require((at is None or opaque(at)) and (restarts is None or type(restarts) is int and restarts >= 0))
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions") or ())
        return ("node" if at not in (None, node) else
                "failed" if status.get("phase") in ("Failed", "Succeeded") or "terminated" in state or
                waiting is not None and waiting.get("reason") != "ContainerCreating" else
                "pending" if at is None or status.get("phase") != "Running" else
                "starting" if not ready else None), at, restarts, ready

    def process(self, component, deployment):
        """The process for the writer Deployment's read and its pods on the writer's node,
        or the token process for the DaemonSet's read and its pods on each replica member's node."""
        token, v = component == "registry-token", self.recipe["service"]
        names = [m["member"] for m in self.recipe["members"]] if token else [v["writer"]]
        value = {"state":"not-ready", "reason":"unobservable", **({"pods":[
            {"member":x, "ready":False, "restarts":None} for x in names]} if token else {"node":None, "restarts":None})}
        (record, obj), pods = deployment, self.pods(component)
        try:
            # Pods on a node that is no replica member are ignored.
            facts = [self.pod([p for p in pods if not token or p["spec"].get("nodeName") == x], x) for x in names]
            status = (obj or {}).get("status") or {}
            counted = obj is not None and ([status.get("observedGeneration")] == [1] if token else [status.get(key) for key in (
                "observedGeneration", "readyReplicas", "availableReplicas")] == [v["writer_generation"], 1, 1])
            stopped = not token and obj is not None and (obj.get("spec") or {}).get("replicas") == 0
        except (StateRefused, ValueError, TypeError, KeyError, AttributeError):
            return value
        if record["class"] == "unobservable":
            return value
        if token:
            value["pods"] = [{"member":x, "ready":f[0] is None, "restarts":f[2]} for x, f in zip(names, facts)]
        else:
            value.update(node=facts[0][1], restarts=facts[0][2])
        value["reason"] = ("stopped" if stopped and record["class"] in ("owned", "owned-drifted") else
                           ("daemonset" if token else "deployment") if record["class"] != "owned" else
                           next((f[0] for f in facts if f[0]), None) or (None if counted else "starting"))
        value["state"] = "not-ready" if value["reason"] else "ready"
        return value

    def nodes(self):
        """`nodes`: one fact per replica member, in member order."""
        try:
            rows = [line.split("\t") for line in self.kubectl("get", "nodes", "-o", "jsonpath=" + NODES,
                                                               limit=524288).decode().splitlines()]
            state_require(rows and all(len(row) == 4 for row in rows) and len({row[0] for row in rows}) == len(rows))
        except (Refused, StateRefused, UnicodeDecodeError) as error:
            tolerated(error)
            rows = None
        found = {row[0]:row for row in rows or ()}
        return [{"member":m["member"], "node":"unobservable" if rows is None else
                 "not-ready" if m["member"] not in found else
                 "drifted" if found[m["member"]][1] != m["node_uid"] else
                 "ready" if found[m["member"]][3] == "True" and found[m["member"]][2] != "true" else "not-ready"}
                for m in self.recipe["members"]]

    def context(self):
        """The exact trust in `recipe.trust.certificates`, or None when it does not load."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        try:
            context.load_verify_locations(cadata="".join(block + "\n" for block in self.recipe["trust"]["certificates"]))
            return context
        except (ssl.SSLError, ValueError):
            return None

    def enforcement(self):
        """`enforcement`: two requests without credentials per ingress member, concurrently."""
        r, t = self.recipe, self.recipe["token"]
        host, members, context = r["endpoint"]["host"], r["ingress"], self.context()
        if context is None:
            return [{"registry":"untrusted", "token":"untrusted"} for _ in members]
        out = [{"registry":"unobservable", "token":"unobservable"} for _ in members]
        challenge = b'Bearer realm="%s",service="%s"' % (t["realm"].encode(), t["service"].encode())

        def one(n, member):
            # One cap for both connections; its expiry is `unobservable`.
            end = min(DEADLINE, time.monotonic() + 8)
            for field, path in (("registry", "/v2/"), ("token", t["path"] + "?service=" + quote(t["service"], safe=""))):
                head = exchange(context, member, host, path, end)
                if isinstance(head, bytes):
                    status, auth, api = answer(head)
                    head = (("challenge" if status == [b"401"] and auth == [challenge] and api else
                             "open" if status[:1] and re.fullmatch(rb"2[0-9][0-9]", status[0]) and api else "other")
                            if field == "registry" else
                            "refused" if status == [b"401"] and auth == [b'Basic realm="broil-registry-token"'] else "other")
                out[n][field] = head
        threads = [threading.Thread(target=one, args=item, daemon=True) for item in enumerate(members)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return out

    def grants(self):
        """The grant probe: one token request per installed `publication` and `node-pull`
        principal, concurrently, through the first ingress member; the maintenance principal is never sent."""
        r, t = self.recipe, self.recipe["token"]
        probed = [x for x in self.header["expected"]["principals"] if x["purpose"] != "maintenance"]
        out, context = ["unobservable"] * len(probed), self.context()
        if context is None:
            return ["untrusted"] * len(probed)

        def one(n, entry):
            password = (self.values or {}).get(entry["secret"]["name"])
            if password is None:
                return
            query = "service=" + quote(t["service"], safe="") + "".join("&scope=" + quote(
                "repository:%s:pull,push,delete" % x, safe="") for x in entry["repositories"]) + "&scope=" + quote(
                "registry:catalog:*", safe="")
            basic = base64.b64encode(("%s:%s" % (entry["name"], password)).encode()).decode()
            body = fetch(context, r["ingress"][0], r["endpoint"]["host"], (
                "GET %s?%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nConnection: close\r\n\r\n" % (
                    t["path"], query, r["endpoint"]["host"], basic)).encode(), min(DEADLINE, time.monotonic() + 8))
            # The response, the token and the password are discarded here.
            out[n] = body if isinstance(body, str) else "granted" if granted(body, entry, t["service"]) else "other"
        threads = [threading.Thread(target=one, args=item, daemon=True) for item in enumerate(probed)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return out

    def inspect(self, result):
        """The facts, read in order, after the batched reads."""
        self.principal_reads(self.header["expected"]["principals"] is not None)
        state_require(not self.malformed, "credential")
        reads, s = [self.read(n) for n in range(5)], self.recipe["signing"]
        token = self.process("registry-token", reads[2])
        signing = self.signing_secret(s["name"], s["generation"], s["uid"], self.ownership(s))
        configmap, sha, _ = self.configmap()
        process = self.process("registry-service", self.read(2, SERVICE))
        result.update(objects=[record for record, _ in reads], signing={k:signing[k] for k in ("class", "activation")},
                      token=token, registry={"configmap":configmap, "configuration_sha256":sha, "process":process},
                      nodes=self.nodes(), enforcement=self.enforcement(), principals=self.principal_fact(),
                      grants=self.grants() if self.header["probe"] else None)

    # ---- The effects ----
    def fresh(self, resource):
        """The receiver checks: the step's Resource, intent, the prerequisite, then fresh records equal to `preflight`."""
        r = self.recipe
        state_require(isinstance(resource, dict) and resource == dict(
            resource, kind="service", owner=r["owner"], machine=None, path=None, namespace="broil-registry"), "ownership")
        state_hex(resource["generation"])
        self.prerequisite()
        principals = self.tag == "configure-principals"
        self.principal_reads(principals or self.header["expected"]["principals"] is not None)
        reads = [self.read(n) for n in range(5)]
        configmap, sha, obj = self.configmap()
        facts = [x["class"] for x in self.principal_fact() or ()] if principals else []
        state_require("unobservable" not in [record["class"] for record, _ in reads] + [configmap] + facts, "readiness")
        state_require(self.header["preflight"] == {"objects":[record for record, _ in reads],
                                                   "registry":{"configmap":configmap, "configuration_sha256":sha},
                                                   **({"principals":self.principal_fact()} if principals else {})},
                      "ownership")
        return reads, configmap, sha, obj

    def create_object(self, result):
        """`create-object`: the selected absent token object, created once."""
        n, res = self.header["object_ordinal"] - 1, self.header["resource"]
        state_require(self.recipe["stage"] == "create" and isinstance(res, dict) and
                      res.get("id") == "registry-token-object-%02d" % (n + 1) and res.get("name") == "broil-registry-token" and
                      res.get("uid") is None, "ownership")
        if self.started(result):
            return
        reads = self.fresh(res)[0]
        state_require(reads[n][0]["class"] == "absent" and (not n or reads[0][0]["class"] == "owned"), "ownership")
        state_require(DEADLINE - time.monotonic() >= 50, "timeout")
        self.effect_started = True
        uid = self.kubectl("create", "-f", "-", "-o", "jsonpath={.metadata.uid}", input=canonical(self.wanted[n]) + b"\n",
                           limit=512, timeout="40s", seconds=45, mutating=True).decode()
        state_require(opaque(uid))
        result["terminal"] = self.terminal("succeeded", None, res, uid)

    def configure(self, result):
        """`configure-token`, `switch-registry` and `configure-principals`: the
        pod read, one read-and-test patch, then the eviction."""
        r, res, e, tag = self.recipe, self.header["resource"], self.header["expected"], self.tag
        token, listed = tag != "switch-registry", r["principals"] if tag == "configure-principals" else None
        uid = e["objects"][1] if token else r["service"]["configmap"]["uid"]
        state_require(r["stage"] == {"configure-token":"configure", "switch-registry":"switch",
                                     "configure-principals":"principals"}[tag] and
                      isinstance(res, dict) and res.get("uid") == uid and
                      res.get("id") == ("registry-token-object-02" if token else "registry-service-object-03") and
                      res.get("name") == ("broil-registry-token" if token else "broil-registry"), "ownership")
        if self.started(result):
            return
        reads, configmap, sha, obj = self.fresh(res)
        # The stage's row: every token object owned; for the switch, the Secret at the recipe's certificate
        # and the ConfigMap `base` before any switch, otherwise `switched` at the recorded one; for the principals,
        # the ConfigMap `switched` at the recorded switch and every current generation's Secret `owned` and `active`.
        row = True if tag == "configure-token" else (configmap, sha) == ("switched", e["configuration"]) and \
            e["configuration"] is not None if listed else e["certificate"] == r["certificate"]["sha256"] and \
            (configmap, sha) == (("switched", e["configuration"]) if e["configuration"] else ("base", sha))
        state_require(row and all(record["class"] == "owned" for record, _ in reads), "ownership")
        if listed:
            facts = [self.facts[x["secret"]["name"]] for x in listed]
            state_require(all(x["class"] != "unobservable" for x in facts) and self.values is not None, "readiness")
            state_require(all((x["class"], x["activation"]) == ("owned", "active") for x in facts), "ownership")
            state_require(not self.malformed, "credential")
            state_require(all(self.values.get(x["secret"]["name"]) is not None for x in listed), "ownership")
        state_require(not self.malformed, "credential")
        if listed or tag == "configure-token" and e["principals"] is not None:
            # The first hash write, and every later token Secret write beside verifiers, takes the auth-Secret custody.
            out = command(self.executable, ["secrets-encrypt", "status"], limits=(65536, 65536), probe=True)
            state_require(out and not out[0] and b"Encryption Status: Enabled" in out[1], "readiness")
        if listed:
            c = self.crypt
            try:
                verifiers = [c.crypt(self.values[x["secret"]["name"]], c.mksalt(c.METHOD_BLOWFISH, rounds=1024))
                             for x in listed]
            except (OSError, ValueError):
                raise StateRefused("credential")
            state_require(all(re.fullmatch(VERIFIER, v.encode()) for v in verifiers), "capability")
            configuration = b64(rendered(listed, verifiers))
        # One eviction per token pod, each at the 20-second bound, so 20 seconds more per member beyond the first.
        names = [m["member"] for m in r["members"]]
        state_require(DEADLINE - time.monotonic() >= 60 + 20 * (len(names) - 1 if token else 0), "timeout")
        pods = self.pods("registry-token" if token else "registry-service")
        nodes = [(pod.get("spec") or {}).get("nodeName") for pod in pods or ()]
        state_require(pods is not None and (len(set(nodes)) == len(nodes) if token else len(pods) <= 1), "readiness")
        # In member order; a pod on a node that is no replica member follows them.
        order = lambda n: (names.index(nodes[n]), "") if nodes[n] in names else (len(names), str(nodes[n]))
        metas = [pods[n]["metadata"] for n in sorted(range(len(pods)), key=order)]
        state_require(all(opaque(meta["name"]) and opaque(meta["uid"]) for meta in metas))
        path, now, new = ("/data/config.yml", reads[1][1]["data"]["config.yml"], configuration) if listed else (
            "/data/signer.crt", reads[1][1]["data"]["signer.crt"], b64(r["certificate"]["pem"] + "\n")) \
            if token else ("/data", obj["data"], self.switched)
        patch = [{"op":"test", "path":"/metadata/uid", "value":uid}, {"op":"test", "path":path, "value":now},
                 {"op":"replace", "path":path, "value":new}]
        self.effect_started = True
        state_require(self.kubectl("patch", "secret" if token else "configmap", res["name"], "-n", "broil-registry",
                                   "--type=json", "--patch-file=/dev/stdin", "-o", "jsonpath={.metadata.uid}",
                                   input=canonical(patch), limit=512, mutating=True) == uid.encode())
        for meta in metas:
            self.kubectl("create", "--raw", "/api/v1/namespaces/broil-registry/pods/%s/eviction" % meta["name"], "-f", "-",
                         input=canonical({"apiVersion":"policy/v1", "kind":"Eviction", "metadata":{
                             "name":meta["name"], "namespace":"broil-registry"},
                             "deleteOptions":{"preconditions":{"uid":meta["uid"]}}}), limit=65536, mutating=True)
        result["terminal"] = self.terminal("succeeded", None, res, uid)

    def run(self, result):
        tag = self.tag
        if tag not in self.HOST and (self.recipe["principals"] or self.header["expected"]["principals"]):
            self.crypt = bcrypt()
        if tag == "inspect-host":
            result.update(self.host())
        elif tag == "inspect-objects":
            self.prerequisite()
            self.inspect(result)
        else:
            {"import-image":self.import_image, "create-object":self.create_object}.get(tag, self.configure)(result)


# Each protocol's receiver, reply magic, own header fields, tags, result facts and reply reserve.
PROTOCOLS = {"broil-k3s-registry-auth":(AuthReceiver, b"BK3SRAU1\n", "expected projection", AUTH_TAGS,
                                        ("objects", "registration", "signing", "services"), 8192),
             "broil-k3s-registry-token":(TokenReceiver, b"BK3SRTK2\n", "expected object_ordinal probe member", TOKEN_TAGS,
                                         ("generation", "image", "runtime", "objects", "signing", "token", "registry",
                                          "nodes", "enforcement", "principals", "grants"), 16384)}


def registry_request(raw, header):
    """One protocol's header."""
    global DEADLINE
    kind, _, fields, tags, _, reserve = PROTOCOLS[header["protocol"]]
    state_require(17 + len(raw) + reserve <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms recipe resource preflight " + fields)
    state_require(canonical(header) == raw, "integrity")
    state_require(type(header["version"]) is int and header["version"] == kind.VERSION,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > kind.VERSION else "integrity")
    tag = header["action"]
    state_require(tag in tags, "capability")
    mutation = not tag.startswith("inspect-")
    state_hex(header["request_id"])
    state_binding(header["binding"])
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation, "ownership")
    state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(header["recipe"])) <= 32768, "bound")
    kind.admit(header, tag)
    state_require((header["preflight"] is None) != mutation and (header["resource"] is None) != mutation, "ownership")
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    state_require(sys.stdin.buffer.read(1) == b"", "integrity")


def registry_main(raw, header):
    kind, magic, _, _, facts, _ = PROTOCOLS[header["protocol"]]
    receiver = None
    status = "unknown"
    result = {"terminal":None, **dict.fromkeys(facts), "failure":None}
    prefix = magic + struct.pack(">I", len(raw)) + raw
    try:
        registry_request(raw, header)
        receiver = kind(header)
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
                result["terminal"] = receiver.terminal("failed", failure, header["resource"])
                status = "failed"
            except BaseException:
                status = "unknown"
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root, receiver.executable):
                if fd is not None:
                    os.close(fd)
    if status != "ok":
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
    registry_main(raw, header)
    os._exit(0)
except Exception:
    os._exit(125)
