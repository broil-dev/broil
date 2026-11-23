#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, profile-bound K3s `release` body: the `broil-k3s-release` protocol and the release
Secret wire."""
import base64
import fcntl
import hashlib
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
import time

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
    "credential-grant": "binding action admission_sha256 selection_sha256 resource",
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


# The ten profile bodies.
BODIES = {"control", "lifecycle", "network", "ingress", "cert_manager", "registry", "node", "delivery", "release",
          "service_guard"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def utf8_safe(value):
    return isinstance(value, str) and 0 < len(value.encode()) <= 4096 and "\0" not in value


class Receiver:
    """The receiver framework that both protocols of the body share."""
    FAMILY, KEYS = None, ()

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
        self.effect_started = False
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
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == bodies["release"], "ownership")
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
        # A read off the recipe's `api_server` needs a server whose own claim binds the request's derived
        # participant set, which only a member of that set holds.
        state_require(not getattr(self, "status_read", False) or self.member["role"] == "server" and
                      self.claim["participants_sha256"] == self.binding["participants_sha256"], "ownership")
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
                 "effect":"complete" if outcome == "succeeded" else "unknown" if self.effect_started else "absent",
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

    def finish(self, outcome, failure, effect, resource=None, uid=None):
        """The terminal receipt with an explicit effect."""
        state_require(self.intent is not None and self.published is None and WRITERS_SETTLED, "busy")
        value = {"schema":1, "kind":"terminal", "binding":self.binding, "action":self.action,
                 "payload_sha256":self.intent["payload_sha256"], "outcome":outcome, "failure":failure, "effect":effect,
                 "writer_ended":True, "resource":resource, "resource_identity":uid, "completed_ms":state_now()}
        self.revalidate()
        state_publish(self.dispatch_path() + "/terminal.json", value)
        self.published = value
        return value

    def get(self, resource, name, namespace):
        """One object read: its JSON, or None for the exact `NotFound`; an object holds up to a whole payload."""
        outcome = self.kubectl("get", resource, name, "-n", namespace, "-o", "json", limit=4 * MAXIMUM, probe=True)
        state_require(outcome is not None, "timeout")
        if outcome[0] == 0:
            return decode(outcome[1])
        state_require(b"(NotFound)" in outcome[2], "transport")
        return None

    def namespace_missing(self, text, namespace):
        """The namespace rejection: the tool's error carries `(NotFound)` and `namespaces "<namespace>" not
        found`, and a live read of that Namespace finds it absent."""
        if "(NotFound)" not in text or 'namespaces "%s" not found' % namespace not in text:
            return False
        outcome = self.kubectl("get", "namespace", namespace, "-o", "json", limit=65536, probe=True)
        state_require(outcome is not None, "timeout")
        if outcome[0] == 0:
            return False
        state_require(b"(NotFound)" in outcome[2], "transport")
        return True

    def listed(self, resource, namespace, managed=False, selector=None):
        """One bounded list of `resource` in `namespace`; `managed` keeps each item's managedFields, which
        `kubectl get` otherwise omits; a `selector` narrows it by labels."""
        extra = ("--show-managed-fields",) if managed else ()
        extra += ("-l", selector) if selector else ()
        return decode(self.kubectl("get", resource, "-n", namespace, "-o", "json", *extra, limit=LIST))["items"]


# ---- The release protocol ----
TAGS = ("discover-kinds", "apply-objects", "inspect-workloads", "observe-release")
FACTS = ("kinds", "objects", "secrets", "workloads", "pods", "presence")
MAGIC = b"BK3SREL1\n"
PAYLOAD, LIST, REPLY, RECIPE = 983032, 524288, 262144, 49152
READS = ("discover-", "inspect-", "observe-")
LABEL = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")
SUBDOMAIN = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?")
KEY = re.compile(r"[-._a-zA-Z0-9]{1,253}")
WORKLOADS = {("apps/v1", "Deployment"), ("apps/v1", "StatefulSet"), ("apps/v1", "DaemonSet"),
             ("apps/v1", "ReplicaSet"), ("batch/v1", "Job"), ("v1", "Pod")}


def resource(api_version, kind):
    """The kubectl resource argument of a kind: `<kind>.<version>.<group>`, the bare kind for the core group."""
    group, _, version = api_version.rpartition("/")
    return kind.lower() + ("." + version + "." + group if group else "")


def kinds(value):
    state_require(isinstance(value, list) and len(value) <= 1024 and all(
        isinstance(k, dict) and set(k) == {"api_version", "kind"} and utf8_safe(k["api_version"]) and
        utf8_safe(k["kind"]) for k in value), "ownership")
    return value


def documents(data):
    """The YAML stream's documents, each as its exact bytes; empty and `null` ones skipped."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise StateRefused("integrity")
    docs, current = [], []

    def flush():
        body = "".join(current)
        meaningful = [x for x in body.splitlines() if x.strip() and not x.lstrip().startswith("#")]
        if meaningful and "".join(meaningful).strip() not in ("null", "~"):
            docs.append(body)
        current.clear()
    for line in text.splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        if bare == "---" or bare.startswith("--- "):
            flush()
            if bare.startswith("--- ") and bare[4:].strip():
                current.append(bare[4:] + "\n")
        elif bare == "...":
            flush()
        else:
            current.append(line)
    flush()
    return docs


def scalar(value):
    value = value.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def flow(value):
    """A one-line flow mapping's first-level keys and scalars, `{}` when `value` is not one."""
    value, out = value.strip(), {}
    if not value.startswith("{"):
        return out
    items, depth, quote, start = [], 0, None, 1
    for n, c in enumerate(value):
        if quote:
            quote = None if c == quote else quote
        elif c in "'\"":
            quote = c
        elif c in "{[":
            depth += 1
        elif c in "]}":
            depth -= 1
            if depth == 0:
                if value[n + 1:].strip() and not value[n + 1:].lstrip().startswith("#"):
                    return {}
                items.append(value[start:n])
                break
        elif c == "," and depth == 1:
            items.append(value[start:n])
            start = n + 1
    for item in items:
        key, sep, rest = item.partition(":")
        if sep:
            out[scalar(key)] = scalar(rest)
    return out


def named(doc):
    """A document's `(apiVersion, kind, namespace, name)`: a JSON document's fields, else the block mapping's top-level
    scalars and `metadata`'s first-level `name` and `namespace`, a one-line flow mapping's included."""
    try:
        value = json.loads(doc)
        meta = value.get("metadata") or {}
        return value.get("apiVersion"), value.get("kind"), meta.get("namespace"), meta.get("name")
    except (ValueError, AttributeError):
        pass
    top, meta, inside, depth = {}, {}, False, None
    for line in doc.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            match = re.match(r"([A-Za-z]+):(.*)$", line.rstrip())
            inside = bool(match) and match.group(1) == "metadata" and not scalar(match.group(2))
            if match and match.group(1) in ("apiVersion", "kind"):
                top[match.group(1)] = scalar(match.group(2))
            elif match and match.group(1) == "metadata":
                meta.update({k:v for k, v in flow(match.group(2)).items() if k in ("name", "namespace")})
        elif inside:
            depth = indent if depth is None else depth
            match = re.match(r"\s*(name|namespace):(.*)$", line.rstrip())
            if indent == depth and match:
                meta[match.group(1)] = scalar(match.group(2))
    return top.get("apiVersion"), top.get("kind"), meta.get("namespace"), meta.get("name")


def condition(obj, kind):
    return any(c.get("type") == kind and c.get("status") == "True" for c in (obj.get("status") or {}).get("conditions") or ())


def stalled(obj):
    return any(c.get("type") == "Progressing" and c.get("reason") == "ProgressDeadlineExceeded"
               for c in (obj.get("status") or {}).get("conditions") or ())


def rolling(spec):
    return (spec.get("updateStrategy") or {}).get("type", "RollingUpdate") == "RollingUpdate"


def readiness(w, obj):
    """The row of one workload object, `{available, desired, kind, name, namespace, outcome, ready,
    updated}`: `updated` null for a Job, a Pod and a ReplicaSet, `available` null for a Job and a Pod; an absent
    object is `not-ready` with null counts."""
    row = {"available":None, "desired":None, "kind":w["kind"], "name":w["name"], "namespace":w["namespace"],
           "outcome":"not-ready", "ready":None, "updated":None}
    if obj is None:
        return row
    spec, status, meta = obj.get("spec") or {}, obj.get("status") or {}, obj.get("metadata") or {}
    kind = w["kind"]
    if kind == "Job":
        row.update(desired=spec.get("completions") or 1, ready=status.get("succeeded") or 0)
        row["outcome"] = "failed" if condition(obj, "Failed") else \
            "succeeded" if row["ready"] == row["desired"] else "not-ready"
        return row
    if kind == "Pod":
        ready = int(status.get("phase") == "Running" and condition(obj, "Ready"))
        row.update(desired=1, ready=ready, outcome="succeeded" if ready else "not-ready")
        return row
    # Every other controller kind first observes its generation.
    current = status.get("observedGeneration") is not None and \
        status.get("observedGeneration") == meta.get("generation")
    if kind == "DaemonSet":
        desired = status.get("desiredNumberScheduled") or 0
        row.update(desired=desired, updated=status.get("updatedNumberScheduled") or 0,
                   ready=status.get("numberReady") or 0, available=status.get("numberAvailable") or 0)
        done = row["updated"] == desired and row["available"] == desired if rolling(spec) else row["ready"] == desired
    else:
        desired = spec.get("replicas", 1)
        row.update(desired=desired, ready=status.get("readyReplicas") or 0,
                   available=status.get("availableReplicas") or 0)
        if kind != "ReplicaSet":
            row["updated"] = status.get("updatedReplicas") or 0
        if kind == "Deployment":
            if current and spec.get("paused") is True:
                row["outcome"] = "paused"
                return row
            if current and stalled(obj):
                row["outcome"] = "stalled"
                return row
            done = row["updated"] == desired and (status.get("replicas") or 0) == desired and \
                row["available"] == desired
        elif kind == "StatefulSet" and rolling(spec):
            partition = ((spec.get("updateStrategy") or {}).get("rollingUpdate") or {}).get("partition") or 0
            done = row["updated"] >= (desired - partition if partition <= desired else 0) and row["ready"] == desired
        else:
            done = row["ready"] == desired
    row["outcome"] = "succeeded" if current and done else "not-ready"
    return row


def owned_by(obj, uid):
    return any(r.get("controller") is True and r.get("uid") == uid for r in (obj.get("metadata") or {}).get(
        "ownerReferences") or ())


SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


def image_id(raw):
    """An `image_id`: a status `imageID` with at most one leading `<scheme>://` removed, None when absent or
    empty; a remainder that is not printable ASCII without `"` or `\\`, or longer than 512 bytes, refuses
    `integrity`."""
    if raw is None or raw == "":
        return None
    state_require(isinstance(raw, str), "integrity")
    match = SCHEME.match(raw)
    value = raw[match.end():] if match else raw
    state_require(len(value) <= 512 and all(" " <= c <= "~" and c not in "\"\\" for c in value), "integrity")
    return value


def ordinal(pod):
    """A StatefulSet pod's ordinal: its `apps.kubernetes.io/pod-index` label, else its name's last part."""
    meta = pod.get("metadata") or {}
    index = str((meta.get("labels") or {}).get("apps.kubernetes.io/pod-index") or
                str(meta.get("name") or "").rpartition("-")[2])
    return int(index) if index.isdigit() else -1


class ReleaseReceiver(Receiver):
    FAMILY, KEYS = "release", ("recipe", "expected", "wait_ms")

    def __init__(self, header, data):
        super().__init__(header)
        self.data, self.status = data, "ok"
        self.payload["payload_sha256"] = hashlib.sha256(data).hexdigest()

    def check(self, profile):
        """The recipe on its API executor, and each action's `expected` and payload."""
        r, b, e = self.recipe, self.binding, self.expected
        state_fields(r, "scope owner operation cluster action api_server release release_sha256 application namespace "
                        "required excluded objects_sha256 chunks secrets hooks settles version profile_sha256")
        state_cluster(r["cluster"])
        state_member(r["api_server"])
        chunks = r["chunks"]
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      r["version"] == 1 and r["action"] in ("release-apply", "release-rollback") and
                      isinstance(r["namespace"], str) and LABEL.fullmatch(r["namespace"]) is not None and
                      isinstance(r["application"], str) and LABEL.fullmatch(r["application"]) is not None and
                      all(isinstance(r[k], list) for k in ("required", "excluded", "secrets", "hooks")) and
                      isinstance(chunks, list) and all(isinstance(c, dict) and set(c) == {"first", "count", "sha256"}
                                                       for c in chunks), "ownership")
        # Every mutation runs on the recipe's `api_server`; a `release status` read may go to the current acting first
        # server instead, which open() admits only as a participant server of the derived binding.
        self.status_read = self.member != r["api_server"]
        state_require(not self.status_read or self.tag in ("discover-kinds", "observe-release", "inspect-workloads"),
                      "ownership")
        state_require(isinstance(e, dict), "ownership")
        tag, ns = self.tag, r["namespace"]
        if tag == "discover-kinds":
            state_require(set(e) == {"kinds"}, "ownership")
            kinds(e["kinds"])
        elif tag == "observe-release":
            state_require(set(e) == {"namespace", "kinds", "secrets"} and e["namespace"] == ns and
                          isinstance(e["secrets"], list) and len(e["secrets"]) <= 32 and
                          all(isinstance(n, str) and SUBDOMAIN.fullmatch(n) for n in e["secrets"]), "ownership")
            kinds(e["kinds"])
        elif tag == "inspect-workloads":
            state_require(set(e) == {"workloads", "bound"} and isinstance(e["workloads"], list) and
                          isinstance(e["bound"], list) and all(
                              isinstance(w, dict) and set(w) == {"api_version", "kind", "namespace", "name"} and
                              (w["api_version"], w["kind"]) in WORKLOADS and w["namespace"] == ns and utf8_safe(w["name"])
                              for w in e["workloads"]) and all(
                              isinstance(x, dict) and set(x) == {"reference", "root", "manifests"} and
                              utf8_safe(x["reference"]) and DIGEST.fullmatch(str(x["root"])) and
                              isinstance(x["manifests"], list) and all(DIGEST.fullmatch(str(m)) for m in x["manifests"])
                              for x in e["bound"]), "ownership")
            state_require(len(e["workloads"]) <= 32, "bound")
        else:
            state_require(set(e) == {"chunk", "namespace", "objects"} and type(e["chunk"]) is int and
                          0 <= e["chunk"] < len(chunks) and e["namespace"] == ns and isinstance(e["objects"], list) and
                          all(isinstance(o, dict) and set(o) == {"api_version", "kind", "namespace", "name"} and
                              all(o[k] is None or utf8_safe(o[k]) for k in o) for o in e["objects"]), "ownership")
            chunk = chunks[e["chunk"]]
            state_require(chunk["sha256"] == self.payload["payload_sha256"] and chunk["count"] == len(e["objects"]),
                          "ownership")
        state_require(bool(self.data) == (tag == "apply-objects") and
                      (self.header["wait_ms"] is None or tag == "inspect-workloads"), "ownership")

    def discover_kinds(self, result):
        """One `kubectl api-resources -o wide`, bounded; `kinds` per expected kind."""
        lines = self.kubectl("api-resources", "-o", "wide", limit=LIST).decode("utf-8", "replace").splitlines()
        state_require(lines, "integrity")
        columns = [(m.group(), m.start()) for m in re.finditer(r"\S+", lines[0])]
        starts = dict(columns)
        state_require({"APIVERSION", "NAMESPACED", "KIND"} <= set(starts), "integrity")
        bounds = {name:(start, columns[n + 1][1] if n + 1 < len(columns) else None)
                  for n, (name, start) in enumerate(columns)}
        served = {}
        for line in lines[1:]:
            cell = lambda name: line[bounds[name][0]:bounds[name][1]].strip()
            served[(cell("APIVERSION"), cell("KIND"))] = cell("NAMESPACED") == "true"
        result["kinds"] = [{"api_version":k["api_version"], "kind":k["kind"],
                            "served":(k["api_version"], k["kind"]) in served,
                            "namespaced":served.get((k["api_version"], k["kind"]))} for k in self.expected["kinds"]]

    def observe_release(self, result):
        """One bounded list per kind; the objects whose managedFields name manager `broil`, at most 512; then each
        named Secret's `{name, uid}` by a metadata-only read."""
        found, ns = [], self.expected["namespace"]
        for k in self.expected["kinds"]:
            for item in self.listed(resource(k["api_version"], k["kind"]), ns, managed=True):
                meta = item.get("metadata") or {}
                if any(f.get("manager") == "broil" for f in meta.get("managedFields") or ()):
                    found.append({"kind":item.get("kind") or k["kind"], "name":meta.get("name"),
                                  "namespace":meta.get("namespace"), "uid":meta.get("uid")})
        result["objects"] = found[:512]
        result["presence"] = {"truncated":len(found) > 512}
        result["secrets"] = [{"name":n, "uid":(secret_metadata(self.owner_path, ns, n) or {}).get("uid")}
                             for n in self.expected["secrets"]]

    def current_pods(self, w, obj, pods, listed):
        """The current pods of one workload: a Deployment's newest ReplicaSet's, a `RollingUpdate`
        StatefulSet's update revision's at or above its partition, a `RollingUpdate` DaemonSet's current
        `controller-revision-hash`'s, and every pod of an `OnDelete` workload, a ReplicaSet, a Job or a Pod."""
        meta, spec, status = obj.get("metadata") or {}, obj.get("spec") or {}, obj.get("status") or {}
        uid, kind = meta.get("uid"), w["kind"]
        label = lambda p, key: ((p.get("metadata") or {}).get("labels") or {}).get(key)
        if kind == "Pod":
            return [obj]
        owned = [p for p in pods if owned_by(p, uid)]
        if kind == "Deployment":
            sets = [s for s in listed("replicaset.v1.apps") if owned_by(s, uid)]
            revision = lambda s: int(((s.get("metadata") or {}).get("annotations") or {}).get(
                "deployment.kubernetes.io/revision") or 0)
            newest = (max(sets, key=revision).get("metadata") or {}).get("uid") if sets else None
            return [p for p in pods if newest is not None and owned_by(p, newest)]
        if kind == "StatefulSet" and rolling(spec):
            partition = ((spec.get("updateStrategy") or {}).get("rollingUpdate") or {}).get("partition") or 0
            return [p for p in owned if label(p, "controller-revision-hash") == status.get("updateRevision") and
                    ordinal(p) >= partition]
        if kind == "DaemonSet" and rolling(spec):
            # Only the DaemonSet's own revisions: its selector's labels narrow the list before the owner check.
            labels = (spec.get("selector") or {}).get("matchLabels") or {}
            selector = ",".join("%s=%s" % (k, v) for k, v in sorted(labels.items()))
            revisions = [r for r in listed("controllerrevision.v1.apps", selector) if owned_by(r, uid)]
            newest = label(max(revisions, key=lambda r: r.get("revision") or 0), "controller-revision-hash") \
                if revisions else None
            return [p for p in owned if newest is not None and label(p, "controller-revision-hash") == newest]
        return owned

    def failing(self, pod, bound, ready, template):
        """The row of one current pod, or None: reason `node` for a node outside the recipe's `required`,
        else `digest` for the first bound container, regular then init, whose `image_id` digest is neither the
        bound root nor a recorded manifest digest; while its workload is not ready, an unscheduled pod or a
        container without an `imageID` establishes nothing. A container is bound by its own image or by its name
        in the workload's pod template, so a current pod of an earlier image is still checked."""
        meta, spec, status = pod.get("metadata") or {}, pod.get("spec") or {}, pod.get("status") or {}
        row = {"namespace":meta.get("namespace"), "pod":meta.get("name"), "node":spec.get("nodeName"),
               "reason":"node", "container":None, "image_id":None}
        if row["node"] is not None and row["node"] not in self.recipe["required"]:
            return row
        regular = {c.get("name"):c for c in status.get("containerStatuses") or ()}
        init = {c.get("name"):c for c in status.get("initContainerStatuses") or ()}
        names = lambda field: {c.get("name"):bound[c.get("image")] for c in template.get(field) or ()
                               if c.get("image") in bound}
        bound_regular, bound_init = names("containers"), names("initContainers")
        for c, statuses, by_name in [(c, regular, bound_regular) for c in spec.get("containers") or ()] + \
                [(c, init, bound_init) for c in spec.get("initContainers") or ()]:
            b = bound.get(c.get("image")) or by_name.get(c.get("name"))
            if b is None:
                continue
            value = image_id((statuses.get(c.get("name")) or {}).get("imageID"))
            if value is None and not ready:
                continue
            if value is None or value.rpartition("@")[2] not in [b["root"]] + b["manifests"]:
                row.update(reason="digest", container=c.get("name"), image_id=value)
                return row
        return None

    def workload_pods(self, rows, objects):
        """The group's failing current pods, `node` rows before `digest` rows, each reason by
        namespace and pod name; pods with a deletion timestamp or in phase `Failed` are not checked."""
        ns, bound = self.recipe["namespace"], {b["reference"]:b for b in self.expected["bound"]}
        pods = [p for p in self.listed("pod", ns) if "deletionTimestamp" not in (p.get("metadata") or {})]
        cache = {}
        listed = lambda kind, selector=None: cache[(kind, selector)] if (kind, selector) in cache else \
            cache.setdefault((kind, selector), self.listed(kind, ns, selector=selector))
        out = []
        for w, obj, row in zip(self.expected["workloads"], objects, rows):
            if obj is None:
                continue
            spec = obj.get("spec") or {}
            template = spec if w["kind"] == "Pod" else (spec.get("template") or {}).get("spec") or {}
            for p in self.current_pods(w, obj, pods, listed):
                if "deletionTimestamp" in (p.get("metadata") or {}) or (p.get("status") or {}).get("phase") == "Failed":
                    continue
                found = self.failing(p, bound, row["outcome"] == "succeeded", template)
                if found is not None:
                    out.append(found)
        return sorted(out, key=lambda r: (r["reason"] != "node", r["namespace"] or "", r["pod"] or ""))

    def inspect_workloads(self, result):
        """Re-read every 2 seconds until every workload succeeded, one is paused, stalled or a failed
        Job, or the wait ends; then the group's failing pods, at most 32, `presence.truncated` marking that cap."""
        until = time.monotonic() + min((self.header["wait_ms"] or 0) / 1000, DEADLINE - time.monotonic() - 3)
        while True:
            objects = [self.get(resource(w["api_version"], w["kind"]), w["name"], w["namespace"])
                       for w in self.expected["workloads"]]
            rows = [readiness(w, obj) for w, obj in zip(self.expected["workloads"], objects)]
            if all(r["outcome"] == "succeeded" for r in rows) or \
                    any(r["outcome"] in ("failed", "paused", "stalled") for r in rows) or time.monotonic() + 2 > until:
                break
            time.sleep(2)
        failing = self.workload_pods(rows, objects)
        result["workloads"], result["pods"] = rows, failing[:32]
        result["presence"] = {"truncated":len(failing) > 32}

    def apply_objects(self, result):
        """Per object in order: read its UID and resourceVersion, then one server-side apply of exactly that document
        with field manager `broil` and no forced conflicts; stop at the first failure."""
        global EFFECTS, WRITERS_SETTLED
        e, ns = self.expected, self.expected["namespace"]
        docs = documents(self.data)
        state_require(len(docs) == len(e["objects"]), "ownership")
        for doc, o in zip(docs, e["objects"]):
            api, kind, namespace, name = named(doc)
            state_require((api, kind, name) == (o["api_version"], o["kind"], o["name"]) and
                          namespace in (None, o["namespace"]), "ownership")
        state_require(DEADLINE - time.monotonic() >= 50, "timeout")
        self.begin()
        rows, changed, failure = [], False, None
        for doc, o in zip(docs, e["objects"]):
            row = {"kind":o["kind"], "name":o["name"], "namespace":o["namespace"] or ns, "outcome":"not-run", "uid":None,
                   "reason":None}
            rows.append(row)
            if failure is not None:
                continue
            target = resource(o["api_version"], o["kind"])
            before = self.get(target, o["name"], ns)
            self.effect_started = EFFECTS = True
            outcome = self.kubectl("apply", "--server-side", "--field-manager=broil", "-n", ns, "-f", "-",
                                   input=doc.encode(), limit=65536, seconds=45, probe=True, mutating=True, timeout="40s")
            if outcome is None:
                WRITERS_SETTLED = False
                raise StateRefused("timeout")
            if outcome[0] != 0:
                text = outcome[2].decode("utf-8", "replace")
                if "Apply failed with" in text:
                    row.update(outcome="failed", reason="conflict")
                    failure = "ownership"
                elif " is invalid" in text or "admission webhook" in text or "(Invalid)" in text or \
                        "(Forbidden)" in text or "(BadRequest)" in text or self.namespace_missing(text, ns):
                    row.update(outcome="failed", reason="rejected")
                    failure = "configuration"
                else:
                    raise StateRefused("transport")
                continue
            after = self.get(target, o["name"], ns)
            state_require(after is not None, "transport")
            meta, old = after.get("metadata") or {}, (before or {}).get("metadata") or {}
            row["uid"] = meta.get("uid")
            row["outcome"] = "created" if before is None else "unchanged" if \
                old.get("resourceVersion") == meta.get("resourceVersion") else "configured"
            changed |= row["outcome"] != "unchanged"
        result["objects"] = rows
        if failure is None:
            result["terminal"] = self.finish("succeeded", None, "complete")
        else:
            result["terminal"] = self.finish("failed", failure, "partial" if changed else "absent")
            self.status = "failed"

    def run(self, result):
        if self.tag == "apply-objects":
            previous = self.previous()
            if previous is not None:
                result["terminal"] = previous
                return
        getattr(self, self.tag.replace("-", "_"))(result)


def release_request(raw, header):
    """The header, then `u32be(payload_length)`, the optional payload and EOF."""
    global DEADLINE
    state_require(isinstance(header, dict) and header.get("protocol") == "broil-k3s-release", "integrity")
    state_require(17 + len(raw) <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms recipe expected wait_ms")
    state_require(canonical(header) == raw, "integrity")
    state_require(type(header["version"]) is int and header["version"] == 1,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
    tag = header["action"]
    state_require(tag in TAGS, "capability")
    mutation = tag == "apply-objects"
    state_hex(header["request_id"])
    state_binding(header["binding"])
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation, "ownership")
    state_require(header["wait_ms"] is None or type(header["wait_ms"]) is int and 0 <= header["wait_ms"] <= 7200000,
                  "ownership")
    state_require(isinstance(header["recipe"], dict) and len(canonical(header["recipe"])) <= RECIPE, "bound")
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    length = struct.unpack(">I", read_exact(4))[0]
    state_require(length <= PAYLOAD and 8 + len(raw) + length <= 1048576, "bound")
    data = read_exact(length)
    state_require(sys.stdin.buffer.read(1) == b"", "integrity")
    return data


def release_main(raw, header):
    receiver = None
    status = "unknown"
    result = {"terminal":None, **dict.fromkeys(FACTS), "failure":None}
    prefix = MAGIC + struct.pack(">I", len(raw)) + raw
    try:
        data = release_request(raw, header)
        receiver = ReleaseReceiver(header, data)
        receiver.profile()
        receiver.open()
        receiver.owned()
        receiver.run(result)
        status = receiver.status
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
    # A failed chunk keeps its per-object outcomes; every other non-`ok` reply carries none.
    if status not in ("ok", "failed"):
        result.update(dict.fromkeys(FACTS))
    if status == "failed" and receiver.status == "failed":
        result["failure"] = receiver.published["failure"]
    body = canonical({"kind":"result", "status":status, **result})
    if len(body) > REPLY:
        os._exit(125)
    sys.stdout.buffer.write(prefix + struct.pack(">I", len(body)) + body)
    sys.stdout.buffer.flush()


METADATA = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"


def secret_metadata(owner_path, namespace, name):
    """One Secret's `{uid, resourceVersion}`, None when absent: one direct HTTPS `GET` to the local API server with the
    managed administrator kubeconfig's client credentials and CA, asking for `PartialObjectMetadata` so that its data
    is never fetched; any other reply refuses `integrity` and is not retained, detail `secret-metadata` when it is not
    `PartialObjectMetadata` or carries `data`."""
    import http.client
    import ssl
    text = read_file(owner_path + "/admin.yaml", 65536).decode("ascii")
    pem = {}
    for key in ("certificate-authority-data", "client-certificate-data", "client-key-data"):
        found = re.findall(r'"?%s"?\s*:\s*"?([A-Za-z0-9+/=]+)' % key, text)
        state_require(len(found) == 1, "ownership")
        pem[key] = base64.b64decode(found[0], validate=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=pem["certificate-authority-data"].decode("ascii"))
    handles = []
    try:
        for key in ("client-certificate-data", "client-key-data"):
            handles.append(os.memfd_create("broil-k3s-release", os.MFD_CLOEXEC))
            view = memoryview(pem[key])
            while view:
                view = view[os.write(handles[-1], view):]
        context.load_cert_chain("/proc/self/fd/%d" % handles[0], "/proc/self/fd/%d" % handles[1])
    finally:
        for fd in handles:
            os.close(fd)
    seconds = DEADLINE - time.monotonic()
    state_require(seconds > 1, "timeout")
    connection = http.client.HTTPSConnection("127.0.0.1", 6443, context=context, timeout=min(seconds, 10))
    try:
        connection.request("GET", "/api/v1/namespaces/%s/secrets/%s" % (namespace, name), headers={"Accept":METADATA})
        response = connection.getresponse()
        body = bytearray(response.read(65537))
        code = response.status
    except (OSError, http.client.HTTPException):
        raise StateRefused("transport")
    finally:
        connection.close()
    try:
        state_require(len(body) <= 65536, "bound")
        if code == 404:
            return None
        state_require(code == 200, "transport")
        value = decode(bytes(body))
        if not (isinstance(value, dict) and value.get("kind") == "PartialObjectMetadata" and
                value.get("apiVersion") == "meta.k8s.io/v1" and "data" not in value and "stringData" not in value):
            raise StateRefused("integrity", "secret-metadata")
        meta = value.get("metadata")
        state_require(isinstance(meta, dict) and meta.get("name") == name and meta.get("namespace") == namespace and
                      utf8_safe(meta.get("uid")), "integrity")
        return {"uid":meta["uid"], "resourceVersion":meta.get("resourceVersion")}
    except StateRefused:
        raise
    except Exception:
        raise StateRefused("integrity", "secret-metadata")
    finally:
        body[:] = bytes(len(body))
        value = None


# ---- The release Secret wire ----
SECRET_MAGIC = b"BK3SRS1\n"
SECRET_FIELDS = {"protocol", "version", "action", "request_id", "project", "environment", "target", "owner", "operation",
                 "attempt", "destination", "cluster", "resource", "application", "namespace", "secret", "keys",
                 "profile_sha256", "script_sha256", "selection_sha256", "remaining_ms", "slot_lengths"}
SECRET_LABELS = ("broil.dev/managed-by", "broil.dev/component", "broil.dev/application")


class SecretReceiver(Receiver):
    """The writer admission of one `apply-secret` dispatch under its one-use durable grant."""
    FAMILY = "release"

    def __init__(self, binding, projection):
        self.header = {"action":"apply-secret", "recipe":None, "expected":None, "resource":None}
        self.binding = binding
        self.member = binding["recipient"]
        self.tag = "apply-secret"
        self.action = "credential:apply-secret"
        self.recipe = {"cluster":projection["cluster"]}
        self.payload = projection
        self.root = self.lock = self.executable = None
        self.root_id = self.lock_id = None
        self.claim = self.reservation = self.intent = self.published = None
        self.effect_started = False
        self.owner_path = ROOT + "/owners/" + binding["owner"]

    def check(self, profile):
        pass


def secret_header(raw, header):
    """The exact header, at most 8192 bytes; any other shape is malformed input (status 4)."""
    global DEADLINE
    require(len(raw) <= 8192 and isinstance(header, dict) and set(header) == SECRET_FIELDS and canonical(header) == raw, 4)
    try:
        state_value(header)
    except StateRefused:
        raise Refused(4)
    require(header["protocol"] == "broil-k3s-release-secret" and header["version"] == 1 and
            header["action"] == "apply-secret" and re.fullmatch(r"[0-9a-f]{32}", str(header["request_id"])), 4)
    require(all(opaque(header[k]) for k in ("owner", "operation", "attempt", "target")) and
            all(isinstance(header[k], str) and header[k] for k in ("project", "environment")), 4)
    d, c, r = header["destination"], header["cluster"], header["resource"]
    require(isinstance(d, dict) and set(d) == {"machine", "member", "role", "node_uid"} and d["role"] in ("server", "agent"), 4)
    require(isinstance(c, dict) and set(c) == {"uid", "ca_sha256"} and opaque(c["uid"]), 4)
    require(isinstance(r, dict) and set(r) == {"kind", "id", "generation", "uid"} and r["kind"] == "application-secret" and
            opaque(r["id"]) and opaque(r["generation"]) and (r["uid"] is None or opaque(r["uid"])), 4)
    keys, lengths = header["keys"], header["slot_lengths"]
    require(all(isinstance(header[k], str) for k in ("application", "namespace", "secret")) and
            LABEL.fullmatch(header["application"]) and LABEL.fullmatch(header["namespace"]) and
            SUBDOMAIN.fullmatch(header["secret"]), 4)
    require(isinstance(keys, list) and 0 < len(keys) <= 256 and all(isinstance(k, str) and KEY.fullmatch(k) for k in keys)
            and len(set(keys)) == len(keys), 4)
    require(isinstance(lengths, list) and len(lengths) == len(keys) and
            all(type(n) is int and 0 < n <= 1048576 for n in lengths), 4)
    require(4 + len(raw) + sum(4 + n for n in lengths) <= 1048576, 4)
    for name in ("profile_sha256", "script_sha256", "selection_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", str(header[name])), 4)
    require(type(header["remaining_ms"]) is int and 0 < header["remaining_ms"] <= 7200000, 4)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000


def secret_grant(header):
    """The one-use durable grant of this dispatch, validated before any slot is read."""
    path = ROOT + "/attempts/" + header["attempt"] + "/credentials/" + header["request_id"] + ".json"
    grant = state_read(path, "credential-grant")
    state_require(grant is not None, "ownership")
    binding = grant["binding"]
    projection = {k:v for k, v in header.items() if k not in ("remaining_ms", "slot_lengths")}
    state_require(grant["action"] == "apply-secret" and
                  grant["admission_sha256"] == state_hash("broil-infra-credential-admission-v1", projection) and
                  grant["selection_sha256"] == header["selection_sha256"] and binding["dispatch"] == header["request_id"]
                  and all(binding[k] == header[k] for k in ("owner", "operation", "attempt"))
                  and all(binding["scope"][k] == header[k] for k in ("project", "environment", "target"))
                  and {k:binding["recipient"][k] for k in ("machine", "member", "role", "node_uid")} == header["destination"]
                  and binding["fingerprints"]["profile_sha256"] == header["profile_sha256"]
                  and binding["fingerprints"]["script_sha256"] == header["script_sha256"], "ownership")
    resource = grant["resource"]
    state_require(isinstance(resource, dict) and {k:resource.get(k) for k in ("kind", "id", "generation", "uid")} ==
                  header["resource"] and resource.get("namespace") == header["namespace"] and
                  resource.get("name") == header["secret"], "ownership")
    receiver = SecretReceiver(binding, projection)
    receiver.profile()
    receiver.open()
    receiver.active()
    # A grant is one use: an existing intent of this dispatch refuses, terminal or not.
    state_require(state_read(receiver.dispatch_path() + "/intent.json", "intent") is None, "ownership")
    return receiver, resource


def apply_secret(receiver, header, slots):
    """The encryption check, the one-use intent, the metadata read and its UID rule, then one server-side apply
    through standard input."""
    global EFFECTS
    status = command(receiver.executable, ["secrets-encrypt", "status"], limits=(65536, 65536))
    require(b"Encryption Status: Enabled\n" in status + b"\n", 3)
    ns, name, uid = header["namespace"], header["secret"], header["resource"]["uid"]
    receiver.begin()
    before = secret_metadata(receiver.owner_path, ns, name)
    if (before or {}).get("uid") != uid:
        # A UID race since the admission read: nothing is written.
        receiver.finish("failed", "ownership", "absent", receiver.grant_resource)
        return 2, b""
    labels = dict(zip(SECRET_LABELS, ("broil", "application-secret", header["application"])))
    document = bytearray(canonical({"apiVersion":"v1", "kind":"Secret", "type":"Opaque",
                                    "metadata":{"name":name, "namespace":ns, "labels":labels},
                                    "data":{k:base64.b64encode(v).decode() for k, v in zip(header["keys"], slots)}}))
    receiver.effect_started = EFFECTS = True
    try:
        outcome = receiver.kubectl("apply", "--server-side", "--field-manager=broil", "-n", ns, "-f", "-",
                                   input=bytes(document), limit=65536, seconds=45, probe=True, mutating=True,
                                   timeout="40s")
    finally:
        document[:] = bytes(len(document))
    state_require(outcome is not None, "timeout")
    if outcome[0] != 0:
        text = outcome[2].decode("utf-8", "replace")
        conflict = "Apply failed with" in text
        rejected = " is invalid" in text or "admission webhook" in text or "(Invalid)" in text or \
            "(Forbidden)" in text or not conflict and receiver.namespace_missing(text, ns)
        state_require(conflict or rejected, "transport")
        receiver.finish("failed", "ownership" if conflict else "configuration", "absent", receiver.grant_resource)
        return 2, b""
    after = secret_metadata(receiver.owner_path, ns, name)
    state_require(after is not None, "transport")
    reply = canonical({"outcome":"created" if before is None else "unchanged" if
                       before["resourceVersion"] == after["resourceVersion"] else "configured", "uid":after["uid"]})
    state_require(len(reply) <= 256, "bound")
    receiver.finish("succeeded", None, "complete", receiver.grant_resource)
    return 0, reply


def secret_main(raw, header):
    status, kind, data, receiver = 1, 0, b"", None
    try:
        secret_header(raw, header)
        receiver, resource = secret_grant(header)
        receiver.grant_resource = resource
        slots = []
        for length in header["slot_lengths"]:
            size = struct.unpack(">I", read_exact(4))[0]
            require(size == length, 4)
            slots.append(bytearray(read_exact(size)))
        require(sys.stdin.buffer.read(1) == b"", 4)
        try:
            status, data = apply_secret(receiver, header, slots)
        finally:
            for slot in slots:
                slot[:] = bytes(len(slot))
        kind = 3 if status == 0 else 0
    except Refused as error:
        status = 6 if EFFECTS else error.code
    except StateRefused as error:
        status = 6 if EFFECTS else 1
        if error.detail == "secret-metadata" and receiver is not None and not receiver.effect_started:
            # A metadata response read before any write that is not `PartialObjectMetadata` or carries
            # `data` is a settled pre-write refusal, never retained.
            try:
                receiver.finish("failed", "integrity", "absent", receiver.grant_resource)
                status = 2
            except BaseException:
                status = 6
    except Exception:
        status = 6 if EFFECTS else 1
    if receiver is not None and status != 0 and receiver.intent is not None and receiver.published is None:
        try:
            receiver.terminal("failed", "credential", receiver.grant_resource)
        except BaseException:
            status = 6
    if receiver is not None:
        for fd in (receiver.lock, receiver.root, receiver.executable):
            if fd is not None:
                os.close(fd)
    if status != 0:
        kind, data = 0, b""
    sys.stdout.buffer.write(SECRET_MAGIC + struct.pack(">I", len(raw)) + raw + bytes([status, kind]) +
                            struct.pack(">I", len(data)) + data)
    sys.stdout.buffer.flush()


try:
    os.umask(0o077)
    length = struct.unpack(">I", read_exact(4))[0]
    require(0 < length <= 65536, 4)
    raw = read_exact(length)
    header = decode(raw)
    require(isinstance(header, dict) and header.get("protocol") in ("broil-k3s-release", "broil-k3s-release-secret"), 4)
    if header["protocol"] == "broil-k3s-release":
        release_main(raw, header)
    else:
        secret_main(raw, header)
    os._exit(0)
except Exception:
    os._exit(125)
