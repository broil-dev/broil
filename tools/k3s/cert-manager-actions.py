#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, profile-bound K3s cert-manager installation receiver."""
import base64
import concurrent.futures
import datetime
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
import tarfile
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


MANIFEST = "e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f"
RENDER = "128cff01c7045fe773965a5e2c98fcd4798056293396b1ddc627392b9bfbf2b8"
IMAGES = {"controller":"57bb397c639e0e94184ba67848e5dad04284f24645e521e764a0ee5f5002f286",
          "cainjector":"aa2bc58725d92a643f5069dde58abc93b65566ded8951348873ac9ee7efef66c",
          "webhook":"b929259301ee75270ab4651d5e6bd4ba7b6624b1ce48ba767d064295a9312101",
          "acmesolver":"dc5c5b8456d1a50af47a240987e85afce352b5c1155a8a4698b7c91eac19f407"}
PINS = {"version":"v1.21.2", "manifest":MANIFEST, "render":RENDER, "images":IMAGES}
BODIES = {"control", "lifecycle", "network", "ingress", "cert_manager", "registry", "node", "delivery", "release", "service_guard"}
IMPORTED = ("controller", "cainjector", "webhook")
REPOSITORY = "quay.io/jetstack/cert-manager-"
NAMED = {x:REPOSITORY + x + ":broil-proof" for x in IMPORTED}
DIGESTED = {x:REPOSITORY + x + "@sha256:" + IMAGES[x] for x in IMPORTED}
TARGETS = {**{NAMED[x]:IMAGES[x] for x in IMPORTED}, **{DIGESTED[x]:IMAGES[x] for x in IMPORTED}}
PIN = "io.cri-containerd.pinned=pinned"
SOLVER = "--acme-http01-solver-image=" + REPOSITORY + "acmesolver"
# The generation's four consumed assets and their file names.
FILES = {"cert-manager-" + x:"cert-manager-" + x + ".tar" for x in IMPORTED}
FILES["cert-manager-manifest"] = "cert-manager.yaml"
# The 47 manifest objects in order: (apiVersion, kind, resource, names), a
# namespaced name written namespace/name.
GROUPS = (
    ("v1", "Namespace", "namespace", "cert-manager"),
    ("apiextensions.k8s.io/v1", "CustomResourceDefinition", "customresourcedefinition.apiextensions.k8s.io",
     "challenges.acme.cert-manager.io orders.acme.cert-manager.io certificaterequests.cert-manager.io "
     "certificates.cert-manager.io clusterissuers.cert-manager.io issuers.cert-manager.io"),
    ("v1", "ServiceAccount", "serviceaccount", "{0}-cainjector {0} {0}-webhook"),
    ("rbac.authorization.k8s.io/v1", "ClusterRole", "clusterrole.rbac.authorization.k8s.io",
     "cert-manager-cainjector {1}-issuers {1}-clusterissuers {1}-certificates {1}-orders {1}-challenges "
     "{1}-ingress-shim cert-manager-cluster-view cert-manager-view cert-manager-edit {2} "
     "{1}-certificatesigningrequests {3}"),
    ("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "clusterrolebinding.rbac.authorization.k8s.io",
     "cert-manager-cainjector {1}-issuers {1}-clusterissuers {1}-certificates {1}-orders {1}-challenges "
     "{1}-ingress-shim {2} {1}-certificatesigningrequests {3}"),
    ("rbac.authorization.k8s.io/v1", "Role", "role.rbac.authorization.k8s.io", "{4}"),
    ("rbac.authorization.k8s.io/v1", "RoleBinding", "rolebinding.rbac.authorization.k8s.io", "{4}"),
    ("v1", "Service", "service", "{0}-cainjector {0} {0}-webhook"),
    ("apps/v1", "Deployment", "deployment.apps", "{0}-cainjector {0} {0}-webhook"),
    ("admissionregistration.k8s.io/v1", "MutatingWebhookConfiguration",
     "mutatingwebhookconfiguration.admissionregistration.k8s.io", "cert-manager-webhook"),
    ("admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration",
     "validatingwebhookconfiguration.admissionregistration.k8s.io", "cert-manager-webhook"),
)
PARTS = ("cert-manager/cert-manager", "cert-manager-controller", "cert-manager-controller-approve:cert-manager-io",
         "cert-manager-webhook:subjectaccessreviews", "kube-system/cert-manager-cainjector:leaderelection "
         "kube-system/cert-manager:leaderelection cert-manager/cert-manager-webhook:dynamic-serving")
OBJECTS = [(version, kind, resource, *(name.split("/") if "/" in name else (None, name)))
           for version, kind, resource, names in GROUPS for name in names.format(*PARTS).split()]
# The runtime identities that must be absent before creation; the
# absent Namespace implies the webhook CA Secret's absence.
RUNTIME = (("lease.coordination.k8s.io", "kube-system", "cert-manager-controller"),
           ("lease.coordination.k8s.io", "kube-system", "cert-manager-cainjector-leader-election"),
           ("apiservice.apiregistration.k8s.io", None, "v1.cert-manager.io"),
           ("apiservice.apiregistration.k8s.io", None, "v1.acme.cert-manager.io"))
SERVER_FIELDS = ("creationTimestamp", "uid", "resourceVersion", "generation", "managedFields")
LABELS = {"broil.dev/managed-by":"broil", "broil.dev/component":"cert-manager"}
# The closed API defaults of each webhook entry.
DEFAULTS = {"MutatingWebhookConfiguration":{"objectSelector":{}, "namespaceSelector":{}, "reinvocationPolicy":"Never"},
            "ValidatingWebhookConfiguration":{"objectSelector":{}}}
SERVER_KEYS = {"Namespace":("labels", "kubernetes.io/metadata.name"),
               "Deployment":("annotations", "deployment.kubernetes.io/revision")}
DEPTH = 64
CREATED = "{.apiVersion}{\"\\t\"}{.kind}{\"\\t\"}{.metadata.namespace}{\"\\t\"}{.metadata.name}{\"\\t\"}" \
          "{.metadata.uid}{\"\\n\"}"
ISSUER = {"apiVersion":"cert-manager.io/v1", "kind":"Issuer",
          "metadata":{"generateName":"broil-webhook-probe-", "namespace":"cert-manager"}, "spec":{"selfSigned":{}}}
WEBHOOK = 'failed calling webhook "webhook.cert-manager.io"'
TIMEOUTS = ("TLS handshake timeout", "context deadline exceeded", "Client.Timeout exceeded", "i/o timeout")
# The closed mapping of a failed probe, first match first: (reason, required phrases, any-of phrases).
MAPPING = (
    ("crd", ('no matches for kind "Issuer" in version "cert-manager.io/v1"',), ()),
    ("dry-run", ('admission webhook "', '" does not support dry run'), ()),
    ("denied", ('admission webhook "', '" denied the request'), ()),
    ("endpoints", (WEBHOOK, 'no endpoints available for service "cert-manager-webhook"'), ()),
    ("certificate", (WEBHOOK, "x509:"), ()),
    ("timeout", (WEBHOOK,), TIMEOUTS),
    ("call", (WEBHOOK,), ()),
    ("other-webhook", ('failed calling webhook "',), ()),
)
# The largest reply after the header echo: 47 records with 128-byte
# UIDs and a terminal receipt carrying a 4096-byte binding stay under it.
RESERVE = 24576
WHITESPACE = re.compile(r"[ \t\r\n]*")


def fact(ready, reason="missing"):
    return {"state":"ready" if ready else "not-ready", "reason":"observed" if ready else reason}


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    value = hashlib.sha256()
    while chunk := os.read(fd, 1048576):
        state_check()
        value.update(chunk)
    return value.hexdigest()


def bounded(value, depth=1):
    """What `C` can encode, within its string bound and at most 64 nested containers."""
    if isinstance(value, (dict, list)):
        state_require(depth <= DEPTH, "bound")
        for key in value if isinstance(value, dict) else ():
            bounded(key, depth)
        for item in value.values() if isinstance(value, dict) else value:
            bounded(item, depth + 1)
    elif isinstance(value, str):
        state_require("\0" not in value and len(value.encode("utf-8")) <= 4096, "bound")
    else:
        state_require(value is None or type(value) is bool or type(value) is int and 0 <= value < 2 ** 64)
    return value


def documents(raw, count=None):
    """JSON documents separated only by whitespace, each decoded under the depth bound."""
    text, index, found = raw.decode("utf-8"), 0, []
    decoder = json.JSONDecoder(object_pairs_hook=unique)
    while (index := WHITESPACE.match(text, index).end()) < len(text):
        state_require(count is None or len(found) < count)
        try:
            item, index = decoder.raw_decode(text, index)
        except RecursionError:
            raise StateRefused("bound")
        found.append(bounded(item))
    state_require(count is None or len(found) == count)
    return found


def recipe_check(recipe, binding, profile):
    state_fields(recipe, "scope owner operation cluster members first_server version generations profile_sha256 "
                         "manifest_sha256 render_sha256")
    state_require(recipe["scope"] == binding["scope"] and recipe["owner"] == binding["owner"] and
                  recipe["profile_sha256"] == binding["fingerprints"]["profile_sha256"] and
                  recipe["version"] == profile["k3s_version"] and recipe["manifest_sha256"] == MANIFEST and
                  recipe["render_sha256"] == RENDER, "ownership")
    state_cluster(recipe["cluster"])
    members = recipe["members"]
    state_require(recipe["cluster"] is not None and isinstance(members, list) and
                  1 <= len(members) <= 128 and recipe["first_server"] == members[0], "ownership")
    for member in members:
        state_member(member)
        state_require(member["role"] in ("server", "agent") and member["node_uid"] is not None, "ownership")
    machines = [m["machine"] for m in members]
    state_require(len(set(machines)) == len(members) == len({m["member"] for m in members}) and
                  members[0]["role"] == "server" and binding["recipient"] in members, "ownership")
    state_require(isinstance(recipe["operation"], str) and recipe["operation"].startswith("infra-operation-"), "ownership")
    state_hex(recipe["operation"][16:])
    entries = recipe["generations"]
    state_require(isinstance(entries, list) and len(entries) == len(members), "ownership")
    for entry, machine in zip(entries, machines):
        state_fields(entry, "machine generation marker_sha256")
        state_require(entry["machine"] == machine, "ownership")
        state_hex(entry["generation"])
        state_hex(entry["marker_sha256"], 64)


def render(docs):
    """The three fixed substitutions, each site exactly once."""
    sites = []
    for doc in docs:
        for container in doc["spec"]["template"]["spec"]["containers"] if doc["kind"] == "Deployment" else ():
            for x in IMPORTED:
                if container.get("image") == REPOSITORY + x + ":v1.21.2":
                    container["image"] = DIGESTED[x]
                    sites.append(x)
                    if container.get("imagePullPolicy") == "IfNotPresent":
                        container["imagePullPolicy"] = "Never"
                        sites.append("never")
            for index, arg in enumerate(container.get("args") or []):
                if arg == SOLVER + ":v1.21.2":
                    container["args"][index] = SOLVER + "@sha256:" + IMAGES["acmesolver"]
                    sites.append("solver")
    state_require(sorted(sites) == sorted([*IMPORTED, "never", "never", "never", "solver"]))
    return hashlib.sha256(canonical(docs)).hexdigest()


def restrict(observed, rendered):
    """The observed object under the rendered one: rendered map keys, every observed list element, observed scalars."""
    if isinstance(rendered, dict) and isinstance(observed, dict):
        return {key:restrict(observed[key], value) for key, value in rendered.items() if key in observed}
    if isinstance(rendered, list) and isinstance(observed, list):
        return [restrict(item, rendered[index]) if index < len(rendered) else item for index, item in enumerate(observed)]
    return observed


def without_ca(entry):
    if isinstance(entry, dict) and isinstance(entry.get("clientConfig"), dict):
        entry = dict(entry, clientConfig={k:v for k, v in entry["clientConfig"].items() if k != "caBundle"})
    return entry


def with_defaults(kind, entry):
    """A rendered webhook entry plus the closed API defaults."""
    entry = decode(canonical(entry))
    for key, default in DEFAULTS[kind].items():
        entry.setdefault(key, default)
    for rule in entry.get("rules") or []:
        rule.setdefault("scope", "*")
    entry["clientConfig"]["service"].setdefault("port", 443)
    return entry


def projection(obj, rendered):
    """The projection of an object, restricted by its rendered form."""
    metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    maps = {key:dict(metadata.get(key) or {}) for key in ("labels", "annotations")}
    if rendered["kind"] in SERVER_KEYS:
        key, name = SERVER_KEYS[rendered["kind"]]
        maps[key].pop(name, None)
    fields = {}
    for key, value in rendered.items():
        if key not in ("metadata", "status") and key in obj:
            webhooks = key == "webhooks" and isinstance(obj[key], list)
            fields[key] = [without_ca(entry) for entry in obj[key]] if webhooks else restrict(obj[key], value)
    return bounded({"labels":maps["labels"], "annotations":maps["annotations"],
                    "finalizers":metadata.get("finalizers") or [], "owner_references":metadata.get("ownerReferences") or [],
                    "deleting":"deletionTimestamp" in metadata, "fields":fields})


def available(kind, obj):
    status = obj.get("status") if isinstance(obj.get("status"), dict) else {}
    if kind == "CustomResourceDefinition":
        conditions = {c.get("type"):c.get("status") for c in status.get("conditions") or [] if isinstance(c, dict)}
        return "ready" if conditions.get("Established") == conditions.get("NamesAccepted") == "True" else "not-ready"
    if kind == "Deployment":
        return "ready" if status.get("observedGeneration") == obj["metadata"].get("generation") and \
            status.get("availableReplicas") == (obj.get("spec") or {}).get("replicas") == 1 else "not-ready"
    return "ready"


def created(raw):
    """Exactly the 47 identities in order, one opaque UID each."""
    rows = raw.decode("utf-8").split("\n")
    state_require(rows.pop() == "" and len(rows) == len(OBJECTS) and all(len(row) < 512 for row in rows))
    uids = []
    for row, (version, kind, _, namespace, name) in zip(rows, OBJECTS):
        fields = row.split("\t")
        state_require(len(fields) == 5 and fields[:4] == [version, kind, namespace or "", name] and opaque(fields[4]))
        uids.append(fields[4])
    return uids


class CertManagerReceiver:
    FAMILY, KEYS = "cert-manager", ("recipe", "original_recipe_sha256", "uids", "resource", "preflight")

    def __init__(self, header):
        self.header = header
        self.binding = header["binding"]
        self.member = self.binding["recipient"]
        self.tag = header["action"]
        self.action = "lifecycle:%s-%s" % (self.FAMILY, self.tag)
        self.recipe = header["recipe"]
        self.payload = {key:header.get(key) for key in self.KEYS}
        self.root = self.lock = self.executable = None
        self.root_id = self.lock_id = None
        self.claim = self.reservation = self.intent = self.published = None
        self.effect_started = False
        self.owner_path = ROOT + "/owners/" + self.binding["owner"]
        # A derived current recipe's annotations compare with the original's hash.
        self.recipe_hash = self.payload.get("original_recipe_sha256") or \
            state_hash("broil-k3s-%s-recipe-v1" % self.FAMILY, self.recipe)
        # The recipe is checked later, before any effect.
        r = self.recipe.get
        self.annotations = {
            "broil.dev/owner":r("owner"), "broil.dev/creation-operation":r("operation"),
            "broil.dev/cluster-uid":(r("cluster") or {}).get("uid"), "broil.dev/recipe-sha256":self.recipe_hash,
            "broil.dev/profile-sha256":r("profile_sha256"), "broil.dev/render-sha256":RENDER}
        self.expected = []

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
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == bodies["cert_manager"] and
                      profile.get("cert_manager") == PINS, "ownership")
        tools = self.binding["fingerprints"]["tools"]
        state_require(len(tools) == 2 and tools[0]["name"] == "bootstrap-index" and
                      tools[1] == {"name":"k3s", "sha256":profile["k3s_sha256"]}, "capability")
        self.host_profile = profile
        self.check(profile)
        self.executable = tool(profile)

    def check(self, profile):
        recipe_check(self.recipe, self.binding, profile)
        state_require(self.tag in ("inspect-host", "import-images") or self.member == self.recipe["members"][0],
                      "ownership")

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
        exclusive = self.tag not in ("inspect-host", "inspect-objects")
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

    def kubectl(self, *args, input=None, source=None, limit=MAXIMUM, seconds=20, bound=True, probe=False,
                mutating=False, timeout="10s"):
        kubeconfig = f"{self.owner_path}/admin.yaml"
        read_file(kubeconfig, 65536)
        return command(self.executable, ["kubectl", "--kubeconfig", kubeconfig, "--request-timeout=" + timeout, *args], input,
                       limits=(limit, 65536 if probe else MAXIMUM), source=source, seconds=seconds, bound=bound,
                       probe=probe, mutating=mutating)

    def runtime(self, *args, mutating=False, source=None, seconds=20):
        return command(self.executable, list(args), limits=(MAXIMUM, 65536), mutating=mutating, source=source,
                       seconds=seconds)

    # ---- Host facts: generation, images and runtime ----
    def generation(self, member):
        """The bound generation as a whole; returns the held consumed assets."""
        entry = next(e for e in self.recipe["generations"] if e["machine"] == member["machine"])
        machine, owner, path = member["machine"], self.binding["owner"], f"{self.owner_path}/assets/{entry['generation']}"
        resource = {"kind":"bootstrap-assets", "id":machine, "owner":owner, "generation":entry["generation"],
                    "machine":machine, "path":path + "/", "namespace":None, "name":None, "uid":None}
        gfd, held = state_directory(path), {}
        try:
            binding, marker = state_read(path + "/binding.json"), state_read(path + "/complete.json")
            state_require(binding is not None and marker is not None and
                          hashlib.sha256(canonical(marker)).hexdigest() == entry["marker_sha256"], "readiness")
            state_fields(binding, "schema kind recipe_sha256 resource directory")
            state_fields(marker, "schema kind scope owner operation attempt resource recipe_sha256 directory inactive assets")
            here, assets = identity(gfd), marker["assets"]
            state_require(binding["kind"] == "bootstrap-generation" and marker["kind"] == "bootstrap-complete" and
                          binding["resource"] == marker["resource"] == resource and marker["inactive"] is True and
                          binding["directory"] == marker["directory"] == here and marker["owner"] == owner and
                          binding["recipe_sha256"] == marker["recipe_sha256"] and marker["scope"] == self.binding["scope"] and
                          isinstance(assets, list) and all(isinstance(a, dict) and set(a) == {"id", "size", "sha256", "identity"}
                                                           for a in assets), "readiness")
            by_identity = {tuple(a["identity"]):a for a in assets}
            state_require(len(by_identity) == len(assets) == len({a["id"] for a in assets}), "readiness")
            seen = set()
            for name in set(state_names(path, 64)) - {"binding.json", "complete.json"}:
                fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=gfd)
                try:
                    asset = by_identity.get(tuple(identity(fd)))
                    state_require(asset is not None and state_private(fd).st_size == asset["size"] and
                                  digest(fd) == asset["sha256"] and
                                  (FILES.get(asset["id"]) == name) == (name in FILES.values()), "readiness")
                    seen.add(asset["id"])
                    if name in FILES.values():
                        held[asset["id"]], fd = fd, None
                finally:
                    if fd is not None:
                        os.close(fd)
            state_require(seen == {a["id"] for a in assets} and set(held) == set(FILES) and
                          next(a for a in assets if a["id"] == "cert-manager-manifest")["sha256"] == MANIFEST, "readiness")
            for x in IMPORTED:
                os.lseek(held["cert-manager-" + x], 0, os.SEEK_SET)
                with open(os.dup(held["cert-manager-" + x]), "rb") as stream, tarfile.open(fileobj=stream, mode="r:") as bundle:
                    item = bundle.getmember("index.json")
                    state_require(item.isfile() and item.size <= 4096, "readiness")
                    index = decode(bundle.extractfile(item).read(4097))
                manifests = index.get("manifests") if isinstance(index, dict) else None
                state_require(isinstance(manifests, list) and len(manifests) == 1 and isinstance(manifests[0], dict) and
                              manifests[0].get("digest") == "sha256:" + IMAGES[x] and
                              manifests[0].get("annotations") == {"io.containerd.image.name":NAMED[x]}, "readiness")
            return resource, here, held
        except BaseException:
            for fd in held.values():
                os.close(fd)
            raise
        finally:
            os.close(gfd)

    def records(self):
        """The pinned records present, each with whether it carries the CRI pin label; another target refuses."""
        found = {}
        for line in self.runtime("ctr", "-n", "k8s.io", "images", "ls").decode("utf-8").split("\n")[1:]:
            fields = line.split()
            if fields and fields[0] in TARGETS:
                state_require(fields[2] == "sha256:" + TARGETS[fields[0]], "ownership")
                found[fields[0]] = PIN in fields[-1].split(",")
        return found

    def images(self):
        records = self.records()
        listed = decode(self.runtime("crictl", "images", "-o", "json"))
        items = listed.get("images") if isinstance(listed, dict) else None
        state_require(isinstance(items, list), "integrity")
        pinned = [any(isinstance(i, dict) and DIGESTED[x] in (i.get("repoDigests") or []) and i.get("pinned") is True
                      for i in items) for x in IMPORTED]
        return fact(all(records.get(name) for name in TARGETS) and all(pinned))

    def host(self):
        self.owned()
        facts = {"member":self.member}
        try:
            for fd in self.generation(self.member)[2].values():
                os.close(fd)
            facts["generation"] = fact(True)
        except StateRefused as error:
            if error.failure != "readiness":
                raise
            facts["generation"] = fact(False)
        try:
            facts["images"], facts["runtime"] = self.images(), fact(True)
        except Refused:
            facts["images"], facts["runtime"] = fact(False, "unobservable"), fact(False)
        state_require(len(canonical(facts)) <= 4096, "bound")
        return facts

    def import_images(self, result):
        """Per image, import from the held descriptor only when absent, tag, label; then verify."""
        self.active()
        resource, directory_id, held = self.generation(self.member)
        try:
            state_require(self.header["resource"] == resource, "ownership")
            self.images()
            previous = self.begin()
            if previous is not None:
                result["terminal"] = previous
                return
            self.revalidate()
            self.effect_started = True
            for x in IMPORTED:
                if NAMED[x] not in self.records():
                    os.lseek(held["cert-manager-" + x], 0, os.SEEK_SET)
                    self.runtime("ctr", "-n", "k8s.io", "images", "import", "-", mutating=True,
                                 source=held["cert-manager-" + x], seconds=600)
                if DIGESTED[x] not in self.records():
                    self.runtime("ctr", "-n", "k8s.io", "images", "tag", NAMED[x], DIGESTED[x], mutating=True)
                for name in (NAMED[x], DIGESTED[x]):
                    self.runtime("ctr", "-n", "k8s.io", "images", "label", name, PIN, mutating=True)
            state_require(self.images()["state"] == "ready", "readiness")
            result["terminal"] = self.terminal("succeeded", None, resource, directory_id)
        finally:
            for fd in held.values():
                os.close(fd)
        result["hosts"] = self.host()

    # ---- Objects: the render, the classes, the webhook fact ----
    def rendered(self):
        """Convert the first server's verified manifest, check and render it, and add the ownership metadata."""
        held = self.generation(self.recipe["members"][0])[2]
        try:
            os.lseek(held["cert-manager-manifest"], 0, os.SEEK_SET)
            raw = self.kubectl("create", "--dry-run=client", "--validate=false", "-f", "-", "-o", "json",
                               source=held["cert-manager-manifest"], limit=4194304)
        finally:
            for fd in held.values():
                os.close(fd)
        docs = documents(raw, len(OBJECTS))
        for doc, (version, kind, _, namespace, name) in zip(docs, OBJECTS):
            metadata = doc.get("metadata") if isinstance(doc, dict) else None
            state_require(isinstance(metadata, dict) and [doc.get("apiVersion"), doc.get("kind"), metadata.get("namespace"),
                                                          metadata.get("name")] == [version, kind, namespace, name] and
                          "status" not in doc and not set(SERVER_FIELDS) & set(metadata) and
                          not set(LABELS) & set(metadata.get("labels") or {}) and
                          not set(self.annotations) & set(metadata.get("annotations") or {}))
        state_require(render(docs) == self.recipe["render_sha256"])
        for doc in docs:
            metadata = doc["metadata"]
            metadata["labels"] = dict(metadata.get("labels") or {}, **LABELS)
            metadata["annotations"] = dict(metadata.get("annotations") or {}, **self.annotations)
            owned = dict(doc, webhooks=[with_defaults(doc["kind"], e) for e in doc["webhooks"]]) if "webhooks" in doc else doc
            self.expected.append(projection(owned, doc))
        return docs

    def anchor(self, uids):
        """The anchor's non-null expected UID equals its host receipt's `resource_identity`."""
        if uids is None or uids[0] is None:
            return
        found = [t["resource_identity"] for _, intent, t in self.ledger()
                 if intent["action"] == "lifecycle:cert-manager-create-objects" and t is not None and
                 t["outcome"] == "succeeded" and intent["binding"]["operation"] == self.recipe["operation"] and
                 intent["binding"]["owner"] == self.recipe["owner"] and intent["binding"]["scope"] == self.recipe["scope"]]
        state_require(found == [uids[0]], "ownership")

    def classify(self, rendered, uids):
        """The record for each manifest object in order; a runtime identity refuses before creation."""
        def read(item):
            resource, namespace, name, limit = item
            try:
                raw = self.kubectl("get", f"{resource}/{name}", *(("--namespace", namespace) if namespace else ()),
                                   "--ignore-not-found", "-o", "json", limit=limit)
            except Refused as error:
                if error.code != 5:
                    raise
                return False
            return documents(raw, 1)[0] if raw.strip() else None
        items = [(resource, namespace, name, 1048576) for _, _, resource, namespace, name in OBJECTS]
        if uids is None:
            items += [(*identity_value, 262144) for identity_value in RUNTIME]
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            found = list(pool.map(read, items))
        state_require(all(item is None for item in found[len(OBJECTS):]), "ownership")
        records = []
        for index, (obj, doc, (_, kind, _, namespace, name)) in enumerate(zip(found, rendered, OBJECTS)):
            record = {"kind":kind, "namespace":namespace, "name":name, "uid":None, "class":"absent",
                      "spec_sha256":None, "available":"unobserved"}
            if obj is False:
                record["class"] = "unobservable"
            elif obj is not None:
                metadata = obj.get("metadata") if isinstance(obj, dict) else None
                state_require(isinstance(metadata, dict) and obj.get("kind") == kind and metadata.get("name") == name and
                              metadata.get("namespace") == namespace and opaque(metadata.get("uid")))
                value = projection(obj, doc)
                owned = uids is not None and uids[index] == metadata["uid"] and \
                    all((metadata.get("annotations") or {}).get(k) == v for k, v in self.annotations.items())
                drifted = value != self.expected[index] or \
                    kind in ("Deployment", "CustomResourceDefinition") and metadata.get("generation") != 1
                record.update(uid=metadata["uid"], spec_sha256=state_hash("broil-k3s-cert-manager-object-v1", value),
                              available=available(kind, obj),
                              **{"class":"foreign" if not owned else "owned-drifted" if drifted else "owned-ready"})
            state_require(len(canonical(record)) <= 512, "bound")
            records.append(record)
        return records, found

    def webhook(self, records, found):
        """The `webhook` fact; the probe is the read's last request."""
        if any(records[index]["class"] != "owned-ready" for index in (0, 45, 46)):
            return fact(False, "objects")
        if not all(isinstance(e.get("clientConfig"), dict) and e["clientConfig"].get("caBundle")
                   for index in (45, 46) for e in found[index]["webhooks"]):
            return fact(False, "ca-bundle")
        if DEADLINE - time.monotonic() < 12:
            return fact(False, "budget")
        outcome = self.kubectl("create", "--dry-run=server", "--validate=false", "-o", "json", "-f", "-",
                               input=canonical(ISSUER) + b"\n", limit=65536, seconds=11, bound=False, probe=True)
        if outcome is None:
            return fact(False, "timeout")
        code, out, err = outcome
        if code == 0:
            docs = documents(out)
            metadata = docs[0].get("metadata") if len(docs) == 1 and isinstance(docs[0], dict) else None
            state_require(isinstance(metadata, dict) and docs[0].get("apiVersion") == "cert-manager.io/v1" and
                          docs[0].get("kind") == "Issuer" and metadata.get("namespace") == "cert-manager" and
                          isinstance(metadata.get("name"), str) and
                          re.fullmatch(r"broil-webhook-probe-[a-z0-9]{1,43}", metadata["name"]) is not None)
            return fact(docs[0].get("spec") == {"selfSigned":{}}, "mutated")
        text = err.decode("utf-8", "replace")
        for reason, required, optional in MAPPING:
            if all(p in text for p in required) and (not optional or any(p in text for p in optional)):
                return fact(False, reason)
        named = 'webhook "' in text
        timeout = any(p in text for p in ("context deadline exceeded", "Client.Timeout exceeded",
                                          "Error from server (Timeout)"))
        return fact(False, "timeout" if timeout and not named else "unobservable")

    def inspect(self, result):
        rendered = self.rendered()
        uids = self.header["uids"]
        self.anchor(uids)
        records, found = self.classify(rendered, uids)
        webhook = self.webhook(records, found)
        ready = all(r["class"] == "owned-ready" and r["available"] == "ready" for r in records) and \
            webhook["state"] == "ready"
        result.update(objects=records, webhook=webhook, services="unobserved" if ready else "not-ready")

    def create(self, result):
        self.active()
        resource = self.header["resource"]
        state_require(isinstance(resource, dict) and resource.get("generation") is not None, "ownership")
        state_hex(resource["generation"])
        state_require(resource == {"kind":"service", "id":"cert-manager-object-01", "owner":self.recipe["owner"],
                                   "generation":resource["generation"], "machine":None, "path":None, "namespace":None,
                                   "name":"cert-manager", "uid":None} and
                      self.binding["operation"] == self.recipe["operation"], "ownership")
        rendered = self.rendered()
        records, _ = self.classify(rendered, None)
        preflight = self.header["preflight"]
        state_require(isinstance(preflight, list) and len(preflight) == len(OBJECTS), "ownership")
        for old, new in zip(preflight, records):
            state_fields(old, "kind namespace name uid class spec_sha256 available")
            state_require(old == new and new["class"] == "absent", "ownership")
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        self.effect_started = True
        uids = created(self.kubectl("create", "--validate=false", "-f", "-", "-o", "jsonpath=" + CREATED,
                                    input=canonical({"apiVersion":"v1", "kind":"List", "items":rendered}) + b"\n",
                                    limit=len(OBJECTS) * 512, seconds=300, mutating=True))
        result["terminal"] = self.terminal("succeeded", None, resource, uids[0])
        result["objects"] = [{"kind":kind, "namespace":namespace, "name":name, "uid":uid, "class":"owned-ready",
                              "spec_sha256":state_hash("broil-k3s-cert-manager-object-v1", value), "available":"unobserved"}
                             for (_, kind, _, namespace, name), uid, value in zip(OBJECTS, uids, self.expected)]


# ---- The issuer protocol ----
ISSUER_TAGS = ("inspect-objects", "create-object", "register-input", "activate", "create-issuer")
LABELED = ("broil.dev/owner", "broil.dev/generation", "broil.dev/activation", "broil.dev/managed-by", "broil.dev/component")
OWNERSHIP = ("broil.dev/owner", "broil.dev/creation-operation", "broil.dev/cluster-uid", "broil.dev/recipe-sha256",
             "broil.dev/profile-sha256")
KEY_LISTS = [" ".join(sorted(LABELED)) + " ", " ".join(sorted(OWNERSHIP)) + " "]


def template(labels, annotations, data=()):
    """A Secret read's tab-separated fields: nothing here can fail on a valid object or print another value."""
    return '{{"\\t"}}'.join(["{{.type}}", "{{.metadata.uid}}"] + [
        "{{range $k, $v := .metadata.%s}}{{$k}} {{end}}" % x for x in ("labels", "annotations")] + [
        '{{with .metadata.%s}}{{printf "%%q" (index . "%s")}}{{end}}' % (x, key)
        for x, keys in (("labels", labels), ("annotations", annotations)) for key in keys] + [
        "{{range .metadata.ownerReferences}}x{{end}}", "{{range .metadata.finalizers}}{{.}} {{end}}",
        "{{if .metadata.deletionTimestamp}}deleting{{end}}"] + [
        '{{with .data}}{{with index . "%s"}}{{.}}{{end}}{{end}}' % key for key in data])


# The Secret's seventeen fields.
SECRET_FIELDS = template(LABELED, OWNERSHIP)
# Each effect's stage row: the Secret's class and activation, the registration; no ClusterIssuer.
ROWS = {"create-object":("absent", None, "absent"), "register-input":("owned", "inactive", "absent"),
        "activate":("owned", "inactive", "present"), "create-issuer":("owned", "active", "present")}


def quoted(value):
    return '"%s"' % value


def name40(value):
    return hashlib.sha256(canonical(value)).hexdigest()[:40]


class IssuerReceiver(CertManagerReceiver):
    FAMILY, KEYS = "issuer", ("recipe", "expected", "resource", "preflight", "projection")

    def check(self, profile):
        """The recipe and the names."""
        r, b = self.recipe, self.binding
        state_fields(r, "scope owner operation cluster first_server anchor_uid version issuer resource "
                        "cluster_issuer_name stage origins profile_sha256")
        res, owner = r["resource"], r["owner"]
        state_fields(res, "kind id owner generation machine path namespace name uid")
        state_cluster(r["cluster"])
        state_hex(res["generation"])
        self.secret = "broil-input-" + name40([owner, {k:res[k] for k in ("kind", "id", "generation")}])
        self.issuer = "broil-issuer-" + name40([owner, {"kind":"issuer", "id":res["id"]}])
        state_require(r["scope"] == b["scope"] and owner == b["owner"] and r["operation"] == b["operation"] and
                      r["profile_sha256"] == b["fingerprints"]["profile_sha256"] and r["cluster"] and
                      r["version"] == profile["k3s_version"] and self.member == r["first_server"] and
                      res == dict(res, kind="issuer", id="issuer-object-" + r["issuer"], owner=owner, path=None,
                                  machine=self.member["machine"], namespace="cert-manager", name=self.secret) and
                      (res["uid"] is None or opaque(res["uid"])) and r["cluster_issuer_name"] == self.issuer, "ownership")
        # An object's annotations: its origin's, or this request's when it creates the object.
        self.owned_secret, self.owned_issuer = ({
            "broil.dev/owner":owner, "broil.dev/cluster-uid":r["cluster"]["uid"],
            "broil.dev/creation-operation":(origin or r)["operation"],
            "broil.dev/recipe-sha256":origin["recipe_sha256"] if origin else self.recipe_hash,
            "broil.dev/profile-sha256":r["profile_sha256"]} for origin in (r["origins"]["secret"], r["origins"]["cluster_issuer"]))
        self.projection = {"labels":{"broil.dev/managed-by":"broil", "broil.dev/component":"issuer"},
                           "annotations":self.owned_issuer, "owner_references":[], "finalizers":[], "deleting":False,
                           "spec":{"ca":{"secretName":self.secret}}}
        self.path = "%s/resources/%s/%s" % (self.owner_path, res["id"], res["generation"])

    def get(self, kind, name, *args, seconds=20):
        """A bounded read's output, None for the exact `NotFound` answer, else False."""
        outcome = self.kubectl("get", kind, name, *args, limit=262144, seconds=seconds, probe=True)
        if outcome is None or outcome[0] and outcome[2] != b'Error from server (NotFound): %s "%s" not found\n' % (
                kind.encode(), name.encode()):
            return False
        return None if outcome[0] else outcome[1]

    def prerequisites(self, *crds):
        """The prerequisites: the Namespace UID and each CRD's conditions."""
        uid = self.get("namespaces", "cert-manager", "-o", "jsonpath={.metadata.uid}")
        state_require(uid is not False, "readiness")
        state_require(uid == self.recipe["anchor_uid"].encode(), "ownership")
        for crd in crds:
            out = self.get("customresourcedefinitions", crd + ".cert-manager.io", "-o",
                           "go-template={{range .status.conditions}}{{.type}}={{.status}} {{end}}") or b""
            state_require({"Established=True", "NamesAccepted=True"} <= set(out.decode().split()), "readiness")

    def api(self, record, uid, annotations, projection, label, kinds, *where):
        """One cert-manager object's class into `record`; its status and the named conditions at its generation."""
        out = self.get(record["kind"].lower() + "s.cert-manager.io", record["name"], *where, "-o", "json")
        if out is not None:
            try:
                obj = documents(out or b"!", 1)[0]
                meta = obj["metadata"]
                state_require(obj["kind"] == record["kind"] and meta["name"] == record["name"] and opaque(meta["uid"]))
                value = {"labels":meta.get("labels") or {}, "annotations":meta.get("annotations") or {},
                         "owner_references":meta.get("ownerReferences") or [], "finalizers":meta.get("finalizers") or [],
                         "deleting":"deletionTimestamp" in meta, "spec":obj.get("spec")}
                owned = uid == meta["uid"] and all(value["annotations"].get(k) == v for k, v in annotations.items())
                record.update(uid=meta["uid"], spec_sha256=state_hash(label, value),
                              **{"class":"foreign" if not owned else "owned" if value == projection else "owned-drifted"})
                status = obj.get("status") or {}
                return status, [next((c.get("status") for c in status.get("conditions") or []
                                      if c.get("type") == kind and c.get("observedGeneration") == meta.get("generation")), None)
                                for kind in kinds]
            except (Refused, StateRefused, ValueError, TypeError, KeyError, AttributeError):
                record["class"] = "unobservable"
        return {}, [None] * len(kinds)

    def observe(self):
        """The prerequisites, classes and `issuer` fact."""
        self.prerequisites("clusterissuers")
        expected = self.header["expected"]
        secret, issuer = ({"kind":kind, "namespace":ns, "name":name, "uid":None, "class":"absent", "activation":None,
            "spec_sha256":None} for kind, ns, name in (("Secret", "cert-manager", self.secret), ("ClusterIssuer", None, self.issuer)))
        out = self.get("secrets", self.secret, "-n", "cert-manager", "-o", "go-template=" + SECRET_FIELDS)
        f = out.decode("utf-8", "replace").split("\t") if out else []
        if out is not None and (len(f) != 17 or not opaque(f[1])):
            secret["class"] = "unobservable"  # possibly the whole Secret: discarded unparsed
        elif out is not None:
            act = f[6][1:-1]
            owned = expected["secret"] == f[1] and f[9:14] == [quoted(self.owned_secret[k]) for k in OWNERSHIP]
            fits = f[0] == "Opaque" and f[2:4] == KEY_LISTS and act in ("inactive", "active") and f[14:] == ["", "", ""] and \
                f[4:9] == [quoted(v) for v in (self.recipe["owner"], self.recipe["resource"]["generation"], act, "broil", "issuer")]
            secret.update(uid=f[1], activation=act if owned and fits else None,
                          **{"class":"foreign" if not owned else "owned" if fits else "owned-drifted"})
        _, (ready,) = self.api(issuer, expected["cluster_issuer"], self.owned_issuer, self.projection,
                               "broil-k3s-issuer-object-v1", ("Ready",))
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
        classes = {secret["class"], issuer["class"], registration["class"]}
        reason = ("unobservable" if classes & {"unobservable", "foreign", "owned-drifted"} else
                  {"True":"observed", "False":"rejected"}.get(ready, "pending") if issuer["class"] == "owned" else
                  "absent" if secret["activation"] == "active" else "inactive")
        return [secret, issuer], {"registration":registration, "ready":fact(reason == "observed", reason)}

    def run(self, result):
        records, issuer = self.observe()
        tag, res, preflight = self.tag, self.header["resource"], self.header["preflight"]
        if tag == "inspect-objects":
            result.update(objects=records, issuer=issuer,
                          services="unobserved" if issuer["ready"]["state"] == "ready" else "not-ready")
            return
        self.active()
        state_require(res == self.recipe["resource"] and preflight == dict(preflight, objects=records) and
                      preflight["issuer"]["registration"] == issuer["registration"] and records[1]["class"] == "absent" and
                      (records[0]["class"], records[0]["activation"], issuer["registration"]["class"]) == ROWS[tag],
                      "ownership")
        if tag == "register-input":
            # The control body's own admission checks of the projection.
            projection, profile, r, b = self.header["projection"], self.host_profile, self.recipe, self.binding
            state_require(isinstance(projection, dict) and set(projection) == set(
                "schema binding declaration scripts registries secrets references profile".split()) and
                          projection["schema"] == 1 and projection["profile"] == profile and
                          projection["binding"] == {
                              **{k:r["scope"][k] for k in ("project", "environment", "target")}, "owner":r["owner"],
                              "operation":b["operation"], "attempt":b["attempt"], "issuer":r["issuer"],
                              "cluster":r["cluster"], **dict.fromkeys(("source", "service", "principal", "origin", "recovery")),
                              "destination":{k:r["first_server"][k] for k in ("machine", "member", "role", "node_uid")},
                              "resource":dict({k:res[k] for k in ("kind", "id", "generation")}, uid=records[0]["uid"]),
                              "profile_sha256":b["fingerprints"]["profile_sha256"], "script_sha256":profile["script_sha256"]},
                          "ownership")
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        uid = self.create_issuer(result) if tag == "create-issuer" else res["uid"]
        self.effect_started = True
        if tag == "create-object":
            uid = self.make({"apiVersion":"v1", "kind":"Secret", "type":"Opaque", "metadata":{
                "name":self.secret, "namespace":"cert-manager", "annotations":self.owned_secret,
                "labels":dict(zip(LABELED, (self.recipe["owner"], res["generation"], "inactive", "broil", "issuer")))}}).decode()
            state_require(opaque(uid))
        elif tag == "activate":
            label = "/metadata/labels/broil.dev~1activation"
            patch = [{"op":"test", "path":"/metadata/uid", "value":uid}, {"op":"test", "path":label, "value":"inactive"},
                     {"op":"replace", "path":label, "value":"active"}]
            state_require(self.kubectl("patch", "secret", self.secret, "-n", "cert-manager", "--type=json", "-p",
                                       canonical(patch).decode(), "-o", "jsonpath={.metadata.uid}", limit=512,
                                       mutating=True) == uid.encode())
        elif tag == "register-input":
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
            result["issuer"] = {"ready":fact(False, "inactive"), "registration":{
                "class":"present", "directory":here, "record_sha256":hashlib.sha256(canonical(record)).hexdigest()}}
            uid = None
        result["terminal"] = self.terminal("succeeded", None, res, uid)

    def make(self, doc, *args, **options):
        return self.kubectl(*args, "create", "-f", "-", "-o", "jsonpath={.metadata.uid}", input=canonical(doc) + b"\n",
                            limit=512, **options or {"mutating":True})

    def create_once(self, doc, *where):
        """The bounded create of one object, ending in the API server's answer, and its conclusive refusals."""
        global WRITERS_SETTLED
        kind, name = doc["kind"], doc["metadata"]["name"]
        state_require(DEADLINE - time.monotonic() >= 50, "timeout")
        # Only a child that exits on its own, not a local overrun or an abandoned one, leaves writers settled.
        self.effect_started, WRITERS_SETTLED = True, False
        outcome = self.make(doc, timeout="40s", seconds=45, probe=True)
        state_require(outcome, "timeout")
        WRITERS_SETTLED = True
        code, out, err = outcome
        if code:
            # The first standard-error line that is no warning; later lines are not matched.
            line = next((x for x in err.decode("utf-8", "replace").split("\n") if not x.startswith("Warning: ")), "")
            at, invalid = line.find('admission webhook "'), '"%s" is invalid: ' % name
            state_require([line.startswith("Error from server (InternalError): ") and 'failed calling webhook "' in line,
                           line.startswith("Error from server (Forbidden): ") and line.find('" denied the request', at) > at >= 0,
                           line.startswith(("The %s " % kind + invalid, "The %ss " % kind.lower() + invalid))].count(True) == 1 and
                          self.get(kind.lower() + "s.cert-manager.io", name, *where, "-o", "name", seconds=4) is None, "transport")
            self.effect_started = False
            raise StateRefused("readiness")
        uid = out.decode()
        state_require(opaque(uid))
        return uid

    def create_issuer(self, result):
        uid = self.create_once({"apiVersion":"cert-manager.io/v1", "kind":"ClusterIssuer", "spec":self.projection["spec"],
                                "metadata":{"name":self.issuer, "labels":self.projection["labels"],
                                            "annotations":self.owned_issuer}})
        result["objects"] = [{"kind":"ClusterIssuer", "namespace":None, "name":self.issuer, "uid":uid, "class":"owned",
                              "activation":None, "spec_sha256":state_hash("broil-k3s-issuer-object-v1", self.projection)}]


# ---- The certificate protocol ----
CERTIFICATE_TAGS = ("inspect-objects", "create-object")
COMPONENT = ("broil.dev/managed-by", "broil.dev/component")
NOTED = tuple("cert-manager.io/" + x for x in ("certificate-name", "issuer-name", "issuer-kind", "issuer-group", "alt-names"))
# The twenty-one fields: the public certificates, never `tls.key`.
TLS_FIELDS = template(COMPONENT, OWNERSHIP + NOTED, ("tls.crt", "ca.crt"))
TLS_KEYS = [" ".join(sorted(x)) + " " for x in (COMPONENT + ("controller.cert-manager.io/fao",), OWNERSHIP + NOTED + tuple(
    "cert-manager.io/" + x for x in ("common-name", "ip-sans", "uri-sans")))]
PEM = re.compile(r"-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=\n]+)-----END CERTIFICATE-----\n?")


def utc(digits):
    """Epoch seconds of fourteen digits `YYYYMMDDHHMMSS`, range-checked."""
    state_require(len(digits) == 14 and digits.isascii() and digits.isdigit())
    return int(datetime.datetime(*(int(digits[i:i + 2 + 2 * (i == 0)]) for i in (0, 4, 6, 8, 10, 12)),
                                 tzinfo=datetime.timezone.utc).timestamp())


def stamp(value):
    """A status timestamp `YYYY-MM-DDTHH:MM:SSZ` in epoch seconds, else None."""
    try:
        state_require(isinstance(value, str) and len(value) == 20 and value[4::3] == "--T::Z")
        return utc(re.sub("[-T:Z]", "", value))
    except (StateRefused, ValueError):
        return None


def validity(der):
    """A bounded DER walk: one certificate's notBefore and notAfter."""
    def item(at, tag=None):
        state_require(at + 2 <= len(der))
        kind, size, at = der[at], der[at + 1], at + 2
        if size & 0x80:
            count = size & 0x7f
            state_require(1 <= count <= 4 and at + count <= len(der))
            size, at = int.from_bytes(der[at:at + count], "big"), at + count
        state_require(tag in (None, kind) and at + size <= len(der))
        return kind, at, at + size
    _, at, end = item(0, 0x30)
    state_require(end == len(der))
    _, at, _ = item(at, 0x30)
    kind, _, after = item(at)
    at = after if kind == 0xa0 else at
    for tag in (0x02, 0x30, 0x30):
        at = item(at, tag)[2]
    _, at, _ = item(at, 0x30)
    times = []
    for _ in range(2):
        kind, start, at = item(at)
        text = der[start:at].decode("ascii")
        state_require(len(text) == {0x17:13, 0x18:15}.get(kind) and text[-1] == "Z")
        times.append(utc((("19" if text[:2] >= "50" else "20") if kind == 0x17 else "") + text[:-1]))
    return times


def chain(crt, ca):
    """The leaf's validity and the chain expiry; a malformed certificate refuses."""
    def certificates(field):
        text = base64.b64decode(field, validate=True).decode("ascii")
        state_require(PEM.sub("", text).strip() == "")
        return [validity(base64.b64decode(x.replace("\n", ""), validate=True)) for x in PEM.findall(text)]
    (leaf, *rest), ca = certificates(crt), certificates(ca)
    state_require(len(ca) == 1)
    return leaf + [min(x[1] for x in rest + ca)]


def rfc(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


class CertificateReceiver(IssuerReceiver):
    FAMILY, KEYS = "certificate", ("recipe", "expected", "resource", "preflight")

    def check(self, profile):
        """The recipe, the names and the render."""
        r, b = self.recipe, self.binding
        state_fields(r, "scope owner operation cluster first_server anchor_uid version certificate resource "
                        "certificate_name secret_name issuer spec stage origins profile_sha256")
        res, owner, issuer, spec, origins = r["resource"], r["owner"], r["issuer"], r["spec"], r["origins"]
        state_fields(res, "kind id owner generation machine path namespace name uid")
        state_fields(issuer, "name cluster_issuer_name secret_name")
        state_fields(spec, "dns_names duration_s renew_before_s")
        state_fields(origins, "certificate cluster_issuer")
        state_fields(origins["cluster_issuer"], "operation recipe_sha256 uid")
        mine = origins["certificate"]
        if mine is not None:
            state_fields(mine, "operation recipe_sha256")
        state_cluster(r["cluster"])
        state_hex(res["generation"])
        hashed = name40([owner, {"kind":"certificate", "id":res["id"]}])
        self.certificate, self.secret, self.issuer = "broil-certificate-" + hashed, "broil-tls-" + hashed, issuer["cluster_issuer_name"]
        names, create = spec["dns_names"], r["stage"] == "create"
        state_require(r["scope"] == b["scope"] and owner == b["owner"] and r["operation"] == b["operation"] and
                      r["profile_sha256"] == b["fingerprints"]["profile_sha256"] and r["cluster"] and
                      r["version"] == profile["k3s_version"] and self.member == r["first_server"] and
                      res == dict(res, kind="service", id="certificate-object-" + r["certificate"], owner=owner, path=None,
                                  machine=None, namespace="cert-manager", name=self.certificate) and
                      r["stage"] in ("create", "observe") and (res["uid"] is None) == create == (mine is None) and
                      (create or opaque(res["uid"])) and r["certificate_name"] == self.certificate and
                      r["secret_name"] == self.secret and
                      self.issuer == "broil-issuer-" + name40([owner, {"kind":"issuer", "id":"issuer-object-" + issuer["name"]}]) and
                      isinstance(names, list) and names and all(isinstance(x, str) for x in names) and
                      all(type(spec[k]) is int for k in ("duration_s", "renew_before_s")), "ownership")
        # The Certificate's annotations: its creating request's; the ClusterIssuer's from its origin.
        common = {"broil.dev/owner":owner, "broil.dev/cluster-uid":r["cluster"]["uid"], "broil.dev/profile-sha256":r["profile_sha256"]}
        self.owned_certificate, self.owned_issuer = (dict(common, **{"broil.dev/creation-operation":(origin or r)["operation"],
            "broil.dev/recipe-sha256":origin["recipe_sha256"] if origin else self.recipe_hash})
            for origin in (mine, origins["cluster_issuer"]))
        self.projection = {"labels":{"broil.dev/managed-by":"broil", "broil.dev/component":"issuer"},
                           "annotations":self.owned_issuer, "owner_references":[], "finalizers":[], "deleting":False,
                           "spec":{"ca":{"secretName":issuer["secret_name"]}}}
        labels = dict(zip(COMPONENT, ("broil", "certificate")))
        self.render = {"apiVersion":"cert-manager.io/v1", "kind":"Certificate", "metadata":{
            "name":self.certificate, "namespace":"cert-manager", "labels":labels, "annotations":self.owned_certificate}, "spec":{
            "secretName":self.secret, "issuerRef":{"group":"cert-manager.io", "kind":"ClusterIssuer", "name":self.issuer},
            "dnsNames":names, "duration":"%ds" % spec["duration_s"], "renewBefore":"%ds" % spec["renew_before_s"],
            "privateKey":{"algorithm":"RSA", "encoding":"PKCS1", "size":2048, "rotationPolicy":"Always"},
            "secretTemplate":{"labels":labels, "annotations":self.owned_certificate}}}
        self.projected = {"labels":labels, "annotations":self.owned_certificate, "owner_references":[], "finalizers":[],
                          "deleting":False, "spec":self.render["spec"]}

    def observe(self):
        """The prerequisites, classes and `certificate` fact; also the ClusterIssuer's `Ready`."""
        self.prerequisites("certificates", "clusterissuers")
        spec = self.recipe["spec"]
        cert, secret, issuer = ({"kind":kind, "namespace":ns, "name":name, "uid":None, "class":"absent", "spec_sha256":None}
            for kind, ns, name in (("Certificate", "cert-manager", self.certificate), ("Secret", "cert-manager", self.secret),
                                   ("ClusterIssuer", None, self.issuer)))
        status, (ready, issuing) = self.api(cert, self.header["expected"]["certificate"], self.owned_certificate, self.projected,
                                            "broil-k3s-certificate-object-v1", ("Ready", "Issuing"), "-n", "cert-manager")
        out = self.get("secrets", self.secret, "-n", "cert-manager", "-o", "go-template=" + TLS_FIELDS)
        f = out.decode("utf-8", "replace").split("\t") if out else []
        walked = names = None
        if out is not None and (len(f) != 21 or not opaque(f[1])):
            secret["class"] = "unobservable"  # possibly the whole Secret: discarded unparsed
        elif out is not None:
            mine = cert["class"] == "owned" and f[6:12] == [quoted(x) for x in [*map(self.owned_certificate.get, OWNERSHIP), self.certificate]]
            fits = f[0] == "kubernetes.io/tls" and f[2:4] == TLS_KEYS and f[4:6] == ['"broil"', '"certificate"'] and \
                f[12:15] == [quoted(x) for x in (self.issuer, "ClusterIssuer", "cert-manager.io")] and f[16:19] == ["", "", ""]
            try:
                walked = mine and fits and chain(f[19], f[20])
            except (StateRefused, ValueError, IndexError):
                pass
            secret.update(uid=f[1], **{"class":"foreign" if not mine else "owned-drifted" if not fits else
                                       "owned" if walked else "unobservable"})
            names = f[15]
        _, (current,) = self.api(issuer, self.recipe["origins"]["cluster_issuer"]["uid"], self.owned_issuer, self.projection,
                                 "broil-k3s-issuer-object-v1", ("Ready",))
        times = [stamp(status.get(key)) for key in ("notBefore", "notAfter", "renewalTime")]
        # A present time is set only when it parses; the body clock is sampled once, in whole seconds.
        last, now = status.get("lastFailureTime"), state_now() // 1000
        failed = stamp(last)
        unset = None in times or last is not None and failed is None
        reason = ("unobservable" if {cert["class"], secret["class"], issuer["class"]} & {"unobservable", "foreign", "owned-drifted"} else
                  "issuer" if current != "True" and ready != "True" else
                  "absent" if cert["class"] == "absent" else
                  "expired" if walked and now > walked[1] else
                  "rejected" if ready != "True" and issuing == "False" and failed is not None else
                  "pending" if ready != "True" or not walked or unset or walked[:2] != times[:2] else
                  "names" if names != quoted(",".join(spec["dns_names"])) else
                  "lifetime" if [times[1] - times[0], times[1] - times[2]] != [spec["duration_s"], spec["renew_before_s"]] or
                  walked[2] < times[1] else "observed")
        issued = None
        if cert["class"] == secret["class"] == "owned" and ready == "True" and not unset:
            renewal = ("issuer" if current != "True" else "failed" if issuing == "False" and failed is not None else
                       "overdue" if now >= times[2] + 300 else "issuing" if issuing == "True" else "scheduled")
            issued = dict(zip(("not_before", "not_after", "renewal_time", "chain_not_after", "renewal", "last_failure_time"),
                              [*map(rfc, times + walked[2:]), renewal, None if failed is None else rfc(failed)]))
        return [cert, secret, issuer], {"ready":fact(reason == "observed", reason), "issued":issued}, current

    def run(self, result):
        records, certificate, current = self.observe()
        if self.tag == "inspect-objects":
            result.update(objects=records, certificate=certificate,
                          services="ready" if certificate["ready"]["state"] == "ready" else "not-ready")
            return
        self.active()
        res, preflight = self.header["resource"], self.header["preflight"]
        # The `create` row, the ClusterIssuer `Ready` and datastore encryption, before any effect.
        state_require(res == self.recipe["resource"] and self.recipe["stage"] == "create" and
                      set(preflight) == {"objects", "certificate"} and preflight["objects"] == records and
                      [x["class"] for x in records] == ["absent", "absent", "owned"], "ownership")
        state_require(current == "True", "readiness")
        out = command(self.executable, ["secrets-encrypt", "status"], limits=(65536, 65536), probe=True)
        state_require(out and not out[0] and b"Encryption Status: Enabled" in out[1], "readiness")
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        result["terminal"] = self.terminal("succeeded", None, res, self.create_once(self.render, "-n", "cert-manager"))


# Each protocol's receiver, reply magic, own header fields, tags and result facts.
PROTOCOLS = {"broil-k3s-cert-manager":(CertManagerReceiver, b"BK3SCMG1\n", "uids original_recipe_sha256", ("inspect-host", "import-images",
                                     "inspect-objects", "create-objects"), ("hosts", "objects", "webhook", "services")),
             "broil-k3s-issuer":(IssuerReceiver, b"BK3SISS1\n", "expected projection", ISSUER_TAGS,
                                 ("objects", "issuer", "services")),
             "broil-k3s-certificate":(CertificateReceiver, b"BK3SCRT1\n", "expected", CERTIFICATE_TAGS,
                                      ("objects", "certificate", "services"))}


def cert_manager_request(raw, header, family):
    """One protocol's header."""
    global DEADLINE
    _, _, fields, tags, _ = PROTOCOLS[header["protocol"]]
    plain = family == "cert-manager"
    state_require(17 + len(raw) + (RESERVE if plain else 8192) <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms recipe resource preflight " + fields)
    state_require(canonical(header) == raw, "integrity")
    state_require(type(header["version"]) is int and header["version"] == 1,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
    tag, uids = header["action"], header.get("uids")
    state_require(tag in tags, "capability")
    mutation = tag not in ("inspect-host", "inspect-objects")
    state_hex(header["request_id"])
    state_binding(header["binding"])
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation, "ownership")
    state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(header["recipe"])) <= 32768, "bound")
    if not plain:
        state_fields(header["expected"], "secret cluster_issuer registration" if family == "issuer" else "certificate")
        state_require((header["preflight"] is None) != mutation and (header["resource"] is None) != mutation and
                      (header.get("projection") is None) == (tag != "register-input"), "ownership")
    state_require(not plain or (header["preflight"] is None) == (tag != "create-objects") and
                  (header["resource"] is None) == (not mutation) and (uids is None or tag == "inspect-objects") and
                  (uids is None or isinstance(uids, list) and len(uids) == len(OBJECTS) and
                   all(uid is None or opaque(uid) for uid in uids)), "ownership")
    if plain and header["original_recipe_sha256"] is not None:
        state_require(tag != "create-objects", "ownership")
        state_hex(header["original_recipe_sha256"], 64)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    state_require(sys.stdin.buffer.read(1) == b"", "integrity")


def cert_manager_main(raw, header):
    kind, magic, _, _, facts = PROTOCOLS[header["protocol"]]
    family = kind.FAMILY
    receiver = None
    status = "unknown"
    result = {"terminal":None, **dict.fromkeys(facts), "failure":None}
    prefix = magic + struct.pack(">I", len(raw)) + raw
    try:
        cert_manager_request(raw, header, family)
        receiver = kind(header)
        receiver.profile()
        receiver.open()
        receiver.owned()
        tag = header["action"]
        if family != "cert-manager":
            receiver.run(result)
        elif tag == "inspect-host":
            result["hosts"] = receiver.host()
        elif tag == "import-images":
            receiver.import_images(result)
        elif tag == "inspect-objects":
            receiver.inspect(result)
        else:
            receiver.create(result)
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
                result["terminal"] = receiver.terminal("failed", failure, header["resource"] if family != "cert-manager" else None)
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
    cert_manager_main(raw, header)
    os._exit(0)
except Exception:
    os._exit(125)
