#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, profile-bound K3s Traefik and ServiceLB ingress receiver."""
import base64
import concurrent.futures
import fcntl
import hashlib
import ipaddress
import json
import lzma
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
            bound=False):
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
            require(time.monotonic() < until, 6)
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
                        # The host-port reads report their profile bound as `bound`.
                        state_require(fits or not bound or stream is not process.stdout, "bound")
                        require(fits, 4)
                        streams[stream].extend(chunk)
                    else:
                        poll.unregister(stream)
        process.wait(timeout=max(0.001, until - time.monotonic()))
        require(process.returncode in allowed, 5)
        completed = True
        return bytes(streams[process.stdout])
    finally:
        # A failed mutating API client can leave server-side work unresolved.
        # Killing the local process alone cannot justify a writer-ended receipt.
        if (input is not None or mutating) and not completed:
            WRITERS_SETTLED = False
        poll.close()
        if process.poll() is None:
            process.kill()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                WRITERS_SETTLED = False
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def kubectl(fd, owner, *args, input=None, output_limit=MAXIMUM, bound=False):
    kubeconfig = f"{ROOT}/owners/{owner}/admin.yaml"
    read_file(kubeconfig, 65536)
    return command(fd, ["kubectl", "--kubeconfig", kubeconfig, "--request-timeout=10s", *args], input,
                   limits=(output_limit, MAXIMUM), bound=bound)


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




TEMPLATE_HASH = "e398aa7f8f6686c480ea666984b55cda9ca7b561dbd5b4308455262533edda17"
IMAGE = "96780238b1bbda5a9bb997f4307ce69e798ad1cf6eb7f2dcc0a440823467d199"
CHARTS = {
    "traefik": "a9ebcfeecdd5b9f1ffea1167a7ffee69e346cd10864998ce8e44b51c204b7767",
    "traefik_crd": "cd588985d419ca98f1e529a74a5ef06939795311450e8ec31671d8b1b2c1e93c",
}
CHART_DIR = "/var/lib/rancher/k3s/server/static/charts"
CHART_FILES = {"traefik": "traefik-40.1.4+up40.1.0.tgz", "traefik_crd": "traefik-crd-40.1.4+up40.1.0.tgz"}
NAMED = "docker.io/library/traefik:broil-proof"
DIGESTED = "docker.io/library/traefik@sha256:" + IMAGE
PIN = "io.cri-containerd.pinned=pinned"
KLIPPER = "910944bb0bd94f060a82a56ca1ea1c577d3e49b3473a093a47a985f32e92d94a"
# K3s's airgap import names every image by digest at each start.
LB_DIGESTED = "docker.io/rancher/klipper-lb@sha256:" + KLIPPER
TARGETS = {NAMED:IMAGE, DIGESTED:IMAGE, LB_DIGESTED:KLIPPER}
SERVICELB = "svclb-traefik"
# The traefik container arguments that the pinned charts render for every
# recipe (no API address, affinity or toleration reaches an argument),
# derived once from a guest install of both chart objects.
ARGS = [
    "--entryPoints.metrics.address=:9100/tcp", "--entryPoints.traefik.address=:8080/tcp",
    "--entryPoints.web.address=:8000/tcp", "--entryPoints.websecure.address=:8443/tcp",
    "--api.dashboard=true", "--ping=true", "--metrics.prometheus=true",
    "--metrics.prometheus.entrypoint=metrics", "--providers.kubernetescrd",
    "--providers.kubernetescrd.allowEmptyServices=true", "--providers.kubernetesingress",
    "--providers.kubernetesingress.allowEmptyServices=true",
    "--providers.kubernetesingress.ingressendpoint.publishedservice=kube-system/traefik",
    "--providers.kubernetesingress.ingressClass=traefik", "--entryPoints.websecure.http.tls=true",
    "--log.level=INFO",
]
PORTS = [{"name":"web", "port":80, "protocol":"TCP", "targetPort":"web"},
         {"name":"websecure", "port":443, "protocol":"TCP", "targetPort":"websecure"}]
CHART_NAMES = ("traefik-crd", "traefik")
CRD_GROUPS = (
    ("traefik.io", "ingressroutes ingressroutetcps ingressrouteudps middlewares middlewaretcps serverstransports "
                   "serverstransporttcps tlsoptions tlsstores traefikservices"),
    ("hub.traefik.io", "accesscontrolpolicies aiservices apiauths apibundles apicatalogitems apiplans apiportalauths "
                       "apiportals apiratelimits apis apiversions contentitems managedapplications "
                       "managedsubscriptions uplinks"),
    ("gateway.networking.k8s.io", "backendtlspolicies gatewayclasses gateways grpcroutes httproutes listenersets "
                                  "referencegrants tlsroutes"),
)
# The 51 result positions: (kind, namespace, name, chart index).
RESULTS = [item for index, chart in enumerate(CHART_NAMES) for item in (
    ("Job", "kube-system", "helm-install-" + chart, index), ("ServiceAccount", "kube-system", "helm-" + chart, index),
    ("ClusterRoleBinding", None, "helm-kube-system-" + chart, index),
    ("Secret", "kube-system", "chart-values-" + chart, index), ("ConfigMap", "kube-system", "chart-content-" + chart, index))]
RESULTS += [("Secret", "kube-system", f"sh.helm.release.v1.{chart}.v1", index) for index, chart in enumerate(CHART_NAMES)]
RESULTS += [("CustomResourceDefinition", None, name + "." + group, 0) for group, names in CRD_GROUPS for name in names.split()]
RESULTS += [("ServiceAccount", "kube-system", "traefik", 1), ("ClusterRole", None, "traefik-kube-system", 1),
            ("ClusterRoleBinding", None, "traefik-kube-system", 1), ("DaemonSet", "kube-system", "traefik", 1),
            ("Service", "kube-system", "traefik", 1), ("IngressClass", None, "traefik", 1)]
RESOURCES = {"Job":"job.batch", "ServiceAccount":"serviceaccount", "Secret":"secret", "ConfigMap":"configmap",
             "ClusterRoleBinding":"clusterrolebinding.rbac.authorization.k8s.io",
             "ClusterRole":"clusterrole.rbac.authorization.k8s.io", "DaemonSet":"daemonset.apps", "Service":"service",
             "CustomResourceDefinition":"customresourcedefinition.apiextensions.k8s.io",
             "IngressClass":"ingressclass.networking.k8s.io"}
# Conditions print whole: a jsonpath filter fails on the `conditions: null` that
# freshly created Gateway API CRDs carry until their controller updates them.
FIELDS = (".kind", ".metadata.namespace", ".metadata.name", ".metadata.uid", ".metadata.labels",
          ".metadata.annotations", ".metadata.ownerReferences", ".spec.template.metadata.annotations",
          ".status.conditions", ".roleRef", ".subjects",
          ".spec.template.spec.affinity", ".spec.template.spec.tolerations",
          '.spec.template.spec.containers[?(@.name=="traefik")].image',
          '.spec.template.spec.containers[?(@.name=="traefik")].args', ".status.desiredNumberScheduled",
          ".status.numberReady", ".spec.type", ".spec.ports", ".spec.controller")
OBJECTSET = "objectset.rio.cattle.io/"
# The complete source template, one xz stream in base85.
TEMPLATE = (
    '{Wp48S^xk9=GL@E0stWa8~^|S5YJf5-~@C6FkJu^=l+bR`IJ>?9~bwMNM^@#a7ZTQ6sF7xx4nv8@Y;90#7o{ltBXvSGoaAQ^<6!@'
    'LMrRoY{@3yRKpW2I~mD#PnYbNNt`mp%gJ!N<Cbduf7R{i|7XPe(kLdz)Fp=Tv-*HCvUl(UV~_=JYm`6EpR^^M;OCr5wS)F$MJKr='
    'shKg36=$DTrx=W#CmcoXW8Bp>$#RG){km`>X=HgSvS+}YWX>*}m^XOg$%Cj>4x(-W5q3)>_fyaHc4i`XhNzEQIFq;DhBdv~`db9W'
    '<Q2@^ica7}7mKK$)I_QIC+h?r{pxb4pY;w=Xz6O=xdR+&Xv)&k2DSCLZf(CTHlO(M_z%ZRkZl%8n%+09B{V9=khf-79-=i3vq6(z'
    'sa%EZ;8t?a{*Z5;;;EcvVO<O`8@i|N-b*`Zqrw1cX@yMWO}GvCvuk-z%Yf_eC{8rk*?^6;Zmp2rV*;E3>;E*(FjhhzMVsv%4fpNP'
    '5*t$7w8`DFw}8J8CR`*D!UUgpuD9&6i+1E=4wrPj7mY-12^upd^G8-y=pXC@-f;E*wG<Tx)dNMBJa^~m53!pzTG7N#anHWFp8&}1'
    'k#wvg$phk|)@g<~{Wf4dF|~Gpsuq{GGFghe7$@Mpy8bz`lDx_5l`D0HV;3SlNILE4WiV;NOV7tGJo~xMZxL>?8(m+5>+1=h>gEnb'
    'NbN&oFoUFtb8RwDKbWzq3M%v;i;!O|oz%Y~0NfP-@RTTt2kD(d00GPd^#}j}{~J{AvBYQl0ssI200dcD'
)


def template():
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    raw = decoder.decompress(base64.b85decode(TEMPLATE), 4097)
    state_require(decoder.eof and not decoder.unused_data and hashlib.sha256(raw).hexdigest() == TEMPLATE_HASH,
                  "ownership")
    return raw.decode("utf-8")


def quoted(value):
    state_require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._/:=-]*", value) is not None, "ownership")
    return '"' + value + '"'


def render(recipe, taints):
    """Fixed sites of the pinned template, each exactly once."""
    text = template()
    api = recipe["network"]["api"]
    names = [m["member"] for m in recipe["members"]
             if m["machine"] in {e["machine"] for e in recipe["ingress_members"]}]
    tolerations = "".join(f"    - key: {quoted(key)}\n      operator: \"Equal\"\n      value: {quoted(value)}\n"
                          f"      effect: {quoted(effect)}\n" for key, value, effect in taints)
    for old, new in (
        ("https://%{KUBERNETES_API}%/static/charts/traefik-crd-40.1.4+up40.1.0.tgz",
         f"https://{api}/static/charts/traefik-crd-40.1.4+up40.1.0.tgz"),
        ("https://%{KUBERNETES_API}%/static/charts/traefik-40.1.4+up40.1.0.tgz",
         f"https://{api}/static/charts/traefik-40.1.4+up40.1.0.tgz"),
        ('"%{SYSTEM_DEFAULT_REGISTRY_RAW}%"', '""'),
        ("    deployment:\n      podAnnotations:\n", '    deployment:\n      kind: "DaemonSet"\n      podAnnotations:\n'),
        ("      kubernetesIngress:\n        publishedService:\n",
         '      kubernetesIngress:\n        ingressClass: "traefik"\n        publishedService:\n'),
        ('    image:\n      repository: "rancher/mirrored-library-traefik"\n      tag: "3.7.8"\n',
         f'    image:\n      registry: "docker.io"\n      repository: "library/traefik"\n      digest: "sha256:{IMAGE}"\n'),
        ('      effect: "NoSchedule"\n    service:\n', '      effect: "NoSchedule"\n' + tolerations + "    service:\n"),
        ('      spec:\n        ipFamilyPolicy: "PreferDualStack"\n',
         '      spec:\n        type: "ClusterIP"\n        ipFamilyPolicy: "PreferDualStack"\n'),
    ):
        state_require(text.count(old) == 1, "ownership")
        text = text.replace(old, new)
    state_require("%{" not in text and "%}" not in text and text.endswith('"PreferDualStack"\n'), "ownership")
    text += ('    versionOverride: "v3.7.13"\n    affinity:\n      nodeAffinity:\n'
             '        requiredDuringSchedulingIgnoredDuringExecution:\n          nodeSelectorTerms:\n'
             '          - matchExpressions:\n            - key: "kubernetes.io/hostname"\n'
             '              operator: "In"\n              values:\n' +
             "".join(f"              - {quoted(name)}\n" for name in names) +
             "    ingressClass:\n      enabled: true\n      isDefaultClass: false\n")
    raw = text.encode("utf-8")
    state_require(hashlib.sha256(raw).hexdigest() == recipe["render_sha256"], "ownership")
    return raw, names


def ingress_recipe(recipe, binding, profile):
    state_fields(recipe, "scope owner operation cluster members first_server ingress_members version network "
                         "profile_sha256 template_sha256 render_sha256 servicelb_sha256")
    state_require(recipe["scope"] == binding["scope"] and recipe["owner"] == binding["owner"] and
                  recipe["profile_sha256"] == binding["fingerprints"]["profile_sha256"] and
                  recipe["version"] == profile["k3s_version"] and recipe["template_sha256"] == TEMPLATE_HASH, "ownership")
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
    state_hex(recipe["render_sha256"], 64)
    state_hex(recipe["servicelb_sha256"], 64)
    entries = recipe["ingress_members"]
    state_require(isinstance(entries, list) and 1 <= len(entries) <= 128, "ownership")
    for entry in entries:
        state_fields(entry, "machine generation marker_sha256")
        state_hex(entry["generation"])
        state_hex(entry["marker_sha256"], 64)
    selected = {e["machine"] for e in entries}
    state_require([e["machine"] for e in entries] == [m for m in machines if m in selected] and
                  len(selected) == len(entries), "ownership")
    state_fields(recipe["network"], "service_cidr api")
    try:
        services = ipaddress.IPv4Network(recipe["network"]["service_cidr"], strict=True)
    except (ValueError, TypeError):
        raise StateRefused("integrity")
    state_require(str(services) == recipe["network"]["service_cidr"] and services.num_addresses > 2 and
                  recipe["network"]["api"] == f"{services.network_address + 1}:443", "ownership")


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    value = hashlib.sha256()
    while chunk := os.read(fd, 1048576):
        state_check()
        value.update(chunk)
    return value.hexdigest()


def lines(raw, count):
    rows = []
    for line in raw.decode("utf-8").split("\n")[:-1] if raw else []:
        fields = line.split("\t")
        state_require(len(fields) == count)
        rows.append(fields)
    return rows


def value(text):
    return decode(text) if text else None


def condition(row, kind):
    return any(isinstance(c, dict) and c.get("type") == kind and c.get("status") == "True" for c in value(row[8]) or [])


def fact(ready, reason="missing"):
    return {"state":"ready" if ready else "not-ready", "reason":"observed" if ready else reason}


NOT_APPLICABLE = {"state":"unobserved", "reason":"not-applicable"}


def chart_projection(obj, annotation="helmcharts.cattle.io/managed-by", fixed="helm-controller",
                     finalizer="wrangler.cattle.io/on-helm-chart-remove"):
    """The closed projection; helm-controller adds exactly the two excluded entries."""
    metadata = obj.get("metadata", {})
    annotations = dict(metadata.get("annotations") or {})
    if fixed is None or annotations.get(annotation) == fixed:
        annotations.pop(annotation, None)
    return {"labels":metadata.get("labels") or {}, "annotations":annotations,
            "finalizers":[f for f in metadata.get("finalizers") or [] if f != finalizer],
            "owner_references":metadata.get("ownerReferences") or [], "deleting":"deletionTimestamp" in metadata,
            "spec":obj.get("spec")}


def affinity(names):
    return {"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[
        {"matchExpressions":[{"key":"kubernetes.io/hostname", "operator":"In", "values":names}]}]}}}


def tolerations(taints):
    """The tolerations as the API returns them: an empty value is omitted."""
    return [{"key":"CriticalAddonsOnly", "operator":"Exists"},
            {"key":"node-role.kubernetes.io/control-plane", "operator":"Exists", "effect":"NoSchedule"}] + \
        [dict({"key":k, "operator":"Equal", "effect":e}, **({"value":v} if v else {})) for k, v, e in taints]


def servicelb(names, taints):
    """The canonical ServiceLB manifest before ownership metadata."""
    def labels():
        return {"app":SERVICELB}
    containers = [{"name":f"lb-tcp-{p}", "image":LB_DIGESTED, "imagePullPolicy":"Never",
                   "ports":[{"name":f"lb-tcp-{p}", "containerPort":p, "hostPort":p, "protocol":"TCP"}],
                   "env":[{"name":k, "value":v} for k, v in (("SRC_PORT", str(p)), ("SRC_RANGES", "0.0.0.0/0"),
                          ("DEST_PROTO", "TCP"), ("DEST_PORT", str(p)), ("DEST_IPS", "$(TRAEFIK_SERVICE_HOST)"))],
                   "securityContext":{"capabilities":{"add":["NET_ADMIN"]}}} for p in (80, 443)]
    return {"apiVersion":"apps/v1", "kind":"DaemonSet",
            "metadata":{"name":SERVICELB, "namespace":"kube-system", "labels":labels()},
            "spec":{"selector":{"matchLabels":labels()}, "template":{"metadata":{"labels":labels()}, "spec":{
                "priorityClassName":"system-node-critical", "serviceAccountName":"default",
                "automountServiceAccountToken":False, "enableServiceLinks":True, "affinity":affinity(names),
                "tolerations":tolerations(taints), "containers":containers}}}}


# The ServiceLB workload's fixed projection: its metadata, exactly the
# rendered spec fields, then one line per container, then its status.
LB_POD = ("priorityClassName", "serviceAccountName", "automountServiceAccountToken", "enableServiceLinks",
          "affinity", "tolerations")
LB_CONTAINER = ("name", "image", "imagePullPolicy", "ports", "env", "securityContext")
LB_TEMPLATE = "{\"\\t\"}".join("{" + f + "}" for f in (
    ".metadata.uid", ".metadata.labels", ".metadata.annotations", ".metadata.finalizers", ".metadata.ownerReferences",
    ".metadata.deletionTimestamp", ".spec.selector", ".spec.template.metadata.labels",
    *(".spec.template.spec." + key for key in LB_POD), ".metadata.generation", ".status.observedGeneration",
    ".status.desiredNumberScheduled", ".status.numberReady")) + \
    "{range .spec.template.spec.containers[*]}{\"\\n\"}" + \
    "{\"\\t\"}".join("{." + key + "}" for key in LB_CONTAINER) + "{end}{\"\\n\"}"
# One line per non-terminal pod: its controller UID, then its TCP/UDP/SCTP
# host-port entries for 80 and 443 from containers and restartable init
# containers.
HELD = "{range .ports[?(@.hostPort==80)]}{.hostPort}/{.protocol} {end}" \
       "{range .ports[?(@.hostPort==443)]}{.hostPort}/{.protocol} {end}"
HOST_PORT_ROW = ("{range .metadata.ownerReferences[?(@.controller==true)]}{.uid}{end}{\"\\t\"}"
                 "{range .spec.initContainers[?(@.restartPolicy==\"Always\")]}" + HELD + "{end}"
                 "{range .spec.containers[*]}" + HELD + "{end}{\"\\n\"}")
HOST_PORTS = "{range .items[*]}" + HOST_PORT_ROW + "{end}"
LB_PODS = "{range .items[*]}{.metadata.ownerReferences}{\"\\t\"}{.spec.nodeName}{\"\\t\"}" \
          "{.spec.containers[*].image}{\"\\t\"}{.status.containerStatuses[*].imageID}{\"\\t\"}" \
          "{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}"


def lb_object(raw):
    """Rebuild the observed ServiceLB workload from its fixed projection, or None when absent."""
    rows = raw.decode("utf-8").split("\n")[:-1] if raw else []
    if not rows:
        return None
    fields, containers = rows[0].split("\t"), [row.split("\t") for row in rows[1:]]
    state_require(len(fields) == 18 and all(len(c) == 6 for c in containers))
    flags = {"true":True, "false":False}
    pod = {key:value(text) if key in ("affinity", "tolerations") else flags.get(text, text or None)
           for key, text in zip(LB_POD, fields[8:14])}
    pod["containers"] = [{key:value(text) if key in ("ports", "env", "securityContext") else text
                          for key, text in zip(LB_CONTAINER, c)} for c in containers]
    status = [int(text) if text else None for text in fields[14:]]
    return {"metadata":{"uid":fields[0], "labels":value(fields[1]), "annotations":value(fields[2]),
                        "finalizers":value(fields[3]), "ownerReferences":value(fields[4]),
                        **({"deletionTimestamp":fields[5]} if fields[5] else {})},
            "spec":{"selector":value(fields[6]), "template":{"metadata":{"labels":value(fields[7])}, "spec":pod}},
            "status":status}


def lb_projection(obj):
    """The same six keys; only the apps/v1 generation annotation is excluded."""
    return chart_projection(obj, "deprecated.daemonset.template.generation", None, None)


def controller(text):
    return next((r.get("uid") for r in value(text) or [] if isinstance(r, dict) and r.get("controller") is True), None)


def listeners(tables=(("/proc/net/tcp", 8), ("/proc/net/tcp6", 32))):
    """Stream both TCP tables; keep only whether a LISTEN entry holds port 80 or 443."""
    held = False
    for path, width in tables:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        except OSError:
            raise StateRefused("integrity")
        try:
            pending, header = b"", True
            while True:
                state_check()
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    raise StateRefused("integrity")
                *rows, pending = (pending + chunk).split(b"\n")
                if not chunk and pending:
                    rows, pending = [pending], b""
                for row in rows:
                    state_require(len(row) < 512)
                    if header:
                        header = False
                        continue
                    fields = row.split()
                    state_require(len(fields) > 3 and
                                  re.fullmatch(b"[0-9A-Fa-f]{%d}:[0-9A-Fa-f]{4}" % width, fields[1]) is not None and
                                  re.fullmatch(b"[0-9A-Fa-f]{2}", fields[3]) is not None)
                    held |= int(fields[3], 16) == 10 and int(fields[1][-4:], 16) in (80, 443)
                state_require(len(pending) < 512)
                if not chunk:
                    break
        finally:
            os.close(fd)
    return fact(not held, "collision")


def sysctl(name, root="/proc/sys/"):
    try:
        with open(root + name, "rb") as stream:
            raw = stream.read(65)
    except OSError:
        raise StateRefused("integrity")
    state_require(len(raw) <= 64 and re.fullmatch(b"[0-9]+\n", raw) is not None)
    return int(raw)


class IngressReceiver:
    def __init__(self, header):
        self.header = header
        self.binding = header["binding"]
        self.member = self.binding["recipient"]
        self.tag = header["action"]
        self.action = "lifecycle:ingress-" + self.tag
        self.recipe = header["recipe"]
        self.payload = {"recipe":self.recipe, "original_recipe_sha256":header.get("original_recipe_sha256"),
                        "object_ordinal":header["object_ordinal"], "resource":header["resource"],
                        "preflight":header["preflight"]}
        self.root = self.lock = self.executable = None
        self.root_id = self.lock_id = None
        self.claim = self.reservation = self.intent = self.published = None
        self.effect_started = False
        self.owner_path = ROOT + "/owners/" + self.binding["owner"]
        # A derived current recipe's annotations compare with the original's hash.
        self.recipe_hash = self.payload["original_recipe_sha256"] or state_hash("broil-k3s-ingress-recipe-v1", self.recipe)

    def profile(self):
        state_require(os.geteuid() == 0 and
                      os.environ.get("BROIL_MACHINE") == self.member["machine"] and
                      os.environ.get("BROIL_ENV") == self.binding["scope"]["environment"], "ownership")
        raw = read_file(PROFILE, 16384, private=False)
        profile = decode(raw)
        bodies = profile.get("bodies")
        state_require(isinstance(bodies, dict) and
                      set(bodies) == {"control", "lifecycle", "network", "ingress", "cert_manager", "registry", "node", "delivery", "release", "service_guard"} and
                      hashlib.sha256(raw).hexdigest() == self.binding["fingerprints"]["profile_sha256"] and
                      profile["script_sha256"] == self.binding["fingerprints"]["script_sha256"] == bodies["control"] and
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == bodies["ingress"] and
                      profile.get("ingress_templates") == {"traefik":TEMPLATE_HASH} and
                      profile.get("ingress_images") == {"traefik":IMAGE, "klipper_lb":KLIPPER} and
                      profile.get("ingress_charts") == CHARTS, "ownership")
        tools = self.binding["fingerprints"]["tools"]
        state_require(len(tools) == 2 and tools[0]["name"] == "bootstrap-index" and
                      tools[1] == {"name":"k3s", "sha256":profile["k3s_sha256"]}, "capability")
        ingress_recipe(self.recipe, self.binding, profile)
        members = self.recipe["members"]
        ingress = {e["machine"] for e in self.recipe["ingress_members"]}
        state_require(self.member == members[0] if self.tag in ("inspect-objects", "create-object") else
                      self.member["machine"] in ingress if self.tag == "import-image" else
                      self.member["role"] == "server" or self.member["machine"] in ingress, "ownership")
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
        exclusive = self.tag in ("import-image", "create-object")
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

    def kubectl(self, *args, input=None, limit=MAXIMUM, bound=False):
        return kubectl(self.executable, self.binding["owner"], *args, input=input, output_limit=limit, bound=bound)

    def runtime(self, *args, mutating=False, source=None, seconds=20):
        return command(self.executable, list(args), limits=(MAXIMUM, 65536), mutating=mutating, source=source,
                       seconds=seconds)

    # ---- Host facts: generation, images and runtime, listeners and forwarding, charts ----
    def charts(self):
        ready = True
        for key, name in CHART_FILES.items():
            try:
                parent, _ = directory(CHART_DIR)
                try:
                    fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
                finally:
                    os.close(parent)
                try:
                    st = os.fstat(fd)
                    ready &= (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and
                              not st.st_mode & 0o022 and digest(fd) == CHARTS[key])
                finally:
                    os.close(fd)
            except (FileNotFoundError, Refused):
                ready = False
        return fact(ready)

    def generation(self):
        """Check the bound generation as a whole; return the held `traefik.tar`."""
        entry = next(e for e in self.recipe["ingress_members"] if e["machine"] == self.member["machine"])
        machine, owner, path = self.member["machine"], self.binding["owner"], f"{self.owner_path}/assets/{entry['generation']}"
        resource = {"kind":"bootstrap-assets", "id":machine, "owner":owner, "generation":entry["generation"],
                    "machine":machine, "path":path + "/", "namespace":None, "name":None, "uid":None}
        gfd, archive = state_directory(path), None
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
                                  digest(fd) == asset["sha256"] and (asset["id"] == "traefik") == (name == "traefik.tar"),
                                  "readiness")
                    seen.add(asset["id"])
                    if name == "traefik.tar":
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
                          manifests[0].get("digest") == "sha256:" + IMAGE and
                          manifests[0].get("annotations") == {"io.containerd.image.name":NAMED}, "readiness")
            return resource, here, archive
        except BaseException:
            if archive is not None:
                os.close(archive)
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

    def image(self):
        """The image fact and the ServiceLB `lb_image` fact."""
        records = self.records()
        listed = decode(self.runtime("crictl", "images", "-o", "json"))
        images = listed.get("images") if isinstance(listed, dict) else None
        state_require(isinstance(images, list), "integrity")
        def pinned(name):
            return any(isinstance(item, dict) and name in (item.get("repoDigests") or []) and
                       item.get("pinned") is True for item in images)
        return (fact(records.get(NAMED) and records.get(DIGESTED) and pinned(DIGESTED)),
                fact(LB_DIGESTED in records and pinned(LB_DIGESTED), "absent"))

    def host(self):
        self.owned()
        server = self.member["role"] == "server"
        ingress = self.member["machine"] in {e["machine"] for e in self.recipe["ingress_members"]}
        facts = {"member":self.member, "charts":self.charts() if server else NOT_APPLICABLE,
                 **{key:NOT_APPLICABLE for key in ("generation", "image", "runtime", "listeners", "forwarding",
                                                    "lb_image")}}
        if ingress:
            try:
                _, _, archive = self.generation()
                os.close(archive)
                facts["generation"] = fact(True)
            except StateRefused as error:
                if error.failure != "readiness":
                    raise
                facts["generation"] = fact(False)
            try:
                facts["image"], facts["lb_image"] = self.image()
                facts["runtime"] = fact(True)
            except Refused:
                facts["image"], facts["runtime"] = fact(False, "unobservable"), fact(False)
                facts["lb_image"] = fact(False, "unobservable")
            # Host sockets and inherited forwarding.
            facts["listeners"] = listeners()
            facts["forwarding"] = fact(sysctl("net/ipv4/conf/all/forwarding") == 1 and
                                       sysctl("net/core/devconf_inherit_init_net") != 2)
        state_require(len(canonical(facts)) <= 4096, "bound")
        return facts

    def import_image(self, result):
        """Import from the held descriptor only when absent, tag, label, verify."""
        self.active()
        resource, directory_id, archive = self.generation()
        try:
            state_require(self.header["resource"] == resource, "ownership")
            self.image()
            previous = self.begin()
            if previous is not None:
                result["terminal"] = previous
                return
            self.revalidate()
            self.effect_started = True
            if NAMED not in self.records():
                os.lseek(archive, 0, os.SEEK_SET)
                self.runtime("ctr", "-n", "k8s.io", "images", "import", "-", mutating=True, source=archive,
                             seconds=600)
            if DIGESTED not in self.records():
                self.runtime("ctr", "-n", "k8s.io", "images", "tag", NAMED, DIGESTED, mutating=True)
            for name in (NAMED, DIGESTED):
                self.runtime("ctr", "-n", "k8s.io", "images", "label", name, PIN, mutating=True)
            state_require(self.image()[0]["state"] == "ready", "readiness")
            result["terminal"] = self.terminal("succeeded", None, resource, directory_id)
        finally:
            os.close(archive)
        result["hosts"] = self.host()

    # ---- Objects: the three ingress objects and the 51 results ----
    def nodes(self):
        template_text = "{range .items[*]}{.metadata.name}{\"\\t\"}{.metadata.uid}{\"\\t\"}{.spec.unschedulable}" \
                        "{\"\\t\"}{.spec.taints}{\"\\n\"}{end}"
        rows = lines(self.kubectl("get", "nodes", "-o", "jsonpath=" + template_text, limit=524288), 4)
        found = {name:(uid, cordon == "true", value(taints) or []) for name, uid, cordon, taints in rows}
        state_require(len(found) == len(rows) <= 1024, "bound")
        for member in self.recipe["members"]:
            node = found.get(member["member"])
            state_require(node is not None, "readiness")
            state_require(node[0] == member["node_uid"], "ownership")
        return found

    def expected(self, nodes):
        taints = set()
        for member in self.recipe["members"]:
            if member["machine"] in {e["machine"] for e in self.recipe["ingress_members"]}:
                for taint in nodes[member["member"]][2]:
                    state_require(isinstance(taint, dict) and isinstance(taint.get("key"), str), "integrity")
                    if not taint["key"].startswith("node.kubernetes.io/"):
                        taints.add((taint["key"], taint.get("value", ""), taint.get("effect")))
        taints = sorted(taints, key=lambda t: tuple(str(x).encode() for x in t))
        raw, names = render(self.recipe, taints)
        chunks = raw.split(b"\n---\n")
        state_require(len(chunks) == 2, "ownership")
        rendered = []
        for chart, chunk in zip(CHART_NAMES, chunks):
            obj = decode(self.kubectl("create", "--dry-run=client", "--validate=false", "-f", "-", "-o", "json",
                                      input=chunk, limit=16384))
            metadata = obj.get("metadata")
            state_require(isinstance(metadata, dict) and obj.get("kind") == "HelmChart" and
                          obj.get("apiVersion") == "helm.cattle.io/v1" and metadata.get("name") == chart and
                          metadata.get("namespace") == "kube-system", "ownership")
            state_require(metadata.pop("creationTimestamp", None) is None and not obj.get("status") and
                          "labels" not in metadata and "annotations" not in metadata and
                          "driver" not in obj["spec"], "ownership")
            obj.pop("status", None)
            # The pinned HelmChart CRD defaults this field on creation.
            obj["spec"]["driver"] = "secret"
            self.own(metadata, self.recipe["render_sha256"])
            state_require(len(canonical(obj)) <= 16384, "bound")
            rendered.append(obj)
        workload = servicelb(names, taints)
        state_require(hashlib.sha256(canonical(workload)).hexdigest() == self.recipe["servicelb_sha256"], "ownership")
        self.own(workload["metadata"], self.recipe["servicelb_sha256"])
        return rendered + [workload], names, taints

    def own(self, metadata, render):
        """The ownership labels and annotations, beside any rendered label."""
        metadata["labels"] = dict(metadata.get("labels") or {}, **{"broil.dev/managed-by":"broil",
                                                                   "broil.dev/component":"ingress"})
        metadata["annotations"] = {
            "broil.dev/owner":self.recipe["owner"], "broil.dev/creation-operation":self.recipe["operation"],
            "broil.dev/cluster-uid":self.recipe["cluster"]["uid"], "broil.dev/recipe-sha256":self.recipe_hash,
            "broil.dev/profile-sha256":self.recipe["profile_sha256"], "broil.dev/render-sha256":render}

    def charts_observed(self):
        raw = self.kubectl("get", "helmchart.helm.cattle.io", *CHART_NAMES, "--namespace", "kube-system",
                           "--ignore-not-found", "-o", "json", limit=131072)
        items = decode(raw).get("items", []) if raw.strip() else []
        state_require(isinstance(items, list) and len(items) <= 2, "ownership")
        found = {}
        for item in items:
            state_require(isinstance(item, dict) and item.get("kind") == "HelmChart", "ownership")
            name = item.get("metadata", {}).get("name")
            state_require(name in CHART_NAMES and name not in found, "ownership")
            found[name] = item
        return found

    def receipts(self):
        records = {}
        for _, intent, terminal in self.ledger():
            if intent["action"] != "lifecycle:ingress-create-object" or terminal is None or \
               terminal["outcome"] != "succeeded":
                continue
            resource = terminal["resource"]
            state_require(isinstance(resource, dict), "ownership")
            key = resource.get("id")
            state_require(key not in records and opaque(terminal["resource_identity"]) and
                          intent["binding"]["owner"] == self.recipe["owner"] and
                          intent["binding"]["scope"] == self.recipe["scope"] and
                          intent["binding"]["operation"] == self.recipe["operation"], "ownership")
            records[key] = terminal["resource_identity"]
        return records

    def observed(self):
        names = [f"{RESOURCES[kind]}/{name}" for kind, _, name, _ in RESULTS]
        template_text = "{range .items[*]}" + "{\"\\t\"}".join("{" + field + "}" for field in FIELDS) + \
            "{\"\\n\"}{end}"
        rows = lines(self.kubectl("get", "--namespace", "kube-system", *names, "--ignore-not-found",
                                  "-o", "jsonpath=" + template_text), len(FIELDS))
        found = {}
        for row in rows:
            key = (row[0], row[1] or None, row[2])
            state_require(key not in found and opaque(row[3]), "ownership")
            found[key] = row
        listing = "{range .items[*]}{.metadata.name}{\"\\t\"}{.metadata.uid}{\"\\t\"}{.metadata.labels}{\"\\n\"}{end}"
        releases = {chart:[] for chart in CHART_NAMES}
        for name, uid, labels in lines(self.kubectl("get", "secret", "--namespace", "kube-system", "-l",
                                                    "owner=helm,name in (traefik-crd,traefik)",
                                                    "-o", "jsonpath=" + listing, limit=65536), 3):
            chart = (value(labels) or {}).get("name")
            state_require(chart in releases and len(releases[chart]) < 64, "ownership")
            releases[chart].append((name, uid))
        return found, releases

    def classify(self, expected, names, taints):
        receipts = self.receipts()
        charts = self.charts_observed()
        found, releases = self.observed()
        objects, owners = [], []
        for ordinal, (chart, obj) in enumerate(zip(CHART_NAMES, expected), 1):
            record = {"kind":"HelmChart", "namespace":"kube-system", "name":chart, "uid":None, "class":"absent",
                      "spec_sha256":None, "available":"unobserved"}
            actual = charts.get(chart)
            owner = None
            if actual is not None:
                uid = actual["metadata"].get("uid")
                state_require(opaque(uid), "ownership")
                projection = chart_projection(actual)
                record["uid"] = uid
                record["spec_sha256"] = state_hash("broil-k3s-ingress-object-v1", projection)
                if receipts.get(f"ingress-object-{ordinal:02d}") == uid:
                    owner = (uid, actual.get("status", {}).get("jobName"))
                    record["class"] = "owned-ready" if projection == chart_projection(obj) else "owned-drifted"
                else:
                    record["class"] = "foreign"
            objects.append(record)
            owners.append(owner)
        results = []
        for position, (kind, namespace, name, index) in enumerate(RESULTS, 1):
            chart = CHART_NAMES[index]
            row = found.get((kind, namespace, name))
            record = {"uid":None, "class":"absent", "available":"unobserved"}
            if row is not None:
                record["uid"] = row[3]
                owned, drifted, ready = self.attribute(position, row, chart, owners[index], results, found, names, taints)
                record["class"] = "foreign" if not owned else "owned-drifted" if drifted else "owned-ready"
                if owned:
                    record["available"] = "ready" if ready else "not-ready"
            if position in (11, 12) and any(entry[0] != name for entry in releases[chart]):
                owned = record["class"] in ("owned-ready", "owned-drifted")
                record["class"] = "owned-drifted" if owned else "foreign"
                record["available"] = record["available"] if owned else "unobserved"
            state_require(len(canonical(record)) <= 128, "bound")
            results.append(record)
        for ordinal, record in enumerate(objects):
            if record["class"] in ("owned-ready", "owned-drifted"):
                complete = results[ordinal * 5]["class"] == "owned-ready" and results[ordinal * 5]["available"] == "ready"
                deployed = results[10 + ordinal]["class"] == "owned-ready" and results[10 + ordinal]["available"] == "ready"
                record["available"] = "ready" if complete and deployed else "not-ready"
        # The ServiceLB workload, owned under the chart objects' rule.
        record = {"kind":"DaemonSet", "namespace":"kube-system", "name":SERVICELB, "uid":None, "class":"absent",
                  "spec_sha256":None, "available":"unobserved"}
        workload = self.workload()
        if workload is not None:
            uid, projection = workload["metadata"]["uid"], lb_projection(workload)
            generation, observed, desired, ready = workload["status"]
            state_require(opaque(uid), "ownership")
            record.update(uid=uid, spec_sha256=state_hash("broil-k3s-ingress-object-v1", projection),
                          available="ready" if observed == generation and desired == ready == len(names) else "not-ready",
                          **{"class":"foreign" if receipts.get("ingress-object-03") != uid else
                             "owned-ready" if projection == lb_projection(expected[2]) else "owned-drifted"})
        objects.append(record)
        for record in objects:
            state_require(len(canonical(record)) <= 1024, "bound")
        return objects, results

    def workload(self):
        return lb_object(self.kubectl("get", "daemonset.apps/" + SERVICELB, "--namespace", "kube-system",
                                      "--ignore-not-found", "-o", "jsonpath=" + LB_TEMPLATE, limit=65536))

    def observe(self, ordinal):
        return self.workload() if ordinal == 3 else self.charts_observed().get(CHART_NAMES[ordinal - 1])

    def attribute(self, position, row, chart, owner, results, found, names, taints):
        """The chain from an owned chart object; returns (attributed, drifted, ready)."""
        if owner is None:
            return False, False, False
        labels, annotations = value(row[4]) or {}, value(row[5]) or {}
        references = value(row[6]) or []
        kind = row[0]
        if position <= 10:
            identity_values = ("helm-controller-chart-registration", "helm.cattle.io/v1, Kind=HelmChart", chart, "kube-system")
            keys = ("id", "owner-gvk", "owner-name", "owner-namespace")
            ok = all(annotations.get(OBJECTSET + k) == v for k, v in zip(keys, identity_values)) and \
                labels.get(OBJECTSET + "hash") == hashlib.sha1("".join(identity_values).encode()).hexdigest()
            if kind == "ClusterRoleBinding":
                ok &= value(row[9]) == {"apiGroup":"rbac.authorization.k8s.io", "kind":"ClusterRole",
                                        "name":"cluster-admin"} and \
                      value(row[10]) == [{"kind":"ServiceAccount", "name":"helm-" + chart, "namespace":"kube-system"}]
            else:
                ok &= len(references) == 1 and isinstance(references[0], dict) and \
                      {k:references[0].get(k) for k in ("apiVersion", "kind", "name", "uid")} == \
                      {"apiVersion":"helm.cattle.io/v1", "kind":"HelmChart", "name":chart, "uid":owner[0]}
            if kind == "Job":
                ok &= owner[1] in (None, row[2])
                return ok, False, condition(row, "Complete")
            return ok, False, True
        if position <= 12:
            job = found.get(("Job", "kube-system", "helm-install-" + chart))
            config = (value(job[7]) or {}).get("helmcharts.helm.cattle.io/configHash") if job else None
            ok = results[(position - 11) * 5]["class"] == "owned-ready" and isinstance(config, str) and \
                config.startswith("SHA256=") and len(config) == 71 and \
                {k:labels.get(k) for k in ("owner", "name", "version")} == {"owner":"helm", "name":chart, "version":"1"} and \
                labels.get("helmcharts.helm.cattle.io/configHash") == config[7:70]
            status = labels.get("status")
            return ok, status not in ("pending-install", "failed", "deployed"), status == "deployed"
        ok = annotations.get("meta.helm.sh/release-name") == chart and \
            annotations.get("meta.helm.sh/release-namespace") == "kube-system" and \
            labels.get("app.kubernetes.io/managed-by") == "Helm" and \
            results[10 + CHART_NAMES.index(chart)]["class"] in ("owned-ready", "owned-drifted")
        if kind == "DaemonSet":
            drifted = value(row[11]) != affinity(names) or value(row[12]) != tolerations(taints) or \
                row[13] != DIGESTED or value(row[14]) != ARGS
            desired = int(row[15] or 0)
            return ok, drifted, desired > 0 and int(row[16] or 0) == desired
        if kind == "Service":
            return ok, row[17] != "ClusterIP" or value(row[18]) != PORTS, True
        if kind == "IngressClass":
            return ok, row[19] != "traefik.io/ingress-controller" or \
                annotations.get("ingressclass.kubernetes.io/is-default-class") != "false", True
        if kind == "CustomResourceDefinition":
            return ok, False, condition(row, "Established")
        return ok, False, True

    def placement(self, results, names):
        daemonset = results[48]
        if daemonset["class"] != "owned-ready":
            return fact(False, "absent")
        listing = "{range .items[*]}{.metadata.ownerReferences}{\"\\t\"}{.spec.nodeName}{\"\\t\"}" \
                  "{.spec.containers[*].image}{\"\\t\"}{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}"
        rows = lines(self.kubectl("get", "pods", "--namespace", "kube-system", "-l", "app.kubernetes.io/name=traefik",
                                  "-o", "jsonpath=" + listing, limit=262144), 4)
        placed = []
        for references, node, image, ready in rows:
            if any(isinstance(r, dict) and r.get("uid") == daemonset["uid"] for r in value(references) or []):
                placed.append((node, image == DIGESTED and ready == "True"))
        return fact(sorted(placed) == sorted((name, True) for name in names), "placement")

    def selected(self, owned, ready, names):
        """The pods and controller revisions that the workload's selector matches, with no phase filter;
        returns the `servicelb` placement and `selector` facts."""
        pods = lines(self.kubectl("get", "pods", "--namespace", "kube-system", "-l", "app=" + SERVICELB,
                                  "-o", "jsonpath=" + LB_PODS, limit=262144), 5)
        revisions = lines(self.kubectl("get", "controllerrevisions.apps", "--namespace", "kube-system", "-l",
                                       "app=" + SERVICELB, "-o",
                                       "jsonpath={range .items[*]}{.metadata.ownerReferences}{\"\\n\"}{end}",
                                       limit=262144), 1)
        placed = sorted((node, images.split() == ids.split() == [LB_DIGESTED] * 2 and state == "True")
                        for references, node, images, ids, state in pods if owned and controller(references) == owned)
        return (fact(ready and placed == sorted((name, True) for name in names), "placement"),
                fact(all(owned and controller(row[0]) == owned for row in pods + revisions), "collision"))

    def host_ports(self, positions, owned):
        """One field-selected read per ingress member, at most eight at once, results in `members` order."""
        def read(entry):
            return self.kubectl("get", "pods", "--all-namespaces", "--field-selector",
                                f"spec.nodeName={entry[1]},status.phase!=Succeeded,status.phase!=Failed",
                                "-o", "jsonpath=" + HOST_PORTS, limit=16384, bound=True)
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            replies = list(pool.map(read, positions))
        held = []
        for (position, _), raw in zip(positions, replies):
            rows = raw.split(b"\n")
            state_require(rows.pop() == b"")
            state_require(len(rows) <= 110 and all(len(row) < 128 for row in rows), "bound")
            foreign = False
            for row in rows:
                uid, tab, entries = row.partition(b"\t")
                ports = entries.split()
                state_require(len(ports) <= 10, "bound")
                state_require(tab and all(re.fullmatch(b"(80|443)/(TCP|UDP|SCTP)", p) for p in ports))
                foreign |= uid.decode("ascii") != owned and bool({b"80/TCP", b"443/TCP"} & set(ports))
            if foreign:
                held.append(position)
        return held

    def inspect(self, result):
        nodes = self.nodes()
        expected, names, taints = self.expected(nodes)
        objects, results = self.classify(expected, names, taints)
        api = self.kubectl("get", "service", "kubernetes", "--namespace", "default", "-o",
                           "jsonpath={.spec.clusterIP}:{.spec.ports[?(@.name==\"https\")].port}", limit=256)
        cordoned = [index for index, member in enumerate(self.recipe["members"], 1) if nodes[member["member"]][1]]
        positions = [(index, member["member"]) for index, member in enumerate(self.recipe["members"], 1)
                     if member["machine"] in {e["machine"] for e in self.recipe["ingress_members"]}]
        owned = objects[2]["uid"] if objects[2]["class"] in ("owned-ready", "owned-drifted") else None
        servicelb_fact, selector = self.selected(owned, objects[2]["class"] == "owned-ready", names)
        ingress = {"api":fact(api.decode("utf-8") == self.recipe["network"]["api"], "mismatch"),
                   "cordoned":cordoned, "host_ports":self.host_ports(positions, owned),
                   "placement":self.placement(results, names), "servicelb":servicelb_fact, "selector":selector,
                   "ingress_class":fact(results[48]["class"] == results[50]["class"] == "owned-ready", "absent")}
        ready = all(r["class"] == "owned-ready" and r["available"] == "ready" for r in objects + results) and \
            all(ingress[key]["state"] == "ready" for key in ("api", "placement", "servicelb", "selector",
                                                               "ingress_class")) and \
            not {index for index, _ in positions} & set(cordoned) and not ingress["host_ports"]
        result.update({"objects":objects, "results":results, "ingress":ingress,
                       "services":"unobserved" if ready else "not-ready"})
        return expected, objects, results

    def create(self, result):
        self.active()
        ordinal = self.header["object_ordinal"]
        state_uint(ordinal, 1, 3)
        resource = self.header["resource"]
        state_require(isinstance(resource, dict) and resource.get("generation") is not None, "ownership")
        state_hex(resource["generation"])
        state_require(resource == {"kind":"service", "id":f"ingress-object-{ordinal:02d}", "owner":self.recipe["owner"],
                                   "generation":resource["generation"], "machine":None, "path":None,
                                   "namespace":"kube-system", "name":(*CHART_NAMES, SERVICELB)[ordinal - 1],
                                   "uid":None} and
                      self.binding["operation"] == self.recipe["operation"], "ownership")
        expected, objects, results = self.inspect(result)
        preflight = self.header["preflight"]
        state_fields(preflight, "objects results")
        state_require(isinstance(preflight["objects"], list) and len(preflight["objects"]) == 3 and
                      isinstance(preflight["results"], list) and len(preflight["results"]) == 51, "ownership")
        for old, new in zip(preflight["objects"], objects):
            state_fields(old, "kind namespace name uid class spec_sha256 available")
            state_require(old == new or old["class"] == new["class"] == "owned-ready" and
                          all(old[k] == new[k] for k in ("kind", "namespace", "name", "uid", "spec_sha256")), "ownership")
        # The progress rule: helm-controller creates results asynchronously.
        for (_, _, _, index), old, new in zip(RESULTS, preflight["results"], results):
            state_fields(old, "uid class available")
            created = index + 1 < ordinal
            state_require(old == new or created and (old["class"] == "absent" and new["class"] == "owned-ready" or
                                                     old["class"] == new["class"] == "owned-ready" and
                                                     old["uid"] == new["uid"]), "ownership")
        state_require(objects[ordinal - 1]["class"] == "absent" and
                      all(item["class"] in ("absent", "owned-ready") for item in objects + results), "ownership")
        # Create 3 reobserves the host-port and selector admission facts.
        state_require(ordinal < 3 or not result["ingress"]["host_ports"] and
                      result["ingress"]["selector"]["state"] == "ready", "ownership")
        # The selected absent identity has a second read immediately before effect.
        state_require(self.observe(ordinal) is None, "ownership")
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        self.effect_started = True
        self.kubectl("create", "-f", "-", input=canonical(expected[ordinal - 1]) + b"\n", limit=4096)
        actual = self.observe(ordinal)
        project = lb_projection if ordinal == 3 else chart_projection
        state_require(actual is not None and opaque(actual["metadata"].get("uid")) and
                      project(actual) == project(expected[ordinal - 1]), "ownership")
        result["terminal"] = self.terminal("succeeded", None, resource, actual["metadata"]["uid"])
        self.inspect(result)


def ingress_request(raw, header):
    global DEADLINE
    state_require(17 + len(raw) + 20480 <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms recipe original_recipe_sha256 "
                 "object_ordinal resource preflight")
    state_require(header["protocol"] == "broil-k3s-ingress" and canonical(header) == raw, "integrity")
    state_require(type(header["version"]) is int and header["version"] == 1,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
    tag = header["action"]
    state_require(tag in ("inspect-host", "import-image", "inspect-objects", "create-object"), "capability")
    mutation = tag in ("import-image", "create-object")
    state_hex(header["request_id"])
    state_binding(header["binding"])
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation, "ownership")
    state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(header["recipe"])) <= 32768, "bound")
    state_require((header["object_ordinal"] is None and header["preflight"] is None) == (tag != "create-object") and
                  (header["resource"] is None) == (not mutation), "ownership")
    if header["original_recipe_sha256"] is not None:
        state_require(tag != "create-object", "ownership")
        state_hex(header["original_recipe_sha256"], 64)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    state_require(sys.stdin.buffer.read(1) == b"", "integrity")


def ingress_main(raw, header):
    receiver = None
    status = "unknown"
    result = {"terminal":None, "hosts":None, "objects":None, "results":None, "ingress":None, "services":None,
              "failure":None}
    prefix = b"BK3SING1\n" + struct.pack(">I", len(raw)) + raw
    try:
        ingress_request(raw, header)
        receiver = IngressReceiver(header)
        receiver.profile()
        receiver.open()
        receiver.owned()
        tag = header["action"]
        if tag == "inspect-host":
            result["hosts"] = receiver.host()
        elif tag == "import-image":
            receiver.import_image(result)
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
                result["terminal"] = receiver.terminal("failed", failure)
                status = "failed"
            except BaseException:
                status = "unknown"
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root, receiver.executable):
                if fd is not None:
                    os.close(fd)
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
    require(isinstance(header, dict) and header.get("protocol") == "broil-k3s-ingress", 4)
    ingress_main(raw, header)
    os._exit(0)
except Exception:
    os._exit(125)
