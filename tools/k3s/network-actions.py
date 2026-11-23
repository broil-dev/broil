#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, profile-bound K3s network, DNS and storage receiver."""
import base64
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
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tarfile
import threading
import time

ROOT = "/var/lib/broil/k3s"
PROFILE = ROOT + "/action-profile.json"
K3S = "/usr/local/libexec/broil-k3s"
MAXIMUM = 1048576
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
EFFECTS = False
DEADLINE = time.monotonic() + 7200
WRITERS_SETTLED = True
# The mutating tags of every protocol, which hold the host lock exclusively.
MUTATIONS = ("create-", "import-")

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


def command(fd, args, input=None, allowed=(0,), extra_fds=(), limits=(MAXIMUM, MAXIMUM), argv0=None, seconds=20,
            source=None, mutating=False):
    global WRITERS_SETTLED
    require(time.monotonic() < DEADLINE, 6)
    process = subprocess.Popen([argv0 or f"/proc/self/fd/{fd}", *args],
        executable=f"/proc/self/fd/{fd}", pass_fds=(fd, *extra_fds),
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
                        require(len(streams[stream]) + len(chunk) <= limit, 4)
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


def kubectl(fd, owner, *args, input=None, output_limit=MAXIMUM, timeout="10s", seconds=20):
    kubeconfig = f"{ROOT}/owners/{owner}/admin.yaml"
    read_file(kubeconfig, 65536)
    return command(fd, ["kubectl", "--kubeconfig", kubeconfig, "--request-timeout=" + timeout, *args], input,
                   limits=(output_limit, MAXIMUM), seconds=seconds)


def life_kubectl(fd, kubeconfig, *args):
    require(len(kubeconfig) <= 65536, 4)
    return command(fd, ["kubectl", "--kubeconfig=/dev/stdin", "--request-timeout=10s", *args],
                   kubeconfig, limits=(65536, 4096))


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
STATE_WORK = {"reserve-owner", "acquire-writer", "prepare-input", "admit-credential"}
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


def state_projection(members):
    return state_hash("broil-infra-participants-v1", [dict(m, node_uid=None) for m in members])


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


# Ordinals are part of the request and are never selected by the caller.
OBJECTS = (
    ("ServiceAccount", "kube-system", "coredns", "dns"),
    ("ClusterRole", None, "system:coredns", "dns"),
    ("ClusterRoleBinding", None, "system:coredns", "dns"),
    ("ConfigMap", "kube-system", "coredns", "dns"),
    ("Deployment", "kube-system", "coredns", "dns"),
    ("Service", "kube-system", "kube-dns", "dns"),
    ("ServiceAccount", "kube-system", "local-path-provisioner-service-account", "storage"),
    ("ClusterRole", None, "local-path-provisioner-role", "storage"),
    ("ClusterRoleBinding", None, "local-path-provisioner-bind", "storage"),
    ("Deployment", "kube-system", "local-path-provisioner", "storage"),
    ("StorageClass", None, "local-path", "storage"),
    ("ConfigMap", "kube-system", "local-path-config", "storage"),
)
TEMPLATE_HASHES = {
    "coredns": "f726a65f4fe05f646a34f09306645545d8d2e70d3c59c32592d97419ad3b8968",
    "local_storage": "205c88f49b770331799a7d52c73f380a31cea59a5087c9f58179d2265fe93009",
}
IMAGE_NAMES = {
    "coredns": "rancher/mirrored-coredns-coredns:1.14.6",
    "provisioner": "rancher/local-path-provisioner:v0.0.37",
    "helper": "rancher/mirrored-library-busybox:1.37.0",
}


def template(key, encoded):
    state_require(key in TEMPLATE_HASHES, "capability")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    raw = decoder.decompress(base64.b85decode(encoded), 8193)
    state_require(decoder.eof and not decoder.unused_data and len(raw) <= 8192 and
                  hashlib.sha256(raw).hexdigest() == TEMPLATE_HASHES[key], "ownership")
    return raw


def render_template(raw, replacements):
    rendered = raw.decode("utf-8")
    for old, new in replacements.items():
        state_require(rendered.count(old) == 1, "ownership")
        rendered = rendered.replace(old, new)
    state_require("%{" not in rendered and "%}" not in rendered, "ownership")
    return rendered.encode("utf-8")


def select_projection(expected, actual):
    """Compare every declared source field; ignore only server-added fields."""
    if isinstance(expected, dict):
        state_require(isinstance(actual, dict), "ownership")
        return {key:select_projection(value, actual.get(key)) for key, value in expected.items()}
    if isinstance(expected, list):
        state_require(isinstance(actual, list) and len(actual) == len(expected), "ownership")
        return [select_projection(value, item) for value, item in zip(expected, actual)]
    state_require(actual == expected, "ownership")
    return actual

# Complete source templates, each one xz stream in base85.
TEMPLATES = {
    'coredns': (
        '{Wp48S^xk9=GL@E0stWa761SMbT8$j;1qWTSX}@xoC#F9+fjo=h0CYtsYLt4SK=Ylxf;fVtl%l|L>?5$fU3rr0`Q#Qs`tMToNR9-'
        'nT9?+nY(=Z0)KblX;?g`njwi)Y9z?ms?rm<@BnHFCVNPcOv0%er<Oig>Tsl|0+rr_#zr(oaEo6{YU1>|vvAJrxbV2oYaEp*{IiUx'
        'Rr?K^&_t_wGQ$Tb3&1l{^sOSjTXPRuB_rwu=3zZWdQOX27wC=$FZ?cuAGSE7R%me|HS$%IX=zf>XR_%HrCE2m48A&`ka9CL<C5tA'
        '!HI#|WS4T|4zc)^wr_SEdwPJ>{%F<;`=QznTAD4V05+I-Veh>=SJ(9)xMf#qYI&cNxuGpTVDZv<E^kLA-g$K6DrwY~Jxj-8My)(='
        'Xp&t@)pue?flhipwJQG?hp+^2e9W}3cCbHW=G2EmLOFMN<j_&ojMCb5gDem8Bbw(hsm5&s6LRp-vA9BiG)_}G7@abS+bO!xf46m>'
        'L8uHUD1L-JS$IUascK)JcX;Y=fdyQKj@%-``k8X|YX1k0%n3e39?IV*!RrY6b94>g<iP0B;cMrm`dJLi-6crTU;RrqZAcv~Zxx7i'
        '?EW_!q9=RF40I7Do9tbXwnPX_9;EMpAn+WB(O&P8v@d=-@O#jnY)=*}1+)$*Ts$_qAGZNU`|};C^FhGsw2p}OE`tAT9`VSAj{s~v'
        'hA=^1D8?CXGY68X4&_2!#N&Tk2Bd=C0LhCWZ#Qy>lwn~P!Y^KUCqyv_20qh|9W8@2hUmiENC;pbJ-Eu96D0pg#3sbMh`$^}%33mw'
        'KSixiQCnd0$m=rx>USd-!q;#Ky$Fm_kvhBGmjn1(mg&af>q0ehGijg|m{G=l3B}HVJg3pjsw25;?ZvVQy%&@qq^Oa-Aeen>;0{nl'
        '5fICfOTH8`A&Ru$mNVb-D?wircSDR9Ivs`5a%m==ZILNK^foOlCyFCF1K3$*^C36S>K>8w>OsJdyX3pk4^YxEV3o=aTY%8}@53d8'
        'Mfs!~e{eb(i?+m@?8-Fs-@)m1`WNPx3SyxLN=+g(*oCYUbE?Cl6XKg|osX@$`)6auQ;wNx%EDBt>}4yJw$xqV>(Bg~sCBs}ycsAL'
        'zC&{h+fv(hCv~efZ&A_?8AYjNz`$yO;~k`*z$;c({RqlyxJ_-8dw~+#UvCn@q~F0=h3ZC_DhHMyc+(~2<;xL|NGH{8qV?2kl!{k8'
        '*BLqZ$A4gdaJOOwO}Mnsa-Uo}i`u4lHz7dB)YF6!{ExVdXMK>F;803`^v5u6=*xwn%KT!DvbLSC0<prQM%R4u-M8;tju3YGVYq8Z'
        '^9Eu0Fo>5CvjUwqZPKu_#^;NfP<S6p*q0}7ry+c+lRXDu0bO?_(x`E9MIcY;*l`<Z>D{#GObn-qawh9q8l64}-dxcyn^PSSOcNv9'
        '-w0l`s`;~UBWP(Em9bJ{Qc*h};8gh#{yo~#$i>yA{}S^BCEzMd&??i;9S}LV5hOR1GYsk5S^bQ^V4MKDmDO)q{MIjx0d0r#VHfye'
        'k33!zy^n8^pTKX(Aa!HSE88$A0x>mq$&qZjX60IhTH8E3B!5E3%&bArwSH`OD%}ny;>%fXtahh=!K__KIh_2o_SdcMGqoXhu?Y~*'
        '+D$J!n>7EX-$$#@S0d$v<#J?c(eu%X2&8luqpgkFBNyx9%|~2Zv)zM__qtJu{we88F3PCgris=4g80k)(x{-B=m5_pL}LP}lC~Cd'
        'j7f_gTBFvh`>ubXO|om&zOa~OU+JM#_2@IQ8{D>4gu`DsbJdc!Z`7$9$Ek2*^$2qmKjk39ACfOZ(2EmD{I2ZhZQsCN+}R2f71=Yv'
        'p*-7)_}YV)R7$X$vtM*V3Tu^GMdA{kU#}kdPXl@U2soaLx`F;3Hm4CLc)8|)ve?0At*n9jzPxZo20|HfAYwC-I+|S|sY;2$aTKu9'
        'm4{tEKuDWD!889&Q$v=J)^7a11xwxW?_!!GM35|V7z&QfcYHXDJTZisQE3A;W}zta-lkWhNt6IR%Buc|?_FZV2|-Flxj~R}GvHW%'
        'CJxc>JIz8h&~2<60gs4NTZ8++F?^T>936FD@Y!Es=I@x_qCI6{wyK5JFANV{xfes-W1_?WYSW8WHlC{200Hz2_$UAX!%HgtvBYQl'
        '0ssI200dcD'
    ),
    'local_storage': (
        '{Wp48S^xk9=GL@E0stWa761SMbT8$j;0)UYg<SwJoC#F9+fjo=h0CYtsYLt4SK=Ylxf;fVtl%l|L>?5$fU3rr0`Q#Qs`tMToNR9-'
        'nT9?+nUYr3z1&UduI*I^)L8AKD(~2Ui>mgFE3p1AU3$6D>_%d3yg_0G$96m`LQyN(+Edht_3j6VWiEpyaJylu#F!TbaE~Uq%>bh?'
        '{@Et-kTTNKEJx7yg60hv^k+cVd+>^l&fUaO-5wu)wfA`U8OJX<W3CBEZ6UAXYvZ<_{N+n47$H3zqssS%qJB)-sG9USi!crkEnUm$'
        'cd8Od)lS@zQqsyUk}1P{Qn1P5`f3(eSS3-^7t+hK1)ugWpw_2nkiW&D$e1g>uGRNu$$}e|s`JlIMEXK3Jg1uHl8gGs3x%;OCFy*2'
        'L(?$S>?6@^QambzUaepJ(r5TD5AfZ&#Dh-0JAF+CO2&RqGNI4jVQSC0+}9_~%0old7SswOWo%L1_@AP1a*q|N3Q5#w+;^B9B3e$C'
        '%N+zaFX~h6t~YH^Wgk>gwS14;?b2asU|uf|hk9ks$q0+|R?FG%Nh2`8NrIT{dh5ViUlA^#<}gXiImGABWi9TNX4Og`mGRw-h9S$8'
        '6AjO0rcM?LAD&pj1}~Th0>~F0i$gNyEnSInz)5F2!<7ATs~7l)*^mXm5jYsv1<BuAGd35leteZw%}Z)ax#zv1LWV&KNf$n|-aSC`'
        '&8m)oaJE`PIw)$U+btYSyfHyNpr*Hh8!}rfo|z>3ad>QcE>)iJOF^brpx%#z)_dFM(vX6#w*Bp?`&^cmJu1G0OBbI}2{Y{n4ME+='
        'GBN(ObD}R?BN~^@7ZKv-3GagmPGLx0i3>1*#KVf3w6C+Jq$ISHq9o7xn1W6Ha1=-+a!U8;&Q&B&c2T#0!^m1_IGf?_)q^4E$mM*V'
        'eYQv>2$i}JU#}AKnt!tS$Lq20ZGNKMhuj`hi*}kh$ez-kW9RjF8E0IgwLQ8$+T}_r%!ORJKxE*Yr{Zuo-Oh&JJxAIJ;jd89lWd16'
        ';*mLeg+D91T_4Oc(@M`Z<h_)DW}Pe7bXC?xwZSR!wD~pOt|$&hD7Ye2B#rzacnr_<2?NP?U;P9e(iK$xdML8GxpEfl+_rh(?Ku8='
        'F4C9u_&{)<mVl8LK^m6sP0q_x!UtBZ49y!8wlTmgc>8~M2+OYR!KFrF??3TNl&y_`a$m1zu1}nbu(9fS9;A3@`)pa%)abd6$9fab'
        'lH!9Lu#|34?NcUxXcdWQE8lA_xG@D!|C(HPA<CnMmys3zX{AZsi2S=XF)sWoa&qUWsquDCu%0MOLs0ho@I|ph#0lj&M0)&2Q9rjp'
        '3DuM(iTqqgzoOA=wN@?QLF|X#V%4B)8yWrjEcqfN&u@~I6t(c!P-GM55;<92D4F?5B*4e9I*YaOo&QM>>L;C|`VU_7kC*TnvW<D_'
        '7C>#+HX%eJ(U6sryNQs&@7pJv#!IBPI(}EUiptZ0P!qood5p`czs(t%kUK&>+k>8NCmO0D_i5)A>{;U=lIFp(00000Qr#fFKtl&0'
        '00E&1+!+7>IqGm@vBYQl0ssI200dcD'
    ),
}

IMAGE_DIGESTS = {
    "coredns": "1ba6f47265602e2e50a9c4669e3a955e4298a0d30dc82f39293d4bf1a851e0ff",
    "provisioner": "c3f2c60ee2490eb83ac00101d7e239fd8c20a5b8b4038e2dfc36a7e66fe99c08",
    "helper": "ad9fa4d07136a83e69a54ef00102f579d04eba431932de3b0f098cc5d5948f9f",
}


def network_recipe(recipe, binding, profile):
    state_fields(recipe, "scope owner operation cluster members first_server version network profile_sha256 "
                         "coredns_template_sha256 local_storage_template_sha256 coredns_render_sha256 local_storage_render_sha256")
    state_require(recipe["scope"] == binding["scope"] and recipe["owner"] == binding["owner"] and
                  recipe["profile_sha256"] == binding["fingerprints"]["profile_sha256"] and
                  recipe["version"] == profile["k3s_version"], "ownership")
    state_cluster(recipe["cluster"])
    state_require(recipe["cluster"] is not None and isinstance(recipe["members"], list) and
                  1 <= len(recipe["members"]) <= 128 and recipe["first_server"] == recipe["members"][0], "ownership")
    for member in recipe["members"]:
        state_member(member)
        state_require(member["role"] in ("server", "agent") and member["node_uid"] is not None, "ownership")
    state_require(len({m["machine"] for m in recipe["members"]}) == len(recipe["members"]) and
                  len({m["member"] for m in recipe["members"]}) == len(recipe["members"]), "ownership")
    state_require(recipe["first_server"]["role"] == "server" and
                  binding["recipient"] in recipe["members"], "ownership")
    state_require(isinstance(recipe["operation"], str) and recipe["operation"].startswith("infra-operation-"), "ownership")
    state_hex(recipe["operation"][16:])
    state_fields(recipe["network"], "pod_cidr service_cidr cluster_dns cluster_domain flannel")
    network = recipe["network"]
    try:
        pod = ipaddress.IPv4Network(network["pod_cidr"], strict=True)
        services = ipaddress.IPv4Network(network["service_cidr"], strict=True)
        dns = ipaddress.IPv4Address(network["cluster_dns"])
    except (ValueError, TypeError):
        raise StateRefused("integrity")
    state_require(str(pod) == network["pod_cidr"] and str(services) == network["service_cidr"] and
                  str(dns) == network["cluster_dns"] and dns in services and
                  not pod.overlaps(services) and network["flannel"] == "vxlan" and
                  isinstance(network["cluster_domain"], str) and
                  re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", network["cluster_domain"]), "ownership")
    state_require(profile.get("network_templates") == TEMPLATE_HASHES and
                  profile.get("network_images") == IMAGE_DIGESTS, "ownership")
    for key in TEMPLATE_HASHES:
        state_require(recipe[key + "_template_sha256"] == TEMPLATE_HASHES[key], "ownership")
    for key in ("coredns_render_sha256", "local_storage_render_sha256"):
        state_hex(recipe[key], 64)


def render_manifest(recipe, profile):
    network = recipe["network"]
    references = {key:"docker.io/" + IMAGE_NAMES[key].split(":", 1)[0] + "@sha256:" + IMAGE_DIGESTS[key]
                  for key in IMAGE_DIGESTS}
    coredns = render_template(template("coredns", TEMPLATES["coredns"]), {
        "data:\n  Corefile: |": "data:\n  NodeHosts: \"\"\n  Corefile: |",
        "%{CLUSTER_DOMAIN}%": network["cluster_domain"],
        "%{CLUSTER_DNS}%": network["cluster_dns"],
        "%{CLUSTER_DNS_LIST}%": "[" + network["cluster_dns"] + "]",
        "%{CLUSTER_DNS_IPFAMILYPOLICY}%": "SingleStack",
        "%{SYSTEM_DEFAULT_REGISTRY}%" + IMAGE_NAMES["coredns"]: references["coredns"],
    })
    local = render_template(template("local_storage", TEMPLATES["local_storage"]), {
        "%{SYSTEM_DEFAULT_REGISTRY}%" + IMAGE_NAMES["provisioner"]: references["provisioner"],
        "%{SYSTEM_DEFAULT_REGISTRY}%" + IMAGE_NAMES["helper"]: references["helper"],
        "%{DEFAULT_LOCAL_STORAGE_PATH}%": "/var/lib/rancher/k3s/storage",
    })
    state_require(hashlib.sha256(coredns).hexdigest() == recipe["coredns_render_sha256"] and
                  hashlib.sha256(local).hexdigest() == recipe["local_storage_render_sha256"], "ownership")
    return coredns, local


def fixed_resource(recipe, ordinal, generation):
    kind, namespace, name, family = OBJECTS[ordinal - 1]
    return {"kind":"service" if family == "dns" else "storage", "id":f"network-object-{ordinal:02d}",
            "owner":recipe["owner"], "generation":generation, "machine":None, "path":None,
            "namespace":namespace, "name":name, "uid":None}


class NetworkReceiver:
    FAMILY, KEYS, RECIPE = "network", ("recipe", "original_recipe_sha256", "object_ordinal", "resource", "preflight"), 1

    def __init__(self, header):
        self.header = header
        self.binding = header["binding"]
        self.tag = header["action"]
        self.action = "lifecycle:%s-%s" % (self.FAMILY, self.tag)
        self.recipe = header["recipe"]
        self.payload = {key:header[key] for key in self.KEYS}
        self.root = self.lock = self.executable = None
        self.root_id = self.lock_id = None
        self.claim = self.reservation = self.intent = None
        self.effect_started = False
        self.owner_path = ROOT + "/owners/" + self.binding["owner"]
        # A derived current recipe's annotations compare with the original's hash.
        self.recipe_hash = header.get("original_recipe_sha256") or \
            state_hash("broil-k3s-%s-recipe-v%d" % (self.FAMILY, self.RECIPE), self.recipe)

    def check(self, profile):
        network_recipe(self.recipe, self.binding, profile)

    def profile(self):
        state_require(os.geteuid() == 0 and
                      os.environ.get("BROIL_MACHINE") == self.binding["recipient"]["machine"] and
                      os.environ.get("BROIL_ENV") == self.binding["scope"]["environment"], "ownership")
        raw = read_file(PROFILE, 16384, private=False)
        profile = decode(raw)
        bodies = profile.get("bodies")
        state_require(isinstance(bodies, dict) and set(bodies) == {"control", "lifecycle", "network", "ingress", "cert_manager", "registry", "node", "delivery", "release", "service_guard"} and
                      hashlib.sha256(raw).hexdigest() == self.binding["fingerprints"]["profile_sha256"] and
                      profile["script_sha256"] == self.binding["fingerprints"]["script_sha256"] == bodies["control"] and
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == bodies["network"] and
                      profile.get("network_templates") == TEMPLATE_HASHES and
                      profile.get("network_images") == IMAGE_DIGESTS, "ownership")
        tools = self.binding["fingerprints"]["tools"]
        state_require(len(tools) == 2 and tools[0]["name"] == "bootstrap-index" and
                      tools[1] == {"name":"k3s", "sha256":profile["k3s_sha256"]}, "capability")
        self.check(profile)
        self.executable = tool(profile)
        self.profile_data = profile

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
            fcntl.flock(self.lock, (fcntl.LOCK_EX if self.tag.startswith(MUTATIONS) else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateRefused("busy")
        self.lock_id = identity(self.lock)
        self.revalidate()
        self.claim = state_read(ROOT + "/machine-claim.json", "machine-claim")
        state_require(self.claim is not None and self.claim["scope"] == self.binding["scope"] and
                      self.claim["owner"] == self.binding["owner"] and
                      self.claim["participants_sha256"] == self.binding["participants_sha256"] and
                      self.claim["member"] == self.binding["recipient"] and
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
                      record["machine"] == {key:self.binding["recipient"][key] for key in ("machine", "member", "role", "node_uid")} and
                      record["cluster"] == self.recipe["cluster"], "ownership")
        return record

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
        digest = state_hash("broil-infra-step-v1", self.payload)
        if previous is not None:
            state_require(previous["binding"] == self.binding and previous["action"] == self.action and
                          previous["payload_sha256"] == digest, "ownership")
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
        self.intent = {"schema":1,"kind":"intent","binding":self.binding,"action":self.action,
                       "payload_sha256":digest,"admitted_ms":state_now()}
        self.revalidate()
        state_publish(path + "/intent.json", self.intent)
        self.reservation["dispatches"].append(self.binding["dispatch"])
        self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        return None

    def terminal(self, outcome, failure, resource=None, uid=None):
        state_require(self.intent is not None and WRITERS_SETTLED, "busy")
        value = {"schema":1,"kind":"terminal","binding":self.binding,"action":self.action,
                 "payload_sha256":self.intent["payload_sha256"],"outcome":outcome,"failure":failure,
                 "effect":"complete" if outcome == "succeeded" else "unknown" if self.effect_started else "absent",
                 "writer_ended":True,"resource":resource,"resource_identity":uid,"completed_ms":state_now()}
        self.revalidate()
        state_publish(self.dispatch_path() + "/terminal.json", value)
        return value

    def expected(self):
        coredns, local = render_manifest(self.recipe, self.profile_data)
        rendered = []
        for family, raw in (("dns", coredns), ("storage", local)):
            chunks = raw.split(b"\n---\n")
            state_require(len(chunks) == 6, "ownership")
            for chunk in chunks:
                data = kubectl(self.executable, self.binding["owner"], "create", "--dry-run=client",
                               "--validate=false", "-f", "-", "-o", "json", input=chunk,
                               output_limit=8192)
                obj = decode(data)
                ordinal = len(rendered) + 1
                kind, namespace, name, expected_family = OBJECTS[ordinal - 1]
                state_require(obj["kind"] == kind and obj["metadata"]["name"] == name and
                              obj["metadata"].get("namespace") == namespace and family == expected_family,
                              "ownership")
                metadata = obj["metadata"]
                # kubectl's client-side dry run supplies this empty server field.
                state_require(metadata.pop("creationTimestamp", None) is None, "ownership")
                state_require(not obj.get("status"), "ownership")
                obj.pop("status", None)
                if ordinal == 5:
                    probe = obj["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]
                    state_require(probe.get("initialDelaySeconds") == 0, "ownership")
                    del probe["initialDelaySeconds"]
                labels = metadata.setdefault("labels", {})
                annotations = metadata.setdefault("annotations", {})
                additions = {
                    "broil.dev/owner":self.recipe["owner"],
                    "broil.dev/creation-operation":self.recipe["operation"],
                    "broil.dev/cluster-uid":self.recipe["cluster"]["uid"],
                    "broil.dev/recipe-sha256":self.recipe_hash,
                    "broil.dev/profile-sha256":self.recipe["profile_sha256"],
                    "broil.dev/render-sha256":self.recipe["coredns_render_sha256" if family == "dns" else
                                                           "local_storage_render_sha256"],
                }
                state_require(not (set(labels) & {"broil.dev/managed-by", "broil.dev/component"}) and
                              not (set(annotations) & set(additions)), "ownership")
                labels.update({"broil.dev/managed-by":"broil", "broil.dev/component":family})
                annotations.update(additions)
                state_require(len(canonical(obj)) <= 8192, "bound")
                rendered.append(obj)
        return rendered

    def get(self, expected):
        kind = expected["kind"].lower()
        name = expected["metadata"]["name"]
        namespace = expected["metadata"].get("namespace")
        args = ("get", kind, name, "--ignore-not-found", "-o", "json")
        if namespace is not None:
            args += ("--namespace", namespace)
        raw = kubectl(self.executable, self.binding["owner"], *args, output_limit=16384)
        if not raw.strip():
            return None
        actual = decode(raw)
        state_require(isinstance(actual, dict) and actual.get("kind") == expected["kind"] and
                      actual.get("metadata", {}).get("name") == name and
                      actual.get("metadata", {}).get("namespace") == namespace, "ownership")
        return actual

    def receipts(self):
        records = {}
        for _, intent, terminal in self.ledger():
            if intent["action"] != "lifecycle:network-create-object" or terminal is None or \
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

    @staticmethod
    def projection(expected, actual):
        if isinstance(expected, dict):
            state_require(isinstance(actual, dict), "ownership")
            return {key:NetworkReceiver.projection(value, actual.get(key)) for key, value in expected.items()}
        if isinstance(expected, list):
            state_require(isinstance(actual, list) and len(actual) == len(expected), "ownership")
            return [NetworkReceiver.projection(value, item) for value, item in zip(expected, actual)]
        return actual

    def objects(self, expected):
        nodes = decode(kubectl(self.executable, self.binding["owner"], "get", "nodes", "-o", "json",
                               output_limit=1048576))
        state_require(nodes.get("kind") in ("List", "NodeList") and isinstance(nodes.get("items"), list) and
                      len(nodes["items"]) == len(self.recipe["members"]), "ownership")
        observed_nodes = {node.get("metadata", {}).get("name"):node for node in nodes["items"]}
        state_require(len(observed_nodes) == len(self.recipe["members"]), "ownership")
        for member in self.recipe["members"]:
            node = observed_nodes.get(member["member"])
            state_require(node is not None and node["metadata"].get("uid") == member["node_uid"] and
                          any(condition.get("type") == "Ready" and condition.get("status") == "True"
                              for condition in node.get("status", {}).get("conditions", [])) and
                          not any(taint.get("key") == "node.kubernetes.io/not-ready"
                              for taint in node.get("spec", {}).get("taints", [])), "readiness")
        namespace = kubectl(self.executable, self.binding["owner"], "get", "namespace", "kube-system",
                            "--ignore-not-found", "-o", "json", output_limit=8192)
        state_require(bool(namespace.strip()) and decode(namespace)["metadata"]["name"] == "kube-system", "ownership")
        classes = decode(kubectl(self.executable, self.binding["owner"], "get", "storageclass",
                                 "-o", "json", output_limit=32768))
        state_require(classes["kind"] in ("List", "StorageClassList") and isinstance(classes["items"], list) and
                      len(classes["items"]) <= 128, "bound")
        for item in classes["items"]:
            annotations = item.get("metadata", {}).get("annotations", {})
            state_require(item["metadata"]["name"] == "local-path" or
                          annotations.get("storageclass.kubernetes.io/is-default-class") != "true" and
                          annotations.get("storageclass.beta.kubernetes.io/is-default-class") != "true", "ownership")
        receipts = self.receipts()
        records = []
        for ordinal, obj in enumerate(expected, 1):
            actual = self.get(obj)
            metadata = obj["metadata"]
            record = {"kind":obj["kind"], "namespace":metadata.get("namespace"), "name":metadata["name"],
                      "uid":None, "class":"absent", "spec_sha256":None, "available":"unobserved"}
            if actual is not None:
                meta = actual["metadata"]
                uid = meta.get("uid")
                state_require(opaque(uid), "ownership")
                record["uid"] = uid
                actual_projection = self.projection(obj, actual)
                record["spec_sha256"] = state_hash("broil-k3s-network-object-v1", actual_projection)
                wanted = state_hash("broil-k3s-network-object-v1", obj)
                owned = receipts.get(f"network-object-{ordinal:02d}") == uid
                exact = actual_projection == obj
                record["class"] = "owned-ready" if owned and exact else "owned-drifted" if owned else "foreign"
                if record["class"] == "owned-ready":
                    if obj["kind"] == "Deployment":
                        ready = actual.get("status", {}).get("availableReplicas", 0) >= 1
                        record["available"] = "ready" if ready else "not-ready"
                    else:
                        record["available"] = "ready"
                state_require(len(canonical(actual)) <= 16384 and len(canonical(record)) <= 1024, "bound")
            records.append(record)
        return records

    @staticmethod
    def host_command(path, *args, maximum=65536, allowed=(0,)):
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            value = os.fstat(fd)
            state_require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and
                          not value.st_mode & 0o022, "ownership")
            return command(fd, list(args), allowed=allowed, limits=(maximum, 4096), argv0=path)
        finally:
            os.close(fd)

    @staticmethod
    def fact(ready, absent="missing"):
        return {"state":"ready" if ready else "not-ready", "reason":"observed" if ready else absent}

    def host(self):
        self.owned()
        config = decode(read_file("/etc/rancher/k3s/config.yaml", 8192))
        member = self.binding["recipient"]
        server = member["role"] == "server"
        network = self.recipe["network"]
        state_require(config["node-name"] == member["member"] and
                      isinstance(config["node-ip"], str) and
                      str(ipaddress.IPv4Address(config["node-ip"])) == config["node-ip"], "ownership")
        if server:
            state_require(config["cluster-cidr"] == network["pod_cidr"] and
                          config["service-cidr"] == network["service_cidr"] and
                          config["cluster-dns"] == network["cluster_dns"] and
                          config["cluster-domain"] == network["cluster_domain"] and
                          config["flannel-backend"] == "vxlan" and
                          "coredns" in config["disable"] and "local-storage" in config["disable"],
                          "configuration")
            # The agent view's exact label/taint comparison, which a target
            # without agents cannot obtain; Kubernetes condition taints vary.
            node = decode(kubectl(self.executable, self.binding["owner"], "get", "node", member["member"],
                                  "-o", "json", output_limit=65536))
            labels, taints = node["metadata"].get("labels", {}), node.get("spec", {}).get("taints", [])
            state_require(isinstance(labels, dict) and isinstance(taints, list) and
                          all(isinstance(t, dict) and isinstance(t.get("key"), str) for t in taints), "integrity")
            state_require(sorted(k + "=" + v for k, v in labels.items() if isinstance(v, str) and not k.startswith(
                              ("kubernetes.io/", "node.kubernetes.io/", "beta.kubernetes.io/", "k3s.io/",
                               "node-role.kubernetes.io/"))) == sorted(config["node-label"]) and
                          sorted(t["key"] + "=" + t.get("value", "") + ":" + str(t.get("effect")) for t in taints
                                 if not t["key"].startswith("node.kubernetes.io/")) ==
                          sorted(t for t in config["node-taint"] if not t.startswith("node.kubernetes.io/")),
                          "ownership")
        addresses = decode(self.host_command("/usr/sbin/ip", "-j", "-4", "address", "show"))
        state_require(isinstance(addresses, list) and len(addresses) <= 128, "bound")
        matching = [entry for entry in addresses if any(address.get("local") == config["node-ip"]
                    for address in entry.get("addr_info", []))]
        interface = any("UP" in entry.get("flags", []) for entry in matching)
        links = decode(self.host_command("/usr/sbin/ip", "-j", "link", "show"))
        state_require(isinstance(links, list) and len(links) <= 256, "bound")
        flannel = any(entry.get("ifname") == "flannel.1" and
                      {"UP", "LOWER_UP"}.issubset(entry.get("flags", [])) and
                      entry.get("link_type") == "ether" for entry in links)
        rules = self.host_command("/usr/sbin/iptables-save", maximum=131072)
        proxy = b":KUBE-SERVICES " in rules and b"-A KUBE-SERVICES " in rules
        policy = b":KUBE-ROUTER-" in rules and b"-A KUBE-ROUTER-" in rules
        sockets = self.host_command("/usr/bin/ss", "-H", "-lnptu", maximum=65536)
        socket_lines = [line.split() for line in sockets.splitlines()]
        state_require(len(socket_lines) <= 256, "bound")
        def listening(protocol, port, process=None):
            return any(len(line) >= 6 and line[0] == protocol and
                       line[4].rsplit(b":", 1)[-1] == str(port).encode() and
                       (process is None or process in b" ".join(line[6:])) for line in socket_lines)
        process = b"k3s-server" if server else b"k3s-agent"
        ports = listening(b"udp", 8472) and listening(b"tcp", 10250, process) and \
            listening(b"tcp", 10256, process) and (not server or listening(b"tcp", 6443, process))
        routes = decode(self.host_command("/usr/sbin/ip", "-j", "-4", "route", "show", maximum=32768))
        state_require(isinstance(routes, list) and len(routes) <= 256, "bound")
        pod_cidr = ipaddress.IPv4Network(network["pod_cidr"])
        service_cidr = ipaddress.IPv4Network(network["service_cidr"])
        routed = False
        conflict = False
        for item in routes:
            destination = item.get("dst", "default")
            if destination == "default":
                continue
            try:
                subnet = ipaddress.IPv4Network(destination, strict=False)
            except (ValueError, TypeError):
                raise StateRefused("integrity")
            device = item.get("dev")
            routed |= subnet.overlaps(pod_cidr) and device == "flannel.1"
            conflict |= subnet.overlaps(pod_cidr) and device not in ("flannel.1", "cni0") or \
                subnet.overlaps(service_cidr) and device not in ("lo", "kube-ipvs0")
        service_name = "broil-k3s.service" if server else "broil-k3s-agent.service"
        service = self.host_command("/usr/bin/systemctl", "is-active", service_name,
                                    maximum=128, allowed=(0, 3)).strip() == b"active"
        capacity = os.statvfs("/var/lib/rancher/k3s")
        enough = capacity.f_bavail * capacity.f_frsize >= 134217728
        facts = {"member":member,
                 "configuration":self.fact(True), "interface":self.fact(interface),
                 "routes":self.fact((routed or len(self.recipe["members"]) == 1) and not conflict),
                 "ports":self.fact(ports),
                 "flannel":self.fact(flannel), "proxy":self.fact(proxy),
                 "policy":self.fact(policy), "capacity":self.fact(enough, "insufficient"),
                 "service":self.fact(service)}
        state_require(len(canonical(facts)) <= 4096, "bound")
        return facts

    def inspect(self, result):
        expected = self.expected()
        objects = self.objects(expected)
        result["objects"] = objects
        for key, block in (("services", objects[:6]), ("storage", objects[6:])):
            # Workload DNS and retained PVC behavior require separate probes.
            # Object and Deployment health alone cannot establish either fact.
            result[key] = "unobserved" if all(item["class"] == "owned-ready" and
                    item["available"] == "ready" for item in block) else "not-ready"
        return expected, objects

    def create(self, result):
        self.active()
        ordinal = self.header["object_ordinal"]
        state_uint(ordinal, 1, 12)
        resource = self.header["resource"]
        state_require(resource == fixed_resource(self.recipe, ordinal, resource["generation"]) and
                      resource["uid"] is None and self.binding["recipient"] == self.recipe["first_server"] and
                      self.binding["operation"] == self.recipe["operation"], "ownership")
        expected, observed = self.inspect(result)
        preflight = self.header["preflight"]
        state_require(isinstance(preflight, list) and len(preflight) == 12, "ownership")
        for old, new in zip(preflight, observed):
            state_fields(old, "kind namespace name uid class spec_sha256 available")
            state_require(old == new or old["class"] == new["class"] == "owned-ready" and
                          old["uid"] == new["uid"] and old["kind"] == new["kind"] and
                          old["namespace"] == new["namespace"] and old["name"] == new["name"] and
                          old["spec_sha256"] == new["spec_sha256"], "ownership")
        state_require(observed[ordinal - 1]["class"] == "absent" and
                      all(item["class"] in ("absent", "owned-ready") for item in observed), "ownership")
        # The selected absent identity has a second read immediately before effect.
        state_require(self.get(expected[ordinal - 1]) is None, "ownership")
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        self.effect_started = True
        kubectl(self.executable, self.binding["owner"], "create", "-f", "-",
                input=canonical(expected[ordinal - 1]) + b"\n", output_limit=4096)
        actual = self.get(expected[ordinal - 1])
        state_require(actual is not None and opaque(actual["metadata"].get("uid")) and
                      self.projection(expected[ordinal - 1], actual) == expected[ordinal - 1], "ownership")
        uid = actual["metadata"]["uid"]
        result["terminal"] = self.terminal("succeeded", None, resource, uid)
        result["objects"] = self.objects(expected)

    def run(self, result):
        if self.tag == "inspect-host":
            result["hosts"] = self.host()
        elif self.tag == "inspect-objects":
            self.inspect(result)
        else:
            self.create(result)


# ---- The registry storage protocol ----
RESERVED = ("/etc/rancher", "/run", "/var/lib/rancher", "/var/lib/kubelet", "/var/lib/cni", "/var/log/pods",
            "/var/log/containers", "/var/lib/broil", "/var/lib/broil-k3s-incoming", "/var/lib/broil-k3s-replication",
            "/root/.broil")
RECORD = "broil-storage.json"
FIELDS = set("schema kind scope owner operation attempt cluster registry member path capacity_mib runtime directory "
             "data fsid".split())
FACT = set("class parent ancestor filesystem available_mib record_sha256 directory data fsid".split())
ORIGIN = ("record_sha256", "directory", "data", "fsid")
# The parents that name their deciding ancestor.
ANCESTRY = ("unsafe", "closed", "untraversable")
# The replication unit's filesystem restrictions, which the delivery body renders
# and the traversal probe applies.
REPLICATION_RESTRICTIONS = ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes")
# The service traversal probe: `<path>` on standard input, `O_PATH` lookups from `/`, and one line naming
# the depth of the directory whose search was denied, or `none`.
PROBE = """import os,sys
p=sys.stdin.buffer.read().split(b"/")[1:]
f,r=os.open(b"/",os.O_PATH|os.O_DIRECTORY),b"none"
for d,c in enumerate(p):
 last=d==len(p)-1
 try:f=os.open(c,os.O_PATH|os.O_NOFOLLOW|(0 if last else os.O_DIRECTORY),dir_fd=f)
 except OSError as e:
  if e.errno in(1,13):r=b"%d"%d
  elif not(last and e.errno==2):raise
  break
sys.stdout.buffer.write(r+b"\\n")
"""
# The Node rows: name, UID, `spec.unschedulable` and the `Ready` status.
NODES = '{range .items[*]}{.metadata.name}{"\\t"}{.metadata.uid}{"\\t"}{.spec.unschedulable}{"\\t"}' \
        '{range .status.conditions[?(@.type=="Ready")]}{.status}{end}{"\\n"}{end}'


def mounts():
    """`/proc/self/mountinfo`'s mount points, octal escapes decoded, with their filesystem types."""
    fd = os.open("/proc/self/mountinfo", os.O_RDONLY | os.O_CLOEXEC)
    try:
        raw = b""
        while len(raw) <= MAXIMUM:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            raw += chunk
        state_require(len(raw) <= MAXIMUM, "bound")
    finally:
        os.close(fd)
    found = []
    for line in raw.decode("utf-8", "surrogateescape").splitlines():
        left, _, right = line.partition(" - ")
        found.append((re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), left.split(" ")[4]), right.split(" ")[0]))
    return found


def within(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def probe(path):
    """The service traversal probe: None when every ancestor is searched, the denied depth, or "no result"."""
    argv = ["systemd-run", "--wait", "--pipe", "--quiet", "--collect", "--property=RuntimeMaxSec=30",
            *("--property=" + item for item in REPLICATION_RESTRICTIONS), "/usr/bin/setpriv", "--reuid=10000",
            "--regid=10000", "--clear-groups", "/usr/bin/python3", "-I", "-c", PROBE]
    try:
        done = subprocess.run(argv, input=os.fsencode(path), capture_output=True,
                              timeout=max(0.001, min(30, DEADLINE - time.monotonic())))
        lines = done.stdout.split(b"\n")
        if done.returncode == 0 and len(lines) == 2 and not lines[1]:
            if lines[0] == b"none":
                return None
            if re.fullmatch(rb"0|[1-9][0-9]{0,3}", lines[0]) and int(lines[0]) < len(Path(path).parts) - 1:
                return int(lines[0])
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return "no result"


class StorageReceiver(NetworkReceiver):
    FAMILY, KEYS, HOST = "registry-storage", ("recipe", "expected", "resource", "preflight", "member"), (
        "inspect-storage", "create-storage")

    def check(self, profile):
        """The recipe and the names; the recipient by action."""
        r = self.recipe
        state_fields(r, "scope owner operation cluster first_server members version registry path capacity_mib "
                        "runtime stage origins profile_sha256")
        self.common(profile)
        self.bind(r, self.header["expected"], r["origins"])

    def common(self, profile):
        """The fields that every registry protocol's recipe shares, and the recipient by action."""
        r, b, member = self.recipe, self.binding, self.header["member"]
        members = r["members"]
        state_cluster(r["cluster"])
        state_require(isinstance(members, list) and 0 < len(members) <= 1024, "ownership")
        for item in [r["first_server"], *members]:
            state_member(item)
        host = self.tag in self.HOST
        self.index = members.index(member) if host and member in members else None
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      r["profile_sha256"] == b["fingerprints"]["profile_sha256"] and r["cluster"] and
                      r["version"] == profile["k3s_version"] and r["first_server"]["role"] == "server" and
                      all(m["role"] != "backup" and m["node_uid"] is not None for m in members) and
                      len({m["member"] for m in members}) == len(members) and
                      (self.index is not None and b["recipient"] == member if host else
                       member is None and b["recipient"] == r["first_server"]) and
                      opaque(r["registry"]) and r["stage"] in ("create", "extend", "observe"), "ownership")

    def bind(self, store, expected, origins, every=False):
        """The storage fields of `store` and the recipient's origin against `expected`; `every`
        requires every member's origin, as at the `observe` row."""
        r, self.expect = self.recipe, expected
        state_fields(origins, "directories")
        path, entries, stage = store["path"], origins["directories"], r["stage"]
        state_require(isinstance(entries, list) and len(entries) == len(r["members"]), "ownership")
        for origin in entries:
            if origin is not None:
                state_fields(origin, "operation recipe_sha256 " + " ".join(ORIGIN))
        present = [origin is not None for origin in entries]
        mine = entries[self.index] if self.index is not None else None
        parts = Path(path).parts[1:] if isinstance(path, str) else ()
        state_require(path.startswith("/") and str(Path(path)) == path and parts and
                      len(path.encode()) <= 4090 and all(0 < len(p.encode()) <= 255 and p != ".." for p in parts) and
                      type(store["capacity_mib"]) is int and store["capacity_mib"] > 0 and
                      store["runtime"] == {"uid":10000, "gid":10000} and
                      (all(present) if every else not any(present) if stage == "create" else True) and
                      expected == (None if mine is None else {k:mine[k] for k in ORIGIN}), "ownership")
        self.path = path
        # The record's fields that the class compares, with the recipient's recipe member.
        self.store = {**{k:r[k] for k in ("scope", "owner", "cluster", "registry")}, "path":path,
                      "capacity_mib":store["capacity_mib"], "runtime":store["runtime"],
                      "member":r["members"][self.index] if self.index is not None else None}

    def walk(self):
        """The descriptor walk from `/` to `<path>`'s parent: the parent class, the deciding ancestor, whether a
        component is missing, and the parent's descriptor when the walk completes."""
        current, parent, ancestor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW), "safe", None
        try:
            for depth, part in enumerate(("",) + Path(self.path).parent.parts[1:]):
                if part:
                    try:
                        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=current)
                    except FileNotFoundError:
                        return parent, ancestor, True, None
                    except OSError as error:
                        if error.errno not in (20, 40):  # ENOTDIR, ELOOP: not a directory, or a symlink
                            raise
                        if parent == "safe":
                            value = os.stat(part, dir_fd=current, follow_symlinks=False)
                            parent, ancestor = "unsafe", [depth, value.st_uid, value.st_gid, value.st_mode & 0o7777]
                        return parent, ancestor, False, None
                    os.close(current)
                    current = fd
                value = os.fstat(current)
                # The first failing ancestor decides, `unsafe` before `closed` at one ancestor.
                failed = ("unsafe" if value.st_uid or value.st_mode & 0o022 else
                          "closed" if not value.st_mode & 0o001 else None)
                if failed and parent == "safe":
                    parent, ancestor = failed, [depth, value.st_uid, value.st_gid, value.st_mode & 0o7777]
            fd, current = current, None
            return parent, ancestor, False, fd
        finally:
            if current is not None:
                os.close(current)

    def observe(self, walked=None):
        """The `storage` fact, from a fresh walk or the caller's held one."""
        fact = {"class":"unobservable", "parent":"reserved", "ancestor":None, "filesystem":"unobservable",
                "available_mib":None, "record_sha256":None, "directory":None, "data":None, "fsid":None}
        if any(within(self.path, root) for root in RESERVED):
            return fact
        fd = missing = None
        try:
            fact["parent"], ancestor, missing, fd = walked or self.walk()
            if fact["parent"] == "safe" and missing:
                fact["parent"] = "absent"
            if fact["parent"] == "safe" and fd is not None:
                # Every ancestor passes: the probe decides.
                denied = probe(self.path)
                if denied == "no result":
                    fact["parent"] = "unobservable"
                elif denied is not None:
                    value = os.stat(str(Path(*Path(self.path).parts[:denied + 1])), follow_symlinks=False)
                    fact["parent"], ancestor = "untraversable", [denied, value.st_uid, value.st_gid,
                                                                 value.st_mode & 0o7777]
            if fact["parent"] in ANCESTRY:
                fact["ancestor"] = dict(zip(("depth", "uid", "gid", "mode"), ancestor))
        except OSError:
            fact["parent"] = "unobservable"
        try:
            found = mounts()
            best = max((point for point, _ in found if within(str(Path(self.path).parent), point)), key=len)
            fact["filesystem"] = "supported" if [t for p, t in found if p == best][-1] in ("ext4", "btrfs") else "unsupported"
            below = any(within(point, self.path) for point, _ in found)
        except (OSError, ValueError, IndexError):
            below = None
        if fd is None:
            fact["class"] = "absent" if missing else "unobservable"
            return fact
        try:
            value = os.fstatvfs(fd)
            fact["available_mib"] = value.f_bavail * value.f_frsize >> 20
            fact.update(self.leaf(fd, below))
        except OSError:
            fact["class"] = "unobservable"
        finally:
            if walked is None:
                os.close(fd)
        if below is None and fact["class"].startswith("owned"):
            fact["class"] = "unobservable"  # the mount rule is unobserved
        return fact

    def leaf(self, parent, below):
        """The class of `<path>`, with the live identities."""
        name = Path(self.path).name
        try:
            value = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return {"class":"absent"}
        if not stat.S_ISDIR(value.st_mode):
            return {"class":"foreign"}
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
        data = None
        try:
            mine, fsid = os.fstat(fd), os.fstatvfs(fd).f_fsid
            fact = {"class":"foreign", "directory":[mine.st_dev, mine.st_ino], "fsid":fsid}
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > 2:
                        break
            try:
                data = os.open("data", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
                content = os.fstat(data)
                fact["data"] = [content.st_dev, content.st_ino]
            except OSError:
                content = None
            try:
                record_fd = os.open(RECORD, os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    held, raw = os.fstat(record_fd), os.read(record_fd, 8193)
                finally:
                    os.close(record_fd)
            except OSError:
                return fact
            if len(raw) == held.st_size <= 8192:
                fact["record_sha256"] = hashlib.sha256(raw).hexdigest()
            r, expected = self.store, self.expect
            try:
                record = decode(raw)
                state_require(isinstance(record, dict) and set(record) == FIELDS and raw == canonical(record) + b"\n" and
                              record["schema"] == 1 and record["kind"] == "registry-storage" and
                              all(record[k] == r[k] for k in ("scope", "owner", "registry", "path")) and
                              all(isinstance(record[k], list) and len(record[k]) == 2 and
                                  all(type(x) is int for x in record[k]) for k in ("directory", "data")))
            except (Refused, StateRefused, ValueError):
                return fact
            # The member by the participant projection: a node UID that changed stays `owned`.
            same = lambda m: isinstance(m, dict) and dict(m, node_uid=None) == dict(r["member"] or {}, node_uid=None)
            owned = (sorted(names) == [RECORD, "data"] and mine.st_uid == mine.st_gid == 0 and
                     stat.S_IMODE(mine.st_mode) == 0o711 and stat.S_ISREG(held.st_mode) and
                     held.st_uid == held.st_gid == 0 and stat.S_IMODE(held.st_mode) == 0o600 and held.st_nlink == 1 and
                     content is not None and content.st_uid == content.st_gid == 10000 and not content.st_mode & 0o007 and
                     all(record[k] == r[k] for k in ("cluster", "capacity_mib", "runtime")) and
                     same(record["member"]) and record["directory"][1] == mine.st_ino and
                     record["data"][1] == content.st_ino and record["fsid"] == fsid == os.fstatvfs(data).f_fsid and
                     (expected is None or [expected["directory"][1], expected["data"][1], expected["fsid"],
                                           expected["record_sha256"]] == [mine.st_ino, content.st_ino, fsid,
                                                                          fact["record_sha256"]]) and below is False)
            fact["class"] = "owned" if owned else "owned-drifted"
            return fact
        finally:
            os.close(fd)
            if data is not None:
                os.close(data)

    @staticmethod
    def refusal(fact, capacity):
        """The create-row refusal of a host fact, or None."""
        if fact["parent"] == "reserved":
            return "configuration"
        # An unsafe parent decides before an unread class: the walk stops at a symlink or non-directory.
        unread = fact["class"] == "unobservable" and fact["parent"] != "unsafe"
        if unread or "unobservable" in (fact["parent"], fact["filesystem"]) or \
           fact["parent"] == "safe" and fact["available_mib"] is None:
            return "readiness"
        if fact["class"] not in ("absent", "unobservable") or fact["parent"] in ANCESTRY:
            return "ownership"
        if fact["parent"] == "absent":
            return "readiness"
        if fact["filesystem"] != "supported" or fact["available_mib"] < capacity:
            return "storage"
        return None

    def nodes(self):
        """`nodes`: one fact per replica member, in member order."""
        members = self.recipe["members"]
        try:
            raw = kubectl(self.executable, self.binding["owner"], "get", "nodes", "-o", "jsonpath=" + NODES,
                          output_limit=524288)
            rows = [line.split("\t") for line in raw.decode().splitlines()]
            state_require(rows and all(len(row) == 4 for row in rows) and len({row[0] for row in rows}) == len(rows))
        except Refused as error:
            state_require(error.code != 4, "bound")
            rows = None
        except (StateRefused, subprocess.SubprocessError, UnicodeDecodeError):
            rows = None
        found = {row[0]:row for row in rows or ()}
        return [{"member":m["member"], "node":"unobservable" if rows is None else
                 "not-ready" if m["member"] not in found else
                 "drifted" if found[m["member"]][1] != m["node_uid"] else
                 "ready" if found[m["member"]][3] == "True" and found[m["member"]][2] != "true" else "not-ready"}
                for m in members]

    def create_storage(self, result):
        """`create-storage`: one exclusive directory, content root and record."""
        global EFFECTS
        self.active()
        r, res, pre, member = self.recipe, self.header["resource"], self.header["preflight"], self.header["member"]
        state_require(r["stage"] != "observe" and self.expect is None and isinstance(res, dict) and res == dict(
            res, kind="replica", id="registry-replica-" + member["member"], owner=r["owner"],
            machine=member["machine"], path=self.path, namespace=None, name=None, uid=None) and
                      isinstance(pre, dict) and set(pre) == FACT and self.refusal(pre, r["capacity_mib"]) is None,
                      "ownership")
        state_hex(res["generation"])
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        walked = self.walk()
        fd = walked[3]
        try:
            # The recheck on the same walk, immediately before the effect: a failure refuses with no effect.
            failure = self.refusal(self.observe(walked), r["capacity_mib"])
            state_require(failure is None, failure)
            self.effect_started = EFFECTS = True
            name = Path(self.path).name
            os.mkdir(name, 0o700, dir_fd=fd)
            leaf = os.open(name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
            try:
                # root:root 0711, whatever group or setgid bit `mkdir` took from the parent.
                os.fchown(leaf, 0, 0)
                os.fchmod(leaf, 0o711)
                os.mkdir("data", 0o700, dir_fd=leaf)
                data = os.open("data", os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=leaf)
                try:
                    os.fchown(data, 10000, 10000)
                    os.fsync(data)
                    record = {"schema":1, "kind":"registry-storage", "attempt":self.binding["attempt"],
                              "member":member, "directory":identity(leaf), "data":identity(data),
                              "fsid":os.fstatvfs(leaf).f_fsid, **{k:r[k] for k in (
                                  "scope", "owner", "operation", "cluster", "registry", "path", "capacity_mib",
                                  "runtime")}}
                finally:
                    os.close(data)
                raw = canonical(record) + b"\n"
                state_require(len(raw) <= 8192, "bound")
                out = os.open(RECORD, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=leaf)
                try:
                    view = memoryview(raw)
                    while view:
                        view = view[os.write(out, view):]
                    os.fsync(out)
                finally:
                    os.close(out)
                os.fsync(leaf)
                os.fsync(fd)
                created = identity(leaf)
            finally:
                os.close(leaf)
        finally:
            if fd is not None:
                os.close(fd)
        result["terminal"] = self.terminal("succeeded", None, res, created)
        result["storage"] = self.observe()

    def run(self, result):
        if self.tag == "inspect-storage":
            result["storage"] = self.observe()
        elif self.tag == "create-storage":
            self.create_storage(result)
        else:
            result["nodes"] = self.nodes()


# ---- The registry service protocol ----
DISTRIBUTION = {"version":"v3.1.1", "image":"broil.invalid/candidate/distribution",
                "digest":"ac52bec3025b9dc75a26112e076e3e0af646fbb40af67ae9f2fcd6465963b839"}
NAMED = DISTRIBUTION["image"] + ":broil-proof"
DIGESTED = DISTRIBUTION["image"] + "@sha256:" + DISTRIBUTION["digest"]
PIN = "io.cri-containerd.pinned=pinned"
SERVICE = {"broil.dev/managed-by":"broil", "broil.dev/component":"registry-service"}
# The registry's `config.yml`, exactly 187 bytes.
CONFIG = ("version: 0.1\nlog:\n  level: error\nstorage:\n  filesystem:\n    rootdirectory: /data\n  delete:\n"
          "    enabled: false\n  maintenance:\n    uploadpurging:\n      enabled: false\nhttp:\n  addr: \":5000\"\n")
# The objects in order: kind, API version, `kubectl get` resource, and each kind's admitted server-written
# labels, annotations and finalizers; the Deployment's revision follows the writer moves.
KINDS = (("Namespace", "v1", "namespaces", {"kubernetes.io/metadata.name":"broil-registry"}, {}, ()),
         ("NetworkPolicy", "networking.k8s.io/v1", "networkpolicies.networking.k8s.io", {}, {}, ()),
         ("ConfigMap", "v1", "configmaps", {}, {}, ()),
         ("Service", "v1", "services", {}, {}, ()),
         ("Deployment", "apps/v1", "deployments.apps", {}, None, ()))
# The server's defaults in the Service's complete projection.
DEFAULTS = {"internalTrafficPolicy":"Cluster", "ipFamilies":["IPv4"], "ipFamilyPolicy":"SingleStack",
            "sessionAffinity":"None"}


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    value = hashlib.sha256()
    while chunk := os.read(fd, 1048576):
        state_check()
        value.update(chunk)
    return value.hexdigest()


def pick(render, actual):
    """`actual` restricted to the fields that `render` carries."""
    if isinstance(render, dict) and isinstance(actual, dict):
        return {key:pick(value, actual.get(key)) for key, value in render.items()}
    if isinstance(render, list) and isinstance(actual, list) and len(render) == len(actual):
        return [pick(value, item) for value, item in zip(render, actual)]
    return actual


def strip(entries, admitted):
    """`entries` without the admitted server-written ones."""
    return {key:value for key, value in (entries or {}).items() if admitted.get(key) != value}


class ServiceReceiver(StorageReceiver):
    FAMILY, KEYS, HOST, RECIPE = "registry-service", ("recipe", "expected", "resource", "preflight", "object_ordinal",
                                                      "member"), ("inspect-host", "import-image"), 2
    # The objects' kinds table, labels and projection hash label.
    TABLE, MARK, OBJECT = KINDS, SERVICE, "broil-k3s-registry-service-object-v1"

    def check(self, profile):
        """The recipe against the pin, its storage included."""
        r, expected = self.recipe, self.header["expected"]
        state_fields(r, "scope owner operation cluster first_server members writer writer_generation version registry "
                        "registry_version image assets storage tolerations stage origins profile_sha256")
        state_fields(r["storage"], "path capacity_mib runtime origins")
        state_fields(r["origins"], "objects configuration images")
        state_fields(expected, "storage objects")
        origins, tolerations, alternate = r["origins"]["objects"], r["tolerations"], r["origins"]["configuration"]
        images, assets, stage = r["origins"]["images"], r["assets"], r["stage"]
        state_require(alternate is None or stage != "create" and state_hex(alternate, 64) is None, "ownership")
        state_require(profile.get("registry") == DISTRIBUTION and r["registry_version"] == DISTRIBUTION["version"] and
                      r["image"] == DIGESTED and isinstance(tolerations, list) and len(tolerations) <= 64 and
                      isinstance(origins, list) and len(origins) == 5 and isinstance(assets, list) and
                      isinstance(images, list) and len(images) == len(assets) == len(r["members"]) and
                      r["writer"] in [m["member"] for m in r["members"] if isinstance(m, dict)] and
                      type(r["writer_generation"]) is int and r["writer_generation"] % 2 == 1, "ownership")
        for taint in tolerations:
            state_fields(taint, "key value effect")
            state_require(isinstance(taint["key"], str) and isinstance(taint["value"], str) and
                          taint["effect"] in ("NoSchedule", "PreferNoSchedule", "NoExecute"), "ownership")
        for origin in origins:
            if origin is not None:
                state_fields(origin, "operation recipe_sha256 uid")
        for entry, member in zip(assets, r["members"]):
            state_fields(entry, "member generation marker_sha256")
            state_hex(entry["generation"])
            state_hex(entry["marker_sha256"], 64)
            state_require(entry["member"] == member["member"], "ownership")
        for image in images:
            if image is not None:
                state_fields(image, "operation")
        create = stage == "create"
        state_require(all((origin is None) == create for origin in origins) and
                      (create or expected["objects"] == [origin["uid"] for origin in origins]) and
                      (all(i is None for i in images) if create else
                       all(images) if stage == "observe" else not all(images)), "ownership")
        self.common(profile)
        self.bind(r["storage"], expected["storage"], r["storage"]["origins"], True)
        self.wanted = self.renders()

    def runtime(self, *args, **options):
        return command(self.executable, list(args), limits=(MAXIMUM, 65536), **options)

    # ---- Host facts and the import ----
    def entry(self):
        """The recipient replica member's `assets` entry."""
        return self.recipe["assets"][self.index]

    def assets(self):
        """The recipient's bound generation Resource and path."""
        machine, generation = self.binding["recipient"]["machine"], self.entry()["generation"]
        path = f"{self.owner_path}/assets/{generation}"
        return {"kind":"bootstrap-assets", "id":machine, "owner":self.binding["owner"], "generation":generation,
                "machine":machine, "path":path + "/", "namespace":None, "name":None, "uid":None}, path

    def generation(self):
        """The whole-generation check for `distribution`; the held archive, or `readiness`."""
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
                                  digest(fd) == asset["sha256"] and
                                  (asset["id"] == "distribution") == (name == "distribution.tar"), "readiness")
                    seen.add(asset["id"])
                    if name == "distribution.tar":
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
                          manifests[0].get("digest") == "sha256:" + DISTRIBUTION["digest"] and
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
                if fields[2] != "sha256:" + DISTRIBUTION["digest"]:
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
        """The four host facts."""
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
        facts["storage"] = self.observe()
        return facts

    def import_image(self, result):
        """`import-image`: intent, the rechecks, then the import, tag and labels."""
        global EFFECTS
        self.active()
        pre = self.header["preflight"]
        r = self.recipe
        state_require((r["stage"] == "create" or r["origins"]["images"][self.index] is None) and
                      self.header["resource"] == self.assets()[0] and
                      isinstance(pre, dict) and set(pre) == {"generation", "image", "runtime"} and
                      pre["generation"] == pre["runtime"] == "ready" and pre["image"] in ("ready", "not-ready"),
                      "ownership")
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        resource, directory_id, archive = self.generation()
        try:
            state_require(self.image() != "conflicting", "ownership")
            self.effect_started = EFFECTS = True
            if NAMED not in self.records():
                os.lseek(archive, 0, os.SEEK_SET)
                self.runtime("ctr", "-n", "k8s.io", "images", "import", "-", source=archive, mutating=True,
                             seconds=600)
            if DIGESTED not in self.records():
                self.runtime("ctr", "-n", "k8s.io", "images", "tag", NAMED, DIGESTED, mutating=True)
            for name in (NAMED, DIGESTED):
                self.runtime("ctr", "-n", "k8s.io", "images", "label", name, PIN, mutating=True)
            state_require(self.image() == "ready", "readiness")
            result["terminal"] = self.terminal("succeeded", None, resource, directory_id)
        finally:
            os.close(archive)
        result.update(self.host())

    # ---- API facts and the creates ----
    def annotations(self, n):
        """The five ownership annotations of object `n`'s creating request."""
        r, origin = self.recipe, self.recipe["origins"]["objects"][n]
        return {"broil.dev/owner":r["owner"], "broil.dev/creation-operation":(origin or r)["operation"],
                "broil.dev/cluster-uid":r["cluster"]["uid"],
                "broil.dev/recipe-sha256":origin["recipe_sha256"] if origin else self.recipe_hash,
                "broil.dev/profile-sha256":r["profile_sha256"]}

    def renders(self):
        """The five renders, each with its metadata."""
        r, selector = self.recipe, {"matchLabels":SERVICE}
        pod = {"automountServiceAccountToken":False, "enableServiceLinks":False,
               "nodeSelector":{"kubernetes.io/hostname":r["writer"]}, "securityContext":{
            "runAsNonRoot":True, "runAsUser":10000, "runAsGroup":10000, "seccompProfile":{"type":"RuntimeDefault"}},
            "containers":[{"name":"distribution", "image":DIGESTED, "imagePullPolicy":"Never",
                           "args":["serve", "/config/config.yml"], "ports":[{"containerPort":5000, "protocol":"TCP"}],
                           "securityContext":{"allowPrivilegeEscalation":False, "readOnlyRootFilesystem":True,
                                              "capabilities":{"drop":["ALL"]}},
                           "resources":{"requests":{"cpu":"50m", "memory":"64Mi"}, "limits":{"memory":"256Mi"}},
                           "readinessProbe":{"tcpSocket":{"port":5000}, "periodSeconds":2},
                           "volumeMounts":[{"name":"data", "mountPath":"/data"},
                                           {"name":"config", "mountPath":"/config", "readOnly":True}]}],
            "volumes":[{"name":"data", "hostPath":{"path":self.path + "/data", "type":"Directory"}},
                       {"name":"config", "configMap":{"name":"broil-registry"}}]}
        if r["tolerations"]:
            # The API returns an empty toleration value omitted.
            pod["tolerations"] = [dict({"key":t["key"], "operator":"Equal", "effect":t["effect"]},
                                       **({"value":t["value"]} if t["value"] else {})) for t in r["tolerations"]]
        bodies = ({}, {"spec":{"podSelector":selector, "policyTypes":["Ingress"]}}, {"data":{"config.yml":CONFIG}},
                  {"spec":{"type":"ClusterIP", "selector":SERVICE,
                           "ports":[{"port":5000, "targetPort":5000, "protocol":"TCP"}]}},
                  {"spec":{"replicas":1, "strategy":{"type":"Recreate"}, "selector":selector,
                           "template":{"metadata":{"labels":SERVICE}, "spec":pod}}})
        renders = []
        for n, (kind, version, *_) in enumerate(KINDS):
            meta = {"name":"broil-registry", "labels":SERVICE, "annotations":self.annotations(n)}
            if n:
                meta["namespace"] = "broil-registry"
            renders.append({"apiVersion":version, "kind":kind, "metadata":meta, **bodies[n]})
        return renders

    def project(self, n, obj, render):
        """The projection of object `n`, and the render's with the server's defaults; the Deployment's
        generation is the writer's."""
        if n == 0:
            return {}, {}
        if n == 2:
            return ({key:obj.get(key) for key in ("data", "binaryData", "immutable")},
                    {"data":render["data"], "binaryData":None, "immutable":None})
        if n in (1, 4):
            return ({"generation":obj["metadata"].get("generation"), "spec":pick(render["spec"], obj.get("spec"))},
                    {"generation":self.recipe["writer_generation"] if n == 4 else 1, "spec":render["spec"]})
        return ({key:value for key, value in obj["spec"].items() if key not in ("clusterIP", "clusterIPs")},
                {**render["spec"], **DEFAULTS})

    def read(self, n):
        """The record of object `n`, with the object itself when it is present and readable."""
        kind, _, resource, labels, annotations, finalizers = self.TABLE[n]
        if annotations is None:
            annotations = {"deployment.kubernetes.io/revision":str((self.recipe["writer_generation"] + 1) // 2)}
        render = self.wanted[n]
        wanted = render["metadata"]
        record = {"kind":kind, "namespace":wanted.get("namespace"), "name":wanted["name"], "uid":None,
                  "class":"unobservable", "spec_sha256":None}
        args = ("--namespace", wanted["namespace"]) if "namespace" in wanted else ()
        try:
            raw = kubectl(self.executable, self.binding["owner"], "get", resource, wanted["name"], *args,
                          "--ignore-not-found", "-o", "json", output_limit=262144)
            if not raw.strip():
                record["class"] = "absent"
                return record, None
            obj = decode(raw)
            meta = obj["metadata"]
            state_require(obj["kind"] == kind and meta["name"] == wanted["name"] and
                          meta.get("namespace") == wanted.get("namespace") and opaque(meta["uid"]))
            projection, expected = self.project(n, obj, render)
            found = meta.get("annotations") or {}
            attributed = self.header["expected"]["objects"][n] == meta["uid"] and \
                all(found.get(k) == v for k, v in wanted["annotations"].items())
            alternate = n == 2 and self.OBJECT == ServiceReceiver.OBJECT and self.recipe["origins"]["configuration"]
            exact = strip(meta.get("labels"), labels) == self.MARK and strip(found, annotations) == wanted["annotations"] and \
                set(meta.get("finalizers") or ()) <= set(finalizers) and not meta.get("ownerReferences") and \
                "deletionTimestamp" not in meta and (state_hash(self.OBJECT, projection) == alternate if alternate
                                                     else projection == expected)
            record.update(uid=meta["uid"], spec_sha256=state_hash(self.OBJECT, projection),
                          **{"class":"owned" if attributed and exact else "owned-drifted" if attributed else "foreign"})
            state_require(len(canonical(record)) <= 512, "bound")
            return record, obj
        except Refused as error:
            state_require(error.code != 4, "bound")
        except StateRefused as error:
            state_require(error.failure != "bound", "bound")
        except (subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError):
            pass
        record.update(uid=None, spec_sha256=None, **{"class":"unobservable"})
        return record, None

    def process(self, deployment):
        """`process` from the Deployment's read and its pods."""
        value = {"state":"not-ready", "reason":"unobservable", "node":None, "restarts":None}
        record, obj = deployment
        try:
            raw = kubectl(self.executable, self.binding["owner"], "get", "pods", "--namespace", "broil-registry",
                          "--selector", "broil.dev/managed-by=broil,broil.dev/component=registry-service", "-o", "json",
                          output_limit=262144)
            pods = [pod for pod in decode(raw)["items"] if "deletionTimestamp" not in pod["metadata"]]
            status = (pods[0].get("status") or {}) if len(pods) == 1 else {}
            container = (status.get("containerStatuses") or [{}])[0]
            state = container.get("state") or {}
            if len(pods) == 1:
                value.update(node=pods[0]["spec"].get("nodeName"), restarts=container.get("restartCount"))
            state_require((value["node"] is None or opaque(value["node"])) and
                          (value["restarts"] is None or type(value["restarts"]) is int and value["restarts"] >= 0))
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions") or ())
            counted = obj is not None and [(obj.get("status") or {}).get(key) for key in (
                "observedGeneration", "readyReplicas", "availableReplicas")] == [self.recipe["writer_generation"], 1, 1]
            stopped = record["class"].startswith("owned") and ((obj or {}).get("spec") or {}).get("replicas") == 0
        except Refused as error:
            state_require(error.code != 4, "bound")
            return value
        except (StateRefused, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError):
            return value
        if record["class"] == "unobservable":
            return value
        waiting = state.get("waiting")
        value["reason"] = ("stopped" if stopped else "deployment" if record["class"] != "owned" else
                           "absent" if not pods else "pods" if len(pods) > 1 else
                           "node" if value["node"] not in (None, self.recipe["writer"]) else
                           "failed" if status.get("phase") in ("Failed", "Succeeded") or "terminated" in state or
                           waiting is not None and waiting.get("reason") != "ContainerCreating" else
                           "pending" if value["node"] is None or status.get("phase") != "Running" else
                           "starting" if not ready or not counted else None)
        value["state"] = "not-ready" if value["reason"] else "ready"
        return value

    def inspect(self, result):
        """The three API facts."""
        reads = [self.read(n) for n in range(5)]
        result.update(objects=[record for record, _ in reads], process=self.process(reads[4]), nodes=self.nodes())

    def create_object(self, result):
        """`create-object`: the selected absent object, created once."""
        self.active()
        r, res, pre, n = self.recipe, self.header["resource"], self.header["preflight"], self.header["object_ordinal"] - 1
        render = self.wanted[n]
        state_require(r["stage"] == "create" and isinstance(res, dict) and res == dict(
            res, kind="service", id="registry-service-object-%02d" % (n + 1), owner=r["owner"],
            machine=None, path=None, namespace=render["metadata"].get("namespace"), name=render["metadata"]["name"],
            uid=None) and isinstance(pre, dict) and set(pre) == {"objects", "nodes"} and
                      isinstance(pre["objects"], list) and len(pre["objects"]) == 5 and
                      all(isinstance(item, dict) for item in pre["objects"]) and
                      pre["objects"][n].get("class") == "absent" and (not n or pre["objects"][0].get("class") == "owned"),
                      "ownership")
        state_hex(res["generation"])
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        # The recheck immediately before the effect: the object absent, its Namespace owned.
        current = (self.read(n)[0]["class"], self.read(0)[0]["class"] if n else "owned")
        state_require("unobservable" not in current, "readiness")
        state_require(current == ("absent", "owned"), "ownership")
        state_require(DEADLINE - time.monotonic() >= 50, "timeout")
        self.effect_started = True
        uid = kubectl(self.executable, self.binding["owner"], "create", "-f", "-", "-o", "jsonpath={.metadata.uid}",
                      input=canonical(render) + b"\n", output_limit=512, timeout="40s", seconds=45).decode()
        state_require(opaque(uid))
        result["terminal"] = self.terminal("succeeded", None, res, uid)

    def run(self, result):
        if self.tag == "inspect-host":
            result.update(self.host())
        elif self.tag == "import-image":
            self.import_image(result)
        elif self.tag == "inspect-objects":
            self.inspect(result)
        else:
            self.create_object(result)


# ---- The registry endpoint protocol ----
EDGE = {"broil.dev/managed-by":"broil", "broil.dev/component":"registry-endpoint"}
ROUTE = ("IngressRoute", "traefik.io/v1alpha1", "ingressroutes.traefik.io", {}, {}, ())
# The objects in order, as KINDS rows without server-written entries, and their namespaces and names.
EDGES = (("NetworkPolicy", "networking.k8s.io/v1", "networkpolicies.networking.k8s.io", {}, {}, ()), ROUTE, ROUTE)
PLACES = (("broil-registry", "broil-registry-endpoint"), ("cert-manager", "broil-registry-tls"),
          ("broil-registry", "broil-registry"))
# The issued Secret's template: its type, UID and stored base64 of `tls.crt`, never `tls.key` or `ca.crt`.
ISSUED = '{{.type}}{{"\\t"}}{{.metadata.uid}}{{"\\t"}}{{with .data}}{{with index . "tls.crt"}}{{.}}{{end}}{{end}}'
# The certificate block: line-feed lines of base64 between the two marker lines.
BLOCK = re.compile(rb"-----BEGIN CERTIFICATE-----\n((?:[A-Za-z0-9+/=]+\n)+)-----END CERTIFICATE-----")


def leaf_of(pem):
    """The DER bytes of `pem`'s first certificate block, or None when it has none."""
    match = BLOCK.match(pem, max(0, pem.find(b"-----BEGIN CERTIFICATE-----")))
    try:
        return base64.b64decode(match.group(1).replace(b"\n", b""), validate=True) if match else None
    except ValueError:
        return None


def distribution(head):
    """Whether a complete response head carries Distribution's version header, whatever its status."""
    return any(name.strip().lower() == b"docker-distribution-api-version" and value.strip() == b"registry/2.0"
               for name, _, value in (line.partition(b":") for line in head.split(b"\r\n")[1:]))


def address(value):
    try:
        return isinstance(value, str) and str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


class EndpointReceiver(ServiceReceiver):
    FAMILY, KEYS, HOST, RECIPE = "registry-endpoint", ("recipe", "expected", "resource", "preflight",
                                                       "object_ordinal"), (), 1
    TABLE, MARK, OBJECT = EDGES, EDGE, "broil-k3s-registry-endpoint-object-v1"

    def check(self, profile):
        """The recipe; both actions on the first server."""
        r, b, expected = self.recipe, self.binding, self.header["expected"]
        state_fields(r, "scope owner operation cluster first_server anchor_uid version registry endpoint trust "
                        "certificate ingress stage origins profile_sha256")
        e, t, c, o = r["endpoint"], r["trust"], r["certificate"], r["origins"]
        state_fields(e, "name host port origin")
        state_fields(t, "certificates sha256")
        state_fields(c, "name certificate secret uid cluster_issuer")
        state_fields(o, "objects service certificate")
        state_cluster(r["cluster"])
        state_member(r["first_server"])
        state_hex(t["sha256"], 64)
        objects, service, create = o["objects"], o["service"], r["stage"] == "create"
        # The Certificate's and the issued Secret's names, rederived.
        named = isinstance(c["name"], str) and hashlib.sha256(canonical(
            [r["owner"], {"kind":"certificate", "id":"certificate-object-" + c["name"]}])).hexdigest()[:40]
        state_require(isinstance(objects, list) and len(objects) == 3 and isinstance(service, list) and
                      len(service) == 5, "ownership")
        for origin in objects + service:
            if origin is not None:
                state_fields(origin, "operation recipe_sha256 uid")
        state_require(r["scope"] == b["scope"] and r["owner"] == b["owner"] and r["operation"] == b["operation"] and
                      r["profile_sha256"] == b["fingerprints"]["profile_sha256"] and r["cluster"] and
                      r["version"] == profile["k3s_version"] and r["first_server"]["role"] == "server" and
                      r["first_server"]["node_uid"] is not None and b["recipient"] == r["first_server"] and
                      opaque(r["registry"]) and opaque(r["anchor_uid"]) and r["stage"] in ("create", "observe") and
                      isinstance(e["host"], str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", e["host"]) and
                      e["port"] == 443 and e["origin"] == f"https://{e['host']}:443" and
                      isinstance(t["certificates"], list) and t["certificates"] and
                      all(isinstance(x, str) for x in t["certificates"]) and
                      named and c["certificate"] == "broil-certificate-" + named and
                      c["secret"] == "broil-tls-" + named and opaque(c["uid"]) and opaque(c["cluster_issuer"]) and
                      isinstance(r["ingress"], list) and 0 < len(r["ingress"]) <= 128 and
                      all(map(address, r["ingress"])) and None not in service and opaque(service[0]["uid"]) and
                      all((x is None) == create for x in objects) and
                      (create or expected["objects"] == [x["uid"] for x in objects]), "ownership")
        self.wanted = self.renders()

    def renders(self):
        """The three renders, each with its metadata."""
        r, host = self.recipe, self.recipe["endpoint"]["host"]

        def route(match, service, tls):
            return {"entryPoints":["websecure"], "routes":[{"kind":"Rule", "match":match, "services":[service]}],
                    "tls":tls}
        specs = ({"podSelector":{"matchLabels":SERVICE}, "policyTypes":["Ingress"], "ingress":[{"from":[{
                      "namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"kube-system"}},
                      "podSelector":{"matchLabels":{"app.kubernetes.io/name":"traefik",
                                                    "app.kubernetes.io/instance":"traefik-kube-system"}}}],
                      "ports":[{"protocol":"TCP", "port":5000}]}]},
                 route(f"Host(`{host}`) && PathPrefix(`/.broil-tls/`)", {"kind":"TraefikService", "name":"noop@internal"},
                       {"secretName":r["certificate"]["secret"]}),
                 route(f"Host(`{host}`)", {"name":"broil-registry", "port":5000}, {}))
        return [{"apiVersion":row[1], "kind":row[0], "metadata":{"name":name, "namespace":space, "labels":EDGE,
                 "annotations":self.annotations(n)}, "spec":specs[n]}
                for n, (row, (space, name)) in enumerate(zip(EDGES, PLACES))]

    @staticmethod
    def project(n, obj, render):
        """The projection: `metadata.generation` with the complete `spec`, and the render's."""
        return {"generation":obj["metadata"].get("generation"), "spec":obj.get("spec")}, {"generation":1,
                                                                                          "spec":render["spec"]}

    def issued(self):
        """`issued`: the Certificate's read, then the issued Secret's through `ISSUED`."""
        c, where, reads = self.recipe["certificate"], ("--namespace", "cert-manager", "--ignore-not-found"), []
        for args in (("certificates.cert-manager.io", c["certificate"], *where, "-o", "json"),
                     ("secrets", c["secret"], *where, "-o", "go-template=" + ISSUED)):
            try:
                reads.append(kubectl(self.executable, self.binding["owner"], "get", *args, output_limit=262144))
            except Refused as error:
                state_require(error.code != 4, "bound")
                reads.append(None)
            except subprocess.SubprocessError:
                reads.append(None)
        cert, secret = reads
        try:
            obj = cert.strip() and decode(cert)
            state_require(not obj or obj["kind"] == "Certificate" and obj["metadata"]["name"] == c["certificate"] and
                          opaque(obj["metadata"]["uid"]))
            state = "deleted" if not obj or obj["metadata"]["uid"] != c["uid"] else None
        except (Refused, StateRefused, ValueError, TypeError, KeyError, AttributeError):
            return {"state":"unobservable", "leaf_sha256":None}
        found, leaf = "absent", None
        try:
            # Output other than exactly three fields is discarded unparsed.
            fields = secret.decode("ascii").split("\t") if secret else ()
            state_require(secret == b"" or len(fields) == 3 and opaque(fields[1]))
            der = fields and fields[0] == "kubernetes.io/tls" and leaf_of(base64.b64decode(fields[2], validate=True))
            if der:
                found, leaf = "present", hashlib.sha256(der).hexdigest()
        except (StateRefused, AttributeError, ValueError):
            found = "unobservable"
        return {"state":state or found, "leaf_sha256":leaf if (state or found) in ("present", "deleted") else None}

    def served(self, leaf):
        """`served`: each ingress member's TLS, concurrently, trusting exactly the catalog CA."""
        r = self.recipe
        host, members = r["endpoint"]["host"], r["ingress"]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        try:
            context.load_verify_locations(cadata="".join(block + "\n" for block in r["trust"]["certificates"]))
        except (ssl.SSLError, ValueError):
            return [{"state":"not-ready", "reason":"untrusted"} for _ in members]
        out = [{"state":"not-ready", "reason":"unobservable"} for _ in members]

        def one(n, member):
            # One cap from the connect through the last read; its expiry is `unobservable`, never `unreachable`.
            end, step, reason = min(DEADLINE, time.monotonic() + 8), "unreachable", "unobservable"
            left = lambda: max(0.001, end - time.monotonic())
            try:
                with socket.create_connection((member, 443), timeout=left()) as raw:
                    raw.settimeout(left())
                    with context.wrap_socket(raw, server_hostname=host) as tls:
                        step, mine = "unobservable", hashlib.sha256(tls.getpeercert(True)).hexdigest()
                        if leaf is not None and mine != leaf:
                            reason = "stale"
                        elif leaf is not None:
                            tls.settimeout(left())
                            tls.sendall(b"GET /v2/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host.encode())
                            head = b""
                            while b"\r\n\r\n" not in head and len(head) <= 16384:
                                tls.settimeout(left())
                                chunk = tls.recv(16385 - len(head))
                                if not chunk:
                                    break
                                head += chunk
                            complete = 0 <= head.find(b"\r\n\r\n") <= 16380
                            reason = ("unobservable" if not complete else
                                      None if distribution(head[:head.find(b"\r\n\r\n")]) else "backend")
            except ssl.SSLCertVerificationError as error:
                reason = "name" if error.verify_code == 62 else "untrusted"
            except TimeoutError:
                reason = "unobservable"
            except OSError:
                reason = step
            except Exception:
                reason = "unobservable"
            out[n] = {"state":"not-ready" if reason else "ready", "reason":reason}
        threads = [threading.Thread(target=one, args=item, daemon=True) for item in enumerate(members)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        return out

    def inspect(self, result):
        """The three facts, read in order."""
        objects = [self.read(n)[0] for n in range(3)]
        issued = self.issued()
        result.update(objects=objects, issued=issued, served=self.served(issued["leaf_sha256"]))

    def namespace(self, name):
        """The recheck read: the Namespace's UID while it exists and is not being deleted, else None."""
        try:
            raw = kubectl(self.executable, self.binding["owner"], "get", "namespaces", name, "--ignore-not-found",
                          "-o", "json", output_limit=262144)
            meta = decode(raw)["metadata"] if raw.strip() else {"deletionTimestamp":None}
            return None if "deletionTimestamp" in meta else meta["uid"]
        except Refused as error:
            state_require(error.code != 4, "bound")
        except (StateRefused, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError):
            pass
        raise StateRefused("readiness")

    def create_object(self, result):
        """`create-object`: the selected absent endpoint object, created once."""
        self.active()
        r, res, pre, n = self.recipe, self.header["resource"], self.header["preflight"], self.header["object_ordinal"] - 1
        meta = self.wanted[n]["metadata"]
        state_require(r["stage"] == "create" and isinstance(res, dict) and res == dict(
            res, kind="service", id="registry-endpoint-object-%02d" % (n + 1), owner=r["owner"], machine=None, path=None,
            namespace=meta["namespace"], name=meta["name"], uid=None) and isinstance(pre, dict) and
                      set(pre) == {"objects", "issued"} and isinstance(pre["objects"], list) and
                      len(pre["objects"]) == 3 and isinstance(pre["objects"][n], dict) and
                      pre["objects"][n].get("class") == "absent" and isinstance(pre["issued"], dict) and
                      set(pre["issued"]) == {"state", "leaf_sha256"}, "ownership")
        state_hex(res["generation"])
        previous = self.begin()
        if previous is not None:
            result["terminal"] = previous
            return
        self.revalidate()
        # The recheck immediately before the effect: the object absent, its Namespace present with its UID.
        current = self.read(n)[0]["class"]
        state_require(current != "unobservable", "readiness")
        state_require(current == "absent" and self.namespace(meta["namespace"]) == (
            r["anchor_uid"] if n == 1 else r["origins"]["service"][0]["uid"]), "ownership")
        state_require(DEADLINE - time.monotonic() >= 50, "timeout")
        self.effect_started = True
        uid = kubectl(self.executable, self.binding["owner"], "create", "-f", "-", "-o", "jsonpath={.metadata.uid}",
                      input=canonical(self.wanted[n]) + b"\n", output_limit=512, timeout="40s", seconds=45).decode()
        state_require(opaque(uid))
        result["terminal"] = self.terminal("succeeded", None, res, uid)

    def run(self, result):
        if self.tag == "inspect-objects":
            self.inspect(result)
        else:
            self.create_object(result)


# Each protocol's receiver, reply magic, own header fields, tags, reply reserve, initial facts and version.
PROTOCOLS = {"broil-k3s-network":(NetworkReceiver, b"BK3SNET1\n", "object_ordinal original_recipe_sha256",
                                  ("inspect-host", "inspect-objects", "create-object"), 20480,
                                  {"hosts":None, "objects":None, "services":"unobserved", "storage":"unobserved"}, 1),
             "broil-k3s-registry-storage":(StorageReceiver, b"BK3SRGS2\n", "expected member",
                                           ("inspect-storage", "create-storage", "inspect-objects"),
                                           8192, dict.fromkeys(("storage", "nodes")), 2),
             "broil-k3s-registry-service":(ServiceReceiver, b"BK3SRSV2\n", "expected object_ordinal member",
                                           ("inspect-host", "import-image", "inspect-objects", "create-object"), 16384,
                                           dict.fromkeys(("generation", "image", "runtime", "storage", "objects",
                                                          "process", "nodes")), 2),
             "broil-k3s-registry-endpoint":(EndpointReceiver, b"BK3SREP1\n", "expected object_ordinal",
                                            ("inspect-objects", "create-object"), 16384,
                                            dict.fromkeys(("objects", "issued", "served")), 1)}


def network_request(raw, header):
    global DEADLINE
    kind, _, field, tags, reserve, _, version = PROTOCOLS[header["protocol"]]
    state_require(17 + len(raw) + reserve <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms recipe resource preflight " + field)
    state_require(canonical(header) == raw, "integrity")
    state_require(type(header["version"]) is int and header["version"] == version,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > version else
                  "integrity")
    tag = header["action"]
    state_require(tag in tags, "capability")
    mutation = tag.startswith(MUTATIONS)
    state_hex(header["request_id"])
    state_binding(header["binding"])
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation, "ownership")
    state_require(len(canonical(header["binding"])) <= 4096 and len(canonical(header["recipe"])) <= 32768,
                  "bound")
    if kind is NetworkReceiver:
        state_require((header["object_ordinal"] is None and header["resource"] is None and
                       header["preflight"] is None) != mutation, "ownership")
        if header["original_recipe_sha256"] is not None:
            state_require(not mutation, "ownership")
            state_hex(header["original_recipe_sha256"], 64)
        if tag != "inspect-host":
            state_require(header["binding"]["recipient"] == header["recipe"]["first_server"], "ownership")
    else:
        expected, count = header["expected"], 3 if kind is EndpointReceiver else 5
        if kind is not StorageReceiver:
            state_fields(expected, "objects" if count == 3 else "storage objects")
            ordinal, objects = header["object_ordinal"], expected["objects"]
            state_require(isinstance(objects, list) and len(objects) == count and
                          all(uid is None or opaque(uid) for uid in objects) and
                          (ordinal is None) != (tag == "create-object"), "ownership")
            if ordinal is not None:
                state_uint(ordinal, 1, count)
            expected = expected.get("storage")
        if expected is not None:
            state_fields(expected, " ".join(ORIGIN))
        state_require((header["resource"] is None) != mutation and (header["preflight"] is None) != mutation, "ownership")
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    state_require(sys.stdin.buffer.read(1) == b"", "integrity")


def network_main(raw, header):
    kind, magic, _, _, _, facts, _ = PROTOCOLS[header["protocol"]]
    receiver = None
    status = "unknown"
    result = {"terminal":None, **facts, "failure":None}
    prefix = magic + struct.pack(">I", len(raw)) + raw
    try:
        network_request(raw, header)
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
        if receiver is not None and receiver.intent is not None:
            try:
                result["terminal"] = receiver.terminal("failed", failure,
                                                       None if kind is NetworkReceiver else header["resource"])
                status = "failed"
            except BaseException:
                status = "unknown"
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root, receiver.executable):
                if fd is not None:
                    os.close(fd)
    if status != "ok" and kind is not NetworkReceiver:
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
    network_main(raw, header)
    os._exit(0)
except Exception:
    os._exit(125)
