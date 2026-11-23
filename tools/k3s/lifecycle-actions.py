#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
"""Closed, request-bound K3s lifecycle actions."""
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
import stat
import struct
import subprocess
import sys
import time

ROOT = "/var/lib/broil/k3s"
PROFILE = ROOT + "/action-profile.json"
K3S = "/usr/local/libexec/broil-k3s"
RANCHER = "/var/lib/rancher"
DATA = RANCHER + "/k3s"
DATASTORE = DATA + "/server"
IMAGES = DATA + "/agent/images"
ETC = "/etc/rancher"
CONFIG = ETC + "/k3s/config.yaml"
SYSTEMD = "/etc/systemd/system"
UNIT = SYSTEMD + "/broil-k3s.service"
SERVICE = "broil-k3s.service"
AGENT_UNIT = SYSTEMD + "/broil-k3s-agent.service"
AGENT_SERVICE = "broil-k3s-agent.service"
MAXIMUM = 1048576
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
EFFECTS = False
DEADLINE = time.monotonic() + 7200
WRITERS_SETTLED = True
# Hash-bound service guard, carried as xz/base85.
GUARD = '{Wp48S^xk9=GL@E0stWa761SMbT8$j;1Bi&DqR2(h(bq-BQwKy4>SE(XCGcZ`#1HFdES(Qmwmq?=93+I&Bu{+e~Jp-`keDB9+f75m+Oyj)m+;M2*B-|%MaLCN2E)p<as-}_d*0Pg{bv-;ntS%2-)?eHMYUlNj`_u<l7pKmoN|3W5o2R<$AmC<i8wol$~?W@j{ED`C!pklFBbc9h?QHmD^X!O*9i}1Z3c2UG0rC;z%@vFfmy^DDbak0_9-9sG0*2&<t{&?dvis|CD@-S15m}C9;VLy%`B=xAxiKIpZ&odlnX*Kf3%>?q_2yxYS>!{&$xxdgI&q4AG4UB&bn`K04*ujNTlZB$=U%bZl7W6fX@Ft+e8C4M`v)#D;6--gM8vc~p`Qz2Mb*FUr>QZe2LU3e`KLqv|D<8s84*jUA~ELE>2m%xVx`n}yuUqOJ{~ExXMC{o$2iqVJI;!CgOBQRCBU3w}?tcXxvZ2ZU&d`q?}Gy#MAXnIx+Gu|%dO1~wSl#3Iqxo2I$*-K7T||5spZ;AoEAD?E;u{R0%c^M#ust8l{ROcGp)CWf3hKT!f0r{;OenCiTI4*VQ)CFOPuzf4e|5e{~l`gFFzH!(?~w>2}UC3K~g_vLp<%fDPDeuP&S@AAxSJDJ_zbf#t^Cnj3w83(kS{-)J1kNY=ejOGT7_BKO29q<dIlf3`&uAANWeZ)6<oVHgdLE*~x6p;_LW5x3BRtU}yGCF0RCDa)|r=E&7(uOW$>k_#6?z?=<ACto>fC(uslkK4f-n%uT;I6PxG^tdP#;BHZjxm!P@NP{2eYgF72G78&Z(7EvEa`2KfMgY#$B{T@af;kBm1WZWQJ2>@vasg1G%;^;%Pa;+wu99RZ^W|Ao=Mm4SX51Y8V*}Ks)8k}Ui|`pG^&uwPnZL0Qr3i1qAdY^%=<6(y?}{f<TG(wBwK`Il@J`nq|r@)>2i<>`$p)!4#BJY7gj)E+M$mkCtgINcl9p!5W3-L;X7=w$!FOo_77-Q`8Axr=l-48#*r^XW%?v5cjChSNQ}L)PXWHaGgReJLjn#!;=>0yO3F&X!!Xd_wBnAv&9!+7^GBK(GXs@Mektyx-H<2_1y_jlbm=)mq&2({pdnY3nC3||q+wmFPoM%6D2ZSbruaD@OL{Jky<?CBm(Lbd@O%bZgN2MYVK+5;Wx`DNrBc5_0DMN5{RoM3jq(A>i%(8e6)90#_<k!FGPwBOqYCziAPslWysWR745-$8DnHXxBlHD~SWIO-rjmH)4)~_Tl)4{h0?ATfw-AUm32goNA4C?)|Cvt1m|Gzs1_EG`@xD3ud)T=SnZL<IYS{K-SLS~9hjx{b<+m|@+FF2i!uXU8wo8b|JeK>$s|P?$Km*W_t>=6<f=y}t*b}agH8(0q<lL<_|5N*FUNX^A1-hgavO!>3h%I#Fu*(`YKy$buXritt`C}XIX8*EZ7(GXE*_WcnkntXkm$6z_NTpc#I-a#ks#a6>_W%%ij_N>ByT`hyN`65TR$1|6Cu_!?#lyhOD#(Q_@s;OvHG4&sW|g!K4RQ1>O|$O~R8>k24jQT3KF*TF5Zy0<3TFjU;nSjqEp6TZHg9_S3AOt$KIW3eKHG*E{h%S^i(e2a>iag<H%t{Nk<b2YpllX~3+g;KEq;$Q`c;v0gP0V3fU>UKmrn6Xd<(aJA*CtovqZ`_!5D17Jo}UpeZk9M%(&ep*Fm%|Qi#$a+H0NJ8uDdZ5q2e{MdNyzEh)$;cHH#!t2K9l%P3tsVNevXgc6Yb8)szo4|`HF1U$3ldo^~i2PPbeAdq9SX;;^%$k5bydb;)Wx*7a4fHT0tVBM>|7v*F49If>O4qlrDf8w+r3_9XL4YH0nHKo4%!FrlFf!)(-L+q#JSc`1&1Af1{YpnXvJ!QNdx1=m0#&9aXT=!iq;8yRXC=5+N&tV|uMouV&lJL>_gEH2z;}nOEKtXnAK%JP@qKOx1m9>JTTmM<Ay%pDb?FN{B4ROtVgdc$v1?=h#QgL&{gO{j{g4j0=U!j7XqZ1lHR;jY624ZkI1YR}B3IG5A-hR3&JzX!u00G7f_a6WNCJx`tvBYQl0ssI200dcD'
LIFE_RESERVE = 6249
LIFE_TAINT = r"[^=\s]+=[^:\s]*:(NoSchedule|PreferNoSchedule|NoExecute)"
LIFE_RESOURCE = "kind id owner generation machine path namespace name uid"
LIFE_AGENT_ACTIONS = ("inspect-agent", "observe-agent-membership", "activate-agent", "start-agent", "observe-agent", "publish-agent")
LIFE_READS = ("inspect-installation", "observe-server", "inspect-owned-server", "inspect-join", "observe-membership", "observe-join",
              "inspect-agent", "observe-agent-membership", "observe-agent")
LIFE_JOIN_ACTIONS = ("inspect-owned-server", "inspect-join", "observe-membership", "activate-join", "start-join", "observe-join", "publish-member")
LIFE_ACTIONS = LIFE_READS + ("activate-server", "start-server", "publish-identity", "publish-cluster", "prepare-join-source",
                            "activate-join", "start-join", "publish-member", "activate-agent", "start-agent", "publish-agent")
LIFE_FIRST = ("activate-server", "start-server", "observe-server", "publish-identity", "prepare-join-source",
              "inspect-owned-server", "inspect-join", "observe-membership", "activate-join", "start-join", "observe-join", "publish-member")
LIFE_KEYS = ("api", "quorum", "nodes", "services", "storage", "publication")
LIFE_RIS = "recipe_identity_sha256"
LIFE_FACTS = ("operation", "attempt", "recipe_sha256", LIFE_RIS, "marker_sha256", "config_sha256", "unit_sha256", "guard_sha256")
LIFE_DISABLE = ["coredns", "local-storage", "metrics-server", "servicelb", "traefik"]


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


def command(fd, args, input=None, allowed=(0,), extra_fds=(), limits=(MAXIMUM, MAXIMUM)):
    global WRITERS_SETTLED
    require(time.monotonic() < DEADLINE, 6)
    process = subprocess.Popen([f"/proc/self/fd/{fd}", *args], pass_fds=(fd, *extra_fds),
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
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
    until = min(DEADLINE, time.monotonic() + 20)
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
        if input is not None and not completed:
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


def kubectl(fd, owner, *args, input=None, output_limit=MAXIMUM):
    kubeconfig = f"{ROOT}/owners/{owner}/admin.yaml"
    read_file(kubeconfig, 65536)
    return command(fd, ["kubectl", "--kubeconfig", kubeconfig, "--request-timeout=10s", *args], input,
                   limits=(output_limit, MAXIMUM))


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


# ---- Lifecycle helpers ----
def life_guard():
    """The guard bytes: one complete xz stream."""
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
    raw = decompressor.decompress(base64.b85decode(GUARD), 4097)
    state_require(len(raw) <= 4096 and decompressor.eof and not decompressor.unused_data, "bound")
    return raw


def life_unit(owner):
    s = f"{ROOT}/owners/{owner}/service"
    return ("[Unit]\nDescription=Broil K3s server (" + owner + ")\nAfter=network-online.target\nWants=network-online.target\n"
            "StartLimitIntervalSec=300s\nStartLimitBurst=5\n\n[Service]\nType=simple\nUMask=0022\n"
            "ExecStartPre=/usr/bin/python3 " + s + "/guard.py\nExecStart=" + K3S + " server --config " + CONFIG + "\n"
            "StandardOutput=append:" + s + "/service.log\nStandardError=append:" + s + "/service.log\nKillMode=process\nDelegate=yes\n"
            "LimitNOFILE=1048576\nLimitNPROC=infinity\nLimitCORE=0\nTasksMax=infinity\nTimeoutStartSec=0\nRestart=always\nRestartSec=5s\n\n"
            "[Install]\nWantedBy=multi-user.target\n").encode()


def life_agent_unit(owner):
    return life_unit(owner).replace(b"Broil K3s server (", b"Broil K3s agent (").replace(
        b"broil-k3s server --config", b"broil-k3s agent --config")


def life_config(recipe, owner):
    """The closed rendered configuration."""
    c, m, active = recipe["config"], recipe["member"], f"{ROOT}/owners/{owner}/active/"
    joined = "source" in recipe
    state_fields(c, ("server" if joined else "cluster-init") + " token-file agent-token-file node-name node-ip advertise-address tls-san cluster-cidr service-cidr cluster-dns "
                    "cluster-domain flannel-backend secrets-encryption write-kubeconfig write-kubeconfig-mode disable "
                    "disable-default-registry-endpoint etcd-expose-metrics kube-apiserver-arg node-label node-taint")
    state_require(c["token-file"] == active + "server-token" and c["agent-token-file"] == active + "agent-token" and
                  c["write-kubeconfig"] == f"{ROOT}/owners/{owner}/admin-raw.yaml", "ownership")
    state_require((isinstance(c["server"], str) and c["server"].startswith("https://") if joined else c["cluster-init"] is True) and
                  c["secrets-encryption"] is True and c["disable-default-registry-endpoint"] is True and
                  c["etcd-expose-metrics"] is False and c["flannel-backend"] == "vxlan" and c["write-kubeconfig-mode"] == "0600" and
                  c["disable"] == LIFE_DISABLE and c["kube-apiserver-arg"] == ["anonymous-auth=false"] and c["node-name"] == m["member"])
    state_require(str(ipaddress.IPv4Address(c["node-ip"])) == c["node-ip"] == c["advertise-address"] and
                  str(ipaddress.IPv4Address(c["cluster-dns"])) == c["cluster-dns"] and
                  all(str(ipaddress.IPv4Network(c[k])) == c[k] for k in ("cluster-cidr", "service-cidr")))
    state_require(isinstance(c["cluster-domain"], str) and re.fullmatch(r"[a-z0-9.-]{1,253}", c["cluster-domain"]) is not None)
    state_require(isinstance(c["tls-san"], list) and all(isinstance(s, str) and s for s in c["tls-san"]), "bound")
    labels, taints = c["node-label"], c["node-taint"]
    state_require(isinstance(labels, list) and all(isinstance(l, str) and re.fullmatch(r"[^=\s]+=[^=\s]*", l) for l in labels))
    keys = [l.split("=", 1)[0].encode() for l in labels]
    state_require(keys == sorted(keys) and len(set(keys)) == len(keys))
    state_require(isinstance(taints, list) and all(isinstance(t, str) and re.fullmatch(LIFE_TAINT, t) for t in taints))


def life_identity(value):
    state_fields(value, "cluster node_uid data")
    state_cluster(value["cluster"])
    state_require(value["cluster"] is not None and opaque(value["node_uid"]) and isinstance(value["data"], list) and len(value["data"]) == 2)
    for item in value["data"]:
        state_uint(item)


def life_raw(owner):
    """One K3s-owned raw generation, read twice."""
    path = f"{ROOT}/owners/{owner}/admin-raw.yaml"
    parent = state_directory(str(Path(path).parent))
    fd = None
    try:
        fd = os.open("admin-raw.yaml", os.O_RDONLY | NOFOLLOW, dir_fd=parent)
        before = os.fstat(fd)
        state_require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1 and
                      stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= 65536, "ownership")
        first = os.read(fd, 65537)
        state_require(len(first) == before.st_size and not os.read(fd, 1), "ownership")
        os.lseek(fd, 0, os.SEEK_SET)
        second = os.read(fd, 65537)
        after = os.fstat(fd)
        state_require(first == second and not os.read(fd, 1) and
                      (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                      (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
                      identity(fd) == state_file_identity(path), "ownership")
        return first
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def life_decode_raw(raw):
    """The pinned writer's raw kubeconfig shape."""
    state_require(0 < len(raw) <= 65536 and raw.endswith(b"\n"), "credential")
    lines = raw.splitlines(keepends=True)
    prefix = [b"apiVersion: v1\n", b"clusters:\n", b"- cluster:\n", b"    certificate-authority-data: "]
    state_require(len(lines) in (18, 19) and lines[:3] == prefix[:3] and lines[3].startswith(prefix[3]), "credential")
    ca = lines[3][len(prefix[3]):-1]
    fixed = [b"    server: https://127.0.0.1:6443\n", b"  name: default\n", b"contexts:\n", b"- context:\n",
             b"    cluster: default\n", b"    user: default\n", b"  name: default\n", b"current-context: default\n", b"kind: Config\n"]
    state_require(lines[4:13] == fixed, "credential")
    tail = lines[13:]
    if tail and tail[0] == b"preferences: {}\n":
        tail = tail[1:]
    state_require(len(tail) == 5 and tail[0] == b"users:\n" and tail[1] == b"- name: default\n" and
                  tail[2] == b"  user:\n" and tail[3].startswith(b"    client-certificate-data: ") and
                  tail[4].startswith(b"    client-key-data: "), "credential")
    cert = tail[3][len(b"    client-certificate-data: "):-1]
    key = tail[4][len(b"    client-key-data: "):-1]
    for value in (ca, cert, key):
        state_require(0 < len(value) <= 16384 and len(value) % 4 == 0 and
                      re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", value) is not None, "credential")
        decoded = base64.b64decode(value, validate=True)
        state_require(bool(decoded) and base64.b64encode(decoded) == value, "credential")
    state_require(base64.b64decode(ca) == read_file(DATASTORE + "/tls/server-ca.crt", 65536, private=False), "trust")
    obj = {"apiVersion": "v1", "kind": "Config", "clusters": [{"name": "default", "cluster": {
        "certificate-authority-data": ca.decode("ascii"), "server": "https://127.0.0.1:6443"}}],
        "contexts": [{"name": "default", "context": {"cluster": "default", "user": "default"}}],
        "current-context": "default", "preferences": {}, "users": [{"name": "default", "user": {
            "client-certificate-data": cert.decode("ascii"), "client-key-data": key.decode("ascii")}}]}
    state_require(len(canonical(obj)) + 1 <= 65536, "bound")
    return obj


def life_source_resource(resource, binding):
    state_fields(resource, LIFE_RESOURCE)
    state_hex(resource["owner"])
    state_hex(resource["generation"])
    state_require(resource["kind"] in ("server-input", "agent-input") and opaque(resource["id"]) and
                  resource["owner"] == binding["owner"] and resource["machine"] == binding["recipient"]["machine"] and
                  all(resource[k] is None for k in ("namespace", "name", "uid")), "ownership")
    path = f"{ROOT}/owners/{resource['owner']}/resources/{resource['id']}/{resource['generation']}"
    state_require(resource["path"] == path and len(canonical(resource)) <= 512, "ownership")
    return path


def life_common_recipe(r):
    state_fields(r["assets"], "generation marker_sha256")
    state_hex(r["assets"]["generation"])
    state_hex(r["assets"]["marker_sha256"], 64)
    state_fields(r["input"], "generation")
    state_hex(r["input"]["generation"])
    state_require(isinstance(r["version"], str) and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+\+k3s[0-9]+", r["version"]) is not None)
    for key, name in (("executable", "k3s"), ("archive", "k3s-airgap")):
        a = r[key]
        state_fields(a, "id filename size sha256")
        state_require(a["id"] == name and opaque(a["filename"]))
        state_uint(a["size"], 1)
        state_hex(a["sha256"], 64)
    state_hex(r["guard_sha256"], 64)
    state_hex(r["unit_sha256"], 64)


def life_source_input(r, b, kind):
    source = r["source_input"]
    state_fields(source, LIFE_RESOURCE)
    state_require(source["kind"] == kind and source["owner"] == b["owner"] and
                  source["machine"] == r["source"]["machine"] and
                  source["generation"] == r["input"]["generation"] and
                  source["path"] == f"{ROOT}/owners/{b['owner']}/resources/{source['id']}/{source['generation']}", "ownership")


def life_members(r, b):
    members = r["members"]
    state_require(isinstance(members, list) and 1 <= len(members) <= 128, "bound")
    for member in members:
        state_member(member)
    state_require(len({m["machine"] for m in members}) == len(members) and
                  b["recipient"] in members and b["participants_sha256"] == state_projection(members), "ownership")
    return members


def life_first(members, machine):
    return next((m for m in members if m["role"] == "server" and m["node_uid"] and m["machine"] != machine), None)


def life_agent_recipe(r, b):
    state_fields(r, "schema scope owner operation attempt source member members cluster installed wave assets input source_input "
                 "version executable archive guard_sha256 unit_sha256 config api_endpoint")
    state_require(r["schema"] == 3 and all(r[k] == b[k] for k in ("scope", "owner", "operation", "attempt")), "ownership")
    state_scope(r["scope"])
    state_cluster(r["cluster"])
    members = life_members(r, b)
    state_require(r["source"] == life_first(members, r["member"]["machine"]) and
                  r["source"]["node_uid"] is not None and r["member"] in members and
                  r["member"]["role"] == "agent" and
                  b["recipient"] in (r["source"], r["member"]), "ownership")
    installed = r["installed"]
    state_require(isinstance(installed, list) and 1 <= len(installed) < len(members), "ownership")
    active = [member for member in members if member["role"] != "backup"]
    for index, entry in enumerate(installed):
        state_fields(entry, "member recipe_identity_sha256")
        state_require(index < len(active) and entry["member"] == active[index] and
                      entry["member"]["node_uid"] is not None, "ownership")
        state_hex(entry[LIFE_RIS], 64)
    state_fields(r["wave"], "id index boundary_sha256")
    state_hex(r["wave"]["id"])
    state_uint(r["wave"]["index"], 0, 15)
    state_hex(r["wave"]["boundary_sha256"], 64)
    life_source_input(r, b, "agent-input")
    life_common_recipe(r)
    c = r["config"]
    state_fields(c, "server token-file node-name node-ip node-label node-taint disable-default-registry-endpoint")
    state_require(c["disable-default-registry-endpoint"] is True and isinstance(c["server"], str) and
                  c["server"].startswith("https://") and c["server"] != "https://127.0.0.1:6443" and
                  c["token-file"] == f"{ROOT}/owners/{b['owner']}/active/agent-token" and
                  c["node-name"] == r["member"]["member"] and
                  str(ipaddress.IPv4Address(c["node-ip"])) == c["node-ip"], "ownership")
    state_require(isinstance(c["node-label"], list) and isinstance(c["node-taint"], list) and
                  all(isinstance(v, str) and re.fullmatch(r"[^=\s]+=[^=\s]*", v) for v in c["node-label"]) and
                  all(isinstance(v, str) and re.fullmatch(LIFE_TAINT, v)
                      for v in c["node-taint"]), "configuration")


def life_recipe(r, b):
    """Validate recipe shape and binding."""
    if r.get("schema") == 3:
        life_agent_recipe(r, b)
        return
    joined = "source" in r
    fields = "schema scope owner operation attempt member members assets input version executable archive guard_sha256 unit_sha256 config api_endpoint"
    state_fields(r, fields + (" source cluster installed source_input" if joined else ""))
    state_require(r["schema"] == 2)
    state_scope(r["scope"])
    state_require(all(r[k] == b[k] for k in ("scope", "owner", "operation", "attempt")), "ownership")
    members = life_members(r, b)
    state_require(r["member"] in members and r["member"]["role"] == "server", "ownership")
    if joined:
        state_cluster(r["cluster"])
        servers = [member for member in members if member["role"] == "server"]
        state_require(r["cluster"] is not None and r["source"] == life_first(members, r["member"]["machine"]) and
                      r["source"]["node_uid"] is not None and r["member"] != r["source"] and
                      len(servers) == 3 and isinstance(r["installed"], list) and
                      1 <= len(r["installed"]) <= 3 and
                      [entry["member"] for entry in r["installed"]] == [m for m in servers if m["node_uid"]][:len(r["installed"])],
                      "ownership")
        life_source_input(r, b, "server-input")
        for installed in r["installed"]:
            state_fields(installed, "member recipe_identity_sha256")
            state_member(installed["member"])
            state_require(installed["member"]["node_uid"] is not None, "ownership")
            state_hex(installed[LIFE_RIS], 64)
    else:
        state_require(r["member"] == members[0], "ownership")
    life_common_recipe(r)
    life_config(r, b["owner"])
    state_require(isinstance(r["api_endpoint"], str) and r["api_endpoint"].startswith("https://") and
                  r["api_endpoint"] != "https://127.0.0.1:6443", "configuration")


def life_member_list(raw):
    state_require(0 < len(raw) <= 65536, "bound")
    try:
        wire = decode(raw)
    except (ValueError, UnicodeDecodeError, TypeError):
        raise StateRefused("integrity")
    state_fields(wire, "members")
    state_require(isinstance(wire["members"], list) and 1 <= len(wire["members"]) <= 3, "integrity")
    members, ids, names, peers = [], set(), set(), set()
    for item in wire["members"]:
        state_require(isinstance(item, dict) and {"ID", "peerURLs"} <= set(item) <=
                      {"ID", "name", "peerURLs", "clientURLs", "isLearner"}, "integrity")
        ident, name = item["ID"], item.get("name", "")
        state_require(type(ident) is int and 1 <= ident <= 18446744073709551615 and ident not in ids and
                      isinstance(name, str) and len(name.encode("utf-8")) <= 262 and
                      (not name or re.fullmatch(r"[A-Za-z0-9_.-]+", name) is not None) and
                      (not name or name not in names), "integrity")
        peer, clients, learner = item["peerURLs"], item.get("clientURLs", []), item.get("isLearner", False)
        state_require(isinstance(peer, list) and len(peer) == 1 and type(peer[0]) is str and
                      re.fullmatch(r"https://[0-9.]+:2380", peer[0]) is not None and
                      peer[0] not in peers and isinstance(clients, list) and
                      len(clients) <= 1 and type(learner) is bool and
                      (not clients or type(clients[0]) is str and
                       clients[0] == peer[0][:-4] + "2379"), "integrity")
        address = peer[0][8:-5]
        state_require(str(ipaddress.IPv4Address(address)) == address, "integrity")
        ids.add(ident)
        peers.add(peer[0])
        if name:
            names.add(name)
        members.append({"id": ident, "name": name, "peer_urls": peer,
                        "client_urls": clients, "learner": learner})
    return sorted(members, key=lambda member: member["id"])


def life_run(args):
    left = DEADLINE - time.monotonic()
    state_require(left > 0, "timeout")
    result = subprocess.run(args, capture_output=True, timeout=left, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    state_require(len(result.stdout) < 65536 and len(result.stderr) < 65536, "bound")
    return result.returncode, result.stdout.decode("ascii", "replace")


def life_exists(path):
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False


def life_dir(path, mode):
    """A trusted root directory at a mode."""
    parent, _ = directory(str(Path(path).parent))
    try:
        try:
            os.mkdir(Path(path).name, mode, dir_fd=parent)
        except FileExistsError:
            return
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=parent)
        try:
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def life_write(path, data, mode):
    """An exclusive, synced root file; its identity."""
    global EFFECTS
    parent, _ = directory(str(Path(path).parent))
    try:
        state_check()
        fd = os.open(Path(path).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, mode, dir_fd=parent)
        try:
            EFFECTS = True
            os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                count = os.write(fd, view)
                state_require(count > 0, "storage")
                view = view[count:]
            os.fsync(fd)
            os.fsync(parent)
            return identity(fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def life_file(path, mode, digest=None, size=None):
    """A root-owned regular file's identity."""
    parent, _ = directory(str(Path(path).parent))
    try:
        fd = os.open(Path(path).name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        st = os.fstat(fd)
        state_require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == mode and
                      (size is None or st.st_size == size), "ownership")
        if digest is not None:
            state_require(life_digest(fd) == digest, "ownership")
        return identity(fd)
    finally:
        os.close(fd)


def life_digest(fd):
    hasher = hashlib.sha256()
    while chunk := os.read(fd, 1048576):
        state_check()
        hasher.update(chunk)
    return hasher.hexdigest()


def life_data_id():
    fd, _ = directory(DATA)
    try:
        return identity(fd)
    finally:
        os.close(fd)


class LifeReceiver:
    def __init__(self, header):
        self.header = header
        self.binding = header["binding"]
        self.tag = header["action"]
        self.action = "lifecycle:" + self.tag
        self.payload = header["payload"]
        self.recipe = self.payload["recipe"]
        self.root = self.lock = None
        self.root_id = self.lock_id = None
        self.claim = self.reservation = None
        self.intent = None
        self.effect_started = False
        self.pins = self.executable = None
        b, r = self.binding, self.recipe
        self.agent = r.get("schema") == 3
        first = b["recipient"] == r["member"]
        state_require(first if self.tag in LIFE_FIRST else not first if self.tag == "publish-cluster" else True, "ownership")
        if self.tag in LIFE_AGENT_ACTIONS:
            state_require((not first if self.tag == "observe-agent-membership" else first), "ownership")
        joined = "source" in r
        self.recipe_hash = state_hash("broil-k3s-agent-recipe-v1" if self.agent else
                                      "broil-k3s-join-recipe-v2" if joined else "broil-k3s-server-recipe-v2", r)
        omitted = ("operation", "attempt", "members", "installed", "wave") if self.agent else \
            ("operation", "attempt", "members", "installed") if joined else ("operation", "attempt", "members")
        projection = dict({k: v for k, v in r.items() if k not in omitted}, member=dict(r["member"], node_uid=None))
        self.identity_hash = state_hash("broil-k3s-agent-recipe-identity-v1" if self.agent else
                                        "broil-k3s-join-recipe-identity-v2" if joined else "broil-k3s-server-recipe-identity-v2", projection)
        self.unit = life_agent_unit(b["owner"]) if self.agent else life_unit(b["owner"])
        self.guard = life_guard()
        state_require(hashlib.sha256(self.unit).hexdigest() == r["unit_sha256"] and hashlib.sha256(self.guard).hexdigest() == r["guard_sha256"], "ownership")
        self.config_hash = hashlib.sha256(canonical(r["config"]) + b"\n").hexdigest()
        self.owner_path = f"{ROOT}/owners/{b['owner']}"

    def profile(self):
        state_require(os.geteuid() == 0, "ownership")
        b = self.binding
        state_require(os.environ.get("BROIL_MACHINE") == b["recipient"]["machine"] and os.environ.get("BROIL_ENV") == b["scope"]["environment"], "ownership")
        raw = read_file(PROFILE, 16384, private=False)
        profile = decode(raw)
        bodies = profile.get("bodies")
        state_require(isinstance(bodies, dict) and hashlib.sha256(raw).hexdigest() == b["fingerprints"]["profile_sha256"] and
                      profile["script_sha256"] == b["fingerprints"]["script_sha256"] == bodies.get("control") and
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == bodies.get("lifecycle") and
                      hashlib.sha256(self.guard).hexdigest() == bodies.get("service_guard"), "ownership")
        tools = b["fingerprints"]["tools"]
        state_require(len(tools) == 2 and tools[0]["name"] == "bootstrap-index" and tools[1] == {"name": "k3s", "sha256": profile["k3s_sha256"]}, "capability")
        state_require(self.recipe["version"] == profile["k3s_version"] and self.recipe["executable"]["sha256"] == profile["k3s_sha256"], "ownership")
        self.executable = tool(profile)
        self.executable_identity = identity(self.executable)
        self.pins = profile
        return profile

    def open(self):
        try:
            self.root = state_directory(ROOT)
        except FileNotFoundError:
            return False
        self.root_id = identity(self.root)
        try:
            self.lock = os.open("mutation.lock", os.O_RDWR | NOFOLLOW, dir_fd=self.root)
        except FileNotFoundError:
            state_require(set(state_names(ROOT, 8)) <= {"action-profile.json"}, "ownership")
            return False
        state_require(state_private(self.lock).st_size == 0)
        try:
            fcntl.flock(self.lock, (fcntl.LOCK_SH if self.tag in LIFE_READS else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateRefused("busy")
        self.lock_id = identity(self.lock)
        self.revalidate()
        self.claim = state_read(ROOT + "/machine-claim.json", "machine-claim")
        if self.claim is not None:
            state_scope(self.claim["scope"])
            state_member(self.claim["member"])
            c, b = self.claim, self.binding
            state_require(c["scope"] == b["scope"] and c["owner"] == b["owner"] and c["participants_sha256"] == b["participants_sha256"] and
                          b["recipient"] in (c["member"], dict(c["member"], node_uid=None)) and
                          c["root_identity"] == self.root_id and c["lock_identity"] == self.lock_id, "ownership")
        self.reservation = state_read(self.attempt_path() + "/reservation.json", "reservation")
        return True

    def revalidate(self):
        state_check()
        fd = state_directory(ROOT)
        try:
            state_require(identity(fd) == self.root_id and state_file_identity(ROOT + "/mutation.lock") == self.lock_id and
                          identity(self.lock) == self.lock_id, "ownership")
        finally:
            os.close(fd)

    def attempt_path(self):
        return ROOT + "/attempts/" + self.binding["attempt"]

    def dispatch_path(self, dispatch=None):
        return ROOT + "/dispatches/" + (dispatch or self.binding["dispatch"])

    def replace(self, path, record):
        self.revalidate()
        expected = state_file_identity(path)
        state_publish(path, record, expected)

    def machine(self):
        return {k:self.binding["recipient"][k] for k in ("machine", "member", "role", "node_uid")}

    def owned(self):
        state_require(self.claim is not None, "ownership")
        value = state_read(self.owner_path + "/ownership.json")
        state_require(value is not None, "ownership")
        state_fields(value, "schema owner scope machine cluster data")
        m = self.machine()
        state_require(value["owner"] == self.binding["owner"] and value["scope"] == {k:self.binding["scope"][k] for k in ("project", "environment", "target")} and
                      (value["machine"] == m or m["node_uid"] is None and dict(value["machine"], node_uid=None) == m), "ownership")
        state_cluster(value["cluster"])
        if value["data"] is not None:
            state_require(life_data_id() == value["data"], "ownership")
        return value

    def active(self):
        self.owned()
        state_require(state_read(self.attempt_path() + "/seal.json", "seal") is None and
                      state_read(self.attempt_path() + "/retirement.json", "retirement") is None, "ownership")
        state_require(self.reservation is not None and self.reservation["state"] in ("reserved", "active") and
                      self.claim["active_attempt"] == self.binding["attempt"] and
                      self.claim["generation"] == self.binding["receiver_generation"], "ownership")
        original = self.reservation["binding"]
        state_require(all(original[k] == self.binding[k] for k in original if k not in ("step", "dispatch")), "ownership")

    def ledger(self):
        path = ROOT + "/dispatches"
        try:
            names = state_names(path, 1048576)
        except FileNotFoundError:
            return []
        work = []
        total = 0
        for name in names:
            state_hex(name)
            directory_path = path + "/" + name
            entries = set(state_names(directory_path, 3)) - {"bootstrap-input.json"}
            state_require(entries in ({"intent.json"}, {"intent.json", "terminal.json"}))
            intent = state_read(directory_path + "/intent.json", "intent")
            state_require(intent is not None and intent["binding"]["dispatch"] == name)
            terminal = state_read(directory_path + "/terminal.json", "terminal")
            if terminal is not None:
                state_require(terminal["binding"] == intent["binding"] and terminal["action"] == intent["action"] and
                              terminal["payload_sha256"] == intent["payload_sha256"] and terminal["writer_ended"] is True)
            if intent["binding"]["attempt"] == self.binding["attempt"]:
                state_require(intent["binding"]["owner"] == self.binding["owner"] and intent["binding"]["scope"] == self.binding["scope"], "ownership")
                total += len(canonical(intent)) + 1 + (len(canonical(terminal)) + 1 if terminal else 0)
                state_require(total <= 33554432 and len(work) < 1024, "bound")
                work.append((name, intent, terminal))
            elif terminal is None:
                raise StateRefused("busy")
        return work

    def begin(self):
        path = self.dispatch_path()
        previous = state_read(path + "/intent.json", "intent")
        if previous is not None:
            state_require(previous["binding"] == self.binding and previous["action"] == self.action and
                          previous["payload_sha256"] == state_hash("broil-infra-step-v1", self.payload), "ownership")
            terminal = state_read(path + "/terminal.json", "terminal")
            state_require(terminal is not None, "busy")
            return terminal
        work = self.ledger()
        state_require(all(t is not None for _, _, t in work), "busy")
        if self.reservation is not None:
            actual = [name for name, intent, _ in work if intent["action"] in STATE_WORK or intent["action"].startswith(("credential:", "bootstrap:", "lifecycle:"))]
            state_require(set(actual) == set(self.reservation["dispatches"]) and len(actual) == len(self.reservation["dispatches"]), "ownership")
        state_require(len(work) < 1024, "bound")
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
        state_publish(path + "/intent.json", self.intent)
        if self.reservation is not None and self.action.startswith(("credential:", "bootstrap:", "lifecycle:")):
            self.reservation["dispatches"].append(self.binding["dispatch"])
            self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        return None

    def terminal(self, outcome, failure, resource=None, resource_identity=None):
        state_require(self.intent is not None and WRITERS_SETTLED, "busy")
        value = {"schema":1, "kind":"terminal", "binding":self.binding, "action":self.action,
                 "payload_sha256":self.intent["payload_sha256"], "outcome":outcome, "failure":failure,
                 "effect":"complete" if outcome == "succeeded" else "unknown" if self.effect_started else "absent",
                 "writer_ended":True, "resource":resource, "resource_identity":resource_identity, "completed_ms":state_now()}
        self.revalidate()
        state_publish(self.dispatch_path() + "/terminal.json", value)
        return value

    # -- classification --
    def present(self):
        o = self.owner_path
        return [p for p in (DATA, ETC + "/k3s", UNIT, AGENT_UNIT, SYSTEMD + "/k3s.service", SYSTEMD + "/k3s-agent.service", o + "/service", o + "/active")
                if life_exists(p)]

    def ownership(self):
        value = state_read(self.owner_path + "/ownership.json")
        if value is None:
            return None
        state_fields(value, "schema owner scope machine cluster data")
        b = self.binding
        state_require(value["owner"] == b["owner"] and value["scope"] == {k:b["scope"][k] for k in ("project", "environment", "target")} and
                      dict(value["machine"], node_uid=None) == dict(self.machine(), node_uid=None), "ownership")
        state_cluster(value["cluster"])
        return value

    def record(self):
        """The re-verified activation record."""
        r, b, s, a = self.recipe, self.binding, self.owner_path + "/service", self.owner_path + "/active"
        record = state_read(s + "/activation.json", schema=3 if self.agent else 2)
        state_require(record is not None, "ownership")
        state_fields(record, "schema kind scope owner operation attempt member recipe_sha256 recipe_identity_sha256 marker_sha256 assets input "
                             "executable archive config_sha256 unit_sha256 guard_sha256 identities api_endpoint")
        ids = record["identities"]
        state_fields(ids, "config unit agent-token guard log" if self.agent else
                     "agent-token archive config guard log server-token unit")
        state_require(record["kind"] == ("agent-activation" if self.agent else "server-activation") and
                      record["schema"] == (3 if self.agent else 2) and record["api_endpoint"] == r["api_endpoint"] and
                      record["scope"] == b["scope"] and record["owner"] == b["owner"] and
                      (not self.agent or record["member"] == dict(r["member"], node_uid=None)) and
                      record[LIFE_RIS] == self.identity_hash and record["assets"] == r["assets"] and record["input"] == r["input"] and
                      record["marker_sha256"] == r["assets"]["marker_sha256"] and record["config_sha256"] == self.config_hash and
                      record["unit_sha256"] == r["unit_sha256"] and record["guard_sha256"] == r["guard_sha256"] and
                      all({k:record[key][k] for k in r[key]} == r[key] for key in ("executable", "archive")), "ownership")
        state_require(self.executable_identity == record["executable"]["identity"], "ownership")
        for path in (s, a):
            os.close(state_directory(path))
        if self.agent:
            state_require(not any(life_exists(p) for p in (UNIT, DATASTORE, self.owner_path + "/admin-raw.yaml",
                          self.owner_path + "/admin.yaml", a + "/server-token")), "ownership")
        archive_id = record["archive"]["identity"]
        state_require(life_file(IMAGES + "/" + r["archive"]["filename"], 0o600, r["archive"]["sha256"], r["archive"]["size"]) == archive_id and
                      (self.agent or archive_id == ids["archive"]) and
                      life_file(CONFIG, 0o600, record["config_sha256"]) == ids["config"] and
                      life_file(AGENT_UNIT if self.agent else UNIT, 0o644, record["unit_sha256"]) == ids["unit"] and
                      life_file(s + "/guard.py", 0o700, record["guard_sha256"]) == ids["guard"] and life_file(s + "/service.log", 0o600) == ids["log"] and
                      (self.agent or life_file(a + "/server-token", 0o600) == ids["server-token"]) and
                      life_file(a + "/agent-token", 0o600) == ids["agent-token"], "ownership")
        return record

    def unit_facts(self):
        code, out = life_run(["systemctl", "show", "-p", "ActiveState", "-p", "SubState", "-p", "UnitFileState",
                              AGENT_SERVICE if self.agent else SERVICE])
        state_require(code == 0, "readiness")
        return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)

    def probe(self, access=None, raw=False):
        """Readiness and identity via the owner's access."""
        readiness = dict.fromkeys(LIFE_KEYS, "unobserved")
        readiness.update(dict.fromkeys(LIFE_KEYS[:3], "not-ready"))
        owner, name, observed = self.binding["owner"], self.recipe["member"]["member"], None
        unpublished = self.ownership()["machine"]["node_uid"] is None
        if access is None and unpublished:
            if not life_exists(f"{ROOT}/owners/{owner}/admin-raw.yaml"):
                return readiness, None
            access = life_raw(owner)
            life_decode_raw(access)
            raw = True
        elif access is None and not life_exists(f"{ROOT}/owners/{owner}/admin.yaml"):
            return readiness, None
        try:
            call = (lambda *args: life_kubectl(self.executable, access, *args)) if access is not None else \
                (lambda *args: kubectl(self.executable, owner, *args))
            if call("get", "--raw=/readyz") == b"ok":
                readiness["api"] = "ready"
            verbose = call("get", "--raw=/readyz?verbose").decode("ascii", "replace")
            if re.search(r"^\[\+\]etcd ok$", verbose, re.M) and re.search(r"^\[\+\]etcd-readiness ok$", verbose, re.M):
                readiness["quorum"] = "ready"
            node = decode(call("get", "node", name, "-o", "json"))
            status = node.get("status", {})
            if status.get("nodeInfo", {}).get("kubeletVersion") == self.recipe["version"] and \
                    any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", [])):
                readiness["nodes"] = "ready"
            config = decode(call("config", "view", "--raw", "--minify", "-o", "json"))
            state_require(len(config["clusters"]) == 1 and set(config["clusters"][0]["cluster"]) == {"server", "certificate-authority-data"} and
                          config["clusters"][0]["cluster"]["server"] ==
                          ("https://127.0.0.1:6443" if raw else self.recipe["api_endpoint"]),
                          "ownership")
            certificate = base64.b64decode(config["clusters"][0]["cluster"]["certificate-authority-data"], validate=True)
            ca = hashlib.sha256(certificate).hexdigest()
            state_require(ca == hashlib.sha256(read_file(DATASTORE + "/tls/server-ca.crt", 65536, private=False)).hexdigest(), "ownership")
            uid = call("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").decode("ascii")
            observed = {"cluster": {"uid": uid, "ca_sha256": ca}, "node_uid": node["metadata"]["uid"], "data": life_data_id()}
            life_identity(observed)
            require(time.monotonic() < DEADLINE, 6)
        except Refused as error:
            if error.code not in (5, 6):
                raise
            readiness.update(dict.fromkeys(LIFE_KEYS[:3], "not-ready"))
            observed = None
        return readiness, observed

    def membership(self, removed=None):
        readiness, observed = self.probe()
        if observed is None:
            return None
        owner = self.binding["owner"]
        raw_access = self.ownership()["machine"]["node_uid"] is None
        access = life_raw(owner) if raw_access else None
        call = (lambda *args: life_kubectl(self.executable, access, *args)) if raw_access else \
            (lambda *args: kubectl(self.executable, owner, *args, output_limit=MAXIMUM))
        raw = call("--server=https://127.0.0.1:6443", "get", "--raw=/db/info")
        members = life_member_list(raw)
        nodes = decode(call("--server=https://127.0.0.1:6443", "get", "nodes", "-o", "json"))
        state_require(isinstance(nodes, dict) and isinstance(nodes.get("items"), list) and
                      len(nodes["items"]) <= 128, "integrity")
        declared = {m["member"]: m for m in self.recipe["members"] if m["role"] == "server"}
        seen, ip, left = set(), removed and removed["node_ip"], 0
        if removed:
            state_require(removed["member"] != self.recipe["member"]["member"] != ip != self.recipe["config"]["node-ip"] and
                          not any(isinstance(n, dict) and isinstance(m := n.get("metadata"), dict) and
                                  (m.get("name") == removed["member"] or
                                   m.get("annotations", {}).get("etcd.k3s.cattle.io/node-address") == ip and
                                   any(e["peer_urls"][0][8:-5] == ip for e in members)) for n in nodes["items"]), "ownership")
        for member in members:
            peer = member["peer_urls"][0][8:-5]
            if peer == ip:
                left += 1
                continue
            if not member["name"] or member["learner"] or not member["client_urls"]:
                continue
            matches = [node for node in nodes["items"] if isinstance(node, dict) and
                       isinstance(node.get("metadata"), dict) and
                       node["metadata"].get("annotations", {}).get("etcd.k3s.cattle.io/node-name") == member["name"]]
            state_require(len(matches) == 1, "ownership")
            node = matches[0]
            meta = node["metadata"]
            name = meta.get("name")
            selected = declared.get(name)
            expected_uid = observed["node_uid"] if name == self.recipe["member"]["member"] else selected["node_uid"] if selected else None
            addresses = node.get("status", {}).get("addresses", [])
            state_require(selected is not None and name not in seen and
                          (meta.get("uid") == expected_uid if expected_uid is not None else
                           selected["node_uid"] is None and opaque(meta.get("uid"))) and
                          meta.get("annotations", {}).get("etcd.k3s.cattle.io/node-address") == peer and
                          any(isinstance(a, dict) and a.get("type") == "InternalIP" and a.get("address") == peer for a in addresses), "ownership")
            if name == self.recipe["member"]["member"]:
                labels = meta.get("labels", {})
                taints = node.get("spec", {}).get("taints", [])
                state_require(all(labels.get(k) == v for k, v in
                                  (label.split("=", 1) for label in self.recipe["config"]["node-label"])), "ownership")
                for taint in self.recipe["config"]["node-taint"]:
                    key, value_effect = taint.split("=", 1)
                    value, effect = value_effect.rsplit(":", 1)
                    state_require(any(t.get("key") == key and t.get("value", "") == value and
                                      t.get("effect") == effect for t in taints), "ownership")
            seen.add(name)
        cluster = self.recipe["cluster"] if "source" in self.recipe else observed["cluster"]
        state_require(observed["cluster"] == cluster, "ownership")
        return {"cluster": cluster, "observer": self.binding["recipient"]["machine"],
                "node_uid": observed["node_uid"],
                "healthy": all(readiness[k] == "ready" for k in ("api", "quorum", "nodes")) and
                           not left and len(seen) == len(members),
                "members": members}

    def admin_record(self, name, record):
        state_require(record is not None, "ownership")
        state_fields(record, "schema kind binding recipe_identity_sha256 api_endpoint identity previous file")
        state_binding(record["binding"])
        state_require(record["kind"] == "admin-publication" and
                      name == record["binding"]["dispatch"] and
                      record["binding"]["owner"] == self.binding["owner"] and
                      record["binding"]["scope"] == self.binding["scope"] and
                      dict(record["binding"]["recipient"], node_uid=None) == dict(self.recipe["member"], node_uid=None) and
                      record[LIFE_RIS] == self.identity_hash and
                      record["api_endpoint"] == self.recipe["api_endpoint"] and
                      isinstance(record["file"], list) and len(record["file"]) == 2 and
                      all(type(n) is int and n >= 0 for n in record["file"]) and
                      (record["previous"] is None or isinstance(record["previous"], list) and
                       len(record["previous"]) == 2 and all(type(n) is int and n >= 0 for n in record["previous"])), "ownership")
        life_identity(record["identity"])

    def admin_candidate(self, dispatch):
        path = self.owner_path + "/.admin-" + dispatch
        file_id = life_file(path, 0o600)
        raw = read_file(path, 65536)
        obj = decode(raw)
        state_require(raw == canonical(obj) + b"\n" and isinstance(obj, dict), "ownership")
        try:
            cluster = obj["clusters"][0]["cluster"]
            user = obj["users"][0]["user"]
            ca, cert, key = (cluster["certificate-authority-data"], user["client-certificate-data"],
                             user["client-key-data"])
            state_require(all(isinstance(value, str) and value.isascii() for value in (ca, cert, key)) and
                          cluster["server"] == self.recipe["api_endpoint"], "ownership")
            source = ("apiVersion: v1\nclusters:\n- cluster:\n    certificate-authority-data: " + ca +
                      "\n    server: https://127.0.0.1:6443\n  name: default\ncontexts:\n- context:\n"
                      "    cluster: default\n    user: default\n  name: default\ncurrent-context: default\n"
                      "kind: Config\npreferences: {}\nusers:\n- name: default\n  user:\n"
                      "    client-certificate-data: " + cert + "\n    client-key-data: " + key + "\n")
            normalized = life_decode_raw(source.encode("ascii"))
            normalized["clusters"][0]["cluster"]["server"] = self.recipe["api_endpoint"]
            state_require(obj == normalized and life_file(path, 0o600) == file_id, "ownership")
        except (KeyError, IndexError, TypeError, UnicodeEncodeError):
            raise StateRefused("ownership")
        return file_id

    def admin_chain(self, records, current):
        """Follow publication generation and step order."""
        def rank(record):
            binding = record["binding"]
            return binding["receiver_generation"], binding["step"]

        seen = set()
        while current is not None:
            state_require(current not in seen, "ownership")
            seen.add(current)
            previous = records[current]["previous"]
            if previous is None:
                break
            before = rank(records[current])
            parent = max(((rank(record), name)
                          for name, record in records.items()
                          if name not in seen and record["file"] == previous and
                          rank(record) < before), default=None)
            state_require(parent is not None, "ownership")
            current = parent[1]
        return seen

    def admin_evidence(self, expected=None, unfinished=None, selected_file=None):
        """Check selected history and pending writer."""
        service = self.owner_path + "/service"
        pointer = state_read(service + "/admin-access.json", schema=2)
        state_require(pointer is not None, "ownership")
        state_fields(pointer, "schema publication")
        state_hex(pointer["publication"])
        directory = service + "/admin-publications"
        names = state_names(directory, 1024)
        state_require(all(re.fullmatch(r"[0-9a-f]{32}\.json", name) for name in names), "ownership")
        records = {}
        total = 0
        for name in names:
            record = state_read(directory + "/" + name, schema=2)
            self.admin_record(name[:-5], record)
            total += len(canonical(record)) + 1
            state_require(total <= 33554432, "bound")
            records[name[:-5]] = record
        publication = records.get(pointer["publication"])
        state_require(publication is not None, "ownership")
        state_require((expected is None or publication["identity"] == expected) and
                      publication["file"] == (selected_file if selected_file is not None else
                                               life_file(self.owner_path + "/admin.yaml", 0o600)), "ownership")
        state_require(all(record["identity"] == publication["identity"] for record in records.values()), "ownership")
        seen = self.admin_chain(records, pointer["publication"])
        state_require(set(records) - seen == ({unfinished} if unfinished in records else set()), "ownership")
        return pointer, publication

    def admin_writer(self, dispatch, action, publication=None, allow_terminal=False):
        """Unfinished evidence's durable writer."""
        intent = state_read(self.dispatch_path(dispatch) + "/intent.json", "intent")
        state_require(intent is not None and intent["binding"]["dispatch"] == dispatch and
                      intent["action"] == "lifecycle:" + action and
                      intent["binding"]["owner"] == self.binding["owner"] and
                      intent["binding"]["scope"] == self.binding["scope"] and
                      dict(intent["binding"]["recipient"], node_uid=None) == dict(self.recipe["member"], node_uid=None), "ownership")
        state_hex(intent["payload_sha256"], 64)
        terminal = state_read(self.dispatch_path(dispatch) + "/terminal.json", "terminal")
        state_require((terminal is None or allow_terminal and terminal["binding"] == intent["binding"] and
                       terminal["action"] == intent["action"] and terminal["payload_sha256"] == intent["payload_sha256"] and
                       terminal["outcome"] == "succeeded") and
                      (publication is None or publication["binding"] == intent["binding"] and
                       publication[LIFE_RIS] == self.identity_hash and
                       publication["api_endpoint"] == self.recipe["api_endpoint"]), "ownership")
        reservation = state_read(ROOT + "/attempts/" + intent["binding"]["attempt"] + "/reservation.json", "reservation")
        state_require(reservation is not None and reservation["state"] in ("reserved", "active") and
                      dispatch in reservation["dispatches"] and self.claim is not None and
                      self.claim["active_attempt"] == intent["binding"]["attempt"] and
                      self.claim["generation"] == intent["binding"]["receiver_generation"] and
                      reservation["binding"]["operation"] == intent["binding"]["operation"] and
                      reservation["binding"]["owner"] == self.binding["owner"], "ownership")
        return intent

    def admin_window(self, expected=None):
        service = self.owner_path + "/service"
        try:
            names = state_names(self.owner_path, 1024)
        except FileNotFoundError:
            names = []
        candidates = [name[7:] for name in names if name.startswith(".admin-")]
        state_require(all(re.fullmatch(r"[0-9a-f]{32}", name) for name in candidates) and len(candidates) <= 1, "ownership")
        try:
            record_names = state_names(service + "/admin-publications", 1024)
        except FileNotFoundError:
            record_names = []
        state_require(all(re.fullmatch(r"[0-9a-f]{32}\.json", name) for name in record_names), "ownership")
        records = {name[:-5]: state_read(service + "/admin-publications/" + name, schema=2) for name in record_names}
        for name, record in records.items():
            self.admin_record(name, record)
        pointer = state_read(service + "/admin-access.json", schema=2)
        if expected is None:
            dispatches = set(candidates) | set(records) | ({pointer["publication"]} if pointer else set())
            if not dispatches:
                state_require(not life_exists(self.owner_path + "/admin.yaml"), "ownership")
                return "unpublished"
            state_require(len(dispatches) == 1, "ownership")
            dispatch = dispatches.pop()
            publication = records.get(dispatch)
            self.admin_writer(dispatch, "publish-member" if "source" in self.recipe else "publish-identity", publication,
                              allow_terminal=bool(pointer and publication and not candidates and life_exists(self.owner_path + "/admin.yaml")))
            managed = self.owner_path + "/admin.yaml"
            state_require(not pointer or pointer == {"schema":2, "publication":dispatch}, "ownership")
            if publication is not None:
                state_require(publication["identity"]["data"] == life_data_id(), "ownership")
            claim_uid = self.claim["member"]["node_uid"]
            if claim_uid is not None:
                state_require(pointer is not None and publication is not None and
                              dispatch not in candidates and life_exists(managed) and
                              publication["identity"]["node_uid"] == claim_uid, "ownership")
            if publication is None:
                state_require(not pointer and not life_exists(managed) and dispatch in candidates, "ownership")
                self.admin_candidate(dispatch)
            else:
                state_require(publication["previous"] is None and publication["kind"] == "admin-publication" and
                              publication["binding"]["dispatch"] == dispatch and
                              (self.admin_candidate(dispatch) == publication["file"] if dispatch in candidates else
                               life_file(managed, 0o600) == publication["file"]), "ownership")
                state_require((dispatch in candidates) != life_exists(managed), "ownership")
            return "interrupted"
        state_require(pointer is not None, "ownership")
        state_fields(pointer, "schema publication")
        selected = records.get(pointer["publication"])
        state_require(selected is not None, "ownership")
        chain = self.admin_chain(records, pointer["publication"])
        successors = [name for name, record in records.items() if name not in chain and
                      record["previous"] == selected["file"]]
        pending = set(candidates) | set(successors)
        state_require(len(pending) <= 1, "ownership")
        if pending:
            dispatch = pending.pop()
            state_require(dispatch != pointer["publication"], "ownership")
            publication = records.get(dispatch)
            self.admin_writer(dispatch, "prepare-join-source", publication)
            self.admin_evidence(expected, dispatch, selected["file"])
            candidate = self.owner_path + "/.admin-" + dispatch
            managed = self.owner_path + "/admin.yaml"
            if publication is None:
                state_require(dispatch in candidates and life_file(managed, 0o600) == selected["file"], "ownership")
                self.admin_candidate(dispatch)
            else:
                state_require(publication["previous"] == selected["file"] and
                              publication["identity"] == expected and
                              (self.admin_candidate(dispatch) == publication["file"] if dispatch in candidates else
                               life_file(managed, 0o600) == publication["file"]), "ownership")
                state_require((dispatch in candidates) == (life_file(managed, 0o600) == selected["file"]), "ownership")
            return "interrupted"
        _, publication = self.admin_evidence(expected)
        dispatch = pointer["publication"]
        if publication["previous"] is not None and state_read(self.dispatch_path(dispatch) + "/terminal.json", "terminal") is None:
            self.admin_writer(dispatch, "prepare-join-source", publication)
            return "interrupted"
        return "published"

    def admin_candidate_render(self, expected):
        source = life_raw(self.binding["owner"])
        obj = life_decode_raw(source)
        _, raw_identity = self.probe(access=source, raw=True)
        state_require(raw_identity == expected, "trust")
        obj["clusters"][0]["cluster"]["server"] = self.recipe["api_endpoint"]
        rendered = canonical(obj) + b"\n"
        state_require(len(rendered) <= 65536, "bound")
        candidate = self.owner_path + "/.admin-" + self.binding["dispatch"]
        file_id = life_write(candidate, rendered, 0o600)
        _, observed = self.probe(access=rendered)
        state_require(observed == expected and life_file(candidate, 0o600) == file_id and
                      read_file(candidate, 65536) == rendered, "trust")
        return candidate, file_id

    def publish_admin(self, expected):
        """Publish managed access under the owning intent."""
        state_require(self.intent is not None, "ownership")
        service = self.owner_path + "/service"
        managed = self.owner_path + "/admin.yaml"
        state_require(not life_exists(managed) and
                      state_read(service + "/admin-access.json", schema=2) is None, "ownership")
        try:
            state_require(not state_names(service + "/admin-publications", 1024), "ownership")
        except FileNotFoundError:
            pass
        candidate, file_id = self.admin_candidate_render(expected)
        directory = service + "/admin-publications"
        state_mkdir(directory)
        evidence = {"schema":2, "kind":"admin-publication", "binding":self.binding,
                    LIFE_RIS:self.identity_hash, "api_endpoint":self.recipe["api_endpoint"],
                    "identity":expected, "previous":None, "file":file_id}
        state_publish(directory + "/" + self.binding["dispatch"] + ".json", evidence)
        parent = state_directory(self.owner_path)
        try:
            state_require(not life_exists(managed) and life_file(candidate, 0o600) == file_id, "ownership")
            os.rename(Path(candidate).name, "admin.yaml", src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        state_publish(service + "/admin-access.json", {"schema":2, "publication":self.binding["dispatch"]})
        self.admin_evidence(expected)

    def refresh_admin(self, expected):
        """Refresh the exact managed projection."""
        state_require(self.intent is not None, "ownership")
        pointer, previous = self.admin_evidence(expected)
        service = self.owner_path + "/service"
        managed = self.owner_path + "/admin.yaml"
        old_file = previous["file"]
        pointer_id = life_file(service + "/admin-access.json", 0o600)
        candidate, file_id = self.admin_candidate_render(expected)
        publication = {"schema":2, "kind":"admin-publication", "binding":self.binding,
                       LIFE_RIS:self.identity_hash, "api_endpoint":self.recipe["api_endpoint"],
                       "identity":expected, "previous":old_file, "file":file_id}
        directory = service + "/admin-publications"
        state_require(len(state_names(directory, 1024)) < 1024, "bound")
        state_publish(directory + "/" + self.binding["dispatch"] + ".json", publication)
        parent = state_directory(self.owner_path)
        try:
            state_require(life_file(managed, 0o600) == old_file and life_file(candidate, 0o600) == file_id, "ownership")
            os.replace(Path(candidate).name, "admin.yaml", src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        state_require(life_file(service + "/admin-access.json", 0o600) == pointer_id, "ownership")
        state_publish(service + "/admin-access.json", {"schema":2, "publication":self.binding["dispatch"]}, pointer_id)
        self.admin_evidence(expected)

    def classify(self, probe):
        """Class, publication, records and readiness."""
        b, r = self.binding, self.recipe
        found = self.present()
        ownership = self.ownership()
        published = ownership is not None and ownership["cluster"] is not None
        if b["recipient"] != r["member"]:
            return "absent" if not found else "foreign", "published" if published else "unpublished", None, ownership, None
        if not found:
            return "absent", "unpublished", None, ownership, None
        try:
            record = self.record()
        except (Refused, FileNotFoundError, KeyError, TypeError, ValueError, AttributeError):
            record = None
        except StateRefused as refused:
            state_require(refused.failure == "ownership", refused.failure)
            record = None
        if record is None or ownership is None:
            return "foreign", "unpublished", None, ownership, None
        if self.agent:
            if ownership["cluster"] != r["cluster"]:
                return "foreign", "unpublished", record, ownership, None
            unit = self.unit_facts()
            uid = ownership["machine"]["node_uid"]
            state = "published" if uid is not None else "unpublished"
            active = unit.get("ActiveState") == "active" and unit.get("UnitFileState") == "enabled"
            if uid is None:
                return ("started" if active else "activated" if unit.get("ActiveState") == "inactive" else "foreign"), state, record, ownership, None
            data = life_data_id()
            valid = (active or r["member"]["node_uid"] is None and unit.get("UnitFileState") == "disabled" and
                     unit.get("ActiveState") == "inactive") and ownership["data"] == data and self.claim is not None and self.claim["member"]["node_uid"] == uid
            return ("owned" if valid else "foreign"), state, record, ownership, None
        datastore, unit = life_exists(DATASTORE), self.unit_facts()
        if ownership["machine"]["node_uid"] is None:
            state_require(ownership["cluster"] == (r["cluster"] if "source" in r else None), "ownership")
            try:
                state = self.admin_window()
            except StateRefused as refused:
                if refused.failure not in ("ownership", "integrity", "credential", "trust"):
                    raise
                return "foreign", "unpublished", record, ownership, None
            except (Refused, FileNotFoundError, KeyError, TypeError, ValueError, AttributeError):
                return "foreign", "unpublished", record, ownership, None
            if state == "unpublished" and self.claim is not None and self.claim["member"]["node_uid"] is not None:
                return "foreign", state, record, ownership, None
            if not datastore and unit.get("ActiveState") == "inactive":
                return "activated", state, record, ownership, None
            if datastore and unit.get("UnitFileState") == "enabled":
                return "started", state, record, ownership, self.probe()[0] if probe and state == "unpublished" else None
            return "foreign", state, record, ownership, None
        node_uid = ownership["machine"]["node_uid"]
        data = life_data_id()
        if not (datastore and ownership["data"] == data and node_uid is not None and self.claim is not None and self.claim["member"]["node_uid"] == node_uid):
            return "foreign", "published", record, ownership, None
        try:
            state = self.admin_window({"cluster":ownership["cluster"], "node_uid":node_uid, "data":ownership["data"]})
        except StateRefused as refused:
            if refused.failure not in ("ownership", "integrity", "credential", "trust"):
                raise
            return "foreign", "unpublished", record, ownership, None
        except (Refused, FileNotFoundError, KeyError, TypeError, ValueError, AttributeError):
            return "foreign", "unpublished", record, ownership, None
        if state == "interrupted":
            return "owned", state, record, ownership, None
        readiness = None
        if probe:
            readiness, live = self.probe()
            if live is not None and live != {"cluster": ownership["cluster"], "node_uid": node_uid, "data": ownership["data"]}:
                return "foreign", "published", record, ownership, readiness
        return "owned", state, record, ownership, readiness

    def facts(self, cls, state, record, ownership):
        facts = {"class": cls, "publication_state": state, **{k: (record[k] if record is not None else None) for k in LIFE_FACTS}, "identity": None}
        if cls == "owned":
            facts["identity"] = {"cluster": ownership["cluster"], "node_uid": ownership["machine"]["node_uid"], "data": ownership["data"]}
        return facts

    # -- actions --
    def inspect_installation(self, data):
        cls, state, record, ownership, readiness = self.classify(True)
        if cls == "absent" and self.binding["recipient"] == self.recipe["member"]:
            self.verify()
        data["installation"] = self.facts(cls, state, record, ownership)
        data["readiness"] = readiness

    def inspect_owned(self, data):
        self.inspect_installation(data)
        state_require(data["installation"]["class"] == "owned" and
                      data["installation"]["publication_state"] == "published", "ownership")

    def inspect_join(self, data):
        state_require("source" in self.recipe, "capability")
        cls, state, record, ownership, readiness = self.classify(True)
        state_require(cls in ("absent", "activated", "started", "owned"), "ownership")
        if cls == "absent":
            self.verify_assets()
            state_require(not life_exists(self.owner_path + "/resources/" + self.recipe["source_input"]["id"] +
                                          "/" + self.recipe["input"]["generation"]), "ownership")
        data["installation"] = self.facts(cls, state, record, ownership)
        data["readiness"] = readiness

    def observe_membership(self, data):
        data["membership"] = self.membership(self.payload["removed"])

    def observe_agent_membership(self, data):
        r, b = self.recipe, self.binding
        state_require(self.agent and b["recipient"] == r["source"], "ownership")
        owned = self.ownership()
        state_require(owned is not None and owned["cluster"] == r["cluster"] and
                      owned["machine"]["node_uid"] == r["source"]["node_uid"], "ownership")
        owner = b["owner"]
        raw = kubectl(self.executable, owner, "--server=https://127.0.0.1:6443",
                      "get", "nodes", "-o", "json", output_limit=MAXIMUM)
        nodes = decode(raw)
        state_require(isinstance(nodes, dict) and isinstance(nodes.get("items"), list) and
                      len(nodes["items"]) <= 128, "bound")
        by_name = {}
        for node in nodes["items"]:
            state_require(isinstance(node, dict) and isinstance(node.get("metadata"), dict), "integrity")
            meta = node["metadata"]
            name, uid = meta.get("name"), meta.get("uid")
            state_require(opaque(name) and opaque(uid) and name not in by_name, "ownership")
            by_name[name] = node
        names = {m["member"] for m in r["members"] if m["role"] != "backup"}
        state_require(len(names) == len([m for m in r["members"] if m["role"] != "backup"]), "ownership")
        foreign = [{"name": name, "uid": node["metadata"]["uid"]} for name, node in sorted(by_name.items()) if name not in names]
        entries = []
        for member in r["members"]:
            if member["role"] == "backup":
                entries.append({"member": member, "present": False, "uid": None, "ready": False,
                                "roles": [], "labels": [], "taints": []})
                continue
            node = by_name.get(member["member"])
            if node is None:
                entries.append({"member": member, "present": False, "uid": None, "ready": False,
                                "roles": [], "labels": [], "taints": []})
                continue
            meta = node["metadata"]
            labels = meta.get("labels", {})
            taints = node.get("spec", {}).get("taints", [])
            state_require(isinstance(labels, dict) and isinstance(taints, list), "integrity")
            roles = ["server"] if any(k in labels for k in
                     ("node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master")) else ["agent"]
            custom = sorted(k + "=" + v for k, v in labels.items()
                            if not k.startswith(("kubernetes.io/", "node.kubernetes.io/", "beta.kubernetes.io/",
                                                 "k3s.io/", "node-role.kubernetes.io/")) and isinstance(v, str))
            scoped = sorted(t["key"] + "=" + t.get("value", "") + ":" + t["effect"] for t in taints
                            if isinstance(t, dict) and isinstance(t.get("key"), str) and
                            isinstance(t.get("effect"), str))
            conditions = node.get("status", {}).get("conditions", [])
            ready = any(isinstance(c, dict) and c.get("type") == "Ready" and c.get("status") == "True"
                        for c in conditions) and node.get("status", {}).get("nodeInfo", {}).get("kubeletVersion") == r["version"]
            entries.append({"member": member, "present": True, "uid": meta["uid"], "ready": ready,
                            "roles": roles, "labels": custom, "taints": scoped})
        cluster = {"uid": kubectl(self.executable, owner, "--server=https://127.0.0.1:6443",
                   "get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}", output_limit=512).decode("ascii"),
                   "ca_sha256": hashlib.sha256(read_file(DATASTORE + "/tls/server-ca.crt", 65536, private=False)).hexdigest()}
        state_require(cluster == r["cluster"] and not foreign, "ownership")
        data["agent_view"] = {"cluster": cluster, "observer": r["source"], "members": entries, "foreign": foreign}

    def observe_join(self, data):
        state_require("source" in self.recipe, "capability")
        self.observe(data)
        data["membership"] = self.membership()

    def publish_member(self, data):
        state_require("source" in self.recipe and self.payload["membership"]["healthy"] is True and
                      self.membership() == self.payload["membership"], "ownership")
        self.publish_identity(data)
        data["membership"] = self.membership()

    def observe(self, data):
        cls, state, record, ownership, _ = self.classify(False)
        state_require(cls in ("started", "owned"), "ownership")
        if state == "interrupted":
            data["installation"] = self.facts(cls, state, record, ownership)
            return
        while True:
            readiness, observed = self.probe()
            left = DEADLINE - time.monotonic() - 2.5
            if all(readiness[k] == "ready" for k in ("api", "quorum", "nodes")) or left <= 0:
                break
            time.sleep(min(2, left))
        if cls == "owned" and observed is not None:
            state_require(observed == {"cluster": ownership["cluster"], "node_uid": ownership["machine"]["node_uid"], "data": ownership["data"]}, "ownership")
        data["installation"], data["readiness"], data["identity"] = self.facts(cls, state, record, ownership), readiness, observed

    def verify(self):
        """Read-only admission from absent, before effects."""
        verified = []
        for detail, verify in (("assets", self.verify_assets), ("input", self.verify_input)):
            try:
                verified.append(verify())
            except FileNotFoundError:
                raise StateRefused("readiness", detail)
            except StateRefused as error:
                if error.failure == "readiness":
                    raise StateRefused("readiness", detail)
                raise
        return tuple(verified)

    def verify_assets(self):
        b, r, o = self.binding, self.recipe, self.owner_path
        gen = f"{o}/assets/{r['assets']['generation']}"
        gfd = state_directory(gen)
        try:
            marker = state_read(gen + "/complete.json")
            state_require(marker is not None and hashlib.sha256(canonical(marker)).hexdigest() == r["assets"]["marker_sha256"], "readiness")
            state_fields(marker, "schema kind scope owner operation attempt resource recipe_sha256 directory inactive assets")
            state_require(marker["kind"] == "bootstrap-complete" and marker["owner"] == b["owner"] and marker["scope"] == b["scope"] and
                          marker["directory"] == identity(gfd) and marker["inactive"] is True, "ownership")
            assets = {tuple(x["identity"]): x for x in marker["assets"]}
            state_require(len(assets) == len(marker["assets"]) and all({"id", "size", "sha256", "identity"} == set(x) for x in marker["assets"]))
            seen, archive = set(), None
            for name in state_names(gen, 64):
                if name in ("binding.json", "complete.json"):
                    continue
                fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=gfd)
                try:
                    asset = assets.get(tuple(identity(fd)))
                    state_require(asset is not None and state_private(fd).st_size == asset["size"] and life_digest(fd) == asset["sha256"], "readiness")
                    seen.add(asset["id"])
                    archive = name if asset["id"] == "k3s-airgap" else archive
                finally:
                    os.close(fd)
            state_require(seen == set(assets[k]["id"] for k in assets) and archive == r["archive"]["filename"], "readiness")
            for key, name in (("executable", "k3s"), ("archive", "k3s-airgap")):
                entry = next((x for x in marker["assets"] if x["id"] == name), None)
                state_require(entry is not None and all(entry[k] == r[key][k] for k in ("id", "size", "sha256")), "readiness")
            return archive
        finally:
            os.close(gfd)

    def verify_input(self):
        b, r, o = self.binding, self.recipe, self.owner_path
        base = o + "/resources"
        hits = [n for n in state_names(base, 1024) if life_exists(f"{base}/{n}/{r['input']['generation']}")]
        state_require(len(hits) == 1 and (not self.agent or hits[0] == r["source_input"]["id"]), "readiness")
        ipath = f"{base}/{hits[0]}/{r['input']['generation']}"
        ifd = state_directory(ipath)
        try:
            rec = state_read(ipath + "/binding.json")
            state_require(rec is not None, "readiness")
            state_fields(rec, "schema directory projection inactive registration_pending")
            pb = rec["projection"]["binding"]
            state_require(rec["directory"] == identity(ifd) and rec["inactive"] is True and rec["registration_pending"] is True and
                          pb["owner"] == b["owner"] and pb["resource"]["kind"] == ("agent-input" if self.agent else "server-input") and
                          pb["resource"]["id"] == hits[0] and
                          pb["cluster"] == (r["cluster"] if "source" in r else None) and
                          pb["destination"]["machine"] == b["recipient"]["machine"], "ownership")
            tokens = {}
            if self.agent:
                state_require(not life_exists(ipath + "/server-token"), "ownership")
            for name in (("agent-token",) if self.agent else ("server-token", "agent-token")):
                life_file(ipath + "/" + name, 0o600)
                tokens[name] = read_file(ipath + "/" + name, 4096)
                pattern = (b"K10" + r["cluster"]["ca_sha256"].encode() + rb"::node:[0-9a-f]{64}" if self.agent else
                           b"K10" + r["cluster"]["ca_sha256"].encode() + rb"::server:[0-9a-f]{64}" if
                           "source" in r and name == "server-token" else
                           rb"[0-9a-f]{64}" if "source" in r else rb"[0-9a-f]{64}\n?")
                state_require(re.fullmatch(pattern, tokens[name]) is not None, "ownership")
            if not self.agent:
                state_require(tokens["server-token"] != tokens["agent-token"], "ownership")
            return tokens
        finally:
            os.close(ifd)

    def install(self, archive, tokens):
        """Install assets; record the activation."""
        b, r, o = self.binding, self.recipe, self.owner_path
        s, a = o + "/service", o + "/active"
        self.effect_started = True
        ids = {}
        life_dir(RANCHER, 0o755)
        for path in (DATA, DATA + "/agent", IMAGES):
            state_mkdir(path)
        gfd = state_directory(f"{o}/assets/{r['assets']['generation']}")
        try:
            ids["archive"] = self.copy_archive(gfd, archive, r["archive"])
        finally:
            os.close(gfd)
        state_mkdir(a)
        for name in (("agent-token",) if self.agent else ("server-token", "agent-token")):
            ids[name] = life_write(a + "/" + name, tokens[name], 0o600)
        life_dir(ETC, 0o755)
        parent, _ = directory(ETC)
        try:
            os.mkdir("k3s", 0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        os.close(state_directory(ETC + "/k3s"))
        ids["config"] = life_write(CONFIG, canonical(r["config"]) + b"\n", 0o600)
        state_mkdir(s)
        ids["log"] = life_write(s + "/service.log", b"", 0o600)
        ids["guard"] = life_write(s + "/guard.py", self.guard, 0o700)
        ids["unit"] = life_write(AGENT_UNIT if self.agent else UNIT, self.unit, 0o644)
        record = {"schema":3 if self.agent else 2, "kind":"agent-activation" if self.agent else "server-activation",
                  "scope":b["scope"], "owner":b["owner"], "operation":b["operation"], "attempt":b["attempt"],
                  "member":r["member"], "recipe_sha256":self.recipe_hash, LIFE_RIS:self.identity_hash,
                  "marker_sha256":r["assets"]["marker_sha256"], "assets":r["assets"], "input":r["input"],
                  "executable":dict(r["executable"], identity=self.executable_identity), "archive":dict(r["archive"], identity=ids["archive"]),
                  "config_sha256":self.config_hash, "unit_sha256":r["unit_sha256"], "guard_sha256":r["guard_sha256"],
                  "identities":{k:v for k,v in ids.items() if not self.agent or k != "archive"}, "api_endpoint":r["api_endpoint"]}
        state_publish(s + "/activation.json", record)
        return record

    def copy_archive(self, gfd, name, asset):
        """Copy the verified archive exclusively."""
        global EFFECTS
        source = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=gfd)
        parent = state_directory(IMAGES)
        out = None
        try:
            out = os.open(asset["filename"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=parent)
            EFFECTS = True
            hasher, total = hashlib.sha256(), 0
            while chunk := os.read(source, 1048576):
                state_check()
                total += len(chunk)
                state_require(total <= asset["size"], "readiness")
                hasher.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(out, view)
                    state_require(written > 0, "storage")
                    view = view[written:]
            state_require(total == asset["size"] and hasher.hexdigest() == asset["sha256"], "readiness")
            os.fsync(out)
            os.fsync(parent)
            return identity(out)
        finally:
            for fd in (source, parent, out):
                if fd is not None:
                    os.close(fd)

    def activate(self, data):
        self.active()
        cls, state, record, ownership, _ = self.classify(False)
        state_require(cls in ("absent", "activated"), "ownership")
        verified = self.verify() if cls == "absent" else None
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        if verified is not None:
            record = self.install(*verified)
        data["terminal"] = self.terminal("succeeded", None)
        data["installation"] = self.facts("activated", state, record, ownership)

    def start(self, data):
        self.active()
        cls, state, record, ownership, _ = self.classify(False)
        state_require(cls == "activated" and (self.agent or not life_exists(DATASTORE)), "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        service = AGENT_SERVICE if self.agent else SERVICE
        for args in (("daemon-reload",), ("enable", service), ("start", service)):
            code, _ = life_run(["systemctl", *args])
            state_require(code == 0, "readiness")
        while True:
            self.record()
            if not self.agent:
                state_require(self.owned()["cluster"] == (self.recipe["cluster"] if "source" in self.recipe else None), "ownership")
            unit = self.unit_facts()
            ready = unit.get("ActiveState") == "active" and unit.get("UnitFileState") == "enabled"
            if self.agent and ready:
                break
            state_require(self.agent or ready, "readiness")
            left = DEADLINE - time.monotonic()
            state_require(left > 0, "timeout")
            if not self.agent and life_exists(DATASTORE):
                break
            time.sleep(min(2, left))
        cls, state, record, ownership, _ = self.classify(False)
        state_require(cls == "started" and state == "unpublished", "ownership")
        unit = self.unit_facts()
        state_require(unit.get("ActiveState") == "active" and unit.get("UnitFileState") == "enabled", "readiness")
        data["terminal"] = self.terminal("succeeded", None)
        data["installation"] = self.facts("started", state, record, ownership)

    def publish_identity(self, data):
        self.active()
        cls, state, record, ownership, _ = self.classify(False)
        state_require(cls == "started", "ownership")
        expected = self.payload["identity"]
        readiness, observed = self.probe()
        state_require(observed == expected, "ownership")
        c, b, node_uid = self.claim, self.binding, expected["node_uid"]
        state_require(b["recipient"]["node_uid"] is None and c["participants_sha256"] == b["participants_sha256"] and
                      c["member"] in (b["recipient"], dict(b["recipient"], node_uid=node_uid)), "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        pointer_path = self.owner_path + "/service/admin-access.json"
        if life_exists(pointer_path):
            _, publication = self.admin_evidence(expected)
            prior = publication["binding"]
            intent = state_read(ROOT + "/dispatches/" + prior["dispatch"] + "/intent.json", "intent")
            state_require(intent is not None and intent["binding"] == prior and
                          intent["action"] == self.action and
                          intent["payload_sha256"] == state_hash("broil-infra-step-v1", self.payload) and
                          all(prior[k] == b[k] for k in ("scope", "owner", "operation", "attempt", "recipient")) and
                          c["member"] == dict(b["recipient"], node_uid=node_uid), "ownership")
        else:
            self.publish_admin(expected)
        self.admin_evidence(expected)
        if c["member"]["node_uid"] is None:
            self.claim = dict(c, member=dict(c["member"], node_uid=node_uid))
            self.replace(ROOT + "/machine-claim.json", self.claim)
        state_require(ownership["cluster"] in (None, expected["cluster"]), "ownership")
        ownership = dict(ownership, cluster=expected["cluster"], data=expected["data"], machine=dict(ownership["machine"], node_uid=node_uid))
        self.replace(self.owner_path + "/ownership.json", ownership)
        data["terminal"] = self.terminal("succeeded", None)
        data["installation"], data["readiness"], data["identity"] = self.facts("owned", "published", record, ownership), readiness, observed

    def publish_cluster(self, data):
        self.active()
        state_require(not self.present(), "ownership")
        ownership, cluster = self.owned(), self.payload["identity"]["cluster"]
        state_require(ownership["data"] is None and ownership["machine"]["node_uid"] is None and ownership["cluster"] in (None, cluster), "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        if ownership["cluster"] is None:
            self.replace(self.owner_path + "/ownership.json", dict(ownership, cluster=cluster))
        data["terminal"] = self.terminal("succeeded", None)
        data["installation"] = self.facts("absent", "published", None, None)

    def prepare_join_source(self, data):
        self.active()
        resource, projection = self.payload["resource"], self.payload["projection"]
        path = life_source_resource(resource, self.binding)
        state_fields(projection, "schema binding declaration scripts registries secrets references profile")
        p = projection["binding"]
        state_fields(p, "project environment target owner operation attempt source destination cluster resource "
                     "profile_sha256 script_sha256 issuer service principal origin recovery")
        members = self.recipe["members"]
        servers = [member for member in members if member["role"] == "server"]
        agent = resource["kind"] == "agent-input"
        agents = [member for member in members if member["role"] == "agent"]
        selected = lambda member: {key:member[key] for key in ("machine", "member", "role", "node_uid")}
        declared = projection["declaration"].get("members") if isinstance(projection["declaration"], dict) else None
        state_require((len(servers) in (1, 3) and all(member["node_uid"] is not None for member in servers)
                       if agent else len(servers) == 3 and (all(member["node_uid"] is None for member in agents) or
                                                            [m["node_uid"] for m in servers].count(None) == 1)) and
                      len(members) <= 128 and members[0] == servers[0] and
                      [p["source"]] == [selected(m) for m in servers if m["machine"] != p["destination"]["machine"]][:1] and
                      (p["destination"] == selected(next((m for m in agents if m["node_uid"] is None), None))
                       if agent and any(m["node_uid"] is None for m in agents) else
                       any(p["destination"] == selected(member) and member["node_uid"] is None for member in servers)) and
                      isinstance(declared, list) and len(declared) == len(members) and
                      all(isinstance(item, dict) and item.get("machine") == member["machine"] and
                          item.get("name") == member["member"] and item.get("role") == member["role"]
                          for item, member in zip(declared, members)) and
                      projection["declaration"]["api"]["endpoint"] == self.recipe["api_endpoint"] and
                      projection["profile"] == self.pins and
                      p["profile_sha256"] == self.binding["fingerprints"]["profile_sha256"] and
                      p["script_sha256"] == self.binding["fingerprints"]["script_sha256"], "ownership")
        scripts = projection["scripts"]
        state_require(isinstance(scripts, dict) and set(scripts) == {p["source"]["machine"], p["destination"]["machine"]}, "ownership")
        for machine, script in scripts.items():
            state_fields(script, "script_sha256 interpreter cwd environment privilege timeout_seconds")
            state_require(script["script_sha256"] == p["script_sha256"] and
                          script["interpreter"] is None and script["cwd"] is None and
                          script["environment"] == {"BROIL_ENV":p["environment"], "BROIL_MACHINE":machine}, "ownership")
        state_require(projection["schema"] == 1 and p["owner"] == self.binding["owner"] and
                      p["operation"] == self.binding["operation"] and p["attempt"] == self.binding["attempt"] and
                      p["source"] == {k:self.binding["recipient"][k] for k in ("machine", "member", "role", "node_uid")} and
                      p["cluster"] == self.owned()["cluster"] and
                      p["resource"] == {k:resource[k] for k in ("kind", "id", "generation", "uid")} and
                      p["destination"]["machine"] != p["source"]["machine"] and
                      p["destination"]["role"] == ("agent" if agent else "server") and p["destination"]["node_uid"] is None and
                      p["source"]["node_uid"] is not None and not projection["references"] and
                      all(p[k] is None for k in ("issuer", "service", "principal", "origin", "recovery")), "ownership")
        state_require(all(p[k] == self.binding["scope"][k] for k in ("project", "environment", "target")) and
                      projection["profile"]["script_sha256"] == self.binding["fingerprints"]["script_sha256"], "ownership")
        cls, publication, record, ownership, _ = self.classify(False)
        state_require(cls == "owned" and publication == "published" and
                      ownership["machine"]["node_uid"] == p["source"]["node_uid"] and
                      record[LIFE_RIS] == self.identity_hash, "ownership")
        state_require(not life_exists(path), "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        self.refresh_admin({"cluster":ownership["cluster"], "node_uid":ownership["machine"]["node_uid"], "data":ownership["data"]})
        base = self.owner_path + "/resources"
        state_mkdir(base)
        state_mkdir(base + "/" + resource["id"])
        parent = state_directory(base + "/" + resource["id"])
        try:
            os.mkdir(resource["generation"], 0o700, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        fd = state_directory(path)
        try:
            file_id = identity(fd)
            state_publish(path + "/binding.json", {"schema":1, "directory":file_id,
                       "projection":projection, "inactive":True, "registration_pending":False})
        finally:
            os.close(fd)
        self.reservation["state"] = "active"
        self.replace(self.attempt_path() + "/reservation.json", self.reservation)
        data["terminal"] = self.terminal("succeeded", None, resource, file_id)


class AgentReceiver(LifeReceiver):
    """An agent installation: one token, no local admin."""

    def selected_view(self):
        r, view = self.recipe, self.payload["agent_view"]
        state_require(view["cluster"] == r["cluster"] and view["observer"] == r["source"] and
                      not view["foreign"] and [entry["member"] for entry in view["members"]] == r["members"], "ownership")
        selected = next((entry for entry in view["members"] if entry["member"] == r["member"]), None)
        state_require(selected is not None and selected["present"] is True and selected["ready"] is True and
                      selected["roles"] == ["agent"] and selected["uid"] is not None and
                      selected["labels"] == r["config"]["node-label"] and
                      selected["taints"] == r["config"]["node-taint"], "readiness")
        return selected

    def inspect_agent(self, data):
        cls, state, record, ownership, readiness = self.classify(False)
        state_require(cls in ("absent", "activated", "started", "owned"), "ownership")
        if cls == "absent":
            self.verify_assets()
        data["installation"] = self.facts(cls, state, record, ownership)
        data["readiness"] = readiness

    def observe_agent(self, data):
        cls, state, record, ownership, _ = self.classify(False)
        state_require(cls in ("started", "owned"), "ownership")
        selected = self.selected_view()
        data_id = life_data_id()
        data["installation"] = self.facts(cls, state, record, ownership)
        data["readiness"] = dict.fromkeys(LIFE_KEYS, "unobserved")
        ready = self.unit_facts().get("ActiveState") == "active"
        data["readiness"]["nodes"] = "ready" if ready else "not-ready"
        state_require(ready and
                      (cls != "owned" or ownership["data"] == data_id and
                       (self.recipe["member"]["node_uid"] is None or ownership["machine"]["node_uid"] == selected["uid"])), "readiness")
        data["identity"] = {"cluster":self.recipe["cluster"], "node_uid":selected["uid"], "data":data_id}

    def publish_agent(self, data):
        self.active()
        cls, _, record, ownership, _ = self.classify(False)
        rep = cls == "owned" and self.recipe["member"]["node_uid"] is None
        state_require(cls == "started" or rep, "ownership")
        expected, view = self.payload["identity"], self.payload["agent_view"]
        selected = self.selected_view()
        state_require(expected["cluster"] == self.recipe["cluster"] and selected["uid"] == expected["node_uid"] and
                      self.claim["member"]["node_uid"] == ownership["machine"]["node_uid"] != expected["node_uid"] and
                      (rep or ownership["machine"]["node_uid"] is None), "ownership")
        data_id = life_data_id()
        state_require(expected["data"] == data_id, "ownership")
        previous = self.begin()
        if previous is not None:
            data["terminal"] = previous
            return
        self.effect_started = True
        self.claim = dict(self.claim, member=dict(self.claim["member"], node_uid=expected["node_uid"]))
        self.replace(ROOT + "/machine-claim.json", self.claim)
        ownership = dict(ownership, data=data_id, machine=dict(ownership["machine"], node_uid=expected["node_uid"]))
        self.replace(self.owner_path + "/ownership.json", ownership)
        data["terminal"] = self.terminal("succeeded", None)
        data["installation"] = self.facts("owned", "published", record, ownership)
        data["identity"], data["agent_view"] = expected, view


def life_request(raw, header):
    global DEADLINE
    reserve = 8196 if header.get("action") == "prepare-join-source" else \
        16388 if header.get("action") in LIFE_JOIN_ACTIONS + LIFE_AGENT_ACTIONS else LIFE_RESERVE
    state_require(14 + len(raw) + reserve <= 65536, "bound")
    state_value(header)
    state_fields(header, "protocol version action request_id binding remaining_ms payload")
    state_require(header["protocol"] == "broil-k3s-lifecycle" and canonical(header) == raw)
    state_require(type(header["version"]) is int and header["version"] == 1,
                  "unsupported-version" if type(header["version"]) is int and header["version"] > 1 else "integrity")
    state_require(header["action"] in LIFE_ACTIONS, "capability")
    state_hex(header["request_id"])
    state_binding(header["binding"])
    mutation = header["action"] not in LIFE_READS
    state_uint(header["remaining_ms"], 1, 7200000 if mutation else 30000)
    state_require((header["request_id"] == header["binding"]["dispatch"]) == mutation)
    DEADLINE = time.monotonic() + header["remaining_ms"] / 1000
    p = header["payload"]
    joined_action = header["action"] in LIFE_JOIN_ACTIONS
    agent_action = header["action"] in LIFE_AGENT_ACTIONS
    state_fields(p, "resource projection recipe" if header["action"] == "prepare-join-source" else
                 "recipe_kind recipe identity membership removed" if joined_action else
                 "recipe identity agent_view" if agent_action else "recipe identity")
    state_require(len(canonical(header["binding"])) <= 4096, "bound")
    life_recipe(p["recipe"], header["binding"])
    if agent_action:
        state_require(p["recipe"]["schema"] == 3 and
                      (p["identity"] is not None) == (header["action"] == "publish-agent") and
                      (p["agent_view"] is not None) ==
                      (header["action"] in ("observe-agent", "publish-agent")), "ownership")
    if joined_action:
        state_require(p["recipe_kind"] == ("join" if "source" in p["recipe"] else "initial"), "ownership")
        state_require(header["action"] in ("inspect-owned-server", "observe-membership") or
                      p["recipe_kind"] == "join", "ownership")
        state_require((header["action"] == "publish-member") ==
                      (p["identity"] is not None and p["membership"] is not None), "integrity")
        r = p["removed"]
        if r is not None:
            state_fields(r, "member node_ip")
            state_require(header["action"] == "observe-membership" and r["member"] and type(r["member"]) is str and
                          str(ipaddress.IPv4Address(r["node_ip"])) == r["node_ip"])
    if header["action"] == "prepare-join-source":
        life_source_resource(p["resource"], header["binding"])
        state_require(isinstance(p["projection"], dict), "integrity")
    elif header["action"] in ("publish-identity", "publish-cluster", "publish-member", "publish-agent"):
        life_identity(p["identity"])
    else:
        state_require(p["identity"] is None)
    state_require(sys.stdin.buffer.read(1) == b"")


def life_main(raw, header):
    receiver, status = None, "unknown"
    joined_action = header.get("action") in LIFE_JOIN_ACTIONS
    agent_action = header.get("action") in LIFE_AGENT_ACTIONS
    data = {"terminal": None, "installation": None, "readiness": None, "identity": None, "failure": None, "detail": None}
    if joined_action:
        data["membership"] = None
    prefix = b"BK3SLIFE1\n" + struct.pack(">I", len(raw)) + raw
    try:
        life_request(raw, header)
        receiver = LifeReceiver(header) if header["action"] == "observe-agent-membership" else \
            AgentReceiver(header) if agent_action else LifeReceiver(header)
        receiver.profile()
        present = receiver.open()
        tag = header["action"]
        state_require(present or tag in ("inspect-installation", "inspect-join", "inspect-agent"), "ownership")
        methods = {"inspect-installation": "inspect_installation", "observe-server": "observe", "activate-server": "activate",
                   "start-server": "start", "publish-identity": "publish_identity", "publish-cluster": "publish_cluster",
                   "prepare-join-source": "prepare_join_source", "inspect-owned-server": "inspect_owned",
                   "inspect-join": "inspect_join", "observe-membership": "observe_membership",
                   "activate-join": "activate", "start-join": "start", "observe-join": "observe_join",
                   "publish-member": "publish_member", "inspect-agent": "inspect_agent",
                   "observe-agent-membership": "observe_agent_membership", "activate-agent": "activate",
                   "start-agent": "start", "observe-agent": "observe_agent", "publish-agent": "publish_agent"}
        getattr(receiver, methods[tag])(data)
        status = "ok"
    except Exception as error:
        failure = (error.failure if isinstance(error, StateRefused) else "timeout" if isinstance(error, subprocess.TimeoutExpired) else
                   "transport" if isinstance(error, subprocess.SubprocessError) else "storage" if isinstance(error, OSError) else "integrity")
        data = {"terminal": None, "installation": None, "readiness": None, "identity": None, "failure": failure, "detail": None}
        if joined_action:
            data["membership"] = None
        status = "unknown" if EFFECTS else "busy" if failure == "busy" else "unsupported-version" if failure == "unsupported-version" else "bound" if failure == "bound" else "refused"
        if receiver is not None and receiver.intent is not None:
            try:
                data["terminal"] = receiver.terminal("failed", failure)
                status = "failed"
            except BaseException:
                status = "unknown"
        if status == "refused" and failure == "readiness" and header["action"] in ("inspect-installation", "activate-server"):
            data["detail"] = getattr(error, "detail", None)
    finally:
        if receiver is not None:
            for fd in (receiver.lock, receiver.root, receiver.executable):
                if fd is not None:
                    os.close(fd)
    if agent_action:
        data.setdefault("agent_view", None)
    body = canonical({"kind": "result", "status": status, **data})
    if (joined_action or agent_action) and len(body) > 16384:
        os._exit(125)
    result = prefix + struct.pack(">I", len(body)) + body
    if len(result) > 65536:
        os._exit(125)
    sys.stdout.buffer.write(result)
    sys.stdout.buffer.flush()


raw = None
try:
    os.umask(0o077)
    length = struct.unpack(">I", read_exact(4))[0]
    require(0 < length <= 65536, 4)
    raw = read_exact(length)
    header = decode(raw)
    require(isinstance(header, dict) and header.get("protocol") == "broil-k3s-lifecycle", 4)
    life_main(raw, header)
    os._exit(0)
except Exception:
    os._exit(125)
