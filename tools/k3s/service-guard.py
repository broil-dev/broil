#!/usr/bin/python3 -I
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import os
import re
import stat
import sys

ROOT = "/var/lib/broil/k3s"
K3S = "/usr/local/libexec/broil-k3s"
CONFIG = "/etc/rancher/k3s/config.yaml"
UNIT = "/etc/systemd/system/broil-k3s"
REFUSAL = "broil-k3s guard: activation inputs changed; start refused"


def need(valid):
    if not valid:
        raise ValueError


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1048576):
            value.update(chunk)
    return value.hexdigest()


def check(path, mode, directory=False):
    st = os.lstat(path)
    kind = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink == 1
    need(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == mode and kind)
    return [st.st_dev, st.st_ino]


def main():
    s = os.path.dirname(os.path.abspath(__file__))
    o = os.path.dirname(s)
    owner = os.path.basename(o)
    need(o == f"{ROOT}/owners/{owner}" and s == o + "/service")
    a = o + "/active/"
    for path in (o, s, o + "/active"):
        check(path, 0o700, True)
    check(s + "/activation.json", 0o600)
    with open(s + "/activation.json", "rb") as stream:
        r = json.load(stream)
    with open(ROOT + "/action-profile.json", "rb") as stream:
        p = json.load(stream)
    agent = r["kind"] == "agent-activation"
    need(r["kind"] in ("agent-activation", "server-activation") and r["schema"] == (3 if agent else 2) and r["owner"] == owner)
    ids = r["identities"]
    if agent:
        need(r["member"]["role"] == "agent" and set(ids) == {"config", "unit", "agent-token", "guard", "log"})
        need(set(r["input"]) == {"generation"} and re.fullmatch(r"[0-9a-f]{32}", r["input"]["generation"]))
        need(not any(os.path.lexists(p) for p in (UNIT + ".service", a + "server-token", o + "/admin-raw.yaml", o + "/admin.yaml")))
    st = os.lstat(K3S)
    need(st.st_uid == 0 and not st.st_mode & 0o022 and stat.S_ISREG(st.st_mode) and
         [st.st_dev, st.st_ino] == r["executable"]["identity"])
    need(digest(K3S) == r["executable"]["sha256"] == p["k3s_sha256"])
    unit = UNIT + ("-agent.service" if agent else ".service")
    for path, mode, name, expected in ((CONFIG, 0o600, "config", r["config_sha256"]),
                                       (unit, 0o644, "unit", r["unit_sha256"]),
                                       (s + "/guard.py", 0o700, "guard", r["guard_sha256"])):
        need(check(path, mode) == ids[name] and digest(path) == expected)
    need(os.path.abspath(__file__) == s + "/guard.py")
    with open(CONFIG, encoding="utf-8") as stream:
        c = json.load(stream)
    joined = "server" in c
    if agent:
        need(set(c) == {"server", "token-file", "node-name", "node-ip", "node-label", "node-taint",
                        "disable-default-registry-endpoint"} and c["token-file"] == a + "agent-token" and
             c["node-name"] == r["member"]["member"] and c["server"].startswith("https://"))
    else:
        need(joined != ("cluster-init" in c) and (joined or c["cluster-init"] is True))
    for name in (("agent-token", "log") if agent else ("server-token", "agent-token", "log")):
        path = s + "/service.log" if name == "log" else a + name
        need(check(path, 0o600) == ids[name])
    with open(a + "agent-token", "rb") as stream:
        token = stream.read(4097)
    if agent:
        need(re.fullmatch(rb"K10[0-9a-f]{64}::node:[0-9a-f]{64}", token))
    else:
        with open(a + "server-token", "rb") as stream:
            server = stream.read(4097)
        pattern = rb"K10[0-9a-f]{64}::server:[0-9a-f]{64}" if joined else rb"[0-9a-f]{64}\n?"
        need(re.fullmatch(pattern, server) is not None and
             re.fullmatch(rb"[0-9a-f]{64}\n?", token) is not None and server != token)


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001 - every difference refuses the start
        print(REFUSAL, flush=True)
        sys.exit(1)
