#!/usr/bin/env bash
# Copyright 2026 Broil contributors
# SPDX-License-Identifier: Apache-2.0
# Build the Metrics Server derivative with its exact reviewed module overlay.
set -euo pipefail
metrics_source="${1:?usage: build-metrics-server.sh ABSOLUTE_SOURCE ABSOLUTE_OUTPUT}"
metrics_output="${2:?usage: build-metrics-server.sh ABSOLUTE_SOURCE ABSOLUTE_OUTPUT}"
case "$metrics_source:$metrics_output" in /*:/*) ;; *) exit 2 ;; esac
python3 - "$metrics_source" "$metrics_output" "${BASH_SOURCE[0]}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

source, output, script = map(Path, sys.argv[1:])
lock = json.loads((script.parent / "metrics-server-source.lock.json").read_bytes())
overlay_path = script.parent / lock["overlay"]["file"]
assert hashlib.sha256(overlay_path.read_bytes()).hexdigest() == lock["overlay"]["sha256"]
overlay = json.loads(overlay_path.read_bytes())
for name, identity in lock["source"]["files"].items():
    identity = overlay["derived_files"].get(name, identity)
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == identity["sha256"], "derived-source-required"
env = {key: os.environ[key] for key in ("PATH", "GOCACHE", "GOMODCACHE")}
env.update(lock["environment"])
assert subprocess.check_output(["go", "version"], env=env).strip() == b"go version go1.27.1 linux/amd64"
argv = [str(output) if value == "{output}" else value for value in lock["build_command"]]
subprocess.run(argv, cwd=source, env=env, check=True, timeout=900)
PY
chmod 0700 -- "$metrics_output"
