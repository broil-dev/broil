#!/usr/bin/env bash
set -euo pipefail

policy_command=${BROIL_EXAMPLE_SSHD_POLICY_COMMAND:-sshd -T}
policy=$(sh -c "$policy_command")

if ! printf '%s\n' "$policy" | awk '
  tolower($1) == "subsystem" && tolower($2) == "sftp" { found = 1 }
  END { exit found ? 0 : 1 }
'; then
  printf 'sftp subsystem is not enabled in effective sshd policy\n' >&2
  exit 1
fi
