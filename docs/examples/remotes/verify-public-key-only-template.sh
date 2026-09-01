#!/usr/bin/env bash
set -euo pipefail

policy_command=${BROIL_EXAMPLE_SSHD_POLICY_COMMAND:-sshd -T}
policy=$(sh -c "$policy_command")

require_setting() {
  local key=$1
  local value=$2
  if ! printf '%s\n' "$policy" | awk -v k="$key" -v v="$value" '
    tolower($1) == k && tolower($2) == v { found = 1 }
    END { exit found ? 0 : 1 }
  '; then
    printf 'required sshd setting missing: %s %s\n' "$key" "$value" >&2
    exit 1
  fi
}

require_setting pubkeyauthentication yes
require_setting passwordauthentication no
require_setting kbdinteractiveauthentication no

if printf '%s\n' "$policy" | awk '
  tolower($1) == "challengeresponseauthentication" && tolower($2) != "no" { found = 1 }
  END { exit found ? 0 : 1 }
'; then
  printf 'challenge-response authentication remains enabled\n' >&2
  exit 1
fi
