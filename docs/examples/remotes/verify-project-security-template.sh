#!/usr/bin/env bash
set -euo pipefail

# Replace these hooks with project-owned security checks. Each hook should be a
# fixed trusted command from configuration, not user input.
required_hooks=${BROIL_EXAMPLE_SECURITY_HOOKS:-}
if [[ -z "$required_hooks" ]]; then
  printf 'BROIL_EXAMPLE_SECURITY_HOOKS is empty\n' >&2
  exit 1
fi

while IFS= read -r hook; do
  [[ -z "$hook" ]] && continue
  sh -c "$hook"
done <<EOF
$required_hooks
EOF
