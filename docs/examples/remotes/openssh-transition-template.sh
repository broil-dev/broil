#!/usr/bin/env bash
set -euo pipefail

phase=${1:-}
if [[ -z "$phase" ]]; then
  printf 'usage: %s <prepare|apply|validate|reload|rollback>\n' "$0" >&2
  exit 2
fi

run_hook() {
  local name=$1
  local command=${!name:-}
  if [[ -z "$command" ]]; then
    printf 'missing required project hook %s\n' "$name" >&2
    exit 1
  fi
  sh -c "$command"
}

case "$phase" in
  prepare)
    # Create backups or rollback markers. Keep them owner/root protected.
    run_hook BROIL_EXAMPLE_SSH_PREPARE_COMMAND
    ;;
  apply)
    # Enable canonical public-key access, disable weaker steady-state auth,
    # and enable SFTP using project-owned OS policy.
    run_hook BROIL_EXAMPLE_SSH_APPLY_COMMAND
    ;;
  validate)
    # Validate prospective daemon configuration before reload.
    run_hook BROIL_EXAMPLE_SSH_VALIDATE_COMMAND
    ;;
  reload)
    # Reload without reboot. A reboot belongs in a later configure action.
    run_hook BROIL_EXAMPLE_SSH_RELOAD_COMMAND
    ;;
  rollback)
    # Restore the prepared state through the retained bootstrap connection.
    run_hook BROIL_EXAMPLE_SSH_ROLLBACK_COMMAND
    ;;
  *)
    printf 'unknown transition phase: %s\n' "$phase" >&2
    exit 2
    ;;
esac
