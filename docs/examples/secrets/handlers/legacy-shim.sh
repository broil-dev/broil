#!/usr/bin/env bash
# Adapt the four documented legacy profiles without changing their source files.
set -euo pipefail
export LC_ALL=C
die() { printf '%s\n' "$1" >&2; exit 1; }
[[ $# -ge 3 ]] || die 'Usage: legacy-shim.sh <profile> <source-file> <callback...>'
profile=$1
source_file=$2
shift 2
case "$profile" in db-password|api-key|ssh-key|inter-service-token) ;; *) die 'Unknown legacy profile.' ;; esac
[[ -f "$source_file" && ! -L "$source_file" ]] || die 'Source handler unavailable.'
if [[ "$*" == capabilities ]]; then
    printf '{"recreate":[]}\n'
    exit 0
fi
[[ $# == 2 ]] || die 'Invalid callback.'
state=$1
verb=$2
case "$state:$verb" in
    CREATED:action|CREATED:verify|CREATED:rollback|TRANSITION_READY:action|TRANSITION_READY:verify|TRANSITION_READY:rollback|DEPLOYED:verify|DEPLOYED:rollback|OLD_REVOKED:action|OLD_REVOKED:verify|OLD_REVOKED:rollback|VERIFIED:verify|VERIFIED:rollback) ;;
    *) die 'Unsupported mapping; Broil owns STORE_UPDATED and deploy dispatch.' ;;
esac
[[ ${BROIL_ROTATION_ID:-} =~ ^[0-9]{14}[0-9a-f]{8}$ ]] || die 'Invalid recorded rotation ID.'
[[ ${BROIL_ROTATION_SET:-} == */* ]] || die 'Missing store-relative set.'
export ROTATION_PROJECT=${BROIL_ROTATION_SET%%/*}
export ROTATION_ENV=${BROIL_ROTATION_SET#*/}
export ROTATION_SECRET_KEY=${BROIL_ROTATION_KEY:?}
unset ROTATION_NEW_VALUE ROTATION_NEW_PUBKEY ROTATION_SSH_DIR
ROTATION_NEW_VALUE=
IFS= builtin read -r -d '' -n 1048577 ROTATION_NEW_VALUE || true
[[ ${#ROTATION_NEW_VALUE} -le 1048576 ]] || die 'Candidate too large.'
supplied=false
[[ -z "$ROTATION_NEW_VALUE" ]] || supplied=true

# Every legacy read has a private terminal. Stdout stays discarded, including
# the inter-service-token callback that prints its secret value.
read() {
    [[ ${BROIL_ROTATION_NON_INTERACTIVE:-} != 1 ]] || die 'Legacy manual callback requires a private terminal.'
    local tty
    exec {tty}<>/dev/tty || die 'Private terminal unavailable.'
    case "${*: -1}" in
        ROTATION_NEW_VALUE) printf 'Enter the provider key (hidden): ' >&"$tty" ;;
        answer) printf 'Verify the described external effect (y/n): ' >&"$tty" ;;
        *) printf 'Complete the described external action, then press Enter: ' >&"$tty" ;;
    esac
    local result=0
    builtin read "$@" <&"$tty" || result=$?
    exec {tty}>&-
    return "$result"
}
confirm() {
    [[ ${BROIL_ROTATION_NON_INTERACTIVE:-} != 1 ]] || die 'External proof requires a private terminal.'
    local answer tty
    exec {tty}<>/dev/tty || die 'Private terminal unavailable.'
    printf '%s\nConfirmed (yes/no): ' "$1" >&"$tty"
    IFS= builtin read -r answer <&"$tty" || { exec {tty}>&-; return 1; }
    exec {tty}>&-
    [[ "$answer" == yes ]]
}

if [[ "$profile" == db-password ]]; then
    # The inspected source prologue is non-mutating. Supply a valid placeholder
    # so it cannot select its date-derived fallback while discovering the user.
    resolved_user=$(
        export ROTATION_TEMP_ROLE=broil_probe
        source "$source_file" >/dev/null
        printf '%s' "$ROTATION_DB_USER"
    )
    [[ "$resolved_user" =~ ^[a-z_][a-z0-9_]*$ && ${#resolved_user} -le 39 ]] || die 'DB user must be lowercase ASCII and at most 39 bytes.'
    export ROTATION_DB_USER=$resolved_user
    export ROTATION_TEMP_ROLE="${resolved_user}_r${BROIL_ROTATION_ID}"
fi

# Reconstruct legacy SSH metadata from the supplied private input in a private,
# ID-derived directory. An unpersisted source note is never required on CREATED.
prepare_ssh_dir() {
    local parent=/dev/shm
    if [[ ! -d "$parent" || ! -w "$parent" ]]; then
        parent=${TMPDIR:-/tmp}
        printf 'SSH shim uses persistent temporary storage; crashes may leave private material.\n' >&2
    fi
    [[ "$parent" == /* && ! -L "$parent" && "$parent" != *$'\n'* && "$parent" != *$'\r'* && ${#parent} -le 3800 ]] || die 'Unsafe temporary parent.'
    ROTATION_SSH_DIR="$parent/broil-legacy-ssh-$BROIL_ROTATION_ID"
    if [[ ! -e "$ROTATION_SSH_DIR" && ! -L "$ROTATION_SSH_DIR" ]]; then
        mkdir -m 700 -- "$ROTATION_SSH_DIR"
    fi
    [[ -d "$ROTATION_SSH_DIR" && ! -L "$ROTATION_SSH_DIR" && -O "$ROTATION_SSH_DIR" ]] || die 'Unsafe SSH directory.'
    [[ $(stat -c %a -- "$ROTATION_SSH_DIR") == 700 ]] || die 'Unsafe SSH directory mode.'
    for path in "$ROTATION_SSH_DIR/new_key" "$ROTATION_SSH_DIR/new_key.pub"; do
        [[ ! -e "$path" && ! -L "$path" ]] || [[ -f "$path" && ! -L "$path" && -O "$path" ]] || die 'Unsafe SSH file.'
    done
    export ROTATION_SSH_DIR
}
if [[ "$profile" == ssh-key ]]; then
    prepare_ssh_dir
    if $supplied; then
        private_file=$(command mktemp "$ROTATION_SSH_DIR/.key-XXXXXXXX")
        chmod 600 -- "$private_file"
        printf '%s' "$ROTATION_NEW_VALUE" > "$private_file"
        # OpenSSH's file reader needs a final LF; the framed/store value remains
        # byte-identical to the source shell variable (including a missing LF).
        [[ "$ROTATION_NEW_VALUE" == *$'\n' ]] || printf '\n' >> "$private_file"
        mv -f -- "$private_file" "$ROTATION_SSH_DIR/new_key"
        ROTATION_NEW_PUBKEY=$(ssh-keygen -y -f "$ROTATION_SSH_DIR/new_key" 2>/dev/null) || die 'SSH candidate invalid.'
        export ROTATION_NEW_PUBKEY
    fi
    # Only the documented source's mktemp -d call is mapped. Its files remain
    # handler-owned; no Broil store/cursor path can be supplied here.
    mktemp() {
        [[ $# == 1 && $1 == -d ]] || die 'Unknown source temporary-file operation.'
        prepare_ssh_dir
        rm -f -- "$ROTATION_SSH_DIR/new_key" "$ROTATION_SSH_DIR/new_key.pub"
        printf '%s\n' "$ROTATION_SSH_DIR"
    }
fi
source "$source_file" >/dev/null
call() {
    declare -F "$1" >/dev/null || die 'Source callback unavailable.'
    if [[ "$profile" == db-password && ( "$1" == verify_created || "$1" == verify_deployed ) ]]; then
        PGPASSWORD=$ROTATION_NEW_VALUE "$@" >/dev/null
    else
        "$@" >/dev/null
    fi
}
printf 'Legacy %s: %s %s. Broil owns all store and vault updates.\n' "$profile" "$state" "$verb" >&2

if [[ "$verb" == rollback ]]; then
    case "$state" in
        CREATED)
            call rollback_created
            if [[ "$profile" == db-password || "$profile" == api-key ]]; then
                confirm 'Verify creation residue is removed on every host/provider; inspect the dashboard for provider-assigned orphan keys.'
            fi
            ;;
        *) confirm "Undo $state externally and restore consumers using the old current value. Do not run legacy git checkout, SOPS edits or whole-document vault sync." ;;
    esac
    exit 0
fi

case "$state:$verb" in
    CREATED:action)
        if $supplied && [[ "$profile" != db-password ]]; then
            # API/token/SSH source actions unconditionally replace their input;
            # the supplied candidate already fulfills their creation operation.
            [[ "$profile" != api-key ]] || confirm 'Confirm this supplied key was created at the provider and belongs to this rotation.'
        else
            [[ "$profile" != api-key ]] || printf 'Create a key at the provider. An interruption before persistence may orphan it.\n' >&2
            call action_created
        fi
        [[ -n "$ROTATION_NEW_VALUE" && ${#ROTATION_NEW_VALUE} -le 1048576 ]] || die 'Source did not return a bounded candidate.'
        if ! $supplied; then
            printf 'BROIL_ROTATION_VALUE_BYTES=%s\n' "${#ROTATION_NEW_VALUE}"
            printf '%s' "$ROTATION_NEW_VALUE"
        fi
        if [[ "$profile" == ssh-key ]]; then
            $supplied || printf '\n'
            printf 'BROIL_ROTATION_NOTE=%s\n' "$ROTATION_SSH_DIR"
        fi
        ;;
    CREATED:verify) call verify_created ;;
    TRANSITION_READY:*)
        case "$profile" in
            db-password|api-key)
                call verify_created
                confirm 'Prove the candidate and old access both work; prepare consumers to use the candidate. For DBs, deploy with the temporary role on every configured host. Do not edit/sync the store.'
                ;;
            *)
                printf 'Install dual access at the receiver/SSH targets; use explicit secrets reads if needed.\n' >&2
                if [[ "$profile" == ssh-key && "$verb" == action ]]; then printf '%s\n' "$ROTATION_NEW_PUBKEY" >&2; fi
                call "${verb}_transition_ready"
                ;;
        esac
        ;;
    DEPLOYED:verify)
        if [[ "$profile" == db-password || "$profile" == api-key ]]; then call verify_store_updated; else call verify_deployed; fi
        ;;
    OLD_REVOKED:action)
        printf 'Revoke old external access now; verify all hosts/providers.\n' >&2
        if [[ "$profile" == db-password || "$profile" == api-key ]]; then
            call action_deployed
            call verify_deployed
            if [[ "$profile" == db-password ]]; then confirm 'Switch consumers back to the original DB role with the current password on every host before dropping the temporary role.'; fi
        fi
        call action_old_revoked
        ;;
    OLD_REVOKED:verify)
        if [[ "$profile" == db-password || "$profile" == api-key ]]; then call verify_deployed; fi
        call verify_old_revoked
        ;;
    VERIFIED:verify)
        call verify_final
        if [[ "$profile" == ssh-key ]]; then
            rm -f -- "$ROTATION_SSH_DIR/new_key" "$ROTATION_SSH_DIR/new_key.pub"
            rmdir -- "$ROTATION_SSH_DIR"
        fi
        ;;
    *) die 'Unknown callback mapping.' ;;
esac
