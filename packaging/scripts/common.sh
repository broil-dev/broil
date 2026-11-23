#!/usr/bin/env bash
set -euo pipefail

pkg_die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

pkg_repo_root() {
    local dir="${1:-$PWD}"

    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/Cargo.toml" && -f "$dir/Cargo.lock" && -d "$dir/packaging" ]]; then
            (cd "$dir" && pwd -P)
            return 0
        fi
        dir="$(dirname "$dir")"
    done

    pkg_die "run from the Broil source or release project root"
}

pkg_container_engine() {
    if [[ -n "${CONTAINER_ENGINE:-}" ]]; then
        command -v "$CONTAINER_ENGINE" >/dev/null 2>&1 || pkg_die "container engine not found: $CONTAINER_ENGINE"
        printf '%s\n' "$CONTAINER_ENGINE"
        return 0
    fi

    if command -v docker >/dev/null 2>&1; then
        printf '%s\n' docker
        return 0
    fi

    if command -v podman >/dev/null 2>&1; then
        printf '%s\n' podman
        return 0
    fi

    pkg_die "install docker or podman, or set CONTAINER_ENGINE"
}

pkg_load_target_config() {
    TARGET_TRIPLE="${TARGET_TRIPLE:-x86_64-unknown-linux-gnu}"

    case "$TARGET_TRIPLE" in
        x86_64-unknown-linux-gnu)
            TARGET_NOTICE_PATH="THIRD-PARTY-NOTICES.md"
            ;;
        *)
            pkg_die "unsupported release target: $TARGET_TRIPLE"
            ;;
    esac

    TARGET_ROOT="packaging/targets/$TARGET_TRIPLE"
    BUILDER_DEFINITION_PATH="$TARGET_ROOT/builder/Containerfile"

    [[ -f "$BUILDER_DEFINITION_PATH" ]] || pkg_die "missing builder definition: $BUILDER_DEFINITION_PATH"
    [[ -f "$TARGET_NOTICE_PATH" ]] || pkg_die "missing target notice: $TARGET_NOTICE_PATH"
}

pkg_is_git_worktree() {
    git rev-parse --is-inside-work-tree >/dev/null 2>&1
}

pkg_require_clean_git_checkout() {
    pkg_is_git_worktree || return 0

    local status
    status="$(git status --porcelain=v1 --untracked-files=all 2>/dev/null)" || {
        pkg_die "cannot inspect git checkout status"
    }

    [[ -z "$status" ]] || {
        pkg_die "refusing release package from dirty git checkout; commit, remove, or ignore local changes before packaging"
    }
}

pkg_resolved_source_revision_matching_head() {
    local value="$1"

    pkg_is_git_worktree || {
        printf '%s\n' "$value"
        return 0
    }
    pkg_require_clean_git_checkout

    local head_revision
    local explicit_revision

    head_revision="$(git rev-parse --verify "HEAD^{commit}" 2>/dev/null)" || {
        pkg_die "cannot inspect git HEAD for SOURCE_REVISION"
    }
    explicit_revision="$(git rev-parse --verify --end-of-options "${value}^{commit}" 2>/dev/null)" || {
        pkg_die "SOURCE_REVISION must resolve to git HEAD when run from a Git checkout"
    }

    [[ "$explicit_revision" == "$head_revision" ]] || {
        pkg_die "SOURCE_REVISION resolves to $explicit_revision but checkout HEAD is $head_revision"
    }

    printf '%s\n' "$explicit_revision"
}

pkg_source_revision() {
    local value="${SOURCE_REVISION:-}"

    if [[ -z "$value" ]]; then
        pkg_is_git_worktree || pkg_die "set SOURCE_REVISION when git HEAD is unavailable"
        pkg_require_clean_git_checkout
        value="$(git rev-parse --verify HEAD 2>/dev/null)" || pkg_die "set SOURCE_REVISION when git HEAD is unavailable"
    fi

    [[ "$value" != *$'\n'* && -n "$value" ]] || pkg_die "SOURCE_REVISION must be a single non-empty value"
    if [[ -n "${SOURCE_REVISION:-}" ]]; then
        value="$(pkg_resolved_source_revision_matching_head "$value")"
    fi

    printf '%s\n' "$value"
}

pkg_source_date_epoch() {
    local value="${SOURCE_DATE_EPOCH:-}"

    if [[ -z "$value" ]]; then
        value="$(git log -1 --format=%ct HEAD 2>/dev/null)" || pkg_die "set SOURCE_DATE_EPOCH when git history is unavailable"
    fi

    [[ "$value" =~ ^[0-9]+$ ]] || pkg_die "SOURCE_DATE_EPOCH must be a non-negative integer"
    printf '%s\n' "$value"
}

pkg_image_identity() {
    local engine="$1"
    local tag="$2"
    local identity

    identity="$("$engine" image inspect --format '{{.Id}}' "$tag" 2>/dev/null)" || {
        pkg_die "builder image not found for tag $tag; run packaging/scripts/build-builder-image.sh"
    }

    [[ -n "$identity" ]] || pkg_die "empty image identity for $tag"
    printf '%s\n' "$identity"
}
