#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/common.sh"

ROOT="$(pkg_repo_root)"
cd "$ROOT"

pkg_load_target_config

ENGINE="$(pkg_container_engine)"
IMAGE_TAG="${BUILDER_IMAGE_TAG:-broil-release-builder:$TARGET_TRIPLE}"
IMAGE_IDENTITY="$(pkg_image_identity "$ENGINE" "$IMAGE_TAG")"
pkg_require_clean_git_checkout
SOURCE_REVISION_VALUE="$(pkg_source_revision)"
SOURCE_DATE_EPOCH_VALUE="$(pkg_source_date_epoch)"
OUTPUT_DIR_VALUE="${OUTPUT_DIR:-packaging/out/$TARGET_TRIPLE}"
PYTHON_BIN="${PYTHON:-python3}"
VOLUME_SUFFIX="${CONTAINER_VOLUME_SUFFIX:-}"

case "$VOLUME_SUFFIX" in
    "" | ":z" | ":Z")
        ;;
    *)
        pkg_die "CONTAINER_VOLUME_SUFFIX may only be empty, :z, or :Z"
        ;;
esac

command -v "$PYTHON_BIN" >/dev/null 2>&1 || pkg_die "python3 is required to create deterministic archives"

BUILDER_RUSTC_VERSION="$("$ENGINE" run --rm "$IMAGE_TAG" rustc --version --verbose)" || {
    pkg_die "failed to read rustc version from builder image $IMAGE_TAG"
}

REMAP_FLAG="--remap-path-prefix=/workspace=."
[[ -z "${RUSTFLAGS:-}" ]] || pkg_die "RUSTFLAGS must not be set for release packaging; the script sets only $REMAP_FLAG"
RUSTFLAGS_VALUE="$REMAP_FLAG"

USER_ARGS=()
if [[ "${CONTAINER_RUN_AS_CURRENT_USER:-1}" != "0" ]]; then
    USER_ARGS=(--user "$(id -u):$(id -g)" -e "HOME=/tmp" -e "CARGO_HOME=/tmp/cargo")
fi

"$ENGINE" run --rm \
    "${USER_ARGS[@]}" \
    -v "$ROOT:/workspace$VOLUME_SUFFIX" \
    -w /workspace \
    -e CARGO_INCREMENTAL=0 \
    -e CARGO_TERM_COLOR=never \
    -e "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH_VALUE" \
    -e "RUSTFLAGS=$RUSTFLAGS_VALUE" \
    "$IMAGE_TAG" \
    cargo build --locked --release --bin broil --target "$TARGET_TRIPLE"

BINARY_PATH="target/$TARGET_TRIPLE/release/broil"
[[ -f "$BINARY_PATH" ]] || pkg_die "expected canonical binary missing: $BINARY_PATH"

CREATE_ARGS=(
    "$SCRIPT_DIR/create-tarball.py"
    --root "$ROOT"
    --target-triple "$TARGET_TRIPLE"
    --binary "$BINARY_PATH"
    --notice-path "$TARGET_NOTICE_PATH"
    --builder-definition-path "$BUILDER_DEFINITION_PATH"
    --builder-image-identity "$IMAGE_IDENTITY"
    --builder-rustc-version "$BUILDER_RUSTC_VERSION"
    --source-revision "$SOURCE_REVISION_VALUE"
    --source-date-epoch "$SOURCE_DATE_EPOCH_VALUE"
    --output-dir "$OUTPUT_DIR_VALUE"
)

if [[ -n "${BROIL_VERSION:-}" ]]; then
    CREATE_ARGS+=(--package-version "$BROIL_VERSION")
fi

"$PYTHON_BIN" "${CREATE_ARGS[@]}"
