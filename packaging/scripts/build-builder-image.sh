#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
source "$SCRIPT_DIR/common.sh"

ROOT="$(pkg_repo_root)"
cd "$ROOT"

pkg_load_target_config

ENGINE="$(pkg_container_engine)"
IMAGE_TAG="${BUILDER_IMAGE_TAG:-broil-release-builder:$TARGET_TRIPLE}"
BUILD_CONTEXT="$ROOT/$TARGET_ROOT/builder"
OUTPUT_DIR="${OUTPUT_DIR:-packaging/out/$TARGET_TRIPLE}"

"$ENGINE" build \
    --label "org.opencontainers.image.title=Broil release builder" \
    --label "org.opencontainers.image.description=Local Broil release builder for $TARGET_TRIPLE" \
    --label "org.broil.release.target=$TARGET_TRIPLE" \
    -f "$ROOT/$BUILDER_DEFINITION_PATH" \
    -t "$IMAGE_TAG" \
    "$BUILD_CONTEXT"

IMAGE_IDENTITY="$(pkg_image_identity "$ENGINE" "$IMAGE_TAG")"

mkdir -p "$OUTPUT_DIR"
{
    printf 'target=%s\n' "$TARGET_TRIPLE"
    printf 'tag=%s\n' "$IMAGE_TAG"
    printf 'definition=%s\n' "$BUILDER_DEFINITION_PATH"
    printf 'identity=%s\n' "$IMAGE_IDENTITY"
} > "$OUTPUT_DIR/builder-image.txt"

printf 'builder_image_tag=%s\n' "$IMAGE_TAG"
printf 'builder_image_identity=%s\n' "$IMAGE_IDENTITY"
