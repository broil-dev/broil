#!/usr/bin/env bash
# Source-built filesystem helper. Run from the source repository root.
set -euo pipefail
image_worker_output="${1:?usage: build-worker.sh OUTPUT_DIRECTORY [INSTALLED_HELPER]}"
case "$image_worker_output" in /*) ;; *) echo 'output directory must be absolute' >&2; exit 2 ;; esac
export CARGO_TARGET_DIR="$image_worker_output"
export CARGO_BUILD_JOBS=1
image_worker_source="$(pwd -P)"
image_worker_cargo_source="$(realpath -m -- "${CARGO_HOME:-$HOME/.cargo}")"
export RUSTFLAGS="--remap-path-prefix=$image_worker_source=/broil --remap-path-prefix=$image_worker_cargo_source=/cargo -C link-arg=-Wl,--build-id=none"
cargo +1.92.0 build --locked --release --target x86_64-unknown-linux-gnu -p broil-command --bin broil-image-client-worker
if [[ $# == 2 ]]; then
    cp -- "$image_worker_output/x86_64-unknown-linux-gnu/release/broil-image-client-worker" "$2"
    chmod 0700 -- "$2"
fi
