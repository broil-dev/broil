# Broil Release Packaging

This tree contains source-controlled release packaging inputs carried into the
release project.

The initial supported target is `x86_64-unknown-linux-gnu`. Generated package
outputs are written under `packaging/out/` and are intentionally ignored.

## Build the local builder image

Run from the source or release project root:

```sh
packaging/scripts/build-builder-image.sh
```

The default image tag is `broil-release-builder:x86_64-unknown-linux-gnu`.
Set `CONTAINER_ENGINE=podman` to use Podman, or `BUILDER_IMAGE_TAG=<tag>` to
choose another local tag.

The builder image is local-first. The scripts do not require pushing a Broil
image to Docker Hub or another registry. The current builder uses the official
Rust base image tag recorded in the target Containerfile; the manifest records
the rebuilt local image identity for the release artifact.

## Build the tar.gz archive

Run from the source or release project root after building the local image:

```sh
packaging/scripts/package-tarball.sh
```

Inputs may be overridden with environment variables:

| Variable | Default |
| --- | --- |
| `TARGET_TRIPLE` | `x86_64-unknown-linux-gnu` |
| `CONTAINER_ENGINE` | first available `docker`, then `podman` |
| `BUILDER_IMAGE_TAG` | `broil-release-builder:$TARGET_TRIPLE` |
| `SOURCE_REVISION` | clean `git rev-parse --verify HEAD` |
| `SOURCE_DATE_EPOCH` | `git log -1 --format=%ct HEAD` |
| `BROIL_VERSION` | `[workspace.package].version` from `Cargo.toml` |
| `OUTPUT_DIR` | `packaging/out/$TARGET_TRIPLE` |

The package script builds `broil` inside the local builder with the committed
`Cargo.lock`, `--locked`, target `x86_64-unknown-linux-gnu`, disabled
incremental compilation, and a `/workspace` path remap.

When run from a Git checkout, the package script rejects uncommitted,
untracked, non-ignored files before packaging. Caller `RUSTFLAGS` is also
rejected; release packaging sets only the deterministic `/workspace` path
remap.

If `SOURCE_REVISION` is set from a Git checkout, it must resolve to the current
clean `HEAD`, and the manifest records that resolved commit. Use an
archive/source identity override only when packaging from a non-Git source tree.

## Outputs

For version `<version>` and target `<target>`, the output directory contains:

- `broil-<version>-<target>.tar.gz`
- `SHA256SUMS`

The archive contains exactly four file entries below
`broil-<version>-<target>/`:

- `LICENSE`
- `THIRD-PARTY-NOTICES.md`
- `broil`
- `manifest.json`

Tar entry order, modes, ownership, and mtimes are deterministic. Gzip metadata
uses the recorded `SOURCE_DATE_EPOCH` and carries no local file name.

The manifest records the source revision, target triple, timestamp seed,
`Cargo.lock` hash, builder definition path, local builder image identity,
`rustc --version --verbose`, canonical binary hash and size, and legal-file
hashes.

## Rebuild comparison

Downloader/operator verification compares the rebuilt canonical binary SHA-256
with `binary.sha256` in the archive manifest, not the archive bytes:

1. Extract `manifest.json` from the released archive and record
   `source_revision`, `source_date_epoch`, `target_triple`,
   `builder.definition_path`, `builder.image_identity`, `binary.sha256` and
   the `legal.*` fields.
2. Check out the recorded source revision, with no uncommitted or untracked
   non-ignored files.
3. Rebuild the local builder image from the recorded builder definition:

   ```sh
   TARGET_TRIPLE=x86_64-unknown-linux-gnu \
     packaging/scripts/build-builder-image.sh
   ```

   Its local image identity should match `builder.image_identity`; record a
   mismatch as the reproducibility boundary being evaluated.
4. Rebuild with the manifest's timestamp seed:

   ```sh
   SOURCE_REVISION=<manifest-source-revision> \
   SOURCE_DATE_EPOCH=<manifest-source-date-epoch> \
   TARGET_TRIPLE=x86_64-unknown-linux-gnu \
     packaging/scripts/package-tarball.sh
   ```

5. Compare the rebuilt canonical binary digest with `binary.sha256`:

   ```sh
   sha256sum target/x86_64-unknown-linux-gnu/release/broil
   ```

6. Confirm that the archive's legal files match the repository's notice
   inputs. For `x86_64-unknown-linux-gnu`, `legal.notices_path` is
   `THIRD-PARTY-NOTICES.md`.

A differing binary digest fails verification even when the archive structure,
its checksum and the legal files are valid.
