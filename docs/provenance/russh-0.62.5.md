# Vendored Russh Provenance

This document is the release-carried provenance record for the modified
`russh 0.62.5` source tree at `crates/vendor/russh-0.62.5/`.

## Selected Source

| Item | Identity |
| --- | --- |
| Release version | `v0.1.0` |
| Release identity mode | version tag |
| Release artifact scope | independent source tree |
| Vendored package path | `crates/vendor/russh-0.62.5/` |
| Vendored package Git tree | `8aa6b2d53df8d22feba6692f6d4e4491f736a296` |
| Vendored package structural tree SHA-256 | `499508c733f299545e379c6bc1b69f9c9f5314a53e5dd42f46dccaee1661f099` |
| Upstream archive | `docs/dev/ssh-hardening-evidence/russh-0.62.5.crate` |
| Upstream archive SHA-256 | `da7c230e0ed9cbeb92fbad6c8848985d6df2a1464c0dc247a021abd666e9005e` |
| Upstream revision | `4882af71cf27ea5293636bf4985ef296dcf20896` |
| Pristine archive tree SHA-256 | `f977b09a136975ecf7313995ce8a3640aac20fc24f4570963dd5dad8b9b1c941` |
| License SHA-256 | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| Upstream root listing SHA-256 | `ede150c02915205045a54a220223b31707c683f9e94ae904511c335c7f0d188e` |

## Production Boundary

The selected automated SSH backend uses vendored `russh 0.62.5` with the `ring`
feature and default features disabled. The initial production evidence covers
`x86_64-unknown-linux-gnu`, the locked normal dependency closure for the
released `broil` binary, and 162 production packages.

Relevant target-local evidence is carried in
`docs/dev/ssh-hardening-evidence/context.txt`, with supporting evidence files in
the same directory.

## Modification Scope

Only these six vendored source files differ from the pristine archive, apart
from the added license and Broil provenance notices:

- `src/auth.rs`
- `src/client/encrypted.rs`
- `src/client/mod.rs`
- `src/keys/format/mod.rs`
- `src/keys/format/pkcs5.rs`
- `src/keys/mod.rs`

Each modified source contains exactly once:

```text
// Modified by the Broil project from russh 0.62.5; see LICENSE.txt and docs/provenance/russh-0.62.5.md for provenance.
```

The reviewed semantic changes are represented by:

| Item | SHA-256 |
| --- | --- |
| Vendor patch | `039ab5dfdbbe2e6a1b8f70d192e2b22713bdcd77e2127c80db37db4ee097c858` |
| Upstream-root patch | `6f81d55ed98298b3192daaf8816907d29d0ca21d8522620574ad72b5a520e05a` |
| Patched pre-notice tree | `ec260bcb6251182504d2ef6976206329f7eaea11f367ec819724902e0a1647cc` |

The final vendored tree hash includes the Broil modification notices. A
separate tree guard demonstrates that a one-byte vendored-tree mutation changes
the structural tree identity, while Cargo's lockfile alone does not authenticate
path dependency contents.

## Release Notes

This file is the stable provenance target for source releases. Development-only
automation paths are intentionally omitted from this release-carried record.
