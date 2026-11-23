# Vendored Russh Provenance

This document is the release-carried provenance record for the modified
`russh 0.62.5` source tree at `crates/vendor/russh-0.62.5/`.

## Candidate Source

| Item | Identity |
| --- | --- |
| Release version | `v0.2.0` |
| Release identity mode | version tag |
| Release artifact scope | independent source tree |
| Vendored package path | `crates/vendor/russh-0.62.5/` |
| Vendored package Git tree | `72a18b698711d07bf9d3201ff0c90668ee8ad20d` |
| Vendored package structural tree SHA-256 | `31770301ec8d79fcd8a2dd59f8b1ed136d604254f8671eb17241b8ffa131e245` |
| Upstream archive | `russh-0.62.5.crate`, as published on crates.io |
| Upstream archive SHA-256 | `da7c230e0ed9cbeb92fbad6c8848985d6df2a1464c0dc247a021abd666e9005e` |
| Upstream revision | `4882af71cf27ea5293636bf4985ef296dcf20896` |
| Pristine archive tree SHA-256 | `f977b09a136975ecf7313995ce8a3640aac20fc24f4570963dd5dad8b9b1c941` |
| License SHA-256 | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| Upstream root listing SHA-256 | `ede150c02915205045a54a220223b31707c683f9e94ae904511c335c7f0d188e` |

## Production Boundary

The candidate automated SSH backend uses vendored `russh 0.62.5` with the `ring`
feature and default features disabled. The initial production evidence covers
`x86_64-unknown-linux-gnu`, the locked normal dependency closure for the
released `broil` binary, and 176 exact normal package identities. This candidate
requires final code review and renewed production selection. Its
status is `candidate-pending-qualification`. Prior identities and the
target-local evidence are retained in the source repository's development
records, which a source release does not carry.

The additional state channel permits one fixed 1048576-byte public stdout
response per private connection. Ordinary stdout and aggregate stderr keep
their 65536-byte limits; packet, queue, message and scalar-custody bounds are
unchanged. Only the typed scalar-free state invocation selects this channel.

## Modification Scope

These 14 vendored source files differ from the pristine archive, apart
from the added license and Broil provenance notices. `src/client/private.rs`
is an added file. The edits in `src/cipher/mod.rs` and one of those in
`src/keys/format/pkcs5.rs` only keep the build without the `flate2` and `rsa`
features free of compiler warnings: a constant that only the `flate2` code
reads is compiled with that feature alone, and the decoded key bytes are
dropped explicitly where no `rsa` decoder reads them.

- `src/auth.rs`
- `src/channels/channel_ref.rs`
- `src/channels/mod.rs`
- `src/cipher/mod.rs`
- `src/client/encrypted.rs`
- `src/client/mod.rs`
- `src/client/private.rs`
- `src/client/session.rs`
- `src/keys/format/mod.rs`
- `src/keys/format/pkcs5.rs`
- `src/keys/mod.rs`
- `src/server/session.rs`
- `src/session.rs`
- `src/sshbuffer.rs`

Each modified source contains exactly once:

```text
// Modified by the Broil project from russh 0.62.5; see LICENSE.txt and docs/provenance/russh-0.62.5.md for provenance.
```

The reviewed semantic changes are represented by:

| Item | SHA-256 |
| --- | --- |
| Vendor patch | `a518dddb4405f39c9a7253b1b28959b22c24ec02dd3728b68f93a5c67491e7dc` |
| Upstream-root patch | `6a4af3854996626aeadc5d29c8e448a0d3eebfd87e68a2b8c90c4cc0e36f2655` |
| Patched pre-notice tree | `f1dd317d78e45d42eb9161301f24793fa8b6556a0a83801544d2fb47342cb88f` |

The final vendored tree hash includes the Broil modification notices. A
separate tree guard demonstrates that a one-byte vendored-tree mutation changes
the structural tree identity, while Cargo's lockfile alone does not authenticate
path dependency contents.

## Release Notes

This file is the stable provenance target for source releases. Development-only
automation paths are intentionally omitted from this release-carried record.
