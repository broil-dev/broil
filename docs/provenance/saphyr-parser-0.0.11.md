# Hardened Saphyr Parser Provenance

Broil uses the official saphyr-parser 0.0.11 source at `crates/vendor/saphyr-parser-0.0.11/`, with isolated scalar-storage hardening. It is excluded from workspace membership and selected only by broil-secrets; broil-config retains the registry parser. No workspace patch or upstream version change applies.

| Identity | Value |
| --- | --- |
| Official archive | https://static.crates.io/crates/saphyr-parser/saphyr-parser-0.0.11.crate |
| Archive SHA-256 | `ebfd783fcf1b3f6bafd557be0e1427ec54f826f513c3cdd749f9844484df2a13` |
| Upstream revision | `f606ac7ae9e222513dfb04f831bd8cabe87e870f`, path `parser` |
| Edition / MSRV | 2024 / 1.85.0 |
| License | MIT OR Apache-2.0; retain both Chen Yuheng and Ethiraric notices |
| Final files / bytes | 40 / 381910 |
| Final tree SHA-256 | `fea1803b7ddfc87bea4ac3e14400c2dcf346a1e3479c886fca03c34e6cdac0be` |
| Patch SHA-256 | `33ec119f05d8921ed3827f09c8c81fdaec7322dc18a9f20aff68ce774a3bb2c0` |

Tree identities below hash a UTF-8 manifest of all regular files, sorted by relative POSIX path, one line per file: `six-octal-digit-mode SHA256 relative-path\n`. Modes come from the delivered tree. Patch identities hash Python `difflib.unified_diff` output (three context lines, `a/<path>` / `b/<path>` headers), concatenated in sorted path order against the official archive; added files have empty old content. No archive file is removed. These identities authenticate path source content independently of Cargo.lock.

## Modification boundary

`src/scalar.rs` supplies a zeroizing owned UTF-8 scalar with redacted Debug and an allocation-moving handoff. All three scanner accumulators, scanner tokens and parser events carry that owner, including error and early-drop paths. `src/debug.rs` disables content-bearing debug output. `Cargo.toml` adds locked zeroize 1.9.0 with alloc and a test-only wipe observer feature. Existing grammar, input cursor, tag/anchor syntax, upstream notices and license bytes remain.

The complete changed-file set is:

- `Cargo.toml`
- `src/debug.rs`
- `src/lib.rs`
- `src/parser.rs`
- `src/scalar.rs`
- `src/scanner.rs`
- `tests/issues.rs`
- `tests/plain_tab.rs`
- `tests/span.rs`

The three upstream test edits only correct the parser Marker import or adapt scalar extraction for synthetic expected-value comparisons. Production Broil never clones parser/scalar events; upstream API-compatible clones also produce protected owners. No general-purpose secret YAML loader is used.

Two accepted unzeroized transfer residues remain: scalar accumulator growth fragments and the block-scalar line buffer. Final scalar allocations are wiped on success, scan/parse error and abandonment; they are not a third exemption. Borrowed StrInput contains the caller's protected input plus scalar cursor/offset state. Whitespace scratch contains only whitespace. The registry configuration parser has a separate non-secret boundary.

## Preserved legal inputs

| Path | SHA-256 |
| --- | --- |
| `.licenses/ChenYuheng-Apache` | `b2174e5bfaba26c7a78172221e190e57897b643ee21ed8ce582cf72c9b381589` |
| `.licenses/ChenYuheng-MIT` | `70480dc70c2fe1d9bbb64dab9a0abce266332905ffef9cabeae26dd027716ecb` |
| `.licenses/Ethiraric-Apache` | `e0f2efbe68fb02db5485f2bef61d8b49e788def182d3262af2df50e87c0d19f8` |
| `.licenses/Ethiraric-MIT` | `90f4ea53f408858ba4886f57b8e3ceac876eefbb59c20f0844f0abbfa59e2749` |
| `LICENSE` | `932dc213b1bbd3d5950e155cf0c8f065aaa6e520d01f410cfaacec5798b8215b` |
