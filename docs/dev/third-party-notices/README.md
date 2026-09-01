# Third-Party Notice Regeneration

This procedure regenerates the root `x86_64-unknown-linux-gnu` notice only.
It does not generate non-root target notices.

## Evidence Commands

Run from the repository root into a disposable temporary directory:

```sh
cargo metadata --locked --offline --format-version 1 --filter-platform x86_64-unknown-linux-gnu
cargo tree --locked --offline --package broil --target x86_64-unknown-linux-gnu --edges normal --prefix none --format '{p}|{f}'
```

These commands derive the target-filtered locked normal dependency closure for
the released `broil` binary. Build, development, and test-only edges are outside
the root notice closure.

## Source Inputs

Use these inputs:

- `Cargo.lock`
- metadata-selected workspace manifests
- resolved registry package roots and path package roots
- resolved feature data
- package source/checksum or path identity
- package legal-material files whose basenames match `LICENSE*`, `COPYING*`,
  `COPYRIGHT*`, `NOTICE*`, `AUTHORS*`, `ATTRIBUTION*`,
  `ACKNOWLEDGEMENTS*`, `PATENTS*`, or `UNLICENSE*`
- `crates/vendor/russh-0.62.5/LICENSE.txt`
- the six vendored Russh files carrying Broil modification notices
- `docs/provenance/russh-0.62.5.md`
- existing `THIRD-PARTY-NOTICES.md` and
  `docs/dev/third-party-notices/x86_64-unknown-linux-gnu-closure.tsv` as
  formatting baselines only

## Outputs

The generated-output scope is exactly:

- `THIRD-PARTY-NOTICES.md`
- `docs/dev/third-party-notices/x86_64-unknown-linux-gnu-closure.tsv`

The ledger keeps the existing column schema, retains first-party trace rows as
non-notice entries, records every selected package's identity, features,
license, manifest, and legal-material SHA-256 inputs, and sorts rows
consistently with the existing ledger.

The notice is rebuilt from the regenerated ledger for
`x86_64-unknown-linux-gnu` only. It preserves the exact-target closure identity,
package inventory, vendored Russh provenance and modification-notice content,
source-specific notice and attribution content, and deduplicated retained
license terms.

## Diff Review Gate

After regeneration, review:

```sh
git diff -- THIRD-PARTY-NOTICES.md docs/dev/third-party-notices/x86_64-unknown-linux-gnu-closure.tsv
```

Accept only changes explained by moved provenance paths, recalculated digests,
changed vendored modification-notice text, or Cargo evidence proving a real
package, license, legal-material, target, or closure-boundary change. If any
other change appears, stop and record a blocker instead of committing the
notice update.
