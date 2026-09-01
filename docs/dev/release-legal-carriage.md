# GitHub Release Legal Carriage

This operator record implements [licensing.md §5](../../specs/licensing.md) for
source releases and executable GitHub Release assets. It adds no publication
automation or package format.

## Source repository and source releases

Before publishing a source release, confirm it retains:

1. Root `LICENSE` and root `THIRD-PARTY-NOTICES.md`.
2. Every committed `notices/<target-triple>/THIRD-PARTY-NOTICES.md`.
3. All first-party Rust source, including files outside the 45-file header set.
4. The complete `crates/vendor/russh-0.62.5/` tree, its `LICENSE.txt`, and
   the six existing Broil modification notices and provenance material.

The source-release inventory is broader than the product-header set. Do not
remove source or vendor material because it lacks a first-party header.

## Release-specific executable asset map

Before publishing an executable asset, record one unique row for it in the
release record using this table. No asset may be published while the table is
empty, an exact asset filename is unlisted, a filename appears more than once,
the kind is not `raw` or `archive`, or the target is unknown.

| Exact GitHub asset filename | Kind (`raw` or `archive`) | Release target | Selected repository notice | Legal carriage verification |
| --- | --- | --- | --- | --- |

A mapping row selects its notice only after its exact target is known:

- `x86_64-unknown-linux-gnu` selects root
  `THIRD-PARTY-NOTICES.md`.
- Any other target selects only
  `notices/<target-triple>/THIRD-PARTY-NOTICES.md`. If that separately
  reviewed notice is absent, publication for that target is blocked.
- Never substitute, copy, or relabel a notice generated for another target.

## Raw executable assets

For every mapped raw executable asset, the GitHub Release asset set MUST
contain:

1. A `LICENSE` companion whose bytes exactly equal repository-root
   `LICENSE`. One release-level `LICENSE` asset may serve more than one raw
   executable only when the byte-identity check passes for every mapped asset.
2. A companion named exactly
   `<raw-asset-name>.THIRD-PARTY-NOTICES.md` whose bytes exactly equal that
   raw asset's target-matched repository notice.

Record the raw asset filename, the selected notice path, and the verified
SHA-256 values in the release-specific map. A filename or target mismatch
blocks publication.

## Executable archives

For every mapped archive asset, the archive MUST contain:

- `LICENSE`, byte-identical to repository-root `LICENSE`; and
- `THIRD-PARTY-NOTICES.md`, byte-identical to that archive target's selected
  repository notice.

Record the archive filename, target, selected notice path, and the verified
entry hashes in the release-specific map. An archive with missing, renamed, or
non-identical legal files blocks publication.

## Required verification

For each row, compare extracted or companion bytes with the selected repository
files (for example, with `sha256sum` or `cmp`). Confirm target selection
before the comparison and preserve the completed map with the release record.
This document intentionally does not create GitHub Actions, package archives,
or other publication automation.
