# SOPS Regex Source Provenance

The broil-secrets Go adapter uses an isolated regex 1.13.1 / regex-automata 0.4.18 / regex-syntax 0.8.11 family with Unicode 15.0.0 tables. All three packages are explicitly excluded from the workspace. Only their normal internal path edges and generated data are changed; registry consumers and the reviewed SSH source remain separate.

## Source and tree identities

Archives are at `https://static.crates.io/crates/<name>/<name>-<version>.crate`; each package retains its MIT OR Apache-2.0 licensing and MSRV 1.65.

| Package | Archive SHA-256 | Final tree SHA-256 | Patch SHA-256 | Files / bytes |
| --- | --- | --- | --- | --- |
| regex-1.13.1 | `f020237b6c8eed93db2e2cb53c00c60a8e1bc73da7d073199a1180401450218d` | `40e83e0acec4c22a08570c51501b4264dae7f8977401bb4c02d09fe7811e276b` | `860931fca02f599b7da311f9e356e37867d47e1d2f208675043837b6134299b6` | 55 / 731495 |
| regex-automata-0.4.18 | `ad8553b9b26413251cbf30e620595c7a41b3887f03da04579c0e6b0d6a06b4b2` | `214e9b5571494c76ef1743bebeb3d590125369794089c10ab5f1a446dab2eb93` | `c76c527d5c3cddd3dbff0f9d9f6ffc00b1ba1b66c228cef9dc8751d375cfa852` | 107 / 2733539 |
| regex-syntax-0.8.11 | `d6f6ff9a378485b298a5286656da665ba74413d36db0979633275d2e708145d4` | `8defa45ff6349904115fd574b2f683485d83b1ca9a8d029f1817a603b31977cb` | `f240f6c4704dc9e3e1dd055502380d992990dc4c5aadb235e52c4c09f6d47625` | 45 / 1658574 |

Tree identities below hash a UTF-8 manifest of all regular files, sorted by relative POSIX path, one line per file: `six-octal-digit-mode SHA256 relative-path\n`. Modes come from the delivered tree. Patch identities hash Python `difflib.unified_diff` output (three context lines, `a/<path>` / `b/<path>` headers), concatenated in sorted path order against the official archive; added files have empty old content. No archive file is removed. These identities authenticate path source content independently of Cargo.lock.

The first two packages change only Cargo.toml, adding path edges and prominent modification notices. regex-syntax keeps all runtime implementation files and replaces exactly 15 `src/unicode_tables/*.rs` data files, each with a Broil modification notice. The three `DONOR-LICENSE-*` files preserve the contributing archive's legal material, including Unicode attribution.

## Unicode donor

Official archive: https://static.crates.io/crates/regex-syntax/regex-syntax-0.8.2.crate

Archive SHA-256: `c08c74e62047bb2de4ff487b251e4a92e24f48745648451635cec7d591162d9f`. The donor runtime engine is not used. The unmodified data manifest has SHA-256 `c8495f5e6eb2900252e65f456c7e4f669888982cb8e50563d34b477fb3719793` and is reproduced below. Remove only the single Broil notice line to compare an imported data file with this donor identity.

```text
2a2599a4e406fbbd0efd16aa6ce385c3f97b87c34820d6686a9f9113a5231c67  age.rs
9583803d4a10486da372b76979dbd26349b40766229467238eff972c1d78e47b  case_folding_simple.rs
36a93ba1cdeed96a00ff29a5ab5afd2c578a89541bf4dd8b18478146cebda0aa  general_category.rs
39c388e9805a8391d3d3e69d74d831ce4fb99aa7e13e52c64dd2bd16d4765301  grapheme_cluster_break.rs
26c837099cd934c8062e24bc9a0aaecf15fe1de03f9c6da3f3e1e5ac3ca24bee  mod.rs
a98ea4afe71c2947023ae12bd25c46bf4c7de48eeb40979eca5c96ba62cee02e  perl_decimal.rs
ea2b3b84b4a48334082dadc6c37d9fcc9c9ded84b40e8f5c9c9314898638967e  perl_space.rs
6f1156bd6af32151ecffea4abe07a38fa04b1fc1b227ec1a8dac5d5f08d9d74b  perl_word.rs
0bd64f6e3228eaecf47824e238bdf1f8a9eef113ace6e790a57f045a8106701c  property_bool.rs
5ca25437927eb70c62adf7d038e99a601cfb8a718677fd6de832589664d3c481  property_names.rs
5b4cc02392d382cf7af60455fc87b9980e97409b62a4b8d6c5843190d2e2d21d  property_values.rs
ea1d771b6d0a4b12d143f9bad2ea9342a0887878cbbe3c11262b6eabedaf2dd4  script.rs
beeb8349703d903ff861beb8401bfd2599e457dc25df872e69d6ad1615f8b5e9  script_extension.rs
2befe2a27cc4e8aecb624e310ef9f371462470dd3b2f572cec1f5873a5e30aa9  sentence_break.rs
94679177731b515f0c360eff394286a1f99b59527bdbc826cbf51d32f9666187  word_break.rs
```

## Supported feature and matching boundary

The direct regex dependency disables defaults and enables exactly `std`, `perf`, `unicode-case`, `unicode-gencat`, `unicode-perl`, `unicode-script`. Independent normal broil-secrets and workspace/all-target resolution must leave `default`, aggregate `unicode`, `unicode-age`, `unicode-bool` and `unicode-segment` off the isolated syntax identity. Registry regex remains distinct. Arbitrary all-feature builds of the private data transplant are unsupported: the excluded age dispatcher names donor-absent Unicode 15.1/16.0 tables. The active category, script, Perl and simple-fold consumers retain their table interfaces.

The adapter implements the two pinned Go property lookup profiles; carried SOPS version metadata never chooses one. Legacy C excludes Cn; the newer lookup includes unassigned scalars, aliases, canonical lookup, LC, ASCII and Assigned. Quoting, classes, inversions, ASCII Perl/boundary semantics, supported flags and Go repeat limits are handled before compiling the translated public pattern. A proven rejection in one grammar gives SOPS's fixed no-match behavior only for authenticated reads when the other grammar accepts. Neither grammar accepting refuses; all writers require both. Path-rule compile failures are never ignored.

Only public patterns and compiled automata are cached. The `Regex::is_match` call borrows its input. Meta/PikeVM/DFA caches retain automaton state and positions, not copied matched scalar/comment strings or capture contents. Source expressions are capped at 64 KiB, translations at 1 MiB, compiled programs at 8 MiB and each DFA cache at 2 MiB; at most two selector matchers exist. Path matchers are dropped between rules. Engine construction/syntax failures remain distinct from proven Go-language rejection. These caps are not a process-wide memory limit.

## Go source observations and attribution

Source copies were inspected from `https://raw.githubusercontent.com/golang/go/<tag>/src/<path>`. The source minimum toolchain declarations do not identify the installed SOPS executable; independent binary probes establish those outcomes. The Go-derived category/script/alias identifiers in `go_regex.rs` carry the following source identities and BSD attribution.

| Tag / source | SHA-256 |
| --- | --- |
| `go1.22.9/regexp/syntax/parse.go` | `62b45bc8bed65a54075bc3c959f9c2e8374cd44193a594dd76d04771a9eaf893` |
| `go1.22.9/unicode/tables.go` | `80a109e5dd4ed40a85d69ddf95175f647bbd68c577d27eb475cda63790bb2487` |
| `go1.25.0/regexp/syntax/parse.go` | `d0f657113901da39d6118e4172206a0358b71c96ef43051cc0a741a0a4d04820` |
| `go1.25.0/regexp/syntax/doc.go` | `d61fed6f5a70cb4a0883f2c70da086d52edc80faf79ecb33a95393f28f24711e` |
| `go1.25.0/unicode/tables.go` | `6a88d48746c4b2c471cc04ae40559694b734770212e6f5ea5f1962adb0c0bdb1` |

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Retained legal material

| Package / path | SHA-256 |
| --- | --- |
| `regex-1.13.1/LICENSE-APACHE` | `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2` |
| `regex-1.13.1/LICENSE-MIT` | `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb` |
| `regex-automata-0.4.18/LICENSE-APACHE` | `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2` |
| `regex-automata-0.4.18/LICENSE-MIT` | `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb` |
| `regex-syntax-0.8.11/DONOR-LICENSE-APACHE` | `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2` |
| `regex-syntax-0.8.11/DONOR-LICENSE-MIT` | `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb` |
| `regex-syntax-0.8.11/DONOR-LICENSE-UNICODE` | `74db5baf44a41b1000312c673544b3374e4198af5605c7f9080a402cec42cfa3` |
| `regex-syntax-0.8.11/LICENSE-APACHE` | `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2` |
| `regex-syntax-0.8.11/LICENSE-MIT` | `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb` |
| `regex-syntax-0.8.11/src/unicode_tables/LICENSE-UNICODE` | `74db5baf44a41b1000312c673544b3374e4198af5605c7f9080a402cec42cfa3` |
