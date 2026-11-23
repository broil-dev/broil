# Image analyzer

This source-built helper implements private protocol 2 for one immutable
Dockerfile conversion. Broil invokes it through the admitted image client.
Recursive producer graphs, source snapshots, solves and publication have separate
owners; a complete conversion establishes none of those results.

It uses the unmodified BuildKit v0.24.0 parser, instruction model, shell expansion
and converter at b772c318368090fb2ffc9c0fed92e0a35bf82389. The supported Dockerfile
frontend is 1.18.0, manifest
`sha256:6ce6616ec35021075551c55e604374e8b47a66d157bc55ec2f2d2326450a9ae1`.

## Build and install

Acquire the exact Go compiler in `toolchain.lock.json`, verify its archive
SHA-256, and put that compiler in PATH. In an isolated copy of this directory,
with caller-owned module/build caches:

```sh
export GOTOOLCHAIN=local GOENV=off GOWORK=off CGO_ENABLED=0
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
go mod download
bash build-analyzer.sh /absolute/installed/image-analyzer
```

The build script disables network module/toolchain selection and uses the pinned
compiler, readonly module graph, trimpath, disabled VCS stamping and empty build
ID. Preserve the exact module sums, all Go sources, build script, compiler lock
and actual legal material. The executable needs neither compiler nor module
cache at runtime. No download or tool lookup occurs on analysis invocation.
Broil requires an explicit installed path and verifies its recorded size/SHA-256
before copying and launching it privately.

`toolchain.lock.json` records the actual non-standard package/module closure and
its license/notice paths. `license_files` deduplicates identical retained texts;
compiler and standard-library notices retain their source paths and hashes. This
helper has its own legal inventory, separate from the Rust executable.

## Protocol and custody

No arguments are accepted. Stdin is one unsigned 32-bit big-endian length, UTF-8
JSON request and EOF. Stdout is exactly two such frames and EOF: the analysis
projection, then private generated configuration/Dockerfile/bindings. Non-complete
results use an empty second frame. There is no protocol-1 fallback.

Every nonempty
frame binds protocol, operation, attempt and resolution identities. Semantic
statuses are `complete`, `metadata-required`, `invalid` and `unsupported`. Exit
zero means a completed exchange, including a semantic refusal; nonzero exit,
missing/trailing frames, contradictory fields or observed timeout/cancellation
prevent adoption. Only checked original references, source roles/tag origins,
source ranges, graph IDs and closed diagnostics may enter the public projection.

The helper receives no credentials, automatic exports or builder connection. Its
resolver uses only supplied metadata and cannot perform network/gateway solves.
Ordinary remote ADD remains an upstream source operation without a download.
Reachable inheritance and file-source roles remain distinct; stored ONBUILD is
not executed for file-only uses. Original metadata is separately authenticated
by the caller; descriptor validation cannot create transfer provenance.

The Rust caller owns fixed-capacity zeroizing input/output holders. Payloads do
not enter filesystem-worker jobs, public launch captures or printable JSON trees.
The Go process is external-consumer custody; no Go heap or operating-system
erasure guarantee is implied. Both stdout frames together, including prefixes,
fit 16 MiB. Input has the same total bound. The helper's input/conversion/write
watchdogs fit its original 30-second lifetime; the caller independently enforces
stage/pipe deadlines and one cleanup grace.

## Identities and derived content

The resolution preimage is the spec's length-delimited `broil.image.analysis.v2`
encoding. It binds original bytes/path, public options/platforms, sorted
arguments/contexts, frontend, analyzer identity and each ordered original
metadata descriptor association. The analyzer identity is SHA-256 of its
`public-tools.json` record encoded as compact JSON with recursively sorted UTF-8
object keys, unescaped non-ASCII text and unchanged array order. The executable
digest is recorded after building and is never its own embedded build input.

Private role projections keep original repository/root facts separate from
derived config/manifest roots. File sources remove only unexecuted OnBuild.
Inheritance rewrites only parsed trigger source operands and applies the pinned
`history.go` tail-completion convention. It preserves existing history and adds
only fixed synthetic records when the original layer history is unavailable.
Each map retains exact original descriptors, layer ordinals/diff IDs and the
history source digest. Authored deferred ONBUILD stays portable and unchanged.

Production adoption requires two byte-identical isolated/source-carried rebuilds,
then analyzer identity pinning, then a fresh filesystem-helper rebuild and pin.
The production Rust conformance leaf and complete backend proof must pass on
that tuple; historical prototype evidence cannot substitute for them.
