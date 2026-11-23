# Production image client

The internal `broil-command::images` API runs selected Buildx and registry stages.
It adds no public Broil command. Graph generation, secret acquisition, managed
builder lifecycle, exporter policy and persistent artifact records have separate
owners. Call `preflight` before acquiring private inputs, keep their owners alive
only for the selected consumer, and inspect explicit `cleanup` results.

## Supported installation

The controller and filesystem helper support Linux x86_64. Install the exact
Docker 28.2.2, Buildx 0.25.0, Buildctl 0.24.0 and registry-helper bytes listed in
`public-tools.json` and `compatibility.json`. Archive URLs, member names, source
identities and SHA-256 values identify the public tools. Build the registry
helper using `../image-registry/README.md` and its locked toolchain. Set its
installed executable mode to 0700 or 0755; compiler output may otherwise inherit
group write permission. Supply absolute, symlink-free installed paths.

Tools must be invoking-user/root-owned executable regular files without group or
other write permission. The client checks exact sizes, hashes and versions and
makes verified 0700 copies inside an exclusive 0700 workspace. A mismatched or
missing tool fails. Invocation never downloads a replacement or changes trust.
The local OS and installed tools are trusted execution dependencies.

## Filesystem helper build

Build from the release-carried repository root with Rust 1.92.0 and the GNU
Linux x86_64 linker/runtime baseline recorded in `compatibility.json`. This
reproduction compiler is separate from the Rust 1.87 minimum source
compatibility floor. Install the compiler explicitly before building; the
runtime needs no compiler, source tree or developer cache.

```sh
bash tools/image-client/build-worker.sh /absolute/build-output /absolute/bin/broil-image-client-worker
sha256sum /absolute/bin/broil-image-client-worker
```

The recipe uses the committed lockfile, release profile, explicit GNU target,
one build job, normalized source/Cargo-source paths and no linker build ID.
Compare the encoded size and SHA-256 with `filesystem_helper` in
`compatibility.json` before installing a controller that expects those bytes.
Use a fresh output directory for an independent rebuild. Required Rust package
sources are identified by Cargo.lock checksums or release-carried path sources.

The small binary root directly includes only the filesystem/protocol modules;
it does not include its own identity table. Build the helper first, establish
its source/build/legal identity, then build the controller against that fixed
table. `public-tools.json` is a separate helper input containing no helper hash.
Changing any helper input requires a newly established identity and renewed
checks. Editing a version label alone cannot qualify a different executable.

Shared `broil-core` changes also change these inputs. Renewal must derive the
helper's actual locked normal graph and legal files before recording its new
source hashes, executable size and SHA-256. The current helper graph includes
the core's `bech32` dependency; the canonical Broil graph already contained it.
Keep each executable's separate ledger and notice, including current lockfile
provenance. A diagnostic build hash is only a candidate until the production
client proof and its independent same-input/source-release rebuilds pass.

Source releases carry all first-party Rust source except tests. The exact
normal helper Rust inputs are exempt from comment stripping, and the
compatibility table pins them as released: without the test-gated item that
ends such a file in the source repository. The canonical Broil binary archive
remains unchanged; this helper is installed separately from source.

## Calls, output ownership and limits

`Operation::analyze` accepts an owned `analysis::Snapshot` of original Dockerfile
bytes, public `Options` and privately supplied `Metadata`. Registry metadata is
constructed against a sealed `VerifiedOutput` and revalidated independently of
the supplied bytes. This stage performs no file acquisition, registry lookup or
builder connection. Install/select `Tool::Analyzer` explicitly; analyzer-only
operations require that tool and the filesystem helper. Their initial copy and
conversion share the original 30-second preparation/analysis deadline.

The returned outcome exposes only the checked status, original source uses,
locations, bounded graph identifiers and observation. Complete outcomes also
own opaque private candidate material; they do not assert complete project
graphs or permission to solve. See the source-carried
[analyzer instructions](../image-analyzer/README.md).

An operation holds one of four process-wide permits and runs stages sequentially.
Capacity exhaustion fails promptly. A delayed launch or unresolved process keeps
its permit; caller timeout does not authorize another child or a retry.

Registry reads and Bake OCI-layout image output use a fresh producer directory
under workspace `staging`. The producer creates its initially absent `content`
child. Registry roots remain constrained by the complete receipt and original
request/pins. A new Bake output may discover its root from a single-descriptor
OCI layout wrapper, followed by complete original-byte verification. Discovery
does not relax a supplied expected root. Failed or uncertain work is not adopted.

A solve stage writing a registry cache adds a second fresh `bake` producer
directory for the `type=local` cache export, which the helper verifies as
complete cache content: a Bake output may be cache content only as `complete`,
never metadata-only or receipt-bound. That one export slot is the only cache
content the caller declares. The export is re-homed into a private
`cache-upload` layout before any upload, and only that layout is kept.

With the Docker tool selected and a daemon socket that passes the protected
socket check, a stage may run exactly `docker --host unix://<socket> load
--quiet --input <archive>` on a verified operation-owned archive and `docker
--host unix://<socket> image inspect --format <fixed object> <reference>`. Their
output is parsed privately and never echoed; no other Docker form runs.

Keep returned `VerifiedOutput` objects for the consuming stage. Pass the selected
outputs to explicit cleanup to preserve those subtrees and required ancestors.
Preserved transient output is not a durable artifact record. Upload inputs,
independent retention, other operations, remote service and builder cache remain
separately owned. Dropping an operation performs no filesystem cleanup or wait.
A consumer session or solve whose close kept outputs returns a single-use
release token; `consumers::release` runs the owner's own `cleanup` job over its
workspace, and a refusal before that job's dispatch returns the token
unconsumed.

Default maxima are 30 minutes per solve, 30 seconds per metadata stage, 10 seconds
per private handoff, 30 seconds per independently idle pipe, 100 milliseconds
post-exit drain, and one 5-second total cleanup grace. Callers may tighten them.
Streams are separately bounded to 16 MiB, records to 64 KiB and 65,536 per stage.
Adopted still-owned file bytes are bounded to 5 GiB and traversals to 65,536 names.
Known growth is checked before copying and output before use; external writers
can temporarily exceed the allowance or exhaust storage. This is not a disk quota.

Late completion, descendants, blocked filesystem work and failed cleanup retain
explicit uncertainty. A child exit does not prove remote work stopped, an image
was Built/Published, or private bytes were erased from external/kernel storage.

## Private input and legal evidence

Child environments contain selected public values and canonical private client
paths. Conflicting tool controls, including configured telemetry variables even
when empty, fail before acquisition/dispatch. Ambient credentials and automatic
secret exports are absent. Builder TLS and instruction secret/SSH channels keep
their separate protected-consumer lifetimes. Registry scalars use only their
framed private pipe, never Bake, argv, ordinary environment or workspace files.

`custody.md` documents retained storage and residue. `normal-closure.tsv` and
`THIRD-PARTY-NOTICES.md` cover this helper's separately derived normal dependency
graph. The repository-root notice separately covers the canonical Broil binary.
Both notices must be reviewed after an affected dependency/lock/source change.

The production-client and retained registry/backend CI proofs are distinct.
Prototype success alone does not qualify this client. Runtime acceptance requires
actual callers, independent readback and failure controls, source-carried
independent helper rebuilds, and the applicable unit/lint/MSRV/docs gates.

The production-client proof renders the release rules into a disposable tree
with a pinned renderer, without a release loop or target-repository
operations, then compares independent helper builds.
The proof compares the rebuilt helper with the fixed compatibility table; it
does not update that table. It also proves that isolated source mutations to
environment refusal, receipt identity, deadlines, completion observations and
expected output roots fail independent assertions, then reruns those assertions
with the original source restored.
