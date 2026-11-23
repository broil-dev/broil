# Build and publish project images

Use Broil's `image` commands to build a selected image and its inferred
dependencies on a declared BuildKit builder, publish verified image content,
and inspect the records needed to understand what completed. Building and
publishing are separate operations: retained content can be published later
without rebuilding it.

A **producer** is a named `images` declaration, such as `base` or `app`.
Its Dockerfile identifies dependencies through image references. A **builder**
is the authenticated endpoint that performs the build. A **registry** stores
published content. The build creates immutable **artifact records** with exact
content identities; its separate **operation journal** records progress,
failures and uncertain effects. Two builds can have the same content digest
and different Artifact IDs.

This guide assumes familiarity with Dockerfiles and an installed Broil binary.
The controller supports Linux x86_64. Images support `linux/amd64` and
`linux/arm64` when the selected builder can execute them. These commands
establish build and publication evidence; deployment and runtime management
belong to later workflows.

## Start with inspection

The [example project](examples/images/README.md) has an `app` Dockerfile that
inherits `base`. From the source repository root:

```sh
broil --file docs/examples/images/broil.yaml get --json cfg images
broil --file docs/examples/images/broil.yaml get --json cfg tools
broil image --help
broil help image builder
```

These commands need no image tools, builder, secret store or registry. `get cfg`
reads declarations without opening their referenced files or contacting an
endpoint. Help also works without configuration. It has the same payload in
both forms, for example `broil help image build` and `broil image build --help`.
Place `--help` immediately after a group or leaf; a later `--help` is an
operational option error.

The example contains placeholder addresses and paths. Prepare a controller
and replace them before attempting graph analysis or a build. Graph analysis
can read source files and acquire authenticated metadata; it is an operation,
unlike configuration inspection.

## Prepare a controller

Install the exact executables recorded in
[the tool inventory](../tools/image-client/public-tools.json) and
[the helper compatibility record](../tools/image-client/compatibility.json).
The supported versions are Docker CLI 28.2.2, Buildx 0.25.0 and buildctl 0.24.0.
Those files specify archive URLs, archive and executable hashes, and member
names. An executable with the right version text but different bytes is refused.

The filesystem helper is built from the release-carried source, separately
from the controller. Its reproduction compiler is Rust 1.92.0 on the recorded
GNU Linux x86_64 compiler/linker/runtime baseline. The Rust 1.87 source
compatibility floor is a separate promise. From the repository root, use
absolute paths for your build output and installation directory:

```sh
bash tools/image-client/build-worker.sh /absolute/build-output /absolute/bin/broil-image-client-worker
sha256sum /absolute/bin/broil-image-client-worker
```

Compare the helper's size and hash with the compatibility record. Build the
controller only after establishing the helper identity it will require.
The [client installation instructions](../tools/image-client/README.md#filesystem-helper-build)
explain the complete recipe and source requirements.

Build the [registry helper](../tools/image-registry/README.md) and
[image analyzer](../tools/image-analyzer/README.md#build-and-install) using
their own locked compiler archives, checksums and build recipes. Preserve their
recorded sources and notices. Compilation may need the documented downloads;
image invocation performs no download, tool search or version override.
The installed helpers need neither compiler nor source tree at runtime.

Declare paths to the **executable files themselves**, not their directories:

```yaml
tools:
  filesystem_helper: /opt/broil/bin/broil-image-client-worker
  registry: /opt/broil/bin/image-registry
  analyzer: /opt/broil/bin/image-analyzer
  buildx: /opt/broil/bin/docker-buildx
  buildctl: /opt/broil/bin/buildctl
  docker: /opt/broil/bin/docker
```

Paths must be normalized absolute UTF-8 paths without symlink traversal.
Files must be executable, owned by you or root, and not writable by group or
others. Broil verifies exact identities before launch and makes private tool
copies for the operation. No ambient Docker context or default builder is used.

| Tool member | Required by |
| --- | --- |
| `filesystem_helper` | Graph, build, publish and every builder leaf |
| `registry` | Graph, build and publish |
| `analyzer` | Graph and build |
| `buildx`, `buildctl` | Build and every builder leaf |
| `docker` | Build only when a requested target uses `docker-load` |

A registry, retained OCI or cache-only build needs no Docker declaration.
Store inspection and recovery need none of these tools. `record list` and
`record show` require a writable project root: they create caller-owned 0700
`state/` and `state/artifacts/` if absent. They do not create operation journals.

## Declare images, endpoints and credentials

See [image catalogs](image-catalog.md) for the schema and
[the example configuration](examples/images/broil.yaml) for a connected project.
Each producer names its output image reference, builder and source context.
The default output is a registry publication; retained layouts and archives,
Docker loading and cache-only work are explicit alternatives.

The same image reference in a reachable Dockerfile identifies a project
producer. `FROM`, `COPY --from`, `RUN --mount=from` and inherited `ONBUILD`
sources contribute dependencies according to their actual use. Do not add a
handwritten dependency list or producer-to-target binding. A matching tag plus
digest is an exact constraint; the tag does not substitute for the digest.

An external builder needs its endpoint, CA/trust settings and TLS client
certificate/key references. A managed builder additionally names a machine in
the selected environment's remote inventory and a lifecycle script. A registry
declares its endpoint, trust and the credential scopes permitted for metadata,
pull, cache read/write and push. One endpoint may have distinct credentials
for different repositories and purposes.

Credentials are `{set, key}` references into the native secret store, not
command-line scalars. Follow [secret-store setup](secrets.md) before using
authenticated endpoints. The selected secrets overlay and captured identity
inputs govern acquisition. Registry credentials reach only the selected
registry consumer; they are not written into Bake inputs or passed to the
analyzer. Instruction secret and SSH inputs retain their separate declarations
and lifetimes. No default SSH agent or Docker credential helper is consulted.

`--non-interactive` disables prompts for build, publish and builder operations.
Otherwise a prompt still requires a usable private terminal. Store-only leaves
never prompt. There is no credential-scalar or tool-path command option.

## Choose an environment

Graph, build, publish and builder commands use non-empty ambient `BROIL_ENV`,
including when `--file` is present. Absent or empty selects root catalogs.
There is no `--env` option.

```sh
BROIL_ENV=ci broil --file /absolute/project/broil.yaml image build --target app --builder shared --format json
```

An environment replaces whole same-named image, builder and registry entries.
For `tools`, each declared executable path replaces its root counterpart;
omitted members retain the root path. A declared image environment must match
`[A-Za-z0-9][A-Za-z0-9_-]*`. Names such as `_dev`, `dev 1` and `dév` may be valid
for ordinary Broil commands, but image operations refuse them. Unknown names
are refused before store access. A non-UTF-8 ambient value is converted lossily
for lookup and then fails lookup or the image-name grammar; it is never treated
as absent.

`status`, `record list`, `record show`, `resume` and `settle` neither select nor
validate an image environment. `get cfg` likewise shows literal declarations:
use `get --json cfg environments.ci.tools` to inspect that overlay.

## Graph and build

Run these examples from a configured project directory. Replace `app`, `base`
and `shared` with your declared names. Each `--target` is explicit; there is
no implicit all-targets default.

### Inspect dependencies

```sh
broil image graph --target app --format json
```

The report includes the request, nodes, inferred edges, original source
locations, external sources, diagnostics, `complete` and `graph_id`. Its
default build platform is `linux/amd64` and default staging is `metadata`.
Use `--build-platform linux/arm64` to choose another analysis platform, or
`--staging content` to request verified external content staging. Graph analysis
does not probe a builder or build a producer. A dependency awaiting actual
producer metadata remains provisional; an incomplete report exits 1.

Graph inspection releases its staged metadata and content after preparing the
report. Cleanup or release can fail even when the graph is complete. In that
case the Resolution still appears on stdout, the exit status is 1, and stderr
identifies cleanup uncertainty and any remaining owner paths. A clean graph
result prints no stderr diagnostic.

### Build the selected targets

```sh
broil image build --target app --target base --builder shared --format json
```

Broil builds required producers in dependency order on the named builder and
finishes each requested target's output. A registry target includes its
publication result beside its output result. The report preserves partial
successes if a later target fails. Builds remain silent until their report
returns; there is no progress stream.

Without `--build-platform`, Broil probes the builder, including the initial
`linux/amd64` discovery prerequisite. An explicit platform skips that probe.
Repeat `--platform` to restrict image platforms and `--registry` to restrict
permitted registry selections. Platform names use `os/architecture[/variant]`.
Unsupported subsets and unknown catalog names are runtime refusals.

`--refresh` skips cache reads and forces fresh work according to cache policy.
`--optional-cache-reads` allows a verified cache miss to continue without that
cache; the failed transfer observation remains visible. Success requires every
target's requested output/publication and `cache_complete: true`.

## Outputs and ownership

| Output | Result and retained ownership |
| --- | --- |
| `registry` | Verify and publish the required content closure, then report the binding |
| `oci-layout` | Retain a complete OCI directory at the explicit output path |
| `oci-archive` | Retain a deterministic archive at the explicit output path |
| `docker-load` | Load into an explicitly selected development Docker daemon |
| `cache-only` | Cache work without a runnable artifact or a publication claim |

Retained output destinations must be absent and outside the workspace and
protected-lease parents, their ancestors and descendants. Use a separate path
such as `retained/base`; the project root, `state/`, `state/workspaces/` and
`/dev/shm` cannot be output destinations. Retention never replaces an existing
destination. Choose another destination when a new build must retain new content.

For `docker-load`, declare the Docker executable and pass its absolute daemon
socket path explicitly:

```sh
broil image build --target development --builder shared --docker-daemon /run/docker.sock --format json
```

This example assumes a declared `development` target with `output.type:
docker-load` and a usable supported daemon. It does not select an ambient
Docker socket or context.

An operation's ordinary private workspace is
`state/workspaces/<operation-id>/`; successful cleanup removes that workspace.
The borrowed 0700 parent remains. Protected leases live separately under the
verified tmpfs parent `/dev/shm`. Retained OCI content, builder cache and
immutable records have separate owners and persist independently. Dropping a
report or ending a process is not a request to remove retained content.

After a successful build finishes reading and recording its results, the command
releases its temporary graph and node staging and records that cleanup in the
same operation journal. Successful commands report no remaining staging in
`retained`. Node and closure paths describe where the build read its inputs;
those historical paths may no longer exist. Use the explicit retained output
location, registry digest or immutable record for later work.

A failed build preserves its caller-owned staging. Cleanup refusal, cancellation,
uncertain readers or failure to record cleanup also produces status 1, even when
the domain report says `stop: success`. The report identifies unconsumed owners;
stderr preserves cleanup failures and residue paths, including a failed release
that consumed its token. Broil does not retry those releases or sweep directories.

### Publish retained content independently

First run `broil image status --format json` and find the build operation whose
target results include `base` at the export phase. Use that operation's
`operation_id` and the retained target name. Set the shell variable below to
that recorded ID; do not substitute a content digest:

```sh
build_operation=operation_REPLACE_WITH_RECORDED_ID
broil image publish --target base --operation "$build_operation" --format json
```

The placeholder must be replaced with `operation-` followed by 32 lowercase
hexadecimal characters. Broil reads the journal's recorded location and exact
root, recovers platform labels from verified retained metadata, and re-verifies
the content before publication. It accepts both retained layouts and archives.
No committed artifact record is required to publish retained content.

Optional `--registry release` selects the registry declaration. Optional
`--artifact` requests a record binding; it does not locate the input or prove
a binding. The report distinguishes a bound Artifact ID from
`artifact-id-deferred`. Missing or corrupt retention needs an explicit new
build; publish does not rebuild, change a digest or silently fall back to cache.

## Use a recorded artifact in a runtime

An artifact's **root digest** identifies its complete OCI image or platform
index. For an index, the runtime selects a child image for `linux/amd64` or
`linux/arm64`; that child's configuration digest differs from the root digest.
Use the recorded repository and root as `repository@sha256:…`, with an explicit
platform, when handing the artifact to a runtime. A tag can move after the
record was written. Docker's image ID identifies the selected configuration
and does not replace the recorded repository/root association.

The runtime needs its own registry access and trusted endpoint. Broil's builder
credentials and private client configuration are not runtime configuration.
Keep retained OCI bytes when later publication must work after builder-cache
loss. If publication was interrupted, inspect its journal and make an explicit
retry decision; a later successful pull does not rewrite the original Unknown
outcome, which means completion could not be confirmed.

Broil's image commands
establish Built and Published evidence. Runtime setup, deployment health,
distribution and application-data recovery remain separate work.

## Inspect records and recover

An Artifact ID is `artifact-` plus 32 lowercase hexadecimal characters.
An Operation ID is `operation-` plus 32 lowercase hexadecimal characters.
Read real values from your reports; placeholders in this guide are not usable
identities. Neither identifier is an image digest.

### List and show immutable records

```sh
broil image record list --format json
artifact=artifact_REPLACE_WITH_LISTED_ID
broil image record show "$artifact" --format json
```

Listing validates every in-domain committed record before printing any ID.
Partial commit files and unrelated names are excluded. A corrupt committed
record fails the entire listing instead of being skipped. Show reads the exact
ID; it performs no digest search. JSON from `record show` is byte-identical to
the stored record's encoding, including its one final newline.

### Rebuild current status

```sh
broil image status --format json
operation=operation_REPLACE_WITH_RECORDED_ID
broil image status --operation "$operation" --format json
```

Status rebuilds under `state/index/current.lock` from journals and settlement
markers. It does not trust a cached index. A held lock fails with `capability`
instead of showing old data. The report distinguishes unproved allocations,
committed or abandoned records, bound or unbound publications, unresolved
publication disposition, and settled versus unsettled ambiguity. A missing
named operation creates neither that operation nor a replacement index.

### Observe an interrupted operation

```sh
broil image resume "$operation" --format json
```

Resume resolves exact-name record commit windows and completes a settlement
whose marker already chose an ID. It reports changed tool identities and any
required decision. It never chooses a candidate, rebuilds, republishes, retries
an indeterminate write or fabricates unavailable remote evidence. A
`requires_explicit_decision: true` result exits 1; inspect it before taking a
new action.

An `unknown` publication or cache result means completion is still unproved,
even when the journal records that result. Resume keeps the decision required
until a definite result for the same attempt is recorded. Status preserves the
earlier Unknown in the target's history; without a Published observation it
shows no publication binding.

### Settle a recorded binding ambiguity

When status identifies a `binding-ambiguous` observation, read its sequence
and recorded candidate IDs. The sequence is a decimal integer from 0 through
999999999 without leading zeros. Choose one actual candidate, then set these
variables to the recorded values:

```sh
ambiguity=REPLACE_WITH_RECORDED_SEQUENCE
artifact=artifact_REPLACE_WITH_CANDIDATE_ID
broil image settle "$operation" --ambiguity "$ambiguity" --artifact "$artifact" --format json
broil image status --operation "$operation" --format json
```

Settlement durably selects that candidate. Repeating the same choice completes
it idempotently; a different choice is refused and reports the winner's ID.
An unlisted ID or a sequence naming no ambiguity is refused before any write.
No artifact record is rewritten.

## Access and manage builders

An external endpoint needs only authenticated access. A managed builder also
needs the selected environment's machine inventory, canonical SSH
authentication, privilege and lifecycle adapter. Prepare those prerequisites
through [the remote workflow](remotes.md) and
[the builder adapter guide](examples/builders/README.md).

### Inspect an authenticated endpoint

```sh
broil image builder access shared --format json
```

Access reports validated BuildKit capabilities and platforms without claiming
lifecycle ownership. For a managed builder, inspect also checks its stored
ownership:

```sh
BROIL_ENV=ci broil image builder inspect shared --format json
```

The response keeps endpoint results, remote dispatch/status/signal, local
failure and ownership uncertainty separate. An endpoint response cannot replace
a failed lifecycle result.

### Set up or reconcile a managed builder

Download and independently verify the exact BuildKit archive as described in
[the adapter guide](examples/builders/README.md#obtain-the-buildkit-archive).
Set `archive` to that file's absolute path, then run the leaf matching your task:

```sh
archive=/absolute/downloads/buildkit-v0.24.0.linux-amd64.tar.gz
BROIL_ENV=ci broil image builder setup shared --archive "$archive" --format json
BROIL_ENV=ci broil image builder reconcile shared --archive "$archive" --format json
```

Setup installs the dedicated owned service; repeated setup preserves unchanged
configuration and cache. Reconcile uses the stored ownership and interrupted
intent. Add `--arm64-emulation` only when intentionally enabling the pinned
emulator; it defaults off. Platform advertisement still needs actual execution
support. A busy lock or uncertain ownership requires inspection, not a second
competing operation.

### Remove the owned service

```sh
BROIL_ENV=ci broil image builder remove shared --format json
```

Ordinary removal stops/removes the owned service while retaining its cache and
storage. Adding `--purge` deletes that verified owned storage too; use it only
when that data is no longer needed. Unrelated services and data remain outside
the builder's ownership. Keep the local `state/builders/` record for these
operations; a moved project or changed scope needs an ownership decision.

## Understand failures and limits

The default table output is for people. `--format json` is one compact document
with recursively sorted keys, sequence order preserved and one newline.
`record show` is the stated exception: its stored field order is preserved.
No report is streamed. A failed operation that produced a report still prints
its available outcomes; an earlier refusal prints no invented report.

Exit 0 means the leaf's required evidence succeeded; 1 means runtime refusal,
failure or unresolved decision; 2 means usage error. Child exits and signals
remain evidence rather than becoming Broil's exit code. Runtime stderr begins
`broil: <class>:`. Classes are configuration, capability, credential,
authentication, trust, tool, source-drift, integrity, publication, timeout,
cancellation, storage, indeterminate and cache-miss.

SIGINT and SIGTERM request cancellation and bounded cleanup. A second signal
does not bypass cleanup. Cancellation exits 1. A lost connection or child exit
does not prove that remote work stopped; cleanup and ownership uncertainty
remain separate from completion.

If cancellation or a deadline causes a record task's result to be lost, the
command reports `indeterminate`. Inspect status and resume before deciding on
another action; the signal alone does not establish what the task completed.

### Configured child environments

Image children start from an empty environment, then apply root and selected
public `env_vars`. They do not copy ambient variables or automatically export
secrets. Name matching below is ASCII case-insensitive, in this order:

1. Remove `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, `BROIL_SECRETS_IDENTITY`,
   `BROIL_SECRETS_PASSPHRASE` and `BAO_TOKEN`.
2. Set normalized `BROIL_ROOT` and the selected `BROIL_ENV`; omit the latter
   for root-only work.
3. Replace `HOME`, `DOCKER_CONFIG`, `BUILDX_CONFIG`, `XDG_CONFIG_HOME`,
   `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR` and
   `TMPDIR` with private workspace directories.
4. Replace `PATH` with the private verified-tool directory and `LC_ALL`/`LANG`
   with `C`.
5. Refuse remaining names beginning `DOCKER_`, `BUILDX_`, `BUILDKIT_`,
   `BUILDKITD_`, `XDG_`, `LD_`, `DYLD_`, `SSL_` or `OTEL_`; names ending
   `_PROXY`; and exact names `SSLKEYLOGFILE`, `GODEBUG`, `GOGC`, `GOMEMLIMIT`,
   `GOENV`, `GOTOOLCHAIN`, `SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `TRACEPARENT` and
   `TRACESTATE`. Tracing controls are refused even when empty.

Ordinary declarations such as `https_proxy`, `DOCKER_HOST` and `SSH_AUTH_SOCK`
can therefore refuse every dispatching image leaf. The fixed diagnostic is
`env_vars declares a name or value the image child-environment policy refuses`.
It names neither the key nor its value. Find the declaration by comparing the
list above with these literal configuration subtrees:

```sh
broil get --json cfg env_vars
broil get --json cfg environments.ci.env_vars
```

This refusal happens before credential acquisition or tool launch, after the
workspace parent is opened. It can leave empty 0700 `state/workspaces/`.
The maps also have finite pair/byte limits; exceeding them prints
`env_vars exceeds the image child-environment bounds` with class `integrity`.
An unknown target or Docker-load matrix refusal may leave the same empty parent.
Unknown environments, missing required tools and invalid executable paths fail
earlier and create no `state/`.

### Storage, cache and custody

Imported cache is trusted build input; Broil does not verify its provenance.
A metadata-only `FROM scratch` producer cannot write cache. Cache promotion
reads the closure twice. Cache state is independent from retained image content
and is not a durable substitute for it.

Every tool/network stage has finite limits. Defaults include 30 minutes per
solve, 30 seconds per metadata/capability stage, 10 seconds for private handoff,
30 seconds per independently idle pipe and one 5-second cleanup grace. Each
stdout/stderr stream has a 16 MiB bound. A record step has a 30-second clock;
publication's retained metadata adapter admits at most 1 MiB per object and
64 manifests/platforms.

Staging accounting limits adopted content, not an external writer's peak.
A tool may temporarily exceed the allowance or exhaust storage. The default
adopted staging allowance is 5 GiB and a content closure is at most 4 GiB.
Tool copies, the 1 MiB reserve and metadata consume part of the allowance.
Output retention and archive unpacking need room for a closure copy. Publication
layout assembly counts its re-homed closure; the subsequent upload counts its
own client state because the content has a separate owner. A cache-writing node
must fit derived inputs, image output and cache export together, potentially
counting a base layer three times. These are accounting bounds, not disk quotas.

Known private inputs use bounded zeroizing holders and protected leases, with
reported residue or unresolved custody. Kernel, swap and crash-dump limits
remain as described in [secret custody](secrets.md). Return, unlink and child
exit do not prove erasure from memory, logs, backups or devices. Treat an
uncertain cleanup result as a separate fact even when build or publication
completed.
