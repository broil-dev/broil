# Scoped registry transfer prototype

This Linux/amd64 helper evaluates the scoped registry boundary. It is not a
public Broil command or a passing aggregate backend gate.

Build with the exact compiler/archive hash in `toolchain.lock.json`, with its
recorded environment and `go build -trimpath -buildvcs=false -ldflags=-buildid=`.
Only the Go standard library is selected. Do not permit automatic toolchain or
module downloads. The executable runs without the compiler in PATH. Source,
module, build inputs, and legal files are all contained in this directory and
carried by the current source-release rules.

Protocol v1 accepts one private stdin frame: big-endian u32 public JSON length,
public policy JSON, big-endian u32 credential length, credential bytes, and EOF.
Stdout uses a big-endian u32 length followed by one typed result JSON and EOF.
No arguments or environment variables select credentials. One process serves
one repository, purpose, operation, and selected scalar. Both descriptors must
be private pipes. Duplicate/unknown fields, invalid UTF-8, escaped path forms,
extra requests, trailing bytes, and unsupported combinations fail before HTTP.

All public header fields below are required; only the stated fields permit null.

| Field | Value |
| --- | --- |
| `protocol_version` | Integer 1 |
| `operation_id` | `operation-` followed by 32 lowercase hexadecimal characters |
| `endpoint`, `development_http` | HTTPS origin URL; HTTP requires explicit `true` for isolated development |
| `ca` | Null for OS roots, or absolute PEM path, maximum 1 MiB |
| `repository` | Canonical endpoint authority plus lowercase repository path; no tag/digest |
| `reference` | That repository with optional tag and/or `@sha256:<64 lowercase hex>`; absent tag/digest means latest |
| `expected_root` | Null or `{digest, size, media_type}`; required for upload; positive size and supported root media |
| `purpose`, `action`, `content_kind` | Exactly one row of the operation table below |
| `auth` | `{kind: "none"}`, `{kind: "bearer"}`, or `{kind: "password", username, token_service}` |
| `staging_dir` | New absolute path under a caller-owned 0700 parent |
| `input_dir` | Existing private OCI-layout directory for upload; null otherwise |
| `limits` | Object of zero or more tighter positive integer limits from the table below |

Password mode requires a nonempty UTF-8 username without colon/control bytes.
`token_service` is null or exactly `{realm, service}`. The realm must have the
same scheme, canonical hostname and effective port, with an absolute path of
ASCII alphanumeric/underscore/hyphen segments. No userinfo, query, fragment,
percent escape, dot/empty segment, or trailing slash is allowed. Service is
1–255 non-whitespace printable ASCII bytes, compared exactly. Hostnames are
canonical lowercase ASCII DNS, canonical IPv4, or bracketed IPv6 without zones.
Scalars are nonempty NUL-free UTF-8; Bearer values additionally use the HTTP
Bearer token alphabet. Anonymous access requires zero scalar bytes.

| Purpose / action / kind | Authorized selected-repository resources |
| --- | --- |
| metadata / inspect / image | GET/HEAD manifests/indexes and referenced configuration blobs; no layers |
| pull / fetch / image | GET/HEAD complete image closure |
| cache_read / fetch / cache | GET/HEAD complete cache closure |
| push / upload / image | Closure GET/HEAD; blob POST/PATCH/PUT; manifest/index PUT; complete verification reads |
| cache_write / upload / cache | Same write/verification methods for the selected cache closure |

Resources are constructed as `/v2/<repository>/manifests/<ref>` and
`/v2/<repository>/blobs/<digest>`. Optional GET `/v2/` is credential-free.
No catalog, tag listing, mount, deletion, arbitrary URL/header or credential
discovery is available. Direct Basic/static Bearer never falls back or exchanges
tokens. Declared token mode sends the password only to its exact realm, with
policy-derived `service` and `repository:<repository>:pull` scope (or
`pull,push` for writes). A challenge may advertise a subset of those actions;
duplicate, broader, conflicting, or unknown parameters fail before disclosure.
Token JSON permits token/access_token (identical when both occur), positive
expires_in and UTC issued_at only; expiry defaults to 60 seconds from receipt.
No refresh token, redirect, cross-operation token reuse or anonymous fallback.

Only bounded 307/308 reads preserving the exact resource, method and origin
are followed. Queries, signed URLs and foreign origins are rejected. Upload
sessions bind `/v2/<repository>/blobs/uploads/<1–128 alphanumeric/hyphen bytes>`.
Continuation permits only one nonempty `_state` (4096 decoded bytes; total
query 8192 encoded bytes). Completion adds the locally verified digest; a
Location cannot supply it or replace the bound session/repository/origin.
Writes authenticate through a read first and are never automatically replayed.

| Limit names (bytes unless stated) | Default and hard maximum |
| --- | --- |
| header_bytes, result_bytes, http_header_bytes, stderr_bytes | 65536 each |
| credential_bytes, token_response_bytes | 1048576 each |
| metadata_bytes | 16777216 per object |
| blob_bytes, content_bytes, staging_bytes, network_bytes | 1073741824; 4294967296; 5368709120; 17179869184 |
| descriptors, descriptor_edges, graph_depth | 4096; 8192; 32 |
| requests, redirects, token_exchanges | 16384 total; 3 per read; 2 per process |
| operation_ms, frame_ms, connect_ms, request_ms, idle_ms, cleanup_ms | 1800000; 10000; 20000; 300000; 30000; 5000 |

Owned protocol JSON has depth 16; content JSON has depth 128. Operation time
starts at process launch. Deadlines run concurrently; cleanup has only its
additional grace. The caller must supervise every pipe, cancellation and exit,
and report uncertain termination when it cannot observe cleanup in time.

Results contain exactly `protocol_version`, `operation_id` (null only before a
valid policy), `status`, `failure_class`, `dispatch`, `completion_uncertain`,
`cleanup_uncertain`, `root`, `closure_complete`, `verified_descriptors`,
`verified_bytes`, and `peak_staging_bytes`. Status is succeeded/failed/cancelled/
unknown; dispatch is none/read/write. Failure classes are none, policy,
credential, authentication, trust, protocol, integrity, cache-miss, storage, limit, timeout,
cancellation, or indeterminate. Success requires exit 0, failure class none,
validated non-null root and no uncertainty. Inspect always has incomplete
closure; failures have null root and incomplete closure. Malformed/missing
results or contradictory caller observations fail closed. Treat both child
streams as private; validate borrowed fields before any printable projection.

`cache-miss` is a non-success result only for the initial cache_read/fetch/cache
root GET: HTTP 404 and exactly one MANIFEST_UNKNOWN error. The private error
envelope permits only `errors`, whose single entry requires string `code` and
allows string `message` and arbitrary private `detail`. The complete UTF-8 JSON
must have no duplicate/unknown members, at most 16 nesting levels and 65536 bytes,
subject to tighter metadata/network/deadline limits. Other statuses, malformed
errors, missing descendants, wrong pins, authentication and write failures never
qualify. This reports the registry's response, not proven grants or global absence.

A miss requires normal nonzero exit, failed/read, null root, incomplete closure,
zero verified counts and completed cleanup without uncertainty. Only a caller's
explicitly optional cache read may skip that validated result, bound to its exact
operation, original policy and observed child/cleanup state. Required reads and
all other failures remain fatal. No cache bytes exist to import. The unreleased
protocol remains v1, but this variant requires the revised exact source/build
tuple and renewed CI conformance; old success-only Rust callers still refuse it.
Generic older-helper integrity results cannot substitute for this capability.

Supported content is OCI image indexes/manifests/configurations, Docker schema-2
lists/manifests/configurations, ordinary OCI tar/gzip/zstd and Docker gzip layers.
Cache kind permits OCI manifests with BuildKit cacheconfig.v0 and OCI layers;
it proves byte transfer only. External blobs and subject/artifact graphs fail.
Resolve tags once, verify every descriptor and platform/config association,
preserve encoded bytes, and verify complete uploads by immutable readback.

All content lives in caller-owned 0700 directories and 0600 regular files,
without symlink traversal. `blobs/sha256/<hex>` preserves original bytes;
fetch adds a separate OCI wrapper and atomic final `verified.json`. Inspect
never advertises a complete layout. The caller owns successful read staging
and must recheck hashes before reuse. Upload preserves input and removes its
scratch. Failed cleanup removes only matching invocation-created identities;
unknown writes retain uncertainty and never trigger replay or registry deletion.

The Go process is an external credential consumer. Its memory and HTTP headers
are not covered by Rust zeroization claims. Cleanup makes no Go, kernel, swap,
or crash-dump erasure guarantee. Staging contains private image content. A
transfer receipt cannot establish Built/Published or cache-reuse outcomes.

First-party source uses Apache-2.0 (`LICENSE`). Go and its standard-library
vendor code use the actual license/patent texts under `legal/`; the lock maps
each upstream path to its verified copy. These notices are separate from the
Broil Rust executable's target-specific notices.
