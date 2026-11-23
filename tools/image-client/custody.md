# Image client custody and completion boundary

This audit describes the image-local Rust path and protocol-3 filesystem helper.
It preserves the existing registry helper's external-consumer boundary. No
acquired credential or key is permitted in ordinary image staging.

| Storage | Owner and last use |
| --- | --- |
| Selected public policy, paths, command arguments and frame prefix | Controller/launch task; bounded before dispatch; contains no private scalar or raw tool output |
| Registry credential | Existing `OwnedSecret`; borrowed directly for nonblocking pipe writes; dropped on full write/EOF or the first handoff failure/cancellation |
| Child stdout/stderr | Image `Bytes`, preallocated to the exact finite capacity and wiped on drop, success and every failure path |
| Parsed control and content values | Borrowed slices of the owning private buffer; vectors contain views, not decoded private bytes |
| Escaped strings and duplicate-member keys | Direct decoding into `Bytes`; ordered sets own zeroizing keys, including unknown/discarded/error cases |
| Content metadata and platform fields | Bounded zeroizing buffers retained only while validating original content and graph/platform associations |
| File copying/hashing scratch | Fixed 64 KiB `Bytes`, cleared between reads and on error/drop |
| SHA-256 state and partial blocks | sha2 0.11.0 with `zeroize`; Sha256VarCore wipes state/count on drop, block-buffer 0.12.1 wipes its block and position on drop |
| Digest result | Fixed output array explicitly zeroized after comparison; only a validated encoded identity becomes a public descriptor |
| Launched child awaiting adoption | Bounded result slot with its permit; abandoned delivery closes private pipes, attempts group termination and retains unresolved capacity without a blocking Drop |
| Selected acquisition inputs | Existing bounded `CredentialInputs`; an independent zeroizing duplicate goes to each scalar resolver; the original ends after the final acquisition, before tool execution |
| TLS/instruction scalar being materialized | One moved `OwnedSecret`; direct borrowed partial writes, followed by drop before result delivery, including failure |
| Protected lease | Public identities, checked counts and retained descriptors only; private bytes are in its exclusively created tmpfs files, outside ordinary workspaces |
| Unobserved local action or result | The shared operation task slot and permit remain held; a stalled write retains its one zeroizing scalar until that syscall returns |
| Immutable analyzer snapshot | `analysis::Snapshot` owns original Dockerfile and verified metadata in fixed-capacity `Bytes`; it survives result validation and, for complete candidates, remains with the private candidate until consumer last use |
| Analyzer request | Two-pass size calculation followed by direct JSON/base64 encoding into one exact-size `Bytes`; the supervisor consumes it at completed write/EOF or earlier failure, independently of the original snapshot |
| Analyzer material and inverse-map checks | Borrowed frame views and zeroizing decoded config/manifest/alias/escaped-string holders; only validated original identities, finite ranges/IDs and closed classes enter ordinary public storage |

The manifest-selected graph pins digest 0.11.3, sha2 0.11.0, block-buffer 0.12.1
and zeroize 1.9.0. The relevant dependency paths are `sha2/src/block_api.rs`,
`digest/src/block_api`, and `block-buffer/src/lib.rs`. Their retained state and
reset/error drops must be re-audited on a locked source or feature change.
Ordinary serde_json owns only already-public requests and compiled public tables;
private strings never enter its unescape scratch or owned Value representation.

The analyzer uses the already locked base64ct 1.8.3 package directly, with
`default-features = false`; actual unified Cargo features remain part of the
normal-closure evidence. Only `Base64::encode` and `Base64::decode` slice APIs
are selected. No allocating `encode_string`/`decode_vec` or `decode_in_place`
path is called. Both encoded and decoded limits, padded lengths and arithmetic
are checked before allocating the fixed caller-owned destination. Failed and
discarded destinations are still wiped. Strict decoding re-encodes/checks the
last block, so noncanonical trailing bits and padding cannot pass.

Audited locked `base64ct/src/encoding.rs` transfer scratch: padded encoding uses
one three-byte stack tail; decoding uses four-byte input and three-byte output
tails; `validate_last_block` uses a four-byte re-encoding destination and the
encoder's tail. These transient codec transfers are not retained plaintext
owners or allocating parser trees. They are not explicitly wiped by the library
and retain the existing transport-buffer residue boundary, without claiming
stack/register erasure. No dependency-owned buffer survives the API return.
The exact crate archive/checksum is already in Cargo.lock; these selected paths
must be re-audited on source/version/feature changes. Hash output arrays are
explicitly wiped after producing the permitted content digest.

Analyzer requests never use `Input.prefix`, scalar storage, worker protocol 3
or public launch captures. Analyzer-only admission carries its original
preparation deadline into the first conversion. Later attempts have distinct
monotonic counters and immutable resolution identities. All parsing/adoption
stays inside the original analysis stage; stale/cross-operation/attempt echoes,
nonzero exit, cancellation, unfinished pipes and surplus frames prevent adoption.
The content parser's 8192-node/128-level variant is selected only for analyzer
frames; worker/progress envelope limits stay unchanged.

Verified registry output retains its original normalized request reference in
the sealed capability. Independently supplied metadata must verify exact bytes,
root/index/manifest/config/platform relationships against that capability;
raw descriptor checking cannot manufacture transfer provenance. Private bindings
preserve the original descriptor/layer/config/history relationships. Inherited
trigger changes are checked against the original parent/trigger/use map without
introducing a second Dockerfile grammar. Candidate material is not solve-ready
content or a completed producer graph.

The launch task captures public executable identity, bounded argv/environment,
cwd, cancellation/deadline state, a permit and designated pipe/result handles.
It does not capture the scalar or private output. The caller owns the concurrent
pipe/deadline loop. A cancelled or late task cannot receive a new frame or become
another stage's child. Unobserved process ownership never returns reusable
capacity merely because the caller returned.

Ordinary workspace traversal, hashing and recursive cleanup occur only in a
supervised child. Public executable bootstrap validation/spawn uses the bounded launch task.
The pipe loop and Drop never traverse, hash, join or recursively delete. Cleanup
rechecks the operation root and recorded parent/entry identities and preserves
explicit retained roots and ancestors. Slot creation and produced verification
share the producing stage's clock and cleanup grace.

The selected consumer API is `images::consumers::{registry,builder}`. Preparation
borrows the loaded project immutably and binds its root/environment, catalog
policy, original reference, purpose, operation and requested target/stage.
Its public frame/argv bounds and required installed tools are checked before
acquisition. The prepared value accepts acquisition inputs and cancellation,
not a replacement request. A registry call consumes one stage; a builder call
performs discovery or one prepared solve and closes. Neither returns credentials,
an idle authenticated session or a callback for later work.

`broil-secrets::read::resolve_scalar_with_options` changes only the explicit
non-interactive option; the original entry point delegates with its existing
default. Image consumers pass explicit store-relative set/literal key and the
same acquisition cancellation control. Native authenticated local reads,
configured vault-first selection, allowed unavailability fallback and owned-token
revocation remain in the existing resolver. Store diagnostics are discarded at
the image boundary. Token cleanup failure fails the consumer independently of
subsequent client/workspace cleanup. Provider version metadata remains unavailable;
no secret fingerprint is manufactured.

`protected.rs` performs each private-path open, inspection, tmpfs check, creation,
write, recheck and unlink inside `supervise::local`. Its private typed action
set cannot acquire a scalar or launch a tool. It shares `Task`/`Permit` admission
with public launch and retains the slot through result observation. Both caller
and action check the original deadline/cancellation. Public launch rechecks only
retained descriptor/path identities immediately before spawn. No protected file,
scalar or lease job enters protocol 3. Test hooks exist only in test builds;
production has no hook field, callback value or runtime delay/trust switch.

Before opening a client or acquiring a scalar, the selected lease path must be
disjoint from the operation workspace, prepared input/read grants, selected
source contexts/Dockerfile and declared retention path. This prevents private
files from entering ordinary worker scans or authorized context reads. Paths
retain the existing normalized, no-symlink and trusted-local-OS contract.

Private files have exclusive 0600 creation beneath a fresh 0700 session on an
already available verified tmpfs. Directory names use the operation identity;
files use numeric positions, never set/key names. Checked limits are 1 MiB per
scalar, 128 files and 16 MiB of values including partial files. Parent and file
identities bind access and explicit matching cleanup. An unobserved creation
does not confer deletion authority over a later path occupant. Borrowed CA files
and explicit SSH-agent sockets are checked but never deleted or stopped.

The scalar moves into the local action without cloning its allocation. A stalled
syscall cannot be safely preempted: the task keeps that zeroizing holder until
the call returns, then ends custody before any further step or result delivery.
The caller reports the unresolved owner and possible residue, prevents another
stage or cleanup task, and retains admission until process exit if ownership
cannot be reconciled. Late/dropped results release handles only; Drop does no
filesystem work or join. This bounds abandoned owners to four, without promising
capacity recovery, successful erasure or removal of crash residue.

The final successful or failed client stage retains its clock. Session close
uses its one absolute cleanup deadline for local `rm --keep-daemon`, protected
files and ordinary workspace cleanup, in that order. Acquisition failure before
a client stage begins one cleanup grace on that failure. No cleanup task starts
after expiry or with unresolved readers. Verified retained OCI content survives
independently of cleanup failure. Selected secret/SSH Bake mappings replace
conflicting prepared mappings and use public IDs/paths only.

The controller modules and scalar option are outside the filesystem
helper's recorded source inputs. A later change added a core image-model field and
refreshed the helper's source, binary, lock and legal identities in
`compatibility.json`; its linked normal graph and protocol remained unchanged.
Existing native SOPS/age,
vault JSON, registry and hashing inspections retain only their matching source
and call-path scope.

The registry scalar holder ends independently of the external Go process. Builder
TLS, instruction secrets and SSH forwarding keep their existing private tmpfs,
pipe or socket consumers and separate last-use/cancellation responsibilities.
The local tools/OS are trusted dependencies. This does not contain instruction
code or an external tool that leaks input it receives.

Kernel/syscall transfer copies, hash-compression transfer registers, external
client/daemon storage, inaccessible live buffers, forced death, swap and crash
dumps have their existing residue limits. Ordinary artifact files are not a
zeroizing filesystem. Observed termination is not proof of erasure, and bounded
return is not proof that every late OS or remote effect was prevented.
