# Run the replicated managed registry

A K3s target that declares a managed `registry` keeps a full copy of the
registry's content on every member. Each node pulls release images from its own
copy, so a deployment needs no image traffic from the origin and node pulls keep
working while the member that accepts pushes is away. This page explains what
runs where, how to read its health, how the push side moves between members and
which limits apply.

Start with a target [created](k3s-create.md) with a managed registry and the
publication prerequisites of [Publish to the managed registry](k3s-registry-publish.md).
The commands below use environment `prod`, target `edge` with servers
`server-1` to `server-3` and agents `agent-4` to `agent-6`, and run on the Linux
controller from the configured project root.

## What runs on each member

Four roles share one registry name and one origin endpoint:

| Role | Where | What it does |
| --- | --- | --- |
| Replica | Every member not recorded as removed | The directory `registry.storage.path` holds the whole registry content in its `data` subdirectory. |
| Writer | One member | The only read-write Distribution. It accepts pushes and origin reads behind the declared endpoint, as before. |
| Replication | Every member | A Broil-owned Syncthing service, `broil-k3s-replication`, sends the writer's replica to every other replica. It is send-only on the writer and receive-only elsewhere. |
| Reader and local token service | Every member | A read-only Distribution on `127.0.0.1:5599` serves that member's node pulls from its local replica; the token service also answers on `127.0.0.1:5598`, so pulls stay authenticated with the node-pull principal's grants. |

`registry.member` names the initial writer. The current writer is recorded with
the target and moves only when [its member is drained](k3s-manage.md#maintain-members).
`registry.storage.path` and `capacity_mib` apply to every member, not only to
the writer: each member needs the declared free capacity at creation.

`node_registries[].fallback` decides what a node does when its replica lacks
content. With `disabled`, the default, a node pulls only from its local reader.
With `same-origin`, it tries its local reader first and the origin second.
External registries render as before.

Members reach each other on TCP and UDP port 22000. Open that port between all
members before `create`.

## Read the registry's state

Two live reads create no operation:

```sh
BROIL_ENV=prod broil k3s registry inspect edge --format json
BROIL_ENV=prod broil k3s delivery check edge --format json
```

`registry inspect` reports one observation per component and member:
`registry-writer` (the current writer and whether pushes are accepted),
`registry-replica` (each member's folder type, completion, outstanding bytes,
connected peers and `state`), `registry-reader` and `registry-token-local`
(each member's loopback service), beside the storage, service and endpoint
components. `delivery check` is the compact per-member projection to read
before a delivery: `replica`, `folder`, `completion`, `need_bytes`,
`peers_connected` and the `reader` and `token` states.

A replica's `state` is one of:

| State | Meaning |
| --- | --- |
| `in-sync` | The replica holds everything the writer sent. |
| `syncing` | It is still receiving. A push reaches other replicas after the writer's watcher or its 60-second rescan sees it. |
| `local-changes` | Someone changed a receive-only replica. The next `reconcile` reverts it. |
| `stopped` | The member's replication service is not running. |
| `removed` | The member is recorded as removed. |
| `unobserved` | The read failed. |

Exit 0 means every member was observed. A replica that is still syncing is a
fact, not a failed read.

## Move the writer

The writer moves only through a drain of its member, which needs an approval.
The observed plan names the new writer and states whether pushes can be lost:

```sh
BROIL_ENV=prod broil k3s plan edge --action node-drain --member server-1 --observe --format json
```

Read `writer_move` `{from, to, loss_possible}` and pass the plan's `approval` to
`node drain edge server-1 --approve <digest>`. The new writer is the first
server, then the first agent, in declaration order that is Ready, uncordoned and
in sync, other than the old writer. Without one, as on a single-member target,
the drain refuses `no-writer-candidate`.

During the move Broil stops the writer, rescans the old writer's replica, waits
until the old writer sees the new writer's replica complete and the new writer
reports itself in sync, switches the two folder types, starts the writer on the
new member and checks that it is ready. The drain report's
`writer_move.pause_duration_ms` is how long pushes and origin reads were
refused. Node pulls never stop. The endpoint, its certificate and its token
realm do not change. `node uncordon` does not move the writer back.

When the writer's member is unreachable, the plan reports `loss_possible: true`
and the approval covers that statement: pushes that reached only the old
writer's replica cannot be proved present. Broil detaches the old writer's
device from every reachable member and moves the writer without the rescan and
the old writer's half of the proof. Republish retained artifacts afterwards
with `broil image publish` if you need them. A member that later returns is
configured receive-only before any peer accepts its device again.

A move that fails after stopping the writer leaves pushes refused and the
operation unresolved, with recovery `operator-recovery`. Broil never restarts
the old writer implicitly.

## Limits

These limits apply to the replicated registry:

- **Full content everywhere.** Every replica member holds the whole registry
  and needs the declared capacity, which is checked only at creation. Nothing
  is deleted before the later maintenance roadmap, so every replica grows.
  Nothing enforces the capacity, so content can fill a filesystem.
- **Ports.** Members reach each other on TCP and UDP port 22000. The reader and
  the local token service use loopback ports 5599 and 5598, and the replication
  API loopback port 8384. Any local process can reach them; the API answers
  only with its key.
- **Replication lag.** A replica receives a push after the writer's watcher or
  its 60-second rescan sees it. Distribution writes link files and blobs
  separately, so a replica can briefly hold a manifest whose blobs have not
  arrived. A release delivery checks the whole closure through the member's
  reader before it pulls.
- **Unplanned writer loss.** Pushes stop until a drain moves the writer; node
  pulls continue from every replica. A move from an unreachable writer may lose
  pushes that no other replica received. A partitioned writer that keeps
  running cannot accept pushes through the endpoint, whose Service routes only
  to a ready pod, but its process stays until its machine stops.
- **The move window.** Pushes and origin reads are refused for
  `pause_duration_ms`. Uploads in progress are lost, as at any writer restart.
- **Revert.** A receive-only replica's local changes, including an operator's,
  are discarded by the next `reconcile`.
- **Trust domain.** Readers and local token services answer every process on
  their member that presents node-pull or other principal credentials. Host
  networking puts the reader outside NetworkPolicy, and the signing key's tmpfs
  copy exists on every replica member.
- **Residue.** A removed member keeps its replica, its replication home with its
  device key and its record. The old machine of a replaced member keeps them
  too, with its unit stopped when it was reachable. Broil never deletes them in
  this version.
- **Owner room.** Each replica member adds two Resources to the owner record,
  which lowers the
  [supported target size](k3s-operations.md#cases-node-registry-configuration-does-not-cover);
  the [member limit](k3s-operations.md#member-maintenance-limits) states the
  result.

The writer service has these limits:

- **Reachability.** The writer speaks plain HTTP. It is reachable from inside
  its pod, through RBAC-authorized `kubectl port-forward` or the API server's
  pod proxy, and from the current writer's own host network, which K3s's
  network policy controller admits. After the token switch every request needs
  a token. The policy refuses a pod in another namespace, on any node, and
  another node's host network.
- **One writer.** One pod on the current writer's node, with no high
  availability. An unavailable writer member stops pushes until a drain moves
  the writer; node pulls continue from every replica.
- **Created once.** The five service objects are created once. Any change of
  their labels, annotations, finalizers or spec, other than a writer move's
  replica count and node selector and the token switch's configuration, is
  drift that refuses `ownership`, with no repair in this version. Deleting the
  writer pod is the supported restart; `kubectl rollout restart` and
  `kubectl scale` change the Deployment and leave drift.
- **Deletion and uploads.** Deletion and upload purging are disabled. An upload
  in flight does not survive a pod restart or a writer move.
- **Images on every member.** The Distribution image is imported and pinned on
  every replica member from its staged bootstrap content.
- **Restarts.** Content persists across a pod restart and a node restart,
  because it lives on the writer's replica and on every other replica.
- **Failure after recording.** Any failure after an operation is recorded
  leaves the target refusing `busy` until operator recovery.
- **Adoption.** The derived image runs as the writer only under the
  configuration that its advisory dispositions assume.
- **Image removal.** An operator who removes a pinned image record is refused
  `readiness` at the next observation. Broil never imports it again in this
  version, except on a replaced member's new machine.

The replica directories have these limits:

- **Capacity on every member.** Every replica member needs the declared
  capacity, checked only at creation, and every replica grows with the
  registry.
- **Host-side changes.** Root deleting or editing a backing directory, its
  record or its content root is detected at the next observation (`absent`,
  `foreign` or `owned-drifted`), within the identity limit below, but not
  prevented. A receive-only replica's changed content is reverted by the next
  `reconcile`; a deleted directory or record refuses every later reconcile until
  the later roadmap's restore or repair.
- **Mounts.** A mount added below the path is `owned-drifted`; a filesystem
  mounted at the path hides the record and is `foreign`. Broil removes neither.
- **Identity.** After creation Broil compares inode numbers and the filesystem
  id, not device numbers. A block-level copy of the whole filesystem keeps that
  identity and is not detected, nor is a deleted and recreated layout on the
  same filesystem with a copied record that reuses freed inode numbers.
- **Filesystems.** Only ext4 and btrfs are supported; xfs is refused because its
  filesystem id is its device number.
- **Member loss.** A lost member's content remains on every other replica. A
  lost writer member stops pushes until a drain moves the writer.
- **Removed and replaced members.** A removed member's directory, and an old
  machine's directory after a replacement onto a new machine, stay with their
  records; Broil never deletes them in this version.
- **Relocation and resize.** A changed path or capacity changes the declaration
  and refuses `ownership` until it is reverted. Storage relocation is the later
  roadmap's explicit restore.
- **Runtime identity.** User and group 10000 are fixed.
- **Ancestors.** Every ancestor of the path must be a root-owned directory
  without group or other write and with other search, and user 10000 must be
  able to search it under the replication unit's restrictions. This is Broil's
  supported layout, not a claim that Linux requires other search: an ancestor
  that grants the service search only through its group or an ACL entry is
  refused. Layouts that earlier versions accepted with a closed ancestor, such
  as a root-owned 0700 parent, are refused at every stage, including the
  observation of existing storage. Broil does not migrate them, changes no
  ancestor's owner, mode or ACL, never moves retained data and suggests no path
  change; review any host-permission change separately.
- **Failure after recording.** Any failure after recording leaves the target
  refusing `busy` until operator recovery.
- **Other services' trees.** Only K3s's, kubelet's and Broil's trees are
  reserved. A path inside another service's data root is admitted and shares
  that service's cleanup.
- **Declaration changes.** A registry declared or changed after the target
  exists refuses `ownership` until the declaration is reverted.

## When the registry cannot recover

Losing every replica, or a changed registry declaration that you keep, leaves
this target refusing until the later roadmap's restore or repair. Meanwhile only
a new target provides a managed registry: a distinct target (another target
name, environment or project) whose hosts hold no Broil claim and no existing
K3s data, configuration or service, with the pinned K3s executable and profile
from [base provisioning](k3s-bootstrap.md#host-prerequisites) still installed.
While the old target stays declared, the new target shares none of its API,
registration or managed-registry endpoint origins and no overlapping storage.
The old owner record is retained, this version cannot release a claimed host,
and removing the old declaration prevents record inspection. The new registry
starts empty: publish retained images again, or rebuild content that only the
old registry held.
