# Inspect and manage an owned K3s target

Use live observations to decide whether an existing cluster needs attention,
then select the smallest supported reconciliation. Broil keeps declarations,
recorded operations and current observations distinct: an earlier successful
operation is not a current health check, and a complete read can report a
component that is not ready.

Start with a [created target](k3s-create.md), its unchanged declaration, matching
Broil/profile, trusted SSH routes and published managed administrator access.
Run Bash commands on the Linux controller from the configured project root.
Replace environment `lab` and target `demo` with your names. `--file` may select
that project's configuration from another directory; `BROIL_ENV` is still required.

## Choose an observation

The first useful result is a complete member observation:

```sh
BROIL_ENV=lab broil k3s nodes demo --format json --non-interactive
```

Read `outcome`, each observation's `facts` and `readiness`, and any `failure`.
`complete` with exit 0 means the requested facts were obtained completely.
It can include a non-ready member or a mismatch. Foreign nodes remain separate
and do not become owned members.

| Question | Command after `BROIL_ENV=lab broil k3s` |
| --- | --- |
| What does each declared component report? | `status demo` |
| Which member identity, role, version, label or taint differs? | `nodes demo` |
| What does a particular subsystem report? | `diagnose demo --component api` |
| Which workloads and counts are visible? | `workloads demo` |
| Which services exist and which does Broil own? | `services demo` |
| What does the registry stack report? | `registry inspect demo` |
| Is every replica, reader and local token service ready for a delivery? | `delivery check demo` |
| What does an application's active release report on the cluster? | `release status demo <application>` |

These views create no operation, supply no credentials and make no
lifecycle or Kubernetes change. API inventories need the acting first server,
the first server in declaration order that is not recorded as removed and has
a published node UID, and its
managed access. Broil does not use an ambient kubeconfig or refresh
missing/expired access. A validated missing cluster reports `create`; unsafe
or expired existing access must be resolved as reported, not treated as absence.

Read `source`, `observed_ms` and `operation` together: `live` describes this
invocation, `recorded` keeps its original time and operation, and `declaration`
describes configuration. Different members can have different read times and
failures; the report is not an atomic cluster snapshot.

`nodes`, `workloads`, `services` and `diagnose` accept `--limit` from 1 to 1000,
default 100. A truncated result, failed required read or uncertain cleanup exits
1 and keeps available public facts. Broil does not fetch another page. Smaller
limits can avoid reply-size refusal but cannot make an incomplete read complete.
JSON and table contain the same public facts; neither exposes raw API objects,
Secrets, logs or kubeconfig material. The [view reference](k3s-operations.md#read-live-views)
explains component-specific readiness and provenance limits.

For repeated commands, a root alias such as the following shortens the same
selection. Add it to your existing alias map, rather than replacing the file:

```yaml
aliases:
  kn: k3s nodes demo
```

```sh
BROIL_ENV=lab broil kn --format json
```

The selected environment's aliases overlay root aliases. An alias expands
once; complete built-in leaves still own their operands and errors. See
[aliases](aliases.md) and [command resolution](command-resolution.md) before
adding grouped shortcuts.

## Apply a selected change

**Inspection** reads references and installed evidence without fetching secret
values for comparison. **Reconciliation** runs the selected existing operations.
Choose by the intended effect:

| Selection | Effect and important boundary |
| --- | --- |
| `credentials inspect … --consumer admin` or `access check` | Verify existing managed administrator access live; no export or refresh |
| `credentials reconcile … --consumer admin` | The same verification only; no preparation, supply or recorded operation |
| `credentials reconcile … --consumer infrastructure-tls` | Reconcile declared private-CA issuers then certificates; active issuer replacement remains deferred |
| `credentials reconcile … --consumer registry-auth` | Change every declared principal in name order, including unchanged values, then install and verify token configuration; no principal selector |
| `credentials reconcile … --consumer node-pull` | Change matching managed node-pull principals, token configuration, all required node configurations and their owned restart, then verify grants |
| `registry reconcile` | Registry storage/service/endpoint/signing/token/principal sequence on an existing cluster; no unrelated network, issuer or certificate reconciliation |

Before changing a principal password, finish rollback or cleanup of any active
rotation for that key, then use `broil secrets edit` and, if a vault is
configured, `broil secrets sync`. These K3s commands do not edit/sync the store
or run its rotation protocol. Passwords must be 1–72 bytes with no NUL; node
configuration has [additional value, file and CA-path constraints](k3s-operations.md#prepare-the-entries).
Keep all supplying sources consistent throughout an incomplete change.

Password changes have no overlap. Existing tokens can live for 300 seconds;
new authentication can fail during the switch and token pod restart. Superseded
private generations remain, and removing a declaration is not complete
revocation. `TRANSITION_READY` rotation is unsupported for these passwords.
Active signing-key replacement is also deferred. Read the
[password procedure](k3s-operations.md#change-or-revoke-a-password) before acting.

For a managed node-pull change, the command owns the order: principal, token
configuration, every node's new file and restart, then grant observation. It
does not change publication/maintenance passwords. A required external entry
without an admitted verifier refuses before effects. If a bad value was supplied
but could not be rendered, repair the value and follow the
[complete change order](k3s-operations.md#change-a-node-credential).

Preview your selected work before invoking it. This example selects node-pull
configuration and will restart members when you run the reconciliation:

```sh
BROIL_ENV=lab broil k3s plan demo --action credentials-reconcile --consumer node-pull --format json
BROIL_ENV=lab broil k3s credentials reconcile demo --consumer node-pull --non-interactive --format json
BROIL_ENV=lab broil k3s credentials inspect demo --consumer node-pull --format json
```

Look for complete execution and the selected installed grant/configuration
evidence. `verified` does not compare installed passwords to today's store
values, and configured node access does not prove a production pull. Use the
[manual digest pull and scoped cleanup](k3s-operations.md#check-that-every-node-can-pull)
when you need that separate observation.

Every controlled restart run restarts every selected member, and restarting a
single server interrupts its API/datastore. The service allows five starts in
300 seconds. Runs consume one operation per member and retained attempts on
every member; finite stores have no compaction. The declaration's 128-member
range exceeds the size that these operations can support. Review
[restart limits](k3s-operations.md#cases-the-restart-does-not-cover) and
[node configuration limits](k3s-operations.md#cases-node-registry-configuration-does-not-cover)
before scheduling repeated changes. A settled refusal before a record and an
Unknown operation have different continuation rules; use the reported recovery.

## Maintain members

Member maintenance takes one owned member out of service and brings it back,
or moves it to another machine, while the rest of the target keeps running.
Each command records operations and changes the cluster; preview it first.
The examples use target `demo` with servers `server-1` to `server-3` and agents
`agent-4` to `agent-6`, and `registry.member: server-1`, the initial registry
writer. In the commands, set `APPROVAL` to the `approval` digest of the
observed plan just before, and `RELEASE` to a release ID.

Four commands make up the lifecycle:

| Command after `BROIL_ENV=lab broil k3s` | Effect |
| --- | --- |
| `node drain demo <member>` | Cordons the member and evicts its pods through the eviction API. Draining the registry writer's member also moves the writer and needs `--approve`. |
| `node uncordon demo <member>` | Makes a drained member schedulable again. The writer does not move back. |
| `node remove demo <member> --approve <digest>` | Removes a drained member from the cluster and records it as removed. Its data stays on its machine. |
| `node replace demo <member> --approve <digest>` | Joins the removed member's declared machine and returns it to service. |

Every command needs settled history: an unsettled earlier operation of the
target refuses `busy` and names it. Each refusal line names the member and the
next command, for example
`readiness: not-drained (agent-5 still runs 2 evictable pods; run k3s node drain edge agent-5)`.

### Drain a member

```sh
BROIL_ENV=lab broil k3s plan demo --action node-drain --member agent-5 --observe --format json
BROIL_ENV=lab broil k3s node drain demo agent-5 --format json
```

The plan's `pods` lists each pod to evict or that would block. Drain respects
PodDisruptionBudgets and waits for them within the target's step timeout; there
is no bypass. DaemonSet pods stay. A pod with local storage or without a
controller blocks the drain: the report lists it under `blocked` with reason
`pdb`, `local-storage` or `unmanaged`, the member stays cordoned, and you move
or scale the workload, or delete the unmanaged pod, then drain again, or run
`node uncordon`. A member with more than 128 pods cannot be drained; see the
[pod cap](k3s-operations.md#member-maintenance-limits).

Draining the writer's member moves the
[registry writer](k3s-registry.md#move-the-writer). The plan reports
`writer_move` and an `approval`, and the drain refuses
`approval-required` without it:

```sh
BROIL_ENV=lab broil k3s plan demo --action node-drain --member server-1 --observe --format json
BROIL_ENV=lab broil k3s node drain demo server-1 --approve "$APPROVAL" --format json
```

When no other member is Ready,
uncordoned and in sync to take the writer, as on a single-member target, the
drain refuses `no-writer-candidate`.

### Remove a member

Removal needs a drained member and an unchanged declaration:

```sh
BROIL_ENV=lab broil k3s plan demo --action node-remove --member agent-5 --observe --format json
BROIL_ENV=lab broil k3s node remove demo agent-5 --approve "$APPROVAL" --format json
```

Removal deletes the Kubernetes node, removes a server's etcd member, stops K3s,
the replication service, the reader and the local token service on the member,
removes its replication device from every other member, and rebinds every
surviving member's host claim to the new member set. It keeps the member's
data, replica directory and host claim on its machine. The report's `removed`
lists `done`, `not-run` or `not-applicable` for each effect.

The member stays declared and is recorded as removed. `status` reports it as
`removed`; `create` and `reconcile` skip it and never rejoin it; releases no
longer require it and report it under `excluded`. A removed member that comes
back with its K3s unit still enabled registers its Node again, and every later
operation refuses `ownership` until you stop the unit or replace the member.

Removal refuses before recording when:

- the member still runs evictable pods (`not-drained`);
- removing a server would leave fewer than two healthy etcd voters (`quorum`):
  three servers may go to two only as the recorded step toward a replacement;
- another server is already recorded as removed (`second-server`): replace it
  first;
- the target has one server and the member is that server (`one-server`);
- `api.endpoint` or `registration_endpoint` is the member's own address
  (`configuration: declaration`).

Endpoints are fixed at creation. A server whose address is an endpoint can be
drained and uncordoned but never removed or replaced in that target. Declare
the endpoints as a DNS name or load-balancer address that you can repoint, and
any server can be removed and replaced; keeping that name pointed at a
remaining server is your responsibility.

### Replace a removed member

Replacement joins the machine that the member's declaration now names. Edit
only that member's `machine`, `node_ip` and `interface`, and declare the new
machine under `remote.machines`:

```yaml
members:
  # ...
  - machine: m7            # was m5
    role: agent
    name: agent-5
    node_ip: 10.10.10.107  # was 10.10.10.105
    interface: eth0
```

Then preview and replace:

```sh
BROIL_ENV=lab broil k3s plan demo --action node-replace --member agent-5 --observe --format json
BROIL_ENV=lab broil k3s node replace demo agent-5 --approve "$APPROVAL" --format json
```

Replacement prepares the new host, supplies its node registries, joins it (a
server's etcd member is added again under the same name), starts its
replication service, reader and local token service, waits within the step
timeout until its replica is in sync, rebinds the other members' claims and
records the new declaration. A server is replaced only onto a new machine
(`same-machine-server` otherwise). An agent may also return on its own machine
after repair, with an unchanged declaration, reusing its claim, replica and
data. Any other declaration change refuses `declaration`.

Replace one member at a time. Run `node replace` again until the
replacement succeeds. Finish it before you remove or replace another member,
and before you drain or remove the replaced member. Broil does not support a
second replacement, or maintenance of the replaced member, while a
replacement is unfinished.

The replaced node starts with no images. Deliver the active release again, so
that the member pulls and pins it; until then `release status` reports the
member without the active images, and a later `release apply` or
`release rollback` fails its delivery recheck:

```sh
BROIL_ENV=lab broil k3s release deliver demo "$RELEASE"
```

### Delete an agent's entry

After a recorded removal you may delete an agent's member entry from the
declaration instead of replacing it. `reconcile` accepts the deletion and
records one `rebind-declaration` operation. A member named in `registry.member`
or `infrastructure.ingress_members` cannot be deleted: configuration loading
rejects the dangling reference, and changing either list is a declaration
change that `reconcile` refuses. Replace such a member instead. Servers stay one
or three.

### Unreachable members

A member that answers on no owned route and whose Node is not Ready is
unreachable:

- An unreachable member other than the registry writer's cannot be drained
  (`transport: unreachable`). Remove it directly; the approved plan binds it as
  unreachable, and its host effects are reported `not-run`.
- The writer's unreachable member can be drained. The drain completes when every
  evictable pod is terminating and its controller's replacement is Ready on
  another node, within the step timeout; the report marks `unreachable: true`,
  and the writer move reports `loss_possible: true`.

Before the first effect, Broil checks again that the member is still
unreachable; a member that answers refuses `stale-approval`, and you plan
again. While the unreachability is checked, another member that is not Ready
in the agent view refuses `agent-view`, and a surviving server that is not a
healthy voter refuses `quorum`.

### One-server targets

On a one-server target the only server can be drained when another member can
take the registry writer, or when it is not the writer. It can never be removed
or replaced (`one-server`), because no quorum or join source would remain.

## Export administrator access deliberately

Export grants the existing administrator credential's privileges and expiry.
It is not a reduced role, renewal or revocable Broil session. You own the file,
its backups and every copy; deleting one file revokes none of them.

On the Linux controller, choose a new file below an existing private directory
owned by your user with mode 0700. All ancestors must be trusted, without
symlinks or untrusted write access. For this example, create a new directory
under your home, then export from the configured project root:

```sh
mkdir -m 700 "$HOME/broil-access"
BROIL_ENV=lab broil k3s access export demo --output "$HOME/broil-access/demo.yaml" --format json
```

Success reports `export.publication: published` after live verification and
atomic, durable publication of a complete 0600 file. Broil changes no default
context or environment and overwrites no existing entry. Repeating against that
file refuses. Expired or unsafe managed access is refused without raw fallback.
An interrupted export may leave protected temporary or final residue; inspect
`export.temporary_residue`, publication and recovery before doing anything else.
Cancellation is not proof of absence or secure erasure. The
[export reference](k3s-operations.md#export-administrator-access-deliberately)
describes custody and uncertainty.

## Storage loss and changed declarations

Every member holds a full replica of the managed registry, and one member, the
writer, accepts pushes. Losing a member leaves its content on every other
replica; losing the writer's member stops pushes until a drain moves the
writer, with possible loss of pushes that no other replica received. Node pulls
continue from every replica. [Run the replicated managed registry](k3s-registry.md)
explains the replicas, the writer move and their limits.

Losing every replica leaves the registry refusing until a later restore or
repair capability, and meanwhile only a new target provides a managed registry.
A changed registry declaration refuses until reverted; this version cannot
migrate the existing registry to the changed declaration.

A new target must use unclaimed hosts with no existing K3s data, configuration
or service, while retaining the base-provisioned pinned executable and profile.
Keep the old records. While the old target is declared, the new target shares
none of its API, registration or registry endpoint origins and no overlapping
storage. Removing the old declaration also ends inspection of its records.
The new registry starts empty: republish retained images, or rebuild content
that existed only in the old registry. It does not repair the old target.

Clearing busy cannot reopen a recorded failed creation. Neither a copied disk
nor a manual K3s snapshot restore has supported adoption; identity-preserving
restores may escape observation. These detection limits and refusal cases are
spelled out in [storage limits](k3s-operations.md#cases-the-storage-checks-do-not-cover).

For partial or Unknown work, inspect [local records](k3s-operations.md#read-local-records)
and use [observation-first operation recovery](k3s-operations.md#observe-before-considering-a-retry).
There is no force-clear, takeover or general repair command. Preserve records,
locks and private residue rather than trying to make an uncertain operation
look absent.
