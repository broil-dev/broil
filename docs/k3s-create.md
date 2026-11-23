# Create a K3s target

Use this guide to turn a prepared declaration into a Broil-owned cluster and
its declared infrastructure. Broil records which hosts, cluster identities and
service objects it owns, so later commands can observe the same resources and
refuse foreign or changed ones. Start with a declaration preview before making
any remote change.

This guide is for a Linux operator familiar with SSH and K3s. Run commands in
Bash on the Linux x86_64 controller where Broil is installed, from your configured
project root. The examples use environment `lab` and target `demo`; replace
both with your own declared names. The [source example](examples/k3s/README.md)
is an inspection example, not a ready-to-run cluster.

## Establish the target and its prerequisites

A **project** is the directory containing the selected `broil.yaml` or
`broil.yml`. An **environment** owns a remote machine inventory and named K3s
**targets**. A target describes one cluster; its **members** name machines in
that inventory and assign each a server or agent role. A target has one or
three servers. A managed registry is a separate service with its own storage
and ownership inside that cluster.

Decide these declarations before creation. Members, endpoint origins, registry
storage and credential references enter recorded identities. Editing them
later is not an in-place migration: Broil refuses changed ownership inputs.
An existing K3s installation cannot be adopted by deleting Broil's records.

Supply the following before continuing:

- **Matching executable and assets.** Use the Broil binary with its matching
  source-carried action profile and bootstrap index. This profile uses K3s
  `v1.36.4+k3s1` on Ubuntu 24.04, systemd, amd64 nodes. Base provisioning must
  supply the pinned `/usr/local/libexec/broil-k3s` executable and root-owned
  action profile. Broil verifies them; it does not install or replace them.
  Complete the manifest and independent online or bundle assets in
  [Prepare K3s hosts and bootstrap assets](k3s-bootstrap.md#what-you-supply).
- **Unclaimed, prepared hosts.** Meet every
  [host prerequisite](k3s-bootstrap.md#host-prerequisites), including canonical
  SSH access, explicit trust and privilege, cgroup/kernel setup, no active
  swap, sufficient capacity, correct clock, routes and free ports. Hosts must
  have no existing K3s data, configuration or service. Broil does not run an
  installer or generic `remote provision` for you.
- **A qualified lifecycle script.** The selected remote script must carry the
  matching `tools/k3s/protected-actions.py` body and the declared non-PTY
  privilege route. Replace the example's refusing script only after preparing
  both.
- **Names, network and storage.** Set the members' actual addresses/interfaces,
  API and registration endpoints, certificate names and non-overlapping
  pod/service CIDRs. For a registry, prepare its
  [storage parent on every member](k3s-operations.md#prepare-the-storage-member),
  [CA and endpoint](k3s-operations.md#prepare-the-endpoint), and
  [signer certificate](k3s-operations.md#prepare-the-signer-certificate), and
  open TCP and UDP port 22000 between members for its
  [replication](k3s-registry.md).
  The controller and nodes need their own DNS or hosts entries for the registry.
- **Protected values.** Put server/agent tokens, private-CA values, the signing
  key and principal passwords in the configured [secret store](secrets.md).
  A reference such as `{set: example/lab, key: server-token}` identifies a
  store-relative set and literal key, not the value. Follow the specific
  [signing-key form](k3s-operations.md#generate-the-signing-key) and
  [principal password form](k3s-operations.md#prepare-the-principal-passwords).
  Only private-CA issuers are active; remove the illustrative ACME issuer from
  your declaration before creating a target that would select it.

The `backup` mapping remains required because it is part of the configuration
identity. This version neither contacts that machine nor resolves its recovery
identity, and does not implement backup or restore. Keeping the mapping does
not promise compatibility with a later recovery implementation. Declare the
registry's maintenance principal too: adding it later changes ownership inputs.
Its installation is required; maintenance authentication and deletion are deferred.

For node registry entries, check the [file and value limits](k3s-operations.md#prepare-the-entries)
and [supported target sizes](k3s-operations.md#cases-node-registry-configuration-does-not-cover)
before creation. The schema's 128-member maximum does not mean every operation
fits that size. Node configuration also performs a controlled K3s restart.

## Preview the selected work

K3s commands require a nonempty, known `BROIL_ENV`, including when using
`--file`. The target name is resolved only in that project's selected
environment. A shell's `BROIL_ROOT` cannot redirect the selected project.

From the configured project root:

```sh
BROIL_ENV=lab broil k3s show demo --format json
BROIL_ENV=lab broil k3s plan demo --action create --format json
```

The first result shows the declaration. The plan lists the intended members,
resources, unopened asset paths and protected references. Neither command
acquires the referenced values, contacts hosts or creates operation state.
Generated identities and readiness are still unknown. Successful parsing is
not proof that hosts, assets or credentials are ready.

To select a file while working in another directory, replace the absolute
example path below with your project's file. Put `--file` before `k3s`:

```sh
BROIL_ENV=lab broil --file /srv/project/broil.yaml k3s plan demo --action create --format json
```

An optional observation adds recorded facts and current member ownership and
identity reads. It does not create an operation or inspect live component
readiness; unavailable observations retain their failure and exit 1:

```sh
BROIL_ENV=lab broil k3s plan demo --action create --observe --format json
```

## Create and read the result

**Restrict ingress reachability before creating a registry.** The TLS endpoint
is installed before token authentication. Stopping between endpoint creation
and the token switch can leave the reachable registry unauthenticated. An
Unknown operation can prolong that window until operator recovery, for which
this version provides no repair executor. Keep the restriction until you have
checked authentication; see the
[endpoint limits](k3s-operations.md#cases-the-endpoint-checks-do-not-cover).

Creation modifies every selected member: preparation, first server, ordered
server/agent joins, network, ingress, cert-manager, issuers, certificates,
registry and node registry configuration. Review the preview first, then run:

```sh
BROIL_ENV=lab broil k3s create demo --non-interactive --format json
```

Read `outcome`, each stage's calls and readiness, and `operations`. Exit 0
means every selected stage reached its own completion requirement. It does
not establish application health, an image pull or durable registry availability.
Some component readiness remains `unobserved`; the
[completion reference](k3s-operations.md#create-and-reconcile) explains each
stage. An operation ID identifies recorded work; it is not a credential or
permission to replay a write. Reports are bounded to one complete 1 MiB payload.

An unchanged repeat observes existing identities and continues only where the
owning operation permits it. It does not erase failed records or adopt foreign
resources. Once the cluster is published, use the narrower
[management guide](k3s-manage.md) for live reads and selected reconciliation.
To join a declared member individually, use the
[server](k3s-server-join.md) or [agent](k3s-agent-join.md) procedure.

## If creation stops

Keep the report and its operation IDs. The first interrupt stops scheduling
after the current call settles; a second cancels it under its existing clock.
Cancellation is not rollback, and a call already running can outlive the
command's scheduling timeout.

Inspect [local operation records](k3s-operations.md#read-local-records), then
follow the returned `recovery.choice`. `operation resume` observes the original
work; it does not replay lifecycle effects or clear an uncertain writer.
`operator-recovery` is a boundary, not an available force-clear command. Do not
delete locks or records to force a retry. A recorded failed registry creation
stays refused even after busy-state recovery.

Losing every registry replica has no supported restore in this version.
A changed declaration can be reverted, but a new target is a distinct cluster
on unclaimed hosts with separate endpoint origins and non-overlapping storage.
Keep the old records. See [storage loss and changed declarations](k3s-manage.md#storage-loss-and-changed-declarations)
before considering that path.
