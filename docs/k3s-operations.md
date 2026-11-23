# Inspect and recover K3s operation records

For a task path, start with [create](k3s-create.md),
[manage](k3s-manage.md) or [registry publish](k3s-registry-publish.md).
This page preserves the detailed operation and component reference.

Operation records explain what Broil intended, what it observed, and which
effects remain uncertain. They let you inspect an interrupted operation before
deciding whether to retry a supported metadata step.

Use `plan` to preview the declared work, `create` to prepare and join members
and install their infrastructure, and `reconcile` to observe and converge that
infrastructure on a published cluster. See [Create and reconcile](#create-and-reconcile).
Target and operation inspection, operation recovery, [ordered server joins](k3s-server-join.md)
and [agent joins](k3s-agent-join.md) are also available, as are
[member maintenance](k3s-manage.md#maintain-members) (drain, uncordon, remove
and replace), [application releases](k3s-releases.md) and
[history cleanup](#clean-up-operation-history). Backups, upgrades and
join-token maintenance belong to a later roadmap.
[Credentials and administrator access](#credentials-and-administrator-access)
explains the selected consumer commands and deliberate private export.
For current observations without recording or changing an operation, use
[Read live views](#read-live-views), including registry inspection.
The internal, CI-qualified `prepare-server-inputs` operation also appears here:
it prepares an inactive pair for a later server and does not join that server.
An additional-server join records `join-server`. Its prepared pair belongs to
that same operation; a prior `prepare-server-inputs` pair does not authorize it.
An agent join records `join-agent`; a `join-agents` batch records one operation
per selected agent and a durable gate before the next wave.
The internal `reconcile-network` operation records the fixed CoreDNS and
local-path resources after every declared member has joined. `create` and `reconcile` call it. Its record separates object installation from DNS
service and storage behavior. In `operation show` output, `readiness.services`
covers the six CoreDNS objects and `readiness.storage` the six local-path
objects. `not-ready` means at least one of those objects is missing, changed or
not owned by the operation, or the component's Deployment has no available
replica. `unobserved` means all six objects match and the Deployment is
available, but the operation has no live service-name or retained-volume proof;
it is also shown before any object observation. The network operation never
reports `ready`, so its record does not establish complete infrastructure
readiness for an application.
The internal `reconcile-ingress` operation installs Traefik on the members named
in the target's `ingress_members` and publishes it on their host ports 80 and
443, after every declared member has joined and the network resources above are
owned. `create` and `reconcile` call it. [Ingress records](#ingress-records)
explains what it creates, what an ingress member must provide, how to read its
readiness and which cases it does not protect.
The internal `reconcile-cert-manager` operation installs the pinned cert-manager
release, which issues the declared TLS certificates, after every
declared member has joined and the network resources above are owned. It does
not need Traefik; `create` and `reconcile` call it after ingress.
[cert-manager records](#cert-manager-records) explains what it installs, what it
checks and how to read its readiness.
The internal `reconcile-issuer` operation then makes Broil the owner of one
declared `private-ca` issuer, the cert-manager signer for your own CA.
`create` and `reconcile` call it for each declared issuer. [Private-CA issuer records](#private-ca-issuer-records)
explains what it creates, what to prepare and how to read its readiness.
The internal `reconcile-certificate` operation creates the cert-manager
Certificate of one declared certificate from its ready issuer and observes the
issued certificate. `create` and `reconcile` call it.
[Certificate records](#certificate-records) explains what it creates, how to
read its readiness and how to use the result.
The internal `reconcile-registry-storage` operation creates the declared
registry's retained storage, one replica directory on every member, and
observes them. `create` and `reconcile` call it. [Registry storage records](#registry-storage-records) explains
what it creates, what to prepare and how to read its readiness.
The internal `reconcile-registry-service` operation runs the registry's
writer, its one read-write Distribution, on the current writer's replica, and
the internal `reconcile-registry-replication` operation keeps every replica in
step and runs each member's local reader;
[Run the replicated managed registry](k3s-registry.md) explains them. The internal
`reconcile-registry-endpoint` operation then serves it over HTTPS through
Traefik on every ingress member's port 443, with the certificate that
`registry.certificate` names. `create` and `reconcile` call all three.
[Registry service records](#registry-service-records) and
[Registry endpoint records](#registry-endpoint-records) explain what they
create, what to prepare and how to read their readiness.
The internal `reconcile-registry-auth` operation makes Broil the owner of the
registry's token-signing key; its first call records three operations, which
create, supply and activate the key. The internal `reconcile-registry-token`
operation then runs the token server and switches the registry to token
authentication, after which every push and pull is refused until the declared
principals are installed: `reconcile-registry-auth`, once per principal,
supplies each principal's password, and a `reconcile-registry-token` stage gives
the token server their users and grants. `create` and `reconcile` sequence these calls.
[Registry signing-key records](#registry-signing-key-records),
[Registry token records](#registry-token-records) and
[Registry principal records](#registry-principal-records) explain them.
With principals installed, `broil image build` and `broil image publish`
publish to the managed registry; [Publish to the managed registry](#publish-to-the-managed-registry)
explains what to declare, what `readiness.publication` reports and the limits.
The internal restart restarts every declared member's K3s service once and
records one `restart-member` operation per member. It changes no configuration
and has no public command. [Controlled restart records](#controlled-restart-records)
explains its order, how to read a run and its limits.
Internal node registry configuration supplies each member's credentials for the
declared `node_registries` in `prepare-node-registry` operations, then writes
each member's K3s registry configuration and restarts it in the same order,
recording `configure-node-registries` operations. `create` and `reconcile`
include this controlled restart; [Node registry configuration](#node-registry-configuration) explains
what it writes, what refuses and how to change a credential.
Help topics for other planned commands describe the future command tree;
recognizing one of those commands does not enable it.

## Credentials and administrator access

Use these commands to check a particular credential consumer, apply its
supported changes, or deliberately save administrator access for another client.
A **consumer** is the component that uses a credential: administrator access,
infrastructure TLS, registry authentication, or node pulls. Each has separate
ownership and verification. A successful inspection does not prove that the
current secret-store value equals the installed value, or that an application
can pull an image.

Start with an existing [created cluster](#create-and-reconcile), its unchanged
target declaration and working trusted SSH connections. Broil uses its existing
managed administrator access and verifies the cluster and first-server identity.
It cannot refresh missing or expired access through these commands or fall back
to K3s's raw/default kubeconfig.

Run the examples from the configured project root. Replace environment `lab`
and target `demo` with your selection. Inspection reads public references and
the selected installed evidence without acquiring secret-store values for
comparison or creating operations:

```sh
BROIL_ENV=lab broil k3s credentials inspect demo --consumer admin --format json
BROIL_ENV=lab broil k3s access check demo --format json
```

`access check` exits successfully only after verifying the existing managed
access live. Inspect the report's `access`, `observations` and `failure` fields.
Live observations and recorded configurations have separate source/time labels.
An inspection can complete with known non-readiness; missing required evidence
produces a nonzero exit. Neither command writes a kubeconfig.

Choose reconciliation according to its effects:

| Consumer | Supported reconciliation |
| --- | --- |
| `admin` | Verification only, equivalent to `access check`; no supply, refresh or operation |
| `infrastructure-tls` | Reconcile declared private-CA issuers, then certificates; observing an active issuer does not apply edited source bytes |
| `registry-auth` | Reconcile signing, change every declared principal in name order, then install and verify the token configuration |
| `node-pull` | For each managed entry, change its node-pull principal, update token authentication, change every required node's configuration and perform the owned restart, then verify grants |

`registry-auth` creates new generations for active principals even if their
source values have not changed. There is no principal selector. Node-pull
reconciliation changes no publication or maintenance password. Old passwords
stop working when the verifier changes; new passwords may not work before that
point, and existing tokens can remain valid for 300 seconds. Prepare the
corresponding clients before changing credentials. Reconciliation does not edit
or sync the secret store and does not run its rotation protocol. Active signing
key replacement and active private-CA generation replacement remain deferred.

Preview the exact selected work before executing it:

```sh
BROIL_ENV=lab broil k3s plan demo --action credentials-reconcile --consumer node-pull --format json
BROIL_ENV=lab broil k3s credentials reconcile demo --consumer node-pull --format json
```

Without `--observe`, a preview reads declarations only. Adding `--observe`
adds bounded member/history observations without changing credentials. A
required external node-pull entry has no admitted grant verifier in this
version: the entire mutation refuses before acquiring values or making changes.
Inspection can still show its recorded facts and unknown access. Managed grant
checks use the installed publication/node-pull cohort; they never authenticate
as the maintenance principal and do not prove a production image pull.

For registry-only convergence, use `plan demo --action registry-reconcile`
followed by `registry reconcile demo`. The latter checks the existing cluster
and converges only registry storage, service, endpoint, signing, token and
principal configuration. It does not create members, change node credentials,
publish images, or perform backup/retention work.

During a registry or mutating credential sequence, the first interrupt stops
later scheduling after the current call settles. A second interrupt cancels
that call. A credential helper can still end on the first signal; inspect
partial results and the explicit recovery choice before another invocation.
Verification-only administrator reconciliation and other reads cancel on the
first signal. Cancellation does not prove an effect was undone.

A member operation (`node drain`, `node uncordon`, `node remove` or
`node replace`) refuses `readiness: admin-access` when its acting first server
has no published managed administrator access, which happens only after a
failed publication. Read that operation with `operation show` (or find it with
`operation list`), then rebuild the server: `node drain`, `node remove`, and
`node replace` onto a newly declared machine, whose join publishes the access
again. That path is refused on a one-server target (`one-server`), for a
server whose `node_ip` is the `api.endpoint` or `registration_endpoint` host
(`configuration: declaration`), and while another server is already recorded as
removed (`second-server`); there the recovery is recreating the target.

The acting first server is the first server in declaration order that is not
recorded as removed and has a published node UID, so a server under
replacement takes that role back only when its join publishes its UID. The
issuer and registry-auth Resources follow it: the removal of the acting first
server, or the replacement join that restores it, moves their `machine` to the
new acting first server in the same owner record, once. A generation
registered on the old machine but not yet active cannot be finished there, so
`node remove` of the acting first server, and `node replace` of a server that
precedes it in declaration order, refuse `busy: pending-generation` before
recording while such a generation exists, for example
`busy: pending-generation (registry-auth-object-signing is registered on node-1 but not active; run k3s reconcile edge first)`.
Finish that generation with the named reconcile first. Between a
replacement's `begin` and its join, the observation-only network, ingress and
cert-manager repeats refuse `readiness`, and views report those rows
unobservable; complete the replacement first.

### Export administrator access deliberately

Exported access carries the existing administrator credential's privileges and
expiry. It is a reusable private file, with no reduced role or Broil-managed
revocation/renewal. You are responsible for its use, protection, copies and
backups. Deleting one file does not revoke any copy. Export does not change
`KUBECONFIG`, the default context, or an existing file.

Choose a new destination under an existing, invoking-user-owned directory with
mode `0700`. Its ancestors must be trusted directories without symlinks or
untrusted write access; avoid shared temporary directories. For example, on the
Linux controller, create a new private directory under your home directory:

```sh
mkdir -m 700 "$HOME/broil-access"
BROIL_ENV=lab broil k3s access export demo --output "$HOME/broil-access/demo.yaml" --format json
```

Success requires a complete verified snapshot, atomic publication as a new
`0600` file, and durable filesystem checks. The report's `export.publication`
is `published` on success. Existing files and competing entries are preserved;
Broil creates no parent directory and chooses no alternate output path.

On failure, inspect `export.publication`, `export.temporary_residue` and
`recovery` before acting. An `unknown` publication or reported temporary may
still hold protected material. Keep it private and resolve the reported path;
do not assume cancellation removed it or retry over an existing file. An
expired, changed or unavailable remote access source refuses without exporting.
Filesystem calls may finish late; neither cancellation nor deletion guarantees
secure erasure.

## Create and reconcile

These commands operate on every member of one declared target. `create`
prepares hosts, creates the first server, joins additional servers in order,
joins agents in waves, then installs network, ingress, cert-manager, issuers,
certificates, the registry and node registry access. `reconcile` starts at
network; without a published cluster it asks you to run `create`.

Before executing, complete [host preparation prerequisites](k3s-bootstrap.md#host-prerequisites),
configure trusted SSH access and the pinned lifecycle profile, and supply the
referenced credentials, manifest and bundle. For a registry, also prepare its
[storage member](#prepare-the-storage-member), [CA and endpoint](#prepare-the-endpoint)
and [signer certificate](#prepare-the-signer-certificate). Restrict ingress
reachability during the [unauthenticated endpoint window](#cases-the-endpoint-checks-do-not-cover).
Only private-CA issuers are supported: a selected ACME issuer refuses before
any state, file or host inspection, naming the issuer and later roadmap.

From your configured project root, replace `lab` and `demo` with the selected
environment and target. First preview the complete intended resource list:

```sh
BROIL_ENV=lab broil k3s plan demo --action create --format json
BROIL_ENV=lab broil k3s plan demo --action create --observe --format json
```

The first command reads declarations only. It shows configured resource names,
credential references and unopened file paths; generated identities and live
readiness remain unknown. `--observe` adds separately labelled recorded facts
and current member ownership/identity reads. It creates no operation or lock
and does not inspect live component readiness. One unreachable member does not
hide the others; an incomplete observation exits 1. Neither preview issues an
approval digest. Join-only previews use `--action node-join --member NAME` or
`--action node-join-agents` and include no unrelated components.

Once the prerequisites and preview match your intended target, run:

```sh
BROIL_ENV=lab broil k3s create demo --non-interactive --format json
BROIL_ENV=lab broil k3s reconcile demo --non-interactive --format json
```

Exit 0 means every selected stage reached its stated ceiling. It does not
claim that all infrastructure behavior was tested. Host and membership stages
confirm their own preparation and membership contracts. Network services and
storage, ingress, cert-manager and issuers stop at `unobserved`; certificates
reach services `ready`; registry service reaches services/storage `ready`;
token service reaches services `ready` with publication `unobserved`. Node
registry configuration includes its own restart; no additional restart runs.
Read each component section below for what those results establish.

The report lists stages, affected members, exact operation IDs and each call's
separate evidence. Earlier registry service readiness remains visible after a
later token call. `recorded` counts distinct operations, including appended
attempts; `possibly_recorded` names uncertain publications. Use `operation show`
for full history. JSON and table carry the same facts, limited to one complete
1 MiB report; oversized output refuses instead of truncating evidence.

A readiness wait starts at 10 seconds and doubles to at most 60 seconds.
Each issuer waits at most 5 minutes; ingress, each certificate,
registry service and final token publication observation at most 10 minutes;
network, cert-manager and the token switch at most 15 minutes. Only a succeeded call
below its ceiling is re-observed, with two exceptions: a token switch waiting on
a previously succeeded create/configure, and, in `create` only, a network stage
refused with detail `settling` because Flannel, kube-proxy or the network-policy
controller is still starting on a member. Every member is inspected first, so
a route, capacity or other host problem on any member still refuses at once.
`reconcile` stops on that refusal at once. A component that never starts costs
the network stage its full 15 minutes and then stops with `waiting`,
`readiness` and detail `settling`. Any other expired wait stops with `waiting`
and `readiness`.

`operation_timeout` bounds new call and wait scheduling. A call already running
keeps its own full operation timeout, so the command can overrun by one call.
The first SIGINT or SIGTERM stops further scheduling and prints a notice while
the current call finishes, including its internal operations. A second signal
cancels that call. A signal after all required work finishes preserves the
result. A secret reader may independently stop on the first signal.

A stop exits 1 with one recovery choice: `create` for an unpublished reconcile;
`rerun` after fixing a known refusal, deadline or scheduling stop;
`credential-change` for its named credential; `resume` for Unknown metadata
preparation; or `operator-recovery` for other Unknown effects, ownership refusal
or store exhaustion. `none` means success. Keep uncertain records intact.
The current credential change and operator recovery may require functionality
that has no public command; the report does not authorize an implicit repair.

A repeat `create` observes existing installations and appends to completed host
preparation without retransferring assets. The original owner fixes the whole
declaration: changing a referenced path, member, endpoint, issuer or certificate
can refuse ownership even when the changed field belongs to a later stage.
A clean prerequisite refusal still fixes that declaration. Fix host conditions
without editing the target, then rerun.
If correcting the declaration requires a new target, its hosts must be unclaimed
and its endpoints and storage must not overlap another declared target's.
This version cannot replace the recorded owner in place.

Every recording call consumes one of the target's 16,384 operation records. A
converged reconcile records ten operations plus one per issuer and certificate
(twelve with one of each). Readiness re-observations add more. Nothing is
removed automatically; `operation prune` removes approved settled records (see
[Clean up operation history](#clean-up-operation-history)).

## Understand the record

A [target](k3s.md) is a declaration in one environment. An **owner** identifies
the particular installation recorded for that target. A matching target name
alone does not establish ownership of a machine or its data.

An **operation** retains its original request, including the complete member
selection. Each **attempt** has separate steps and dispatch identities. A retry
adds another attempt; it does not edit the original request or erase earlier
observations. Local and remote writer records exclude conflicting attempts.

**Unknown** means an effect or its cleanup has not been established. It is not
proof that nothing happened. A later matching receiver receipt can establish
current completion while the record still retains the earlier uncertainty.
Recorded success also does not prove that a cluster or service is healthy now.

The current command can also report uncertain local completion or cleanup when
it cannot observe file work finishing before its deadline. It preserves the
original failure and reports cleanup uncertainty separately. That uncertainty
does not create a historical receipt or authorize a new attempt.

## Ingress records

The `reconcile-ingress` operation makes Traefik reachable on TCP port 80 (HTTP)
and TCP port 443 (HTTPS) of every ingress member, and on no other member. It
creates three objects in the `kube-system` namespace:

- The HelmCharts `traefik-crd` and `traefik`. K3s's helm controller installs
  them after the operation, and Traefik then runs as a DaemonSet on exactly the
  ingress members. The operation imports the pinned Traefik image on each
  ingress member only and pins it there so the kubelet keeps it.
- The DaemonSet `svclb-traefik`, the ServiceLB workload. Its pods also run on
  exactly the ingress members and forward host ports 80 and 443 to the Traefik
  Service. They use the pinned `klipper-lb` image that K3s's bundled image
  archive already provides on every member, so nothing is pulled from a
  registry.

The ServiceLB pods restart until the Traefik Service exists and then forward to
it. HTTPS on port 443 presents Traefik's default certificate, because this
operation manages no certificates. Only the Traefik Service is published: a
LoadBalancer Service of your own stays unserved, because K3s's own ServiceLB
controller stays disabled. Existing host firewall rules are not replaced.

Traefik serves only Ingresses whose `ingressClassName` is `traefik`, and
Ingresses without a class whose legacy `kubernetes.io/ingress.class` annotation
is `traefik`. The class `traefik` is not the default, so Kubernetes never
assigns it to an Ingress without a class.

### Prepare the ingress members

The operation checks these conditions before it records anything, and refuses
when one fails. The failure class in parentheses tells you what to fix:

- No object that the operation would create, such as IngressClass `traefik`,
  already exists without Broil ownership (`ownership`).
- No original member is cordoned (`ownership` when the cordoned member is not an
  ingress member, `readiness` when it is).
- No process listens on TCP port 80 or 443 of an ingress member's host network,
  at any address (`ownership`). The ServiceLB forwarding would hide it, so
  Broil refuses instead. It never stops the process; stop or move it yourself.
- No pod other than the ServiceLB DaemonSet's declares TCP host port 80 or 443
  on an ingress member, in a container or a restartable init container, until
  the pod has finished (`ownership`). A pod that has succeeded or failed holds
  no port and does not count.
- No pod or controller revision in `kube-system` carries the label
  `app=svclb-traefik` unless the ServiceLB DaemonSet controls it (`ownership`).
  That DaemonSet would adopt and possibly delete it.
- Each ingress member forwards IPv4 traffic: `net.ipv4.conf.all.forwarding` is
  1 and `net.core.devconf_inherit_init_net` is not 2 (`readiness`). K3s sets
  the first to 1 on the hosts it runs on. The second makes each new pod network
  inherit that value, and the ServiceLB pods forward only when it does.
- Each ingress member's K3s image store holds the pinned `klipper-lb` image,
  which K3s's CRI reports as pinned (`readiness`). A record of that name with
  another image refuses `ownership`.
- Broil can read each ingress member's TCP socket tables `/proc/net/tcp` and
  `/proc/net/tcp6` (`integrity`). A member whose kernel boots with IPv6
  disabled, for example with `ipv6.disable=1`, has no `/proc/net/tcp6` and
  refuses; disabling IPv6 through sysctl keeps the table.

Ingress members must also not publish TCP port 80 or 443 through NAT rules
alone. Examples are Docker with `userland-proxy: false`, a Service's
`externalIPs` on a member address and a manual DNAT rule. Broil does not detect
such a publication, and it would compete with the ServiceLB forwarding. Docker's
default userland proxy holds a listening socket, which the listener check
refuses.

A later run applies the same checks. It also refuses when an object the
operation created was changed out of band, for example a widened ServiceLB node
affinity or an edited image, environment variable or port. Broil never repairs,
replaces or deletes such an object.

### Read the ingress readiness

For this operation `readiness.services` is `not-ready` while any of these holds:

- a HelmChart, the ServiceLB DaemonSet or an installed object is missing,
  changed, not owned or still installing;
- Traefik or ServiceLB does not run on exactly the ingress members with the
  pinned images;
- an ingress member is cordoned, a listener or foreign host-port pod appeared
  on it, or a foreign object carries the ServiceLB label;
- an ingress member's Traefik image, `klipper-lb` image or forwarding is not
  ready.

An initial operation therefore usually reports `not-ready`, because the
installation finishes after it. Running the operation again only observes and
then reports the finished state. A record that stopped before it observed the
objects also reports `not-ready`. `unobserved` means everything matches but no
live routing proof exists; this version never reports `ready`.

### Cases the ingress checks do not cover

These limits apply; the cases distinguish observation gaps from repeat
refusals. Apart from NAT-only publications, they arise because Kubernetes
acts on the two DaemonSets without Broil once they exist:

- **NAT-only publications.** As described above, a TCP 80 or 443 publication
  through NAT rules alone goes undetected and competes with the ServiceLB
  forwarding.
- **Preemption after a pod goes missing.** If a ServiceLB pod goes missing
  while a lower-priority pod of yours takes port 80 or 443 on that member, the
  recreated ServiceLB pod preempts, that is deletes, your pod. The same can
  happen in the short window between the operation's last check and the first
  scheduling of the ServiceLB pods.
- **Adoption by label.** A pod of yours labeled `app=svclb-traefik` that
  appears after installation is adopted by the ServiceLB DaemonSet and may be
  deleted. A pod or controller revision in `kube-system` that matches the
  Traefik DaemonSet's selector, `app.kubernetes.io/name=traefik` together with
  `app.kubernetes.io/instance=traefik-kube-system`, is adopted once Traefik is
  installed and may be deleted. The operation does not check for such objects.
- **Full members.** The Traefik and ServiceLB pods need a free pod slot on each
  ingress member; kubelet's default limit is 110 pods per node. On a member
  without room, creating them, or recreating one later, can make the scheduler
  preempt a lower-priority pod of yours. Leave room for two more pods on each
  ingress member.

## cert-manager records

The `reconcile-cert-manager` operation installs cert-manager v1.21.2 from the
manifest that host preparation verified and staged on each member. It creates
the manifest's 47 objects once: the `cert-manager` Namespace, six
CustomResourceDefinitions (Issuer, Certificate and their companions), the RBAC
objects, three Services and Deployments (controller, `cainjector` and webhook)
and the webhook's two configurations. Each carries the labels
`broil.dev/managed-by: broil` and `broil.dev/component: cert-manager` and the
Broil ownership annotations.

Before creating them, the operation imports the controller, `cainjector` and
webhook images on every member and pins them so the kubelet keeps them. The
Deployments name each image by digest and never pull. The operation creates no
Issuer, Certificate or Secret and does not read the declared `issuers` or
`certificates`; issuing certificates belongs to a later version. cert-manager
then adds two leader-election Leases in `kube-system` and its webhook's serving
CA, the Secret `cert-manager/cert-manager-webhook-ca`, which Broil never reads.

### Prepare the cluster

The operation checks these conditions before it records anything, and refuses
when one fails. The failure class in parentheses tells you what to fix:

- The target's `infrastructure.cert_manager_version` is `v1.21.2`, the only
  version this release installs (`configuration`).
- None of the 47 objects exists yet, and neither do the Leases
  `kube-system/cert-manager-controller` and
  `kube-system/cert-manager-cainjector-leader-election` or the APIServices
  `v1.cert-manager.io` and `v1.acme.cert-manager.io` (`ownership`). Kubernetes
  registers such an APIService for any CustomResourceDefinition in those
  groups and removes it shortly after that definition is deleted, so wait for it
  to disappear before retrying.
- Each member still holds the bootstrap files its preparation verified, and
  its K3s runtime answers (`readiness`). An image record with one of the
  cert-manager names that points to another image refuses `ownership`.
- No earlier operation of the target is unresolved (`busy`).
- The selection fits the operation's message limits (`bound`); see the member
  count below.

A later run applies the same checks to the objects this operation created. It
refuses with `ownership` when one was changed out of band, for example an added
toleration on a Deployment, an extra RBAC rule or subject, or an edited webhook
entry. Broil never repairs, replaces or deletes such an object. Undoing the
edit clears the refusal, except on the three Deployments and the six
definitions: Kubernetes counts every change to their `spec` and never resets
that count, so any such change keeps the refusal even after you undo it. That
includes `kubectl rollout restart` and `kubectl scale`. This version provides
no recovery for that case.

### Read the cert-manager readiness

In `operation show` output, `readiness.services` is `unobserved` exactly when
all of these hold, and `not-ready` otherwise:

- all 47 objects are the ones the operation created, unchanged;
- the six definitions are established and each Deployment has its one pod
  available;
- the webhook answers: the Namespace and both webhook configurations are
  unchanged, both carry the injected CA, and a server-side dry run of a test
  Issuer passes the webhook. The dry run stores nothing;
- every member's three images are present and pinned.

The pods start and the CA is injected after the operation, so an initial run
usually reports `not-ready`; running it again only observes the finished state.
This version never reports `ready`, because no certificate has been issued.

If the reply of the create step is lost, `operation resume` can bind only the
Namespace to the operation. The other 46 objects then report `foreign`. Here
that means Broil cannot prove this operation created them, not that someone
else did. The record stays in `operator-recovery`; see
[Observe before considering a retry](#observe-before-considering-a-retry).

### Cases the cert-manager checks do not cover

These limits apply; a repeat can refuse even while a component keeps serving:

- **Pod placement.** The cert-manager pods tolerate no taints. They avoid
  members whose declared taints include `NoSchedule` or `NoExecute`, and if
  every member has one, readiness stays `not-ready`.
- **Unchecked fields.** On the Namespace, the ServiceAccounts, the RBAC objects
  and the Services, a field that the manifest does not set is not compared, for
  example a Service's `externalIPs`.
- **Built-in roles.** Upstream labels add cert-manager's read and edit rules to
  the built-in `view`, `edit` and `admin` ClusterRoles.
- **Secret access.** cert-manager's controller can read, write and delete every
  Secret in the cluster, and its `cainjector` can read every Secret. That
  includes later issuer and registry credentials. The Traefik chart installed
  by `reconcile-ingress` can also read every Secret.
- **Opt-in behavior.** cert-manager acts on objects that ask for it: an Ingress
  annotated `cert-manager.io/issuer` or `cert-manager.io/cluster-issuer` gets a
  Certificate, and a webhook configuration, definition or APIService annotated
  `cert-manager.io/inject-ca-from*` gets a CA injected. Broil adds no such
  annotation.
- **Admission webhooks of your own.** A webhook that denies Issuers, changes
  them or cannot be reached keeps readiness `not-ready`.
- **Replaced members.** The images live in each member's K3s image store. A
  member that a restore replaces or prepares again lacks them, and a later run
  refuses the changed member instead of importing them again. Importing them
  again belongs to a later roadmap's restore. Until then this target keeps
  refusing that repeat, although cert-manager may keep serving on members that
  retained its images. A new target is a separate supported setup: a distinct
  target (another name, environment or project) whose hosts hold no Broil claim
  and no existing K3s data, configuration or service, the pinned K3s executable
  and profile that [base provisioning](k3s-bootstrap.md#host-prerequisites)
  supplies still being required, and that, while this target stays declared,
  shares none of this target's endpoint origins (API, registration or managed
  registry) and no storage that overlaps this target's.
  [Cases the storage checks do not cover](#cases-the-storage-checks-do-not-cover)
  explains what the old target keeps.
- **Member count.** Each member adds a few hundred bytes to the operation's
  messages, so fewer than the 128 members that a declaration allows fit: 72
  with short machine, node and account names and no jump route, fewer with
  longer names or jump routes. Public `plan`, `create` and `reconcile` check a
  reference fit before effects, using 36-byte node identities and the actual
  declaration. The post-join check still uses the real identities and can refuse
  `bound` after earlier stages succeeded.

## Private-CA issuer records

A `private-ca` issuer lets cert-manager sign certificates with a CA you
provide, for example for the registry endpoint in a later version. The
internal `reconcile-issuer` operation sets up one declared issuer and reports
whether cert-manager accepts it; it issues no certificate itself
([Certificate records](#certificate-records) covers issuance). Its first call
records three operations:

1. `reconcile-issuer` creates the issuer Secret `cert-manager/broil-input-…`,
   Opaque with no data and labeled `broil.dev/activation: inactive`, and
   registers it on the first server for Broil's protected credential consumer.
2. `prepare-state`, whose `request.consumer.action` is `supply-issuer-ca`,
   writes the declared certificate and key from the native secret store into
   the Secret as `tls.crt` and `tls.key`.
3. `reconcile-issuer` labels the Secret `active` and creates the ClusterIssuer
   `broil-issuer-…`, which signs requests from every namespace with that Secret.

Each later call records one `reconcile-issuer` operation that only observes or,
after a refused ClusterIssuer create, finishes it (see
[Read the issuer readiness](#read-the-issuer-readiness)). The name hashes derive
from the owner and the issuer, and each object read records both objects'
names, UIDs and classes in an `issuer-observation` event. Broil never replaces,
rotates or deletes either object in this version.

### Prepare the CA and the target

Choose the CA before you create the cluster, because the owner records the
whole declaration then:

- Declare every issuer before the cluster exists. An issuer added later refuses
  `ownership`, as every declaration change does.
- Declare no `acme-http01` issuer. A target that declares one, referenced or
  not, refuses `capability` before Broil reads a secret or contacts a member;
  this version cannot run ACME issuers.
- Use a CA dedicated to this cluster, with `pathLenConstraint` 0 and name
  constraints for the cluster's names. [Cases the issuer checks do not
  cover](#cases-the-issuer-checks-do-not-cover) explains why.
- Check that the key matches the certificate before the first call. A pair that
  does not parse or match fails the supply with `credential` and writes
  nothing, but the failure stays Unknown, credential steps cannot be retried,
  and the target then refuses later operations with `busy`. With the PEM files
  at hand, these two commands must print the same digest:

  ```sh
  openssl x509 -in ca.crt -noout -pubkey | openssl sha256
  openssl pkey -in ca.key -pubout | openssl sha256
  ```

The operation checks these conditions before it records anything, and refuses
when one fails:

- The issuer name is a declared `private-ca` issuer (`configuration`).
- The network resources and the cert-manager installation belong to this owner
  (`ownership`), and the latest `reconcile-cert-manager` operation reports
  `readiness.services: unobserved` (`readiness`); run that operation again until
  it does.
- No earlier operation of the target is unresolved (`busy`).
- The `cert-manager` Namespace is the one the installation created
  (`ownership`), and the ClusterIssuer definition is established
  (`readiness`).
- An object with one of the issuer's derived names is absent or is the one an
  earlier operation of this issuer created, unchanged (`ownership`). Do not
  create or edit `broil-input-` Secrets or `broil-issuer-` ClusterIssuers. An
  object Broil cannot read refuses `readiness`.
- Creating the ClusterIssuer needs at least 60 seconds: the target's step
  timeout, the lifecycle script's timeout and the operation's remaining time
  must each allow it (`bound`).
- The selection fits the operation's message limits (`bound`), as for the
  cert-manager installation.

A later call applies the same checks. It refuses with `ownership` when the
Secret or the ClusterIssuer was changed out of band, for example an added label
or annotation, an edited `spec`, an ownerReference or a finalizer. Broil never
repairs, replaces or deletes such an object.

### Read the issuer readiness

In `operation show` output, `readiness.services` is `unobserved` when the
ClusterIssuer reports `Ready` `True` for its current generation, and `not-ready`
otherwise. `Ready` means that cert-manager accepted the key pair, not that it
has issued a certificate, so the issuer operation never reports `ready`.

Each object read records the issuer's state and reason under `issuer.ready` in
its `issuer-observation` event; the latest one is current.

| `issuer.ready` | Meaning |
| --- | --- |
| `ready`, `observed` | cert-manager verified the key pair (condition reason `KeyPairVerified`). |
| `not-ready`, `rejected` | cert-manager rejected the pair, for example a certificate that is not a CA (`ErrInvalidKeyPair`) or a Secret without data (`ErrGetKeyPair`). |
| `not-ready`, `pending` | cert-manager has not reported on the ClusterIssuer's current generation, or reports `Unknown`. |
| `not-ready`, `absent` | The Secret is active, but no ClusterIssuer exists. |
| `not-ready`, `inactive` | The Secret is missing or not yet active, and no ClusterIssuer exists. |
| `not-ready`, `unobservable` | An object could not be read, or it was changed or created outside Broil. |

An admission webhook or policy can refuse the ClusterIssuer create, for
example a webhook of yours that matches ClusterIssuers but cannot be reached.
When Broil proves that the API server refused and stored nothing, the operation
ends `failed` with `readiness`, and neither `completion_unknown` nor
`cleanup_unknown` is set. The Secret stays active with its material. Fix the
webhook or policy and call again: the next operation only creates the
ClusterIssuer.

Every other failure after the operation is recorded stays Unknown, for example
a lost reply or a timeout, and the target refuses later operations, other
issuers' included, with `busy`. `operation resume` observes the objects
read-only. If the reply of the ClusterIssuer create was lost, resume reports the
ClusterIssuer `foreign`. Here that means Broil cannot prove this operation
created it, not that someone else did. The record stays in
`operator-recovery`; see
[Observe before considering a retry](#observe-before-considering-a-retry).

### Cases the issuer checks do not cover

These limits apply to the CA and cluster; the cases below distinguish
undetected changes from repeat refusals:

- **ClusterIssuer scope.** cert-manager approves every certificate request that
  names the ClusterIssuer, from any namespace, and the CA signs whatever the
  request asks for, including any DNS name or IP address and a CA certificate.
  Anyone allowed to create Certificates or CertificateRequests in any
  namespace, including holders of the built-in `edit` and `admin` roles, can
  therefore obtain a certificate signed by your CA. Unless your CA forbids it,
  that includes a subordinate CA, which could impersonate a registry endpoint
  to every client that trusts your CA. Hence the dedicated CA with
  `pathLenConstraint` 0 and name constraints.
- **CA constraints.** Broil checks only that the certificate and key parse and
  match. cert-manager checks the CA's constraints when the ClusterIssuer is
  created; an issuer it rejects stays `not-ready`, `rejected`. The supplied
  Secret cannot receive new material, because the consumer refuses an existing
  key, and this version cannot replace it.
- **Data keys.** Broil's read prints only the Secret's metadata, so a data key
  added to or removed from it after the supply goes unnoticed. A removed or damaged key
  shows only as `rejected`, once cert-manager reports it.
- **Unsettled failures.** Only a proven refusal of the ClusterIssuer create
  settles. A webhook that hangs ends in the API server's own refusal before
  Broil's 40-second client timeout and settles; a client timeout, for example
  from an overloaded API server, stays Unknown. An operation deadline that the
  earlier steps use up can leave less than 50 seconds for the create; Broil
  then does not start it, and the operation stays unresolved after the Secret
  was activated.
- **Settled history.** A settled failed or cancelled operation remains visible
  and permits a later call after its cause is fixed. Incomplete steps or
  completion/cleanup uncertainty still refuse `busy`. A clean host-prerequisite
  or foreign first-server refusal before reservation leaves unused steps,
  not an unresolved write. This does not authorize replay or erase the refusal.
- **CA rotation.** Changing the CA certificate or key in the native secret
  store after the supply has no effect and goes undetected; the Secret keeps
  the material it received.
- **Secret access.** As [described for cert-manager](#cases-the-cert-manager-checks-do-not-cover),
  cert-manager's controller and `cainjector` and the Traefik chart can read
  every Secret in the cluster, including the issuer Secret with your CA key.

## Certificate records

A declared certificate gives a service a TLS certificate for its declared
`dns_names`, signed by your CA through one of the target's `private-ca`
issuers. The managed registry endpoint consumes its selected certificate. The
internal `reconcile-certificate` operation handles one declared certificate, and
each call records exactly one operation:

1. While the certificate has no Certificate yet, the operation creates the
   cert-manager Certificate `cert-manager/broil-certificate-…`. It asks the
   issuer's ClusterIssuer for exactly the declared names, `duration` and
   `renew_before`. cert-manager then generates a private key in the cluster,
   has the CA sign it and writes the result into the Secret
   `cert-manager/broil-tls-…`. Broil never writes that Secret.
2. Every later call only observes the Certificate, the issued Secret and the
   ClusterIssuer.

Issuance takes a moment after the create, so the creating operation usually
records the certificate as still `pending`. Call again to observe the issued
certificate. The name hashes derive from the owner and the certificate name,
and each object read records the three objects' names, UIDs and classes in a
`certificate-observation` event. Broil never replaces or deletes the
Certificate or the Secret in this version. A Certificate deleted outside Broil
is not recreated: every later call for it refuses `ownership` before recording
anything, other certificates are unaffected, and this version has no way to
recreate it. If only the issued Secret is deleted, cert-manager issues the
certificate again. cert-manager also renews the certificate on its own; see
[Follow renewals](#follow-renewals).

### Prepare the certificates

The owner records the whole declaration when you create the cluster, so plan
the certificates first:

- Declare every certificate, with its `issuer`, `dns_names` and lifetime, before
  the cluster exists. A certificate added or changed later refuses `ownership`,
  as every declaration change does.
- Give each certificate a `duration` of at least `1h` and a `renew_before` of at
  least `5m`, cert-manager's minimums. A shorter value refuses `configuration`
  before Broil records anything, reads a secret or contacts a member. Without a
  value, `duration` is `2160h` and `renew_before` is `720h`.
- Use a CA that stays valid longer than the longest declared `duration`. A
  certificate that outlives its CA is issued anyway but reports `lifetime`.
- Declare no `acme-http01` issuer; a target that declares one refuses
  `capability`, as for issuers.
- Reconcile the certificate's issuer first, until its latest `reconcile-issuer`
  operation reports `readiness.services: unobserved`. Only the create needs
  that; later calls observe the certificate whatever the issuer reports.

The operation checks these conditions before it records anything, and refuses
when one fails:

- The certificate is declared and its lifetime meets the minimums
  (`configuration`).
- The network resources and the cert-manager installation belong to this owner
  (`ownership`), and the latest `reconcile-cert-manager` operation reports
  `readiness.services: unobserved` (`readiness`).
- No earlier operation of the target is unresolved (`busy`).
- The certificate's issuer is bound: its Secret is owned and its ClusterIssuer
  exists (`readiness`). For the create, its latest `reconcile-issuer` operation
  must also report `readiness.services: unobserved` (`readiness`), because an
  unready issuer cannot issue.
- The `cert-manager` Namespace is the one the installation created
  (`ownership`), and the Certificate and ClusterIssuer definitions are
  established (`readiness`).
- Before the first create, no Certificate and no Secret with the derived names
  exist (`ownership`). cert-manager would write into an existing Secret of that
  name, so do not create `broil-certificate-` Certificates or `broil-tls-`
  Secrets. The ClusterIssuer is the issuer's own, unchanged (`ownership`), and
  reports `Ready` (`readiness`). Creating the Certificate needs at least 60
  seconds: the target's step timeout, the lifecycle script's timeout and the
  operation's remaining time must each allow it (`bound`).
- The selection fits the operation's message limits (`bound`), for example a
  certificate with very many names.

Right before the create, the first server also checks that datastore encryption
is enabled, because the issued private key is stored there (`readiness`).

A later call applies the same checks, except the issuer's latest reconcile: the
call's own read reports the ClusterIssuer's state, so a still-valid certificate
stays observable while its issuer is not ready. It refuses with `ownership` when
the Certificate or the issued Secret was changed out of band, for example an
added label or annotation, an edited `spec`, a changed Secret type, an
ownerReference or a finalizer. Broil never repairs, replaces or deletes such an
object.

### Read the certificate readiness

In `operation show` output, `readiness.services` is `ready` when the latest
object read reports the certificate `ready` and the operation recorded no
failure, and `not-ready` otherwise. `ready` means that the Certificate is the
one Broil created, cert-manager reports it `Ready`, and the issued Secret holds
an unexpired certificate for exactly the declared names and lifetime whose CA
outlives it. It does not mean that anything serves the certificate or that its
next renewal will succeed, and the record's other readiness fields are
unaffected.

Each object read records the state and reason under `certificate.ready` in its
`certificate-observation` event; the latest one is current. While cert-manager
reports the certificate `Ready`, `certificate.issued` adds its UTC times:
`not_before`, `not_after`, `renewal_time`, when cert-manager renews it, and
`chain_not_after`, when the first of its chain's CA certificates expires. It
also adds `renewal`, the state of the next renewal (see
[Follow renewals](#follow-renewals)), and `last_failure_time`, when
cert-manager's latest issuance attempt failed, or `null`.

| `certificate.ready` | Meaning |
| --- | --- |
| `ready`, `observed` | The certificate is issued exactly as declared. |
| `not-ready`, `unobservable` | An object could not be read, or it was changed or created outside Broil. |
| `not-ready`, `issuer` | The ClusterIssuer does not report `Ready` for its current generation, and cert-manager does not report the certificate `Ready` either, for example before the first issuance. |
| `not-ready`, `absent` | No Certificate exists. |
| `not-ready`, `expired` | The issued certificate's `notAfter` has passed by the first server's clock. When cert-manager still reports it `Ready`, `certificate.issued.renewal` shows why it was not renewed. |
| `not-ready`, `rejected` | cert-manager's latest issuance attempt failed and the certificate is not `Ready`, for example because signing failed. cert-manager retries after a backoff. |
| `not-ready`, `pending` | Issuance has not finished, the issued Secret is missing, a status time cannot be read, or the Secret and the Certificate's status briefly disagree, as during a renewal. Call again. |
| `not-ready`, `names` | The issued names differ from the declared `dns_names`. |
| `not-ready`, `lifetime` | The issued lifetime differs from the declared one, or a CA of the chain expires before the certificate. |

An admission webhook or policy can refuse the Certificate create, for example a
webhook of yours that matches Certificates but cannot be reached. When Broil
proves that the API server refused and stored nothing, the operation ends
`failed` with `readiness`, and neither `completion_unknown` nor
`cleanup_unknown` is set. Fix the webhook or policy and call again: the next
operation creates the Certificate.

Every other failure after the operation is recorded stays Unknown, for example
a lost reply or a timeout, and the target refuses later operations, other
certificates' and issuers' included, with `busy`. `operation resume` observes
the objects read-only and can record the Certificate's UID from the create
receipt. If the create's reply was lost, resume reports a Certificate it may
have created as `foreign`, because Broil cannot prove this operation created
it. The record stays in `operator-recovery`; see
[Observe before considering a retry](#observe-before-considering-a-retry).

### Follow renewals

cert-manager renews each issued certificate on its own: at `renewal_time` it
issues a new certificate with a new private key into the same issued Secret.
Broil never triggers, retries or forces a renewal. It observes each one, so that
while the current certificate is still valid you can tell whether its renewal
will happen.

While a renewal fails or waits, cert-manager keeps the current certificate in
the Secret and keeps reporting it `Ready`, so the certificate stays `ready`
until it expires. Each object read reports the next renewal in
`certificate.issued.renewal`, the first of these states that applies:

| `renewal` | Meaning | What to do |
| --- | --- | --- |
| `issuer` | The ClusterIssuer does not report `Ready` for its current generation, so a renewal waits for it. | Repair the issuer, for example its CA material. The waiting renewal completes once the ClusterIssuer is `Ready`. |
| `failed` | cert-manager's latest renewal attempt failed, for example because signing failed; `last_failure_time` says when. cert-manager tries again after a backoff of one hour, doubling after each further failure up to 32 hours. | Repair the cause, then wait for the next attempt or start one with cert-manager's own tooling. |
| `overdue` | At least 300 seconds have passed since `renewal_time` and no renewal completed, for example because cert-manager's controller is not running. | Check cert-manager's controller and the Certificate's events. |
| `issuing` | A renewal is in progress. | Call again. |
| `scheduled` | The next renewal is due at `renewal_time`. | Nothing. |

A consumer that serves the issued Secret must serve each renewed certificate to
new connections. The pinned Traefik does this on its own when cert-manager
writes the Secret, without a restart; established connections keep the
certificate they started with.

### Use the issued certificate

The [registry endpoint](#registry-endpoint-records) serves the certificate
that `registry.certificate` names; nothing else in this version serves a
certificate. A client that trusts only the system's CAs refuses the
certificate. Give the clients you control your CA
file. `curl --cacert ca.crt` trusts it; on Debian and Ubuntu, curl also keeps
its compiled-in CA path. The following command trusts only your CA. Replace
`HOST` with the endpoint's address and `NAME` with one of the certificate's
`dns_names`:

```sh
openssl s_client -connect HOST:443 -servername NAME -CAfile ca.crt -no-CApath -no-CAstore -verify_hostname NAME -verify_return_error </dev/null
```

Without `-verify_hostname`, `openssl s_client` does not check the name.
Without `-verify_return_error`, it connects even when verification fails, so
check that it prints `Verify return code: 0 (ok)`. The `</dev/null` ends the
command after the handshake instead of waiting for input. `-no-CAstore` needs
OpenSSL 3.0 or later.

### Cases the certificate checks do not cover

These limits apply; the individual cases describe detection and refusal:

- **ClusterIssuer scope.** As [described for issuers](#cases-the-issuer-checks-do-not-cover),
  anyone allowed to create Certificates or CertificateRequests can obtain a
  certificate from your CA, including for this certificate's names. Broil's
  Certificate does not reserve them.
- **Secret adoption window.** The create refuses an existing Secret of the
  derived name, but for as long as the Certificate exists, cert-manager writes
  into any Secret of that name: one created between the check and its first
  write, or one recreated after the issued Secret was deleted.
- **Data keys.** Broil's read prints only the Secret's metadata and the two
  public certificates, never `tls.key`. A changed or removed key shows only
  through cert-manager's own checks and re-issuance.
- **Secret identity.** Broil recognizes the issued Secret by its annotations,
  which any writer of that Secret can copy, and not by its UID. A copy with
  matching annotations is indistinguishable from cert-manager's own write.
- **Lifetime.** cert-manager's CA issuer issues a certificate that outlives its
  CA. Broil reports it `lifetime` but does not prevent it, and clients stop
  accepting the certificate when the CA expires.
- **Renewal.** Broil reports each renewal's state but never triggers, retries
  or forces a renewal. After a failure, cert-manager's next attempt follows its
  backoff unless you start one with cert-manager's own tooling. cert-manager can
  keep reporting a certificate `Ready` after its `notAfter`, because it does not
  check it again when it expires; Broil reports such a certificate `expired`.
- **Damaged Secret.** Traefik keeps no last good certificate: when the issued
  Secret's `tls.crt` or `tls.key` is missing or cannot be parsed, it serves its
  default certificate for the name until the next good write. A failed renewal
  never writes the Secret, so the current certificate stays served.
- **Clock.** `overdue` and `expired` use the first server's clock. cert-manager
  renews by the clock of the node that runs its controller, so `overdue` can
  come early or late by the difference between the two clocks, and `expired`
  by the first server's own clock error. Host preparation requires synchronized
  clocks, but nothing checks them again later or compares two hosts' clocks.
- **Changed issuer CA.** If the issuer Secret's CA is changed outside Broil, the
  next renewal issues from the changed CA, and neither the issuer nor the
  certificate reports it. Clients that trust only your declared CA then refuse
  the renewed certificate. This version cannot replace a CA.
- **Serving.** Nothing serves the certificate until its consumer does, and only
  clients that trust your CA explicitly verify it.
- **Unsettled failures and settled history.** The issuer's two cases apply, and
  a refused Certificate create is a second kind of settled refusal.
- **Declaration changes.** A certificate added or changed after the cluster
  exists refuses `ownership`; this version cannot reconcile it in place.
- **Secret access.** As [described for cert-manager](#cases-the-cert-manager-checks-do-not-cover),
  cert-manager's controller and `cainjector` and the Traefik chart can read
  every Secret in the cluster, including the issued certificate's key. Broil's
  own read receives the whole Secret, key included, through the owned
  administrator access, although it prints only the public parts.

## Registry storage records

The managed registry keeps a full copy of its content on every member that is
not recorded as removed: one replica directory per member, so that the content
survives pod and node restarts and the loss of any one member. The internal
`reconcile-registry-storage` operation makes Broil the owner of those
directories before the registry service exists. Each call records exactly one
operation:

1. The first call creates the backing directory, the declared
   `registry.storage.path`, on every member. Each holds the storage-owner record
   `broil-storage.json` and the content root `data`, owned by user and group
   10000, which the registry's writer, its readers and the replication service
   run as.
2. A call after a [replacement](k3s-manage.md#replace-a-removed-member) onto a
   new machine creates the directory on that machine only.
3. Every other call only observes the directories and the nodes.

There is no PersistentVolume or claim: the writer and the readers mount a
member's content root directly. Each storage-owner record holds its directory's
identities and never changes; it is how a later roadmap's backups and restores
will recognize this storage. Broil never deletes, recreates or purges a
directory or its content. [Run the replicated managed registry](k3s-registry.md)
explains how the replicas stay in step.

### Prepare the storage member

The owner records the whole declaration when you create the cluster, so declare
the registry and its storage first. A registry declared or changed later refuses
`ownership`, and a changed path or capacity cannot be reconciled in place.

Choose a `registry.storage.path` outside the trees that K3s, kubelet and Broil
own and clean up: `/etc/rancher`, `/run`, `/var/lib/rancher`,
`/var/lib/kubelet`, `/var/lib/cni`, `/var/log/pods`, `/var/log/containers`,
`/var/lib/broil`, `/var/lib/broil-k3s-incoming`,
`/var/lib/broil-k3s-replication` and `/root/.broil`. A path equal to one of them
or inside one fails configuration loading in every environment. A path such as
`/srv/broil-registry/origin` works.

On every member, prepare the path's parent directory, but not the path itself:

- Every directory from `/` to the parent exists, is owned by root, is not
  writable by its group or by others, grants search to others, and none is a
  symbolic link. A world-writable directory such as `/tmp` and a closed
  directory such as a root-owned 0700 parent do not qualify.
- The parent is on an ext4 or btrfs filesystem with at least `capacity_mib` MiB
  available. Other filesystems, including xfs and tmpfs, are refused, because
  Broil identifies the storage by a filesystem id that only ext4 and btrfs keep
  across reboots.
- Nothing exists at the declared path; Broil creates it.

The operation checks these conditions on every member before it records
anything, and refuses when one fails. The failure class in parentheses tells
you what to fix:

- The target declares a registry (`configuration`), and the issuer of
  `registry.certificate` is not `acme-http01` (`capability`).
- The network resources belong to this owner (`ownership`), no earlier operation
  of the target is unresolved (`busy`), and every member has joined
  (`readiness`).
- The path is not in a reserved tree (`configuration`). Every ancestor is safe
  and searchable by user 10000 (`ownership`, naming the ancestor, its owner and
  mode and the failed requirement), the parent is present (`readiness`), and
  the filesystem and the free space suffice (`storage`).
- Nothing exists at the path on a member where it is created (`ownership`).
- Every member's node is Ready and not cordoned (`readiness`). Uncordon nodes
  before the call.
- Creating the directories needs at least 60 seconds per step (`bound`). A path
  whose record or messages cannot fit the operation's limits also refuses
  `bound`.

A later call applies the same node and ancestor checks. It refuses with
`ownership` when a directory was changed out of band: a changed owner, group or
mode (the content root may take any mode that gives others no access), an added
or missing entry, a replaced directory or a mount below the path.

### Read the storage readiness

In `operation show` output, `readiness.storage` is `ready` when the latest reads
find every member's directory as Broil created it and every member's node Ready
and not cordoned, and the operation recorded no failure. Otherwise it is
`not-ready`. It does not mean that the registry service runs, that the replicas
are in sync or that content persists; the
[replication's readiness](k3s-registry.md#read-the-registrys-state) adds each
replica's synchronization.

Each read records a `registry-storage-observation` event; the latest ones are
current. Each member's read reports its directory under `storage`: its `class`
(`absent`, `owned`, `owned-drifted`, `foreign` or `unobservable`), the `parent`,
`filesystem` and `available_mib` checks, and the record's hash and the
identities. The first server's read reports each member's node under `nodes`:
`ready`, `not-ready` (absent, not Ready or cordoned), `drifted` for a node with
another UID, or `unobservable`. A member recorded as removed is not read.

Every failure after the operation is recorded leaves it unresolved, and the
target refuses later operations with `busy` until operator recovery. That
includes a refusal right before an effect, although nothing changed, and a node
that turns NotReady or is cordoned during the operation. `operation resume`
observes read-only and never repeats an effect. See
[Observe before considering a retry](#observe-before-considering-a-retry).

### Cases the storage checks do not cover

The replica directories' limits are stated in
[Run the replicated managed registry](k3s-registry.md#limits): capacity on every
member, host-side changes, mounts, identity, filesystems, member loss, removed
and replaced members, relocation and resize, the runtime identity, ancestors,
failure after recording, other services' trees and declaration changes.

Some of those cases leave the registry refusing every later call. Undo the
cause where you can: revert a changed registry declaration, or undo an
out-of-band change to a directory, such as a mount at or below the path, a
changed owner, group or mode, or an added entry. Either clears the refusal; a
`busy` target first needs operator recovery. Otherwise, or to keep a
declaration change, only a new target gives you a working managed registry, as
[When the registry cannot recover](k3s-registry.md#when-the-registry-cannot-recover)
describes.

## Registry service records

The managed registry accepts pushes through one Distribution service, the
writer, on the current writer's [replica](#registry-storage-records). The
internal `reconcile-registry-service` operation makes Broil the owner of that
service. Each call records exactly one operation:

1. The first call imports the Distribution image that Broil pins into every
   member's container runtime and pins it there, so the writer and the readers
   can run on any member. The image comes from the bootstrap content already
   staged on each member; it is never pulled. Then the call creates five
   objects, in this order: the Namespace `broil-registry`, a NetworkPolicy that
   admits no ingress, the ConfigMap with Distribution's configuration, a
   ClusterIP Service on port 5000 and a Deployment with one replica that runs
   as user and group 10000 on the current writer's node and mounts its content
   root.
2. A call after a replacement onto a new machine imports the image on that
   machine only.
3. Every other call only observes the images, the five objects and the writer
   pod.

Broil records each object's UID before it creates the next one. It never
deletes, replaces or reconfigures an object or the image; only a
[writer move](k3s-registry.md#move-the-writer) changes the Deployment's replica
count and node, and only the [token switch](#registry-token-records) changes the
ConfigMap.

### Prepare the service

Declare the registry and its storage before you create the cluster, as
[Prepare the storage member](#prepare-the-storage-member) describes, with
`registry.version: v3.1.1` and `registry.image:
broil.invalid/candidate/distribution@sha256:ac52bec3025b9dc75a26112e076e3e0af646fbb40af67ae9f2fcd6465963b839`,
the build that Broil pins. The comparison is exact text: another version or
another spelling of the image refuses `configuration`. Then establish the
storage with its operation, and keep each member's bootstrap content as
prepared; it holds the Distribution archive whenever a registry is declared.

The operation checks, before it records anything:

- The storage operation's gates and your declaration (`configuration`,
  `capability`), and the network resources (`ownership`).
- Every member's replica exists and is recorded (`readiness`), and no earlier
  operation of the target is unresolved (`busy`).
- Each member that imports has an intact staged bootstrap generation that holds
  the pinned archive (`readiness`).
- The step timeout, each member's lifecycle-script timeout and the operation's
  remaining time allow the imports and creates (`bound`). About 660 seconds of
  operation time per importing member are needed at the default budgets; see
  the [operation timeout limit](#member-maintenance-limits).
- Every member's node is Ready and not cordoned, as for the storage. The images
  and the objects must be readable (`readiness`) and Broil's: another image
  under the pinned names, an object that someone else created or changed, or
  only some of the five objects refuse `ownership`.

### Read the service readiness

In `operation show` output the service reports two readiness fields:

| Field | `ready` when |
| --- | --- |
| `services` | All five objects are as Broil created them, the image is pinned on every member, and the writer pod is Running and Ready on the current writer's node. |
| `publication` | Never: the service reports `not-ready`. The [token operation](#read-the-publication-readiness) reports publication readiness. |

The service does not report `readiness.storage`; the storage and replication
operations do.

The first call can report `services` `not-ready`, with `process` `pending` or
`starting`, while the pod starts; a later call reports `ready`.

Each read records a `registry-service-observation` event. Each member's read
reports `generation`, `image` (`ready`, `conflicting`, `not-ready` or
`unobservable`), `runtime` and its storage fact. The first server's read reports
the five objects' classes under `objects`, the nodes, and the writer pod under
`process`. When `process` is not ready, its `reason` is the first of
`unobservable`, `stopped` (a writer move stopped it), `deployment` (the
Deployment is not Broil's as created), `absent` (no pod), `pods` (more than
one), `node` (on another node than the current writer's), `failed`, `pending`
(not scheduled or not started) and `starting` (running, not yet ready or
counted).

A failure after the operation is recorded leaves the target `busy` until
operator recovery, as for [the storage](#read-the-storage-readiness).

### Cases the service checks do not cover

The writer service's limits are stated in
[Run the replicated managed registry](k3s-registry.md#limits): reachability,
one writer, objects created once, deletion and uploads, images on every member,
restarts, failure after recording, adoption and image removal. In short, the
writer is plain HTTP inside the cluster and token-authenticated after the
switch, one pod with no high availability, and deleting its pod is the
supported restart; `kubectl rollout restart` and `kubectl scale` leave drift
that this version cannot recover from. Node pulls never depend on the writer:
each member's reader serves them from its own replica.

## Registry endpoint records

Clients reach the managed registry over HTTPS: through Traefik on each
declared ingress member's port 443, with the certificate that Broil issues and
renews for `registry.certificate`. The internal `reconcile-registry-endpoint`
operation makes Broil the owner of that endpoint once the
[registry service](#registry-service-records) exists. `create` and `reconcile` call it;
only the [token switch](#registry-token-records) adds authentication; see
[the endpoint's limits](#cases-the-endpoint-checks-do-not-cover). Each call
records exactly one operation:

1. The first call records the endpoint's origin, `https://HOST:443` for the
   catalog entry that `registry.endpoint` names. Then it creates three objects,
   in this order:
   - the NetworkPolicy `broil-registry/broil-registry-endpoint`, which admits
     Traefik's pods to the registry pod's port 5000 beside the service's
     deny-all policy;
   - the IngressRoute `cert-manager/broil-registry-tls`, which loads the issued
     certificate's Secret `cert-manager/broil-tls-…` into Traefik, so that
     Traefik serves it for the endpoint host. It does not copy the Secret, and
     its own route answers only the path prefix `/.broil-tls/`;
   - the IngressRoute `broil-registry/broil-registry`, which routes the endpoint
     host to the registry Service on Traefik's TLS entry point only, never on
     port 80.
2. Every later call only observes the three objects, the issued certificate and
   the TLS that each ingress member serves.

Broil records each object's UID before it creates the next one. It never
deletes, replaces, patches or reconfigures an endpoint object, a service or
ingress object or the issued Secret.

### Prepare the endpoint

The owner records the whole declaration when you create the cluster,
including the registry's catalog entry and its `ca` path. So, before you
create the cluster:

- Give the catalog entry that `registry.endpoint` names an explicit `ca` and
  port 443: write its endpoint as `https://HOST` or `https://HOST:443`, where
  `HOST` is one of `registry.certificate`'s `dns_names`. Adding `ca` or changing
  the port later refuses `ownership`, so a target created without `ca` cannot
  use the endpoint in this version.
- Make the `ca` file your CA's public certificate: the same certificate that
  you supplied as the issuer's `certificate` reference, never the issued leaf.
  This version exports no CA certificate. The file holds only PEM
  `CERTIFICATE` blocks with LF line endings, at most 4096 bytes each and 8192
  bytes in all, with nothing but blank lines around them. CRLF line endings,
  other text such as OpenSSL's `subject=` lines and other PEM blocks are refused
  here, although the registry helper accepts them.

Then establish the ingress on the declared `ingress_members`, cert-manager,
the issuer and `registry.certificate`, reconciled until its readiness is
`ready`, and the registry storage and service.

The operation checks, before it records anything:

- The service's gates and your declaration (`configuration`, `capability`),
  then the trust gate: no `ca`, another port, or a CA file that cannot be read
  or holds anything but the blocks above (`configuration`).
- The network resources (`ownership`); the service's six objects, cert-manager,
  the certificate and the ingress objects established (`readiness`); and no
  earlier operation of the target unresolved (`busy`).
- A first call needs the certificate's latest operation to report `ready`
  (`readiness`), at least 60 seconds per step and 260 seconds of the
  operation's time (`bound`).
- The three objects must be readable (`readiness`) and Broil's: an object that
  someone else created or changed, or only some of the three, refuse
  `ownership`. A first call also needs the issued Secret present (`readiness`).

### Read the endpoint readiness

In `operation show` output, `readiness.services` is `ready` when the three
objects are as Broil created them, the issued Secret holds the certificate,
and every ingress member serves that certificate, verified with only your CA
file, and Distribution answers `GET /v2/` through it. Any answer counts, so a
challenge after the token switch leaves the rule unchanged.
`readiness.publication` stays `not-ready`; the
[token operation](#read-the-publication-readiness) reports it.
`readiness.storage` stays `unobserved`; the
[storage operation's](#read-the-storage-readiness) is authoritative.

The first call can report `services` `not-ready`, with each member that is not
ready reporting `backend` or `untrusted`, while Traefik loads the new objects,
which takes seconds; a later call reports `ready`.

Each read records a `registry-endpoint-observation` event. `objects` holds the
three objects' classes. `issued` holds the issued certificate's `state`:
`present`, `deleted` (the Certificate was deleted outside Broil, or replaced by
one with another UID), `absent` (no Secret, or no certificate in it) or
`unobservable`, and the SHA-256 of the issued certificate. `served` holds one entry per ingress member, in
`ingress_members` order. When an entry is `not-ready`, its `reason` is the
first of these that applies:

| `reason` | Meaning | What to check |
| --- | --- | --- |
| `unreachable` | No connection to the member's port 443, or a TLS handshake that failed for another reason than the certificate. | ServiceLB and Traefik on that member, and the network path to it. |
| `untrusted` | The served certificate does not verify with your CA file, as when Traefik serves its own default certificate. | That the serving object exists and the issued Secret is intact. Compare your CA file with the issued Secret's public `ca.crt`. |
| `name` | A certificate from your CA for another name is served. | IngressRoutes or TLSStores that add a certificate for the host. |
| `stale` | Another certificate from your CA for the host is served. | A foreign route or certificate winning the host. Right after a renewal, call again: one observation can straddle it. |
| `unobservable` | The connection or the response did not complete in time, the member closed the connection or sent a response head over 16384 bytes, or your CA verified a certificate while the issued certificate could not be read or is missing. | Call again, then check the member, the issued Secret and the API server. |
| `backend` | The issued certificate is served, but Distribution did not answer. | The registry route, the endpoint's NetworkPolicy and the registry pod. |

To check a member yourself from a host with your CA file, replace `NODE_IP`
with the member's address and `HOST` with the endpoint host:

```sh
openssl s_client -connect NODE_IP:443 -servername HOST -CAfile ca.crt -no-CApath -no-CAstore -verify_hostname HOST -verify_return_error </dev/null
```

It prints `Verify return code: 0 (ok)` for a verified certificate.

A failure after the operation is recorded leaves the target `busy` until
operator recovery, as for [the storage](#read-the-storage-readiness).
`operation resume` observes read-only: it never records an object's UID or
repeats a create.

### Cases the endpoint checks do not cover

These limits apply; the individual cases describe detection and refusal:

- **No authentication of its own.** Until the
  [token service](#registry-token-records) switches Distribution to token
  authentication, any client that reaches an ingress member's port 443 can push
  and pull, whether or not it verifies the certificate: trusting your CA is the
  client's own check. `create` and `reconcile` pass through this window between
  endpoint creation and the token switch. A stop there leaves it open; restrict
  ingress reachability before starting. Unknown effects require operator
  recovery, so another call may not be allowed to finish the switch. Before
  the endpoint existed, nothing outside the cluster reached the service.
- **TLS ends at Traefik.** Traefik reaches Distribution over plain HTTP on the
  pod network. The endpoint's policy selects pods by label, so anyone who can
  create a pod in `kube-system` with the labels `app.kubernetes.io/name:
  traefik` and `app.kubernetes.io/instance: traefik-kube-system` reaches the
  registry pod's port 5000. The service's node-local reach is unchanged.
- **Issuer scope and foreign routes.** Anyone who can create Certificates can
  obtain a certificate from your CA for the endpoint's name, and any
  IngressRoute or TLSStore in any namespace can add a certificate or a route for
  the same host. Broil refuses neither; the observation reports `name`, `stale`
  or `backend` when one wins. A foreign IngressRoute with a longer,
  path-specific rule on the host, such as a ``PathPrefix(`/v2/REPOSITORY/`)``
  rule, wins for those paths only: `GET /v2/` does not detect it, and once the
  registry has authentication it would receive the credentials that clients
  send to those paths.
- **Port 443 and HTTPS only.** No registry route exists on port 80, where the
  host gets Traefik's `404`. The [ingress limits](#cases-the-ingress-checks-do-not-cover)
  apply, such as undetected NAT-only publications.
- **Renewal.** Traefik serves each renewed certificate to new connections
  within seconds, without a restart. Established connections keep their
  certificate, and an observation whose Secret read and handshake straddle a
  renewal reports `stale` once. The registry helper opens a connection per
  request, so a renewal between requests interrupts nothing. A damaged issued
  Secret makes Traefik serve its default certificate (`untrusted`). A
  Certificate deleted outside Broil leaves its Secret in place, so Traefik keeps
  serving the last certificate, which nothing renews; the observation reports
  `issued` `deleted` and `services` `not-ready`, and the certificate's own
  operations refuse `ownership`.
- **Clock.** A client whose clock is behind the issuing node's can briefly see a
  just-renewed certificate as not yet valid.
- **Certificate health.** The endpoint does not check the certificate's
  lifetime or renewals; the [certificate's readiness](#read-the-certificate-readiness)
  and [renewal states](#follow-renewals) report them.
- **Trust declared before creation.** Declare `ca` and port 443 before you
  create the cluster; afterwards the owner refuses the change with `ownership`.
- **CA file.** The file holds your CA's certificate, never a leaf, in the form
  that [Prepare the endpoint](#prepare-the-endpoint) describes. A larger bundle,
  CRLF line endings, other text or other blocks refuse `configuration`, even
  where the registry helper (up to 1 MiB) or the node-registry supply (up to
  256 KiB) accepts the file. A block that is not a certificate makes every
  member `untrusted`.
- **Secret reads.** Each observation reads the issued Secret with a template
  that prints only its type, UID and public certificate. The `kubectl` child
  still receives the whole Secret, `tls.key` included, from the API server, so
  its memory and the receiver's are crash residue.
- **Created once.** Any change of the three objects' labels, annotations,
  finalizers or spec is drift that refuses `ownership`, with no repair in this
  version; a later version that changes an object brings its own rule.
- **Failure after recording.** Any failure after the operation is recorded
  leaves the target `busy` until operator recovery. Recovery alone does not
  reopen creation: the planned records exist and an earlier request names them,
  so a later call refuses `ownership` until a later version's repair.
- **Budgets.** A first call refuses `bound` unless each step keeps at least 60
  seconds and the operation at least 260 seconds.
- **Deadlines.** The budget covers the creates, not the member-wide reads before
  them, so a nearly spent operation deadline can still stop a later create with
  `timeout` after the operation is recorded.

## Registry signing-key records

The managed registry will authenticate clients with tokens that a token server
signs. The internal `reconcile-registry-auth` operation takes the first step:
it makes Broil the owner of the key that you declare as
`registry.authentication.signing_key`, in three operations like an
[issuer's](#private-ca-issuer-records), once the
[registry service](#registry-service-records) exists:

1. `reconcile-registry-auth` creates the Secret `broil-registry/broil-input-…`,
   Opaque with no data and labeled `broil.dev/activation: inactive`, and
   registers it on the first server for Broil's protected credential consumer.
2. `prepare-state`, whose `request.consumer.action` is
   `supply-registry-signing`, checks the key's form and writes it from the
   native secret store into the Secret as `signing-key`.
3. `reconcile-registry-auth` labels the Secret `active`.

Each later call records one operation that only observes. A
`registry.authentication.profile` other than `docker-auth`, or no
`signing_key`, refuses `configuration` before anything is recorded. This
operation does not observe the [token server](#registry-token-records) that
reads the key, so `readiness.services` is `unobserved` for an active key and
`not-ready` otherwise, and never `ready`.

### Generate the signing key

The key must be one PEM block labeled `PRIVATE KEY`: an unencrypted PKCS#8 RSA
key of 2048 to 4096 bits without attributes, with or without one final line
feed. This command writes one to `signing.key`:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing.key
```

Before you create the target, store the file's content under the set and key
that `signing_key` names, with `broil secrets edit`
(see [Local writes and editor exposure](secrets.md#local-writes-and-editor-exposure)),
and [prepare its certificate](#prepare-the-signer-certificate). Then remove
`signing.key` or keep it protected.

The check refuses a PKCS#1 key (`BEGIN RSA PRIVATE KEY`), as older `openssl
genrsa` writes, and a PKCS#8 key with attributes, although the token server
could load them. This command converts such a key, `old.key`, to the accepted
form:

```sh
openssl pkey -in old.key -out signing.key
```

A refused key fails the supply with `credential`, Unknown, and the target then
refuses later operations with `busy` until operator recovery.

### Cases the signing-key checks do not cover

- **Anonymous until the switch.** This operation changes no endpoint or
  service object: clients reach the registry
  [as before](#cases-the-endpoint-checks-do-not-cover) until the
  [token service](#registry-token-records) switches Distribution.
- **Key content.** The check reads the key's structure, not its numbers. A key
  damaged inside its values passes and is activated; only the token server's
  load reveals it.
- **Declaration and store changes.** Declare the key before the cluster exists:
  a `signing_key` added or changed later refuses `ownership`. Changing the key
  in the native secret store after the supply has no effect and goes
  undetected. `broil secrets rotate` with any generator but `handler` stores a
  value that a later supply refuses.
- **No replacement or revocation.** This version cannot replace or revoke an
  active key; a later roadmap adds that. Until then a compromised key needs
  operator recovery. The active Secret keeps the key, every etcd snapshot
  carries it, an Unknown supply can leave it in the inactive Secret, and the
  registration record stays on the first server.
- **Secret access.** As [described for cert-manager](#cases-the-cert-manager-checks-do-not-cover),
  cert-manager and the Traefik chart can read every Secret, this one included.
- **Unsettled failures.** Every failure after an operation is recorded leaves
  the target `busy` until operator recovery; `operation resume` only observes.

## Registry token records

The internal `reconcile-registry-token` operation runs the registry's token
server and switches the registry to token authentication. It needs the
[endpoint](#registry-endpoint-records) and an active
[signing key](#registry-signing-key-records); `create` and `reconcile` call it.
The token server (the pinned cesanta docker_auth) signs tokens with the active
key; after the switch, Distribution accepts only tokens that verify with your
declared certificate. Every push and pull through the endpoint is then refused
until the [principals](#registry-principal-records) are installed.

### Prepare the signer certificate

Declare `registry.authentication.signing_certificate` beside `signing_key`
before you create the target: the path of a public PEM certificate for the
signing key, from the project root when relative. A path added or changed later
refuses `ownership`; a new file at the same path is supported. With the key
from [Generate the signing key](#generate-the-signing-key):

```sh
openssl req -x509 -key signing.key -subj /CN=broil-registry-token -days 365 -out signer.crt
```

The file must hold exactly one `CERTIFICATE` block for an RSA key. Broil checks
its structure, not its signature, dates or extensions. A missing file, another
block or an EC certificate refuses `configuration` before anything is recorded.

The realm and service come from the `token_service` of the registry's `push`
catalog entry, a password entry. The realm's path must be exactly `/auth` or
`/auth/token`, and the service must not contain `"` or `\`; otherwise every
call refuses `configuration`. Both are fixed when the target is created.

### What a call records

Each call records one operation per needed stage, in this order:

1. `create` imports and pins the `auth` image on the registry's member and
   creates five objects named `broil-registry-token` in `broil-registry`: a
   NetworkPolicy that admits only Traefik, a Secret holding the token server's
   configuration and your certificate, a Deployment, a Service and an
   IngressRoute for the realm's path.
2. `configure` replaces the certificate in that Secret when your file
   changed, then restarts the token pod.
3. `switch` adds the token configuration and your certificate to the
   registry's ConfigMap and restarts the registry pod. It follows only once the
   token server is ready, which shows that it loaded the certificate with the
   key; otherwise a later call switches.
4. `principals` writes the [principals'](#registry-principal-records) users
   and grants into that Secret and restarts the token pod.

One call records at most three of these. A call with nothing to change records
one observing operation.
`readiness.services` is `ready` when the five objects are owned, the key is
active, both pods are ready, the ConfigMap holds the switch, every ingress
member answers `GET /v2/` with the exact `Bearer` challenge and the realm with
the token server's refusal, and, once principals are installed, the
[grant check](#read-the-principal-readiness) passes. A call that switches
usually ends `not-ready` while the new registry pod starts; a later call reports
`ready`.
`readiness.publication` is `unobserved` when `readiness.services` is `ready`
with principals installed, and `not-ready` otherwise; see
[Read the publication readiness](#read-the-publication-readiness).

### Cases the token checks do not cover

- **Refused until principals.** Until the `principals` stage installs users, no
  token is issued, so every push and pull is refused, including from the
  registry member's own host.
- **Realm and service.** They come from the catalog's publication entry and are
  fixed when the target is created. Declare the same realm and service for
  every purpose of the registry: a client that expects another one refuses the
  challenge. Until principals are installed every request is refused anyway,
  whatever credentials or `token_service` a catalog entry declares.
- **A certificate for another key.** Before the switch, the token pod restarts
  and never becomes ready, so the switch waits; reissue the certificate for the
  signing key at the same path, and the next calls configure and switch. After
  the switch, another key refuses `configuration`: key replacement belongs to a
  later roadmap.
- **Renewal interrupts service.** A new certificate for the same key records
  `configure`, which stops token issuance until the new token pod is ready, then
  a repeat `switch`, which stops pushes and pulls until the new registry pod is
  ready and loses uploads in flight.
- **Certificate content.** A certificate that passes the structure check but
  that the token server cannot parse stops token issuance until you reissue it.
- **The restart window.** Between a change and its pod's restart, the old pod
  keeps serving the earlier configuration; Traefik answers 503 for a few seconds
  after it. A pod that started from earlier data stays until you delete it,
  which is the supported restart.
- **Routing.** A foreign IngressRoute with a longer rule for the realm's path
  receives its requests. Traefik reaches the token server over plain HTTP, and
  processes on the registry member reach both pods directly.
- **Interrupted changes.** An interrupted `configure` or `switch` whose change
  completed leaves the Secret or the ConfigMap unlike the records: after
  operator recovery, this operation and `reconcile-registry-service` refuse
  `ownership` until a later version repairs it.
- **Budgets.** `create` needs step and script timeouts of at least 60 seconds
  and, with the defaults, 1130 seconds of operation time; `switch` needs step
  and script timeouts of at least 70 seconds and 260 seconds of operation
  time, and `configure`, which evicts one token pod per replica member, 20
  seconds more of each for every member beyond the first. A deadline that the
  earlier reads consume can still stop a step with `timeout` before its
  change. Installed principals raise these figures; see [their budgets](#cases-the-principal-checks-do-not-cover).
- **Custody.** The token server is the key's first reader: the kubelet writes
  it to a memory-backed file on the registry's member, readable by the pod's
  group, and the token server holds it in memory; neither is covered by
  datastore encryption. The token server logs each failed login's username and
  source address, never passwords or tokens; once principals are installed, it
  also [logs each issued token](#cases-the-principal-checks-do-not-cover).

## Registry principal records

After the [token service](#registry-token-records) switches the registry,
clients need principals. A **principal** is one entry under
`registry.authentication.principals`: a name, which becomes the token server's
username, a `purpose`, a `password` reference and the repositories it may use.
Each purpose has fixed actions: `publication` pulls and pushes, `node-pull`
pulls, and `maintenance` pulls and deletes. Broil installs the principals in
two internal steps that `create` and `reconcile` sequence:

1. For each principal without an installed password, in name order, the
   [signing key's](#registry-signing-key-records) three operations run, each
   only when needed: `reconcile-registry-auth` creates and registers an
   inactive Secret `broil-registry/broil-input-…` for the Resource
   `registry-auth-object-principal-<name>`; `prepare-state`, whose
   `request.consumer.action` is `supply-registry-principal`, checks the
   password's form and writes it as `password`; and `reconcile-registry-auth`
   labels the Secret `active`. Once all are installed, a call only observes.
2. A `reconcile-registry-token` call then records the `principals` stage: on
   the first server it hashes each active password with bcrypt (cost 10),
   writes one user per principal and one access entry per declared repository
   into the token Secret's `config.yml`, and restarts the token pod.

### Prepare the principal passwords

Declare every principal, with its password reference and repositories, before
you create the target: a principal added, removed or changed later refuses
`ownership`. Store each password under its reference with `broil secrets edit`
(see [Local writes and editor exposure](secrets.md#local-writes-and-editor-exposure))
before the principals are installed. A password must be 1 to 72 bytes without a
NUL byte, bcrypt's limit, so encode at most 36 random bytes as hexadecimal or
at most 54 as base64. This command prints 64 hexadecimal characters:

```sh
openssl rand -hex 32
```

A value outside that form fails the supply with `credential`, Unknown, and the
target refuses later operations with `busy` until operator recovery. The Secret
is then abandoned, and a principal without an installed password refuses
`ownership` until a [credential change](#change-or-revoke-a-password) replaces
it. At most 8 principals, each with at most 64 repositories and a name of at
most 93 bytes, fit, and together they must fit the token operation's messages
even with the signing certificate and the catalog CA at their largest allowed
sizes; a larger declaration still validates, but its calls refuse `bound`
before anything is recorded.

### Read the principal readiness

A principal's `reconcile-registry-auth` operation reports `readiness.services`
`unobserved` once its Secret is active, as the signing key's does. The token
operation's `registry-token-observation` events add `principals`, each current
Secret's `class` and `activation` in name order, and `grants`, which only an
observing call fills. That call requests a token through the endpoint for each
installed `publication` and `node-pull` principal, asking for every action on
its repositories and for the catalog: `granted` means that the token carries
exactly the declared actions; `other` means any other answer; `unreachable`,
`untrusted` and `unobservable` mean a failed connection, TLS check or time
limit. Once principals are installed, `readiness.services` is `ready` only when
every grant is `granted`, so the call that records `principals` ends
`not-ready` and a later observing call reports `ready`. Broil never sends the
maintenance password; every token call checks in memory, on the first server,
that each user's stored hash matches its principal's password.
The principals' own operations report `readiness.publication` `not-ready`; the
token operation's becomes `unobserved` once the grants pass
([Read the publication readiness](#read-the-publication-readiness)).

### What the token server enforces

| Purpose | Granted on its repositories | Refused |
| --- | --- | --- |
| `publication` | `pull`, `push` | `delete`; every other repository; the catalog |
| `node-pull` | `pull` | `push`, `delete`; every other repository; the catalog |
| `maintenance` | `pull`; `delete`, which Distribution answers with 405 because deletion stays disabled | `push`; every other repository; the catalog |

A wrong, empty or unknown password, an unknown user and a request without
credentials get 401 at the realm and no token. Basic credentials whose query
names another `account` get 400. Distribution refuses with 401 a token requested
without a scope or for another repository, a token for another service, an
expired token and a token signed by another key. Nothing falls back to another
principal or to anonymous access. Each token is valid for 300 seconds.

### Change or revoke a password

Broil applies a stored password only when it installs or changes that
principal; it neither applies nor detects a later store change. To change one:

1. Roll back or clean up any `broil secrets rotate` of that key in progress,
   whose marker blocks the edit (see [Rotation and recovery](secrets.md#rotation-and-recovery)).
2. Store the new value with `broil secrets edit`, then, when a vault is
   configured, `broil secrets sync`, because the supply reads the vault first.
3. Choose the [public consumer](#credentials-and-administrator-access).
   `credentials reconcile demo --consumer registry-auth` changes every declared
   principal, even unchanged values, then installs token configuration and
   observes grants. There is no one-principal selector. For a managed node-pull
   password, use `--consumer node-pull` so node configuration and restart follow
   in the required order; it changes no publication or maintenance password.
4. Inspect the same consumer and confirm the selected installed grants are
   `granted`. These are installed-generation observations, not comparisons with
   the current store. Each active principal change records three operations for
   a new Resource `registry-auth-object-principal-<name>.<k>`, starting at 2.

`broil secrets rotate` cannot change these passwords: its `TRANSITION_READY`
state requires the token server to accept the new value while the old one still
works, and the token server holds one password per user. For the same reason
the change, which is also how you revoke a leaked password, has no overlap.
Until the `principals` stage's patch, the new value is refused and the old one
works; from then on the old value is refused, though tokens issued earlier stay
valid for up to 300 seconds, and no token is issued while the token pod
restarts. A `node-pull` principal's change refuses node pulls until the node
credential change gives every node the new value
([Change a node credential](#change-a-node-credential)). The old
value stays in the superseded Secret, and this version cannot remove a
principal's access entirely: removing a principal changes the declaration,
which refuses `ownership`, so only a new target drops it.

### Cases the principal checks do not cover

- **Plaintext passwords in the cluster.** Each principal Secret holds its
  password under datastore encryption; no pod mounts it. Its readers are the
  signing key's ([described there](#cases-the-signing-key-checks-do-not-cover)),
  whose key in the same namespace already gives them every grant. The token pod
  reads the hashes from a memory-backed file on the registry's member, outside
  datastore encryption, and every etcd snapshot carries both Secrets.
- **Residue and lifetime.** Superseded and abandoned Secrets, with any supplied
  password, and their registration records stay. Each change permanently adds
  about 300 bytes to the owner record's 65,536 and at least four operations to
  the target's 16,384 operation records, so the owner record allows fewer than
  256 changes. Deleting a
  superseded Secret before a later `principals` stage stops naming it makes the
  token Secret drift.
- **Deletion and the catalog.** Deletion stays disabled, so the maintenance
  principal removes nothing, and every principal is refused the catalog.
- **Credentials cross the realm route.** As the token section's
  [routing case](#cases-the-token-checks-do-not-cover) describes, Basic
  credentials reach the token pod over plain HTTP behind Traefik, across the
  cluster network when the ingress member is not the registry's member, and a
  foreign IngressRoute with a longer rule receives them. Each observing call's
  grant check sends the publication and node-pull passwords that way.
- **The token server's log.** It records each failed login's username and source
  address and each issued token's user, source address, scopes and claims,
  never a password or a token's signature; each observing call adds one line
  per checked principal.
- **Out-of-band changes.** The token server reloads `config.yml` at the
  kubelet's next volume sync, measured at 21 to 81 seconds, so an edit of the
  token Secret takes effect without Broil, and the next call refuses
  `ownership`. A principal Secret changed or deleted out of band makes every
  token call, a certificate renewal included, refuse `ownership` until undone.
- **The host's `crypt`.** The first server hashes with its Ubuntu 24.04 Python
  3.12's `crypt` module, which Python 3.13 removes; without it every token call
  with installed principals refuses `capability`.
- **Budgets.** With N principals, `principals` needs step and script timeouts of
  at least 76 + 2N seconds and 320 + 2N seconds of operation time; with
  principals installed, `configure` needs 76 + N and 320 + N, and `switch`
  74 + N and 300 + N. `principals` and `configure` add 20 seconds to each
  figure for every replica member beyond the first, one more token pod
  eviction.
- **Failure after recording.** As for the signing key, a failure leaves the
  target `busy` until operator recovery. After it, an interrupted `principals`
  stage whose patch completed refuses `ownership` until a later version repairs
  it, and a Secret whose creation, supply or activation failed is abandoned.

## Publish to the managed registry

Once the [principals](#registry-principal-records) are installed, the image
commands publish to the managed registry as to any other registry:
`broil image build` publishes each target whose output is a registry, and
`broil image publish` publishes content that an earlier build retained. The
[image guide](images.md) explains both commands; this section covers what the
managed registry adds. Publication is the image commands' own work: no K3s
operation runs during it, and it changes no K3s record.

### Declare the publication entry

The `registries` entry that the registry's `endpoint` names is also the image
commands' publication entry. As in the [example project](examples/k3s/broil.yaml):

- its `ca` is your registry CA file, which replaces the system roots;
- its `push` names your `publication` principal as `username`, with that
  principal's exact `password` reference and repositories;
- its `push.token_service` names the realm and service of the
  [token server](#prepare-the-signer-certificate).

The **controller**, the machine where you run the image commands, resolves the
endpoint's host with its own resolver, and Broil adds no name resolution. Point
the host at an ingress member through your DNS or the controller's
`/etc/hosts`; with the example's ingress member:

```text
192.0.2.10 registry.example.test
```

Any [builder](images.md#declare-images-endpoints-and-credentials) outside the
cluster works: one on another machine, or an independently managed builder on
a member host. With a registry output the builder exports to the controller,
whose registry helper uploads; the builder never contacts the registry.

The image commands select declarations in the environment that `BROIL_ENV`
names, or in the root catalogs without it, while K3s operations use the
target's environment. Run them with `BROIL_ENV` naming the target's
environment, or keep the `registries` entry and the `secrets` configuration out
of that environment so that both read the root declarations. An environment
that the image commands select must match `[A-Za-z0-9][A-Za-z0-9_-]*`. Decide
before you create the target: its owner records the entry
([see below](#cases-publication-does-not-cover)).

### Publish and confirm

Declare an image whose repository the publication principal may push, here
with the example's entry `local` and a builder `shared` declared as the
[image catalog](image-catalog.md#example) shows:

```yaml
images:
  app:
    image: registry.example.test/team/app:v1
    builder: shared
    registry: local
    context: app
    platforms: [linux/amd64, linux/arm64]
```

Then build it from the project root:

```sh
BROIL_ENV=lab broil image build --target app --builder shared --format json
```

The command exits 0 only when every registry target is published: the helper
uploaded each blob that the registry lacked and every manifest, wrote the tag,
then read every object of the **closure** (the index, each platform's manifest,
configuration and layers) back by digest and the tag back to its root. That
readback is the publication's proof. To publish retained content without
rebuilding, see [Publish retained content independently](images.md#publish-retained-content-independently).

### Read the publication readiness

In `operation show` output of a `reconcile-registry-token` operation,
`readiness.publication` is `unobserved` when principals are installed and
`readiness.services` is `ready`, and `not-ready` otherwise. `unobserved` means
that the operation's final read, after the switch and without a failure, found:

- the token server's five objects owned, the signing key owned and active, and
  the token server ready;
- the registry's ConfigMap switched and the registry ready;
- every ingress member answering `GET /v2/` with the exact `Bearer` challenge
  and the realm with the token server's refusal;
- every `publication` and `node-pull` principal's grants `granted` through the
  first ingress member, the publication principal's `pull` and `push` included.

It never becomes `ready`: only an upload with its readback proves publication,
and each publication's own result is that proof. Broil writes no test image to
check. `unobserved` covers neither storage readiness, which the
[service](#read-the-service-readiness) reports, nor capacity, which is checked
only when the storage is created, nor the controller's path to the endpoint,
nor the [attempt bound](#fit-each-attempt-in-30-seconds). The other registry
operations report `not-ready`, and the storage operations `unobserved`.

### Recover an interrupted publication

A publication whose result is not established is Unknown: the command prints
`indeterminate` and exits 1. [`broil image resume`](images.md#observe-an-interrupted-operation)
observes it without sending a registry request and keeps requiring your
decision. To decide, publish again: `broil image publish` for retained content,
or a new build, because after a registry output the image commands release the
exported layout. A new publication skips each blob that the registry already
holds and reads everything back.

### Fit each attempt in 30 seconds

The image commands stop the registry helper once it has written nothing for 30
seconds, and the helper writes its result only when it exits. So each
publication attempt has 30 seconds from the helper's start, at any registry,
however its requests progress. Within them the helper hashes the local objects,
uploads the blobs that the registry lacks and every manifest, writes the tag,
then reads back every object of the closure, skipped blobs included, at the
controller's link rate to the endpoint.

An attempt that does not finish is Unknown, printed `indeterminate`, with class
`timeout`. Its completed blobs stay, so the next attempt uploads only the rest.
An attempt cut during its readback may already have moved the tag to the new,
unverified root, while no publication is recorded. Two cases never publish at
that link rate, through either command:

- a closure whose readback alone takes more than 30 seconds, though each
  attempt may still move the tag;
- a blob whose upload alone takes more than 30 seconds.

At 100 Mbit/s, 30 seconds move about 358 MiB, so a new image of about 179 MiB
fits one attempt, and a closure or a single blob of about 358 MiB is the most
that can ever publish. The image commands' largest closure, 4 GiB, needs about
1.15 Gbit/s even with every blob present, and their largest blob, 1 GiB, about
286 Mbit/s. These are upper bounds: hashing and requests take part of the 30
seconds. Publish large images from a controller with a fast path to an ingress
member, and give them a retained output so that `broil image publish` can repeat
without rebuilding.

Two more limits lie beyond the bound and apply only once a later version lifts
it:

- **The authorization window.** The token server's answers state no lifetime,
  so the helper treats each token as valid for 60 seconds and exchanges at most
  twice per attempt: a request that would start more than about 120 seconds
  after the first exchange fails `authentication`. At 100 Mbit/s this would
  admit a readback of about 1.4 GiB.
- **One request through Traefik.** Traefik's default read timeout cuts a request
  whose body takes more than 60 seconds to arrive, and the helper uploads each
  blob in one request, so a longer upload is cut and Unknown. At 100 Mbit/s
  this would admit a blob of about 715 MiB.

Lifting the bound needs a change to the registry helper or to how the image
commands supervise it; lifting the other two then needs a token server that
states a lifetime, another token rule in the helper, or other Traefik timeouts.

### Cases publication does not cover

- **No K3s checks.** The image commands never run the K3s agreement checks. A
  catalog without a matching `push` entry pushes anonymously, and the
  registry's challenge then fails the first request, which the command reports
  as `configuration`. A `push` entry naming a principal that cannot push makes
  the first refused write Unknown. Every K3s operation refuses such a catalog
  before any effect.
- **A store change alone.** A new publication password that you stored, and
  synced when a vault is configured, without the
  [credential change](#change-or-revoke-a-password) makes publication fail
  `authentication` while `readiness.publication` stays `unobserved`, because the
  grant check uses the installed password. After the change and the token
  operation's `principals` stage, publication succeeds.
- **In-flight uploads.** A registry pod restart, including the one after a
  signer-certificate change, loses an upload in progress; publish again as
  [above](#recover-an-interrupted-publication). A renewal of the endpoint
  certificate from the same CA interrupts no upload.
- **Residue.** An incomplete publication's blobs and abandoned upload sessions
  stay in the registry's storage: upload purging, deletion and garbage
  collection are disabled.
- **No deletion.** No publication is ever removed, and a moved tag's old root
  stays readable by digest.
- **Concurrent writers.** Nothing coordinates them: the last writer of a tag
  wins.
- **The entry is fixed.** The owner records the catalog entry when the target is
  created. Adding a repository or another purpose entry later makes each K3s
  operation refuse `ownership`, and `operation resume` report drift, until you
  revert it.
- **Custody.** Each upload acquires the publication password itself and passes
  it only to the registry helper's standard input; tokens stay in the helper's
  memory. Neither enters image or K3s records, command output or member files.
  The token server's log holds only what
  [the principal cases](#cases-the-principal-checks-do-not-cover) describe.

## Controlled restart records

The internal restart restarts the K3s service of every declared member of a
target exactly once, one member at a time, and observes each member ready
before the next one restarts. It records one `restart-member` operation per
member and has no public command. It changes no unit file, token or registry
file and never drains or cordons a node. [Node registry configuration](#node-registry-configuration)
uses the same order to make rendered registry configuration take effect,
because K3s reads that configuration when its service starts.

### What a run restarts

A **run** restarts every member of the target's original selection once, in
this order:

1. **Servers, one at a time, in declaration order.** Before each restart, every
   server must report a healthy etcd membership with the same voters and, on a
   target with agents, the first server must see every member present and
   Ready with its declared labels and taints. After the restart, Broil waits
   until the server's API, etcd and Node are ready and its Lease is renewed,
   then requires every server to report the same voters again before the next
   server.
2. **Agents, in declaration order and in waves of `agent_wave_size`.** The first
   server must see each restarted agent Ready with its declared labels, exactly
   its declared taints and a renewed Lease before the next agent restarts.
   After the last agent of each wave, the first server must again see every
   member present and Ready, and every server must report the same voters.

Each operation holds the writer on every member while it runs, so no other
operation changes the target meanwhile. Before it records anything, it checks
every member's ownership, its K3s service and its **start guard**, the check
that runs before every start of that service and stops the start when an
installed input has changed: an unreachable member refuses `transport`, a
service that is not running refuses `readiness` and a failing guard refuses
`ownership`. A refusal records nothing.

### Read a run

`operation list` shows one `restart-member` operation per restarted member. In
`operation show`, the `restart-recipe` event among the `observations`
identifies the run: `recipe.run` is the operation ID of the run's first
operation and `recipe.position` is the member's place in the order above,
counted from 0. Two `node-observation` events describe the restart: `kind`
`restart` names the unit's `previous_invocation` and its new `invocation`, and
`kind` `node` shows the facts observed afterwards and whether the member was
`ready`.

A succeeded operation takes `readiness.quorum` and `readiness.api` from the
check, after a server's restart or after a wave's last agent, that every server
reports the same voters. It takes `readiness.nodes` from the check after a
wave's last agent that the first server sees every member present and Ready;
on a target without agents, `readiness.nodes` repeats `readiness.quorum`. An
operation that did not succeed reports all three `unobserved`, even when some
of its reads answered healthy: only a succeeded operation completed and passed
its checks. Every other readiness an operation did not observe after its
restart is `unobserved`, and `services`, `storage` and `publication` always
are: a successful run does not show that the target's infrastructure is ready.

### Incomplete runs and Unknown operations

- **A refusal before a record**, such as an unreachable member or a deadline
  between two operations, leaves the earlier operations succeeded and the run
  incomplete: the latest operation's `position` is below the last member's. The
  next call continues the run at the next member while that operation is still
  the target's latest. After any other operation on the target, the next call
  starts a new run that restarts every member again.
- **A failure after a record**, such as a lost restart reply, a member that
  never becomes ready, a voter check that loses quorum or a deadline, leaves
  that operation Unknown with its writers held. `operation resume` observes it
  read-only and never restarts a member; no restart step can be retried, so the
  record stays in `operator-recovery` (see
  [Observe before considering a retry](#observe-before-considering-a-retry)).
  Every later operation on the target, including the next restart, refuses
  `busy` until operator recovery.

### Cases the restart does not cover

- **One-server targets.** Restarting the only server interrupts the API and
  the datastore while it restarts. Agents and their workloads keep running.
- **Start limiter.** The K3s service allows five starts in 300 seconds; a
  sixth stops it until the window passes or `systemctl reset-failed` clears
  the count. Broil adds exactly one start per member per run and never runs
  `reset-failed`; after a failed start, the service's own automatic restarts
  add starts until the limiter stops them. A member that crash-loops or is
  restarted too often fails `readiness` and leaves the target `busy`.
- **Supported size.** Every operation must fit its records in their size
  limits, and the restart checks this for the whole run before it restarts
  anything. With the reference sizes that Broil's own tests use, the largest
  target that fits has 25 members with one server and 20 with three, whatever
  the wave width; longer project paths, member names or routes, or a larger
  declaration, fit fewer. A declaration allows up to 128 members. A larger
  target refuses `bound`, so an outcome that needs every node restarted, such
  as node registry configuration, whose own [supported size](#cases-node-registry-configuration-does-not-cover)
  is smaller, is unavailable for it.
- **Store use.** A run uses one of the target's 16,384 operation records per
  member and, on every member, one of its 16,384 attempt records per operation.
  Repeated runs fill them until `operation prune` removes settled ones (see
  [Clean up operation history](#clean-up-operation-history)); a full store
  refuses new work, and a run that reaches that point part-way stays
  incomplete.
- **Not convergent.** Every successful run restarts every member once; a call
  after a complete run starts a new run.
- **Changes during a run.** A member whose unit fails, or whose guard inputs
  change, between the run's checks and its own turn fails its restart without
  effect, after the record, and the run ends Unknown.
- **Stalled reads and short deadlines.** A check that answers with an error,
  stalls on a restarting API past its read deadline or never sees the expected
  state after a restart leaves the operation Unknown and the target `busy`.
  Broil refuses `bound` before any record when the step or lifecycle-script
  timeout, or the remaining operation time, is under 70 seconds, but checks
  that consume an operation's deadline can still leave the restart under its
  60-second minimum; its `timeout` refusal then leaves the operation Unknown
  and the target `busy`.
- **Declaration changes.** Any declaration change after the target was created
  refuses `ownership` before anything is recorded; a run adopts no changed
  member, label, taint or wave width.
- **The registry writer.** Restarting the current writer's member restarts
  its K3s service with containerd and the kubelet, so pushes stop until the
  writer pod runs again; the content stays on every replica, and every other
  member keeps serving node pulls from its own replica, as
  [the writer's limits](k3s-registry.md#limits) describe.
- **Unguarded files.** Before every start, the guard checks only its own
  inputs. Other files that K3s reads at a start, such as
  [registry configuration](#node-registry-configuration), take effect without
  that check.

## Node registry configuration

Node registry configuration lets every member's K3s pull images from the
registries that the target's `node_registries` declares, with each entry's
username and stored password and, when its catalog registry declares a `ca`
file, that CA. K3s reads its registry configuration only when its service
starts, so Broil writes each member's configuration and then restarts the
member. `create` and `reconcile` sequence the install below; explicit credential
change remains internal:

- The **install** supplies each member's credential and trust for every entry
  that the member does not hold yet, then configures every member in one run.
- The **credential change** of one entry supplies a new credential and trust to
  every member, then configures every member in a new run.

Neither call contacts a registry, and neither proves that a pull works;
[Check that every node can pull](#check-that-every-node-can-pull) shows how to
check one member.

### What a call writes

A **supply** is one `prepare-node-registry` operation for one member and one
entry. It writes a new **generation**, an inactive input directory
`/var/lib/broil/k3s/owners/<owner>/resources/node-registry-<registry>/<generation>/`,
holding the password from the entry's reference, read from the vault first when
a vault is configured, and, when the catalog registry declares `ca`, that file's
bytes as `ca.crt`. A supply starts, restarts and stops nothing. The owner record
keeps one node-registry Resource per member and entry, naming its current
generation; a later supply replaces it in place. Supplies run in plan order:
servers, then agents, each in declaration order, and each entry in declaration
order.

A **configure operation** is one `configure-node-registries` operation per
member, in [the controlled restart's order](#what-a-run-restarts): a restart
operation with one more step, the **render**, immediately before the member's
restart. The render writes, on its member and in this order:

1. a **CA copy** of each entry that has a CA,
   `/var/lib/broil/k3s/owners/<owner>/node/node-registry-<registry>.<generation>.crt`,
   mode 0600;
2. the **host record** `/var/lib/broil/k3s/owners/<owner>/node/registries.json`,
   mode 0600, which names each entry's rendered generation and the one the file
   held before as `previous`; it holds no password or digest of one and no
   reply or record carries it;
3. `/etc/rancher/k3s/registries.yaml`, root-owned mode 0600, replaced
   atomically. For each entry, `mirrors.<key>` names the origin as its only
   endpoint, and `configs.<key>` holds `auth.username`, `auth.password` and,
   with a CA, `tls.ca_file` naming the CA copy. Every independent entry of the
   existing file is kept with the same value.

An entry's **key** is its catalog endpoint's authority as written: the lowercase
host, plus the port only when the endpoint writes one, such as
`registry.example.test` or `registry.example.test:5000`. Its **alias** is the
same host with the scheme's default port written out when the key has no port,
or without it when the key writes the default port. The file is JSON, which K3s
reads as YAML on servers and agents; Broil writes the characters that a YAML
reader refuses or folds, such as C1 controls and U+2028, as `\uxxxx` escapes.

### Prepare the entries

- Declare every `node_registries` entry before you create the target. Adding,
  removing or changing one later refuses `ownership`; only the stored password
  and the CA file's bytes can change. As in the
  [example project](examples/k3s/broil.yaml), each entry of the target's
  `node_registries` names a catalog `registry`, the `repositories` below that
  registry's endpoint that the nodes pull, and the `username` and `password`
  reference that the nodes send; its optional `fallback`, `disabled` by default
  or `same-origin`, renders the same entry in this version:

  ```yaml
  node_registries:
    - registry: local
      repositories: [registry.example.test/team/app]
      username: runtime
      password: {set: example/lab, key: pull-password}
  ```

  The managed registry's entry, whose catalog registry has the origin of the
  managed registry's `endpoint`, must name a
  [`node-pull` principal](#registry-principal-records) as `username`, with
  that principal's exact `password` reference and repositories; the example's
  `username: runtime` names its `runtime` principal. Broil refuses the
  declaration otherwise.
- Use HTTPS origins. An `http` origin, the key `docker.io`, whose containerd
  default endpoint is another origin, and the managed registry's entry without
  a catalog `ca` refuse `configuration`. At most 8 entries fit.
- Store each password under its reference with `broil secrets edit`. It must be
  1 to 4096 bytes without a NUL byte and without the bytes 0x01–0x07, 0x0B,
  0x0E–0x1F and 0x7F: K3s copies the password into containerd's configuration
  in a form that containerd refuses for those bytes, so Broil never renders such
  a value. A value outside 1 to 4096 bytes or holding a NUL fails its supply
  with `credential` after the record, which leaves the target `busy` until
  operator recovery. A value holding one of the other bytes is supplied, then
  refused by the run at its first member before any configure operation is
  recorded. Of `broil secrets rotate`'s generators, `hex:<n>` fits for n up
  to 2048 and `base64:<n>` for n up to 3072; check an `ssh-ed25519`, `prompt`
  or `handler` value's length and bytes. This command prints 64 hexadecimal
  characters:

  ```sh
  openssl rand -hex 32
  ```

  The managed registry's entry uses its `node-pull` principal's password, which
  [must be 1 to 72 bytes](#prepare-the-principal-passwords).
- Keep each declared CA file a readable regular file of 1 to 262144 bytes. A
  file that grows past that bound, becomes empty or becomes unreadable between
  a call's check and its supply fails that supply after its record, which leaves
  the target `busy` until operator recovery.
- For the managed registry, install the [principals](#registry-principal-records)
  first. A managed entry carries the node-pull principal's current generation;
  nodes configured before the principals were installed make the next install
  refuse `configuration`, and the target needs one credential change.
- Keep any entries of your own in `/etc/rancher/k3s/registries.yaml` in the
  JSON form that the next section describes.

Before recording anything, both calls refuse, in this order: a missing or
changed owner (`ownership`) or a member without its published node UID
(`readiness`); for the change, an unknown entry (`configuration`); more than 8
entries, or a CA file that the call would supply and that is empty or over
262144 bytes (`bound`), or that is not a readable regular file
(`configuration`); an `http` origin, a `docker.io` key or a managed entry
without `ca` (`configuration`); an earlier operation that is not settled
(`busy`); an append without the owner room (`bound`, see
[Cases node registry configuration does not cover](#cases-node-registry-configuration-does-not-cover));
configure operations that would not fit (`bound`); and a current generation
supplied for another node-pull principal generation (`configuration`, naming
`change_node_registry`).

### What an existing file may hold

Before each configure operation records anything, every member checks its own
generations and its `registries.yaml`, and each render checks again. A missing
file holds nothing. A present file must be a root-owned, single-link regular
file of mode 0600, and its JSON must decode into an object with only `mirrors`
and `configs`, each an object of objects, where each `mirrors` entry's
`endpoint` is a list of `http` or `https` URLs with a host. Broil cannot prove
what any other file means to K3s, so it refuses and leaves the file
byte-unchanged; the first matching row gives the class:

| File | Class |
| --- | --- |
| Over 65536 bytes; a string over 4096 bytes or holding a NUL; nesting over 16 containers; an object or list over 4096 members | `bound` |
| Not JSON, such as YAML; empty; a duplicate key; a number; `NaN`; a lone surrogate; a key over 1024 characters; a string holding a byte 0x01–0x07, 0x0B, 0x0E–0x1F or 0x7F | `ownership` |
| Not the object described above; an `endpoint` that is not a list of `http` or `https` URLs with a host | `ownership` |
| Another owner, mode, file type or link count; a symbolic link | `ownership` |

Each of these collisions also refuses `ownership`:

1. a `mirrors` or `configs` key equal to an entry's key or alias, compared
   without case and without a trailing dot, unless it is Broil's own rendered
   entry;
2. Broil's own entry changed by someone else (drift);
3. another `mirrors` entry with an endpoint on an entry's host, whatever its
   scheme or port, because containerd would send that endpoint the entry's
   credentials, over plain HTTP for an `http` endpoint.

A `*` entry never collides: an authority with its own entry does not use it. A
generation or CA copy that the host record names and that is missing refuses
`ownership`, as does a rendering that would hold one of the bytes above; a
rendering that would not fit 65536 bytes refuses `bound`.

### Read a configuration run

`operation list` shows the `prepare-node-registry` supplies and the
`configure-node-registries` operations. In `operation show`, a supply's first
observation is its `node-registry-supply` event: for the managed registry's
entry, `principal` is the node-pull principal's current generation as
`{id, generation}`, or null before the principals are installed; for an
external registry it is null. Its `inspection` event shows the new
generation inactive, and every readiness of a supply is `unobserved`.

A configure operation's `restart-recipe` event carries `run` and `position` as
a [restart's](#read-a-run) does, and `registries`, the member's entries: its
`registry`, its key as `authority`, `origin`, `username`, `fallback`,
`principal`, the rendered generation as `resource`, and `ca`, which says
whether a CA is rendered. The render adds a
`node-observation` with `kind` `configure`; the `restart` and `node`
observations and the readiness follow the restart's rules, and no readiness
reports a pull.

The recipe also names its run's **plan** as `recipe.plan_sha256`. The plan
covers every member's entries: a new generation of any entry, or a new
node-pull principal generation for the managed registry's entry, makes a new
plan. A plan is **configured** when one run, the operations sharing one
`recipe.run`, has a succeeded configure operation at every position with that
`plan_sha256`. The **current plan** is the one that the members' current
generations and the principal give now.

A later call picks the first case that applies:

1. The latest operation is a succeeded configure operation of the current plan
   before its last member: the call continues that run.
2. The current plan is configured: the install records nothing.
3. Another plan is configured and the current one never ran, as after a
   change's supplies whose run was refused: the install refuses
   `configuration`, naming `change_node_registry`. Run the change again.
4. Another plan is configured and the current one has a configure operation,
   as after an interrupted change's run and another operation: the call starts
   a new run, restarting every member, with no supply.
5. No plan is configured: the call starts a run.

A failure after a record leaves the operation Unknown and the target `busy`
until operator recovery, as for a [restart](#incomplete-runs-and-unknown-operations).
`operation resume` records `operator-recovery`, and `operation retry` refuses:
neither a supply's input preparation nor a render or restart is retried. A lost
render reply leaves the member's restart undispatched, so the member keeps its
running K3s, possibly with the new file not yet in effect.

### Change a node credential

Neither call notices a changed password or CA file. After changing either, run
the credential change for that entry. For the managed registry's node-pull
principal the order is:

1. Roll back or clean up any `broil secrets rotate` of that key in progress.
2. Store the new value with `broil secrets edit`, then, when a vault is
   configured, `broil secrets sync`.
3. From the configured project root, run
   `BROIL_ENV=lab broil k3s credentials reconcile demo --consumer node-pull --format json`.
   Replace `lab` and `demo` with your names. It changes each managed node-pull
   principal, installs token configuration, changes every required node's files
   and performs the owned restart, then observes grants, in that order.
4. Inspect `--consumer node-pull` and confirm the required installed grants and
   node configuration evidence. A complete change proves no production pull.

The change has no overlap, because the token server holds one password per
user. Until the `principals` stage's patch, the nodes pull with the old value;
from then on the old value is refused, though tokens issued earlier stay valid
for up to 300 seconds, until each node's restart under the node change. Pulls
can also fail on a member while the run restarts it, or while it restarts an
ingress member that a node reaches the registry through. In the other order,
each node is refused from its own restart until the `principals` stage. A new
value holding one of the bytes above is supplied but never rendered: the node
change refuses at its first member, and from the `principals` stage on the
nodes' pulls stay refused until you repeat the whole order with another value.
Check a value from `prompt`, a handler or an edit before you change it.

Public node-pull reconciliation refuses a required external entry without an
admitted verifier before effects. The lower-level external-entry change contract
still orders origin update, native edit/optional vault sync and node change;
this is not an available public-command procedure. Between the calls of an
incomplete install and during one change, do not change the stored value, the
vault's included, and keep the store
and the vault in agreement: nothing detects a difference, so members could
receive different values.

### Check that every node can pull

A configuration run proves that each member holds the rendered files, not that
it can pull: name resolution, the registry's endpoint, its token server and the
credential all have to work from the member itself. Broil's tests qualify node
pulls from the managed registry on a server and an agent, but Broil itself does
not pull on your nodes. To check a member, pull one published image by digest
with K3s's own CRI client, which uses only the configuration that Broil
rendered and sends no credential of its own.

Before you check:

- The member must resolve the registry's endpoint host itself, to an ingress
  member that serves the endpoint on port 443. Broil does not add the endpoint
  host to name resolution, on members or on the controller: use your DNS or the
  member's `/etc/hosts`.
- Pull one of the entry's repositories exactly as the entry lists it, such as
  `registry.example.test/team/app`: its first part is the entry's key, the
  catalog endpoint's host and port as the endpoint writes them.
  `registry.example.test:443/team/app` names another authority to
  containerd: it gets no credential or CA, and on a member whose
  `registries.yaml` holds a `*` mirror it goes to that mirror.
- Pull by the artifact's [root digest](images.md#use-a-recorded-artifact-in-a-runtime),
  never by a tag. `broil image record show <artifact-id> --format json` prints
  the artifact's record ([finding the Artifact ID](images.md#list-and-show-immutable-records)):
  its `root.digest` is the digest to pull, and its `platforms` list each
  platform's `manifest` and `config` digests.

On the member, with the root's digest, `sha256:` and 64 hexadecimal characters,
in place of `<digest>`:

```sh
sudo /usr/local/libexec/broil-k3s crictl pull registry.example.test/team/app@<digest>
sudo /usr/local/libexec/broil-k3s crictl inspecti -o json registry.example.test/team/app@<digest>
```

`/usr/local/libexec/broil-k3s` is the pinned K3s executable that your base
provisioning supplies ([host prerequisites](k3s-bootstrap.md#host-prerequisites)),
and its `crictl` talks to the member's own K3s containerd. The pull exits with
status 0 when it succeeds. `inspecti` then shows the image's `status.id`, which
is the record's config digest for the member's platform, `linux/amd64` on an
amd64 member, and `status.repoDigests`, which contains the reference you
pulled.

The following symptoms are examples, not an exhaustive diagnosis. Before
changing DNS or credentials, check the prerequisites above and whether a restart
or token change is still running. Without a configured host entry, first check
the exact authority and complete the required node configuration.

| The message includes | Cause | What to do |
| --- | --- | --- |
| `connect: connection refused` | The member resolves the endpoint host to an address where nothing serves port 443 | Fix the member's name resolution, or check that the ingress member it resolves to is running |
| `x509: certificate signed by unknown authority` | The reference does not start with the entry's key exactly, or the CA that the last run rendered did not issue the endpoint's certificate | Write the key exactly; after changing the CA file, run the [credential change](#change-a-node-credential) |
| `x509: certificate is valid for …, not <host>` | The reference names a host that the endpoint's certificate does not cover | Write the entry's key |
| `failed to fetch oauth token: … 401 Unauthorized` | The token server refuses the node's password, as after a principal change before the node change | Run the node change in the [order above](#change-a-node-credential) |
| `authorization failed: no basic auth credentials` | The reference went to a registry that has no credential for its authority, such as a `*` mirror, because it does not start with the entry's key | Write the entry's key |

While a run restarts members, or a principal change replaces the token server,
pulls can fail for a short time; check again after it ends.

The checked image stays in the member's containerd image store, because Broil
does not pull or remove node images. Remove it when you are done, unless a
workload on the member uses the same image:

```sh
sudo /usr/local/libexec/broil-k3s crictl rmi registry.example.test/team/app@<digest>
```

What this check and Broil's tests do not cover:

- **No delivery evidence.** A check records nothing: the image's evidence stays
  Built and Published. The pull does not make the image seeded or delivered to
  nodes, applied or healthy, and it does not show that the image stays
  available or that members share it.
- **Managed registry only.** Broil's tests qualify pulls from the managed
  registry. An external registry's entry is rendered the same way but is not
  qualified.
- **No kubelet credentials.** `crictl` sends no credential of its own, so this
  checks neither the kubelet's image-pull secrets nor its credential providers.
- **Platform.** An amd64 member pulls the `linux/amd64` image; Broil claims no
  arm64 execution.
- **Supported size and the cases below.** Above the
  [supported size](#cases-node-registry-configuration-does-not-cover) no member
  is configured, and the other cases below still apply.

### Cases node registry configuration does not cover

- **Supported size.** Two bounds apply and the smaller binds: each configure
  operation's records must fit, as a restart's must, and the 65536-byte owner
  record must hold the target's baseline, about 11 to 14.5 KB with the registry
  stack, about 1.5 KB per member with each replica member's two replication
  Resources, and one node-registry Resource of about 345 bytes per member and
  entry. With the reference sizes that Broil's tests use, the largest targets
  that fit are:

  | Entries | One server | Three servers |
  | --- | --- | --- |
  | 1 | 24 | 20 |
  | 2 | 22 | 20 |
  | 3 | 19 | 19 |
  | 4 | 17 | 17 |
  | 8 | 11 | 11 |

  With one entry the configure fit binds; from two entries with one server and
  from three with three servers the owner record does. Longer project paths,
  member, machine or principal names, and owner appends recorded before the
  install, such as earlier principal changes, fit about one member fewer where
  the owner record binds. A larger target refuses `bound` before anything is
  recorded, so its nodes cannot pull from a declared registry and a later
  password change cannot reach them. Declarations of up to 128 members stay
  valid.
- **The reserve.** A call that adds node-registry Resources also keeps owner
  room for 16 later principal changes, about 5.5 KB, because each
  [principal change](#change-or-revoke-a-password) permanently adds one
  Resource. A credential change replaces Resources in place and needs no room.
  An install that stopped part-way, at a deadline or a failure, becomes
  permanently `bound` if owner appends recorded before it completes take the
  room that its remaining supplies need: its supplies stay, and no run or
  change is possible.
- **Store use.** An install records one supply per member and entry plus one
  configure operation per member, and a change one supply and one configure
  operation per member; a change whose run is refused records its supplies
  again on the next attempt. At 24 members with one entry, an install takes 48
  of the target's 16,384 operation records and each change another 48, so a
  target that held K operations before the install allows (16384 - K - 48) / 48
  changes, rounded down, before the next operation refuses `bound: store-full`
  and `operation prune` must remove settled records. Each member also keeps at
  most 16,384 attempt records. Each supply
  contacts every member, so an install makes about 4,100 remote calls at 24
  members with one entry and about 7,100 at 11 members with eight, before its
  run. A deadline between supplies leaves them partial: the next install
  completes them, and an interrupted change is called again.
- **Every run restarts every member.** A run inherits the restart's
  [limits](#cases-the-restart-does-not-cover): the one-server interruption,
  the start limiter, changes during a run, stalled reads and short deadlines,
  and the registry writer.
- **Rendered but not applied.** A member can hold the new file under its old
  K3s: when its restart refuses without effect after the render, when the
  operation is cancelled between the two steps, or when the render's reply is
  lost; after a lost restart reply it is unknown whether the file took effect.
  The file then takes effect at the next start from any cause, such as a crash,
  a reboot or a later run, without the start guard's check. With a file that it
  cannot parse, K3s keeps its unit active but starts neither containerd nor the
  kubelet; with a file whose credential containerd refuses, K3s exits and
  restarts until systemd's start limit stops it. Broil writes neither itself,
  but it keeps an independent entry that K3s refuses for another reason, and a
  later edit can write either. Broil has no rollback: repair or remove the file
  and, for a unit that the start limit stopped, run `systemctl reset-failed`
  and start it.
- **Unguarded file and drift.** The start guard does not check
  `registries.yaml`, so an edit takes effect at the next start. A repeat after
  a complete run does not read the file; the next run refuses a Broil entry
  that someone changed.
- **Derived copies.** At each start whose file it can parse, K3s copies every
  `configs` entry's `auth`, password included, into containerd's
  `/var/lib/rancher/k3s/agent/etc/containerd/config.toml`, mode 0644 below the
  root-only `/var/lib/rancher/k3s`, and writes `certs.d/<authority>/hosts.toml`
  files with endpoints and CA paths but no credential. A start that cannot
  parse the file keeps the previous copy.
- **Node trust adds the CA.** containerd adds the CA copy to the node's system
  roots instead of replacing them, so a node also accepts a certificate for the
  entry's host that its system roots verify.
- **Token realms.** containerd answers each registry's authentication challenge
  itself, and Broil does not restrict the realm that an external registry's
  challenge names, so the password can reach a realm on another host.
- **Exact authority spelling.** containerd selects a registry's configuration
  by the image reference's exact authority. A reference that writes the default
  port where the key omits it, or omits it where the key writes it, gets no
  credential or CA, and a foreign `*` mirror applies to it.
- **Only the form is checked.** Broil checks an independent entry's form, not
  whether K3s or containerd accepts its values; one that they refuse stops the
  member at its next start, which a run's restart can be.
- **Residue.** Superseded generations, each holding its old password at mode
  0600 below the root-only owner directory, their CA copies, and a crash's
  temporary or two-link file in `/etc/rancher/k3s` stay until a later cleanup
  contract. A two-link `registries.yaml` refuses every later run until you
  remove the temporary name, and recorded generation files that you remove
  refuse that member's next run until restored.
- **No pull proof and no peer mirror.** A run proves the rendered files, their
  custody and the restart, never a pull; [check a member](#check-that-every-node-can-pull)
  yourself. A mirror's only endpoint is its own origin, so `fallback`
  `disabled` and `same-origin` render the same entries. Broil's tests show
  that with either value a member whose managed registry is unreachable does
  not fall back to a `*` mirror.

## Member maintenance limits

[Maintain members](k3s-manage.md#maintain-members) teaches drain, uncordon,
removal and replacement. These limits apply to them:

- **Member limit.** The owner record holds each member's entry and join inputs
  and, since replication, two registry Resources per replica member, beside the
  registry stack's baseline, the node-registry Resources and their reserve.
  Measured at the reference sizes that Broil's tests use, a member costs about
  1.5 KB of the owner record in all, and the largest supported targets are 24
  members with one server and 20 with three for one node-registry entry, where
  the configure fit binds, and fewer with more entries, as the table in
  [Cases node registry configuration does not cover](#cases-node-registry-configuration-does-not-cover)
  states. Above that size, every operation that appends to the owner record
  refuses `bound` before anything is recorded. Declarations of 1 to 128 members
  stay valid.
- **Operation timeout.** The registry service's and token service's `create`
  and `extend` stages import images on every replica member and need about 660
  seconds of remaining operation time per importing member at the default
  budgets. With the default 2-hour `operation_timeout`, more than 10 importing
  members refuse `bound` before anything is recorded. A larger target must
  raise `operation_timeout`, at most 24 hours, to cover those budgets.
- **Pod cap.** A member with more than 128 pods bound to its Node outside phases
  `Succeeded` and `Failed` cannot be drained. Its drain refuses
  `bound: size (<member> has <N> pods; the limit is 128)` before recording, or
  stops with detail `pod-cap` when the count grows past 128 during the drain,
  leaving the member cordoned with no pod evicted. Classification and naming
  read pods in pages of 70 and eviction runs in pages of 32. When more than 140
  evictable pods remain at a failed wait's bound, which needs pods that joined
  the cordoned Node, the report names the first 140, ordered by namespace and
  pod, and sets `truncated` true.
- **Operations in flight.** The unreachable-member exception covers only the
  drain or removal that binds it. An earlier operation that was running when a
  member became unreachable stays unresolved, and the target refuses `busy`,
  until `operation resume` observes that member again. While the member stays
  unreachable it can be neither drained nor removed, because both require
  settled history. Returning the member, or a later roadmap's operator
  recovery, ends this state.
- **Agent joins beside a removed server.** While a server is recorded as
  removed, no agent joins: a fresh agent join refuses `configuration`, and an
  agent replacement or a join repeat refuses `ownership`. Replace the removed
  server first. K3s itself would accept the join with two healthy servers; the
  limit is Broil's, whose join recipes carry three servers.
- **Joins after a first-server change.** After the declaration's first server
  is removed or replaced on a new machine, every agent join refuses
  `ownership`: `node join`, `node join-agents`, a repeat, and an agent
  replacement on a new or the same machine. A repeat of the first server's own
  replacement join refuses `ownership` too. `reconcile` and `node replace` of a
  server never repeat a join.
- **One replacement at a time.** Finish a replacement with `node replace`
  before you remove or replace another member, and before you drain or remove
  the replaced member. A second replacement, or such maintenance, while a
  replacement is unfinished is unsupported.
- **Removal pod wait.** `node remove` waits after deleting the member's Node
  until Kubernetes' pod garbage collection has deleted the pods bound to it,
  usually 60 to 80 seconds. A `step_timeout` below about 2 minutes can reach
  that bound, which leaves the removal unknown with its writers held, and the
  target refuses `busy`. Broil has no recovery for it, as for the removal's
  etcd-member and final-view waits.
- **Administrator access rebuild.** An acting first server without published
  managed administrator access is rebuilt by `node drain`, `node remove` and
  `node replace` onto a newly declared machine, as
  [Credentials and administrator access](#credentials-and-administrator-access)
  describes. That path is refused on a one-server target (`one-server`), for a
  server whose `node_ip` is the `api.endpoint` or `registration_endpoint` host
  (`configuration: declaration`), and while another server is already recorded
  as removed (`second-server`); there the recovery is recreating the target.

## Clean up operation history

Every operation, release and host attempt record stays until you remove it.
A target holds at most 16,384 operation records and 16,384 release records, and
each member at most 16,384 attempt records. Of those, 16 operation records and
16 attempt records per member are reserved for recovery: `operation resume`,
`operation retry` and an approved `release apply` that settles an unknown hook
may use them, other leaves may not. Nothing is deleted automatically.

### Watch the usage

Every K3s report that loads the target's state, `status` included, carries
`store`, for example:

```json
{"hosts":{"attempts":15790,"limit":16384,"member":"server-1"},"limit":16384,"operations":15812,"release_limit":16384,"releases":3817,"warning":true}
```

`hosts` is the fullest member as last recorded. `warning` turns true at 90% of
any cap. Before its first record, each lifecycle leaf checks that its whole
workflow fits outside the reserve: `release deploy` one release and two
operations, each deliver, apply, rollback and retain one operation, `node
replace` its phases, and `node join`, `node join-agents` and `credentials
reconcile` every operation their plan lists, each with one attempt record on
every member it selects. Without room it refuses
`bound: store-full (target edge holds 16383 of 16384 operation records and release deploy needs 2; run k3s plan edge --action operation-prune --observe)`.

### Preview and prune

`operation prune` removes approved settled records outside a retention policy.
Its default policy keeps the last 90 days, counted from the start of the
current UTC day, and the newest 500 operation records. Preview it, set
`APPROVAL` to the plan's `approval` digest, then prune with the same policy
options:

```sh
BROIL_ENV=prod broil k3s plan edge --action operation-prune --observe --format json
BROIL_ENV=prod broil k3s operation prune edge --approve "$APPROVAL"
```

`--keep-days` (1 to 3650) and `--keep-last` (100 to 16384) change the policy;
the plan and the prune must use the same values, because the approval binds
them. The plan's `prune` lists every removed and every kept record, untruncated,
with one reason per kept record, and its `summary` counts sum to `before`.
A record is kept for the first reason that applies:

| Reason | The record |
| --- | --- |
| `recovery` | Is not settled (an outcome other than succeeded, failed or cancelled, or completion or cleanup unknown), names a recovery choice other than none, or is one side of a settlement pair. |
| `cited` | Is named by the owner record (the writer, removed members, Resource and claim publications), by a current recipe origin, by a restart predecessor, a node-registry supply, a creation or join recipe, an agent wave, the preparations that create's checks read, an unfinished `node replace`, or a drain whose member is still cordoned. |
| `kept-release` | Belongs to a release whose record is kept. |
| `newest` | Is the newest settled operation of its family: its action with its member, release, application or consumer. |
| `policy` | Is inside the retention policy. |

A failed or cancelled outcome alone never makes a record removable. A release
record and all of its operations are removed together, and only when the
release is neither active, rollback nor staged, everything of it is outside the
policy, none of its operations is kept for recovery or citation, and its images
are no longer pinned: nothing was delivered, or a later `release retain`
released it. Run `release retain` first to release old pins.

The prune deletes exactly the approved local records, extends the target's
checkpoint and removes the matching attempt records on every reachable member.
Each member then keeps a fixed-size checkpoint and refuses any operation at or
below its watermark, so removed records can never run again. A removed
operation or release is not recorded any more: `operation show`, `resume` and
`retry`, and `release show`, refuse it with the checkpoint's counts and never
say whether that ID existed.

### Interrupted prunes and unreachable members

The prune runs even while an earlier operation is unsettled, and keeps that
operation with reason `recovery`. It writes a one-use cleanup intent first, so
it works on a full store. While the local part is incomplete, every other leaf
of the target refuses `busy: prune`; run the same `operation prune` with the
same digest to complete it. An unreachable member is reported with
`reachable: false` and its attempt records stay pending; they never block the
approval, the next prune removes them first, and a member recorded as removed
drops out. The report's `hosts[].outcome` is `succeeded`, `pending` or
`unknown`, and pending members set recovery `rerun`. A prune whose policy
matches nothing refuses `bound: nothing-eligible`.

### Cases the cleanup does not cover

- **Whole-target reads.** Each leaf reads the operation summaries, at most 256
  MiB at the caps with maximum-size summaries, streamed within its existing
  deadlines.
- **Restored state.** A request's sequence comes from local records alone, so
  restoring an older copy of the controller state, which this version does not
  support, could reuse sequences at or below a member's watermark; those
  operations refuse `ownership`, naming the watermark.
- **Unreachable machines.** Pins and attempt records on a machine that is no
  longer a current member's (a removed member that is never replaced, or the
  old machine of a member replaced onto another) stay on that machine. Broil no
  longer reaches it, and they count toward no cap.
- **Other records.** Agent waves and bootstrap records keep their own caps. The
  prune never deletes registry content, application data, other host data or
  the K3s datastore.

## Read live views

Use a live view to inspect the selected cluster before deciding what to do next.
`status` collects the declared components; a narrower view helps answer one
question with fewer reads. These commands use existing ownership records and
trusted member access. They create no operation, refresh no credentials, and
make no lifecycle or Kubernetes changes.

Before starting, use a target whose cluster identity and managed administrator
access were published by [creation](#create-and-reconcile). Keep its declaration,
recorded identities and qualified profile unchanged. The acting first server,
the first server in declaration order that is not recorded as removed and has
a published node UID, must be
reachable for API inventories; other member reads use their own trusted SSH
routes. A member recorded as removed is reported with ownership state `removed`
and is never probed. Views never select your ambient kubeconfig or another endpoint when
that access fails. A missing owner or cluster reports `readiness` with recovery
`create`; malformed records and profile drift retain their explicit refusals.

From the configured project root, replace `lab` and `demo` with your environment
and target. Start with member observations:

```sh
BROIL_ENV=lab broil k3s nodes demo --format json --non-interactive
```

Look for `outcome: complete` and exit status 0. They mean the requested facts
were observed completely. A complete inspection can show a non-ready member or
a mismatch; inspect each row's `readiness` and `facts.comparison` before deciding
whether infrastructure is ready for your task. A foreign Node is reported
separately and never becomes a member Broil owns.

| Question | Command after `BROIL_ENV=lab broil k3s` |
| --- | --- |
| What does each declared component report? | `status demo` |
| Which member UID, version, role, labels or taints differs? | `nodes demo` |
| What does one subsystem report? | `diagnose demo --component api` |
| Which workloads exist and what counts do they expose? | `workloads demo` |
| Which services exist and which are owned by Broil? | `services demo` |
| What does the declared registry stack report? | `registry inspect demo` |

All accept `--format json` or `--format table`; both contain the same public
facts. Diagnosis also accepts `datastore`, `network`, `dns`, `storage`, `ingress`,
`certificates` and `registry`. Registry inspection requires a declared registry.
A selected ACME issuer remains unavailable. API and node views do not select
unrelated issuer domains.

Read `source`, `observed_ms` and `operation` together. A `live` row belongs to
this invocation, a `recorded` row retains its original operation and time, and
a `declaration` row describes configuration. Member rows also retain each read's
time and failure: an unavailable member need not hide available API facts or
another member's observations. The report is not an atomic cluster snapshot.

`nodes`, `workloads`, `services` and `diagnose` accept `--limit 1` through
`--limit 1000`, defaulting to 100. Workload limits apply across all five kinds,
and node limits include foreign-node rows. `truncated: true` means required
items were omitted or the server reported another page. Broil does not fetch
that page automatically. Truncated, failed or uncertain required reads exit 1
and retain available public facts. A smaller limit can avoid a reply-size
refusal, but cannot turn an incomplete inventory into a complete one. Reports
that exceed the final output bound refuse before writing any payload.

Component limits still apply: network, ingress, cert-manager and issuer service
readiness can remain `unobserved`; registry storage is a separate fact, and
each replica's synchronization is reported per member by the
`registry-replica` rows.
A service recipe recorded before token configuration can report ConfigMap drift while the token
row reports ready. Interpret those rows with each component's own section of this guide.
Publication and configured node access are recorded observations. Publication
never becomes `ready` in a view, and configured node access proves no production
pull. Workload counts and Service addresses do not prove application health or
delivery. Views expose no raw API objects, logs, Secrets or kubeconfigs.

Use the reported failure and [local records](#read-local-records) to investigate
an incomplete read. Recovery advice grants no automatic repair, migration,
credential refresh or retry. Fix the named prerequisite before requesting a
new observation.

## Read local records

Start in the selected Broil project with a configured K3s target and an explicit
environment through `BROIL_ENV`. The following examples use environment `lab` and target `demo`;
replace them with names from your declaration. Use `--file` before the command
when selecting a particular configuration file.

```sh
BROIL_ENV=lab broil k3s list --format json
BROIL_ENV=lab broil k3s show demo --format json
BROIL_ENV=lab broil k3s operation list demo --format json
```

The first two commands inspect declarations. Operation list reads existing
records under the selected project's `state/infrastructure/targets/` directory.
These commands do not acquire credentials, contact members or create state.
An empty operation list means there are no recorded operations for that scope;
unsafe or incomplete state produces an error instead of an empty result.

Copy an operation ID from the list before requesting its full record:

```sh
BROIL_ENV=lab broil k3s operation show demo OPERATION_ID --format json
```

Replace `OPERATION_ID` with the complete recorded `infra-operation-…` identifier.
Inspect `outcome`, `failure`, `completion_unknown`, `cleanup_unknown`, the step
observations and `recovery`. A successful `show` command can display a failed
historical operation. List returns at most the newest 100 summaries and reports
`truncated` when more exist. Full reports refuse oversized output before writing
it. JSON and table output contain the same public facts.

## Observe before considering a retry

Live observation requires the original complete member selection, trusted SSH
routes, explicit privilege and the matching qualified lifecycle script and
tool profile. Keep the recorded configuration, credential references and
installation identities intact.

```sh
BROIL_ENV=lab broil k3s operation resume demo OPERATION_ID --format json --non-interactive
```

Resume contacts the original participants and appends observations. It never
replays a dispatch, creates an owner, retires a writer or starts another attempt.
For `prepare-server-inputs`, resume also never refreshes the managed admin
kubeconfig, republishes either input, or cleans a possible private residue.
For `join-server`, resume observes the original installation, resources,
writers and receipts. It does not prepare credentials, activate or start K3s,
publish an identity or retry membership.
For `join-agent`, resume observes the original installation, resources, writers
and receipts. It does not acquire credentials, activate or start K3s, publish
an identity or advance a batch wave.
For `reconcile-issuer`, resume observes the issuer objects. It can record the
Secret's UID from the original create receipt or confirm the ClusterIssuer from
a recorded create reply. It never creates, supplies, activates or deletes.
For `reconcile-certificate`, resume observes the certificate objects. It can
record the Certificate's UID from the original create receipt. It never creates,
renews or deletes.
For `reconcile-registry-token`, resume observes the token objects and the
registry's ConfigMap. It never patches, restarts or records a UID.
For `release-deliver`, `release-retain`, `release-apply` and
`release-rollback`, resume observes the recorded receipts of the release steps.
It replays nothing: no pull, pin, unpin, apply or hook runs again. An
apply or rollback that stays unknown reports failure `readiness`, since its
first owner inspection has no receipt to observe, while `operation show` and
`release show` keep the recorded failure. A failure that Broil detected itself
after recording, such as `ownership` or `integrity`, is recorded with the
operation, so `operation show` names it while the operation stays unknown; a
cancellation, an expired deadline or a storage failure is named only in that
run's report.
It returns status 1 when observations remain incomplete or a recovery decision
is needed. Repeating resume may discover an already durable receipt; it does
not cause another effect.

A `retry` recovery choice includes a proposed step, effects and an exact approval
digest. Review that proposal before using its values:

```sh
BROIL_ENV=lab broil k3s operation retry demo OPERATION_ID --step STEP --approve DIGEST --format json --non-interactive
```

Replace all three uppercase operands with values from that operation and its
current proposal. The digest authorizes only those exact freshly revalidated
facts. Changed identities, destinations, configuration or writer state cause
refusal; approval never overrides them. This foundation retries only a proved
absent-effect owner reservation or a proved absent-effect input preparation
whose old writers have all retired. Credential and lifecycle actions cannot be
retried through this executor, and completed steps are not replayed.

If recovery reports `operator-recovery`, retain the records and resolve the
reported ownership, identity or settlement problem before observing again.
Do not delete lock files, reservations or operation directories to force a
retry. There is no force-clear or takeover command in this foundation.

Before upgrading Broil, finish every unfinished operation with the earlier
Broil that recorded it: resume, retry or settle it there. This Broil cannot
read the operation records of a target that an earlier Broil created: every
command that reads them, `operation list` and `operation show` included,
refuses `integrity`, even when every operation finished. Keep the earlier
Broil for such a target. A target that replaces it with this Broil needs
another target name, because the name selects the target's local records,
and unclaimed hosts, as for any [new target](k3s-create.md#establish-the-target-and-its-prerequisites).
The upgrade is one-way: once this Broil has written a target's records, an
earlier Broil refuses them. Keep a copy of the earlier binary while targets
that it created remain, and use it for those targets only.
