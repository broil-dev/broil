# Deploy applications to a K3s target

A release is an immutable record of what an application runs: its manifests
with every Broil image bound to an exact digest, its hooks and the versions of
its Secrets. Broil delivers a release's images to every required node from that
node's own registry replica, applies the manifests and checks health. Because
every applied release is recorded, Broil knows what runs now and can return to
the last healthy release with one command.

Start with a target [created](k3s-create.md) with a managed registry, images
published to it as [Publish to the managed registry](k3s-registry-publish.md)
describes, and, for Secrets, a [secret store](secrets.md). The examples use
environment `prod`, project root `/srv/shop`, target `edge` with servers
`server-1` to `server-3` and agents `agent-4` to `agent-6`, and application
`shop` with catalog images `api` and `worker`. Run the commands on the Linux
controller from the project root.

## How a release moves through its states

Each release passes four evidence states, each established by one command:

| State | Established by | Meaning |
| --- | --- | --- |
| Seeded | `release deliver` | Every required node's local replica holds the release's images. |
| Delivered | `release deliver` | Every required node pulled each image at its exact digest and pinned it, so image garbage collection keeps it. |
| Applied | `release apply` | The Secrets and objects were applied to the cluster. |
| Healthy | `release apply` | Every workload is ready with the bound digests on delivered nodes, and every health hook passed. |

`release prepare` records the release and changes nothing in the cluster.
`release deploy` runs prepare, deliver and apply in one command and stops at the
first stage that does not succeed.

Two releases of an application have roles:

- **Active** is the release whose apply or rollback most recently changed the
  cluster, whether or not it reached Applied. After a partial apply, the
  partial release is active and its `evidence.applied` is false.
- **Rollback** is the most recent Healthy release other than the active one, or
  null. After any failed or partial apply, `release rollback` restores the last
  Healthy state.

## Declare an application

Applications belong to one environment, outside the target's declaration, so
adding or changing one never changes the target. The smallest declaration names
the target, the namespace and the manifests:

```yaml
environments:
  prod:
    applications:
      shop:
        target: edge
        namespace: shop
        manifests: [deploy/shop/]
```

`manifests` lists `BROIL_ROOT`-relative files or directories; a directory
contributes its `*.yaml` and `*.yml` files, not recursively, in name order.
Instead of `manifests`, `render` may name a controller hook whose standard
output is the manifest YAML; the output is stored in the release, so a rollback
applies the same bytes without rendering again. Every object must be in the
application's namespace, except one optional Namespace object of that name.

A complete declaration adds the required nodes, the health timeout, hooks and
Secrets:

```yaml
environments:
  prod:
    remote:
      machines:
        db1: {address: 10.10.10.30}
    applications:
      shop:
        target: edge
        namespace: shop
        manifests: [deploy/shop/]
        delivery:
          nodes: all
        health:
          timeout: 10m
        hooks:
          before_apply:
            - {name: backup, location: controller, argv: [scripts/db-backup.sh], timeout: 15m,
               secrets: {PGPASSWORD: {set: shop/prod, key: backup_password}}}
            - {name: migrate, location: db1, argv: [/opt/shop/migrate, up], timeout: 10m}
          health:
            - {name: smoke, location: controller, argv: [scripts/smoke.sh, https://shop.example.test], timeout: 2m}
        secrets:
          shop-db:
            DATABASE_URL: {set: shop/prod, key: database_url}
```

| Field | Default | Rule |
| --- | --- | --- |
| `delivery.nodes` | `all` | `all` (every member not recorded as removed), `{members: [...]}` or `{labels: {key: value}}`. Recorded at prepare. Workloads must schedule only onto these members. |
| `health.timeout` | `10m` | At most `2h`. Bounds workload readiness before health hooks run. |
| `hooks.before_apply` | empty | Run in order after the delivery recheck and before any Secret or object is applied. |
| `hooks.health` | empty | Run in order after workload readiness. |
| `secrets` | empty | Each entry becomes one Opaque Secret in the namespace, from `{set, key}` references. |

Configuration errors stop at loading, before any command runs, for example
`broil: application config value at environments.prod.applications.shop must be exactly one of manifests or render`.

## Bind images in manifests

Write a catalog image as `broil-image://<image>` in a container's `image`:

```yaml
spec:
  template:
    spec:
      containers:
        - name: api
          image: broil-image://api
```

`release prepare` replaces it with the bound `repository@digest` of the selected
artifact record, for example
`registry.example.test/shop/api@sha256:9cc2…dcc3`. Nothing else is rewritten.
The reference is recognized only as the exact `image` of a container, init
container or ephemeral container of a Pod or of the pod template of a
Deployment, StatefulSet, DaemonSet, ReplicaSet, Job or CronJob; any other
occurrence refuses. A bound container must not set `imagePullPolicy: Always`.
Images written without `broil-image://` stay as written; Broil neither delivers
them nor checks their digests. Manifests must not contain `kind: Secret`;
declare Secrets under `secrets`.

Prepare takes the newest record of each image published at an origin of the
target's `node_registries`. Pass `--artifacts api=<artifact-id>` to choose one
explicitly; a record bound at two such origins is ambiguous and refuses.

## Deploy a release

```sh
BROIL_ENV=prod broil k3s release deploy edge shop
```

Exit status 0 means the release is Applied and Healthy. Read `active`,
`rollback`, `evidence` and each entry of `stages`. Per-stage details are in
`release show` and `delivery report`.

To deliver ahead of a maintenance window and apply later, run the stages
separately. `prepare` prints the new release ID:

```sh
BROIL_ENV=prod broil k3s release prepare edge shop
BROIL_ENV=prod broil k3s release deliver edge "$RELEASE"
BROIL_ENV=prod broil k3s release apply edge "$RELEASE"
```

where `RELEASE` holds the prepared release's ID. Preparing again with identical
inputs returns the same release with `existing: true`.

### What deliver does

For each required node, deliver waits, within the target's step timeout, until
the node's local replica holds the release's whole closure for the node's
platform, checked through the node's own reader. It then pulls each image
through the container runtime, verifies its digest and image ID and pins it.
The report's `nodes[].images[].source` is `replica`, `present` (already pinned,
no pull), `external` (an external registry) or `origin-fallback` (the replica
did not have it in time and the node's `fallback: same-origin` reached the
origin). `origin` counts the requests the origin served for the release during
the window. `delivery check` shows the replicas' state before you deliver.

### What apply does

Apply first checks every required node again for the exact pinned images, and
asks the API which kinds are cluster-scoped; any cluster-scoped kind other than
the Namespace fails before any change. It then runs the `before_apply` hooks,
applies the Namespace, then the Secrets, then the other objects in manifest
order with server-side apply (field manager `broil`, no forced conflicts),
waits up to `health.timeout` for workload readiness, checks that every current
pod of those workloads runs the bound digests on a delivered node, and runs the
health hooks.

Readiness is checked per kind, once each controller except a Job has observed
its current generation:

- A Deployment is ready when its updated and total replicas equal the desired
  count and its available replicas reach it, so `minReadySeconds` counts. A
  paused Deployment, or one whose progress deadline was exceeded, stops health
  at once.
- A StatefulSet with `RollingUpdate` is ready when its updated replicas reach
  the desired count less its partition and its ready replicas reach the desired
  count.
- A DaemonSet with `RollingUpdate` is ready when its updated and available pods
  reach the desired count.
- A StatefulSet or DaemonSet with `OnDelete`, and a ReplicaSet, are ready when
  their ready pods reach the desired count.
- A Job is ready when its succeeded pods reach its completions; a failed Job
  stops health at once. A Pod is ready when it is Running and Ready.
- A CronJob is applied but has no readiness.

Workloads are read in groups of 32 in manifest order. Each group waits with
what remains of `health.timeout` until a failing pod is found. Once one is
found, every later group is read once without waiting, while one step timeout
still fits before the operation deadline, and health then stops; the health
hooks do not run. The current pods are those of a Deployment's newest
ReplicaSet, a StatefulSet's update revision at or above its partition, a
DaemonSet's current revision, and every pod of an `OnDelete` workload, a
ReplicaSet, a Job or a Pod. Pods being deleted or in phase `Failed` are not
checked. A pod fails when it runs on a node outside the required set, or when a
bound container reports an image ID whose digest is neither the bound root nor
a recorded manifest digest, whatever repository it names; while its workload is
not ready yet, an unscheduled pod or a container without an image ID is not a
failure.

The report lists those pods in `health.undelivered_pods`, each row
`{member, namespace, pod, reason, container, image_id}`: reason `node` rows
first, then `digest` rows naming the first failing container, regular
containers before init containers, and its `image_id`, the image ID without a
leading `docker-pullable://` or other scheme. Each group contributes at most 32
rows, its `node` rows first, and the rows of all groups share a fixed byte
budget of 32 widest rows, groups with a `node` row first. When rows were left
out, or a workload was not read or not ready after a failing pod was found,
`health.undelivered_truncated` and the report's `truncated` are true: the list
is not exhaustive.

## Hooks and their environments

A hook is a literal `argv`, with no shell, run either on the `controller` or as
a machine's canonical account on a machine of `remote.machines`, without
privilege. Every hook has a required `timeout`, at most `2h`, after which it is
terminated and fails as `timeout`.

Controller hooks run in `BROIL_ROOT` with the environment Broil builds for
local commands (`BROIL_ROOT`, `BROIL_ENV` and the resolved `env_vars`, with no
automatic secret injection) plus their declared `secrets` as environment
variables for that one process. Remote hooks run in the account's home
directory with the remote environment mappings and take no Secrets. Both get
`BROIL_TARGET`, `BROIL_APPLICATION`, `BROIL_RELEASE`, `BROIL_HOOK_STAGE`,
`BROIL_OPERATION` and `BROIL_HOOK_ATTEMPT`. Hooks get no standard input, and the
output of non-render hooks is discarded. Every side effect of a hook is yours;
Broil records only the stage, exit status, duration and outcome.

A `before_apply` hook runs at most once with success per release: a later apply
skips hooks that succeeded and runs failed ones again. When a hook's outcome is
unknown, for example after a lost connection to its machine, a later apply runs
it again only when it is declared `repeatable: true`. Otherwise apply refuses
`hook-unknown` and names an observed plan:

```sh
BROIL_ENV=prod broil k3s plan edge --action release-apply --release "$RELEASE" --observe --format json
BROIL_ENV=prod broil k3s release apply edge "$RELEASE" --approve "$APPROVAL"
```

Confirm what the hook did, then pass the plan's `approval` as `APPROVAL`. The
approved apply first settles the earlier apply operation as failed, keeping the
hook's outcome unknown, and then proceeds. Health hooks are always repeatable
and run on every apply and rollback.

## Secrets at current values

Secrets are not part of the release content. Prepare records each reference's
version as unverified metadata, read without decrypting (`sops:<time>`,
`vault:<version>` or null); values never enter release records. Apply and
rollback write the current values and report each Secret's current `version`
beside its `prepared_version`. Versions are reported, never enforced, and a
rollback does not restore earlier values, as it does not restore data.

## Roll back and release old images

When an apply fails its health checks, the release is active but not Healthy,
and the report's recovery is `rollback`:

```sh
BROIL_ENV=prod broil k3s release rollback edge shop
```

Rollback re-applies the stored manifests of the rollback release, writes the
Secrets' current values, runs its health checks and no `before_apply` hooks. It
never rolls data back.

Delivered images stay pinned on the nodes. `release retain` unpins the images
of the application's releases outside its kept set: the active and rollback
releases and every release prepared after the active one that was never
applied. An image that a kept release of any application uses stays pinned.
Preview it and approve:

```sh
BROIL_ENV=prod broil k3s plan edge --action release-retain --application shop --observe --format json
BROIL_ENV=prod broil k3s release retain edge shop --approve "$APPROVAL"
```

Unpinning lets the node's image garbage collection reclaim the image. Registry
content is never deleted in this version.

## Read releases

These commands record nothing:

| Question | Command after `BROIL_ENV=prod broil k3s` |
| --- | --- |
| What runs now, on which nodes, and which objects of earlier releases remain? | `release status edge shop` |
| Which releases exist and what role does each have? | `release list edge shop` |
| What does one release contain, and what did its applies report? | `release show edge "$RELEASE"` |
| How long did each node take to receive and pull it? | `delivery report edge "$RELEASE"` |
| Are the replicas, readers and token services ready? | `delivery check edge` |

`release status` reads the cluster through the acting first server. Its
`nodes[]` report `present`, `missing` or `unobserved` for the active and
rollback images, and `orphaned` lists objects of earlier releases that the
active one no longer contains; Broil never deletes them.

`release show` lists the 16 newest applies and rollbacks of a release. Its
`truncated` is true when more exist or when a listed run's
`health.undelivered_truncated` is true; the read still exits 0.

## Recover from a failed report

A refusal prints one line on standard error before anything is recorded, such
as `configuration: binding (deploy/shop/api.yaml: broil-image://payments is not in the image catalog)`,
and names the fix. Once an operation is recorded, the command prints only its
report: a failed report exits 1 with `failure`, `detail` and `recovery`.

| `detail` | What happened | Next step |
| --- | --- | --- |
| `incomplete-delivery` | A required node did not receive or keep the release. | Run `release deliver` for that release once the member is reachable. |
| `replica-incomplete` | A node's replica did not hold the closure within the step timeout. | Run `delivery check`, fix replication between members, then run the command again, or set `fallback: same-origin`. |
| `platform` | A node's platform is missing from the release's images. | Publish the missing platform and prepare a new release. |
| `digest` | A node resolved a different digest. | Operator recovery: inspect that node's registry configuration. |
| `cluster-scoped` | The manifests contain a cluster-scoped kind; nothing ran. | Move the kind out of the manifests and prepare a new release. |
| `rejected-object` | The API server rejected an object, which was not written; later objects were not applied. | Correct the manifests and prepare a new release. When the application namespace is missing, create it and apply again, or add its `Namespace` object and prepare a new release. |
| `secret-metadata` | The API server answered a Secret metadata request with Secret data or another form; nothing was written. | Run the command again once the API server answers metadata requests with metadata only. |
| `hook` | A hook failed or timed out. | Fix the cause and apply again; failed hooks run again, succeeded ones are skipped. |
| `hook-unknown` | A hook's outcome is unknown. | Resume the named operation, then approve the plan for a non-repeatable hook, as above. |
| `field-conflict` | Another field manager owns a field. | Roll back when objects changed; otherwise remove the other manager and apply again. |
| `rollout`, failure `timeout` | Workloads did not become ready in time before any failing pod was found. | Roll back. |
| `rollout`, failure `readiness` | A Deployment is paused or exceeded its progress deadline, or a Job failed; `health.workloads` names it. | Paused: resume its rollout and apply again (a rollback leaves the pause in place); if the manifest sets `spec.paused: true`, remove it and prepare a new release. Otherwise roll back; for a stalled Deployment first find why its pods do not become available. |
| `undelivered-node`, a `node` row | A pod runs on a node outside the required set. | Roll back, then constrain scheduling or widen `delivery.nodes`. |
| `undelivered-node`, `digest` rows only | A container runs another image than the release binds. | Each row's `image_id` is what the node reports. Null: no image ID yet; wait and apply again. Another image: find what changed the pod's image; for an `OnDelete` StatefulSet or DaemonSet, or a ReplicaSet, delete the pods that still run an earlier image. The same content under another repository and digest: remove only that reference on the node with `k3s ctr -n k8s.io images rm <image_id>`, never the image, and only when no other workload runs it and no kept release of any application binds it (`release show` lists each kept release's references); then delete the pod and apply again. Otherwise leave the pods running: the release stays `undelivered-node`. When `health.undelivered_truncated` is true, the list is not exhaustive and applying again reads the other workloads again. |
| `undelivered-node`, outcome `unknown` | A read after a failing pod was found was lost or refused, or the run was cancelled or reached its deadline. | Run `operation resume` with the named operation first; the rows are partial. Then follow the settled report. |
| `health-check` | A health hook failed. | Roll back. |
| null, outcome `unknown`, failure `transport` | A reply was lost; the effect is unknown. | The target refuses `busy` until operator recovery; run `operation resume` with the named operation. |
| null, outcome `unknown`, failure `credential` | Writing a Secret ended with an unknown effect. | The target refuses `busy` until operator recovery; run `operation resume` with the named operation. |
| null, outcome `unknown`, another failure | The run stopped after recording, for example on `ownership`, `integrity`, `timeout` or `cancelled`. | Run `operation resume` with the named operation. A failure Broil detected itself is recorded, so `operation show` and `release show` name it; a cancellation, an expired deadline or a storage failure is named in this report only. |

`operation resume` of a release operation that stays unknown reports failure
`readiness` and exits 1; `operation show` keeps the recorded failure.

A release whose widest apply report could exceed 1 MiB is refused
`bound: report` by `release prepare` (and so by `release deploy` before
delivery), and again by `release apply` and `release rollback` before they read
the cluster; split the application's objects or Secrets.

Every lifecycle command needs settled history; an unsettled earlier operation
refuses `busy` and names it. A full history store refuses `store-full`; see
[Clean up operation history](k3s-operations.md#clean-up-operation-history).

## Limits

- A release holds at most 32 images, 4 MiB of bound manifests and 512 objects.
  An application has at most 32 Secrets of 64 keys each, and at most 16 hooks per
  stage.
- A target holds at most 16,384 release records.
- Release records live in the project's state and survive only with it; an
  approved history cleanup may remove unpinned old ones.
- Objects removed from a manifest set are reported as orphaned by
  `release status` and never deleted.
- Registry content is never deleted in this version; holds and garbage
  collection belong to a later roadmap, which must keep every kept release's
  images.
