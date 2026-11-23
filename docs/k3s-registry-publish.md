# Publish an image to the managed registry

Use Broil's image commands to publish through a registry that your K3s target
already owns. An image build produces content; publication uploads and reads
back that content by digest. Neither action deploys a workload, proves a node
pull, or guarantees that the registry will remain available.

Start on the Linux controller in the configured project root, using Bash and
a matching installed Broil binary. The examples use environment `lab`, target
`demo`, registry entry `local`, image target `app` and builder `shared`.
Replace these with your declared names. Complete [target creation](k3s-create.md)
and the [controller tool setup](images.md#prepare-a-controller), then check the
[image and builder declarations](images.md#declare-images-endpoints-and-credentials)
before continuing. The supplied K3s example alone declares no usable builder
or build context.

## Connect the service, endpoint and publisher

The **managed service** owns the registry pod, storage and authentication.
Its `endpoint` selects a **registry catalog entry**, which gives the image
publisher its URL, CA and protected credentials. A **publication principal**
grants pull/push on specified repositories; a node-pull principal and maintenance
principal have different purposes. Declare their bindings before target creation.

Check these inputs:

- `registries.local.ca` names your explicit CA file; the publisher uses it in
  place of system roots. The file must be owned by you or root and have no
  group/other write permission (for example, mode `0644`). Broil refuses unsafe
  permissions even when K3s can read the certificate.
  The entry's `push` names the publication principal,
  its exact password reference and repositories, and matching `token_service`
  realm/service. Follow the [publication entry reference](k3s-operations.md#declare-the-publication-entry).
- The controller's DNS or hosts configuration resolves the endpoint to an
  ingress member serving HTTPS on port 443. Broil adds no name resolution.
- The builder runs outside the cluster's workloads: on another machine or as
  an independently managed builder on a member host. With default registry
  output, it exports to the controller, whose helper uploads. The builder does
  not contact this registry.
- Run image commands with `BROIL_ENV=lab` so their registry and secrets overlays
  match K3s selection. Without it, image commands select root catalogs. Choose
  this before creation; a later changed registry entry refuses ownership.

Inspect the installed stack first:

```sh
BROIL_ENV=lab broil k3s registry inspect demo --format json
BROIL_ENV=lab broil k3s credentials inspect demo --consumer registry-auth --format json
```

Read the token/principal observations and grants. `publication: unobserved`
can describe a switched, authenticated service with installed grants. It is not
an upload, current-store comparison or durable availability claim. A changed
store password needs the [supported credential change](k3s-manage.md#apply-a-selected-change)
before the publisher can use it.

## Size an attempt before uploading

**Each helper attempt must finish within 30 seconds.** The bound includes local
hashing, all missing blob uploads, manifest uploads, tag PUT/GET and full closure
readback, even for blobs already present. A **closure** is the root image/index
and all required platform manifests, configurations and layers.

A blob whose upload alone exceeds that bound, or a closure whose readback alone
exceeds it, cannot publish at that link rate. Repeating does not overcome the
readback bound. At 100 Mbit/s the ideal transfer budget is about 358 MiB total,
or about 179 MiB for new content uploaded and read back once; hashing and requests
leave less. Use a controller with a sufficiently fast path and retained output
when rebuilding would be costly.

The 30-second bound binds before the longer token and Traefik limits. The tag
can already have moved when readback fails, leaving no publication evidence.
Concurrent tag writers are uncoordinated. Read
[attempt limits](k3s-operations.md#fit-each-attempt-in-30-seconds) before relying
on repeated attempts or moving a shared tag.

## Build and publish

The image target connects a build context, builder and allowed repository.
This fragment assumes `shared` is a configured builder and `app/` contains your
build context and Dockerfile. Merge it into your project's image catalog:

```yaml
images:
  app:
    image: registry.example.test/team/app:v1
    builder: shared
    registry: local
    context: app
    platforms: [linux/amd64, linux/arm64]
```

```sh
BROIL_ENV=lab broil image build --target app --builder shared --format json
```

Exit 0 requires publication for every registry-output target. Read the result's
target/publication evidence: the helper uploads missing blobs and manifests,
writes and checks the tag, then reads the complete closure back by digest.
That evidence describes this observation only. A tag's previous root remains
readable by digest, but is not captured as a rollback choice.

## Publish retained content without rebuilding

A retained OCI layout or archive separates building from publication. Before a
new build, add this `output` mapping inside the `app` image declaration above:

```yaml
    output:
      type: oci-layout
      path: retained-app
```

Choose an absent destination outside the workspace and protected-lease trees;
an existing retained output is never overwritten. The path is relative to the
project root, which already supplies this example's parent directory.
See [output ownership](images.md#outputs-and-ownership) for its
custody and path constraints. Then build the retained content:

```sh
BROIL_ENV=lab broil image build --target app --builder shared --format json
broil image status --format json
```

From the status report, select the build operation whose `app` target has the
retention observation. This retained-output build has not published the image.
Replace the variable value below with that complete `operation-` ID followed
by 32 lowercase hexadecimal characters, not an artifact ID or a digest:

```sh
build_operation=operation_REPLACE_WITH_RECORDED_ID
BROIL_ENV=lab broil image publish --target app --operation "$build_operation" --registry local --format json
```

The publisher locates and re-verifies the journal's retained content, uploads
it through `local`, and records this new publication operation without changing
the artifact record. Missing or corrupt retention requires a new build; publish
does not silently rebuild. Retained publication has the same attempt bound and
readback requirements as default registry output.

## Read a failure and choose the next action

An unacknowledged publication is Unknown, printed `indeterminate`, with exit 1.
Keep its operation ID. [Image resume](images.md#observe-an-interrupted-operation)
observes recorded evidence without sending a registry request or replaying the
upload. A retry is an explicit new publication for retained content, or normally
a new build after default registry output, whose exported layout was released.
Each new attempt skips blobs already present but still reads back the full closure.

Incomplete blobs and upload sessions can remain. Deletion, upload purging,
retention holds and garbage collection are deferred. Last writer wins for tags;
successful publication is neither a retention hold nor backup. A publication
reaches the writer's replica first and every other member's replica shortly
after; while the writer's member is away, pushes stop and node pulls continue
([Run the replicated managed registry](k3s-registry.md)). A registry that lost
every replica follows the
[storage-loss boundary](k3s-manage.md#storage-loss-and-changed-declarations).

Use the artifact record's root digest when checking a node, not a mutable tag.
The [manual node-pull procedure](k3s-operations.md#check-that-every-node-can-pull)
checks the exact registry authority and platform digest and explains scoped
cleanup. It adds no Broil delivery or application-health evidence; to run the
published image, [deploy a release](k3s-releases.md).
