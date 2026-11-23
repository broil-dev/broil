# Prepare K3s hosts and bootstrap assets

Host preparation checks that each declared member can run the pinned K3s
release and places one verified, inactive copy of the bootstrap assets on it.
This guide explains what preparation needs from you, what it observes, and
what it records. For declaration inspection, see
[inspect K3s target declarations](k3s.md); for reading operation records, see
[operation records and recovery](k3s-operations.md).

Preparation itself does not install or start K3s, import images, join nodes or
activate credentials. Public `create` performs preparation first, then those
lifecycle steps. Supply the inputs below before [creating the target](k3s-operations.md#create-and-reconcile);
every later step consumes only a completed generation.

## Why independent assets and completed generations

A cluster is only as trustworthy as the bytes it boots from. Broil therefore
never lets a host decide what to download: the exact release executable, the
official air-gap image archive, the addon images and the derived component
images are pinned by size and SHA-256 in a **bootstrap index** that ships with
Broil (`tools/k3s/bootstrap-index.lock.json`). A **manifest** that you write
selects that complete set and, online, tells each host where to fetch each
file. The manifest can never add, drop or replace an asset; a different digest
is a refusal, not a new pin.

Each member receives the set in its own root-owned **generation** directory.
The host verifies every byte it receives, and the controller verifies bundle
files again before sending them. Only when every asset is present and verified
does the host write an immutable completion marker. Later steps use a
generation only if the marker, the file identities and the recorded receipts
all agree. A partial directory, a copied marker or a file that changed after
verification is never adopted, and a repeated preparation never overwrites an
existing file.

The official air-gap archive is a special case. Its nested image indexes name
platforms and attestations that the archive does not contain. A source-carried
policy enumerates exactly those absent entries for this one archive, so the
unchanged official bytes verify while every other missing blob, for every
asset, remains a refusal.

## What you supply

### Declaration fields

Under `environments.<environment>.k3s.<target>.bootstrap`:

| Field | Meaning |
| --- | --- |
| `mode` | `online` (hosts fetch from your HTTPS source) or `bundle` (the controller transfers local files) |
| `manifest` | Path of the manifest file, resolved below the project root; a relative path starts at the root, and a location outside the project root is refused |
| `bundle` | Directory holding the asset files, resolved below the project root like the manifest; required exactly when `mode` is `bundle` |

Inspection never opens these paths. They are opened only when preparation runs.

### The manifest

The manifest is one JSON object in canonical form (keys sorted, no
insignificant whitespace) followed by a single newline, at most 32768 bytes.
It contains exactly:

| Field | Value |
| --- | --- |
| `schema` | `1` |
| `profile_sha256` | SHA-256 of the shipped `tools/k3s/action-profile.json` |
| `platform` | `linux/amd64` |
| `version` | The target's K3s version, currently `v1.36.4+k3s1` |
| `assets` | Every selected asset, in index order, each with `id`, `size`, `sha256`, `origin` and `url` |

`id`, `size`, `sha256` and `origin` repeat the index entry exactly. `url` is
`null` in bundle mode. In online mode it is a direct `https://` URL with a DNS
name or IPv4 address, an optional port and a nonempty path; user information,
query strings, fragments, redirects and dot segments are refused, and the
location must not be the managed registry's origin.

Eleven assets are always selected. The `distribution` and `auth` assets are
added when the target declares a managed registry:

| Asset id | File name | Selected |
| --- | --- | --- |
| `k3s` | `k3s` | always |
| `k3s-airgap` | `k3s-airgap-images-amd64.tar.gz` | always |
| `cert-manager-acmesolver` | `cert-manager-acmesolver.tar` | always |
| `cert-manager-cainjector` | `cert-manager-cainjector.tar` | always |
| `cert-manager-controller` | `cert-manager-controller.tar` | always |
| `cert-manager-startupapicheck` | `cert-manager-startupapicheck.tar` | always |
| `cert-manager-webhook` | `cert-manager-webhook.tar` | always |
| `coredns` | `coredns.tar` | always |
| `traefik` | `traefik.tar` | always |
| `cert-manager-manifest` | `cert-manager.yaml` | always |
| `metrics-server` | `metrics-server.tar` | always |
| `distribution` | `distribution.tar` | with a managed registry |
| `auth` | `auth.tar` | with a managed registry |

Copy `size`, `sha256` and `origin` for each entry from the shipped index. An
illustrative entry looks like this (values abbreviated):

```json
{"id":"k3s","origin":"https://github.com/k3s-io/k3s/releases/download/v1.36.4%2Bk3s1/k3s","sha256":"835873f3…","size":78991522,"url":null}
```

### An online source

Publish the exact files at the URLs named in the manifest. Each host fetches
with normal certificate and host-name validation, so the server certificate
must chain to a CA the hosts already trust. Hosts follow no redirects, use no
proxy or mirror, and retry nothing; a source that is unreachable or serves
different bytes is a classified failure of that asset. The derived images
(`metrics-server`, `distribution`, `auth`) and the addon bundles are Broil
build outputs, so you publish them yourself or use bundle mode.

### A bundle directory

Place the files under the declared directory using the file names above. The
directory must lie below the project root, like the manifest; a bundle staged
elsewhere, such as `/srv/k3s-bundle`, is refused when preparation runs. Keep
the manifest and the bundle below directories owned by root or by the user
running Broil, without group or other write permission; the controller refuses
inputs under a shared writable directory. Files must be regular single-link
files. The controller verifies each archive's exact layout and image closure
before any transfer, then the host verifies every received byte again.

## Host prerequisites

Preparation observes each member in declaration order and records a fixed set
of checks. Every check must pass before any host is modified; a failing check
is reported and nothing is repaired, downloaded or installed. A check whose
host utilities do not answer within its budget, or whose output is too large to
inspect, is recorded as `unknown` rather than as a pass or a failure; it blocks
preparation in the same way and tells you that the host, not the declaration,
needs attention. The three network checks compare the host with your
declaration: the member's `interface` and `node_ip`, the API and registration
endpoint hosts and certificate names, and the pod and service CIDRs.

| Check | What the host must provide |
| --- | --- |
| `host-profile` | Ubuntu 24.04, amd64, systemd |
| `canonical-access` | The declared canonical account with its standard home |
| `privilege` | Root, directly or through the declared sudo route |
| `tools` | `/usr/bin/python3`, `ip`, `timedatectl`, `systemctl` and `getent` at their stock paths |
| `sftp` | The stock `/usr/lib/openssh/sftp-server` |
| `cgroups` | cgroup v2 with the cpu, memory and pids controllers |
| `kernel` | Overlay filesystem, `br_netfilter` loaded and IPv4 forwarding enabled |
| `swap` | No active swap |
| `capacity` | Two CPUs and 2 GiB for a server, one CPU and 512 MiB for an agent, plus disk space for the assets, their expansion, one extra copy and a 1 GiB reserve |
| `destination-storage` | `/var/lib/broil/k3s` on ext4, xfs or btrfs |
| `interface` | The declared `interface` exists and carries exactly the declared `node_ip` |
| `dns` | Every declared endpoint name (the API and registration endpoint hosts and the certificate names that are not IPv4 addresses) resolves through the host resolver to at least one IPv4 address, none inside the pod or service CIDR; names are looked up in bounded batches under the check's budget |
| `routes` | No route in the main table other than the default route overlaps the declared pod or service CIDR, and every other member's declared `node_ip` is routable |
| `clock` | `timedatectl` reports NTP synchronization |
| `ports` | Nothing listening on the K3s API, registration, etcd, kubelet, ingress or VXLAN ports |
| `foreign-installation` | No `/var/lib/rancher/k3s`, `/etc/rancher/k3s`, `/usr/local/bin/k3s` or K3s units |
| `existing-generation` | The destination is absent or already holds this exact completed set |

Supply these through your normal base provisioning. Preparation itself changes
no sysctl, firewall, swap, module, route or service, and it never calls an
installer or `remote provision`.

Two further prerequisites are verified by every protected K3s action rather
than recorded as preparation checks. Supply both through base provisioning;
one method installs the executable at mode `0755` and copies the
source-carried profile verbatim. Creation later verifies the executable against the completed
generation's `k3s` asset and never installs or replaces it.

| Prerequisite | What the host must provide |
| --- | --- |
| `/usr/local/libexec/broil-k3s` | The pinned K3s executable: a root-owned regular file without group or other write permission whose SHA-256 equals the profile's `k3s_sha256` |
| `/var/lib/broil/k3s/action-profile.json` | The shipped `tools/k3s/action-profile.json`, root-owned, mode `0600` |

Changing the shipped profile (a release that pins a new executable or body
set) changes every selection hash bound to it, so records prepared under an
earlier profile refuse under the new one by design; no in-place migration
exists. Do not replace the profile or clear an existing owner's records to
force admission. A new target needs unclaimed hosts with no K3s installation,
separate endpoint origins and non-overlapping storage while the old target is
declared; follow the [creation prerequisites](k3s-create.md#establish-the-target-and-its-prerequisites).

### What creation consumes

Public [create](k3s-create.md) calls the internal first-server operation after
host and initial-input preparation. That operation activates prepared records
and downloads or generates nothing: it re-verifies the completed bootstrap generation and copies
its airgap image archive into the K3s images directory, copies the two token
files of the prepared server input into the owner's `active/` directory (the
inactive generation itself stays immutable), renders the owned K3s
configuration from your declaration, installs a private `broil-k3s.service`
unit whose prestart guard refuses a changed input, starts it, and records the
observed cluster identity only after the API, datastore and node report ready.
A repeated creation observes the existing server and preserves its installation.
It can finish propagating the cluster identity to other declared members.

### Admin access and later server input

The owned first server is the prerequisite for preparing another server's
input. K3s writes its own raw admin kubeconfig with a loopback API address.
Broil verifies that file, then publishes a separate owned admin kubeconfig
for the API endpoint in the declaration. Protected readers use the managed
file and verify the live cluster and node identity before reading a credential.
The raw file is never the endpoint offered to another member.

The internal server-input preparation entry point is qualified in CI and has
no public command yet. It prepares a fresh source and destination input pair
under one operation, uses the existing protected reader to transfer the join
credentials, and seals the writers. The destination input remains inactive;
preparation does not join or start that server. A later join must establish its
own admission and cannot reuse this operation as join authority.

For an already owned first server in a declared three-server target, the public
[ordered server join](k3s-server-join.md) prepares a new pair inside its own
operation and admits the next declared server. A successful second-server join
is an intermediate two-voter state, not full declared membership. [Agent joins](k3s-agent-join.md) follow complete server membership.

If K3s regenerates its raw admin credentials, an authorized source-preparation
operation can refresh the managed file after verifying the same declared API,
CA, cluster and node. Creation repeat and operation resume only observe;
they do not refresh it. An interrupted publication or uncertain credential
transfer remains **Unknown** with its ownership evidence and possible private
residue. Use [operation records and recovery](k3s-operations.md) to inspect
that state; do not remove the owned files to force another preparation.

Before acquiring a writer for an absent first server, creation verifies the
complete asset generation and both inactive token files. Missing or incomplete
prerequisites refuse with `readiness` and detail `assets` or `input`, leaving
remote ownership, writer metadata and installation unchanged. If an external
actor removes a prerequisite after that check, activation refuses before
installation; the acquired writer remains active and the incomplete operation
requires operator recovery. Creation does not retry or clear that writer.

## Inspect the example declaration

The [example project](examples/k3s/README.md) declares online mode with an
illustrative manifest path. Inspecting it needs no files or hosts:

```sh
broil --file docs/examples/k3s/broil.yaml get --json cfg environments.lab.k3s.demo.bootstrap
```

The result shows `mode` and `manifest`. Preparation resolves the manifest from
the selected project root only when it runs.

## What preparation records

A preparation is one durable operation with action `prepare-hosts`. `broil k3s
operation list` and `operation show` (see
[operation records and recovery](k3s-operations.md)) present it like any other
operation, with these additional observations:

| Observation | Content |
| --- | --- |
| `bootstrap-recipe` | The complete manifest and selection the operation was bound to |
| `bootstrap-host` | One member's prerequisite facts and check results |
| `bootstrap-asset` | One asset's file identity and state on one member |
| `bootstrap-generation` | The generation directory and, on completion, its marker |

The completion marker lists every asset with its size, digest and file
identity and carries `inactive: true`. A succeeded operation means every member
holds a complete verified generation and every host writer was retired. It does
not mean K3s is installed or any service is ready.

## When something fails

A failed prerequisite stops the operation before it acquires any host, so the
remedy is provisioning, followed by a new preparation. A failure after a host
was acquired, such as a lost connection during a transfer, leaves durable
records and possibly a partial generation. `operation resume` observes those
records without downloading, publishing or deleting anything, and preparation
failures never receive a retry proposal. Once the previous operation is settled,
run a new preparation; it allocates a fresh generation and leaves the earlier
directory in place. Do not remove or edit files under `/var/lib/broil/k3s`
by hand.
