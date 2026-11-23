# Inspect K3s target declarations

Use Broil configuration inspection to review a cluster's declared members,
network, infrastructure services and credential references before preparing its
hosts. This guide covers declaration inspection. For what a host must provide
and how bootstrap assets are selected and verified, see
[prepare K3s hosts and bootstrap assets](k3s-bootstrap.md). For existing
metadata attempts, see [operation records and recovery](k3s-operations.md).
For a task path, use [create a target](k3s-create.md),
[inspect and manage it](k3s-manage.md),
[publish to its registry](k3s-registry-publish.md), then
[deploy applications](k3s-releases.md). Upgrades, backup and restore
remain deferred; operation observation and bounded recovery are available. To join individual members of an existing
Broil-owned cluster, see [join the next server](k3s-server-join.md) and
[join declared agents](k3s-agent-join.md).

A **target** describes one cluster within an environment. Its **members** refer
to machines in that environment's remote inventory; each member has a server
or agent role and a Kubernetes node name. A supported declaration has one or
three servers, with additional agents when needed.

An optional **managed registry service** describes the installation and its
storage, which every member holds as a full replica; `registry.member` names the
initial writer that accepts pushes (see
[Run the replicated managed registry](k3s-registry.md)). Its `version` and `image` must name the Distribution build
that Broil pins; see [Prepare the service](k3s-operations.md#prepare-the-service).
Its **endpoint** names an entry in the existing `registries`
catalog, which describes the URL, trust and publication credentials used by
clients. For the managed registry, declare that entry's `ca` and port 443 before
you create the target; see [Prepare the endpoint](k3s-operations.md#prepare-the-endpoint).
Once the registry's principals are installed, the image commands publish
through that entry; see [Publish to the managed registry](k3s-operations.md#publish-to-the-managed-registry).
A node-access entry can also use an external registry without declaring a
managed service.

Credentials appear only as **protected references**, such as
`{set: example/lab, key: server-token}`. `set` names a store-relative secret set;
`key` is a literal key in that set. Server joins, agent joins, publication,
node pulls and recovery use separate references. See the
[secret-store guide](secrets.md) for storing the corresponding values.

## Inspect the example

Start from the source repository root with a built or installed `broil` binary.
The [example project](examples/k3s/README.md) contains one server, an off-node
backup declaration and a registry with separate publication, pull and
maintenance principals. Its addresses, paths, asset digest and public recovery
recipient are illustrative; no remote services or private keys are needed for
these commands.

```sh
broil --file docs/examples/k3s/broil.yaml get --json cfg environments.lab.k3s
broil --file docs/examples/k3s/broil.yaml get --json cfg environments.lab.k3s.demo.members
broil --file docs/examples/k3s/broil.yaml get --json cfg registries.local
```

The first result contains the `demo` target. The second shows its member's
machine, role, node name and network address. The third shows the endpoint and
publication references. Inspection loads the selected file and its fragments,
resolves `$extends`, and validates declarations. It does not open referenced
assets or secret stores, select credentials, contact endpoints or create
cluster state. Ambient `BROIL_ENV` does not change these explicit inspection
paths.

Optional mapping sections appear as empty objects when absent or null.
Operational defaults, such as timeouts, do not appear unless declared. A valid
projection establishes configuration syntax, not host availability, credential
validity, ownership or support for a particular execution profile.

## Organize your declaration

Place targets under `environments.<environment>.k3s.<target>`; a root `k3s`
section is invalid. Give each member a unique machine reference, node name and
IPv4 address. The backup machine must be outside that target's members. API
and registration endpoints require HTTPS and explicit ports, and their hosts
must appear in the API certificate names.

Bootstrap manifest and bundle paths are resolved below the selected project
root and refused outside it; other controller asset paths, such as a registry
CA file, start at that root when relative and may be absolute.
Remote storage paths must be absolute, without empty, `.` or `..` components.
Path text receives no shell, tilde or environment expansion. A registry storage
path must also lie outside the trees that K3s, kubelet and Broil own: see
[Prepare the storage member](k3s-operations.md#prepare-the-storage-member) for
the list and what every member needs. A registry's
`authentication.signing_key` must hold a key in the form that
[Generate the signing key](k3s-operations.md#generate-the-signing-key) describes,
and `authentication.signing_certificate` names that key's certificate
([Prepare the signer certificate](k3s-operations.md#prepare-the-signer-certificate)).
Declare both, and store the key, before you create the target: either one added
or changed later refuses `ownership`. Declare every `authentication.principals`
entry before then too: a principal added, removed or changed later refuses
`ownership`. Each principal's `password` must hold 1 to 72 bytes without a NUL
byte, and at most 8 principals, each with at most 64 repositories and a name of
at most 93 bytes, can be installed; see
[Prepare the principal passwords](k3s-operations.md#prepare-the-principal-passwords).

If inspection fails, use the reported configuration path to correct the
declaration, then repeat the same command. All declarations are validated,
including those outside the inspected target. Missing machine, script or
endpoint references are checked when an operational caller selects that target;
they do not require file or network access during inspection.
