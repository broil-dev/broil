# Image project example

This project shows two related images: `app` inherits `base` through its
Dockerfile. Broil infers that dependency from `FROM`; the configuration has no
dependency list. Building `app` schedules the required base automatically.
Explicitly requesting `base` too retains its output as a reusable OCI layout.

The supplied addresses and installation paths are placeholders. The project
contains no credential, private key or secret store. Configuration inspection
works as supplied; building requires your tools, endpoints and credentials.

## Inspect without installing build tools

From the repository root, with the Broil executable installed:

```sh
broil --file docs/examples/images/broil.yaml get --json cfg images
broil --file docs/examples/images/broil.yaml get --json cfg tools
broil --file docs/examples/images/broil.yaml get --json cfg environments.ci
broil --file missing image build --help
```

The first three commands print declarations without contacting endpoints,
opening contexts or secrets, or creating `state/`. The last command prints
static command help even though its configuration path does not exist.
The documentation CI checks these inspection paths; it does not build against
the placeholder endpoints.

## Build with your installation

Follow [the image guide](../../images.md#prepare-a-controller) to install and
declare the exact tool executables. Replace both endpoint hosts and the image
references, including `app/Dockerfile`'s `FROM`, consistently. Provide the
builder CA and the two declared TLS secret references, and configure registry
authentication for your repository if it requires it. The builder must support
the two declared image platforms; choose a smaller set if appropriate.

From this example directory, after completing those prerequisites:

```sh
broil image graph --target app --format json
broil image build --target app --target base --builder shared --format json
broil image record list --format json
broil image status --format json
```

Graph inspection may report a provisional dependency until the producer's
actual metadata is available. The build resolves it as the producer completes.
A successful build publishes `app` and retains `base` at `retained/base`.
The output directory must be absent before retention; a second retention at
the same path fails instead of replacing it. Read the build report before
choosing the next action.

`BROIL_ENV=ci` selects the `ci` overlay even with `--file`. Its registry tool
path replaces the root path; its whole `app` definition replaces the root
definition. The unchanged `base` definition is inherited. Inspection through
`get cfg` always shows declarations, not this operational overlay.

Retained content and immutable records remain after build cleanup. They are
your durable inputs for publication and inspection; do not put retained output
inside `state/workspaces` or `/dev/shm`. Successful builds remove their temporary
graph/node staging; node and closure paths in the report are historical locations.
Failed or uncertain cleanup keeps remaining owners visible in the report and
diagnostic. See [ownership and recovery](../../images.md#outputs-and-ownership)
before removing any example data you have built.
