# Managed BuildKit builders

The `broil_command::images::builders` API manages one declared machine through
its configured `lifecycle_script`. The supplied adapter is
[`ubuntu24.py`](../../docs/examples/builders/ubuntu24.py), for Ubuntu 24.04,
x86_64, systemd, Python 3 and the installed OpenSSH SFTP server. The canonical
account needs its configured public-key authentication and explicit sudo
privilege, or root authentication. Provision these prerequisites with the
existing remote-machine workflow before setup.

Load the adapter's complete text as the `body` of a `remote.scripts` entry and
set the managed builder's `lifecycle_script` to that entry's name. Use its
shebang and `pty: never`. The script and builder must select the same explicit
privilege profile when the script specifies one. Public archive/CA uploads run
as the canonical account; lifecycle RPCs use the selected privilege.

Setup requires an absolute path to the independently downloaded BuildKit
archive in [manifest.json](manifest.json). For example:

```sh
curl --fail --location --output buildkit-v0.24.0.linux-amd64.tar.gz \
  https://github.com/moby/buildkit/releases/download/v0.24.0/buildkit-v0.24.0.linux-amd64.tar.gz
printf '%s  %s\n' af8064eca16077b4d6937745988ba2d2dfa439540874cdcd918318315f3ba1d3 \
  buildkit-v0.24.0.linux-amd64.tar.gz | sha256sum --check
```

Broil verifies the public archive before transfer. The adapter verifies the
archive and selected members before installing the dedicated OCI worker.
Set `arm64_emulation: true` in the typed setup request to install the pinned
BuildKit emulator; the default is false. The daemon advertises the configured
platforms, and acceptance also requires actual execution on those platforms.

Each installation owns `broil-builder-<owner>.service` and
`/var/lib/broil/builders/<owner>/`. Local ownership lives beneath the selected
project's `state/builders/`. Keep that record for inspection, reconciliation
and removal. A moved project or changed scope requires an explicit ownership
decision. Repeated setup preserves unchanged service configuration and cache.
Normal removal retains cache; a typed `purge: true` request authorizes removal
of that verified owned storage.

An interrupted operation retains its original intent. Use the typed reconcile
operation before continuing uncertain work. Reconciliation attempts the shared
lock without waiting and returns busy while the writer still owns it.
Unknown entries, changed identities, mounts and unresolved
ownership require operator resolution. Do not replace or rearm upload claims.

Server certificate/key values come from the selected native secret store and
travel through the private RPC input. The script, Python interpreter,
filesystem and BuildKit are external consumers. Installed keys remain in
root-owned private TLS generations for the daemon's lifetime; unlinking them
does not promise memory, journal, backup or device erasure. Public ownership
and upload records contain references and public metadata.

The supplied adapter's support evidence is tied to its source and configuration.
Modified scripts need their own evidence. Source, normal dependency closure,
private transport controls, writer/claim controls and production CI must pass
the code acceptance gate before this candidate is selected.
