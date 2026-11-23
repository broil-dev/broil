# Managed builder adapter

[`ubuntu24.py`](ubuntu24.py) is the supplied lifecycle adapter for a dedicated
BuildKit OCI-worker service on Ubuntu 24.04 x86_64 with systemd. Broil invokes
it through a declared remote script and records the resources it owns. It does
not provision a machine or establish its SSH trust for you.

Prepare the machine with [Broil's remote workflow](../../remotes.md), including
its canonical public-key authentication, host-key trust and explicit privilege
profile (or a root account). The machine needs Python 3, systemctl and the
OpenSSH SFTP server. The adapter checks its prerequisites before lifecycle
work. Keep the declared builder inside that environment's own inventory.

Load the adapter's complete source into a `remote.scripts` entry's `body`,
preserving its shebang. Set `pty: never`; use the same explicit privilege when
the script declares one. Set the managed builder's `lifecycle_script` to that
script name. Public archive and CA
uploads use the canonical account; lifecycle operations use the selected
privilege. TLS certificate/key references use the selected native secret store.

## Obtain the BuildKit archive

From a download directory on the controller, with curl and sha256sum installed:

```sh
curl --fail --location --output buildkit-v0.24.0.linux-amd64.tar.gz \
  https://github.com/moby/buildkit/releases/download/v0.24.0/buildkit-v0.24.0.linux-amd64.tar.gz
printf '%s  %s\n' af8064eca16077b4d6937745988ba2d2dfa439540874cdcd918318315f3ba1d3 \
  buildkit-v0.24.0.linux-amd64.tar.gz | sha256sum --check
```

Continue only after the checksum passes. The expected archive and member
identities are in [manifest.json](../../../tools/image-builder/manifest.json).
Broil verifies the archive before transfer, and the adapter verifies the archive
and selected members before installation. No build command downloads a missing
archive. Pass the verified file's absolute path to `image builder setup` or
`image builder reconcile`; see [the command examples](../../images.md#access-and-manage-builders).

Setup creates an owned `broil-builder-<owner>.service` and a dedicated
`/var/lib/broil/builders/<owner>/` tree. The local ownership record is under
the selected project's `state/builders/`. Repeated setup preserves unchanged
configuration and cache. Reconciliation uses the original interrupted intent;
a held lock reports busy instead of waiting indefinitely.

ARM64 emulation is opt-in through `--arm64-emulation`. The pinned emulator is
part of the verified archive; advertising a platform is not itself proof that
it can execute. Ordinary removal retains cache/storage. `--purge` authorizes
deleting the verified owned storage; inspect ownership before choosing it.
Changed identities, unknown entries or mounts need an operator decision.

Private daemon keys remain in root-owned TLS generations for the service's
lifetime. Deleting a file does not promise erasure from memory or storage.
Modified adapters need their own support evidence. Keep source and configuration
with your operational record.
