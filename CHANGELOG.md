# Changelog

## v0.2.0 - 2026-11-23

- Add `secrets` commands for SOPS/age encrypted stores, with injection into launched commands, users and teams, rotation with resume and rollback, and optional OpenBao vault access.
- Add `image` commands that build project images and their inferred dependencies on BuildKit builders, publish them to OCI registries, and keep immutable artifact records.
- Add `k3s` commands that create and manage K3s clusters on declared machines, with server and agent membership, networking, ingress, and private-CA certificates.
- Add a managed, authenticated registry for K3s targets, replicated to every member so that each node pulls images from its local copy.
- Add recorded K3s application releases with digest-bound images, delivery to every required node, health checks, and rollback.
- Add drain, removal, and replacement of K3s cluster members, and bounded K3s operation history with pruning.
- Raise the minimum supported Rust version to 1.87.
- Add reproducible packaging of a Linux `tar.gz` release archive whose `broil` binary can be verified by rebuilding it.

## v0.1.0 - 2026-08-31

- Add project-local configuration, environment selection, and `run`/`env` commands for repeatable scripts.
- Add `get` for inspecting resolved project state.
- Add root and environment aliases plus discoverable executable command groups.
- Add deterministic command resolution and config-independent `help` and `version` commands.
- Add remote inventory management with SSH, execution, transfer, trust, readiness, statistics, and provisioning workflows.
- Add protected provisioning with secret input, bounded authentication failures, and a startup progress watchdog.
- Adopt Apache-2.0 licensing and carry third-party notices with the source.
