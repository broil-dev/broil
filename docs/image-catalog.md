# Image catalogs

Broil loads image, builder, and registry declarations from the project config,
including fragments and `$extends`. Inspect them with the existing `get cfg`
command:

```sh
broil get --json cfg images
broil get cfg images.app.context
broil get --json cfg environments.ci.images
```

Catalog names use ASCII letters, digits, underscores, and hyphens, beginning
with a letter or digit. Absent or null catalogs inspect as `{}`. Every declared
definition is validated, including definitions in unselected environments.
Unknown fields, malformed references, and incorrect types report a config path.

## Example

```yaml
builders:
  shared:
    kind: external
    endpoint: tcp://builder.example.test:1234
    tls:
      ca: broil/tls/ca.pem
      certificate: {set: demo/ci, key: build_client_certificate}
      key: {set: demo/ci, key: build_client_key}
registries:
  release:
    endpoint: https://registry.example.test
images:
  app:
    image: registry.example.test/demo/app:dev
    builder: shared
    registry: release
    context: app
    args: {MODE: release}
    platforms: [linux/amd64, linux/arm64]
environments:
  ci:
    images:
      app:
        image: registry.example.test/demo/app:ci
        builder: shared
        output: {type: oci-layout, path: broil/artifacts/app-ci}
```

Loading and inspection do not open the source context, Dockerfile, certificate,
SSH socket, output destination, or secret store. Endpoint declarations do not
contact or provision a service. The example can therefore be inspected before
these inputs exist. The [image command guide](images.md) explains graph analysis,
builds, publication, records, recovery and builder operations.

## Declarations and selected values

`get cfg` preserves declared strings, sequences, tags, and digest pins. It
materializes accepted nullable mappings, but does not select an operational
environment or substitute effective defaults. Read environment declarations
through literal `environments.<name>...` paths, even with an unknown ambient
`BROIL_ENV` or an explicit `--file`.

The image selection API takes an explicit environment name after config loading.
Absent/empty selects root; unknown names fail. A named environment replaces
each same-named catalog definition as a whole. Empty environment catalogs retain
root entries. This differs from `$extends`, which merges declarations before
schema validation. Root-origin references resolve against the selected catalogs.

Effective defaults apply after replacement: context `.`, Dockerfile inside that
context, platforms `[linux/amd64]`, registry output, and persistent builder cache.
An explicitly supplied Dockerfile resolves from `BROIL_ROOT`, as do all other
relative paths. Paths are normalized lexically; shell variables and `~` remain
literal. Capability and filesystem checks belong to the consuming operation.

Producer output identities normalize Docker Hub/library shorthand and implicit
`latest`. Duplicate identities fail. Tags remain case-sensitive; a declared
tag plus `sha256` digest retains both. Registry/cache references must match the
named endpoint authority, and a cache write cannot overwrite a producer's
repository/tag even if that producer also declares a digest pin.

## Registry and protected references

Credentials are explicit `{set, key}` references, with a store-relative
project/set and literal key. Inline values and default-set shorthand are invalid.
Builder TLS, registry purposes, instruction secrets, and SSH forwarding retain
separate declarations; parsing never acquires their values.

Registry auth purposes are `metadata`, `pull`, `cache_read`, `cache_write`, and
`push`. Each entry declares unique normalized repositories on its endpoint and
either a token reference or a public username plus password reference. Different
repositories/purposes at one endpoint are legal. Overlapping exact scopes in
different definitions fail, even if their secret references are identical.

A password entry may permit one exact same-origin token realm and service.
The realm needs a canonical non-root path; a different scheme or effective port
is a different origin. A static token cannot declare token-service permission.
HTTP requires explicit `development_http: true`. No challenge-derived trust or
credential fallback is implied.

Selected registry policy keeps credentials and transport trust together.
An explicit registry reference uses its own declaration. Implicit metadata/base
selection requires one applicable credential candidate or an unambiguous
anonymous transport policy. Anonymous policy is decided before acquisition;
it is not a response to credential failure.

Managed builder declarations name an environment-owned remote machine and
optionally an effective privilege profile. These references are checked only
when managed work consumes the builder. An unused managed declaration does not
prevent root-only work with an external builder. Equal machine names in two
environments refer to separate inventory entries.

Managed lifecycle operations also require `lifecycle_script` to name an
effective `remote.scripts` entry. Existing declarations without that field keep
their TLS client access. The [builder guide](../tools/image-builder/README.md)
describes the supplied Ubuntu adapter, pinned archive, ownership records,
reconciliation and cache-preserving removal. External builders use endpoint
inspection without acquiring machine lifecycle ownership.
