# Secret-store examples

- [In-project store](in-project/README.md): start with an empty destination and
  create a local encrypted store through Broil.
- [External store](external-store/README.md): point at a sibling checkout and
  map application variables, a shared registry credential and a derived URL.
- [Rotation handlers](handlers/README.md): install and configure service-specific
  actions and verification, including the legacy adapter.

These files contain public configuration and placeholders only. Identity files,
encrypted sets and build assets are created in the operator's own project; none
are shipped here. Read the [guide and migration map](../../secrets.md) before
adopting an example. Config inspection needs no store or identity:

```sh
broil --file docs/examples/secrets/in-project/broil.yaml get --json cfg secrets
broil --file docs/examples/secrets/external-store/broil.yaml get --json cfg secrets
```
