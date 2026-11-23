# External shared store

Merge `broil.yaml` into the consumer project next to the `shared-secrets` checkout.
`../shared-secrets/secrets` resolves from that project's root, independently of the
caller's directory. It needs no `init`: use an authorized existing store,
identity and recipient rules. Replace the illustrative identity `alice` with
your own configured identity. No key or encrypted set is supplied here.

The 30 exports illustrate a consumer's `vault-fetch-secrets.sh` replacement:
`REPORTING_DB_PASS` shares `db_pass`, `MYSQL_ROOT_PASSWORD` shares
`blog_database_password`, and the database URL substitutes the literal
`db_pass` key. `DOCKER_REGISTRY_PASSWORD` reads the explicitly qualified
`_shared/registry` set. Templates cannot substitute another export name.

```sh
broil get --json cfg secrets
broil get --json cfg environments.ci.secrets
broil secrets check --set app/dev --local
broil env ci your-command
broil secrets export --set app/ci --format sh
```

Root selection is `dev`; environment `ci` overrides it. Export `--set` changes
default-set references only, retaining the shared registry reference. Broil
does not interpret consumer-specific vault environment overrides; translate
selection explicitly. Configuration inspection works even when the sibling
store is absent; operational reads require its files and authorized identity access.

To use vault-first reads, add the [guide's vault configuration](../../../secrets.md#optional-vault)
to this same `secrets` mapping. Leave it absent for local-only operation.
Commit writes in the store checkout and have recipients pull them; Broil
does not perform either Git step. See the [migration map](../../../secrets.md#migration-map)
for login, another export recipe, mobile assets and administration.
