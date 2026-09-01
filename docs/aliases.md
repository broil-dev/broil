# Aliases

Aliases are configured shortcuts. They can live at the root config level or
inside an environment.

```yaml
aliases:
  t: run test
  db:
    migrate: run db-migrate

environments:
  staging:
    aliases:
      deploy: run deploy-staging
```

Invoke an alias by its full path:

```sh
broil t
broil db migrate
BROIL_ENV=staging broil deploy
```

## Arguments

Arguments after the alias path are appended to the configured command:

```yaml
aliases:
  test: run test
```

```sh
broil test -- --ignored
```

This expands once to `run test -- --ignored`.

## Environment Overlay

When ambient `BROIL_ENV` names a configured environment, that environment's
aliases overlay root aliases. Groups merge recursively; leaves replace leaves.

`--file <path>` still uses ambient `BROIL_ENV` to select aliases. It does not
make local script execution use that environment unless the expanded command
explicitly runs `env <name>`.

## Precedence

Broil tries complete built-in commands first, then complete aliases, then
eligible files under `broil/bin`.

Alias groups are prefixes. A group only selects a command when the full path
reaches a leaf. A shorter alias leaf owns the remaining arguments before
executable commands are considered.

After one alias expands, Broil skips alias lookup and resolves the expanded
tokens through built-ins and executable commands.
