# Remotes

Broil remote management runs against the inventory owned by the active
environment. Set `BROIL_ENV` to a non-empty configured environment before any
remote operation:

```sh
BROIL_ENV=prod broil remote list --all
```

There is no separate remote environment flag. When `--file <path>` selects a
project, ambient `BROIL_ENV` still selects that project's remote inventory.

## Inventory

Project-level `remote` definitions are reusable building blocks:

- defaults
- secret providers
- authentication profiles
- privilege profiles
- jump hosts
- remote scripts
- provisioning profiles
- machine templates

Machine instances live only under `environments.<name>.remote.machines`:

```yaml
remote:
  auth_profiles:
    deploy-key:
      user: deploy
      public_key:
        identities:
          - agent:
              fingerprint: SHA256:replace-with-your-key
  privilege_profiles:
    sudo:
      method: sudo

environments:
  prod:
    remote:
      machines:
        app-1:
          address: app-1.example.invalid
          canonical_auth: deploy-key
          privilege: sudo
          tags: [app]
```

Each environment owns its own machines. A project-level machine template can be
reused by many environments, but it is not itself a target.

## Selectors

Remote commands select declared machines by exact logical name, exact address,
exact tag, or explicit `--all`:

```sh
BROIL_ENV=prod broil remote check --machine app-1
BROIL_ENV=prod broil remote stats --tag app
BROIL_ENV=prod broil remote list --all
```

Repeated machine selectors form a union. Repeated tags narrow the selected set.
`--all` is mutually exclusive with machine and tag selectors. `remote ssh`
selects exactly one machine.

## Commands

`remote list` is network-free. Add `--plan` to inspect the effective
provisioning plan without contacting machines.

```sh
BROIL_ENV=prod broil remote list --all --plan
```

`remote trust` enrolls or replaces host-key trust for selected machines or one
jump host.

```sh
BROIL_ENV=prod broil remote trust --machine app-1 --fingerprint SHA256:...
```

`remote check` reports operational and security readiness. `remote stats`
reports resource state.

```sh
BROIL_ENV=prod broil remote check --all --format json
BROIL_ENV=prod broil remote stats --tag app
```

`remote ssh` opens an interactive session. By default it delegates to system
OpenSSH with canonical public-key authentication. `--bootstrap` uses Broil's
automation backend for an explicit bootstrap session.

```sh
BROIL_ENV=prod broil remote ssh --machine app-1
```

`remote exec` runs an argv command or one shell body:

```sh
BROIL_ENV=prod broil remote exec --machine app-1 -- uname -a
BROIL_ENV=prod broil remote exec --machine app-1 --shell -- 'printf "%s\n" "$HOSTNAME"'
```

`remote run` runs a configured remote script:

```sh
BROIL_ENV=prod broil remote run --tag app -- deploy --dry-run
```

`copy-to` and `copy-from` transfer files or recursive directories over SFTP:

```sh
BROIL_ENV=prod broil remote copy-to --machine app-1 -- ./dist/app /opt/app/bin/app
BROIL_ENV=prod broil remote copy-from --machine app-1 -- /var/log/app ./logs
```

Use `--recursive` for directories and `--overwrite` for existing destinations.
Uploads can set `--mode`; privileged uploads can also set `--owner`.

`remote provision` runs configured provisioning profiles:

```sh
BROIL_ENV=prod broil remote provision --machine app-1
```

Provisioning may enable SFTP so Broil can perform safe file transfer. A
successful provisioning run must prove canonical public-key access,
public-key-only server policy, SFTP availability, and every configured security
verifier before configure steps continue.

## Secrets And Privilege

Secrets are referenced by named providers. Do not put secret values in config,
arguments, reports, or scripts.

Privilege profiles currently use `sudo`. Commands that accept a privilege
profile name resolve it per target before dispatch. `remote run` uses only the
selected remote script's privilege setting.

## Reports And Parallelism

Most networked multi-target commands accept `--jobs <number|all>` and
`--fail-fast`. Reports written with `--report <path>` contain selected targets,
durations, steps, statuses, and categorized failures without secrets or command
bodies.
