# Broil

Broil is a project-local command runner for scripts, environment shells,
configuration inspection, and remote machine operations.

## Build From Source

Broil is a Rust workspace. Use Rust 1.85 or newer:

```sh
cargo build --release -p broil
```

The built binary is `target/release/broil`.

## Quickstart

Create `broil.yaml` or `broil.yml` at your project root:

```yaml
env_vars:
  APP_ENV: dev
scripts:
  test: "cargo test"
  serve: "cargo run"
environments:
  prod:
    env_vars:
      APP_ENV: prod
aliases:
  t: run test
```

Run a script:

```sh
broil run test
```

Open an environment shell, or run one command inside an environment:

```sh
broil env prod
broil env prod broil run serve
```

Inspect resolved project state:

```sh
broil get root
broil get name
broil get --json cfg scripts
```

Use aliases and executable commands for shorter project workflows:

```sh
broil t
broil db migrate
```

Remote operations use the active `BROIL_ENV` inventory:

```sh
BROIL_ENV=prod broil remote list --all
BROIL_ENV=prod broil remote check --all
```

## Guides

- [Scripts and environments](docs/scripts-and-environments.md)
- [Aliases](docs/aliases.md)
- [Executable commands](docs/executable-commands.md)
- [Get](docs/get.md)
- [Command resolution](docs/command-resolution.md)
- [Remotes](docs/remotes.md)
- [Remote example templates](docs/examples/remotes/README.md)
