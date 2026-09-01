# Scripts And Environments

Broil loads configuration from a project root. By default it searches upward
from the current directory for exactly one `broil.yaml` or `broil.yml`.

Use `--file <path>` before the command to select a config file directly:

```sh
broil --file ./ops/broil.yaml run build
```

## Scripts

Define local scripts under `scripts`:

```yaml
scripts:
  build: "cargo build"
  test: "cargo test"
```

Run a script with:

```sh
broil run build
broil run test -- --ignored
```

The first token after `run` is always the script name, except `--help`, which
shows command help. Later tokens are passed to the script.

## Environment Values

Root `env_vars` apply to local script execution. Environment `env_vars` overlay
root values when an environment is active:

```yaml
env_vars:
  LOG_LEVEL: info
environments:
  staging:
    env_vars:
      LOG_LEVEL: debug
```

Without `--file`, `broil run` uses a non-empty ambient `BROIL_ENV` when it names
a configured environment. With `--file`, local script execution ignores ambient
`BROIL_ENV`.

Broil always supplies `BROIL_ROOT` to child commands. It supplies `BROIL_ENV`
when an execution environment is active.

## Environment Shells

Open an environment shell:

```sh
broil env staging
```

Run one command inside an environment:

```sh
broil env staging broil run test
```

The first token after `env` is always the environment name, except `--help`.
Later tokens form the command to run inside that environment.

## Config Fragments

Broil also loads YAML fragments from `broil/cfg/` below the project root.
Fragment filenames map to nested config paths. For example,
`broil/cfg/environments.staging.env_vars.yaml` contributes to
`environments.staging.env_vars`.
