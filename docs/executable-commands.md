# Executable Commands

Executable commands are project-local files under `broil/bin/`. They are
discovered automatically and do not need config entries.

```text
broil/bin/
  db/
    migrate
  lint
```

Invoke them by path segments:

```sh
broil lint
broil db migrate --dry-run
```

## Eligibility

Each command or group name must be a valid alias segment:

- non-empty UTF-8
- no `.`
- not starting with `-`
- digits are allowed

An entry must be executable. A file is selected as a command. A directory is a
command group and must be addressed by its full chain.

Ineligible entries are ignored during lookup. If lookup reaches a group and the
next segment is missing or unknown, Broil reports a command-chain usage error.

## Runtime Context

Broil launches the selected file directly from the project root. Remaining CLI
tokens are passed as child arguments exactly as supplied.

Executable commands use the same local execution environment rules as
`broil run`: root and active environment variables are applied, and
`BROIL_ROOT` plus optional `BROIL_ENV` are supplied to the child.

## Precedence

Executable commands are the final provider. A complete built-in command wins
first. A complete alias wins next. Partial built-in and alias paths can still
fall through to executable lookup.
