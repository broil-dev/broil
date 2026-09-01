# Command Resolution

Broil resolves a command by finding a complete command path.

## Rules

1. Complete built-in commands win first.
2. Complete configured aliases win next.
3. Eligible executable files under `broil/bin` are tried last.
4. Groups are prefixes, not commands.
5. Once a command is selected, it owns every remaining token.
6. Aliases expand once and then skip alias lookup.

Built-in matching happens before config loading. Help and version forms that do
not need project config run immediately. Other complete built-ins, partial
built-ins, and unknown command paths load and validate config before aliases or
executable commands can run.

Executable lookup is lazy. Broil does not inspect `broil/bin` after a complete
built-in or alias is selected.

## Built-In Boundaries

| Built-in | Complete forms | Partial forms |
| --- | --- | --- |
| `run` | `run --help`; otherwise `run <script>` for any first operand | bare `run` |
| `env` | `env --help`; otherwise `env <name>` for any first operand | bare `env` |
| `get` | `get --help`, `get root`, `get name`, `get cfg <dot.path>` | bare `get`, missing or unknown selector |
| `remote` | `remote --help`, `remote <verb> --help`, recognized `remote <verb>` | bare `remote`, unknown second token |
| `help` | `help [topic]` | none |
| `version` | `version` | none |
| root shorthand | `--help`, `--version` | none |

Only an invocation with no arguments prints general help before option parsing.
After `--file <path>` is consumed, a missing command is a usage error.

Command-local help is recognized only at its documented position. For example,
`broil run --help` prints run help, while `broil run build --help` passes
`--help` to the `build` script.

## Coexistence

A complete built-in wins over an alias or executable with the same path.
Partial built-ins continue to aliases and executable commands:

| Setup | Invocation | Result |
| --- | --- | --- |
| Alias leaf `get.report` | `broil get report` | Alias leaf |
| Built-in `get name` and alias `get.name` | `broil get name` | Built-in |
| File `broil/bin/get/nodes` | `broil get nodes` | Executable, when no alias leaf completes |
| Top-level alias leaf `run` | `broil run` | Alias leaf |
| Alias child `run.quick` | `broil run quick` | Built-in `run <script>` |

A shorter alias leaf wins before executable lookup when no built-in completes.
For example, alias leaf `db` receives `migrate` from `broil db migrate` and
therefore shadows executable path `db/migrate`.

Expanded aliases use built-ins first and executable commands second. Appended
arguments can complete a built-in operand or an executable command group chain.

## Diagnostics

If no command is selected, Broil reports the most specific available diagnostic:

1. executable command group failure;
2. retained built-in partial;
3. retained alias partial;
4. generic unknown command.

Usage diagnostics exit `2`. Runtime failures, such as unreadable config or
failed executable launch, exit `1`.
