# Get

`broil get` inspects resolved project state without launching a child process.

```sh
broil get root
broil get name
broil get cfg scripts
broil get --json cfg environments.staging.env_vars
```

## Selectors

`root` prints the resolved project root.

`name` prints the project root basename.

`cfg <dot.path>` prints a value from the resolved config after fragments and
inheritance are applied.

## Output Modes

`--plain` is the default. For strings, it prints the raw value. For mappings,
sequences, booleans, integers, and null, it prints compact JSON.

`--json` prints compact JSON for every value, including strings.

`--plain` and `--json` are mutually exclusive and must appear before the
selector.

## Dot Paths

Dot paths traverse mappings only:

```sh
broil get cfg scripts.build
```

Broil v1 does not provide escaping for config keys that contain `.` and does
not index sequences.

`get cfg` reads the normalized config. It does not apply an execution
environment overlay after dispatch.
