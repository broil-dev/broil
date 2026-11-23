# Rotation handlers

Copy this whole directory when installing the examples: the four extensionless
entrypoints use `_example.py`. Python 3 is required; DB operations use `psql`,
and SSH operations use OpenSSH. Configure actual service accounts, targets and
proofs before use. These are interactive examples, with separate action and
verification gates. They refuse missing proof under `--non-interactive` and
declare no post-revocation recreation capability.

For example, after copying the directory to `broil/secrets/handlers`, configure
an existing local deploy script:

```yaml
secrets:
  project: app
  store: broil/secrets
  set: dev
  rotation:
    deploy: deploy
```

Start a DB password rotation with
`broil secrets rotate new db_pass --generator hex:32 --type db-password`.
Use `--generator handler --type api-key` for a provider-assigned API key,
`--generator ssh-ed25519 --type ssh-key` for SSH, or
`--generator base64:32 --type inter-service-token` for a receiver token.
No value belongs in a Broil argument or configuration field.

Broil writes the initial marker before invoking a handler. It passes the
candidate through stdin, followed by EOF without an extra newline. The handler
receives `<STATE> <action|verify|rollback>` appended to its configured argv.
The only capability invocation is `capabilities`, with empty stdin; these
examples return `{"recreate":[]}`. Broil owns STORE_UPDATED and deploy dispatch.
Handler verification must prove external effects even when a deploy hook exits
successfully.

For handler generation, CREATED action stdout contains
`BROIL_ROTATION_VALUE_BYTES=<positive decimal byte count>` followed by LF and
exactly that many UTF-8 value bytes. An optional trailer is LF,
`BROIL_ROTATION_NOTE=<public note>`, and LF. Value bytes may contain final
newlines or text that resembles the trailer; only the byte count separates
them. Built-in generation permits empty CREATED action stdout or the note line
alone. Notes are explicitly non-secret, single-line, NUL-free and at most
4096 bytes. All candidates are nonempty, NUL-free UTF-8, bounded to 1 MiB.
Broil discards other handler stdout. Stderr is the handler's public operator
channel and must not contain values.

Handler metadata is `BROIL_ROTATION_ID`, `BROIL_ROTATION_KEY`,
`BROIL_ROTATION_SET` (store-relative identifier), `BROIL_ROTATION_PROJECT`,
`BROIL_ROTATION_TYPE`, `BROIL_ROTATION_STATE_FILE`, `BROIL_ROOT`, the recorded
`BROIL_ENV` when present, and the persisted `BROIL_ROTATION_NOTE` when present.
`BROIL_ROTATION_NON_INTERACTIVE=1` forbids manual prompts. Ordinary env_vars
come from the recorded environment. Automatic secret exports and ambient
credential inputs are excluded. The ID is persisted by Broil; handlers must
reuse it rather than derive a new name from the date or set path.

Noninteractive callbacks have a five-minute execution bound. Broil interrupts
and reaps the direct child on cancellation or failure. Descendants retaining
pipes cannot hold the parent open indefinitely; descendants and other external
side effects remain the handler's responsibility.

## Service-specific steps

| Example | Required setup and proof |
| --- | --- |
| DB password | Set `ROTATION_DB_HOSTS` (space-separated), `ROTATION_DB_USER` and optionally `ROTATION_DB_NAME`; illustrative defaults are `db-primary.example.test db-secondary.example.test`, role `app` and database `postgres`. Supply the postgres administrator's own client authentication outside Broil's handler environment. CREATED upserts `<user>_r<ID>` on every host and proves candidate login. The user must be a lowercase ASCII SQL identifier of at most 39 bytes, keeping the full role at most 63 bytes. TRANSITION_READY prepares consumers to deploy using the temporary role. OLD_REVOKED updates the original role, requires verified consumer migration back to it, then drops the temporary role. Confirm old-password rejection on every host. |
| API key | Create/test a key at the actual provider and prove both keys work before promotion. Verify consumers, revoke the old key and test its rejection. A provider-assigned key created before Broil persists its value/note may be orphaned; inspect the provider dashboard after an interrupted CREATED action or rollback. |
| SSH key | Set `ROTATION_SSH_TARGET` to a known, verified host; ordinary OpenSSH host-key verification remains enabled. Install the public key on every target alongside old access, verify real candidate login and consumers, then remove/test old access. |
| Inter-service token | Configure the receiver to accept both tokens and prove that behavior before promotion; deploy senders, then remove the old token and prove rejection. |

Before promotion, rollback retains the old current value. After promotion,
Broil first restores current, synchronizes a configured vault and proves the
restoration before any external rollback callbacks. The examples require the
operator to undo external changes/redeploy as needed. They never claim revoked
credentials have automatically become usable again. `cleanup --force` removes
local recovery data and does not revoke external access.

## External storage and process boundary

The examples are separate processes. Python, Bash, provider clients and their
subprocesses own the values they receive; Broil does not erase their memory or
logs. The DB example supplies PGPASSWORD only to its own verification subprocess
and sends password-bearing SQL through that client's stdin; configure server
and client logging appropriately. Avoid shell tracing.

The SSH example stores private material in an owned 0700 ID-named directory,
preferring `/dev/shm`; private files are mode 0600. It removes its files after a
successful VERIFIED verification or CREATED rollback. A missing tmpfs uses the
system temporary directory with an explicit residue warning. Crashes, failed
cleanup, swap and dumps may leave material. Inspect only the identified
handler-owned directory after recovery; never remove unrelated temporary files.
The public key is safe to display. `ssh-keygen` here is an external handler
tool; Broil's built-in `ssh-ed25519` generator runs natively.

## Legacy adapter

The shim supports only the four reference profiles `db-password`, `api-key`,
`ssh-key` and `inter-service-token`, with the callback contract below. Configure
an explicit profile and its unchanged source file; arbitrary scripts are not
supported. For example:

```yaml
secrets:
  rotation:
    handlers:
      legacy-db:
        - docs/examples/secrets/handlers/legacy-shim.sh
        - db-password
        - /path/to/shared-secrets/secrets/handlers/db-password.sh
      legacy-ssh:
        - docs/examples/secrets/handlers/legacy-shim.sh
        - ssh-key
        - /path/to/shared-secrets/secrets/handlers/ssh-key.sh
```

Invoke `--type legacy-db` with a generator. The shim resolves the DB user from
the source's non-mutating prologue with a placeholder role, then exports the
validated `<lowercase-user>_r<recorded-ID>` before real dispatch. A 40-byte user
is refused. Moving the set or resuming on another day does not change the role.

The reference files use different phase meanings from Broil. This is the
mapping, including the callback exclusions needed to preserve store ownership:

| Broil step | DB / API references | SSH / token references |
| --- | --- | --- |
| CREATED | Source action/verify; capture the shell variable after action | Same; reconstruct SSH public/temp metadata between calls |
| TRANSITION_READY | Source verify_created plus explicit dual-access proof; no legacy store edit or vault read | Source transition action/verify |
| STORE_UPDATED | Broil only | Broil only |
| DEPLOYED | Broil deploy, then source verify_store_updated | Broil deploy, then source verify_deployed |
| OLD_REVOKED | Source action_deployed/verify_deployed, then old_revoked action/verify; DB consumers move back before temporary-role deletion | Source old_revoked action/verify |
| VERIFIED | Source verify_final, followed by applicable temp cleanup | Same |
| Rollback | Source rollback_created for creation residue; explicit wrapper proofs for other external undo | Same; no source callback that requests store restoration |

The shim reserves stdin for exact candidate bytes, routes legacy manual reads
through `/dev/tty`, and discards source function stdout. This prevents the
reference token handler's printed value from entering Broil output or notes.
With a supplied built-in candidate, API/token/SSH creation never regenerates it.
SSH uses a private ID-derived directory so CREATED verification/replay does not
need an unpersisted note. Later temporary material is reconstructed from the
candidate, and successful verification/rollback cleans it.

The reference source files themselves still export values and some pass values
to their own client argv. Those source-side exposures remain external to Broil;
the shim preserves source bytes and does not claim to harden those clients.
The legacy SSH handler's own command substitution strips the final LF when it
generates a key. Its handler-generated path therefore does not preserve exact
key bytes. Configure the SSH adapter and use Broil's built-in
`--generator ssh-ed25519 --type legacy-ssh` path, which the adapter tests cover;
the unchanged source is not silently repaired by the shim.
Manual steps require a terminal and real operator proof. Unknown profiles or
callback mappings fail explicitly. Do not use the legacy whole-document
`sync-to-openbao.sh` on rotated stores: it would expose the reserved rotation
subtree; use `broil secrets sync`.

Broil's test fixtures pin the four inspected source files by SHA-256;
automated tests verify source identity, callback order, both DB hosts, framing, private-terminal gates and
absence of legacy store/vault calls.

### Updating an installed copy

Finish or roll back active rotations with the installed copy and its recorded
configuration before replacing it, changing handler types or changing DB
settings. Then update configuration paths to `legacy-shim.sh` and the chosen
handler types, and configure real DB hosts/users before starting new work.
The native examples' illustrative DB defaults do not override the adapter's
unchanged source defaults; configure each installation explicitly.

The renamed adapter uses `broil-legacy-ssh-<recorded-ID>` for its own temporary
directory. It does not migrate or sweep temporary material created by older
copies. Let each old copy perform its own cleanup; after recovery, inspect only
its identified handler-owned residue, including persistent-temp fallback files.
