# Secrets and optional vault access

Broil stores secrets as native SOPS YAML encrypted to age recipients. The
store can live in the project or at an absolute or project-relative path in
another checkout. Distribution is manual: commit and distribute the changed
store files after a write.

Start with the [in-project](examples/secrets/in-project/README.md) or
[external-store](examples/secrets/external-store/README.md) example. The latter
demonstrates a complete consumer export mapping. Existing users can go to the
[migration map](#migration-map), [teams](#users-and-teams),
[rotation](#rotation-and-recovery), or [manual SOPS migration](#manual-selector-migration).

## Store, selection and configuration

The store contains these paths; names in angle brackets describe your own files:

| Path | Purpose |
| --- | --- |
| `.sops.yaml` | Ordered public creation rules and age recipients |
| `broil-secrets.yaml`, `teams.yaml` | Public team definitions and membership |
| `keys/<name>.pub`, `keys/<name>.key.age` | Public recipient and encrypted identity |
| `credentials/<name>.yaml`, `policies/*.hcl` | Encrypted vault credentials and public ACLs |
| `handlers/<type>` | Executable rotation actions and verification |
| `<project>/<set>.yaml`, `<project>/<set>/<name>.yaml` | Ordinary and nested encrypted sets |
| `_shared/<set>.yaml` | Cross-project encrypted sets |

Only ordinary project and `_shared` YAML files are enumerated and synced.
Administration files are excluded; a non-SOPS YAML file in data scope is an
error. Broil reserves top-level `_broil` for rotation and `sops` for format
metadata. Ordinary names such as `jwt_signing_key_previous` have no special
meaning. Key operands are literal names, including dots, not traversal paths.

`store` defaults to `broil/secrets`, resolved from `BROIL_ROOT`; absolute paths
and `../shared-secrets/secrets` work. Configured paths do not expand `~` or variables.
`project` defaults to the root directory's basename. `--set dev` selects
`<project>/dev`, while `--set app/dev` or `--set _shared/registry` is already
store-relative. Omit the `.yaml` extension. Explicit export/provider `set`
fields always require a qualified store-relative name. The current CLI rejects
option-shaped `--set` values starting with `--`; use a qualified project/set
selector for such a set.

Secrets commands select root configuration plus nonempty ambient `BROIL_ENV`,
even with `--file`. An unknown environment fails before access. Selection is
explicit `--set`, then effective `secrets.set`, then that environment's name;
there is no implicit `dev` when none is available. Store-wide administration
needs no default set. Root/environment fields overlay, while exports merge by
name and each environment entry replaces that whole root declaration.

Configuration inspection does not read the store or vault, acquire an identity,
or prompt. It shows declarations, not execution overlays or resolved values:

```sh
broil get --json cfg secrets
broil get --json cfg environments.ci.secrets
```

## Identity and access

Identity precedence is nonempty `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, configured
`secrets.identity`, nonempty `BROIL_SECRETS_IDENTITY`, the sole encrypted
identity in `keys/`, then interactive selection. Raw inputs accept age key-file
syntax with multiple identities; a relative `SOPS_AGE_KEY_FILE` uses the caller's
working directory. A failed explicit source never falls through. Configuration
identity takes precedence over the identity environment variable.

Named encrypted identities use nonempty `BROIL_SECRETS_PASSPHRASE` or hidden
private-terminal input. Supply environment secrets through your protected
launcher or credential manager; never type a passphrase into command arguments
or shell history. `--non-interactive` forbids all name/passphrase prompts and
does not make a new human identity or a hidden-value write unattended.

Private identities and credentials must be regular, safely opened files with
the required owner and private permissions; symlink traversal is rejected.
Use owner-only mode 0600 for these files and protect their directories. Git
does not preserve private read permissions: restore them after a fresh checkout.
Public recipients/rules and shared set ciphertext may be readable by others.
Recipients receive changes by pulling the store and acquiring their own
passphrase separately. Broil never commits, pushes or pulls for them.

## Local startup and explicit output

```yaml
secrets:
  store: broil/secrets
  project: app
  identity: alice
  set: dev
  inject: true
  exports:
    TOKEN: token
    DATABASE_URL:
      set: app/dev
      template: 'postgres://app:${db_password}@localhost/app'
environments:
  dev: null
```

Initialize an absent or empty store, then create its first set:

```sh
broil secrets init --identity alice
broil secrets set token --set dev
broil secrets set db_password --set dev
```

Init asks for and confirms a hidden passphrase. It creates a passphrase-encrypted
identity, its public recipient, the project directory, and a project creation
rule. It refuses populated stores. It creates no empty secret document.
`set --set` creates a missing document only when its final path has a valid
creation rule. Existing files are authenticated before modification.

Set values come from the private terminal, never arguments or operational
stdin. Empty input skips a set. A nonempty value requires confirmation and is
stored as a string, preserving its whitespace. Values are limited to 1 MiB;
EOF, Ctrl-C, or Ctrl-D cancels. `--non-interactive` refuses commands that need
these prompts. Without `--set`, guided set visits only the configured project's
sets: exact `dev`, `ci`, `test`, then other identifiers in byte order, with
exact `prod` last. A default set does not change this guided behavior.

Read a value explicitly or launch a consumer:

```sh
broil secrets get token
broil secrets export --format sh
broil env dev your-command
```

`get` and `export` intentionally reveal values on stdout. `env` export format
is a literal line format and should not be sourced as shell code. Shell export
format quotes values literally, including quotes and newlines.

`get --plain` adds one command newline to a string's exact bytes; `--json`
encodes the actual value as JSON. Use JSON decoding when saving exact file
contents, including trailing newlines. `list` prints names, and `list --slots`
adds names of local pending/previous slots without their values. `check --local`
validates sets and applicable exports; `check --all --local` checks every
ordinary set. `check` can reject a readable set's unsupported rotation layout;
it does not repair it. Every leaf has config-independent immediate `--help`.

## Exports and child injection

Declare `VAR: key`, `VAR: {set: app/dev, key: key}`, or
`VAR: {template: 'literal ${key}', set: app/dev}`. Template `set` is optional.
Keys in placeholders are ASCII identifiers; `$$` emits a literal dollar sign.
Placeholders refer directly to secret keys in one set, never other exports,
shell expressions, defaults or cross-set interpolation. Templates do not URL
encode: the database-URL example assumes a password suitable for a URI; encode
it in the consumer if arbitrary password characters need escaping.

`export --set` changes only default-set references. All declarations must
resolve to nonempty scalars before any output or launch. Strings preserve
bytes; booleans/numbers use compact JSON spelling. Nulls, objects, arrays and
NUL-bearing values cannot become environment variables. `--format json` is a
sorted object of names to strings; `--format env` refuses CR/LF-bearing values.
Explicit export works independently of `inject`. Templates are bounded to
64 KiB, individual scalars to 1 MiB, and total rendered exports to 16 MiB.

Automatic injection requires effective `inject: true`. It applies to `run`,
both `env` modes, and executable commands. Every export must resolve completely
before a child or rcfile is created. Exports replace configured environment
variables; Broil's reserved variables keep their final precedence. An
environment can override injection and individual declarations. With `--file`,
run and executable injection use root configuration; explicit `env <name>`
uses that environment. Secrets command leaves retain their separate ambient
`BROIL_ENV` selection rule.

Help, version, configuration inspection, remote local children, and the
internal editor do not resolve exports. The five credential inputs
`SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, `BROIL_SECRETS_IDENTITY`,
`BROIL_SECRETS_PASSPHRASE`, and `BAO_TOKEN` are filtered from inherited child
environments. A caller's already-exported ordinary variables remain ordinary
inherited environment, including secrets the caller previously exported.

## Local writes and editor exposure

Edit and update recipients with:

```sh
broil secrets edit --set dev
broil secrets rekey --all
```

Edit selects nonempty `VISUAL`, then `EDITOR`, tokenizes it as literal argv,
and appends the absolute edit filename. It does not evaluate shell expressions
in the editor setting. The editor runs in the caller's working directory with
the filtered ordinary environment. An unchanged edit makes no store change.
An editor failure or invalid edit leaves ciphertext unchanged. Broil preserves
reserved rotation data and refuses changes to keys with active rotations.

Editing requires usable tmpfs, preferring `/dev/shm`, then `XDG_RUNTIME_DIR`.
The file is mode 0600 inside a private 0700 directory, removed with its sibling
files after success or failure where possible. Configure editors to disable
swap, backup, persistent undo, and history files: files written elsewhere and
editor subprocesses are external exposure. The editor's own terminal output
is also outside Broil's diagnostic handling.

For Vim, an explicit literal-argv setting disables startup customizations,
swap, backups, persistent undo and viminfo history for this invocation:

```sh
VISUAL='vim -u NONE -i NONE -n -c "set nobackup nowritebackup noundofile"' broil secrets edit --set dev
```

An injected interactive shell instead prefers `XDG_RUNTIME_DIR`, then
`/dev/shm`, and falls back to the existing `TMPDIR`/system-temp location when
neither is usable. Its rcfile uses the same private modes and literal quoting,
and cleanup is attempted after the shell exits or launch fails. A killed
process may leave a plaintext rcfile, including on persistent storage after
fallback. Tmpfs can swap; process environments, child output, crash dumps,
and external editors are not erasure guarantees.

Writing leaves operate locally even when vault configuration is present, and
do not sync implicitly. Use `secrets sync` to publish local values to a vault.

Rekey uses the final-path creation rules and changes recipient wraps without
changing user values or existing value ciphertext. Removing a recipient does
not revoke access to copies of older ciphertext. Files authenticated under
either pinned SOPS interpretation can be read, but every mutation requires
compatibility with both. Incompatible files remain read-only, including for
editor no-ops and rekey; selector migration is a separate manual operation.

Writes use a local store lock and private ciphertext replacement with fsync.
A batch can partially complete: check the reported changed paths, failing path,
and any “may have changed” disposition before retrying. After partial init,
inspect the created skeleton and resolve it manually before another init.
`--quiet` suppresses only the commit reminder. It does not hide changed paths,
partial failures, or cleanup failures. Broil does not run Git or promise
cross-checkout atomicity.

## Optional vault

Add a vault address to enable vault-first reads and injection:

```yaml
secrets:
  store: broil/secrets
  project: app
  set: dev
  identity: alice
  vault:
    address: https://vault.example.test
    mount: secret
    credential: credentials/alice.yaml
    fallback: none
```

The server must already be initialized, with an AppRole auth method and a KV v2
mount. Broil does not deploy or initialize OpenBao or provision TLS. Use HTTPS
in production: certificate trust comes from the operating system, including
hostname verification. There is no verification bypass. Plain HTTP is supported
for isolated development and CI. Requests have a 20-second connect budget and a
60-second whole-request budget; Broil ignores proxy environment settings and
never follows redirects or automatically retries writes.

The credential file is private SOPS YAML containing string `role_id` and
`secret_id`, with optional `unseal_key`. Its default path is
`credentials/<resolved-identity>.yaml`; raw age keys without an available
identity name require an explicit credential path. Credential paths are relative
to the store and must pass private-file ownership, permission, and symlink checks.
Identity acquisition keeps the local source precedence described above.

A nonempty ambient `BAO_TOKEN` takes precedence over AppRole login and is never
revoked by Broil. A nonempty ambient `BAO_ADDR` overrides a selected vault but
does not enable ordinary vault reads in a local-only project. Explicit `login`
and `vault` commands can select that address independently. A sealed server
needs the selected credential's unseal key; Broil rechecks health after unseal.
`vault status` reads health without opening credentials or changing seal state.

```sh
broil secrets vault status
broil secrets vault unseal --non-interactive
broil secrets login --non-interactive
broil secrets sync --all --non-interactive
broil secrets vault exec -- your-vault-client arg1 arg2
```

`login` deliberately prints just a token and newline, and hands that token to
the caller. Failure diagnostics include one `failure class:` line. Status 3
means rejected AppRole login or no usable returned token; 4 means unavailability
or server 5xx; identity unlock/decryption failures use 1 and `identity-decrypt`.
Other runtime failures use 1 and `runtime`; usage uses 2 and `runtime`. A caller
that refetches credentials must distinguish `identity-decrypt` from other
status-1 failures. An output/flush error cannot retract bytes a sink accepted.

Other consumers revoke tokens they mint before completing. Reads and exports
finish cleanup before exposing prepared values; a revocation failure aborts
that consumer. Vault exec transfers address and token only to the immediate
child, launches argv without a shell in the caller's directory, and preserves
the child's exit status even if revocation fails. Its child environment follows
ordinary run selection, including `--file` suppression of ambient execution
`BROIL_ENV`; secret configuration still uses its separate ambient selection.
No automatic export injection occurs in this child. Interrupt/termination
handling reaps the direct child and attempts bounded revocation. Uncatchable
process death can leave a minted token live; child processes and deliberate
stdout consumers control their own copies.

Vault reads remain scoped to existing, structurally valid local set files.
They need no local decryption authority when a caller token succeeds. Missing
sets cannot become vault-only reads; use an external client under vault exec
for vault-only paths. `--local` forces local reads. Explicit `fallback: local`
allows fallback for network unavailability and generic 5xx only. Denials,
missing paths, invalid credentials, malformed data, TLS failures, and integrity
errors fail hard. A sealed or uninitialized server is not a fallback success.

Sync authenticates one local set at a time and writes only user data to its
complete KV path, including nested identifiers. It excludes administration files,
SOPS metadata, and the whole top-level `_broil` subtree. Ordinary `_previous`
keys and nested user mappings remain data. Sync never pulls values into the
store or deletes vault-only paths. It stops at the first failure and reports
completed set identifiers; success prints `ok`. Retire legacy whole-document
sync scripts on stores with rotation data because they can publish `_broil`.
Broil sync after a legacy upload repairs the current KV user data; it cannot
retract prior exposure, KV history or copies already consumed. After OLD_REVOKED,
the retained previous rotation value may already be a revoked credential.
`vault status` reports `reconcile_needed: true|false` only after complete drift
inspection with available authority; `unknown` makes no drift claim.

## Users and teams

After init, establish explicit public administration metadata. In the store,
`broil-secrets.yaml` can define a local-only starting policy:

```yaml
version: 1
teams:
  operators:
    policies: []
    decrypt: all
  developers:
    policies: []
    decrypt: [app/dev]
  machines:
    policies: []
    decrypt: [app/ci]
    machine_passphrase_file: _shared/build-machine.yaml
    service_account: true
```

Create `teams.yaml` with `alice: [operators]`, matching the initialized
`keys/alice.pub` and Alice's acquired private identity. Init alone does not
grant administration authority. A `decrypt: all` team defines operators;
scoped `decrypt` lists grant exact sets, not future descendants. Add an
operator-readable public creation rule for `_shared/build-machine.yaml`
before creating the machine record: init's project rule does not cover it.
Use your real public recipients in `.sops.yaml`, preserving first-match order.

Every identity and credential needs an unambiguous membership owner. Operators
receive every managed set and credential; credentials otherwise belong only
to their user. Memberships combine scopes. A vault-first team may have an empty
local decrypt list; vault policies and age recipients are separate access
controls. With a vault, supply actual `policies/<name>.hcl` and list those names
under the appropriate team. Empty policies grant no implicit vault admin rights.
Migrate existing operator credentials/policies explicitly before administration;
do not try to adopt orphaned files by rerunning `user add`.

```sh
broil secrets user add bob --team developers
broil secrets user add build-agent --team machines --machine --non-interactive
broil secrets user list
broil secrets user rename bob robert
broil secrets user remove robert --yes --non-interactive
broil secrets vault reconcile
```

Adding a team to an existing user preserves its identity and credential IDs;
duplicate membership is a validated no-op. New humans choose and confirm a
hidden passphrase. A machine gets a generated passphrase stored only in the
encrypted `{name, passphrase}` record and configured KV path. One team supports
at most one machine; that machine belongs to exactly one machine-capable team.
Humans may share that team. Machine status comes from authenticated records,
not team names. The record must be readable independently of the machine
identity it unlocks, by operators and any configured consumers.

`service_account: true` controls periodic vault tokens (8760h), independently
of machine identity handling. Ordinary roles use 24h/72h TTLs. Broil creates
`approle-<user>` and a `rotate-<user>` self-rotation policy alongside the team's
policy union. CI-variable publication, renewal and cleanup of consumer-held
tokens remain the consumer's responsibility.

To rotate a human, select that human's current identity and run
`broil secrets user rotate bob`; a fresh confirmed passphrase needs a terminal.
Configured identity wins over `BROIL_SECRETS_IDENTITY`, so use the human's own
configuration rather than expecting that variable to override an operator.
For machines, an operator runs
`broil secrets user rotate build-agent --machine --non-interactive`.
Replacement decryption and, with a vault, direct replacement AppRole login are
verified before old access is retired. Human self-service does not accept an
operator key or ambient token in place of the current private identity.

Rotation retains the AppRole/role ID and unrelated SecretIDs. Removal deletes
the whole managed user; removing an operator requires a surviving operator's
key. Rename preserves the local age key/passphrase but a vault rename must
verify the newly named role before retiring the old one. Before retirement,
failed changes attempt restoration and cleanup. Once old role/SecretID
retirement succeeds or becomes uncertain, keep the verified replacement and
repair forward. Inspect reported completed/uncertain changes and retained
encrypted recovery before retrying; do not overwrite a concurrently changed
store with an old snapshot. Historic ciphertext and independently issued
bearer tokens retain their own access/expiry/revocation lifetimes.

`vault reconcile` displays policy/role-setting drift and asks before applying
it; `--yes --non-interactive` explicitly permits unattended application. It
preserves role IDs and SecretIDs, does not create missing roles or edit local
recipients, and reports partial writes for repair/rerun. An empty diff needs no
confirmation. Lifecycle and reconcile vault failures never become local
success through `fallback: local`.

## Rotation and recovery

Rotation works with a local store alone. A configured vault adds mandatory
sync/readback during promotion and restoration; vault failure then blocks
progress even with ordinary-read fallback configured. Vault availability does
not replace service-specific action and verification.

Install and configure the [example handlers](examples/secrets/handlers/README.md)
or your own executable protocol, and select a configured local deploy script:

```yaml
secrets:
  rotation:
    deploy: deploy
```

With an existing `db_pass`, a configured `db-password` handler and deploy script:

```sh
broil secrets rotate new db_pass --set dev --generator hex:32 --type db-password
broil secrets rotate status db_pass --set dev
broil secrets rotate resume db_pass --set dev
broil secrets rotate rollback db_pass --set dev
```

`hex:<n>` and `base64:<n>` encode that many random bytes. `ssh-ed25519` creates
an OpenSSH Ed25519 private key and prints only its public key to stderr;
`prompt` uses hidden terminal input; `handler` obtains a framed candidate from
the chosen handler. Candidates must be nonempty UTF-8 without NUL, at most
1 MiB. Broil preserves final CR/LF bytes; arbitrary binary data needs an
explicit consumer encoding such as base64.

| State | Required effect and proof |
| --- | --- |
| CREATED | Persist the initial marker, generate and verify candidate, then encrypt pending |
| TRANSITION_READY | Make the external service accept candidate alongside old access; verify |
| STORE_UPDATED | Atomically move old current to previous and promote pending; sync if configured and prove local/vault current |
| DEPLOYED | Run the deploy hook or operator deployment; prove consumers use candidate |
| OLD_REVOKED | Revoke old external access and prove rejection |
| VERIFIED | Prove final health, then remove marker and previous unless retained |

The public marker is MAC-covered inside the SOPS document; pending/previous
are encrypted under `_broil.rotation`. Rotation requires a compatible
`unencrypted_suffix` policy, with encrypted concrete slot paths, a plaintext
MAC-covered marker and no `mac_only_encrypted` declaration. Other selector
modes can remain usable for ordinary secrets while refusing rotation. Broil
does not silently change protection rules to make a set rotatable.

The cursor under `$XDG_STATE_HOME/broil/rotations/<store-hash>/` (default
`$HOME/.local/state`) contains metadata only. The store marker controls resume;
a stale cursor is rebuilt. `status` needs no identity and explicitly reports
`authenticated: false`; it is not proof that the recorded state is authentic.
A cursor without a marker is historical and cannot restart a rotation.

Failed gates retain the marker and relevant slots. Resume requires the recorded
operator/host; `--force` allows a warned takeover without bypassing authentication
or gates. CREATED replay regenerates or repeats the idempotent creation action
with its persisted ID. STORE_UPDATED replay repeats only sync/readback, never
promotion. Other external steps verify before repeating actions where possible;
hooks must tolerate retries. The recorded environment and handler configuration
must remain available. No-handler rotations require explicit human gates;
`--non-interactive` cannot skip them. Handler/deploy calls in that mode have a
five-minute bound; descendants and external effects remain the handler's work.

Before promotion, rollback keeps old current and undoes external steps. After
promotion it first restores current and proves local/configured-vault access,
then undoes external steps. Interrupted rollback records its remaining reverse
calls. At OLD_REVOKED or VERIFIED, including in-progress states, rollback
requires the handler's explicit recreation capability. The shipped examples
declare none. A revoked credential cannot be made usable by changing local
data alone.

`--keep-previous` retains the encrypted previous slot after success;
`broil secrets rotate clear-previous db_pass --set dev` removes it only when
there is no active marker. `broil secrets rotate cleanup db_pass --set dev
--force` abandons that key's local slots/marker without revoking external
objects or syncing. Inspect the provider and plan a fresh rotation/recovery
before using this escape.

Handler values travel on stdin, never Broil argv/environment. Handler stderr,
client subprocesses, files, logs and memory are external exposure. Provider
creation interrupted before candidate/note persistence may leave an orphan;
check the provider even when no pending slot exists. The legacy shim preserves
the original handlers and their client-argv/environment exposures. Its legacy
handler-generated SSH path loses a final LF in the source's command substitution;
use Broil's covered `--generator ssh-ed25519 --type legacy-ssh` path with the
configured SSH adapter instead. See [adapter setup](examples/secrets/handlers/README.md#legacy-adapter).

Use one coordinating operator for a shared store. Pull before starting, inspect
markers, and distribute every changed encrypted/public file as required by the
deployment. Local locks do not coordinate unpulled checkouts; Git distribution
and service deployment are separate from store promotion. Ordinary overlap
keys, such as JWT current/previous keys, remain application-managed user keys;
internal rotation slots are never injected or synced to consumers.

## Remote store providers

Remote password, key-passphrase, sudo and provisioning secret-stdin consumers
can select a store key without exporting it into general child environments:

```yaml
secrets:
  store: ../shared-secrets/secrets
  project: app
remote:
  secret_providers:
    sudo-password:
      store: {key: deploy_password}
    shared-passphrase:
      store: {key: ssh_passphrase, set: _shared/ci}
  privilege_profiles:
    sudo: {method: sudo, password: {secret: sudo-password}}
```

The remote-inventory environment selects the secrets overlay, including with
`--file`. Explicit provider sets are always qualified. Each consumer resolves
freshly through the same local/vault policy and token cleanup; inspection does
not resolve providers. Values preserve exact scalar bytes without a command
newline; sudo still refuses CR/LF-bearing passwords. See the
[remote guide](remotes.md).

## Manual selector migration

Broil authenticates files under either pinned SOPS 3.9.4/3.13.1 interpretation,
but every mutation requires the original and output to be compatible with both.
Some Unicode selectors differ between the pins. Editing `.sops.yaml`, running
`updatekeys`/rekey, deleting divergent keys, or opening/closing Broil's editor
does not migrate an incompatible original; even a no-op edit is refused.

Migration is a deliberate whole-document decrypt/re-encrypt operation outside
Broil. Work on an authorized copy with protected temporary plaintext and
independently available intended recipients:

1. Preserve original ciphertext, creation rules and recipient set. Authenticate
   and decrypt with the capable pinned SOPS binary, without disabling MAC checks.
2. Choose a selector accepted by both pins without exposing any formerly encrypted
   value or comment. A default `_unencrypted` suffix is suitable only after
   checking keys and every ancestor for accidental plaintext coverage.
3. Encrypt a separate candidate with the same recipients and the portable rule.
   Pass the actual final filename, rooted at the selected configuration's
   directory, through SOPS `--filename-override`; the scratch candidate filename
   must not choose its recipient/protection rule.
4. Authenticate the candidate under both pins and Broil. Compare ordered typed
   values, mapping/sequence order, comments and their attachment, and actual
   encryption coverage. Verify each intended recipient's access. A single `get`
   or `check` success is insufficient to establish whole-document equivalence.
5. Only after all checks pass, deliberately replace the original ciphertext and
   distribute the matching public rules. Remove temporary plaintext promptly.
   Any failed check leaves the originals and their rules in place.

There is no Broil migration
command. A public comment/selector declaration or a SOPS scalar type label does
not acquire extra cryptographic authentication from profile agreement. Tmpfs can swap and crash dumps, editor state and
external SOPS processes retain their own plaintext exposure boundaries.

## Migration map

This index maps existing store, application, mobile and infrastructure workflows
to Broil commands. Adoption happens in each consumer repository; Broil does not
rewrite deployment scripts or publish CI variables.

| Existing workflow | Broil destination and remaining responsibility |
| --- | --- |
| `vault-login.sh`, `lib/vault-auth.sh` | `secrets login --non-interactive` for an actual credential helper; apply the status/cache mapping below and clean up handed-out tokens |
| `bao.sh` | `secrets vault exec -- bao ...`; Broil owns cleanup of tokens it mints |
| `dump-vault-keys.sh` | `secrets list --set app/dev` and explicit `get` for store-backed data; `vault exec -- bao kv list secret/_shared/tls` / `kv get` for vault-only data |
| `lib/age-expect.sh` | Protected `BROIL_SECRETS_PASSPHRASE` input; no expect process is required to unlock a native identity |
| Machine passphrase acquisition helper | `secrets get passphrase --set app/dev/dev-user --json` from independent operator access, then consumer-owned JSON decoding and private cache management |
| Consumer `vault-fetch-secrets.sh` | Explicit export declarations; [external-store recipe](examples/secrets/external-store/broil.yaml) and another consumer map below |
| `--dump-env`, consumer vault environment overrides | `export --format sh` for shell source; explicit `--set`/environment selection; no automatic recognition of old variable names |
| Mobile `fetch-mobile-secrets.sh` | `get --json` plus the checked consumer-side asset writer below; APNs upload and build signing remain external |
| `sync-to-openbao.sh` | `secrets sync --set app/dev` or `--all`; retire the whole-document uploader on rotated stores because it exposes `_broil` |
| `set-project-secret.sh`, `sops-bulk-set.sh` | `secrets set <key>` guided across project sets, or `--set` for one set, with hidden input and confirmation |
| `rename-vault-key.sh` | `secrets edit --set app/dev` to rename the literal user key, then explicit `sync --set app/dev` where configured; user rename changes an identity instead |
| `rotate.sh`, four type handlers | `secrets rotate` and [installed handlers/legacy shim](examples/secrets/handlers/README.md); service proof and application overlap keys remain explicit |
| `add-vault-user.sh`, `lib/vault_user.py` / `TEAM_MAP` | Explicit `broil-secrets.yaml`/`teams.yaml` bootstrap, then `user add <name> --team <team>` |
| `remove-vault-user.sh`, `vault-list-users.sh` | Whole-user `user remove` with confirmation, or `user list` |
| `rotate-vault-credentials.sh`, user-name migration | `user rotate` or `user rename` with verified replacement and partial-recovery handling |
| `remove-vault-role.sh` | Per-team operator procedure below; preserve identity, remaining scope and machine/operator ownership |
| `lib/reconcile-approle.sh` | Public policy/membership edits followed by `vault reconcile`; local decrypt revocation additionally needs recipient edits/rekey |
| CI credential generation helpers | Machine/service-account `user add`/`user rotate`; publish needed credentials through the CI provider's own protected interface |
| `init-openbao.sh`, `renew-certs.sh` | OpenBao deployment/initialization and certbot/TLS remain external |
| TLS pull / `tls_vault_credential_helper` | `login` helper or `vault exec -- bao kv get secret/_shared/tls/...`; vault-only TLS paths are not implicit local sets |
| Kubernetes `render-secrets.sh` | Feed explicit exports to the renderer; mapping, output-file permissions and deployment remain consumer work |

### Login status and the consumer passphrase cache

| Failure | Legacy login | Broil login | Cache decision |
| --- | --- | --- | --- |
| Identity decrypt/passphrase | 2 | 1 plus exact `failure class: identity-decrypt` line | Refetch |
| AppRole rejected/no token | 3 | 3 | Retain legacy refetch handling |
| Vault unavailable/5xx | 4 | 4 | Keep cache and stop |
| Usage | Script-specific | 2 | Keep cache and fix invocation |
| Other runtime/config/I/O | Script-specific | 1 plus `failure class: runtime` | Keep cache and fix cause |

Replacing an old `2|3)` refetch arm with an unconditional `1|3)` would discard a
valid cached passphrase on unrelated errors, including a broken `broil.yaml`.
This Bash sketch sets `refetch_cache` only for the intended classes. Configure
`machine-broil.yaml` with the machine's named identity, credential and store;
set `BAO_ADDR` to that same selected vault. `PASSPHRASE_CACHE` is an existing
private, trusted file. Run with shell tracing disabled:

```bash
umask 077
unset BAO_TOKEN SOPS_AGE_KEY SOPS_AGE_KEY_FILE
export BAO_ADDR=https://vault.example.test
login_diag=$(mktemp /dev/shm/broil-login.XXXXXX) || exit 1
trap 'rm -f -- "$login_diag"; unset token cached_passphrase' EXIT
cached_passphrase=$(cat -- "$PASSPHRASE_CACHE") || exit 1
[ -n "$cached_passphrase" ] || exit 1
rc=0
token=$(BROIL_SECRETS_PASSPHRASE="$cached_passphrase" \
  broil --file machine-broil.yaml secrets login --non-interactive \
  2>"$login_diag") || rc=$?
unset cached_passphrase
refetch_cache=false
if [ "$rc" -eq 0 ]; then
  BAO_TOKEN="$token" bao token revoke -self >/dev/null || exit 1
elif [ "$rc" -eq 3 ] || { [ "$rc" -eq 1 ] && \
     grep -Fxq 'failure class: identity-decrypt' "$login_diag"; }; then
  refetch_cache=true
else
  cat -- "$login_diag" >&2
  exit "$rc" # Keep the cache for runtime/config/I/O or availability failure.
fi
unset token
# Continue the caller's existing cache/refetch flow using refetch_cache.
```

The independent operator that fetches the machine record must be able to
decrypt it without first unlocking that same machine. For exact cache bytes,
decode JSON `get` output instead of shell-stripping a plaintext result's final
newlines. `login` transfers token ownership: a discarded successful token can
remain live. Prefer `vault exec` when no standalone token is needed. Shell
variables, the external `bao` client and process death retain their own token
exposure/cleanup limits.

### Consumer export maps

The external-store example includes a shared registry object, duplicate password
aliases and a literal-key database template. A separate application can use this
`exports` mapping with `project: app`:

```yaml
exports:
  APP_TELNYX_API_KEY: telnyx_api_key
  APP_FCM_SERVICE_ACCOUNT: fcm_service_account
  APP_MAILGUN_API_KEY: mailgun_api_key
  APP_MAILGUN_WEBHOOK_SIGNING_KEY: mailgun_webhook_signing_key
  APP_MODERATION_AI_API_KEY: moderation_ai_api_key
  APP_CSAM_HASHLIST_CREDENTIAL: csam_hashlist_credential
  APP_MINIO_ROOT_USER: minio_root_user
  APP_MINIO_ROOT_PASSWORD: minio_root_password
  APP_MINIO_SERVICE_ACCESS_KEY: minio_service_access_key
  APP_MINIO_SERVICE_SECRET_KEY: minio_service_secret_key
  APP_MINIO_MODERATION_READONLY: minio_moderation_readonly
  APP_MINIO_BACKUP_READONLY: minio_backup_readonly
  APP_MEDIA_URL_SIGNING_KEY: media_url_signing_key
  APP_TURN_STATIC_AUTH_SECRET: turn_static_auth_secret
  APP_PAYMENT_PROCESSOR_API_KEY: payment_processor_api_key
  APP_JWT_SIGNING_KEY_CURRENT: jwt_signing_key_current
  APP_JWT_SIGNING_KEY_PREVIOUS: jwt_signing_key_previous
  APP_POSTGRES_APP_PASSWORD: postgres_app_password
  APP_REDIS_PASSWORD: redis_password
  APP_CDN_API_TOKEN: cdn_api_token
  APP_PHONE_HASH_HMAC_KEY: phone_hash_hmac_key
  APP_SERVICE_API_KEY: service_api_key
  DOCKER_REGISTRY_PASSWORD:
    set: _shared/registry
    key: docker_hub_password
```

Place it inside `secrets`; both JWT keys remain ordinary consumer data. Select
`app/ci` explicitly when a CI process otherwise runs a dev environment.
Map legacy `local` to `dev` in configuration as the external-store
example does. Broil does not read consumer run-mode or vault override variables
automatically.

For consumers that need a sourced shell snapshot, capture successfully before
evaluation, without ignoring a producer failure in process substitution:

```sh
secret_exports=$(broil secrets export --set app/ci --format sh) || exit 1
eval "$secret_exports"
unset secret_exports
```

Only evaluate Broil's successful `sh` output from your trusted configuration.
`env` is for literal line consumers; it is not interchangeable with shell code
or every dotenv parser. A baked `--dump-env` replacement is still a plaintext
artifact: create it privately, exclude it from Git/build logs and distribute
it through the consumer's protected channel. Injection avoids the intermediate
file when the service can be launched through `broil env` or `broil run`.

### Mobile asset writer

Use this Python 3 consumer recipe from a trusted, owned mobile application working
tree with Broil configuration pointing at the shared store. Choose `app/dev`,
`app/test` or `app/prod` explicitly for the intended build. It reads and
decodes all three values before replacing any output, preserves decoded bytes,
stages private files beside their targets, and keeps values out of diagnostics:

```python
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile

selected_set = "app/prod"
assets = [
    ("google_services_json", "android/app/google-services.json", False),
    ("google_service_info_plist_b64", "ios/App/GoogleService-Info.plist", True),
    ("android_upload_keystore_b64", "android/app/upload.keystore", True),
]
os.umask(0o077)
prepared, staged = [], []
try:
    for key, filename, encoded in assets:
        result = subprocess.run(
            ["broil", "secrets", "get", key, "--set", selected_set,
             "--json", "--non-interactive"],
            stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=180,
        )
        value = json.loads(result.stdout)
        if not isinstance(value, str) or not value or "\0" in value:
            raise ValueError("invalid asset")
        data = base64.b64decode(value, validate=True) if encoded else value.encode("utf-8")
        if not data:
            raise ValueError("empty asset")
        prepared.append((Path(filename), data))
    for target, data in prepared:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".broil-asset-", dir=target.parent)
        staged.append((Path(temporary), target))
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    for temporary, target in staged:
        os.replace(temporary, target)
except Exception:
    raise SystemExit("Asset preparation/publication failed; inspect destination paths before retrying.") from None
finally:
    for temporary, _ in staged:
        temporary.unlink(missing_ok=True)
```

A read/decode failure leaves destinations unchanged. Separate file replacements
are not a multi-file transaction: an I/O failure during publication can leave
a partial set. Use trusted nonsymlink parent paths and existing build exclusions;
new output files are mode 0600. Python buffers, build tools, persistent output
and crash residue are outside Broil's protected holders. Review/logging tools
must not collect these assets.

`apple_apns_auth_key_b64` remains a manual Firebase/APNs upload and is not
written by this recipe. Decode it only for that authorized operation. Feed
`android_keystore_password` through an explicit export to the build consumer's
protected input/environment contract; configure Gradle signing to read that
input. Do not place it in a Broil value argument or secret-bearing Gradle argv.
Broil provides no `export --decode`, `--out` or automatic mobile file writer.

### Removing one team while retaining the user

The legacy `remove-vault-role.sh` removes team policy access while retaining
identity and role. Broil has no team-removal leaf. For an ordinary user who will
retain another membership, a coordinating operator can:

1. Snapshot public manifests/rules and encrypted files, inspect remaining scope
   and obtain independent operator/recovery access. Exclude concurrent writers.
2. Remove only the chosen membership from `teams.yaml`, preserving explicit
   ownership, the remaining team union, identity and credential records.
3. If local access must also shrink, update affected `.sops.yaml` rules to remove
   the recipient only where no remaining membership grants access; include
   shadowed/future rules. Preserve operators and unrelated external recipients.
   Run `broil secrets rekey --all` and verify retained access to each intended
   set. Reconcile alone does not perform recipient changes.
4. With a vault, run `broil secrets vault reconcile` and inspect the proposed
   policy union/TTL changes. Use `vault exec -- bao ...` for an explicitly
   planned low-level operation without a dedicated leaf. Verify resulting
   access with the retained user credential and handle previously issued tokens
   separately. Distribute the changed store and inspect any partial failure.

Do not delete a user's final membership while leaving unowned keys/credentials.
Retain a deliberate team with appropriate scope, or choose confirmed whole-user
removal if that is the intent. Operator demotion requires a surviving operator
and recipient updates across all managed sets/credentials, including future
rules. Machine membership changes additionally need a consistent authenticated
record, exactly one machine-capable membership, unique record ownership and
independent decryption. These final/operator/machine cases require a specific
recovery plan before edits; the ordinary-user sequence is not universal.
`user remove` is not a shortcut for retaining a user with less team access.
