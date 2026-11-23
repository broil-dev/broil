# In-project store

Copy `broil.yaml` into your own project (merge it with existing configuration).
Leave `broil/secrets` absent or empty. The adjacent `.sops.yaml` illustrates
public creation rules; do not copy it into the store before initialization.

From your project root, with Broil installed and a private terminal:

```sh
broil secrets init --identity alice
broil secrets set token --set dev
broil secrets check --set dev --local
broil env dev your-command
```

Init prompts twice for a new identity passphrase and creates its real public
recipient rule. Set prompts for the value and confirmation, then creates
`app/dev.yaml`. Replace `your-command` with a consumer that reads `APP_TOKEN`.
There is no vault configuration, so reads, injection and rotation use the local
store. A fresh `ci` set needs its own `set token --set ci` before CI consumers
can use it. Initialization does not configure teams or service handlers.

Commit and distribute the reported encrypted/public store changes yourself;
keep decrypted values and identity passphrases out of the repository. Each
recipient must pull updates and restore required private-file permissions in
their checkout. See [identity and team setup](../../../secrets.md#identity-and-access)
and [rotation](../../../secrets.md#rotation-and-recovery).
