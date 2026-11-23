// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::vault::{
    Session,
    json::{Text, Value},
    session::Credentials,
};

pub fn run(
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    inputs: CredentialInputs,
    interaction: &mut dyn Interaction,
) -> Report {
    let mut report = Report::default();
    report.error = perform(selected, options, cwd, inputs, interaction, &mut report).err();
    report
}

fn perform(
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    mut inputs: CredentialInputs,
    interaction: &mut dyn Interaction,
    report: &mut Report,
) -> Result<()> {
    let name = options
        .key
        .as_deref()
        .ok_or(Error::class("user required"))?;
    store::validate_component(name).map_err(Error::store)?;
    let store = Store::open(&selected.store_root()).map_err(Error::store)?;
    let lock = store.write().map_err(Error::store)?;
    let mut batch = lock.admin();
    let mut before = Roster::load(&mut batch)?;
    if !before.members.contains_key(name) {
        return Err(Error::class("unknown user").subject(name));
    }
    let address = if selected.config.vault.address.is_some() {
        Some(crate::vault::session::address(
            selected,
            &mut inputs,
            false,
        )?)
    } else {
        None
    };
    let caller = if address.is_some() {
        super::vault::caller(&mut inputs)?
    } else {
        None
    };
    let mut keys = identity::acquire(
        &store,
        cwd,
        selected.config.identity.as_deref(),
        inputs,
        options.non_interactive,
    )?;
    let operator = if options.machine {
        before.operator(&keys)?
    } else {
        keys.retain(|k| k.recipient().to_string() == before.recipients[name]);
        if keys.is_empty() {
            return Err(Error::class("a matching user identity is required"));
        }
        name.to_owned()
    };
    if !options.machine && options.non_interactive {
        return Err(Error::class("human rotation requires a private terminal"));
    }
    let classification = if options.machine || before.all(name) {
        before.classify(&mut batch, &keys, true)
    } else {
        before.classify_user(&mut batch, &keys, name)
    };
    classification.inspect_err(|_| {
        report.details.push("Machine classification failed; ask an operator to inspect the authenticated team records before retrying rotation.".into());
    })?;
    let machine_path = before.machines.get(name).cloned();
    if options.machine != machine_path.is_some() {
        return Err(Error::class(
            "machine classification requires a matching authenticated record and --machine; ask an operator to inspect the team record",
        ));
    }
    for team in &before.members[name] {
        if let Some(path) = &before.teams[team].machine_path {
            if batch.read(path, false).map_err(Error::store)?.is_none() {
                return Err(Error::class("machine classification record missing; ask an operator to inspect the team record").subject(path));
            }
        }
    }
    if let Some(path) = &machine_path {
        if before
            .ordinary(path)
            .iter()
            .all(|r| r == &before.recipients[name])
        {
            return Err(Error::class(
                "machine passphrase has no independent recipient",
            ));
        }
    }
    let pass = if options.machine {
        machine_passphrase()?
    } else {
        new_passphrase(interaction)?
    };
    let generated = Identity::generate().map_err(|_| Error::class("identity generation"))?;
    let recipient = generated.recipient().to_string();
    let raw = generated
        .encode()
        .map_err(|_| Error::class("identity encoding"))?;
    let encrypted = age::encrypt_with_passphrase(raw.as_str().as_bytes(), &pass)
        .map_err(|_| Error::class("identity encryption"))?;
    drop(raw);
    let opened = age::decrypt(&encrypted, &[], Some(&pass))
        .map_err(|_| Error::class("replacement identity verification"))?
        .into_secret()
        .map_err(|_| Error::class("replacement identity verification"))?;
    let reopened = age::parse_identity_file(&opened)
        .map_err(|_| Error::class("replacement identity verification"))?;
    if reopened.len() != 1 || reopened[0].recipient().to_string() != recipient {
        return Err(Error::class("replacement identity verification"));
    }
    drop(reopened);
    drop(opened);
    let mut after = before.clone();
    after.recipients.insert(name.into(), recipient.clone());
    batch
        .set(&format!("keys/{name}.key.age"), true, &encrypted)
        .map_err(Error::store)?;
    batch
        .set(
            &format!("keys/{name}.pub"),
            false,
            format!("{recipient}\n").as_bytes(),
        )
        .map_err(Error::store)?;
    let mut rules = Rules::load(&mut batch)?;
    rules.rotate(&before, name, &recipient)?;
    let affected = prepare_documents(
        &mut batch,
        &rules,
        &before,
        &after,
        name,
        &keys,
        machine_path.as_deref(),
        &pass,
    )?;
    batch
        .set(".sops.yaml", false, rules.encode()?.as_bytes())
        .map_err(Error::store)?;
    let mut remote = if let Some(address) = address {
        Some(Remote::prepare(
            &address,
            caller,
            selected,
            &before,
            name,
            &operator,
            &mut batch,
            &keys,
            &rules,
            machine_path.as_deref(),
        )?)
    } else {
        None
    };
    let result = (|| {
        batch.stage_recovery().map_err(Error::store)?;
        if let Some(remote) = &mut remote {
            remote.mint(&mut batch, &keys, &rules, report)?;
        }
        verify_candidates(
            &batch,
            &affected,
            &recipient,
            std::slice::from_ref(&generated),
            &keys,
            false,
        )?;
        batch.apply().map_err(Error::store)?;
        let machine_readers = if machine_path
            .as_ref()
            .is_some_and(|path| after.ordinary(path).contains(&recipient))
        {
            std::slice::from_ref(&generated)
        } else {
            &keys
        };
        if let Some(remote) = &mut remote {
            remote.publish_machine(&mut batch, machine_readers, report)?;
        }
        let replacement = if let Some(path) = &machine_path {
            let record = store
                .read(
                    &SetId::new(path.strip_suffix(".yaml").unwrap()).map_err(Error::store)?,
                    machine_readers,
                )
                .map_err(Error::store)?;
            let persisted = model::text(
                record
                    .get("passphrase")
                    .ok_or(Error::class("machine passphrase missing"))?,
            )?;
            if model::text(
                record
                    .get("name")
                    .ok_or(Error::class("machine name missing"))?,
            )? != name
                || persisted != pass.as_str()
            {
                return Err(Error::class("persisted machine record mismatch"));
            }
            if let Some(remote) = &mut remote {
                remote.check_machine_passphrase(persisted)?;
            }
            let protected = OwnedSecret::from_zeroizing(Zeroizing::new(persisted.to_owned()));
            drop(record);
            store
                .unlock_identity(name, &protected)
                .map_err(Error::store)?
        } else {
            store.unlock_identity(name, &pass).map_err(Error::store)?
        };
        if replacement.len() != 1
            || replacement[0].recipient().to_string() != recipient
            || store.recipient(name).map_err(Error::store)?.to_string() != recipient
        {
            return Err(Error::class("installed replacement identity mismatch"));
        }
        drop(pass);
        drop(generated);
        verify_candidates(&batch, &affected, &recipient, &replacement, &keys, true)?;
        drop(keys);
        if let Some(remote) = &mut remote {
            remote.verify_login(&store, &replacement)?;
            drop(replacement);
            batch.fresh().map_err(Error::store)?;
            remote.retire(report)?;
        }
        batch.fresh().map_err(Error::store)?;
        Ok(())
    })();
    let mut recovery = batch.cleanup_failed;
    report.cleanup_failed |= batch.cleanup_failed;
    if result.is_err() {
        if remote.as_ref().is_some_and(|r| r.retirement_attempted) {
            recovery = true;
            report.details.push("Old SecretID retirement succeeded or is uncertain; keep the verified replacement and finish recovery forward. Do not restore the old credential.".into());
        } else {
            let restored = batch.rollback().is_ok();
            recovery |= !restored;
            report.details.push(if restored {
                "Original local files restored where changed; old SecretID retirement was not attempted."
            } else {
                "Local restoration incomplete; retain encrypted recovery and inspect the reported paths."
            }.into());
            if let Some(remote) = &mut remote {
                recovery |= !remote.compensate(report);
            }
        }
    }
    if let Some(remote) = &mut remote {
        recovery |= !remote.finish(report);
    }
    drop(remote);
    report.changed.extend(batch.changed.iter().cloned());
    report.uncertain.extend(batch.uncertain.iter().cloned());
    report.failed_path = batch.failed_path.clone();
    for path in &batch.restored {
        report
            .details
            .push(format!("Restored: {}", output::public_name(path)));
    }
    if !recovery && batch.cleanup().is_err() {
        recovery = true;
        report.cleanup_failed = true;
    }
    if recovery {
        if let Some(path) = batch.recovery_path() {
            report.details.push(format!(
                "Encrypted recovery: {}",
                output::public_name(&path.to_string_lossy())
            ));
        }
    }
    if result.is_ok() {
        if recovery {
            return Err(Error::class(
                "rotation completed with outstanding recovery or token cleanup",
            ));
        }
        report.details.push("Historic ciphertext remains readable with old keys; externally issued vault tokens require separate revocation or expiry.".into());
    }
    result
}

struct Affected {
    path: String,
    private: bool,
    recipients: BTreeSet<String>,
}

#[allow(clippy::too_many_arguments)]
fn prepare_documents(
    batch: &mut Admin<'_>,
    rules: &Rules,
    before: &Roster,
    after: &Roster,
    name: &str,
    keys: &[Identity],
    machine: Option<&str>,
    pass: &OwnedSecret,
) -> Result<Vec<Affected>> {
    let mut paths = batch
        .sets()
        .map_err(Error::store)?
        .iter()
        .map(SetId::file_path)
        .collect::<BTreeSet<_>>();
    paths.extend(
        before
            .credentials
            .iter()
            .map(|n| format!("credentials/{n}.yaml")),
    );
    for team in before.teams.values() {
        paths.extend(team.decrypt.iter().map(|s| format!("{s}.yaml")));
    }
    paths.extend(before.teams.values().filter_map(|t| t.machine_path.clone()));
    let owners = before.recipients.values().cloned().collect();
    let mut affected = Vec::new();
    for path in paths {
        let owner = path
            .strip_prefix("credentials/")
            .and_then(|p| p.strip_suffix(".yaml"));
        let private = owner.is_some();
        let expected = owner.map_or_else(|| before.ordinary(&path), |o| before.credential(o));
        let wanted = owner.map_or_else(|| after.ordinary(&path), |o| after.credential(o));
        let old_rule = rules.select_original(&path)?;
        let rule_old = old_rule
            .recipients()
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let raw = batch.read(&path, private).map_err(Error::store)?;
        let actual = raw.as_ref().map(recorded_recipients).transpose()?;
        let granted = expected.contains(&before.recipients[name]);
        if rule_old.contains(&before.recipients[name]) != granted
            || actual
                .as_ref()
                .is_some_and(|a| a.contains(&before.recipients[name]) != granted)
        {
            return Err(
                Error::class("unexplained recipient outside the user's established scope")
                    .subject(&path),
            );
        }
        let machine_write = machine == Some(path.as_str());
        if !granted && !machine_write {
            continue;
        }
        let final_rule = rules.select(&path)?;
        let final_recipients = final_rule
            .recipients()
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let mut replaced = rule_old.clone();
        if replaced.remove(&before.recipients[name]) {
            replaced.insert(after.recipients[name].clone());
        }
        if final_recipients != replaced || !wanted.is_subset(&final_recipients) {
            return Err(
                Error::class("replacement rule changes recipient allocation").subject(&path),
            );
        }
        if raw.is_none() {
            continue;
        }
        drop(raw);
        let document = batch.document(&path, private, keys).map_err(Error::store)?;
        rules::check_original(&document, &old_rule, &expected, &owners, private)?;
        let encoded = if machine_write {
            let mut candidate = document.data().duplicate().map_err(crypto)?;
            candidate
                .put(
                    "passphrase",
                    sops::Value::string(pass.as_str()).map_err(crypto)?,
                )
                .map_err(crypto)?;
            let rewritten = document.rewrite(candidate).map_err(crypto)?;
            sops::decrypt(rewritten, keys)
                .map_err(crypto)?
                .rewrap(&final_rule)
                .map_err(crypto)?
        } else {
            document.rewrap(&final_rule).map_err(crypto)?
        };
        drop(document);
        if machine_write {
            rules::protected_fields(&encoded, &path, &["name", "passphrase"])?;
        }
        batch
            .set(&path, private, encoded.as_bytes())
            .map_err(Error::store)?;
        affected.push(Affected {
            path,
            private,
            recipients: final_recipients,
        });
    }
    batch.fresh().map_err(Error::store)?;
    Ok(affected)
}

fn recorded_recipients(raw: &sops::Plaintext) -> Result<BTreeSet<String>> {
    sops::inspect(raw).map_err(crypto)?;
    let tree = sops::parse_plaintext(raw).map_err(crypto)?;
    let entries = tree
        .get("sops")
        .and_then(|v| v.get("age"))
        .and_then(sops::Value::sequence)
        .ok_or(Error::class("invalid recipient metadata"))?;
    entries
        .iter()
        .filter(|v| !matches!(v, sops::Value::Comment(_)))
        .map(|v| {
            model::text(
                v.get("recipient")
                    .ok_or(Error::class("missing recipient metadata"))?,
            )?
            .parse::<age::Recipient>()
            .map(|r| r.to_string())
            .map_err(|_| Error::class("invalid recipient metadata"))
        })
        .collect()
}

fn verify_candidates(
    batch: &Admin<'_>,
    affected: &[Affected],
    recipient: &str,
    replacement: &[Identity],
    authority: &[Identity],
    persisted: bool,
) -> Result<()> {
    batch.fresh().map_err(Error::store)?;
    for item in affected {
        let keys = if item.recipients.contains(recipient) {
            replacement
        } else {
            authority
        };
        let candidate = batch
            .candidate_document(&item.path, keys)
            .map_err(Error::store)?;
        if candidate.recipients().map_err(crypto)? != item.recipients {
            return Err(Error::class("candidate recipient verification"));
        }
        drop(candidate);
        if persisted {
            batch
                .verify_candidate(&item.path, item.private, keys)
                .map_err(Error::store)?;
        }
    }
    batch.fresh().map_err(Error::store)
}

struct Machine {
    path: String,
    old: output::Prepared,
    metadata: output::Prepared,
    installed_metadata: Option<output::Prepared>,
    attempted: bool,
}
struct Remote {
    session: Session,
    name: String,
    role: String,
    credentials: Credentials,
    minted: Option<Text>,
    mint_attempted: bool,
    verification_token: Option<Text>,
    machine: Option<Machine>,
    mount: String,
    retirement_attempted: bool,
}
impl Remote {
    #[allow(clippy::too_many_arguments)]
    fn prepare(
        address: &str,
        caller: Option<OwnedSecret>,
        selected: &Selection,
        roster: &Roster,
        name: &str,
        operator: &str,
        batch: &mut Admin<'_>,
        keys: &[Identity],
        rules: &Rules,
        machine_path: Option<&str>,
    ) -> Result<Self> {
        let role = super::vault::role_name(name);
        super::vault::backend_name(&role)?;
        let path = format!("credentials/{name}.yaml");
        let credentials = super::vault::credentials(batch, &path, keys)?;
        replacement_credential(
            batch,
            keys,
            rules,
            &path,
            &credentials,
            "rotation-preflight",
        )?;
        let authority_path = selected
            .config
            .vault
            .credential
            .clone()
            .unwrap_or_else(|| format!("credentials/{operator}.yaml"));
        let authority = if caller.is_none() {
            let document = batch
                .document(&authority_path, true, keys)
                .map_err(Error::store)?;
            if document.recipients().map_err(crypto)? != roster.credential(operator) {
                return Err(Error::class(
                    "operation credential recipients are ambiguous",
                ));
            }
            Some(super::vault::credentials(batch, &authority_path, keys)?)
        } else {
            None
        };
        let mut session = Session::administrative(
            address,
            caller.as_ref().map(OwnedSecret::as_str),
            authority.as_ref().or(Some(&credentials)),
        )?;
        drop(authority);
        let mount = selected
            .config
            .vault
            .mount
            .clone()
            .unwrap_or_else(|| "secret".into());
        let result = (|| {
            let mut required: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            required.insert(
                format!("auth/approle/role/{role}/secret-id"),
                ["update".into()].into(),
            );
            required.insert(
                format!("auth/approle/role/{role}/secret-id/destroy"),
                ["update".into()].into(),
            );
            if caller.is_none() {
                required.insert("auth/token/revoke-self".into(), ["update".into()].into());
            }
            if let Some(path) = machine_path {
                let set = path.strip_suffix(".yaml").unwrap();
                required.insert(format!("{mount}/metadata/{set}"), ["read".into()].into());
                required.insert(
                    format!("{mount}/data/{set}"),
                    ["read".into(), "update".into()].into(),
                );
            }
            let (client, token) = session.parts();
            client.require_capabilities(token, &required)?;
            let machine = if let Some(path) = machine_path {
                let path = path.strip_suffix(".yaml").unwrap().to_owned();
                let metadata = super::vault::metadata(client, token, &mount, &path)?
                    .ok_or(Error::class("machine KV record missing"))?;
                if super::vault::version(Some(&metadata))? == 0 {
                    return Err(Error::class("invalid machine KV version"));
                }
                let old = client.read_machine_record(token, &mount, &path)?;
                let document = batch
                    .document(&format!("{path}.yaml"), false, keys)
                    .map_err(Error::store)?;
                if ["name", "passphrase"].iter().any(|k| {
                    old.get(k).and_then(Value::scalar)
                        != document
                            .data()
                            .get(k)
                            .and_then(sops::Value::scalar)
                            .map(sops::Scalar::as_str)
                }) {
                    return Err(Error::class("machine vault/local record mismatch"));
                }
                Some(Machine {
                    path,
                    old: old.render(true, false)?,
                    metadata,
                    installed_metadata: None,
                    attempted: false,
                })
            } else {
                None
            };
            batch.fresh().map_err(Error::store)?;
            Ok(machine)
        })();
        drop(caller);
        let machine = match result {
            Ok(m) => m,
            Err(e) => {
                if session.cleanup().is_err() {
                    return Err(Error::class(
                        "rotation preflight and owned token cleanup failed",
                    ));
                }
                return Err(e);
            }
        };
        Ok(Self {
            session,
            name: name.into(),
            role,
            credentials,
            minted: None,
            mint_attempted: false,
            verification_token: None,
            machine,
            mount,
            retirement_attempted: false,
        })
    }
    fn mint(
        &mut self,
        batch: &mut Admin<'_>,
        keys: &[Identity],
        rules: &Rules,
        report: &mut Report,
    ) -> Result<()> {
        batch.fresh().map_err(Error::store)?;
        self.check_machine(false)?;
        batch
            .recovery_public(
                "vault-actions.tsv",
                format!("operation\trotate\nrole\t{}\n", self.role).as_bytes(),
            )
            .map_err(Error::store)?;
        let (client, token) = self.session.parts();
        self.mint_attempted = true;
        report.details.push(format!(
            "Replacement SecretID mint attempted: {}",
            output::public_name(&self.role)
        ));
        let result = client.mint_secret_id(token, &self.role)?;
        let secret = result
            .get("secret_id")
            .filter(|v| matches!(v, Value::String(_)))
            .and_then(Value::scalar)
            .filter(|v| {
                !v.is_empty() && !v.contains('\0') && *v != self.credentials.secret.as_str()
            })
            .ok_or(Error::class(
                "invalid or non-distinct replacement secret ID",
            ))?;
        self.minted = Some(Text::copy(secret)?);
        let numeric = |name: &str| {
            result
                .get(name)
                .filter(|v| matches!(v, Value::Literal(_)))
                .and_then(Value::scalar)
                .and_then(|s| s.parse::<u64>().ok())
        };
        let usable = numeric("secret_id_num_uses") == Some(0) && numeric("secret_id_ttl").is_some();
        drop(result);
        let path = format!("credentials/{}.yaml", self.name);
        let encoded = replacement_credential(
            batch,
            keys,
            rules,
            &path,
            &self.credentials,
            self.minted.as_ref().unwrap().as_str(),
        )?;
        batch
            .set(&path, true, encoded.as_bytes())
            .map_err(Error::store)?;
        self.credentials.unseal.take();
        if !usable {
            return Err(Error::class(
                "replacement SecretID must have unlimited uses and valid TTL before verification",
            ));
        }
        Ok(())
    }
    fn check_machine(&mut self, installed: bool) -> Result<()> {
        if let Some(machine) = &self.machine {
            let (client, token) = self.session.parts();
            let expected = if installed {
                machine
                    .installed_metadata
                    .as_ref()
                    .ok_or(Error::class("machine KV write is uncertain"))?
            } else {
                &machine.metadata
            };
            let current = super::vault::metadata(client, token, &self.mount, &machine.path)?;
            if !super::vault::same(current.as_ref(), Some(expected)) {
                return Err(Error::class("machine KV changed since snapshot"));
            }
        }
        Ok(())
    }
    fn publish_machine(
        &mut self,
        batch: &mut Admin<'_>,
        keys: &[Identity],
        report: &mut Report,
    ) -> Result<()> {
        self.check_machine(false)?;
        let Some(machine) = &mut self.machine else {
            return Ok(());
        };
        batch.fresh().map_err(Error::store)?;
        let document = batch
            .candidate_document(&format!("{}.yaml", machine.path), keys)
            .map_err(Error::store)?;
        let body = output::get(document.data(), true)?;
        drop(document);
        let (client, token) = self.session.parts();
        machine.attempted = true;
        report.details.push(format!(
            "Machine KV write attempted: {}",
            output::public_name(&machine.path)
        ));
        let old_version = super::vault::version(Some(&machine.metadata))?;
        client.write_set_cas(token, &self.mount, &machine.path, &body, old_version)?;
        let installed = super::vault::metadata(client, token, &self.mount, &machine.path)?;
        if super::vault::version(installed.as_ref())?
            != old_version
                .checked_add(1)
                .ok_or(Error::class("KV version overflow"))?
        {
            return Err(Error::class(
                "machine KV version changed during publication",
            ));
        }
        machine.installed_metadata = installed;
        let persisted = client
            .read_machine_record(token, &self.mount, &machine.path)?
            .render(true, true)?;
        if persisted.as_bytes() != body.as_bytes() {
            return Err(Error::class("machine KV verification mismatch"));
        }
        self.check_machine(true)
    }
    fn check_machine_passphrase(&mut self, pass: &str) -> Result<()> {
        self.check_machine(true)?;
        if let Some(machine) = &self.machine {
            let (client, token) = self.session.parts();
            let record = client.read_machine_record(token, &self.mount, &machine.path)?;
            if record.get("name").and_then(Value::scalar) != Some(self.name.as_str())
                || record.get("passphrase").and_then(Value::scalar) != Some(pass)
            {
                return Err(Error::class("persisted machine KV passphrase mismatch"));
            }
        }
        self.check_machine(true)
    }
    fn verify_login(&mut self, store: &Store, keys: &[Identity]) -> Result<()> {
        let document = store
            .read_credential(
                &store::CredentialId::new(&self.name).map_err(Error::store)?,
                keys,
            )
            .map_err(Error::store)?;
        let role = model::text(
            document
                .get("role_id")
                .ok_or(Error::class("replacement role ID missing"))?,
        )?;
        let secret = model::text(
            document
                .get("secret_id")
                .ok_or(Error::class("replacement secret ID missing"))?,
        )?;
        if role != self.credentials.role.as_str()
            || Some(secret) != self.minted.as_ref().map(Text::as_str)
        {
            return Err(Error::class("persisted replacement credential mismatch"));
        }
        self.verification_token = Some(self.session.client.login(role, secret)?);
        drop(document);
        self.session
            .client
            .revoke(self.verification_token.as_ref().unwrap().as_str())?;
        self.verification_token = None;
        Ok(())
    }
    fn retire(&mut self, report: &mut Report) -> Result<()> {
        self.check_machine(true)?;
        self.retirement_attempted = true;
        report.details.push(format!(
            "Old SecretID retirement attempted: {}",
            output::public_name(&self.role)
        ));
        let (client, token) = self.session.parts();
        client.destroy_secret_id(token, &self.role, self.credentials.secret.as_str())?;
        report.details.push("Old SecretID retired after replacement verification; other IDs and the AppRole are preserved.".into());
        Ok(())
    }
    fn compensate(&mut self, report: &mut Report) -> bool {
        self.session.client.administrative_cleanup(true);
        let mut clean = true;
        if self.machine.as_ref().is_some_and(|m| m.attempted) {
            let result = (|| -> Result<()> {
                self.check_machine(true)?;
                let machine = self.machine.as_ref().unwrap();
                let (client, token) = self.session.parts();
                let version = super::vault::version(machine.installed_metadata.as_ref())?;
                client.write_set_cas(token, &self.mount, &machine.path, &machine.old, version)?;
                let restored = client
                    .read_machine_record(token, &self.mount, &machine.path)?
                    .render(true, false)?;
                if restored.as_bytes() != machine.old.as_bytes() {
                    return Err(Error::class("machine KV restore verification failed"));
                }
                Ok(())
            })();
            clean &= result.is_ok();
            report.details.push(if result.is_ok() { "Original machine KV record restored with CAS." } else { "Machine KV restoration failed or is uncertain; do not overwrite another writer." }.into());
        }
        if let Some(secret) = self.minted.take() {
            let (client, token) = self.session.parts();
            if client
                .destroy_secret_id(token, &self.role, secret.as_str())
                .is_err()
            {
                clean = false;
                report.details.push("Replacement SecretID cleanup failed or is uncertain; a newly minted credential may remain live.".into());
            } else {
                report.details.push(
                    "Known replacement SecretID destroyed; old SecretID was not retired.".into(),
                );
            }
        } else if self.mint_attempted {
            clean = false;
            report.details.push("SecretID mint outcome is unknown; inspect the named AppRole for external residue. No mint retry was made.".into());
        }
        self.session.client.administrative_cleanup(false);
        clean
    }
    fn finish(&mut self, report: &mut Report) -> bool {
        let mut clean = true;
        if let Some(token) = self.verification_token.take() {
            if self.session.client.revoke(token.as_str()).is_err() {
                clean = false;
                report.details.push(
                    "Verification token revocation failed; an issued token may remain live.".into(),
                );
            }
        }
        if self.session.cleanup().is_err() {
            clean = false;
            report.details.push(
                "Operation-owned token revocation failed; caller tokens remain caller-owned."
                    .into(),
            );
        }
        clean
    }
}

fn replacement_credential(
    batch: &mut Admin<'_>,
    keys: &[Identity],
    rules: &Rules,
    path: &str,
    credentials: &Credentials,
    secret: &str,
) -> Result<sops::Plaintext> {
    let mut fields = vec![
        ("role_id", credentials.role.as_str()),
        ("secret_id", secret),
    ];
    if let Some(unseal) = &credentials.unseal {
        fields.push(("unseal_key", unseal.as_str()));
    }
    let encoded = batch
        .credential_replacement(path, keys, &fields, &rules.select(path)?)
        .map_err(Error::store)?;
    rules::protected_fields(
        &encoded,
        path,
        &fields.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
    )?;
    Ok(encoded)
}
