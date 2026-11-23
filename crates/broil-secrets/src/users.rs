// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod model;
mod reconcile;
mod rotate;
mod rules;
mod vault;

pub use reconcile::{needed as reconcile_needed, run as reconcile};
pub use rotate::run as rotate;

use crate::{
    age::{self, Identity},
    identity, output,
    read::{Error, Options, Result, Selection},
    sops,
    store::{self, SetId, Store, admin::Admin},
    write::{Interaction, Report},
};
use broil_core::secret::{
    MAX_CREDENTIAL_PROMPT_VALUE_BYTES, OwnedSecret, environment::CredentialInputs,
};
use model::Roster;
use rules::Rules;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Add,
    Remove,
    Rename,
}

pub(super) struct Operation {
    kind: Kind,
    name: String,
    target: String,
    fresh: bool,
}
fn crypto(error: sops::Error) -> Error {
    Error::store(error.into())
}

pub fn list(
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    inputs: CredentialInputs,
) -> Result<output::Prepared> {
    let store = Store::open(&selected.store_root()).map_err(Error::store)?;
    let session = store.write().map_err(Error::store)?;
    let mut batch = session.admin();
    let mut roster = Roster::load(&mut batch)?;
    if roster.has_records(&mut batch)? {
        let keys = identity::acquire(
            &store,
            cwd,
            selected.config.identity.as_deref(),
            inputs,
            options.non_interactive,
        )?;
        roster.classify(&mut batch, &keys, false)?;
    }
    batch.fresh().map_err(Error::store)?;
    roster.list()
}

pub fn run(
    kind: Kind,
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    inputs: CredentialInputs,
    interaction: &mut dyn Interaction,
) -> Report {
    let mut report = Report::default();
    report.error = perform(
        kind,
        selected,
        options,
        cwd,
        inputs,
        interaction,
        &mut report,
    )
    .err();
    report
}

#[allow(clippy::too_many_arguments)]
fn perform(
    kind: Kind,
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
    let session = store.write().map_err(Error::store)?;
    let mut batch = session.admin();
    let mut before = Roster::load(&mut batch)?;
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
        inputs
            .take("BAO_TOKEN")
            .map_err(|_| Error::class("invalid caller token"))?
            .map(|v| {
                v.into_secret()
                    .map_err(|_| Error::class("invalid caller token"))
            })
            .transpose()?
    } else {
        None
    };
    let keys = identity::acquire(
        &store,
        cwd,
        selected.config.identity.as_deref(),
        inputs,
        options.non_interactive,
    )?;
    let operator = before.operator(&keys)?;
    before.classify(&mut batch, &keys, true)?;
    let mut after = before.clone();
    let fresh = !before.members.contains_key(name);
    let target = if kind == Kind::Rename {
        options
            .new_name
            .as_deref()
            .ok_or(Error::class("rename destination required"))?
    } else {
        name
    };
    store::validate_component(target).map_err(Error::store)?;
    let operation = Operation {
        kind,
        name: name.into(),
        target: target.into(),
        fresh,
    };
    let mut generated = None;
    let mut machine_data = None;
    match kind {
        Kind::Add => {
            let team = options
                .team
                .as_deref()
                .ok_or(Error::class("team required"))?;
            let definition = before
                .teams
                .get(team)
                .ok_or(Error::class("unknown team").subject(team))?;
            if !fresh && options.machine {
                return Err(Error::class(
                    "an existing identity cannot be converted to a machine",
                ));
            }
            if before.machines.contains_key(name) && !before.members[name].contains(team) {
                return Err(Error::class("a machine must belong to exactly one team"));
            }
            if options.machine {
                let path = definition
                    .machine_path
                    .as_ref()
                    .ok_or(Error::class("team is not machine-capable"))?;
                if before.machines.values().any(|p| p == path)
                    || batch.read(path, false).map_err(Error::store)?.is_some()
                {
                    return Err(Error::class("team already has a machine passphrase record"));
                }
                after.machines.insert(name.into(), path.clone());
            }
            after
                .members
                .entry(name.into())
                .or_default()
                .insert(team.into());
            if fresh {
                if options.non_interactive && !options.machine {
                    return Err(Error::class(
                        "new human creation requires a private terminal",
                    ));
                }
                let passphrase = if options.machine {
                    machine_passphrase()?
                } else {
                    new_passphrase(interaction)?
                };
                let identity =
                    Identity::generate().map_err(|_| Error::class("identity generation"))?;
                let recipient = identity.recipient().to_string();
                let raw = identity
                    .encode()
                    .map_err(|_| Error::class("identity encoding"))?;
                let encrypted = age::encrypt_with_passphrase(raw.as_str().as_bytes(), &passphrase)
                    .map_err(|_| Error::class("identity encryption"))?;
                drop(raw);
                let reopened = age::decrypt(&encrypted, &[], Some(&passphrase))
                    .map_err(|_| Error::class("new identity verification"))?
                    .into_secret()
                    .map_err(|_| Error::class("new identity verification"))?;
                let reopened = age::parse_identity_file(&reopened)
                    .map_err(|_| Error::class("new identity verification"))?;
                if reopened.len() != 1 || reopened[0].recipient().to_string() != recipient {
                    return Err(Error::class("new identity verification"));
                }
                drop(reopened);
                if options.machine {
                    machine_data = Some(secret_mapping(&[
                        ("name", name),
                        ("passphrase", passphrase.as_str()),
                    ])?);
                }
                drop(passphrase);
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
                generated = Some(identity);
            }
        }
        Kind::Remove | Kind::Rename => {
            if fresh {
                return Err(Error::class("unknown user").subject(name));
            }
            if kind == Kind::Rename {
                if before.members.contains_key(target) {
                    return Err(Error::class("rename destination exists").subject(target));
                }
                let memberships = after.members.remove(name).unwrap();
                after.members.insert(target.into(), memberships);
                let recipient = after.recipients.remove(name).unwrap();
                after.recipients.insert(target.into(), recipient);
                if let Some(path) = after.machines.remove(name) {
                    after.machines.insert(target.into(), path);
                }
                for (suffix, private) in [(".pub", false), (".key.age", true)] {
                    let old = format!("keys/{name}{suffix}");
                    let new = format!("keys/{target}{suffix}");
                    let bytes = batch
                        .read_bytes(&old, private)
                        .map_err(Error::store)?
                        .ok_or(Error::class("missing identity"))?;
                    if batch
                        .read_bytes(&new, private)
                        .map_err(Error::store)?
                        .is_some()
                    {
                        return Err(Error::class("rename artifact collision"));
                    }
                    batch.set(&new, private, &bytes).map_err(Error::store)?;
                    batch.delete(&old, private).map_err(Error::store)?;
                }
                if after.credentials.remove(name) {
                    after.credentials.insert(target.into());
                }
            } else {
                after.members.remove(name);
                after.recipients.remove(name);
                after.machines.remove(name);
                after.credentials.remove(name);
                for (suffix, private) in [(".pub", false), (".key.age", true)] {
                    batch
                        .delete(&format!("keys/{name}{suffix}"), private)
                        .map_err(Error::store)?;
                }
            }
        }
    }
    if after.operators().is_empty() {
        return Err(Error::class(
            "cannot remove the last independently usable operator",
        ));
    }
    after.operator(&keys).map_err(|_| {
        Error::class("operator removal requires a matching surviving operator identity")
    })?;
    if let Some(path) = after.machines.get(target) {
        if after
            .ordinary(path)
            .iter()
            .all(|r| r == &after.recipients[target])
        {
            return Err(Error::class(
                "machine passphrase has no independent recipient",
            ));
        }
    }
    let mut rules = Rules::load(&mut batch)?;
    let new_credential = address.is_some() && (fresh || kind == Kind::Rename);
    if new_credential {
        after.credentials.insert(target.into());
    }
    prepare_access(
        &mut batch,
        &mut rules,
        &before,
        &after,
        &operation,
        &keys,
        machine_data.as_ref(),
        new_credential,
    )?;
    drop(machine_data);
    batch
        .set("teams.yaml", false, after.encode_members()?.as_bytes())
        .map_err(Error::store)?;
    batch
        .set(".sops.yaml", false, rules.encode()?.as_bytes())
        .map_err(Error::store)?;
    batch.fresh().map_err(Error::store)?;
    if kind == Kind::Remove {
        let scopes = before.members[name]
            .iter()
            .flat_map(|t| {
                if before.teams[t].all {
                    vec!["all".into()]
                } else {
                    before.teams[t].decrypt.iter().cloned().collect()
                }
            })
            .collect::<BTreeSet<String>>();
        let description = format!(
            "Remove {} (scopes: {})",
            output::public_name(name),
            scopes
                .iter()
                .map(|s| output::public_name(s))
                .collect::<Vec<_>>()
                .join(", ")
        );
        report.details.push(description.clone());
        if !options.yes {
            if options.non_interactive {
                return Err(Error::class(
                    "user remove requires --yes in non-interactive mode",
                ));
            }
            let answer = interaction.prompt(&format!("{description} [y/N]"), false, 32)?;
            if !matches!(
                answer.as_str().trim().to_ascii_lowercase().as_str(),
                "y" | "yes"
            ) {
                return Err(Error::class("user removal cancelled"));
            }
        }
    }
    if kind == Kind::Add && !fresh && before.members == after.members {
        report
            .details
            .push("Membership already present; no changes.".into());
        return Ok(());
    }
    let mut remote = if let Some(address) = address {
        Some(vault::Remote::prepare(
            &address, caller, selected, &operator, &before, &after, &operation, &mut batch, &keys,
            &rules,
        )?)
    } else {
        None
    };
    let result = (|| {
        batch.stage_recovery().map_err(Error::store)?;
        if let Some(remote) = &mut remote {
            remote.before_local(&mut batch, &rules, &keys, report)?;
        }
        batch.apply().map_err(Error::store)?;
        batch.verify_documents(&keys).map_err(Error::store)?;
        verify_local(&store, &after, &operation, generated.as_ref(), &keys)?;
        drop(generated.take());
        if let Some(remote) = &mut remote {
            remote.after_local(&mut batch, report)?;
        }
        Ok(())
    })();
    drop(generated.take());
    drop(keys);
    let retired = remote.as_ref().is_some_and(|r| r.retired);
    let mut recovery_needed = batch.cleanup_failed;
    report.cleanup_failed |= batch.cleanup_failed;
    if result.is_err() {
        if retired {
            recovery_needed = true;
            report.details.push("Old vault access is revoked or uncertain; finish the reported local/remote changes forward. The old role was not recreated.".into());
        } else {
            let restored = batch.rollback().is_ok();
            recovery_needed |= !restored;
            report.details.push(
                if restored {
                    "Original local files restored where changed; old access has not been retired."
                } else {
                    "Local restoration incomplete; inspect encrypted recovery before retrying."
                }
                .into(),
            );
            if let Some(remote) = &mut remote {
                recovery_needed |= !remote.compensate(report);
            }
        }
    }
    if let Some(remote) = &mut remote {
        if remote.finish(report).is_err() {
            recovery_needed = true;
        }
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
    if !recovery_needed && batch.cleanup().is_err() {
        recovery_needed = true;
        report.cleanup_failed = true;
    }
    if recovery_needed {
        if let Some(path) = batch.recovery_path() {
            report.details.push(format!(
                "Encrypted recovery: {}",
                output::public_name(&path.to_string_lossy())
            ));
        }
    }
    if result.is_ok() && recovery_needed {
        return Err(Error::class(
            "administration completed with outstanding recovery or token cleanup",
        ));
    }
    if kind == Kind::Remove && result.is_ok() {
        report.details.push("Historic ciphertext remains readable with old keys; previously issued external vault tokens require separate revocation or expiry.".into());
    }
    result
}

fn new_passphrase(interaction: &mut dyn Interaction) -> Result<OwnedSecret> {
    let pass = interaction.prompt("New passphrase", true, MAX_CREDENTIAL_PROMPT_VALUE_BYTES)?;
    if pass.is_empty()
        || pass.as_str().contains('\0')
        || pass.len() > MAX_CREDENTIAL_PROMPT_VALUE_BYTES
    {
        return Err(Error::class("invalid new passphrase"));
    }
    let confirmation = interaction.prompt(
        "Confirm passphrase",
        true,
        MAX_CREDENTIAL_PROMPT_VALUE_BYTES,
    )?;
    if pass.as_str() != confirmation.as_str() {
        return Err(Error::class("passphrase confirmation"));
    }
    Ok(pass)
}
fn machine_passphrase() -> Result<OwnedSecret> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| Error::class("machine randomness"))?;
    let mut output = Zeroizing::new(String::with_capacity(64));
    const HEX: &[u8] = b"0123456789abcdef";
    for byte in bytes.iter() {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
    Ok(OwnedSecret::from_zeroizing(output))
}
pub(super) fn secret_mapping(fields: &[(&str, &str)]) -> Result<sops::Plaintext> {
    let body = crate::vault::api::strings(fields)?;
    sops::Plaintext::copy_from(body.as_str()).map_err(crypto)
}

#[allow(clippy::too_many_arguments)]
fn prepare_access(
    batch: &mut Admin<'_>,
    rules: &mut Rules,
    before: &Roster,
    after: &Roster,
    op: &Operation,
    keys: &[Identity],
    machine_data: Option<&sops::Plaintext>,
    new_credential: bool,
) -> Result<()> {
    let old_credential = format!("credentials/{}.yaml", op.name);
    let retired = (op.kind != Kind::Add).then_some(old_credential.as_str());
    rules.update_operators(before, after, retired)?;
    let owners = before.recipients.values().cloned().collect::<BTreeSet<_>>();
    let sets = batch.sets().map_err(Error::store)?;
    let mut paths = sets.iter().map(SetId::file_path).collect::<BTreeSet<_>>();
    for team in after.teams.values() {
        paths.extend(team.decrypt.iter().map(|s| format!("{s}.yaml")));
    }
    if let Some(path) = after.machines.get(&op.target) {
        paths.insert(path.clone());
    }
    for path in paths {
        let original = batch.read(&path, false).map_err(Error::store)?;
        let original_rule = rules.select_original(&path)?;
        let document = if original.is_some() {
            drop(original);
            Some(batch.document(&path, false, keys).map_err(Error::store)?)
        } else {
            None
        };
        let external = if let Some(document) = &document {
            rules::check_original(
                document,
                &original_rule,
                &before.ordinary(&path),
                &owners,
                false,
            )?
        } else {
            original_rule
                .recipients()
                .iter()
                .map(ToString::to_string)
                .filter(|r| !owners.contains(r))
                .collect()
        };
        if op.kind == Kind::Remove && before.machines.get(&op.name) == Some(&path) {
            batch.delete(&path, false).map_err(Error::store)?;
            continue;
        }
        let mut wanted = after.ordinary(&path);
        wanted.extend(external);
        if wanted.is_empty() {
            return Err(Error::class("recipient removal would lock out a set").subject(&path));
        }
        if rules
            .select(&path)?
            .recipients()
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
            != wanted
        {
            rules.exact(&path, &original_rule, &wanted)?;
        }
        let rule = rules.select(&path)?;
        if rule
            .recipients()
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>()
            != wanted
        {
            return Err(Error::class("candidate recipient-rule conflict").subject(&path));
        }
        if let Some(document) = document {
            let encoded = if op.kind == Kind::Rename && before.machines.get(&op.name) == Some(&path)
            {
                let mut candidate = document.data().duplicate().map_err(crypto)?;
                candidate
                    .put("name", sops::Value::string(&op.target).map_err(crypto)?)
                    .map_err(crypto)?;
                let rewritten = document.rewrite(candidate).map_err(crypto)?;
                sops::decrypt(rewritten, keys)
                    .map_err(crypto)?
                    .rewrap(&rule)
                    .map_err(crypto)?
            } else {
                let encoded = document.rewrap(&rule).map_err(crypto)?;
                if document.recipients().map_err(crypto)? == wanted {
                    continue;
                }
                encoded
            };
            batch
                .set(&path, false, encoded.as_bytes())
                .map_err(Error::store)?;
        } else if let Some(machine_data) =
            machine_data.filter(|_| after.machines.get(&op.target) == Some(&path))
        {
            let encoded =
                rules::protected_create(rules, &path, machine_data, &["name", "passphrase"])?;
            batch
                .set(&path, false, encoded.as_bytes())
                .map_err(Error::store)?;
        }
    }
    for owner in &before.credentials {
        let path = format!("credentials/{owner}.yaml");
        let document = batch.document(&path, true, keys).map_err(Error::store)?;
        let original = rules.select_original(&path)?;
        rules::check_original(
            &document,
            &original,
            &before.credential(owner),
            &owners,
            true,
        )?;
        if owner == &op.name && op.kind != Kind::Add {
            batch.delete(&path, true).map_err(Error::store)?;
            if op.kind == Kind::Remove || new_credential {
                continue;
            }
        }
        let next_owner = if owner == &op.name { &op.target } else { owner };
        let next = format!("credentials/{next_owner}.yaml");
        let wanted = after.credential(next_owner);
        rules.exact(&next, &original, &wanted)?;
        let encoded = document.rewrap(&rules.select(&next)?).map_err(crypto)?;
        if path != next || document.recipients().map_err(crypto)? != wanted {
            batch
                .set(&next, true, encoded.as_bytes())
                .map_err(Error::store)?;
        }
    }
    if new_credential {
        let path = format!("credentials/{}.yaml", op.target);
        if batch.read(&path, true).map_err(Error::store)?.is_some() {
            return Err(Error::class("new credential path already exists"));
        }
        let policy = if op.kind == Kind::Rename && before.credentials.contains(&op.name) {
            rules.select_original(&old_credential)?
        } else {
            rules.select_original(&path)?
        };
        rules.exact(&path, &policy, &after.credential(&op.target))?;
        let placeholder = secret_mapping(&[("role_id", "preflight"), ("secret_id", "preflight")])?;
        rules::protected_create(rules, &path, &placeholder, &["role_id", "secret_id"])?;
    }
    Ok(())
}

fn verify_local(
    store: &Store,
    after: &Roster,
    op: &Operation,
    generated: Option<&Identity>,
    operators: &[Identity],
) -> Result<()> {
    if let Some(identity) = generated {
        for id in store.sets().map_err(Error::store)? {
            if after
                .ordinary(&id.file_path())
                .contains(&identity.recipient().to_string())
            {
                store
                    .read(&id, std::slice::from_ref(identity))
                    .map_err(Error::store)?;
            }
        }
        if after.credentials.contains(&op.target) {
            store
                .read_credential(
                    &store::CredentialId::new(&op.target).map_err(Error::store)?,
                    std::slice::from_ref(identity),
                )
                .map_err(Error::store)?;
        }
    }
    if let Some(path) = after.machines.get(&op.target) {
        let record = store
            .read(
                &SetId::new(path.strip_suffix(".yaml").unwrap()).map_err(Error::store)?,
                operators,
            )
            .map_err(Error::store)?;
        let name = record
            .get("name")
            .and_then(sops::Value::scalar)
            .ok_or(Error::class("machine verification"))?
            .as_str();
        if name != op.target {
            return Err(Error::class("machine verification name mismatch"));
        }
        let pass = record
            .get("passphrase")
            .and_then(sops::Value::scalar)
            .ok_or(Error::class("machine verification"))?
            .as_str();
        let pass = crate::vault::json::Text::copy(pass)?;
        drop(record);
        let protected = OwnedSecret::from_zeroizing(Zeroizing::new(pass.as_str().to_owned()));
        drop(pass);
        let keys = store
            .unlock_identity(&op.target, &protected)
            .map_err(Error::store)?;
        drop(protected);
        if keys.len() != 1 || keys[0].recipient().to_string() != after.recipients[&op.target] {
            return Err(Error::class("machine verification key mismatch"));
        }
    }
    Ok(())
}
