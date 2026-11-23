// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::vault::{
    Session,
    api::Client,
    json::{Text, Value},
};
use std::io::Write;

struct Desired {
    policies: BTreeMap<String, String>,
    roles: BTreeMap<String, output::Prepared>,
}
struct Drift {
    policies: BTreeMap<String, Option<Text>>,
    roles: BTreeMap<String, super::vault::Role>,
    changed_policies: BTreeSet<String>,
    changed_roles: BTreeMap<String, Vec<&'static str>>,
}
const OWNED: [&str; 4] = [
    "token_policies",
    "token_ttl",
    "token_max_ttl",
    "token_period",
];

pub fn run(
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    inputs: CredentialInputs,
    interaction: &mut dyn Interaction,
    output: &mut dyn Write,
) -> Report {
    let mut report = Report::default();
    report.error = perform(
        selected,
        options,
        cwd,
        inputs,
        interaction,
        output,
        &mut report,
    )
    .err();
    report
}

#[allow(clippy::too_many_arguments)]
fn perform(
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    mut inputs: CredentialInputs,
    interaction: &mut dyn Interaction,
    output: &mut dyn Write,
    report: &mut Report,
) -> Result<()> {
    let address = crate::vault::session::address(selected, &mut inputs, true)?;
    let caller = super::vault::caller(&mut inputs)?;
    let store = Store::open(&selected.store_root()).map_err(Error::store)?;
    let lock = store.write().map_err(Error::store)?;
    let mut batch = lock.admin();
    let roster = Roster::load(&mut batch)?;
    let keys = identity::acquire(
        &store,
        cwd,
        selected.config.identity.as_deref(),
        inputs,
        options.non_interactive,
    )?;
    let operator = roster.operator(&keys)?;
    let desired = Desired::load(&mut batch, &roster)?;
    let credential = if caller.is_none() {
        let path = selected
            .config
            .vault
            .credential
            .clone()
            .unwrap_or_else(|| format!("credentials/{operator}.yaml"));
        let document = batch.document(&path, true, &keys).map_err(Error::store)?;
        if document.recipients().map_err(crypto)? != roster.credential(&operator) {
            return Err(Error::class("operator credential recipients are ambiguous"));
        }
        Some(super::vault::credentials(&mut batch, &path, &keys)?)
    } else {
        None
    };
    drop(keys);
    let mut session = Session::administrative(
        &address,
        caller.as_ref().map(OwnedSecret::as_str),
        credential.as_ref(),
    )?;
    drop(credential);
    let result = (|| {
        let (client, token) = session.parts();
        let drift = desired.inspect(client, token)?;
        batch.fresh().map_err(Error::store)?;
        let listing = drift.display()?;
        output
            .write_all(listing.as_bytes())
            .and_then(|()| output.flush())
            .map_err(|_| Error::class("drift output I/O"))?;
        if drift.empty() {
            return Ok(());
        }
        if !options.yes {
            if options.non_interactive {
                return Err(Error::class(
                    "vault reconcile requires --yes in non-interactive mode",
                ));
            }
            let answer =
                interaction.prompt("Apply the displayed vault changes? [y/N]", false, 32)?;
            if !matches!(
                answer.as_str().trim().to_ascii_lowercase().as_str(),
                "y" | "yes"
            ) {
                return Err(Error::class("vault reconciliation cancelled"));
            }
        }
        let required = drift.capabilities(caller.is_none());
        client.require_capabilities(token, &required)?;
        batch.fresh().map_err(Error::store)?;
        desired.apply(&drift, client, token, &batch, report)
    })();
    drop(caller);
    let cleanup = session.cleanup();
    if result.is_err() {
        report.details.push("Reconcile stopped; inspect completed or uncertain vault changes, repair the cause, and rerun reconcile.".into());
    }
    if cleanup.is_err() {
        report.details.push(
            "Operation-owned token revocation failed; an issued token may remain live.".into(),
        );
        if result.is_ok() {
            return Err(Error::class("reconcile owned token cleanup failed"));
        }
    }
    result
}

pub fn needed(
    selected: &Selection,
    cwd: &Path,
    mut inputs: CredentialInputs,
    address: &str,
) -> Option<bool> {
    (|| -> Result<bool> {
        let store = Store::open(&selected.store_root()).map_err(Error::store)?;
        let lock = store.write().map_err(Error::store)?;
        let mut batch = lock.admin();
        let roster = Roster::load(&mut batch)?;
        let desired = Desired::load(&mut batch, &roster)?;
        let caller = super::vault::caller(&mut inputs)?;
        let mut keys = None;
        let credentials = if caller.is_none() {
            Some(crate::vault::session::credentials(
                selected,
                cwd,
                &mut inputs,
                true,
                &mut keys,
            )?)
        } else {
            None
        };
        drop(keys);
        let mut session = Session::inspection(
            address,
            caller.as_ref().map(OwnedSecret::as_str),
            credentials.as_ref(),
        )?;
        drop(credentials);
        drop(caller);
        let result = (|| {
            let (client, token) = session.parts();
            let drift = desired.inspect(client, token)?;
            batch.fresh().map_err(Error::store)?;
            Ok(!drift.empty())
        })();
        session.cleanup()?;
        result
    })()
    .ok()
}

impl Desired {
    fn load(batch: &mut Admin<'_>, roster: &Roster) -> Result<Self> {
        let mut policies = BTreeMap::new();
        let mut folded = BTreeSet::new();
        let mut role_names = BTreeSet::new();
        let mut generated = BTreeSet::new();
        for user in roster.members.keys() {
            let role = super::vault::role_name(user);
            super::vault::backend_name(&role)?;
            if !role_names.insert(role.to_ascii_lowercase()) {
                return Err(Error::class("vault role case-fold collision"));
            }
            generated.insert(super::vault::self_name(user).to_ascii_lowercase());
        }
        for file in batch.names("policies").map_err(Error::store)? {
            let Some(name) = file.strip_suffix(".hcl") else {
                continue;
            };
            super::vault::backend_name(name)?;
            let folded_name = name.to_ascii_lowercase();
            if matches!(folded_name.as_str(), "root" | "default")
                || generated.contains(&folded_name)
                || !folded.insert(folded_name)
            {
                return Err(Error::class(
                    "policy file collides with a policy, self-policy or built-in name",
                )
                .subject(name));
            }
            let raw = batch
                .read(&format!("policies/{file}"), false)
                .map_err(Error::store)?
                .ok_or(Error::class("policy file missing").subject(name))?;
            if raw.as_str().trim().is_empty() || raw.as_str().contains('\0') {
                return Err(Error::class("invalid policy file").subject(name));
            }
            crate::vault::api::strings(&[("policy", raw.as_str())])?;
            policies.insert(name.to_owned(), raw.as_str().to_owned());
        }
        for name in roster.teams.values().flat_map(|t| t.policies.iter()) {
            if !policies.contains_key(name) {
                return Err(
                    Error::class("missing team policy or conflicting policy spelling")
                        .subject(name),
                );
            }
        }
        let mut roles = BTreeMap::new();
        for user in roster.members.keys() {
            policies.insert(
                super::vault::self_name(user),
                super::vault::self_policy(user),
            );
            roles.insert(super::vault::role_name(user), owned_settings(roster, user)?);
        }
        batch.fresh().map_err(Error::store)?;
        Ok(Self { policies, roles })
    }
    fn inspect(&self, client: &mut Client, token: &str) -> Result<Drift> {
        let mut drift = Drift {
            policies: BTreeMap::new(),
            roles: BTreeMap::new(),
            changed_policies: BTreeSet::new(),
            changed_roles: BTreeMap::new(),
        };
        for (name, desired) in &self.policies {
            let actual = client.read_policy_optional(token, name)?;
            if actual.as_ref().map(Text::as_str) != Some(desired.as_str()) {
                drift.changed_policies.insert(name.clone());
            }
            drift.policies.insert(name.clone(), actual);
        }
        for (name, desired) in &self.roles {
            let actual = super::vault::role(client, token, name)?.ok_or(Error::class("expected AppRole missing; inspect user add or manual recovery before reconcile").subject(name))?;
            let fields = changed_fields(&actual.settings, desired)?;
            if !fields.is_empty() {
                drift.changed_roles.insert(name.clone(), fields);
            }
            drift.roles.insert(name.clone(), actual);
        }
        Ok(drift)
    }
    fn apply(
        &self,
        drift: &Drift,
        client: &mut Client,
        token: &str,
        batch: &Admin<'_>,
        report: &mut Report,
    ) -> Result<()> {
        for name in &drift.changed_policies {
            batch.fresh().map_err(Error::store)?;
            let current = client.read_policy_optional(token, name)?;
            if current.as_ref().map(Text::as_str) != drift.policies[name].as_ref().map(Text::as_str)
            {
                return Err(
                    Error::class("vault policy changed since drift inspection").subject(name)
                );
            }
            batch.fresh().map_err(Error::store)?;
            report.details.push(format!(
                "Vault policy write attempted (uncertain until verified): {}",
                output::public_name(name)
            ));
            client.write_policy(token, name, &self.policies[name])?;
            if client
                .read_policy_optional(token, name)?
                .as_ref()
                .map(Text::as_str)
                != Some(self.policies[name].as_str())
            {
                return Err(Error::class("vault policy readback mismatch").subject(name));
            }
            report.details.push(format!(
                "Vault policy verified: {}",
                output::public_name(name)
            ));
        }
        for name in drift.changed_roles.keys() {
            batch.fresh().map_err(Error::store)?;
            let before = &drift.roles[name];
            let current = super::vault::role(client, token, name)?
                .ok_or(Error::class("vault role disappeared before update").subject(name))?;
            if !super::vault::same_role(before, &current)? {
                return Err(Error::class("vault role changed since drift inspection").subject(name));
            }
            batch.fresh().map_err(Error::store)?;
            report.details.push(format!(
                "Vault role settings write attempted (uncertain until verified): {}",
                output::public_name(name)
            ));
            client.write_role(token, name, &self.roles[name])?;
            let persisted = super::vault::role(client, token, name)?
                .ok_or(Error::class("vault role disappeared after update").subject(name))?;
            if persisted.id.as_str() != before.id.as_str()
                || !changed_fields(&persisted.settings, &self.roles[name])?.is_empty()
                || !same_restrictions(&before.settings, &persisted.settings)?
            {
                return Err(Error::class(
                    "vault role ID, restrictions or owned settings changed unexpectedly",
                )
                .subject(name));
            }
            report.details.push(format!(
                "Vault role settings verified with credential IDs preserved: {}",
                output::public_name(name)
            ));
        }
        batch.fresh().map_err(Error::store)
    }
}
impl Drift {
    fn empty(&self) -> bool {
        self.changed_policies.is_empty() && self.changed_roles.is_empty()
    }
    fn display(&self) -> Result<output::Prepared> {
        output::prepare(output::MAX_OUTPUT_BYTES, |w| {
            if self.empty() {
                return w.text("No vault drift.\n");
            }
            for name in &self.changed_policies {
                w.text(&format!("Policy {}: body\n", output::public_name(name)))?;
            }
            for (name, fields) in &self.changed_roles {
                w.text(&format!(
                    "AppRole {}: {}\n",
                    output::public_name(name),
                    fields.join(", ")
                ))?;
            }
            Ok(())
        })
    }
    fn capabilities(&self, owned_token: bool) -> BTreeMap<String, BTreeSet<String>> {
        let mut required = BTreeMap::new();
        for name in self.policies.keys() {
            let mut caps = BTreeSet::from(["read".into()]);
            if self.changed_policies.contains(name) {
                caps.insert("update".into());
            }
            required.insert(format!("sys/policies/acl/{name}"), caps);
        }
        for name in self.roles.keys() {
            let mut caps = BTreeSet::from(["read".into()]);
            if self.changed_roles.contains_key(name) {
                caps.insert("update".into());
            }
            required.insert(format!("auth/approle/role/{name}"), caps);
            required.insert(
                format!("auth/approle/role/{name}/role-id"),
                ["read".into()].into(),
            );
        }
        if owned_token {
            required.insert("auth/token/revoke-self".into(), ["update".into()].into());
        }
        required
    }
}
fn owned_settings(roster: &Roster, user: &str) -> Result<output::Prepared> {
    output::prepare(sops::MAX_DOCUMENT_BYTES, |w| {
        w.text("{\"token_policies\":[")?;
        for (i, name) in roster.policies(user).iter().enumerate() {
            if i > 0 {
                w.text(",")?;
            }
            output::json_string(w, name)?;
        }
        w.text(if roster.service(user) {
            "],\"token_ttl\":0,\"token_max_ttl\":0,\"token_period\":31536000}"
        } else {
            "],\"token_ttl\":86400,\"token_max_ttl\":259200,\"token_period\":0}"
        })
    })
}
fn policies(value: &Value) -> Result<BTreeSet<&str>> {
    match value {
        Value::Null => Ok(BTreeSet::new()),
        Value::Array(values) => values
            .iter()
            .map(|v| match v {
                Value::String(t) => Ok(t.as_str()),
                _ => Err(Error::class("malformed role policies")),
            })
            .collect(),
        _ => Err(Error::class("malformed role policies")),
    }
}
fn changed_fields(actual: &Value, wanted: &output::Prepared) -> Result<Vec<&'static str>> {
    let wanted = crate::vault::json::Raw::parse(wanted.as_bytes())?.decode()?;
    let mut fields = Vec::new();
    for field in OWNED {
        let current = actual
            .get(field)
            .ok_or(Error::class("malformed role settings"))?;
        let desired = wanted.get(field).unwrap();
        let equal = if field == "token_policies" {
            policies(current)? == policies(desired)?
        } else {
            super::vault::duration(current)? == super::vault::duration(desired)?
        };
        if !equal {
            fields.push(field);
        }
    }
    Ok(fields)
}
fn same_restrictions(before: &Value, after: &Value) -> Result<bool> {
    let names = before
        .keys()?
        .into_iter()
        .chain(after.keys()?)
        .collect::<BTreeSet<_>>();
    for name in names {
        if OWNED.contains(&name) || matches!(name, "policies" | "period") {
            continue;
        }
        let encoded = |v: &Value| v.render(true, false);
        let a = before.get(name).map(encoded).transpose()?;
        let b = after.get(name).map(encoded).transpose()?;
        if a.as_ref().map(output::Prepared::as_bytes) != b.as_ref().map(output::Prepared::as_bytes)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
