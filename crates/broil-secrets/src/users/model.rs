// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::sops::{Entry, ScalarKind, Value};

#[derive(Clone)]
pub(super) struct Team {
    pub policies: BTreeSet<String>,
    pub all: bool,
    pub decrypt: BTreeSet<String>,
    pub machine_path: Option<String>,
    pub service: bool,
}
#[derive(Clone)]
pub(super) struct Roster {
    pub teams: BTreeMap<String, Team>,
    pub members: BTreeMap<String, BTreeSet<String>>,
    pub recipients: BTreeMap<String, String>,
    pub machines: BTreeMap<String, String>,
    pub credentials: BTreeSet<String>,
}

pub(super) fn fields(value: &Value) -> Result<Vec<(&str, &Value)>> {
    value
        .entries()
        .ok_or(Error::class("invalid administration mapping"))?
        .iter()
        .filter_map(|e| match e {
            Entry::Pair(k, v) => Some(Ok((k.as_str(), v))),
            Entry::Comment(_) => None,
        })
        .collect()
}
pub(super) fn text(value: &Value) -> Result<&str> {
    value
        .scalar()
        .filter(|s| s.kind() == ScalarKind::String)
        .map(|s| s.as_str())
        .ok_or(Error::class("invalid administration string"))
}
fn names(value: &Value, set: bool) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for value in value
        .sequence()
        .ok_or(Error::class("invalid administration sequence"))?
    {
        if matches!(value, Value::Comment(_)) {
            continue;
        }
        let name = text(value)?;
        if set {
            SetId::new(name).map_err(Error::store)?;
        } else {
            store::validate_component(name).map_err(Error::store)?;
        }
        if !result.insert(name.into()) {
            return Err(Error::class("duplicate administration entry"));
        }
    }
    Ok(result)
}
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .ok_or(Error::class("missing administration field").subject(key))
}

impl Roster {
    pub fn load(batch: &mut Admin<'_>) -> Result<Self> {
        let raw = batch.read("broil-secrets.yaml", false).map_err(Error::store)?
            .ok_or(Error::class("user administration requires broil-secrets.yaml and explicit operator membership in teams.yaml; see docs/secrets.md"))?;
        let manifest = sops::parse_plaintext(&raw).map_err(crypto)?;
        for (key, _) in fields(&manifest)? {
            if !matches!(key, "version" | "teams") {
                return Err(Error::class("unknown manifest field").subject(key));
            }
        }
        if !manifest
            .get("version")
            .and_then(Value::scalar)
            .is_some_and(|s| s.kind() == ScalarKind::Integer && s.as_str() == "1")
        {
            return Err(Error::class("unsupported manifest version"));
        }
        let mut teams = BTreeMap::new();
        let mut machine_paths = BTreeSet::new();
        for (name, value) in fields(required(&manifest, "teams")?)? {
            store::validate_component(name).map_err(Error::store)?;
            for (key, _) in fields(value)? {
                if !matches!(
                    key,
                    "policies" | "decrypt" | "machine_passphrase_file" | "service_account"
                ) {
                    return Err(Error::class("unknown team field").subject(key));
                }
            }
            let policies = names(required(value, "policies")?, false)?;
            let scope = required(value, "decrypt")?;
            let all = text(scope).is_ok_and(|s| s == "all");
            let decrypt = if all {
                BTreeSet::new()
            } else {
                names(scope, true)?
            };
            let machine_path = value
                .get("machine_passphrase_file")
                .map(text)
                .transpose()?
                .map(str::to_owned);
            if let Some(path) = &machine_path {
                let set = path
                    .strip_suffix(".yaml")
                    .ok_or(Error::class("machine path must be an ordinary .yaml set"))?;
                SetId::new(set).map_err(Error::store)?;
                if !machine_paths.insert(path.clone()) {
                    return Err(Error::class("teams share a machine passphrase path"));
                }
            }
            let service = match value.get("service_account") {
                None => false,
                Some(Value::Scalar(s)) if s.kind() == ScalarKind::Boolean => s.as_str() == "True",
                Some(_) => return Err(Error::class("invalid service_account flag")),
            };
            teams.insert(
                name.into(),
                Team {
                    policies,
                    all,
                    decrypt,
                    machine_path,
                    service,
                },
            );
        }
        let membership = batch.read("teams.yaml", false).map_err(Error::store)?;
        let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        if let Some(raw) = membership {
            let tree = sops::parse_plaintext(&raw).map_err(crypto)?;
            for (name, values) in fields(&tree)? {
                store::validate_component(name).map_err(Error::store)?;
                let selected = names(values, false)?;
                if selected.is_empty() || selected.iter().any(|t| !teams.contains_key(t)) {
                    return Err(Error::class("empty membership or unknown team").subject(name));
                }
                members.insert(name.into(), selected);
            }
        }
        let mut recipients = BTreeMap::new();
        let mut ownership = BTreeSet::new();
        let mut expected_keys = BTreeSet::new();
        for name in members.keys() {
            let public_path = format!("keys/{name}.pub");
            let private_path = format!("keys/{name}.key.age");
            let public = batch
                .read(&public_path, false)
                .map_err(Error::store)?
                .ok_or(Error::class("missing public identity").subject(name))?;
            let recipient = public
                .as_str()
                .trim()
                .parse::<age::Recipient>()
                .map_err(|_| Error::class("invalid public identity").subject(name))?
                .to_string();
            if !ownership.insert(recipient.clone()) {
                return Err(Error::class("duplicate recipient ownership"));
            }
            let private = batch
                .read_bytes(&private_path, true)
                .map_err(Error::store)?
                .ok_or(Error::class("missing encrypted identity").subject(name))?;
            if age::validate_identity_envelope(&private).is_err() {
                return Err(Error::class("identity is not age encrypted").subject(name));
            }
            recipients.insert(name.clone(), recipient);
            expected_keys.insert(format!("{name}.pub"));
            expected_keys.insert(format!("{name}.key.age"));
        }
        if batch
            .names("keys")
            .map_err(Error::store)?
            .into_iter()
            .collect::<BTreeSet<_>>()
            != expected_keys
        {
            return Err(Error::class(
                "orphan or unknown identity artifacts; explicitly configure existing users before administration",
            ));
        }
        let mut credentials = BTreeSet::new();
        for file in batch.names("credentials").map_err(Error::store)? {
            let name = file
                .strip_suffix(".yaml")
                .filter(|name| members.contains_key(*name))
                .ok_or(Error::class("orphan or unknown credential artifact"))?;
            let raw = batch
                .read(&format!("credentials/{file}"), true)
                .map_err(Error::store)?
                .ok_or(Error::class("missing credential artifact"))?;
            sops::inspect(&raw).map_err(crypto)?;
            credentials.insert(name.into());
        }
        Ok(Self {
            teams,
            members,
            recipients,
            machines: BTreeMap::new(),
            credentials,
        })
    }
    pub fn has_records(&self, batch: &mut Admin<'_>) -> Result<bool> {
        let mut found = false;
        for team in self.teams.values() {
            if let Some(path) = &team.machine_path {
                found |= batch.read(path, false).map_err(Error::store)?.is_some();
            }
        }
        Ok(found)
    }
    pub fn classify(
        &mut self,
        batch: &mut Admin<'_>,
        keys: &[Identity],
        writing: bool,
    ) -> Result<()> {
        self.classify_selected(batch, keys, writing, None)
    }
    pub fn classify_user(
        &mut self,
        batch: &mut Admin<'_>,
        keys: &[Identity],
        name: &str,
    ) -> Result<()> {
        let teams = self.members[name].clone();
        self.classify_selected(batch, keys, true, Some(&teams))
    }
    fn classify_selected(
        &mut self,
        batch: &mut Admin<'_>,
        keys: &[Identity],
        writing: bool,
        selected: Option<&BTreeSet<String>>,
    ) -> Result<()> {
        for (team, definition) in &self.teams {
            if selected.is_some_and(|teams| !teams.contains(team)) {
                continue;
            }
            let Some(path) = &definition.machine_path else {
                continue;
            };
            let Some(raw) = batch.read(path, false).map_err(Error::store)? else {
                if selected.is_some() {
                    return Err(Error::class("machine classification record missing; ask an operator to inspect the team record").subject(path));
                }
                continue;
            };
            let document = sops::decrypt(raw, keys).map_err(crypto)?;
            if writing {
                document.ensure_writable().map_err(crypto)?;
            }
            let data = document.data();
            if fields(data)?
                .iter()
                .any(|(k, _)| !matches!(*k, "name" | "passphrase"))
            {
                return Err(Error::class("invalid machine record"));
            }
            let name = text(required(data, "name")?)?;
            let pass = text(required(data, "passphrase")?)?;
            if pass.is_empty() || pass.contains('\0') || pass.len() > sops::MAX_SCALAR_BYTES {
                return Err(Error::class("invalid machine passphrase record"));
            }
            if !self
                .members
                .get(name)
                .is_some_and(|teams| teams.len() == 1 && teams.contains(team))
            {
                return Err(Error::class("machine record membership mismatch").subject(path));
            }
            if self.machines.insert(name.into(), path.clone()).is_some() {
                return Err(Error::class("ambiguous machine identity"));
            }
        }
        Ok(())
    }
    pub fn all(&self, name: &str) -> bool {
        self.members[name].iter().any(|t| self.teams[t].all)
    }
    pub fn operators(&self) -> BTreeSet<String> {
        self.members
            .keys()
            .filter(|name| self.all(name))
            .map(|name| self.recipients[name].clone())
            .collect()
    }
    pub fn operator(&self, keys: &[Identity]) -> Result<String> {
        self.members
            .keys()
            .find(|n| {
                self.all(n)
                    && keys
                        .iter()
                        .any(|k| k.recipient().to_string() == self.recipients[*n])
            })
            .cloned()
            .ok_or(Error::class(
                "a matching existing operator identity is required",
            ))
    }
    pub fn ordinary(&self, path: &str) -> BTreeSet<String> {
        let set = path.strip_suffix(".yaml").unwrap_or(path);
        self.members
            .iter()
            .filter(|(_, teams)| {
                teams
                    .iter()
                    .any(|t| self.teams[t].all || self.teams[t].decrypt.contains(set))
            })
            .map(|(n, _)| self.recipients[n].clone())
            .collect()
    }
    pub fn credential(&self, name: &str) -> BTreeSet<String> {
        let mut recipients = self.operators();
        recipients.insert(self.recipients[name].clone());
        recipients
    }
    pub fn policies(&self, name: &str) -> BTreeSet<String> {
        self.members[name]
            .iter()
            .flat_map(|t| self.teams[t].policies.iter().cloned())
            .chain([format!("rotate-{name}")])
            .collect()
    }
    pub fn service(&self, name: &str) -> bool {
        self.members[name].iter().any(|t| self.teams[t].service)
    }
    pub fn encode_members(&self) -> Result<sops::Plaintext> {
        let mut entries = Vec::new();
        for (name, teams) in &self.members {
            entries.push(Entry::Pair(
                name.clone(),
                Value::Sequence(
                    teams
                        .iter()
                        .map(|t| Value::string(t))
                        .collect::<std::result::Result<_, _>>()
                        .map_err(crypto)?,
                ),
            ));
        }
        sops::render(&Value::Mapping(entries)).map_err(crypto)
    }
    pub fn list(&self) -> Result<output::Prepared> {
        output::prepare(output::MAX_OUTPUT_BYTES, |w| {
            w.text("NAME\tTEAMS\tMACHINE\n")?;
            for (name, teams) in &self.members {
                w.text(&output::public_name(name))?;
                w.text("\t")?;
                for (i, team) in teams.iter().enumerate() {
                    if i > 0 {
                        w.text(",")?;
                    }
                    w.text(&output::public_name(team))?;
                }
                w.text(if self.machines.contains_key(name) {
                    "\ttrue\n"
                } else {
                    "\tfalse\n"
                })?;
            }
            Ok(())
        })
    }
}
