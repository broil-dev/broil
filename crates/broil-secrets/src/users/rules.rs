// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::sops::{CreationRule, Entry, Plaintext, Value};

pub(super) struct Rules {
    pub original: Plaintext,
    tree: Value,
    dirty: bool,
}
fn literal(path: &str) -> String {
    format!("(?s)^{}$", regex::escape(path))
}
fn recipients(rule: &Value) -> Result<BTreeSet<String>> {
    let value = rule
        .get("age")
        .ok_or(Error::class("missing rule recipients"))?;
    let text = model::text(value)?;
    if text.trim().is_empty() {
        return Err(Error::class("empty rule recipients"));
    }
    text.split(',')
        .map(|r| {
            r.trim()
                .parse::<age::Recipient>()
                .map(|r| r.to_string())
                .map_err(|_| Error::class("invalid rule recipient"))
        })
        .collect()
}
fn set_recipients(rule: &mut Value, recipients: &BTreeSet<String>) -> Result<()> {
    if recipients.is_empty() {
        return Err(Error::class("empty rule recipients"));
    }
    rule.put(
        "age",
        Value::string(&recipients.iter().cloned().collect::<Vec<_>>().join(",")).map_err(crypto)?,
    )
    .map_err(crypto)
}
impl Rules {
    pub fn load(batch: &mut Admin<'_>) -> Result<Self> {
        let original = batch
            .read(".sops.yaml", false)
            .map_err(Error::store)?
            .ok_or(Error::class("missing recipient rules"))?;
        let tree = sops::parse_plaintext(&original).map_err(crypto)?;
        if tree
            .get("creation_rules")
            .and_then(Value::sequence)
            .is_none()
        {
            return Err(Error::class("invalid creation rules"));
        }
        Ok(Self {
            original,
            tree,
            dirty: false,
        })
    }
    pub fn select_original(&self, path: &str) -> Result<CreationRule> {
        sops::recipients_for(&self.original, path).map_err(crypto)
    }
    pub fn select(&self, path: &str) -> Result<CreationRule> {
        sops::recipients_for(&self.encode()?, path).map_err(crypto)
    }
    pub fn encode(&self) -> Result<Plaintext> {
        if !self.dirty {
            return Plaintext::copy_from(self.original.as_str()).map_err(crypto);
        }
        sops::render(&self.tree).map_err(crypto)
    }
    fn sequence(&mut self) -> Result<&mut Vec<Value>> {
        let Value::Mapping(root) = &mut self.tree else {
            return Err(Error::class("invalid rules"));
        };
        root.iter_mut()
            .find_map(|e| match e {
                Entry::Pair(k, Value::Sequence(v)) if k == "creation_rules" => Some(v),
                _ => None,
            })
            .ok_or(Error::class("invalid rules"))
    }
    pub fn update_operators(
        &mut self,
        before: &Roster,
        after: &Roster,
        retired_credential: Option<&str>,
    ) -> Result<()> {
        let old = before.operators();
        let new = after.operators();
        let removed: BTreeSet<_> = before
            .recipients
            .values()
            .filter(|r| !after.recipients.values().any(|a| a == *r))
            .cloned()
            .collect();
        let retired = retired_credential.map(literal);
        let mut changed = false;
        let sequence = self.sequence()?;
        for rule in sequence.iter_mut() {
            if matches!(rule, Value::Comment(_)) {
                continue;
            }
            if rule.get("age").is_none() {
                continue;
            }
            let existing = recipients(rule)?;
            let affected =
                !existing.is_disjoint(&removed) || (!existing.is_disjoint(&old) && old != new);
            if !affected {
                continue;
            }
            sops::validate_admin_rule(rule).map_err(crypto)?;
            let mut wanted = existing
                .difference(&removed)
                .cloned()
                .collect::<BTreeSet<_>>();
            if !existing.is_disjoint(&old) {
                wanted.extend(new.iter().cloned());
            }
            if wanted.is_empty()
                && retired.as_deref() == rule.get("path_regex").map(model::text).transpose()?
            {
                continue;
            }
            set_recipients(rule, &wanted)?;
            changed |= existing != wanted;
        }
        if let Some(retired) = retired {
            let count = sequence.len();
            sequence.retain(|rule| {
                rule.get("path_regex").and_then(|v| model::text(v).ok()) != Some(retired.as_str())
            });
            changed |= sequence.len() != count;
        }
        self.dirty |= changed;
        Ok(())
    }
    pub fn rotate(&mut self, roster: &Roster, name: &str, replacement: &str) -> Result<()> {
        let old = &roster.recipients[name];
        let mut scoped_patterns = BTreeSet::new();
        for path in roster.members[name]
            .iter()
            .flat_map(|team| {
                roster.teams[team]
                    .decrypt
                    .iter()
                    .map(|s| format!("{s}.yaml"))
            })
            .chain([format!("credentials/{name}.yaml")])
        {
            scoped_patterns.insert(literal(&path));
            scoped_patterns.insert(format!("^{}$", regex::escape(&path)));
            scoped_patterns.insert(format!("^{}$", regex::escape(&path).replace("\\.", "[.]")));
        }
        let mut changed = false;
        for rule in self.sequence()? {
            if matches!(rule, Value::Comment(_)) || rule.get("age").is_none() {
                continue;
            }
            if !recipients(rule)?.contains(old) {
                continue;
            }
            sops::validate_admin_rule(rule).map_err(crypto)?;
            if !roster.all(name)
                && !rule
                    .get("path_regex")
                    .map(model::text)
                    .transpose()?
                    .is_some_and(|p| scoped_patterns.contains(p))
            {
                return Err(Error::class(
                    "scoped rotation requires literal owned rules; ask an operator to resolve broad or ambiguous grants",
                ));
            }
            let value = model::text(rule.get("age").unwrap())?
                .split(',')
                .map(|r| {
                    if r.trim() == old {
                        replacement
                    } else {
                        r.trim()
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            rule.put("age", Value::string(&value).map_err(crypto)?)
                .map_err(crypto)?;
            sops::validate_admin_rule(rule).map_err(crypto)?;
            changed = true;
        }
        self.dirty |= changed;
        Ok(())
    }
    pub fn exact(
        &mut self,
        path: &str,
        policy: &CreationRule,
        wanted: &BTreeSet<String>,
    ) -> Result<()> {
        let pattern = literal(path);
        let mut rule = Value::Mapping(vec![Entry::Pair(
            "path_regex".into(),
            Value::string(&pattern).map_err(crypto)?,
        )]);
        set_recipients(&mut rule, wanted)?;
        if let Some(key) = policy.selector().recorded_key() {
            rule.put(
                key,
                Value::string(policy.selector().expression()).map_err(crypto)?,
            )
            .map_err(crypto)?;
        }
        if let Some(mac) = policy.mac_only_encrypted() {
            let value = sops::parse_plaintext(
                &Plaintext::copy_from(if mac { "v: true\n" } else { "v: false\n" })
                    .map_err(crypto)?,
            )
            .map_err(crypto)?
            .take("v")
            .map_err(crypto)?;
            rule.put("mac_only_encrypted", value).map_err(crypto)?;
        }
        sops::validate_admin_rule(&rule).map_err(crypto)?;
        self.dirty = true;
        let sequence = self.sequence()?;
        if let Some(index) = sequence.iter().position(|existing| {
            existing.get("path_regex").and_then(|v| model::text(v).ok()) == Some(pattern.as_str())
                && model::fields(existing).is_ok_and(|fields| {
                    fields.iter().all(|(key, _)| {
                        matches!(
                            *key,
                            "path_regex"
                                | "age"
                                | "unencrypted_suffix"
                                | "encrypted_suffix"
                                | "unencrypted_regex"
                                | "encrypted_regex"
                                | "encrypted_comment_regex"
                                | "unencrypted_comment_regex"
                                | "mac_only_encrypted"
                        )
                    })
                })
                && [
                    "unencrypted_suffix",
                    "encrypted_suffix",
                    "unencrypted_regex",
                    "encrypted_regex",
                    "encrypted_comment_regex",
                    "unencrypted_comment_regex",
                    "mac_only_encrypted",
                ]
                .iter()
                .all(|key| match (existing.get(key), rule.get(key)) {
                    (None, None) => true,
                    (Some(a), Some(b)) => a.same(b),
                    _ => false,
                })
        }) {
            set_recipients(&mut sequence[index], wanted)?;
            let existing = sequence.remove(index);
            sequence.insert(0, existing);
        } else {
            sequence.insert(0, rule);
        }
        Ok(())
    }
}

pub(super) fn check_original(
    document: &sops::Document,
    rule: &CreationRule,
    expected: &BTreeSet<String>,
    owners: &BTreeSet<String>,
    credential: bool,
) -> Result<BTreeSet<String>> {
    document.ensure_writable().map_err(crypto)?;
    let actual = document.recipients().map_err(crypto)?;
    let from_rule = rule
        .recipients()
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    if actual != from_rule
        || !expected.is_subset(&actual)
        || actual.intersection(owners).any(|r| !expected.contains(r))
        || (credential && actual != *expected)
    {
        return Err(
            Error::class("ambiguous document, membership or recipient-rule ownership")
                .subject(rule.final_path()),
        );
    }
    let a = document.selector();
    let b = rule.selector();
    if a.recorded_key().unwrap_or("unencrypted_suffix")
        != b.recorded_key().unwrap_or("unencrypted_suffix")
        || a.expression() != b.expression()
        || document.mac_only_encrypted().unwrap_or(false)
            != rule.mac_only_encrypted().unwrap_or(false)
    {
        return Err(
            Error::class("document and creation-rule policy conflict").subject(rule.final_path())
        );
    }
    document.rewrap(rule).map_err(crypto)?;
    Ok(actual.difference(owners).cloned().collect())
}

pub(super) fn protected_create(
    rules: &Rules,
    path: &str,
    plaintext: &Plaintext,
    fields: &[&str],
) -> Result<Plaintext> {
    let rule = rules.select(path)?;
    let encoded = sops::create(plaintext, &rule).map_err(crypto)?;
    protected_fields(&encoded, path, fields)?;
    Ok(encoded)
}
pub(super) fn protected_fields(encoded: &Plaintext, path: &str, fields: &[&str]) -> Result<()> {
    let (tree, _) = sops::inspect(encoded).map_err(crypto)?;
    for field in fields {
        if !tree
            .get(field)
            .and_then(Value::scalar)
            .is_some_and(|v| v.as_str().starts_with("ENC[AES256_GCM,"))
        {
            return Err(
                Error::class("creation rule exposes a credential or machine field").subject(path),
            );
        }
    }
    Ok(())
}
