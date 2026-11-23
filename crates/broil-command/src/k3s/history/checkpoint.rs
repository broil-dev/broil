// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{decode_record, encode_record};
use crate::k3s::release::Refusal;
use serde_json::Value;

const KEYS: [&str; 9] = [
    "schema",
    "kind",
    "scope",
    "owner",
    "pruned_operations",
    "pruned_releases",
    "pruned_through_sequence",
    "pruned_kinds",
    "chain_sha256",
];

pub const LIMIT: usize = 589_824;

pub const KINDS: usize = 1024;

pub fn encode(value: &Value) -> Result<Vec<u8>, Refusal> {
    check_kinds("pruned_kinds", &value["pruned_kinds"])?;
    encode_record(value, "history-checkpoint", &KEYS, LIMIT)
}

pub(super) fn check_kinds(field: &str, kinds: &Value) -> Result<(), Refusal> {
    match kinds {
        Value::Null => Ok(()),
        Value::Array(entries) => {
            if entries.len() > KINDS {
                return Err(integrity(format!(
                    "{field} holds {} entries; at most {KINDS}",
                    entries.len()
                )));
            }
            let mut previous: Option<(&str, &str, &str)> = None;
            for entry in entries {
                let key = entry_key(entry)
                    .ok_or_else(|| integrity(format!("a {field} entry is outside its grammars")))?;
                if previous.is_some_and(|p| p >= key) {
                    return Err(integrity(format!(
                        "{field} is not a sorted union without duplicates"
                    )));
                }
                previous = Some(key);
            }
            Ok(())
        }
        _ => Err(integrity(format!("{field} is neither a list nor null"))),
    }
}

pub fn decode(bytes: &[u8]) -> Result<Value, Refusal> {
    if bytes.len() > LIMIT {
        return Err(integrity(format!(
            "the history checkpoint is {} bytes; the limit is {LIMIT}",
            bytes.len()
        )));
    }
    decode_record(bytes, encode).map_err(|r| Refusal::new("integrity", r.boundary, r.detail))
}

pub fn merge_kinds(existing: &Value, added: &Value) -> Value {
    let (Some(existing), Some(added)) = (existing.as_array(), added.as_array()) else {
        return Value::Null;
    };
    let mut union = std::collections::BTreeMap::new();
    for entry in existing.iter().chain(added) {
        if let Some((namespace, api_version, kind)) = entry_key(entry) {
            union.insert(
                (namespace.to_owned(), api_version.to_owned(), kind.to_owned()),
                serde_json::json!({"api_version": api_version, "kind": kind, "namespace": namespace}),
            );
        }
    }
    if union.len() > KINDS {
        return Value::Null;
    }
    Value::Array(union.into_values().collect())
}

pub fn completion(current: &str, before: &str, after: &str) -> Result<bool, Refusal> {
    if current == before {
        Ok(true)
    } else if current == after {
        Ok(false)
    } else {
        Err(Refusal::new(
            "integrity",
            "history",
            "the history checkpoint is neither the prune's predecessor nor its successor",
        ))
    }
}

fn integrity(detail: String) -> Refusal {
    Refusal::new("integrity", "history", detail)
}

fn entry_key(entry: &Value) -> Option<(&str, &str, &str)> {
    let fields = entry.as_object()?;
    if fields.len() != 3 {
        return None;
    }
    let api_version = fields.get("api_version")?.as_str()?;
    let kind = fields.get("kind")?.as_str()?;
    let namespace = fields.get("namespace")?.as_str()?;
    let version_ok = match api_version.split_once('/') {
        None => label(api_version),
        Some((group, version)) => subdomain(group) && label(version),
    };
    let kind_ok = (1..=63).contains(&kind.len())
        && kind.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && kind.as_bytes()[0].is_ascii_alphabetic()
        && kind.as_bytes()[kind.len() - 1].is_ascii_alphanumeric();
    (version_ok && kind_ok && label(namespace)).then_some((namespace, api_version, kind))
}

fn label(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn subdomain(s: &str) -> bool {
    s.len() <= 253 && s.split('.').all(label)
}
