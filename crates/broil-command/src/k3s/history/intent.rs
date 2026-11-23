// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{decode_record, encode_record};
use crate::k3s::release::Refusal;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const LIMIT: usize = 4_718_592;
const OTHERS: usize = 4_194_304;

const KEYS: [&str; 15] = [
    "schema",
    "kind",
    "scope",
    "owner",
    "prune",
    "approval",
    "policy",
    "cutoff_ms",
    "phase",
    "checkpoint_before",
    "checkpoint_after",
    "operations",
    "releases",
    "kinds",
    "hosts",
];

pub fn encode(value: &Value) -> Result<Vec<u8>, Refusal> {
    if !matches!(value["phase"].as_str(), Some("local" | "hosts")) {
        return Err(Refusal::new(
            "integrity",
            "history",
            "the prune intent's phase is not local or hosts",
        ));
    }
    super::checkpoint::check_kinds("kinds", &value["kinds"])?;
    if !value["kinds"].is_null() {
        let mut others = value.clone();
        others["kinds"] = Value::Null;
        encode_record(&others, "prune-intent", &KEYS, OTHERS)?;
    }
    encode_record(value, "prune-intent", &KEYS, LIMIT)
}

pub fn decode(bytes: &[u8]) -> Result<Value, Refusal> {
    decode_record(bytes, encode)
}

pub fn merge(lists: &Value, carried: &Value) -> Result<Value, Refusal> {
    let malformed = || {
        Refusal::new(
            "integrity",
            "history",
            "a pending host list is not [{machine, entries}]",
        )
    };
    let mut machines: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for source in [lists, carried] {
        for host in source.as_array().ok_or_else(malformed)? {
            let machine = host["machine"].as_str().ok_or_else(malformed)?;
            let entries = machines.entry(machine.to_owned()).or_default();
            for entry in host["entries"].as_array().ok_or_else(malformed)? {
                if !entry["attempt"].is_string() || !entry["sequence"].is_u64() {
                    return Err(malformed());
                }
                if !entries.iter().any(|e| e["attempt"] == entry["attempt"]) {
                    entries.push(entry.clone());
                }
            }
        }
    }
    Ok(Value::Array(
        machines
            .into_iter()
            .map(|(machine, entries)| json!({"machine": machine, "entries": entries}))
            .collect(),
    ))
}
