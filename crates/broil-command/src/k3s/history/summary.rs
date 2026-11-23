// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{decode_record, encode_record};
use crate::k3s::release::Refusal;
use serde_json::{Value, json};
use std::io::Read;
use std::path::Path;

pub const LIMIT: usize = 16_384;
pub const CITES: usize = 64;

const KEYS: [&str; 20] = [
    "schema",
    "kind",
    "operation",
    "sequence",
    "created_ms",
    "action",
    "family",
    "release",
    "application",
    "run",
    "machines",
    "attempts",
    "outcome",
    "completion_unknown",
    "cleanup_unknown",
    "recovery",
    "settles",
    "pinned",
    "cites",
    "cites_complete",
];

fn malformed() -> Refusal {
    Refusal::new("integrity", "history", "an operation summary is malformed")
}

fn texts(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|a| a.iter().all(Value::is_string))
}

fn optional_text(value: &Value) -> bool {
    value.is_null() || value.is_string()
}

pub fn encode(value: &Value) -> Result<Vec<u8>, Refusal> {
    let typed = value["operation"].is_string()
        && value["sequence"].is_u64()
        && value["created_ms"].is_u64()
        && value["action"].is_string()
        && ["family", "release", "application", "settles"]
            .iter()
            .all(|k| optional_text(&value[*k]))
        && (value["run"].is_null() || value["run"].is_object())
        && texts(&value["machines"])
        && value["attempts"].is_u64()
        && value["outcome"].is_string()
        && value["completion_unknown"].is_boolean()
        && value["cleanup_unknown"].is_boolean()
        && value["recovery"].is_string()
        && texts(&value["pinned"])
        && texts(&value["cites"])
        && value["cites_complete"].is_boolean();
    if !typed {
        return Err(malformed());
    }
    if value["cites"].as_array().map_or(0, Vec::len) > CITES {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("an operation summary lists more than {CITES} cites"),
        ));
    }
    encode_record(value, "operation-summary", &KEYS, LIMIT)
}

pub fn decode(bytes: &[u8]) -> Result<Value, Refusal> {
    decode_record(bytes, encode)
}

pub fn derive(input: &Value) -> Result<Value, Refusal> {
    let action = input["action"].as_str().ok_or_else(malformed)?;
    let mut pinned: Vec<&Value> = Vec::new();
    if action == "release-deliver" {
        for pin in input["pins"].as_array().into_iter().flatten() {
            let machine = &pin["machine"];
            if matches!(pin["effect"].as_str(), Some("complete" | "partial"))
                && !pinned.contains(&machine)
            {
                pinned.push(machine);
            }
        }
    }
    let cites = input["cites"].as_array().ok_or_else(malformed)?;
    let projection = &input["projection"];
    let summary = json!({
        "schema": 1, "kind": "operation-summary", "operation": input["operation"],
        "sequence": input["sequence"], "created_ms": input["created_ms"], "action": action,
        "family": super::family(action, &input["subject"]), "release": input["release"],
        "application": input["application"], "run": input["run"], "machines": input["machines"],
        "attempts": input["attempts"], "outcome": projection["outcome"],
        "completion_unknown": projection["completion_unknown"],
        "cleanup_unknown": projection["cleanup_unknown"], "recovery": projection["recovery"],
        "settles": input["settles"], "pinned": pinned,
        "cites": &cites[..cites.len().min(CITES)], "cites_complete": cites.len() <= CITES,
    });
    encode(&summary)?;
    Ok(summary)
}

pub fn stale(bytes: Option<&[u8]>, current: &Value) -> bool {
    bytes.is_none_or(|bytes| decode(bytes).ok().as_ref() != Some(current))
}

pub fn stream(operations: &Path, visit: &mut dyn FnMut(Value)) -> Result<(usize, u64), Refusal> {
    let unreadable = |what: &str| {
        Refusal::new(
            "integrity",
            "history",
            format!("the operation summary of {what} cannot be read"),
        )
    };
    let mut names: Vec<std::ffi::OsString> = std::fs::read_dir(operations)
        .map_err(|_| unreadable("the target"))?
        .map(|entry| entry.map(|e| e.file_name()))
        .collect::<std::io::Result<_>>()
        .map_err(|_| unreadable("the target"))?;
    names.sort();
    let (mut count, mut total) = (0usize, 0u64);
    let mut bytes = Vec::with_capacity(LIMIT + 1);
    for name in names {
        let what = name.to_string_lossy().into_owned();
        bytes.clear();
        std::fs::File::open(operations.join(&name).join("summary.json"))
            .and_then(|file| file.take(LIMIT as u64 + 1).read_to_end(&mut bytes))
            .map_err(|_| unreadable(&what))?;
        let summary = decode(&bytes).map_err(|_| unreadable(&what))?;
        total += bytes.len() as u64;
        count += 1;
        visit(summary);
    }
    Ok((count, total))
}
