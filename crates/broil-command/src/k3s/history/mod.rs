// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub mod checkpoint;
pub mod host_checkpoint;
pub mod intent;
pub mod summary;

use super::release::Refusal;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const CAP: u64 = 16_384;
pub const RESERVE: u64 = 16;
pub const WARNING: u64 = 14_746;
const DAY_MS: u64 = 86_400_000;

pub const READ_PRIMITIVES: &[&str] = &[
    "read_operations",
    "agent_context",
    "stream",
    "history_records",
    "complete_records",
];

fn refusal(failure: &'static str, detail: impl Into<String>) -> Refusal {
    Refusal::new(failure, "history", detail)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub keep_days: u32,
    pub keep_last: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            keep_days: 90,
            keep_last: 500,
        }
    }
}

impl Policy {
    pub fn new(keep_days: u32, keep_last: u32) -> Result<Self, Refusal> {
        if !(1..=3650).contains(&keep_days) {
            return Err(Refusal::new(
                "configuration",
                "keep-days",
                format!("--keep-days is {keep_days}; it must be 1 to 3650"),
            ));
        }
        if !(100..=16_384).contains(&keep_last) {
            return Err(Refusal::new(
                "configuration",
                "keep-last",
                format!("--keep-last is {keep_last}; it must be 100 to 16384"),
            ));
        }
        Ok(Self {
            keep_days,
            keep_last,
        })
    }
}

pub fn cutoff_ms(policy: &Policy, now_ms: u64) -> u64 {
    (now_ms / DAY_MS * DAY_MS).saturating_sub(u64::from(policy.keep_days) * DAY_MS)
}

pub fn inside_policy(policy: &Policy, now_ms: u64, operations: &[Value]) -> BTreeSet<String> {
    let cutoff = cutoff_ms(policy, now_ms);
    let mut by_sequence: Vec<&Value> = operations.iter().collect();
    by_sequence.sort_by_key(|o| std::cmp::Reverse(o["sequence"].as_u64().unwrap_or(0)));
    let newest = by_sequence.iter().take(policy.keep_last as usize);
    let recent = operations
        .iter()
        .filter(|o| o["created_ms"].as_u64().is_some_and(|c| c >= cutoff));
    newest
        .copied()
        .chain(recent)
        .filter_map(|o| o["operation"].as_str().map(str::to_owned))
        .collect()
}

pub fn family(action: &str, request: &Value) -> Option<String> {
    let text = |value: &Value| value.as_str().map(str::to_owned);
    match action {
        "release-deliver" | "release-apply" => return text(&request["release"]),
        "release-rollback" | "release-retain" => return text(&request["application"]),
        _ => {}
    }
    if !request["consumer"].is_null() || action == "prepare-node-registry" {
        return text(&request["consumer"]["resource"]);
    }
    match action {
        "reconcile-issuer" | "reconcile-certificate" | "reconcile-registry-auth" => {
            text(&request["resource"])
        }
        "join-server"
        | "join-agent"
        | "prepare-server-inputs"
        | "restart-member"
        | "node-drain"
        | "node-uncordon"
        | "node-remove"
        | "node-replace" => text(&request["member"]),
        _ => None,
    }
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn settled(operation: &Value) -> bool {
    operation["settled"] == true
}

fn unit_reason(
    release: &Value,
    unit: &[&Value],
    store: &Value,
    operations: &[&Value],
    inside: &BTreeSet<String>,
    cutoff: u64,
) -> Option<&'static str> {
    let name = release["release"].as_str().unwrap_or("");
    let application = &release["application"];
    if unit.iter().any(|o| !settled(o)) {
        return Some("recovery");
    }
    if unit.iter().any(|o| o["cited"] == true) {
        return Some("cited");
    }
    if strings(&store["kept_set"]).contains(&name) {
        return Some("kept-release");
    }
    let id = |o: &Value| o["operation"].as_str().unwrap_or("").to_owned();
    if release["created_ms"].as_u64().is_none_or(|c| c >= cutoff)
        || unit.iter().any(|o| inside.contains(&id(o)))
    {
        return Some("policy");
    }
    let participants = strings(&store["participants"]);
    let delivers: Vec<&&Value> = unit
        .iter()
        .filter(|o| o["action"] == "release-deliver")
        .collect();
    let last = delivers
        .iter()
        .filter_map(|o| o["sequence"].as_u64())
        .max()
        .unwrap_or(0);
    let pinned: BTreeSet<&str> = delivers
        .iter()
        .flat_map(|o| strings(&o["pinned"]))
        .collect();
    let released = |machine: &str| {
        operations.iter().any(|o| {
            o["action"] == "release-retain"
                && o["outcome"] == "succeeded"
                && o["application"] == *application
                && o["sequence"].as_u64().is_some_and(|s| s > last)
                && strings(&o["released"]).contains(&name)
                && strings(&o["machines"]).contains(&machine)
        })
    };
    if pinned
        .iter()
        .any(|m| participants.contains(m) && !released(m))
    {
        return Some("pinned");
    }
    let hooked = unit.iter().any(|o| {
        o["hooks"].as_array().into_iter().flatten().any(|h| {
            h["repeatable"] == false
                && matches!(h["outcome"].as_str(), Some("succeeded" | "unknown"))
        })
    });
    if hooked {
        let created = release["created_ms"].as_u64().unwrap_or(0);
        let superseded = store["releases"].as_array().into_iter().flatten().any(|r| {
            r["application"] == *application
                && r["created_ms"].as_u64().is_some_and(|c| c > created)
                && operations.iter().any(|o| {
                    o["action"] == "release-apply"
                        && o["release"] == r["release"]
                        && o["outcome"] == "succeeded"
                })
        });
        if !superseded {
            return Some("kept-release");
        }
    }
    None
}

pub fn classify<'s>(policy: &Policy, store: &'s Value) -> Result<Value, Refusal> {
    let malformed = || refusal("integrity", "an operation summary is malformed");
    let mut operations: Vec<&'s Value> = store["operations"]
        .as_array()
        .ok_or_else(malformed)?
        .iter()
        .collect();
    if operations
        .iter()
        .any(|o| !o["operation"].is_string() || !o["sequence"].is_u64() || !o["action"].is_string())
    {
        return Err(malformed());
    }
    operations.sort_by_key(|o| o["sequence"].as_u64());
    let now = store["now_ms"].as_u64().ok_or_else(malformed)?;
    let cutoff = cutoff_ms(policy, now);
    let all: Vec<Value> = operations.iter().map(|o| (*o).clone()).collect();
    let inside = inside_policy(policy, now, &all);
    let mut releases: Vec<&Value> = store["releases"].as_array().into_iter().flatten().collect();
    releases.sort_by_key(|r| r["created_ms"].as_u64());
    let names: BTreeSet<&str> = releases
        .iter()
        .filter_map(|r| r["release"].as_str())
        .collect();
    let unit_of = |o: &'s Value| o["release"].as_str().filter(|r| names.contains(r));
    let mut unit_reasons: BTreeMap<&str, Option<&'static str>> = BTreeMap::new();
    for release in &releases {
        let name = release["release"].as_str().ok_or_else(malformed)?;
        let unit: Vec<&Value> = operations
            .iter()
            .copied()
            .filter(|o| unit_of(o) == Some(name))
            .collect();
        unit_reasons.insert(
            name,
            unit_reason(release, &unit, store, &operations, &inside, cutoff),
        );
    }
    let remaining = |name: &str| unit_reasons.get(name).is_some_and(Option::is_some);
    let family_of = |o: &'s Value| Some((o["action"].as_str()?, o["family"].as_str()));
    let mut newest: BTreeMap<(&str, Option<&str>), u64> = BTreeMap::new();
    for o in operations.iter().filter(|o| settled(o)) {
        let Some(key) = family_of(o) else { continue };
        let sequence = o["sequence"].as_u64().unwrap_or(0);
        let entry = newest.entry(key).or_insert(sequence);
        *entry = (*entry).max(sequence);
    }
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    let mut summary = BTreeMap::from([
        ("recovery", 0u64),
        ("cited", 0),
        ("kept-release", 0),
        ("newest", 0),
        ("policy", 0),
        ("removed", 0),
    ]);
    for o in &operations {
        let id = o["operation"].as_str().unwrap_or("");
        let retain_cited = o["action"] == "release-retain"
            && o["outcome"] == "succeeded"
            && strings(&o["released"]).iter().any(|r| remaining(r));
        let base = if !settled(o) {
            Some("recovery")
        } else if o["cited"] == true || retain_cited {
            Some("cited")
        } else {
            None
        };
        let reason = match unit_of(o) {
            Some(name) if !remaining(name) => None,
            Some(_) => base.or(Some("kept-release")),
            None => base.or_else(|| {
                if settled(o)
                    && family_of(o).and_then(|k| newest.get(&k)) == o["sequence"].as_u64().as_ref()
                {
                    Some("newest")
                } else if inside.contains(id) {
                    Some("policy")
                } else {
                    None
                }
            }),
        };
        match reason {
            Some(reason) => {
                *summary.entry(reason).or_default() += 1;
                kept.push(
                    json!({"action": o["action"], "created_ms": o["created_ms"], "operation": id,
                    "reason": reason, "release": o["release"]}),
                );
            }
            None => {
                *summary.entry("removed").or_default() += 1;
                removed.push(json!(id));
            }
        }
    }
    let mut released_removed = Vec::new();
    let mut released_kept = Vec::new();
    for release in &releases {
        let name = release["release"].as_str().unwrap_or("");
        match unit_reasons.get(name).copied().flatten() {
            Some(reason) => released_kept.push(json!({"reason": reason, "release": name})),
            None => released_removed.push(json!(name)),
        }
    }
    Ok(json!({
        "before": operations.len(), "after": operations.len() - removed.len(),
        "removed": removed, "kept": kept,
        "releases": {"removed": released_removed, "kept": released_kept},
        "summary": summary,
    }))
}

pub fn need(leaf: &str, input: &Value) -> Value {
    let listed = input["operations"].as_u64().unwrap_or(0);
    let (operations, releases, attempts, reserve) = match leaf {
        "release deploy" => (2, u64::from(input["prepare_records"] == true), 2, false),
        "release prepare" => (0, 1, 0, false),
        "release apply" => (1, 0, 1, input["settles"] == true),
        "release deliver" | "release rollback" | "release retain" | "node drain"
        | "node uncordon" | "node remove" | "registry reconcile" => (1, 0, 1, false),
        "operation retry" | "operation resume" => (0, 0, 1, true),
        "node replace"
        | "create"
        | "reconcile"
        | "node join"
        | "node join-agents"
        | "credentials reconcile" => (listed, 0, listed, false),
        _ => (0, 0, 0, false),
    };
    json!({"operations": operations, "releases": releases, "attempts": attempts, "reserve": reserve})
}

pub fn workflow_need(_leaf: &str, plan: &Value) -> Value {
    let mut operations = 0u64;
    let mut hosts = BTreeMap::<String, u64>::new();
    for operation in plan["waves"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|w| w.as_array().into_iter().flatten())
    {
        operations += 1;
        let selected: BTreeSet<&str> = operation["hosts"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for host in selected {
            *hosts.entry(host.to_owned()).or_default() += 1;
        }
    }
    let attempts = hosts.values().copied().max().unwrap_or(0);
    json!({"operations": operations, "releases": 0, "attempts": attempts, "hosts": hosts, "reserve": false})
}

pub fn fits(need: &Value, usage: &Value) -> bool {
    let limit = if need["reserve"] == true {
        CAP
    } else {
        CAP - RESERVE
    };
    let count = |v: &Value| v.as_u64().unwrap_or(u64::MAX);
    let fullest = usage["hosts"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(_, v)| count(v))
        .max()
        .unwrap_or(0);
    let room =
        |used: u64, wanted: u64, limit: u64| wanted == 0 || used.saturating_add(wanted) <= limit;
    room(
        count(&usage["operations"]),
        count(&need["operations"]),
        limit,
    ) && room(count(&usage["releases"]), count(&need["releases"]), CAP)
        && room(fullest, count(&need["attempts"]), limit)
}

pub fn warning(usage: &Value) -> bool {
    ["operations", "releases", "attempts"]
        .iter()
        .any(|k| usage[*k].as_u64().is_some_and(|n| n >= WARNING))
}

pub fn next_sequence(sequences: &[u64], pruned_through: Option<u64>) -> u64 {
    sequences
        .iter()
        .copied()
        .chain(pruned_through)
        .max()
        .unwrap_or(0)
        + 1
}

pub fn host_admission(host: &Value, sequence: u64, reserve: bool) -> Result<(), Refusal> {
    let watermark = host["watermark_sequence"].as_u64().unwrap_or(0);
    if sequence <= watermark {
        return Err(refusal(
            "ownership",
            format!(
                "operation sequence {sequence} is at or below the host's watermark {watermark}"
            ),
        ));
    }
    let attempts = host["attempts"].as_u64().unwrap_or(u64::MAX);
    let limit = if reserve { CAP } else { CAP - RESERVE };
    if attempts.saturating_add(1) > limit {
        return Err(Refusal::new(
            "bound",
            "store-full",
            format!("the host holds {attempts} attempt records; the limit is {limit}"),
        ));
    }
    Ok(())
}

pub fn chain_sha256(
    previous: &str,
    approval: &str,
    operations: &[String],
    releases: &[String],
) -> String {
    super::state::hash(
        "broil-history-chain-v1",
        &json!({"previous": previous, "approval": approval, "operations": operations, "releases": releases}),
    )
    .unwrap_or_default()
}

pub fn approval(decision: &Value) -> String {
    let mut bound = decision.clone();
    if let Some(hosts) = bound["hosts"].as_array_mut() {
        for host in hosts.iter_mut().filter_map(Value::as_object_mut) {
            host.remove("reachable");
        }
    }
    format!(
        "sha256:{}",
        super::state::hash("broil-infra-approval-v1", &bound).unwrap_or_default()
    )
}

fn encode_record(
    value: &Value,
    kind: &str,
    keys: &[&str],
    limit: usize,
) -> Result<Vec<u8>, Refusal> {
    let exact = value.as_object().is_some_and(|fields| {
        fields.len() == keys.len() && keys.iter().all(|k| fields.contains_key(*k))
    });
    if !exact || value["schema"] != 1 || value["kind"] != kind {
        return Err(refusal(
            "integrity",
            format!("the {kind} record does not hold exactly its fields"),
        ));
    }
    let mut bytes = super::state::canonical(value).map_err(|_| {
        refusal(
            "integrity",
            format!("the {kind} record is not canonical JSON"),
        )
    })?;
    bytes.push(b'\n');
    if bytes.len() > limit {
        return Err(Refusal::new(
            "bound",
            "size",
            format!(
                "the {kind} record is {} bytes; the limit is {limit}",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

fn decode_record(
    bytes: &[u8],
    encode: impl Fn(&Value) -> Result<Vec<u8>, Refusal>,
) -> Result<Value, Refusal> {
    let body = bytes.strip_suffix(b"\n").ok_or_else(|| {
        refusal(
            "integrity",
            "a history record does not end in one line feed",
        )
    })?;
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| refusal("integrity", "a history record is not JSON"))?;
    if encode(&value)? != bytes {
        return Err(refusal("integrity", "a history record is not canonical"));
    }
    Ok(value)
}
