// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Failure, Result, Snapshot, hash, operation_id, report, require, rpc,
    session::{Local, fresh, now},
    store::HistoryRead,
};
use crate::k3s::commands::Refusal;
use crate::k3s::history::{self as logic, Policy};
use broil_config::LoadedProject;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const PLAN_LIMIT: usize = 4_194_304;
const CHUNK: usize = 1024;
const BATCH: usize = 1024;
const ZEROS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn refused(failure: Failure, boundary: &'static str, detail: impl Into<String>) -> Refusal {
    Refusal {
        failure,
        boundary: Some(boundary),
        detail: Some(detail.into()),
    }
}

fn named(value: &Value, own: &str, found: &mut Vec<String>) {
    match value {
        Value::String(s) if operation_id(s) && s != own && !found.contains(s) => {
            found.push(s.clone());
        }
        Value::Array(items) => items.iter().for_each(|v| named(v, own, found)),
        Value::Object(map) => map.values().for_each(|v| named(v, own, found)),
        _ => {}
    }
}

fn cites(snapshot: &Snapshot) -> Vec<String> {
    let own = snapshot.request["operation"].as_str().unwrap_or("");
    let mut found = Vec::new();
    named(&snapshot.request, own, &mut found);
    for observation in &snapshot.observations {
        named(&observation["event"], own, &mut found);
    }
    found
}

fn recipe<'a>(snapshot: &'a Snapshot, key: &str) -> Option<&'a Value> {
    snapshot
        .observations
        .iter()
        .map(|o| &o["event"]["recipe"][key])
        .find(|v| !v.is_null())
}

fn text(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_str)
        .map_or(Value::Null, |s| json!(s))
}

fn subject(snapshot: &Snapshot) -> Value {
    let request = &snapshot.request;
    let own = request["operation"].clone();
    let action = request["action"].as_str().unwrap_or("");
    let release = request
        .get("release")
        .filter(|v| v.is_string())
        .cloned()
        .unwrap_or_else(|| text(recipe(snapshot, "release")));
    let application = request
        .get("application")
        .filter(|v| v.is_string())
        .cloned()
        .unwrap_or_else(|| text(recipe(snapshot, "application")));
    let consumer = if request["consumer"].is_null() && action != "prepare-node-registry" {
        Value::Null
    } else {
        let id = &request["consumer"]["projection"]["binding"]["resource"]["id"];
        json!({"resource": if id.is_string() { id.clone() } else { own.clone() }})
    };
    let resource = match action {
        "reconcile-issuer" | "reconcile-certificate" | "reconcile-registry-auth" => {
            let id = &request["resources"][0]["id"];
            if id.is_string() {
                id.clone()
            } else {
                own.clone()
            }
        }
        _ => Value::Null,
    };
    let member = recipe(snapshot, "member")
        .and_then(|m| m["member"].as_str().or(m.as_str()))
        .map_or(own.clone(), |m| json!(m));
    json!({"release": release, "application": application, "consumer": consumer,
        "resource": resource, "member": member})
}

pub(super) fn summary(scope: &Value, snapshot: &Snapshot) -> Result<Value> {
    let request = &snapshot.request;
    let action = request["action"].as_str().ok_or(Failure::Integrity)?;
    let shown = report::report(scope, "show", std::slice::from_ref(snapshot))?;
    let subject = subject(snapshot);
    let run = if matches!(action, "restart-member" | "configure-node-registries") {
        match (
            recipe(snapshot, "run"),
            recipe(snapshot, "position"),
            recipe(snapshot, "plan_sha256"),
        ) {
            (Some(run), Some(position), Some(plan)) => {
                json!({"run": run, "position": position, "plan_sha256": plan})
            }
            _ => Value::Null,
        }
    } else {
        Value::Null
    };
    let machines: Vec<Value> = request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .map(|m| m["machine"].clone())
        .collect();
    let settles = snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "release-settlement")
        .and_then(|o| {
            let mut found = Vec::new();
            named(
                &o["event"],
                request["operation"].as_str().unwrap_or(""),
                &mut found,
            );
            found.into_iter().next()
        });
    let pins: Vec<Value> = snapshot
        .observations
        .iter()
        .map(|o| &o["event"])
        .filter(|e| e["action"] == "pin-image" || e["type"] == "pin-image")
        .map(|e| json!({"machine": e["machine"], "effect": e["effect"]}))
        .collect();
    let input = json!({
        "operation": request["operation"], "sequence": request["sequence"],
        "created_ms": request["created_ms"], "action": action, "subject": subject,
        "release": subject["release"], "application": subject["application"], "run": run,
        "machines": machines, "attempts": snapshot.attempts.len(),
        "projection": {
            "outcome": shown["outcome"].as_str().unwrap_or("unknown"),
            "completion_unknown": shown["completion_unknown"] == true,
            "cleanup_unknown": shown["cleanup_unknown"] == true,
            "recovery": shown["recovery"]["choice"].as_str().unwrap_or("none"),
        },
        "settles": settles, "pins": pins, "cites": cites(snapshot),
    });
    logic::summary::derive(&input).map_err(|_| Failure::Bound)
}

fn settled(summary: &Value) -> bool {
    matches!(
        summary["outcome"].as_str(),
        Some("succeeded" | "failed" | "cancelled")
    ) && summary["completion_unknown"] == false
        && summary["cleanup_unknown"] == false
        && summary["recovery"] == "none"
}

fn id(summary: &Value) -> &str {
    summary["operation"].as_str().unwrap_or("")
}

fn sequence(summary: &Value) -> u64 {
    summary["sequence"].as_u64().unwrap_or(0)
}

fn needs_record(summary: &Value) -> bool {
    summary["cites_complete"] == false
        || summary["action"] == "configure-node-registries"
        || summary["action"]
            .as_str()
            .is_some_and(|a| a.starts_with("release-"))
}

fn read(store: &mut super::Store) -> Result<(HistoryRead, BTreeMap<String, Snapshot>)> {
    let history = store.history_records()?;
    let wanted: Vec<String> = history
        .summaries
        .iter()
        .filter(|s| needs_record(s))
        .map(|s| id(s).to_owned())
        .collect();
    let mut records = BTreeMap::new();
    for chunk in wanted.chunks(BATCH) {
        for snapshot in store.complete_records(chunk.to_vec())? {
            let key = snapshot.request["operation"]
                .as_str()
                .ok_or(Failure::Integrity)?
                .to_owned();
            records.insert(key, snapshot);
        }
    }
    Ok((history, records))
}

fn release_store(project: &LoadedProject, scope: &Value) -> Result<std::path::PathBuf> {
    Ok(project
        .broil_root
        .join("state/releases")
        .join(scope["hash"].as_str().ok_or(Failure::Integrity)?))
}

fn releases(project: &LoadedProject, scope: &Value) -> std::result::Result<Vec<Value>, Refusal> {
    let store = release_store(project, scope)?;
    if matches!(std::fs::symlink_metadata(&store), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(Vec::new());
    }
    crate::k3s::release::store::enumerate(&store).map_err(|r| Refusal {
        failure: match r.failure {
            "bound" => Failure::Bound,
            "storage" => Failure::Storage,
            _ => Failure::Integrity,
        },
        boundary: Some(r.boundary),
        detail: Some(r.detail),
    })
}

fn newest<'a>(operations: impl Iterator<Item = &'a Value>) -> Option<&'a Value> {
    operations.max_by_key(|s| sequence(s))
}

fn dependencies(
    history: &HistoryRead,
    records: &BTreeMap<String, Snapshot>,
) -> Result<BTreeSet<String>> {
    let summaries = &history.summaries;
    let mut cited = BTreeSet::new();
    let mut found = Vec::new();
    if let Some(owner) = &history.owner {
        named(owner, "", &mut found);
    }
    for wave in &history.waves {
        named(wave, "", &mut found);
    }
    cited.extend(found);
    let by_family = |pick: &dyn Fn(&Value) -> bool| -> BTreeMap<(String, String), &Value> {
        let mut newest: BTreeMap<(String, String), &Value> = BTreeMap::new();
        for s in summaries.iter().filter(|s| pick(s)) {
            let key = (
                s["action"].as_str().unwrap_or("").to_owned(),
                s["family"].as_str().unwrap_or("").to_owned(),
            );
            let entry = newest.entry(key).or_insert(s);
            if sequence(s) > sequence(entry) {
                *entry = s;
            }
        }
        newest
    };
    let succeeded = |s: &Value| s["outcome"] == "succeeded";
    for s in summaries {
        if s["action"]
            .as_str()
            .is_some_and(|a| a.starts_with("create-"))
        {
            cited.insert(id(s).to_owned());
        }
    }
    for s in by_family(&|s| {
        succeeded(s)
            && s["action"].as_str().is_some_and(|a| {
                matches!(a, "join-server" | "join-agent") || a.starts_with("prepare-")
            })
    })
    .values()
    {
        cited.insert(id(s).to_owned());
    }
    let restarts: Vec<&Value> = summaries
        .iter()
        .filter(|s| s["action"] == "restart-member" && !s["run"].is_null())
        .collect();
    if let Some(latest) = newest(restarts.iter().copied()) {
        for s in &restarts {
            if s["run"]["run"] == latest["run"]["run"] {
                cited.insert(id(s).to_owned());
            }
        }
    }
    let configures: Vec<&Value> = summaries
        .iter()
        .filter(|s| s["action"] == "configure-node-registries")
        .collect();
    let complete = configures
        .iter()
        .filter(|s| {
            records.get(id(s)).is_some_and(|r| {
                let position = recipe(r, "position").and_then(Value::as_u64);
                let members = recipe(r, "plan")
                    .and_then(|p| p["members"].as_array())
                    .map(|m| m.len() as u64);
                succeeded(s) && position.zip(members).is_some_and(|(p, n)| p + 1 == n)
            })
        })
        .max_by_key(|s| sequence(s));
    let start = complete.map_or(0, |last| {
        configures
            .iter()
            .filter(|s| s["run"]["run"] == last["run"]["run"])
            .map(|s| sequence(s))
            .min()
            .unwrap_or(0)
    });
    for s in &configures {
        if sequence(s) >= start {
            cited.insert(id(s).to_owned());
        }
    }
    let mut replaces: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for s in summaries.iter().filter(|s| s["action"] == "node-replace") {
        replaces
            .entry(s["family"].as_str().unwrap_or(""))
            .or_default()
            .push(s);
    }
    for list in replaces.values_mut() {
        list.sort_by_key(|s| std::cmp::Reverse(sequence(s)));
        cited.extend(list.iter().take(2).map(|s| id(s).to_owned()));
    }
    for s in by_family(&|s| s["action"] == "node-drain").values() {
        cited.insert(id(s).to_owned());
    }
    Ok(cited)
}

fn release_facts(record: Option<&Snapshot>) -> (Value, Value) {
    let Some(record) = record else {
        return (json!([]), json!([]));
    };
    let mut hooks = Vec::new();
    let mut released = Vec::new();
    for o in &record.observations {
        let event = &o["event"];
        if event["type"].as_str().is_some_and(|t| t.contains("hook")) {
            hooks.push(json!({"repeatable": event["repeatable"] == true,
                "outcome": event["outcome"].as_str().unwrap_or("unknown")}));
        }
        for r in event["released"].as_array().into_iter().flatten() {
            let name = r["release"].as_str().or(r.as_str());
            if let Some(name) = name {
                released.push(json!(name));
            }
        }
    }
    (json!(hooks), json!(released))
}

fn kept_set(
    summaries: &[Value],
    releases: &[Value],
    records: &BTreeMap<String, Snapshot>,
) -> Vec<String> {
    let mut kept = BTreeSet::new();
    let applications: BTreeSet<&str> = releases
        .iter()
        .filter_map(|r| r["application"].as_str())
        .collect();
    let applies: Vec<&Value> = summaries
        .iter()
        .filter(|s| {
            matches!(
                s["action"].as_str(),
                Some("release-apply" | "release-rollback")
            )
        })
        .collect();
    let read: Vec<Snapshot> = applies
        .iter()
        .filter_map(|s| records.get(id(s)).cloned())
        .collect();
    for application in applications {
        let unread = applies
            .iter()
            .any(|s| s["application"] == application && !records.contains_key(id(s)));
        if unread {
            kept.extend(
                releases
                    .iter()
                    .filter(|r| r["application"] == application)
                    .filter_map(|r| r["release"].as_str().map(str::to_owned)),
            );
        } else {
            let history = super::release_delivery::kept_history(&read, releases);
            let derived = crate::k3s::release::kept::derive(application, &history);
            kept.extend(
                derived["kept"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().or(v["release"].as_str()).map(str::to_owned)),
            );
        }
    }
    kept.into_iter().collect()
}

struct Decision {
    classified: Value,
    operations: Vec<String>,
    releases: Vec<String>,
    hosts: Value,
    unsettled: BTreeMap<String, u64>,
    participants: Vec<Value>,
    cutoff_ms: u64,
    approval: String,
    summaries: Vec<Value>,
}

fn decide(
    scope: &Value,
    policy: &Policy,
    now_ms: u64,
    history: &HistoryRead,
    records: &BTreeMap<String, Snapshot>,
    release_records: &[Value],
) -> std::result::Result<Decision, Refusal> {
    let owner = history.owner.as_ref().ok_or(Failure::Ownership)?;
    let participants = super::survivors(owner)?;
    let machines: Vec<&str> = participants
        .iter()
        .filter_map(|m| m["machine"].as_str())
        .collect();
    let dependencies = dependencies(history, records)?;
    let kept = kept_set(&history.summaries, release_records, records);
    let releases: Vec<Value> = release_records
        .iter()
        .map(|r| json!({"release": r["release"], "application": r["application"], "created_ms": r["created_ms"]}))
        .collect();
    let mut cited = dependencies;
    let classified = loop {
        let operations: Vec<Value> = history
            .summaries
            .iter()
            .map(|s| {
                let (hooks, released) = release_facts(records.get(id(s)));
                let mut o = s.clone();
                o["settled"] = json!(settled(s));
                o["cited"] = json!(cited.contains(id(s)));
                o["hooks"] = hooks;
                o["released"] = released;
                o
            })
            .collect();
        let input = json!({"now_ms": now_ms, "participants": machines, "operations": operations,
            "releases": releases, "kept_set": kept});
        let classified = logic::classify(policy, &input).map_err(|r| Refusal {
            failure: Failure::Integrity,
            boundary: Some("history"),
            detail: Some(r.detail),
        })?;
        let removed: BTreeSet<&str> = classified["removed"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let mut added = false;
        for s in history
            .summaries
            .iter()
            .filter(|s| !removed.contains(id(s)))
        {
            let all = match records.get(id(s)) {
                Some(record) if s["cites_complete"] == false => cites(record),
                _ => s["cites"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c.as_str().map(str::to_owned))
                    .collect(),
            };
            for c in all {
                if removed.contains(c.as_str()) && cited.insert(c) {
                    added = true;
                }
            }
        }
        if !added {
            break classified;
        }
    };
    let by_id: BTreeMap<&str, &Value> = history.summaries.iter().map(|s| (id(s), s)).collect();
    let operations: Vec<String> = classified["removed"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let removed_releases: Vec<String> = classified["releases"]["removed"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let mut unsettled = BTreeMap::new();
    let mut lists = Vec::new();
    for machine in &machines {
        let selects = |s: &Value| {
            s["machines"]
                .as_array()
                .is_some_and(|m| m.iter().any(|v| v == machine))
        };
        let bound = history
            .summaries
            .iter()
            .filter(|s| !settled(s) && selects(s))
            .map(sequence)
            .min()
            .unwrap_or(u64::MAX);
        unsettled.insert((*machine).to_owned(), bound);
        let mut entries = Vec::new();
        for operation in &operations {
            let s = by_id.get(operation.as_str()).ok_or(Failure::Integrity)?;
            if selects(s) {
                for attempt in history.attempts.get(operation).into_iter().flatten() {
                    entries.push(json!({"attempt": attempt, "sequence": sequence(s)}));
                }
            }
        }
        lists.push(json!({"machine": machine, "entries": entries}));
    }
    let members: BTreeSet<&str> = owner["members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["machine"].as_str())
        .collect();
    let carried: Vec<Value> = history
        .intent
        .as_ref()
        .filter(|i| i["phase"] == "hosts")
        .and_then(|i| i["hosts"].as_array())
        .into_iter()
        .flatten()
        .filter(|h| h["machine"].as_str().is_some_and(|m| members.contains(m)))
        .cloned()
        .collect();
    let hosts = logic::intent::merge(&json!(lists), &json!(carried)).map_err(|r| Refusal {
        failure: Failure::Integrity,
        boundary: Some("history"),
        detail: Some(r.detail),
    })?;
    let cutoff_ms = logic::cutoff_ms(policy, now_ms);
    let bound_hosts: Vec<Value> = lists
        .iter()
        .map(|h| {
            json!({"machine": h["machine"], "attempts": h["entries"].as_array().into_iter().flatten()
                .map(|e| e["attempt"].clone()).collect::<Vec<_>>()})
        })
        .collect();
    let approval = logic::approval(&json!({
        "scope": scope, "action": "operation-prune",
        "policy": {"keep_days": policy.keep_days, "keep_last": policy.keep_last},
        "cutoff_ms": cutoff_ms, "owner": owner["owner"], "generation": owner["generation"],
        "operations": operations, "releases": removed_releases, "hosts": bound_hosts,
    }));
    Ok(Decision {
        classified,
        operations,
        releases: removed_releases,
        hosts,
        unsettled,
        participants,
        cutoff_ms,
        approval,
        summaries: history.summaries.clone(),
    })
}

fn usage(
    summaries: &[Value],
    releases: usize,
    participants: &[Value],
    pending: &Value,
    exact: &BTreeMap<String, u64>,
) -> Value {
    let mut fullest = json!({"member": null, "attempts": 0, "limit": logic::CAP});
    let mut most = None;
    for member in participants {
        let machine = member["machine"].as_str().unwrap_or("");
        let count = exact.get(machine).copied().unwrap_or_else(|| {
            let recorded: u64 = summaries
                .iter()
                .filter(|s| {
                    s["machines"]
                        .as_array()
                        .is_some_and(|m| m.iter().any(|v| v == machine))
                })
                .map(|s| s["attempts"].as_u64().unwrap_or(0))
                .sum();
            let carried = pending
                .as_array()
                .into_iter()
                .flatten()
                .filter(|h| h["machine"] == machine)
                .map(|h| h["entries"].as_array().map_or(0, Vec::len) as u64)
                .sum::<u64>();
            recorded + carried
        });
        if most.is_none_or(|m| count > m) {
            most = Some(count);
            fullest = json!({"member": member["member"], "attempts": count, "limit": logic::CAP});
        }
    }
    let operations = summaries.len() as u64;
    let warning = [operations, releases as u64, most.unwrap_or(0)]
        .iter()
        .any(|n| *n >= logic::WARNING);
    json!({"operations": operations, "limit": logic::CAP, "releases": releases,
        "release_limit": logic::CAP, "hosts": fullest, "warning": warning})
}

pub(in crate::k3s) fn attach_store(root: &std::path::Path, scope: &Value, report: &mut Value) {
    let Some(fields) = report.as_object_mut() else {
        return;
    };
    if fields.contains_key("store") {
        return;
    }
    let usage = (|| -> std::result::Result<Value, Refusal> {
        let mut store = super::Store::new(
            root.to_path_buf(),
            scope.clone(),
            30_000,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )?;
        let history = store.history_records();
        let released = store.release(tokio::time::Instant::now() + Duration::from_secs(5));
        let history = history?;
        released?;
        let owner = history.owner.as_ref().ok_or(Failure::Integrity)?;
        let participants = super::survivors(owner)?;
        let store = root
            .join("state/releases")
            .join(scope["hash"].as_str().ok_or(Failure::Integrity)?);
        let releases = if matches!(std::fs::symlink_metadata(&store), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        {
            0
        } else {
            crate::k3s::release::store::enumerate(&store)
                .map_err(|_| Failure::Integrity)?
                .len()
        };
        let pending = history
            .intent
            .as_ref()
            .map_or(json!([]), |i| i["hosts"].clone());
        Ok(usage(
            &history.summaries,
            releases,
            &participants,
            &pending,
            &BTreeMap::new(),
        ))
    })();
    fields.insert("store".to_owned(), usage.unwrap_or(Value::Null));
}

pub(super) fn capacity(
    target: &str,
    leaf: &str,
    previous: &[Snapshot],
    operations: u64,
    attempts: &BTreeMap<String, u64>,
) -> Option<String> {
    let limit = logic::CAP - logic::RESERVE;
    let prune = format!("run k3s plan {target} --action operation-prune --observe");
    let held = previous.len() as u64;
    if operations > 0 && held + operations > limit {
        return Some(format!(
            "target {target} holds {held} of {} operation records and {leaf} needs {operations}; {prune}",
            logic::CAP
        ));
    }
    for (machine, wanted) in attempts.iter().filter(|(_, n)| **n > 0) {
        let recorded: u64 = previous
            .iter()
            .filter(|s| {
                s.request["members"]
                    .as_array()
                    .is_some_and(|m| m.iter().any(|v| v["machine"] == machine.as_str()))
            })
            .map(|s| s.attempts.len() as u64)
            .sum();
        if recorded + wanted > limit {
            return Some(format!(
                "machine {machine} holds {recorded} of {} attempt records and {leaf} needs {wanted}; {prune}",
                logic::CAP
            ));
        }
    }
    None
}

pub(in crate::k3s) fn workflow_room(
    root: &std::path::Path,
    scope: &Value,
    leaf: &str,
    plan: impl FnOnce(&[Snapshot], &[super::store::WaveRecord]) -> Result<Value>,
) -> std::result::Result<(), Refusal> {
    let Ok(mut store) = super::Store::new(
        root.to_path_buf(),
        scope.clone(),
        30_000,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    ) else {
        return Ok(());
    };
    let context = store.agent_context();
    store.release(tokio::time::Instant::now() + Duration::from_secs(5))?;
    let Ok((previous, waves)) = context else {
        return Ok(());
    };
    let need = logic::workflow_need(leaf, &plan(&previous, &waves)?);
    let attempts: BTreeMap<String, u64> = need["hosts"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(machine, n)| (machine.clone(), n.as_u64().unwrap_or(0)))
        .collect();
    let target = scope["target"].as_str().unwrap_or("");
    let operations = need["operations"].as_u64().unwrap_or(0);
    match capacity(target, leaf, &previous, operations, &attempts) {
        Some(detail) => Err(refused(Failure::Bound, "store-full", detail)),
        None => Ok(()),
    }
}

fn incomplete(target: &str, intent: &Value) -> Refusal {
    refused(
        Failure::Busy,
        "prune",
        format!(
            "a history cleanup of target {target} is incomplete; run k3s operation prune {target} --approve {}",
            intent["approval"].as_str().unwrap_or("")
        ),
    )
}

pub(in crate::k3s) fn unfinished(
    root: &std::path::Path,
    scope: &Value,
    target: &str,
) -> std::result::Result<(), Refusal> {
    let path = root
        .join("state/infrastructure/targets")
        .join(scope["hash"].as_str().ok_or(Failure::Integrity)?)
        .join("history/intent.json");
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Failure::Storage.into()),
    };
    let intent = logic::intent::decode(&raw).map_err(|_| Failure::Integrity)?;
    if intent["phase"] == "local" {
        return Err(incomplete(target, &intent));
    }
    Ok(())
}

pub(in crate::k3s) fn pruned_operations(
    root: &std::path::Path,
    scope: &Value,
) -> std::result::Result<Option<u64>, Refusal> {
    let path = root
        .join("state/infrastructure/targets")
        .join(scope["hash"].as_str().ok_or(Failure::Integrity)?)
        .join("history/checkpoint.json");
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Failure::Storage.into()),
    };
    let checkpoint = logic::checkpoint::decode(&raw).map_err(|_| Failure::Integrity)?;
    if checkpoint["scope"] != *scope {
        return Err(Failure::Ownership.into());
    }
    Ok(checkpoint["pruned_operations"].as_u64().filter(|n| *n > 0))
}

fn nothing_eligible(target: &str) -> Refusal {
    refused(
        Failure::Bound,
        "nothing-eligible",
        format!(
            "no record of target {target} is settled, outside the policy and uncited; keep fewer days or records, settle recovery, or run k3s release retain to unpin old releases"
        ),
    )
}

fn projection(decision: &Decision, reachable: &BTreeMap<String, Option<bool>>) -> Value {
    let by_id: BTreeMap<&str, &Value> = decision.summaries.iter().map(|s| (id(s), s)).collect();
    let removed: Vec<Value> = decision
        .operations
        .iter()
        .filter_map(|o| by_id.get(o.as_str()))
        .map(|s| json!({"action": s["action"], "created_ms": s["created_ms"], "operation": s["operation"], "release": s["release"]}))
        .collect();
    let hosts: Vec<Value> = decision
        .participants
        .iter()
        .map(|member| {
            let machine = member["machine"].as_str().unwrap_or("");
            let bound = decision.unsettled.get(machine).copied().unwrap_or(u64::MAX);
            let entries: Vec<&Value> = decision
                .hosts
                .as_array()
                .into_iter()
                .flatten()
                .filter(|h| h["machine"] == machine)
                .flat_map(|h| h["entries"].as_array().into_iter().flatten())
                .collect();
            let targeted = entries
                .iter()
                .filter(|e| e["sequence"].as_u64().is_some_and(|s| s < bound))
                .count();
            json!({"member": member["member"], "reachable": reachable.get(machine).copied().flatten(),
                "attempts": targeted, "pending": entries.len() - targeted})
        })
        .collect();
    let c = &decision.classified;
    json!({"before": c["before"], "after": c["after"], "removed": removed, "kept": c["kept"],
        "releases": c["releases"], "hosts": hosts, "summary": c["summary"]})
}

async fn host_call(
    project: &LoadedProject,
    policy: &crate::k3s::Policy,
    target: &str,
    binding: Value,
    action: &str,
    payload: Value,
) -> Result<Value> {
    let context = rpc::Context::new(project, super::issuer::duplicate(policy)?, target)?;
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
    );
    let mut binding = binding;
    binding["fingerprints"] = context.fingerprints.clone();
    let observed = context.invoke(&binding, action, payload, deadline).await;
    observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))
}

fn binding(
    owner: &Value,
    scope: &Value,
    prune: &str,
    member: &Value,
    generation: u64,
    request: &str,
) -> Result<Value> {
    Ok(
        json!({"scope": scope, "owner": owner["owner"], "operation": format!("infra-operation-{prune}"),
        "attempt": prune, "step": 1, "dispatch": fresh()?, "recipient": member,
        "receiver_generation": generation, "request_sha256": request,
        "participants_sha256": owner["participants_sha256"], "fingerprints": null}),
    )
}

async fn inspect_owner(
    project: &LoadedProject,
    policy: &crate::k3s::Policy,
    target: &str,
    owner: &Value,
    scope: &Value,
    member: &Value,
) -> Result<Option<u64>> {
    let nonce = fresh()?;
    let binding = binding(owner, scope, &nonce, member, 0, ZEROS)?;
    match host_call(
        project,
        policy,
        target,
        binding,
        "inspect",
        json!({"subject":"owner","dispatch":null,"resource":null}),
    )
    .await
    {
        Ok(response) => {
            require(
                response["status"] == "ok" && response["data"]["claim"]["owner"] == owner["owner"],
                Failure::Ownership,
            )?;
            Ok(Some(
                response["data"]["claim"]["generation"]
                    .as_u64()
                    .ok_or(Failure::Integrity)?,
            ))
        }
        Err(Failure::Transport | Failure::Timeout) => Ok(None),
        Err(failure) => Err(failure),
    }
}

pub(in crate::k3s) async fn plan(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    keep: Policy,
    observe: bool,
) -> std::result::Result<Value, Refusal> {
    let host_policy = super::issuer::duplicate(&policy)?;
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let result = local.work(read).await;
    let (history, records) = local.complete(result, &context.clock).await?;
    if let Some(intent) = history.intent.as_ref().filter(|i| i["phase"] == "local") {
        return Err(incomplete(target, intent));
    }
    if history.owner.is_none() {
        return Err(nothing_eligible(target));
    }
    let release_records = releases(project, &context.scope)?;
    let decision = decide(
        &context.scope,
        &keep,
        now()?,
        &history,
        &records,
        &release_records,
    )?;
    if decision.operations.is_empty() && decision.releases.is_empty() {
        return Err(nothing_eligible(target));
    }
    let owner = history.owner.as_ref().ok_or(Failure::Ownership)?;
    let mut reachable = BTreeMap::new();
    if observe {
        for member in &decision.participants {
            let found =
                inspect_owner(project, &host_policy, target, owner, &context.scope, member).await?;
            reachable.insert(
                member["machine"].as_str().unwrap_or("").to_owned(),
                Some(found.is_some()),
            );
        }
    }
    let mut effects = vec![json!({"action": "delete-records", "member": null})];
    for member in &decision.participants {
        effects.push(json!({"action": "delete-attempts", "member": member["member"]}));
    }
    let report = json!({"format_version": 1, "scope": context.scope, "view": "plan",
        "action": "operation-prune", "observed": observe,
        "policy": {"keep_days": keep.keep_days, "keep_last": keep.keep_last},
        "prune": projection(&decision, &reachable), "effects": effects,
        "approval": if observe { json!(decision.approval) } else { Value::Null }});
    let size = super::canonical(&report)?.len();
    if size > PLAN_LIMIT {
        return Err(refused(
            Failure::Bound,
            "report",
            format!(
                "the operation-prune plan needs {size} bytes; the limit is {PLAN_LIMIT}: run it with a larger --keep-last or a smaller window"
            ),
        ));
    }
    Ok(report)
}

struct HostOutcome {
    attempts_removed: Value,
    watermark_sequence: Value,
    outcome: &'static str,
}

struct Hosts<'a> {
    project: &'a LoadedProject,
    policy: &'a crate::k3s::Policy,
    target: &'a str,
    scope: &'a Value,
    owner: &'a Value,
    participants: &'a [Value],
}

async fn prune_hosts(
    reach: &Hosts<'_>,
    local: &mut Local,
    unsettled: &BTreeMap<String, u64>,
    mut intent: Value,
    exact: &mut BTreeMap<String, u64>,
) -> Result<(Value, BTreeMap<String, HostOutcome>)> {
    let Hosts {
        project,
        policy,
        target,
        scope,
        owner,
        participants,
    } = *reach;
    let prune = intent["prune"]
        .as_str()
        .ok_or(Failure::Integrity)?
        .to_owned();
    let mut outcomes = BTreeMap::new();
    let hosts = intent["hosts"].as_array().cloned().unwrap_or_default();
    let mut remaining_hosts = Vec::new();
    for host in hosts {
        let machine = host["machine"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        let mut entries: Vec<Value> = host["entries"].as_array().cloned().unwrap_or_default();
        let member = participants
            .iter()
            .find(|m| m["machine"] == machine.as_str());
        let bound = unsettled.get(&machine).copied().unwrap_or(u64::MAX);
        let Some(member) = member else {
            remaining_hosts.push(json!({"machine": machine, "entries": entries}));
            continue;
        };
        let targeted: Vec<Value> = entries
            .iter()
            .filter(|e| e["sequence"].as_u64().is_some_and(|s| s < bound))
            .cloned()
            .collect();
        let mut outcome = HostOutcome {
            attempts_removed: Value::Null,
            watermark_sequence: Value::Null,
            outcome: "succeeded",
        };
        if !targeted.is_empty() {
            match inspect_owner(project, policy, target, owner, scope, member).await {
                Ok(Some(generation)) => {
                    for chunk in targeted.chunks(CHUNK) {
                        let attempts: Vec<Value> =
                            chunk.iter().map(|e| e["attempt"].clone()).collect();
                        let watermark = chunk
                            .iter()
                            .filter_map(|e| e["sequence"].as_u64())
                            .max()
                            .unwrap_or(1);
                        let request = hash(
                            "broil-history-host-v1",
                            &json!({"prune": prune, "machine": machine, "attempts": attempts}),
                        )?;
                        let binding = binding(owner, scope, &prune, member, generation, &request)?;
                        let reply = host_call(
                            project,
                            policy,
                            target,
                            binding,
                            "prune-attempts",
                            json!({"attempts": attempts, "watermark_sequence": watermark}),
                        )
                        .await;
                        match reply {
                            Ok(reply) if reply["status"] == "ok" => {
                                let history = &reply["data"]["history"];
                                outcome.attempts_removed =
                                    history["checkpoint"]["attempts_removed"].clone();
                                outcome.watermark_sequence =
                                    history["checkpoint"]["watermark_sequence"].clone();
                                if let Some(count) = history["attempts"].as_u64() {
                                    exact.insert(machine.clone(), count);
                                }
                                entries.retain(|e| !chunk.contains(e));
                                let mut next = intent.clone();
                                let mut hosts = remaining_hosts.clone();
                                hosts.push(json!({"machine": machine, "entries": entries}));
                                hosts.extend(
                                    next["hosts"]
                                        .as_array()
                                        .into_iter()
                                        .flatten()
                                        .filter(|h| {
                                            h["machine"]
                                                .as_str()
                                                .is_some_and(|m| m > machine.as_str())
                                        })
                                        .cloned(),
                                );
                                next["hosts"] = json!(hosts);
                                let published = next.clone();
                                local
                                    .work(move |store| store.publish_intent(published))
                                    .await?;
                                intent = next;
                            }
                            Ok(_) => {
                                outcome.outcome = "unknown";
                                break;
                            }
                            Err(Failure::Transport | Failure::Timeout) => {
                                outcome.outcome = "pending";
                                break;
                            }
                            Err(_) => {
                                outcome.outcome = "unknown";
                                break;
                            }
                        }
                    }
                }
                Ok(None) => outcome.outcome = "pending",
                Err(failure) => return Err(failure),
            }
        }
        remaining_hosts.push(json!({"machine": machine, "entries": entries}));
        outcomes.insert(machine, outcome);
    }
    intent["hosts"] = json!(remaining_hosts);
    let empty = remaining_hosts
        .iter()
        .all(|h| h["entries"].as_array().is_none_or(Vec::is_empty));
    if empty {
        local.work(|store| store.remove_intent()).await?;
        Ok((Value::Null, outcomes))
    } else {
        let published = intent.clone();
        local
            .work(move |store| store.publish_intent(published))
            .await?;
        Ok((intent, outcomes))
    }
}

fn releases_named(releases: &[String], name: &str) -> bool {
    releases.iter().any(|r| r == name)
}

async fn prune_local(
    project: &LoadedProject,
    local: &mut Local,
    scope: &Value,
    history: &HistoryRead,
    mut intent: Value,
) -> std::result::Result<(Value, Value), Refusal> {
    let operations: Vec<String> = intent["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let releases: Vec<String> = intent["releases"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    for batch in operations.chunks(BATCH) {
        let candidates = operations.clone();
        let batch = batch.to_vec();
        local
            .work(move |store| store.trash_operations(candidates, batch))
            .await?;
    }
    crate::k3s::release::store::prune(&release_store(project, scope)?, &releases).map_err(|r| {
        Refusal {
            failure: Failure::Storage,
            boundary: Some(r.boundary),
            detail: Some(r.detail),
        }
    })?;
    let old = history.checkpoint.clone().unwrap_or_else(
        || json!({"pruned_operations": 0, "pruned_releases": 0, "pruned_through_sequence": 0, "pruned_kinds": []}),
    );
    let through = intent["hosts"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|h| h["entries"].as_array().into_iter().flatten())
        .filter_map(|e| e["sequence"].as_u64())
        .chain(old["pruned_through_sequence"].as_u64())
        .max()
        .unwrap_or(0);
    let after = json!({"schema": 1, "kind": "history-checkpoint", "scope": scope,
        "owner": intent["owner"],
        "pruned_operations": old["pruned_operations"].as_u64().unwrap_or(0) + operations.len() as u64,
        "pruned_releases": old["pruned_releases"].as_u64().unwrap_or(0) + releases.len() as u64,
        "pruned_through_sequence": through,
        "pruned_kinds": logic::checkpoint::merge_kinds(&old["pruned_kinds"], &intent["kinds"]),
        "chain_sha256": intent["checkpoint_after"]});
    let before = intent["checkpoint_before"]
        .as_str()
        .ok_or(Failure::Integrity)?
        .to_owned();
    let recorded = after.clone();
    local
        .work(move |store| store.checkpoint(before, recorded))
        .await?;
    intent["phase"] = json!("hosts");
    let published = intent.clone();
    local
        .work(move |store| store.publish_intent(published))
        .await?;
    let checkpoint = match &history.checkpoint {
        Some(current) if current["chain_sha256"] == intent["checkpoint_after"] => current.clone(),
        _ => after,
    };
    Ok((intent, checkpoint))
}

pub(in crate::k3s) async fn prune(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    keep: Policy,
    approve: &str,
) -> std::result::Result<(Value, bool), Refusal> {
    let host_policy = super::issuer::duplicate(&policy)?;
    let context = rpc::Context::new(project, policy, target)?;
    let scope = context.scope.clone();
    let mut local = Local::new(&context)?;
    let result = async {
        local.work(|store| store.pruning()).await?;
        let (history, records) = local.work(read).await?;
        let owner = history.owner.clone().ok_or(Failure::Ownership)?;
        let participants = super::survivors(&owner)?;
        let reach = Hosts {
            project,
            policy: &host_policy,
            target,
            scope: &scope,
            owner: &owner,
            participants: &participants,
        };
        let mut exact = BTreeMap::new();
        let mut checkpoint = history.checkpoint.clone();
        let mut removed = (0usize, 0usize);
        let mut history = history;
        let mut records = records;
        let intent = match history.intent.clone() {
            Some(intent) if intent["phase"] == "local" => {
                if intent["approval"] != approve {
                    return Err(incomplete(target, &intent));
                }
                removed = (
                    intent["operations"].as_array().map_or(0, Vec::len),
                    intent["releases"].as_array().map_or(0, Vec::len),
                );
                let (intent, after) =
                    prune_local(project, &mut local, &scope, &history, intent).await?;
                checkpoint = Some(after);
                intent
            }
            Some(intent) => {
                let unsettled = unsettled_bounds(&history.summaries, &participants);
                let (left, _) =
                    prune_hosts(&reach, &mut local, &unsettled, intent, &mut exact).await?;
                let (fresh_history, fresh_records) = local.work(read).await?;
                history = fresh_history;
                records = fresh_records;
                if left.is_null() {
                    history.intent = None;
                }
                Value::Null
            }
            None => Value::Null,
        };
        let intent = if intent.is_null() {
            let release_records = releases(project, &scope)?;
            let decision = decide(&scope, &keep, now()?, &history, &records, &release_records)?;
            if decision.approval != approve {
                return Err(refused(
                    Failure::Ownership,
                    "stale-approval",
                    format!("the approved plan changed; run k3s plan {target} --action operation-prune --observe again"),
                ));
            }
            if decision.operations.is_empty() && decision.releases.is_empty() {
                return Err(nothing_eligible(target));
            }
            let mut hashes = Vec::with_capacity(decision.operations.len());
            for chunk in decision.operations.chunks(BATCH) {
                let chunk = chunk.to_vec();
                hashes.extend(local.work(move |store| store.request_hashes(chunk)).await?);
            }
            let contents: Vec<String> = decision
                .releases
                .iter()
                .map(|r| {
                    release_records
                        .iter()
                        .find(|record| record["release"] == r.as_str())
                        .and_then(|record| record["content_sha256"].as_str())
                        .map(str::to_owned)
                        .ok_or(Failure::Integrity)
                })
                .collect::<Result<_>>()?;
            let before = history
                .checkpoint
                .as_ref()
                .and_then(|c| c["chain_sha256"].as_str())
                .unwrap_or(ZEROS)
                .to_owned();
            let after = logic::chain_sha256(&before, approve, &hashes, &contents);
            let named: Vec<Value> = release_records
                .iter()
                .filter(|r| {
                    r["release"]
                        .as_str()
                        .is_some_and(|n| releases_named(&decision.releases, n))
                })
                .flat_map(|r| r["manifests"]["objects"].as_array().cloned().unwrap_or_default())
                .map(|o| json!({"api_version": o["api_version"], "kind": o["kind"], "namespace": o["namespace"]}))
                .collect();
            let kinds = logic::checkpoint::merge_kinds(&json!([]), &json!(named));
            let intent = json!({"schema": 1, "kind": "prune-intent", "scope": scope,
                "owner": owner["owner"], "prune": fresh()?, "approval": approve,
                "policy": {"keep_days": keep.keep_days, "keep_last": keep.keep_last},
                "cutoff_ms": decision.cutoff_ms, "phase": "local",
                "checkpoint_before": before, "checkpoint_after": after,
                "operations": decision.operations, "releases": decision.releases,
                "kinds": kinds, "hosts": decision.hosts});
            if logic::intent::encode(&intent).is_err() {
                return Err(refused(
                    Failure::Bound,
                    "prune",
                    "the cleanup intent would exceed 4718592 bytes with the pending host entries",
                ));
            }
            let published = intent.clone();
            local
                .work(move |store| store.publish_intent(published))
                .await?;
            removed = (decision.operations.len(), decision.releases.len());
            let (intent, after) = prune_local(project, &mut local, &scope, &history, intent).await?;
            checkpoint = Some(after);
            intent
        } else {
            intent
        };
        let remaining: BTreeSet<String> = intent["operations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let summaries: Vec<Value> = history
            .summaries
            .iter()
            .filter(|s| !remaining.contains(id(s)))
            .cloned()
            .collect();
        let unsettled = unsettled_bounds(&summaries, &participants);
        let (pending, outcomes) =
            prune_hosts(&reach, &mut local, &unsettled, intent, &mut exact).await?;
        let release_count = releases(project, &scope)?.len();
        let hosts: Vec<Value> = participants
            .iter()
            .map(|member| {
                let machine = member["machine"].as_str().unwrap_or("");
                let outcome = outcomes.get(machine);
                json!({"member": member["member"],
                    "attempts_removed": outcome.map_or(Value::Null, |o| o.attempts_removed.clone()),
                    "watermark_sequence": outcome.map_or(Value::Null, |o| o.watermark_sequence.clone()),
                    "outcome": outcome.map_or("succeeded", |o| o.outcome)})
            })
            .collect();
        let rerun = hosts.iter().any(|h| h["outcome"] != "succeeded");
        let checkpoint = checkpoint.map_or(Value::Null, |c| {
            json!({"pruned_operations": c["pruned_operations"], "pruned_releases": c["pruned_releases"],
                "pruned_through_sequence": c["pruned_through_sequence"],
                "pruned_kinds": c["pruned_kinds"].as_array().map_or(Value::Null, |k| json!(k.len())),
                "chain_sha256": c["chain_sha256"]})
        });
        let pending_hosts = if pending.is_null() { json!([]) } else { pending["hosts"].clone() };
        Ok(json!({"format_version": 1, "scope": scope, "view": "operation-prune",
            "outcome": "succeeded", "failure": null, "detail": null,
            "completion_unknown": false, "cleanup_unknown": false, "truncated": false,
            "operations": [],
            "recovery": {"choice": if rerun { "rerun" } else { "none" }, "operation": null,
                "subject": if rerun { json!(format!("k3s operation prune {target}")) } else { Value::Null }},
            "store": usage(&summaries, release_count, &participants, &pending_hosts, &exact),
            "policy": {"keep_days": keep.keep_days, "keep_last": keep.keep_last},
            "removed": {"operations": removed.0, "releases": removed.1},
            "checkpoint": checkpoint, "hosts": hosts}))
    }
    .await;
    match result {
        Ok(report) => {
            let report = local
                .complete(Ok(report), &context.clock)
                .await
                .map_err(Refusal::from)?;
            Ok((report, true))
        }
        Err(refusal) => {
            let _ = local
                .complete::<()>(Err(refusal.failure), &context.clock)
                .await;
            Err(refusal)
        }
    }
}

fn unsettled_bounds(summaries: &[Value], participants: &[Value]) -> BTreeMap<String, u64> {
    participants
        .iter()
        .filter_map(|m| m["machine"].as_str())
        .map(|machine| {
            let bound = summaries
                .iter()
                .filter(|s| {
                    !settled(s)
                        && s["machines"]
                            .as_array()
                            .is_some_and(|m| m.iter().any(|v| v == machine))
                })
                .map(sequence)
                .min()
                .unwrap_or(u64::MAX);
            (machine.to_owned(), bound)
        })
        .collect()
}
