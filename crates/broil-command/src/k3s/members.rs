// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::release::Refusal;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

pub const STEP_LIMIT: usize = 1024;
pub const OBSERVATION_LIMIT: usize = 4096;
pub const POD_LIMIT: usize = 128;
pub const PAGE_PODS: usize = 70;
pub const EVICT_PODS: usize = 32;
pub const NAMED_PODS: usize = 140;
const DEFAULT_STEP_TIMEOUT_MS: u64 = 15 * 60 * 1000;

const DECISION_KEYS: [&str; 15] = [
    "schema",
    "scope",
    "owner",
    "local_generation",
    "action",
    "member",
    "cluster",
    "members",
    "removed",
    "writer",
    "reachability",
    "checks",
    "writer_move",
    "transition",
    "effects",
];

const APPROVAL_LABEL: &str = "broil-infra-approval-v1";

fn removed(target: &Value) -> Vec<&str> {
    target["removed"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.as_str().or_else(|| r["member"].as_str()))
        .collect()
}

fn declared(target: &Value) -> Vec<&Value> {
    target["members"].as_array().into_iter().flatten().collect()
}

fn name(member: &Value) -> &str {
    member["name"].as_str().unwrap_or("")
}

fn target_name(target: &Value) -> &str {
    target["name"].as_str().unwrap_or("")
}

pub fn acting_first_server(target: &Value, operated: Option<&str>) -> Option<String> {
    let removed = removed(target);
    let survivors: Vec<&Value> = declared(target)
        .into_iter()
        .filter(|m| m["role"] == "server" && !removed.contains(&name(m)))
        .collect();
    let published: Vec<&str> = survivors
        .iter()
        .filter(|m| m["node_uid"].is_string())
        .map(|m| name(m))
        .collect();
    let servers = if published.is_empty() {
        survivors.into_iter().map(name).collect()
    } else {
        published
    };
    servers
        .iter()
        .find(|s| Some(**s) != operated)
        .or_else(|| servers.first())
        .map(|s| (*s).to_owned())
}

pub fn participants(target: &Value) -> Vec<String> {
    let removed = removed(target);
    declared(target)
        .into_iter()
        .map(name)
        .filter(|n| !removed.contains(n))
        .map(str::to_owned)
        .collect()
}

pub fn writer_candidate(
    target: &Value,
    old_writer: &str,
    observed: &Value,
) -> Result<String, Refusal> {
    let removed = removed(target);
    let members: Vec<&Value> = target["members"].as_array().into_iter().flatten().collect();
    let facts: Vec<&Value> = observed.as_array().into_iter().flatten().collect();
    let eligible = |member: &&&Value| {
        let name = member["name"].as_str().unwrap_or("");
        name != old_writer
            && !removed.contains(&name)
            && facts.iter().any(|f| {
                f["member"] == name
                    && f["ready"] == true
                    && f["cordoned"] == false
                    && f["replica"] == "in-sync"
                    && f["service_running"] == true
            })
    };
    ["server", "agent"]
        .iter()
        .find_map(|role| {
            members
                .iter()
                .filter(|m| m["role"] == *role)
                .find(eligible)
                .and_then(|m| m["name"].as_str())
        })
        .map(str::to_owned)
        .ok_or_else(|| {
            Refusal::new(
                "readiness",
                "no-writer-candidate",
                format!(
                    "no other member is ready, uncordoned and in sync to take the registry writer; run k3s delivery check {}",
                    target["name"].as_str().unwrap_or("")
                ),
            )
        })
}

pub fn server_removal(target: &Value, member: &str, healthy: &[&str]) -> Result<(), Refusal> {
    let all = declared(target);
    if !all
        .iter()
        .any(|m| name(m) == member && m["role"] == "server")
    {
        return Ok(());
    }
    let name_of = target_name(target);
    let servers: Vec<&str> = all
        .iter()
        .filter(|m| m["role"] == "server")
        .map(|m| name(m))
        .collect();
    if servers.len() == 1 {
        return Err(Refusal::new(
            "configuration",
            "one-server",
            format!(
                "{member} is the only server of target {name_of}; it cannot be removed or replaced"
            ),
        ));
    }
    let removed = removed(target);
    if let Some(other) = servers
        .iter()
        .find(|s| **s != member && removed.contains(s))
    {
        return Err(Refusal::new(
            "configuration",
            "second-server",
            format!(
                "{other} is already recorded as removed; run k3s node replace {name_of} {other} first"
            ),
        ));
    }
    let others: Vec<&str> = servers
        .iter()
        .copied()
        .filter(|s| *s != member && !removed.contains(s))
        .collect();
    if let Some(sick) = others.iter().find(|s| !healthy.contains(s)) {
        let count = others.iter().filter(|s| healthy.contains(s)).count();
        let voters = if count == 1 { "voter" } else { "voters" };
        return Err(Refusal::new(
            "readiness",
            "quorum",
            format!(
                "removing {member} leaves {count} healthy etcd {voters} of {}; run k3s status {name_of} and restore {sick} first",
                others.len()
            ),
        ));
    }
    Ok(())
}

pub fn admit_operand(target: &Value, leaf: &str, member: &str) -> Result<(), Refusal> {
    let is_removed = removed(target).contains(&member);
    let name_of = target_name(target);
    match (leaf == "node replace", is_removed) {
        (true, false) => Err(Refusal::new(
            "configuration",
            "not-removed",
            format!(
                "{member} has no recorded removal; run k3s node remove {name_of} {member} first"
            ),
        )),
        (false, true) => Err(Refusal::new(
            "configuration",
            "removed",
            format!(
                "{member} is recorded as removed; run k3s node replace {name_of} {member} after editing its machine"
            ),
        )),
        _ => Ok(()),
    }
}

pub fn admin_access_refusal(target: &str, server: &str, operation: Option<&str>) -> Refusal {
    let find = match operation {
        Some(operation) => format!("k3s operation show {target} {operation}"),
        None => format!("k3s operation list {target}"),
    };
    Refusal::new(
        "readiness",
        "admin-access",
        format!(
            "{server} has no published administrator access; run {find}, then rebuild it: k3s node drain {target} {server}, k3s node remove {target} {server}, k3s node replace {target} {server} on a newly declared machine"
        ),
    )
}

pub fn admin_access_operation(server: &str, operations: &Value) -> Option<String> {
    operations
        .as_array()?
        .iter()
        .filter(|o| o["publishes"] == server && o["outcome"] != "succeeded")
        .max_by_key(|o| o["sequence"].as_u64().unwrap_or(0))
        .and_then(|o| o["operation"].as_str())
        .map(str::to_owned)
}

pub fn pending_generation(
    target: &Value,
    leaf: &str,
    member: &str,
    pending: &[Value],
) -> Result<(), Refusal> {
    let Some(first) = pending.first() else {
        return Ok(());
    };
    let acting = acting_first_server(target, None);
    let position = |name: &str| declared(target).iter().position(|m| self::name(m) == name);
    let changes = match leaf {
        "node remove" => acting.as_deref() == Some(member),
        "node replace" => {
            declared(target)
                .iter()
                .any(|m| self::name(m) == member && m["role"] == "server")
                && acting
                    .as_deref()
                    .and_then(position)
                    .is_none_or(|a| position(member).is_some_and(|p| p < a))
        }
        _ => false,
    };
    if !changes {
        return Ok(());
    }
    Err(Refusal::new(
        "busy",
        "pending-generation",
        format!(
            "{} is registered on {} but not active; run k3s reconcile {} first",
            first["id"].as_str().unwrap_or(""),
            first["machine"].as_str().unwrap_or(""),
            target_name(target)
        ),
    ))
}

const LOST_TAINTS: [&str; 3] = [
    "node.kubernetes.io/not-ready=:NoExecute",
    "node.kubernetes.io/unreachable=:NoExecute",
    "node.kubernetes.io/unschedulable=:NoSchedule",
];

fn stale(member: &str) -> Refusal {
    Refusal::new(
        "ownership",
        "stale-approval",
        format!("{member} answers again; the observed plan no longer holds"),
    )
}

fn unready(name: &str, why: &str) -> Refusal {
    Refusal::new("readiness", "agent-view", format!("{name} {why}"))
}

fn differs(name: &str, why: &str) -> Refusal {
    Refusal::new("ownership", "agent-view", format!("{name} {why}"))
}

pub fn readiness_read(read: &Value) -> Result<(), Refusal> {
    let member = read["member"].as_str().unwrap_or("");
    let expected = read["expected"]
        .as_array()
        .ok_or_else(|| integrity("the readiness read names its participants"))?;
    let operated = expected
        .iter()
        .find(|e| e["member"]["member"] == member)
        .ok_or_else(|| integrity("the readiness read's member is a participant"))?;
    let name_of = |entry: &Value| entry["member"]["member"].as_str().unwrap_or("").to_owned();
    if read["view"].is_null() {
        let slots = read["round"]
            .as_array()
            .ok_or_else(|| integrity("the readiness read carries a view or a round"))?;
        let healthy = |entry: &Value| {
            slots
                .iter()
                .any(|s| s["observer"] == entry["member"]["machine"] && s["healthy"] == true)
        };
        if healthy(operated) {
            return Err(stale(member));
        }
        if let Some(sick) = expected
            .iter()
            .find(|e| e["member"]["member"] != member && !healthy(e))
        {
            return Err(Refusal::new(
                "readiness",
                "quorum",
                format!(
                    "{} is not a healthy voter in the membership round",
                    name_of(sick)
                ),
            ));
        }
        return Ok(());
    }
    let items = read["view"]["members"]
        .as_array()
        .filter(|items| items.len() == expected.len())
        .ok_or_else(|| differs("the agent view", "lists other members"))?;
    for (entry, item) in expected.iter().zip(items) {
        let name = name_of(entry);
        if item["member"] != entry["member"] {
            return Err(differs(&name, "is not the agent view's entry in its place"));
        }
        if name == member {
            if item["present"] != true {
                continue;
            }
            if item["ready"] == true {
                return Err(stale(member));
            }
            let taints: Vec<&Value> = item["taints"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|t| !t.as_str().is_some_and(|t| LOST_TAINTS.contains(&t)))
                .collect();
            if item["uid"] != entry["node_uid"]
                || item["labels"] != entry["labels"]
                || json!(taints) != entry["taints"]
            {
                return Err(differs(&name, "has a Node other than its recorded one"));
            }
            continue;
        }
        if item["present"] != true
            || item["uid"] != entry["node_uid"]
            || item["ready"] != true
            || item["roles"] != json!([entry["role"]])
        {
            return Err(unready(&name, "is not present and Ready in the agent view"));
        }
        if item["labels"] != entry["labels"] || item["taints"] != entry["taints"] {
            return Err(differs(&name, "has labels or taints other than declared"));
        }
    }
    Ok(())
}

fn normalized(entry: &Value) -> Value {
    let mut entry = entry.clone();
    if let Some(taints) = entry.get("taints").and_then(Value::as_array) {
        let mut set: Vec<Value> = taints
            .iter()
            .map(|t| {
                json!({"key": t["key"], "value": t["value"].as_str().unwrap_or(""), "effect": t["effect"]})
            })
            .collect();
        set.sort_by_key(Value::to_string);
        set.dedup();
        entry["taints"] = json!(set);
    }
    entry
}

pub fn replacement(
    recorded: &Value,
    current: &Value,
    member: &str,
) -> Result<&'static str, Refusal> {
    let (before, after) = (&recorded["target"], &current["target"]);
    let outside = || {
        Refusal::new(
            "configuration",
            "declaration",
            format!(
                "the declaration of target {} changed outside the machine, node_ip and interface of {member}; revert the other changes",
                target_name(after)
            ),
        )
    };
    let (old, new) = (declared(before), declared(after));
    let Some(index) = old.iter().position(|m| name(m) == member) else {
        return Err(outside());
    };
    if old.len() != new.len() || name(new[index]) != member {
        return Err(outside());
    }
    let without = |target: &Value| {
        let mut t = target.clone();
        if let Some(map) = t.as_object_mut() {
            map.remove("members");
        }
        t
    };
    let transition = |entry: &Value| {
        let mut e = normalized(entry);
        if let Some(map) = e.as_object_mut() {
            for key in ["machine", "node_ip", "interface"] {
                map.remove(key);
            }
        }
        e
    };
    let same_entries = old.iter().zip(&new).enumerate().all(|(i, (a, b))| {
        if i == index {
            transition(a) == transition(b)
        } else {
            a == b
        }
    });
    if without(before) != without(after) || !same_entries {
        return Err(outside());
    }
    let (old_machine, new_machine) = (&old[index]["machine"], &new[index]["machine"]);
    let scripts = |projection: &Value, machine: &Value| -> (Map<String, Value>, Value) {
        let mut map = projection["scripts"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        let own = machine
            .as_str()
            .and_then(|m| map.remove(m))
            .unwrap_or(Value::Null);
        (map, own)
    };
    let (old_scripts, mut old_own) = scripts(recorded, old_machine);
    let (new_scripts, new_own) = scripts(current, new_machine);
    if let Some(name) = old_own
        .get_mut("environment")
        .and_then(|e| e.get_mut("BROIL_MACHINE"))
    {
        *name = new_machine.clone();
    }
    if old_scripts != new_scripts || old_own != new_own {
        return Err(outside());
    }
    let routes = |projection: &Value| {
        let mut map = projection["routes"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        map.remove(member);
        map
    };
    if routes(recorded) != routes(current) {
        return Err(outside());
    }
    if old_machine != new_machine {
        return Ok("new-machine");
    }
    if new[index]["role"] == "server" {
        return Err(Refusal::new(
            "configuration",
            "same-machine-server",
            format!(
                "{member} can only be replaced onto a new machine; declare a new machine for it"
            ),
        ));
    }
    if normalized(old[index]) != normalized(new[index]) {
        return Err(outside());
    }
    Ok("same-machine")
}

pub fn deleted_agents(recorded: &Value, current: &Value, removed: &[&str]) -> Option<Vec<String>> {
    let (before, after) = (declared(&recorded["target"]), declared(&current["target"]));
    let deleted: Vec<&Value> = before
        .iter()
        .copied()
        .filter(|m| !after.iter().any(|a| name(a) == name(m)))
        .collect();
    if deleted.is_empty()
        || deleted
            .iter()
            .any(|m| m["role"] != "agent" || !removed.contains(&name(m)))
    {
        return None;
    }
    let kept: Vec<&Value> = before
        .iter()
        .copied()
        .filter(|m| !deleted.iter().any(|d| name(d) == name(m)))
        .collect();
    let without = |target: &Value| {
        let mut t = target.clone();
        if let Some(map) = t.as_object_mut() {
            map.remove("members");
        }
        t
    };
    if kept != after
        || without(&recorded["target"]) != without(&current["target"])
        || recorded["registries"] != current["registries"]
        || recorded["secrets"] != current["secrets"]
    {
        return None;
    }
    let mut scripts = recorded["scripts"].as_object().cloned().unwrap_or_default();
    for machine in deleted.iter().filter_map(|m| m["machine"].as_str()) {
        if !kept.iter().any(|m| m["machine"] == machine) {
            scripts.remove(machine);
        }
    }
    (Value::Object(scripts) == current["scripts"])
        .then(|| deleted.iter().map(|m| name(m).to_owned()).collect())
}

fn integrity(detail: &str) -> Refusal {
    Refusal::new("integrity", "decision", detail)
}

pub fn decision(observed: &Value) -> Result<Value, Refusal> {
    let mut decision = Map::new();
    for key in DECISION_KEYS {
        let value = observed
            .get(key)
            .ok_or_else(|| integrity("the observed plan lacks a member decision field"))?;
        decision.insert(key.to_owned(), value.clone());
    }
    if let Some(members) = decision.get_mut("members").and_then(Value::as_array_mut) {
        for member in members {
            if let Some(map) = member.as_object_mut() {
                map.remove("observed_ms");
            }
        }
    }
    Ok(Value::Object(decision))
}

pub fn approval(decision: &Value) -> Result<String, Refusal> {
    let exact = decision.as_object().is_some_and(|fields| {
        fields.len() == DECISION_KEYS.len() && DECISION_KEYS.iter().all(|k| fields.contains_key(*k))
    });
    if !exact {
        return Err(integrity(
            "a member decision holds exactly its fifteen fields",
        ));
    }
    super::state::hash(APPROVAL_LABEL, decision)
        .map(|digest| format!("sha256:{digest}"))
        .map_err(|_| integrity("the member decision is not canonical JSON"))
}

pub fn check_approval(approved: &str, fresh: &Value) -> Result<(), Refusal> {
    let digest = approval(fresh)?;
    if digest == approved {
        return Ok(());
    }
    Err(Refusal::new(
        "ownership",
        "stale-approval",
        format!(
            "the observed plan changed; run k3s plan {} --action {} --member {} --observe",
            fresh["scope"]["target"].as_str().unwrap_or(""),
            fresh["action"].as_str().unwrap_or(""),
            fresh["member"]["name"].as_str().unwrap_or("")
        ),
    ))
}

pub fn issues_approval(action: &str, facts: &Value) -> Result<bool, Refusal> {
    let settled = facts["known"] == true && facts["refusals"].as_array().is_some_and(Vec::is_empty);
    match action {
        "node-drain" => {
            if facts["writer"] == true {
                return Ok(settled);
            }
            if facts["reachability"] == "unreachable" {
                let member = facts["member"].as_str().unwrap_or("");
                return Err(Refusal::new(
                    "transport",
                    "unreachable",
                    format!(
                        "{member} does not answer on any owned route; run k3s plan {} --action node-remove --member {member} --observe",
                        facts["target"].as_str().unwrap_or("")
                    ),
                ));
            }
            Ok(false)
        }
        "node-remove" | "node-replace" => Ok(settled),
        "node-uncordon" => Ok(false),
        _ => Err(integrity("not a member operation")),
    }
}

fn count(layout: &Value, key: &str) -> usize {
    layout[key]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0)
}

pub fn step_count(layout: &Value) -> Result<usize, Refusal> {
    let n = count(layout, "participants");
    let servers = count(layout, "servers");
    let replicas = count(layout, "replica_members");
    let unreachable = layout["reachability"] == "unreachable";
    let writer = layout["writer"] == true;
    let action = layout["action"].as_str().unwrap_or("");
    let excepted = unreachable && (action == "node-remove" || action == "node-drain" && writer);
    let acquired = n.saturating_sub(usize::from(excepted));
    let further = readiness_slots(excepted, n, servers)
        + match action {
            "node-drain" => {
                DRAIN_STEPS
                    + if !writer {
                        0
                    } else if unreachable {
                        replicas + 4
                    } else {
                        8
                    }
            }
            "node-uncordon" => 1,
            "node-remove" => {
                let server = layout["member_role"] == "server";
                let polled = if server { servers.saturating_sub(1) } else { 0 };
                let last = if server && n == servers {
                    servers.saturating_sub(1)
                } else {
                    1
                };
                2 + polled + last + 2 * n.saturating_sub(1)
            }
            "node-replace" => match layout["phase"].as_str() {
                Some("begin") => n,
                Some("complete") if n == servers => 1 + servers,
                Some("complete") => 2,
                _ => return Err(integrity("a node-replace layout names its phase")),
            },
            "rebind-declaration" => 0,
            _ => return Err(integrity("not a member operation")),
        };
    let steps = 6 * acquired + further;
    if steps > STEP_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("the {action} operation needs {steps} steps; the limit is {STEP_LIMIT}"),
        ));
    }
    Ok(steps)
}

fn readiness_slots(excepted: bool, participants: usize, servers: usize) -> usize {
    match (excepted, participants == servers) {
        (false, _) => 0,
        (true, false) => 1,
        (true, true) => servers.saturating_sub(1),
    }
}

pub const DRAIN_STEPS: usize = 1 + 2 + 4 + 1 + 2;

fn step_timeout_ms(layout: &Value) -> u64 {
    layout["step_timeout_ms"]
        .as_u64()
        .unwrap_or(DEFAULT_STEP_TIMEOUT_MS)
}

fn five_second_dispatches(timeout_ms: u64) -> usize {
    usize::try_from(timeout_ms.div_ceil(5000)).unwrap_or(usize::MAX)
}

pub fn polled_dispatches(timeout_ms: u64) -> usize {
    five_second_dispatches(timeout_ms).min(180)
}

pub fn poll_interval_ms(timeout_ms: u64, capped: bool) -> u64 {
    if capped {
        (timeout_ms / 180).max(5000)
    } else {
        5000
    }
}

pub fn observation_count(layout: &Value) -> Result<usize, Refusal> {
    step_count(layout)?;
    let n = count(layout, "participants");
    let servers = count(layout, "servers");
    let replicas = count(layout, "replica_members");
    let unreachable = layout["reachability"] == "unreachable";
    let writer = layout["writer"] == true;
    let action = layout["action"].as_str().unwrap_or("");
    let excepted = unreachable && (action == "node-remove" || action == "node-drain" && writer);
    let acquired = n.saturating_sub(usize::from(excepted));
    let timeout = step_timeout_ms(layout);
    let polled = polled_dispatches(timeout);
    let (mutation, read) = (3, 2);
    let round = polled + 1;
    let further = 2 * readiness_slots(excepted, n, servers)
        + match action {
            "node-drain" => {
                let wait = if unreachable {
                    five_second_dispatches(timeout)
                } else {
                    polled
                };
                let mut drain = mutation + 2 * read + 4 * mutation + 2 * wait + 2 * read;
                if writer {
                    drain += if unreachable { 3 * replicas + 12 } else { 23 };
                }
                drain
            }
            "node-uncordon" => mutation,
            "node-remove" => {
                let server = layout["member_role"] == "server";
                let rounds = if server {
                    servers.saturating_sub(1) * round
                } else {
                    0
                };
                let last = if server && n == servers {
                    servers.saturating_sub(1) * round
                } else {
                    4
                };
                2 * mutation + rounds + 6 * n.saturating_sub(1) + last
            }
            "node-replace" => match layout["phase"].as_str() {
                Some("begin") => mutation * n,
                _ if n == servers => read + servers * round,
                _ => read + 4,
            },
            _ => 0,
        };
    let observations = 2 + 16 * acquired + further;
    if observations > OBSERVATION_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!(
                "the {action} operation needs {observations} observations; the limit is {OBSERVATION_LIMIT}"
            ),
        ));
    }
    Ok(observations)
}

fn pod_key(entry: &Value) -> (String, String) {
    (
        entry["namespace"].as_str().unwrap_or("").to_owned(),
        entry["pod"].as_str().unwrap_or("").to_owned(),
    )
}

fn pod_cap() -> Refusal {
    Refusal::new("bound", "pod-cap", "pod-cap")
}

fn pages_of(pages: &Value) -> Result<&Vec<Value>, Refusal> {
    pages
        .as_array()
        .ok_or_else(|| Refusal::new("integrity", "pages", "the pages are not a list"))
}

pub fn compose_pages(pages: &Value) -> Result<Vec<Value>, Refusal> {
    let pages = pages_of(pages)?;
    let mut seen = BTreeSet::new();
    let mut composed = Vec::new();
    for page in pages {
        if count(page, "total") > POD_LIMIT {
            return Err(pod_cap());
        }
        for entry in page["pods"].as_array().into_iter().flatten() {
            if seen.insert(pod_key(entry)) {
                composed.push(entry.clone());
            }
        }
    }
    if pages.last().is_some_and(|p| !p["next"].is_null()) {
        return Err(pod_cap());
    }
    Ok(composed)
}

pub fn eviction_pages(classification: &[Value]) -> Vec<Vec<Value>> {
    let evictable: Vec<Value> = classification
        .iter()
        .filter(|p| p["class"] == "evictable" && p["terminating"] != true)
        .map(|p| json!({"namespace": p["namespace"], "pod": p["pod"]}))
        .collect();
    evictable
        .chunks(EVICT_PODS)
        .map(<[Value]>::to_vec)
        .collect()
}

pub fn compose_naming(pages: &Value) -> Result<Value, Refusal> {
    let pages = pages_of(pages)?;
    let mut seen = BTreeSet::new();
    let mut pods = Vec::new();
    for entry in pages
        .iter()
        .flat_map(|p| p["pods"].as_array().into_iter().flatten())
    {
        if seen.insert(pod_key(entry)) {
            pods.push(entry.clone());
        }
    }
    let mut truncated = pages.last().is_some_and(|p| !p["next"].is_null());
    if pods.len() > NAMED_PODS {
        pods.truncate(NAMED_PODS);
        truncated = true;
    }
    Ok(json!({"pods": pods, "truncated": truncated}))
}

pub fn removal_payload(
    observer: &Value,
    member_recipe: &Value,
    target: &Value,
) -> Result<Value, Refusal> {
    let member = member_recipe["recipe"]["member"]
        .as_str()
        .or_else(|| member_recipe["recipe"]["member"]["member"].as_str())
        .unwrap_or("");
    let entry = declared(target)
        .into_iter()
        .find(|m| name(m) == member && m["role"] == "server")
        .ok_or_else(|| {
            Refusal::new(
                "integrity",
                "removed",
                format!("{member} has no server entry in the owner snapshot"),
            )
        })?;
    let node_ip = entry["node_ip"]
        .as_str()
        .ok_or_else(|| Refusal::new("integrity", "removed", format!("{member} has no node IP")))?;
    Ok(
        json!({"recipe_kind": observer["recipe_kind"], "recipe": observer["recipe"],
        "identity": null, "membership": null,
        "removed": {"member": member, "node_ip": node_ip}}),
    )
}

fn term_matches(term: &Value, labels: &Value) -> bool {
    term["matchExpressions"]
        .as_array()
        .into_iter()
        .flatten()
        .all(|e| {
            let label = labels[e["key"].as_str().unwrap_or("")].as_str();
            let values: Vec<&str> = e["values"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            match e["operator"].as_str() {
                Some("In") => label.is_some_and(|l| values.contains(&l)),
                Some("NotIn") => label.is_none_or(|l| !values.contains(&l)),
                Some("Exists") => label.is_some(),
                Some("DoesNotExist") => label.is_none(),
                _ => false,
            }
        })
}

fn selects_only(volume: &Value, node: &str, nodes: &[&Value]) -> bool {
    let terms = &volume["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"];
    let Some(terms) = terms.as_array() else {
        return false;
    };
    let selected: BTreeSet<&str> = nodes
        .iter()
        .filter(|n| {
            let labels = &n["metadata"]["labels"];
            terms.iter().any(|t| term_matches(t, labels))
        })
        .filter_map(|n| n["metadata"]["name"].as_str())
        .collect();
    selected.len() == 1 && selected.contains(node)
}

fn class(pod: &Value, node: &str, cluster: &Value) -> &'static str {
    let metadata = &pod["metadata"];
    let controller = metadata["ownerReferences"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|o| o["controller"] == true);
    let mirror = metadata["annotations"]
        .get("kubernetes.io/config.mirror")
        .is_some_and(|v| !v.is_null());
    if mirror || controller.is_some_and(|o| o["kind"] == "DaemonSet") {
        return "daemon";
    }
    let labels = &metadata["labels"];
    if metadata["namespace"] == "broil-registry"
        && labels["broil.dev/managed-by"] == "broil"
        && labels["broil.dev/component"] == "registry-service"
    {
        return "writer";
    }
    let nodes: Vec<&Value> = cluster["nodes"].as_array().into_iter().flatten().collect();
    let local = pod["spec"]["volumes"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|v| {
            if v.get("hostPath").is_some_and(|h| !h.is_null()) {
                return true;
            }
            let Some(claim) = v["persistentVolumeClaim"]["claimName"].as_str() else {
                return false;
            };
            let bound = cluster["claims"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|c| {
                    c["metadata"]["namespace"] == metadata["namespace"]
                        && c["metadata"]["name"] == claim
                })
                .and_then(|c| c["spec"]["volumeName"].as_str());
            bound.is_some_and(|volume| {
                cluster["volumes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|pv| pv["metadata"]["name"] == volume)
                    .is_some_and(|pv| selects_only(pv, node, &nodes))
            })
        });
    if local {
        return "local-storage";
    }
    if controller.is_none() {
        return "unmanaged";
    }
    "evictable"
}

pub fn classify_pods(node: &str, cluster: &Value) -> Result<Vec<Value>, Refusal> {
    let pods: Vec<&Value> = cluster["pods"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| {
            p["spec"]["nodeName"] == node
                && !matches!(p["status"]["phase"].as_str(), Some("Succeeded" | "Failed"))
        })
        .collect();
    if pods.len() > POD_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("{node} has {} pods; the limit is {POD_LIMIT}", pods.len()),
        ));
    }
    Ok(pods
        .into_iter()
        .map(|p| {
            let metadata = &p["metadata"];
            json!({"namespace": metadata["namespace"], "pod": metadata["name"],
                "class": class(p, node, cluster),
                "terminating": metadata.get("deletionTimestamp").is_some_and(|d| !d.is_null())})
        })
        .collect())
}
