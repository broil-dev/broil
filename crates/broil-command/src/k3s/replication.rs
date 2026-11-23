// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::release::Refusal;
use serde_json::{Value, json};

pub const RECIPE_LABEL: &str = "broil-k3s-registry-replication-recipe-v1";
pub const RECIPE_LIMIT: usize = 32_768;
pub const STEP_LIMIT: usize = 1024;
pub const OBJECTS: [&str; 2] = ["registry-reader-object-01", "registry-reader-object-02"];

const RECIPE_KEYS: [&str; 18] = [
    "scope",
    "owner",
    "operation",
    "cluster",
    "first_server",
    "version",
    "registry",
    "path",
    "writer",
    "members",
    "devices",
    "detached",
    "assets",
    "reader",
    "tolerations",
    "stage",
    "origins",
    "profile_sha256",
];

const FACT_KEYS: [&str; 16] = [
    "record",
    "service",
    "device_id",
    "configuration",
    "folder",
    "state",
    "completion",
    "need_bytes",
    "need_items",
    "need_deletes",
    "local_changes",
    "peers_connected",
    "peers_expected",
    "bytes_received",
    "bytes_sent",
    "peer_completion",
];

const COMPLETION_KEYS: [&str; 4] = ["completion", "need_bytes", "need_items", "need_deletes"];

fn exactly(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|fields| {
        fields.len() == keys.len() && keys.iter().all(|k| fields.contains_key(*k))
    })
}

fn refusal(failure: &'static str, detail: &str) -> Refusal {
    Refusal::new(failure, "registry-replication", detail)
}

pub fn recipe_sha256(recipe: &Value) -> String {
    super::state::hash(RECIPE_LABEL, recipe).unwrap_or_default()
}

pub fn check_recipe(recipe: &Value) -> Result<(), Refusal> {
    if !exactly(recipe, &RECIPE_KEYS)
        || !exactly(
            &recipe["reader"],
            &["realm_path", "service", "certificate", "switch_operation"],
        )
        || !exactly(&recipe["origins"], &["replication", "objects"])
    {
        return Err(refusal(
            "integrity",
            "the replication recipe does not hold exactly its fields",
        ));
    }
    let size = super::state::canonical(recipe)
        .map_err(|_| refusal("integrity", "the replication recipe is not canonical JSON"))?
        .len();
    if size > RECIPE_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("the replication recipe is {size} bytes; the limit is {RECIPE_LIMIT}"),
        ));
    }
    Ok(())
}

fn parts(facts: &Value) -> (&[Value], [&str; 2]) {
    let members = facts["members"].as_array().map_or(&[][..], Vec::as_slice);
    let objects = &facts["objects"];
    (
        members,
        [
            objects["configmap"].as_str().unwrap_or(""),
            objects["daemonset"].as_str().unwrap_or(""),
        ],
    )
}

fn detached(facts: &Value) -> Vec<&str> {
    facts["detached"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn changed(member: &Value) -> bool {
    member["writer"] != true
        && (member["state"] == "local-changes"
            || member["local_changes"].as_u64().is_some_and(|n| n > 0))
}

pub fn stage(facts: &Value) -> Result<&'static str, Refusal> {
    let (members, objects) = parts(facts);
    let drifted = |class: &str| matches!(class, "foreign" | "owned-drifted");
    if members
        .iter()
        .any(|m| m["record"].as_str().is_some_and(drifted))
        || objects.iter().any(|c| drifted(c))
    {
        return Err(refusal(
            "ownership",
            "a replication record or reader object is not Broil's own",
        ));
    }
    let owned = |m: &Value| m["record"] == "owned";
    if members
        .iter()
        .any(|m| m["record"] == "unobservable" || owned(m) && m["configuration"].is_null())
        || objects.contains(&"unobservable")
    {
        return Err(refusal("readiness", "a replication fact is unobservable"));
    }
    if members.iter().all(|m| m["record"] == "absent") && objects == ["absent", "absent"] {
        return Ok("create");
    }
    let shape = || refusal("ownership", "the replication facts match no stage");
    if objects != ["owned", "owned"] {
        return Err(shape());
    }
    let senders: Vec<&Value> = members
        .iter()
        .filter(|m| m["folder"] == "sendonly")
        .collect();
    if members
        .iter()
        .any(|m| owned(m) && (m["writer"] == true) != (m["folder"] == "sendonly"))
        || senders.len() > 1
    {
        return Err(refusal(
            "ownership",
            "the writer's folder is not the only send-only folder",
        ));
    }
    if members.iter().any(|m| !owned(m)) {
        return if members
            .iter()
            .all(|m| owned(m) || m["record"] == "absent" && m["resource"] == true)
        {
            Ok("extend")
        } else {
            Err(shape())
        };
    }
    let configure = members
        .iter()
        .any(|m| m["configuration"] == "differs" || changed(m))
        || facts["reader_differs"] == true
        || !detached(facts).is_empty();
    Ok(if configure { "configure" } else { "observe" })
}

fn effect(action: &str, subject: &Value) -> Value {
    json!({"action": action, "subject": subject})
}

fn writer_last<'a>(members: impl Iterator<Item = &'a Value>) -> Vec<&'a Value> {
    let (mut readers, writers): (Vec<&Value>, Vec<&Value>) =
        members.partition(|m| m["writer"] != true);
    readers.extend(writers);
    readers
}

pub fn effects(facts: &Value) -> Result<Vec<Value>, Refusal> {
    let stage = stage(facts)?;
    let (members, _) = parts(facts);
    let mut out = Vec::new();
    match stage {
        "create" | "extend" => {
            let created: Vec<&Value> = members
                .iter()
                .filter(|m| stage == "create" || m["record"] == "absent")
                .collect();
            for m in &created {
                out.push(effect("create-replication", &m["member"]));
                out.push(effect("create-replica", &m["member"]));
            }
            let order = if stage == "create" {
                members.iter().collect()
            } else {
                writer_last(members.iter())
            };
            for m in order {
                out.push(effect("configure-replication", &m["member"]));
            }
            if stage == "create" {
                for id in OBJECTS {
                    out.push(effect("create-object", &json!(id)));
                }
            }
        }
        "configure" => {
            let returning = detached(facts);
            let configured: Vec<&Value> = if returning.is_empty() {
                writer_last(members.iter().filter(|m| m["configuration"] == "differs"))
            } else {
                let (first, rest): (Vec<&Value>, Vec<&Value>) = members
                    .iter()
                    .partition(|m| m["member"].as_str().is_some_and(|n| returning.contains(&n)));
                first
                    .into_iter()
                    .chain(writer_last(rest.into_iter()))
                    .collect()
            };
            for m in configured {
                out.push(effect("configure-replication", &m["member"]));
            }
            for m in members.iter().filter(|m| changed(m)) {
                out.push(effect("revert-replica", &m["member"]));
            }
            if facts["reader_differs"] == true {
                out.push(effect("configure-reader", &json!(OBJECTS[0])));
            }
        }
        _ => {}
    }
    Ok(out)
}

pub fn writer_generation(owner: &Value) -> u64 {
    1 + 2 * owner["writer"]["moves"].as_u64().unwrap_or(0)
}

pub fn step_count(members: &[Value], replicas: usize, effects: usize) -> Result<usize, Refusal> {
    let servers = members.iter().filter(|m| m["role"] == "server").count();
    let agents = usize::from(servers < members.len());
    let count = 6 * members.len() + 2 * servers + 2 * agents + 3 * effects + 3 * (replicas + 1);
    if count > STEP_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("the replication operation needs {count} steps; the limit is {STEP_LIMIT}"),
        ));
    }
    Ok(count)
}

fn device_id(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 8
        && groups.iter().all(|g| {
            g.len() == 7
                && g.bytes()
                    .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        })
}

fn counter(value: &Value) -> bool {
    value.is_null() || value.is_u64()
}

fn completion(value: &Value) -> bool {
    exactly(value, &COMPLETION_KEYS)
        && value["completion"]
            .as_f64()
            .is_some_and(|c| (0.0..=100.0).contains(&c))
        && COMPLETION_KEYS[1..].iter().all(|k| value[*k].is_u64())
}

pub fn facts(reply: &Value) -> Result<Value, Refusal> {
    let one_of = |key: &str, values: &[&str], nullable: bool| {
        reply[key]
            .as_str()
            .map_or(nullable && reply[key].is_null(), |v| values.contains(&v))
    };
    let valid = exactly(reply, &FACT_KEYS)
        && one_of(
            "record",
            &[
                "absent",
                "owned",
                "owned-drifted",
                "foreign",
                "unobservable",
            ],
            false,
        )
        && one_of("service", &["running", "stopped", "unobservable"], false)
        && (reply["device_id"].is_null() || reply["device_id"].as_str().is_some_and(device_id))
        && one_of("configuration", &["owned", "differs"], true)
        && one_of("folder", &["sendonly", "receiveonly"], true)
        && one_of(
            "state",
            &[
                "in-sync",
                "syncing",
                "local-changes",
                "stopped",
                "removed",
                "unobserved",
            ],
            false,
        )
        && (reply["completion"].is_null()
            || reply["completion"]
                .as_f64()
                .is_some_and(|c| (0.0..=100.0).contains(&c)))
        && [
            "need_bytes",
            "need_items",
            "need_deletes",
            "local_changes",
            "peers_connected",
            "peers_expected",
            "bytes_received",
            "bytes_sent",
        ]
        .iter()
        .all(|k| counter(&reply[*k]))
        && (reply["peer_completion"].is_null() || completion(&reply["peer_completion"]));
    if !valid {
        return Err(refusal(
            "integrity",
            "an inspect-replication reply is not exactly its closed facts",
        ));
    }
    Ok(reply.clone())
}

fn complete(value: &Value) -> bool {
    value["completion"].as_f64() == Some(100.0)
        && COMPLETION_KEYS[1..]
            .iter()
            .all(|k| value[*k].as_u64() == Some(0))
}

pub fn completion_proved(old: &Value, new: &Value) -> bool {
    complete(&old["peer_completion"]) && new["state"] == "in-sync"
}
