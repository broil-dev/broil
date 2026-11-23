// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::release::Refusal;
use serde_json::{Value, json};

pub const STEP_LIMIT: usize = 1024;

fn names(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

pub fn required_set(input: &Value) -> Result<Value, Refusal> {
    let removed = names(&input["removed"]);
    let (excluded, required): (Vec<&str>, Vec<&str>) = names(&input["policy_members"])
        .into_iter()
        .partition(|member| removed.contains(member));
    if required.is_empty() {
        return Err(Refusal::new(
            "readiness",
            "delivery",
            "every member of the release's policy is recorded as removed; replace a member or prepare a new release",
        ));
    }
    Ok(json!({"required": required, "excluded": excluded}))
}

pub fn resolve_nodes(input: &Value) -> Result<Vec<String>, Refusal> {
    let application = input["application"].as_str().unwrap_or("");
    let removed = names(&input["removed"]);
    let members: Vec<&Value> = input["members"].as_array().into_iter().flatten().collect();
    let live = |member: &&&Value| {
        member["name"]
            .as_str()
            .is_some_and(|name| !removed.contains(&name))
    };
    let nodes = &input["nodes"];
    let selected: Vec<String> = if nodes == "all" {
        members
            .iter()
            .filter(live)
            .filter_map(|m| m["name"].as_str().map(str::to_owned))
            .collect()
    } else if let Some(labels) = nodes.get("labels").and_then(Value::as_object) {
        members
            .iter()
            .filter(live)
            .filter(|m| labels.iter().all(|(k, v)| &m["labels"][k] == v))
            .filter_map(|m| m["name"].as_str().map(str::to_owned))
            .collect()
    } else {
        let listed = names(&nodes["members"]);
        if let Some(member) = listed.iter().find(|name| removed.contains(name)) {
            return Err(Refusal::new(
                "configuration",
                "removed",
                format!(
                    "applications.{application}.delivery.nodes names {member}, which is recorded as removed; replace it or edit the list"
                ),
            ));
        }
        members
            .iter()
            .filter_map(|m| m["name"].as_str())
            .filter(|name| listed.contains(name))
            .map(str::to_owned)
            .collect()
    };
    if selected.is_empty() {
        return Err(Refusal::new(
            "readiness",
            "delivery",
            format!(
                "applications.{application}.delivery.nodes selects no member that is not recorded as removed; edit the list"
            ),
        ));
    }
    Ok(selected)
}

pub const OBSERVATION_LIMIT: usize = 4096;

pub const CLOSURE_CAP: usize = 24;

pub fn deliver_layout(input: &Value) -> Result<Value, Refusal> {
    let count = |key: &str| input[key].as_u64().unwrap_or(0) as usize;
    let (participants, required) = (count("participants"), count("required"));
    let reads = if input["managed_origin"] == true {
        2
    } else {
        0
    };
    let steps = 6 * participants + 4 * required + reads;
    let per_member = if input["managed_images"] == true {
        2 + CLOSURE_CAP + 1 + 3 + 3
    } else {
        2 + 1 + 3 + 3
    };
    let observations = 1 + 16 * participants + 2 * reads + per_member * required + 1;
    if steps > STEP_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("the operation needs {steps} steps; the limit is {STEP_LIMIT}"),
        ));
    }
    if observations > OBSERVATION_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!(
                "the operation can record {observations} observations; the limit is {OBSERVATION_LIMIT}"
            ),
        ));
    }
    Ok(json!({"steps": steps, "observations": observations}))
}

const FRAME: usize = 65_536;
const RESERVE: usize = 8_192;

pub fn origin_reads(input: &Value) -> &'static str {
    if input["managed_origin"] != true {
        return "none";
    }
    let recipe_bytes = input["recipe_bytes"]
        .as_u64()
        .map_or(RECIPE_LIMIT, |b| b as usize);
    let repositories = input["repositories"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let expected =
        json!({"since_ms": u64::MAX, "repositories": repositories, "digests": input["digests"]});
    let widest = json!({"protocol": "broil-k3s-delivery", "version": 1,
        "action": "read-origin-log", "request_id": "f".repeat(32),
        "binding": {"pad": "f".repeat(2048)}, "remaining_ms": 30_000, "wait_ms": null,
        "recipe": "r".repeat(recipe_bytes), "expected": expected, "resource": null,
        "preflight": null, "member": "f".repeat(64)});
    let header = serde_json::to_vec(&widest).map_or(usize::MAX, |b| b.len());
    if header.saturating_add(17 + RESERVE) <= FRAME {
        "dispatch"
    } else {
        "deselect"
    }
}

pub fn window(input: &Value) -> Value {
    let settled = |read: &Value| (read["read"] == "settled").then(|| read["ms"].clone());
    let last = input["last_settled_ms"].clone();
    match settled(&input["start"]) {
        None => json!({"started_ms": input["first_inspect_ms"], "ended_ms": last,
            "end": "deselect"}),
        Some(started) => json!({"started_ms": started,
            "ended_ms": settled(&input["end"]).unwrap_or(last), "end": "dispatch"}),
    }
}

pub fn present_images(input: &Value) -> Result<Value, Refusal> {
    let expected = input["expected"].as_object().cloned().unwrap_or_default();
    let images: Vec<&Value> = input["images"].as_array().into_iter().flatten().collect();
    let (mut delivered, mut pin, mut missing) = (Vec::new(), Vec::new(), Vec::new());
    for (reference, config) in &expected {
        match images.iter().find(|i| i["reference"] == reference.as_str()) {
            Some(i) if i["present"] == true && i["repo_digests_match"] == true => {
                if i["image_id"] != *config {
                    return Err(Refusal::new(
                        "integrity",
                        "digest",
                        format!(
                            "{reference} is held with image ID {}; the release's config digest is {}",
                            i["image_id"].as_str().unwrap_or(""),
                            config.as_str().unwrap_or("")
                        ),
                    ));
                }
                if i["pinned"] == true {
                    delivered.push(json!(reference));
                } else {
                    pin.push(json!(reference));
                }
            }
            _ => missing.push(json!(reference)),
        }
    }
    Ok(json!({"delivered": delivered, "pin": pin, "missing": missing}))
}

pub fn retain_release(derived: &Value, records: &Value) -> Value {
    match derived["active"].as_str() {
        Some(active) => json!({"release": active,
            "release_sha256": records[active]["release_sha256"]}),
        None => json!({"release": null, "release_sha256": null}),
    }
}

pub fn retain_steps(participants: usize, effects: usize) -> usize {
    6 * participants + 2 * effects
}

const RECIPE_KEYS: [&str; 14] = [
    "scope",
    "owner",
    "operation",
    "cluster",
    "action",
    "release",
    "release_sha256",
    "writer",
    "fallback",
    "members",
    "excluded",
    "images",
    "unpin",
    "profile_sha256",
];

pub const RECIPE_LIMIT: usize = 49_152;

pub const REPORT_DELIVERIES: usize = 16;

pub fn recipe_sha256(recipe: &Value) -> String {
    let bytes = serde_json::to_vec(recipe).unwrap_or_default();
    super::release::sha256_hex(&[b"broil-k3s-delivery-recipe-v1\n", &bytes])
}

pub fn check_recipe(recipe: &Value) -> Result<(), Refusal> {
    let exact = recipe.as_object().is_some_and(|o| {
        o.len() == RECIPE_KEYS.len() && RECIPE_KEYS.iter().all(|k| o.contains_key(*k))
    });
    if !exact {
        return Err(Refusal::new(
            "integrity",
            "delivery",
            "the delivery recipe does not hold exactly its fields",
        ));
    }
    let size = super::state::canonical(recipe)
        .map_err(|_| {
            Refusal::new(
                "integrity",
                "delivery",
                "the delivery recipe is not canonical JSON",
            )
        })?
        .len();
    if size > RECIPE_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("the delivery recipe is {size} bytes; the limit is {RECIPE_LIMIT}"),
        ));
    }
    Ok(())
}

pub fn recipe_images(release: &Value, artifacts: &Value) -> Result<Value, Refusal> {
    let disagree = |image: &str| {
        Refusal::new(
            "integrity",
            "release",
            format!(
                "the artifact record of image {image} does not agree with the release's manifests"
            ),
        )
    };
    let mut images = Vec::new();
    for image in release.as_array().into_iter().flatten() {
        let name = image["image"].as_str().unwrap_or("");
        let artifact = image["artifact"].as_str().ok_or_else(|| disagree(name))?;
        let recorded = artifacts[artifact]["platforms"]
            .as_array()
            .ok_or_else(|| disagree(name))?;
        let mut platforms = Vec::new();
        for platform in image["platforms"]
            .as_array()
            .ok_or_else(|| disagree(name))?
        {
            let found = recorded
                .iter()
                .find(|p| p["platform"] == platform["platform"])
                .filter(|p| p["manifest"] == platform["manifest"] && p["config"].is_string())
                .ok_or_else(|| disagree(name))?;
            platforms.push(
                json!({"platform": platform["platform"], "manifest": platform["manifest"],
                "config": found["config"]}),
            );
        }
        images.push(json!({"image": image["image"], "artifact": image["artifact"],
            "reference": image["reference"], "repository": image["repository"], "root": image["root"],
            "managed": image["managed"], "platforms": platforms}));
    }
    Ok(Value::Array(images))
}

pub fn fallback(entries: &Value) -> Value {
    entries
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["managed"] == true)
        .map_or(Value::Null, |e| e["fallback"].clone())
}

pub fn member_steps(facts: &Value) -> Value {
    let images: Vec<&Value> = facts["images"].as_array().into_iter().flatten().collect();
    let missing = |i: &Value| i["present"] != true;
    let check_closure = images.iter().any(|i| i["managed"] == true);
    let pull = images.iter().any(|i| missing(i));
    let pin = pull
        || images
            .iter()
            .any(|i| i["present"] == true && i["pinned"] != true);
    json!({"check_closure": check_closure, "pull": pull, "pin": pin})
}

pub fn evidence(input: &Value) -> Value {
    let managed = input["managed"] == true;
    let fallback = input["fallback"] == "same-origin";
    let nodes: Vec<&Value> = input["nodes"].as_array().into_iter().flatten().collect();
    let fell_back = |n: &Value| fallback && n["origin_fallback"] == true;
    let seeded_on = |n: &Value| !managed || (n["replica_ready"] == true && !fell_back(n));
    let delivered = nodes.iter().all(|n| n["delivered"] == true);
    let seeded = nodes.iter().all(|n| seeded_on(n));
    let succeeded = delivered && nodes.iter().all(|n| seeded_on(n) || fell_back(n));
    json!({"evidence": {"delivered": delivered, "seeded": seeded},
        "outcome": if succeeded { "succeeded" } else { "failed" }})
}

pub fn origin(aggregate: &Value) -> Value {
    const FIELDS: [&str; 5] = [
        "complete",
        "requests",
        "bytes",
        "all_sized",
        "estimate_bytes",
    ];
    let exact = aggregate
        .as_object()
        .is_some_and(|o| o.len() == FIELDS.len() && FIELDS.iter().all(|k| o.contains_key(*k)));
    let (Some(requests), Some(bytes), Some(estimate)) = (
        aggregate["requests"].as_u64(),
        aggregate["bytes"].as_u64(),
        aggregate["estimate_bytes"].as_u64(),
    ) else {
        return Value::Null;
    };
    if !exact || aggregate["complete"] != true || !aggregate["all_sized"].is_boolean() {
        return Value::Null;
    }
    let (bytes, source) = if aggregate["all_sized"] == true {
        (bytes, "access-log")
    } else {
        (estimate, "descriptor-estimate")
    };
    json!({"bytes": bytes, "bytes_source": source, "requests": requests})
}

pub fn report(input: &Value) -> Result<Value, Refusal> {
    let release = input["release"].as_str().unwrap_or("");
    let deliveries = input["deliveries"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    if deliveries.is_empty() {
        let target = input["target"].as_str().unwrap_or("");
        return Err(Refusal::new(
            "configuration",
            "delivery",
            format!(
                "{release} has no recorded delivery; run k3s release deliver {target} {release}"
            ),
        ));
    }
    let newest = &deliveries[deliveries.len().saturating_sub(REPORT_DELIVERIES)..];
    Ok(json!({"release": release, "deliveries": newest,
        "truncated": deliveries.len() > REPORT_DELIVERIES}))
}

pub fn origin_read(input: &Value) -> &'static str {
    const AGGREGATE: [&str; 5] = [
        "all_sized",
        "bytes",
        "complete",
        "estimate_bytes",
        "requests",
    ];
    let response = &input["response"];
    if input["recordable"] != true {
        return "report-only";
    }
    if response.is_null() {
        return "unread";
    }
    let ok = response["status"] == "ok";
    if response["kind"] != "result"
        || response["failure"].is_null() != ok
        || !response["terminal"].is_null()
    {
        return "integrity";
    }
    if !ok {
        return "unread";
    }
    let shaped = response["log"].as_object().is_some_and(|log| {
        log.len() == AGGREGATE.len() && AGGREGATE.iter().all(|key| log.contains_key(*key))
    }) && ["node", "images", "closure"]
        .iter()
        .all(|key| response[*key].is_null());
    if shaped { "settled" } else { "integrity" }
}
