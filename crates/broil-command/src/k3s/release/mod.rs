// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub mod binding;
pub mod kept;
pub mod record;
pub mod select;
pub mod store;
pub mod version;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const PAYLOAD_LIMIT: usize = 983_032;
pub const RECIPE_LIMIT: usize = 49_152;

const RECIPE_KEYS: [&str; 19] = [
    "action",
    "api_server",
    "application",
    "chunks",
    "cluster",
    "excluded",
    "hooks",
    "namespace",
    "objects_sha256",
    "operation",
    "owner",
    "profile_sha256",
    "release",
    "release_sha256",
    "required",
    "scope",
    "secrets",
    "settles",
    "version",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub failure: &'static str,
    pub boundary: &'static str,
    pub detail: String,
}

impl Refusal {
    pub fn new(failure: &'static str, boundary: &'static str, detail: impl Into<String>) -> Self {
        Self {
            failure,
            boundary,
            detail: detail.into(),
        }
    }
}

pub(crate) fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn labeled(label: &str, value: &Value) -> String {
    let encoded = serde_json::to_vec(value).expect("JSON values encode");
    sha256_hex(&[label.as_bytes(), b"\n", &encoded])
}

const FRAME_LIMIT: usize = 65_536;
const OBSERVATION_ENVELOPE: usize = 4096;
pub const WORKLOAD_GROUP: usize = 32;
const STEP_LIMIT: usize = 1024;
pub const SECRET_HEADER_LIMIT: usize = 8192;

fn encoded_len(value: &Value) -> usize {
    serde_json::to_vec(value).expect("JSON values encode").len()
}

fn identity_len(object: &Value) -> usize {
    encoded_len(
        &json!({"api_version": object["api_version"], "kind": object["kind"],
        "namespace": object["namespace"], "name": object["name"]}),
    )
}

fn row_len(object: &Value) -> usize {
    encoded_len(&json!({"kind": object["kind"], "name": object["name"],
        "namespace": object["namespace"], "outcome": "configured", "uid": "u".repeat(36),
        "reason": "rejected"}))
}

fn header_base(index: usize) -> usize {
    encoded_len(&json!({"protocol": "broil-k3s-release", "version": 1,
        "action": "apply-objects", "binding": "b".repeat(4094), "request_id": "0".repeat(32),
        "remaining_ms": 7_200_000, "recipe": "r".repeat(RECIPE_LIMIT - 2), "wait_ms": null,
        "expected": {"chunk": index, "namespace": "n".repeat(63), "objects": []}}))
}

pub fn chunks(objects: &[Value], namespace_first: bool) -> Result<Vec<Value>, Refusal> {
    let mut result: Vec<Value> = Vec::new();
    let mut first = 0;
    let (mut size, mut header, mut rows) = (0, header_base(0), 2);
    for (index, object) in objects.iter().enumerate() {
        let bytes = object["document"].as_str().map_or(0, str::len);
        if bytes > PAYLOAD_LIMIT {
            return Err(Refusal::new(
                "bound",
                "size",
                format!(
                    "document {} is {bytes} bytes after binding; the limit is {PAYLOAD_LIMIT}",
                    index + 1
                ),
            ));
        }
        let comma = usize::from(index > first);
        let alone = namespace_first && index <= 1;
        let fits = size + bytes <= PAYLOAD_LIMIT
            && header + comma + identity_len(object) <= FRAME_LIMIT
            && rows + comma + row_len(object) <= FRAME_LIMIT - OBSERVATION_ENVELOPE;
        if index > first && (alone || !fits) {
            close(&mut result, objects, first, index);
            first = index;
            (size, header, rows) = (0, header_base(result.len()), 2);
        }
        let comma = usize::from(index > first);
        header += comma + identity_len(object);
        rows += comma + row_len(object);
        size += bytes;
        if header > FRAME_LIMIT || rows > FRAME_LIMIT - OBSERVATION_ENVELOPE {
            return Err(Refusal::new(
                "bound",
                "size",
                format!("object {} cannot fit an apply-objects header", index + 1),
            ));
        }
    }
    close(&mut result, objects, first, objects.len());
    Ok(result)
}

fn close(result: &mut Vec<Value>, objects: &[Value], first: usize, end: usize) {
    if end > first {
        let parts: Vec<&[u8]> = objects[first..end]
            .iter()
            .map(|o| o["document"].as_str().unwrap_or("").as_bytes())
            .collect();
        result.push(json!({"first": first, "count": end - first, "sha256": sha256_hex(&parts)}));
    }
}

pub fn concatenate(contributions: &[&[u8]]) -> Vec<u8> {
    let mut input = Vec::new();
    for (index, contribution) in contributions.iter().enumerate() {
        if index > 0 {
            let ends = ends_with_separator(contributions[index - 1]);
            if !input.is_empty() && !input.ends_with(b"\n") {
                input.push(b'\n');
            }
            if !ends {
                input.extend_from_slice(b"---\n");
            }
        }
        input.extend_from_slice(contribution);
    }
    input
}

fn ends_with_separator(contribution: &[u8]) -> bool {
    let trimmed = contribution.strip_suffix(b"\n").unwrap_or(contribution);
    trimmed.ends_with(b"\n---") || trimmed == b"---"
}

pub fn apply_steps(counts: &Value) -> Result<usize, Refusal> {
    let n = |key: &str| counts[key].as_u64().unwrap_or(0) as usize;
    let groups = n("workloads").div_ceil(WORKLOAD_GROUP);
    let steps = 6 * n("participants")
        + n("required")
        + 3 * n("secrets")
        + 2 * n("chunks")
        + groups
        + n("before_apply")
        + n("health")
        + 1;
    if steps > STEP_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("the operation needs {steps} steps; the limit is {STEP_LIMIT}"),
        ));
    }
    Ok(steps)
}

pub const REPORT_LIMIT: usize = 1_048_576;
pub const UNDELIVERED_BUDGET: usize = 32 * 1228 + 31;
const WORKLOAD_KINDS: [(&str, &str); 6] = [
    ("apps/v1", "Deployment"),
    ("apps/v1", "StatefulSet"),
    ("apps/v1", "DaemonSet"),
    ("apps/v1", "ReplicaSet"),
    ("batch/v1", "Job"),
    ("v1", "Pod"),
];

pub fn report_input(record: &Value, leaf: &str, required: &[Value], excluded: &[Value]) -> Value {
    let list = |value: &Value| value.as_array().cloned().unwrap_or_default();
    let objects = list(&record["manifests"]["objects"]);
    let row = |o: &Value| {
        let namespace = if o["namespace"].is_null() && o["kind"] != "Namespace" {
            record["namespace"].clone()
        } else {
            o["namespace"].clone()
        };
        json!({"kind": o["kind"], "name": o["name"], "namespace": namespace})
    };
    let workloads: Vec<Value> = objects
        .iter()
        .filter(|o| {
            WORKLOAD_KINDS
                .iter()
                .any(|(v, k)| o["api_version"] == *v && o["kind"] == *k)
        })
        .map(row)
        .collect();
    let secrets: Vec<Value> = list(&record["secrets"])
        .iter()
        .map(|s| {
            json!({"secret": s["secret"],
                "keys": list(&s["keys"]).iter().map(|k| k["data_key"].clone()).collect::<Vec<_>>(),
                "version": s["keys"][0]["version"]})
        })
        .collect();
    let hooks: Vec<Value> = list(&record["hooks"])
        .iter()
        .map(|h| json!({"stage": h["stage"], "name": h["name"], "location": h["location"]}))
        .collect();
    json!({"leaf": leaf, "application": record["application"], "release": record["release"],
        "objects": objects.iter().map(row).collect::<Vec<_>>(), "workloads": workloads,
        "secrets": secrets, "hooks": hooks, "required": required, "excluded": excluded})
}

pub fn report_price(input: &Value) -> Result<usize, Refusal> {
    let list = |value: &Value| value.as_array().cloned().unwrap_or_default();
    let member = json!("m".repeat(253));
    let operation = json!(format!("infra-operation-{}", "f".repeat(32)));
    let release = input["release"].clone();
    let nullable = |widest: Value| {
        if encoded_len(&widest) < encoded_len(&Value::Null) {
            Value::Null
        } else {
            widest
        }
    };
    let time = nullable(json!(u64::MAX));
    let count = nullable(json!(u64::from(u32::MAX)));
    let exit = nullable(json!(255));
    let scope = json!({"project": "p".repeat(4096), "environment": "e".repeat(63),
        "target": "t".repeat(63), "hash": "f".repeat(64)});
    let hooks = list(&input["hooks"]);
    let hook_rows: Vec<Value> = hooks
        .iter()
        .filter(|h| h["stage"] == "before_apply")
        .map(|h| {
            json!({"duration_ms":time,"exit":exit,"location":h["location"],"name":h["name"],
                "outcome":"succeeded","stage":"before_apply"})
        })
        .collect();
    let checks: Vec<Value> = hooks
        .iter()
        .filter(|h| h["stage"] == "health")
        .map(|h| json!({"duration_ms":time,"exit":exit,"name":h["name"],"outcome":"succeeded"}))
        .collect();
    let version = json!("v".repeat(26));
    let secrets: Vec<Value> = list(&input["secrets"])
        .iter()
        .map(|s| {
            json!({"keys":s["keys"],"outcome":"configured","prepared_version":version,
                "secret":s["secret"],"version":version})
        })
        .collect();
    let objects: Vec<Value> = list(&input["objects"])
        .iter()
        .map(|o| {
            json!({"kind":o["kind"],"name":o["name"],"namespace":o["namespace"],
                "outcome":"configured"})
        })
        .collect();
    let workloads: Vec<Value> = list(&input["workloads"])
        .iter()
        .map(|w| {
            json!({"available":count,"desired":count,"kind":w["kind"],"name":w["name"],
                "namespace":w["namespace"],"outcome":"not-ready","ready":count,"updated":count})
        })
        .collect();
    let names = |key: &str| vec![member.clone(); list(&input[key]).len()];
    let report = json!({"format_version":1,"scope":scope,"view":"release-rollback",
        "outcome":"succeeded","failure":"unsupported-version","detail":"incomplete-delivery",
        "completion_unknown":false,"cleanup_unknown":false,"truncated":false,
        "operations":[{"action":"release-rollback","cleanup_unknown":false,
            "completion_unknown":false,"created_ms":time,"failure":"unsupported-version",
            "operation":operation,"outcome":"succeeded"}],
        "store":{"operations":count,"limit":count,"releases":count,"release_limit":count,
            "hosts":{"member":member,"attempts":count,"limit":count},"warning":false},
        "recovery":{"choice":"operator-recovery","operation":operation,"subject":member},
        "application":input["application"],"release":release,"from":release,
        "settled":operation,
        "delivery_recheck":{"excluded":names("excluded"),"members":names("required"),
            "observed_ms":time,"outcome":"succeeded"},
        "hooks":hook_rows,"secrets":secrets,"objects":objects,
        "health":{"checks":checks,"observed_ms":time,"outcome":"succeeded",
            "undelivered_pods":[],"undelivered_truncated":false,"workloads":workloads},
        "evidence":{"applied":false,"healthy":false},"active":release,"rollback":release});
    let json = encoded_len(&report);
    let table: usize = report.as_object().map_or(0, |fields| {
        fields
            .iter()
            .map(|(key, value)| key.len() + 1 + encoded_len(value) + 1)
            .sum()
    });
    let price = json.max(table) + 1 + UNDELIVERED_BUDGET;
    if price > REPORT_LIMIT {
        return Err(Refusal::new(
            "bound",
            "report",
            format!(
                "the apply report of application {} could reach {price} bytes; the limit is {REPORT_LIMIT}; split the application's objects or Secrets and prepare a new release",
                input["application"].as_str().unwrap_or("")
            ),
        ));
    }
    Ok(price)
}

pub fn check_secret_header(declaration: &Value) -> Result<usize, Refusal> {
    let route = json!({"address": "a".repeat(253), "port": 65_535, "account": "u".repeat(32),
        "host_key_sha256": "f".repeat(64)});
    let destination = json!({"machine": "m".repeat(63), "member": "m".repeat(63),
        "role": "server", "route": route, "jump": route, "node_uid": "f".repeat(128)});
    let keys = declaration["keys"].as_array().cloned().unwrap_or_default();
    let header = json!({"protocol": "broil-k3s-release-secret", "version": 1,
        "action": "apply-secret", "request_id": "f".repeat(32), "project": "p".repeat(63),
        "environment": "e".repeat(63), "target": "t".repeat(63), "owner": "f".repeat(32),
        "operation": format!("infra-operation-{}", "f".repeat(32)), "attempt": "f".repeat(32),
        "destination": destination,
        "cluster": {"uid": "f".repeat(128), "ca_sha256": "f".repeat(64)},
        "resource": {"kind": "application-secret",
            "id": format!("application-secret-{}", "f".repeat(40)),
            "generation": "f".repeat(32), "uid": "f".repeat(36)},
        "application": declaration["application"], "namespace": declaration["namespace"],
        "secret": declaration["secret"], "keys": keys,
        "profile_sha256": "f".repeat(64), "script_sha256": "f".repeat(64),
        "selection_sha256": "f".repeat(64), "remaining_ms": 7_200_000,
        "slot_lengths": vec![1_048_576; keys.len()]});
    let size = encoded_len(&header);
    if size > SECRET_HEADER_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!(
                "Secret {}'s apply header is {size} bytes at its widest; the limit is {SECRET_HEADER_LIMIT}",
                declaration["secret"].as_str().unwrap_or("")
            ),
        ));
    }
    Ok(size)
}

pub fn step_payloads(
    recipe: &Value,
    record: &Value,
    objects: &[Value],
) -> Result<Vec<Vec<u8>>, Refusal> {
    let integrity = |detail: &str| Refusal::new("integrity", "release", detail.to_owned());
    if record::release_sha256(record) != recipe["release_sha256"].as_str().unwrap_or("") {
        return Err(integrity("the release record differs from the recipe's"));
    }
    let mut payloads = Vec::new();
    for chunk in recipe["chunks"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let first = chunk["first"].as_u64().unwrap_or(u64::MAX) as usize;
        let count = chunk["count"].as_u64().unwrap_or(0) as usize;
        let run = objects
            .get(first..first.saturating_add(count))
            .ok_or_else(|| integrity("a chunk names objects the release lacks"))?;
        let payload: Vec<u8> = run
            .iter()
            .flat_map(|o| o["document"].as_str().unwrap_or("").bytes())
            .collect();
        if chunk["sha256"].as_str() != Some(sha256_hex(&[&payload]).as_str()) {
            return Err(integrity(
                "a chunk's manifest bytes differ from the recipe's",
            ));
        }
        payloads.push(payload);
    }
    Ok(payloads)
}

pub fn status_reads(input: &Value) -> Value {
    let target = &input["target"];
    json!({
        "recipient": crate::k3s::members::acting_first_server(target, None),
        "participants": crate::k3s::members::participants(target),
        "orphaned_reason": if input["recipe"].is_null() { json!("no-apply") } else { Value::Null },
    })
}

pub fn recipe_sha256(recipe: &Value) -> String {
    labeled("broil-k3s-release-recipe-v1", recipe)
}

pub fn check_recipe(recipe: &Value) -> Result<(), Refusal> {
    let fields = recipe.as_object().ok_or_else(|| {
        Refusal::new(
            "integrity",
            "release",
            "the release recipe is not an object",
        )
    })?;
    if fields.len() != RECIPE_KEYS.len() || RECIPE_KEYS.iter().any(|key| !fields.contains_key(*key))
    {
        return Err(Refusal::new(
            "integrity",
            "release",
            "the release recipe does not hold exactly its fields",
        ));
    }
    let size = serde_json::to_vec(recipe)
        .expect("JSON values encode")
        .len();
    if size > RECIPE_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!("the release recipe is {size} bytes; the limit is {RECIPE_LIMIT}"),
        ));
    }
    Ok(())
}

pub const UNKNOWN_RUN_ACTIONS: [&str; 4] = [
    "release-deliver",
    "release-retain",
    "release-apply",
    "release-rollback",
];

pub fn unknown_run(input: &Value) -> Value {
    let projection = &input["projection"];
    let own = &input["failure"];
    let unnamed = projection["outcome"] == "unknown" && projection["failure"].is_null();
    let append = if input["ending"] == "controller"
        && unnamed
        && UNKNOWN_RUN_ACTIONS
            .iter()
            .any(|action| input["action"] == *action)
        && own.is_string()
    {
        own.clone()
    } else {
        Value::Null
    };
    let failure = if !projection["failure"].is_null() {
        projection["failure"].clone()
    } else {
        own.clone()
    };
    json!({"append": append, "failure": failure})
}

pub fn orphaned(input: &Value) -> Value {
    let failed = |read: &Value| matches!(read.as_str(), Some("unmade" | "failed" | "cancelled"));
    let reason = if input["recipe"] != true {
        "no-apply"
    } else if input["api"] != true || failed(&input["discover"]) {
        "unobserved"
    } else if input["kinds"] == "bound" {
        "kind-bound"
    } else {
        match input["observe"].as_str() {
            Some("read") => "",
            Some("truncated") => "object-bound",
            Some("bound") => "list-bound",
            _ => "unobserved",
        }
    };
    let complete = input["complete"] == true && !matches!(reason, "no-apply" | "unobserved");
    json!({
        "orphaned_reason": if reason.is_empty() { Value::Null } else { json!(reason) },
        "outcome": if complete { "complete" } else { "incomplete" },
    })
}
