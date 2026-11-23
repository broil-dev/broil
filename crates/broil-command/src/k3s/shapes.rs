// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::release::{Refusal, labeled};
use serde_json::Value;

pub fn earlier(family: &str, payload: &Value) -> Value {
    let mut earlier = payload.clone();
    let remove = |value: &mut Value, keys: &[&str]| {
        if let Some(fields) = value.as_object_mut() {
            for key in keys {
                fields.remove(*key);
            }
        }
    };
    match family {
        "acquire-writer" => remove(&mut earlier, &["excluded", "sequence", "reserve"]),
        "reserve-owner" => remove(&mut earlier, &["excluded"]),
        "seal-writer" | "retire-writer" => remove(&mut earlier, &["members", "excluded"]),
        "observe-membership" => remove(&mut earlier, &["removed"]),
        "network" | "ingress" | "cert-manager" => {
            remove(&mut earlier, &["original_recipe_sha256"]);
        }
        "registry-storage" | "registry-token" => remove(&mut earlier, &["member"]),
        "registry-service" => {
            remove(&mut earlier, &["member"]);
            remove(&mut earlier["recipe"]["origins"], &["images"]);
        }
        "node-registry" => {
            if let Some(entries) = earlier["recipe"]["registries"].as_array_mut() {
                for entry in entries {
                    remove(entry, &["managed"]);
                }
            }
        }
        _ => {}
    }
    earlier
}

pub fn candidates(schema: &Value, recorded: bool, family: &str, payload: &Value) -> Vec<Value> {
    if recorded && schema.as_u64() == Some(1) {
        vec![earlier(family, payload), payload.clone()]
    } else {
        vec![payload.clone()]
    }
}

pub fn verify(input: &Value) -> Result<Value, Refusal> {
    if input["request"]["fingerprints"] != input["current"] {
        return Err(Refusal::new(
            "ownership",
            "drift",
            "the operation was recorded under another profile; finish it with the broil that recorded it",
        ));
    }
    candidates(
        &input["request"]["schema"],
        input["recorded"] == true,
        input["family"].as_str().unwrap_or(""),
        &input["payload"],
    )
    .into_iter()
    .find(|shape| input["payload_sha256"] == labeled("broil-infra-step-v1", shape).as_str())
    .ok_or_else(|| {
        Refusal::new(
            "integrity",
            "payload",
            "the step's payload hash does not match its operation's payload shape",
        )
    })
}
