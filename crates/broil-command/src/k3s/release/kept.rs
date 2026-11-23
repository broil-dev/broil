// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::{Value, json};
use std::collections::BTreeSet;

fn list<'a>(value: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    value[key].as_array().into_iter().flatten()
}

fn newest<'a>(operations: impl Iterator<Item = &'a Value>) -> Option<&'a Value> {
    operations.max_by(|a, b| {
        (a["created_ms"].as_u64(), a["operation"].as_str())
            .cmp(&(b["created_ms"].as_u64(), b["operation"].as_str()))
    })
}

pub fn derive(application: &str, history: &Value) -> Value {
    let operations: Vec<&Value> = list(history, "operations")
        .filter(|op| {
            op["application"] == application
                && matches!(
                    op["action"].as_str(),
                    Some("release-apply" | "release-rollback")
                )
        })
        .collect();
    let releases: Vec<&Value> = list(history, "releases")
        .filter(|r| r["application"] == application)
        .collect();
    let active = newest(
        operations
            .iter()
            .copied()
            .filter(|op| op["changed"] == true),
    )
    .and_then(|op| op["release"].as_str());
    let rollback = newest(
        operations
            .iter()
            .copied()
            .filter(|op| op["healthy"] == true && op["release"].as_str() != active),
    )
    .and_then(|op| op["release"].as_str());
    let changed: BTreeSet<&str> = operations
        .iter()
        .filter(|op| op["changed"] == true)
        .filter_map(|op| op["release"].as_str())
        .collect();
    let floor = active.and_then(|id| {
        releases
            .iter()
            .find(|r| r["release"] == id)
            .and_then(|r| r["created_ms"].as_u64())
    });
    let mut others: Vec<&Value> = releases
        .iter()
        .copied()
        .filter(|r| {
            let id = r["release"].as_str().unwrap_or("");
            Some(id) != active
                && Some(id) != rollback
                && match active {
                    None => true,
                    Some(_) => r["created_ms"].as_u64() > floor && !changed.contains(id),
                }
        })
        .collect();
    others.sort_by(|a, b| {
        (b["created_ms"].as_u64(), b["release"].as_str())
            .cmp(&(a["created_ms"].as_u64(), a["release"].as_str()))
    });
    let kept: Vec<&str> = active
        .into_iter()
        .chain(rollback)
        .chain(others.iter().filter_map(|r| r["release"].as_str()))
        .collect();
    json!({"active": active, "rollback": rollback, "kept": kept})
}

pub fn released(application: &str, history: &Value) -> Value {
    let applications: BTreeSet<&str> = list(history, "releases")
        .filter_map(|r| r["application"].as_str())
        .collect();
    let mut kept_releases = BTreeSet::new();
    for other in applications {
        for id in derive(other, history)["kept"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if let Some(id) = id.as_str() {
                kept_releases.insert(id.to_owned());
            }
        }
    }
    let images_of = |id: &str| -> Vec<(String, String)> {
        history["images"][id]
            .as_array()
            .into_iter()
            .flatten()
            .map(|i| {
                (
                    i["image"].as_str().unwrap_or("").to_owned(),
                    i["reference"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect()
    };
    let kept_references: BTreeSet<String> = kept_releases
        .iter()
        .flat_map(|id| images_of(id).into_iter().map(|(_, reference)| reference))
        .collect();
    let mut own: Vec<&Value> = list(history, "releases")
        .filter(|r| r["application"] == application)
        .filter(|r| !kept_releases.contains(r["release"].as_str().unwrap_or("")))
        .collect();
    own.sort_by(|a, b| {
        (a["created_ms"].as_u64(), a["release"].as_str())
            .cmp(&(b["created_ms"].as_u64(), b["release"].as_str()))
    });
    let mut result = Vec::new();
    for release in own {
        let id = release["release"].as_str().unwrap_or("");
        let mut names: Vec<String> = Vec::new();
        for (name, reference) in images_of(id) {
            if !kept_references.contains(&reference) && !names.contains(&name) {
                names.push(name);
            }
        }
        if !names.is_empty() {
            result.push(json!({"release": id, "images": names}));
        }
    }
    Value::Array(result)
}
