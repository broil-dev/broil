// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::Refusal;
use serde_json::{Value, json};

fn bound_at<'a>(record: &'a Value, origins: &[&str]) -> Vec<&'a Value> {
    record["publications"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| {
            p["bound"] == true && p["origin"].as_str().is_some_and(|o| origins.contains(&o))
        })
        .collect()
}

pub fn artifact(request: &Value) -> Result<Value, Refusal> {
    let image = request["image"].as_str().unwrap_or("");
    let target = request["target"].as_str().unwrap_or("");
    let origins: Vec<&str> = request["origins"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let records: Vec<&Value> = request["records"]
        .as_array()
        .into_iter()
        .flatten()
        .collect();
    let selected = match request["explicit"].as_str() {
        Some(explicit) => {
            let record = records
                .iter()
                .find(|r| r["artifact"] == explicit)
                .ok_or_else(|| {
                    Refusal::new(
                        "configuration",
                        "artifact",
                        format!("{explicit} is not in the image record store; pass the ID of an existing record"),
                    )
                })?;
            if record["image"] != image {
                return Err(Refusal::new(
                    "integrity",
                    "artifact",
                    format!("{explicit} is not a record of image {image}"),
                ));
            }
            *record
        }
        None => records
            .iter()
            .filter(|r| r["image"] == image && !bound_at(r, &origins).is_empty())
            .max_by(|a, b| {
                (a["created_ms"].as_u64(), a["artifact"].as_str())
                    .cmp(&(b["created_ms"].as_u64(), b["artifact"].as_str()))
            })
            .ok_or_else(|| {
                Refusal::new(
                    "configuration",
                    "artifact",
                    format!(
                        "image {image} has no record published at an origin of target {target}; publish it or pass --artifacts {image}=<artifact-id>"
                    ),
                )
            })?,
    };
    let artifact = selected["artifact"].as_str().unwrap_or("");
    let publications = bound_at(selected, &origins);
    let publication = match publications.as_slice() {
        [one] => *one,
        [] => {
            return Err(Refusal::new(
                "configuration",
                "artifact",
                format!(
                    "{artifact} has no bound publication at an origin of target {target}; publish it or pass --artifacts with a record bound at one"
                ),
            ));
        }
        many => {
            return Err(Refusal::new(
                "configuration",
                "artifact",
                format!(
                    "{artifact} is bound at {} origins of target {target}; pass --artifacts with a record bound at one",
                    many.len()
                ),
            ));
        }
    };
    let repository = publication["repository"].as_str().unwrap_or("");
    let root = publication["root"].as_str().unwrap_or("");
    Ok(json!({
        "artifact": artifact,
        "image": image,
        "origin": publication["origin"],
        "repository": repository,
        "root": root,
        "reference": format!("{repository}@{root}"),
        "managed": publication["origin"] == request["managed_origin"],
        "platforms": selected.get("platforms").cloned().unwrap_or_else(|| json!([])),
    }))
}
