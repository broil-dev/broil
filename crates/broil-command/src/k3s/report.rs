// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::release::Refusal;
use serde_json::Value;

pub const REPORT_LIMIT: usize = 1_048_576;

const ENVELOPE: [&str; 12] = [
    "format_version",
    "scope",
    "view",
    "outcome",
    "failure",
    "detail",
    "completion_unknown",
    "cleanup_unknown",
    "truncated",
    "operations",
    "recovery",
    "store",
];

const SCOPE: [&str; 4] = ["environment", "hash", "project", "target"];

const STORE: [&str; 6] = [
    "operations",
    "limit",
    "releases",
    "release_limit",
    "hosts",
    "warning",
];

const PREPARE: [&str; 10] = [
    "application",
    "release",
    "existing",
    "created_ms",
    "images",
    "manifests",
    "secrets",
    "hooks",
    "policy",
    "target",
];

const APPLY: [&str; 11] = [
    "application",
    "release",
    "settled",
    "delivery_recheck",
    "hooks",
    "secrets",
    "objects",
    "health",
    "evidence",
    "active",
    "rollback",
];

const READS: [&str; 5] = [
    "release-list",
    "release-status",
    "release-show",
    "delivery-report",
    "delivery-check",
];

const LIFECYCLE_OUTCOMES: [&str; 4] = ["succeeded", "failed", "cancelled", "unknown"];
const READ_OUTCOMES: [&str; 4] = ["complete", "incomplete", "refused", "cancelled"];
const LIFECYCLE_CHOICES: [&str; 7] = [
    "none",
    "resume",
    "rerun",
    "deliver",
    "rollback",
    "approve",
    "operator-recovery",
];
const READ_CHOICES: [&str; 3] = ["none", "create", "operator-recovery"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Table,
}

fn fields(view: &str) -> Option<(Vec<&'static str>, &'static [&'static str])> {
    let required: Vec<&'static str> = match view {
        "release-prepare" => PREPARE.to_vec(),
        "release-apply" => APPLY.to_vec(),
        "release-rollback" => {
            let mut all = APPLY.to_vec();
            all.push("from");
            all
        }
        "release-show" => {
            let mut all = PREPARE.to_vec();
            all.extend(["role", "evidence_records", "applies", "history"]);
            all
        }
        "release-deploy" => vec![
            "application",
            "release",
            "stages",
            "evidence",
            "active",
            "rollback",
        ],
        "release-retain" => vec!["application", "keep", "released"],
        "release-status" => vec![
            "application",
            "active",
            "rollback",
            "observed_ms",
            "excluded",
            "nodes",
            "workloads",
            "orphaned",
            "orphaned_reason",
        ],
        "release-list" => vec!["application", "limit", "releases"],
        "release-deliver" => vec![
            "application",
            "release",
            "writer",
            "evidence",
            "excluded",
            "nodes",
            "origin",
        ],
        "delivery-report" => vec!["release", "deliveries"],
        "delivery-check" => vec!["writer", "observed_ms", "members"],
        "node-drain" => vec![
            "member",
            "cordoned",
            "unreachable",
            "evicted",
            "blocked",
            "writer_move",
        ],
        "node-uncordon" => vec!["member", "cordoned"],
        "node-remove" => vec!["member", "checks", "removed"],
        "node-replace" => vec![
            "member",
            "previous_machine",
            "machine",
            "same_machine",
            "joined",
            "replica",
            "rebound",
        ],
        "operation-prune" => vec!["policy", "removed", "checkpoint", "hosts"],
        _ => return None,
    };
    let optional: &'static [&'static str] = if view == "release-status" {
        &["release"]
    } else {
        &[]
    };
    Some((required, optional))
}

fn refuse(detail: impl Into<String>) -> Refusal {
    Refusal::new("bound", "report", detail)
}

fn exact(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.len() == keys.len() && keys.iter().all(|k| map.contains_key(*k)))
}

fn one_of(value: &Value, set: &[&str]) -> bool {
    value.as_str().is_some_and(|s| set.contains(&s))
}

pub fn encode(report: &Value, format: Format) -> Result<Vec<u8>, Refusal> {
    let map = report
        .as_object()
        .ok_or_else(|| refuse("a report is a JSON object"))?;
    let view = report["view"].as_str().unwrap_or("");
    let (required, optional) =
        fields(view).ok_or_else(|| refuse(format!("{view:?} is not a known view")))?;
    let closed = ENVELOPE
        .iter()
        .chain(&required)
        .all(|k| map.contains_key(*k))
        && map.keys().all(|k| {
            ENVELOPE.contains(&k.as_str())
                || required.contains(&k.as_str())
                || optional.contains(&k.as_str())
        });
    if !closed {
        return Err(refuse(format!(
            "the {view} report holds exactly its view's fields"
        )));
    }
    let read = READS.contains(&view);
    let (outcomes, choices, recovery): (&[&str], &[&str], &[&str]) = if read {
        (&READ_OUTCOMES, &READ_CHOICES, &["choice", "reason"])
    } else {
        (
            &LIFECYCLE_OUTCOMES,
            &LIFECYCLE_CHOICES,
            &["choice", "operation", "subject"],
        )
    };
    let envelope = report["format_version"] == 1
        && exact(&report["scope"], &SCOPE)
        && exact(&report["store"], &STORE)
        && exact(&report["store"]["hosts"], &["member", "attempts", "limit"])
        && one_of(&report["outcome"], outcomes)
        && exact(&report["recovery"], recovery)
        && one_of(&report["recovery"]["choice"], choices)
        && report["operations"].is_array();
    if !envelope {
        return Err(refuse(format!("the {view} report's envelope is invalid")));
    }
    let mut bytes = Vec::new();
    match format {
        Format::Json => {
            bytes = serde_json::to_vec(report).map_err(|e| refuse(e.to_string()))?;
            bytes.push(b'\n');
        }
        Format::Table => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            for key in keys {
                bytes.extend_from_slice(key.as_bytes());
                bytes.push(b'\t');
                serde_json::to_writer(&mut bytes, &map[key]).map_err(|e| refuse(e.to_string()))?;
                bytes.push(b'\n');
                if bytes.len() > REPORT_LIMIT {
                    break;
                }
            }
        }
    }
    if bytes.len() > REPORT_LIMIT {
        return Err(refuse(format!(
            "the {view} report needs {} bytes; the limit is {REPORT_LIMIT}",
            bytes.len()
        )));
    }
    Ok(bytes)
}
