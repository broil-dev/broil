// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, Snapshot, require};
use serde_json::{Value, json};
use std::io::Write;

pub(super) fn readiness() -> Value {
    json!({"api":"unobserved","quorum":"unobserved","nodes":"unobserved",
        "services":"unobserved","storage":"unobserved","publication":"unobserved"})
}

fn clean_refusal(snapshot: &Snapshot, attempt: &Value) -> bool {
    let action = snapshot.request["action"].as_str().unwrap_or("");
    if !matches!(action, "prepare-hosts" | "create-server") {
        return false;
    }
    let mut refused = false;
    let mut inspected = false;
    for step in snapshot
        .steps
        .iter()
        .filter(|s| s["attempt"] == attempt["attempt"])
    {
        let observation = match (action, step["action"].as_str()) {
            ("prepare-hosts", Some("bootstrap:inspect-host")) => "bootstrap-host",
            (
                "create-server",
                Some("lifecycle:inspect-installation" | "lifecycle:inspect-owned-server"),
            ) => "lifecycle-installation",
            _ => return false,
        };
        let events: Vec<_> = snapshot
            .observations
            .iter()
            .filter(|o| {
                o["attempt"] == step["attempt"]
                    && o["step"] == step["step"]
                    && o["dispatch"] == step["dispatch"]
            })
            .collect();
        if !events
            .iter()
            .any(|o| o["source"]["kind"] == "receiver" && o["event"]["type"] == observation)
            || !events.iter().any(|o| {
                o["event"]["type"] == "dispatch"
                    && o["event"]["transport"]["exit"] == 0
                    && o["event"]["transport"]["signal"].is_null()
                    && o["event"]["transport"]["input_released"] == true
                    && o["event"]["transport"]["staging_cleanup"] == "clean"
            })
        {
            return false;
        }
        if events.iter().any(|o| {
            let event = &o["event"];
            (event["type"] == "dispatch"
                && (event["transport"]["exit"] != 0
                    || !event["transport"]["signal"].is_null()
                    || event["transport"]["input_released"] != true
                    || event["transport"]["staging_cleanup"] != "clean"))
                || (event["type"] == "failure"
                    && (event["completion_unknown"] != false || event["cleanup_unknown"] != false))
        }) {
            return false;
        }
        inspected = true;
        refused |= events.iter().any(|o| {
            o["event"]["type"] == "failure"
                && o["event"]["outcome"] == "failed"
                && o["event"]["completion_unknown"] == false
                && o["event"]["cleanup_unknown"] == false
                && if action == "prepare-hosts" {
                    o["event"]["failure"] == "readiness"
                } else {
                    o["event"]["failure"] == "ownership"
                        && events.iter().any(|o| {
                            o["event"]["type"] == "lifecycle-installation"
                                && o["event"]["class"] == "foreign"
                        })
                }
        });
    }
    inspected && refused
}

pub(super) fn clean_refused(snapshot: &Snapshot) -> bool {
    !snapshot.attempts.is_empty() && snapshot.attempts.iter().all(|a| clean_refusal(snapshot, a))
}

pub(super) fn summary(snapshot: &Snapshot) -> Value {
    let mut outcome = "succeeded";
    let mut failure = Value::Null;
    let mut unknown = snapshot.attempts.iter().any(|attempt| {
        !clean_refusal(snapshot, attempt)
            && attempt["steps"].as_array().is_none_or(|ids| {
                ids.iter().any(|id| {
                    !snapshot
                        .steps
                        .iter()
                        .any(|step| step["step"] == *id && step["attempt"] == attempt["attempt"])
                })
            })
    });
    let mut cleanup = false;
    let release = super::super::release::UNKNOWN_RUN_ACTIONS
        .iter()
        .any(|action| snapshot.request["action"] == *action);
    let mut dispatch_failure = Value::Null;
    for step in &snapshot.steps {
        let mut receipt = None;
        let mut undispatched = None;
        let mut dispatched_failure = None;
        let readonly = matches!(
            step["action"].as_str(),
            Some(
                "bootstrap:inspect-host"
                    | "bootstrap:inspect-generation"
                    | "lifecycle:inspect-installation"
                    | "lifecycle:observe-server"
                    | "lifecycle:inspect-owned-server"
                    | "lifecycle:inspect-join"
                    | "lifecycle:observe-membership"
                    | "lifecycle:observe-join"
                    | "lifecycle:inspect-agent"
                    | "lifecycle:observe-agent-membership"
                    | "lifecycle:observe-agent"
                    | "lifecycle:network-inspect-host"
                    | "lifecycle:network-inspect-objects"
                    | "lifecycle:ingress-inspect-host"
                    | "lifecycle:ingress-inspect-objects"
                    | "lifecycle:cert-manager-inspect-host"
                    | "lifecycle:cert-manager-inspect-objects"
                    | "lifecycle:issuer-inspect-objects"
                    | "lifecycle:certificate-inspect-objects"
                    | "lifecycle:registry-storage-inspect-storage"
                    | "lifecycle:registry-storage-inspect-objects"
                    | "lifecycle:registry-service-inspect-host"
                    | "lifecycle:registry-service-inspect-objects"
                    | "lifecycle:registry-endpoint-inspect-objects"
                    | "lifecycle:registry-auth-inspect-objects"
                    | "lifecycle:registry-token-inspect-host"
                    | "lifecycle:registry-token-inspect-objects"
                    | "lifecycle:registry-replication-inspect-replication"
                    | "lifecycle:registry-replication-inspect-objects"
                    | "lifecycle:delivery-inspect-images"
                    | "lifecycle:delivery-check-closure"
                    | "lifecycle:delivery-read-origin-log"
                    | "lifecycle:node-observe-node"
                    | "lifecycle:node-observe-drain"
                    | "lifecycle:release-discover-kinds"
                    | "lifecycle:release-inspect-workloads"
                    | "lifecycle:release-observe-release"
                    | "hook:before_apply"
                    | "hook:health"
                    | "inspect"
            )
        );
        let mut inspected = false;
        let mut failed_read = false;
        for observation in &snapshot.observations {
            if observation["attempt"] != step["attempt"]
                || observation["step"] != step["step"]
                || observation["dispatch"] != step["dispatch"]
            {
                continue;
            }
            let event = &observation["event"];
            if matches!(
                event["type"].as_str(),
                Some(
                    "bootstrap-host"
                        | "bootstrap-generation"
                        | "lifecycle-installation"
                        | "server-membership"
                        | "agent-membership"
                        | "network-observation"
                        | "ingress-observation"
                        | "cert-manager-observation"
                        | "issuer-observation"
                        | "certificate-observation"
                        | "registry-storage-observation"
                        | "registry-service-observation"
                        | "registry-endpoint-observation"
                        | "registry-auth-observation"
                        | "registry-token-observation"
                        | "replication-observation"
                        | "delivery-observation"
                        | "node-observation"
                        | "member-observation"
                        | "release-observation"
                        | "release-hook"
                        | "inspection"
                )
            ) {
                inspected = true;
            }
            if event["type"] == "receiver" {
                let terminal = &event["receipt"];
                if terminal["binding"]["dispatch"] == step["dispatch"]
                    && terminal["action"] == step["action"]
                    && terminal["payload_sha256"] == step["payload_sha256"]
                {
                    receipt = Some(terminal);
                }
            }
            if matches!(event["type"].as_str(), Some("dispatch" | "receiver")) {
                let transport = &event["transport"];
                cleanup |=
                    transport["input_released"] != true || transport["staging_cleanup"] != "clean";
                if event["type"] == "dispatch" && transport["dispatch"] == "none" {
                    undispatched = Some(event);
                }
                if event["type"] == "dispatch" && !event["failure"].is_null() {
                    dispatched_failure.get_or_insert(&event["failure"]);
                }
            }
            if event["type"] == "failure" {
                failed_read |= readonly && event["outcome"] == "failed";
                unknown |= event["completion_unknown"] == true;
                cleanup |= event["cleanup_unknown"] == true;
                if outcome == "succeeded" && event["outcome"] == "failed" {
                    outcome = "failed";
                }
                if failure.is_null() {
                    failure = event["failure"].clone();
                }
            }
        }
        match receipt {
            Some(receipt)
                if receipt["outcome"] == "succeeded" && receipt["effect"] == "complete" => {}
            Some(receipt)
                if receipt["effect"] == "absent"
                    || receipt["effect"] == "partial"
                        && receipt["outcome"] == "failed"
                        && (step["action"]
                            .as_str()
                            .is_some_and(|a| a.starts_with("lifecycle:delivery-"))
                            || receipt["action"] == "lifecycle:node-evict"
                            || receipt["action"] == "lifecycle:release-apply-objects") =>
            {
                if outcome == "succeeded" {
                    outcome = if receipt["outcome"] == "cancelled" {
                        "cancelled"
                    } else {
                        "failed"
                    };
                    failure = receipt["failure"].clone();
                }
            }
            Some(receipt) => {
                unknown = true;
                if release && failure.is_null() {
                    failure = receipt["failure"].clone();
                }
                if dispatch_failure.is_null() {
                    dispatch_failure = dispatched_failure.cloned().unwrap_or(Value::Null);
                }
            }
            None if readonly && (inspected || failed_read) => {}
            None => match undispatched {
                Some(event)
                    if event["outcome"] == "succeeded"
                        && event["failure"].is_null()
                        && event["transport"] == super::provenance::undispatched_transport() => {}
                Some(event) if event["outcome"] == "failed" || event["outcome"] == "cancelled" => {
                    if outcome == "succeeded" {
                        outcome = if event["outcome"] == "cancelled" {
                            "cancelled"
                        } else {
                            "failed"
                        };
                        failure = event["failure"].clone();
                    }
                }
                _ => {
                    unknown = true;
                    if dispatch_failure.is_null() {
                        dispatch_failure = dispatched_failure.cloned().unwrap_or(Value::Null);
                    }
                }
            },
        }
    }
    if snapshot
        .observations
        .iter()
        .any(|o| o["event"]["type"] == "release-settlement")
    {
        unknown = false;
        if outcome == "succeeded" {
            outcome = "failed";
        }
    }
    if unknown || cleanup {
        outcome = "unknown";
    }
    if release && outcome == "unknown" && failure.is_null() {
        failure = if dispatch_failure.is_null() {
            snapshot
                .observations
                .iter()
                .find(|o| o["step"].is_null() && o["event"]["type"] == "failure")
                .map_or(Value::Null, |o| o["event"]["failure"].clone())
        } else {
            dispatch_failure
        };
    }
    json!({"operation":snapshot.request["operation"],"created_ms":snapshot.request["created_ms"],"action":snapshot.request["action"],
        "outcome":outcome,"failure":failure,"completion_unknown":unknown,"cleanup_unknown":cleanup})
}

fn ingress_services(snapshot: &Snapshot) -> Value {
    let latest = |member: &Value| {
        snapshot
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == "ingress-observation" && o["event"]["member"] == *member
            })
            .map(|o| &o["event"])
    };
    let Some(objects) = latest(&Value::Null) else {
        return json!("not-ready");
    };
    let entries = snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "ingress-recipe")
        .and_then(|o| o["event"]["recipe"]["ingress_members"].as_array());
    let images = entries
        .zip(snapshot.request["members"].as_array())
        .is_some_and(|(entries, members)| {
            members
                .iter()
                .filter(|m| entries.iter().any(|e| e["machine"] == m["machine"]))
                .all(|m| {
                    latest(m).is_some_and(|e| {
                        ["image", "lb_image", "listeners", "forwarding"]
                            .iter()
                            .all(|key| e["hosts"][*key]["state"] == "ready")
                    })
                })
        });
    json!(if objects["services"] == "unobserved" && images {
        "unobserved"
    } else {
        "not-ready"
    })
}

fn cert_manager_services(snapshot: &Snapshot) -> Value {
    let latest = |member: &Value| {
        snapshot
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == "cert-manager-observation"
                    && o["event"]["member"] == *member
                    && (!member.is_null() || !o["event"]["services"].is_null())
            })
            .map(|o| &o["event"])
    };
    let images = snapshot.request["members"]
        .as_array()
        .is_some_and(|members| {
            members
                .iter()
                .all(|m| latest(m).is_some_and(|e| e["hosts"]["images"]["state"] == "ready"))
        });
    json!(
        if latest(&Value::Null).is_some_and(|e| e["services"] == "unobserved") && images {
            "unobserved"
        } else {
            "not-ready"
        }
    )
}

fn secret_services(snapshot: &Snapshot, kind: &str) -> Value {
    let latest = snapshot
        .observations
        .iter()
        .rev()
        .find(|o| o["event"]["type"] == kind && !o["event"]["services"].is_null());
    json!(
        if latest.is_some_and(|o| o["event"]["services"] == "unobserved")
            && !snapshot
                .observations
                .iter()
                .any(|o| { o["event"]["type"] == "failure" && o["event"]["outcome"] == "failed" })
        {
            "unobserved"
        } else {
            "not-ready"
        }
    )
}

pub(super) fn token_readiness(snapshot: &Snapshot) -> (Value, Value) {
    let latest = snapshot.observations.iter().rev().find(|o| {
        o["event"]["type"] == "registry-token-observation" && !o["event"]["objects"].is_null()
    });
    let failed = snapshot
        .observations
        .iter()
        .any(|o| o["event"]["type"] == "failure");
    let values = super::registry_service::recipe_of("registry-token", snapshot)
        .and_then(|recipe| super::registry_token::resumed(snapshot, recipe))
        .unwrap_or(Value::Null);
    let services = match latest {
        Some(read)
            if !failed
                && read["event"]["registry"]["configuration_sha256"] == values["configuration"] =>
        {
            let probed = super::registry_token::probed(&values["principals"]);
            super::registry_token::readiness(&read["event"], probed)
        }
        _ => "not-ready",
    };
    let publication = super::registry_token::publication(services, &values["principals"]);
    (json!(services), json!(publication))
}

fn certificate_services(snapshot: &Snapshot) -> Value {
    let latest = snapshot.observations.iter().rev().find(|o| {
        o["event"]["type"] == "certificate-observation" && !o["event"]["services"].is_null()
    });
    json!(if latest.is_some_and(|o| o["event"]["services"] == "ready")
        && !snapshot
            .observations
            .iter()
            .any(|o| o["event"]["type"] == "failure")
    {
        "ready"
    } else {
        "not-ready"
    })
}

fn replication_readiness(snapshot: &Snapshot) -> (Value, Value) {
    let kind = super::registry_replication::OBSERVATION;
    let api = snapshot
        .observations
        .iter()
        .rev()
        .find(|o| o["event"]["type"] == kind && o["event"]["member"].is_null());
    let hosts: Option<Vec<Value>> = snapshot.request["members"].as_array().and_then(|members| {
        members
            .iter()
            .map(|m| {
                snapshot
                    .observations
                    .iter()
                    .rev()
                    .find(|o| {
                        o["event"]["type"] == kind
                            && o["event"]["member"]["machine"] == m["machine"]
                    })
                    .map(|o| o["event"].clone())
            })
            .collect()
    });
    let (Some(api), Some(hosts)) = (api, hosts) else {
        return (json!("unobserved"), json!("unobserved"));
    };
    let (storage, services) = super::registry_replication::readiness(&hosts, &api["event"]);
    let failed = snapshot
        .observations
        .iter()
        .any(|o| o["event"]["type"] == "failure");
    let state = |value: &str| json!(if failed { "not-ready" } else { value });
    (state(storage), state(services))
}

fn registry_readiness(snapshot: &Snapshot, family: &str) -> (Value, Value) {
    let latest = |host: bool| {
        snapshot.observations.iter().rev().find(|o| {
            o["event"]["type"] == format!("{family}-observation")
                && o["event"]["member"].is_null() != host
        })
    };
    let (Some(host), Some(api)) = (latest(true), latest(false)) else {
        return (json!("unobserved"), json!("unobserved"));
    };
    let hosts = || -> Option<Vec<Value>> {
        let members = snapshot.request["members"].as_array()?;
        members
            .iter()
            .map(|m| {
                snapshot
                    .observations
                    .iter()
                    .rev()
                    .find(|o| {
                        o["event"]["type"] == format!("{family}-observation")
                            && o["event"]["member"]["machine"] == m["machine"]
                    })
                    .map(|o| o["event"].clone())
            })
            .collect()
    };
    let version2 = api["event"].get("nodes").is_some();
    let (services, storage) = if family == "registry-service" && version2 {
        let Some(hosts) = hosts() else {
            return (json!("unobserved"), json!("unobserved"));
        };
        (
            super::registry_service::readiness(&hosts, &api["event"]),
            "unobserved",
        )
    } else if family == "registry-service" {
        super::registry_service::readiness_v1(&host["event"], &api["event"])
    } else if version2 {
        let Some(hosts) = hosts() else {
            return (json!("unobserved"), json!("unobserved"));
        };
        let storage: Vec<Value> = hosts.into_iter().map(|h| h["storage"].clone()).collect();
        (
            "unobserved",
            super::registry_storage::readiness(&storage, &api["event"]["nodes"]),
        )
    } else {
        (
            "unobserved",
            super::registry_storage::readiness_v1(&host["event"]["storage"], &api["event"]),
        )
    };
    let failed = snapshot
        .observations
        .iter()
        .any(|o| o["event"]["type"] == "failure");
    let state = |value: &str| {
        json!(if value == "ready" && failed {
            "not-ready"
        } else {
            value
        })
    };
    (state(services), state(storage))
}

fn endpoint_services(snapshot: &Snapshot) -> Value {
    let Some(latest) = snapshot
        .observations
        .iter()
        .rev()
        .find(|o| o["event"]["type"] == "registry-endpoint-observation")
    else {
        return json!("unobserved");
    };
    let failed = snapshot
        .observations
        .iter()
        .any(|o| o["event"]["type"] == "failure");
    json!(if failed {
        "not-ready"
    } else {
        super::registry_endpoint::readiness(&latest["event"])
    })
}

pub(in crate::k3s) fn listed(
    scope: &Value,
    snapshots: &[Snapshot],
    unlisted: &[Value],
) -> Result<Value> {
    let mut value = report(scope, "list", snapshots)?;
    if unlisted.is_empty() {
        return Ok(value);
    }
    let rows = value["operations"].as_array().cloned().unwrap_or_default();
    let all: Vec<&Value> = rows.iter().chain(unlisted).collect();
    value["truncated"] = json!(true);
    value["completion_unknown"] = json!(all.iter().any(|v| v["completion_unknown"] == true));
    value["cleanup_unknown"] = json!(all.iter().any(|v| v["cleanup_unknown"] == true));
    value["outcome"] = json!(if all.iter().any(|v| v["outcome"] == "unknown") {
        "unknown"
    } else if all.iter().any(|v| v["outcome"] == "failed") {
        "failed"
    } else {
        "succeeded"
    });
    Ok(value)
}

pub(in crate::k3s) fn report(scope: &Value, view: &str, snapshots: &[Snapshot]) -> Result<Value> {
    let mut value = json!({"format_version":1,"scope":scope,"view":view,"operation":null,"attempt":null,"action":null,
        "request":null,"attempts":[],"steps":[],"observations":[],"operations":[],"members":[],"resources":[],"readiness":readiness(),
        "outcome":null,"failure":null,"completion_unknown":false,"cleanup_unknown":false,"truncated":false,
        "recovery":{"choice":"none","proposal":null}});
    if view == "list" {
        let mut summaries: Vec<Value> = snapshots.iter().map(summary).collect();
        summaries.sort_by(|a, b| {
            b["created_ms"]
                .as_u64()
                .cmp(&a["created_ms"].as_u64())
                .then_with(|| a["operation"].as_str().cmp(&b["operation"].as_str()))
        });
        value["truncated"] = json!(summaries.len() > 100);
        value["completion_unknown"] =
            json!(summaries.iter().any(|v| v["completion_unknown"] == true));
        value["cleanup_unknown"] = json!(summaries.iter().any(|v| v["cleanup_unknown"] == true));
        if !summaries.is_empty() {
            value["outcome"] = json!(if summaries.iter().any(|v| v["outcome"] == "unknown") {
                "unknown"
            } else if summaries.iter().any(|v| v["outcome"] == "failed") {
                "failed"
            } else {
                "succeeded"
            });
        }
        summaries.truncate(100);
        value["operations"] = json!(summaries);
    } else {
        require(snapshots.len() == 1, Failure::Readiness)?;
        let snapshot = &snapshots[0];
        let current = summary(snapshot);
        for key in [
            "operation",
            "action",
            "outcome",
            "failure",
            "completion_unknown",
            "cleanup_unknown",
        ] {
            value[key] = current[key].clone();
        }
        value["attempt"] = snapshot
            .attempts
            .last()
            .map_or(Value::Null, |a| a["attempt"].clone());
        value["request"] = snapshot.request.clone();
        value["attempts"] = json!(snapshot.attempts);
        value["steps"] = json!(snapshot.steps);
        value["observations"] = json!(snapshot.observations);
        value["members"] = snapshot.request["members"].clone();
        value["resources"] = snapshot.request["resources"].clone();
        for observation in &snapshot.observations {
            let event = &observation["event"];
            if event["type"] == "network-observation" && event["member"].is_null() {
                value["readiness"]["services"] = event["services"].clone();
                value["readiness"]["storage"] = event["storage"].clone();
            }
            if event["type"] == "recovery" {
                value["recovery"] = json!({"choice":event["choice"],"proposal":event["proposal"]});
            }
        }
        if snapshot.request["action"] == "reconcile-ingress" {
            value["readiness"]["services"] = ingress_services(snapshot);
        }
        if snapshot.request["action"] == "reconcile-cert-manager" {
            value["readiness"]["services"] = cert_manager_services(snapshot);
        }
        if snapshot.request["action"] == "reconcile-issuer" {
            value["readiness"]["services"] = secret_services(snapshot, "issuer-observation");
        }
        if snapshot.request["action"] == "reconcile-registry-auth" {
            value["readiness"]["services"] = secret_services(snapshot, "registry-auth-observation");
            value["readiness"]["publication"] = json!("not-ready");
        }
        if snapshot.request["action"] == "reconcile-certificate" {
            value["readiness"]["services"] = certificate_services(snapshot);
        }
        if snapshot.request["action"] == "reconcile-registry-token" {
            let (services, publication) = token_readiness(snapshot);
            value["readiness"]["services"] = services;
            value["readiness"]["publication"] = publication;
        }
        if snapshot.request["action"] == "reconcile-registry-replication" {
            let (storage, services) = replication_readiness(snapshot);
            value["readiness"]["storage"] = storage;
            value["readiness"]["services"] = services;
            value["readiness"]["publication"] = json!("not-ready");
        }
        if super::node::carries(&snapshot.request["action"]) {
            let (quorum, nodes) = super::node::readiness(snapshot, &value["outcome"]);
            value["readiness"]["api"] = quorum.clone();
            value["readiness"]["quorum"] = quorum;
            value["readiness"]["nodes"] = nodes;
        }
        if snapshot.request["action"] == "reconcile-registry-endpoint" {
            value["readiness"]["services"] = endpoint_services(snapshot);
            value["readiness"]["publication"] = json!("not-ready");
        } else if let Some(family) = snapshot.request["action"]
            .as_str()
            .and_then(|action| action.strip_prefix("reconcile-"))
            .filter(|family| matches!(*family, "registry-storage" | "registry-service"))
        {
            let (services, storage) = registry_readiness(snapshot, family);
            value["readiness"]["storage"] = storage;
            if family == "registry-service" {
                value["readiness"]["services"] = services;
                value["readiness"]["publication"] = json!("not-ready");
            }
        }
        if value["outcome"] == "unknown" && value["recovery"]["choice"] == "none" {
            value["recovery"] = json!({"choice":"observe","proposal":null});
        }
    }
    Ok(value)
}

pub(in crate::k3s) fn render(value: &Value, table: bool) -> Result<Vec<u8>> {
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > 1_048_576)
            {
                return Err(std::io::Error::other("report bound"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    if table {
        for (name, value) in value.as_object().ok_or(Failure::Integrity)? {
            output
                .write_all(name.as_bytes())
                .and_then(|_| output.write_all(b"\t"))
                .map_err(|_| Failure::Bound)?;
            serde_json::to_writer(&mut output, value).map_err(|_| Failure::Bound)?;
            output.write_all(b"\n").map_err(|_| Failure::Bound)?;
        }
    } else {
        serde_json::to_writer(&mut output, value).map_err(|_| Failure::Bound)?;
        output.write_all(b"\n").map_err(|_| Failure::Bound)?;
    }
    Ok(output.0)
}

