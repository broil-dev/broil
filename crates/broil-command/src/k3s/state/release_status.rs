// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::network;
use super::release::{RECIPE, applied_release, event, lifecycle_envelope, list, ordered};
use super::release_delivery::{
    self as delivery, Leaf, Reported, envelope, records, refused, releases, store_usage,
};
use super::session::{Local, fresh, now};
use super::{Failure, Result, Snapshot, hash, rpc};
use broil_config::LoadedProject;
use serde_json::{Value, json};
use std::time::Duration;

fn binding(
    context: &rpc::Context<'_>,
    owner: &Value,
    source: &Snapshot,
    member: &Value,
    recipe: &Value,
    query: &str,
) -> Result<Value> {
    let attempt = &source.attempts.last().ok_or(Failure::Integrity)?["attempt"];
    let step = source
        .steps
        .iter()
        .filter(|s| s["attempt"] == *attempt)
        .filter_map(|s| s["step"].as_u64())
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .filter(|s| *s <= u64::from(u32::MAX))
        .ok_or(Failure::Bound)?;
    let projection = json!({"scope":context.scope,"view":"release-status","component":null,
        "limit":null,"owner":owner["owner"],"cluster":owner["cluster"],"member":member,
        "source_operation":source.request["operation"],"source_attempt":attempt,
        "recipe_sha256":hash("broil-k3s-release-recipe-v1", recipe)?,"query":query});
    Ok(json!({"scope":context.scope,"owner":owner["owner"],
        "operation":source.request["operation"],"attempt":attempt,"step":step,
        "dispatch":fresh()?,"recipient":member,"receiver_generation":0,
        "request_sha256":hash("broil-infra-view-v1",&projection)?,
        "participants_sha256":owner["participants_sha256"],"fingerprints":context.fingerprints}))
}

async fn read(
    context: &rpc::Context<'_>,
    family: &network::Family,
    binding: &Value,
    tag: &str,
    payload: &Value,
) -> Option<Value> {
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now()
            + Duration::from_secs(context.selected.step_timeout.seconds.min(30)),
    );
    network::invoke(context, family, binding, tag, payload, deadline, None)
        .await
        .response
        .filter(|r| r["status"] == "ok")
}

async fn classified(
    context: &rpc::Context<'_>,
    binding: &Value,
    tag: &str,
    payload: &Value,
) -> std::result::Result<Value, &'static str> {
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now()
            + Duration::from_secs(context.selected.step_timeout.seconds.min(30)),
    );
    let observed = network::invoke(
        context,
        &super::release_apply::FAMILY,
        binding,
        tag,
        payload,
        deadline,
        None,
    )
    .await;
    match observed.response {
        Some(reply) if reply["status"] == "ok" => Ok(reply),
        Some(reply) if reply["status"] == "bound" => Err("bound"),
        _ if observed.failure == Some(Failure::Cancelled)
            || context.policy.cancellation.is_cancelled() =>
        {
            Err("cancelled")
        }
        _ => Err("failed"),
    }
}

fn pruned_kinds(context: &rpc::Context<'_>) -> Result<Option<Vec<Value>>> {
    let hash = context.scope["hash"].as_str().ok_or(Failure::Integrity)?;
    let path = context
        .project
        .broil_root
        .join("state/infrastructure/targets")
        .join(hash)
        .join("history/checkpoint.json");
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Some(Vec::new())),
        Err(_) => return Err(Failure::Storage),
    };
    let checkpoint =
        crate::k3s::history::checkpoint::decode(&raw).map_err(|_| Failure::Integrity)?;
    if checkpoint["scope"] != context.scope {
        return Err(Failure::Ownership);
    }
    Ok(match checkpoint.get("pruned_kinds") {
        None => Some(Vec::new()),
        Some(Value::Null) => None,
        Some(kinds) => Some(list(kinds).to_vec()),
    })
}

fn presence(reply: Option<&Value>, images: &[Value]) -> (Value, Value) {
    let Some(reply) = reply else {
        return (json!("unobserved"), Value::Null);
    };
    let seen = |image: &Value| {
        list(&reply["images"])
            .iter()
            .find(|i| i["reference"] == image["reference"])
            .cloned()
            .unwrap_or(Value::Null)
    };
    let present = images
        .iter()
        .all(|i| seen(i)["present"] == true && seen(i)["repo_digests_match"] == true);
    let pinned = images.iter().all(|i| seen(i)["pinned"] == true);
    (
        json!(if present { "present" } else { "missing" }),
        json!(pinned),
    )
}

pub async fn status(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    application: &str,
) -> Leaf<Reported> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let loaded = records(&mut local).await;
    let _ = local.finish(&context.clock).await;
    let (previous, owner) = loaded?;
    let stored = releases(&context)?;
    if !stored.iter().any(|r| r["application"] == application) {
        return Err(refused(
            Failure::Configuration,
            "release",
            format!("application {application} has no recorded release"),
        ));
    }
    let roles = super::release::roles(&previous, &stored, application);
    let record_of = |id: &Value| stored.iter().find(|r| r["release"] == *id);
    let active = record_of(&roles["active"]);
    let rollback = record_of(&roles["rollback"]);
    let removed: Vec<Value> = list(&owner["removed"])
        .iter()
        .map(|r| r["member"].clone())
        .collect();
    let source = ordered(
        previous
            .iter()
            .filter(|s| !roles["active"].is_null() && applied_release(s) == Some(&roles["active"]))
            .collect(),
    )
    .into_iter()
    .next();
    let recipe = source
        .and_then(|s| event(s, RECIPE))
        .map(|e| e["recipe"].clone());
    let mut complete = true;
    let mut inspected = std::collections::BTreeMap::new();
    let mut workloads = Vec::new();
    let mut managed: Option<Vec<Value>> = None;
    let mut orphan = json!({"recipe":false,"api":false,"kinds":null,"discover":null,
        "observe":null});
    if let (Some(source), Some(recipe), Some(active)) = (source, &recipe, active) {
        orphan["recipe"] = json!(true);
        let mut references: Vec<Value> = list(&active["images"])
            .iter()
            .map(|i| i["reference"].clone())
            .collect();
        for image in rollback.map_or(&[][..], |r| list(&r["images"])) {
            if !references.contains(&image["reference"]) {
                references.push(image["reference"].clone());
            }
        }
        let required_now: Vec<&Value> = list(&active["policy"]["members"])
            .iter()
            .filter(|m| !removed.contains(m))
            .collect();
        for member in list(&owner["members"]) {
            if !list(&recipe["required"]).contains(&member["member"])
                || !required_now.contains(&&member["member"])
            {
                continue;
            }
            let payload = json!({"recipe":recipe,"expected":{"references":references},
                "resource":null,"preflight":null,"wait_ms":null,"member":member["member"]});
            let reply = match binding(
                &context,
                &owner,
                source,
                member,
                recipe,
                "delivery:inspect-images",
            ) {
                Ok(b) => read(&context, &delivery::FAMILY, &b, "inspect-images", &payload).await,
                Err(_) => None,
            };
            complete &= reply.is_some();
            inspected.insert(member["member"].as_str().unwrap_or("").to_owned(), reply);
        }
        let declared: Vec<Value> = list(&owner["members"])
            .iter()
            .map(|m| json!({"name":m["member"],"role":m["role"],"node_uid":m["node_uid"]}))
            .collect();
        let reads = crate::k3s::release::status_reads(
            &json!({"recipe":recipe,"target":{"members":declared,"removed":removed}}),
        );
        let survivors = super::survivors(&owner)?;
        let api = survivors.iter().find(|m| m["member"] == reads["recipient"]);
        let release_payload = |expected: Value, wait: Value| json!({"recipe":recipe,"expected":expected,"wait_ms":wait});
        let objects = list(&active["manifests"]["objects"]);
        let namespace = &active["namespace"];
        let waited: Vec<Value> = objects
            .iter()
            .filter(|o| {
                [
                    ("apps/v1", "Deployment"),
                    ("apps/v1", "StatefulSet"),
                    ("apps/v1", "DaemonSet"),
                    ("apps/v1", "ReplicaSet"),
                    ("batch/v1", "Job"),
                    ("v1", "Pod"),
                ]
                .iter()
                .any(|(v, k)| o["api_version"] == *v && o["kind"] == *k)
            })
            .map(|o| {
                json!({"api_version":o["api_version"],"kind":o["kind"],"namespace":namespace,
                    "name":o["name"]})
            })
            .collect();
        let bound: Vec<Value> = list(&active["images"])
            .iter()
            .map(|i| {
                json!({"reference":i["reference"],"root":i["root"],
                    "manifests":list(&i["platforms"]).iter().map(|p| p["manifest"].clone()).collect::<Vec<_>>()})
            })
            .collect();
        if let Some(api) = api {
            orphan["api"] = json!(true);
            for group in waited.chunks(crate::k3s::release::WORKLOAD_GROUP) {
                let reply = match binding(
                    &context,
                    &owner,
                    source,
                    api,
                    recipe,
                    "release:inspect-workloads",
                ) {
                    Ok(b) => {
                        read(
                            &context,
                            &super::release_apply::FAMILY,
                            &b,
                            "inspect-workloads",
                            &release_payload(json!({"workloads":group,"bound":bound}), json!(0)),
                        )
                        .await
                    }
                    Err(_) => None,
                };
                complete &= reply.is_some();
                workloads.extend(reply.map_or_else(Vec::new, |r| list(&r["workloads"]).to_vec()));
            }
            let mut kinds: Vec<Value> = Vec::new();
            for record in stored.iter().filter(|r| r["namespace"] == *namespace) {
                for o in list(&record["manifests"]["objects"]) {
                    let kind = json!({"api_version":o["api_version"],"kind":o["kind"]});
                    if o["kind"] != "Namespace" && !kinds.contains(&kind) {
                        kinds.push(kind);
                    }
                }
            }
            let pruned = pruned_kinds(&context)?;
            for entry in pruned.iter().flatten() {
                let kind = json!({"api_version":entry["api_version"],"kind":entry["kind"]});
                if entry["namespace"] == *namespace
                    && entry["kind"] != "Namespace"
                    && !kinds.contains(&kind)
                {
                    kinds.push(kind);
                }
            }
            if pruned.is_none() || kinds.len() > 1024 {
                orphan["kinds"] = json!("bound");
            } else {
                orphan["kinds"] = json!("within");
                let discovered = match binding(
                    &context,
                    &owner,
                    source,
                    api,
                    recipe,
                    "release:discover-kinds",
                ) {
                    Ok(b) => {
                        classified(
                            &context,
                            &b,
                            "discover-kinds",
                            &release_payload(json!({"kinds":kinds}), Value::Null),
                        )
                        .await
                    }
                    Err(_) => Err("unmade"),
                };
                orphan["discover"] = json!(match &discovered {
                    Ok(_) => "read",
                    Err("bound") => "failed",
                    Err(read) => read,
                });
                if let Ok(discovered) = discovered {
                    let served: Vec<Value> = list(&discovered["kinds"])
                        .iter()
                        .filter(|k| k["served"] == true && k["namespaced"] == true)
                        .map(|k| json!({"api_version":k["api_version"],"kind":k["kind"]}))
                        .collect();
                    let observed = match binding(
                        &context,
                        &owner,
                        source,
                        api,
                        recipe,
                        "release:observe-release",
                    ) {
                        Ok(b) => {
                            classified(
                                &context,
                                &b,
                                "observe-release",
                                &release_payload(
                                    json!({"namespace":namespace,"kinds":served,"secrets":[]}),
                                    Value::Null,
                                ),
                            )
                            .await
                        }
                        Err(_) => Err("unmade"),
                    };
                    orphan["observe"] = json!(match &observed {
                        Ok(o) if o["presence"]["truncated"] == true => "truncated",
                        Ok(_) => "read",
                        Err(read) => read,
                    });
                    if let Ok(o) = observed {
                        if o["presence"]["truncated"] != true {
                            managed = Some(list(&o["objects"]).to_vec());
                        }
                    }
                }
            }
        } else {
            complete = false;
        }
    }
    orphan["complete"] = json!(complete);
    let decided = crate::k3s::release::orphaned(&orphan);
    let orphaned_reason = decided["orphaned_reason"].clone();
    let complete = decided["outcome"] == "complete";
    let active_images = active.map_or(&[][..], |r| list(&r["images"]));
    let rollback_images = rollback.map_or(&[][..], |r| list(&r["images"]));
    let mut nodes = Vec::new();
    for declared in &context.selected.declaration.members {
        let member = json!(declared.name);
        if removed.contains(&member) {
            nodes.push(
                json!({"active":null,"member":member,"pinned":null,"ready":null,
                "rollback":null,"state":"removed"}),
            );
            continue;
        }
        let reply = inspected.get(&declared.name).and_then(Option::as_ref);
        let listed = inspected.contains_key(&declared.name);
        let (active_state, pinned) = if active.is_none() {
            (Value::Null, Value::Null)
        } else if listed {
            presence(reply, active_images)
        } else {
            (json!("unobserved"), Value::Null)
        };
        let rollback_state = if rollback.is_none() {
            Value::Null
        } else if listed {
            presence(reply, rollback_images).0
        } else {
            json!("unobserved")
        };
        nodes.push(json!({"active":active_state,"member":member,"pinned":pinned,
            "ready":if listed {json!(reply.is_some() && active_state == "present" && pinned == true)} else {Value::Null},
            "rollback":rollback_state,"state":"member"}));
    }
    let mut orphaned = Vec::new();
    if let (Some(managed), Some(active)) = (&managed, active) {
        let namespace = &active["namespace"];
        let mut kept: Vec<&Value> = list(&active["manifests"]["objects"]).iter().collect();
        for other in stored
            .iter()
            .filter(|r| r["namespace"] == *namespace && r["application"] != application)
        {
            let other_roles = super::release::roles(
                &previous,
                &stored,
                other["application"].as_str().unwrap_or(""),
            );
            if other_roles["active"] == other["release"] {
                kept.extend(list(&other["manifests"]["objects"]));
            }
        }
        let same = |a: &Value, b: &Value| {
            a["kind"] == b["kind"]
                && a["name"] == b["name"]
                && (b["namespace"].is_null() || a["namespace"] == b["namespace"])
        };
        for object in managed {
            if object["kind"] == "Namespace" || kept.iter().any(|k| same(object, k)) {
                continue;
            }
            let mut owners: Vec<&Value> = stored
                .iter()
                .filter(|r| {
                    r["application"] == application
                        && list(&r["manifests"]["objects"])
                            .iter()
                            .any(|o| same(object, o))
                })
                .collect();
            owners.sort_by_key(|r| std::cmp::Reverse(r["created_ms"].as_u64()));
            orphaned.push(json!({"kind":object["kind"],"name":object["name"],
                "namespace":object["namespace"],
                "release":owners.first().map_or(Value::Null, |r| r["release"].clone())}));
        }
        orphaned.sort_by(|a, b| {
            (a["kind"].as_str(), a["name"].as_str()).cmp(&(b["kind"].as_str(), b["name"].as_str()))
        });
    }
    let members = super::survivors(&owner)?;
    let mut report = envelope(
        &context,
        "release-status",
        store_usage(&previous, None, &members, stored.len()),
    );
    let excluded: Vec<Value> = active
        .map(|r| {
            list(&r["policy"]["members"])
                .iter()
                .filter(|m| removed.contains(m))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    report["application"] = json!(application);
    report["release"] = roles["active"].clone();
    report["active"] = roles["active"].clone();
    report["rollback"] = roles["rollback"].clone();
    report["observed_ms"] = json!(now()?);
    report["excluded"] = Value::Array(excluded);
    report["nodes"] = Value::Array(nodes);
    report["workloads"] = Value::Array(workloads);
    report["orphaned"] = if managed.is_some() {
        Value::Array(orphaned)
    } else {
        Value::Null
    };
    report["orphaned_reason"] = orphaned_reason;
    if !complete {
        report["outcome"] = json!("incomplete");
        report["failure"] = json!("readiness");
        report["completion_unknown"] = json!(true);
        report["recovery"] = json!({"choice":"operator-recovery","reason":"readiness"});
    }
    Ok((report, complete))
}

fn stage(name: &str, report: Option<&Value>) -> Value {
    match report {
        Some(r) => json!({"detail":r["detail"],"failure":r["failure"],"outcome":r["outcome"],
            "stage":name}),
        None => json!({"detail":null,"failure":null,"outcome":"not-run","stage":name}),
    }
}

fn staged(context: &rpc::Context<'_>, result: Leaf<Reported>) -> Value {
    match result {
        Ok((report, _)) => report,
        Err(refusal) => {
            let mut report = lifecycle_envelope(context, "release-deploy", Value::Null);
            report["outcome"] = json!("failed");
            report["failure"] = json!(refusal.failure.name());
            report["detail"] = json!(refusal.boundary);
            report["recovery"] = json!({"choice":"rerun","operation":null,"subject":null});
            report
        }
    }
}

pub async fn deploy(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    application: &str,
    artifacts: Option<&str>,
) -> Leaf<Reported> {
    let context = rpc::Context::new(project, super::issuer::duplicate(&policy)?, target)?;
    let (prepared, _) = super::release::prepare(
        project,
        super::issuer::duplicate(&policy)?,
        target,
        application,
        artifacts,
    )
    .await?;
    let release = prepared["release"].as_str().unwrap_or("").to_owned();
    let mut stages = vec![stage("prepare", Some(&prepared))];
    let mut operations = Vec::new();
    let mut evidence = json!({"applied":false,"delivered":false,"healthy":false,"seeded":false});
    let delivered = staged(
        &context,
        delivery::deliver(
            project,
            super::issuer::duplicate(&policy)?,
            target,
            &release,
        )
        .await,
    );
    operations.extend(list(&delivered["operations"]).iter().cloned());
    stages.push(stage("deliver", Some(&delivered)));
    evidence["delivered"] = json!(delivered["evidence"]["delivered"] == true);
    evidence["seeded"] = json!(delivered["evidence"]["seeded"] == true);
    let last = if delivered["outcome"] == "succeeded" {
        let applied = staged(
            &context,
            super::release_apply::apply(project, policy, target, &release, None).await,
        );
        operations.extend(list(&applied["operations"]).iter().cloned());
        evidence["applied"] = json!(applied["evidence"]["applied"] == true);
        evidence["healthy"] = json!(applied["evidence"]["healthy"] == true);
        let health_failed = matches!(
            applied["detail"].as_str(),
            Some("rollout" | "undelivered-node" | "health-check")
        );
        if health_failed {
            stages
                .push(json!({"detail":null,"failure":null,"outcome":"succeeded","stage":"apply"}));
            stages.push(stage("health", Some(&applied)));
        } else {
            stages.push(stage("apply", Some(&applied)));
            stages.push(if applied["outcome"] == "succeeded" {
                json!({"detail":null,"failure":null,"outcome":"succeeded","stage":"health"})
            } else {
                stage("health", None)
            });
        }
        applied
    } else {
        stages.push(stage("apply", None));
        stages.push(stage("health", None));
        delivered
    };
    let succeeded = stages.iter().all(|s| s["outcome"] == "succeeded");
    let mut report = lifecycle_envelope(&context, "release-deploy", last["store"].clone());
    report["application"] = json!(application);
    report["release"] = json!(release);
    report["stages"] = Value::Array(stages);
    report["evidence"] = evidence;
    report["operations"] = Value::Array(operations);
    for key in [
        "outcome",
        "failure",
        "detail",
        "completion_unknown",
        "cleanup_unknown",
    ] {
        report[key] = last[key].clone();
    }
    report["recovery"] = last["recovery"].clone();
    report["active"] = last.get("active").cloned().unwrap_or(Value::Null);
    report["rollback"] = last.get("rollback").cloned().unwrap_or(Value::Null);
    if !succeeded && report["outcome"] == "succeeded" {
        report["outcome"] = json!("failed");
    }
    Ok((report, succeeded))
}

