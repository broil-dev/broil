// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::Policy;
use super::{
    Failure, Result, Snapshot, canonical, hash, require, rpc, schema,
    session::{Local, Session},
};
use broil_config::LoadedProject;
use broil_core::secret::path_safety::sudo_nonce;
use serde_json::{Value, json};
use std::time::Duration;

async fn open<'a>(
    project: &'a LoadedProject,
    policy: Policy,
    target: &str,
    operation: &str,
) -> super::ExecutionResult<(rpc::Context<'a>, Local)> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let id = operation.to_owned();
    if let Err(failure) = local.work(move |store| store.lock(&id)).await {
        return Err(local.failure(failure, &context.clock).await);
    }
    Ok((context, local))
}

fn bind_bootstrap(context: &mut rpc::Context<'_>, local: &Local) -> Result<()> {
    let snapshot = local.snapshot()?;
    if snapshot.request["action"] != "prepare-hosts" {
        return Ok(());
    }
    let recipe = snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "bootstrap-recipe")
        .map(|o| &o["event"]["recipe"])
        .ok_or(Failure::Integrity)?;
    let expected = super::hash("broil-k3s-bootstrap-recipe-v1", recipe)?;
    let recorded = snapshot.request["fingerprints"]["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|t| t["name"] == "bootstrap-recipe"))
        .and_then(|t| t["sha256"].as_str())
        .ok_or(Failure::Integrity)?;
    require(recorded == expected, Failure::Integrity)?;
    context.bind_recipe(&expected)
}

pub async fn resume(
    project: &LoadedProject,
    policy: Policy,
    target: &str,
    operation: &str,
) -> super::ExecutionResult<(Value, bool)> {
    let (mut context, mut local) = open(project, policy, target, operation).await?;
    if let Err(failure) = bind_bootstrap(&mut context, &local) {
        return Err(local.failure(failure, &context.clock).await);
    }
    let result: Result<_> = async {
        let original = local.snapshot()?.clone();
        let observed = observe(&context, &mut local, &original).await;
        let mut complete = false;
        let result = match observed {
            Ok(writers) => {
                let snapshot = local.snapshot()?.clone();
                let current = super::report::report(
                    &context.scope,
                    "resume",
                    std::slice::from_ref(&snapshot),
                )?;
                complete = current["outcome"] == "succeeded" && current["cleanup_unknown"] == false;
                if complete {
                    Ok(None)
                } else {
                    proposal(&context, &snapshot, &writers, None)
                        .await
                        .map(Some)
                }
            }
            Err(failure) => {
                local.limit_observation(context.clock.terminal_deadline());
                Err(failure)
            }
        };
        let event = match &result {
            Ok(Some(proposal)) => json!({"type":"recovery","choice":"retry","proposal":proposal}),
            Ok(None) => json!({"type":"recovery","choice":"none","proposal":null}),
            Err(_) => json!({"type":"recovery","choice":"operator-recovery","proposal":null}),
        };
        local.append(None, event, None, Value::Null).await?;
        let mut value = super::report::report(
            &context.scope,
            "resume",
            std::slice::from_ref(local.snapshot()?),
        )?;
        if let Err(failure) = result {
            value["failure"] = json!(failure.name());
            complete = false;
        }
        Ok((value, complete))
    }
    .await;
    local.complete(result, &context.clock).await
}

pub(in crate::k3s) async fn retry(
    project: &LoadedProject,
    policy: Policy,
    target: &str,
    operation: &str,
    step: u64,
    approve: &str,
) -> super::ExecutionResult<(Value, bool)> {
    let (mut context, mut local) = open(project, policy, target, operation).await?;
    if let Err(failure) = bind_bootstrap(&mut context, &local) {
        return Err(local.failure(failure, &context.clock).await);
    }
    let validated: Result<_> = async {
        let snapshot = local.snapshot()?.clone();
        let prior = snapshot
            .observations
            .iter()
            .rev()
            .find(|o| o["event"]["type"] == "recovery")
            .map(|o| o["event"]["proposal"].clone())
            .ok_or(Failure::Readiness)?;
        require(
            prior["digest"] == approve && prior["decision"]["original_step"] == step,
            Failure::Ownership,
        )?;
        let writers = observe(&context, &mut local, &snapshot).await?;
        let fresh = proposal(
            &context,
            local.snapshot()?,
            &writers,
            Some(prior["decision"]["resources"].clone()),
        )
        .await?;
        require(fresh == prior, Failure::Ownership)?;
        let snapshot = local.snapshot()?;
        let original = snapshot
            .steps
            .iter()
            .find(|s| s["step"] == step)
            .ok_or(Failure::Integrity)?;
        let payload = if original["action"] == "prepare-input" {
            Some(reproduce_input(&context, snapshot, original)?)
        } else {
            None
        };
        local.work(|store| store.verify()).await?;
        Ok((prior, payload))
    }
    .await;
    let (prior, payload) = match validated {
        Ok(value) => value,
        Err(failure) => {
            return Err(local.failure(failure, &context.clock).await);
        }
    };
    let snapshot = Box::pin(Session::retry(context, local, prior, payload)).await?;
    let value = super::report::report(
        &snapshot.request["scope"],
        "retry",
        std::slice::from_ref(&snapshot),
    )?;
    let complete = value["outcome"] == "succeeded" && value["cleanup_unknown"] == false;
    Ok((value, complete))
}

pub(super) async fn inspect(
    context: &rpc::Context<'_>,
    snapshot: &Snapshot,
    binding: &Value,
    subject: &str,
    dispatch: Value,
    resource: Value,
) -> Result<rpc::Observed> {
    let observed = context
        .invoke_recorded(
            snapshot,
            binding,
            "inspect",
            json!({"subject":subject,"dispatch":dispatch,"resource":resource}),
            tokio::time::Instant::now()
                + Duration::from_secs(context.selected.step_timeout.seconds),
        )
        .await;
    require(
        observed.failure.is_none() && observed.response.is_some(),
        observed.failure.unwrap_or(Failure::Transport),
    )?;
    Ok(observed)
}

pub(super) fn member_binding(
    snapshot: &Snapshot,
    member: &Value,
    attempt: &Value,
) -> Result<Value> {
    let step = snapshot
        .steps
        .iter()
        .rev()
        .find(|s| s["attempt"] == *attempt && s["recipient"] == *member)
        .or_else(|| snapshot.steps.iter().find(|s| s["attempt"] == *attempt))
        .ok_or(Failure::Readiness)?;
    let mut binding = snapshot.binding(step);
    if step["recipient"] != *member {
        binding["recipient"] = member.clone();
        binding["receiver_generation"] = json!(0);
    }
    Ok(binding)
}

async fn observe(
    context: &rpc::Context<'_>,
    local: &mut Local,
    snapshot: &Snapshot,
) -> Result<Vec<Value>> {
    let request = &snapshot.request;
    require(
        request["scope"] == context.scope
            && request["config"] == context.config
            && request["references"] == context.references
            && super::stable_fingerprints(request) == context.owner_fingerprints
            && request["fingerprints"] == context.fingerprints,
        Failure::Ownership,
    )?;
    let (acquired, _) = super::session::selection(snapshot)?;
    context.authenticate_owned(&json!(acquired)).await?;
    if matches!(
        request["action"].as_str(),
        Some(
            "reconcile-network"
                | "reconcile-ingress"
                | "reconcile-cert-manager"
                | "reconcile-issuer"
                | "reconcile-certificate"
                | "reconcile-registry-storage"
                | "reconcile-registry-service"
                | "reconcile-registry-endpoint"
                | "reconcile-registry-auth"
                | "reconcile-registry-token"
                | "reconcile-registry-replication"
                | "release-deliver"
                | "release-retain"
                | "release-apply"
                | "release-rollback"
        )
    ) {
        return super::network::resume_recorded(context, local, snapshot).await;
    }
    let attempt = snapshot
        .attempts
        .iter()
        .max_by_key(|a| a["steps"][0].as_u64())
        .ok_or(Failure::Integrity)?;
    let members = &acquired;
    let lifecycle = request["action"] == "create-server";
    let agent = request["action"] == "join-agent";
    let join = request["action"] == "join-server" || agent;
    let selected = if join {
        Some(
            members
                .iter()
                .position(|m| m["machine"] == request["resources"][1]["machine"])
                .ok_or(Failure::Integrity)?,
        )
    } else {
        None
    };
    let mut published: Option<Value> = None;
    let mut joined_identity: Option<Value> = None;
    let mut writers = Vec::new();
    for (index, member) in members.iter().enumerate() {
        let binding = member_binding(snapshot, member, &attempt["attempt"])?;
        let owner = inspect(
            context,
            snapshot,
            &binding,
            "owner",
            Value::Null,
            Value::Null,
        )
        .await?
        .response
        .ok_or(Failure::Transport)?;
        require(
            owner["status"] == "ok" || owner["status"] == "absent",
            Failure::Ownership,
        )?;
        if owner["status"] == "absent" {
            require(
                request["cluster"].is_null() && member["node_uid"].is_null(),
                Failure::Ownership,
            )?;
            writers.push(json!({"claim":null,"reservation":null,"seal":null,"retirement":null}));
        } else if lifecycle {
            super::server::resume_member(
                context,
                local,
                snapshot,
                index,
                &binding,
                &owner["data"]["ownership"],
                &mut published,
            )
            .await?;
            let response = inspect(
                context,
                snapshot,
                &binding,
                "writer",
                Value::Null,
                Value::Null,
            )
            .await?
            .response
            .ok_or(Failure::Transport)?;
            require(
                response["status"] == "ok" || response["status"] == "absent",
                Failure::Readiness,
            )?;
            writers.push(response["data"].clone());
        } else if join && selected == Some(index) {
            require(
                owner["data"]["ownership"]["cluster"] == request["cluster"],
                Failure::Ownership,
            )?;
            joined_identity = super::server::resume_join_member(
                context,
                local,
                snapshot,
                index,
                &binding,
                &owner["data"]["ownership"],
            )
            .await?;
            let response = inspect(
                context,
                snapshot,
                &binding,
                "writer",
                Value::Null,
                Value::Null,
            )
            .await?
            .response
            .ok_or(Failure::Transport)?;
            require(
                response["status"] == "ok" || response["status"] == "absent",
                Failure::Readiness,
            )?;
            writers.push(response["data"].clone());
        } else {
            require(
                owner["data"]["ownership"]["cluster"] == request["cluster"],
                Failure::Ownership,
            )?;
            let response = inspect(
                context,
                snapshot,
                &binding,
                "identity",
                Value::Null,
                Value::Null,
            )
            .await?
            .response
            .ok_or(Failure::Transport)?;
            require(response["status"] == "ok", Failure::Ownership)?;
            let identity = &response["data"]["identity"];
            require(
                identity["member"] == *member && identity["cluster"] == request["cluster"],
                Failure::Ownership,
            )?;
            local.append(None,json!({"type":"identity","member":member,"cluster":identity["cluster"],"resources":[],"readiness":identity["readiness"]}),
                Some(&member["machine"]),Value::Null).await?;
            let response = inspect(
                context,
                snapshot,
                &binding,
                "writer",
                Value::Null,
                Value::Null,
            )
            .await?
            .response
            .ok_or(Failure::Transport)?;
            require(
                response["status"] == "ok" || response["status"] == "absent",
                Failure::Readiness,
            )?;
            writers.push(response["data"].clone());
        }
    }
    for step in snapshot.steps.iter().filter(|s| {
        !matches!(
            s["action"].as_str(),
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
                    | "lifecycle:node-observe-node"
                    | "lifecycle:node-observe-drain"
                    | "inspect"
            )
        ) && !snapshot.deselected(s)
    }) {
        let observed = context
            .receipt(
                snapshot,
                step,
                tokio::time::Instant::now()
                    + Duration::from_secs(context.selected.step_timeout.seconds),
            )
            .await;
        let response = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(
            response["status"] == "ok" && !response["data"]["terminal"].is_null(),
            Failure::Readiness,
        )?;
        let receipt = &response["data"]["terminal"];
        local
            .append(
                Some(step),
                json!({"type":"receiver","receipt":receipt,"transport":observed.transport}),
                Some(&step["recipient"]["machine"]),
                receipt["completed_ms"].clone(),
            )
            .await?;
    }
    for resource in request["resources"].as_array().ok_or(Failure::Integrity)? {
        let member = members
            .iter()
            .find(|m| m["machine"] == resource["machine"])
            .ok_or(Failure::Ownership)?;
        let index = members
            .iter()
            .position(|m| m == member)
            .ok_or(Failure::Integrity)?;
        if writers[index]["claim"].is_null() {
            continue;
        }
        let binding = member_binding(snapshot, member, &attempt["attempt"])?;
        let response = inspect(
            context,
            snapshot,
            &binding,
            "resource",
            Value::Null,
            resource.clone(),
        )
        .await?
        .response
        .ok_or(Failure::Transport)?;
        require(
            response["status"] == "ok" || response["status"] == "absent",
            Failure::Ownership,
        )?;
    }
    if let (Some(index), Some(identity)) = (selected, joined_identity) {
        if snapshot.owner["members"][index]["node_uid"].is_null() {
            let publication = snapshot
                .steps
                .iter()
                .find(|s| {
                    s["action"]
                        == if agent {
                            "lifecycle:publish-agent"
                        } else {
                            "lifecycle:publish-member"
                        }
                        && s["recipient"] == request["members"][index]
                })
                .ok_or(Failure::Readiness)?;
            let receipt = local
                .snapshot()?
                .observations
                .iter()
                .rev()
                .find(|o| {
                    o["event"]["type"] == "receiver"
                        && o["step"] == publication["step"]
                        && o["attempt"] == publication["attempt"]
                })
                .ok_or(Failure::Readiness)?["event"]["receipt"]
                .clone();
            require(
                receipt["binding"] == snapshot.binding(publication)
                    && receipt["outcome"] == "succeeded"
                    && receipt["effect"] == "complete",
                Failure::Ownership,
            )?;
            let member = request["members"][index].clone();
            local
                .append(
                    Some(publication),
                    json!({"type":"identity","member":member,"cluster":identity["cluster"],
                        "resources":[],"readiness":super::report::readiness()}),
                    Some(&member["machine"]),
                    Value::Null,
                )
                .await?;
            let mut owner =
                super::server::published_owner(&local.snapshot()?.owner, index, &identity)?;
            let pair = request["resources"].as_array().ok_or(Failure::Integrity)?;
            require(
                pair.iter().all(|resource| {
                    !owner["resources"]
                        .as_array()
                        .is_some_and(|retained| retained.contains(resource))
                }),
                Failure::Ownership,
            )?;
            owner["resources"]
                .as_array_mut()
                .ok_or(Failure::Integrity)?
                .extend(pair.iter().cloned());
            let operation = request["operation"]
                .as_str()
                .ok_or(Failure::Integrity)?
                .to_owned();
            local
                .work(move |store| store.replace_owner(owner, &operation))
                .await?;
        }
    }
    Ok(writers)
}

fn terminal<'a>(snapshot: &'a Snapshot, step: &Value) -> Result<&'a Value> {
    snapshot
        .observations
        .iter()
        .rev()
        .find(|o| {
            o["event"]["type"] == "receiver"
                && o["attempt"] == step["attempt"]
                && o["step"] == step["step"]
                && o["dispatch"] == step["dispatch"]
        })
        .map(|o| &o["event"]["receipt"])
        .ok_or(Failure::Readiness)
}

pub(super) async fn proposal(
    context: &rpc::Context<'_>,
    snapshot: &Snapshot,
    writers: &[Value],
    resources: Option<Value>,
) -> Result<Value> {
    let request = &snapshot.request;
    require(
        request["action"] != "prepare-node-registry",
        Failure::Capability,
    )?;
    let attempt = snapshot
        .attempts
        .iter()
        .max_by_key(|a| a["steps"][0].as_u64())
        .ok_or(Failure::Integrity)?;
    let mut failed = None;
    for step in snapshot.steps.iter().filter(|s| {
        s["attempt"] == attempt["attempt"]
            && !s["action"]
                .as_str()
                .is_some_and(super::provenance::lifecycle_inspection)
            && !snapshot.deselected(s)
    }) {
        require(
            !step["action"]
                .as_str()
                .is_some_and(|a| a.starts_with("lifecycle:")),
            Failure::Capability,
        )?;
        let receipt = terminal(snapshot, step)?;
        require(receipt["writer_ended"] == true, Failure::Readiness)?;
        if receipt["outcome"] == "succeeded" && receipt["effect"] == "complete" {
            continue;
        }
        require(
            failed.is_none()
                && receipt["outcome"] == "failed"
                && receipt["effect"] == "absent"
                && matches!(
                    step["action"].as_str(),
                    Some("reserve-owner" | "prepare-input")
                ),
            Failure::Capability,
        )?;
        failed = Some(step);
    }
    let failed = failed.ok_or(Failure::Readiness)?;
    require(
        failed["action"] != "reserve-owner" || request["consumer"].is_null(),
        Failure::Capability,
    )?;
    let (members, _) = super::session::selection(snapshot)?;
    require(writers.len() == members.len(), Failure::Integrity)?;
    let mut receivers = Vec::new();
    for (member, writer) in members.iter().zip(writers) {
        let claim = &writer["claim"];
        let reservation = &writer["reservation"];
        require(
            claim.is_null() || claim["active_attempt"].is_null(),
            Failure::Busy,
        )?;
        let (state, receipt, retired) = if reservation.is_null() {
            require(failed["action"] == "reserve-owner", Failure::Readiness)?;
            require(
                !snapshot.steps.iter().any(|s| {
                    s["attempt"] == attempt["attempt"]
                        && s["recipient"] == *member
                        && s["action"] != "reserve-owner"
                }),
                Failure::Readiness,
            )?;
            let last = snapshot
                .steps
                .iter()
                .rev()
                .find(|s| s["attempt"] == attempt["attempt"] && s["recipient"] == *member);
            (
                if claim.is_null() {
                    "absent"
                } else {
                    "reserved"
                },
                last.map(|s| terminal(snapshot, s).and_then(|r| hash("broil-infra-receipt-v1", r)))
                    .transpose()?
                    .map_or(Value::Null, Value::String),
                Value::Null,
            )
        } else {
            require(
                reservation["state"] == "retired" && reservation["members"] == json!(members),
                Failure::Busy,
            )?;
            let seal_step = snapshot
                .steps
                .iter()
                .find(|s| {
                    s["attempt"] == attempt["attempt"]
                        && s["recipient"] == *member
                        && s["action"] == "seal-writer"
                })
                .ok_or(Failure::Readiness)?;
            let retire_step = snapshot
                .steps
                .iter()
                .find(|s| {
                    s["attempt"] == attempt["attempt"]
                        && s["recipient"] == *member
                        && s["action"] == "retire-writer"
                })
                .ok_or(Failure::Readiness)?;
            require(
                snapshot.succeeded(seal_step) && snapshot.succeeded(retire_step),
                Failure::Readiness,
            )?;
            let seal = &writer["seal"];
            let retirement = &writer["retirement"];
            require(
                seal["binding"] == snapshot.binding(seal_step)
                    && retirement["binding"] == snapshot.binding(retire_step)
                    && reservation["seal_sha256"] == hash("broil-infra-seal-v1", seal)?
                    && reservation["retirement_sha256"]
                        == hash("broil-infra-retirement-v1", retirement)?
                    && retirement["seals"] == snapshot.retirement_payload(retire_step)?["seals"]
                    && claim["generation"] == retirement["next_generation"],
                Failure::Ownership,
            )?;
            (
                "retired",
                json!(hash(
                    "broil-infra-receipt-v1",
                    terminal(snapshot, retire_step)?
                )?),
                reservation["retirement_sha256"].clone(),
            )
        };
        receivers.push(json!({"machine":member["machine"],"generation":if claim.is_null(){json!(0)}else{claim["generation"].clone()},
            "state":state,"terminal_sha256":receipt,"retirement_sha256":retired}));
    }
    let proposed = if failed["action"] == "prepare-input" {
        reproduce_input(context, snapshot, failed)?;
        let mut original = failed["resource"].clone();
        let supplied = resources
            .as_ref()
            .map(|v| v.as_array().ok_or(Failure::Integrity))
            .transpose()?;
        let generation = match supplied {
            Some(v) => {
                require(v.len() == 1, Failure::Integrity)?;
                v[0]["generation"]
                    .as_str()
                    .ok_or(Failure::Integrity)?
                    .to_owned()
            }
            None => sudo_nonce().map_err(|_| Failure::Storage)?,
        };
        require(
            super::nonce(&generation) && original["generation"] != generation,
            Failure::Ownership,
        )?;
        original["generation"] = json!(generation);
        original["path"] = json!(format!(
            "/var/lib/broil/k3s/owners/{}/resources/{}/{}",
            request["owner"].as_str().ok_or(Failure::Integrity)?,
            original["id"].as_str().ok_or(Failure::Integrity)?,
            generation
        ));
        let proposed = json!([original]);
        if let Some(ref expected) = resources {
            require(*expected == proposed, Failure::Ownership)?;
        }
        let response = inspect(
            context,
            snapshot,
            &snapshot.binding(failed),
            "resource",
            Value::Null,
            proposed[0].clone(),
        )
        .await?
        .response
        .ok_or(Failure::Transport)?;
        require(response["status"] == "absent", Failure::Ownership)?;
        proposed
    } else {
        require(
            resources.as_ref().is_none_or(|r| *r == json!([])),
            Failure::Integrity,
        )?;
        json!([])
    };
    let mut ordered = members.iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| a["machine"].as_str().cmp(&b["machine"].as_str()));
    let mut effects = Vec::new();
    for action in ["reserve-owner", "acquire-writer"] {
        for m in &ordered {
            effects.push(json!({"action":action,"machine":m["machine"],"resource":null}));
        }
    }
    if failed["action"] == "prepare-input" {
        effects.push(json!({"action":"prepare-input","machine":failed["recipient"]["machine"],"resource":proposed[0]}));
    }
    for action in ["seal-writer", "retire-writer"] {
        for m in &ordered {
            effects.push(json!({"action":action,"machine":m["machine"],"resource":null}));
        }
    }
    let decision = json!({"schema":1,"scope":request["scope"],"owner":request["owner"],"operation":request["operation"],
        "failed_attempt":attempt["attempt"],"original_step":if failed["original_step"].is_null(){&failed["step"]}else{&failed["original_step"]},"action":failed["action"],
        "request_sha256":hash("broil-infra-request-v1",request)?,"local_generation":snapshot.owner["generation"],
        "members":request["members"],"cluster":request["cluster"],"resources":proposed,"fingerprints":request["fingerprints"],
        "participants_sha256":request["participants_sha256"],"receivers":receivers,"effects":effects,
        "gates":{"writers_settled":true,"original_selection_intact":true,"destination_absent":true,"lifecycle_required":false}});
    let proposal = json!({"digest":format!("sha256:{}",hash("broil-infra-approval-v1",&decision)?),"decision":decision});
    schema::decode(&canonical(&proposal)?, "Proposal", 65536)?;
    Ok(proposal)
}

fn reproduce_input(context: &rpc::Context<'_>, snapshot: &Snapshot, step: &Value) -> Result<Value> {
    super::recipe::revalidate(context, &snapshot.request)?;
    require(step["action"] == "prepare-input", Failure::Capability)?;
    snapshot.consumer_payload(step)
}
