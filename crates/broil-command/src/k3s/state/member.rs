// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::network::{self, Family};
use super::node::FAMILY;
use super::registry_replication as replication;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, hash, require, rpc};
use crate::k3s::commands::{Output, Refusal};
use crate::k3s::members;
use crate::k3s::report::{Format, encode};
use broil_config::LoadedProject;
use broil_core::k3s::{Role, Target};
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const ACTIONS: [&str; 5] = [
    "node-drain",
    "node-uncordon",
    "node-remove",
    "node-replace",
    "rebind-declaration",
];

const RECIPE_LIMIT: usize = 32_768;

const CLASSIFY_PAGES: usize = 2;
const EVICT_PAGES: usize = 4;
const NAMING_PAGES: usize = 2;

const TAGS: [(&str, bool); 7] = [
    ("cordon", true),
    ("uncordon", true),
    ("observe-drain", false),
    ("evict", true),
    ("delete-node", true),
    ("stop-member", true),
    ("start-member", true),
];

pub(super) fn carries(action: &Value) -> bool {
    action.as_str().is_some_and(|a| ACTIONS.contains(&a))
}

pub(in crate::k3s) fn action(verb: &str, planned: &str) -> Option<&'static str> {
    let action = match verb {
        "plan" => planned,
        "node drain" => "node-drain",
        "node uncordon" => "node-uncordon",
        "node remove" => "node-remove",
        "node replace" => "node-replace",
        _ => return None,
    };
    ACTIONS[..4].iter().copied().find(|a| *a == action)
}

fn verb(action: &str) -> &'static str {
    match action {
        "node-drain" => "node drain",
        "node-uncordon" => "node uncordon",
        "node-remove" => "node remove",
        _ => "node replace",
    }
}

fn failure(name: &str) -> Failure {
    match name {
        "configuration" => Failure::Configuration,
        "readiness" => Failure::Readiness,
        "ownership" => Failure::Ownership,
        "transport" => Failure::Transport,
        "busy" => Failure::Busy,
        "bound" => Failure::Bound,
        "timeout" => Failure::Timeout,
        "capability" => Failure::Capability,
        _ => Failure::Integrity,
    }
}

fn refusal(failure: Failure, boundary: &'static str, detail: String) -> Refusal {
    Refusal {
        failure,
        boundary: Some(boundary),
        detail: Some(detail),
    }
}

fn rule(refused: crate::k3s::release::Refusal) -> Refusal {
    refusal(failure(refused.failure), refused.boundary, refused.detail)
}

fn role(role: Role) -> &'static str {
    match role {
        Role::Server => "server",
        Role::Agent => "agent",
    }
}

fn step_action(tag: &str) -> String {
    format!("lifecycle:node-{tag}")
}

fn mutation(tag: &str) -> bool {
    TAGS.iter().any(|(t, m)| *t == tag && *m)
}

fn projection(scope: &Value, declared: &Target, owner: Option<&Value>) -> Value {
    let members: Vec<Value> = declared
        .members
        .iter()
        .map(|m| {
            json!({"name":m.name,"role":role(m.role),"machine":m.machine,
                "node_ip":m.node_ip.to_string()})
        })
        .collect();
    json!({"name":scope["target"],"members":members,"removed":removed(owner)})
}

pub(super) fn removal_target(observations: &[Value], removed: &Value) -> Value {
    let members: Vec<Value> = observations
        .iter()
        .filter(|o| {
            o["event"]["type"] == "server-recipe" && o["event"]["recipe"]["member"] == *removed
        })
        .map(|o| {
            json!({"name":removed["member"],"role":"server",
                "node_ip":o["event"]["recipe"]["config"]["node-ip"]})
        })
        .collect();
    json!({"members":members})
}

pub(in crate::k3s) fn uncreated(
    root: &std::path::Path,
    scope: &Value,
    declared: &Target,
    action: &str,
    member: &str,
) -> std::result::Result<(), Refusal> {
    let hash = scope["hash"].as_str().ok_or(Failure::Integrity)?;
    let owner = root
        .join("state/infrastructure/targets")
        .join(hash)
        .join("owner.json");
    match std::fs::symlink_metadata(&owner) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Failure::Storage.into()),
    }
    let target = scope["target"].as_str().unwrap_or("");
    members::admit_operand(&projection(scope, declared, None), verb(action), member)
        .map_err(rule)?;
    Err(refusal(
        Failure::Configuration,
        "declaration",
        format!("target {target} has no recorded creation; run k3s create {target}"),
    ))
}

pub(in crate::k3s) fn joinable(
    root: &std::path::Path,
    scope: &Value,
    declared: &Target,
    member: &str,
) -> std::result::Result<(), Refusal> {
    let Ok(mut store) = super::Store::new(
        root.to_path_buf(),
        scope.clone(),
        30_000,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    ) else {
        return Ok(());
    };
    let context = store.agent_context();
    store.release(tokio::time::Instant::now() + Duration::from_secs(5))?;
    let Ok((previous, _)) = context else {
        return Ok(());
    };
    let owner = previous.first().map(|s| s.owner.clone());
    members::admit_operand(
        &projection(scope, declared, owner.as_ref()),
        "node join",
        member,
    )
    .map_err(rule)
}

fn removed(owner: Option<&Value>) -> Value {
    owner
        .map(|o| o["removed"].clone())
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]))
}

fn writer(context: &rpc::Context<'_>, owner: &Value) -> Option<String> {
    let registry = context.selected.declaration.registry.as_ref()?;
    Some(
        owner["writer"]["member"]
            .as_str()
            .map_or_else(|| registry.member.clone(), str::to_owned),
    )
}

fn effect(action: &str, member: Option<&str>) -> Value {
    json!({"action":action,"image":null,"member":member,"release":null})
}

fn effects(
    declared: &Target,
    action: &str,
    member: &str,
    writer: Option<&str>,
    to: Option<&str>,
    same_machine: bool,
) -> Vec<Value> {
    let server = declared
        .members
        .iter()
        .any(|m| m.name == member && m.role == Role::Server);
    match action {
        "node-drain" if writer == Some(member) => vec![
            effect("stop-writer", Some(member)),
            effect("move-writer", to),
            effect("evict", Some(member)),
        ],
        "node-drain" => vec![effect("evict", Some(member))],
        "node-uncordon" => vec![effect("uncordon", Some(member))],
        "node-remove" => {
            let mut effects = vec![
                effect("stop-services", Some(member)),
                effect("delete-node", Some(member)),
            ];
            if server {
                effects.push(effect("remove-etcd-member", Some(member)));
            }
            if declared.registry.is_some() {
                effects.push(effect("remove-device", Some(member)));
            }
            effects.push(effect("rebind-claims", None));
            effects
        }
        _ => {
            let mut effects = Vec::new();
            if !same_machine {
                effects.push(effect("prepare-host", Some(member)));
            }
            effects.extend([
                effect("join", Some(member)),
                effect("start-services", Some(member)),
                effect("rebind-claims", None),
                effect("rebind-declaration", Some(member)),
            ]);
            effects
        }
    }
}

fn plan(scope: &Value, action: &str, member: &str, observed: bool) -> Value {
    json!({"format_version":1,"scope":scope,"view":"plan","action":action,"observed":observed,
        "member":member,"members":[],"effects":[],"pods":[],"checks":null,"writer_move":null,
        "transition":null,"refusals":[],"approval":null})
}

pub(in crate::k3s) fn intended(
    scope: &Value,
    declared: &Target,
    action: &str,
    member: &str,
) -> std::result::Result<Value, Refusal> {
    require(
        declared.members.iter().any(|m| m.name == member),
        Failure::Configuration,
    )?;
    let writer = declared.registry.as_ref().map(|r| r.member.as_str());
    let mut value = plan(scope, action, member, false);
    value["effects"] = json!(effects(declared, action, member, writer, None, false));
    value["unknown"] = json!([
        "ownership",
        "history",
        "writer",
        "reachability",
        "pods",
        "quorum"
    ]);
    Ok(value)
}

pub(in crate::k3s) struct Leaf<'a> {
    pub action: &'static str,
    pub member: &'a str,
    pub approve: Option<&'a str>,
    pub plan: bool,
    pub table: bool,
}

pub(in crate::k3s) fn command(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    leaf: Leaf<'_>,
) -> std::result::Result<Output, Refusal> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Failure::Bound)?;
    let cancelled = policy.cancellation.clone();
    let result = runtime.block_on(async {
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| Failure::Bound)?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| Failure::Bound)?;
        let work = run(project, policy, target, &leaf);
        tokio::pin!(work);
        loop {
            tokio::select! {
                result = &mut work => break result,
                _ = interrupt.recv() => cancelled.cancel(),
                _ = terminate.recv() => cancelled.cancel(),
            }
        }
    });
    runtime.shutdown_background();
    let (value, status) = result?;
    let payload = if value["view"] == "plan" {
        super::render(&value, leaf.table)?
    } else {
        encode(
            &value,
            if leaf.table {
                Format::Table
            } else {
                Format::Json
            },
        )
        .map_err(rule)?
    };
    Ok(Output { payload, status })
}

struct Admitted {
    owner: Value,
    survivors: Vec<Value>,
    member: Value,
    first: Option<Value>,
    writer: Option<String>,
    target: Value,
}

fn settled(context: &rpc::Context<'_>, previous: &[Snapshot]) -> std::result::Result<(), Refusal> {
    let target = context.scope["target"].as_str().unwrap_or("");
    for snapshot in previous {
        let report = super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?;
        if super::session::settled(&report).is_err() {
            let operation = snapshot.request["operation"].as_str().unwrap_or("");
            return Err(refusal(
                Failure::Busy,
                "operation",
                format!(
                    "{operation} of target {target} is unsettled; run k3s operation show {target} {operation}, and if no broil process runs it, k3s operation resume {target} {operation}"
                ),
            ));
        }
    }
    Ok(())
}

fn publications(context: &rpc::Context<'_>, previous: &[Snapshot]) -> Result<Value> {
    let mut summaries = Vec::new();
    for snapshot in previous {
        let publishing: Vec<&Value> = snapshot
            .steps
            .iter()
            .filter(|s| {
                matches!(
                    s["action"].as_str(),
                    Some("lifecycle:publish-identity" | "lifecycle:publish-member")
                )
            })
            .map(|s| &s["recipient"]["member"])
            .collect();
        if publishing.is_empty() {
            continue;
        }
        let report = super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?;
        for server in publishing {
            summaries.push(json!({"operation":snapshot.request["operation"],
                "sequence":snapshot.request["sequence"],"action":snapshot.request["action"],
                "outcome":report["outcome"],"publishes":server}));
        }
    }
    Ok(json!(summaries))
}

async fn admin_access(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    admitted: &Admitted,
    cleanup: &mut bool,
) -> std::result::Result<(), Refusal> {
    let first = admitted.first.as_ref().ok_or(Failure::Readiness)?;
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let missing = super::access::published(
        context,
        &admitted.owner,
        first,
        &operation,
        &attempt,
        cleanup,
    )
    .await?;
    if missing.is_none() {
        return Ok(());
    }
    let server = first["member"].as_str().unwrap_or("");
    let failed = members::admin_access_operation(server, &publications(context, previous)?);
    Err(rule(members::admin_access_refusal(
        context.scope["target"].as_str().unwrap_or(""),
        server,
        failed.as_deref(),
    )))
}

fn pending(
    admitted: &Admitted,
    previous: &[Snapshot],
    leaf: &str,
) -> std::result::Result<(), Refusal> {
    let mut target = admitted.target.clone();
    let recorded = admitted.owner["members"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for member in target["members"].as_array_mut().into_iter().flatten() {
        member["node_uid"] = recorded
            .iter()
            .find(|m| m["member"] == member["name"])
            .map_or(Value::Null, |m| m["node_uid"].clone());
    }
    let generations = pending_generations(&admitted.owner, previous)?;
    let member = admitted.member["member"].as_str().unwrap_or("");
    members::pending_generation(&target, leaf, member, &generations).map_err(rule)
}

fn admit(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    action: &str,
    member: &str,
) -> std::result::Result<Admitted, Refusal> {
    let name = context.scope["target"].as_str().unwrap_or("").to_owned();
    settled(context, previous)?;
    let owner = previous.first().map(|s| s.owner.clone());
    let target = projection(&context.scope, context.selected.declaration, owner.as_ref());
    if action != "node-replace" || replacing(previous, member).is_none() {
        members::admit_operand(&target, verb(action), member).map_err(rule)?;
    }
    let Some(owner) = owner.filter(|o| !o["cluster"].is_null()) else {
        return Err(refusal(
            Failure::Configuration,
            "declaration",
            format!("target {name} has no recorded creation; run k3s create {name}"),
        ));
    };
    if !matches!(action, "node-replace" | "node-uncordon")
        && owner["fingerprints"] != context.owner_fingerprints
    {
        let doing = match action {
            "node-drain" => "draining",
            "node-uncordon" => "uncordoning",
            _ => "removing",
        };
        return Err(refusal(
            Failure::Configuration,
            "declaration",
            format!(
                "the declaration of target {name} changed since creation; revert it before {doing} {member}"
            ),
        ));
    }
    let survivors = super::survivors(&owner)?;
    require(
        owner["participants_sha256"] == super::participants(&json!(survivors))?,
        Failure::Ownership,
    )?;
    let entry = owner["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|m| m["member"] == member)
        .cloned()
        .ok_or(Failure::Ownership)?;
    if action != "node-replace" {
        require(entry["node_uid"].is_string(), Failure::Readiness)?;
    }
    let first = survivors
        .iter()
        .find(|m| m["role"] == "server" && m["member"] != member)
        .or_else(|| survivors.iter().find(|m| m["role"] == "server"))
        .cloned();
    let writer = writer(context, &owner);
    Ok(Admitted {
        owner,
        survivors,
        member: entry,
        first,
        writer,
        target,
    })
}

#[allow(clippy::too_many_arguments)]
fn recipe(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    operation: &str,
    action: &str,
    phase: Value,
    reachability: &str,
    writer_move: Value,
    transition: Value,
    decision: Option<&Value>,
) -> Result<Value> {
    let first = admitted.first.clone().ok_or(Failure::Readiness)?;
    let recipe = json!({"scope":context.scope,"owner":admitted.owner["owner"],"operation":operation,
        "cluster":admitted.owner["cluster"],"first_server":first,
        "version":context.selected.declaration.version,"action":action,"phase":phase,
        "member":admitted.member,"participants":admitted.survivors,"removed":removed(Some(&admitted.owner)),
        "writer":admitted.owner["writer"].clone(),"reachability":reachability,"writer_move":writer_move,
        "transition":transition,
        "decision_sha256":decision.map(|d| hash("broil-infra-approval-v1", d)).transpose()?,
        "profile_sha256":context.fingerprints["profile_sha256"]});
    require(
        super::canonical(&recipe)?.len() <= RECIPE_LIMIT,
        Failure::Bound,
    )?;
    Ok(recipe)
}

fn request(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    operation: &str,
    action: &str,
    sequence: u64,
) -> Result<Value> {
    let members = json!(admitted.survivors);
    Ok(
        json!({"schema":2,"kind":"request","scope":context.scope,"owner":admitted.owner["owner"],
        "operation":operation,"created_ms":now()?,"sequence":sequence,"action":action,
        "members":members,"cluster":admitted.owner["cluster"],"resources":[],
        "config":context.config,"references":context.references,"consumer":null,
        "fingerprints":context.fingerprints,"participants_sha256":super::participants(&members)?,
        "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
        "step_timeout_ms":context.selected.step_timeout.seconds*1000}),
    )
}

fn steps(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    action: &str,
    writer: bool,
    reachability: &str,
) -> std::result::Result<usize, Refusal> {
    let servers = admitted
        .survivors
        .iter()
        .filter(|m| m["role"] == "server")
        .count();
    let replicas = if context.selected.declaration.registry.is_some() {
        admitted.survivors.len()
    } else {
        0
    };
    let phase = match action {
        "node-replace" if admitted.survivors.contains(&admitted.member) => json!("complete"),
        "node-replace" => json!("begin"),
        _ => Value::Null,
    };
    let layout = json!({"action":action,"phase":phase,
        "participants":admitted.survivors.len(),"servers":servers,"writer":writer,
        "reachability":reachability,"replica_members":replicas,
        "member_role":admitted.member["role"],
        "step_timeout_ms":context.selected.step_timeout.seconds * 1000});
    members::observation_count(&layout).map_err(rule)?;
    members::step_count(&layout).map_err(rule)
}

struct Observed {
    reachable: bool,
    node: Value,
    observed_ms: u64,
}

#[allow(clippy::too_many_arguments)]
async fn observe(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    action: &str,
    request: &Value,
    recipe: &Value,
    attempt: &str,
    count: usize,
    every: bool,
    cleanup: &mut bool,
) -> Result<Observed> {
    let machine = admitted.member["machine"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    let reachable = match context.probe(machine).await {
        Ok(mut route) => {
            route["node_uid"] = admitted.member["node_uid"].clone();
            require(route == admitted.member, Failure::Ownership)?;
            true
        }
        Err(Failure::Transport) => false,
        Err(failure) => return Err(failure),
    };
    let mut node = Value::Null;
    if matches!(action, "node-drain" | "node-remove") {
        let first = admitted.first.as_ref().ok_or(Failure::Readiness)?;
        let index = admitted
            .survivors
            .iter()
            .position(|m| m == first)
            .ok_or(Failure::Integrity)?;
        let every = every || action == "node-remove";
        let mut pages: Vec<Value> = Vec::new();
        let mut after = Value::Null;
        while pages.len() < 15 {
            let payload = action_payload(recipe, Value::Null, after, Some("classify"));
            let deadline = context.clock.deadline().min(
                tokio::time::Instant::now()
                    + Duration::from_secs(context.selected.step_timeout.seconds),
            );
            let observed = network::invoke(
                context,
                &FAMILY,
                &network::read_binding(request, attempt, count as u64, index)?,
                "observe-drain",
                &payload,
                deadline,
                None,
            )
            .await;
            *cleanup |= network::unclean(&observed.transport);
            let result = observed
                .response
                .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
            require(result["status"] == "ok", super::server::refused(&result))?;
            require(result["member"].is_object(), Failure::Integrity)?;
            after = result["member"]["next"].clone();
            pages.push(result["member"].clone());
            if !every || after.is_null() {
                break;
            }
        }
        node = pages.first().cloned().ok_or(Failure::Integrity)?;
        let mut seen = Vec::new();
        for pod in pages
            .iter()
            .flat_map(|p| p["pods"].as_array().into_iter().flatten())
        {
            if !seen
                .iter()
                .any(|s: &Value| s["namespace"] == pod["namespace"] && s["pod"] == pod["pod"])
            {
                seen.push(pod.clone());
            }
        }
        node["pods"] = json!(seen);
    }
    Ok(Observed {
        reachable,
        node,
        observed_ms: now()?,
    })
}

fn pods<'v>(node: &'v Value, classes: &'v [&str]) -> impl Iterator<Item = &'v Value> {
    node["pods"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(move |p| p["class"].as_str().is_some_and(|c| classes.contains(&c)))
}

fn action_payload(recipe: &Value, pods: Value, after: Value, view: Option<&str>) -> Value {
    json!({"recipe":recipe,"expected":{"node_uid":recipe["member"]["node_uid"],"pods":pods,
        "after":after,"view":view},"wait_ms":null})
}

fn pod_limit(name: &str, node: &Value) -> Option<Refusal> {
    let total = node["total"].as_u64()?;
    (total > members::POD_LIMIT as u64).then(|| {
        refusal(
            Failure::Bound,
            "size",
            format!(
                "{name} has {total} pods; the limit is {}",
                members::POD_LIMIT
            ),
        )
    })
}

fn not_drained(target: &str, member: &str, count: usize) -> Refusal {
    let pods = if count == 1 { "pod" } else { "pods" };
    refusal(
        Failure::Readiness,
        "not-drained",
        format!(
            "{member} still runs {count} evictable {pods}; run k3s node drain {target} {member}"
        ),
    )
}

fn endpoint(context: &rpc::Context<'_>, member: &str) -> Option<Refusal> {
    let declared = &context.selected.declaration;
    let selected = context
        .selected
        .members
        .iter()
        .find(|m| m.declaration.name == member)?;
    let node = selected.declaration.node_ip.to_string();
    let machine = selected.machine.settings.address.as_deref();
    for (field, endpoint, loss) in [
        (
            "api.endpoint",
            &declared.api.endpoint,
            "the cluster's API would be lost",
        ),
        (
            "registration_endpoint",
            &declared.registration_endpoint,
            "members would lose their join endpoint",
        ),
    ] {
        let host = endpoint.authority.host.as_str();
        let kind = if host == node {
            "node"
        } else if machine == Some(host) {
            "machine"
        } else {
            continue;
        };
        return Some(refusal(
            Failure::Configuration,
            "declaration",
            format!(
                "{field} {} is {member}'s {kind} address, so {loss} when {member}'s machine goes; endpoints are fixed at creation, so {member} can be drained but not removed or replaced in this target",
                crate::k3s::origin(endpoint)
            ),
        ));
    }
    None
}

struct Round {
    healthy: Vec<String>,
    others: usize,
    slots: Vec<Value>,
}

fn sources(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    admitted: &Admitted,
    operation: &str,
    attempt: &str,
) -> Result<Vec<Value>> {
    let first = admitted.first.clone().ok_or(Failure::Readiness)?;
    let mut events =
        network::source_recipes(previous, context, &admitted.owner, operation, attempt)?;
    for event in &mut events {
        if event["type"] == "agent-join-recipe" {
            event["recipe"]["source"] = first.clone();
        }
    }
    Ok(events)
}

#[allow(clippy::too_many_arguments)]
async fn quorum(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    request: &Value,
    attempt: &str,
    count: usize,
    sources: &[Value],
    cleanup: &mut bool,
) -> Result<Round> {
    let mut round = Round {
        healthy: Vec::new(),
        others: 0,
        slots: Vec::new(),
    };
    for event in sources
        .iter()
        .filter(|e| e["type"] == "server-recipe" && e["recipe"]["member"] != admitted.member)
    {
        let member = &event["recipe"]["member"];
        let index = admitted
            .survivors
            .iter()
            .position(|m| m == member)
            .ok_or(Failure::Ownership)?;
        round.others += 1;
        let payload = json!({"recipe_kind":event["recipe_kind"],"recipe":event["recipe"],
            "identity":null,"membership":null,"removed":null});
        let deadline = context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(context.selected.step_timeout.seconds),
        );
        let observed = super::server::invoke(
            context,
            &network::read_binding(request, attempt, count as u64, index)?,
            "observe-membership",
            &payload,
            deadline,
            None,
        )
        .await;
        *cleanup |= network::unclean(&observed.transport);
        let healthy = observed.result.as_ref().is_some_and(|result| {
            let view = &result["membership"];
            result["status"] == "ok"
                && view["healthy"] == true
                && view["cluster"] == request["cluster"]
                && view["node_uid"] == member["node_uid"]
                && view["observer"] == member["machine"]
        });
        round
            .slots
            .push(json!({"observer":member["machine"],"healthy":healthy}));
        if healthy {
            round
                .healthy
                .push(member["member"].as_str().unwrap_or("").to_owned());
        }
    }
    Ok(round)
}

fn readiness_input(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    view: Value,
    slots: Value,
) -> Result<Value> {
    let mut expected = Vec::new();
    for member in &admitted.survivors {
        let (labels, taints) = network::declared(context, member)?;
        expected.push(json!({"member":member,"node_uid":member["node_uid"],
            "role":member["role"],"labels":labels,"taints":taints}));
    }
    Ok(
        json!({"member":admitted.member["member"],"expected":expected,"view":view,
        "round":slots}),
    )
}

#[allow(clippy::too_many_arguments)]
async fn readiness(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    request: &Value,
    attempt: &str,
    count: usize,
    sources: &[Value],
    round: &Round,
    cleanup: &mut bool,
) -> Result<std::result::Result<(), Refusal>> {
    let input = match sources.iter().find(|e| e["type"] == "agent-join-recipe") {
        Some(agent) => {
            let first = admitted.first.as_ref().ok_or(Failure::Readiness)?;
            let index = admitted
                .survivors
                .iter()
                .position(|m| m == first)
                .ok_or(Failure::Integrity)?;
            let payload = json!({"recipe":agent["recipe"],"identity":null,"agent_view":null});
            let deadline = context.clock.deadline().min(
                tokio::time::Instant::now()
                    + Duration::from_secs(context.selected.step_timeout.seconds),
            );
            let observed = super::server::invoke(
                context,
                &network::read_binding(request, attempt, count as u64, index)?,
                "observe-agent-membership",
                &payload,
                deadline,
                None,
            )
            .await;
            *cleanup |= network::unclean(&observed.transport);
            let result = observed
                .result
                .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
            require(result["status"] == "ok", super::server::refused(&result))?;
            readiness_input(context, admitted, result["agent_view"].clone(), Value::Null)?
        }
        None => readiness_input(context, admitted, Value::Null, json!(round.slots))?,
    };
    Ok(members::readiness_read(&input).map_err(rule))
}

#[allow(clippy::too_many_arguments)]
async fn candidate(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    request: &Value,
    attempt: &str,
    count: usize,
    recipe: &Value,
    cleanup: &mut bool,
) -> Result<std::result::Result<String, Refusal>> {
    let objects = replication::origin_uids(recipe);
    let deadline = || {
        context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(context.selected.step_timeout.seconds),
        )
    };
    let first = admitted.first.as_ref().ok_or(Failure::Readiness)?;
    let index = |member: &Value| {
        admitted
            .survivors
            .iter()
            .position(|m| m["member"] == member["member"])
            .ok_or(Failure::Integrity)
    };
    let api = network::invoke(
        context,
        &replication::FAMILY,
        &network::read_binding(request, attempt, count as u64, index(first)?)?,
        "inspect-objects",
        &replication::read_payload(recipe, None, &objects),
        deadline(),
        None,
    )
    .await;
    *cleanup |= network::unclean(&api.transport);
    let nodes = api
        .response
        .filter(|r| r["status"] == "ok")
        .map(|r| r["node"].clone())
        .unwrap_or(Value::Null);
    let mut facts = Vec::new();
    for (position, member) in recipe["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .enumerate()
    {
        if member["member"] == admitted.member["member"] {
            continue;
        }
        let read = network::invoke(
            context,
            &replication::FAMILY,
            &network::read_binding(request, attempt, count as u64, index(member)?)?,
            "inspect-replication",
            &replication::read_payload(recipe, Some(position), &objects),
            deadline(),
            None,
        )
        .await;
        *cleanup |= network::unclean(&read.transport);
        let Some(result) = read.response.filter(|r| r["status"] == "ok") else {
            continue;
        };
        let node = nodes
            .as_array()
            .into_iter()
            .flatten()
            .find(|n| n["member"] == member["member"])
            .map_or(Value::Null, |n| n["node"].clone());
        facts.push(json!({"member":member["member"],"ready":node == "ready",
            "cordoned":node != "ready","replica":result["replication"]["state"],
            "service_running":result["replication"]["service"] == "running"}));
    }
    let old = admitted.member["member"].as_str().unwrap_or("");
    Ok(members::writer_candidate(&admitted.target, old, &json!(facts)).map_err(rule))
}

const MOVE: [(&str, &str); 8] = [
    ("stop-writer", "first"),
    ("scan-replica", "from"),
    ("inspect-replication", "from"),
    ("inspect-replication", "to"),
    ("configure-replication", "from"),
    ("configure-replication", "to"),
    ("start-writer", "first"),
    ("inspect-objects", "first"),
];

fn move_payload(
    recipe: &Value,
    member_recipe: &Value,
    owner: &Value,
    position: usize,
    step_timeout_ms: &Value,
) -> Result<Value> {
    let (tag, role) = MOVE[position];
    let moved = &member_recipe["writer_move"];
    let to = recipe["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .position(|m| m["member"] == moved["to"])
        .ok_or(Failure::Ownership)?;
    let device = if matches!(position, 2 | 3 | 5 | 6 | 7) {
        recipe["devices"][to]["device_id"].clone()
    } else {
        Value::Null
    };
    let moves = member_recipe["writer"]["moves"].as_u64().unwrap_or(0);
    let generation = 1 + 2 * moves;
    let generation = match tag {
        "stop-writer" => json!(generation),
        "start-writer" => json!(generation + 1),
        _ => Value::Null,
    };
    let wait = match tag {
        "stop-writer" | "scan-replica" | "inspect-replication" | "inspect-objects" => {
            json!(
                step_timeout_ms
                    .as_u64()
                    .ok_or(Failure::Integrity)?
                    .min(7_200_000)
            )
        }
        _ => Value::Null,
    };
    let member = if role == "first" {
        Value::Null
    } else {
        moved[role].clone()
    };
    let resource = if matches!(tag, "scan-replica" | "configure-replication") {
        replication_resource(owner, &json!({"member":member}))?
    } else {
        Value::Null
    };
    Ok(json!({"recipe":recipe,
        "expected":{"objects":replication::origin_uids(recipe),"device":device,
            "writer_generation":generation},
        "resource":resource,"preflight":null,"wait_ms":wait,"member":member}))
}

async fn writer_drain(
    context: rpc::Context<'_>,
    mut local: Local,
    previous: &[Snapshot],
    admitted: Admitted,
    approve: Option<&str>,
) -> std::result::Result<(Value, i32), Refusal> {
    let action = "node-drain";
    let name = admitted.member["member"].as_str().unwrap_or("").to_owned();
    let target = context.scope["target"].as_str().unwrap_or("").to_owned();
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let count = steps(&context, &admitted, action, true, "reachable")?;
    let sequence = local.work(|store| store.next_sequence()).await?;
    let request = request(&context, &admitted, &operation, action, sequence)?;
    let first = admitted.first.clone().ok_or(Failure::Readiness)?;
    let guess = recipe(
        &context,
        &admitted,
        &operation,
        action,
        Value::Null,
        "reachable",
        Value::Null,
        Value::Null,
        None,
    )?;
    let mut cleanup = false;
    let assessed: std::result::Result<_, Refusal> = async {
        let (replicated, _) = replication::maintenance_recipe(
            &context,
            previous,
            &admitted.owner,
            &operation,
            "move",
            &first,
        )?
        .ok_or(Failure::Configuration)?;
        let observed = observe(
            &context,
            &admitted,
            action,
            &request,
            &guess,
            &attempt,
            count,
            false,
            &mut cleanup,
        )
        .await?;
        let mut recipes = Vec::new();
        if !observed.reachable {
            recipes = sources(&context, previous, &admitted, &operation, &attempt)?;
            let round = quorum(
                &context,
                &admitted,
                &request,
                &attempt,
                count,
                &recipes,
                &mut cleanup,
            )
            .await?;
            readiness(
                &context,
                &admitted,
                &request,
                &attempt,
                count,
                &recipes,
                &round,
                &mut cleanup,
            )
            .await??;
        }
        if let Some(refused) = pod_limit(&name, &observed.node) {
            return Err(refused);
        }
        let to = candidate(
            &context,
            &admitted,
            &request,
            &attempt,
            count,
            &replicated,
            &mut cleanup,
        )
        .await??;
        let writer_move = json!({"from":name,"loss_possible":!observed.reachable,"to":to});
        let effects = effects(
            context.selected.declaration,
            action,
            &name,
            Some(&name),
            Some(&to),
            false,
        );
        let decision = decision(
            &context,
            &admitted,
            action,
            &observed,
            &Value::Null,
            &effects,
            &writer_move,
            &Value::Null,
        )?;
        let Some(approve) = approve else {
            return Err(refusal(
                Failure::Ownership,
                "approval-required",
                format!(
                    "{name} is the registry writer, so this moves the writer; run k3s plan {target} --action node-drain --member {name} --observe"
                ),
            ));
        };
        members::check_approval(approve, &decision).map_err(rule)?;
        Ok((decision, writer_move, replicated, observed.reachable, recipes))
    }
    .await;
    local.cleanup_unknown |= cleanup;
    let (decision, writer_move, mut replicated, reachable, recipes) = match assessed {
        Ok(assessed) => assessed,
        Err(refused) => {
            let _ = local.finish(&context.clock).await;
            return Err(refused);
        }
    };
    let reachability = if reachable {
        "reachable"
    } else {
        "unreachable"
    };
    let count = steps(&context, &admitted, action, true, reachability)?;
    if !reachable {
        let index = replicated["members"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .position(|m| m["member"] == name.as_str())
            .ok_or(Failure::Ownership)?;
        let device = replicated["devices"][index]["device_id"].clone();
        require(device.is_string(), Failure::Readiness)?;
        replicated["detached"] = json!([device]);
    }
    let member_recipe = recipe(
        &context,
        &admitted,
        &operation,
        action,
        Value::Null,
        reachability,
        writer_move,
        Value::Null,
        Some(&decision),
    )?;
    let store = store_usage(&context, previous, &admitted.survivors, 1)?;
    let mut events = recipes;
    events.push(json!({"type":"replication-recipe","recipe":replicated}));
    let mut session = begin(
        context,
        local,
        &admitted,
        request,
        &member_recipe,
        events,
        &attempt,
        count,
    )
    .await?;
    let mut fields = json!({"member":name,"cordoned":false,"unreachable":!reachable,
        "evicted":[],"blocked":[],"writer_move":null});
    let result = Box::pin(session.drain(&member_recipe, &mut fields)).await;
    let detail = session.local.failure_detail;
    let snapshot = session.local.complete(result, &session.context.clock).await;
    let (snapshot, status) = match snapshot {
        Ok(snapshot) => (Some(snapshot), 0),
        Err(failure) => (failure.snapshot.map(|s| *s), 1),
    };
    let value = report(
        &session.context,
        snapshot.as_ref(),
        store,
        action,
        &name,
        detail,
        fields,
    )?;
    Ok((value, status))
}

fn replication_resource(owner: &Value, member: &Value) -> Result<Value> {
    let id = replication::replication_id(member["member"].as_str().ok_or(Failure::Integrity)?)?;
    owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == id.as_str())
        .cloned()
        .ok_or(Failure::Ownership)
}

fn replica_payload(
    recipe: Option<&Value>,
    member: &Value,
    step_timeout_ms: &Value,
) -> Result<Value> {
    let Some(recipe) = recipe else {
        return device_payload(None, &Value::Null, member, member);
    };
    let index = recipe["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .position(|m| m["member"] == member["member"])
        .ok_or(Failure::Ownership)?;
    let wait = step_timeout_ms
        .as_u64()
        .ok_or(Failure::Integrity)?
        .min(7_200_000);
    Ok(json!({"recipe":recipe,
        "expected":{"objects":replication::origin_uids(recipe),
            "device":recipe["devices"][index]["device_id"],"writer_generation":null},
        "resource":null,"preflight":null,"wait_ms":wait,"member":member["member"]}))
}

fn device_payload(
    recipe: Option<&Value>,
    resource: &Value,
    removed: &Value,
    recipient: &Value,
) -> Result<Value> {
    let Some(recipe) = recipe else {
        return Ok(
            json!({"recipe":null,"expected":null,"resource":null,"preflight":null,
            "wait_ms":null,"member":recipient["member"]}),
        );
    };
    let index = recipe["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .position(|m| m["member"] == removed["member"])
        .ok_or(Failure::Ownership)?;
    Ok(json!({"recipe":recipe,
        "expected":{"objects":replication::origin_uids(recipe),
            "device":recipe["devices"][index]["device_id"],"writer_generation":null},
        "resource":resource,"preflight":null,"wait_ms":null,"member":recipient["member"]}))
}

fn removal_view(
    context: &rpc::Context<'_>,
    members: &[Value],
    removed: &Value,
    cluster: &Value,
    view: &Value,
) -> Result<()> {
    require(
        view["cluster"] == *cluster
            && view["foreign"].as_array().is_some_and(Vec::is_empty)
            && view["members"]
                .as_array()
                .is_some_and(|items| items.len() == members.len()),
        Failure::Ownership,
    )?;
    for (index, expected) in members.iter().enumerate() {
        let item = &view["members"][index];
        require(item["member"] == *expected, Failure::Ownership)?;
        if expected == removed {
            require(item["present"] == false, Failure::Readiness)?;
            continue;
        }
        require(
            item["present"] == true
                && item["uid"] == expected["node_uid"]
                && item["ready"] == true
                && item["roles"] == json!([expected["role"]]),
            Failure::Readiness,
        )?;
        let (labels, taints) = network::declared(context, expected)?;
        require(
            item["labels"] == labels && item["taints"] == taints,
            Failure::Ownership,
        )?;
    }
    Ok(())
}

fn successor(old: &Value, recipe: &Value, operation: &Value) -> Result<Value> {
    let member = &recipe["member"];
    let mut owner = old.clone();
    owner["previous_generation"] = old["generation"].clone();
    owner["generation"] = json!(fresh()?);
    owner["created_ms"] = json!(now()?);
    let mut removed = old["removed"].as_array().cloned().unwrap_or_default();
    removed.push(
        json!({"member":member["member"],"machine":member["machine"],
        "operation":operation}),
    );
    owner["removed"] = json!(removed);
    owner["maintained"] = json!(true);
    if old.get("writer").is_none() {
        owner["writer"] = Value::Null;
    }
    owner["participants_sha256"] = json!(super::participants(&json!(super::survivors(&owner)?))?);
    let acting = super::survivors(old)?
        .into_iter()
        .find(|m| m["role"] == "server")
        .ok_or(Failure::Integrity)?;
    if acting == *member {
        for resource in owner["resources"]
            .as_array_mut()
            .ok_or(Failure::Integrity)?
            .iter_mut()
            .filter(|r| r["kind"] == "issuer" || r["kind"] == "registry-auth")
        {
            resource["machine"] = recipe["first_server"]["machine"].clone();
        }
    }
    Ok(owner)
}

pub(super) fn pending_generations(owner: &Value, previous: &[Snapshot]) -> Result<Vec<Value>> {
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    let succeeded = |s: &Snapshot| super::report::summary(s)["outcome"] == "succeeded";
    let mut pending = Vec::new();
    for resource in resources {
        let id = resource["id"].as_str().unwrap_or("");
        let origins = match resource["kind"].as_str() {
            Some("issuer") => {
                let issuer = id
                    .strip_prefix("issuer-object-")
                    .ok_or(Failure::Integrity)?;
                super::issuer::origins(previous, issuer, resource, &succeeded)
            }
            Some("registry-auth") => {
                let principal = super::registry_auth::principal_of(id);
                let replaced = principal.is_some_and(|(name, k)| {
                    resources.iter().any(|r| {
                        r["id"]
                            .as_str()
                            .and_then(super::registry_auth::principal_of)
                            .is_some_and(|(other, later)| other == name && later > k)
                    })
                });
                if replaced {
                    continue;
                }
                super::registry_auth::origins(previous, resource, &succeeded)
            }
            _ => continue,
        };
        let lifecycle = if resource["kind"] == "issuer" {
            &super::issuer::LIFECYCLE
        } else {
            super::registry_auth::lifecycle(resource).0
        };
        let abandoned = previous.iter().any(|s| {
            let carried = &s.request["resources"][0];
            let stage = s.observations.iter().find_map(|o| {
                (o["event"]["type"] == lifecycle.event("recipe"))
                    .then(|| o["event"]["recipe"]["stage"].as_str())
                    .flatten()
            });
            let effect = |tag: &str| {
                s.steps
                    .iter()
                    .any(|step| step["action"] == lifecycle.action(tag) && s.succeeded(step))
            };
            carried["id"] == resource["id"]
                && carried["generation"] == resource["generation"]
                && s.observations.iter().any(|o| {
                    o["event"]["type"] == "recovery" && o["event"]["choice"] == "operator-recovery"
                })
                && (s.request["action"] == format!("reconcile-{}", lifecycle.family.name)
                    && match stage {
                        Some("create") => !effect("create-object"),
                        Some("activate") => !effect("activate"),
                        _ => false,
                    }
                    || s.request["action"] == "prepare-state"
                        && s.request["consumer"]["action"] == lifecycle.consumer
                        && !succeeded(s))
        });
        if abandoned {
            continue;
        }
        let origins = origins?;
        if !origins["registration"].is_null() && origins["activation"].is_null() {
            pending.push(resource.clone());
        }
    }
    Ok(pending)
}

pub(super) fn replaced(old: &Value, owner: &Value, snapshot: &Snapshot) -> bool {
    let Some(recipe) = snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "member-recipe")
        .map(|o| &o["event"]["recipe"])
    else {
        return false;
    };
    let rebound = snapshot
        .steps
        .iter()
        .filter(|s| s["action"] == "rebind-claim")
        .collect::<Vec<_>>();
    let Ok(mut expected) = successor(old, recipe, &snapshot.request["operation"]) else {
        return false;
    };
    for key in ["generation", "created_ms", "lock_identity"] {
        expected[key] = owner[key].clone();
    }
    if snapshot.request["action"] == "node-drain" {
        return moved(old, owner, snapshot, recipe);
    }
    if snapshot.request["action"] == "rebind-declaration" {
        return declaration_rebound(old, owner, snapshot, recipe);
    }
    if snapshot.request["action"] == "node-replace" {
        return recipe["phase"] == "begin"
            && rebound.len() == snapshot.request["members"].as_array().map_or(0, Vec::len)
            && rebound.iter().all(|s| snapshot.succeeded(s))
            && replacement_begun(old, owner, snapshot, recipe);
    }
    snapshot.request["action"] == "node-remove"
        && old["removed"]
            .as_array()
            .is_none_or(|r| !r.iter().any(|r| r["member"] == recipe["member"]["member"]))
        && rebound.len() + 1 == snapshot.request["members"].as_array().map_or(0, Vec::len)
        && rebound.iter().all(|s| snapshot.succeeded(s))
        && *owner == expected
}

fn moved(old: &Value, owner: &Value, snapshot: &Snapshot, recipe: &Value) -> bool {
    let moved = &recipe["writer_move"];
    let mut expected = old.clone();
    for key in ["generation", "created_ms", "lock_identity"] {
        expected[key] = owner[key].clone();
    }
    expected["previous_generation"] = old["generation"].clone();
    expected["writer"] = json!({"member":moved["to"],"operation":snapshot.request["operation"],
        "moves":old["writer"]["moves"].as_u64().unwrap_or(0) + 1});
    if old.get("removed").is_none() {
        expected["removed"] = json!([]);
        expected["maintained"] = json!(false);
    }
    !moved.is_null()
        && snapshot.observations.iter().any(|o| {
            o["event"]["type"] == "writer-move"
                && o["event"]["from"] == moved["from"]
                && o["event"]["to"] == moved["to"]
        })
        && *owner == expected
}

fn checks(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    action: &str,
    observed: &Observed,
    round: Option<&Round>,
) -> (Vec<Refusal>, Value) {
    let target = context.scope["target"].as_str().unwrap_or("");
    let name = admitted.member["member"].as_str().unwrap_or("");
    let is_writer = admitted.writer.as_deref() == Some(name);
    let mut refusals = Vec::new();
    let mut checks = Value::Null;
    match action {
        "node-drain" => {
            if !is_writer && !observed.reachable {
                let facts = json!({"target":target,"member":name,"writer":false,
                    "reachability":"unreachable","known":true,"refusals":[]});
                if let Err(refused) = members::issues_approval(action, &facts) {
                    refusals.push(rule(refused));
                }
            }
            refusals.extend(pod_limit(name, &observed.node));
        }
        "node-remove" => {
            let count = observed.node["evictable"]
                .as_u64()
                .map_or(1, |n| n as usize);
            let blocking = pods(&observed.node, &["local-storage", "unmanaged"])
                .next()
                .is_some();
            let drained =
                observed.node["cordoned"] == true && count == 0 && !blocking && !is_writer;
            if !observed.reachable && !is_writer {
            } else if !drained {
                refusals.push(not_drained(target, name, count.max(usize::from(is_writer))));
            }
            let healthy: Vec<&str> = round
                .map(|r| r.healthy.iter().map(String::as_str).collect())
                .unwrap_or_default();
            if let Err(refused) = members::server_removal(&admitted.target, name, &healthy) {
                refusals.push(rule(refused));
            }
            if let Some(refused) = endpoint(context, name) {
                refusals.push(refused);
            }
            let servers = context
                .selected
                .declaration
                .members
                .iter()
                .filter(|m| m.role == Role::Server)
                .count();
            let quorum = round
                .filter(|_| admitted.member["role"] == "server")
                .map_or(Value::Null, |r| {
                    json!({"servers_after":r.others,"servers_before":r.others + 1,
                        "voters_healthy":r.healthy.len()})
                });
            checks = json!({"drained":drained,
                "one_server":admitted.member["role"] == "server" && servers == 1,
                "quorum":quorum,"unreachable":!observed.reachable});
        }
        _ => {}
    }
    (refusals, checks)
}

#[allow(clippy::too_many_arguments)]
fn decision(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    action: &str,
    observed: &Observed,
    checks: &Value,
    effects: &[Value],
    writer_move: &Value,
    transition: &Value,
) -> std::result::Result<Value, Refusal> {
    let members: Vec<Value> = admitted
        .survivors
        .iter()
        .map(|m| {
            json!({"name":m["member"],"route":m["route"],"node_uid":m["node_uid"],
                "observed_ms":observed.observed_ms})
        })
        .collect();
    members::decision(
        &json!({"schema":1,"scope":context.scope,"owner":admitted.owner["owner"],
        "local_generation":admitted.owner["generation"],"action":action,
        "member":{"name":admitted.member["member"],"machine":admitted.member["machine"],
            "node_uid":admitted.member["node_uid"]},
        "cluster":admitted.owner["cluster"],"members":members,
        "removed":removed(Some(&admitted.owner)),"writer":admitted.owner["writer"],
        "reachability":if observed.reachable {"reachable"} else {"unreachable"},
        "checks":checks,"writer_move":writer_move,"transition":transition,"effects":effects}),
    )
    .map_err(rule)
}

fn store_usage(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    survivors: &[Value],
    added: usize,
) -> Result<Value> {
    let path = context
        .project
        .broil_root
        .join("state/releases")
        .join(context.scope["hash"].as_str().ok_or(Failure::Integrity)?);
    let releases = if path.exists() {
        crate::k3s::release::store::enumerate(&path)
            .map_err(|_| Failure::Integrity)?
            .len()
    } else {
        0
    };
    let mut fullest = (Value::Null, 0usize);
    for member in survivors {
        let attempts: usize = previous
            .iter()
            .filter(|s| {
                s.request["members"]
                    .as_array()
                    .is_some_and(|m| m.iter().any(|m| m["machine"] == member["machine"]))
            })
            .map(|s| s.attempts.len())
            .sum::<usize>()
            + added;
        if fullest.0.is_null() || attempts > fullest.1 {
            fullest = (member["member"].clone(), attempts);
        }
    }
    let operations = previous.len() + added;
    let warning = operations >= 14_746 || releases >= 14_746 || fullest.1 >= 14_746;
    Ok(
        json!({"operations":operations,"limit":16_384,"releases":releases,
        "release_limit":16_384,"hosts":{"member":fullest.0,"attempts":fullest.1,"limit":16_384},
        "warning":warning}),
    )
}

fn report(
    context: &rpc::Context<'_>,
    snapshot: Option<&Snapshot>,
    store: Value,
    view: &str,
    member: &str,
    detail: Option<&str>,
    fields: Value,
) -> Result<Value> {
    let summary = snapshot.map(super::report::summary);
    let outcome = summary
        .as_ref()
        .map_or("unknown", |s| s["outcome"].as_str().unwrap_or("unknown"));
    let operation = summary
        .as_ref()
        .map_or(Value::Null, |s| s["operation"].clone());
    let recovery = match outcome {
        "succeeded" => json!({"choice":"none","operation":null,"subject":null}),
        _ if detail == Some("writer-move") => {
            json!({"choice":"operator-recovery","operation":operation,"subject":member})
        }
        "failed" | "cancelled" if detail.is_some() => {
            json!({"choice":"rerun","operation":operation,"subject":member})
        }
        "unknown" => json!({"choice":"resume","operation":operation,"subject":member}),
        _ => json!({"choice":"operator-recovery","operation":operation,"subject":member}),
    };
    let mut value = json!({"format_version":1,"scope":context.scope,"view":view,"outcome":outcome,
        "failure":summary.as_ref().map_or(json!("transport"), |s| s["failure"].clone()),
        "detail":detail,
        "completion_unknown":summary.as_ref().map_or(json!(true), |s| s["completion_unknown"].clone()),
        "cleanup_unknown":summary.as_ref().map_or(json!(false), |s| s["cleanup_unknown"].clone()),
        "truncated":false,"operations":summary.into_iter().collect::<Vec<_>>(),
        "recovery":recovery,"store":store});
    for (key, field) in fields.as_object().ok_or(Failure::Integrity)? {
        value[key.as_str()] = field.clone();
    }
    Ok(value)
}

async fn run(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    leaf: &Leaf<'_>,
) -> std::result::Result<(Value, i32), Refusal> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let (previous, _) = local.work(|store| store.agent_context()).await?;
    let action = leaf.action;
    let member = leaf.member;
    let admitted = match admit(&context, &previous, action, member) {
        Ok(admitted) => {
            let mut cleanup = false;
            let checked = admin_access(&context, &previous, &admitted, &mut cleanup).await;
            local.cleanup_unknown |= cleanup;
            checked.map(|()| admitted)
        }
        Err(refused) => Err(refused),
    };
    let target = context.scope["target"].as_str().unwrap_or("").to_owned();
    if leaf.plan {
        let mut value = plan(&context.scope, action, member, true);
        let admitted = match admitted {
            Ok(admitted) => admitted,
            Err(refused) => {
                value["refusals"] = json!([{"detail":refused.boundary,"subject":member}]);
                let _ = local.finish(&context.clock).await;
                return Ok((value, 0));
            }
        };
        return observed_plan(&context, &mut local, &previous, &admitted, action, value).await;
    }
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err(refused) => {
            let _ = local.finish(&context.clock).await;
            return Err(refused);
        }
    };
    let name = admitted.member["member"].as_str().unwrap_or("").to_owned();
    let is_writer = admitted.writer.as_deref() == Some(name.as_str());
    match action {
        "node-drain" if is_writer => {
            return writer_drain(context, local, &previous, admitted, leaf.approve).await;
        }
        "node-drain" if leaf.approve.is_some() => {
            return Err(refusal(
                Failure::Ownership,
                "stale-approval",
                format!(
                    "the observed plan changed; run k3s plan {target} --action node-drain --member {name} --observe"
                ),
            ));
        }
        "node-remove" => {
            return remove(
                context,
                local,
                &previous,
                admitted,
                leaf.approve.unwrap_or(""),
            )
            .await;
        }
        "node-replace" => {
            return replace(
                context,
                local,
                &previous,
                admitted,
                leaf.approve.unwrap_or(""),
            )
            .await;
        }
        _ => {}
    }
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let count = steps(&context, &admitted, action, false, "reachable")?;
    let sequence = local.work(|store| store.next_sequence()).await?;
    let request = request(&context, &admitted, &operation, action, sequence)?;
    let member_recipe = recipe(
        &context,
        &admitted,
        &operation,
        action,
        Value::Null,
        "reachable",
        Value::Null,
        Value::Null,
        None,
    )?;
    let mut cleanup = false;
    let observed = observe(
        &context,
        &admitted,
        action,
        &request,
        &member_recipe,
        &attempt,
        count,
        false,
        &mut cleanup,
    )
    .await;
    local.cleanup_unknown |= cleanup;
    let observed = observed?;
    let (refusals, _) = checks(&context, &admitted, action, &observed, None);
    if let Some(refused) = refusals.into_iter().next() {
        let _ = local.finish(&context.clock).await;
        return Err(refused);
    }
    let store = store_usage(&context, &previous, &admitted.survivors, 1)?;
    let mut session = begin(
        context,
        local,
        &admitted,
        request,
        &member_recipe,
        Vec::new(),
        &attempt,
        count,
    )
    .await?;
    let mut fields = match action {
        "node-drain" => json!({"member":name,"cordoned":false,"unreachable":false,"evicted":[],
            "blocked":[],"writer_move":null}),
        _ => json!({"member":name,"cordoned":true}),
    };
    let result = match action {
        "node-drain" => Box::pin(session.drain(&member_recipe, &mut fields)).await,
        _ => Box::pin(session.uncordon(&member_recipe, &mut fields)).await,
    };
    let detail = session.local.failure_detail;
    let snapshot = session.local.complete(result, &session.context.clock).await;
    let (snapshot, status) = match snapshot {
        Ok(snapshot) => (Some(snapshot), 0),
        Err(failure) => (failure.snapshot.map(|s| *s), 1),
    };
    let value = report(
        &session.context,
        snapshot.as_ref(),
        store,
        action,
        &name,
        detail,
        fields,
    )?;
    Ok((value, status))
}

async fn remove(
    context: rpc::Context<'_>,
    mut local: Local,
    previous: &[Snapshot],
    admitted: Admitted,
    approve: &str,
) -> std::result::Result<(Value, i32), Refusal> {
    let action = "node-remove";
    let name = admitted.member["member"].as_str().unwrap_or("").to_owned();
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let count = steps(&context, &admitted, action, false, "reachable")?;
    let sequence = local.work(|store| store.next_sequence()).await?;
    let request = request(&context, &admitted, &operation, action, sequence)?;
    let guess = recipe(
        &context,
        &admitted,
        &operation,
        action,
        Value::Null,
        "reachable",
        Value::Null,
        Value::Null,
        None,
    )?;
    let sources = sources(&context, previous, &admitted, &operation, &attempt)?;
    let mut cleanup = false;
    let assessed: std::result::Result<_, Refusal> = async {
        let observed = observe(
            &context,
            &admitted,
            action,
            &request,
            &guess,
            &attempt,
            count,
            false,
            &mut cleanup,
        )
        .await?;
        let round = quorum(
            &context,
            &admitted,
            &request,
            &attempt,
            count,
            &sources,
            &mut cleanup,
        )
        .await?;
        if !observed.reachable {
            readiness(
                &context,
                &admitted,
                &request,
                &attempt,
                count,
                &sources,
                &round,
                &mut cleanup,
            )
            .await??;
        }
        let (refusals, checks) = checks(&context, &admitted, action, &observed, Some(&round));
        if let Some(refused) = refusals.into_iter().next() {
            return Err(refused);
        }
        pending(&admitted, previous, "node remove")?;
        let effects = effects(
            context.selected.declaration,
            action,
            &name,
            admitted.writer.as_deref(),
            None,
            false,
        );
        let decision = decision(
            &context,
            &admitted,
            action,
            &observed,
            &checks,
            &effects,
            &Value::Null,
            &Value::Null,
        )?;
        members::check_approval(approve, &decision).map_err(rule)?;
        Ok((decision, checks, observed.reachable))
    }
    .await;
    local.cleanup_unknown |= cleanup;
    let (decision, checks, reachable) = match assessed {
        Ok(assessed) => assessed,
        Err(refused) => {
            let _ = local.finish(&context.clock).await;
            return Err(refused);
        }
    };
    let reachability = if reachable {
        "reachable"
    } else {
        "unreachable"
    };
    let count = steps(&context, &admitted, action, false, reachability)?;
    let member_recipe = recipe(
        &context,
        &admitted,
        &operation,
        action,
        Value::Null,
        reachability,
        Value::Null,
        Value::Null,
        Some(&decision),
    )?;
    let replicated = replication::maintenance_recipe(
        &context,
        previous,
        &admitted.owner,
        &operation,
        "observe",
        admitted.first.as_ref().ok_or(Failure::Readiness)?,
    )?;
    let mut events = sources;
    if let Some((recipe, _)) = &replicated {
        events.push(json!({"type":"replication-recipe","recipe":recipe}));
    }
    let store = store_usage(&context, previous, &admitted.survivors, 1)?;
    let mut session = begin(
        context,
        local,
        &admitted,
        request,
        &member_recipe,
        events,
        &attempt,
        count,
    )
    .await?;
    let mut fields = json!({"member":name,"checks":checks,"removed":{"claims_rebound":[],
        "device_removed":"not-run","etcd_member":if admitted.member["role"] == "server" {"not-run"} else {"not-applicable"},
        "node":"not-run","services_stopped":"not-run"}});
    let result = Box::pin(session.remove(&member_recipe, replicated.is_some(), &mut fields)).await;
    let detail = session.local.failure_detail;
    let snapshot = session.local.complete(result, &session.context.clock).await;
    let (snapshot, status) = match snapshot {
        Ok(snapshot) => (Some(snapshot), 0),
        Err(failure) => (failure.snapshot.map(|s| *s), 1),
    };
    let value = report(
        &session.context,
        snapshot.as_ref(),
        store,
        action,
        &name,
        detail,
        fields,
    )?;
    Ok((value, status))
}

pub(super) fn recorded_config(previous: &[Snapshot], owner: &Value) -> Result<Value> {
    let recorded = &owner["fingerprints"]["config_sha256"];
    for snapshot in previous {
        let config = &snapshot.request["config"];
        if config.is_object() && json!(hash("broil-infra-config-v1", config)?) == *recorded {
            return Ok(config.clone());
        }
    }
    Err(Failure::Integrity)
}

fn removed_names(owner: &Value) -> Vec<String> {
    owner["removed"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["member"].as_str().map(str::to_owned))
        .collect()
}

pub(super) fn deleted_agents(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
) -> Result<Option<Vec<String>>> {
    let recorded = recorded_config(previous, owner)?;
    let removed = removed_names(owner);
    let removed: Vec<&str> = removed.iter().map(String::as_str).collect();
    Ok(members::deleted_agents(
        &recorded,
        &context.config,
        &removed,
    ))
}

pub(super) fn transition_of(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
) -> Result<Option<String>> {
    let recorded = recorded_config(previous, owner)?;
    if recorded["registries"] != context.config["registries"]
        || recorded["secrets"] != context.config["secrets"]
    {
        return Ok(None);
    }
    let projection =
        |config: &Value| json!({"target":config["target"],"scripts":config["scripts"],"routes":{}});
    Ok(removed_names(owner).into_iter().find(|member| {
        members::replacement(&projection(&recorded), &projection(&context.config), member).is_ok()
    }))
}

fn rebind_admit(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
) -> std::result::Result<(Admitted, Vec<String>), Refusal> {
    settled(context, previous)?;
    let owner = previous
        .first()
        .map(|s| s.owner.clone())
        .filter(|o| !o["cluster"].is_null())
        .ok_or(Failure::Readiness)?;
    let deleted = deleted_agents(context, previous, &owner)?.ok_or(Failure::Ownership)?;
    let stable = |fingerprints: &Value| {
        let mut f = fingerprints.clone();
        f["config_sha256"] = Value::Null;
        f
    };
    require(
        stable(&owner["fingerprints"]) == stable(&context.owner_fingerprints),
        Failure::Ownership,
    )?;
    let survivors = super::survivors(&owner)?;
    require(
        owner["participants_sha256"] == super::participants(&json!(survivors))?,
        Failure::Ownership,
    )?;
    let member = owner["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|m| m["member"] == deleted[0].as_str())
        .cloned()
        .ok_or(Failure::Ownership)?;
    let first = survivors.iter().find(|m| m["role"] == "server").cloned();
    let writer = writer(context, &owner);
    let target = projection(&context.scope, context.selected.declaration, Some(&owner));
    Ok((
        Admitted {
            owner,
            survivors,
            member,
            first,
            writer,
            target,
        },
        deleted,
    ))
}

pub(super) async fn rebind_declaration(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let action = "rebind-declaration";
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let (previous, _) = local.work(|store| store.agent_context()).await?;
    let admitted = rebind_admit(&context, &previous);
    let admitted = match admitted.and_then(|(admitted, deleted)| {
        let count = steps(&context, &admitted, action, false, "reachable")?;
        Ok((admitted, deleted, count))
    }) {
        Ok(admitted) => admitted,
        Err(refused) => {
            let _ = local.finish(&context.clock).await;
            return Err(refused.failure.into());
        }
    };
    let (admitted, deleted, count) = admitted;
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let sequence = local.work(|store| store.next_sequence()).await?;
    let request = request(&context, &admitted, &operation, action, sequence)?;
    let member_recipe = recipe(
        &context,
        &admitted,
        &operation,
        action,
        Value::Null,
        "reachable",
        Value::Null,
        Value::Null,
        None,
    )?;
    let mut session = begin(
        context,
        local,
        &admitted,
        request,
        &member_recipe,
        Vec::new(),
        &attempt,
        count,
    )
    .await
    .map_err(|refused| super::ExecutionFailure {
        failure: refused.failure,
        completion_unknown: true,
        cleanup_unknown: false,
        snapshot: None,
        detail: None,
    })?;
    let result = Box::pin(session.rebind(&deleted)).await;
    session.local.complete(result, &session.context.clock).await
}

fn rebound(old: &Value, deleted: &[String], fingerprints: &Value) -> Result<Value> {
    let mut owner = old.clone();
    owner["previous_generation"] = old["generation"].clone();
    owner["generation"] = json!(fresh()?);
    owner["created_ms"] = json!(now()?);
    let gone = |m: &Value| {
        m["member"]
            .as_str()
            .is_some_and(|n| deleted.iter().any(|d| d == n))
    };
    for key in ["members", "removed"] {
        let kept: Vec<Value> = old[key]
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .filter(|m| !gone(m))
            .cloned()
            .collect();
        owner[key] = json!(kept);
    }
    owner["fingerprints"] = fingerprints.clone();
    Ok(owner)
}

fn declaration_rebound(old: &Value, owner: &Value, snapshot: &Snapshot, recipe: &Value) -> bool {
    let names: Vec<String> = removed_names(old)
        .into_iter()
        .filter(|n| {
            owner["members"]
                .as_array()
                .is_some_and(|m| !m.iter().any(|m| m["member"] == n.as_str()))
        })
        .collect();
    let agents = names.iter().all(|n| {
        old["members"].as_array().is_some_and(|m| {
            m.iter()
                .any(|m| m["member"] == n.as_str() && m["role"] == "agent")
        })
    });
    let Ok(mut expected) = rebound(old, &names, &super::stable_fingerprints(&snapshot.request))
    else {
        return false;
    };
    for key in ["generation", "created_ms", "lock_identity"] {
        expected[key] = owner[key].clone();
    }
    agents
        && names
            .iter()
            .any(|n| recipe["member"]["member"] == n.as_str())
        && *owner == expected
}

fn replica_ids(member: &str) -> [String; 2] {
    [
        format!("registry-replica-{member}"),
        format!("registry-replication-{member}"),
    ]
}

fn begun(old: &Value, transition: &Value, entry: &Value, fingerprints: &Value) -> Result<Value> {
    let name = transition["member"].as_str().ok_or(Failure::Integrity)?;
    let mut owner = old.clone();
    owner["previous_generation"] = old["generation"].clone();
    owner["generation"] = json!(fresh()?);
    owner["created_ms"] = json!(now()?);
    let removed: Vec<Value> = old["removed"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| r["member"] != name)
        .cloned()
        .collect();
    owner["removed"] = json!(removed);
    let mut entry = entry.clone();
    entry["node_uid"] = Value::Null;
    let mut found = false;
    for member in owner["members"]
        .as_array_mut()
        .ok_or(Failure::Integrity)?
        .iter_mut()
        .filter(|m| m["member"] == name)
    {
        *member = entry.clone();
        found = true;
    }
    require(found, Failure::Integrity)?;
    if transition["same_machine"] != true {
        let ids = replica_ids(name);
        for resource in owner["resources"]
            .as_array_mut()
            .ok_or(Failure::Integrity)?
            .iter_mut()
            .filter(|r| {
                r["id"]
                    .as_str()
                    .is_some_and(|id| ids.iter().any(|i| i == id))
            })
        {
            resource["generation"] = json!(fresh()?);
            resource["machine"] = transition["new_machine"].clone();
        }
    }
    owner["fingerprints"] = fingerprints.clone();
    owner["participants_sha256"] = json!(super::participants(&json!(super::survivors(&owner)?))?);
    Ok(owner)
}

fn replacement_begun(old: &Value, owner: &Value, snapshot: &Snapshot, recipe: &Value) -> bool {
    let transition = &recipe["transition"];
    let Some(name) = transition["member"].as_str() else {
        return false;
    };
    let Some(entry) = owner["members"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["member"] == name))
    else {
        return false;
    };
    let Ok(mut expected) = begun(
        old,
        transition,
        entry,
        &super::stable_fingerprints(&snapshot.request),
    ) else {
        return false;
    };
    for key in ["generation", "created_ms", "lock_identity"] {
        expected[key] = owner[key].clone();
    }
    let ids = replica_ids(name);
    if let (Some(expected), Some(successor)) = (
        expected["resources"].as_array_mut(),
        owner["resources"].as_array(),
    ) {
        for (resource, after) in expected.iter_mut().zip(successor) {
            if transition["same_machine"] != true
                && resource["id"]
                    .as_str()
                    .is_some_and(|id| ids.iter().any(|i| i == id))
            {
                resource["generation"] = after["generation"].clone();
            }
        }
    }
    recipe["member"]["member"] == name
        && transition["phase"] == "begin"
        && old["removed"]
            .as_array()
            .is_some_and(|r| r.iter().any(|r| r["member"] == name))
        && entry["machine"] == transition["new_machine"]
        && owner["participants_sha256"] == transition["new_participants_sha256"]
        && *owner == expected
}

pub(super) fn replacing(previous: &[Snapshot], member: &str) -> Option<Value> {
    let mut latest: Option<(&Snapshot, &Value)> = None;
    for snapshot in previous.iter().filter(|s| {
        s.request["action"] == "node-replace" && super::report::summary(s)["outcome"] == "succeeded"
    }) {
        let Some(recipe) = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "member-recipe")
            .map(|o| &o["event"]["recipe"])
        else {
            continue;
        };
        if recipe["member"]["member"] != member {
            continue;
        }
        let newer = latest.is_none_or(|(old, _)| {
            snapshot.request["sequence"].as_u64() > old.request["sequence"].as_u64()
        });
        if newer {
            latest = Some((snapshot, recipe));
        }
    }
    latest
        .filter(|(_, recipe)| recipe["phase"] == "begin")
        .map(|(_, recipe)| recipe["transition"].clone())
}

struct Replaced {
    transition: Value,
    participants: Vec<Value>,
    decision: Value,
}

async fn replacement(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    admitted: &Admitted,
) -> std::result::Result<Replaced, Refusal> {
    let name = admitted.member["member"]
        .as_str()
        .ok_or(Failure::Integrity)?
        .to_owned();
    let target = context.scope["target"].as_str().unwrap_or("").to_owned();
    let owner = &admitted.owner;
    let servers = context
        .selected
        .declaration
        .members
        .iter()
        .filter(|m| m.role == Role::Server)
        .count();
    if admitted.member["role"] == "server" && servers == 1 {
        return Err(refusal(
            Failure::Configuration,
            "one-server",
            format!(
                "{name} is the only server of target {target}; it cannot be removed or replaced"
            ),
        ));
    }
    let (transition, participants) = match replacing(previous, &name) {
        Some(recorded) => (recorded, super::survivors(owner)?),
        None => {
            let recorded = recorded_config(previous, owner)?;
            let outside = || {
                refusal(
                    Failure::Configuration,
                    "declaration",
                    format!(
                        "the declaration of target {target} changed outside the machine, node_ip and interface of {name}; revert the other changes"
                    ),
                )
            };
            if recorded["registries"] != context.config["registries"]
                || recorded["secrets"] != context.config["secrets"]
            {
                return Err(outside());
            }
            let routes: serde_json::Map<String, Value> = owner["members"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .iter()
                .filter_map(|m| {
                    Some((
                        m["member"].as_str()?.to_owned(),
                        json!({"route":m["route"],"jump":m["jump"]}),
                    ))
                })
                .collect();
            let projection = |config: &Value| {
                let mut declared = config["target"].clone();
                if let Some(fields) = declared.as_object_mut() {
                    fields.insert("name".into(), json!(target));
                }
                json!({"target":declared,"scripts":config["scripts"],"routes":routes})
            };
            let kind =
                members::replacement(&projection(&recorded), &projection(&context.config), &name)
                    .map_err(rule)?;
            let machine = context
                .selected
                .members
                .iter()
                .find(|m| m.declaration.name == name)
                .map(|m| m.declaration.machine.clone())
                .ok_or(Failure::Configuration)?;
            let entry = context.probe(&machine).await?;
            let participants = replaced_participants(owner, &entry)?;
            let hash = super::participants(&json!(participants))?;
            let same = kind == "same-machine";
            if same {
                let removal = owner["removed"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|r| r["member"] == name.as_str())
                    .map(|r| r["operation"].clone())
                    .ok_or(Failure::Integrity)?;
                let retained = previous
                    .iter()
                    .find(|s| s.request["operation"] == removal)
                    .map(|s| s.request["participants_sha256"].clone())
                    .ok_or(Failure::Integrity)?;
                if retained != json!(hash) {
                    return Err(refusal(
                        Failure::Configuration,
                        "declaration",
                        format!(
                            "stale-claim: {name}'s claim on {machine} does not bind the replacement's members; replace {name} on a new machine"
                        ),
                    ));
                }
            }
            let transition = json!({"member":name,"phase":"begin","old_machine":admitted.member["machine"],
                "new_machine":machine,"same_machine":same,
                "old_config_sha256":owner["fingerprints"]["config_sha256"],
                "new_config_sha256":context.owner_fingerprints["config_sha256"],
                "new_participants_sha256":hash});
            (transition, participants)
        }
    };
    let effects = effects(
        context.selected.declaration,
        "node-replace",
        &name,
        admitted.writer.as_deref(),
        None,
        transition["same_machine"] == true,
    );
    let observed = Observed {
        reachable: true,
        node: Value::Null,
        observed_ms: now()?,
    };
    let decision = decision(
        context,
        admitted,
        "node-replace",
        &observed,
        &Value::Null,
        &effects,
        &Value::Null,
        &transition,
    )?;
    Ok(Replaced {
        transition,
        participants,
        decision,
    })
}

fn replaced_participants(owner: &Value, entry: &Value) -> Result<Vec<Value>> {
    let removed = removed_names(owner);
    let mut participants = Vec::new();
    for member in owner["members"].as_array().ok_or(Failure::Integrity)? {
        if member["member"] == entry["member"] {
            let mut entry = entry.clone();
            entry["node_uid"] = Value::Null;
            participants.push(entry);
        } else if !removed.iter().any(|r| member["member"] == r.as_str()) {
            participants.push(member.clone());
        }
    }
    Ok(participants)
}

pub(super) struct Position {
    pub(super) begun: Option<u64>,
    pub(super) prepared: bool,
    pub(super) joined: Option<u64>,
}

pub(super) fn position(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    member: &str,
) -> Result<Position> {
    let entry = owner["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|m| m["member"] == member)
        .ok_or(Failure::Ownership)?;
    let machine = context
        .selected
        .declaration
        .members
        .iter()
        .find(|m| m.name == member)
        .map(|m| m.machine.as_str())
        .ok_or(Failure::Configuration)?;
    let mut position = Position {
        begun: None,
        prepared: entry["machine"] == machine && entry["node_uid"].is_string(),
        joined: None,
    };
    if replacing(previous, member).is_none() {
        return Ok(position);
    }
    let succeeded = |s: &&Snapshot| super::report::summary(s)["outcome"] == "succeeded";
    position.begun = previous
        .iter()
        .filter(succeeded)
        .filter(|s| {
            s.request["action"] == "node-replace"
                && s.observations.iter().any(|o| {
                    o["event"]["type"] == "member-recipe"
                        && o["event"]["recipe"]["phase"] == "begin"
                        && o["event"]["recipe"]["member"]["member"] == member
                })
        })
        .filter_map(|s| s.request["sequence"].as_u64())
        .max();
    let after = |s: &&Snapshot| s.request["sequence"].as_u64() > position.begun;
    let same = previous
        .iter()
        .filter(succeeded)
        .find(|s| s.request["sequence"].as_u64() == position.begun)
        .and_then(|s| {
            s.observations
                .iter()
                .find(|o| o["event"]["type"] == "member-recipe")
        })
        .is_some_and(|o| o["event"]["recipe"]["transition"]["same_machine"] == true);
    position.prepared = same
        || previous.iter().filter(succeeded).filter(after).any(|s| {
            s.request["action"] == "prepare-hosts"
                && s.request["resources"].as_array().is_some_and(|r| {
                    r.iter()
                        .any(|r| r["kind"] == "bootstrap-assets" && r["id"] == machine)
                })
        });
    if entry["node_uid"].is_string() {
        position.joined = previous
            .iter()
            .filter(succeeded)
            .filter(after)
            .filter(|s| {
                matches!(
                    s.request["action"].as_str(),
                    Some("join-server" | "join-agent")
                )
            })
            .filter_map(|s| s.request["sequence"].as_u64())
            .max()
            .or(position.begun);
    }
    Ok(position)
}

pub(super) async fn join_replacement(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    member: &str,
) -> super::ExecutionResult<Snapshot> {
    let context = rpc::Context::new(project, policy, target)?;
    let declared = context
        .selected
        .declaration
        .members
        .iter()
        .find(|m| m.name == member)
        .ok_or(Failure::Configuration)?;
    let (machine, server) = (declared.machine.clone(), declared.role == Role::Server);
    let (_, previous) = super::converge::records(&context).await?;
    let owner = &previous.first().ok_or(Failure::Ownership)?.owner;
    let source = super::join_source(owner, &machine)?;
    let policy = super::issuer::duplicate(&context.policy)?;
    if server {
        super::join_server(project, policy, target, &machine, &source).await
    } else {
        super::join_agent(project, policy, target, &machine, &source).await
    }
}

async fn replace(
    context: rpc::Context<'_>,
    mut local: Local,
    previous: &[Snapshot],
    admitted: Admitted,
    approve: &str,
) -> std::result::Result<(Value, i32), Refusal> {
    let name = admitted.member["member"].as_str().unwrap_or("").to_owned();
    let assessed = match replacement(&context, previous, &admitted).await {
        Ok(replaced) if replacing(previous, &name).is_none() => {
            pending(&admitted, previous, "node replace").map(|()| replaced)
        }
        assessed => assessed,
    };
    let _ = local.finish(&context.clock).await;
    let replaced = assessed?;
    members::check_approval(approve, &replaced.decision).map_err(rule)?;
    let stop = context.policy.cancellation.clone();
    let (output, succeeded) = super::converge::replace_sequence(&context, &name, approve, stop)
        .await
        .map_err(Refusal::from)?;
    let stop = replace_stop(&output, &name)?;
    let (_, after) = super::converge::records(&context)
        .await
        .map_err(|e| Refusal::from(e.failure))?;
    let owner = &after.first().ok_or(Failure::Ownership)?.owner;
    let entry = owner["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|m| m["member"] == name.as_str())
        .cloned()
        .ok_or(Failure::Ownership)?;
    let transition = &replaced.transition;
    let latest = |phase: &str| {
        after
            .iter()
            .filter(|s| {
                s.request["action"] == "node-replace"
                    && s.observations.iter().any(|o| {
                        o["event"]["type"] == "member-recipe"
                            && o["event"]["recipe"]["phase"] == phase
                            && o["event"]["recipe"]["member"]["member"] == name.as_str()
                    })
            })
            .max_by_key(|s| s.request["sequence"].as_u64())
    };
    let rebound = latest("begin").is_some_and(|s| {
        s.request["members"].as_array().is_some_and(|members| {
            members.iter().all(|m| {
                s.steps.iter().any(|step| {
                    step["action"] == "rebind-claim"
                        && step["recipient"]["member"] == m["member"]
                        && s.succeeded(step)
                })
            })
        })
    });
    let replica = latest("complete")
        .and_then(|s| {
            s.observations.iter().rev().find(|o| {
                o["event"]["type"] == replication::OBSERVATION
                    && o["event"]["member"]["member"] == name.as_str()
            })
        })
        .map_or(json!({"completion":null,"state":null}), |o| {
            json!({"completion":o["event"]["replication"]["completion"],
                "state":o["event"]["replication"]["state"]})
        });
    let survivors = super::survivors(owner)?;
    let store = store_usage(&context, &after, &survivors, 0)?;
    let value = json!({"format_version":1,"scope":context.scope,"view":"node-replace",
        "outcome":stop["outcome"],"failure":stop["failure"],"detail":stop["detail"],
        "completion_unknown":output["completion_unknown"],"cleanup_unknown":output["cleanup_unknown"],
        "truncated":output["truncated"],"operations":output["operations"],"recovery":stop["recovery"],
        "store":store,"member":name,"previous_machine":transition["old_machine"],
        "machine":transition["new_machine"],"same_machine":transition["same_machine"],
        "joined":entry["node_uid"].is_string() && entry["machine"] == transition["new_machine"],
        "replica":replica,"rebound":rebound});
    Ok((value, i32::from(!succeeded)))
}

pub(super) fn replace_stop(output: &Value, member: &str) -> std::result::Result<Value, Refusal> {
    let uncertain = output["completion_unknown"] == true || output["cleanup_unknown"] == true;
    let recorded = output["operations"]
        .as_array()
        .is_some_and(|operations| !operations.is_empty());
    let outcome = output["outcome"].as_str().ok_or(Failure::Integrity)?;
    if matches!(outcome, "refused" | "failed") && !recorded && !uncertain {
        let failure = super::converge::recorded_failure(&output["failure"]);
        return Err(if output["detail"] == "store-full" {
            let plan = output["recovery"]["subject"].as_str().unwrap_or("");
            refusal(failure, "store-full", plan.to_owned())
        } else {
            Refusal {
                failure,
                boundary: None,
                detail: output["detail"].as_str().map(str::to_owned),
            }
        });
    }
    let outcome = match outcome {
        "waiting" | "refused" if uncertain => "unknown",
        "waiting" | "refused" => "failed",
        outcome => outcome,
    };
    let mut recovery = output["recovery"].clone();
    if matches!(
        recovery["choice"].as_str(),
        Some("create" | "credential-change" | "replace")
    ) {
        recovery["choice"] = json!("rerun");
    }
    if recovery["choice"] == "resume" {
        recovery["subject"] = json!(member);
    }
    Ok(
        json!({"outcome":outcome,"failure":output["failure"],"detail":output["detail"],
        "recovery":recovery}),
    )
}

pub(super) async fn replacement_begin(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    member: &str,
    approve: &str,
) -> super::ExecutionResult<Snapshot> {
    let action = "node-replace";
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let (previous, _) = local.work(|store| store.agent_context()).await?;
    let mut cleanup = false;
    let admitted: std::result::Result<_, Refusal> = async {
        let admitted = admit(&context, &previous, action, member)?;
        require(
            replacing(&previous, member).is_none(),
            Failure::Configuration,
        )?;
        admin_access(&context, &previous, &admitted, &mut cleanup).await?;
        let replaced = replacement(&context, &previous, &admitted).await?;
        pending(&admitted, &previous, "node replace")?;
        members::check_approval(approve, &replaced.decision).map_err(rule)?;
        let count = steps(&context, &admitted, action, false, "reachable")?;
        Ok((admitted, replaced, count))
    }
    .await;
    local.cleanup_unknown |= cleanup;
    let (admitted, replaced, count) = match admitted {
        Ok(admitted) => admitted,
        Err(refused) => {
            let _ = local.finish(&context.clock).await;
            return Err(refused.failure.into());
        }
    };
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let sequence = local.work(|store| store.next_sequence()).await?;
    let request = request(&context, &admitted, &operation, action, sequence)?;
    let member_recipe = recipe(
        &context,
        &admitted,
        &operation,
        action,
        json!("begin"),
        "reachable",
        Value::Null,
        replaced.transition.clone(),
        Some(&replaced.decision),
    )?;
    let mut session = begin(
        context,
        local,
        &admitted,
        request,
        &member_recipe,
        Vec::new(),
        &attempt,
        count,
    )
    .await
    .map_err(|refused| super::ExecutionFailure {
        failure: refused.failure,
        completion_unknown: true,
        cleanup_unknown: false,
        snapshot: None,
        detail: None,
    })?;
    let result =
        Box::pin(session.replace_begin(&replaced.transition, &replaced.participants)).await;
    session.local.complete(result, &session.context.clock).await
}

pub(super) async fn replacement_complete(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    member: &str,
) -> super::ExecutionResult<Snapshot> {
    let action = "node-replace";
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let (previous, _) = local.work(|store| store.agent_context()).await?;
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let admitted: std::result::Result<_, Refusal> = (|| {
        let admitted = admit(&context, &previous, action, member)?;
        let transition = replacing(&previous, member).ok_or(Failure::Configuration)?;
        require(
            admitted.survivors.contains(&admitted.member),
            Failure::Ownership,
        )?;
        require(admitted.member["node_uid"].is_string(), Failure::Readiness)?;
        let count = steps(&context, &admitted, action, false, "reachable")?;
        let mut events = sources(&context, &previous, &admitted, &operation, &attempt)?;
        let replicated = replication::maintenance_recipe(
            &context,
            &previous,
            &admitted.owner,
            &operation,
            "observe",
            admitted.first.as_ref().ok_or(Failure::Readiness)?,
        )?;
        if let Some((recipe, _)) = &replicated {
            events.push(json!({"type":"replication-recipe","recipe":recipe}));
        }
        Ok((admitted, transition, count, events, replicated.is_some()))
    })();
    let (admitted, transition, count, events, replicated) = match admitted {
        Ok(admitted) => admitted,
        Err(refused) => {
            let _ = local.finish(&context.clock).await;
            return Err(refused.failure.into());
        }
    };
    let sequence = local.work(|store| store.next_sequence()).await?;
    let request = request(&context, &admitted, &operation, action, sequence)?;
    let member_recipe = recipe(
        &context,
        &admitted,
        &operation,
        action,
        json!("complete"),
        "reachable",
        Value::Null,
        transition,
        None,
    )?;
    let mut session = begin(
        context,
        local,
        &admitted,
        request,
        &member_recipe,
        events,
        &attempt,
        count,
    )
    .await
    .map_err(|refused| super::ExecutionFailure {
        failure: refused.failure,
        completion_unknown: true,
        cleanup_unknown: false,
        snapshot: None,
        detail: None,
    })?;
    let result = Box::pin(session.replace_complete(&member_recipe, replicated)).await;
    session.local.complete(result, &session.context.clock).await
}

async fn observed_plan(
    context: &rpc::Context<'_>,
    local: &mut Local,
    previous: &[Snapshot],
    admitted: &Admitted,
    action: &str,
    mut value: Value,
) -> std::result::Result<(Value, i32), Refusal> {
    if action == "node-replace" {
        let assessed = replacement(context, previous, admitted).await;
        let _ = local.finish(&context.clock).await;
        let name = admitted.member["member"].as_str().unwrap_or("");
        match assessed {
            Ok(replaced) => {
                value["members"] = replaced.decision["members"].clone();
                value["effects"] = replaced.decision["effects"].clone();
                value["transition"] = replaced.transition;
                value["observed_ms"] = json!(now()?);
                value["approval"] = json!(members::approval(&replaced.decision).map_err(rule)?);
            }
            Err(refused) => {
                value["refusals"] = json!([{"detail":refused.boundary,"subject":name}]);
            }
        }
        return Ok((value, 0));
    }
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let name = admitted.member["member"].as_str().unwrap_or("").to_owned();
    let is_writer = admitted.writer.as_deref() == Some(name.as_str());
    let count = steps(context, admitted, action, is_writer, "reachable")?;
    let sequence = local.work(|store| store.next_sequence()).await?;
    let request = request(context, admitted, &operation, action, sequence)?;
    let member_recipe = recipe(
        context,
        admitted,
        &operation,
        action,
        if action == "node-replace" {
            json!("begin")
        } else {
            Value::Null
        },
        "reachable",
        Value::Null,
        Value::Null,
        None,
    )?;
    let mut cleanup = false;
    let observed: Result<_> = async {
        let observed = observe(
            context,
            admitted,
            action,
            &request,
            &member_recipe,
            &attempt,
            count,
            true,
            &mut cleanup,
        )
        .await?;
        let mut ready = Ok(());
        let round = if action == "node-remove"
            || action == "node-drain" && is_writer && !observed.reachable
        {
            let sources = sources(context, previous, admitted, &operation, &attempt)?;
            let round = quorum(
                context,
                admitted,
                &request,
                &attempt,
                count,
                &sources,
                &mut cleanup,
            )
            .await?;
            if !observed.reachable {
                ready = readiness(
                    context,
                    admitted,
                    &request,
                    &attempt,
                    count,
                    &sources,
                    &round,
                    &mut cleanup,
                )
                .await?;
            }
            Some(round)
        } else {
            None
        };
        let moved = if action == "node-drain" && is_writer {
            let first = admitted.first.clone().ok_or(Failure::Readiness)?;
            let (recipe, _) = replication::maintenance_recipe(
                context,
                previous,
                &admitted.owner,
                &operation,
                "move",
                &first,
            )?
            .ok_or(Failure::Configuration)?;
            candidate(
                context,
                admitted,
                &request,
                &attempt,
                count,
                &recipe,
                &mut cleanup,
            )
            .await?
        } else {
            Ok(String::new())
        };
        Ok((observed, round, moved, ready))
    }
    .await;
    let _ = local.finish(&context.clock).await;
    let (observed, round, moved, ready) = observed?;
    let (mut refusals, checks) = checks(context, admitted, action, &observed, round.as_ref());
    if let Err(refused) = ready {
        refusals.insert(0, refused);
    }
    let mut writer_move = Value::Null;
    if action == "node-drain" && is_writer {
        match moved {
            Ok(to) => {
                writer_move = json!({"from":name,"loss_possible":!observed.reachable,"to":to});
            }
            Err(refused) => refusals.push(refused),
        }
    }
    let effects = effects(
        context.selected.declaration,
        action,
        &name,
        admitted.writer.as_deref(),
        writer_move["to"].as_str(),
        false,
    );
    let decision = decision(
        context,
        admitted,
        action,
        &observed,
        &checks,
        &effects,
        &writer_move,
        &Value::Null,
    )?;
    value["writer_move"] = writer_move;
    value["members"] = decision["members"].clone();
    value["effects"] = json!(effects);
    value["checks"] = checks;
    value["observed_ms"] = json!(observed.observed_ms);
    if action == "node-drain" {
        let pods: Vec<Value> = pods(&observed.node, &["evictable", "local-storage", "unmanaged"])
            .map(|p| {
                let evict = p["class"] == "evictable";
                json!({"action":if evict {"evict"} else {"block"},"namespace":p["namespace"],
                    "pod":p["pod"],"reason":if evict {Value::Null} else {p["class"].clone()}})
            })
            .collect();
        value["pods"] = json!(pods);
    }
    value["refusals"] = json!(
        refusals
            .iter()
            .map(|r| json!({"detail":r.boundary,"subject":name}))
            .collect::<Vec<_>>()
    );
    let facts = json!({"target":context.scope["target"],"member":name,"writer":is_writer,
        "reachability":if observed.reachable {"reachable"} else {"unreachable"},
        "known":true,"refusals":value["refusals"]});
    if let Ok(true) = members::issues_approval(action, &facts) {
        value["approval"] = json!(members::approval(&decision).map_err(rule)?);
    }
    Ok((value, 0))
}

#[allow(clippy::too_many_arguments)]
async fn begin<'a>(
    context: rpc::Context<'a>,
    mut local: Local,
    admitted: &Admitted,
    request: Value,
    member_recipe: &Value,
    events: Vec<Value>,
    attempt_id: &str,
    count: usize,
) -> std::result::Result<Session<'a>, Refusal> {
    let recorded: Result<()> = async {
        let attempt = json!({"schema":1,"kind":"attempt","scope":request["scope"],
            "owner":request["owner"],"operation":request["operation"],"attempt":attempt_id,
            "created_ms":request["created_ms"],"request_sha256":hash("broil-infra-request-v1", &request)?,
            "parent_attempt":null,"original_step":null,"approval":null,
            "steps":(1..=count).collect::<Vec<_>>()});
        let owner = admitted.owner.clone();
        let operation = request["operation"].clone();
        local
            .work(move |store| store.create(owner, request, attempt))
            .await?;
        for event in std::iter::once(json!({"type":"member-recipe","recipe":member_recipe}))
            .chain(events)
        {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":admitted.owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt_id,"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok(())
    }
    .await;
    if let Err(failure) = recorded {
        let failed = local.failure(failure, &context.clock).await;
        return Err(failed.failure.into());
    }
    let attempt = local
        .snapshot()?
        .attempts
        .first()
        .cloned()
        .ok_or(Failure::Integrity)?;
    let (members, _) = super::session::selection(local.snapshot()?)?;
    let generations = vec![0; members.len()];
    Ok(Session {
        context,
        local,
        attempt,
        members,
        generations,
        next_step: 1,
        consumer: None,
        existing_resources: true,
        mode: Mode::Acquiring,
        retry_input: None,
        agent_view_wait: false,
        wave_boundary: None,
        wave_operations: Vec::new(),
        wave_gate_needed: false,
    })
}

impl Session<'_> {
    async fn member_acquire(&mut self) -> Result<Vec<usize>> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let cluster = self.local.snapshot()?.request["cluster"].clone();
        for &index in &order {
            let owner = self
                .inspect_step(index, "owner", Value::Null, Value::Null)
                .await?;
            require(
                owner["status"] == "ok"
                    && owner["data"]["claim"]["active_attempt"].is_null()
                    && owner["data"]["ownership"]["cluster"] == cluster
                    && owner["data"]["ownership"]["machine"]["node_uid"]
                        == self.members[index]["node_uid"],
                Failure::Ownership,
            )?;
            self.generations[index] = owner["data"]["claim"]["generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?;
            let writer = self
                .inspect_step(index, "writer", Value::Null, Value::Null)
                .await?;
            require(
                writer["status"] == "absent" || writer["status"] == "ok",
                Failure::Ownership,
            )?;
        }
        let (_, excluded) = super::session::selection(self.local.snapshot()?)?;
        for &index in &order {
            self.dispatch(
                index,
                "reserve-owner",
                json!({"members":self.members,"excluded":excluded,"cluster":cluster,
                    "fingerprints":self.context.fingerprints}),
                Vec::new(),
            )
            .await?;
        }
        for &index in &order {
            self.dispatch(
                index,
                "acquire-writer",
                super::session::acquire_payload(self.local.snapshot()?, &self.members)?,
                Vec::new(),
            )
            .await?;
        }
        self.acquired()?;
        self.mode = Mode::Work;
        self.context
            .authenticate_participants(&Value::Array(self.members.clone()))
            .await?;
        Ok(order)
    }

    fn index_of(&self, member: &Value) -> Result<usize> {
        self.members
            .iter()
            .position(|m| m == member)
            .ok_or(Failure::Integrity)
    }

    pub(super) async fn member_step(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<(Value, Value)> {
        self.context.check()?;
        let mutation = mutation(tag);
        require(!mutation || self.mode == Mode::Work, Failure::Capability)?;
        let action = step_action(tag);
        let step = self.intended(index, &action, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let child = mutation.then(|| self.context.clock.for_credential_action(deadline));
        let observed = network::invoke(
            &self.context,
            &FAMILY,
            &binding,
            tag,
            &payload,
            deadline,
            child.as_ref(),
        )
        .await;
        let settles = tag == "evict"
            && observed.failure.is_none()
            && !network::unclean(&observed.transport)
            && observed.response.as_ref().is_some_and(|result| {
                let receipt = &result["terminal"];
                result["status"] == "failed"
                    && result["failure"] == "readiness"
                    && receipt["outcome"] == "failed"
                    && receipt["failure"] == "readiness"
                    && matches!(receipt["effect"].as_str(), Some("absent" | "partial"))
                    && receipt["writer_ended"] == true
                    && receipt["binding"] == binding
                    && receipt["payload_sha256"] == step["payload_sha256"]
                    && result["member"].is_object()
            })
            && tokio::time::Instant::now() < deadline;
        self.local.completion_unknown |=
            mutation && observed.failure.is_some() && observed.transport["dispatch"] != "none";
        if !settles
            && (observed.failure.is_some()
                || observed
                    .response
                    .as_ref()
                    .is_some_and(|result| result["status"] != "ok"))
        {
            self.local
                .limit_observation(self.context.clock.terminal_deadline());
        }
        self.append(
            &step,
            json!({"type":"dispatch","transport":observed.transport,
                "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                "failure":observed.failure.map(Failure::name)}),
            false,
            Value::Null,
        )
        .await?;
        let result = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        self.local.completion_unknown |= mutation
            && (result["status"] == "unknown" || result["terminal"]["effect"] == "unknown");
        require(
            result["kind"] == "result"
                && (result["failure"].is_null() == (result["status"] == "ok")),
            Failure::Integrity,
        )?;
        if let Some(receipt) = result["terminal"].as_object() {
            let receipt = Value::Object(receipt.clone());
            require(
                receipt["binding"] == binding
                    && receipt["action"] == action
                    && receipt["payload_sha256"] == step["payload_sha256"],
                Failure::Ownership,
            )?;
            self.append(
                &step,
                json!({"type":"receiver","receipt":receipt,"transport":observed.transport}),
                true,
                receipt["completed_ms"].clone(),
            )
            .await?;
        }
        let selected = payload["recipe"]["member"].clone();
        if result["status"] == "ok" || settles {
            self.append(
                &step,
                json!({"type":"member-observation","member":selected,"kind":tag,
                    "node":result["member"],"unit":result["unit"]}),
                true,
                Value::Null,
            )
            .await?;
        }
        if settles {
            if let Some(mut child) = child {
                child.complete().map_err(|_| Failure::Timeout)?;
            }
            self.local.work(|store| store.verify()).await?;
            self.mode = Mode::SettlementOnly;
            self.next_step += 1;
            return Ok((step, result));
        }
        require(result["status"] == "ok", super::server::refused(&result))?;
        if mutation {
            require(
                result["terminal"]["outcome"] == "succeeded"
                    && result["terminal"]["effect"] == "complete"
                    && result["terminal"]["writer_ended"] == true,
                Failure::Readiness,
            )?;
            if let Some(mut child) = child {
                child.complete().map_err(|_| Failure::Timeout)?;
            }
        }
        require(
            result["member"].is_object() != matches!(tag, "stop-member" | "start-member"),
            Failure::Integrity,
        )?;
        self.next_step += 1;
        Ok((step, result))
    }

    async fn drain_wait(
        &mut self,
        index: usize,
        payload: Value,
        refs: Vec<Value>,
        unreachable: bool,
    ) -> Result<(Value, Value, bool)> {
        self.context.check()?;
        let action = step_action("observe-drain");
        let step = self.intended(index, &action, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let budget = Duration::from_secs(self.context.selected.step_timeout.seconds);
        let timeout_ms = self.context.selected.step_timeout.seconds * 1000;
        let deadline = self
            .context
            .clock
            .deadline()
            .min(tokio::time::Instant::now() + budget);
        let interval = Duration::from_millis(members::poll_interval_ms(timeout_ms, !unreachable));
        let cap = if unreachable {
            usize::try_from(timeout_ms.div_ceil(5000)).map_err(|_| Failure::Bound)?
        } else {
            members::polled_dispatches(timeout_ms)
        };
        let gone = |result: &Value| result["member"]["evictable"] == 0;
        let mut last = None;
        for _ in 0..cap {
            if !super::node::dispatchable(deadline, tokio::time::Instant::now()) {
                break;
            }
            let observed = network::invoke(
                &self.context,
                &FAMILY,
                &binding,
                "observe-drain",
                &payload,
                deadline,
                None,
            )
            .await;
            if observed.failure.is_some() {
                self.local
                    .limit_observation(self.context.clock.terminal_deadline());
            }
            self.append(
                &step,
                json!({"type":"dispatch","transport":observed.transport,
                    "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                    "failure":observed.failure.map(Failure::name)}),
                false,
                Value::Null,
            )
            .await?;
            let result = observed
                .response
                .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
            require(
                result["kind"] == "result"
                    && result["failure"].is_null() == (result["status"] == "ok"),
                Failure::Integrity,
            )?;
            require(result["status"] == "ok", super::server::refused(&result))?;
            require(result["member"].is_object(), Failure::Integrity)?;
            let done = gone(&result);
            last = Some(result);
            if done {
                break;
            }
            self.context.check()?;
            let next = tokio::time::Instant::now() + interval;
            if next + Duration::from_secs(5) >= deadline {
                break;
            }
            tokio::time::sleep_until(next).await;
        }
        let result = last.ok_or(Failure::Readiness)?;
        let done = gone(&result);
        self.append(
            &step,
            json!({"type":"member-observation","member":payload["recipe"]["member"],
                "kind":"observe-drain","node":result["member"],"unit":null}),
            true,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok((step, result, done))
    }

    async fn member_deselect(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<()> {
        self.listed_deselect(index, &step_action(tag), payload, refs)
            .await
    }

    async fn listed_deselect(
        &mut self,
        index: usize,
        action: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<()> {
        self.context.check()?;
        let step = self.intended(index, action, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.append(
            &step,
            json!({"type":"dispatch","transport":super::provenance::undispatched_transport(),
                "outcome":"succeeded","failure":null}),
            false,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok(())
    }

    async fn stopped(
        &mut self,
        step: &Value,
        failure: Failure,
        detail: &'static str,
    ) -> Result<()> {
        self.append(
            step,
            json!({"type":"failure","failure":failure.name(),"outcome":"failed",
                "completion_unknown":false,"cleanup_unknown":false}),
            false,
            Value::Null,
        )
        .await?;
        self.local.work(|store| store.verify()).await?;
        self.local.failure_detail = Some(detail);
        self.mode = Mode::SettlementOnly;
        Ok(())
    }

    async fn uncordon(&mut self, recipe: &Value, fields: &mut Value) -> Result<Snapshot> {
        let order = self.member_acquire().await?;
        let sequence = network::latest_sequence(self.local.snapshot()?, "member-recipe")?;
        let first = self.index_of(&recipe["first_server"])?;
        let payload = action_payload(recipe, Value::Null, Value::Null, None);
        let (_, result) = self
            .member_step(first, "uncordon", payload, vec![sequence])
            .await?;
        fields["cordoned"] = result["member"]["cordoned"].clone();
        self.settle(&order).await
    }

    async fn drain(&mut self, recipe: &Value, fields: &mut Value) -> Result<Snapshot> {
        let order = self.member_acquire().await?;
        let unreachable = recipe["reachability"] == "unreachable";
        if unreachable {
            if let Some((step, refused)) = self.readiness_slot(recipe).await? {
                self.stopped(
                    &step,
                    refused.failure,
                    refused.boundary.unwrap_or("readiness"),
                )
                .await?;
                self.deselect_drain(recipe).await?;
                return self.settle(&order).await;
            }
        }
        let sequence = network::latest_sequence(self.local.snapshot()?, "member-recipe")?;
        let first = self.index_of(&recipe["first_server"])?;
        let plain = action_payload(recipe, Value::Null, Value::Null, None);
        let (_, cordoned) = self
            .member_step(first, "cordon", plain, vec![sequence.clone()])
            .await?;
        fields["cordoned"] = cordoned["member"]["cordoned"].clone();
        if !recipe["writer_move"].is_null() {
            self.writer_move(recipe, fields).await?;
        }
        let mut halted = false;
        let mut pages: Vec<Value> = Vec::new();
        let mut cited: Vec<Value> = Vec::new();
        for page in 0..CLASSIFY_PAGES {
            let after = pages.last().map_or(Value::Null, |p| p["next"].clone());
            let mut refs = vec![sequence.clone()];
            refs.extend(cited.last().cloned());
            let payload = action_payload(recipe, Value::Null, after.clone(), Some("classify"));
            if halted || page > 0 && after.is_null() {
                self.member_deselect(first, "observe-drain", payload, refs)
                    .await?;
                continue;
            }
            let (step, result) = self
                .member_step(first, "observe-drain", payload, refs)
                .await?;
            cited.push(self.recorded_sequence(&step, "member-observation")?);
            let node = result["member"].clone();
            let capped = node["total"]
                .as_u64()
                .is_none_or(|t| t > members::POD_LIMIT as u64)
                || page + 1 == CLASSIFY_PAGES && !node["next"].is_null();
            pages.push(node);
            let blocking: Vec<Value> = pages
                .iter()
                .flat_map(|p| pods(p, &["local-storage", "unmanaged"]))
                .map(|p| json!({"namespace":p["namespace"],"pod":p["pod"],"reason":p["class"]}))
                .collect();
            if capped {
                self.stopped(&step, Failure::Bound, "pod-cap").await?;
                halted = true;
            } else if let Some(block) = blocking.first() {
                let detail = if block["reason"] == "local-storage" {
                    "local-storage"
                } else {
                    "unmanaged"
                };
                fields["blocked"] = json!(blocking);
                self.stopped(&step, Failure::Readiness, detail).await?;
                halted = true;
            }
        }
        let composed = if halted {
            Vec::new()
        } else {
            members::compose_pages(&json!(pages)).map_err(|_| Failure::Integrity)?
        };
        let batches = members::eviction_pages(&composed);
        let mut evicted: Vec<Value> = Vec::new();
        for page in 0..EVICT_PAGES {
            let batch = batches.get(page).cloned().unwrap_or_default();
            let mut refs = vec![sequence.clone()];
            refs.extend(cited.iter().cloned());
            let empty = batch.is_empty();
            let payload = action_payload(recipe, json!(batch), Value::Null, None);
            if halted || empty {
                self.member_deselect(first, "evict", payload, refs).await?;
                continue;
            }
            let (_, result) = self.member_step(first, "evict", payload, refs).await?;
            if self.mode == Mode::SettlementOnly {
                let kept: Vec<Value> = result["member"]["pods"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| json!({"namespace":p["namespace"],"pod":p["pod"],"reason":"pdb"}))
                    .collect();
                evicted.extend(batch.into_iter().filter(|p| {
                    !kept
                        .iter()
                        .any(|k| k["namespace"] == p["namespace"] && k["pod"] == p["pod"])
                }));
                fields["blocked"] = json!(kept);
                self.local.failure_detail = Some("pdb");
                halted = true;
            } else {
                evicted.extend(batch);
            }
        }
        fields["evicted"] = json!(
            composed
                .iter()
                .filter(|p| {
                    p["class"] == "evictable"
                        && (p["terminating"] == true
                            || evicted
                                .iter()
                                .any(|e| e["namespace"] == p["namespace"] && e["pod"] == p["pod"]))
                })
                .map(|p| json!({"namespace":p["namespace"],"pod":p["pod"]}))
                .collect::<Vec<_>>()
        );
        let wait = action_payload(recipe, Value::Null, Value::Null, Some("wait"));
        let named = action_payload(recipe, Value::Null, Value::Null, Some("remaining"));
        if halted {
            self.member_deselect(first, "observe-drain", wait, vec![sequence.clone()])
                .await?;
            for _ in 0..NAMING_PAGES {
                self.member_deselect(
                    first,
                    "observe-drain",
                    named.clone(),
                    vec![sequence.clone()],
                )
                .await?;
            }
            return self.settle(&order).await;
        }
        let (step, _, done) = self
            .drain_wait(first, wait, vec![sequence.clone()], unreachable)
            .await?;
        let settling = self.recorded_sequence(&step, "member-observation")?;
        if done {
            for _ in 0..NAMING_PAGES {
                self.member_deselect(
                    first,
                    "observe-drain",
                    named.clone(),
                    vec![sequence.clone(), settling.clone()],
                )
                .await?;
            }
            return self.settle(&order).await;
        }
        if unreachable {
            self.stopped(&step, Failure::Timeout, "replacement-pods")
                .await?;
        } else {
            self.stopped(&step, Failure::Readiness, "pdb").await?;
        }
        let mut naming: Vec<Value> = Vec::new();
        let mut refs = vec![sequence.clone(), settling];
        let mut payload = named;
        for page in 0..NAMING_PAGES {
            if page > 0 && payload["expected"]["after"].is_null() {
                self.member_deselect(first, "observe-drain", payload.clone(), refs.clone())
                    .await?;
                continue;
            }
            let (step, result) = self
                .member_step(first, "observe-drain", payload, refs)
                .await?;
            refs = vec![
                sequence.clone(),
                self.recorded_sequence(&step, "member-observation")?,
            ];
            payload = action_payload(
                recipe,
                Value::Null,
                result["member"]["next"].clone(),
                Some("remaining"),
            );
            naming.push(result["member"].clone());
        }
        let named = members::compose_naming(&json!(naming)).map_err(|_| Failure::Integrity)?;
        if unreachable {
            fields["evicted"] = json!(
                named["pods"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| json!({"namespace":p["namespace"],"pod":p["pod"]}))
                    .collect::<Vec<_>>()
            );
            fields["truncated"] = named["truncated"].clone();
            return self.settle(&order).await;
        }
        fields["blocked"] = json!(
            named["pods"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| json!({"namespace":p["namespace"],"pod":p["pod"],"reason":"pdb"}))
                .collect::<Vec<_>>()
        );
        fields["truncated"] = named["truncated"].clone();
        self.settle(&order).await
    }
}

impl Session<'_> {
    async fn family_mutation(
        &mut self,
        family: &Family,
        index: usize,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<(Value, Value)> {
        self.context.check()?;
        require(self.mode == Mode::Work, Failure::Capability)?;
        let action = format!("lifecycle:{}-{tag}", family.name);
        let step = self.intended(index, &action, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let child = self.context.clock.for_credential_action(deadline);
        let observed = network::invoke(
            &self.context,
            family,
            &binding,
            tag,
            &payload,
            deadline,
            Some(&child),
        )
        .await;
        self.local.completion_unknown |=
            observed.failure.is_some() && observed.transport["dispatch"] != "none";
        if observed.failure.is_some()
            || observed
                .response
                .as_ref()
                .is_some_and(|result| result["status"] != "ok")
        {
            self.local
                .limit_observation(self.context.clock.terminal_deadline());
        }
        self.append(
            &step,
            json!({"type":"dispatch","transport":observed.transport,
                "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                "failure":observed.failure.map(Failure::name)}),
            false,
            Value::Null,
        )
        .await?;
        let result = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        self.local.completion_unknown |=
            result["status"] == "unknown" || result["terminal"]["effect"] == "unknown";
        require(
            result["kind"] == "result"
                && (result["failure"].is_null() == (result["status"] == "ok")),
            Failure::Integrity,
        )?;
        if let Some(receipt) = result["terminal"].as_object() {
            let receipt = Value::Object(receipt.clone());
            require(
                receipt["binding"] == binding
                    && receipt["action"] == action
                    && receipt["payload_sha256"] == step["payload_sha256"],
                Failure::Ownership,
            )?;
            self.append(
                &step,
                json!({"type":"receiver","receipt":receipt,"transport":observed.transport}),
                true,
                receipt["completed_ms"].clone(),
            )
            .await?;
        }
        require(result["status"] == "ok", super::server::refused(&result))?;
        require(
            result["terminal"]["outcome"] == "succeeded"
                && result["terminal"]["effect"] == "complete"
                && result["terminal"]["writer_ended"] == true,
            Failure::Readiness,
        )?;
        let mut child = child;
        child.complete().map_err(|_| Failure::Timeout)?;
        self.next_step += 1;
        Ok((step, result))
    }

    async fn family_read(
        &mut self,
        family: &Family,
        index: usize,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<Value> {
        self.context.check()?;
        let action = format!("lifecycle:{}-{tag}", family.name);
        let step = self.intended(index, &action, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let observed = network::invoke(
            &self.context,
            family,
            &binding,
            tag,
            &payload,
            deadline,
            None,
        )
        .await;
        if observed.failure.is_some()
            || observed
                .response
                .as_ref()
                .is_some_and(|result| result["status"] != "ok")
        {
            self.local
                .limit_observation(self.context.clock.terminal_deadline());
        }
        self.append(
            &step,
            json!({"type":"dispatch","transport":observed.transport,
                "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                "failure":observed.failure.map(Failure::name)}),
            false,
            Value::Null,
        )
        .await?;
        let result = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(
            result["kind"] == "result"
                && (result["failure"].is_null() == (result["status"] == "ok")),
            Failure::Integrity,
        )?;
        require(result["status"] == "ok", super::server::refused(&result))?;
        replication::shape(tag, &result)?;
        let member = if tag == "inspect-replication" {
            self.members[index].clone()
        } else {
            Value::Null
        };
        self.append(
            &step,
            json!({"type":replication::OBSERVATION,"member":member,
                "replication":result["replication"],"objects":result["objects"],
                "readers":result["readers"],"tokens":result["tokens"],"writer":result["writer"],
                "node":result["node"],"cordoned":null}),
            true,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok(result)
    }

    async fn writer_move(&mut self, recipe: &Value, fields: &mut Value) -> Result<()> {
        let snapshot = self.local.snapshot()?;
        let owner = snapshot.owner.clone();
        let operation = snapshot.request["operation"].clone();
        let moved = recipe["writer_move"].clone();
        let unreachable = recipe["reachability"] == "unreachable";
        let from = self
            .members
            .iter()
            .position(|m| m["member"] == moved["from"]);
        let mut paused = None;
        let mut old = Value::Null;
        for (index, tag, payload, refs) in self.move_layout(recipe)? {
            if replication::mutation(tag) {
                if tag == "stop-writer" {
                    paused = Some(tokio::time::Instant::now());
                }
                let moved = self
                    .family_mutation(&replication::FAMILY, index, tag, payload, refs.clone())
                    .await;
                if moved.is_err() {
                    self.local.failure_detail = Some("writer-move");
                }
                moved?;
                continue;
            }
            let result = self
                .family_read(&replication::FAMILY, index, tag, payload, refs.clone())
                .await;
            let result = match result {
                Ok(result) => result,
                Err(failure) => {
                    self.local.failure_detail = Some("writer-move");
                    return Err(failure);
                }
            };
            let proved = match tag {
                "inspect-replication" if Some(index) == from => {
                    old = result["replication"].clone();
                    crate::k3s::replication::completion_proved(&old, &json!({"state":"in-sync"}))
                }
                "inspect-replication" if unreachable => result["replication"]["state"] == "in-sync",
                "inspect-replication" => {
                    crate::k3s::replication::completion_proved(&old, &result["replication"])
                }
                _ => {
                    result["writer"]["process"]["state"] == "ready"
                        && result["writer"]["process"]["node"] == moved["to"]
                }
            };
            if !proved {
                self.local.failure_detail = Some("writer-move");
                return Err(if tag == "inspect-objects" {
                    Failure::Readiness
                } else {
                    Failure::Timeout
                });
            }
        }
        let pause = paused.map_or(0, |start| start.elapsed().as_millis());
        let snapshot = self.local.snapshot()?;
        let step = snapshot
            .steps
            .iter()
            .rev()
            .find(|s| s["action"] == replication::action("inspect-objects").as_str())
            .cloned()
            .ok_or(Failure::Integrity)?;
        self.append(
            &step,
            json!({"type":"writer-move","from":moved["from"],"to":moved["to"],
                "operation":operation,"loss_possible":moved["loss_possible"]}),
            false,
            Value::Null,
        )
        .await?;
        let mut successor = owner.clone();
        successor["previous_generation"] = owner["generation"].clone();
        successor["generation"] = json!(fresh()?);
        successor["created_ms"] = json!(now()?);
        successor["writer"] = json!({"member":moved["to"],"operation":operation,
            "moves":owner["writer"]["moves"].as_u64().unwrap_or(0) + 1});
        if owner.get("removed").is_none() {
            successor["removed"] = json!([]);
            successor["maintained"] = json!(false);
        }
        let id = operation.as_str().ok_or(Failure::Integrity)?.to_owned();
        self.local
            .work(move |store| store.replace_owner(successor, &id))
            .await?;
        fields["writer_move"] = json!({"completion_checked":!unreachable,"from":moved["from"],
            "loss_possible":moved["loss_possible"],"pause_duration_ms":pause,"to":moved["to"]});
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn move_layout(&self, recipe: &Value) -> Result<Vec<(usize, &'static str, Value, Vec<Value>)>> {
        let snapshot = self.local.snapshot()?;
        let refs = vec![
            network::latest_sequence(snapshot, "member-recipe")?,
            network::latest_sequence(snapshot, "replication-recipe")?,
        ];
        let replicated = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "replication-recipe")
            .map(|o| &o["event"]["recipe"])
            .ok_or(Failure::Integrity)?;
        let timeout = &snapshot.request["step_timeout_ms"];
        let moved = &recipe["writer_move"];
        let unreachable = recipe["reachability"] == "unreachable";
        let at = |member: &Value| {
            self.members
                .iter()
                .position(|m| m["member"] == *member)
                .ok_or(Failure::Integrity)
        };
        let mut layout = Vec::new();
        for (position, (tag, role)) in MOVE.iter().enumerate() {
            if unreachable && matches!(position, 1 | 2 | 4) {
                continue;
            }
            if unreachable && position == 5 {
                for member in replicated["members"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .iter()
                    .filter(|m| m["member"] != moved["from"])
                {
                    let index = at(&member["member"])?;
                    let recipient = &self.members[index];
                    let resource = replication_resource(&snapshot.owner, recipient)?;
                    let payload =
                        device_payload(Some(replicated), &resource, &recipe["member"], recipient)?;
                    layout.push((index, "remove-device", payload, refs.clone()));
                }
            }
            let index = if *role == "first" {
                self.index_of(&recipe["first_server"])?
            } else {
                at(&moved[*role])?
            };
            let payload = move_payload(replicated, recipe, &snapshot.owner, position, timeout)?;
            layout.push((index, *tag, payload, refs.clone()));
        }
        Ok(layout)
    }

    async fn deselect_drain(&mut self, recipe: &Value) -> Result<()> {
        let sequence = network::latest_sequence(self.local.snapshot()?, "member-recipe")?;
        let first = self.index_of(&recipe["first_server"])?;
        let refs = vec![sequence];
        let plain = action_payload(recipe, Value::Null, Value::Null, None);
        self.member_deselect(first, "cordon", plain, refs.clone())
            .await?;
        if !recipe["writer_move"].is_null() {
            for (index, tag, payload, cited) in self.move_layout(recipe)? {
                self.listed_deselect(index, &replication::action(tag), payload, cited)
                    .await?;
            }
        }
        let classify = action_payload(recipe, Value::Null, Value::Null, Some("classify"));
        for _ in 0..CLASSIFY_PAGES {
            self.member_deselect(first, "observe-drain", classify.clone(), refs.clone())
                .await?;
        }
        let evict = action_payload(recipe, json!([]), Value::Null, None);
        for _ in 0..EVICT_PAGES {
            self.member_deselect(first, "evict", evict.clone(), refs.clone())
                .await?;
        }
        let wait = action_payload(recipe, Value::Null, Value::Null, Some("wait"));
        self.member_deselect(first, "observe-drain", wait, refs.clone())
            .await?;
        let named = action_payload(recipe, Value::Null, Value::Null, Some("remaining"));
        for _ in 0..NAMING_PAGES {
            self.member_deselect(first, "observe-drain", named.clone(), refs.clone())
                .await?;
        }
        Ok(())
    }

    async fn removal_round(&mut self, removed: &Value) -> Result<()> {
        let snapshot = self.local.snapshot()?;
        let cluster = snapshot.request["cluster"].clone();
        let member_recipe = network::latest_sequence(snapshot, "member-recipe")?;
        let event_of = |sequence: &Value| {
            snapshot
                .observations
                .iter()
                .find(|o| o["sequence"] == *sequence)
                .map(|o| o["event"].clone())
                .ok_or(Failure::Integrity)
        };
        let recipe_event = event_of(&member_recipe)?;
        let target = removal_target(&snapshot.observations, removed);
        let sources: Vec<(Value, Value)> = snapshot
            .observations
            .iter()
            .filter(|o| {
                o["event"]["type"] == "server-recipe" && o["event"]["recipe"]["member"] != *removed
            })
            .map(|o| (o["sequence"].clone(), o["event"].clone()))
            .collect();
        let remaining = sources.len();
        for (sequence, event) in sources {
            let index = self.index_of(&event["recipe"]["member"])?;
            let payload = members::removal_payload(&event, &recipe_event, &target)
                .map_err(|_| Failure::Integrity)?;
            let (result, _) = self
                .slot_citing(
                    index,
                    "observe-membership",
                    payload,
                    vec![member_recipe.clone(), sequence],
                )
                .await?;
            let view = &result["membership"];
            let voters = view["members"].as_array().ok_or(Failure::Integrity)?;
            require(
                view["cluster"] == cluster
                    && view["node_uid"] == self.members[index]["node_uid"]
                    && view["observer"] == self.members[index]["machine"],
                Failure::Ownership,
            )?;
            require(
                view["healthy"] == true
                    && voters.len() == remaining
                    && !voters.iter().any(|v| v["name"] == removed["member"]),
                Failure::Readiness,
            )?;
        }
        Ok(())
    }

    async fn replacement_round(&mut self) -> Result<()> {
        let snapshot = self.local.snapshot()?;
        let cluster = snapshot.request["cluster"].clone();
        let sources: Vec<(Value, Value)> = snapshot
            .observations
            .iter()
            .filter(|o| o["event"]["type"] == "server-recipe")
            .map(|o| (o["sequence"].clone(), o["event"].clone()))
            .collect();
        let servers = sources.len();
        for (sequence, event) in sources {
            let index = self.index_of(&event["recipe"]["member"])?;
            let payload = json!({"recipe_kind":event["recipe_kind"],"recipe":event["recipe"],
                "identity":null,"membership":null,"removed":null});
            let (result, _) = self
                .slot_polled(
                    index,
                    "observe-membership",
                    payload,
                    vec![sequence],
                    Some(servers),
                )
                .await?;
            let view = &result["membership"];
            require(
                view["cluster"] == cluster
                    && view["node_uid"] == self.members[index]["node_uid"]
                    && view["observer"] == self.members[index]["machine"],
                Failure::Ownership,
            )?;
            require(
                view["healthy"] == true
                    && view["members"]
                        .as_array()
                        .is_some_and(|voters| voters.len() == servers),
                Failure::Readiness,
            )?;
        }
        Ok(())
    }

    async fn final_view(
        &mut self,
        first: usize,
        read: &Value,
        recipe_sequence: &Value,
        removing: bool,
    ) -> Result<()> {
        let removed = if removing {
            read["recipe"]["member"].clone()
        } else {
            Value::Null
        };
        let snapshot = self.local.snapshot()?;
        let cluster = snapshot.request["cluster"].clone();
        let participants: Vec<Value> = snapshot.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let Some((sequence, recipe)) = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "agent-join-recipe")
            .map(|o| (o["sequence"].clone(), o["event"]["recipe"].clone()))
        else {
            if !removing {
                return self.replacement_round().await;
            }
            if removed["role"] == "server" {
                return self.removal_round(&removed).await;
            }
            let view = action_payload(&read["recipe"], Value::Null, Value::Null, Some("classify"));
            let (_, result) = self
                .member_step(first, "observe-drain", view, vec![recipe_sequence.clone()])
                .await?;
            return require(result["member"]["present"] == false, Failure::Readiness);
        };
        let payload = json!({"recipe":recipe,"identity":null,"agent_view":null});
        let step = self.intended(
            first,
            "lifecycle:observe-agent-membership",
            &payload,
            vec![sequence],
        )?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let mut dispatches = 0;
        let result = loop {
            let observed = super::server::invoke(
                &self.context,
                &binding,
                "observe-agent-membership",
                &payload,
                deadline,
                None,
            )
            .await;
            dispatches += 1;
            if observed.failure.is_some() {
                self.local
                    .limit_observation(self.context.clock.terminal_deadline());
            }
            self.append(
                &step,
                json!({"type":"dispatch","transport":observed.transport,
                    "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                    "failure":observed.failure.map(Failure::name)}),
                false,
                Value::Null,
            )
            .await?;
            let result = observed
                .result
                .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
            let passed = removal_view(
                &self.context,
                &participants,
                &removed,
                &cluster,
                &result["agent_view"],
            )
            .is_ok();
            if result["status"] != "ok"
                || passed
                || dispatches == super::node::GATE_CAP
                || tokio::time::Instant::now() + Duration::from_secs(5) >= deadline
            {
                break result;
            }
            self.context.check()?;
            tokio::time::sleep(Duration::from_secs(5)).await;
        };
        require(result["status"] == "ok", super::server::refused(&result))?;
        self.settlement(&step, &result, &payload)?;
        self.append(
            &step,
            json!({"type":"agent-membership","view":result["agent_view"]}),
            true,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        removal_view(
            &self.context,
            &participants,
            &removed,
            &cluster,
            &result["agent_view"],
        )
        .map_err(|failure| match failure {
            Failure::Ownership => Failure::Readiness,
            other => other,
        })
    }

    async fn remove(
        &mut self,
        recipe: &Value,
        replicated: bool,
        fields: &mut Value,
    ) -> Result<Snapshot> {
        let order = self.member_acquire().await?;
        let unreachable = recipe["reachability"] == "unreachable";
        if unreachable {
            if let Some((step, refused)) = self.readiness_slot(recipe).await? {
                self.stopped(
                    &step,
                    refused.failure,
                    refused.boundary.unwrap_or("readiness"),
                )
                .await?;
                self.deselect_removal(recipe, replicated).await?;
                return self.settle(&order).await;
            }
        }
        let snapshot = self.local.snapshot()?;
        let sequence = network::latest_sequence(snapshot, "member-recipe")?;
        let replication_sequence = if replicated {
            Some(network::latest_sequence(snapshot, "replication-recipe")?)
        } else {
            None
        };
        let replication_recipe = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "replication-recipe")
            .map(|o| o["event"]["recipe"].clone());
        let owner = snapshot.owner.clone();
        let operation = snapshot.request["operation"].clone();
        let removed = recipe["member"].clone();
        let selected = self.members.iter().position(|m| *m == removed);
        let first = self.index_of(&recipe["first_server"])?;
        let read = action_payload(recipe, Value::Null, Value::Null, None);
        match selected {
            Some(selected) if !unreachable => {
                self.member_step(
                    selected,
                    "stop-member",
                    read.clone(),
                    vec![sequence.clone()],
                )
                .await?;
                fields["removed"]["services_stopped"] = json!("done");
            }
            None if unreachable => {
                self.deselect_on(
                    &removed,
                    "stop-member",
                    read.clone(),
                    vec![sequence.clone()],
                )
                .await?;
            }
            _ => return Err(Failure::Integrity),
        }
        let (_, deleted) = self
            .member_step(first, "delete-node", read.clone(), vec![sequence.clone()])
            .await?;
        require(deleted["member"]["present"] == false, Failure::Readiness)?;
        fields["removed"]["node"] = json!("done");
        if removed["role"] == "server" {
            self.removal_round(&removed).await?;
            fields["removed"]["etcd_member"] = json!("done");
        }
        let others: Vec<usize> = (0..self.members.len())
            .filter(|&i| Some(i) != selected)
            .collect();
        for &index in &others {
            let mut refs = vec![sequence.clone()];
            match &replication_sequence {
                Some(replication_sequence) => {
                    let resource = replication_resource(&owner, &self.members[index])?;
                    let payload = device_payload(
                        replication_recipe.as_ref(),
                        &resource,
                        &removed,
                        &self.members[index],
                    )?;
                    refs.push(replication_sequence.clone());
                    self.family_mutation(
                        &replication::FAMILY,
                        index,
                        "remove-device",
                        payload,
                        refs,
                    )
                    .await?;
                }
                None => {
                    let payload =
                        device_payload(None, &Value::Null, &removed, &self.members[index])?;
                    self.listed_deselect(
                        index,
                        &replication::action("remove-device"),
                        payload,
                        refs,
                    )
                    .await?;
                }
            }
        }
        fields["removed"]["device_removed"] =
            json!(if replicated { "done" } else { "not-applicable" });
        self.final_view(first, &read, &sequence, true).await?;
        let survivors: Vec<Value> = others.iter().map(|&i| self.members[i].clone()).collect();
        let participants = super::participants(&json!(survivors))?;
        for &index in order.iter().filter(|&&i| Some(i) != selected) {
            self.dispatch(
                index,
                "rebind-claim",
                json!({"members":survivors,"participants_sha256":participants}),
                Vec::new(),
            )
            .await?;
            fields["removed"]["claims_rebound"]
                .as_array_mut()
                .ok_or(Failure::Integrity)?
                .push(self.members[index]["member"].clone());
        }
        let settled = self.settle(&order).await?;
        let successor = successor(&settled.owner, recipe, &operation)?;
        let named = operation.as_str().ok_or(Failure::Integrity)?.to_owned();
        self.local
            .work(move |store| store.replace_owner(successor, &named))
            .await?;
        Ok(self.local.snapshot()?.clone())
    }

    async fn deselect_on(
        &mut self,
        recipient: &Value,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<()> {
        self.context.check()?;
        let snapshot = self.local.snapshot()?;
        let step = json!({"schema":1,"kind":"step","scope":snapshot.request["scope"],
            "owner":snapshot.request["owner"],"operation":snapshot.request["operation"],
            "attempt":self.attempt["attempt"],"step":self.next_step,
            "original_step":self.attempt["original_step"],"created_ms":now()?,"dispatch":fresh()?,
            "action":step_action(tag),"recipient":recipient,"resource":null,
            "expected_receiver_generation":0,"request_sha256":self.attempt["request_sha256"],
            "payload_sha256":hash("broil-infra-step-v1", &payload)?,"payload_observations":refs});
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.append(
            &step,
            json!({"type":"dispatch","transport":super::provenance::undispatched_transport(),
                "outcome":"succeeded","failure":null}),
            false,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok(())
    }

    async fn once(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<(Value, Value)> {
        self.context.check()?;
        let step = self.intended(index, &format!("lifecycle:{tag}"), &payload, refs)?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let observed =
            super::server::invoke(&self.context, &binding, tag, &payload, deadline, None).await;
        if observed.failure.is_some() {
            self.local
                .limit_observation(self.context.clock.terminal_deadline());
        }
        self.append(
            &step,
            json!({"type":"dispatch","transport":observed.transport,
                "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                "failure":observed.failure.map(Failure::name)}),
            false,
            Value::Null,
        )
        .await?;
        let result = observed
            .result
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(result["status"] == "ok", super::server::refused(&result))?;
        self.settlement(&step, &result, &payload)?;
        let event = if tag == "observe-membership" {
            json!({"type":"server-membership","member":self.members[index],
                "membership":result["membership"]})
        } else {
            json!({"type":"agent-membership","view":result["agent_view"]})
        };
        self.append(&step, event, true, Value::Null).await?;
        self.next_step += 1;
        Ok((step, result))
    }

    async fn readiness_slot(&mut self, recipe: &Value) -> Result<Option<(Value, Refusal)>> {
        let snapshot = self.local.snapshot()?;
        let cluster = snapshot.request["cluster"].clone();
        let participants = snapshot.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let agent = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "agent-join-recipe")
            .map(|o| (o["sequence"].clone(), o["event"]["recipe"].clone()));
        let servers: Vec<(Value, Value)> = snapshot
            .observations
            .iter()
            .filter(|o| {
                o["event"]["type"] == "server-recipe"
                    && o["event"]["recipe"]["member"] != recipe["member"]
            })
            .map(|o| (o["sequence"].clone(), o["event"].clone()))
            .collect();
        let mut expected = Vec::new();
        for member in &participants {
            let (labels, taints) = network::declared(&self.context, member)?;
            expected.push(json!({"member":member,"node_uid":member["node_uid"],
                "role":member["role"],"labels":labels,"taints":taints}));
        }
        let (step, view, slots) = match agent {
            Some((sequence, agent)) => {
                let first = self.index_of(&recipe["first_server"])?;
                let payload = json!({"recipe":agent,"identity":null,"agent_view":null});
                let (step, result) = self
                    .once(first, "observe-agent-membership", payload, vec![sequence])
                    .await?;
                (step, result["agent_view"].clone(), Value::Null)
            }
            None => {
                let mut last = Value::Null;
                let mut slots = Vec::new();
                for (sequence, event) in servers {
                    let index = self.index_of(&event["recipe"]["member"])?;
                    let payload = json!({"recipe_kind":event["recipe_kind"],
                        "recipe":event["recipe"],"identity":null,"membership":null,"removed":null});
                    let (step, result) = self
                        .once(index, "observe-membership", payload, vec![sequence])
                        .await?;
                    let view = &result["membership"];
                    let member = &self.members[index];
                    slots.push(json!({"observer":member["machine"],
                        "healthy":view["healthy"] == true && view["cluster"] == cluster
                            && view["node_uid"] == member["node_uid"]
                            && view["observer"] == member["machine"]}));
                    last = step;
                }
                (last, Value::Null, json!(slots))
            }
        };
        let input = json!({"member":recipe["member"]["member"],"expected":expected,
            "view":view,"round":slots});
        if let Err(refused) = members::readiness_read(&input) {
            return Ok(Some((step, rule(refused))));
        }
        let machine = recipe["member"]["machine"]
            .as_str()
            .ok_or(Failure::Integrity)?;
        Ok(match self.context.probe(machine).await {
            Err(Failure::Transport) => None,
            Err(failure) => return Err(failure),
            Ok(_) => Some((
                step,
                refusal(
                    Failure::Ownership,
                    "stale-approval",
                    format!(
                        "{} answers again; the observed plan no longer holds",
                        recipe["member"]["member"].as_str().unwrap_or("")
                    ),
                ),
            )),
        })
    }

    async fn deselect_removal(&mut self, recipe: &Value, replicated: bool) -> Result<()> {
        let snapshot = self.local.snapshot()?;
        let sequence = network::latest_sequence(snapshot, "member-recipe")?;
        let recipe_event = json!({"recipe":recipe});
        let replication = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "replication-recipe")
            .map(|o| (o["sequence"].clone(), o["event"]["recipe"].clone()));
        let agent = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "agent-join-recipe")
            .map(|o| (o["sequence"].clone(), o["event"]["recipe"].clone()));
        let sources: Vec<(Value, Value)> = snapshot
            .observations
            .iter()
            .filter(|o| {
                o["event"]["type"] == "server-recipe"
                    && o["event"]["recipe"]["member"] != recipe["member"]
            })
            .map(|o| (o["sequence"].clone(), o["event"].clone()))
            .collect();
        let target = removal_target(&snapshot.observations, &recipe["member"]);
        let owner = snapshot.owner.clone();
        let removed = recipe["member"].clone();
        let first = self.index_of(&recipe["first_server"])?;
        let read = action_payload(recipe, Value::Null, Value::Null, None);
        self.deselect_on(
            &removed,
            "stop-member",
            read.clone(),
            vec![sequence.clone()],
        )
        .await?;
        self.member_deselect(first, "delete-node", read.clone(), vec![sequence.clone()])
            .await?;
        let server = removed["role"] == "server";
        let mut round = Vec::new();
        for (source, event) in &sources {
            let index = self.index_of(&event["recipe"]["member"])?;
            let payload = members::removal_payload(event, &recipe_event, &target)
                .map_err(|_| Failure::Integrity)?;
            round.push((index, payload, vec![sequence.clone(), source.clone()]));
        }
        if server {
            for (index, payload, refs) in round.clone() {
                self.listed_deselect(index, "lifecycle:observe-membership", payload, refs)
                    .await?;
            }
        }
        for index in 0..self.members.len() {
            let member = self.members[index].clone();
            let mut refs = vec![sequence.clone()];
            let payload = match (&replication, replicated) {
                (Some((source, recipe)), true) => {
                    refs.push(source.clone());
                    let resource = replication_resource(&owner, &member)?;
                    device_payload(Some(recipe), &resource, &removed, &member)?
                }
                _ => device_payload(None, &Value::Null, &removed, &member)?,
            };
            self.listed_deselect(index, &replication::action("remove-device"), payload, refs)
                .await?;
        }
        match &agent {
            Some((source, agent)) => {
                let payload = json!({"recipe":agent,"identity":null,"agent_view":null});
                self.listed_deselect(
                    first,
                    "lifecycle:observe-agent-membership",
                    payload,
                    vec![source.clone()],
                )
                .await?;
            }
            None if server => {
                for (index, payload, refs) in round {
                    self.listed_deselect(index, "lifecycle:observe-membership", payload, refs)
                        .await?;
                }
            }
            None => {
                let view = action_payload(recipe, Value::Null, Value::Null, Some("classify"));
                self.member_deselect(first, "observe-drain", view, vec![sequence.clone()])
                    .await?;
            }
        }
        let participants = super::participants(&json!(self.members))?;
        for index in 0..self.members.len() {
            let payload = json!({"members":self.members,"participants_sha256":participants});
            self.listed_deselect(index, "rebind-claim", payload, Vec::new())
                .await?;
        }
        Ok(())
    }

    async fn rebind(&mut self, deleted: &[String]) -> Result<Snapshot> {
        let order = self.member_acquire().await?;
        let settled = self.settle(&order).await?;
        let operation = settled.request["operation"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        let successor = rebound(&settled.owner, deleted, &self.context.owner_fingerprints)?;
        self.local
            .work(move |store| store.replace_owner(successor, &operation))
            .await?;
        Ok(self.local.snapshot()?.clone())
    }

    async fn replace_complete(&mut self, recipe: &Value, replicated: bool) -> Result<Snapshot> {
        let order = self.member_acquire().await?;
        let snapshot = self.local.snapshot()?;
        let sequence = network::latest_sequence(snapshot, "member-recipe")?;
        let replication_recipe = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "replication-recipe")
            .map(|o| o["event"]["recipe"].clone());
        let mut refs = vec![sequence.clone()];
        if replicated {
            refs.push(network::latest_sequence(snapshot, "replication-recipe")?);
        }
        let timeout = snapshot.request["step_timeout_ms"].clone();
        let member = recipe["member"].clone();
        let selected = self.index_of(&member)?;
        let first = self.index_of(&recipe["first_server"])?;
        let payload = replica_payload(replication_recipe.as_ref(), &member, &timeout)?;
        let mut incomplete = false;
        if replicated {
            let result = self
                .family_read(
                    &replication::FAMILY,
                    selected,
                    "inspect-replication",
                    payload,
                    refs,
                )
                .await?;
            if result["replication"]["state"] != "in-sync" {
                let step = self
                    .local
                    .snapshot()?
                    .steps
                    .last()
                    .cloned()
                    .ok_or(Failure::Integrity)?;
                self.stopped(&step, Failure::Timeout, "replica-incomplete")
                    .await?;
                incomplete = true;
            }
        } else {
            self.listed_deselect(
                selected,
                &replication::action("inspect-replication"),
                payload,
                refs,
            )
            .await?;
        }
        let read = action_payload(recipe, Value::Null, Value::Null, None);
        if incomplete {
            let snapshot = self.local.snapshot()?;
            let (agents, agent_recipe) = snapshot
                .observations
                .iter()
                .find(|o| o["event"]["type"] == "agent-join-recipe")
                .map(|o| (o["sequence"].clone(), o["event"]["recipe"].clone()))
                .ok_or(Failure::Capability)?;
            self.listed_deselect(
                first,
                "lifecycle:observe-agent-membership",
                json!({"recipe":agent_recipe,"identity":null,"agent_view":null}),
                vec![agents],
            )
            .await?;
            return match self.settle(&order).await {
                Err(Failure::Readiness) => Err(Failure::Timeout),
                other => other,
            };
        }
        self.final_view(first, &read, &sequence, false).await?;
        self.settle(&order).await
    }

    async fn replace_begin(
        &mut self,
        transition: &Value,
        participants: &[Value],
    ) -> Result<Snapshot> {
        let order = self.member_acquire().await?;
        let hash = super::participants(&json!(participants))?;
        require(
            transition["new_participants_sha256"] == json!(hash),
            Failure::Integrity,
        )?;
        for &index in &order {
            self.dispatch(
                index,
                "rebind-claim",
                json!({"members":participants,"participants_sha256":hash}),
                Vec::new(),
            )
            .await?;
        }
        let settled = self.settle(&order).await?;
        let entry = participants
            .iter()
            .find(|m| m["member"] == transition["member"])
            .ok_or(Failure::Integrity)?;
        let successor = begun(
            &settled.owner,
            transition,
            entry,
            &self.context.owner_fingerprints,
        )?;
        let operation = settled.request["operation"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        self.local
            .work(move |store| store.replace_owner(successor, &operation))
            .await?;
        Ok(self.local.snapshot()?.clone())
    }
}

impl Snapshot {
    pub(super) fn member_device_payload(&self, step: &Value) -> Result<Value> {
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        if self.request["action"] == "node-drain" {
            return self.member_move_payload(step);
        }
        if self.request["action"] == "node-replace" {
            return self.member_replica_payload(step);
        }
        require(
            step["action"] == replication::action("remove-device").as_str()
                && self.request["action"] == "node-remove"
                && matches!(refs.len(), 1 | 2),
            Failure::Capability,
        )?;
        let observed = |sequence: &Value, kind: &str| -> Result<&Value> {
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == *sequence)
                .ok_or(Failure::Integrity)?;
            require(
                observation["operation"] == step["operation"]
                    && observation["attempt"] == step["attempt"]
                    && observation["event"]["type"] == kind,
                Failure::Ownership,
            )?;
            Ok(&observation["event"]["recipe"])
        };
        let removed = &observed(&refs[0], "member-recipe")?["member"];
        require(
            step["recipient"] != *removed && *removed != Value::Null,
            Failure::Ownership,
        )?;
        let payload = match refs.get(1) {
            Some(sequence) => {
                let recipe = observed(sequence, "replication-recipe")?;
                require(
                    recipe["operation"] == self.request["operation"],
                    Failure::Ownership,
                )?;
                let resource = replication_resource(&self.owner, &step["recipient"])?;
                device_payload(Some(recipe), &resource, removed, &step["recipient"])?
            }
            None => device_payload(None, &Value::Null, removed, &step["recipient"])?,
        };
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    fn member_replica_payload(&self, step: &Value) -> Result<Value> {
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            step["action"] == replication::action("inspect-replication").as_str()
                && matches!(refs.len(), 1 | 2),
            Failure::Capability,
        )?;
        let observed = |sequence: &Value, kind: &str| -> Result<&Value> {
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == *sequence)
                .ok_or(Failure::Integrity)?;
            require(
                observation["operation"] == step["operation"]
                    && observation["attempt"] == step["attempt"]
                    && observation["event"]["type"] == kind,
                Failure::Ownership,
            )?;
            Ok(&observation["event"]["recipe"])
        };
        let member_recipe = observed(&refs[0], "member-recipe")?;
        require(
            member_recipe["phase"] == "complete" && step["recipient"] == member_recipe["member"],
            Failure::Ownership,
        )?;
        let recipe = match refs.get(1) {
            Some(sequence) => {
                let recipe = observed(sequence, "replication-recipe")?;
                require(
                    recipe["operation"] == self.request["operation"],
                    Failure::Ownership,
                )?;
                Some(recipe)
            }
            None => None,
        };
        let payload = replica_payload(
            recipe,
            &member_recipe["member"],
            &self.request["step_timeout_ms"],
        )?;
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    fn member_move_payload(&self, step: &Value) -> Result<Value> {
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(refs.len() == 2, Failure::Integrity)?;
        let observed = |sequence: &Value, kind: &str| -> Result<&Value> {
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == *sequence)
                .ok_or(Failure::Integrity)?;
            require(
                observation["operation"] == step["operation"]
                    && observation["attempt"] == step["attempt"]
                    && observation["event"]["type"] == kind,
                Failure::Ownership,
            )?;
            Ok(&observation["event"]["recipe"])
        };
        let member_recipe = observed(&refs[0], "member-recipe")?;
        let recipe = observed(&refs[1], "replication-recipe")?;
        let tag = step["action"]
            .as_str()
            .and_then(|a| a.strip_prefix("lifecycle:registry-replication-"))
            .ok_or(Failure::Capability)?;
        let moved = &member_recipe["writer_move"];
        let unreachable = member_recipe["reachability"] == "unreachable";
        require(
            recipe["operation"] == self.request["operation"]
                && recipe["first_server"] == member_recipe["first_server"]
                && recipe["writer"] == moved["from"],
            Failure::Ownership,
        )?;
        if tag == "remove-device" {
            require(
                unreachable && step["recipient"]["member"] != moved["from"],
                Failure::Ownership,
            )?;
            let resource = replication_resource(&self.owner, &step["recipient"])?;
            let payload = device_payload(
                Some(recipe),
                &resource,
                &member_recipe["member"],
                &step["recipient"],
            )?;
            require(
                hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
                Failure::Integrity,
            )?;
            return Ok(payload);
        }
        let position = MOVE
            .iter()
            .position(|(t, role)| {
                *t == tag
                    && if *role == "first" {
                        step["recipient"] == member_recipe["first_server"]
                    } else {
                        step["recipient"]["member"] == moved[*role]
                    }
            })
            .ok_or(Failure::Ownership)?;
        require(
            !unreachable || !matches!(position, 1 | 2 | 4),
            Failure::Ownership,
        )?;
        let payload = move_payload(
            recipe,
            member_recipe,
            &self.owner,
            position,
            &self.request["step_timeout_ms"],
        )?;
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    pub(super) fn member_payload(&self, step: &Value) -> Result<Value> {
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let tag = step["action"]
            .as_str()
            .and_then(|a| a.strip_prefix("lifecycle:node-"))
            .filter(|t| TAGS.iter().any(|(tag, _)| tag == t))
            .ok_or(Failure::Capability)?;
        let observed = |sequence: &Value| -> Result<&Value> {
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == *sequence)
                .ok_or(Failure::Integrity)?;
            require(
                observation["operation"] == step["operation"]
                    && observation["attempt"] == step["attempt"],
                Failure::Ownership,
            )?;
            Ok(&observation["event"])
        };
        require(
            match tag {
                "evict" => {
                    (2..=1 + CLASSIFY_PAGES).contains(&refs.len())
                        || refs.len() == 1 && self.deselected(step)
                }
                "observe-drain" => matches!(refs.len(), 1 | 2),
                _ => refs.len() == 1,
            },
            Failure::Integrity,
        )?;
        let event = observed(&refs[0])?;
        require(event["type"] == "member-recipe", Failure::Ownership)?;
        let recipe = &event["recipe"];
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["action"] == self.request["action"]
                && recipe["participants"] == self.request["members"]
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && step["recipient"]
                    == recipe[if matches!(tag, "stop-member" | "start-member") {
                        "member"
                    } else {
                        "first_server"
                    }],
            Failure::Ownership,
        )?;
        let mut cited = Vec::new();
        for sequence in &refs[1..] {
            let page = observed(sequence)?;
            require(
                page["type"] == "member-observation"
                    && page["kind"] == "observe-drain"
                    && page["member"] == recipe["member"],
                Failure::Integrity,
            )?;
            cited.push(page["node"].clone());
        }
        let candidates: Vec<Value> = match tag {
            "evict" => {
                let mut batches = members::compose_pages(&json!(cited))
                    .map(|c| members::eviction_pages(&c))
                    .unwrap_or_default();
                batches.push(Vec::new());
                batches
                    .into_iter()
                    .map(|b| action_payload(recipe, json!(b), Value::Null, None))
                    .collect()
            }
            "observe-drain" => {
                let after = cited.first().map_or(Value::Null, |c| c["next"].clone());
                let mut views: Vec<Value> = ["classify", "wait", "remaining"]
                    .into_iter()
                    .map(|v| action_payload(recipe, Value::Null, after.clone(), Some(v)))
                    .collect();
                views.push(action_payload(
                    recipe,
                    Value::Null,
                    Value::Null,
                    Some("remaining"),
                ));
                views
            }
            _ => vec![action_payload(recipe, Value::Null, Value::Null, None)],
        };
        for payload in candidates {
            if hash("broil-infra-step-v1", &payload)? == step["payload_sha256"] {
                return Ok(payload);
            }
        }
        Err(Failure::Integrity)
    }

    pub(super) fn member_observation(&self, observation: &Value, step: &Value) -> Result<()> {
        let event = &observation["event"];
        let joined = self.request["action"] == "join-agent" && event["kind"] == "start-member";
        let kind = if joined {
            "agent-join-recipe"
        } else {
            "member-recipe"
        };
        let recipe = self
            .observations
            .iter()
            .find(|o| o["event"]["type"] == kind)
            .map(|o| &o["event"]["recipe"]);
        require(
            (carries(&self.request["action"]) || joined)
                && observation["source"]["kind"] == "receiver"
                && observation["source"]["machine"] == step["recipient"]["machine"]
                && event["kind"].as_str().map(step_action).as_ref()
                    == step["action"].as_str().map(str::to_owned).as_ref()
                && recipe.is_some_and(|r| event["member"] == r["member"]),
            Failure::Ownership,
        )
    }
}
