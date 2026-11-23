// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::node::{self, Configure};
use super::session::{Local, Mode, Session, fresh, now, settled};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc};
use crate::k3s::{Cluster, Generation, Operation, Policy};
use broil_config::LoadedProject;
use broil_core::k3s::RegistryFallback;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) const ENTRIES: &str = "broil-k3s-node-registries-v2";
const RESERVE: usize = 16;

#[derive(Clone, Debug)]
struct Declared {
    registry: String,
    authority: String,
    origin: String,
    username: String,
    fallback: &'static str,
    http: bool,
    managed: bool,
    ca: Option<PathBuf>,
}

fn declared(context: &rpc::Context<'_>) -> Result<Vec<Declared>> {
    let selected = &context.selected;
    let managed = selected
        .declaration
        .registry
        .as_ref()
        .and_then(|r| selected.registries.get(&r.endpoint))
        .map(|e| e.declaration.endpoint.origin());
    let nodes = &selected.declaration.node_registries;
    require(
        nodes.len() == selected.node_registry_fallbacks.len(),
        Failure::Integrity,
    )?;
    nodes
        .iter()
        .zip(&selected.node_registry_fallbacks)
        .map(|(node, fallback)| {
            let catalog = selected
                .registries
                .get(&node.registry)
                .ok_or(Failure::Configuration)?;
            let endpoint = &catalog.declaration.endpoint;
            Ok(Declared {
                registry: node.registry.clone(),
                authority: endpoint.authority.to_string(),
                origin: crate::k3s::origin(endpoint),
                username: node.username.clone(),
                fallback: match fallback {
                    RegistryFallback::Disabled => "disabled",
                    RegistryFallback::SameOrigin => "same-origin",
                },
                http: endpoint.scheme == "http",
                managed: managed.as_ref() == Some(&endpoint.origin()),
                ca: catalog.ca.clone(),
            })
        })
        .collect()
}

fn id(registry: &str) -> String {
    format!("node-registry-{registry}")
}

pub(super) fn resource(owner: &Value, registry: &str, machine: &Value, generation: &str) -> Value {
    let id = id(registry);
    let path = format!(
        "/var/lib/broil/k3s/owners/{}/resources/{id}/{generation}",
        owner["owner"].as_str().unwrap_or("")
    );
    json!({"kind":"node-registry","id":id,"owner":owner["owner"],"generation":generation,
        "machine":machine,"path":path,"namespace":null,"name":null,"uid":null})
}

fn current<'v>(owner: &'v Value, registry: &str, machine: &Value) -> Vec<&'v Value> {
    let id = id(registry);
    owner["resources"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["kind"] == "node-registry" && r["id"] == id && r["machine"] == *machine)
        .collect()
}

fn ordered(owner: &Value) -> Result<Vec<Value>> {
    let members = super::survivors(owner)?;
    Ok(["server", "agent"]
        .iter()
        .flat_map(|role| members.iter().filter(move |m| m["role"] == *role))
        .cloned()
        .collect())
}

fn succeeded(context: &rpc::Context<'_>, snapshot: &Snapshot) -> bool {
    super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        .is_ok_and(|report| report["outcome"] == "succeeded")
}

pub(super) fn pending(previous: &[Snapshot], owner: &Value) -> Result<Option<Value>> {
    Ok(super::survivors(owner)?.into_iter().find(|m| {
        m["node_uid"].is_null()
            && m["member"]
                .as_str()
                .is_some_and(|name| super::member::replacing(previous, name).is_some())
    }))
}

fn naming(failure: Failure, what: String) -> super::ExecutionFailure {
    super::ExecutionFailure {
        detail: Some(Box::leak(what.into_boxed_str())),
        ..failure.into()
    }
}

fn principal(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    entry: &Declared,
) -> Result<Value> {
    if !entry.managed {
        return Ok(Value::Null);
    }
    let found =
        super::registry_auth::current(previous, owner, &entry.username, &|s: &Snapshot| {
            succeeded(context, s)
        })?;
    Ok(found.map_or(
        Value::Null,
        |c| json!({"id":c["id"],"generation":c["generation"]}),
    ))
}

pub(super) fn inputs(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    supplied: &[(Value, String)],
) -> Result<Configure> {
    let declared = declared(context)?;
    let principals = declared
        .iter()
        .map(|d| principal(context, previous, owner, d))
        .collect::<Result<Vec<_>>>()?;
    let mut inputs = Configure {
        entries: BTreeMap::new(),
        resources: BTreeMap::new(),
    };
    for member in &super::survivors(owner)? {
        let (mut entries, mut resources) = (Vec::new(), Vec::new());
        for (d, principal) in declared.iter().zip(&principals) {
            let fresh = supplied.iter().any(|(machine, registry)| {
                *machine == member["machine"] && *registry == d.registry
            });
            let resource = if fresh {
                resource(owner, &d.registry, &member["machine"], &"f".repeat(32))
            } else {
                match current(owner, &d.registry, &member["machine"]).as_slice() {
                    [found] => (*found).clone(),
                    _ => return Err(Failure::Ownership),
                }
            };
            entries.push(
                json!({"registry":d.registry,"authority":d.authority,"origin":d.origin,
                "managed":d.managed,"username":d.username,"fallback":d.fallback,"principal":principal,
                "resource":{"id":resource["id"],"generation":resource["generation"]},
                "ca":d.ca.is_some()}),
            );
            resources.push(resource);
        }
        let name = member["member"].as_str().ok_or(Failure::Integrity)?;
        inputs
            .entries
            .insert(name.to_owned(), Value::Array(entries));
        inputs
            .resources
            .insert(name.to_owned(), Value::Array(resources));
    }
    Ok(inputs)
}

fn supplied_principal<'v>(previous: &'v [Snapshot], resource: &Value) -> Option<&'v Value> {
    previous
        .iter()
        .filter(|s| {
            s.request["action"] == "prepare-node-registry"
                && s.request["resources"] == json!([resource])
        })
        .find_map(|s| {
            s.observations
                .first()
                .filter(|o| o["event"]["type"] == "node-registry-supply")
        })
        .map(|o| &o["event"]["principal"])
}

fn stale<'v>(
    previous: &[Snapshot],
    owner: &Value,
    inputs: &'v Configure,
    replaced: &[(Value, String)],
) -> Result<Option<&'v str>> {
    for member in ordered(owner)? {
        let name = member["member"].as_str().ok_or(Failure::Integrity)?;
        let entries = inputs.entries.get(name).and_then(Value::as_array);
        let resources = inputs.resources.get(name).and_then(Value::as_array);
        let (Some(entries), Some(resources)) = (entries, resources) else {
            return Err(Failure::Integrity);
        };
        for (entry, resource) in entries.iter().zip(resources) {
            let registry = entry["registry"].as_str().ok_or(Failure::Integrity)?;
            if replaced
                .iter()
                .any(|(machine, r)| *machine == member["machine"] && r == registry)
            {
                continue;
            }
            if supplied_principal(previous, resource) != Some(&entry["principal"]) {
                return Ok(Some(registry));
            }
        }
    }
    Ok(None)
}

pub(super) fn supplied(previous: &[Snapshot], owner: &Value, inputs: &Configure) -> Result<()> {
    require(
        stale(previous, owner, inputs, &[])?.is_none(),
        Failure::Configuration,
    )
}

fn ca_file(path: &Path) -> Result<()> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Failure::Configuration)?;
    let file = std::fs::File::from(fd);
    require(
        file.metadata().is_ok_and(|m| m.is_file()),
        Failure::Configuration,
    )?;
    let length = std::io::copy(
        &mut std::io::Read::take(file, 262_145),
        &mut std::io::sink(),
    )
    .map_err(|_| Failure::Configuration)?;
    require((1..=262_144).contains(&length), Failure::Bound)
}

pub(super) fn room(owner: &Value, appended: &[Value], principals: &[&str]) -> Result<()> {
    let mut widest = owner.clone();
    for key in ["generation", "previous_generation"] {
        widest[key] = json!("f".repeat(32));
    }
    widest["created_ms"] = json!(u64::MAX);
    widest["lock_identity"] = json!([u64::MAX, u64::MAX]);
    widest["resources"]
        .as_array_mut()
        .ok_or(Failure::Integrity)?
        .extend(appended.iter().cloned());
    let reserve = match principals.iter().max_by_key(|name| name.len()) {
        None => 0,
        Some(name) => {
            let generation = json!({"kind":"registry-auth",
                "id":super::registry_auth::principal_id(name, 999),"owner":owner["owner"],
                "generation":"f".repeat(32),"machine":owner["members"][0]["machine"],"path":null,
                "namespace":"broil-registry","name":"f".repeat(52),"uid":"f".repeat(36)});
            RESERVE * (canonical(&generation)?.len() + 1)
        }
    };
    require(
        canonical(&widest)?.len() + 1 + reserve <= 65_536,
        Failure::Bound,
    )
}

fn admitted_pending(
    context: &rpc::Context<'_>,
    owner: &Value,
    declared: &[Declared],
    change: Option<&str>,
    pending: Option<&Value>,
) -> super::ExecutionResult<Vec<(Value, String)>> {
    let members = super::survivors(owner)?;
    require(
        !owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["participants_sha256"] == super::participants(&json!(members))?
            && super::declares_survivors(context, owner)?,
        Failure::Ownership,
    )?;
    require(
        members
            .iter()
            .all(|m| m["node_uid"].is_string() || Some(m) == pending)
            && (change.is_none() || pending.is_none()),
        Failure::Readiness,
    )?;
    require(
        change.is_none_or(|name| declared.iter().any(|d| d.registry == name)),
        Failure::Configuration,
    )?;
    if declared.len() > 8 {
        return Err(naming(
            Failure::Bound,
            format!("{} entries", declared.len()),
        ));
    }
    if let Some(d) = declared
        .iter()
        .find(|d| !crate::k3s::protocol::opaque(&id(&d.registry)))
    {
        return Err(naming(Failure::Bound, d.registry.clone()));
    }
    let order = ordered(owner)?;
    let mut supplies = Vec::new();
    if let Some(name) = change {
        supplies.extend(
            order
                .iter()
                .map(|m| (m["machine"].clone(), name.to_owned())),
        );
    }
    for member in &order {
        for d in declared
            .iter()
            .filter(|d| Some(d.registry.as_str()) != change)
        {
            if current(owner, &d.registry, &member["machine"]).is_empty() {
                supplies.push((member["machine"].clone(), d.registry.clone()));
            }
        }
    }
    for d in declared
        .iter()
        .filter(|d| supplies.iter().any(|(_, r)| *r == d.registry))
    {
        if let Some(path) = &d.ca {
            ca_file(path).map_err(|failure| naming(failure, d.registry.clone()))?;
        }
    }
    if let Some(d) = declared
        .iter()
        .find(|d| d.http || d.authority == "docker.io" || (d.managed && d.ca.is_none()))
    {
        return Err(naming(Failure::Configuration, d.registry.clone()));
    }
    Ok(supplies)
}

fn owner_room(
    context: &rpc::Context<'_>,
    owner: &Value,
    declared: &[Declared],
    supplies: &[(Value, String)],
) -> super::ExecutionResult<()> {
    let appended: Vec<Value> = supplies
        .iter()
        .filter(|(machine, registry)| current(owner, registry, machine).is_empty())
        .map(|(machine, registry)| resource(owner, registry, machine, &"f".repeat(32)))
        .collect();
    if !appended.is_empty() {
        let principals: Vec<&str> = context
            .selected
            .declaration
            .registry
            .iter()
            .flat_map(|r| r.authentication.principals.keys().map(String::as_str))
            .collect();
        let members = owner["members"].as_array().map_or(0, Vec::len);
        room(owner, &appended, &principals).map_err(|failure| {
            naming(
                failure,
                format!("{members} members and {} entries", declared.len()),
            )
        })?;
    }
    Ok(())
}

async fn gates(
    project: &LoadedProject,
    policy: &Policy,
    target: &str,
    change: Option<&str>,
) -> super::ExecutionResult<(Vec<(Value, String)>, bool)> {
    let context = rpc::Context::new(project, super::issuer::duplicate(policy)?, target)?;
    let mut local = Local::new(&context)?;
    let read = local
        .work(|store| Ok((store.agent_context()?, store.next_sequence()?)))
        .await;
    let ((previous, _), request_sequence) = local.complete(read, &context.clock).await?;
    let declared = declared(&context)?;
    let owner = &previous.first().ok_or(Failure::Ownership)?.owner;
    let pending = pending(&previous, owner)?;
    let supplies = admitted_pending(&context, owner, &declared, change, pending.as_ref())?;
    for snapshot in &previous {
        settled(&super::report::report(
            &context.scope,
            "show",
            std::slice::from_ref(snapshot),
        )?)?;
    }
    owner_room(&context, owner, &declared, &supplies)?;
    if declared.is_empty() {
        return Ok((supplies, false));
    }
    let inputs = inputs(&context, &previous, owner, &supplies)?;
    if pending.is_none() {
        let mut surviving = owner.clone();
        surviving["members"] = json!(super::survivors(owner)?);
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":owner["owner"],
            "operation":format!("infra-operation-{}", fresh()?),"created_ms":now()?,"sequence":request_sequence,
            "action":"restart-member","members":surviving["members"],"cluster":owner["cluster"],
            "resources":[],"config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":owner["participants_sha256"],
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        node::admissible(
            &context,
            &previous,
            &surviving,
            Some(&inputs),
            &request,
            &fresh()?,
        )?;
    }
    if let Some(registry) = stale(&previous, owner, &inputs, &supplies)? {
        return Err(naming(
            Failure::Configuration,
            format!("change_node_registry {registry}"),
        ));
    }
    Ok((supplies, true))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rule {
    Continue,
    Configured,
    Refused,
    Restart,
    First,
}

fn recipe_of(snapshot: &Snapshot) -> Option<&Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "restart-recipe")
        .map(|o| &o["event"]["recipe"])
}

fn newest_complete(
    previous: &[Snapshot],
    succeeded: &dyn Fn(&Snapshot) -> bool,
) -> Option<(String, u64)> {
    let mut runs: BTreeMap<(&str, &str), BTreeMap<u64, u64>> = BTreeMap::new();
    let mut sizes = BTreeMap::new();
    for snapshot in previous
        .iter()
        .filter(|s| s.request["action"] == "configure-node-registries" && succeeded(s))
    {
        let Some(recipe) = recipe_of(snapshot) else {
            continue;
        };
        let (Some(plan), Some(run), Some(position), Some(sequence)) = (
            recipe["plan_sha256"].as_str(),
            recipe["run"].as_str(),
            recipe["position"].as_u64(),
            snapshot.request["sequence"].as_u64(),
        ) else {
            continue;
        };
        runs.entry((plan, run))
            .or_default()
            .insert(position, sequence);
        sizes.insert(
            plan,
            recipe["plan"]["members"].as_array().map_or(0, Vec::len) as u64,
        );
    }
    runs.into_iter()
        .filter_map(|((plan, _), positions)| {
            let size = sizes[plan];
            let complete = size > 0 && (0..size).all(|p| positions.contains_key(&p));
            complete.then(|| (positions[&(size - 1)], plan.to_owned(), positions[&0]))
        })
        .max_by_key(|(last, ..)| *last)
        .map(|(_, plan, first)| (plan, first))
}

pub(super) fn configured(
    previous: &[Snapshot],
    succeeded: &dyn Fn(&Snapshot) -> bool,
) -> BTreeSet<String> {
    newest_complete(previous, succeeded)
        .map(|(plan, _)| plan)
        .into_iter()
        .collect()
}

pub(super) fn rule(
    previous: &[Snapshot],
    succeeded: &dyn Fn(&Snapshot) -> bool,
    plan_sha256: &str,
) -> Rule {
    let latest = previous
        .iter()
        .max_by_key(|s| s.request["sequence"].as_u64());
    let continued = latest
        .filter(|s| s.request["action"] == "configure-node-registries" && succeeded(s))
        .and_then(recipe_of)
        .is_some_and(|r| {
            let members = r["plan"]["members"].as_array().map_or(0, Vec::len) as u64;
            r["plan_sha256"] == plan_sha256
                && r["position"].as_u64().is_some_and(|p| p + 1 < members)
        });
    let newest = newest_complete(previous, succeeded);
    let ran = newest.as_ref().is_some_and(|(_, first)| {
        previous
            .iter()
            .filter(|s| s.request["action"] == "configure-node-registries")
            .filter(|s| s.request["sequence"].as_u64().is_some_and(|q| q > *first))
            .filter_map(recipe_of)
            .any(|r| r["plan_sha256"] == plan_sha256)
    });
    match newest {
        _ if continued => Rule::Continue,
        Some((plan, _)) if plan == plan_sha256 => Rule::Configured,
        None => Rule::First,
        Some(_) if ran => Rule::Restart,
        Some(_) => Rule::Refused,
    }
}

fn compared(
    previous: &[Snapshot],
    succeeded: &dyn Fn(&Snapshot) -> bool,
    plan: &Value,
    plan_sha256: &str,
) -> Result<String> {
    let Some((configured, _)) = newest_complete(previous, succeeded) else {
        return Ok(plan_sha256.to_owned());
    };
    let Some(recorded) = previous
        .iter()
        .filter_map(recipe_of)
        .find(|r| r["plan_sha256"] == configured.as_str())
    else {
        return Ok(plan_sha256.to_owned());
    };
    let current = plan["members"].as_array().ok_or(Failure::Integrity)?;
    let kept = recorded["plan"]["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|m| current.iter().any(|c| c["member"] == m["member"]))
        .cloned()
        .collect();
    let width = recorded["plan"]["wave_width"]
        .as_u64()
        .and_then(|w| u8::try_from(w).ok())
        .ok_or(Failure::Integrity)?;
    let projection = node::planned(kept, width, &recorded["plan"]["profile_sha256"]);
    Ok(if hash(node::CONFIGURE_PLAN, &projection)? == plan_sha256 {
        configured
    } else {
        plan_sha256.to_owned()
    })
}

fn projected_rule(
    previous: &[Snapshot],
    succeeded: &dyn Fn(&Snapshot) -> bool,
    plan: &Value,
    plan_sha256: &str,
) -> Result<Rule> {
    match rule(previous, succeeded, plan_sha256) {
        Rule::Continue => Ok(Rule::Continue),
        _ => Ok(rule(
            previous,
            succeeded,
            &compared(previous, succeeded, plan, plan_sha256)?,
        )),
    }
}

pub(super) fn observed_configuration(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
) -> Result<bool> {
    let mut surviving = owner.clone();
    surviving["members"] = json!(super::survivors(owner)?);
    let inputs = inputs(context, previous, &surviving, &[])?;
    let plan = inputs.plan(node::plan(context, previous, &surviving)?)?;
    let digest = hash(node::CONFIGURE_PLAN, &plan)?;
    let ok = |s: &Snapshot| succeeded(context, s);
    Ok(projected_rule(previous, &ok, &plan, &digest)? == Rule::Configured)
}

async fn derived(
    project: &LoadedProject,
    policy: &Policy,
    target: &str,
) -> super::ExecutionResult<(Rule, String)> {
    let context = rpc::Context::new(project, super::issuer::duplicate(policy)?, target)?;
    let mut local = Local::new(&context)?;
    let read = local.work(|store| store.agent_context()).await;
    let (previous, _) = local.complete(read, &context.clock).await?;
    let owner = &previous.first().ok_or(Failure::Ownership)?.owner;
    let mut surviving = owner.clone();
    surviving["members"] = json!(super::survivors(owner)?);
    let inputs = inputs(&context, &previous, &surviving, &[])?;
    let plan = inputs.plan(node::plan(&context, &previous, &surviving)?)?;
    let plan_sha256 = hash(node::CONFIGURE_PLAN, &plan)?;
    let ok = |s: &Snapshot| succeeded(&context, s);
    let rule = projected_rule(&previous, &ok, &plan, &plan_sha256)?;
    Ok((rule, plan_sha256))
}

async fn supply(
    project: &LoadedProject,
    policy: &Policy,
    target: &str,
    machine: &Value,
    registry: &str,
) -> super::ExecutionResult<Snapshot> {
    let machine = machine.as_str().ok_or(Failure::Integrity)?;
    Box::pin(Session::begin_node_registry(
        project,
        super::issuer::duplicate(policy)?,
        target,
        machine,
        registry,
    ))
    .await?
    .prepare_metadata()
    .await
}

pub(super) async fn node_registries(
    project: &LoadedProject,
    policy: Policy,
    target: &str,
) -> super::ExecutionResult<Option<Snapshot>> {
    let (supplies, declared) = gates(project, &policy, target, None).await?;
    if !declared {
        return Ok(None);
    }
    let mut last = None;
    for (machine, registry) in &supplies {
        last = Some(supply(project, &policy, target, machine, registry).await?);
    }
    let (rule, plan_sha256) = derived(project, &policy, target).await?;
    match rule {
        Rule::Configured => Ok(last),
        Rule::Refused if replacing(project, &policy, target).await? => {
            node::run(project, policy, target, Some(&plan_sha256))
                .await
                .map(Some)
        }
        Rule::Refused => Err(naming(
            Failure::Configuration,
            "change_node_registry".into(),
        )),
        Rule::Continue | Rule::Restart | Rule::First => {
            node::run(project, policy, target, Some(&plan_sha256))
                .await
                .map(Some)
        }
    }
}

async fn replacing(
    project: &LoadedProject,
    policy: &Policy,
    target: &str,
) -> super::ExecutionResult<bool> {
    let context = rpc::Context::new(project, super::issuer::duplicate(policy)?, target)?;
    let mut local = Local::new(&context)?;
    let read = local.work(|store| store.agent_context()).await;
    let (previous, _) = local.complete(read, &context.clock).await?;
    let owner = &previous.first().ok_or(Failure::Ownership)?.owner;
    Ok(super::survivors(owner)?.iter().any(|m| {
        m["member"]
            .as_str()
            .is_some_and(|name| super::member::replacing(&previous, name).is_some())
    }))
}

pub(super) async fn supply_replacement(
    project: &LoadedProject,
    policy: Policy,
    target: &str,
    member: &str,
) -> super::ExecutionResult<Option<Snapshot>> {
    let (supplies, declared) = gates(project, &policy, target, None).await?;
    if !declared {
        return Ok(None);
    }
    let machine = rpc::Context::new(project, super::issuer::duplicate(&policy)?, target)?
        .selected
        .declaration
        .members
        .iter()
        .find(|m| m.name == member)
        .map(|m| json!(m.machine))
        .ok_or(Failure::Configuration)?;
    let mut last = None;
    for (on, registry) in supplies.iter().filter(|(on, _)| *on == machine) {
        last = Some(supply(project, &policy, target, on, registry).await?);
    }
    Ok(last)
}

pub(super) async fn change_node_registry(
    project: &LoadedProject,
    policy: Policy,
    target: &str,
    registry: &str,
) -> super::ExecutionResult<Option<Snapshot>> {
    let (supplies, _) = gates(project, &policy, target, Some(registry)).await?;
    for (machine, name) in &supplies {
        supply(project, &policy, target, machine, name).await?;
    }
    let (_, plan_sha256) = derived(project, &policy, target).await?;
    node::run(project, policy, target, Some(&plan_sha256))
        .await
        .map(Some)
}

pub(super) fn join_render(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    operation: &str,
    joining: &Value,
) -> Result<Option<Value>> {
    let name = &joining["member"]["member"];
    let mut surviving = owner.clone();
    surviving["members"] = json!(super::survivors(owner)?);
    let inputs = inputs(context, previous, &surviving, &[])?;
    let registries = inputs.registries(name)?;
    if registries.as_array().is_none_or(Vec::is_empty) {
        return Ok(None);
    }
    let plan = inputs.plan(node::plan_joining(
        context,
        previous,
        &surviving,
        Some(joining),
    )?)?;
    let position = plan["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .position(|m| m["member"] == *name)
        .ok_or(Failure::Integrity)?;
    node::recipe(
        &context.scope,
        &surviving,
        operation,
        context.selected.declaration.version.as_str(),
        &json!(operation),
        position,
        &plan,
        Some(registries),
    )
    .map(Some)
}

impl super::session::Session<'_> {
    pub(super) async fn pre_start_render(&mut self, index: usize) -> Result<()> {
        let Some(found) = self
            .local
            .snapshot()?
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "restart-recipe")
            .cloned()
        else {
            return Ok(());
        };
        let payload = json!({"recipe":found["event"]["recipe"],"expected":null,"wait_ms":null});
        self.family_step(
            index,
            "configure-registries",
            payload,
            vec![found["sequence"].clone()],
        )
        .await?;
        Ok(())
    }
}

pub(super) fn supply_steps(members: usize) -> usize {
    4 * members + 4
}

pub(super) fn replacement_destination(
    members: &[Value],
    pending: Option<&Value>,
    destination: &str,
) -> Result<()> {
    require(
        members
            .iter()
            .all(|m| m["node_uid"].is_string() || Some(m) == pending)
            && pending.is_none_or(|m| m["machine"] == destination),
        Failure::Readiness,
    )
}

pub(super) fn successor(owner: &Value, resource: &Value) -> Result<Value> {
    let mut owner = owner.clone();
    owner["previous_generation"] = owner["generation"].clone();
    owner["generation"] = json!(fresh()?);
    owner["created_ms"] = json!(now()?);
    let resources = owner["resources"]
        .as_array_mut()
        .ok_or(Failure::Integrity)?;
    match resources
        .iter_mut()
        .find(|r| r["id"] == resource["id"] && r["machine"] == resource["machine"])
    {
        Some(found) => *found = resource.clone(),
        None => resources.push(resource.clone()),
    }
    Ok(owner)
}

pub(super) fn replaced(old: &Value, owner: &Value, snapshot: &Snapshot) -> bool {
    let (Some(prior), Some(successor), Some([r])) = (
        old["resources"].as_array(),
        owner["resources"].as_array(),
        snapshot.request["resources"].as_array().map(Vec::as_slice),
    ) else {
        return false;
    };
    let mut expected = prior.clone();
    match prior
        .iter()
        .position(|p| p["id"] == r["id"] && p["machine"] == r["machine"])
    {
        Some(index) => {
            let mut kept = prior[index].clone();
            kept["generation"] = r["generation"].clone();
            kept["path"] = r["path"].clone();
            if kept != *r {
                return false;
            }
            expected[index] = r.clone();
        }
        None => expected.push(r.clone()),
    }
    let on_machine = |step: &Value| step["recipient"]["machine"] == r["machine"];
    let supplied = [
        "prepare-input",
        "admit-credential",
        "credential:supply-node-registry",
    ]
    .iter()
    .all(|action| {
        snapshot
            .steps
            .iter()
            .any(|s| s["action"] == *action && on_machine(s) && snapshot.succeeded(s))
    });
    let inspected = snapshot.observations.iter().any(|o| {
        let (event, found) = (&o["event"], &o["event"]["data"]["resource"]);
        event["type"] == "inspection"
            && event["subject"] == "resource"
            && event["resource"] == *r
            && event["status"] == "ok"
            && found["resource"] == *r
            && found["identity"]
                .as_array()
                .is_some_and(|i| i.len() == 2 && i.iter().all(Value::is_u64))
            && found["inactive"] == true
            && snapshot.steps.iter().any(|s| {
                s["action"] == "inspect"
                    && on_machine(s)
                    && s["attempt"] == o["attempt"]
                    && s["step"] == o["step"]
                    && s["dispatch"] == o["dispatch"]
            })
    });
    r["kind"] == "node-registry"
        && *successor == expected
        && supplied
        && inspected
        && owner["members"] == old["members"]
        && owner["cluster"] == old["cluster"]
}

impl<'a> Session<'a> {
    pub(super) async fn begin_node_registry(
        project: &'a LoadedProject,
        policy: Policy,
        target: &str,
        destination: &str,
        registry: &str,
    ) -> super::ExecutionResult<Self> {
        let context = rpc::Context::new(project, policy, target)?;
        let mut local = Local::new(&context)?;
        let prepared: Result<_> = async {
            let (previous, _) = local.work(|store| store.agent_context()).await?;
            let owned = previous.first().ok_or(Failure::Ownership)?.owner.clone();
            let members = super::survivors(&owned)?;
            require(!owned["cluster"].is_null()
                && owned["fingerprints"] == context.owner_fingerprints
                && owned["participants_sha256"] == super::participants(&json!(members))?
                && super::declares_survivors(&context, &owned)?, Failure::Ownership)?;
            for snapshot in &previous {
                settled(&super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?)?;
            }
            let pending = pending(&previous, &owned)?;
            replacement_destination(&members, pending.as_ref(), destination)?;
            context.authenticate_owned(&json!(members)).await?;
            let entry = declared(&context)?.into_iter().find(|d| d.registry == registry)
                .ok_or(Failure::Configuration)?;
            let principal = principal(&context, &previous, &owned, &entry)?;
            let member = members.iter().find(|m| m["machine"] == destination).ok_or(Failure::Ownership)?;
            let cluster = owned["cluster"].clone();
            let generation = Generation {
                owner: owned["owner"].as_str().ok_or(Failure::Integrity)?.into(),
                operation: format!("infra-operation-{}", fresh()?),
                attempt: fresh()?,
                resource: id(registry),
                generation: fresh()?,
                resource_uid: None,
                cluster: Some(Cluster {
                    uid: cluster["uid"].as_str().ok_or(Failure::Integrity)?.into(),
                    ca_sha256: cluster["ca_sha256"].as_str().ok_or(Failure::Integrity)?.into(),
                }),
                destination_uid: member["node_uid"].as_str().map(str::to_owned),
                source_uid: None,
            };
            let resource = resource(&owned, registry, &member["machine"], &generation.generation);
            let mut selection = super::issuer::duplicate(&context.policy)?;
            selection.deadline = context.clock.deadline();
            let consumer = crate::k3s::prepare(project, selection, target, destination, generation,
                Operation::NodeRegistry { registry: registry.into() }).map_err(|_| Failure::Configuration)?;
            require(consumer.base["cluster"] == cluster, Failure::Ownership)?;
            let request_sequence = local.work(|store| store.next_sequence()).await?;
            let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":owned["owner"],
                "operation":consumer.base["operation"],"created_ms":now()?,"sequence":request_sequence,"action":"prepare-node-registry",
                "members":members,"cluster":cluster,"resources":[resource],"config":context.config,
                "references":context.references,
                "consumer":{"action":consumer.action.tag(),"projection":consumer.projection()},
                "fingerprints":context.fingerprints,"participants_sha256":owned["participants_sha256"],
                "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
                "step_timeout_ms":context.selected.step_timeout.seconds*1000});
            let request_hash = hash("broil-infra-request-v1", &request)?;
            let mut generations = Vec::with_capacity(members.len());
            for member in &members {
                let binding = json!({"scope":context.scope,"owner":owned["owner"],"operation":request["operation"],
                    "attempt":consumer.base["attempt"],"step":1,"dispatch":fresh()?,"recipient":member,
                    "receiver_generation":0,"request_sha256":request_hash,
                    "participants_sha256":owned["participants_sha256"],"fingerprints":context.fingerprints});
                let deadline = context.clock.deadline().min(tokio::time::Instant::now()
                    + Duration::from_secs(context.selected.step_timeout.seconds));
                let observed = context.invoke(&binding, "inspect",
                    json!({"subject":"owner","dispatch":null,"resource":null}), deadline).await;
                let response = observed.response.ok_or(observed.failure.unwrap_or(Failure::Transport))?;
                let joined = Some(member) != pending.as_ref();
                require(response["status"] == "ok" && response["data"]["claim"]["active_attempt"].is_null()
                    && (!joined || response["data"]["ownership"]["cluster"] == cluster), Failure::Ownership)?;
                generations.push(response["data"]["claim"]["generation"].as_u64().ok_or(Failure::Integrity)?);
                if !joined {
                    continue;
                }
                let observed = context.invoke(&binding, "inspect",
                    json!({"subject":"identity","dispatch":null,"resource":null}), deadline).await;
                let response = observed.response.ok_or(observed.failure.unwrap_or(Failure::Transport))?;
                require(response["status"] == "ok" && response["data"]["identity"]["member"] == *member
                    && response["data"]["identity"]["cluster"] == cluster, Failure::Ownership)?;
            }
            let count = supply_steps(members.len());
            require(count <= 1024, Failure::Bound)?;
            let attempt = json!({"schema":1,"kind":"attempt","scope":context.scope,"owner":owned["owner"],
                "operation":request["operation"],"attempt":consumer.base["attempt"],"created_ms":now()?,
                "request_sha256":request_hash,"parent_attempt":null,"original_step":null,"approval":null,
                "steps":(1..=count).collect::<Vec<_>>()});
            let event = json!({"schema":1,"kind":"observation","scope":context.scope,"owner":owned["owner"],
                "operation":request["operation"],"sequence":1,"recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},"attempt":attempt["attempt"],"step":null,
                "dispatch":null,"event":{"type":"node-registry-supply","principal":principal}});
            let stored = attempt.clone();
            local.work(move |store| store.create(owned, request, stored)).await?;
            local.work(move |store| store.append(event)).await?;
            Ok((attempt, members, generations, consumer))
        }.await;
        let (attempt, members, generations, consumer) = match prepared {
            Ok(value) => value,
            Err(failure) => return Err(local.failure(failure, &context.clock).await),
        };
        Ok(Self {
            context,
            local,
            attempt,
            members,
            generations,
            next_step: 1,
            consumer: Some(consumer),
            existing_resources: false,
            mode: Mode::Acquiring,
            retry_input: None,
            agent_view_wait: false,
            wave_boundary: None,
            wave_operations: Vec::new(),
            wave_gate_needed: false,
        })
    }
}

