// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::issuer;
use super::network::{self, Family};
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{NETWORK, PROFILE, protocol};
use broil_config::LoadedProject;
use broil_core::k3s::{Infrastructure, ManagedRegistry, Target};
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "registry-storage",
    protocol: "broil-k3s-registry-storage",
    magic: b"BK3SRGS2\n",
    header: "RegistryStorageHeader",
    result: "RegistryStorageResult",
    body: NETWORK,
    planned: 0,
    reserve: 8_192,
    version: 2,
};

const RUNTIME: u64 = 10_000;

const ANCESTRY: [&str; 3] = ["unsafe", "closed", "untraversable"];

pub(super) fn action(tag: &str) -> String {
    format!("lifecycle:registry-storage-{tag}")
}

pub(super) fn gate(certificate: Option<&str>, infrastructure: &Infrastructure) -> Result<()> {
    let certificate = certificate.ok_or(Failure::Configuration)?;
    let declared = infrastructure
        .certificates
        .get(certificate)
        .and_then(|c| infrastructure.issuers.get(&c.issuer))
        .ok_or(Failure::Configuration)?;
    require(!issuer::acme(declared), Failure::Capability)
}

fn gates(target: &Target) -> Result<ManagedRegistry> {
    let registry = target.registry.as_ref();
    gate(
        registry.map(|r| r.certificate.as_str()),
        &target.infrastructure,
    )?;
    registry.cloned().ok_or(Failure::Configuration)
}

pub(super) fn replica_id(member: &str) -> Result<String> {
    let id = format!("registry-replica-{member}");
    require(id.len() <= 128, Failure::Bound)?;
    require(protocol::opaque(&id), Failure::Configuration)?;
    Ok(id)
}

pub(super) fn stage(origins: &Value, replaced: bool) -> Result<&'static str> {
    let entries = origins["directories"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    match entries.iter().filter(|e| !e.is_null()).count() {
        0 => Ok("create"),
        n if n == entries.len() => Ok("observe"),
        _ if replaced => Ok("extend"),
        _ => Err(Failure::Ownership),
    }
}

pub(super) fn effects(origins: &Value) -> usize {
    origins["directories"]
        .as_array()
        .map_or(0, |entries| entries.iter().filter(|e| e.is_null()).count())
}

pub(super) fn step_count(members: &[Value], replicas: usize, effects: usize) -> Result<usize> {
    issuer::step_count(members, effects)?
        .checked_add(replicas.checked_mul(3).ok_or(Failure::Bound)?)
        .filter(|n| *n <= 1024)
        .ok_or(Failure::Bound)
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("unobservable")
}

type Fact<'a> = (&'a str, &'a str, &'a str, Option<u64>, bool);

fn fact((storage, origin): &(Value, bool)) -> Fact<'_> {
    (
        text(&storage["class"]),
        text(&storage["parent"]),
        text(&storage["filesystem"]),
        storage["available_mib"].as_u64(),
        *origin,
    )
}

fn precedence(
    capacity: u64,
    directories: &[(Value, bool)],
    nodes: Option<&Value>,
) -> std::result::Result<(), (Failure, Option<usize>)> {
    let fail = |failure| Err((failure, None));
    let states: Vec<&str> = match nodes {
        Some(nodes) => {
            let list = nodes.as_array().map(Vec::as_slice).unwrap_or_default();
            if list.len() != directories.len() {
                return fail(Failure::Integrity);
            }
            list.iter().map(|n| text(&n["node"])).collect()
        }
        None => Vec::new(),
    };
    let facts: Vec<Fact<'_>> = directories.iter().map(fact).collect();
    if facts.iter().any(|f| f.1 == "reserved") {
        return fail(Failure::Configuration);
    }
    let unread = |&(class, parent, filesystem, available, origin): &Fact<'_>| {
        class == "unobservable" && parent != "unsafe"
            || parent == "unobservable"
            || !origin && (filesystem == "unobservable" || parent == "safe" && available.is_none())
    };
    if facts.iter().any(unread) || states.contains(&"unobservable") {
        return fail(Failure::Readiness);
    }
    if states.contains(&"drifted") {
        return fail(Failure::Ownership);
    }
    if states.iter().any(|n| *n != "ready") {
        return fail(Failure::Readiness);
    }
    let row = |&(class, _, _, _, origin): &Fact<'_>| {
        class == "unobservable" || class == if origin { "owned" } else { "absent" }
    };
    if !facts.iter().all(row) {
        return fail(Failure::Ownership);
    }
    if let Some(index) = facts.iter().position(|f| ANCESTRY.contains(&f.1)) {
        return Err((Failure::Ownership, Some(index)));
    }
    for &(_, parent, filesystem, available, _) in facts.iter().filter(|f| !f.4) {
        if parent == "absent" {
            return fail(Failure::Readiness);
        }
        if filesystem != "supported" || available.is_none_or(|a| a < capacity) {
            return fail(Failure::Storage);
        }
    }
    Ok(())
}

pub(super) fn admits(capacity: u64, directories: &[(Value, bool)], nodes: &Value) -> Result<()> {
    precedence(capacity, directories, Some(nodes)).map_err(|(failure, _)| failure)
}

pub(super) fn columns(capacity: u64, directories: &[(Value, bool)], _nodes: &Value) -> Result<()> {
    precedence(capacity, directories, None).map_err(|(failure, _)| failure)
}

pub(super) fn confirms(storage: &[Value]) -> Result<()> {
    require(
        !storage
            .iter()
            .any(|s| s["class"] == "foreign" || s["class"] == "owned-drifted"),
        Failure::Ownership,
    )?;
    require(
        !storage
            .iter()
            .any(|s| text(&s["class"]) == "unobservable" || text(&s["parent"]) == "unobservable"),
        Failure::Readiness,
    )?;
    require(
        storage
            .iter()
            .all(|s| s["class"] == "owned" && s["parent"] == "safe"),
        Failure::Ownership,
    )
}

pub(super) fn ancestor_detail(member: &str, path: &str, storage: &Value) -> Option<String> {
    let requirement = match storage["parent"].as_str()? {
        "unsafe" => "root-owned directory without group or other write required",
        "closed" => "unsupported ancestor layout: other-search required",
        "untraversable" => "service identity cannot traverse this ancestor",
        _ => return None,
    };
    let ancestor = &storage["ancestor"];
    let depth = usize::try_from(ancestor["depth"].as_u64()?).ok()?;
    let components: Vec<&str> = path.split('/').skip(1).collect();
    if depth >= components.len() {
        return None;
    }
    let prefix = format!("/{}", components[..depth].join("/"));
    Some(format!(
        "{member}: {prefix} ({}:{} {:04o}): {requirement}",
        ancestor["uid"].as_u64()?,
        ancestor["gid"].as_u64()?,
        ancestor["mode"].as_u64()?
    ))
}

pub(super) fn readiness(storage: &[Value], nodes: &Value) -> &'static str {
    let nodes = nodes.as_array().map(Vec::as_slice).unwrap_or_default();
    if !storage.is_empty()
        && nodes.len() == storage.len()
        && storage.iter().all(|s| s["class"] == "owned")
        && nodes.iter().all(|n| n["node"] == "ready")
    {
        "ready"
    } else {
        "not-ready"
    }
}

pub(super) fn readiness_v1(storage: &Value, api: &Value) -> &'static str {
    let classes = [&storage["class"], &api["objects"][0]["class"]];
    if classes.iter().all(|c| *c == "owned")
        && api["node"] == "ready"
        && api["volume"]["binding"] == "reserved"
    {
        "ready"
    } else {
        "not-ready"
    }
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let host = matches!(tag, "inspect-storage" | "create-storage");
    require(
        result["storage"].is_null() != host
            && result["nodes"].is_null() == host
            && (host || result["nodes"].is_array())
            && result["terminal"].is_null() != (tag == "create-storage"),
        Failure::Integrity,
    )
}

pub(super) fn expected(recipe: &Value, index: usize) -> Value {
    let origin = &recipe["origins"]["directories"][index];
    if origin.is_null() {
        Value::Null
    } else {
        json!({"record_sha256":origin["record_sha256"],"directory":origin["directory"],
            "data":origin["data"],"fsid":origin["fsid"]})
    }
}

fn recipe_of(snapshot: &Snapshot) -> Result<&Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "registry-storage-recipe")
        .map(|o| &o["event"]["recipe"])
        .ok_or(Failure::Integrity)
}

pub(super) fn origins(previous: &[Snapshot], resources: &[Value]) -> Result<Value> {
    let mut made: Vec<(&Snapshot, &Value)> = Vec::new();
    for snapshot in previous
        .iter()
        .filter(|s| s.request["action"] == "reconcile-registry-storage")
    {
        for step in snapshot
            .steps
            .iter()
            .filter(|step| step["action"] == action("create-storage"))
        {
            require(snapshot.succeeded(step), Failure::Ownership)?;
            made.push((snapshot, issuer::recorded(snapshot, step, "receiver")?));
        }
    }
    let mut directories = Vec::with_capacity(resources.len());
    for resource in resources {
        let found: Vec<&(&Snapshot, &Value)> = made
            .iter()
            .filter(|(_, receipt)| receipt["event"]["receipt"]["resource"] == *resource)
            .collect();
        require(found.len() <= 1, Failure::Ownership)?;
        let Some((snapshot, receipt)) = found.first() else {
            directories.push(Value::Null);
            continue;
        };
        let identity = &receipt["event"]["receipt"]["resource_identity"];
        let after = receipt["sequence"].as_u64().ok_or(Failure::Integrity)?;
        let read = snapshot
            .observations
            .iter()
            .find(|o| {
                o["event"]["type"] == "registry-storage-observation"
                    && o["event"]["member"]["machine"] == resource["machine"]
                    && o["sequence"].as_u64().is_some_and(|s| s > after)
            })
            .map(|o| &o["event"]["storage"])
            .ok_or(Failure::Ownership)?;
        require(
            identity.is_array() && read["class"] == "owned" && read["directory"] == *identity,
            Failure::Ownership,
        )?;
        let recipe_sha256 = hash("broil-k3s-registry-storage-recipe-v1", recipe_of(snapshot)?)?;
        directories.push(json!({"operation":snapshot.request["operation"],
            "recipe_sha256":recipe_sha256,"record_sha256":read["record_sha256"],
            "directory":read["directory"],"data":read["data"],"fsid":read["fsid"]}));
    }
    Ok(json!({"directories":directories}))
}

pub(super) fn planned(
    owner: &Value,
    registry: &ManagedRegistry,
    members: &[Value],
    _previous: &[Snapshot],
) -> Result<(Vec<Value>, Option<Value>)> {
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    let mut held = Vec::with_capacity(members.len());
    for member in members {
        let id = replica_id(member["member"].as_str().ok_or(Failure::Integrity)?)?;
        let found: Vec<&Value> = resources
            .iter()
            .filter(|r| r["id"] == id.as_str())
            .collect();
        require(found.len() <= 1, Failure::Ownership)?;
        held.push((id, found.first().copied()));
    }
    let resource = |id: &str, generation: &Value, machine: &Value| {
        json!({"kind":"replica","id":id,"owner":owner["owner"],"generation":generation,
            "machine":machine,"path":registry.storage.path,"namespace":null,"name":null,"uid":null})
    };
    if held.iter().all(|(_, found)| found.is_some()) {
        let mut list = Vec::with_capacity(held.len());
        for ((id, found), member) in held.iter().zip(members) {
            let found = found.ok_or(Failure::Integrity)?;
            require(
                *found == resource(id, &found["generation"], &member["machine"]),
                Failure::Ownership,
            )?;
            list.push(found.clone());
        }
        return Ok((list, None));
    }
    require(
        held.iter().all(|(_, found)| found.is_none()),
        Failure::Ownership,
    )?;
    let mut list = Vec::with_capacity(held.len());
    for ((id, _), member) in held.iter().zip(members) {
        list.push(resource(id, &json!(fresh()?), &member["machine"]));
    }
    let mut successor = owner.clone();
    successor["previous_generation"] = successor["generation"].clone();
    successor["generation"] = json!(fresh()?);
    successor["created_ms"] = json!(now()?);
    successor["resources"]
        .as_array_mut()
        .ok_or(Failure::Integrity)?
        .extend(list.iter().cloned());
    Ok((list, Some(successor)))
}

#[allow(clippy::too_many_arguments)]
fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    registry: &ManagedRegistry,
    members: &[Value],
    stage: &str,
    origins: &Value,
) -> Result<Value> {
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let first_server = members
        .iter()
        .find(|m| m["role"] == "server")
        .ok_or(Failure::Ownership)?;
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"first_server":first_server,"members":members,
        "version":context.selected.declaration.version,"registry":registry.name,
        "path":registry.storage.path,"capacity_mib":registry.storage.capacity_mib,
        "runtime":{"uid":RUNTIME,"gid":RUNTIME},"stage":stage,"origins":origins,
        "profile_sha256":context.fingerprints["profile_sha256"]});
    schema::validate(&canonical(&recipe)?, "RegistryStorageRecipe", 32_768)?;
    Ok(recipe)
}

pub(super) fn widest_fact() -> Value {
    let identity = json!([u64::MAX, u64::MAX]);
    json!({"class":"owned-drifted","parent":"untraversable",
        "ancestor":{"depth":2044,"uid":u32::MAX,"gid":u32::MAX,"mode":0o7777},
        "filesystem":"unobservable","available_mib":u64::MAX,"record_sha256":"0".repeat(64),
        "directory":identity,"data":identity,"fsid":u64::MAX})
}

fn fits(request: &Value, attempt: &str, count: usize, recipe: &Value, index: usize) -> Result<()> {
    let path = recipe["path"].as_str().ok_or(Failure::Integrity)?;
    require(path.len() + "/data".len() <= 4_095, Failure::Bound)?;
    let identity = json!([u64::MAX, u64::MAX]);
    let members = recipe["members"].as_array().ok_or(Failure::Integrity)?;
    let member = members.get(index).ok_or(Failure::Integrity)?;
    let record = json!({"schema":1,"kind":"registry-storage","scope":recipe["scope"],
        "owner":recipe["owner"],"operation":recipe["operation"],"attempt":attempt,
        "cluster":recipe["cluster"],"registry":recipe["registry"],"member":member,
        "path":path,"capacity_mib":recipe["capacity_mib"],"runtime":recipe["runtime"],
        "directory":identity,"data":identity,"fsid":u64::MAX});
    require(canonical(&record)?.len() < 8_192, Failure::Bound)?;
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let mut binding = network::read_binding(request, attempt, last, index)?;
    binding["receiver_generation"] = json!(u64::MAX);
    let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
    let expected = json!({"record_sha256":"0".repeat(64),"directory":identity,"data":identity,
        "fsid":u64::MAX});
    let header = json!({"protocol":FAMILY.protocol,"version":FAMILY.version,
        "action":"create-storage","request_id":fresh()?,"binding":binding,
        "remaining_ms":7_200_000,"recipe":recipe,"expected":expected,
        "resource":resources.get(index).ok_or(Failure::Integrity)?,"preflight":widest_fact(),
        "member":member});
    require(
        canonical(&header)?
            .len()
            .checked_add(17 + FAMILY.reserve)
            .is_some_and(|n| n <= 65_536),
        Failure::Bound,
    )?;
    let terminal = json!({"schema":1,"kind":"terminal","binding":binding,
        "action":action("create-storage"),"payload_sha256":"0".repeat(64),"outcome":"succeeded",
        "failure":"unsupported-version","effect":"complete","writer_ended":true,
        "resource":resources[index],"resource_identity":identity,"completed_ms":u64::MAX});
    let host = json!({"kind":"result","status":"unsupported-version","terminal":terminal,
        "storage":widest_fact(),"nodes":null,"failure":"unsupported-version"});
    let nodes: Vec<Value> = members
        .iter()
        .map(|m| json!({"member":m["member"],"node":"unobservable"}))
        .collect();
    let api = json!({"kind":"result","status":"unsupported-version","terminal":null,
        "storage":null,"nodes":nodes,"failure":"unsupported-version"});
    for reply in [host, api] {
        require(canonical(&reply)?.len() <= FAMILY.reserve, Failure::Bound)?;
    }
    Ok(())
}

async fn admission_read(
    context: &rpc::Context<'_>,
    binding: &Value,
    tag: &str,
    payload: &Value,
    cleanup: &mut bool,
) -> Result<Value> {
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
    );
    let observed = network::invoke(context, &FAMILY, binding, tag, payload, deadline, None).await;
    *cleanup |= network::unclean(&observed.transport);
    let result = observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", super::server::refused(&result))?;
    shape(tag, &result)?;
    Ok(result)
}

fn first_server(request: &Value) -> Result<usize> {
    request["members"]
        .as_array()
        .and_then(|members| members.iter().position(|m| m["role"] == "server"))
        .ok_or(Failure::Integrity)
}

pub(super) fn read_payload(recipe: &Value, index: Option<usize>) -> Value {
    let (expected, member) = match index {
        Some(index) => (expected(recipe, index), recipe["members"][index].clone()),
        None => (Value::Null, Value::Null),
    };
    json!({"recipe":recipe,"expected":expected,"resource":null,"preflight":null,"member":member})
}

fn directories(recipe: &Value, storage: &[Value]) -> Vec<(Value, bool)> {
    storage
        .iter()
        .enumerate()
        .map(|(index, s)| {
            (
                s.clone(),
                !recipe["origins"]["directories"][index].is_null(),
            )
        })
        .collect()
}

fn detail(recipe: &Value, storage: &[Value], index: Option<usize>) -> Option<&'static str> {
    let index = index?;
    let member = recipe["members"][index]["member"].as_str()?;
    let path = recipe["path"].as_str()?;
    ancestor_detail(member, path, &storage[index]).map(|d| &*Box::leak(d.into_boxed_str()))
}

#[allow(clippy::too_many_arguments)]
async fn preflight(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    source_events: &[Value],
    cleanup: &mut bool,
    detail_of: &mut Option<&'static str>,
) -> Result<()> {
    let binding = |index| network::read_binding(request, attempt, last, index);
    let members = recipe["members"].as_array().ok_or(Failure::Integrity)?;
    let mut storage = Vec::with_capacity(members.len());
    for index in 0..members.len() {
        let payload = read_payload(recipe, Some(index));
        let read = admission_read(
            context,
            &binding(index)?,
            "inspect-storage",
            &payload,
            cleanup,
        )
        .await?;
        storage.push(read["storage"].clone());
    }
    let first = first_server(request)?;
    let api = admission_read(
        context,
        &binding(first)?,
        "inspect-objects",
        &read_payload(recipe, None),
        cleanup,
    )
    .await?;
    let capacity = recipe["capacity_mib"].as_u64().ok_or(Failure::Integrity)?;
    if let Err((failure, index)) = precedence(
        capacity,
        &directories(recipe, &storage),
        Some(&api["nodes"]),
    ) {
        *detail_of = detail(recipe, &storage, index);
        return Err(failure);
    }
    network::membership_reads(context, request, attempt, last, source_events, cleanup).await
}

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<(Box<Session<'a>>, Value)> {
    let context = rpc::Context::new(project, policy, target)?;
    let registry = gates(context.selected.declaration)?;
    let mut local = Local::new(&context)?;
    let mut detail_of = None;
    let prepared: Result<_> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e| e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()), Failure::Ownership)?;
        require(owner["resources"].as_array().is_some_and(|resources| resources.iter()
            .filter(|r| r["id"].as_str().is_some_and(|id| id.starts_with("network-object-"))
                && r["uid"].is_string()).count() == 12), Failure::Ownership)?;
        for snapshot in &previous {
            super::session::settled(&super::report::report(&context.scope, "show",
                std::slice::from_ref(snapshot))?)?;
        }
        let members = super::survivors(&owner)?;
        require(members.iter().all(|m| m["node_uid"].is_string()), Failure::Readiness)?;
        let (resources, pending_owner) = planned(&owner, &registry, &members, &previous)?;
        let origins = origins(&previous, &resources)?;
        let replaced = previous.iter().any(|s| s.request["action"] == "node-replace");
        let stage = stage(&origins, replaced)?;
        if stage != "observe" {
            let machine = members.iter().find(|m| m["role"] == "server")
                .and_then(|m| m["machine"].as_str()).ok_or(Failure::Integrity)?;
            let target = context.inventory.machines.iter().find(|m| m.name == machine)
                .ok_or(Failure::Configuration)?;
            let script = context.inventory.scripts.get(&context.selected.declaration.lifecycle_script)
                .ok_or(Failure::Configuration)?;
            let remaining = context.clock.deadline()
                .saturating_duration_since(tokio::time::Instant::now()).as_secs();
            issuer::budget(context.selected.step_timeout.seconds,
                script.timeout.as_ref().map_or(target.timeouts.command.seconds, |d| d.seconds),
                remaining)?;
        }
        context.authenticate_owned(&Value::Array(members.clone())).await?;
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let participants = super::participants(&Value::Array(members.clone()))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let storage_recipe = recipe(&context, &current_owner, &operation, &registry, &members,
            stage, &origins)?;
        let created = now()?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-registry-storage",
            "members":members,"cluster":current_owner["cluster"],"resources":resources,
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let count = step_count(&members, members.len(), effects(&origins))?;
        for index in 0..members.len() {
            fits(&request, &attempt_id, count, &storage_recipe, index)?;
        }
        let mut cleanup = false;
        let checked = preflight(&context, &request, &attempt_id, count as u64, &storage_recipe,
            &source_events, &mut cleanup, &mut detail_of).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_registry_storage(successor)).await?;
            require(local.snapshot()?.owner["resources"].as_array().is_some_and(|held|
                held.ends_with(&resources)), Failure::Ownership)?;
            local.snapshot()?.owner.clone()
        } else {
            current_owner
        };
        let attempt = json!({"schema":1,"kind":"attempt","scope":context.scope,
            "owner":current_owner["owner"],"operation":operation,"attempt":attempt_id,
            "created_ms":created,"request_sha256":hash("broil-infra-request-v1",&request)?,
            "parent_attempt":null,"original_step":null,"approval":null,
            "steps":(1..=count).collect::<Vec<_>>()});
        let stored_owner = current_owner.clone();
        let stored_attempt = attempt.clone();
        local.work(move |store| store.create(stored_owner, request, stored_attempt)).await?;
        for event in std::iter::once(json!({"type":"registry-storage-recipe","recipe":storage_recipe}))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members, attempt_id, storage_recipe))
    }.await;
    let (members, attempt_id, storage_recipe) = match prepared {
        Ok(value) => value,
        Err(failure) => {
            local.failure_detail = local.failure_detail.or(detail_of);
            return Err(local.failure(failure, &context.clock).await);
        }
    };
    let attempt = local
        .snapshot()?
        .attempts
        .iter()
        .find(|a| a["attempt"] == attempt_id)
        .ok_or(Failure::Integrity)?
        .clone();
    let generations = vec![0; members.len()];
    Ok((
        Box::new(Session {
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
        }),
        storage_recipe,
    ))
}

impl Session<'_> {
    async fn storage_read(
        &mut self,
        index: Option<usize>,
        recipe: &Value,
        recipe_seq: &Value,
    ) -> Result<Value> {
        let (recipient, tag) = match index {
            Some(index) => (index, "inspect-storage"),
            None => (
                first_server(&self.local.snapshot()?.request)?,
                "inspect-objects",
            ),
        };
        let payload = read_payload(recipe, index);
        Ok(self
            .family_step(recipient, tag, payload, vec![recipe_seq.clone()])
            .await?
            .1)
    }

    async fn storage_reads(
        &mut self,
        recipe: &Value,
        recipe_seq: &Value,
    ) -> Result<(Vec<Value>, Value)> {
        let mut storage = Vec::with_capacity(self.members.len());
        for index in 0..self.members.len() {
            let read = self.storage_read(Some(index), recipe, recipe_seq).await?;
            storage.push(read["storage"].clone());
        }
        let api = self.storage_read(None, recipe, recipe_seq).await?;
        Ok((storage, api["nodes"].clone()))
    }

    async fn storage_effect(
        &mut self,
        index: usize,
        recipe: &Value,
        recipe_seq: &Value,
        resource: &Value,
    ) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let machine = &self.members[index]["machine"];
        let latest = snapshot
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == "registry-storage-observation"
                    && o["event"]["member"]["machine"] == *machine
            })
            .ok_or(Failure::Integrity)?
            .clone();
        let mut refs = vec![
            recipe_seq.clone(),
            network::latest_sequence(snapshot, "server-membership")?,
            latest["sequence"].clone(),
        ];
        if self.members.iter().any(|member| member["role"] == "agent") {
            refs.push(network::latest_sequence(snapshot, "agent-membership")?);
        }
        refs.sort_by_key(Value::as_u64);
        refs.dedup();
        let payload = json!({"recipe":recipe,"expected":expected(recipe, index),
            "resource":resource,"preflight":latest["event"]["storage"],
            "member":recipe["members"][index]});
        self.family_step(index, "create-storage", payload, refs)
            .await
    }

    async fn gated_reads(
        &mut self,
        recipe: &Value,
        recipe_seq: &Value,
    ) -> Result<(Vec<Value>, Value)> {
        self.network_source_gate().await?;
        self.storage_reads(recipe, recipe_seq).await
    }

    fn refuse(
        &mut self,
        recipe: &Value,
        storage: &[Value],
        refused: (Failure, Option<usize>),
    ) -> Failure {
        self.local.failure_detail = self
            .local
            .failure_detail
            .or(detail(recipe, storage, refused.1));
        refused.0
    }

    async fn storage_run(&mut self, recipe: Value) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq =
            network::latest_sequence(self.local.snapshot()?, "registry-storage-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let capacity = recipe["capacity_mib"].as_u64().ok_or(Failure::Integrity)?;
        for &member in &order {
            let owner = self
                .inspect_step(member, "owner", Value::Null, Value::Null)
                .await?;
            require(
                owner["status"] == "ok"
                    && owner["data"]["claim"]["active_attempt"].is_null()
                    && owner["data"]["ownership"]["cluster"] == cluster
                    && owner["data"]["ownership"]["machine"]["node_uid"]
                        == self.members[member]["node_uid"],
                Failure::Ownership,
            )?;
            self.generations[member] = owner["data"]["claim"]["generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?;
            let writer = self
                .inspect_step(member, "writer", Value::Null, Value::Null)
                .await?;
            require(
                writer["status"] == "absent" || writer["status"] == "ok",
                Failure::Ownership,
            )?;
        }
        let (storage, nodes) = self.gated_reads(&recipe, &recipe_seq).await?;
        if let Err(refused) = precedence(capacity, &directories(&recipe, &storage), None) {
            return Err(self.refuse(&recipe, &storage, refused));
        }
        let _ = nodes;
        for &member in &order {
            self.dispatch(
                member,
                "reserve-owner",
                json!({"members":self.members,"excluded":null,"cluster":cluster,
                "fingerprints":self.context.fingerprints}),
                Vec::new(),
            )
            .await?;
        }
        for &member in &order {
            self.dispatch(
                member,
                "acquire-writer",
                super::session::acquire_payload(self.local.snapshot()?, &self.members)?,
                Vec::new(),
            )
            .await?;
        }
        self.acquired()?;
        self.mode = Mode::Work;
        self.context
            .authenticate_owned(&Value::Array(self.members.clone()))
            .await?;
        let (storage, _) = self.gated_reads(&recipe, &recipe_seq).await?;
        if let Err(refused) = precedence(capacity, &directories(&recipe, &storage), None) {
            return Err(self.refuse(&recipe, &storage, refused));
        }
        let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
        for index in 0..self.members.len() {
            if !recipe["origins"]["directories"][index].is_null() {
                continue;
            }
            let (step, created) = self
                .storage_effect(index, &recipe, &recipe_seq, &resources[index])
                .await?;
            let identity = created["terminal"]["resource_identity"].clone();
            let receipt = self
                .inspect_step(index, "dispatch", step["dispatch"].clone(), Value::Null)
                .await?;
            require(receipt["status"] == "ok", Failure::Ownership)?;
            let read = self.storage_read(Some(index), &recipe, &recipe_seq).await?;
            require(
                read["storage"]["class"] == "owned" && read["storage"]["directory"] == identity,
                Failure::Ownership,
            )?;
        }
        let (storage, _) = self.storage_reads(&recipe, &recipe_seq).await?;
        confirms(&storage)?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let (mut session, recipe) = begin(project, policy, target).await?;
    let result = Box::pin(session.storage_run(recipe)).await;
    session.local.complete(result, &session.context.clock).await
}

