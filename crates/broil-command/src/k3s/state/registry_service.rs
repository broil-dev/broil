// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::issuer;
use super::network::{self, Family};
use super::registry_storage as storage;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{NETWORK, PROFILE, protocol};
use broil_config::LoadedProject;
use broil_core::k3s::{Infrastructure, ManagedRegistry, TaintEffect};
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "registry-service",
    protocol: "broil-k3s-registry-service",
    magic: b"BK3SRSV2\n",
    header: "RegistryServiceHeader",
    result: "RegistryServiceResult",
    body: NETWORK,
    planned: 5,
    reserve: 16_384,
    version: 2,
};

const OBJECTS: [(&str, Option<&str>); 5] = [
    ("service", None),
    ("service", Some("broil-registry")),
    ("service", Some("broil-registry")),
    ("service", Some("broil-registry")),
    ("service", Some("broil-registry")),
];

pub(super) fn action(tag: &str) -> String {
    format!("lifecycle:registry-service-{tag}")
}

pub(super) fn gate(registry: &ManagedRegistry, pin: &Value) -> Result<()> {
    let image = format!(
        "{}@sha256:{}",
        pin["image"].as_str().unwrap_or_default(),
        pin["digest"].as_str().unwrap_or_default()
    );
    require(
        pin["version"] == registry.version.as_str() && registry.image.supplied == image,
        Failure::Configuration,
    )
}

pub(super) fn gates(
    registry: Option<&ManagedRegistry>,
    infrastructure: &Infrastructure,
    profile: &Value,
) -> Result<ManagedRegistry> {
    storage::gate(registry.map(|r| r.certificate.as_str()), infrastructure)?;
    let registry = registry.cloned().ok_or(Failure::Configuration)?;
    gate(&registry, &profile["registry"])?;
    Ok(registry)
}

fn ids() -> Vec<String> {
    (1..=5)
        .map(|n| format!("registry-service-object-{n:02}"))
        .collect()
}

pub(super) fn stage(origins: &Value) -> Result<&'static str> {
    let objects = origins["objects"].as_array().ok_or(Failure::Integrity)?;
    let images = origins["images"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if objects.iter().all(Value::is_null) && origins["configuration"].is_null() {
        Ok("create")
    } else if objects.iter().all(Value::is_object) {
        Ok(if images.iter().any(Value::is_null) {
            "extend"
        } else {
            "observe"
        })
    } else {
        Err(Failure::Ownership)
    }
}

pub(super) fn effects(origins: &Value) -> usize {
    let images = origins["images"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    match stage(origins) {
        Ok("create") => images.len() + 5,
        Ok("extend") => images.iter().filter(|i| i.is_null()).count(),
        _ => 0,
    }
}

pub(super) fn budgets(
    imports: u64,
    creates: u64,
    step: u64,
    member: u64,
    first: u64,
    remaining: u64,
) -> Result<()> {
    let importing = step.min(member);
    let needed = imports
        .checked_mul(importing.min(600) + 2 * 30)
        .and_then(|n| n.checked_add(creates.checked_mul(45 + 2 * 30)?))
        .and_then(|n| n.checked_add(50))
        .ok_or(Failure::Bound)?;
    require(
        importing.min(first) >= 60 && remaining >= needed,
        Failure::Bound,
    )
}

pub(super) fn established(
    owner: &Value,
    _registry: &ManagedRegistry,
    members: &[Value],
) -> Result<Vec<Value>> {
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    require(
        resources
            .iter()
            .filter(|r| {
                r["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("network-object-"))
                    && r["uid"].is_string()
            })
            .count()
            == 12,
        Failure::Ownership,
    )?;
    let mut replicas = Vec::with_capacity(members.len());
    for member in members {
        let id = storage::replica_id(member["member"].as_str().ok_or(Failure::Integrity)?)?;
        let held = resources
            .iter()
            .find(|r| r["id"] == id.as_str())
            .ok_or(Failure::Readiness)?;
        replicas.push(held.clone());
    }
    require(
        members.iter().all(|m| m["node_uid"].is_string()),
        Failure::Readiness,
    )?;
    Ok(replicas)
}

pub(super) fn storage_origins(previous: &[Snapshot], replicas: &[Value]) -> Result<Value> {
    let origins = storage::origins(previous, replicas).map_err(|failure| {
        if failure == Failure::Integrity {
            failure
        } else {
            Failure::Readiness
        }
    })?;
    require(
        !replicas.is_empty()
            && origins["directories"]
                .as_array()
                .is_some_and(|d| d.iter().all(Value::is_object)),
        Failure::Readiness,
    )?;
    Ok(origins)
}

pub(super) fn evidence(found: Result<(Vec<Value>, Vec<Value>)>) -> Result<(Value, Value)> {
    match found {
        Ok((entries, resources)) if entries.len() == 1 && resources.len() == 1 => Ok((
            json!({"generation":entries[0]["generation"],"marker_sha256":entries[0]["marker_sha256"]}),
            resources[0].clone(),
        )),
        Err(Failure::Integrity) => Err(Failure::Integrity),
        _ => Err(Failure::Readiness),
    }
}

fn precedence(
    stage: &str,
    capacity: u64,
    hosts: &[(Value, bool)],
    api: &Value,
    nodes: bool,
) -> Result<()> {
    let directories: Vec<(Value, bool)> = hosts
        .iter()
        .map(|(h, _)| (h["storage"].clone(), true))
        .collect();
    if nodes {
        storage::admits(capacity, &directories, &api["nodes"])?;
    } else {
        storage::columns(capacity, &directories, &api["nodes"])?;
    }
    let objects = api["objects"].as_array().ok_or(Failure::Integrity)?;
    require(objects.len() == 5, Failure::Integrity)?;
    require(
        hosts
            .iter()
            .all(|(h, _)| h["image"] != "unobservable" && h["runtime"] == "ready")
            && objects.iter().all(|o| o["class"] != "unobservable"),
        Failure::Readiness,
    )?;
    require(
        hosts
            .iter()
            .all(|(h, imports)| !imports || h["generation"] == "ready"),
        Failure::Readiness,
    )?;
    require(
        hosts.iter().all(|(h, _)| h["image"] != "conflicting"),
        Failure::Ownership,
    )?;
    require(
        hosts
            .iter()
            .all(|(h, imports)| *imports || h["image"] == "ready"),
        Failure::Readiness,
    )?;
    let wanted = if stage == "create" { "absent" } else { "owned" };
    require(
        objects.iter().all(|o| o["class"] == wanted),
        Failure::Ownership,
    )
}

pub(super) fn admits(
    stage: &str,
    capacity: u64,
    hosts: &[(Value, bool)],
    api: &Value,
) -> Result<()> {
    precedence(stage, capacity, hosts, api, true)
}

pub(super) fn columns(
    stage: &str,
    capacity: u64,
    hosts: &[(Value, bool)],
    api: &Value,
) -> Result<()> {
    precedence(stage, capacity, hosts, api, false)
}

pub(super) fn confirms(hosts: &[Value], api: &Value) -> Result<()> {
    let objects = api["objects"].as_array().ok_or(Failure::Integrity)?;
    require(
        hosts
            .iter()
            .all(|h| h["image"] != "unobservable" && h["image"] != "not-ready")
            && objects.iter().all(|o| o["class"] != "unobservable"),
        Failure::Readiness,
    )?;
    require(
        objects.len() == 5
            && objects.iter().all(|o| o["class"] == "owned")
            && hosts.iter().all(|h| h["image"] == "ready"),
        Failure::Ownership,
    )
}

pub(super) fn readiness(hosts: &[Value], api: &Value) -> &'static str {
    let owned = api["objects"]
        .as_array()
        .is_some_and(|o| o.len() == 5 && o.iter().all(|o| o["class"] == "owned"));
    if owned
        && !hosts.is_empty()
        && hosts.iter().all(|h| h["image"] == "ready")
        && api["process"]["state"] == "ready"
    {
        "ready"
    } else {
        "not-ready"
    }
}

pub(super) fn readiness_v1(host: &Value, api: &Value) -> (&'static str, &'static str) {
    let state = |ready: bool| if ready { "ready" } else { "not-ready" };
    let owned = api["objects"]
        .as_array()
        .is_some_and(|o| o.len() == 6 && o.iter().all(|o| o["class"] == "owned"));
    let claim = &api["objects"][3];
    (
        state(owned && api["process"]["state"] == "ready"),
        state(
            host["storage"]["class"] == "owned"
                && api["volume"]["record"]["class"] == "owned"
                && api["node"] == "ready"
                && api["volume"]["binding"] == "bound"
                && claim["class"] == "owned"
                && claim["uid"].is_string()
                && api["volume"]["claim_uid"] == claim["uid"],
        ),
    )
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let host = matches!(tag, "inspect-host" | "import-image");
    let api = tag == "inspect-objects";
    require(
        ["generation", "image", "runtime", "storage"]
            .iter()
            .all(|key| result[*key].is_null() != host)
            && ["objects", "process", "nodes"]
                .iter()
                .all(|key| result[*key].is_null() != api)
            && (!api || result["objects"].is_array() && result["nodes"].is_array())
            && result["terminal"].is_null() == matches!(tag, "inspect-host" | "inspect-objects"),
        Failure::Integrity,
    )
}

pub(super) fn expected(recipe: &Value, index: Option<usize>) -> Value {
    let objects: Vec<Value> = recipe["origins"]["objects"]
        .as_array()
        .map_or_else(Vec::new, |o| {
            o.iter().map(|origin| origin["uid"].clone()).collect()
        });
    let storage = index.map_or(Value::Null, |index| {
        storage::expected(&recipe["storage"], index)
    });
    json!({"storage":storage,"objects":objects})
}

pub(super) fn recipe_of<'s>(family: &str, snapshot: &'s Snapshot) -> Result<&'s Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == format!("{family}-recipe"))
        .map(|o| &o["event"]["recipe"])
        .ok_or(Failure::Integrity)
}

pub(super) fn reads_after<'s>(
    family: &str,
    snapshot: &'s Snapshot,
    sequence: &Value,
) -> impl Iterator<Item = &'s Value> {
    let (after, kind) = (
        sequence.as_u64().unwrap_or(u64::MAX),
        format!("{family}-observation"),
    );
    snapshot.observations.iter().filter(move |o| {
        o["event"]["type"] == kind.as_str()
            && o["event"]["member"].is_null()
            && o["sequence"].as_u64().is_some_and(|s| s > after)
    })
}

pub(super) fn object_origins(previous: &[Snapshot], resources: &[Value]) -> Result<Value> {
    let configuration = match resources.get(2) {
        Some(configmap) => {
            super::registry_token::switch_origin(previous, configmap)?["configuration_sha256"]
                .clone()
        }
        None => Value::Null,
    };
    Ok(
        json!({"objects":objects("registry-service", previous, resources)?,
        "configuration":configuration}),
    )
}

pub(super) fn origins(
    previous: &[Snapshot],
    resources: &[Value],
    assets: &[Value],
) -> Result<Value> {
    let mut origins = object_origins(previous, resources)?;
    origins["images"] = json!(imported("registry-service", previous, assets)?);
    Ok(origins)
}

pub(super) fn imported(
    family: &str,
    previous: &[Snapshot],
    assets: &[Value],
) -> Result<Vec<Value>> {
    let (import, request) = (
        format!("lifecycle:{family}-import-image"),
        format!("reconcile-{family}"),
    );
    let mut images = Vec::with_capacity(assets.len());
    for asset in assets {
        let found: Vec<(&Snapshot, &Value)> = previous
            .iter()
            .filter(|s| s.request["action"] == request.as_str())
            .flat_map(|s| {
                s.steps
                    .iter()
                    .filter(|step| {
                        step["action"] == import.as_str()
                            && step["resource"]["id"] == asset["id"]
                            && step["resource"]["generation"] == asset["generation"]
                            && step["resource"]["machine"] == asset["machine"]
                    })
                    .map(move |step| (s, step))
            })
            .collect();
        let Some(&(snapshot, _)) = found.last() else {
            images.push(Value::Null);
            continue;
        };
        require(
            found.iter().all(|(s, step)| s.succeeded(step)),
            Failure::Ownership,
        )?;
        images.push(json!({"operation":snapshot.request["operation"]}));
    }
    Ok(images)
}

pub(super) fn recipe_label(family: &str) -> String {
    let version = if matches!(family, "registry-service" | "registry-token") {
        2
    } else {
        1
    };
    format!("broil-k3s-{family}-recipe-v{version}")
}

pub(super) fn objects(
    family: &str,
    previous: &[Snapshot],
    resources: &[Value],
) -> Result<Vec<Value>> {
    let (create, request) = (
        format!("lifecycle:{family}-create-object"),
        format!("reconcile-{family}"),
    );
    let mut objects = Vec::with_capacity(resources.len());
    for (n, resource) in resources.iter().enumerate() {
        let found: Vec<(&Snapshot, &Value)> = previous
            .iter()
            .filter(|s| s.request["action"] == request.as_str())
            .flat_map(|s| {
                s.steps
                    .iter()
                    .filter(|step| {
                        step["action"] == create.as_str()
                            && step["resource"]["id"] == resource["id"]
                            && step["resource"]["generation"] == resource["generation"]
                    })
                    .map(move |step| (s, step))
            })
            .collect();
        require(found.len() <= 1, Failure::Ownership)?;
        let Some(&(snapshot, step)) = found.first() else {
            require(resource["uid"].is_null(), Failure::Ownership)?;
            objects.push(Value::Null);
            continue;
        };
        let uid = &resource["uid"];
        let receipt = issuer::recorded(snapshot, step, "receiver")?;
        let observed = reads_after(family, snapshot, &receipt["sequence"]).any(|o| {
            o["event"]["objects"][n]["class"] == "owned" && o["event"]["objects"][n]["uid"] == *uid
        });
        let bound = snapshot.observations.iter().any(|o| {
            o["event"]["type"] == "identity"
                && o["event"]["resources"][0]["id"] == resource["id"]
                && o["event"]["resources"][0]["uid"] == *uid
        });
        require(
            snapshot.succeeded(step)
                && uid.is_string()
                && receipt["event"]["receipt"]["resource_identity"] == *uid
                && observed
                && bound,
            Failure::Ownership,
        )?;
        objects.push(json!({"operation":snapshot.request["operation"],
            "recipe_sha256":hash(&recipe_label(family), recipe_of(family, snapshot)?)?,
            "uid":uid}));
    }
    Ok(objects)
}

pub(super) fn planned(owner: &Value, previous: &[Snapshot]) -> Result<(Vec<Value>, Option<Value>)> {
    let ids = ids();
    let shaped = |n: usize, generation: Value, uid: Value| {
        json!({"kind":OBJECTS[n].0,"id":ids[n],"owner":owner["owner"],"generation":generation,
            "machine":null,"path":null,"namespace":OBJECTS[n].1,"name":"broil-registry","uid":uid})
    };
    let held: Vec<&Value> = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| {
            r["id"]
                .as_str()
                .is_some_and(|id| ids.iter().any(|i| i == id))
        })
        .collect();
    if held.is_empty() {
        let planned = (0..5)
            .map(|n| Ok(shaped(n, json!(fresh()?), Value::Null)))
            .collect::<Result<Vec<_>>>()?;
        let mut successor = owner.clone();
        successor["previous_generation"] = successor["generation"].clone();
        successor["generation"] = json!(fresh()?);
        successor["created_ms"] = json!(now()?);
        successor["resources"]
            .as_array_mut()
            .ok_or(Failure::Integrity)?
            .extend(planned.iter().cloned());
        return Ok((planned, Some(successor)));
    }
    require(
        held.len() == 5
            && held
                .iter()
                .enumerate()
                .all(|(n, r)| **r == shaped(n, r["generation"].clone(), r["uid"].clone())),
        Failure::Ownership,
    )?;
    if held.iter().any(|r| r["uid"].is_null()) {
        require(
            held.iter().all(|r| r["uid"].is_null())
                && !previous.iter().any(|s| {
                    s.request["resources"]
                        .as_array()
                        .is_some_and(|r| r.iter().any(|r| r["id"] == ids[0]))
                }),
            Failure::Ownership,
        )?;
    }
    Ok((held.into_iter().cloned().collect(), None))
}

fn effect(effect: TaintEffect) -> &'static str {
    match effect {
        TaintEffect::NoSchedule => "NoSchedule",
        TaintEffect::PreferNoSchedule => "PreferNoSchedule",
        TaintEffect::NoExecute => "NoExecute",
    }
}

pub(super) fn tolerations(context: &rpc::Context<'_>, member: &str) -> Result<Vec<Value>> {
    let declared = context
        .selected
        .declaration
        .members
        .iter()
        .find(|m| m.name == member)
        .ok_or(Failure::Configuration)?;
    Ok(declared
        .taints
        .iter()
        .map(|t| json!({"key":t.key,"value":t.value,"effect":effect(t.effect)}))
        .collect())
}

pub(super) fn replica_tolerations(
    context: &rpc::Context<'_>,
    members: &[Value],
) -> Result<Vec<Value>> {
    let mut list: Vec<Value> = Vec::new();
    for member in members {
        let name = member["member"].as_str().ok_or(Failure::Integrity)?;
        for toleration in tolerations(context, name)? {
            if !list.contains(&toleration) {
                list.push(toleration);
            }
        }
    }
    Ok(list)
}

pub(super) fn writer(owner: &Value, registry: &ManagedRegistry) -> Result<(String, u64)> {
    let record = &owner["writer"];
    if record.is_null() {
        return Ok((registry.member.clone(), 1));
    }
    let member = record["member"].as_str().ok_or(Failure::Integrity)?;
    let moves = record["moves"].as_u64().ok_or(Failure::Integrity)?;
    let generation = moves
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or(Failure::Integrity)?;
    Ok((member.to_owned(), generation))
}

pub(super) fn creation_tolerations(previous: &[Snapshot], origins: &Value) -> Result<Value> {
    let operation = origins["objects"][0]["operation"]
        .as_str()
        .ok_or(Failure::Ownership)?;
    let creating = previous
        .iter()
        .find(|s| s.request["operation"] == operation)
        .ok_or(Failure::Ownership)?;
    let recipe = recipe_of("registry-service", creating)?;
    require(
        hash(&recipe_label("registry-service"), recipe)? == origins["objects"][0]["recipe_sha256"],
        Failure::Ownership,
    )?;
    let tolerations = recipe["tolerations"].clone();
    require(tolerations.is_array(), Failure::Integrity)?;
    Ok(tolerations)
}

fn recorded_tolerations(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    members: &[Value],
    origins: &Value,
) -> Result<Value> {
    if origins["objects"][0].is_null() {
        return Ok(json!(replica_tolerations(context, members)?));
    }
    creation_tolerations(previous, origins)
}

#[allow(clippy::too_many_arguments)]
fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    registry: &ManagedRegistry,
    members: &[Value],
    assets: &[Value],
    storage_origins: &Value,
    tolerations: &Value,
    stage: &str,
    origins: &Value,
) -> Result<Value> {
    let first_server = members
        .iter()
        .find(|m| m["role"] == "server")
        .ok_or(Failure::Ownership)?;
    let (writer, writer_generation) = writer(owner, registry)?;
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"first_server":first_server,"members":members,
        "writer":writer,"writer_generation":writer_generation,
        "version":context.selected.declaration.version,"registry":registry.name,
        "registry_version":registry.version,"image":registry.image.supplied,"assets":assets,
        "storage":{"path":registry.storage.path,"capacity_mib":registry.storage.capacity_mib,
            "runtime":{"uid":10_000,"gid":10_000},"origins":storage_origins},
        "tolerations":tolerations,"stage":stage,"origins":origins,
        "profile_sha256":context.fingerprints["profile_sha256"]});
    schema::validate(&canonical(&recipe)?, "RegistryServiceRecipe", 32_768)?;
    Ok(recipe)
}

fn widest_api(recipe: &Value) -> Value {
    let wide = "f".repeat(128);
    let object = json!({"kind":"NetworkPolicy","namespace":"broil-registry",
        "name":"broil-registry","uid":wide,"class":"owned-drifted","spec_sha256":"0".repeat(64)});
    let nodes: Vec<Value> = recipe["members"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|m| json!({"member":m["member"],"node":"unobservable"}))
        .collect();
    json!({"objects":vec![object; 5],"nodes":nodes})
}

fn fits(request: &Value, attempt: &str, count: usize, recipe: &Value, index: usize) -> Result<()> {
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let binding = |member: usize| -> Result<Value> {
        let mut binding = network::read_binding(request, attempt, last, member)?;
        binding["receiver_generation"] = json!(u64::MAX);
        Ok(binding)
    };
    let wide = "f".repeat(128);
    let identity = json!([u64::MAX, u64::MAX]);
    let api = widest_api(recipe);
    let expected = json!({"storage":{"record_sha256":"0".repeat(64),"directory":identity,
        "data":identity,"fsid":u64::MAX},"objects":vec![json!(wide); 5]});
    let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
    let objects = resources.len().checked_sub(5).ok_or(Failure::Integrity)?;
    let member = &recipe["members"][index];
    let mut headers = Vec::new();
    for ordinal in 1..=5 {
        headers.push(json!({"protocol":FAMILY.protocol,"version":FAMILY.version,
            "action":"create-object","request_id":fresh()?,"binding":binding(0)?,
            "remaining_ms":7_200_000,"recipe":recipe,"expected":{"storage":null,
            "objects":expected["objects"]},"resource":resources[objects + ordinal - 1],
            "preflight":api,"object_ordinal":ordinal,"member":null}));
    }
    let asset = resources.first().ok_or(Failure::Integrity)?;
    headers.push(json!({"protocol":FAMILY.protocol,"version":FAMILY.version,
        "action":"import-image","request_id":fresh()?,"binding":binding(index)?,
        "remaining_ms":7_200_000,"recipe":recipe,"expected":expected,"resource":asset,
        "preflight":{"generation":"not-ready","image":"unobservable","runtime":"not-ready"},
        "object_ordinal":null,"member":member}));
    for header in headers {
        require(
            canonical(&header)?
                .len()
                .checked_add(17 + FAMILY.reserve)
                .is_some_and(|n| n <= 65_536),
            Failure::Bound,
        )?;
    }
    let terminal = json!({"schema":1,"kind":"terminal","binding":binding(index)?,
        "action":action("import-image"),"payload_sha256":"0".repeat(64),"outcome":"succeeded",
        "failure":"unsupported-version","effect":"complete","writer_ended":true,
        "resource":asset,"resource_identity":identity,"completed_ms":u64::MAX});
    let import = json!({"kind":"result","status":"unsupported-version","terminal":terminal,
        "generation":"not-ready","image":"unobservable","runtime":"not-ready",
        "storage":storage::widest_fact(),"objects":null,"process":null,"nodes":null,
        "failure":"unsupported-version"});
    let reads = json!({"kind":"result","status":"unsupported-version","terminal":null,
        "generation":null,"image":null,"runtime":null,"storage":null,"objects":api["objects"],
        "process":{"state":"not-ready","reason":"unobservable","node":wide,"restarts":u64::MAX},
        "nodes":api["nodes"],"failure":"unsupported-version"});
    for reply in [import, reads] {
        require(canonical(&reply)?.len() <= FAMILY.reserve, Failure::Bound)?;
    }
    Ok(())
}

pub(super) async fn admission_read(
    context: &rpc::Context<'_>,
    family: &Family,
    shape: fn(&str, &Value) -> Result<()>,
    binding: &Value,
    tag: &str,
    payload: &Value,
    cleanup: &mut bool,
) -> Result<Value> {
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
    );
    let observed = network::invoke(context, family, binding, tag, payload, deadline, None).await;
    *cleanup |= network::unclean(&observed.transport);
    let result = observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", super::server::refused(&result))?;
    shape(tag, &result)?;
    Ok(result)
}

pub(super) fn read_payload(recipe: &Value, index: Option<usize>, objects: &Value) -> Value {
    let mut expected = expected(recipe, index);
    expected["objects"] = objects.clone();
    let member = index.map_or(Value::Null, |index| recipe["members"][index].clone());
    json!({"recipe":recipe,"expected":expected,"resource":null,"preflight":null,
        "object_ordinal":null,"member":member})
}

pub(super) fn importing(recipe: &Value) -> Vec<bool> {
    let images = recipe["origins"]["images"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let create = recipe["stage"] == "create";
    images.iter().map(|i| create || i.is_null()).collect()
}

pub(super) fn first_server(request: &Value) -> Result<usize> {
    request["members"]
        .as_array()
        .and_then(|members| members.iter().position(|m| m["role"] == "server"))
        .ok_or(Failure::Integrity)
}

async fn preflight(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    source_events: &[Value],
    cleanup: &mut bool,
) -> Result<()> {
    let binding = |index| network::read_binding(request, attempt, last, index);
    let objects = expected(recipe, None)["objects"].clone();
    let imports = importing(recipe);
    let mut hosts = Vec::with_capacity(imports.len());
    for (index, imports) in imports.into_iter().enumerate() {
        let host = admission_read(
            context,
            &FAMILY,
            shape,
            &binding(index)?,
            "inspect-host",
            &read_payload(recipe, Some(index), &objects),
            cleanup,
        )
        .await?;
        hosts.push((host, imports));
    }
    let api = admission_read(
        context,
        &FAMILY,
        shape,
        &binding(first_server(request)?)?,
        "inspect-objects",
        &read_payload(recipe, None, &objects),
        cleanup,
    )
    .await?;
    let stage = recipe["stage"].as_str().ok_or(Failure::Integrity)?;
    let capacity = recipe["storage"]["capacity_mib"]
        .as_u64()
        .ok_or(Failure::Integrity)?;
    admits(stage, capacity, &hosts, &api)?;
    network::membership_reads(context, request, attempt, last, source_events, cleanup).await
}

pub(super) fn script_seconds(context: &rpc::Context<'_>, member: &Value) -> Result<u64> {
    let machine = member["machine"].as_str().ok_or(Failure::Integrity)?;
    let target = context
        .inventory
        .machines
        .iter()
        .find(|m| m.name == machine)
        .ok_or(Failure::Configuration)?;
    let script = context
        .inventory
        .scripts
        .get(&context.selected.declaration.lifecycle_script)
        .ok_or(Failure::Configuration)?;
    Ok(script
        .timeout
        .as_ref()
        .map_or(target.timeouts.command.seconds, |d| d.seconds))
}

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<(Box<Session<'a>>, Value)> {
    let context = rpc::Context::new(project, policy, target)?;
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let declaration = context.selected.declaration;
    let registry = gates(
        declaration.registry.as_ref(),
        &declaration.infrastructure,
        &profile,
    )?;
    let mut local = Local::new(&context)?;
    let prepared: Result<_> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e| e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()), Failure::Ownership)?;
        let members = super::survivors(&owner)?;
        let replicas = established(&owner, &registry, &members)?;
        for snapshot in &previous {
            super::session::settled(&super::report::report(&context.scope, "show",
                std::slice::from_ref(snapshot))?)?;
        }
        let storage_origins = storage_origins(&previous, &replicas)?;
        let (objects, pending_owner) = planned(&owner, &previous)?;
        let found: Vec<Result<(Value, Value)>> = members.iter()
            .map(|m| evidence(super::ingress::generations(&previous, &context, std::iter::once(m))))
            .collect();
        let held: Vec<Value> = found.iter()
            .map(|f| f.as_ref().map_or(Value::Null, |(_, resource)| resource.clone()))
            .collect();
        let origins = origins(&previous, &objects, &held)?;
        let stage = stage(&origins)?;
        let mut assets = Vec::with_capacity(members.len());
        for (member, found) in members.iter().zip(found) {
            let (entry, _) = found?;
            assets.push(json!({"member":member["member"],"generation":entry["generation"],
                "marker_sha256":entry["marker_sha256"]}));
        }
        let imports: Vec<bool> = origins["images"].as_array().ok_or(Failure::Integrity)?
            .iter().map(|i| stage == "create" || i.is_null()).collect();
        if stage != "observe" {
            let remaining = context.clock.deadline()
                .saturating_duration_since(tokio::time::Instant::now()).as_secs();
            let mut importing = u64::MAX;
            let mut every = u64::MAX;
            for (member, imports) in members.iter().zip(&imports) {
                let seconds = script_seconds(&context, member)?;
                every = every.min(seconds);
                if *imports {
                    importing = importing.min(seconds);
                }
            }
            let count = imports.iter().filter(|i| **i).count() as u64;
            budgets(count, if stage == "create" { 5 } else { 0 },
                context.selected.step_timeout.seconds, importing, every, remaining)?;
        }
        context.authenticate_owned(&Value::Array(members.clone())).await?;
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let participants = super::participants(&Value::Array(members.clone()))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let tolerations = recorded_tolerations(&context, &previous, &members, &origins)?;
        let service_recipe = recipe(&context, &current_owner, &operation, &registry, &members,
            &assets, &storage_origins, &tolerations, stage, &origins)?;
        let created = now()?;
        let resources: Vec<Value> = held.iter().zip(&imports).filter(|(_, i)| **i)
            .map(|(r, _)| r.clone()).chain(objects.iter().cloned()).collect();
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-registry-service",
            "members":members,"cluster":current_owner["cluster"],"resources":resources,
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let count = storage::step_count(&members, members.len(), effects(&origins))?;
        for index in 0..members.len() {
            fits(&request, &attempt_id, count, &service_recipe, index)?;
        }
        let mut cleanup = false;
        let checked = preflight(&context, &request, &attempt_id, count as u64, &service_recipe,
            &source_events, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_registry_service(successor)).await?;
            require(local.snapshot()?.owner["resources"].as_array().is_some_and(|resources|
                resources.ends_with(&objects)), Failure::Ownership)?;
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
        for event in std::iter::once(json!({"type":"registry-service-recipe","recipe":service_recipe}))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members, attempt_id, service_recipe))
    }.await;
    let (members, attempt_id, service_recipe) = match prepared {
        Ok(value) => value,
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
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
        service_recipe,
    ))
}

impl Session<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn service_effect(
        &mut self,
        family: &str,
        api: fn(&Value) -> Value,
        index: usize,
        tag: &str,
        recipe: &Value,
        refs: &[Value],
        expected: &Value,
        resource: &Value,
        ordinal: Value,
        member: Option<Value>,
    ) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let (host, kind) = (tag == "import-image", format!("{family}-observation"));
        let recipient = &self.members[index];
        let latest = snapshot
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == kind.as_str()
                    && if host {
                        o["event"]["member"] == *recipient
                    } else {
                        o["event"]["member"].is_null() && !o["event"]["objects"].is_null()
                    }
            })
            .ok_or(Failure::Integrity)?
            .clone();
        let mut refs = refs.to_vec();
        refs.push(network::latest_sequence(snapshot, "server-membership")?);
        refs.push(latest["sequence"].clone());
        if self.members.iter().any(|member| member["role"] == "agent") {
            refs.push(network::latest_sequence(snapshot, "agent-membership")?);
        }
        refs.sort_by_key(Value::as_u64);
        refs.dedup();
        let event = &latest["event"];
        let preflight = if host {
            json!({"generation":event["generation"],"image":event["image"],"runtime":event["runtime"]})
        } else {
            api(event)
        };
        let mut payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight,"object_ordinal":ordinal});
        if let Some(member) = member {
            payload["member"] = member;
        }
        self.family_step(index, tag, payload, refs).await
    }

    async fn service_reads(
        &mut self,
        recipe: &Value,
        refs: &[Value],
        objects: &Value,
    ) -> Result<(Vec<Value>, Value)> {
        let mut hosts = Vec::with_capacity(self.members.len());
        for index in 0..self.members.len() {
            let payload = read_payload(recipe, Some(index), objects);
            hosts.push(
                self.family_step(index, "inspect-host", payload, refs.to_vec())
                    .await?
                    .1,
            );
        }
        let first = first_server(&self.local.snapshot()?.request)?;
        let payload = read_payload(recipe, None, objects);
        let api = self
            .family_step(first, "inspect-objects", payload, refs.to_vec())
            .await?
            .1;
        Ok((hosts, api))
    }

    async fn service_run(&mut self, recipe: Value) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq =
            network::latest_sequence(self.local.snapshot()?, "registry-service-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let stage = recipe["stage"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        let capacity = recipe["storage"]["capacity_mib"]
            .as_u64()
            .ok_or(Failure::Integrity)?;
        let imports = importing(&recipe);
        let mut objects = expected(&recipe, None)["objects"].clone();
        let mut refs = vec![recipe_seq];
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
        let paired = |hosts: Vec<Value>| -> Vec<(Value, bool)> {
            hosts.into_iter().zip(imports.iter().copied()).collect()
        };
        self.network_source_gate().await?;
        let (hosts, api) = self.service_reads(&recipe, &refs, &objects).await?;
        columns(&stage, capacity, &paired(hosts), &api)?;
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
        self.network_source_gate().await?;
        let (hosts, api) = self.service_reads(&recipe, &refs, &objects).await?;
        columns(&stage, capacity, &paired(hosts), &api)?;
        let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
        let first = first_server(&request)?;
        let mut assets = resources.iter();
        for (index, imports) in imports.iter().enumerate() {
            if !imports {
                continue;
            }
            let resource = assets.next().ok_or(Failure::Integrity)?.clone();
            let mut values = expected(&recipe, Some(index));
            values["objects"] = objects.clone();
            let (step, _) = self
                .service_effect(
                    "registry-service",
                    |event| json!({"objects":event["objects"],"nodes":event["nodes"]}),
                    index,
                    "import-image",
                    &recipe,
                    &refs,
                    &values,
                    &resource,
                    Value::Null,
                    Some(recipe["members"][index].clone()),
                )
                .await?;
            let receipt = self
                .inspect_step(index, "dispatch", step["dispatch"].clone(), Value::Null)
                .await?;
            require(receipt["status"] == "ok", Failure::Ownership)?;
            let payload = read_payload(&recipe, Some(index), &objects);
            self.family_step(index, "inspect-host", payload, refs.clone())
                .await?;
        }
        if stage == "create" {
            let offset = resources.len().checked_sub(5).ok_or(Failure::Integrity)?;
            for ordinal in 1..=5 {
                let resource = &resources[offset + ordinal - 1];
                let values = json!({"storage":null,"objects":objects});
                let (step, created) = self
                    .service_effect(
                        "registry-service",
                        |event| json!({"objects":event["objects"],"nodes":event["nodes"]}),
                        first,
                        "create-object",
                        &recipe,
                        &refs,
                        &values,
                        resource,
                        json!(ordinal),
                        Some(Value::Null),
                    )
                    .await?;
                let receipt = self
                    .inspect_step(first, "dispatch", step["dispatch"].clone(), Value::Null)
                    .await?;
                require(receipt["status"] == "ok", Failure::Ownership)?;
                let identity = created["terminal"]["resource_identity"].clone();
                require(
                    identity.as_str().is_some_and(protocol::opaque),
                    Failure::Ownership,
                )?;
                objects[ordinal - 1] = identity.clone();
                refs.push(
                    issuer::recorded(self.local.snapshot()?, &step, "receiver")?["sequence"]
                        .clone(),
                );
                let payload = read_payload(&recipe, None, &objects);
                let read = self
                    .family_step(first, "inspect-objects", payload, refs.clone())
                    .await?
                    .1;
                let object = &read["objects"][ordinal - 1];
                require(
                    object["class"] == "owned" && object["uid"] == identity,
                    Failure::Ownership,
                )?;
                let mut published = resource.clone();
                published["uid"] = identity;
                self.append(
                    &step,
                    json!({"type":"identity","member":null,"cluster":cluster,
                        "resources":[published],"readiness":super::report::readiness()}),
                    false,
                    Value::Null,
                )
                .await?;
                super::ingress::publish(&mut self.local, &published).await?;
            }
        }
        let (hosts, api) = self.service_reads(&recipe, &refs, &objects).await?;
        confirms(&hosts, &api)?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let (mut session, recipe) = begin(project, policy, target).await?;
    let result = Box::pin(session.service_run(recipe)).await;
    session.local.complete(result, &session.context.clock).await
}

