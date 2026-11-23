// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::issuer;
use super::network::{self, Family};
use super::registry_endpoint as endpoint;
use super::registry_service as service;
use super::registry_token as token;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::release::Refusal;
use crate::k3s::{DELIVERY, PROFILE, protocol, replication};
use broil_config::LoadedProject;
use serde_json::{Value, json};

pub(super) const FAMILY: Family = Family {
    name: "registry-replication",
    protocol: "broil-k3s-registry-replication",
    magic: b"BK3SRRP1\n",
    header: "RegistryReplicationHeader",
    result: "RegistryReplicationResult",
    body: DELIVERY,
    planned: 2,
    reserve: 16_384,
    version: 1,
};

pub(super) const PATH: &str = "/var/lib/broil-k3s-replication";
const READER: &str = "broil-registry-reader";
const HOST: [&str; 8] = [
    "inspect-replication",
    "create-replication",
    "create-replica",
    "configure-replication",
    "scan-replica",
    "revert-replica",
    "remove-device",
    "stop-replication",
];
pub(super) const MUTATIONS: [&str; 11] = [
    "create-replication",
    "create-replica",
    "configure-replication",
    "scan-replica",
    "revert-replica",
    "remove-device",
    "stop-replication",
    "create-object",
    "configure-reader",
    "stop-writer",
    "start-writer",
];

pub(super) fn action(tag: &str) -> String {
    format!("lifecycle:registry-replication-{tag}")
}

pub(super) const OBSERVATION: &str = "replication-observation";

pub(super) fn mutation(tag: &str) -> bool {
    MUTATIONS.contains(&tag)
}

pub(super) fn host(tag: &str) -> bool {
    HOST.contains(&tag)
}

fn refused(refusal: Refusal) -> Failure {
    match refusal.failure {
        "ownership" => Failure::Ownership,
        "readiness" => Failure::Readiness,
        "bound" => Failure::Bound,
        "busy" => Failure::Busy,
        _ => Failure::Integrity,
    }
}

pub(super) fn replication_id(member: &str) -> Result<String> {
    let id = format!("registry-replication-{member}");
    require(id.len() <= 128, Failure::Bound)?;
    require(protocol::opaque(&id), Failure::Configuration)?;
    Ok(id)
}

pub(super) fn wait_ms(tag: &str, request: &Value) -> Value {
    if matches!(tag, "scan-replica" | "revert-replica") {
        json!(
            request["step_timeout_ms"]
                .as_u64()
                .unwrap_or(0)
                .min(7_200_000)
        )
    } else {
        Value::Null
    }
}

pub(super) fn planned(
    owner: &Value,
    members: &[Value],
    previous: &[Snapshot],
) -> Result<(Vec<Value>, Vec<Value>, Option<Value>)> {
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    let found = |id: &str| -> Result<Option<Value>> {
        let found: Vec<&Value> = resources.iter().filter(|r| r["id"] == id).collect();
        require(found.len() <= 1, Failure::Ownership)?;
        Ok(found.first().map(|r| (*r).clone()))
    };
    let replication = |id: &str, generation: &Value, machine: &Value| {
        json!({"kind":"replication","id":id,"owner":owner["owner"],"generation":generation,
            "machine":machine,"path":PATH,"namespace":null,"name":null,"uid":null})
    };
    let reader = |n: usize, generation: &Value, uid: &Value| {
        json!({"kind":"service","id":replication::OBJECTS[n],"owner":owner["owner"],
            "generation":generation,"machine":null,"path":null,"namespace":"broil-registry",
            "name":READER,"uid":uid})
    };
    let mut held = Vec::with_capacity(members.len());
    for member in members {
        let id = replication_id(member["member"].as_str().ok_or(Failure::Integrity)?)?;
        held.push((id.clone(), found(&id)?));
    }
    let readers = [
        found(replication::OBJECTS[0])?,
        found(replication::OBJECTS[1])?,
    ];
    if held.iter().all(|(_, r)| r.is_none()) && readers.iter().all(Option::is_none) {
        let mut planned = Vec::with_capacity(members.len());
        for ((id, _), member) in held.iter().zip(members) {
            planned.push(replication(id, &json!(fresh()?), &member["machine"]));
        }
        let objects = vec![
            reader(0, &json!(fresh()?), &Value::Null),
            reader(1, &json!(fresh()?), &Value::Null),
        ];
        let mut successor = owner.clone();
        successor["previous_generation"] = successor["generation"].clone();
        successor["generation"] = json!(fresh()?);
        successor["created_ms"] = json!(now()?);
        successor["resources"]
            .as_array_mut()
            .ok_or(Failure::Integrity)?
            .extend(planned.iter().chain(&objects).cloned());
        return Ok((planned, objects, Some(successor)));
    }
    let mut list = Vec::with_capacity(members.len());
    for ((id, found), member) in held.into_iter().zip(members) {
        let found = found.ok_or(Failure::Ownership)?;
        require(
            found == replication(&id, &found["generation"], &member["machine"]),
            Failure::Ownership,
        )?;
        list.push(found);
    }
    let mut objects = Vec::with_capacity(2);
    for (n, found) in readers.into_iter().enumerate() {
        let found = found.ok_or(Failure::Ownership)?;
        require(
            found == reader(n, &found["generation"], &found["uid"]),
            Failure::Ownership,
        )?;
        objects.push(found);
    }
    if objects.iter().any(|r| r["uid"].is_null()) {
        require(
            objects.iter().all(|r| r["uid"].is_null())
                && !previous.iter().any(|s| {
                    s.request["resources"]
                        .as_array()
                        .is_some_and(|r| r.iter().any(|r| r["id"] == replication::OBJECTS[0]))
                }),
            Failure::Ownership,
        )?;
    }
    Ok((list, objects, None))
}

fn replication_origins(previous: &[Snapshot], replications: &[Value]) -> Result<Vec<Value>> {
    let create = action("create-replication");
    let mut origins = Vec::with_capacity(replications.len());
    for resource in replications {
        let found: Vec<(&Snapshot, &Value)> = previous
            .iter()
            .filter(|s| s.request["action"] == "reconcile-registry-replication")
            .flat_map(|s| {
                s.steps
                    .iter()
                    .filter(|step| {
                        step["action"] == create.as_str()
                            && step["resource"]["id"] == resource["id"]
                            && step["resource"]["generation"] == resource["generation"]
                            && step["resource"]["machine"] == resource["machine"]
                    })
                    .map(move |step| (s, step))
            })
            .collect();
        let Some(&(snapshot, _)) = found.last() else {
            origins.push(Value::Null);
            continue;
        };
        require(
            found.iter().all(|(s, step)| s.succeeded(step)),
            Failure::Ownership,
        )?;
        origins.push(json!({"operation":snapshot.request["operation"]}));
    }
    Ok(origins)
}

fn object_origins(previous: &[Snapshot], readers: &[Value]) -> Result<Vec<Value>> {
    let create = action("create-object");
    let mut origins = Vec::with_capacity(readers.len());
    for (n, resource) in readers.iter().enumerate() {
        let found: Vec<(&Snapshot, &Value)> = previous
            .iter()
            .filter(|s| s.request["action"] == "reconcile-registry-replication")
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
            origins.push(Value::Null);
            continue;
        };
        let uid = &resource["uid"];
        let receipt = issuer::recorded(snapshot, step, "receiver")?;
        let after = receipt["sequence"].as_u64().unwrap_or(u64::MAX);
        let observed = snapshot.observations.iter().any(|o| {
            o["event"]["type"] == OBSERVATION
                && o["event"]["member"].is_null()
                && o["sequence"].as_u64().is_some_and(|s| s > after)
                && o["event"]["objects"][n]["class"] == "owned"
                && o["event"]["objects"][n]["uid"] == *uid
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
        let payload = snapshot.registry_replication_payload(step)?;
        origins.push(json!({"operation":snapshot.request["operation"],
            "recipe_sha256":hash(replication::RECIPE_LABEL, &payload["recipe"])?,"uid":uid}));
    }
    Ok(origins)
}

fn listed(origins: Vec<Value>) -> Value {
    if origins.iter().all(Value::is_null) {
        Value::Null
    } else {
        json!(origins)
    }
}

pub(super) fn origins(
    previous: &[Snapshot],
    replications: &[Value],
    readers: &[Value],
) -> Result<Value> {
    Ok(
        json!({"replication":listed(replication_origins(previous, replications)?),
        "objects":listed(object_origins(previous, readers)?)}),
    )
}

fn observed_device(snapshot: &Snapshot, member: &Value) -> Option<Value> {
    snapshot
        .observations
        .iter()
        .rev()
        .find(|o| {
            o["event"]["type"] == OBSERVATION
                && o["event"]["member"]["member"] == member["member"]
                && o["event"]["replication"]["record"] == "owned"
                && o["event"]["replication"]["device_id"].is_string()
        })
        .map(|o| o["event"]["replication"]["device_id"].clone())
}

fn devices(previous: &[Snapshot], members: &[Value], origins: &Value) -> Result<Value> {
    let Some(list) = origins.as_array() else {
        return Ok(Value::Null);
    };
    let mut devices = Vec::with_capacity(members.len());
    for (member, origin) in members.iter().zip(list) {
        let device = match origin["operation"].as_str() {
            Some(operation) => {
                let creating = previous
                    .iter()
                    .find(|s| s.request["operation"] == operation)
                    .ok_or(Failure::Ownership)?;
                observed_device(creating, member).ok_or(Failure::Ownership)?
            }
            None => Value::Null,
        };
        devices.push(json!({"member":member["member"],"device_id":device}));
    }
    Ok(json!(devices))
}

pub(super) fn effective(recipe: &Value, filled: &[Value]) -> Value {
    if filled.iter().all(Value::is_null) {
        return recipe.clone();
    }
    let mut value = recipe.clone();
    let members = recipe["members"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    value["devices"] = json!(
        members
            .iter()
            .enumerate()
            .map(|(n, m)| {
                let recorded = &recipe["devices"][n]["device_id"];
                let device = if recorded.is_null() {
                    filled.get(n).cloned().unwrap_or(Value::Null)
                } else {
                    recorded.clone()
                };
                json!({"member":m["member"],"device_id":device})
            })
            .collect::<Vec<_>>()
    );
    value
}

fn reader(previous: &[Snapshot], owner: &Value, configmap: &Value) -> Result<Value> {
    let (resources, pending) = token::planned(owner, previous)?;
    require(
        pending.is_none() && resources.iter().all(|r| r["uid"].is_string()),
        Failure::Readiness,
    )?;
    let origins = endpoint::prerequisite(token::origins(previous, &resources, configmap))?;
    require(
        origins["switch"].is_object() && !origins["principals"].is_null(),
        Failure::Readiness,
    )?;
    let operation = &origins["switch"]["operation"];
    let switched = previous
        .iter()
        .find(|s| s.request["operation"] == *operation)
        .ok_or(Failure::Ownership)?;
    let recipe = service::recipe_of("registry-token", switched)?;
    Ok(
        json!({"realm_path":recipe["token"]["path"],"service":recipe["token"]["service"],
        "certificate":recipe["certificate"]["pem"],"switch_operation":operation}),
    )
}

fn reader_stale(previous: &[Snapshot], reader: &Value) -> Result<bool> {
    let (create, configure) = (action("create-object"), action("configure-reader"));
    let latest = previous
        .iter()
        .filter(|s| s.request["action"] == "reconcile-registry-replication")
        .filter(|s| {
            s.steps.iter().any(|step| {
                s.succeeded(step)
                    && (step["action"] == configure.as_str()
                        || step["action"] == create.as_str()
                            && step["resource"]["id"] == replication::OBJECTS[0])
            })
        })
        .max_by_key(|s| s.request["created_ms"].as_u64());
    let Some(snapshot) = latest else {
        return Ok(false);
    };
    let recipe = recipe_of(snapshot)?;
    Ok(recipe["reader"]["switch_operation"] != reader["switch_operation"])
}

pub(super) fn recipe_of(snapshot: &Snapshot) -> Result<&Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "replication-recipe")
        .map(|o| &o["event"]["recipe"])
        .ok_or(Failure::Integrity)
}

pub(super) fn expected(objects: &Value) -> Value {
    json!({"objects":objects,"device":null,"writer_generation":null})
}

pub(super) fn origin_uids(recipe: &Value) -> Value {
    match recipe["origins"]["objects"].as_array() {
        Some(objects) => json!(objects.iter().map(|o| o["uid"].clone()).collect::<Vec<_>>()),
        None => json!([null, null]),
    }
}

pub(super) fn read_payload(recipe: &Value, index: Option<usize>, objects: &Value) -> Value {
    let member = index.map_or(Value::Null, |index| {
        recipe["members"][index]["member"].clone()
    });
    json!({"recipe":recipe,"expected":expected(objects),"resource":null,"preflight":null,
        "wait_ms":null,"member":member})
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let api = tag == "inspect-objects";
    let facts = matches!(tag, "inspect-replication" | "create-replication");
    require(
        result["replication"].is_null() != facts
            && ["objects", "readers", "tokens", "writer", "node"]
                .iter()
                .all(|key| result[*key].is_null() != api)
            && result["cordoned"].is_null()
            && result["terminal"].is_null()
                == matches!(tag, "inspect-replication" | "inspect-objects"),
        Failure::Integrity,
    )?;
    if facts {
        replication::facts(&result["replication"]).map_err(refused)?;
    }
    if api {
        require(
            result["objects"].as_array().is_some_and(|o| o.len() == 2),
            Failure::Integrity,
        )?;
    }
    Ok(())
}

pub(super) fn stage_facts(
    recipe: &Value,
    hosts: &[Value],
    api: &Value,
    held: &[bool],
    stale: bool,
) -> Value {
    let members = recipe["members"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let rows: Vec<Value> = members
        .iter()
        .zip(hosts)
        .zip(held)
        .map(|((m, h), held)| {
            let f = &h["replication"];
            json!({"member":m["member"],"writer":m["member"] == recipe["writer"],"resource":held,
                "record":f["record"],"configuration":f["configuration"],"folder":f["folder"],
                "state":f["state"],"local_changes":f["local_changes"]})
        })
        .collect();
    let mut configmap = api["objects"][0]["class"].clone();
    let differs = stale && configmap == "owned-drifted";
    if differs {
        configmap = json!("owned");
    }
    json!({"members":rows,"objects":{"configmap":configmap,"daemonset":api["objects"][1]["class"]},
        "reader_differs":differs,"detached":recipe["detached"]})
}

pub(super) fn view_inputs(owner: &Value, snapshot: &Snapshot) -> Result<(Value, Value)> {
    let recipe = recipe_of(snapshot)?;
    let members = snapshot.request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    let filled: Vec<Value> = members
        .iter()
        .enumerate()
        .map(|(n, m)| {
            if recipe["devices"][n]["device_id"].is_null() {
                observed_device(snapshot, m).unwrap_or(Value::Null)
            } else {
                Value::Null
            }
        })
        .collect();
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    let objects: Vec<Value> = replication::OBJECTS
        .iter()
        .map(|id| {
            resources
                .iter()
                .find(|r| r["id"] == *id)
                .map_or(Value::Null, |r| r["uid"].clone())
        })
        .collect();
    Ok((effective(recipe, &filled), json!(objects)))
}

pub(super) fn readiness(hosts: &[Value], api: &Value) -> (&'static str, &'static str) {
    let state = |ready: bool| if ready { "ready" } else { "not-ready" };
    let storage = !hosts.is_empty()
        && hosts.iter().all(|h| {
            let f = &h["replication"];
            f["record"] == "owned" && f["configuration"] == "owned" && f["state"] == "in-sync"
        });
    let pods = |key: &str| {
        api[key].as_array().is_some_and(|rows| {
            rows.len() == hosts.len() && rows.iter().all(|r| r["ready"] == true)
        })
    };
    let services = api["objects"]
        .as_array()
        .is_some_and(|o| o.len() == 2 && o.iter().all(|o| o["class"] == "owned"))
        && pods("readers")
        && pods("tokens")
        && api["writer"]["process"]["state"] == "ready";
    (state(storage), state(services))
}

#[allow(clippy::too_many_arguments)]
fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    registry: &broil_core::k3s::ManagedRegistry,
    members: &[Value],
    devices: &Value,
    assets: &[Value],
    reader: &Value,
    tolerations: &Value,
    stage: &str,
    origins: &Value,
) -> Result<Value> {
    let first_server = members
        .iter()
        .find(|m| m["role"] == "server")
        .ok_or(Failure::Ownership)?;
    let (writer, _) = service::writer(owner, registry)?;
    let mut listed = Vec::with_capacity(members.len());
    for member in members {
        let declared = context
            .selected
            .declaration
            .members
            .iter()
            .find(|m| member["member"] == m.name.as_str())
            .ok_or(Failure::Configuration)?;
        let mut entry = member.clone();
        entry["node_ip"] = json!(declared.node_ip.to_string());
        listed.push(entry);
    }
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"first_server":first_server,
        "version":context.selected.declaration.version,"registry":registry.name,
        "path":registry.storage.path,"writer":writer,"members":listed,"devices":devices,
        "detached":[],"assets":assets,"reader":reader,"tolerations":tolerations,"stage":stage,
        "origins":origins,"profile_sha256":context.fingerprints["profile_sha256"]});
    replication::check_recipe(&recipe).map_err(refused)?;
    schema::validate(
        &canonical(&recipe)?,
        "RegistryReplicationRecipe",
        replication::RECIPE_LIMIT,
    )?;
    Ok(recipe)
}

pub(super) fn maintenance_recipe(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    operation: &str,
    stage: &str,
    first: &Value,
) -> Result<Option<(Value, Vec<Value>)>> {
    let Some(registry) = context.selected.declaration.registry.as_ref() else {
        return Ok(None);
    };
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    if !resources.iter().any(|r| r["kind"] == "replication") {
        return Ok(None);
    }
    let members = super::survivors(owner)?;
    let replicas = service::established(owner, registry, &members)?;
    service::storage_origins(previous, &replicas)?;
    let services: Vec<Value> = (1..=5)
        .map(|n| {
            resources
                .iter()
                .find(|r| {
                    r["id"] == format!("registry-service-object-{n:02}") && r["uid"].is_string()
                })
                .cloned()
                .ok_or(Failure::Readiness)
        })
        .collect::<Result<_>>()?;
    let service_origins = endpoint::prerequisite(service::object_origins(previous, &services))?;
    let reader = reader(previous, owner, &services[2])?;
    let (replications, readers, pending) = planned(owner, &members, previous)?;
    require(pending.is_none(), Failure::Ownership)?;
    let origins = origins(previous, &replications, &readers)?;
    let devices = devices(previous, &members, &origins["replication"])?;
    let mut assets = Vec::with_capacity(members.len());
    for member in &members {
        let (entry, _) = service::evidence(super::ingress::generations(
            previous,
            context,
            std::iter::once(member),
        ))?;
        assets.push(entry);
    }
    let tolerations = service::creation_tolerations(previous, &service_origins)?;
    let mut recipe = recipe(
        context,
        owner,
        operation,
        registry,
        &members,
        &devices,
        &assets,
        &reader,
        &json!(tolerations),
        stage,
        &origins,
    )?;
    recipe["first_server"] = first.clone();
    Ok(Some((recipe, replications)))
}

fn fits(request: &Value, attempt: &str, count: usize, recipe: &Value) -> Result<()> {
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let members = recipe["members"].as_array().ok_or(Failure::Integrity)?;
    let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
    let wide = "f".repeat(128);
    let device = "AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA-AAAAAAA";
    let mut full = recipe.clone();
    full["devices"] = json!(
        members
            .iter()
            .map(|m| json!({"member":m["member"],"device_id":device}))
            .collect::<Vec<_>>()
    );
    let expected = json!({"objects":[wide, wide],"device":device,"writer_generation":u64::MAX});
    let resource = resources
        .iter()
        .max_by_key(|r| canonical(r).map_or(0, |b| b.len()))
        .ok_or(Failure::Integrity)?;
    for (index, member) in members.iter().enumerate() {
        let mut binding = network::read_binding(request, attempt, last, index)?;
        binding["receiver_generation"] = json!(u64::MAX);
        let header = json!({"protocol":FAMILY.protocol,"version":FAMILY.version,
            "action":"configure-replication","request_id":fresh()?,"binding":binding,
            "remaining_ms":7_200_000,"wait_ms":7_200_000,"recipe":full,"expected":expected,
            "resource":resource,"preflight":null,"member":member["member"]});
        require(
            canonical(&header)?
                .len()
                .checked_add(17 + FAMILY.reserve)
                .is_some_and(|n| n <= 65_536),
            Failure::Bound,
        )?;
    }
    let mut binding = network::read_binding(request, attempt, last, 0)?;
    binding["receiver_generation"] = json!(u64::MAX);
    let terminal = json!({"schema":1,"kind":"terminal","binding":binding,
        "action":action("configure-replication"),"payload_sha256":"0".repeat(64),
        "outcome":"succeeded","failure":"unsupported-version","effect":"complete",
        "writer_ended":true,"resource":resource,"resource_identity":[u64::MAX, u64::MAX],
        "completed_ms":u64::MAX});
    let completion = json!({"completion":100,"need_bytes":u64::MAX,"need_items":u64::MAX,
        "need_deletes":u64::MAX});
    let facts = json!({"record":"owned-drifted","service":"unobservable","device_id":device,
        "configuration":"differs","folder":"receiveonly","state":"local-changes",
        "completion":100,"need_bytes":u64::MAX,"need_items":u64::MAX,"need_deletes":u64::MAX,
        "local_changes":u64::MAX,"peers_connected":u64::MAX,"peers_expected":u64::MAX,
        "bytes_received":u64::MAX,"bytes_sent":u64::MAX,"peer_completion":completion});
    let host = json!({"kind":"result","status":"unsupported-version","terminal":terminal,
        "replication":facts,"objects":null,"readers":null,"tokens":null,"writer":null,"node":null,
        "cordoned":null,"failure":"unsupported-version"});
    let pods: Vec<Value> = members
        .iter()
        .map(|m| json!({"member":m["member"],"pod":"f".repeat(63),"ready":false}))
        .collect();
    let nodes: Vec<Value> = members
        .iter()
        .map(|m| json!({"member":m["member"],"node":"unobservable"}))
        .collect();
    let object = json!({"kind":"DaemonSet","namespace":"broil-registry","name":READER,
        "uid":wide,"class":"owned-drifted"});
    let api = json!({"kind":"result","status":"unsupported-version","terminal":null,
        "replication":null,"objects":[object, object],"readers":pods,"tokens":pods,
        "writer":{"class":"unobservable","uid":wide,"generation":u64::MAX,
            "process":{"state":"not-ready","node":wide}},
        "node":nodes,"cordoned":null,"failure":"unsupported-version"});
    for reply in [host, api] {
        require(canonical(&reply)?.len() <= FAMILY.reserve, Failure::Bound)?;
    }
    Ok(())
}

async fn admission_reads(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    cleanup: &mut bool,
) -> Result<(Vec<Value>, Value)> {
    let binding = |index| network::read_binding(request, attempt, last, index);
    let objects = origin_uids(recipe);
    let members = recipe["members"].as_array().ok_or(Failure::Integrity)?;
    let mut hosts = Vec::with_capacity(members.len());
    for index in 0..members.len() {
        hosts.push(
            service::admission_read(
                context,
                &FAMILY,
                shape,
                &binding(index)?,
                "inspect-replication",
                &read_payload(recipe, Some(index), &objects),
                cleanup,
            )
            .await?,
        );
    }
    let api = service::admission_read(
        context,
        &FAMILY,
        shape,
        &binding(service::first_server(request)?)?,
        "inspect-objects",
        &read_payload(recipe, None, &objects),
        cleanup,
    )
    .await?;
    Ok((hosts, api))
}

type Admitted<'a> = (Box<Session<'a>>, Value, Vec<Value>, bool);

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Admitted<'a>> {
    let context = rpc::Context::new(project, policy, target)?;
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let declaration = context.selected.declaration;
    let (registry, _, _, _, _) = token::gates(
        &project.broil_root,
        declaration.registry.as_ref(),
        &declaration.infrastructure,
        &context.selected.registries,
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
        let replicas = service::established(&owner, &registry, &members)?;
        for snapshot in &previous {
            super::session::settled(&super::report::report(&context.scope, "show",
                std::slice::from_ref(snapshot))?)?;
        }
        service::storage_origins(&previous, &replicas)?;
        let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
        let services: Vec<Value> = (1..=5)
            .map(|n| resources.iter().find(|r| r["id"] == format!("registry-service-object-{n:02}")
                && r["uid"].is_string()).cloned().ok_or(Failure::Readiness))
            .collect::<Result<_>>()?;
        let service_origins = endpoint::prerequisite(service::object_origins(&previous, &services))?;
        require(service_origins["objects"].as_array()
            .is_some_and(|o| o.iter().all(Value::is_object)), Failure::Readiness)?;
        let reader = reader(&previous, &owner, &services[2])?;
        let (replications, readers, pending_owner) = planned(&owner, &members, &previous)?;
        let origins = origins(&previous, &replications, &readers)?;
        let devices = devices(&previous, &members, &origins["replication"])?;
        let mut assets = Vec::with_capacity(members.len());
        for member in &members {
            let (entry, _) = service::evidence(super::ingress::generations(&previous, &context,
                std::iter::once(member)))?;
            assets.push(entry);
        }
        let tolerations = service::creation_tolerations(&previous, &service_origins)?;
        let stale = reader_stale(&previous, &reader)?;
        context.authenticate_owned(&Value::Array(members.clone())).await?;
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let participants = super::participants(&Value::Array(members.clone()))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let held = vec![pending_owner.is_none(); members.len()];
        let build = |stage: &str| recipe(&context, &current_owner, &operation, &registry, &members,
            &devices, &assets, &reader, &json!(tolerations), stage, &origins);
        let guess = build(if origins["objects"].is_null() { "create" } else { "observe" })?;
        let created = now()?;
        let held_resources: Vec<Value> = replicas.iter().chain(&replications).chain(&readers)
            .cloned().collect();
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-registry-replication",
            "members":members,"cluster":current_owner["cluster"],"resources":held_resources,
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let widest = replication::step_count(&members, members.len(), 0).map_err(refused)?;
        let mut cleanup = false;
        let read = admission_reads(&context, &request, &attempt_id, widest as u64, &guess, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        let (hosts, api) = read?;
        let facts = stage_facts(&guess, &hosts, &api, &held, stale);
        let stage = replication::stage(&facts).map_err(refused)?;
        require(pending_owner.is_none() || stage == "create", Failure::Ownership)?;
        let effects = replication::effects(&facts).map_err(refused)?;
        let replication_recipe = build(stage)?;
        let count = replication::step_count(&members, members.len(), effects.len()).map_err(refused)?;
        fits(&request, &attempt_id, count, &replication_recipe)?;
        let mut cleanup = false;
        let checked = network::membership_reads(&context, &request, &attempt_id, count as u64,
            &source_events, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_registry_replication(successor)).await?;
            let appended: Vec<Value> = replications.iter().chain(&readers).cloned().collect();
            require(local.snapshot()?.owner["resources"].as_array().is_some_and(|resources|
                resources.ends_with(&appended)), Failure::Ownership)?;
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
        for event in std::iter::once(json!({"type":"replication-recipe","recipe":replication_recipe}))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members, attempt_id, replication_recipe, effects, stale))
    }.await;
    let (members, attempt_id, recipe, effects, stale) = match prepared {
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
        recipe,
        effects,
        stale,
    ))
}

impl Session<'_> {
    fn read_sequence(&self, step: &Value) -> Result<Value> {
        self.local
            .snapshot()?
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["attempt"] == step["attempt"]
                    && o["step"] == step["step"]
                    && o["event"]["type"] == OBSERVATION
            })
            .map(|o| o["sequence"].clone())
            .ok_or(Failure::Integrity)
    }

    async fn replication_reads(
        &mut self,
        recipe: &Value,
        refs: &[Value],
        objects: &Value,
    ) -> Result<(Vec<Value>, Value)> {
        let mut hosts = Vec::with_capacity(self.members.len());
        for index in 0..self.members.len() {
            let payload = read_payload(recipe, Some(index), objects);
            hosts.push(
                self.family_step(index, "inspect-replication", payload, refs.to_vec())
                    .await?
                    .1,
            );
        }
        let first = service::first_server(&self.local.snapshot()?.request)?;
        let payload = read_payload(recipe, None, objects);
        let api = self
            .family_step(first, "inspect-objects", payload, refs.to_vec())
            .await?
            .1;
        Ok((hosts, api))
    }

    async fn replication_effect(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        refs: &[Value],
    ) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let mut refs = refs.to_vec();
        refs.push(network::latest_sequence(snapshot, "server-membership")?);
        if self.members.iter().any(|member| member["role"] == "agent") {
            refs.push(network::latest_sequence(snapshot, "agent-membership")?);
        }
        refs.sort_by_key(Value::as_u64);
        refs.dedup();
        self.family_step(index, tag, payload, refs).await
    }

    async fn replication_run(
        &mut self,
        recipe: Value,
        effects: Vec<Value>,
        stale: bool,
    ) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, "replication-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let resources = request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let m = self.members.len();
        require(resources.len() == 2 * m + 2, Failure::Integrity)?;
        let held = vec![true; m];
        let mut objects = origin_uids(&recipe);
        let mut filled = vec![Value::Null; m];
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
        let admitted = |hosts: &[Value], api: &Value| -> Result<()> {
            let facts = stage_facts(&recipe, hosts, api, &held, stale);
            let stage = replication::stage(&facts).map_err(refused)?;
            let now = replication::effects(&facts).map_err(refused)?;
            require(
                stage == recipe["stage"] && now == effects,
                Failure::Ownership,
            )
        };
        self.network_source_gate().await?;
        let (hosts, api) = self.replication_reads(&recipe, &refs, &objects).await?;
        admitted(&hosts, &api)?;
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
        let (hosts, api) = self.replication_reads(&recipe, &refs, &objects).await?;
        admitted(&hosts, &api)?;
        let first = service::first_server(&request)?;
        for effect in &effects {
            let tag = effect["action"].as_str().ok_or(Failure::Integrity)?;
            let current = effective(&recipe, &filled);
            let wait = wait_ms(tag, &request);
            if host(tag) {
                let index = self
                    .members
                    .iter()
                    .position(|m| m["member"] == effect["subject"])
                    .ok_or(Failure::Integrity)?;
                let resource = if tag == "create-replica" {
                    resources[index].clone()
                } else {
                    resources[m + index].clone()
                };
                let payload = json!({"recipe":current,"expected":expected(&objects),
                    "resource":resource,"preflight":null,"wait_ms":wait,
                    "member":self.members[index]["member"]});
                let (step, _) = self.replication_effect(index, tag, payload, &refs).await?;
                let receipt = self
                    .inspect_step(index, "dispatch", step["dispatch"].clone(), Value::Null)
                    .await?;
                require(receipt["status"] == "ok", Failure::Ownership)?;
                let payload = read_payload(&current, Some(index), &objects);
                let (read_step, read) = self
                    .family_step(index, "inspect-replication", payload, refs.clone())
                    .await?;
                if tag == "create-replication" {
                    let facts = &read["replication"];
                    require(
                        facts["record"] == "owned" && facts["device_id"].is_string(),
                        Failure::Ownership,
                    )?;
                    filled[index] = facts["device_id"].clone();
                    refs.push(self.read_sequence(&read_step)?);
                }
            } else {
                let n = replication::OBJECTS
                    .iter()
                    .position(|id| effect["subject"] == *id)
                    .ok_or(Failure::Integrity)?;
                let resource = resources[2 * m + n].clone();
                let payload = json!({"recipe":current,"expected":expected(&objects),
                    "resource":resource,"preflight":null,"wait_ms":wait,"member":null});
                let (step, created) = self.replication_effect(first, tag, payload, &refs).await?;
                let receipt = self
                    .inspect_step(first, "dispatch", step["dispatch"].clone(), Value::Null)
                    .await?;
                require(receipt["status"] == "ok", Failure::Ownership)?;
                if tag != "create-object" {
                    let payload = read_payload(&current, None, &objects);
                    self.family_step(first, "inspect-objects", payload, refs.clone())
                        .await?;
                    continue;
                }
                let identity = created["terminal"]["resource_identity"].clone();
                require(
                    identity.as_str().is_some_and(protocol::opaque),
                    Failure::Ownership,
                )?;
                objects[n] = identity.clone();
                refs.push(
                    issuer::recorded(self.local.snapshot()?, &step, "receiver")?["sequence"]
                        .clone(),
                );
                let payload = read_payload(&current, None, &objects);
                let read = self
                    .family_step(first, "inspect-objects", payload, refs.clone())
                    .await?
                    .1;
                let object = &read["objects"][n];
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
        let current = effective(&recipe, &filled);
        let (hosts, api) = self.replication_reads(&current, &refs, &objects).await?;
        require(
            hosts
                .iter()
                .all(|h| h["replication"]["record"] != "unobservable")
                && api["objects"]
                    .as_array()
                    .is_some_and(|o| o.iter().all(|o| o["class"] != "unobservable")),
            Failure::Readiness,
        )?;
        require(
            hosts.iter().all(|h| {
                h["replication"]["record"] == "owned"
                    && h["replication"]["configuration"] == "owned"
            }) && api["objects"]
                .as_array()
                .is_some_and(|o| o.len() == 2 && o.iter().all(|o| o["class"] == "owned")),
            Failure::Ownership,
        )?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let (mut session, recipe, effects, stale) = begin(project, policy, target).await?;
    let result = Box::pin(session.replication_run(recipe, effects, stale)).await;
    session.local.complete(result, &session.context.clock).await
}
