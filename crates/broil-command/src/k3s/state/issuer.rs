// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::network::{self, Family};
use super::provenance::undispatched_transport;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{ADAPTER, CERT_MANAGER, PROFILE, protocol};
use broil_config::LoadedProject;
use broil_core::k3s::Issuer;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "issuer",
    protocol: "broil-k3s-issuer",
    magic: b"BK3SISS1\n",
    header: "IssuerHeader",
    result: "IssuerResult",
    body: CERT_MANAGER,
    planned: 1,
    reserve: 8_192,
    version: 1,
};

pub(super) struct Lifecycle {
    pub(super) family: &'static Family,
    pub(super) consumer: &'static str,
    pub(super) wrapper: Option<&'static str>,
    pub(super) facts: &'static [&'static str],
}

impl Lifecycle {
    pub(super) fn action(&self, tag: &str) -> String {
        format!("lifecycle:{}-{tag}", self.family.name)
    }

    pub(super) fn event(&self, kind: &str) -> String {
        format!("{}-{kind}", self.family.name)
    }

    pub(super) fn registration<'v>(&self, event: &'v Value) -> &'v Value {
        self.wrapper
            .map_or(&event["registration"], |fact| &event[fact]["registration"])
    }
}

pub(super) const LIFECYCLE: Lifecycle = Lifecycle {
    family: &FAMILY,
    consumer: "supply-issuer-ca",
    wrapper: Some("issuer"),
    facts: &["issuer"],
};

pub(super) const ANCHOR: &str = "cert-manager-object-01";

pub(super) fn action(tag: &str) -> String {
    format!("lifecycle:issuer-{tag}")
}

pub(super) fn acme(issuer: &Issuer) -> bool {
    matches!(issuer, Issuer::AcmeHttp01 { .. })
}

pub(super) fn acme_gate(issuers: &BTreeMap<String, Issuer>) -> Result<()> {
    require(!issuers.values().any(acme), Failure::Capability)
}

fn name40(value: &Value) -> Result<String> {
    Ok(protocol::digest(&canonical(value)?)[..40].to_owned())
}

pub(super) fn secret_name(owner: &Value, resource: &Value) -> Result<String> {
    let identity =
        json!({"kind":resource["kind"],"id":resource["id"],"generation":resource["generation"]});
    Ok(format!(
        "broil-input-{}",
        name40(&json!([owner, identity]))?
    ))
}

pub(super) fn cluster_issuer_name(owner: &Value, id: &Value) -> Result<String> {
    Ok(format!(
        "broil-issuer-{}",
        name40(&json!([owner, {"kind":"issuer","id":id}]))?
    ))
}

pub(super) fn resource_id(issuer: &str) -> Result<String> {
    let id = format!("issuer-object-{issuer}");
    require(id.len() <= 128, Failure::Bound)?;
    require(protocol::opaque(&id), Failure::Configuration)?;
    Ok(id)
}

pub(super) fn projection(
    request: &Value,
    issuer: &str,
    operation: &Value,
    attempt: &Value,
    resource: &Value,
) -> Result<Value> {
    let declared = &request["config"]["target"]["infrastructure"]["issuers"][issuer];
    require(declared["kind"] == "private-ca", Failure::Configuration)?;
    let selectors = json!({"issuer":issuer,"service":null,"origin":null});
    let references = json!([declared["certificate"], declared["key"]]);
    secret_projection(
        request,
        (operation, attempt, resource),
        selectors,
        references,
    )
}

pub(super) fn secret_projection(
    request: &Value,
    (operation, attempt, resource): (&Value, &Value, &Value),
    selectors: Value,
    references: Value,
) -> Result<Value> {
    let config = &request["config"];
    let first = &request["members"][0];
    let machine = first["machine"].as_str().ok_or(Failure::Integrity)?;
    let mut script = config["scripts"][machine]
        .as_object()
        .cloned()
        .ok_or(Failure::Integrity)?;
    script.remove("name");
    script.remove("pty");
    let mut scripts = serde_json::Map::new();
    scripts.insert(machine.into(), Value::Object(script));
    let scope = &request["scope"];
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    let mut binding = json!({"project":scope["project"],"environment":scope["environment"],
        "target":scope["target"],"owner":request["owner"],"operation":operation,"attempt":attempt,
        "source":null,"destination":{"machine":first["machine"],"member":first["member"],
            "role":first["role"],"node_uid":first["node_uid"]},
        "cluster":request["cluster"],"resource":{"kind":resource["kind"],"id":resource["id"],
            "generation":resource["generation"],"uid":resource["uid"]},
        "profile_sha256":protocol::digest(PROFILE),"script_sha256":protocol::digest(ADAPTER),
        "principal":null,"recovery":null});
    for (key, value) in selectors.as_object().ok_or(Failure::Integrity)? {
        binding[key] = value.clone();
    }
    Ok(
        json!({"schema":1,"binding":binding,"declaration":config["target"],
        "scripts":scripts,"registries":config["registries"],"secrets":config["secrets"],
        "references":references,"profile":profile}),
    )
}

pub(super) fn record_sha256(directory: &Value, projection: &Value) -> Result<String> {
    Ok(protocol::digest(&canonical(
        &json!({"schema":1,"directory":directory,"projection":projection,
            "inactive":true,"registration_pending":false}),
    )?))
}

pub(super) fn stage(origins: &Value) -> Result<&'static str> {
    let set = |key: &str| !origins[key].is_null();
    match (
        set("secret"),
        set("registration"),
        set("supply"),
        set("activation"),
        set("cluster_issuer"),
    ) {
        (false, false, false, false, false) => Ok("create"),
        (true, true, false, false, false) => Ok("supply"),
        (true, true, true, false, false) => Ok("activate"),
        (true, true, true, true, false) => Ok("finish-activation"),
        (true, true, true, true, true) => Ok("observe"),
        _ => Err(Failure::Ownership),
    }
}

pub(super) fn effects(stage: &str) -> usize {
    match stage {
        "create" | "activate" => 2,
        "finish-activation" => 1,
        _ => 0,
    }
}

pub(super) fn step_count(members: &[Value], effects: usize) -> Result<usize> {
    let servers = members.iter().filter(|m| m["role"] == "server").count();
    let agents = usize::from(members.iter().any(|m| m["role"] == "agent"));
    members
        .len()
        .checked_mul(6)
        .and_then(|n| n.checked_add(servers.checked_mul(2)?))
        .and_then(|n| n.checked_add(agents * 2 + effects * 3 + 3))
        .filter(|n| *n <= 1024)
        .ok_or(Failure::Bound)
}

pub(super) fn budget(step: u64, script: u64, remaining: u64) -> Result<()> {
    require(step.min(script).min(remaining) >= 60, Failure::Bound)
}

pub(super) fn confirms(stage: &str, reply: &Value) -> Result<()> {
    let class = |value: &Value| value["class"].as_str().unwrap_or("").to_owned();
    let (secret, cluster) = (&reply["objects"][0], &reply["objects"][1]);
    let registration = class(&reply["issuer"]["registration"]);
    let classes = [class(secret), class(cluster), registration.clone()];
    require(
        !classes
            .iter()
            .any(|c| c == "foreign" || c == "owned-drifted"),
        Failure::Ownership,
    )?;
    require(
        !classes.iter().any(|c| c == "unobservable"),
        Failure::Readiness,
    )?;
    let owned = |activation: &str| secret["class"] == "owned" && secret["activation"] == activation;
    require(
        match stage {
            "create" => {
                secret["class"] == "absent"
                    && registration == "absent"
                    && cluster["class"] == "absent"
            }
            "activate" => {
                owned("inactive") && registration == "present" && cluster["class"] == "absent"
            }
            "finish-activation" => {
                owned("active") && registration == "present" && cluster["class"] == "absent"
            }
            "observe" => owned("active") && cluster["class"] == "owned",
            _ => false,
        },
        Failure::Ownership,
    )
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let read = tag == "inspect-objects";
    require(
        result["objects"].is_null() != (read || tag == "create-issuer")
            && result["issuer"].is_null() != (read || tag == "register-input")
            && result["services"].is_null() != read
            && result["terminal"].is_null() == read,
        Failure::Integrity,
    )
}

pub(super) fn conclusive(
    result: &Value,
    transport: &Value,
    binding: &Value,
    step: &Value,
    resource: &Value,
) -> bool {
    let receipt = &result["terminal"];
    result["status"] == "failed"
        && result["failure"] == "readiness"
        && receipt["binding"] == *binding
        && receipt["action"] == step["action"]
        && receipt["payload_sha256"] == step["payload_sha256"]
        && receipt["outcome"] == "failed"
        && receipt["effect"] == "absent"
        && receipt["failure"] == "readiness"
        && receipt["writer_ended"] == true
        && receipt["resource"] == *resource
        && receipt["resource_identity"].is_null()
        && transport["exit"] == 0
        && transport["signal"].is_null()
        && transport["input_released"] == true
        && transport["staging_cleanup"] == "clean"
}

pub(super) fn expected(recipe: &Value) -> Value {
    let registration = &recipe["origins"]["registration"];
    json!({"secret":recipe["resource"]["uid"],
        "cluster_issuer":recipe["origins"]["cluster_issuer"]["uid"],
        "registration":if registration.is_null() {Value::Null} else {
            json!({"directory":registration["directory"],"record_sha256":registration["record_sha256"]})}})
}

fn recipe_of<'s>(lifecycle: &Lifecycle, snapshot: &'s Snapshot) -> Result<&'s Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == lifecycle.event("recipe"))
        .map(|o| &o["event"]["recipe"])
        .ok_or(Failure::Integrity)
}

pub(super) fn recorded<'s>(snapshot: &'s Snapshot, step: &Value, kind: &str) -> Result<&'s Value> {
    snapshot
        .observations
        .iter()
        .find(|o| {
            o["attempt"] == step["attempt"]
                && o["step"] == step["step"]
                && o["event"]["type"] == kind
        })
        .ok_or(Failure::Ownership)
}

fn reads_after<'s>(
    lifecycle: &Lifecycle,
    snapshot: &'s Snapshot,
    sequence: &Value,
) -> impl Iterator<Item = &'s Value> {
    let after = sequence.as_u64().unwrap_or(u64::MAX);
    let kind = lifecycle.event("observation");
    snapshot.observations.iter().filter(move |o| {
        o["event"]["type"] == kind.as_str()
            && !o["event"]["services"].is_null()
            && o["sequence"].as_u64().is_some_and(|s| s > after)
    })
}

pub(super) fn origins(
    previous: &[Snapshot],
    issuer: &str,
    resource: &Value,
    succeeded_supply: &dyn Fn(&Snapshot) -> bool,
) -> Result<Value> {
    let reproduce = |request: &Value, attempt: &Value| {
        projection(request, issuer, &request["operation"], attempt, resource)
    };
    secret_origins(&LIFECYCLE, previous, resource, succeeded_supply, &reproduce)
}

pub(super) fn secret_origins(
    lifecycle: &Lifecycle,
    previous: &[Snapshot],
    resource: &Value,
    succeeded_supply: &dyn Fn(&Snapshot) -> bool,
    reproduce: &dyn Fn(&Value, &Value) -> Result<Value>,
) -> Result<Value> {
    let (uid, label) = (
        &resource["uid"],
        format!("broil-k3s-{}-recipe-v1", lifecycle.family.name),
    );
    let mine: Vec<&Snapshot> = previous
        .iter()
        .filter(|s| {
            s.request["action"] == format!("reconcile-{}", lifecycle.family.name)
                && s.request["resources"][0]["id"] == resource["id"]
                && s.request["resources"][0]["generation"] == resource["generation"]
        })
        .collect();
    let succeeded = |snapshot: &Snapshot, tag: &str| -> Vec<Value> {
        snapshot
            .steps
            .iter()
            .filter(|s| s["action"] == lifecycle.action(tag) && snapshot.succeeded(s))
            .cloned()
            .collect()
    };
    let creates: Vec<&&Snapshot> = mine
        .iter()
        .filter(|s| !succeeded(s, "create-object").is_empty())
        .collect();
    require(creates.len() <= 1, Failure::Ownership)?;
    let (mut secret, mut registration) = (Value::Null, Value::Null);
    if let Some(snapshot) = creates.first() {
        let created = succeeded(snapshot, "create-object");
        let step = &created[0];
        let receipt = recorded(snapshot, step, "receiver")?;
        let identity = snapshot.observations.iter().any(|o| {
            o["event"]["type"] == "identity"
                && o["event"]["resources"][0]["id"] == resource["id"]
                && o["event"]["resources"][0]["uid"] == *uid
        });
        let read = reads_after(lifecycle, snapshot, &receipt["sequence"]).any(|o| {
            o["event"]["objects"][0]["class"] == "owned" && o["event"]["objects"][0]["uid"] == *uid
        });
        require(
            uid.is_string()
                && receipt["event"]["receipt"]["resource_identity"] == *uid
                && identity
                && read,
            Failure::Ownership,
        )?;
        secret = json!({"operation":snapshot.request["operation"],
            "recipe_sha256":hash(&label, recipe_of(lifecycle, snapshot)?)?});
        if let Some(step) = succeeded(snapshot, "register-input").first() {
            let reply = recorded(snapshot, step, &lifecycle.event("observation"))?;
            let fact = lifecycle.registration(&reply["event"]);
            let projection = reproduce(&snapshot.request, &step["attempt"])?;
            let confirmed = reads_after(lifecycle, snapshot, &reply["sequence"])
                .any(|o| lifecycle.registration(&o["event"]) == fact);
            require(
                fact["class"] == "present"
                    && record_sha256(&fact["directory"], &projection)? == fact["record_sha256"]
                    && confirmed,
                Failure::Ownership,
            )?;
            registration = json!({"operation":snapshot.request["operation"],
                "attempt":step["attempt"],"directory":fact["directory"],
                "record_sha256":fact["record_sha256"]});
        }
    } else {
        require(uid.is_null(), Failure::Ownership)?;
    }
    let supplies: Vec<&Snapshot> = previous
        .iter()
        .filter(|s| {
            s.request["action"] == "prepare-state"
                && s.request["consumer"]["action"] == lifecycle.consumer
                && s.request["resources"] == json!([resource])
                && succeeded_supply(s)
        })
        .collect();
    require(supplies.len() <= 1, Failure::Ownership)?;
    let supply = supplies
        .first()
        .map_or(Value::Null, |s| json!({"operation":s.request["operation"]}));
    let activations: Vec<(&Snapshot, Value)> = mine
        .iter()
        .flat_map(|s| {
            succeeded(s, "activate")
                .into_iter()
                .map(move |step| (*s, step))
        })
        .collect();
    require(activations.len() <= 1, Failure::Ownership)?;
    let mut activation = Value::Null;
    if let Some((snapshot, step)) = activations.first() {
        let receipt = recorded(snapshot, step, "receiver")?;
        let active = reads_after(lifecycle, snapshot, &receipt["sequence"])
            .any(|o| o["event"]["objects"][0]["activation"] == "active");
        require(
            receipt["event"]["receipt"]["resource_identity"] == *uid && active,
            Failure::Ownership,
        )?;
        activation = json!({"operation":snapshot.request["operation"]});
    }
    let creations: Vec<(&Snapshot, Value)> = mine
        .iter()
        .flat_map(|s| {
            succeeded(s, "create-issuer")
                .into_iter()
                .map(move |step| (*s, step))
        })
        .collect();
    require(creations.len() <= 1, Failure::Ownership)?;
    let mut cluster_issuer = Value::Null;
    if let Some((snapshot, step)) = creations.first() {
        let reply = recorded(snapshot, step, "issuer-observation")?;
        let record = &reply["event"]["objects"][0];
        let bound = reads_after(lifecycle, snapshot, &reply["sequence"])
            .any(|o| binds(record, &o["event"]));
        require(record["uid"].is_string() && bound, Failure::Ownership)?;
        cluster_issuer = json!({"operation":snapshot.request["operation"],
            "recipe_sha256":hash(&label, recipe_of(lifecycle, snapshot)?)?,
            "uid":record["uid"]});
    }
    let mut origins = json!({"secret":secret,"registration":registration,"supply":supply,
        "activation":activation});
    if lifecycle.family.name == "issuer" {
        origins["cluster_issuer"] = cluster_issuer;
    }
    Ok(origins)
}

pub(super) fn binds(record: &Value, read: &Value) -> bool {
    ["kind", "namespace", "name", "uid", "class", "spec_sha256"]
        .iter()
        .all(|key| read["objects"][1][*key] == record[*key])
}

fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    issuer: &str,
    resource: &Value,
    stage: &str,
    origins: &Value,
) -> Result<Value> {
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let anchor = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == ANCHOR)
        .ok_or(Failure::Ownership)?;
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"first_server":members.first().ok_or(Failure::Integrity)?,
        "anchor_uid":anchor["uid"],"version":context.selected.declaration.version,
        "issuer":issuer,"resource":resource,
        "cluster_issuer_name":cluster_issuer_name(&owner["owner"], &resource["id"])?,
        "stage":stage,"origins":origins,"profile_sha256":context.fingerprints["profile_sha256"]});
    schema::validate(&canonical(&recipe)?, "IssuerRecipe", 32_768)?;
    Ok(recipe)
}

pub(super) fn prepared_projection(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    attempt: &str,
    resource: &Value,
    consumer: crate::k3s::Operation,
) -> Result<Value> {
    let p = &context.policy;
    let policy = crate::k3s::Policy {
        environment: p.environment.clone(),
        cwd: p.cwd.clone(),
        environment_snapshot: p.environment_snapshot.clone(),
        credentials: p
            .credentials
            .try_duplicate()
            .map_err(|_| Failure::Credential)?,
        non_interactive: p.non_interactive,
        deadline: context.clock.deadline(),
        cancellation: p.cancellation.clone(),
    };
    let text = |value: &Value| -> Result<String> {
        Ok(value.as_str().ok_or(Failure::Integrity)?.to_owned())
    };
    let first = &super::acting_server(owner)?;
    let generation = crate::k3s::Generation {
        owner: text(&owner["owner"])?,
        operation: operation.into(),
        attempt: attempt.into(),
        resource: text(&resource["id"])?,
        generation: text(&resource["generation"])?,
        resource_uid: resource["uid"].as_str().map(str::to_owned),
        cluster: Some(crate::k3s::Cluster {
            uid: text(&owner["cluster"]["uid"])?,
            ca_sha256: text(&owner["cluster"]["ca_sha256"])?,
        }),
        destination_uid: first["node_uid"].as_str().map(str::to_owned),
        source_uid: None,
    };
    let prepared = crate::k3s::prepare(
        context.project,
        policy,
        &text(&context.scope["target"])?,
        &text(&first["machine"])?,
        generation,
        consumer,
    )
    .map_err(|_| Failure::Configuration)?;
    Ok(prepared.projection().clone())
}

fn fits(
    request: &Value,
    attempt: &str,
    count: usize,
    recipe: &Value,
    projection: &Value,
) -> Result<()> {
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let mut binding = network::read_binding(request, attempt, last, 0)?;
    binding["receiver_generation"] = json!(u64::MAX);
    let wide = "f".repeat(128);
    let record = json!({"kind":"ClusterIssuer","namespace":"cert-manager","name":"f".repeat(53),
        "uid":wide,"class":"owned-drifted","activation":"inactive","spec_sha256":"0".repeat(64)});
    let registration = json!({"directory":[u64::MAX,u64::MAX],"record_sha256":"0".repeat(64)});
    let preflight = json!({"objects":[record,record],"issuer":{"registration":{"class":"present",
        "directory":[u64::MAX,u64::MAX],"record_sha256":"0".repeat(64)},
        "ready":{"state":"not-ready","reason":"unobservable"}}});
    let header = json!({"protocol":FAMILY.protocol,"version":1,"action":"register-input",
        "request_id":fresh()?,"binding":binding,"remaining_ms":7_200_000,"recipe":recipe,
        "expected":{"secret":wide,"cluster_issuer":wide,"registration":registration},
        "resource":request["resources"][0],"preflight":preflight,"projection":projection});
    require(
        canonical(&header)?
            .len()
            .checked_add(17 + FAMILY.reserve)
            .is_some_and(|n| n <= 65_536),
        Failure::Bound,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn preflight(
    family: &Family,
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    expected: Value,
    stage: &str,
    confirms: fn(&str, &Value) -> Result<()>,
    source_events: &[Value],
    cleanup: &mut bool,
) -> Result<()> {
    let payload = json!({"recipe":recipe,"expected":expected,"resource":null,
        "preflight":null,"projection":null});
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
    );
    let observed = network::invoke(
        context,
        family,
        &network::read_binding(request, attempt, last, 0)?,
        "inspect-objects",
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
    confirms(stage, &result)?;
    network::membership_reads(context, request, attempt, last, source_events, cleanup).await
}

pub(super) fn prerequisites(scope: &Value, previous: &[Snapshot], owner: &Value) -> Result<()> {
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    let bound = |prefix: &str| {
        resources
            .iter()
            .filter(|r| {
                r["id"].as_str().is_some_and(|id| id.starts_with(prefix)) && r["uid"].is_string()
            })
            .count()
    };
    require(
        bound("network-object-") == 12 && bound(ANCHOR) == 1,
        Failure::Ownership,
    )?;
    let latest = previous
        .iter()
        .filter(|s| s.request["action"] == "reconcile-cert-manager")
        .max_by_key(|s| s.request["created_ms"].as_u64())
        .ok_or(Failure::Readiness)?;
    let report = super::report::report(scope, "show", std::slice::from_ref(latest))?;
    require(
        report["readiness"]["services"] == "unobserved",
        Failure::Readiness,
    )
}

fn planned(owner: &Value, issuer: &str) -> Result<(Value, Option<Value>)> {
    planned_secret(owner, &resource_id(issuer)?, "issuer", "cert-manager")
}

pub(super) fn planned_secret(
    owner: &Value,
    id: &str,
    kind: &str,
    namespace: &str,
) -> Result<(Value, Option<Value>)> {
    let acting = super::acting_server(owner)?;
    let first = &acting["machine"];
    let existing: Vec<&Value> = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| r["id"] == id)
        .collect();
    require(existing.len() <= 1, Failure::Ownership)?;
    if let Some(resource) = existing.first() {
        require(
            resource["kind"] == kind
                && resource["owner"] == owner["owner"]
                && resource["machine"] == *first
                && resource["path"].is_null()
                && resource["namespace"] == namespace
                && resource["name"] == json!(secret_name(&owner["owner"], resource)?),
            Failure::Ownership,
        )?;
        return Ok(((*resource).clone(), None));
    }
    let mut resource = json!({"kind":kind,"id":id,"owner":owner["owner"],
        "generation":fresh()?,"machine":first,"path":null,"namespace":namespace,
        "name":null,"uid":null});
    resource["name"] = json!(secret_name(&owner["owner"], &resource)?);
    let mut successor = owner.clone();
    successor["previous_generation"] = successor["generation"].clone();
    successor["generation"] = json!(fresh()?);
    successor["created_ms"] = json!(now()?);
    successor["resources"]
        .as_array_mut()
        .ok_or(Failure::Integrity)?
        .push(resource.clone());
    Ok((resource, Some(successor)))
}

pub(super) enum Begun<'a> {
    Request(Box<Session<'a>>, Value, &'static str),
    Supply(Value),
    Done,
}

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
    issuer: &str,
    observe: bool,
) -> super::ExecutionResult<Begun<'a>> {
    let context = rpc::Context::new(project, policy, target)?;
    let declared = &context.selected.declaration.infrastructure.issuers;
    acme_gate(declared)?;
    require(
        matches!(declared.get(issuer), Some(Issuer::PrivateCa { .. })),
        Failure::Configuration,
    )?;
    let mut local = Local::new(&context)?;
    let prepared: Result<_> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e| e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()
                && v.iter().all(|m| m["node_uid"].is_string())), Failure::Ownership)?;
        let report = |snapshot: &Snapshot| {
            super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        };
        for snapshot in &previous {
            super::session::settled(&report(snapshot)?)?;
        }
        prerequisites(&context.scope, &previous, &owner)?;
        let (resource, pending_owner) = planned(&owner, issuer)?;
        let succeeded = |snapshot: &Snapshot| report(snapshot).is_ok_and(|r| r["outcome"] == "succeeded");
        let origins = origins(&previous, issuer, &resource, &succeeded)?;
        let stage = stage(&origins)?;
        require((stage == "create") == resource["uid"].is_null(), Failure::Ownership)?;
        if stage == "supply" {
            return Ok(Err(resource));
        }
        if stage == "observe" && !observe {
            return Ok(Err(Value::Null));
        }
        if matches!(stage, "activate" | "finish-activation") {
            let machine = owner["members"][0]["machine"].as_str().ok_or(Failure::Integrity)?;
            let target = context.inventory.machines.iter().find(|m| m.name == machine)
                .ok_or(Failure::Configuration)?;
            let script = context.inventory.scripts.get(&context.selected.declaration.lifecycle_script)
                .ok_or(Failure::Configuration)?;
            let remaining = context.clock.deadline()
                .saturating_duration_since(tokio::time::Instant::now()).as_secs();
            budget(context.selected.step_timeout.seconds,
                script.timeout.as_ref().map_or(target.timeouts.command.seconds, |d| d.seconds),
                remaining)?;
        }
        context.authenticate_owned(&json!(super::survivors(&owner)?)).await?;
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let members = super::survivors(&current_owner)?;
        let participants = super::participants(&json!(members))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let mut survivors = current_owner.clone();
        survivors["members"] = json!(members);
        let issuer_recipe = recipe(&context, &survivors, &operation, issuer, &resource, stage, &origins)?;
        let created = now()?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-issuer",
            "members":members,"cluster":current_owner["cluster"],"resources":[resource],
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let count = step_count(&members, effects(stage))?;
        let widest = if stage == "create" {
            let mut bound = resource.clone();
            bound["uid"] = json!("f".repeat(128));
            let ours = projection(&request, issuer, &json!(operation), &json!(attempt_id), &bound)?;
            let consumer = crate::k3s::Operation::Issuer { name: issuer.into() };
            require(ours == prepared_projection(&context, &current_owner, &operation, &attempt_id, &bound, consumer)?,
                Failure::Configuration)?;
            ours
        } else {
            Value::Null
        };
        fits(&request, &attempt_id, count, &issuer_recipe, &widest)?;
        let mut cleanup = false;
        let checked = preflight(&FAMILY, &context, &request, &attempt_id, count as u64,
            &issuer_recipe, expected(&issuer_recipe), stage, confirms, &source_events, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_issuer(successor)).await?;
            require(local.snapshot()?.owner["resources"].as_array()
                .is_some_and(|resources| resources.last() == Some(&resource)), Failure::Ownership)?;
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
        for event in std::iter::once(json!({"type":"issuer-recipe","recipe":issuer_recipe}))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok(Ok((members, attempt_id, issuer_recipe, stage)))
    }.await;
    let (members, attempt_id, issuer_recipe, stage) = match prepared {
        Ok(Ok(value)) => value,
        Ok(Err(resource)) => {
            local
                .finish(&context.clock)
                .await
                .map_err(|failure| super::ExecutionFailure {
                    failure,
                    completion_unknown: false,
                    cleanup_unknown: true,
                    snapshot: None,
                    detail: None,
                })?;
            return Ok(if resource.is_null() {
                Begun::Done
            } else {
                Begun::Supply(resource)
            });
        }
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
    Ok(Begun::Request(
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
        issuer_recipe,
        stage,
    ))
}

pub(super) fn resumed(
    snapshot: &Snapshot,
    steps: &[Value],
    recipe: &Value,
) -> (Value, Option<Value>) {
    let mut values = expected(recipe);
    let step = |tag: &str| steps.iter().find(|s| s["action"] == action(tag));
    let reply =
        |tag: &str| step(tag).and_then(|s| recorded(snapshot, s, "issuer-observation").ok());
    let created = step("create-object")
        .and_then(|step| recorded(snapshot, step, "receiver").ok())
        .map(|o| o["event"]["receipt"].clone())
        .filter(|r| r["outcome"] == "succeeded" && r["effect"] == "complete");
    if let Some(receipt) = &created {
        values["secret"] = receipt["resource_identity"].clone();
    }
    if let Some(reply) = reply("register-input") {
        let fact = &reply["event"]["issuer"]["registration"];
        values["registration"] =
            json!({"directory":fact["directory"],"record_sha256":fact["record_sha256"]});
    }
    if let Some(reply) = reply("create-issuer") {
        values["cluster_issuer"] = reply["event"]["objects"][0]["uid"].clone();
    }
    (values, created)
}

pub(super) type Resumed = fn(&Snapshot, &[Value], &Value) -> (Value, Option<Value>);

pub(super) async fn resume_objects(
    context: &rpc::Context<'_>,
    local: &mut Local,
    original: &Snapshot,
    recipe: &Value,
) -> Result<()> {
    resume_secret(&LIFECYCLE, context, local, original, recipe, resumed).await
}

pub(super) async fn resume_secret(
    lifecycle: &Lifecycle,
    context: &rpc::Context<'_>,
    local: &mut Local,
    original: &Snapshot,
    recipe: &Value,
    resumed: Resumed,
) -> Result<()> {
    let Some(inspect_step) = original
        .steps
        .iter()
        .rev()
        .find(|s| s["action"] == lifecycle.action("inspect-objects"))
    else {
        return Ok(());
    };
    let snapshot = local.snapshot()?.clone();
    let create = original
        .steps
        .iter()
        .find(|s| s["action"] == lifecycle.action("create-object"));
    let (values, created) = resumed(&snapshot, &original.steps, recipe);
    let payload = json!({"recipe":recipe,"expected":values,"resource":null,"preflight":null,
        "projection":null});
    let observed = network::invoke(
        context,
        lifecycle.family,
        &original.binding(inspect_step),
        "inspect-objects",
        &payload,
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
        None,
    )
    .await;
    let result = observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", super::server::refused(&result))?;
    local
        .append(
            Some(inspect_step),
            network::observation(lifecycle.family, Value::Null, &result),
            Some(&original.request["members"][0]["machine"]),
            Value::Null,
        )
        .await?;
    let (Some(step), Some(receipt)) = (create, created) else {
        return Ok(());
    };
    let uid = &receipt["resource_identity"];
    let prior = snapshot.owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == step["resource"]["id"])
        .ok_or(Failure::Ownership)?;
    if prior["uid"].is_string() {
        return require(prior["uid"] == *uid, Failure::Ownership);
    }
    require(
        result["objects"][0]["uid"] == *uid && result["objects"][0]["class"] == "owned",
        Failure::Ownership,
    )?;
    let mut published = step["resource"].clone();
    published["uid"] = uid.clone();
    local
        .append(
            Some(step),
            json!({"type":"identity","member":null,"cluster":snapshot.request["cluster"],
                "resources":[published],"readiness":super::report::readiness()}),
            None,
            Value::Null,
        )
        .await?;
    super::ingress::publish(local, &published).await
}

impl Session<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn secret_step(
        &mut self,
        tag: &str,
        recipe: &Value,
        expected: &Value,
        resource: &Value,
        preflight: Value,
        projection: Value,
        mut refs: Vec<Value>,
    ) -> Result<(Value, Value)> {
        refs.sort_by_key(Value::as_u64);
        refs.dedup();
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight,"projection":projection});
        self.family_step(0, tag, payload, refs).await
    }

    pub(super) async fn secret_read(
        &mut self,
        recipe: &Value,
        recipe_seq: &Value,
        expected: &Value,
        cited: &[Value],
    ) -> Result<Value> {
        let refs = std::iter::once(recipe_seq.clone())
            .chain(cited.iter().cloned())
            .collect();
        Ok(self
            .secret_step(
                "inspect-objects",
                recipe,
                expected,
                &Value::Null,
                Value::Null,
                Value::Null,
                refs,
            )
            .await?
            .1)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn secret_effect(
        &mut self,
        lifecycle: &Lifecycle,
        tag: &str,
        recipe: &Value,
        recipe_seq: &Value,
        expected: &Value,
        resource: &Value,
        projection: Value,
        identity: Option<Value>,
    ) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let latest = snapshot
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == lifecycle.event("observation")
                    && !o["event"]["services"].is_null()
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
        refs.extend(identity);
        let mut preflight = json!({"objects":latest["event"]["objects"]});
        for fact in lifecycle.facts {
            preflight[*fact] = latest["event"][*fact].clone();
        }
        self.secret_step(tag, recipe, expected, resource, preflight, projection, refs)
            .await
    }

    pub(super) async fn secret_receipt(&mut self, step: &Value) -> Result<Value> {
        let receipt = self
            .inspect_step(0, "dispatch", step["dispatch"].clone(), Value::Null)
            .await?;
        require(receipt["status"] == "ok", Failure::Ownership)?;
        Ok(receipt)
    }

    pub(super) fn recorded_sequence(&self, step: &Value, kind: &str) -> Result<Value> {
        Ok(recorded(self.local.snapshot()?, step, kind)?["sequence"].clone())
    }

    pub(super) async fn deselect_read(
        &mut self,
        action: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<()> {
        self.context.check()?;
        let step = self.intended(0, action, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.append(
            &step,
            json!({"type":"dispatch","transport":undispatched_transport(),"outcome":"succeeded",
                "failure":null}),
            false,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok(())
    }

    async fn issuer_run(&mut self, recipe: Value, stage: &str) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, "issuer-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let resource = request["resources"][0].clone();
        let issuer = recipe["issuer"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        let mut values = expected(&recipe);
        let mut cited: Vec<Value> = Vec::new();
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
        self.network_source_gate().await?;
        let first = self
            .secret_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms(stage, &first)?;
        for &index in &order {
            self.dispatch(
                index,
                "reserve-owner",
                json!({"members":self.members,"excluded":null,"cluster":cluster,
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
            .authenticate_owned(&Value::Array(self.members.clone()))
            .await?;
        self.network_source_gate().await?;
        let second = self
            .secret_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms(stage, &second)?;
        if stage == "create" {
            let (step, created) = self
                .secret_effect(
                    &LIFECYCLE,
                    "create-object",
                    &recipe,
                    &recipe_seq,
                    &values,
                    &resource,
                    Value::Null,
                    None,
                )
                .await?;
            let uid = created["terminal"]["resource_identity"].clone();
            require(
                uid.as_str().is_some_and(protocol::opaque),
                Failure::Ownership,
            )?;
            self.secret_receipt(&step).await?;
            values["secret"] = uid.clone();
            cited.push(self.recorded_sequence(&step, "receiver")?);
            let read = self
                .secret_read(&recipe, &recipe_seq, &values, &cited)
                .await?;
            require(
                read["objects"][0]["class"] == "owned"
                    && read["objects"][0]["uid"] == uid
                    && read["objects"][0]["activation"] == "inactive",
                Failure::Ownership,
            )?;
            let mut published = resource.clone();
            published["uid"] = uid;
            self.append(
                &step,
                json!({"type":"identity","member":null,"cluster":cluster,
                    "resources":[published],"readiness":super::report::readiness()}),
                false,
                Value::Null,
            )
            .await?;
            super::ingress::publish(&mut self.local, &published).await?;
            let identity = network::latest_sequence(self.local.snapshot()?, "identity")?;
            let projection = projection(
                &request,
                &issuer,
                &request["operation"],
                &self.attempt["attempt"],
                &published,
            )?;
            let (step, registered) = self
                .secret_effect(
                    &LIFECYCLE,
                    "register-input",
                    &recipe,
                    &recipe_seq,
                    &values,
                    &resource,
                    projection.clone(),
                    Some(identity),
                )
                .await?;
            let fact = registered["issuer"]["registration"].clone();
            require(
                fact["class"] == "present"
                    && record_sha256(&fact["directory"], &projection)? == fact["record_sha256"],
                Failure::Ownership,
            )?;
            self.secret_receipt(&step).await?;
            values["registration"] =
                json!({"directory":fact["directory"],"record_sha256":fact["record_sha256"]});
            cited.push(self.recorded_sequence(&step, "issuer-observation")?);
            let read = self
                .secret_read(&recipe, &recipe_seq, &values, &cited)
                .await?;
            require(read["issuer"]["registration"] == fact, Failure::Ownership)?;
        } else if matches!(stage, "activate" | "finish-activation") {
            if stage == "activate" {
                let (step, _) = self
                    .secret_effect(
                        &LIFECYCLE,
                        "activate",
                        &recipe,
                        &recipe_seq,
                        &values,
                        &resource,
                        Value::Null,
                        None,
                    )
                    .await?;
                self.secret_receipt(&step).await?;
                let read = self
                    .secret_read(&recipe, &recipe_seq, &values, &cited)
                    .await?;
                require(
                    read["objects"][0]["class"] == "owned"
                        && read["objects"][0]["activation"] == "active",
                    Failure::Ownership,
                )?;
            }
            let (step, created) = self
                .secret_effect(
                    &LIFECYCLE,
                    "create-issuer",
                    &recipe,
                    &recipe_seq,
                    &values,
                    &resource,
                    Value::Null,
                    None,
                )
                .await?;
            if self.mode == Mode::SettlementOnly {
                self.deselect_read(
                    "inspect",
                    json!({"subject":"dispatch","dispatch":step["dispatch"],"resource":null}),
                    Vec::new(),
                )
                .await?;
                let payload = json!({"recipe":recipe,"expected":values,"resource":null,
                    "preflight":null,"projection":null});
                let refs: Vec<Value> = std::iter::once(recipe_seq.clone())
                    .chain(cited.iter().cloned())
                    .collect();
                for _ in 0..2 {
                    self.deselect_read(&action("inspect-objects"), payload.clone(), refs.clone())
                        .await?;
                }
                return self.settle(&order).await;
            }
            let record = created["objects"][0].clone();
            self.secret_receipt(&step).await?;
            values["cluster_issuer"] = record["uid"].clone();
            cited.push(self.recorded_sequence(&step, "issuer-observation")?);
            let read = self
                .secret_read(&recipe, &recipe_seq, &values, &cited)
                .await?;
            require(binds(&record, &read), Failure::Ownership)?;
        }
        let last = self
            .secret_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms(
            if stage == "create" {
                "activate"
            } else {
                "observe"
            },
            &last,
        )?;
        self.settle(&order).await
    }
}

pub(super) fn duplicate(policy: &super::super::Policy) -> Result<super::super::Policy> {
    Ok(super::super::Policy {
        environment: policy.environment.clone(),
        cwd: policy.cwd.clone(),
        environment_snapshot: policy.environment_snapshot.clone(),
        credentials: policy
            .credentials
            .try_duplicate()
            .map_err(|_| Failure::Credential)?,
        non_interactive: policy.non_interactive,
        deadline: policy.deadline,
        cancellation: policy.cancellation.clone(),
    })
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
    issuer: &str,
) -> super::ExecutionResult<Snapshot> {
    let mut last: Option<Snapshot> = None;
    loop {
        match begin(project, duplicate(&policy)?, target, issuer, last.is_none()).await? {
            Begun::Request(mut session, recipe, stage) => {
                let result = Box::pin(session.issuer_run(recipe, stage)).await;
                let snapshot = session
                    .local
                    .complete(result, &session.context.clock)
                    .await?;
                if stage == "observe" || matches!(stage, "activate" | "finish-activation") {
                    return Ok(snapshot);
                }
                last = Some(snapshot);
            }
            Begun::Supply(resource) => {
                let first = resource["machine"]
                    .as_str()
                    .ok_or(Failure::Integrity)?
                    .to_owned();
                let selection = super::ResourceSelection {
                    id: resource["id"]
                        .as_str()
                        .ok_or(Failure::Integrity)?
                        .to_owned(),
                    generation: resource["generation"]
                        .as_str()
                        .ok_or(Failure::Integrity)?
                        .to_owned(),
                };
                last = Some(
                    super::consume_existing(
                        project,
                        duplicate(&policy)?,
                        target,
                        &first,
                        selection,
                        super::super::Operation::Issuer {
                            name: issuer.into(),
                        },
                    )
                    .await?,
                );
            }
            Begun::Done => return last.ok_or_else(|| Failure::Integrity.into()),
        }
    }
}

