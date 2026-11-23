// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::certificate;
use super::issuer::{self, ANCHOR};
use super::network::{self, Family};
use super::registry_service as service;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{NETWORK, PROFILE, protocol};
use base64ct::Encoding;
use broil_config::LoadedProject;
use broil_config::images::select::EffectiveRegistry;
use broil_core::k3s::{Infrastructure, ManagedRegistry};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "registry-endpoint",
    protocol: "broil-k3s-registry-endpoint",
    magic: b"BK3SREP1\n",
    header: "RegistryEndpointHeader",
    result: "RegistryEndpointResult",
    body: NETWORK,
    planned: 4,
    reserve: 16_384,
    version: 1,
};

const ORIGIN: &str = "registry-endpoint-origin";

const OBJECTS: [(&str, &str); 3] = [
    ("broil-registry", "broil-registry-endpoint"),
    ("cert-manager", "broil-registry-tls"),
    ("broil-registry", "broil-registry"),
];

pub(super) fn certificate_blocks(bytes: &[u8]) -> Result<Vec<String>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::Configuration)?;
    require(!text.contains('\r'), Failure::Configuration)?;
    let mut blocks = Vec::new();
    let mut open: Option<Vec<&str>> = None;
    for line in text.split('\n') {
        if let Some(lines) = open.as_mut() {
            if line != END {
                require(
                    !line.is_empty()
                        && line
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)),
                    Failure::Configuration,
                )?;
                lines.push(line);
                continue;
            }
            let body = lines[1..].concat();
            let block = format!("{}\n{END}", lines.join("\n"));
            let mut der = vec![0; body.len()];
            require(
                lines.len() > 1
                    && block.len() <= 4096
                    && base64ct::Base64::decode(body.as_bytes(), &mut der).is_ok(),
                Failure::Configuration,
            )?;
            blocks.push(block);
            open = None;
        } else if line == BEGIN {
            open = Some(vec![line]);
        } else {
            require(
                line.bytes().all(|b| b == b' ' || b == b'\t'),
                Failure::Configuration,
            )?;
        }
    }
    require(open.is_none() && !blocks.is_empty(), Failure::Configuration)?;
    Ok(blocks)
}

pub(super) fn trust_gate(name: &str, entry: &EffectiveRegistry) -> Result<(Value, Value)> {
    let (endpoint, ca) = declared_trust(name, entry)?;
    let bytes = crate::k3s::read_ca(ca, 8_192)
        .map_err(|_| Failure::Configuration)?
        .ok_or(Failure::Configuration)?;
    let certificates = certificate_blocks(&bytes)?;
    Ok((
        endpoint,
        json!({"certificates":certificates,"sha256":protocol::digest(&bytes)}),
    ))
}

pub(super) fn declared_trust<'e>(
    name: &str,
    entry: &'e EffectiveRegistry,
) -> Result<(Value, &'e std::path::Path)> {
    let ca = entry.ca.as_deref().ok_or(Failure::Configuration)?;
    let origin = entry.declaration.endpoint.origin();
    require(origin.port == 443, Failure::Configuration)?;
    Ok((
        json!({"name":name,"host":origin.host,"port":443,
            "origin":format!("https://{}:443", origin.host)}),
        ca,
    ))
}

pub(super) fn gates(
    registry: Option<&ManagedRegistry>,
    infrastructure: &Infrastructure,
    registries: &BTreeMap<String, EffectiveRegistry>,
    profile: &Value,
) -> Result<(ManagedRegistry, Value, Value)> {
    let registry = service::gates(registry, infrastructure, profile)?;
    let entry = registries
        .get(&registry.endpoint)
        .ok_or(Failure::Configuration)?;
    let (endpoint, trust) = trust_gate(&registry.endpoint, entry)?;
    Ok((registry, endpoint, trust))
}

pub(super) fn established(owner: &Value, certificate: &str) -> Result<(Vec<Value>, Value)> {
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    let networked = resources
        .iter()
        .filter(|r| {
            r["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("network-object-"))
                && r["uid"].is_string()
        })
        .count();
    require(networked == 12, Failure::Ownership)?;
    let bound = |id: &str| {
        resources
            .iter()
            .find(|r| r["id"] == id && r["uid"].is_string())
            .cloned()
    };
    let services: Option<Vec<Value>> = (1..=5)
        .map(|n| bound(&format!("registry-service-object-{n:02}")))
        .collect();
    let ingress = (1..=3).all(|n| bound(&format!("ingress-object-{n:02}")).is_some());
    match (services, bound(&certificate::resource_id(certificate)?)) {
        (Some(services), Some(resource)) if ingress && bound(ANCHOR).is_some() => {
            Ok((services, resource))
        }
        _ => Err(Failure::Readiness),
    }
}

pub(super) fn prerequisite<T>(found: Result<T>) -> Result<T> {
    found.map_err(|failure| {
        if failure == Failure::Integrity {
            failure
        } else {
            Failure::Readiness
        }
    })
}

fn shaped(owner: &Value, origin: &str, n: usize, generation: Value, uid: Value) -> Value {
    if n == 0 {
        return json!({"kind":"endpoint","id":ORIGIN,"owner":owner,"generation":generation,
            "machine":null,"path":null,"namespace":null,"name":origin,"uid":null});
    }
    let (namespace, name) = OBJECTS[n - 1];
    json!({"kind":"service","id":format!("registry-endpoint-object-{n:02}"),"owner":owner,
        "generation":generation,"machine":null,"path":null,"namespace":namespace,"name":name,
        "uid":uid})
}

pub(super) fn planned(
    owner: &Value,
    origin: &str,
    previous: &[Snapshot],
) -> Result<(Vec<Value>, Option<Value>)> {
    let endpoint = |r: &Value| {
        r["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("registry-endpoint-"))
    };
    let held: Vec<&Value> = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| endpoint(r))
        .collect();
    if held.is_empty() {
        let planned = (0..4)
            .map(|n| {
                Ok(shaped(
                    &owner["owner"],
                    origin,
                    n,
                    json!(fresh()?),
                    Value::Null,
                ))
            })
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
        held.len() == 4
            && held.iter().enumerate().all(|(n, r)| {
                **r == shaped(
                    &owner["owner"],
                    origin,
                    n,
                    r["generation"].clone(),
                    r["uid"].clone(),
                )
            }),
        Failure::Ownership,
    )?;
    if held[1..].iter().any(|r| r["uid"].is_null()) {
        require(
            held[1..].iter().all(|r| r["uid"].is_null())
                && !previous.iter().any(|s| {
                    s.request["resources"]
                        .as_array()
                        .is_some_and(|r| r.iter().any(endpoint))
                }),
            Failure::Ownership,
        )?;
    }
    Ok((held.into_iter().cloned().collect(), None))
}

pub(super) fn stage(objects: &[Value]) -> Result<&'static str> {
    if objects.iter().all(Value::is_null) {
        Ok("create")
    } else if objects.iter().all(Value::is_object) {
        Ok("observe")
    } else {
        Err(Failure::Ownership)
    }
}

pub(super) fn staged(
    objects: &[Value],
    ready: impl FnOnce() -> Result<()>,
    budget: impl FnOnce() -> Result<()>,
) -> Result<&'static str> {
    let stage = stage(objects)?;
    if stage == "create" {
        ready()?;
        budget()?;
    }
    Ok(stage)
}

pub(super) fn effects(stage: &str) -> usize {
    if stage == "create" { 3 } else { 0 }
}

pub(super) fn certificate_ready(
    previous: &[Snapshot],
    resource: &Value,
    report: &dyn Fn(&Snapshot) -> Result<Value>,
) -> Result<()> {
    let latest = previous
        .iter()
        .filter(|s| {
            s.request["action"] == "reconcile-certificate"
                && s.request["resources"][0]["id"] == resource["id"]
        })
        .max_by_key(|s| s.request["created_ms"].as_u64())
        .ok_or(Failure::Readiness)?;
    require(
        report(latest)?["readiness"]["services"] == "ready",
        Failure::Readiness,
    )
}

pub(super) fn budgets(step: u64, script: u64, remaining: u64) -> Result<()> {
    require(
        step.min(script) >= 60 && remaining >= 2 * (45 + 2 * 30) + 50,
        Failure::Bound,
    )
}

pub(super) fn admits(stage: &str, reply: &Value) -> Result<()> {
    let objects = reply["objects"].as_array().ok_or(Failure::Integrity)?;
    require(objects.len() == 3, Failure::Integrity)?;
    require(
        objects.iter().all(|o| o["class"] != "unobservable"),
        Failure::Readiness,
    )?;
    let create = stage == "create";
    require(
        !create || reply["issued"]["state"] == "present",
        Failure::Readiness,
    )?;
    let wanted = if create { "absent" } else { "owned" };
    require(
        objects.iter().all(|o| o["class"] == wanted),
        Failure::Ownership,
    )
}

pub(super) fn readiness(read: &Value) -> &'static str {
    let owned = read["objects"]
        .as_array()
        .is_some_and(|o| o.len() == 3 && o.iter().all(|o| o["class"] == "owned"));
    let served = read["served"]
        .as_array()
        .is_some_and(|s| !s.is_empty() && s.iter().all(|s| s["state"] == "ready"));
    if owned && read["issued"]["state"] == "present" && served {
        "ready"
    } else {
        "not-ready"
    }
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let read = tag == "inspect-objects";
    require(
        ["objects", "issued", "served"]
            .iter()
            .all(|key| result[*key].is_null() != read)
            && result["terminal"].is_null() == read,
        Failure::Integrity,
    )
}

pub(super) fn expected(recipe: &Value) -> Value {
    let objects: Vec<Value> = recipe["origins"]["objects"]
        .as_array()
        .map_or_else(Vec::new, |o| {
            o.iter().map(|origin| origin["uid"].clone()).collect()
        });
    json!({"objects":objects})
}

pub(super) fn ingress(context: &rpc::Context<'_>, removed: &Value) -> Result<Vec<Value>> {
    let declaration = context.selected.declaration;
    let ingress: Vec<Value> = declaration
        .infrastructure
        .ingress_members
        .iter()
        .filter(|name| {
            removed
                .as_array()
                .is_none_or(|r| !r.iter().any(|r| r["member"] == name.as_str()))
        })
        .map(|name| {
            declaration
                .members
                .iter()
                .find(|m| m.name == *name)
                .map(|m| json!(m.node_ip.to_string()))
                .ok_or(Failure::Configuration)
        })
        .collect::<Result<_>>()?;
    require(!ingress.is_empty(), Failure::Readiness)?;
    Ok(ingress)
}

#[allow(clippy::too_many_arguments)]
fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    registry: &ManagedRegistry,
    endpoint: &Value,
    trust: &Value,
    certificate: &Value,
    stage: &str,
    origins: &Value,
) -> Result<Value> {
    let anchor = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == ANCHOR)
        .ok_or(Failure::Readiness)?;
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"first_server":super::acting_server(owner)?,"anchor_uid":anchor["uid"],
        "version":context.selected.declaration.version,"registry":registry.name,
        "endpoint":endpoint,"trust":trust,"certificate":certificate,"ingress":ingress(context, &owner["removed"])?,
        "stage":stage,"origins":origins,"profile_sha256":context.fingerprints["profile_sha256"]});
    schema::validate(&canonical(&recipe)?, "RegistryEndpointRecipe", 32_768)?;
    Ok(recipe)
}

pub(super) fn fits(request: &Value, attempt: &str, count: usize, recipe: &Value) -> Result<()> {
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let mut binding = network::read_binding(request, attempt, last, 0)?;
    binding["receiver_generation"] = json!(u64::MAX);
    let wide = "f".repeat(128);
    let objects: Vec<Value> = OBJECTS
        .iter()
        .map(|(namespace, name)| {
            json!({"kind":"NetworkPolicy","namespace":namespace,"name":name,"uid":wide,
                "class":"owned-drifted","spec_sha256":"0".repeat(64)})
        })
        .collect();
    let issued = json!({"state":"unobservable","leaf_sha256":"0".repeat(64)});
    let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
    for ordinal in 1..=3 {
        let header = json!({"protocol":FAMILY.protocol,"version":1,"action":"create-object",
            "request_id":fresh()?,"binding":binding,"remaining_ms":7_200_000,"recipe":recipe,
            "expected":{"objects":vec![json!(wide); 3]},
            "resource":resources.get(ordinal).ok_or(Failure::Integrity)?,
            "preflight":{"objects":objects,"issued":issued},"object_ordinal":ordinal});
        require(
            canonical(&header)?
                .len()
                .checked_add(17 + FAMILY.reserve)
                .is_some_and(|n| n <= 65_536),
            Failure::Bound,
        )?;
    }
    let members = recipe["ingress"].as_array().map_or(0, Vec::len);
    let served = vec![json!({"state":"not-ready","reason":"unobservable"}); members];
    let reply = json!({"kind":"result","status":"unsupported-version","terminal":null,
        "objects":objects,"issued":issued,"served":served,"failure":"unsupported-version"});
    require(canonical(&reply)?.len() <= FAMILY.reserve, Failure::Bound)
}

#[allow(clippy::too_many_arguments)]
async fn preflight(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    stage: &str,
    source_events: &[Value],
    cleanup: &mut bool,
) -> Result<()> {
    let payload = json!({"recipe":recipe,"expected":expected(recipe),"resource":null,
        "preflight":null,"object_ordinal":null});
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
    );
    let observed = network::invoke(
        context,
        &FAMILY,
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
    shape("inspect-objects", &result)?;
    served(recipe, &result)?;
    admits(stage, &result)?;
    network::membership_reads(context, request, attempt, last, source_events, cleanup).await
}

fn served(recipe: &Value, result: &Value) -> Result<()> {
    require(
        result["served"].as_array().is_some_and(|entries| {
            Some(entries.len()) == recipe["ingress"].as_array().map(Vec::len)
                && entries
                    .iter()
                    .all(|e| e["reason"].is_null() == (e["state"] == "ready"))
        }),
        Failure::Integrity,
    )
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
    let (registry, endpoint, trust) = gates(
        declaration.registry.as_ref(),
        &declaration.infrastructure,
        &context.selected.registries,
        &profile,
    )?;
    let declared = context
        .selected
        .declaration
        .infrastructure
        .certificates
        .get(&registry.certificate)
        .ok_or(Failure::Configuration)?
        .clone();
    let mut local = Local::new(&context)?;
    let prepared: Result<_> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e| e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()
                && v.iter().all(|m| m["node_uid"].is_string())), Failure::Ownership)?;
        let members = super::survivors(&owner)?;
        let (services, resource) = established(&owner, &registry.certificate)?;
        let report = |snapshot: &Snapshot| {
            super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        };
        for snapshot in &previous {
            super::session::settled(&report(snapshot)?)?;
        }
        let service_origins = prerequisite(service::object_origins(&previous, &services))?;
        require(service_origins["objects"].as_array()
            .is_some_and(|o| o.iter().all(Value::is_object)), Failure::Readiness)?;
        let (_, cluster_issuer) = prerequisite(certificate::bound_issuer(
            &context.scope,
            &previous,
            &owner,
            &declared.issuer,
        ))?;
        let certificate_origins =
            prerequisite(certificate::origins(&previous, &resource, &cluster_issuer))?;
        require(!certificate_origins["certificate"].is_null(), Failure::Readiness)?;
        let origin = endpoint["origin"].as_str().ok_or(Failure::Integrity)?;
        let (resources, pending_owner) = planned(&owner, origin, &previous)?;
        let objects = service::objects("registry-endpoint", &previous, &resources[1..])?;
        let stage = staged(&objects, || certificate_ready(&previous, &resource, &report), || {
            let remaining = context.clock.deadline()
                .saturating_duration_since(tokio::time::Instant::now()).as_secs();
            budgets(context.selected.step_timeout.seconds,
                service::script_seconds(&context, &members[0])?, remaining)
        })?;
        context.authenticate_owned(&Value::Array(members.clone())).await?;
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let participants = super::participants(&Value::Array(members.clone()))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let (certificate_name, secret_name) = certificate::names(&current_owner["owner"], &resource["id"])?;
        let bound_certificate = json!({"name":registry.certificate,"certificate":certificate_name,
            "secret":secret_name,"uid":resource["uid"],
            "cluster_issuer":certificate_origins["cluster_issuer"]["uid"]});
        let all_origins = json!({"objects":objects,"service":service_origins["objects"],
            "certificate":certificate_origins});
        let endpoint_recipe = recipe(&context, &current_owner, &operation, &registry, &endpoint,
            &trust, &bound_certificate, stage, &all_origins)?;
        let created = now()?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-registry-endpoint",
            "members":members,"cluster":current_owner["cluster"],"resources":resources,
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let count = issuer::step_count(&members, effects(stage))?;
        fits(&request, &attempt_id, count, &endpoint_recipe)?;
        let mut cleanup = false;
        let checked = preflight(&context, &request, &attempt_id, count as u64, &endpoint_recipe,
            stage, &source_events, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_registry_endpoint(successor)).await?;
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
        for event in std::iter::once(json!({"type":"registry-endpoint-recipe","recipe":endpoint_recipe}))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members, attempt_id, endpoint_recipe))
    }.await;
    let (members, attempt_id, endpoint_recipe) = match prepared {
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
        endpoint_recipe,
    ))
}

impl Session<'_> {
    async fn endpoint_read(
        &mut self,
        recipe: &Value,
        refs: &[Value],
        expected: &Value,
    ) -> Result<Value> {
        let payload = json!({"recipe":recipe,"expected":expected,"resource":null,"preflight":null,
            "object_ordinal":null});
        let result = self
            .family_step(0, "inspect-objects", payload, refs.to_vec())
            .await?
            .1;
        served(recipe, &result)?;
        Ok(result)
    }

    async fn endpoint_effect(
        &mut self,
        recipe: &Value,
        refs: &[Value],
        expected: &Value,
        resource: &Value,
        ordinal: usize,
    ) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let latest = snapshot
            .observations
            .iter()
            .rev()
            .find(|o| o["event"]["type"] == "registry-endpoint-observation")
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
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":{"objects":event["objects"],"issued":event["issued"]},
            "object_ordinal":ordinal});
        self.family_step(0, "create-object", payload, refs).await
    }

    async fn endpoint_run(&mut self, recipe: Value) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq =
            network::latest_sequence(self.local.snapshot()?, "registry-endpoint-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let stage = recipe["stage"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        let mut values = expected(&recipe);
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
        self.network_source_gate().await?;
        let read = self.endpoint_read(&recipe, &refs, &values).await?;
        admits(&stage, &read)?;
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
        let read = self.endpoint_read(&recipe, &refs, &values).await?;
        admits(&stage, &read)?;
        if stage == "create" {
            let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
            for ordinal in 1..=3 {
                let (step, created) = self
                    .endpoint_effect(&recipe, &refs, &values, &resources[ordinal], ordinal)
                    .await?;
                let receipt = self
                    .inspect_step(0, "dispatch", step["dispatch"].clone(), Value::Null)
                    .await?;
                require(receipt["status"] == "ok", Failure::Ownership)?;
                let identity = created["terminal"]["resource_identity"].clone();
                require(
                    identity.as_str().is_some_and(protocol::opaque),
                    Failure::Ownership,
                )?;
                values["objects"][ordinal - 1] = identity.clone();
                refs.push(
                    issuer::recorded(self.local.snapshot()?, &step, "receiver")?["sequence"]
                        .clone(),
                );
                let read = self.endpoint_read(&recipe, &refs, &values).await?;
                let object = &read["objects"][ordinal - 1];
                require(
                    object["class"] == "owned" && object["uid"] == identity,
                    Failure::Ownership,
                )?;
                let mut published = resources[ordinal].clone();
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
        let read = self.endpoint_read(&recipe, &refs, &values).await?;
        admits("observe", &read)?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let (mut session, recipe) = begin(project, policy, target).await?;
    let result = Box::pin(session.endpoint_run(recipe)).await;
    session.local.complete(result, &session.context.clock).await
}

