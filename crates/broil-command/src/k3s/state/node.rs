// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::network::{self, Family};
use super::session::{Local, Mode, Session, fresh, now};
use super::store::WaveRecord;
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::NODE;
use broil_config::LoadedProject;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "node",
    protocol: "broil-k3s-node",
    magic: b"BK3SNOD1\n",
    header: "NodeHeader",
    result: "NodeResult",
    body: NODE,
    planned: 0,
    reserve: 8_192,
    version: 1,
};

pub(super) const ACTIONS: &[&str] = &["restart-member", "configure-node-registries"];

pub(super) const CONFIGURE_PLAN: &str = "broil-k3s-node-configure-plan-v1";

pub(super) struct Configure {
    pub(super) entries: std::collections::BTreeMap<String, Value>,
    pub(super) resources: std::collections::BTreeMap<String, Value>,
}

impl Configure {
    pub(super) fn plan(&self, mut plan: Value) -> Result<Value> {
        for entry in plan["members"].as_array_mut().ok_or(Failure::Integrity)? {
            let name = entry["member"].as_str().ok_or(Failure::Integrity)?;
            let entries = self.entries.get(name).ok_or(Failure::Ownership)?;
            entry["registries_sha256"] = json!(hash(super::node_registry::ENTRIES, entries)?);
        }
        Ok(plan)
    }

    pub(super) fn registries(&self, name: &Value) -> Result<&Value> {
        let name = name.as_str().ok_or(Failure::Integrity)?;
        self.entries.get(name).ok_or(Failure::Ownership)
    }

    fn request(&self, request: &Value, member: &Value) -> Result<Value> {
        let name = member["member"].as_str().ok_or(Failure::Integrity)?;
        let mut request = request.clone();
        request["action"] = json!("configure-node-registries");
        request["resources"] = self.resources.get(name).ok_or(Failure::Ownership)?.clone();
        Ok(request)
    }
}

pub(super) fn carries(action: &Value) -> bool {
    action
        .as_str()
        .is_some_and(|action| ACTIONS.contains(&action))
}

pub(super) const WAIT_MS: u64 = 25_000;
pub(super) const OBSERVE_CAP: usize = 8;
pub(super) const GATE_CAP: usize = 3;
const GATE_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const REMOVAL_CAP: usize = 180;
const GUARD: Duration = Duration::from_secs(5);

pub(super) fn dispatchable(deadline: tokio::time::Instant, now: tokio::time::Instant) -> bool {
    deadline.saturating_duration_since(now) > GUARD
}

fn wave_end(plan: &Value, name: &Value) -> bool {
    plan["waves"].as_array().is_some_and(|waves| {
        waves
            .iter()
            .any(|wave| wave.as_array().and_then(|w| w.last()) == Some(name))
    })
}

pub(super) fn step_count(plan: &Value, position: usize) -> Result<usize> {
    let members = plan["members"].as_array().ok_or(Failure::Integrity)?;
    let render = usize::from(configures(plan));
    let servers = members.iter().filter(|m| m["role"] == "server").count();
    let gate = servers + usize::from(servers < members.len());
    let entry = members.get(position).ok_or(Failure::Integrity)?;
    let tail = if entry["role"] == "server" {
        servers
    } else if wave_end(plan, &entry["member"]) {
        servers + 1
    } else {
        0
    };
    members
        .len()
        .checked_mul(6)
        .and_then(|n| n.checked_add(2 * gate + 2 + tail + render))
        .filter(|n| *n <= 1024)
        .ok_or(Failure::Bound)
}

fn configures(plan: &Value) -> bool {
    plan["members"][0].get("registries_sha256").is_some()
}

fn succeeded(context: &rpc::Context<'_>, snapshot: &Snapshot) -> bool {
    super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        .is_ok_and(|report| report["outcome"] == "succeeded")
}

fn first_recipe<'a>(
    context: &rpc::Context<'_>,
    previous: &'a [Snapshot],
    member: &Value,
) -> Result<&'a Value> {
    let matching: Vec<_> = previous
        .iter()
        .filter(|s| s.request["action"] == "create-server" && succeeded(context, s))
        .flat_map(|s| &s.observations)
        .filter(|o| {
            o["event"]["type"] == "lifecycle-recipe"
                && o["event"]["recipe"]["member"]["machine"] == member["machine"]
                && o["event"]["recipe"]["member"]["node_uid"].is_null()
        })
        .collect();
    require(matching.len() == 1, Failure::Ownership)?;
    Ok(&matching[0]["event"]["recipe"])
}

pub(super) fn plan(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
) -> Result<Value> {
    plan_joining(context, previous, owner, None)
}

pub(super) fn plan_joining(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    joining: Option<&Value>,
) -> Result<Value> {
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let mut entries = Vec::new();
    let first = &context.selected.declaration.members[0].name;
    for role in ["server", "agent"] {
        for member in members {
            if member["role"] != role {
                continue;
            }
            let recipe = if let Some(recipe) =
                joining.filter(|r| r["member"]["member"] == member["member"])
            {
                recipe
            } else if member["member"] == first.as_str() {
                first_recipe(context, previous, member)
                    .or_else(|_| super::agent::prior_recipe(context, previous, member))?
            } else {
                super::agent::prior_recipe(context, previous, member)?
            };
            entries.push(json!({"member":member["member"],"role":role,
                "recipe_identity_sha256":super::provenance::recipe_identity(recipe)?}));
        }
    }
    require(entries.len() == members.len(), Failure::Ownership)?;
    Ok(planned(
        entries,
        context.selected.agent_wave_size,
        &context.fingerprints["profile_sha256"],
    ))
}

pub(super) fn planned(entries: Vec<Value>, width: u8, profile: &Value) -> Value {
    let agents: Vec<Value> = entries
        .iter()
        .filter(|e| e["role"] == "agent")
        .map(|e| e["member"].clone())
        .collect();
    let waves: Vec<Value> = agents
        .chunks(usize::from(width.max(1)))
        .map(|wave| json!(wave))
        .collect();
    json!({"members":entries,"wave_width":width,"waves":waves,"profile_sha256":profile})
}

#[allow(clippy::too_many_arguments)]
pub(super) fn recipe(
    scope: &Value,
    owner: &Value,
    operation: &str,
    version: &str,
    run: &Value,
    position: usize,
    plan: &Value,
    registries: Option<&Value>,
) -> Result<Value> {
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let entry = &plan["members"][position];
    let member = members
        .iter()
        .find(|m| m["member"] == entry["member"] && m["role"] == entry["role"])
        .ok_or(Failure::Integrity)?;
    let label = if registries.is_some() {
        CONFIGURE_PLAN
    } else {
        "broil-k3s-node-plan-v1"
    };
    let mut recipe = json!({"scope":scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"first_server":members.iter().find(|m| m["role"] == "server").ok_or(Failure::Integrity)?,
        "version":version,"run":run,"position":position,"plan":plan,
        "plan_sha256":hash(label, plan)?,"member":member,
        "wave_end":wave_end(plan, &entry["member"]),"profile_sha256":plan["profile_sha256"]});
    if let Some(registries) = registries {
        recipe["registries"] = registries.clone();
    }
    schema::validate(&canonical(&recipe)?, "NodeRecipe", 32_768)?;
    Ok(recipe)
}

pub(super) fn render_fits(request: &Value, attempt: &str, recipe: &Value) -> Result<()> {
    let length = |value: &Value| -> Result<usize> { Ok(canonical(value)?.len()) };
    let widest = request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .max_by_key(|m| length(m).unwrap_or(usize::MAX))
        .ok_or(Failure::Integrity)?;
    let binding = json!({"scope":request["scope"],"owner":request["owner"],
        "operation":request["operation"],"attempt":attempt,"step":u32::MAX,
        "dispatch":"f".repeat(32),"recipient":widest,"receiver_generation":u64::MAX,
        "request_sha256":"f".repeat(64),"participants_sha256":request["participants_sha256"],
        "fingerprints":request["fingerprints"]});
    let header = json!({"protocol":FAMILY.protocol,"version":1,"action":"configure-registries",
        "request_id":"f".repeat(32),"binding":binding,"remaining_ms":7_200_000,
        "recipe":recipe,"expected":null,"wait_ms":null});
    require(
        length(&binding)? <= 4096 && 17 + length(&header)? + FAMILY.reserve <= 65_536,
        Failure::Bound,
    )
}

pub(super) fn next(latest: Option<&Value>, plan_sha256: &str, operation: &str) -> (Value, usize) {
    if let Some(recipe) = latest {
        let members = recipe["plan"]["members"].as_array().map_or(0, Vec::len);
        let position = recipe["position"].as_u64().map(|p| p as usize + 1);
        if recipe["plan_sha256"] == plan_sha256 && position.is_some_and(|p| p < members) {
            return (recipe["run"].clone(), position.unwrap_or(0));
        }
    }
    (json!(operation), 0)
}

pub(super) fn unrestarted(previous: &[Snapshot], run: &Value, position: usize) -> bool {
    !previous.iter().flat_map(|s| &s.observations).any(|o| {
        o["event"]["type"] == "restart-recipe"
            && o["event"]["recipe"]["run"] == *run
            && o["event"]["recipe"]["position"]
                .as_u64()
                .is_some_and(|p| p >= position as u64)
    })
}

pub(super) fn gated(agents: bool, waves: &[WaveRecord]) -> Result<()> {
    require(
        !agents || waves.last().is_some_and(|wave| wave.gate.is_some()),
        Failure::Busy,
    )
}

pub(super) fn budget(step: u64, script: u64, remaining: Option<u64>) -> Result<()> {
    require(
        step.min(script).min(remaining.unwrap_or(u64::MAX)) >= 70,
        Failure::Bound,
    )
}

pub(super) fn configure_budget(step: u64, script: u64, remaining: Option<u64>) -> Result<()> {
    budget(step, script, remaining.map(|r| r.saturating_sub(10)))
}

pub(super) fn expected(member: &Value, entry: Option<&Value>, lease_after_ms: &Value) -> Value {
    json!({"member":member["member"],"node_uid":member["node_uid"],
        "labels":entry.map(|e| e["labels"].clone()),"taints":entry.map(|e| e["taints"].clone()),
        "lease_after_ms":lease_after_ms})
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let unit = &result["unit"];
    require(
        match tag {
            "inspect-member" => {
                unit.is_object()
                    && unit["previous_invocation"].is_null()
                    && result["guard"].is_string()
                    && result["node"].is_null()
                    && result["terminal"].is_null()
            }
            "observe-node" => {
                result["node"].is_object()
                    && unit.is_null()
                    && result["guard"].is_null()
                    && result["terminal"].is_null()
            }
            "restart" => {
                unit.is_object()
                    && unit["invocation"].is_string()
                    && unit["previous_invocation"].is_string()
                    && unit["invocation"] != unit["previous_invocation"]
                    && result["guard"].is_null()
                    && result["node"].is_null()
                    && result["terminal"].is_object()
            }
            "configure-registries" => {
                unit.is_null()
                    && result["guard"].is_null()
                    && result["node"].is_null()
                    && result["terminal"].is_object()
            }
            _ => false,
        },
        Failure::Integrity,
    )
}

pub(super) fn readiness(snapshot: &Snapshot, outcome: &Value) -> (Value, Value) {
    if outcome != "succeeded" {
        return (json!("unobserved"), json!("unobserved"));
    }
    let restart = snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "node-observation" && o["event"]["kind"] == "restart")
        .and_then(|o| o["sequence"].as_u64());
    let after = |kind: &'static str| {
        snapshot.observations.iter().filter(move |o| {
            o["event"]["type"] == kind
                && restart.is_some_and(|r| o["sequence"].as_u64().is_some_and(|s| s > r))
        })
    };
    let state = |states: Vec<bool>| {
        json!(if states.is_empty() {
            "unobserved"
        } else if states.iter().all(|s| *s) {
            "ready"
        } else {
            "not-ready"
        })
    };
    let quorum = state(
        after("server-membership")
            .map(|o| o["event"]["membership"]["healthy"] == true)
            .collect(),
    );
    let agents = snapshot.request["members"]
        .as_array()
        .is_some_and(|members| members.iter().any(|m| m["role"] == "agent"));
    let nodes = if agents {
        state(
            after("agent-membership")
                .map(|o| {
                    o["event"]["view"]["members"]
                        .as_array()
                        .is_some_and(|items| {
                            items
                                .iter()
                                .all(|i| i["present"] == true && i["ready"] == true)
                        })
                })
                .collect(),
        )
    } else {
        quorum.clone()
    };
    (quorum, nodes)
}

fn dispatched(transport: Value, failure: Option<Failure>) -> Value {
    json!({"type":"dispatch","transport":transport,
        "outcome":if failure.is_some() {"unknown"} else {"running"},"failure":failure.map(Failure::name)})
}

pub(super) fn fits(
    request: &Value,
    attempt: &str,
    events: &[Value],
    expected: &Value,
) -> Result<()> {
    let length = |value: &Value| -> Result<usize> { Ok(canonical(value)?.len()) };
    let recipe = &events.first().ok_or(Failure::Integrity)?["recipe"];
    let position = recipe["position"].as_u64().ok_or(Failure::Integrity)? as usize;
    let count = step_count(&recipe["plan"], position)?;
    let render = usize::from(recipe.get("registries").is_some());
    let members = request["members"].as_array().ok_or(Failure::Integrity)?;
    let servers = members.iter().filter(|m| m["role"] == "server").count();
    let agents = usize::from(servers < members.len());
    let n = members.len();
    let request_bytes = canonical(request)?;
    let attempt_bytes = canonical(&record(request, attempt, count)?)?;
    require(
        request_bytes.len() < 262_144 && attempt_bytes.len() < 65_536,
        Failure::Bound,
    )?;
    let widest = members
        .iter()
        .max_by_key(|m| length(m).unwrap_or(usize::MAX))
        .ok_or(Failure::Integrity)?;
    let binding = json!({"scope":request["scope"],"owner":request["owner"],
        "operation":request["operation"],"attempt":attempt,"step":u32::MAX,
        "dispatch":"f".repeat(32),"recipient":widest,"receiver_generation":u64::MAX,
        "request_sha256":"f".repeat(64),"participants_sha256":request["participants_sha256"],
        "fingerprints":request["fingerprints"]});
    require(length(&binding)? <= 4096, Failure::Bound)?;
    let null = Value::Null;
    let listed = json!({"registries":recipe["registries"]});
    let mut frames = vec![
        ("restart", 7_200_000u64, &null, Value::Null),
        ("observe-node", 30_000, expected, json!(WAIT_MS)),
    ];
    if render == 1 {
        frames.push(("configure-registries", 7_200_000, &null, Value::Null));
        frames.push(("inspect-member", 30_000, &listed, Value::Null));
    }
    for (tag, remaining, expected, wait) in frames {
        let header = json!({"protocol":FAMILY.protocol,"version":1,"action":tag,
            "request_id":"f".repeat(32),"binding":binding,"remaining_ms":remaining,
            "recipe":recipe,"expected":expected,"wait_ms":wait});
        require(
            17 + length(&header)? + FAMILY.reserve <= 65_536,
            Failure::Bound,
        )?;
    }
    for event in &events[1..] {
        let (action, payload) = if event["type"] == "server-recipe" {
            (
                "observe-membership",
                json!({"recipe_kind":event["recipe_kind"],
                "recipe":event["recipe"],"identity":null,"membership":null,"removed":null}),
            )
        } else {
            (
                "observe-agent-membership",
                json!({"recipe":event["recipe"],"identity":null,
                "agent_view":null}),
            )
        };
        let header = json!({"protocol":"broil-k3s-lifecycle","version":1,"action":action,
            "request_id":"f".repeat(32),"binding":binding,"remaining_ms":30_000,"payload":payload});
        require(14 + length(&header)? + 16_388 <= 65_536, Failure::Bound)?;
    }
    let observation = |event: Value| -> Result<usize> {
        let size = length(
            &json!({"schema":1,"kind":"observation","scope":request["scope"],
            "owner":request["owner"],"operation":request["operation"],"sequence":4096,
            "recorded_ms":u64::MAX,"producer_ms":u64::MAX,
            "source":{"kind":"receiver","machine":widest["machine"]},"attempt":attempt,
            "step":u32::MAX,"dispatch":"f".repeat(32),"event":event}),
        )?;
        require(size < 65_536, Failure::Bound)?;
        Ok(size + 1)
    };
    let step = |references: usize| -> Result<usize> {
        Ok(
            length(&json!({"schema":1,"kind":"step","scope":request["scope"],
            "owner":request["owner"],"operation":request["operation"],"attempt":attempt,
            "step":u32::MAX,"original_step":null,"created_ms":u64::MAX,"dispatch":"f".repeat(32),
            "action":"lifecycle:observe-agent-membership","recipient":widest,"resource":null,
            "expected_receiver_generation":u64::MAX,"request_sha256":"f".repeat(64),
            "payload_sha256":"f".repeat(64),"payload_observations":vec![4096; references]}))?
                + 1,
        )
    };
    let transport = json!({"dispatch":"confirmed","exit":u64::MAX,"signal":"x".repeat(128),
        "input_released":false,"staging_cleanup":"residue"});
    let dispatch = observation(json!({"type":"dispatch","transport":transport,
        "outcome":"succeeded","failure":"unsupported-version"}))?;
    let receiver = observation(
        json!({"type":"receiver","receipt":{"schema":1,"kind":"terminal",
        "binding":binding,"action":"lifecycle:observe-agent-membership",
        "payload_sha256":"f".repeat(64),"outcome":"succeeded","failure":"unsupported-version",
        "effect":"complete","writer_ended":true,"resource":null,"resource_identity":null,
        "completed_ms":u64::MAX},"transport":transport}),
    )?;
    let reservation = observation(json!({"type":"reservation","member":widest,
        "generation":u64::MAX,"state":"reserved","receipt_sha256":"f".repeat(64)}))?;
    let identity = json!([u64::MAX, u64::MAX]);
    let inspection = observation(json!({"type":"inspection","subject":"writer",
        "observed_dispatch":"f".repeat(32),"resource":null,"status":"absent","data":{
        "claim":{"schema":1,"kind":"machine-claim","scope":request["scope"],
            "owner":request["owner"],"member":widest,
            "participants_sha256":request["participants_sha256"],"generation":u64::MAX,
            "active_attempt":"f".repeat(32),"root_identity":identity,"lock_identity":identity},
        "ownership":{"schema":1,"owner":request["owner"],"scope":request["scope"],
            "machine":widest,"cluster":{"uid":"x".repeat(128),"ca_sha256":"f".repeat(64)},
            "data":identity},
        "reservation":null,"terminal":null,"seal":null,"retirement":null,"resource":null,
        "identity":null,"failure":null}}))?;
    let membership = observation(json!({"type":"server-membership","member":widest,
        "membership":{}}))?
        + 16_384;
    let node = observation(json!({"type":"node-observation","member":widest,
        "kind":"restart","unit":null,"node":null}))?
        + 8_192;
    let failure = observation(json!({"type":"failure","failure":"unsupported-version",
        "outcome":"cancelled","completion_unknown":false,"cleanup_unknown":false}))?;
    let gates = count - 6 * n - 2 - render;
    let observations = [
        events.len(),
        4 * n,
        12 * n,
        gates * (GATE_CAP + 1),
        3 + 3 * render,
        OBSERVE_CAP + 1,
        1,
    ]
    .iter()
    .sum::<usize>();
    require(observations <= 4096, Failure::Bound)?;
    let mut parts = vec![
        request_bytes.len() + length(&request["members"])? + length(&request["resources"])? + 3,
        attempt_bytes.len() + 1,
        4096,
        2 * n * (step(0)? + dispatch + inspection),
        3 * n * (step(0)? + dispatch + receiver + reservation),
        n * (step(2 * n)? + dispatch + receiver + reservation),
        gates * (step(1)? + GATE_CAP * dispatch + membership),
        (1 + render) * (step(1 + servers + agents)? + dispatch + receiver + node),
        step(3)? + OBSERVE_CAP * dispatch + node,
        failure,
    ];
    for event in events {
        parts.push(observation(event.clone())?);
    }
    let report = parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(*part))
        .ok_or(Failure::Bound)?;
    require(report <= 1_048_576, Failure::Bound)
}

fn record(request: &Value, attempt: &str, count: usize) -> Result<Value> {
    Ok(
        json!({"schema":1,"kind":"attempt","scope":request["scope"],"owner":request["owner"],
        "operation":request["operation"],"attempt":attempt,"created_ms":request["created_ms"],
        "request_sha256":hash("broil-infra-request-v1", request)?,"parent_attempt":null,
        "original_step":null,"approval":null,"steps":(1..=count).collect::<Vec<_>>()}),
    )
}

fn declared(context: &rpc::Context<'_>, member: &Value) -> Result<Value> {
    let (labels, taints) = network::declared(context, member)?;
    Ok(json!({"labels":labels,"taints":taints}))
}

pub(super) fn admissible(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    inputs: Option<&Configure>,
    request: &Value,
    attempt: &str,
) -> Result<(Value, Vec<Value>)> {
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let operation = request["operation"].as_str().ok_or(Failure::Integrity)?;
    let version = context.selected.declaration.version.as_str();
    let plan = plan(context, previous, owner)?;
    let plan = match inputs {
        Some(inputs) => inputs.plan(plan)?,
        None => plan,
    };
    let sources = network::source_recipes(previous, context, owner, operation, attempt)?;
    let agents = members.iter().any(|m| m["role"] == "agent");
    for position in 0..members.len() {
        let name = &plan["members"][position]["member"];
        let registries = inputs.map(|i| i.registries(name)).transpose()?;
        let recipe = recipe(
            &context.scope,
            owner,
            operation,
            version,
            &json!(operation),
            position,
            &plan,
            registries,
        )?;
        let request = match inputs {
            Some(inputs) => inputs.request(request, &recipe["member"])?,
            None => request.clone(),
        };
        let widest = if agents {
            declared(context, &recipe["member"])?
        } else {
            Value::Null
        };
        let expected = expected(
            &recipe["member"],
            widest.is_object().then_some(&widest),
            &json!(u64::MAX),
        );
        let events: Vec<Value> = std::iter::once(json!({"type":"restart-recipe","recipe":recipe}))
            .chain(sources.iter().cloned())
            .collect();
        fits(&request, attempt, &events, &expected)?;
    }
    Ok((plan, sources))
}

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
    configure: Option<&str>,
) -> super::ExecutionResult<(Session<'a>, Value)> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let prepared: Result<_> = async {
        let (previous, waves) = local.work(|store| store.agent_context()).await?;
        let owner = previous.first().ok_or(Failure::Ownership)?.owner.clone();
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints, Failure::Ownership)?;
        let members = super::survivors(&owner)?;
        let participants = super::participants(&json!(members))?;
        require(owner["participants_sha256"] == participants, Failure::Ownership)?;
        let owner_record = owner.clone();
        let mut owner = owner;
        owner["members"] = json!(members);
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let version = context.selected.declaration.version.as_str();
        let inputs = configure.map(|_| super::node_registry::inputs(&context, &previous, &owner, &[]))
            .transpose()?;
        let agents = members.iter().any(|m| m["role"] == "agent");
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":owner["owner"],
            "operation":operation,"created_ms":now()?,"sequence":request_sequence,"action":"restart-member",
            "members":members,"cluster":owner["cluster"],"resources":[],
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let (plan, sources) = admissible(&context, &previous, &owner, inputs.as_ref(), &request, &attempt_id)?;
        let (action, label) = match inputs {
            Some(_) => ("configure-node-registries", CONFIGURE_PLAN),
            None => ("restart-member", "broil-k3s-node-plan-v1"),
        };
        let plan_sha256 = hash(label, &plan)?;
        for snapshot in &previous {
            super::session::settled(&super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?)?;
        }
        let latest = previous.iter().max_by(|a, b| {
            a.request["created_ms"].as_u64().cmp(&b.request["created_ms"].as_u64())
                .then_with(|| a.request["operation"].as_str().cmp(&b.request["operation"].as_str()))
        });
        let predecessor = latest
            .filter(|s| s.request["action"] == action && succeeded(&context, s))
            .and_then(|s| s.observations.iter().find(|o| o["event"]["type"] == "restart-recipe"))
            .map(|o| &o["event"]["recipe"]);
        let (run, position) = next(predecessor, &plan_sha256, &operation);
        require(unrestarted(&previous, &run, position), Failure::Busy)?;
        gated(agents, &waves)?;
        if let Some(inputs) = &inputs {
            require(configure == Some(plan_sha256.as_str()), Failure::Ownership)?;
            super::node_registry::supplied(&previous, &owner, inputs)?;
        }
        require(super::declares_survivors(&context, &owner_record)?, Failure::Ownership)?;
        require(members.iter().all(|m| m["node_uid"].is_string()), Failure::Readiness)?;
        let registries = inputs.as_ref().map(|i| i.registries(&plan["members"][position]["member"])).transpose()?;
        let restart_recipe = recipe(&context.scope, &owner, &operation, version, &run, position, &plan, registries)?;
        let request = match &inputs {
            Some(inputs) => inputs.request(&request, &restart_recipe["member"])?,
            None => request,
        };
        let script = context.inventory.scripts.get(&context.selected.declaration.lifecycle_script)
            .ok_or(Failure::Configuration)?;
        let remaining = context.clock.deadline()
            .saturating_duration_since(tokio::time::Instant::now()).as_secs();
        for member in &members {
            let machine = context.inventory.machines.iter()
                .find(|m| member["machine"] == m.name.as_str()).ok_or(Failure::Configuration)?;
            (if inputs.is_some() { configure_budget } else { budget })(context.selected.step_timeout.seconds,
                script.timeout.as_ref().map_or(machine.timeouts.command.seconds, |d| d.seconds),
                (*member == restart_recipe["member"]).then_some(remaining))?;
        }
        context.authenticate_owned(&owner["members"]).await?;
        let count = step_count(&plan, position)?;
        let mut cleanup = false;
        let checked: Result<()> = async {
            for entry in plan["members"].as_array().ok_or(Failure::Integrity)? {
                let index = members.iter().position(|m| m["member"] == entry["member"])
                    .ok_or(Failure::Integrity)?;
                let expected = match &inputs {
                    Some(inputs) => json!({"registries":inputs.registries(&entry["member"])?}),
                    None => Value::Null,
                };
                let payload = json!({"recipe":restart_recipe,"expected":expected,"wait_ms":null});
                let deadline = context.clock.deadline().min(tokio::time::Instant::now()
                    + Duration::from_secs(context.selected.step_timeout.seconds));
                let observed = network::invoke(&context, &FAMILY,
                    &network::read_binding(&request, &attempt_id, count as u64, index)?,
                    "inspect-member", &payload, deadline, None).await;
                cleanup |= network::unclean(&observed.transport);
                let result = observed.response.ok_or(observed.failure.unwrap_or(Failure::Transport))?;
                require(result["status"] == "ok", super::server::refused(&result))?;
                shape("inspect-member", &result)?;
                let unit = &result["unit"];
                require(unit["active"] == "active" && unit["sub"] == "running"
                    && unit["result"] == "success", Failure::Readiness)?;
                require(result["guard"] == "pass", Failure::Ownership)?;
            }
            network::membership_reads(&context, &request, &attempt_id, count as u64, &sources,
                &mut cleanup).await
        }.await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let attempt = record(&request, &attempt_id, count)?;
        let stored_owner = owner_record.clone();
        let stored_attempt = attempt.clone();
        local.work(move |store| store.create(stored_owner, request, stored_attempt)).await?;
        for event in std::iter::once(json!({"type":"restart-recipe","recipe":restart_recipe}))
            .chain(sources) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt_id,"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members, attempt_id, restart_recipe))
    }.await;
    let (members, attempt_id, restart_recipe) = match prepared {
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
        Session {
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
        },
        restart_recipe,
    ))
}

impl Session<'_> {
    pub(super) async fn slot(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        source: Value,
    ) -> Result<(Value, Value)> {
        self.slot_citing(index, tag, payload, vec![source]).await
    }

    pub(super) async fn slot_citing(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        sources: Vec<Value>,
    ) -> Result<(Value, Value)> {
        self.slot_polled(index, tag, payload, sources, None).await
    }

    pub(super) async fn slot_polled(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        sources: Vec<Value>,
        voters: Option<usize>,
    ) -> Result<(Value, Value)> {
        self.context.check()?;
        let previous = self.local.step_deadline;
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        self.local.step_deadline = Some(deadline);
        let step = self.intended(index, &format!("lifecycle:{tag}"), &payload, sources)?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let cluster = self.local.snapshot()?.request["cluster"].clone();
        let server = tag == "observe-membership";
        let (cap, interval) = if payload["removed"].is_null() && voters.is_none() {
            (GATE_CAP, GATE_INTERVAL)
        } else {
            (
                REMOVAL_CAP,
                GATE_INTERVAL.max(Duration::from_secs(
                    self.context.selected.step_timeout.seconds / REMOVAL_CAP as u64,
                )),
            )
        };
        let mut dispatches = 0;
        let result = loop {
            let observed =
                super::server::invoke(&self.context, &binding, tag, &payload, deadline, None).await;
            dispatches += 1;
            self.local.step_deadline = previous;
            if observed.failure.is_some() {
                self.local
                    .limit_observation(self.context.clock.terminal_deadline());
            }
            self.append(
                &step,
                dispatched(observed.transport, observed.failure),
                false,
                Value::Null,
            )
            .await?;
            let result = observed
                .result
                .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
            let healthy = if server {
                result["membership"]["healthy"] == true
                    && voters.is_none_or(|n| {
                        result["membership"]["members"]
                            .as_array()
                            .is_some_and(|v| v.len() == n)
                    })
            } else {
                network::check_agent_view(
                    &self.context,
                    &self.members,
                    &cluster,
                    &result["agent_view"],
                )
                .is_ok()
            };
            if result["status"] != "ok"
                || healthy
                || dispatches == cap
                || tokio::time::Instant::now() + interval >= deadline
            {
                break result;
            }
            self.context.check()?;
            tokio::time::sleep(interval).await;
            self.local.step_deadline = Some(deadline);
        };
        require(result["status"] == "ok", super::server::refused(&result))?;
        self.settlement(&step, &result, &payload)?;
        let event = if server {
            json!({"type":"server-membership","member":self.members[index],
                "membership":result["membership"]})
        } else {
            json!({"type":"agent-membership","view":result["agent_view"]})
        };
        self.append(&step, event, true, Value::Null).await?;
        self.next_step += 1;
        let kind = if server {
            "server-membership"
        } else {
            "agent-membership"
        };
        let recorded = self.recorded_sequence(&step, kind)?;
        Ok((result, recorded))
    }

    async fn round(&mut self) -> Result<Vec<Value>> {
        let snapshot = self.local.snapshot()?;
        let cluster = snapshot.request["cluster"].clone();
        let sources: Vec<(Value, Value)> = snapshot
            .observations
            .iter()
            .filter(|o| o["event"]["type"] == "server-recipe")
            .map(|o| (o["sequence"].clone(), o["event"].clone()))
            .collect();
        let servers: Vec<usize> = (0..self.members.len())
            .filter(|&index| self.members[index]["role"] == "server")
            .collect();
        let (mut evidence, mut views, mut peers) = (Vec::new(), Vec::new(), Vec::new());
        for index in servers {
            let (sequence, event) = sources
                .iter()
                .find(|(_, event)| event["recipe"]["member"] == self.members[index])
                .cloned()
                .ok_or(Failure::Integrity)?;
            let payload = json!({"recipe_kind":event["recipe_kind"],"recipe":event["recipe"],
                "identity":null,"membership":null,"removed":null});
            let (result, recorded) = self
                .slot(index, "observe-membership", payload, sequence)
                .await?;
            let view = &result["membership"];
            require(
                view["healthy"] == true
                    && view["cluster"] == cluster
                    && view["node_uid"] == self.members[index]["node_uid"]
                    && view["observer"] == self.members[index]["machine"],
                Failure::Readiness,
            )?;
            evidence.push(recorded);
            views.push(view.clone());
            let machine = self.members[index]["machine"].as_str().unwrap_or("");
            peers.push(
                self.context
                    .selected
                    .declaration
                    .members
                    .iter()
                    .find(|m| m.machine == machine)
                    .map(|m| format!("https://{}:2380", m.node_ip))
                    .unwrap_or_default(),
            );
        }
        super::join::admit_views(&views, &peers)?;
        Ok(evidence)
    }

    async fn view(&mut self) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let cluster = snapshot.request["cluster"].clone();
        let (sequence, recipe) = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "agent-join-recipe")
            .map(|o| (o["sequence"].clone(), o["event"]["recipe"].clone()))
            .ok_or(Failure::Integrity)?;
        let payload = json!({"recipe":recipe,"identity":null,"agent_view":null});
        let (result, recorded) = self
            .slot(0, "observe-agent-membership", payload, sequence)
            .await?;
        network::check_agent_view(
            &self.context,
            &self.members,
            &cluster,
            &result["agent_view"],
        )
        .map_err(|failure| match failure {
            Failure::Ownership => Failure::Readiness,
            other => other,
        })?;
        Ok((result["agent_view"].clone(), recorded))
    }

    async fn gate(&mut self) -> Result<(Vec<Value>, Option<(Value, Value)>)> {
        let round = self.round().await?;
        let view = if self.members.iter().any(|m| m["role"] == "agent") {
            Some(self.view().await?)
        } else {
            None
        };
        Ok((round, view))
    }

    async fn observe(
        &mut self,
        index: usize,
        member: usize,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<()> {
        self.context.check()?;
        let previous = self.local.step_deadline;
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        self.local.step_deadline = Some(deadline);
        let step = self.intended(index, "lifecycle:node-observe-node", &payload, refs)?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let mut settled = None;
        for _ in 0..OBSERVE_CAP {
            if !dispatchable(deadline, tokio::time::Instant::now()) {
                break;
            }
            let observed = network::invoke(
                &self.context,
                &FAMILY,
                &binding,
                "observe-node",
                &payload,
                deadline,
                None,
            )
            .await;
            self.local.step_deadline = previous;
            if observed.failure.is_some() {
                self.local
                    .limit_observation(self.context.clock.terminal_deadline());
            }
            self.append(
                &step,
                dispatched(observed.transport, observed.failure),
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
            shape("observe-node", &result)?;
            let ready = result["node"]["ready"] == true;
            settled = Some(result);
            if ready {
                break;
            }
            self.context.check()?;
            self.local.step_deadline = Some(deadline);
        }
        self.local.step_deadline = previous;
        let result = settled.ok_or(Failure::Readiness)?;
        let observed = self.members[member].clone();
        self.append(
            &step,
            network::observation(&FAMILY, observed.clone(), &result),
            true,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        require(
            result["node"]["ready"] == true && result["node"]["member"] == observed["member"],
            Failure::Readiness,
        )
    }

    pub(super) async fn restart_sequence(&mut self, recipe: Value) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, "restart-recipe")?;
        let cluster = self.local.snapshot()?.request["cluster"].clone();
        let member = self
            .members
            .iter()
            .position(|m| *m == recipe["member"])
            .ok_or(Failure::Integrity)?;
        let server = recipe["member"]["role"] == "server";
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
        self.gate().await?;
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
        let (baseline, view) = self.gate().await?;
        let mut refs = vec![recipe_seq.clone()];
        refs.extend(baseline.iter().cloned());
        refs.extend(view.iter().map(|(_, sequence)| sequence.clone()));
        let payload = json!({"recipe":recipe,"expected":null,"wait_ms":null});
        if recipe.get("registries").is_some() {
            self.family_step(
                member,
                "configure-registries",
                payload.clone(),
                refs.clone(),
            )
            .await?;
        }
        let (step, restarted) = self.family_step(member, "restart", payload, refs).await?;
        let receipt = self.recorded_sequence(&step, "receiver")?;
        let entry = match &view {
            Some((view, _)) => Some(
                view["members"]
                    .as_array()
                    .and_then(|items| items.iter().find(|i| i["member"] == recipe["member"]))
                    .ok_or(Failure::Integrity)?,
            ),
            None => None,
        };
        let expected = expected(
            &recipe["member"],
            entry,
            &restarted["terminal"]["completed_ms"],
        );
        let mut refs = vec![recipe_seq, receipt];
        refs.extend(view.iter().map(|(_, sequence)| sequence.clone()));
        refs.sort_by_key(Value::as_u64);
        let payload = json!({"recipe":recipe,"expected":expected,"wait_ms":WAIT_MS});
        self.observe(if server { member } else { 0 }, member, payload, refs)
            .await?;
        if server || recipe["wave_end"] == true {
            if !server {
                self.view().await?;
            }
            let after = self.round().await?;
            require(
                self.round_members(&after)? == self.round_members(&baseline)?,
                Failure::Readiness,
            )?;
        }
        self.settle(&order).await
    }
}

pub(super) async fn restart_members(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    run(project, policy, target, None).await
}

pub(super) async fn run(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
    configure: Option<&str>,
) -> super::ExecutionResult<Snapshot> {
    require(!policy.cancellation.is_cancelled(), Failure::Cancelled)?;
    loop {
        let (mut session, recipe) = begin(
            project,
            super::issuer::duplicate(&policy)?,
            target,
            configure,
        )
        .await?;
        let last = recipe["position"].as_u64().map(|p| p + 1)
            == recipe["plan"]["members"]
                .as_array()
                .map(|members| members.len() as u64);
        let result = Box::pin(session.restart_sequence(recipe)).await;
        let snapshot = session
            .local
            .complete(result, &session.context.clock)
            .await?;
        if last {
            return Ok(snapshot);
        }
    }
}

