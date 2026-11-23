// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::provenance::{recipe_hash, recipe_identity};
use super::session::{Mode, Session, fresh};
use super::store::WaveRecord;
use super::{
    Failure, Result, Snapshot, Store, bootstrap, canonical, hash, nonce, require, rpc, schema,
    server,
};
use crate::k3s::protocol;
use serde_json::{Value, json};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub(super) async fn join_agents(
    project: &broil_config::LoadedProject,
    policy: super::super::Policy,
    target: &str,
    source: &str,
    destinations: &[String],
    width: u8,
) -> super::ExecutionResult<Snapshot> {
    require(
        !destinations.is_empty() && (1..=16).contains(&width),
        Failure::Configuration,
    )?;
    require(!policy.cancellation.is_cancelled(), Failure::Cancelled)?;
    let scope = super::scope(&project.broil_root, &policy.environment, target)?;
    let remaining = policy
        .deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .as_millis()
        .min(30_000) as u64;
    require(remaining > 0, Failure::Timeout)?;
    let mut store = Store::new(
        project.broil_root.clone(),
        scope,
        remaining,
        Arc::new(AtomicBool::new(false)),
    )?;
    let (previous, records) = store.agent_context()?;
    let owner = &previous.first().ok_or(Failure::Ownership)?.owner;
    let all: Vec<_> = owner["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|member| member["role"] == "agent")
        .collect();
    require(
        all.len() == destinations.len()
            && all
                .iter()
                .zip(destinations)
                .all(|(member, machine)| member["machine"] == *machine),
        Failure::Ownership,
    )?;
    let _ = source;
    let source = &super::join_source(owner, "")?;
    let (agents, start) = wave_start(owner, &records)?;
    let destinations: Vec<String> = agents
        .iter()
        .filter_map(|member| member["machine"].as_str().map(str::to_owned))
        .collect();
    store.release(
        policy
            .deadline
            .min(tokio::time::Instant::now() + Duration::from_secs(5)),
    )?;
    let batch = fresh()?;
    let mut last = None;
    for machine in &destinations[start..] {
        let credentials = policy
            .credentials
            .try_duplicate()
            .map_err(|_| Failure::Credential)?;
        let next_policy = super::super::Policy {
            environment: policy.environment.clone(),
            cwd: policy.cwd.clone(),
            environment_snapshot: policy.environment_snapshot.clone(),
            credentials,
            non_interactive: policy.non_interactive,
            deadline: policy.deadline,
            cancellation: policy.cancellation.clone(),
        };
        let wave = json!({"batch_id":batch,"size":usize::from(width).min(destinations.len() -
            destinations.iter().position(|item| item == machine).ok_or(Failure::Integrity)?),
            "single":false});
        let snapshot = Session::begin_join(
            project,
            next_policy,
            target,
            machine,
            source,
            true,
            Some(wave),
        )
        .await?
        .join_agent()
        .await?;
        last = Some(snapshot);
    }
    last.ok_or(Failure::Configuration.into())
}

pub(super) fn wave_start<'o>(
    owner: &'o Value,
    records: &[WaveRecord],
) -> Result<(Vec<&'o Value>, usize)> {
    let survivors = super::survivors(owner)?;
    let agents: Vec<&Value> = owner["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|member| member["role"] == "agent")
        .filter(|member| survivors.iter().any(|s| s == *member))
        .collect();
    require(!agents.is_empty(), Failure::Configuration)?;
    let pending = agents
        .iter()
        .position(|member| member["node_uid"].is_null());
    let start = if let Some(record) = records.last().filter(|record| record.gate.is_none()) {
        let selected = record.boundary["selected"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let name = selected
            .iter()
            .find(|name| {
                agents
                    .iter()
                    .any(|member| member["member"] == **name && member["node_uid"].is_null())
            })
            .or_else(|| selected.last())
            .ok_or(Failure::Integrity)?;
        agents
            .iter()
            .position(|member| member["member"] == *name)
            .ok_or(Failure::Ownership)?
    } else if let Some(index) = pending {
        index
    } else {
        agents.len() - 1
    };
    Ok((agents, start))
}

pub(in crate::k3s) fn wave_plan(
    previous: &[Snapshot],
    records: &[WaveRecord],
    width: usize,
) -> Result<Value> {
    let owner = &previous.first().ok_or(Failure::Ownership)?.owner;
    let source = super::join_source(owner, "")?;
    let (agents, start) = wave_start(owner, records)?;
    let waves: Vec<Vec<Value>> = agents[start..]
        .chunks(width.max(1))
        .map(|wave| {
            wave.iter()
                .map(|m| json!({"action":"join-agent","hosts":[source, m["machine"]]}))
                .collect()
        })
        .collect();
    Ok(json!({"waves": waves}))
}

fn succeeded(scope: &Value, snapshot: &Snapshot) -> bool {
    super::report::report(scope, "show", std::slice::from_ref(snapshot))
        .is_ok_and(|report| report["outcome"] == "succeeded" && report["cleanup_unknown"] == false)
}

pub(super) fn join_selection(members: &[Value], destination: &str) -> Result<bool> {
    let servers: Vec<_> = members.iter().filter(|m| m["role"] == "server").collect();
    let agents: Vec<_> = members.iter().filter(|m| m["role"] == "agent").collect();
    require(
        matches!(servers.len(), 1 | 3)
            && servers.iter().all(|m| m["node_uid"].is_string())
            && !agents.is_empty(),
        Failure::Configuration,
    )?;
    let selected = agents
        .iter()
        .position(|m| m["machine"] == destination)
        .ok_or(Failure::Configuration)?;
    let pending = agents
        .iter()
        .position(|m| m["node_uid"].is_null())
        .unwrap_or(agents.len());
    require(
        agents[..pending].iter().all(|m| m["node_uid"].is_string())
            && agents[pending..].iter().all(|m| m["node_uid"].is_null())
            && (selected < pending || selected == pending && pending < agents.len()),
        Failure::Configuration,
    )?;
    Ok(selected < pending)
}

pub(super) fn replacement_selection(members: &[Value], destination: &str) -> Result<bool> {
    let selected = members
        .iter()
        .find(|m| m["machine"] == destination && m["role"] == "agent")
        .ok_or(Failure::Configuration)?;
    require(
        members
            .iter()
            .filter(|m| m["role"] == "server")
            .all(|m| m["node_uid"].is_string()),
        Failure::Configuration,
    )?;
    Ok(selected["node_uid"].is_string())
}

pub(super) fn unit_text(owner: &str) -> Result<String> {
    let server = server::unit_text(owner);
    let agent = server
        .replace("Broil K3s server (", "Broil K3s agent (")
        .replace("broil-k3s server --config", "broil-k3s agent --config");
    require(
        server != agent && !agent.contains("broil-k3s server --config"),
        Failure::Integrity,
    )?;
    Ok(agent)
}

type WaveSelection = (Value, Value, Option<Value>, Vec<String>, bool);

pub(super) fn prior_recipe<'a>(
    context: &rpc::Context<'_>,
    previous: &'a [Snapshot],
    member: &Value,
) -> Result<&'a Value> {
    let matching = previous
        .iter()
        .filter(|s| {
            succeeded(&context.scope, s)
                && matches!(
                    s.request["action"].as_str(),
                    Some("join-server" | "join-agent")
                )
        })
        .flat_map(|s| s.observations.iter().map(move |o| (s, o)))
        .filter(|(_, o)| {
            matches!(
                o["event"]["type"].as_str(),
                Some("server-join-recipe" | "agent-join-recipe")
            ) && o["event"]["recipe"]["member"]["machine"] == member["machine"]
                && o["event"]["recipe"]["member"]["node_uid"].is_null()
        });
    Ok(&super::current_installation(matching)?["event"]["recipe"])
}

fn joining_operation(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    boundary: &Value,
    index: usize,
) -> Result<String> {
    let selected = &boundary["selected"][index];
    let boundary_hash = hash("broil-k3s-agent-wave-boundary-v1", boundary)?;
    let matching: Vec<_> = previous
        .iter()
        .filter(|snapshot| {
            snapshot.request["action"] == "join-agent"
                && !snapshot.request["consumer"].is_null()
                && succeeded(&context.scope, snapshot)
                && snapshot.observations.iter().any(|observation| {
                    let recipe = &observation["event"]["recipe"];
                    observation["event"]["type"] == "agent-join-recipe"
                        && recipe["wave"]["id"] == boundary["id"]
                        && recipe["wave"]["index"].as_u64() == Some(index as u64)
                        && recipe["wave"]["boundary_sha256"] == boundary_hash
                        && recipe["member"]["member"] == *selected
                        && recipe["member"]["node_uid"].is_null()
                })
        })
        .collect();
    require(matching.len() == 1, Failure::Ownership)?;
    Ok(matching[0].request["operation"]
        .as_str()
        .ok_or(Failure::Integrity)?
        .to_owned())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn select_wave(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    members: &[Value],
    source_recipe: &Value,
    records: &[WaveRecord],
    destination: &str,
    repeat: bool,
    input: &Value,
) -> Result<WaveSelection> {
    let batch = input["batch_id"].as_str().ok_or(Failure::Configuration)?;
    let width = usize::try_from(input["size"].as_u64().ok_or(Failure::Configuration)?)
        .map_err(|_| Failure::Configuration)?;
    require(
        nonce(batch) && (1..=usize::from(context.selected.agent_wave_size)).contains(&width),
        Failure::Configuration,
    )?;
    let member = members
        .iter()
        .find(|member| member["machine"] == destination)
        .ok_or(Failure::Configuration)?;
    let name = &member["member"];
    let replacing = name
        .as_str()
        .is_some_and(|n| super::member::replacing(previous, n).is_some());
    let participants = super::participants(&json!(members))?;
    let matching: Vec<_> = records
        .iter()
        .filter(|record| {
            record.boundary["selected"]
                .as_array()
                .is_some_and(|selected| selected.contains(name))
                && (!replacing
                    || super::participants(&record.boundary["members"])
                        .ok()
                        .as_ref()
                        == Some(&participants))
        })
        .collect();
    require(matching.len() <= 1, Failure::Ownership)?;
    let (boundary, fresh_boundary, gate_complete) = if let Some(record) = matching.first() {
        require(
            super::participants(&record.boundary["members"])?
                == super::participants(&json!(members))?
                && record.boundary["agent_wave_size"] == json!(context.selected.agent_wave_size),
            Failure::Ownership,
        )?;
        (record.boundary.clone(), None, record.gate.is_some())
    } else {
        require(
            !repeat && records.last().is_none_or(|record| record.gate.is_some()),
            Failure::Busy,
        )?;
        let active: Vec<_> = members
            .iter()
            .filter(|member| member["role"] != "backup")
            .collect();
        let pending = active
            .iter()
            .position(|member| member["node_uid"].is_null())
            .ok_or(Failure::Configuration)?;
        require(
            active[pending]["machine"] == destination && active[pending]["role"] == "agent",
            Failure::Configuration,
        )?;
        let mut installed = Vec::new();
        for member in &active[..pending] {
            let recipe = super::installation_recipe(context, previous, member, source_recipe)?;
            installed
                .push(json!({"member":member,"recipe_identity_sha256":recipe_identity(recipe)?}));
        }
        let wave_members: Vec<_> = active[pending..]
            .iter()
            .filter(|member| !replacing || member["node_uid"].is_null())
            .take(width)
            .collect();
        require(
            wave_members
                .iter()
                .all(|member| member["role"] == "agent" && member["node_uid"].is_null()),
            Failure::Configuration,
        )?;
        let selected: Vec<_> = wave_members
            .iter()
            .map(|member| member["member"].clone())
            .collect();
        require(
            !selected.is_empty() && selected.len() <= 16,
            Failure::Configuration,
        )?;
        let previous_gate = if let Some(record) = records.last() {
            let gate = record.gate.as_ref().ok_or(Failure::Busy)?;
            json!({"id":record.boundary["id"],"gate_sha256":hash("broil-k3s-agent-wave-gate-v1",gate)?})
        } else {
            Value::Null
        };
        let id = if input["single"] == true {
            batch.to_owned()
        } else {
            fresh()?
        };
        let boundary = json!({"schema":1,"kind":"agent-wave-boundary","scope":context.scope,
            "owner":source_recipe["owner"],"id":id,"batch_id":batch,
            "ordinal":records.len() + 1,"previous_gate":previous_gate,
            "cluster":previous.first().ok_or(Failure::Ownership)?.owner["cluster"],
            "members":members,"installed":installed,"selected":selected,
            "agent_wave_size":context.selected.agent_wave_size});
        schema::validate(&canonical(&boundary)?, "AgentWaveBoundary", 65_536)?;
        (boundary.clone(), Some(boundary), false)
    };
    let selected = boundary["selected"].as_array().ok_or(Failure::Integrity)?;
    let index = selected
        .iter()
        .position(|candidate| candidate == name)
        .ok_or(Failure::Ownership)?;
    let selected_len = selected.len();
    let prior_count = if repeat { index + 1 } else { index };
    let prior = (0..prior_count)
        .map(|i| joining_operation(context, previous, &boundary, i))
        .collect::<Result<Vec<_>>>()?;
    let wave = json!({"id":boundary["id"],"index":index,
        "boundary_sha256":hash("broil-k3s-agent-wave-boundary-v1", &boundary)?});
    let longest_operation = format!("infra-operation-{}", "f".repeat(32));
    let max_reference = json!({"operation":longest_operation,"sequence":4096});
    let max_gate = json!({"schema":1,"kind":"agent-wave-gate","scope":boundary["scope"],
        "owner":boundary["owner"],"id":boundary["id"],
        "boundary_sha256":wave["boundary_sha256"],
        "operations":vec![longest_operation.clone();selected_len],
        "observer_operation":longest_operation,"agent_view_ref":max_reference,
        "server_membership_refs":vec![max_reference;members.iter().filter(|m|m["role"] == "server").count()]});
    schema::validate(&canonical(&max_gate)?, "AgentWaveGate", 65_536)?;
    Ok((
        wave,
        boundary,
        fresh_boundary,
        prior,
        !gate_complete && index + 1 == selected_len,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn recipe_events(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    members: &Value,
    resources: &[Value],
    operation: &str,
    attempt: &str,
    source_recipe: &Value,
    repeat: bool,
    wave: &Value,
) -> Result<Vec<Value>> {
    let all = members.as_array().ok_or(Failure::Integrity)?;
    let selected_machine = resources.get(1).ok_or(Failure::Integrity)?["machine"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    let selected = all
        .iter()
        .position(|m| m["machine"] == selected_machine)
        .ok_or(Failure::Ownership)?;
    require(all[selected]["role"] == "agent", Failure::Ownership)?;
    let mut installed = Vec::new();
    let mut events = Vec::new();
    for (index, member) in all.iter().enumerate() {
        if index >= selected || member["role"] == "backup" || member["node_uid"].is_null() {
            continue;
        }
        let original = super::installation_recipe(context, previous, member, source_recipe)?;
        let initial = std::ptr::eq(original, source_recipe);
        let identity = recipe_identity(original)?;
        let mut recipe = original.clone();
        recipe["operation"] = json!(operation);
        recipe["attempt"] = json!(attempt);
        recipe["members"] = members.clone();
        recipe["member"] = member.clone();
        if !initial {
            recipe["source"] = super::acting_first(all, &member["machine"])
                .ok_or(Failure::Ownership)?
                .clone();
            recipe["installed"] = json!(installed);
        }
        require(recipe_identity(&recipe)? == identity, Failure::Ownership)?;
        installed.push(json!({"member":member,"recipe_identity_sha256":identity}));
        events.push(if member["role"] == "server" {
            json!({"type":"server-recipe","recipe_kind":if initial {"initial"} else {"join"},"recipe":recipe})
        } else {
            json!({"type":"agent-recipe","recipe":recipe})
        });
    }
    if repeat {
        let original = prior_recipe(context, previous, &all[selected])?;
        let mut recipe = original.clone();
        recipe["operation"] = json!(operation);
        recipe["attempt"] = json!(attempt);
        recipe["members"] = members.clone();
        recipe["member"] = all[selected].clone();
        recipe["source"] = super::acting_first(all, &all[selected]["machine"])
            .ok_or(Failure::Ownership)?
            .clone();
        recipe["installed"] = json!(installed);
        if all[selected]["node_uid"].is_null() {
            recipe["wave"] = wave.clone();
        }
        require(
            recipe_identity(&recipe)? == recipe_identity(original)?,
            Failure::Ownership,
        )?;
        events.push(json!({"type":"agent-join-recipe","recipe":recipe}));
        return Ok(events);
    }
    let replacing = all[selected]["member"]
        .as_str()
        .is_some_and(|n| super::member::replacing(previous, n).is_some());
    let marker_event = if replacing {
        bootstrap::replacement_generation(context, previous, selected_machine)
    } else {
        bootstrap::selection_generation(context, previous, members, selected_machine)?
    }
    .ok_or(Failure::Readiness)?;
    let declared = context
        .selected
        .declaration
        .members
        .iter()
        .find(|m| m.machine == selected_machine)
        .ok_or(Failure::Configuration)?;
    let base = server::rendered_config(
        context,
        source_recipe["owner"].as_str().ok_or(Failure::Integrity)?,
        declared,
    );
    let config = json!({
        "server":crate::k3s::origin(&context.selected.declaration.registration_endpoint),
        "token-file":server::owner_path(source_recipe["owner"].as_str().ok_or(Failure::Integrity)?, "active/agent-token"),
        "node-name":base["node-name"],"node-ip":base["node-ip"],
        "node-label":base["node-label"],"node-taint":base["node-taint"],
        "disable-default-registry-endpoint":true
    });
    let unit = unit_text(source_recipe["owner"].as_str().ok_or(Failure::Integrity)?)?;
    let recipe = json!({"schema":3,"scope":context.scope,"owner":source_recipe["owner"],
        "operation":operation,"attempt":attempt,
        "source":super::acting_first(all, &all[selected]["machine"]).ok_or(Failure::Ownership)?,
        "member":all[selected],
        "members":members,"cluster":previous.first().ok_or(Failure::Ownership)?.owner["cluster"],
        "installed":installed,"wave":wave,
        "assets":{"generation":marker_event["event"]["resource"]["generation"],
                  "marker_sha256":protocol::digest(&canonical(&marker_event["event"]["marker"])?),},
        "input":{"generation":resources[1]["generation"]},"source_input":resources[0],
        "version":source_recipe["version"],"executable":source_recipe["executable"],
        "archive":source_recipe["archive"],"guard_sha256":source_recipe["guard_sha256"],
        "unit_sha256":protocol::digest(unit.as_bytes()),
        "config":config,"api_endpoint":source_recipe["api_endpoint"]});
    schema::validate(&canonical(&recipe)?, "AgentJoinRecipe", 65_536)?;
    recipe_hash(&recipe)?;
    recipe_identity(&recipe)?;
    events.push(json!({"type":"agent-join-recipe","recipe":recipe}));
    Ok(events)
}

pub(super) fn preflight(
    context: &rpc::Context<'_>,
    owner: &Value,
    request: &Value,
    attempt: &Value,
    events: &[Value],
    members: &[Value],
) -> Result<()> {
    let length = |value: &Value| -> Result<usize> { Ok(canonical(value)?.len()) };
    let add = |parts: &[usize]| -> Result<usize> {
        parts.iter().try_fold(0usize, |total, part| {
            total.checked_add(*part).ok_or(Failure::Bound)
        })
    };
    let request_bytes = canonical(request)?;
    schema::validate(&request_bytes, "request", 262_144)?;
    require(
        request_bytes.len() < 262_144 && members.len() <= 128,
        Failure::Bound,
    )?;
    let attempt_bytes = canonical(attempt)?;
    schema::validate(&attempt_bytes, "attempt", 65_536)?;
    require(attempt_bytes.len() < 65_536, Failure::Bound)?;
    let owner_bytes = canonical(owner)?;
    schema::validate(&owner_bytes, "owner", 65_536)?;
    require(owner_bytes.len() < 65_536, Failure::Bound)?;
    let mut recipe_bytes = 0;
    let mut recipe_records = 0;
    for event in events {
        recipe_bytes = recipe_bytes.max(length(&event["recipe"])?);
        let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
            "owner":request["owner"],"operation":request["operation"],"sequence":4096,
            "recorded_ms":u64::MAX,"producer_ms":null,
            "source":{"kind":"controller","machine":null},"attempt":attempt["attempt"],
            "step":null,"dispatch":null,"event":event});
        let bytes = canonical(&observation)?;
        schema::validate(&bytes, "observation", 65_536)?;
        require(bytes.len() < 65_536, Failure::Bound)?;
        recipe_records = add(&[recipe_records, bytes.len() + 1])?;
    }
    let mut binding_bytes = 0;
    for member in members {
        let binding = json!({"scope":context.scope,"owner":request["owner"],
            "operation":request["operation"],"attempt":attempt["attempt"],
            "step":u32::MAX,"dispatch":"f".repeat(32),"recipient":member,
            "receiver_generation":u64::MAX,"request_sha256":"f".repeat(64),
            "participants_sha256":request["participants_sha256"],"fingerprints":context.fingerprints});
        binding_bytes = binding_bytes.max(length(&binding)?);
    }
    require(binding_bytes <= 4096, Failure::Bound)?;
    require(
        add(&[binding_bytes * 3, recipe_bytes, 16_384, 2048])? < 65_536,
        Failure::Bound,
    )?;
    require(
        add(&[binding_bytes, recipe_bytes, 16_384, 8196, 2048])? <= 65_536,
        Failure::Bound,
    )?;
    let count = attempt["steps"].as_array().ok_or(Failure::Integrity)?.len();
    require(count <= 1024, Failure::Bound)?;
    let servers = members.iter().filter(|m| m["role"] == "server").count();
    let repeat = request["consumer"].is_null();
    let lifecycle_slots = 3 * servers + if repeat { 6 } else { 10 };
    let membership_slots = 2 * servers + if repeat { 4 } else { 6 };
    let fixed_slot = add(&[binding_bytes * 3, 2048])?;
    let report_bound = add(&[
        request_bytes.len() + 1,
        attempt_bytes.len() + 1,
        owner_bytes.len() + 1,
        recipe_records * 2,
        count.checked_mul(fixed_slot).ok_or(Failure::Bound)?,
        lifecycle_slots
            .checked_mul(recipe_bytes * 2)
            .ok_or(Failure::Bound)?,
        membership_slots.checked_mul(16_384).ok_or(Failure::Bound)?,
    ])?;
    require(report_bound <= 1_048_576, Failure::Bound)
}

impl Session<'_> {
    pub(super) async fn join_agent(mut self) -> super::ExecutionResult<Snapshot> {
        let result = self.join_agent_work().await;
        self.local.complete(result, &self.context.clock).await
    }

    async fn restart_replaced(&mut self, selected: usize, inspected: Option<u64>) -> Result<()> {
        let (recipe, sequence) = self.agent_recipe()?;
        let inspected = inspected.ok_or(Failure::Integrity)?;
        let old = self
            .local
            .snapshot()?
            .observations
            .iter()
            .find(|o| o["sequence"] == inspected)
            .ok_or(Failure::Integrity)?["event"]["identity"]["node_uid"]
            .clone();
        require(old.is_string(), Failure::Ownership)?;
        let payload = json!({"recipe":recipe,"expected":{"node_uid":old,"pods":null,"after":null,
            "view":null},"wait_ms":null});
        self.member_step(
            selected,
            "start-member",
            payload,
            vec![json!(sequence), json!(inspected)],
        )
        .await?;
        let (post_start_view, post_start_sequence) = self.agent_view(selected, true).await?;
        let step = self.next_step;
        let observed = self
            .lifecycle_dispatch(
                step,
                selected,
                "observe-agent",
                json!({"recipe":recipe,"identity":null,"agent_view":post_start_view}),
                vec![json!(sequence), json!(post_start_sequence)],
                false,
            )
            .await?;
        let identity = observed.result["identity"].clone();
        require(
            observed.result["installation"]["class"] == "owned"
                && identity["node_uid"].is_string()
                && identity["node_uid"] != old,
            Failure::Readiness,
        )?;
        let installation = observed.observation.ok_or(Failure::Integrity)?;
        self.next_step += 1;
        let (view, view_sequence) = self.agent_view(selected, true).await?;
        require(
            view == post_start_view
                && identity["cluster"] == view["cluster"]
                && identity["node_uid"] == view["members"][selected]["uid"],
            Failure::Readiness,
        )?;
        let step = self.next_step;
        self.lifecycle_dispatch(
            step,
            selected,
            "publish-agent",
            json!({"recipe":recipe,"identity":identity,"agent_view":view}),
            vec![
                json!(sequence),
                json!(post_start_sequence),
                json!(installation),
                json!(view_sequence),
            ],
            true,
        )
        .await?;
        self.next_step += 1;
        let snapshot = self.local.snapshot()?;
        let owner = server::published_owner(&snapshot.owner, selected, &identity)?;
        let operation = snapshot.request["operation"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        self.local
            .work(move |store| store.replace_owner(owner, &operation))
            .await
    }

    fn agent_recipe(&self) -> Result<(Value, u64)> {
        let event = self
            .local
            .snapshot()?
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "agent-join-recipe")
            .ok_or(Failure::Integrity)?;
        Ok((
            event["event"]["recipe"].clone(),
            event["sequence"].as_u64().ok_or(Failure::Integrity)?,
        ))
    }

    async fn agent_view(
        &mut self,
        selected: usize,
        selected_present: bool,
    ) -> Result<(Value, u64)> {
        let (recipe, sequence) = self.agent_recipe()?;
        let step = self.next_step;
        let previous = self
            .local
            .snapshot()?
            .observations
            .iter()
            .rev()
            .find(|o| o["event"]["type"] == "agent-membership")
            .map(|o| o["sequence"].clone());
        let mut references = vec![json!(sequence)];
        if let Some(previous) = previous {
            references.push(previous);
        }
        self.agent_view_wait = selected_present;
        let observer = self
            .members
            .iter()
            .position(|m| Some(m) == super::acting_first(&self.members, &Value::Null))
            .ok_or(Failure::Ownership)?;
        let dispatched = self
            .lifecycle_dispatch(
                step,
                observer,
                "observe-agent-membership",
                json!({"recipe":recipe,"identity":null,"agent_view":null}),
                references,
                false,
            )
            .await;
        self.agent_view_wait = false;
        let result = dispatched?;
        self.next_step += 1;
        let view = result.result["agent_view"].clone();
        require(
            view["cluster"] == self.local.snapshot()?.request["cluster"]
                && view["observer"] == self.members[observer]
                && view["foreign"] == json!([]),
            Failure::Ownership,
        )?;
        let entries = view["members"].as_array().ok_or(Failure::Integrity)?;
        require(entries.len() == self.members.len(), Failure::Readiness)?;
        for (index, (member, entry)) in self.members.iter().zip(entries).enumerate() {
            require(entry["member"] == *member, Failure::Ownership)?;
            if member["role"] == "backup" || member["node_uid"].is_null() && index != selected {
                require(
                    entry["present"] == false
                        && entry["uid"].is_null()
                        && entry["ready"] == false
                        && entry["roles"] == json!([])
                        && entry["labels"] == json!([])
                        && entry["taints"] == json!([]),
                    Failure::Ownership,
                )?;
                continue;
            }
            if index == selected && member["node_uid"].is_null() && !selected_present {
                require(
                    entry["present"] == false && entry["uid"].is_null(),
                    Failure::Ownership,
                )?;
                continue;
            }
            let role = if member["role"] == "server" {
                "server"
            } else {
                "agent"
            };
            require(
                entry["present"] == true
                    && entry["ready"] == true
                    && entry["roles"] == json!([role])
                    && (member["node_uid"].is_null()
                        && index == selected
                        && entry["uid"].is_string()
                        || entry["uid"] == member["node_uid"]),
                Failure::Readiness,
            )?;
            let declared = self
                .context
                .selected
                .declaration
                .members
                .iter()
                .find(|d| d.machine == member["machine"])
                .ok_or(Failure::Configuration)?;
            let config = server::rendered_config(
                &self.context,
                self.local.snapshot()?.request["owner"]
                    .as_str()
                    .ok_or(Failure::Integrity)?,
                declared,
            );
            require(
                entry["labels"] == config["node-label"] && entry["taints"] == config["node-taint"],
                Failure::Ownership,
            )?;
        }
        let event = self
            .local
            .snapshot()?
            .observations
            .iter()
            .rev()
            .find(|o| o["step"] == step && o["event"]["type"] == "agent-membership")
            .ok_or(Failure::Integrity)?;
        Ok((view, event["sequence"].as_u64().ok_or(Failure::Integrity)?))
    }

    async fn join_agent_work(&mut self) -> Result<Snapshot> {
        let request = &self.local.snapshot()?.request;
        require(request["action"] == "join-agent", Failure::Capability)?;
        let pair = request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        require(
            pair.len() == 2
                && (request["consumer"].is_null()
                    || super::acting_first(&self.members, &pair[1]["machine"])
                        .is_some_and(|m| m["machine"] == pair[0]["machine"])),
            Failure::Ownership,
        )?;
        let selected = self
            .members
            .iter()
            .position(|m| m["machine"] == pair[1]["machine"])
            .ok_or(Failure::Integrity)?;
        let servers: Vec<_> = self
            .members
            .iter()
            .enumerate()
            .filter_map(|(i, m)| (m["role"] == "server").then_some(i))
            .collect();
        let repeat = request["consumer"].is_null();
        let same = repeat && self.members[selected]["node_uid"].is_null();
        require(
            matches!(servers.len(), 1 | 3)
                && self.members[selected]["role"] == "agent"
                && (same || repeat == self.members[selected]["node_uid"].is_string()),
            Failure::Ownership,
        )?;
        let cluster = request["cluster"].clone();
        let mut order: Vec<_> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        for &index in &order {
            let owner = self
                .inspect_step(index, "owner", Value::Null, Value::Null)
                .await?;
            require(
                owner["status"] == "ok"
                    && owner["data"]["claim"]["active_attempt"].is_null()
                    && owner["data"]["ownership"]["cluster"] == cluster
                    && ["machine", "member", "role", "node_uid"].iter().all(|key| {
                        owner["data"]["ownership"]["machine"][*key] == self.members[index][*key]
                            || same && index == selected && *key == "node_uid"
                    }),
                Failure::Ownership,
            )?;
            self.generations[index] = owner["data"]["claim"]["generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?;
            let writer = self
                .inspect_step(index, "writer", Value::Null, Value::Null)
                .await?;
            require(
                matches!(writer["status"].as_str(), Some("ok" | "absent")),
                Failure::Ownership,
            )?;
        }
        for &index in &servers {
            let (recipe, kind, sequence) = self.join_recipe(index, false)?;
            let tag = if kind == "initial" {
                "inspect-installation"
            } else {
                "inspect-owned-server"
            };
            let payload = if kind == "initial" {
                json!({"recipe":recipe,"identity":null})
            } else {
                json!({"recipe_kind":kind,"recipe":recipe,"identity":null,"membership":null,"removed":null})
            };
            let step = self.next_step;
            let result = self
                .lifecycle_dispatch(step, index, tag, payload, vec![json!(sequence)], false)
                .await?;
            require(
                result.result["installation"]["class"] == "owned",
                Failure::Ownership,
            )?;
            self.next_step += 1;
        }
        let (recipe, sequence) = self.agent_recipe()?;
        let step = self.next_step;
        let result = self
            .lifecycle_dispatch(
                step,
                selected,
                "inspect-agent",
                json!({"recipe":recipe,"identity":null,"agent_view":null}),
                vec![json!(sequence)],
                false,
            )
            .await?;
        let inspected = result.observation;
        require(
            result.result["installation"]["class"] == if repeat { "owned" } else { "absent" },
            Failure::Ownership,
        )?;
        self.next_step += 1;
        if !repeat {
            for resource in &pair {
                let index = self
                    .members
                    .iter()
                    .position(|m| m["machine"] == resource["machine"])
                    .ok_or(Failure::Integrity)?;
                let result = self
                    .inspect_step(index, "resource", Value::Null, resource.clone())
                    .await?;
                require(result["status"] == "absent", Failure::Ownership)?;
            }
        }
        self.agent_view(selected, repeat && !same).await?;
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
        self.membership_round(&servers, servers.len(), false)
            .await?;
        self.agent_view(selected, repeat && !same).await?;
        if same {
            self.restart_replaced(selected, inspected).await?;
        } else if repeat {
            let (recipe, sequence) = self.agent_recipe()?;
            let (view, view_sequence) = self.agent_view(selected, true).await?;
            let step = self.next_step;
            let result = self
                .lifecycle_dispatch(
                    step,
                    selected,
                    "observe-agent",
                    json!({"recipe":recipe,"identity":null,"agent_view":view}),
                    vec![json!(sequence), json!(view_sequence)],
                    false,
                )
                .await?;
            require(
                result.result["installation"]["class"] == "owned"
                    && result.result["identity"]["node_uid"] == self.members[selected]["node_uid"],
                Failure::Readiness,
            )?;
            self.next_step += 1;
        } else {
            self.consume().await?;
            for resource in &pair {
                let index = self
                    .members
                    .iter()
                    .position(|m| m["machine"] == resource["machine"])
                    .ok_or(Failure::Integrity)?;
                let result = self
                    .inspect_step(index, "resource", Value::Null, resource.clone())
                    .await?;
                require(
                    result["status"] == "ok"
                        && result["data"]["resource"]["identity"].is_array()
                        && result["data"]["resource"]["inactive"] == true,
                    Failure::Ownership,
                )?;
            }
            let (recipe, sequence) = self.agent_recipe()?;
            let payload = || json!({"recipe":recipe,"identity":null,"agent_view":null});
            let step = self.next_step;
            self.lifecycle_dispatch(
                step,
                selected,
                "activate-agent",
                payload(),
                vec![json!(sequence)],
                true,
            )
            .await?;
            self.next_step += 1;
            self.pre_start_render(selected).await?;
            let (_, before_start_sequence) = self.agent_view(selected, false).await?;
            let step = self.next_step;
            self.lifecycle_dispatch(
                step,
                selected,
                "start-agent",
                payload(),
                vec![json!(sequence), json!(before_start_sequence)],
                true,
            )
            .await?;
            self.next_step += 1;
            let (post_start_view, post_start_sequence) = self.agent_view(selected, true).await?;
            let step = self.next_step;
            let observed = self
                .lifecycle_dispatch(
                    step,
                    selected,
                    "observe-agent",
                    json!({"recipe":recipe,"identity":null,"agent_view":post_start_view}),
                    vec![json!(sequence), json!(post_start_sequence)],
                    false,
                )
                .await?;
            require(
                observed.result["installation"]["class"] == "started"
                    && observed.result["identity"]["node_uid"].is_string(),
                Failure::Readiness,
            )?;
            let identity = observed.result["identity"].clone();
            let installation = observed.observation.ok_or(Failure::Integrity)?;
            self.next_step += 1;
            let (view, view_sequence) = self.agent_view(selected, true).await?;
            require(
                view == post_start_view
                    && identity["cluster"] == view["cluster"]
                    && identity["node_uid"] == view["members"][selected]["uid"],
                Failure::Readiness,
            )?;
            let observed_step = self
                .local
                .snapshot()?
                .steps
                .iter()
                .find(|record| record["step"] == step)
                .ok_or(Failure::Integrity)?;
            require(
                observed_step["payload_observations"] == json!([sequence, post_start_sequence])
                    && sequence < post_start_sequence
                    && post_start_sequence < installation
                    && installation < view_sequence,
                Failure::Integrity,
            )?;
            let step = self.next_step;
            let references = vec![
                json!(sequence),
                json!(post_start_sequence),
                json!(installation),
                json!(view_sequence),
            ];
            self.lifecycle_dispatch(
                step,
                selected,
                "publish-agent",
                json!({"recipe":recipe,"identity":identity,"agent_view":view}),
                references,
                true,
            )
            .await?;
            self.next_step += 1;
            let snapshot = self.local.snapshot()?;
            let mut owner = server::published_owner(&snapshot.owner, selected, &identity)?;
            owner["resources"]
                .as_array_mut()
                .ok_or(Failure::Integrity)?
                .extend(pair);
            let operation = snapshot.request["operation"]
                .as_str()
                .ok_or(Failure::Integrity)?
                .to_owned();
            self.local
                .work(move |store| store.replace_owner(owner, &operation))
                .await?;
        }
        let gate_refs = if self.wave_gate_needed {
            let (_, view_sequence) = self.agent_view(selected, true).await?;
            let server_sequences = self
                .membership_round(&servers, servers.len(), false)
                .await?;
            Some((view_sequence, server_sequences))
        } else {
            None
        };
        let settled = self.settle(&order).await?;
        if let Some((view_sequence, server_sequences)) = gate_refs {
            let boundary = self.wave_boundary.as_ref().ok_or(Failure::Integrity)?;
            let operation = settled.request["operation"]
                .as_str()
                .ok_or(Failure::Integrity)?;
            let mut operations = self.wave_operations.clone();
            if !repeat || same {
                operations.push(operation.to_owned());
            }
            let gate = json!({"schema":1,"kind":"agent-wave-gate","scope":self.context.scope,
                "owner":settled.request["owner"],"id":boundary["id"],
                "boundary_sha256":hash("broil-k3s-agent-wave-boundary-v1", boundary)?,
                "operations":operations,"observer_operation":operation,
                "agent_view_ref":{"operation":operation,"sequence":view_sequence},
                "server_membership_refs":server_sequences.into_iter().map(|sequence|
                    json!({"operation":operation,"sequence":sequence})).collect::<Vec<_>>()});
            schema::validate(&canonical(&gate)?, "AgentWaveGate", 65_536)?;
            self.local.work(move |store| store.wave_gate(gate)).await?;
        }
        Ok(settled)
    }
}

