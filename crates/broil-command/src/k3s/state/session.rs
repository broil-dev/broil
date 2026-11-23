// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::Policy;
use super::{Failure, Result, Snapshot, Store, hash, require, rpc};
use broil_config::LoadedProject;
use broil_core::secret::path_safety::sudo_nonce;
use broil_remote::scheduler::CancellationToken;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(super) fn fresh() -> Result<String> {
    sudo_nonce().map_err(|_| Failure::Storage)
}
pub(super) fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Storage)?
        .as_millis()
        .try_into()
        .map_err(|_| Failure::Bound)
}

pub(super) struct Local {
    store: Option<Store>,
    cancelled: Arc<AtomicBool>,
    deadline: tokio::time::Instant,
    cancellation: CancellationToken,
    pub(super) step_deadline: Option<tokio::time::Instant>,
    last_snapshot: Option<Snapshot>,
    pub(super) completion_unknown: bool,
    pub(super) cleanup_unknown: bool,
    pub(super) failure_detail: Option<&'static str>,

}

struct PendingStore(Option<Store>);

impl Drop for PendingStore {
    fn drop(&mut self) {
        std::mem::forget(self.0.take());
    }
}

impl Local {
    pub(super) fn new(context: &rpc::Context<'_>) -> Result<Self> {
        let deadline = context.clock.deadline();
        let remaining = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis();
        require(remaining > 0, Failure::Timeout)?;
        let cancelled = Arc::new(AtomicBool::new(context.policy.cancellation.is_cancelled()));
        let mut store = Store::new(
            context.project.broil_root.clone(),
            context.scope.clone(),
            remaining.min(7_200_000) as u64,
            cancelled.clone(),
        )?;
        store.bind_clock(context.clock.clone());
        Ok(Self {
            store: Some(store),
            cancelled,
            deadline,
            cancellation: context.policy.cancellation.clone(),
            step_deadline: None,
            last_snapshot: None,
            completion_unknown: false,
            cleanup_unknown: false,
            failure_detail: None,

        })
    }

    pub(super) async fn work<T: Send + 'static>(
        &mut self,
        action: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        if self.cancellation.is_cancelled() {
            self.cancelled.store(true, Ordering::Release);
            return Err(Failure::Cancelled);
        }
        require(
            tokio::time::Instant::now() < self.deadline,
            Failure::Timeout,
        )?;
        let deadline = self
            .deadline
            .min(self.step_deadline.unwrap_or(self.deadline))
            .min(tokio::time::Instant::now() + Duration::from_secs(30));
        require(tokio::time::Instant::now() < deadline, Failure::Timeout)?;
        let store = self.store.take().ok_or(Failure::Busy)?;
        if let Ok(snapshot) = store.snapshot() {
            self.last_snapshot = Some(snapshot.clone());
        }
        let mut pending = PendingStore(Some(store));

        let task = tokio::task::spawn_blocking(move || {
            let store = pending.0.as_mut().expect("owned store");
            let remaining = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(30_000) as u64;
            let result = store.constrain_work(remaining).and_then(|()| action(store));

            (pending, result)
        });
        let completed = tokio::select! {
            biased;
            _=self.cancellation.cancelled()=>Err(Failure::Cancelled),
            result=tokio::time::timeout_at(deadline,task)=>match result {
                Ok(Ok(value))=>Ok(value),Ok(Err(_))=>Err(Failure::Storage),Err(_)=>Err(Failure::Timeout),
            },
        };
        match completed {
            Ok((mut pending, result)) => {
                self.store = pending.0.take();
                if let Ok(snapshot) = self.snapshot() {
                    self.last_snapshot = Some(snapshot.clone());
                }
                result
            }
            Err(failure) => {
                self.cancelled.store(true, Ordering::Release);
                Err(failure)
            }
        }
    }

    pub(super) fn snapshot(&self) -> Result<&Snapshot> {
        self.store.as_ref().ok_or(Failure::Busy)?.snapshot()
    }

    pub(super) async fn finish(
        &mut self,
        clock: &broil_remote::exec::private::ActionClock,
    ) -> Result<()> {
        let until = clock.local_release_deadline(&self.cancellation);
        if until <= tokio::time::Instant::now() {
            let mut store = self.store.take().ok_or(Failure::Busy)?;
            let result = store.dispose();
            drop(store);
            if result.is_err() {
                clock.abort();
            }
            return result;
        }
        let mut pending = PendingStore(Some(self.store.take().ok_or(Failure::Busy)?));

        let mut task = tokio::task::spawn_blocking(move || {
            let result = pending.0.as_mut().expect("owned store").release(until);

            (pending, result)
        });
        let result = async {
            let completed = tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => {
                    clock.abort();
                    tokio::time::timeout_at(until, &mut task).await
                }
                completed = tokio::time::timeout_at(until, &mut task) => completed,
            };
            let (mut pending, result) = completed
                .map_err(|_| Failure::Timeout)?
                .map_err(|_| Failure::Storage)?;
            drop(pending.0.take());
            result
        }
        .await;
        if result.is_err() {
            clock.abort();
        }
        result
    }

    pub(super) fn limit_observation(&mut self, until: tokio::time::Instant) {
        self.step_deadline = Some(self.step_deadline.map_or(until, |old| old.min(until)));
    }

    pub(super) async fn failure(
        &mut self,
        failure: Failure,
        clock: &broil_remote::exec::private::ActionClock,
    ) -> super::ExecutionFailure {
        clock.abort();
        let snapshot = self
            .snapshot()
            .ok()
            .cloned()
            .or_else(|| self.last_snapshot.clone())
            .map(Box::new);
        let completion_unknown = self.completion_unknown
            || self.store.is_none()
            || self
                .store
                .as_ref()
                .is_some_and(|s| s.publication() == super::Publication::PossiblyPublished);
        let released = self.finish(clock).await;
        let cleanup_unknown = self.cleanup_unknown || released.is_err();
        super::ExecutionFailure {
            failure,
            completion_unknown,
            cleanup_unknown,
            snapshot,
            detail: self.failure_detail,
        }
    }

    pub(super) async fn complete<T>(
        &mut self,
        result: Result<T>,
        clock: &broil_remote::exec::private::ActionClock,
    ) -> super::ExecutionResult<T> {
        match result {
            Err(failure) => Err(self.failure(failure, clock).await),
            Ok(value) => {
                let snapshot = self
                    .snapshot()
                    .ok()
                    .cloned()
                    .or_else(|| self.last_snapshot.clone())
                    .map(Box::new);
                match self.finish(clock).await {
                    Ok(()) => Ok(value),
                    Err(failure) => Err(super::ExecutionFailure {
                        failure,
                        completion_unknown: false,
                        cleanup_unknown: true,
                        snapshot,
                        detail: None,
                    }),
                }
            }
        }
    }

    pub(super) async fn append(
        &mut self,
        step: Option<&Value>,
        event: Value,
        machine: Option<&Value>,
        producer: Value,
    ) -> Result<()> {
        let request = &self.snapshot()?.request;
        let observation = json!({"schema":1,"kind":"observation","scope":request["scope"],"owner":request["owner"],
            "operation":request["operation"],"sequence":1,"recorded_ms":now()?,"producer_ms":producer,
            "source":{"kind":if machine.is_some(){"receiver"}else{"controller"},"machine":machine.cloned().unwrap_or(Value::Null)},
            "attempt":step.map(|s|&s["attempt"]),"step":step.map(|s|&s["step"]),"dispatch":step.map(|s|&s["dispatch"]),"event":event});
        self.work(move |store| store.append(observation)).await
    }
}

pub(super) fn acquire_payload(snapshot: &Snapshot, members: &[Value]) -> Result<Value> {
    let sequence = snapshot.request["sequence"]
        .as_u64()
        .ok_or(Failure::Integrity)?;
    let (_, excluded) = selection(snapshot)?;
    Ok(
        json!({"members":members,"excluded":excluded,"sequence":sequence,
        "reserve":snapshot.attempts.len() > 1}),
    )
}

pub(super) fn selection(snapshot: &Snapshot) -> Result<(Vec<Value>, Value)> {
    let members = snapshot.request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .clone();
    let excepted = matches!(
        snapshot.request["action"].as_str(),
        Some("node-drain" | "node-remove")
    );
    let recipe = snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "member-recipe")
        .map(|o| &o["event"]["recipe"]);
    let Some(recipe) = recipe.filter(|r| excepted && r["reachability"] == "unreachable") else {
        return Ok((members, Value::Null));
    };
    let member = members
        .iter()
        .find(|m| m["member"] == recipe["member"]["member"])
        .cloned()
        .ok_or(Failure::Integrity)?;
    let acquired = members.into_iter().filter(|m| *m != member).collect();
    Ok((acquired, json!({"member":member,"reason":"unreachable"})))
}

pub(super) fn replacement_host(snapshot: &Snapshot) -> Result<Option<Value>> {
    let request = &snapshot.request;
    let resources = request["resources"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let [resource] = resources else {
        return Ok(None);
    };
    if request["action"] != "prepare-hosts"
        || request["cluster"].is_null()
        || resource["kind"] != "bootstrap-assets"
    {
        return Ok(None);
    }
    request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|m| m["machine"] == resource["machine"])
        .cloned()
        .map(Some)
        .ok_or(Failure::Integrity)
}

pub(super) fn reserve_admits(request: &Value, cluster: &Value) -> bool {
    *cluster == request["cluster"]
        || (cluster.is_null()
            && request["action"] == "create-server"
            && !request["cluster"].is_null())
}

pub(super) struct Session<'a> {
    pub(super) context: rpc::Context<'a>,
    pub(super) local: Local,
    pub(super) attempt: Value,
    pub(super) members: Vec<Value>,
    pub(super) generations: Vec<u64>,
    pub(super) next_step: u64,
    pub(super) consumer: Option<super::super::Prepared<'a>>,
    pub(super) existing_resources: bool,
    pub(super) mode: Mode,
    pub(super) retry_input: Option<(usize, Value)>,
    pub(super) agent_view_wait: bool,
    pub(super) wave_boundary: Option<Value>,
    pub(super) wave_operations: Vec<String>,
    pub(super) wave_gate_needed: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    Acquiring,
    Work,
    SettlementOnly,
}

pub(super) fn selects_survivors(owned: &Value, members: &Value) -> Result<bool> {
    Ok(json!(super::survivors(owned)?) == *members)
}

pub(super) fn unchecked_claim(existing_resources: bool, approval: &Value, action: &Value) -> bool {
    !existing_resources
        && approval.is_null()
        && action != "prepare-server-inputs"
        && action != "prepare-node-registry"
}

pub(super) fn settled(report: &Value) -> Result<()> {
    require(
        matches!(
            report["outcome"].as_str(),
            Some("succeeded" | "failed" | "cancelled")
        ) && report["completion_unknown"] == false
            && report["cleanup_unknown"] == false,
        Failure::Busy,
    )
}

pub(super) fn inspected<'v>(
    selected: &'v [Value],
    member: &'v Value,
) -> impl Iterator<Item = &'v Value> {
    selected
        .iter()
        .filter(move |r| r["machine"] == member["machine"])
}

impl<'a> Session<'a> {
    pub(super) async fn begin(
        project: &'a LoadedProject,
        policy: Policy,
        target: &str,
    ) -> super::ExecutionResult<Self> {
        Self::begin_work(project, policy, target, None, false, None).await
    }

    pub(super) async fn begin_consumer(
        project: &'a LoadedProject,
        policy: Policy,
        target: &str,
        destination: &str,
        operation: super::super::Operation,
    ) -> super::ExecutionResult<Self> {
        Self::begin_work(
            project,
            policy,
            target,
            Some((destination, operation)),
            false,
            None,
        )
        .await
    }

    pub(super) async fn begin_join(
        project: &'a LoadedProject,
        policy: Policy,
        target: &str,
        destination: &str,
        source: &str,
        agent: bool,
        wave: Option<Value>,
    ) -> super::ExecutionResult<Self> {
        Self::begin_work(
            project,
            policy,
            target,
            Some((
                destination,
                if agent {
                    super::super::Operation::AgentJoin {
                        source: source.into(),
                    }
                } else {
                    super::super::Operation::ServerJoin {
                        source: source.into(),
                    }
                },
            )),
            true,
            wave,
        )
        .await
    }

    async fn begin_work(
        project: &'a LoadedProject,
        policy: Policy,
        target: &str,
        mut consumer: Option<(&str, super::super::Operation)>,
        join: bool,
        wave: Option<Value>,
    ) -> super::ExecutionResult<Self> {
        let context = rpc::Context::new(project, policy, target)?;
        let mut local = Local::new(&context)?;
        let prepared: Result<_> = async {
        let server_inputs = consumer.as_ref().is_some_and(|(_, action)| {
            matches!(action, super::super::Operation::ServerJoin { .. })
        });
        let agent_inputs = consumer.as_ref().is_some_and(|(_, action)| {
            matches!(action, super::super::Operation::AgentJoin { .. })
        });
        let (previous, wave_records) = if agent_inputs && join {
            local.work(|store| store.agent_context()).await?
        } else {
            (local.work(|store| store.read_operations(None).map_err(|e|e.failure)).await?, Vec::new())
        };
        for snapshot in &previous {
            let report =
                super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?;
            settled(&report)?;
        }
        let join_inputs = server_inputs || agent_inputs;
        require(!join || join_inputs, Failure::Capability)?;
        require(agent_inputs == wave.is_some(), Failure::Capability)?;
        let mut members = if join {
            json!(super::survivors(&previous.first().ok_or(Failure::Ownership)?.owner)?)
        } else {
            context.authenticate().await?
        };
        let join_destination = consumer.as_ref().map(|(destination, _)| (*destination).to_owned());
        let mut join_repeat = false;
        let mut join_replacing = false;
        let mut same_machine = false;
        if join_inputs {
            let owned = &previous.first().ok_or(Failure::Ownership)?.owner;
            if !join {
                context.authenticate_owned(&owned["members"]).await?;
            }
            require(
                !owned["cluster"].is_null()
                    && owned["fingerprints"] == context.owner_fingerprints
                    && owned["participants_sha256"] == super::participants(&members)?,
                Failure::Ownership,
            )?;
            members = json!(super::survivors(owned)?);
            if join {
                consumer = consumer
                    .map(|(destination, action)| {
                        let source = super::join_source(owned, destination)?;
                        Ok::<_, Failure>((destination, match action {
                            super::super::Operation::ServerJoin { .. } => {
                                super::super::Operation::ServerJoin { source }
                            }
                            super::super::Operation::AgentJoin { .. } => {
                                super::super::Operation::AgentJoin { source }
                            }
                            other => other,
                        }))
                    })
                    .transpose()?;
            }
            if join {
                let destination = consumer.as_ref().ok_or(Failure::Integrity)?.0;
                let transition = members.as_array().ok_or(Failure::Integrity)?.iter()
                    .find(|m| m["machine"] == destination)
                    .and_then(|m| m["member"].as_str())
                    .and_then(|name| super::member::replacing(&previous, name));
                let replacing = transition.is_some();
                join_replacing = replacing;
                same_machine = agent_inputs && transition.is_some_and(|t| t["same_machine"] == true);
                if agent_inputs {
                    join_repeat = if replacing {
                        super::agent::replacement_selection(members.as_array().ok_or(Failure::Integrity)?, destination)?
                    } else {
                        super::agent::join_selection(members.as_array().ok_or(Failure::Integrity)?, destination)?
                    };
                } else {
                    let servers: Vec<_> = members.as_array().ok_or(Failure::Integrity)?.iter()
                        .filter(|m| m["role"] == "server").collect();
                    join_repeat = if replacing {
                        super::join::replacement_selection(&servers, destination)?
                    } else {
                        super::join::join_selection(&servers, destination)?
                    };
                }
            }
        }
        let owner = previous
            .first()
            .map(|s| {
                s.owner["owner"]
                    .as_str()
                    .ok_or(Failure::Integrity)
                    .map(str::to_owned)
            })
            .transpose()?
            .map_or_else(fresh, Ok)?;
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt = fresh()?;
        let created = now()?;
        let participants = super::participants(&members)?;
        let consumer = match if join_repeat || same_machine {None} else {consumer} {
            None => None,
            Some((destination, action)) => {
                require(
                    matches!(action, super::super::Operation::InitialServer | super::super::Operation::ServerJoin { .. } | super::super::Operation::AgentJoin { .. }),
                    Failure::Capability,
                )?;
                let p = &context.policy;
                let policy = Policy {
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
                let cluster = previous.first().map(|s| &s.owner["cluster"]);
                let source_uid = match &action {
                    super::super::Operation::ServerJoin { source } | super::super::Operation::AgentJoin { source } => members
                        .as_array()
                        .and_then(|items| items.iter().find(|m| m["machine"] == *source))
                        .and_then(|m| m["node_uid"].as_str())
                        .map(str::to_owned),
                    _ => None,
                };
                let generation = super::super::Generation {
                    owner: owner.clone(),
                    operation: operation.clone(),
                    attempt: attempt.clone(),
                    resource: if join_inputs { fresh()? } else { "initial-server".into() },
                    generation: fresh()?,
                    resource_uid: None,
                    cluster: if join_inputs {
                        let cluster = cluster.ok_or(Failure::Ownership)?;
                        Some(super::super::Cluster {
                            uid: cluster["uid"].as_str().ok_or(Failure::Integrity)?.into(),
                            ca_sha256: cluster["ca_sha256"].as_str().ok_or(Failure::Integrity)?.into(),
                        })
                    } else { None },
                    destination_uid: None,
                    source_uid,
                };
                Some(
                    super::super::prepare(project, policy, target, destination, generation, action)
                        .map_err(|_| Failure::Configuration)?,
                )
            }
        };
        let resources:Vec<Value>=if join_repeat || same_machine {
            previous.iter().find(|s| s.request["action"] == if agent_inputs {"join-agent"} else {"join-server"}
                && s.observations.iter().any(|o| o["event"]["type"] == if agent_inputs {"agent-join-recipe"} else {"server-join-recipe"}
                    && o["event"]["recipe"]["member"]["machine"] == join_destination.as_deref().unwrap_or("")))
                .ok_or(Failure::Ownership)?.request["resources"].as_array().ok_or(Failure::Integrity)?.clone()
        } else {consumer.iter().flat_map(|prepared|{
            let r=&prepared.base["resource"];
            let machines = if join_inputs {
                vec![prepared.source.as_deref().unwrap_or(""), prepared.destination.as_str()]
            } else { vec![prepared.destination.as_str()] };
            machines.into_iter().map(|machine| json!({"kind":r["kind"],"id":r["id"],"owner":owner,"generation":r["generation"],"machine":machine,
                "path":format!("/var/lib/broil/k3s/owners/{}/resources/{}/{}",owner,r["id"].as_str().unwrap_or(""),r["generation"].as_str().unwrap_or("")),
                "namespace":null,"name":null,"uid":r["uid"]})).collect::<Vec<_>>()
        }).collect()};
        if join_repeat || same_machine {
            let retained = previous.first().ok_or(Failure::Ownership)?.owner["resources"].as_array().ok_or(Failure::Integrity)?;
            require(resources.len() == 2 && resources.iter().all(|resource| retained.contains(resource)), Failure::Ownership)?;
        }
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":owner,"operation":operation,
            "created_ms":created,"sequence":request_sequence,"action":if agent_inputs {"join-agent"} else if join {"join-server"} else if server_inputs {"prepare-server-inputs"} else {"prepare-state"},"members":members,
            "cluster":if join_inputs {previous.first().ok_or(Failure::Ownership)?.owner["cluster"].clone()} else {Value::Null},"resources":resources,
            "config":context.config,"references":context.references,"consumer":consumer.as_ref().map(|p|json!({"action":p.action.tag(),"projection":p.projection()})),
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,"step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let owned = if let Some(snapshot) = previous.first() {
            let owned = &snapshot.owner;
            let selected = if join {
                selects_survivors(owned, &members)?
            } else {
                owned["members"] == members
            };
            require(
                selected
                    && (join_inputs || owned["cluster"].is_null())
                    && owned["fingerprints"] == context.owner_fingerprints
                    && owned["participants_sha256"] == participants,
                Failure::Ownership,
            )?;
            owned.clone()
        } else {
            json!({"schema":1,"kind":"owner","scope":context.scope,"owner":owner,"generation":fresh()?,"previous_generation":null,
                "created_ms":created,"members":members,"cluster":null,"resources":[],"fingerprints":context.owner_fingerprints,
                "participants_sha256":participants,"lock_identity":[0,0],"writer":null,"removed":[],
                "maintained":false})
        };
        let members = members.as_array().ok_or(Failure::Integrity)?.clone();
        let generations = members
            .iter()
            .map(|member| {
                previous
                    .iter()
                    .flat_map(|s| &s.observations)
                    .filter(|o| {
                        o["event"]["type"] == "reservation"
                            && o["event"]["state"] == "retired"
                            && o["event"]["member"] == *member
                    })
                    .filter_map(|o| o["event"]["generation"].as_u64())
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let count = if agent_inputs {
            let servers = members.iter().filter(|m| m["role"] == "server").count();
            members.len().checked_mul(6).and_then(|n| n.checked_add(servers * 2))
                .and_then(|n| n.checked_add(if same_machine { 8 } else if join_repeat { 5 } else { 26 }))
        } else if join_repeat {
            members.len().checked_mul(6).and_then(|n| n.checked_add(13))
        } else if join {
            members.len().checked_mul(6).and_then(|n| n.checked_add(38))
        } else if server_inputs {
            members.len().checked_mul(6).and_then(|n| n.checked_add(19))
        } else {
            members.len().checked_mul(4)
                .and_then(|n| n.checked_add(if consumer.is_some() { 3 } else { 0 }))
        }.ok_or(Failure::Bound)?;
        require(count <= 1024, Failure::Bound)?;
        let mut attempt = json!({"schema":1,"kind":"attempt","scope":context.scope,"owner":owner,"operation":operation,"attempt":attempt,
            "created_ms":created,"request_sha256":hash("broil-infra-request-v1",&request)?,"parent_attempt":null,"original_step":null,
            "approval":null,"steps":(1..=count).collect::<Vec<_>>()});
        let source_recipe = if join_inputs {
            let installations: Vec<_> = previous.iter()
                .filter(|snapshot| snapshot.request["action"] == "create-server"
                    && snapshot.observations.iter().any(|observation| {
                        observation["event"]["type"] == "lifecycle-installation"
                            && observation["event"]["publication_state"] == "published"
                    }))
                .collect();
            let installed = *installations.first().ok_or(Failure::Ownership)?;
            let original = &installed.lifecycle_recipe()?["event"]["recipe"];
            require(original["schema"] == 2, Failure::UnsupportedVersion)?;
            let identity = super::provenance::recipe_identity(original)?;
            for snapshot in &installations {
                require(super::provenance::recipe_identity(&snapshot.lifecycle_recipe()?["event"]["recipe"])? == identity,
                    Failure::Ownership)?;
            }
            require(installed.observations.iter().any(|observation| {
                observation["event"]["type"] == "lifecycle-installation"
                    && observation["event"]["activation"]["recipe_identity_sha256"] == identity
            }), Failure::Ownership)?;
            let mut recipe = original.clone();
            recipe["operation"] = json!(operation);
            recipe["attempt"] = attempt["attempt"].clone();
            recipe["members"] = json!(members);
            recipe["member"] = members[0].clone();
            require(super::provenance::recipe_identity(&recipe)? == identity, Failure::Ownership)?;
            Some(recipe)
        } else { None };
        let (wave_selection, wave_boundary, new_wave_boundary, wave_operations, wave_gate_needed) = if agent_inputs && join {
            let (selection, boundary, fresh_boundary, operations, gate_needed) = super::agent::select_wave(
                &context, &previous, &members, source_recipe.as_ref().ok_or(Failure::Integrity)?,
                &wave_records, join_destination.as_deref().ok_or(Failure::Integrity)?,
                join_repeat, wave.as_ref().ok_or(Failure::Integrity)?)?;
            (Some(selection), Some(boundary), fresh_boundary, operations, gate_needed)
        } else { (None, None, None, Vec::new(), false) };
        if wave_gate_needed {
            let servers = members.iter().filter(|member| member["role"] == "server").count();
            let count = count.checked_add(servers + 1).ok_or(Failure::Bound)?;
            require(count <= 1024, Failure::Bound)?;
            attempt["steps"] = json!((1..=count).collect::<Vec<_>>());
        }
        let recipe_events = if agent_inputs {
            super::agent::recipe_events(&context, &previous, &Value::Array(members.clone()),
                &resources, &operation, attempt["attempt"].as_str().ok_or(Failure::Integrity)?,
                source_recipe.as_ref().ok_or(Failure::Integrity)?, join_repeat || same_machine,
                wave_selection.as_ref().ok_or(Failure::Integrity)?)?
        } else if join {
            super::join::recipe_events(&context, &previous, &Value::Array(members.clone()),
                &resources, &operation, attempt["attempt"].as_str().ok_or(Failure::Integrity)?,
                source_recipe.as_ref().ok_or(Failure::Integrity)?, join_repeat)?
        } else {
            source_recipe.into_iter().map(|recipe| json!({"type":"server-recipe","recipe_kind":"initial","recipe":recipe})).collect()
        };
        if join {
            if agent_inputs {
                super::agent::preflight(&context, &owned, &request, &attempt, &recipe_events, &members)?;
            } else {
                super::join::preflight(&context, &owned, &request, &attempt, &recipe_events, &members)?;
            }
            context.authenticate_owned(&Value::Array(members.clone())).await?;
        }
        let mut recipe_events = recipe_events;
        if join && join_replacing && !join_repeat && !same_machine {
            let destination = join_destination.as_deref().ok_or(Failure::Integrity)?;
            let joining = recipe_events.iter().find(|e| {
                matches!(e["type"].as_str(), Some("server-join-recipe" | "agent-join-recipe"))
                    && e["recipe"]["member"]["machine"] == destination
            }).ok_or(Failure::Integrity)?["recipe"].clone();
            if let Some(recipe) = super::node_registry::join_render(&context, &previous, &owned, &operation, &joining)? {
                super::node::render_fits(&request, attempt["attempt"].as_str().ok_or(Failure::Integrity)?, &recipe)?;
                let count = attempt["steps"].as_array().map_or(0, Vec::len) + 1;
                require(count <= 1024, Failure::Bound)?;
                attempt["steps"] = json!((1..=count).collect::<Vec<_>>());
                recipe_events.push(json!({"type":"restart-recipe","recipe":recipe}));
            }
        }
        if let Some(boundary) = new_wave_boundary {
            local.work(move |store| store.wave_boundary(boundary)).await?;
        }
        let stored_attempt = attempt.clone();
        local
            .work(move |store| store.create(owned, request, stored_attempt))
            .await?;
        for event in recipe_events {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,"owner":owner,"operation":operation,
                "sequence":1,"recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,
                "event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((attempt, generations, members, consumer, wave_boundary, wave_operations, wave_gate_needed))
        }.await;
        let (
            attempt,
            generations,
            members,
            consumer,
            wave_boundary,
            wave_operations,
            wave_gate_needed,
        ) = match prepared {
            Ok(value) => value,
            Err(failure) => {
                return Err(local.failure(failure, &context.clock).await);
            }
        };
        Ok(Self {
            context,
            local,
            attempt,
            generations,
            members,
            next_step: 1,
            consumer,
            existing_resources: false,
            mode: Mode::Acquiring,
            retry_input: None,
            agent_view_wait: false,
            wave_boundary,
            wave_operations,
            wave_gate_needed,
        })
    }

    pub(super) async fn begin_existing(
        project: &'a LoadedProject,
        policy: Policy,
        target: &str,
        destination: &str,
        selection: super::ResourceSelection,
        operation: super::super::Operation,
    ) -> super::ExecutionResult<Self> {
        let context = rpc::Context::new(project, policy, target)?;
        let mut local = Local::new(&context)?;
        let prepared: Result<_> = async {
            require(super::super::protocol::opaque(&selection.id)
                && super::nonce(&selection.generation), Failure::Configuration)?;
            let previous = local.work(|store| store.read_operations(None).map_err(|e|e.failure)).await?;
            let first = previous.first().ok_or(Failure::Ownership)?;
            for snapshot in &previous {
                settled(&super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?)?;
            }
            let id = first.request["operation"].as_str().ok_or(Failure::Integrity)?.to_owned();
            local.work(move |store| store.lock(&id)).await?;
            let owned = local.snapshot()?.owner.clone();
            require(owned == first.owner
                && owned["scope"] == context.scope && owned["fingerprints"] == context.owner_fingerprints, Failure::Ownership)?;
            let members = owned["members"].as_array().ok_or(Failure::Integrity)?.clone();
            context.authenticate_owned(&owned["members"]).await?;
            let resources = owned["resources"].as_array().ok_or(Failure::Integrity)?;
            let selected: Vec<_> = resources.iter().filter(|r| r["id"] == selection.id
                && r["generation"] == selection.generation && r["machine"] == destination
                && r["owner"] == owned["owner"]).collect();
            require(selected.len() == 1, Failure::Ownership)?;
            let node = |name: &str| -> Result<Option<String>> {
                Ok(members.iter().find(|m| m["machine"] == name).ok_or(Failure::Ownership)?
                    ["node_uid"].as_str().map(str::to_owned))
            };
            let source_uid = match &operation {
                super::super::Operation::ServerJoin {source} | super::super::Operation::AgentJoin {source} => node(source)?,
                _ => None,
            };
            let cluster = &owned["cluster"];
            let generation = super::super::Generation {
                owner: owned["owner"].as_str().ok_or(Failure::Integrity)?.into(),
                operation: format!("infra-operation-{}", fresh()?), attempt: fresh()?,
                resource: selection.id, generation: selection.generation,
                resource_uid: selected[0]["uid"].as_str().map(str::to_owned),
                cluster: if cluster.is_null() {None} else {Some(super::super::Cluster {
                    uid: cluster["uid"].as_str().ok_or(Failure::Integrity)?.into(),
                    ca_sha256: cluster["ca_sha256"].as_str().ok_or(Failure::Integrity)?.into(),
                })},
                destination_uid: node(destination)?, source_uid,
            };
            let p = &context.policy;
            let consumer = super::super::prepare(project, Policy {
                environment: p.environment.clone(), cwd: p.cwd.clone(),
                environment_snapshot: p.environment_snapshot.clone(),
                credentials: p.credentials.try_duplicate().map_err(|_| Failure::Credential)?,
                non_interactive: p.non_interactive, deadline: context.clock.deadline(),
                cancellation: p.cancellation.clone(),
            }, target, destination, generation, operation).map_err(|_| Failure::Configuration)?;
            require(consumer.base["cluster"] == owned["cluster"], Failure::Ownership)?;
            let mut resources = Vec::new();
            for selected in [&consumer.base["source"], &consumer.base["destination"]] {
                if selected.is_null() { continue; }
                let member = members.iter().find(|m| m["machine"] == selected["machine"]).ok_or(Failure::Ownership)?;
                for key in ["machine", "member", "role", "node_uid"] {
                    require(member[key] == selected[key], Failure::Ownership)?;
                }
                let matches: Vec<_> = owned["resources"].as_array().ok_or(Failure::Integrity)?.iter()
                    .filter(|r| r["machine"] == selected["machine"] && r["owner"] == owned["owner"]
                        && ["kind", "id", "generation", "uid"].iter().all(|k| r[*k] == consumer.base["resource"][*k]))
                    .cloned().collect();
                require(matches.len() == 1, Failure::Ownership)?;
                resources.extend(matches);
            }
            let request_sequence = local.work(|store| store.next_sequence()).await?;
            let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":owned["owner"],
                "operation":consumer.base["operation"],"created_ms":now()?,"sequence":request_sequence,"action":"prepare-state","members":members,
                "cluster":owned["cluster"],"resources":resources,"config":context.config,"references":context.references,
                "consumer":{"action":consumer.action.tag(),"projection":consumer.projection()},
                "fingerprints":context.fingerprints,"participants_sha256":owned["participants_sha256"],
                "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
                "step_timeout_ms":context.selected.step_timeout.seconds*1000});
            let request_hash = hash("broil-infra-request-v1", &request)?;
            let mut generations = Vec::with_capacity(members.len());
            for member in &members {
                let binding = json!({"scope":context.scope,"owner":owned["owner"],"operation":request["operation"],
                    "attempt":consumer.base["attempt"],"step":1,"dispatch":fresh()?,"recipient":member,
                    "receiver_generation":0,"request_sha256":request_hash,"participants_sha256":owned["participants_sha256"],
                    "fingerprints":context.fingerprints});
                let deadline = context.clock.deadline().min(tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds));
                let observed = context.invoke(&binding, "inspect", json!({"subject":"owner","dispatch":null,"resource":null}), deadline).await;
                let response = observed.response.ok_or(observed.failure.unwrap_or(Failure::Transport))?;
                require(response["status"] == "ok" && response["data"]["claim"]["active_attempt"].is_null()
                    && response["data"]["ownership"]["cluster"] == owned["cluster"], Failure::Ownership)?;
                generations.push(response["data"]["claim"]["generation"].as_u64().ok_or(Failure::Integrity)?);
                let observed = context.invoke(&binding, "inspect", json!({"subject":"identity","dispatch":null,"resource":null}), deadline).await;
                let response = observed.response.ok_or(observed.failure.unwrap_or(Failure::Transport))?;
                require(response["status"] == "ok" && response["data"]["identity"]["member"] == *member
                    && response["data"]["identity"]["cluster"] == owned["cluster"], Failure::Ownership)?;
                for resource in inspected(&resources, member) {
                    let observed = context.invoke(&binding, "inspect", json!({"subject":"resource","dispatch":null,"resource":resource}), deadline).await;
                    let response = observed.response.ok_or(observed.failure.unwrap_or(Failure::Transport))?;
                    require(response["status"] == "ok" && response["data"]["resource"]["resource"] == *resource
                        && !response["data"]["resource"]["identity"].is_null(), Failure::Ownership)?;
                }
            }
            let count = members.len().checked_mul(4).and_then(|n| n.checked_add(resources.len()*2)).ok_or(Failure::Bound)?;
            require(count <= 1024, Failure::Bound)?;
            let attempt = json!({"schema":1,"kind":"attempt","scope":context.scope,"owner":owned["owner"],
                "operation":request["operation"],"attempt":consumer.base["attempt"],"created_ms":now()?,
                "request_sha256":request_hash,"parent_attempt":null,"original_step":null,"approval":null,
                "steps":(1..=count).collect::<Vec<_>>()});
            let stored = attempt.clone();
            local.work(move |store| store.create(owned, request, stored)).await?;
            Ok((attempt, members, generations, consumer))
        }.await;
        let (attempt, members, generations, consumer) = match prepared {
            Ok(value) => value,
            Err(failure) => {
                return Err(local.failure(failure, &context.clock).await);
            }
        };
        Ok(Self {
            context,
            local,
            attempt,
            members,
            generations,
            next_step: 1,
            consumer: Some(consumer),
            existing_resources: true,
            mode: Mode::Acquiring,
            retry_input: None,
            agent_view_wait: false,
            wave_boundary: None,
            wave_operations: Vec::new(),
            wave_gate_needed: false,
        })
    }

    pub(super) async fn retry(
        context: rpc::Context<'a>,
        mut local: Local,
        proposal: Value,
        original_payload: Option<Value>,
    ) -> super::ExecutionResult<Snapshot> {
        let prepared: Result<_> = async {
        context.check()?;
        let snapshot = local.snapshot()?;
        let request = &snapshot.request;
        let decision = &proposal["decision"];
        let members = request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let generations = decision["receivers"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .map(|r| r["generation"].as_u64().ok_or(Failure::Integrity))
            .collect::<Result<Vec<_>>>()?;
        let first = snapshot
            .attempts
            .iter()
            .flat_map(|a| a["steps"].as_array().into_iter().flatten())
            .filter_map(Value::as_u64)
            .max()
            .ok_or(Failure::Integrity)?
            .checked_add(1)
            .ok_or(Failure::Bound)?;
        let count = members.len() * 4 + usize::from(original_payload.is_some());
        require(
            first
                .checked_add(count as u64)
                .is_some_and(|end| end <= u32::MAX as u64)
                && snapshot
                    .attempts
                    .iter()
                    .map(|a| a["steps"].as_array().map_or(1024, Vec::len))
                    .sum::<usize>()
                    + count
                    <= 1024,
            Failure::Bound,
        )?;
        let attempt_id = fresh()?;
        let retry_input = match original_payload {
            None => None,
            Some(mut payload) => {
                let resource = decision["resources"].as_array().ok_or(Failure::Integrity)?;
                require(resource.len() == 1, Failure::Integrity)?;
                let resource = &resource[0];
                let index = members
                    .iter()
                    .position(|m| m["machine"] == resource["machine"])
                    .ok_or(Failure::Ownership)?;
                payload["resource"] = resource.clone();
                payload["projection"]["binding"]["attempt"] = json!(attempt_id);
                payload["projection"]["binding"]["resource"]["generation"] =
                    resource["generation"].clone();
                Some((index, payload))
            }
        };
        let attempt = json!({"schema":1,"kind":"attempt","scope":request["scope"],"owner":request["owner"],"operation":request["operation"],
            "attempt":attempt_id,"created_ms":now()?,"request_sha256":hash("broil-infra-request-v1",request)?,
            "parent_attempt":decision["failed_attempt"],"original_step":decision["original_step"],"approval":proposal,
            "steps":(first..first+count as u64).collect::<Vec<_>>()});
        let stored = attempt.clone();
        local.work(move |store| store.attempt(stored)).await?;
        Ok((attempt, members, generations, first, retry_input))
        }.await;
        let (attempt, members, generations, first, retry_input) = match prepared {
            Ok(value) => value,
            Err(failure) => {
                return Err(local.failure(failure, &context.clock).await);
            }
        };
        Self {
            context,
            local,
            attempt,
            members,
            generations,
            next_step: first,
            consumer: None,
            existing_resources: false,
            mode: Mode::Acquiring,
            retry_input,
            agent_view_wait: false,
            wave_boundary: None,
            wave_operations: Vec::new(),
            wave_gate_needed: false,
        }
        .prepare_metadata()
        .await
    }

    pub(super) fn intended(
        &self,
        index: usize,
        action: &str,
        payload: &Value,
        references: Vec<Value>,
    ) -> Result<Value> {
        let snapshot = self.local.snapshot()?;
        let mut references = references;
        if let Some(event) = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "component-assets")
        {
            let family = [
                "lifecycle:network-",
                "lifecycle:ingress-",
                "lifecycle:cert-manager-",
            ]
            .iter()
            .any(|prefix| action.starts_with(prefix));
            if family && !references.is_empty() {
                references.insert(1, event["sequence"].clone());
            }
        }
        Ok(
            json!({"schema":1,"kind":"step","scope":snapshot.request["scope"],"owner":snapshot.request["owner"],
            "operation":snapshot.request["operation"],"attempt":self.attempt["attempt"],"step":self.next_step,"original_step":self.attempt["original_step"],
            "created_ms":now()?,"dispatch":fresh()?,"action":action,"recipient":self.members[index],"resource":payload.get("resource").cloned().unwrap_or(Value::Null),
            "expected_receiver_generation":self.generations[index],"request_sha256":self.attempt["request_sha256"],
            "payload_sha256":hash("broil-infra-step-v1",payload)?,"payload_observations":references}),
        )
    }

    pub(super) async fn append(
        &mut self,
        step: &Value,
        event: Value,
        receiver: bool,
        producer: Value,
    ) -> Result<()> {
        self.local
            .append(
                Some(step),
                event,
                receiver.then_some(&step["recipient"]["machine"]),
                producer,
            )
            .await
    }

    pub(super) async fn unknown_run<T>(&mut self, result: &Result<T>) {
        let Err(failure) = result else {
            return;
        };
        let ending = match failure {
            Failure::Cancelled => "cancelled",
            Failure::Timeout => "timeout",
            Failure::Storage | Failure::Busy => "storage",
            _ => "controller",
        };
        let Ok(snapshot) = self.local.snapshot() else {
            return;
        };
        let projection = super::report::summary(snapshot);
        let decided = crate::k3s::release::unknown_run(&json!({
            "action": snapshot.request["action"],
            "projection": {"outcome": projection["outcome"], "failure": projection["failure"]},
            "ending": ending, "failure": failure.name()}));
        if decided["append"].is_null() {
            return;
        }
        let _ = self
            .local
            .append(
                None,
                json!({"type":"failure","failure":decided["append"],"outcome":"unknown",
                    "completion_unknown":false,"cleanup_unknown":false}),
                None,
                Value::Null,
            )
            .await;
    }

    pub(super) fn settlement(&self, step: &Value, response: &Value, payload: &Value) -> Result<()> {
        let data = &response["data"];
        let generation = step["expected_receiver_generation"]
            .as_u64()
            .ok_or(Failure::Integrity)?;
        let snapshot = self.local.snapshot()?;
        match step["action"].as_str() {
            Some("reserve-owner") => {
                require(
                    data["claim"]["generation"] == generation.max(1)
                        && data["claim"]["active_attempt"].is_null()
                        && reserve_admits(&snapshot.request, &data["ownership"]["cluster"]),
                    Failure::Ownership,
                )?;
            }
            Some("acquire-writer") => {
                let acquired = generation.checked_add(1).ok_or(Failure::Bound)?;
                let mut binding = snapshot.binding(step);
                binding["receiver_generation"] = json!(acquired);
                require(
                    data["claim"]["generation"] == acquired
                        && data["claim"]["active_attempt"] == step["attempt"]
                        && data["reservation"]["binding"] == binding
                        && data["reservation"]["members"] == json!(self.members)
                        && data["reservation"]["state"] == "reserved",
                    Failure::Ownership,
                )?;
            }
            Some("seal-writer") => {
                let work = snapshot.sealed_work(&step["attempt"], &step["recipient"]);
                let mut dispatches = Vec::new();
                let mut receipts = Vec::new();
                for work in work {
                    let receipt = snapshot
                        .observations
                        .iter()
                        .find(|o| {
                            o["dispatch"] == work["dispatch"] && o["event"]["type"] == "receiver"
                        })
                        .map(|o| &o["event"]["receipt"])
                        .ok_or(Failure::Readiness)?;
                    require(receipt["writer_ended"] == true, Failure::Readiness)?;
                    dispatches.push(work["dispatch"].clone());
                    receipts.push(hash("broil-infra-receipt-v1", receipt)?);
                }
                let seal = &data["seal"];
                require(
                    seal["binding"] == snapshot.binding(step)
                        && seal["dispatches"] == json!(dispatches)
                        && seal["terminal_sha256s"] == json!(receipts)
                        && data["reservation"]["state"] == "sealed"
                        && data["reservation"]["dispatches"] == seal["dispatches"]
                        && data["reservation"]["seal_sha256"] == hash("broil-infra-seal-v1", seal)?,
                    Failure::Ownership,
                )?;
            }
            Some("retire-writer") => {
                let retirement = &data["retirement"];
                let next = generation.checked_add(1).ok_or(Failure::Bound)?;
                require(
                    retirement["binding"] == snapshot.binding(step)
                        && retirement["seals"] == payload["seals"]
                        && retirement["next_generation"] == next
                        && data["claim"]["generation"] == next
                        && data["claim"]["active_attempt"].is_null()
                        && data["reservation"]["state"] == "retired"
                        && data["reservation"]["retirement_sha256"]
                            == hash("broil-infra-retirement-v1", retirement)?,
                    Failure::Ownership,
                )?;
            }
            Some("prepare-input") => {
                require(
                    data["resource"]["resource"] == payload["resource"]
                        && data["resource"]["inactive"] == true
                        && data["resource"]["identity"].is_array(),
                    Failure::Ownership,
                )?;
            }
            Some("admit-credential") => {}
            Some("rebind-claim") => {
                require(
                    data["claim"]["participants_sha256"] == payload["participants_sha256"]
                        && data["claim"]["active_attempt"] == step["attempt"]
                        && data["claim"]["generation"] == generation,
                    Failure::Ownership,
                )?;
            }
            Some(action) if action.starts_with("lifecycle:") => {
                super::server::settlement(snapshot, step, response)?;
            }
            _ => return Err(Failure::Capability),
        }
        Ok(())
    }

    pub(super) async fn dispatch(
        &mut self,
        index: usize,
        action: &str,
        payload: Value,
        references: Vec<Value>,
    ) -> Result<Value> {
        self.context.check()?;
        require(
            self.mode != Mode::SettlementOnly || matches!(action, "seal-writer" | "retire-writer"),
            Failure::Capability,
        )?;
        let previous_deadline = self.local.step_deadline;
        let deadline = self
            .context
            .clock
            .deadline()
            .min(previous_deadline.unwrap_or(self.context.clock.deadline()))
            .min(
                tokio::time::Instant::now()
                    + Duration::from_secs(self.context.selected.step_timeout.seconds),
            );
        self.local.step_deadline = Some(deadline);
        let step = self.intended(index, action, &payload, references)?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let observed = self
            .context
            .invoke_recorded(
                self.local.snapshot()?,
                &binding,
                action,
                payload.clone(),
                deadline,
            )
            .await;
        let candidate = observed.response.as_ref().is_some_and(|response| {
            let receipt = &response["data"]["terminal"];
            self.mode == Mode::Work
                && action == "prepare-input"
                && observed.failure.is_none()
                && response["status"] == "failed"
                && receipt["outcome"] == "failed"
                && receipt["effect"] == "absent"
                && receipt["writer_ended"] == true
                && !matches!(
                    receipt["failure"].as_str(),
                    None | Some("timeout" | "cancelled" | "credential")
                )
                && receipt["binding"] == binding
                && receipt["payload_sha256"] == step["payload_sha256"]
                && tokio::time::Instant::now() < deadline
        });
        if observed.failure.is_some()
            || observed
                .response
                .as_ref()
                .is_some_and(|r| r["status"] != "ok")
                && !candidate
        {
            self.local
                .limit_observation(self.context.clock.terminal_deadline());
        }
        self.local.completion_unknown |=
            observed.failure.is_some() && observed.transport["dispatch"] != "none";
        self.append(
            &step,
            json!({"type":"dispatch","transport":observed.transport,
            "outcome":if observed.failure.is_some() {"unknown"}else{"running"},
            "failure":observed.failure.map(Failure::name)}),
            false,
            Value::Null,
        )
        .await?;
        let response = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        let data = &response["data"];
        if !data["terminal"].is_null() {
            self.append(&step,json!({"type":"receiver","receipt":data["terminal"],"transport":observed.transport}),true,data["terminal"]["completed_ms"].clone()).await?;
        }
        if response["status"] != "ok" && self.mode == Mode::Work && action == "prepare-input" {
            require(candidate, Failure::Readiness)?;
            self.context.check()?;
            require(tokio::time::Instant::now() < deadline, Failure::Timeout)?;
            self.acquired()?;
            let receipt = &data["terminal"];
            require(
                response["status"] == "failed"
                    && receipt["outcome"] == "failed"
                    && receipt["effect"] == "absent"
                    && receipt["writer_ended"] == true
                    && receipt["binding"] == binding
                    && receipt["action"] == action
                    && receipt["payload_sha256"] == step["payload_sha256"]
                    && !receipt["failure"].is_null()
                    && data["failure"] == receipt["failure"]
                    && receipt["resource_identity"].is_null()
                    && observed.failure.is_none()
                    && observed.transport["exit"] == 0
                    && observed.transport["signal"].is_null()
                    && observed.transport["input_released"] == true
                    && observed.transport["staging_cleanup"] == "clean",
                Failure::Readiness,
            )?;
            self.local.work(|store| store.verify()).await?;
            self.context.check()?;
            require(tokio::time::Instant::now() < deadline, Failure::Timeout)?;
            self.mode = Mode::SettlementOnly;
            self.next_step += 1;
            self.local.step_deadline = previous_deadline;
            return Ok(response);
        }
        require(response["status"] == "ok", Failure::Readiness)?;
        self.settlement(&step, &response, &payload)?;
        if matches!(
            action,
            "prepare-input" | "admit-credential" | "rebind-claim"
        ) {
            self.next_step += 1;
            self.local.step_deadline = previous_deadline;
            return Ok(response);
        }
        let (state, generation, receipt, producer) = match action {
            "reserve-owner" => (
                "reserved",
                data["claim"]["generation"].clone(),
                hash("broil-infra-receipt-v1", &data["terminal"])?,
                data["terminal"]["completed_ms"].clone(),
            ),
            "acquire-writer" => (
                "reserved",
                data["claim"]["generation"].clone(),
                hash("broil-infra-receipt-v1", &data["terminal"])?,
                data["terminal"]["completed_ms"].clone(),
            ),
            "seal-writer" => (
                "sealed",
                step["expected_receiver_generation"].clone(),
                hash("broil-infra-seal-v1", &data["seal"])?,
                data["seal"]["sealed_ms"].clone(),
            ),
            "retire-writer" => (
                "retired",
                data["claim"]["generation"].clone(),
                hash("broil-infra-retirement-v1", &data["retirement"])?,
                data["retirement"]["retired_ms"].clone(),
            ),
            _ => return Err(Failure::Capability),
        };
        self.append(&step,json!({"type":"reservation","member":self.members[index],"generation":generation,"state":state,"receipt_sha256":receipt}),true,producer).await?;
        self.generations[index] = generation.as_u64().ok_or(Failure::Integrity)?;
        self.next_step += 1;
        self.local.step_deadline = previous_deadline;
        Ok(response)
    }

    pub(super) async fn consume(&mut self) -> Result<()> {
        require(self.mode == Mode::Work, Failure::Capability)?;
        self.acquired()?;
        let mut prepared = self.consumer.take().ok_or(Failure::Capability)?;
        prepared.refresh_action_clock();
        let resources = self.local.snapshot()?.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let destination = self
            .members
            .iter()
            .position(|m| m["machine"] == prepared.destination)
            .ok_or(Failure::Ownership)?;
        if matches!(
            self.local.snapshot()?.request["action"].as_str(),
            Some("prepare-server-inputs" | "join-server" | "join-agent")
        ) {
            let snapshot = self.local.snapshot()?;
            let source = resources.first().ok_or(Failure::Integrity)?.clone();
            let index = self
                .members
                .iter()
                .position(|m| m["machine"] == source["machine"])
                .ok_or(Failure::Ownership)?;
            let observation = snapshot
                .observations
                .iter()
                .find(|o| o["event"]["type"] == "server-recipe")
                .ok_or(Failure::Integrity)?;
            let sequence = observation["sequence"].clone();
            let payload = json!({"resource":source,"projection":prepared.projection(),
                "recipe":observation["event"]["recipe"]});
            let id = self.next_step;
            let mut references = vec![sequence];
            if snapshot.request["action"] == "join-server" {
                let mut round: Vec<_> = snapshot
                    .observations
                    .iter()
                    .rev()
                    .filter(|o| o["event"]["type"] == "server-membership")
                    .take(
                        snapshot.request["members"]
                            .as_array()
                            .ok_or(Failure::Integrity)?
                            .iter()
                            .filter(|m| m["role"] == "server" && !m["node_uid"].is_null())
                            .count(),
                    )
                    .map(|o| o["sequence"].clone())
                    .collect();
                round.reverse();
                references.extend(round);
            }
            self.lifecycle_dispatch(id, index, "prepare-join-source", payload, references, true)
                .await?;
            self.next_step += 1;
            let dispatch = self
                .local
                .snapshot()?
                .steps
                .last()
                .ok_or(Failure::Integrity)?["dispatch"]
                .clone();
            let receipt = self
                .inspect_step(index, "dispatch", dispatch, Value::Null)
                .await?;
            require(
                receipt["status"] == "ok" && receipt["data"]["terminal"]["outcome"] == "succeeded",
                Failure::Readiness,
            )?;
        }
        if !self.existing_resources {
            let resource = resources
                .iter()
                .find(|r| r["machine"] == prepared.destination)
                .ok_or(Failure::Ownership)?
                .clone();
            self.dispatch(
                destination,
                "prepare-input",
                json!({"resource":resource,"projection":prepared.projection()}),
                Vec::new(),
            )
            .await?;
            if matches!(
                self.local.snapshot()?.request["action"].as_str(),
                Some("prepare-server-inputs" | "join-server" | "join-agent")
            ) {
                let dispatch = self
                    .local
                    .snapshot()?
                    .steps
                    .last()
                    .ok_or(Failure::Integrity)?["dispatch"]
                    .clone();
                let receipt = self
                    .inspect_step(destination, "dispatch", dispatch, Value::Null)
                    .await?;
                require(
                    receipt["status"] == "ok"
                        && receipt["data"]["terminal"]["outcome"] == "succeeded",
                    Failure::Readiness,
                )?;
            }
            if self.mode == Mode::SettlementOnly {
                self.next_step += 2;
                return Ok(());
            }
        }
        self.acquired()?;
        let clock = self
            .context
            .clock
            .for_credential_action(prepared.clock.deadline());
        let previous_deadline = self.local.step_deadline;
        self.local.step_deadline = Some(clock.deadline());
        use super::super::protocol::Action;
        let mut actions = Vec::new();
        if let Some(source) = &prepared.source {
            let index = self
                .members
                .iter()
                .position(|m| m["machine"] == *source)
                .ok_or(Failure::Ownership)?;
            let read = match prepared.action {
                Action::ServerJoin => Action::ReadServer,
                Action::AgentJoin => Action::ReadAgent,
                _ => return Err(Failure::Capability),
            };
            actions.push((index, read));
        }
        actions.push((destination, prepared.action));
        let join_inputs = matches!(
            self.local.snapshot()?.request["action"].as_str(),
            Some("prepare-server-inputs" | "join-server" | "join-agent")
        );
        let mut credentials = Vec::new();
        let mut requests = std::collections::BTreeMap::new();
        let mut deferred = None;
        for (index, action) in actions {
            let resource = resources
                .iter()
                .find(|r| r["machine"] == self.members[index]["machine"])
                .ok_or(Failure::Ownership)?
                .clone();
            let mut admission = prepared.base.clone();
            admission["protocol"] = json!("broil-k3s-actions");
            admission["version"] = json!(1);
            admission["action"] = json!(action.tag());
            admission["for_action"] = Value::Null;
            admission["request_id"] = json!(fresh()?);
            let mut credential = self.intended(
                index,
                &format!("credential:{}", action.tag()),
                &admission,
                Vec::new(),
            )?;
            credential["step"] = json!(
                self.next_step
                    + if join_inputs {
                        if action == prepared.action { 3 } else { 2 }
                    } else {
                        1
                    }
            );
            credential["dispatch"] = admission["request_id"].clone();
            credential["resource"] = resource.clone();
            let grant = json!({"action":action.tag(),"request_id":admission["request_id"],"credential_step":credential["step"],
                "admission_sha256":hash("broil-infra-credential-admission-v1",&admission)?,
                "selection_sha256":admission["selection_sha256"],"resource":resource});
            if join_inputs {
                let stored = credential.clone();
                self.local.work(move |store| store.step(stored)).await?;
            }
            if join_inputs && action == prepared.action {
                deferred = Some((index, grant));
            } else {
                if !join_inputs {
                    let stored = credential.clone();
                    self.local.work(move |store| store.step(stored)).await?;
                }
                self.dispatch(index, "admit-credential", grant, Vec::new())
                    .await?;
                if join_inputs {
                    let dispatch = self
                        .local
                        .snapshot()?
                        .steps
                        .iter()
                        .find(|step| step["step"] == self.next_step - 1)
                        .ok_or(Failure::Integrity)?["dispatch"]
                        .clone();
                    let receipt = self
                        .inspect_step(index, "dispatch", dispatch, Value::Null)
                        .await?;
                    require(
                        receipt["status"] == "ok"
                            && receipt["data"]["terminal"]["outcome"] == "succeeded",
                        Failure::Readiness,
                    )?;
                }
                self.next_step += 1;
            }
            requests.insert(action.tag().into(), admission);
            credentials.push(credential);
        }
        self.local.work(|store| store.verify()).await?;
        clock
            .check(&self.context.policy.cancellation)
            .map_err(|_| Failure::Timeout)?;
        self.local.step_deadline = previous_deadline;
        prepared.authority = Some(super::CredentialAuthority { clock, requests });
        let (outcome, phase_failure) = if join_inputs {
            let (reached, wait) = tokio::sync::oneshot::channel();
            let (proceed, resumed) = tokio::sync::oneshot::channel();
            prepared.relay_gate = Some(super::super::RelayGate {
                reached,
                proceed: resumed,
            });
            let mut run = Box::pin(prepared.run());
            let first = tokio::select! {
                reached = wait => Ok(reached),
                outcome = &mut run => Err(outcome),
            };
            match first {
                Err(outcome) => (outcome, None),
                Ok(reached) => {
                    let stage: Result<()> = async {
                        let transport = reached.map_err(|_| Failure::Transport)?;
                        let source = credentials.first().ok_or(Failure::Integrity)?;
                        self.append(
                            source,
                            json!({"type":"dispatch","transport":transport,
                            "outcome":"running","failure":null}),
                            false,
                            Value::Null,
                        )
                        .await?;
                        let source_index = self
                            .members
                            .iter()
                            .position(|m| m["machine"] == source["recipient"]["machine"])
                            .ok_or(Failure::Ownership)?;
                        let response = self
                            .inspect_step(
                                source_index,
                                "dispatch",
                                source["dispatch"].clone(),
                                Value::Null,
                            )
                            .await?;
                        let receipt = &response["data"]["terminal"];
                        require(
                            response["status"] == "ok"
                                && receipt["outcome"] == "succeeded"
                                && receipt["writer_ended"] == true,
                            Failure::Readiness,
                        )?;
                        self.append(
                            source,
                            json!({"type":"receiver","receipt":receipt,
                            "transport":transport}),
                            true,
                            receipt["completed_ms"].clone(),
                        )
                        .await?;
                        let (index, grant) = deferred.take().ok_or(Failure::Integrity)?;
                        self.dispatch(index, "admit-credential", grant, Vec::new())
                            .await?;
                        let dispatch = self
                            .local
                            .snapshot()?
                            .steps
                            .iter()
                            .find(|step| step["step"] == self.next_step - 1)
                            .ok_or(Failure::Integrity)?["dispatch"]
                            .clone();
                        let response = self
                            .inspect_step(index, "dispatch", dispatch, Value::Null)
                            .await?;
                        require(
                            response["status"] == "ok"
                                && response["data"]["terminal"]["outcome"] == "succeeded",
                            Failure::Readiness,
                        )?;
                        self.next_step += 1;
                        Ok(())
                    }
                    .await;
                    if stage.is_ok() {
                        let _ = proceed.send(());
                    }
                    (run.await, stage.err())
                }
            }
        } else {
            (Box::pin(prepared.run()).await, None)
        };

        self.local.cleanup_unknown |= outcome.failure
            == Some(super::super::Failure::AcquisitionCleanup)
            || outcome.steps.iter().any(|s| {
                s.possible_consumer_residue
                    || s.transport.possible_staging_residue
                    || s.transport.unresolved_input
            });
        self.local.completion_unknown |= outcome
            .steps
            .iter()
            .any(|s| !s.inspecting && s.transport.dispatched && s.failure.is_some());
        if outcome.failure.is_some() {
            self.local
                .limit_observation(self.context.clock.terminal_deadline());
        }

        for credential in &credentials {
            if join_inputs && credential == &credentials[0] {
                continue;
            }
            for observed in &outcome.steps {
                if observed
                    .request_id
                    .as_ref()
                    .is_some_and(|id| credential["dispatch"] == *id)
                {
                    let persisted = self.append(credential,
                        json!({"type":"dispatch","transport":rpc::transport(&observed.transport),
                            "outcome":if observed.failure.is_some(){"unknown"}else{"running"},
                            "failure":if observed.failure.is_some(){json!("credential")}else{Value::Null}}),
                        false, Value::Null).await;
                    if outcome.failure.is_none() {
                        persisted?;
                    }
                }
            }
        }
        if outcome.failure.is_some() {
            self.context.clock.abort();
            if let Some(step) = if phase_failure.is_some() {
                credentials.first()
            } else {
                credentials.last()
            } {
                let event = json!({"type":"failure","failure":"credential","outcome":"failed",
                    "completion_unknown":self.local.completion_unknown,"cleanup_unknown":self.local.cleanup_unknown});
                let _ = self.append(step, event, false, Value::Null).await;
            }
            return Err(phase_failure.unwrap_or(Failure::Credential));
        }
        if let Some(failure) = phase_failure {
            return Err(failure);
        }
        for credential in &credentials {
            if join_inputs && credential == &credentials[0] {
                continue;
            }
            if join_inputs {
                let index = self
                    .members
                    .iter()
                    .position(|m| m["machine"] == credential["recipient"]["machine"])
                    .ok_or(Failure::Ownership)?;
                let response = self
                    .inspect_step(
                        index,
                        "dispatch",
                        credential["dispatch"].clone(),
                        Value::Null,
                    )
                    .await?;
                let receipt = &response["data"]["terminal"];
                require(
                    response["status"] == "ok"
                        && receipt["outcome"] == "succeeded"
                        && receipt["writer_ended"] == true,
                    Failure::Readiness,
                )?;
                let transport = outcome
                    .steps
                    .iter()
                    .find(|step| {
                        step.request_id
                            .as_ref()
                            .is_some_and(|id| credential["dispatch"] == *id)
                    })
                    .map(|step| rpc::transport(&step.transport))
                    .ok_or(Failure::Integrity)?;
                self.append(
                    credential,
                    json!({"type":"receiver","receipt":receipt,
                    "transport":transport}),
                    true,
                    receipt["completed_ms"].clone(),
                )
                .await?;
                continue;
            }
            let deadline = tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds);
            let observed = self
                .context
                .receipt(self.local.snapshot()?, credential, deadline)
                .await;
            let response = observed
                .response
                .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
            let receipt = &response["data"]["terminal"];
            require(
                response["status"] == "ok"
                    && receipt["outcome"] == "succeeded"
                    && receipt["writer_ended"] == true,
                Failure::Readiness,
            )?;
            self.append(
                credential,
                json!({"type":"receiver","receipt":receipt,"transport":observed.transport}),
                true,
                receipt["completed_ms"].clone(),
            )
            .await?;
        }
        Ok(())
    }

    pub(super) fn acquired(&self) -> Result<()> {
        self.acquired_of(&(0..self.members.len()).collect::<Vec<_>>())
    }

    pub(super) fn acquired_of(&self, indices: &[usize]) -> Result<()> {
        let snapshot = self.local.snapshot()?;
        for &index in indices {
            let member = self.members.get(index).ok_or(Failure::Integrity)?;
            let step = snapshot
                .steps
                .iter()
                .find(|s| {
                    s["attempt"] == self.attempt["attempt"]
                        && s["action"] == "acquire-writer"
                        && s["recipient"] == *member
                })
                .ok_or(Failure::Ownership)?;
            require(
                snapshot.succeeded(step)
                    && step["expected_receiver_generation"]
                        .as_u64()
                        .and_then(|g| g.checked_add(1))
                        == Some(self.generations[index]),
                Failure::Ownership,
            )?;
            require(
                snapshot.observations.iter().any(|o| {
                    o["attempt"] == step["attempt"]
                        && o["step"] == step["step"]
                        && o["dispatch"] == step["dispatch"]
                        && o["event"]["type"] == "reservation"
                        && o["event"]["member"] == *member
                        && o["event"]["state"] == "reserved"
                        && o["event"]["generation"] == self.generations[index]
                }),
                Failure::Ownership,
            )?;
        }
        Ok(())
    }

    pub(super) async fn prepare_metadata(mut self) -> super::ExecutionResult<Snapshot> {
        let result = Box::pin(self.prepare()).await;
        self.local.complete(result, &self.context.clock).await
    }

    pub(super) async fn inspect_step(
        &mut self,
        index: usize,
        subject: &str,
        dispatch: Value,
        resource: Value,
    ) -> Result<Value> {
        self.context.check()?;
        let payload = json!({"subject":subject,"dispatch":dispatch,"resource":resource});
        let step = self.intended(index, "inspect", &payload, Vec::new())?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let observed = if subject == "dispatch" {
            let expected = self
                .local
                .snapshot()?
                .steps
                .iter()
                .find(|candidate| {
                    candidate["dispatch"] == dispatch
                        && candidate["recipient"] == self.members[index]
                        && candidate["action"] != "inspect"
                })
                .ok_or(Failure::Integrity)?;
            self.context
                .inspect_dispatch(
                    self.local.snapshot()?,
                    &binding,
                    payload.clone(),
                    deadline,
                    expected,
                )
                .await
        } else {
            self.context
                .invoke(&binding, "inspect", payload.clone(), deadline)
                .await
        };
        self.append(
            &step,
            json!({"type":"dispatch","transport":observed.transport,
            "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
            "failure":observed.failure.map(Failure::name)}),
            false,
            Value::Null,
        )
        .await?;
        let response = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(
            matches!(response["status"].as_str(), Some("ok" | "absent")),
            Failure::Ownership,
        )?;
        self.append(
            &step,
            json!({"type":"inspection","subject":subject,
            "observed_dispatch":dispatch,"resource":resource,
            "status":response["status"],"data":response["data"]}),
            true,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok(response)
    }

    async fn admit_owner(&mut self, index: usize, initial_input: bool) -> Result<()> {
        let payload = json!({"members":self.members,"excluded":null,"cluster":self.local.snapshot()?.request["cluster"],"fingerprints":self.context.fingerprints});
        let probe = self.intended(index, "reserve-owner", &payload, Vec::new())?;
        let binding = self.local.snapshot()?.binding(&probe);
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let observed = self
            .context
            .invoke(
                &binding,
                "inspect",
                json!({"subject":"owner","dispatch":null,"resource":null}),
                deadline,
            )
            .await;
        let response = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        let generation = match response["status"].as_str() {
            Some("absent") => 0,
            Some("ok") => response["data"]["claim"]["generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?,
            _ => return Err(Failure::Ownership),
        };
        require(
            unchecked_claim(
                self.existing_resources,
                &self.attempt["approval"],
                &self.local.snapshot()?.request["action"],
            ) || self.generations[index] == generation,
            Failure::Ownership,
        )?;
        if initial_input && response["status"] == "ok" {
            let claim = &response["data"]["claim"];
            require(
                claim["active_attempt"].is_null()
                    && claim["scope"] == binding["scope"]
                    && claim["owner"] == binding["owner"]
                    && claim["member"] == binding["recipient"]
                    && claim["participants_sha256"] == binding["participants_sha256"]
                    && response["data"]["ownership"]["cluster"].is_null(),
                Failure::Ownership,
            )?;
            let observed = self
                .context
                .invoke(
                    &binding,
                    "inspect",
                    json!({"subject":"identity","dispatch":null,"resource":null}),
                    deadline,
                )
                .await;
            let response = observed
                .response
                .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
            require(
                response["status"] == "ok"
                    && response["data"]["identity"]["member"] == self.members[index]
                    && response["data"]["identity"]["cluster"].is_null(),
                Failure::Ownership,
            )?;
        }
        self.generations[index] = generation;
        Ok(())
    }

    async fn prepare(&mut self) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let initial_input = self.local.snapshot()?.request["consumer"]["action"]
            == "supply-initial-server"
            && (self.consumer.is_some() || self.retry_input.is_some());
        let server_inputs = self.local.snapshot()?.request["action"] == "prepare-server-inputs";
        if server_inputs {
            let cluster = self.local.snapshot()?.request["cluster"].clone();
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
                    writer["status"] == "ok" || writer["status"] == "absent",
                    Failure::Ownership,
                )?;
            }
            let observation = self
                .local
                .snapshot()?
                .observations
                .iter()
                .find(|o| o["event"]["type"] == "server-recipe")
                .ok_or(Failure::Integrity)?;
            let recipe = observation["event"]["recipe"].clone();
            let sequence = observation["sequence"].clone();
            let server_indices: Vec<_> = (0..self.members.len())
                .filter(|&index| self.members[index]["role"] == "server")
                .collect();
            for index in server_indices {
                let id = self.next_step;
                let result = self
                    .lifecycle_dispatch(
                        id,
                        index,
                        "inspect-installation",
                        json!({"recipe":recipe,"identity":null}),
                        vec![sequence.clone()],
                        false,
                    )
                    .await?;
                require(
                    result.result["installation"]["class"]
                        == if index == 0 { "owned" } else { "absent" },
                    Failure::Ownership,
                )?;
                self.next_step += 1;
            }
            let pair = self.local.snapshot()?.request["resources"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .clone();
            for resource in pair {
                let index = self
                    .members
                    .iter()
                    .position(|m| m["machine"] == resource["machine"])
                    .ok_or(Failure::Ownership)?;
                let response = self
                    .inspect_step(index, "resource", Value::Null, resource)
                    .await?;
                require(response["status"] == "absent", Failure::Ownership)?;
            }
        }
        if initial_input {
            for &index in &order {
                self.admit_owner(index, true).await?;
            }
        }
        for &index in &order {
            if !initial_input {
                self.admit_owner(index, false).await?;
            }
            let payload = json!({"members":self.members,"excluded":null,"cluster":self.local.snapshot()?.request["cluster"],"fingerprints":self.context.fingerprints});
            self.dispatch(index, "reserve-owner", payload, Vec::new())
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
        if let Some((index, payload)) = self.retry_input.take() {
            self.dispatch(index, "prepare-input", payload, Vec::new())
                .await?;
        }
        if self.consumer.is_some() {
            Box::pin(self.consume()).await?;
        }
        if self.local.snapshot()?.request["action"] == "prepare-server-inputs" {
            let snapshot = self.local.snapshot()?;
            let pair = snapshot.request["resources"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .clone();
            require(pair.len() == 2, Failure::Integrity)?;
            for resource in &pair {
                let index = self
                    .members
                    .iter()
                    .position(|m| m["machine"] == resource["machine"])
                    .ok_or(Failure::Ownership)?;
                let response = self
                    .inspect_step(index, "resource", Value::Null, resource.clone())
                    .await?;
                require(
                    response["status"] == "ok"
                        && response["data"]["resource"]["resource"] == *resource
                        && response["data"]["resource"]["identity"].is_array()
                        && response["data"]["resource"]["inactive"] == true,
                    Failure::Ownership,
                )?;
            }
            let snapshot = self.local.snapshot()?;
            let mut owner = snapshot.owner.clone();
            owner["previous_generation"] = owner["generation"].clone();
            owner["generation"] = json!(fresh()?);
            owner["created_ms"] = json!(now()?);
            owner["resources"]
                .as_array_mut()
                .ok_or(Failure::Integrity)?
                .extend(pair.iter().cloned());
            let operation = snapshot.request["operation"]
                .as_str()
                .ok_or(Failure::Integrity)?
                .to_owned();
            self.local
                .work(move |store| store.replace_owner(owner, &operation))
                .await?;
        }
        if self.local.snapshot()?.request["action"] == "prepare-node-registry" {
            if self.mode != Mode::Work {
                self.next_step += 1;
            } else {
                let snapshot = self.local.snapshot()?;
                let resource = snapshot.request["resources"][0].clone();
                let operation = snapshot.request["operation"]
                    .as_str()
                    .ok_or(Failure::Integrity)?
                    .to_owned();
                let index = self
                    .members
                    .iter()
                    .position(|m| m["machine"] == resource["machine"])
                    .ok_or(Failure::Ownership)?;
                let response = self
                    .inspect_step(index, "resource", Value::Null, resource.clone())
                    .await?;
                let found = &response["data"]["resource"];
                require(
                    response["status"] == "ok"
                        && found["resource"] == resource
                        && found["identity"].is_array()
                        && found["inactive"] == true,
                    Failure::Ownership,
                )?;
                let owner =
                    super::node_registry::successor(&self.local.snapshot()?.owner, &resource)?;
                self.local
                    .work(move |store| store.replace_owner(owner, &operation))
                    .await?;
            }
        }
        self.settle(&order).await
    }

    pub(super) async fn settle(&mut self, order: &[usize]) -> Result<Snapshot> {
        let snapshot = self.local.snapshot()?;
        for step in snapshot.steps.iter().filter(|s| {
            s["attempt"] == self.attempt["attempt"]
                && !matches!(
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
                            | "lifecycle:network-inspect-host"
                            | "lifecycle:network-inspect-objects"
                            | "lifecycle:ingress-inspect-host"
                            | "lifecycle:ingress-inspect-objects"
                            | "lifecycle:cert-manager-inspect-host"
                            | "lifecycle:cert-manager-inspect-objects"
                            | "lifecycle:issuer-inspect-objects"
                            | "lifecycle:certificate-inspect-objects"
                            | "lifecycle:registry-storage-inspect-storage"
                            | "lifecycle:registry-storage-inspect-objects"
                            | "lifecycle:registry-service-inspect-host"
                            | "lifecycle:registry-service-inspect-objects"
                            | "lifecycle:registry-endpoint-inspect-objects"
                            | "lifecycle:registry-auth-inspect-objects"
                            | "lifecycle:registry-token-inspect-host"
                            | "lifecycle:registry-token-inspect-objects"
                            | "lifecycle:registry-replication-inspect-replication"
                            | "lifecycle:registry-replication-inspect-objects"
                            | "lifecycle:delivery-inspect-images"
                            | "lifecycle:delivery-check-closure"
                            | "lifecycle:delivery-read-origin-log"
                            | "lifecycle:node-observe-node"
                            | "lifecycle:node-observe-drain"
                            | "lifecycle:release-discover-kinds"
                            | "lifecycle:release-inspect-workloads"
                            | "lifecycle:release-observe-release"
                            | "hook:before_apply"
                            | "hook:health"
                            | "inspect"
                    )
                )
                && !snapshot.deselected(s)
        }) {
            require(
                snapshot.observations.iter().any(|o| {
                    o["event"]["type"] == "receiver"
                        && o["attempt"] == step["attempt"]
                        && o["step"] == step["step"]
                        && o["dispatch"] == step["dispatch"]
                        && o["event"]["receipt"]["binding"] == snapshot.binding(step)
                        && o["event"]["receipt"]["payload_sha256"] == step["payload_sha256"]
                        && o["event"]["receipt"]["writer_ended"] == true
                }),
                Failure::Readiness,
            )?;
        }
        for &index in order {
            let (_, excluded) = selection(self.local.snapshot()?)?;
            let payload = json!({"members":self.members,"excluded":excluded});
            self.dispatch(index, "seal-writer", payload, Vec::new())
                .await?;
        }
        let snapshot = self.local.snapshot()?;
        let references: Vec<Value> = snapshot
            .observations
            .iter()
            .filter(|o| {
                o["attempt"] == self.attempt["attempt"]
                    && (o["event"]["type"] == "reservation" && o["event"]["state"] == "sealed"
                        || o["event"]["type"] == "receiver"
                            && o["event"]["receipt"]["action"] == "seal-writer")
            })
            .map(|o| o["sequence"].clone())
            .collect();
        let payload = snapshot.retirement_evidence(&self.attempt["attempt"], &references)?;
        for &index in order {
            self.dispatch(index, "retire-writer", payload.clone(), references.clone())
                .await?;
        }
        require(self.mode != Mode::SettlementOnly, Failure::Readiness)?;
        Ok(self.local.snapshot()?.clone())
    }
}
