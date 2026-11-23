// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod grammar;
pub use grammar::{Verb, group, help};

use super::{config_json, state, subtree};
use broil_config::{LoadedProject, k3s::select};
use broil_core::secret::environment::CredentialInputs;
use serde_json::json;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};

pub struct Invocation {
    pub verb: Verb,
    pub operands: Vec<String>,
    pub options: BTreeMap<String, String>,
}

pub struct Inputs<'a> {
    pub cwd: &'a Path,
    pub environment: Option<&'a OsStr>,
    pub env_snapshot: &'a [(OsString, OsString)],
    pub credentials: CredentialInputs,
}

pub struct Output {
    pub payload: Vec<u8>,
    pub status: i32,
}

#[derive(Debug)]
pub struct Refusal {
    pub failure: state::Failure,
    pub boundary: Option<&'static str>,
    pub detail: Option<String>,
}

impl From<state::Failure> for Refusal {
    fn from(failure: state::Failure) -> Self {
        Self {
            failure,
            boundary: None,
            detail: None,
        }
    }
}

impl From<state::ExecutionFailure> for Refusal {
    fn from(failure: state::ExecutionFailure) -> Self {
        Self {
            failure: failure.failure,
            boundary: None,
            detail: failure.detail.map(str::to_owned),
        }
    }
}

impl PartialEq<state::Failure> for Refusal {
    fn eq(&self, failure: &state::Failure) -> bool {
        self.failure == *failure
    }
}

pub fn run(
    project: &LoadedProject,
    invocation: Invocation,
    inputs: Inputs<'_>,
) -> std::result::Result<Output, Refusal> {
    let environment = inputs
        .environment
        .and_then(OsStr::to_str)
        .filter(|v| !v.is_empty())
        .ok_or(state::Failure::Configuration)?;
    let env = project
        .config
        .environments
        .get(environment)
        .ok_or(state::Failure::Configuration)?;
    let verb = invocation.verb.name();
    let table = invocation
        .options
        .get("--format")
        .is_none_or(|v| v == "table");
    if verb == "list" {
        let targets:Vec<_>=env.k3s.iter().map(|(name,target)|json!({"target":name,"members":target.members.len(),"version":target.version})).collect();
        let value = json!({"format_version":1,"environment":environment,"targets":targets});
        return Ok(Output {
            payload: state::render(&value, table)?,
            status: 0,
        });
    }
    let target = invocation
        .operands
        .first()
        .ok_or(state::Failure::Configuration)?;
    let selected = select::select(project, inputs.environment, target)
        .map_err(|_| state::Failure::Configuration)?;
    if verb == "show" {
        let declaration = config_json(
            subtree(
                &project.config.normalized,
                &["environments", environment, "k3s", target],
            )
            .map_err(|_| state::Failure::Configuration)?,
        );
        return Ok(Output {
            payload: state::render(
                &json!({"format_version":1,"environment":environment,"target":target,"declaration":declaration}),
                table,
            )?,
            status: 0,
        });
    }
    if let Some(member) = invocation
        .operands
        .get(1)
        .filter(|_| verb.starts_with("node "))
    {
        state::require(
            selected
                .declaration
                .members
                .iter()
                .any(|m| m.name == *member),
            state::Failure::Configuration,
        )?;
    }
    let action = invocation
        .options
        .get("--action")
        .map(String::as_str)
        .unwrap_or(verb);
    if verb != "operation prune" {
        let scope = state::scope(&project.broil_root, environment, target)?;
        state::history::unfinished(&project.broil_root, &scope, target)?;
        if let Some(operation) = invocation.operands.get(1).filter(|_| {
            matches!(
                verb,
                "operation show" | "operation resume" | "operation retry"
            )
        }) {
            let recorded = project
                .broil_root
                .join("state/infrastructure/targets")
                .join(scope["hash"].as_str().ok_or(state::Failure::Integrity)?)
                .join("operations")
                .join(operation);
            if state::operation_id(operation) && std::fs::symlink_metadata(&recorded).is_err() {
                if let Some(n) = state::history::pruned_operations(&project.broil_root, &scope)? {
                    return Err(Refusal {
                        failure: state::Failure::Configuration,
                        boundary: Some("operation"),
                        detail: Some(format!(
                            "{operation} is not recorded for target {target}; history cleanups removed {n} operation records"
                        )),
                    });
                }
            }
        }
    }
    let application = if verb.starts_with("release ") && !RELEASE_OPERAND.contains(&verb) {
        invocation.operands.get(1)
    } else {
        invocation.options.get("--application")
    };
    if let Some(application) = application {
        let declared = env.applications.get(application).ok_or_else(|| Refusal {
            failure: state::Failure::Configuration,
            boundary: Some("application"),
            detail: Some(format!(
                "{application} is not declared in environment {environment}"
            )),
        })?;
        if declared.target != *target {
            return Err(Refusal {
                failure: state::Failure::Configuration,
                boundary: Some("application"),
                detail: Some(format!(
                    "{application} belongs to target {}, not {target}",
                    declared.target
                )),
            });
        }
    }
    let release = if RELEASE_OPERAND.contains(&verb) {
        invocation.operands.get(1)
    } else {
        invocation.options.get("--release")
    };
    if let Some(release) = release {
        let scope = state::scope(&project.broil_root, environment, target)?;
        let store = project
            .broil_root
            .join("state/releases")
            .join(scope["hash"].as_str().ok_or(state::Failure::Integrity)?);
        if !recorded(&store, release)? {
            let pruned = pruned_releases(&project.broil_root, &scope)?;
            let removed = pruned
                .map(|n| format!("; history cleanups removed {n} release records"))
                .unwrap_or_default();
            return Err(Refusal {
                failure: state::Failure::Configuration,
                boundary: Some("release"),
                detail: Some(format!(
                    "{release} is not recorded for target {target}{removed}"
                )),
            });
        }
    }
    if let Some(member_action) = state::member::action(verb, action) {
        let member = if verb == "plan" {
            invocation.options.get("--member")
        } else {
            invocation.operands.get(1)
        }
        .ok_or(state::Failure::Configuration)?;
        let scope = state::scope(&project.broil_root, environment, target)?;
        if verb == "plan" && !invocation.options.contains_key("--observe") {
            let value =
                state::member::intended(&scope, selected.declaration, member_action, member)?;
            return Ok(Output {
                payload: state::render(&value, table)?,
                status: 0,
            });
        }
        if verb != "plan" {
            state::member::uncreated(
                &project.broil_root,
                &scope,
                selected.declaration,
                member_action,
                member,
            )?;
        }
        let policy = super::Policy {
            environment: environment.into(),
            cwd: inputs.cwd.to_path_buf(),
            environment_snapshot: inputs.env_snapshot.to_vec(),
            credentials: inputs.credentials,
            non_interactive: invocation.options.contains_key("--non-interactive"),
            deadline: tokio::time::Instant::now()
                + std::time::Duration::from_secs(selected.operation_timeout.seconds),
            cancellation: broil_remote::scheduler::CancellationToken::default(),
        };
        return state::member::command(
            project,
            policy,
            target,
            state::member::Leaf {
                action: member_action,
                member,
                approve: invocation.options.get("--approve").map(String::as_str),
                plan: verb == "plan",
                table,
            },
        );
    }
    if matches!(
        verb,
        "release deliver"
            | "release retain"
            | "delivery report"
            | "delivery check"
            | "release prepare"
            | "release list"
            | "release show"
            | "release apply"
            | "release rollback"
            | "release status"
            | "release deploy"
    ) || verb == "plan" && matches!(action, "release-retain" | "release-apply")
    {
        let policy = super::Policy {
            environment: environment.into(),
            cwd: inputs.cwd.to_path_buf(),
            environment_snapshot: inputs.env_snapshot.to_vec(),
            credentials: inputs.credentials,
            non_interactive: invocation.options.contains_key("--non-interactive"),
            deadline: tokio::time::Instant::now()
                + std::time::Duration::from_secs(selected.operation_timeout.seconds),
            cancellation: broil_remote::scheduler::CancellationToken::default(),
        };
        return delivery(project, &invocation, policy, target, table);
    }
    if verb == "operation prune" || verb == "plan" && action == "operation-prune" {
        return history(
            project,
            &invocation,
            inputs,
            selected.operation_timeout.seconds,
            target,
            table,
        );
    }
    let later = matches!(
        verb,
        "upgrade"
            | "remove"
            | "purge"
            | "registry upgrade"
            | "registry remove"
            | "registry maintenance plan"
            | "registry maintenance run"
            | "backup create"
            | "backup list"
            | "backup restore"
            | "registry backup"
            | "registry restore"
            | "registry retention list"
            | "registry retention hold"
            | "registry retention release"
    ) || (verb == "plan"
        && !matches!(
            action,
            "create"
                | "reconcile"
                | "node-join"
                | "node-join-agents"
                | "credentials-reconcile"
                | "registry-reconcile"
        ))
        || invocation
            .options
            .get("--consumer")
            .is_some_and(|c| matches!(c.as_str(), "server-token" | "agent-token"));
    if later
        || (!state::views::supported(verb)
            && !state::access::supported(verb)
            && !matches!(
                verb,
                "operation list"
                    | "operation show"
                    | "operation resume"
                    | "operation retry"
                    | "node join"
                    | "node join-agents"
                    | "plan"
                    | "create"
                    | "reconcile"
            ))
    {
        return Err(Refusal {
            failure: state::Failure::Capability,
            boundary: Some(if later {
                "a later roadmap implements it"
            } else {
                "not implemented in this version"
            }),
            detail: None,
        });
    }
    if state::views::supported(verb) {
        state::views::preflight(
            selected.declaration,
            verb,
            invocation.options.get("--component").map(String::as_str),
        )?;
    }
    let access_command = state::access::supported(verb)
        || verb == "plan" && matches!(action, "credentials-reconcile" | "registry-reconcile");
    let consumer = invocation.options.get("--consumer").map(String::as_str);
    if access_command {
        state::access::preflight(
            &selected,
            if verb == "plan" { action } else { verb },
            consumer,
        )?;
    }
    let scope = state::scope(&project.broil_root, environment, target)?;
    let operation = invocation.operands.get(1).map(String::as_str);
    if matches!(verb, "operation list" | "operation show") {
        let mut store = state::Store::new(
            project.broil_root.clone(),
            scope.clone(),
            30_000,
            Arc::new(AtomicBool::new(false)),
        )?;
        let read = match operation {
            Some(_) => store.read_operations(operation).map(|s| (s, Vec::new())),
            None => store.read_listed(),
        };
        let (snapshots, unlisted) = match read {
            Ok(read) => read,
            Err(failure) => {
                let mut value =
                    failure.report(&scope, if operation.is_some() { "show" } else { "list" })?;
                state::history::attach_store(&project.broil_root, &scope, &mut value);
                return Ok(Output {
                    payload: state::render(&value, table)?,
                    status: 1,
                });
            }
        };
        let mut value = if operation.is_some() {
            state::recorded_report(&scope, "show", &snapshots)?
        } else {
            state::listed_report(&scope, &snapshots, &unlisted)?
        };
        state::history::attach_store(&project.broil_root, &scope, &mut value);
        return Ok(Output {
            payload: state::render(&value, table)?,
            status: 0,
        });
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| state::Failure::Bound)?;
    let cancelled = broil_remote::scheduler::CancellationToken::default();
    let policy = super::Policy {
        environment: environment.into(),
        cwd: inputs.cwd.to_path_buf(),
        environment_snapshot: inputs.env_snapshot.to_vec(),
        credentials: inputs.credentials,
        non_interactive: invocation.options.contains_key("--non-interactive"),
        deadline: tokio::time::Instant::now()
            + std::time::Duration::from_secs(selected.operation_timeout.seconds),
        cancellation: cancelled.clone(),
    };
    let convergence = !access_command && matches!(verb, "plan" | "create" | "reconcile");
    let prepared = if convergence {
        Some(state::converge::Prepared::new(
            project, &policy, target, action,
        )?)
    } else {
        None
    };
    let access_prepared = if access_command {
        Some(state::access::Prepared::new(
            project,
            &policy,
            target,
            if verb == "plan" { action } else { verb },
            consumer,
            invocation.options.get("--output").map(String::as_str),
        )?)
    } else {
        None
    };
    let plan = if verb == "plan" && access_command {
        Some(
            access_prepared
                .as_ref()
                .ok_or(state::Failure::Integrity)?
                .plan()?,
        )
    } else if verb == "plan" {
        Some(prepared.as_ref().ok_or(state::Failure::Integrity)?.plan(
            action,
            invocation.options.get("--member").map(String::as_str),
        )?)
    } else {
        None
    };
    if verb == "plan" && !invocation.options.contains_key("--observe") {
        return Ok(Output {
            payload: state::render(plan.as_ref().ok_or(state::Failure::Integrity)?, table)?,
            status: 0,
        });
    }
    if verb == "credentials reconcile" && !matches!(consumer, Some("admin")) {
        let workflow = access_prepared
            .as_ref()
            .ok_or(state::Failure::Integrity)?
            .workflow()?;
        state::history::workflow_room(&project.broil_root, &scope, verb, |_, _| Ok(workflow))?;
    }
    if verb == "node join" {
        state::member::joinable(
            &project.broil_root,
            &scope,
            selected.declaration,
            operation.ok_or(state::Failure::Configuration)?,
        )?;
    }
    if matches!(verb, "node join" | "node join-agents") {
        let members = &selected.declaration.members;
        let width = usize::from(selected.agent_wave_size).max(1);
        state::history::workflow_room(&project.broil_root, &scope, verb, |previous, waves| {
            if verb == "node join-agents" {
                return state::wave_plan(previous, waves, width);
            }
            let member = members
                .iter()
                .find(|m| Some(m.name.as_str()) == operation)
                .ok_or(state::Failure::Configuration)?;
            let source = match previous.first() {
                Some(snapshot) => state::join_source(&snapshot.owner, &member.machine)?,
                None => members
                    .first()
                    .ok_or(state::Failure::Configuration)?
                    .machine
                    .clone(),
            };
            let action = if member.role == broil_core::k3s::Role::Agent {
                "join-agent"
            } else {
                "join-server"
            };
            Ok(serde_json::json!({"waves": [[{"action": action,
                "hosts": [source, member.machine]}]]}))
        })?;
    }
    let stop = broil_remote::scheduler::CancellationToken::default();
    let result = runtime.block_on(async {
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| state::Failure::Bound)?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| state::Failure::Bound)?;
        let work = async {
            if let Some(prepared)=access_prepared {return prepared.run(plan,stop.clone()).await;}
            if state::views::supported(verb) {
                let limit = matches!(verb, "diagnose" | "nodes" | "workloads" | "services")
                    .then(|| invocation.options.get("--limit").map_or(Ok(100), |n| n.parse::<usize>().map_err(|_| state::Failure::Configuration)))
                    .transpose()?;
                if let Some(limit) = limit { state::require((1..=1000).contains(&limit), state::Failure::Configuration)?; }
                return state::views::run(project, policy, target, verb,
                    invocation.options.get("--component").map(String::as_str), limit).await;
            }
            if let Some(prepared) = prepared {
                return prepared.run(action, plan, stop.clone()).await;
            }
            if verb == "node join" {
                let member = operation.ok_or(state::Failure::Configuration)?;
                let selected_member = selected
                    .declaration
                    .members
                    .iter()
                    .find(|m| m.name == member)
                    .ok_or(state::Failure::Configuration)?;
                let source = selected
                    .declaration
                    .members
                    .first()
                    .ok_or(state::Failure::Configuration)?;
                let snapshot = if selected_member.role == broil_core::k3s::Role::Agent {
                    state::join_agent(
                        project,
                        policy,
                        target,
                        &selected_member.machine,
                        &source.machine,
                    )
                    .await?
                } else {
                    state::join_server(
                        project,
                        policy,
                        target,
                        &selected_member.machine,
                        &source.machine,
                    )
                    .await?
                };
                return Ok((state::recorded_report(&scope, "show", &[snapshot])?, true));
            }
            if verb == "node join-agents" {
                let source = selected
                    .declaration
                    .members
                    .first()
                    .ok_or(state::Failure::Configuration)?;
                let agents: Vec<_> = selected
                    .declaration
                    .members
                    .iter()
                    .filter(|member| member.role == broil_core::k3s::Role::Agent)
                    .map(|member| member.machine.clone())
                    .collect();
                let snapshot = state::join_agents(
                    project,
                    policy,
                    target,
                    &source.machine,
                    &agents,
                    selected.agent_wave_size,
                )
                .await?;
                return Ok((state::recorded_report(&scope, "show", &[snapshot])?, true));
            }
            let operation = operation.ok_or(state::Failure::Configuration)?;
            if verb == "operation retry" {
                let step = invocation
                    .options
                    .get("--step")
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or(state::Failure::Configuration)?;
                let approve = invocation
                    .options
                    .get("--approve")
                    .ok_or(state::Failure::Configuration)?;
                state::retry(project, policy, target, operation, step, approve).await
            } else {
                state::resume(project, policy, target, operation).await
            }
        };
        tokio::pin!(work);
        loop {
            tokio::select! {
                result=&mut work=>break result,
                _=interrupt.recv()=>{},
                _=terminate.recv()=>{},
            }
            if signal(verb,consumer,&stop,&cancelled) {
                eprintln!("broil: k3s {verb}: stopping after the work in progress; interrupt again to cancel it");
            }
        }
    });
    runtime.shutdown_background();
    let (mut value, complete) = match result {
        Ok(value) => value,
        Err(failure) if convergence || access_command || state::views::supported(verb) => {
            return Err(failure.into());
        }
        Err(failure) => (
            failure.report(
                &scope,
                if verb == "operation retry" {
                    "retry"
                } else if matches!(verb, "node join" | "node join-agents") {
                    "join"
                } else {
                    "resume"
                },
            )?,
            false,
        ),
    };
    if !state::views::supported(verb) || verb == "status" {
        state::history::attach_store(&project.broil_root, &scope, &mut value);
    }
    Ok(Output {
        payload: state::render(&value, table)?,
        status: if complete { 0 } else { 1 },
    })
}

fn delivery(
    project: &LoadedProject,
    invocation: &Invocation,
    policy: super::Policy,
    target: &str,
    table: bool,
) -> std::result::Result<Output, Refusal> {
    use state::release_delivery as leaves;
    let verb = invocation.verb.name();
    let operand = invocation.operands.get(1).map(String::as_str).unwrap_or("");
    let cancellation = policy.cancellation.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| state::Failure::Bound)?;
    let result = runtime.block_on(async {
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| state::Failure::Bound)?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| state::Failure::Bound)?;
        let work = async {
            match verb {
                "release deliver" => leaves::deliver(project, policy, target, operand)
                    .await
                    .map(|(report, complete)| (report, complete, true)),
                "release retain" => {
                    let approve = invocation
                        .options
                        .get("--approve")
                        .ok_or(state::Failure::Configuration)?;
                    leaves::retain(project, policy, target, operand, approve)
                        .await
                        .map(|(report, complete)| (report, complete, true))
                }
                "delivery report" => leaves::delivery_report(project, policy, target, operand)
                    .await
                    .map(|(report, complete)| (report, complete, true)),
                "delivery check" => leaves::delivery_check(project, policy, target)
                    .await
                    .map(|(report, complete)| (report, complete, true)),
                "release prepare" => state::release::prepare(
                    project,
                    policy,
                    target,
                    operand,
                    invocation.options.get("--artifacts").map(String::as_str),
                )
                .await
                .map(|(report, complete)| (report, complete, true)),
                "release list" => {
                    let limit = invocation
                        .options
                        .get("--limit")
                        .map_or(Ok(100), |n| n.parse::<usize>())
                        .map_err(|_| state::Failure::Configuration)?;
                    state::release::list_releases(project, policy, target, operand, limit)
                        .await
                        .map(|(report, complete)| (report, complete, true))
                }
                "release show" => state::release::show(project, policy, target, operand)
                    .await
                    .map(|(report, complete)| (report, complete, true)),
                "release apply" => state::release_apply::apply(
                    project,
                    policy,
                    target,
                    operand,
                    invocation.options.get("--approve").map(String::as_str),
                )
                .await
                .map(|(report, complete)| (report, complete, true)),
                "release rollback" => {
                    state::release_apply::rollback(project, policy, target, operand)
                        .await
                        .map(|(report, complete)| (report, complete, true))
                }
                "release status" => state::release_status::status(project, policy, target, operand)
                    .await
                    .map(|(report, complete)| (report, complete, true)),
                "release deploy" => state::release_status::deploy(
                    project,
                    policy,
                    target,
                    operand,
                    invocation.options.get("--artifacts").map(String::as_str),
                )
                .await
                .map(|(report, complete)| (report, complete, true)),
                _ if invocation.options.contains_key("--release") => {
                    let release = invocation
                        .options
                        .get("--release")
                        .ok_or(state::Failure::Configuration)?;
                    let observe = invocation.options.contains_key("--observe");
                    state::release_apply::plan(project, policy, target, release, observe)
                        .await
                        .map(|plan| (plan, true, false))
                }
                _ => {
                    let application = invocation
                        .options
                        .get("--application")
                        .ok_or(state::Failure::Configuration)?;
                    let observe = invocation.options.contains_key("--observe");
                    leaves::retain_plan(project, policy, target, application, observe)
                        .await
                        .map(|plan| (plan, true, false))
                }
            }
        };
        tokio::pin!(work);
        loop {
            tokio::select! {
                result = &mut work => break result,
                _ = interrupt.recv() => cancellation.cancel(),
                _ = terminate.recv() => cancellation.cancel(),
            }
        }
    });
    runtime.shutdown_background();
    let (value, complete, view) = result.map_err(|refused| Refusal {
        failure: refused.failure,
        boundary: refused.boundary,
        detail: refused.detail,
    })?;
    let payload = if view {
        let format = if table {
            super::report::Format::Table
        } else {
            super::report::Format::Json
        };
        super::report::encode(&value, format).map_err(|refusal| Refusal {
            failure: state::Failure::Bound,
            boundary: Some(refusal.boundary),
            detail: Some(refusal.detail),
        })?
    } else {
        state::render(&value, table)?
    };
    Ok(Output {
        payload,
        status: if complete { 0 } else { 1 },
    })
}

fn history(
    project: &LoadedProject,
    invocation: &Invocation,
    inputs: Inputs<'_>,
    timeout_seconds: u64,
    target: &str,
    table: bool,
) -> std::result::Result<Output, Refusal> {
    let number = |name: &str, default: u32| {
        invocation
            .options
            .get(name)
            .map_or(Ok(default), |v| v.parse::<u32>())
            .map_err(|_| state::Failure::Configuration)
    };
    let defaults = super::history::Policy::default();
    let keep = super::history::Policy::new(
        number("--keep-days", defaults.keep_days)?,
        number("--keep-last", defaults.keep_last)?,
    )
    .map_err(|_| state::Failure::Configuration)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| state::Failure::Bound)?;
    let policy = super::Policy {
        environment: inputs
            .environment
            .and_then(OsStr::to_str)
            .ok_or(state::Failure::Configuration)?
            .into(),
        cwd: inputs.cwd.to_path_buf(),
        environment_snapshot: inputs.env_snapshot.to_vec(),
        credentials: inputs.credentials,
        non_interactive: invocation.options.contains_key("--non-interactive"),
        deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds),
        cancellation: broil_remote::scheduler::CancellationToken::default(),
    };
    let result = runtime.block_on(async {
        if invocation.verb.name() == "plan" {
            let observe = invocation.options.contains_key("--observe");
            state::history::plan(project, policy, target, keep, observe)
                .await
                .map(|plan| (plan, true))
        } else {
            let approve = invocation
                .options
                .get("--approve")
                .ok_or(state::Failure::Configuration)?;
            state::history::prune(project, policy, target, keep, approve).await
        }
    });
    runtime.shutdown_background();
    let (value, complete) = result?;
    let payload = if value["view"] == "plan" {
        state::render(&value, table)?
    } else {
        let format = if table {
            super::report::Format::Table
        } else {
            super::report::Format::Json
        };
        super::report::encode(&value, format).map_err(|r| Refusal {
            failure: state::Failure::Bound,
            boundary: Some(r.boundary),
            detail: Some(r.detail),
        })?
    };
    Ok(Output {
        payload,
        status: if complete { 0 } else { 1 },
    })
}

const RELEASE_OPERAND: &[&str] = &[
    "release deliver",
    "release apply",
    "release show",
    "delivery report",
];

fn pruned_releases(
    root: &Path,
    scope: &serde_json::Value,
) -> std::result::Result<Option<u64>, Refusal> {
    let hash = scope["hash"].as_str().ok_or(state::Failure::Integrity)?;
    let path = root
        .join("state/infrastructure/targets")
        .join(hash)
        .join("history/checkpoint.json");
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(state::Failure::Storage.into()),
    };
    let checkpoint =
        super::history::checkpoint::decode(&raw).map_err(|_| state::Failure::Integrity)?;
    if checkpoint["scope"] != *scope {
        return Err(state::Failure::Ownership.into());
    }
    Ok(checkpoint["pruned_releases"].as_u64().filter(|n| *n > 0))
}

fn recorded(store: &Path, release: &str) -> std::result::Result<bool, Refusal> {
    match std::fs::symlink_metadata(store) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        _ => {}
    }
    let releases = super::release::store::enumerate(store).map_err(|refusal| Refusal {
        failure: match refusal.failure {
            "bound" => state::Failure::Bound,
            "storage" => state::Failure::Storage,
            _ => state::Failure::Integrity,
        },
        boundary: Some(refusal.boundary),
        detail: Some(refusal.detail),
    })?;
    Ok(releases.iter().any(|r| r["release"] == release))
}

fn signal(
    verb: &str,
    consumer: Option<&str>,
    stop: &broil_remote::scheduler::CancellationToken,
    active: &broil_remote::scheduler::CancellationToken,
) -> bool {
    if matches!(verb, "create" | "reconcile" | "registry reconcile")
        || verb == "credentials reconcile" && consumer != Some("admin")
    {
        state::converge::interrupt(stop, active)
    } else {
        active.cancel();
        false
    }
}

