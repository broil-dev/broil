// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::alias::{env_jump_alias, root_jump_alias, target_alias};
use crate::known_hosts::{AliasState, CommitOutcome, KnownHostsStore, Mutation, StoreError};
use crate::scheduler::CancellationToken;
use crate::transport::{FetchRequest, HostKeyFetcher, JumpFetchRequest};
use crate::{EffectiveInventory, EffectiveMachine, FailureClass, HostKey, JumpScope};

pub const VERIFIABLE_ALGORITHMS: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntityKind {
    Jump,
    Machine,
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jump => "jump",
            Self::Machine => "machine",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustEntity {
    pub kind: EntityKind,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub alias: String,
    pub timeout: Duration,
    pub selected_machines: Vec<String>,
    pub via_jump: bool,
    pub jump: Option<TrustJump>,
}

#[derive(Debug, Clone)]
pub struct TrustJump {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub alias: String,
    pub auth_profile: String,
}

#[derive(Debug, Clone)]
pub struct TrustPlan {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub entities: Vec<TrustEntity>,
}

#[derive(Debug)]
pub struct TrustError {
    class: FailureClass,
    diagnostic: String,
}

impl TrustError {
    pub fn class(&self) -> FailureClass {
        self.class
    }
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.diagnostic)
    }
}

impl std::error::Error for TrustError {}

pub fn plan_machines(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
) -> Result<TrustPlan, TrustError> {
    let selected_machines = selected
        .iter()
        .map(|machine| machine.name.clone())
        .collect::<Vec<_>>();
    let mut entities = Vec::new();
    let mut emitted_jumps = BTreeSet::new();
    for machine in selected {
        let jump = if machine.route == "direct" {
            None
        } else {
            Some(
                inventory
                    .jumps
                    .iter()
                    .find(|jump| jump.name == machine.route)
                    .ok_or_else(|| TrustError {
                        class: FailureClass::Configuration,
                        diagnostic: format!("unknown jump host {}", machine.route),
                    })?,
            )
        };
        if let Some(jump) = jump {
            if emitted_jumps.insert(machine.route.clone()) {
                let dependents = selected
                    .iter()
                    .filter(|candidate| candidate.route == jump.name)
                    .map(|candidate| candidate.name.clone())
                    .collect();
                entities.push(jump_entity(root, inventory, jump, dependents));
            }
        }
        entities.push(TrustEntity {
            kind: EntityKind::Machine,
            name: machine.name.clone(),
            address: machine.address.clone(),
            port: machine.port,
            alias: target_alias(root, &inventory.environment, &machine.name),
            timeout: Duration::from_secs(machine.timeouts.connect.seconds),
            selected_machines: vec![machine.name.clone()],
            via_jump: machine.route != "direct",
            jump: jump.map(|jump| TrustJump {
                name: jump.name.clone(),
                address: jump.address.clone(),
                port: jump.port,
                alias: jump_alias(root, inventory, jump),
                auth_profile: jump.auth_profile.clone(),
            }),
        });
    }
    Ok(TrustPlan {
        environment: inventory.environment.clone(),
        selected_machines,
        entities,
    })
}

pub fn plan_jump(
    root: &Path,
    inventory: &EffectiveInventory,
    name: &str,
) -> Result<TrustPlan, TrustError> {
    let jump = inventory
        .jumps
        .iter()
        .find(|jump| jump.name == name)
        .ok_or_else(|| TrustError {
            class: FailureClass::Selector,
            diagnostic: format!("unknown jump host {name}"),
        })?;
    Ok(TrustPlan {
        environment: inventory.environment.clone(),
        selected_machines: Vec::new(),
        entities: vec![jump_entity(root, inventory, jump, Vec::new())],
    })
}

fn jump_entity(
    root: &Path,
    inventory: &EffectiveInventory,
    jump: &crate::EffectiveJump,
    selected_machines: Vec<String>,
) -> TrustEntity {
    let alias = match jump.scope {
        JumpScope::Root => root_jump_alias(root, &jump.name),
        JumpScope::Environment => env_jump_alias(root, &inventory.environment, &jump.name),
    };
    TrustEntity {
        kind: EntityKind::Jump,
        name: jump.name.clone(),
        address: jump.address.clone(),
        port: jump.port,
        alias,
        timeout: Duration::from_secs(jump.connect_timeout.seconds),
        selected_machines,
        via_jump: false,
        jump: None,
    }
}

fn jump_alias(root: &Path, inventory: &EffectiveInventory, jump: &crate::EffectiveJump) -> String {
    match jump.scope {
        JumpScope::Root => root_jump_alias(root, &jump.name),
        JumpScope::Environment => env_jump_alias(root, &inventory.environment, &jump.name),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Unknown,
    Trusted,
    Changed,
}

impl TrustState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Trusted => "trusted",
            Self::Changed => "changed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustAction {
    Enrolled,
    Replaced,
    Unchanged,
}

impl TrustAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enrolled => "enrolled",
            Self::Replaced => "replaced",
            Self::Unchanged => "unchanged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    Success,
    Failed,
}

impl TrustStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TrustOptions {
    pub fingerprint: Option<String>,
    pub replace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustCandidate {
    pub entity_kind: EntityKind,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub prior_state: TrustState,
    pub canonicalizing: bool,
}

pub trait TrustDecider {
    fn observe_key(&mut self, candidate: &TrustCandidate);
    fn confirm(&mut self, candidate: &TrustCandidate) -> bool;
    fn confirm_cancellable(
        &mut self,
        candidate: &TrustCandidate,
        cancel: &CancellationToken,
    ) -> TrustConfirmation {
        let accepted = self.confirm(candidate);
        if cancel.is_cancelled() {
            TrustConfirmation::Cancelled
        } else if accepted {
            TrustConfirmation::Accepted
        } else {
            TrustConfirmation::Declined
        }
    }
    fn observe_failure(&mut self, kind: EntityKind, name: &str, diagnostic: &str);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustConfirmation {
    Accepted,
    Declined,
    Cancelled,
}

pub trait Clock {
    fn now_millis(&mut self) -> u128;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&mut self) -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }
}

pub struct InterruptWatcher {
    stop: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for InterruptWatcher {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
pub fn spawn_interrupt_watcher(cancel: CancellationToken) -> Option<InterruptWatcher> {
    let stop = CancellationToken::default();
    let stop_for_thread = stop.clone();
    let thread = std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        runtime.block_on(async move {
            let Ok(mut interrupt) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            else {
                return;
            };
            let mut seen = false;
            loop {
                tokio::select! {
                    _ = stop_for_thread.cancelled() => return,
                    signal = interrupt.recv() => {
                        if signal.is_none() {
                            return;
                        }
                        if seen {
                            crate::secret::restore_global_input_terminal();
                            std::process::exit(130);
                        }
                        seen = true;
                        cancel.cancel();
                    }
                }
            }
        });
    });
    Some(InterruptWatcher {
        stop,
        thread: Some(thread),
    })
}

#[cfg(not(unix))]
pub fn spawn_interrupt_watcher(_cancel: CancellationToken) -> Option<InterruptWatcher> {
    None
}

#[derive(Debug, Clone)]
pub struct TrustResult {
    pub entity_kind: EntityKind,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub selected_machines: Vec<String>,
    pub prior_state: Option<TrustState>,
    pub algorithm: Option<String>,
    pub fingerprint: Option<String>,
    pub action: Option<TrustAction>,
    pub status: TrustStatus,
    pub failure_class: Option<FailureClass>,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TrustOutcome {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub duration_millis: u128,
    pub results: Vec<TrustResult>,
}

impl TrustOutcome {
    pub fn status(&self) -> i32 {
        if self
            .results
            .iter()
            .all(|result| result.status == TrustStatus::Success)
        {
            0
        } else {
            1
        }
    }
}

pub fn run(
    plan: &TrustPlan,
    store: &KnownHostsStore,
    options: &TrustOptions,
    fetcher: &mut dyn HostKeyFetcher,
    decider: &mut dyn TrustDecider,
    clock: &mut dyn Clock,
) -> TrustOutcome {
    run_cancellable(
        plan,
        store,
        options,
        fetcher,
        decider,
        clock,
        &CancellationToken::default(),
    )
}

pub fn run_cancellable(
    plan: &TrustPlan,
    store: &KnownHostsStore,
    options: &TrustOptions,
    fetcher: &mut dyn HostKeyFetcher,
    decider: &mut dyn TrustDecider,
    clock: &mut dyn Clock,
    cancel: &CancellationToken,
) -> TrustOutcome {
    let started = clock.now_millis();
    let mut results = Vec::with_capacity(plan.entities.len());

    if cancel.is_cancelled() {
        push_unprocessed_cancellations(&mut results, &plan.entities, decider);
        return finished_outcome(plan, clock, started, results);
    }

    if options.fingerprint.is_some() && !plan.selected_machines.is_empty() {
        for entity in plan
            .entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Jump)
        {
            let state = store
                .snapshot()
                .and_then(|snapshot| snapshot.inspect(&entity.alias, false));
            match state {
                Ok(AliasState::Pinned(_)) => {}
                Ok(_) => {
                    let diagnostic = "a machine fingerprint requires every jump host to be pinned before network activity";
                    decider.observe_failure(entity.kind, &entity.name, diagnostic);
                    results.push(failed_result(
                        entity,
                        Some(TrustState::Unknown),
                        FailureClass::UnknownHostKey,
                        diagnostic,
                    ));
                    return finished_outcome(plan, clock, started, results);
                }
                Err(error) => {
                    decider.observe_failure(entity.kind, &entity.name, &error.to_string());
                    results.push(store_failure(entity, None, &error));
                    return finished_outcome(plan, clock, started, results);
                }
            }
        }
    }

    for (index, entity) in plan.entities.iter().enumerate() {
        if cancel.is_cancelled() {
            push_unprocessed_cancellations(&mut results, &plan.entities[index..], decider);
            break;
        }
        let snapshot = match store.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                decider.observe_failure(entity.kind, &entity.name, &error.to_string());
                results.push(store_failure(entity, None, &error));
                continue;
            }
        };
        let alias_state = match snapshot.inspect(&entity.alias, options.replace) {
            Ok(state) => state,
            Err(error) => {
                decider.observe_failure(entity.kind, &entity.name, &error.to_string());
                results.push(store_failure(entity, None, &error));
                continue;
            }
        };
        let fingerprint_applies = entity.kind == EntityKind::Machine
            || (plan.selected_machines.is_empty() && entity.kind == EntityKind::Jump);
        let jump_request = match target_jump_request(entity, store, &results) {
            Ok(request) => request,
            Err((class, diagnostic)) => {
                decider.observe_failure(entity.kind, &entity.name, &diagnostic);
                results.push(failed_result(entity, None, class, &diagnostic));
                continue;
            }
        };

        let (algorithms, pin_constrained) = match &alias_state {
            AliasState::Pinned(key) if !options.replace => (vec![key.algorithm.clone()], true),
            AliasState::Pinned(key) => (pinned_first(std::slice::from_ref(key)), false),
            AliasState::Replaceable { prior, .. } => (pinned_first(prior), false),
            AliasState::Unknown => (
                VERIFIABLE_ALGORITHMS
                    .iter()
                    .map(|algorithm| (*algorithm).to_string())
                    .collect(),
                false,
            ),
        };
        let request = FetchRequest {
            entity_kind: entity.kind,
            name: entity.name.clone(),
            address: entity.address.clone(),
            port: entity.port,
            timeout: entity.timeout,
            algorithms,
            pin_constrained,
            jump: jump_request,
        };
        let presented = match fetcher.fetch_cancellable(&request, cancel) {
            Ok(key) => key,
            Err(error) => {
                let prior_state = match &alias_state {
                    AliasState::Unknown => TrustState::Unknown,
                    AliasState::Pinned(_) if error.class == FailureClass::ChangedHostKey => {
                        TrustState::Changed
                    }
                    AliasState::Pinned(_) => TrustState::Trusted,
                    AliasState::Replaceable { .. } => TrustState::Changed,
                };
                decider.observe_failure(entity.kind, &entity.name, &error.diagnostic);
                let mut result =
                    failed_result(entity, Some(prior_state), error.class, &error.diagnostic);
                if error.class == FailureClass::Cancellation {
                    result.diagnostic = Some("cancelled".to_string());
                }
                results.push(result);
                if error.class == FailureClass::Cancellation {
                    push_unprocessed_cancellations(
                        &mut results,
                        &plan.entities[index + 1..],
                        decider,
                    );
                    break;
                }
                continue;
            }
        };
        let unchanged =
            matches!(&alias_state, AliasState::Pinned(pinned) if same_key(pinned, &presented));
        let canonicalizing = matches!(
            &alias_state,
            AliasState::Replaceable {
                prior,
                duplicate: true,
            } if prior.iter().any(|key| same_key(key, &presented))
        );
        let prior_state = match &alias_state {
            AliasState::Unknown => TrustState::Unknown,
            AliasState::Pinned(_) if unchanged => TrustState::Trusted,
            AliasState::Pinned(_) | AliasState::Replaceable { .. } => TrustState::Changed,
        };
        let candidate = TrustCandidate {
            entity_kind: entity.kind,
            name: entity.name.clone(),
            address: entity.address.clone(),
            port: entity.port,
            algorithm: presented.algorithm.clone(),
            fingerprint: presented.fingerprint.clone(),
            prior_state,
            canonicalizing,
        };
        decider.observe_key(&candidate);

        if cancel.is_cancelled() {
            decider.observe_failure(entity.kind, &entity.name, "cancelled");
            let mut result = failed_result(
                entity,
                Some(prior_state),
                FailureClass::Cancellation,
                "cancelled",
            );
            result.algorithm = Some(presented.algorithm);
            result.fingerprint = Some(presented.fingerprint);
            results.push(result);
            push_unprocessed_cancellations(&mut results, &plan.entities[index + 1..], decider);
            break;
        }

        if unchanged {
            if fingerprint_applies
                && options
                    .fingerprint
                    .as_ref()
                    .is_some_and(|expected| expected != &presented.fingerprint)
            {
                decider.observe_failure(
                    entity.kind,
                    &entity.name,
                    "the supplied fingerprint does not match the presented trusted key",
                );
                let mut result = failed_result(
                    entity,
                    Some(prior_state),
                    FailureClass::Configuration,
                    "the supplied fingerprint does not match the presented trusted key",
                );
                result.algorithm = Some(presented.algorithm);
                result.fingerprint = Some(presented.fingerprint);
                results.push(result);
            } else {
                results.push(success_result(
                    entity,
                    prior_state,
                    &presented,
                    TrustAction::Unchanged,
                ));
            }
            continue;
        }

        let fingerprint_matches = fingerprint_applies
            && options
                .fingerprint
                .as_ref()
                .is_some_and(|expected| expected == &presented.fingerprint);
        let decision = match &alias_state {
            AliasState::Unknown => match options.fingerprint.as_ref() {
                Some(_) if fingerprint_applies => {
                    if fingerprint_matches {
                        TrustConfirmation::Accepted
                    } else {
                        TrustConfirmation::Declined
                    }
                }
                _ => decider.confirm_cancellable(&candidate, cancel),
            },
            AliasState::Pinned(_) => {
                if !options.replace {
                    TrustConfirmation::Declined
                } else {
                    match options.fingerprint.as_ref() {
                        Some(_) if fingerprint_applies => {
                            if fingerprint_matches {
                                TrustConfirmation::Accepted
                            } else {
                                TrustConfirmation::Declined
                            }
                        }
                        _ => decider.confirm_cancellable(&candidate, cancel),
                    }
                }
            }
            AliasState::Replaceable { .. } => {
                if !options.replace {
                    TrustConfirmation::Declined
                } else {
                    match options.fingerprint.as_ref() {
                        Some(_) if fingerprint_applies => {
                            if fingerprint_matches {
                                TrustConfirmation::Accepted
                            } else {
                                TrustConfirmation::Declined
                            }
                        }
                        _ => decider.confirm_cancellable(&candidate, cancel),
                    }
                }
            }
        };
        if decision == TrustConfirmation::Cancelled {
            decider.observe_failure(entity.kind, &entity.name, "cancelled");
            let mut result = failed_result(
                entity,
                Some(prior_state),
                FailureClass::Cancellation,
                "cancelled",
            );
            result.algorithm = Some(presented.algorithm);
            result.fingerprint = Some(presented.fingerprint);
            results.push(result);
            push_unprocessed_cancellations(&mut results, &plan.entities[index + 1..], decider);
            break;
        }
        if decision == TrustConfirmation::Declined {
            let class = if matches!(alias_state, AliasState::Unknown) {
                FailureClass::UnknownHostKey
            } else {
                FailureClass::ChangedHostKey
            };
            let diagnostic = if class == FailureClass::UnknownHostKey {
                if fingerprint_applies && options.fingerprint.is_some() {
                    "the supplied fingerprint does not match the presented unknown host key"
                } else {
                    "unknown host key was not confirmed"
                }
            } else if canonicalizing {
                "duplicate known-hosts entries were not approved for canonicalization with --replace"
            } else {
                "changed host key was not approved with --replace"
            };
            decider.observe_failure(entity.kind, &entity.name, diagnostic);
            let mut result = failed_result(entity, Some(prior_state), class, diagnostic);
            result.algorithm = Some(presented.algorithm);
            result.fingerprint = Some(presented.fingerprint);
            results.push(result);
            continue;
        }

        let (mutation, action) = if matches!(alias_state, AliasState::Unknown) {
            (Mutation::Enroll, TrustAction::Enrolled)
        } else {
            (Mutation::Replace, TrustAction::Replaced)
        };
        match store.commit(&entity.alias, &alias_state, &presented, mutation) {
            Ok(CommitOutcome::Applied) => {
                results.push(success_result(entity, prior_state, &presented, action));
            }
            Ok(CommitOutcome::AlreadyTrusted) => results.push(success_result(
                entity,
                prior_state,
                &presented,
                TrustAction::Unchanged,
            )),
            Err(error) => {
                decider.observe_failure(entity.kind, &entity.name, &error.to_string());
                results.push(store_failure(entity, Some(prior_state), &error));
            }
        }
    }

    finished_outcome(plan, clock, started, results)
}

fn target_jump_request(
    entity: &TrustEntity,
    store: &KnownHostsStore,
    results: &[TrustResult],
) -> Result<Option<JumpFetchRequest>, (FailureClass, String)> {
    let Some(jump) = &entity.jump else {
        return Ok(None);
    };
    if results.iter().any(|result| {
        result.entity_kind == EntityKind::Jump
            && result.name == jump.name
            && result.status == TrustStatus::Failed
    }) {
        return Err((
            FailureClass::JumpFailure,
            format!(
                "jump host {} failed; target host key was not contacted",
                jump.name
            ),
        ));
    }
    let snapshot = store
        .snapshot()
        .map_err(|error| (error.class(), error.to_string()))?;
    match snapshot
        .inspect(&jump.alias, false)
        .map_err(|error| (error.class(), error.to_string()))?
    {
        AliasState::Pinned(expected_key) => Ok(Some(JumpFetchRequest {
            name: jump.name.clone(),
            address: jump.address.clone(),
            port: jump.port,
            auth_profile: jump.auth_profile.clone(),
            expected_key,
        })),
        AliasState::Unknown | AliasState::Replaceable { .. } => Err((
            FailureClass::JumpFailure,
            format!(
                "jump host {} is not pinned; target host key was not contacted",
                jump.name
            ),
        )),
    }
}

fn same_key(left: &HostKey, right: &HostKey) -> bool {
    left.algorithm == right.algorithm && left.base64 == right.base64
}

fn pinned_first(prior: &[HostKey]) -> Vec<String> {
    let mut algorithms = Vec::with_capacity(VERIFIABLE_ALGORITHMS.len());
    for key in prior {
        if VERIFIABLE_ALGORITHMS.contains(&key.algorithm.as_str())
            && !algorithms.contains(&key.algorithm)
        {
            algorithms.push(key.algorithm.clone());
        }
    }
    for algorithm in VERIFIABLE_ALGORITHMS {
        if !algorithms.iter().any(|candidate| candidate == algorithm) {
            algorithms.push((*algorithm).to_string());
        }
    }
    algorithms
}

fn success_result(
    entity: &TrustEntity,
    prior_state: TrustState,
    key: &HostKey,
    action: TrustAction,
) -> TrustResult {
    TrustResult {
        entity_kind: entity.kind,
        name: entity.name.clone(),
        address: entity.address.clone(),
        port: entity.port,
        selected_machines: entity.selected_machines.clone(),
        prior_state: Some(prior_state),
        algorithm: Some(key.algorithm.clone()),
        fingerprint: Some(key.fingerprint.clone()),
        action: Some(action),
        status: TrustStatus::Success,
        failure_class: None,
        diagnostic: None,
    }
}

fn failed_result(
    entity: &TrustEntity,
    prior_state: Option<TrustState>,
    class: FailureClass,
    diagnostic: &str,
) -> TrustResult {
    TrustResult {
        entity_kind: entity.kind,
        name: entity.name.clone(),
        address: entity.address.clone(),
        port: entity.port,
        selected_machines: entity.selected_machines.clone(),
        prior_state,
        algorithm: None,
        fingerprint: None,
        action: None,
        status: TrustStatus::Failed,
        failure_class: Some(class),
        diagnostic: Some(diagnostic.to_string()),
    }
}

fn cancellation_result(entity: &TrustEntity) -> TrustResult {
    failed_result(entity, None, FailureClass::Cancellation, "cancelled")
}

fn push_unprocessed_cancellations(
    results: &mut Vec<TrustResult>,
    entities: &[TrustEntity],
    decider: &mut dyn TrustDecider,
) {
    for entity in entities {
        decider.observe_failure(entity.kind, &entity.name, "cancelled");
        results.push(cancellation_result(entity));
    }
}

fn finished_outcome(
    plan: &TrustPlan,
    clock: &mut dyn Clock,
    started: u128,
    results: Vec<TrustResult>,
) -> TrustOutcome {
    let finished = clock.now_millis();
    TrustOutcome {
        environment: plan.environment.clone(),
        selected_machines: plan.selected_machines.clone(),
        duration_millis: finished.saturating_sub(started),
        results,
    }
}

fn store_failure(
    entity: &TrustEntity,
    prior_state: Option<TrustState>,
    error: &StoreError,
) -> TrustResult {
    failed_result(entity, prior_state, error.class(), &error.to_string())
}
