// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use broil_config::LoadedProject;
use broil_core::remote::{PrivilegeProfile, SecretProvider};
use russh::ChannelMsg;
use russh::client;
use russh::keys::{Algorithm, HashAlg, PublicKeyBase64};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::alias::{env_jump_alias, root_jump_alias, target_alias};
use crate::auth::{self, AuthContext};
pub use crate::jobs::RequestedJobs;
use crate::known_hosts::{AliasState, KnownHostsStore, StoreError};

use crate::jobs::resolve_jobs;
use crate::scheduler::{self, CancellationToken};
use crate::{
    EffectiveInventory, EffectiveMachine, EffectiveTimeouts, FailureClass, HostKey, JumpScope,
};

pub const INITIAL_SCOPE: &str = "initial";
const SUDO_CANCEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub sudo: bool,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeCategory {
    Operational,
    Security,
}

impl ProbeCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operational => "operational",
            Self::Security => "security",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeName {
    Dns,
    Tcp,
    JumpTrust,
    Jump,
    TargetTrust,
    CanonicalAuth,
    RemoteExec,
    Sftp,
    Sudo,
    PublicKeyOnlyPolicy,
}

impl ProbeName {
    pub const ORDER: [Self; 10] = [
        Self::Dns,
        Self::Tcp,
        Self::JumpTrust,
        Self::Jump,
        Self::TargetTrust,
        Self::CanonicalAuth,
        Self::RemoteExec,
        Self::Sftp,
        Self::Sudo,
        Self::PublicKeyOnlyPolicy,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::JumpTrust => "jump_trust",
            Self::Jump => "jump",
            Self::TargetTrust => "target_trust",
            Self::CanonicalAuth => "canonical_auth",
            Self::RemoteExec => "remote_exec",
            Self::Sftp => "sftp",
            Self::Sudo => "sudo",
            Self::PublicKeyOnlyPolicy => "public_key_only_policy",
        }
    }

    pub fn category(self) -> ProbeCategory {
        match self {
            Self::Dns | Self::Tcp | Self::Jump | Self::RemoteExec | Self::Sftp | Self::Sudo => {
                ProbeCategory::Operational
            }
            Self::JumpTrust
            | Self::TargetTrust
            | Self::CanonicalAuth
            | Self::PublicKeyOnlyPolicy => ProbeCategory::Security,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Pass,
    Negative,
    NotApplicable,
    Error,
    NotRun,
}

impl ProbeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Negative => "negative",
            Self::NotApplicable => "not_applicable",
            Self::Error => "error",
            Self::NotRun => "not_run",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    NotReady,
    Indeterminate,
}

impl Readiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NotReady => "not_ready",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    Success,
    Failed,
}

impl TargetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignal {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRecord {
    pub category: ProbeCategory,
    pub probe: ProbeName,
    pub outcome: ProbeOutcome,
    pub failure_class: Option<FailureClass>,
    pub diagnostic: Option<String>,
    pub dispatched: bool,
    pub remote_status: Option<i32>,
    pub remote_signal: Option<RemoteSignal>,
    pub possible_staging_residue: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckTargetResult {
    pub machine: String,
    pub scope: String,
    pub status: TargetStatus,
    pub failure_class: Option<FailureClass>,
    pub dispatched: bool,
    pub remote_status: Option<i32>,
    pub remote_signal: Option<RemoteSignal>,
    pub possible_staging_residue: bool,
    pub operational_readiness: Readiness,
    pub security_readiness: Readiness,
    pub overall_readiness: Readiness,
    pub probes: Vec<ProbeRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub scope: String,
    pub duration_millis: u128,
    pub results: Vec<CheckTargetResult>,
}

impl CheckOutcome {
    pub fn status(&self) -> i32 {
        if self
            .results
            .iter()
            .all(|result| result.overall_readiness == Readiness::Ready)
        {
            0
        } else {
            1
        }
    }
}

#[derive(Debug)]
pub struct CheckRunError {
    class: FailureClass,
    diagnostic: String,
}

impl CheckRunError {
    pub fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn class(&self) -> FailureClass {
        self.class
    }
}

impl std::fmt::Display for CheckRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for CheckRunError {}

#[derive(Debug, Clone)]
pub struct CheckTarget {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub target_alias: String,
    pub canonical_profile: String,
    pub canonical_user: String,
    pub privilege_profile: Option<String>,
    pub timeouts: EffectiveTimeouts,
    pub route: CheckRoute,
}

#[derive(Debug, Clone)]
pub enum CheckRoute {
    Direct,
    ViaJump(CheckJump),
}

#[derive(Debug, Clone)]
pub struct CheckJump {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub alias: String,
    pub auth_profile: String,
}

#[derive(Debug, Clone)]
pub struct TargetCheckOptions {
    pub sudo: bool,
    pub cancel: CancellationToken,
}

pub trait CheckBackend: Clone + Send + Sync + 'static {
    fn check_target(
        &self,
        target: CheckTarget,
        options: TargetCheckOptions,
    ) -> Pin<Box<dyn Future<Output = CheckTargetResult> + Send>>;
}

#[derive(Clone)]
pub struct RusshCheckBackend {
    store: KnownHostsStore,
    auth_context: AuthContext,
    privilege_context: PrivilegeContext,
}

impl RusshCheckBackend {
    pub fn new(
        store: KnownHostsStore,
        auth_context: AuthContext,
        privilege_context: PrivilegeContext,
    ) -> Self {
        Self {
            store,
            auth_context,
            privilege_context,
        }
    }
}

impl CheckBackend for RusshCheckBackend {
    fn check_target(
        &self,
        target: CheckTarget,
        options: TargetCheckOptions,
    ) -> Pin<Box<dyn Future<Output = CheckTargetResult> + Send>> {
        let backend = self.clone();
        Box::pin(async move { backend.check_real_target(target, options).await })
    }
}

#[derive(Clone)]
pub struct PrivilegeContext {
    secret_context: crate::secret::SecretContext,
    privilege_profiles: BTreeMap<String, PrivilegeProfile>,
}

impl PrivilegeContext {
    pub fn with_store_context(mut self, store: crate::secret::StoreContext) -> Self {
        if self.privilege_profiles.values().any(|profile| {
            profile
                .password
                .as_ref()
                .is_some_and(|secret| self.secret_context.is_store_provider(&secret.secret))
        }) {
            self.secret_context = self.secret_context.with_store_context(store);
        }
        self
    }

    pub fn with_store_context_for_profiles(
        mut self,
        store: crate::secret::StoreContext,
        profiles: &[&str],
    ) -> Self {
        if profiles
            .iter()
            .filter_map(|name| self.privilege_profiles.get(*name))
            .any(|profile| {
                profile
                    .password
                    .as_ref()
                    .is_some_and(|secret| self.secret_context.is_store_provider(&secret.secret))
            })
        {
            self.secret_context = self.secret_context.with_store_context(store);
        }
        self
    }

    pub fn from_project(
        project: &LoadedProject,
        environment: &str,
        env_snapshot: &[(std::ffi::OsString, std::ffi::OsString)],
    ) -> Self {
        let env_remote = &project.config.environments[environment].remote.definitions;
        let mut secret_providers = project.config.remote.definitions.secret_providers.clone();
        secret_providers.extend(env_remote.secret_providers.clone());
        let mut privilege_profiles = project.config.remote.definitions.privilege_profiles.clone();
        privilege_profiles.extend(env_remote.privilege_profiles.clone());
        Self::new(
            project.broil_root.clone(),
            env_snapshot.to_vec(),
            secret_providers,
            privilege_profiles,
        )
    }

    pub fn new(
        root: PathBuf,
        env_snapshot: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        secret_providers: BTreeMap<String, SecretProvider>,
        privilege_profiles: BTreeMap<String, PrivilegeProfile>,
    ) -> Self {
        Self {
            secret_context: crate::secret::SecretContext::new(root, env_snapshot, secret_providers),
            privilege_profiles,
        }
    }

    fn profile(&self, name: &str) -> Result<&PrivilegeProfile, ProbeFailure> {
        self.privilege_profiles.get(name).ok_or_else(|| {
            ProbeFailure::new(
                FailureClass::Configuration,
                format!("unknown privilege profile {name}"),
            )
        })
    }

    async fn sudo_password_input(
        &self,
        profile: &PrivilegeProfile,
        cancel: &CancellationToken,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ProbeFailure> {
        let Some(secret) = &profile.password else {
            return Ok(None);
        };
        let password = self
            .secret_context
            .resolve_owned_cancellable(&secret.secret, cancel)
            .await
            .map_err(|error| {
                ProbeFailure::new(
                    error.class(),
                    format!("sudo password secret {} unavailable", secret.secret),
                )
            })?;
        let input = crate::sudo::sudo_password_input(&password)
            .map_err(|error| ProbeFailure::new(error.class(), error.to_string()))?;
        Ok(Some(input))
    }
}

pub fn run<B: CheckBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &CheckOptions,
    backend: B,
) -> Result<CheckOutcome, CheckRunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            CheckRunError::new(
                FailureClass::CapabilityUnsupported,
                format!("cannot initialize remote check runtime: {error}"),
            )
        })?;
    runtime.block_on(run_async(root, inventory, selected, options, backend))
}

async fn run_async<B: CheckBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &CheckOptions,
    backend: B,
) -> Result<CheckOutcome, CheckRunError> {
    let started = now_millis();
    let targets = plan_targets(root, inventory, selected)?;
    let selected_machines = targets
        .iter()
        .map(|target| target.name.clone())
        .collect::<Vec<_>>();
    let jobs = resolve_jobs(
        options.jobs,
        &inventory.operations_parallelism,
        targets.len(),
    );
    let cancel = CancellationToken::default();
    let interrupt_task = spawn_interrupt_watcher(cancel.clone());
    let target_options = TargetCheckOptions {
        sudo: options.sudo,
        cancel: cancel.clone(),
    };
    let result_options = target_options.clone();
    let results = scheduler::run_bounded(
        targets.into_iter().map(Some).collect(),
        jobs,
        options.fail_fast,
        cancel,
        move |target, token| {
            let backend = backend.clone();
            let mut options = target_options.clone();
            options.cancel = token;
            async move { backend.check_target(target, options).await }
        },
        |result| result.overall_readiness != Readiness::Ready,
        move |target, class| not_started_result(target, class, result_options.sudo),
    )
    .await;
    if let Some(task) = interrupt_task {
        task.abort();
    }

    Ok(CheckOutcome {
        environment: inventory.environment.clone(),
        selected_machines,
        scope: INITIAL_SCOPE.to_string(),
        duration_millis: now_millis().saturating_sub(started),
        results,
    })
}

#[cfg(unix)]
fn spawn_interrupt_watcher(cancel: CancellationToken) -> Option<tokio::task::JoinHandle<()>> {
    let mut interrupt =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok()?;
    Some(tokio::spawn(async move {
        let mut state = InterruptState::default();
        while interrupt.recv().await.is_some() {
            match handle_interrupt(&mut state, &cancel) {
                InterruptAction::Cancel => {}
                InterruptAction::Exit(code) => {
                    crate::secret::restore_global_input_terminal();
                    std::process::exit(code);
                }
            }
        }
    }))
}

#[cfg(not(unix))]
fn spawn_interrupt_watcher(_cancel: CancellationToken) -> Option<tokio::task::JoinHandle<()>> {
    None
}

#[derive(Default)]
struct InterruptState {
    seen: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterruptAction {
    Cancel,
    Exit(i32),
}

fn handle_interrupt(state: &mut InterruptState, cancel: &CancellationToken) -> InterruptAction {
    if state.seen {
        InterruptAction::Exit(130)
    } else {
        state.seen = true;
        cancel.cancel();
        InterruptAction::Cancel
    }
}

fn plan_targets(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
) -> Result<Vec<CheckTarget>, CheckRunError> {
    selected
        .iter()
        .map(|machine| {
            let route = if machine.route == "direct" {
                CheckRoute::Direct
            } else {
                let jump = inventory
                    .jumps
                    .iter()
                    .find(|jump| jump.name == machine.route)
                    .ok_or_else(|| {
                        CheckRunError::new(
                            FailureClass::Configuration,
                            format!("unknown jump host {}", machine.route),
                        )
                    })?;
                let alias = match jump.scope {
                    JumpScope::Root => root_jump_alias(root, &jump.name),
                    JumpScope::Environment => {
                        env_jump_alias(root, &inventory.environment, &jump.name)
                    }
                };
                CheckRoute::ViaJump(CheckJump {
                    name: jump.name.clone(),
                    address: jump.address.clone(),
                    port: jump.port,
                    alias,
                    auth_profile: jump.auth_profile.clone(),
                })
            };
            Ok(CheckTarget {
                name: machine.name.clone(),
                address: machine.address.clone(),
                port: machine.port,
                target_alias: target_alias(root, &inventory.environment, &machine.name),
                canonical_profile: machine.canonical_profile.clone(),
                canonical_user: machine.canonical_user.clone(),
                privilege_profile: machine.privilege_profile.clone(),
                timeouts: machine.timeouts.clone(),
                route,
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
struct ProbeFailure {
    class: FailureClass,
    diagnostic: String,
    dispatched: bool,
    remote_status: Option<i32>,
    remote_signal: Option<RemoteSignal>,
    possible_staging_residue: bool,
}

impl ProbeFailure {
    fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
            dispatched: false,
            remote_status: None,
            remote_signal: None,
            possible_staging_residue: false,
        }
    }

    fn dispatched(mut self) -> Self {
        self.dispatched = true;
        self
    }

    fn remote_result(mut self, status: Option<i32>, signal: Option<RemoteSignal>) -> Self {
        self.remote_status = status;
        self.remote_signal = signal;
        self
    }

    fn residue(mut self) -> Self {
        self.possible_staging_residue = true;
        self
    }
}

#[derive(Debug, Clone)]
enum ProbeResult {
    Pass {
        dispatched: bool,
        possible_staging_residue: bool,
    },
    Negative {
        remote_status: Option<i32>,
        remote_signal: Option<RemoteSignal>,
        dispatched: bool,
        possible_staging_residue: bool,
    },
    Error(ProbeFailure),
}

impl ProbeResult {
    fn pass() -> Self {
        Self::Pass {
            dispatched: false,
            possible_staging_residue: false,
        }
    }

    fn dispatched_pass() -> Self {
        Self::Pass {
            dispatched: true,
            possible_staging_residue: false,
        }
    }

    fn dispatched_pass_with_residue(possible_staging_residue: bool) -> Self {
        Self::Pass {
            dispatched: true,
            possible_staging_residue,
        }
    }
}

impl RusshCheckBackend {
    async fn check_real_target(
        &self,
        target: CheckTarget,
        options: TargetCheckOptions,
    ) -> CheckTargetResult {
        let mut builder = TargetBuilder::new(target.clone(), options.sudo);

        let (endpoint, endpoint_port) = route_endpoint(&target);
        let connect_timeout = connect_timeout(&target);
        let command_timeout = command_timeout(&target);
        let connect_deadline = tokio::time::Instant::now() + connect_timeout;

        let addresses = match cancellable_probe(
            &options.cancel,
            self.resolve_dns(endpoint, endpoint_port, connect_deadline),
        )
        .await
        {
            Ok(addresses) => {
                if !builder.record(ProbeName::Dns, ProbeResult::pass()) {
                    return builder.finish(None);
                }
                addresses
            }
            Err(error) => {
                builder.record(ProbeName::Dns, ProbeResult::Error(error));
                return builder.finish(None);
            }
        };

        let stream = match cancellable_probe(&options.cancel, async {
            connect_addresses(&addresses, endpoint, endpoint_port, connect_deadline).await
        })
        .await
        {
            Ok(stream) => stream,
            Err(error) => {
                builder.record(ProbeName::Tcp, ProbeResult::Error(error));
                return builder.finish(None);
            }
        };
        if !builder.record(ProbeName::Tcp, ProbeResult::pass()) {
            return builder.finish(None);
        }

        let mut target_session = match &target.route {
            CheckRoute::Direct => {
                builder.record(ProbeName::JumpTrust, ProbeResult::pass());
                builder.record(ProbeName::Jump, ProbeResult::pass());
                match cancellable_probe(
                    &options.cancel,
                    self.connect_direct_target(&target, stream, connect_deadline),
                )
                .await
                {
                    Ok(session) => {
                        builder.record(ProbeName::TargetTrust, ProbeResult::pass());
                        session
                    }
                    Err(error) => {
                        builder.record(ProbeName::TargetTrust, ProbeResult::Error(error));
                        return builder.finish(None);
                    }
                }
            }
            CheckRoute::ViaJump(jump) => {
                match cancellable_probe(
                    &options.cancel,
                    self.connect_jump_for_target(jump, stream, connect_deadline),
                )
                .await
                {
                    Ok(jump_session) => {
                        builder.record(ProbeName::JumpTrust, ProbeResult::pass());
                        let target_connection = if options.cancel.is_cancelled() {
                            Err((ProbeName::Jump, cancellation_failure()))
                        } else {
                            tokio::select! {
                            biased;
                            _ = options.cancel.cancelled() => Err((
                                ProbeName::Jump,
                                cancellation_failure().dispatched(),
                            )),
                            result = self.authenticate_jump_and_open_target(
                                jump_session,
                                jump,
                                &target,
                                connect_deadline,
                                &options.cancel,
                            ) => result,
                            }
                        };
                        match target_connection {
                            Ok(session) => {
                                builder.record(ProbeName::Jump, ProbeResult::dispatched_pass());
                                builder.record(ProbeName::TargetTrust, ProbeResult::pass());
                                session
                            }
                            Err((probe, error)) => {
                                builder.record(probe, ProbeResult::Error(error));
                                return builder.finish(None);
                            }
                        }
                    }
                    Err(error) => {
                        builder.record(ProbeName::JumpTrust, ProbeResult::Error(error));
                        return builder.finish(None);
                    }
                }
            }
        };

        if options.cancel.is_cancelled() {
            builder.record(
                ProbeName::CanonicalAuth,
                ProbeResult::Error(ProbeFailure::new(FailureClass::Cancellation, "cancelled")),
            );
            return builder.finish(None);
        }

        let canonical_auth = tokio::select! {
            biased;
            _ = options.cancel.cancelled() => Err(cancellation_failure().dispatched()),
            result = timeout_probe(
                command_timeout,
                auth::authenticate_profile_cancellable(
                    &mut target_session,
                    &self.auth_context,
                    &target.canonical_profile,
                    &options.cancel,
                ),
                FailureClass::IndeterminateAfterDispatch,
                "canonical authentication timed out after dispatch",
            ) => result,
        };
        match canonical_auth {
            Ok(Ok(())) => {
                builder.record(ProbeName::CanonicalAuth, ProbeResult::dispatched_pass());
            }
            Ok(Err(error)) => {
                let dispatched = !matches!(
                    error.class(),
                    FailureClass::SecretUnavailable
                        | FailureClass::AuthenticationLocallyUnavailable
                );
                let failure = if dispatched {
                    ProbeFailure::new(error.class(), error.to_string()).dispatched()
                } else {
                    ProbeFailure::new(error.class(), error.to_string())
                };
                builder.record(ProbeName::CanonicalAuth, ProbeResult::Error(failure));
                return builder.finish(None);
            }
            Err(error) => {
                builder.record(ProbeName::CanonicalAuth, ProbeResult::Error(error));
                return builder.finish(None);
            }
        }

        if options.cancel.is_cancelled() {
            builder.record(
                ProbeName::RemoteExec,
                ProbeResult::Error(ProbeFailure::new(FailureClass::Cancellation, "cancelled")),
            );
            return builder.finish(None);
        }

        let remote_exec = tokio::select! {
            biased;
            _ = options.cancel.cancelled() => Err(cancellation_failure().dispatched()),
            result = run_remote_command(
                &mut target_session,
                "true",
                None,
                command_timeout,
                false,
                false,
            ) => result,
        };
        match remote_exec {
            Ok(command) if command.status == Some(0) => {
                builder.record(ProbeName::RemoteExec, ProbeResult::dispatched_pass());
            }
            Ok(command) if command.status.is_some() => {
                builder.record(
                    ProbeName::RemoteExec,
                    ProbeResult::Negative {
                        remote_status: command.status,
                        remote_signal: command.signal,
                        dispatched: true,
                        possible_staging_residue: false,
                    },
                );
            }
            Ok(command) => {
                builder.record(
                    ProbeName::RemoteExec,
                    ProbeResult::Error(command.into_missing_status_failure()),
                );
                return builder.finish(None);
            }
            Err(error) => {
                builder.record(ProbeName::RemoteExec, ProbeResult::Error(error));
                return builder.finish(None);
            }
        }

        if options.cancel.is_cancelled() {
            builder.record(
                ProbeName::Sftp,
                ProbeResult::Error(ProbeFailure::new(FailureClass::Cancellation, "cancelled")),
            );
            return builder.finish(None);
        }

        let sftp = tokio::select! {
            biased;
            _ = options.cancel.cancelled() => Err(cancellation_failure().dispatched()),
            result = run_sftp_probe(&mut target_session, command_timeout) => result,
        };
        match sftp {
            Ok(true) => {
                builder.record(ProbeName::Sftp, ProbeResult::dispatched_pass());
            }
            Ok(false) => {
                builder.record(
                    ProbeName::Sftp,
                    ProbeResult::Negative {
                        remote_status: None,
                        remote_signal: None,
                        dispatched: true,
                        possible_staging_residue: false,
                    },
                );
            }
            Err(error) => {
                builder.record(ProbeName::Sftp, ProbeResult::Error(error));
                return builder.finish(None);
            }
        }

        if options.sudo {
            if options.cancel.is_cancelled() {
                builder.record(
                    ProbeName::Sudo,
                    ProbeResult::Error(ProbeFailure::new(FailureClass::Cancellation, "cancelled")),
                );
                return builder.finish(None);
            }
            let sudo = self
                .run_sudo_probe(
                    &mut target_session,
                    &target,
                    command_timeout,
                    &options.cancel,
                )
                .await;
            if !builder.record(ProbeName::Sudo, sudo) {
                return builder.finish(None);
            }
        }

        builder.finish(None)
    }

    async fn resolve_dns(
        &self,
        address: &str,
        port: u16,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<std::net::SocketAddr>, ProbeFailure> {
        let addresses = tokio::time::timeout_at(deadline, tokio::net::lookup_host((address, port)))
            .await
            .map_err(|_| ProbeFailure::new(FailureClass::Dns, "DNS resolution timed out"))?
            .map_err(|error| {
                ProbeFailure::new(FailureClass::Dns, format!("DNS resolution failed: {error}"))
            })?
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            Err(ProbeFailure::new(
                FailureClass::Dns,
                "DNS resolution returned no addresses",
            ))
        } else {
            Ok(addresses)
        }
    }

    async fn connect_direct_target(
        &self,
        target: &CheckTarget,
        stream: tokio::net::TcpStream,
        deadline: tokio::time::Instant,
    ) -> Result<client::Handle<StrictHandler>, ProbeFailure> {
        let expected = self.pinned_key(&target.target_alias, FailureClass::UnknownHostKey)?;
        connect_strict(stream, expected, deadline)
            .await
            .map_err(strict_target_trust_failure)
    }

    async fn connect_jump_for_target(
        &self,
        jump: &CheckJump,
        stream: tokio::net::TcpStream,
        deadline: tokio::time::Instant,
    ) -> Result<client::Handle<StrictHandler>, ProbeFailure> {
        let expected = self.pinned_key(&jump.alias, FailureClass::UnknownHostKey)?;
        let session = connect_strict(stream, expected, deadline)
            .await
            .map_err(|error| strict_jump_trust_failure(&jump.name, error))?;
        Ok(session)
    }

    async fn authenticate_jump_and_open_target(
        &self,
        mut jump_session: client::Handle<StrictHandler>,
        jump: &CheckJump,
        target: &CheckTarget,
        deadline: tokio::time::Instant,
        cancel: &CancellationToken,
    ) -> Result<client::Handle<StrictHandler>, (ProbeName, ProbeFailure)> {
        timeout_at_probe(
            deadline,
            auth::authenticate_profile_cancellable(
                &mut jump_session,
                &self.auth_context,
                &jump.auth_profile,
                cancel,
            ),
            FailureClass::JumpFailure,
            "jump authentication timed out",
        )
        .await
        .map_err(|error| (ProbeName::Jump, error))?
        .map_err(|error| {
            let error = error.into_jump_failure(&jump.name);
            (
                ProbeName::Jump,
                ProbeFailure::new(error.class(), error.to_string()),
            )
        })?;
        let channel = tokio::time::timeout_at(
            deadline,
            jump_session.channel_open_direct_tcpip(
                target.address.clone(),
                u32::from(target.port),
                "127.0.0.1",
                0,
            ),
        )
        .await
        .map_err(|_| {
            (
                ProbeName::Jump,
                ProbeFailure::new(
                    FailureClass::JumpFailure,
                    format!(
                        "jump host {} timed out opening target channel to {}:{}",
                        jump.name, target.address, target.port
                    ),
                )
                .dispatched(),
            )
        })?
        .map_err(|error| {
            (
                ProbeName::Jump,
                ProbeFailure::new(
                    FailureClass::JumpFailure,
                    format!(
                        "jump host {} could not open target channel to {}:{}: {error}",
                        jump.name, target.address, target.port
                    ),
                )
                .dispatched(),
            )
        })?;

        let expected = self
            .pinned_key(&target.target_alias, FailureClass::UnknownHostKey)
            .map_err(|error| (ProbeName::TargetTrust, error))?;
        connect_strict(channel.into_stream(), expected, deadline)
            .await
            .map_err(|error| (ProbeName::TargetTrust, strict_target_trust_failure(error)))
    }

    fn pinned_key(
        &self,
        alias: &str,
        unknown_class: FailureClass,
    ) -> Result<HostKey, ProbeFailure> {
        match self
            .store
            .snapshot()
            .and_then(|snapshot| snapshot.inspect(alias, false))
        {
            Ok(AliasState::Pinned(key)) => Ok(key),
            Ok(AliasState::Unknown) => Err(ProbeFailure::new(
                unknown_class,
                "host key is not pinned in the Broil known-hosts store",
            )),
            Ok(AliasState::Replaceable { .. }) => Err(ProbeFailure::new(
                FailureClass::Configuration,
                "known-hosts state requires replacement before read-only verification",
            )),
            Err(error) => Err(store_probe_failure(error)),
        }
    }

    async fn run_sudo_probe(
        &self,
        session: &mut client::Handle<StrictHandler>,
        target: &CheckTarget,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> ProbeResult {
        let Some(profile_name) = target.privilege_profile.as_deref() else {
            return ProbeResult::Error(missing_sudo_privilege_failure());
        };
        let profile = match self.privilege_context.profile(profile_name) {
            Ok(profile) => profile.clone(),
            Err(error) => return ProbeResult::Error(error),
        };

        let preflight_command = shell_join(&crate::sudo::sudo_preflight_argv());
        let preflight = if cancel.is_cancelled() {
            Err(cancellation_failure())
        } else {
            tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(cancellation_failure().dispatched()),
            result = run_remote_command(
                session,
                &preflight_command,
                None,
                timeout,
                false,
                true,
            ) => result,
            }
        };
        match preflight.map(|result| classify_sudo_preflight(result, profile.password.is_some())) {
            Ok(SudoPreflightDecision::UsePasswordlessStaging) => {
                self.run_staged_sudo(session, &profile, false, timeout, cancel)
                    .await
            }
            Ok(SudoPreflightDecision::UsePasswordStaging) => {
                self.run_staged_sudo(session, &profile, true, timeout, cancel)
                    .await
            }
            Ok(SudoPreflightDecision::Finished(result)) => result,
            Err(error) => ProbeResult::Error(error),
        }
    }

    async fn run_staged_sudo(
        &self,
        session: &mut client::Handle<StrictHandler>,
        profile: &PrivilegeProfile,
        use_password: bool,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> ProbeResult {
        let nonce = match crate::path_safety::sudo_nonce() {
            Ok(nonce) => nonce,
            Err(_) => {
                return ProbeResult::Error(
                    ProbeFailure::new(FailureClass::Sudo, "sudo nonce generation failed")
                        .dispatched(),
                );
            }
        };
        if cancel.is_cancelled() {
            return ProbeResult::Error(cancellation_failure().dispatched());
        }
        let staging = match tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(cancellation_failure().dispatched()),
            result = stage_check_launcher(session, &nonce, timeout) => result,
        } {
            Ok(launcher) => launcher,
            Err(error) => return ProbeResult::Error(error.residue()),
        };
        if cancel.is_cancelled() {
            let failure = cancellation_failure().dispatched();
            return ProbeResult::Error(
                cleanup_staging_or_residue(session, &staging.launcher, timeout, failure).await,
            );
        }
        let launcher_argv = vec![staging.launcher.clone()];
        let sudo_argv = if use_password {
            match crate::sudo::password_sudo_argv(&launcher_argv, &nonce) {
                Ok(argv) => argv,
                Err(error) => {
                    let failure = ProbeFailure::new(error.class(), error.to_string()).dispatched();
                    return ProbeResult::Error(
                        cleanup_staging_or_residue(session, &staging.launcher, timeout, failure)
                            .await,
                    );
                }
            }
        } else {
            match crate::sudo::passwordless_sudo_argv(&launcher_argv, &nonce) {
                Ok(argv) => argv,
                Err(error) => {
                    let failure = ProbeFailure::new(error.class(), error.to_string()).dispatched();
                    return ProbeResult::Error(
                        cleanup_staging_or_residue(session, &staging.launcher, timeout, failure)
                            .await,
                    );
                }
            }
        };
        let password_input = if use_password {
            match self
                .privilege_context
                .sudo_password_input(profile, cancel)
                .await
            {
                Ok(input) => input,
                Err(error) => {
                    return ProbeResult::Error(
                        cleanup_staging_or_residue(
                            session,
                            &staging.launcher,
                            timeout,
                            error.dispatched(),
                        )
                        .await,
                    );
                }
            }
        } else {
            None
        };
        let command = shell_join(&sudo_argv);
        if cancel.is_cancelled() {
            let failure = cancellation_failure().dispatched();
            return ProbeResult::Error(
                cleanup_staging_or_residue(session, &staging.launcher, timeout, failure).await,
            );
        }
        let chmod = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(cancellation_failure().dispatched()),
            result = make_launcher_executable(session, &staging.launcher, timeout) => result,
        };
        if let Err(error) = chmod {
            return ProbeResult::Error(
                cleanup_staging_or_residue(session, &staging.launcher, timeout, error).await,
            );
        }
        if cancel.is_cancelled() {
            let failure = cancellation_failure().dispatched();
            return ProbeResult::Error(
                cleanup_staging_or_residue(session, &staging.launcher, timeout, failure).await,
            );
        }
        let command = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(cancellation_failure().dispatched()),
            result = run_remote_command(
                session,
                &command,
                password_input,
                timeout,
                false,
                true,
            ) => result,
        };
        let mut residue = true;
        let command = match command {
            Ok(command) => command,
            Err(error) => {
                return ProbeResult::Error(
                    cleanup_staging_or_residue(session, &staging.launcher, timeout, error).await,
                );
            }
        };
        if cleanup_staging(session, &staging.launcher, timeout)
            .await
            .is_ok()
        {
            residue = false;
        }
        classify_staged_sudo_command(command, &nonce, residue)
    }
}

fn route_endpoint(target: &CheckTarget) -> (&str, u16) {
    match &target.route {
        CheckRoute::Direct => (target.address.as_str(), target.port),
        CheckRoute::ViaJump(jump) => (jump.address.as_str(), jump.port),
    }
}

fn connect_timeout(target: &CheckTarget) -> Duration {
    Duration::from_secs(target.timeouts.connect.seconds)
}

fn command_timeout(target: &CheckTarget) -> Duration {
    Duration::from_secs(target.timeouts.command.seconds)
}

fn missing_sudo_privilege_failure() -> ProbeFailure {
    ProbeFailure::new(
        FailureClass::Configuration,
        "remote check --sudo requires an effective privilege profile",
    )
}

fn store_probe_failure(error: StoreError) -> ProbeFailure {
    ProbeFailure::new(error.class(), error.to_string())
}

#[derive(Clone)]
struct StrictHandler {
    expected: HostKey,
}

impl client::Handler for StrictHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(same_key(&host_key(server_public_key), &self.expected))
    }
}

async fn connect_addresses(
    addresses: &[std::net::SocketAddr],
    configured_address: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> Result<tokio::net::TcpStream, ProbeFailure> {
    for address in addresses {
        match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(_)) => {}
            Err(_) => break,
        }
    }
    Err(ProbeFailure::new(
        FailureClass::ConnectTimeout,
        format!("cannot connect to {configured_address}:{port} within the configured timeout"),
    ))
}

async fn connect_strict<R>(
    stream: R,
    expected: HostKey,
    deadline: tokio::time::Instant,
) -> Result<client::Handle<StrictHandler>, ProbeFailure>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = client_config(std::slice::from_ref(&expected.algorithm))?;
    tokio::time::timeout_at(
        deadline,
        client::connect_stream(
            Arc::new(config),
            stream,
            StrictHandler {
                expected: expected.clone(),
            },
        ),
    )
    .await
    .map_err(|_| ProbeFailure::new(FailureClass::Protocol, "SSH key exchange timed out"))?
    .map_err(strict_connect_failure)
}

fn strict_connect_failure(error: russh::Error) -> ProbeFailure {
    match error {
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => ProbeFailure::new(
            FailureClass::UnknownHostKey,
            "strict host-key verification failed",
        ),
        russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Key,
            ..
        } => ProbeFailure::new(
            FailureClass::ChangedHostKey,
            "host no longer offers the pinned host-key algorithm",
        ),
        error => ProbeFailure::new(
            FailureClass::Protocol,
            format!("SSH protocol failure before host-key verification: {error}"),
        ),
    }
}

fn strict_target_trust_failure(error: ProbeFailure) -> ProbeFailure {
    if error.class == FailureClass::UnknownHostKey {
        ProbeFailure::new(
            FailureClass::ChangedHostKey,
            "target host key does not match the pinned key",
        )
    } else {
        error
    }
}

fn strict_jump_trust_failure(jump_name: &str, error: ProbeFailure) -> ProbeFailure {
    if error.class == FailureClass::UnknownHostKey {
        ProbeFailure::new(
            FailureClass::ChangedHostKey,
            format!("jump host {jump_name} key does not match the pinned key"),
        )
    } else {
        error
    }
}

fn client_config(algorithms: &[String]) -> Result<client::Config, ProbeFailure> {
    let algorithms = algorithms
        .iter()
        .map(|name| {
            Algorithm::from_str(name).map_err(|_| {
                ProbeFailure::new(
                    FailureClass::Configuration,
                    format!("unsupported configured host-key algorithm {name}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut config = client::Config::default();
    config.preferred.key = Cow::Owned(algorithms);
    config.nodelay = true;
    Ok(config)
}

fn same_key(left: &HostKey, right: &HostKey) -> bool {
    left.algorithm == right.algorithm && left.base64 == right.base64
}

fn host_key(server_public_key: &russh::keys::ssh_key::PublicKey) -> HostKey {
    HostKey {
        algorithm: server_public_key.algorithm().to_string(),
        base64: server_public_key.public_key_base64(),
        fingerprint: server_public_key.fingerprint(HashAlg::Sha256).to_string(),
    }
}

async fn timeout_probe<T>(
    timeout: Duration,
    future: impl Future<Output = T>,
    timeout_class: FailureClass,
    diagnostic: &'static str,
) -> Result<T, ProbeFailure> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| ProbeFailure::new(timeout_class, diagnostic).dispatched())
}

async fn timeout_at_probe<T>(
    deadline: tokio::time::Instant,
    future: impl Future<Output = T>,
    timeout_class: FailureClass,
    diagnostic: &'static str,
) -> Result<T, ProbeFailure> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| ProbeFailure::new(timeout_class, diagnostic).dispatched())
}

async fn cancellable_probe<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, ProbeFailure>>,
) -> Result<T, ProbeFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancellation_failure()),
        result = future => result,
    }
}

fn cancellation_failure() -> ProbeFailure {
    ProbeFailure::new(FailureClass::Cancellation, "cancelled")
}

#[derive(Debug)]
struct RemoteCommand {
    status: Option<i32>,
    signal: Option<RemoteSignal>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl RemoteCommand {
    fn into_missing_status_failure(self) -> ProbeFailure {
        ProbeFailure {
            class: FailureClass::IndeterminateAfterDispatch,
            diagnostic: "remote command ended without a numeric status".to_string(),
            dispatched: true,
            remote_status: self.status,
            remote_signal: self.signal,
            possible_staging_residue: false,
        }
    }
}

struct RemoteCommandInput {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
}

impl RemoteCommandInput {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes, position: 0 }
    }
}

impl AsyncRead for RemoteCommandInput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let available = self.bytes.len().saturating_sub(self.position);
        if available == 0 || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let copied = available.min(buffer.remaining());
        let start = self.position;
        let end = start + copied;
        buffer.put_slice(&self.bytes[start..end]);
        self.position = end;
        Poll::Ready(Ok(()))
    }
}

async fn run_remote_command(
    session: &mut client::Handle<StrictHandler>,
    command: &str,
    stdin: Option<Zeroizing<Vec<u8>>>,
    timeout: Duration,
    capture_stdout: bool,
    capture_stderr: bool,
) -> Result<RemoteCommand, ProbeFailure> {
    let command = command.as_bytes().to_vec();
    tokio::time::timeout(timeout, async move {
        let mut channel = session.channel_open_session().await.map_err(|error| {
            ProbeFailure::new(
                FailureClass::IndeterminateAfterDispatch,
                format!("cannot open SSH session channel: {error}"),
            )
            .dispatched()
        })?;
        channel.exec(true, command).await.map_err(|error| {
            ProbeFailure::new(
                FailureClass::IndeterminateAfterDispatch,
                format!("cannot dispatch SSH exec request: {error}"),
            )
            .dispatched()
        })?;
        if let Some(stdin) = stdin {
            channel
                .data(RemoteCommandInput::new(stdin))
                .await
                .map_err(|error| {
                    ProbeFailure::new(
                        FailureClass::IndeterminateAfterDispatch,
                        format!("cannot write SSH channel input: {error}"),
                    )
                    .dispatched()
                })?;
        }
        channel.eof().await.map_err(|error| {
            ProbeFailure::new(
                FailureClass::IndeterminateAfterDispatch,
                format!("cannot send SSH channel EOF: {error}"),
            )
            .dispatched()
        })?;
        let mut status = None;
        let mut signal = None;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } if capture_stdout => append_bounded(&mut stdout, &data),
                ChannelMsg::ExtendedData { data, ext } if capture_stderr && ext == 1 => {
                    append_bounded(&mut stderr, &data)
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    status = Some(i32::try_from(exit_status).unwrap_or(i32::MAX));
                }
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    signal = Some(RemoteSignal {
                        name: format!("{signal_name:?}"),
                    });
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(RemoteCommand {
            status,
            signal,
            stdout,
            stderr,
        })
    })
    .await
    .map_err(|_| {
        ProbeFailure::new(
            FailureClass::IndeterminateAfterDispatch,
            "remote command timed out after dispatch",
        )
        .dispatched()
    })?
}

fn append_bounded(output: &mut Vec<u8>, data: &[u8]) {
    let available = 8192usize.saturating_sub(output.len());
    output.extend_from_slice(&data[..data.len().min(available)]);
}

fn classify_sftp_subsystem_reply(
    message: Option<ChannelMsg>,
) -> Result<Option<bool>, ProbeFailure> {
    match message {
        Some(ChannelMsg::Success) => Ok(Some(true)),
        Some(ChannelMsg::Failure) => Ok(Some(false)),
        Some(ChannelMsg::WindowAdjusted { .. }) => Ok(None),
        Some(ChannelMsg::Close) | None => Err(ProbeFailure::new(
            FailureClass::Sftp,
            "SFTP subsystem request closed before success",
        )
        .dispatched()),
        Some(message) => Err(ProbeFailure::new(
            FailureClass::Sftp,
            format!(
                "unexpected SFTP subsystem reply before success: {}",
                sftp_channel_message_name(&message)
            ),
        )
        .dispatched()),
    }
}

fn sftp_channel_message_name(message: &ChannelMsg) -> &'static str {
    match message {
        ChannelMsg::Open { .. } => "open",
        ChannelMsg::Data { .. } => "data",
        ChannelMsg::ExtendedData { .. } => "extended_data",
        ChannelMsg::Eof => "eof",
        ChannelMsg::Close => "close",
        ChannelMsg::RequestPty { .. } => "request_pty",
        ChannelMsg::RequestShell { .. } => "request_shell",
        ChannelMsg::Exec { .. } => "exec",
        ChannelMsg::Signal { .. } => "signal",
        ChannelMsg::RequestSubsystem { .. } => "request_subsystem",
        ChannelMsg::RequestX11 { .. } => "request_x11",
        ChannelMsg::SetEnv { .. } => "set_env",
        ChannelMsg::WindowChange { .. } => "window_change",
        ChannelMsg::AgentForward { .. } => "agent_forward",
        ChannelMsg::XonXoff { .. } => "xon_xoff",
        ChannelMsg::ExitStatus { .. } => "exit_status",
        ChannelMsg::ExitSignal { .. } => "exit_signal",
        ChannelMsg::WindowAdjusted { .. } => "window_adjusted",
        ChannelMsg::Success => "success",
        ChannelMsg::Failure => "failure",
        ChannelMsg::OpenFailure(_) => "open_failure",
        _ => "unknown",
    }
}

async fn run_sftp_probe(
    session: &mut client::Handle<StrictHandler>,
    timeout: Duration,
) -> Result<bool, ProbeFailure> {
    tokio::time::timeout(timeout, async {
        let mut channel = session.channel_open_session().await.map_err(|error| {
            ProbeFailure::new(
                FailureClass::IndeterminateAfterDispatch,
                format!("cannot open SSH session channel for SFTP: {error}"),
            )
            .dispatched()
        })?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|error| {
                ProbeFailure::new(
                    FailureClass::Sftp,
                    format!("SFTP subsystem request failed: {error}"),
                )
                .dispatched()
            })?;
        loop {
            match classify_sftp_subsystem_reply(channel.wait().await)? {
                Some(true) => break,
                Some(false) => return Ok(false),
                None => {}
            }
        }
        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|error| {
                ProbeFailure::new(
                    FailureClass::Sftp,
                    format!("SFTP initialization failed: {error}"),
                )
                .dispatched()
            })?;
        sftp.canonicalize(".").await.map_err(|error| {
            ProbeFailure::new(
                FailureClass::Sftp,
                format!("SFTP canonicalize failed: {error}"),
            )
            .dispatched()
        })?;
        Ok(true)
    })
    .await
    .map_err(|_| {
        ProbeFailure::new(
            FailureClass::IndeterminateAfterDispatch,
            "SFTP probe timed out after dispatch",
        )
        .dispatched()
    })?
}

struct StagedLauncher {
    launcher: String,
}

async fn stage_check_launcher(
    session: &mut client::Handle<StrictHandler>,
    nonce: &str,
    timeout: Duration,
) -> Result<StagedLauncher, ProbeFailure> {
    let script = format!(
        "set -efu\n\
         uid=$(id -u)\n\
         broil_private_dir() {{\n\
         path=$1\n\
         if [ -e \"$path\" ]; then\n\
         [ ! -L \"$path\" ] || exit 1\n\
         [ -d \"$path\" ] || exit 1\n\
         else\n\
         mkdir \"$path\" || exit 1\n\
         fi\n\
         [ ! -L \"$path\" ] || exit 1\n\
         [ \"$(stat -c '%u' \"$path\")\" = \"$uid\" ] || exit 1\n\
         chmod 00700 \"$path\" || exit 1\n\
         [ \"$(stat -c '%a' \"$path\")\" = 700 ] || exit 1\n\
         }}\n\
         broil_private_file() {{\n\
         path=$1\n\
         [ ! -L \"$path\" ] || exit 1\n\
         [ -f \"$path\" ] || exit 1\n\
         [ \"$(stat -c '%u' \"$path\")\" = \"$uid\" ] || exit 1\n\
         chmod 00600 \"$path\" || exit 1\n\
         [ \"$(stat -c '%a' \"$path\")\" = 600 ] || exit 1\n\
         }}\n\
         umask 077\n\
         broil_private_dir \"${{HOME:?}}/.broil\"\n\
         broil_private_dir \"${{HOME:?}}/.broil/tmp\"\n\
         base=\"${{HOME:?}}/.broil/tmp/exec\"\n\
         broil_private_dir \"$base\"\n\
         dir=$(mktemp -d \"$base/check.XXXXXXXXXX\")\n\
         broil_private_dir \"$dir\"\n\
         launcher=$(mktemp \"$dir/launcher.XXXXXXXXXX\")\n\
         broil_private_file \"$launcher\"\n\
         sidecar=\"$launcher.broil-sudo-frame\"\n\
         cat >\"$launcher\" <<'BROIL_LAUNCHER'\n\
         #!/bin/sh\n\
         exit 0\n\
         BROIL_LAUNCHER\n\
         broil_private_file \"$launcher\"\n\
         set -C\n\
         : >\"$sidecar\"\n\
         set +C\n\
         broil_private_file \"$sidecar\"\n\
         printf 'BROIL-SUDO:%s\\n' '{nonce}' >\"$sidecar\"\n\
         broil_private_file \"$sidecar\"\n\
         printf '%s\\n' \"$launcher\"\n"
    );
    let result = run_remote_command(
        session,
        "sh -s",
        Some(Zeroizing::new(script.into_bytes())),
        timeout,
        true,
        false,
    )
    .await?;
    if result.status != Some(0) {
        return Err(
            ProbeFailure::new(FailureClass::Sudo, "sudo check launcher staging failed")
                .dispatched(),
        );
    }
    let launcher = String::from_utf8_lossy(&result.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    if !launcher.starts_with('/') || launcher.ends_with('/') {
        return Err(ProbeFailure::new(
            FailureClass::Sudo,
            "sudo check launcher staging returned an unsafe path",
        )
        .dispatched());
    }
    Ok(StagedLauncher { launcher })
}

async fn make_launcher_executable(
    session: &mut client::Handle<StrictHandler>,
    launcher: &str,
    timeout: Duration,
) -> Result<(), ProbeFailure> {
    staging_parent(launcher)?;
    let launcher = shell_quote(launcher);
    let command = format!(
        "uid=$(id -u); path={launcher}; [ ! -L \"$path\" ] && [ -f \"$path\" ] && [ \"$(stat -c '%u' \"$path\")\" = \"$uid\" ] && chmod 00700 -- \"$path\" && [ \"$(stat -c '%a' \"$path\")\" = 700 ]"
    );
    let result = run_remote_command(session, &command, None, timeout, false, false).await?;
    if result.status == Some(0) {
        Ok(())
    } else if result.status.is_some() {
        Err(
            ProbeFailure::new(FailureClass::Sudo, "sudo launcher chmod did not complete")
                .dispatched(),
        )
    } else {
        Err(result.into_missing_status_failure())
    }
}

async fn cleanup_staging(
    session: &mut client::Handle<StrictHandler>,
    launcher: &str,
    timeout: Duration,
) -> Result<(), ProbeFailure> {
    let parent = staging_parent(launcher)?;
    let command = format!(
        "rm -f -- {} {}; rmdir -- {}",
        shell_quote(launcher),
        shell_quote(&format!("{launcher}.broil-sudo-frame")),
        shell_quote(parent)
    );
    let result = run_remote_command(session, &command, None, timeout, false, false).await?;
    if result.status == Some(0) {
        Ok(())
    } else {
        Err(
            ProbeFailure::new(FailureClass::Sudo, "sudo staging cleanup did not complete")
                .dispatched(),
        )
    }
}

async fn cleanup_staging_or_residue(
    session: &mut client::Handle<StrictHandler>,
    launcher: &str,
    timeout: Duration,
    failure: ProbeFailure,
) -> ProbeFailure {
    let timeout = cleanup_timeout_for_failure(timeout, &failure);
    if cleanup_staging(session, launcher, timeout).await.is_ok() {
        failure
    } else {
        failure.residue()
    }
}

fn cleanup_timeout_for_failure(timeout: Duration, failure: &ProbeFailure) -> Duration {
    if failure.class == FailureClass::Cancellation && timeout > SUDO_CANCEL_CLEANUP_TIMEOUT {
        SUDO_CANCEL_CLEANUP_TIMEOUT
    } else {
        timeout
    }
}

fn staging_parent(launcher: &str) -> Result<&str, ProbeFailure> {
    match launcher.rsplit_once('/') {
        Some((parent, _)) if parent.starts_with('/') && parent.contains("/.broil/tmp/exec/") => {
            Ok(parent)
        }
        _ => Err(ProbeFailure::new(
            FailureClass::Sudo,
            "sudo staging path is unsafe",
        )),
    }
}

fn frame_failure(diagnostic: &str, residue: bool) -> ProbeFailure {
    let failure = ProbeFailure::new(FailureClass::Sudo, diagnostic).dispatched();
    if residue { failure.residue() } else { failure }
}

fn residue_if(failure: ProbeFailure, residue: bool) -> ProbeFailure {
    if residue { failure.residue() } else { failure }
}

fn classify_staged_sudo_command(command: RemoteCommand, nonce: &str, residue: bool) -> ProbeResult {
    match crate::sudo::parse_sudo_control_frame(&command.stderr, nonce) {
        Ok(crate::sudo::SudoControlFrameParse::Complete(_)) => {
            if command.status == Some(0) {
                ProbeResult::dispatched_pass_with_residue(residue)
            } else if command.status.is_some() {
                ProbeResult::Negative {
                    remote_status: command.status,
                    remote_signal: command.signal,
                    dispatched: true,
                    possible_staging_residue: residue,
                }
            } else {
                ProbeResult::Error(residue_if(command.into_missing_status_failure(), residue))
            }
        }
        Ok(crate::sudo::SudoControlFrameParse::Pending) => ProbeResult::Error(frame_failure(
            "sudo control frame was not observed",
            residue,
        )),
        Err(error) => ProbeResult::Error(frame_failure(&error.to_string(), residue)),
    }
}

fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

enum SudoPreflightDecision {
    UsePasswordlessStaging,
    UsePasswordStaging,
    Finished(ProbeResult),
}

fn classify_sudo_preflight(result: RemoteCommand, has_password: bool) -> SudoPreflightDecision {
    match result.status {
        Some(0) => SudoPreflightDecision::UsePasswordlessStaging,
        Some(126 | 127) => sudo_preflight_error(
            result,
            "sudo preflight command was not executable or was not found",
        ),
        Some(_) if has_password => SudoPreflightDecision::UsePasswordStaging,
        Some(_) => sudo_preflight_error(result, "passwordless sudo preflight did not succeed"),
        None => SudoPreflightDecision::Finished(ProbeResult::Error(
            result.into_missing_status_failure(),
        )),
    }
}

fn sudo_preflight_error(result: RemoteCommand, diagnostic: &'static str) -> SudoPreflightDecision {
    SudoPreflightDecision::Finished(ProbeResult::Error(
        ProbeFailure::new(FailureClass::Sudo, diagnostic)
            .remote_result(result.status, result.signal)
            .dispatched(),
    ))
}

struct TargetBuilder {
    target: CheckTarget,
    sudo: bool,
    records: Vec<ProbeRecord>,
    stopped: bool,
    dispatched: bool,
    possible_staging_residue: bool,
}

impl TargetBuilder {
    fn new(target: CheckTarget, sudo: bool) -> Self {
        Self {
            target,
            sudo,
            records: Vec::new(),
            stopped: false,
            dispatched: false,
            possible_staging_residue: false,
        }
    }

    fn record(&mut self, probe: ProbeName, result: ProbeResult) -> bool {
        if self.stopped || !self.applicable(probe) {
            return false;
        }
        let record = match result {
            ProbeResult::Pass {
                dispatched,
                possible_staging_residue,
            } => ProbeRecord {
                category: probe.category(),
                probe,
                outcome: ProbeOutcome::Pass,
                failure_class: None,
                diagnostic: None,
                dispatched,
                remote_status: None,
                remote_signal: None,
                possible_staging_residue,
            },
            ProbeResult::Negative {
                remote_status,
                remote_signal,
                dispatched,
                possible_staging_residue,
            } => ProbeRecord {
                category: probe.category(),
                probe,
                outcome: ProbeOutcome::Negative,
                failure_class: None,
                diagnostic: None,
                dispatched,
                remote_status,
                remote_signal,
                possible_staging_residue,
            },
            ProbeResult::Error(failure) => {
                self.stopped = true;
                ProbeRecord {
                    category: probe.category(),
                    probe,
                    outcome: ProbeOutcome::Error,
                    failure_class: Some(failure.class),
                    diagnostic: Some(failure.diagnostic),
                    dispatched: failure.dispatched,
                    remote_status: failure.remote_status,
                    remote_signal: failure.remote_signal,
                    possible_staging_residue: failure.possible_staging_residue,
                }
            }
        };
        self.dispatched |= record.dispatched;
        self.possible_staging_residue |= record.possible_staging_residue;
        self.records.push(record);
        !self.stopped
    }

    fn applicable(&self, probe: ProbeName) -> bool {
        applicable(probe, &self.target.route, self.sudo)
    }

    fn finish(mut self, override_class: Option<FailureClass>) -> CheckTargetResult {
        for probe in ProbeName::ORDER {
            if self.records.iter().any(|record| record.probe == probe) {
                continue;
            }
            let outcome = if self.applicable(probe) {
                ProbeOutcome::NotRun
            } else {
                ProbeOutcome::NotApplicable
            };
            self.records.push(ProbeRecord {
                category: probe.category(),
                probe,
                outcome,
                failure_class: None,
                diagnostic: None,
                dispatched: false,
                remote_status: None,
                remote_signal: None,
                possible_staging_residue: false,
            });
        }
        self.records.sort_by_key(|record| {
            ProbeName::ORDER
                .iter()
                .position(|probe| probe == &record.probe)
        });
        let operational_readiness = category_readiness(&self.records, ProbeCategory::Operational);
        let security_readiness = category_readiness(&self.records, ProbeCategory::Security);
        let overall_readiness = overall_readiness(operational_readiness, security_readiness);
        let failure_class = override_class.or_else(|| match overall_readiness {
            Readiness::Ready => None,
            Readiness::NotReady => Some(FailureClass::ReadinessNegative),
            Readiness::Indeterminate => self
                .records
                .iter()
                .find(|record| record.outcome == ProbeOutcome::Error)
                .and_then(|record| record.failure_class)
                .or(Some(FailureClass::ReadinessNegative)),
        });
        let remote_status = self.records.iter().find_map(|record| record.remote_status);
        let remote_signal = self
            .records
            .iter()
            .find_map(|record| record.remote_signal.clone());
        CheckTargetResult {
            machine: self.target.name,
            scope: INITIAL_SCOPE.to_string(),
            status: if overall_readiness == Readiness::Ready {
                TargetStatus::Success
            } else {
                TargetStatus::Failed
            },
            failure_class,
            dispatched: self.dispatched,
            remote_status,
            remote_signal,
            possible_staging_residue: self.possible_staging_residue,
            operational_readiness,
            security_readiness,
            overall_readiness,
            probes: self.records,
        }
    }
}

fn not_started_result(target: CheckTarget, class: FailureClass, sudo: bool) -> CheckTargetResult {
    TargetBuilder::new(target, sudo).finish(Some(class))
}

fn applicable(probe: ProbeName, route: &CheckRoute, sudo: bool) -> bool {
    match probe {
        ProbeName::JumpTrust | ProbeName::Jump => matches!(route, CheckRoute::ViaJump(_)),
        ProbeName::Sudo => sudo,
        ProbeName::PublicKeyOnlyPolicy => false,
        _ => true,
    }
}

fn category_readiness(records: &[ProbeRecord], category: ProbeCategory) -> Readiness {
    let applicable = records
        .iter()
        .filter(|record| record.category == category)
        .filter(|record| record.outcome != ProbeOutcome::NotApplicable)
        .collect::<Vec<_>>();
    if applicable
        .iter()
        .any(|record| matches!(record.outcome, ProbeOutcome::Error | ProbeOutcome::NotRun))
    {
        Readiness::Indeterminate
    } else if applicable
        .iter()
        .any(|record| record.outcome == ProbeOutcome::Negative)
    {
        Readiness::NotReady
    } else {
        Readiness::Ready
    }
}

fn overall_readiness(operational: Readiness, security: Readiness) -> Readiness {
    if operational == Readiness::Indeterminate || security == Readiness::Indeterminate {
        Readiness::Indeterminate
    } else if operational == Readiness::NotReady || security == Readiness::NotReady {
        Readiness::NotReady
    } else {
        Readiness::Ready
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

