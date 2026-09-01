// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use broil_core::error::UsageError;
use broil_core::remote::DurationValue;

use crate::jobs::{RequestedJobs, resolve_jobs};
use crate::scheduler::{self, CancellationToken};
pub use crate::transfer_sftp::{SftpSetupBackend, TransferPrivilegeContext, TransferSetupHandle};
use crate::{
    EffectiveInventory, EffectiveJump, EffectiveMachine, FailureClass, JumpScope, Selectors,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

impl TransferDirection {
    pub fn command(self) -> &'static str {
        match self {
            Self::Upload => "remote copy-to",
            Self::Download => "remote copy-from",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "copy-to",
            Self::Download => "copy-from",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostsSource {
    DefaultHome,
    Override,
}

impl KnownHostsSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefaultHome => "default",
            Self::Override => "override",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedKnownHosts {
    pub source: KnownHostsSource,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRequest {
    pub direction: TransferDirection,
    pub selectors: Selectors,
    pub recursive: bool,
    pub overwrite: bool,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub privilege: Option<String>,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: ResolvedKnownHosts,
    pub caller_cwd: PathBuf,
    pub source: Vec<u8>,
    pub destination: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPlan {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub direction: TransferDirection,
    pub jobs: Vec<TransferJob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferJob {
    pub machine: String,
    pub address: String,
    pub port: u16,
    pub target_alias: String,
    pub route: String,
    pub jump: Option<TransferJump>,
    pub canonical_profile: String,
    pub canonical_user: String,
    pub direction: TransferDirection,
    pub recursive: bool,
    pub multi_machine_download: bool,
    pub overwrite: bool,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub privilege: Option<String>,
    pub known_hosts: ResolvedKnownHosts,
    pub caller_cwd: PathBuf,
    pub connect_timeout: DurationValue,
    pub capability_probe_timeout: DurationValue,
    pub transfer_timeout: DurationValue,
    pub source: Vec<u8>,
    pub destination: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferJump {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub alias: String,
    pub auth_profile: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    Success,
    Failed,
}

impl TransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTargetResult {
    pub machine: String,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub failure_class: Option<FailureClass>,
    pub diagnostic: Option<String>,
    pub dispatched: bool,
    pub remote_status: Option<i32>,
    pub possible_staging_residue: bool,
    pub diagnostic_in_report: bool,
}

impl TransferTargetResult {
    pub fn success(job: &TransferJob) -> Self {
        Self {
            machine: job.machine.clone(),
            direction: job.direction,
            status: TransferStatus::Success,
            failure_class: None,
            diagnostic: None,
            dispatched: true,
            remote_status: None,
            possible_staging_residue: false,
            diagnostic_in_report: true,
        }
    }

    pub fn failure(
        machine: impl Into<String>,
        direction: TransferDirection,
        class: FailureClass,
        diagnostic: impl Into<String>,
    ) -> Self {
        Self::failure_with_dispatch(machine, direction, class, diagnostic, false)
    }

    pub fn failure_with_dispatch(
        machine: impl Into<String>,
        direction: TransferDirection,
        class: FailureClass,
        diagnostic: impl Into<String>,
        dispatched: bool,
    ) -> Self {
        Self {
            machine: machine.into(),
            direction,
            status: TransferStatus::Failed,
            failure_class: Some(class),
            diagnostic: Some(diagnostic.into()),
            dispatched,
            remote_status: None,
            possible_staging_residue: false,
            diagnostic_in_report: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutcome {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub direction: TransferDirection,
    pub duration_millis: u128,
    pub results: Vec<TransferTargetResult>,
}

impl TransferOutcome {
    pub fn status(&self) -> i32 {
        if self
            .results
            .iter()
            .all(|result| result.status == TransferStatus::Success)
        {
            0
        } else {
            1
        }
    }
}

#[derive(Debug)]
pub enum TransferPlanError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

impl TransferPlanError {
    pub fn class(&self) -> FailureClass {
        match self {
            Self::Usage(_) => FailureClass::Selector,
            Self::Runtime { class, .. } => *class,
        }
    }
}

impl std::fmt::Display for TransferPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(formatter),
            Self::Runtime { diagnostic, .. } => formatter.write_str(diagnostic),
        }
    }
}

impl std::error::Error for TransferPlanError {}

#[derive(Debug)]
pub enum TransferRunError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

impl TransferRunError {
    pub fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self::Runtime {
            class,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn class(&self) -> FailureClass {
        match self {
            Self::Usage(_) => FailureClass::Selector,
            Self::Runtime { class, .. } => *class,
        }
    }
}

impl std::fmt::Display for TransferRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(formatter),
            Self::Runtime { diagnostic, .. } => formatter.write_str(diagnostic),
        }
    }
}

impl std::error::Error for TransferRunError {}

impl From<TransferPlanError> for TransferRunError {
    fn from(error: TransferPlanError) -> Self {
        match error {
            TransferPlanError::Usage(error) => Self::Usage(error),
            TransferPlanError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetTransferOptions {
    pub cancel: CancellationToken,
}

#[derive(Debug, Clone, Default)]
pub struct TransferRunOptions {
    pub cancel: CancellationToken,
}

pub trait TransferBackend: Clone + Send + Sync + 'static {
    fn transfer_target(
        &self,
        job: TransferJob,
        options: TargetTransferOptions,
    ) -> Pin<Box<dyn Future<Output = TransferTargetResult> + Send>>;
}

pub fn plan(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &TransferRequest,
) -> Result<TransferPlan, TransferPlanError> {
    let selected =
        crate::select(inventory, &request.selectors, false).map_err(TransferPlanError::Usage)?;
    let selected_machines = selected
        .iter()
        .map(|machine| machine.name.clone())
        .collect::<Vec<_>>();
    let multi_machine_download =
        request.direction == TransferDirection::Download && selected.len() > 1;
    let jobs = selected
        .into_iter()
        .map(|machine| plan_job(root, inventory, machine, request, multi_machine_download))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(TransferPlan {
        environment: inventory.environment.clone(),
        selected_machines,
        direction: request.direction,
        jobs,
    })
}

pub fn run<B: TransferBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &TransferRequest,
    backend: B,
) -> Result<TransferOutcome, TransferRunError> {
    run_with_options(
        root,
        inventory,
        request,
        TransferRunOptions::default(),
        backend,
    )
}

pub fn run_with_options<B: TransferBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &TransferRequest,
    options: TransferRunOptions,
    backend: B,
) -> Result<TransferOutcome, TransferRunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            TransferRunError::new(
                FailureClass::CapabilityUnsupported,
                format!("cannot initialize remote transfer runtime: {error}"),
            )
        })?;
    runtime.block_on(run_async(root, inventory, request, &options, backend))
}

async fn run_async<B: TransferBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &TransferRequest,
    options: &TransferRunOptions,
    backend: B,
) -> Result<TransferOutcome, TransferRunError> {
    let started = now_millis();
    let plan = plan(root, inventory, request).map_err(TransferRunError::from)?;
    let jobs = resolve_jobs(
        request.jobs,
        &inventory.operations_parallelism,
        plan.jobs.len(),
    );
    let cancel = options.cancel.clone();
    let interrupt_task = spawn_interrupt_watcher(cancel.clone());
    let results = scheduler::run_bounded(
        plan.jobs.into_iter().map(Some).collect(),
        jobs,
        request.fail_fast,
        cancel,
        move |job, token| {
            let backend = backend.clone();
            let options = TargetTransferOptions { cancel: token };
            async move { backend.transfer_target(job, options).await }
        },
        |result| result.status != TransferStatus::Success,
        move |job, class| {
            TransferTargetResult::failure(
                job.machine,
                job.direction,
                class,
                "remote transfer target was not scheduled",
            )
        },
    )
    .await;
    if let Some(task) = interrupt_task {
        task.abort();
    }
    Ok(finished_outcome(
        plan.environment,
        plan.selected_machines,
        plan.direction,
        started,
        results,
    ))
}

#[cfg(unix)]
fn spawn_interrupt_watcher(cancel: CancellationToken) -> Option<tokio::task::JoinHandle<()>> {
    let mut interrupt =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()).ok()?;
    Some(tokio::spawn(async move {
        let mut seen = false;
        while interrupt.recv().await.is_some() {
            if seen {
                crate::secret::restore_global_input_terminal();
                std::process::exit(130);
            }
            seen = true;
            cancel.cancel();
        }
    }))
}

#[cfg(not(unix))]
fn spawn_interrupt_watcher(_cancel: CancellationToken) -> Option<tokio::task::JoinHandle<()>> {
    None
}

fn finished_outcome(
    environment: String,
    selected_machines: Vec<String>,
    direction: TransferDirection,
    started: u128,
    results: Vec<TransferTargetResult>,
) -> TransferOutcome {
    TransferOutcome {
        environment,
        selected_machines,
        direction,
        duration_millis: now_millis().saturating_sub(started),
        results,
    }
}

fn plan_job(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &EffectiveMachine,
    request: &TransferRequest,
    multi_machine_download: bool,
) -> Result<TransferJob, TransferPlanError> {
    let jump = plan_jump(root, inventory, machine)?;
    Ok(TransferJob {
        machine: machine.name.clone(),
        address: machine.address.clone(),
        port: machine.port,
        target_alias: crate::alias::target_alias(root, &inventory.environment, &machine.name),
        route: machine.route.clone(),
        jump,
        canonical_profile: machine.canonical_profile.clone(),
        canonical_user: machine.canonical_user.clone(),
        direction: request.direction,
        recursive: request.recursive,
        multi_machine_download,
        overwrite: request.overwrite,
        mode: request.mode.clone(),
        owner: request.owner.clone(),
        privilege: request.privilege.clone(),
        known_hosts: request.known_hosts.clone(),
        caller_cwd: request.caller_cwd.clone(),
        connect_timeout: machine.timeouts.connect.clone(),
        capability_probe_timeout: machine.timeouts.command.clone(),
        transfer_timeout: machine.timeouts.transfer.clone(),
        source: request.source.clone(),
        destination: request.destination.clone(),
    })
}

fn plan_jump(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &EffectiveMachine,
) -> Result<Option<TransferJump>, TransferPlanError> {
    if machine.route == "direct" {
        return Ok(None);
    }
    let jump = inventory
        .jumps
        .iter()
        .find(|jump| jump.name == machine.route)
        .ok_or_else(|| TransferPlanError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: format!("unknown jump host {}", machine.route),
        })?;
    Ok(Some(plan_transfer_jump(root, inventory, jump)))
}

fn plan_transfer_jump(
    root: &Path,
    inventory: &EffectiveInventory,
    jump: &EffectiveJump,
) -> TransferJump {
    let alias = match jump.scope {
        JumpScope::Root => crate::alias::root_jump_alias(root, &jump.name),
        JumpScope::Environment => {
            crate::alias::env_jump_alias(root, &inventory.environment, &jump.name)
        }
    };
    TransferJump {
        name: jump.name.clone(),
        address: jump.address.clone(),
        port: jump.port,
        alias,
        auth_profile: jump.auth_profile.clone(),
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

