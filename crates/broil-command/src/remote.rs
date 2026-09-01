// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use broil_config::LoadedProject;
use broil_core::error::{RemoteError, UsageError};
use broil_remote::{
    EffectiveMachine, EffectiveNamedScriptAction, EffectivePlan, EffectivePlanAction,
    EffectivePlanStep, EffectiveTimedAction, FailureClass, PlanValidationError,
};
use serde_json::{Value, json};

pub use broil_remote::Selectors;
pub use broil_remote::check::RequestedJobs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Table,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListRequest {
    pub selectors: Selectors,
    pub plan: bool,
    pub output: OutputMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    Runtime(RemoteError),
    Usage(UsageError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListOutput {
    pub payload: Vec<u8>,
    pub invalid_plan_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRequest {
    pub selectors: Selectors,
    pub jump: Option<String>,
    pub known_hosts: Option<PathBuf>,
    pub fingerprint: Option<String>,
    pub replace: bool,
    pub report: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    pub selectors: Selectors,
    pub sudo: bool,
    pub output: OutputMode,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: Option<PathBuf>,
    pub report: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsRequest {
    pub selectors: Selectors,
    pub output: OutputMode,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: Option<PathBuf>,
    pub report: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshRequest {
    pub selectors: Selectors,
    pub bootstrap: bool,
    pub pty: PtyRequest,
    pub known_hosts: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyRequest {
    Auto,
    Force,
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecCommand {
    Argv(Vec<Vec<u8>>),
    Shell(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub selectors: Selectors,
    pub pty: PtyRequest,
    pub privilege: Option<String>,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub command: ExecCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub selectors: Selectors,
    pub pty: PtyRequest,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub script: Vec<u8>,
    pub args: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyToRequest {
    pub selectors: Selectors,
    pub recursive: bool,
    pub overwrite: bool,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub privilege: Option<String>,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub source: PathBuf,
    pub destination: OsString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyFromRequest {
    pub selectors: Selectors,
    pub recursive: bool,
    pub overwrite: bool,
    pub mode: Option<String>,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: Option<PathBuf>,
    pub report: Option<PathBuf>,
    pub source: OsString,
    pub destination: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionRequest {
    pub selectors: Selectors,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: Option<PathBuf>,
    pub report: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustOutput {
    pub payload: Vec<u8>,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutput {
    pub payload: Vec<u8>,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsOutput {
    pub payload: Vec<u8>,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshOutput {
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutput {
    pub payload: Vec<u8>,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionOutput {
    pub payload: Vec<u8>,
    pub status: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KnownHostsLocation {
    Default(PathBuf),
    Override(PathBuf),
}

#[derive(Debug)]
pub enum TrustCommandError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

#[derive(Debug)]
pub enum CheckCommandError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

#[derive(Debug)]
pub enum StatsCommandError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

#[derive(Debug)]
pub enum SshCommandError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

#[derive(Debug)]
pub enum ExecCommandError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

#[derive(Debug)]
pub enum RunCommandError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

#[derive(Debug)]
pub enum TransferCommandError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

#[derive(Debug)]
pub enum ProvisionCommandError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

impl std::fmt::Display for TrustCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(f),
            Self::Runtime { diagnostic, .. } => f.write_str(diagnostic),
        }
    }
}

impl std::error::Error for TrustCommandError {}

impl std::fmt::Display for CheckCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(f),
            Self::Runtime { diagnostic, .. } => f.write_str(diagnostic),
        }
    }
}

impl std::error::Error for CheckCommandError {}

impl std::fmt::Display for StatsCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(f),
            Self::Runtime { diagnostic, .. } => f.write_str(diagnostic),
        }
    }
}

impl std::error::Error for StatsCommandError {}

impl std::fmt::Display for SshCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(f),
            Self::Runtime { diagnostic, .. } => f.write_str(diagnostic),
        }
    }
}

impl std::error::Error for SshCommandError {}

impl std::fmt::Display for ExecCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(f),
            Self::Runtime { diagnostic, .. } => f.write_str(diagnostic),
        }
    }
}

impl std::error::Error for ExecCommandError {}

impl std::fmt::Display for RunCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(f),
            Self::Runtime { diagnostic, .. } => f.write_str(diagnostic),
        }
    }
}

impl std::error::Error for RunCommandError {}

impl std::fmt::Display for TransferCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(f),
            Self::Runtime { diagnostic, .. } => f.write_str(diagnostic),
        }
    }
}

impl std::error::Error for TransferCommandError {}

impl std::fmt::Display for ProvisionCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(f),
            Self::Runtime { diagnostic, .. } => f.write_str(diagnostic),
        }
    }
}

impl std::error::Error for ProvisionCommandError {}

impl From<TrustCommandError> for CheckCommandError {
    fn from(error: TrustCommandError) -> Self {
        match error {
            TrustCommandError::Usage(error) => Self::Usage(error),
            TrustCommandError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

impl From<TrustCommandError> for StatsCommandError {
    fn from(error: TrustCommandError) -> Self {
        match error {
            TrustCommandError::Usage(error) => Self::Usage(error),
            TrustCommandError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

impl From<TrustCommandError> for ExecCommandError {
    fn from(error: TrustCommandError) -> Self {
        match error {
            TrustCommandError::Usage(error) => Self::Usage(error),
            TrustCommandError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

impl From<TrustCommandError> for SshCommandError {
    fn from(error: TrustCommandError) -> Self {
        match error {
            TrustCommandError::Usage(error) => Self::Usage(error),
            TrustCommandError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

impl From<TrustCommandError> for RunCommandError {
    fn from(error: TrustCommandError) -> Self {
        match error {
            TrustCommandError::Usage(error) => Self::Usage(error),
            TrustCommandError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

impl From<TrustCommandError> for TransferCommandError {
    fn from(error: TrustCommandError) -> Self {
        match error {
            TrustCommandError::Usage(error) => Self::Usage(error),
            TrustCommandError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

impl From<TrustCommandError> for ProvisionCommandError {
    fn from(error: TrustCommandError) -> Self {
        match error {
            TrustCommandError::Usage(error) => Self::Usage(error),
            TrustCommandError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

impl From<broil_remote::transfer::TransferPlanError> for TransferCommandError {
    fn from(error: broil_remote::transfer::TransferPlanError) -> Self {
        match error {
            broil_remote::transfer::TransferPlanError::Usage(error) => Self::Usage(error),
            broil_remote::transfer::TransferPlanError::Runtime { class, diagnostic } => {
                Self::Runtime { class, diagnostic }
            }
        }
    }
}

impl From<broil_remote::stats::StatsRunError> for StatsCommandError {
    fn from(error: broil_remote::stats::StatsRunError) -> Self {
        match error {
            broil_remote::stats::StatsRunError::Usage(error) => Self::Usage(error),
            broil_remote::stats::StatsRunError::Runtime { class, diagnostic } => {
                Self::Runtime { class, diagnostic }
            }
        }
    }
}

impl From<broil_remote::provision::ProvisionPlanError> for ProvisionCommandError {
    fn from(error: broil_remote::provision::ProvisionPlanError) -> Self {
        match error {
            broil_remote::provision::ProvisionPlanError::Usage(error) => Self::Usage(error),
            broil_remote::provision::ProvisionPlanError::Runtime { class, diagnostic } => {
                Self::Runtime { class, diagnostic }
            }
        }
    }
}

impl From<broil_remote::transfer::TransferRunError> for TransferCommandError {
    fn from(error: broil_remote::transfer::TransferRunError) -> Self {
        match error {
            broil_remote::transfer::TransferRunError::Usage(error) => Self::Usage(error),
            broil_remote::transfer::TransferRunError::Runtime { class, diagnostic } => {
                Self::Runtime { class, diagnostic }
            }
        }
    }
}

pub fn unavailable(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    verb: &str,
) -> RemoteError {
    match broil_remote::resolve(project, ambient_environment) {
        Ok(_) => RemoteError::UnavailablePhase {
            verb: verb.to_string(),
        },
        Err(error) => error,
    }
}

pub fn list(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    request: &ListRequest,
) -> Result<ListOutput, ListError> {
    let inventory =
        broil_remote::resolve(project, ambient_environment).map_err(ListError::Runtime)?;
    let selected =
        broil_remote::select(&inventory, &request.selectors, true).map_err(ListError::Usage)?;
    let invalid_plan_count = if request.plan {
        selected
            .iter()
            .filter(|machine| machine.plan.is_err())
            .count()
    } else {
        0
    };
    let payload = match request.output {
        OutputMode::Table => render_table(&selected, request.plan),
        OutputMode::Json => render_json(&inventory.environment, &selected, request.plan),
    };
    Ok(ListOutput {
        payload,
        invalid_plan_count,
    })
}

pub fn trust(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &TrustRequest,
    stderr: &mut dyn Write,
) -> Result<TrustOutput, TrustCommandError> {
    let inventory = broil_remote::resolve(project, ambient_environment).map_err(|error| {
        TrustCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: error.to_string(),
        }
    })?;
    let plan = if let Some(jump) = &request.jump {
        broil_remote::trust::plan_jump(&project.broil_root, &inventory, jump).map_err(|_| {
            TrustCommandError::Usage(UsageError::RemoteUnknownJump { name: jump.clone() })
        })?
    } else {
        let selected = broil_remote::select(&inventory, &request.selectors, false)
            .map_err(TrustCommandError::Usage)?;
        if request.fingerprint.is_some() && selected.len() != 1 {
            return Err(TrustCommandError::Usage(
                UsageError::RemoteFingerprintCardinality,
            ));
        }
        broil_remote::trust::plan_machines(&project.broil_root, &inventory, &selected).map_err(
            |error| TrustCommandError::Runtime {
                class: error.class(),
                diagnostic: error.to_string(),
            },
        )?
    };

    let location = resolve_known_hosts_location(
        &project.broil_root,
        inventory.known_hosts.as_deref(),
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )?;
    let store = match location {
        KnownHostsLocation::Default(home) => {
            broil_remote::known_hosts::KnownHostsStore::open_default(&home)
        }
        KnownHostsLocation::Override(path) => {
            broil_remote::known_hosts::KnownHostsStore::open_override(&path)
        }
    }
    .map_err(|error| TrustCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;

    let auth_context = broil_remote::auth::AuthContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let mut fetcher =
        broil_remote::transport::RusshHostKeyFetcher::with_auth_context(Some(auth_context))
            .map_err(|error| TrustCommandError::Runtime {
                class: FailureClass::CapabilityUnsupported,
                diagnostic: format!("cannot initialize SSH transport: {error}"),
            })?;
    let cancel = broil_remote::scheduler::CancellationToken::default();
    let _interrupt = broil_remote::trust::spawn_interrupt_watcher(cancel.clone());
    let mut decider = TerminalDecider { stderr };
    let mut clock = broil_remote::trust::SystemClock;
    let outcome = broil_remote::trust::run_cancellable(
        &plan,
        &store,
        &broil_remote::trust::TrustOptions {
            fingerprint: request.fingerprint.clone(),
            replace: request.replace,
        },
        &mut fetcher,
        &mut decider,
        &mut clock,
        &cancel,
    );
    let payload = render_trust_results(&outcome);
    if let Some(path) = &request.report {
        let report_path = normalize_path(cwd, path);
        let report = render_trust_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| TrustCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote trust report: {error}"),
        })?;
    }
    Ok(TrustOutput {
        payload,
        status: outcome.status(),
    })
}

pub fn check(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &CheckRequest,
) -> Result<CheckOutput, CheckCommandError> {
    let inventory = broil_remote::resolve(project, ambient_environment).map_err(|error| {
        CheckCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: error.to_string(),
        }
    })?;
    let selected = broil_remote::select(&inventory, &request.selectors, false)
        .map_err(CheckCommandError::Usage)?;
    let location = resolve_known_hosts_location(
        &project.broil_root,
        inventory.known_hosts.as_deref(),
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )
    .map_err(CheckCommandError::from)?;
    let store = match location {
        KnownHostsLocation::Default(home) => {
            broil_remote::known_hosts::KnownHostsStore::open_default(&home)
        }
        KnownHostsLocation::Override(path) => {
            broil_remote::known_hosts::KnownHostsStore::open_override(&path)
        }
    }
    .map_err(|error| CheckCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let auth_context = broil_remote::auth::AuthContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let privilege_context = broil_remote::check::PrivilegeContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let backend =
        broil_remote::check::RusshCheckBackend::new(store, auth_context, privilege_context);
    let outcome = broil_remote::check::run(
        &project.broil_root,
        &inventory,
        &selected,
        &broil_remote::check::CheckOptions {
            sudo: request.sudo,
            jobs: request.jobs,
            fail_fast: request.fail_fast,
        },
        backend,
    )
    .map_err(|error| CheckCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let payload = match request.output {
        OutputMode::Table => render_check_table(&outcome),
        OutputMode::Json => render_check_json(&outcome),
    };
    if let Some(path) = &request.report {
        let report_path = normalize_path(cwd, path);
        let report = render_check_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| CheckCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote check report: {error}"),
        })?;
    }
    Ok(CheckOutput {
        payload,
        status: outcome.status(),
    })
}

#[doc(hidden)]
pub fn run_stats_with_backend<B: broil_remote::stats::StatsBackend>(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &StatsRequest,
    backend: B,
) -> Result<StatsOutput, StatsCommandError> {
    let (inventory, stats_request) =
        stats_request(project, ambient_environment, cwd, env_snapshot, request)?;
    let outcome =
        broil_remote::stats::run(&project.broil_root, &inventory, &stats_request, backend)
            .map_err(StatsCommandError::from)?;
    let payload = match request.output {
        OutputMode::Table => render_stats_table(&outcome),
        OutputMode::Json => render_stats_json(&outcome),
    };
    if let Some(path) = request.report.as_deref() {
        let report_path = normalize_path(cwd, path);
        let report = render_stats_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| StatsCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote stats report: {error}"),
        })?;
    }
    Ok(StatsOutput {
        payload,
        status: outcome.status(),
    })
}

pub fn stats(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &StatsRequest,
) -> Result<StatsOutput, StatsCommandError> {
    let (inventory, stats_request) =
        stats_request(project, ambient_environment, cwd, env_snapshot, request)?;
    let store = match stats_request.known_hosts.source {
        broil_remote::stats::KnownHostsSource::DefaultHome => {
            broil_remote::known_hosts::KnownHostsStore::open_default(
                &stats_request.known_hosts.path,
            )
        }
        broil_remote::stats::KnownHostsSource::Override => {
            broil_remote::known_hosts::KnownHostsStore::open_override(
                &stats_request.known_hosts.path,
            )
        }
    }
    .map_err(|error| StatsCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let auth_context = broil_remote::auth::AuthContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let privilege_context = broil_remote::exec::PrivilegeContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let backend =
        broil_remote::stats::RusshStatsBackend::new(store, auth_context, privilege_context);
    let outcome =
        broil_remote::stats::run(&project.broil_root, &inventory, &stats_request, backend)
            .map_err(StatsCommandError::from)?;
    let payload = match request.output {
        OutputMode::Table => render_stats_table(&outcome),
        OutputMode::Json => render_stats_json(&outcome),
    };
    if let Some(path) = request.report.as_deref() {
        let report_path = normalize_path(cwd, path);
        let report = render_stats_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| StatsCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote stats report: {error}"),
        })?;
    }
    Ok(StatsOutput {
        payload,
        status: outcome.status(),
    })
}

pub fn exec(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &ExecRequest,
) -> Result<ExecOutput, ExecCommandError> {
    let inventory = broil_remote::resolve(project, ambient_environment).map_err(|error| {
        ExecCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: error.to_string(),
        }
    })?;
    let selected = broil_remote::select(&inventory, &request.selectors, false)
        .map_err(ExecCommandError::Usage)?;
    if request.pty == PtyRequest::Force && selected.len() != 1 {
        return Err(ExecCommandError::Usage(UsageError::RemotePtyCardinality));
    }

    let local_terminal = detect_local_terminal(env_snapshot);
    let pty = match request.pty {
        PtyRequest::Auto => broil_remote::exec::PtyMode::Auto,
        PtyRequest::Force => broil_remote::exec::PtyMode::Force,
        PtyRequest::Disable => broil_remote::exec::PtyMode::Disable,
    };
    let stdin = Vec::new();

    let location = resolve_known_hosts_location(
        &project.broil_root,
        inventory.known_hosts.as_deref(),
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )
    .map_err(ExecCommandError::from)?;
    let store = match location {
        KnownHostsLocation::Default(home) => {
            broil_remote::known_hosts::KnownHostsStore::open_default(&home)
        }
        KnownHostsLocation::Override(path) => {
            broil_remote::known_hosts::KnownHostsStore::open_override(&path)
        }
    }
    .map_err(|error| ExecCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let auth_context = broil_remote::auth::AuthContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let privilege_context = broil_remote::exec::PrivilegeContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let backend = broil_remote::exec::RusshExecBackend::new(store, auth_context, privilege_context);
    let outcome = broil_remote::exec::run(
        &project.broil_root,
        &inventory,
        &selected,
        &broil_remote::exec::ExecOptions {
            command: match &request.command {
                ExecCommand::Argv(argv) => broil_remote::exec::ExecCommand::Argv(argv.clone()),
                ExecCommand::Shell(body) => broil_remote::exec::ExecCommand::Shell(body.clone()),
            },
            pty,
            jobs: request.jobs,
            fail_fast: request.fail_fast,
            stdin,
            local_terminal,
            privilege: request.privilege.clone(),
        },
        backend,
    )
    .map_err(|error| ExecCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let stdout = render_exec_stream(&outcome, ExecStream::Stdout);
    let stderr = render_exec_stderr(&outcome);
    if let Some(path) = &request.report {
        let report_path = normalize_path(cwd, path);
        let report = render_exec_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| ExecCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote exec report: {error}"),
        })?;
    }
    Ok(ExecOutput {
        stdout,
        stderr,
        status: outcome.status(),
    })
}

pub fn ssh(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &SshRequest,
) -> Result<SshOutput, SshCommandError> {
    let inventory = broil_remote::resolve(project, ambient_environment).map_err(|error| {
        SshCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: error.to_string(),
        }
    })?;
    let selected = broil_remote::select(&inventory, &request.selectors, false)
        .map_err(SshCommandError::Usage)?;
    if selected.len() != 1 {
        return Err(SshCommandError::Usage(
            UsageError::RemoteSingleTargetRequired {
                verb: "ssh".to_string(),
            },
        ));
    }
    if request.bootstrap {
        if request.pty == PtyRequest::Disable {
            return Err(SshCommandError::Usage(UsageError::RemoteBootstrapNoPty));
        }
        let local_terminal = detect_local_terminal(env_snapshot);
        broil_remote::ssh::validate_bootstrap_local_terminal(&local_terminal).map_err(|error| {
            SshCommandError::Runtime {
                class: error.class(),
                diagnostic: error.to_string(),
            }
        })?;
        let location = resolve_known_hosts_location(
            &project.broil_root,
            inventory.known_hosts.as_deref(),
            cwd,
            env_snapshot,
            request.known_hosts.as_deref(),
        )
        .map_err(SshCommandError::from)?;
        let store = match location {
            KnownHostsLocation::Default(home) => {
                broil_remote::known_hosts::KnownHostsStore::open_default(&home)
            }
            KnownHostsLocation::Override(path) => {
                broil_remote::known_hosts::KnownHostsStore::open_override(&path)
            }
        }
        .map_err(|error| SshCommandError::Runtime {
            class: error.class(),
            diagnostic: error.to_string(),
        })?;
        let auth_context = broil_remote::auth::AuthContext::from_project(
            project,
            &inventory.environment,
            env_snapshot,
        );
        let cancel = broil_remote::scheduler::CancellationToken::default();
        let _interrupt = broil_remote::ssh::spawn_bootstrap_interrupt_watcher(cancel.clone());
        let outcome = broil_remote::ssh::run_bootstrap_interactive(
            &project.broil_root,
            &inventory,
            &selected,
            &broil_remote::ssh::BootstrapSshOptions {
                store,
                auth_context,
                cancel,
            },
            &local_terminal,
        )
        .map_err(|error| SshCommandError::Runtime {
            class: error.class(),
            diagnostic: error.to_string(),
        })?;
        return Ok(SshOutput {
            status: outcome.status,
        });
    }

    let home = resolve_home(env_snapshot)?;
    let location = resolve_known_hosts_location(
        &project.broil_root,
        inventory.known_hosts.as_deref(),
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )
    .map_err(SshCommandError::from)?;
    let store = match location {
        KnownHostsLocation::Default(home) => {
            broil_remote::known_hosts::KnownHostsStore::open_default(&home)
        }
        KnownHostsLocation::Override(path) => {
            broil_remote::known_hosts::KnownHostsStore::open_override(&path)
        }
    }
    .map_err(|error| SshCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let auth_context = broil_remote::auth::AuthContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let mut runner = broil_remote::ssh::SystemSshRunner;
    let outcome = broil_remote::ssh::run(
        &project.broil_root,
        &inventory,
        &selected,
        &broil_remote::ssh::SshOptions {
            pty: match request.pty {
                PtyRequest::Auto | PtyRequest::Force => broil_remote::ssh::PtyMode::Force,
                PtyRequest::Disable => broil_remote::ssh::PtyMode::Disable,
            },
            home,
            store,
            auth_context,
            env_snapshot: env_snapshot.to_vec(),
        },
        &mut runner,
    )
    .map_err(|error| SshCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    Ok(SshOutput {
        status: outcome.status,
    })
}

pub fn run(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &RunRequest,
) -> Result<RunOutput, RunCommandError> {
    let inventory = broil_remote::resolve(project, ambient_environment).map_err(|error| {
        RunCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: error.to_string(),
        }
    })?;
    let selected = broil_remote::select(&inventory, &request.selectors, false)
        .map_err(RunCommandError::Usage)?;
    if request.pty == PtyRequest::Force && selected.len() != 1 {
        return Err(RunCommandError::Usage(UsageError::RemotePtyCardinality));
    }

    let local_terminal = detect_local_terminal(env_snapshot);
    let pty = match request.pty {
        PtyRequest::Auto => broil_remote::exec::PtyMode::Auto,
        PtyRequest::Force => broil_remote::exec::PtyMode::Force,
        PtyRequest::Disable => broil_remote::exec::PtyMode::Disable,
    };
    let stdin = Vec::new();

    let location = resolve_known_hosts_location(
        &project.broil_root,
        inventory.known_hosts.as_deref(),
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )
    .map_err(RunCommandError::from)?;
    let store = match location {
        KnownHostsLocation::Default(home) => {
            broil_remote::known_hosts::KnownHostsStore::open_default(&home)
        }
        KnownHostsLocation::Override(path) => {
            broil_remote::known_hosts::KnownHostsStore::open_override(&path)
        }
    }
    .map_err(|error| RunCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let auth_context = broil_remote::auth::AuthContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let privilege_context = broil_remote::exec::PrivilegeContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let backend = broil_remote::exec::RusshExecBackend::new(store, auth_context, privilege_context);
    let outcome = broil_remote::exec::run_script(
        &project.broil_root,
        &inventory,
        &selected,
        &broil_remote::exec::RunScriptOptions {
            script: request.script.clone(),
            args: request.args.clone(),
            pty,
            jobs: request.jobs,
            fail_fast: request.fail_fast,
            stdin,
            local_terminal,
        },
        backend,
    )
    .map_err(|error| RunCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let stdout = render_exec_stream(&outcome, ExecStream::Stdout);
    let stderr = render_exec_stderr(&outcome);
    if let Some(path) = &request.report {
        let report_path = normalize_path(cwd, path);
        let report = render_run_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| RunCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote run report: {error}"),
        })?;
    }
    Ok(RunOutput {
        stdout,
        stderr,
        status: outcome.status(),
    })
}

pub fn copy_to(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &CopyToRequest,
) -> Result<TransferOutput, TransferCommandError> {
    let (inventory, transfer_request) =
        copy_to_transfer_request(project, ambient_environment, cwd, env_snapshot, request)?;
    run_transfer(
        project,
        cwd,
        env_snapshot,
        &inventory,
        &transfer_request,
        request.report.as_deref(),
    )
}

pub fn copy_from(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &CopyFromRequest,
) -> Result<TransferOutput, TransferCommandError> {
    let (inventory, transfer_request) =
        copy_from_transfer_request(project, ambient_environment, cwd, env_snapshot, request)?;
    run_transfer(
        project,
        cwd,
        env_snapshot,
        &inventory,
        &transfer_request,
        request.report.as_deref(),
    )
}

#[doc(hidden)]
pub fn plan_provision(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &ProvisionRequest,
) -> Result<broil_remote::provision::ProvisionPlan, ProvisionCommandError> {
    let (inventory, request) =
        provision_request(project, ambient_environment, cwd, env_snapshot, request)?;
    broil_remote::provision::plan(&project.broil_root, &inventory, &request)
        .map_err(ProvisionCommandError::from)
}

#[doc(hidden)]
pub fn provision_pre_dispatch(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &ProvisionRequest,
) -> Result<ProvisionOutput, ProvisionCommandError> {
    let (inventory, provision_request) =
        provision_request(project, ambient_environment, cwd, env_snapshot, request)?;
    let outcome = broil_remote::provision::pre_dispatch_outcome(
        &project.broil_root,
        &inventory,
        &provision_request,
        &broil_remote::provision::ProvisionRunOptions::default(),
    )
    .map_err(ProvisionCommandError::from)?;
    let payload = render_provision_table(&outcome);
    if let Some(path) = &request.report {
        let report_path = normalize_path(cwd, path);
        let report = render_provision_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| ProvisionCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote provision report: {error}"),
        })?;
    }
    Ok(ProvisionOutput {
        payload,
        status: outcome.status(),
    })
}

#[doc(hidden)]
pub fn execute_provision(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &ProvisionRequest,
) -> Result<ProvisionOutput, ProvisionCommandError> {
    let (inventory, provision_request) =
        provision_request(project, ambient_environment, cwd, env_snapshot, request)?;
    run_provision(
        project,
        cwd,
        env_snapshot,
        &inventory,
        &provision_request,
        request.report.as_deref(),
    )
}

#[doc(hidden)]
pub fn plan_copy_to_transfer(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &CopyToRequest,
) -> Result<broil_remote::transfer::TransferPlan, TransferCommandError> {
    let (inventory, request) =
        copy_to_transfer_request(project, ambient_environment, cwd, env_snapshot, request)?;
    broil_remote::transfer::plan(&project.broil_root, &inventory, &request)
        .map_err(TransferCommandError::from)
}

#[doc(hidden)]
pub fn plan_copy_from_transfer(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &CopyFromRequest,
) -> Result<broil_remote::transfer::TransferPlan, TransferCommandError> {
    let (inventory, request) =
        copy_from_transfer_request(project, ambient_environment, cwd, env_snapshot, request)?;
    broil_remote::transfer::plan(&project.broil_root, &inventory, &request)
        .map_err(TransferCommandError::from)
}

fn copy_to_transfer_request(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &CopyToRequest,
) -> Result<
    (
        broil_remote::EffectiveInventory,
        broil_remote::transfer::TransferRequest,
    ),
    TransferCommandError,
> {
    let inventory = resolve_transfer_inventory(project, ambient_environment)?;
    broil_remote::select(&inventory, &request.selectors, false)
        .map_err(TransferCommandError::Usage)?;
    let known_hosts = resolve_transfer_known_hosts(
        project,
        &inventory,
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )?;
    let request = broil_remote::transfer::TransferRequest {
        direction: broil_remote::transfer::TransferDirection::Upload,
        selectors: request.selectors.clone(),
        recursive: request.recursive,
        overwrite: request.overwrite,
        mode: request.mode.clone(),
        owner: request.owner.clone(),
        privilege: request.privilege.clone(),
        jobs: request.jobs,
        fail_fast: request.fail_fast,
        known_hosts,
        caller_cwd: cwd.to_path_buf(),
        source: request.source.as_os_str().as_encoded_bytes().to_vec(),
        destination: request.destination.as_encoded_bytes().to_vec(),
    };
    Ok((inventory, request))
}

fn copy_from_transfer_request(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &CopyFromRequest,
) -> Result<
    (
        broil_remote::EffectiveInventory,
        broil_remote::transfer::TransferRequest,
    ),
    TransferCommandError,
> {
    let inventory = resolve_transfer_inventory(project, ambient_environment)?;
    broil_remote::select(&inventory, &request.selectors, false)
        .map_err(TransferCommandError::Usage)?;
    let known_hosts = resolve_transfer_known_hosts(
        project,
        &inventory,
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )?;
    let request = broil_remote::transfer::TransferRequest {
        direction: broil_remote::transfer::TransferDirection::Download,
        selectors: request.selectors.clone(),
        recursive: request.recursive,
        overwrite: request.overwrite,
        mode: request.mode.clone(),
        owner: None,
        privilege: None,
        jobs: request.jobs,
        fail_fast: request.fail_fast,
        known_hosts,
        caller_cwd: cwd.to_path_buf(),
        source: request.source.as_encoded_bytes().to_vec(),
        destination: request.destination.as_os_str().as_encoded_bytes().to_vec(),
    };
    Ok((inventory, request))
}

fn run_transfer(
    project: &LoadedProject,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    inventory: &broil_remote::EffectiveInventory,
    request: &broil_remote::transfer::TransferRequest,
    report: Option<&Path>,
) -> Result<TransferOutput, TransferCommandError> {
    let auth_context = broil_remote::auth::AuthContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let privilege_context = broil_remote::transfer::TransferPrivilegeContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let backend = broil_remote::transfer::SftpSetupBackend::with_privilege_context(
        auth_context,
        privilege_context,
    );
    let outcome = broil_remote::transfer::run(&project.broil_root, inventory, request, backend)
        .map_err(TransferCommandError::from)?;
    let payload = render_transfer_table(&outcome);
    if let Some(path) = report {
        let report_path = normalize_path(cwd, path);
        let report = render_transfer_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| TransferCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote transfer report: {error}"),
        })?;
    }
    Ok(TransferOutput {
        payload,
        status: outcome.status(),
    })
}

fn run_provision(
    project: &LoadedProject,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    inventory: &broil_remote::EffectiveInventory,
    request: &broil_remote::provision::ProvisionRequest,
    report: Option<&Path>,
) -> Result<ProvisionOutput, ProvisionCommandError> {
    let store = match &request.known_hosts {
        broil_remote::provision::ResolvedKnownHosts {
            source: broil_remote::provision::KnownHostsSource::DefaultHome,
            path,
        } => broil_remote::known_hosts::KnownHostsStore::open_default(path),
        broil_remote::provision::ResolvedKnownHosts {
            source: broil_remote::provision::KnownHostsSource::Override,
            path,
        } => broil_remote::known_hosts::KnownHostsStore::open_override(path),
    }
    .map_err(|error| ProvisionCommandError::Runtime {
        class: error.class(),
        diagnostic: error.to_string(),
    })?;
    let auth_context = broil_remote::auth::AuthContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let exec_privilege_context = broil_remote::exec::PrivilegeContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let transfer_privilege_context = broil_remote::transfer::TransferPrivilegeContext::from_project(
        project,
        &inventory.environment,
        env_snapshot,
    );
    let env_remote = &project.config.environments[&inventory.environment]
        .remote
        .definitions;
    let mut secret_providers = project.config.remote.definitions.secret_providers.clone();
    secret_providers.extend(env_remote.secret_providers.clone());
    let secret_context = broil_remote::secret::SecretContext::new(
        project.broil_root.clone(),
        env_snapshot.to_vec(),
        secret_providers,
    );
    let local_artifact_home = resolve_provision_home(env_snapshot)?;
    let exec_backend = broil_remote::exec::RusshExecBackend::new(
        store.clone(),
        auth_context.clone(),
        exec_privilege_context,
    );
    let backend = broil_remote::provision::RusshProvisionBackend::new(
        broil_remote::ssh::BootstrapSshOptions {
            store,
            auth_context,
            cancel: broil_remote::scheduler::CancellationToken::default(),
        },
        exec_backend,
        transfer_privilege_context,
        secret_context,
        env_snapshot.to_vec(),
        local_artifact_home,
    );
    let outcome = broil_remote::provision::run(
        &project.broil_root,
        inventory,
        request,
        &broil_remote::provision::ProvisionRunOptions::default(),
        backend,
    )
    .map_err(ProvisionCommandError::from)?;
    let payload = render_provision_table(&outcome);
    if let Some(path) = report {
        let report_path = normalize_path(cwd, path);
        let report = render_provision_report(&outcome);
        write_atomic(&report_path, &report).map_err(|error| ProvisionCommandError::Runtime {
            class: FailureClass::TransferPathSafety,
            diagnostic: format!("cannot write remote provision report: {error}"),
        })?;
    }
    Ok(ProvisionOutput {
        payload,
        status: outcome.status(),
    })
}

fn resolve_transfer_inventory(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
) -> Result<broil_remote::EffectiveInventory, TransferCommandError> {
    broil_remote::resolve(project, ambient_environment).map_err(|error| {
        TransferCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: error.to_string(),
        }
    })
}

fn resolve_transfer_known_hosts(
    project: &LoadedProject,
    inventory: &broil_remote::EffectiveInventory,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    requested: Option<&Path>,
) -> Result<broil_remote::transfer::ResolvedKnownHosts, TransferCommandError> {
    let location = resolve_known_hosts_location(
        &project.broil_root,
        inventory.known_hosts.as_deref(),
        cwd,
        env_snapshot,
        requested,
    )?;
    Ok(match location {
        KnownHostsLocation::Default(path) => broil_remote::transfer::ResolvedKnownHosts {
            source: broil_remote::transfer::KnownHostsSource::DefaultHome,
            path,
        },
        KnownHostsLocation::Override(path) => broil_remote::transfer::ResolvedKnownHosts {
            source: broil_remote::transfer::KnownHostsSource::Override,
            path,
        },
    })
}

fn stats_request(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &StatsRequest,
) -> Result<
    (
        broil_remote::EffectiveInventory,
        broil_remote::stats::StatsRequest,
    ),
    StatsCommandError,
> {
    let inventory = broil_remote::resolve(project, ambient_environment).map_err(|error| {
        StatsCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: error.to_string(),
        }
    })?;
    broil_remote::select(&inventory, &request.selectors, false)
        .map_err(StatsCommandError::Usage)?;
    let location = resolve_known_hosts_location(
        &project.broil_root,
        inventory.known_hosts.as_deref(),
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )
    .map_err(StatsCommandError::from)?;
    let known_hosts = match location {
        KnownHostsLocation::Default(path) => broil_remote::stats::ResolvedKnownHosts {
            source: broil_remote::stats::KnownHostsSource::DefaultHome,
            path,
        },
        KnownHostsLocation::Override(path) => broil_remote::stats::ResolvedKnownHosts {
            source: broil_remote::stats::KnownHostsSource::Override,
            path,
        },
    };
    let request = broil_remote::stats::StatsRequest {
        selectors: request.selectors.clone(),
        jobs: request.jobs,
        fail_fast: request.fail_fast,
        known_hosts,
    };
    Ok((inventory, request))
}

fn provision_request(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    request: &ProvisionRequest,
) -> Result<
    (
        broil_remote::EffectiveInventory,
        broil_remote::provision::ProvisionRequest,
    ),
    ProvisionCommandError,
> {
    let inventory = broil_remote::resolve(project, ambient_environment).map_err(|error| {
        ProvisionCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: error.to_string(),
        }
    })?;
    broil_remote::select(&inventory, &request.selectors, false)
        .map_err(ProvisionCommandError::Usage)?;
    let known_hosts = resolve_provision_known_hosts(
        project,
        &inventory,
        cwd,
        env_snapshot,
        request.known_hosts.as_deref(),
    )?;
    Ok((
        inventory,
        broil_remote::provision::ProvisionRequest {
            selectors: request.selectors.clone(),
            jobs: request.jobs,
            fail_fast: request.fail_fast,
            known_hosts,
        },
    ))
}

fn resolve_provision_known_hosts(
    project: &LoadedProject,
    inventory: &broil_remote::EffectiveInventory,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    requested: Option<&Path>,
) -> Result<broil_remote::provision::ResolvedKnownHosts, ProvisionCommandError> {
    let location = resolve_known_hosts_location(
        &project.broil_root,
        inventory.known_hosts.as_deref(),
        cwd,
        env_snapshot,
        requested,
    )?;
    Ok(match location {
        KnownHostsLocation::Default(path) => broil_remote::provision::ResolvedKnownHosts {
            source: broil_remote::provision::KnownHostsSource::DefaultHome,
            path,
        },
        KnownHostsLocation::Override(path) => broil_remote::provision::ResolvedKnownHosts {
            source: broil_remote::provision::KnownHostsSource::Override,
            path,
        },
    })
}

struct TerminalDecider<'a> {
    stderr: &'a mut dyn Write,
}

const TRUST_CONFIRMATION_PROMPT: &str = "Trust this host key? Type yes: ";

fn resolve_known_hosts_location(
    broil_root: &Path,
    configured: Option<&str>,
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    requested: Option<&Path>,
) -> Result<KnownHostsLocation, TrustCommandError> {
    if let Some(path) = requested {
        return Ok(KnownHostsLocation::Override(normalize_path(cwd, path)));
    }
    if let Some(path) = configured {
        return Ok(KnownHostsLocation::Override(normalize_path(
            broil_root,
            Path::new(path),
        )));
    }
    env_snapshot
        .iter()
        .find(|(name, _)| name.as_os_str() == "HOME")
        .map(|(_, value)| KnownHostsLocation::Default(PathBuf::from(value)))
        .ok_or_else(|| TrustCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: "HOME is required for the default Broil known-hosts store".to_string(),
        })
}

fn resolve_home(env_snapshot: &[(OsString, OsString)]) -> Result<PathBuf, SshCommandError> {
    let home = env_snapshot
        .iter()
        .find(|(name, _)| name.as_os_str() == "HOME")
        .map(|(_, value)| PathBuf::from(value))
        .ok_or_else(|| SshCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: "HOME is required for remote ssh temporary artifacts".to_string(),
        })?;
    if !home.is_absolute() {
        return Err(SshCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: "HOME must be absolute for remote ssh temporary artifacts".to_string(),
        });
    }
    Ok(home)
}

fn resolve_provision_home(
    env_snapshot: &[(OsString, OsString)],
) -> Result<PathBuf, ProvisionCommandError> {
    let home = env_snapshot
        .iter()
        .find(|(name, _)| name.as_os_str() == "HOME")
        .map(|(_, value)| PathBuf::from(value))
        .ok_or_else(|| ProvisionCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: "HOME is required for remote provision temporary artifacts".to_string(),
        })?;
    if !home.is_absolute() {
        return Err(ProvisionCommandError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: "HOME must be absolute for remote provision temporary artifacts"
                .to_string(),
        });
    }
    Ok(home)
}

fn render_trust_candidate(candidate: &broil_remote::trust::TrustCandidate) -> String {
    let suffix = if candidate.canonicalizing {
        " (canonicalizing duplicate known-hosts entries)"
    } else {
        ""
    };
    format!(
        "{} {}: {} {}{suffix}\n",
        candidate.entity_kind.as_str(),
        candidate.name,
        candidate.algorithm,
        candidate.fingerprint,
    )
}

fn render_trust_failure(
    kind: broil_remote::trust::EntityKind,
    name: &str,
    diagnostic: &str,
) -> String {
    format!("{} {}: {diagnostic}\n", kind.as_str(), name)
}

impl broil_remote::trust::TrustDecider for TerminalDecider<'_> {
    fn observe_key(&mut self, candidate: &broil_remote::trust::TrustCandidate) {
        let _ = self
            .stderr
            .write_all(render_trust_candidate(candidate).as_bytes());
    }

    fn confirm(&mut self, _candidate: &broil_remote::trust::TrustCandidate) -> bool {
        let stdin = std::io::stdin();
        if !stdin.is_terminal() {
            return false;
        }
        let _ = write!(self.stderr, "{TRUST_CONFIRMATION_PROMPT}");
        let _ = self.stderr.flush();
        let mut answer = String::new();
        stdin.lock().read_line(&mut answer).is_ok() && answer.trim_end() == "yes"
    }

    fn confirm_cancellable(
        &mut self,
        _candidate: &broil_remote::trust::TrustCandidate,
        cancel: &broil_remote::scheduler::CancellationToken,
    ) -> broil_remote::trust::TrustConfirmation {
        let stdin = std::io::stdin();
        confirm_cancellable_from_terminal(self.stderr, stdin.is_terminal(), cancel)
    }

    fn observe_failure(
        &mut self,
        kind: broil_remote::trust::EntityKind,
        name: &str,
        diagnostic: &str,
    ) {
        let _ = self
            .stderr
            .write_all(render_trust_failure(kind, name, diagnostic).as_bytes());
    }
}

fn confirm_cancellable_from_terminal(
    stderr: &mut dyn Write,
    is_terminal: bool,
    cancel: &broil_remote::scheduler::CancellationToken,
) -> broil_remote::trust::TrustConfirmation {
    if !is_terminal {
        return broil_remote::trust::TrustConfirmation::Declined;
    }
    let _ = write!(stderr, "{TRUST_CONFIRMATION_PROMPT}");
    let _ = stderr.flush();
    read_cancellable_trust_confirmation(cancel)
}

fn read_cancellable_trust_confirmation(
    cancel: &broil_remote::scheduler::CancellationToken,
) -> broil_remote::trust::TrustConfirmation {
    match broil_remote::secret::read_stdin_line_cancellable(cancel, false) {
        Ok(answer) => {
            if std::str::from_utf8(&answer).is_ok_and(|answer| answer.trim_end() == "yes") {
                broil_remote::trust::TrustConfirmation::Accepted
            } else {
                broil_remote::trust::TrustConfirmation::Declined
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            broil_remote::trust::TrustConfirmation::Cancelled
        }
        Err(_) => broil_remote::trust::TrustConfirmation::Declined,
    }
}

fn render_trust_results(outcome: &broil_remote::trust::TrustOutcome) -> Vec<u8> {
    let mut output = String::new();
    for result in &outcome.results {
        output.push_str(result.entity_kind.as_str());
        output.push(' ');
        output.push_str(&result.name);
        output.push('\t');
        output.push_str(result.status.as_str());
        if let Some(action) = result.action {
            output.push('\t');
            output.push_str(action.as_str());
        }
        if let Some(class) = result.failure_class {
            output.push('\t');
            output.push_str(class.as_str());
        }
        output.push('\n');
    }
    output.into_bytes()
}

fn render_trust_report(outcome: &broil_remote::trust::TrustOutcome) -> Vec<u8> {
    let results = outcome
        .results
        .iter()
        .map(|result| {
            let mut value = json!({
                "address": result.address,
                "entity_kind": result.entity_kind.as_str(),
                "name": result.name,
                "port": result.port,
                "selected_machines": result.selected_machines,
                "status": result.status.as_str(),
            });
            if let Some(state) = result.prior_state {
                value["prior_state"] = json!(state.as_str());
            }
            if let Some(algorithm) = &result.algorithm {
                value["algorithm"] = json!(algorithm);
            }
            if let Some(fingerprint) = &result.fingerprint {
                value["fingerprint"] = json!(fingerprint);
            }
            if let Some(action) = result.action {
                value["action"] = json!(action.as_str());
            }
            if let Some(class) = result.failure_class {
                value["failure_class"] = json!(class.as_str());
            }
            if let Some(diagnostic) = &result.diagnostic {
                value["diagnostic"] = json!(diagnostic);
            }
            value
        })
        .collect::<Vec<_>>();
    let mut bytes = serde_json::to_vec(&json!({
        "command": "remote trust",
        "duration_ms": outcome.duration_millis,
        "environment": outcome.environment,
        "results": results,
        "selected_machine_targets": outcome.selected_machines,
    }))
    .expect("remote trust report values always serialize");
    bytes.push(b'\n');
    bytes
}

fn render_check_table(outcome: &broil_remote::check::CheckOutcome) -> Vec<u8> {
    let mut output = String::from(
        "MACHINE\tSCOPE\tSTATUS\toperational_readiness\tsecurity_readiness\toverall_readiness\tFAILURE\tremote_status\tremote_signal\n",
    );
    for result in &outcome.results {
        let failure = result
            .failure_class
            .map(FailureClass::as_str)
            .unwrap_or("-");
        let remote_status = result
            .remote_status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "-".to_string());
        let remote_signal = result
            .remote_signal
            .as_ref()
            .map(|signal| signal.name.as_str())
            .unwrap_or("-");
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            result.machine,
            result.scope,
            result.status.as_str(),
            result.operational_readiness.as_str(),
            result.security_readiness.as_str(),
            result.overall_readiness.as_str(),
            failure,
            remote_status,
            remote_signal,
        ));
        for probe in &result.probes {
            output.push_str(&format!(
                "  probe\t{}\tcategory={}\toutcome={}",
                probe.probe.as_str(),
                probe.category.as_str(),
                probe.outcome.as_str(),
            ));
            if let Some(class) = probe.failure_class {
                output.push_str(&format!("\tfailure_class={}", class.as_str()));
            }
            if let Some(status) = probe.remote_status {
                output.push_str(&format!("\tremote_status={status}"));
            }
            if let Some(signal) = &probe.remote_signal {
                output.push_str(&format!("\tremote_signal={}", signal.name));
            }
            if probe.dispatched {
                output.push_str("\tdispatched=true");
            }
            if probe.possible_staging_residue {
                output.push_str("\tpossible_staging_residue=true");
            }
            output.push('\n');
        }
    }
    output.into_bytes()
}

fn render_check_json(outcome: &broil_remote::check::CheckOutcome) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "environment": &outcome.environment,
        "scope": &outcome.scope,
        "results": outcome.results.iter().map(check_result_json).collect::<Vec<_>>(),
    }))
    .expect("remote check values always serialize");
    bytes.push(b'\n');
    bytes
}

fn render_check_report(outcome: &broil_remote::check::CheckOutcome) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "command": "remote check",
        "duration_ms": outcome.duration_millis,
        "environment": &outcome.environment,
        "results": outcome.results.iter().map(check_result_json).collect::<Vec<_>>(),
        "scope": &outcome.scope,
        "selected_machine_targets": &outcome.selected_machines,
    }))
    .expect("remote check report values always serialize");
    bytes.push(b'\n');
    bytes
}

fn check_result_json(result: &broil_remote::check::CheckTargetResult) -> Value {
    let mut value = json!({
        "dispatched": result.dispatched,
        "failure_class": result.failure_class.map(FailureClass::as_str),
        "machine": &result.machine,
        "operational_readiness": result.operational_readiness.as_str(),
        "overall_readiness": result.overall_readiness.as_str(),
        "possible_staging_residue": result.possible_staging_residue,
        "probes": result.probes.iter().map(check_probe_json).collect::<Vec<_>>(),
        "scope": &result.scope,
        "security_readiness": result.security_readiness.as_str(),
        "status": result.status.as_str(),
    });
    if let Some(status) = result.remote_status {
        value["remote_status"] = json!(status);
    }
    if let Some(signal) = &result.remote_signal {
        value["remote_signal"] = json!(signal.name);
    }
    value
}

fn check_probe_json(probe: &broil_remote::check::ProbeRecord) -> Value {
    let mut value = json!({
        "category": probe.category.as_str(),
        "dispatched": probe.dispatched,
        "failure_class": probe.failure_class.map(FailureClass::as_str),
        "outcome": probe.outcome.as_str(),
        "possible_staging_residue": probe.possible_staging_residue,
        "probe": probe.probe.as_str(),
    });
    if let Some(diagnostic) = &probe.diagnostic {
        value["diagnostic"] = json!(diagnostic);
    }
    if let Some(status) = probe.remote_status {
        value["remote_status"] = json!(status);
    }
    if let Some(signal) = &probe.remote_signal {
        value["remote_signal"] = json!(signal.name);
    }
    value
}

fn render_stats_table(outcome: &broil_remote::stats::StatsOutcome) -> Vec<u8> {
    let mut output = String::from(
        "MACHINE\tSTATUS\tFAILURE\tremote_status\tremote_signal\tpossible_staging_residue\n",
    );
    for result in &outcome.results {
        let failure = result
            .failure_class
            .map(FailureClass::as_str)
            .unwrap_or("-");
        let remote_status = result
            .remote_status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "-".to_string());
        let remote_signal = result
            .remote_signal
            .as_ref()
            .map(|signal| signal.name.as_str())
            .unwrap_or("-");
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            stats_table_field(&result.machine),
            result.status.as_str(),
            failure,
            remote_status,
            remote_signal,
            result.possible_staging_residue,
        ));
        for category in &result.categories {
            output.push_str(&format!(
                "  stats\t{}\tstatus={}",
                category.category.as_str(),
                category.status.as_str(),
            ));
            if let Some(class) = category.failure_class {
                output.push_str(&format!("\tfailure_class={}", class.as_str()));
            }
            if let Some(diagnostic) = &category.diagnostic {
                output.push_str(&format!("\tdiagnostic={}", stats_table_field(diagnostic)));
            }
            if let Some(status) = category.remote_status {
                output.push_str(&format!("\tremote_status={status}"));
            }
            if let Some(signal) = &category.remote_signal {
                output.push_str(&format!("\tremote_signal={}", signal.name));
            }
            if category.dispatched {
                output.push_str("\tdispatched=true");
            }
            if category.possible_staging_residue {
                output.push_str("\tpossible_staging_residue=true");
            }
            output.push('\n');
            for record in &category.records {
                output.push_str("    record");
                if let Some(name) = &record.name {
                    output.push_str(&format!("\tname={}", stats_table_field(name)));
                }
                for (key, value) in &record.values {
                    output.push_str(&format!(
                        "\t{}={}",
                        stats_table_field(key),
                        stats_table_field(value)
                    ));
                }
                output.push('\n');
            }
        }
    }
    output.into_bytes()
}

fn stats_table_field(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

fn render_stats_json(outcome: &broil_remote::stats::StatsOutcome) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "environment": &outcome.environment,
        "results": outcome.results.iter().map(stats_result_json).collect::<Vec<_>>(),
    }))
    .expect("remote stats values always serialize");
    bytes.push(b'\n');
    bytes
}

fn render_stats_report(outcome: &broil_remote::stats::StatsOutcome) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "command": "remote stats",
        "duration_ms": outcome.duration_millis,
        "environment": &outcome.environment,
        "results": outcome.results.iter().map(stats_result_json).collect::<Vec<_>>(),
        "selected_machine_targets": &outcome.selected_machines,
    }))
    .expect("remote stats report values always serialize");
    bytes.push(b'\n');
    bytes
}

fn stats_result_json(result: &broil_remote::stats::StatsTargetResult) -> Value {
    let mut value = json!({
        "categories": result.categories.iter().map(stats_category_json).collect::<Vec<_>>(),
        "dispatched": result.dispatched,
        "failure_class": result.failure_class.map(FailureClass::as_str),
        "machine": &result.machine,
        "possible_staging_residue": result.possible_staging_residue,
        "status": result.status.as_str(),
    });
    if let Some(diagnostic) = &result.diagnostic {
        value["diagnostic"] = json!(diagnostic);
    }
    if let Some(status) = result.remote_status {
        value["remote_status"] = json!(status);
    }
    if let Some(signal) = &result.remote_signal {
        value["remote_signal"] = json!(signal.name);
    }
    value
}

fn stats_category_json(category: &broil_remote::stats::StatsCategoryResult) -> Value {
    let mut value = json!({
        "category": category.category.as_str(),
        "dispatched": category.dispatched,
        "failure_class": category.failure_class.map(FailureClass::as_str),
        "possible_staging_residue": category.possible_staging_residue,
        "records": category.records.iter().map(stats_record_json).collect::<Vec<_>>(),
        "status": category.status.as_str(),
    });
    if let Some(diagnostic) = &category.diagnostic {
        value["diagnostic"] = json!(diagnostic);
    }
    if let Some(status) = category.remote_status {
        value["remote_status"] = json!(status);
    }
    if let Some(signal) = &category.remote_signal {
        value["remote_signal"] = json!(signal.name);
    }
    value
}

fn stats_record_json(record: &broil_remote::stats::StatsRecord) -> Value {
    json!({
        "name": &record.name,
        "values": &record.values,
    })
}

#[derive(Clone, Copy)]
enum ExecStream {
    Stdout,
    Stderr,
}

fn detect_local_terminal(
    env_snapshot: &[(OsString, OsString)],
) -> broil_remote::exec::LocalTerminal {
    let term = env_snapshot
        .iter()
        .find(|(name, _)| name.as_os_str() == "TERM")
        .map(|(_, value)| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "xterm".to_string());
    broil_remote::exec::LocalTerminal {
        stdin: std::io::stdin().is_terminal(),
        stdout: std::io::stdout().is_terminal(),
        stderr: std::io::stderr().is_terminal(),
        term,
        columns: 80,
        rows: 24,
    }
}

fn render_exec_stream(outcome: &broil_remote::exec::ExecOutcome, stream: ExecStream) -> Vec<u8> {
    if outcome.results.len() == 1 {
        return match stream {
            ExecStream::Stdout => outcome.results[0].stdout.clone(),
            ExecStream::Stderr => outcome.results[0].stderr.clone(),
        };
    }
    let mut output = Vec::new();
    for result in &outcome.results {
        let bytes = match stream {
            ExecStream::Stdout => &result.stdout,
            ExecStream::Stderr => &result.stderr,
        };
        if !output.is_empty() && !output.ends_with(b"\n") && !bytes.is_empty() {
            output.push(b'\n');
        }
        prefix_lines(&mut output, &result.machine, bytes);
    }
    output
}

fn render_exec_stderr(outcome: &broil_remote::exec::ExecOutcome) -> Vec<u8> {
    let mut stderr = render_exec_stream(outcome, ExecStream::Stderr);
    for result in &outcome.results {
        if result.status == broil_remote::exec::TargetStatus::Success {
            continue;
        }
        if outcome.results.len() == 1 && result.failure_class == Some(FailureClass::RemoteNonzero) {
            continue;
        }
        let class = result
            .failure_class
            .map(FailureClass::as_str)
            .unwrap_or("unknown");
        let diagnostic = result.diagnostic.as_deref().unwrap_or("remote exec failed");
        if !stderr.is_empty() && !stderr.ends_with(b"\n") {
            stderr.push(b'\n');
        }
        stderr.extend_from_slice(
            format!("{}\tfailed\t{}\t{}\n", result.machine, class, diagnostic).as_bytes(),
        );
    }
    stderr
}

fn prefix_lines(output: &mut Vec<u8>, machine: &str, bytes: &[u8]) {
    let mut line_start = true;
    for byte in bytes {
        if line_start {
            output.extend_from_slice(machine.as_bytes());
            output.push(b'\t');
            line_start = false;
        }
        output.push(*byte);
        if *byte == b'\n' {
            line_start = true;
        }
    }
}

fn render_exec_report(outcome: &broil_remote::exec::ExecOutcome) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "actions": [{
            "name": "exec",
            "stages": [
                "connect/authenticate",
                "stage launcher",
                "chmod launcher",
                "dispatch launcher",
                "cleanup staging",
            ],
        }],
        "command": "remote exec",
        "duration_ms": outcome.duration_millis,
        "environment": &outcome.environment,
        "results": outcome.results.iter().map(|result| exec_result_json(result, "exec")).collect::<Vec<_>>(),
        "selected_machine_targets": &outcome.selected_machines,
    }))
    .expect("remote exec report values always serialize");
    bytes.push(b'\n');
    bytes
}

fn render_run_report(outcome: &broil_remote::exec::ExecOutcome) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "actions": [{
            "name": "run",
            "stages": [
                "connect/authenticate",
                "stage launcher/body",
                "chmod launcher/body",
                "dispatch script",
                "cleanup staging",
            ],
        }],
        "command": "remote run",
        "duration_ms": outcome.duration_millis,
        "environment": &outcome.environment,
        "results": outcome.results.iter().map(|result| exec_result_json(result, "run")).collect::<Vec<_>>(),
        "selected_machine_targets": &outcome.selected_machines,
    }))
    .expect("remote run report values always serialize");
    bytes.push(b'\n');
    bytes
}

fn render_transfer_table(outcome: &broil_remote::transfer::TransferOutcome) -> Vec<u8> {
    let mut output = String::from(
        "MACHINE\tDIRECTION\tSTATUS\tFAILURE\tdispatched\tpossible_staging_residue\tDIAGNOSTIC\n",
    );
    for result in &outcome.results {
        let failure = result
            .failure_class
            .map(FailureClass::as_str)
            .unwrap_or("-");
        let diagnostic = transfer_public_diagnostic(result)
            .map(|diagnostic| sanitize_transfer_text(&diagnostic))
            .unwrap_or_else(|| "-".to_string());
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            result.machine,
            result.direction.as_str(),
            result.status.as_str(),
            failure,
            result.dispatched,
            result.possible_staging_residue,
            diagnostic,
        ));
    }
    output.into_bytes()
}

#[doc(hidden)]
pub fn render_transfer_report(outcome: &broil_remote::transfer::TransferOutcome) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "actions": [{
            "name": outcome.direction.as_str(),
            "stages": [
                "plan transfer",
                "probe SFTP capability",
                "transfer data",
                "finalize destination",
            ],
        }],
        "command": outcome.direction.command(),
        "direction": outcome.direction.as_str(),
        "duration_ms": outcome.duration_millis,
        "environment": &outcome.environment,
        "results": outcome.results.iter().map(transfer_result_json).collect::<Vec<_>>(),
        "selected_machine_targets": &outcome.selected_machines,
    }))
    .expect("remote transfer report values always serialize");
    bytes.push(b'\n');
    bytes
}

fn transfer_result_json(result: &broil_remote::transfer::TransferTargetResult) -> Value {
    let mut value = json!({
        "direction": result.direction.as_str(),
        "dispatched": result.dispatched,
        "failure_class": result.failure_class.map(FailureClass::as_str),
        "machine": &result.machine,
        "possible_staging_residue": result.possible_staging_residue,
        "status": result.status.as_str(),
    });
    if result.diagnostic_in_report {
        if let Some(diagnostic) = transfer_public_diagnostic(result) {
            value["diagnostic"] = json!(diagnostic);
        }
    }
    if let Some(status) = result.remote_status {
        value["remote_status"] = json!(status);
    }
    value
}

fn render_provision_table(outcome: &broil_remote::provision::ProvisionOutcome) -> Vec<u8> {
    let mut output = String::from(
        "MACHINE\tSTATUS\tFAILURE\tdispatched\tPHASE\tACTION\tpossible_staging_residue\tDIAGNOSTIC\n",
    );
    for result in &outcome.results {
        let failure = result
            .failure_class
            .map(FailureClass::as_str)
            .unwrap_or("-");
        let phase = result.phase.as_deref().unwrap_or("-");
        let action = result.action.as_deref().unwrap_or("-");
        let diagnostic = result
            .diagnostic
            .as_deref()
            .map(sanitize_transfer_text)
            .unwrap_or_else(|| "-".to_string());
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            result.machine,
            result.status.as_str(),
            failure,
            result.dispatched,
            phase,
            action,
            result.possible_staging_residue,
            diagnostic,
        ));
    }
    output.into_bytes()
}

#[doc(hidden)]
pub fn render_provision_report(outcome: &broil_remote::provision::ProvisionOutcome) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({
        "actions": [{
            "name": "provision",
            "stages": [
                "plan provisioning",
                "pre-dispatch validation",
                "bootstrap",
                "secure",
                "security gate",
                "configure",
            ],
        }],
        "command": "remote provision",
        "duration_ms": outcome.duration_millis,
        "environment": &outcome.environment,
        "results": outcome.results.iter().map(provision_result_json).collect::<Vec<_>>(),
        "selected_machine_targets": &outcome.selected_machines,
    }))
    .expect("remote provision report values always serialize");
    bytes.push(b'\n');
    bytes
}

fn provision_result_json(result: &broil_remote::provision::ProvisionTargetResult) -> Value {
    let mut value = json!({
        "dispatched": result.dispatched,
        "failure_class": result.failure_class.map(FailureClass::as_str),
        "machine": &result.machine,
        "possible_staging_residue": result.possible_staging_residue,
        "status": result.status.as_str(),
    });
    if result.diagnostic_in_report {
        if let Some(diagnostic) = &result.diagnostic {
            value["diagnostic"] = json!(sanitize_transfer_text(diagnostic));
        }
    }
    if let Some(phase) = &result.phase {
        value["phase"] = json!(phase);
    }
    if let Some(action) = &result.action {
        value["action"] = json!(action);
    }
    if let Some(status) = result.remote_status {
        value["remote_status"] = json!(status);
    }
    if let Some(signal) = &result.remote_signal {
        value["remote_signal"] = json!(signal.name);
    }
    value
}

fn transfer_public_diagnostic(
    result: &broil_remote::transfer::TransferTargetResult,
) -> Option<String> {
    let diagnostic = result.diagnostic.as_deref()?;
    let diagnostic = sanitize_transfer_text(diagnostic);
    if result.failure_class == Some(FailureClass::Sftp)
        && diagnostic.starts_with("SFTP subsystem request")
    {
        Some(format!(
            "{diagnostic}; enable SFTP on the selected host before using remote copy"
        ))
    } else {
        Some(diagnostic)
    }
}

fn sanitize_transfer_text(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\t' | '\n' | '\r' => ' ',
            character if character.is_control() => '?',
            character => character,
        })
        .collect()
}

fn exec_result_json(result: &broil_remote::exec::ExecTargetResult, action: &str) -> Value {
    let mut value = json!({
        "action": action,
        "dispatched": result.dispatched,
        "failure_class": result.failure_class.map(FailureClass::as_str),
        "machine": &result.machine,
        "possible_staging_residue": result.possible_staging_residue,
        "status": result.status.as_str(),
    });
    if result.diagnostic_in_report {
        if let Some(diagnostic) = &result.diagnostic {
            value["diagnostic"] = json!(diagnostic);
        }
    }
    if let Some(status) = result.remote_status {
        value["remote_status"] = json!(status);
    }
    if let Some(signal) = &result.remote_signal {
        value["remote_signal"] = json!(signal.name);
    }
    value
}

fn normalize_path(base: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
        }
    }
    normalized
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("report path has no parent"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_nanos();
    let temp = path.with_extension(format!("tmp.{nonce:016x}"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    fs::File::open(parent)?.sync_all()
}

fn render_table(machines: &[&EffectiveMachine], include_plan: bool) -> Vec<u8> {
    let mut output = String::from(
        "NAME\tADDRESS\tPORT\tTAGS\tROUTE\tCANONICAL\tBOOTSTRAP\tPRIVILEGE\tPROVISION\tTIMEOUTS\n",
    );
    for machine in machines {
        let canonical = format!("{}({})", machine.canonical_profile, machine.canonical_user);
        let bootstrap = machine
            .bootstrap_profiles
            .iter()
            .map(|auth| format!("{}({})", auth.profile, auth.user))
            .collect::<Vec<_>>()
            .join(",");
        let privilege = machine.privilege_profile.as_deref().unwrap_or("-");
        let profiles = machine.provision_profiles.join(",");
        let timeouts = format!(
            "connect={},command={},transfer={},reboot-disconnect={},reboot-readiness={},reboot-poll={}",
            machine.timeouts.connect.source,
            machine.timeouts.command.source,
            machine.timeouts.transfer.source,
            machine.timeouts.reboot_disconnect.source,
            machine.timeouts.reboot_readiness.source,
            machine.timeouts.reboot_poll.source,
        );
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            machine.name,
            machine.address,
            machine.port,
            machine.tags.join(","),
            machine.route,
            canonical,
            bootstrap,
            privilege,
            profiles,
            timeouts,
        ));
        if include_plan {
            match &machine.plan {
                Ok(Some(plan)) => render_table_plan(&mut output, plan),
                Ok(None) => output.push_str("  plan\tnone\n"),
                Err(error) => render_table_plan_error(&mut output, error),
            }
        }
    }
    output.into_bytes()
}

fn render_table_plan_error(output: &mut String, error: &PlanValidationError) {
    output.push_str("  plan\tinvalid\n");
    match error {
        PlanValidationError::TransitionOwnerCount { count } => output.push_str(&format!(
            "  plan-error\tkind=transition_owner_count\tcount={count}\n"
        )),
        PlanValidationError::MissingSecurityVerifier => {
            output.push_str("  plan-error\tkind=missing_security_verifier\n");
        }
        PlanValidationError::MissingScriptBinding { action, binding } => output.push_str(&format!(
            "  plan-error\tkind=missing_script_binding\taction={action}\tbinding={binding}\n"
        )),
        PlanValidationError::UnprivilegedSecurityVerifier { action } => output.push_str(&format!(
            "  plan-error\tkind=unprivileged_security_verifier\taction={action}\n"
        )),
        PlanValidationError::UploadOwnerRequiresRoot { action } => output.push_str(&format!(
            "  plan-error\tkind=upload_owner_requires_root\taction={action}\n"
        )),
        PlanValidationError::MissingSecretStdinProvider { action, provider } => {
            output.push_str(&format!(
                "  plan-error\tkind=missing_secret_stdin_provider\taction={action}\tprovider={provider}\n"
            ));
        }
        PlanValidationError::MissingActionPrivilege { action, privilege } => {
            output.push_str(&format!(
                "  plan-error\tkind=missing_action_privilege\taction={action}\tprivilege={privilege}\n"
            ));
        }
        PlanValidationError::PasswordSudoWithSecretStdin { action } => output.push_str(&format!(
            "  plan-error\tkind=password_sudo_with_secret_stdin\taction={action}\n"
        )),
        PlanValidationError::UnprivilegedReboot { action } => output.push_str(&format!(
            "  plan-error\tkind=unprivileged_reboot\taction={action}\n"
        )),
        PlanValidationError::ActionBeforeConfigure { action } => output.push_str(&format!(
            "  plan-error\tkind=action_before_configure\taction={action}\n"
        )),
    }
}

fn render_table_plan(output: &mut String, plan: &EffectivePlan) {
    render_table_phase(output, plan, "bootstrap");
    render_table_phase(output, plan, "secure");
    output.push_str(&format!("  transition\towner={}\n", plan.transition_owner));
    for action in &plan.transition_actions {
        render_table_named_script(output, "    transition-action", action);
    }
    for action in &plan.security_verifiers {
        render_table_named_script(output, "  security-verifier", action);
    }
    render_table_phase(output, plan, "configure");
}

fn render_table_phase(output: &mut String, plan: &EffectivePlan, phase: &str) {
    let steps: Vec<_> = plan
        .steps
        .iter()
        .filter(|step| step.phase == phase)
        .collect();
    if steps.is_empty() {
        return;
    }
    output.push_str(&format!("  phase\t{phase}\n"));
    for step in steps {
        render_table_step(output, step);
    }
}

fn render_table_step(output: &mut String, step: &EffectivePlanStep) {
    output.push_str(&format!("    step\t{}\n", step.id));
    if let Some(action) = &step.check {
        render_table_timed(output, "      check", action);
    }
    render_table_action(output, "      run", &step.run);
    if let Some(action) = &step.verify {
        render_table_timed(output, "      verify", action);
    }
}

fn render_table_named_script(output: &mut String, row: &str, action: &EffectiveNamedScriptAction) {
    output.push_str(&format!(
        "{row}\t{}\tkind=script\tscript={}\ttimeout={}",
        action.name, action.script, action.timeout.source
    ));
    if action.stdin_secret {
        output.push_str("\tstdin=secret");
    }
    output.push('\n');
}

fn render_table_timed(output: &mut String, row: &str, action: &EffectiveTimedAction) {
    output.push_str(&format!("{row}\tkind={}", action.kind));
    if let Some(script) = &action.script {
        output.push_str(&format!("\tscript={script}"));
    }
    if action.stdin_secret {
        output.push_str("\tstdin=secret");
    }
    output.push_str(&format!("\ttimeout={}\n", action.timeout.source));
}

fn render_table_action(output: &mut String, row: &str, action: &EffectivePlanAction) {
    match action {
        EffectivePlanAction::Timed(action) => render_table_timed(output, row, action),
        EffectivePlanAction::Reboot(action) => {
            output.push_str(&format!(
                "{row}\tkind=reboot\tdisconnect_timeout={}\treadiness_timeout={}\tpoll_interval={}\n",
                action.disconnect_timeout.source,
                action.readiness_timeout.source,
                action.poll_interval.source,
            ));
            if let Some(when) = &action.when {
                render_table_timed(output, "        when", when);
            }
        }
    }
}

fn render_json(environment: &str, machines: &[&EffectiveMachine], include_plan: bool) -> Vec<u8> {
    let records: Vec<Value> = machines
        .iter()
        .map(|machine| machine_json(machine, include_plan))
        .collect();
    let mut bytes = serde_json::to_vec(&json!({
        "environment": environment,
        "machines": records,
    }))
    .expect("remote inventory values always serialize");
    bytes.push(b'\n');
    bytes
}

fn machine_json(machine: &EffectiveMachine, include_plan: bool) -> Value {
    let mut value = json!({
        "address": machine.address,
        "bootstrap_auth": machine.bootstrap_profiles.iter().map(|auth| json!({
            "profile": auth.profile,
            "user": auth.user,
        })).collect::<Vec<_>>(),
        "canonical_auth": {
            "profile": machine.canonical_profile,
            "user": machine.canonical_user,
        },
        "name": machine.name,
        "port": machine.port,
        "privilege": machine.privilege_profile,
        "provision_profiles": machine.provision_profiles,
        "route": machine.route,
        "tags": machine.tags,
        "timeouts": {
            "command": machine.timeouts.command.source,
            "connect": machine.timeouts.connect.source,
            "reboot_disconnect": machine.timeouts.reboot_disconnect.source,
            "reboot_poll": machine.timeouts.reboot_poll.source,
            "reboot_readiness": machine.timeouts.reboot_readiness.source,
            "transfer": machine.timeouts.transfer.source,
        },
    });
    if include_plan {
        value["plan"] = match &machine.plan {
            Ok(Some(plan)) => plan_json(plan),
            Ok(None) => Value::Null,
            Err(error) => plan_error_json(error),
        };
    }
    value
}

fn plan_json(plan: &EffectivePlan) -> Value {
    json!({
        "security_verifiers": plan.security_verifiers.iter().map(named_script_json).collect::<Vec<_>>(),
        "steps": plan.steps.iter().map(|step| json!({
            "check": step.check.as_ref().map(timed_action_json),
            "id": step.id,
            "phase": step.phase,
            "run": action_json(&step.run),
            "verify": step.verify.as_ref().map(timed_action_json),
        })).collect::<Vec<_>>(),
        "status": "valid",
        "transition_actions": plan.transition_actions.iter().map(named_script_json).collect::<Vec<_>>(),
        "transition_owner": plan.transition_owner,
    })
}

fn plan_error_json(error: &PlanValidationError) -> Value {
    let error = match error {
        PlanValidationError::TransitionOwnerCount { count } => json!({
            "count": count,
            "kind": "transition_owner_count",
        }),
        PlanValidationError::MissingSecurityVerifier => json!({
            "kind": "missing_security_verifier",
        }),
        PlanValidationError::MissingScriptBinding { action, binding } => json!({
            "action": action,
            "binding": binding,
            "kind": "missing_script_binding",
        }),
        PlanValidationError::UnprivilegedSecurityVerifier { action } => json!({
            "action": action,
            "kind": "unprivileged_security_verifier",
        }),
        PlanValidationError::UploadOwnerRequiresRoot { action } => json!({
            "action": action,
            "kind": "upload_owner_requires_root",
        }),
        PlanValidationError::MissingSecretStdinProvider { action, provider } => json!({
            "action": action,
            "kind": "missing_secret_stdin_provider",
            "provider": provider,
        }),
        PlanValidationError::MissingActionPrivilege { action, privilege } => json!({
            "action": action,
            "kind": "missing_action_privilege",
            "privilege": privilege,
        }),
        PlanValidationError::PasswordSudoWithSecretStdin { action } => json!({
            "action": action,
            "kind": "password_sudo_with_secret_stdin",
        }),
        PlanValidationError::UnprivilegedReboot { action } => json!({
            "action": action,
            "kind": "unprivileged_reboot",
        }),
        PlanValidationError::ActionBeforeConfigure { action } => json!({
            "action": action,
            "kind": "action_before_configure",
        }),
    };
    json!({
        "error": error,
        "failure_class": "configuration",
        "status": "invalid",
    })
}

fn named_script_json(action: &EffectiveNamedScriptAction) -> Value {
    let mut value = json!({
        "kind": "script",
        "name": action.name,
        "script": action.script,
        "timeout": action.timeout.source,
    });
    if action.stdin_secret {
        value["stdin"] = json!("secret");
    }
    value
}

fn timed_action_json(action: &EffectiveTimedAction) -> Value {
    let mut value = json!({
        "kind": action.kind,
        "timeout": action.timeout.source,
    });
    if let Some(script) = &action.script {
        value["script"] = json!(script);
    }
    if action.stdin_secret {
        value["stdin"] = json!("secret");
    }
    value
}

fn action_json(action: &EffectivePlanAction) -> Value {
    match action {
        EffectivePlanAction::Timed(action) => timed_action_json(action),
        EffectivePlanAction::Reboot(action) => json!({
            "disconnect_timeout": action.disconnect_timeout.source,
            "kind": "reboot",
            "poll_interval": action.poll_interval.source,
            "readiness_timeout": action.readiness_timeout.source,
            "when": action.when.as_ref().map(timed_action_json),
        }),
    }
}

