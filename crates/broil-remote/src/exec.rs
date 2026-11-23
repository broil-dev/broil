// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use broil_config::LoadedProject;
use broil_core::remote::{PrivilegeProfile, PtyMode as ScriptPtyMode, RemoteEnvValue};
use russh::ChannelMsg;
use russh::client;
use russh::keys::Algorithm;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zeroize::Zeroizing;

use crate::alias::{env_jump_alias, root_jump_alias, target_alias};
use crate::auth::{self, AuthContext};
use crate::check::RemoteSignal;
use crate::jobs::{RequestedJobs, resolve_jobs};
use crate::known_hosts::{AliasState, KnownHostsStore, StoreError};
use crate::scheduler::{self, CancellationToken};
use crate::transport::StrictHandler;
use crate::{
    EffectiveInventory, EffectiveMachine, EffectiveTimeouts, FailureClass, HostKey, JumpScope,
};

#[path = "private_exec.rs"]
pub mod private;

const CANCEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyMode {
    Auto,
    Force,
    Disable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecCommand {
    Argv(Vec<Vec<u8>>),
    Shell(Vec<u8>),
    Script(RemoteScriptCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteScriptCommand {
    pub body: Vec<u8>,
    pub interpreter: Option<Vec<Vec<u8>>>,
    pub cwd: Option<Vec<u8>>,
    pub cwd_display: Option<String>,
    pub cwd_nonce: String,
    pub env: BTreeMap<String, Vec<u8>>,
    pub args: Vec<Vec<u8>>,
}

pub(crate) struct RemoteScriptContext<'a> {
    pub(crate) environment: &'a str,
    pub(crate) env_vars: &'a BTreeMap<String, String>,
    pub(crate) default_interpreter: &'a [String],
}

impl<'a> RemoteScriptContext<'a> {
    fn from_inventory(inventory: &'a EffectiveInventory) -> Self {
        Self {
            environment: &inventory.environment,
            env_vars: &inventory.env_vars,
            default_interpreter: &inventory.default_interpreter,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecOptions {
    pub command: ExecCommand,
    pub pty: PtyMode,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub stdin: Vec<u8>,
    pub local_terminal: LocalTerminal,
    pub privilege: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RunScriptOptions {
    pub script: Vec<u8>,
    pub args: Vec<Vec<u8>>,
    pub pty: PtyMode,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub stdin: Vec<u8>,
    pub local_terminal: LocalTerminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTerminal {
    pub stdin: bool,
    pub stdout: bool,
    pub stderr: bool,
    pub term: String,
    pub columns: u32,
    pub rows: u32,
}

impl Default for LocalTerminal {
    fn default() -> Self {
        Self {
            stdin: false,
            stdout: false,
            stderr: false,
            term: "xterm".to_string(),
            columns: 80,
            rows: 24,
        }
    }
}

#[derive(Clone)]
pub struct StaticStdin {
    inner: Arc<StaticStdinInner>,
}

enum StaticStdinInner {
    Plain(Vec<u8>),
    Secret(Mutex<Option<Zeroizing<Vec<u8>>>>),
}

impl StaticStdin {
    pub fn empty() -> Self {
        Self::plain(Vec::new())
    }

    pub fn plain(bytes: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(StaticStdinInner::Plain(bytes)),
        }
    }

    pub fn secret(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(StaticStdinInner::Secret(Mutex::new(Some(bytes)))),
        }
    }

    fn is_empty(&self) -> bool {
        matches!(&*self.inner, StaticStdinInner::Plain(bytes) if bytes.is_empty())
    }

    fn next_input(&self) -> Result<Option<Zeroizing<Vec<u8>>>, ExecFailure> {
        match &*self.inner {
            StaticStdinInner::Plain(bytes) if bytes.is_empty() => Ok(None),
            StaticStdinInner::Plain(bytes) => Ok(Some(Zeroizing::new(bytes.clone()))),
            StaticStdinInner::Secret(bytes) => bytes
                .lock()
                .expect("secret stdin mutex poisoned")
                .take()
                .map(Some)
                .ok_or_else(|| {
                    ExecFailure::new(
                        FailureClass::IndeterminateAfterDispatch,
                        "secret stdin was already consumed",
                    )
                    .dispatched()
                    .residue()
                }),
        }
    }
}

impl fmt::Debug for StaticStdin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self.inner {
            StaticStdinInner::Plain(bytes) => formatter
                .debug_struct("StaticStdin")
                .field("kind", &"plain")
                .field("len", &bytes.len())
                .finish(),
            StaticStdinInner::Secret(_) => formatter.write_str("StaticStdin::Secret([REDACTED])"),
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
pub struct ExecTargetResult {
    pub machine: String,
    pub status: TargetStatus,
    pub failure_class: Option<FailureClass>,
    pub diagnostic: Option<String>,
    pub dispatched: bool,
    pub remote_status: Option<i32>,
    pub remote_signal: Option<RemoteSignal>,
    pub possible_staging_residue: bool,
    pub diagnostic_in_report: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutcome {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub duration_millis: u128,
    pub results: Vec<ExecTargetResult>,
}

impl ExecOutcome {
    pub fn status(&self) -> i32 {
        if self.results.len() == 1 {
            return self.results[0].single_status();
        }
        if self
            .results
            .iter()
            .all(|result| result.status == TargetStatus::Success)
        {
            0
        } else {
            1
        }
    }
}

impl ExecTargetResult {
    fn success(machine: String, command: RemoteCommand, residue: bool) -> Self {
        Self {
            machine,
            status: TargetStatus::Success,
            failure_class: None,
            diagnostic: None,
            dispatched: true,
            remote_status: command.status,
            remote_signal: command.signal,
            possible_staging_residue: residue,
            diagnostic_in_report: true,
            stdout: command.stdout,
            stderr: command.stderr,
        }
    }

    fn failure(machine: String, failure: ExecFailure) -> Self {
        Self {
            machine,
            status: TargetStatus::Failed,
            failure_class: Some(failure.class),
            diagnostic: Some(failure.diagnostic),
            dispatched: failure.dispatched,
            remote_status: failure.remote_status,
            remote_signal: failure.remote_signal,
            possible_staging_residue: failure.possible_staging_residue,
            diagnostic_in_report: failure.diagnostic_in_report,
            stdout: failure.stdout,
            stderr: failure.stderr,
        }
    }

    fn single_status(&self) -> i32 {
        if self.status == TargetStatus::Success {
            return 0;
        }
        if self.dispatched {
            if self.failure_class == Some(FailureClass::Configuration)
                && self.remote_status == Some(125)
            {
                return 1;
            }
            if let Some(status) = self.remote_status {
                return status;
            }
            if let Some(signal) = &self.remote_signal {
                return signal_status(&signal.name).unwrap_or(1);
            }
        }
        1
    }
}

#[derive(Debug)]
pub struct ExecRunError {
    class: FailureClass,
    diagnostic: String,
}

impl ExecRunError {
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

impl std::fmt::Display for ExecRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for ExecRunError {}

#[derive(Debug, Clone)]
pub struct ExecTarget {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub target_alias: String,
    pub canonical_profile: String,
    pub canonical_user: String,
    pub privilege_profile: Option<String>,
    pub vars: BTreeMap<String, String>,
    pub timeouts: EffectiveTimeouts,
    pub route: ExecRoute,
}

#[derive(Debug, Clone)]
pub enum ExecRoute {
    Direct,
    ViaJump(ExecJump),
}

#[derive(Debug, Clone)]
pub struct ExecJump {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub alias: String,
    pub auth_profile: String,
}

pub type SharedStream = Arc<Mutex<dyn Write + Send>>;

#[derive(Clone)]
pub struct LiveStreams {
    stdout: SharedStream,
    stderr: SharedStream,
}

impl fmt::Debug for LiveStreams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveStreams")
            .finish_non_exhaustive()
    }
}

impl LiveStreams {
    fn from_std_streams() -> Result<Self, ExecFailure> {
        let stdout =
            stream_writer(std::io::stdout().as_fd().try_clone_to_owned()).map_err(|error| {
                ExecFailure::new(
                    FailureClass::CapabilityUnsupported,
                    format!("cannot duplicate local stdout for live output: {error}"),
                )
            })?;
        let stderr =
            stream_writer(std::io::stderr().as_fd().try_clone_to_owned()).map_err(|error| {
                ExecFailure::new(
                    FailureClass::CapabilityUnsupported,
                    format!("cannot duplicate local stderr for live output: {error}"),
                )
            })?;
        Ok(Self { stdout, stderr })
    }
}

fn stream_writer(dup: std::io::Result<OwnedFd>) -> std::io::Result<SharedStream> {
    match dup {
        Ok(fd) => Ok(Arc::new(Mutex::new(File::from(fd)))),
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::BADF.raw_os_error()) => {
            Ok(Arc::new(Mutex::new(std::io::sink())))
        }
        Err(error) => Err(error),
    }
}

#[derive(Debug, Clone)]
pub struct TargetExecOptions {
    pub command: Arc<ExecCommand>,
    pub stdin: StaticStdin,
    pub forward_stdin: bool,
    pub live_streams: Option<LiveStreams>,
    pub pty: bool,
    pub local_terminal: LocalTerminal,
    pub privilege: Option<String>,
    pub dispatch_timeout_seconds: Option<u64>,
    pub cancel: CancellationToken,
}

impl TargetExecOptions {
    pub fn live_output(&self) -> bool {
        self.live_streams.is_some()
    }
}

pub trait ExecBackend: Clone + Send + Sync + 'static {
    fn exec_target(
        &self,
        target: ExecTarget,
        options: TargetExecOptions,
    ) -> Pin<Box<dyn Future<Output = ExecTargetResult> + Send>>;
}

#[derive(Clone)]
pub struct RusshExecBackend {
    store: KnownHostsStore,
    auth_context: AuthContext,
    privilege_context: PrivilegeContext,
}

impl RusshExecBackend {
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

    pub fn privilege_password_pacing(&self, name: &str) -> Option<bool> {
        self.privilege_context.privilege_password_pacing(name)
    }
}

impl ExecBackend for RusshExecBackend {
    fn exec_target(
        &self,
        target: ExecTarget,
        options: TargetExecOptions,
    ) -> Pin<Box<dyn Future<Output = ExecTargetResult> + Send>> {
        let backend = self.clone();
        Box::pin(async move { backend.exec_real_target(target, options).await })
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

    pub fn with_non_interactive(mut self, non_interactive: bool) -> Self {
        self.secret_context = self.secret_context.with_non_interactive(non_interactive);
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
        Self {
            secret_context: crate::secret::SecretContext::new(
                project.broil_root.clone(),
                env_snapshot.to_vec(),
                secret_providers,
            ),
            privilege_profiles,
        }
    }

    pub fn privilege_password_pacing(&self, name: &str) -> Option<bool> {
        let profile = self.privilege_profiles.get(name)?;
        let secret = profile.password.as_ref()?;
        Some(self.secret_context.provider_is_human_paced(&secret.secret))
    }

    fn profile(&self, name: &str) -> Result<&PrivilegeProfile, ExecFailure> {
        self.privilege_profiles.get(name).ok_or_else(|| {
            ExecFailure::new(
                FailureClass::Configuration,
                format!("unknown privilege profile {name}"),
            )
        })
    }

    async fn sudo_password_input(
        &self,
        profile: &PrivilegeProfile,
        cancel: &CancellationToken,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, ExecFailure> {
        let Some(secret) = &profile.password else {
            return Ok(None);
        };
        let password = self
            .secret_context
            .resolve_owned_cancellable(&secret.secret, cancel)
            .await
            .map_err(|error| {
                ExecFailure::new(
                    error.class(),
                    format!("sudo password secret {} unavailable", secret.secret),
                )
            })?;
        let input = crate::sudo::sudo_password_input(&password)
            .map_err(|error| ExecFailure::new(error.class(), error.to_string()))?;
        Ok(Some(input))
    }
}

pub fn run<B: ExecBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &ExecOptions,
    backend: B,
) -> Result<ExecOutcome, ExecRunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            ExecRunError::new(
                FailureClass::CapabilityUnsupported,
                format!("cannot initialize remote exec runtime: {error}"),
            )
        })?;
    runtime.block_on(run_async(root, inventory, selected, options, backend))
}

async fn run_async<B: ExecBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &ExecOptions,
    backend: B,
) -> Result<ExecOutcome, ExecRunError> {
    let started = now_millis();
    if options.pty == PtyMode::Force && selected.len() != 1 {
        return Err(ExecRunError::new(
            FailureClass::Selector,
            "remote exec --pty requires exactly one target",
        ));
    }
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
    let single_target = targets.len() == 1;
    let pty = resolve_pty(options.pty, targets.len(), &options.local_terminal);
    let live_streams = single_target
        .then(LiveStreams::from_std_streams)
        .transpose()
        .map_err(|failure| ExecRunError::new(failure.class, failure.diagnostic))?;
    let cancel = CancellationToken::default();
    let interrupt_task = spawn_interrupt_watcher(cancel.clone());
    let target_options = TargetExecOptions {
        command: Arc::new(options.command.clone()),
        stdin: StaticStdin::plain(options.stdin.clone()),
        forward_stdin: single_target && options.stdin.is_empty(),
        live_streams,
        pty,
        local_terminal: options.local_terminal.clone(),
        privilege: options.privilege.clone(),
        dispatch_timeout_seconds: None,
        cancel: cancel.clone(),
    };
    let results = scheduler::run_bounded(
        targets.into_iter().map(Some).collect(),
        jobs,
        options.fail_fast,
        cancel,
        move |target, token| {
            let backend = backend.clone();
            let mut options = target_options.clone();
            options.cancel = token;
            async move { backend.exec_target(target, options).await }
        },
        |result| result.status != TargetStatus::Success,
        move |target, class| {
            ExecTargetResult::failure(
                target.name,
                ExecFailure::new(class, "remote exec target was not scheduled"),
            )
        },
    )
    .await;
    if let Some(task) = interrupt_task {
        task.abort();
    }

    Ok(ExecOutcome {
        environment: inventory.environment.clone(),
        selected_machines,
        duration_millis: now_millis().saturating_sub(started),
        results,
    })
}

pub async fn run_argv(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &EffectiveMachine,
    argv: Vec<Vec<u8>>,
    backend: RusshExecBackend,
    timeout_seconds: u64,
    cancel: CancellationToken,
) -> Result<ExecTargetResult, ExecRunError> {
    let target = plan_targets(root, inventory, &[machine])?
        .pop()
        .ok_or_else(|| ExecRunError::new(FailureClass::Configuration, "no target"))?;
    let options = TargetExecOptions {
        command: Arc::new(ExecCommand::Argv(argv)),
        stdin: StaticStdin::empty(),
        forward_stdin: false,
        live_streams: None,
        pty: false,
        local_terminal: LocalTerminal::default(),
        privilege: None,
        dispatch_timeout_seconds: Some(timeout_seconds),
        cancel,
    };
    Ok(backend.exec_target(target, options).await)
}

pub fn run_script<B: ExecBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &RunScriptOptions,
    backend: B,
) -> Result<ExecOutcome, ExecRunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            ExecRunError::new(
                FailureClass::CapabilityUnsupported,
                format!("cannot initialize remote run runtime: {error}"),
            )
        })?;
    runtime.block_on(run_script_async(
        root, inventory, selected, options, backend,
    ))
}

async fn run_script_async<B: ExecBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &RunScriptOptions,
    backend: B,
) -> Result<ExecOutcome, ExecRunError> {
    let started = now_millis();
    let selected_machines = selected
        .iter()
        .map(|target| target.name.clone())
        .collect::<Vec<_>>();
    let script_name = match String::from_utf8(options.script.clone()) {
        Ok(name) => name,
        Err(_) => {
            return Ok(finished_outcome(
                inventory,
                selected_machines,
                started,
                selected
                    .iter()
                    .map(|machine| {
                        config_result(
                            machine.name.clone(),
                            "remote script name is not valid UTF-8",
                        )
                    })
                    .collect(),
            ));
        }
    };
    let Some(script) = inventory.scripts.get(&script_name) else {
        return Ok(finished_outcome(
            inventory,
            selected_machines,
            started,
            selected
                .iter()
                .map(|machine| {
                    config_result(
                        machine.name.clone(),
                        format!("unknown remote script {script_name}"),
                    )
                })
                .collect(),
        ));
    };
    if script.pty == ScriptPtyMode::Always && selected.len() != 1 {
        return Ok(finished_outcome(
            inventory,
            selected_machines,
            started,
            selected
                .iter()
                .map(|machine| {
                    config_result(
                        machine.name.clone(),
                        "remote script requires a PTY and selected multiple targets",
                    )
                })
                .collect(),
        ));
    }
    if script.pty == ScriptPtyMode::Auto && options.pty == PtyMode::Force && selected.len() != 1 {
        return Err(ExecRunError::new(
            FailureClass::Selector,
            "remote run --pty requires exactly one target",
        ));
    }

    let targets = plan_targets(root, inventory, selected)?;
    let jobs = resolve_jobs(
        options.jobs,
        &inventory.operations_parallelism,
        targets.len(),
    );
    let single_target = targets.len() == 1;
    let items = targets
        .into_iter()
        .map(|target| {
            plan_script_work_item(
                inventory,
                target,
                script,
                options,
                single_target,
                selected.len(),
            )
        })
        .collect::<Vec<_>>();

    let cancel = CancellationToken::default();
    let interrupt_task = spawn_interrupt_watcher(cancel.clone());
    let results = scheduler::run_bounded(
        items.into_iter().map(Some).collect(),
        jobs,
        options.fail_fast,
        cancel,
        move |item, token| {
            let backend = backend.clone();
            async move {
                match item {
                    ScriptWorkItem::Ready(result) => result,
                    ScriptWorkItem::Dispatch(target, mut options) => {
                        options.cancel = token;
                        backend.exec_target(*target, options).await
                    }
                }
            }
        },
        |result| result.status != TargetStatus::Success,
        move |item, class| match item {
            ScriptWorkItem::Ready(result) => result,
            ScriptWorkItem::Dispatch(target, _) => {
                let target = *target;
                unscheduled_result(target.name, class, "remote run target was not scheduled")
            }
        },
    )
    .await;
    if let Some(task) = interrupt_task {
        task.abort();
    }

    Ok(finished_outcome(
        inventory,
        selected_machines,
        started,
        results,
    ))
}

fn finished_outcome(
    inventory: &EffectiveInventory,
    selected_machines: Vec<String>,
    started: u128,
    results: Vec<ExecTargetResult>,
) -> ExecOutcome {
    ExecOutcome {
        environment: inventory.environment.clone(),
        selected_machines,
        duration_millis: now_millis().saturating_sub(started),
        results,
    }
}

enum ScriptWorkItem {
    Dispatch(Box<ExecTarget>, TargetExecOptions),
    Ready(ExecTargetResult),
}

fn plan_script_work_item(
    inventory: &EffectiveInventory,
    target: ExecTarget,
    script: &crate::EffectiveRemoteScript,
    options: &RunScriptOptions,
    single_target: bool,
    target_count: usize,
) -> ScriptWorkItem {
    let pty = match resolve_script_pty(script.pty, options, target_count) {
        Ok(pty) => pty,
        Err(diagnostic) => return ScriptWorkItem::Ready(config_result(target.name, diagnostic)),
    };
    let context = RemoteScriptContext::from_inventory(inventory);
    let command = match prepare_script_command(&context, &target, script, &options.args) {
        Ok(command) => command,
        Err(failure) => {
            return ScriptWorkItem::Ready(ExecTargetResult::failure(target.name, failure));
        }
    };
    let dispatch_timeout_seconds = script
        .timeout
        .as_ref()
        .map(|timeout| timeout.seconds)
        .or(Some(target.timeouts.command.seconds));
    let privilege = script.privilege.clone();
    let live_streams = match single_target
        .then(LiveStreams::from_std_streams)
        .transpose()
    {
        Ok(live_streams) => live_streams,
        Err(failure) => {
            return ScriptWorkItem::Ready(ExecTargetResult::failure(target.name, failure));
        }
    };
    ScriptWorkItem::Dispatch(
        Box::new(target),
        TargetExecOptions {
            command: Arc::new(ExecCommand::Script(command)),
            stdin: StaticStdin::plain(options.stdin.clone()),
            forward_stdin: single_target && options.stdin.is_empty(),
            live_streams,
            pty,
            local_terminal: options.local_terminal.clone(),
            privilege,
            dispatch_timeout_seconds,
            cancel: CancellationToken::default(),
        },
    )
}

fn resolve_script_pty(
    policy: ScriptPtyMode,
    options: &RunScriptOptions,
    target_count: usize,
) -> Result<bool, String> {
    match policy {
        ScriptPtyMode::Always => {
            if target_count != 1 {
                Err("remote script requires a PTY and selected multiple targets".to_string())
            } else if options.pty == PtyMode::Disable {
                Err("remote script requires a PTY but --no-pty was requested".to_string())
            } else if options.pty != PtyMode::Force
                && !(options.local_terminal.stdin && options.local_terminal.stdout)
            {
                Err("remote script requires a PTY but no local terminal is available".to_string())
            } else {
                Ok(true)
            }
        }
        ScriptPtyMode::Never => {
            if options.pty == PtyMode::Force {
                Err("remote script disables PTY but --pty was requested".to_string())
            } else {
                Ok(false)
            }
        }
        ScriptPtyMode::Auto => Ok(resolve_pty(
            options.pty,
            target_count,
            &options.local_terminal,
        )),
    }
}

pub(crate) fn prepare_script_command(
    context: &RemoteScriptContext<'_>,
    target: &ExecTarget,
    script: &crate::EffectiveRemoteScript,
    args: &[Vec<u8>],
) -> Result<RemoteScriptCommand, ExecFailure> {
    let mut env = BTreeMap::new();
    for (name, source) in &script.env {
        let value = match source {
            RemoteEnvValue::Value(value) => value,
            RemoteEnvValue::FromEnv(name) => context.env_vars.get(name).ok_or_else(|| {
                ExecFailure::new(
                    FailureClass::Configuration,
                    format!("remote script env source {name} is not defined"),
                )
            })?,
            RemoteEnvValue::FromMachine(name) => target.vars.get(name).ok_or_else(|| {
                ExecFailure::new(
                    FailureClass::Configuration,
                    format!("remote script machine var {name} is not defined"),
                )
            })?,
        };
        env.insert(name.clone(), value.as_bytes().to_vec());
    }
    env.insert(
        "BROIL_ENV".to_string(),
        context.environment.as_bytes().to_vec(),
    );
    env.insert("BROIL_MACHINE".to_string(), target.name.as_bytes().to_vec());
    let body = script.body.as_bytes().to_vec();
    let interpreter = if crate::staging::body_has_shebang(&body) {
        None
    } else {
        Some(
            script
                .interpreter
                .as_deref()
                .unwrap_or(context.default_interpreter)
                .iter()
                .map(|arg| arg.as_bytes().to_vec())
                .collect(),
        )
    };
    let cwd_nonce = if script.cwd.is_some() {
        crate::path_safety::sudo_nonce().map_err(|_| {
            ExecFailure::new(
                FailureClass::CapabilityUnsupported,
                "cwd control-frame nonce generation failed",
            )
        })?
    } else {
        String::new()
    };
    Ok(RemoteScriptCommand {
        body,
        interpreter,
        cwd: script.cwd.as_ref().map(|cwd| cwd.as_bytes().to_vec()),
        cwd_display: script.cwd.clone(),
        cwd_nonce,
        env,
        args: args.to_vec(),
    })
}

fn config_result(machine: String, diagnostic: impl Into<String>) -> ExecTargetResult {
    ExecTargetResult::failure(
        machine,
        ExecFailure::new(FailureClass::Configuration, diagnostic),
    )
}

fn unscheduled_result(
    machine: String,
    class: FailureClass,
    diagnostic: impl Into<String>,
) -> ExecTargetResult {
    ExecTargetResult::failure(machine, ExecFailure::new(class, diagnostic))
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
                restore_global_raw_terminal();
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

fn resolve_pty(mode: PtyMode, target_count: usize, local_terminal: &LocalTerminal) -> bool {
    match mode {
        PtyMode::Auto => target_count == 1 && local_terminal.stdin && local_terminal.stdout,
        PtyMode::Force => true,
        PtyMode::Disable => false,
    }
}

fn plan_targets(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
) -> Result<Vec<ExecTarget>, ExecRunError> {
    selected
        .iter()
        .map(|machine| {
            let route = if machine.route == "direct" {
                ExecRoute::Direct
            } else {
                let jump = inventory
                    .jumps
                    .iter()
                    .find(|jump| jump.name == machine.route)
                    .ok_or_else(|| {
                        ExecRunError::new(
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
                ExecRoute::ViaJump(ExecJump {
                    name: jump.name.clone(),
                    address: jump.address.clone(),
                    port: jump.port,
                    alias,
                    auth_profile: jump.auth_profile.clone(),
                })
            };
            Ok(ExecTarget {
                name: machine.name.clone(),
                address: machine.address.clone(),
                port: machine.port,
                target_alias: target_alias(root, &inventory.environment, &machine.name),
                canonical_profile: machine.canonical_profile.clone(),
                canonical_user: machine.canonical_user.clone(),
                privilege_profile: machine.privilege_profile.clone(),
                vars: machine.vars.clone(),
                timeouts: machine.timeouts.clone(),
                route,
            })
        })
        .collect()
}

impl RusshExecBackend {
    pub(crate) async fn exec_authenticated_target(
        &self,
        session: &mut client::Handle<StrictHandler>,
        target: &ExecTarget,
        options: &TargetExecOptions,
    ) -> ExecTargetResult {
        let command_timeout = Duration::from_secs(target.timeouts.command.seconds);
        let dispatch_timeout = Duration::from_secs(
            options
                .dispatch_timeout_seconds
                .unwrap_or(target.timeouts.command.seconds),
        );
        target_result_from_execution(
            target,
            self.exec_authenticated_target_inner(
                session,
                target,
                options,
                command_timeout,
                dispatch_timeout,
            )
            .await,
        )
    }

    async fn exec_real_target(
        &self,
        target: ExecTarget,
        options: TargetExecOptions,
    ) -> ExecTargetResult {
        let command_timeout = Duration::from_secs(target.timeouts.command.seconds);
        let dispatch_timeout = Duration::from_secs(
            options
                .dispatch_timeout_seconds
                .unwrap_or(target.timeouts.command.seconds),
        );
        target_result_from_execution(
            &target,
            self.exec_real_target_inner(&target, &options, command_timeout, dispatch_timeout)
                .await,
        )
    }

    async fn exec_real_target_inner(
        &self,
        target: &ExecTarget,
        options: &TargetExecOptions,
        helper_timeout: Duration,
        dispatch_timeout: Duration,
    ) -> Result<(RemoteCommand, bool), ExecFailure> {
        let mut session = self.connect_and_authenticate(target, options).await?;
        self.exec_authenticated_target_inner(
            &mut session,
            target,
            options,
            helper_timeout,
            dispatch_timeout,
        )
        .await
    }

    async fn exec_authenticated_target_inner(
        &self,
        session: &mut client::Handle<StrictHandler>,
        target: &ExecTarget,
        options: &TargetExecOptions,
        helper_timeout: Duration,
        dispatch_timeout: Duration,
    ) -> Result<(RemoteCommand, bool), ExecFailure> {
        if options.cancel.is_cancelled() {
            return Err(cancellation_failure());
        }

        let mut sudo = None;
        if let Some(profile_name) = effective_privilege(target, options)? {
            sudo = Some(
                self.prepare_sudo(session, &profile_name, helper_timeout, &options.cancel)
                    .await?,
            );
        }

        let (launcher_payload, body_payload, body_executable, cwd_frame) = match &*options.command {
            ExecCommand::Argv(argv) => (crate::staging::launcher_for_argv(argv), None, false, None),
            ExecCommand::Shell(body) => {
                (crate::staging::launcher_for_shell(body), None, false, None)
            }
            ExecCommand::Script(command) => {
                let command = script_command_with_distinct_cwd_nonce(
                    command,
                    sudo.as_ref().map(|sudo| sudo.nonce.as_str()),
                )?;
                let body_has_shebang = crate::staging::body_has_shebang(&command.body);
                (
                    crate::staging::launcher_for_script(
                        body_has_shebang,
                        command.interpreter.as_deref(),
                        command.cwd.as_deref(),
                        &command.cwd_nonce,
                        &command.env,
                        &command.args,
                    ),
                    Some(command.body.clone()),
                    body_has_shebang,
                    command.cwd_display.clone().map(|cwd| CwdFrameExpectation {
                        nonce: command.cwd_nonce.clone(),
                        cwd,
                    }),
                )
            }
        };
        let sidecar = sudo
            .as_ref()
            .map(|sudo| sudo.control_frame_contents.as_slice());
        let staged = self
            .stage_launcher(
                session,
                &launcher_payload,
                body_payload.as_deref(),
                sidecar,
                helper_timeout,
            )
            .await?;

        let launcher_argv = vec![staged.launcher.clone()];
        let dispatch = if let Some(sudo) = sudo.as_mut() {
            match sudo
                .finalize(&self.privilege_context, &launcher_argv, &options.cancel)
                .await
            {
                Ok(dispatch) => dispatch,
                Err(error) => {
                    return Err(cleanup_staging_or_residue(
                        session,
                        &staged.launcher,
                        helper_timeout,
                        error,
                    )
                    .await);
                }
            }
        } else {
            DispatchCommand {
                command: crate::staging::shell_join(&launcher_argv),
                password_stdin: None,
                sudo_nonce: None,
            }
        };

        if let Err(error) = self
            .make_launcher_executable(session, &staged.launcher, helper_timeout)
            .await
        {
            return Err(cleanup_staging_or_residue(
                session,
                &staged.launcher,
                helper_timeout,
                error,
            )
            .await);
        }
        if options.cancel.is_cancelled() {
            let failure = cancellation_failure();
            return Err(cleanup_staging_or_residue(
                session,
                &staged.launcher,
                helper_timeout,
                failure,
            )
            .await);
        }
        if body_executable {
            let Some(body) = staged.body.as_deref() else {
                return Err(cleanup_staging_or_residue(
                    session,
                    &staged.launcher,
                    helper_timeout,
                    ExecFailure::new(
                        FailureClass::TransferPathSafety,
                        "remote run script body staging path was not returned",
                    ),
                )
                .await);
            };
            if let Err(error) = self
                .make_script_body_executable(session, body, helper_timeout)
                .await
            {
                return Err(cleanup_staging_or_residue(
                    session,
                    &staged.launcher,
                    helper_timeout,
                    error,
                )
                .await);
            }
        }

        let DispatchCommand {
            command,
            password_stdin,
            sudo_nonce,
        } = dispatch;
        let command = run_user_launcher(
            session,
            UserLauncherRequest {
                command: &command,
                password_stdin,
                sudo_nonce: sudo_nonce.as_deref(),
                stdin: &options.stdin,
                forward_stdin: options.forward_stdin,
                live_streams: options.live_streams.clone(),
                pty: options.pty,
                local_terminal: &options.local_terminal,
                timeout: dispatch_timeout,
                cancel: &options.cancel,
                cwd_frame: cwd_frame.as_ref(),
            },
        )
        .await;
        let mut residue = true;
        let command = match command {
            Ok(command) => command,
            Err(error) => {
                return Err(cleanup_staging_or_residue(
                    session,
                    &staged.launcher,
                    helper_timeout,
                    error,
                )
                .await);
            }
        };
        if cleanup_staging(session, &staged.launcher, helper_timeout)
            .await
            .is_ok()
        {
            residue = false;
        }
        Ok((command, residue))
    }

    async fn connect_and_authenticate(
        &self,
        target: &ExecTarget,
        options: &TargetExecOptions,
    ) -> Result<client::Handle<StrictHandler>, ExecFailure> {
        self.connect_bound(target, options, None).await
    }

    async fn connect_bound(
        &self,
        target: &ExecTarget,
        options: &TargetExecOptions,
        pins: Option<&private::VerifiedKeys>,
    ) -> Result<client::Handle<StrictHandler>, ExecFailure> {
        let (endpoint, endpoint_port) = route_endpoint(target);
        let connect_timeout = Duration::from_secs(target.timeouts.connect.seconds);
        let connect_deadline = tokio::time::Instant::now() + connect_timeout;
        let addresses = cancellable(
            &options.cancel,
            resolve_dns(endpoint, endpoint_port, connect_deadline),
        )
        .await?;
        let stream = cancellable(
            &options.cancel,
            connect_addresses(&addresses, endpoint, endpoint_port, connect_deadline),
        )
        .await?;
        let mut session = match &target.route {
            ExecRoute::Direct => {
                let expected = match pins {
                    Some(pins) => pins.target.clone(),
                    None => self.pinned_key(&target.target_alias, FailureClass::UnknownHostKey)?,
                };
                cancellable(
                    &options.cancel,
                    connect_strict(stream, expected, connect_deadline),
                )
                .await
                .map_err(strict_target_trust_failure)?
            }
            ExecRoute::ViaJump(jump) => {
                let expected = match pins {
                    Some(pins) => pins.jump.clone().ok_or_else(|| {
                        ExecFailure::new(FailureClass::Configuration, "private jump pin is missing")
                    })?,
                    None => self.pinned_key(&jump.alias, FailureClass::UnknownHostKey)?,
                };
                let mut jump_session = cancellable(
                    &options.cancel,
                    connect_strict(stream, expected, connect_deadline),
                )
                .await
                .map_err(|error| strict_jump_trust_failure(&jump.name, error))?;
                cancellable(&options.cancel, async {
                    timeout_at(
                        connect_deadline,
                        auth::authenticate_profile_cancellable(
                            &mut jump_session,
                            &self.auth_context,
                            &jump.auth_profile,
                            &options.cancel,
                        ),
                        FailureClass::JumpFailure,
                        "jump authentication timed out",
                    )
                    .await?
                    .map_err(|error| {
                        let error = error.into_jump_failure(&jump.name);
                        ExecFailure::new(error.class(), error.to_string())
                    })
                })
                .await?;
                let channel = cancellable(&options.cancel, async {
                    tokio::time::timeout_at(
                        connect_deadline,
                        jump_session.channel_open_direct_tcpip(
                            target.address.clone(),
                            u32::from(target.port),
                            "127.0.0.1",
                            0,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        ExecFailure::new(
                            FailureClass::JumpFailure,
                            format!(
                                "jump host {} timed out opening target channel to {}:{}",
                                jump.name, target.address, target.port
                            ),
                        )
                    })?
                    .map_err(|error| {
                        ExecFailure::new(
                            FailureClass::JumpFailure,
                            format!(
                                "jump host {} could not open target channel to {}:{}: {error}",
                                jump.name, target.address, target.port
                            ),
                        )
                    })
                })
                .await?;
                let expected = match pins {
                    Some(pins) => pins.target.clone(),
                    None => self.pinned_key(&target.target_alias, FailureClass::UnknownHostKey)?,
                };
                cancellable(
                    &options.cancel,
                    connect_strict(channel.into_stream(), expected, connect_deadline),
                )
                .await
                .map_err(strict_target_trust_failure)?
            }
        };
        if options.cancel.is_cancelled() {
            return Err(cancellation_failure());
        }
        cancellable(&options.cancel, async {
            timeout(
                Duration::from_secs(target.timeouts.command.seconds),
                auth::authenticate_profile_cancellable(
                    &mut session,
                    &self.auth_context,
                    &target.canonical_profile,
                    &options.cancel,
                ),
                FailureClass::Protocol,
                "canonical authentication timed out",
            )
            .await?
            .map_err(|error| ExecFailure::new(error.class(), error.to_string()))
        })
        .await?;
        Ok(session)
    }

    fn pinned_key(&self, alias: &str, unknown_class: FailureClass) -> Result<HostKey, ExecFailure> {
        match self
            .store
            .snapshot()
            .and_then(|snapshot| snapshot.inspect(alias, false))
        {
            Ok(AliasState::Pinned(key)) => Ok(key),
            Ok(AliasState::Unknown) => Err(ExecFailure::new(
                unknown_class,
                "host key is not pinned in the Broil known-hosts store",
            )),
            Ok(AliasState::Replaceable { .. }) => Err(ExecFailure::new(
                FailureClass::Configuration,
                "known-hosts state requires replacement before read-only verification",
            )),
            Err(error) => Err(store_failure(error)),
        }
    }

    async fn prepare_sudo(
        &self,
        session: &mut client::Handle<StrictHandler>,
        profile_name: &str,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<PendingSudo, ExecFailure> {
        let profile = self.privilege_context.profile(profile_name)?.clone();
        let preflight = crate::staging::shell_join(&crate::sudo::sudo_preflight_argv());
        let result =
            run_helper_command(session, &preflight, None, timeout, false, false, cancel).await?;
        match classify_sudo_preflight(result, profile.password.is_some())? {
            SudoMode::Passwordless => Ok(PendingSudo::passwordless()?),
            SudoMode::Password => Ok(PendingSudo::password(profile)?),
        }
    }

    async fn stage_launcher(
        &self,
        session: &mut client::Handle<StrictHandler>,
        launcher: &[u8],
        body: Option<&[u8]>,
        sidecar: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<crate::staging::StagedLauncher, ExecFailure> {
        let input = crate::staging::staging_input(launcher, body, sidecar);
        let result = run_helper_command(
            session,
            &crate::staging::receiver_command(),
            Some(input),
            timeout,
            true,
            false,
            &CancellationToken::default(),
        )
        .await
        .map_err(|failure| failure.residue())?;
        crate::staging::classify_receiver_status(
            result.status,
            &result.stdout,
            body.is_some(),
            sidecar.is_some(),
        )
        .map_err(ExecFailure::from_staging)
    }

    async fn make_launcher_executable(
        &self,
        session: &mut client::Handle<StrictHandler>,
        launcher: &str,
        timeout: Duration,
    ) -> Result<(), ExecFailure> {
        let command = crate::staging::make_launcher_executable_command(launcher)
            .map_err(ExecFailure::from_staging)?;
        let result = run_helper_command(
            session,
            &command,
            None,
            timeout,
            false,
            false,
            &CancellationToken::default(),
        )
        .await
        .map_err(|failure| failure.residue())?;
        if result.status == Some(0) {
            Ok(())
        } else {
            Err(ExecFailure::new(
                FailureClass::TransferPathSafety,
                "remote exec launcher chmod did not complete",
            )
            .residue())
        }
    }

    async fn make_script_body_executable(
        &self,
        session: &mut client::Handle<StrictHandler>,
        body: &str,
        timeout: Duration,
    ) -> Result<(), ExecFailure> {
        let command = crate::staging::make_script_body_executable_command(body)
            .map_err(ExecFailure::from_staging)?;
        let result = run_helper_command(
            session,
            &command,
            None,
            timeout,
            false,
            false,
            &CancellationToken::default(),
        )
        .await
        .map_err(|failure| failure.residue())?;
        if result.status == Some(0) {
            Ok(())
        } else {
            Err(ExecFailure::new(
                FailureClass::TransferPathSafety,
                "remote run script body chmod did not complete",
            )
            .residue())
        }
    }
}

fn target_result_from_execution(
    target: &ExecTarget,
    execution: Result<(RemoteCommand, bool), ExecFailure>,
) -> ExecTargetResult {
    match execution {
        Ok((command, residue))
            if command.cwd_frame.is_some()
                && command.status == Some(125)
                && command.signal.is_none() =>
        {
            let cwd = command.cwd_frame.clone().unwrap_or_default();
            let failure = ExecFailure::new(
                FailureClass::Configuration,
                format!("remote cwd {cwd} could not be entered"),
            )
            .omit_diagnostic_from_report()
            .dispatched()
            .remote_result(command.status, command.signal)
            .streams(command.stdout, command.stderr)
            .residue_if(residue);
            ExecTargetResult::failure(target.name.clone(), failure)
        }
        Ok((command, residue)) if command.status == Some(0) && command.signal.is_none() => {
            ExecTargetResult::success(target.name.clone(), command, residue)
        }
        Ok((command, residue)) if command.status.is_none() && command.signal.is_none() => {
            let failure = ExecFailure::new(
                FailureClass::IndeterminateAfterDispatch,
                "remote command ended without a numeric status",
            )
            .dispatched()
            .streams(command.stdout, command.stderr)
            .residue_if(residue);
            ExecTargetResult::failure(target.name.clone(), failure)
        }
        Ok((command, residue)) => {
            let failure = ExecFailure::new(FailureClass::RemoteNonzero, "remote command failed")
                .dispatched()
                .remote_result(command.status, command.signal)
                .streams(command.stdout, command.stderr)
                .residue_if(residue);
            ExecTargetResult::failure(target.name.clone(), failure)
        }
        Err(failure) => ExecTargetResult::failure(target.name.clone(), failure),
    }
}

fn effective_privilege(
    target: &ExecTarget,
    options: &TargetExecOptions,
) -> Result<Option<String>, ExecFailure> {
    let _ = target;
    Ok(options.privilege.clone())
}

struct PendingSudo {
    mode: PendingSudoMode,
    control_frame_contents: Zeroizing<Vec<u8>>,
    nonce: String,
}

enum PendingSudoMode {
    Passwordless,
    Password(PrivilegeProfile),
}

struct DispatchCommand {
    command: String,
    password_stdin: Option<Zeroizing<Vec<u8>>>,
    sudo_nonce: Option<String>,
}

#[derive(Clone)]
struct CwdFrameExpectation {
    nonce: String,
    cwd: String,
}

fn script_command_with_distinct_cwd_nonce(
    command: &RemoteScriptCommand,
    sudo_nonce: Option<&str>,
) -> Result<RemoteScriptCommand, ExecFailure> {
    if command.cwd.is_none() || Some(command.cwd_nonce.as_str()) != sudo_nonce {
        return Ok(command.clone());
    }
    let mut command = command.clone();
    loop {
        let nonce = crate::path_safety::sudo_nonce().map_err(|_| {
            ExecFailure::new(
                FailureClass::CapabilityUnsupported,
                "cwd control-frame nonce generation failed",
            )
        })?;
        if Some(nonce.as_str()) != sudo_nonce {
            command.cwd_nonce = nonce;
            return Ok(command);
        }
    }
}

impl PendingSudo {
    fn passwordless() -> Result<Self, ExecFailure> {
        let nonce = crate::path_safety::sudo_nonce()
            .map_err(|_| ExecFailure::new(FailureClass::Sudo, "sudo nonce generation failed"))?;
        let control_frame_contents = sudo_control_frame_contents(&nonce)?;
        Ok(Self {
            mode: PendingSudoMode::Passwordless,
            control_frame_contents,
            nonce,
        })
    }

    fn password(profile: PrivilegeProfile) -> Result<Self, ExecFailure> {
        let nonce = crate::path_safety::sudo_nonce()
            .map_err(|_| ExecFailure::new(FailureClass::Sudo, "sudo nonce generation failed"))?;
        let control_frame_contents = sudo_control_frame_contents(&nonce)?;
        Ok(Self {
            mode: PendingSudoMode::Password(profile),
            control_frame_contents,
            nonce,
        })
    }

    async fn finalize(
        &self,
        privilege_context: &PrivilegeContext,
        launcher_argv: &[String],
        cancel: &CancellationToken,
    ) -> Result<DispatchCommand, ExecFailure> {
        match &self.mode {
            PendingSudoMode::Passwordless => {
                let argv = crate::sudo::passwordless_sudo_argv(launcher_argv, &self.nonce)
                    .map_err(|error| ExecFailure::new(error.class(), error.to_string()))?;
                Ok(DispatchCommand {
                    command: crate::staging::shell_join(&argv),
                    password_stdin: None,
                    sudo_nonce: Some(self.nonce.clone()),
                })
            }
            PendingSudoMode::Password(profile) => {
                let argv = crate::sudo::password_sudo_argv(launcher_argv, &self.nonce)
                    .map_err(|error| ExecFailure::new(error.class(), error.to_string()))?;
                Ok(DispatchCommand {
                    command: crate::staging::shell_join(&argv),
                    password_stdin: privilege_context
                        .sudo_password_input(profile, cancel)
                        .await?,
                    sudo_nonce: Some(self.nonce.clone()),
                })
            }
        }
    }
}

fn sudo_control_frame_contents(nonce: &str) -> Result<Zeroizing<Vec<u8>>, ExecFailure> {
    let mut frame = Zeroizing::new(Vec::with_capacity("BROIL-SUDO:".len() + nonce.len() + 1));
    if nonce.is_empty() || !nonce.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ExecFailure::new(
            FailureClass::Sudo,
            "sudo nonce is invalid",
        ));
    }
    frame.extend_from_slice(b"BROIL-SUDO:");
    frame.extend_from_slice(nonce.as_bytes());
    frame.push(b'\n');
    Ok(frame)
}

enum SudoMode {
    Passwordless,
    Password,
}

fn classify_sudo_preflight(
    result: RemoteCommand,
    has_password: bool,
) -> Result<SudoMode, ExecFailure> {
    match result.status {
        Some(0) => Ok(SudoMode::Passwordless),
        Some(126 | 127) => Err(ExecFailure::new(
            FailureClass::Sudo,
            "sudo preflight command was not executable or was not found",
        )),
        Some(_) if has_password => Ok(SudoMode::Password),
        Some(_) => Err(ExecFailure::new(
            FailureClass::Sudo,
            "passwordless sudo preflight did not succeed",
        )),
        None => Err(ExecFailure::new(
            FailureClass::Protocol,
            "sudo preflight ended without a numeric status",
        )),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExecFailure {
    pub(crate) class: FailureClass,
    pub(crate) diagnostic: String,
    pub(crate) diagnostic_in_report: bool,
    pub(crate) dispatched: bool,
    pub(crate) remote_status: Option<i32>,
    pub(crate) remote_signal: Option<RemoteSignal>,
    pub(crate) possible_staging_residue: bool,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl ExecFailure {
    fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
            dispatched: false,
            remote_status: None,
            remote_signal: None,
            possible_staging_residue: false,
            diagnostic_in_report: true,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn from_staging(failure: crate::staging::StagingFailure) -> Self {
        Self::new(failure.class, failure.diagnostic).residue_if(failure.possible_staging_residue)
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

    fn streams(mut self, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        self.stdout = stdout;
        self.stderr = stderr;
        self
    }

    fn residue(mut self) -> Self {
        self.possible_staging_residue = true;
        self
    }

    fn clear_residue(mut self) -> Self {
        self.possible_staging_residue = false;
        self
    }

    fn residue_if(self, residue: bool) -> Self {
        if residue { self.residue() } else { self }
    }

    fn omit_diagnostic_from_report(mut self) -> Self {
        self.diagnostic_in_report = false;
        self
    }
}

#[derive(Debug)]
struct RemoteCommand {
    status: Option<i32>,
    signal: Option<RemoteSignal>,
    cwd_frame: Option<String>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct CommandInput {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
}

impl CommandInput {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes, position: 0 }
    }
}

impl AsyncRead for CommandInput {
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

type StdinChunk = Result<Vec<u8>, String>;

fn spawn_stdin_reader() -> tokio::sync::mpsc::UnboundedReceiver<StdinChunk> {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut input = [0_u8; 8192];
        loop {
            match stdin.read(&mut input) {
                Ok(0) => {
                    let _ = sender.send(Ok(Vec::new()));
                    break;
                }
                Ok(read) => {
                    if sender.send(Ok(input[..read].to_vec())).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(format!("cannot read local stdin: {error}")));
                    break;
                }
            }
        }
    });
    receiver
}

async fn next_stdin_chunk(
    receiver: &mut Option<tokio::sync::mpsc::UnboundedReceiver<StdinChunk>>,
) -> Option<StdinChunk> {
    if let Some(receiver) = receiver {
        receiver.recv().await
    } else {
        std::future::pending().await
    }
}

async fn run_helper_command(
    session: &mut client::Handle<StrictHandler>,
    command: &str,
    stdin: Option<Zeroizing<Vec<u8>>>,
    timeout: Duration,
    capture_stdout: bool,
    capture_stderr: bool,
    cancel: &CancellationToken,
) -> Result<RemoteCommand, ExecFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    tokio::time::timeout(timeout, async move {
        let channel = session.channel_open_session().await.map_err(|error| {
            ExecFailure::new(
                FailureClass::Protocol,
                format!("cannot open SSH session channel: {error}"),
            )
        })?;
        channel
            .exec(true, command.as_bytes().to_vec())
            .await
            .map_err(|error| {
                ExecFailure::new(
                    FailureClass::Protocol,
                    format!("cannot dispatch SSH helper request: {error}"),
                )
            })?;
        if let Some(stdin) = stdin {
            channel
                .data(CommandInput::new(stdin))
                .await
                .map_err(|error| {
                    ExecFailure::new(
                        FailureClass::Protocol,
                        format!("cannot write SSH helper input: {error}"),
                    )
                })?;
        }
        channel.eof().await.map_err(|error| {
            ExecFailure::new(
                FailureClass::Protocol,
                format!("cannot send SSH helper EOF: {error}"),
            )
        })?;
        collect_channel(channel, capture_stdout, capture_stderr).await
    })
    .await
    .map_err(|_| ExecFailure::new(FailureClass::Protocol, "SSH helper command timed out"))?
}

struct UserLauncherRequest<'a> {
    command: &'a str,
    password_stdin: Option<Zeroizing<Vec<u8>>>,
    sudo_nonce: Option<&'a str>,
    cwd_frame: Option<&'a CwdFrameExpectation>,
    stdin: &'a StaticStdin,
    forward_stdin: bool,
    live_streams: Option<LiveStreams>,
    pty: bool,
    local_terminal: &'a LocalTerminal,
    timeout: Duration,
    cancel: &'a CancellationToken,
}

async fn run_user_launcher(
    session: &mut client::Handle<StrictHandler>,
    request: UserLauncherRequest<'_>,
) -> Result<RemoteCommand, ExecFailure> {
    let UserLauncherRequest {
        command,
        password_stdin,
        sudo_nonce,
        cwd_frame,
        stdin,
        forward_stdin,
        live_streams,
        pty,
        local_terminal,
        timeout,
        cancel,
    } = request;
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    tokio::time::timeout(timeout, async move {
        let channel = session.channel_open_session().await.map_err(|error| {
            ExecFailure::new(
                FailureClass::Protocol,
                format!("cannot open SSH session channel: {error}"),
            )
        })?;
        if pty {
            let (columns, rows) = effective_terminal_size(local_terminal);
            channel
                .request_pty(true, &local_terminal.term, columns, rows, 0, 0, &[])
                .await
                .map_err(|error| {
                    ExecFailure::new(
                        FailureClass::Protocol,
                        format!("cannot request remote PTY: {error}"),
                    )
                })?;
        }
        channel
            .exec(true, command.as_bytes().to_vec())
            .await
            .map_err(|error| {
                ExecFailure::new(
                    FailureClass::IndeterminateAfterDispatch,
                    format!("cannot dispatch SSH exec request: {error}"),
                )
                .dispatched()
                .residue()
            })?;
        if let Some(password) = password_stdin {
            channel
                .data(CommandInput::new(password))
                .await
                .map_err(|error| {
                    ExecFailure::new(
                        FailureClass::IndeterminateAfterDispatch,
                        format!("cannot write sudo password prelude: {error}"),
                    )
                    .dispatched()
                    .residue()
                })?;
        }
        if pty {
            let frames = ChannelControlFrames {
                sudo_nonce,
                cwd_frame,
            };
            return run_pty_channel(
                channel,
                stdin,
                forward_stdin,
                local_terminal,
                cancel,
                live_streams.as_ref(),
                frames,
            )
            .await;
        }
        let frames = ChannelControlFrames {
            sudo_nonce,
            cwd_frame,
        };
        run_raw_channel(
            channel,
            stdin,
            forward_stdin,
            live_streams.as_ref(),
            cancel,
            frames,
        )
        .await
    })
    .await
    .map_err(|_| {
        ExecFailure::new(
            FailureClass::IndeterminateAfterDispatch,
            "remote command timed out after dispatch",
        )
        .dispatched()
        .residue()
    })?
}

#[derive(Clone, Copy)]
struct ChannelControlFrames<'a> {
    sudo_nonce: Option<&'a str>,
    cwd_frame: Option<&'a CwdFrameExpectation>,
}

struct ControlFrameState<'a> {
    sudo_nonce: Option<&'a str>,
    cwd_frame: Option<&'a CwdFrameExpectation>,
    pty: bool,
    sudo_consumed: bool,
    cwd_consumed: bool,
    cwd_anchor: usize,
    matched_cwd: Option<String>,
    output_released: bool,
}

impl<'a> ControlFrameState<'a> {
    fn new(frames: ChannelControlFrames<'a>, pty: bool) -> Self {
        Self {
            sudo_nonce: frames.sudo_nonce,
            cwd_frame: frames.cwd_frame,
            pty,
            sudo_consumed: frames.sudo_nonce.is_none(),
            cwd_consumed: frames.cwd_frame.is_none(),
            cwd_anchor: 0,
            matched_cwd: None,
            output_released: frames.sudo_nonce.is_none() && frames.cwd_frame.is_none(),
        }
    }

    fn stdin_ready(&self) -> bool {
        self.sudo_consumed
    }

    fn output_ready(&self) -> bool {
        self.sudo_consumed && self.cwd_consumed
    }

    fn inspect(&mut self, stdout: &mut Vec<u8>, stderr: &mut Vec<u8>) -> Result<(), ExecFailure> {
        let stream = if self.pty { stdout } else { stderr };
        if !self.sudo_consumed {
            let Some(nonce) = self.sudo_nonce else {
                self.sudo_consumed = true;
                return Ok(());
            };
            let Some(anchor) = consume_sudo_control_frame(stream, nonce, self.pty)? else {
                return Ok(());
            };
            self.cwd_anchor = anchor;
            self.sudo_consumed = true;
        }
        if !self.cwd_consumed {
            let Some(expectation) = self.cwd_frame else {
                self.cwd_consumed = true;
                return Ok(());
            };
            let anchor = self.cwd_anchor.min(stream.len());
            match cwd_control_frame_parse(&stream[anchor..], &expectation.nonce) {
                CwdControlFrameParse::Complete(payload_start) => {
                    let payload_start = anchor + payload_start;
                    let mut stripped =
                        Vec::with_capacity(anchor + stream.len().saturating_sub(payload_start));
                    stripped.extend_from_slice(&stream[..anchor]);
                    stripped.extend_from_slice(&stream[payload_start..]);
                    *stream = stripped;
                    self.matched_cwd = Some(expectation.cwd.clone());
                    self.cwd_consumed = true;
                }
                CwdControlFrameParse::Diverged => {
                    self.cwd_consumed = true;
                }
                CwdControlFrameParse::Pending => {}
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ExecFailure> {
        if !self.sudo_consumed {
            return Err(ExecFailure::new(
                FailureClass::Sudo,
                "sudo control frame was not observed",
            )
            .dispatched()
            .residue());
        }
        self.cwd_consumed = true;
        Ok(())
    }
}

fn consume_sudo_control_frame(
    stream: &mut Vec<u8>,
    nonce: &str,
    pty: bool,
) -> Result<Option<usize>, ExecFailure> {
    match crate::sudo::parse_sudo_control_frame(stream, nonce) {
        Ok(crate::sudo::SudoControlFrameParse::Complete(frame)) => {
            let anchor = if pty { 0 } else { frame.preceding.len() };
            let mut stripped = Vec::with_capacity(if pty {
                frame.payload.len()
            } else {
                frame.preceding.len() + frame.payload.len()
            });
            if !pty {
                stripped.extend_from_slice(frame.preceding);
            }
            stripped.extend_from_slice(frame.payload);
            *stream = stripped;
            Ok(Some(anchor))
        }
        Ok(crate::sudo::SudoControlFrameParse::Pending) => Ok(None),
        Err(error) => Err(ExecFailure::new(error.class(), error.to_string())
            .dispatched()
            .residue()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CwdControlFrameParse {
    Pending,
    Complete(usize),
    Diverged,
}

fn cwd_control_frame_parse(stream: &[u8], nonce: &str) -> CwdControlFrameParse {
    let mut expected = Vec::with_capacity("BROIL-RUN-CWD:".len() + nonce.len() + 2);
    expected.extend_from_slice(b"BROIL-RUN-CWD:");
    expected.extend_from_slice(nonce.as_bytes());
    expected.push(b'\n');
    let lf_expected = expected.clone();
    expected.pop();
    expected.extend_from_slice(b"\r\n");
    let crlf_expected = expected;

    if stream.starts_with(&lf_expected) {
        return CwdControlFrameParse::Complete(lf_expected.len());
    }
    if stream.starts_with(&crlf_expected) {
        return CwdControlFrameParse::Complete(crlf_expected.len());
    }
    if lf_expected.starts_with(stream) || crlf_expected.starts_with(stream) {
        CwdControlFrameParse::Pending
    } else {
        CwdControlFrameParse::Diverged
    }
}

async fn send_static_channel_stdin(
    write_half: &russh::ChannelWriteHalf<client::Msg>,
    stdin: &StaticStdin,
    stream_name: &str,
) -> Result<(), ExecFailure> {
    if let Some(stdin) = stdin.next_input()? {
        write_half
            .data(CommandInput::new(stdin))
            .await
            .map_err(|error| {
                ExecFailure::new(
                    FailureClass::IndeterminateAfterDispatch,
                    format!("cannot write {stream_name} input: {error}"),
                )
                .dispatched()
                .residue()
            })?;
    }
    write_half.eof().await.map_err(|error| {
        ExecFailure::new(
            FailureClass::IndeterminateAfterDispatch,
            format!("cannot send {stream_name} EOF: {error}"),
        )
        .dispatched()
        .residue()
    })
}

fn write_local_stream(
    streams: &LiveStreams,
    data: &[u8],
    stderr: bool,
    diagnostic: &str,
) -> Result<(), ExecFailure> {
    let stream = if stderr {
        &streams.stderr
    } else {
        &streams.stdout
    };
    let result = stream
        .lock()
        .map_err(|_| std::io::Error::other("live output writer is poisoned"))
        .and_then(|mut stream| stream.write_all(data).and_then(|_| stream.flush()));
    result.map_err(|error| {
        ExecFailure::new(
            FailureClass::IndeterminateAfterDispatch,
            format!("{diagnostic}: {error}"),
        )
        .dispatched()
        .residue()
    })
}

fn release_raw_output(
    control: &mut ControlFrameState<'_>,
    live_streams: Option<&LiveStreams>,
    stdout: &mut Vec<u8>,
    stderr: &mut Vec<u8>,
) -> Result<(), ExecFailure> {
    if control.output_released || !control.sudo_consumed {
        return Ok(());
    }
    if let Some(streams) = live_streams {
        write_local_stream(streams, stdout, false, "cannot write remote stdout")?;
        stdout.clear();
    }
    if !control.cwd_consumed {
        return Ok(());
    }
    if let Some(streams) = live_streams {
        write_local_stream(streams, stderr, true, "cannot write remote stderr")?;
        stderr.clear();
    }
    control.output_released = true;
    Ok(())
}

fn release_pty_output(
    control: &mut ControlFrameState<'_>,
    live_stdout: Option<&LiveStreams>,
    stdout: &mut Vec<u8>,
) -> Result<(), ExecFailure> {
    if control.output_released || !control.output_ready() {
        return Ok(());
    }
    if let Some(streams) = live_stdout {
        write_local_stream(streams, stdout, false, "cannot write remote PTY stdout")?;
        stdout.clear();
    }
    control.output_released = true;
    Ok(())
}

async fn run_raw_channel(
    channel: russh::Channel<client::Msg>,
    stdin: &StaticStdin,
    forward_stdin: bool,
    live_streams: Option<&LiveStreams>,
    cancel: &CancellationToken,
    frames: ChannelControlFrames<'_>,
) -> Result<RemoteCommand, ExecFailure> {
    let (mut read_half, write_half) = channel.split();
    let mut control = ControlFrameState::new(frames, false);
    let mut stdin_rx = None;
    let mut stdin_done = true;
    let mut static_stdin_sent = forward_stdin;
    if forward_stdin {
        if control.stdin_ready() {
            stdin_rx = Some(spawn_stdin_reader());
            stdin_done = false;
        }
    } else if control.stdin_ready() || stdin.is_empty() {
        send_static_channel_stdin(&write_half, stdin, "SSH channel").await?;
        static_stdin_sent = true;
    }
    let mut status = None;
    let mut signal = None;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = write_half.signal(russh::Sig::INT).await;
                tokio::time::sleep(CANCEL_CLEANUP_TIMEOUT).await;
                let _ = write_half.close().await;
                return Err(cancellation_failure().dispatched().residue());
            }
            chunk = next_stdin_chunk(&mut stdin_rx), if !stdin_done => {
                let Some(chunk) = chunk else {
                    stdin_done = true;
                    write_half.eof().await.map_err(|error| {
                        ExecFailure::new(
                            FailureClass::IndeterminateAfterDispatch,
                            format!("cannot send SSH channel EOF: {error}"),
                        )
                        .dispatched()
                        .residue()
                    })?;
                    continue;
                };
                let chunk = chunk.map_err(|error| {
                    ExecFailure::new(FailureClass::IndeterminateAfterDispatch, error)
                        .dispatched()
                        .residue()
                })?;
                if chunk.is_empty() {
                    stdin_done = true;
                    write_half.eof().await.map_err(|error| {
                        ExecFailure::new(
                            FailureClass::IndeterminateAfterDispatch,
                            format!("cannot send SSH channel EOF: {error}"),
                        )
                        .dispatched()
                        .residue()
                    })?;
                    continue;
                }
                write_half.data_bytes(chunk).await.map_err(|error| {
                    ExecFailure::new(
                        FailureClass::IndeterminateAfterDispatch,
                        format!("cannot write SSH channel input: {error}"),
                    )
                    .dispatched()
                    .residue()
                })?;
            }
            message = read_half.wait() => {
                let Some(message) = message else {
                    break;
                };
                match message {
                    ChannelMsg::Data { data } => {
                        if let Some(streams) = live_streams.filter(|_| control.output_released) {
                            write_local_stream(streams, &data, false, "cannot write remote stdout")?;
                        } else {
                            stdout.extend_from_slice(&data);
                            control.inspect(&mut stdout, &mut stderr)?;
                        }
                    }
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        if let Some(streams) = live_streams.filter(|_| control.output_released) {
                            write_local_stream(streams, &data, true, "cannot write remote stderr")?;
                        } else {
                            stderr.extend_from_slice(&data);
                            control.inspect(&mut stdout, &mut stderr)?;
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        status = Some(i32::try_from(exit_status).unwrap_or(i32::MAX));
                    }
                    ChannelMsg::ExitSignal { signal_name, .. } => {
                        signal = Some(remote_signal(signal_name));
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
                if control.stdin_ready() {
                    if forward_stdin && stdin_rx.is_none() && stdin_done {
                        stdin_rx = Some(spawn_stdin_reader());
                        stdin_done = false;
                    } else if !forward_stdin && !static_stdin_sent {
                        send_static_channel_stdin(&write_half, stdin, "SSH channel").await?;
                        static_stdin_sent = true;
                    }
                }
                release_raw_output(&mut control, live_streams, &mut stdout, &mut stderr)?;
            }
        }
    }

    control.finish()?;
    release_raw_output(&mut control, live_streams, &mut stdout, &mut stderr)?;
    Ok(RemoteCommand {
        status,
        signal,
        cwd_frame: control.matched_cwd,
        stdout,
        stderr,
    })
}

async fn run_pty_channel(
    channel: russh::Channel<client::Msg>,
    stdin: &StaticStdin,
    forward_stdin: bool,
    local_terminal: &LocalTerminal,
    cancel: &CancellationToken,
    live_streams: Option<&LiveStreams>,
    frames: ChannelControlFrames<'_>,
) -> Result<RemoteCommand, ExecFailure> {
    let _raw_terminal = RawTerminalGuard::enter(local_terminal)?;
    let live_stdout = live_streams.filter(|_| local_terminal.stdout);
    let (mut read_half, write_half) = channel.split();
    let mut control = ControlFrameState::new(frames, true);
    let mut stdin_rx = None;
    let mut stdin_done = true;
    let mut static_stdin_sent = forward_stdin;
    if forward_stdin {
        if control.stdin_ready() {
            stdin_rx = Some(spawn_stdin_reader());
            stdin_done = false;
        }
    } else if control.stdin_ready() {
        send_static_channel_stdin(&write_half, stdin, "SSH PTY").await?;
        static_stdin_sent = true;
    }
    let mut resize_signal = resize_signal(local_terminal);
    let mut interrupt_seen = false;
    let mut status = None;
    let mut signal = None;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = write_half.signal(russh::Sig::INT).await;
                tokio::time::sleep(CANCEL_CLEANUP_TIMEOUT).await;
                let _ = write_half.close().await;
                return Err(cancellation_failure().dispatched().residue());
            }
            _ = wait_resize_signal(&mut resize_signal), if resize_signal.is_some() => {
                let (columns, rows) = effective_terminal_size(local_terminal);
                let _ = write_half.window_change(columns, rows, 0, 0).await;
            }
            chunk = next_stdin_chunk(&mut stdin_rx), if !stdin_done => {
                let Some(chunk) = chunk else {
                    stdin_done = true;
                    write_half.eof().await.map_err(|error| {
                        ExecFailure::new(
                            FailureClass::IndeterminateAfterDispatch,
                            format!("cannot send SSH PTY EOF: {error}"),
                        )
                        .dispatched()
                        .residue()
                    })?;
                    continue;
                };
                let chunk = chunk.map_err(|error| {
                    ExecFailure::new(FailureClass::IndeterminateAfterDispatch, error)
                        .dispatched()
                        .residue()
                })?;
                if chunk.is_empty() {
                    stdin_done = true;
                    write_half.eof().await.map_err(|error| {
                        ExecFailure::new(
                            FailureClass::IndeterminateAfterDispatch,
                            format!("cannot send SSH PTY EOF: {error}"),
                        )
                        .dispatched()
                        .residue()
                    })?;
                    continue;
                }
                if chunk.contains(&0x03) {
                    if interrupt_seen {
                        crate::secret::restore_global_input_terminal();
                        restore_global_raw_terminal();
                        std::process::exit(130);
                    }
                    interrupt_seen = true;
                    cancel.cancel();
                }
                write_half.data_bytes(chunk).await.map_err(|error| {
                    ExecFailure::new(
                        FailureClass::IndeterminateAfterDispatch,
                        format!("cannot write SSH PTY input: {error}"),
                    )
                    .dispatched()
                    .residue()
                })?;
                if interrupt_seen {
                    let _ = write_half.signal(russh::Sig::INT).await;
                }
            }
            message = read_half.wait() => {
                let Some(message) = message else {
                    break;
                };
                match message {
                    ChannelMsg::Data { data } => {
                        if let Some(streams) = live_stdout.filter(|_| control.output_released) {
                            write_local_stream(streams, &data, false, "cannot write remote PTY stdout")?;
                        } else {
                            stdout.extend_from_slice(&data);
                            control.inspect(&mut stdout, &mut stderr)?;
                        }
                    }
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        if let Some(streams) = live_stdout.filter(|_| control.output_released) {
                            write_local_stream(streams, &data, false, "cannot write remote PTY stdout")?;
                        } else {
                            stdout.extend_from_slice(&data);
                        }
                        if !control.output_released {
                            control.inspect(&mut stdout, &mut stderr)?;
                        }
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        status = Some(i32::try_from(exit_status).unwrap_or(i32::MAX));
                    }
                    ChannelMsg::ExitSignal { signal_name, .. } => {
                        signal = Some(remote_signal(signal_name));
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
                if control.stdin_ready() {
                    if forward_stdin && stdin_rx.is_none() && stdin_done {
                        stdin_rx = Some(spawn_stdin_reader());
                        stdin_done = false;
                    } else if !forward_stdin && !static_stdin_sent {
                        send_static_channel_stdin(&write_half, stdin, "SSH PTY").await?;
                        static_stdin_sent = true;
                    }
                }
                release_pty_output(&mut control, live_stdout, &mut stdout)?;
            }
        }
    }

    control.finish()?;
    release_pty_output(&mut control, live_stdout, &mut stdout)?;
    Ok(RemoteCommand {
        status,
        signal,
        cwd_frame: control.matched_cwd,
        stdout,
        stderr,
    })
}

static RAW_TERMINAL_STATE: Mutex<Option<RawTerminalState>> = Mutex::new(None);

#[derive(Clone)]
struct RawTerminalState {
    fd: RawTerminalFd,
    original: rustix::termios::Termios,
}

#[derive(Clone, Copy)]
enum RawTerminalFd {
    Stdin,
    Stdout,
    Stderr,
}

struct RawTerminalGuard {
    active: bool,
}

impl RawTerminalGuard {
    fn enter(local_terminal: &LocalTerminal) -> Result<Self, ExecFailure> {
        let Some(fd) = RawTerminalFd::from_terminal(local_terminal) else {
            return Ok(Self { active: false });
        };
        let original = fd.getattr().map_err(|error| {
            ExecFailure::new(
                FailureClass::IndeterminateAfterDispatch,
                format!("cannot read local terminal mode: {error}"),
            )
            .dispatched()
            .residue()
        })?;
        let mut raw = original.clone();
        raw.make_raw();
        fd.setattr(&raw).map_err(|error| {
            ExecFailure::new(
                FailureClass::IndeterminateAfterDispatch,
                format!("cannot enter local terminal raw mode: {error}"),
            )
            .dispatched()
            .residue()
        })?;
        *RAW_TERMINAL_STATE.lock().expect("raw terminal state") =
            Some(RawTerminalState { fd, original });
        Ok(Self { active: true })
    }
}

impl RawTerminalFd {
    fn from_terminal(local_terminal: &LocalTerminal) -> Option<Self> {
        if local_terminal.stdin {
            Some(Self::Stdin)
        } else if local_terminal.stdout {
            Some(Self::Stdout)
        } else if local_terminal.stderr {
            Some(Self::Stderr)
        } else {
            None
        }
    }

    fn getattr(self) -> rustix::io::Result<rustix::termios::Termios> {
        match self {
            Self::Stdin => rustix::termios::tcgetattr(std::io::stdin()),
            Self::Stdout => rustix::termios::tcgetattr(std::io::stdout()),
            Self::Stderr => rustix::termios::tcgetattr(std::io::stderr()),
        }
    }

    fn setattr(self, termios: &rustix::termios::Termios) -> rustix::io::Result<()> {
        match self {
            Self::Stdin => rustix::termios::tcsetattr(
                std::io::stdin(),
                rustix::termios::OptionalActions::Now,
                termios,
            ),
            Self::Stdout => rustix::termios::tcsetattr(
                std::io::stdout(),
                rustix::termios::OptionalActions::Now,
                termios,
            ),
            Self::Stderr => rustix::termios::tcsetattr(
                std::io::stderr(),
                rustix::termios::OptionalActions::Now,
                termios,
            ),
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if self.active {
            restore_global_raw_terminal();
        }
    }
}

fn restore_global_raw_terminal() {
    let state = RAW_TERMINAL_STATE
        .lock()
        .expect("raw terminal state")
        .take();
    if let Some(state) = state {
        let _ = state.fd.setattr(&state.original);
    }
}

fn effective_terminal_size(local_terminal: &LocalTerminal) -> (u32, u32) {
    terminal_size().unwrap_or_else(|| (local_terminal.columns.max(1), local_terminal.rows.max(1)))
}

fn terminal_size() -> Option<(u32, u32)> {
    terminal_size_from(std::io::stdout())
        .or_else(|| terminal_size_from(std::io::stderr()))
        .or_else(|| terminal_size_from(std::io::stdin()))
}

fn terminal_size_from<Fd: rustix::fd::AsFd>(fd: Fd) -> Option<(u32, u32)> {
    let size = rustix::termios::tcgetwinsize(fd).ok()?;
    if size.ws_col == 0 || size.ws_row == 0 {
        None
    } else {
        Some((u32::from(size.ws_col), u32::from(size.ws_row)))
    }
}

fn resize_signal(local_terminal: &LocalTerminal) -> Option<tokio::signal::unix::Signal> {
    if local_terminal.stdin || local_terminal.stdout || local_terminal.stderr {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
    } else {
        None
    }
}

async fn wait_resize_signal(signal: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(signal) = signal {
        let _ = signal.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

async fn collect_channel(
    mut channel: russh::Channel<client::Msg>,
    capture_stdout: bool,
    capture_stderr: bool,
) -> Result<RemoteCommand, ExecFailure> {
    let mut status = None;
    let mut signal = None;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } if capture_stdout => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext } if capture_stderr && ext == 1 => {
                stderr.extend_from_slice(&data)
            }
            ChannelMsg::ExitStatus { exit_status } => {
                status = Some(i32::try_from(exit_status).unwrap_or(i32::MAX));
            }
            ChannelMsg::ExitSignal { signal_name, .. } => {
                signal = Some(remote_signal(signal_name));
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    Ok(RemoteCommand {
        status,
        signal,
        cwd_frame: None,
        stdout,
        stderr,
    })
}

async fn cleanup_staging(
    session: &mut client::Handle<StrictHandler>,
    launcher: &str,
    timeout: Duration,
) -> Result<(), ExecFailure> {
    let command = crate::staging::cleanup_command(launcher).map_err(ExecFailure::from_staging)?;
    let result = run_helper_command(
        session,
        &command,
        None,
        timeout,
        false,
        false,
        &CancellationToken::default(),
    )
    .await?;
    if result.status == Some(0) {
        Ok(())
    } else {
        Err(ExecFailure::new(
            FailureClass::TransferPathSafety,
            "remote exec staging cleanup did not complete",
        ))
    }
}

async fn cleanup_staging_or_residue(
    session: &mut client::Handle<StrictHandler>,
    launcher: &str,
    timeout: Duration,
    failure: ExecFailure,
) -> ExecFailure {
    let cleanup_timeout =
        if failure.class == FailureClass::Cancellation && timeout > CANCEL_CLEANUP_TIMEOUT {
            CANCEL_CLEANUP_TIMEOUT
        } else {
            timeout
        };
    if cleanup_staging(session, launcher, cleanup_timeout)
        .await
        .is_ok()
    {
        failure.clear_residue()
    } else {
        failure.residue()
    }
}

fn route_endpoint(target: &ExecTarget) -> (&str, u16) {
    match &target.route {
        ExecRoute::Direct => (target.address.as_str(), target.port),
        ExecRoute::ViaJump(jump) => (jump.address.as_str(), jump.port),
    }
}

async fn resolve_dns(
    address: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> Result<Vec<std::net::SocketAddr>, ExecFailure> {
    let addresses = tokio::time::timeout_at(deadline, tokio::net::lookup_host((address, port)))
        .await
        .map_err(|_| ExecFailure::new(FailureClass::Dns, "DNS resolution timed out"))?
        .map_err(|error| {
            ExecFailure::new(FailureClass::Dns, format!("DNS resolution failed: {error}"))
        })?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        Err(ExecFailure::new(
            FailureClass::Dns,
            "DNS resolution returned no addresses",
        ))
    } else {
        Ok(addresses)
    }
}

async fn connect_addresses(
    addresses: &[std::net::SocketAddr],
    configured_address: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> Result<tokio::net::TcpStream, ExecFailure> {
    for address in addresses {
        match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(_)) => {}
            Err(_) => break,
        }
    }
    Err(ExecFailure::new(
        FailureClass::ConnectTimeout,
        format!("cannot connect to {configured_address}:{port} within the configured timeout"),
    ))
}

async fn connect_strict<R>(
    stream: R,
    expected: HostKey,
    deadline: tokio::time::Instant,
) -> Result<client::Handle<StrictHandler>, ExecFailure>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = client_config(std::slice::from_ref(&expected.algorithm))?;
    tokio::time::timeout_at(
        deadline,
        client::connect_stream(
            Arc::new(config),
            stream,
            StrictHandler::new(expected.clone()),
        ),
    )
    .await
    .map_err(|_| ExecFailure::new(FailureClass::Protocol, "SSH key exchange timed out"))?
    .map_err(strict_connect_failure)
}

fn strict_connect_failure(error: russh::Error) -> ExecFailure {
    match error {
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => ExecFailure::new(
            FailureClass::UnknownHostKey,
            "strict host-key verification failed",
        ),
        russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Key,
            ..
        } => ExecFailure::new(
            FailureClass::ChangedHostKey,
            "host no longer offers the pinned host-key algorithm",
        ),
        error => ExecFailure::new(
            FailureClass::Protocol,
            format!("SSH protocol failure before host-key verification: {error}"),
        ),
    }
}

fn strict_target_trust_failure(error: ExecFailure) -> ExecFailure {
    if error.class == FailureClass::UnknownHostKey {
        ExecFailure::new(
            FailureClass::ChangedHostKey,
            "target host key does not match the pinned key",
        )
    } else {
        error
    }
}

fn strict_jump_trust_failure(jump_name: &str, error: ExecFailure) -> ExecFailure {
    if error.class == FailureClass::UnknownHostKey {
        ExecFailure::new(
            FailureClass::ChangedHostKey,
            format!("jump host {jump_name} key does not match the pinned key"),
        )
    } else {
        error
    }
}

fn client_config(algorithms: &[String]) -> Result<client::Config, ExecFailure> {
    let algorithms = algorithms
        .iter()
        .map(|name| {
            Algorithm::from_str(name).map_err(|_| {
                ExecFailure::new(
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

async fn timeout<T>(
    timeout: Duration,
    future: impl Future<Output = T>,
    class: FailureClass,
    diagnostic: &'static str,
) -> Result<T, ExecFailure> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| ExecFailure::new(class, diagnostic))
}

async fn timeout_at<T>(
    deadline: tokio::time::Instant,
    future: impl Future<Output = T>,
    class: FailureClass,
    diagnostic: &'static str,
) -> Result<T, ExecFailure> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| ExecFailure::new(class, diagnostic))
}

async fn cancellable<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, ExecFailure>>,
) -> Result<T, ExecFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancellation_failure()),
        result = future => result,
    }
}

fn cancellation_failure() -> ExecFailure {
    ExecFailure::new(FailureClass::Cancellation, "cancelled")
}

fn store_failure(error: StoreError) -> ExecFailure {
    ExecFailure::new(error.class(), error.to_string())
}

pub(crate) fn signal_status(name: &str) -> Option<i32> {
    let number = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "ABRT" => 6,
        "FPE" => 8,
        "KILL" => 9,
        "SEGV" => 11,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "USR1" => 10,
        "USR2" => 12,
        _ => return None,
    };
    Some(128 + number)
}

pub(crate) fn remote_signal(signal: russh::Sig) -> RemoteSignal {
    let name = match signal {
        russh::Sig::ABRT => "ABRT".to_string(),
        russh::Sig::ALRM => "ALRM".to_string(),
        russh::Sig::FPE => "FPE".to_string(),
        russh::Sig::HUP => "HUP".to_string(),
        russh::Sig::ILL => "ILL".to_string(),
        russh::Sig::INT => "INT".to_string(),
        russh::Sig::KILL => "KILL".to_string(),
        russh::Sig::PIPE => "PIPE".to_string(),
        russh::Sig::QUIT => "QUIT".to_string(),
        russh::Sig::SEGV => "SEGV".to_string(),
        russh::Sig::TERM => "TERM".to_string(),
        russh::Sig::USR1 => "USR1".to_string(),
        russh::Sig::Custom(name) => name,
    };
    RemoteSignal { name }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

