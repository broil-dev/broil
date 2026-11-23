// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::future::Future;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use broil_core::error::UsageError;
use broil_core::remote::{DurationValue, PtyMode, RemoteEnvValue};
use zeroize::Zeroizing;

pub use crate::jobs::RequestedJobs;
use crate::jobs::resolve_jobs;
use crate::scheduler::CancellationToken;
use crate::{
    EffectiveAuth, EffectiveInventory, EffectiveJump, EffectiveMachine, EffectiveTimeouts,
    FailureClass, JumpScope, PlanValidationError, Selectors,
};

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
pub struct ProvisionRequest {
    pub selectors: Selectors,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: ResolvedKnownHosts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionPlan {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub job_limit: usize,
    pub jobs: Vec<ProvisionJob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionJob {
    pub target: ProvisionTarget,
    pub plan: Result<Option<ProvisionTargetPlan>, PlanValidationError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionTarget {
    pub machine: String,
    pub address: String,
    pub port: u16,
    pub target_alias: String,
    pub route: String,
    pub jump: Option<ProvisionJump>,
    pub canonical_profile: String,
    pub canonical_user: String,
    pub bootstrap_profiles: Vec<EffectiveAuth>,
    pub privilege_profile: Option<String>,
    pub provision_profiles: Vec<String>,
    pub vars: BTreeMap<String, String>,
    pub known_hosts: ResolvedKnownHosts,
    pub connect_timeout: DurationValue,
    pub command_timeout: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionJump {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub alias: String,
    pub auth_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionTargetPlan {
    pub profiles: Vec<String>,
    pub steps: Vec<ProvisionStep>,
    pub transition_owner: String,
    pub transition_actions: Vec<NamedScriptAction>,
    pub security_verifiers: Vec<NamedScriptAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionStep {
    pub id: String,
    pub phase: String,
    pub check: Option<ScriptAction>,
    pub run: ProvisionAction,
    pub verify: Option<ScriptAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedScriptAction {
    pub name: String,
    pub action: ScriptAction,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ScriptAction {
    pub script: String,
    pub privilege: Option<String>,
    pub stdin: Option<ScriptStdin>,
    pub timeout: DurationValue,
}

impl fmt::Debug for ScriptAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptAction")
            .field("script", &self.script)
            .field("privilege", &self.privilege)
            .field("stdin", &self.stdin.as_ref().map(|_| "secret"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ScriptStdin {
    Secret { provider: String },
}

impl fmt::Debug for ScriptStdin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret { .. } => formatter.write_str("Secret([REDACTED])"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionAction {
    Script(ScriptAction),
    CopyTo(CopyToAction),
    CopyFrom(CopyFromAction),
    Reboot(RebootAction),
    Local(LocalAction),
}

impl ProvisionAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Script(_) => "script",
            Self::CopyTo(_) => "copy_to",
            Self::CopyFrom(_) => "copy_from",
            Self::Reboot(_) => "reboot",
            Self::Local(_) => "local",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyToAction {
    pub source: String,
    pub destination: String,
    pub recursive: bool,
    pub overwrite: bool,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub privilege: Option<String>,
    pub timeout: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyFromAction {
    pub source: String,
    pub destination: String,
    pub recursive: bool,
    pub overwrite: bool,
    pub mode: Option<String>,
    pub timeout: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootAction {
    pub when: Option<ScriptAction>,
    pub privilege: Option<String>,
    pub disconnect_timeout: DurationValue,
    pub readiness_timeout: DurationValue,
    pub poll_interval: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAction {
    pub command: Vec<String>,
    pub timeout: DurationValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionStatus {
    Pending,
    Succeeded,
    Failed,
}

impl ProvisionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignal {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionTargetResult {
    pub machine: String,
    pub status: ProvisionStatus,
    pub failure_class: Option<FailureClass>,
    pub diagnostic: Option<String>,
    pub diagnostic_in_report: bool,
    pub dispatched: bool,
    pub phase: Option<String>,
    pub action: Option<String>,
    pub remote_status: Option<i32>,
    pub remote_signal: Option<RemoteSignal>,
    pub possible_staging_residue: bool,
}

impl ProvisionTargetResult {
    fn pending(job: &ProvisionJob) -> Self {
        Self {
            machine: job.target.machine.clone(),
            status: ProvisionStatus::Pending,
            failure_class: None,
            diagnostic: None,
            diagnostic_in_report: false,
            dispatched: false,
            phase: None,
            action: None,
            remote_status: None,
            remote_signal: None,
            possible_staging_residue: false,
        }
    }

    fn succeeded(machine: impl Into<String>, dispatched: bool, residue: bool) -> Self {
        Self {
            machine: machine.into(),
            status: ProvisionStatus::Succeeded,
            failure_class: None,
            diagnostic: None,
            diagnostic_in_report: false,
            dispatched,
            phase: None,
            action: None,
            remote_status: None,
            remote_signal: None,
            possible_staging_residue: residue,
        }
    }

    fn failure(
        machine: impl Into<String>,
        class: FailureClass,
        diagnostic: impl Into<String>,
    ) -> Self {
        Self {
            machine: machine.into(),
            status: ProvisionStatus::Failed,
            failure_class: Some(class),
            diagnostic: Some(diagnostic.into()),
            diagnostic_in_report: true,
            dispatched: false,
            phase: None,
            action: None,
            remote_status: None,
            remote_signal: None,
            possible_staging_residue: false,
        }
    }

    fn with_context(mut self, phase: Option<String>, action: Option<String>) -> Self {
        self.phase = phase;
        self.action = action;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionOutcome {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub duration_millis: u128,
    pub results: Vec<ProvisionTargetResult>,
}

impl ProvisionOutcome {
    pub fn status(&self) -> i32 {
        if self.results.len() == 1 {
            let result = &self.results[0];
            if result.status != ProvisionStatus::Failed {
                return 0;
            }
            if result.dispatched && result.failure_class == Some(FailureClass::RemoteNonzero) {
                if let Some(status) = result.remote_status {
                    return status;
                }
                if let Some(signal) = &result.remote_signal {
                    return crate::exec::signal_status(&signal.name).unwrap_or(1);
                }
            }
            return 1;
        }
        if self
            .results
            .iter()
            .any(|result| result.status == ProvisionStatus::Failed)
        {
            1
        } else {
            0
        }
    }
}

#[derive(Debug)]
pub enum ProvisionPlanError {
    Usage(UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

impl ProvisionPlanError {
    pub fn class(&self) -> FailureClass {
        match self {
            Self::Usage(_) => FailureClass::Selector,
            Self::Runtime { class, .. } => *class,
        }
    }
}

impl std::fmt::Display for ProvisionPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(formatter),
            Self::Runtime { diagnostic, .. } => formatter.write_str(diagnostic),
        }
    }
}

impl std::error::Error for ProvisionPlanError {}

#[derive(Debug, Clone, Default)]
pub struct ProvisionRunOptions {
    pub cancel: CancellationToken,
}

pub struct ProvisionScriptInvocation {
    pub command: crate::exec::RemoteScriptCommand,
    pub action: ScriptAction,
    pub stdin: Option<ProvisionSecretStdin>,
}

impl fmt::Debug for ProvisionScriptInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionScriptInvocation")
            .field("command", &self.command)
            .field("action", &self.action)
            .field(
                "stdin",
                &self
                    .stdin
                    .as_ref()
                    .map(|_| "ProvisionSecretStdin([REDACTED])"),
            )
            .finish()
    }
}

pub struct ProvisionSecretStdin {
    bytes: Zeroizing<Vec<u8>>,
}

impl ProvisionSecretStdin {
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self { bytes }
    }

    pub fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl fmt::Debug for ProvisionSecretStdin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisionSecretStdin([REDACTED])")
    }
}

#[derive(Debug, Clone)]
pub struct ProvisionActionContext {
    pub phase: String,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct ProvisionTransferInvocation {
    pub job: crate::transfer::TransferJob,
}

#[derive(Debug, Clone)]
pub struct ProvisionLocalInvocation {
    pub action: LocalAction,
    pub root: PathBuf,
    pub environment: String,
    pub env_vars: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ProvisionRebootInvocation {
    pub action: RebootAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionInputQuery<'a> {
    SecretProvider(&'a str),
    PrivilegeProfile(Option<&'a str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionInputPacing {
    None,
    Machine,
    Human,
}

pub trait ProvisionBackend: Clone + Send + Sync + 'static {
    type Session: Send + 'static;

    fn input_pacing(&self, query: ProvisionInputQuery<'_>) -> ProvisionInputPacing;

    fn human_paced_authentication_resolutions(&self, profile: &str) -> usize;

    fn connect_target(
        &self,
        target: ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Session, ProvisionTargetResult>> + Send>>;

    fn run_script<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        invocation: ProvisionScriptInvocation,
        context: ProvisionActionContext,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>>;

    fn resolve_secret_stdin<'a>(
        &'a self,
        provider: &'a str,
        cancel: CancellationToken,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ProvisionSecretStdin, crate::secret::SecretFailure>>
                + Send
                + 'a,
        >,
    >;

    fn run_transfer<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        invocation: ProvisionTransferInvocation,
        context: ProvisionActionContext,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>>;

    fn request_reboot<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        invocation: ProvisionRebootInvocation,
        context: ProvisionActionContext,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>>;

    fn run_local<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        invocation: ProvisionLocalInvocation,
        context: ProvisionActionContext,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>>;

    fn target_session_is_closed(&self, session: &mut Self::Session) -> bool;

    fn disconnect(&self, session: Self::Session) -> Pin<Box<dyn Future<Output = ()> + Send>>;

    fn session_authentication(
        &self,
        session: &Self::Session,
    ) -> crate::ssh::BootstrapAuthentication;

    fn prove_canonical_access(
        &self,
        target: ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send>>;

    fn open_fresh_canonical_session(
        &self,
        target: ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Session, ProvisionTargetResult>> + Send>>;

    fn prove_public_key_only(
        &self,
        target: ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send>>;

    fn probe_sftp_gate<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>>;

    fn retain_successful_session<'a>(
        &'a self,
        target: &'a ProvisionTarget,
        session: Self::Session,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

#[derive(Clone)]
pub struct RusshProvisionBackend {
    ssh_options: crate::ssh::BootstrapSshOptions,
    exec_backend: crate::exec::RusshExecBackend,
    transfer_privilege_context: crate::transfer::TransferPrivilegeContext,
    secret_context: crate::secret::SecretContext,
    local_env_snapshot: Vec<(OsString, OsString)>,
    local_artifact_home: PathBuf,
    retained_sessions: Arc<Mutex<Vec<(String, crate::ssh::BootstrapSession)>>>,
}

impl RusshProvisionBackend {
    pub fn new(
        ssh_options: crate::ssh::BootstrapSshOptions,
        exec_backend: crate::exec::RusshExecBackend,
        transfer_privilege_context: crate::transfer::TransferPrivilegeContext,
        secret_context: crate::secret::SecretContext,
        local_env_snapshot: Vec<(OsString, OsString)>,
        local_artifact_home: PathBuf,
    ) -> Self {
        Self {
            ssh_options,
            exec_backend,
            transfer_privilege_context,
            secret_context,
            local_env_snapshot,
            local_artifact_home,
            retained_sessions: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ProvisionBackend for RusshProvisionBackend {
    type Session = crate::ssh::BootstrapSession;

    fn input_pacing(&self, query: ProvisionInputQuery<'_>) -> ProvisionInputPacing {
        let human_paced = match query {
            ProvisionInputQuery::SecretProvider(provider) => {
                Some(self.secret_context.provider_is_human_paced(provider))
            }
            ProvisionInputQuery::PrivilegeProfile(None) => None,
            ProvisionInputQuery::PrivilegeProfile(Some(profile)) => {
                self.exec_backend.privilege_password_pacing(profile)
            }
        };
        match human_paced {
            None => ProvisionInputPacing::None,
            Some(true) => ProvisionInputPacing::Human,
            Some(false) => ProvisionInputPacing::Machine,
        }
    }

    fn human_paced_authentication_resolutions(&self, profile: &str) -> usize {
        self.ssh_options
            .auth_context
            .human_paced_authentication_resolutions(profile)
    }

    fn connect_target(
        &self,
        target: ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Session, ProvisionTargetResult>> + Send>> {
        let mut options = self.ssh_options.clone();
        options.cancel = cancel;
        Box::pin(async move {
            crate::ssh::connect_bootstrap_provision_target(&target, &options)
                .await
                .map_err(|error| ssh_result(&target, error))
        })
    }

    fn run_script<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        invocation: ProvisionScriptInvocation,
        context: ProvisionActionContext,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>> {
        Box::pin(async move {
            let exec_target = exec_target_for_script(target, &invocation.action);
            let options = crate::exec::TargetExecOptions {
                command: Arc::new(crate::exec::ExecCommand::Script(invocation.command)),
                stdin: invocation
                    .stdin
                    .map(|stdin| crate::exec::StaticStdin::secret(stdin.into_bytes()))
                    .unwrap_or_else(crate::exec::StaticStdin::empty),
                forward_stdin: false,
                live_streams: None,
                pty: false,
                local_terminal: crate::exec::LocalTerminal::default(),
                privilege: invocation.action.privilege,
                dispatch_timeout_seconds: Some(invocation.action.timeout.seconds),
                cancel,
            };
            let result = self
                .exec_backend
                .exec_authenticated_target(session.session_mut(), &exec_target, &options)
                .await;
            exec_result(target, context, result)
        })
    }

    fn resolve_secret_stdin<'a>(
        &'a self,
        provider: &'a str,
        cancel: CancellationToken,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ProvisionSecretStdin, crate::secret::SecretFailure>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let secret = self
                .secret_context
                .resolve_owned_cancellable(provider, &cancel)
                .await?;
            Ok(ProvisionSecretStdin::new(secret.into_bytes()))
        })
    }

    fn run_transfer<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        invocation: ProvisionTransferInvocation,
        context: ProvisionActionContext,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>> {
        Box::pin(async move {
            let root_authenticated =
                session_authenticated_user(target, session.authenticated_profile()) == Some("root");
            let result = crate::transfer_sftp::provision_transfer_target(
                session.session_mut(),
                root_authenticated,
                &invocation.job,
                &self.transfer_privilege_context,
                &cancel,
            )
            .await;
            transfer_result(target, context, result)
        })
    }

    fn request_reboot<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        invocation: ProvisionRebootInvocation,
        context: ProvisionActionContext,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>> {
        Box::pin(async move {
            let exec_target = exec_target_for_reboot(target, &invocation.action);
            let options = crate::exec::TargetExecOptions {
                command: Arc::new(crate::exec::ExecCommand::Argv(vec![b"reboot".to_vec()])),
                stdin: crate::exec::StaticStdin::empty(),
                forward_stdin: false,
                live_streams: None,
                pty: false,
                local_terminal: crate::exec::LocalTerminal::default(),
                privilege: invocation.action.privilege.clone(),
                dispatch_timeout_seconds: Some(invocation.action.disconnect_timeout.seconds),
                cancel,
            };
            let result = self
                .exec_backend
                .exec_authenticated_target(session.session_mut(), &exec_target, &options)
                .await;
            exec_result(target, context, result)
        })
    }

    fn run_local<'a>(
        &'a self,
        _session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        invocation: ProvisionLocalInvocation,
        context: ProvisionActionContext,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>> {
        Box::pin(async move {
            let handoff = match prepare_local_openssh_handoff(
                target,
                &self.local_artifact_home,
                &self.ssh_options.auth_context,
            )
            .await
            {
                Ok(handoff) => handoff,
                Err(LocalHandoffError::Preflight(error)) => {
                    return ssh_result(target, error)
                        .with_context(Some(context.phase), Some(context.action));
                }
                Err(LocalHandoffError::Worker) => {
                    return local_failure(
                        target,
                        context,
                        FailureClass::Configuration,
                        "remote provision local openssh handoff worker failed",
                        false,
                        true,
                    );
                }
            };
            let environment = local_child_environment(
                &self.local_env_snapshot,
                &invocation.env_vars,
                &invocation.root,
                &invocation.environment,
                &target.machine,
                handoff.config(),
                handoff.host(),
            );
            run_local_child(
                target,
                context,
                invocation,
                environment,
                LocalHandoffGuard::new(handoff),
                cancel,
            )
            .await
        })
    }

    fn target_session_is_closed(&self, session: &mut Self::Session) -> bool {
        session.target_session_is_closed()
    }

    fn disconnect(&self, session: Self::Session) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move { session.disconnect().await })
    }

    fn session_authentication(
        &self,
        session: &Self::Session,
    ) -> crate::ssh::BootstrapAuthentication {
        session.authentication()
    }

    fn prove_canonical_access(
        &self,
        target: ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send>> {
        let mut options = self.ssh_options.clone();
        options.cancel = cancel;
        Box::pin(async move {
            match crate::ssh::prove_canonical_provision_target(&target, &options).await {
                Ok(()) => ProvisionTargetResult::succeeded(target.machine, false, false),
                Err(error) => ssh_result(&target, error),
            }
        })
    }

    fn open_fresh_canonical_session(
        &self,
        target: ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Session, ProvisionTargetResult>> + Send>> {
        let mut options = self.ssh_options.clone();
        options.cancel = cancel;
        Box::pin(async move {
            crate::ssh::connect_canonical_provision_target(&target, &options)
                .await
                .map_err(|error| ssh_result(&target, error))
        })
    }

    fn prove_public_key_only(
        &self,
        target: ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send>> {
        let mut options = self.ssh_options.clone();
        options.cancel = cancel;
        Box::pin(async move {
            match crate::ssh::prove_public_key_only_provision_target(&target, &options).await {
                Ok(()) => ProvisionTargetResult::succeeded(target.machine, true, false),
                Err(error) => ssh_probe_result(&target, error),
            }
        })
    }

    fn probe_sftp_gate<'a>(
        &'a self,
        session: &'a mut Self::Session,
        target: &'a ProvisionTarget,
        cancel: CancellationToken,
    ) -> Pin<Box<dyn Future<Output = ProvisionTargetResult> + Send + 'a>> {
        Box::pin(async move {
            let timeout = std::time::Duration::from_secs(target.command_timeout.seconds);
            match crate::transfer_sftp::provision_sftp_gate_probe(
                session.session_mut(),
                timeout,
                &cancel,
            )
            .await
            {
                Ok(()) => ProvisionTargetResult::succeeded(target.machine.clone(), true, false),
                Err(error) => sftp_gate_result(target, error),
            }
        })
    }

    fn retain_successful_session<'a>(
        &'a self,
        target: &'a ProvisionTarget,
        session: Self::Session,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        let retained_sessions = Arc::clone(&self.retained_sessions);
        let machine = target.machine.clone();
        Box::pin(async move {
            retained_sessions
                .lock()
                .expect("retained provision sessions")
                .push((machine, session));
        })
    }
}

pub fn plan(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &ProvisionRequest,
) -> Result<ProvisionPlan, ProvisionPlanError> {
    let selected =
        crate::select(inventory, &request.selectors, false).map_err(ProvisionPlanError::Usage)?;
    let selected_machines = selected
        .iter()
        .map(|machine| machine.name.clone())
        .collect::<Vec<_>>();
    let job_limit = resolve_jobs(
        request.jobs,
        &inventory.provision_parallelism,
        selected.len(),
    );
    let jobs = selected
        .into_iter()
        .map(|machine| plan_job(root, inventory, machine, request))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProvisionPlan {
        environment: inventory.environment.clone(),
        selected_machines,
        job_limit,
        jobs,
    })
}

pub fn pre_dispatch_outcome(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &ProvisionRequest,
    options: &ProvisionRunOptions,
) -> Result<ProvisionOutcome, ProvisionPlanError> {
    let started = now_millis();
    let plan = plan(root, inventory, request)?;
    let results = if options.cancel.is_cancelled() {
        plan.jobs
            .iter()
            .map(|job| {
                ProvisionTargetResult::failure(
                    job.target.machine.clone(),
                    FailureClass::Cancellation,
                    "remote provision target was not scheduled",
                )
            })
            .collect()
    } else if request.fail_fast
        && plan
            .jobs
            .iter()
            .any(|job| job.target.provision_profiles.is_empty())
    {
        plan.jobs
            .iter()
            .map(|job| {
                if job.target.provision_profiles.is_empty() {
                    planless_result(job)
                } else {
                    ProvisionTargetResult::failure(
                        job.target.machine.clone(),
                        FailureClass::FailFast,
                        "remote provision target was not scheduled",
                    )
                }
            })
            .collect()
    } else {
        let mut stopped = false;
        plan.jobs
            .iter()
            .map(|job| {
                if stopped {
                    return ProvisionTargetResult::failure(
                        job.target.machine.clone(),
                        FailureClass::FailFast,
                        "remote provision target was not scheduled",
                    );
                }
                let result = pre_dispatch_result(job);
                if request.fail_fast && result.status == ProvisionStatus::Failed {
                    stopped = true;
                }
                result
            })
            .collect()
    };
    Ok(ProvisionOutcome {
        environment: plan.environment,
        selected_machines: plan.selected_machines,
        duration_millis: now_millis().saturating_sub(started),
        results,
    })
}

pub fn run<B: ProvisionBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &ProvisionRequest,
    options: &ProvisionRunOptions,
    backend: B,
) -> Result<ProvisionOutcome, ProvisionPlanError> {
    let started = now_millis();
    let plan = plan(root, inventory, request)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(resolved_provision_worker_threads(plan.job_limit))
        .enable_all()
        .build()
        .map_err(|error| ProvisionPlanError::Runtime {
            class: FailureClass::CapabilityUnsupported,
            diagnostic: format!("cannot initialize remote provision runtime: {error}"),
        })?;
    let outcome = runtime.block_on(run_async(
        root, inventory, request, options, backend, started, plan,
    ));
    crate::secret::restore_global_input_terminal();
    runtime.shutdown_background();
    outcome
}

const PROVISION_WORKER_THREAD_CAP: usize = 64;

fn provision_worker_threads(job_limit: usize, default_parallelism: usize) -> usize {
    let default_parallelism = default_parallelism.max(1);
    job_limit
        .saturating_add(1)
        .max(default_parallelism)
        .min(default_parallelism.max(PROVISION_WORKER_THREAD_CAP))
}

fn resolved_provision_worker_threads(job_limit: usize) -> usize {
    let default_parallelism = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    provision_worker_threads(job_limit, default_parallelism)
}

#[allow(clippy::too_many_arguments)]
async fn run_async<B: ProvisionBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &ProvisionRequest,
    options: &ProvisionRunOptions,
    backend: B,
    started: u128,
    plan: ProvisionPlan,
) -> Result<ProvisionOutcome, ProvisionPlanError> {
    let environment = plan.environment;
    let selected_machines = plan.selected_machines;
    let job_limit = plan.job_limit;
    let jobs = plan.jobs;
    let interrupt_task = spawn_interrupt_watcher(options.cancel.clone());
    let results = if options.cancel.is_cancelled() {
        jobs.iter()
            .map(|job| {
                target_not_scheduled(
                    job.target.machine.clone(),
                    FailureClass::Cancellation,
                    "remote provision target was not scheduled",
                )
            })
            .collect()
    } else if request.fail_fast
        && jobs
            .iter()
            .any(|job| job.target.provision_profiles.is_empty())
    {
        jobs.iter()
            .map(|job| {
                if job.target.provision_profiles.is_empty() {
                    planless_result(job)
                } else {
                    target_not_scheduled(
                        job.target.machine.clone(),
                        FailureClass::FailFast,
                        "remote provision target was not scheduled",
                    )
                }
            })
            .collect()
    } else {
        let root = Arc::new(root.to_path_buf());
        let inventory = Arc::new(inventory.clone());
        let items = jobs
            .into_iter()
            .map(provision_work_item)
            .collect::<Vec<_>>();
        let concurrency = crate::scheduler::effective_limit(job_limit, items.len());
        crate::scheduler::run_bounded(
            items.into_iter().map(Some).collect(),
            job_limit,
            request.fail_fast,
            options.cancel.clone(),
            move |item, token| {
                let root = Arc::clone(&root);
                let inventory = Arc::clone(&inventory);
                let backend = backend.clone();
                async move {
                    match item {
                        ProvisionWorkItem::Ready(result) => result,
                        ProvisionWorkItem::Dispatch(job) => {
                            run_job(root, inventory, *job, backend, concurrency, token).await
                        }
                    }
                }
            },
            |result| result.status == ProvisionStatus::Failed,
            |item, class| match item {
                ProvisionWorkItem::Ready(result) => result,
                ProvisionWorkItem::Dispatch(job) => target_not_scheduled(
                    job.target.machine,
                    class,
                    "remote provision target was not scheduled",
                ),
            },
        )
        .await
    };
    if let Some(task) = interrupt_task {
        task.abort();
    }
    Ok(ProvisionOutcome {
        environment,
        selected_machines,
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

enum ProvisionWorkItem {
    Ready(ProvisionTargetResult),
    Dispatch(Box<ProvisionJob>),
}

fn provision_work_item(job: ProvisionJob) -> ProvisionWorkItem {
    if job.target.provision_profiles.is_empty() {
        return ProvisionWorkItem::Ready(planless_result(&job));
    }
    match &job.plan {
        Ok(Some(_)) => ProvisionWorkItem::Dispatch(Box::new(job)),
        Ok(None) | Err(_) => ProvisionWorkItem::Ready(pre_dispatch_result(&job)),
    }
}

async fn run_job<B: ProvisionBackend>(
    root: Arc<PathBuf>,
    inventory: Arc<EffectiveInventory>,
    job: ProvisionJob,
    backend: B,
    concurrency: usize,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    let Ok(Some(plan)) = &job.plan else {
        return pre_dispatch_result(&job);
    };
    let pre_gate_steps = steps_for_phases(plan, &["bootstrap", "secure"]);
    let configure_steps = steps_for_phases(plan, &["configure"]);
    if pre_gate_steps.is_empty() && plan.transition_actions.is_empty() {
        return ProvisionTargetResult::succeeded(job.target.machine, false, false);
    }
    if cancel.is_cancelled() {
        return target_not_scheduled(
            job.target.machine,
            FailureClass::Cancellation,
            "remote provision target was not scheduled",
        );
    }
    let budget_inputs = connect_budget_inputs(&backend, &job.target, concurrency);
    let connected = guard_connect_boundary(
        ConnectBoundary::Connect,
        &job.target,
        budget_inputs,
        &cancel,
        |child| backend.connect_target(job.target.clone(), child),
    )
    .await;
    let mut session = match connected {
        Ok(Ok(session)) => session,
        Ok(Err(result)) | Err(result) => return result,
    };
    let mut dispatched = false;
    let mut residue = false;
    let env = ProvisionRunEnv {
        root: root.as_path(),
        inventory: inventory.as_ref(),
        plan,
        budget_inputs,
    };
    for step in pre_gate_steps {
        let result = run_step(
            env,
            &backend,
            &mut session,
            &job.target,
            &step,
            cancel.clone(),
        )
        .await;
        dispatched |= result.dispatched;
        residue |= result.possible_staging_residue;
        if result.status == ProvisionStatus::Failed {
            guard_disconnect(&backend, &job.target, session, &cancel).await;
            return with_accumulated_residue(result, residue);
        }
    }
    let transition = run_transition(
        env.inventory,
        &backend,
        &mut session,
        &job.target,
        plan,
        env.budget_inputs,
        cancel.clone(),
    )
    .await;
    dispatched |= transition.dispatched;
    residue |= transition.possible_staging_residue;
    if transition.status == ProvisionStatus::Failed {
        guard_disconnect(&backend, &job.target, session, &cancel).await;
        return with_accumulated_residue(transition, residue);
    }
    if !plan.transition_actions.is_empty() {
        let gate = run_security_gate(
            env.inventory,
            &backend,
            &job.target,
            plan,
            env.budget_inputs,
            cancel.clone(),
        )
        .await;
        match gate {
            Ok(success) => {
                dispatched |= success.result.dispatched;
                residue |= success.result.possible_staging_residue;
                let mut canonical_session = success.session;
                guard_disconnect(&backend, &job.target, session, &cancel).await;
                for step in configure_steps {
                    let result = run_step(
                        env,
                        &backend,
                        &mut canonical_session,
                        &job.target,
                        &step,
                        cancel.clone(),
                    )
                    .await;
                    dispatched |= result.dispatched;
                    residue |= result.possible_staging_residue;
                    if result.status == ProvisionStatus::Failed {
                        guard_disconnect(&backend, &job.target, canonical_session, &cancel).await;
                        return with_accumulated_residue(result, residue);
                    }
                }
                backend
                    .retain_successful_session(&job.target, canonical_session)
                    .await;
                return ProvisionTargetResult::succeeded(job.target.machine, dispatched, residue);
            }
            Err(gate_failure) => {
                let mut flags = TransitionFlags {
                    dispatched,
                    residue,
                };
                flags.merge(&gate_failure);
                let context = TransitionContext {
                    inventory: env.inventory,
                    backend: &backend,
                    target: &job.target,
                    plan,
                };
                let result = rollback_after_transition_failure(
                    &context,
                    &mut session,
                    gate_failure,
                    flags,
                    cancel.clone(),
                )
                .await;
                guard_disconnect(&backend, &job.target, session, &cancel).await;
                return result;
            }
        }
    }
    backend
        .retain_successful_session(&job.target, session)
        .await;
    ProvisionTargetResult::succeeded(job.target.machine, dispatched, residue)
}

fn steps_for_phases(plan: &ProvisionTargetPlan, phases: &[&str]) -> Vec<ProvisionStep> {
    plan.steps
        .iter()
        .filter(|step| phases.contains(&step.phase.as_str()))
        .cloned()
        .collect()
}

async fn run_transition<B: ProvisionBackend>(
    inventory: &EffectiveInventory,
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    plan: &ProvisionTargetPlan,
    budget_inputs: ConnectBudgetInputs,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    if plan.transition_actions.is_empty() {
        return ProvisionTargetResult::succeeded(target.machine.clone(), false, false);
    }
    let context = TransitionContext {
        inventory,
        backend,
        target,
        plan,
    };
    let mut flags = TransitionFlags::default();
    for name in ["prepare", "apply", "validate", "reload"] {
        if name == "apply"
            && backend.session_authentication(session)
                == crate::ssh::BootstrapAuthentication::Bootstrap
        {
            let result =
                prove_canonical_access(backend, target, budget_inputs, cancel.clone()).await;
            flags.merge(&result);
            if result.status == ProvisionStatus::Failed {
                return rollback_after_transition_failure(
                    &context,
                    session,
                    result,
                    flags,
                    cancel.clone(),
                )
                .await;
            }
        }
        let result = run_transition_script(&context, session, name, cancel.clone()).await;
        flags.merge(&result);
        if result.status == ProvisionStatus::Failed {
            return rollback_after_transition_failure(
                &context,
                session,
                result,
                flags,
                cancel.clone(),
            )
            .await;
        }
    }
    ProvisionTargetResult::succeeded(target.machine.clone(), flags.dispatched, flags.residue)
}

struct SecurityGateSuccess<S> {
    session: S,
    result: ProvisionTargetResult,
}

async fn run_security_gate<B: ProvisionBackend>(
    inventory: &EffectiveInventory,
    backend: &B,
    target: &ProvisionTarget,
    plan: &ProvisionTargetPlan,
    budget_inputs: ConnectBudgetInputs,
    cancel: CancellationToken,
) -> Result<SecurityGateSuccess<B::Session>, ProvisionTargetResult> {
    let mut flags = TransitionFlags::default();
    let fresh_context = ProvisionActionContext {
        phase: "security_gate".to_string(),
        action: "fresh_canonical_session".to_string(),
    };
    let mut fresh_session = match open_fresh_canonical_session(
        backend,
        target,
        fresh_context,
        budget_inputs,
        cancel.clone(),
    )
    .await
    {
        Ok((session, result)) => {
            flags.merge(&result);
            session
        }
        Err(result) => return Err(result),
    };

    let public_key_result = run_public_key_only_probe(
        backend,
        target,
        ProvisionActionContext {
            phase: "security_gate".to_string(),
            action: "public_key_only_probe".to_string(),
        },
        budget_inputs,
        cancel.clone(),
    )
    .await;
    flags.merge(&public_key_result);
    if public_key_result.status == ProvisionStatus::Failed {
        guard_disconnect(backend, target, fresh_session, &cancel).await;
        return Err(with_result_flags(public_key_result, flags));
    }

    let sftp_result = run_sftp_gate_probe(
        backend,
        &mut fresh_session,
        target,
        ProvisionActionContext {
            phase: "security_gate".to_string(),
            action: "sftp_probe".to_string(),
        },
        cancel.clone(),
    )
    .await;
    flags.merge(&sftp_result);
    if sftp_result.status == ProvisionStatus::Failed {
        guard_disconnect(backend, target, fresh_session, &cancel).await;
        return Err(with_result_flags(sftp_result, flags));
    }

    for verifier in &plan.security_verifiers {
        let context = ProvisionActionContext {
            phase: "security_gate".to_string(),
            action: verifier.name.clone(),
        };
        let result = run_script_action(
            inventory,
            backend,
            &mut fresh_session,
            target,
            &verifier.action,
            context,
            cancel.clone(),
        )
        .await;
        let result = security_verifier_result(result);
        flags.merge(&result);
        if result.status == ProvisionStatus::Failed {
            guard_disconnect(backend, target, fresh_session, &cancel).await;
            return Err(with_result_flags(result, flags));
        }
    }

    Ok(SecurityGateSuccess {
        session: fresh_session,
        result: ProvisionTargetResult::succeeded(
            target.machine.clone(),
            flags.dispatched,
            flags.residue,
        ),
    })
}

async fn open_fresh_canonical_session<B: ProvisionBackend>(
    backend: &B,
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    budget_inputs: ConnectBudgetInputs,
    cancel: CancellationToken,
) -> Result<(B::Session, ProvisionTargetResult), ProvisionTargetResult> {
    if cancel.is_cancelled() {
        return Err(ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Cancellation,
            "remote provision action was cancelled before dispatch",
        )
        .with_context(Some(context.phase), Some(context.action)));
    }
    let phase = context.phase;
    let action = context.action;
    let success_phase = phase.clone();
    let success_action = action.clone();
    let opened = guard_connect_boundary(
        ConnectBoundary::FreshCanonicalSession,
        target,
        budget_inputs,
        &cancel,
        |child| backend.open_fresh_canonical_session(target.clone(), child),
    )
    .await;
    match opened {
        Ok(Ok(session)) => Ok((
            session,
            ProvisionTargetResult::succeeded(target.machine.clone(), false, false)
                .with_context(Some(success_phase), Some(success_action)),
        )),
        Ok(Err(result)) | Err(result) => Err(result.with_context(Some(phase), Some(action))),
    }
}

async fn run_public_key_only_probe<B: ProvisionBackend>(
    backend: &B,
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    budget_inputs: ConnectBudgetInputs,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    if cancel.is_cancelled() {
        return ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Cancellation,
            "remote provision action was cancelled before dispatch",
        )
        .with_context(Some(context.phase), Some(context.action));
    }
    guard_connect_boundary(
        ConnectBoundary::PublicKeyOnlyProbe,
        target,
        budget_inputs,
        &cancel,
        |child| backend.prove_public_key_only(target.clone(), child),
    )
    .await
    .unwrap_or_else(|expiry| expiry)
    .with_context(Some(context.phase), Some(context.action))
}

async fn run_sftp_gate_probe<B: ProvisionBackend>(
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    if cancel.is_cancelled() {
        return ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Cancellation,
            "remote provision action was cancelled before dispatch",
        )
        .with_context(Some(context.phase), Some(context.action));
    }
    let child = cancel.child();
    let probed = guard_inline_boundary(
        command_units(target, 2),
        &child,
        backend.probe_sftp_gate(session, target, child.clone()),
    )
    .await;
    probed
        .unwrap_or_else(|| {
            watchdog_failure(
                target,
                FailureClass::SecurityGate,
                true,
                false,
                "remote provision sftp capability probe made no progress within its \
                 provisioning progress bound",
            )
        })
        .with_context(Some(context.phase), Some(context.action))
}

#[derive(Clone, Copy)]
struct TransitionContext<'a, B: ProvisionBackend> {
    inventory: &'a EffectiveInventory,
    backend: &'a B,
    target: &'a ProvisionTarget,
    plan: &'a ProvisionTargetPlan,
}

#[derive(Clone, Copy, Default)]
struct TransitionFlags {
    dispatched: bool,
    residue: bool,
}

impl TransitionFlags {
    fn merge(&mut self, result: &ProvisionTargetResult) {
        self.dispatched |= result.dispatched;
        self.residue |= result.possible_staging_residue;
    }
}

async fn run_transition_script<B: ProvisionBackend>(
    context: &TransitionContext<'_, B>,
    session: &mut B::Session,
    name: &str,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    let Some(action) = transition_script(context.plan, name) else {
        return ProvisionTargetResult::failure(
            context.target.machine.clone(),
            FailureClass::Configuration,
            format!("provision SSH transition action {name} is not resolved"),
        )
        .with_context(Some("ssh_transition".to_string()), Some(name.to_string()));
    };
    let action_context = ProvisionActionContext {
        phase: "ssh_transition".to_string(),
        action: name.to_string(),
    };
    run_script_action(
        context.inventory,
        context.backend,
        session,
        context.target,
        action,
        action_context,
        cancel,
    )
    .await
}

async fn prove_canonical_access<B: ProvisionBackend>(
    backend: &B,
    target: &ProvisionTarget,
    budget_inputs: ConnectBudgetInputs,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    let context = ProvisionActionContext {
        phase: "ssh_transition".to_string(),
        action: "canonical_proof".to_string(),
    };
    if cancel.is_cancelled() {
        return ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Cancellation,
            "remote provision action was cancelled before dispatch",
        )
        .with_context(Some(context.phase), Some(context.action));
    }
    guard_connect_boundary(
        ConnectBoundary::CanonicalProof,
        target,
        budget_inputs,
        &cancel,
        |child| backend.prove_canonical_access(target.clone(), child),
    )
    .await
    .unwrap_or_else(|expiry| expiry)
    .with_context(Some(context.phase), Some(context.action))
}

async fn rollback_after_transition_failure<B: ProvisionBackend>(
    context: &TransitionContext<'_, B>,
    session: &mut B::Session,
    original: ProvisionTargetResult,
    mut flags: TransitionFlags,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    for name in ["rollback", "reload"] {
        let result = run_transition_script(context, session, name, cancel.clone()).await;
        flags.merge(&result);
        if result.status == ProvisionStatus::Failed {
            return rollback_failure_result(context.target, result, flags);
        }
    }
    with_result_flags(original, flags)
}

fn transition_script<'a>(plan: &'a ProvisionTargetPlan, name: &str) -> Option<&'a ScriptAction> {
    plan.transition_actions
        .iter()
        .find(|action| action.name == name)
        .map(|action| &action.action)
}

fn with_result_flags(
    mut result: ProvisionTargetResult,
    flags: TransitionFlags,
) -> ProvisionTargetResult {
    result.dispatched |= flags.dispatched;
    result.possible_staging_residue |= flags.residue;
    result
}

fn with_accumulated_residue(
    mut result: ProvisionTargetResult,
    residue: bool,
) -> ProvisionTargetResult {
    result.possible_staging_residue |= residue;
    result
}

fn rollback_failure_result(
    target: &ProvisionTarget,
    failed: ProvisionTargetResult,
    flags: TransitionFlags,
) -> ProvisionTargetResult {
    ProvisionTargetResult {
        machine: target.machine.clone(),
        status: ProvisionStatus::Failed,
        failure_class: Some(FailureClass::Rollback),
        diagnostic: Some(
            "SSH transition rollback failed; machine may require out-of-band SSH recovery"
                .to_string(),
        ),
        diagnostic_in_report: true,
        dispatched: flags.dispatched,
        phase: failed.phase,
        action: failed.action,
        remote_status: failed.remote_status,
        remote_signal: failed.remote_signal,
        possible_staging_residue: flags.residue,
    }
}

#[derive(Clone, Copy)]
struct ProvisionRunEnv<'a> {
    root: &'a Path,
    inventory: &'a EffectiveInventory,
    plan: &'a ProvisionTargetPlan,
    budget_inputs: ConnectBudgetInputs,
}

async fn run_step<B: ProvisionBackend>(
    env: ProvisionRunEnv<'_>,
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    step: &ProvisionStep,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    let phase = step.phase.clone();
    let mut dispatched = false;
    let mut residue = false;
    if let Some(check) = &step.check {
        let context = ProvisionActionContext {
            phase: phase.clone(),
            action: format!("{}.check", step.id),
        };
        let result = run_script_action(
            env.inventory,
            backend,
            session,
            target,
            check,
            context,
            cancel.clone(),
        )
        .await;
        dispatched |= result.dispatched;
        residue |= result.possible_staging_residue;
        match check_decision(&result) {
            CheckDecision::Run => {
                let run_context = ProvisionActionContext {
                    phase: phase.clone(),
                    action: format!("{}.run.{}", step.id, step.run.kind()),
                };
                let result = run_provision_action(
                    env,
                    backend,
                    session,
                    target,
                    &step.run,
                    run_context,
                    cancel.clone(),
                )
                .await;
                dispatched |= result.dispatched;
                residue |= result.possible_staging_residue;
                if result.status == ProvisionStatus::Failed {
                    return with_accumulated_residue(result, residue);
                }
            }
            CheckDecision::SkipRun => {}
            CheckDecision::Stop(result) => return result,
        }
    } else {
        let context = ProvisionActionContext {
            phase: phase.clone(),
            action: format!("{}.run.{}", step.id, step.run.kind()),
        };
        let result = run_provision_action(
            env,
            backend,
            session,
            target,
            &step.run,
            context,
            cancel.clone(),
        )
        .await;
        dispatched |= result.dispatched;
        residue |= result.possible_staging_residue;
        if result.status == ProvisionStatus::Failed {
            return result;
        }
    }
    if let Some(verify) = &step.verify {
        let context = ProvisionActionContext {
            phase,
            action: format!("{}.verify", step.id),
        };
        let result = run_script_action(
            env.inventory,
            backend,
            session,
            target,
            verify,
            context,
            cancel,
        )
        .await;
        dispatched |= result.dispatched;
        residue |= result.possible_staging_residue;
        if result.status == ProvisionStatus::Failed {
            return with_accumulated_residue(result, residue);
        }
    }
    ProvisionTargetResult::succeeded(target.machine.clone(), dispatched, residue)
}

async fn run_provision_action<B: ProvisionBackend>(
    env: ProvisionRunEnv<'_>,
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    action: &ProvisionAction,
    context: ProvisionActionContext,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    match action {
        ProvisionAction::Script(script) => {
            run_script_action(
                env.inventory,
                backend,
                session,
                target,
                script,
                context,
                cancel,
            )
            .await
        }
        ProvisionAction::CopyTo(copy_to) => {
            let job = upload_transfer_job(env.root, target, copy_to);
            run_transfer_action(backend, session, target, job, context, cancel).await
        }
        ProvisionAction::CopyFrom(copy_from) => {
            let job = download_transfer_job(env.root, target, copy_from);
            run_transfer_action(backend, session, target, job, context, cancel).await
        }
        ProvisionAction::Reboot(reboot) => {
            run_reboot_action(env, backend, session, target, reboot, context, cancel).await
        }
        ProvisionAction::Local(local) => {
            run_local_action(env, backend, session, target, local, context, cancel).await
        }
    }
}

async fn run_reboot_action<B: ProvisionBackend>(
    env: ProvisionRunEnv<'_>,
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    action: &RebootAction,
    context: ProvisionActionContext,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    let mut flags = TransitionFlags::default();
    if let Some(when) = &action.when {
        let when_context = ProvisionActionContext {
            phase: context.phase.clone(),
            action: format!("{}.when", context.action),
        };
        let result = run_script_action(
            env.inventory,
            backend,
            session,
            target,
            when,
            when_context,
            cancel.clone(),
        )
        .await;
        flags.merge(&result);
        match reboot_when_decision(&result) {
            RebootWhenDecision::Run => {}
            RebootWhenDecision::Skip => {
                return with_result_flags(
                    ProvisionTargetResult::succeeded(target.machine.clone(), false, false),
                    flags,
                );
            }
            RebootWhenDecision::Stop => return with_result_flags(result, flags),
        }
    }

    if cancel.is_cancelled() {
        return with_result_flags(
            ProvisionTargetResult::failure(
                target.machine.clone(),
                FailureClass::Cancellation,
                "remote provision action was cancelled before dispatch",
            )
            .with_context(Some(context.phase), Some(context.action)),
            flags,
        );
    }

    let disconnect_deadline =
        tokio::time::Instant::now() + duration_value(&action.disconnect_timeout);
    let pacing = backend.input_pacing(ProvisionInputQuery::PrivilegeProfile(
        action.privilege.as_deref(),
    ));
    let invocation = ProvisionRebootInvocation {
        action: action.clone(),
    };
    let request = if pacing == ProvisionInputPacing::Human {
        GuardedAction {
            result: backend
                .request_reboot(session, target, invocation, context.clone(), cancel.clone())
                .await,
            stopped: false,
        }
    } else {
        let request_context = context.clone();
        guard_action(
            ActionBoundary::RebootRequest,
            target,
            &request_context,
            duration_value(&action.disconnect_timeout),
            pacing == ProvisionInputPacing::Machine,
            &cancel,
            |child| {
                backend.request_reboot(session, target, invocation, request_context.clone(), child)
            },
        )
        .await
    };
    flags.merge(&request.result);
    if request.stopped {
        return with_result_flags(request.result, flags);
    }
    let request = request.result;
    if !reboot_request_can_wait_for_disconnect(&request) {
        return with_result_flags(request, flags);
    }

    let disconnect = wait_for_reboot_disconnect(
        backend,
        session,
        target,
        disconnect_deadline,
        context.clone(),
        cancel.clone(),
    )
    .await;
    flags.merge(&disconnect);
    if disconnect.status == ProvisionStatus::Failed {
        return with_result_flags(disconnect, flags);
    }

    match wait_for_reboot_readiness(
        env.inventory,
        backend,
        target,
        env.plan,
        action,
        env.budget_inputs,
        context.clone(),
        cancel,
    )
    .await
    {
        Ok(success) => {
            flags.merge(&success.result);
            *session = success.session;
            with_result_flags(
                ProvisionTargetResult::succeeded(target.machine.clone(), false, false)
                    .with_context(Some(context.phase), Some(context.action)),
                flags,
            )
        }
        Err(result) => {
            flags.merge(&result);
            with_result_flags(
                result.with_context(Some(context.phase), Some(context.action)),
                flags,
            )
        }
    }
}

enum RebootWhenDecision {
    Run,
    Skip,
    Stop,
}

fn reboot_when_decision(result: &ProvisionTargetResult) -> RebootWhenDecision {
    if result.status == ProvisionStatus::Succeeded {
        return RebootWhenDecision::Run;
    }
    if result.dispatched
        && result.failure_class == Some(FailureClass::RemoteNonzero)
        && result.remote_status.is_some_and(|status| status != 0)
        && result.remote_signal.is_none()
    {
        return RebootWhenDecision::Skip;
    }
    RebootWhenDecision::Stop
}

fn reboot_request_can_wait_for_disconnect(result: &ProvisionTargetResult) -> bool {
    result.status == ProvisionStatus::Succeeded
        || (result.dispatched
            && result.failure_class == Some(FailureClass::IndeterminateAfterDispatch))
}

async fn wait_for_reboot_disconnect<B: ProvisionBackend>(
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    deadline: tokio::time::Instant,
    context: ProvisionActionContext,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    loop {
        if cancel.is_cancelled() {
            return ProvisionTargetResult::failure(
                target.machine.clone(),
                FailureClass::Cancellation,
                "remote provision action was cancelled after reboot dispatch",
            )
            .with_context(Some(context.phase), Some(context.action));
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return reboot_timeout_result(
                target,
                &context,
                "reboot disconnect was not observed before the configured timeout",
            );
        }
        if backend.target_session_is_closed(session) {
            return ProvisionTargetResult::succeeded(target.machine.clone(), false, false);
        }
        sleep_or_cancel(
            deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(250)),
            &cancel,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_reboot_readiness<B: ProvisionBackend>(
    inventory: &EffectiveInventory,
    backend: &B,
    target: &ProvisionTarget,
    plan: &ProvisionTargetPlan,
    action: &RebootAction,
    budget_inputs: ConnectBudgetInputs,
    context: ProvisionActionContext,
    cancel: CancellationToken,
) -> Result<SecurityGateSuccess<B::Session>, ProvisionTargetResult> {
    let deadline = tokio::time::Instant::now() + duration_value(&action.readiness_timeout);
    loop {
        if cancel.is_cancelled() {
            return Err(ProvisionTargetResult::failure(
                target.machine.clone(),
                FailureClass::Cancellation,
                "remote provision action was cancelled while waiting for reboot readiness",
            ));
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(reboot_timeout_result(
                target,
                &context,
                "reboot readiness was not proved before the configured timeout",
            ));
        }
        match tokio::time::timeout_at(
            deadline,
            run_security_gate(
                inventory,
                backend,
                target,
                plan,
                budget_inputs,
                cancel.clone(),
            ),
        )
        .await
        {
            Ok(Ok(success)) => return Ok(success),
            Ok(Err(result)) if reboot_readiness_retryable(&result) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(reboot_timeout_result(
                        target,
                        &context,
                        "reboot readiness was not proved before the configured timeout",
                    ));
                }
                sleep_or_cancel(
                    deadline
                        .saturating_duration_since(now)
                        .min(duration_value(&action.poll_interval)),
                    &cancel,
                )
                .await;
            }
            Ok(Err(result)) => return Err(result),
            Err(_) => {
                return Err(reboot_timeout_result(
                    target,
                    &context,
                    "reboot readiness was not proved before the configured timeout",
                ));
            }
        }
    }
}

fn reboot_readiness_retryable(result: &ProvisionTargetResult) -> bool {
    result.phase.as_deref() == Some("security_gate")
        && result.action.as_deref() == Some("fresh_canonical_session")
        && matches!(
            result.failure_class,
            Some(
                FailureClass::Dns
                    | FailureClass::ConnectTimeout
                    | FailureClass::AuthenticationTimeout
                    | FailureClass::JumpFailure
                    | FailureClass::Protocol
            )
        )
}

fn reboot_timeout_result(
    target: &ProvisionTarget,
    context: &ProvisionActionContext,
    diagnostic: &str,
) -> ProvisionTargetResult {
    ProvisionTargetResult::failure(
        target.machine.clone(),
        FailureClass::RebootTimeout,
        diagnostic,
    )
    .with_context(Some(context.phase.clone()), Some(context.action.clone()))
}

async fn sleep_or_cancel(duration: Duration, cancel: &CancellationToken) {
    if duration.is_zero() {
        tokio::task::yield_now().await;
        return;
    }
    tokio::select! {
        _ = tokio::time::sleep(duration) => {}
        _ = cancel.cancelled() => {}
    }
}


enum GuardOutcome<T> {
    Returned(T),
    Expired(Option<T>),
}

fn command_units(target: &ProvisionTarget, units: u32) -> Duration {
    duration_value(&target.command_timeout).saturating_mul(units)
}

fn connect_plus_command_units(target: &ProvisionTarget, units: u32) -> Duration {
    duration_value(&target.connect_timeout).saturating_add(command_units(target, units))
}

fn watchdog_failure(
    target: &ProvisionTarget,
    class: FailureClass,
    dispatched: bool,
    residue: bool,
    diagnostic: impl Into<String>,
) -> ProvisionTargetResult {
    let mut result = ProvisionTargetResult::failure(target.machine.clone(), class, diagnostic);
    result.dispatched = dispatched;
    result.possible_staging_residue = residue;
    result.diagnostic_in_report = true;
    result
}

async fn guard_spawned_boundary<T, F>(
    budget: Duration,
    cooperative: Duration,
    child: &CancellationToken,
    future: F,
) -> GuardOutcome<T>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let mut handle = tokio::task::spawn(future);
    match tokio::time::timeout(budget, &mut handle).await {
        Ok(joined) => GuardOutcome::Returned(join_boundary(joined)),
        Err(_) => {
            child.cancel();
            match tokio::time::timeout(cooperative, &mut handle).await {
                Ok(joined) => GuardOutcome::Expired(Some(join_boundary(joined))),
                Err(_) => {
                    handle.abort();
                    child.drain_store_workers();
                    GuardOutcome::Expired(None)
                }
            }
        }
    }
}

fn join_boundary<T>(joined: Result<T, tokio::task::JoinError>) -> T {
    match joined {
        Ok(value) => value,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => panic!("remote provision boundary task failed: {error}"),
    }
}

async fn guard_inline_boundary<T, F>(
    budget: Duration,
    child: &CancellationToken,
    future: F,
) -> Option<T>
where
    F: Future<Output = T>,
{
    match tokio::time::timeout(budget, future).await {
        Ok(value) => Some(value),
        Err(_) => {
            child.cancel();
            None
        }
    }
}

async fn guard_action_boundary<T, F>(
    budget: Duration,
    grace: Duration,
    child: &CancellationToken,
    future: F,
) -> GuardOutcome<T>
where
    F: Future<Output = T>,
{
    tokio::pin!(future);
    match tokio::time::timeout(budget, &mut future).await {
        Ok(value) => GuardOutcome::Returned(value),
        Err(_) => {
            child.cancel();
            match tokio::time::timeout(grace, &mut future).await {
                Ok(value) => GuardOutcome::Expired(Some(value)),
                Err(_) => GuardOutcome::Expired(None),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConnectBudgetInputs {
    chain_human_paced: usize,
    canonical_human_paced: usize,
    concurrency: usize,
}

impl ConnectBudgetInputs {
    fn chain_allotment(self) -> u32 {
        saturating_units(self.chain_human_paced.saturating_mul(self.concurrency))
    }

    fn canonical_allotment(self) -> u32 {
        saturating_units(self.canonical_human_paced.saturating_mul(self.concurrency))
    }
}

fn connect_budget_inputs<B: ProvisionBackend>(
    backend: &B,
    target: &ProvisionTarget,
    concurrency: usize,
) -> ConnectBudgetInputs {
    let canonical_human_paced =
        backend.human_paced_authentication_resolutions(&target.canonical_profile);
    let chain_human_paced =
        target
            .bootstrap_profiles
            .iter()
            .fold(canonical_human_paced, |sum, auth| {
                sum.saturating_add(backend.human_paced_authentication_resolutions(&auth.profile))
            });
    ConnectBudgetInputs {
        chain_human_paced,
        canonical_human_paced,
        concurrency,
    }
}

fn saturating_units(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn connect_units_plus_command_units(
    target: &ProvisionTarget,
    connects: u32,
    commands: u32,
) -> Duration {
    duration_value(&target.connect_timeout)
        .saturating_mul(connects)
        .saturating_add(command_units(target, commands))
}

#[derive(Clone, Copy)]
enum ConnectBoundary {
    Connect,
    FreshCanonicalSession,
    CanonicalProof,
    PublicKeyOnlyProbe,
}

impl ConnectBoundary {
    fn budget(self, target: &ProvisionTarget, inputs: ConnectBudgetInputs) -> Duration {
        match self {
            Self::Connect => connect_units_plus_command_units(
                target,
                2u32.saturating_add(
                    saturating_units(target.bootstrap_profiles.len()).saturating_mul(2),
                ),
                2u32.saturating_add(inputs.chain_allotment()),
            ),
            Self::FreshCanonicalSession => connect_units_plus_command_units(
                target,
                2,
                2u32.saturating_add(inputs.canonical_allotment()),
            ),
            Self::CanonicalProof => connect_units_plus_command_units(
                target,
                2,
                4u32.saturating_add(inputs.canonical_allotment()),
            ),
            Self::PublicKeyOnlyProbe => connect_plus_command_units(target, 5),
        }
    }

    fn expiry(self, target: &ProvisionTarget) -> ProvisionTargetResult {
        match self {
            Self::Connect | Self::FreshCanonicalSession | Self::CanonicalProof => watchdog_failure(
                target,
                FailureClass::ConnectTimeout,
                false,
                false,
                "remote provision target connection made no progress within its \
                 provisioning progress bound",
            ),
            Self::PublicKeyOnlyProbe => watchdog_failure(
                target,
                FailureClass::SecurityGate,
                true,
                false,
                "remote provision public-key-only probe made no progress within its \
                 provisioning progress bound after dispatch",
            ),
        }
    }
}

async fn guard_connect_boundary<T, F>(
    boundary: ConnectBoundary,
    target: &ProvisionTarget,
    budget_inputs: ConnectBudgetInputs,
    job_cancel: &CancellationToken,
    build: impl FnOnce(CancellationToken) -> F,
) -> Result<T, ProvisionTargetResult>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let child = job_cancel.child();
    let future = build(child.clone());
    match guard_spawned_boundary(
        boundary.budget(target, budget_inputs),
        duration_value(&target.command_timeout),
        &child,
        future,
    )
    .await
    {
        GuardOutcome::Returned(value) => Ok(value),
        GuardOutcome::Expired(Some(value)) if job_cancel.is_cancelled() => Ok(value),
        GuardOutcome::Expired(_) => Err(boundary.expiry(target)),
    }
}

async fn guard_disconnect<B: ProvisionBackend>(
    backend: &B,
    target: &ProvisionTarget,
    session: B::Session,
    job_cancel: &CancellationToken,
) {
    let child = job_cancel.child();
    let _ = guard_spawned_boundary(
        command_units(target, 3),
        duration_value(&target.command_timeout),
        &child,
        backend.disconnect(session),
    )
    .await;
}

#[derive(Clone, Copy)]
enum ActionBoundary {
    Script,
    RebootRequest,
    Local,
}

impl ActionBoundary {
    fn kind(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::RebootRequest => "reboot request",
            Self::Local => "local",
        }
    }

    fn budget(
        self,
        target: &ProvisionTarget,
        action_timeout: Duration,
        armed_finalize: bool,
    ) -> Duration {
        let units = match self {
            Self::Script => 6,
            Self::RebootRequest => 5,
            Self::Local => 3,
        };
        let units = units + u32::from(armed_finalize);
        action_timeout.saturating_add(command_units(target, units))
    }

    fn grace(self, target: &ProvisionTarget, armed_finalize: bool) -> Duration {
        command_units(target, 4 + u32::from(armed_finalize))
    }

    fn synthesized(self, target: &ProvisionTarget) -> ProvisionTargetResult {
        let mut diagnostic = format!(
            "remote provision {} action made no progress within its provisioning progress \
             bound and was stopped after dispatch; cleanup is unproved and the session state \
             after the stop is unknown",
            self.kind()
        );
        if matches!(self, Self::Local) {
            diagnostic.push_str("; the direct child was killed without its exit status observed");
        }
        watchdog_failure(
            target,
            FailureClass::IndeterminateAfterDispatch,
            true,
            true,
            diagnostic,
        )
    }

    fn stopped_success(self, target: &ProvisionTarget) -> ProvisionTargetResult {
        watchdog_failure(
            target,
            FailureClass::IndeterminateAfterDispatch,
            true,
            true,
            format!(
                "remote provision {} action reported no failure only after it was stopped by \
                 its provisioning progress bound; cleanup is unproved and the session state \
                 after the stop is unknown",
                self.kind()
            ),
        )
    }
}

fn stopped_action_result(
    mut result: ProvisionTargetResult,
    boundary: ActionBoundary,
    job_cancelled: bool,
) -> ProvisionTargetResult {
    if !job_cancelled && result.failure_class == Some(FailureClass::Cancellation) {
        result.failure_class = Some(if result.dispatched {
            FailureClass::IndeterminateAfterDispatch
        } else {
            match boundary {
                ActionBoundary::Script | ActionBoundary::RebootRequest => FailureClass::Protocol,
                ActionBoundary::Local => FailureClass::Cancellation,
            }
        });
    }
    let note = format!(
        "remote provision {} action was stopped by its provisioning progress bound; the \
         session state after the stop is unknown",
        boundary.kind()
    );
    result.diagnostic = Some(match result.diagnostic.take() {
        Some(diagnostic) => format!("{diagnostic}; {note}"),
        None => note,
    });
    result.diagnostic_in_report = true;
    result
}

struct GuardedAction {
    result: ProvisionTargetResult,
    stopped: bool,
}

async fn guard_action<F>(
    boundary: ActionBoundary,
    target: &ProvisionTarget,
    context: &ProvisionActionContext,
    action_timeout: Duration,
    armed_finalize: bool,
    job_cancel: &CancellationToken,
    build: impl FnOnce(CancellationToken) -> F,
) -> GuardedAction
where
    F: Future<Output = ProvisionTargetResult>,
{
    let child = job_cancel.child();
    let future = build(child.clone());
    match guard_action_boundary(
        boundary.budget(target, action_timeout, armed_finalize),
        boundary.grace(target, armed_finalize),
        &child,
        future,
    )
    .await
    {
        GuardOutcome::Returned(result) => GuardedAction {
            result,
            stopped: false,
        },
        GuardOutcome::Expired(Some(result)) => GuardedAction {
            result: if result.status == ProvisionStatus::Failed {
                stopped_action_result(result, boundary, job_cancel.is_cancelled())
            } else {
                boundary
                    .stopped_success(target)
                    .with_context(Some(context.phase.clone()), Some(context.action.clone()))
            },
            stopped: true,
        },
        GuardOutcome::Expired(None) => GuardedAction {
            result: boundary
                .synthesized(target)
                .with_context(Some(context.phase.clone()), Some(context.action.clone())),
            stopped: true,
        },
    }
}

fn duration_value(value: &DurationValue) -> Duration {
    Duration::from_secs(value.seconds)
}

async fn run_transfer_action<B: ProvisionBackend>(
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    job: crate::transfer::TransferJob,
    context: ProvisionActionContext,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    if cancel.is_cancelled() {
        return ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Cancellation,
            "remote provision action was cancelled before dispatch",
        )
        .with_context(Some(context.phase), Some(context.action));
    }
    backend
        .run_transfer(
            session,
            target,
            ProvisionTransferInvocation { job },
            context,
            cancel,
        )
        .await
}

async fn run_local_action<B: ProvisionBackend>(
    env: ProvisionRunEnv<'_>,
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    action: &LocalAction,
    context: ProvisionActionContext,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    if context.phase != "configure" {
        return unsupported_action_result(
            target,
            context,
            action_kind_local(),
            FailureClass::Configuration,
        );
    }
    if cancel.is_cancelled() {
        return ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Cancellation,
            "remote provision action was cancelled before dispatch",
        )
        .with_context(Some(context.phase), Some(context.action));
    }
    let invocation = ProvisionLocalInvocation {
        action: action.clone(),
        root: env.root.to_path_buf(),
        environment: env.inventory.environment.clone(),
        env_vars: env.inventory.env_vars.clone(),
    };
    let action_timeout = duration_value(&action.timeout);
    let guard_context = context.clone();
    guard_action(
        ActionBoundary::Local,
        target,
        &guard_context,
        action_timeout,
        false,
        &cancel,
        |child| backend.run_local(session, target, invocation, context, child),
    )
    .await
    .result
}

async fn run_script_action<B: ProvisionBackend>(
    inventory: &EffectiveInventory,
    backend: &B,
    session: &mut B::Session,
    target: &ProvisionTarget,
    action: &ScriptAction,
    context: ProvisionActionContext,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    if cancel.is_cancelled() {
        return ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Cancellation,
            "remote provision action was cancelled before dispatch",
        )
        .with_context(Some(context.phase), Some(context.action));
    }
    let invocation = match script_invocation(inventory, target, action) {
        Ok(invocation) => invocation,
        Err(result) => return (*result).with_context(Some(context.phase), Some(context.action)),
    };
    let invocation =
        match resolve_script_stdin(backend, target, invocation, &context, cancel.clone()).await {
            Ok(invocation) => invocation,
            Err(result) => return result,
        };
    let pacing = backend.input_pacing(ProvisionInputQuery::PrivilegeProfile(
        invocation.action.privilege.as_deref(),
    ));
    if pacing == ProvisionInputPacing::Human {
        return backend
            .run_script(session, target, invocation, context, cancel)
            .await;
    }
    let action_timeout = duration_value(&invocation.action.timeout);
    let armed_finalize = pacing == ProvisionInputPacing::Machine;
    let guard_context = context.clone();
    guard_action(
        ActionBoundary::Script,
        target,
        &guard_context,
        action_timeout,
        armed_finalize,
        &cancel,
        |child| backend.run_script(session, target, invocation, context, child),
    )
    .await
    .result
}

fn action_kind_local() -> &'static str {
    "local"
}

enum CheckDecision {
    SkipRun,
    Run,
    Stop(ProvisionTargetResult),
}

fn check_decision(result: &ProvisionTargetResult) -> CheckDecision {
    if result.status == ProvisionStatus::Succeeded {
        return CheckDecision::SkipRun;
    }
    if result.dispatched
        && result.failure_class == Some(FailureClass::RemoteNonzero)
        && result.remote_status.is_some_and(|status| status != 0)
        && result.remote_signal.is_none()
    {
        return CheckDecision::Run;
    }
    CheckDecision::Stop(result.clone())
}

fn script_invocation(
    inventory: &EffectiveInventory,
    target: &ProvisionTarget,
    action: &ScriptAction,
) -> Result<ProvisionScriptInvocation, Box<ProvisionTargetResult>> {
    let Some(script) = inventory.scripts.get(&action.script) else {
        return Err(Box::new(ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Configuration,
            format!("unknown remote script {}", action.script),
        )));
    };
    if script.pty == PtyMode::Always {
        return Err(Box::new(ProvisionTargetResult::failure(
            target.machine.clone(),
            FailureClass::Configuration,
            format!("provision script {} requires a PTY", action.script),
        )));
    }
    let mut env = BTreeMap::new();
    for (name, source) in &script.env {
        let value = match source {
            RemoteEnvValue::Value(value) => value,
            RemoteEnvValue::FromEnv(name) => inventory.env_vars.get(name).ok_or_else(|| {
                Box::new(ProvisionTargetResult::failure(
                    target.machine.clone(),
                    FailureClass::Configuration,
                    format!("remote script env source {name} is not defined"),
                ))
            })?,
            RemoteEnvValue::FromMachine(name) => target.vars.get(name).ok_or_else(|| {
                Box::new(ProvisionTargetResult::failure(
                    target.machine.clone(),
                    FailureClass::Configuration,
                    format!("remote script machine var {name} is not defined"),
                ))
            })?,
        };
        env.insert(name.clone(), value.as_bytes().to_vec());
    }
    env.insert(
        "BROIL_ENV".to_string(),
        inventory.environment.as_bytes().to_vec(),
    );
    env.insert(
        "BROIL_MACHINE".to_string(),
        target.machine.as_bytes().to_vec(),
    );
    let body = script.body.as_bytes().to_vec();
    let interpreter = if crate::staging::body_has_shebang(&body) {
        None
    } else {
        Some(
            script
                .interpreter
                .as_ref()
                .unwrap_or(&inventory.default_interpreter)
                .iter()
                .map(|arg| arg.as_bytes().to_vec())
                .collect(),
        )
    };
    let cwd_nonce = if script.cwd.is_some() {
        crate::path_safety::sudo_nonce().map_err(|_| {
            Box::new(ProvisionTargetResult::failure(
                target.machine.clone(),
                FailureClass::CapabilityUnsupported,
                "cwd control-frame nonce generation failed",
            ))
        })?
    } else {
        String::new()
    };
    Ok(ProvisionScriptInvocation {
        command: crate::exec::RemoteScriptCommand {
            body,
            interpreter,
            cwd: script.cwd.as_ref().map(|cwd| cwd.as_bytes().to_vec()),
            cwd_display: script.cwd.clone(),
            cwd_nonce,
            env,
            args: Vec::new(),
        },
        action: action.clone(),
        stdin: None,
    })
}

async fn resolve_script_stdin<B: ProvisionBackend>(
    backend: &B,
    target: &ProvisionTarget,
    mut invocation: ProvisionScriptInvocation,
    context: &ProvisionActionContext,
    cancel: CancellationToken,
) -> Result<ProvisionScriptInvocation, ProvisionTargetResult> {
    let Some(ScriptStdin::Secret { provider }) = invocation.action.stdin.as_ref() else {
        return Ok(invocation);
    };
    let provider = provider.clone();
    let armed = backend.input_pacing(ProvisionInputQuery::SecretProvider(&provider))
        != ProvisionInputPacing::Human;
    let child = cancel.child();
    let resolved = if armed {
        guard_inline_boundary(
            command_units(target, 2),
            &child,
            backend.resolve_secret_stdin(&provider, child.clone()),
        )
        .await
    } else {
        Some(backend.resolve_secret_stdin(&provider, cancel).await)
    };
    match resolved {
        Some(Ok(stdin)) => {
            invocation.stdin = Some(stdin);
            Ok(invocation)
        }
        Some(Err(error)) => Err(ProvisionTargetResult::failure(
            target.machine.clone(),
            error.class(),
            "provisioning secret stdin provider unavailable",
        )
        .with_context(Some(context.phase.clone()), Some(context.action.clone()))),
        None => Err(watchdog_failure(
            target,
            FailureClass::SecretUnavailable,
            false,
            false,
            "provisioning secret stdin resolution made no progress within its \
             provisioning progress bound",
        )
        .with_context(Some(context.phase.clone()), Some(context.action.clone()))),
    }
}

fn provision_known_hosts_store(
    known_hosts: &ResolvedKnownHosts,
) -> Result<crate::known_hosts::KnownHostsStore, crate::ssh::SshError> {
    let result = match known_hosts.source {
        KnownHostsSource::DefaultHome => {
            crate::known_hosts::KnownHostsStore::open_default(&known_hosts.path)
        }
        KnownHostsSource::Override => {
            crate::known_hosts::KnownHostsStore::open_override(&known_hosts.path)
        }
    };
    result.map_err(|error| crate::ssh::SshError::new(error.class(), error.to_string()))
}

fn local_child_environment(
    base: &[(OsString, OsString)],
    env_vars: &BTreeMap<String, String>,
    root: &Path,
    environment_name: &str,
    machine: &str,
    ssh_config: &Path,
    ssh_host: &str,
) -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    for (name, value) in base {
        if local_reserved_env(name) {
            continue;
        }
        environment.insert(name.clone(), value.clone());
    }
    for (name, value) in env_vars {
        environment.insert(OsString::from(name), OsString::from(value));
    }
    environment.insert(
        OsString::from("BROIL_ROOT"),
        root.as_os_str().to_os_string(),
    );
    environment.insert(
        OsString::from("BROIL_ENV"),
        OsString::from(environment_name),
    );
    environment.insert(OsString::from("BROIL_MACHINE"), OsString::from(machine));
    environment.insert(
        OsString::from("BROIL_SSH_CONFIG"),
        ssh_config.as_os_str().to_os_string(),
    );
    environment.insert(OsString::from("BROIL_SSH_HOST"), OsString::from(ssh_host));
    environment
}

fn local_reserved_env(name: &OsString) -> bool {
    matches!(
        name.to_str(),
        Some("BROIL_ROOT" | "BROIL_ENV" | "BROIL_MACHINE" | "BROIL_SSH_CONFIG" | "BROIL_SSH_HOST")
    )
}

async fn run_local_child(
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    invocation: ProvisionLocalInvocation,
    environment: BTreeMap<OsString, OsString>,
    mut handoff: LocalHandoffGuard,
    cancel: CancellationToken,
) -> ProvisionTargetResult {
    let Some((program, args)) = invocation.action.command.split_first() else {
        let residue = handoff.cleanup().await;
        return local_failure(
            target,
            context,
            FailureClass::Configuration,
            "remote provision local action command is empty",
            false,
            residue,
        );
    };
    if cancel.is_cancelled() {
        let residue = handoff.cleanup().await;
        return local_failure(
            target,
            context,
            FailureClass::Cancellation,
            "remote provision action was cancelled before dispatch",
            false,
            residue,
        );
    }

    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .current_dir(&invocation.root)
        .env_clear()
        .envs(environment.iter())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let residue = handoff.cleanup().await;
            return local_failure(
                target,
                context,
                FailureClass::Configuration,
                format!("cannot launch remote provision local action: {error}"),
                false,
                residue,
            );
        }
    };

    let deadline = tokio::time::Instant::now() + duration_value(&invocation.action.timeout);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let residue = handoff.cleanup().await;
                return local_status_result(target, context, status, residue);
            }
            Ok(None) => {}
            Err(error) => {
                let residue = handoff.cleanup().await;
                return local_failure(
                    target,
                    context,
                    FailureClass::IndeterminateAfterDispatch,
                    format!("cannot wait for remote provision local action: {error}"),
                    true,
                    residue,
                );
            }
        }
        if cancel.is_cancelled() {
            kill_and_reap_local_child(&mut child).await;
            let residue = handoff.cleanup().await;
            return local_failure(
                target,
                context,
                FailureClass::Cancellation,
                "remote provision action was cancelled after local child dispatch",
                true,
                residue,
            );
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            kill_and_reap_local_child(&mut child).await;
            let residue = handoff.cleanup().await;
            return local_failure(
                target,
                context,
                FailureClass::IndeterminateAfterDispatch,
                "remote provision local action timed out after dispatch",
                true,
                residue,
            );
        }
        let sleep = deadline
            .saturating_duration_since(now)
            .min(Duration::from_millis(50));
        tokio::select! {
            _ = tokio::time::sleep(sleep) => {}
            _ = cancel.cancelled() => {}
        }
    }
}

async fn kill_and_reap_local_child(child: &mut tokio::process::Child) {
    if let Some(pid) = child
        .id()
        .and_then(|id| rustix::process::Pid::from_raw(id as i32))
    {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    }
    let _ = child.wait().await;
}

enum LocalHandoffError {
    Preflight(crate::ssh::SshError),
    Worker,
}

async fn prepare_local_openssh_handoff(
    target: &ProvisionTarget,
    home: &Path,
    auth_context: &crate::auth::AuthContext,
) -> Result<crate::ssh::ProvisionLocalOpenSshHandoff, LocalHandoffError> {
    let target = target.clone();
    let home = home.to_path_buf();
    let auth_context = auth_context.clone();
    match tokio::task::spawn_blocking(move || {
        let store = provision_known_hosts_store(&target.known_hosts)?;
        crate::ssh::prepare_provision_local_openssh_handoff(&target, &home, &store, &auth_context)
    })
    .await
    {
        Ok(Ok(handoff)) => Ok(handoff),
        Ok(Err(error)) => Err(LocalHandoffError::Preflight(error)),
        Err(_) => Err(LocalHandoffError::Worker),
    }
}

struct LocalHandoffGuard {
    handoff: Option<crate::ssh::ProvisionLocalOpenSshHandoff>,
}

impl LocalHandoffGuard {
    fn new(handoff: crate::ssh::ProvisionLocalOpenSshHandoff) -> Self {
        Self {
            handoff: Some(handoff),
        }
    }

    async fn cleanup(&mut self) -> bool {
        let Some(handoff) = self.handoff.take() else {
            return false;
        };
        match tokio::task::spawn_blocking(move || handoff.cleanup()).await {
            Ok(result) => result.is_err(),
            Err(_) => true,
        }
    }
}

impl Drop for LocalHandoffGuard {
    fn drop(&mut self) {
        let Some(handoff) = self.handoff.take() else {
            return;
        };
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(move || {
                    let _ = handoff.cleanup();
                });
            }
            Err(_) => {
                let _ = handoff.cleanup();
            }
        }
    }
}

fn local_status_result(
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    status: std::process::ExitStatus,
    residue: bool,
) -> ProvisionTargetResult {
    if status.success() {
        return ProvisionTargetResult::succeeded(target.machine.clone(), true, residue)
            .with_context(Some(context.phase), Some(context.action));
    }
    if let Some(code) = status.code() {
        return local_failure(
            target,
            context,
            FailureClass::Configuration,
            format!("remote provision local action exited with status {code}"),
            true,
            residue,
        );
    }
    if let Some(signal) = status.signal() {
        return local_failure(
            target,
            context,
            FailureClass::Configuration,
            format!("remote provision local action terminated by signal {signal}"),
            true,
            residue,
        );
    }
    local_failure(
        target,
        context,
        FailureClass::IndeterminateAfterDispatch,
        "remote provision local action ended without an exit status",
        true,
        residue,
    )
}

fn local_failure(
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    class: FailureClass,
    diagnostic: impl Into<String>,
    dispatched: bool,
    residue: bool,
) -> ProvisionTargetResult {
    let mut result = ProvisionTargetResult::failure(target.machine.clone(), class, diagnostic)
        .with_context(Some(context.phase), Some(context.action));
    result.dispatched = dispatched;
    result.possible_staging_residue = residue;
    result
}

fn unsupported_action_result(
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    kind: &str,
    class: FailureClass,
) -> ProvisionTargetResult {
    ProvisionTargetResult::failure(
        target.machine.clone(),
        class,
        format!("remote provision {kind} action is not available in this phase"),
    )
    .with_context(Some(context.phase), Some(context.action))
}

fn exec_target_for_script(
    target: &ProvisionTarget,
    action: &ScriptAction,
) -> crate::exec::ExecTarget {
    crate::exec::ExecTarget {
        name: target.machine.clone(),
        address: target.address.clone(),
        port: target.port,
        target_alias: target.target_alias.clone(),
        canonical_profile: target.canonical_profile.clone(),
        canonical_user: target.canonical_user.clone(),
        privilege_profile: target.privilege_profile.clone(),
        vars: target.vars.clone(),
        timeouts: script_timeouts(target, &action.timeout),
        route: match &target.jump {
            Some(jump) => crate::exec::ExecRoute::ViaJump(crate::exec::ExecJump {
                name: jump.name.clone(),
                address: jump.address.clone(),
                port: jump.port,
                alias: jump.alias.clone(),
                auth_profile: jump.auth_profile.clone(),
            }),
            None => crate::exec::ExecRoute::Direct,
        },
    }
}

fn exec_target_for_reboot(
    target: &ProvisionTarget,
    action: &RebootAction,
) -> crate::exec::ExecTarget {
    crate::exec::ExecTarget {
        name: target.machine.clone(),
        address: target.address.clone(),
        port: target.port,
        target_alias: target.target_alias.clone(),
        canonical_profile: target.canonical_profile.clone(),
        canonical_user: target.canonical_user.clone(),
        privilege_profile: target.privilege_profile.clone(),
        vars: target.vars.clone(),
        timeouts: script_timeouts(target, &action.disconnect_timeout),
        route: match &target.jump {
            Some(jump) => crate::exec::ExecRoute::ViaJump(crate::exec::ExecJump {
                name: jump.name.clone(),
                address: jump.address.clone(),
                port: jump.port,
                alias: jump.alias.clone(),
                auth_profile: jump.auth_profile.clone(),
            }),
            None => crate::exec::ExecRoute::Direct,
        },
    }
}

fn script_timeouts(target: &ProvisionTarget, timeout: &DurationValue) -> EffectiveTimeouts {
    EffectiveTimeouts {
        connect: target.connect_timeout.clone(),
        command: timeout.clone(),
        transfer: timeout.clone(),
        reboot_disconnect: timeout.clone(),
        reboot_readiness: timeout.clone(),
        reboot_poll: timeout.clone(),
    }
}

fn ssh_result(target: &ProvisionTarget, error: crate::ssh::SshError) -> ProvisionTargetResult {
    let mut result =
        ProvisionTargetResult::failure(target.machine.clone(), error.class(), error.to_string());
    result.diagnostic_in_report = false;
    result
}

fn ssh_probe_result(
    target: &ProvisionTarget,
    error: crate::ssh::SshProbeError,
) -> ProvisionTargetResult {
    ProvisionTargetResult {
        machine: target.machine.clone(),
        status: ProvisionStatus::Failed,
        failure_class: Some(error.class()),
        diagnostic: Some(error.diagnostic().to_string()),
        diagnostic_in_report: true,
        dispatched: error.dispatched(),
        phase: None,
        action: None,
        remote_status: None,
        remote_signal: None,
        possible_staging_residue: false,
    }
}

fn sftp_gate_result(
    target: &ProvisionTarget,
    error: crate::transfer_sftp::TransferSetupError,
) -> ProvisionTargetResult {
    let class = if error.class() == FailureClass::Cancellation {
        FailureClass::Cancellation
    } else {
        FailureClass::SecurityGate
    };
    ProvisionTargetResult {
        machine: target.machine.clone(),
        status: ProvisionStatus::Failed,
        failure_class: Some(class),
        diagnostic: Some(error.diagnostic().to_string()),
        diagnostic_in_report: true,
        dispatched: error.dispatched(),
        phase: None,
        action: None,
        remote_status: None,
        remote_signal: None,
        possible_staging_residue: false,
    }
}

fn security_verifier_result(mut result: ProvisionTargetResult) -> ProvisionTargetResult {
    if result.status == ProvisionStatus::Failed
        && result.failure_class == Some(FailureClass::RemoteNonzero)
    {
        result.failure_class = Some(FailureClass::SecurityGate);
    }
    result
}

fn exec_result(
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    result: crate::exec::ExecTargetResult,
) -> ProvisionTargetResult {
    let status = match result.status {
        crate::exec::TargetStatus::Success => ProvisionStatus::Succeeded,
        crate::exec::TargetStatus::Failed => ProvisionStatus::Failed,
    };
    ProvisionTargetResult {
        machine: target.machine.clone(),
        status,
        failure_class: result.failure_class,
        diagnostic: result.diagnostic,
        diagnostic_in_report: result.diagnostic_in_report,
        dispatched: result.dispatched,
        phase: Some(context.phase),
        action: Some(context.action),
        remote_status: result.remote_status,
        remote_signal: result
            .remote_signal
            .map(|signal| RemoteSignal { name: signal.name }),
        possible_staging_residue: result.possible_staging_residue,
    }
}

fn upload_transfer_job(
    root: &Path,
    target: &ProvisionTarget,
    action: &CopyToAction,
) -> crate::transfer::TransferJob {
    let mut job = provision_transfer_job(
        root,
        target,
        crate::transfer::TransferDirection::Upload,
        action.recursive,
        action.overwrite,
        &action.mode,
        &action.timeout,
        &action.source,
        &action.destination,
    );
    job.owner = action.owner.clone();
    job.privilege = action.privilege.clone();
    job
}

fn download_transfer_job(
    root: &Path,
    target: &ProvisionTarget,
    action: &CopyFromAction,
) -> crate::transfer::TransferJob {
    provision_transfer_job(
        root,
        target,
        crate::transfer::TransferDirection::Download,
        action.recursive,
        action.overwrite,
        &action.mode,
        &action.timeout,
        &action.source,
        &action.destination,
    )
}

#[allow(clippy::too_many_arguments)]
fn provision_transfer_job(
    root: &Path,
    target: &ProvisionTarget,
    direction: crate::transfer::TransferDirection,
    recursive: bool,
    overwrite: bool,
    mode: &Option<String>,
    timeout: &DurationValue,
    source: &str,
    destination: &str,
) -> crate::transfer::TransferJob {
    crate::transfer::TransferJob {
        machine: target.machine.clone(),
        address: target.address.clone(),
        port: target.port,
        target_alias: target.target_alias.clone(),
        route: target.route.clone(),
        jump: target.jump.as_ref().map(transfer_jump),
        canonical_profile: target.canonical_profile.clone(),
        canonical_user: target.canonical_user.clone(),
        direction,
        recursive,
        multi_machine_download: false,
        overwrite,
        mode: mode.clone(),
        owner: None,
        privilege: None,
        known_hosts: transfer_known_hosts(&target.known_hosts),
        caller_cwd: root.to_path_buf(),
        connect_timeout: target.connect_timeout.clone(),
        capability_probe_timeout: target.command_timeout.clone(),
        transfer_timeout: timeout.clone(),
        source: source.as_bytes().to_vec(),
        destination: destination.as_bytes().to_vec(),
    }
}

fn transfer_jump(jump: &ProvisionJump) -> crate::transfer::TransferJump {
    crate::transfer::TransferJump {
        name: jump.name.clone(),
        address: jump.address.clone(),
        port: jump.port,
        alias: jump.alias.clone(),
        auth_profile: jump.auth_profile.clone(),
    }
}

fn transfer_known_hosts(known_hosts: &ResolvedKnownHosts) -> crate::transfer::ResolvedKnownHosts {
    crate::transfer::ResolvedKnownHosts {
        source: match known_hosts.source {
            KnownHostsSource::DefaultHome => crate::transfer::KnownHostsSource::DefaultHome,
            KnownHostsSource::Override => crate::transfer::KnownHostsSource::Override,
        },
        path: known_hosts.path.clone(),
    }
}

fn session_authenticated_user<'a>(target: &'a ProvisionTarget, profile: &str) -> Option<&'a str> {
    if profile == target.canonical_profile {
        return Some(&target.canonical_user);
    }
    target
        .bootstrap_profiles
        .iter()
        .find(|auth| auth.profile == profile)
        .map(|auth| auth.user.as_str())
}

fn transfer_result(
    target: &ProvisionTarget,
    context: ProvisionActionContext,
    result: crate::transfer::TransferTargetResult,
) -> ProvisionTargetResult {
    ProvisionTargetResult {
        machine: target.machine.clone(),
        status: match result.status {
            crate::transfer::TransferStatus::Success => ProvisionStatus::Succeeded,
            crate::transfer::TransferStatus::Failed => ProvisionStatus::Failed,
        },
        failure_class: result.failure_class,
        diagnostic: result.diagnostic,
        diagnostic_in_report: result.diagnostic_in_report,
        dispatched: result.dispatched,
        phase: Some(context.phase),
        action: Some(context.action),
        remote_status: None,
        remote_signal: None,
        possible_staging_residue: result.possible_staging_residue,
    }
}

fn target_not_scheduled(
    machine: impl Into<String>,
    class: FailureClass,
    diagnostic: impl Into<String>,
) -> ProvisionTargetResult {
    ProvisionTargetResult::failure(machine, class, diagnostic)
}

fn plan_job(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &EffectiveMachine,
    request: &ProvisionRequest,
) -> Result<ProvisionJob, ProvisionPlanError> {
    let jump = plan_jump(root, inventory, machine)?;
    let target = ProvisionTarget {
        machine: machine.name.clone(),
        address: machine.address.clone(),
        port: machine.port,
        target_alias: crate::alias::target_alias(root, &inventory.environment, &machine.name),
        route: machine.route.clone(),
        jump,
        canonical_profile: machine.canonical_profile.clone(),
        canonical_user: machine.canonical_user.clone(),
        bootstrap_profiles: machine.bootstrap_profiles.clone(),
        privilege_profile: machine.privilege_profile.clone(),
        provision_profiles: machine.provision_profiles.clone(),
        vars: machine.vars.clone(),
        known_hosts: request.known_hosts.clone(),
        connect_timeout: machine.timeouts.connect.clone(),
        command_timeout: machine.timeouts.command.clone(),
    };
    let plan = machine
        .plan
        .clone()
        .map(|plan| plan.map(|plan| target_plan(machine, plan)));
    Ok(ProvisionJob { target, plan })
}

fn target_plan(machine: &EffectiveMachine, plan: crate::EffectivePlan) -> ProvisionTargetPlan {
    ProvisionTargetPlan {
        profiles: machine.provision_profiles.clone(),
        steps: plan.runtime_steps,
        transition_owner: plan.transition_owner,
        transition_actions: plan.runtime_transition_actions,
        security_verifiers: plan.runtime_security_verifiers,
    }
}

fn plan_jump(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &EffectiveMachine,
) -> Result<Option<ProvisionJump>, ProvisionPlanError> {
    if machine.route == "direct" {
        return Ok(None);
    }
    let jump = inventory
        .jumps
        .iter()
        .find(|jump| jump.name == machine.route)
        .ok_or_else(|| ProvisionPlanError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: format!("unknown jump host {}", machine.route),
        })?;
    Ok(Some(plan_provision_jump(root, inventory, jump)))
}

fn plan_provision_jump(
    root: &Path,
    inventory: &EffectiveInventory,
    jump: &EffectiveJump,
) -> ProvisionJump {
    let alias = match jump.scope {
        JumpScope::Root => crate::alias::root_jump_alias(root, &jump.name),
        JumpScope::Environment => {
            crate::alias::env_jump_alias(root, &inventory.environment, &jump.name)
        }
    };
    ProvisionJump {
        name: jump.name.clone(),
        address: jump.address.clone(),
        port: jump.port,
        alias,
        auth_profile: jump.auth_profile.clone(),
    }
}

fn pre_dispatch_result(job: &ProvisionJob) -> ProvisionTargetResult {
    if job.target.provision_profiles.is_empty() {
        return planless_result(job);
    }
    match &job.plan {
        Ok(Some(_)) => ProvisionTargetResult::pending(job),
        Ok(None) => planless_result(job),
        Err(error) => {
            let (phase, action) = validation_context(error);
            let mut result = ProvisionTargetResult::failure(
                job.target.machine.clone(),
                FailureClass::Configuration,
                error.to_string(),
            )
            .with_context(phase, action);
            if matches!(
                error,
                PlanValidationError::MissingSecretStdinProvider { .. }
            ) {
                result.diagnostic_in_report = false;
            }
            result
        }
    }
}

fn planless_result(job: &ProvisionJob) -> ProvisionTargetResult {
    ProvisionTargetResult::failure(
        job.target.machine.clone(),
        FailureClass::Configuration,
        "selected machine has no provisioning plan",
    )
}

fn validation_context(error: &PlanValidationError) -> (Option<String>, Option<String>) {
    let action = match error {
        PlanValidationError::MissingScriptBinding { action, .. }
        | PlanValidationError::UnprivilegedSecurityVerifier { action }
        | PlanValidationError::UploadOwnerRequiresRoot { action }
        | PlanValidationError::MissingSecretStdinProvider { action, .. }
        | PlanValidationError::MissingActionPrivilege { action, .. }
        | PlanValidationError::PasswordSudoWithSecretStdin { action }
        | PlanValidationError::UnprivilegedReboot { action }
        | PlanValidationError::ActionBeforeConfigure { action } => Some(action.clone()),
        PlanValidationError::TransitionOwnerCount { .. }
        | PlanValidationError::MissingSecurityVerifier => None,
    };
    let phase = action
        .as_deref()
        .and_then(|action| action.split('.').nth(1))
        .map(str::to_string);
    (phase, action)
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

