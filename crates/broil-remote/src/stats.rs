// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use broil_core::remote::DurationValue;
use russh::ChannelMsg;
use russh::client;
use russh::keys::Algorithm;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::auth::{self, AuthContext};
use crate::check::RemoteSignal;
use crate::exec::ExecBackend;
pub use crate::jobs::RequestedJobs;
use crate::jobs::resolve_jobs;
use crate::known_hosts::{AliasState, KnownHostsStore, StoreError};
use crate::scheduler::{self, CancellationToken};
use crate::transport::StrictHandler;
use crate::{
    EffectiveInventory, EffectiveJump, EffectiveMachine, FailureClass, JumpScope, Selectors,
};

const COLLECTOR_OUTPUT_LIMIT: usize = 64 * 1024;
const STATS_CANCEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const GENERIC_LINUX_COLLECTOR_COMMAND: &str = r#"LC_ALL=C
export LC_ALL
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
printf 'BROIL_STATS_V1\n'
printf 'BEGIN uptime\n'
if IFS= read -r line < /proc/uptime; then printf '%s\n' "$line"; else printf 'UNSUPPORTED\n'; fi
printf 'END uptime\n'
printf 'BEGIN load\n'
if IFS= read -r line < /proc/loadavg; then printf '%s\n' "$line"; else printf 'UNSUPPORTED\n'; fi
printf 'END load\n'
printf 'BEGIN cpu\n'
if [ -r /proc/stat ]; then
  while IFS= read -r line; do
    case "$line" in
      cpu\ *) printf '%s\n' "$line"; break ;;
    esac
  done < /proc/stat
else
  printf 'UNSUPPORTED\n'
fi
printf 'END cpu\n'
printf 'BEGIN memory\n'
if [ -r /proc/meminfo ]; then cat /proc/meminfo; else printf 'UNSUPPORTED\n'; fi
printf 'END memory\n'
printf 'BEGIN filesystem\n'
if command -v df >/dev/null 2>&1; then df -P -k 2>/dev/null || printf 'UNSUPPORTED\n'; else printf 'UNSUPPORTED\n'; fi
printf 'END filesystem\n'
"#;

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
pub struct StatsRequest {
    pub selectors: Selectors,
    pub jobs: Option<RequestedJobs>,
    pub fail_fast: bool,
    pub known_hosts: ResolvedKnownHosts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsPlan {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub jobs: Vec<StatsJob>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsJob {
    pub environment: String,
    pub machine: String,
    pub address: String,
    pub port: u16,
    pub target_alias: String,
    pub route: String,
    pub jump: Option<StatsJump>,
    pub canonical_profile: String,
    pub canonical_user: String,
    pub privilege_profile: Option<String>,
    pub vars: BTreeMap<String, String>,
    pub default_interpreter: Vec<String>,
    pub env_vars: BTreeMap<String, String>,
    pub stats_script: Option<StatsScript>,
    pub known_hosts: ResolvedKnownHosts,
    pub connect_timeout: DurationValue,
    pub command_timeout: DurationValue,
    pub timeouts: crate::EffectiveTimeouts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsScript {
    pub name: String,
    pub script: crate::EffectiveRemoteScript,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsJump {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub alias: String,
    pub auth_profile: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsCategory {
    Uptime,
    Load,
    Cpu,
    Memory,
    Filesystem,
}

impl StatsCategory {
    pub const ALL: [Self; 5] = [
        Self::Uptime,
        Self::Load,
        Self::Cpu,
        Self::Memory,
        Self::Filesystem,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uptime => "uptime",
            Self::Load => "load",
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Filesystem => "filesystem",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsCategoryStatus {
    Success,
    Unsupported,
    Failed,
    NotRun,
}

impl StatsCategoryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Unsupported => "unsupported",
            Self::Failed => "failed",
            Self::NotRun => "not_run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsRecord {
    pub name: Option<String>,
    pub values: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsCategoryResult {
    pub category: StatsCategory,
    pub status: StatsCategoryStatus,
    pub records: Vec<StatsRecord>,
    pub failure_class: Option<FailureClass>,
    pub diagnostic: Option<String>,
    pub dispatched: bool,
    pub remote_status: Option<i32>,
    pub remote_signal: Option<crate::check::RemoteSignal>,
    pub possible_staging_residue: bool,
}

impl StatsCategoryResult {
    pub fn success(category: StatsCategory, records: Vec<StatsRecord>) -> Self {
        Self {
            category,
            status: StatsCategoryStatus::Success,
            records,
            failure_class: None,
            diagnostic: None,
            dispatched: true,
            remote_status: None,
            remote_signal: None,
            possible_staging_residue: false,
        }
    }

    pub fn unsupported(category: StatsCategory, diagnostic: impl Into<String>) -> Self {
        Self::failure(
            category,
            StatsCategoryStatus::Unsupported,
            FailureClass::CapabilityUnsupported,
            diagnostic,
            true,
        )
    }

    pub fn collection_failure(category: StatsCategory, diagnostic: impl Into<String>) -> Self {
        Self::failure(
            category,
            StatsCategoryStatus::Failed,
            FailureClass::StatisticsCollection,
            diagnostic,
            true,
        )
    }

    pub fn indeterminate(category: StatsCategory, diagnostic: impl Into<String>) -> Self {
        Self::failure(
            category,
            StatsCategoryStatus::Failed,
            FailureClass::IndeterminateAfterDispatch,
            diagnostic,
            true,
        )
    }

    pub fn not_run(category: StatsCategory, class: FailureClass) -> Self {
        Self::failure(
            category,
            StatsCategoryStatus::NotRun,
            class,
            "remote stats target was not scheduled",
            false,
        )
    }

    fn failure(
        category: StatsCategory,
        status: StatsCategoryStatus,
        class: FailureClass,
        diagnostic: impl Into<String>,
        dispatched: bool,
    ) -> Self {
        Self::failure_with_details(category, status, class, diagnostic, dispatched, None, None)
    }

    fn failure_with_details(
        category: StatsCategory,
        status: StatsCategoryStatus,
        class: FailureClass,
        diagnostic: impl Into<String>,
        dispatched: bool,
        remote_status: Option<i32>,
        remote_signal: Option<RemoteSignal>,
    ) -> Self {
        Self {
            category,
            status,
            records: Vec::new(),
            failure_class: Some(class),
            diagnostic: Some(diagnostic.into()),
            dispatched,
            remote_status,
            remote_signal,
            possible_staging_residue: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsTargetStatus {
    Success,
    Failed,
}

impl StatsTargetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsTargetResult {
    pub machine: String,
    pub status: StatsTargetStatus,
    pub failure_class: Option<FailureClass>,
    pub diagnostic: Option<String>,
    pub dispatched: bool,
    pub remote_status: Option<i32>,
    pub remote_signal: Option<crate::check::RemoteSignal>,
    pub possible_staging_residue: bool,
    pub categories: Vec<StatsCategoryResult>,
}

impl StatsTargetResult {
    pub fn from_categories(
        machine: impl Into<String>,
        categories: Vec<StatsCategoryResult>,
    ) -> Self {
        let status = if categories
            .iter()
            .all(|category| category.status == StatsCategoryStatus::Success)
        {
            StatsTargetStatus::Success
        } else {
            StatsTargetStatus::Failed
        };
        let first_failure = categories
            .iter()
            .find(|category| category.status != StatsCategoryStatus::Success);
        Self {
            machine: machine.into(),
            status,
            failure_class: first_failure.and_then(|category| category.failure_class),
            diagnostic: first_failure.and_then(|category| category.diagnostic.clone()),
            dispatched: categories.iter().any(|category| category.dispatched),
            remote_status: first_failure.and_then(|category| category.remote_status),
            remote_signal: first_failure.and_then(|category| category.remote_signal.clone()),
            possible_staging_residue: categories
                .iter()
                .any(|category| category.possible_staging_residue),
            categories,
        }
    }

    pub fn not_started(job: StatsJob, class: FailureClass) -> Self {
        Self::from_categories(
            job.machine,
            StatsCategory::ALL
                .into_iter()
                .map(|category| StatsCategoryResult::not_run(category, class))
                .collect(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsOutcome {
    pub environment: String,
    pub selected_machines: Vec<String>,
    pub duration_millis: u128,
    pub results: Vec<StatsTargetResult>,
}

impl StatsOutcome {
    pub fn status(&self) -> i32 {
        if self
            .results
            .iter()
            .all(|result| result.status == StatsTargetStatus::Success)
        {
            0
        } else {
            1
        }
    }
}

#[derive(Debug)]
pub enum StatsPlanError {
    Usage(broil_core::error::UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

impl StatsPlanError {
    pub fn class(&self) -> FailureClass {
        match self {
            Self::Usage(_) => FailureClass::Selector,
            Self::Runtime { class, .. } => *class,
        }
    }
}

impl std::fmt::Display for StatsPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(formatter),
            Self::Runtime { diagnostic, .. } => formatter.write_str(diagnostic),
        }
    }
}

impl std::error::Error for StatsPlanError {}

#[derive(Debug)]
pub enum StatsRunError {
    Usage(broil_core::error::UsageError),
    Runtime {
        class: FailureClass,
        diagnostic: String,
    },
}

impl StatsRunError {
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

impl std::fmt::Display for StatsRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(error) => error.fmt(formatter),
            Self::Runtime { diagnostic, .. } => formatter.write_str(diagnostic),
        }
    }
}

impl std::error::Error for StatsRunError {}

impl From<StatsPlanError> for StatsRunError {
    fn from(error: StatsPlanError) -> Self {
        match error {
            StatsPlanError::Usage(error) => Self::Usage(error),
            StatsPlanError::Runtime { class, diagnostic } => Self::Runtime { class, diagnostic },
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetStatsOptions {
    pub cancel: CancellationToken,
}

#[derive(Debug, Clone, Default)]
pub struct StatsRunOptions {
    pub cancel: CancellationToken,
}

pub trait StatsBackend: Clone + Send + Sync + 'static {
    fn collect_target(
        &self,
        job: StatsJob,
        options: TargetStatsOptions,
    ) -> Pin<Box<dyn Future<Output = StatsTargetResult> + Send>>;
}

#[derive(Clone)]
pub struct RusshStatsBackend {
    store: KnownHostsStore,
    auth_context: AuthContext,
    privilege_context: crate::exec::PrivilegeContext,
}

impl RusshStatsBackend {
    pub fn new(
        store: KnownHostsStore,
        auth_context: AuthContext,
        privilege_context: crate::exec::PrivilegeContext,
    ) -> Self {
        Self {
            store,
            auth_context,
            privilege_context,
        }
    }
}

impl StatsBackend for RusshStatsBackend {
    fn collect_target(
        &self,
        job: StatsJob,
        options: TargetStatsOptions,
    ) -> Pin<Box<dyn Future<Output = StatsTargetResult> + Send>> {
        let backend = self.clone();
        Box::pin(async move { backend.collect_real_target(job, options).await })
    }
}

impl RusshStatsBackend {
    async fn collect_real_target(
        &self,
        job: StatsJob,
        options: TargetStatsOptions,
    ) -> StatsTargetResult {
        let machine = job.machine.clone();
        match self.collect_real_target_inner(&job, &options.cancel).await {
            Ok(categories) => StatsTargetResult::from_categories(machine, categories),
            Err(failure) => failure.into_target(machine),
        }
    }

    async fn collect_real_target_inner(
        &self,
        job: &StatsJob,
        cancel: &CancellationToken,
    ) -> Result<Vec<StatsCategoryResult>, StatsFailure> {
        if job.stats_script.is_some() {
            return self.collect_script_target(job, cancel).await;
        }
        let mut session = self.connect_and_authenticate(job, cancel).await?;
        if cancel.is_cancelled() {
            return Err(cancellation_failure());
        }
        let command = run_remote_command(
            &mut session,
            GENERIC_LINUX_COLLECTOR_COMMAND,
            Duration::from_secs(job.command_timeout.seconds),
            cancel,
        )
        .await?;
        categories_from_collector_command(command)
    }

    async fn collect_script_target(
        &self,
        job: &StatsJob,
        cancel: &CancellationToken,
    ) -> Result<Vec<StatsCategoryResult>, StatsFailure> {
        let script = job
            .stats_script
            .as_ref()
            .expect("caller checked stats_script");
        if script.script.pty == crate::PtyMode::Always {
            return Err(StatsFailure::new(
                FailureClass::Configuration,
                format!(
                    "configured stats script {} requires a PTY but remote stats is PTY-free",
                    script.name
                ),
            ));
        }
        let target = exec_target_from_stats_job(job);
        let context = crate::exec::RemoteScriptContext {
            environment: &job.environment,
            env_vars: &job.env_vars,
            default_interpreter: &job.default_interpreter,
        };
        let command = crate::exec::prepare_script_command(&context, &target, &script.script, &[])
            .map_err(StatsFailure::from_exec_failure)?;
        let backend = crate::exec::RusshExecBackend::new(
            self.store.clone(),
            self.auth_context.clone(),
            self.privilege_context.clone(),
        );
        let result = backend
            .exec_target(
                target,
                crate::exec::TargetExecOptions {
                    command: Arc::new(crate::exec::ExecCommand::Script(command)),
                    stdin: crate::exec::StaticStdin::empty(),
                    forward_stdin: false,
                    live_streams: None,
                    pty: false,
                    local_terminal: crate::exec::LocalTerminal::default(),
                    privilege: script.script.privilege.clone(),
                    dispatch_timeout_seconds: script
                        .script
                        .timeout
                        .as_ref()
                        .map(|timeout| timeout.seconds)
                        .or(Some(job.command_timeout.seconds)),
                    cancel: cancel.clone(),
                },
            )
            .await;
        categories_from_script_result(script, result)
    }

    async fn connect_and_authenticate(
        &self,
        job: &StatsJob,
        cancel: &CancellationToken,
    ) -> Result<client::Handle<StrictHandler>, StatsFailure> {
        let (endpoint, endpoint_port) = route_endpoint(job);
        let connect_deadline =
            tokio::time::Instant::now() + Duration::from_secs(job.connect_timeout.seconds);
        let stream = cancellable(cancel, async {
            crate::transport::connect_tcp(endpoint, endpoint_port, connect_deadline)
                .await
                .map_err(StatsFailure::from_transport)
        })
        .await?;

        let mut session = if let Some(jump) = &job.jump {
            let expected = self.pinned_key(&jump.alias, FailureClass::UnknownHostKey)?;
            let mut jump_session = cancellable(cancel, async {
                connect_strict(stream, expected, connect_deadline)
                    .await
                    .map_err(|error| strict_jump_trust_failure(&jump.name, error))
            })
            .await?;
            cancellable_dispatched(cancel, async {
                timeout_at(
                    connect_deadline,
                    auth::authenticate_profile_cancellable(
                        &mut jump_session,
                        &self.auth_context,
                        &jump.auth_profile,
                        cancel,
                    ),
                    FailureClass::JumpFailure,
                    "jump authentication timed out",
                )
                .await?
                .map_err(|error| auth_failure(error.into_jump_failure(&jump.name)))
            })
            .await?;
            let channel = cancellable_dispatched(cancel, async {
                tokio::time::timeout_at(
                    connect_deadline,
                    jump_session.channel_open_direct_tcpip(
                        job.address.clone(),
                        u32::from(job.port),
                        "127.0.0.1",
                        0,
                    ),
                )
                .await
                .map_err(|_| {
                    StatsFailure::new(
                        FailureClass::JumpFailure,
                        format!(
                            "jump host {} timed out opening target channel to {}:{}",
                            jump.name, job.address, job.port
                        ),
                    )
                    .dispatched()
                })?
                .map_err(|error| {
                    StatsFailure::new(
                        FailureClass::JumpFailure,
                        format!(
                            "jump host {} could not open target channel to {}:{}: {error}",
                            jump.name, job.address, job.port
                        ),
                    )
                    .dispatched()
                })
            })
            .await?;
            let expected = self.pinned_key(&job.target_alias, FailureClass::UnknownHostKey)?;
            cancellable(cancel, async {
                connect_strict(channel.into_stream(), expected, connect_deadline)
                    .await
                    .map_err(strict_target_trust_failure)
            })
            .await?
        } else {
            let expected = self.pinned_key(&job.target_alias, FailureClass::UnknownHostKey)?;
            cancellable(cancel, async {
                connect_strict(stream, expected, connect_deadline)
                    .await
                    .map_err(strict_target_trust_failure)
            })
            .await?
        };

        if cancel.is_cancelled() {
            return Err(cancellation_failure());
        }
        cancellable_dispatched(cancel, async {
            timeout(
                Duration::from_secs(job.command_timeout.seconds),
                auth::authenticate_profile_cancellable(
                    &mut session,
                    &self.auth_context,
                    &job.canonical_profile,
                    cancel,
                ),
                FailureClass::IndeterminateAfterDispatch,
                "canonical authentication timed out after dispatch",
            )
            .await?
            .map_err(auth_failure)
        })
        .await?;
        Ok(session)
    }

    fn pinned_key(
        &self,
        alias: &str,
        unknown_class: FailureClass,
    ) -> Result<crate::HostKey, StatsFailure> {
        match self
            .store
            .snapshot()
            .and_then(|snapshot| snapshot.inspect(alias, false))
        {
            Ok(AliasState::Pinned(key)) => Ok(key),
            Ok(AliasState::Unknown) => Err(StatsFailure::new(
                unknown_class,
                "host key is not pinned in the Broil known-hosts store",
            )),
            Ok(AliasState::Replaceable { .. }) => Err(StatsFailure::new(
                FailureClass::Configuration,
                "known-hosts state requires replacement before read-only verification",
            )),
            Err(error) => Err(store_failure(error)),
        }
    }
}

#[derive(Debug, Clone)]
struct StatsFailure {
    class: FailureClass,
    diagnostic: String,
    dispatched: bool,
    remote_status: Option<i32>,
    remote_signal: Option<RemoteSignal>,
    possible_staging_residue: bool,
}

impl StatsFailure {
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

    fn dispatched_if(mut self, dispatched: bool) -> Self {
        self.dispatched = dispatched;
        self
    }

    fn remote_result(mut self, status: Option<i32>, signal: Option<RemoteSignal>) -> Self {
        self.remote_status = status;
        self.remote_signal = signal;
        self
    }

    fn residue_if(mut self, residue: bool) -> Self {
        if residue {
            self.possible_staging_residue = true;
        }
        self
    }

    fn from_exec_failure(error: crate::exec::ExecFailure) -> Self {
        Self {
            class: error.class,
            diagnostic: error.diagnostic,
            dispatched: error.dispatched,
            remote_status: error.remote_status,
            remote_signal: error.remote_signal,
            possible_staging_residue: error.possible_staging_residue,
        }
    }

    fn from_transport(error: crate::transport::FetchFailure) -> Self {
        Self::new(error.class, error.diagnostic)
    }

    fn into_target(self, machine: String) -> StatsTargetResult {
        StatsTargetResult::from_categories(
            machine,
            StatsCategory::ALL
                .into_iter()
                .map(|category| {
                    let mut result = StatsCategoryResult::failure_with_details(
                        category,
                        StatsCategoryStatus::Failed,
                        self.class,
                        self.diagnostic.clone(),
                        self.dispatched,
                        self.remote_status,
                        self.remote_signal.clone(),
                    );
                    result.possible_staging_residue = self.possible_staging_residue;
                    result
                })
                .collect(),
        )
    }
}

fn exec_target_from_stats_job(job: &StatsJob) -> crate::exec::ExecTarget {
    let route = if let Some(jump) = &job.jump {
        crate::exec::ExecRoute::ViaJump(crate::exec::ExecJump {
            name: jump.name.clone(),
            address: jump.address.clone(),
            port: jump.port,
            alias: jump.alias.clone(),
            auth_profile: jump.auth_profile.clone(),
        })
    } else {
        crate::exec::ExecRoute::Direct
    };
    crate::exec::ExecTarget {
        name: job.machine.clone(),
        address: job.address.clone(),
        port: job.port,
        target_alias: job.target_alias.clone(),
        canonical_profile: job.canonical_profile.clone(),
        canonical_user: job.canonical_user.clone(),
        privilege_profile: job.privilege_profile.clone(),
        vars: job.vars.clone(),
        timeouts: job.timeouts.clone(),
        route,
    }
}

fn categories_from_script_result(
    script: &StatsScript,
    result: crate::exec::ExecTargetResult,
) -> Result<Vec<StatsCategoryResult>, StatsFailure> {
    let residue = result.possible_staging_residue;
    if result.status == crate::exec::TargetStatus::Success {
        return Ok(with_staging_residue(
            parse_stats_envelope_output(&result.stdout, "configured stats script"),
            residue,
        ));
    }
    match result.failure_class {
        Some(FailureClass::RemoteNonzero) => {
            if let Some(status) = result.remote_status {
                Err(StatsFailure::new(
                    FailureClass::StatisticsCollection,
                    format!(
                        "configured stats script {} exited with status {status}",
                        script.name
                    ),
                )
                .dispatched()
                .remote_result(result.remote_status, result.remote_signal)
                .residue_if(residue))
            } else if result.remote_signal.is_some() {
                Err(StatsFailure::new(
                    FailureClass::StatisticsCollection,
                    format!(
                        "configured stats script {} exited due to signal",
                        script.name
                    ),
                )
                .dispatched()
                .remote_result(result.remote_status, result.remote_signal)
                .residue_if(residue))
            } else {
                Err(StatsFailure::new(
                    FailureClass::StatisticsCollection,
                    format!("configured stats script {} failed", script.name),
                )
                .dispatched()
                .residue_if(residue))
            }
        }
        Some(class) => Err(StatsFailure::new(
            class,
            result
                .diagnostic
                .unwrap_or_else(|| "configured stats script failed".to_string()),
        )
        .residue_if(residue)
        .remote_result(result.remote_status, result.remote_signal)
        .dispatched_if(result.dispatched)),
        None => Err(StatsFailure::new(
            FailureClass::StatisticsCollection,
            format!("configured stats script {} failed", script.name),
        )
        .residue_if(residue)),
    }
}

fn with_staging_residue(
    mut categories: Vec<StatsCategoryResult>,
    residue: bool,
) -> Vec<StatsCategoryResult> {
    if residue {
        for category in &mut categories {
            category.possible_staging_residue = true;
        }
    }
    categories
}

fn route_endpoint(job: &StatsJob) -> (&str, u16) {
    if let Some(jump) = &job.jump {
        (jump.address.as_str(), jump.port)
    } else {
        (job.address.as_str(), job.port)
    }
}

async fn connect_strict<R>(
    stream: R,
    expected: crate::HostKey,
    deadline: tokio::time::Instant,
) -> Result<client::Handle<StrictHandler>, StatsFailure>
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
    .map_err(|_| StatsFailure::new(FailureClass::Protocol, "SSH key exchange timed out"))?
    .map_err(strict_connect_failure)
}

fn strict_connect_failure(error: russh::Error) -> StatsFailure {
    match error {
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => StatsFailure::new(
            FailureClass::UnknownHostKey,
            "strict host-key verification failed",
        ),
        russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Key,
            ..
        } => StatsFailure::new(
            FailureClass::ChangedHostKey,
            "host no longer offers the pinned host-key algorithm",
        ),
        error => StatsFailure::new(
            FailureClass::Protocol,
            format!("SSH protocol failure before host-key verification: {error}"),
        ),
    }
}

fn strict_target_trust_failure(error: StatsFailure) -> StatsFailure {
    if error.class == FailureClass::UnknownHostKey {
        StatsFailure::new(
            FailureClass::ChangedHostKey,
            "target host key does not match the pinned key",
        )
    } else {
        error
    }
}

fn strict_jump_trust_failure(jump_name: &str, error: StatsFailure) -> StatsFailure {
    if error.class == FailureClass::UnknownHostKey {
        StatsFailure::new(
            FailureClass::ChangedHostKey,
            format!("jump host {jump_name} key does not match the pinned key"),
        )
    } else {
        error
    }
}

fn client_config(algorithms: &[String]) -> Result<client::Config, StatsFailure> {
    let algorithms = algorithms
        .iter()
        .map(|name| {
            Algorithm::from_str(name).map_err(|_| {
                StatsFailure::new(
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
) -> Result<T, StatsFailure> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| StatsFailure::new(class, diagnostic).dispatched())
}

async fn timeout_at<T>(
    deadline: tokio::time::Instant,
    future: impl Future<Output = T>,
    class: FailureClass,
    diagnostic: &'static str,
) -> Result<T, StatsFailure> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| StatsFailure::new(class, diagnostic).dispatched())
}

async fn cancellable<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, StatsFailure>>,
) -> Result<T, StatsFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancellation_failure()),
        result = future => result,
    }
}

async fn cancellable_dispatched<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, StatsFailure>>,
) -> Result<T, StatsFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure().dispatched());
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancellation_failure().dispatched()),
        result = future => result,
    }
}

fn cancellation_failure() -> StatsFailure {
    StatsFailure::new(FailureClass::Cancellation, "cancelled")
}

fn auth_failure(error: auth::AuthFailure) -> StatsFailure {
    let dispatched = !matches!(
        error.class(),
        FailureClass::SecretUnavailable | FailureClass::AuthenticationLocallyUnavailable
    );
    let failure = StatsFailure::new(error.class(), error.to_string());
    if dispatched {
        failure.dispatched()
    } else {
        failure
    }
}

fn store_failure(error: StoreError) -> StatsFailure {
    StatsFailure::new(error.class(), error.to_string())
}

#[derive(Debug)]
struct RemoteCommand {
    status: Option<i32>,
    signal: Option<RemoteSignal>,
    stdout: Vec<u8>,
}

async fn run_remote_command(
    session: &mut client::Handle<StrictHandler>,
    command: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<RemoteCommand, StatsFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    let command = command.as_bytes().to_vec();
    let deadline = tokio::time::Instant::now() + timeout;
    let channel = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(cancellation_failure()),
        result = tokio::time::timeout_at(deadline, session.channel_open_session()) => {
            result.map_err(|_| collector_timeout_failure())?.map_err(|error| {
                StatsFailure::new(
                    FailureClass::Protocol,
                    format!("cannot open SSH session channel: {error}"),
                )
            })?
        }
    };
    tokio::time::timeout_at(deadline, channel.exec(true, command))
        .await
        .map_err(|_| collector_timeout_failure())?
        .map_err(|error| {
            StatsFailure::new(
                FailureClass::Protocol,
                format!("cannot dispatch SSH exec request: {error}"),
            )
        })?;

    let (mut read_half, write_half) = channel.split();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            let _ = write_half.signal(russh::Sig::INT).await;
            tokio::time::sleep(STATS_CANCEL_CLEANUP_TIMEOUT).await;
            let _ = write_half.close().await;
            return Err(cancellation_failure().dispatched());
        }
        result = tokio::time::timeout_at(deadline, write_half.eof()) => {
            result.map_err(|_| collector_timeout_failure())?.map_err(|error| {
                StatsFailure::new(
                    FailureClass::IndeterminateAfterDispatch,
                    format!("cannot send SSH channel EOF: {error}"),
                )
                .dispatched()
            })?;
        }
    }

    let mut status = None;
    let mut signal = None;
    let mut stdout = Vec::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                let _ = write_half.signal(russh::Sig::INT).await;
                tokio::time::sleep(STATS_CANCEL_CLEANUP_TIMEOUT).await;
                let _ = write_half.close().await;
                return Err(cancellation_failure().dispatched());
            }
            _ = tokio::time::sleep_until(deadline) => return Err(collector_timeout_failure()),
            message = read_half.wait() => {
                let Some(message) = message else {
                    break;
                };
                match message {
                    ChannelMsg::Data { data } => append_bounded(&mut stdout, &data),
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
        }
    }
    Ok(RemoteCommand {
        status,
        signal,
        stdout,
    })
}

fn collector_timeout_failure() -> StatsFailure {
    StatsFailure::new(
        FailureClass::IndeterminateAfterDispatch,
        "generic stats collector timed out after dispatch",
    )
    .dispatched()
}

fn append_bounded(output: &mut Vec<u8>, data: &[u8]) {
    let available = COLLECTOR_OUTPUT_LIMIT.saturating_sub(output.len());
    output.extend_from_slice(&data[..data.len().min(available)]);
}

fn categories_from_collector_command(
    command: RemoteCommand,
) -> Result<Vec<StatsCategoryResult>, StatsFailure> {
    match command.status {
        Some(0) => Ok(parse_generic_linux_stats_output(&command.stdout)),
        Some(status) => Err(StatsFailure::new(
            FailureClass::StatisticsCollection,
            format!("generic stats collector exited with status {status}"),
        )
        .dispatched()
        .remote_result(Some(status), command.signal)),
        None if command.signal.is_some() => Err(StatsFailure::new(
            FailureClass::StatisticsCollection,
            "generic stats collector exited due to signal",
        )
        .dispatched()
        .remote_result(None, command.signal)),
        None => Err(StatsFailure::new(
            FailureClass::IndeterminateAfterDispatch,
            "generic stats collector ended without a numeric status",
        )
        .dispatched()),
    }
}

fn parse_generic_linux_stats_output(output: &[u8]) -> Vec<StatsCategoryResult> {
    parse_stats_envelope_output(output, "generic stats collector")
}

fn parse_stats_envelope_output(output: &[u8], source: &str) -> Vec<StatsCategoryResult> {
    match parse_stats_envelope_output_inner(output, source) {
        Ok(results) => results,
        Err(diagnostic) => {
            StatsFailure::new(FailureClass::StatisticsCollection, diagnostic)
                .dispatched()
                .into_target("__collector__".to_string())
                .categories
        }
    }
}

fn parse_stats_envelope_output_inner(
    output: &[u8],
    source: &str,
) -> Result<Vec<StatsCategoryResult>, String> {
    let text =
        std::str::from_utf8(output).map_err(|_| format!("{source} emitted non-UTF-8 output"))?;
    if text
        .chars()
        .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(format!("{source} emitted unsupported control characters"));
    }
    if text.trim() == "UNSUPPORTED" {
        return Ok(StatsCategory::ALL.into_iter().map(unsupported).collect());
    }
    let lines = text.lines().collect::<Vec<_>>();
    if lines.first().copied() != Some("BROIL_STATS_V1") {
        return Err(format!("{source} emitted an unsupported envelope"));
    }
    Ok(vec![
        parse_uptime(&lines),
        parse_load(&lines),
        parse_cpu(&lines),
        parse_memory(&lines),
        parse_filesystem(&lines),
    ])
}

enum SectionData<'a> {
    Unsupported,
    Lines(Vec<&'a str>),
}

fn section_data<'a>(
    lines: &'a [&'a str],
    name: &str,
    category: StatsCategory,
) -> Result<SectionData<'a>, StatsCategoryResult> {
    let begin = format!("BEGIN {name}");
    let end = format!("END {name}");
    let Some(start) = lines.iter().position(|line| *line == begin) else {
        return Err(StatsCategoryResult::collection_failure(
            category,
            format!("{} collector section missing", category.as_str()),
        ));
    };
    let Some(relative_end) = lines[start + 1..].iter().position(|line| *line == end) else {
        return Err(StatsCategoryResult::collection_failure(
            category,
            format!("{} collector section did not terminate", category.as_str()),
        ));
    };
    let section = lines[start + 1..start + 1 + relative_end]
        .iter()
        .copied()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if section.len() == 1 && section[0].trim() == "UNSUPPORTED" {
        Ok(SectionData::Unsupported)
    } else {
        Ok(SectionData::Lines(section))
    }
}

fn unsupported(category: StatsCategory) -> StatsCategoryResult {
    StatsCategoryResult::unsupported(
        category,
        format!("{} collector unsupported", category.as_str()),
    )
}

fn malformed(category: StatsCategory) -> StatsCategoryResult {
    StatsCategoryResult::collection_failure(
        category,
        format!("{} collector returned malformed data", category.as_str()),
    )
}

fn parse_uptime(lines: &[&str]) -> StatsCategoryResult {
    let category = StatsCategory::Uptime;
    let section = match section_data(lines, "uptime", category) {
        Ok(SectionData::Unsupported) => return unsupported(category),
        Ok(SectionData::Lines(section)) => section,
        Err(result) => return result,
    };
    let Some(line) = section.first() else {
        return malformed(category);
    };
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return malformed(category);
    }
    let Ok(uptime) = decimal_value(parts[0]) else {
        return malformed(category);
    };
    let Ok(idle) = decimal_value(parts[1]) else {
        return malformed(category);
    };
    StatsCategoryResult::success(
        category,
        vec![StatsRecord {
            name: Some("summary".to_string()),
            values: BTreeMap::from([
                ("idle_seconds".to_string(), idle),
                ("uptime_seconds".to_string(), uptime),
            ]),
        }],
    )
}

fn parse_load(lines: &[&str]) -> StatsCategoryResult {
    let category = StatsCategory::Load;
    let section = match section_data(lines, "load", category) {
        Ok(SectionData::Unsupported) => return unsupported(category),
        Ok(SectionData::Lines(section)) => section,
        Err(result) => return result,
    };
    let Some(line) = section.first() else {
        return malformed(category);
    };
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 5 {
        return malformed(category);
    }
    let Ok(one) = decimal_value(parts[0]) else {
        return malformed(category);
    };
    let Ok(five) = decimal_value(parts[1]) else {
        return malformed(category);
    };
    let Ok(fifteen) = decimal_value(parts[2]) else {
        return malformed(category);
    };
    let Some((running, total)) = parts[3].split_once('/') else {
        return malformed(category);
    };
    if parse_u64_value(running).is_err()
        || parse_u64_value(total).is_err()
        || parse_u64_value(parts[4]).is_err()
    {
        return malformed(category);
    }
    StatsCategoryResult::success(
        category,
        vec![StatsRecord {
            name: Some("summary".to_string()),
            values: BTreeMap::from([
                ("fifteen_minutes".to_string(), fifteen),
                ("five_minutes".to_string(), five),
                ("last_pid".to_string(), parts[4].to_string()),
                ("one_minute".to_string(), one),
                ("running_processes".to_string(), running.to_string()),
                ("total_processes".to_string(), total.to_string()),
            ]),
        }],
    )
}

fn parse_cpu(lines: &[&str]) -> StatsCategoryResult {
    let category = StatsCategory::Cpu;
    let section = match section_data(lines, "cpu", category) {
        Ok(SectionData::Unsupported) => return unsupported(category),
        Ok(SectionData::Lines(section)) => section,
        Err(result) => return result,
    };
    let Some(line) = section.iter().find(|line| line.starts_with("cpu ")) else {
        return malformed(category);
    };
    let mut parts = line.split_whitespace();
    if parts.next() != Some("cpu") {
        return malformed(category);
    }
    let fields = parts.collect::<Vec<_>>();
    if fields.len() < 4 {
        return malformed(category);
    }
    let values = match fields
        .iter()
        .map(|value| parse_u64_value(value))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(values) => values,
        Err(_) => return malformed(category),
    };
    let total = values.iter().copied().sum::<u64>();
    let idle = values.get(3).copied().unwrap_or_default();
    let iowait = values.get(4).copied().unwrap_or_default();
    let busy = total.saturating_sub(idle).saturating_sub(iowait);
    let names = [
        "user_jiffies",
        "nice_jiffies",
        "system_jiffies",
        "idle_jiffies",
        "iowait_jiffies",
        "irq_jiffies",
        "softirq_jiffies",
        "steal_jiffies",
        "guest_jiffies",
        "guest_nice_jiffies",
    ];
    let mut record = BTreeMap::new();
    for (index, value) in values.iter().enumerate().take(names.len()) {
        record.insert(names[index].to_string(), value.to_string());
    }
    record.insert("busy_jiffies".to_string(), busy.to_string());
    record.insert("total_jiffies".to_string(), total.to_string());
    StatsCategoryResult::success(
        category,
        vec![StatsRecord {
            name: Some("summary".to_string()),
            values: record,
        }],
    )
}

fn parse_memory(lines: &[&str]) -> StatsCategoryResult {
    let category = StatsCategory::Memory;
    let section = match section_data(lines, "memory", category) {
        Ok(SectionData::Unsupported) => return unsupported(category),
        Ok(SectionData::Lines(section)) => section,
        Err(result) => return result,
    };
    if section.is_empty() {
        return malformed(category);
    }
    let mut values = BTreeMap::new();
    for line in section {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next().and_then(|key| key.strip_suffix(':')) else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        let Ok(value) = parse_u64_value(value) else {
            return malformed(category);
        };
        let Some(output_key) = memory_output_key(key) else {
            continue;
        };
        values.insert(output_key.to_string(), value.to_string());
    }
    if !values.contains_key("mem_total_kib") || !values.contains_key("mem_free_kib") {
        return malformed(category);
    }
    StatsCategoryResult::success(
        category,
        vec![StatsRecord {
            name: Some("summary".to_string()),
            values,
        }],
    )
}

fn memory_output_key(key: &str) -> Option<&'static str> {
    match key {
        "MemTotal" => Some("mem_total_kib"),
        "MemFree" => Some("mem_free_kib"),
        "MemAvailable" => Some("mem_available_kib"),
        "Buffers" => Some("buffers_kib"),
        "Cached" => Some("cached_kib"),
        "SwapTotal" => Some("swap_total_kib"),
        "SwapFree" => Some("swap_free_kib"),
        _ => None,
    }
}

fn parse_filesystem(lines: &[&str]) -> StatsCategoryResult {
    let category = StatsCategory::Filesystem;
    let section = match section_data(lines, "filesystem", category) {
        Ok(SectionData::Unsupported) => return unsupported(category),
        Ok(SectionData::Lines(section)) => section,
        Err(result) => return result,
    };
    if section.is_empty() {
        return malformed(category);
    }
    let rows = section
        .into_iter()
        .filter(|line| !line.starts_with("Filesystem "))
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return malformed(category);
    }
    let mut records = Vec::with_capacity(rows.len());
    for line in rows {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 {
            return malformed(category);
        }
        if parse_u64_value(fields[1]).is_err()
            || parse_u64_value(fields[2]).is_err()
            || parse_u64_value(fields[3]).is_err()
            || !fields[4].ends_with('%')
            || parse_u64_value(fields[4].trim_end_matches('%')).is_err()
        {
            return malformed(category);
        }
        let mounted_on = fields[5..].join(" ");
        records.push(StatsRecord {
            name: Some(mounted_on.clone()),
            values: BTreeMap::from([
                ("available_1k".to_string(), fields[3].to_string()),
                ("blocks_1k".to_string(), fields[1].to_string()),
                ("capacity_percent".to_string(), fields[4].to_string()),
                ("filesystem".to_string(), fields[0].to_string()),
                ("mounted_on".to_string(), mounted_on),
                ("used_1k".to_string(), fields[2].to_string()),
            ]),
        });
    }
    StatsCategoryResult::success(category, records)
}

fn decimal_value(value: &str) -> Result<String, ()> {
    let parsed = value.parse::<f64>().map_err(|_| ())?;
    if parsed.is_finite() && parsed >= 0.0 {
        Ok(value.to_string())
    } else {
        Err(())
    }
}

fn parse_u64_value(value: &str) -> Result<u64, ()> {
    value.parse::<u64>().map_err(|_| ())
}

pub fn plan(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &StatsRequest,
) -> Result<StatsPlan, StatsPlanError> {
    let selected =
        crate::select(inventory, &request.selectors, false).map_err(StatsPlanError::Usage)?;
    let selected_machines = selected
        .iter()
        .map(|machine| machine.name.clone())
        .collect::<Vec<_>>();
    let jobs = selected
        .into_iter()
        .map(|machine| plan_job(root, inventory, machine, request))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(StatsPlan {
        environment: inventory.environment.clone(),
        selected_machines,
        jobs,
    })
}

pub fn run<B: StatsBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &StatsRequest,
    backend: B,
) -> Result<StatsOutcome, StatsRunError> {
    run_with_options(
        root,
        inventory,
        request,
        StatsRunOptions::default(),
        backend,
    )
}

pub fn run_with_options<B: StatsBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &StatsRequest,
    options: StatsRunOptions,
    backend: B,
) -> Result<StatsOutcome, StatsRunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            StatsRunError::new(
                FailureClass::CapabilityUnsupported,
                format!("cannot initialize remote stats runtime: {error}"),
            )
        })?;
    runtime.block_on(run_async(root, inventory, request, &options, backend))
}

async fn run_async<B: StatsBackend>(
    root: &Path,
    inventory: &EffectiveInventory,
    request: &StatsRequest,
    options: &StatsRunOptions,
    backend: B,
) -> Result<StatsOutcome, StatsRunError> {
    let started = now_millis();
    let plan = plan(root, inventory, request).map_err(StatsRunError::from)?;
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
            let options = TargetStatsOptions { cancel: token };
            async move { backend.collect_target(job, options).await }
        },
        |result| result.status != StatsTargetStatus::Success,
        StatsTargetResult::not_started,
    )
    .await;
    if let Some(task) = interrupt_task {
        task.abort();
    }
    Ok(StatsOutcome {
        environment: plan.environment,
        selected_machines: plan.selected_machines,
        duration_millis: now_millis().saturating_sub(started),
        results,
    })
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

fn plan_job(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &EffectiveMachine,
    request: &StatsRequest,
) -> Result<StatsJob, StatsPlanError> {
    let jump = plan_jump(root, inventory, machine)?;
    let stats_script = machine
        .stats_script
        .as_ref()
        .map(|name| {
            inventory
                .scripts
                .get(name.as_str())
                .map(|script| StatsScript {
                    name: name.clone(),
                    script: script.clone(),
                })
                .ok_or_else(|| StatsPlanError::Runtime {
                    class: FailureClass::Configuration,
                    diagnostic: format!("unknown stats script {name}"),
                })
        })
        .transpose()?;
    Ok(StatsJob {
        environment: inventory.environment.clone(),
        machine: machine.name.clone(),
        address: machine.address.clone(),
        port: machine.port,
        target_alias: crate::alias::target_alias(root, &inventory.environment, &machine.name),
        route: machine.route.clone(),
        jump,
        canonical_profile: machine.canonical_profile.clone(),
        canonical_user: machine.canonical_user.clone(),
        privilege_profile: machine.privilege_profile.clone(),
        vars: machine.vars.clone(),
        default_interpreter: inventory.default_interpreter.clone(),
        env_vars: inventory.env_vars.clone(),
        stats_script,
        known_hosts: request.known_hosts.clone(),
        connect_timeout: machine.timeouts.connect.clone(),
        command_timeout: machine.timeouts.command.clone(),
        timeouts: machine.timeouts.clone(),
    })
}

fn plan_jump(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &EffectiveMachine,
) -> Result<Option<StatsJump>, StatsPlanError> {
    if machine.route == "direct" {
        return Ok(None);
    }
    let jump = inventory
        .jumps
        .iter()
        .find(|jump| jump.name == machine.route)
        .ok_or_else(|| StatsPlanError::Runtime {
            class: FailureClass::Configuration,
            diagnostic: format!("unknown jump host {}", machine.route),
        })?;
    Ok(Some(plan_stats_jump(root, inventory, jump)))
}

fn plan_stats_jump(root: &Path, inventory: &EffectiveInventory, jump: &EffectiveJump) -> StatsJump {
    let alias = match jump.scope {
        JumpScope::Root => crate::alias::root_jump_alias(root, &jump.name),
        JumpScope::Environment => {
            crate::alias::env_jump_alias(root, &inventory.environment, &jump.name)
        }
    };
    StatsJump {
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

