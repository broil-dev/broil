// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::alias::{env_jump_alias, root_jump_alias, target_alias};
use crate::auth::{
    AttemptConnections, AuthContext, Authenticated, ConnectFuture, OpenSshPublicKeyIdentity,
    openssh_public_key_profile,
};
use crate::exec::{LocalTerminal, remote_signal, signal_status};
use crate::known_hosts::{AliasState, KnownHostsStore, StoreError};
use crate::path_safety::{effective_uid, random_bytes};
use crate::scheduler::CancellationToken;
use crate::{
    EffectiveInventory, EffectiveJump, EffectiveMachine, FailureClass, HostKey, JumpScope,
};
use russh::keys::Algorithm;
use russh::{ChannelMsg, MethodKind, MethodSet, client};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::transport::{LinkLoss, LinkState, StrictHandler};

const SSH_PROGRAM: &str = "ssh";
const STALE_ARTIFACT_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const BOOTSTRAP_CANCEL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtyMode {
    Force,
    Disable,
}

#[derive(Clone)]
pub struct SshOptions {
    pub pty: PtyMode,
    pub home: PathBuf,
    pub store: KnownHostsStore,
    pub auth_context: AuthContext,
    pub env_snapshot: Vec<(OsString, OsString)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshOutcome {
    pub status: i32,
}

#[derive(Clone)]
pub struct BootstrapSshOptions {
    pub store: KnownHostsStore,
    pub auth_context: AuthContext,
    pub cancel: CancellationToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapAuthentication {
    Canonical,
    Bootstrap,
}

pub struct BootstrapSession {
    machine: String,
    authenticated_profile: String,
    authentication: BootstrapAuthentication,
    session: client::Handle<StrictHandler>,
    jump_session: Option<client::Handle<StrictHandler>>,
}

impl BootstrapSession {
    pub fn machine(&self) -> &str {
        &self.machine
    }

    pub fn authenticated_profile(&self) -> &str {
        &self.authenticated_profile
    }

    pub fn authentication(&self) -> BootstrapAuthentication {
        self.authentication
    }

    pub(crate) fn session_mut(&mut self) -> &mut client::Handle<StrictHandler> {
        &mut self.session
    }

    pub(crate) fn target_session_is_closed(&self) -> bool {
        self.session.is_closed()
    }

    pub async fn disconnect(mut self) {
        let _ = self
            .session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await;
        if let Some(jump) = self.jump_session.take() {
            let _ = jump
                .disconnect(russh::Disconnect::ByApplication, "", "English")
                .await;
        }
    }

    pub async fn run_interactive_pty(
        mut self,
        local_terminal: &LocalTerminal,
        cancel: &CancellationToken,
    ) -> Result<SshOutcome, SshError> {
        let mut channel = cancellable(cancel, async {
            self.session.channel_open_session().await.map_err(|error| {
                SshError::new(
                    FailureClass::Protocol,
                    format!("cannot open bootstrap SSH session channel: {error}"),
                )
            })
        })
        .await?;
        let (columns, rows) = effective_terminal_size(local_terminal);
        let pty_request = "cannot request bootstrap SSH PTY";
        cancellable(cancel, async {
            channel
                .request_pty(true, &local_terminal.term, columns, rows, 0, 0, &[])
                .await
                .map_err(|error| {
                    SshError::new(FailureClass::Protocol, format!("{pty_request}: {error}"))
                })
        })
        .await?;
        cancellable(cancel, async {
            expect_bootstrap_channel_success(&mut channel, pty_request).await
        })
        .await?;
        let shell_request = "cannot request bootstrap SSH shell";
        cancellable(cancel, async {
            channel.request_shell(true).await.map_err(|error| {
                SshError::new(FailureClass::Protocol, format!("{shell_request}: {error}"))
            })
        })
        .await?;
        cancellable(cancel, async {
            expect_bootstrap_channel_success(&mut channel, shell_request).await
        })
        .await?;

        let outcome = run_bootstrap_pty_channel(channel, local_terminal, cancel).await;
        let _ = self
            .session
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await;
        if let Some(jump) = self.jump_session.take() {
            let _ = jump
                .disconnect(russh::Disconnect::ByApplication, "", "English")
                .await;
        }
        outcome
    }
}

async fn expect_bootstrap_channel_success(
    channel: &mut russh::Channel<client::Msg>,
    request: &str,
) -> Result<(), SshError> {
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => return Ok(()),
            Some(ChannelMsg::Failure) => {
                return Err(SshError::new(
                    FailureClass::Protocol,
                    format!("{request}: server refused request"),
                ));
            }
            Some(ChannelMsg::Close) | None => {
                return Err(SshError::new(
                    FailureClass::Protocol,
                    format!("{request}: channel closed before request confirmation"),
                ));
            }
            Some(_) => {}
        }
    }
}

#[derive(Debug)]
pub struct SshError {
    class: FailureClass,
    diagnostic: String,
}

impl SshError {
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

impl fmt::Display for SshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for SshError {}

#[derive(Debug)]
pub(crate) struct SshProbeError {
    class: FailureClass,
    diagnostic: String,
    dispatched: bool,
}

impl SshProbeError {
    fn new(class: FailureClass, diagnostic: impl Into<String>, dispatched: bool) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
            dispatched,
        }
    }

    fn from_ssh(error: SshError, dispatched: bool) -> Self {
        Self::new(error.class(), error.to_string(), dispatched)
    }

    pub(crate) fn class(&self) -> FailureClass {
        self.class
    }

    pub(crate) fn diagnostic(&self) -> &str {
        &self.diagnostic
    }

    pub(crate) fn dispatched(&self) -> bool {
        self.dispatched
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInvocation {
    pub program: OsString,
    pub config: PathBuf,
    pub host: String,
    pub environment: BTreeMap<OsString, OsString>,
}

pub trait SshRunner {
    fn run(&mut self, invocation: &SshInvocation) -> Result<i32, SshError>;
}

pub struct SystemSshRunner;

impl SshRunner for SystemSshRunner {
    fn run(&mut self, invocation: &SshInvocation) -> Result<i32, SshError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|error| {
                SshError::new(
                    FailureClass::CapabilityUnsupported,
                    format!("cannot initialize system ssh runner: {error}"),
                )
            })?;
        let status = runtime.block_on(run_system_ssh_child(invocation))?;
        child_status_code(status)
    }
}

pub struct BootstrapInterruptWatcher {
    stop: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for BootstrapInterruptWatcher {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
pub fn spawn_bootstrap_interrupt_watcher(
    cancel: CancellationToken,
) -> Option<BootstrapInterruptWatcher> {
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
                            restore_bootstrap_raw_terminal();
                            std::process::exit(130);
                        }
                        seen = true;
                        cancel.cancel();
                    }
                }
            }
        });
    });
    Some(BootstrapInterruptWatcher {
        stop,
        thread: Some(thread),
    })
}

#[cfg(not(unix))]
pub fn spawn_bootstrap_interrupt_watcher(
    _cancel: CancellationToken,
) -> Option<BootstrapInterruptWatcher> {
    None
}

async fn run_system_ssh_child(invocation: &SshInvocation) -> Result<ExitStatus, SshError> {
    let mut child = tokio::process::Command::new(&invocation.program)
        .arg("-F")
        .arg(&invocation.config)
        .arg(&invocation.host)
        .env_clear()
        .envs(invocation.environment.iter())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| {
            SshError::new(
                FailureClass::CapabilityUnsupported,
                format!("cannot launch system ssh: {error}"),
            )
        })?;
    wait_for_system_ssh(&mut child).await.map_err(|error| {
        SshError::new(
            FailureClass::CapabilityUnsupported,
            format!("cannot wait for system ssh: {error}"),
        )
    })
}

async fn wait_for_system_ssh(child: &mut tokio::process::Child) -> std::io::Result<ExitStatus> {
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    tokio::select! {
        status = child.wait() => status,
        _ = interrupt.recv() => wait_after_forwarded_signal(child, rustix::process::Signal::INT).await,
        _ = terminate.recv() => wait_after_forwarded_signal(child, rustix::process::Signal::TERM).await,
        _ = hangup.recv() => wait_after_forwarded_signal(child, rustix::process::Signal::HUP).await,
    }
}

async fn wait_after_forwarded_signal(
    child: &mut tokio::process::Child,
    signal: rustix::process::Signal,
) -> std::io::Result<ExitStatus> {
    if let Some(id) = child
        .id()
        .and_then(|id| rustix::process::Pid::from_raw(id as i32))
    {
        let _ = rustix::process::kill_process(id, signal);
    }
    child.wait().await
}

fn child_status_code(status: ExitStatus) -> Result<i32, SshError> {
    if let Some(code) = status.code() {
        return Ok(code);
    }
    if let Some(signal) = status.signal() {
        return Ok(128 + signal);
    }
    Err(SshError::new(
        FailureClass::CapabilityUnsupported,
        "system ssh status is neither an exit code nor a signal",
    ))
}

type BootstrapStdinChunk = Result<Vec<u8>, String>;

pub fn validate_bootstrap_local_terminal(local_terminal: &LocalTerminal) -> Result<(), SshError> {
    if !local_terminal.stdin || !local_terminal.stdout {
        return Err(SshError::new(
            FailureClass::Configuration,
            "remote ssh --bootstrap requires local stdin and stdout terminals",
        ));
    }
    probe_stdin_raw_mode()
}

async fn run_bootstrap_pty_channel(
    channel: russh::Channel<client::Msg>,
    local_terminal: &LocalTerminal,
    cancel: &CancellationToken,
) -> Result<SshOutcome, SshError> {
    let _raw_terminal = BootstrapRawTerminalGuard::enter()?;
    let (mut read_half, write_half) = channel.split();
    let mut stdin_rx = Some(spawn_bootstrap_stdin_reader());
    let mut resize_signal = resize_signal(local_terminal);
    let mut status = None;
    let mut signal = None;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = write_half.signal(russh::Sig::INT).await;
                tokio::time::sleep(BOOTSTRAP_CANCEL_CLEANUP_TIMEOUT).await;
                let _ = write_half.close().await;
                return Err(cancellation_failure());
            }
            _ = wait_resize_signal(&mut resize_signal), if resize_signal.is_some() => {
                let (columns, rows) = effective_terminal_size(local_terminal);
                let _ = write_half.window_change(columns, rows, 0, 0).await;
            }
            chunk = next_bootstrap_stdin_chunk(&mut stdin_rx), if stdin_rx.is_some() => {
                let Some(chunk) = chunk else {
                    stdin_rx = None;
                    let _ = write_half.eof().await;
                    continue;
                };
                let chunk = chunk.map_err(|error| {
                    SshError::new(FailureClass::IndeterminateAfterDispatch, error)
                })?;
                if chunk.is_empty() {
                    stdin_rx = None;
                    let _ = write_half.eof().await;
                    continue;
                }
                write_half.data_bytes(chunk).await.map_err(|error| {
                    SshError::new(
                        FailureClass::IndeterminateAfterDispatch,
                        format!("cannot write bootstrap SSH PTY input: {error}"),
                    )
                })?;
            }
            message = read_half.wait() => {
                let Some(message) = message else {
                    break;
                };
                match message {
                    ChannelMsg::Data { data } => {
                        write_bootstrap_stream(&data, false)?;
                    }
                    ChannelMsg::ExtendedData { data, ext: 1 } => {
                        write_bootstrap_stream(&data, true)?;
                    }
                    ChannelMsg::ExitStatus { exit_status } => {
                        status = Some(i32::try_from(exit_status).unwrap_or(i32::MAX));
                    }
                    ChannelMsg::ExitSignal { signal_name, .. } => {
                        signal = Some(signal_name);
                    }
                    ChannelMsg::Close => break,
                    _ => {}
                }
            }
        }
    }

    bootstrap_pty_status(status, signal)
}

fn bootstrap_pty_status(
    status: Option<i32>,
    signal: Option<russh::Sig>,
) -> Result<SshOutcome, SshError> {
    if let Some(status) = status {
        return Ok(SshOutcome { status });
    }
    if let Some(signal) = signal {
        let signal = remote_signal(signal);
        return Ok(SshOutcome {
            status: signal_status(&signal.name).unwrap_or(1),
        });
    }
    Err(SshError::new(
        FailureClass::IndeterminateAfterDispatch,
        "remote bootstrap SSH session ended without a numeric status",
    ))
}

fn spawn_bootstrap_stdin_reader() -> tokio::sync::mpsc::UnboundedReceiver<BootstrapStdinChunk> {
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

async fn next_bootstrap_stdin_chunk(
    receiver: &mut Option<tokio::sync::mpsc::UnboundedReceiver<BootstrapStdinChunk>>,
) -> Option<BootstrapStdinChunk> {
    if let Some(receiver) = receiver {
        receiver.recv().await
    } else {
        std::future::pending().await
    }
}

fn write_bootstrap_stream(bytes: &[u8], stderr: bool) -> Result<(), SshError> {
    if stderr {
        let mut stream = std::io::stderr().lock();
        stream.write_all(bytes).and_then(|_| stream.flush())
    } else {
        let mut stream = std::io::stdout().lock();
        stream.write_all(bytes).and_then(|_| stream.flush())
    }
    .map_err(|error| {
        SshError::new(
            FailureClass::IndeterminateAfterDispatch,
            format!("cannot write bootstrap SSH PTY output: {error}"),
        )
    })
}

#[cfg(unix)]
fn resize_signal(local_terminal: &LocalTerminal) -> Option<tokio::signal::unix::Signal> {
    if !(local_terminal.stdin || local_terminal.stdout || local_terminal.stderr) {
        return None;
    }
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
}

#[cfg(not(unix))]
fn resize_signal(_local_terminal: &LocalTerminal) -> Option<()> {
    None
}

#[cfg(unix)]
async fn wait_resize_signal(signal: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(signal) = signal {
        let _ = signal.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn wait_resize_signal(signal: &mut Option<()>) {
    if signal.is_some() {
        std::future::pending::<()>().await;
    }
}

fn effective_terminal_size(local_terminal: &LocalTerminal) -> (u32, u32) {
    terminal_size().unwrap_or_else(|| (local_terminal.columns.max(1), local_terminal.rows.max(1)))
}

fn terminal_size() -> Option<(u32, u32)> {
    terminal_size_from(std::io::stdout())
        .or_else(|| terminal_size_from(std::io::stdin()))
        .or_else(|| terminal_size_from(std::io::stderr()))
}

fn terminal_size_from<Fd: rustix::fd::AsFd>(fd: Fd) -> Option<(u32, u32)> {
    let size = rustix::termios::tcgetwinsize(fd).ok()?;
    if size.ws_col == 0 || size.ws_row == 0 {
        None
    } else {
        Some((u32::from(size.ws_col), u32::from(size.ws_row)))
    }
}

static BOOTSTRAP_RAW_TERMINAL_STATE: Mutex<Option<rustix::termios::Termios>> = Mutex::new(None);

struct BootstrapRawTerminalGuard {
    active: bool,
}

impl BootstrapRawTerminalGuard {
    fn enter() -> Result<Self, SshError> {
        let original = rustix::termios::tcgetattr(std::io::stdin()).map_err(|error| {
            SshError::new(
                FailureClass::Configuration,
                format!("cannot read local stdin terminal mode for bootstrap PTY: {error}"),
            )
        })?;
        let mut raw = original.clone();
        raw.make_raw();
        *BOOTSTRAP_RAW_TERMINAL_STATE
            .lock()
            .expect("bootstrap raw terminal state") = Some(original);
        if let Err(error) = rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Now,
            &raw,
        ) {
            restore_bootstrap_raw_terminal();
            return Err(SshError::new(
                FailureClass::Configuration,
                format!("cannot enter local stdin raw mode for bootstrap PTY: {error}"),
            ));
        }
        Ok(Self { active: true })
    }

    fn restore(&mut self) -> Result<(), SshError> {
        if self.active {
            self.active = false;
            restore_bootstrap_raw_terminal_checked()?;
        }
        Ok(())
    }
}

impl Drop for BootstrapRawTerminalGuard {
    fn drop(&mut self) {
        if self.active {
            restore_bootstrap_raw_terminal();
        }
    }
}

fn probe_stdin_raw_mode() -> Result<(), SshError> {
    let mut raw_terminal = BootstrapRawTerminalGuard::enter()?;
    raw_terminal.restore()
}

fn restore_bootstrap_raw_terminal() {
    let _ = restore_bootstrap_raw_terminal_checked();
}

fn restore_bootstrap_raw_terminal_checked() -> Result<(), SshError> {
    let state = BOOTSTRAP_RAW_TERMINAL_STATE
        .lock()
        .expect("bootstrap raw terminal state")
        .take();
    if let Some(original) = state {
        rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Now,
            &original,
        )
        .map_err(|error| {
            SshError::new(
                FailureClass::Configuration,
                format!("cannot restore local stdin terminal mode for bootstrap PTY: {error}"),
            )
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct SshTarget {
    name: String,
    address: String,
    port: u16,
    alias: String,
    profile: String,
    bootstrap_profiles: Vec<String>,
    connect_timeout: Duration,
    authentication_timeout: Option<Duration>,
    route: SshRoute,
}

#[derive(Debug, Clone)]
enum SshRoute {
    Direct,
    ViaJump(SshJump),
}

#[derive(Debug, Clone)]
struct SshJump {
    name: String,
    address: String,
    port: u16,
    alias: String,
    profile: String,
}

#[derive(Debug, Clone)]
struct OpenSshHost {
    id: String,
    host_name: String,
    port: u16,
    user: String,
    trust_alias: String,
    host_key_algorithm: String,
    identities: Vec<OpenSshConfigIdentity>,
    identity_agent: OpenSshIdentityAgent,
    request_tty: &'static str,
    proxy_jump: Option<String>,
}

#[derive(Debug, Clone)]
struct OpenSshHostPlan {
    id: String,
    host_name: String,
    port: u16,
    user: String,
    trust_alias: String,
    host_key_algorithm: String,
    identities: Vec<OpenSshPublicKeyIdentity>,
    identity_agent: OpenSshIdentityAgent,
    request_tty: &'static str,
    proxy_jump: Option<String>,
}

#[derive(Debug, Clone)]
enum OpenSshConfigIdentity {
    File(PathBuf),
    MaterializedPublicKey(PathBuf),
}

#[derive(Debug, Clone)]
enum OpenSshIdentityAgent {
    None,
    Socket(PathBuf),
}

#[derive(Debug, Clone)]
struct PinnedRouteKeys {
    target: HostKey,
    jump: Option<HostKey>,
}

pub fn run<R: SshRunner>(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &SshOptions,
    runner: &mut R,
) -> Result<SshOutcome, SshError> {
    if selected.len() != 1 {
        return Err(SshError::new(
            FailureClass::Selector,
            "remote ssh requires exactly one selected machine",
        ));
    }
    let target = plan_target(root, inventory, selected[0])?;
    preflight_proxy_reuse_inputs(&target, &options.home)?;
    let route_keys = preflight_known_hosts(&options.store, &target)?;
    let host_plans = plan_host_inputs(&target, options, &route_keys)?;
    validate_render_inputs(options.store.path(), &host_plans)?;
    validate_generated_artifact_config_values(&options.home, &host_plans)?;

    reclaim_stale_artifacts(&options.home)?;
    let artifacts = ArtifactDir::create(&options.home)?;
    let hosts = materialize_hosts(host_plans, &artifacts)?;
    let config = render_config(options.store.path(), &hosts, RenderConfigKind::RemoteSsh)?;
    let config_path = artifacts.write_private_file("config", config.as_bytes())?;
    let invocation = SshInvocation {
        program: OsString::from(SSH_PROGRAM),
        config: config_path,
        host: target.alias.clone(),
        environment: ssh_child_environment(&options.env_snapshot),
    };
    let status = runner.run(&invocation)?;
    Ok(SshOutcome { status })
}

pub async fn connect_bootstrap(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &BootstrapSshOptions,
) -> Result<BootstrapSession, SshError> {
    if selected.len() != 1 {
        return Err(SshError::new(
            FailureClass::Selector,
            "remote ssh --bootstrap requires exactly one selected machine",
        ));
    }
    let target = plan_target(root, inventory, selected[0])?;
    let route_keys = preflight_known_hosts(&options.store, &target)?;
    connect_bootstrap_target(target, route_keys, options).await
}

async fn run_provision_prologue<T, F>(prologue: F) -> Result<T, SshError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, SshError> + Send + 'static,
{
    tokio::task::spawn_blocking(prologue)
        .await
        .unwrap_or_else(|_| {
            Err(SshError::new(
                FailureClass::Configuration,
                "ssh provisioning preflight worker failed",
            ))
        })
}

async fn provision_connect_prologue(
    target: &crate::provision::ProvisionTarget,
    options: &BootstrapSshOptions,
    canonical_only: bool,
) -> Result<(SshTarget, PinnedRouteKeys), SshError> {
    let authentication_timeout = provision_auth_timeout(target);
    let target = target.clone();
    let store = options.store.clone();
    run_provision_prologue(move || {
        let mut target = provision_target(&target, Some(authentication_timeout))?;
        if canonical_only {
            target.bootstrap_profiles.clear();
        }
        let route_keys = preflight_known_hosts(&store, &target)?;
        Ok((target, route_keys))
    })
    .await
}

pub(crate) async fn connect_bootstrap_provision_target(
    target: &crate::provision::ProvisionTarget,
    options: &BootstrapSshOptions,
) -> Result<BootstrapSession, SshError> {
    let (target, route_keys) = provision_connect_prologue(target, options, false).await?;
    connect_bootstrap_target(target, route_keys, options).await
}

pub(crate) async fn connect_canonical_provision_target(
    target: &crate::provision::ProvisionTarget,
    options: &BootstrapSshOptions,
) -> Result<BootstrapSession, SshError> {
    let (target, route_keys) = provision_connect_prologue(target, options, true).await?;
    connect_bootstrap_target(target, route_keys, options).await
}

#[derive(Debug)]
pub(crate) struct ProvisionLocalOpenSshHandoff {
    config: PathBuf,
    host: String,
    artifacts: ArtifactDir,
}

impl ProvisionLocalOpenSshHandoff {
    pub(crate) fn config(&self) -> &Path {
        &self.config
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn cleanup(self) -> Result<(), std::io::Error> {
        self.artifacts.cleanup()
    }
}

pub(crate) fn prepare_provision_local_openssh_handoff(
    target: &crate::provision::ProvisionTarget,
    home: &Path,
    store: &KnownHostsStore,
    auth_context: &AuthContext,
) -> Result<ProvisionLocalOpenSshHandoff, SshError> {
    let target = provision_target(target, None)?;
    preflight_proxy_reuse_inputs(&target, home)?;
    let route_keys = preflight_known_hosts(store, &target)?;
    let options = SshOptions {
        pty: PtyMode::Disable,
        home: home.to_path_buf(),
        store: store.clone(),
        auth_context: auth_context.clone(),
        env_snapshot: Vec::new(),
    };
    let host_plans = plan_host_inputs(&target, &options, &route_keys)?;
    validate_render_inputs(store.path(), &host_plans)?;
    validate_generated_artifact_config_values(home, &host_plans)?;

    reclaim_stale_artifacts(home)?;
    let artifacts = ArtifactDir::create(home)?;
    let hosts = materialize_hosts(host_plans, &artifacts)?;
    let config = render_config(store.path(), &hosts, RenderConfigKind::ProvisionLocal)?;
    let config = artifacts.write_private_file("config", config.as_bytes())?;
    Ok(ProvisionLocalOpenSshHandoff {
        config,
        host: target.alias,
        artifacts,
    })
}

pub(crate) async fn prove_canonical_provision_target(
    target: &crate::provision::ProvisionTarget,
    options: &BootstrapSshOptions,
) -> Result<(), SshError> {
    let session = connect_canonical_provision_target(target, options).await?;
    session.disconnect().await;
    Ok(())
}

pub(crate) async fn prove_public_key_only_provision_target(
    target: &crate::provision::ProvisionTarget,
    options: &BootstrapSshOptions,
) -> Result<(), SshProbeError> {
    let timeout = Duration::from_secs(target.command_timeout.seconds);
    let owned_target = target.clone();
    let store = options.store.clone();
    let auth_context = options.auth_context.clone();
    let (target, canonical_profile, route_keys) = run_provision_prologue(move || {
        let target = provision_target(&owned_target, None)?;
        let canonical_profile =
            openssh_public_key_profile(&auth_context, &target.profile).map_err(auth_failure)?;
        let route_keys = preflight_known_hosts(&store, &target)?;
        Ok((target, canonical_profile, route_keys))
    })
    .await
    .map_err(|error| SshProbeError::from_ssh(error, false))?;
    let mut connection = connect_target_session(&target, route_keys, options)
        .await
        .map_err(|error| SshProbeError::from_ssh(error, false))?;
    let result = public_key_only_auth_probe(
        connection.as_mut(),
        &canonical_profile.user,
        timeout,
        &options.cancel,
    )
    .await;
    let _ = connection
        .session
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await;
    if let Some(jump) = connection.jump_session.take() {
        let _ = jump
            .disconnect(russh::Disconnect::ByApplication, "", "English")
            .await;
    }
    result
}

pub fn run_bootstrap_interactive(
    root: &Path,
    inventory: &EffectiveInventory,
    selected: &[&EffectiveMachine],
    options: &BootstrapSshOptions,
    local_terminal: &LocalTerminal,
) -> Result<SshOutcome, SshError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            SshError::new(
                FailureClass::CapabilityUnsupported,
                format!("cannot initialize bootstrap SSH runner: {error}"),
            )
        })?;
    runtime.block_on(async {
        let session = connect_bootstrap(root, inventory, selected, options).await?;
        session
            .run_interactive_pty(local_terminal, &options.cancel)
            .await
    })
}

fn plan_target(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &EffectiveMachine,
) -> Result<SshTarget, SshError> {
    let route = if machine.route == "direct" {
        SshRoute::Direct
    } else {
        let jump = inventory
            .jumps
            .iter()
            .find(|jump| jump.name == machine.route)
            .ok_or_else(|| {
                SshError::new(
                    FailureClass::Configuration,
                    format!("unknown jump host {}", machine.route),
                )
            })?;
        SshRoute::ViaJump(plan_jump(root, inventory, jump))
    };
    Ok(SshTarget {
        name: machine.name.clone(),
        address: machine.address.clone(),
        port: machine.port,
        alias: target_alias(root, &inventory.environment, &machine.name),
        profile: machine.canonical_profile.clone(),
        bootstrap_profiles: machine
            .bootstrap_profiles
            .iter()
            .map(|auth| auth.profile.clone())
            .collect(),
        connect_timeout: Duration::from_secs(machine.timeouts.connect.seconds),
        authentication_timeout: None,
        route,
    })
}

fn plan_jump(root: &Path, inventory: &EffectiveInventory, jump: &EffectiveJump) -> SshJump {
    let alias = match jump.scope {
        JumpScope::Root => root_jump_alias(root, &jump.name),
        JumpScope::Environment => env_jump_alias(root, &inventory.environment, &jump.name),
    };
    SshJump {
        name: jump.name.clone(),
        address: jump.address.clone(),
        port: jump.port,
        alias,
        profile: jump.auth_profile.clone(),
    }
}

fn provision_target(
    target: &crate::provision::ProvisionTarget,
    authentication_timeout: Option<Duration>,
) -> Result<SshTarget, SshError> {
    let route = match &target.jump {
        Some(jump) => SshRoute::ViaJump(SshJump {
            name: jump.name.clone(),
            address: jump.address.clone(),
            port: jump.port,
            alias: jump.alias.clone(),
            profile: jump.auth_profile.clone(),
        }),
        None if target.route == "direct" => SshRoute::Direct,
        None => {
            return Err(SshError::new(
                FailureClass::Configuration,
                format!("unknown jump host {}", target.route),
            ));
        }
    };
    Ok(SshTarget {
        name: target.machine.clone(),
        address: target.address.clone(),
        port: target.port,
        alias: target.target_alias.clone(),
        profile: target.canonical_profile.clone(),
        bootstrap_profiles: target
            .bootstrap_profiles
            .iter()
            .map(|auth| auth.profile.clone())
            .collect(),
        connect_timeout: Duration::from_secs(target.connect_timeout.seconds),
        authentication_timeout,
        route,
    })
}

fn provision_auth_timeout(target: &crate::provision::ProvisionTarget) -> Duration {
    Duration::from_secs(target.connect_timeout.seconds)
}

async fn connect_bootstrap_target(
    target: SshTarget,
    route_keys: PinnedRouteKeys,
    options: &BootstrapSshOptions,
) -> Result<BootstrapSession, SshError> {
    let first = connect_target_session(&target, route_keys.clone(), options).await?;
    let connections = TargetConnections {
        target: &target,
        route_keys,
        options,
    };
    let authenticated = authenticate_bootstrap_target_session(
        first,
        &connections,
        &target,
        &options.auth_context,
        &options.cancel,
    )
    .await?;
    let authentication = if authenticated.profile == target.profile {
        BootstrapAuthentication::Canonical
    } else {
        BootstrapAuthentication::Bootstrap
    };

    Ok(BootstrapSession {
        machine: target.name.clone(),
        authenticated_profile: authenticated.profile,
        authentication,
        session: authenticated.connection.session,
        jump_session: authenticated.connection.jump_session,
    })
}

pub(crate) struct TargetConnection {
    session: client::Handle<StrictHandler>,
    jump_session: Option<client::Handle<StrictHandler>>,
    link: LinkState,
}

impl AsMut<client::Handle<StrictHandler>> for TargetConnection {
    fn as_mut(&mut self) -> &mut client::Handle<StrictHandler> {
        &mut self.session
    }
}

impl TargetConnection {
    fn lost(&self) -> Option<String> {
        match self.link.loss() {
            Some(LinkLoss::ServerDisconnect { message, .. }) if !message.is_empty() => Some(
                format!("server disconnected during authentication: {message}"),
            ),
            Some(LinkLoss::ServerDisconnect { reason, .. }) => Some(format!(
                "server disconnected during authentication ({reason})"
            )),
            Some(LinkLoss::TransportError(error)) => Some(format!(
                "SSH connection lost during authentication: {error}"
            )),
            None => self
                .session
                .is_closed()
                .then(|| "SSH connection closed during authentication".to_string()),
        }
    }
}

struct TargetConnections<'a> {
    target: &'a SshTarget,
    route_keys: PinnedRouteKeys,
    options: &'a BootstrapSshOptions,
}

impl AttemptConnections for TargetConnections<'_> {
    type Handler = StrictHandler;
    type Connection = TargetConnection;

    fn connect(&self) -> ConnectFuture<'_, TargetConnection> {
        Box::pin(async move {
            connect_target_session(self.target, self.route_keys.clone(), self.options)
                .await
                .map_err(|error| {
                    crate::auth::AuthFailure::connection_failed(error.class(), error.to_string())
                })
        })
    }

    fn lost(&self, connection: &TargetConnection) -> Option<String> {
        connection.lost()
    }
}

async fn authenticate_bootstrap_target_session<T: AttemptConnections<Handler = StrictHandler>>(
    first: T::Connection,
    connections: &T,
    target: &SshTarget,
    auth_context: &AuthContext,
    cancel: &CancellationToken,
) -> Result<Authenticated<T::Connection>, SshError> {
    match target.authentication_timeout {
        Some(budget) => {
            let clock = crate::secret::PacedClock::new();
            let auth_context = auth_context.clone().with_paced_clock(clock.clone());
            let bound = ProvisionAttemptBound {
                cancel: cancel.clone(),
                budget,
                clock,
            };
            let auth = crate::auth::authenticate_canonical_then_bootstrap_bounded_cancellable(
                first,
                connections,
                &auth_context,
                &target.profile,
                &target.bootstrap_profiles,
                cancel,
                &bound,
            );
            cancellable_auth(cancel, auth).await
        }
        None => {
            let auth = crate::auth::authenticate_canonical_then_bootstrap_cancellable(
                first,
                connections,
                auth_context,
                &target.profile,
                &target.bootstrap_profiles,
                cancel,
            );
            cancellable_auth(cancel, auth).await
        }
    }
}

struct ProvisionAttemptBound {
    cancel: CancellationToken,
    budget: Duration,
    clock: crate::secret::PacedClock,
}

impl crate::auth::AttemptBound for ProvisionAttemptBound {
    fn bound<'a>(
        &'a self,
        attempt: crate::auth::AttemptFuture<'a>,
    ) -> crate::auth::AttemptFuture<'a> {
        Box::pin(cancellable_timed_auth(
            &self.cancel,
            self.budget,
            &self.clock,
            attempt,
            "provisioning target authentication timed out",
        ))
    }
}

async fn connect_target_session(
    target: &SshTarget,
    route_keys: PinnedRouteKeys,
    options: &BootstrapSshOptions,
) -> Result<TargetConnection, SshError> {
    let deadline = tokio::time::Instant::now() + target.connect_timeout;
    Ok(match &target.route {
        SshRoute::Direct => {
            let stream = cancellable(&options.cancel, async {
                crate::transport::connect_tcp(&target.address, target.port, deadline)
                    .await
                    .map_err(transport_failure)
            })
            .await?;
            let (session, link) = cancellable(
                &options.cancel,
                connect_strict_observed(stream, route_keys.target.clone(), deadline),
            )
            .await
            .map_err(|error| strict_target_trust_failure(&target.name, error))?;
            TargetConnection {
                session,
                jump_session: None,
                link,
            }
        }
        SshRoute::ViaJump(jump) => {
            let jump_key = route_keys.jump.clone().ok_or_else(|| {
                SshError::new(
                    FailureClass::Configuration,
                    "remote ssh --bootstrap jump route is missing a pinned key",
                )
            })?;
            let stream = cancellable(&options.cancel, async {
                crate::transport::connect_tcp(&jump.address, jump.port, deadline)
                    .await
                    .map_err(|error| jump_endpoint_failure(&jump.name, error))
            })
            .await?;
            let mut jump_session =
                cancellable(&options.cancel, connect_strict(stream, jump_key, deadline))
                    .await
                    .map_err(|error| strict_jump_trust_failure(&jump.name, error))?;
            cancellable(&options.cancel, async {
                timeout_at(
                    deadline,
                    crate::auth::authenticate_profile_cancellable(
                        &mut jump_session,
                        &options.auth_context,
                        &jump.profile,
                        &options.cancel,
                    ),
                    FailureClass::JumpFailure,
                    "jump authentication timed out",
                )
                .await?
                .map_err(|error| {
                    let error = error.into_jump_failure(&jump.name);
                    SshError::new(error.class(), error.to_string())
                })
            })
            .await?;
            let channel = cancellable(&options.cancel, async {
                tokio::time::timeout_at(
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
                    SshError::new(
                        FailureClass::JumpFailure,
                        format!(
                            "jump host {} timed out opening target channel to {}:{}",
                            jump.name, target.address, target.port
                        ),
                    )
                })?
                .map_err(|error| {
                    SshError::new(
                        FailureClass::JumpFailure,
                        format!(
                            "jump host {} could not open target channel to {}:{}: {error}",
                            jump.name, target.address, target.port
                        ),
                    )
                })
            })
            .await?;
            let (session, link) = cancellable(
                &options.cancel,
                connect_strict_observed(channel.into_stream(), route_keys.target.clone(), deadline),
            )
            .await
            .map_err(|error| strict_target_trust_failure(&target.name, error))?;
            TargetConnection {
                session,
                jump_session: Some(jump_session),
                link,
            }
        }
    })
}

async fn public_key_only_auth_probe(
    session: &mut client::Handle<StrictHandler>,
    user: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Result<(), SshProbeError> {
    if cancel.is_cancelled() {
        return Err(SshProbeError::new(
            FailureClass::Cancellation,
            "cancelled",
            false,
        ));
    }
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            return Err(SshProbeError::new(
                FailureClass::Cancellation,
                "cancelled",
                true,
            ));
        }
        result = tokio::time::timeout(timeout, session.authenticate_none(user)) => result,
    };
    let result = result
        .map_err(|_| {
            SshProbeError::new(
                FailureClass::SecurityGate,
                "public-key-only authentication probe timed out after dispatch",
                true,
            )
        })?
        .map_err(|error| {
            SshProbeError::new(
                FailureClass::SecurityGate,
                format!("public-key-only authentication probe failed: {error}"),
                true,
            )
        })?;
    match result {
        client::AuthResult::Success => Err(SshProbeError::new(
            FailureClass::SecurityGate,
            "target accepted SSH none authentication during the security gate",
            true,
        )),
        client::AuthResult::Failure {
            remaining_methods,
            partial_success,
        } => validate_public_key_only_method_set(&remaining_methods, partial_success),
    }
}

fn validate_public_key_only_method_set(
    remaining_methods: &MethodSet,
    partial_success: bool,
) -> Result<(), SshProbeError> {
    if partial_success {
        return Err(SshProbeError::new(
            FailureClass::SecurityGate,
            "public-key-only authentication probe returned partial success",
            true,
        ));
    }
    if remaining_methods.has_unknown() {
        return Err(SshProbeError::new(
            FailureClass::SecurityGate,
            "target advertises unrecognized authentication methods during the security gate",
            true,
        ));
    }
    if remaining_methods.len() == 1 && remaining_methods[0] == MethodKind::PublicKey {
        return Ok(());
    }
    Err(SshProbeError::new(
        FailureClass::SecurityGate,
        "target did not advertise exactly one remaining SSH authentication method: publickey",
        true,
    ))
}

fn transport_failure(error: crate::transport::FetchFailure) -> SshError {
    SshError::new(error.class, error.diagnostic)
}

fn jump_endpoint_failure(jump_name: &str, error: crate::transport::FetchFailure) -> SshError {
    SshError::new(
        error.class,
        format!(
            "jump host {jump_name} endpoint failed before target connection: {}",
            error.diagnostic
        ),
    )
}

async fn connect_strict_observed<R>(
    stream: R,
    expected: HostKey,
    deadline: tokio::time::Instant,
) -> Result<(client::Handle<StrictHandler>, LinkState), SshError>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let algorithm = pinned_algorithm(&expected)?;
    let config = bootstrap_client_config(&[algorithm])?;
    let handler = StrictHandler::new(expected);
    let link = handler.link();
    let session = tokio::time::timeout_at(
        deadline,
        client::connect_stream(Arc::new(config), stream, handler),
    )
    .await
    .map_err(|_| SshError::new(FailureClass::Protocol, "SSH key exchange timed out"))?
    .map_err(strict_connect_failure)?;
    Ok((session, link))
}

async fn connect_strict<R>(
    stream: R,
    expected: HostKey,
    deadline: tokio::time::Instant,
) -> Result<client::Handle<StrictHandler>, SshError>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_strict_observed(stream, expected, deadline)
        .await
        .map(|(session, _link)| session)
}

fn strict_connect_failure(error: russh::Error) -> SshError {
    match error {
        russh::Error::UnknownKey | russh::Error::KeyChanged { .. } => SshError::new(
            FailureClass::UnknownHostKey,
            "strict host-key verification failed",
        ),
        russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Key,
            ..
        } => SshError::new(
            FailureClass::ChangedHostKey,
            "host no longer offers the pinned host-key algorithm",
        ),
        error => SshError::new(
            FailureClass::Protocol,
            format!("SSH protocol failure before host-key verification: {error}"),
        ),
    }
}

fn strict_target_trust_failure(target_name: &str, error: SshError) -> SshError {
    if error.class == FailureClass::UnknownHostKey {
        SshError::new(
            FailureClass::ChangedHostKey,
            "target host key does not match the pinned key",
        )
    } else if error.class == FailureClass::Protocol {
        SshError::new(
            FailureClass::Protocol,
            format!("target {target_name}: {error}"),
        )
    } else {
        error
    }
}

fn strict_jump_trust_failure(jump_name: &str, error: SshError) -> SshError {
    if error.class == FailureClass::UnknownHostKey {
        SshError::new(
            FailureClass::ChangedHostKey,
            format!("jump host {jump_name} key does not match the pinned key"),
        )
    } else if error.class == FailureClass::Protocol {
        SshError::new(
            FailureClass::Protocol,
            format!("jump host {jump_name}: {error}"),
        )
    } else {
        error
    }
}

fn bootstrap_client_config(algorithms: &[String]) -> Result<client::Config, SshError> {
    let algorithms = algorithms
        .iter()
        .map(|name| {
            Algorithm::from_str(name).map_err(|_| {
                SshError::new(
                    FailureClass::Configuration,
                    format!("unsupported configured host-key algorithm {name}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(crate::transport::strict_client_config_from_algorithms(
        algorithms, None,
    ))
}

async fn timeout_at<T>(
    deadline: tokio::time::Instant,
    future: impl Future<Output = T>,
    class: FailureClass,
    diagnostic: &'static str,
) -> Result<T, SshError> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| SshError::new(class, diagnostic))
}

async fn cancellable<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, SshError>>,
) -> Result<T, SshError> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancellation_failure()),
        result = future => result,
    }
}

async fn cancellable_auth<T>(
    cancel: &CancellationToken,
    future: impl Future<Output = Result<T, crate::auth::AuthFailure>>,
) -> Result<T, SshError> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancellation_failure()),
        result = future => result.map_err(auth_failure),
    }
}

async fn cancellable_timed_auth<T>(
    cancel: &CancellationToken,
    budget: Duration,
    clock: &crate::secret::PacedClock,
    future: impl Future<Output = Result<T, crate::auth::AuthFailure>>,
    timeout_diagnostic: &'static str,
) -> Result<T, crate::auth::AuthFailure> {
    if cancel.is_cancelled() {
        return Err(crate::auth::AuthFailure::cancelled());
    }
    let from = clock.charged();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(crate::auth::AuthFailure::cancelled()),
        _ = clock.expired(from, budget) => {
            Err(crate::auth::AuthFailure::attempt_timed_out(timeout_diagnostic))
        }
        result = future => result,
    }
}

fn cancellation_failure() -> SshError {
    SshError::new(FailureClass::Cancellation, "cancelled")
}

fn preflight_proxy_reuse_inputs(target: &SshTarget, home: &Path) -> Result<(), SshError> {
    if !matches!(target.route, SshRoute::ViaJump(_)) {
        return Ok(());
    }
    if !proxy_config_path_safe(home.join(".broil/tmp/remote")) {
        return Err(SshError::new(
            FailureClass::TransferPathSafety,
            "remote ssh temporary path cannot be safely reused by system OpenSSH proxy delegation",
        ));
    }
    if !proxy_config_path_safe(OsStr::new(SSH_PROGRAM)) {
        return Err(SshError::new(
            FailureClass::TransferPathSafety,
            "system ssh argv[0] cannot be safely reused by system OpenSSH proxy delegation",
        ));
    }
    if !proxy_target_address_safe(&target.address) {
        return Err(SshError::new(
            FailureClass::Configuration,
            format!(
                "remote ssh target address for {} cannot be safely reused by system OpenSSH proxy delegation",
                target.name
            ),
        ));
    }
    Ok(())
}

fn proxy_config_path_safe(value: impl AsRef<OsStr>) -> bool {
    value
        .as_ref()
        .as_encoded_bytes()
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn proxy_target_address_safe(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'%' | b'-')
    })
}

fn preflight_known_hosts(
    store: &KnownHostsStore,
    target: &SshTarget,
) -> Result<PinnedRouteKeys, SshError> {
    let target_key = pinned_key(store, &target.alias)?;
    let jump_key = if let SshRoute::ViaJump(jump) = &target.route {
        Some(pinned_key(store, &jump.alias)?)
    } else {
        None
    };
    Ok(PinnedRouteKeys {
        target: target_key,
        jump: jump_key,
    })
}

fn pinned_key(store: &KnownHostsStore, alias: &str) -> Result<HostKey, SshError> {
    match store
        .snapshot()
        .and_then(|snapshot| snapshot.inspect(alias, false))
    {
        Ok(AliasState::Pinned(key)) => Ok(key),
        Ok(AliasState::Unknown) => Err(SshError::new(
            FailureClass::UnknownHostKey,
            "host key is not pinned in the Broil known-hosts store",
        )),
        Ok(AliasState::Replaceable { .. }) => unreachable!(
            "read-only known-hosts inspection must classify replaceable state as an error"
        ),
        Err(error) => Err(store_failure(error)),
    }
}

fn store_failure(error: StoreError) -> SshError {
    SshError::new(error.class(), error.to_string())
}

fn plan_host_inputs(
    target: &SshTarget,
    options: &SshOptions,
    route_keys: &PinnedRouteKeys,
) -> Result<Vec<OpenSshHostPlan>, SshError> {
    let target_profile =
        openssh_public_key_profile(&options.auth_context, &target.profile).map_err(auth_failure)?;
    let mut hosts = Vec::new();
    if let SshRoute::ViaJump(jump) = &target.route {
        let jump_profile = openssh_public_key_profile(&options.auth_context, &jump.profile)
            .map_err(auth_failure)?;
        let jump_key = route_keys.jump.as_ref().ok_or_else(|| {
            SshError::new(
                FailureClass::Configuration,
                "remote ssh jump route is missing a pinned key",
            )
        })?;
        hosts.push(OpenSshHostPlan {
            id: jump.alias.clone(),
            host_name: jump.address.clone(),
            port: jump.port,
            user: jump_profile.user,
            trust_alias: jump.alias.clone(),
            host_key_algorithm: pinned_algorithm(jump_key)?,
            identities: jump_profile.identities,
            identity_agent: identity_agent(jump_profile.agent_socket),
            request_tty: "no",
            proxy_jump: None,
        });
    }
    hosts.push(OpenSshHostPlan {
        id: target.alias.clone(),
        host_name: target.address.clone(),
        port: target.port,
        user: target_profile.user,
        trust_alias: target.alias.clone(),
        host_key_algorithm: pinned_algorithm(&route_keys.target)?,
        identities: target_profile.identities,
        identity_agent: identity_agent(target_profile.agent_socket),
        request_tty: match options.pty {
            PtyMode::Force => "force",
            PtyMode::Disable => "no",
        },
        proxy_jump: match &target.route {
            SshRoute::Direct => None,
            SshRoute::ViaJump(jump) => Some(jump.alias.clone()),
        },
    });
    Ok(hosts)
}

fn materialize_hosts(
    plans: Vec<OpenSshHostPlan>,
    artifacts: &ArtifactDir,
) -> Result<Vec<OpenSshHost>, SshError> {
    plans
        .into_iter()
        .map(|plan| {
            Ok(OpenSshHost {
                id: plan.id,
                host_name: plan.host_name,
                port: plan.port,
                user: plan.user,
                trust_alias: plan.trust_alias,
                host_key_algorithm: plan.host_key_algorithm,
                identities: materialize_identities(&plan.identities, artifacts)?,
                identity_agent: plan.identity_agent,
                request_tty: plan.request_tty,
                proxy_jump: plan.proxy_jump,
            })
        })
        .collect()
}

fn validate_render_inputs(store_path: &Path, hosts: &[OpenSshHostPlan]) -> Result<(), SshError> {
    render_argv_token(path_value(store_path)?, ValueRule::PercentExpand)?;
    render_argv_token(
        path_value(Path::new("/dev/null"))?,
        ValueRule::PercentExpand,
    )?;
    for host in hosts {
        if !route_token_safe(&host.id) || !route_token_safe(&host.trust_alias) {
            return Err(SshError::new(
                FailureClass::Configuration,
                "remote ssh generated an unsafe OpenSSH route token",
            ));
        }
        render_argv_token(&host.host_name, ValueRule::PercentExpand)?;
        render_argv_token(&host.user, ValueRule::Literal)?;
        render_argv_token(&host.host_key_algorithm, ValueRule::Literal)?;
        render_argv_token(&host.port.to_string(), ValueRule::Literal)?;
        render_argv_token(host.request_tty, ValueRule::Literal)?;
        if let Some(jump) = &host.proxy_jump {
            if !route_token_safe(jump) {
                return Err(SshError::new(
                    FailureClass::Configuration,
                    "remote ssh generated an unsafe OpenSSH route token",
                ));
            }
        }
        match &host.identity_agent {
            OpenSshIdentityAgent::None => {
                render_argv_token("none", ValueRule::Literal)?;
            }
            OpenSshIdentityAgent::Socket(path) => {
                let value = path_value(path)?;
                validate_identity_agent_value(value)?;
                render_argv_token(value, ValueRule::PercentExpand)?;
            }
        }
        for identity in &host.identities {
            if let OpenSshPublicKeyIdentity::File { path } = identity {
                render_argv_token(path_value(path)?, ValueRule::PercentExpand)?;
            }
        }
    }
    Ok(())
}

fn validate_generated_artifact_config_values(
    home: &Path,
    hosts: &[OpenSshHostPlan],
) -> Result<(), SshError> {
    let needs_materialized_identity = hosts.iter().any(|host| {
        host.identities
            .iter()
            .any(|identity| matches!(identity, OpenSshPublicKeyIdentity::Agent { .. }))
    });
    if needs_materialized_identity {
        let sample = home.join(
            ".broil/tmp/remote/ssh.00000000000000000000000000000000/identity-0.pub.00000000000000000000000000000000",
        );
        render_argv_token(path_value(&sample)?, ValueRule::PercentExpand)?;
    }
    Ok(())
}

fn auth_failure(error: crate::auth::AuthFailure) -> SshError {
    SshError::new(error.class(), error.to_string())
}

fn pinned_algorithm(key: &HostKey) -> Result<String, SshError> {
    if is_verifiable_host_key_algorithm(&key.algorithm) {
        Ok(key.algorithm.clone())
    } else {
        Err(SshError::new(
            FailureClass::Configuration,
            "pinned host key is outside the v1 verifiable-algorithm boundary",
        ))
    }
}

fn is_verifiable_host_key_algorithm(value: &str) -> bool {
    matches!(
        value,
        "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521"
    )
}

fn identity_agent(socket: Option<PathBuf>) -> OpenSshIdentityAgent {
    match socket {
        Some(path) => OpenSshIdentityAgent::Socket(path),
        None => OpenSshIdentityAgent::None,
    }
}

fn materialize_identities(
    identities: &[OpenSshPublicKeyIdentity],
    artifacts: &ArtifactDir,
) -> Result<Vec<OpenSshConfigIdentity>, SshError> {
    identities
        .iter()
        .enumerate()
        .map(|(index, identity)| match identity {
            OpenSshPublicKeyIdentity::File { path } => {
                Ok(OpenSshConfigIdentity::File(path.clone()))
            }
            OpenSshPublicKeyIdentity::Agent { public_key } => {
                let path = artifacts
                    .write_private_file(&format!("identity-{index}.pub"), public_key.as_bytes())?;
                Ok(OpenSshConfigIdentity::MaterializedPublicKey(path))
            }
        })
        .collect()
}

#[derive(Clone, Copy)]
enum RenderConfigKind {
    RemoteSsh,
    ProvisionLocal,
}

fn render_config(
    store_path: &Path,
    hosts: &[OpenSshHost],
    kind: RenderConfigKind,
) -> Result<String, SshError> {
    let mut output = String::new();
    output.push_str("Host *\n");
    if matches!(kind, RenderConfigKind::ProvisionLocal) {
        push_keyword(&mut output, "BatchMode", "yes", ValueRule::Literal)?;
    }
    push_keyword(
        &mut output,
        "CanonicalizeHostname",
        "no",
        ValueRule::Literal,
    )?;
    push_keyword(&mut output, "CheckHostIP", "no", ValueRule::Literal)?;
    push_keyword(
        &mut output,
        "ClearAllForwardings",
        "yes",
        ValueRule::Literal,
    )?;
    push_keyword(&mut output, "ControlMaster", "no", ValueRule::Literal)?;
    push_keyword(&mut output, "ForwardAgent", "no", ValueRule::Literal)?;
    push_keyword(&mut output, "ForwardX11", "no", ValueRule::Literal)?;
    push_keyword(
        &mut output,
        "GlobalKnownHostsFile",
        path_value(Path::new("/dev/null"))?,
        ValueRule::PercentExpand,
    )?;
    push_keyword(
        &mut output,
        "HostbasedAuthentication",
        "no",
        ValueRule::Literal,
    )?;
    push_keyword(&mut output, "IdentitiesOnly", "yes", ValueRule::Literal)?;
    push_keyword(
        &mut output,
        "KbdInteractiveAuthentication",
        "no",
        ValueRule::Literal,
    )?;
    push_keyword(
        &mut output,
        "PasswordAuthentication",
        "no",
        ValueRule::Literal,
    )?;
    push_keyword(&mut output, "PermitLocalCommand", "no", ValueRule::Literal)?;
    push_keyword(
        &mut output,
        "PreferredAuthentications",
        "publickey",
        ValueRule::Literal,
    )?;
    push_keyword(
        &mut output,
        "PubkeyAuthentication",
        "yes",
        ValueRule::Literal,
    )?;
    push_keyword(
        &mut output,
        "StrictHostKeyChecking",
        "yes",
        ValueRule::Literal,
    )?;
    push_keyword(&mut output, "UpdateHostKeys", "no", ValueRule::Literal)?;
    push_keyword(
        &mut output,
        "UserKnownHostsFile",
        path_value(store_path)?,
        ValueRule::PercentExpand,
    )?;
    for host in hosts {
        push_host_block(&mut output, host)?;
    }
    Ok(output)
}

fn push_host_block(output: &mut String, host: &OpenSshHost) -> Result<(), SshError> {
    output.push_str("Host ");
    push_bare_route_token(output, &host.id)?;
    output.push('\n');
    push_keyword(
        output,
        "HostName",
        &host.host_name,
        ValueRule::PercentExpand,
    )?;
    push_keyword(
        output,
        "HostKeyAlias",
        &host.trust_alias,
        ValueRule::Literal,
    )?;
    push_keyword(
        output,
        "HostKeyAlgorithms",
        &host.host_key_algorithm,
        ValueRule::Literal,
    )?;
    push_keyword(output, "Port", &host.port.to_string(), ValueRule::Literal)?;
    if let Some(jump) = &host.proxy_jump {
        push_raw_bare_keyword(output, "ProxyJump", jump)?;
    }
    push_keyword(output, "RequestTTY", host.request_tty, ValueRule::Literal)?;
    push_keyword(output, "User", &host.user, ValueRule::Literal)?;
    push_identity_agent(output, &host.identity_agent)?;
    for identity in &host.identities {
        match identity {
            OpenSshConfigIdentity::File(path)
            | OpenSshConfigIdentity::MaterializedPublicKey(path) => {
                push_keyword(
                    output,
                    "IdentityFile",
                    path_value(path)?,
                    ValueRule::PercentExpand,
                )?;
            }
        }
    }
    push_keyword(
        output,
        "CertificateFile",
        path_value(Path::new("/dev/null"))?,
        ValueRule::PercentExpand,
    )?;
    Ok(())
}

fn push_identity_agent(
    output: &mut String,
    identity_agent: &OpenSshIdentityAgent,
) -> Result<(), SshError> {
    match identity_agent {
        OpenSshIdentityAgent::None => {
            push_keyword(output, "IdentityAgent", "none", ValueRule::Literal)
        }
        OpenSshIdentityAgent::Socket(path) => {
            let value = path_value(path)?;
            validate_identity_agent_value(value)?;
            push_keyword(output, "IdentityAgent", value, ValueRule::PercentExpand)
        }
    }
}

#[derive(Clone, Copy)]
enum ValueRule {
    Literal,
    PercentExpand,
}

fn push_keyword(
    output: &mut String,
    name: &str,
    value: &str,
    rule: ValueRule,
) -> Result<(), SshError> {
    output.push_str("  ");
    output.push_str(name);
    output.push(' ');
    push_argv_token(output, value, rule)?;
    output.push('\n');
    Ok(())
}

fn push_raw_bare_keyword(output: &mut String, name: &str, value: &str) -> Result<(), SshError> {
    output.push_str("  ");
    output.push_str(name);
    output.push(' ');
    push_bare_route_token(output, value)?;
    output.push('\n');
    Ok(())
}

fn push_bare_route_token(output: &mut String, value: &str) -> Result<(), SshError> {
    if !route_token_safe(value) {
        return Err(SshError::new(
            FailureClass::Configuration,
            "remote ssh generated an unsafe OpenSSH route token",
        ));
    }
    output.push_str(value);
    Ok(())
}

fn route_token_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn push_argv_token(output: &mut String, value: &str, rule: ValueRule) -> Result<(), SshError> {
    let rendered = render_argv_token(value, rule)?;
    output.push('"');
    output.push_str(&rendered);
    output.push('"');
    Ok(())
}

fn render_argv_token(value: &str, rule: ValueRule) -> Result<String, SshError> {
    validate_config_value(value)?;
    let mut output = String::new();
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            return Err(SshError::new(
                FailureClass::Configuration,
                "remote ssh generated an OpenSSH config value that cannot be represented safely",
            ));
        }
        if matches!(rule, ValueRule::PercentExpand) && character == '%' {
            output.push_str("%%");
        } else {
            output.push(character);
        }
    }
    Ok(output)
}

fn validate_config_value(value: &str) -> Result<(), SshError> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character == '\u{7f}' || character.is_control())
    {
        return Err(SshError::new(
            FailureClass::Configuration,
            "remote ssh generated an unsafe OpenSSH config value",
        ));
    }
    if value.contains("${") {
        return Err(SshError::new(
            FailureClass::Configuration,
            "remote ssh OpenSSH config value contains unsupported environment expansion",
        ));
    }
    Ok(())
}

fn path_value(path: &Path) -> Result<&str, SshError> {
    path.to_str().ok_or_else(|| {
        SshError::new(
            FailureClass::Configuration,
            "remote ssh OpenSSH config path is not valid UTF-8",
        )
    })
}

fn validate_identity_agent_value(value: &str) -> Result<(), SshError> {
    if value == "SSH_AUTH_SOCK"
        || value.starts_with('$')
        || value.starts_with('~')
        || !Path::new(value).is_absolute()
    {
        return Err(SshError::new(
            FailureClass::Configuration,
            "remote ssh IdentityAgent value cannot be represented safely",
        ));
    }
    Ok(())
}

fn ssh_child_environment(env_snapshot: &[(OsString, OsString)]) -> BTreeMap<OsString, OsString> {
    let mut environment = BTreeMap::new();
    for (name, value) in env_snapshot {
        if name.as_os_str() == "SSH_ASKPASS"
            || name.as_os_str() == "DISPLAY"
            || name.as_os_str() == "SSH_AUTH_SOCK"
        {
            continue;
        }
        environment.insert(name.clone(), value.clone());
    }
    environment.insert(
        OsString::from("SSH_ASKPASS_REQUIRE"),
        OsString::from("never"),
    );
    environment
}

#[derive(Debug)]
struct ArtifactDir {
    path: PathBuf,
}

impl ArtifactDir {
    fn create(home: &Path) -> Result<Self, SshError> {
        let base = open_artifact_base(home)?;
        for _ in 0..64 {
            let name = format!("ssh.{}", nonce_hex()?);
            match rustix::fs::mkdirat(&base.dir, name.as_str(), private_dir_mode()) {
                Ok(()) => {
                    let dir = open_child_dir(&base.dir, name.as_str())?;
                    rustix::fs::fchmod(&dir, private_dir_mode()).map_err(path_error)?;
                    validate_private_dir_descriptor(&dir)?;
                    let path = base.path.join(name);
                    return Ok(Self { path });
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(path_error(error)),
            }
        }
        Err(SshError::new(
            FailureClass::TransferPathSafety,
            "cannot create unique remote ssh artifact directory",
        ))
    }

    fn write_private_file(&self, prefix: &str, bytes: &[u8]) -> Result<PathBuf, SshError> {
        for _ in 0..64 {
            let path = self.path.join(format!("{prefix}.{}", nonce_hex()?));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(bytes).map_err(path_error)?;
                    file.sync_all().map_err(path_error)?;
                    file.set_permissions(fs::Permissions::from_mode(0o600))
                        .map_err(path_error)?;
                    validate_private_file(&file)?;
                    return Ok(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(path_error(error)),
            }
        }
        Err(SshError::new(
            FailureClass::TransferPathSafety,
            "cannot create unique remote ssh artifact file",
        ))
    }

    fn cleanup(mut self) -> Result<(), std::io::Error> {
        let path = std::mem::take(&mut self.path);
        if path.as_os_str().is_empty() {
            return Ok(());
        }
        fs::remove_dir_all(path)
    }
}

struct ArtifactBase {
    path: PathBuf,
    dir: File,
}

fn reclaim_stale_artifacts(home: &Path) -> Result<(), SshError> {
    let base = open_artifact_base(home)?;
    let Ok(entries) = fs::read_dir(&base.path) else {
        return Ok(());
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !stale_artifact_dir_name(name) {
            continue;
        }
        let path = base.path.join(name);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !private_dir_metadata(&metadata) {
            continue;
        }
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if SystemTime::now()
            .duration_since(modified)
            .map_or(true, |age| age < STALE_ARTIFACT_AGE)
        {
            continue;
        }
        if open_child_dir(&base.dir, name)
            .and_then(|dir| validate_private_dir_descriptor(&dir))
            .is_err()
        {
            continue;
        }
        if artifact_dir_contains_only_private_files(&path) {
            let _ = fs::remove_dir_all(path);
        }
    }
    Ok(())
}

fn stale_artifact_dir_name(name: &str) -> bool {
    name.strip_prefix("ssh.").is_some_and(|suffix| {
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn artifact_dir_contains_only_private_files(path: &Path) -> bool {
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if !artifact_file_name(name) {
            return false;
        }
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            return false;
        };
        if !private_file_metadata(&metadata) {
            return false;
        }
    }
    true
}

fn artifact_file_name(name: &str) -> bool {
    let Some((prefix, nonce)) = name.rsplit_once('.') else {
        return false;
    };
    (prefix == "config"
        || prefix
            .strip_prefix("identity-")
            .and_then(|rest| rest.strip_suffix(".pub"))
            .is_some_and(|index| {
                !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
            }))
        && nonce.len() == 32
        && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

impl Drop for ArtifactDir {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn open_artifact_base(home: &Path) -> Result<ArtifactBase, SshError> {
    let home_dir = open_existing_dir(home)?;
    validate_home_dir(&home_dir)?;
    let broil = open_private_child_dir(&home_dir, ".broil")?;
    let tmp = open_private_child_dir(&broil, "tmp")?;
    let remote = open_private_child_dir(&tmp, "remote")?;
    Ok(ArtifactBase {
        path: home.join(".broil/tmp/remote"),
        dir: remote,
    })
}

fn open_existing_dir(path: &Path) -> Result<File, SshError> {
    if !path.is_absolute() {
        return Err(SshError::new(
            FailureClass::TransferPathSafety,
            "remote ssh artifact home must be absolute",
        ));
    }
    let mut dir = rustix::fs::open(
        Path::new("/"),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(path_error)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                dir = rustix::fs::openat(
                    &dir,
                    part,
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(path_error)?;
            }
            _ => {
                return Err(SshError::new(
                    FailureClass::TransferPathSafety,
                    "remote ssh artifact home path is unsafe",
                ));
            }
        }
    }
    Ok(File::from(dir))
}

fn open_private_child_dir(parent: &File, name: &str) -> Result<File, SshError> {
    match rustix::fs::mkdirat(parent, name, private_dir_mode()) {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(path_error(error)),
    }
    let dir = open_child_dir(parent, name)?;
    validate_private_dir_descriptor(&dir)?;
    Ok(dir)
}

fn open_child_dir(parent: &File, name: &str) -> Result<File, SshError> {
    let descriptor = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(path_error)?;
    Ok(File::from(descriptor))
}

fn validate_home_dir(dir: &File) -> Result<(), SshError> {
    let metadata = dir.metadata().map_err(path_error)?;
    if !metadata.is_dir() || metadata.uid() != effective_uid() {
        return Err(SshError::new(
            FailureClass::TransferPathSafety,
            "remote ssh artifact home must be owned by the current user",
        ));
    }
    Ok(())
}

fn validate_private_dir_descriptor(dir: &File) -> Result<(), SshError> {
    let metadata = dir.metadata().map_err(path_error)?;
    if !private_dir_metadata(&metadata) {
        return Err(SshError::new(
            FailureClass::TransferPathSafety,
            "remote ssh artifact directory must be owned by the current user with mode 0700",
        ));
    }
    Ok(())
}

fn private_dir_metadata(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == effective_uid()
        && metadata.mode() & 0o077 == 0
}

fn private_dir_mode() -> rustix::fs::Mode {
    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR
}

fn validate_private_file(file: &File) -> Result<(), SshError> {
    let metadata = file.metadata().map_err(path_error)?;
    if !private_file_metadata(&metadata) {
        return Err(SshError::new(
            FailureClass::TransferPathSafety,
            "remote ssh artifact file must be owned by the current user with mode 0600",
        ));
    }
    Ok(())
}

fn private_file_metadata(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == effective_uid()
        && metadata.mode() & 0o077 == 0
}

fn nonce_hex() -> Result<String, SshError> {
    let mut raw = [0u8; 16];
    random_bytes(&mut raw).map_err(|_| {
        SshError::new(
            FailureClass::CapabilityUnsupported,
            "remote ssh artifact nonce generation failed",
        )
    })?;
    Ok(raw.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn path_error(error: impl fmt::Display) -> SshError {
    SshError::new(
        FailureClass::TransferPathSafety,
        format!("remote ssh artifact path operation failed: {error}"),
    )
}

