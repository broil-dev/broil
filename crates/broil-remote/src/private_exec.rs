// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use russh::client::private::{
    PrivateInput, PrivateInputUse, PrivateMessage, PrivateRead, PrivateWrite,
};
use zeroize::Zeroize;

#[path = "k3s_upload.rs"]
mod k3s_upload;
#[path = "public_upload.rs"]
mod public_upload;
pub use k3s_upload::{K3S_INCOMING, K3sUploadBinding};
pub use public_upload::{UploadBinding, UploadOutcome};

#[path = "private_staging.rs"]
mod private_staging;
pub use private_staging::{ActionClock, CredentialClock, StagedConnection, StagingPlan};

const OUTPUT_LIMIT: usize = 65_536;
const K3S_BODY_LIMIT: usize = 262_144;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Preparation {
    Generic,
    K3s,
}

#[derive(Clone, Copy)]
enum Capture {
    Ordinary,
    K3sState,
}

impl Capture {
    fn stdout_limit(self) -> usize {
        match self {
            Self::Ordinary => OUTPUT_LIMIT,
            Self::K3sState => 1_048_576,
        }
    }
}

pub struct Output {
    data: Zeroizing<Vec<u8>>,
    len: usize,
    received: usize,
}

impl Output {
    fn new() -> Result<Self, FailureClass> {
        Self::bounded(OUTPUT_LIMIT)
    }
    fn bounded(limit: usize) -> Result<Self, FailureClass> {
        let mut data = Zeroizing::new(Vec::new());
        data.try_reserve_exact(limit)
            .map_err(|_| FailureClass::CapabilityUnsupported)?;
        data.resize(limit, 0);
        Ok(Self {
            data,
            len: 0,
            received: 0,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), FailureClass> {
        self.received = self
            .received
            .checked_add(bytes.len())
            .filter(|n| *n <= self.data.len())
            .ok_or(FailureClass::Protocol)?;
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|n| *n <= self.data.len())
            .ok_or(FailureClass::Protocol)?;
        self.data[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    fn remove(&mut self, start: usize, end: usize) {
        self.data.copy_within(end..self.len, start);
        let next = self.len - (end - start);
        self.data[next..self.len].zeroize();
        self.len = next;
    }
}

#[derive(Debug, Default)]
pub struct Observation {
    pub failure: Option<FailureClass>,
    pub dispatched: bool,
    pub remote_status: Option<i32>,
    pub remote_signal: Option<RemoteSignal>,
    pub possible_staging_residue: bool,
    pub unresolved_input: bool,
}

pub struct Outcome {
    pub observation: Observation,
    pub stdout: Output,
    pub stderr: Output,
    cleanup_deadline: Option<tokio::time::Instant>,
}

pub struct Plan {
    target: ExecTarget,
    command: RemoteScriptCommand,
    privilege: Option<String>,
    timeout: Duration,
    preparation: Preparation,
}

pub fn prepare(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &str,
    script: &str,
    privilege: Option<&str>,
) -> Result<Plan, FailureClass> {
    prepare_profile(
        root,
        inventory,
        machine,
        script,
        privilege,
        Preparation::Generic,
    )
}

pub fn prepare_k3s(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &str,
    script: &str,
    privilege: Option<&str>,
) -> Result<Plan, FailureClass> {
    prepare_profile(
        root,
        inventory,
        machine,
        script,
        privilege,
        Preparation::K3s,
    )
}

fn prepare_profile(
    root: &Path,
    inventory: &EffectiveInventory,
    machine: &str,
    script: &str,
    privilege: Option<&str>,
    preparation: Preparation,
) -> Result<Plan, FailureClass> {
    let target = inventory
        .machines
        .iter()
        .find(|m| m.name == machine)
        .ok_or(FailureClass::Configuration)?;
    let script = inventory
        .scripts
        .get(script)
        .ok_or(FailureClass::Configuration)?;
    if script.pty == ScriptPtyMode::Always
        || script
            .privilege
            .as_deref()
            .is_some_and(|p| Some(p) != privilege)
        || (target.canonical_user != "root" && privilege.is_none())
    {
        return Err(FailureClass::Configuration);
    }
    let target = plan_targets(root, inventory, &[target])
        .map_err(|e| e.class)?
        .remove(0);
    let command = prepare_script_command(
        &RemoteScriptContext::from_inventory(inventory),
        &target,
        script,
        &[],
    )
    .map_err(|e| e.class)?;
    let body_limit = match preparation {
        Preparation::Generic => OUTPUT_LIMIT,
        Preparation::K3s => K3S_BODY_LIMIT,
    };
    if command.body.len() > body_limit {
        return Err(FailureClass::Configuration);
    }
    let seconds = script
        .timeout
        .as_ref()
        .map_or(target.timeouts.command.seconds, |d| d.seconds);
    Ok(Plan {
        target,
        command,
        privilege: privilege.map(str::to_string),
        timeout: Duration::from_secs(seconds),
        preparation,
    })
}

pub(super) struct VerifiedKeys {
    pub(super) target: HostKey,
    pub(super) jump: Option<HostKey>,
}

pub struct Connection {
    backend: RusshExecBackend,
    session: client::Handle<StrictHandler>,
    plan: Plan,
    pub verified_host: HostKey,
    pub verified_jump: Option<HostKey>,
    cancel: CancellationToken,
    cleanup_deadline: Option<tokio::time::Instant>,
    unresolved_input: bool,
}

impl Plan {
    pub fn script(&self) -> &RemoteScriptCommand {
        &self.command
    }
    pub fn with_k3s_body(mut self, body: &[u8]) -> Result<Plan, FailureClass> {
        if self.preparation != Preparation::K3s || body.len() > K3S_BODY_LIMIT {
            return Err(FailureClass::Configuration);
        }
        self.command.body = body.to_vec();
        Ok(self)
    }
    pub async fn connect(
        self,
        backend: RusshExecBackend,
        cancel: CancellationToken,
    ) -> Result<Connection, FailureClass> {
        let options = TargetExecOptions {
            command: Arc::new(ExecCommand::Script(self.command.clone())),
            stdin: StaticStdin::empty(),
            forward_stdin: false,
            live_streams: None,
            pty: false,
            local_terminal: LocalTerminal::default(),
            privilege: self.privilege.clone(),
            dispatch_timeout_seconds: Some(self.timeout.as_secs()),
            cancel: cancel.clone(),
        };
        let verified_host = backend
            .pinned_key(&self.target.target_alias, FailureClass::UnknownHostKey)
            .map_err(|e| e.class)?;
        let verified_jump = match &self.target.route {
            ExecRoute::Direct => None,
            ExecRoute::ViaJump(jump) => Some(
                backend
                    .pinned_key(&jump.alias, FailureClass::UnknownHostKey)
                    .map_err(|e| e.class)?,
            ),
        };
        let session = backend
            .connect_bound(
                &self.target,
                &options,
                Some(&VerifiedKeys {
                    target: verified_host.clone(),
                    jump: verified_jump.clone(),
                }),
            )
            .await
            .map_err(|e| e.class)?;
        Ok(Connection {
            backend,
            session,
            plan: self,
            verified_host,
            verified_jump,
            cancel,
            cleanup_deadline: None,
            unresolved_input: false,
        })
    }
}

pub type ReadySignal = tokio::sync::watch::Sender<Option<Zeroizing<Vec<u8>>>>;

struct Frames<'a> {
    sudo: Option<&'a str>,
    cwd: Option<&'a CwdFrameExpectation>,
    anchor: usize,
    cwd_failed: bool,
    ready: Option<&'a ReadySignal>,
}

fn ready_frame(bytes: &[u8]) -> Option<&[u8]> {
    fn field(rest: &mut &[u8]) -> Option<()> {
        let size = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let end = size.checked_add(4)?;
        rest.get(4..end)?;
        *rest = rest.get(end..)?;
        Some(())
    }
    let mut rest = bytes.strip_prefix(b"BK3SBOOT1\n")?;
    field(&mut rest)?;
    let start = bytes.len() - rest.len();
    field(&mut rest)?;
    let end = bytes.len() - rest.len();
    Some(&bytes[start + 4..end])
}

impl Frames<'_> {
    fn inspect(&mut self, stderr: &mut Output) -> Result<(), FailureClass> {
        if let Some(nonce) = self.sudo {
            match crate::sudo::parse_sudo_control_frame(stderr.bytes(), nonce)
                .map_err(|_| FailureClass::Sudo)?
            {
                crate::sudo::SudoControlFrameParse::Pending => return Ok(()),
                crate::sudo::SudoControlFrameParse::Complete(frame) => {
                    let start = frame.preceding.len();
                    let end = stderr.len - frame.payload.len();
                    stderr.remove(start, end);
                    self.anchor = start;
                    self.sudo = None;
                }
            }
        }
        if let Some(frame) = self.cwd {
            match cwd_control_frame_parse(&stderr.bytes()[self.anchor..], &frame.nonce) {
                CwdControlFrameParse::Pending => {}
                CwdControlFrameParse::Complete(length) => {
                    stderr.remove(self.anchor, self.anchor + length);
                    self.cwd_failed = true;
                    self.cwd = None;
                }
                CwdControlFrameParse::Diverged => self.cwd = None,
            }
        }
        Ok(())
    }
}

struct Payload {
    prefix: Zeroizing<Vec<u8>>,
    scalar: StaticStdin,
}

async fn send(
    write: &PrivateWrite,
    input: Zeroizing<Vec<u8>>,
    uses: &mut Vec<PrivateInputUse>,
) -> Result<(), FailureClass> {
    let input = PrivateInput::new(input).map_err(|_| FailureClass::Protocol)?;
    uses.push(input.use_state());
    write
        .data(input)
        .await
        .map_err(|_| FailureClass::IndeterminateAfterDispatch)
}

async fn receive(
    read: &mut PrivateRead,
    frames: &mut Frames<'_>,
    output: &mut Outcome,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<bool, FailureClass> {
    let message = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(FailureClass::Cancellation),
        result = tokio::time::timeout_at(deadline, read.wait()) => result
            .map_err(|_| FailureClass::IndeterminateAfterDispatch)?.map_err(|_| FailureClass::Protocol)?,
    };
    match message {
        Some(PrivateMessage::Data(data)) => {
            output.stdout.append(data.as_ref())?;
            if let Some(signal) = frames.ready {
                if signal.borrow().is_none() {
                    if let Some(frame) = ready_frame(output.stdout.bytes()) {
                        let _ = signal.send(Some(Zeroizing::new(frame.to_vec())));
                    }
                }
            }
        }
        Some(PrivateMessage::Stderr(data)) => output.stderr.append(data.as_ref())?,
        Some(PrivateMessage::ExitStatus(status)) => {
            if output.observation.remote_status.is_some()
                || output.observation.remote_signal.is_some()
            {
                return Err(FailureClass::Protocol);
            }
            output.observation.remote_status =
                Some(i32::try_from(status).map_err(|_| FailureClass::Protocol)?);
        }
        Some(PrivateMessage::ExitSignal(signal)) => {
            if output.observation.remote_status.is_some()
                || output.observation.remote_signal.is_some()
            {
                return Err(FailureClass::Protocol);
            }
            output.observation.remote_signal = Some(remote_signal(signal));
        }
        Some(PrivateMessage::Failure) => return Err(FailureClass::Protocol),
        Some(PrivateMessage::Close) => {
            frames.inspect(&mut output.stderr)?;
            return Ok(true);
        }
        None => return Err(FailureClass::IndeterminateAfterDispatch),
        _ => {}
    }
    frames.inspect(&mut output.stderr)?;
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
async fn collect(
    read: &mut PrivateRead,
    write: &PrivateWrite,
    payload: Payload,
    mut frames: Frames<'_>,
    output: &mut Outcome,
    uses: &mut Vec<PrivateInputUse>,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<(), FailureClass> {
    while frames.sudo.is_some() {
        if receive(read, &mut frames, output, deadline, cancel).await? {
            return Err(
                if output.observation.remote_status.is_some()
                    || output.observation.remote_signal.is_some()
                {
                    FailureClass::Sudo
                } else {
                    FailureClass::IndeterminateAfterDispatch
                },
            );
        }
    }
    let sending = async {
        let bound = deadline.min(tokio::time::Instant::now() + Duration::from_secs(10));
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(FailureClass::Cancellation),
            result = tokio::time::timeout_at(bound, async {
                send(write, payload.prefix, uses).await?;
                if let Some(scalar) = payload.scalar.next_input().map_err(|e| e.class)? {
                    send(write, scalar, uses).await?;
                }
                write.eof().await.map_err(|_| FailureClass::IndeterminateAfterDispatch)
            }) => result.map_err(|_| FailureClass::IndeterminateAfterDispatch)?,
        }
    };
    let reading = async {
        while !receive(read, &mut frames, output, deadline, cancel).await? {}
        if output.observation.remote_status.is_none() && output.observation.remote_signal.is_none()
        {
            return Err(FailureClass::IndeterminateAfterDispatch);
        }
        if frames.cwd_failed
            && output.observation.remote_status == Some(125)
            && output.observation.remote_signal.is_none()
        {
            return Err(FailureClass::Configuration);
        }
        Ok(())
    };
    tokio::try_join!(sending, reading)?;
    Ok(())
}

async fn command(
    session: &mut client::Handle<StrictHandler>,
    command: &str,
    password: Option<Zeroizing<Vec<u8>>>,
    frames: Frames<'_>,
    payload: Payload,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<Outcome, FailureClass> {
    command_with_capture(
        session,
        command,
        password,
        frames,
        payload,
        deadline,
        cancel,
        Capture::Ordinary,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn command_with_capture(
    session: &mut client::Handle<StrictHandler>,
    command: &str,
    password: Option<Zeroizing<Vec<u8>>>,
    frames: Frames<'_>,
    payload: Payload,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
    capture: Capture,
    clock: Option<&ActionClock>,
) -> Result<Outcome, FailureClass> {
    let mut outcome = Outcome {
        observation: Observation::default(),
        stdout: Output::bounded(capture.stdout_limit())?,
        stderr: Output::new()?,
        cleanup_deadline: None,
    };
    let stopped = async {
        match clock {
            Some(clock) => clock.stopped().await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(stopped);
    let channel = tokio::select! {
        biased;
        _ = &mut stopped => return Err(FailureClass::IndeterminateAfterDispatch),
        _ = cancel.cancelled() => return Err(FailureClass::Cancellation),
        result = tokio::time::timeout_at(deadline, async {
            match capture {
                Capture::Ordinary => session.channel_open_private_session().await,
                Capture::K3sState => session.channel_open_private_state_session().await,
            }
        }) => result.map_err(|_| FailureClass::Protocol)?.map_err(|_| FailureClass::Protocol)?,
    };
    let (mut read, write) = channel.split();
    let mut uses = Vec::with_capacity(3);
    let action = async {
        if cancel.is_cancelled() {
            return Err(FailureClass::Cancellation);
        }
        outcome.observation.dispatched = true;
        tokio::time::timeout_at(deadline, write.exec(command.as_bytes().to_vec()))
            .await
            .map_err(|_| FailureClass::IndeterminateAfterDispatch)?
            .map_err(|_| FailureClass::IndeterminateAfterDispatch)?;
        if let Some(password) = password {
            tokio::time::timeout_at(deadline, send(&write, password, &mut uses))
                .await
                .map_err(|_| FailureClass::IndeterminateAfterDispatch)??;
        }
        collect(
            &mut read,
            &write,
            payload,
            frames,
            &mut outcome,
            &mut uses,
            deadline,
            cancel,
        )
        .await
    };
    let result = tokio::select! {
        biased;
        _ = &mut stopped => Err(FailureClass::IndeterminateAfterDispatch),
        result = action => result,
    };
    if let Err(failure) = result {
        outcome.observation.failure = Some(failure);
        let until = clock.map_or_else(
            || tokio::time::Instant::now() + CANCEL_CLEANUP_TIMEOUT,
            |clock| clock.terminal(None),
        );
        outcome.cleanup_deadline = Some(until);
        let _ = tokio::time::timeout_at(until, async {
            let _ = write.signal(russh::Sig::TERM).await;
            let _ = write.close().await;
        })
        .await;
    }
    outcome.observation.unresolved_input = uses.iter().any(|state| !state.released());
    if outcome.observation.unresolved_input {
        outcome
            .observation
            .failure
            .get_or_insert(FailureClass::IndeterminateAfterDispatch);
    }
    Ok(outcome)
}

fn empty_frames() -> Frames<'static> {
    Frames {
        sudo: None,
        cwd: None,
        anchor: 0,
        cwd_failed: false,
        ready: None,
    }
}

fn payload(prefix: Zeroizing<Vec<u8>>) -> Payload {
    Payload {
        prefix,
        scalar: StaticStdin::empty(),
    }
}

fn helper_ok(outcome: &Outcome) -> Result<(), FailureClass> {
    if let Some(failure) = outcome.observation.failure {
        return Err(failure);
    }
    if outcome.observation.remote_status != Some(0) || outcome.observation.remote_signal.is_some() {
        return Err(FailureClass::Protocol);
    }
    Ok(())
}

impl Connection {
    pub fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub async fn run(
        mut self,
        header: Vec<u8>,
        scalar: StaticStdin,
    ) -> Result<Outcome, FailureClass> {
        if self.plan.preparation != Preparation::Generic {
            return Err(FailureClass::Configuration);
        }
        if header.len() > OUTPUT_LIMIT || self.cancel.is_cancelled() {
            return Err(if self.cancel.is_cancelled() {
                FailureClass::Cancellation
            } else {
                FailureClass::Configuration
            });
        }
        if matches!(&*scalar.inner, StaticStdinInner::Plain(bytes) if !bytes.is_empty()) {
            return Err(FailureClass::Configuration);
        }
        let deadline = tokio::time::Instant::now() + self.plan.timeout;
        let mut prefix = Zeroizing::new(Vec::with_capacity(header.len() + 4));
        prefix.extend_from_slice(&(header.len() as u32).to_be_bytes());
        prefix.extend_from_slice(&header);
        let mut staged = None;
        let mut staging_attempted = false;
        let executed = self
            .run_inner(
                payload_with_scalar(prefix, scalar),
                deadline,
                &mut staged,
                &mut staging_attempted,
            )
            .await;
        let mut result = match executed {
            Ok(outcome) => Ok(outcome),
            Err(failure) => Ok(Outcome {
                observation: Observation {
                    failure: Some(failure),
                    unresolved_input: self.unresolved_input,
                    possible_staging_residue: staging_attempted,
                    ..Observation::default()
                },
                stdout: Output::new()?,
                stderr: Output::new()?,
                cleanup_deadline: self.cleanup_deadline,
            }),
        };
        let cleanup_deadline = result
            .as_ref()
            .ok()
            .and_then(|r| r.cleanup_deadline)
            .or(self.cleanup_deadline)
            .unwrap_or_else(|| tokio::time::Instant::now() + CANCEL_CLEANUP_TIMEOUT);
        if let Some(staged) = staged {
            let cleanup = crate::staging::cleanup_command(&staged.launcher).map_err(|e| e.class);
            let removed = if let Ok(cleanup) = cleanup {
                match tokio::time::timeout_at(
                    cleanup_deadline,
                    command(
                        &mut self.session,
                        &cleanup,
                        None,
                        empty_frames(),
                        payload(Zeroizing::new(Vec::new())),
                        cleanup_deadline,
                        &CancellationToken::default(),
                    ),
                )
                .await
                {
                    Ok(Ok(outcome)) => helper_ok(&outcome).is_ok(),
                    _ => false,
                }
            } else {
                false
            };
            if let Ok(outcome) = &mut result {
                outcome.observation.possible_staging_residue = !removed;
            }
        } else if let Ok(outcome) = &mut result {
            outcome.observation.possible_staging_residue = staging_attempted;
        }
        let _ = tokio::time::timeout_at(
            cleanup_deadline,
            self.session
                .disconnect(russh::Disconnect::ByApplication, "", ""),
        )
        .await;
        if tokio::time::timeout_at(cleanup_deadline, &mut self.session)
            .await
            .is_err()
        {
            if let Ok(outcome) = &mut result {
                outcome.observation.unresolved_input = true;
                outcome
                    .observation
                    .failure
                    .get_or_insert(FailureClass::IndeterminateAfterDispatch);
            }
        }
        if let Ok(outcome) = &mut result {
            if outcome.observation.possible_staging_residue {
                outcome
                    .observation
                    .failure
                    .get_or_insert(FailureClass::IndeterminateAfterDispatch);
            }
        }
        result
    }

    async fn run_inner(
        &mut self,
        payload: Payload,
        deadline: tokio::time::Instant,
        staged_result: &mut Option<crate::staging::StagedLauncher>,
        staging_attempted: &mut bool,
    ) -> Result<Outcome, FailureClass> {
        let mut sudo = None;
        if self.plan.target.canonical_user != "root" {
            let profile = self
                .backend
                .privilege_context
                .profile(
                    self.plan
                        .privilege
                        .as_deref()
                        .ok_or(FailureClass::Configuration)?,
                )
                .map_err(|e| e.class)?
                .clone();
            let preflight = crate::staging::shell_join(&crate::sudo::sudo_preflight_argv());
            let result = command(
                &mut self.session,
                &preflight,
                None,
                empty_frames(),
                self::payload(Zeroizing::new(Vec::new())),
                deadline,
                &self.cancel,
            )
            .await?;
            self.cleanup_deadline = self.cleanup_deadline.or(result.cleanup_deadline);
            self.unresolved_input |= result.observation.unresolved_input;
            if let Some(failure) = result.observation.failure {
                return Err(failure);
            }
            sudo = Some(match result.observation.remote_status {
                Some(0) => PendingSudo::passwordless().map_err(|e| e.class)?,
                Some(126 | 127) => return Err(FailureClass::Sudo),
                Some(_) if profile.password.is_some() => {
                    PendingSudo::password(profile).map_err(|e| e.class)?
                }
                _ => return Err(FailureClass::Sudo),
            });
        }
        let configured = script_command_with_distinct_cwd_nonce(
            &self.plan.command,
            sudo.as_ref().map(|s| s.nonce.as_str()),
        )
        .map_err(|e| e.class)?;
        let executable = crate::staging::body_has_shebang(&configured.body);
        let launcher = crate::staging::launcher_for_script(
            executable,
            configured.interpreter.as_deref(),
            configured.cwd.as_deref(),
            &configured.cwd_nonce,
            &configured.env,
            &configured.args,
        );
        let staged_input = crate::staging::staging_input(
            &launcher,
            Some(&configured.body),
            sudo.as_ref().map(|s| s.control_frame_contents.as_slice()),
        );
        *staging_attempted = true;
        let result = command(
            &mut self.session,
            &crate::staging::receiver_command(),
            None,
            empty_frames(),
            self::payload(staged_input),
            deadline,
            &self.cancel,
        )
        .await?;
        self.cleanup_deadline = self.cleanup_deadline.or(result.cleanup_deadline);
        self.unresolved_input |= result.observation.unresolved_input;
        helper_ok(&result)?;
        let raw = result.stdout.bytes();
        let path = std::str::from_utf8(raw).map_err(|_| FailureClass::Protocol)?;
        let path = path.strip_suffix('\n').ok_or(FailureClass::Protocol)?;
        if path.len() > 4096 || path.contains(['\n', '\r']) || !path.starts_with('/') {
            return Err(FailureClass::Protocol);
        }
        let staged = crate::staging::parse_receiver_stdout(path.as_bytes(), true, sudo.is_some())
            .map_err(|e| e.class)?;
        *staged_result = Some(staged.clone());
        let mut chmod = vec![
            crate::staging::make_launcher_executable_command(&staged.launcher)
                .map_err(|e| e.class)?,
        ];
        if executable {
            chmod.push(
                crate::staging::make_script_body_executable_command(
                    staged.body.as_deref().ok_or(FailureClass::Protocol)?,
                )
                .map_err(|e| e.class)?,
            );
        }
        for action in chmod {
            let result = command(
                &mut self.session,
                &action,
                None,
                empty_frames(),
                self::payload(Zeroizing::new(Vec::new())),
                deadline,
                &self.cancel,
            )
            .await?;
            self.cleanup_deadline = self.cleanup_deadline.or(result.cleanup_deadline);
            self.unresolved_input |= result.observation.unresolved_input;
            helper_ok(&result)?;
        }
        let argv = vec![staged.launcher];
        let dispatch = match sudo.as_mut() {
            Some(sudo) => sudo
                .finalize(&self.backend.privilege_context, &argv, &self.cancel)
                .await
                .map_err(|e| e.class)?,
            None => DispatchCommand {
                command: crate::staging::shell_join(&argv),
                password_stdin: None,
                sudo_nonce: None,
            },
        };
        let cwd_frame = configured.cwd_display.map(|cwd| CwdFrameExpectation {
            cwd,
            nonce: configured.cwd_nonce,
        });
        command(
            &mut self.session,
            &dispatch.command,
            dispatch.password_stdin,
            Frames {
                sudo: dispatch.sudo_nonce.as_deref(),
                cwd: cwd_frame.as_ref(),
                anchor: 0,
                cwd_failed: false,
                ready: None,
            },
            payload,
            deadline,
            &self.cancel,
        )
        .await
    }
}

fn payload_with_scalar(prefix: Zeroizing<Vec<u8>>, scalar: StaticStdin) -> Payload {
    Payload { prefix, scalar }
}
