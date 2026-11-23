// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::sync::Mutex;

const HELPER: &str = include_str!("private_staging.py");
const INPUT_LIMIT: usize = 1_048_576;

#[derive(Clone)]
pub struct ActionClock(Arc<Mutex<ClockState>>);

struct ClockState {
    deadline: tokio::time::Instant,
    cleanup: Arc<Mutex<Option<tokio::time::Instant>>>,
    parent: Option<ActionClock>,
    stopped: CancellationToken,
    closed: bool,
}

pub struct CredentialClock {
    clock: ActionClock,
    completed: bool,
}

impl CredentialClock {
    pub fn deadline(&self) -> tokio::time::Instant {
        self.clock.deadline()
    }

    pub fn check(&self, cancellation: &CancellationToken) -> Result<(), FailureClass> {
        self.clock.check(cancellation)
    }

    pub fn complete(&mut self) -> Result<(), FailureClass> {
        self.clock.check(&CancellationToken::default())?;
        self.clock.0.lock().expect("action clock").closed = true;
        self.completed = true;
        Ok(())
    }

    pub fn abort(&self) -> tokio::time::Instant {
        self.clock.terminal(None)
    }

    pub fn stop_signal(&self) -> CancellationToken {
        self.clock.0.lock().expect("action clock").stopped.clone()
    }

    pub async fn stopped(&self) {
        self.clock.stopped().await;
    }
}

impl Drop for CredentialClock {
    fn drop(&mut self) {
        if !self.completed {
            self.clock.terminal(None);
        }
    }
}

impl ActionClock {
    pub fn new(deadline: tokio::time::Instant) -> Self {
        Self(Arc::new(Mutex::new(ClockState {
            deadline,
            cleanup: Arc::new(Mutex::new(None)),
            parent: None,
            stopped: CancellationToken::default(),
            closed: false,
        })))
    }

    pub fn deadline(&self) -> tokio::time::Instant {
        let state = self.0.lock().expect("action clock");
        state.parent.as_ref().map_or(state.deadline, |parent| {
            state.deadline.min(parent.deadline())
        })
    }

    pub fn abort(&self) {
        self.terminal(None);
    }

    pub fn terminal_deadline(&self) -> tokio::time::Instant {
        self.terminal(None)
    }

    pub fn local_release_deadline(&self, cancellation: &CancellationToken) -> tokio::time::Instant {
        if self.check(cancellation).is_err() {
            self.terminal(None)
        } else {
            self.deadline()
                .min(tokio::time::Instant::now() + CANCEL_CLEANUP_TIMEOUT)
        }
    }

    pub fn for_state_rpc(&self, step_deadline: tokio::time::Instant) -> Self {
        let state = self.0.lock().expect("action clock");
        Self(Arc::new(Mutex::new(ClockState {
            deadline: step_deadline.min(tokio::time::Instant::now() + Duration::from_secs(30)),
            cleanup: state.cleanup.clone(),
            parent: Some(self.clone()),
            stopped: state.stopped.clone(),
            closed: false,
        })))
    }

    pub fn for_credential_action(&self, deadline: tokio::time::Instant) -> CredentialClock {
        let state = self.0.lock().expect("action clock");
        CredentialClock {
            clock: Self(Arc::new(Mutex::new(ClockState {
                deadline,
                cleanup: state.cleanup.clone(),
                parent: Some(self.clone()),
                stopped: state.stopped.clone(),
                closed: false,
            }))),
            completed: false,
        }
    }

    fn cap(&self, timeout: Duration) {
        let mut state = self.0.lock().expect("action clock");
        state.deadline = state.deadline.min(tokio::time::Instant::now() + timeout);
    }

    pub(super) fn terminal(&self, observed: Option<tokio::time::Instant>) -> tokio::time::Instant {
        let state = self.0.lock().expect("action clock");
        let mut cleanup = state.cleanup.lock().expect("action cleanup");
        let candidate =
            observed.unwrap_or_else(|| tokio::time::Instant::now() + CANCEL_CLEANUP_TIMEOUT);
        let until = cleanup.map_or(candidate, |old| old.min(candidate));
        *cleanup = Some(until);
        state.stopped.cancel();
        until
    }

    pub(super) async fn stopped(&self) {
        let token = self.0.lock().expect("action clock").stopped.clone();
        token.cancelled().await;
    }

    fn check(&self, cancel: &CancellationToken) -> Result<(), FailureClass> {
        if cancel.is_cancelled() {
            self.terminal(None);
            return Err(FailureClass::Cancellation);
        }
        let expired = tokio::time::Instant::now() >= self.deadline();
        if expired {
            self.terminal(None);
            return Err(FailureClass::IndeterminateAfterDispatch);
        }
        let state = self.0.lock().expect("action clock");
        if state.closed || state.cleanup.lock().expect("action cleanup").is_some() {
            return Err(FailureClass::IndeterminateAfterDispatch);
        }
        Ok(())
    }
}

pub(super) struct Binding {
    pub(super) account: String,
    pub(super) nonce: String,
    pub(super) launcher: String,
}

impl Binding {
    pub(super) fn new(account: &str) -> Result<Self, FailureClass> {
        let bytes = account.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 32
            || !(bytes[0].is_ascii_lowercase() || bytes[0] == b'_')
            || !bytes
                .iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(c))
        {
            return Err(FailureClass::Configuration);
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| FailureClass::CapabilityUnsupported)?;
        let nonce = data_encoding::HEXLOWER.encode(&random);
        let home = if account == "root" {
            "/root".into()
        } else {
            format!("/home/{account}")
        };
        Ok(Self {
            launcher: format!("{home}/.broil/tmp/exec/k3s.{nonce}/launcher"),
            account: account.into(),
            nonce,
        })
    }

    pub(super) fn command(&self, operation: &str, extra: Option<String>) -> String {
        crate::staging::shell_join(&self.argv(operation, extra))
    }

    fn argv(&self, operation: &str, extra: Option<String>) -> Vec<String> {
        let mut args = vec![
            "/usr/bin/python3".into(),
            "-I".into(),
            "-c".into(),
            HELPER.into(),
            operation.into(),
        ];
        if operation != "receive" {
            args.extend([self.account.clone(), self.nonce.clone()]);
        }
        args.extend(extra);
        args
    }

    pub(super) fn input(
        &self,
        launcher: &[u8],
        body: &[u8],
        sidecar: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, FailureClass> {
        let header = format!(
            "BROIL-EXEC-STAGING-K3S-2\n{}\n{}\n{}\n1\n{}\n{}\nEND\n",
            self.account,
            self.nonce,
            launcher.len(),
            body.len(),
            sidecar.map_or(0, <[u8]>::len)
        );
        let total = header
            .len()
            .checked_add(launcher.len())
            .and_then(|n| n.checked_add(body.len()))
            .and_then(|n| n.checked_add(sidecar.map_or(0, <[u8]>::len)))
            .filter(|n| *n <= INPUT_LIMIT)
            .ok_or(FailureClass::Configuration)?;
        if header.len() > 256 || launcher.len() > OUTPUT_LIMIT || body.len() > K3S_BODY_LIMIT {
            return Err(FailureClass::Configuration);
        }
        let mut input = Zeroizing::new(Vec::new());
        input
            .try_reserve_exact(total)
            .map_err(|_| FailureClass::CapabilityUnsupported)?;
        input.extend_from_slice(header.as_bytes());
        input.extend_from_slice(launcher);
        input.extend_from_slice(body);
        if let Some(sidecar) = sidecar {
            input.extend_from_slice(sidecar);
        }
        Ok(input)
    }
}

pub struct StagingPlan {
    plan: Plan,
    binding: Binding,
    clock: ActionClock,
    owned_credential: bool,
}

impl Plan {
    pub fn k3s_staging(self, clock: ActionClock) -> Result<StagingPlan, FailureClass> {
        if self.preparation != Preparation::K3s {
            return Err(FailureClass::Configuration);
        }
        let binding = Binding::new(&self.target.canonical_user)?;
        clock.cap(self.timeout);
        Ok(StagingPlan {
            plan: self,
            binding,
            clock,
            owned_credential: false,
        })
    }

    pub fn k3s_credential_staging(
        self,
        clock: &CredentialClock,
    ) -> Result<StagingPlan, FailureClass> {
        let mut plan = self.k3s_staging(clock.clock.clone())?;
        plan.owned_credential = true;
        Ok(plan)
    }
}

pub struct StagedConnection {
    connection: Connection,
    binding: Binding,
    clock: ActionClock,
    sudo: Option<PendingSudo>,
    password: Option<Zeroizing<Vec<u8>>>,
    cwd: Option<CwdFrameExpectation>,
    attempted: bool,
    owned_credential: bool,
}

fn failed(failure: FailureClass) -> Observation {
    Observation {
        failure: Some(failure),
        ..Observation::default()
    }
}

fn empty_output(failure: FailureClass) -> Result<Outcome, FailureClass> {
    Ok(Outcome {
        observation: failed(failure),
        stdout: Output::new()?,
        stderr: Output::new()?,
        cleanup_deadline: None,
    })
}

fn quiet(outcome: &Outcome) -> Result<(), FailureClass> {
    helper_ok(outcome)?;
    if !outcome.stdout.bytes().is_empty() || !outcome.stderr.bytes().is_empty() {
        return Err(FailureClass::Protocol);
    }
    Ok(())
}

impl StagingPlan {
    pub async fn connect(
        self,
        backend: RusshExecBackend,
        cancel: CancellationToken,
    ) -> Result<StagedConnection, Observation> {
        self.clock.check(&cancel).map_err(failed)?;
        let connected = tokio::select! {
            biased;
            _ = self.clock.stopped() => Ok(Err(FailureClass::IndeterminateAfterDispatch)),
            result = tokio::time::timeout_at(self.clock.deadline(), self.plan.connect(backend, cancel)) => result,
        };
        let connection = match connected {
            Ok(Ok(connection)) => connection,
            result => {
                self.clock.terminal(None);
                return Err(failed(match result {
                    Ok(Err(failure)) => failure,
                    _ => FailureClass::IndeterminateAfterDispatch,
                }));
            }
        };
        let mut staged = StagedConnection {
            connection,
            binding: self.binding,
            clock: self.clock,
            sudo: None,
            password: None,
            cwd: None,
            attempted: false,
            owned_credential: self.owned_credential,
        };
        if let Err(failure) = staged.admit().await {
            let mut observation = staged.close().await;
            observation.failure = Some(failure);
            return Err(observation);
        }
        Ok(staged)
    }
}

impl StagedConnection {
    pub fn deadline(&self) -> tokio::time::Instant {
        self.clock.deadline()
    }
    pub fn verified_host(&self) -> &HostKey {
        &self.connection.verified_host
    }
    pub fn verified_jump(&self) -> Option<&HostKey> {
        self.connection.verified_jump.as_ref()
    }

    async fn helper(
        &mut self,
        cmd: &str,
        input: Zeroizing<Vec<u8>>,
    ) -> Result<Outcome, FailureClass> {
        self.clock.check(&self.connection.cancel)?;
        let result = command_with_capture(
            &mut self.connection.session,
            cmd,
            None,
            empty_frames(),
            payload(input),
            self.clock.deadline(),
            &self.connection.cancel,
            Capture::Ordinary,
            Some(&self.clock),
        )
        .await?;
        self.connection.cleanup_deadline =
            self.connection.cleanup_deadline.or(result.cleanup_deadline);
        self.connection.unresolved_input |= result.observation.unresolved_input;
        if let Some(until) = result.cleanup_deadline {
            self.clock.terminal(Some(until));
        }
        Ok(result)
    }

    async fn admit(&mut self) -> Result<(), FailureClass> {
        if self.binding.account != "root" {
            let profile = self
                .connection
                .backend
                .privilege_context
                .profile(
                    self.connection
                        .plan
                        .privilege
                        .as_deref()
                        .ok_or(FailureClass::Configuration)?,
                )
                .map_err(|e| e.class)?
                .clone();
            let result = self
                .helper(
                    &crate::staging::shell_join(&crate::sudo::sudo_preflight_argv()),
                    Zeroizing::new(Vec::new()),
                )
                .await?;
            if let Some(failure) = result.observation.failure {
                return Err(failure);
            }
            self.sudo = Some(match result.observation.remote_status {
                Some(0) if result.stdout.bytes().is_empty() && result.stderr.bytes().is_empty() => {
                    PendingSudo::passwordless().map_err(|e| e.class)?
                }
                Some(126 | 127) | None => return Err(FailureClass::Sudo),
                Some(_) if profile.password.is_some() => {
                    PendingSudo::password(profile).map_err(|e| e.class)?
                }
                _ => return Err(FailureClass::Sudo),
            });
        }
        let configured = script_command_with_distinct_cwd_nonce(
            &self.connection.plan.command,
            self.sudo.as_ref().map(|s| s.nonce.as_str()),
        )
        .map_err(|e| e.class)?;
        while self
            .sudo
            .as_ref()
            .is_some_and(|sudo| sudo.nonce == self.binding.nonce)
        {
            self.binding = Binding::new(&self.connection.plan.target.canonical_user)?;
        }
        let executable = crate::staging::body_has_shebang(&configured.body);
        let launcher = crate::staging::launcher_for_script(
            executable,
            configured.interpreter.as_deref(),
            configured.cwd.as_deref(),
            &configured.cwd_nonce,
            &configured.env,
            &configured.args,
        );
        let input = self.binding.input(
            &launcher,
            &configured.body,
            self.sudo
                .as_ref()
                .map(|s| s.control_frame_contents.as_slice()),
        )?;
        self.attempted = true;
        let result = self
            .helper(&self.binding.command("receive", None), input)
            .await?;
        if let Some(sudo) = &mut self.sudo {
            sudo.control_frame_contents = Zeroizing::new(Vec::new());
        }
        helper_ok(&result)?;
        if result.stdout.bytes() != format!("{}\n", self.binding.launcher).as_bytes()
            || !result.stderr.bytes().is_empty()
        {
            return Err(FailureClass::Protocol);
        }
        let result = self
            .helper(
                &self
                    .binding
                    .command("arm", Some(u8::from(executable).to_string())),
                Zeroizing::new(Vec::new()),
            )
            .await?;
        quiet(&result)?;
        if let Some(PendingSudo {
            mode: PendingSudoMode::Password(profile),
            ..
        }) = &self.sudo
        {
            self.password = self
                .connection
                .backend
                .privilege_context
                .sudo_password_input(profile, &self.connection.cancel)
                .await
                .map_err(|e| e.class)?;
        }
        self.clock.check(&self.connection.cancel)?;
        self.cwd = configured.cwd_display.map(|cwd| CwdFrameExpectation {
            cwd,
            nonce: configured.cwd_nonce,
        });
        Ok(())
    }

    pub async fn close(mut self) -> Observation {
        self.password.take();
        let until = self.clock.terminal(self.connection.cleanup_deadline);
        let mut observation = Observation::default();
        self.finish(&mut observation, until).await;
        observation
    }

    pub async fn close_observation(mut self) -> Observation {
        self.password.take();
        let failure = self.clock.check(&self.connection.cancel).err();
        let until = if failure.is_some() {
            self.clock.terminal(self.connection.cleanup_deadline)
        } else {
            self.clock
                .deadline()
                .min(tokio::time::Instant::now() + CANCEL_CLEANUP_TIMEOUT)
        };
        let mut observation = Observation {
            failure,
            ..Observation::default()
        };
        self.finish(&mut observation, until).await;
        if self.connection.cancel.is_cancelled() {
            observation
                .failure
                .get_or_insert(FailureClass::Cancellation);
        }
        if observation.failure.is_some() {
            self.clock.terminal(Some(until));
        }
        observation
    }

    pub async fn run(
        self,
        header: Vec<u8>,
        scalar: StaticStdin,
        terminal: bool,
    ) -> Result<Outcome, FailureClass> {
        self.run_profile(header, scalar, terminal, Capture::Ordinary, 4096, None)
            .await
    }

    pub async fn run_state(self, header: Vec<u8>, terminal: bool) -> Result<Outcome, FailureClass> {
        self.run_profile(
            header,
            StaticStdin::empty(),
            terminal,
            Capture::K3sState,
            65_536,
            None,
        )
        .await
    }

    pub async fn run_bootstrap(
        self,
        header: Vec<u8>,
        terminal: bool,
    ) -> Result<Outcome, FailureClass> {
        self.run_profile(
            header,
            StaticStdin::empty(),
            terminal,
            Capture::Ordinary,
            65_536,
            None,
        )
        .await
    }

    pub async fn run_lifecycle(
        self,
        header: Vec<u8>,
        terminal: bool,
    ) -> Result<Outcome, FailureClass> {
        self.run_profile(
            header,
            StaticStdin::empty(),
            terminal,
            Capture::Ordinary,
            65_536,
            None,
        )
        .await
    }

    pub async fn run_bootstrap_ready(
        self,
        header: Vec<u8>,
        signal: &ReadySignal,
    ) -> Result<Outcome, FailureClass> {
        self.run_profile(
            header,
            StaticStdin::empty(),
            false,
            Capture::Ordinary,
            65_536,
            Some(signal),
        )
        .await
    }

    pub async fn run_credential(
        self,
        header: Vec<u8>,
        scalar: StaticStdin,
    ) -> Result<Outcome, FailureClass> {
        if !self.owned_credential {
            drop(scalar);
            self.close().await;
            return Err(FailureClass::Configuration);
        }
        self.run_profile(header, scalar, false, Capture::Ordinary, 4096, None)
            .await
    }

    pub async fn run_release_secret(
        self,
        header: Vec<u8>,
        scalar: StaticStdin,
        terminal: bool,
    ) -> Result<Outcome, FailureClass> {
        const PROTOCOL: &[u8] = br#","protocol":"broil-k3s-release-secret","#;
        let release_secret = header.starts_with(br#"{"action":"apply-secret","#)
            && header.windows(PROTOCOL.len()).any(|w| w == PROTOCOL);
        let limit = if release_secret { 8192 } else { 0 };
        self.run_profile(header, scalar, terminal, Capture::Ordinary, limit, None)
            .await
    }

    pub async fn run_release(
        self,
        header: Vec<u8>,
        payload: &[u8],
        terminal: bool,
    ) -> Result<Outcome, FailureClass> {
        if payload.len() > 983_032 {
            self.close().await;
            return Err(FailureClass::Configuration);
        }
        let mut trailer = Vec::with_capacity(payload.len() + 4);
        trailer.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        trailer.extend_from_slice(payload);
        self.run_framed(
            header,
            &trailer,
            StaticStdin::empty(),
            terminal,
            Capture::K3sState,
            65_536,
            None,
        )
        .await
    }

    async fn run_profile(
        self,
        header: Vec<u8>,
        scalar: StaticStdin,
        terminal: bool,
        capture: Capture,
        header_limit: usize,
        ready: Option<&ReadySignal>,
    ) -> Result<Outcome, FailureClass> {
        self.run_framed(header, &[], scalar, terminal, capture, header_limit, ready)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_framed(
        mut self,
        header: Vec<u8>,
        trailer: &[u8],
        scalar: StaticStdin,
        terminal: bool,
        capture: Capture,
        header_limit: usize,
        ready: Option<&ReadySignal>,
    ) -> Result<Outcome, FailureClass> {
        let valid = self.clock.check(&self.connection.cancel).and_then(|()| {
            if header.is_empty()
                || header.len() > header_limit
                || matches!(&*scalar.inner, StaticStdinInner::Plain(bytes) if !bytes.is_empty())
            {
                Err(FailureClass::Configuration)
            } else {
                Ok(())
            }
        });
        let mut outcome = if let Err(failure) = valid {
            drop(scalar);
            empty_output(failure)?
        } else {
            let remaining = self
                .clock
                .deadline()
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(7_200_000);
            let mut argv = self.binding.argv("use", Some(remaining.to_string()));
            if let Some(sudo) = &self.sudo {
                let mut prefix: Vec<String> = match sudo.mode {
                    PendingSudoMode::Passwordless => vec!["sudo".into(), "-n".into(), "--".into()],
                    PendingSudoMode::Password(_) => vec![
                        "sudo".into(),
                        "-S".into(),
                        "-p".into(),
                        "".into(),
                        "--".into(),
                    ],
                };
                prefix.append(&mut argv);
                argv = prefix;
            }
            let mut prefix = Zeroizing::new(Vec::with_capacity(header.len() + 4 + trailer.len()));
            prefix.extend_from_slice(&(header.len() as u32).to_be_bytes());
            prefix.extend_from_slice(&header);
            prefix.extend_from_slice(trailer);
            match command_with_capture(
                &mut self.connection.session,
                &crate::staging::shell_join(&argv),
                self.password.take(),
                Frames {
                    sudo: self.sudo.as_ref().map(|s| s.nonce.as_str()),
                    cwd: self.cwd.as_ref(),
                    anchor: 0,
                    cwd_failed: false,
                    ready,
                },
                payload_with_scalar(prefix, scalar),
                self.clock.deadline(),
                &self.connection.cancel,
                capture,
                Some(&self.clock),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(failure) => empty_output(failure)?,
            }
        };
        let until = if terminal || outcome.observation.failure.is_some() {
            self.clock.terminal(
                outcome
                    .cleanup_deadline
                    .or(self.connection.cleanup_deadline),
            )
        } else {
            self.clock
                .deadline()
                .min(tokio::time::Instant::now() + CANCEL_CLEANUP_TIMEOUT)
        };
        self.finish(&mut outcome.observation, until).await;
        if self.connection.cancel.is_cancelled() {
            outcome
                .observation
                .failure
                .get_or_insert(FailureClass::Cancellation);
        }
        if outcome.observation.failure.is_some() {
            self.clock.terminal(Some(until));
        }
        Ok(outcome)
    }

    async fn finish(&mut self, observation: &mut Observation, until: tokio::time::Instant) {
        if self.attempted {
            let result = tokio::time::timeout_at(
                until,
                command(
                    &mut self.connection.session,
                    &self.binding.command("cleanup", None),
                    None,
                    empty_frames(),
                    payload(Zeroizing::new(Vec::new())),
                    until,
                    &CancellationToken::default(),
                ),
            )
            .await;
            observation.possible_staging_residue =
                !matches!(result, Ok(Ok(ref value)) if quiet(value).is_ok());
        }
        let _ = tokio::time::timeout_at(
            until,
            self.connection
                .session
                .disconnect(russh::Disconnect::ByApplication, "", ""),
        )
        .await;
        if tokio::time::timeout_at(until, &mut self.connection.session)
            .await
            .is_err()
        {
            observation.unresolved_input = true;
        }
        observation.unresolved_input |= self.connection.unresolved_input;
        if observation.possible_staging_residue || observation.unresolved_input {
            observation
                .failure
                .get_or_insert(FailureClass::IndeterminateAfterDispatch);
        }
    }
}
