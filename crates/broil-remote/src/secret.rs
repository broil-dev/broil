// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use broil_core::remote::SecretProvider;
pub use broil_core::secret::{OwnedSecret, normalize_path, restore_global_input_terminal};
use broil_core::secret::{SecretNormalizationError, label_writer};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::FailureClass;
use crate::path_safety::{CapabilityError, defensive_open};
use crate::scheduler::CancellationToken;

pub mod store;
pub use store::StoreContext;

const MAX_SECRET_BYTES: usize = 64 * 1024;
const CANCELLABLE_READ_SLEEP: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub struct SecretFailure {
    class: FailureClass,
    diagnostic: String,
}

impl SecretFailure {
    fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn class(&self) -> FailureClass {
        self.class
    }
}

impl fmt::Display for SecretFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for SecretFailure {}

#[derive(Clone)]
pub struct SecretContext {
    root: PathBuf,
    env_snapshot: Vec<(OsString, OsString)>,
    providers: BTreeMap<String, SecretProvider>,
    prompt_terminal: Option<PromptTerminal>,
    paced_clock: Option<PacedClock>,
    store: Option<StoreContext>,
    non_interactive: bool,
}

impl SecretContext {
    pub fn new(
        root: PathBuf,
        env_snapshot: Vec<(OsString, OsString)>,
        providers: BTreeMap<String, SecretProvider>,
    ) -> Self {
        Self {
            root,
            env_snapshot,
            providers,
            prompt_terminal: None,
            paced_clock: None,
            store: None,
            non_interactive: false,
        }
    }

    pub fn with_store_context(mut self, mut store: StoreContext) -> Self {
        store.non_interactive = self.non_interactive;
        if self
            .providers
            .values()
            .any(|p| matches!(p, SecretProvider::Store { .. }))
        {
            self.store = Some(store);
        }
        self
    }

    pub fn with_non_interactive(mut self, non_interactive: bool) -> Self {
        self.non_interactive = non_interactive;
        if let Some(store) = self.store.as_mut() {
            store.non_interactive = non_interactive;
        }
        self
    }

    pub fn with_store_context_for_providers(
        mut self,
        mut store: StoreContext,
        providers: &[&str],
    ) -> Self {
        store.non_interactive = self.non_interactive;
        if providers.iter().any(|name| self.is_store_provider(name)) {
            self.store = Some(store);
        }
        self
    }

    pub(crate) fn is_store_provider(&self, name: &str) -> bool {
        matches!(self.providers.get(name), Some(SecretProvider::Store { .. }))
    }

    pub fn with_paced_clock(mut self, clock: PacedClock) -> Self {
        self.paced_clock = Some(clock);
        self
    }

    pub fn with_prompt_terminal(mut self, terminal: PromptTerminal) -> Self {
        self.prompt_terminal = Some(terminal);
        self
    }

    pub fn cache(&self) -> SecretCache<'_> {
        SecretCache {
            context: self,
            resolved: BTreeMap::new(),
        }
    }

    pub fn env_snapshot(&self) -> &[(OsString, OsString)] {
        &self.env_snapshot
    }

    pub async fn resolve_owned_cancellable(
        &self,
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<OwnedSecret, SecretFailure> {
        if cancel.is_cancelled() {
            return Err(cancelled_provider(name));
        }
        let provider = self.provider(name)?.clone();
        if let SecretProvider::Store { key, set } = provider {
            let context = self
                .store
                .clone()
                .ok_or_else(|| provider_failure(name, "secret unavailable"))?;
            return store::resolve_owned(context, name, key, set, cancel, self.paced_clock.clone())
                .await;
        }
        let _pause = self
            .paced_clock
            .as_ref()
            .filter(|_| self.provider_is_human_paced(name))
            .map(PacedClock::pause);
        let context = self.clone();
        let owned_name = name.to_string();
        let cancel = cancel.clone();
        tokio::task::spawn_blocking(move || {
            resolve_provider_cancellable(&owned_name, &provider, &context, &cancel)
        })
        .await
        .map_err(|_| {
            SecretFailure::new(
                FailureClass::SecretUnavailable,
                "secret provider worker failed",
            )
        })?
    }

    pub fn provider_is_human_paced(&self, name: &str) -> bool {
        if self.non_interactive {
            return false;
        }
        if matches!(self.providers.get(name), Some(SecretProvider::Store { .. })) {
            return self.store.as_ref().is_some_and(StoreContext::may_prompt);
        }
        matches!(
            self.providers.get(name),
            Some(SecretProvider::Prompt { .. }) | Some(SecretProvider::Helper { .. })
        )
    }

    fn provider(&self, name: &str) -> Result<&SecretProvider, SecretFailure> {
        self.providers.get(name).ok_or_else(|| {
            SecretFailure::new(
                FailureClass::SecretUnavailable,
                format!("secret provider {name} is unavailable"),
            )
        })
    }

    fn normalize_config_path(&self, path: &str) -> PathBuf {
        normalize_path(&self.root, Path::new(path))
    }
}

pub type SharedLabelWriter = Arc<Mutex<dyn Write + Send>>;

#[derive(Clone)]
pub struct PromptTerminal {
    input: Arc<OwnedFd>,
    label_writer: SharedLabelWriter,
}

impl PromptTerminal {
    pub fn new(input: OwnedFd, label_writer: SharedLabelWriter) -> Self {
        Self {
            input: Arc::new(input),
            label_writer,
        }
    }
}

#[derive(Clone)]
pub struct PacedClock(Arc<PacedClockInner>);

struct PacedClockInner {
    state: Mutex<PacedClockState>,
    changed: watch::Sender<u64>,
}

struct PacedClockState {
    charged: Duration,
    running_since: Option<tokio::time::Instant>,
    paused: usize,
}

pub struct PacedPause(Arc<PacedClockInner>);

impl Default for PacedClock {
    fn default() -> Self {
        Self::new()
    }
}

impl PacedClock {
    pub fn new() -> Self {
        Self(Arc::new(PacedClockInner {
            state: Mutex::new(PacedClockState {
                charged: Duration::ZERO,
                running_since: Some(tokio::time::Instant::now()),
                paused: 0,
            }),
            changed: watch::Sender::new(0),
        }))
    }

    pub fn charged(&self) -> Duration {
        self.0.snapshot().0
    }

    pub fn pause(&self) -> PacedPause {
        {
            let mut state = self.0.lock();
            if state.paused == 0 {
                if let Some(since) = state.running_since.take() {
                    state.charged = state.charged.saturating_add(since.elapsed());
                }
            }
            state.paused += 1;
        }
        self.0.notify();
        PacedPause(Arc::clone(&self.0))
    }

    pub async fn expired(&self, from: Duration, budget: Duration) {
        let mut changed = self.0.changed.subscribe();
        loop {
            let (charged, running) = self.0.snapshot();
            let elapsed = charged.saturating_sub(from);
            if elapsed >= budget {
                return;
            }
            if running {
                tokio::select! {
                    _ = tokio::time::sleep(budget - elapsed) => {}
                    _ = changed.changed() => {}
                }
            } else if changed.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

impl PacedClockInner {
    fn lock(&self) -> MutexGuard<'_, PacedClockState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn snapshot(&self) -> (Duration, bool) {
        let state = self.lock();
        let running = state
            .running_since
            .map(|since| since.elapsed())
            .unwrap_or(Duration::ZERO);
        (
            state.charged.saturating_add(running),
            state.running_since.is_some(),
        )
    }

    fn notify(&self) {
        self.changed
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

impl Drop for PacedPause {
    fn drop(&mut self) {
        {
            let mut state = self.0.lock();
            state.paused = state.paused.saturating_sub(1);
            if state.paused == 0 {
                state.running_since = Some(tokio::time::Instant::now());
            }
        }
        self.0.notify();
    }
}

pub struct SecretCache<'a> {
    context: &'a SecretContext,
    resolved: BTreeMap<String, OwnedSecret>,
}

impl<'a> SecretCache<'a> {
    pub fn resolve(&mut self, name: &str) -> Result<&OwnedSecret, SecretFailure> {
        self.resolve_cancellable(name, &CancellationToken::default())
    }

    pub fn resolve_cancellable(
        &mut self,
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<&OwnedSecret, SecretFailure> {
        if !self.resolved.contains_key(name) {
            let secret = resolve_provider_cancellable(
                name,
                self.context.provider(name)?,
                self.context,
                cancel,
            )?;
            self.resolved.insert(name.to_string(), secret);
        }
        Ok(self
            .resolved
            .get(name)
            .expect("secret was inserted before lookup"))
    }

    pub fn remove(&mut self, name: &str) {
        self.resolved.remove(name);
    }
}

fn resolve_provider_cancellable(
    name: &str,
    provider: &SecretProvider,
    context: &SecretContext,
    cancel: &CancellationToken,
) -> Result<OwnedSecret, SecretFailure> {
    if cancel.is_cancelled() {
        return Err(cancelled_provider(name));
    }
    let bytes = match provider {
        SecretProvider::Prompt { label } => {
            if context.non_interactive {
                return Err(provider_failure(
                    name,
                    "prompt provider is unavailable non-interactively",
                ));
            }
            prompt_secret_cancellable(label, context.prompt_terminal.as_ref(), cancel).map_err(
                |error| provider_io_failure(name, "prompt provider is unavailable", error),
            )?
        }
        SecretProvider::File { path } => {
            read_secret_file(&context.normalize_config_path(path), false)
                .map_err(|_| provider_failure(name, "file provider is unavailable"))?
        }
        SecretProvider::Helper { command } => helper_secret_cancellable(command, context, cancel)
            .map_err(|error| {
            provider_io_failure(name, "helper provider is unavailable", error)
        })?,
        SecretProvider::Store { key, set } => {
            return context
                .store
                .as_ref()
                .ok_or_else(|| provider_failure(name, "secret unavailable"))?
                .resolve(
                    name,
                    key,
                    set.as_deref(),
                    cancel,
                    context.paced_clock.clone(),
                );
        }
    };
    normalize_secret(name, bytes)
}

pub fn read_secret_file(
    path: &Path,
    allow_group_other: bool,
) -> Result<Zeroizing<Vec<u8>>, CapabilityError> {
    let mut file = defensive_open(path, allow_group_other)?;
    read_bounded(&mut file).map_err(|_| CapabilityError::UnsafePath)
}

fn read_bounded(reader: &mut dyn Read) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 1));
    reader
        .take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret exceeds maximum size",
        ));
    }
    Ok(bytes)
}

fn prompt_secret_cancellable(
    label: &str,
    terminal: Option<&PromptTerminal>,
    cancel: &CancellationToken,
) -> io::Result<Zeroizing<Vec<u8>>> {
    match terminal {
        Some(terminal) => {
            let mut label_writer = terminal
                .label_writer
                .lock()
                .map_err(|_| io::Error::other("prompt label writer is poisoned"))?;
            prompt_secret_from_fd(
                label,
                terminal.input.as_fd(),
                rustix::termios::isatty(terminal.input.as_fd()),
                &mut *label_writer,
                cancel,
            )
        }
        None => {
            let stdin = io::stdin();
            let mut label_writer = label_writer(io::stderr().as_fd().try_clone_to_owned())?;
            prompt_secret_from_fd(
                label,
                stdin.as_fd(),
                stdin.is_terminal(),
                &mut *label_writer,
                cancel,
            )
        }
    }
}

fn prompt_secret_from_fd(
    label: &str,
    fd: BorrowedFd<'_>,
    is_terminal: bool,
    stderr: &mut dyn Write,
    cancel: &CancellationToken,
) -> io::Result<Zeroizing<Vec<u8>>> {
    broil_core::secret::prompt_secret_from_fd(label, fd, is_terminal, stderr, &|| {
        cancel.is_cancelled()
    })
}

pub fn read_stdin_line_cancellable(
    cancel: &CancellationToken,
    hide_input: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    broil_core::secret::read_stdin_line_cancellable(&|| cancel.is_cancelled(), hide_input)
}

fn helper_secret_cancellable(
    command: &[String],
    context: &SecretContext,
    cancel: &CancellationToken,
) -> io::Result<Zeroizing<Vec<u8>>> {
    if cancel.is_cancelled() {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
    }
    let (program, args) = command
        .split_first()
        .ok_or_else(|| io::Error::other("empty helper command"))?;
    let program = helper_program(program, context);
    let mut child = Command::new(program)
        .args(args)
        .current_dir(&context.root)
        .env_clear()
        .envs(
            context
                .env_snapshot
                .iter()
                .map(|(name, value)| (name, value)),
        )
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("helper stdout unavailable"))?;
    let bytes = match read_bounded_cancellable(&stdout, cancel) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let status = wait_helper(&mut child, cancel)?;
    if !status.success() {
        return Err(io::Error::other("helper failed"));
    }
    Ok(bytes)
}

fn read_bounded_cancellable<Fd: AsFd>(
    fd: Fd,
    cancel: &CancellationToken,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let _guard = NonblockingGuard::enter(fd.as_fd())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 1));
    let mut buffer = Zeroizing::new([0_u8; 4096]);
    loop {
        if cancel.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        match rustix::io::read(fd.as_fd(), &mut buffer[..]) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                if bytes.len() > MAX_SECRET_BYTES {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "secret exceeds maximum size",
                    ));
                }
            }
            Err(error)
                if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK =>
            {
                std::thread::sleep(CANCELLABLE_READ_SLEEP);
            }
            Err(error) if error == rustix::io::Errno::INTR => {
                std::thread::sleep(CANCELLABLE_READ_SLEEP);
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

fn wait_helper(
    child: &mut Child,
    cancel: &CancellationToken,
) -> io::Result<std::process::ExitStatus> {
    loop {
        if cancel.is_cancelled() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        std::thread::sleep(CANCELLABLE_READ_SLEEP);
    }
}

struct NonblockingGuard<Fd: AsFd> {
    fd: Fd,
    original_flags: rustix::fs::OFlags,
    active: bool,
}

impl<Fd: AsFd> NonblockingGuard<Fd> {
    fn enter(fd: Fd) -> io::Result<Self> {
        let original_flags = rustix::fs::fcntl_getfl(fd.as_fd()).map_err(io::Error::from)?;
        rustix::fs::fcntl_setfl(fd.as_fd(), original_flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(io::Error::from)?;
        Ok(Self {
            fd,
            original_flags,
            active: true,
        })
    }
}

impl<Fd: AsFd> Drop for NonblockingGuard<Fd> {
    fn drop(&mut self) {
        if self.active {
            let _ = rustix::fs::fcntl_setfl(self.fd.as_fd(), self.original_flags);
        }
    }
}

fn helper_program(program: &str, context: &SecretContext) -> OsString {
    let path = Path::new(program);
    if path.components().next().is_some() && program.contains('/') {
        context.normalize_config_path(program).into_os_string()
    } else {
        OsStr::new(program).to_os_string()
    }
}

fn normalize_secret(name: &str, bytes: Zeroizing<Vec<u8>>) -> Result<OwnedSecret, SecretFailure> {
    broil_core::secret::normalize_secret(bytes).map_err(|error| {
        let detail = match error {
            SecretNormalizationError::UnusableBytes => "provider returned unusable secret bytes",
            SecretNormalizationError::InvalidUtf8 => "provider returned non-UTF-8 secret bytes",
        };
        provider_failure(name, detail)
    })
}

fn provider_failure(name: &str, detail: &str) -> SecretFailure {
    SecretFailure::new(
        FailureClass::SecretUnavailable,
        format!("secret provider {name} failed: {detail}"),
    )
}

fn provider_io_failure(name: &str, detail: &str, error: io::Error) -> SecretFailure {
    if error.kind() == io::ErrorKind::Interrupted {
        cancelled_provider(name)
    } else {
        provider_failure(name, detail)
    }
}

fn cancelled_provider(name: &str) -> SecretFailure {
    SecretFailure::new(
        FailureClass::Cancellation,
        format!("secret provider {name} was cancelled"),
    )
}

impl From<CapabilityError> for SecretFailure {
    fn from(_: CapabilityError) -> Self {
        SecretFailure::new(
            FailureClass::SecretUnavailable,
            "secret provider failed path-safety checks",
        )
    }
}
