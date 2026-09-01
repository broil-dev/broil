// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use broil_core::remote::SecretProvider;
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::FailureClass;
use crate::path_safety::{CapabilityError, defensive_open};
use crate::scheduler::CancellationToken;

const MAX_SECRET_BYTES: usize = 64 * 1024;
const CANCELLABLE_READ_SLEEP: Duration = Duration::from_millis(25);

static INPUT_GUARD: Mutex<()> = Mutex::new(());
static INPUT_TERMINAL_STATE: Mutex<Option<InputTerminalState>> = Mutex::new(None);

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

pub struct OwnedSecret {
    value: Zeroizing<String>,
}

impl OwnedSecret {
    pub fn from_zeroizing(value: Zeroizing<String>) -> Self {
        Self { value }
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub fn len(&self) -> usize {
        self.value.len()
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.value).into_bytes())
    }
}

impl fmt::Debug for OwnedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedSecret([REDACTED])")
    }
}

#[derive(Clone)]
pub struct SecretContext {
    root: PathBuf,
    env_snapshot: Vec<(OsString, OsString)>,
    providers: BTreeMap<String, SecretProvider>,
    prompt_terminal: Option<PromptTerminal>,
    paced_clock: Option<PacedClock>,
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
        }
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

fn label_writer(dup: io::Result<OwnedFd>) -> io::Result<Box<dyn Write + Send>> {
    match dup {
        Ok(fd) => Ok(Box::new(File::from(fd))),
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::BADF.raw_os_error()) => {
            Ok(Box::new(io::sink()))
        }
        Err(error) => Err(error),
    }
}

fn prompt_secret_from_fd(
    label: &str,
    fd: BorrowedFd<'_>,
    is_terminal: bool,
    stderr: &mut dyn Write,
    cancel: &CancellationToken,
) -> io::Result<Zeroizing<Vec<u8>>> {
    if !is_terminal {
        return Err(io::Error::other("stdin is not a terminal"));
    }
    write!(stderr, "{label}: ")?;
    stderr.flush()?;
    let line = read_line_from_private_terminal_fd(fd, cancel, true)?;
    writeln!(stderr)?;
    Ok(line)
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

pub fn read_stdin_line_cancellable(
    cancel: &CancellationToken,
    hide_input: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        return Err(io::Error::other("stdin is not a terminal"));
    }
    read_line_from_private_terminal_fd(stdin.as_fd(), cancel, hide_input)
}

fn read_line_from_private_terminal_fd(
    fd: BorrowedFd<'_>,
    cancel: &CancellationToken,
    hide_input: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let private_fd = open_private_terminal_fd(fd)?;
    read_line_from_fd(private_fd.as_fd(), cancel, hide_input)
}

fn open_private_terminal_fd(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let flags =
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOCTTY;
    let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    match rustix::fs::open(proc_path.as_str(), flags, rustix::fs::Mode::empty()) {
        Ok(private_fd) => Ok(private_fd),
        Err(error) if fd.as_raw_fd() == 0 => {
            match rustix::fs::open("/dev/tty", flags, rustix::fs::Mode::empty()) {
                Ok(private_fd) => Ok(private_fd),
                Err(_) => Err(io::Error::from(error)),
            }
        }
        Err(error) => Err(io::Error::from(error)),
    }
}

fn read_line_from_fd(
    fd: BorrowedFd<'_>,
    cancel: &CancellationToken,
    hide_input: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let _guard = InputGuard::enter(fd, hide_input)?;
    read_fd_until_line(fd, cancel)
}

fn read_fd_until_line(
    fd: BorrowedFd<'_>,
    cancel: &CancellationToken,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 1));
    let mut buffer = Zeroizing::new([0_u8; 1024]);
    loop {
        if cancel.is_cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        match rustix::io::read(fd, &mut buffer[..]) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                let chunk = &buffer[..read];
                if let Some(index) = chunk.iter().position(|byte| *byte == b'\n') {
                    bytes.extend_from_slice(&chunk[..=index]);
                    if bytes.len() > MAX_SECRET_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "secret exceeds maximum size",
                        ));
                    }
                    return Ok(bytes);
                }
                bytes.extend_from_slice(chunk);
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

struct InputTerminalState {
    fd: OwnedFd,
    original_termios: rustix::termios::Termios,
    original_flags: rustix::fs::OFlags,
    termios_changed: bool,
}

struct InputGuard {
    _lock: MutexGuard<'static, ()>,
    active: bool,
}

impl InputGuard {
    fn enter(fd: BorrowedFd<'_>, hide_input: bool) -> io::Result<Self> {
        let lock = INPUT_GUARD.lock().expect("input guard mutex poisoned");
        let restore_fd = rustix::io::fcntl_dupfd_cloexec(fd, 0).map_err(io::Error::from)?;
        let original_termios = rustix::termios::tcgetattr(fd)
            .map_err(|_| io::Error::other("cannot read terminal mode"))?;
        let original_flags = rustix::fs::fcntl_getfl(fd).map_err(io::Error::from)?;
        *INPUT_TERMINAL_STATE
            .lock()
            .expect("input terminal state mutex poisoned") = Some(InputTerminalState {
            fd: restore_fd,
            original_termios: original_termios.clone(),
            original_flags,
            termios_changed: hide_input,
        });
        if hide_input {
            let mut updated_termios = original_termios.clone();
            updated_termios
                .local_modes
                .remove(rustix::termios::LocalModes::ECHO);
            if rustix::termios::tcsetattr(
                fd,
                rustix::termios::OptionalActions::Flush,
                &updated_termios,
            )
            .is_err()
            {
                restore_global_input_terminal();
                return Err(io::Error::other("cannot update terminal mode"));
            }
        }
        if let Err(error) =
            rustix::fs::fcntl_setfl(fd, original_flags | rustix::fs::OFlags::NONBLOCK)
        {
            restore_global_input_terminal();
            return Err(io::Error::from(error));
        }
        Ok(Self {
            _lock: lock,
            active: true,
        })
    }
}

impl Drop for InputGuard {
    fn drop(&mut self) {
        if self.active {
            restore_global_input_terminal();
        }
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

pub fn restore_global_input_terminal() {
    let state = INPUT_TERMINAL_STATE
        .lock()
        .expect("input terminal state mutex poisoned")
        .take();
    if let Some(state) = state {
        if state.termios_changed {
            let _ = rustix::termios::tcsetattr(
                &state.fd,
                rustix::termios::OptionalActions::Flush,
                &state.original_termios,
            );
        }
        let _ = rustix::fs::fcntl_setfl(&state.fd, state.original_flags);
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

fn normalize_secret(
    name: &str,
    mut bytes: Zeroizing<Vec<u8>>,
) -> Result<OwnedSecret, SecretFailure> {
    if bytes.ends_with(b"\r\n") {
        let len = bytes.len();
        bytes.truncate(len - 2);
    } else if bytes.ends_with(b"\n") {
        let len = bytes.len();
        bytes.truncate(len - 1);
    }
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() > MAX_SECRET_BYTES {
        return Err(provider_failure(
            name,
            "provider returned unusable secret bytes",
        ));
    }
    std::str::from_utf8(&bytes)
        .map_err(|_| provider_failure(name, "provider returned non-UTF-8 secret bytes"))?;
    Ok(OwnedSecret::from_zeroizing(Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes))
            .expect("secret bytes were validated as UTF-8"),
    )))
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

pub fn normalize_path(base: &Path, path: &Path) -> PathBuf {
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

impl From<CapabilityError> for SecretFailure {
    fn from(_: CapabilityError) -> Self {
        SecretFailure::new(
            FailureClass::SecretUnavailable,
            "secret provider failed path-safety checks",
        )
    }
}
