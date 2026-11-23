// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Shared zeroizing secret holders, provider normalization, and guarded terminal input.

pub mod environment;
pub mod path_safety;

use std::fmt;
use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use zeroize::Zeroizing;

const MAX_SECRET_BYTES: usize = 64 * 1024;
/// Retain the credential prompt's 64-KiB envelope, including a submitted LF.
pub const MAX_CREDENTIAL_PROMPT_VALUE_BYTES: usize = MAX_SECRET_BYTES - 1;
const CANCELLABLE_READ_SLEEP: Duration = Duration::from_millis(25);

static INPUT_GUARD: Mutex<()> = Mutex::new(());
static INPUT_TERMINAL_STATE: Mutex<Option<InputTerminalState>> = Mutex::new(None);

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

/// A provider normalization failure that never contains secret bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretNormalizationError {
    UnusableBytes,
    InvalidUtf8,
}

/// Normalize provider output by removing one trailing LF or CRLF, preserving
/// embedded newlines, and rejecting empty, NUL-bearing, oversized, or non-UTF-8
/// values. The 64 KiB bound and line rule belong to this provider input format;
/// they do not define the format of future store values or rotation candidates.
pub fn normalize_secret(
    mut bytes: Zeroizing<Vec<u8>>,
) -> Result<OwnedSecret, SecretNormalizationError> {
    if bytes.ends_with(b"\r\n") {
        let len = bytes.len();
        bytes.truncate(len - 2);
    } else if bytes.ends_with(b"\n") {
        let len = bytes.len();
        bytes.truncate(len - 1);
    }
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() > MAX_SECRET_BYTES {
        return Err(SecretNormalizationError::UnusableBytes);
    }
    std::str::from_utf8(&bytes).map_err(|_| SecretNormalizationError::InvalidUtf8)?;
    Ok(OwnedSecret::from_zeroizing(Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes))
            .expect("secret bytes were validated as UTF-8"),
    )))
}

/// Resolve a path lexically from its base without symlink or tilde expansion.
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

/// Maps the duplicate of fd 2 a prompt renders its label through.
///
/// `Ok(fd)` wraps the duplicate in a `File`: unbuffered, so `write!` plus
/// `flush` issues the same `write(2)` sequence `Stderr` does. `EBADF` maps to
/// `io::sink()`, mirroring std's own policy of treating stderr writes to a
/// closed fd 2 as successful no-ops, so a prompt proceeds label-less rather
/// than failing as `secret unavailable`. The arm is defensive rather than
/// behaviour-preserving for a configuration that works today: std's startup
/// sanitization opens `/dev/null` over any of fds 0-2 that are closed before
/// `main`, so `2>&-` reaches the `Ok` arm with a `/dev/null` descriptor, and
/// only an fd 2 closed after startup reaches this one. Any other error passes
/// through and becomes `SecretUnavailable` at the provider boundary.
pub fn label_writer(dup: io::Result<OwnedFd>) -> io::Result<Box<dyn Write + Send>> {
    match dup {
        Ok(fd) => Ok(Box::new(File::from(fd))),
        Err(error) if error.raw_os_error() == Some(rustix::io::Errno::BADF.raw_os_error()) => {
            Ok(Box::new(io::sink()))
        }
        Err(error) => Err(error),
    }
}

/// Read hidden input through the shared guard after the terminal gate and label.
pub fn prompt_secret_from_fd(
    label: &str,
    fd: BorrowedFd<'_>,
    is_terminal: bool,
    stderr: &mut dyn Write,
    cancel: &dyn Fn() -> bool,
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

/// Open the controlling terminal independently of operational stdio and hold the
/// shared input guard across both prompt label and input. No stdio relocking.
pub fn prompt_private(label: &str, hide_input: bool) -> io::Result<OwnedSecret> {
    let value = prompt_private_bounded(label, hide_input, MAX_CREDENTIAL_PROMPT_VALUE_BYTES)?;
    if value.is_empty() {
        return Err(io::Error::other("invalid terminal input"));
    }
    Ok(value)
}

/// A submitted, optionally empty line for guided writes. EOF is cancellation.
/// This consumer has its own bound; credential providers retain their 64-KiB
/// nonempty normalization and existing terminal semantics.
pub fn prompt_private_bounded(
    label: &str,
    hide_input: bool,
    limit: usize,
) -> io::Result<OwnedSecret> {
    prompt_private_bounded_cancellable(label, hide_input, limit, &|| false)
}

/// The same private-terminal path with cancellation during guard acquisition
/// and input. Operational stdin and the CLI's held stream locks stay untouched.
pub fn prompt_private_bounded_cancellable(
    label: &str,
    hide_input: bool,
    limit: usize,
    cancel: &dyn Fn() -> bool,
) -> io::Result<OwnedSecret> {
    check_cancelled(cancel)?;
    if limit > 1024 * 1024 {
        return Err(io::Error::other("terminal input bound"));
    }
    let fd = rustix::fs::open(
        "/dev/tty",
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOCTTY,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut writer = File::from(rustix::io::fcntl_dupfd_cloexec(&fd, 0).map_err(io::Error::from)?);
    let guard = InputGuard::enter_mode_cancellable(fd.as_fd(), hide_input, true, cancel)?;
    write!(writer, "{label}: ")?;
    writer.flush()?;
    let result = read_submitted_line(fd.as_fd(), limit, cancel);
    drop(guard);
    writeln!(writer)?;
    let mut bytes = result?;
    let submitted_len = bytes.len();
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(submitted_len - 2);
    } else {
        bytes.truncate(submitted_len - 1);
    }
    if bytes.len() > limit || bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
        return Err(io::Error::other("invalid terminal input"));
    }
    Ok(OwnedSecret::from_zeroizing(Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes)).expect("validated terminal input"),
    )))
}

fn check_cancelled(cancel: &dyn Fn() -> bool) -> io::Result<()> {
    if cancel() {
        Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
    } else {
        Ok(())
    }
}

fn read_submitted_line(
    fd: BorrowedFd<'_>,
    limit: usize,
    cancel: &dyn Fn() -> bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let capacity = limit
        .checked_add(2)
        .ok_or_else(|| io::Error::other("terminal input bound"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| io::Error::other("terminal input allocation"))?;
    let mut buffer = Zeroizing::new([0u8; 1024]);
    loop {
        check_cancelled(cancel)?;
        match rustix::io::read(fd, &mut buffer[..]) {
            Ok(0) => return Err(io::Error::other("terminal input cancelled")),
            Ok(count) => {
                for byte in &buffer[..count] {
                    match *byte {
                        3 | 4 | 26 => return Err(io::Error::other("terminal input cancelled")),
                        8 | 127 => {
                            if !bytes.is_empty() {
                                let mut start = bytes.len() - 1;
                                while start > 0 && bytes[start] & 0xc0 == 0x80 {
                                    start -= 1;
                                }
                                use zeroize::Zeroize;
                                bytes[start..].zeroize();
                                bytes.truncate(start);
                            }
                        }
                        byte => {
                            if bytes.len() == capacity {
                                return Err(io::Error::other("terminal input bound"));
                            }
                            bytes.push(byte);
                            if byte == b'\n' {
                                return Ok(bytes);
                            }
                        }
                    }
                }
            }
            Err(error)
                if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK =>
            {
                std::thread::sleep(CANCELLABLE_READ_SLEEP)
            }
            Err(error) => return Err(io::Error::from(error)),
        }
    }
}

pub fn read_stdin_line_cancellable(
    cancel: &dyn Fn() -> bool,
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
    cancel: &dyn Fn() -> bool,
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
    cancel: &dyn Fn() -> bool,
    hide_input: bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let _guard = InputGuard::enter(fd, hide_input)?;
    read_fd_until_line(fd, cancel)
}

fn read_fd_until_line(
    fd: BorrowedFd<'_>,
    cancel: &dyn Fn() -> bool,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_SECRET_BYTES + 1));
    let mut buffer = Zeroizing::new([0_u8; 1024]);
    loop {
        if cancel() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        match rustix::io::read(fd, &mut buffer[..]) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                let chunk = &buffer[..read];
                if let Some(index) = chunk.iter().position(|byte| *byte == b'\n') {
                    if index + 1 > MAX_SECRET_BYTES - bytes.len() {
                        return Err(io::Error::other("secret exceeds maximum size"));
                    }
                    bytes.extend_from_slice(&chunk[..=index]);
                    if bytes.len() > MAX_SECRET_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "secret exceeds maximum size",
                        ));
                    }
                    return Ok(bytes);
                }
                if chunk.len() > MAX_SECRET_BYTES - bytes.len() {
                    return Err(io::Error::other("secret exceeds maximum size"));
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
        Self::enter_mode(fd, hide_input, false)
    }
    fn enter_mode(fd: BorrowedFd<'_>, hide_input: bool, submitted: bool) -> io::Result<Self> {
        let lock = INPUT_GUARD.lock().expect("input guard mutex poisoned");
        Self::enter_locked(fd, hide_input, submitted, lock)
    }
    fn enter_mode_cancellable(
        fd: BorrowedFd<'_>,
        hide_input: bool,
        submitted: bool,
        cancel: &dyn Fn() -> bool,
    ) -> io::Result<Self> {
        let lock = loop {
            check_cancelled(cancel)?;
            match INPUT_GUARD.try_lock() {
                Ok(lock) => break lock,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(CANCELLABLE_READ_SLEEP);
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(io::Error::other("input guard mutex poisoned"));
                }
            }
        };
        check_cancelled(cancel)?;
        Self::enter_locked(fd, hide_input, submitted, lock)
    }
    fn enter_locked(
        fd: BorrowedFd<'_>,
        hide_input: bool,
        submitted: bool,
        lock: MutexGuard<'static, ()>,
    ) -> io::Result<Self> {
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
            termios_changed: hide_input || submitted,
        });
        if hide_input || submitted {
            let mut updated_termios = original_termios.clone();
            if hide_input {
                updated_termios
                    .local_modes
                    .remove(rustix::termios::LocalModes::ECHO);
            }
            // Canonical terminal buffers silently truncate long values. Read the
            // bounded line ourselves; handle cancellation bytes before returning
            // so the same guard always restores echo and signal modes.
            if submitted {
                updated_termios.local_modes.remove(
                    rustix::termios::LocalModes::ICANON | rustix::termios::LocalModes::ISIG,
                );
                if hide_input {
                    updated_termios
                        .local_modes
                        .remove(rustix::termios::LocalModes::ECHONL);
                }
            }
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

