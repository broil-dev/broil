// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{buffer::Bytes, common::*, files, protected};
use broil_core::secret::OwnedSecret;
use rustix::process::{Pid, Signal};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::{
        fd::AsFd,
        unix::process::{CommandExt, ExitStatusExt},
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

static OPERATIONS: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct Permit {
    occupied: AtomicBool,

}

impl Permit {
    pub(crate) fn acquire() -> Result<Arc<Self>> {
        OPERATIONS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 4).then_some(n + 1)
            })
            .map_err(|_| Failure::Capacity)?;
        Ok(Arc::new(Self {
            occupied: AtomicBool::new(false),

        }))
    }
}

pub(crate) struct Task {
    permit: Option<Arc<Permit>>,
}
impl Task {
    pub(crate) fn begin(permit: &Arc<Permit>) -> Result<Self> {
        require(
            !permit.occupied.swap(true, Ordering::AcqRel),
            Failure::Indeterminate,
        )?;
        Ok(Self {
            permit: Some(permit.clone()),
        })
    }
    pub(crate) fn observed(mut self) {
        if let Some(permit) = self.permit.take() {
            permit.occupied.store(false, Ordering::Release);
        }
    }
}
impl Drop for Task {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            std::mem::forget(permit);
        }
    }
}

pub(crate) struct Active {
    end: u64,
    cancelled: Arc<AtomicBool>,
    abandoned: Arc<AtomicBool>,
    cleanup: Arc<AtomicU64>,
    cleanup_ms: u64,

}

pub(crate) struct Grace(Option<u64>);

impl Grace {
    pub(crate) fn unbounded() -> Self {
        Self(None)
    }
    pub(crate) fn until(end: u64) -> Self {
        Self(Some(end))
    }
    pub(crate) fn check(&self) -> Result<()> {
        match self.0 {
            Some(end) => before(end),
            None => Ok(()),
        }
    }
}

impl Active {
    pub(crate) fn after_write(&self) {

    }
    pub(crate) fn after_scalar_drop(&self) {

    }
    fn before_delivery(&self) {

    }
    pub(crate) fn end(&self) -> u64 {
        self.end
    }
    pub(crate) fn check(&self) -> Result<()> {
        before(self.end)?;
        require(
            !self.cancelled.load(Ordering::Acquire) && !self.abandoned.load(Ordering::Acquire),
            Failure::Cancellation,
        )
    }
    pub(crate) fn cleanup_grace(&self) -> Grace {
        let until = monotonic_ns()
            .min(self.end)
            .saturating_add(self.cleanup_ms * 1_000_000);
        Grace::until(
            self.cleanup
                .compare_exchange(0, until, Ordering::AcqRel, Ordering::Acquire)
                .err()
                .unwrap_or(until),
        )
    }
    pub(crate) fn io<T>(&self, call: impl FnOnce() -> std::io::Result<T>) -> Result<T> {
        self.check()?;
        let result = call().map_err(|_| Failure::Storage);
        self.check()?;
        result
    }
    pub(crate) fn sys<T>(&self, call: impl FnOnce() -> rustix::io::Result<T>) -> Result<T> {
        self.io(|| call().map_err(Into::into))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        OPERATIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Launch {
    pub executable: Entry,
    pub digest: String,
    pub size: u64,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub protected: protected::Checks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dispatch {
    None,
    Possible,
    Observed,
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub failure: Option<Failure>,
    pub dispatch: Dispatch,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub cancellation_requested: bool,
    pub completion_uncertain: bool,
    pub cleanup_uncertain: bool,
    pub started_ns: u64,
    pub finished_ns: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

impl Observation {
    pub(crate) fn new(start: u64) -> Self {
        Self {
            failure: None,
            dispatch: Dispatch::None,
            exit_code: None,
            signal: None,
            cancellation_requested: false,
            completion_uncertain: false,
            cleanup_uncertain: false,
            started_ns: start,
            finished_ns: start,
            stdout_bytes: 0,
            stderr_bytes: 0,
        }
    }
}

pub(crate) struct Output {
    pub observation: Observation,
    pub stdout: Bytes,
    pub stdout_used: usize,
    pub stderr: Bytes,
    pub stderr_used: usize,
}

pub(crate) struct Input {
    pub prefix: Vec<u8>,
    pub scalar: Option<OwnedSecret>,
    pub private: Option<Bytes>,
}

struct PendingChild {
    child: Option<Child>,
    permit: Arc<Permit>,
}

impl PendingChild {
    fn take(mut self) -> Child {
        self.child.take().expect("pending child is consumed once")
    }
}

impl Drop for PendingChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.stdin.take();
            child.stdout.take();
            child.stderr.take();
            if let Ok(pid) = pid(&child) {
                let _ = rustix::process::kill_process_group(pid, Signal::KILL);
            }
            std::mem::forget(self.permit.clone());
        }
    }
}

impl Input {
    fn len(&self) -> usize {
        self.prefix.len()
            + self.scalar.as_ref().map_or(0, |s| s.len())
            + self.private.as_ref().map_or(0, |s| s.get().len())
    }
    fn release(&mut self) {
        self.scalar.take();
        self.private.take();
    }
    fn bytes(&self, offset: usize) -> &[u8] {
        if offset < self.prefix.len() {
            &self.prefix[offset..]
        } else if let Some(private) = &self.private {
            &private.get()[offset - self.prefix.len()..]
        } else {
            self.scalar
                .as_ref()
                .map(|s| &s.as_str().as_bytes()[offset - self.prefix.len()..])
                .unwrap_or(&[])
        }
    }
}

fn nonblocking(fd: impl AsFd) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(&fd).map_err(|_| Failure::Tool)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(|_| Failure::Tool)
}

fn group_alive(pid: Pid) -> bool {
    rustix::process::test_kill_process_group(pid).is_ok()
}

fn pid(child: &Child) -> Result<Pid> {
    let raw = i32::try_from(child.id()).map_err(|_| Failure::Tool)?;
    Pid::from_raw(raw).ok_or(Failure::Tool)
}

fn terminate(child: &mut Child, until: u64) -> bool {
    child.stdin.take();
    child.stdout.take();
    child.stderr.take();
    let Ok(pid) = pid(child) else { return false };
    let _ = rustix::process::kill_process_group(pid, Signal::TERM);
    let escalation = monotonic_ns().saturating_add(100_000_000).min(until);
    let mut exited = false;
    loop {
        if child.try_wait().ok().flatten().is_some() {
            exited = true;
        }
        if exited && !group_alive(pid) {
            return true;
        }
        let now = monotonic_ns();
        if now >= escalation {
            let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        }
        if now >= until {
            return false;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn abandon(mut child: Child, until: u64, permit: Arc<Permit>) {
    if !terminate(&mut child, until) {
        std::mem::forget(permit);
    }
}

pub(crate) struct Clock {
    pub start: u64,
    pub end: u64,
    pub cleanup_end: Option<u64>,
    pub cleanup_limit_ms: u64,
    shared_cleanup: Arc<AtomicU64>,
}

pub(crate) fn local(
    lease: protected::Lease,
    action: protected::Action,
    clock: &mut Clock,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> (Option<protected::Lease>, Result<()>) {
    let (lease, result) = local_work(
        LocalWork::Protected(lease, action),
        clock,
        cancelled,
        permit,
    );
    (
        lease.and_then(|lease| match lease {
            LocalLease::Protected(lease) => Some(lease),
            _ => None,
        }),
        result,
    )
}

pub(crate) fn builder_local(
    lease: super::builders::records::Lease,
    action: super::builders::records::Action,
    clock: &mut Clock,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> (Option<super::builders::records::Lease>, Result<()>) {
    let (lease, result) = local_work(LocalWork::Builder(lease, action), clock, cancelled, permit);
    (
        lease.and_then(|lease| match lease {
            LocalLease::Builder(lease) => Some(lease),
            _ => None,
        }),
        result,
    )
}

enum LocalWork {
    Access(crate::k3s::state::access::FileWork),
    Protected(protected::Lease, protected::Action),
    Builder(
        super::builders::records::Lease,
        super::builders::records::Action,
    ),
    Source(SourceRead),
    Materialize(Box<super::solve::MaterializeWork>),
    Snapshot(super::solve::SnapshotWork),
    Public(Box<dyn PublicAction>),
}

enum LocalLease {
    Access(crate::k3s::state::access::FileWork),
    Protected(protected::Lease),
    Builder(super::builders::records::Lease),
    Source(SourceRead),
    Materialize(Box<super::solve::MaterializeWork>),
    Snapshot(super::solve::SnapshotWork),
    Public(Box<dyn PublicAction>),
}

pub(crate) trait PublicAction: Send {
    fn apply(&mut self, active: &Active) -> Result<()>;
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any>;
}

impl LocalWork {
    fn retained(self) -> LocalLease {
        match self {
            Self::Access(work) => LocalLease::Access(work),
            Self::Protected(lease, _) => LocalLease::Protected(lease),
            Self::Builder(lease, _) => LocalLease::Builder(lease),
            Self::Source(read) => LocalLease::Source(read),
            Self::Materialize(work) => LocalLease::Materialize(work),
            Self::Snapshot(work) => LocalLease::Snapshot(work),
            Self::Public(work) => LocalLease::Public(work),
        }
    }
    fn apply(self, active: &Active) -> (LocalLease, Result<()>) {
        match self {
            Self::Access(mut work) => {
                let result = active.check().and_then(|_| work.apply(active));
                (LocalLease::Access(work), result)
            }
            Self::Protected(mut lease, action) => {
                let result = active
                    .check()
                    .and_then(|_| action.apply(&mut lease, active));
                (LocalLease::Protected(lease), result)
            }
            Self::Builder(mut lease, action) => {
                let result = active
                    .check()
                    .and_then(|_| action.apply(&mut lease, active));
                (LocalLease::Builder(lease), result)
            }
            Self::Source(mut read) => {
                let result = active.check().and_then(|_| read.apply(active));
                (LocalLease::Source(read), result)
            }
            Self::Materialize(mut work) => {
                let result = active.check().and_then(|_| work.apply(active));
                (LocalLease::Materialize(work), result)
            }
            Self::Snapshot(mut work) => {
                let result = active.check().and_then(|_| work.apply(active));
                (LocalLease::Snapshot(work), result)
            }
            Self::Public(mut work) => {
                let result = active.check().and_then(|_| work.apply(active));
                (LocalLease::Public(work), result)
            }
        }
    }
}

pub(crate) struct SourceRead {
    path: PathBuf,
    limit: usize,
    result: Option<SourceBytes>,
}

pub(crate) struct SourceBytes {
    pub bytes: Bytes,
    #[allow(dead_code)]
    pub device: u64,
    #[allow(dead_code)]
    pub inode: u64,
    pub size: u64,
    pub digest: String,
}

impl SourceRead {
    pub(crate) fn new(path: PathBuf, limit: usize) -> Result<Self> {
        require(
            valid_path(&path) && limit > 0 && limit <= 1_048_576,
            Failure::Policy,
        )?;
        Ok(Self {
            path,
            limit,
            result: None,
        })
    }

    pub(crate) fn take(self) -> Option<SourceBytes> {
        self.result
    }

    fn apply(&mut self, active: &Active) -> Result<()> {
        use broil_core::secret::path_safety;
        use rustix::fs::{Mode, OFlags};
        use std::os::unix::fs::MetadataExt;
        require(self.result.is_none(), Failure::Policy)?;
        active.check()?;
        let (parent, name) =
            path_safety::defensive_open_parent(&self.path).map_err(|_| Failure::Storage)?;
        active.check()?;
        let handle = std::fs::File::from(active.sys(|| {
            rustix::fs::openat(
                &parent,
                &name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        let metadata = active.io(|| handle.metadata())?;
        require(metadata.is_file(), Failure::Policy)?;
        let size = metadata.len();
        require(size > 0 && size <= self.limit as u64, Failure::Limit)?;
        let mut input = active.io(|| {
            path_safety::reopen_for_read(&handle)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })?;
        let mut bytes = Bytes::new(size as usize)?;
        let mut offset = 0;
        while offset < bytes.get().len() {
            let count = active.io(|| input.read(&mut bytes.get_mut()[offset..]))?;
            require(count > 0, Failure::Integrity)?;
            offset += count;
        }
        let mut tail = Bytes::new(1)?;
        require(
            active.io(|| input.read(tail.get_mut()))? == 0,
            Failure::Integrity,
        )?;
        let after = active.io(|| handle.metadata())?;
        require(
            after.is_file()
                && after.len() == size
                && after.dev() == metadata.dev()
                && after.ino() == metadata.ino(),
            Failure::Integrity,
        )?;
        std::str::from_utf8(bytes.get()).map_err(|_| Failure::Policy)?;
        let digest = super::analysis::hash(bytes.get());
        active.check()?;
        self.result = Some(SourceBytes {
            bytes,
            device: metadata.dev(),
            inode: metadata.ino(),
            size,
            digest,
        });
        Ok(())
    }
}

pub(crate) fn source_local(
    read: SourceRead,
    clock: &mut Clock,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> (Option<SourceRead>, Result<()>) {
    let (lease, result) = local_work(LocalWork::Source(read), clock, cancelled, permit);
    (
        lease.and_then(|lease| match lease {
            LocalLease::Source(read) => Some(read),
            _ => None,
        }),
        result,
    )
}

pub(crate) fn materialize_local(
    work: super::solve::MaterializeWork,
    clock: &mut Clock,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> (Option<super::solve::MaterializeWork>, Result<()>) {
    let (lease, result) = local_work(
        LocalWork::Materialize(Box::new(work)),
        clock,
        cancelled,
        permit,
    );
    (
        lease.and_then(|lease| match lease {
            LocalLease::Materialize(work) => Some(*work),
            _ => None,
        }),
        result,
    )
}

pub(crate) fn snapshot_local(
    work: super::solve::SnapshotWork,
    clock: &mut Clock,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> (Option<super::solve::SnapshotWork>, Result<()>) {
    let (lease, result) = local_work(LocalWork::Snapshot(work), clock, cancelled, permit);
    (
        lease.and_then(|lease| match lease {
            LocalLease::Snapshot(work) => Some(work),
            _ => None,
        }),
        result,
    )
}

pub(crate) fn access_local(
    work: crate::k3s::state::access::FileWork,
    clock: &mut Clock,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> (Option<crate::k3s::state::access::FileWork>, Result<()>) {
    let (work, result) = local_work(LocalWork::Access(work), clock, cancelled, permit);
    (
        work.and_then(|work| match work {
            LocalLease::Access(work) => Some(work),
            _ => None,
        }),
        result,
    )
}

pub(crate) fn public_local<W: PublicAction + 'static>(
    work: W,
    clock: &mut Clock,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> (Option<W>, Result<()>) {
    let (lease, result) = local_work(LocalWork::Public(Box::new(work)), clock, cancelled, permit);
    (
        lease.and_then(|lease| match lease {
            LocalLease::Public(work) => work.into_any().downcast::<W>().ok().map(|work| *work),
            _ => None,
        }),
        result,
    )
}

fn local_work(
    work: LocalWork,
    clock: &mut Clock,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> (Option<LocalLease>, Result<()>) {
    if let Err(failure) = before(clock.end)
        .and_then(|_| require(!cancelled.load(Ordering::Acquire), Failure::Cancellation))
    {
        return (Some(work.retained()), Err(failure));
    }
    let task = match Task::begin(permit) {
        Ok(task) => task,
        Err(error) => return (Some(work.retained()), Err(error)),
    };
    let abandoned = Arc::new(AtomicBool::new(false));
    let active = Active {
        end: clock.end,
        cancelled: cancelled.clone(),
        abandoned: abandoned.clone(),
        cleanup: clock.shared_cleanup.clone(),
        cleanup_ms: clock.cleanup_limit_ms,

    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let spawned = thread::Builder::new()
        .name("broil-image-local".into())
        .spawn(move || {
            let (lease, result) = work.apply(&active);
            active.before_delivery();
            let result = active.check().and(result);
            let _ = sender.try_send((lease, result));
        });
    if spawned.is_err() {
        return (None, Err(Failure::Capacity));
    }
    loop {
        let failure = if cancelled.load(Ordering::Acquire) {
            Some(Failure::Cancellation)
        } else if monotonic_ns() >= clock.end {
            Some(Failure::Timeout)
        } else {
            None
        };
        if let Some(failure) = failure {
            abandoned.store(true, Ordering::Release);
            return (None, Err(failure));
        }
        match receiver.try_recv() {
            Ok((lease, result)) => {
                if cancelled.load(Ordering::Acquire) || monotonic_ns() >= clock.end {
                    abandoned.store(true, Ordering::Release);
                    return (
                        None,
                        Err(if cancelled.load(Ordering::Acquire) {
                            Failure::Cancellation
                        } else {
                            Failure::Timeout
                        }),
                    );
                }
                task.observed();
                return (Some(lease), result);
            }
            Err(mpsc::TryRecvError::Disconnected) => return (None, Err(Failure::Indeterminate)),
            Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
        }
    }
}

impl Clock {
    pub(crate) fn new(milliseconds: u64) -> Result<Self> {
        let start = monotonic_ns();
        Ok(Self {
            start,
            end: deadline(start, milliseconds)?,
            cleanup_end: None,
            cleanup_limit_ms: 5000,
            shared_cleanup: Arc::new(AtomicU64::new(0)),
        })
    }
    pub(crate) fn cleanup(&mut self, milliseconds: u64) -> u64 {
        let milliseconds = milliseconds.min(self.cleanup_limit_ms);
        let until = monotonic_ns()
            .min(self.end)
            .saturating_add(milliseconds * 1_000_000);
        let old =
            self.shared_cleanup
                .compare_exchange(0, until, Ordering::AcqRel, Ordering::Acquire);
        let until = old.err().unwrap_or(until);
        self.cleanup_end = Some(until);
        until
    }
}

pub(crate) fn run(
    launch: Launch,
    mut input: Input,
    clock: &mut Clock,
    limits: &Limits,
    cancelled: &Arc<AtomicBool>,
    permit: &Arc<Permit>,
) -> std::result::Result<Output, Observation> {
    let mut observation = Observation::new(clock.start);
    let task = Task::begin(permit).map_err(|failure| {
        observation.failure = Some(failure);
        observation.cleanup_uncertain = true;
        observation.clone()
    })?;
    let pipe_start = monotonic_ns();
    let result = (|| -> Result<Output> {
        limits.validate()?;
        require(
            input.scalar.is_none() || input.private.is_none(),
            Failure::Policy,
        )?;
        if input.private.is_some() {
            require(input.len() <= limits.stream_bytes, Failure::Limit)?;
        }
        before(clock.end)?;
        require(!cancelled.load(Ordering::Acquire), Failure::Cancellation)?;
        let abandoned = Arc::new(AtomicBool::new(false));
        let spawning = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::sync_channel(1);
        let task_cancelled = cancelled.clone();
        let task_abandoned = abandoned.clone();
        let task_spawning = spawning.clone();
        let task_permit = permit.clone();
        let end = clock.end;
        let cleanup = clock.shared_cleanup.clone();
        let cleanup_ms = limits.cleanup_ms.min(clock.cleanup_limit_ms);
        thread::Builder::new()
            .name("broil-image-launch".into())
            .spawn(move || {
                let active = || {
                    before(end).and_then(|_| {
                        require(
                            !task_cancelled.load(Ordering::Acquire)
                                && !task_abandoned.load(Ordering::Acquire),
                            Failure::Cancellation,
                        )
                    })
                };
                let result = (|| {
                    active()?;
                    let executable = files::open(&launch.executable, true)?;
                    files::verify_file(&executable, &launch.digest, launch.size, launch.size, end)?;
                    active()?;
                    files::open(&launch.executable, true)?;
                    active()?;
                    launch.protected.recheck(&Active {
                        end,
                        cancelled: task_cancelled.clone(),
                        abandoned: task_abandoned.clone(),
                        cleanup: cleanup.clone(),
                        cleanup_ms,

                    })?;
                    active()?;
                    task_spawning.store(true, Ordering::Release);
                    Command::new(&launch.executable.path)
                        .args(&launch.args)
                        .env_clear()
                        .envs(&launch.env)
                        .current_dir(&launch.cwd)
                        .process_group(0)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .map_err(|_| Failure::Tool)
                })();
                if let Ok(child) = result {
                    if active().is_err() {
                        let until = monotonic_ns()
                            .min(end)
                            .saturating_add(cleanup_ms * 1_000_000);
                        let until = cleanup
                            .compare_exchange(0, until, Ordering::AcqRel, Ordering::Acquire)
                            .err()
                            .unwrap_or(until);
                        abandon(child, until, task_permit);
                    } else if let Err(
                        mpsc::TrySendError::Disconnected(Ok(child))
                        | mpsc::TrySendError::Full(Ok(child)),
                    ) = sender.try_send(Ok(PendingChild {
                        child: Some(child),
                        permit: task_permit.clone(),
                    })) {
                        let until = monotonic_ns()
                            .min(end)
                            .saturating_add(cleanup_ms * 1_000_000);
                        let until = cleanup
                            .compare_exchange(0, until, Ordering::AcqRel, Ordering::Acquire)
                            .err()
                            .unwrap_or(until);
                        abandon(child.take(), until, task_permit);
                    }
                } else {
                    let _ = sender.try_send(result.map(|child| PendingChild {
                        child: Some(child),
                        permit: task_permit,
                    }));
                }
            })
            .map_err(|_| Failure::Capacity)?;
        let mut child = loop {
            if cancelled.load(Ordering::Acquire) || monotonic_ns() >= clock.end {
                abandoned.store(true, Ordering::Release);
                observation.dispatch = if spawning.load(Ordering::Acquire) {
                    Dispatch::Possible
                } else {
                    Dispatch::None
                };
                observation.completion_uncertain = observation.dispatch != Dispatch::None;
                observation.cleanup_uncertain = true;
                clock.cleanup(limits.cleanup_ms);
                return Err(if cancelled.load(Ordering::Acquire) {
                    Failure::Cancellation
                } else {
                    Failure::Timeout
                });
            }
            match receiver.try_recv() {
                Ok(result) => break result?.take(),
                Err(mpsc::TryRecvError::Disconnected) => return Err(Failure::Tool),
                Err(mpsc::TryRecvError::Empty) => thread::sleep(Duration::from_millis(1)),
            }
        };
        observation.dispatch = Dispatch::Observed;
        let mut stdin = child.stdin.take();
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let mut exit = None;
        let io = (|| -> Result<Output> {
            nonblocking(stdin.as_ref().ok_or(Failure::Tool)?)?;
            nonblocking(stdout.as_ref().ok_or(Failure::Tool)?)?;
            nonblocking(stderr.as_ref().ok_or(Failure::Tool)?)?;
            let mut out = Bytes::new(limits.stream_bytes + 1)?;
            let mut err = Bytes::new(limits.stream_bytes + 1)?;
            let (mut sent, mut out_used, mut err_used) = (0, 0, 0);
            let mut last = [pipe_start; 3];
            let mut drain_end = clock.end;
            loop {
                let now = monotonic_ns();
                require(!cancelled.load(Ordering::Acquire), Failure::Cancellation)?;
                require(now < clock.end, Failure::Timeout)?;
                if let Some(pipe) = stdin.as_mut() {
                    require(
                        now < deadline(pipe_start, limits.handoff_ms)?
                            && now < deadline(last[0], limits.idle_ms)?,
                        Failure::Timeout,
                    )?;
                    let bytes = input.bytes(sent);
                    if bytes.is_empty() {
                        stdin.take();
                        input.release();
                    } else {
                        match pipe.write(bytes) {
                            Ok(0) => return Err(Failure::Tool),
                            Ok(n) => {
                                sent += n;
                                last[0] = now;
                                if sent == input.len() {
                                    stdin.take();
                                    input.release();
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => return Err(Failure::Tool),
                        }
                    }
                }
                for index in 0..2 {
                    let (used, storage, last) = if index == 0 {
                        (&mut out_used, &mut out, &mut last[1])
                    } else {
                        (&mut err_used, &mut err, &mut last[2])
                    };
                    let read = if index == 0 {
                        stdout
                            .as_mut()
                            .map(|pipe| pipe.read(&mut storage.get_mut()[*used..]))
                    } else {
                        stderr
                            .as_mut()
                            .map(|pipe| pipe.read(&mut storage.get_mut()[*used..]))
                    };
                    if let Some(read) = read {
                        require(now < deadline(*last, limits.idle_ms)?, Failure::Timeout)?;
                        match read {
                            Ok(0) => {
                                if index == 0 {
                                    stdout.take();
                                } else {
                                    stderr.take();
                                }
                            }
                            Ok(n) => {
                                *used += n;
                                *last = now;
                                require(*used <= limits.stream_bytes, Failure::Limit)?;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => return Err(Failure::Tool),
                        }
                    }
                }
                observation.stdout_bytes = out_used as u64;
                observation.stderr_bytes = err_used as u64;
                if exit.is_none() {
                    exit = child.try_wait().map_err(|_| Failure::Tool)?;
                    if let Some(exit) = exit {
                        observation.exit_code = exit.code();
                        observation.signal = exit.signal();
                        drain_end = clock.end.min(deadline(now, limits.drain_ms)?);
                        require(stdin.is_none(), Failure::Tool)?;
                    }
                }
                if exit.is_some() {
                    if stdout.is_none() && stderr.is_none() {
                        break;
                    }
                    require(now < drain_end, Failure::Timeout)?;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Ok(Output {
                observation: observation.clone(),
                stdout: out,
                stdout_used: out_used,
                stderr: err,
                stderr_used: err_used,
            })
        })();
        let pipe_residue = exit.is_some() && (stdout.is_some() || stderr.is_some());
        input.release();
        stdin.take();
        stdout.take();
        stderr.take();
        let clean = if exit.is_some() && pid(&child).is_ok_and(|p| !group_alive(p)) {
            true
        } else {
            terminate(&mut child, clock.cleanup(limits.cleanup_ms))
        };
        if !clean || pipe_residue {
            observation.cleanup_uncertain = true;
            std::mem::forget(permit.clone());
        }
        match io {
            Ok(mut output) if clean && !pipe_residue => {
                output.observation.finished_ns = monotonic_ns();
                Ok(output)
            }
            Ok(_) => Err(Failure::Indeterminate),
            Err(failure) => Err(failure),
        }
    })();
    if !observation.cleanup_uncertain {
        task.observed();
    }
    result.map_err(|failure| {
        observation.failure = Some(failure);
        observation.cancellation_requested = cancelled.load(Ordering::Acquire);
        observation.completion_uncertain |= observation.dispatch != Dispatch::None;
        observation.finished_ns = monotonic_ns();
        observation
    })
}

