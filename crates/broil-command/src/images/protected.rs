// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{common::*, solve::Watch, supervise::Active};
use broil_core::secret::{OwnedSecret, path_safety::effective_uid};
use rustix::fs::{AtFlags, Mode, OFlags};
use std::{
    fs::{File, Metadata},
    io::Write,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

pub(crate) const MAX_FILES: usize = 128;
pub(crate) const MAX_BYTES: u64 = 16_777_216;
pub(crate) const MAX_SCALAR: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Type {
    Parent,
    Directory,
    Private,
    Ca,
    Socket,
    Daemon,
}

#[derive(Clone, Debug)]
struct Handle {
    file: Arc<File>,
    path: PathBuf,
    device: u64,
    inode: u64,
    kind: Type,
}

fn check_metadata(m: &Metadata, kind: Type) -> Result<()> {
    let uid = effective_uid();
    let mode = m.mode() & 0o7777;
    let valid = match kind {
        Type::Parent => {
            m.is_dir()
                && (m.uid() == uid || m.uid() == 0)
                && (mode & 0o022 == 0 || mode & 0o1000 != 0)
        }
        Type::Directory => m.is_dir() && m.uid() == uid && mode == 0o700,
        Type::Private => m.is_file() && m.uid() == uid && mode == 0o600 && m.nlink() == 1,
        Type::Ca => m.is_file() && (m.uid() == uid || m.uid() == 0) && mode & 0o022 == 0,
        Type::Socket => m.file_type().is_socket() && m.uid() == uid,
        Type::Daemon => m.file_type().is_socket() && daemon_owner(m.uid(), uid),
    };
    require(valid, Failure::Policy)
}

impl Handle {
    fn new(file: File, path: &Path, kind: Type, active: &Active) -> Result<Self> {
        let m = active.io(|| file.metadata())?;
        check_metadata(&m, kind)?;
        Ok(Self {
            file: Arc::new(file),
            path: path.into(),
            device: m.dev(),
            inode: m.ino(),
            kind,
        })
    }

    fn same(&self, file: &File, active: &Active) -> Result<()> {
        let m = active.io(|| file.metadata())?;
        check_metadata(&m, self.kind)?;
        require(
            m.dev() == self.device && m.ino() == self.inode,
            Failure::Integrity,
        )
    }

    fn recheck(&self, active: &Active) -> Result<()> {
        self.same(&self.file, active)?;
        let current = open(&self.path, self.kind, active)?;
        require(
            current.device == self.device && current.inode == self.inode,
            Failure::Integrity,
        )
    }
}

fn open(path: &Path, kind: Type, active: &Active) -> Result<Handle> {
    require(valid_path(path), Failure::Policy)?;
    let mut file = File::from(active.sys(|| {
        rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })?);
    let parts: Vec<_> = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    for (i, name) in parts.iter().enumerate() {
        check_metadata(&active.io(|| file.metadata())?, Type::Parent)?;
        let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        file = File::from(active.sys(|| {
            rustix::fs::openat(
                &file,
                *name,
                if i + 1 == parts.len() {
                    flags
                } else {
                    flags | OFlags::DIRECTORY
                },
                Mode::empty(),
            )
        })?);
    }
    Handle::new(file, path, kind, active)
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Checks(Vec<Handle>);
impl Checks {
    pub(crate) fn recheck(&self, active: &Active) -> Result<()> {
        for handle in &self.0 {
            handle.recheck(active)?;
        }
        active.check()
    }
}

pub(crate) fn daemon_owner(owner: u32, invoking: u32) -> bool {
    owner == invoking || owner == 0
}

pub(crate) fn daemon_socket<W: Watch>(path: &Path, active: &W) -> Result<Checks> {
    require(valid_path(path), Failure::Policy)?;
    let mut file = File::from(active.sys(|| {
        rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })?);
    let parts: Vec<_> = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    for name in parts {
        check_metadata(&active.io(|| file.metadata())?, Type::Parent)?;
        file = File::from(active.sys(|| {
            rustix::fs::openat(
                &file,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
    }
    let m = active.io(|| file.metadata())?;
    check_metadata(&m, Type::Daemon)?;
    Ok(Checks(vec![Handle {
        file: Arc::new(file),
        path: path.into(),
        device: m.dev(),
        inode: m.ino(),
        kind: Type::Daemon,
    }]))
}

pub(crate) struct DaemonCheck {
    path: PathBuf,
    checks: Option<Checks>,
}

impl DaemonCheck {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path, checks: None }
    }
    pub(crate) fn take(self) -> Option<Checks> {
        self.checks
    }
}

impl super::supervise::PublicAction for DaemonCheck {
    fn apply(&mut self, active: &Active) -> Result<()> {
        require(self.checks.is_none(), Failure::Policy)?;
        self.checks = Some(daemon_socket(&self.path, active)?);
        active.check()
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

pub(crate) struct Lease {
    pub(crate) path: PathBuf,
    parent_path: PathBuf,
    ca: Option<PathBuf>,
    sockets: Vec<PathBuf>,
    parent: Option<Handle>,
    directory: Option<Handle>,
    borrowed: Checks,
    files: Vec<Handle>,
    bytes: u64,
    attempted_directory: bool,
    unknown_file: bool,
    files_needed: bool,
}

impl Lease {
    pub(crate) fn new(
        parent: PathBuf,
        operation: &str,
        ca: Option<PathBuf>,
        sockets: Vec<PathBuf>,
        files_needed: bool,
    ) -> Result<Self> {
        require(
            valid_operation(operation) && valid_path(&parent) && sockets.len() <= 128,
            Failure::Policy,
        )?;
        for path in ca.iter().chain(&sockets) {
            require(valid_path(path), Failure::Policy)?;
        }
        Ok(Self {
            path: parent.join(operation),
            parent_path: parent,
            ca,
            sockets,
            parent: None,
            directory: None,
            borrowed: Checks::default(),
            files: Vec::new(),
            bytes: 0,
            attempted_directory: false,
            unknown_file: false,
            files_needed,
        })
    }

    pub(crate) fn residue(&self) -> bool {
        self.attempted_directory
    }

    pub(crate) fn file_path(&self, index: usize) -> PathBuf {
        self.path.join(format!("input-{index}"))
    }

    pub(crate) fn checks(&self) -> Checks {
        Checks(
            self.parent
                .iter()
                .chain(&self.directory)
                .chain(&self.files)
                .chain(&self.borrowed.0)
                .cloned()
                .collect(),
        )
    }

    fn prepare(&mut self, active: &Active) -> Result<()> {
        require(
            self.parent.is_none() && !self.attempted_directory,
            Failure::Policy,
        )?;
        if let Some(path) = &self.ca {
            self.borrowed.0.push(open(path, Type::Ca, active)?);
        }
        for path in &self.sockets {
            self.borrowed.0.push(open(path, Type::Socket, active)?);
        }
        if !self.files_needed {
            return active.check();
        }
        let parent = open(&self.parent_path, Type::Parent, active)?;
        require(
            active.sys(|| rustix::fs::fstatfs(&*parent.file))?.f_type == 0x0102_1994,
            Failure::Policy,
        )?;
        self.parent = Some(parent);
        let parent = self.parent.as_ref().ok_or(Failure::Policy)?;
        self.attempted_directory = true;
        active.sys(|| {
            rustix::fs::mkdirat(
                &*parent.file,
                self.path.file_name().ok_or(rustix::io::Errno::INVAL)?,
                Mode::from_raw_mode(0o700),
            )
        })?;
        let file = File::from(active.sys(|| {
            rustix::fs::openat(
                &*parent.file,
                self.path.file_name().ok_or(rustix::io::Errno::INVAL)?,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        self.directory = Some(Handle::new(file, &self.path, Type::Directory, active)?);
        self.checks().recheck(active)
    }

    fn materialize(&mut self, scalar: OwnedSecret, active: &Active) -> Result<()> {
        let result = self.write_scalar(&scalar, active);
        drop(scalar);
        active.after_scalar_drop();
        result
    }

    fn write_scalar(&mut self, scalar: &OwnedSecret, active: &Active) -> Result<()> {
        let size = scalar.len();
        require(
            size > 0 && size <= MAX_SCALAR && self.files.len() < MAX_FILES,
            Failure::Limit,
        )?;
        let total = self.bytes.checked_add(size as u64).ok_or(Failure::Limit)?;
        require(total <= MAX_BYTES && !self.unknown_file, Failure::Limit)?;
        self.checks().recheck(active)?;
        let directory = self.directory.as_ref().ok_or(Failure::Policy)?;
        let path = self.file_path(self.files.len());
        self.unknown_file = true;
        let mut file = File::from(active.sys(|| {
            rustix::fs::openat(
                &*directory.file,
                path.file_name().ok_or(rustix::io::Errno::INVAL)?,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
        })?);
        let handle = Handle::new(
            active.io(|| file.try_clone())?,
            &path,
            Type::Private,
            active,
        )?;
        self.files.push(handle);
        self.bytes = total;
        self.unknown_file = false;
        let mut offset = 0;
        while offset < size {
            let count = active.io(|| {
                let result = file.write(&scalar.as_str().as_bytes()[offset..]);
                active.after_write();
                result
            })?;
            require(count != 0, Failure::Storage)?;
            offset += count;
        }
        self.checks().recheck(active)
    }

    fn cleanup(&mut self, active: &Active) -> Result<()> {
        if !self.attempted_directory {
            return Ok(());
        }
        require(!self.unknown_file, Failure::Indeterminate)?;
        let parent = self.parent.as_ref().ok_or(Failure::Indeterminate)?;
        let directory = self.directory.as_ref().ok_or(Failure::Indeterminate)?;
        parent.recheck(active)?;
        directory.recheck(active)?;
        while let Some(handle) = self.files.last() {
            handle.recheck(active)?;
            active.sys(|| {
                rustix::fs::unlinkat(
                    &*directory.file,
                    handle.path.file_name().ok_or(rustix::io::Errno::INVAL)?,
                    AtFlags::empty(),
                )
            })?;
            self.files.pop();
        }
        directory.recheck(active)?;
        active.sys(|| {
            rustix::fs::unlinkat(
                &*parent.file,
                self.path.file_name().ok_or(rustix::io::Errno::INVAL)?,
                AtFlags::REMOVEDIR,
            )
        })?;
        self.attempted_directory = false;
        self.directory = None;
        self.bytes = 0;
        Ok(())
    }
}

pub(crate) enum Action {
    Prepare,
    Materialize(OwnedSecret),
    Recheck,
    Cleanup,
}
impl Action {
    pub(crate) fn apply(self, lease: &mut Lease, active: &Active) -> Result<()> {
        match self {
            Self::Prepare => lease.prepare(active),
            Self::Materialize(scalar) => lease.materialize(scalar, active),
            Self::Recheck => lease.checks().recheck(active),
            Self::Cleanup => lease.cleanup(active),
        }
    }
}
