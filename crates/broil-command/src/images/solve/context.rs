// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    buffer::Bytes,
    common::*,
    files,
    supervise::{Active, Grace},
};
use super::identity;
use broil_core::secret::path_safety;
use rustix::fs::{Dir, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::File,
    io::Read,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) enum Point<'a> {
    Checked(&'a Path),
    Created(&'a Path),
    Renaming(&'a Path),
    Published(&'a Path),
    Writing(u64),
}

pub(crate) trait Watch {
    fn watch(&self) -> Result<()>;
    fn deadline(&self) -> u64 {
        u64::MAX
    }
    fn grace(&self) -> Grace {
        Grace::unbounded()
    }
    fn at(&self, _point: Point<'_>) -> Result<()> {
        Ok(())
    }
    fn io<T>(&self, call: impl FnOnce() -> std::io::Result<T>) -> Result<T> {
        self.watch()?;
        let result = call().map_err(|_| Failure::Storage);
        self.watch()?;
        result
    }
    fn sys<T>(&self, call: impl FnOnce() -> rustix::io::Result<T>) -> Result<T> {
        self.io(|| call().map_err(Into::into))
    }
}

impl Watch for Active {
    fn watch(&self) -> Result<()> {
        self.check()
    }
    fn deadline(&self) -> u64 {
        self.end()
    }
    fn grace(&self) -> Grace {
        self.cleanup_grace()
    }
}

impl Watch for Grace {
    fn watch(&self) -> Result<()> {
        self.check()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Observed {
    Context,
    Ignore,
    Budget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Refused {
    pub(crate) failure: Failure,
    pub(crate) observed: Option<Observed>,
}

fn refused(failure: Failure, observed: Observed) -> Refused {
    Refused {
        failure,
        observed: Some(observed),
    }
}

impl From<Failure> for Refused {
    fn from(failure: Failure) -> Self {
        Refused {
            failure,
            observed: match failure {
                Failure::Limit => Some(Observed::Budget),
                _ => None,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextEntry {
    pub(crate) directory: String,
    pub(crate) path: Vec<u8>,
    pub(crate) kind: &'static str,
    pub(crate) mode: u32,
    pub(crate) size: u64,
    pub(crate) target: Vec<u8>,
    pub(crate) digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IgnoreEntry {
    Absent,
    File {
        mode: u32,
        size: u64,
        digest: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContextLimits {
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ContextRequest {
    pub(crate) context: PathBuf,
    pub(crate) named: BTreeMap<String, PathBuf>,
    pub(crate) dockerfile: PathBuf,
    pub(crate) limits: ContextLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContextSnapshot {
    pub(crate) context_id: String,
    pub(crate) record: IgnoreEntry,
    pub(crate) default_ignore: IgnoreEntry,
    pub(crate) named_ignore: BTreeMap<String, IgnoreEntry>,
    pub(crate) entries: u64,
    pub(crate) bytes: u64,
}

impl ContextRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        require(
            valid_path(&self.context)
                && valid_path(&self.dockerfile)
                && self.named.len() <= 126
                && self.named.values().all(|path| valid_path(path))
                && self.limits.entries > 0
                && self.limits.entries <= 65_536
                && self.limits.bytes > 0
                && self.limits.bytes <= 4_294_967_296,
            Failure::Policy,
        )
    }
    pub(crate) fn record_path(&self) -> PathBuf {
        let mut name = self
            .dockerfile
            .file_name()
            .map(OsStr::to_os_string)
            .unwrap_or_default();
        name.push(".dockerignore");
        self.dockerfile.with_file_name(name)
    }
}

fn hex(digest: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

struct Budget {
    entries: u64,
    bytes: u64,
    limits: ContextLimits,
}

impl Budget {
    fn entry(&mut self) -> Result<()> {
        self.entries = self.entries.checked_add(1).ok_or(Failure::Limit)?;
        require(self.entries <= self.limits.entries, Failure::Limit)
    }
    fn bytes(&mut self, size: u64) -> Result<()> {
        self.bytes = self.bytes.checked_add(size).ok_or(Failure::Limit)?;
        require(self.bytes <= self.limits.bytes, Failure::Limit)
    }
}

fn hash_file<W: Watch>(watch: &W, handle: &File, size: u64, budget: &mut Budget) -> Result<String> {
    budget.bytes(size)?;
    let mut input = watch.io(|| {
        path_safety::reopen_for_read(handle)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    })?;
    let mut scratch = Bytes::new(65_536)?;
    let mut hash = Sha256::new();
    let mut used = 0u64;
    loop {
        let count = watch.io(|| input.read(scratch.get_mut()))?;
        if count == 0 {
            break;
        }
        used = used.checked_add(count as u64).ok_or(Failure::Limit)?;
        require(used <= size, Failure::Integrity)?;
        hash.update(&scratch.get()[..count]);
        scratch.clear();
    }
    require(used == size, Failure::Integrity)?;
    let mut output = hash.finalize();
    let text = hex(output.as_slice());
    output.as_mut_slice().zeroize();
    Ok(text)
}

fn open_child<W: Watch>(watch: &W, directory: &File, name: &OsStr) -> Result<File> {
    Ok(File::from(watch.io(|| {
        rustix::fs::openat(
            directory,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(Into::into)
    })?))
}

fn walk<W: Watch>(
    watch: &W,
    root: &Path,
    directory: &str,
    ignores: &[Vec<u8>],
    entries: &mut Vec<ContextEntry>,
    budget: &mut Budget,
) -> std::result::Result<IgnoreEntry, Refused> {
    let (parent, name) = path_safety::defensive_open_parent(root)
        .map_err(|_| refused(Failure::Policy, Observed::Context))?;
    let root_fd = open_child(watch, &parent, &name)?;
    if !watch.io(|| root_fd.metadata())?.is_dir() {
        return Err(refused(Failure::Policy, Observed::Context));
    }
    let mut ignore = IgnoreEntry::Absent;
    let mut pending: Vec<(File, Vec<u8>)> = vec![(root_fd, Vec::new())];
    while let Some((dir, prefix)) = pending.pop() {
        watch.watch()?;
        let readable = files::read(&dir)?;
        let iter = watch.io(|| Dir::read_from(&readable).map_err(Into::into))?;
        for item in iter {
            watch.watch()?;
            let item = item.map_err(|_| Failure::Storage)?;
            let raw = item.file_name().to_bytes();
            if matches!(raw, b"." | b"..") {
                continue;
            }
            require(
                raw.len() <= 255 && !raw.contains(&b'/') && !raw.contains(&0),
                Failure::Policy,
            )
            .map_err(|failure| refused(failure, Observed::Context))?;
            budget.entry()?;
            let name = OsStr::from_bytes(raw);
            let handle = open_child(watch, &dir, name)?;
            let metadata = watch.io(|| handle.metadata())?;
            let mut path = prefix.clone();
            if !path.is_empty() {
                path.push(b'/');
            }
            path.extend_from_slice(raw);
            let root_ignore = prefix.is_empty() && raw == b".dockerignore";
            let at_ignore = root_ignore || ignores.contains(&path);
            let observed = if at_ignore {
                Observed::Ignore
            } else {
                Observed::Context
            };
            let mode = metadata.mode() & 0o7777;
            let file_type = metadata.file_type();
            let entry = if file_type.is_symlink() {
                require(!at_ignore, Failure::Policy).map_err(|f| refused(f, observed))?;
                let target = watch
                    .io(|| rustix::fs::readlinkat(&dir, name, Vec::new()).map_err(Into::into))?;
                ContextEntry {
                    directory: directory.into(),
                    path,
                    kind: "symlink",
                    mode,
                    size: 0,
                    target: target.to_bytes().to_vec(),
                    digest: String::new(),
                }
            } else if file_type.is_dir() {
                require(!at_ignore, Failure::Policy).map_err(|f| refused(f, observed))?;
                pending.try_reserve(1).map_err(|_| Failure::Limit)?;
                pending.push((handle, path.clone()));
                ContextEntry {
                    directory: directory.into(),
                    path,
                    kind: "directory",
                    mode,
                    size: 0,
                    target: Vec::new(),
                    digest: String::new(),
                }
            } else if file_type.is_file() {
                let size = metadata.len();
                let digest = hash_file(watch, &handle, size, budget)?;
                if root_ignore {
                    ignore = IgnoreEntry::File {
                        mode,
                        size,
                        digest: digest.clone(),
                    };
                }
                ContextEntry {
                    directory: directory.into(),
                    path,
                    kind: "file",
                    mode,
                    size,
                    target: Vec::new(),
                    digest,
                }
            } else {
                return Err(refused(Failure::Policy, observed));
            };
            entries.try_reserve(1).map_err(|_| Failure::Limit)?;
            entries.push(entry);
        }
    }
    Ok(ignore)
}

fn record<W: Watch>(
    watch: &W,
    path: &Path,
    budget: &mut Budget,
) -> std::result::Result<IgnoreEntry, Refused> {
    let (parent, name) = path_safety::defensive_open_parent(path).map_err(|_| Failure::Storage)?;
    watch.watch()?;
    let opened = rustix::fs::openat(
        &parent,
        &name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    );
    watch.watch()?;
    let handle = match opened {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(IgnoreEntry::Absent),
        Err(_) => return Err(Failure::Storage.into()),
    };
    let metadata = watch.io(|| handle.metadata())?;
    require(metadata.file_type().is_file(), Failure::Policy)
        .map_err(|f| refused(f, Observed::Ignore))?;
    let size = metadata.len();
    Ok(IgnoreEntry::File {
        mode: metadata.mode() & 0o7777,
        size,
        digest: hash_file(watch, &handle, size, budget)?,
    })
}

pub(crate) fn snapshot<W: Watch>(
    watch: &W,
    request: &ContextRequest,
) -> std::result::Result<ContextSnapshot, Refused> {
    request.validate()?;
    let mut budget = Budget {
        entries: 0,
        bytes: 0,
        limits: request.limits,
    };
    let record_path = request.record_path();
    let trees: Vec<&Path> = std::iter::once(request.context.as_path())
        .chain(request.named.values().map(PathBuf::as_path))
        .collect();
    let inside = |root: &Path| -> Vec<Vec<u8>> {
        let own = root.join(".dockerignore");
        std::iter::once(record_path.clone())
            .chain(trees.iter().map(|tree| tree.join(".dockerignore")))
            .filter(|path| *path != own)
            .filter_map(|path| {
                path.strip_prefix(root)
                    .ok()
                    .map(|relative| relative.as_os_str().as_bytes().to_vec())
            })
            .collect()
    };
    let mut entries = Vec::new();
    let default_ignore = walk(
        watch,
        &request.context,
        "",
        &inside(&request.context),
        &mut entries,
        &mut budget,
    )?;
    let mut named_ignore = BTreeMap::new();
    for (name, path) in &request.named {
        let ignore = walk(watch, path, name, &inside(path), &mut entries, &mut budget)?;
        named_ignore.insert(name.clone(), ignore);
    }
    entries.sort_by(|a, b| {
        a.directory
            .as_bytes()
            .cmp(b.directory.as_bytes())
            .then_with(|| a.path.cmp(&b.path))
    });
    let record = record(watch, &record_path, &mut budget)?;
    let context_id = identity::context_id(&entries, &record)?;
    watch.watch()?;
    Ok(ContextSnapshot {
        context_id,
        record,
        default_ignore,
        named_ignore,
        entries: budget.entries,
        bytes: budget.bytes,
    })
}

pub(crate) struct SnapshotWork {
    request: ContextRequest,
    result: Option<ContextSnapshot>,
    refused: Option<Refused>,
}

impl SnapshotWork {
    pub(crate) fn new(request: ContextRequest) -> Result<Self> {
        request.validate()?;
        Ok(Self {
            request,
            result: None,
            refused: None,
        })
    }
    pub(crate) fn take(self) -> (Option<ContextSnapshot>, Option<Refused>) {
        (self.result, self.refused)
    }
    pub(crate) fn apply<W: Watch>(&mut self, watch: &W) -> Result<()> {
        require(self.result.is_none(), Failure::Policy)?;
        match snapshot(watch, &self.request) {
            Ok(snapshot) => {
                self.result = Some(snapshot);
                Ok(())
            }
            Err(refused) => {
                self.refused = Some(refused);
                Err(refused.failure)
            }
        }
    }
}
