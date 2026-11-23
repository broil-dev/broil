// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Disposition, Error, ErrorKind, Result, Store};
use broil_core::secret::path_safety as safe;
use rustix::fs::{self, AtFlags, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, Metadata},
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(super) fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|_| ErrorKind::Io.into())
}
pub(super) fn sys<T>(result: rustix::io::Result<T>) -> Result<T> {
    result.map_err(|_| ErrorKind::UnsafePath.into())
}

#[derive(PartialEq, Eq)]
pub(super) struct Stamp {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Stamp {
    fn of(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            size: m.size(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

pub(super) fn same_inode(a: &File, b: &File) -> Result<bool> {
    let a = io(a.metadata())?;
    let b = io(b.metadata())?;
    Ok(a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mode() == b.mode())
}

pub(super) fn directory(file: &File, private: bool) -> Result<()> {
    let m = io(file.metadata())?;
    if !m.is_dir()
        || (m.uid() != safe::effective_uid() && m.uid() != 0)
        || (private && (m.uid() != safe::effective_uid() || m.mode() & 0o777 != 0o700))
    {
        return Err(ErrorKind::UnsafePath.into());
    }
    Ok(())
}

pub(super) fn open_entry(parent: &File, name: &OsStr) -> Result<Option<File>> {
    match fs::openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(ErrorKind::UnsafePath.into()),
    }
}

pub(super) fn open_dir(parent: &File, name: &OsStr) -> Result<File> {
    let file = File::from(sys(fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ))?);
    directory(&file, false)?;
    Ok(file)
}

pub(super) fn names(directory: &File) -> Result<Vec<OsString>> {
    let mut output = Vec::new();
    for entry in sys(fs::Dir::read_from(directory))? {
        let entry = sys(entry)?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        if output.len() == 65536 {
            return Err(ErrorKind::SizeLimit.into());
        }
        output.push(OsStr::from_bytes(name).to_owned());
    }
    output.sort();
    Ok(output)
}

#[derive(PartialEq, Eq)]
pub(super) struct Snapshot {
    stamp: Stamp,
    digest: [u8; 32],
}

pub(super) fn read(file: &File, private: bool) -> Result<(Zeroizing<Vec<u8>>, Snapshot)> {
    safe::recheck_open_metadata(file, !private).map_err(|_| ErrorKind::UnsafePath)?;
    let before = io(file.metadata())?;
    let size = usize::try_from(before.len()).map_err(|_| ErrorKind::SizeLimit)?;
    if size > crate::sops::MAX_DOCUMENT_BYTES {
        return Err(ErrorKind::SizeLimit.into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(size)
        .map_err(|_| ErrorKind::Allocation)?;
    bytes.resize(size, 0);
    let mut reader = safe::reopen_for_read(file).map_err(|_| ErrorKind::UnsafePath)?;
    io(reader.read_exact(&mut bytes))?;
    let mut extra = Zeroizing::new([0u8; 1]);
    if io(reader.read(&mut *extra))? != 0 {
        return Err(ErrorKind::Stale.into());
    }
    let stamp = Stamp::of(&before);
    if stamp != Stamp::of(&io(reader.metadata())?) {
        return Err(ErrorKind::Stale.into());
    }
    let digest = Sha256::digest(&*bytes).into();
    Ok((bytes, Snapshot { stamp, digest }))
}

pub(super) struct Target {
    pub path: String,
    pub parent: File,
    pub name: OsString,
    pub private: bool,
    pub original: Option<Snapshot>,
}

impl Store {
    pub(super) fn root_current(&self) -> Result<()> {
        let current =
            safe::defensive_open_directory_no_symlink(&self.root).map_err(|_| ErrorKind::Stale)?;
        directory(&current, false)?;
        if !same_inode(&current, &self.directory)? {
            return Err(ErrorKind::Stale.into());
        }
        Ok(())
    }

    pub(super) fn parent(&self, relative: &str, create: bool) -> Result<(File, OsString)> {
        self.root_current()?;
        let mut parts = relative.split('/').collect::<Vec<_>>();
        let name = parts.pop().ok_or(ErrorKind::InvalidName)?;
        let mut parent =
            safe::reopen_for_read(&self.directory).map_err(|_| ErrorKind::UnsafePath)?;
        for part in parts {
            if create && open_entry(&parent, OsStr::new(part))?.is_none() {
                sys(fs::mkdirat(&parent, part, Mode::from_raw_mode(0o700)))?;
                if parent.sync_all().is_err() {
                    return Err(Error {
                        kind: ErrorKind::Io,
                        disposition: Disposition::MayHaveChanged,
                        cleanup_failed: false,
                    });
                }
            }
            parent = open_dir(&parent, OsStr::new(part))?;
        }
        Ok((parent, name.into()))
    }

    pub(super) fn target(
        &self,
        path: String,
        private: bool,
        create_parents: bool,
    ) -> Result<Target> {
        let (parent, name) = self.parent(&path, create_parents)?;
        Ok(Target {
            path,
            parent,
            name,
            private,
            original: None,
        })
    }
}

impl Target {
    pub fn load_bytes(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        let file = open_entry(&self.parent, &self.name)?.ok_or(ErrorKind::Missing)?;
        let (bytes, snapshot) = read(&file, self.private)?;
        self.original = Some(snapshot);
        Ok(bytes)
    }
    pub fn load(&mut self) -> Result<crate::sops::Plaintext> {
        Ok(crate::sops::Plaintext::from_bytes(self.load_bytes()?)?)
    }
    pub fn fresh(&self, store: &Store) -> Result<()> {
        let (parent, _) = store.parent(&self.path, false)?;
        if !same_inode(&parent, &self.parent)? {
            return Err(ErrorKind::Stale.into());
        }
        let file = open_entry(&parent, &self.name)?;
        match (&self.original, file) {
            (None, None) => Ok(()),
            (Some(expected), Some(file)) => {
                let (_, actual) = read(&file, self.private)?;
                if *expected == actual {
                    Ok(())
                } else {
                    Err(ErrorKind::Stale.into())
                }
            }
            _ => Err(ErrorKind::Stale.into()),
        }
    }
}

pub(super) fn checkpoint(stage: &'static str) -> Result<()> {

    let _ = stage;
    Ok(())
}

pub(super) struct Temp<'a> {
    pub parent: &'a File,
    pub name: String,
    pub file: File,
    present: bool,
}
impl<'a> Temp<'a> {
    pub fn keep_for_workspace(&mut self) {
        self.present = false;
    }
    pub fn new(parent: &'a File) -> Result<Self> {
        let name = format!(
            ".broil-{}",
            safe::sudo_nonce().map_err(|_| ErrorKind::Randomness)?
        );
        let file = File::from(sys(fs::openat(
            parent,
            name.as_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ))?);
        let mut temp = Self {
            parent,
            name,
            file,
            present: true,
        };
        if fs::fchmod(&temp.file, Mode::from_raw_mode(0o600)).is_err() {
            let cleanup_failed = temp.cleanup().is_err();
            return Err(Error {
                kind: ErrorKind::Io,
                disposition: Disposition::Unchanged,
                cleanup_failed,
            });
        }
        Ok(temp)
    }
    pub fn cleanup(&mut self) -> Result<()> {
        if !self.present {
            return Ok(());
        }
        checkpoint("cleanup")?;
        match open_entry(self.parent, OsStr::new(&self.name))? {
            None => {}
            Some(file) if same_inode(&file, &self.file)? => {
                sys(fs::unlinkat(
                    self.parent,
                    self.name.as_str(),
                    AtFlags::empty(),
                ))?;
            }
            Some(_) => return Err(ErrorKind::Stale.into()),
        }
        self.present = false;
        Ok(())
    }
}
impl Drop for Temp<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub(super) fn replace(
    store: &Store,
    target: &Target,
    encoded: &crate::sops::Plaintext,
    rule: Option<&Target>,
) -> Result<Disposition> {
    replace_bytes(store, target, encoded.as_bytes(), rule)
}

pub(super) fn replace_bytes(
    store: &Store,
    target: &Target,
    encoded: &[u8],
    rule: Option<&Target>,
) -> Result<Disposition> {
    replace_observed(store, target, encoded, rule, &mut None)
}

pub(super) fn replace_observed(
    store: &Store,
    target: &Target,
    encoded: &[u8],
    rule: Option<&Target>,
    installed: &mut Option<Snapshot>,
) -> Result<Disposition> {
    target.fresh(store)?;
    if let Some(rule) = rule {
        rule.fresh(store)?;
    }
    let mut temp = Temp::new(&target.parent)?;
    let mut renamed = false;
    let result = (|| {
        checkpoint("write")?;
        io(temp.file.write_all(encoded))?;
        checkpoint("flush")?;
        io(temp.file.flush())?;
        checkpoint("file-sync")?;
        io(temp.file.sync_all())?;
        checkpoint("before-rename")?;
        target.fresh(store)?;
        if let Some(rule) = rule {
            rule.fresh(store)?;
        }
        if !open_entry(&target.parent, OsStr::new(&temp.name))?
            .is_some_and(|file| same_inode(&file, &temp.file).unwrap_or(false))
        {
            return Err(ErrorKind::Stale.into());
        }
        checkpoint("rename")?;
        let (_, snapshot) = read(&temp.file, target.private)?;
        sys(fs::renameat_with(
            &target.parent,
            temp.name.as_str(),
            &target.parent,
            &target.name,
            if target.original.is_none() {
                RenameFlags::NOREPLACE
            } else {
                RenameFlags::empty()
            },
        ))?;
        renamed = true;
        checkpoint("installed-metadata")?;
        let mut snapshot = snapshot;
        snapshot.stamp = Stamp::of(&io(temp.file.metadata())?);
        *installed = Some(snapshot);
        temp.present = false;
        checkpoint("directory-sync")?;
        io(target.parent.sync_all())?;
        Ok(Disposition::Changed)
    })();
    result.map_err(|mut error: Error| {
        if renamed {
            error.disposition = Disposition::MayHaveChanged;
        }
        error.cleanup_failed |= temp.cleanup().is_err();
        error
    })
}

pub(super) struct DirectoryPlan {
    path: PathBuf,
    ancestor: PathBuf,
    directory: File,
    identity: (u64, u64, u32, u32, u32),
    missing: Vec<OsString>,
}
impl DirectoryPlan {
    pub fn fresh_with_created(
        &self,
        created: &std::collections::BTreeMap<PathBuf, File>,
    ) -> Result<()> {
        let current = safe::defensive_open_directory_no_symlink(&self.ancestor)
            .map_err(|_| ErrorKind::Stale)?;
        if !same_inode(&current, &self.directory)? {
            return Err(ErrorKind::Stale.into());
        }
        let mut path = self.ancestor.clone();
        for part in &self.missing {
            path.push(part);
            if let Some(expected) = created.get(&path) {
                let current = safe::defensive_open_directory_no_symlink(&path)
                    .map_err(|_| ErrorKind::Stale)?;
                if !same_inode(&current, expected)? {
                    return Err(ErrorKind::Stale.into());
                }
            } else {
                let parent = safe::defensive_open_directory_no_symlink(
                    path.parent().ok_or(ErrorKind::Stale)?,
                )
                .map_err(|_| ErrorKind::Stale)?;
                if open_entry(&parent, part)?.is_some() {
                    return Err(ErrorKind::Stale.into());
                }
                break;
            }
        }
        Ok(())
    }
    pub fn inspect(path: &Path) -> Result<Self> {
        absolute(path)?;
        let root = safe::defensive_open_directory_no_symlink(Path::new("/"))
            .map_err(|_| ErrorKind::UnsafePath)?;
        let mut directory = safe::reopen_for_read(&root).map_err(|_| ErrorKind::UnsafePath)?;
        let mut ancestor = PathBuf::from("/");
        let mut missing = Vec::new();
        for part in path.components().filter_map(|p| match p {
            std::path::Component::Normal(p) => Some(p),
            _ => None,
        }) {
            if missing.is_empty() && open_entry(&directory, part)?.is_some() {
                directory = open_dir(&directory, part)?;
                Self::safe_parent(&directory)?;
                ancestor.push(part);
            } else {
                missing.push(part.to_owned());
            }
        }
        let metadata = io(directory.metadata())?;
        let identity = (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
        );
        let plan = Self {
            path: path.into(),
            ancestor,
            directory,
            identity,
            missing,
        };
        plan.fresh()?;
        Ok(plan)
    }
    fn safe_parent(file: &File) -> Result<()> {
        directory(file, false)
    }
    pub fn exists(&self) -> bool {
        self.missing.is_empty()
    }
    pub fn fresh(&self) -> Result<()> {
        let current = safe::defensive_open_directory_no_symlink(&self.ancestor)
            .map_err(|_| ErrorKind::Stale)?;
        Self::safe_parent(&current)?;
        let metadata = io(current.metadata())?;
        if (
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
        ) != self.identity
        {
            return Err(ErrorKind::Stale.into());
        }
        if !same_inode(&current, &self.directory)? {
            return Err(ErrorKind::Stale.into());
        }
        if let Some(first) = self.missing.first() {
            if open_entry(&self.directory, first)?.is_some() {
                return Err(ErrorKind::Stale.into());
            }
        }
        Ok(())
    }
    pub fn existing(&self) -> Option<&File> {
        self.exists().then_some(&self.directory)
    }
    pub fn create(&self, mut created: impl FnMut(&Path)) -> Result<File> {
        self.fresh()?;
        let mut directory =
            safe::reopen_for_read(&self.directory).map_err(|_| ErrorKind::UnsafePath)?;
        let mut path = self.ancestor.clone();
        for part in &self.missing {
            let pinned =
                safe::defensive_open_directory_no_symlink(&path).map_err(|_| ErrorKind::Stale)?;
            if !same_inode(&pinned, &directory)? {
                return Err(ErrorKind::Stale.into());
            }
            checkpoint("create-directory")?;
            sys(fs::mkdirat(&directory, part, Mode::from_raw_mode(0o700)))?;
            path.push(part);
            created(&path);
            let result = (|| {
                let child = open_dir(&directory, part)?;
                sys(fs::fchmod(&child, Mode::from_raw_mode(0o700)))?;
                self::directory(&child, true)?;
                checkpoint("created-directory-sync")?;
                io(directory.sync_all())?;
                let current = safe::defensive_open_directory_no_symlink(&path)
                    .map_err(|_| ErrorKind::Stale)?;
                if !same_inode(&current, &child)? {
                    return Err(ErrorKind::Stale.into());
                }
                Ok(child)
            })();
            directory = result.map_err(|mut error: Error| {
                error.disposition = Disposition::MayHaveChanged;
                error
            })?;
        }
        let current =
            safe::defensive_open_directory_no_symlink(&self.path).map_err(|_| ErrorKind::Stale)?;
        if !same_inode(&current, &directory)? {
            return Err(ErrorKind::Stale.into());
        }
        Ok(directory)
    }
}

pub(super) fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|c| {
            !matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(ErrorKind::UnsafePath.into());
    }
    Ok(())
}
