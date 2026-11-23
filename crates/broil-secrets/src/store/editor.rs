// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Disposition, ErrorKind, Result, SetId, WriteSession,
    filesystem::{self, Target, checkpoint, io, sys},
};
use crate::{
    age::Identity,
    sops::{self, Document, Plaintext},
};
use broil_core::secret::path_safety as safe;
use rustix::fs::{self, AtFlags, Mode};
use std::{
    ffi::OsStr,
    fmt,
    fs::File,
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

struct Workspace {
    parent: File,
    directory: File,
    name: String,
    path: PathBuf,
    present: bool,
    tmpfs: bool,
}
impl Workspace {
    fn new(path: &Path) -> Result<Self> {
        Self::new_with(path, true, "broil-edit")
    }
    fn new_with(path: &Path, tmpfs: bool, prefix: &str) -> Result<Self> {
        filesystem::absolute(path)?;
        let validated =
            safe::defensive_open_directory_no_symlink(path).map_err(|_| ErrorKind::NoTmpfs)?;
        let parent = safe::reopen_for_read(&validated).map_err(|_| ErrorKind::NoTmpfs)?;
        let m = io(parent.metadata())?;
        if (tmpfs && sys(fs::fstatfs(&parent))?.f_type != 0x0102_1994)
            || !m.is_dir()
            || (m.uid() != 0 && m.uid() != safe::effective_uid())
            || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0)
        {
            return Err(ErrorKind::NoTmpfs.into());
        }
        let name = format!(
            "{prefix}-{}",
            safe::sudo_nonce().map_err(|_| ErrorKind::Randomness)?
        );
        sys(fs::mkdirat(
            &parent,
            name.as_str(),
            Mode::from_raw_mode(0o700),
        ))?;
        let directory = match filesystem::open_dir(&parent, OsStr::new(&name)) {
            Ok(directory) => directory,
            Err(mut error) => {
                error.cleanup_failed =
                    fs::unlinkat(&parent, name.as_str(), AtFlags::REMOVEDIR).is_err();
                return Err(error);
            }
        };
        let mut workspace = Self {
            parent,
            directory,
            path: path.join(&name),
            name,
            present: true,
            tmpfs,
        };
        if fs::fchmod(&workspace.directory, Mode::from_raw_mode(0o700)).is_err()
            || filesystem::directory(&workspace.directory, true).is_err()
            || workspace.current().is_err()
        {
            let cleanup_failed = workspace.cleanup().is_err();
            let mut error = super::Error::from(ErrorKind::NoTmpfs);
            error.cleanup_failed = cleanup_failed;
            return Err(error);
        }
        Ok(workspace)
    }
    fn current(&self) -> Result<()> {
        let parent = io(self.parent.metadata())?;
        if (self.tmpfs && sys(fs::fstatfs(&self.parent))?.f_type != 0x0102_1994)
            || (parent.uid() != 0 && parent.uid() != safe::effective_uid())
            || (parent.mode() & 0o022 != 0 && parent.mode() & 0o1000 == 0)
        {
            return Err(ErrorKind::UnsafePath.into());
        }
        filesystem::directory(&self.directory, true)?;
        let current =
            safe::defensive_open_directory_no_symlink(&self.path).map_err(|_| ErrorKind::Stale)?;
        if !filesystem::same_inode(&current, &self.directory)? {
            return Err(ErrorKind::Stale.into());
        }
        Ok(())
    }
    fn cleanup(&mut self) -> Result<()> {
        if !self.present {
            return Ok(());
        }
        checkpoint("editor-cleanup")?;
        let current = filesystem::open_entry(&self.parent, OsStr::new(&self.name))?
            .ok_or(ErrorKind::Stale)?;
        if !filesystem::same_inode(&current, &self.directory)? {
            return Err(ErrorKind::Stale.into());
        }
        remove_contents(&self.directory, 0, &mut 65536)?;
        let current = filesystem::open_entry(&self.parent, OsStr::new(&self.name))?
            .ok_or(ErrorKind::Stale)?;
        if !filesystem::same_inode(&current, &self.directory)? {
            return Err(ErrorKind::Stale.into());
        }
        sys(fs::unlinkat(
            &self.parent,
            self.name.as_str(),
            AtFlags::REMOVEDIR,
        ))?;
        self.present = false;
        Ok(())
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub struct PrivateTemp {
    workspace: Workspace,
    file: File,
    filename: String,
    path: PathBuf,
}
impl fmt::Debug for PrivateTemp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateTemp([REDACTED])")
    }
}
impl PrivateTemp {
    pub fn create(contents: &[u8], parents: &[&Path], fallback: Option<&Path>) -> Result<Self> {
        for (parent, tmpfs) in parents
            .iter()
            .map(|p| (*p, true))
            .chain(fallback.map(|p| (p, false)))
        {
            let mut workspace = match Workspace::new_with(parent, tmpfs, "broil-env") {
                Ok(workspace) => workspace,
                Err(error) if error.cleanup_failed => return Err(error),
                Err(_) => continue,
            };
            let setup: Result<(File, String)> = (|| {
                workspace.current()?;
                let mut temp = filesystem::Temp::new(&workspace.directory)?;
                io(temp.file.write_all(contents))?;
                io(temp.file.flush())?;
                workspace.current()?;
                let file = io(temp.file.try_clone())?;
                let filename = temp.name.clone();
                temp.keep_for_workspace();
                Ok((file, filename))
            })();
            match setup {
                Ok((file, filename)) => {
                    let path = workspace.path.join(&filename);
                    return Ok(Self {
                        workspace,
                        file,
                        filename,
                        path,
                    });
                }
                Err(mut error) => {
                    error.cleanup_failed |= workspace.cleanup().is_err();
                    if error.cleanup_failed {
                        return Err(error);
                    }
                }
            }
        }
        Err(ErrorKind::NoTmpfs.into())
    }
    pub fn path(&self) -> Result<&Path> {
        self.workspace.current()?;
        let current =
            filesystem::open_entry(&self.workspace.directory, OsStr::new(&self.filename))?
                .ok_or(ErrorKind::Stale)?;
        if !filesystem::same_inode(&current, &self.file)? {
            return Err(ErrorKind::Stale.into());
        }
        Ok(&self.path)
    }
}

fn remove_contents(directory: &File, depth: usize, remaining: &mut usize) -> Result<()> {
    if depth > 128 {
        return Err(ErrorKind::SizeLimit.into());
    }
    for name in filesystem::names(directory)? {
        *remaining = remaining.checked_sub(1).ok_or(ErrorKind::SizeLimit)?;
        let Some(entry) = filesystem::open_entry(directory, &name)? else {
            continue;
        };
        let m = io(entry.metadata())?;
        let flags = if m.is_dir() {
            let child = filesystem::open_dir(directory, &name)?;
            if !filesystem::same_inode(&entry, &child)? {
                return Err(ErrorKind::Stale.into());
            }
            remove_contents(&child, depth + 1, remaining)?;
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        let current = filesystem::open_entry(directory, &name)?.ok_or(ErrorKind::Stale)?;
        if !filesystem::same_inode(&entry, &current)? {
            return Err(ErrorKind::Stale.into());
        }
        sys(fs::unlinkat(directory, &name, flags))?;
    }
    Ok(())
}

pub struct Edit<'session, 'store> {
    session: &'session WriteSession<'store>,
    target: Target,
    document: Document,
    workspace: Workspace,
    filename: String,
}
impl fmt::Debug for Edit<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Edit([REDACTED])")
    }
}
impl<'store> WriteSession<'store> {
    pub fn edit<'session>(
        &'session self,
        id: &SetId,
        identities: &[Identity],
        xdg_runtime: Option<&Path>,
    ) -> Result<Edit<'session, 'store>> {
        let mut parents = vec![Path::new("/dev/shm")];
        if let Some(path) = xdg_runtime {
            parents.push(path);
        }
        self.edit_in(id, identities, &parents)
    }
    fn edit_in<'session>(
        &'session self,
        id: &SetId,
        identities: &[Identity],
        parents: &[&Path],
    ) -> Result<Edit<'session, 'store>> {
        let (target, document) = self.original(id.file_path(), false, identities)?;
        let plaintext = document.render_editor()?;
        let mut prepared = None;
        for parent in parents {
            let mut workspace = match Workspace::new(parent) {
                Ok(workspace) => workspace,
                Err(error) if error.cleanup_failed => return Err(error),
                Err(_) => continue,
            };
            let setup = (|| -> Result<String> {
                workspace.current()?;
                let mut file = filesystem::Temp::new(&workspace.directory)?;
                checkpoint("editor-write")?;
                io(file.file.write_all(plaintext.as_bytes()))?;
                io(file.file.flush())?;
                let name = file.name.clone();
                file.keep_for_workspace();
                Ok(name)
            })();
            match setup {
                Ok(filename) => {
                    prepared = Some((workspace, filename));
                    break;
                }
                Err(mut error) => {
                    if workspace.cleanup().is_err() {
                        error.cleanup_failed = true;
                        return Err(error);
                    }
                }
            }
        }
        drop(plaintext);
        let (workspace, filename) = prepared.ok_or(ErrorKind::NoTmpfs)?;
        Ok(Edit {
            session: self,
            target,
            document,
            workspace,
            filename,
        })
    }
}
impl Edit<'_, '_> {
    pub fn path(&self) -> PathBuf {
        self.workspace.path.join(&self.filename)
    }
    pub fn finish(mut self) -> Result<Disposition> {
        let result = (|| {
            self.workspace.current()?;
            let file =
                filesystem::open_entry(&self.workspace.directory, OsStr::new(&self.filename))?
                    .ok_or(ErrorKind::Editor)?;
            let (bytes, snapshot) = filesystem::read(&file, true)?;
            let current =
                filesystem::open_entry(&self.workspace.directory, OsStr::new(&self.filename))?
                    .ok_or(ErrorKind::Stale)?;
            let (_, actual) = filesystem::read(&current, true)?;
            if snapshot != actual {
                return Err(ErrorKind::Stale.into());
            }
            let plaintext = Plaintext::from_bytes(bytes)?;
            let candidate = sops::parse_plaintext(&plaintext)?;
            drop(plaintext);
            self.session
                .candidate(&self.target, &self.document, candidate)
        })();
        self.complete(result)
    }
    pub fn abort(mut self) -> Result<Disposition> {
        self.complete(Ok(Disposition::Unchanged))
    }
    fn complete(&mut self, result: Result<Disposition>) -> Result<Disposition> {
        match self.workspace.cleanup() {
            Ok(()) => result,
            Err(_) => match result {
                Ok(disposition) => Err(super::Error {
                    kind: ErrorKind::Editor,
                    disposition,
                    cleanup_failed: true,
                }),
                Err(mut error) => {
                    error.cleanup_failed = true;
                    Err(error)
                }
            },
        }
    }
}

