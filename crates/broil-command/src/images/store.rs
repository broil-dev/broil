// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{common::*, supervise::Active};
use broil_core::secret::path_safety::effective_uid;
use rustix::fs::{Mode, OFlags, RenameFlags};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

pub(crate) type ReadBytes = Option<(Vec<u8>, (u64, u64))>;

pub(crate) fn identity(file: &File, active: &Active) -> Result<(u64, u64)> {
    let m = active.io(|| file.metadata())?;
    Ok((m.dev(), m.ino()))
}

pub(crate) fn owned(file: &File, directory: bool, active: &Active) -> Result<()> {
    let m = active.io(|| file.metadata())?;
    require(
        m.uid() == effective_uid()
            && m.mode() & 0o7777 == if directory { 0o700 } else { 0o600 }
            && if directory {
                m.is_dir()
            } else {
                m.is_file() && m.nlink() == 1
            },
        Failure::Integrity,
    )
}

pub(crate) fn open_directory(path: &Path, active: &Active) -> Result<File> {
    require(valid_path(path), Failure::Policy)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut file = File::from(active.sys(|| rustix::fs::open("/", flags, Mode::empty()))?);
    for part in path.components() {
        if let Component::Normal(name) = part {
            let m = active.io(|| file.metadata())?;
            require(
                (m.uid() == 0 || m.uid() == effective_uid())
                    && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0),
                Failure::Policy,
            )?;
            file =
                File::from(active.sys(|| rustix::fs::openat(&file, name, flags, Mode::empty()))?);
        }
    }
    Ok(file)
}

pub(crate) fn state_directory(root: &Path, create: bool, active: &Active) -> Result<File> {
    let root = open_directory(root, active)?;
    child_directory(&root, "state", create, active)
}

pub(crate) fn child_directory(
    parent: &File,
    name: &str,
    create: bool,
    active: &Active,
) -> Result<File> {
    if create {
        active.check()?;
        match rustix::fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(Failure::Storage),
        }
        active.check()?;
    }
    let file = File::from(active.sys(|| {
        rustix::fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })?);
    owned(&file, true, active)?;
    Ok(file)
}

pub(crate) fn existing_child_directory(
    parent: &File,
    name: &str,
    active: &Active,
) -> Result<Option<File>> {
    active.check()?;
    let opened = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    );
    active.check()?;
    let file = match opened {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(Failure::Storage),
    };
    owned(&file, true, active)?;
    Ok(Some(file))
}

pub(crate) fn read(directory: &File, name: &str, limit: u64, active: &Active) -> Result<ReadBytes> {
    active.check()?;
    let opened = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    );
    active.check()?;
    let mut file = match opened {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(Failure::Storage),
    };
    owned(&file, false, active)?;
    let size = active.io(|| file.metadata())?.len();
    require(size <= limit, Failure::Limit)?;
    let mut bytes = vec![0; size as usize];
    active.io(|| file.read_exact(&mut bytes))?;
    let mut extra = [0];
    require(
        active.io(|| file.read(&mut extra))? == 0,
        Failure::Integrity,
    )?;
    let identity = identity(&file, active)?;
    Ok(Some((bytes, identity)))
}

pub(crate) struct Prepared {
    file: File,
    temporary: String,
}

pub(crate) fn prepare(
    directory: &File,
    temporary: String,
    bytes: &[u8],
    active: &Active,
) -> Result<Prepared> {
    let mut file = File::from(active.sys(|| {
        rustix::fs::openat(
            directory,
            temporary.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
    })?);
    owned(&file, false, active)?;
    active.io(|| file.write_all(bytes))?;
    active.io(|| file.sync_all())?;
    Ok(Prepared { file, temporary })
}

pub(crate) fn publish(
    directory: &File,
    prepared: Prepared,
    name: &str,
    expected: Option<(u64, u64)>,
    active: &Active,
) -> Result<(u64, u64)> {
    let Prepared { file, temporary } = prepared;
    if let Some(expected) = expected {
        let old = File::from(active.sys(|| {
            rustix::fs::openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        owned(&old, false, active)?;
        require(identity(&old, active)? == expected, Failure::Integrity)?;
        active.sys(|| rustix::fs::renameat(directory, temporary.as_str(), directory, name))?;
    } else {
        active.sys(|| {
            rustix::fs::renameat_with(
                directory,
                temporary.as_str(),
                directory,
                name,
                RenameFlags::NOREPLACE,
            )
        })?;
    }
    identity(&file, active)
}

pub(crate) fn sync_parent(directory: &File, active: &Active) -> Result<()> {
    active.io(|| directory.sync_all())
}

pub(crate) fn publish_new(
    directory: &File,
    prepared: Prepared,
    name: &str,
    active: &Active,
) -> Result<Option<(u64, u64)>> {
    let Prepared { file, temporary } = prepared;
    active.check()?;
    let renamed = rustix::fs::renameat_with(
        directory,
        temporary.as_str(),
        directory,
        name,
        RenameFlags::NOREPLACE,
    );
    active.check()?;
    match renamed {
        Ok(()) => Ok(Some(identity(&file, active)?)),
        Err(rustix::io::Errno::EXIST) => Ok(None),
        Err(_) => Err(Failure::Storage),
    }
}

pub(crate) fn scan(
    directory: &File,
    mut in_domain: impl FnMut(&str) -> bool,
    active: &Active,
) -> Result<Vec<String>> {
    active.check()?;
    let mut names = Vec::new();
    let handle = active.io(|| directory.try_clone())?;
    for entry in rustix::fs::Dir::read_from(&handle).map_err(|_| Failure::Storage)? {
        active.check()?;
        let entry = entry.map_err(|_| Failure::Storage)?;
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if in_domain(name) {
            names.try_reserve(1).map_err(|_| Failure::Limit)?;
            names.push(name.to_owned());
        }
    }
    Ok(names)
}
