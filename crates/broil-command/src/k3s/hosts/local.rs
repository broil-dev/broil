// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, require};
use rustix::fs::{Mode, OFlags};
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

pub(crate) struct Held {
    pub file: File,
    pub identity: [u64; 2],
    pub size: u64,
}

fn trusted(directory: &File) -> Result<()> {
    let metadata = directory.metadata().map_err(|_| Failure::Storage)?;
    require(
        metadata.is_dir()
            && (metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw())
            && metadata.mode() & 0o022 == 0,
        Failure::Configuration,
    )
}

pub(crate) fn open(root: &Path, path: &Path, limit: u64) -> Result<Held> {
    require(
        root.is_absolute() && path.is_absolute(),
        Failure::Configuration,
    )?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Failure::Configuration)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(
        rustix::fs::open(root, directory_flags, Mode::empty()).map_err(|_| Failure::Storage)?,
    );
    trusted(&directory)?;
    let mut components = relative.components().peekable();
    let mut leaf = None;
    while let Some(component) = components.next() {
        let Component::Normal(name) = component else {
            return Err(Failure::Configuration);
        };
        if components.peek().is_none() {
            leaf = Some(name);
            break;
        }
        directory = File::from(
            rustix::fs::openat(&directory, name, directory_flags, Mode::empty())
                .map_err(|_| Failure::Storage)?,
        );
        trusted(&directory)?;
    }
    let name = leaf.ok_or(Failure::Configuration)?;
    let file = File::from(
        rustix::fs::openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Failure::Storage)?,
    );
    let metadata = file.metadata().map_err(|_| Failure::Storage)?;
    require(
        metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= limit,
        Failure::Configuration,
    )?;
    Ok(Held {
        identity: [metadata.dev(), metadata.ino()],
        size: metadata.len(),
        file,
    })
}

impl Held {
    pub(crate) fn recheck(&self) -> Result<()> {
        let metadata = self.file.metadata().map_err(|_| Failure::Storage)?;
        require(
            metadata.is_file()
                && metadata.nlink() == 1
                && [metadata.dev(), metadata.ino()] == self.identity
                && metadata.len() == self.size,
            Failure::Integrity,
        )
    }

    pub(crate) fn read_all(&self) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.size as usize + 1)
            .map_err(|_| Failure::Bound)?;
        (&self.file)
            .take(self.size + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Storage)?;
        require(bytes.len() as u64 == self.size, Failure::Integrity)?;
        self.recheck()?;
        Ok(bytes)
    }
}
