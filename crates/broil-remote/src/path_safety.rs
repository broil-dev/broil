// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use rustix::fs::{Mode, OFlags};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityError {
    UnsafePath,
    ForeignOwner,
    LoosePermissions,
    Randomness,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafePathEntryType {
    RegularFile,
    Directory,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafePathFinal {
    Existing(SafePathEntryType),
    Absent,
}

pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub fn random_bytes(buffer: &mut [u8]) -> Result<(), CapabilityError> {
    getrandom::fill(buffer).map_err(|_| CapabilityError::Randomness)
}

pub fn sudo_nonce() -> Result<String, CapabilityError> {
    let mut raw = [0u8; 16];
    random_bytes(&mut raw)?;
    Ok(raw.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn defensive_open(path: &Path, allow_group_other: bool) -> Result<File, CapabilityError> {
    let validated = defensive_open_validated(path, allow_group_other)?;
    reopen_for_read(&validated)
}

pub fn defensive_open_regular_no_symlink(path: &Path) -> Result<File, CapabilityError> {
    let descriptor = defensive_open_path(path)?;
    if classify_open_descriptor(&descriptor)? != SafePathEntryType::RegularFile {
        return Err(CapabilityError::UnsafePath);
    }
    reopen_for_read(&descriptor)
}

pub fn defensive_open_directory_no_symlink(path: &Path) -> Result<File, CapabilityError> {
    let descriptor = defensive_open_path(path)?;
    if classify_open_descriptor(&descriptor)? != SafePathEntryType::Directory {
        return Err(CapabilityError::UnsafePath);
    }
    Ok(descriptor)
}

pub fn defensive_open_parent(path: &Path) -> Result<(File, OsString), CapabilityError> {
    if !path.is_absolute() {
        return Err(CapabilityError::UnsafePath);
    }
    let name = path
        .file_name()
        .map(OsStr::to_os_string)
        .ok_or(CapabilityError::UnsafePath)?;
    let parent = path.parent().ok_or(CapabilityError::UnsafePath)?;
    let mut dir = rustix::fs::open(
        Path::new("/"),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CapabilityError::UnsafePath)?;
    for component in parent.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                dir = rustix::fs::openat(
                    &dir,
                    part,
                    OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CapabilityError::UnsafePath)?;
            }
            _ => return Err(CapabilityError::UnsafePath),
        }
    }
    Ok((File::from(dir), name))
}

pub fn defensive_classify(path: &Path) -> Result<SafePathEntryType, CapabilityError> {
    let descriptor = defensive_open_path(path)?;
    classify_open_descriptor(&descriptor)
}

pub fn defensive_classify_or_absent_final(path: &Path) -> Result<SafePathFinal, CapabilityError> {
    match defensive_open_path(path) {
        Ok(descriptor) => classify_open_descriptor(&descriptor).map(SafePathFinal::Existing),
        Err(CapabilityError::UnsafePath) => {
            let (parent, name) = defensive_open_parent(path)?;
            match rustix::fs::openat(
                &parent,
                &name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(descriptor) => {
                    let descriptor = File::from(descriptor);
                    classify_open_descriptor(&descriptor).map(SafePathFinal::Existing)
                }
                Err(rustix::io::Errno::NOENT) => Ok(SafePathFinal::Absent),
                Err(_) => Err(CapabilityError::UnsafePath),
            }
        }
        Err(error) => Err(error),
    }
}

pub fn defensive_open_validated(
    path: &Path,
    allow_group_other: bool,
) -> Result<File, CapabilityError> {
    let descriptor = defensive_open_path(path)?;
    recheck_open_metadata(&descriptor, allow_group_other)?;
    Ok(descriptor)
}

fn defensive_open_path(path: &Path) -> Result<File, CapabilityError> {
    if !path.is_absolute() {
        return Err(CapabilityError::UnsafePath);
    }
    let mut dir = rustix::fs::open(
        Path::new("/"),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CapabilityError::UnsafePath)?;
    let mut components: Vec<&OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => components.push(part),
            _ => return Err(CapabilityError::UnsafePath),
        }
    }
    for (index, part) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let flags = if last {
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC
        } else {
            OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
        };
        dir = rustix::fs::openat(&dir, *part, flags, Mode::empty())
            .map_err(|_| CapabilityError::UnsafePath)?;
    }
    Ok(File::from(dir))
}

fn classify_open_descriptor(file: &File) -> Result<SafePathEntryType, CapabilityError> {
    let metadata = file.metadata().map_err(|_| CapabilityError::UnsafePath)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(CapabilityError::UnsafePath);
    }
    if file_type.is_file() {
        Ok(SafePathEntryType::RegularFile)
    } else if file_type.is_dir() {
        Ok(SafePathEntryType::Directory)
    } else {
        Ok(SafePathEntryType::Other)
    }
}

pub fn reopen_for_read(validated: &File) -> Result<File, CapabilityError> {
    File::open(format!("/proc/self/fd/{}", validated.as_raw_fd()))
        .map_err(|_| CapabilityError::UnsafePath)
}

pub fn recheck_open_metadata(file: &File, allow_group_other: bool) -> Result<(), CapabilityError> {
    let metadata = file.metadata().map_err(|_| CapabilityError::UnsafePath)?;
    if !metadata.is_file() {
        return Err(CapabilityError::UnsafePath);
    }
    if metadata.uid() != effective_uid() && metadata.uid() != 0 {
        return Err(CapabilityError::ForeignOwner);
    }
    if !allow_group_other && metadata.mode() & 0o077 != 0 {
        return Err(CapabilityError::LoosePermissions);
    }
    Ok(())
}

pub struct EchoGuard<Fd: AsFd> {
    fd: Fd,
    original: rustix::termios::Termios,
    restored: bool,
}

impl<Fd: AsFd> EchoGuard<Fd> {
    pub fn disable_echo(fd: Fd) -> Result<Self, CapabilityError> {
        let original =
            rustix::termios::tcgetattr(fd.as_fd()).map_err(|_| CapabilityError::Terminal)?;
        let mut updated = original.clone();
        updated
            .local_modes
            .remove(rustix::termios::LocalModes::ECHO);
        rustix::termios::tcsetattr(
            fd.as_fd(),
            rustix::termios::OptionalActions::Flush,
            &updated,
        )
        .map_err(|_| CapabilityError::Terminal)?;
        Ok(Self {
            fd,
            original,
            restored: false,
        })
    }

    pub fn echo_enabled(&self) -> Result<bool, CapabilityError> {
        let current =
            rustix::termios::tcgetattr(self.fd.as_fd()).map_err(|_| CapabilityError::Terminal)?;
        Ok(current
            .local_modes
            .contains(rustix::termios::LocalModes::ECHO))
    }

    pub fn restore(&mut self) -> Result<(), CapabilityError> {
        if !self.restored {
            rustix::termios::tcsetattr(
                self.fd.as_fd(),
                rustix::termios::OptionalActions::Flush,
                &self.original,
            )
            .map_err(|_| CapabilityError::Terminal)?;
            self.restored = true;
        }
        Ok(())
    }
}

impl<Fd: AsFd> Drop for EchoGuard<Fd> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    match rustix::fs::flock(
        file.as_fd(),
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    ) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
        Err(error) => Err(error.into()),
    }
}
