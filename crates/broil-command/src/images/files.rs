// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Blocking filesystem work. Called only in a filesystem child or public launch task.

use broil_core::secret::path_safety;
use rustix::fs::{AtFlags, Dir, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};
use zeroize::Zeroize;

use super::buffer::Bytes;
use super::common::*;

pub(crate) fn identity(
    file: &File,
    path: &Path,
    ownership: Ownership,
    tool: bool,
) -> Result<Entry> {
    require(valid_path(path), Failure::Policy)?;
    let metadata = file.metadata().map_err(|_| Failure::Storage)?;
    let kind = if metadata.is_file() {
        Kind::File
    } else {
        require(metadata.is_dir(), Failure::Policy)?;
        Kind::Directory
    };
    require(
        metadata.uid() == path_safety::effective_uid() || (tool && metadata.uid() == 0),
        Failure::Policy,
    )?;
    if tool {
        require(
            metadata.mode() & 0o022 == 0 && metadata.mode() & 0o111 != 0,
            Failure::Policy,
        )?;
    }
    Ok(Entry {
        path: path.into(),
        device: metadata.dev(),
        inode: metadata.ino(),
        kind,
        ownership,
    })
}

pub(crate) fn open_path(path: &Path, ownership: Ownership, tool: bool) -> Result<(File, Entry)> {
    require(valid_path(path), Failure::Policy)?;
    let (parent, name) = path_safety::defensive_open_parent(path).map_err(|_| Failure::Policy)?;
    let file = File::from(
        rustix::fs::openat(
            &parent,
            &name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Failure::Storage)?,
    );
    let entry = identity(&file, path, ownership, tool)?;
    Ok((file, entry))
}

pub(crate) fn open(entry: &Entry, tool: bool) -> Result<File> {
    let (file, actual) = open_path(&entry.path, entry.ownership, tool)?;
    require(actual == *entry, Failure::Integrity)?;
    Ok(file)
}

pub(crate) fn read(file: &File) -> Result<File> {
    path_safety::reopen_for_read(file).map_err(|_| Failure::Storage)
}

pub(crate) fn private_directory(entry: &Entry) -> Result<File> {
    require(entry.kind == Kind::Directory, Failure::Policy)?;
    let file = open(entry, false)?;
    require(
        file.metadata().map_err(|_| Failure::Storage)?.mode() & 0o777 == 0o700,
        Failure::Policy,
    )?;
    Ok(file)
}

pub(crate) fn child(parent: &File, path: &Path, ownership: Ownership) -> Result<(File, Entry)> {
    let name = path.file_name().ok_or(Failure::Policy)?;
    let file = File::from(
        rustix::fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Failure::Storage)?,
    );
    let entry = identity(&file, path, ownership, false)?;
    Ok((file, entry))
}

pub(crate) fn mkdir(parent: &File, path: &Path) -> Result<(File, Entry)> {
    let name = path.file_name().ok_or(Failure::Policy)?;
    rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(0o700)).map_err(|_| Failure::Storage)?;
    let (file, entry) = child(parent, path, Ownership::Operation)?;
    require(
        entry.kind == Kind::Directory
            && file.metadata().map_err(|_| Failure::Storage)?.mode() & 0o777 == 0o700,
        Failure::Policy,
    )?;
    Ok((file, entry))
}

pub(crate) const DIRECTORIES: &[&str] = &[
    "home",
    "docker",
    "buildx",
    "plugins",
    "xdg",
    "xdg/config",
    "xdg/cache",
    "xdg/data",
    "xdg/state",
    "xdg/runtime",
    "tmp",
    "tools",
    "staging",
];

pub(crate) fn prepare(parent: &Entry, path: &Path, end: u64) -> Result<(Entry, Vec<Entry>)> {
    before(end)?;
    require(
        parent.ownership == Ownership::Borrowed && path.parent() == Some(parent.path.as_path()),
        Failure::Policy,
    )?;
    let parent_fd = private_directory(parent)?;
    let (workspace_fd, workspace) = mkdir(&parent_fd, path)?;
    let mut directories = Vec::new();
    for name in DIRECTORIES {
        before(end)?;
        let destination = path.join(name);
        let (parent_fd, _) = if name.starts_with("xdg/") {
            child(&workspace_fd, &path.join("xdg"), Ownership::Operation)?
        } else {
            (
                workspace_fd.try_clone().map_err(|_| Failure::Storage)?,
                workspace.clone(),
            )
        };
        let (_, entry) = mkdir(&parent_fd, &destination)?;
        directories.push(entry);
    }
    open(&workspace, false)?;
    Ok((workspace, directories))
}

pub(crate) struct Node {
    pub entry: Entry,
    parent: File,
    parent_entry: Entry,
    name: OsString,
}

pub(crate) struct Scan {
    pub bytes: u64,
    pub entries: u64,
    pub nodes: Vec<Node>,
}

pub(crate) fn scan(
    root: &Entry,
    limits: &ContentLimits,
    end: u64,
    preserve: &[Entry],
) -> Result<Scan> {
    before(end)?;
    let root_fd = private_directory(root)?;
    let mut pending = vec![(root_fd, root.clone())];
    let mut unique = BTreeSet::new();
    let mut result = Scan {
        bytes: 0,
        entries: 1,
        nodes: Vec::new(),
    };
    while let Some((directory, parent)) = pending.pop() {
        before(end)?;
        // Traversal identities use O_PATH; getdents needs a readable descriptor.
        let readable = read(&directory)?;
        let iter = Dir::read_from(&readable).map_err(|_| Failure::Storage)?;
        for item in iter {
            before(end)?;
            let item = item.map_err(|_| Failure::Storage)?;
            let raw = item.file_name().to_bytes();
            if matches!(raw, b"." | b"..") {
                continue;
            }
            require(
                raw.len() <= 255 && std::str::from_utf8(raw).is_ok(),
                Failure::Policy,
            )?;
            result.entries = result.entries.checked_add(1).ok_or(Failure::Limit)?;
            require(result.entries <= limits.entries, Failure::Limit)?;
            let name = OsStr::from_bytes(raw);
            let path = parent.path.join(name);
            let (file, entry) = child(&directory, &path, Ownership::Operation)?;
            let metadata = file.metadata().map_err(|_| Failure::Storage)?;
            if preserve.iter().any(|kept| path.starts_with(&kept.path)) {
                continue;
            }
            if entry.kind == Kind::File && unique.insert((entry.device, entry.inode)) {
                result.bytes = result
                    .bytes
                    .checked_add(metadata.len())
                    .ok_or(Failure::Limit)?;
                require(result.bytes <= limits.staging_bytes, Failure::Limit)?;
            }
            result.nodes.try_reserve(1).map_err(|_| Failure::Limit)?;
            result.nodes.push(Node {
                entry: entry.clone(),
                parent: directory.try_clone().map_err(|_| Failure::Storage)?,
                parent_entry: parent.clone(),
                name: name.into(),
            });
            if entry.kind == Kind::Directory {
                pending.try_reserve(1).map_err(|_| Failure::Limit)?;
                pending.push((file, entry));
            }
        }
    }
    open(root, false)?;
    Ok(result)
}

/// Hash exact encoded bytes with fixed zeroizing I/O storage. No path/error data is printed.
pub(crate) fn verify_file(
    file: &File,
    digest: &str,
    size: u64,
    maximum: u64,
    end: u64,
) -> Result<()> {
    require(
        digest.len() == 71 && digest.starts_with("sha256:") && hex(&digest.as_bytes()[7..]),
        Failure::Policy,
    )?;
    require(size <= maximum, Failure::Limit)?;
    require(
        file.metadata().map_err(|_| Failure::Storage)?.len() == size,
        Failure::Integrity,
    )?;
    let mut input = read(file)?;
    let mut scratch = Bytes::new(65_536)?;
    let mut hash = Sha256::new();
    let mut used = 0u64;
    loop {
        before(end)?;
        let count = input
            .read(scratch.get_mut())
            .map_err(|_| Failure::Storage)?;
        if count == 0 {
            break;
        }
        used = used.checked_add(count as u64).ok_or(Failure::Limit)?;
        require(used <= size, Failure::Integrity)?;
        hash.update(&scratch.get()[..count]);
        scratch.clear();
    }
    require(
        used == size && file.metadata().map_err(|_| Failure::Storage)?.len() == size,
        Failure::Integrity,
    )?;
    let mut output = hash.finalize();
    let same = output.iter().enumerate().all(|(i, b)| {
        const DIGITS: &[u8] = b"0123456789abcdef";
        digest.as_bytes()[7 + i * 2] == DIGITS[(b >> 4) as usize]
            && digest.as_bytes()[8 + i * 2] == DIGITS[(b & 15) as usize]
    });
    output.as_mut_slice().zeroize();
    require(same, Failure::Integrity)
}

pub(crate) fn metadata(file: &File, maximum: u64, end: u64) -> Result<Bytes> {
    before(end)?;
    let length = file.metadata().map_err(|_| Failure::Storage)?.len();
    require(length <= maximum && length <= 16_777_216, Failure::Limit)?;
    let mut bytes = Bytes::new(length as usize)?;
    let mut input = read(file)?;
    let mut offset = 0;
    while offset < bytes.get().len() {
        before(end)?;
        let count = input
            .read(&mut bytes.get_mut()[offset..])
            .map_err(|_| Failure::Storage)?;
        require(count > 0, Failure::Integrity)?;
        offset += count;
    }
    let mut tail = Bytes::new(1)?;
    require(
        input.read(tail.get_mut()).map_err(|_| Failure::Storage)? == 0,
        Failure::Integrity,
    )?;
    Ok(bytes)
}

pub(crate) fn copy_tool(
    workspace: &Entry,
    source: &Entry,
    destination: &Path,
    digest: &str,
    size: u64,
    limits: &ContentLimits,
    end: u64,
) -> Result<Entry> {
    before(end)?;
    require(
        source.kind == Kind::File
            && source.ownership != Ownership::Operation
            && destination.parent() == Some(workspace.path.join("tools").as_path()),
        Failure::Policy,
    )?;
    let scan = scan(workspace, limits, end, &[])?;
    require(
        size <= limits
            .staging_bytes
            .checked_sub(scan.bytes)
            .ok_or(Failure::Limit)?,
        Failure::Limit,
    )?;
    let source_fd = open(source, true)?;
    verify_file(&source_fd, digest, size, size, end)?;
    let workspace_fd = private_directory(workspace)?;
    let (tools, _) = child(
        &workspace_fd,
        &workspace.path.join("tools"),
        Ownership::Operation,
    )?;
    let destination_fd = File::from(
        rustix::fs::openat(
            &tools,
            destination.file_name().ok_or(Failure::Policy)?,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o700),
        )
        .map_err(|_| Failure::Storage)?,
    );
    let mut input = read(&source_fd)?;
    let mut output = &destination_fd;
    let mut scratch = Bytes::new(65_536)?;
    let mut used = 0u64;
    loop {
        before(end)?;
        let count = input
            .read(scratch.get_mut())
            .map_err(|_| Failure::Storage)?;
        if count == 0 {
            break;
        }
        used = used.checked_add(count as u64).ok_or(Failure::Limit)?;
        require(used <= size, Failure::Integrity)?;
        output
            .write_all(&scratch.get()[..count])
            .map_err(|_| Failure::Storage)?;
        scratch.clear();
    }
    require(used == size, Failure::Integrity)?;
    rustix::fs::fchmod(&destination_fd, Mode::from_raw_mode(0o700))
        .map_err(|_| Failure::Storage)?;
    verify_file(&destination_fd, digest, size, size, end)?;
    open(source, true)?;
    identity(&destination_fd, destination, Ownership::Operation, true)
}

pub(crate) fn cleanup(
    workspace: &Entry,
    roots: &[Entry],
    preserve: &[Entry],
    limits: &ContentLimits,
    end: u64,
) -> Result<u64> {
    before(end)?;
    for (index, entry) in roots.iter().enumerate() {
        require(
            entry.ownership == Ownership::Operation && entry.path.starts_with(&workspace.path),
            Failure::Policy,
        )?;
        for other in &roots[..index] {
            require(
                !entry.path.starts_with(&other.path) && !other.path.starts_with(&entry.path),
                Failure::Policy,
            )?;
        }
        open(entry, false)?;
    }
    for (index, entry) in preserve.iter().enumerate() {
        require(entry.ownership != Ownership::Operation, Failure::Policy)?;
        for other in &preserve[..index] {
            require(
                !entry.path.starts_with(&other.path) && !other.path.starts_with(&entry.path),
                Failure::Policy,
            )?;
        }
        open(entry, false)?;
    }
    // A complete identity inventory precedes mutation. Oversized files can still
    // be removed, but an incomplete or unsafe name traversal grants no authority.
    let mut cleanup_limits = limits.clone();
    cleanup_limits.staging_bytes = u64::MAX;
    let mut inventory = scan(workspace, &cleanup_limits, end, preserve)?;
    inventory
        .nodes
        .sort_by_key(|node| std::cmp::Reverse(node.entry.path.components().count()));
    let mut removed = 0;
    for node in inventory.nodes {
        before(end)?;
        if !roots
            .iter()
            .any(|root| node.entry.path.starts_with(&root.path))
            || preserve.iter().any(|kept| {
                kept.path.starts_with(&node.entry.path) || node.entry.path.starts_with(&kept.path)
            })
        {
            continue;
        }
        open(workspace, false)?;
        open(&node.parent_entry, false)?;
        let (_, current) = child(&node.parent, &node.entry.path, Ownership::Operation)?;
        require(current == node.entry, Failure::Integrity)?;
        let flags = if current.kind == Kind::Directory {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        rustix::fs::unlinkat(&node.parent, &node.name, flags).map_err(|_| Failure::Storage)?;
        removed += 1;
    }
    if roots.iter().any(|root| root == workspace)
        && !preserve
            .iter()
            .any(|kept| kept.path.starts_with(&workspace.path))
    {
        before(end)?;
        open(workspace, false)?;
        let (parent, name) =
            path_safety::defensive_open_parent(&workspace.path).map_err(|_| Failure::Storage)?;
        rustix::fs::unlinkat(&parent, name, AtFlags::REMOVEDIR).map_err(|_| Failure::Storage)?;
        removed += 1;
    }
    Ok(removed)
}
