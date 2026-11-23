// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    buffer::Bytes,
    common::*,
    files,
    solve::{Point, Watch},
    supervise::{Active, PublicAction},
};
use super::OutputCheck;
use super::assemble::{Assembly, OCI_LAYOUT, Source};
use broil_core::secret::path_safety;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroize;

const BLOCK: u64 = 512;

#[derive(Clone, Debug)]
pub(crate) enum Member {
    Directory(&'static str),
    Blob(Descriptor, Source),
    Bytes(&'static str, Vec<u8>),
}

impl Member {
    fn name(&self) -> String {
        match self {
            Self::Directory(name) | Self::Bytes(name, _) => (*name).into(),
            Self::Blob(descriptor, _) => format!("blobs/sha256/{}", &descriptor.digest[7..]),
        }
    }
    fn size(&self) -> u64 {
        match self {
            Self::Directory(_) => 0,
            Self::Blob(descriptor, _) => descriptor.size,
            Self::Bytes(_, bytes) => bytes.len() as u64,
        }
    }
}

fn padded(size: u64) -> Result<u64> {
    size.checked_add(BLOCK - 1)
        .map(|n| n / BLOCK * BLOCK)
        .ok_or(Failure::Limit)
}

pub(crate) fn header(name: &str, size: u64, directory: bool) -> Result<[u8; 512]> {
    require(
        !name.is_empty() && name.len() <= 100 && size < 0o77777777777,
        Failure::Limit,
    )?;
    let mut block = [0u8; 512];
    block[..name.len()].copy_from_slice(name.as_bytes());
    let octal = |block: &mut [u8; 512], offset: usize, width: usize, value: u64| {
        let text = format!("{value:0width$o}", width = width - 1);
        block[offset..offset + width - 1].copy_from_slice(text.as_bytes());
    };
    octal(&mut block, 100, 8, if directory { 0o755 } else { 0o644 });
    octal(&mut block, 108, 8, 0);
    octal(&mut block, 116, 8, 0);
    octal(&mut block, 124, 12, size);
    octal(&mut block, 136, 12, 0);
    block[156] = if directory { b'5' } else { b'0' };
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    octal(&mut block, 329, 8, 0);
    octal(&mut block, 337, 8, 0);
    block[148..156].copy_from_slice(b"        ");
    let sum: u64 = block.iter().map(|b| u64::from(*b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    Ok(block)
}

pub(crate) fn members(assembly: &Assembly, manifest: Option<Vec<u8>>) -> Vec<Member> {
    let mut members = vec![
        Member::Directory("blobs/"),
        Member::Directory("blobs/sha256/"),
    ];
    let mut blobs = assembly.blobs.clone();
    blobs.sort_by(|a, b| a.0.digest.cmp(&b.0.digest));
    members.extend(
        blobs
            .into_iter()
            .map(|(descriptor, source)| Member::Blob(descriptor, source)),
    );
    members.push(Member::Bytes("index.json", assembly.wrapper.clone()));
    if let Some(manifest) = manifest {
        members.push(Member::Bytes("manifest.json", manifest));
    }
    members.push(Member::Bytes("oci-layout", OCI_LAYOUT.to_vec()));
    members
}

pub(crate) fn archive_size(members: &[Member]) -> Result<u64> {
    members.iter().try_fold(2 * BLOCK, |total, member| {
        total
            .checked_add(BLOCK)
            .and_then(|n| n.checked_add(padded(member.size()).ok()?))
            .ok_or(Failure::Limit)
    })
}

pub(crate) fn layout_size(assembly: &Assembly) -> Result<u64> {
    assembly
        .blobs
        .iter()
        .try_fold(
            (OCI_LAYOUT.len() + assembly.wrapper.len()) as u64,
            |n, (d, _)| n.checked_add(d.size),
        )
        .ok_or(Failure::Limit)
}

pub(crate) fn docker_manifest(
    config: &Descriptor,
    reference: &str,
    layers: &[Descriptor],
) -> Result<Vec<u8>> {
    let text = |value: &str| serde_json::to_string(value).map_err(|_| Failure::Protocol);
    let mut out = format!(
        "[{{\"Config\":{},\"RepoTags\":[{}],\"Layers\":[",
        text(&format!("blobs/sha256/{}", &config.digest[7..]))?,
        text(reference)?
    );
    for (i, layer) in layers.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&text(&format!("blobs/sha256/{}", &layer.digest[7..]))?);
    }
    out.push_str("]}]");
    Ok(out.into_bytes())
}

pub(crate) fn protected_directory<W: Watch>(watch: &W, path: &Path) -> Result<File> {
    require(valid_path(path), Failure::Policy)?;
    let mut current = File::from(watch.sys(|| {
        rustix::fs::open(
            "/",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })?);
    let names: Vec<&OsStr> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    let check = |file: &File| -> Result<()> {
        let metadata = watch.io(|| file.metadata())?;
        let uid = path_safety::effective_uid();
        let mode = metadata.mode() & 0o7777;
        require(
            metadata.is_dir()
                && (metadata.uid() == uid || metadata.uid() == 0)
                && (mode & 0o022 == 0 || mode & 0o1000 != 0),
            Failure::Policy,
        )
    };
    check(&current)?;
    for name in names {
        current = File::from(watch.sys(|| {
            rustix::fs::openat(
                &current,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        check(&current)?;
    }
    Ok(current)
}

fn open_blob<W: Watch>(watch: &W, source: &Entry, descriptor: &Descriptor) -> Result<File> {
    let directory = files::open(source, false)?;
    let (blobs, _) = files::child(&directory, &source.path.join("blobs"), source.ownership)?;
    let (sha, _) = files::child(&blobs, &source.path.join("blobs/sha256"), source.ownership)?;
    let (blob, item) = files::child(
        &sha,
        &source
            .path
            .join("blobs/sha256")
            .join(&descriptor.digest[7..]),
        source.ownership,
    )?;
    require(item.kind == Kind::File, Failure::Policy)?;
    let metadata = watch.io(|| blob.metadata())?;
    require(metadata.len() == descriptor.size, Failure::Integrity)?;
    watch.io(|| {
        path_safety::reopen_for_read(&blob)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    })
}

fn digest_text(hash: Sha256) -> String {
    let mut output = hash.finalize();
    const HEX: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in output.iter() {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    output.as_mut_slice().zeroize();
    text
}

struct Sink<'a, W: Watch> {
    watch: &'a W,
    file: &'a File,
    hash: Sha256,
    written: u64,
}

impl<W: Watch> Sink<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.watch.at(Point::Writing(self.written))?;
        let mut output = self.file;
        let mut offset = 0;
        while offset < bytes.len() {
            let count = self.watch.io(|| output.write(&bytes[offset..]))?;
            require(count != 0, Failure::Storage)?;
            offset += count;
        }
        self.hash.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }
}

fn copy_blob<W: Watch>(
    watch: &W,
    sink: &mut Sink<'_, W>,
    source: &Source,
    descriptor: &Descriptor,
    layout: Option<&Entry>,
) -> std::result::Result<(), (Failure, OutputCheck)> {
    let retention = |failure| (failure, OutputCheck::Retention);
    let entry = match source {
        Source::Index => layout.ok_or(retention(Failure::Integrity))?,
        Source::Node(entry) => entry,
    };
    let mut input = open_blob(watch, entry, descriptor).map_err(retention)?;
    let mut scratch = Bytes::new(65_536).map_err(retention)?;
    let mut hash = Sha256::new();
    let mut used = 0u64;
    loop {
        let count = watch
            .io(|| input.read(scratch.get_mut()))
            .map_err(retention)?;
        if count == 0 {
            break;
        }
        used = used
            .checked_add(count as u64)
            .ok_or(retention(Failure::Limit))?;
        if used > descriptor.size {
            return Err(retention(Failure::Integrity));
        }
        hash.update(&scratch.get()[..count]);
        sink.write(&scratch.get()[..count]).map_err(retention)?;
        scratch.clear();
    }
    if used != descriptor.size || digest_text(hash) != descriptor.digest {
        return Err(retention(Failure::Integrity));
    }
    Ok(())
}

fn write_archive<W: Watch>(
    watch: &W,
    sink: &mut Sink<'_, W>,
    members: &[Member],
    layout: Option<&Entry>,
) -> std::result::Result<(), (Failure, OutputCheck)> {
    let retention = |failure| (failure, OutputCheck::Retention);
    for member in members {
        let size = member.size();
        let block = header(&member.name(), size, matches!(member, Member::Directory(_)))
            .map_err(retention)?;
        sink.write(&block).map_err(retention)?;
        match member {
            Member::Directory(_) => {}
            Member::Blob(descriptor, source) => copy_blob(watch, sink, source, descriptor, layout)?,
            Member::Bytes(_, bytes) => sink.write(bytes).map_err(retention)?,
        }
        let padding = padded(size).map_err(retention)? - size;
        sink.write(&vec![0u8; padding as usize])
            .map_err(retention)?;
    }
    sink.write(&[0u8; 1024]).map_err(retention)
}

fn reread_archive<W: Watch>(
    watch: &W,
    file: &File,
    members: &[Member],
    index: Option<&[u8]>,
) -> Result<(String, u64)> {
    let mut input = watch.io(|| {
        path_safety::reopen_for_read(file)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    })?;
    let mut whole = Sha256::new();
    let mut total = 0u64;
    let mut exact = |input: &mut File,
                     length: u64,
                     whole: &mut Sha256,
                     check: &mut dyn FnMut(&[u8]) -> Result<()>|
     -> Result<()> {
        let mut scratch = Bytes::new(65_536)?;
        let mut left = length;
        while left > 0 {
            let want = left.min(65_536) as usize;
            let count = watch.io(|| input.read(&mut scratch.get_mut()[..want]))?;
            require(count > 0, Failure::Integrity)?;
            whole.update(&scratch.get()[..count]);
            check(&scratch.get()[..count])?;
            left -= count as u64;
            total += count as u64;
        }
        scratch.clear();
        Ok(())
    };
    for member in members {
        let size = member.size();
        let block = header(&member.name(), size, matches!(member, Member::Directory(_)))?;
        let mut offset = 0usize;
        exact(&mut input, BLOCK, &mut whole, &mut |bytes| {
            require(
                bytes == &block[offset..offset + bytes.len()],
                Failure::Integrity,
            )?;
            offset += bytes.len();
            Ok(())
        })?;
        match member {
            Member::Directory(_) => {}
            Member::Blob(descriptor, source) => {
                let mut hash = Sha256::new();
                let expected = match source {
                    Source::Index => Some(index.ok_or(Failure::Integrity)?),
                    Source::Node(_) => None,
                };
                let mut offset = 0usize;
                exact(&mut input, size, &mut whole, &mut |bytes| {
                    if let Some(expected) = expected {
                        require(
                            bytes == &expected[offset..offset + bytes.len()],
                            Failure::Integrity,
                        )?;
                    }
                    offset += bytes.len();
                    hash.update(bytes);
                    Ok(())
                })?;
                require(digest_text(hash) == descriptor.digest, Failure::Integrity)?;
            }
            Member::Bytes(_, planned) => {
                let mut offset = 0usize;
                exact(&mut input, size, &mut whole, &mut |bytes| {
                    require(
                        bytes == &planned[offset..offset + bytes.len()],
                        Failure::Integrity,
                    )?;
                    offset += bytes.len();
                    Ok(())
                })?;
            }
        }
        let padding = padded(size)? - size;
        exact(&mut input, padding, &mut whole, &mut |bytes| {
            require(bytes.iter().all(|b| *b == 0), Failure::Integrity)
        })?;
    }
    exact(&mut input, 2 * BLOCK, &mut whole, &mut |bytes| {
        require(bytes.iter().all(|b| *b == 0), Failure::Integrity)
    })?;
    let mut tail = [0u8; 1];
    require(watch.io(|| input.read(&mut tail))? == 0, Failure::Integrity)?;
    Ok((digest_text(whole), total))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Unit {
    Layout,
    Archive,
}

#[derive(Clone, Debug)]
pub(crate) struct Published {
    pub(crate) entry: Entry,
    pub(crate) archive: Option<(String, u64)>,
}

pub(crate) struct RetainWork {
    destination: PathBuf,
    unit: Unit,
    temporary: String,
    members: Vec<Member>,
    wrapper: Vec<u8>,
    layout: Entry,
    index: Option<Vec<u8>>,
    blobs: Vec<(Descriptor, Source)>,
    total: u64,
    pub(crate) result: Option<Published>,
    pub(crate) check: Option<OutputCheck>,
    pub(crate) residue: bool,
    pub(crate) published: bool,
}

impl RetainWork {
    pub(crate) fn new(
        destination: PathBuf,
        unit: Unit,
        operation: &str,
        assembly: &Assembly,
        layout: &Entry,
    ) -> Result<Self> {
        require(
            valid_path(&destination) && valid_operation(operation),
            Failure::Policy,
        )?;
        require(
            layout.kind == Kind::Directory && layout.ownership == Ownership::Operation,
            Failure::Policy,
        )?;
        let members = members(assembly, None);
        let total = match unit {
            Unit::Layout => layout_size(assembly)?,
            Unit::Archive => archive_size(&members)?,
        };
        Ok(Self {
            destination,
            unit,
            temporary: format!(".broil-{}", &operation[10..]),
            members,
            wrapper: assembly.wrapper.clone(),
            layout: layout.clone(),
            index: assembly.index.clone(),
            blobs: assembly.blobs.clone(),
            total,
            result: None,
            check: None,
            residue: false,
            published: false,
        })
    }

    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    fn refuse(&mut self, failure: Failure, check: OutputCheck) -> Result<()> {
        self.check = Some(check);
        Err(failure)
    }

    pub(crate) fn run<W: Watch>(&mut self, watch: &W) -> Result<()> {
        require(self.result.is_none() && !self.published, Failure::Policy)?;
        let name = self
            .destination
            .file_name()
            .ok_or(Failure::Policy)?
            .to_os_string();
        let parent_path = self
            .destination
            .parent()
            .ok_or(Failure::Policy)?
            .to_path_buf();
        let parent = match protected_directory(watch, &parent_path) {
            Ok(parent) => parent,
            Err(failure) => return self.refuse(failure, OutputCheck::Destination),
        };
        let readable = match files::read(&parent) {
            Ok(file) => file,
            Err(failure) => return self.refuse(failure, OutputCheck::Destination),
        };
        let exists = |watch: &W| -> Result<()> {
            watch.watch()?;
            let opened = rustix::fs::openat(
                &parent,
                &name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            );
            watch.watch()?;
            match opened {
                Ok(_) => Err(Failure::Policy),
                Err(rustix::io::Errno::NOENT) => Ok(()),
                Err(_) => Err(Failure::Storage),
            }
        };
        if let Err(failure) = exists(watch) {
            return self.refuse(failure, OutputCheck::Destination);
        }
        if let Err(failure) = watch.at(Point::Checked(&self.destination)) {
            return self.refuse(failure, OutputCheck::Destination);
        }
        let available = match watch.sys(|| rustix::fs::fstatvfs(&readable)) {
            Ok(stat) => stat.f_bavail.saturating_mul(stat.f_frsize),
            Err(failure) => return self.refuse(failure, OutputCheck::Destination),
        };
        if self.total > available {
            return self.refuse(Failure::Storage, OutputCheck::Destination);
        }
        let temporary = self.temporary.clone();
        let created = match self.unit {
            Unit::Archive => watch.sys(|| {
                rustix::fs::openat(
                    &parent,
                    &temporary,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
                .map(File::from)
            }),
            Unit::Layout => watch
                .sys(|| rustix::fs::mkdirat(&parent, &temporary, Mode::from_raw_mode(0o700)))
                .and_then(|_| {
                    watch.sys(|| {
                        rustix::fs::openat(
                            &parent,
                            &temporary,
                            OFlags::PATH | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map(File::from)
                    })
                }),
        };
        let created = match created {
            Ok(file) => file,
            Err(failure) => {
                let existing = watch
                    .sys(|| {
                        rustix::fs::openat(
                            &parent,
                            &temporary,
                            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                    })
                    .is_ok();
                return self.refuse(
                    if existing { Failure::Policy } else { failure },
                    OutputCheck::Destination,
                );
            }
        };
        let identity = match identity_of(watch, &created, &self.destination).or_else(|failure| {
            identity_of(&watch.grace(), &created, &self.destination).map_err(|_| failure)
        }) {
            Ok(identity) => identity,
            Err(failure) => {
                self.residue = true;
                return self.refuse(failure, OutputCheck::Retention);
            }
        };
        let mode = if self.unit == Unit::Archive {
            0o600
        } else {
            0o700
        };
        match watch.io(|| created.metadata()) {
            Ok(m) if m.uid() == path_safety::effective_uid() && m.mode() & 0o777 == mode => {}
            other => {
                return self.fail(
                    watch,
                    &parent,
                    other.err().unwrap_or(Failure::Policy),
                    OutputCheck::Destination,
                    Some(identity),
                );
            }
        }
        let written = match self.unit {
            Unit::Archive => self.write_file_unit(watch, &created),
            Unit::Layout => self.write_directory_unit(watch, &created),
        };
        if let Err((failure, check)) = written {
            return self.fail(watch, &parent, failure, check, Some(identity));
        }
        let renamed = watch.sys(|| {
            rustix::fs::renameat_with(&parent, &temporary, &parent, &name, RenameFlags::NOREPLACE)
        });
        if let Err(failure) = renamed {
            let failure = if exists(watch) == Err(Failure::Policy) {
                Failure::Policy
            } else {
                failure
            };
            return self.fail(
                watch,
                &parent,
                failure,
                OutputCheck::Destination,
                Some(identity),
            );
        }
        self.published = true;
        if let Err(failure) = watch.io(|| readable.sync_all()) {
            return self.refuse(failure, OutputCheck::Retention);
        }
        if let Err(failure) = watch.at(Point::Published(&self.destination)) {
            return self.refuse(failure, OutputCheck::Retention);
        }
        let published = match watch.sys(|| {
            rustix::fs::openat(
                &parent,
                &name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        }) {
            Ok(fd) => File::from(fd),
            Err(failure) => return self.refuse(failure, OutputCheck::Retention),
        };
        let entry = match files::identity(&published, &self.destination, Ownership::Retained, false)
        {
            Ok(entry) if (entry.device, entry.inode) == identity => entry,
            Ok(_) => return self.refuse(Failure::Integrity, OutputCheck::Retention),
            Err(failure) => return self.refuse(failure, OutputCheck::Retention),
        };
        let archive = if self.unit == Unit::Archive {
            match reread_archive(watch, &published, &self.members, self.index.as_deref()) {
                Ok(read) if read.1 == self.total => Some(read),
                Ok(_) => return self.refuse(Failure::Integrity, OutputCheck::Retention),
                Err(failure) => return self.refuse(failure, OutputCheck::Retention),
            }
        } else {
            None
        };
        watch.watch()?;
        self.result = Some(Published { entry, archive });
        Ok(())
    }

    fn write_file_unit<W: Watch>(
        &self,
        watch: &W,
        file: &File,
    ) -> std::result::Result<(), (Failure, OutputCheck)> {
        let retention = |failure| (failure, OutputCheck::Retention);
        let mut sink = Sink {
            watch,
            file,
            hash: Sha256::new(),
            written: 0,
        };
        write_archive(watch, &mut sink, &self.members, Some(&self.layout))?;
        if sink.written != self.total {
            return Err(retention(Failure::Integrity));
        }
        watch.io(|| file.sync_all()).map_err(retention)
    }

    fn write_directory_unit<W: Watch>(
        &self,
        watch: &W,
        directory: &File,
    ) -> std::result::Result<(), (Failure, OutputCheck)> {
        let retention = |failure| (failure, OutputCheck::Retention);
        let root = self.destination.with_file_name(&self.temporary);
        let mut written = 0u64;
        written = create(watch, directory, "oci-layout", written, |sink| {
            sink.write(OCI_LAYOUT).map_err(retention)
        })?;
        written = create(watch, directory, "index.json", written, |sink| {
            sink.write(&self.wrapper).map_err(retention)
        })?;
        let (blobs, _) = files::mkdir(directory, &root.join("blobs")).map_err(retention)?;
        let (sha, _) = files::mkdir(&blobs, &root.join("blobs/sha256")).map_err(retention)?;
        for (descriptor, source) in &self.blobs {
            written = create(watch, &sha, &descriptor.digest[7..], written, |sink| {
                copy_blob(watch, sink, source, descriptor, Some(&self.layout))
            })?;
        }
        if written != self.total {
            return Err(retention(Failure::Integrity));
        }
        for handle in [&sha, &blobs, directory] {
            let readable = files::read(handle).map_err(retention)?;
            watch.io(|| readable.sync_all()).map_err(retention)?;
        }
        Ok(())
    }

    fn fail<W: Watch>(
        &mut self,
        watch: &W,
        parent: &File,
        failure: Failure,
        check: OutputCheck,
        identity: Option<(u64, u64)>,
    ) -> Result<()> {
        if let Some(identity) = identity {
            self.residue = remove(watch, parent, &self.temporary, identity, Gone::Residue)
                .or_else(|_| {
                    remove(
                        &watch.grace(),
                        parent,
                        &self.temporary,
                        identity,
                        Gone::Removed,
                    )
                })
                .is_err();
        }
        self.refuse(failure, check)
    }
}

fn identity_of<W: Watch>(watch: &W, created: &File, destination: &Path) -> Result<(u64, u64)> {
    watch.at(Point::Created(destination))?;
    let metadata = watch.io(|| created.metadata())?;
    Ok((metadata.dev(), metadata.ino()))
}

#[derive(Clone, Copy)]
enum Gone {
    Residue,
    Removed,
}

fn remove<W: Watch>(
    watch: &W,
    parent: &File,
    name: &str,
    identity: (u64, u64),
    gone: Gone,
) -> Result<()> {
    let opened = watch.io(|| {
        match rustix::fs::openat(
            parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Err(rustix::io::Errno::NOENT) if matches!(gone, Gone::Removed) => Ok(None),
            other => other.map(Some).map_err(Into::into),
        }
    })?;
    let Some(handle) = opened.map(File::from) else {
        return Ok(());
    };
    let metadata = watch.io(|| handle.metadata())?;
    require(
        (metadata.dev(), metadata.ino()) == identity,
        Failure::Integrity,
    )?;
    if metadata.is_dir() {
        remove_children(watch, &handle, 0)?;
        watch.sys(|| rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR))
    } else {
        watch.sys(|| rustix::fs::unlinkat(parent, name, AtFlags::empty()))
    }
}

fn remove_children<W: Watch>(watch: &W, directory: &File, depth: u32) -> Result<()> {
    require(depth < 4, Failure::Integrity)?;
    let readable = files::read(directory)?;
    let names: Vec<std::ffi::OsString> = watch
        .io(|| rustix::fs::Dir::read_from(&readable).map_err(Into::into))?
        .filter_map(|item| item.ok())
        .map(|item| {
            use std::os::unix::ffi::OsStrExt;
            OsStr::from_bytes(item.file_name().to_bytes()).to_os_string()
        })
        .filter(|name| name != "." && name != "..")
        .collect();
    for name in names {
        let child = File::from(watch.sys(|| {
            rustix::fs::openat(
                directory,
                &name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        let metadata = watch.io(|| child.metadata())?;
        require(
            metadata.uid() == path_safety::effective_uid(),
            Failure::Policy,
        )?;
        if metadata.is_dir() {
            remove_children(watch, &child, depth + 1)?;
            watch.sys(|| rustix::fs::unlinkat(directory, &name, AtFlags::REMOVEDIR))?;
        } else {
            watch.sys(|| rustix::fs::unlinkat(directory, &name, AtFlags::empty()))?;
        }
    }
    Ok(())
}

fn create<W: Watch>(
    watch: &W,
    parent: &File,
    name: &str,
    written: u64,
    body: impl FnOnce(&mut Sink<'_, W>) -> std::result::Result<(), (Failure, OutputCheck)>,
) -> std::result::Result<u64, (Failure, OutputCheck)> {
    let retention = |failure| (failure, OutputCheck::Retention);
    let file = File::from(
        watch
            .sys(|| {
                rustix::fs::openat(
                    parent,
                    name,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::from_raw_mode(0o600),
                )
            })
            .map_err(retention)?,
    );
    let mut sink = Sink {
        watch,
        file: &file,
        hash: Sha256::new(),
        written,
    };
    body(&mut sink)?;
    let written = sink.written;
    watch.io(|| file.sync_all()).map_err(retention)?;
    Ok(written)
}

impl PublicAction for RetainWork {
    fn apply(&mut self, active: &Active) -> Result<()> {
        self.run(active)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

pub(crate) struct ArchiveWork {
    workspace: Entry,
    members: Vec<Member>,
    layout: Entry,
    index: Option<Vec<u8>>,
    total: u64,
    pub(crate) result: Option<(Entry, String, u64)>,
}

impl ArchiveWork {
    pub(crate) fn new(
        workspace: Entry,
        assembly: &Assembly,
        manifest: Vec<u8>,
        layout: &Entry,
    ) -> Result<Self> {
        require(
            workspace.kind == Kind::Directory && workspace.ownership == Ownership::Operation,
            Failure::Policy,
        )?;
        require(
            layout.kind == Kind::Directory && layout.ownership == Ownership::Operation,
            Failure::Policy,
        )?;
        let members = members(assembly, Some(manifest));
        Ok(Self {
            workspace,
            total: archive_size(&members)?,
            members,
            layout: layout.clone(),
            index: assembly.index.clone(),
            result: None,
        })
    }

    pub(crate) fn total(&self) -> u64 {
        self.total
    }

    pub(crate) fn run<W: Watch>(&mut self, watch: &W) -> Result<()> {
        require(self.result.is_none(), Failure::Policy)?;
        watch.watch()?;
        let workspace = files::private_directory(&self.workspace)?;
        let outputs_path = self.workspace.path.join("outputs");
        let (outputs, _) = files::child(&workspace, &outputs_path, Ownership::Operation)?;
        let path = outputs_path.join("docker.tar");
        let file = super::super::solve::create_file(watch, &outputs, &path)?;
        let mut sink = Sink {
            watch,
            file: &file,
            hash: Sha256::new(),
            written: 0,
        };
        write_archive(watch, &mut sink, &self.members, Some(&self.layout))
            .map_err(|(failure, _)| failure)?;
        require(sink.written == self.total, Failure::Integrity)?;
        let digest = digest_text(sink.hash);
        let (digest_read, size) =
            reread_archive(watch, &file, &self.members, self.index.as_deref())?;
        require(
            digest_read == digest && size == self.total,
            Failure::Integrity,
        )?;
        let entry = files::identity(&file, &path, Ownership::Operation, false)?;
        watch.watch()?;
        self.result = Some((entry, digest, size));
        Ok(())
    }
}

impl PublicAction for ArchiveWork {
    fn apply(&mut self, active: &Active) -> Result<()> {
        self.run(active)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
