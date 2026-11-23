// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    buffer::Bytes,
    common::*,
    files,
    outputs::OCI_LAYOUT,
    solve::{Point, Watch, create_directory, create_file, write_file},
    supervise::{Active, PublicAction},
};
use super::receipt::Planned;
use broil_core::{images::OutputKind, secret::path_safety};
use rustix::fs::{Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

const BASE: &str = "publish";
const UPLOAD: &str = "publish/upload";

const BLOCK: usize = 512;

fn digest_text(hash: Sha256) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut output = hash.finalize();
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in output.as_slice() {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    output.as_mut_slice().zeroize();
    text
}

struct Created {
    layout: Entry,
    entries: Vec<Entry>,
}

fn create_layout<W: Watch>(watch: &W, workspace: &Entry) -> Result<(File, File, Created)> {
    let workspace_fd = files::private_directory(workspace)?;
    let base = workspace.path.join(BASE);
    let (base_fd, base_entry) = create_directory(watch, &workspace_fd, &base)?;
    let upload = workspace.path.join(UPLOAD);
    let (upload_fd, upload_entry) = create_directory(watch, &base_fd, &upload)?;
    let (blobs_fd, blobs_entry) = create_directory(watch, &upload_fd, &upload.join("blobs"))?;
    let (sha_fd, sha_entry) = create_directory(watch, &blobs_fd, &upload.join("blobs/sha256"))?;
    Ok((
        upload_fd,
        sha_fd,
        Created {
            layout: upload_entry.clone(),
            entries: vec![base_entry, upload_entry, blobs_entry, sha_entry],
        },
    ))
}

fn recheck<W: Watch>(watch: &W, created: &Created) -> Result<()> {
    for entry in &created.entries {
        watch.watch()?;
        files::open(entry, false)?;
    }
    watch.watch()?;
    Ok(())
}

pub(crate) struct PublishWork {
    workspace: Entry,
    wrapper: Vec<u8>,
    index: Option<(Descriptor, Vec<u8>)>,
    blobs: Vec<(Descriptor, Entry)>,
    content_bytes: u64,
    allowance: u64,
    limits: ContentLimits,
    result: Option<Entry>,
}

impl PublishWork {
    pub(crate) fn new(
        workspace: Entry,
        planned: &Planned,
        allowance: u64,
        limits: &ContentLimits,
    ) -> Result<Self> {
        require(
            workspace.kind == Kind::Directory && workspace.ownership == Ownership::Operation,
            Failure::Policy,
        )?;
        planned.root.validate()?;
        require(!planned.blobs.is_empty(), Failure::Integrity)?;
        require(!planned.wrapper.is_empty(), Failure::Policy)?;
        let mut blobs = Vec::new();
        for (descriptor, _, source) in &planned.blobs {
            descriptor.validate()?;
            require(
                source.kind == Kind::Directory
                    && source.ownership == Ownership::Retained
                    && !source.path.starts_with(&workspace.path),
                Failure::Policy,
            )?;
            blobs.push((descriptor.clone(), source.clone()));
        }
        Ok(Self {
            workspace,
            wrapper: planned.wrapper.clone(),
            index: planned
                .index
                .as_ref()
                .map(|bytes| (planned.root.clone(), bytes.clone())),
            blobs,
            content_bytes: planned.content_bytes,
            allowance,
            limits: limits.clone(),
            result: None,
        })
    }

    pub(crate) fn take(self) -> Option<Entry> {
        self.result
    }

    fn admissible<W: Watch>(&self, watch: &W) -> Result<()> {
        let scan = files::scan(&self.workspace, &self.limits, watch.deadline(), &[])?;
        let room = self
            .limits
            .staging_bytes
            .checked_sub(scan.bytes)
            .ok_or(Failure::Limit)?;
        require(
            self.content_bytes <= room.min(self.allowance),
            Failure::Limit,
        )?;
        for (_, source) in &self.blobs {
            watch.watch()?;
            require(source.device == self.workspace.device, Failure::Storage)?;
        }
        Ok(())
    }

    fn rehome<W: Watch>(
        &self,
        watch: &W,
        sha: &File,
        sha_path: &Path,
        descriptor: &Descriptor,
        source: &Entry,
    ) -> Result<Entry> {
        let name = &descriptor.digest[7..];
        watch.watch()?;
        let directory = files::open(source, false)?;
        let (source_blobs, _) =
            files::child(&directory, &source.path.join("blobs"), source.ownership)?;
        let blobs_path = source.path.join("blobs/sha256");
        let (source_sha, _) = files::child(&source_blobs, &blobs_path, source.ownership)?;
        let handle = File::from(watch.sys(|| {
            rustix::fs::openat(
                &source_sha,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        let metadata = watch.io(|| handle.metadata())?;
        require(
            metadata.is_file() && metadata.uid() == path_safety::effective_uid(),
            Failure::Policy,
        )?;
        require(
            metadata.nlink() == 1 && metadata.len() == descriptor.size,
            Failure::Integrity,
        )?;
        let opened = watch.io(|| {
            path_safety::reopen_for_read(&handle)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })?;
        watch.sys(|| rustix::fs::fchmod(&opened, Mode::from_raw_mode(0o600)))?;
        watch.at(Point::Renaming(&blobs_path.join(name)))?;
        watch.sys(|| {
            rustix::fs::renameat_with(&source_sha, name, sha, name, RenameFlags::NOREPLACE)
        })?;
        let (_, moved) = files::child(sha, &sha_path.join(name), Ownership::Operation)?;
        require(
            moved.kind == Kind::File
                && moved.device == metadata.dev()
                && moved.inode == metadata.ino(),
            Failure::Integrity,
        )?;
        Ok(moved)
    }

    fn recheck_present<W: Watch>(
        &self,
        watch: &W,
        sha: &File,
        sha_path: &Path,
        descriptor: &Descriptor,
    ) -> Result<()> {
        let path = sha_path.join(&descriptor.digest[7..]);
        let (file, entry) = files::child(sha, &path, Ownership::Operation)?;
        require(entry.kind == Kind::File, Failure::Policy)?;
        let metadata = watch.io(|| file.metadata())?;
        require(metadata.len() == descriptor.size, Failure::Integrity)?;
        Ok(())
    }

    pub(crate) fn run<W: Watch>(&mut self, watch: &W) -> Result<()> {
        require(self.result.is_none(), Failure::Policy)?;
        watch.watch()?;
        self.admissible(watch)?;
        let (upload_fd, sha, mut created) = create_layout(watch, &self.workspace)?;
        let upload = self.workspace.path.join(UPLOAD);
        created.entries.push(write_file(
            watch,
            &upload_fd,
            &upload.join("oci-layout"),
            OCI_LAYOUT,
        )?);
        created.entries.push(write_file(
            watch,
            &upload_fd,
            &upload.join("index.json"),
            &self.wrapper,
        )?);
        let sha_path = upload.join("blobs/sha256");
        let mut present = BTreeSet::new();
        if let Some((descriptor, bytes)) = &self.index {
            created.entries.push(write_file(
                watch,
                &sha,
                &sha_path.join(&descriptor.digest[7..]),
                bytes,
            )?);
            present.insert(descriptor.digest.clone());
        }
        for (descriptor, source) in &self.blobs {
            watch.watch()?;
            if present.insert(descriptor.digest.clone()) {
                created
                    .entries
                    .push(self.rehome(watch, &sha, &sha_path, descriptor, source)?);
            } else {
                self.recheck_present(watch, &sha, &sha_path, descriptor)?;
            }
        }
        recheck(watch, &created)?;
        self.result = Some(created.layout);
        Ok(())
    }
}

impl PublicAction for PublishWork {
    fn apply(&mut self, active: &Active) -> Result<()> {
        self.run(active)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[derive(Clone, Debug)]
pub struct RetainedArtifact {
    pub location: PathBuf,
    pub kind: OutputKind,
    pub root: Descriptor,
    pub manifests: Vec<(String, Descriptor)>,
    pub verified_files: u64,
    pub verified_bytes: u64,
    pub archive: Option<(String, u64)>,
}

pub(crate) enum Member {
    Directory(String),
    Blob(String, u64),
    Metadata(String, u64),
}

pub(crate) fn header(block: &[u8; BLOCK]) -> Result<Option<Member>> {
    if block.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    require(
        &block[257..263] == b"ustar\0" && &block[263..265] == b"00",
        Failure::Policy,
    )?;
    let expected = {
        let mut copy = *block;
        copy[148..156].copy_from_slice(b"        ");
        let sum: u64 = copy.iter().map(|byte| u64::from(*byte)).sum();
        format!("{sum:06o}\0 ")
    };
    require(block[148..156] == *expected.as_bytes(), Failure::Integrity)?;
    let field = |offset: usize, width: usize| -> Result<&str> {
        let bytes = &block[offset..offset + width];
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).map_err(|_| Failure::Policy)
    };
    let octal = |offset: usize, width: usize| -> Result<u64> {
        let text = field(offset, width)?.trim_end_matches(' ');
        require(!text.is_empty(), Failure::Policy)?;
        u64::from_str_radix(text, 8).map_err(|_| Failure::Policy)
    };
    let name = field(0, 100)?.to_owned();
    let size = octal(124, 12)?;
    let mode = octal(100, 8)?;
    let directory = block[156] == b'5';
    require(
        (directory || block[156] == b'0')
            && octal(108, 8)? == 0
            && octal(116, 8)? == 0
            && octal(136, 12)? == 0
            && octal(329, 8)? == 0
            && octal(337, 8)? == 0
            && block[157..257].iter().all(|byte| *byte == 0)
            && block[265..329].iter().all(|byte| *byte == 0)
            && block[345..].iter().all(|byte| *byte == 0),
        Failure::Policy,
    )?;
    if directory {
        require(mode == 0o755 && size == 0, Failure::Policy)?;
        return Ok(Some(Member::Directory(name)));
    }
    require(mode == 0o644, Failure::Policy)?;
    if let Some(digest) = name.strip_prefix("blobs/sha256/") {
        require(
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            Failure::Policy,
        )?;
        return Ok(Some(Member::Blob(format!("sha256:{digest}"), size)));
    }
    Ok(Some(Member::Metadata(name, size)))
}

pub(crate) struct UnpackWork {
    workspace: Entry,
    artifact: RetainedArtifact,
    allowance: u64,
    limits: ContentLimits,
    result: Option<Entry>,
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
enum Expect {
    Blobs,
    BlobsSha,
    Blob,
    Layout,
    End,
}

impl UnpackWork {
    pub(crate) fn new(
        workspace: Entry,
        artifact: RetainedArtifact,
        allowance: u64,
        limits: &ContentLimits,
    ) -> Result<Self> {
        require(
            workspace.kind == Kind::Directory && workspace.ownership == Ownership::Operation,
            Failure::Policy,
        )?;
        require(artifact.kind == OutputKind::OciArchive, Failure::Policy)?;
        artifact.root.validate()?;
        let (digest, size) = artifact.archive.clone().ok_or(Failure::Policy)?;
        require(
            digest.len() == 71 && digest.starts_with("sha256:") && size > 0,
            Failure::Policy,
        )?;
        require(
            valid_path(&artifact.location) && !artifact.location.starts_with(&workspace.path),
            Failure::Policy,
        )?;
        require(
            artifact.verified_files > 0
                && artifact.verified_files <= limits.descriptors
                && artifact.verified_bytes <= limits.content_bytes,
            Failure::Limit,
        )?;
        Ok(Self {
            workspace,
            artifact,
            allowance,
            limits: limits.clone(),
            result: None,
        })
    }

    pub(crate) fn take(self) -> Option<Entry> {
        self.result
    }

    fn admissible<W: Watch>(&self, watch: &W) -> Result<()> {
        let scan = files::scan(&self.workspace, &self.limits, watch.deadline(), &[])?;
        let room = self
            .limits
            .staging_bytes
            .checked_sub(scan.bytes)
            .ok_or(Failure::Limit)?;
        require(
            self.artifact.verified_bytes <= room.min(self.allowance),
            Failure::Limit,
        )?;
        Ok(())
    }

    fn block<W: Watch>(
        &self,
        watch: &W,
        input: &mut File,
        whole: &mut Sha256,
    ) -> Result<[u8; BLOCK]> {
        let mut block = [0u8; BLOCK];
        let mut offset = 0;
        while offset < BLOCK {
            let count = watch.io(|| input.read(&mut block[offset..]))?;
            require(count > 0, Failure::Integrity)?;
            offset += count;
        }
        whole.update(block);
        Ok(block)
    }

    #[allow(clippy::too_many_arguments)]
    fn extract<W: Watch>(
        &self,
        watch: &W,
        input: &mut File,
        whole: &mut Sha256,
        parent: &File,
        path: &Path,
        size: u64,
        digest: Option<&str>,
    ) -> Result<Entry> {
        require(size <= self.limits.blob_bytes, Failure::Limit)?;
        let mut file = create_file(watch, parent, path)?;
        let mut scratch = Bytes::new(65_536)?;
        let mut hash = Sha256::new();
        let mut left = size;
        while left > 0 {
            watch.watch()?;
            let want = left.min(scratch.get().len() as u64) as usize;
            let count = watch.io(|| input.read(&mut scratch.get_mut()[..want]))?;
            require(count > 0, Failure::Integrity)?;
            let chunk = &scratch.get()[..count];
            hash.update(chunk);
            whole.update(chunk);
            let mut offset = 0;
            while offset < count {
                let written = watch.io(|| file.write(&chunk[offset..count]))?;
                require(written > 0, Failure::Storage)?;
                offset += written;
            }
            left -= count as u64;
            scratch.clear();
        }
        let text = digest_text(hash);
        if let Some(expected) = digest {
            require(text == expected, Failure::Integrity)?;
        }
        let padding = (BLOCK - (size as usize % BLOCK)) % BLOCK;
        if padding > 0 {
            let mut block = [0u8; BLOCK];
            let mut offset = 0;
            while offset < padding {
                let count = watch.io(|| input.read(&mut block[offset..padding]))?;
                require(count > 0, Failure::Integrity)?;
                offset += count;
            }
            whole.update(&block[..padding]);
            require(
                block[..padding].iter().all(|byte| *byte == 0),
                Failure::Integrity,
            )?;
        }
        let metadata = watch.io(|| file.metadata())?;
        require(metadata.len() == size, Failure::Integrity)?;
        files::identity(&file, path, Ownership::Operation, false)
    }

    pub(crate) fn run<W: Watch>(&mut self, watch: &W) -> Result<()> {
        require(self.result.is_none(), Failure::Policy)?;
        watch.watch()?;
        let (recorded_digest, recorded_size) =
            self.artifact.archive.clone().ok_or(Failure::Policy)?;
        self.admissible(watch)?;
        let (handle, entry) =
            files::open_path(&self.artifact.location, Ownership::Retained, false)?;
        require(entry.kind == Kind::File, Failure::Policy)?;
        let metadata = watch.io(|| handle.metadata())?;
        require(
            metadata.is_file() && metadata.uid() == path_safety::effective_uid(),
            Failure::Policy,
        )?;
        require(metadata.len() == recorded_size, Failure::Integrity)?;
        let mut input = watch.io(|| {
            path_safety::reopen_for_read(&handle)
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })?;
        let (upload_fd, sha_fd, mut created) = create_layout(watch, &self.workspace)?;
        let upload = self.workspace.path.join(UPLOAD);
        let sha_path = upload.join("blobs/sha256");
        let mut whole = Sha256::new();
        let mut blobs: BTreeSet<String> = BTreeSet::new();
        let mut bytes = 0u64;
        let mut expect = Expect::Blobs;
        let mut last = String::new();
        loop {
            watch.watch()?;
            let block = self.block(watch, &mut input, &mut whole)?;
            let Some(member) = header(&block)? else {
                require(expect == Expect::End, Failure::Policy)?;
                break;
            };
            match member {
                Member::Directory(name) => {
                    let wanted = match expect {
                        Expect::Blobs => "blobs/",
                        Expect::BlobsSha => "blobs/sha256/",
                        _ => return Err(Failure::Policy),
                    };
                    require(name == wanted, Failure::Policy)?;
                    expect = if expect == Expect::Blobs {
                        Expect::BlobsSha
                    } else {
                        Expect::Blob
                    };
                }
                Member::Blob(digest, size) => {
                    require(expect == Expect::Blob, Failure::Policy)?;
                    require(digest > last, Failure::Policy)?;
                    last = digest.clone();
                    require(blobs.insert(digest.clone()), Failure::Integrity)?;
                    bytes = bytes.checked_add(size).ok_or(Failure::Limit)?;
                    require(
                        blobs.len() as u64 <= self.limits.descriptors
                            && bytes <= self.limits.content_bytes,
                        Failure::Limit,
                    )?;
                    created.entries.push(self.extract(
                        watch,
                        &mut input,
                        &mut whole,
                        &sha_fd,
                        &sha_path.join(&digest[7..]),
                        size,
                        Some(&digest),
                    )?);
                }
                Member::Metadata(name, size) => {
                    let wanted = match expect {
                        Expect::Blob => "index.json",
                        Expect::Layout => "oci-layout",
                        _ => return Err(Failure::Policy),
                    };
                    require(name == wanted, Failure::Policy)?;
                    require(size <= self.limits.metadata_bytes, Failure::Limit)?;
                    created.entries.push(self.extract(
                        watch,
                        &mut input,
                        &mut whole,
                        &upload_fd,
                        &upload.join(&name),
                        size,
                        None,
                    )?);
                    expect = if name == "index.json" {
                        Expect::Layout
                    } else {
                        Expect::End
                    };
                }
            }
        }
        let tail = self.block(watch, &mut input, &mut whole)?;
        require(tail.iter().all(|byte| *byte == 0), Failure::Integrity)?;
        let mut after = [0u8; 1];
        require(
            watch.io(|| input.read(&mut after))? == 0,
            Failure::Integrity,
        )?;
        require(digest_text(whole) == recorded_digest, Failure::Integrity)?;
        require(
            blobs.contains(&self.artifact.root.digest)
                && self
                    .artifact
                    .manifests
                    .iter()
                    .all(|(_, manifest)| blobs.contains(&manifest.digest))
                && blobs.len() as u64 == self.artifact.verified_files
                && bytes == self.artifact.verified_bytes,
            Failure::Integrity,
        )?;
        recheck(watch, &created)?;
        self.result = Some(created.layout);
        Ok(())
    }
}

impl PublicAction for UnpackWork {
    fn apply(&mut self, active: &Active) -> Result<()> {
        self.run(active)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
