// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    common::*,
    json::Value,
    store::{self, child_directory, identity, open_directory, owned},
    supervise::Active,
};
use broil_core::secret::path_safety::{sudo_nonce, try_lock_exclusive};
use rustix::fs::{Mode, OFlags};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::PathBuf};

pub(crate) struct Lease {
    root: PathBuf,
    scope: Json,
    ca: PathBuf,
    adapter: Json,
    index: String,
    directory: Option<File>,
    directory_identity: Option<(u64, u64)>,
    lock: Option<File>,
    record_identity: Option<(u64, u64)>,
    pub record: Option<Json>,
    pub archive: Option<(PathBuf, u64, String)>,
    pub publication_uncertain: bool,
}

pub(crate) enum Action {
    Open {
        create: bool,
    },
    Save(Json),
    Archive {
        path: PathBuf,
        size: u64,
        digest: String,
    },
}

fn decode(bytes: &[u8], scope: &Json) -> Result<Json> {
    let fields = Value::parse(bytes)?.object(&[
        b"schema",
        b"scope",
        b"owner",
        b"operation",
        b"step",
        b"intent",
        b"observation",
        b"uncertain",
        b"active",
        b"history",
        b"upload_request",
        b"transfer",
        b"removal",
    ])?;
    require(fields[0].number()? == 1, Failure::Protocol)?;
    let owner = fields[2].text()?;
    require(
        owner.get().len() == 32 && hex(owner.get()),
        Failure::Protocol,
    )?;
    let operation = fields[3].text()?;
    require(
        operation.get().len() == 32 && hex(operation.get()),
        Failure::Protocol,
    )?;
    fields[4].number()?;
    let intent = fields[5].text()?;
    require(
        [
            b"inspect".as_slice(),
            b"prepare",
            b"install",
            b"certificate",
            b"key",
            b"activate",
            b"reconcile",
            b"remove",
            b"retained",
            b"purged",
            b"upload",
        ]
        .contains(&intent.get()),
        Failure::Protocol,
    )?;
    fields[7].boolean()?;
    fields[8].boolean()?;
    if !fields[12].is_null() {
        fields[12].boolean()?;
    }
    observation(fields[6])?;
    transfer(fields[11])?;
    if !fields[10].is_null() {
        let upload =
            fields[10].object(&[b"purpose", b"size", b"sha256", b"temporary", b"final"])?;
        require(
            upload[0].equals("archive")? || upload[0].equals("ca")?,
            Failure::Protocol,
        )?;
        require(upload[1].number()? <= 268_435_456, Failure::Limit)?;
        hexadecimal(upload[2], 64, false)?;
        require(
            upload[3].equals("upload.tmp")?
                && (upload[4].equals("archive")? || upload[4].equals("ca")?),
            Failure::Protocol,
        )?;
    }
    let history = fields[9].array()?;
    require(history.len() <= 32, Failure::Limit)?;
    for entry in history {
        let entry = entry.object(&[
            b"operation",
            b"step",
            b"intent",
            b"uncertain",
            b"transfer",
            b"followup_step",
            b"observation",
        ])?;
        hexadecimal(entry[0], 32, false)?;
        require(entry[1].number()? < entry[5].number()?, Failure::Protocol)?;
        require(entry[3].boolean()?, Failure::Protocol)?;
        require(entry[2].text()?.get().len() <= 32, Failure::Protocol)?;
        transfer(entry[4])?;
        observation(entry[6])?;
    }
    let result: Json = serde_json::from_slice(bytes).map_err(|_| Failure::Protocol)?;
    require(&result["scope"] == scope, Failure::Integrity)?;
    Ok(result)
}

fn hexadecimal(value: Value<'_>, size: usize, empty: bool) -> Result<()> {
    let text = value.text()?;
    require(
        (empty && text.get().is_empty()) || (text.get().len() == size && hex(text.get())),
        Failure::Protocol,
    )
}

fn file_identity(value: Value<'_>) -> Result<()> {
    let fields = value.object(&[b"device", b"inode", b"mode", b"uid", b"gid", b"links"])?;
    fields[0].number()?;
    require(
        fields[1].number()? > 0
            && fields[2].number()? <= 0o177777
            && fields[3].number()? <= u32::MAX as u64
            && fields[4].number()? <= u32::MAX as u64
            && fields[5].number()? > 0,
        Failure::Protocol,
    )
}

fn observation(value: Value<'_>) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    let fields = value.object(&[
        b"state",
        b"service",
        b"credentials",
        b"storage",
        b"resources",
        b"generation",
        b"unit_digest",
        b"resumed",
        b"upload",
        b"pending",
        b"inputs",
        b"arm64_emulation",
    ])?;
    super::protocol::known(fields[0], super::protocol::STATES)?;
    for value in &fields[1..4] {
        super::protocol::known(*value, super::protocol::PARTS)?;
    }
    hexadecimal(fields[5], 32, true)?;
    hexadecimal(fields[6], 64, true)?;
    fields[7].boolean()?;
    fields[9].boolean()?;
    fields[11].boolean()?;
    let resources = fields[4].array()?;
    require(resources.len() <= 128, Failure::Limit)?;
    let mut seen = std::collections::BTreeSet::new();
    for value in resources {
        let resource = value.object(&[b"name", b"device", b"inode", b"mode", b"uid", b"size"])?;
        require(seen.insert(resource_name(resource[0])?), Failure::Protocol)?;
        require(
            resource[0].text()?.get().len() <= 256
                && resource[2].number()? > 0
                && matches!(resource[3].number()? & 0o170000, 0o040000 | 0o100000)
                && resource[4].number()? <= u32::MAX as u64
                && resource[5].number()? <= 536_870_912,
            Failure::Protocol,
        )?;
        resource[1].number()?;
    }
    for (key, value) in fields[10].members()? {
        require(
            key.equals("archive")? || key.equals("ca")?,
            Failure::Protocol,
        )?;
        let name = super::protocol::scoped_resource(value, u64::MAX)?;
        require(
            name.starts_with("incoming/") && seen.contains(&name),
            Failure::Protocol,
        )?;
    }
    if !fields[8].is_null() {
        let upload =
            fields[8].object(&[b"binding", b"claim", b"identity", b"length", b"sha256"])?;
        let binding = upload[0].object(&[
            b"protocol",
            b"owner",
            b"operation",
            b"step",
            b"scope",
            b"container",
            b"purpose",
            b"temporary",
            b"final",
            b"size",
            b"sha256",
        ])?;
        require(
            binding[0].number()? == 1
                && binding[3].number()? > 0
                && binding[9].number()? <= 268_435_456,
            Failure::Protocol,
        )?;
        hexadecimal(binding[1], 32, false)?;
        hexadecimal(binding[2], 32, false)?;
        hexadecimal(binding[4], 64, false)?;
        hexadecimal(binding[10], 64, false)?;
        file_identity(binding[5])?;
        file_identity(upload[2])?;
        let purpose = super::protocol::known(binding[6], &["archive", "ca"])?;
        require(
            binding[7].equals("upload.tmp")? && binding[8].equals(purpose)?,
            Failure::Protocol,
        )?;
        require(
            upload[1].equals(&format!("claim-{}.json", binding[3].number()?))?
                && upload[3].number()? <= 65_536,
            Failure::Protocol,
        )?;
        hexadecimal(upload[4], 64, false)?;
    }
    Ok(())
}

fn resource_name(value: Value<'_>) -> Result<String> {
    let text = value.text()?;
    let name = std::str::from_utf8(text.get()).map_err(|_| Failure::Protocol)?;
    if [
        "root",
        "owner.json",
        "bin",
        "tls",
        "state",
        "incoming",
        "ca.pem",
        "unit",
        "bin/buildkitd",
        "bin/buildkit-runc",
        "bin/buildkit-qemu-aarch64",
    ]
    .contains(&name)
    {
        return Ok(name.to_string());
    }
    if let Some(generation) = name.strip_prefix("tls/") {
        let (generation, suffix) = generation.split_once('/').unwrap_or((generation, ""));
        require(
            generation.len() == 32
                && hex(generation.as_bytes())
                && ["", "certificate", "key"].contains(&suffix),
            Failure::Protocol,
        )?;
        return Ok(name.to_string());
    }
    super::protocol::scoped_resource(value, u64::MAX)
}

fn transfer(value: Value<'_>) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    let fields = value.object(&[
        b"launcher_dispatched",
        b"mutation_dispatched",
        b"transfer_complete",
        b"remote_status",
        b"staging_residue",
        b"unresolved_session",
        b"temporary",
        b"destination",
    ])?;
    for index in [0, 1, 2, 4, 5] {
        fields[index].boolean()?;
    }
    if !fields[3].is_null() {
        require(fields[3].number()? <= i32::MAX as u64, Failure::Protocol)?;
    }
    require(
        fields[6].text()?.get().len() <= 4096 && fields[7].text()?.get().len() <= 4096,
        Failure::Protocol,
    )
}

impl Lease {
    pub(crate) fn new(root: PathBuf, scope: Json, ca: PathBuf, adapter: Json) -> Result<Self> {
        require(valid_path(&root), Failure::Policy)?;
        let bytes = serde_json::to_vec(&scope).map_err(|_| Failure::Protocol)?;
        require(bytes.len() <= 32_768, Failure::Limit)?;
        let index = String::new();
        require(valid_path(&ca), Failure::Policy)?;
        Ok(Self {
            root,
            scope,
            ca,
            adapter,
            index,
            directory: None,
            directory_identity: None,
            lock: None,
            record_identity: None,
            record: None,
            archive: None,
            publication_uncertain: false,
        })
    }

    pub(crate) fn scope_digest(&self) -> &str {
        &self.index
    }
    pub(crate) fn scope(&self) -> &Json {
        &self.scope
    }
    pub(crate) fn path(&self) -> PathBuf {
        self.root
            .join("state/builders")
            .join(format!("{}.json", self.index))
    }

    fn recheck(&self, active: &Active) -> Result<()> {
        let directory = open_directory(&self.root.join("state/builders"), active)?;
        owned(&directory, true, active)?;
        require(
            Some(identity(&directory, active)?) == self.directory_identity,
            Failure::Integrity,
        )?;
        let lock = self.lock.as_ref().ok_or(Failure::Integrity)?;
        let current = File::from(active.sys(|| {
            rustix::fs::openat(
                &directory,
                format!("{}.lock", self.index),
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        owned(&current, false, active)?;
        require(
            identity(&current, active)? == identity(lock, active)?,
            Failure::Integrity,
        )
    }

    fn open(&mut self, create: bool, active: &Active) -> Result<()> {
        require(self.directory.is_none(), Failure::Policy)?;
        let root = open_directory(&self.root, active)?;
        let m = active.io(|| root.metadata())?;
        self.scope["project_device"] = json!(m.dev());
        self.scope["project_inode"] = json!(m.ino());
        let adapter = serde_json::to_vec(&self.adapter).map_err(|_| Failure::Protocol)?;
        require(adapter.len() <= 1_048_576, Failure::Limit)?;
        active.check()?;
        self.scope["adapter_sha256"] = json!(super::public_hex(&Sha256::digest(&adapter)));
        let parent = open_directory(self.ca.parent().ok_or(Failure::Policy)?, active)?;
        let mut ca = File::from(active.sys(|| {
            rustix::fs::openat(
                &parent,
                self.ca.file_name().ok_or(rustix::io::Errno::INVAL)?,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        let m = active.io(|| ca.metadata())?;
        require(
            m.is_file() && m.len() > 0 && m.len() <= 1_048_576 && m.mode() & 0o022 == 0,
            Failure::Policy,
        )?;
        let mut scratch = [0; 65_536];
        let mut hash = Sha256::new();
        let mut count = 0u64;
        loop {
            let n = active.io(|| ca.read(&mut scratch))?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n as u64)
                .filter(|n| *n <= m.len())
                .ok_or(Failure::Limit)?;
            hash.update(&scratch[..n]);
        }
        require(count == m.len(), Failure::Integrity)?;
        self.scope["ca_sha256"] = json!(super::public_hex(&hash.finalize()));
        self.scope["ca_size"] = json!(count);
        self.index = super::public_hex(&Sha256::digest(
            serde_json::to_vec(&self.scope).map_err(|_| Failure::Protocol)?,
        ));
        active.check()?;
        let state = child_directory(&root, "state", create, active)?;
        let directory = child_directory(&state, "builders", create, active)?;
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        if create {
            flags |= OFlags::CREATE;
        }
        let lock = File::from(active.sys(|| {
            rustix::fs::openat(
                &directory,
                format!("{}.lock", self.index),
                flags,
                Mode::RUSR | Mode::WUSR,
            )
        })?);
        owned(&lock, false, active)?;
        require(active.io(|| try_lock_exclusive(&lock))?, Failure::Capacity)?;
        self.directory_identity = Some(identity(&directory, active)?);
        self.lock = Some(lock);
        self.directory = Some(directory);
        self.recheck(active)?;
        let name = format!("{}.json", self.index);
        let read = store::read(
            self.directory.as_ref().ok_or(Failure::Integrity)?,
            &name,
            65_536,
            active,
        );
        match read {
            Ok(Some((bytes, identity))) => {
                self.record_identity = Some(identity);
                self.record = Some(decode(&bytes, &self.scope)?);
            }
            Ok(None) if create => {
                let owner = sudo_nonce().map_err(|_| Failure::Storage)?;
                let operation = sudo_nonce().map_err(|_| Failure::Storage)?;
                self.save(
                    json!({"schema":1,"scope":self.scope,"owner":owner,"operation":operation,
                    "step":0,"intent":"inspect","observation":null,"uncertain":false,
                    "active":false,"history":[],"upload_request":null,"transfer":null,"removal":null}),
                    active,
                )?;
            }
            Ok(None) => return Err(Failure::Storage),
            Err(failure) => return Err(failure),
        }
        Ok(())
    }

    fn save(&mut self, value: Json, active: &Active) -> Result<()> {
        self.recheck(active)?;
        let bytes = serde_json::to_vec(&value).map_err(|_| Failure::Protocol)?;
        decode(&bytes, &self.scope)?;
        if let Some(record) = &self.record {
            require(record["owner"] == value["owner"], Failure::Integrity)?;
        }
        let directory = self.directory.as_ref().ok_or(Failure::Integrity)?;
        let name = format!("{}.json", self.index);
        let temporary = format!(
            "{}.{}.partial",
            self.index,
            sudo_nonce().map_err(|_| Failure::Storage)?
        );
        let prepared = store::prepare(directory, temporary, &bytes, active)?;
        self.recheck(active)?;
        self.publication_uncertain = true;
        let identity = store::publish(directory, prepared, &name, self.record_identity, active)?;
        self.publication_uncertain = true;
        self.record_identity = Some(identity);
        self.record = Some(value);
        store::sync_parent(directory, active)?;
        self.publication_uncertain = false;
        Ok(())
    }

    fn archive(&mut self, path: PathBuf, size: u64, digest: String, active: &Active) -> Result<()> {
        require(
            valid_path(&path)
                && size > 0
                && size <= 268_435_456
                && digest.len() == 64
                && hex(digest.as_bytes()),
            Failure::Policy,
        )?;
        let parent = open_directory(path.parent().ok_or(Failure::Policy)?, active)?;
        let mut file = File::from(active.sys(|| {
            rustix::fs::openat(
                &parent,
                path.file_name().ok_or(rustix::io::Errno::INVAL)?,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })?);
        let before = active.io(|| file.metadata())?;
        require(before.is_file() && before.len() == size, Failure::Integrity)?;
        let mut hash = Sha256::new();
        let mut scratch = [0; 65_536];
        let mut count = 0u64;
        loop {
            let n = active.io(|| file.read(&mut scratch))?;
            if n == 0 {
                break;
            }
            count = count
                .checked_add(n as u64)
                .filter(|n| *n <= size)
                .ok_or(Failure::Limit)?;
            hash.update(&scratch[..n]);
        }
        require(
            count == size && super::public_hex(&hash.finalize()) == digest,
            Failure::Integrity,
        )?;
        let after = active.io(|| file.metadata())?;
        require(
            before.dev() == after.dev() && before.ino() == after.ino() && after.len() == size,
            Failure::Integrity,
        )?;
        self.archive = Some((path, size, digest));
        Ok(())
    }
}

impl Action {
    pub(crate) fn apply(self, lease: &mut Lease, active: &Active) -> Result<()> {
        match self {
            Self::Open { create } => lease.open(create, active),
            Self::Save(value) => lease.save(value, active),
            Self::Archive { path, size, digest } => lease.archive(path, size, digest, active),
        }
    }
}
