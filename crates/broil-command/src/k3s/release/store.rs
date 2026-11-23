// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Refusal, binding::MANIFEST_LIMIT, record, sha256_hex};
use broil_core::secret::path_safety::{effective_uid, sudo_nonce};
use rustix::fs::{Mode, OFlags, RenameFlags};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

pub const RELEASE_LIMIT: usize = 16_384;
const RECORD: &str = "release.json";
const MANIFESTS: &str = "manifests.yaml";
const TRASH: &str = ".trash";

fn storage(detail: impl Into<String>) -> Refusal {
    Refusal::new("storage", "release", detail)
}

fn integrity(detail: impl Into<String>) -> Refusal {
    Refusal::new("integrity", "release", detail)
}

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn owned(file: &File, directory: bool) -> Result<(), Refusal> {
    let m = file
        .metadata()
        .map_err(|_| storage("the release store is unreadable"))?;
    let shape = if directory {
        m.is_dir()
    } else {
        m.is_file() && m.nlink() == 1
    };
    if m.uid() == effective_uid()
        && m.mode() & 0o7777 == if directory { 0o700 } else { 0o600 }
        && shape
    {
        Ok(())
    } else {
        Err(integrity(
            "a release store entry is not the user's private file",
        ))
    }
}

fn open_store(path: &Path) -> Result<File, Refusal> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(storage("the release store path is not absolute"));
    }
    let mut file = File::from(
        rustix::fs::open("/", DIRECTORY, Mode::empty())
            .map_err(|_| storage("the release store is unreadable"))?,
    );
    for part in path.components() {
        if let Component::Normal(name) = part {
            let m = file
                .metadata()
                .map_err(|_| storage("the release store is unreadable"))?;
            if !((m.uid() == 0 || m.uid() == effective_uid())
                && (m.mode() & 0o022 == 0 || m.mode() & 0o1000 != 0))
            {
                return Err(storage("an ancestor of the release store is not trusted"));
            }
            file = File::from(
                rustix::fs::openat(&file, name, DIRECTORY, Mode::empty())
                    .map_err(|_| storage("the release store is unreadable"))?,
            );
        }
    }
    owned(&file, true)?;
    Ok(file)
}

fn child_directory(parent: &File, name: &str) -> Result<Option<File>, Refusal> {
    match rustix::fs::openat(parent, name, DIRECTORY, Mode::empty()) {
        Ok(fd) => {
            let file = File::from(fd);
            owned(&file, true)?;
            Ok(Some(file))
        }
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(integrity(format!("{name} is not a private directory"))),
    }
}

fn names(directory: &File, limit: usize) -> Result<Vec<String>, Refusal> {
    let handle = directory
        .try_clone()
        .map_err(|_| storage("the release store is unreadable"))?;
    let mut result = Vec::new();
    for entry in rustix::fs::Dir::read_from(&handle)
        .map_err(|_| storage("the release store is unreadable"))?
    {
        let entry = entry.map_err(|_| storage("the release store is unreadable"))?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| integrity("a release store name is not UTF-8"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        if result.len() == limit {
            return Err(Refusal::new(
                "bound",
                "store-full",
                format!("the release store holds more than {limit} entries"),
            ));
        }
        result.push(name.to_owned());
    }
    result.sort();
    Ok(result)
}

fn read(directory: &File, name: &str, limit: u64) -> Result<Vec<u8>, Refusal> {
    let mut file = File::from(
        rustix::fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| integrity(format!("{name} is missing or not a regular file")))?,
    );
    owned(&file, false)?;
    let size = file
        .metadata()
        .map_err(|_| storage("the release store is unreadable"))?
        .len();
    if size > limit {
        return Err(integrity(format!("{name} exceeds its bound")));
    }
    let mut bytes = vec![0; size as usize];
    file.read_exact(&mut bytes)
        .map_err(|_| storage("the release store is unreadable"))?;
    let mut extra = [0];
    if file
        .read(&mut extra)
        .map_err(|_| storage("the release store is unreadable"))?
        != 0
    {
        return Err(integrity(format!("{name} changed while read")));
    }
    Ok(bytes)
}

fn valid_release_name(name: &str) -> bool {
    name.strip_prefix("release-").is_some_and(|nonce| {
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn write_private(directory: &File, name: &str, bytes: &[u8]) -> Result<(), Refusal> {
    let mut file = File::from(
        rustix::fs::openat(
            directory,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| storage(format!("{name} could not be created")))?,
    );
    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR)
        .map_err(|_| storage(format!("{name} could not be created")))?;
    owned(&file, false)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| storage(format!("{name} could not be written")))
}

fn remove_temporary(store: &File, name: &str) {
    if let Ok(fd) = rustix::fs::openat(store, name, DIRECTORY, Mode::empty()) {
        for child in [RECORD, MANIFESTS] {
            let _ = rustix::fs::unlinkat(&fd, child, rustix::fs::AtFlags::empty());
        }
    }
    let _ = rustix::fs::unlinkat(store, name, rustix::fs::AtFlags::REMOVEDIR);
}

pub fn publish(store: &Path, record: &Value, manifests: &[u8]) -> Result<(), Refusal> {
    let encoded = record::encode(record)?;
    let name = record["release"].as_str().unwrap_or("");
    if record["manifests"]["bytes"].as_u64() != Some(manifests.len() as u64)
        || record["manifests"]["sha256"].as_str() != Some(sha256_hex(&[manifests]).as_str())
    {
        return Err(integrity("the record does not describe its manifest bytes"));
    }
    let directory = open_store(store)?;
    let temporary = format!(
        ".tmp-{}",
        sudo_nonce().map_err(|_| storage("no randomness for a temporary name"))?
    );
    rustix::fs::mkdirat(&directory, temporary.as_str(), Mode::RWXU)
        .map_err(|_| storage("the release directory could not be created"))?;
    let staged = (|| {
        let child = File::from(
            rustix::fs::openat(&directory, temporary.as_str(), DIRECTORY, Mode::empty())
                .map_err(|_| storage("the release directory could not be opened"))?,
        );
        rustix::fs::fchmod(&child, Mode::RWXU)
            .map_err(|_| storage("the release directory could not be created"))?;
        owned(&child, true)?;
        write_private(&child, MANIFESTS, manifests)?;
        write_private(&child, RECORD, &encoded)?;
        child
            .sync_all()
            .map_err(|_| storage("the release directory could not be synced"))?;
        rustix::fs::renameat_with(
            &directory,
            temporary.as_str(),
            &directory,
            name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| match error {
            rustix::io::Errno::EXIST => integrity(format!("{name} already exists")),
            _ => storage("the release directory could not be published"),
        })
    })();
    if let Err(refusal) = staged {
        remove_temporary(&directory, &temporary);
        return Err(refusal);
    }
    directory.sync_all().map_err(|_| {
        storage(format!(
            "{name} may exist: the release store could not be synced"
        ))
    })
}

pub fn enumerate(store: &Path) -> Result<Vec<Value>, Refusal> {
    let directory = open_store(store)?;
    let mut releases = Vec::new();
    for name in names(&directory, RELEASE_LIMIT + 1)? {
        if name == TRASH {
            child_directory(&directory, TRASH)?;
            continue;
        }
        if !valid_release_name(&name) {
            return Err(integrity(format!(
                "the release store holds an unexplained entry {name}"
            )));
        }
        if releases.len() == RELEASE_LIMIT {
            return Err(Refusal::new(
                "bound",
                "store-full",
                format!("the release store holds more than {RELEASE_LIMIT} releases"),
            ));
        }
        let child = child_directory(&directory, &name)?
            .ok_or_else(|| integrity(format!("{name} vanished during enumeration")))?;
        let children: BTreeSet<String> = names(&child, 3)?.into_iter().collect();
        if children != BTreeSet::from([RECORD.to_owned(), MANIFESTS.to_owned()]) {
            return Err(integrity(format!(
                "{name} does not hold exactly its two files"
            )));
        }
        let value = record::decode(&read(&child, RECORD, record::RECORD_LIMIT as u64)?)?;
        if value["release"] != name.as_str() {
            return Err(integrity(format!("{name} holds another release's record")));
        }
        let manifests = read(&child, MANIFESTS, MANIFEST_LIMIT as u64)?;
        if value["manifests"]["bytes"].as_u64() != Some(manifests.len() as u64)
            || value["manifests"]["sha256"].as_str() != Some(sha256_hex(&[&manifests]).as_str())
        {
            return Err(integrity(format!(
                "{name}'s manifest bytes differ from its record"
            )));
        }
        releases.push(value);
    }
    Ok(releases)
}

pub fn prune(store: &Path, releases: &[String]) -> Result<(), Refusal> {
    if releases.is_empty()
        || matches!(std::fs::symlink_metadata(store), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(());
    }
    let directory = open_store(store)?;
    match rustix::fs::mkdirat(&directory, TRASH, Mode::RWXU) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(storage("the release trash could not be created")),
    }
    let trash =
        child_directory(&directory, TRASH)?.ok_or_else(|| storage("the release trash vanished"))?;
    for name in releases {
        if !valid_release_name(name) {
            return Err(integrity(format!("{name} is not a release ID")));
        }
        match rustix::fs::renameat_with(
            &directory,
            name.as_str(),
            &trash,
            name.as_str(),
            RenameFlags::NOREPLACE,
        ) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(_) => return Err(storage(format!("{name} could not be moved to the trash"))),
        }
    }
    let synced = |file: &File| {
        file.sync_all()
            .map_err(|_| storage("the release store could not be synced"))
    };
    synced(&directory)?;
    synced(&trash)?;
    for name in names(&trash, RELEASE_LIMIT)? {
        if let Some(child) = child_directory(&trash, &name)? {
            for file in names(&child, 3)? {
                rustix::fs::unlinkat(&child, file.as_str(), rustix::fs::AtFlags::empty())
                    .map_err(|_| storage(format!("{name} could not be removed")))?;
            }
        }
        rustix::fs::unlinkat(&trash, name.as_str(), rustix::fs::AtFlags::REMOVEDIR)
            .map_err(|_| storage(format!("{name} could not be removed")))?;
    }
    synced(&trash)
}
