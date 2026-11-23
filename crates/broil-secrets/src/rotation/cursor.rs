// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    read::{Error, Result},
    store::{Marker, RollbackStage, SetId},
};
use broil_core::secret::{normalize_path, path_safety as safe};
use rustix::fs::{self, AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

const LIMIT: usize = 2 * 1024 * 1024;
pub(super) struct Cursor {
    directory: PathBuf,
}
impl Cursor {
    pub(super) fn new(base: &Path, store: &Path) -> Result<Self> {
        if !base.is_absolute() || !store.is_absolute() {
            return Err(error());
        }
        let store = normalize_path(Path::new("/"), store);
        let mut hash = String::with_capacity(64);
        for byte in Sha256::digest(store.as_os_str().as_bytes()) {
            use std::fmt::Write;
            write!(hash, "{byte:02x}").expect("String write");
        }
        Ok(Self {
            directory: normalize_path(Path::new("/"), base)
                .join("broil/rotations")
                .join(hash),
        })
    }
    pub(super) fn path(&self, id: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            return Err(error());
        }
        Ok(self.directory.join(format!("{id}.json")))
    }
    fn open(&self, create: bool) -> Result<Option<File>> {
        let mut directory = File::from(
            fs::open(
                "/",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| error())?,
        );
        let count = self.directory.components().count();
        for (i, part) in self.directory.components().enumerate() {
            let Component::Normal(name) = part else {
                continue;
            };
            if create {
                match fs::mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) => directory.sync_all().map_err(|_| error())?,
                    Err(rustix::io::Errno::EXIST) => (),
                    Err(_) => return Err(error()),
                }
            }
            directory = match fs::openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => File::from(fd),
                Err(rustix::io::Errno::NOENT) if !create => return Ok(None),
                Err(_) => return Err(error()),
            };
            let m = directory.metadata().map_err(|_| error())?;
            if !m.is_dir() || ![0, safe::effective_uid()].contains(&m.uid()) {
                return Err(error());
            }
            if i + 3 >= count && (m.uid() != safe::effective_uid() || m.mode() & 0o777 != 0o700) {
                return Err(error());
            }
        }
        Ok(Some(directory))
    }
    fn read(directory: &File, name: &OsStr) -> Result<Option<Vec<u8>>> {
        let file = match fs::openat(
            directory,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(error()),
        };
        let m = file.metadata().map_err(|_| error())?;
        if !m.is_file()
            || m.uid() != safe::effective_uid()
            || m.mode() & 0o777 != 0o600
            || m.len() > LIMIT as u64
        {
            return Err(error());
        }
        let mut bytes = Vec::new();
        file.take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| error())?;
        if bytes.len() > LIMIT {
            return Err(error());
        }
        Ok(Some(bytes))
    }
    pub(super) fn reconcile(
        &self,
        set: &SetId,
        key: &str,
        marker: &Marker,
        authenticated: bool,
        active: bool,
    ) -> Result<bool> {
        let path = self.path(&marker.id)?;
        let directory = self.open(true)?.ok_or_else(error)?;
        let rollback=marker.rollback.as_ref().map(|r|serde_json::json!({"stage":match r.stage {RollbackStage::Sync=>"sync",RollbackStage::Handlers=>"handlers",RollbackStage::Finish=>"finish"},"from_state":r.from_state.as_str(),"remaining":r.remaining.iter().map(|s|s.as_str()).collect::<Vec<_>>()}));
        let wanted = serde_json::json!({"version":1,"set":set.as_str(),"key":key,"id":marker.id,"state":marker.state.as_str(),"in_progress":marker.in_progress,"operator":marker.operator,"host":marker.host,"started":marker.started,"rollback":rollback,"authenticated":authenticated,"active":active});
        let bytes = serde_json::to_vec(&wanted).map_err(|_| error())?;
        if bytes.len() > LIMIT {
            return Err(error());
        }
        let name = path.file_name().ok_or_else(error)?;
        let before = Self::read(&directory, name)?;
        if before.as_deref() == Some(&bytes) {
            return Ok(false);
        }
        let nonce = safe::sudo_nonce().map_err(|_| error())?;
        let temporary = format!(".cursor-{nonce}");
        let mut temp = File::from(
            fs::openat(
                &directory,
                &temporary,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| error())?,
        );
        let result = (|| {
            temp.write_all(&bytes)
                .and_then(|()| temp.sync_all())
                .map_err(|_| error())?;
            Self::read(&directory, name)?;
            let fresh = self.open(false)?.ok_or_else(error)?;
            let a = directory.metadata().map_err(|_| error())?;
            let b = fresh.metadata().map_err(|_| error())?;
            if a.dev() != b.dev() || a.ino() != b.ino() {
                return Err(error());
            }
            fs::renameat(&directory, &temporary, &directory, name).map_err(|_| error())?;
            directory.sync_all().map_err(|_| error())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&directory, &temporary, AtFlags::empty());
        }
        result?;
        Ok(true)
    }
    pub(super) fn historical(
        &self,
        sets: &[SetId],
        key: Option<&str>,
        active_ids: &[String],
    ) -> Result<Vec<String>> {
        let Some(directory) = self.open(false)? else {
            return Ok(Vec::new());
        };
        let mut result = Vec::new();
        let mut count = 0;
        for entry in fs::Dir::read_from(&directory).map_err(|_| error())? {
            count += 1;
            if count > 65536 {
                return Err(error());
            }
            let entry = entry.map_err(|_| error())?;
            let name = entry.file_name();
            let Ok(name) = name.to_str() else {
                continue;
            };
            let Some(id) = name.strip_suffix(".json").filter(|s| valid_id(s)) else {
                continue;
            };
            if active_ids.iter().any(|s| s == id) {
                continue;
            }
            let Some(bytes) = Self::read(&directory, OsStr::new(name))? else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            if value.get("id").and_then(|v| v.as_str()) != Some(id) {
                continue;
            }
            if !sets
                .iter()
                .any(|s| Some(s.as_str()) == value.get("set").and_then(|v| v.as_str()))
            {
                continue;
            }
            if key.is_some_and(|k| Some(k) != value.get("key").and_then(|v| v.as_str())) {
                continue;
            }
            result.push(id.to_owned());
        }
        result.sort();
        Ok(result)
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 22
        && id.as_bytes()[..14].iter().all(u8::is_ascii_digit)
        && id.as_bytes()[14..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}
fn error() -> Error {
    Error::class(
        "rotation cursor unavailable or unsafe; inspect the authoritative store marker before resume",
    )
}
