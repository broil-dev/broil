// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    filesystem::{self as fs, DirectoryPlan, Target, checkpoint},
    *,
};
use rustix::fs::{AtFlags, Mode, OFlags};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
};
use zeroize::Zeroizing;

const MAX_BATCH_BYTES: usize = 256 * 1024 * 1024;

struct Item {
    parents: DirectoryPlan,
    target: Option<Target>,
    private: bool,
    original: Option<Zeroizing<Vec<u8>>>,
    candidate: Option<Option<Zeroizing<Vec<u8>>>>,
    applied: bool,
}

pub(crate) struct Admin<'a> {
    session: &'a WriteSession<'a>,
    items: BTreeMap<String, Item>,
    inventories: BTreeMap<String, Vec<String>>,
    sets: Option<BTreeSet<String>>,
    created: BTreeMap<PathBuf, File>,
    recovery: Option<Recovery>,
    recovery_location: Option<PathBuf>,
    pub changed: Vec<String>,
    pub uncertain: Vec<String>,
    pub restored: Vec<String>,
    pub failed_path: Option<String>,
    pub cleanup_failed: bool,
}

impl WriteSession<'_> {
    pub(crate) fn admin(&self) -> Admin<'_> {
        Admin {
            session: self,
            items: BTreeMap::new(),
            inventories: BTreeMap::new(),
            sets: None,
            created: BTreeMap::new(),
            recovery: None,
            recovery_location: None,
            changed: Vec::new(),
            uncertain: Vec::new(),
            restored: Vec::new(),
            failed_path: None,
            cleanup_failed: false,
        }
    }
}

fn copy(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if bytes.len() > sops::MAX_DOCUMENT_BYTES {
        return Err(ErrorKind::SizeLimit.into());
    }
    let mut result = Zeroizing::new(Vec::new());
    result
        .try_reserve_exact(bytes.len())
        .map_err(|_| ErrorKind::Allocation)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

impl Admin<'_> {
    pub fn store(&self) -> &Store {
        self.session.store
    }
    pub fn sets(&mut self) -> Result<Vec<SetId>> {
        let sets = self.store().sets()?;
        if self.sets.is_none() {
            self.sets = Some(sets.iter().map(SetId::file_path).collect());
        }
        Ok(sets)
    }
    fn capture(&mut self, path: &str, private: bool) -> Result<()> {
        if !broil_core::secrets::valid_relative_file(path) || path.split('/').count() > 128 {
            return Err(ErrorKind::InvalidName.into());
        }
        if let Some(item) = self.items.get_mut(path) {
            item.private |= private;
            if let Some(target) = &mut item.target {
                target.private |= private;
            }
            return Ok(());
        }
        if self.recovery.is_some() {
            return Err(ErrorKind::Stale.into());
        }
        if self.items.len() >= 65536 {
            return Err(ErrorKind::SizeLimit.into());
        }
        let absolute = self.store().root.join(path);
        let parents = DirectoryPlan::inspect(absolute.parent().ok_or(ErrorKind::InvalidName)?)?;
        let (target, original) = if parents.exists() {
            let mut target = self.store().target(path.into(), private, false)?;
            let bytes = if fs::open_entry(&target.parent, &target.name)?.is_some() {
                Some(target.load_bytes()?)
            } else {
                None
            };
            target.fresh(self.store())?;
            (Some(target), bytes)
        } else {
            (None, None)
        };
        self.items.insert(
            path.into(),
            Item {
                parents,
                target,
                private,
                original,
                candidate: None,
                applied: false,
            },
        );
        self.bound()
    }
    fn bound(&self) -> Result<()> {
        let total = self
            .items
            .values()
            .try_fold(0usize, |n, item| {
                n.checked_add(item.original.as_ref().map_or(0, |b| b.len()))
                    .and_then(|n| {
                        n.checked_add(
                            item.candidate
                                .as_ref()
                                .and_then(Option::as_ref)
                                .map_or(0, |b| b.len()),
                        )
                    })
            })
            .ok_or(ErrorKind::SizeLimit)?;
        if total > MAX_BATCH_BYTES {
            return Err(ErrorKind::SizeLimit.into());
        }
        Ok(())
    }
    pub fn read(&mut self, path: &str, private: bool) -> Result<Option<Plaintext>> {
        self.capture(path, private)?;
        self.fresh_item(path)?;
        self.items[path]
            .original
            .as_ref()
            .map(|b| Plaintext::from_bytes(copy(b)?).map_err(Into::into))
            .transpose()
    }
    pub fn read_bytes(&mut self, path: &str, private: bool) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.capture(path, private)?;
        self.fresh_item(path)?;
        self.items[path]
            .original
            .as_ref()
            .map(|b| copy(b))
            .transpose()
    }
    pub fn document(
        &mut self,
        path: &str,
        private: bool,
        keys: &[age::Identity],
    ) -> Result<Document> {
        let bytes = self.read(path, private)?.ok_or(ErrorKind::Missing)?;
        let document = sops::decrypt(bytes, keys)?;
        document.ensure_writable()?;
        owned::validate(document.data(), document.selector())?;
        Ok(document)
    }
    pub fn candidate_document(&self, path: &str, keys: &[age::Identity]) -> Result<Document> {
        self.fresh_item(path)?;
        let item = &self.items[path];
        let bytes = match &item.candidate {
            Some(Some(bytes)) => bytes,
            Some(None) => return Err(ErrorKind::Missing.into()),
            None => item.original.as_ref().ok_or(ErrorKind::Missing)?,
        };
        Ok(sops::decrypt(Plaintext::from_bytes(copy(bytes)?)?, keys)?)
    }
    pub fn credential_replacement(
        &mut self,
        original: &str,
        keys: &[age::Identity],
        fields: &[(&str, &str)],
        rule: &sops::CreationRule,
    ) -> Result<Plaintext> {
        let document = self.document(original, true, keys)?;
        let mut candidate = document.data().duplicate()?;
        for (name, value) in fields {
            candidate.put(name, Value::string(value)?)?;
        }
        if !fields.iter().any(|(name, _)| *name == "unseal_key")
            && candidate.get("unseal_key").is_some()
        {
            candidate.take("unseal_key")?;
        }
        owned::generic_candidate(&document, &candidate)?;
        let rewritten = document.rewrite(candidate)?;
        drop(document);
        Ok(sops::decrypt(rewritten, keys)?.rewrap(rule)?)
    }
    pub fn recovery_public(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        validate_component(name)?;
        self.recovery
            .as_mut()
            .ok_or(ErrorKind::Missing)?
            .write(name, bytes)
    }
    pub fn set(&mut self, path: &str, private: bool, bytes: &[u8]) -> Result<()> {
        self.capture(path, private)?;
        let item = self.items.get_mut(path).unwrap();
        if item.applied {
            return Err(ErrorKind::Stale.into());
        }
        item.candidate = if item.original.as_deref().is_some_and(|old| old == bytes) {
            None
        } else {
            Some(Some(copy(bytes)?))
        };
        self.bound()?;
        if self.recovery.is_some() {
            self.save_candidate(path)?;
        }
        Ok(())
    }
    pub fn delete(&mut self, path: &str, private: bool) -> Result<()> {
        self.capture(path, private)?;
        let item = self.items.get_mut(path).unwrap();
        if item.applied {
            return Err(ErrorKind::Stale.into());
        }
        if item.original.is_some() {
            item.candidate = Some(None);
        }
        Ok(())
    }
    pub fn names(&mut self, directory: &str) -> Result<Vec<String>> {
        validate_component(directory)?;
        let names = self.current_names(directory)?;
        self.inventories
            .entry(directory.into())
            .or_insert_with(|| names.clone());
        Ok(names)
    }
    fn current_names(&self, directory: &str) -> Result<Vec<String>> {
        if fs::open_entry(&self.store().directory, OsStr::new(directory))?.is_none() {
            return Ok(Vec::new());
        }
        fs::names(&fs::open_dir(
            &self.store().directory,
            OsStr::new(directory),
        )?)?
        .into_iter()
        .map(|n| n.into_string().map_err(|_| ErrorKind::InvalidName.into()))
        .collect()
    }
    fn fresh_item(&self, path: &str) -> Result<()> {
        let item = &self.items[path];
        item.parents.fresh_with_created(&self.created)?;
        if let Some(target) = &item.target {
            target.fresh(self.store())?;
        }
        Ok(())
    }
    pub fn fresh(&self) -> Result<()> {
        self.store().root_current()?;
        for path in self.items.keys() {
            self.fresh_item(path)?;
        }
        for (directory, before) in &self.inventories {
            let mut expected = before.clone();
            for (path, item) in &self.items {
                if !item.applied {
                    continue;
                }
                if let Some(name) = path
                    .strip_prefix(&format!("{directory}/"))
                    .filter(|s| !s.contains('/'))
                {
                    expected.retain(|n| n != name);
                    if item.target.as_ref().is_some_and(|t| t.original.is_some()) {
                        expected.push(name.into());
                    }
                }
            }
            expected.sort();
            if expected != self.current_names(directory)? {
                return Err(ErrorKind::Stale.into());
            }
        }
        if let Some(before) = &self.sets {
            let mut expected = before.clone();
            for (path, item) in &self.items {
                if !item.applied
                    || path
                        .strip_suffix(".yaml")
                        .is_none_or(|s| SetId::new(s).is_err())
                {
                    continue;
                }
                expected.remove(path);
                if item.target.as_ref().is_some_and(|t| t.original.is_some()) {
                    expected.insert(path.clone());
                }
            }
            if self
                .store()
                .sets()?
                .iter()
                .map(SetId::file_path)
                .collect::<BTreeSet<_>>()
                != expected
            {
                return Err(ErrorKind::Stale.into());
            }
        }
        Ok(())
    }
    pub fn stage_recovery(&mut self) -> Result<()> {
        checkpoint("admin-preflight")?;
        self.fresh()?;
        if self.recovery.is_some() {
            return Err(ErrorKind::Exists.into());
        }
        let base = std::env::temp_dir();
        if base.starts_with(self.store().root()) {
            return Err(ErrorKind::UnsafePath.into());
        }
        let location = base.join(format!(
            "broil-user-recovery-{}",
            safe::sudo_nonce().map_err(|_| ErrorKind::Randomness)?
        ));
        self.recovery_location = Some(location.clone());
        self.recovery = Some(Recovery::new(&location)?);
        let mut index = String::new();
        for (i, (path, item)) in self.items.iter().enumerate() {
            index.push_str(&format!(
                "{i}\t{}\t{}\n",
                crate::output::public_name(path),
                if item.original.is_some() {
                    "original"
                } else {
                    "absent"
                }
            ));
            if let Some(bytes) = &item.original {
                self.recovery
                    .as_mut()
                    .unwrap()
                    .write(&format!("{i}.original"), bytes)?;
            }
        }
        self.recovery
            .as_mut()
            .unwrap()
            .write("paths.tsv", index.as_bytes())?;
        for path in self.items.keys().cloned().collect::<Vec<_>>() {
            self.save_candidate(&path)?;
        }
        self.fresh()
    }
    fn save_candidate(&mut self, path: &str) -> Result<()> {
        let i = self
            .items
            .keys()
            .position(|p| p == path)
            .ok_or(ErrorKind::Missing)?;
        if let Some(Some(bytes)) = &self.items[path].candidate {
            self.recovery
                .as_mut()
                .unwrap()
                .write(&format!("{i}.candidate"), bytes)?;
        }
        Ok(())
    }
    pub fn apply(&mut self) -> Result<()> {
        if self.recovery.is_none() {
            return Err(ErrorKind::Missing.into());
        }
        self.fresh()?;
        let paths = self
            .items
            .iter()
            .filter(|(_, i)| i.candidate.is_some())
            .map(|(p, _)| p.clone())
            .collect::<Vec<_>>();
        for path in paths {
            self.failed_path = Some(path.clone());
            self.fresh()?;
            checkpoint("admin-before-write")?;
            self.fresh()?;
            let absolute = self.store().root.join(&path);
            let parents = DirectoryPlan::inspect(absolute.parent().ok_or(ErrorKind::InvalidName)?)?;
            let mut made = Vec::new();
            let result = parents.create(|p| made.push(p.to_path_buf()));
            for p in made {
                self.changed
                    .push(init::relative_directory(&self.store().root, &p));
                let opened =
                    safe::defensive_open_directory_no_symlink(&p).map_err(|_| ErrorKind::Stale)?;
                self.created.insert(p, opened);
            }
            let parent = result?;
            let store = self.session.store;
            let item = self.items.get_mut(&path).unwrap();
            if item.target.is_none() {
                let target = store.target(path.clone(), item.private, false)?;
                if !fs::same_inode(&parent, &target.parent)? {
                    return Err(ErrorKind::Stale.into());
                }
                item.target = Some(target);
            }
            let target = item.target.as_mut().unwrap();
            let mut installed = None;
            let mut deleted = false;
            let result = match item.candidate.as_ref().unwrap() {
                Some(bytes) => fs::replace_observed(store, target, bytes, None, &mut installed),
                None => delete(store, target, &mut deleted),
            };
            if installed.is_some() || deleted {
                target.original = installed;
                item.applied = true;
            }
            match result {
                Ok(_) => self.changed.push(path.clone()),
                Err(error) => {
                    self.cleanup_failed |= error.cleanup_failed;
                    if error.disposition != Disposition::Unchanged {
                        self.uncertain.push(path.clone());
                    }
                    return Err(error);
                }
            }
        }
        self.failed_path = None;
        self.fresh()
    }
    pub fn rollback(&mut self) -> Result<()> {
        let mut failed = self
            .uncertain
            .iter()
            .any(|path| self.items.get(path).is_none_or(|item| !item.applied));
        let paths = self
            .items
            .iter()
            .filter(|(_, i)| i.applied)
            .map(|(p, _)| p.clone())
            .collect::<Vec<_>>();
        for path in paths.into_iter().rev() {
            let store = self.session.store;
            let item = self.items.get_mut(&path).unwrap();
            let target = item.target.as_mut().unwrap();
            let result = (|| {
                checkpoint("admin-restore")?;
                target.fresh(store)?;
                let mut installed = None;
                let result = if let Some(bytes) = &item.original {
                    fs::replace_observed(store, target, bytes, None, &mut installed)
                } else {
                    delete(store, target, &mut false)
                };
                if result.is_ok() {
                    target.original = installed;
                    item.applied = false;
                }
                result
            })();
            if result.is_ok() {
                self.restored.push(path);
            } else {
                failed = true;
            }
        }
        if failed {
            Err(ErrorKind::Stale.into())
        } else {
            Ok(())
        }
    }
    pub fn verify_documents(&self, keys: &[age::Identity]) -> Result<()> {
        self.fresh()?;
        for (path, item) in &self.items {
            if !matches!(item.candidate, Some(Some(_)))
                || !(path.starts_with("credentials/")
                    || path
                        .strip_suffix(".yaml")
                        .is_some_and(|s| SetId::new(s).is_ok()))
            {
                continue;
            }
            let (_, document) = self.store().load(path.clone(), item.private, keys)?;
            document.ensure_writable()?;
            owned::validate(document.data(), document.selector())?;
        }
        self.fresh()
    }
    pub fn verify_candidate(
        &self,
        path: &str,
        private: bool,
        keys: &[age::Identity],
    ) -> Result<()> {
        self.fresh()?;
        checkpoint("admin-verify-candidate")?;
        let bytes = self
            .items
            .get(path)
            .and_then(|i| i.candidate.as_ref())
            .and_then(Option::as_ref)
            .ok_or(ErrorKind::Missing)?;
        let mut target = self.store().target(path.into(), private, false)?;
        let persisted = target.load_bytes()?;
        if persisted.as_slice() != bytes.as_slice() {
            return Err(ErrorKind::Stale.into());
        }
        let document = sops::decrypt(Plaintext::from_bytes(persisted)?, keys)?;
        document.ensure_writable()?;
        owned::validate(document.data(), document.selector())?;
        drop(document);
        target.fresh(self.store())?;
        self.fresh()
    }
    pub fn recovery_path(&self) -> Option<&Path> {
        self.recovery_location.as_deref()
    }
    pub fn cleanup(&mut self) -> Result<()> {
        if let Some(recovery) = &mut self.recovery {
            recovery.cleanup()?;
        } else if self.recovery_location.is_some() {
            return Err(ErrorKind::Io.into());
        }
        self.recovery = None;
        self.recovery_location = None;
        Ok(())
    }
}

fn delete(store: &Store, target: &Target, deleted: &mut bool) -> Result<Disposition> {
    target.fresh(store)?;
    if target.original.is_none() {
        return Ok(Disposition::Unchanged);
    }
    checkpoint("admin-delete")?;
    target.fresh(store)?;
    fs::sys(rustix::fs::unlinkat(
        &target.parent,
        &target.name,
        AtFlags::empty(),
    ))?;
    *deleted = true;
    (|| {
        checkpoint("admin-delete-sync")?;
        fs::io(target.parent.sync_all())?;
        Ok(Disposition::Changed)
    })()
    .map_err(|mut e: Error| {
        e.disposition = Disposition::MayHaveChanged;
        e
    })
}

struct Recovery {
    parent: File,
    name: String,
    directory: File,
    files: BTreeMap<String, File>,
}
impl Recovery {
    fn new(path: &Path) -> Result<Self> {
        let base = path.parent().ok_or(ErrorKind::InvalidName)?;
        let parent =
            safe::defensive_open_directory_no_symlink(base).map_err(|_| ErrorKind::UnsafePath)?;
        fs::directory(&parent, false)?;
        let parent = safe::reopen_for_read(&parent).map_err(|_| ErrorKind::UnsafePath)?;
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or(ErrorKind::InvalidName)?
            .to_owned();
        fs::sys(rustix::fs::mkdirat(
            &parent,
            name.as_str(),
            Mode::from_raw_mode(0o700),
        ))?;
        let directory = fs::open_dir(&parent, OsStr::new(&name))?;
        fs::sys(rustix::fs::fchmod(&directory, Mode::from_raw_mode(0o700)))?;
        fs::directory(&directory, true)?;
        fs::io(parent.sync_all())?;
        Ok(Self {
            parent,
            name,
            directory,
            files: BTreeMap::new(),
        })
    }
    fn write(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        checkpoint("admin-recovery-write")?;
        if let Some(old) = self.files.get(name) {
            if !fs::open_entry(&self.directory, OsStr::new(name))?
                .is_some_and(|f| fs::same_inode(&f, old).unwrap_or(false))
            {
                return Err(ErrorKind::Stale.into());
            }
            fs::sys(rustix::fs::unlinkat(
                &self.directory,
                name,
                AtFlags::empty(),
            ))?;
        }
        let mut file = File::from(fs::sys(rustix::fs::openat(
            &self.directory,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ))?);
        fs::sys(rustix::fs::fchmod(&file, Mode::from_raw_mode(0o600)))?;
        fs::io(file.write_all(bytes))?;
        fs::io(file.sync_all())?;
        self.files.insert(name.into(), file);
        fs::io(self.directory.sync_all())
    }
    fn cleanup(&mut self) -> Result<()> {
        checkpoint("admin-recovery-cleanup")?;
        for name in self.files.keys().cloned().collect::<Vec<_>>() {
            if !fs::open_entry(&self.directory, OsStr::new(&name))?
                .is_some_and(|f| fs::same_inode(&f, &self.files[&name]).unwrap_or(false))
            {
                return Err(ErrorKind::Stale.into());
            }
            fs::sys(rustix::fs::unlinkat(
                &self.directory,
                name.as_str(),
                AtFlags::empty(),
            ))?;
            self.files.remove(&name);
        }
        if !fs::open_entry(&self.parent, OsStr::new(&self.name))?
            .is_some_and(|f| fs::same_inode(&f, &self.directory).unwrap_or(false))
        {
            return Err(ErrorKind::Stale.into());
        }
        fs::sys(rustix::fs::unlinkat(
            &self.parent,
            self.name.as_str(),
            AtFlags::REMOVEDIR,
        ))?;
        fs::io(self.parent.sync_all())
    }
}
