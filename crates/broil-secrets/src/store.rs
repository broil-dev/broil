// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod admin;
mod editor;
mod filesystem;
mod identity;
mod init;
mod owned;

use crate::{
    age,
    sops::{self, Document, Entry, Plaintext, Value},
};
use broil_core::secret::{normalize_path, path_safety as safe};
use filesystem::{Target, checkpoint};
use std::{
    ffi::OsStr,
    fmt,
    fs::File,
    path::{Path, PathBuf},
};

pub use editor::{Edit, PrivateTemp};
pub use identity::{IdentityNames, read_raw_identity};
pub use init::Initialization;
pub(crate) use owned::RotationUpdate;
pub use owned::{Marker, Rollback, RollbackStage, State, UnauthenticatedStatus};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Unchanged,
    Changed,
    MayHaveChanged,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ErrorKind {
    InvalidName,
    UnsafePath,
    Missing,
    Exists,
    Busy,
    Stale,
    Io,
    SizeLimit,
    Allocation,
    Randomness,
    OwnedSchema,
    OwnedMutation,
    ActiveRotation,
    RotationPolicy(String),
    Identity,
    NoTmpfs,
    Editor,
    Sops(sops::Error),
}
#[derive(Debug, Eq, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub disposition: Disposition,
    pub cleanup_failed: bool,
}
impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            disposition: Disposition::Unchanged,
            cleanup_failed: false,
        }
    }
}
impl From<sops::Error> for Error {
    fn from(error: sops::Error) -> Self {
        ErrorKind::Sops(error).into()
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::Sops(error) => write!(f, "{error}")?,
            kind => write!(f, "secret store operation failed: {kind:?}")?,
        }
        write!(f, "; disposition: {:?}", self.disposition)?;
        if self.cleanup_failed {
            f.write_str("; temporary storage cleanup failed")?;
        }
        Ok(())
    }
}
impl std::error::Error for Error {}

const RESERVED: [&str; 4] = ["keys", "credentials", "policies", "handlers"];

pub fn validate_component(name: &str) -> Result<()> {
    if broil_core::secrets::valid_component(name) {
        Ok(())
    } else {
        Err(ErrorKind::InvalidName.into())
    }
}
pub fn validate_project(name: &str) -> Result<()> {
    if broil_core::secrets::valid_project(name) {
        Ok(())
    } else {
        Err(ErrorKind::InvalidName.into())
    }
}
pub(crate) fn validate_user_key(name: &str) -> Result<()> {
    if name.is_empty()
        || matches!(name, "_broil" | "sops")
        || name.len() > sops::MAX_SCALAR_BYTES
        || name.contains('\0')
    {
        return Err(ErrorKind::InvalidName.into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SetId(String);
impl SetId {
    pub fn new(name: &str) -> Result<Self> {
        if !broil_core::secrets::valid_set(name, true) {
            return Err(ErrorKind::InvalidName.into());
        }
        Ok(Self(name.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn file_path(&self) -> String {
        format!("{}.yaml", self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialId(String);
impl CredentialId {
    pub fn new(name: &str) -> Result<Self> {
        validate_component(name)?;
        Ok(Self(name.to_owned()))
    }
    pub fn file_path(&self) -> String {
        format!("credentials/{}.yaml", self.0)
    }
}

pub fn resolve_root(broil_root: &Path, configured: &Path) -> Result<PathBuf> {
    filesystem::absolute(broil_root)?;
    if configured.as_os_str().is_empty() {
        return Err(ErrorKind::InvalidName.into());
    }
    Ok(normalize_path(broil_root, configured))
}

pub struct Store {
    root: PathBuf,
    directory: File,
}
impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Store([REDACTED])")
    }
}
impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        filesystem::absolute(root)?;
        let validated =
            safe::defensive_open_directory_no_symlink(root).map_err(|_| ErrorKind::UnsafePath)?;
        filesystem::directory(&validated, false)?;
        let directory = safe::reopen_for_read(&validated).map_err(|_| ErrorKind::UnsafePath)?;
        Ok(Self {
            root: root.to_owned(),
            directory,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn sets(&self) -> Result<Vec<SetId>> {
        self.root_current()?;
        let mut output = Vec::new();
        let mut remaining = 65536;
        self.enumerate(&self.directory, "", 0, &mut remaining, &mut output)?;
        self.root_current()?;
        output.sort();
        Ok(output)
    }
    pub fn project_sets(&self, project: &str) -> Result<Vec<SetId>> {
        validate_project(project)?;
        self.root_current()?;
        if filesystem::open_entry(&self.directory, OsStr::new(project))?.is_none() {
            return Ok(Vec::new());
        }
        let directory = filesystem::open_dir(&self.directory, OsStr::new(project))?;
        let mut output = Vec::new();
        self.enumerate(
            &directory,
            &format!("{project}/"),
            1,
            &mut 65536,
            &mut output,
        )?;
        self.root_current()?;
        output.sort();
        Ok(output)
    }
    fn enumerate(
        &self,
        directory: &File,
        prefix: &str,
        depth: usize,
        remaining: &mut usize,
        output: &mut Vec<SetId>,
    ) -> Result<()> {
        if depth > 128 {
            return Err(ErrorKind::SizeLimit.into());
        }
        for name in filesystem::names(directory)? {
            *remaining = remaining.checked_sub(1).ok_or(ErrorKind::SizeLimit)?;
            let name = name.to_str().ok_or(ErrorKind::InvalidName)?;
            if depth == 0 && RESERVED.contains(&name) {
                continue;
            }
            let file =
                filesystem::open_entry(directory, OsStr::new(name))?.ok_or(ErrorKind::Stale)?;
            let metadata = filesystem::io(file.metadata())?;
            if metadata.is_dir() {
                if depth == 0 {
                    validate_project(name)?;
                }
                let child = filesystem::open_dir(directory, OsStr::new(name))?;
                let path = format!("{prefix}{name}/");
                self.enumerate(&child, &path, depth + 1, remaining, output)?;
            } else if metadata.is_file() {
                if depth == 0 || !name.ends_with(".yaml") {
                    continue;
                }
                let id = SetId::new(&format!("{prefix}{}", &name[..name.len() - 5]))?;
                let mut target = self.target(id.file_path(), false, false)?;
                sops::inspect(&target.load()?)?;
                target.fresh(self)?;
                output.push(id);
            } else {
                return Err(ErrorKind::UnsafePath.into());
            }
        }
        Ok(())
    }
    fn load(
        &self,
        path: String,
        private: bool,
        identities: &[age::Identity],
    ) -> Result<(Target, Document)> {
        let mut target = self.target(path, private, false)?;
        let document = sops::decrypt(target.load()?, identities)?;
        target.fresh(self)?;
        Ok((target, document))
    }
    pub fn read(&self, id: &SetId, identities: &[age::Identity]) -> Result<DecryptedSet> {
        Ok(DecryptedSet(
            self.load(id.file_path(), false, identities)?.1,
        ))
    }
    pub fn read_credential(
        &self,
        id: &CredentialId,
        identities: &[age::Identity],
    ) -> Result<DecryptedSet> {
        Ok(DecryptedSet(self.load(id.file_path(), true, identities)?.1))
    }
    pub fn read_private_document(
        &self,
        path: &str,
        identities: &[age::Identity],
    ) -> Result<DecryptedSet> {
        if !broil_core::secrets::valid_relative_file(path) || path.split('/').count() > 128 {
            return Err(ErrorKind::InvalidName.into());
        }
        Ok(DecryptedSet(
            self.load(path.to_owned(), true, identities)?.1,
        ))
    }
    pub fn inspect_set(&self, id: &SetId) -> Result<()> {
        let mut target = self.target(id.file_path(), false, false)?;
        sops::inspect(&target.load()?)?;
        target.fresh(self)
    }
    pub fn plaintext_metadata(&self, id: &SetId) -> Result<(Vec<String>, String)> {
        let mut target = self.target(id.file_path(), false, false)?;
        let metadata = sops::plaintext_metadata(&target.load()?)?;
        target.fresh(self)?;
        Ok(metadata)
    }
    pub fn status(&self, id: &SetId) -> Result<UnauthenticatedStatus> {
        let mut target = self.target(id.file_path(), false, false)?;
        let status = owned::status(&target.load()?)?;
        target.fresh(self)?;
        Ok(status)
    }
    pub fn write(&self) -> Result<WriteSession<'_>> {
        self.root_current()?;
        let lock = safe::reopen_for_read(&self.directory).map_err(|_| ErrorKind::UnsafePath)?;
        if !filesystem::io(safe::try_lock_exclusive(&lock))? {
            return Err(ErrorKind::Busy.into());
        }
        self.root_current()?;
        Ok(WriteSession {
            store: self,
            _lock: lock,
        })
    }
}

pub struct DecryptedSet(Document);
impl fmt::Debug for DecryptedSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DecryptedSet([REDACTED])")
    }
}
impl DecryptedSet {
    pub fn get(&self, key: &str) -> Option<&Value> {
        if matches!(key, "_broil" | "sops") {
            None
        } else {
            self.0.data().get(key)
        }
    }
    pub fn keys(&self) -> Vec<&str> {
        let mut keys: Vec<_> = self
            .0
            .data()
            .entries()
            .into_iter()
            .flatten()
            .filter_map(|entry| match entry {
                Entry::Pair(key, _) if key != "_broil" && key != "sops" => Some(key.as_str()),
                _ => None,
            })
            .collect();
        keys.sort();
        keys
    }
    pub fn decoded_bytes(&self) -> usize {
        crate::read::decoded_bytes(self.0.data())
    }
    pub fn check(&self) -> Result<()> {
        owned::document_capability(&self.0)?;
        for key in self.keys() {
            self.check_rotation(key)?;
        }
        for (key, _) in owned::entries(self.0.data())? {
            self.check_rotation(key)?;
        }
        Ok(())
    }
    pub fn check_owned(&self) -> Result<()> {
        owned::validate(self.0.data(), self.0.selector())
    }
    pub fn check_writable(&self) -> Result<()> {
        self.0.ensure_writable()?;
        self.check_owned()
    }
    pub fn check_rotation(&self, key: &str) -> Result<()> {
        owned::capability(&self.0, key)
    }
    pub fn slots(&self) -> Result<Vec<String>> {
        self.check_owned()?;
        let mut slots = Vec::new();
        for (key, record) in owned::entries(self.0.data())? {
            for slot in ["pending", "previous"] {
                if record.get(slot).is_some() {
                    slots.push(format!("_broil.rotation.{key}.{slot}"));
                }
            }
        }
        slots.sort();
        Ok(slots)
    }
}

pub struct WriteSession<'a> {
    store: &'a Store,
    _lock: File,
}
impl fmt::Debug for WriteSession<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WriteSession([REDACTED])")
    }
}
impl WriteSession<'_> {
    pub fn prepare_sets(
        &self,
        sets: &[SetId],
        key: &str,
        allow_create: bool,
    ) -> Result<Vec<PreparedSet>> {
        validate_user_key(key)?;
        if sets.len() > 65536 {
            return Err(ErrorKind::SizeLimit.into());
        }
        let mut prepared = Vec::new();
        for id in sets {
            let path = id.file_path();
            let absolute = self.store.root.join(&path);
            let parents = filesystem::DirectoryPlan::inspect(
                absolute.parent().ok_or(ErrorKind::InvalidName)?,
            )?;
            let existing = if let Some(parent) = parents.existing() {
                filesystem::open_entry(parent, absolute.file_name().ok_or(ErrorKind::InvalidName)?)?
                    .is_some()
            } else {
                false
            };
            let (original, rules) = if existing {
                let mut target = self.store.target(path, false, false)?;
                target.load_bytes()?;
                (Some(target), None)
            } else {
                if !allow_create || sets.len() != 1 {
                    return Err(ErrorKind::Missing.into());
                }
                let mut rules = self.store.target(".sops.yaml".into(), false, false)?;
                rules.load_bytes()?;
                (None, Some(rules))
            };
            prepared.push(PreparedSet {
                id: id.clone(),
                original,
                parents,
                rules,
            });
        }
        self.store.root_current()?;
        Ok(prepared)
    }

    pub fn preflight_set(
        &self,
        target: &PreparedSet,
        identities: &[age::Identity],
        key: &str,
    ) -> Result<()> {
        validate_user_key(key)?;
        target.fresh(self)?;
        if target.original.is_some() {
            let (_, document) = self.original(target.id.file_path(), false, identities)?;
            if owned::active(document.data(), document.selector(), key) {
                return Err(ErrorKind::ActiveRotation.into());
            }
        } else {
            let mut rules = self.store.target(".sops.yaml".into(), false, false)?;
            let rule = sops::recipients_for(&rules.load()?, &target.id.file_path())?;
            sops::create(&new_value_document(key, "preflight")?, &rule)?;
        }
        target.fresh(self)?;
        checkpoint("set-preflight")
    }

    pub fn apply_set(
        &self,
        target: &PreparedSet,
        identities: &[age::Identity],
        key: &str,
        value: &str,
    ) -> std::result::Result<Vec<String>, BatchFailure> {
        let mut completed = Vec::new();
        let mut failing = target.id.file_path();
        let result = (|| {
            self.preflight_set(target, identities, key)?;
            if let Some(original) = &target.original {
                let (_, document) = self.original(failing.clone(), false, identities)?;
                original.fresh(self.store)?;
                let mut candidate = document.data().duplicate()?;
                candidate.put(key, Value::string(value)?)?;
                let disposition = self.candidate(original, &document, candidate)?;
                if disposition != Disposition::Unchanged {
                    completed.push(failing.clone());
                }
            } else {
                let mut rules = self.store.target(".sops.yaml".into(), false, false)?;
                let rule = sops::recipients_for(&rules.load()?, &failing)?;
                let encoded = sops::create(&new_value_document(key, value)?, &rule)?;
                target.fresh(self)?;
                let parent = target
                    .parents
                    .create(|path| completed.push(init::relative_directory(&self.store.root, path)))
                    .inspect_err(|error| {
                        if error.disposition == Disposition::MayHaveChanged {
                            if let Some(path) = completed.pop() {
                                failing = path;
                            }
                        }
                    })?;
                let destination = self.store.target(failing.clone(), false, false)?;
                if !filesystem::same_inode(&parent, &destination.parent)? {
                    return Err(ErrorKind::Stale.into());
                }
                if let Some(original_rule) = &target.rules {
                    original_rule.fresh(self.store)?;
                }
                filesystem::replace(self.store, &destination, &encoded, Some(&rules))?;
                completed.push(failing.clone());
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(completed),
            Err(error) => Err(BatchFailure {
                completed,
                failing,
                error,
            }),
        }
    }

    fn original(
        &self,
        path: String,
        private: bool,
        identities: &[age::Identity],
    ) -> Result<(Target, Document)> {
        let (target, document) = self.store.load(path, private, identities)?;
        document.ensure_writable()?;
        owned::validate(document.data(), document.selector())?;
        Ok((target, document))
    }
    fn candidate(
        &self,
        target: &Target,
        document: &Document,
        candidate: Value,
    ) -> Result<Disposition> {
        document.ensure_writable()?;
        owned::generic_candidate(document, &candidate)?;
        let encoded = document.rewrite(candidate.duplicate()?)?;
        target.fresh(self.store)?;
        if document.data().same(&candidate) {
            return Ok(Disposition::Unchanged);
        }
        drop(candidate);
        filesystem::replace(self.store, target, &encoded, None)
    }
    pub fn set(
        &self,
        id: &SetId,
        identities: &[age::Identity],
        key: &str,
        value: Value,
    ) -> Result<Disposition> {
        validate_user_key(key)?;
        let (target, document) = self.original(id.file_path(), false, identities)?;
        if owned::active(document.data(), document.selector(), key) {
            return Err(ErrorKind::ActiveRotation.into());
        }
        let mut candidate = document.data().duplicate()?;
        candidate.put(key, value)?;
        self.candidate(&target, &document, candidate)
    }
    pub fn remove(
        &self,
        id: &SetId,
        identities: &[age::Identity],
        key: &str,
    ) -> Result<Disposition> {
        validate_user_key(key)?;
        let (target, document) = self.original(id.file_path(), false, identities)?;
        if owned::active(document.data(), document.selector(), key) {
            return Err(ErrorKind::ActiveRotation.into());
        }
        let mut candidate = document.data().duplicate()?;
        if candidate.get(key).is_some() {
            candidate.take(key)?;
        }
        self.candidate(&target, &document, candidate)
    }
    pub fn write_editor(
        &self,
        id: &SetId,
        identities: &[age::Identity],
        plaintext: &Plaintext,
    ) -> Result<Disposition> {
        let (target, document) = self.original(id.file_path(), false, identities)?;
        self.candidate(&target, &document, sops::parse_plaintext(plaintext)?)
    }
    fn create_path(
        &self,
        path: String,
        private: bool,
        plaintext: &Plaintext,
    ) -> Result<Disposition> {
        let data = sops::parse_plaintext(plaintext)?;
        if data.get("_broil").is_some() {
            return Err(ErrorKind::OwnedMutation.into());
        }
        drop(data);
        let mut rules = self.store.target(".sops.yaml".to_owned(), false, false)?;
        let rule = sops::recipients_for(&rules.load()?, &path)?;
        let encoded = sops::create(plaintext, &rule)?;
        rules.fresh(self.store)?;
        let target = self.store.target(path, private, true)?;
        if filesystem::open_entry(&target.parent, &target.name)?.is_some() {
            return Err(ErrorKind::Exists.into());
        }
        filesystem::replace(self.store, &target, &encoded, Some(&rules))
    }
    pub fn create(&self, id: &SetId, plaintext: &Plaintext) -> Result<Disposition> {
        self.create_path(id.file_path(), false, plaintext)
    }
    pub fn create_credential(
        &self,
        id: &CredentialId,
        plaintext: &Plaintext,
    ) -> Result<Disposition> {
        self.create_path(id.file_path(), true, plaintext)
    }
    pub fn write_credential(
        &self,
        id: &CredentialId,
        identities: &[age::Identity],
        plaintext: &Plaintext,
    ) -> Result<Disposition> {
        let (target, document) = self.original(id.file_path(), true, identities)?;
        self.candidate(&target, &document, sops::parse_plaintext(plaintext)?)
    }
    pub(crate) fn read_rotation(
        &self,
        id: &SetId,
        identities: &[age::Identity],
        key: &str,
    ) -> Result<RotationUpdate> {
        let (_, document) = self.original(id.file_path(), false, identities)?;
        owned::projection(&document, key)
    }

    pub(crate) fn update_rotation(
        &self,
        id: &SetId,
        identities: &[age::Identity],
        key: &str,
        update: owned::RotationUpdate,
    ) -> Result<Disposition> {
        let (target, document) = self.original(id.file_path(), false, identities)?;
        let encoded = document.rewrite(owned::updated(&document, key, update)?)?;
        drop(document);
        filesystem::replace(self.store, &target, &encoded, None)
    }
    pub fn rekey(
        &self,
        sets: &[SetId],
        identities: &[age::Identity],
    ) -> std::result::Result<Vec<String>, BatchFailure> {
        let mut paths: Vec<_> = sets.iter().map(SetId::file_path).collect();
        paths.sort();
        paths.dedup();
        let mut completed = Vec::new();
        let mut failing = ".sops.yaml".to_owned();
        let result = (|| -> Result<()> {
            let mut rules = self.store.target(".sops.yaml".to_owned(), false, false)?;
            let config = rules.load()?;
            let mut targets = Vec::new();
            for path in paths {
                failing = path.clone();
                let (target, document) = self.original(path.clone(), false, identities)?;
                let rule = sops::recipients_for(&config, &path)?;
                document.rewrap(&rule)?;
                target.fresh(self.store)?;
                targets.push(target);
            }
            checkpoint("rekey-preflight")?;
            rules.fresh(self.store)?;
            for target in &targets {
                failing = target.path.clone();
                target.fresh(self.store)?;
            }
            for target in targets {
                failing = target.path.clone();
                target.fresh(self.store)?;
                let (_, document) = self.original(target.path.clone(), false, identities)?;
                let rule = sops::recipients_for(&config, &target.path)?;
                let encoded = document.rewrap(&rule)?;
                drop(document);
                filesystem::replace(self.store, &target, &encoded, Some(&rules))?;
                completed.push(target.path);
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(completed),
            Err(error) => Err(BatchFailure {
                completed,
                failing,
                error,
            }),
        }
    }
}

pub struct PreparedSet {
    id: SetId,
    original: Option<Target>,
    parents: filesystem::DirectoryPlan,
    rules: Option<Target>,
}
impl PreparedSet {
    pub fn id(&self) -> &SetId {
        &self.id
    }
    pub fn needs_identity(&self) -> bool {
        self.original.is_some()
    }
    pub fn fresh(&self, session: &WriteSession<'_>) -> Result<()> {
        session.store.root_current()?;
        self.parents.fresh()?;
        if let Some(target) = &self.original {
            target.fresh(session.store)?;
        } else if let Some(parent) = self.parents.existing() {
            let name = format!(
                "{}.yaml",
                self.id
                    .as_str()
                    .rsplit('/')
                    .next()
                    .ok_or(ErrorKind::InvalidName)?
            );
            if filesystem::open_entry(parent, OsStr::new(&name))?.is_some() {
                return Err(ErrorKind::Stale.into());
            }
        }
        if let Some(rules) = &self.rules {
            rules.fresh(session.store)?;
        }
        Ok(())
    }
}

fn new_value_document(key: &str, value: &str) -> Result<Plaintext> {
    let encoded = crate::output::prepare(sops::MAX_DOCUMENT_BYTES, |writer| {
        writer.text("{")?;
        crate::output::json_string(writer, key)?;
        writer.text(": ")?;
        crate::output::json_string(writer, value)?;
        writer.text("}\n")
    })
    .map_err(|_| ErrorKind::SizeLimit)?;
    Ok(Plaintext::copy_from(encoded.as_str())?)
}

#[derive(Debug)]
pub struct BatchFailure {
    pub completed: Vec<String>,
    pub failing: String,
    pub error: Error,
}
impl BatchFailure {
    pub fn recovery(&self) -> &'static str {
        "Inspect the reported files and durability disposition; correct the failure, then retry rekey."
    }
}
