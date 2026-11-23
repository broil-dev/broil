// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    identity,
    output::{self, ExportFormat, Prepared},
    sops::{self, Entry, Value},
    store::{self, DecryptedSet, SetId, Store},
};
use broil_core::{
    model::BroilConfig,
    secret::{environment::CredentialInputs, normalize_path},
    secrets::{Export, ExportValue, SecretsConfig, TemplatePart, valid_project},
};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt,
    path::{Path, PathBuf},
};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error {
    class: &'static str,
    subject: Option<String>,
    vault: Option<crate::vault::Error>,
}
impl Error {
    pub fn cleanup_failed(&self) -> bool {
        self.class == "vault owned token cleanup failed"
            || self.vault.is_some_and(|error| error.cleanup_failed)
    }

    pub fn class(class: &'static str) -> Self {
        Self {
            class,
            subject: None,
            vault: None,
        }
    }
    pub(crate) fn subject(mut self, name: &str) -> Self {
        self.subject = Some(output::public_name(name));
        self
    }
    pub(crate) fn store(error: store::Error) -> Self {
        use sops::Error as S;
        use store::ErrorKind as K;
        match error.kind {
            K::Sops(S::IncompatibleOriginal) => {
                Self::class("original policy; manually migrate to a portable selector")
            }
            K::Sops(S::IncompatibleCandidate) => {
                Self::class("candidate policy; manually migrate to a portable selector")
            }
            K::Sops(S::IncompatibleRule) => {
                Self::class("final-path rule policy; manually migrate to a portable selector")
            }
            K::Sops(S::AmbiguousAuthentication) => Self::class("ambiguous authentication"),
            K::Sops(S::UnsupportedMetadata(keys)) => {
                Self::class("uninterpreted metadata").subject(&keys.join(", "))
            }
            K::RotationPolicy(name) => Self::class("rotation capability").subject(&name),
            K::OwnedSchema => Self::class("owned schema"),
            K::OwnedMutation => Self::class("reserved data mutation"),
            K::ActiveRotation => Self::class("active rotation"),
            K::InvalidName => Self::class("invalid name or reserved key"),
            K::NoTmpfs => Self::class("no safe tmpfs"),
            K::Exists => Self::class("destination already populated"),
            K::Busy => Self::class("store locked"),
            K::SizeLimit | K::Sops(S::SizeLimit) => Self::class("size limit"),
            K::Allocation | K::Sops(S::Allocation) => Self::class("allocation"),
            K::UnsafePath | K::Stale => Self::class("unsafe or changed path"),
            K::Sops(_) => Self::class("authenticated read"),
            _ => Self::class("store access"),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = self.vault {
            return write!(f, "{error}");
        }
        f.write_str(self.class)?;
        if let Some(name) = &self.subject {
            write!(f, " ({name})")?;
        }
        Ok(())
    }
}
impl std::error::Error for Error {}
impl From<crate::vault::Error> for Error {
    fn from(error: crate::vault::Error) -> Self {
        Self {
            class: "vault",
            subject: None,
            vault: Some(error),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Selection {
    pub config: SecretsConfig,
    root: PathBuf,
    pub environment: Option<String>,
}

pub fn resolve_scalar(
    selected: &Selection,
    cwd: &Path,
    inputs: CredentialInputs,
    key: &str,
    set: Option<&str>,
    control: &identity::AcquisitionControl,
) -> Result<broil_core::secret::OwnedSecret> {
    resolve_scalar_with_options(selected, cwd, inputs, key, set, control, false)
}

#[allow(clippy::too_many_arguments)]
pub fn resolve_scalar_with_options(
    selected: &Selection,
    cwd: &Path,
    inputs: CredentialInputs,
    key: &str,
    set: Option<&str>,
    control: &identity::AcquisitionControl,
    non_interactive: bool,
) -> Result<broil_core::secret::OwnedSecret> {
    control.check()?;
    if !broil_core::secrets::valid_key(key)
        || set.is_some_and(|id| !broil_core::secrets::valid_set(id, true))
    {
        return Err(Error::class("scalar selector"));
    }
    let id = selected.default_set(set)?;
    let store = Store::open(&selected.store_root()).map_err(Error::store)?;
    let options = Options {
        non_interactive,
        ..Options::default()
    };
    let mut resolver = Resolver::new(&store, selected, &options, cwd, inputs, false);
    resolver.control = control.clone();
    let result = (|| {
        let set = resolver.read(&id, false)?;
        control.check()?;
        let value = set.get(key).ok_or(Error::class("scalar unavailable"))?;
        let text = value.scalar().ok_or(Error::class("non-scalar value"))?;
        if text.is_empty() || text.contains('\0') || text.len() > sops::MAX_SCALAR_BYTES {
            return Err(Error::class("invalid scalar value"));
        }
        let scalar = output::prepare(sops::MAX_SCALAR_BYTES, |writer| value.emit_scalar(writer))?;
        drop(set);
        control.check()?;
        scalar.into_secret()
    })();
    let scalar = resolver.finish(result)?;
    control.check()?;
    Ok(scalar)
}
impl Selection {
    pub fn new(config: &BroilConfig, root: &Path, environment: Option<&OsStr>) -> Result<Self> {
        let env = environment.filter(|e| !e.is_empty());
        let selected = if let Some(env) = env {
            Some(
                config
                    .environments
                    .get(env.to_str().ok_or(Error::class("unknown environment"))?)
                    .ok_or(Error::class("unknown environment"))?,
            )
        } else {
            None
        };
        Ok(Self {
            config: selected.map_or_else(
                || config.secrets.clone(),
                |e| config.secrets.overlay(&e.secrets),
            ),
            root: root.into(),
            environment: env.and_then(OsStr::to_str).map(str::to_owned),
        })
    }
    pub fn project(&self) -> Result<&str> {
        let name = self
            .config
            .project
            .as_deref()
            .or_else(|| self.root.file_name()?.to_str())
            .ok_or(Error::class("project name"))?;
        if !valid_project(name) {
            return Err(Error::class("project name"));
        }
        Ok(name)
    }
    pub fn store_root(&self) -> PathBuf {
        normalize_path(
            &self.root,
            Path::new(self.config.store.as_deref().unwrap_or("broil/secrets")),
        )
    }
    pub fn default_set(&self, explicit: Option<&str>) -> Result<SetId> {
        let name = explicit
            .or(self.config.set.as_deref())
            .or(self.environment.as_deref())
            .ok_or(Error::class("no selected set"))?;
        let resolved;
        let name = if name.contains('/') {
            name
        } else {
            resolved = format!("{}/{name}", self.project()?);
            &resolved
        };
        SetId::new(name).map_err(|_| Error::class("set selector"))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ReadKind {
    Get,
    List,
    Export,
    Check,
}
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub key: Option<String>,
    pub set: Option<String>,
    pub all: bool,
    pub local: bool,
    pub non_interactive: bool,
    pub json: bool,
    pub slots: bool,
    pub format: ExportFormat,
    pub quiet: bool,
    pub identity: Option<String>,
    pub team: Option<String>,
    pub machine: bool,
    pub yes: bool,
    pub new_name: Option<String>,
    pub child: Vec<std::ffi::OsString>,
    pub generator: Option<String>,
    pub handler_type: Option<String>,
    pub keep_previous: bool,
    pub force: bool,
}

#[derive(Default)]
struct SetConsumers<'a> {
    check: bool,
    exports: Vec<(&'a str, &'a Export)>,
}

pub fn run(
    kind: ReadKind,
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    inputs: CredentialInputs,
) -> Result<Prepared> {
    if matches!(kind, ReadKind::Export) {
        let values = resolve_exports(selected, options, cwd, inputs)?;
        return output::exports(&values, options.format);
    }
    let one = if matches!(kind, ReadKind::Get | ReadKind::List)
        || (matches!(kind, ReadKind::Check) && !options.all)
    {
        Some(selected.default_set(options.set.as_deref())?)
    } else {
        None
    };
    let mut groups: BTreeMap<SetId, SetConsumers<'_>> = BTreeMap::new();
    let store = Store::open(&selected.store_root()).map_err(Error::store)?;
    if matches!(kind, ReadKind::Check) {
        let sets = if options.all {
            store.sets().map_err(Error::store)?
        } else {
            vec![one.clone().unwrap()]
        };
        for set in &sets {
            groups.entry(set.clone()).or_default().check = true;
        }
        group_exports(&mut groups, selected, options, Some(&sets))?;
    }
    let mut resolver = Resolver::new(
        &store,
        selected,
        options,
        cwd,
        inputs,
        matches!(kind, ReadKind::Check),
    );
    let result = (|| {
        if let Some(id) = one.filter(|_| !matches!(kind, ReadKind::Check)) {
            let set = resolver.read(&id, false)?;
            return match kind {
                ReadKind::Get => {
                    let key = options.key.as_deref().ok_or(Error::class("key required"))?;
                    let value = set
                        .get(key)
                        .ok_or_else(|| Error::class("missing key").subject(key))?;
                    value.get(options.json)
                }
                ReadKind::List => {
                    let slots = if options.slots {
                        match &set {
                            ResolvedSet::Local(local) => local.slots().map_err(Error::store)?,
                            ResolvedSet::Vault(_) => {
                                resolver.local(&id)?.slots().map_err(Error::store)?
                            }
                        }
                    } else {
                        Vec::new()
                    };
                    let mut names = set.keys()?;
                    names.extend(slots.iter().map(String::as_str));
                    output::list_refs(names)
                }
                _ => unreachable!(),
            };
        }
        resolve_groups(&mut resolver, groups, &selected.config.exports, false)?;
        output::prepare(output::MAX_OUTPUT_BYTES, |w| w.text("ok\n"))
    })();
    resolver.finish(result)
}

pub fn resolve_exports(
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    inputs: CredentialInputs,
) -> Result<BTreeMap<String, Prepared>> {
    let mut groups = BTreeMap::new();
    group_exports(&mut groups, selected, options, None)?;
    if groups.is_empty() {
        drop(inputs);
        return render_literals(&selected.config.exports);
    }
    let store = Store::open(&selected.store_root()).map_err(Error::store)?;
    let mut resolver = Resolver::new(&store, selected, options, cwd, inputs, false);
    let result = resolve_groups(&mut resolver, groups, &selected.config.exports, true);
    resolver.finish(result)
}

fn resolve_groups(
    resolver: &mut Resolver<'_>,
    groups: BTreeMap<SetId, SetConsumers<'_>>,
    exports: &BTreeMap<String, Export>,
    retain: bool,
) -> Result<BTreeMap<String, Prepared>> {
    let mut decoded = 0;
    let mut rendered = 0;
    let mut results = render_literals(exports)?;
    for result in results.values() {
        add_budget(&mut rendered, result.as_bytes().len())?;
    }
    for (id, consumers) in groups {
        let set = resolver.read(&id, consumers.check)?;
        add_budget(&mut decoded, set.decoded_bytes())?;
        for (name, export) in consumers.exports {
            let value = render_export(export, Some(&set))?;
            add_budget(&mut rendered, value.as_bytes().len())?;
            if retain {
                results.insert(name.into(), value);
            }
        }
    }
    Ok(results)
}
fn add_budget(total: &mut usize, amount: usize) -> Result<()> {
    *total = total
        .checked_add(amount)
        .ok_or(Error::class("size limit"))?;
    if *total > sops::MAX_DOCUMENT_BYTES {
        return Err(Error::class("size limit"));
    }
    Ok(())
}
fn source_keys(export: &Export) -> Vec<&str> {
    match &export.value {
        ExportValue::Key(key) => vec![key],
        ExportValue::Template(parts) => parts
            .iter()
            .filter_map(|p| match p {
                TemplatePart::Key(key) => Some(key.as_str()),
                _ => None,
            })
            .collect(),
    }
}
fn group_exports<'a>(
    groups: &mut BTreeMap<SetId, SetConsumers<'a>>,
    selected: &'a Selection,
    options: &Options,
    checked: Option<&[SetId]>,
) -> Result<()> {
    for (name, export) in &selected.config.exports {
        if source_keys(export).is_empty() {
            continue;
        }
        let sets = if let Some(explicit) = &export.set {
            vec![SetId::new(explicit).map_err(|_| Error::class("export set"))?]
        } else if options.all {
            let prefix = format!("{}/", selected.project()?);
            let sets = checked
                .unwrap_or(&[])
                .iter()
                .filter(|id| id.as_str().starts_with(&prefix))
                .cloned()
                .collect::<Vec<_>>();
            if sets.is_empty() {
                return Err(Error::class("unresolved export"));
            }
            sets
        } else {
            vec![selected.default_set(options.set.as_deref())?]
        };
        for set in sets {
            groups.entry(set).or_default().exports.push((name, export));
        }
    }
    Ok(())
}
fn render_literals(exports: &BTreeMap<String, Export>) -> Result<BTreeMap<String, Prepared>> {
    let mut output = BTreeMap::new();
    let mut total = 0;
    for (name, export) in exports {
        if source_keys(export).is_empty() {
            let rendered = render_export(export, None)?;
            add_budget(&mut total, rendered.as_bytes().len())?;
            output.insert(name.clone(), rendered);
        }
    }
    Ok(output)
}
fn render_export(export: &Export, set: Option<&ResolvedSet>) -> Result<Prepared> {
    let emit_key = |writer: &mut output::Writer, key: &str| {
        let value = set
            .and_then(|s| s.get(key))
            .ok_or_else(|| Error::class("missing or non-scalar export source").subject(key))?;
        let text = value
            .scalar()
            .ok_or_else(|| Error::class("non-scalar export source").subject(key))?;
        if text.is_empty() || text.contains('\0') || text.len() > sops::MAX_SCALAR_BYTES {
            return Err(Error::class("invalid export source").subject(key));
        }
        value.emit_scalar(writer)
    };
    let result = output::prepare(sops::MAX_DOCUMENT_BYTES, |writer| {
        match &export.value {
            ExportValue::Key(key) => emit_key(writer, key)?,
            ExportValue::Template(parts) => {
                for part in parts {
                    match part {
                        TemplatePart::Key(key) => emit_key(writer, key)?,
                        TemplatePart::Literal(text) => writer.text(text)?,
                    }
                }
            }
        }
        Ok(())
    })?;
    if result.as_bytes().is_empty() || result.as_bytes().contains(&0) {
        return Err(Error::class("empty or NUL export"));
    }
    Ok(result)
}

pub(crate) fn decoded_bytes(value: &Value) -> usize {
    match value {
        Value::Scalar(s) => s.as_str().len(),
        Value::Comment(c) => c.as_str().len(),
        Value::Null => 0,
        Value::Sequence(values) => values.iter().map(decoded_bytes).sum(),
        Value::Mapping(entries) => entries
            .iter()
            .map(|e| match e {
                Entry::Pair(k, v) => k.len() + decoded_bytes(v),
                Entry::Comment(c) => c.as_str().len(),
            })
            .sum(),
    }
}

enum ResolvedSet {
    Local(Box<DecryptedSet>),
    Vault(crate::vault::json::Value),
}
enum ValueRef<'a> {
    Local(&'a Value),
    Vault(&'a crate::vault::json::Value),
}
impl<'a> ValueRef<'a> {
    fn get(&self, json: bool) -> Result<Prepared> {
        match self {
            Self::Local(value) => output::get(value, json),
            Self::Vault(value) => value.render(json, true),
        }
    }
    fn scalar(&self) -> Option<&str> {
        match self {
            Self::Local(value) => value.scalar().map(sops::Scalar::as_str),
            Self::Vault(value) => value.scalar(),
        }
    }
    fn emit_scalar(&self, writer: &mut output::Writer) -> Result<()> {
        match self {
            Self::Local(value) => output::scalar(
                writer,
                value.scalar().ok_or(Error::class("non-scalar export"))?,
                false,
            ),
            Self::Vault(value) => {
                writer.text(value.scalar().ok_or(Error::class("non-scalar export"))?)
            }
        }
    }
}
impl ResolvedSet {
    fn get(&self, key: &str) -> Option<ValueRef<'_>> {
        if matches!(key, "_broil" | "sops") {
            return None;
        }
        match self {
            Self::Local(set) => set.get(key).map(ValueRef::Local),
            Self::Vault(set) => set.get(key).map(ValueRef::Vault),
        }
    }
    fn keys(&self) -> Result<Vec<&str>> {
        match self {
            Self::Local(set) => Ok(set.keys()),
            Self::Vault(set) => set.keys().map_err(Into::into),
        }
    }
    fn decoded_bytes(&self) -> usize {
        match self {
            Self::Local(set) => set.decoded_bytes(),
            Self::Vault(set) => set.decoded_bytes(),
        }
    }
}
struct Resolver<'a> {
    store: &'a Store,
    selected: &'a Selection,
    options: &'a Options,
    cwd: &'a Path,
    inputs: CredentialInputs,
    keys: Option<Vec<crate::age::Identity>>,
    session: Option<crate::vault::Session>,
    fallback: bool,
    needs_local: bool,
    control: identity::AcquisitionControl,
}
impl<'a> Resolver<'a> {
    fn new(
        store: &'a Store,
        selected: &'a Selection,
        options: &'a Options,
        cwd: &'a Path,
        inputs: CredentialInputs,
        needs_local: bool,
    ) -> Self {
        Self {
            store,
            selected,
            options,
            cwd,
            inputs,
            keys: None,
            session: None,
            fallback: false,
            needs_local: needs_local
                || options.slots
                || selected.config.vault.fallback == Some(broil_core::secrets::Fallback::Local),
            control: identity::AcquisitionControl::default(),
        }
    }
    fn local(&mut self, id: &SetId) -> Result<DecryptedSet> {
        self.control.check()?;
        if self.keys.is_none() {
            self.keys = Some(
                identity::acquire_named_controlled(
                    self.store,
                    self.cwd,
                    self.selected.config.identity.as_deref(),
                    std::mem::take(&mut self.inputs),
                    self.options.non_interactive,
                    false,
                    &self.control,
                )?
                .keys,
            );
        }
        self.control.check()?;
        let set = self
            .store
            .read(id, self.keys.as_ref().unwrap())
            .map_err(Error::store)?;
        self.control.check()?;
        Ok(set)
    }
    fn can_fallback(&self, error: &crate::vault::Error) -> bool {
        error.fallback
            && self.selected.config.vault.fallback == Some(broil_core::secrets::Fallback::Local)
    }
    fn read(&mut self, id: &SetId, check: bool) -> Result<ResolvedSet> {
        self.control.check()?;
        let vault =
            self.selected.config.vault.address.is_some() && !self.options.local && !self.fallback;
        if vault {
            self.store.inspect_set(id).map_err(Error::store)?;
            if self.session.is_none() {
                match crate::vault::Session::open_controlled(
                    self.selected,
                    self.cwd,
                    &mut self.inputs,
                    self.options.non_interactive,
                    &mut self.keys,
                    false,
                    &self.control,
                ) {
                    Ok(session) => {
                        self.session = Some(session);
                        if !self.needs_local {
                            self.keys.take();
                            self.inputs = CredentialInputs::default();
                        }
                    }
                    Err(error) if self.can_fallback(&error) => self.fallback = true,
                    Err(error) => return Err(error.into()),
                }
            }
            if !self.fallback {
                if check {
                    self.local(id)?.check().map_err(Error::store)?;
                }
                let result = self.session.as_mut().unwrap().read_set(
                    self.selected
                        .config
                        .vault
                        .mount
                        .as_deref()
                        .unwrap_or("secret"),
                    id,
                );
                match result {
                    Ok(value) => return Ok(ResolvedSet::Vault(value)),
                    Err(error) if self.can_fallback(&error) => (),
                    Err(error) => return Err(error.into()),
                }
            }
        }
        let set = self.local(id)?;
        if check {
            set.check().map_err(Error::store)?;
        }
        Ok(ResolvedSet::Local(Box::new(set)))
    }
    fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        self.keys.take();
        drop(self.inputs);
        if let Some(mut session) = self.session.take() {
            if session.cleanup().is_err() {
                return Err(Error::class("vault owned token cleanup failed"));
            }
        }
        result
    }
}
