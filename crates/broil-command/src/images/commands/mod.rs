// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod build;
mod builder;
mod graph;
mod help;
mod publish;
mod record;
mod render;
mod resume;
mod settle;
mod status;

pub use help::help;

use super::{
    Cancellation, Entry, Failure, Kind, Limits, Ownership, Policy, StageError, Tool, common,
    consumers, files, records, store, supervise::Active,
};
use broil_config::{LoadedProject, images::select};
use broil_core::{
    images::valid_name,
    secret::{environment::CredentialInputs, path_safety::sudo_nonce},
};
use records::FailureClass;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fmt,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Graph,
    Build,
    Publish,
    Status,
    RecordList,
    RecordShow,
    Resume,
    Settle,
    BuilderAccess,
    BuilderInspect,
    BuilderSetup,
    BuilderReconcile,
    BuilderRemove,
}

impl Verb {
    pub fn named(path: &str) -> Option<Self> {
        Some(match path {
            "graph" => Self::Graph,
            "build" => Self::Build,
            "publish" => Self::Publish,
            "status" => Self::Status,
            "record list" => Self::RecordList,
            "record show" => Self::RecordShow,
            "resume" => Self::Resume,
            "settle" => Self::Settle,
            "builder access" => Self::BuilderAccess,
            "builder inspect" => Self::BuilderInspect,
            "builder setup" => Self::BuilderSetup,
            "builder reconcile" => Self::BuilderReconcile,
            "builder remove" => Self::BuilderRemove,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Graph => "graph",
            Self::Build => "build",
            Self::Publish => "publish",
            Self::Status => "status",
            Self::RecordList => "record list",
            Self::RecordShow => "record show",
            Self::Resume => "resume",
            Self::Settle => "settle",
            Self::BuilderAccess => "builder access",
            Self::BuilderInspect => "builder inspect",
            Self::BuilderSetup => "builder setup",
            Self::BuilderReconcile => "builder reconcile",
            Self::BuilderRemove => "builder remove",
        }
    }
    pub fn builder(self) -> bool {
        matches!(
            self,
            Self::BuilderAccess
                | Self::BuilderInspect
                | Self::BuilderSetup
                | Self::BuilderReconcile
                | Self::BuilderRemove
        )
    }
    pub fn dispatching(self) -> bool {
        self.builder() || matches!(self, Self::Graph | Self::Build | Self::Publish)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    #[default]
    Table,
    Json,
}

#[derive(Clone, Debug)]
pub struct Invocation {
    pub verb: Verb,
    pub format: Format,
    pub targets: Vec<String>,
    pub platforms: Option<Vec<String>>,
    pub registries: Option<Vec<String>>,
    pub builder: Option<String>,
    pub operation: Option<String>,
    pub artifact: Option<String>,
    pub build_platform: Option<String>,
    pub content_staging: bool,
    pub archive: Option<PathBuf>,
    pub docker_daemon: Option<PathBuf>,
    pub ambiguity: Option<u64>,
    pub refresh: bool,
    pub optional_cache_reads: bool,
    pub non_interactive: bool,
    pub arm64_emulation: bool,
    pub purge: bool,
}

pub struct Inputs<'a> {
    pub cwd: &'a Path,
    pub environment: Option<&'a OsStr>,
    pub env_snapshot: &'a [(OsString, OsString)],
    pub credentials: CredentialInputs,
}

impl Inputs<'_> {
    fn consumer(self, non_interactive: bool) -> consumers::Inputs {
        consumers::Inputs {
            cwd: self.cwd.into(),
            credentials: self.credentials,
            non_interactive,
        }
    }
}

pub struct Output {
    pub payload: Vec<u8>,
    pub status: i32,
    pub diagnostic: Option<String>,
}

#[derive(Debug)]
pub struct Error {
    class: FailureClass,
    diagnostic: String,
}
impl Error {
    pub fn output_write() -> Self {
        Self::new(
            FailureClass::of(Failure::Storage),
            "cannot write image output",
        )
    }

    fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
        }
    }
    fn failure(verb: Verb, failure: Failure) -> Self {
        Self::new(
            FailureClass::of(failure),
            format!("image {} failed", verb.name()),
        )
    }
    fn stage(verb: Verb, error: StageError) -> Self {
        Self::new(
            FailureClass::of(error.failure),
            format!(
                "image {} failed; {}",
                verb.name(),
                render::observation(&error.observation)
            ),
        )
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.class.name(), self.diagnostic)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

pub fn valid_operation_id(value: &str) -> bool {
    common::valid_operation(value)
}
pub fn valid_artifact_id(value: &str) -> bool {
    records::valid_artifact(value)
}
pub fn valid_operand_path(value: &Path) -> bool {
    common::valid_path(value)
}

struct Signals(Option<tokio::sync::oneshot::Sender<()>>);
impl Signals {
    fn install(cancellation: Cancellation) -> common::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Failure::Capacity)?;
        let entered = runtime.enter();
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|_| Failure::Capacity)?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| Failure::Capacity)?;
        drop(entered);
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("image-signals".into())
            .spawn(move || {
                runtime.block_on(async move {
                    loop {
                        tokio::select! {
                            _ = &mut stopped => break,
                            _ = interrupt.recv() => cancellation.cancel(),
                            _ = terminate.recv() => cancellation.cancel(),
                        }
                    }
                })
            })
            .map_err(|_| Failure::Capacity)?;
        Ok(Self(Some(stop)))
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            let _ = stop.send(());
        }
    }
}

pub fn run(
    project: &LoadedProject,
    invocation: Invocation,
    inputs: Inputs<'_>,
    cancellation: Cancellation,
) -> Result<Output> {
    let _signals =
        Signals::install(cancellation.clone()).map_err(|f| Error::failure(invocation.verb, f))?;
    match invocation.verb {
        Verb::Graph => graph::run(project, invocation, inputs, cancellation),
        Verb::Build => build::run(project, invocation, inputs, cancellation),
        Verb::Publish => publish::run(project, invocation, inputs, cancellation),
        Verb::Status => status::run(project, invocation, cancellation),
        Verb::RecordList | Verb::RecordShow => record::run(project, invocation, cancellation),
        Verb::Resume => resume::run(project, invocation, cancellation),
        Verb::Settle => settle::run(project, invocation, cancellation),
        _ => builder::run(project, invocation, inputs, cancellation),
    }
}

fn step<T: Send + 'static>(
    root: &Path,
    verb: Verb,
    cancellation: &Cancellation,
    job: impl FnOnce(&Path, &Active) -> Result<T> + Send + 'static,
) -> Result<T> {
    let limits = Limits::default();
    records::step(
        root,
        limits.metadata_ms,
        limits.cleanup_ms,
        cancellation.flag(),
        move |root, active| Ok(job(root, active)),
    )
    .map_err(|f| Error::failure(verb, f))?
}

fn operation(root: &Path, id: &str, verb: Verb, active: &Active) -> Result<()> {
    let mut directory = store::open_directory(root, active).map_err(|f| Error::failure(verb, f))?;
    for name in ["state", "operations", id] {
        directory = store::existing_child_directory(&directory, name, active)
            .map_err(|f| Error::failure(verb, f))?
            .ok_or_else(|| Error::new(FailureClass::Configuration, format!("no operation {id}")))?;
    }
    Ok(())
}

struct Assembly {
    operation_id: String,
    environment: Option<String>,
    helper: Entry,
    tools: BTreeMap<Tool, Entry>,
}
fn assemble_before_store(
    project: &LoadedProject,
    verb: Verb,
    inputs: &Inputs<'_>,
) -> Result<Assembly> {
    let environment = inputs
        .environment
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string_lossy().into_owned());
    let catalogs = select::select(project, environment.as_deref()).map_err(|_| {
        Error::new(
            FailureClass::Configuration,
            "unknown or invalid image environment or catalogs",
        )
    })?;
    if environment.as_deref().is_some_and(|name| !valid_name(name)) {
        return Err(Error::new(
            FailureClass::Configuration,
            "image environment must match [A-Za-z0-9][A-Za-z0-9_-]*",
        ));
    }
    let declared = &catalogs.tools;
    let mut needed = vec![(
        "filesystem_helper",
        declared.filesystem_helper.as_deref(),
        None,
    )];
    if matches!(verb, Verb::Graph | Verb::Build | Verb::Publish) {
        needed.push((
            "registry",
            declared.registry.as_deref(),
            Some(Tool::Registry),
        ));
    }
    if matches!(verb, Verb::Graph | Verb::Build) {
        needed.push((
            "analyzer",
            declared.analyzer.as_deref(),
            Some(Tool::Analyzer),
        ));
    }
    if verb == Verb::Build || verb.builder() {
        needed.push(("buildx", declared.buildx.as_deref(), Some(Tool::Buildx)));
        needed.push((
            "buildctl",
            declared.buildctl.as_deref(),
            Some(Tool::Buildctl),
        ));
    }
    for (name, path, _) in &needed {
        if path.is_none() {
            return Err(Error::new(
                FailureClass::Configuration,
                format!("missing image tool {name}"),
            ));
        }
    }
    if verb == Verb::Build && declared.docker.is_some() {
        needed.push(("docker", declared.docker.as_deref(), Some(Tool::Docker)));
    }
    let mut helper = None;
    let mut tools = BTreeMap::new();
    for (_, path, tool) in needed {
        let (_, entry) = files::open_path(
            Path::new(path.expect("required declarations checked")),
            Ownership::Borrowed,
            true,
        )
        .map_err(|f| Error::failure(verb, f))?;
        if entry.kind != Kind::File {
            return Err(Error::failure(verb, Failure::Policy));
        }
        if let Some(tool) = tool {
            tools.insert(tool, entry);
        } else {
            helper = Some(entry);
        }
    }
    let operation_id = format!(
        "operation-{}",
        sudo_nonce().map_err(|_| Error::failure(verb, Failure::Storage))?
    );
    let parent = project.broil_root.join("state/workspaces");
    for path in [&project.broil_root, &parent, &parent.join(&operation_id)] {
        if !common::valid_path(path) {
            return Err(Error::failure(verb, Failure::Policy));
        }
    }
    Ok(Assembly {
        operation_id,
        environment,
        helper: helper.expect("helper declaration checked"),
        tools,
    })
}

fn workspace(root: &Path, verb: Verb, active: &Active) -> Result<Entry> {
    let state = store::state_directory(root, true, active).map_err(|f| Error::failure(verb, f))?;
    let parent = store::child_directory(&state, "workspaces", true, active)
        .map_err(|f| Error::failure(verb, f))?;
    files::identity(
        &parent,
        &root.join("state/workspaces"),
        Ownership::Borrowed,
        false,
    )
    .map_err(|f| Error::failure(verb, f))
}

fn finish_assembly(
    project: &LoadedProject,
    verb: Verb,
    assembly: Assembly,
    parent: Entry,
) -> Result<Policy> {
    let selected_env = assembly
        .environment
        .as_ref()
        .map(|name| project.config.environments[name].env_vars.clone())
        .unwrap_or_default();
    let policy = Policy {
        operation_id: assembly.operation_id,
        root: project.broil_root.clone(),
        environment: assembly.environment,
        root_env: project.config.env_vars.clone(),
        selected_env,
        parent,
        helper: assembly.helper,
        tools: assembly.tools,
        limits: Limits::default(),
    };
    validate_assembly(&policy, verb)?;
    Ok(policy)
}

fn validate_assembly(policy: &Policy, verb: Verb) -> Result<()> {
    policy.validate().map_err(|failure| match failure {
        Failure::Limit => Error::new(
            FailureClass::of(failure),
            "env_vars exceeds the image child-environment bounds",
        ),
        Failure::Policy => Error::new(
            FailureClass::of(failure),
            "env_vars declares a name or value the image child-environment policy refuses",
        ),
        other => Error::failure(verb, other),
    })
}

fn policy(
    project: &LoadedProject,
    verb: Verb,
    inputs: &Inputs<'_>,
    cancellation: &Cancellation,
) -> Result<Policy> {
    let assembly = assemble_before_store(project, verb, inputs)?;
    let parent = step(
        &project.broil_root,
        verb,
        cancellation,
        move |root, active| workspace(root, verb, active),
    )?;
    finish_assembly(project, verb, assembly, parent)
}

fn output(
    invocation: &Invocation,
    value: serde_json::Value,
    class: Option<FailureClass>,
    diagnostic: Option<String>,
) -> Result<Output> {
    let payload =
        render::encode(value, invocation.format).map_err(|f| Error::failure(invocation.verb, f))?;
    Ok(Output {
        payload,
        status: if class.is_some() { 1 } else { 0 },
        diagnostic: class.map(|class| {
            Error::new(
                class,
                diagnostic.unwrap_or_else(|| format!("image {} failed", invocation.verb.name())),
            )
            .to_string()
        }),
    })
}
