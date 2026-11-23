// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod cache;
mod context;
mod identity;
mod inputs;

use super::{
    Entry, StageError, VerifiedOutput,
    analysis::{self, same},
    buffer::Bytes,
    client::{BakeFailure, Baked, BuilderCapabilities, CacheArguments, Kept},
    common::*,
    graph::{Diagnostic, Material, NodeKey, Resolution, Resolved, State, Subject},
    json::Value,
    outputs::{
        Handoff, NotExported as OutputNotExported, OutputInput, TargetOutcome, TargetReport,
    },
    publish::{NotPublished, PublicationOutcome, PublicationReport, PublishInput},
    supervise::Observation,
};
use broil_config::images::select::{EffectiveBuilder, EffectiveImage};
use broil_core::images::{BuilderKind, OutputConfig, SecretReference};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) use cache::{Agreement, NodePlan, UploadWork, csv_safe, project_id};
pub use cache::{ExportMode, Freshness, Location};
pub use context::IgnoreEntry;
pub(crate) use context::{
    ContextLimits, ContextRequest, ContextSnapshot, Point, Refused as ContextRefused, SnapshotWork,
    Watch,
};
pub(crate) use identity::{GeneratedIdentity, generated_inputs_id};
pub use inputs::DerivedInputProvenance;
pub(crate) use inputs::{
    IgnoreCopy, MaterializeWork, Materialized, Plan, PlanFacts, PlanInputs, create_directory,
    create_file, plan, write_file,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailedCheck {
    Builder,
    BuildPlatform,
    Platform,
    Material,
    Bindings,
    Operand,
    Link,
    Context,
    Ignore,
    Budget,
    Bake,
    OutputPin,
    Alias,
    Configuration,
    Cache,
    CacheRead,
}

impl FailedCheck {
    pub fn name(self) -> &'static str {
        match self {
            Self::Builder => "builder",
            Self::BuildPlatform => "build-platform",
            Self::Platform => "platform",
            Self::Material => "material",
            Self::Bindings => "bindings",
            Self::Operand => "operand",
            Self::Link => "link",
            Self::Context => "context",
            Self::Ignore => "ignore",
            Self::Budget => "budget",
            Self::Bake => "bake",
            Self::OutputPin => "output-pin",
            Self::Alias => "alias",
            Self::Configuration => "configuration",
            Self::Cache => "cache",
            Self::CacheRead => "cache-read",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Refusal {
    pub(crate) failure: Failure,
    pub(crate) check: Option<FailedCheck>,
}

impl From<Failure> for Refusal {
    fn from(failure: Failure) -> Self {
        Self {
            failure,
            check: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotDispatched {
    Cancelled,
    Stale,
    GraphDiagnostic,
    ProducerFailed,
    ProducerNotBuilt,
    Provisional,
    Stopped,
}

impl NotDispatched {
    pub fn name(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Stale => "stale",
            Self::GraphDiagnostic => "graph-diagnostic",
            Self::ProducerFailed => "producer-failed",
            Self::ProducerNotBuilt => "producer-not-built",
            Self::Provisional => "provisional",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IgnoreReport {
    pub record: IgnoreEntry,
    pub default_ignore: IgnoreEntry,
    pub named_ignore: BTreeMap<String, IgnoreEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontendGap {
    pub reference: String,
    pub content: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuilderIdentity {
    pub name: String,
    pub kind: &'static str,
    pub endpoint: String,
    pub server_name: String,
    pub version: String,
    pub oci_worker: bool,
    pub platforms: Vec<String>,
    pub build_platform: String,
}

#[derive(Clone, Debug)]
pub struct BuiltNode {
    pub context_id: String,
    pub ignore: IgnoreReport,
    pub dockerfile_digest: String,
    pub bake_digest: String,
    pub build_platform: String,
    pub generated_inputs_id: String,
    pub output: VerifiedOutput,
    pub frontend: Option<FrontendGap>,
    pub derived_entries: u64,
    pub derived_bytes: u64,
    pub derived_inputs: Vec<DerivedInputProvenance>,
    pub builder: BuilderIdentity,
    pub image: EffectiveImage,
    pub upload: Option<VerifiedOutput>,
}

#[derive(Clone, Debug)]
pub struct ReadReport {
    pub registry: String,
    pub reference: String,
    pub outcome: ReadOutcome,
    pub root: Option<Descriptor>,
    pub imported: bool,
    pub operation_id: Option<String>,
    pub session: Option<SessionObservation>,
    pub release: ReleaseOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOutcome {
    Fetched,
    OptionalMiss,
    Skipped,
    Failed(Failure),
    Cancelled,
}

impl ReadOutcome {
    pub fn name(self) -> &'static str {
        match self {
            Self::Fetched => "fetched",
            Self::OptionalMiss => "optional-miss",
            Self::Skipped => "skipped",
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug)]
pub enum ReleaseOutcome {
    None,
    Released,
    Unreleased(Option<Failure>),
    Failed(Failure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    Written,
    Promoted,
    Failed(Failure),
    Unknown(Failure),
    Cancelled,
}

impl WriteOutcome {
    pub fn name(self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::Promoted => "promoted",
            Self::Failed(_) => "failed",
            Self::Unknown(_) => "unknown",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug)]
pub struct WriteReport {
    pub registry: String,
    pub mode: ExportMode,
    pub export_root: Option<Descriptor>,
    pub writer_reference: Option<String>,
    pub outcome: WriteOutcome,
    pub namespace_reference: String,
    pub promotion: Option<WriteOutcome>,
    pub writer_session: Option<SessionObservation>,
    pub promotion_session: Option<SessionObservation>,
}

#[derive(Clone, Debug)]
pub struct NodeCache {
    pub no_cache: bool,
    pub secret_freshness: Freshness,
    pub secrets: Vec<SecretReference>,
    pub reads: Vec<ReadReport>,
    pub write: Option<WriteReport>,
}

#[derive(Clone, Debug)]
pub enum NodeOutcome {
    Built(Box<BuiltNode>),
    Failed {
        class: Failure,
        check: Option<FailedCheck>,
    },
    NotDispatched(NotDispatched),
}

#[derive(Clone, Debug)]
pub struct SessionObservation {
    pub operation_id: String,
    pub cleanup: std::result::Result<Observation, StageError>,
    pub residue: bool,
    pub unresolved_owner: bool,
}

#[derive(Clone, Debug)]
pub struct NodeReport {
    pub producer: String,
    pub platform: String,
    pub outcome: NodeOutcome,
    pub session: Option<SessionObservation>,
    pub cache: Option<NodeCache>,
}

#[derive(Clone, Debug)]
pub enum Stop {
    Success,
    Quiescent,
    Stale(Vec<Diagnostic>),
    BuilderAgreement,
    CacheAgreement,
    CacheWrite,
    NodeFailed,
    Cancelled,
    GraphRefused(StageError),
    ProbeFailed(StageError),
    Bound,
}

#[derive(Debug)]
pub struct SolveReport {
    pub build_platform: Option<String>,
    pub probe: Option<SessionObservation>,
    pub graph_sessions: Vec<SessionObservation>,
    pub resolution: Option<Resolution>,
    pub nodes: Vec<NodeReport>,
    pub closures: Vec<VerifiedOutput>,
    pub stop: Stop,
    pub node_sessions: u64,
    pub re_entries: u64,
    pub targets: Vec<TargetReport>,
    pub publications: Vec<PublicationReport>,
    pub retained: Vec<Kept>,
    pub cache_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub dockerfile_bytes: u64,
    pub bake_bytes: u64,
    pub layouts: u64,
    pub derived_entries: u64,
    pub named_directories: u64,
    pub context_entries: u64,
    pub context_bytes: u64,
    pub node_builds: u64,
    pub re_entries: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            dockerfile_bytes: inputs::MAX_DOCKERFILE as u64,
            bake_bytes: inputs::MAX_BAKE as u64,
            layouts: inputs::MAX_LAYOUTS as u64,
            derived_entries: inputs::MAX_DERIVED_ENTRIES,
            named_directories: inputs::MAX_NAMED_DIRECTORIES as u64,
            context_entries: 65_536,
            context_bytes: 4_294_967_296,
            node_builds: 1024,
            re_entries: 1024,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        let maximum = Self::default();
        for (value, max) in [
            (self.dockerfile_bytes, maximum.dockerfile_bytes),
            (self.bake_bytes, maximum.bake_bytes),
            (self.layouts, maximum.layouts),
            (self.derived_entries, maximum.derived_entries),
            (self.named_directories, maximum.named_directories),
            (self.context_entries, maximum.context_entries),
            (self.context_bytes, maximum.context_bytes),
            (self.node_builds, maximum.node_builds),
            (self.re_entries, maximum.re_entries),
        ] {
            require(value > 0 && value <= max, Failure::Limit)?;
        }
        Ok(())
    }
}

pub(crate) struct Selection {
    pub(crate) catalog_id: String,
    pub(crate) image: Option<EffectiveImage>,
    pub(crate) builder_name: String,
    pub(crate) builder: EffectiveBuilder,
}

pub(crate) trait NodeDriver {
    fn select(&mut self) -> Result<Selection>;
    fn workspace(&self) -> PathBuf;
    fn allowance(&self) -> u64;
    fn deadline(&self) -> Result<u64>;
    fn open(&mut self) -> std::result::Result<(), StageError>;
    fn snapshot(
        &mut self,
        request: &ContextRequest,
    ) -> std::result::Result<std::result::Result<ContextSnapshot, ContextRefused>, StageError>;
    fn recheck(
        &mut self,
        resolution: &Resolution,
        material: &Material,
        selection: &Selection,
    ) -> std::result::Result<Vec<Diagnostic>, StageError>;
    fn acquire(&mut self, image: &EffectiveImage) -> std::result::Result<(), StageError>;
    fn discover(
        &mut self,
        builder: &EffectiveBuilder,
        image: &EffectiveImage,
    ) -> std::result::Result<BuilderCapabilities, StageError>;
    fn materialize(
        &mut self,
        plan: Plan,
        ignore: Option<IgnoreCopy>,
    ) -> std::result::Result<std::result::Result<(Materialized, PlanFacts), Refusal>, StageError>;
    fn recheck_imports(
        &mut self,
        imports: &[VerifiedOutput],
    ) -> std::result::Result<(), StageError>;
    fn dispatch(
        &mut self,
        target: &str,
        bake: &Entry,
        facts: &PlanFacts,
        platform: &str,
        cache: &CacheArguments,
    ) -> std::result::Result<Baked, BakeFailure>;
    fn upload_layout(
        &mut self,
        export: &VerifiedOutput,
    ) -> std::result::Result<VerifiedOutput, StageError>;
    fn exported_config(
        &mut self,
        output: &VerifiedOutput,
        platform: &str,
    ) -> std::result::Result<Bytes, StageError>;
    fn dispatched(&self) -> bool;
    fn carried(&self) -> bool;
    fn close(self, keep: &[VerifiedOutput]) -> (Option<SessionObservation>, Option<Kept>);
}

pub(crate) type SessionResult<T> = (
    std::result::Result<T, StageError>,
    Option<SessionObservation>,
);

pub(crate) struct Catalogs {
    pub(crate) catalog_id: String,
    pub(crate) images: BTreeMap<String, EffectiveImage>,
}

pub(crate) struct ReadInput<'a> {
    pub(crate) location: &'a Location,
    pub(crate) optional: bool,
    pub(crate) target: Option<&'a str>,
}

pub(crate) struct ReadResult {
    pub(crate) outcome: ReadOutcome,
    pub(crate) fetched: Option<(VerifiedOutput, Option<Kept>)>,
    pub(crate) operation_id: Option<String>,
    pub(crate) session: Option<SessionObservation>,
}

pub(crate) struct WriteInput<'a> {
    pub(crate) registry: &'a str,
    pub(crate) reference: &'a str,
    pub(crate) layout: &'a VerifiedOutput,
    pub(crate) target: Option<&'a str>,
}

pub(crate) struct WriteResult {
    pub(crate) outcome: WriteOutcome,
    pub(crate) session: Option<SessionObservation>,
}

pub(crate) trait Sessions {
    fn cancelled(&self) -> bool;
    fn probe(&mut self) -> SessionResult<String>;
    fn resolve(
        &mut self,
        build_platform: &str,
        prior: Option<(Resolution, Material)>,
        outputs: BTreeMap<NodeKey, VerifiedOutput>,
    ) -> (SessionResult<Resolved>, Option<Kept>);
    fn catalogs(&mut self) -> Result<Catalogs>;
    fn build(&mut self, input: &NodeInput<'_>) -> NodeResult;
    fn cache_read(&mut self, read: &ReadInput<'_>) -> ReadResult;
    fn cache_write(&mut self, write: &WriteInput<'_>) -> WriteResult;
    fn release(&mut self, kept: Kept) -> std::result::Result<(), (Option<Kept>, Failure)>;
    fn output(&mut self, input: &OutputInput<'_>) -> TargetReport;
    fn publish(&mut self, input: &PublishInput<'_>) -> (PublicationReport, Option<Kept>);
}

pub(crate) struct Recorded<'a> {
    pub(crate) catalog_id: &'a str,
    pub(crate) outputs: &'a BTreeMap<String, OutputConfig>,
    pub(crate) root: &'a Path,
    pub(crate) environment: Option<&'a str>,
    pub(crate) registries: Option<&'a [String]>,
    pub(crate) refresh: bool,
    pub(crate) optional_cache_reads: bool,
    pub(crate) docker_daemon: Option<&'a Path>,
}

pub(crate) struct LoopRequest<'a> {
    pub(crate) targets: &'a [String],
    pub(crate) build_platform: Option<&'a str>,
    pub(crate) builder: &'a str,
    pub(crate) expected_contexts: &'a BTreeMap<(String, String), String>,
    pub(crate) limits: &'a Limits,
    pub(crate) recorded: Recorded<'a>,
}

pub(crate) struct NodeInput<'a> {
    pub(crate) key: NodeKey,
    pub(crate) recorded_builder: String,
    pub(crate) resolution: &'a Resolution,
    pub(crate) material: &'a Material,
    pub(crate) build_platform: &'a str,
    pub(crate) request_builder: &'a str,
    pub(crate) expected_context: Option<&'a str>,
    pub(crate) limits: &'a Limits,
    pub(crate) cache: &'a NodePlan,
    pub(crate) output: Option<&'a OutputConfig>,
    pub(crate) imports: &'a [VerifiedOutput],
}

pub(crate) struct NodeResult {
    pub(crate) outcome: NodeOutcome,
    pub(crate) session: Option<SessionObservation>,
    pub(crate) stale: Vec<Diagnostic>,
    #[allow(dead_code)]
    pub(crate) dispatched: bool,
    pub(crate) carried: bool,
    pub(crate) kept: Option<Kept>,
}

fn stale_on(subject: Subject) -> Diagnostic {
    Diagnostic {
        subject,
        reason: "stale",
        location: analysis::Location::Unavailable,
        cycle: Vec::new(),
    }
}

enum SessionEnd {
    Built(Box<BuiltNode>),
    Refused(Refusal),
    Stale(Vec<Diagnostic>),
    Error(StageError),
}

pub(crate) fn node_session<D: NodeDriver>(mut driver: D, input: &NodeInput<'_>) -> NodeResult {
    let end = run_steps(&mut driver, input);
    let dispatched = driver.dispatched();
    let carried = driver.carried();
    let (outcome, keep, stale) = match end {
        SessionEnd::Built(built) => {
            let mut keep = vec![built.output.clone()];
            keep.extend(built.upload.clone());
            (NodeOutcome::Built(built), keep, Vec::new())
        }
        SessionEnd::Stale(stale) => (
            NodeOutcome::NotDispatched(NotDispatched::Stale),
            Vec::new(),
            stale,
        ),
        SessionEnd::Refused(refusal) => (
            outcome_of(refusal.failure, refusal.check, dispatched),
            Vec::new(),
            Vec::new(),
        ),
        SessionEnd::Error(error) => (
            outcome_of(error.failure, None, dispatched),
            Vec::new(),
            Vec::new(),
        ),
    };
    let (session, kept) = driver.close(&keep);
    NodeResult {
        outcome,
        session,
        stale,
        dispatched,
        carried,
        kept,
    }
}

fn outcome_of(failure: Failure, check: Option<FailedCheck>, dispatched: bool) -> NodeOutcome {
    if failure == Failure::Cancellation && !dispatched {
        NodeOutcome::NotDispatched(NotDispatched::Cancelled)
    } else {
        NodeOutcome::Failed {
            class: failure,
            check,
        }
    }
}

fn bound_selection<'s>(
    selection: &'s Selection,
    input: &NodeInput<'_>,
) -> std::result::Result<&'s EffectiveImage, SessionEnd> {
    let image = match &selection.image {
        Some(image)
            if selection.catalog_id == input.resolution.catalog_id
                && image.declaration.builder == input.recorded_builder =>
        {
            image
        }
        _ => return Err(SessionEnd::Stale(vec![stale_on(Subject::Catalogs)])),
    };
    if image.declaration.builder != input.request_builder {
        return Err(SessionEnd::Refused(Refusal {
            failure: Failure::Policy,
            check: Some(FailedCheck::Builder),
        }));
    }
    Ok(image)
}

fn run_steps<D: NodeDriver>(driver: &mut D, input: &NodeInput<'_>) -> SessionEnd {
    macro_rules! stage {
        ($e:expr) => {
            match $e {
                Ok(value) => value,
                Err(error) => return SessionEnd::Error(error),
            }
        };
    }
    macro_rules! refuse {
        ($e:expr) => {
            match $e {
                Ok(value) => value,
                Err(refusal) => return SessionEnd::Refused(refusal),
            }
        };
    }
    let selection = match driver.select() {
        Ok(selection) => selection,
        Err(failure) => return SessionEnd::Refused(failure.into()),
    };
    let image = match bound_selection(&selection, input) {
        Ok(image) => image.clone(),
        Err(end) => return end,
    };
    if image.declaration.cache != input.cache.declaration
        || input
            .output
            .is_some_and(|output| image.declaration.output != *output)
    {
        return SessionEnd::Stale(vec![stale_on(Subject::Catalogs)]);
    }
    let ordinal = input
        .resolution
        .nodes
        .iter()
        .position(|n| n.producer == input.key.producer && n.platform == input.key.platform);
    let resolution_id = ordinal.and_then(|o| input.resolution.nodes[o].resolution_id.clone());
    let (Some(associations), Some(ordinal), Some(resolution_id)) = (
        input.material.associations(&input.key),
        ordinal,
        resolution_id,
    ) else {
        return SessionEnd::Refused(Refusal {
            failure: Failure::Integrity,
            check: Some(FailedCheck::Material),
        });
    };
    let end = match driver.deadline() {
        Ok(end) => end,
        Err(failure) => return SessionEnd::Refused(failure.into()),
    };
    let workspace = driver.workspace();
    let plan = refuse!(plan(&PlanInputs {
        key: &input.key,
        image: &image,
        associations,
        material: input.material,
        workspace: &workspace,
        allowance: driver.allowance(),
        end,
        no_cache: input.cache.no_cache,
    }));
    if plan.dockerfile.get().len() as u64 > input.limits.dockerfile_bytes
        || plan.bake.len() as u64 > input.limits.bake_bytes
        || plan.layouts.len() as u64 > input.limits.layouts
        || plan.derived_entries > input.limits.derived_entries
        || image.contexts.len() as u64 > input.limits.named_directories
    {
        return SessionEnd::Refused(Refusal {
            failure: Failure::Limit,
            check: Some(FailedCheck::Budget),
        });
    }
    stage!(driver.open());
    let request = ContextRequest {
        context: image.context.clone(),
        named: image.contexts.clone(),
        dockerfile: image.dockerfile.clone(),
        limits: ContextLimits {
            entries: input.limits.context_entries,
            bytes: input.limits.context_bytes,
        },
    };
    let snapshot = match stage!(driver.snapshot(&request)) {
        Ok(snapshot) => snapshot,
        Err(refused) => {
            return SessionEnd::Refused(Refusal {
                failure: refused.failure,
                check: refused.observed.map(|observed| match observed {
                    context::Observed::Context => FailedCheck::Context,
                    context::Observed::Ignore => FailedCheck::Ignore,
                    context::Observed::Budget => FailedCheck::Budget,
                }),
            });
        }
    };
    if input
        .expected_context
        .is_some_and(|expected| expected != snapshot.context_id)
    {
        return SessionEnd::Stale(vec![stale_on(Subject::Node(ordinal as u64))]);
    }
    let drift = stage!(driver.recheck(input.resolution, input.material, &selection));
    if !drift.is_empty() {
        return SessionEnd::Stale(drift);
    }
    stage!(driver.acquire(&image));
    let reselected = match driver.select() {
        Ok(selection) => selection,
        Err(failure) => return SessionEnd::Refused(failure.into()),
    };
    if let Err(end) = bound_selection(&reselected, input) {
        return end;
    }
    if reselected.builder != selection.builder || reselected.image != selection.image {
        return SessionEnd::Refused(Failure::Policy.into());
    }
    let capabilities = stage!(driver.discover(&selection.builder, &image));
    if capabilities.build_platform != input.build_platform {
        return SessionEnd::Refused(Refusal {
            failure: Failure::Policy,
            check: Some(FailedCheck::BuildPlatform),
        });
    }
    if !capabilities.platforms.contains(&input.key.platform) {
        return SessionEnd::Refused(Refusal {
            failure: Failure::Policy,
            check: Some(FailedCheck::Platform),
        });
    }
    let ignore = match &snapshot.record {
        IgnoreEntry::Absent => None,
        IgnoreEntry::File { size, digest, .. } => Some(IgnoreCopy {
            source: request.record_path(),
            size: *size,
            digest: digest.clone(),
        }),
    };
    let (materialized, facts) = refuse!(stage!(driver.materialize(plan, ignore)));
    let cache_read = |failure| Refusal {
        failure,
        check: Some(FailedCheck::CacheRead),
    };
    if !input.imports.is_empty() {
        if let Err(error) = driver.recheck_imports(input.imports) {
            return SessionEnd::Refused(cache_read(error.failure));
        }
    }
    let mut cache = CacheArguments::default();
    for staging in input.imports {
        let staging = staging.retained();
        if !csv_safe(&staging.entry().path) {
            return SessionEnd::Refused(cache_read(Failure::Policy));
        }
        cache
            .imports
            .push((staging.entry().clone(), staging.root().clone()));
    }
    if let Some((_, mode)) = &input.cache.write {
        if !csv_safe(&workspace) {
            return SessionEnd::Refused(Refusal {
                failure: Failure::Policy,
                check: Some(FailedCheck::Cache),
            });
        }
        cache.export = Some(mode.name());
    }
    let baked = match driver.dispatch(
        &input.key.producer,
        &materialized.bake,
        &facts,
        &input.key.platform,
        &cache,
    ) {
        Ok(baked) => baked,
        Err(failure) => {
            let check = if failure.export {
                Some(FailedCheck::Cache)
            } else {
                (failure.error.failure == Failure::Tool).then_some(FailedCheck::Bake)
            };
            return SessionEnd::Refused(Refusal {
                failure: failure.error.failure,
                check,
            });
        }
    };
    let output = baked.image;
    if image
        .declaration
        .image
        .digest
        .as_deref()
        .is_some_and(|digest| digest != output.root().digest)
    {
        return SessionEnd::Refused(Refusal {
            failure: Failure::Integrity,
            check: Some(FailedCheck::OutputPin),
        });
    }
    let config = stage!(driver.exported_config(&output, &input.key.platform));
    if let Err(refusal) = exported_checks(config.get(), &facts, &workspace) {
        return SessionEnd::Refused(refusal);
    }
    let upload = match (&input.cache.write, baked.export) {
        (Some(_), Some(export)) => match driver.upload_layout(&export) {
            Ok(layout) => Some(layout),
            Err(error) => {
                return SessionEnd::Refused(Refusal {
                    failure: error.failure,
                    check: Some(FailedCheck::Cache),
                });
            }
        },
        (None, None) => None,
        _ => {
            return SessionEnd::Refused(Refusal {
                failure: Failure::Integrity,
                check: Some(FailedCheck::Cache),
            });
        }
    };
    let generated_inputs_id = match generated_inputs_id(&GeneratedIdentity {
        producer: &input.key.producer,
        platform: &input.key.platform,
        build_platform: input.build_platform,
        resolution_id: &resolution_id,
        dockerfile_digest: &facts.dockerfile_digest,
        bindings: &facts.bindings,
        contexts: &image.contexts.keys().cloned().collect::<Vec<_>>(),
        args: &image
            .declaration
            .args
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
        stage: image.declaration.stage.as_deref().unwrap_or(""),
        context_id: &snapshot.context_id,
    }) {
        Ok(id) => id,
        Err(failure) => return SessionEnd::Refused(failure.into()),
    };
    SessionEnd::Built(Box::new(BuiltNode {
        context_id: snapshot.context_id,
        ignore: IgnoreReport {
            record: snapshot.record,
            default_ignore: snapshot.default_ignore,
            named_ignore: snapshot.named_ignore,
        },
        dockerfile_digest: facts.dockerfile_digest.clone(),
        bake_digest: facts.bake_digest.clone(),
        build_platform: input.build_platform.into(),
        generated_inputs_id,
        output,
        frontend: facts.frontend.clone().map(|reference| FrontendGap {
            reference,
            content: "unavailable",
            reason: "builder-resolved",
        }),
        derived_entries: facts.derived_entries,
        derived_bytes: facts.derived_bytes,
        derived_inputs: facts.derived_provenance.clone(),
        builder: BuilderIdentity {
            name: selection.builder_name.clone(),
            kind: match selection.builder.declaration.kind {
                BuilderKind::Managed => "managed",
                BuilderKind::External => "external",
            },
            endpoint: selection.builder.declaration.endpoint.supplied.clone(),
            server_name: selection.builder.server_name.clone(),
            version: capabilities.version.to_owned(),
            oci_worker: capabilities.oci_worker,
            platforms: capabilities.platforms.clone(),
            build_platform: capabilities.build_platform.clone(),
        },
        image,
        upload,
    }))
}

const AGREED_FIELDS: [&str; 11] = [
    "Env",
    "Labels",
    "OnBuild",
    "WorkingDir",
    "User",
    "Entrypoint",
    "Cmd",
    "ExposedPorts",
    "Volumes",
    "StopSignal",
    "Shell",
];

pub(crate) fn exported_checks(
    exported: &[u8],
    facts: &PlanFacts,
    workspace: &std::path::Path,
) -> std::result::Result<(), Refusal> {
    let contains =
        |needle: &[u8]| !needle.is_empty() && exported.windows(needle.len()).any(|w| w == needle);
    let private_path = workspace.to_string_lossy();
    for (alias, context) in &facts.generated_aliases {
        if contains(alias.as_bytes()) || contains(context.as_bytes()) {
            return Err(Refusal {
                failure: Failure::Integrity,
                check: Some(FailedCheck::Alias),
            });
        }
    }
    if contains(private_path.as_bytes()) {
        return Err(Refusal {
            failure: Failure::Integrity,
            check: Some(FailedCheck::Alias),
        });
    }
    let agreement = (|| -> Result<bool> {
        let solved = Value::parse_bounded(exported, analysis::OBJECT, 128)?;
        let analyzed = Value::parse_bounded(facts.image_config.get(), analysis::OBJECT, 128)?;
        let solved = solved.optional("config")?.filter(|v| !v.is_null());
        let analyzed = analyzed.optional("config")?.filter(|v| !v.is_null());
        for field in AGREED_FIELDS {
            let a = solved
                .map(|v| v.optional(field))
                .transpose()?
                .flatten()
                .filter(|v| !v.is_null());
            let b = analyzed
                .map(|v| v.optional(field))
                .transpose()?
                .flatten()
                .filter(|v| !v.is_null());
            let equal = match (a, b) {
                (None, None) => true,
                (Some(a), Some(b)) => same(a, b)?,
                _ => false,
            };
            if !equal {
                return Ok(false);
            }
        }
        Ok(true)
    })();
    match agreement {
        Ok(true) => Ok(()),
        Ok(false) => Err(Refusal {
            failure: Failure::Integrity,
            check: Some(FailedCheck::Configuration),
        }),
        Err(failure) => Err(Refusal {
            failure,
            check: Some(FailedCheck::Configuration),
        }),
    }
}

struct Built {
    resolution_id: Option<String>,
    output: VerifiedOutput,
}

#[derive(Clone)]
struct Record {
    outcome: NodeOutcome,
    session: Option<SessionObservation>,
    cache: Option<NodeCache>,
}

impl Record {
    fn failed(class: Failure, check: FailedCheck) -> Self {
        Self {
            outcome: NodeOutcome::Failed {
                class,
                check: Some(check),
            },
            session: None,
            cache: None,
        }
    }
}

type Records = BTreeMap<NodeKey, Record>;

fn dispatchable(
    node: &super::graph::Node,
    built: &BTreeMap<NodeKey, Built>,
    records: &Records,
) -> bool {
    let key = key_of(node);
    node.state == State::Complete
        && built
            .get(&key)
            .is_none_or(|b| b.resolution_id != node.resolution_id)
        && !records.contains_key(&key)
}

fn release_reads<S: Sessions>(
    sessions: &mut S,
    retained: &mut Vec<Kept>,
    cache: &mut NodeCache,
    fetched: Vec<(Option<Kept>, usize)>,
    resolved: bool,
) {
    for (kept, index) in fetched {
        let Some(kept) = kept else {
            continue;
        };
        cache.reads[index].release = if !resolved {
            retained.push(kept);
            ReleaseOutcome::Unreleased(None)
        } else {
            match sessions.release(kept) {
                Ok(()) => ReleaseOutcome::Released,
                Err((Some(kept), class)) => {
                    retained.push(kept);
                    ReleaseOutcome::Unreleased(Some(class))
                }
                Err((None, class)) => ReleaseOutcome::Failed(class),
            }
        };
    }
}

pub(crate) fn run_loop<S: Sessions>(sessions: &mut S, request: &LoopRequest<'_>) -> SolveReport {
    let mut report = SolveReport {
        build_platform: None,
        probe: None,
        graph_sessions: Vec::new(),
        resolution: None,
        nodes: Vec::new(),
        closures: Vec::new(),
        stop: Stop::Quiescent,
        node_sessions: 0,
        re_entries: 0,
        targets: Vec::new(),
        publications: Vec::new(),
        retained: Vec::new(),
        cache_complete: true,
    };
    let build_platform = match request.build_platform {
        Some(platform) => platform.to_owned(),
        None => {
            let (result, observation) = sessions.probe();
            report.probe = observation;
            match result {
                Ok(platform) => platform,
                Err(error) => {
                    report.stop = Stop::ProbeFailed(error);
                    report.targets = unexported(request, OutputNotExported::SolveStopped);
                    return report;
                }
            }
        }
    };
    report.build_platform = Some(build_platform.clone());
    let ((result, observation), kept) = sessions.resolve(&build_platform, None, BTreeMap::new());
    report.graph_sessions.extend(observation);
    report.retained.extend(kept);
    let (mut resolution, mut material) = match result {
        Ok(Resolved::Graph(resolution, material)) => (resolution, material),
        Ok(Resolved::Stale(diagnostics, resolution, material)) => {
            report.stop = Stop::Stale(diagnostics.clone());
            return finish(
                sessions,
                request,
                report,
                resolution,
                material,
                BTreeMap::new(),
                &BTreeMap::new(),
                &diagnostics,
                false,
            );
        }
        Err(error) => {
            report.stop = Stop::GraphRefused(error);
            report.targets = unexported(request, OutputNotExported::SolveStopped);
            return report;
        }
    };
    let mut records: Records = BTreeMap::new();
    let mut built: BTreeMap<NodeKey, Built> = BTreeMap::new();
    let mut plans: BTreeMap<NodeKey, NodePlan> = BTreeMap::new();
    let stop = loop {
        if sessions.cancelled() {
            break Stop::Cancelled;
        }
        let catalogs = match sessions.catalogs() {
            Ok(value) => value,
            Err(failure) => {
                break Stop::GraphRefused(StageError {
                    failure,
                    observation: Observation::new(monotonic_ns()),
                });
            }
        };
        if catalogs.catalog_id != resolution.catalog_id
            || resolution.catalog_id != request.recorded.catalog_id
        {
            break Stop::Stale(vec![stale_on(Subject::Catalogs)]);
        }
        let builders: BTreeMap<String, String> = catalogs
            .images
            .iter()
            .map(|(name, image)| (name.clone(), image.declaration.builder.clone()))
            .collect();
        let mut recorded = BTreeMap::new();
        let mut agreement = None;
        for node in &resolution.nodes {
            let key = key_of(node);
            match builders.get(&node.producer) {
                Some(builder) if builder == request.builder => {
                    recorded.insert(key, builder.clone());
                }
                _ => {
                    records
                        .entry(key)
                        .or_insert(Record::failed(Failure::Policy, FailedCheck::Builder));
                    agreement = Some(Stop::BuilderAgreement);
                    break;
                }
            }
        }
        if let Some(stop) = agreement {
            break stop;
        }
        let facts = Agreement {
            root: request.recorded.root,
            environment: request.recorded.environment,
            registries: request.recorded.registries,
            refresh: request.recorded.refresh,
            images: &catalogs.images,
        };
        plans.clear();
        for node in resolution
            .nodes
            .iter()
            .filter(|n| dispatchable(n, &built, &records))
        {
            match cache::plan(&facts, &node.producer, &node.platform) {
                Ok(plan) => {
                    plans.insert(key_of(node), plan);
                }
                Err(class) => {
                    records.insert(key_of(node), Record::failed(class, FailedCheck::Cache));
                    agreement = Some(Stop::CacheAgreement);
                    break;
                }
            }
        }
        if let Some(stop) = agreement {
            break stop;
        }
        let mut halted = None;
        for node in &resolution.nodes {
            let key = key_of(node);
            let current = built
                .get(&key)
                .is_some_and(|b| b.resolution_id == node.resolution_id);
            if node.state != State::Complete || current || records.contains_key(&key) {
                continue;
            }
            if sessions.cancelled() {
                halted = Some(Stop::Cancelled);
                break;
            }
            if report.node_sessions >= request.limits.node_builds {
                halted = Some(Stop::Bound);
                break;
            }
            let Some(plan) = plans.get(&key) else {
                halted = Some(Stop::CacheAgreement);
                break;
            };
            let (record, stop) = node_with_cache(
                sessions,
                request,
                &mut report,
                NodeInput {
                    key: key.clone(),
                    recorded_builder: recorded[&key].clone(),
                    resolution: &resolution,
                    material: &material,
                    build_platform: &build_platform,
                    request_builder: request.builder,
                    expected_context: request
                        .expected_contexts
                        .get(&(node.producer.clone(), node.platform.clone()))
                        .map(String::as_str),
                    limits: request.limits,
                    cache: plan,
                    output: request
                        .targets
                        .contains(&node.producer)
                        .then(|| request.recorded.outputs.get(&node.producer))
                        .flatten(),
                    imports: &[],
                },
            );
            if let NodeOutcome::Built(node_built) = &record.outcome {
                built.insert(
                    key.clone(),
                    Built {
                        resolution_id: node.resolution_id.clone(),
                        output: node_built.output.clone(),
                    },
                );
            }
            records.insert(key, record);
            if let Some(stop) = stop {
                halted = Some(stop);
                break;
            }
        }
        if let Some(stop) = halted {
            break stop;
        }
        let targets_built = resolution
            .nodes
            .iter()
            .filter(|n| request.targets.contains(&n.producer))
            .all(|n| {
                built
                    .get(&key_of(n))
                    .is_some_and(|b| b.resolution_id == n.resolution_id)
            });
        if targets_built {
            break Stop::Success;
        }
        if sessions.cancelled() {
            break Stop::Cancelled;
        }
        let mut outputs = BTreeMap::new();
        for node in &resolution.nodes {
            if let State::Pending(awaited) = &node.state {
                for ordinal in awaited {
                    let Some(producer) = resolution.nodes.get(*ordinal as usize) else {
                        continue;
                    };
                    let key = key_of(producer);
                    if let Some(b) = built.get(&key) {
                        if b.resolution_id == producer.resolution_id {
                            outputs.entry(key).or_insert_with(|| b.output.clone());
                        }
                    }
                }
            }
        }
        if outputs.is_empty() {
            break Stop::Quiescent;
        }
        if report.re_entries >= request.limits.re_entries {
            break Stop::Bound;
        }
        report.re_entries += 1;
        let prior = resolution.clone();
        let retained: Vec<VerifiedOutput> = material.closures().cloned().collect();
        let ((result, observation), kept) =
            sessions.resolve(&build_platform, Some((resolution, material)), outputs);
        report.graph_sessions.extend(observation);
        report.retained.extend(kept);
        match result {
            Ok(Resolved::Graph(next, next_material)) => {
                resolution = next;
                material = next_material;
            }
            Ok(Resolved::Stale(diagnostics, returned, returned_material)) => {
                resolution = returned;
                material = returned_material;
                break Stop::Stale(diagnostics);
            }
            Err(error) => {
                report.stop = if error.failure == Failure::Cancellation || sessions.cancelled() {
                    Stop::Cancelled
                } else {
                    Stop::GraphRefused(error)
                };
                report.closures = retained;
                report.cache_complete = cache_complete(&records);
                report.nodes = assemble(&prior, &records, &plans, &[], false, &report.stop);
                report.targets = unexported(request, OutputNotExported::SolveStopped);
                report.resolution = Some(prior);
                return report;
            }
        }
    };
    let bound = matches!(stop, Stop::Bound);
    report.stop = stop;
    let stale = match &report.stop {
        Stop::Stale(diagnostics) => diagnostics.clone(),
        _ => Vec::new(),
    };
    finish(
        sessions, request, report, resolution, material, records, &plans, &stale, bound,
    )
}

fn planned_cache(plan: &NodePlan) -> NodeCache {
    NodeCache {
        no_cache: plan.no_cache,
        secret_freshness: plan.freshness,
        secrets: plan.secrets.clone(),
        reads: plan
            .skipped
            .iter()
            .map(|location| ReadReport {
                registry: location.registry.clone(),
                reference: location.reference.clone(),
                outcome: ReadOutcome::Skipped,
                root: None,
                imported: false,
                operation_id: None,
                session: None,
                release: ReleaseOutcome::None,
            })
            .collect(),
        write: None,
    }
}

fn node_with_cache<S: Sessions>(
    sessions: &mut S,
    request: &LoopRequest<'_>,
    report: &mut SolveReport,
    input: NodeInput<'_>,
) -> (Record, Option<Stop>) {
    let plan = input.cache;
    let mut cache = planned_cache(plan);
    let node_target: Option<&str> = request
        .targets
        .iter()
        .find(|t| **t == input.key.producer)
        .map(String::as_str);
    let mut fetched: Vec<(VerifiedOutput, Option<Kept>, usize)> = Vec::new();
    let mut refused = None;
    for location in &plan.reads {
        if sessions.cancelled() {
            refused = Some((
                NodeOutcome::NotDispatched(NotDispatched::Cancelled),
                Stop::Cancelled,
            ));
            break;
        }
        let result = sessions.cache_read(&ReadInput {
            location,
            optional: request.recorded.optional_cache_reads,
            target: node_target,
        });
        let index = cache.reads.len();
        cache.reads.push(ReadReport {
            registry: location.registry.clone(),
            reference: location.reference.clone(),
            outcome: result.outcome,
            root: result
                .fetched
                .as_ref()
                .map(|(output, _)| output.root().clone()),
            imported: false,
            operation_id: result.operation_id,
            session: result.session,
            release: ReleaseOutcome::None,
        });
        match (result.outcome, result.fetched) {
            (ReadOutcome::Fetched, Some((output, kept))) => fetched.push((output, kept, index)),
            (ReadOutcome::OptionalMiss, None) => {}
            (ReadOutcome::Cancelled, _) => {
                refused = Some((
                    NodeOutcome::NotDispatched(NotDispatched::Cancelled),
                    Stop::Cancelled,
                ));
                break;
            }
            (outcome, fetched) => {
                let class = match outcome {
                    ReadOutcome::Failed(class) => class,
                    _ => Failure::Integrity,
                };
                if let Some((_, kept)) = fetched {
                    cache.reads[index].outcome = ReadOutcome::Failed(class);
                    fetched_release(sessions, report, &mut cache, kept, index);
                }
                let stop = if class == Failure::Cancellation || sessions.cancelled() {
                    Stop::Cancelled
                } else {
                    Stop::NodeFailed
                };
                refused = Some((
                    NodeOutcome::Failed {
                        class,
                        check: Some(FailedCheck::CacheRead),
                    },
                    stop,
                ));
                break;
            }
        }
    }
    if let Some((outcome, stop)) = refused {
        let reads = fetched
            .into_iter()
            .map(|(_, kept, index)| (kept, index))
            .collect();
        release_reads(sessions, &mut report.retained, &mut cache, reads, true);
        return (
            Record {
                outcome,
                session: None,
                cache: Some(cache),
            },
            Some(stop),
        );
    }
    report.node_sessions += 1;
    let imports: Vec<VerifiedOutput> = fetched
        .iter()
        .map(|(output, _, _)| output.clone())
        .collect();
    let result = sessions.build(&NodeInput {
        imports: &imports,
        ..input
    });
    let resolved = result
        .session
        .as_ref()
        .is_none_or(|session| session.cleanup.is_ok() && !session.unresolved_owner);
    let reads: Vec<_> = fetched
        .into_iter()
        .map(|(_, kept, index)| {
            cache.reads[index].imported = result.carried;
            (kept, index)
        })
        .collect();
    release_reads(sessions, &mut report.retained, &mut cache, reads, resolved);
    report.retained.extend(result.kept);
    let stop = match &result.outcome {
        NodeOutcome::Built(node_built) => match &plan.write {
            Some((location, mode)) => {
                let write = write_cache(sessions, location, *mode, node_built, node_target);
                let stop = (write.outcome != WriteOutcome::Written).then(|| {
                    if write.outcome == WriteOutcome::Cancelled || sessions.cancelled() {
                        Stop::Cancelled
                    } else {
                        Stop::CacheWrite
                    }
                });
                cache.write = Some(write);
                stop
            }
            None => None,
        },
        NodeOutcome::Failed { class, .. } => {
            Some(if *class == Failure::Cancellation || sessions.cancelled() {
                Stop::Cancelled
            } else {
                Stop::NodeFailed
            })
        }
        NodeOutcome::NotDispatched(reason) => Some(match reason {
            NotDispatched::Cancelled => Stop::Cancelled,
            _ => Stop::Stale(result.stale.clone()),
        }),
    };
    (
        Record {
            outcome: result.outcome,
            session: result.session,
            cache: Some(cache),
        },
        stop,
    )
}

fn fetched_release<S: Sessions>(
    sessions: &mut S,
    report: &mut SolveReport,
    cache: &mut NodeCache,
    kept: Option<Kept>,
    index: usize,
) {
    release_reads(
        sessions,
        &mut report.retained,
        cache,
        vec![(kept, index)],
        true,
    );
}

fn write_cache<S: Sessions>(
    sessions: &mut S,
    location: &Location,
    mode: ExportMode,
    node: &BuiltNode,
    target: Option<&str>,
) -> WriteReport {
    let mut write = WriteReport {
        registry: location.registry.clone(),
        mode,
        export_root: None,
        writer_reference: None,
        outcome: WriteOutcome::Cancelled,
        namespace_reference: location.reference.clone(),
        promotion: None,
        writer_session: None,
        promotion_session: None,
    };
    let Some(layout) = &node.upload else {
        write.outcome = WriteOutcome::Failed(Failure::Integrity);
        return write;
    };
    let writer = cache::writer_reference(&location.reference, layout.root());
    write.export_root = Some(layout.root().clone());
    write.writer_reference = Some(writer.clone());
    if sessions.cancelled() {
        return write;
    }
    let upload = sessions.cache_write(&WriteInput {
        registry: &location.registry,
        reference: &writer,
        layout,
        target,
    });
    write.outcome = upload.outcome;
    write.writer_session = upload.session;
    if write.outcome != WriteOutcome::Written {
        return write;
    }
    if sessions.cancelled() {
        write.promotion = Some(WriteOutcome::Cancelled);
        return write;
    }
    let promotion = sessions.cache_write(&WriteInput {
        registry: &location.registry,
        reference: &location.reference,
        layout,
        target,
    });
    write.promotion = Some(match promotion.outcome {
        WriteOutcome::Written => WriteOutcome::Promoted,
        other => other,
    });
    write.promotion_session = promotion.session;
    write
}

fn key_of(node: &super::graph::Node) -> NodeKey {
    NodeKey {
        producer: node.producer.clone(),
        platform: node.platform.clone(),
    }
}

fn unexported(request: &LoopRequest<'_>, reason: OutputNotExported) -> Vec<TargetReport> {
    request
        .targets
        .iter()
        .map(|target| {
            let kind = request
                .recorded
                .outputs
                .get(target)
                .and_then(|output| output.kind)
                .unwrap_or_default();
            TargetReport::new(target, kind, TargetOutcome::NotExported(reason))
        })
        .collect()
}

fn cache_complete(records: &Records) -> bool {
    records.values().all(|record| {
        !matches!(record.outcome, NodeOutcome::Built(_))
            || record
                .cache
                .as_ref()
                .and_then(|cache| cache.write.as_ref())
                .is_none_or(|write| {
                    write.outcome == WriteOutcome::Written
                        && write.promotion == Some(WriteOutcome::Promoted)
                })
    })
}

pub(crate) struct PublishCandidate {
    pub(crate) image: EffectiveImage,
    pub(crate) nodes: Vec<(String, VerifiedOutput)>,
}

fn run_outputs<S: Sessions>(
    sessions: &mut S,
    request: &LoopRequest<'_>,
    resolution: &Resolution,
    records: &Records,
    stop: &Stop,
) -> (Vec<TargetReport>, BTreeMap<String, PublishCandidate>) {
    if !matches!(stop, Stop::Success) {
        return (
            unexported(request, OutputNotExported::SolveStopped),
            BTreeMap::new(),
        );
    }
    let mut reports = Vec::new();
    let mut candidates = BTreeMap::new();
    let mut reason = None;
    for target in request.targets {
        let kind = request
            .recorded
            .outputs
            .get(target)
            .and_then(|output| output.kind)
            .unwrap_or_default();
        if reason.is_none() && sessions.cancelled() {
            reason = Some(OutputNotExported::Cancelled);
        }
        if let Some(reason) = reason {
            reports.push(TargetReport::new(
                target,
                kind,
                TargetOutcome::NotExported(reason),
            ));
            continue;
        }
        let built: Vec<(&str, &BuiltNode)> = resolution
            .nodes
            .iter()
            .filter(|n| n.producer == *target)
            .filter_map(|n| match records.get(&key_of(n)).map(|r| &r.outcome) {
                Some(NodeOutcome::Built(node)) => Some((n.platform.as_str(), node.as_ref())),
                _ => None,
            })
            .collect();
        let Some((_, first)) = built.first() else {
            reports.push(TargetReport::new(
                target,
                kind,
                TargetOutcome::Failed {
                    class: Failure::Integrity,
                    check: None,
                    published: None,
                },
            ));
            reason = Some(OutputNotExported::Stopped);
            continue;
        };
        let image = &first.image;
        let platforms =
            super::outputs::effective_platforms(image, resolution.request.platforms.as_deref());
        let report = if built.iter().any(|(_, node)| node.image != *image) {
            TargetReport::new(
                target,
                kind,
                TargetOutcome::NotExported(OutputNotExported::Stale),
            )
        } else {
            let nodes: Vec<(String, VerifiedOutput)> = platforms
                .iter()
                .filter_map(|platform| {
                    built
                        .iter()
                        .find(|(p, _)| p == platform)
                        .map(|(p, node)| ((*p).to_owned(), node.output.clone()))
                })
                .collect();
            sessions.output(&OutputInput {
                target,
                image,
                catalog_id: &resolution.catalog_id,
                platforms: &platforms,
                nodes: &nodes,
                docker_daemon: request.recorded.docker_daemon,
            })
        };
        if !report.succeeded() {
            reason = Some(if report.cancelled() || sessions.cancelled() {
                OutputNotExported::Cancelled
            } else {
                OutputNotExported::Stopped
            });
        }
        if matches!(report.outcome, TargetOutcome::Unpublished(_)) {
            let nodes: Vec<(String, VerifiedOutput)> = platforms
                .iter()
                .filter_map(|platform| {
                    built
                        .iter()
                        .find(|(p, _)| p == platform)
                        .map(|(p, node)| ((*p).to_owned(), node.output.clone()))
                })
                .collect();
            candidates.insert(
                (*target).clone(),
                PublishCandidate {
                    image: image.clone(),
                    nodes,
                },
            );
        }
        reports.push(report);
    }
    (reports, candidates)
}

fn run_publications<S: Sessions>(
    sessions: &mut S,
    request: &LoopRequest<'_>,
    targets: &mut [TargetReport],
    candidates: &BTreeMap<String, PublishCandidate>,
    retained: &mut Vec<Kept>,
    stop: &Stop,
) -> Vec<PublicationReport> {
    let mut reports = Vec::new();
    let mut reason = None;
    if !matches!(stop, Stop::Success) {
        reason = Some(NotPublished::SolveStopped);
    }
    for (target, output) in request.targets.iter().zip(targets.iter_mut()) {
        let requested = request
            .recorded
            .outputs
            .get(target)
            .and_then(|output| output.kind)
            .unwrap_or_default()
            == broil_core::images::OutputKind::Registry;
        if !requested {
            continue;
        }
        let blocked = reason.or(match &output.outcome {
            TargetOutcome::Unpublished(_) => None,
            TargetOutcome::NotExported(OutputNotExported::SolveStopped) => {
                Some(NotPublished::SolveStopped)
            }
            TargetOutcome::NotExported(OutputNotExported::Stale) => Some(NotPublished::Stale),
            TargetOutcome::NotExported(OutputNotExported::Cancelled) => {
                Some(NotPublished::Cancelled)
            }
            _ => Some(NotPublished::Stopped),
        });
        if let Some(blocked) = blocked {
            reports.push(PublicationReport::new(
                target,
                PublicationOutcome::NotPublished(blocked),
            ));
            continue;
        }
        let Some(candidate) = candidates.get(target) else {
            reports.push(PublicationReport::new(
                target,
                PublicationOutcome::NotPublished(NotPublished::Stopped),
            ));
            continue;
        };
        let (report, kept) = sessions.publish(&PublishInput::Target {
            target,
            image: &candidate.image,
            nodes: &candidate.nodes,
        });
        if let Some(kept) = kept {
            retained.push(kept);
        }
        if !matches!(report.outcome, PublicationOutcome::NotPublished(_)) {
            if let TargetOutcome::Unpublished(handoff) = &mut output.outcome {
                *handoff = Handoff::Consumed {
                    nodes: handoff.count(),
                };
            }
        }
        if !report.succeeded() {
            reason = Some(if report.cancelled() || sessions.cancelled() {
                NotPublished::Cancelled
            } else {
                NotPublished::Stopped
            });
        }
        reports.push(report);
    }
    reports
}

#[allow(clippy::too_many_arguments)]
fn finish<S: Sessions>(
    sessions: &mut S,
    request: &LoopRequest<'_>,
    mut report: SolveReport,
    resolution: Resolution,
    material: Material,
    records: Records,
    plans: &BTreeMap<NodeKey, NodePlan>,
    stale: &[Diagnostic],
    bound: bool,
) -> SolveReport {
    let (mut targets, candidates) =
        run_outputs(sessions, request, &resolution, &records, &report.stop);
    report.publications = run_publications(
        sessions,
        request,
        &mut targets,
        &candidates,
        &mut report.retained,
        &report.stop,
    );
    report.targets = targets;
    report.cache_complete = cache_complete(&records);
    report.closures = material.closures().cloned().collect();
    report.nodes = assemble(&resolution, &records, plans, stale, bound, &report.stop);
    report.resolution = Some(resolution);
    report
}

fn assemble(
    resolution: &Resolution,
    records: &Records,
    plans: &BTreeMap<NodeKey, NodePlan>,
    stale: &[Diagnostic],
    bound: bool,
    stop: &Stop,
) -> Vec<NodeReport> {
    let cancelled = matches!(stop, Stop::Cancelled);
    let ordinals: Vec<NodeKey> = resolution.nodes.iter().map(key_of).collect();
    let mut awaited: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (ordinal, node) in resolution.nodes.iter().enumerate() {
        if let State::Pending(list) = &node.state {
            awaited.insert(
                ordinal,
                list.iter()
                    .filter_map(|o| usize::try_from(*o).ok())
                    .filter(|o| *o < resolution.nodes.len())
                    .collect(),
            );
        }
    }
    let transitive = |start: usize| -> BTreeSet<usize> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![start];
        while let Some(o) = pending.pop() {
            if let Some(next) = awaited.get(&o) {
                for n in next {
                    if seen.insert(*n) {
                        pending.push(*n);
                    }
                }
            }
        }
        seen
    };
    let diagnosed = |ordinal: usize| -> bool {
        let node = &resolution.nodes[ordinal];
        matches!(
            node.state,
            State::Invalid | State::Unsupported | State::Refused | State::Exhausted
        ) || resolution
            .diagnostics
            .iter()
            .any(|d| d.subject == Subject::Node(ordinal as u64))
    };
    let stale_node = |ordinal: usize| -> bool {
        stale
            .iter()
            .any(|d| d.subject == Subject::Node(ordinal as u64))
    };
    let mut nodes = Vec::new();
    for (ordinal, node) in resolution.nodes.iter().enumerate() {
        let key = &ordinals[ordinal];
        let record = match records.get(key).cloned() {
            Some(recorded) => recorded,
            None => {
                let reason = if cancelled {
                    NotDispatched::Cancelled
                } else if stale_node(ordinal) {
                    NotDispatched::Stale
                } else if diagnosed(ordinal) {
                    NotDispatched::GraphDiagnostic
                } else {
                    let upstream = transitive(ordinal);
                    if upstream.iter().any(|o| {
                        matches!(
                            records.get(&ordinals[*o]).map(|r| &r.outcome),
                            Some(NodeOutcome::Failed { .. })
                        )
                    }) {
                        NotDispatched::ProducerFailed
                    } else if upstream.iter().any(|o| {
                        !records.contains_key(&ordinals[*o]) && !stale_node(*o) && diagnosed(*o)
                    }) {
                        NotDispatched::ProducerNotBuilt
                    } else if bound && matches!(node.state, State::Pending(_)) {
                        NotDispatched::Provisional
                    } else {
                        NotDispatched::Stopped
                    }
                };
                Record {
                    outcome: NodeOutcome::NotDispatched(reason),
                    session: None,
                    cache: plans.get(&ordinals[ordinal]).map(planned_cache),
                }
            }
        };
        nodes.push(NodeReport {
            producer: node.producer.clone(),
            platform: node.platform.clone(),
            outcome: record.outcome,
            session: record.session,
            cache: record.cache,
        });
    }
    nodes
}

