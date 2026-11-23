// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod index;
mod journal;
mod resume;

use super::{
    Cancellation, Descriptor, StageError, VerifiedOutput,
    analysis::{self, HistoryCompletion},
    common::*,
    graph::{Resolution, Resolved},
    json::Value,
    outputs::{self, NotExported, Retained, TargetOutcome, TargetReport},
    policy,
    publish::{
        NotPublished, PublicationClass, PublicationObservation, PublicationOutcome,
        PublicationReport,
    },
    solve::{
        self, BuilderIdentity, BuiltNode, DerivedInputProvenance, IgnoreEntry, NodeCache,
        NodeOutcome, NotDispatched, ReadOutcome, SessionObservation, WriteOutcome,
    },
    store,
    supervise::{self, Active, Clock, Permit},
    tool_policy::Tool,
};
use broil_config::images::select::EffectiveImage;
use broil_core::images::reference::ImageReference;
use broil_core::secret::path_safety::sudo_nonce;
use std::{
    borrow::Cow,
    collections::BTreeMap,
    fmt::Write as _,
    fs::File,
    path::{Path, PathBuf},
};

pub(crate) use index::{
    Commit, Index, Projection, PublicationDisposition, Settled, rebuild, release_candidates,
};
pub(crate) use journal::{
    BindingReason, Boundary, CacheRead, Candidate, Disposition, FailureClass, Journal, Kind,
    LocalIntegrity, Observation, ObservationDetail, OperationRecord, Outcome, PublicationClosure,
    PublicationEntry, RetentionClosure, Settlement, StageAcquisition, Tag, Window,
};
pub(crate) use resume::{Resumed, WindowOutcome, requires_explicit_decision, resume};

pub(crate) const RECORD_BYTES: u64 = 16_777_216;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadFailure {
    UnsupportedVersion(u64),
    Invalid(Failure),
}

impl From<ReadFailure> for Failure {
    fn from(failure: ReadFailure) -> Self {
        match failure {
            ReadFailure::UnsupportedVersion(_) => Failure::Protocol,
            ReadFailure::Invalid(failure) => failure,
        }
    }
}


#[derive(Clone, Debug)]
pub(crate) enum Out {
    Null,
    Bool(bool),
    Number(u64),
    Text(String),
    Array(Vec<Out>),
    Raw(Vec<u8>),
    Object(Vec<(Cow<'static, str>, Out)>),
}

fn object(members: Vec<(&'static str, Out)>) -> Out {
    Out::Object(
        members
            .into_iter()
            .map(|(name, value)| (Cow::Borrowed(name), value))
            .collect(),
    )
}

fn keyed(members: Vec<(String, Out)>) -> Out {
    Out::Object(
        members
            .into_iter()
            .map(|(name, value)| (Cow::Owned(name), value))
            .collect(),
    )
}

impl Out {
    fn text(value: impl Into<String>) -> Self {
        Out::Text(value.into())
    }

    fn write(&self, buffer: &mut String) -> Result<()> {
        match self {
            Out::Null => buffer.push_str("null"),
            Out::Bool(value) => buffer.push_str(if *value { "true" } else { "false" }),
            Out::Number(value) => write!(buffer, "{value}").map_err(|_| Failure::Protocol)?,
            Out::Text(value) => {
                let encoded = serde_json::to_string(value).map_err(|_| Failure::Protocol)?;
                buffer.push_str(&encoded);
            }
            Out::Raw(bytes) => {
                buffer.push_str(std::str::from_utf8(bytes).map_err(|_| Failure::Protocol)?);
            }
            Out::Array(items) => {
                buffer.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        buffer.push(',');
                    }
                    item.write(buffer)?;
                }
                buffer.push(']');
            }
            Out::Object(members) => {
                buffer.push('{');
                for (i, (name, value)) in members.iter().enumerate() {
                    if i > 0 {
                        buffer.push(',');
                    }
                    let encoded = serde_json::to_string(name).map_err(|_| Failure::Protocol)?;
                    buffer.push_str(&encoded);
                    buffer.push(':');
                    value.write(buffer)?;
                }
                buffer.push('}');
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let mut buffer = String::new();
        self.write(&mut buffer)?;
        buffer.push('\n');
        Ok(buffer.into_bytes())
    }
}

pub(crate) fn descriptor_out(descriptor: &Descriptor) -> Out {
    object(vec![
        ("digest", Out::text(&descriptor.digest)),
        ("size", Out::Number(descriptor.size)),
        ("media_type", Out::text(&descriptor.media_type)),
    ])
}

fn descriptors_out(descriptors: &[Descriptor]) -> Out {
    Out::Array(descriptors.iter().map(descriptor_out).collect())
}


pub(crate) fn valid_artifact(value: &str) -> bool {
    value.len() == 41 && value.starts_with("artifact-") && hex(&value.as_bytes()[9..])
}

pub(crate) fn mint_artifact() -> Result<String> {
    let nonce = sudo_nonce().map_err(|_| Failure::Storage)?;
    let id = format!("artifact-{nonce}");
    require(valid_artifact(&id), Failure::Integrity)?;
    Ok(id)
}


#[derive(Clone, Debug)]
pub(crate) enum Fact {
    Available(Out),
    Unavailable(String),
}

impl Fact {
    fn out(&self) -> Out {
        match self {
            Fact::Available(value) => value.clone(),
            Fact::Unavailable(reason) => object(vec![
                ("status", Out::text("unavailable")),
                ("reason", Out::text(reason)),
            ]),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct InputFact {
    pub(crate) declared: Out,
    pub(crate) effective: Out,
    pub(crate) observed: Fact,
}

impl InputFact {
    fn out(&self) -> Out {
        object(vec![
            ("declared", self.declared.clone()),
            ("effective", self.effective.clone()),
            ("observed", self.observed.out()),
        ])
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SourceInput {
    pub(crate) content: InputFact,
    pub(crate) dirty: bool,
    pub(crate) untracked: bool,
    pub(crate) revision: Option<String>,
}

impl SourceInput {
    fn out(&self) -> Out {
        let mut members = vec![
            ("content", self.content.out()),
            ("dirty", Out::Bool(self.dirty)),
            ("untracked", Out::Bool(self.untracked)),
        ];
        if let Some(revision) = &self.revision {
            members.push(("revision", Out::text(revision)));
        }
        object(members)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Transfer {
    pub(crate) adapter_source: String,
    pub(crate) protocol: String,
    pub(crate) registry: String,
    pub(crate) reference: String,
    pub(crate) descriptor: Descriptor,
}

impl Transfer {
    fn out(&self) -> Out {
        object(vec![
            ("adapter_source", Out::text(&self.adapter_source)),
            ("protocol", Out::text(&self.protocol)),
            ("registry", Out::text(&self.registry)),
            ("reference", Out::text(&self.reference)),
            ("descriptor", descriptor_out(&self.descriptor)),
        ])
    }
}

#[derive(Clone, Debug)]
pub(crate) struct PlatformRecord {
    pub(crate) platform: String,
    pub(crate) manifest: Descriptor,
    pub(crate) config: Descriptor,
    pub(crate) layers: Vec<Descriptor>,
}

impl PlatformRecord {
    fn out(&self) -> Out {
        object(vec![
            ("platform", Out::text(&self.platform)),
            ("manifest", descriptor_out(&self.manifest)),
            ("config", descriptor_out(&self.config)),
            ("layers", descriptors_out(&self.layers)),
        ])
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Producer {
    pub(crate) name: String,
    pub(crate) declared: String,
    pub(crate) normalized: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetAssociation {
    pub(crate) project_id: String,
    pub(crate) environment: Option<String>,
    pub(crate) backend: String,
    pub(crate) logical_target: String,
}

impl TargetAssociation {
    fn out(&self) -> Out {
        object(vec![
            ("project_id", Out::text(&self.project_id)),
            (
                "environment",
                match &self.environment {
                    Some(environment) => Out::text(environment),
                    None => Out::Null,
                },
            ),
            ("backend", Out::text(&self.backend)),
            ("logical_target", Out::text(&self.logical_target)),
        ])
    }

    fn validate(&self) -> Result<()> {
        require(
            self.project_id.len() == 72
                && self.project_id.starts_with("project-")
                && hex(&self.project_id.as_bytes()[8..])
                && !self.backend.is_empty()
                && !self.logical_target.is_empty()
                && self.environment.as_ref().is_none_or(|e| !e.is_empty()),
            Failure::Policy,
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Graph {
    pub(crate) analyzer_identity: AnalyzerIdentity,
    pub(crate) catalog_id: String,
    pub(crate) graph_id: String,
    pub(crate) nodes: Out,
    pub(crate) edges: Out,
    pub(crate) source_locations: Out,
    pub(crate) external_pins: Out,
    pub(crate) frontend_pin: String,
    pub(crate) graph_input_id: String,
}

impl Graph {
    fn out(&self) -> Out {
        object(vec![
            ("analyzer_identity", self.analyzer_identity.out()),
            ("catalog_id", Out::text(&self.catalog_id)),
            ("graph_id", Out::text(&self.graph_id)),
            ("nodes", self.nodes.clone()),
            ("edges", self.edges.clone()),
            ("source_locations", self.source_locations.clone()),
            ("external_pins", self.external_pins.clone()),
            ("frontend_pin", Out::text(&self.frontend_pin)),
            ("graph_input_id", Out::text(&self.graph_input_id)),
        ])
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SecretInput {
    pub(crate) consumer: String,
    pub(crate) set: String,
    pub(crate) key: String,
    pub(crate) version: Fact,
}

impl SecretInput {
    fn out(&self) -> Out {
        object(vec![
            ("consumer", Out::text(&self.consumer)),
            ("set", Out::text(&self.set)),
            ("key", Out::text(&self.key)),
            ("version", self.version.out()),
        ])
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Provenance {
    #[allow(dead_code)]
    Available(Vec<Descriptor>),
    Unavailable(String),
}

impl Provenance {
    fn out(&self) -> Out {
        match self {
            Provenance::Available(descriptors) => object(vec![
                ("status", Out::text("available")),
                ("descriptors", descriptors_out(descriptors)),
            ]),
            Provenance::Unavailable(reason) => object(vec![
                ("status", Out::text("unavailable")),
                ("reason", Out::text(reason)),
            ]),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct EvidenceSource {
    pub(crate) node_build: String,
    pub(crate) output: String,
}

#[derive(Clone, Debug)]
pub(crate) struct BuildEvidence {
    pub(crate) method: String,
    pub(crate) closure_identity: String,
    pub(crate) completed_at: String,
    pub(crate) source: EvidenceSource,
}

impl BuildEvidence {
    fn out(&self) -> Out {
        object(vec![
            ("method", Out::text(&self.method)),
            ("closure_identity", Out::text(&self.closure_identity)),
            ("completed_at", Out::text(&self.completed_at)),
            (
                "source",
                object(vec![
                    ("node_build", Out::text(&self.source.node_build)),
                    ("output", Out::text(&self.source.output)),
                ]),
            ),
        ])
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ToolSource {
    Commit(String),
    Inputs {
        source_inputs: String,
        companion: Companion,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Companion {
    BuildkitSource(String),
    Toolchain(String),
}

impl ToolSource {
    fn out(&self) -> Out {
        match self {
            ToolSource::Commit(commit) => object(vec![
                ("variant", Out::text("source-commit")),
                ("source_commit", Out::text(commit)),
            ]),
            ToolSource::Inputs {
                source_inputs,
                companion,
            } => {
                let (name, value) = match companion {
                    Companion::BuildkitSource(value) => ("buildkit_source", value),
                    Companion::Toolchain(value) => ("toolchain", value),
                };
                object(vec![
                    ("variant", Out::text("source-inputs")),
                    ("source_inputs", Out::text(source_inputs)),
                    (name, Out::text(value)),
                ])
            }
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            ToolSource::Commit(commit) => require(
                commit.len() == 40 && hex(commit.as_bytes()),
                Failure::Policy,
            ),
            ToolSource::Inputs {
                source_inputs,
                companion,
            } => {
                require(!source_inputs.is_empty(), Failure::Policy)?;
                match companion {
                    Companion::BuildkitSource(value) => {
                        require(value.len() == 40 && hex(value.as_bytes()), Failure::Policy)
                    }
                    Companion::Toolchain(value) => require(!value.is_empty(), Failure::Policy),
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicCopy {
    pub(crate) version: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) source: ToolSource,
}

impl PublicCopy {
    fn out(&self) -> Out {
        object(vec![
            ("version", Out::text(&self.version)),
            ("sha256", Out::text(&self.sha256)),
            ("size", Out::Number(self.size)),
            ("source", self.source.out()),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AnalyzerIdentity {
    pub(crate) copy: PublicCopy,
    pub(crate) tool_identity: String,
}

impl AnalyzerIdentity {
    fn out(&self) -> Out {
        object(vec![
            ("version", Out::text(&self.copy.version)),
            ("sha256", Out::text(&self.copy.sha256)),
            ("size", Out::Number(self.copy.size)),
            ("source", self.copy.source.out()),
            ("tool_identity", Out::text(&self.tool_identity)),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FilesystemHelper {
    pub(crate) sha256: String,
    pub(crate) size: u64,
    pub(crate) protocol_version: u64,
    pub(crate) target: String,
    pub(crate) build_script: String,
    pub(crate) compiler: Vec<String>,
    pub(crate) source_inputs_id: String,
}

impl FilesystemHelper {
    fn out(&self) -> Out {
        object(vec![
            ("sha256", Out::text(&self.sha256)),
            ("size", Out::Number(self.size)),
            ("protocol_version", Out::Number(self.protocol_version)),
            ("target", Out::text(&self.target)),
            ("build_script", Out::text(&self.build_script)),
            (
                "compiler",
                Out::Array(self.compiler.iter().map(Out::text).collect()),
            ),
            ("source_inputs_id", Out::text(&self.source_inputs_id)),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Tools {
    pub(crate) broil_version: String,
    pub(crate) filesystem_helper: FilesystemHelper,
    pub(crate) public_copies: Vec<(&'static str, PublicCopy)>,
    pub(crate) analyzer: AnalyzerIdentity,
    pub(crate) frontend_reference: String,
    pub(crate) buildkit_version: String,
    pub(crate) buildkit_source_commit: String,
}

impl Tools {
    fn out(&self) -> Out {
        object(vec![
            (
                "broil",
                object(vec![("version", Out::text(&self.broil_version))]),
            ),
            (
                "client",
                object(vec![
                    ("filesystem_helper", self.filesystem_helper.out()),
                    (
                        "public_copies",
                        object(
                            self.public_copies
                                .iter()
                                .map(|(name, copy)| (*name, copy.out()))
                                .collect(),
                        ),
                    ),
                ]),
            ),
            ("analyzer", self.analyzer.out()),
            (
                "frontend",
                object(vec![("reference", Out::text(&self.frontend_reference))]),
            ),
            (
                "buildkit",
                object(vec![
                    ("version", Out::text(&self.buildkit_version)),
                    ("source_commit", Out::text(&self.buildkit_source_commit)),
                ]),
            ),
        ])
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ToolsRefusal {
    pub(crate) failure: Failure,
    #[allow(dead_code)]
    pub(crate) disagreement: Vec<(&'static str, String)>,
}

impl From<Failure> for ToolsRefusal {
    fn from(failure: Failure) -> Self {
        ToolsRefusal {
            failure,
            disagreement: Vec::new(),
        }
    }
}

const PUBLIC_COPIES: [(&str, &str); 5] = [
    ("docker", "source-commit"),
    ("buildx", "source-commit"),
    ("buildctl", "source-commit"),
    ("analyzer", "source-inputs"),
    ("registry", "source-inputs"),
];

fn manifest() -> Result<serde_json::Value> {
    serde_json::from_str(include_str!(
        "../../../../../tools/image-client/public-tools.json"
    ))
    .map_err(|_| Failure::Policy)
}

fn compatibility() -> Result<serde_json::Value> {
    serde_json::from_str(include_str!(
        "../../../../../tools/image-client/compatibility.json"
    ))
    .map_err(|_| Failure::Policy)
}

fn source_inputs_id(value: &serde_json::Value) -> Result<String> {
    let map = value.as_object().ok_or(Failure::Policy)?;
    let mut bytes = Vec::new();
    bytes.push(b'{');
    let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
    for (i, (key, value)) in sorted.into_iter().enumerate() {
        if i != 0 {
            bytes.push(b',');
        }
        serde_json::to_writer(&mut bytes, key).map_err(|_| Failure::Policy)?;
        bytes.push(b':');
        serde_json::to_writer(&mut bytes, value).map_err(|_| Failure::Policy)?;
    }
    bytes.push(b'}');
    Ok(analysis::hash(&bytes))
}

fn text_member(value: &serde_json::Value, name: &str) -> Result<String> {
    Ok(value[name].as_str().ok_or(Failure::Policy)?.to_owned())
}

pub(crate) fn capture_tools(builder_version: &str) -> std::result::Result<Tools, ToolsRefusal> {
    let manifest = manifest()?;
    let compatibility = compatibility()?;

    let (helper_sha256, helper_size) = policy::helper_identity()?;
    let helper = &compatibility["filesystem_helper"];
    let filesystem_helper = FilesystemHelper {
        sha256: helper_sha256,
        size: helper_size,
        protocol_version: helper["protocol_version"].as_u64().ok_or(Failure::Policy)?,
        target: text_member(helper, "target")?,
        build_script: text_member(helper, "build_script")?,
        compiler: helper["compiler"]
            .as_array()
            .ok_or(Failure::Policy)?
            .iter()
            .map(|value| Ok(value.as_str().ok_or(Failure::Policy)?.to_owned()))
            .collect::<Result<Vec<_>>>()?,
        source_inputs_id: source_inputs_id(&helper["source_inputs"])?,
    };

    let mut public_copies = Vec::new();
    for (name, variant) in PUBLIC_COPIES {
        let entry = &manifest["tools"][name];
        let tool = Tool::parse(name)?;
        let (sha256, size) = tool.identity()?;
        let source = match variant {
            "source-commit" => ToolSource::Commit(text_member(entry, "source_commit")?),
            _ => ToolSource::Inputs {
                source_inputs: source_inputs_id(&entry["source_inputs"])?,
                companion: if name == "analyzer" {
                    Companion::BuildkitSource(text_member(entry, "buildkit_source")?)
                } else {
                    Companion::Toolchain(text_member(entry, "toolchain")?)
                },
            },
        };
        source.validate()?;
        public_copies.push((
            name,
            PublicCopy {
                version: text_member(entry, "version")?,
                sha256,
                size,
                source,
            },
        ));
    }

    let analyzer_copy = public_copies
        .iter()
        .find(|(name, _)| *name == "analyzer")
        .map(|(_, copy)| copy.clone())
        .ok_or(Failure::Policy)?;
    let analyzer = AnalyzerIdentity {
        copy: analyzer_copy,
        tool_identity: analysis::tool_identity()?,
    };

    let buildctl = public_copies
        .iter()
        .find(|(name, _)| *name == "buildctl")
        .map(|(_, copy)| copy.clone())
        .ok_or(Failure::Policy)?;
    let buildkit_source_commit = match &buildctl.source {
        ToolSource::Commit(commit) => commit.clone(),
        ToolSource::Inputs { .. } => return Err(Failure::Policy.into()),
    };
    let analyzer_buildkit = match &analyzer.copy.source {
        ToolSource::Inputs {
            companion: Companion::BuildkitSource(value),
            ..
        } => value.clone(),
        _ => return Err(Failure::Policy.into()),
    };

    let mut disagreement = Vec::new();
    if buildctl.version != builder_version {
        disagreement.push(("buildkit.version", builder_version.to_owned()));
        disagreement.push((
            "client.public_copies.buildctl.version",
            buildctl.version.clone(),
        ));
    }
    if buildkit_source_commit != analyzer_buildkit {
        disagreement.push((
            "client.public_copies.buildctl.source.source_commit",
            buildkit_source_commit.clone(),
        ));
        disagreement.push((
            "client.public_copies.analyzer.source.buildkit_source",
            analyzer_buildkit,
        ));
    }
    if !disagreement.is_empty() {
        return Err(ToolsRefusal {
            failure: Failure::Integrity,
            disagreement,
        });
    }

    Ok(Tools {
        broil_version: env!("CARGO_PKG_VERSION").to_owned(),
        filesystem_helper,
        public_copies,
        analyzer,
        frontend_reference: analysis::FRONTEND.to_owned(),
        buildkit_version: buildctl.version.clone(),
        buildkit_source_commit,
    })
}


#[derive(Clone, Debug)]
pub(crate) struct Transformation {
    pub(crate) implementation: String,
    pub(crate) protocol: String,
    pub(crate) inputs_id: String,
    pub(crate) map_id: String,
}

fn range_out(range: &analysis::Range) -> Out {
    let mut members = vec![
        ("start_line", Out::Number(range.start_line)),
        ("end_line", Out::Number(range.end_line)),
    ];
    if let Some(column) = range.start_column {
        members.push(("start_column", Out::Number(column)));
    }
    if let Some(column) = range.end_column {
        members.push(("end_column", Out::Number(column)));
    }
    object(members)
}

fn ranges_out(ranges: &[analysis::Range]) -> Out {
    Out::Array(ranges.iter().map(range_out).collect())
}

fn instruction_name(instruction: analysis::Instruction) -> &'static str {
    match instruction {
        analysis::Instruction::From => "from",
        analysis::Instruction::Copy => "copy",
        analysis::Instruction::RunMount => "run-mount",
    }
}

fn tag_origin_name(origin: analysis::TagOrigin) -> &'static str {
    match origin {
        analysis::TagOrigin::Declared => "declared",
        analysis::TagOrigin::Default => "default",
        analysis::TagOrigin::Absent => "absent",
    }
}

fn role_name(role: analysis::Role) -> &'static str {
    match role {
        analysis::Role::Inheritance => "inheritance",
        analysis::Role::FileSource => "file-source",
    }
}

fn location_out(use_: &analysis::Use) -> Out {
    let mut members = vec![
        ("role", Out::text(role_name(use_.role))),
        ("instruction", Out::text(instruction_name(use_.instruction))),
        ("tag_origin", Out::text(tag_origin_name(use_.tag_origin))),
    ];
    match &use_.location {
        analysis::Location::Dockerfile(ranges) => {
            members.insert(0, ("kind", Out::text("source")));
            members.push(("ranges", ranges_out(ranges)));
        }
        analysis::Location::Inherited {
            parent_reference,
            parent_root,
            parent_platform,
            trigger_index,
            consuming_from,
        } => {
            members.insert(0, ("kind", Out::text("inherited")));
            members.push(("parent_reference", Out::text(parent_reference)));
            members.push(("parent_root", Out::text(parent_root)));
            members.push(("parent_platform", Out::text(parent_platform)));
            members.push(("trigger_index", Out::Number(*trigger_index)));
            members.push(("consuming_from", ranges_out(consuming_from)));
        }
        analysis::Location::Unavailable => {
            members.insert(0, ("kind", Out::text("unavailable")));
        }
    }
    object(members)
}

fn constraint_out(reference: &str) -> Result<Out> {
    let (kind, value) = declared_constraint(reference)?;
    Ok(object(vec![
        ("kind", Out::text(kind)),
        ("value", Out::text(value)),
    ]))
}

fn declared_constraint(reference: &str) -> Result<(&'static str, String)> {
    let parsed = ImageReference::parse(reference).ok_or(Failure::Protocol)?;
    match (parsed.digest, parsed.tag) {
        (Some(digest), _) => Ok(("digest", digest)),
        (None, Some(tag)) => Ok(("tag", tag)),
        (None, None) => Err(Failure::Protocol),
    }
}

fn history_completion_agrees(completion: &HistoryCompletion, preserved_layers: usize) -> bool {
    let zeroed = matches!(
        completion.original_form.as_str(),
        "absent" | "null" | "empty"
    );
    completion.original_non_empty() <= completion.original_total()
        && (!zeroed || (completion.original_total() == 0 && completion.original_non_empty() == 0))
        && completion.added.len() as u64
            == (preserved_layers as u64).saturating_sub(completion.original_non_empty())
}

fn history_completion_out(
    completion: &HistoryCompletion,
    preserved_layers: usize,
) -> Result<Option<Out>> {
    if completion.added.is_empty() {
        return Ok(None);
    }
    require(
        history_completion_agrees(completion, preserved_layers),
        Failure::Integrity,
    )?;
    let entries = completion
        .added
        .iter()
        .map(|entry| {
            object(vec![
                ("history_ordinal", Out::Number(entry.history_ordinal)),
                ("layer_ordinal", Out::Number(entry.layer_ordinal)),
                ("layer_descriptor", descriptor_out(&entry.layer)),
                ("diff_id", Out::text(&entry.diff_id)),
                ("synthetic_identity", Out::text(&entry.entry_sha256)),
            ])
        })
        .collect();
    Ok(Some(object(vec![
        ("original_form", Out::text(&completion.original_form)),
        ("original_total", Out::Number(completion.original_total())),
        (
            "original_non_empty",
            Out::Number(completion.original_non_empty()),
        ),
        ("entries", Out::Array(entries)),
        ("source", Out::text(&completion.source_sha256)),
        ("protocol", Out::Number(completion.protocol_version)),
        ("convention", Out::text(&completion.convention)),
    ])))
}

impl HistoryCompletion {
    fn original_total(&self) -> u64 {
        self.original_entries
    }
    fn original_non_empty(&self) -> u64 {
        self.original_nonempty
    }
}

fn derived_out(
    provenance: &DerivedInputProvenance,
    transformation: &Transformation,
) -> Result<Out> {
    let mut members = vec![
        ("role", Out::text(provenance.role)),
        (
            "original",
            object(vec![
                ("reference", Out::text(&provenance.original_reference)),
                (
                    "constraint",
                    constraint_out(&provenance.original_reference)?,
                ),
                ("platform", Out::text(&provenance.original_platform)),
                ("root", Out::text(&provenance.original_root)),
                ("manifest", descriptor_out(&provenance.original_manifest)),
                ("config", descriptor_out(&provenance.original_config)),
            ]),
        ),
        (
            "derived",
            object(vec![
                ("root", descriptor_out(&provenance.derived_root)),
                ("manifest", descriptor_out(&provenance.derived_manifest)),
                ("config", descriptor_out(&provenance.derived_config)),
            ]),
        ),
        ("preserved_layers", descriptors_out(&provenance.layers)),
        (
            "transformation",
            object(vec![
                ("implementation", Out::text(&transformation.implementation)),
                ("protocol", Out::text(&transformation.protocol)),
                ("inputs_id", Out::text(&transformation.inputs_id)),
                (
                    "map_id",
                    Out::text(format!("{}/{}", transformation.map_id, provenance.ordinal)),
                ),
            ]),
        ),
        (
            "locations",
            Out::Array(provenance.uses.iter().map(location_out).collect()),
        ),
    ];
    let completion = match &provenance.history_completion {
        Some(completion) => history_completion_out(completion, provenance.layers.len())?,
        None => None,
    };
    if let Some(completion) = completion {
        members.push(("history_completion", completion));
    }
    Ok(object(members))
}


#[derive(Clone, Debug)]
pub(crate) struct Inputs {
    pub(crate) source: SourceInput,
    pub(crate) ignore: InputFact,
    pub(crate) stages: InputFact,
    pub(crate) args: Vec<(String, InputFact)>,
    pub(crate) platforms: InputFact,
    pub(crate) builder: InputFact,
    pub(crate) frontend: InputFact,
    pub(crate) outputs: InputFact,
    pub(crate) cache: InputFact,
    pub(crate) entitlements: InputFact,
    pub(crate) transfers: Vec<Transfer>,
    pub(crate) derived: Derived,
}

#[derive(Clone, Debug)]
pub(crate) enum Derived {
    Reported(Vec<DerivedInputProvenance>),
    Encoded(Vec<Vec<u8>>),
}

impl Inputs {
    fn out(&self, transformation: &Transformation) -> Result<Out> {
        let derived = match &self.derived {
            Derived::Reported(entries) => entries
                .iter()
                .map(|entry| derived_out(entry, transformation))
                .collect::<Result<Vec<_>>>()?,
            Derived::Encoded(entries) => entries
                .iter()
                .map(|bytes| Out::Raw(bytes.clone()))
                .collect(),
        };
        Ok(object(vec![
            ("source", self.source.out()),
            ("ignore", self.ignore.out()),
            ("stages", self.stages.out()),
            (
                "args",
                keyed(
                    self.args
                        .iter()
                        .map(|(name, fact)| (name.clone(), fact.out()))
                        .collect(),
                ),
            ),
            ("platforms", self.platforms.out()),
            ("builder", self.builder.out()),
            ("frontend", self.frontend.out()),
            ("outputs", self.outputs.out()),
            ("cache", self.cache.out()),
            ("entitlements", self.entitlements.out()),
            (
                "transfers",
                Out::Array(self.transfers.iter().map(Transfer::out).collect()),
            ),
            ("derived", Out::Array(derived)),
        ]))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Record {
    pub(crate) artifact_id: String,
    pub(crate) created_at: String,
    pub(crate) build_operation_id: String,
    pub(crate) producer: Producer,
    pub(crate) target: TargetAssociation,
    pub(crate) root: Descriptor,
    pub(crate) platforms: Vec<PlatformRecord>,
    pub(crate) associated_content: Vec<Descriptor>,
    pub(crate) inputs: Inputs,
    pub(crate) graph: Graph,
    pub(crate) tools: Tools,
    pub(crate) builder: BuilderIdentity,
    pub(crate) secret_inputs: Vec<SecretInput>,
    pub(crate) provenance: Provenance,
    pub(crate) build_evidence: BuildEvidence,
    pub(crate) annotations: Vec<(String, String)>,
    pub(crate) transformation: Transformation,
}

impl Record {
    fn out(&self) -> Result<Out> {
        let mut members = vec![
            ("format_version", Out::Number(1)),
            ("artifact_id", Out::text(&self.artifact_id)),
            ("created_at", Out::text(&self.created_at)),
            ("build_operation_id", Out::text(&self.build_operation_id)),
            (
                "producer",
                object(vec![
                    ("name", Out::text(&self.producer.name)),
                    ("declared", Out::text(&self.producer.declared)),
                    ("normalized", Out::text(&self.producer.normalized)),
                ]),
            ),
            ("target", self.target.out()),
            ("root", descriptor_out(&self.root)),
            (
                "platforms",
                Out::Array(self.platforms.iter().map(PlatformRecord::out).collect()),
            ),
            (
                "associated_content",
                descriptors_out(&self.associated_content),
            ),
            ("inputs", self.inputs.out(&self.transformation)?),
            ("graph", self.graph.out()),
            ("tools", self.tools.out()),
            ("builder", builder_out(&self.builder)),
            (
                "secret_inputs",
                Out::Array(self.secret_inputs.iter().map(SecretInput::out).collect()),
            ),
            ("provenance", self.provenance.out()),
            ("build_evidence", self.build_evidence.out()),
        ];
        if !self.annotations.is_empty() {
            members.push((
                "annotations",
                keyed(
                    self.annotations
                        .iter()
                        .map(|(key, value)| (key.clone(), Out::text(value)))
                        .collect(),
                ),
            ));
        }
        Ok(object(members))
    }

    fn validate(&self) -> Result<()> {
        require(valid_artifact(&self.artifact_id), Failure::Policy)?;
        require(valid_operation(&self.build_operation_id), Failure::Policy)?;
        require(valid_time(&self.created_at), Failure::Policy)?;
        require(
            valid_time(&self.build_evidence.completed_at),
            Failure::Policy,
        )?;
        self.target.validate()?;
        require(
            !self.producer.name.is_empty()
                && !self.producer.declared.is_empty()
                && !self.producer.normalized.is_empty(),
            Failure::Policy,
        )?;
        self.root.validate()?;
        require(!self.platforms.is_empty(), Failure::Policy)?;
        for platform in &self.platforms {
            require(!platform.platform.is_empty(), Failure::Policy)?;
            platform.manifest.validate()?;
            platform.config.validate()?;
            for layer in &platform.layers {
                layer.validate()?;
            }
        }
        if self.platforms.len() == 1 {
            require(
                self.root == self.platforms[0].manifest
                    || self.root.digest != self.platforms[0].manifest.digest,
                Failure::Integrity,
            )?;
        }
        for descriptor in &self.associated_content {
            descriptor.validate()?;
        }
        if let Derived::Reported(entries) = &self.inputs.derived {
            for entry in entries {
                entry.original_manifest.validate()?;
                entry.original_config.validate()?;
                entry.derived_root.validate()?;
                entry.derived_manifest.validate()?;
                entry.derived_config.validate()?;
                for layer in &entry.layers {
                    layer.validate()?;
                }
                require(
                    entry.derived_root == entry.derived_manifest,
                    Failure::Integrity,
                )?;
                declared_constraint(&entry.original_reference)?;
                if let Some(completion) = &entry.history_completion {
                    require(
                        completion.added.is_empty()
                            || history_completion_agrees(completion, entry.layers.len()),
                        Failure::Integrity,
                    )?;
                }
            }
        }
        for entry in &self.secret_inputs {
            require(
                !entry.consumer.is_empty() && !entry.set.is_empty() && !entry.key.is_empty(),
                Failure::Policy,
            )?;
        }
        for (key, value) in &self.annotations {
            require(!key.is_empty() && !value.contains('\0'), Failure::Policy)?;
        }
        builder_validate(&self.builder)?;
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = self.out()?.encode()?;
        require(bytes.len() as u64 <= RECORD_BYTES, Failure::Limit)?;
        Ok(bytes)
    }
}

fn builder_out(builder: &BuilderIdentity) -> Out {
    object(vec![
        ("logical_name", Out::text(&builder.name)),
        ("kind", Out::text(builder.kind)),
        ("endpoint", Out::text(&builder.endpoint)),
        ("server_name", Out::text(&builder.server_name)),
        (
            "capabilities",
            object(vec![
                ("version", Out::text(&builder.version)),
                ("oci_worker", Out::Bool(builder.oci_worker)),
                (
                    "platforms",
                    Out::Array(builder.platforms.iter().map(Out::text).collect()),
                ),
                ("build_platform", Out::text(&builder.build_platform)),
            ]),
        ),
    ])
}

fn builder_validate(builder: &BuilderIdentity) -> Result<()> {
    require(
        !builder.name.is_empty()
            && !builder.endpoint.is_empty()
            && !builder.server_name.is_empty()
            && !builder.version.is_empty()
            && !builder.platforms.is_empty()
            && !builder.build_platform.is_empty(),
        Failure::Policy,
    )
}

pub(crate) fn format_utc(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (hour, minute, second) = (rest / 3_600, (rest % 3_600) / 60, rest % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub(crate) fn now_utc() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format_utc(seconds)
}

pub(crate) fn valid_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|i| bytes[*i].is_ascii_digit())
}

pub(crate) fn decode_tools(value: Value<'_>) -> Result<Tools> {
    fn text(value: Value<'_>) -> Result<String> {
        Ok(std::str::from_utf8(value.text()?.get())
            .map_err(|_| Failure::Protocol)?
            .into())
    }
    fn source(value: Value<'_>) -> Result<ToolSource> {
        let variant = value.field("variant")?;
        let source = if variant.equals("source-commit")? {
            let f = value.object(&[b"variant", b"source_commit"])?;
            ToolSource::Commit(text(f[1])?)
        } else if variant.equals("source-inputs")? {
            let buildkit = value.object(&[b"variant", b"source_inputs", b"buildkit_source"]);
            match buildkit {
                Ok(f) => ToolSource::Inputs {
                    source_inputs: text(f[1])?,
                    companion: Companion::BuildkitSource(text(f[2])?),
                },
                Err(_) => {
                    let f = value.object(&[b"variant", b"source_inputs", b"toolchain"])?;
                    ToolSource::Inputs {
                        source_inputs: text(f[1])?,
                        companion: Companion::Toolchain(text(f[2])?),
                    }
                }
            }
        } else {
            return Err(Failure::Protocol);
        };
        source.validate()?;
        Ok(source)
    }
    fn copy(value: Value<'_>) -> Result<PublicCopy> {
        let f = value.object(&[b"version", b"sha256", b"size", b"source"])?;
        Ok(PublicCopy {
            version: text(f[0])?,
            sha256: text(f[1])?,
            size: f[2].number()?,
            source: source(f[3])?,
        })
    }
    let top = value.object(&[b"broil", b"client", b"analyzer", b"frontend", b"buildkit"])?;
    let broil = top[0].object(&[b"version"])?;
    let client = top[1].object(&[b"filesystem_helper", b"public_copies"])?;
    let helper = client[0].object(&[
        b"sha256",
        b"size",
        b"protocol_version",
        b"target",
        b"build_script",
        b"compiler",
        b"source_inputs_id",
    ])?;
    let mut public_copies = Vec::new();
    for (name, variant) in PUBLIC_COPIES {
        let entry = client[1].field(name)?;
        let copy = copy(entry)?;
        let tag = match &copy.source {
            ToolSource::Commit(_) => "source-commit",
            ToolSource::Inputs { .. } => "source-inputs",
        };
        require(tag == variant, Failure::Protocol)?;
        public_copies.push((name, copy));
    }
    require(
        client[1].members()?.len() == PUBLIC_COPIES.len(),
        Failure::Protocol,
    )?;
    let analyzer = top[2].object(&[b"version", b"sha256", b"size", b"source", b"tool_identity"])?;
    let frontend = top[3].object(&[b"reference"])?;
    let buildkit = top[4].object(&[b"version", b"source_commit"])?;
    let tools = Tools {
        broil_version: text(broil[0])?,
        filesystem_helper: FilesystemHelper {
            sha256: text(helper[0])?,
            size: helper[1].number()?,
            protocol_version: helper[2].number()?,
            target: text(helper[3])?,
            build_script: text(helper[4])?,
            compiler: helper[5]
                .array()?
                .into_iter()
                .map(text)
                .collect::<Result<Vec<_>>>()?,
            source_inputs_id: text(helper[6])?,
        },
        public_copies,
        analyzer: AnalyzerIdentity {
            copy: PublicCopy {
                version: text(analyzer[0])?,
                sha256: text(analyzer[1])?,
                size: analyzer[2].number()?,
                source: source(analyzer[3])?,
            },
            tool_identity: text(analyzer[4])?,
        },
        frontend_reference: text(frontend[0])?,
        buildkit_version: text(buildkit[0])?,
        buildkit_source_commit: text(buildkit[1])?,
    };
    let public_analyzer = tools
        .public_copies
        .iter()
        .find(|(name, _)| *name == "analyzer")
        .map(|(_, copy)| copy)
        .ok_or(Failure::Protocol)?;
    require(*public_analyzer == tools.analyzer.copy, Failure::Protocol)?;
    let buildctl = tools
        .public_copies
        .iter()
        .find(|(name, _)| *name == "buildctl")
        .map(|(_, copy)| copy)
        .ok_or(Failure::Protocol)?;
    require(
        buildctl.version == tools.buildkit_version,
        Failure::Protocol,
    )?;
    let buildctl_commit = match &buildctl.source {
        ToolSource::Commit(commit) => commit.clone(),
        ToolSource::Inputs { .. } => return Err(Failure::Protocol),
    };
    let analyzer_buildkit = match &tools.analyzer.copy.source {
        ToolSource::Inputs {
            companion: Companion::BuildkitSource(value),
            ..
        } => value.clone(),
        _ => return Err(Failure::Protocol),
    };
    require(
        buildctl_commit == tools.buildkit_source_commit
            && analyzer_buildkit == tools.buildkit_source_commit,
        Failure::Protocol,
    )?;
    Ok(tools)
}


fn decode_text(value: Value<'_>) -> Result<String> {
    Ok(std::str::from_utf8(value.text()?.get())
        .map_err(|_| Failure::Protocol)?
        .into())
}

fn decode_descriptor(value: Value<'_>) -> Result<Descriptor> {
    let f = value.object(&[b"digest", b"size", b"media_type"])?;
    let descriptor = Descriptor {
        digest: decode_text(f[0])?,
        size: f[1].number()?,
        media_type: decode_text(f[2])?,
    };
    descriptor.validate()?;
    Ok(descriptor)
}

fn decode_descriptors(value: Value<'_>) -> Result<Vec<Descriptor>> {
    value.array()?.into_iter().map(decode_descriptor).collect()
}

fn decode_fact(value: Value<'_>) -> Result<Fact> {
    if let Ok(f) = value.object(&[b"status", b"reason"]) {
        if f[0].equals("unavailable")? {
            return Ok(Fact::Unavailable(decode_text(f[1])?));
        }
    }
    Ok(Fact::Available(Out::Raw(value.raw().to_vec())))
}

fn decode_input_fact(value: Value<'_>) -> Result<InputFact> {
    let f = value.object(&[b"declared", b"effective", b"observed"])?;
    Ok(InputFact {
        declared: Out::Raw(f[0].raw().to_vec()),
        effective: Out::Raw(f[1].raw().to_vec()),
        observed: decode_fact(f[2])?,
    })
}

pub(crate) fn decode_record(bytes: &[u8]) -> std::result::Result<Record, ReadFailure> {
    if bytes.len() as u64 > RECORD_BYTES {
        return Err(ReadFailure::Invalid(Failure::Limit));
    }
    let value =
        Value::parse_bounded(bytes, RECORD_BYTES as usize, 64).map_err(ReadFailure::Invalid)?;
    let version = value
        .optional("format_version")
        .map_err(ReadFailure::Invalid)?
        .ok_or(ReadFailure::Invalid(Failure::Protocol))?
        .number()
        .map_err(ReadFailure::Invalid)?;
    if version != 1 {
        return Err(ReadFailure::UnsupportedVersion(version));
    }
    decode_body(value).map_err(ReadFailure::Invalid)
}

fn decode_body(value: Value<'_>) -> Result<Record> {
    let top = journal::optional_fields(
        value,
        &[
            "format_version",
            "artifact_id",
            "created_at",
            "build_operation_id",
            "producer",
            "target",
            "root",
            "platforms",
            "associated_content",
            "inputs",
            "graph",
            "tools",
            "builder",
            "secret_inputs",
            "provenance",
            "build_evidence",
            "annotations",
        ],
    )?;
    let get = |i: usize| top[i].ok_or(Failure::Protocol);
    let producer = get(4)?.object(&[b"name", b"declared", b"normalized"])?;
    let target_fields =
        get(5)?.object(&[b"project_id", b"environment", b"backend", b"logical_target"])?;
    let inputs = get(9)?;
    let graph = get(10)?.object(&[
        b"analyzer_identity",
        b"catalog_id",
        b"graph_id",
        b"nodes",
        b"edges",
        b"source_locations",
        b"external_pins",
        b"frontend_pin",
        b"graph_input_id",
    ])?;
    let builder = get(12)?.object(&[
        b"logical_name",
        b"kind",
        b"endpoint",
        b"server_name",
        b"capabilities",
    ])?;
    let capabilities =
        builder[4].object(&[b"version", b"oci_worker", b"platforms", b"build_platform"])?;
    let evidence =
        get(15)?.object(&[b"method", b"closure_identity", b"completed_at", b"source"])?;
    let evidence_source = evidence[3].object(&[b"node_build", b"output"])?;
    let tools = decode_tools(get(11)?)?;
    let analyzer_identity = tools.analyzer.clone();

    let record = Record {
        artifact_id: decode_text(get(1)?)?,
        created_at: decode_text(get(2)?)?,
        build_operation_id: decode_text(get(3)?)?,
        producer: Producer {
            name: decode_text(producer[0])?,
            declared: decode_text(producer[1])?,
            normalized: decode_text(producer[2])?,
        },
        target: TargetAssociation {
            project_id: decode_text(target_fields[0])?,
            environment: if target_fields[1].is_null() {
                None
            } else {
                Some(decode_text(target_fields[1])?)
            },
            backend: decode_text(target_fields[2])?,
            logical_target: decode_text(target_fields[3])?,
        },
        root: decode_descriptor(get(6)?)?,
        platforms: get(7)?
            .array()?
            .into_iter()
            .map(|item| {
                let f = item.object(&[b"platform", b"manifest", b"config", b"layers"])?;
                Ok(PlatformRecord {
                    platform: decode_text(f[0])?,
                    manifest: decode_descriptor(f[1])?,
                    config: decode_descriptor(f[2])?,
                    layers: decode_descriptors(f[3])?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        associated_content: decode_descriptors(get(8)?)?,
        inputs: decode_inputs(inputs)?,
        graph: Graph {
            analyzer_identity,
            catalog_id: decode_text(graph[1])?,
            graph_id: decode_text(graph[2])?,
            nodes: Out::Raw(graph[3].raw().to_vec()),
            edges: Out::Raw(graph[4].raw().to_vec()),
            source_locations: Out::Raw(graph[5].raw().to_vec()),
            external_pins: Out::Raw(graph[6].raw().to_vec()),
            frontend_pin: decode_text(graph[7])?,
            graph_input_id: decode_text(graph[8])?,
        },
        tools,
        builder: BuilderIdentity {
            name: decode_text(builder[0])?,
            kind: match decode_text(builder[1])?.as_str() {
                "managed" => "managed",
                "external" => "external",
                _ => return Err(Failure::Protocol),
            },
            endpoint: decode_text(builder[2])?,
            server_name: decode_text(builder[3])?,
            version: decode_text(capabilities[0])?,
            oci_worker: capabilities[1].boolean()?,
            platforms: capabilities[2]
                .array()?
                .into_iter()
                .map(decode_text)
                .collect::<Result<Vec<_>>>()?,
            build_platform: decode_text(capabilities[3])?,
        },
        secret_inputs: get(13)?
            .array()?
            .into_iter()
            .map(|item| {
                let f = item.object(&[b"consumer", b"set", b"key", b"version"])?;
                Ok(SecretInput {
                    consumer: decode_text(f[0])?,
                    set: decode_text(f[1])?,
                    key: decode_text(f[2])?,
                    version: decode_fact(f[3])?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        provenance: {
            let status = get(14)?.field("status")?;
            if status.equals("unavailable")? {
                let f = get(14)?.object(&[b"status", b"reason"])?;
                Provenance::Unavailable(decode_text(f[1])?)
            } else {
                let f = get(14)?.object(&[b"status", b"descriptors"])?;
                Provenance::Available(decode_descriptors(f[1])?)
            }
        },
        build_evidence: BuildEvidence {
            method: decode_text(evidence[0])?,
            closure_identity: decode_text(evidence[1])?,
            completed_at: decode_text(evidence[2])?,
            source: EvidenceSource {
                node_build: decode_text(evidence_source[0])?,
                output: decode_text(evidence_source[1])?,
            },
        },
        annotations: match top[16] {
            Some(value) => value
                .members()?
                .into_iter()
                .map(|(key, value)| Ok((decode_text(key)?, decode_text(value)?)))
                .collect::<Result<Vec<_>>>()?,
            None => Vec::new(),
        },
        transformation: Transformation {
            implementation: String::new(),
            protocol: String::new(),
            inputs_id: String::new(),
            map_id: String::new(),
        },
    };
    record.validate()?;
    Ok(record)
}

fn decode_inputs(value: Value<'_>) -> Result<Inputs> {
    let f = value.object(&[
        b"source",
        b"ignore",
        b"stages",
        b"args",
        b"platforms",
        b"builder",
        b"frontend",
        b"outputs",
        b"cache",
        b"entitlements",
        b"transfers",
        b"derived",
    ])?;
    let source = journal::optional_fields(f[0], &["content", "dirty", "untracked", "revision"])?;
    Ok(Inputs {
        source: SourceInput {
            content: decode_input_fact(source[0].ok_or(Failure::Protocol)?)?,
            dirty: source[1].ok_or(Failure::Protocol)?.boolean()?,
            untracked: source[2].ok_or(Failure::Protocol)?.boolean()?,
            revision: source[3].map(decode_text).transpose()?,
        },
        ignore: decode_input_fact(f[1])?,
        stages: decode_input_fact(f[2])?,
        args: f[3]
            .members()?
            .into_iter()
            .map(|(key, value)| Ok((decode_text(key)?, decode_input_fact(value)?)))
            .collect::<Result<Vec<_>>>()?,
        platforms: decode_input_fact(f[4])?,
        builder: decode_input_fact(f[5])?,
        frontend: decode_input_fact(f[6])?,
        outputs: decode_input_fact(f[7])?,
        cache: decode_input_fact(f[8])?,
        entitlements: decode_input_fact(f[9])?,
        transfers: f[10]
            .array()?
            .into_iter()
            .map(|item| {
                let t = item.object(&[
                    b"adapter_source",
                    b"protocol",
                    b"registry",
                    b"reference",
                    b"descriptor",
                ])?;
                Ok(Transfer {
                    adapter_source: decode_text(t[0])?,
                    protocol: decode_text(t[1])?,
                    registry: decode_text(t[2])?,
                    reference: decode_text(t[3])?,
                    descriptor: decode_descriptor(t[4])?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
        derived: Derived::Encoded(
            f[11]
                .array()?
                .into_iter()
                .map(|entry| {
                    decode_derived(entry)?;
                    Ok(entry.raw().to_vec())
                })
                .collect::<Result<Vec<_>>>()?,
        ),
    })
}

fn decode_derived(value: Value<'_>) -> Result<()> {
    let slots = journal::optional_fields(
        value,
        &[
            "role",
            "original",
            "derived",
            "preserved_layers",
            "transformation",
            "locations",
            "history_completion",
        ],
    )?;
    let get = |i: usize| slots[i].ok_or(Failure::Protocol);
    get(0)?.text()?;
    let original = get(1)?.object(&[
        b"reference",
        b"constraint",
        b"platform",
        b"root",
        b"manifest",
        b"config",
    ])?;
    decode_descriptor(original[4])?;
    decode_descriptor(original[5])?;
    let derived = get(2)?.object(&[b"root", b"manifest", b"config"])?;
    let derived_root = decode_descriptor(derived[0])?;
    let derived_manifest = decode_descriptor(derived[1])?;
    decode_descriptor(derived[2])?;
    require(derived_root == derived_manifest, Failure::Integrity)?;
    let preserved = decode_descriptors(get(3)?)?;
    get(4)?.object(&[b"implementation", b"protocol", b"inputs_id", b"map_id"])?;
    get(5)?.array()?;
    if let Some(completion) = slots[6] {
        let c = completion.object(&[
            b"original_form",
            b"original_total",
            b"original_non_empty",
            b"entries",
            b"source",
            b"protocol",
            b"convention",
        ])?;
        let form = decode_text(c[0])?;
        let total = c[1].number()?;
        let non_empty = c[2].number()?;
        let entries = c[3].array()?;
        for entry in &entries {
            let e = entry.object(&[
                b"history_ordinal",
                b"layer_ordinal",
                b"layer_descriptor",
                b"diff_id",
                b"synthetic_identity",
            ])?;
            e[0].number()?;
            e[1].number()?;
            decode_descriptor(e[2])?;
        }
        require(
            non_empty <= total
                && (!matches!(form.as_str(), "absent" | "null" | "empty")
                    || (total == 0 && non_empty == 0))
                && !entries.is_empty()
                && entries.len() as u64 == (preserved.len() as u64).saturating_sub(non_empty),
            Failure::Integrity,
        )?;
    }
    Ok(())
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Committed {
    Complete { artifact_id: String },
    Abandoned {
        artifact_id: String,
        failure_class: FailureClass,
    },
}

pub(crate) struct Store {
    root: PathBuf,
}

impl Store {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Self {
        Store { root: root.into() }
    }

    fn artifacts(&self, active: &Active) -> Result<File> {
        let state = store::state_directory(&self.root, true, active)?;
        store::child_directory(&state, "artifacts", true, active)
    }

    pub(crate) fn list(&self, active: &Active) -> Result<Vec<String>> {
        let artifacts = self.artifacts(active)?;
        let names = store::scan(
            &artifacts,
            |name| name.strip_suffix(".json").is_some_and(valid_artifact),
            active,
        )?;
        let mut ids: Vec<_> = names
            .into_iter()
            .map(|name| {
                name.strip_suffix(".json")
                    .expect("scanned domain")
                    .to_owned()
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    pub(crate) fn read(
        &self,
        artifact_id: &str,
        active: &Active,
    ) -> std::result::Result<Option<Record>, ReadFailure> {
        if !valid_artifact(artifact_id) {
            return Err(ReadFailure::Invalid(Failure::Policy));
        }
        let artifacts = self.artifacts(active).map_err(ReadFailure::Invalid)?;
        let read = store::read(
            &artifacts,
            &format!("{artifact_id}.json"),
            RECORD_BYTES,
            active,
        )
        .map_err(ReadFailure::Invalid)?;
        match read {
            Some((bytes, _)) => Ok(Some(decode_record(&bytes)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn commit(
        &self,
        journal: &Journal,
        record: &Record,
        target: &TargetAssociation,
        observed_at: &str,
        active: &Active,
    ) -> Result<Committed> {
        require(
            record.build_operation_id == journal.operation_id(),
            Failure::Policy,
        )?;
        let artifact_id = record.artifact_id.clone();
        journal.append(
            allocation(
                journal.operation_id(),
                &artifact_id,
                target,
                &record.root,
                observed_at,
            ),
            active,
        )?;

        let committed = self.publish(record, &artifact_id, active);
        let failure = match committed {
            Ok(()) => {
                journal.append(
                    terminal_observation(
                        journal.operation_id(),
                        Kind::RecordCommitted,
                        &artifact_id,
                        observed_at,
                        None,
                    ),
                    active,
                )?;
                return Ok(Committed::Complete { artifact_id });
            }
            Err(failure) => failure,
        };
        let class = FailureClass::of(failure);
        journal.append(
            terminal_observation(
                journal.operation_id(),
                Kind::AllocationAbandoned,
                &artifact_id,
                observed_at,
                Some(class),
            ),
            active,
        )?;
        Ok(Committed::Abandoned {
            artifact_id,
            failure_class: class,
        })
    }

    fn publish(&self, record: &Record, artifact_id: &str, active: &Active) -> Result<()> {
        let bytes = record.encode()?;
        let artifacts = self.artifacts(active)?;
        let prepared =
            store::prepare(&artifacts, journal::temporary(artifact_id)?, &bytes, active)?;
        let name = format!("{artifact_id}.json");
        store::publish_new(&artifacts, prepared, &name, active)?.ok_or(Failure::Integrity)?;
        store::sync_parent(&artifacts, active)
    }
}

fn allocation(
    operation_id: &str,
    artifact_id: &str,
    target: &TargetAssociation,
    root: &Descriptor,
    observed_at: &str,
) -> Observation {
    Observation {
        seq: 0,
        kind: Kind::ArtifactAllocated,
        operation_id: operation_id.to_owned(),
        target: Some(target.clone()),
        phase: None,
        dispatched: None,
        observed_at: observed_at.to_owned(),
        source: None,
        method: None,
        artifact_id: Some(artifact_id.to_owned()),
        outcome: None,
        failure_class: None,
        tool_status: None,
        tool_signal: None,
        cancellation_requested: None,
        cleanup_uncertain: None,
        stage_operation_id: None,
        detail: Some(ObservationDetail::ArtifactAllocated { root: root.clone() }),
    }
}

fn terminal_observation(
    operation_id: &str,
    kind: Kind,
    artifact_id: &str,
    observed_at: &str,
    failure_class: Option<FailureClass>,
) -> Observation {
    Observation {
        seq: 0,
        kind,
        operation_id: operation_id.to_owned(),
        target: None,
        phase: None,
        dispatched: None,
        observed_at: observed_at.to_owned(),
        source: None,
        method: None,
        artifact_id: Some(artifact_id.to_owned()),
        outcome: None,
        failure_class,
        tool_status: None,
        tool_signal: None,
        cancellation_requested: None,
        cleanup_uncertain: None,
        stage_operation_id: None,
        detail: None,
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SettleOutcome {
    Settled { artifact_id: String },
    Completed { artifact_id: String },
    Refused { artifact_id: String },
}

pub(crate) fn settle(
    journal: &Journal,
    ambiguous: &Observation,
    chosen: &Candidate,
    observed_at: &str,
    active: &Active,
) -> std::result::Result<SettleOutcome, ReadFailure> {
    let Some(ObservationDetail::BindingAmbiguous { candidates, .. }) = &ambiguous.detail else {
        return Err(ReadFailure::Invalid(Failure::Policy));
    };
    if ambiguous.kind != Kind::BindingAmbiguous || ambiguous.operation_id != journal.operation_id()
    {
        return Err(ReadFailure::Invalid(Failure::Policy));
    }
    if !candidates.contains(chosen) {
        return Err(ReadFailure::Invalid(Failure::Policy));
    }
    let settlement = Settlement {
        ambiguous_seq: ambiguous.seq,
        artifact_id: chosen.artifact_id.clone(),
        retention_operation_id: chosen.operation_id.clone(),
        retention_seq: chosen.retention_seq,
    };
    let won = journal
        .publish_settlement(&settlement, active)
        .map_err(ReadFailure::Invalid)?
        .is_some();
    let fixed = if won {
        settlement.clone()
    } else {
        let existing = journal
            .settlement(ambiguous.seq, active)?
            .ok_or(ReadFailure::Invalid(Failure::Integrity))?;
        if existing.artifact_id != settlement.artifact_id {
            return Ok(SettleOutcome::Refused {
                artifact_id: existing.artifact_id,
            });
        }
        existing
    };
    let mut completion = terminal_observation(
        journal.operation_id(),
        Kind::BindingResolved,
        &fixed.artifact_id,
        observed_at,
        None,
    );
    completion.detail = Some(ObservationDetail::BindingResolved {
        ambiguous_seq: fixed.ambiguous_seq,
        retention_operation_id: fixed.retention_operation_id.clone(),
        retention_seq: fixed.retention_seq,
    });
    journal
        .append(completion, active)
        .map_err(ReadFailure::Invalid)?;
    Ok(if won {
        SettleOutcome::Settled {
            artifact_id: fixed.artifact_id,
        }
    } else {
        SettleOutcome::Completed {
            artifact_id: fixed.artifact_id,
        }
    })
}


impl Outcome {
    fn of_failure(failure: Failure) -> (Outcome, Option<FailureClass>) {
        if failure == Failure::Cancellation {
            (Outcome::Cancelled, None)
        } else {
            (Outcome::Failed, Some(FailureClass::of(failure)))
        }
    }

    pub(crate) fn of_read(outcome: ReadOutcome) -> (Outcome, Option<FailureClass>) {
        match outcome {
            ReadOutcome::Fetched => (Outcome::Succeeded, None),
            ReadOutcome::OptionalMiss => (Outcome::Failed, Some(FailureClass::CacheMiss)),
            ReadOutcome::Skipped => (Outcome::Pending, None),
            ReadOutcome::Failed(failure) => Outcome::of_failure(failure),
            ReadOutcome::Cancelled => (Outcome::Cancelled, None),
        }
    }

    pub(crate) fn of_write(outcome: WriteOutcome) -> (Outcome, Option<FailureClass>) {
        match outcome {
            WriteOutcome::Written | WriteOutcome::Promoted => (Outcome::Succeeded, None),
            WriteOutcome::Failed(failure) => Outcome::of_failure(failure),
            WriteOutcome::Unknown(_) => (Outcome::Unknown, None),
            WriteOutcome::Cancelled => (Outcome::Cancelled, None),
        }
    }

    pub(crate) fn of_target(outcome: &TargetOutcome) -> (Outcome, Option<FailureClass>) {
        match outcome {
            TargetOutcome::Retained(_)
            | TargetOutcome::Loaded(_)
            | TargetOutcome::CacheOnly
            | TargetOutcome::Unpublished(_) => (Outcome::Succeeded, None),
            TargetOutcome::Failed { class, .. } => Outcome::of_failure(*class),
            TargetOutcome::NotExported(NotExported::Cancelled) => (Outcome::Cancelled, None),
            TargetOutcome::NotExported(_) => (Outcome::Pending, None),
        }
    }

    pub(crate) fn of_publication(outcome: &PublicationOutcome) -> (Outcome, Option<FailureClass>) {
        match outcome {
            PublicationOutcome::Published(_) => (Outcome::Succeeded, None),
            PublicationOutcome::Failed { class, .. } => match class {
                PublicationClass::Failed(failure) => Outcome::of_failure(*failure),
                PublicationClass::Publication => (Outcome::Failed, Some(FailureClass::Publication)),
            },
            PublicationOutcome::Unknown(_) => (Outcome::Unknown, None),
            PublicationOutcome::Cancelled
            | PublicationOutcome::NotPublished(NotPublished::Cancelled) => {
                (Outcome::Cancelled, None)
            }
            PublicationOutcome::NotPublished(_) => (Outcome::Pending, None),
        }
    }

    pub(crate) fn of_node(outcome: &NodeOutcome) -> (Outcome, Option<FailureClass>) {
        match outcome {
            NodeOutcome::Built(_) => (Outcome::Succeeded, None),
            NodeOutcome::Failed { class, .. } => Outcome::of_failure(*class),
            NodeOutcome::NotDispatched(NotDispatched::Cancelled) => (Outcome::Cancelled, None),
            NodeOutcome::NotDispatched(_) => (Outcome::Pending, None),
        }
    }

    pub(crate) fn of_resolved(
        result: &std::result::Result<Resolved, StageError>,
    ) -> (Outcome, Option<FailureClass>) {
        match result {
            Ok(_) => (Outcome::Succeeded, None),
            Err(error) => Outcome::of_failure(error.failure),
        }
    }
}


pub(crate) const NODE_BUILD_PHASE: &str = "node-build";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Acquisition {
    pub(crate) phase: Option<&'static str>,
    pub(crate) role: &'static str,
    pub(crate) dispatched: Option<bool>,
    pub(crate) outcome: Outcome,
    pub(crate) failure_class: Option<FailureClass>,
    pub(crate) source: &'static str,
    pub(crate) method: &'static str,
    pub(crate) target: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TimeRefusal {
    pub(crate) member: &'static str,
    pub(crate) stage: &'static str,
    pub(crate) absent: bool,
}

struct RecordWork<F, T> {
    root: PathBuf,
    job: Option<F>,
    result: Option<T>,
}

impl<F, T> supervise::PublicAction for RecordWork<F, T>
where
    F: FnOnce(&Path, &Active) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    fn apply(&mut self, active: &Active) -> Result<()> {
        let job = self.job.take().ok_or(Failure::Policy)?;
        self.result = Some(job(&self.root, active)?);
        Ok(())
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

pub(crate) fn step<T, F>(
    root: &Path,
    metadata_ms: u64,
    cleanup_ms: u64,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    job: F,
) -> Result<T>
where
    F: FnOnce(&Path, &Active) -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    let mut clock = Clock::new(metadata_ms)?;
    clock.cleanup_limit_ms = clock.cleanup_limit_ms.min(cleanup_ms);
    let permit = loop {
        require(
            !cancelled.load(std::sync::atomic::Ordering::Acquire),
            Failure::Cancellation,
        )?;
        match Permit::acquire() {
            Ok(permit) => break permit,
            Err(Failure::Capacity) => {
                before(clock.end)?;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(failure) => return Err(failure),
        }
    };
    let work = RecordWork {
        root: root.to_path_buf(),
        job: Some(job),
        result: None,
    };
    let (work, result) = supervise::public_local(work, &mut clock, &cancelled, &permit);
    let work = work.ok_or(Failure::Indeterminate)?;
    result?;
    work.result.ok_or(Failure::Indeterminate)
}

pub(crate) struct Recorder {
    root: PathBuf,
    operation_id: String,
    project_id: String,
    environment: Option<String>,
    cancellation: Cancellation,
    metadata_ms: u64,
    cleanup_ms: u64,
    carrier: BTreeMap<String, Acquisition>,
    chains: BTreeMap<String, Vec<PlatformRecord>>,
    fault: Option<Failure>,
    refusals: Vec<TimeRefusal>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Binding {
    Bound(Candidate),
    Unbound(BindingReason),
    Ambiguous(Vec<Candidate>),
}

impl Recorder {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        root: &Path,
        kind: &str,
        origin: &str,
        request: &serde_json::Value,
        environment: Option<String>,
        tools: Tools,
        cancellation: Cancellation,
        limits: &Limits,
    ) -> Result<Recorder> {
        let project_id = solve::project_id(root)?;
        let operation_id = format!("operation-{}", sudo_nonce().map_err(|_| Failure::Capacity)?);
        let record = OperationRecord {
            operation_id: operation_id.clone(),
            kind: kind.to_owned(),
            origin: origin.to_owned(),
            started_at: now_utc(),
            request: Out::Raw(serde_json::to_vec(request).map_err(|_| Failure::Protocol)?),
            tools,
            preceding_operation_id: None,
            retry_reason: None,
        };
        let recorder = Recorder {
            root: root.to_owned(),
            operation_id,
            project_id,
            environment,
            cancellation,
            metadata_ms: limits.metadata_ms,
            cleanup_ms: limits.cleanup_ms,
            carrier: BTreeMap::new(),
            chains: BTreeMap::new(),
            fault: None,
            refusals: Vec::new(),
        };
        recorder.step(move |root, active| {
            let journal = Journal::open(root, &record.operation_id, true, active)?;
            journal.open_operation(&record, active)
        })?;
        Ok(recorder)
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[allow(dead_code)]
    pub(crate) fn fault(&self) -> Option<Failure> {
        self.fault
    }

    #[allow(dead_code)]
    pub(crate) fn refusals(&self) -> &[TimeRefusal] {
        &self.refusals
    }

    pub(crate) fn target(&self, logical_target: &str) -> TargetAssociation {
        TargetAssociation {
            project_id: self.project_id.clone(),
            environment: self.environment.clone(),
            backend: "image".to_owned(),
            logical_target: logical_target.to_owned(),
        }
    }

    pub(crate) fn step<T, F>(&self, job: F) -> Result<T>
    where
        F: FnOnce(&Path, &Active) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        step(
            &self.root,
            self.metadata_ms,
            self.cleanup_ms,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            job,
        )
    }

    fn append(&mut self, observation: Observation) -> Result<Observation> {
        let operation_id = self.operation_id.clone();
        let result = self.step(move |root, active| {
            Journal::open(root, &operation_id, false, active)?.append(observation, active)
        });
        if let Err(failure) = &result {
            self.fault.get_or_insert(*failure);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn observation(
        &self,
        kind: Kind,
        target: Option<TargetAssociation>,
        phase: Option<&str>,
        dispatched: Option<bool>,
        observed_at: String,
        source: Option<&str>,
        method: Option<&str>,
        outcome: Option<(Outcome, Option<FailureClass>)>,
        stage_operation_id: Option<Vec<StageAcquisition>>,
        detail: Option<ObservationDetail>,
    ) -> Observation {
        let (outcome, failure_class) = match outcome {
            Some((outcome, class)) => (Some(outcome), class),
            None => (None, None),
        };
        let staged = kind != Kind::PreDispatch && phase.is_some() && !kind.journal_event();
        Observation {
            seq: 0,
            kind,
            operation_id: self.operation_id.clone(),
            target,
            phase: phase.map(str::to_owned),
            dispatched: if kind == Kind::PreDispatch {
                Some(false)
            } else if staged {
                dispatched
            } else {
                None
            },
            observed_at,
            source: source.map(str::to_owned),
            method: method.map(str::to_owned),
            artifact_id: None,
            outcome,
            failure_class,
            tool_status: None,
            tool_signal: None,
            cancellation_requested: staged.then(|| self.cancellation.requested()),
            cleanup_uncertain: None,
            stage_operation_id,
            detail,
        }
    }

    pub(crate) fn marker(
        &mut self,
        boundary: Boundary,
        target: Option<&str>,
        acquisition: Option<(&'static str, &str)>,
    ) -> Result<()> {
        let observation = self.observation(
            Kind::PreDispatch,
            target.map(|t| self.target(t)),
            Some(boundary.name()),
            Some(false),
            now_utc(),
            None,
            None,
            None,
            acquisition.map(|(role, id)| vec![acquisition_of(role, id)]),
            None,
        );
        self.append(observation).map(|_| ())
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn completion(
        &mut self,
        boundary: Boundary,
        target: Option<&str>,
        outcome: (Outcome, Option<FailureClass>),
        source: &'static str,
        method: &'static str,
        session: Option<&SessionObservation>,
        acquisitions: Vec<StageAcquisition>,
        cache_read: Option<CacheRead>,
    ) -> Result<()> {
        let mut observation = self.observation(
            Kind::Phase,
            target.map(|t| self.target(t)),
            Some(boundary.name()),
            Some(true),
            now_utc(),
            Some(source),
            Some(method),
            Some(outcome),
            (!acquisitions.is_empty()).then_some(acquisitions),
            cache_read.map(|cache_read| ObservationDetail::Phase { cache_read }),
        );
        observation.cleanup_uncertain = Some(cleanup_uncertain(session));
        self.append(observation).map(|_| ())
    }

    pub(crate) fn record_acquisition(&mut self, acquisition_id: &str, acquisition: Acquisition) {
        self.carrier.insert(acquisition_id.to_owned(), acquisition);
    }

    pub(crate) fn recorded(&self, acquisition_id: &str) -> Option<&Acquisition> {
        self.carrier.get(acquisition_id)
    }

    pub(crate) fn staging_lifecycle(
        &mut self,
        acquisition_id: &str,
        acquisition: &Acquisition,
        release_completed: bool,
    ) -> Result<()> {
        let target = acquisition.target.as_deref().map(|t| self.target(t));
        let mut observation = self.observation(
            Kind::StagingLifecycle,
            target,
            acquisition.phase,
            acquisition.dispatched,
            now_utc(),
            Some(acquisition.source),
            Some(acquisition.method),
            Some((acquisition.outcome, acquisition.failure_class)),
            Some(vec![acquisition_of(acquisition.role, acquisition_id)]),
            Some(ObservationDetail::StagingLifecycle { release_completed }),
        );
        if acquisition.phase.is_some() {
            observation.cleanup_uncertain = Some(!release_completed);
        }
        self.append(observation).map(|_| ())
    }

    pub(crate) fn retention(&mut self, target: &str, retained: &Retained) -> Result<()> {
        let observed_at = self.carried_time(&retained.verified_at, "observed_at", "retention")?;
        let location = retained
            .location
            .to_str()
            .ok_or(Failure::Policy)?
            .to_owned();
        let closure = RetentionClosure {
            root: retained.root.clone(),
            manifests: retained
                .manifests
                .iter()
                .map(|(_, descriptor)| descriptor.clone())
                .collect(),
            verified_descriptors: retained.verified_files,
            verified_bytes: retained.verified_bytes,
            archive: retained
                .archive
                .as_ref()
                .map(|(sha256, size)| (*size, sha256.clone())),
        };
        let mut observation = self.observation(
            Kind::Retention,
            Some(self.target(target)),
            Some(Boundary::Export.name()),
            Some(true),
            observed_at,
            Some("output-stage"),
            Some(retained.verification),
            Some((Outcome::Succeeded, None)),
            None,
            Some(ObservationDetail::Retention {
                owner: retained.owner.to_owned(),
                location,
                output_kind: retained.kind.to_owned(),
                closure,
                broil_cleans: false,
                release_covers: false,
            }),
        );
        observation.cleanup_uncertain = Some(false);
        self.append(observation).map(|_| ())
    }

    pub(crate) fn publication(
        &mut self,
        target: &str,
        observation: &PublicationObservation,
        report: &PublicationReport,
        artifact_id: Option<String>,
        binding_reason: Option<BindingReason>,
    ) -> Result<Observation> {
        let observed_at =
            self.carried_time(&observation.observed_at, "observed_at", "publication")?;
        let entries: Vec<PublicationEntry> = observation
            .closure
            .iter()
            .map(|member| {
                Ok(PublicationEntry {
                    descriptor: member.descriptor.clone(),
                    local_integrity: match member.local {
                        "verify-staged" => LocalIntegrity::VerifyStaged,
                        "inspect-prepared" => LocalIntegrity::InspectPrepared,
                        _ => return Err(Failure::Protocol),
                    },
                })
            })
            .collect::<Result<_>>()?;
        let mut seen = std::collections::BTreeSet::new();
        let verified_bytes = entries
            .iter()
            .filter(|entry| seen.insert(entry.descriptor.digest.clone()))
            .map(|entry| entry.descriptor.size)
            .sum();
        let closure = PublicationClosure {
            verified_descriptors: entries.len() as u64,
            verified_bytes,
            closure_complete: true,
            entries,
        };
        let mut record = self.observation(
            Kind::Publication,
            Some(self.target(target)),
            Some(Boundary::Publication.name()),
            Some(true),
            observed_at,
            Some("registry-adapter-receipt"),
            Some(observation.method),
            Some((Outcome::Succeeded, None)),
            Some(publication_acquisitions(report)),
            Some(ObservationDetail::Publication {
                root: observation.root.digest.clone(),
                endpoint: observation.endpoint.clone(),
                server_name: observation.server.authority.clone(),
                repository: observation.repository.clone(),
                closure,
                tags: observation
                    .tag
                    .iter()
                    .map(|tag| Tag {
                        tag: tag.tag.clone(),
                        digest: tag.root.digest.clone(),
                    })
                    .collect(),
                binding_reason,
            }),
        );
        record.artifact_id = artifact_id;
        record.cleanup_uncertain = Some(cleanup_uncertain(report.sessions.last()));
        self.append(record)
    }

    pub(crate) fn ambiguity(
        &mut self,
        publication_seq: u64,
        candidates: Vec<Candidate>,
    ) -> Result<()> {
        let observation = self.observation(
            Kind::BindingAmbiguous,
            None,
            None,
            None,
            now_utc(),
            None,
            None,
            None,
            None,
            Some(ObservationDetail::BindingAmbiguous {
                publication_seq,
                candidates: candidates.clone(),
                reason: BindingReason {
                    disposition: Disposition::Ambiguous,
                    windows: None,
                    candidates: None,
                },
            }),
        );
        self.append(observation).map(|_| ())
    }

    pub(crate) fn commit(&mut self, record: Record) -> Result<Committed> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        let operation_id = self.operation_id.clone();
        let target = record.target.clone();
        let result = self.step(move |root, active| {
            let journal = Journal::open(root, &operation_id, false, active)?;
            Store::new(root).commit(&journal, &record, &target, &now_utc(), active)
        });
        if let Err(failure) = &result {
            self.fault.get_or_insert(*failure);
        }
        result
    }

    pub(crate) fn rebuild_index(&self) -> Result<()> {
        self.step(|root, active| rebuild(root, active).map(|_| ()).map_err(Failure::from))
    }

    pub(crate) fn bind(
        &self,
        location: &Path,
        output_kind: &str,
        root: &Descriptor,
    ) -> Result<Binding> {
        let location = location.to_str().ok_or(Failure::Policy)?.to_owned();
        let output_kind = output_kind.to_owned();
        let root = root.clone();
        self.step(move |store_root, active| {
            bind(store_root, &location, &output_kind, &root, active).map_err(Failure::from)
        })
    }

    pub(crate) fn stash_chains(
        &mut self,
        target: &str,
        outputs: &[(String, VerifiedOutput)],
    ) -> Result<()> {
        let outputs: Vec<(String, Entry, Descriptor)> = outputs
            .iter()
            .map(|(platform, output)| {
                (
                    platform.clone(),
                    output.entry().clone(),
                    output.root().clone(),
                )
            })
            .collect();
        let records = self.step(move |_, active| {
            outputs
                .into_iter()
                .map(|(platform, entry, root)| {
                    let chain = super::graph::read_chain(&entry, &root, &platform, active.end())?;
                    require(chain.indexes.is_empty(), Failure::Integrity)?;
                    let value =
                        Value::parse_bounded(chain.manifest.get(), RECORD_BYTES as usize, 128)?;
                    let config = super::content::descriptor(value.field("config")?, false)?;
                    let mut layers = Vec::new();
                    for layer in value.field("layers")?.array()? {
                        layers.push(super::content::descriptor(layer, false)?);
                    }
                    Ok(PlatformRecord {
                        platform,
                        manifest: root,
                        config,
                        layers,
                    })
                })
                .collect::<Result<Vec<_>>>()
        })?;
        self.chains.insert(target.to_owned(), records);
        Ok(())
    }

    pub(crate) fn chains(&self, target: &str) -> Option<Vec<PlatformRecord>> {
        self.chains.get(target).cloned()
    }

    fn carried_time(
        &mut self,
        value: &str,
        member: &'static str,
        stage: &'static str,
    ) -> Result<String> {
        if value.is_empty() || !valid_time(value) {
            self.refusals.push(TimeRefusal {
                member,
                stage,
                absent: value.is_empty(),
            });
            self.fault.get_or_insert(Failure::Protocol);
            return Err(Failure::Protocol);
        }
        Ok(value.to_owned())
    }
}

fn acquisition_of(role: &str, acquisition_id: &str) -> StageAcquisition {
    StageAcquisition {
        role: role.to_owned(),
        acquisition_id: acquisition_id.to_owned(),
    }
}

pub(crate) fn cleanup_uncertain(session: Option<&SessionObservation>) -> bool {
    session.is_some_and(|session| {
        session.residue
            || session.unresolved_owner
            || match &session.cleanup {
                Ok(observation) => observation.cleanup_uncertain,
                Err(_) => true,
            }
    })
}

pub(crate) fn publication_acquisitions(report: &PublicationReport) -> Vec<StageAcquisition> {
    report
        .staging
        .iter()
        .map(|delta| acquisition_of(delta.operation, &delta.operation_id))
        .collect()
}

pub(crate) fn bind(
    root: &Path,
    location: &str,
    output_kind: &str,
    expected_root: &Descriptor,
    active: &Active,
) -> std::result::Result<Binding, ReadFailure> {
    let state = store::state_directory(root, true, active).map_err(ReadFailure::Invalid)?;
    let operations =
        store::child_directory(&state, "operations", true, active).map_err(ReadFailure::Invalid)?;
    let names = store::scan(&operations, valid_operation, active).map_err(ReadFailure::Invalid)?;
    let mut windows = Vec::new();
    let mut candidates = Vec::new();
    for name in names {
        let journal = Journal::open(root, &name, false, active).map_err(ReadFailure::Invalid)?;
        let observations = journal.observations(active)?;
        for retention in &observations {
            let Some(ObservationDetail::Retention {
                location: retained_location,
                output_kind: retained_kind,
                closure,
                ..
            }) = &retention.detail
            else {
                continue;
            };
            if retained_location != location
                || retained_kind != output_kind
                || closure.root != *expected_root
            {
                continue;
            }
            let target = retention.target.as_ref();
            for allocation in observations
                .iter()
                .filter(|o| o.kind == Kind::ArtifactAllocated && o.target.as_ref() == target)
            {
                let Some(artifact_id) = &allocation.artifact_id else {
                    continue;
                };
                let terminal = observations.iter().find(|o| {
                    matches!(o.kind, Kind::RecordCommitted | Kind::AllocationAbandoned)
                        && o.artifact_id.as_deref() == Some(artifact_id)
                });
                match terminal.map(|o| o.kind) {
                    Some(Kind::RecordCommitted) => candidates.push(Candidate {
                        artifact_id: artifact_id.clone(),
                        operation_id: name.clone(),
                        retention_seq: retention.seq,
                    }),
                    Some(_) => {}
                    None => windows.push(Window {
                        operation_id: name.clone(),
                        artifact_id: artifact_id.clone(),
                    }),
                }
            }
        }
    }
    Ok(if !windows.is_empty() {
        Binding::Unbound(BindingReason {
            disposition: Disposition::UnprovedWindow,
            windows: Some(windows),
            candidates: Some(candidates),
        })
    } else if candidates.len() > 1 {
        Binding::Ambiguous(candidates)
    } else if let Some(candidate) = candidates.pop() {
        Binding::Bound(candidate)
    } else {
        Binding::Unbound(BindingReason {
            disposition: Disposition::NoRecord,
            windows: None,
            candidates: None,
        })
    })
}

pub(crate) fn pinned_buildkit_version() -> Result<String> {
    text_member(&manifest()?["tools"]["buildctl"], "version")
}


pub(crate) struct Evidence<'a> {
    pub(crate) target: &'a str,
    pub(crate) image: &'a EffectiveImage,
    pub(crate) resolution: &'a Resolution,
    pub(crate) nodes: Vec<(
        &'a str,
        &'a BuiltNode,
        Option<&'a SessionObservation>,
        Option<&'a NodeCache>,
    )>,
    pub(crate) root: Descriptor,
    pub(crate) platforms: Vec<PlatformRecord>,
    pub(crate) report: &'a TargetReport,
    pub(crate) output_acquisition: String,
}

fn text_or_null(value: Option<&str>) -> Out {
    match value {
        Some(value) => Out::text(value),
        None => Out::Null,
    }
}

fn path_text(path: &Path) -> Result<String> {
    Ok(path.to_str().ok_or(Failure::Policy)?.to_owned())
}

fn available(members: Vec<(&'static str, Out)>) -> Fact {
    Fact::Available(object(members))
}

fn ignore_out(entry: &IgnoreEntry) -> Out {
    match entry {
        IgnoreEntry::Absent => object(vec![("status", Out::text("absent"))]),
        IgnoreEntry::File { mode, size, digest } => object(vec![
            ("status", Out::text("file")),
            ("mode", Out::Number(u64::from(*mode))),
            ("size", Out::Number(*size)),
            ("digest", Out::text(digest)),
        ]),
    }
}

impl Evidence<'_> {
    pub(crate) fn record(&self, recorder: &Recorder) -> Result<Record> {
        let (_, first, _, _) = self.nodes.first().copied().ok_or(Failure::Policy)?;
        let declaration = &self.image.declaration;

        let platforms = self.platforms.clone();
        require(
            platforms.len() == self.nodes.len()
                && self.nodes.iter().all(|(platform, node, _, _)| {
                    platforms
                        .iter()
                        .any(|p| p.platform == *platform && p.manifest == *node.output.root())
                }),
            Failure::Policy,
        )?;

        let tools = capture_tools(&first.builder.version).map_err(|refusal| refusal.failure)?;

        let identity = declaration.image.identity();
        let mut normalized = identity.repository.clone();
        if let Some(tag) = &identity.tag {
            normalized.push(':');
            normalized.push_str(tag);
        }
        if let Some(digest) = &identity.digest {
            normalized.push('@');
            normalized.push_str(digest);
        }

        let context_ids: Vec<&str> = self
            .nodes
            .iter()
            .map(|(_, node, _, _)| node.context_id.as_str())
            .collect();
        let per_platform = |value: &dyn Fn(&BuiltNode) -> Out| -> Out {
            keyed(
                self.nodes
                    .iter()
                    .map(|(platform, node, _, _)| ((*platform).to_owned(), value(node)))
                    .collect(),
            )
        };
        let node_sessions: Vec<String> = self
            .nodes
            .iter()
            .filter_map(|(_, _, session, _)| session.map(|s| s.operation_id.clone()))
            .collect();
        require(node_sessions.len() == self.nodes.len(), Failure::Policy)?;
        let output_session = self.output_acquisition.clone();

        let source = SourceInput {
            content: InputFact {
                declared: object(vec![
                    ("context", text_or_null(declaration.context.as_deref())),
                    (
                        "dockerfile",
                        text_or_null(declaration.dockerfile.as_deref()),
                    ),
                    (
                        "contexts",
                        keyed(
                            declaration
                                .contexts
                                .iter()
                                .map(|(name, path)| (name.clone(), Out::text(path)))
                                .collect(),
                        ),
                    ),
                ]),
                effective: object(vec![
                    ("context", Out::text(path_text(&self.image.context)?)),
                    ("dockerfile", Out::text(path_text(&self.image.dockerfile)?)),
                    (
                        "contexts",
                        keyed(
                            self.image
                                .contexts
                                .iter()
                                .map(|(name, path)| Ok((name.clone(), Out::text(path_text(path)?))))
                                .collect::<Result<_>>()?,
                        ),
                    ),
                ]),
                observed: available(vec![
                    ("method", Out::text("context-snapshot")),
                    (
                        "context_id",
                        per_platform(&|node| Out::text(&node.context_id)),
                    ),
                    (
                        "dockerfile_digest",
                        per_platform(&|node| Out::text(&node.dockerfile_digest)),
                    ),
                ]),
            },
            dirty: true,
            untracked: true,
            revision: None,
        };
        let ignore = InputFact {
            declared: object(vec![
                (
                    "record",
                    Out::text(format!(
                        "{}.dockerignore",
                        self.image
                            .dockerfile
                            .file_name()
                            .and_then(|name| name.to_str())
                            .ok_or(Failure::Policy)?
                    )),
                ),
                ("default", Out::text(".dockerignore")),
                (
                    "named",
                    Out::Array(self.image.contexts.keys().map(Out::text).collect()),
                ),
            ]),
            effective: per_platform(&|node| {
                object(vec![
                    ("record", ignore_out(&node.ignore.record)),
                    ("default", ignore_out(&node.ignore.default_ignore)),
                    (
                        "named",
                        keyed(
                            node.ignore
                                .named_ignore
                                .iter()
                                .map(|(name, entry)| (name.clone(), ignore_out(entry)))
                                .collect(),
                        ),
                    ),
                ])
            }),
            observed: available(vec![
                ("method", Out::text("context-snapshot")),
                (
                    "context_id",
                    per_platform(&|node| Out::text(&node.context_id)),
                ),
            ]),
        };
        let stages = InputFact {
            declared: text_or_null(declaration.stage.as_deref()),
            effective: Out::text(declaration.stage.as_deref().unwrap_or("final")),
            observed: available(vec![
                ("method", Out::text("dockerfile-digest")),
                (
                    "dockerfile_digest",
                    per_platform(&|node| Out::text(&node.dockerfile_digest)),
                ),
            ]),
        };
        let args = declaration
            .args
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    InputFact {
                        declared: Out::text(value),
                        effective: Out::text(value),
                        observed: available(vec![
                            ("method", Out::text("generated-bake-input")),
                            (
                                "bake_digest",
                                per_platform(&|node| Out::text(&node.bake_digest)),
                            ),
                        ]),
                    },
                )
            })
            .collect();
        let platform_list =
            |platforms: &[String]| Out::Array(platforms.iter().map(Out::text).collect());
        let platforms_fact = InputFact {
            declared: match &declaration.platforms {
                Some(platforms) => platform_list(platforms),
                None => Out::Null,
            },
            effective: platform_list(&self.image.platforms),
            observed: available(vec![
                ("method", Out::text("built-nodes")),
                (
                    "platforms",
                    Out::Array(
                        self.nodes
                            .iter()
                            .map(|(p, _, _, _)| Out::text(*p))
                            .collect(),
                    ),
                ),
                ("build_platform", Out::text(&first.build_platform)),
            ]),
        };
        let builder = InputFact {
            declared: Out::text(&declaration.builder),
            effective: object(vec![
                ("logical_name", Out::text(&first.builder.name)),
                ("endpoint", Out::text(&first.builder.endpoint)),
                ("server_name", Out::text(&first.builder.server_name)),
            ]),
            observed: available(vec![
                ("method", Out::text("builder-session")),
                ("version", Out::text(&first.builder.version)),
                ("build_platform", Out::text(&first.builder.build_platform)),
                ("platforms", platform_list(&first.builder.platforms)),
            ]),
        };
        let frontend = InputFact {
            declared: text_or_null(first.frontend.as_ref().map(|gap| gap.reference.as_str())),
            effective: Out::text(analysis::FRONTEND),
            observed: match &first.frontend {
                Some(gap) => Fact::Unavailable(gap.reason.to_owned()),
                None => available(vec![
                    ("method", Out::text("pinned-frontend")),
                    ("reference", Out::text(analysis::FRONTEND)),
                ]),
            },
        };
        let outputs_fact = InputFact {
            declared: object(vec![
                (
                    "kind",
                    text_or_null(declaration.output.kind.map(outputs::kind_name)),
                ),
                ("path", text_or_null(declaration.output.path.as_deref())),
            ]),
            effective: object(vec![
                (
                    "kind",
                    Out::text(outputs::kind_name(self.image.output_kind)),
                ),
                (
                    "path",
                    match &self.image.output_path {
                        Some(path) => Out::text(path_text(path)?),
                        None => Out::Null,
                    },
                ),
            ]),
            observed: available(vec![
                ("method", Out::text("output-stage")),
                (
                    "outcome",
                    Out::text(target_outcome_name(&self.report.outcome)),
                ),
                ("root", Out::text(&self.root.digest)),
            ]),
        };
        let location_out_ = |location: &broil_core::images::CacheLocation| {
            object(vec![
                ("registry", Out::text(&location.registry)),
                ("reference", Out::text(&location.reference.supplied)),
            ])
        };
        let cache = InputFact {
            declared: object(vec![
                (
                    "builder",
                    match declaration.cache.builder {
                        Some(value) => Out::Bool(value),
                        None => Out::Null,
                    },
                ),
                (
                    "read",
                    Out::Array(declaration.cache.read.iter().map(location_out_).collect()),
                ),
                (
                    "write",
                    match &declaration.cache.write {
                        Some(location) => location_out_(location),
                        None => Out::Null,
                    },
                ),
                (
                    "refresh",
                    match declaration.cache.refresh {
                        Some(value) => Out::Bool(value),
                        None => Out::Null,
                    },
                ),
            ]),
            effective: object(vec![
                ("builder_cache", Out::Bool(self.image.builder_cache)),
                ("refresh", Out::Bool(self.image.refresh)),
                (
                    "nodes",
                    keyed(
                        self.nodes
                            .iter()
                            .map(|(platform, _, _, cache)| {
                                (
                                    (*platform).to_owned(),
                                    match cache {
                                        Some(cache) => object(vec![
                                            ("no_cache", Out::Bool(cache.no_cache)),
                                            (
                                                "secret_freshness",
                                                Out::text(cache.secret_freshness.name()),
                                            ),
                                            ("reads", Out::Number(cache.reads.len() as u64)),
                                            ("write", Out::Bool(cache.write.is_some())),
                                        ]),
                                        None => Out::Null,
                                    },
                                )
                            })
                            .collect(),
                    ),
                ),
            ]),
            observed: available(vec![
                ("method", Out::text("cache-report")),
                (
                    "nodes",
                    keyed(
                        self.nodes
                            .iter()
                            .map(|(platform, _, _, cache)| {
                                (
                                    (*platform).to_owned(),
                                    match cache {
                                        Some(cache) => object(vec![
                                            (
                                                "reads",
                                                Out::Array(
                                                    cache
                                                        .reads
                                                        .iter()
                                                        .map(|read| {
                                                            object(vec![
                                                                (
                                                                    "registry",
                                                                    Out::text(&read.registry),
                                                                ),
                                                                (
                                                                    "reference",
                                                                    Out::text(&read.reference),
                                                                ),
                                                                (
                                                                    "outcome",
                                                                    Out::text(read.outcome.name()),
                                                                ),
                                                                (
                                                                    "imported",
                                                                    Out::Bool(read.imported),
                                                                ),
                                                            ])
                                                        })
                                                        .collect(),
                                                ),
                                            ),
                                            (
                                                "write",
                                                match &cache.write {
                                                    Some(write) => object(vec![
                                                        ("registry", Out::text(&write.registry)),
                                                        (
                                                            "outcome",
                                                            Out::text(write.outcome.name()),
                                                        ),
                                                        (
                                                            "promotion",
                                                            text_or_null(
                                                                write
                                                                    .promotion
                                                                    .map(WriteOutcome::name),
                                                            ),
                                                        ),
                                                    ]),
                                                    None => Out::Null,
                                                },
                                            ),
                                        ]),
                                        None => Out::Null,
                                    },
                                )
                            })
                            .collect(),
                    ),
                ),
            ]),
        };
        let entitlements = InputFact {
            declared: Out::Array(declaration.entitlements.iter().map(Out::text).collect()),
            effective: Out::Array(declaration.entitlements.iter().map(Out::text).collect()),
            observed: Fact::Unavailable(
                "entitlement consumption is not reported by the build client".to_owned(),
            ),
        };

        let mut transfers = Vec::new();
        for (_, node, _, cache) in &self.nodes {
            if let Some(cache) = cache {
                for read in &cache.reads {
                    if let (ReadOutcome::Fetched, Some(root)) = (read.outcome, &read.root) {
                        transfers.push(Transfer {
                            adapter_source: "image-registry".to_owned(),
                            protocol: "oci-distribution".to_owned(),
                            registry: read.registry.clone(),
                            reference: read.reference.clone(),
                            descriptor: root.clone(),
                        });
                    }
                }
            }
            for derived in &node.derived_inputs {
                let registry = self
                    .resolution
                    .external_sources
                    .iter()
                    .find(|source| {
                        source.reference == derived.original_reference
                            && source.platform == derived.original_platform
                    })
                    .and_then(|source| source.registry.clone())
                    .unwrap_or_default();
                transfers.push(Transfer {
                    adapter_source: "image-registry".to_owned(),
                    protocol: "oci-distribution".to_owned(),
                    registry,
                    reference: derived.original_reference.clone(),
                    descriptor: derived.original_manifest.clone(),
                });
            }
        }
        let mut derived: Vec<DerivedInputProvenance> = Vec::new();
        for (_, node, _, _) in &self.nodes {
            for entry in &node.derived_inputs {
                if !derived.iter().any(|d| {
                    d.ordinal == entry.ordinal
                        && d.original_reference == entry.original_reference
                        && d.original_platform == entry.original_platform
                }) {
                    derived.push(entry.clone());
                }
            }
        }

        let nodes = Out::Array(
            self.resolution
                .nodes
                .iter()
                .map(|node| {
                    object(vec![
                        ("producer", Out::text(&node.producer)),
                        ("platform", Out::text(&node.platform)),
                        ("path", Out::text(&node.path)),
                        ("snapshot_size", Out::Number(node.snapshot_size)),
                        ("snapshot_digest", Out::text(&node.snapshot_digest)),
                        ("resolution_id", text_or_null(node.resolution_id.as_deref())),
                        ("state", Out::text(node.state.name())),
                    ])
                })
                .collect(),
        );
        let edges = Out::Array(
            self.resolution
                .edges
                .iter()
                .map(|edge| {
                    let (kind, ordinal) = match edge.target {
                        super::graph::Target::Node(ordinal) => ("node", ordinal),
                        super::graph::Target::Source(ordinal) => ("source", ordinal),
                    };
                    object(vec![
                        ("source", Out::Number(edge.source)),
                        (
                            "target",
                            object(vec![
                                ("kind", Out::text(kind)),
                                ("ordinal", Out::Number(ordinal)),
                            ]),
                        ),
                        ("role", Out::text(role_name(edge.role))),
                        ("instruction", Out::text(instruction_name(edge.instruction))),
                        ("tag_origin", Out::text(tag_origin_name(edge.tag_origin))),
                    ])
                })
                .collect(),
        );
        let source_locations = Out::Array(
            self.resolution
                .edges
                .iter()
                .enumerate()
                .map(|(ordinal, edge)| {
                    let use_ = analysis::Use {
                        role: edge.role,
                        instruction: edge.instruction,
                        tag_origin: edge.tag_origin,
                        location: edge.location.clone(),
                    };
                    object(vec![
                        ("edge", Out::Number(ordinal as u64)),
                        ("location", location_out(&use_)),
                    ])
                })
                .collect(),
        );
        let external_pins = Out::Array(
            self.resolution
                .external_sources
                .iter()
                .map(|source| {
                    object(vec![
                        ("reference", Out::text(&source.reference)),
                        ("platform", Out::text(&source.platform)),
                        ("root", descriptor_out(&source.root)),
                        ("registry", text_or_null(source.registry.as_deref())),
                        ("staging", Out::text(source.staging.name())),
                    ])
                })
                .collect(),
        );
        let request = &self.resolution.request;
        let graph_input = serde_json::json!({
            "build_platform": request.build_platform,
            "catalog_id": self.resolution.catalog_id,
            "environment": request.environment,
            "platforms": request.platforms,
            "staging": request.staging.name(),
            "targets": request.targets,
        });
        let graph_input_id =
            analysis::hash(&serde_json::to_vec(&graph_input).map_err(|_| Failure::Protocol)?);
        let graph = Graph {
            analyzer_identity: tools.analyzer.clone(),
            catalog_id: self.resolution.catalog_id.clone(),
            graph_id: self.resolution.graph_id.clone(),
            nodes,
            edges,
            source_locations,
            external_pins,
            frontend_pin: tools.frontend_reference.clone(),
            graph_input_id,
        };

        let secret_inputs = declaration
            .secrets
            .iter()
            .map(|(consumer, reference)| SecretInput {
                consumer: consumer.clone(),
                set: reference.set.clone(),
                key: reference.key.clone(),
                version: Fact::Unavailable(
                    "the secret provider reports no version for a declared reference".to_owned(),
                ),
            })
            .collect();

        let record = Record {
            artifact_id: mint_artifact()?,
            created_at: now_utc(),
            build_operation_id: recorder.operation_id().to_owned(),
            producer: Producer {
                name: self.target.to_owned(),
                declared: declaration.image.supplied.clone(),
                normalized,
            },
            target: recorder.target(self.target),
            root: self.root.clone(),
            platforms,
            associated_content: Vec::new(),
            inputs: Inputs {
                source,
                ignore,
                stages,
                args,
                platforms: platforms_fact,
                builder,
                frontend,
                outputs: outputs_fact,
                cache,
                entitlements,
                transfers,
                derived: Derived::Reported(derived),
            },
            graph,
            tools,
            builder: first.builder.clone(),
            secret_inputs,
            provenance: Provenance::Unavailable(self.report.provenance_reason.to_owned()),
            build_evidence: BuildEvidence {
                method: "verified-output-closure".to_owned(),
                closure_identity: self.root.digest.clone(),
                completed_at: now_utc(),
                source: EvidenceSource {
                    node_build: node_sessions.join(","),
                    output: output_session,
                },
            },
            annotations: Vec::new(),
            transformation: Transformation {
                implementation: analysis::tool_identity()?,
                protocol: "2".to_owned(),
                inputs_id: context_ids.first().copied().unwrap_or_default().to_owned(),
                map_id: first.generated_inputs_id.clone(),
            },
        };
        record.validate()?;
        Ok(record)
    }
}

fn target_outcome_name(outcome: &TargetOutcome) -> &'static str {
    match outcome {
        TargetOutcome::Retained(_) => "retained",
        TargetOutcome::Loaded(_) => "loaded",
        TargetOutcome::CacheOnly => "cache-only",
        TargetOutcome::Unpublished(_) => "unpublished",
        TargetOutcome::Failed { .. } => "failed",
        TargetOutcome::NotExported(_) => "not-exported",
    }
}

