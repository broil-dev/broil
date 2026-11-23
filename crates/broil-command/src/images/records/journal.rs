// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Out, RECORD_BYTES, ReadFailure, TargetAssociation, Tools, descriptor_out, object,
    valid_artifact, valid_time,
};
use crate::images::{Descriptor, common::*, json::Value, store, supervise::Active};
use broil_core::secret::path_safety::sudo_nonce;
use std::{collections::BTreeSet, fs::File, path::Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

impl Outcome {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Outcome::Pending => "pending",
            Outcome::Running => "running",
            Outcome::Succeeded => "succeeded",
            Outcome::Failed => "failed",
            Outcome::Cancelled => "cancelled",
            Outcome::Unknown => "unknown",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "pending" => Outcome::Pending,
            "running" => Outcome::Running,
            "succeeded" => Outcome::Succeeded,
            "failed" => Outcome::Failed,
            "cancelled" => Outcome::Cancelled,
            "unknown" => Outcome::Unknown,
            _ => return Err(Failure::Protocol),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FailureClass {
    Configuration,
    Capability,
    Credential,
    Authentication,
    Trust,
    Tool,
    SourceDrift,
    Integrity,
    Publication,
    Timeout,
    Cancellation,
    Storage,
    Indeterminate,
    CacheMiss,
}

impl FailureClass {
    pub(crate) fn name(self) -> &'static str {
        match self {
            FailureClass::Configuration => "configuration",
            FailureClass::Capability => "capability",
            FailureClass::Credential => "credential",
            FailureClass::Authentication => "authentication",
            FailureClass::Trust => "trust",
            FailureClass::Tool => "tool",
            FailureClass::SourceDrift => "source-drift",
            FailureClass::Integrity => "integrity",
            FailureClass::Publication => "publication",
            FailureClass::Timeout => "timeout",
            FailureClass::Cancellation => "cancellation",
            FailureClass::Storage => "storage",
            FailureClass::Indeterminate => "indeterminate",
            FailureClass::CacheMiss => "cache-miss",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "configuration" => FailureClass::Configuration,
            "capability" => FailureClass::Capability,
            "credential" => FailureClass::Credential,
            "authentication" => FailureClass::Authentication,
            "trust" => FailureClass::Trust,
            "tool" => FailureClass::Tool,
            "source-drift" => FailureClass::SourceDrift,
            "integrity" => FailureClass::Integrity,
            "publication" => FailureClass::Publication,
            "timeout" => FailureClass::Timeout,
            "cancellation" => FailureClass::Cancellation,
            "storage" => FailureClass::Storage,
            "indeterminate" => FailureClass::Indeterminate,
            "cache-miss" => FailureClass::CacheMiss,
            _ => return Err(Failure::Protocol),
        })
    }

    pub(crate) fn of(failure: Failure) -> Self {
        match failure {
            Failure::Policy => FailureClass::Configuration,
            Failure::Capacity => FailureClass::Capability,
            Failure::Credential => FailureClass::Credential,
            Failure::Authentication => FailureClass::Authentication,
            Failure::Trust => FailureClass::Trust,
            Failure::Protocol | Failure::Tool => FailureClass::Tool,
            Failure::Integrity | Failure::Limit => FailureClass::Integrity,
            Failure::Timeout => FailureClass::Timeout,
            Failure::Cancellation => FailureClass::Cancellation,
            Failure::Storage => FailureClass::Storage,
            Failure::Indeterminate => FailureClass::Indeterminate,
            Failure::CacheMiss => FailureClass::CacheMiss,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Phase,
    PreDispatch,
    ArtifactAllocated,
    RecordCommitted,
    AllocationAbandoned,
    Retention,
    StagingLifecycle,
    Publication,
    BindingAmbiguous,
    BindingResolved,
    Resume,
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Kind::Phase => "phase",
            Kind::PreDispatch => "pre-dispatch",
            Kind::ArtifactAllocated => "artifact-allocated",
            Kind::RecordCommitted => "record-committed",
            Kind::AllocationAbandoned => "allocation-abandoned",
            Kind::Retention => "retention",
            Kind::StagingLifecycle => "staging-lifecycle",
            Kind::Publication => "publication",
            Kind::BindingAmbiguous => "binding-ambiguous",
            Kind::BindingResolved => "binding-resolved",
            Kind::Resume => "resume",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "phase" => Kind::Phase,
            "pre-dispatch" => Kind::PreDispatch,
            "artifact-allocated" => Kind::ArtifactAllocated,
            "record-committed" => Kind::RecordCommitted,
            "allocation-abandoned" => Kind::AllocationAbandoned,
            "retention" => Kind::Retention,
            "staging-lifecycle" => Kind::StagingLifecycle,
            "publication" => Kind::Publication,
            "binding-ambiguous" => Kind::BindingAmbiguous,
            "binding-resolved" => Kind::BindingResolved,
            "resume" => Kind::Resume,
            _ => return Err(Failure::Protocol),
        })
    }

    pub(crate) fn journal_event(self) -> bool {
        matches!(
            self,
            Kind::PreDispatch
                | Kind::ArtifactAllocated
                | Kind::RecordCommitted
                | Kind::AllocationAbandoned
                | Kind::BindingAmbiguous
                | Kind::BindingResolved
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Boundary {
    CacheRead,
    CacheWrite,
    Export,
    Publication,
}

impl Boundary {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Boundary::CacheRead => "cache-read",
            Boundary::CacheWrite => "cache-write",
            Boundary::Export => "export",
            Boundary::Publication => "publication",
        }
    }
    pub(crate) fn of(phase: &str) -> Option<Self> {
        Some(match phase {
            "cache-read" => Boundary::CacheRead,
            "cache-write" => Boundary::CacheWrite,
            "export" => Boundary::Export,
            "publication" => Boundary::Publication,
            _ => return None,
        })
    }
    fn minted_before_dispatch(self) -> bool {
        matches!(self, Boundary::CacheRead | Boundary::CacheWrite)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StageAcquisition {
    pub(crate) role: String,
    pub(crate) acquisition_id: String,
}

impl StageAcquisition {
    fn out(&self) -> Out {
        object(vec![
            ("role", Out::text(&self.role)),
            ("acquisition_id", Out::text(&self.acquisition_id)),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CacheRead {
    pub(crate) registry: String,
    pub(crate) namespace_reference: String,
    pub(crate) helper_identity: String,
    pub(crate) optional_read: bool,
    pub(crate) continued_without_import: Option<bool>,
}

impl CacheRead {
    fn out(&self) -> Out {
        let mut members = vec![
            ("registry", Out::text(&self.registry)),
            ("namespace_reference", Out::text(&self.namespace_reference)),
            ("purpose", Out::text("cache_read")),
            ("action", Out::text("fetch")),
            ("content_kind", Out::text("cache")),
            ("helper_identity", Out::text(&self.helper_identity)),
            ("optional_read", Out::Bool(self.optional_read)),
        ];
        if let Some(continued) = self.continued_without_import {
            members.push(("continued_without_import", Out::Bool(continued)));
        }
        object(members)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetentionClosure {
    pub(crate) root: Descriptor,
    pub(crate) manifests: Vec<Descriptor>,
    pub(crate) verified_descriptors: u64,
    pub(crate) verified_bytes: u64,
    pub(crate) archive: Option<(u64, String)>,
}

impl RetentionClosure {
    fn out(&self) -> Out {
        let mut members = vec![
            ("root", descriptor_out(&self.root)),
            (
                "manifests",
                Out::Array(self.manifests.iter().map(descriptor_out).collect()),
            ),
            (
                "verified_descriptors",
                Out::Number(self.verified_descriptors),
            ),
            ("verified_bytes", Out::Number(self.verified_bytes)),
        ];
        if let Some((size, sha256)) = &self.archive {
            members.push(("archive_size", Out::Number(*size)));
            members.push(("archive_sha256", Out::text(sha256)));
        }
        object(members)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalIntegrity {
    VerifyStaged,
    InspectPrepared,
}

impl LocalIntegrity {
    fn name(self) -> &'static str {
        match self {
            LocalIntegrity::VerifyStaged => "verify-staged",
            LocalIntegrity::InspectPrepared => "inspect-prepared",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "verify-staged" => LocalIntegrity::VerifyStaged,
            "inspect-prepared" => LocalIntegrity::InspectPrepared,
            _ => return Err(Failure::Protocol),
        })
    }
    fn acquisitions(self) -> usize {
        match self {
            LocalIntegrity::VerifyStaged => 2,
            LocalIntegrity::InspectPrepared => 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicationEntry {
    pub(crate) descriptor: Descriptor,
    pub(crate) local_integrity: LocalIntegrity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PublicationClosure {
    pub(crate) entries: Vec<PublicationEntry>,
    pub(crate) verified_descriptors: u64,
    pub(crate) verified_bytes: u64,
    pub(crate) closure_complete: bool,
}

impl PublicationClosure {
    fn out(&self) -> Out {
        object(vec![
            (
                "entries",
                Out::Array(
                    self.entries
                        .iter()
                        .map(|entry| {
                            object(vec![
                                ("descriptor", descriptor_out(&entry.descriptor)),
                                ("local_integrity", Out::text(entry.local_integrity.name())),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "verified_descriptors",
                Out::Number(self.verified_descriptors),
            ),
            ("verified_bytes", Out::Number(self.verified_bytes)),
            ("closure_complete", Out::Bool(self.closure_complete)),
        ])
    }

    fn uniform_integrity(&self) -> Option<LocalIntegrity> {
        let first = self.entries.first()?.local_integrity;
        self.entries
            .iter()
            .all(|entry| entry.local_integrity == first)
            .then_some(first)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Tag {
    pub(crate) tag: String,
    pub(crate) digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Candidate {
    pub(crate) artifact_id: String,
    pub(crate) operation_id: String,
    pub(crate) retention_seq: u64,
}

impl Candidate {
    fn out(&self) -> Out {
        object(vec![
            ("artifact_id", Out::text(&self.artifact_id)),
            ("operation_id", Out::text(&self.operation_id)),
            ("retention_seq", Out::Number(self.retention_seq)),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Disposition {
    UnprovedWindow,
    NoRecord,
    Ambiguous,
}

impl Disposition {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Disposition::UnprovedWindow => "unproved-window",
            Disposition::NoRecord => "no-record",
            Disposition::Ambiguous => "ambiguous",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "unproved-window" => Disposition::UnprovedWindow,
            "no-record" => Disposition::NoRecord,
            "ambiguous" => Disposition::Ambiguous,
            _ => return Err(Failure::Protocol),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Window {
    pub(crate) operation_id: String,
    pub(crate) artifact_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BindingReason {
    pub(crate) disposition: Disposition,
    pub(crate) windows: Option<Vec<Window>>,
    pub(crate) candidates: Option<Vec<Candidate>>,
}

impl BindingReason {
    fn out(&self) -> Out {
        let mut members = vec![("disposition", Out::text(self.disposition.name()))];
        if let Some(windows) = &self.windows {
            members.push((
                "windows",
                Out::Array(
                    windows
                        .iter()
                        .map(|window| {
                            object(vec![
                                ("operation_id", Out::text(&window.operation_id)),
                                ("artifact_id", Out::text(&window.artifact_id)),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        if let Some(candidates) = &self.candidates {
            members.push((
                "candidates",
                Out::Array(candidates.iter().map(Candidate::out).collect()),
            ));
        }
        object(members)
    }

    fn validate(&self) -> Result<()> {
        match self.disposition {
            Disposition::UnprovedWindow => require(
                self.windows.as_ref().is_some_and(|w| !w.is_empty()) && self.candidates.is_some(),
                Failure::Protocol,
            ),
            Disposition::NoRecord | Disposition::Ambiguous => require(
                self.windows.is_none() && self.candidates.is_none(),
                Failure::Protocol,
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ObservationDetail {
    Phase {
        cache_read: CacheRead,
    },
    ArtifactAllocated {
        root: Descriptor,
    },
    Retention {
        owner: String,
        location: String,
        output_kind: String,
        closure: RetentionClosure,
        broil_cleans: bool,
        release_covers: bool,
    },
    StagingLifecycle {
        release_completed: bool,
    },
    Publication {
        root: String,
        endpoint: String,
        server_name: String,
        repository: String,
        closure: PublicationClosure,
        tags: Vec<Tag>,
        binding_reason: Option<BindingReason>,
    },
    BindingAmbiguous {
        publication_seq: u64,
        candidates: Vec<Candidate>,
        reason: BindingReason,
    },
    BindingResolved {
        ambiguous_seq: u64,
        retention_operation_id: String,
        retention_seq: u64,
    },
}

impl ObservationDetail {
    fn kind(&self) -> Kind {
        match self {
            ObservationDetail::Phase { .. } => Kind::Phase,
            ObservationDetail::ArtifactAllocated { .. } => Kind::ArtifactAllocated,
            ObservationDetail::Retention { .. } => Kind::Retention,
            ObservationDetail::StagingLifecycle { .. } => Kind::StagingLifecycle,
            ObservationDetail::Publication { .. } => Kind::Publication,
            ObservationDetail::BindingAmbiguous { .. } => Kind::BindingAmbiguous,
            ObservationDetail::BindingResolved { .. } => Kind::BindingResolved,
        }
    }

    fn out(&self) -> Out {
        match self {
            ObservationDetail::Phase { cache_read } => {
                object(vec![("cache_read", cache_read.out())])
            }
            ObservationDetail::ArtifactAllocated { root } => {
                object(vec![("root", descriptor_out(root))])
            }
            ObservationDetail::Retention {
                owner,
                location,
                output_kind,
                closure,
                broil_cleans,
                release_covers,
            } => object(vec![
                ("owner", Out::text(owner)),
                ("location", Out::text(location)),
                ("output_kind", Out::text(output_kind)),
                ("closure", closure.out()),
                (
                    "cleanup_scope",
                    object(vec![
                        ("broil_cleans", Out::Bool(*broil_cleans)),
                        ("release_covers", Out::Bool(*release_covers)),
                    ]),
                ),
            ]),
            ObservationDetail::StagingLifecycle { release_completed } => {
                object(vec![("release_completed", Out::Bool(*release_completed))])
            }
            ObservationDetail::Publication {
                root,
                endpoint,
                server_name,
                repository,
                closure,
                tags,
                binding_reason,
            } => {
                let mut members = vec![
                    ("root", Out::text(root)),
                    ("endpoint", Out::text(endpoint)),
                    ("server_name", Out::text(server_name)),
                    ("repository", Out::text(repository)),
                    ("closure", closure.out()),
                    (
                        "tags",
                        Out::Array(
                            tags.iter()
                                .map(|tag| {
                                    object(vec![
                                        ("tag", Out::text(&tag.tag)),
                                        ("digest", Out::text(&tag.digest)),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ];
                if let Some(reason) = binding_reason {
                    members.push(("binding_reason", reason.out()));
                }
                object(members)
            }
            ObservationDetail::BindingAmbiguous {
                publication_seq,
                candidates,
                reason,
            } => object(vec![
                ("publication_seq", Out::Number(*publication_seq)),
                (
                    "candidates",
                    Out::Array(candidates.iter().map(Candidate::out).collect()),
                ),
                ("reason", reason.out()),
            ]),
            ObservationDetail::BindingResolved {
                ambiguous_seq,
                retention_operation_id,
                retention_seq,
            } => object(vec![
                ("ambiguous_seq", Out::Number(*ambiguous_seq)),
                ("retention_operation_id", Out::text(retention_operation_id)),
                ("retention_seq", Out::Number(*retention_seq)),
            ]),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) seq: u64,
    pub(crate) kind: Kind,
    pub(crate) operation_id: String,
    pub(crate) target: Option<TargetAssociation>,
    pub(crate) phase: Option<String>,
    pub(crate) dispatched: Option<bool>,
    pub(crate) observed_at: String,
    pub(crate) source: Option<String>,
    pub(crate) method: Option<String>,
    pub(crate) artifact_id: Option<String>,
    pub(crate) outcome: Option<Outcome>,
    pub(crate) failure_class: Option<FailureClass>,
    pub(crate) tool_status: Option<u64>,
    pub(crate) tool_signal: Option<u64>,
    pub(crate) cancellation_requested: Option<bool>,
    pub(crate) cleanup_uncertain: Option<bool>,
    pub(crate) stage_operation_id: Option<Vec<StageAcquisition>>,
    pub(crate) detail: Option<ObservationDetail>,
}

impl Observation {
    fn out(&self) -> Out {
        let mut members: Vec<(&'static str, Out)> = vec![
            ("format_version", Out::Number(1)),
            ("seq", Out::Number(self.seq)),
            ("kind", Out::text(self.kind.name())),
            ("operation_id", Out::text(&self.operation_id)),
        ];
        if let Some(target) = &self.target {
            members.push(("target", target.out()));
        }
        if let Some(phase) = &self.phase {
            members.push(("phase", Out::text(phase)));
        }
        if let Some(dispatched) = self.dispatched {
            members.push(("dispatched", Out::Bool(dispatched)));
        }
        members.push(("observed_at", Out::text(&self.observed_at)));
        if let Some(source) = &self.source {
            members.push(("source", Out::text(source)));
        }
        if let Some(method) = &self.method {
            members.push(("method", Out::text(method)));
        }
        if let Some(artifact_id) = &self.artifact_id {
            members.push(("artifact_id", Out::text(artifact_id)));
        }
        if let Some(outcome) = self.outcome {
            members.push(("outcome", Out::text(outcome.name())));
        }
        if let Some(class) = self.failure_class {
            members.push(("failure_class", Out::text(class.name())));
        }
        if let Some(status) = self.tool_status {
            members.push(("tool_status", Out::Number(status)));
        }
        if let Some(signal) = self.tool_signal {
            members.push(("tool_signal", Out::Number(signal)));
        }
        if let Some(value) = self.cancellation_requested {
            members.push(("cancellation_requested", Out::Bool(value)));
        }
        if let Some(value) = self.cleanup_uncertain {
            members.push(("cleanup_uncertain", Out::Bool(value)));
        }
        if let Some(acquisitions) = &self.stage_operation_id {
            members.push((
                "stage_operation_id",
                Out::Array(acquisitions.iter().map(StageAcquisition::out).collect()),
            ));
        }
        if let Some(detail) = &self.detail {
            members.push(("detail", detail.out()));
        }
        object(members)
    }

    fn validate(&self) -> Result<()> {
        require(valid_operation(&self.operation_id), Failure::Protocol)?;
        require(valid_time(&self.observed_at), Failure::Protocol)?;
        if let Some(target) = &self.target {
            target.validate().map_err(|_| Failure::Protocol)?;
        }
        if let Some(id) = &self.artifact_id {
            require(valid_artifact(id), Failure::Protocol)?;
        }
        let boundary = self.phase.as_deref().and_then(Boundary::of);
        let journal_event = self.kind.journal_event();

        if journal_event {
            require(
                self.outcome.is_none() && self.source.is_none() && self.method.is_none(),
                Failure::Protocol,
            )?;
        } else {
            require(
                self.outcome.is_some() && self.source.is_some() && self.method.is_some(),
                Failure::Protocol,
            )?;
        }

        let class_required =
            self.outcome == Some(Outcome::Failed) || self.kind == Kind::AllocationAbandoned;
        require(
            self.failure_class.is_some() == class_required,
            Failure::Protocol,
        )?;

        let cache_boundary = matches!(
            boundary,
            Some(Boundary::CacheRead) | Some(Boundary::CacheWrite)
        );
        let target_required = match self.kind {
            Kind::Phase | Kind::PreDispatch => !cache_boundary,
            Kind::ArtifactAllocated | Kind::Retention | Kind::Publication => true,
            _ => false,
        };
        let target_forbidden = matches!(
            self.kind,
            Kind::RecordCommitted
                | Kind::AllocationAbandoned
                | Kind::BindingAmbiguous
                | Kind::BindingResolved
        );
        if target_required {
            require(self.target.is_some(), Failure::Protocol)?;
        }
        if target_forbidden {
            require(self.target.is_none(), Failure::Protocol)?;
        }

        let phase_required = matches!(
            self.kind,
            Kind::Phase | Kind::Retention | Kind::Publication | Kind::PreDispatch
        );
        require(
            self.phase.is_some() == phase_required
                || matches!(self.kind, Kind::Resume | Kind::StagingLifecycle),
            Failure::Protocol,
        )?;
        if journal_event && self.kind != Kind::PreDispatch {
            require(self.phase.is_none(), Failure::Protocol)?;
        }

        let id_required = matches!(
            self.kind,
            Kind::ArtifactAllocated
                | Kind::RecordCommitted
                | Kind::AllocationAbandoned
                | Kind::BindingResolved
        );
        if id_required {
            require(self.artifact_id.is_some(), Failure::Protocol)?;
        }
        if matches!(self.kind, Kind::BindingAmbiguous | Kind::PreDispatch) {
            require(self.artifact_id.is_none(), Failure::Protocol)?;
        }

        if self.kind == Kind::PreDispatch {
            require(
                self.dispatched == Some(false)
                    && self.cancellation_requested.is_none()
                    && self.cleanup_uncertain.is_none(),
                Failure::Protocol,
            )?;
        } else if journal_event || self.phase.is_none() {
            require(
                self.dispatched.is_none()
                    && self.cancellation_requested.is_none()
                    && self.cleanup_uncertain.is_none(),
                Failure::Protocol,
            )?;
        } else {
            require(
                self.dispatched.is_some()
                    && self.cancellation_requested.is_some()
                    && self.cleanup_uncertain.is_some(),
                Failure::Protocol,
            )?;
        }

        self.validate_acquisitions(boundary)?;
        self.validate_detail()
    }

    fn validate_acquisitions(&self, boundary: Option<Boundary>) -> Result<()> {
        let present = self.stage_operation_id.as_ref();
        if let Some(acquisitions) = present {
            require(!acquisitions.is_empty(), Failure::Protocol)?;
            for acquisition in acquisitions {
                require(
                    !acquisition.role.is_empty() && valid_operation(&acquisition.acquisition_id),
                    Failure::Protocol,
                )?;
            }
        }
        match self.kind {
            Kind::PreDispatch => {
                let minted = boundary.is_some_and(Boundary::minted_before_dispatch);
                require(present.is_some() == minted, Failure::Protocol)?;
                if minted {
                    require(present.is_some_and(|a| a.len() == 1), Failure::Protocol)?;
                }
            }
            Kind::StagingLifecycle => {
                require(present.is_some_and(|a| a.len() == 1), Failure::Protocol)?;
            }
            Kind::Publication => {
                let ObservationDetail::Publication { closure, .. } =
                    self.detail.as_ref().ok_or(Failure::Protocol)?
                else {
                    return Err(Failure::Protocol);
                };
                require(!closure.entries.is_empty(), Failure::Protocol)?;
                let integrity = closure.uniform_integrity().ok_or(Failure::Protocol)?;
                require(
                    present.is_some_and(|a| a.len() == integrity.acquisitions()),
                    Failure::Protocol,
                )?;
            }
            Kind::ArtifactAllocated
            | Kind::RecordCommitted
            | Kind::AllocationAbandoned
            | Kind::BindingAmbiguous
            | Kind::BindingResolved
            | Kind::Retention
            | Kind::Resume => {
                require(present.is_none(), Failure::Protocol)?;
            }
            Kind::Phase => match boundary {
                Some(Boundary::CacheRead) | Some(Boundary::CacheWrite) => {
                    require(present.is_some_and(|a| a.len() == 1), Failure::Protocol)?;
                }
                Some(Boundary::Export) | Some(Boundary::Publication) => {}
                None => require(present.is_none(), Failure::Protocol)?,
            },
        }
        Ok(())
    }

    fn validate_detail(&self) -> Result<()> {
        match (&self.detail, self.kind) {
            (None, Kind::Phase) => require(
                self.phase.as_deref().and_then(Boundary::of) != Some(Boundary::CacheRead),
                Failure::Protocol,
            ),
            (Some(ObservationDetail::Phase { cache_read }), Kind::Phase) => {
                require(
                    self.phase.as_deref().and_then(Boundary::of) == Some(Boundary::CacheRead),
                    Failure::Protocol,
                )?;
                require(
                    cache_read.continued_without_import.is_some()
                        == (self.failure_class == Some(FailureClass::CacheMiss)),
                    Failure::Protocol,
                )?;
                require(
                    cache_read.continued_without_import != Some(true) || cache_read.optional_read,
                    Failure::Protocol,
                )
            }
            (
                None,
                Kind::PreDispatch
                | Kind::RecordCommitted
                | Kind::AllocationAbandoned
                | Kind::Resume,
            ) => Ok(()),
            (Some(detail), kind) if detail.kind() == kind => match detail {
                ObservationDetail::Retention {
                    output_kind,
                    closure,
                    broil_cleans,
                    release_covers,
                    ..
                } => {
                    require(
                        matches!(output_kind.as_str(), "oci-layout" | "oci-archive"),
                        Failure::Protocol,
                    )?;
                    require(
                        closure.archive.is_some() == (output_kind == "oci-archive"),
                        Failure::Protocol,
                    )?;
                    require(!*broil_cleans && !*release_covers, Failure::Protocol)
                }
                ObservationDetail::Publication {
                    closure,
                    tags,
                    binding_reason,
                    ..
                } => {
                    require(tags.len() <= 1, Failure::Protocol)?;
                    require(
                        closure.verified_descriptors == closure.entries.len() as u64,
                        Failure::Protocol,
                    )?;
                    if let Some(reason) = binding_reason {
                        reason.validate()?;
                        require(
                            self.artifact_id.is_none()
                                && reason.disposition != Disposition::Ambiguous,
                            Failure::Protocol,
                        )?;
                    }
                    Ok(())
                }
                ObservationDetail::BindingAmbiguous {
                    candidates, reason, ..
                } => {
                    require(!candidates.is_empty(), Failure::Protocol)?;
                    require(
                        reason.disposition == Disposition::Ambiguous,
                        Failure::Protocol,
                    )?;
                    reason.validate()
                }
                ObservationDetail::BindingResolved {
                    retention_operation_id,
                    ..
                } => require(valid_operation(retention_operation_id), Failure::Protocol),
                _ => Ok(()),
            },
            _ => Err(Failure::Protocol),
        }
    }
}


pub(super) fn optional_fields<'a>(
    value: Value<'a>,
    allowed: &[&str],
) -> Result<Vec<Option<Value<'a>>>> {
    let mut slots = vec![None; allowed.len()];
    for (key, item) in value.members()? {
        let key = key.text()?;
        let index = allowed
            .iter()
            .position(|name| name.as_bytes() == key.get())
            .ok_or(Failure::Protocol)?;
        require(slots[index].is_none(), Failure::Protocol)?;
        slots[index] = Some(item);
    }
    Ok(slots)
}

fn text(value: Value<'_>) -> Result<String> {
    Ok(std::str::from_utf8(value.text()?.get())
        .map_err(|_| Failure::Protocol)?
        .into())
}

fn descriptor(value: Value<'_>) -> Result<Descriptor> {
    let f = value.object(&[b"digest", b"size", b"media_type"])?;
    let descriptor = Descriptor {
        digest: text(f[0])?,
        size: f[1].number()?,
        media_type: text(f[2])?,
    };
    descriptor.validate()?;
    Ok(descriptor)
}

fn descriptors(value: Value<'_>) -> Result<Vec<Descriptor>> {
    value.array()?.into_iter().map(descriptor).collect()
}

fn supported(value: Value<'_>) -> std::result::Result<(), ReadFailure> {
    let version = value
        .optional("format_version")
        .map_err(ReadFailure::Invalid)?
        .ok_or(ReadFailure::Invalid(Failure::Protocol))?
        .number()
        .map_err(ReadFailure::Invalid)?;
    if version != 1 {
        return Err(ReadFailure::UnsupportedVersion(version));
    }
    Ok(())
}

fn target(value: Value<'_>) -> Result<TargetAssociation> {
    let f = value.object(&[b"project_id", b"environment", b"backend", b"logical_target"])?;
    let association = TargetAssociation {
        project_id: text(f[0])?,
        environment: if f[1].is_null() {
            None
        } else {
            Some(text(f[1])?)
        },
        backend: text(f[2])?,
        logical_target: text(f[3])?,
    };
    association.validate().map_err(|_| Failure::Protocol)?;
    Ok(association)
}

fn candidates(value: Value<'_>) -> Result<Vec<Candidate>> {
    value
        .array()?
        .into_iter()
        .map(|item| {
            let f = item.object(&[b"artifact_id", b"operation_id", b"retention_seq"])?;
            let candidate = Candidate {
                artifact_id: text(f[0])?,
                operation_id: text(f[1])?,
                retention_seq: f[2].number()?,
            };
            require(
                valid_artifact(&candidate.artifact_id) && valid_operation(&candidate.operation_id),
                Failure::Protocol,
            )?;
            Ok(candidate)
        })
        .collect()
}

fn binding_reason(value: Value<'_>) -> Result<BindingReason> {
    let slots = optional_fields(value, &["disposition", "windows", "candidates"])?;
    let reason = BindingReason {
        disposition: Disposition::parse(&text(slots[0].ok_or(Failure::Protocol)?)?)?,
        windows: slots[1]
            .map(|value| {
                value
                    .array()?
                    .into_iter()
                    .map(|item| {
                        let f = item.object(&[b"operation_id", b"artifact_id"])?;
                        let window = Window {
                            operation_id: text(f[0])?,
                            artifact_id: text(f[1])?,
                        };
                        require(
                            valid_operation(&window.operation_id)
                                && valid_artifact(&window.artifact_id),
                            Failure::Protocol,
                        )?;
                        Ok(window)
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?,
        candidates: slots[2].map(candidates).transpose()?,
    };
    reason.validate()?;
    Ok(reason)
}

fn observation_detail(value: Value<'_>, kind: Kind) -> Result<ObservationDetail> {
    Ok(match kind {
        Kind::Phase => {
            let slots = optional_fields(value, &["cache_read"])?;
            let read = slots[0].ok_or(Failure::Protocol)?;
            let f = read.object(&[
                b"registry",
                b"namespace_reference",
                b"purpose",
                b"action",
                b"content_kind",
                b"helper_identity",
                b"optional_read",
                b"continued_without_import",
            ]);
            let (f, continued) = match f {
                Ok(f) => {
                    let continued = Some(f[7].boolean()?);
                    (f, continued)
                }
                Err(_) => (
                    read.object(&[
                        b"registry",
                        b"namespace_reference",
                        b"purpose",
                        b"action",
                        b"content_kind",
                        b"helper_identity",
                        b"optional_read",
                    ])?,
                    None,
                ),
            };
            require(
                f[2].equals("cache_read")? && f[3].equals("fetch")? && f[4].equals("cache")?,
                Failure::Protocol,
            )?;
            ObservationDetail::Phase {
                cache_read: CacheRead {
                    registry: text(f[0])?,
                    namespace_reference: text(f[1])?,
                    helper_identity: text(f[5])?,
                    optional_read: f[6].boolean()?,
                    continued_without_import: continued,
                },
            }
        }
        Kind::ArtifactAllocated => {
            let f = value.object(&[b"root"])?;
            ObservationDetail::ArtifactAllocated {
                root: descriptor(f[0])?,
            }
        }
        Kind::Retention => {
            let f = value.object(&[
                b"owner",
                b"location",
                b"output_kind",
                b"closure",
                b"cleanup_scope",
            ])?;
            let slots = optional_fields(
                f[3],
                &[
                    "root",
                    "manifests",
                    "verified_descriptors",
                    "verified_bytes",
                    "archive_size",
                    "archive_sha256",
                ],
            )?;
            let scope = f[4].object(&[b"broil_cleans", b"release_covers"])?;
            ObservationDetail::Retention {
                owner: text(f[0])?,
                location: text(f[1])?,
                output_kind: text(f[2])?,
                closure: RetentionClosure {
                    root: descriptor(slots[0].ok_or(Failure::Protocol)?)?,
                    manifests: descriptors(slots[1].ok_or(Failure::Protocol)?)?,
                    verified_descriptors: slots[2].ok_or(Failure::Protocol)?.number()?,
                    verified_bytes: slots[3].ok_or(Failure::Protocol)?.number()?,
                    archive: match (slots[4], slots[5]) {
                        (Some(size), Some(sha256)) => Some((size.number()?, text(sha256)?)),
                        (None, None) => None,
                        _ => return Err(Failure::Protocol),
                    },
                },
                broil_cleans: scope[0].boolean()?,
                release_covers: scope[1].boolean()?,
            }
        }
        Kind::StagingLifecycle => {
            let f = value.object(&[b"release_completed"])?;
            ObservationDetail::StagingLifecycle {
                release_completed: f[0].boolean()?,
            }
        }
        Kind::Publication => {
            let slots = optional_fields(
                value,
                &[
                    "root",
                    "endpoint",
                    "server_name",
                    "repository",
                    "closure",
                    "tags",
                    "binding_reason",
                ],
            )?;
            let closure = slots[4].ok_or(Failure::Protocol)?;
            let c = closure.object(&[
                b"entries",
                b"verified_descriptors",
                b"verified_bytes",
                b"closure_complete",
            ])?;
            let entries = c[0]
                .array()?
                .into_iter()
                .map(|item| {
                    let e = item.object(&[b"descriptor", b"local_integrity"])?;
                    Ok(PublicationEntry {
                        descriptor: descriptor(e[0])?,
                        local_integrity: LocalIntegrity::parse(&text(e[1])?)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            ObservationDetail::Publication {
                root: text(slots[0].ok_or(Failure::Protocol)?)?,
                endpoint: text(slots[1].ok_or(Failure::Protocol)?)?,
                server_name: text(slots[2].ok_or(Failure::Protocol)?)?,
                repository: text(slots[3].ok_or(Failure::Protocol)?)?,
                closure: PublicationClosure {
                    entries,
                    verified_descriptors: c[1].number()?,
                    verified_bytes: c[2].number()?,
                    closure_complete: c[3].boolean()?,
                },
                tags: slots[5]
                    .ok_or(Failure::Protocol)?
                    .array()?
                    .into_iter()
                    .map(|item| {
                        let t = item.object(&[b"tag", b"digest"])?;
                        Ok(Tag {
                            tag: text(t[0])?,
                            digest: text(t[1])?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
                binding_reason: slots[6].map(binding_reason).transpose()?,
            }
        }
        Kind::BindingAmbiguous => {
            let f = value.object(&[b"publication_seq", b"candidates", b"reason"])?;
            ObservationDetail::BindingAmbiguous {
                publication_seq: f[0].number()?,
                candidates: candidates(f[1])?,
                reason: binding_reason(f[2])?,
            }
        }
        Kind::BindingResolved => {
            let f = value.object(&[
                b"ambiguous_seq",
                b"retention_operation_id",
                b"retention_seq",
            ])?;
            ObservationDetail::BindingResolved {
                ambiguous_seq: f[0].number()?,
                retention_operation_id: text(f[1])?,
                retention_seq: f[2].number()?,
            }
        }
        Kind::PreDispatch | Kind::RecordCommitted | Kind::AllocationAbandoned | Kind::Resume => {
            return Err(Failure::Protocol);
        }
    })
}

const OBSERVATION_MEMBERS: [&str; 19] = [
    "format_version",
    "seq",
    "kind",
    "operation_id",
    "target",
    "phase",
    "dispatched",
    "observed_at",
    "source",
    "method",
    "artifact_id",
    "outcome",
    "failure_class",
    "tool_status",
    "tool_signal",
    "cancellation_requested",
    "cleanup_uncertain",
    "stage_operation_id",
    "detail",
];

pub(crate) fn decode_observation(bytes: &[u8]) -> std::result::Result<Observation, ReadFailure> {
    fn inner(bytes: &[u8]) -> Result<Observation> {
        let value = Value::parse_bounded(bytes, RECORD_BYTES as usize, 64)?;
        let slots = optional_fields(value, &OBSERVATION_MEMBERS)?;
        let get = |i: usize| slots[i].ok_or(Failure::Protocol);
        let kind = Kind::parse(&text(get(2)?)?)?;
        let observation = Observation {
            seq: get(1)?.number()?,
            kind,
            operation_id: text(get(3)?)?,
            target: slots[4].map(target).transpose()?,
            phase: slots[5].map(text).transpose()?,
            dispatched: slots[6].map(Value::boolean).transpose()?,
            observed_at: text(get(7)?)?,
            source: slots[8].map(text).transpose()?,
            method: slots[9].map(text).transpose()?,
            artifact_id: slots[10].map(text).transpose()?,
            outcome: slots[11]
                .map(|value| Outcome::parse(&text(value)?))
                .transpose()?,
            failure_class: slots[12]
                .map(|value| FailureClass::parse(&text(value)?))
                .transpose()?,
            tool_status: slots[13].map(Value::number).transpose()?,
            tool_signal: slots[14].map(Value::number).transpose()?,
            cancellation_requested: slots[15].map(Value::boolean).transpose()?,
            cleanup_uncertain: slots[16].map(Value::boolean).transpose()?,
            stage_operation_id: slots[17]
                .map(|value| {
                    value
                        .array()?
                        .into_iter()
                        .map(|item| {
                            let f = item.object(&[b"role", b"acquisition_id"])?;
                            Ok(StageAcquisition {
                                role: text(f[0])?,
                                acquisition_id: text(f[1])?,
                            })
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?,
            detail: slots[OBSERVATION_MEMBERS.len() - 1]
                .map(|value| observation_detail(value, kind))
                .transpose()?,
        };
        observation.validate()?;
        Ok(observation)
    }
    let value =
        Value::parse_bounded(bytes, RECORD_BYTES as usize, 64).map_err(ReadFailure::Invalid)?;
    supported(value)?;
    inner(bytes).map_err(ReadFailure::Invalid)
}


#[derive(Clone, Debug)]
pub(crate) struct OperationRecord {
    pub(crate) operation_id: String,
    pub(crate) kind: String,
    pub(crate) origin: String,
    pub(crate) started_at: String,
    pub(crate) request: Out,
    pub(crate) tools: Tools,
    pub(crate) preceding_operation_id: Option<String>,
    pub(crate) retry_reason: Option<String>,
}

impl OperationRecord {
    fn out(&self) -> Out {
        let mut members = vec![
            ("format_version", Out::Number(1)),
            ("operation_id", Out::text(&self.operation_id)),
            ("kind", Out::text(&self.kind)),
            ("origin", Out::text(&self.origin)),
            ("started_at", Out::text(&self.started_at)),
            ("request", self.request.clone()),
            ("tools", self.tools.out()),
        ];
        if let Some(preceding) = &self.preceding_operation_id {
            members.push(("preceding_operation_id", Out::text(preceding)));
            members.push((
                "retry_reason",
                Out::text(self.retry_reason.as_deref().unwrap_or_default()),
            ));
        }
        object(members)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        require(valid_operation(&self.operation_id), Failure::Policy)?;
        require(valid_time(&self.started_at), Failure::Policy)?;
        require(
            !self.kind.is_empty() && !self.origin.is_empty(),
            Failure::Policy,
        )?;
        require(
            self.preceding_operation_id.is_some() == self.retry_reason.is_some(),
            Failure::Policy,
        )?;
        if let Some(preceding) = &self.preceding_operation_id {
            require(
                valid_operation(preceding) && preceding != &self.operation_id,
                Failure::Policy,
            )?;
        }
        let bytes = self.out().encode()?;
        require(bytes.len() as u64 <= RECORD_BYTES, Failure::Limit)?;
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Settlement {
    pub(crate) ambiguous_seq: u64,
    pub(crate) artifact_id: String,
    pub(crate) retention_operation_id: String,
    pub(crate) retention_seq: u64,
}

impl Settlement {
    fn out(&self) -> Out {
        object(vec![
            ("format_version", Out::Number(1)),
            ("ambiguous_seq", Out::Number(self.ambiguous_seq)),
            ("artifact_id", Out::text(&self.artifact_id)),
            (
                "retention_operation_id",
                Out::text(&self.retention_operation_id),
            ),
            ("retention_seq", Out::Number(self.retention_seq)),
        ])
    }

    fn decode(bytes: &[u8]) -> std::result::Result<Self, ReadFailure> {
        let value =
            Value::parse_bounded(bytes, RECORD_BYTES as usize, 64).map_err(ReadFailure::Invalid)?;
        supported(value)?;
        fn inner(value: Value<'_>) -> Result<Settlement> {
            let f = value.object(&[
                b"format_version",
                b"ambiguous_seq",
                b"artifact_id",
                b"retention_operation_id",
                b"retention_seq",
            ])?;
            let settlement = Settlement {
                ambiguous_seq: f[1].number()?,
                artifact_id: text(f[2])?,
                retention_operation_id: text(f[3])?,
                retention_seq: f[4].number()?,
            };
            require(
                valid_artifact(&settlement.artifact_id)
                    && valid_operation(&settlement.retention_operation_id),
                Failure::Protocol,
            )?;
            Ok(settlement)
        }
        inner(value).map_err(ReadFailure::Invalid)
    }
}


const MAX_SEQ: u64 = 999_999_999;

fn observation_seq(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".json")?;
    if digits.is_empty()
        || digits.len() > 9
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    digits.parse().ok()
}

pub(crate) struct Journal {
    operation_id: String,
    directory: File,
    observations: File,
}

impl Journal {
    pub(crate) fn open(
        root: &Path,
        operation_id: &str,
        create: bool,
        active: &Active,
    ) -> Result<Self> {
        require(valid_operation(operation_id), Failure::Policy)?;
        let state = store::state_directory(root, create, active)?;
        let operations = store::child_directory(&state, "operations", create, active)?;
        let directory = store::child_directory(&operations, operation_id, create, active)?;
        let observations = store::child_directory(&directory, "observations", create, active)?;
        if create {
            store::child_directory(&directory, "settlements", true, active)?;
        }
        Ok(Journal {
            operation_id: operation_id.to_owned(),
            directory,
            observations,
        })
    }

    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn open_operation(&self, record: &OperationRecord, active: &Active) -> Result<()> {
        require(record.operation_id == self.operation_id, Failure::Policy)?;
        let bytes = record.encode()?;
        let prepared = store::prepare(&self.directory, temporary("operation")?, &bytes, active)?;
        store::publish_new(&self.directory, prepared, "operation.json", active)?
            .ok_or(Failure::Integrity)?;
        store::sync_parent(&self.directory, active)
    }

    pub(crate) fn read_operation(
        &self,
        active: &Active,
    ) -> std::result::Result<OperationRecord, ReadFailure> {
        let read = store::read(&self.directory, "operation.json", RECORD_BYTES, active)
            .map_err(ReadFailure::Invalid)?;
        let (bytes, _) = read.ok_or(ReadFailure::Invalid(Failure::Storage))?;
        decode_operation(&bytes)
    }

    pub(crate) fn append(
        &self,
        mut observation: Observation,
        active: &Active,
    ) -> Result<Observation> {
        require(
            observation.operation_id == self.operation_id,
            Failure::Policy,
        )?;
        let mut committed = self.committed_seqs(active)?;
        loop {
            let seq = (0..=MAX_SEQ)
                .find(|seq| !committed.contains(seq))
                .ok_or(Failure::Limit)?;
            observation.seq = seq;
            observation.validate()?;
            let bytes = observation.out().encode()?;
            require(bytes.len() as u64 <= RECORD_BYTES, Failure::Limit)?;
            let prepared = store::prepare(
                &self.observations,
                temporary(&seq.to_string())?,
                &bytes,
                active,
            )?;
            let name = format!("{seq}.json");
            if store::publish_new(&self.observations, prepared, &name, active)?.is_some() {
                store::sync_parent(&self.observations, active)?;
                return Ok(observation);
            }
            let next = self.committed_seqs(active)?;
            require(next.contains(&seq), Failure::Storage)?;
            committed = next;
        }
    }

    fn committed_seqs(&self, active: &Active) -> Result<BTreeSet<u64>> {
        let mut seqs = BTreeSet::new();
        for name in store::scan(
            &self.observations,
            |name| observation_seq(name).is_some(),
            active,
        )? {
            if let Some(seq) = observation_seq(&name) {
                seqs.insert(seq);
            }
        }
        Ok(seqs)
    }

    pub(crate) fn observations(
        &self,
        active: &Active,
    ) -> std::result::Result<Vec<Observation>, ReadFailure> {
        let names = store::scan(
            &self.observations,
            |name| observation_seq(name).is_some(),
            active,
        )
        .map_err(ReadFailure::Invalid)?;
        let mut observations = Vec::new();
        for name in names {
            let read = store::read(&self.observations, &name, RECORD_BYTES, active)
                .map_err(ReadFailure::Invalid)?;
            let (bytes, _) = read.ok_or(ReadFailure::Invalid(Failure::Storage))?;
            let observation = decode_observation(&bytes)?;
            let seq = observation_seq(&name).ok_or(ReadFailure::Invalid(Failure::Integrity))?;
            if observation.seq != seq || observation.operation_id != self.operation_id {
                return Err(ReadFailure::Invalid(Failure::Integrity));
            }
            observations.push(observation);
        }
        observations.sort_by(|a, b| (&a.observed_at, a.seq).cmp(&(&b.observed_at, b.seq)));
        Ok(observations)
    }

    pub(crate) fn settlements(
        &self,
        active: &Active,
    ) -> std::result::Result<Vec<Settlement>, ReadFailure> {
        let Some(directory) =
            store::existing_child_directory(&self.directory, "settlements", active)
                .map_err(ReadFailure::Invalid)?
        else {
            return Ok(Vec::new());
        };
        let names = store::scan(&directory, |name| observation_seq(name).is_some(), active)
            .map_err(ReadFailure::Invalid)?;
        let mut settlements = Vec::new();
        for name in names {
            let read = store::read(&directory, &name, RECORD_BYTES, active)
                .map_err(ReadFailure::Invalid)?;
            let (bytes, _) = read.ok_or(ReadFailure::Invalid(Failure::Storage))?;
            let settlement = Settlement::decode(&bytes)?;
            let seq = observation_seq(&name).ok_or(ReadFailure::Invalid(Failure::Integrity))?;
            if settlement.ambiguous_seq != seq {
                return Err(ReadFailure::Invalid(Failure::Integrity));
            }
            settlements.push(settlement);
        }
        settlements.sort_by_key(|settlement| settlement.ambiguous_seq);
        Ok(settlements)
    }

    pub(crate) fn publish_settlement(
        &self,
        settlement: &Settlement,
        active: &Active,
    ) -> Result<Option<()>> {
        require(
            valid_artifact(&settlement.artifact_id)
                && valid_operation(&settlement.retention_operation_id)
                && settlement.ambiguous_seq <= MAX_SEQ,
            Failure::Policy,
        )?;
        let bytes = settlement.out().encode()?;
        let directory = store::child_directory(&self.directory, "settlements", true, active)?;
        let prepared = store::prepare(
            &directory,
            temporary(&settlement.ambiguous_seq.to_string())?,
            &bytes,
            active,
        )?;
        let name = format!("{}.json", settlement.ambiguous_seq);
        if store::publish_new(&directory, prepared, &name, active)?.is_some() {
            store::sync_parent(&directory, active)?;
            return Ok(Some(()));
        }
        Ok(None)
    }

    pub(crate) fn settlement(
        &self,
        ambiguous_seq: u64,
        active: &Active,
    ) -> std::result::Result<Option<Settlement>, ReadFailure> {
        let name = format!("{ambiguous_seq}.json");
        let Some(directory) =
            store::existing_child_directory(&self.directory, "settlements", active)
                .map_err(ReadFailure::Invalid)?
        else {
            return Ok(None);
        };
        let read =
            store::read(&directory, &name, RECORD_BYTES, active).map_err(ReadFailure::Invalid)?;
        match read {
            Some((bytes, _)) => Ok(Some(Settlement::decode(&bytes)?)),
            None => Ok(None),
        }
    }
}

pub(super) fn temporary(stem: &str) -> Result<String> {
    Ok(format!(
        "{stem}.{}.partial",
        sudo_nonce().map_err(|_| Failure::Storage)?
    ))
}

pub(crate) fn decode_operation(bytes: &[u8]) -> std::result::Result<OperationRecord, ReadFailure> {
    let value =
        Value::parse_bounded(bytes, RECORD_BYTES as usize, 64).map_err(ReadFailure::Invalid)?;
    supported(value)?;
    fn inner(value: Value<'_>) -> Result<OperationRecord> {
        let slots = optional_fields(
            value,
            &[
                "format_version",
                "operation_id",
                "kind",
                "origin",
                "started_at",
                "request",
                "tools",
                "preceding_operation_id",
                "retry_reason",
            ],
        )?;
        let get = |i: usize| slots[i].ok_or(Failure::Protocol);
        let record = OperationRecord {
            operation_id: text(get(1)?)?,
            kind: text(get(2)?)?,
            origin: text(get(3)?)?,
            started_at: text(get(4)?)?,
            request: Out::Raw(get(5)?.raw().to_vec()),
            tools: super::decode_tools(get(6)?)?,
            preceding_operation_id: slots[7].map(text).transpose()?,
            retry_reason: slots[8].map(text).transpose()?,
        };
        require(valid_operation(&record.operation_id), Failure::Protocol)?;
        require(valid_time(&record.started_at), Failure::Protocol)?;
        require(
            record.preceding_operation_id.is_some() == record.retry_reason.is_some(),
            Failure::Protocol,
        )?;
        Ok(record)
    }
    inner(value).map_err(ReadFailure::Invalid)
}
