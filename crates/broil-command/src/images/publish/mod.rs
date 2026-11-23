// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod layout;
mod receipt;

use super::{Kept, StageError, VerifiedOutput, common::*, solve::SessionObservation};
use broil_config::images::select::EffectiveImage;
use broil_core::images::OutputKind;
use std::path::PathBuf;

pub use layout::RetainedArtifact;
pub(crate) use layout::{Member, PublishWork, UnpackWork, header};
pub(crate) use receipt::{Binding, Planned, plan_retained, resolve, retained_chain, server};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationClass {
    Failed(Failure),
    Publication,
}

impl PublicationClass {
    pub fn of(failure: Failure) -> Self {
        Self::Failed(failure)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Publication => "publication",
            Self::Failed(Failure::Policy) => "policy",
            Self::Failed(Failure::Credential) => "credential",
            Self::Failed(Failure::Authentication) => "authentication",
            Self::Failed(Failure::Trust) => "trust",
            Self::Failed(Failure::CacheMiss) => "cache-miss",
            Self::Failed(Failure::Protocol) => "protocol",
            Self::Failed(Failure::Integrity) => "integrity",
            Self::Failed(Failure::Storage) => "storage",
            Self::Failed(Failure::Limit) => "limit",
            Self::Failed(Failure::Timeout) => "timeout",
            Self::Failed(Failure::Cancellation) => "cancellation",
            Self::Failed(Failure::Capacity) => "capacity",
            Self::Failed(Failure::Tool) => "tool",
            Self::Failed(Failure::Indeterminate) => "indeterminate",
        }
    }

    pub fn failure(self) -> Option<Failure> {
        match self {
            Self::Failed(failure) => Some(failure),
            Self::Publication => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationCheck {
    Layout,
    Request,
    Transfer,
    Association,
    Closure,
}

impl PublicationCheck {
    pub fn name(self) -> &'static str {
        match self {
            Self::Layout => "layout",
            Self::Request => "request",
            Self::Transfer => "transfer",
            Self::Association => "association",
            Self::Closure => "closure",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotPublished {
    SolveStopped,
    Stopped,
    Stale,
    Cancelled,
}

impl NotPublished {
    pub fn name(self) -> &'static str {
        match self {
            Self::SolveStopped => "solve-stopped",
            Self::Stopped => "stopped",
            Self::Stale => "stale",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerIdentity {
    pub authority: String,
    pub transport: &'static str,
    pub authentication: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureMember {
    pub descriptor: Descriptor,
    pub role: &'static str,
    pub local: &'static str,
    pub endpoint: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagAssociation {
    pub tag: String,
    pub root: Descriptor,
}

#[derive(Clone, Debug)]
pub struct PublicationObservation {
    pub artifact_id: Option<String>,
    pub root: Descriptor,
    pub endpoint: String,
    pub server: ServerIdentity,
    pub repository: String,
    pub association: Descriptor,
    pub closure: Vec<ClosureMember>,
    pub tag: Option<TagAssociation>,
    pub observed_ns: u64,
    pub observed_at: String,
    pub method: &'static str,
    pub operation_id: String,
    pub auxiliary: Vec<Descriptor>,
    pub predicate: &'static str,
}

#[derive(Clone, Debug)]
pub struct Unproved {
    pub class: PublicationClass,
    pub check: Option<PublicationCheck>,
    pub endpoint: String,
    pub server: ServerIdentity,
    pub repository: String,
    pub expected_root: Descriptor,
    pub tag: Option<String>,
    pub completion_uncertain: bool,
    pub cleanup_uncertain: bool,
    pub recovery: &'static str,
    pub local_content: &'static str,
}

#[derive(Clone, Debug)]
pub enum PublicationOutcome {
    Published(Box<PublicationObservation>),
    Failed {
        class: PublicationClass,
        check: Option<PublicationCheck>,
    },
    Unknown(Box<Unproved>),
    Cancelled,
    NotPublished(NotPublished),
}

impl PublicationOutcome {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Published(_) => "published",
            Self::Failed { .. } => "failed",
            Self::Unknown(_) => "unknown",
            Self::Cancelled => "cancelled",
            Self::NotPublished(_) => "not-published",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Residue {
    pub entry: Entry,
    pub root: Descriptor,
    pub reason: &'static str,
}

#[derive(Clone, Debug)]
pub enum PublicationRelease {
    None,
    Released,
    Refused {
        class: Failure,
        residue: Box<Residue>,
    },
    Withheld {
        residue: Box<Residue>,
    },
    Failed {
        class: Failure,
        residue: Box<Residue>,
    },
}

impl PublicationRelease {
    pub fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Released => "released",
            Self::Refused { .. } => "refused",
            Self::Withheld { .. } => "withheld",
            Self::Failed { .. } => "failed",
        }
    }

    pub fn residue(&self) -> Option<&Residue> {
        match self {
            Self::None | Self::Released => None,
            Self::Refused { residue, .. }
            | Self::Withheld { residue }
            | Self::Failed { residue, .. } => Some(residue),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagingDelta {
    pub operation: &'static str,
    pub operation_id: String,
    pub counted_bytes: u64,
    pub allowance_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct StandaloneSource {
    pub location: PathBuf,
    pub kind: &'static str,
    pub root: Descriptor,
    pub verification: &'static str,
    pub verified_files: u64,
    pub verified_bytes: u64,
    pub alternative: &'static str,
}

#[derive(Clone, Debug)]
pub struct PublicationReport {
    pub target: String,
    pub outcome: PublicationOutcome,
    pub release: PublicationRelease,
    pub layout: Option<(Entry, Descriptor)>,
    pub tag: Option<TagAssociation>,
    pub staging: Vec<StagingDelta>,
    pub sessions: Vec<SessionObservation>,
    pub source: Option<Box<StandaloneSource>>,
    pub recovery: &'static str,
}

impl PublicationReport {
    pub(crate) fn new(target: &str, outcome: PublicationOutcome) -> Self {
        Self {
            target: target.into(),
            outcome,
            release: PublicationRelease::None,
            layout: None,
            tag: None,
            staging: Vec::new(),
            sessions: Vec::new(),
            source: None,
            recovery: "none",
        }
    }

    pub fn succeeded(&self) -> bool {
        matches!(self.outcome, PublicationOutcome::Published(_))
    }

    pub(crate) fn cancelled(&self) -> bool {
        matches!(
            self.outcome,
            PublicationOutcome::Cancelled
                | PublicationOutcome::NotPublished(NotPublished::Cancelled)
                | PublicationOutcome::Failed {
                    class: PublicationClass::Failed(Failure::Cancellation),
                    ..
                }
        )
    }
}

pub(crate) struct UploadRequest<'a> {
    pub(crate) input: Entry,
    pub(crate) expected_root: Descriptor,
    pub(crate) inspect: Option<Descriptor>,
    pub(crate) planned: &'a Planned,
}

pub(crate) struct UploadResult {
    pub(crate) outcome: PublicationOutcome,
    pub(crate) session: Option<SessionObservation>,
    pub(crate) staging: Option<StagingDelta>,
    pub(crate) tag: Option<TagAssociation>,
    pub(crate) resolved: bool,
}

pub(crate) trait PublishDriver {
    fn cancelled(&self) -> bool;
    fn open_layout(&mut self) -> std::result::Result<(), StageError>;
    fn layout_operation(&self) -> Option<(String, Entry)>;
    fn allowance(&self) -> u64;
    fn limits(&self) -> ContentLimits;
    fn recheck(&mut self, output: &VerifiedOutput) -> std::result::Result<(), StageError>;
    fn chain(
        &mut self,
        output: &VerifiedOutput,
        platform: &str,
    ) -> std::result::Result<(Descriptor, Vec<Descriptor>), StageError>;
    fn retained_closure(
        &mut self,
        entry: &Entry,
        root: &Descriptor,
        manifests: &[(String, Descriptor)],
    ) -> std::result::Result<Vec<(Descriptor, Vec<Descriptor>)>, StageError>;
    fn layout(
        &mut self,
        work: PublishWork,
        root: &Descriptor,
    ) -> std::result::Result<(Entry, u64, u64), StageError>;
    fn unpack(
        &mut self,
        work: UnpackWork,
        root: &Descriptor,
    ) -> std::result::Result<(Entry, u64, u64), StageError>;
    fn close_layout(
        &mut self,
        layout: Option<&Entry>,
    ) -> (Option<Kept>, Option<SessionObservation>);
    fn upload(&mut self, request: &UploadRequest<'_>) -> UploadResult;
    fn release(&mut self, kept: Kept) -> std::result::Result<(), (Option<Kept>, Failure)>;
}

pub(crate) enum PublishInput<'a> {
    Target {
        target: &'a str,
        image: &'a EffectiveImage,
        nodes: &'a [(String, VerifiedOutput)],
    },
    Standalone {
        target: &'a str,
        artifact: &'a RetainedArtifact,
    },
}

impl PublishInput<'_> {
    pub(crate) fn target(&self) -> &str {
        match self {
            Self::Target { target, .. } | Self::Standalone { target, .. } => target,
        }
    }
}

fn unverified(artifact: &RetainedArtifact, verification: &'static str) -> Box<StandaloneSource> {
    Box::new(StandaloneSource {
        location: artifact.location.clone(),
        kind: super::outputs::kind_name(artifact.kind),
        root: artifact.root.clone(),
        verification,
        verified_files: 0,
        verified_bytes: 0,
        alternative: "new-build-required",
    })
}

fn residue(entry: &Entry, root: &Descriptor, reason: &'static str) -> Box<Residue> {
    Box::new(Residue {
        entry: entry.clone(),
        root: root.clone(),
        reason,
    })
}

pub(crate) fn publication_stage<D: PublishDriver>(
    mut driver: D,
    input: &PublishInput<'_>,
) -> (PublicationReport, Option<Kept>) {
    let mut report = PublicationReport::new(
        input.target(),
        PublicationOutcome::Failed {
            class: PublicationClass::of(Failure::Indeterminate),
            check: None,
        },
    );
    report.recovery = match input {
        PublishInput::Standalone { .. } => "republish-from-retained-identity",
        PublishInput::Target { .. } => "read-only-observation",
    };
    let kept = run_stage(&mut driver, input, &mut report);
    (report, kept)
}

fn run_stage<D: PublishDriver>(
    driver: &mut D,
    input: &PublishInput<'_>,
    report: &mut PublicationReport,
) -> Option<Kept> {
    if driver.cancelled() {
        report.outcome = PublicationOutcome::NotPublished(NotPublished::Cancelled);
        return None;
    }
    if let PublishInput::Standalone { artifact, .. } = input {
        if artifact.kind == OutputKind::OciLayout {
            return standalone_layout(driver, artifact, report);
        }
    }
    if let Err(error) = driver.open_layout() {
        report.outcome = if error.failure == Failure::Cancellation {
            PublicationOutcome::Cancelled
        } else {
            PublicationOutcome::Failed {
                class: PublicationClass::of(error.failure),
                check: None,
            }
        };
        return None;
    }
    let Some((operation_id, workspace)) = driver.layout_operation() else {
        report.outcome = PublicationOutcome::Failed {
            class: PublicationClass::of(Failure::Indeterminate),
            check: None,
        };
        return None;
    };
    let built = plan_and_build(driver, input, &workspace, &operation_id, report);
    let Ok((planned, layout, files, bytes)) = built else {
        let (_, session) = driver.close_layout(None);
        if let Some(session) = session {
            report.sessions.push(session);
        }
        return None;
    };
    report.layout = Some((layout.clone(), planned.root.clone()));
    if let PublishInput::Standalone { artifact, .. } = input {
        report.source = Some(Box::new(StandaloneSource {
            location: artifact.location.clone(),
            kind: super::outputs::kind_name(artifact.kind),
            root: artifact.root.clone(),
            verification: "verify-staged",
            verified_files: files,
            verified_bytes: bytes,
            alternative: "none",
        }));
    }
    let (kept, session) = driver.close_layout(Some(&layout));
    if let Some(session) = session {
        report.sessions.push(session);
    }
    let Some(kept) = kept else {
        report.outcome = PublicationOutcome::Failed {
            class: PublicationClass::of(Failure::Indeterminate),
            check: Some(PublicationCheck::Layout),
        };
        return None;
    };
    let mut retained = layout.clone();
    retained.ownership = Ownership::Retained;
    report.layout = Some((retained.clone(), planned.root.clone()));
    let result = driver.upload(&UploadRequest {
        input: retained.clone(),
        expected_root: planned.root.clone(),
        inspect: None,
        planned: &planned,
    });
    finish(driver, result, &retained, &planned.root, report, Some(kept))
}

fn standalone_layout<D: PublishDriver>(
    driver: &mut D,
    artifact: &RetainedArtifact,
    report: &mut PublicationReport,
) -> Option<Kept> {
    let bound = (|| {
        let (_, entry) = super::files::open_path(&artifact.location, Ownership::Retained, false)?;
        require(entry.kind == Kind::Directory, Failure::Policy)?;
        Ok(entry)
    })();
    let planned = bound.and_then(|entry| {
        let chains = driver
            .retained_closure(&entry, &artifact.root, &artifact.manifests)
            .map_err(|error| error.failure)?;
        let planned = plan_retained(&artifact.root, &artifact.manifests, &chains)?;
        Ok((planned, entry))
    });
    let (planned, input) = match planned {
        Ok(bound) => bound,
        Err(failure) => {
            let mut source = unverified(artifact, "unverified");
            if !matches!(
                failure,
                Failure::Integrity | Failure::Policy | Failure::Storage
            ) {
                source.alternative = "none";
            }
            report.source = Some(source);
            report.outcome = if failure == Failure::Cancellation {
                PublicationOutcome::Cancelled
            } else {
                PublicationOutcome::Failed {
                    class: PublicationClass::of(failure),
                    check: Some(PublicationCheck::Request),
                }
            };
            return None;
        }
    };
    report.source = Some(Box::new(StandaloneSource {
        location: artifact.location.clone(),
        kind: "oci-layout",
        root: artifact.root.clone(),
        verification: "inspect-prepared",
        verified_files: artifact.verified_files,
        verified_bytes: artifact.verified_bytes,
        alternative: "none",
    }));
    let result = driver.upload(&UploadRequest {
        input: input.clone(),
        expected_root: artifact.root.clone(),
        inspect: Some(artifact.root.clone()),
        planned: &planned,
    });
    finish(driver, result, &input, &artifact.root, report, None)
}

fn plan_and_build<D: PublishDriver>(
    driver: &mut D,
    input: &PublishInput<'_>,
    workspace: &Entry,
    operation_id: &str,
    report: &mut PublicationReport,
) -> std::result::Result<(Planned, Entry, u64, u64), ()> {
    let limits = driver.limits();
    let allowance = driver.allowance();
    let planned = match input {
        PublishInput::Target { image, nodes, .. } => {
            let planned = (|| {
                let mut chains = Vec::new();
                for (platform, output) in *nodes {
                    driver.recheck(output)?;
                    let (config, layers) = driver.chain(output, platform)?;
                    chains.push(super::outputs::NodeChain {
                        platform: platform.clone(),
                        output: output.clone(),
                        config,
                        layers,
                    });
                }
                receipt::plan_target(&chains, &image.declaration.image, &limits)
                    .map_err(stage_error)
            })();
            Some(planned.map_err(|error| layout_failure(error, input, report))?)
        }
        PublishInput::Standalone { .. } => None,
    };
    report.staging.push(StagingDelta {
        operation: "layout",
        operation_id: operation_id.into(),
        counted_bytes: match (&planned, input) {
            (Some(planned), _) => planned.content_bytes,
            (None, PublishInput::Standalone { artifact, .. }) => artifact.verified_bytes,
            (None, _) => 0,
        },
        allowance_bytes: allowance,
    });
    let built = match (&planned, input) {
        (Some(planned), _) => PublishWork::new(workspace.clone(), planned, allowance, &limits)
            .map_err(stage_error)
            .and_then(|work| driver.layout(work, &planned.root)),
        (None, PublishInput::Standalone { artifact, .. }) => {
            UnpackWork::new(workspace.clone(), (*artifact).clone(), allowance, &limits)
                .map_err(stage_error)
                .and_then(|work| driver.unpack(work, &artifact.root))
        }
        (None, _) => Err(stage_error(Failure::Indeterminate)),
    };
    let (layout, files, bytes) = built.map_err(|error| layout_failure(error, input, report))?;
    let planned = match (planned, input) {
        (Some(planned), _) => planned,
        (None, PublishInput::Standalone { artifact, .. }) => {
            let read = (|| {
                let chains =
                    driver.retained_closure(&layout, &artifact.root, &artifact.manifests)?;
                plan_retained(&artifact.root, &artifact.manifests, &chains).map_err(stage_error)
            })();
            read.map_err(|error| layout_failure(error, input, report))?
        }
        (None, _) => {
            layout_failure(stage_error(Failure::Indeterminate), input, report);
            return Err(());
        }
    };
    Ok((planned, layout, files, bytes))
}

fn stage_error(failure: Failure) -> StageError {
    StageError {
        failure,
        observation: super::Observation::new(monotonic_ns()),
    }
}

fn layout_failure(error: StageError, input: &PublishInput<'_>, report: &mut PublicationReport) {
    report.outcome = if error.failure == Failure::Cancellation {
        PublicationOutcome::Cancelled
    } else {
        PublicationOutcome::Failed {
            class: PublicationClass::of(error.failure),
            check: Some(PublicationCheck::Layout),
        }
    };
    if let PublishInput::Standalone { artifact, .. } = input {
        report.source = Some(unverified(artifact, "unverified"));
    }
}

fn finish<D: PublishDriver>(
    driver: &mut D,
    result: UploadResult,
    layout: &Entry,
    root: &Descriptor,
    report: &mut PublicationReport,
    kept: Option<Kept>,
) -> Option<Kept> {
    report.outcome = result.outcome;
    if report.layout.is_none() {
        if let (Some(source), PublicationOutcome::Failed { class, .. }) =
            (&mut report.source, &report.outcome)
        {
            if matches!(
                class.failure(),
                Some(Failure::Integrity | Failure::Policy | Failure::Storage)
            ) {
                source.verification = "unverified";
                source.alternative = "new-build-required";
            }
        }
    }
    report.tag = result.tag;
    if let Some(session) = result.session {
        report.sessions.push(session);
    }
    if let Some(delta) = result.staging {
        report.staging.push(delta);
    }
    let kept = kept?;
    if !result.resolved {
        report.release = PublicationRelease::Withheld {
            residue: residue(layout, root, "unresolved-ownership"),
        };
        if let PublicationOutcome::Unknown(unproved) = &mut report.outcome {
            unproved.local_content = "retained";
        }
        return Some(kept);
    }
    match driver.release(kept) {
        Ok(()) => {
            report.release = PublicationRelease::Released;
            if let PublicationOutcome::Unknown(unproved) = &mut report.outcome {
                unproved.local_content = "released";
            }
            None
        }
        Err((Some(kept), class)) => {
            report.release = PublicationRelease::Refused {
                class,
                residue: residue(layout, root, "token-returned"),
            };
            if let PublicationOutcome::Unknown(unproved) = &mut report.outcome {
                unproved.local_content = "retained";
            }
            Some(kept)
        }
        Err((None, class)) => {
            report.release = PublicationRelease::Failed {
                class,
                residue: residue(layout, root, "token-consumed"),
            };
            if let PublicationOutcome::Unknown(unproved) = &mut report.outcome {
                unproved.local_content = "retained";
            }
            None
        }
    }
}

