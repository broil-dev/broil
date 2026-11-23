// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod assemble;
mod retain;

use super::{StageError, VerifiedOutput, common::*, solve::SessionObservation};
use broil_config::images::select::EffectiveImage;
use broil_core::images::OutputKind;
use std::path::{Path, PathBuf};

pub(crate) use assemble::{AssembleWork, Assembly, NodeChain, OCI_LAYOUT, Source, plan};
pub(crate) use retain::{ArchiveWork, RetainWork, Unit, docker_manifest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputCheck {
    Destination,
    Assembly,
    Retention,
    Load,
    Identity,
}

impl OutputCheck {
    pub fn name(self) -> &'static str {
        match self {
            Self::Destination => "destination",
            Self::Assembly => "assembly",
            Self::Retention => "retention",
            Self::Load => "load",
            Self::Identity => "identity",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotExported {
    SolveStopped,
    Stale,
    Stopped,
    Cancelled,
}

impl NotExported {
    pub fn name(self) -> &'static str {
        match self {
            Self::SolveStopped => "solve-stopped",
            Self::Stale => "stale",
            Self::Stopped => "stopped",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Retained {
    pub owner: &'static str,
    pub location: PathBuf,
    pub kind: &'static str,
    pub root: Descriptor,
    pub manifests: Vec<(String, Descriptor)>,
    pub verified_files: u64,
    pub verified_bytes: u64,
    pub archive: Option<(String, u64)>,
    pub verification: &'static str,
    pub verified_ns: u64,
    pub verified_at: String,
    pub cleanup: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Loaded {
    pub socket: PathBuf,
    pub store: &'static str,
    pub image_id: String,
    pub reference: String,
    pub platform: String,
}

#[derive(Clone, Debug)]
pub struct Unpublished {
    pub platform: String,
    pub entry: Entry,
    pub root: Descriptor,
}

#[derive(Clone, Debug)]
pub enum Handoff {
    Nodes(Vec<Unpublished>),
    Consumed { nodes: u64 },
}

impl Handoff {
    pub fn nodes(&self) -> &[Unpublished] {
        match self {
            Self::Nodes(nodes) => nodes,
            Self::Consumed { .. } => &[],
        }
    }

    pub fn count(&self) -> u64 {
        match self {
            Self::Nodes(nodes) => nodes.len() as u64,
            Self::Consumed { nodes } => *nodes,
        }
    }
}

#[derive(Clone, Debug)]
pub enum TargetOutcome {
    Retained(Box<Retained>),
    Loaded(Box<Loaded>),
    CacheOnly,
    Unpublished(Handoff),
    Failed {
        class: Failure,
        check: Option<OutputCheck>,
        published: Option<PathBuf>,
    },
    NotExported(NotExported),
}

#[derive(Clone, Debug)]
pub struct TargetReport {
    pub target: String,
    pub kind: &'static str,
    pub outcome: TargetOutcome,
    pub session: Option<SessionObservation>,
    pub residue: Option<PathBuf>,
    pub provenance: &'static str,
    pub provenance_reason: &'static str,
}

impl TargetReport {
    pub(crate) fn new(target: &str, kind: OutputKind, outcome: TargetOutcome) -> Self {
        Self {
            target: target.into(),
            kind: kind_name(kind),
            outcome,
            session: None,
            residue: None,
            provenance: "unavailable",
            provenance_reason: "attestations-disabled",
        }
    }

    pub fn succeeded(&self) -> bool {
        matches!(
            self.outcome,
            TargetOutcome::Retained(_)
                | TargetOutcome::Loaded(_)
                | TargetOutcome::CacheOnly
                | TargetOutcome::Unpublished(_)
        )
    }

    pub(crate) fn cancelled(&self) -> bool {
        matches!(
            self.outcome,
            TargetOutcome::Failed {
                class: Failure::Cancellation,
                ..
            } | TargetOutcome::NotExported(NotExported::Cancelled)
        )
    }
}

pub(crate) fn kind_name(kind: OutputKind) -> &'static str {
    match kind {
        OutputKind::Registry => "registry",
        OutputKind::OciArchive => "oci-archive",
        OutputKind::OciLayout => "oci-layout",
        OutputKind::DockerLoad => "docker-load",
        OutputKind::CacheOnly => "cache-only",
    }
}

pub(crate) fn effective_platforms(
    image: &EffectiveImage,
    subset: Option<&[String]>,
) -> Vec<String> {
    image
        .platforms
        .iter()
        .filter(|p| subset.is_none_or(|s| s.contains(p)))
        .cloned()
        .collect()
}

pub(crate) struct Matrix<'a> {
    pub(crate) targets: &'a [(String, EffectiveImage)],
    pub(crate) platforms: Option<&'a [String]>,
    pub(crate) docker_daemon: Option<&'a Path>,
    pub(crate) docker_tool: bool,
    pub(crate) lease_parent: &'a Path,
    pub(crate) workspace_parent: &'a Path,
}

pub(crate) fn matrix(request: &Matrix<'_>) -> Result<()> {
    let overlapping = |a: &Path, b: &Path| a.starts_with(b) || b.starts_with(a);
    let mut loads = 0;
    let mut destinations: Vec<&Path> = Vec::new();
    for (_, image) in request.targets {
        let platforms = effective_platforms(image, request.platforms);
        let output = &image.declaration.image;
        match image.output_kind {
            OutputKind::DockerLoad => {
                loads += 1;
                require(
                    platforms.len() == 1
                        && output.effective_tag().is_some()
                        && request.docker_daemon.is_some()
                        && request.docker_tool,
                    Failure::Policy,
                )?;
            }
            OutputKind::OciLayout | OutputKind::OciArchive => {
                let destination = image.output_path.as_deref().ok_or(Failure::Policy)?;
                require(
                    valid_path(destination)
                        && !overlapping(destination, request.lease_parent)
                        && !overlapping(destination, request.workspace_parent)
                        && destinations
                            .iter()
                            .all(|other| !overlapping(destination, other)),
                    Failure::Policy,
                )?;
                destinations.push(destination);
            }
            OutputKind::Registry | OutputKind::CacheOnly => {}
        }
        require(
            output.digest.is_none() || platforms.len() <= 1,
            Failure::Policy,
        )?;
    }
    require(
        request
            .docker_daemon
            .is_none_or(|path| loads > 0 && valid_path(path)),
        Failure::Policy,
    )?;
    for (_, image) in request.targets {
        require(
            effective_platforms(image, request.platforms).len() <= 64,
            Failure::Limit,
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Inspected {
    pub(crate) id: String,
    pub(crate) os: String,
    pub(crate) architecture: String,
    pub(crate) variant: String,
}

pub(crate) trait OutputDriver {
    fn cancelled(&self) -> bool;
    fn select(&mut self, target: &str) -> Result<(String, Option<EffectiveImage>)>;
    fn open(&mut self, docker: bool) -> std::result::Result<(), StageError>;
    fn operation(&self) -> Option<(String, Entry)>;
    fn daemon(&mut self, socket: &Path) -> std::result::Result<(), StageError>;
    fn recheck(&mut self, output: &VerifiedOutput) -> std::result::Result<(), StageError>;
    fn chain(
        &mut self,
        output: &VerifiedOutput,
        platform: &str,
    ) -> std::result::Result<(Descriptor, Vec<Descriptor>), StageError>;
    fn allowance(&self) -> u64;
    fn limits(&self) -> ContentLimits;
    fn assemble(
        &mut self,
        work: AssembleWork,
        root: &Descriptor,
    ) -> std::result::Result<Entry, StageError>;
    fn retain(
        &mut self,
        work: RetainWork,
    ) -> (Option<RetainWork>, std::result::Result<(), StageError>);
    fn inspect(
        &mut self,
        entry: &Entry,
        root: &Descriptor,
    ) -> std::result::Result<(u64, u64), StageError>;
    fn archive(
        &mut self,
        work: ArchiveWork,
    ) -> std::result::Result<(Entry, String, u64), StageError>;
    fn load(
        &mut self,
        archive: &Entry,
        digest: &str,
        size: u64,
        reference: &str,
    ) -> std::result::Result<(), StageError>;
    fn inspect_image(&mut self, reference: &str) -> std::result::Result<Inspected, StageError>;
    fn close(self) -> Option<SessionObservation>;
}

pub(crate) struct OutputInput<'a> {
    pub(crate) target: &'a str,
    pub(crate) image: &'a EffectiveImage,
    pub(crate) catalog_id: &'a str,
    pub(crate) platforms: &'a [String],
    pub(crate) nodes: &'a [(String, VerifiedOutput)],
    pub(crate) docker_daemon: Option<&'a Path>,
}

fn failed(class: Failure, check: Option<OutputCheck>) -> TargetOutcome {
    TargetOutcome::Failed {
        class,
        check,
        published: None,
    }
}

pub(crate) fn familiar(repository: &str) -> &str {
    let name = repository.strip_prefix("docker.io/").unwrap_or(repository);
    match name.strip_prefix("library/") {
        Some(rest) if repository.starts_with("docker.io/") && !rest.contains('/') => rest,
        _ => name,
    }
}

pub(crate) fn output_stage<D: OutputDriver>(
    mut driver: D,
    input: &OutputInput<'_>,
) -> TargetReport {
    let kind = input.image.output_kind;
    let mut report = TargetReport::new(input.target, kind, failed(Failure::Indeterminate, None));
    let (outcome, opened) = run_stage(&mut driver, input, &mut report);
    report.outcome = outcome;
    if opened {
        report.session = driver.close();
    }
    report
}

fn run_stage<D: OutputDriver>(
    driver: &mut D,
    input: &OutputInput<'_>,
    report: &mut TargetReport,
) -> (TargetOutcome, bool) {
    macro_rules! step {
        ($e:expr, $check:expr) => {
            match $e {
                Ok(value) => value,
                Err(error) => return (failed(error.failure, $check), true),
            }
        };
    }
    let kind = input.image.output_kind;
    match driver.select(input.target) {
        Ok((catalog_id, Some(image)))
            if catalog_id == input.catalog_id && image == *input.image => {}
        Ok(_) => return (TargetOutcome::NotExported(NotExported::Stale), false),
        Err(failure) => return (failed(failure, None), false),
    }
    if input.nodes.len() != input.platforms.len()
        || input
            .nodes
            .iter()
            .zip(input.platforms)
            .any(|((platform, output), expected)| platform != expected || !output.producer_image())
    {
        return (failed(Failure::Integrity, None), false);
    }
    match kind {
        OutputKind::CacheOnly => return (TargetOutcome::CacheOnly, false),
        OutputKind::Registry => {
            return (
                TargetOutcome::Unpublished(Handoff::Nodes(
                    input
                        .nodes
                        .iter()
                        .map(|(platform, output)| Unpublished {
                            platform: platform.clone(),
                            entry: output.retained().entry().clone(),
                            root: output.root().clone(),
                        })
                        .collect(),
                )),
                false,
            );
        }
        _ => {}
    }
    if driver.cancelled() {
        return (TargetOutcome::NotExported(NotExported::Cancelled), false);
    }
    let docker = kind == OutputKind::DockerLoad;
    if let Err(error) = driver.open(docker) {
        return (failed(error.failure, None), driver.operation().is_some());
    }
    let Some((operation, workspace)) = driver.operation() else {
        return (failed(Failure::Indeterminate, None), true);
    };
    if docker {
        let socket = match input.docker_daemon {
            Some(socket) => socket,
            None => return (failed(Failure::Policy, Some(OutputCheck::Load)), true),
        };
        step!(driver.daemon(socket), Some(OutputCheck::Load));
    }
    for (_, output) in input.nodes {
        step!(driver.recheck(output), Some(OutputCheck::Assembly));
    }
    let mut chains = Vec::new();
    for (platform, output) in input.nodes {
        let (config, layers) = step!(driver.chain(output, platform), Some(OutputCheck::Assembly));
        chains.push(NodeChain {
            platform: platform.clone(),
            output: output.clone(),
            config,
            layers,
        });
    }
    let reference = &input.image.declaration.image;
    let assembly = match plan(&chains, reference, &driver.limits()) {
        Ok(assembly) => assembly,
        Err(failure) => return (failed(failure, Some(OutputCheck::Assembly)), true),
    };
    let metadata = assembly
        .links
        .iter()
        .map(|(_, d)| d.size)
        .chain(assembly.index.iter().map(|b| b.len() as u64))
        .chain([
            assemble::OCI_LAYOUT.len() as u64,
            assembly.wrapper.len() as u64,
        ])
        .try_fold(0u64, u64::checked_add);
    if metadata.is_none_or(|bytes| bytes > driver.allowance()) {
        return (failed(Failure::Limit, Some(OutputCheck::Assembly)), true);
    }
    let work = step!(
        AssembleWork::new(workspace.clone(), &assembly).map_err(|failure| StageError {
            failure,
            observation: super::Observation::new(monotonic_ns()),
        }),
        Some(OutputCheck::Assembly)
    );
    let layout = step!(
        driver.assemble(work, &assembly.root),
        Some(OutputCheck::Assembly)
    );
    if driver.cancelled() {
        return (failed(Failure::Cancellation, None), true);
    }
    let outcome = match kind {
        OutputKind::OciLayout | OutputKind::OciArchive => retention(
            driver, input, &operation, &assembly, &layout, &chains, report,
        ),
        _ => load(driver, input, &workspace, &assembly, &layout, &chains),
    };
    (outcome, true)
}

#[allow(clippy::too_many_arguments)]
fn retention<D: OutputDriver>(
    driver: &mut D,
    input: &OutputInput<'_>,
    operation: &str,
    assembly: &Assembly,
    layout: &Entry,
    chains: &[NodeChain],
    report: &mut TargetReport,
) -> TargetOutcome {
    let unit = if input.image.output_kind == OutputKind::OciArchive {
        Unit::Archive
    } else {
        Unit::Layout
    };
    let Some(destination) = input.image.output_path.clone() else {
        return failed(Failure::Policy, Some(OutputCheck::Destination));
    };
    let work = match RetainWork::new(destination.clone(), unit, operation, assembly, layout) {
        Ok(work) => work,
        Err(failure) => return failed(failure, Some(OutputCheck::Destination)),
    };
    if work.total() > driver.allowance() {
        return failed(Failure::Limit, Some(OutputCheck::Destination));
    }
    let (work, result) = driver.retain(work);
    let Some(work) = work else {
        let class = result.err().map_or(Failure::Indeterminate, |e| e.failure);
        report.residue = Some(destination.with_file_name(format!(".broil-{}", &operation[10..])));
        return failed(class, Some(OutputCheck::Retention));
    };
    if work.residue {
        report.residue = Some(destination.with_file_name(format!(".broil-{}", &operation[10..])));
    }
    let published = match (&work.result, result) {
        (Some(published), Ok(())) => published.clone(),
        (_, result) => {
            let class = result.err().map_or(Failure::Indeterminate, |e| e.failure);
            return TargetOutcome::Failed {
                class,
                check: Some(work.check.unwrap_or(OutputCheck::Retention)),
                published: work.published.then(|| destination.clone()),
            };
        }
    };
    let manifests = chains
        .iter()
        .map(|c| (c.platform.clone(), c.output.root().clone()))
        .collect();
    let (verified_files, verified_bytes, archive, verification) = match &published.archive {
        Some((digest, size)) => (
            assembly.descriptors,
            assembly.content_bytes,
            Some((digest.clone(), *size)),
            "archive-reread",
        ),
        None => match driver.inspect(&published.entry, &assembly.root) {
            Ok((files, bytes)) => (files, bytes, None, "inspect-prepared"),
            Err(error) => {
                return TargetOutcome::Failed {
                    class: error.failure,
                    check: Some(OutputCheck::Retention),
                    published: Some(destination),
                };
            }
        },
    };
    TargetOutcome::Retained(Box::new(Retained {
        owner: "caller",
        location: destination,
        kind: kind_name(input.image.output_kind),
        root: assembly.root.clone(),
        manifests,
        verified_files,
        verified_bytes,
        archive,
        verification,
        verified_ns: monotonic_ns(),
        verified_at: super::records::now_utc(),
        cleanup: "none",
    }))
}

fn load<D: OutputDriver>(
    driver: &mut D,
    input: &OutputInput<'_>,
    workspace: &Entry,
    assembly: &Assembly,
    layout: &Entry,
    chains: &[NodeChain],
) -> TargetOutcome {
    let image = &input.image.declaration.image;
    let (Some(tag), [chain], Some(socket)) = (image.effective_tag(), chains, input.docker_daemon)
    else {
        return failed(Failure::Policy, Some(OutputCheck::Load));
    };
    let reference = format!("{}:{tag}", image.repository);
    let manifest = match docker_manifest(&chain.config, &reference, &chain.layers)
        .and_then(|manifest| ArchiveWork::new(workspace.clone(), assembly, manifest, layout))
    {
        Ok(work) => work,
        Err(failure) => return failed(failure, Some(OutputCheck::Load)),
    };
    if manifest.total() > driver.allowance() {
        return failed(Failure::Limit, Some(OutputCheck::Load));
    }
    let (archive, digest, size) = match driver.archive(manifest) {
        Ok(result) => result,
        Err(error) => return failed(error.failure, Some(OutputCheck::Load)),
    };
    if let Err(error) = driver.load(&archive, &digest, size, &reference) {
        return failed(error.failure, Some(OutputCheck::Load));
    }
    let inspected = match driver.inspect_image(&reference) {
        Ok(inspected) => inspected,
        Err(error) => return failed(error.failure, Some(OutputCheck::Identity)),
    };
    let parts: Vec<_> = chain.platform.split('/').collect();
    let store = if inspected.id == chain.config.digest {
        "classic"
    } else if inspected.id == chain.output.root().digest {
        "containerd"
    } else {
        return failed(Failure::Integrity, Some(OutputCheck::Identity));
    };
    if inspected.os != parts[0]
        || inspected.architecture != parts[1]
        || inspected.variant != parts.get(2).copied().unwrap_or("")
    {
        return failed(Failure::Integrity, Some(OutputCheck::Identity));
    }
    TargetOutcome::Loaded(Box::new(Loaded {
        socket: socket.to_path_buf(),
        store,
        image_id: inspected.id,
        reference,
        platform: chain.platform.clone(),
    }))
}

