// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::images::{
    Dispatch, Observation,
    outputs::{NotExported, TargetOutcome},
    publish::{NotPublished, PublicationOutcome, PublicationRelease},
    solve::{
        NodeOutcome, NotDispatched, ReadOutcome, ReleaseOutcome, SessionObservation, SolveReport,
        Stop, WriteOutcome,
    },
};
use std::collections::BTreeSet;

#[derive(Default)]
pub(super) struct Evidence {
    pub class: Option<FailureClass>,
    pub details: Vec<String>,
    sessions: BTreeSet<String>,
}

fn clean(o: &Observation) -> bool {
    o.failure.is_none()
        && o.dispatch == Dispatch::Observed
        && o.exit_code == Some(0)
        && o.signal.is_none()
        && !o.cancellation_requested
        && !o.completion_uncertain
        && !o.cleanup_uncertain
}

fn observed_class(o: &Observation) -> FailureClass {
    o.failure.map(FailureClass::of).unwrap_or_else(|| {
        if o.cancellation_requested {
            FailureClass::Cancellation
        } else if o.completion_uncertain || o.cleanup_uncertain {
            FailureClass::Indeterminate
        } else {
            FailureClass::of(Failure::Protocol)
        }
    })
}

impl Evidence {
    fn refuse(&mut self, class: FailureClass, detail: String) {
        self.class.get_or_insert(class);
        self.details.push(detail);
    }

    fn require(&mut self, present: bool, context: &str) {
        if !present {
            self.refuse(
                FailureClass::of(Failure::Protocol),
                format!("contract: {context}"),
            );
        }
    }

    fn session(&mut self, session: Option<&SessionObservation>, required: bool, role: &str) {
        let Some(s) = session else {
            self.require(!required, &format!("missing {role} session"));
            return;
        };
        let distinct = self.sessions.insert(s.operation_id.clone());
        self.require(
            distinct,
            &format!("duplicate {role} owner={}", s.operation_id),
        );
        let (o, failure) = match &s.cleanup {
            Ok(o) => (o, o.failure.map(FailureClass::of)),
            Err(error) => (&error.observation, Some(FailureClass::of(error.failure))),
        };
        let failure = failure
            .or_else(|| {
                o.cancellation_requested
                    .then_some(FailureClass::Cancellation)
            })
            .or_else(|| {
                (o.completion_uncertain || o.cleanup_uncertain || s.residue || s.unresolved_owner)
                    .then_some(FailureClass::Indeterminate)
            })
            .or_else(|| (!clean(o)).then_some(FailureClass::of(Failure::Protocol)));
        if let Some(class) = failure {
            self.refuse(
                class,
                format!(
                    "{role}: owner={}; failure={}; {}; residue={}; unresolved_owner={}",
                    s.operation_id,
                    class.name(),
                    render::observation(o),
                    s.residue,
                    s.unresolved_owner
                ),
            );
        }
    }
}

pub(super) fn readers(report: &SolveReport, explicit_platform: bool) -> Evidence {
    reader_evidence(report, explicit_platform, true)
}

fn reader_evidence(report: &SolveReport, explicit_platform: bool, successful: bool) -> Evidence {
    let mut evidence = Evidence::default();
    evidence.session(
        report.probe.as_ref(),
        successful && !explicit_platform,
        "probe",
    );
    evidence.require(
        !successful || report.re_entries.checked_add(1) == Some(report.graph_sessions.len() as u64),
        "graph session count",
    );
    for session in &report.graph_sessions {
        evidence.session(Some(session), true, "graph");
    }
    evidence.require(
        !successful
            || report.node_sessions
                == report.nodes.iter().filter(|n| n.session.is_some()).count() as u64,
        "node session count",
    );
    for node in &report.nodes {
        evidence.session(
            node.session.as_ref(),
            successful && matches!(node.outcome, NodeOutcome::Built(_)),
            "node",
        );
    }
    for read in report
        .nodes
        .iter()
        .filter_map(|n| n.cache.as_ref())
        .flat_map(|c| &c.reads)
    {
        let required = successful
            && matches!(
                read.outcome,
                ReadOutcome::Fetched | ReadOutcome::OptionalMiss
            );
        evidence.session(read.session.as_ref(), required, "cache-read");
        if required || read.session.is_some() {
            evidence.require(
                read.operation_id.is_some()
                    && read.operation_id.as_deref()
                        == read.session.as_ref().map(|s| s.operation_id.as_str()),
                "cache-read owner/session agreement",
            );
        }
        let failure = match read.release {
            ReleaseOutcome::Unreleased(failure) => {
                Some(failure.map_or(FailureClass::Indeterminate, FailureClass::of))
            }
            ReleaseOutcome::Failed(failure) => Some(FailureClass::of(failure)),
            _ => None,
        };
        if let Some(class) = failure {
            evidence.refuse(
                class,
                format!(
                    "cache-read release: owner={}; failure={}; no retry",
                    read.operation_id.as_deref().unwrap_or("unavailable"),
                    class.name()
                ),
            );
        }
    }
    for write in report
        .nodes
        .iter()
        .filter_map(|n| n.cache.as_ref()?.write.as_ref())
    {
        evidence.session(
            write.writer_session.as_ref(),
            successful && matches!(write.outcome, WriteOutcome::Written),
            "cache-write",
        );
        evidence.session(
            write.promotion_session.as_ref(),
            successful && matches!(write.promotion, Some(WriteOutcome::Promoted)),
            "cache-promotion",
        );
    }
    for target in &report.targets {
        evidence.session(
            target.session.as_ref(),
            successful
                && matches!(
                    target.outcome,
                    TargetOutcome::Retained(_) | TargetOutcome::Loaded(_)
                ),
            "output",
        );
        if let Some(path) = &target.residue {
            evidence.refuse(
                FailureClass::Indeterminate,
                format!("output residue={}", serde_json::json!(path)),
            );
        }
    }
    for publication in &report.publications {
        if let PublicationOutcome::Published(published) = &publication.outcome {
            evidence.require(
                publication.sessions.len() == 2 && publication.staging.len() == 2,
                "publication layout/upload sessions",
            );
            for (i, role) in ["layout", "upload"].iter().enumerate() {
                evidence.require(
                    publication
                        .staging
                        .get(i)
                        .zip(publication.sessions.get(i))
                        .is_some_and(|(delta, session)| {
                            delta.operation == *role && delta.operation_id == session.operation_id
                        }),
                    "publication owner/session agreement",
                );
            }
            evidence.require(
                publication
                    .sessions
                    .get(1)
                    .is_some_and(|s| s.operation_id == published.operation_id),
                "publication receipt owner",
            );
        }
        for session in &publication.sessions {
            evidence.session(Some(session), true, "publication");
        }
        let failure = match &publication.release {
            PublicationRelease::Failed { class, .. }
            | PublicationRelease::Refused { class, .. } => Some(FailureClass::of(*class)),
            PublicationRelease::Withheld { .. } => Some(FailureClass::Indeterminate),
            _ => None,
        };
        if let Some(class) = failure {
            evidence.refuse(
                class,
                format!(
                    "publication release: state={}; failure={}; residue={}; no retry",
                    publication.release.name(),
                    class.name(),
                    serde_json::json!(publication.release.residue().map(|r| &r.entry.path))
                ),
            );
        } else if publication.succeeded() {
            evidence.require(
                matches!(publication.release, PublicationRelease::Released),
                "published layout release",
            );
        }
    }
    evidence
}

fn inventory(
    report: &SolveReport,
    recorder: &records::Recorder,
    evidence: &mut Evidence,
) -> Vec<records::Acquisition> {
    let excluded: BTreeSet<&str> = report
        .nodes
        .iter()
        .filter_map(|n| n.cache.as_ref())
        .flat_map(|c| c.reads.iter().filter_map(|r| r.operation_id.as_deref()))
        .chain(report.publications.iter().flat_map(|p| {
            p.staging
                .iter()
                .filter(|d| d.operation == "layout")
                .map(|d| d.operation_id.as_str())
        }))
        .collect();
    let mut seen = BTreeSet::new();
    let mut acquisitions = Vec::new();
    for kept in &report.retained {
        let id = kept.token.operation_id();
        let acquisition = recorder.recorded(id);
        let graph_owner = report.graph_sessions.iter().any(|s| s.operation_id == id);
        let node = report
            .nodes
            .iter()
            .find(|n| n.session.as_ref().is_some_and(|s| s.operation_id == id));
        let matches = acquisition.is_some_and(|a| {
            a.outcome == records::Outcome::Succeeded
                && a.failure_class.is_none()
                && a.method == "session-result"
                && match a.role {
                    "graph-resolution" => {
                        graph_owner
                            && node.is_none()
                            && a.phase.is_none()
                            && a.dispatched.is_none()
                            && a.target.is_none()
                            && a.source == "graph-session"
                    }
                    "node-build" => {
                        !graph_owner
                            && node.is_some_and(|n| {
                                matches!(n.outcome, NodeOutcome::Built(_))
                                    && a.target.as_deref()
                                        == report
                                            .targets
                                            .iter()
                                            .find(|t| t.target == n.producer)
                                            .map(|t| t.target.as_str())
                            })
                            && a.phase == Some(records::NODE_BUILD_PHASE)
                            && a.dispatched == Some(true)
                            && a.source == "node-session"
                    }
                    _ => false,
                }
        });
        if excluded.contains(id) {
            evidence.refuse(
                FailureClass::Indeterminate,
                format!(
                    "unconsumed domain staging owner={id}; retained={}; no retry",
                    render::kept(kept)
                ),
            );
        } else if !seen.insert(id) || !matches {
            evidence.refuse(
                FailureClass::of(Failure::Protocol),
                format!(
                    "inconsistent staging acquisition: owner={id}; retained={}",
                    render::kept(kept)
                ),
            );
        } else if let Some(acquisition) = acquisition {
            acquisitions.push(acquisition.clone());
        }
    }
    acquisitions
}

pub(super) fn finish(
    invocation: &Invocation,
    policy: &Policy,
    cancellation: Cancellation,
    mut report: SolveReport,
    mut recorder: records::Recorder,
) -> Result<Output> {
    let domain_class = class(&report, &invocation.targets);
    let mut projection = render::build(&report);
    let mut evidence = if domain_class.is_none() {
        readers(&report, invocation.build_platform.is_some())
    } else {
        reader_evidence(&report, invocation.build_platform.is_some(), false)
    };
    let acquisitions = if domain_class.is_none() {
        inventory(&report, &recorder, &mut evidence)
    } else {
        Vec::new()
    };
    let mut retained = std::mem::take(&mut report.retained);
    drop(report);
    if domain_class.is_none() && evidence.class.is_none() {
        let mut remaining = Vec::new();
        let mut owners = retained.into_iter().zip(acquisitions);
        while let Some((kept, acquisition)) = owners.next() {
            let owner = kept.token.operation_id().to_owned();
            let paths: Vec<_> = kept.entries.iter().map(|e| e.path.clone()).collect();
            let (result, returned) = match consumers::release(policy, kept, cancellation.clone()) {
                Ok(observation) => (Ok(observation), None),
                Err(unreleased) => (Err(unreleased.error), unreleased.kept),
            };
            let returned_owner = returned.is_some();
            remaining.extend(returned);
            let (observation, failure) = match &result {
                Ok(o) => (o, (!clean(o)).then(|| observed_class(o))),
                Err(error) => (&error.observation, Some(FailureClass::of(error.failure))),
            };
            let released = result.is_ok() && clean(observation) && !returned_owner;
            if !released {
                let class = failure.unwrap_or(FailureClass::Indeterminate);
                evidence.refuse(class, format!("release: owner={owner}; failure={}; {}; retained_paths={}; returned_owner={returned_owner}", class.name(), render::observation(observation), serde_json::json!(paths)));
            }
            if let Err(failure) = recorder.staging_lifecycle(&owner, &acquisition, released) {
                evidence.refuse(
                    FailureClass::of(failure),
                    format!(
                        "release recording: owner={owner}; failure={}",
                        FailureClass::of(failure).name()
                    ),
                );
                remaining.extend(owners.map(|(kept, _)| kept));
                break;
            }
        }
        retained = remaining;
    }
    projection["retained"] =
        serde_json::json!(retained.iter().map(render::kept).collect::<Vec<_>>());
    let failure = domain_class.or(evidence.class);
    if failure.is_some() && !retained.is_empty() {
        evidence
            .details
            .push(format!("unconsumed staging={}", projection["retained"]));
    }
    output(
        invocation,
        projection,
        failure,
        (!evidence.details.is_empty())
            .then(|| format!("image build failed; {}", evidence.details.join("; "))),
    )
}

fn succeeded(report: &SolveReport, targets: &[String]) -> bool {
    matches!(report.stop, Stop::Success)
        && report.cache_complete
        && targets.iter().all(|name| {
            report
                .targets
                .iter()
                .find(|t| &t.target == name)
                .is_some_and(|target| {
                    if target.kind == "registry" {
                        report
                            .publications
                            .iter()
                            .any(|p| &p.target == name && p.succeeded())
                    } else {
                        target.succeeded()
                    }
                })
        })
}

pub(super) fn class(report: &SolveReport, targets: &[String]) -> Option<FailureClass> {
    if succeeded(report, targets) {
        return None;
    }
    match &report.stop {
        Stop::Cancelled => return Some(FailureClass::Cancellation),
        Stop::GraphRefused(error) | Stop::ProbeFailed(error) => {
            return Some(FailureClass::of(error.failure));
        }
        Stop::Stale(_) => return Some(FailureClass::SourceDrift),
        Stop::Bound => return Some(FailureClass::of(Failure::Limit)),
        _ => {}
    }
    for name in targets {
        if let Some(target) = report.targets.iter().find(|t| &t.target == name) {
            match target.outcome {
                TargetOutcome::Failed { class, .. } => return Some(FailureClass::of(class)),
                TargetOutcome::NotExported(NotExported::Stale) => {
                    return Some(FailureClass::SourceDrift);
                }
                TargetOutcome::NotExported(NotExported::Cancelled) => {
                    return Some(FailureClass::Cancellation);
                }
                _ => {}
            }
        }
    }
    for name in targets {
        if let Some(publication) = report.publications.iter().find(|p| &p.target == name) {
            if !matches!(
                publication.outcome,
                PublicationOutcome::NotPublished(
                    NotPublished::SolveStopped | NotPublished::Stopped
                )
            ) {
                if let Some(class) = publish::class(&publication.outcome) {
                    return Some(class);
                }
            }
        }
    }
    for node in &report.nodes {
        match node.outcome {
            NodeOutcome::Failed { class, .. } => return Some(FailureClass::of(class)),
            NodeOutcome::NotDispatched(NotDispatched::Cancelled) => {
                return Some(FailureClass::Cancellation);
            }
            _ => {}
        }
    }
    for write in report
        .nodes
        .iter()
        .filter_map(|n| n.cache.as_ref()?.write.as_ref())
    {
        for outcome in std::iter::once(write.outcome).chain(write.promotion) {
            match outcome {
                WriteOutcome::Failed(failure) => return Some(FailureClass::of(failure)),
                WriteOutcome::Unknown(_) => return Some(FailureClass::Indeterminate),
                WriteOutcome::Cancelled => return Some(FailureClass::Cancellation),
                _ => {}
            }
        }
    }
    report
        .resolution
        .as_ref()
        .and_then(|r| r.diagnostics.first())
        .map(graph::diagnostic_class)
        .or(Some(FailureClass::of(Failure::Protocol)))
}

pub(super) fn run(
    project: &LoadedProject,
    invocation: Invocation,
    inputs: Inputs<'_>,
    cancellation: Cancellation,
) -> Result<Output> {
    let verb = invocation.verb;
    let policy = policy(project, verb, &inputs, &cancellation)?;
    let selection = consumers::SolveSelection {
        targets: invocation.targets.clone(),
        platforms: invocation.platforms.clone(),
        build_platform: invocation.build_platform.clone(),
        builder: invocation
            .builder
            .clone()
            .ok_or_else(|| Error::failure(verb, Failure::Policy))?,
        registries: invocation.registries.clone(),
        lease_parent: "/dev/shm".into(),
        graph_limits: Default::default(),
        limits: Default::default(),
        expected_contexts: BTreeMap::new(),
        refresh: invocation.refresh,
        optional_cache_reads: invocation.optional_cache_reads,
        docker_daemon: invocation.docker_daemon.clone(),
    };
    let (report, recorder) = consumers::solve(project, policy.clone(), selection)
        .map_err(|f| Error::failure(verb, f))?
        .run_with_recorder(
            inputs.consumer(invocation.non_interactive),
            cancellation.clone(),
        )
        .map_err(|e| Error::stage(verb, e))?;
    finish(&invocation, &policy, cancellation, report, recorder)
}
