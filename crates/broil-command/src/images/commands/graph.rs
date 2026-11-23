// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::images::graph::{Diagnostic, Resolution, Staging};
use crate::images::{Dispatch, Observation};

type Observed = std::result::Result<Observation, StageError>;

pub(super) struct ReleaseReport {
    pub owner: String,
    pub paths: Vec<PathBuf>,
    pub returned_owner: bool,
    pub result: Observed,
}

fn observation(result: &Observed) -> &Observation {
    match result {
        Ok(observation) => observation,
        Err(error) => &error.observation,
    }
}

fn explicit_failure(result: &Observed) -> Option<FailureClass> {
    match result {
        Err(error) => Some(FailureClass::of(error.failure)),
        Ok(observation) => observation.failure.map(FailureClass::of),
    }
}

fn clean(result: &Observed) -> bool {
    let o = observation(result);
    result.is_ok()
        && o.failure.is_none()
        && o.dispatch == Dispatch::Observed
        && o.exit_code == Some(0)
        && o.signal.is_none()
        && !o.cancellation_requested
        && !o.completion_uncertain
        && !o.cleanup_uncertain
}

pub(super) fn finish(
    invocation: &Invocation,
    workspace: &Path,
    result: Result<(serde_json::Value, Option<FailureClass>)>,
    cleanup: Observed,
    protected: consumers::ProtectedObservation,
    release: Option<ReleaseReport>,
) -> Result<Output> {
    let o = observation(&cleanup);
    let protected_uncertain = protected.residue || protected.unresolved_owner;
    let mut class = explicit_failure(&cleanup)
        .or_else(|| {
            o.cancellation_requested
                .then_some(FailureClass::Cancellation)
        })
        .or_else(|| {
            (o.completion_uncertain || o.cleanup_uncertain || protected_uncertain)
                .then_some(FailureClass::Indeterminate)
        });
    let mut successful = clean(&cleanup) && !protected_uncertain;
    let mut details = Vec::new();
    if !clean(&cleanup) {
        details.push(format!(
            "cleanup: failure={}; {}; workspace={}",
            explicit_failure(&cleanup).map_or("none", FailureClass::name),
            render::observation(o),
            serde_json::json!(workspace)
        ));
    }
    if protected_uncertain {
        details.push(format!(
            "protected_session={}; residue={}; unresolved_owner={}",
            serde_json::json!(protected.session),
            protected.residue,
            protected.unresolved_owner
        ));
    }
    if let Some(release) = release {
        let o = observation(&release.result);
        class = class
            .or_else(|| explicit_failure(&release.result))
            .or_else(|| {
                (release.returned_owner
                    || o.cancellation_requested
                    || o.completion_uncertain
                    || o.cleanup_uncertain)
                    .then_some(FailureClass::Indeterminate)
            });
        let released = clean(&release.result) && !release.returned_owner;
        successful &= released;
        if !released {
            details.push(format!(
                "release: failure={}; {}; owner={}; retained_paths={}; returned_owner={}",
                explicit_failure(&release.result).map_or("none", FailureClass::name),
                render::observation(o),
                release.owner,
                serde_json::json!(release.paths),
                release.returned_owner
            ));
        }
    }
    if !successful && class.is_none() {
        class = Some(FailureClass::of(Failure::Protocol));
    }
    match result {
        Ok((projection, graph_class)) => output(
            invocation,
            projection,
            graph_class.or(class),
            (!details.is_empty()).then(|| format!("image graph failed; {}", details.join("; "))),
        ),
        Err(mut error) => {
            if !details.is_empty() {
                error
                    .diagnostic
                    .push_str(&format!("; {}", details.join("; ")));
            }
            Err(error)
        }
    }
}

pub(super) fn diagnostic_class(diagnostic: &Diagnostic) -> FailureClass {
    match diagnostic.reason {
        "policy" => FailureClass::of(Failure::Policy),
        "limit" => FailureClass::of(Failure::Limit),
        "storage" => FailureClass::of(Failure::Storage),
        "integrity" | "missing-metadata" => FailureClass::Integrity,
        "stale" => FailureClass::SourceDrift,
        _ => FailureClass::Configuration,
    }
}
pub(super) fn resolution_class(resolution: &Resolution) -> Option<FailureClass> {
    (!resolution.complete).then(|| {
        resolution
            .diagnostics
            .first()
            .map(diagnostic_class)
            .unwrap_or(FailureClass::of(Failure::Protocol))
    })
}
pub(super) fn run(
    project: &LoadedProject,
    invocation: Invocation,
    inputs: Inputs<'_>,
    cancellation: Cancellation,
) -> Result<Output> {
    let verb = invocation.verb;
    let policy = policy(project, verb, &inputs, &cancellation)?;
    let selection = consumers::GraphSelection {
        targets: invocation.targets.clone(),
        platforms: invocation.platforms.clone(),
        build_platform: invocation
            .build_platform
            .clone()
            .unwrap_or_else(|| "linux/amd64".into()),
        staging: if invocation.content_staging {
            Staging::Content
        } else {
            Staging::Metadata
        },
        registries: invocation.registries.clone(),
        limits: Default::default(),
        producer_outputs: vec![],
        prior: None,
    };
    let outcome = consumers::graph(project, policy.clone(), selection)
        .map_err(|f| Error::failure(verb, f))?
        .run(
            inputs.consumer(invocation.non_interactive),
            cancellation.clone(),
        )
        .map_err(|e| Error::stage(verb, e))?;
    let result = outcome
        .result
        .map(|graph| match graph.result {
            consumers::GraphResult::Resolved {
                resolution,
                material,
            } => {
                let class = resolution_class(&resolution);
                let projection = render::graph(&resolution);
                drop(material);
                (projection, class)
            }
            consumers::GraphResult::Stale { prior, .. } => {
                let projection = render::graph(&prior.resolution);
                drop(prior.material);
                (projection, Some(FailureClass::SourceDrift))
            }
        })
        .map_err(|e| Error::stage(verb, e));
    let release = outcome.release.map(|kept| {
        let owner = kept.token.operation_id().to_owned();
        let paths = kept
            .entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        let (result, returned_owner) = match consumers::release(&policy, kept, cancellation) {
            Ok(observed) => (Ok(observed), false),
            Err(unreleased) => (Err(unreleased.error), unreleased.kept.is_some()),
        };
        ReleaseReport {
            owner,
            paths,
            returned_owner,
            result,
        }
    });
    finish(
        &invocation,
        &policy.workspace_path(),
        result,
        outcome.cleanup,
        outcome.protected,
        release,
    )
}
