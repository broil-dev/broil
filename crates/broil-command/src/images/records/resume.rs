// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    RECORD_BYTES, ReadFailure,
    index::{Projection, project},
    journal::{FailureClass, Journal, Kind, Observation, ObservationDetail, Outcome, Settlement},
};
use crate::images::{Descriptor, common::*, store, supervise::Active};
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WindowOutcome {
    Committed { artifact_id: String },
    Abandoned { artifact_id: String },
    Corrupt { artifact_id: String },
    AlreadyTerminal { artifact_id: String },
}

#[derive(Clone, Debug)]
pub(crate) struct Resumed {
    pub(crate) operation_id: String,
    pub(crate) windows: Vec<WindowOutcome>,
    pub(crate) completed: Vec<Settlement>,
    pub(crate) left_open: Vec<u64>,
    pub(crate) projection: Projection,
    pub(crate) tool_identities_changed: bool,
}

fn read_record(root: &Path, artifact_id: &str, active: &Active) -> Result<store::ReadBytes> {
    let state = store::state_directory(root, false, active)?;
    let artifacts = store::child_directory(&state, "artifacts", true, active)?;
    store::read(
        &artifacts,
        &format!("{artifact_id}.json"),
        RECORD_BYTES,
        active,
    )
}

fn resolve_window(
    root: &Path,
    artifact_id: &str,
    operation_id: &str,
    allocated_root: &Descriptor,
    active: &Active,
) -> Result<WindowOutcome> {
    let Some((bytes, _)) = read_record(root, artifact_id, active)? else {
        return Ok(WindowOutcome::Abandoned {
            artifact_id: artifact_id.to_owned(),
        });
    };
    match super::decode_record(&bytes) {
        Ok(record) => {
            let matches = record.artifact_id == artifact_id
                && record.build_operation_id == operation_id
                && &record.root == allocated_root;
            Ok(if matches {
                WindowOutcome::Committed {
                    artifact_id: artifact_id.to_owned(),
                }
            } else {
                WindowOutcome::Corrupt {
                    artifact_id: artifact_id.to_owned(),
                }
            })
        }
        Err(_) => Ok(WindowOutcome::Corrupt {
            artifact_id: artifact_id.to_owned(),
        }),
    }
}

fn terminal_ids(observations: &[Observation]) -> Vec<String> {
    observations
        .iter()
        .filter(|observation| {
            matches!(
                observation.kind,
                Kind::RecordCommitted | Kind::AllocationAbandoned
            )
        })
        .filter_map(|observation| observation.artifact_id.clone())
        .collect()
}

fn terminal(
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

pub(crate) fn resume(
    root: &Path,
    operation_id: &str,
    observed_at: &str,
    active: &Active,
) -> std::result::Result<Resumed, ReadFailure> {
    let journal = Journal::open(root, operation_id, false, active).map_err(ReadFailure::Invalid)?;
    let operation = journal.read_operation(active)?;
    let observations = journal.observations(active)?;
    let settlements = journal.settlements(active)?;

    let tool_identities_changed = match super::capture_tools(&operation.tools.buildkit_version) {
        Ok(current) => current != operation.tools,
        Err(_) => true,
    };

    let terminals = terminal_ids(&observations);
    let mut windows = Vec::new();
    let mut appended = Vec::new();
    for observation in &observations {
        if observation.kind != Kind::ArtifactAllocated {
            continue;
        }
        let (Some(artifact_id), Some(ObservationDetail::ArtifactAllocated { root: allocated })) =
            (&observation.artifact_id, &observation.detail)
        else {
            return Err(ReadFailure::Invalid(Failure::Integrity));
        };
        if terminals.iter().any(|id| id == artifact_id) {
            windows.push(WindowOutcome::AlreadyTerminal {
                artifact_id: artifact_id.clone(),
            });
            continue;
        }
        let outcome = resolve_window(root, artifact_id, operation_id, allocated, active)
            .map_err(ReadFailure::Invalid)?;
        match &outcome {
            WindowOutcome::Committed { artifact_id } => {
                appended.push(terminal(
                    operation_id,
                    Kind::RecordCommitted,
                    artifact_id,
                    observed_at,
                    None,
                ));
            }
            WindowOutcome::Abandoned { artifact_id } => {
                appended.push(terminal(
                    operation_id,
                    Kind::AllocationAbandoned,
                    artifact_id,
                    observed_at,
                    Some(FailureClass::Storage),
                ));
            }
            WindowOutcome::Corrupt { .. } | WindowOutcome::AlreadyTerminal { .. } => {}
        }
        windows.push(outcome);
    }

    let resolved: Vec<u64> = observations
        .iter()
        .filter_map(|observation| match &observation.detail {
            Some(ObservationDetail::BindingResolved { ambiguous_seq, .. }) => Some(*ambiguous_seq),
            _ => None,
        })
        .collect();
    let mut completed = Vec::new();
    let mut left_open = Vec::new();
    for observation in &observations {
        if observation.kind != Kind::BindingAmbiguous {
            continue;
        }
        if resolved.contains(&observation.seq) {
            continue;
        }
        match settlements
            .iter()
            .find(|settlement| settlement.ambiguous_seq == observation.seq)
        {
            Some(settlement) => {
                let mut completion = terminal(
                    operation_id,
                    Kind::BindingResolved,
                    &settlement.artifact_id,
                    observed_at,
                    None,
                );
                completion.detail = Some(ObservationDetail::BindingResolved {
                    ambiguous_seq: settlement.ambiguous_seq,
                    retention_operation_id: settlement.retention_operation_id.clone(),
                    retention_seq: settlement.retention_seq,
                });
                appended.push(completion);
                completed.push(settlement.clone());
            }
            None => left_open.push(observation.seq),
        }
    }

    for observation in appended {
        journal
            .append(observation, active)
            .map_err(ReadFailure::Invalid)?;
    }

    let observations = journal.observations(active)?;
    let settlements = journal.settlements(active)?;
    Ok(Resumed {
        operation_id: operation_id.to_owned(),
        windows,
        completed,
        left_open,
        projection: project(operation_id, &observations, &settlements),
        tool_identities_changed,
    })
}

pub(crate) fn requires_explicit_decision(observations: &[Observation]) -> bool {
    observations.iter().any(|marker| {
        marker.kind == Kind::PreDispatch
            && !observations
                .iter()
                .any(|completion| completes(marker, completion))
    })
}

fn completes(marker: &Observation, completion: &Observation) -> bool {
    if completion.kind == Kind::PreDispatch
        || completion.phase != marker.phase
        || !completion.outcome.is_some_and(|outcome| {
            !matches!(
                outcome,
                Outcome::Pending | Outcome::Running | Outcome::Unknown
            )
        })
    {
        return false;
    }
    match &marker.stage_operation_id {
        Some(minted) => completion
            .stage_operation_id
            .as_ref()
            .is_some_and(|reported| {
                minted.iter().all(|acquisition| {
                    reported
                        .iter()
                        .any(|r| r.acquisition_id == acquisition.acquisition_id)
                })
            }),
        None => completion.target == marker.target,
    }
}
