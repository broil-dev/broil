// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Out, RECORD_BYTES, ReadFailure,
    journal::{
        BindingReason, FailureClass, Journal, Kind, Observation, ObservationDetail, Settlement,
        temporary,
    },
    object,
};
use crate::images::{common::*, store, supervise::Active};
use broil_core::secret::path_safety::try_lock_exclusive;
use rustix::fs::{Mode, OFlags};
use std::{collections::BTreeMap, fs::File, path::Path};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Commit {
    Unproved {
        artifact_id: String,
    },
    Committed {
        artifact_id: String,
    },
    Abandoned {
        artifact_id: String,
        failure_class: Option<FailureClass>,
    },
}

impl Commit {
    fn artifact_id(&self) -> &str {
        match self {
            Commit::Unproved { artifact_id }
            | Commit::Committed { artifact_id }
            | Commit::Abandoned { artifact_id, .. } => artifact_id,
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Commit::Unproved { .. } => "unproved",
            Commit::Committed { .. } => "committed",
            Commit::Abandoned { .. } => "abandoned",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Settled {
    Unsettled,
    AppendUnproved { artifact_id: String },
    Resolved { artifact_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicationDisposition {
    Bound {
        artifact_id: String,
    },
    Unbound {
        reason: BindingReason,
    },
    Ambiguous {
        ambiguous_seq: u64,
        settled: Settled,
    },
    DispositionUnproved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetState {
    pub(crate) logical_target: String,
    pub(crate) phase: String,
    pub(crate) outcome: String,
    pub(crate) failure_class: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Projection {
    pub(crate) operation_id: String,
    pub(crate) commits: Vec<Commit>,
    pub(crate) publications: Vec<(u64, PublicationDisposition)>,
    pub(crate) targets: Vec<TargetState>,
}

#[derive(Clone, Debug)]
pub(crate) struct Index {
    pub(crate) operations: Vec<Projection>,
}

pub(crate) fn project(
    operation_id: &str,
    observations: &[Observation],
    settlements: &[Settlement],
) -> Projection {
    let mut commits: BTreeMap<String, Commit> = BTreeMap::new();
    for observation in observations {
        let Some(artifact_id) = observation.artifact_id.clone() else {
            continue;
        };
        match observation.kind {
            Kind::ArtifactAllocated => {
                commits
                    .entry(artifact_id.clone())
                    .or_insert(Commit::Unproved { artifact_id });
            }
            Kind::RecordCommitted => {
                commits.insert(artifact_id.clone(), Commit::Committed { artifact_id });
            }
            Kind::AllocationAbandoned => {
                commits.insert(
                    artifact_id.clone(),
                    Commit::Abandoned {
                        artifact_id,
                        failure_class: observation.failure_class,
                    },
                );
            }
            _ => {}
        }
    }

    let mut ambiguities: BTreeMap<u64, (u64, Settled)> = BTreeMap::new();
    for observation in observations {
        if let Some(ObservationDetail::BindingAmbiguous {
            publication_seq, ..
        }) = &observation.detail
        {
            ambiguities.insert(*publication_seq, (observation.seq, Settled::Unsettled));
        }
    }
    for settlement in settlements {
        for (_, (seq, settled)) in ambiguities.iter_mut() {
            if *seq == settlement.ambiguous_seq && *settled == Settled::Unsettled {
                *settled = Settled::AppendUnproved {
                    artifact_id: settlement.artifact_id.clone(),
                };
            }
        }
    }
    for observation in observations {
        let (Some(ObservationDetail::BindingResolved { ambiguous_seq, .. }), Some(artifact_id)) =
            (&observation.detail, &observation.artifact_id)
        else {
            continue;
        };
        for (_, (seq, settled)) in ambiguities.iter_mut() {
            if seq == ambiguous_seq {
                *settled = Settled::Resolved {
                    artifact_id: artifact_id.clone(),
                };
            }
        }
    }

    let mut publications = Vec::new();
    for observation in observations {
        if observation.kind != Kind::Publication {
            continue;
        }
        let binding_reason = match &observation.detail {
            Some(ObservationDetail::Publication { binding_reason, .. }) => binding_reason.clone(),
            _ => None,
        };
        let disposition = match (&observation.artifact_id, binding_reason) {
            (Some(artifact_id), _) => PublicationDisposition::Bound {
                artifact_id: artifact_id.clone(),
            },
            (None, Some(reason)) => PublicationDisposition::Unbound { reason },
            (None, None) => match ambiguities.get(&observation.seq) {
                Some((ambiguous_seq, settled)) => PublicationDisposition::Ambiguous {
                    ambiguous_seq: *ambiguous_seq,
                    settled: settled.clone(),
                },
                None => PublicationDisposition::DispositionUnproved,
            },
        };
        publications.push((observation.seq, disposition));
    }

    let targets = observations
        .iter()
        .filter(|observation| observation.kind == Kind::Phase)
        .filter_map(|observation| {
            Some(TargetState {
                logical_target: observation.target.as_ref()?.logical_target.clone(),
                phase: observation.phase.clone()?,
                outcome: observation.outcome?.name().to_owned(),
                failure_class: observation.failure_class.map(|c| c.name().to_owned()),
            })
        })
        .collect();

    Projection {
        operation_id: operation_id.to_owned(),
        commits: commits.into_values().collect(),
        publications,
        targets,
    }
}

impl Index {
    fn out(&self) -> Out {
        object(vec![
            ("format_version", Out::Number(1)),
            (
                "operations",
                Out::Array(
                    self.operations
                        .iter()
                        .map(|projection| {
                            object(vec![
                                ("operation_id", Out::text(&projection.operation_id)),
                                (
                                    "commits",
                                    Out::Array(
                                        projection
                                            .commits
                                            .iter()
                                            .map(|commit| {
                                                let mut members = vec![
                                                    (
                                                        "artifact_id",
                                                        Out::text(commit.artifact_id()),
                                                    ),
                                                    ("state", Out::text(commit.name())),
                                                ];
                                                if let Commit::Abandoned {
                                                    failure_class: Some(class),
                                                    ..
                                                } = commit
                                                {
                                                    members.push((
                                                        "failure_class",
                                                        Out::text(class.name()),
                                                    ));
                                                }
                                                object(members)
                                            })
                                            .collect(),
                                    ),
                                ),
                                (
                                    "publications",
                                    Out::Array(
                                        projection
                                            .publications
                                            .iter()
                                            .map(|(seq, disposition)| {
                                                disposition_out(*seq, disposition)
                                            })
                                            .collect(),
                                    ),
                                ),
                                (
                                    "targets",
                                    Out::Array(
                                        projection
                                            .targets
                                            .iter()
                                            .map(|target| {
                                                let mut members = vec![
                                                    (
                                                        "logical_target",
                                                        Out::text(&target.logical_target),
                                                    ),
                                                    ("phase", Out::text(&target.phase)),
                                                    ("outcome", Out::text(&target.outcome)),
                                                ];
                                                if let Some(class) = &target.failure_class {
                                                    members
                                                        .push(("failure_class", Out::text(class)));
                                                }
                                                object(members)
                                            })
                                            .collect(),
                                    ),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

fn disposition_out(seq: u64, disposition: &PublicationDisposition) -> Out {
    let mut members = vec![("publication_seq", Out::Number(seq))];
    match disposition {
        PublicationDisposition::Bound { artifact_id } => {
            members.push(("binding", Out::text("bound")));
            members.push(("artifact_id", Out::text(artifact_id)));
        }
        PublicationDisposition::Unbound { reason } => {
            members.push(("binding", Out::text("unbound")));
            members.push(("reason", Out::text(reason.disposition.name())));
        }
        PublicationDisposition::Ambiguous {
            ambiguous_seq,
            settled,
        } => {
            members.push(("binding", Out::text("ambiguous")));
            members.push(("ambiguous_seq", Out::Number(*ambiguous_seq)));
            let (state, artifact_id) = match settled {
                Settled::Unsettled => ("unsettled", None),
                Settled::AppendUnproved { artifact_id } => {
                    ("settled-append-unproved", Some(artifact_id))
                }
                Settled::Resolved { artifact_id } => ("settled", Some(artifact_id)),
            };
            members.push(("settlement", Out::text(state)));
            if let Some(artifact_id) = artifact_id {
                members.push(("artifact_id", Out::text(artifact_id)));
            }
        }
        PublicationDisposition::DispositionUnproved => {
            members.push(("binding", Out::text("disposition-unproved")));
        }
    }
    object(members)
}

fn take_lock(index: &File, active: &Active) -> Result<File> {
    active.check()?;
    let created = rustix::fs::openat(
        index,
        "current.lock",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    );
    active.check()?;
    match created {
        Ok(fd) => drop(File::from(fd)),
        Err(rustix::io::Errno::EXIST) => {}
        Err(_) => return Err(Failure::Storage),
    }
    let file = File::from(active.sys(|| {
        rustix::fs::openat(
            index,
            "current.lock",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })?);
    store::owned(&file, false, active)?;
    require(active.io(|| try_lock_exclusive(&file))?, Failure::Capacity)?;
    Ok(file)
}

pub(crate) fn rebuild(root: &Path, active: &Active) -> std::result::Result<Index, ReadFailure> {
    let state = store::state_directory(root, true, active).map_err(ReadFailure::Invalid)?;
    let index =
        store::child_directory(&state, "index", true, active).map_err(ReadFailure::Invalid)?;
    let _lock = take_lock(&index, active).map_err(ReadFailure::Invalid)?;
    let operations =
        store::child_directory(&state, "operations", true, active).map_err(ReadFailure::Invalid)?;
    let names = store::scan(&operations, valid_operation, active).map_err(ReadFailure::Invalid)?;
    let mut projections = Vec::new();
    for name in names {
        let journal = Journal::open(root, &name, false, active).map_err(ReadFailure::Invalid)?;
        let observations = journal.observations(active)?;
        let settlements = journal.settlements(active)?;
        projections.push(project(&name, &observations, &settlements));
    }
    projections.sort_by(|a, b| a.operation_id.cmp(&b.operation_id));
    let projection = Index {
        operations: projections,
    };
    let bytes = projection.out().encode().map_err(ReadFailure::Invalid)?;
    if bytes.len() as u64 > RECORD_BYTES {
        return Err(ReadFailure::Invalid(Failure::Limit));
    }
    write_current(&index, &bytes, active).map_err(ReadFailure::Invalid)?;
    Ok(projection)
}

fn write_current(index: &File, bytes: &[u8], active: &Active) -> Result<()> {
    let existing = store::read(index, "current.json", RECORD_BYTES, active)?;
    let prepared = store::prepare(index, temporary("current")?, bytes, active)?;
    store::publish(
        index,
        prepared,
        "current.json",
        existing.map(|(_, identity)| identity),
        active,
    )?;
    store::sync_parent(index, active)
}

fn epoch_seconds(value: &str) -> Option<u64> {
    if !super::valid_time(value) {
        return None;
    }
    let number = |range: std::ops::Range<usize>| value.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hour * 3_600 + minute * 60 + second).ok()
}

pub(crate) fn release_candidates(
    root: &Path,
    active: &Active,
) -> std::result::Result<Vec<serde_json::Value>, ReadFailure> {
    if std::fs::symlink_metadata(root.join("state/artifacts")).is_err() {
        return Ok(Vec::new());
    }
    let mut bound: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    if std::fs::symlink_metadata(root.join("state/operations")).is_ok() {
        let state = store::state_directory(root, false, active).map_err(ReadFailure::Invalid)?;
        let operations = store::child_directory(&state, "operations", false, active)
            .map_err(ReadFailure::Invalid)?;
        let names =
            store::scan(&operations, valid_operation, active).map_err(ReadFailure::Invalid)?;
        for name in names {
            let journal =
                Journal::open(root, &name, false, active).map_err(ReadFailure::Invalid)?;
            let observations = journal.observations(active)?;
            let settlements = journal.settlements(active)?;
            for (seq, disposition) in project(&name, &observations, &settlements).publications {
                let artifact = match disposition {
                    PublicationDisposition::Bound { artifact_id }
                    | PublicationDisposition::Ambiguous {
                        settled: Settled::Resolved { artifact_id },
                        ..
                    } => artifact_id,
                    _ => continue,
                };
                let Some(ObservationDetail::Publication {
                    root,
                    endpoint,
                    repository,
                    ..
                }) = observations
                    .iter()
                    .find(|o| o.seq == seq)
                    .and_then(|o| o.detail.as_ref())
                else {
                    continue;
                };
                bound.entry(artifact).or_default().push(serde_json::json!({
                    "endpoint": endpoint, "repository": repository, "root": root}));
            }
        }
    }
    let records = super::Store::new(root);
    let mut out = Vec::new();
    for id in records.list(active).map_err(ReadFailure::Invalid)? {
        let Some(record) = records.read(&id, active)? else {
            continue;
        };
        let platforms: Vec<serde_json::Value> = record
            .platforms
            .iter()
            .map(|p| serde_json::json!({"platform": p.platform, "manifest": p.manifest.digest}))
            .collect();
        out.push(serde_json::json!({
            "artifact": id,
            "image": record.target.logical_target,
            "created_ms": epoch_seconds(&record.created_at).map(|s| s * 1000),
            "publications": bound.remove(&id).unwrap_or_default(),
            "platforms": platforms,
        }));
    }
    Ok(out)
}
