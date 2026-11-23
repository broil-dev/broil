// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, canonical, hash, nonce, operation_id, require, schema};
use crate::images::infrastructure_io::{
    Active, Clock, Permit, PublicAction, public_local, store as io,
};
use broil_core::secret::path_safety::sudo_nonce;
use rustix::fs::{FlockOperation, Mode, OFlags};
use serde_json::{Value, json};
use std::{
    fs::File,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
};

pub(super) fn bound_class(family: &str) -> &'static str {
    if matches!(
        family,
        "issuer"
            | "certificate"
            | "registry-storage"
            | "registry-service"
            | "registry-endpoint"
            | "registry-auth"
            | "registry-token"
            | "registry-replication"
    ) {
        "owned"
    } else {
        "owned-ready"
    }
}

pub(super) fn planned_shape(family: &str, owner: &Value) -> (&'static str, Value) {
    let acting = || super::acting_server(owner).map_or(Value::Null, |m| m["machine"].clone());
    if family == "issuer" {
        ("issuer", acting())
    } else if family == "registry-auth" {
        ("registry-auth", acting())
    } else {
        ("service", Value::Null)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    NotPublished,
    PossiblyPublished,
    Durable,
}

pub(super) fn admit_join_successor(prior: &Value, successor: &Value, member: &str) -> Result<()> {
    let fixed = |owner: &Value| {
        let mut owner = owner.clone();
        if let Some(fields) = owner.as_object_mut() {
            for key in [
                "generation",
                "previous_generation",
                "created_ms",
                "lock_identity",
                "members",
                "resources",
            ] {
                fields.remove(key);
            }
        }
        owner
    };
    require(fixed(prior) == fixed(successor), Failure::Ownership)?;
    let index = prior["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .position(|m| m["member"] == member && m["node_uid"].is_null())
        .ok_or(Failure::Ownership)?;
    let mut expected = prior.clone();
    expected["members"][index]["node_uid"] = successor["members"][index]["node_uid"].clone();
    require(
        expected["members"][index]["node_uid"].is_string()
            && expected["members"] == successor["members"],
        Failure::Ownership,
    )?;
    super::server::rebind_restored(prior, &mut expected, index)?;
    let before = expected["resources"].as_array().ok_or(Failure::Integrity)?;
    let after = successor["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    require(
        after.len() == before.len() + 2 && after[..before.len()] == before[..],
        Failure::Ownership,
    )
}

pub(super) const NETWORK_OBJECTS: [(Option<&str>, &str); 12] = [
    (Some("kube-system"), "coredns"),
    (None, "system:coredns"),
    (None, "system:coredns"),
    (Some("kube-system"), "coredns"),
    (Some("kube-system"), "coredns"),
    (Some("kube-system"), "kube-dns"),
    (
        Some("kube-system"),
        "local-path-provisioner-service-account",
    ),
    (None, "local-path-provisioner-role"),
    (None, "local-path-provisioner-bind"),
    (Some("kube-system"), "local-path-provisioner"),
    (None, "local-path"),
    (Some("kube-system"), "local-path-config"),
];

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub owner: Value,
    pub request: Value,
    pub attempts: Vec<Value>,
    pub steps: Vec<Value>,
    pub observations: Vec<Value>,
}

#[derive(Clone, Debug)]
pub(in crate::k3s) struct WaveRecord {
    pub(super) boundary: Value,
    pub(super) gate: Option<Value>,
}

enum Action {
    Inspect(Option<String>),
    List,
    AgentContext,
    WaveBoundary(Box<Value>),
    WaveGate(Box<Value>),
    Lock(String),
    Create {
        owner: Box<Value>,
        request: Box<Value>,
        attempt: Box<Value>,
    },
    Attempt(Box<Value>),
    Step(Box<Value>),
    Append(Box<Value>),
    PlanNetwork(Box<Value>, &'static str),
    ReplaceOwner {
        owner: Box<Value>,
        operation: String,
    },
    Verify,
    Sequence,
    Release,
    History,
    Load(Vec<String>),
    Requests(Vec<String>),
    Intent(Box<Value>),
    RemoveIntent,
    Trash {
        candidates: Vec<String>,
        batch: Vec<String>,
    },
    Checkpoint {
        before: String,
        after: Box<Value>,
    },
}

#[derive(Clone, Debug, Default)]
pub(super) struct HistoryRead {
    pub(super) owner: Option<Value>,
    pub(super) summaries: Vec<Value>,
    pub(super) attempts: std::collections::BTreeMap<String, Vec<String>>,
    pub(super) waves: Vec<Value>,
    pub(super) checkpoint: Option<Value>,
    pub(super) intent: Option<Value>,
    intent_identity: Option<(u64, u64)>,
}

const OPERATION_CAP: usize = crate::k3s::history::CAP as usize;
const OPERATION_RESERVE: usize = crate::k3s::history::RESERVE as usize;

struct Held {
    target: File,
    target_identity: (u64, u64),
    lock: File,
    lock_identity: (u64, u64),
    exclusive: bool,
}

struct Work {
    root: PathBuf,
    scope: Value,
    held: Option<Held>,
    action: Action,
    snapshots: Vec<Snapshot>,
    unlisted: Vec<Value>,
    owner: Option<Value>,
    waves: Vec<WaveRecord>,
    publication: Arc<AtomicU8>,
    failure: Option<Failure>,
    permit: Arc<Permit>,
    receipts: Option<super::converge::Receipts>,
    sequence: u64,
    history: HistoryRead,
    hashes: Vec<String>,
    pruning: bool,
    reserve: bool,

}

pub struct Store {
    work: Option<Work>,
    permit: Arc<Permit>,
    clock: Clock,
    cancelled: Arc<AtomicBool>,
    publication: Arc<AtomicU8>,
    work_end: Option<u64>,
    owner_clock: broil_remote::exec::private::ActionClock,
}

fn bridge(_: Failure) -> crate::images::Failure {
    crate::images::Failure::Integrity
}

impl PublicAction for Work {
    fn apply(&mut self, active: &Active) -> std::result::Result<(), crate::images::Failure> {
        let releasing = matches!(self.action, Action::Release);
        let result = self.perform(active);
        if !releasing && self.publication.load(Ordering::Acquire) != 0 {
            if let Some(receipts) = &self.receipts {
                receipts.capture(&self.snapshots);
            }
        }
        self.failure = result.as_ref().err().copied();
        result.map_err(bridge)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

impl Store {

    pub fn new(
        root: PathBuf,
        scope: Value,
        timeout_ms: u64,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        schema::validate(&canonical(&scope)?, "Scope", 65536)?;
        require(
            scope["project"].as_str() == root.to_str() && timeout_ms > 0 && timeout_ms <= 7_200_000,
            Failure::Configuration,
        )?;
        let publication = Arc::new(AtomicU8::new(0));
        let permit = Permit::acquire()?;
        Ok(Self {
            work: Some(Work {
                root,
                scope,
                held: None,
                action: Action::Verify,
                snapshots: Vec::new(),
                unlisted: Vec::new(),
                owner: None,
                waves: Vec::new(),
                publication: publication.clone(),
                failure: None,
                permit: permit.clone(),
                receipts: super::converge::Receipts::current(),
                sequence: 1,
                history: HistoryRead::default(),
                hashes: Vec::new(),
                pruning: false,
                reserve: false,

            }),
            permit,
            clock: Clock::new(timeout_ms)?,
            cancelled,
            publication,
            work_end: None,
            owner_clock: broil_remote::exec::private::ActionClock::new(
                tokio::time::Instant::now() + std::time::Duration::from_millis(timeout_ms),
            ),
        })
    }

    pub(super) fn bind_clock(&mut self, clock: broil_remote::exec::private::ActionClock) {
        self.owner_clock = clock;
    }

    pub fn publication(&self) -> Publication {
        match self.publication.load(Ordering::Acquire) {
            0 => Publication::NotPublished,
            2 => Publication::Durable,
            _ => Publication::PossiblyPublished,
        }
    }

    pub(super) fn constrain_work(&mut self, milliseconds: u64) -> Result<()> {
        require(milliseconds > 0, Failure::Timeout)?;
        self.work_end = Some(Clock::new(milliseconds.min(30_000))?.end);
        Ok(())
    }

    pub(super) fn dispose(&mut self) -> Result<()> {
        self.work.as_mut().ok_or(Failure::Busy)?.held = None;
        Ok(())
    }

    pub(super) fn release(&mut self, until: tokio::time::Instant) -> Result<()> {
        let remaining = until
            .saturating_duration_since(tokio::time::Instant::now())
            .as_millis()
            .min(5000) as u64;
        require(remaining > 0, Failure::Timeout)?;
        let mut work = self.work.take().ok_or(Failure::Busy)?;
        work.action = Action::Release;
        work.failure = None;
        let original_end = self.clock.end;
        self.clock.end = Clock::new(remaining)?.end;
        let (work, result) = public_local(
            work,
            &mut self.clock,
            &Arc::new(AtomicBool::new(false)),
            &self.permit,
        );
        self.clock.end = original_end;
        self.work = work;
        result.map_err(Into::into)
    }

    fn act(&mut self, action: Action) -> Result<()> {
        let mut work = self.work.take().ok_or(Failure::Busy)?;
        work.action = action;
        work.failure = None;
        let end = self.clock.end;
        let bound = Clock::new(30_000)?;
        self.clock.end = end.min(bound.end).min(self.work_end.unwrap_or(end));
        let candidate = match &work.action {
            Action::Create { attempt, .. } | Action::Attempt(attempt) => Some((**attempt).clone()),
            Action::Append(event) if event["attempt"].is_string() => Some((**event).clone()),
            _ => None,
        };
        let receipt = work.receipts.clone().zip(candidate);
        if let Some((receipts, attempt)) = &receipt {
            if let Err(failure) = receipts.dispatched(&work.scope, attempt) {
                self.work = Some(work);
                self.clock.end = end;
                return Err(failure);
            }
        }
        let (work, result) = public_local(work, &mut self.clock, &self.cancelled, &self.permit);
        self.clock.end = end;
        if let (Some(work), Some((receipts, attempt))) = (&work, receipt) {
            receipts.returned(&work.scope, &attempt);
        }
        let failure = work.as_ref().and_then(|w| w.failure);
        self.work = work;
        match result {
            Ok(()) => Ok(()),
            Err(e) => Err(failure.unwrap_or_else(|| e.into())),
        }
    }

    pub fn inspect(&mut self, operation: Option<&str>) -> super::ExecutionResult<Vec<Snapshot>> {
        self.read_operations(operation)
    }

    pub fn read_operations(
        &mut self,
        operation: Option<&str>,
    ) -> super::ExecutionResult<Vec<Snapshot>> {
        if let Some(operation) = operation {
            require(operation_id(operation), Failure::Configuration)?;
        }
        self.read_records(Action::Inspect(operation.map(str::to_owned)))
    }

    pub fn read_listed(&mut self) -> super::ExecutionResult<(Vec<Snapshot>, Vec<Value>)> {
        let snapshots = self.read_records(Action::List)?;
        let unlisted = self.work.as_ref().ok_or(Failure::Busy)?.unlisted.clone();
        Ok((snapshots, unlisted))
    }

    fn read_records(&mut self, action: Action) -> super::ExecutionResult<Vec<Snapshot>> {
        let result = self.act(action);
        if result.is_err() {
            self.owner_clock.abort();
        }
        let cancel = broil_remote::scheduler::CancellationToken::default();
        if self.cancelled.load(Ordering::Acquire) {
            cancel.cancel();
        }
        let release = self.release(self.owner_clock.local_release_deadline(&cancel));
        if let Some(failure) = result.as_ref().err().or_else(|| release.as_ref().err()) {
            return Err(super::ExecutionFailure {
                failure: *failure,
                completion_unknown: self.work.is_none()
                    || self.publication() == Publication::PossiblyPublished,
                cleanup_unknown: release.is_err(),
                snapshot: self
                    .work
                    .as_ref()
                    .filter(|w| w.snapshots.len() == 1)
                    .map(|w| Box::new(w.snapshots[0].clone())),
                detail: None,
            });
        }
        Ok(self.work.as_ref().ok_or(Failure::Busy)?.snapshots.clone())
    }

    pub(super) fn agent_context(&mut self) -> Result<(Vec<Snapshot>, Vec<WaveRecord>)> {
        self.act(Action::AgentContext)?;
        let work = self.work.as_ref().ok_or(Failure::Busy)?;
        Ok((work.snapshots.clone(), work.waves.clone()))
    }

    pub(super) fn wave_boundary(&mut self, boundary: Value) -> Result<()> {
        self.act(Action::WaveBoundary(Box::new(boundary)))
    }

    pub(super) fn wave_gate(&mut self, gate: Value) -> Result<()> {
        self.act(Action::WaveGate(Box::new(gate)))
    }

    pub(super) fn next_sequence(&mut self) -> Result<u64> {
        let held = self.work.as_ref().ok_or(Failure::Busy)?.held.is_some();
        let result = self.act(Action::Sequence);
        if !held && self.work.as_ref().is_some_and(|w| w.held.is_some()) {
            let cancel = broil_remote::scheduler::CancellationToken::default();
            let release = self.release(self.owner_clock.local_release_deadline(&cancel));
            result?;
            release?;
        } else {
            result?;
        }
        Ok(self.work.as_ref().ok_or(Failure::Busy)?.sequence)
    }

    pub(super) fn create(&mut self, owner: Value, request: Value, attempt: Value) -> Result<()> {
        self.act(Action::Create {
            owner: Box::new(owner),
            request: Box::new(request),
            attempt: Box::new(attempt),
        })
    }
    pub(super) fn attempt(&mut self, attempt: Value) -> Result<()> {
        self.act(Action::Attempt(Box::new(attempt)))
    }
    pub(super) fn step(&mut self, step: Value) -> Result<()> {
        self.act(Action::Step(Box::new(step)))
    }
    pub(super) fn append(&mut self, event: Value) -> Result<()> {
        self.act(Action::Append(Box::new(event)))
    }
    pub(super) fn replace_owner(&mut self, owner: Value, operation: &str) -> Result<()> {
        require(operation_id(operation), Failure::Configuration)?;
        self.act(Action::ReplaceOwner {
            owner: Box::new(owner),
            operation: operation.to_owned(),
        })
    }
    pub(super) fn plan_network(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "network"))
    }
    pub(super) fn plan_ingress(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "ingress"))
    }
    pub(super) fn plan_cert_manager(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "cert-manager"))
    }
    pub(super) fn plan_issuer(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "issuer"))
    }
    pub(super) fn plan_certificate(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "certificate"))
    }
    pub(super) fn plan_registry_storage(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "registry-storage"))
    }
    pub(super) fn plan_registry_service(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "registry-service"))
    }
    pub(super) fn plan_registry_endpoint(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "registry-endpoint"))
    }
    pub(super) fn plan_registry_auth(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "registry-auth"))
    }
    pub(super) fn plan_registry_token(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "registry-token"))
    }
    pub(super) fn plan_registry_replication(&mut self, owner: Value) -> Result<()> {
        self.act(Action::PlanNetwork(Box::new(owner), "registry-replication"))
    }
    pub(super) fn verify(&mut self) -> Result<()> {
        self.act(Action::Verify)
    }
    pub(super) fn lock(&mut self, operation: &str) -> Result<()> {
        require(operation_id(operation), Failure::Configuration)?;
        self.act(Action::Lock(operation.to_owned()))
    }
    pub(super) fn snapshot(&self) -> Result<&Snapshot> {
        let work = self.work.as_ref().ok_or(Failure::Busy)?;
        require(work.snapshots.len() == 1, Failure::Integrity)?;
        Ok(&work.snapshots[0])
    }

    pub(super) fn observed_owner(&self) -> Result<Option<Value>> {
        Ok(self.work.as_ref().ok_or(Failure::Busy)?.owner.clone())
    }

    pub(super) fn pruning(&mut self) -> Result<()> {
        self.work.as_mut().ok_or(Failure::Busy)?.pruning = true;
        Ok(())
    }

    pub(super) fn history_records(&mut self) -> Result<HistoryRead> {
        self.act(Action::History)?;
        Ok(self.work.as_ref().ok_or(Failure::Busy)?.history.clone())
    }

    pub(super) fn complete_records(&mut self, operations: Vec<String>) -> Result<Vec<Snapshot>> {
        self.act(Action::Load(operations))?;
        Ok(self.work.as_ref().ok_or(Failure::Busy)?.snapshots.clone())
    }

    pub(super) fn request_hashes(&mut self, operations: Vec<String>) -> Result<Vec<String>> {
        self.act(Action::Requests(operations))?;
        Ok(self.work.as_ref().ok_or(Failure::Busy)?.hashes.clone())
    }

    pub(super) fn publish_intent(&mut self, intent: Value) -> Result<()> {
        self.act(Action::Intent(Box::new(intent)))
    }

    pub(super) fn remove_intent(&mut self) -> Result<()> {
        self.act(Action::RemoveIntent)
    }

    pub(super) fn trash_operations(
        &mut self,
        candidates: Vec<String>,
        batch: Vec<String>,
    ) -> Result<()> {
        self.act(Action::Trash { candidates, batch })
    }

    pub(super) fn checkpoint(&mut self, before: String, after: Value) -> Result<()> {
        self.act(Action::Checkpoint {
            before,
            after: Box::new(after),
        })
    }
}

const SUMMARY_TEMPORARY: &str = ".summary-";
const LISTED: usize = 100;

fn unknown_run_event(snapshot: &super::Snapshot, event: &Value) -> Result<()> {
    let failure = &event["event"];
    let projection = super::report::summary(snapshot);
    require(
        crate::k3s::release::UNKNOWN_RUN_ACTIONS
            .iter()
            .any(|action| snapshot.request["action"] == *action)
            && event["source"]["kind"] == "controller"
            && failure["outcome"] == "unknown"
            && failure["failure"].is_string()
            && failure["completion_unknown"] == false
            && failure["cleanup_unknown"] == false
            && !snapshot
                .observations
                .iter()
                .any(|o| o["step"].is_null() && o["event"]["type"] == "failure")
            && projection["outcome"] == "unknown"
            && projection["failure"].is_null(),
        Failure::Integrity,
    )
}

fn remove_tree(parent: &File, name: &str, active: &Active) -> Result<()> {
    active.check()?;
    let stat =
        active.sys(|| rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory {
        active.sys(|| rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::empty()))?;
        return Ok(());
    }
    let directory = File::from(active.sys(|| {
        rustix::fs::openat(
            parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })?);
    for entry in names(&directory, 1_048_576, active)? {
        remove_tree(&directory, &entry, active)?;
    }
    active.sys(|| rustix::fs::unlinkat(parent, name, rustix::fs::AtFlags::REMOVEDIR))?;
    Ok(())
}

fn child(parent: &File, name: &str, create: bool, active: &Active) -> Result<Option<File>> {
    if create {
        let result = io::child_directory(parent, name, true, active)?;
        io::sync_parent(parent, active)?;
        Ok(Some(result))
    } else {
        Ok(io::existing_child_directory(parent, name, active)?)
    }
}

fn names(directory: &File, maximum: usize, active: &Active) -> Result<Vec<String>> {
    active.check()?;
    let handle = active.io(|| directory.try_clone())?;
    let mut result = Vec::new();
    for entry in rustix::fs::Dir::read_from(&handle).map_err(|_| Failure::Storage)? {
        active.check()?;
        let entry = entry.map_err(|_| Failure::Storage)?;
        let name = entry.file_name().to_str().map_err(|_| Failure::Integrity)?;
        if matches!(name, "." | "..") {
            continue;
        }
        require(result.len() < maximum, Failure::Bound)?;
        result.push(name.to_owned());
    }
    active.check()?;
    result.sort();
    Ok(result)
}

fn read(
    directory: &File,
    name: &str,
    kind: &str,
    active: &Active,
    bytes: &mut u64,
) -> Result<Option<Value>> {
    let limit = if kind == "request" { 262144 } else { 65536 };
    let Some((raw, _)) = io::read(directory, name, limit, active)? else {
        return Ok(None);
    };
    *bytes = bytes.checked_add(raw.len() as u64).ok_or(Failure::Bound)?;
    require(*bytes <= 33_554_432, Failure::Bound)?;
    require(raw.last() == Some(&b'\n'), Failure::Integrity)?;
    Ok(Some(schema::decode(
        &raw[..raw.len() - 1],
        kind,
        limit as usize,
    )?))
}

fn publish(
    directory: &File,
    name: &str,
    value: &Value,
    kind: &str,
    active: &Active,
    publication: &AtomicU8,
) -> Result<()> {
    let mut bytes = canonical(value)?;
    let limit = if kind == "request" { 262144 } else { 65536 };
    schema::validate(&bytes, kind, limit)?;
    bytes.push(b'\n');
    require(bytes.len() <= limit, Failure::Bound)?;

    let temporary = format!(".tmp-{}", sudo_nonce().map_err(|_| Failure::Storage)?);
    let prepared = io::prepare(directory, temporary, &bytes, active)?;
    active.check()?;
    publication.store(1, Ordering::Release);
    io::publish(directory, prepared, name, None, active)?;

    io::sync_parent(directory, active)?;
    publication.store(2, Ordering::Release);

    Ok(())
}

impl Work {
    fn target(&self, create: bool, active: &Active) -> Result<Option<File>> {
        let mut directory = io::open_directory(&self.root, active)?;
        for name in [
            "state",
            "infrastructure",
            "targets",
            self.scope["hash"].as_str().ok_or(Failure::Integrity)?,
        ] {
            let Some(next) = child(&directory, name, create, active)? else {
                return Ok(None);
            };
            directory = next;
        }
        Ok(Some(directory))
    }

    fn acquire(&mut self, create: bool, exclusive: bool, active: &Active) -> Result<bool> {
        if self.held.is_some() {
            self.revalidate(active)?;
            require(
                !exclusive || self.held.as_ref().is_some_and(|h| h.exclusive),
                Failure::Busy,
            )?;
            return Ok(true);
        }
        let Some(target) = self.target(create, active)? else {
            return Ok(false);
        };
        let target_identity = io::identity(&target, active)?;
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let lock = if create {
            active.check()?;
            let opened = rustix::fs::openat(
                &target,
                "mutation.lock",
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            );
            active.check()?;
            match opened {
                Ok(fd) => {
                    let f = File::from(fd);
                    active.io(|| f.sync_all())?;
                    io::sync_parent(&target, active)?;
                    f
                }
                Err(rustix::io::Errno::EXIST) => {
                    File::from(active.sys(|| {
                        rustix::fs::openat(&target, "mutation.lock", flags, Mode::empty())
                    })?)
                }
                Err(_) => return Err(Failure::Storage),
            }
        } else {
            File::from(
                active
                    .sys(|| rustix::fs::openat(&target, "mutation.lock", flags, Mode::empty()))?,
            )
        };
        io::owned(&lock, false, active)?;
        require(
            active.io(|| lock.metadata())?.len() == 0,
            Failure::Integrity,
        )?;
        active.check()?;
        rustix::fs::flock(
            &lock,
            if exclusive {
                FlockOperation::NonBlockingLockExclusive
            } else {
                FlockOperation::NonBlockingLockShared
            },
        )
        .map_err(|_| Failure::Busy)?;
        active.check()?;
        let lock_identity = io::identity(&lock, active)?;
        self.held = Some(Held {
            target,
            target_identity,
            lock,
            lock_identity,
            exclusive,
        });
        self.revalidate(active)?;
        Ok(true)
    }

    fn revalidate(&self, active: &Active) -> Result<()> {
        let h = self.held.as_ref().ok_or(Failure::Ownership)?;
        let target = self.target(false, active)?.ok_or(Failure::Ownership)?;
        require(
            io::identity(&target, active)? == h.target_identity,
            Failure::Ownership,
        )?;
        let (_, identity) =
            io::read(&target, "mutation.lock", 0, active)?.ok_or(Failure::Ownership)?;
        io::owned(&h.lock, false, active)?;
        require(
            identity == h.lock_identity && identity == io::identity(&h.lock, active)?,
            Failure::Ownership,
        )?;
        Ok(())
    }

    fn structure(&self, active: &Active, creating: bool) -> Result<()> {
        let h = self.held.as_ref().ok_or(Failure::Ownership)?;
        let mut present = names(&h.target, 5, active)?;
        require(
            present.iter().all(|s| {
                matches!(
                    s.as_str(),
                    "owner.json" | "mutation.lock" | "operations" | "waves" | "history"
                )
            }),
            Failure::Integrity,
        )?;
        if present.iter().any(|s| s == "history") && !self.pruning {
            require(
                self.read_intent(active)?
                    .is_none_or(|(intent, _)| intent["phase"] != "local"),
                Failure::Busy,
            )?;
        }
        present.retain(|s| s != "history");
        if !creating {
            require(
                present == ["mutation.lock", "operations", "owner.json"]
                    || present == ["mutation.lock", "operations", "owner.json", "waves"],
                Failure::Integrity,
            )?;
        }
        Ok(())
    }

    fn next(&self, active: &Active) -> Result<u64> {
        let h = self.held.as_ref().ok_or(Failure::Ownership)?;
        let mut sequences = Vec::new();
        if let Some(operations) = child(&h.target, "operations", false, active)? {
            for id in names(&operations, 16384, active)? {
                require(operation_id(&id), Failure::Integrity)?;
                let directory =
                    child(&operations, &id, false, active)?.ok_or(Failure::Integrity)?;
                let stored = io::read(
                    &directory,
                    "summary.json",
                    crate::k3s::history::summary::LIMIT as u64,
                    active,
                )
                .ok()
                .flatten()
                .and_then(|(raw, _)| crate::k3s::history::summary::decode(&raw).ok())
                .filter(|summary| summary["operation"] == id.as_str());
                let sequence = match stored {
                    Some(summary) => summary["sequence"].as_u64(),
                    None => read(&directory, "request.json", "request", active, &mut 0)?
                        .ok_or(Failure::Integrity)?["sequence"]
                        .as_u64(),
                };
                sequences.push(sequence.ok_or(Failure::Integrity)?);
            }
        }
        let pruned = match child(&h.target, "history", false, active)? {
            None => None,
            Some(history) => match io::read(
                &history,
                "checkpoint.json",
                crate::k3s::history::checkpoint::LIMIT as u64,
                active,
            )? {
                None => None,
                Some((raw, _)) => {
                    let checkpoint = crate::k3s::history::checkpoint::decode(&raw)
                        .map_err(|_| Failure::Integrity)?;
                    require(checkpoint["scope"] == self.scope, Failure::Ownership)?;
                    Some(
                        checkpoint["pruned_through_sequence"]
                            .as_u64()
                            .ok_or(Failure::Integrity)?,
                    )
                }
            },
        };
        Ok(crate::k3s::history::next_sequence(&sequences, pruned))
    }

    fn load(&self, operation: &str, active: &Active) -> Result<Snapshot> {
        let h = self.held.as_ref().ok_or(Failure::Ownership)?;
        let mut bytes = 0;
        let owner = read(&h.target, "owner.json", "owner", active, &mut bytes)?
            .ok_or(Failure::Integrity)?;
        require(
            owner["scope"] == self.scope
                && owner["lock_identity"] == json!([h.lock_identity.0, h.lock_identity.1]),
            Failure::Ownership,
        )?;
        let operations =
            child(&h.target, "operations", false, active)?.ok_or(Failure::Integrity)?;
        let directory = child(&operations, operation, false, active)?.ok_or(Failure::Readiness)?;
        let entries: Vec<String> = names(&directory, 16, active)?
            .into_iter()
            .filter(|n| !n.starts_with(SUMMARY_TEMPORARY))
            .collect();
        require(
            entries == ["attempts", "observations", "request.json", "steps"]
                || entries
                    == [
                        "attempts",
                        "observations",
                        "request.json",
                        "steps",
                        "summary.json",
                    ],
            Failure::Integrity,
        )?;
        bytes = 0;
        let request = read(&directory, "request.json", "request", active, &mut bytes)?
            .ok_or(Failure::Integrity)?;
        require(
            request["scope"] == self.scope
                && request["owner"] == owner["owner"]
                && request["operation"] == operation,
            Failure::Ownership,
        )?;
        let mut snapshot = Snapshot {
            owner,
            request,
            attempts: Vec::new(),
            steps: Vec::new(),
            observations: Vec::new(),
        };
        for (name, kind, maximum, dest) in [
            ("attempts", "attempt", 128, &mut snapshot.attempts),
            ("steps", "step-record", 1024, &mut snapshot.steps),
            (
                "observations",
                "observation",
                4096,
                &mut snapshot.observations,
            ),
        ] {
            let directory = child(&directory, name, false, active)?.ok_or(Failure::Integrity)?;
            for name in names(&directory, maximum, active)? {
                let id = name.strip_suffix(".json").ok_or(Failure::Integrity)?;
                require(
                    if kind == "attempt" {
                        nonce(id)
                    } else {
                        id.parse::<u32>()
                            .ok()
                            .is_some_and(|n| n > 0 && n.to_string() == id)
                    },
                    Failure::Integrity,
                )?;
                let value =
                    read(&directory, &name, kind, active, &mut bytes)?.ok_or(Failure::Integrity)?;
                require(
                    value["scope"] == self.scope
                        && value["owner"] == snapshot.owner["owner"]
                        && value["operation"] == operation,
                    Failure::Ownership,
                )?;
                let field = match kind {
                    "attempt" => "attempt",
                    "step-record" => "step",
                    _ => "sequence",
                };
                require(
                    if kind == "attempt" {
                        value[field] == id
                    } else {
                        value[field].as_u64() == id.parse().ok()
                    },
                    Failure::Integrity,
                )?;
                dest.push(value);
            }
        }
        snapshot.attempts.sort_by_key(|a| a["steps"][0].as_u64());
        snapshot.steps.sort_by_key(|v| v["step"].as_u64());
        snapshot
            .observations
            .sort_by_key(|v| v["sequence"].as_u64());
        for (i, observation) in snapshot.observations.iter().enumerate() {
            require(observation["sequence"] == i + 1, Failure::Integrity)?;
        }
        snapshot.checked(Some([
            snapshot.attempts.len(),
            snapshot.steps.len(),
            snapshot.observations.len(),
        ]))?;
        Ok(snapshot)
    }

    fn load_waves(&self, owner: &Value, active: &Active) -> Result<Vec<WaveRecord>> {
        let h = self.held.as_ref().ok_or(Failure::Ownership)?;
        let Some(waves) = child(&h.target, "waves", false, active)? else {
            return Ok(Vec::new());
        };
        let mut records = Vec::new();
        for name in names(&waves, 1024, active)? {
            require(nonce(&name), Failure::Integrity)?;
            let directory = child(&waves, &name, false, active)?.ok_or(Failure::Integrity)?;
            let files = names(&directory, 2, active)?;
            require(
                files == ["boundary.json"] || files == ["boundary.json", "gate.json"],
                Failure::Integrity,
            )?;
            let boundary = read(
                &directory,
                "boundary.json",
                "AgentWaveBoundary",
                active,
                &mut 0,
            )?
            .ok_or(Failure::Integrity)?;
            require(
                boundary["id"] == name
                    && boundary["scope"] == self.scope
                    && boundary["owner"] == owner["owner"]
                    && boundary["cluster"] == owner["cluster"],
                Failure::Ownership,
            )?;
            let gate = if files.len() == 2 {
                let gate = read(&directory, "gate.json", "AgentWaveGate", active, &mut 0)?
                    .ok_or(Failure::Integrity)?;
                require(
                    gate["id"] == name
                        && gate["scope"] == self.scope
                        && gate["owner"] == owner["owner"]
                        && gate["boundary_sha256"]
                            == hash("broil-k3s-agent-wave-boundary-v1", &boundary)?,
                    Failure::Ownership,
                )?;
                Some(gate)
            } else {
                None
            };
            records.push(WaveRecord { boundary, gate });
        }
        records.sort_by_key(|record| record.boundary["ordinal"].as_u64());
        for (index, record) in records.iter().enumerate() {
            require(
                record.boundary["ordinal"].as_u64() == Some((index + 1) as u64),
                Failure::Integrity,
            )?;
            if index == 0 {
                require(
                    record.boundary["previous_gate"].is_null(),
                    Failure::Integrity,
                )?;
            } else {
                let prior = &records[index - 1];
                let gate = prior.gate.as_ref().ok_or(Failure::Integrity)?;
                require(
                    record.boundary["previous_gate"]
                        == json!({
                            "id":prior.boundary["id"],
                            "gate_sha256":hash("broil-k3s-agent-wave-gate-v1", gate)?
                        }),
                    Failure::Integrity,
                )?;
            }
            if let Some(gate) = &record.gate {
                self.verify_wave_gate(gate, &record.boundary, None, active)?;
            }
        }
        Ok(records)
    }

    fn verify_wave_gate(
        &self,
        gate: &Value,
        boundary: &Value,
        owner: Option<&Value>,
        active: &Active,
    ) -> Result<()> {
        validate_gate(&self.scope, gate, boundary, owner, &mut |id| {
            self.load(id, active)
        })
    }

    fn perform(&mut self, active: &Active) -> Result<()> {
        let action = std::mem::replace(&mut self.action, Action::Verify);
        match action {
            Action::Sequence => {
                self.sequence = 1;
                if !self.acquire(false, false, active)? {
                    return Ok(());
                }
                self.structure(active, true)?;
                self.sequence = self.next(active)?;
                self.revalidate(active)?;
            }
            Action::Release => {

                active.check()?;
                self.held = None;
                active.check()?;
            }
            Action::Lock(id) => {
                self.acquire(false, true, active)?;
                self.structure(active, false)?;
                self.snapshots = vec![self.load(&id, active)?];
                self.refresh(&id, active);
                self.revalidate(active)?;
            }
            Action::Inspect(operation) => {
                self.snapshots.clear();
                self.owner = None;
                if !self.acquire(false, false, active)? {
                    return Ok(());
                }
                self.structure(active, false)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let owner = read(&h.target, "owner.json", "owner", active, &mut 0)?
                    .ok_or(Failure::Integrity)?;
                require(
                    owner["scope"] == self.scope
                        && owner["lock_identity"] == json!([h.lock_identity.0, h.lock_identity.1]),
                    Failure::Ownership,
                )?;
                self.owner = Some(owner);
                let directory =
                    child(&h.target, "operations", false, active)?.ok_or(Failure::Integrity)?;
                let operations = names(&directory, OPERATION_CAP, active)?;
                require(
                    operations.iter().all(|s| operation_id(s)),
                    Failure::Integrity,
                )?;
                if let Some(id) = operation {
                    require(operations.contains(&id), Failure::Readiness)?;
                    self.snapshots.push(self.load(&id, active)?);
                } else {
                    for id in operations {
                        self.snapshots.push(self.load(&id, active)?);
                    }
                }
                self.revalidate(active)?;
            }
            Action::List => {
                self.snapshots.clear();
                self.unlisted.clear();
                self.owner = None;
                if !self.acquire(false, false, active)? {
                    return Ok(());
                }
                self.structure(active, false)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let owner = read(&h.target, "owner.json", "owner", active, &mut 0)?
                    .ok_or(Failure::Integrity)?;
                require(
                    owner["scope"] == self.scope
                        && owner["lock_identity"] == json!([h.lock_identity.0, h.lock_identity.1]),
                    Failure::Ownership,
                )?;
                self.owner = Some(owner);
                let directory =
                    child(&h.target, "operations", false, active)?.ok_or(Failure::Integrity)?;
                let operations = names(&directory, OPERATION_CAP, active)?;
                require(
                    operations.iter().all(|s| operation_id(s)),
                    Failure::Integrity,
                )?;
                let mut summaries = Vec::new();
                let mut rebuilt = std::collections::BTreeMap::new();
                for id in operations {
                    let record =
                        child(&directory, &id, false, active)?.ok_or(Failure::Integrity)?;
                    let stored = io::read(
                        &record,
                        "summary.json",
                        crate::k3s::history::summary::LIMIT as u64,
                        active,
                    )
                    .ok()
                    .flatten()
                    .and_then(|(raw, _)| crate::k3s::history::summary::decode(&raw).ok())
                    .filter(|summary| summary["operation"] == id.as_str());
                    let summary = match stored {
                        Some(summary) => summary,
                        None => {
                            require(rebuilt.len() < LISTED, Failure::Bound)?;
                            let snapshot = self.load(&id, active)?;
                            let summary = super::history::summary(&self.scope, &snapshot)?;
                            rebuilt.insert(id.clone(), snapshot);
                            summary
                        }
                    };
                    summaries.push(json!({"operation":summary["operation"],
                        "created_ms":summary["created_ms"],"outcome":summary["outcome"],
                        "completion_unknown":summary["completion_unknown"],
                        "cleanup_unknown":summary["cleanup_unknown"]}));
                }
                summaries.sort_by(|a, b| {
                    b["created_ms"]
                        .as_u64()
                        .cmp(&a["created_ms"].as_u64())
                        .then_with(|| a["operation"].as_str().cmp(&b["operation"].as_str()))
                });
                let unlisted = summaries.split_off(summaries.len().min(LISTED));
                let mut loaded = rebuilt.len();
                for summary in summaries {
                    let id = summary["operation"].as_str().ok_or(Failure::Integrity)?;
                    let snapshot = match rebuilt.remove(id) {
                        Some(snapshot) => snapshot,
                        None => {
                            loaded += 1;
                            require(loaded <= LISTED, Failure::Bound)?;
                            self.load(id, active)?
                        }
                    };
                    self.snapshots.push(snapshot);
                }
                self.unlisted = unlisted;
                self.revalidate(active)?;
            }
            Action::AgentContext => {
                self.acquire(false, true, active)?;
                self.structure(active, false)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let directory =
                    child(&h.target, "operations", false, active)?.ok_or(Failure::Integrity)?;
                self.snapshots.clear();
                for id in names(&directory, OPERATION_CAP, active)? {
                    require(operation_id(&id), Failure::Integrity)?;
                    self.snapshots.push(self.load(&id, active)?);
                }
                let owner = &self.snapshots.first().ok_or(Failure::Ownership)?.owner;
                self.waves = self.load_waves(owner, active)?;
                self.revalidate(active)?;
            }
            Action::WaveBoundary(boundary) => {
                self.revalidate(active)?;
                schema::validate(&canonical(&boundary)?, "AgentWaveBoundary", 65536)?;
                let owner = &self.snapshots.first().ok_or(Failure::Ownership)?.owner;
                require(
                    boundary["scope"] == self.scope
                        && boundary["owner"] == owner["owner"]
                        && boundary["cluster"] == owner["cluster"]
                        && boundary["members"] == owner["members"]
                        && boundary["ordinal"].as_u64() == Some((self.waves.len() + 1) as u64)
                        && self.waves.last().is_none_or(|record| record.gate.is_some())
                        && !self
                            .waves
                            .iter()
                            .any(|record| record.boundary["id"] == boundary["id"]),
                    Failure::Ownership,
                )?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let waves = child(&h.target, "waves", true, active)?.ok_or(Failure::Storage)?;
                let id = boundary["id"].as_str().ok_or(Failure::Integrity)?;
                active.sys(|| {
                    rustix::fs::mkdirat(&waves, id, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                })?;
                io::sync_parent(&waves, active)?;
                let directory = child(&waves, id, false, active)?.ok_or(Failure::Storage)?;
                publish(
                    &directory,
                    "boundary.json",
                    &boundary,
                    "AgentWaveBoundary",
                    active,
                    &self.publication,
                )?;
                self.waves.push(WaveRecord {
                    boundary: *boundary,
                    gate: None,
                });
                self.revalidate(active)?;
            }
            Action::WaveGate(gate) => {
                self.revalidate(active)?;
                schema::validate(&canonical(&gate)?, "AgentWaveGate", 65536)?;
                let record = self.waves.last().ok_or(Failure::Ownership)?;
                require(
                    record.gate.is_none()
                        && gate["id"] == record.boundary["id"]
                        && gate["boundary_sha256"]
                            == hash("broil-k3s-agent-wave-boundary-v1", &record.boundary)?,
                    Failure::Ownership,
                )?;
                let owner = &self.snapshots.first().ok_or(Failure::Ownership)?.owner;
                self.verify_wave_gate(&gate, &record.boundary, Some(owner), active)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let waves = child(&h.target, "waves", false, active)?.ok_or(Failure::Integrity)?;
                let id = gate["id"].as_str().ok_or(Failure::Integrity)?;
                let directory = child(&waves, id, false, active)?.ok_or(Failure::Integrity)?;
                publish(
                    &directory,
                    "gate.json",
                    &gate,
                    "AgentWaveGate",
                    active,
                    &self.publication,
                )?;
                self.waves.last_mut().ok_or(Failure::Ownership)?.gate = Some(*gate);
                self.revalidate(active)?;
            }
            Action::Create {
                mut owner,
                request,
                attempt,
            } => {
                self.acquire(true, true, active)?;
                self.structure(active, true)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                owner["lock_identity"] = json!([h.lock_identity.0, h.lock_identity.1]);
                require(
                    owner["scope"] == self.scope
                        && request["scope"] == self.scope
                        && request["owner"] == owner["owner"],
                    Failure::Ownership,
                )?;
                Snapshot {
                    owner: (*owner).clone(),
                    request: (*request).clone(),
                    attempts: vec![(*attempt).clone()],
                    steps: Vec::new(),
                    observations: Vec::new(),
                }
                .consistent()?;
                if let Some(old) = read(&h.target, "owner.json", "owner", active, &mut 0)? {
                    require(old == *owner, Failure::Ownership)?;
                } else {
                    publish(
                        &h.target,
                        "owner.json",
                        &owner,
                        "owner",
                        active,
                        &self.publication,
                    )?;
                }
                let operations =
                    child(&h.target, "operations", true, active)?.ok_or(Failure::Storage)?;
                let present = names(&operations, OPERATION_CAP, active)?;
                let limit = if self.reserve {
                    OPERATION_CAP
                } else {
                    OPERATION_CAP - OPERATION_RESERVE
                };
                require(
                    present.len() < limit && present.iter().all(|v| operation_id(v)),
                    Failure::Bound,
                )?;
                require(
                    request["sequence"].as_u64() == Some(self.next(active)?),
                    Failure::Busy,
                )?;
                let id = request["operation"].as_str().ok_or(Failure::Integrity)?;
                require(
                    operation_id(id) && !present.iter().any(|v| v == id),
                    Failure::Integrity,
                )?;
                if let Some(receipts) = &self.receipts {
                    receipts.publication(&self.scope, &attempt, false)?;
                }
                active.sys(|| {
                    rustix::fs::mkdirat(&operations, id, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                })?;
                io::sync_parent(&operations, active)?;
                let directory = child(&operations, id, false, active)?.ok_or(Failure::Storage)?;
                for name in ["attempts", "steps", "observations"] {
                    child(&directory, name, true, active)?;
                }
                publish(
                    &directory,
                    "request.json",
                    &request,
                    "request",
                    active,
                    &self.publication,
                )?;
                self.write_attempt(&directory, &attempt, active)?;
                if let Some(receipts) = &self.receipts {
                    receipts.publication(&self.scope, &attempt, true)?;
                }
                self.snapshots = vec![self.load(id, active)?];
                self.refresh(id, active);
                self.revalidate(active)?;
            }
            Action::Attempt(attempt) => {
                self.acquire(false, true, active)?;
                self.structure(active, false)?;
                let id = attempt["operation"].as_str().ok_or(Failure::Integrity)?;
                let mut snapshot = self.load(id, active)?;
                require(snapshot.attempts.len() < 128, Failure::Bound)?;
                snapshot.attempts.push((*attempt).clone());
                snapshot.checked(Some([
                    snapshot.attempts.len() - 1,
                    snapshot.steps.len(),
                    snapshot.observations.len(),
                ]))?;
                let operations = child(
                    &self.held.as_ref().ok_or(Failure::Ownership)?.target,
                    "operations",
                    false,
                    active,
                )?
                .ok_or(Failure::Integrity)?;
                let directory = child(&operations, id, false, active)?.ok_or(Failure::Integrity)?;
                if let Some(receipts) = &self.receipts {
                    receipts.publication(&self.scope, &attempt, false)?;
                }
                self.write_attempt(&directory, &attempt, active)?;
                if let Some(receipts) = &self.receipts {
                    receipts.publication(&self.scope, &attempt, true)?;
                }
                snapshot.attempts.sort_by_key(|a| a["steps"][0].as_u64());
                self.snapshots = vec![snapshot];
                self.refresh(id, active);
                self.revalidate(active)?;
            }
            Action::Step(step) => {
                self.acquire(false, true, active)?;
                self.structure(active, false)?;
                let id = step["operation"].as_str().ok_or(Failure::Integrity)?;
                let mut snapshot = self.load(id, active)?;
                require(snapshot.steps.len() < 1024, Failure::Bound)?;
                snapshot.steps.push((*step).clone());
                snapshot.checked(Some([
                    snapshot.attempts.len(),
                    snapshot.steps.len() - 1,
                    snapshot.observations.len(),
                ]))?;
                let operations = child(
                    &self.held.as_ref().ok_or(Failure::Ownership)?.target,
                    "operations",
                    false,
                    active,
                )?
                .ok_or(Failure::Integrity)?;
                let directory = child(&operations, id, false, active)?.ok_or(Failure::Integrity)?;
                let steps = child(&directory, "steps", false, active)?.ok_or(Failure::Integrity)?;
                self.revalidate(active)?;
                publish(
                    &steps,
                    &format!("{}.json", step["step"].as_u64().ok_or(Failure::Integrity)?),
                    &step,
                    "step-record",
                    active,
                    &self.publication,
                )?;
                snapshot.steps.sort_by_key(|v| v["step"].as_u64());
                self.snapshots = vec![snapshot];
                self.refresh(id, active);
                self.revalidate(active)?;
            }
            Action::Append(mut event) => {
                self.acquire(false, true, active)?;
                self.structure(active, false)?;
                let id = event["operation"]
                    .as_str()
                    .ok_or(Failure::Integrity)?
                    .to_owned();
                let mut snapshot = self.load(&id, active)?;
                require(snapshot.observations.len() < 4096, Failure::Bound)?;
                event["sequence"] = json!(snapshot.observations.len() + 1);
                require(
                    event["scope"] == self.scope && event["owner"] == snapshot.owner["owner"],
                    Failure::Ownership,
                )?;
                let operations = child(
                    &self.held.as_ref().ok_or(Failure::Ownership)?.target,
                    "operations",
                    false,
                    active,
                )?
                .ok_or(Failure::Integrity)?;
                let directory =
                    child(&operations, &id, false, active)?.ok_or(Failure::Integrity)?;
                let observations =
                    child(&directory, "observations", false, active)?.ok_or(Failure::Integrity)?;
                if event["step"].is_null() && event["event"]["type"] == "failure" {
                    unknown_run_event(&snapshot, &event)?;
                }
                snapshot.observations.push((*event).clone());
                snapshot.checked(Some([
                    snapshot.attempts.len(),
                    snapshot.steps.len(),
                    snapshot.observations.len() - 1,
                ]))?;
                self.revalidate(active)?;
                let receipt_attempt = snapshot
                    .attempts
                    .iter()
                    .find(|a| a["attempt"] == event["attempt"]);
                if let (Some(receipts), Some(attempt)) = (&self.receipts, receipt_attempt) {
                    receipts.publication(&self.scope, attempt, false)?;
                }
                publish(
                    &observations,
                    &format!("{}.json", snapshot.observations.len()),
                    &event,
                    "observation",
                    active,
                    &self.publication,
                )?;
                if let (Some(receipts), Some(attempt)) = (&self.receipts, receipt_attempt) {
                    receipts.publication(&self.scope, attempt, true)?;
                }
                self.snapshots = vec![snapshot];
                self.refresh(&id, active);
            }
            Action::ReplaceOwner {
                mut owner,
                operation,
            } => {
                self.acquire(false, true, active)?;
                self.structure(active, false)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                owner["lock_identity"] = json!([h.lock_identity.0, h.lock_identity.1]);
                let (raw, identity) =
                    io::read(&h.target, "owner.json", 65536, active)?.ok_or(Failure::Integrity)?;
                require(raw.last() == Some(&b'\n'), Failure::Integrity)?;
                let old = schema::decode(&raw[..raw.len() - 1], "owner", 65536)?;
                let maintained = {
                    let snapshot = self.load(&operation, active)?;
                    super::member::carries(&snapshot.request["action"])
                        .then(|| super::member::replaced(&old, &owner, &snapshot))
                };
                let resources_admitted = if let Some(replaced) = maintained {
                    replaced
                } else if owner["resources"] == old["resources"] {
                    true
                } else {
                    let snapshot = self.load(&operation, active)?;
                    let prior = old["resources"].as_array().ok_or(Failure::Integrity)?;
                    let pair = snapshot.request["resources"]
                        .as_array()
                        .ok_or(Failure::Integrity)?;
                    let successor = owner["resources"].as_array().ok_or(Failure::Integrity)?;
                    if let Some(family) = snapshot.request["action"]
                        .as_str()
                        .and_then(|action| action.strip_prefix("reconcile-"))
                    {
                        let count = super::network::family(&snapshot.request["action"]).planned;
                        let storage = family == "registry-storage";
                        let replication = family == "registry-replication";
                        let prefix = if storage {
                            "registry-volume-".to_owned()
                        } else if replication {
                            "registry-reader-object-".to_owned()
                        } else {
                            format!("{family}-object-")
                        };
                        let observed = if replication {
                            "replication-observation".to_owned()
                        } else {
                            format!("{family}-observation")
                        };
                        let create = format!("lifecycle:{family}-create-object");
                        let changed: Vec<_> = prior
                            .iter()
                            .zip(successor)
                            .enumerate()
                            .filter(|(_, (before, after))| before != after)
                            .collect();
                        let selected = changed.first().map(|(index, _)| *index);
                        let identity = snapshot.observations.iter().rev().find(|observation| {
                            observation["event"]["type"] == "identity"
                                && observation["event"]["member"].is_null()
                                && observation["source"]["kind"] == "controller"
                        });
                        changed.len() == 1
                            && successor.len() == prior.len()
                            && if replication {
                                pair.iter().filter(|r| r["kind"] == "service").count() == count
                            } else {
                                pair.iter().filter(|r| r["kind"] != "bootstrap-assets").count() == count
                            }
                            && selected.is_some_and(|index| {
                                index < prior.len()
                                    && prior[index]["id"].as_str().is_some_and(|id| id.starts_with(&prefix))
                            })
                            && selected.is_some_and(|index| {
                                let before = &prior[index];
                                let after = &successor[index];
                                let planned = pair.iter().find(|r| r["id"] == before["id"]);
                                let mut expected = before.clone();
                                expected["uid"] = after["uid"].clone();
                                before["uid"].is_null()
                                    && after["uid"].as_str().is_some_and(super::super::protocol::opaque)
                                    && *after == expected
                                    && planned == Some(before)
                                    && identity.is_some_and(|event| {
                                        event["event"]["cluster"] == old["cluster"]
                                            && event["event"]["resources"] == json!([after])
                                            && snapshot.observations.iter().any(|o| {
                                                o["event"]["type"] == observed.as_str()
                                                    && !o["event"][if matches!(family, "registry-storage" | "registry-service" | "registry-endpoint" | "registry-auth" | "registry-token" | "registry-replication") { "objects" } else { "services" }].is_null()
                                                    && o["sequence"].as_u64() < event["sequence"].as_u64()
                                                    && o["event"]["objects"].as_array().is_some_and(|objects| {
                                                        objects.iter().any(|item| {
                                                            item["name"] == after["name"]
                                                                && item["namespace"] == after["namespace"]
                                                                && item["uid"] == after["uid"]
                                                                && item["class"] == bound_class(family)
                                                        })
                                                    })
                                            })
                                            && snapshot.steps.iter().any(|step| {
                                                step["action"].as_str().is_some_and(|a| {
                                                    a == create || a.strip_suffix('s') == Some(&create)
                                                })
                                                    && step["resource"] == *before
                                                    && snapshot.succeeded(step)
                                                    && snapshot.observations.iter().any(|o| {
                                                        o["step"] == step["step"]
                                                            && o["event"]["type"] == "receiver"
                                                            && o["event"]["receipt"]["resource_identity"] == after["uid"]
                                                    })
                                            })
                                    })
                            })
                            && owner["members"] == old["members"]
                            && owner["cluster"] == old["cluster"]
                    } else if snapshot.request["action"] == "prepare-node-registry" {
                        super::node_registry::replaced(&old, &owner, &snapshot)
                    } else {
                        let agent = snapshot.request["action"] == "join-agent";
                        let actions = [
                            "lifecycle:prepare-join-source",
                            "prepare-input",
                            "admit-credential",
                            if agent {
                                "credential:read-agent-join"
                            } else {
                                "credential:read-server-join"
                            },
                            if agent {
                                "credential:supply-agent-join"
                            } else {
                                "credential:supply-server-join"
                            },
                        ];
                        let joined = pair.get(1).and_then(|input| {
                            old["members"].as_array()?.iter().find(|member| {
                                member["machine"] == input["machine"]
                                    && member["role"] == if agent { "agent" } else { "server" }
                                    && member["node_uid"].is_null()
                            })
                        });
                        pair.len() == 2
                            && successor.len() == prior.len() + 2
                            && if snapshot.request["action"] == "join-server" || agent {
                                joined
                                    .and_then(|m| m["member"].as_str())
                                    .is_some_and(|m| admit_join_successor(&old, &owner, m).is_ok())
                            } else {
                                successor[..prior.len()] == prior[..]
                            }
                            && successor[prior.len()..] == pair[..]
                            && snapshot
                                .steps
                                .iter()
                                .filter(|step| {
                                    step["action"] == "admit-credential" && snapshot.succeeded(step)
                                })
                                .count()
                                == 2
                            && actions.iter().all(|action| {
                                snapshot.steps.iter().any(|step| {
                                    step["action"] == *action && snapshot.succeeded(step)
                                })
                            })
                            && if snapshot.request["action"] == "join-server" || agent {
                                let publication = snapshot.steps.iter().find(|step| {
                                    step["action"]
                                        == if agent {
                                            "lifecycle:publish-agent"
                                        } else {
                                            "lifecycle:publish-member"
                                        }
                                        && step["recipient"]["machine"] == pair[1]["machine"]
                                        && snapshot.succeeded(step)
                                });
                                publication.is_some_and(|step| {
                                    let published =
                                        snapshot.observations.iter().find(|observation| {
                                            observation["step"] == step["step"]
                                                && observation["dispatch"] == step["dispatch"]
                                                && observation["event"]["type"]
                                                    == "lifecycle-installation"
                                                && observation["event"]["class"] == "owned"
                                        });
                                    let repaired = !agent
                                        && snapshot.observations.iter().any(|observation| {
                                            observation["step"] == step["step"]
                                                && observation["dispatch"] == step["dispatch"]
                                                && observation["event"]["type"] == "identity"
                                                && observation["event"]["member"]
                                                    == step["recipient"]
                                                && observation["event"]["cluster"] == old["cluster"]
                                        });
                                    let observed = published.or_else(|| {
                                        repaired
                                            .then(|| {
                                                snapshot.observations.iter().rev().find(
                                                    |observation| {
                                                        observation["event"]["type"]
                                                            == "lifecycle-installation"
                                                            && observation["event"]["member"]
                                                                == step["recipient"]
                                                            && observation["event"]["class"]
                                                                == "owned"
                                                    },
                                                )
                                            })
                                            .flatten()
                                    });
                                    observed.is_some_and(|observation| {
                                        let mut expected = old["members"].clone();
                                        let Some(members) = expected.as_array_mut() else {
                                            return false;
                                        };
                                        let Some(member) = members.iter_mut().find(|member| {
                                            member["machine"] == pair[1]["machine"]
                                                && member["role"]
                                                    == if agent { "agent" } else { "server" }
                                                && member["node_uid"].is_null()
                                        }) else {
                                            return false;
                                        };
                                        member["node_uid"] =
                                            observation["event"]["identity"]["node_uid"].clone();
                                        member["node_uid"].is_string()
                                            && observation["event"]["identity"]["cluster"]
                                                == old["cluster"]
                                            && owner["members"] == expected
                                            && owner["cluster"] == old["cluster"]
                                    })
                                })
                            } else {
                                snapshot.request["action"] == "prepare-server-inputs"
                                    && owner["members"] == old["members"]
                            }
                    }
                };
                require(
                    owner["scope"] == self.scope
                        && old["scope"] == self.scope
                        && owner["owner"] == old["owner"]
                        && owner["previous_generation"] == old["generation"]
                        && owner["generation"] != old["generation"]
                        && (maintained.is_some()
                            || owner["fingerprints"] == old["fingerprints"]
                                && owner["participants_sha256"] == old["participants_sha256"])
                        && resources_admitted,
                    Failure::Ownership,
                )?;
                let mut bytes = canonical(&owner)?;
                schema::validate(&bytes, "owner", 65536)?;
                bytes.push(b'\n');
                require(bytes.len() <= 65536, Failure::Bound)?;
                let temporary = format!(".tmp-{}", sudo_nonce().map_err(|_| Failure::Storage)?);
                self.revalidate(active)?;
                let prepared = io::prepare(&h.target, temporary, &bytes, active)?;
                active.check()?;
                self.publication.store(1, Ordering::Release);
                io::publish(&h.target, prepared, "owner.json", Some(identity), active)?;
                io::sync_parent(&h.target, active)?;
                self.publication.store(2, Ordering::Release);
                self.snapshots = vec![self.load(&operation, active)?];
                self.revalidate(active)?;
            }
            Action::PlanNetwork(mut owner, family) => {
                let prefix = format!("{family}-object-");
                let count = super::network::family(&json!(format!("reconcile-{family}"))).planned;
                self.acquire(false, true, active)?;
                self.structure(active, false)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                owner["lock_identity"] = json!([h.lock_identity.0, h.lock_identity.1]);
                let (raw, identity) =
                    io::read(&h.target, "owner.json", 65536, active)?.ok_or(Failure::Integrity)?;
                require(raw.last() == Some(&b'\n'), Failure::Integrity)?;
                let old = schema::decode(&raw[..raw.len() - 1], "owner", 65536)?;
                let prior = old["resources"].as_array().ok_or(Failure::Integrity)?;
                let successor = owner["resources"].as_array().ok_or(Failure::Integrity)?;
                if family == "registry-storage" {
                    let added = &successor[prior.len().min(successor.len())..];
                    let replicas = super::survivors(&old)?;
                    require(
                        owner["scope"] == old["scope"]
                            && owner["owner"] == old["owner"]
                            && owner["members"] == old["members"]
                            && owner["cluster"] == old["cluster"]
                            && !old["cluster"].is_null()
                            && owner["fingerprints"] == old["fingerprints"]
                            && owner["participants_sha256"] == old["participants_sha256"]
                            && owner["previous_generation"] == old["generation"]
                            && owner["generation"] != old["generation"]
                            && !replicas.is_empty()
                            && successor.len() == prior.len() + replicas.len()
                            && successor[..prior.len()] == prior[..]
                            && prior
                                .iter()
                                .filter(|r| {
                                    r["id"]
                                        .as_str()
                                        .is_some_and(|v| v.starts_with("network-object-"))
                                        && r["uid"].is_string()
                                })
                                .count()
                                == 12
                            && added.iter().zip(&replicas).all(|(r, m)| {
                                r["kind"] == "replica"
                                    && m["member"]
                                        .as_str()
                                        .is_some_and(|m| r["id"] == format!("registry-replica-{m}"))
                                    && !prior.iter().any(|p| p["id"] == r["id"])
                                    && r["owner"] == old["owner"]
                                    && r["generation"].as_str().is_some_and(nonce)
                                    && r["machine"] == m["machine"]
                                    && r["path"].is_string()
                                    && r["namespace"].is_null()
                                    && r["name"].is_null()
                                    && r["uid"].is_null()
                            }),
                        Failure::Ownership,
                    )?;
                } else if family == "registry-service" {
                    let added = &successor[prior.len().min(successor.len())..];
                    let bound = |prefix: &str| {
                        prior
                            .iter()
                            .filter(|r| {
                                r["id"].as_str().is_some_and(|v| v.starts_with(prefix))
                                    && r["uid"].is_string()
                            })
                            .count()
                    };
                    require(
                        owner["scope"] == old["scope"]
                            && owner["owner"] == old["owner"]
                            && owner["members"] == old["members"]
                            && owner["cluster"] == old["cluster"]
                            && !old["cluster"].is_null()
                            && owner["fingerprints"] == old["fingerprints"]
                            && owner["participants_sha256"] == old["participants_sha256"]
                            && owner["previous_generation"] == old["generation"]
                            && owner["generation"] != old["generation"]
                            && successor.len() == prior.len() + count
                            && successor[..prior.len()] == prior[..]
                            && bound("network-object-") == 12
                            && super::survivors(&old)?.iter().all(|m| {
                                prior.iter().any(|r| {
                                    m["member"]
                                        .as_str()
                                        .is_some_and(|m| r["id"] == format!("registry-replica-{m}"))
                                })
                            })
                            && !prior
                                .iter()
                                .any(|r| r["id"].as_str().is_some_and(|v| v.starts_with(&prefix)))
                            && added.iter().enumerate().all(|(n, r)| {
                                r["kind"] == "service"
                                    && r["id"] == format!("{prefix}{:02}", n + 1)
                                    && r["owner"] == old["owner"]
                                    && r["generation"].as_str().is_some_and(nonce)
                                    && r["machine"].is_null()
                                    && r["path"].is_null()
                                    && r["namespace"]
                                        == if n == 0 {
                                            Value::Null
                                        } else {
                                            json!("broil-registry")
                                        }
                                    && r["name"] == "broil-registry"
                                    && r["uid"].is_null()
                            }),
                        Failure::Ownership,
                    )?;
                } else if family == "registry-endpoint" {
                    let added = &successor[prior.len().min(successor.len())..];
                    let bound = |prefix: &str| {
                        prior
                            .iter()
                            .filter(|r| {
                                r["id"].as_str().is_some_and(|v| v.starts_with(prefix))
                                    && r["uid"].is_string()
                            })
                            .count()
                    };
                    let places = [
                        ("broil-registry", "broil-registry-endpoint"),
                        ("cert-manager", "broil-registry-tls"),
                        ("broil-registry", "broil-registry"),
                    ];
                    require(
                        owner["scope"] == old["scope"]
                            && owner["owner"] == old["owner"]
                            && owner["members"] == old["members"]
                            && owner["cluster"] == old["cluster"]
                            && !old["cluster"].is_null()
                            && owner["fingerprints"] == old["fingerprints"]
                            && owner["participants_sha256"] == old["participants_sha256"]
                            && owner["previous_generation"] == old["generation"]
                            && owner["generation"] != old["generation"]
                            && successor.len() == prior.len() + count
                            && successor[..prior.len()] == prior[..]
                            && bound("network-object-") == 12
                            && bound("registry-service-object-") == 5
                            && bound("certificate-object-") >= 1
                            && bound("ingress-object-") == 3
                            && !prior.iter().any(|r| {
                                r["id"]
                                    .as_str()
                                    .is_some_and(|v| v.starts_with("registry-endpoint-"))
                            })
                            && added.iter().enumerate().all(|(n, r)| {
                                r["owner"] == old["owner"]
                                    && r["generation"].as_str().is_some_and(nonce)
                                    && r["machine"].is_null()
                                    && r["path"].is_null()
                                    && r["uid"].is_null()
                                    && r["name"].is_string()
                                    && if n == 0 {
                                        r["kind"] == "endpoint"
                                            && r["id"] == "registry-endpoint-origin"
                                            && r["namespace"].is_null()
                                    } else {
                                        r["kind"] == "service"
                                            && r["id"] == format!("{prefix}{n:02}")
                                            && r["namespace"] == places[n - 1].0
                                            && r["name"] == places[n - 1].1
                                    }
                            }),
                        Failure::Ownership,
                    )?;
                } else if family == "registry-replication" {
                    let added = &successor[prior.len().min(successor.len())..];
                    let replicas = super::survivors(&old)?;
                    let fixed = added.len() == replicas.len() + 2;
                    require(
                        owner["scope"] == old["scope"]
                            && owner["owner"] == old["owner"]
                            && owner["members"] == old["members"]
                            && owner["cluster"] == old["cluster"]
                            && !old["cluster"].is_null()
                            && owner["fingerprints"] == old["fingerprints"]
                            && owner["participants_sha256"] == old["participants_sha256"]
                            && owner["previous_generation"] == old["generation"]
                            && owner["generation"] != old["generation"]
                            && fixed
                            && successor[..prior.len()] == prior[..]
                            && replicas.iter().all(|m| {
                                m["member"].as_str().is_some_and(|m| {
                                    prior
                                        .iter()
                                        .any(|r| r["id"] == format!("registry-replica-{m}"))
                                })
                            })
                            && added.iter().all(|r| {
                                !prior.iter().any(|p| p["id"] == r["id"])
                                    && r["owner"] == old["owner"]
                                    && r["generation"].as_str().is_some_and(nonce)
                                    && r["uid"].is_null()
                            })
                            && added.iter().zip(&replicas).all(|(r, m)| {
                                r["kind"] == "replication"
                                    && m["member"].as_str().is_some_and(|m| {
                                        r["id"] == format!("registry-replication-{m}")
                                    })
                                    && r["machine"] == m["machine"]
                                    && r["path"] == "/var/lib/broil-k3s-replication"
                                    && r["namespace"].is_null()
                                    && r["name"].is_null()
                            })
                            && added[replicas.len().min(added.len())..]
                                .iter()
                                .enumerate()
                                .all(|(n, r)| {
                                    r["kind"] == "service"
                                        && r["id"] == format!("registry-reader-object-{:02}", n + 1)
                                        && r["machine"].is_null()
                                        && r["path"].is_null()
                                        && r["namespace"] == "broil-registry"
                                        && r["name"] == "broil-registry-reader"
                                }),
                        Failure::Ownership,
                    )?;
                } else if family == "registry-token" {
                    let added = &successor[prior.len().min(successor.len())..];
                    let bound = |prefix: &str| {
                        prior
                            .iter()
                            .filter(|r| {
                                r["id"].as_str().is_some_and(|v| v.starts_with(prefix))
                                    && r["uid"].is_string()
                            })
                            .count()
                    };
                    require(
                        owner["scope"] == old["scope"]
                            && owner["owner"] == old["owner"]
                            && owner["members"] == old["members"]
                            && owner["cluster"] == old["cluster"]
                            && !old["cluster"].is_null()
                            && owner["fingerprints"] == old["fingerprints"]
                            && owner["participants_sha256"] == old["participants_sha256"]
                            && owner["previous_generation"] == old["generation"]
                            && owner["generation"] != old["generation"]
                            && successor.len() == prior.len() + count
                            && successor[..prior.len()] == prior[..]
                            && bound("network-object-") == 12
                            && bound("registry-service-object-") == 5
                            && bound("registry-endpoint-object-") == 3
                            && bound("registry-auth-object-signing") == 1
                            && !prior
                                .iter()
                                .any(|r| r["id"].as_str().is_some_and(|v| v.starts_with(&prefix)))
                            && added.iter().enumerate().all(|(n, r)| {
                                r["kind"] == "service"
                                    && r["id"] == format!("{prefix}{:02}", n + 1)
                                    && r["owner"] == old["owner"]
                                    && r["generation"].as_str().is_some_and(nonce)
                                    && r["machine"].is_null()
                                    && r["path"].is_null()
                                    && r["namespace"] == "broil-registry"
                                    && r["name"] == "broil-registry-token"
                                    && r["uid"].is_null()
                            }),
                        Failure::Ownership,
                    )?;
                } else if matches!(family, "issuer" | "certificate" | "registry-auth") {
                    let (anchor, anchors, namespace) = if family == "registry-auth" {
                        ("registry-service-object-", 5, "broil-registry")
                    } else {
                        ("cert-manager-object-01", 1, "cert-manager")
                    };
                    let bound = |prefix: &str| {
                        prior
                            .iter()
                            .filter(|r| {
                                r["id"].as_str().is_some_and(|v| v.starts_with(prefix))
                                    && r["uid"].is_string()
                            })
                            .count()
                    };
                    let added = successor.last().ok_or(Failure::Integrity)?;
                    require(
                        owner["scope"] == old["scope"]
                            && owner["owner"] == old["owner"]
                            && owner["members"] == old["members"]
                            && owner["cluster"] == old["cluster"]
                            && !old["cluster"].is_null()
                            && owner["fingerprints"] == old["fingerprints"]
                            && owner["participants_sha256"] == old["participants_sha256"]
                            && owner["previous_generation"] == old["generation"]
                            && owner["generation"] != old["generation"]
                            && successor.len() == prior.len() + count
                            && successor[..prior.len()] == prior[..]
                            && bound("network-object-") == 12
                            && bound(anchor) == anchors
                            && added["kind"] == planned_shape(family, &old).0
                            && added["id"]
                                .as_str()
                                .is_some_and(|id| id.starts_with(&prefix))
                            && !prior.iter().any(|r| r["id"] == added["id"])
                            && added["owner"] == old["owner"]
                            && added["generation"].as_str().is_some_and(nonce)
                            && added["machine"] == planned_shape(family, &old).1
                            && added["path"].is_null()
                            && added["namespace"] == namespace
                            && added["name"].is_string()
                            && added["uid"].is_null(),
                        Failure::Ownership,
                    )?;
                } else {
                    require(
                        owner["scope"] == old["scope"]
                            && owner["owner"] == old["owner"]
                            && owner["members"] == old["members"]
                            && owner["cluster"] == old["cluster"]
                            && !old["cluster"].is_null()
                            && owner["fingerprints"] == old["fingerprints"]
                            && owner["participants_sha256"] == old["participants_sha256"]
                            && owner["previous_generation"] == old["generation"]
                            && owner["generation"] != old["generation"]
                            && successor.len() == prior.len() + count
                            && successor[..prior.len()] == prior[..]
                            && !prior
                                .iter()
                                .any(|r| r["id"].as_str().is_some_and(|v| v.starts_with(&prefix)))
                            && (family == "network"
                                || prior
                                    .iter()
                                    .filter(|r| {
                                        r["id"]
                                            .as_str()
                                            .is_some_and(|v| v.starts_with("network-object-"))
                                            && r["uid"].is_string()
                                    })
                                    .count()
                                    == 12)
                            && successor[prior.len()..].iter().enumerate().all(
                                |(index, resource)| {
                                    let (namespace, name) = match family {
                                        "ingress" => (
                                            Some("kube-system"),
                                            super::ingress::INGRESS_OBJECTS[index],
                                        ),
                                        "cert-manager" => (None, "cert-manager"),
                                        _ => NETWORK_OBJECTS[index],
                                    };
                                    resource["kind"]
                                        == if family != "network" || index < 6 {
                                            "service"
                                        } else {
                                            "storage"
                                        }
                                        && resource["id"] == format!("{prefix}{:02}", index + 1)
                                        && resource["owner"] == old["owner"]
                                        && resource["generation"].as_str().is_some_and(nonce)
                                        && resource["machine"].is_null()
                                        && resource["path"].is_null()
                                        && resource["namespace"] == json!(namespace)
                                        && resource["name"] == json!(name)
                                        && resource["uid"].is_null()
                                },
                            ),
                        Failure::Ownership,
                    )?;
                }
                let mut bytes = canonical(&owner)?;
                schema::validate(&bytes, "owner", 65536)?;
                bytes.push(b'\n');
                require(bytes.len() <= 65536, Failure::Bound)?;
                let temporary = format!(".tmp-{}", sudo_nonce().map_err(|_| Failure::Storage)?);
                self.revalidate(active)?;
                let prepared = io::prepare(&h.target, temporary, &bytes, active)?;
                active.check()?;
                self.publication.store(1, Ordering::Release);
                io::publish(&h.target, prepared, "owner.json", Some(identity), active)?;
                io::sync_parent(&h.target, active)?;
                self.publication.store(2, Ordering::Release);
                let operation =
                    self.snapshots.first().ok_or(Failure::Integrity)?.request["operation"]
                        .as_str()
                        .ok_or(Failure::Integrity)?
                        .to_owned();
                self.snapshots = vec![self.load(&operation, active)?];
                self.revalidate(active)?;
            }
            Action::Verify => self.revalidate(active)?,
            Action::History => {
                self.history = HistoryRead::default();
                if !self.acquire(false, true, active)? {
                    return Ok(());
                }
                self.structure(active, false)?;
                self.read_history(active)?;
                self.revalidate(active)?;
            }
            Action::Load(operations) => {
                self.revalidate(active)?;
                let mut snapshots = Vec::with_capacity(operations.len());
                for id in &operations {
                    require(operation_id(id), Failure::Integrity)?;
                    snapshots.push(self.load(id, active)?);
                }
                self.snapshots = snapshots;
                self.revalidate(active)?;
            }
            Action::Requests(operations) => {
                self.revalidate(active)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let directory =
                    child(&h.target, "operations", false, active)?.ok_or(Failure::Integrity)?;
                let mut hashes = Vec::with_capacity(operations.len());
                for id in &operations {
                    require(operation_id(id), Failure::Integrity)?;
                    let operation =
                        child(&directory, id, false, active)?.ok_or(Failure::Readiness)?;
                    let request = read(&operation, "request.json", "request", active, &mut 0)?
                        .ok_or(Failure::Integrity)?;
                    require(
                        request["scope"] == self.scope && request["operation"] == id.as_str(),
                        Failure::Ownership,
                    )?;
                    hashes.push(hash("broil-infra-request-v1", &request)?);
                }
                self.hashes = hashes;
                self.revalidate(active)?;
            }
            Action::Intent(intent) => {
                self.revalidate(active)?;
                require(self.pruning, Failure::Ownership)?;
                let bytes =
                    crate::k3s::history::intent::encode(&intent).map_err(|_| Failure::Bound)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let history = child(&h.target, "history", true, active)?.ok_or(Failure::Storage)?;
                let current = self.read_intent(active)?.map(|(_, identity)| identity);
                require(current == self.history.intent_identity, Failure::Ownership)?;
                let temporary = format!(".tmp-{}", sudo_nonce().map_err(|_| Failure::Storage)?);
                let prepared = io::prepare(&history, temporary, &bytes, active)?;
                self.publication.store(1, Ordering::Release);
                let identity = match current {
                    Some(expected) => {
                        io::publish(&history, prepared, "intent.json", Some(expected), active)?
                    }
                    None => io::publish_new(&history, prepared, "intent.json", active)?
                        .ok_or(Failure::Busy)?,
                };
                io::sync_parent(&history, active)?;
                self.publication.store(2, Ordering::Release);
                self.history.intent = Some(*intent);
                self.history.intent_identity = Some(identity);
                self.revalidate(active)?;
            }
            Action::RemoveIntent => {
                self.revalidate(active)?;
                require(self.pruning, Failure::Ownership)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let history =
                    child(&h.target, "history", false, active)?.ok_or(Failure::Integrity)?;
                let current = self.read_intent(active)?.map(|(_, identity)| identity);
                require(
                    current.is_some() && current == self.history.intent_identity,
                    Failure::Ownership,
                )?;
                active.sys(|| {
                    rustix::fs::unlinkat(&history, "intent.json", rustix::fs::AtFlags::empty())
                })?;
                io::sync_parent(&history, active)?;
                self.history.intent = None;
                self.history.intent_identity = None;
                self.revalidate(active)?;
            }
            Action::Trash { candidates, batch } => {
                self.revalidate(active)?;
                require(self.pruning, Failure::Ownership)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let operations =
                    child(&h.target, "operations", false, active)?.ok_or(Failure::Integrity)?;
                let history = child(&h.target, "history", true, active)?.ok_or(Failure::Storage)?;
                let trash = child(&history, "trash", true, active)?.ok_or(Failure::Storage)?;
                let candidates: std::collections::BTreeSet<String> =
                    candidates.into_iter().collect();
                let present = names(&trash, OPERATION_CAP, active)?;
                require(
                    present.iter().all(|id| candidates.contains(id)),
                    Failure::Integrity,
                )?;
                for id in &batch {
                    require(
                        operation_id(id) && candidates.contains(id),
                        Failure::Integrity,
                    )?;
                    if child(&operations, id, false, active)?.is_none() {
                        continue;
                    }
                    active.check()?;
                    self.publication.store(1, Ordering::Release);
                    active.sys(|| {
                        rustix::fs::renameat_with(
                            &operations,
                            id.as_str(),
                            &trash,
                            id.as_str(),
                            rustix::fs::RenameFlags::NOREPLACE,
                        )
                    })?;
                }
                io::sync_parent(&operations, active)?;
                io::sync_parent(&trash, active)?;
                for id in names(&trash, OPERATION_CAP, active)? {
                    remove_tree(&trash, &id, active)?;
                }
                io::sync_parent(&trash, active)?;
                self.publication.store(2, Ordering::Release);
                self.revalidate(active)?;
            }
            Action::Checkpoint { before, after } => {
                self.revalidate(active)?;
                require(self.pruning, Failure::Ownership)?;
                let bytes = crate::k3s::history::checkpoint::encode(&after)
                    .map_err(|_| Failure::Integrity)?;
                let h = self.held.as_ref().ok_or(Failure::Ownership)?;
                let history = child(&h.target, "history", true, active)?.ok_or(Failure::Storage)?;
                let current = io::read(
                    &history,
                    "checkpoint.json",
                    crate::k3s::history::checkpoint::LIMIT as u64,
                    active,
                )?;
                let chain = match &current {
                    None => "0".repeat(64),
                    Some((raw, _)) => crate::k3s::history::checkpoint::decode(raw)
                        .map_err(|_| Failure::Integrity)?["chain_sha256"]
                        .as_str()
                        .ok_or(Failure::Integrity)?
                        .to_owned(),
                };
                let target = after["chain_sha256"].as_str().ok_or(Failure::Integrity)?;
                let replace = crate::k3s::history::checkpoint::completion(&chain, &before, target)
                    .map_err(|_| Failure::Integrity)?;
                if replace {
                    let temporary = format!(".tmp-{}", sudo_nonce().map_err(|_| Failure::Storage)?);
                    let prepared = io::prepare(&history, temporary, &bytes, active)?;
                    self.publication.store(1, Ordering::Release);
                    match current {
                        Some((_, identity)) => {
                            io::publish(
                                &history,
                                prepared,
                                "checkpoint.json",
                                Some(identity),
                                active,
                            )?;
                        }
                        None => {
                            io::publish_new(&history, prepared, "checkpoint.json", active)?
                                .ok_or(Failure::Busy)?;
                        }
                    }
                    io::sync_parent(&history, active)?;
                    self.publication.store(2, Ordering::Release);
                }
                self.history.checkpoint = Some(*after);
                self.revalidate(active)?;
            }
        }
        Ok(())
    }

    fn read_intent(&self, active: &Active) -> Result<Option<(Value, (u64, u64))>> {
        let h = self.held.as_ref().ok_or(Failure::Ownership)?;
        let Some(history) = child(&h.target, "history", false, active)? else {
            return Ok(None);
        };
        let Some((raw, identity)) = io::read(
            &history,
            "intent.json",
            crate::k3s::history::intent::LIMIT as u64,
            active,
        )?
        else {
            return Ok(None);
        };
        let intent = crate::k3s::history::intent::decode(&raw).map_err(|_| Failure::Integrity)?;
        require(intent["scope"] == self.scope, Failure::Ownership)?;
        Ok(Some((intent, identity)))
    }

    fn read_history(&mut self, active: &Active) -> Result<()> {
        let h = self.held.as_ref().ok_or(Failure::Ownership)?;
        let owner =
            read(&h.target, "owner.json", "owner", active, &mut 0)?.ok_or(Failure::Integrity)?;
        require(
            owner["scope"] == self.scope
                && owner["lock_identity"] == json!([h.lock_identity.0, h.lock_identity.1]),
            Failure::Ownership,
        )?;
        let operations =
            child(&h.target, "operations", false, active)?.ok_or(Failure::Integrity)?;
        let mut summaries = Vec::new();
        let mut attempts = std::collections::BTreeMap::new();
        for id in names(&operations, OPERATION_CAP, active)? {
            require(operation_id(&id), Failure::Integrity)?;
            let directory = child(&operations, &id, false, active)?.ok_or(Failure::Integrity)?;
            let stored = io::read(
                &directory,
                "summary.json",
                crate::k3s::history::summary::LIMIT as u64,
                active,
            )
            .ok()
            .flatten()
            .and_then(|(raw, _)| crate::k3s::history::summary::decode(&raw).ok())
            .filter(|summary| summary["operation"] == id.as_str());
            let summary = match stored {
                Some(summary) => summary,
                None => {
                    let snapshot = self.load(&id, active)?;
                    self.summarize(&directory, &snapshot, active)?
                }
            };
            let directory =
                child(&directory, "attempts", false, active)?.ok_or(Failure::Integrity)?;
            let ids = names(&directory, 128, active)?
                .into_iter()
                .map(|n| {
                    n.strip_suffix(".json")
                        .map(str::to_owned)
                        .ok_or(Failure::Integrity)
                })
                .collect::<Result<Vec<_>>>()?;
            attempts.insert(id, ids);
            summaries.push(summary);
        }
        let waves = self
            .load_waves(&owner, active)?
            .into_iter()
            .map(|w| json!({"boundary": w.boundary, "gate": w.gate}))
            .collect();
        let checkpoint = match child(&h.target, "history", false, active)? {
            None => None,
            Some(history) => match io::read(
                &history,
                "checkpoint.json",
                crate::k3s::history::checkpoint::LIMIT as u64,
                active,
            )? {
                None => None,
                Some((raw, _)) => {
                    let checkpoint = crate::k3s::history::checkpoint::decode(&raw)
                        .map_err(|_| Failure::Integrity)?;
                    require(checkpoint["scope"] == self.scope, Failure::Ownership)?;
                    Some(checkpoint)
                }
            },
        };
        let intent = self.read_intent(active)?;
        self.history = HistoryRead {
            owner: Some(owner),
            summaries,
            attempts,
            waves,
            checkpoint,
            intent_identity: intent.as_ref().map(|(_, identity)| *identity),
            intent: intent.map(|(intent, _)| intent),
        };
        Ok(())
    }

    fn summarize(&self, directory: &File, snapshot: &Snapshot, active: &Active) -> Result<Value> {
        let summary = super::history::summary(&self.scope, snapshot)?;
        let bytes = crate::k3s::history::summary::encode(&summary).map_err(|_| Failure::Bound)?;
        let current = io::read(
            directory,
            "summary.json",
            crate::k3s::history::summary::LIMIT as u64 + 1,
            active,
        )?;
        if current.as_ref().is_some_and(|(raw, _)| *raw == bytes) {
            return Ok(summary);
        }
        for name in names(directory, 16, active)? {
            if name.starts_with(SUMMARY_TEMPORARY) {
                active.sys(|| {
                    rustix::fs::unlinkat(directory, name.as_str(), rustix::fs::AtFlags::empty())
                })?;
            }
        }
        let temporary = format!(
            "{SUMMARY_TEMPORARY}{}",
            sudo_nonce().map_err(|_| Failure::Storage)?
        );
        let prepared = io::prepare(directory, temporary, &bytes, active)?;
        io::publish(
            directory,
            prepared,
            "summary.json",
            current.map(|(_, identity)| identity),
            active,
        )?;
        io::sync_parent(directory, active)?;
        Ok(summary)
    }

    fn refresh(&self, operation: &str, active: &Active) {
        let _ = (|| {
            let h = self.held.as_ref().ok_or(Failure::Ownership)?;
            let operations =
                child(&h.target, "operations", false, active)?.ok_or(Failure::Integrity)?;
            let directory =
                child(&operations, operation, false, active)?.ok_or(Failure::Integrity)?;
            let snapshot = self.snapshots.first().ok_or(Failure::Integrity)?;
            self.summarize(&directory, snapshot, active)
        })();
    }

    fn write_attempt(&self, directory: &File, attempt: &Value, active: &Active) -> Result<()> {
        let attempts = child(directory, "attempts", false, active)?.ok_or(Failure::Integrity)?;
        self.revalidate(active)?;
        publish(
            &attempts,
            &format!(
                "{}.json",
                attempt["attempt"].as_str().ok_or(Failure::Integrity)?
            ),
            attempt,
            "attempt",
            active,
            &self.publication,
        )?;
        Ok(())
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        if self.held.is_some() {
            std::mem::forget(self.held.take());
            std::mem::forget(self.permit.clone());
        }
    }
}

impl Snapshot {
    fn bytes(&self) -> Result<usize> {
        std::iter::once(&self.request)
            .chain(&self.attempts)
            .chain(&self.steps)
            .chain(&self.observations)
            .try_fold(0usize, |n, v| {
                n.checked_add(canonical(v)?.len() + 1).ok_or(Failure::Bound)
            })
    }
    pub(super) fn copied_set(&self, o: &Value) -> Result<()> {
        let copies = self
            .observations
            .iter()
            .filter(|p| p["event"]["type"] == "cert-manager-observation" && p["step"].is_null());
        require(
            o["dispatch"].is_null()
                && copies.count() == 1
                && self
                    .attempts
                    .iter()
                    .any(|a| a["attempt"] == o["attempt"] && a["parent_attempt"].is_null()),
            Failure::Integrity,
        )
    }
    pub(super) fn consistent(&self) -> Result<()> {
        self.checked(None)
    }

    fn checked(&self, decoded: Option<[usize; 3]>) -> Result<()> {
        if decoded.is_none() {
            schema::decode(&canonical(&self.owner)?, "owner", 65535)?;
            schema::decode(&canonical(&self.request)?, "request", 262143)?;
        }
        require(
            self.owner["scope"] == self.request["scope"]
                && self.owner["owner"] == self.request["owner"],
            Failure::Ownership,
        )?;
        require(
            self.attempts.len() <= 128
                && self.steps.len() <= 1024
                && self.observations.len() <= 4096,
            Failure::Bound,
        )?;
        let request_hash = super::hash("broil-infra-request-v1", &self.request)?;
        let mut ids = std::collections::BTreeSet::new();
        let mut dispatches = std::collections::BTreeSet::new();
        let mut attempt_ids = std::collections::BTreeSet::new();
        let mut previous_step = 0;
        let mut attempts: Vec<_> = self.attempts.iter().collect();
        attempts.sort_by_key(|a| a["steps"][0].as_u64());
        for attempt in attempts {
            if attempt["parent_attempt"].is_null() {
                require(
                    attempt_ids.is_empty()
                        && attempt["original_step"].is_null()
                        && attempt["approval"].is_null()
                        && (self.request["consumer"].is_null()
                            || self.request["consumer"]["projection"]["binding"]["attempt"]
                                == attempt["attempt"]),
                    Failure::Integrity,
                )?;
            } else {
                require(
                    attempt_ids.contains(
                        attempt["parent_attempt"]
                            .as_str()
                            .ok_or(Failure::Integrity)?,
                    ),
                    Failure::Integrity,
                )?;
                let original = self
                    .steps
                    .iter()
                    .find(|s| s["step"] == attempt["original_step"] && s["original_step"].is_null())
                    .ok_or(Failure::Integrity)?;
                require(
                    self.steps.iter().any(|s| {
                        s["attempt"] == attempt["parent_attempt"]
                            && s["action"] == original["action"]
                            && (s["step"] == original["step"]
                                || s["original_step"] == original["step"])
                    }),
                    Failure::Integrity,
                )?;
                let proposal = &attempt["approval"];
                let decision = &proposal["decision"];
                require(
                    decision["failed_attempt"] == attempt["parent_attempt"]
                        && decision["original_step"] == original["step"]
                        && decision["action"] == original["action"]
                        && decision["request_sha256"] == request_hash,
                    Failure::Integrity,
                )?;
                for key in [
                    "scope",
                    "owner",
                    "operation",
                    "members",
                    "cluster",
                    "fingerprints",
                    "participants_sha256",
                ] {
                    require(decision[key] == self.request[key], Failure::Ownership)?;
                }
                require(
                    self.observations.iter().any(|o| {
                        o["event"]["type"] == "recovery"
                            && o["event"]["choice"] == "retry"
                            && o["event"]["proposal"] == *proposal
                    }),
                    Failure::Integrity,
                )?;
            }
            require(
                attempt_ids.insert(attempt["attempt"].as_str().ok_or(Failure::Integrity)?),
                Failure::Integrity,
            )?;
            require(
                attempt["request_sha256"] == request_hash,
                Failure::Integrity,
            )?;
            for id in attempt["steps"].as_array().ok_or(Failure::Integrity)? {
                let number = id.as_u64().ok_or(Failure::Integrity)?;
                require(
                    number > previous_step && ids.insert(number),
                    Failure::Integrity,
                )?;
                previous_step = number;
                let Some(step) = self.steps.iter().find(|v| v["step"] == *id) else {
                    continue;
                };
                require(
                    step["attempt"] == attempt["attempt"]
                        && step["original_step"] == attempt["original_step"]
                        && step["request_sha256"] == request_hash
                        && dispatches.insert(step["dispatch"].as_str().ok_or(Failure::Integrity)?),
                    Failure::Integrity,
                )?;
                let hook = step["action"]
                    .as_str()
                    .is_some_and(|a| a.starts_with("hook:"));
                require(
                    if hook {
                        step["recipient"].is_null() && step["resource"].is_null()
                    } else {
                        self.request["members"]
                            .as_array()
                            .ok_or(Failure::Integrity)?
                            .contains(&step["recipient"])
                    },
                    Failure::Ownership,
                )?;
            }
        }
        require(
            !self.attempts.is_empty() && ids.len() <= 1024 && dispatches.len() == self.steps.len(),
            Failure::Integrity,
        )?;
        let decoded = decoded.unwrap_or_default();
        for ((kind, records), skip) in [
            ("attempt", &self.attempts),
            ("step-record", &self.steps),
            ("observation", &self.observations),
        ]
        .into_iter()
        .zip(decoded)
        {
            for (index, record) in records.iter().enumerate() {
                if index >= skip {
                    schema::decode(&canonical(record)?, kind, 65535)?;
                }
                for field in ["scope", "owner", "operation"] {
                    require(record[field] == self.request[field], Failure::Ownership)?;
                }
            }
        }
        for (index, o) in self.observations.iter().enumerate() {
            require(o["sequence"] == index + 1, Failure::Integrity)?;
            if o["step"].is_null() {
                let kind = o["event"]["type"].as_str().unwrap_or("");
                if matches!(
                    kind,
                    "bootstrap-recipe"
                        | "lifecycle-recipe"
                        | "server-recipe"
                        | "server-join-recipe"
                        | "agent-recipe"
                        | "agent-join-recipe"
                        | "network-recipe"
                        | "ingress-recipe"
                        | "cert-manager-recipe"
                        | "issuer-recipe"
                        | "certificate-recipe"
                        | "registry-storage-recipe"
                        | "registry-service-recipe"
                        | "registry-endpoint-recipe"
                        | "registry-auth-recipe"
                        | "registry-token-recipe"
                        | "replication-recipe"
                        | "delivery-recipe"
                        | "release-recipe"
                        | "restart-recipe"
                        | "member-recipe"
                ) {
                    require(
                        o["dispatch"].is_null()
                            && self
                                .observations
                                .iter()
                                .filter(|p| {
                                    p["event"]["type"] == kind
                                        && (!matches!(kind, "server-recipe" | "agent-recipe")
                                            || p["event"]["recipe"]["member"]
                                                == o["event"]["recipe"]["member"])
                                })
                                .count()
                                == 1
                            && self.attempts.iter().any(|a| {
                                a["attempt"] == o["attempt"] && a["parent_attempt"].is_null()
                            }),
                        Failure::Integrity,
                    )?;
                } else if kind == "cert-manager-observation" {
                    self.copied_set(o)?;
                } else if kind == "component-assets" {
                    require(
                        matches!(
                            self.request["action"].as_str(),
                            Some(
                                "reconcile-network"
                                    | "reconcile-ingress"
                                    | "reconcile-cert-manager"
                            )
                        ) && self.observations[..index]
                            .iter()
                            .all(|p| p["dispatch"].is_null())
                            && self
                                .observations
                                .iter()
                                .filter(|p| p["event"]["type"] == kind)
                                .count()
                                == 1
                            && self.attempts.iter().any(|a| {
                                a["attempt"] == o["attempt"] && a["parent_attempt"].is_null()
                            }),
                        Failure::Integrity,
                    )?;
                } else if kind == "node-registry-supply" {
                    require(
                        index == 0
                            && self.request["action"] == "prepare-node-registry"
                            && o["dispatch"].is_null()
                            && self.attempts.iter().any(|a| {
                                a["attempt"] == o["attempt"] && a["parent_attempt"].is_null()
                            }),
                        Failure::Integrity,
                    )?;
                } else {
                    require(
                        o["attempt"].is_null() && o["dispatch"].is_null(),
                        Failure::Integrity,
                    )?;
                }
            } else {
                require(
                    self.steps.iter().any(|s| {
                        s["step"] == o["step"]
                            && s["attempt"] == o["attempt"]
                            && s["dispatch"] == o["dispatch"]
                    }),
                    Failure::Integrity,
                )?;
            }
            self.validate_observation(o)?;
        }
        require(
            self.request["action"] != "prepare-node-registry"
                || self.steps.is_empty()
                || self
                    .observations
                    .first()
                    .is_some_and(|o| o["event"]["type"] == "node-registry-supply"),
            Failure::Integrity,
        )?;
        for step in &self.steps {
            if step["action"] == "retire-writer" {
                self.retirement_payload(step)?;
            } else if matches!(
                self.request["action"].as_str(),
                Some("release-apply" | "release-rollback")
            ) && matches!(
                step["action"].as_str(),
                Some("admit-credential" | "credential:apply-secret")
            ) {
                self.release_secret_payload(step)?;
            } else if matches!(
                step["action"].as_str(),
                Some("prepare-input" | "admit-credential")
            ) || step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("credential:"))
            {
                self.consumer_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("bootstrap:"))
            {
                self.bootstrap_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:network-"))
            {
                self.network_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:ingress-"))
            {
                self.ingress_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:cert-manager-"))
            {
                self.cert_manager_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:issuer-"))
            {
                self.issuer_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:certificate-"))
            {
                self.certificate_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:registry-storage-"))
            {
                self.registry_storage_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:registry-service-"))
            {
                self.registry_service_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:registry-endpoint-"))
            {
                self.registry_endpoint_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:registry-auth-"))
            {
                self.registry_auth_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:registry-replication-"))
            {
                self.registry_replication_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:registry-token-"))
            {
                self.registry_token_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:node-"))
            {
                self.node_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:delivery-"))
                && matches!(
                    self.request["action"].as_str(),
                    Some("release-apply" | "release-rollback")
                )
            {
                self.release_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:delivery-"))
            {
                self.delivery_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:release-"))
            {
                self.release_payload(step)?;
            } else if step["action"]
                .as_str()
                .is_some_and(|s| s.starts_with("lifecycle:"))
            {
                self.lifecycle_payload(step)?;
            }
        }
        require(self.bytes()? <= 33_554_432, Failure::Bound)
    }
}

pub(super) fn validate_gate(
    scope: &Value,
    gate: &Value,
    boundary: &Value,
    owner: Option<&Value>,
    load: &mut dyn FnMut(&str) -> Result<Snapshot>,
) -> Result<()> {
    let succeeded = |snapshot: &Snapshot| -> Result<bool> {
        Ok(
            super::report::report(scope, "show", std::slice::from_ref(snapshot))?["outcome"]
                == "succeeded",
        )
    };
    let selected = boundary["selected"].as_array().ok_or(Failure::Integrity)?;
    let operations = gate["operations"].as_array().ok_or(Failure::Integrity)?;
    require(operations.len() == selected.len(), Failure::Ownership)?;
    let original = boundary["members"].as_array().ok_or(Failure::Integrity)?;
    let installed = boundary["installed"].as_array().ok_or(Failure::Integrity)?;
    let prefix = installed.len();
    require(
        prefix + selected.len() <= original.len(),
        Failure::Integrity,
    )?;
    let boundary_hash = hash("broil-k3s-agent-wave-boundary-v1", boundary)?;
    let mut members = original.clone();
    for (index, operation) in operations.iter().enumerate() {
        let id = operation.as_str().ok_or(Failure::Integrity)?;
        let snapshot = load(id)?;
        let position = prefix + index;
        require(
            snapshot.request["action"] == "join-agent"
                && snapshot.request["cluster"] == boundary["cluster"]
                && (snapshot.request["consumer"].is_object()
                    || snapshot
                        .steps
                        .iter()
                        .any(|step| step["action"] == "lifecycle:node-start-member"))
                && original
                    .get(position)
                    .is_some_and(|m| m["member"] == selected[index])
                && succeeded(&snapshot)?
                && snapshot.request["members"] == json!(members),
            Failure::Ownership,
        )?;
        let recipes: Vec<_> = snapshot
            .observations
            .iter()
            .filter(|event| event["event"]["type"] == "agent-join-recipe")
            .collect();
        require(recipes.len() == 1, Failure::Ownership)?;
        let recipe = &recipes[0]["event"]["recipe"];
        require(
            recipe["wave"]
                == json!({"id":boundary["id"],"index":index,"boundary_sha256":boundary_hash})
                && recipe["member"] == original[position],
            Failure::Ownership,
        )?;
        let published: Vec<&Value> = snapshot
            .steps
            .iter()
            .filter(|step| step["action"] == "lifecycle:publish-agent" && snapshot.succeeded(step))
            .collect();
        require(published.len() == 1, Failure::Ownership)?;
        let step = published[0];
        let events: Vec<&Value> = snapshot
            .observations
            .iter()
            .filter(|event| {
                event["step"] == step["step"]
                    && event["attempt"] == step["attempt"]
                    && event["dispatch"] == step["dispatch"]
                    && event["event"]["type"] == "lifecycle-installation"
                    && event["event"]["class"] == "owned"
            })
            .collect();
        require(events.len() == 1, Failure::Ownership)?;
        let uid = &events[0]["event"]["identity"]["node_uid"];
        require(uid.is_string(), Failure::Ownership)?;
        members[position]["node_uid"] = uid.clone();
    }
    let observer = gate["observer_operation"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    let last = operations
        .last()
        .ok_or(Failure::Integrity)?
        .as_str()
        .ok_or(Failure::Integrity)?;
    let observed = load(observer)?;
    require(
        (observer == last
            || observed.request["action"] == "join-agent"
                && observed.request["consumer"].is_null()
                && observed.request["members"] == json!(members)
                && observed.request["resources"][1]["machine"]
                    == members[prefix + selected.len() - 1]["machine"])
            && succeeded(&observed)?,
        Failure::Ownership,
    )?;
    let attempt = &observed.attempts.last().ok_or(Failure::Integrity)?["attempt"];
    let names: Vec<&Value> = installed.iter().map(|i| &i["member"]["member"]).collect();
    let servers: Vec<&Value> = members
        .iter()
        .filter(|m| m["role"] == "server" && names.contains(&&m["member"]))
        .collect();
    let source = *servers.first().ok_or(Failure::Integrity)?;
    let view_ref = &gate["agent_view_ref"];
    require(view_ref["operation"] == observer, Failure::Ownership)?;
    let view_event = observed
        .observations
        .iter()
        .find(|event| {
            event["sequence"] == view_ref["sequence"]
                && event["attempt"] == *attempt
                && event["event"]["type"] == "agent-membership"
                && event["source"]["machine"] == source["machine"]
        })
        .ok_or(Failure::Ownership)?;
    let view_step = observed
        .steps
        .iter()
        .find(|step| {
            step["step"] == view_event["step"]
                && step["attempt"] == *attempt
                && step["action"] == "lifecycle:observe-agent-membership"
        })
        .ok_or(Failure::Ownership)?;
    require(view_step["recipient"] == *source, Failure::Ownership)?;
    let view = &view_event["event"]["view"];
    let entries = view["members"].as_array().ok_or(Failure::Integrity)?;
    let declared = observed.request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    require(
        view["cluster"] == boundary["cluster"]
            && view["observer"] == *source
            && view["foreign"] == json!([])
            && entries.len() == members.len()
            && declared.len() == members.len()
            && entries
                .iter()
                .zip(&members)
                .zip(declared)
                .all(|((entry, member), declared)| {
                    entry["member"] == *declared
                        && (member["node_uid"].is_string()
                            && entry["present"] == true
                            && entry["ready"] == true
                            && entry["uid"] == member["node_uid"]
                            && entry["roles"] == json!([member["role"]])
                            || member["node_uid"].is_null()
                                && entry["present"] == false
                                && entry["uid"].is_null()
                                && entry["ready"] == false
                                && entry["roles"] == json!([])
                                && entry["labels"] == json!([])
                                && entry["taints"] == json!([]))
                }),
        Failure::Readiness,
    )?;
    let server_refs = gate["server_membership_refs"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    require(server_refs.len() == servers.len(), Failure::Ownership)?;
    for (reference, member) in server_refs.iter().zip(&servers) {
        require(reference["operation"] == observer, Failure::Ownership)?;
        let event = observed
            .observations
            .iter()
            .find(|event| {
                event["sequence"] == reference["sequence"]
                    && event["attempt"] == *attempt
                    && event["event"]["type"] == "server-membership"
                    && event["event"]["member"] == **member
            })
            .ok_or(Failure::Ownership)?;
        let step = observed
            .steps
            .iter()
            .find(|step| {
                step["step"] == event["step"]
                    && step["attempt"] == *attempt
                    && step["action"] == "lifecycle:observe-membership"
            })
            .ok_or(Failure::Ownership)?;
        require(step["recipient"] == **member, Failure::Ownership)?;
        require(
            event["sequence"].as_u64() > view_ref["sequence"].as_u64()
                && event["event"]["membership"]["healthy"] == true
                && event["event"]["membership"]["cluster"] == boundary["cluster"]
                && event["event"]["membership"]["node_uid"] == member["node_uid"],
            Failure::Readiness,
        )?;
    }
    if let Some(owner) = owner {
        let current = owner["members"].as_array().ok_or(Failure::Integrity)?;
        for member in &members[prefix..prefix + selected.len()] {
            require(
                current.iter().any(|m| {
                    m["member"] == member["member"] && m["node_uid"] == member["node_uid"]
                }),
                Failure::Ownership,
            )?;
        }
    }
    Ok(())
}
