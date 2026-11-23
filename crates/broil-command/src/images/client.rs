// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Tool,
    common::*,
    json::Value,
    outputs::{ArchiveWork, AssembleWork, Inspected, RetainWork},
    policy::*,
    protected, publish, receipt,
    solve::UploadWork,
    supervise::{self, Clock, Input, Launch, Output, Permit, PublicAction},
};
use broil_core::{
    images::{valid_name, valid_platform},
    secret::OwnedSecret,
};
use serde_json::{Value as Public, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub use super::supervise::{Dispatch, Observation};

#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub(crate) fn flag(&self) -> Arc<AtomicBool> {
        self.0.clone()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Debug)]
pub struct StageError {
    pub failure: Failure,
    pub observation: Observation,
}

#[derive(Clone, Debug)]
pub struct VerifiedOutput {
    operation: String,
    stage: String,
    producer: u64,
    entry: Entry,
    root: Descriptor,
    complete: bool,
    files: u64,
    bytes: u64,
    original_reference: Option<String>,
    producer_image: bool,
    receipt: bool,
    cache: bool,
}
impl VerifiedOutput {
    pub fn entry(&self) -> &Entry {
        &self.entry
    }
    pub(crate) fn retained(&self) -> Self {
        let mut output = self.clone();
        output.entry.ownership = Ownership::Retained;
        output
    }
    pub fn root(&self) -> &Descriptor {
        &self.root
    }
    pub fn closure_complete(&self) -> bool {
        self.complete
    }
    pub fn verified_counts(&self) -> (u64, u64) {
        (self.files, self.bytes)
    }
    pub fn stage(&self) -> &str {
        &self.stage
    }
    pub(crate) fn original_reference(&self) -> Option<&str> {
        self.original_reference.as_deref()
    }
    pub(crate) fn producer_image(&self) -> bool {
        self.producer_image
    }
}

pub struct ReleaseToken {
    operation_id: String,
    workspace: Entry,
    job: u64,
}

impl ReleaseToken {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

impl std::fmt::Debug for ReleaseToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleaseToken")
            .field("operation_id", &self.operation_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Kept {
    pub token: ReleaseToken,
    pub entries: Vec<Entry>,
}

#[derive(Debug)]
pub struct Unreleased {
    pub kept: Option<Kept>,
    pub error: StageError,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CacheArguments {
    pub(crate) imports: Vec<(Entry, Descriptor)>,
    pub(crate) export: Option<&'static str>,
}

pub(crate) struct Baked {
    pub(crate) image: VerifiedOutput,
    pub(crate) export: Option<VerifiedOutput>,
}

pub(crate) struct BakeFailure {
    pub(crate) error: StageError,
    pub(crate) export: bool,
    pub(crate) launched: bool,
}

impl From<BakeFailure> for StageError {
    fn from(failure: BakeFailure) -> Self {
        failure.error
    }
}

#[derive(Debug)]
pub struct RegistryOutcome {
    pub observation: Observation,
    pub output: Option<VerifiedOutput>,
    pub root: Option<Descriptor>,
    pub optional_cache_miss: bool,
    pub closure_complete: bool,
    pub verified: (u64, u64),
    pub helper_allowance: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuilderCapabilities {
    pub version: &'static str,
    pub oci_worker: bool,
    pub platforms: Vec<String>,
    pub build_platform: String,
}

struct Slot {
    entry: Entry,
    producer: u64,
    kind: &'static str,
    stage: String,
}

pub struct Operation {
    policy: Policy,
    cancellation: Cancellation,
    permit: Arc<Permit>,
    workspace: Entry,
    directories: Vec<Entry>,
    tools: BTreeMap<Tool, Entry>,
    job: u64,
    producer: u64,
    owned_bytes: u64,
    usable: bool,
    dispatches: u64,
    last: Observation,
    last_clock: Option<Clock>,
    protected: protected::Checks,
    builder: Option<BuilderPolicy>,
    builder_ready: bool,
    capabilities: Option<BuilderCapabilities>,
    outputs: Vec<VerifiedOutput>,
    analysis_attempt: u64,
    analysis_preparation: Option<(u64, u64)>,
    daemon: Option<PathBuf>,
}

fn framed(value: &Public, limit: usize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| Failure::Protocol)?;
    require(
        !bytes.is_empty() && bytes.len() <= limit.min(65_536),
        Failure::Limit,
    )?;
    let mut result = Vec::with_capacity(bytes.len() + 4);
    result.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(&bytes);
    Ok(result)
}

impl Operation {
    pub fn open(
        checked: Preflight,
        cancellation: Cancellation,
    ) -> std::result::Result<Self, StageError> {
        let start = monotonic_ns();
        let error = |failure| StageError {
            failure,
            observation: Observation::new(start),
        };
        checked.0.validate().map_err(error)?;
        let mut clock = Clock::new(checked.0.limits.metadata_ms).map_err(error)?;
        let permit = Permit::acquire().map_err(error)?;
        let policy = checked.0;
        let analysis_preparation = (policy.tools.len() == 1
            && policy.tools.contains_key(&Tool::Analyzer))
        .then_some((clock.start, clock.end));
        let workspace = Entry {
            path: policy.workspace_path(),
            device: 0,
            inode: 0,
            kind: Kind::Directory,
            ownership: Ownership::Operation,
        };
        let mut operation = Self {
            policy,
            cancellation,
            permit,
            workspace,
            directories: Vec::new(),
            tools: BTreeMap::new(),
            job: 0,
            producer: 0,
            owned_bytes: 0,
            usable: true,
            dispatches: 0,
            last: Observation::new(start),
            last_clock: None,
            protected: protected::Checks::default(),
            builder: None,
            builder_ready: false,
            capabilities: None,
            outputs: Vec::new(),
            analysis_attempt: 0,
            analysis_preparation,
            daemon: None,
        };
        let result = (|| {
            let response = operation.job(
                "prepare",
                json!({"parent":operation.policy.parent.wire()}),
                &mut clock,
            )?;
            let value = receipt::frame(&response.stdout.get()[..response.stdout_used], 65_536)?;
            operation.workspace = receipt::discovered(
                value.field("workspace")?,
                &operation.workspace.path,
                Kind::Directory,
            )?;
            let fields = value.field("result")?.object(&[b"directories"])?;
            let directories = fields[0].array()?;
            require(
                directories.len() == super::files::DIRECTORIES.len(),
                Failure::Protocol,
            )?;
            for (value, name) in directories.into_iter().zip(super::files::DIRECTORIES) {
                operation.directories.push(receipt::discovered(
                    value,
                    &operation.workspace.path.join(name),
                    Kind::Directory,
                )?);
            }
            for (tool, source) in operation.policy.tools.clone() {
                let (digest, size) = tool.identity()?;
                let destination = operation.workspace.path.join("tools").join(tool.name());
                let output = operation.job(
                    "copy-tool",
                    json!({"source":source.wire(),"destination":destination,
                    "tool":tool.name(),"digest":digest,"size":size}),
                    &mut clock,
                )?;
                let response = receipt::frame(&output.stdout.get()[..output.stdout_used], 65_536)?;
                let fields = response.field("result")?.object(&[b"entry"])?;
                operation.tools.insert(
                    tool,
                    receipt::discovered(fields[0], &destination, Kind::File)?,
                );
            }
            before(clock.end)
        })();
        match result {
            Ok(()) => Ok(operation),
            Err(failure) => {
                let mut observation = operation.last.clone();
                observation.failure = Some(failure);
                observation.cleanup_uncertain = true;
                observation.completion_uncertain |= observation.dispatch != Dispatch::None;
                observation.finished_ns = monotonic_ns();
                Err(StageError {
                    failure,
                    observation,
                })
            }
        }
    }

    pub fn workspace(&self) -> &Entry {
        &self.workspace
    }

    pub fn analyze(
        &mut self,
        stage: &str,
        snapshot: super::analysis::Snapshot,
    ) -> std::result::Result<super::analysis::Outcome, StageError> {
        self.stage(stage, false, |this, clock| {
            require(this.tools.contains_key(&Tool::Analyzer), Failure::Policy)?;
            if let Some((start, end)) = this.analysis_preparation.take() {
                clock.start = start;
                clock.end = clock.end.min(end);
                this.active(clock)?;
            }
            this.analysis_attempt = this.analysis_attempt.checked_add(1).ok_or(Failure::Limit)?;
            let attempt = super::analysis::Attempt::new(
                snapshot,
                &this.policy.operation_id,
                this.analysis_attempt,
                this.policy.limits.stream_bytes,
                clock.end,
            )?;
            let input = attempt.encode()?;
            this.active(clock)?;
            let output = this.tool(
                Tool::Analyzer,
                Vec::new(),
                Input {
                    prefix: Vec::new(),
                    scalar: None,
                    private: Some(input),
                },
                clock,
                &this.policy.limits.clone(),
            )?;
            let outcome = attempt.decode(output)?;
            this.active(clock)?;
            Ok(outcome)
        })
    }
    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }

    fn active(&self, clock: &Clock) -> Result<()> {
        self.policy.validate()?;
        require(self.usable, Failure::Indeterminate)?;
        require(!self.cancellation.requested(), Failure::Cancellation)?;
        before(clock.end)
    }

    fn job(&mut self, action: &str, body: Public, clock: &mut Clock) -> Result<Output> {
        self.active(clock)?;
        self.job = self.job.checked_add(1).ok_or(Failure::Limit)?;
        let mut workspace = self.workspace.wire();
        if action == "prepare" {
            workspace["device"] = Public::Null;
            workspace["inode"] = Public::Null;
        }
        let request = json!({"protocol_version":3,"operation_id":self.policy.operation_id,"job_id":self.job,
            "action":action,"workspace":workspace,"deadline_ns":clock.end,"limits":self.policy.limits.content.wire(),"body":body});
        let (digest, size) = helper_identity()?;
        let launch = Launch {
            executable: self.policy.helper.clone(),
            digest,
            size,
            args: Vec::new(),
            env: self.policy.child_environment()?,
            cwd: self.policy.root.clone(),
            protected: protected::Checks::default(),
        };
        let mut limits = self.policy.limits.clone();
        limits.stream_bytes = 65_540;
        let output = self.launch(
            launch,
            Input {
                private: None,
                prefix: framed(&request, 65_536)?,
                scalar: None,
            },
            clock,
            &limits,
        )?;
        let value = receipt::frame(&output.stdout.get()[..output.stdout_used], 65_536)?;
        let fields = value.object(&[
            b"protocol_version",
            b"operation_id",
            b"job_id",
            b"action",
            b"workspace",
            b"status",
            b"failure_class",
            b"effects",
            b"completion_uncertain",
            b"cleanup_uncertain",
            b"accounting_complete",
            b"owned_bytes",
            b"owned_entries",
            b"result",
        ])?;
        require(
            fields[0].number()? == 3
                && fields[1].equals(&self.policy.operation_id)?
                && fields[2].number()? == self.job
                && fields[3].equals(action)?
                && fields[11].number()? <= self.policy.limits.content.staging_bytes
                && fields[12].number()? <= self.policy.limits.content.entries,
            Failure::Protocol,
        )?;
        if action != "prepare" {
            require(
                fields[4].matches(&self.workspace.wire())?,
                Failure::Integrity,
            )?;
        }
        let succeeded = fields[5].equals("succeeded")?;
        let failed = fields[5].equals("failed")?;
        let cancelled = fields[5].equals("cancelled")?;
        let unknown = fields[5].equals("unknown")?;
        let completion_uncertain = fields[8].boolean()?;
        let cleanup_uncertain = fields[9].boolean()?;
        let accounted = fields[10].boolean()?;
        require(
            (succeeded || failed || cancelled || unknown)
                && succeeded == fields[6].equals("none")?
                && succeeded == (output.observation.exit_code == Some(0))
                && output.observation.exit_code.is_some()
                && (!unknown || completion_uncertain)
                && (accounted || cleanup_uncertain)
                && (fields[7].equals("none")?
                    || fields[7].equals("possible")?
                    || fields[7].equals("completed")?),
            Failure::Protocol,
        )?;
        if !succeeded {
            require(fields[13].is_null(), Failure::Protocol)?;
            let mut failure = None;
            for candidate in [
                Failure::Policy,
                Failure::Protocol,
                Failure::Integrity,
                Failure::Storage,
                Failure::Limit,
                Failure::Timeout,
                Failure::Cancellation,
                Failure::Indeterminate,
            ] {
                if fields[6].equals(candidate.name())? {
                    failure = Some(candidate);
                }
            }
            let failure = failure.ok_or(Failure::Protocol)?;
            require(
                !cancelled || failure == Failure::Cancellation,
                Failure::Protocol,
            )?;
            self.last.completion_uncertain |= completion_uncertain;
            self.last.cleanup_uncertain |= cleanup_uncertain;
            return Err(failure);
        }
        require(
            !completion_uncertain && !cleanup_uncertain && accounted,
            Failure::Protocol,
        )?;
        let read = matches!(
            action,
            "inspect-prepared" | "verify-staged" | "verify-produced"
        );
        require(
            fields[7].equals(if read { "none" } else { "completed" })?,
            Failure::Protocol,
        )?;
        self.owned_bytes = fields[11].number()?;
        before(clock.end)?;
        Ok(output)
    }

    fn launch(
        &mut self,
        launch: Launch,
        input: Input,
        clock: &mut Clock,
        limits: &Limits,
    ) -> Result<Output> {
        self.active(clock)?;
        match supervise::run(
            launch,
            input,
            clock,
            limits,
            &self.cancellation.0,
            &self.permit,
        ) {
            Ok(output) => {
                self.last = output.observation.clone();
                self.dispatched();
                Ok(output)
            }
            Err(observation) => {
                let failure = observation.failure.unwrap_or(Failure::Indeterminate);
                self.last = observation;
                self.dispatched();
                Err(failure)
            }
        }
    }

    fn dispatched(&mut self) {
        if self.last.dispatch != Dispatch::None {
            self.dispatches = self.dispatches.saturating_add(1);
        }
    }

    fn tool(
        &mut self,
        tool: Tool,
        args: Vec<String>,
        input: Input,
        clock: &mut Clock,
        limits: &Limits,
    ) -> Result<Output> {
        let mut size = 0usize;
        for arg in &args {
            bounded_text(arg, 65_536)?;
            size = size.checked_add(arg.len()).ok_or(Failure::Limit)?;
        }
        require(args.len() <= 4096 && size <= 65_536, Failure::Limit)?;
        let (digest, size) = tool.identity()?;
        self.launch(
            Launch {
                executable: self.tools.get(&tool).cloned().ok_or(Failure::Policy)?,
                digest,
                size,
                args,
                env: self.policy.child_environment()?,
                cwd: self.policy.root.clone(),
                protected: self.protected.clone(),
            },
            input,
            clock,
            limits,
        )
    }

    fn empty() -> Input {
        Input {
            private: None,
            prefix: Vec::new(),
            scalar: None,
        }
    }

    fn stage<T>(
        &mut self,
        name: &str,
        solve: bool,
        work: impl FnOnce(&mut Self, &mut Clock) -> Result<T>,
    ) -> std::result::Result<T, StageError> {
        if !self.usable {
            return Err(StageError {
                failure: Failure::Indeterminate,
                observation: self.last.clone(),
            });
        }
        let start = monotonic_ns();
        self.last = Observation::new(start);
        let mut clock = Clock::new(if solve {
            self.policy.limits.solve_ms
        } else {
            self.policy.limits.metadata_ms
        })
        .map_err(|failure| StageError {
            failure,
            observation: self.last.clone(),
        })?;
        let result = require(valid_name(name) && name.len() <= 255, Failure::Policy)
            .and_then(|_| self.active(&clock))
            .and_then(|_| work(self, &mut clock))
            .and_then(|value| {
                self.active(&clock)?;
                Ok(value)
            });
        clock.cleanup(self.policy.limits.cleanup_ms);
        self.last_clock = Some(clock);
        result.map_err(|failure| {
            self.usable = false;
            self.last.failure = Some(failure);
            self.last.cancellation_requested = self.cancellation.requested();
            self.last.completion_uncertain |= self.last.dispatch != Dispatch::None;
            self.last.finished_ns = monotonic_ns();
            StageError {
                failure,
                observation: self.last.clone(),
            }
        })
    }

    pub fn versions(&mut self, stage: &str) -> std::result::Result<Observation, StageError> {
        self.stage(stage,false,|this,clock| {
            for (tool,args,expected) in [(Tool::Docker,vec!["--version".into()],b"Docker version 28.2.2, build e6534b4\n".as_slice()),
                (Tool::Buildx,vec!["version".into()],b"github.com/docker/buildx v0.25.0 faaea65da4ba0e58a13cd9cadcb950c51cf3b3c9\n".as_slice()),
                (Tool::Buildctl,vec!["--version".into()],b"buildctl github.com/moby/buildkit v0.24.0 b772c318368090fb2ffc9c0fed92e0a35bf82389\n".as_slice())] {
                let output=this.tool(tool,args,Self::empty(),clock,&this.policy.limits.clone())?;
                require(output.observation.exit_code==Some(0)
                    && &output.stdout.get()[..output.stdout_used]==expected && output.stderr_used==0,Failure::Tool)?;
            }
            Ok(this.last.clone())
        })
    }

    pub fn create_builder(
        &mut self,
        stage: &str,
        builder: BuilderPolicy,
    ) -> std::result::Result<Observation, StageError> {
        self.stage(stage, false, |this, clock| {
            builder.validate()?;
            require(this.builder.is_none(), Failure::Policy)?;
            let output = this.tool(
                Tool::Buildx,
                vec![
                    "create".into(),
                    "--name".into(),
                    this.policy.operation_id.clone(),
                    "--driver".into(),
                    "remote".into(),
                    "--driver-opt".into(),
                    builder.driver_options(),
                    builder.endpoint.clone(),
                ],
                Self::empty(),
                clock,
                &this.policy.limits.clone(),
            )?;
            let expected = format!("{}\n", this.policy.operation_id);
            require(
                output.observation.exit_code == Some(0)
                    && &output.stdout.get()[..output.stdout_used] == expected.as_bytes(),
                Failure::Tool,
            )?;
            this.builder = Some(builder);
            this.builder_ready = false;
            this.capabilities = None;
            Ok(this.last.clone())
        })
    }

    pub fn inspect_builder(&mut self, stage: &str) -> std::result::Result<Observation, StageError> {
        self.stage(stage, false, |this, clock| {
            let builder = this.builder.clone().ok_or(Failure::Policy)?;
            builder.validate()?;
            let output = this.tool(
                Tool::Buildx,
                vec![
                    "inspect".into(),
                    this.policy.operation_id.clone(),
                    "--bootstrap".into(),
                ],
                Self::empty(),
                clock,
                &this.policy.limits.clone(),
            )?;
            require(output.observation.exit_code == Some(0), Failure::Tool)?;
            let bytes = &output.stdout.get()[..output.stdout_used];
            let text = std::str::from_utf8(bytes).map_err(|_| Failure::Protocol)?;
            let mut endpoint = false;
            let mut version = false;
            let mut running = false;
            require(
                text.lines().count() <= this.policy.limits.records,
                Failure::Limit,
            )?;
            for line in text.lines() {
                before(clock.end)?;
                require(
                    line.len() <= this.policy.limits.record_bytes,
                    Failure::Limit,
                )?;
                if let Some(value) = line.strip_prefix("Endpoint:") {
                    endpoint = value.trim() == builder.endpoint;
                }
                if let Some(value) = line.strip_prefix("BuildKit version:") {
                    version = value.trim() == "v0.24.0";
                }
                if let Some(value) = line.strip_prefix("Status:") {
                    running = value.trim() == "running";
                }
                require(!line.starts_with("Error:"), Failure::Tool)?;
            }
            require(endpoint && version && running, Failure::Tool)?;
            let output = this.tool(
                Tool::Buildctl,
                builder.worker_args(),
                Self::empty(),
                clock,
                &this.policy.limits.clone(),
            )?;
            require(output.observation.exit_code == Some(0), Failure::Tool)?;
            let value = Value::parse_bounded(
                &output.stdout.get()[..output.stdout_used],
                this.policy.limits.record_bytes,
                this.policy.limits.json_depth,
            )?;
            this.capabilities = Some(worker_capabilities(value, &builder.platforms)?);
            this.builder_ready = true;
            Ok(this.last.clone())
        })
    }

    pub fn builder_capabilities(&self) -> Option<&BuilderCapabilities> {
        self.builder_ready
            .then_some(self.capabilities.as_ref())
            .flatten()
    }

    fn slot(&mut self, stage: &str, kind: &'static str, clock: &mut Clock) -> Result<Slot> {
        self.producer = self.producer.checked_add(1).ok_or(Failure::Limit)?;
        let name = format!("producer-{}", self.producer);
        let staging = self.directories.last().ok_or(Failure::Policy)?.clone();
        let output = self.job(
            "prepare-slot",
            json!({"staging":staging.wire(),"slot_name":name,
            "producer_id":self.producer,"producer_kind":kind}),
            clock,
        )?;
        let value =
            receipt::frame(&output.stdout.get()[..output.stdout_used], 65_536)?.field("result")?;
        let f = value.object(&[b"slot", b"producer_id", b"producer_kind"])?;
        require(
            f[1].number()? == self.producer && f[2].equals(kind)?,
            Failure::Integrity,
        )?;
        Ok(Slot {
            entry: receipt::discovered(f[0], &staging.path.join(name), Kind::Directory)?,
            producer: self.producer,
            kind,
            stage: stage.into(),
        })
    }

    fn verify_output(
        &mut self,
        slot: &Slot,
        root: Option<&Descriptor>,
        cache: bool,
        complete: bool,
        clock: &mut Clock,
    ) -> Result<VerifiedOutput> {
        let content = json!({"kind":"oci","root":root.map(Descriptor::wire),"content_kind":if cache {"cache"} else {"image"},
            "completeness":if complete {"complete"} else {"metadata"},"registry_receipt":slot.kind=="registry"});
        let output = self.job(
            "verify-produced",
            json!({"slot":slot.entry.wire(),"producer_id":slot.producer,
            "producer_kind":slot.kind,"content":content}),
            clock,
        )?;
        let value =
            receipt::frame(&output.stdout.get()[..output.stdout_used], 65_536)?.field("result")?;
        let f = value.object(&[
            b"slot",
            b"producer_id",
            b"producer_kind",
            b"entry",
            b"verified_files",
            b"verified_bytes",
            b"root",
            b"closure_complete",
        ])?;
        let actual = super::content::descriptor(f[6], true)?;
        require(
            f[0].matches(&slot.entry.wire())?
                && f[1].number()? == slot.producer
                && f[2].equals(slot.kind)?
                && f[7].boolean()? == complete
                && root.is_none_or(|root| *root == actual)
                && f[4].number()? > 0
                && f[4].number()? <= self.policy.limits.content.descriptors
                && f[5].number()? <= self.policy.limits.content.content_bytes,
            Failure::Integrity,
        )?;
        self.active(clock)?;
        let entry = receipt::discovered(f[3], &slot.entry.path.join("content"), Kind::Directory)?;
        let result = VerifiedOutput {
            operation: self.policy.operation_id.clone(),
            stage: slot.stage.clone(),
            producer: slot.producer,
            entry,
            root: actual,
            complete,
            files: f[4].number()?,
            bytes: f[5].number()?,
            original_reference: None,
            producer_image: slot.kind == "bake" && !cache && complete,
            receipt: slot.kind == "registry",
            cache,
        };
        require(self.outputs.len() < 4096, Failure::Limit)?;
        self.outputs.push(result.clone());
        Ok(result)
    }

    fn inspect(
        &mut self,
        entry: &Entry,
        content: &Content,
        clock: &mut Clock,
    ) -> Result<(u64, u64)> {
        let output = self.job(
            "inspect-prepared",
            json!({"entry":entry.wire(),"content":content.wire()}),
            clock,
        )?;
        let value =
            receipt::frame(&output.stdout.get()[..output.stdout_used], 65_536)?.field("result")?;
        let f = value.object(&[
            b"entry",
            b"verified_files",
            b"verified_bytes",
            b"root",
            b"closure_complete",
        ])?;
        require(f[0].matches(&entry.wire())?, Failure::Integrity)?;
        match content {
            Content::File { size, .. } => require(
                f[1].number()? == 1
                    && f[2].number()? == *size
                    && f[3].is_null()
                    && !f[4].boolean()?,
                Failure::Integrity,
            )?,
            Content::Oci { root, complete, .. } => require(
                f[1].number()? > 0
                    && f[1].number()? <= self.policy.limits.content.descriptors
                    && f[2].number()? <= self.policy.limits.content.content_bytes
                    && f[3].matches(&root.wire())?
                    && f[4].boolean()? == *complete,
                Failure::Integrity,
            )?,
        }
        Ok((f[1].number()?, f[2].number()?))
    }

    pub(crate) fn usable(&self) -> bool {
        self.usable
    }

    pub(crate) fn recheck_retained(
        &mut self,
        stage: &str,
        output: &VerifiedOutput,
    ) -> std::result::Result<(), StageError> {
        self.recheck(stage, output, false)
    }

    pub(crate) fn recheck_complete(
        &mut self,
        stage: &str,
        output: &VerifiedOutput,
    ) -> std::result::Result<(), StageError> {
        self.recheck(stage, output, true)
    }

    fn recheck(
        &mut self,
        stage: &str,
        output: &VerifiedOutput,
        solve: bool,
    ) -> std::result::Result<(), StageError> {
        self.stage(stage, solve, |this, clock| {
            let retained = output.retained();
            let counts = this.inspect(
                &retained.entry,
                &Content::Oci {
                    root: retained.root.clone(),
                    cache: retained.cache,
                    complete: retained.complete,
                    registry_receipt: retained.receipt,
                },
                clock,
            )?;
            require(
                counts == (retained.files, retained.bytes),
                Failure::Integrity,
            )
        })
    }

    pub(crate) fn source_snapshot(
        &mut self,
        path: &std::path::Path,
        limit: usize,
    ) -> std::result::Result<supervise::SourceBytes, StageError> {
        let error = |this: &Self, failure| StageError {
            failure,
            observation: this.last.clone(),
        };
        let read = supervise::SourceRead::new(path.into(), limit)
            .map_err(|failure| error(self, failure))?;
        let mut clock =
            Clock::new(self.policy.limits.metadata_ms).map_err(|failure| error(self, failure))?;
        self.active(&clock)
            .map_err(|failure| error(self, failure))?;
        let (read, result) =
            supervise::source_local(read, &mut clock, &self.cancellation.0, &self.permit);
        match (read, result) {
            (Some(read), Ok(())) => {
                let bytes = read
                    .take()
                    .ok_or_else(|| error(self, Failure::Indeterminate))?;
                self.active(&clock)
                    .map_err(|failure| error(self, failure))?;
                Ok(bytes)
            }
            (Some(_), Err(failure)) => Err(error(self, failure)),
            (None, result) => {
                let failure = result.err().unwrap_or(Failure::Indeterminate);
                self.usable = false;
                self.last = Observation::new(clock.start);
                self.last.failure = Some(failure);
                self.last.cancellation_requested = self.cancellation.requested();
                self.last.completion_uncertain = true;
                self.last.cleanup_uncertain = true;
                self.last.finished_ns = monotonic_ns();
                clock.cleanup(self.policy.limits.cleanup_ms);
                self.last_clock = Some(clock);
                Err(error(self, failure))
            }
        }
    }

    fn verify_staged(
        &mut self,
        entry: &Entry,
        content: &Content,
        clock: &mut Clock,
    ) -> Result<(u64, u64)> {
        require(
            entry.ownership == Ownership::Operation && entry.path.starts_with(&self.workspace.path),
            Failure::Policy,
        )?;
        let output = self.job(
            "verify-staged",
            json!({"entry":entry.wire(),"content":content.wire()}),
            clock,
        )?;
        let value =
            receipt::frame(&output.stdout.get()[..output.stdout_used], 65_536)?.field("result")?;
        let f = value.object(&[
            b"entry",
            b"verified_files",
            b"verified_bytes",
            b"root",
            b"closure_complete",
        ])?;
        require(f[0].matches(&entry.wire())?, Failure::Integrity)?;
        match content {
            Content::File { size, .. } => require(
                f[1].number()? == 1
                    && f[2].number()? == *size
                    && f[3].is_null()
                    && !f[4].boolean()?,
                Failure::Integrity,
            )?,
            Content::Oci { root, complete, .. } => require(
                f[1].number()? > 0
                    && f[1].number()? <= self.policy.limits.content.descriptors
                    && f[2].number()? <= self.policy.limits.content.content_bytes
                    && f[3].matches(&root.wire())?
                    && f[4].boolean()? == *complete,
                Failure::Integrity,
            )?,
        }
        Ok((f[1].number()?, f[2].number()?))
    }

    pub(crate) fn verify_inputs(
        &mut self,
        stage: &str,
        items: &[(Entry, Content)],
    ) -> std::result::Result<Vec<(u64, u64)>, StageError> {
        self.stage(stage, false, |this, clock| {
            require(items.len() <= 260, Failure::Limit)?;
            let mut counts = Vec::new();
            for (entry, content) in items {
                counts.push(this.verify_staged(entry, content, clock)?);
            }
            Ok(counts)
        })
    }

    pub(crate) fn remaining(&self) -> u64 {
        self.policy
            .limits
            .content
            .staging_bytes
            .saturating_sub(self.owned_bytes)
    }

    pub(crate) fn node_chain(
        &mut self,
        stage: &str,
        output: &VerifiedOutput,
        platform: &str,
    ) -> std::result::Result<(Descriptor, Vec<Descriptor>), StageError> {
        self.stage(stage, false, |_, clock| {
            require(output.producer_image(), Failure::Policy)?;
            let retained = output.retained();
            let chain =
                super::graph::read_chain(&retained.entry, &retained.root, platform, clock.end)?;
            require(chain.indexes.is_empty(), Failure::Integrity)?;
            let value = Value::parse_bounded(chain.manifest.get(), 16_777_216, 128)?;
            let config = super::content::descriptor(value.field("config")?, false)?;
            let mut layers = Vec::new();
            for layer in value.field("layers")?.array()? {
                layers.push(super::content::descriptor(layer, false)?);
            }
            Ok((config, layers))
        })
    }

    pub(crate) fn retained_closure(
        &mut self,
        stage: &str,
        entry: &Entry,
        root: &Descriptor,
        manifests: &[(String, Descriptor)],
    ) -> std::result::Result<Vec<(Descriptor, Vec<Descriptor>)>, StageError> {
        self.stage(stage, false, |this, clock| {
            let mut chains = Vec::new();
            for (platform, manifest) in manifests {
                this.active(clock)?;
                chains.push(super::publish::retained_chain(
                    entry, root, platform, manifest, clock.end,
                )?);
            }
            Ok(chains)
        })
    }

    pub(crate) fn exported_config(
        &mut self,
        stage: &str,
        output: &VerifiedOutput,
        platform: &str,
    ) -> std::result::Result<super::buffer::Bytes, StageError> {
        self.stage(stage, false, |this, clock| {
            require(
                output.operation == this.policy.operation_id && output.producer_image(),
                Failure::Policy,
            )?;
            let chain = super::graph::read_chain(&output.entry, &output.root, platform, clock.end)?;
            Ok(chain.config)
        })
    }

    pub(crate) fn context_snapshot(
        &mut self,
        request: super::solve::ContextRequest,
    ) -> std::result::Result<
        std::result::Result<super::solve::ContextSnapshot, super::solve::ContextRefused>,
        StageError,
    > {
        let error = |this: &Self, failure| StageError {
            failure,
            observation: this.last.clone(),
        };
        let work =
            super::solve::SnapshotWork::new(request).map_err(|failure| error(self, failure))?;
        let mut clock =
            Clock::new(self.policy.limits.solve_ms).map_err(|failure| error(self, failure))?;
        self.active(&clock)
            .map_err(|failure| error(self, failure))?;
        let (work, result) =
            supervise::snapshot_local(work, &mut clock, &self.cancellation.0, &self.permit);
        match (work, result) {
            (Some(work), Ok(())) => {
                let (snapshot, _) = work.take();
                let snapshot = snapshot.ok_or_else(|| error(self, Failure::Indeterminate))?;
                self.active(&clock)
                    .map_err(|failure| error(self, failure))?;
                Ok(Ok(snapshot))
            }
            (Some(work), Err(failure)) => {
                let (_, refused) = work.take();
                Ok(Err(refused.unwrap_or(super::solve::ContextRefused {
                    failure,
                    observed: None,
                })))
            }
            (None, result) => Err(self.lost_action(result, clock)),
        }
    }

    pub(crate) fn materialize_inputs(
        &mut self,
        work: super::solve::MaterializeWork,
    ) -> std::result::Result<
        std::result::Result<super::solve::Materialized, super::solve::Refusal>,
        StageError,
    > {
        let error = |this: &Self, failure| StageError {
            failure,
            observation: this.last.clone(),
        };
        let mut clock =
            Clock::new(self.policy.limits.metadata_ms).map_err(|failure| error(self, failure))?;
        self.active(&clock)
            .map_err(|failure| error(self, failure))?;
        let (work, result) =
            supervise::materialize_local(work, &mut clock, &self.cancellation.0, &self.permit);
        match (work, result) {
            (Some(work), Ok(())) => {
                let (materialized, _) = work.take();
                let materialized =
                    materialized.ok_or_else(|| error(self, Failure::Indeterminate))?;
                self.active(&clock)
                    .map_err(|failure| error(self, failure))?;
                Ok(Ok(materialized))
            }
            (Some(work), Err(failure)) => {
                let (_, check) = work.take();
                Ok(Err(super::solve::Refusal { failure, check }))
            }
            (None, result) => Err(self.lost_action(result, clock)),
        }
    }

    fn lost_action(&mut self, result: Result<()>, mut clock: Clock) -> StageError {
        let failure = result.err().unwrap_or(Failure::Indeterminate);
        self.usable = false;
        self.last = Observation::new(clock.start);
        self.last.failure = Some(failure);
        self.last.cancellation_requested = self.cancellation.requested();
        self.last.completion_uncertain = true;
        self.last.cleanup_uncertain = true;
        self.last.finished_ns = monotonic_ns();
        clock.cleanup(self.policy.limits.cleanup_ms);
        self.last_clock = Some(clock);
        StageError {
            failure,
            observation: self.last.clone(),
        }
    }

    pub fn registry(
        &mut self,
        stage: &str,
        request: RegistryRequest,
        scalar: Option<OwnedSecret>,
    ) -> std::result::Result<RegistryOutcome, StageError> {
        self.stage(stage, true, |this, clock| {
            request.validate()?;
            clock.cleanup_limit_ms = this
                .policy
                .limits
                .cleanup_ms
                .min(request.limit("cleanup_ms"));
            if let Some(scalar) = &scalar {
                require(
                    request.auth != RegistryAuth::Anonymous
                        && !scalar.as_str().is_empty()
                        && !scalar.as_str().contains('\0')
                        && scalar.as_str().len() as u64 <= request.limit("credential_bytes"),
                    Failure::Policy,
                )?;
                if request.auth == RegistryAuth::Bearer {
                    require(
                        scalar.as_str().bytes().all(|c| (33..=126).contains(&c)),
                        Failure::Policy,
                    )?;
                }
            } else {
                require(request.auth == RegistryAuth::Anonymous, Failure::Policy)?;
            }
            clock.end = clock
                .end
                .min(deadline(clock.start, request.limit("operation_ms"))?);
            if request.inspect_input {
                let input = request.input.as_ref().ok_or(Failure::Policy)?;
                this.inspect(
                    input,
                    &Content::Oci {
                        root: request.expected_root.clone().ok_or(Failure::Policy)?,
                        cache: request.cache,
                        complete: true,
                        registry_receipt: false,
                    },
                    clock,
                )?;
            }
            let slot = this.slot(stage, "registry", clock)?;
            let allowance =
                helper_allowance(this.policy.limits.content.staging_bytes, this.owned_bytes)?;
            let header = request.header(
                &this.policy.operation_id,
                &slot.entry.path.join("content"),
                allowance,
                clock.end.saturating_sub(monotonic_ns()) / 1_000_000,
            )?;
            let mut prefix = framed(&header, request.limit("header_bytes") as usize)?;
            prefix.extend_from_slice(
                &(scalar.as_ref().map_or(0, |s| s.as_str().len()) as u32).to_be_bytes(),
            );
            let mut limits = this.policy.limits.clone();
            limits.handoff_ms = limits.handoff_ms.min(request.limit("frame_ms"));
            limits.idle_ms = limits.idle_ms.min(request.limit("idle_ms"));
            limits.cleanup_ms = limits.cleanup_ms.min(request.limit("cleanup_ms"));
            let output = this.tool(
                Tool::Registry,
                Vec::new(),
                Input {
                    prefix,
                    scalar,
                    private: None,
                },
                clock,
                &limits,
            )?;
            require(
                output.stderr_used as u64 <= request.limit("stderr_bytes"),
                Failure::Limit,
            )?;
            let receipt = receipt::registry(&output, &request, &header).inspect_err(|_| {
                this.last.cleanup_uncertain = true;
            })?;
            this.last.completion_uncertain |= receipt.completion_uncertain;
            this.last.cleanup_uncertain |= receipt.cleanup_uncertain;
            if let Some(failure) = receipt.failure {
                return Err(failure);
            }
            let mut observation = output.observation.clone();
            if receipt.cache_miss {
                observation.failure = Some(Failure::CacheMiss);
            }
            drop(output);
            let verified = if request.action != RegistryAction::Upload && !receipt.cache_miss {
                let mut value = this.verify_output(
                    &slot,
                    receipt.root.as_ref(),
                    request.cache,
                    receipt.complete,
                    clock,
                )?;
                require(
                    value.files == receipt.verified_files && value.bytes == receipt.verified_bytes,
                    Failure::Integrity,
                )?;
                if !request.cache {
                    value.original_reference =
                        Some(super::analysis::normalize(&request.reference)?);
                    *this.outputs.last_mut().ok_or(Failure::Integrity)? = value.clone();
                }
                Some(value)
            } else {
                this.job(
                    "cleanup",
                    json!({"roots":[slot.entry.wire()],"preserve":[]}),
                    clock,
                )?;
                None
            };
            Ok(RegistryOutcome {
                observation,
                output: verified,
                root: receipt.root,
                optional_cache_miss: receipt.cache_miss,
                closure_complete: receipt.complete,
                verified: (receipt.verified_files, receipt.verified_bytes),
                helper_allowance: allowance,
            })
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bake(
        &mut self,
        stage: &str,
        target: &str,
        bake: Entry,
        digest: String,
        size: u64,
        read_paths: &[PathBuf],
        expected_root: Option<Descriptor>,
    ) -> std::result::Result<VerifiedOutput, StageError> {
        let platforms = self
            .builder
            .as_ref()
            .map(|builder| builder.platforms.clone())
            .unwrap_or_default();
        self.bake_selected(
            stage,
            target,
            bake,
            digest,
            size,
            read_paths,
            expected_root,
            &platforms,
            &ProtectedOptions::default(),
            &CacheArguments::default(),
        )
        .map(|baked| baked.image)
        .map_err(StageError::from)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bake_selected(
        &mut self,
        stage: &str,
        target: &str,
        bake: Entry,
        digest: String,
        size: u64,
        read_paths: &[PathBuf],
        expected_root: Option<Descriptor>,
        platforms: &[String],
        protected: &ProtectedOptions,
        cache: &CacheArguments,
    ) -> std::result::Result<Baked, BakeFailure> {
        let mut export_failed = false;
        let mut launched = false;
        let result = self.stage(stage, true, |this, clock| {
            require(
                valid_name(target)
                    && target.len() <= 255
                    && read_paths.len() + cache.imports.len() <= 128,
                Failure::Policy,
            )?;
            let builder = this.builder.clone().ok_or(Failure::Policy)?;
            builder.validate()?;
            require(this.builder_ready, Failure::Policy)?;
            if bake.ownership == Ownership::Operation {
                this.verify_staged(&bake, &Content::File { digest, size }, clock)?;
            } else {
                this.inspect(&bake, &Content::File { digest, size }, clock)?;
            }
            let slot = this.slot(stage, "bake", clock)?;
            let export = match cache.export {
                Some(_) => Some(this.slot(stage, "bake", clock)?),
                None => None,
            };
            let args = bake_arguments(
                &this.policy,
                &builder,
                target,
                &bake,
                read_paths,
                &slot.entry.path,
                platforms,
                protected,
                cache,
                export.as_ref().map(|slot| slot.entry.path.as_path()),
            )?;
            let dispatches = this.dispatches;
            let output = this.tool(
                Tool::Buildx,
                args,
                Self::empty(),
                clock,
                &this.policy.limits.clone(),
            );
            launched = this.dispatches > dispatches;
            let output = output?;
            require(
                output.observation.exit_code == Some(0) && output.stdout_used == 0,
                Failure::Tool,
            )?;
            super::progress::validate(
                &output.stderr.get()[..output.stderr_used],
                &this.policy.limits,
                clock.end,
            )?;
            drop(output);
            let image = this.verify_output(&slot, expected_root.as_ref(), false, true, clock)?;
            let export = match export {
                Some(slot) => Some(
                    this.verify_output(&slot, None, true, true, clock)
                        .inspect_err(|_| export_failed = true)?,
                ),
                None => None,
            };
            Ok(Baked { image, export })
        });
        result.map_err(|error| BakeFailure {
            error,
            export: export_failed,
            launched,
        })
    }

    fn public_action<W: PublicAction + 'static>(
        &mut self,
        work: W,
        clock: &mut Clock,
    ) -> Result<(Option<W>, Result<()>)> {
        clock.cleanup_limit_ms = clock.cleanup_limit_ms.min(self.policy.limits.cleanup_ms);
        let (work, result) =
            supervise::public_local(work, clock, &self.cancellation.0, &self.permit);
        if work.is_none() {
            self.last.completion_uncertain = true;
            self.last.cleanup_uncertain = true;
        }
        Ok((work, result))
    }

    pub(crate) fn upload_layout(
        &mut self,
        export: &VerifiedOutput,
    ) -> std::result::Result<VerifiedOutput, StageError> {
        let work = UploadWork::new(
            self.workspace.clone(),
            export.entry.clone(),
            export.root.clone(),
            self.policy.limits.content.clone(),
        );
        let entry = self.stage("cache-upload", false, |this, clock| {
            require(
                export.operation == this.policy.operation_id
                    && export.cache
                    && export.complete
                    && !export.receipt,
                Failure::Policy,
            )?;
            match this.public_action(work?, clock)? {
                (Some(work), Ok(())) => work.take().ok_or(Failure::Indeterminate),
                (_, result) => Err(result.err().unwrap_or(Failure::Indeterminate)),
            }
        })?;
        let (files, bytes) = self.stage("verify-upload", true, |this, clock| {
            let counts = this.verify_staged(
                &entry,
                &Content::Oci {
                    root: export.root.clone(),
                    cache: true,
                    complete: true,
                    registry_receipt: false,
                },
                clock,
            )?;
            require(counts == (export.files, export.bytes), Failure::Integrity)?;
            require(this.outputs.len() < 4096, Failure::Limit)?;
            Ok(counts)
        })?;
        let layout = VerifiedOutput {
            operation: self.policy.operation_id.clone(),
            stage: "cache-upload".into(),
            producer: export.producer,
            entry,
            root: export.root.clone(),
            complete: true,
            files,
            bytes,
            original_reference: None,
            producer_image: false,
            receipt: false,
            cache: true,
        };
        self.outputs.push(layout.clone());
        Ok(layout)
    }

    pub(crate) fn publication_layout(
        &mut self,
        work: publish::PublishWork,
        root: &Descriptor,
    ) -> std::result::Result<(VerifiedOutput, u64, u64), StageError> {
        let entry = self.stage("publish-layout", false, |this, clock| {
            match this.public_action(work, clock)? {
                (Some(work), Ok(())) => work.take().ok_or(Failure::Indeterminate),
                (_, result) => Err(result.err().unwrap_or(Failure::Indeterminate)),
            }
        })?;
        self.verified_layout(entry, root, "publish-layout")
    }

    pub(crate) fn publication_unpack(
        &mut self,
        work: publish::UnpackWork,
        root: &Descriptor,
    ) -> std::result::Result<(VerifiedOutput, u64, u64), StageError> {
        let entry = self.stage("publish-unpack", true, |this, clock| {
            match this.public_action(work, clock)? {
                (Some(work), Ok(())) => work.take().ok_or(Failure::Indeterminate),
                (_, result) => Err(result.err().unwrap_or(Failure::Indeterminate)),
            }
        })?;
        self.verified_layout(entry, root, "publish-unpack")
    }

    fn verified_layout(
        &mut self,
        entry: Entry,
        root: &Descriptor,
        stage: &'static str,
    ) -> std::result::Result<(VerifiedOutput, u64, u64), StageError> {
        let (files, bytes) = self.stage("verify-publication", true, |this, clock| {
            let counts = this.verify_staged(&entry, &publication_content(root), clock)?;
            require(this.outputs.len() < 4096, Failure::Limit)?;
            Ok(counts)
        })?;
        let layout = VerifiedOutput {
            operation: self.policy.operation_id.clone(),
            stage: stage.into(),
            producer: self.producer,
            entry,
            root: root.clone(),
            complete: true,
            files,
            bytes,
            original_reference: None,
            producer_image: false,
            receipt: false,
            cache: false,
        };
        self.outputs.push(layout.clone());
        Ok((layout, files, bytes))
    }

    pub(crate) fn daemon_socket(&mut self, socket: &Path) -> std::result::Result<(), StageError> {
        let work = protected::DaemonCheck::new(socket.into());
        self.stage("daemon-socket", false, |this, clock| {
            match this.public_action(work, clock)? {
                (Some(work), Ok(())) => {
                    this.protected = work.take().ok_or(Failure::Indeterminate)?;
                    this.daemon = Some(socket.into());
                    Ok(())
                }
                (_, result) => Err(result.err().unwrap_or(Failure::Indeterminate)),
            }
        })
    }

    pub(crate) fn assemble(
        &mut self,
        work: AssembleWork,
        root: &Descriptor,
    ) -> std::result::Result<Entry, StageError> {
        self.stage("assemble", false, |this, clock| {
            let entry = match this.public_action(work, clock)? {
                (Some(work), Ok(())) => work.take().ok_or(Failure::Indeterminate)?,
                (_, result) => return Err(result.err().unwrap_or(Failure::Indeterminate)),
            };
            this.verify_staged(
                &entry,
                &Content::Oci {
                    root: root.clone(),
                    cache: false,
                    complete: false,
                    registry_receipt: false,
                },
                clock,
            )?;
            Ok(entry)
        })
    }

    pub(crate) fn retain(
        &mut self,
        work: RetainWork,
    ) -> (Option<RetainWork>, std::result::Result<(), StageError>) {
        let mut observed = None;
        let result = self.stage("retain", true, |this, clock| {
            let (work, result) = this.public_action(work, clock)?;
            observed = work;
            result
        });
        (observed, result)
    }

    pub fn inspect_published(
        &mut self,
        entry: &Entry,
        root: &Descriptor,
    ) -> std::result::Result<(u64, u64), StageError> {
        self.stage("inspect-retained", true, |this, clock| {
            require(entry.ownership == Ownership::Retained, Failure::Policy)?;
            this.inspect(
                entry,
                &Content::Oci {
                    root: root.clone(),
                    cache: false,
                    complete: true,
                    registry_receipt: false,
                },
                clock,
            )
        })
    }

    pub(crate) fn docker_archive(
        &mut self,
        work: ArchiveWork,
    ) -> std::result::Result<(Entry, String, u64), StageError> {
        self.stage("docker-archive", true, |this, clock| {
            match this.public_action(work, clock)? {
                (Some(work), Ok(())) => work.result.ok_or(Failure::Indeterminate),
                (_, result) => Err(result.err().unwrap_or(Failure::Indeterminate)),
            }
        })
    }

    fn docker(&self, args: &[&str]) -> Result<Vec<String>> {
        let socket = self.daemon.as_ref().ok_or(Failure::Policy)?;
        let mut command = vec![
            "--host".to_string(),
            format!("unix://{}", socket.to_str().ok_or(Failure::Policy)?),
        ];
        command.extend(args.iter().map(|arg| (*arg).to_string()));
        Ok(command)
    }

    pub(crate) fn docker_load(
        &mut self,
        archive: &Entry,
        digest: &str,
        size: u64,
        familiar: &str,
    ) -> std::result::Result<(), StageError> {
        self.stage("docker-load", true, |this, clock| {
            this.verify_staged(
                archive,
                &Content::File {
                    digest: digest.into(),
                    size,
                },
                clock,
            )?;
            let args = this.docker(&[
                "load",
                "--quiet",
                "--input",
                archive.path.to_str().ok_or(Failure::Policy)?,
            ])?;
            let mut limits = this.policy.limits.clone();
            limits.stream_bytes = 65_536;
            let output = this.tool(Tool::Docker, args, Self::empty(), clock, &limits)?;
            require(
                output.observation.exit_code == Some(0)
                    && load_output(&output.stdout.get()[..output.stdout_used], familiar),
                Failure::Tool,
            )
        })
    }

    pub(crate) fn docker_inspect(
        &mut self,
        reference: &str,
    ) -> std::result::Result<Inspected, StageError> {
        self.stage("docker-inspect", false, |this, clock| {
            let args = this.docker(&["image", "inspect", "--format", INSPECT_FORMAT, reference])?;
            let mut limits = this.policy.limits.clone();
            limits.stream_bytes = 65_536;
            let output = this.tool(Tool::Docker, args, Self::empty(), clock, &limits)?;
            require(output.observation.exit_code == Some(0), Failure::Tool)?;
            inspected(&output.stdout.get()[..output.stdout_used])
        })
    }

    pub fn remove_builder(&mut self, stage: &str) -> std::result::Result<Observation, StageError> {
        self.stage(stage, false, |this, clock| {
            require(this.builder.is_some(), Failure::Policy)?;
            let output = this.tool(
                Tool::Buildx,
                vec![
                    "rm".into(),
                    "--keep-daemon".into(),
                    this.policy.operation_id.clone(),
                ],
                Self::empty(),
                clock,
                &this.policy.limits.clone(),
            )?;
            require(output.observation.exit_code == Some(0), Failure::Tool)?;
            this.builder = None;
            this.builder_ready = false;
            Ok(this.last.clone())
        })
    }

    pub fn cleanup(self, keep: &[VerifiedOutput]) -> std::result::Result<Observation, StageError> {
        self.close(None, keep).result
    }

    pub(crate) fn protected_action(
        &mut self,
        lease: protected::Lease,
        action: protected::Action,
    ) -> (
        Option<protected::Lease>,
        std::result::Result<(), StageError>,
    ) {
        let milliseconds = if matches!(&action, protected::Action::Materialize(_)) {
            self.policy.limits.handoff_ms
        } else {
            self.policy.limits.metadata_ms
        };
        let mut clock = match Clock::new(milliseconds) {
            Ok(clock) => clock,
            Err(failure) => {
                return (
                    Some(lease),
                    Err(StageError {
                        failure,
                        observation: self.last.clone(),
                    }),
                );
            }
        };
        if let Err(failure) = self.active(&clock) {
            return (
                Some(lease),
                Err(StageError {
                    failure,
                    observation: self.last.clone(),
                }),
            );
        }
        let (lease, result) = supervise::local(
            lease,
            action,
            &mut clock,
            &self.cancellation.0,
            &self.permit,
        );
        if let Some(lease) = &lease {
            self.protected = lease.checks();
        }
        if let Err(failure) = result {
            self.usable = false;
            self.last = Observation::new(clock.start);
            self.last.failure = Some(failure);
            self.last.cancellation_requested = self.cancellation.requested();
            self.last.completion_uncertain = lease.is_none();
            self.last.cleanup_uncertain = lease.is_none();
            self.last.finished_ns = monotonic_ns();
            clock.cleanup(self.policy.limits.cleanup_ms);
            self.last_clock = Some(clock);
            return (
                lease,
                Err(StageError {
                    failure,
                    observation: self.last.clone(),
                }),
            );
        }
        (lease, Ok(()))
    }

    pub(crate) fn refusal_deadline(&mut self) {
        if self.usable {
            self.last_clock = Clock::new(self.policy.limits.metadata_ms)
                .ok()
                .map(|mut clock| {
                    clock.cleanup(self.policy.limits.cleanup_ms);
                    clock
                });
        }
    }

    pub(crate) fn acquisition_failed(&mut self, failure: Failure) {
        if self.usable {
            self.last = Observation::new(monotonic_ns());
            self.last.failure = Some(failure);
            self.last.cancellation_requested = self.cancellation.requested();
            self.last_clock = Clock::new(self.policy.limits.metadata_ms)
                .ok()
                .map(|mut clock| {
                    clock.cleanup(self.policy.limits.cleanup_ms);
                    clock
                });
            self.usable = false;
        }
    }

    pub(crate) fn close(
        mut self,
        mut lease: Option<protected::Lease>,
        keep: &[VerifiedOutput],
    ) -> Close {
        let mut private_residue = lease.as_ref().is_some_and(|lease| lease.residue());
        let mut unresolved_private_owner = false;
        let mut clock = match self.last_clock.take() {
            Some(clock) => clock,
            None => match Clock::new(self.policy.limits.metadata_ms) {
                Ok(clock) => clock,
                Err(failure) => {
                    return Close {
                        result: Err(StageError {
                            failure,
                            observation: self.last.clone(),
                        }),
                        private_residue,
                        unresolved_private_owner,
                        kept: None,
                    };
                }
            },
        };
        let until = clock.cleanup(self.policy.limits.cleanup_ms);
        clock.end = until;
        let mut metadata_failure = None;
        let result = (|| {
            require(!self.last.cleanup_uncertain, Failure::Indeterminate)?;
            let mut preserve = Vec::new();
            for output in keep {
                require(
                    output.operation == self.policy.operation_id
                        && self.outputs.iter().any(|known| {
                            known.producer == output.producer
                                && known.entry == output.entry
                                && known.root == output.root
                        }),
                    Failure::Policy,
                )?;
                let mut entry = output.entry.clone();
                entry.ownership = Ownership::Retained;
                preserve.push(entry.wire());
            }
            self.usable = true;
            self.cancellation = Cancellation::default();
            if self.builder.is_some() {
                match self.tool(
                    Tool::Buildx,
                    vec![
                        "rm".into(),
                        "--keep-daemon".into(),
                        self.policy.operation_id.clone(),
                    ],
                    Self::empty(),
                    &mut clock,
                    &self.policy.limits.clone(),
                ) {
                    Ok(output) if output.observation.exit_code == Some(0) => {
                        self.builder = None;
                        self.builder_ready = false;
                    }
                    Ok(_) => metadata_failure = Some(Failure::Tool),
                    Err(failure) => metadata_failure = Some(failure),
                }
            }
            require(!self.last.cleanup_uncertain, Failure::Indeterminate)?;
            if let Some(owned) = lease.take() {
                let (observed, result) = supervise::local(
                    owned,
                    protected::Action::Cleanup,
                    &mut clock,
                    &self.cancellation.0,
                    &self.permit,
                );
                unresolved_private_owner = observed.is_none();
                private_residue = observed.as_ref().is_none_or(|lease| lease.residue());
                result?;
            }
            self.protected = protected::Checks::default();
            let output = self.job(
                "cleanup",
                json!({"roots":[self.workspace.wire()],"preserve":preserve}),
                &mut clock,
            )?;
            let value = receipt::frame(&output.stdout.get()[..output.stdout_used], 65_536)?
                .field("result")?;
            let f = value.object(&[b"removed_entries", b"preserved_entries"])?;
            require(
                f[0].number()? <= self.policy.limits.content.entries
                    && f[1].number()? == keep.len() as u64,
                Failure::Protocol,
            )?;
            Ok(output.observation.clone())
        })();
        let result = metadata_failure.map_or(result, Err).map_err(|failure| {
            self.last.failure = Some(failure);
            self.last.cleanup_uncertain = true;
            StageError {
                failure,
                observation: self.last.clone(),
            }
        });
        let kept = (result.is_ok() && !keep.is_empty()).then(|| Kept {
            token: ReleaseToken {
                operation_id: self.policy.operation_id.clone(),
                workspace: self.workspace.clone(),
                job: self.job.saturating_add(1),
            },
            entries: keep.iter().map(|output| output.retained().entry).collect(),
        });
        Close {
            result,
            private_residue,
            unresolved_private_owner,
            kept,
        }
    }
}

pub(crate) struct Close {
    pub(crate) result: std::result::Result<Observation, StageError>,
    pub(crate) private_residue: bool,
    pub(crate) unresolved_private_owner: bool,
    pub(crate) kept: Option<Kept>,
}

pub(crate) fn release(
    policy: Policy,
    kept: Kept,
    cancellation: Cancellation,
) -> std::result::Result<Observation, Box<Unreleased>> {
    let start = monotonic_ns();
    let refused = |kept, failure| {
        Box::new(Unreleased {
            kept: Some(kept),
            error: StageError {
                failure,
                observation: Observation::new(start),
            },
        })
    };
    if cancellation.requested() {
        return Err(refused(kept, Failure::Cancellation));
    }
    if policy.operation_id != kept.token.operation_id
        || kept.token.workspace.path != policy.workspace_path()
        || policy.validate().is_err()
    {
        return Err(refused(kept, Failure::Policy));
    }
    let mut clock = match Clock::new(policy.limits.metadata_ms) {
        Ok(clock) => clock,
        Err(failure) => return Err(refused(kept, failure)),
    };
    let permit = match Permit::acquire() {
        Ok(permit) => permit,
        Err(failure) => return Err(refused(kept, failure)),
    };
    let token = &kept.token;
    let mut owner = Operation {
        policy,
        cancellation,
        permit,
        workspace: token.workspace.clone(),
        directories: Vec::new(),
        tools: BTreeMap::new(),
        job: token.job.saturating_sub(1),
        producer: 0,
        owned_bytes: 0,
        usable: true,
        dispatches: 0,
        last: Observation::new(start),
        last_clock: None,
        protected: protected::Checks::default(),
        builder: None,
        builder_ready: false,
        capabilities: None,
        outputs: Vec::new(),
        analysis_attempt: 0,
        analysis_preparation: None,
        daemon: None,
    };
    let result = owner
        .job(
            "cleanup",
            json!({"roots":[token.workspace.wire()],"preserve":[]}),
            &mut clock,
        )
        .and_then(|output| {
            let value = receipt::frame(&output.stdout.get()[..output.stdout_used], 65_536)?
                .field("result")?;
            let f = value.object(&[b"removed_entries", b"preserved_entries"])?;
            require(
                f[0].number()? <= owner.policy.limits.content.entries && f[1].number()? == 0,
                Failure::Protocol,
            )?;
            Ok(output.observation.clone())
        });
    clock.cleanup(owner.policy.limits.cleanup_ms);
    result.map_err(|failure| {
        let dispatched = owner.last.dispatch != Dispatch::None;
        let mut observation = owner.last.clone();
        observation.failure = Some(failure);
        observation.cancellation_requested = owner.cancellation.requested();
        Box::new(Unreleased {
            kept: (!dispatched).then_some(kept),
            error: StageError {
                failure,
                observation,
            },
        })
    })
}

pub(crate) fn publication_content(root: &Descriptor) -> Content {
    Content::Oci {
        root: root.clone(),
        cache: false,
        complete: true,
        registry_receipt: false,
    }
}

pub(crate) fn helper_allowance(maximum: u64, owned: u64) -> Result<u64> {
    let remainder = maximum.checked_sub(owned).ok_or(Failure::Limit)?;
    require(remainder > 0, Failure::Limit)?;
    Ok(remainder)
}

const INSPECT_FORMAT: &str = "{\"id\":{{json .ID}},\"os\":{{json .Os}},\"architecture\":{{json .Architecture}},\"variant\":{{json .Variant}}}";

pub(crate) fn load_output(stdout: &[u8], familiar: &str) -> bool {
    let Some(text) = std::str::from_utf8(stdout)
        .ok()
        .and_then(|text| text.strip_suffix('\n'))
    else {
        return false;
    };
    let loaded = format!("Loaded image: {familiar}");
    let renamed = |line: &str| {
        line.strip_prefix(&format!(
            "The image {familiar} already exists, renaming the old one with ID sha256:"
        ))
        .and_then(|rest| rest.strip_suffix(" to empty string"))
        .is_some_and(|id| id.len() == 64 && hex(id.as_bytes()))
    };
    match text.split('\n').collect::<Vec<_>>().as_slice() {
        [last] => *last == loaded,
        [first, last] => *last == loaded && renamed(first),
        _ => false,
    }
}

pub(crate) fn inspected(stdout: &[u8]) -> Result<Inspected> {
    let line = stdout.strip_suffix(b"\n").ok_or(Failure::Protocol)?;
    let value = Value::parse_bounded(line, 65_536, 4).map_err(|_| Failure::Protocol)?;
    let fields = value
        .object(&[b"id", b"os", b"architecture", b"variant"])
        .map_err(|_| Failure::Protocol)?;
    let text = |value: Value<'_>| -> Result<String> {
        let bytes = value.text().map_err(|_| Failure::Protocol)?;
        String::from_utf8(bytes.get().to_vec()).map_err(|_| Failure::Protocol)
    };
    Ok(Inspected {
        id: text(fields[0])?,
        os: text(fields[1])?,
        architecture: text(fields[2])?,
        variant: text(fields[3])?,
    })
}

#[derive(Default)]
pub(crate) struct ProtectedOptions {
    pub(crate) selected: bool,
    pub(crate) secrets: BTreeMap<String, PathBuf>,
    pub(crate) ssh: BTreeMap<String, PathBuf>,
    pub(crate) stage: Option<String>,
}
impl ProtectedOptions {
    fn apply(&self, target: &str, args: &mut Vec<String>) -> Result<()> {
        if !self.selected {
            return Ok(());
        }
        require(
            self.secrets.len() <= 128 && self.ssh.len() <= 128,
            Failure::Limit,
        )?;
        args.extend([
            "--set".into(),
            format!("{target}.target={}", self.stage.as_deref().unwrap_or("")),
        ]);
        for (field, entries) in [("secrets", &self.secrets), ("ssh", &self.ssh)] {
            if entries.is_empty() {
                args.extend(["--set".into(), format!("{target}.{field}=")]);
            }
            for (id, path) in entries {
                require(
                    valid_name(id)
                        && id.len() <= 255
                        && valid_path(path)
                        && !path.to_string_lossy().contains([',', '\n', '\r']),
                    Failure::Policy,
                )?;
                let value = if field == "secrets" {
                    format!("type=file,id={id},src={}", path.display())
                } else {
                    format!("{id}={}", path.display())
                };
                args.extend(["--set".into(), format!("{target}.{field}={value}")]);
                args.extend(["--allow".into(), format!("fs.read={}", path.display())]);
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn bake_arguments(
    policy: &Policy,
    builder: &BuilderPolicy,
    target: &str,
    bake: &Entry,
    read_paths: &[PathBuf],
    slot: &std::path::Path,
    platforms: &[String],
    protected: &ProtectedOptions,
    cache: &CacheArguments,
    export: Option<&std::path::Path>,
) -> Result<Vec<String>> {
    require(
        !platforms.is_empty()
            && platforms.len() <= 64
            && platforms.iter().all(|p| valid_platform(p)),
        Failure::Policy,
    )?;
    let destination = slot.join("content");
    let mut args = vec![
        "bake".into(),
        "--builder".into(),
        policy.operation_id.clone(),
        "--file".into(),
        bake.path.display().to_string(),
        "--progress=rawjson".into(),
        "--set".into(),
        format!(
            "{target}.output=type=oci,dest={},tar=false",
            destination.display()
        ),
        "--set".into(),
        format!("{target}.platform={}", platforms.join(",")),
        "--allow".into(),
        format!("fs.write={}", slot.display()),
    ];
    for path in read_paths {
        require(valid_path(path), Failure::Policy)?;
        args.extend(["--allow".into(), format!("fs.read={}", path.display())]);
    }
    for entitlement in &builder.entitlements {
        args.extend(["--allow".into(), entitlement.clone()]);
    }
    for (staging, root) in &cache.imports {
        require(
            valid_path(&staging.path) && super::solve::csv_safe(&staging.path),
            Failure::Policy,
        )?;
        root.validate()?;
        args.extend([
            "--set".into(),
            format!(
                "{target}.cache-from=type=local,src={},digest={}",
                staging.path.display(),
                root.digest
            ),
            "--allow".into(),
            format!("fs.read={}", staging.path.display()),
        ]);
    }
    match (cache.export, export) {
        (Some(mode), Some(slot)) => {
            require(
                matches!(mode, "min" | "max") && super::solve::csv_safe(slot),
                Failure::Policy,
            )?;
            args.extend([
                "--set".into(),
                format!(
                    "{target}.cache-to=type=local,dest={},mode={mode},oci-mediatypes=true,image-manifest=true",
                    slot.join("content").display()
                ),
                "--allow".into(),
                format!("fs.write={}", slot.display()),
            ]);
        }
        (None, None) => {}
        _ => return Err(Failure::Policy),
    }
    protected.apply(target, &mut args)?;
    args.push(target.into());
    let mut bytes = 0usize;
    for arg in &args {
        bounded_text(arg, 65_536)?;
        bytes = bytes.checked_add(arg.len()).ok_or(Failure::Limit)?;
    }
    require(args.len() <= 4096 && bytes <= 65_536, Failure::Limit)?;
    Ok(args)
}

pub(super) fn worker_capabilities(
    value: Value<'_>,
    requested: &[String],
) -> Result<BuilderCapabilities> {
    let mut found = vec![false; requested.len()];
    let mut discovered = std::collections::BTreeSet::new();
    let nodes = value.array()?;
    require(nodes.len() <= 128, Failure::Limit)?;
    let mut oci_worker = false;
    let mut first: Option<Option<String>> = None;
    for node in nodes {
        if !node
            .field("labels")?
            .field("org.mobyproject.buildkit.worker.executor")?
            .equals("oci")?
        {
            continue;
        }
        oci_worker = true;
        let platforms = node.field("platforms")?.array()?;
        require(platforms.len() <= 128, Failure::Limit)?;
        let first_worker = first.is_none();
        if first_worker {
            first = Some(None);
        }
        for (ordinal, platform) in platforms.iter().enumerate() {
            let mut spelled = None;
            if platform.field("os")?.equals("linux")? {
                for arch in [
                    "amd64", "arm64", "arm", "386", "ppc64le", "s390x", "riscv64",
                ] {
                    if platform.field("architecture")?.equals(arch)? {
                        match platform.optional("variant")? {
                            None => {
                                spelled = Some(format!("linux/{arch}"));
                            }
                            Some(value) if value.equals("")? => {
                                spelled = Some(format!("linux/{arch}"));
                            }
                            Some(value) => {
                                for variant in ["v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9"] {
                                    if value.equals(variant)? {
                                        spelled = Some(format!("linux/{arch}/{variant}"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(name) = &spelled {
                discovered.insert(name.clone());
            }
            if first_worker && ordinal == 0 {
                first = Some(spelled.clone());
            }
            let platform = *platform;
            for (i, wanted) in requested.iter().enumerate() {
                let mut parts = wanted.split('/');
                let os = parts.next().ok_or(Failure::Policy)?;
                let arch = parts.next().ok_or(Failure::Policy)?;
                let variant = parts.next();
                if platform.field("os")?.equals(os)?
                    && platform.field("architecture")?.equals(arch)?
                    && match variant {
                        Some(v) => platform
                            .optional("variant")?
                            .is_some_and(|x| x.equals(v).unwrap_or(false)),
                        None => true,
                    }
                {
                    found[i] = true;
                }
            }
        }
    }
    require(oci_worker && found.iter().all(|x| *x), Failure::Tool)?;
    let build_platform = first.flatten().ok_or(Failure::Tool)?;
    Ok(BuilderCapabilities {
        version: "0.24.0",
        oci_worker,
        platforms: discovered.into_iter().collect(),
        build_platform,
    })
}
