// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod protocol;
pub(crate) mod records;

use super::{
    Cancellation, Policy,
    common::*,
    consumers,
    supervise::{self, Clock, Permit, Task},
};
use broil_config::{LoadedProject, images::select};
use broil_core::{
    images::BuilderKind,
    secret::{environment::ordinary_snapshot, path_safety::sudo_nonce},
};
use broil_remote::{
    EffectiveInventory, EffectiveMachine, FailureClass,
    exec::{StaticStdin, private},
    scheduler::CancellationToken,
};
pub use protocol::{Receipt, Resource};
use serde_json::{Value as Json, json};
use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Debug)]
pub enum Action {
    Access,
    Inspect,
    Setup {
        archive: PathBuf,
        arm64_emulation: bool,
    },
    Reconcile {
        archive: PathBuf,
        arm64_emulation: bool,
    },
    Remove {
        purge: bool,
    },
}

#[derive(Clone, Debug)]
pub struct Selection {
    pub builder: String,
    pub stage: String,
    pub protected_parent: PathBuf,
    pub action: Action,
}

#[derive(Debug)]
pub struct Step {
    pub action: String,
    pub step: u64,
    pub transport: private::Observation,
    pub receipt: Option<Receipt>,
    pub upload: Option<private::UploadOutcome>,
    pub local_failure: Option<Failure>,
}

#[derive(Debug)]
pub struct Outcome {
    pub result: Result<()>,
    pub record: Option<PathBuf>,
    pub steps: Vec<Step>,
    pub endpoint: Option<consumers::Outcome<consumers::BuilderOutcome>>,
    pub ownership_uncertain: bool,
}

pub struct Builder<'a> {
    project: &'a LoadedProject,
    policy: Policy,
    selection: Selection,
    builder: select::EffectiveBuilder,
    inventory: Option<EffectiveInventory>,
    client: consumers::Builder<'a>,
}

pub fn prepare(
    project: &LoadedProject,
    policy: Policy,
    selection: Selection,
) -> Result<Builder<'_>> {
    let catalogs =
        select::select(project, policy.environment.as_deref()).map_err(|_| Failure::Policy)?;
    let builder = catalogs
        .builders
        .get(&selection.builder)
        .cloned()
        .ok_or(Failure::Policy)?;
    let access = matches!(selection.action, Action::Access);
    require(
        access || builder.declaration.kind == BuilderKind::Managed,
        Failure::Policy,
    )?;
    if let Action::Setup { archive, .. } | Action::Reconcile { archive, .. } = &selection.action {
        require(valid_path(archive), Failure::Policy)?;
    }
    let inventory = if access {
        None
    } else {
        catalogs
            .managed_builder(&selection.builder)
            .map_err(|_| Failure::Policy)?
            .ok_or(Failure::Policy)?;
        let script = builder
            .declaration
            .lifecycle_script
            .as_deref()
            .ok_or(Failure::Policy)?;
        let inventory =
            broil_remote::resolve(project, policy.environment.as_deref().map(OsStr::new))
                .map_err(|_| Failure::Policy)?;
        private::prepare(
            &project.broil_root,
            &inventory,
            builder
                .declaration
                .machine
                .as_deref()
                .ok_or(Failure::Policy)?,
            script,
            builder.declaration.privilege.as_deref(),
        )
        .map_err(remote_failure)?;
        Some(inventory)
    };
    let client = consumers::builder(
        project,
        policy.clone(),
        consumers::BuilderSelection {
            builder: selection.builder.clone(),
            stage: selection.stage.clone(),
            protected_parent: selection.protected_parent.clone(),
            solve: None,
        },
    )?;
    Ok(Builder {
        project,
        policy,
        selection,
        builder,
        inventory,
        client,
    })
}

fn public_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn remote_failure(failure: FailureClass) -> Failure {
    match failure {
        FailureClass::Configuration | FailureClass::Selector => Failure::Policy,
        FailureClass::UnknownHostKey | FailureClass::ChangedHostKey => Failure::Trust,
        FailureClass::AuthenticationRejected | FailureClass::AuthenticationLocallyUnavailable => {
            Failure::Authentication
        }
        FailureClass::SecretUnavailable => Failure::Credential,
        FailureClass::Cancellation => Failure::Cancellation,
        FailureClass::IndeterminateAfterDispatch => Failure::Indeterminate,
        _ => Failure::Tool,
    }
}

async fn cancelled(cancellation: &Cancellation) {
    while !cancellation.requested() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn observe_remote<T>(
    future: impl std::future::Future<Output = T>,
    cancel: &Cancellation,
    remote: &CancellationToken,
) -> T {
    tokio::pin!(future);
    tokio::select! {
        biased;
        _ = cancelled(cancel) => { remote.cancel(); future.await }
        result = &mut future => result,
    }
}

struct Run<'a> {
    project: &'a LoadedProject,
    inventory: &'a EffectiveInventory,
    machine: &'a EffectiveMachine,
    builder: &'a select::EffectiveBuilder,
    inputs: &'a consumers::Inputs,
    environment: &'a [(OsString, OsString)],
    runtime: tokio::runtime::Runtime,
    permit: Arc<Permit>,
    cancellation: Cancellation,
    metadata_ms: u64,
    lease: Option<records::Lease>,
    steps: Vec<Step>,
}

impl Run<'_> {
    fn local(&mut self, action: records::Action) -> Result<()> {
        let lease = self.lease.take().ok_or(Failure::Indeterminate)?;
        let (lease, result) = supervise::builder_local(
            lease,
            action,
            &mut Clock::new(self.metadata_ms)?,
            &self.cancellation.flag(),
            &self.permit,
        );
        self.lease = lease;
        result
    }
    fn record(&self) -> Result<&Json> {
        self.lease
            .as_ref()
            .and_then(|l| l.record.as_ref())
            .ok_or(Failure::Indeterminate)
    }
    fn connection(&self) -> Result<private::Connection> {
        require(!self.cancellation.requested(), Failure::Cancellation)?;
        let plan = private::prepare(
            &self.project.broil_root,
            self.inventory,
            &self.machine.name,
            self.builder
                .declaration
                .lifecycle_script
                .as_deref()
                .ok_or(Failure::Policy)?,
            self.builder.declaration.privilege.as_deref(),
        )
        .map_err(remote_failure)?;
        let backend = crate::remote::builder_backend(
            self.project,
            self.inventory,
            self.machine,
            &self.inputs.cwd,
            self.environment,
            self.inputs
                .credentials
                .try_duplicate()
                .map_err(|_| Failure::Limit)?,
            self.builder.declaration.privilege.as_deref(),
            self.inputs.non_interactive,
        )
        .map_err(remote_failure)?;
        let remote = CancellationToken::default();
        self.runtime
            .block_on(observe_remote(
                plan.connect(backend, remote.clone()),
                &self.cancellation,
                &remote,
            ))
            .map_err(remote_failure)
    }

    fn check_connection(&self, connection: &private::Connection) -> Result<()> {
        let scope = self.lease.as_ref().ok_or(Failure::Indeterminate)?.scope();
        require(scope["host_key"]==json!({"algorithm":connection.verified_host.algorithm,"base64":connection.verified_host.base64,"fingerprint":connection.verified_host.fingerprint})
            && scope["jump_key"]==json!(connection.verified_jump.as_ref().map(|k|json!({"algorithm":k.algorithm,"base64":k.base64,"fingerprint":k.fingerprint}))),Failure::Trust)
    }

    fn save_intent(&mut self, action: &str, upload: Json) -> Result<u64> {
        require(!self.cancellation.requested(), Failure::Cancellation)?;
        let mut record = self.record()?.clone();
        if record["uncertain"] == true {
            let previous = json!({"operation":record["operation"],"step":record["step"],"intent":record["intent"],
                "uncertain":true,"transfer":record["transfer"],"followup_step":record["step"].as_u64().and_then(|n|n.checked_add(1)),
                "observation":null});
            let history = record["history"].as_array_mut().ok_or(Failure::Protocol)?;
            require(history.len() < 32, Failure::Limit)?;
            history.push(previous);
        }
        let step = record["step"]
            .as_u64()
            .and_then(|n| n.checked_add(1))
            .ok_or(Failure::Limit)?;
        record["step"] = json!(step);
        record["intent"] = json!(action);
        record["uncertain"] = json!(true);
        record["upload_request"] = upload;
        record["transfer"] = Json::Null;
        if action != "inspect" {
            record["active"] = json!(true);
        }
        self.local(records::Action::Save(record))?;
        Ok(step)
    }

    fn action(&mut self, action: &str, purge: bool, arm64: bool) -> Result<Receipt> {
        self.action_with_upload(action, purge, arm64, Json::Null)
    }

    fn action_with_upload(
        &mut self,
        action: &str,
        purge: bool,
        arm64: bool,
        upload: Json,
    ) -> Result<Receipt> {
        let step = self.save_intent(action, upload)?;
        let task = Task::begin(&self.permit)?;
        let result = (|| {
            let connection = self.connection()?;
            self.check_connection(&connection)?;
            let scalar = if matches!(action, "certificate" | "key") {
                let selected = broil_secrets::read::Selection::new(
                    &self.project.config,
                    &self.project.broil_root,
                    Some(OsStr::new(&self.inventory.environment)),
                )
                .map_err(|_| Failure::Policy)?;
                let tls = self
                    .builder
                    .declaration
                    .server_tls
                    .as_ref()
                    .ok_or(Failure::Policy)?;
                Some(consumers::acquire(
                    &selected,
                    self.inputs,
                    if action == "certificate" {
                        &tls.certificate
                    } else {
                        &tls.key
                    },
                    &self.cancellation,
                )?)
            } else {
                None
            };
            let length = scalar.as_ref().map_or(0, |s| s.as_str().len());
            let request = protocol::request(
                self.record()?,
                self.lease
                    .as_ref()
                    .ok_or(Failure::Indeterminate)?
                    .scope_digest(),
                action,
                length,
                purge,
                arm64,
            )?;
            let header = serde_json::to_vec(&request).map_err(|_| Failure::Protocol)?;
            require(header.len() <= 65_536, Failure::Limit)?;
            let input = scalar
                .map(|s| StaticStdin::secret(s.into_bytes()))
                .unwrap_or_else(StaticStdin::empty);
            let remote = connection.cancellation();
            self.runtime
                .block_on(observe_remote(
                    connection.run(header, input),
                    &self.cancellation,
                    &remote,
                ))
                .map(|outcome| (outcome, request))
                .map_err(remote_failure)
        })();
        let (mut result, request) = match result {
            Ok(result) => result,
            Err(error) => {
                task.observed();
                self.steps.push(Step {
                    action: action.into(),
                    step,
                    transport: private::Observation::default(),
                    receipt: None,
                    upload: None,
                    local_failure: Some(error),
                });
                return Err(error);
            }
        };
        let receipt = if result.observation.failure.is_none() {
            protocol::receipt(
                result.stdout.bytes(),
                &request,
                result.observation.remote_status,
                result.observation.remote_signal.is_some(),
            )
            .ok()
        } else {
            None
        };
        if !result.observation.unresolved_input {
            task.observed();
        }
        let failure = result.observation.failure.map(remote_failure);
        if receipt.is_none() && failure.is_none() {
            result.observation.failure = Some(FailureClass::Protocol);
        }
        self.steps.push(Step {
            action: action.into(),
            step,
            transport: result.observation,
            receipt: receipt.clone(),
            upload: None,
            local_failure: None,
        });
        if let Some(failure) = failure {
            return Err(failure);
        }
        let receipt = receipt.ok_or(Failure::Protocol)?;
        require(
            !matches!(
                receipt.state,
                "conflict" | "busy" | "uncertain" | "prerequisite"
            ),
            Failure::Indeterminate,
        )?;
        let mut record = self.record()?.clone();
        for previous in record["history"].as_array_mut().ok_or(Failure::Protocol)? {
            if previous["followup_step"] == step {
                previous["observation"] = receipt.wire();
            }
        }
        record["observation"] = receipt.wire();
        record["uncertain"] = json!(false);
        self.local(records::Action::Save(record))?;
        Ok(receipt)
    }

    fn transfer(&mut self, source: PathBuf, binding: private::UploadBinding) -> Result<()> {
        require(!self.cancellation.requested(), Failure::Cancellation)?;
        let mut record = self.record()?.clone();
        record["intent"] = json!("upload");
        record["uncertain"] = json!(true);
        self.local(records::Action::Save(record))?;
        let task = Task::begin(&self.permit)?;
        let result = (|| {
            let job = crate::remote::builder_transfer(
                self.project,
                self.inventory,
                &self.inputs.cwd,
                self.environment,
                &crate::remote::CopyToRequest {
                    selectors: broil_remote::Selectors {
                        machines: vec![self.machine.name.clone()],
                        tags: vec![],
                        all: false,
                    },
                    recursive: false,
                    overwrite: false,
                    mode: Some("0600".into()),
                    owner: None,
                    privilege: None,
                    jobs: None,
                    fail_fast: false,
                    known_hosts: None,
                    report: None,
                    source,
                    destination: binding.destination().into(),
                },
            )
            .map_err(remote_failure)?;
            let connection = self.connection()?;
            self.check_connection(&connection)?;
            let remote = connection.cancellation();
            self.runtime
                .block_on(observe_remote(
                    connection.upload_public(job, binding.clone()),
                    &self.cancellation,
                    &remote,
                ))
                .map_err(remote_failure)
        })();
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                task.observed();
                self.steps.push(Step {
                    action: "upload".into(),
                    step: binding.step,
                    transport: private::Observation::default(),
                    receipt: None,
                    upload: None,
                    local_failure: Some(error),
                });
                return Err(error);
            }
        };
        if !outcome.unresolved_session {
            task.observed();
        }
        let failure = outcome.failure.map(remote_failure);
        let resolved = !outcome.unresolved_session;
        let observed = json!({"launcher_dispatched":outcome.launcher_dispatched,"mutation_dispatched":outcome.mutation_dispatched,
            "transfer_complete":outcome.transfer_complete,"remote_status":outcome.remote_status,
            "staging_residue":outcome.possible_staging_residue,"unresolved_session":outcome.unresolved_session,
            "temporary":outcome.temporary,"destination":outcome.destination});
        self.steps.push(Step {
            action: "upload".into(),
            step: binding.step,
            transport: private::Observation::default(),
            receipt: None,
            upload: Some(outcome),
            local_failure: None,
        });
        if resolved {
            let mut record = self.record()?.clone();
            record["transfer"] = observed;
            self.local(records::Action::Save(record))?;
        }
        if let Some(failure) = failure {
            return Err(failure);
        }
        require(!self.cancellation.requested(), Failure::Cancellation)
    }

    fn public_input(&mut self, source: PathBuf, purpose: &str, arm64: bool) -> Result<()> {
        if self.record()?["observation"]["inputs"][purpose].is_string() {
            return Ok(());
        }
        let scope = self.lease.as_ref().ok_or(Failure::Indeterminate)?.scope();
        let (size, sha) = if purpose == "archive" {
            (
                &scope["manifest"]["archive_size"],
                &scope["manifest"]["archive_sha256"],
            )
        } else {
            (&scope["ca_size"], &scope["ca_sha256"])
        };
        let input = json!({"purpose":purpose,"size":size,"sha256":sha,"temporary":"upload.tmp","final":purpose});
        let receipt = self.action_with_upload("prepare", false, arm64, input)?;
        let b = &receipt.upload["binding"];
        let text = |name: &str| {
            b[name]
                .as_str()
                .map(str::to_string)
                .ok_or(Failure::Protocol)
        };
        let number = |name: &str| b[name].as_u64().ok_or(Failure::Protocol);
        let binding = private::UploadBinding {
            owner: text("owner")?,
            operation: text("operation")?,
            step: number("step")?,
            scope: text("scope")?,
            device: b["container"]["device"].as_u64().ok_or(Failure::Protocol)?,
            inode: b["container"]["inode"].as_u64().ok_or(Failure::Protocol)?,
            purpose: text("purpose")?,
            size: number("size")?,
            sha256: text("sha256")?,
        };
        self.transfer(source, binding)?;
        let observed = self.action("reconcile", false, arm64)?;
        require(observed.inputs[purpose].is_string(), Failure::Integrity)
    }
}

impl Builder<'_> {
    pub fn run(
        self,
        inputs: consumers::Inputs,
        environment: &[(OsString, OsString)],
        cancellation: Cancellation,
    ) -> Result<Outcome> {
        require(
            valid_path(&inputs.cwd) && !cancellation.requested(),
            Failure::Policy,
        )?;
        if matches!(self.selection.action, Action::Access) {
            let endpoint = self
                .client
                .run(inputs, cancellation)
                .map_err(|e| e.failure)?;
            let result = endpoint.result.as_ref().map(|_| ()).map_err(|e| e.failure);
            return Ok(Outcome {
                result,
                record: None,
                steps: vec![],
                endpoint: Some(endpoint),
                ownership_uncertain: false,
            });
        }
        let inventory = self.inventory.as_ref().ok_or(Failure::Policy)?;
        let machine = inventory
            .machines
            .iter()
            .find(|m| Some(m.name.as_str()) == self.builder.declaration.machine.as_deref())
            .ok_or(Failure::Policy)?;
        let ordinary = ordinary_snapshot(environment);
        let mut run = Run {
            project: self.project,
            inventory,
            machine,
            builder: &self.builder,
            inputs: &inputs,
            environment: &ordinary,
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Failure::Capacity)?,
            permit: Permit::acquire()?,
            cancellation: cancellation.clone(),
            metadata_ms: self.policy.limits.metadata_ms,
            lease: None,
            steps: vec![],
        };
        let plan = private::prepare(
            &self.project.broil_root,
            inventory,
            &machine.name,
            self.builder
                .declaration
                .lifecycle_script
                .as_deref()
                .ok_or(Failure::Policy)?,
            self.builder.declaration.privilege.as_deref(),
        )
        .map_err(remote_failure)?;
        let script = plan.script();
        let adapter = json!({"body":script.body,"interpreter":script.interpreter,"cwd":script.cwd,"env":script.env,"args":script.args,"privilege":self.builder.declaration.privilege});
        let connection = run.connection()?;
        let host = &connection.verified_host;
        let tls = &self.builder.declaration.tls;
        let server = self
            .builder
            .declaration
            .server_tls
            .as_ref()
            .ok_or(Failure::Policy)?;
        let reference = |r: &broil_core::images::SecretReference| json!({"set":r.set,"key":r.key});
        let scope = json!({"project":self.project.broil_root,"environment":inventory.environment,"builder":self.selection.builder,
            "machine":machine.name,"account":machine.canonical_user,"address":machine.address,"port":machine.port,"route":machine.route,
            "jump":inventory.jumps.iter().find(|j|j.name==machine.route).map(|j|json!({"address":j.address,"port":j.port,"auth":j.auth_profile})),
            "jump_key":connection.verified_jump.as_ref().map(|k|json!({"algorithm":k.algorithm,"base64":k.base64,"fingerprint":k.fingerprint})),
            "host_key":{"algorithm":host.algorithm,"base64":host.base64,"fingerprint":host.fingerprint},
            "endpoint":self.builder.declaration.endpoint.supplied,"server_name":self.builder.server_name,"ca":self.builder.ca,
            "client_certificate":reference(&tls.certificate),"client_key":reference(&tls.key),
            "server_certificate":reference(&server.certificate),"server_key":reference(&server.key),
            "manifest":serde_json::from_str::<Json>(include_str!("../../../../../tools/image-builder/manifest.json")).map_err(|_|Failure::Policy)?});
        drop(connection);
        run.lease = Some(records::Lease::new(
            self.project.broil_root.clone(),
            scope,
            self.builder.ca.clone(),
            adapter,
        )?);
        let create = matches!(self.selection.action, Action::Setup { .. });
        run.local(records::Action::Open { create })?;
        let resume_removal = matches!(self.selection.action, Action::Reconcile { .. })
            .then(|| {
                run.record()
                    .ok()
                    .and_then(|record| record["removal"].as_bool())
            })
            .flatten();
        if resume_removal.is_none() && !matches!(self.selection.action, Action::Remove { .. }) {
            let tools = super::Operation::open(
                super::preflight(self.policy.clone())?,
                cancellation.clone(),
            )
            .map_err(|e| e.failure)?;
            let cleaned_tools = tools.cleanup(&[]);
            cleaned_tools.map_err(|e| e.failure)?;
        }
        let result = (|| -> Result<()> {
            let prior_uncertain = run.record()?["uncertain"]
                .as_bool()
                .ok_or(Failure::Protocol)?;
            let active = run.record()?["active"].as_bool().ok_or(Failure::Protocol)?;
            require(
                (!prior_uncertain && !active)
                    || matches!(
                        self.selection.action,
                        Action::Reconcile { .. } | Action::Inspect
                    ),
                Failure::Indeterminate,
            )?;
            if !prior_uncertain
                && !active
                && resume_removal.is_none()
                && !matches!(self.selection.action, Action::Inspect)
            {
                let mut record = run.record()?.clone();
                record["operation"] = json!(sudo_nonce().map_err(|_| Failure::Storage)?);
                record["removal"] = Json::Null;
                run.local(records::Action::Save(record))?;
            }
            let reconciling = matches!(self.selection.action, Action::Reconcile { .. });
            let inspected = run.action(
                if reconciling { "reconcile" } else { "inspect" },
                false,
                false,
            )?;
            match &self.selection.action {
                Action::Inspect => Ok(()),
                Action::Remove { purge } => {
                    require(inspected.state != "missing", Failure::Integrity)?;
                    let mut record = run.record()?.clone();
                    record["removal"] = json!(purge);
                    run.local(records::Action::Save(record))?;
                    run.action("remove", *purge, false)?;
                    Ok(())
                }
                Action::Setup {
                    archive,
                    arm64_emulation,
                }
                | Action::Reconcile {
                    archive,
                    arm64_emulation,
                } => {
                    if matches!(self.selection.action, Action::Reconcile { .. }) {
                        if let Some(purge) = resume_removal {
                            run.action("remove", purge, false)?;
                            return Ok(());
                        }
                        let mut record = run.record()?.clone();
                        record["operation"] = json!(sudo_nonce().map_err(|_| Failure::Storage)?);
                        run.local(records::Action::Save(record))?;
                    }
                    let manifest =
                        run.lease.as_ref().ok_or(Failure::Indeterminate)?.scope()["manifest"]
                            .clone();
                    run.local(records::Action::Archive {
                        path: archive.clone(),
                        size: manifest["archive_size"].as_u64().ok_or(Failure::Policy)?,
                        digest: manifest["archive_sha256"]
                            .as_str()
                            .ok_or(Failure::Policy)?
                            .into(),
                    })?;
                    run.action("prepare", false, *arm64_emulation)?;
                    run.public_input(archive.clone(), "archive", *arm64_emulation)?;
                    run.public_input(self.builder.ca.clone(), "ca", *arm64_emulation)?;
                    run.action("install", false, *arm64_emulation)?;
                    run.action("certificate", false, *arm64_emulation)?;
                    run.action("key", false, *arm64_emulation)?;
                    run.action("activate", false, *arm64_emulation)?;
                    Ok(())
                }
                Action::Access => unreachable!(),
            }
        })();
        let endpoint = if result.is_ok()
            && resume_removal.is_none()
            && matches!(
                self.selection.action,
                Action::Setup { .. } | Action::Reconcile { .. } | Action::Inspect
            ) {
            Some(
                self.client
                    .run(
                        consumers::Inputs {
                            cwd: inputs.cwd.clone(),
                            non_interactive: inputs.non_interactive,
                            credentials: inputs
                                .credentials
                                .try_duplicate()
                                .map_err(|_| Failure::Limit)?,
                        },
                        cancellation,
                    )
                    .map_err(|e| e.failure)?,
            )
        } else {
            None
        };
        let mut result = result.and_then(|()| {
            endpoint.as_ref().map_or(Ok(()), |e| {
                e.result.as_ref().map(|_| ()).map_err(|e| e.failure)
            })
        });
        if result.is_ok() && !matches!(self.selection.action, Action::Inspect) {
            let mut record = run.record()?.clone();
            record["active"] = json!(false);
            record["uncertain"] = json!(false);
            if let Err(failure) = run.local(records::Action::Save(record)) {
                result = Err(failure);
            }
        }
        let record = run.lease.as_ref().map(records::Lease::path);
        let ownership_uncertain =
            run.lease.as_ref().is_none_or(|l| l.publication_uncertain) || result.is_err();
        let steps = std::mem::take(&mut run.steps);
        drop(run);
        Ok(Outcome {
            result,
            record,
            steps,
            endpoint,
            ownership_uncertain,
        })
    }
}
