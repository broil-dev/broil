// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    ADAPTER, CERT_MANAGER, COREDNS_TEMPLATE, DELIVERY, GUARD, INGRESS, INGRESS_TEMPLATE, LIFECYCLE,
    LOCAL_STORAGE_TEMPLATE, NETWORK, NODE, PROFILE, Policy, REGISTRY, RELEASE, config_json,
    protocol, subtree,
};
use super::{Failure, Result, canonical, require, schema};
use crate::images::infrastructure_io::json::Value as Private;
use base64ct::{Base64, Encoding};
use broil_config::{
    LoadedProject,
    k3s::select::{self, SelectedTarget},
};
use broil_core::{k3s::Role, secret::path_safety::sudo_nonce};
use broil_remote::{EffectiveInventory, HostKey, exec::private};
use serde_json::{Value, json};
use std::{
    ffi::OsStr,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub(super) struct Context<'a> {
    pub project: &'a LoadedProject,
    pub policy: Policy,
    pub selected: SelectedTarget<'a>,
    pub inventory: EffectiveInventory,
    pub scope: Value,
    pub config: Value,
    pub references: Value,
    pub fingerprints: Value,
    pub owner_fingerprints: Value,
    pub(super) clock: private::ActionClock,
    failed: AtomicBool,
}

pub(super) struct Observed {
    pub response: Option<Value>,
    pub transport: Value,
    pub failure: Option<Failure>,
}

pub(crate) fn declaration_config(
    project: &LoadedProject,
    environment: &str,
    target: &str,
    selected: &SelectedTarget<'_>,
) -> Result<Value> {
    let declaration = config_json(
        subtree(
            &project.config.normalized,
            &["environments", environment, "k3s", target],
        )
        .map_err(|_| Failure::Configuration)?,
    );
    let mut registries = serde_json::Map::new();
    for (name, endpoint) in &selected.registries {
        let raw = subtree(
            &project.config.normalized,
            &["environments", environment, "registries", name],
        )
        .or_else(|_| subtree(&project.config.normalized, &["registries", name]))
        .map_err(|_| Failure::Configuration)?;
        registries.insert(
            name.clone(),
            json!({"declaration":config_json(raw),"ca_path":endpoint.ca}),
        );
    }
    let secrets = json!({"root":subtree(&project.config.normalized,&["secrets"]).map(config_json).unwrap_or(Value::Null),
        "environment":subtree(&project.config.normalized,&["environments",environment,"secrets"]).map(config_json).unwrap_or(Value::Null),
        "effective":{"store":selected.secrets.store,"project":selected.secrets.project,"identity":selected.secrets.identity,
            "vault":{"address":selected.secrets.vault.address,"mount":selected.secrets.vault.mount,"credential":selected.secrets.vault.credential,
                "fallback":match selected.secrets.vault.fallback {Some(broil_core::secrets::Fallback::Local)=>"local",_=>"none"}}}});
    Ok(json!({"target":declaration,"registries":registries,"secrets":secrets}))
}

impl<'a> Context<'a> {
    pub fn new(project: &'a LoadedProject, policy: Policy, target: &str) -> Result<Self> {
        let selected = select::select(project, Some(OsStr::new(&policy.environment)), target)
            .map_err(|_| Failure::Configuration)?;
        let inventory = broil_remote::resolve(project, Some(OsStr::new(&policy.environment)))
            .map_err(|_| Failure::Configuration)?;
        let scope = super::scope(&project.broil_root, &policy.environment, target)?;
        let t = selected.declaration;
        let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
        require(
            profile["script_sha256"] == protocol::digest(ADAPTER) && t.version == "v1.36.4+k3s1",
            Failure::Capability,
        )?;
        body_pins(&profile)?;
        let mut scripts = serde_json::Map::new();
        for machine in selected
            .members
            .iter()
            .map(|m| m.declaration.machine.as_str())
        {
            let plan = private::prepare_k3s(
                &project.broil_root,
                &inventory,
                machine,
                &t.lifecycle_script,
                t.privilege.as_deref(),
            )
            .map_err(|_| Failure::Configuration)?;
            let script = plan.script();
            let environment = std::collections::BTreeMap::from([
                ("BROIL_ENV".into(), policy.environment.as_bytes().to_vec()),
                ("BROIL_MACHINE".into(), machine.as_bytes().to_vec()),
            ]);
            require(
                script.body == ADAPTER
                    && script.interpreter.is_none()
                    && script.cwd.is_none()
                    && script.args.is_empty()
                    && script.env == environment,
                Failure::Configuration,
            )?;
            let effective = &inventory.scripts[&t.lifecycle_script];
            scripts.insert(machine.into(), json!({"name":t.lifecycle_script,
                "script_sha256":protocol::digest(ADAPTER),"interpreter":null,"cwd":null,
                "environment":{"BROIL_ENV":policy.environment,"BROIL_MACHINE":machine},
                "privilege":t.privilege,"timeout_seconds":effective.timeout.as_ref().map(|v|v.seconds),"pty":"never"}));
        }
        let mut config = declaration_config(project, &policy.environment, target, &selected)?;
        config["scripts"] = json!(scripts);
        let mut references = Vec::new();
        let mut reference = |consumer: &str, r: &broil_core::images::SecretReference| {
            references.push(json!({"consumer":consumer,"set":r.set,"key":r.key}));
        };
        for issuer in t.infrastructure.issuers.values() {
            match issuer {
                broil_core::k3s::Issuer::PrivateCa { certificate, key } => {
                    reference("supply-issuer-ca", certificate);
                    reference("supply-issuer-ca", key);
                }
                broil_core::k3s::Issuer::AcmeHttp01 { account_key, .. } => {
                    reference("supply-issuer-acme", account_key)
                }
            }
        }
        reference("supply-initial-server", &t.credentials.server_token);
        reference("supply-initial-server", &t.credentials.agent_token);
        reference("supply-recovery-key", &t.backup.identity);
        reference("supply-recovery-server-token", &t.credentials.server_token);
        if let Some(registry) = &t.registry {
            if let Some(key) = &registry.authentication.signing_key {
                reference("supply-registry-signing", key);
            }
            for principal in registry.authentication.principals.values() {
                reference("supply-registry-principal", &principal.password);
            }
        }
        for registry in &t.node_registries {
            reference("supply-node-registry", &registry.password);
        }
        let references = json!(references);
        let index_sha256 = crate::k3s::hosts::index::embedded()?.index.sha256.clone();
        let fingerprints = json!({"config_sha256":super::hash("broil-infra-config-v1",&config)?,
            "references_sha256":super::hash("broil-infra-references-v1",&references)?,"profile_sha256":protocol::digest(PROFILE),
            "script_sha256":protocol::digest(ADAPTER),"tools":[{"name":"bootstrap-index","sha256":index_sha256},{"name":"k3s","sha256":profile["k3s_sha256"]}]});
        schema::validate(&canonical(&config)?, "Config", 262144)?;
        schema::validate(&canonical(&references)?, "References", 262144)?;
        schema::validate(&canonical(&fingerprints)?, "Fingerprints", 65536)?;
        let clock = private::ActionClock::new(policy.deadline.min(
            tokio::time::Instant::now() + Duration::from_secs(selected.operation_timeout.seconds),
        ));
        Ok(Self {
            project,
            policy,
            selected,
            inventory,
            scope,
            config,
            references,
            owner_fingerprints: fingerprints.clone(),
            fingerprints,
            clock,
            failed: AtomicBool::new(false),
        })
    }

    pub(super) fn bind_recipe(&mut self, recipe_sha256: &str) -> Result<()> {
        require(super::hex(recipe_sha256, 64), Failure::Integrity)?;
        let mut tools = self.owner_fingerprints["tools"]
            .as_array()
            .cloned()
            .ok_or(Failure::Integrity)?;
        require(
            tools.iter().all(|t| t["name"] != "bootstrap-recipe"),
            Failure::Integrity,
        )?;
        tools.push(json!({"name":"bootstrap-recipe","sha256":recipe_sha256}));
        tools.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let mut fingerprints = self.owner_fingerprints.clone();
        fingerprints["tools"] = Value::Array(tools);
        schema::validate(&canonical(&fingerprints)?, "Fingerprints", 65536)?;
        self.fingerprints = fingerprints;
        Ok(())
    }

    pub(super) fn check(&self) -> Result<()> {
        require(!self.failed.load(Ordering::SeqCst), Failure::Transport)?;
        require(!self.policy.cancellation.is_cancelled(), Failure::Cancelled)?;
        require(
            tokio::time::Instant::now() < self.clock.deadline(),
            Failure::Timeout,
        )
    }

    async fn connect(
        &self,
        machine: &str,
        step_deadline: tokio::time::Instant,
    ) -> std::result::Result<private::StagedConnection, private::Observation> {
        let error = || private::Observation {
            failure: Some(broil_remote::FailureClass::Configuration),
            ..Default::default()
        };
        self.check().map_err(|_| error())?;
        require(
            self.selected
                .members
                .iter()
                .any(|m| m.declaration.machine == machine),
            Failure::Ownership,
        )
        .map_err(|_| error())?;
        let target = self
            .inventory
            .machines
            .iter()
            .find(|m| m.name == machine)
            .ok_or_else(error)?;
        let backend = crate::remote::builder_backend(
            self.project,
            &self.inventory,
            target,
            &self.policy.cwd,
            &self.policy.environment_snapshot,
            self.policy
                .credentials
                .try_duplicate()
                .map_err(|_| error())?,
            self.selected.declaration.privilege.as_deref(),
            self.policy.non_interactive,
        )
        .map_err(|_| error())?;
        let plan = private::prepare_k3s(
            &self.project.broil_root,
            &self.inventory,
            machine,
            &self.selected.declaration.lifecycle_script,
            self.selected.declaration.privilege.as_deref(),
        )
        .map_err(|_| error())?;
        plan.k3s_staging(self.clock.for_state_rpc(step_deadline))
            .map_err(|_| error())?
            .connect(backend, self.policy.cancellation.clone())
            .await
    }

    pub(super) async fn connect_bootstrap(
        &self,
        machine: &str,
        step_deadline: tokio::time::Instant,
        child: Option<&private::CredentialClock>,
    ) -> std::result::Result<private::StagedConnection, private::Observation> {
        self.connect_staged(machine, step_deadline, child, None)
            .await
    }

    pub(super) async fn connect_lifecycle(
        &self,
        machine: &str,
        step_deadline: tokio::time::Instant,
        child: Option<&private::CredentialClock>,
    ) -> std::result::Result<private::StagedConnection, private::Observation> {
        self.connect_staged(machine, step_deadline, child, Some(LIFECYCLE))
            .await
    }

    pub(super) async fn connect_body(
        &self,
        machine: &str,
        step_deadline: tokio::time::Instant,
        child: Option<&private::CredentialClock>,
        body: &'static [u8],
    ) -> std::result::Result<private::StagedConnection, private::Observation> {
        self.connect_staged(machine, step_deadline, child, Some(body))
            .await
    }

    async fn connect_staged(
        &self,
        machine: &str,
        step_deadline: tokio::time::Instant,
        child: Option<&private::CredentialClock>,
        body: Option<&'static [u8]>,
    ) -> std::result::Result<private::StagedConnection, private::Observation> {
        let error = || private::Observation {
            failure: Some(broil_remote::FailureClass::Configuration),
            ..Default::default()
        };
        self.check().map_err(|_| error())?;
        require(
            self.selected
                .members
                .iter()
                .any(|m| m.declaration.machine == machine),
            Failure::Ownership,
        )
        .map_err(|_| error())?;
        let target = self
            .inventory
            .machines
            .iter()
            .find(|m| m.name == machine)
            .ok_or_else(error)?;
        let backend = crate::remote::builder_backend(
            self.project,
            &self.inventory,
            target,
            &self.policy.cwd,
            &self.policy.environment_snapshot,
            self.policy
                .credentials
                .try_duplicate()
                .map_err(|_| error())?,
            self.selected.declaration.privilege.as_deref(),
            self.policy.non_interactive,
        )
        .map_err(|_| error())?;
        let plan = private::prepare_k3s(
            &self.project.broil_root,
            &self.inventory,
            machine,
            &self.selected.declaration.lifecycle_script,
            self.selected.declaration.privilege.as_deref(),
        )
        .map_err(|_| error())?;
        let plan = match body {
            Some(body) => plan.with_k3s_body(body).map_err(|_| error())?,
            None => plan,
        };
        let staged = match child {
            Some(child) => plan.k3s_credential_staging(child),
            None => plan.k3s_staging(self.clock.for_state_rpc(step_deadline)),
        }
        .map_err(|_| error())?;
        staged
            .connect(backend, self.policy.cancellation.clone())
            .await
    }

    pub(super) async fn public_connection(&self, machine: &str) -> Result<private::Connection> {
        self.check()?;
        let target = self
            .inventory
            .machines
            .iter()
            .find(|m| m.name == machine)
            .ok_or(Failure::Ownership)?;
        let backend = crate::remote::builder_backend(
            self.project,
            &self.inventory,
            target,
            &self.policy.cwd,
            &self.policy.environment_snapshot,
            self.policy
                .credentials
                .try_duplicate()
                .map_err(|_| Failure::Credential)?,
            self.selected.declaration.privilege.as_deref(),
            self.policy.non_interactive,
        )
        .map_err(|_| Failure::Configuration)?;
        let plan = private::prepare_k3s(
            &self.project.broil_root,
            &self.inventory,
            machine,
            &self.selected.declaration.lifecycle_script,
            self.selected.declaration.privilege.as_deref(),
        )
        .map_err(|_| Failure::Configuration)?;
        plan.connect(backend, self.policy.cancellation.clone())
            .await
            .map_err(|_| Failure::Transport)
    }

    pub(super) fn transfer_job(
        &self,
        machine: &str,
        source: std::path::PathBuf,
        destination: &str,
    ) -> Result<broil_remote::transfer::TransferJob> {
        crate::remote::builder_transfer(
            self.project,
            &self.inventory,
            &self.policy.cwd,
            &self.policy.environment_snapshot,
            &crate::remote::CopyToRequest {
                selectors: broil_remote::Selectors {
                    machines: vec![machine.to_string()],
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
                destination: destination.into(),
            },
        )
        .map_err(|_| Failure::Configuration)
    }

    pub(super) fn member(
        &self,
        machine: &str,
        connection: &private::StagedConnection,
        node_uid: Value,
    ) -> Result<Value> {
        fn key_hash(key: &HostKey) -> Result<String> {
            require(key.base64.len() <= 16384, Failure::Bound)?;
            let mut bytes = vec![0; key.base64.len()];
            let decoded = Base64::decode(&key.base64, &mut bytes).map_err(|_| Failure::Trust)?;
            Ok(protocol::digest(decoded))
        }
        let jump = connection.verified_jump().map(key_hash).transpose()?;
        self.shaped(
            machine,
            key_hash(connection.verified_host())?,
            jump,
            node_uid,
        )
    }

    pub(super) fn widest_member(&self, machine: &str) -> Result<Value> {
        let route = &self
            .inventory
            .machines
            .iter()
            .find(|m| m.name == machine)
            .ok_or(Failure::Ownership)?
            .route;
        let jump = self.inventory.jumps.iter().any(|j| j.name == *route);
        let hash = "f".repeat(64);
        self.shaped(
            machine,
            hash.clone(),
            jump.then_some(hash),
            json!("f".repeat(128)),
        )
    }

    fn shaped(
        &self,
        machine: &str,
        host: String,
        jump: Option<String>,
        node_uid: Value,
    ) -> Result<Value> {
        let declared = self
            .selected
            .members
            .iter()
            .find(|m| m.declaration.machine == machine)
            .ok_or(Failure::Ownership)?
            .declaration;
        let target = self
            .inventory
            .machines
            .iter()
            .find(|m| m.name == machine)
            .ok_or(Failure::Ownership)?;
        let route = json!({"address":target.address,"port":target.port,"account":target.canonical_user,
            "host_key_sha256":host});
        let jump = match jump {
            None => Value::Null,
            Some(hash) => {
                let jump = self
                    .inventory
                    .jumps
                    .iter()
                    .find(|j| j.name == target.route)
                    .ok_or(Failure::Ownership)?;
                let environment = &self.project.config.environments[&self.policy.environment];
                let account = environment
                    .remote
                    .definitions
                    .auth_profiles
                    .get(&jump.auth_profile)
                    .or_else(|| {
                        self.project
                            .config
                            .remote
                            .definitions
                            .auth_profiles
                            .get(&jump.auth_profile)
                    })
                    .ok_or(Failure::Ownership)?
                    .user
                    .clone();
                json!({"address":jump.address,"port":jump.port,"account":account,"host_key_sha256":hash})
            }
        };
        let member = json!({"machine":machine,"member":declared.name,"role":if declared.role==Role::Server {"server"}else{"agent"},
            "route":route,"jump":jump,"node_uid":node_uid});
        schema::validate(&canonical(&member)?, "Member", 65536)?;
        Ok(member)
    }

    pub async fn authenticate(&self) -> Result<Value> {
        let result = self.authenticate_members().await;
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
            self.clock.abort();
        }
        result
    }

    pub(super) async fn authenticate_owned(&self, expected: &Value) -> Result<()> {
        self.authenticate_participants(expected).await
    }

    pub(super) async fn authenticate_participants(&self, expected: &Value) -> Result<()> {
        let current = expected.as_array().ok_or(Failure::Integrity)?;
        let machines = current
            .iter()
            .map(|m| m["machine"].as_str().ok_or(Failure::Integrity))
            .collect::<Result<Vec<_>>>()?;
        let observed = self.authenticate_machines(&machines).await;
        if observed.is_err() {
            self.failed.store(true, Ordering::SeqCst);
            self.clock.abort();
        }
        let mut observed = observed?;
        let authenticated = observed.as_array_mut().ok_or(Failure::Integrity)?;
        require(authenticated.len() == current.len(), Failure::Ownership)?;
        for (actual, recorded) in authenticated.iter_mut().zip(current) {
            actual["node_uid"] = recorded["node_uid"].clone();
            require(*actual == *recorded, Failure::Ownership)?;
        }
        Ok(())
    }

    pub(super) async fn probe(&self, machine: &str) -> Result<Value> {
        let mut members = self.authenticate_machines(&[machine]).await?;
        members
            .as_array_mut()
            .and_then(Vec::pop)
            .ok_or(Failure::Integrity)
    }

    async fn authenticate_members(&self) -> Result<Value> {
        let machines: Vec<&str> = self
            .selected
            .members
            .iter()
            .map(|m| m.declaration.machine.as_str())
            .collect();
        self.authenticate_machines(&machines).await
    }

    async fn authenticate_machines(&self, machines: &[&str]) -> Result<Value> {
        let mut members = Vec::new();
        require(machines.len() <= 128, Failure::Bound)?;
        for machine in machines {

            let step_deadline = tokio::time::Instant::now()
                + Duration::from_secs(self.selected.step_timeout.seconds);
            let connection = self
                .connect(machine, step_deadline)
                .await
                .map_err(|_| Failure::Transport)?;
            let member = self.member(machine, &connection, Value::Null);
            let closed = connection.close_observation().await;
            require(
                closed.failure.is_none()
                    && !closed.possible_staging_residue
                    && !closed.unresolved_input,
                Failure::Transport,
            )?;
            members.push(member?);
        }
        Ok(json!(members))
    }

    pub async fn invoke(
        &self,
        binding: &Value,
        action: &str,
        payload: Value,
        step_deadline: tokio::time::Instant,
    ) -> Observed {
        Box::pin(self.invoke_guarded(binding, action, payload, step_deadline, None, None)).await
    }

    pub(super) async fn inspect_dispatch(
        &self,
        snapshot: &super::Snapshot,
        binding: &Value,
        payload: Value,
        step_deadline: tokio::time::Instant,
        expected_step: &Value,
    ) -> Observed {
        Box::pin(self.invoke_guarded(
            binding,
            "inspect",
            payload,
            step_deadline,
            Some(expected_step),
            Some(snapshot),
        ))
        .await
    }

    pub(super) async fn invoke_recorded(
        &self,
        snapshot: &super::Snapshot,
        binding: &Value,
        action: &str,
        payload: Value,
        deadline: tokio::time::Instant,
    ) -> Observed {
        Box::pin(self.invoke_guarded(binding, action, payload, deadline, None, Some(snapshot)))
            .await
    }

    pub async fn receipt(
        &self,
        snapshot: &super::Snapshot,
        step: &Value,
        deadline: tokio::time::Instant,
    ) -> Observed {
        let binding = snapshot.binding(step);
        Box::pin(self.invoke_guarded(
            &binding,
            "inspect",
            json!({"subject":"dispatch","dispatch":step["dispatch"],"resource":null}),
            deadline,
            Some(step),
            Some(snapshot),
        ))
        .await
    }

    async fn invoke_guarded(
        &self,
        binding: &Value,
        action: &str,
        payload: Value,
        step_deadline: tokio::time::Instant,
        expected_step: Option<&Value>,
        snapshot: Option<&super::Snapshot>,
    ) -> Observed {
        let mut observed = Observed {
            response: None,
            transport: json!({"dispatch":"none","exit":null,"signal":null,
            "input_released":true,"staging_cleanup":"clean"}),
            failure: None,
        };
        let result=async {
            self.check()?;
            schema::validate(&canonical(binding)?,"Binding",65536)?;
            require(binding["scope"]==self.scope && binding["fingerprints"]==self.fingerprints,Failure::Ownership)?;
            let machine=binding["recipient"]["machine"].as_str().ok_or(Failure::Integrity)?;

            let connection=match Box::pin(self.connect(machine,step_deadline)).await {
                Ok(connection)=>connection,
                Err(failure)=>{observed.transport=transport(&failure);return Err(Failure::Transport);},
            };
            let prepared=(|| {
                require(self.member(machine,&connection,binding["recipient"]["node_uid"].clone())? == binding["recipient"],Failure::Trust)?;
                let remaining=connection.deadline().saturating_duration_since(tokio::time::Instant::now()).as_millis().min(30000) as u64;
                require(remaining>0,Failure::Timeout)?;
                let header=json!({"protocol":"broil-k3s-state","version":1,"action":action,
                    "request_id":sudo_nonce().map_err(|_|Failure::Storage)?,"binding":binding,"remaining_ms":remaining,"payload":payload});
                let bytes=canonical(&header)?;
                schema::validate(&bytes,"Header",65536)?;
                Ok((header,bytes))
            })();
            let (_header,bytes)=match prepared {
                Ok(value)=>value,
                Err(failure)=>{let closed=connection.close().await;observed.transport=transport(&closed);return Err(failure);},
            };
            let output=connection.run_state(bytes.clone(),false).await.map_err(|_|Failure::Transport)?;
            observed.transport=transport(&output.observation);
            require(output.observation.failure.is_none() && output.observation.remote_status==Some(0)
                && output.observation.remote_signal.is_none() && !output.observation.unresolved_input
                && !output.observation.possible_staging_residue && output.stderr.bytes().is_empty(),Failure::Transport)?;
            let response=reply_recorded(output.stdout.bytes(),&bytes,expected_step,snapshot)?;

            observed.response=Some(response);
            Ok(())
        }.await;
        observed.failure = result.err();
        if observed.failure.is_some() {
            self.failed.store(true, Ordering::SeqCst);
            self.clock.abort();
        }
        observed
    }
}

pub(super) fn body_pins(profile: &Value) -> Result<()> {
    let bodies = &profile["bodies"];
    require(
        bodies.as_object().is_some_and(|b| b.len() == 10)
            && bodies["control"] == protocol::digest(ADAPTER)
            && bodies["control"] == profile["script_sha256"]
            && bodies["lifecycle"] == protocol::digest(LIFECYCLE)
            && bodies["network"] == protocol::digest(NETWORK)
            && bodies["ingress"] == protocol::digest(INGRESS)
            && bodies["cert_manager"] == protocol::digest(CERT_MANAGER)
            && bodies["registry"] == protocol::digest(REGISTRY)
            && bodies["node"] == protocol::digest(NODE)
            && bodies["delivery"] == protocol::digest(DELIVERY)
            && bodies["release"] == protocol::digest(RELEASE)
            && bodies["service_guard"] == protocol::digest(GUARD),
        Failure::Configuration,
    )?;
    require(
        profile["cert_manager"]
            == json!({"version":"v1.21.2",
            "manifest":"e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f",
            "render":"128cff01c7045fe773965a5e2c98fcd4798056293396b1ddc627392b9bfbf2b8",
            "images":{
                "controller":"57bb397c639e0e94184ba67848e5dad04284f24645e521e764a0ee5f5002f286",
                "cainjector":"aa2bc58725d92a643f5069dde58abc93b65566ded8951348873ac9ee7efef66c",
                "webhook":"b929259301ee75270ab4651d5e6bd4ba7b6624b1ce48ba767d064295a9312101",
                "acmesolver":"dc5c5b8456d1a50af47a240987e85afce352b5c1155a8a4698b7c91eac19f407",
            }})
            && profile["registry"]
                == json!({"version":"v3.1.1","image":"broil.invalid/candidate/distribution",
                    "digest":"ac52bec3025b9dc75a26112e076e3e0af646fbb40af67ae9f2fcd6465963b839"})
            && profile["auth"]
                == json!({"image":"broil.invalid/candidate/auth",
                    "digest":"b15a78d2bf9007e75f0aab45f540254ce18451289a4868748b599b5175167591"})
            && profile["syncthing"]
                == json!({"version":"v2.1.7",
                    "sha256":"f5c12679f2bad1b5eff619ba7b04ead1a457e439a1e55dc640d4d8995d7f4dbd"}),
        Failure::Configuration,
    )?;
    require(
        profile["ingress_templates"] == json!({"traefik":protocol::digest(INGRESS_TEMPLATE)})
            && profile["ingress_images"]
                == json!({"traefik":"96780238b1bbda5a9bb997f4307ce69e798ad1cf6eb7f2dcc0a440823467d199",
                    "klipper_lb":"910944bb0bd94f060a82a56ca1ea1c577d3e49b3473a093a47a985f32e92d94a"})
            && profile["ingress_charts"]
                == json!({
                    "traefik":"a9ebcfeecdd5b9f1ffea1167a7ffee69e346cd10864998ce8e44b51c204b7767",
                    "traefik_crd":"cd588985d419ca98f1e529a74a5ef06939795311450e8ec31671d8b1b2c1e93c",
                }),
        Failure::Configuration,
    )?;
    require(
        profile["network_templates"]
            == json!({
                "coredns":protocol::digest(COREDNS_TEMPLATE),
                "local_storage":protocol::digest(LOCAL_STORAGE_TEMPLATE),
            })
            && profile["network_images"]
                == json!({
                    "coredns":"1ba6f47265602e2e50a9c4669e3a955e4298a0d30dc82f39293d4bf1a851e0ff",
                    "provisioner":"c3f2c60ee2490eb83ac00101d7e239fd8c20a5b8b4038e2dfc36a7e66fe99c08",
                    "helper":"ad9fa4d07136a83e69a54ef00102f579d04eba431932de3b0f098cc5d5948f9f",
                }),
        Failure::Configuration,
    )
}

pub(in crate::k3s) fn transport(o: &private::Observation) -> Value {
    json!({"dispatch":if o.dispatched {"possible"}else{"none"},"exit":o.remote_status.filter(|s|*s>=0),
        "signal":o.remote_signal.as_ref().map(|s|s.name.as_str()),"input_released":!o.unresolved_input,
        "staging_cleanup":if o.possible_staging_residue {"residue"}else{"clean"}})
}

pub(super) fn reply_recorded(
    bytes: &[u8],
    header: &[u8],
    expected_step: Option<&Value>,
    snapshot: Option<&super::Snapshot>,
) -> Result<Value> {
    require(
        bytes.len() <= 1_048_576 && bytes.starts_with(b"BK3SSTATE1\n"),
        Failure::Integrity,
    )?;
    fn field<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8]> {
        let size = u32::from_be_bytes(
            bytes
                .get(..4)
                .ok_or(Failure::Integrity)?
                .try_into()
                .map_err(|_| Failure::Integrity)?,
        ) as usize;
        let end = size.checked_add(4).ok_or(Failure::Bound)?;
        let value = bytes.get(4..end).ok_or(Failure::Integrity)?;
        *bytes = bytes.get(end..).ok_or(Failure::Integrity)?;
        Ok(value)
    }
    let mut input = &bytes[11..];
    require(field(&mut input)? == header, Failure::Integrity)?;
    let body = field(&mut input)?;
    require(input.is_empty(), Failure::Integrity)?;
    schema::validate(body, "Response", 1_048_576)?;
    let expected: Value = serde_json::from_slice(header).map_err(|_| Failure::Integrity)?;
    bind_response(
        Private::parse_bounded(body, 1_048_576, 17)?,
        &expected,
        expected_step,
    )?;
    bind_records(
        Private::parse_bounded(body, 1_048_576, 17)?,
        &expected,
        snapshot,
    )?;
    schema::decode(body, "Response", 1_048_576)
}

fn bind_resource_identity(value: Private<'_>, resource: &Value) -> Result<()> {
    if value.is_null() {
        return Ok(());
    }
    require(!resource.is_null(), Failure::Ownership)?;
    if !resource["uid"].is_null() {
        require(value.matches(&resource["uid"])?, Failure::Ownership)
    } else if resource["id"].as_str().is_some_and(|id| {
        [
            "network-object-",
            "ingress-object-",
            "cert-manager-object-",
            "issuer-object-",
            "certificate-object-",
            "registry-volume-",
            "registry-service-object-",
            "registry-endpoint-object-",
            "registry-auth-object-",
            "registry-token-object-",
            "registry-reader-object-",
        ]
        .iter()
        .any(|prefix| id.starts_with(prefix))
    }) {
        value.text()?;
        Ok(())
    } else {
        let identity = value.array()?;
        require(identity.len() == 2, Failure::Integrity)?;
        for part in identity {
            part.number()?;
        }
        Ok(())
    }
}

fn recorded_step<'a>(
    record: Private<'_>,
    action: &str,
    snapshot: &'a super::Snapshot,
) -> Result<&'a Value> {
    let binding = record.field("binding")?;
    let id = binding.field("step")?.number()?;
    let step = snapshot
        .steps
        .iter()
        .find(|s| s["step"] == id && s["action"] == action)
        .ok_or(Failure::Ownership)?;
    let mut expected = snapshot.binding(step);
    if action == "acquire-writer" {
        expected["receiver_generation"] = json!(
            step["expected_receiver_generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?
                .checked_add(1)
                .ok_or(Failure::Bound)?
        );
    }
    require(binding.matches(&expected)?, Failure::Ownership)?;
    Ok(step)
}

fn record_hash(label: &str, record: Private<'_>) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(label.as_bytes());
    hash.update(b"\n");
    hash.update(record.raw());
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn receiver_work(step: &Value, snapshot: &super::Snapshot) -> bool {
    !matches!(
        step["action"].as_str(),
        Some(
            "inspect"
                | "seal-writer"
                | "retire-writer"
                | "rebind-claim"
                | "bootstrap:inspect-host"
                | "bootstrap:inspect-generation"
                | "lifecycle:inspect-installation"
                | "lifecycle:observe-server"
                | "lifecycle:inspect-owned-server"
                | "lifecycle:inspect-join"
                | "lifecycle:observe-membership"
                | "lifecycle:observe-join"
                | "lifecycle:inspect-agent"
                | "lifecycle:observe-agent"
                | "lifecycle:observe-agent-membership"
                | "lifecycle:network-inspect-host"
                | "lifecycle:network-inspect-objects"
                | "lifecycle:ingress-inspect-host"
                | "lifecycle:ingress-inspect-objects"
                | "lifecycle:cert-manager-inspect-host"
                | "lifecycle:cert-manager-inspect-objects"
                | "lifecycle:issuer-inspect-objects"
                | "lifecycle:certificate-inspect-objects"
                | "lifecycle:registry-storage-inspect-storage"
                | "lifecycle:registry-storage-inspect-objects"
                | "lifecycle:registry-service-inspect-host"
                | "lifecycle:registry-service-inspect-objects"
                | "lifecycle:registry-endpoint-inspect-objects"
                | "lifecycle:registry-auth-inspect-objects"
                | "lifecycle:registry-token-inspect-host"
                | "lifecycle:registry-token-inspect-objects"
                | "lifecycle:registry-replication-inspect-replication"
                | "lifecycle:registry-replication-inspect-objects"
                | "lifecycle:delivery-inspect-images"
                | "lifecycle:delivery-check-closure"
                | "lifecycle:delivery-read-origin-log"
                | "lifecycle:node-observe-node"
                | "lifecycle:node-observe-drain"
                | "lifecycle:release-discover-kinds"
                | "lifecycle:release-inspect-workloads"
                | "lifecycle:release-observe-release"
        )
    ) && !snapshot.deselected(step)
}

fn bind_records(
    response: Private<'_>,
    header: &Value,
    snapshot: Option<&super::Snapshot>,
) -> Result<()> {
    let data = response.field("data")?;
    let reservation = data.field("reservation")?;
    let seal = data.field("seal")?;
    let retirement = data.field("retirement")?;
    if reservation.is_null() && seal.is_null() && retirement.is_null() {
        return Ok(());
    }
    let snapshot = snapshot.ok_or(Failure::Integrity)?;
    require(
        header["binding"]["request_sha256"]
            == super::hash("broil-infra-request-v1", &snapshot.request)?,
        Failure::Ownership,
    )?;
    let mut seal_hash = None;
    let mut retirement_hash = None;
    if !seal.is_null() {
        let step = recorded_step(seal, "seal-writer", snapshot)?;
        let mut work: Vec<_> = snapshot
            .steps
            .iter()
            .filter(|s| {
                s["attempt"] == step["attempt"]
                    && s["recipient"] == step["recipient"]
                    && s["step"].as_u64() < step["step"].as_u64()
                    && receiver_work(s, snapshot)
            })
            .collect();
        work.sort_by_key(|s| s["step"].as_u64());
        let mut dispatches = Vec::new();
        let mut receipts = Vec::new();
        for work in work {
            let receipt = snapshot
                .observations
                .iter()
                .find(|o| o["dispatch"] == work["dispatch"] && o["event"]["type"] == "receiver")
                .map(|o| &o["event"]["receipt"])
                .ok_or(Failure::Readiness)?;
            require(receipt["writer_ended"] == true, Failure::Readiness)?;
            dispatches.push(work["dispatch"].clone());
            receipts.push(super::hash("broil-infra-receipt-v1", receipt)?);
        }
        require(
            seal.field("dispatches")?.matches(&json!(dispatches))?
                && seal.field("terminal_sha256s")?.matches(&json!(receipts))?,
            Failure::Ownership,
        )?;
        seal_hash = Some(record_hash("broil-infra-seal-v1", seal));
    }
    if !retirement.is_null() {
        let step = recorded_step(retirement, "retire-writer", snapshot)?;
        let payload = snapshot.retirement_payload(step)?;
        let next = step["expected_receiver_generation"]
            .as_u64()
            .ok_or(Failure::Integrity)?
            .checked_add(1)
            .ok_or(Failure::Bound)?;
        require(
            retirement.field("seals")?.matches(&payload["seals"])?
                && retirement.field("next_generation")?.number()? == next,
            Failure::Ownership,
        )?;
        retirement_hash = Some(record_hash("broil-infra-retirement-v1", retirement));
    }
    if !reservation.is_null() {
        let acquired = recorded_step(reservation, "acquire-writer", snapshot)?;
        let (selected, _) = super::session::selection(snapshot)?;
        require(
            reservation.field("members")?.matches(&json!(selected))?,
            Failure::Ownership,
        )?;
        let mut work: Vec<_> = snapshot
            .steps
            .iter()
            .filter(|s| {
                s["attempt"] == acquired["attempt"]
                    && s["recipient"] == acquired["recipient"]
                    && receiver_work(s, snapshot)
            })
            .collect();
        work.sort_by_key(|s| s["step"].as_u64());
        let dispatches = reservation.field("dispatches")?.array()?;
        require(dispatches.len() <= work.len(), Failure::Integrity)?;
        for (actual, expected) in dispatches.iter().zip(&work) {
            require(actual.matches(&expected["dispatch"])?, Failure::Ownership)?;
        }
        let state = reservation.field("state")?;
        if state.equals("sealed")? || state.equals("retired")? {
            require(dispatches.len() == work.len(), Failure::Ownership)?;
        }
        for (field, observed, label) in [
            ("seal_sha256", seal_hash, "sealed"),
            ("retirement_sha256", retirement_hash, "retired"),
        ] {
            let value = reservation.field(field)?;
            if value.is_null() {
                require(
                    !(label == "sealed" && (state.equals("sealed")? || state.equals("retired")?)
                        || label == "retired" && state.equals("retired")?),
                    Failure::Integrity,
                )?;
                continue;
            }
            let retained = snapshot
                .observations
                .iter()
                .find(|o| {
                    o["attempt"] == acquired["attempt"]
                        && o["event"]["type"] == "reservation"
                        && o["event"]["state"] == label
                        && o["event"]["member"] == acquired["recipient"]
                })
                .and_then(|o| o["event"]["receipt_sha256"].as_str())
                .map(str::to_owned);
            if let Some(known) = &retained {
                require(value.equals(known)?, Failure::Ownership)?;
            }
            let known = observed.or(retained).ok_or(Failure::Integrity)?;
            require(value.equals(&known)?, Failure::Ownership)?;
        }
    }
    Ok(())
}

fn bind_response(
    response: Private<'_>,
    header: &Value,
    expected_step: Option<&Value>,
) -> Result<()> {
    let data = response.field("data")?;
    let binding = &header["binding"];
    let allowed: &[&str] = match (
        header["action"].as_str(),
        header["payload"]["subject"].as_str(),
    ) {
        (Some("inspect"), Some("owner")) | (Some("reserve-owner"), _) => {
            &["claim", "ownership", "terminal"]
        }
        (Some("inspect"), Some("writer")) => &["claim", "reservation", "seal", "retirement"],
        (Some("inspect"), Some("dispatch")) => &["terminal"],
        (Some("inspect"), Some("resource")) => &["resource"],
        (Some("inspect"), Some("identity")) => &["identity"],
        (Some("acquire-writer"), _) => &["claim", "reservation", "terminal"],
        (Some("prepare-input"), _) => &["resource", "terminal"],
        (Some("admit-credential"), _) => &["terminal"],
        (Some("seal-writer"), _) => &["reservation", "seal", "terminal"],
        (Some("retire-writer"), _) => &["claim", "reservation", "retirement", "terminal"],
        (Some("rebind-claim"), _) => &["claim", "terminal"],
        (Some("prune-attempts"), _) => &["claim", "history"],
        _ => return Err(Failure::Integrity),
    };
    for (key, value) in data.members()? {
        let key = key.text()?;
        let key = std::str::from_utf8(key.get()).map_err(|_| Failure::Integrity)?;
        require(
            key == "failure" || allowed.contains(&key) || value.is_null(),
            Failure::Integrity,
        )?;
    }
    for field in ["terminal", "reservation", "seal", "retirement"] {
        let record = data.field(field)?;
        if !record.is_null() {
            let actual = record.field("binding")?;
            for key in [
                "scope",
                "owner",
                "operation",
                "attempt",
                "recipient",
                "request_sha256",
                "participants_sha256",
                "fingerprints",
            ] {
                require(
                    actual.field(key)?.matches(&binding[key])?,
                    Failure::Ownership,
                )?;
            }
        }
    }
    let claim = data.field("claim")?;
    let mut claim_uid: Option<Private<'_>> = None;
    if !claim.is_null() {
        for key in ["scope", "owner", "participants_sha256"] {
            let expected = if key == "participants_sha256" && header["action"] == "rebind-claim" {
                &header["payload"][key]
            } else {
                &binding[key]
            };
            let rebound = key == "participants_sha256"
                && matches!(
                    header["action"].as_str(),
                    Some("seal-writer" | "retire-writer")
                )
                && !data.field("reservation")?.is_null();
            require(
                rebound || claim.field(key)?.matches(expected)?,
                Failure::Ownership,
            )?;
        }
        let member = claim.field("member")?;
        if !member.matches(&binding["recipient"])? {
            require(
                binding["recipient"]["node_uid"].is_null(),
                Failure::Ownership,
            )?;
            for key in ["machine", "member", "role", "route", "jump"] {
                require(
                    member.field(key)?.matches(&binding["recipient"][key])?,
                    Failure::Ownership,
                )?;
            }
            let uid = member.field("node_uid")?;
            require(!uid.is_null(), Failure::Ownership)?;
            claim_uid = Some(uid);
        }
        let history = binding["operation"]
            .as_str()
            .and_then(|o| o.strip_prefix("infra-operation-"))
            == binding["attempt"].as_str();
        require(
            history
                || claim.field("active_attempt")?.is_null()
                || claim
                    .field("active_attempt")?
                    .matches(&binding["attempt"])?,
            Failure::Ownership,
        )?;
    }
    let owned = data.field("ownership")?;
    if !owned.is_null() {
        require(
            owned.field("owner")?.matches(&binding["owner"])?,
            Failure::Ownership,
        )?;
        for key in ["project", "environment", "target"] {
            require(
                owned
                    .field("scope")?
                    .field(key)?
                    .matches(&binding["scope"][key])?,
                Failure::Ownership,
            )?;
        }
        for key in ["machine", "member", "role"] {
            require(
                owned
                    .field("machine")?
                    .field(key)?
                    .matches(&binding["recipient"][key])?,
                Failure::Ownership,
            )?;
        }
        let uid = owned.field("machine")?.field("node_uid")?;
        if !uid.matches(&binding["recipient"]["node_uid"])? {
            let published = claim_uid.ok_or(Failure::Ownership)?;
            require(
                binding["recipient"]["node_uid"].is_null() && uid.raw() == published.raw(),
                Failure::Ownership,
            )?;
        }
    }
    let identity = data.field("identity")?;
    if !identity.is_null() {
        require(
            identity.field("member")?.matches(&binding["recipient"])?,
            Failure::Ownership,
        )?;
    }
    let terminal = data.field("terminal")?;
    if !terminal.is_null() {
        require(
            !terminal.field("resource")?.is_null()
                || terminal.field("resource_identity")?.is_null(),
            Failure::Integrity,
        )?;
        if header["action"] == "inspect" {
            let step = expected_step.ok_or(Failure::Integrity)?;
            let mut expected_binding = binding.clone();
            expected_binding["step"] = step["step"].clone();
            expected_binding["dispatch"] = step["dispatch"].clone();
            expected_binding["receiver_generation"] = step["expected_receiver_generation"].clone();
            require(
                header["payload"]["subject"] == "dispatch"
                    && header["payload"]["dispatch"] == step["dispatch"],
                Failure::Integrity,
            )?;
            require(
                terminal.field("binding")?.matches(&expected_binding)?,
                Failure::Ownership,
            )?;
            require(
                terminal.field("action")?.matches(&step["action"])?
                    && terminal
                        .field("payload_sha256")?
                        .matches(&step["payload_sha256"])?
                    && ((!terminal.field("outcome")?.equals("succeeded")?
                        && terminal.field("resource")?.is_null())
                        || terminal.field("resource")?.matches(&step["resource"])?),
                Failure::Ownership,
            )?;
            bind_resource_identity(terminal.field("resource_identity")?, &step["resource"])?;
        } else {
            require(
                terminal.field("binding")?.matches(binding)?,
                Failure::Ownership,
            )?;
            require(
                terminal.field("action")?.matches(&header["action"])?
                    && terminal
                        .field("payload_sha256")?
                        .equals(&super::hash("broil-infra-step-v1", &header["payload"])?)?,
                Failure::Integrity,
            )?;
            let resource = &header["payload"]["resource"];
            require(
                (!terminal.field("outcome")?.equals("succeeded")?
                    && terminal.field("resource")?.is_null())
                    || terminal.field("resource")?.matches(resource)?,
                Failure::Ownership,
            )?;
            bind_resource_identity(terminal.field("resource_identity")?, resource)?;
        }
        require(
            !terminal.field("outcome")?.equals("succeeded")?
                || (terminal.field("effect")?.equals("complete")?
                    && terminal.field("failure")?.is_null()),
            Failure::Integrity,
        )?;
    }
    let status = response.field("status")?;
    if status.equals("ok")? {
        let required: &[&str] = match (
            header["action"].as_str(),
            header["payload"]["subject"].as_str(),
        ) {
            (Some("inspect"), Some("owner")) => &["claim", "ownership"],
            (Some("inspect"), Some("writer")) => &["claim"],
            (Some("inspect"), Some("dispatch")) => &["terminal"],
            (Some("inspect"), Some("identity")) => &["identity"],
            (Some("inspect"), Some("resource")) => &["resource"],
            (Some("reserve-owner"), _) => &["claim", "ownership", "terminal"],
            (Some("acquire-writer"), _) => &["claim", "reservation", "terminal"],
            (Some("prepare-input"), _) => &["resource", "terminal"],
            (Some("admit-credential"), _) => &["terminal"],
            (Some("seal-writer"), _) => &["reservation", "seal", "terminal"],
            (Some("retire-writer"), _) => &["claim", "reservation", "retirement", "terminal"],
            (Some("rebind-claim"), _) => &["terminal"],
            (Some("prune-attempts"), _) => &["claim", "history"],
            _ => return Err(Failure::Integrity),
        };
        for field in required {
            require(!data.field(field)?.is_null(), Failure::Integrity)?;
        }
        if header["action"] == "prepare-input" {
            let witness = data.field("resource")?;
            require(
                witness.field("inactive")?.boolean()?
                    && !witness.field("identity")?.is_null()
                    && witness.field("identity")?.raw()
                        == terminal.field("resource_identity")?.raw(),
                Failure::Ownership,
            )?;
        }
    }
    let resource = data.field("resource")?;
    if !resource.is_null() {
        require(
            (header["action"] == "prepare-input"
                || header["action"] == "inspect" && header["payload"]["subject"] == "resource")
                && resource
                    .field("resource")?
                    .matches(&header["payload"]["resource"])?,
            Failure::Ownership,
        )?;
        bind_resource_identity(resource.field("identity")?, &header["payload"]["resource"])?;
    }
    if header["action"] == "inspect"
        && header["payload"]["subject"] == "resource"
        && (status.equals("ok")? || status.equals("absent")?)
    {
        let resource = data.field("resource")?;
        require(
            resource
                .field("resource")?
                .matches(&header["payload"]["resource"])?,
            Failure::Ownership,
        )?;
        if status.equals("absent")? {
            require(
                matches!(
                    header["payload"]["resource"]["kind"].as_str(),
                    Some("server-input" | "agent-input" | "node-registry" | "recovery")
                ),
                Failure::Capability,
            )?;
            require(
                resource.field("identity")?.is_null() && resource.field("inactive")?.is_null(),
                Failure::Integrity,
            )?;
        } else {
            require(
                !resource.field("identity")?.is_null() && resource.field("inactive")?.boolean()?,
                Failure::Integrity,
            )?;
        }
    }
    if header["action"] != "inspect"
        && header["action"] != "prune-attempts"
        && status.equals("ok")?
    {
        require(
            !terminal.is_null()
                && terminal.field("outcome")?.equals("succeeded")?
                && terminal.field("effect")?.equals("complete")?,
            Failure::Integrity,
        )?;
    }
    Ok(())
}

