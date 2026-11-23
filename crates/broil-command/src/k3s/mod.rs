// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub mod commands;
pub mod delivery;
pub mod history;
pub(crate) mod hosts;
pub mod members;
mod protocol;
pub mod release;
pub mod replication;
pub mod report;
pub mod shapes;
pub mod state;

pub use protocol::ResultClass;

use broil_config::{
    LoadedProject,
    k3s::select::{self, SelectedTarget},
};
use broil_core::{
    images::SecretReference,
    k3s::{Issuer, Role},
    model::ConfigValue,
    secret::{
        environment::{CredentialInputs, ordinary_snapshot},
        path_safety::sudo_nonce,
    },
};
use broil_remote::{
    EffectiveInventory, FailureClass, HostKey,
    exec::{StaticStdin, private},
    scheduler::CancellationToken,
};
use broil_secrets::{identity::AcquisitionControl, read};
use protocol::{Action, canonical, digest, opaque};
use serde_json::{Value, json};
use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
    time::Duration,
};
use zeroize::Zeroizing;

const ADAPTER: &[u8] = include_bytes!("../../../../tools/k3s/protected-actions.py");
const PROFILE: &[u8] = include_bytes!("../../../../tools/k3s/action-profile.json");
const LIFECYCLE: &[u8] = include_bytes!("../../../../tools/k3s/lifecycle-actions.py");
const NETWORK: &[u8] = include_bytes!("../../../../tools/k3s/network-actions.py");
const COREDNS_TEMPLATE: &[u8] =
    include_bytes!("../../../../tools/k3s/templates/v1.36.4-coredns.yaml");
const LOCAL_STORAGE_TEMPLATE: &[u8] =
    include_bytes!("../../../../tools/k3s/templates/v1.36.4-local-storage.yaml");
const INGRESS: &[u8] = include_bytes!("../../../../tools/k3s/ingress-actions.py");
const INGRESS_TEMPLATE: &[u8] = include_bytes!("../../../../tools/k3s/templates/traefik.yaml");
const CERT_MANAGER: &[u8] = include_bytes!("../../../../tools/k3s/cert-manager-actions.py");
const REGISTRY: &[u8] = include_bytes!("../../../../tools/k3s/registry-actions.py");
const NODE: &[u8] = include_bytes!("../../../../tools/k3s/node-actions.py");
const GUARD: &[u8] = include_bytes!("../../../../tools/k3s/service-guard.py");
const DELIVERY: &[u8] = include_bytes!("../../../../tools/k3s/delivery-actions.py");
const RELEASE: &[u8] = include_bytes!("../../../../tools/k3s/release-actions.py");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Configuration,
    Bound,
    Protocol,
    Credential,
    Action,
    Acquisition,
    AcquisitionCleanup,
    Transport,
    Cancellation,
    Deadline,
}
pub type Result<T> = std::result::Result<T, Failure>;

pub struct Policy {
    pub environment: String,
    pub cwd: PathBuf,
    pub environment_snapshot: Vec<(OsString, OsString)>,
    pub credentials: CredentialInputs,
    pub non_interactive: bool,
    pub deadline: tokio::time::Instant,
    pub cancellation: CancellationToken,
}

#[derive(Clone, Debug)]
pub struct Generation {
    pub owner: String,
    pub operation: String,
    pub attempt: String,
    pub resource: String,
    pub generation: String,
    pub resource_uid: Option<String>,
    pub cluster: Option<Cluster>,
    pub destination_uid: Option<String>,
    pub source_uid: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Cluster {
    pub uid: String,
    pub ca_sha256: String,
}

#[derive(Clone, Debug)]
pub enum Operation {
    InitialServer,
    ServerJoin { source: String },
    AgentJoin { source: String },
    AdministrativeCheck,
    Issuer { name: String },
    RegistrySigning,
    RegistryPrincipal { name: String },
    NodeRegistry { registry: String },
    RecoveryKey,
    RecoveryServerToken,
}

#[derive(Debug)]
pub struct Step {
    pub request_id: Option<String>,
    pub action: &'static str,
    pub inspecting: bool,
    pub transport: private::Observation,
    pub result: Option<ResultClass>,
    pub possible_consumer_residue: bool,
    pub failure: Option<Failure>,
    pub cancelled: bool,
    pub deadline_expired: bool,
}

#[derive(Debug)]
pub struct Outcome {
    pub binding: Value,
    pub steps: Vec<Step>,
    pub failure: Option<Failure>,
}

struct Authenticated {
    host: HostKey,
    jump: Option<HostKey>,
}

impl Authenticated {
    fn from(connection: &private::StagedConnection) -> Self {
        Self {
            host: connection.verified_host().clone(),
            jump: connection.verified_jump().cloned(),
        }
    }
    fn matches(&self, connection: &private::StagedConnection) -> bool {
        &self.host == connection.verified_host() && self.jump.as_ref() == connection.verified_jump()
    }
}

pub struct Prepared<'a> {
    project: &'a LoadedProject,
    policy: Policy,
    selected: SelectedTarget<'a>,
    inventory: EffectiveInventory,
    action: Action,
    destination: String,
    source: Option<String>,
    references: Vec<SecretReference>,
    ca: Option<PathBuf>,
    base: Value,
    projection: Value,
    action_timeout: u64,
    clock: private::ActionClock,
    authority: Option<state::CredentialAuthority>,
    relay_gate: Option<RelayGate>,
}

struct RelayGate {
    reached: tokio::sync::oneshot::Sender<Value>,
    proceed: tokio::sync::oneshot::Receiver<()>,
}

fn require(condition: bool, failure: Failure) -> Result<()> {
    if condition { Ok(()) } else { Err(failure) }
}

pub fn declaration_fingerprints(
    project: &LoadedProject,
    selected: &SelectedTarget<'_>,
) -> state::Result<Value> {
    let prefix = format!("environments.{}.k3s.", selected.environment);
    let target = selected
        .config_path
        .strip_prefix(&prefix)
        .ok_or(state::Failure::Configuration)?;
    let config = state::rpc::declaration_config(project, selected.environment, target, selected)?;
    Ok(json!({"declaration_sha256":state::hash("broil-infra-config-v1", &config)?}))
}

fn config_json(value: &ConfigValue) -> Value {
    match value {
        ConfigValue::Null => Value::Null,
        ConfigValue::Bool(v) => json!(v),
        ConfigValue::Integer(v) => json!(v),
        ConfigValue::String(v) => json!(v),
        ConfigValue::Sequence(v) => Value::Array(v.iter().map(config_json).collect()),
        ConfigValue::Mapping(v) => {
            Value::Object(v.iter().map(|(k, v)| (k.clone(), config_json(v))).collect())
        }
    }
}

fn subtree<'a>(mut value: &'a ConfigValue, path: &[&str]) -> Result<&'a ConfigValue> {
    for key in path {
        let ConfigValue::Mapping(map) = value else {
            return Err(Failure::Configuration);
        };
        value = map.get(*key).ok_or(Failure::Configuration)?;
    }
    Ok(value)
}

fn member(
    selected: &SelectedTarget<'_>,
    machine: &str,
    uid: &Option<String>,
    backup: bool,
) -> Result<Value> {
    if backup && machine == selected.declaration.backup.machine {
        require(uid.is_none(), Failure::Configuration)?;
        return Ok(json!({"machine": machine, "member": null, "role": "backup", "node_uid": null}));
    }
    let member = selected
        .members
        .iter()
        .find(|m| m.declaration.machine == machine)
        .ok_or(Failure::Configuration)?
        .declaration;
    require(uid.as_deref().is_none_or(opaque), Failure::Configuration)?;
    Ok(json!({"machine": machine, "member": member.name,
        "role": if member.role == Role::Server { "server" } else { "agent" }, "node_uid": uid}))
}

pub(crate) fn read_ca(
    path: &std::path::Path,
    bound: usize,
) -> std::io::Result<Option<Zeroizing<Vec<u8>>>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?.take(bound as u64 + 1);
    let mut ca = Zeroizing::new(vec![0; bound + 1]);
    let mut used = 0;
    loop {
        let n = file.read(&mut ca[used..])?;
        if n == 0 {
            break;
        }
        used += n;
    }
    if !(1..=bound).contains(&used) {
        return Ok(None);
    }
    ca.truncate(used);
    Ok(Some(ca))
}

fn origin(endpoint: &broil_core::images::reference::Endpoint) -> String {
    let o = endpoint.origin();
    let host = if o.host.contains(':') {
        format!("[{}]", o.host)
    } else {
        o.host
    };
    format!("{}://{}:{}", o.scheme, host, o.port)
}

pub fn prepare<'a>(
    project: &'a LoadedProject,
    mut policy: Policy,
    target: &str,
    destination: &str,
    generation: Generation,
    operation: Operation,
) -> Result<Prepared<'a>> {
    let started = tokio::time::Instant::now();
    let selected = select::select(project, Some(OsStr::new(&policy.environment)), target)
        .map_err(|_| Failure::Configuration)?;
    let inventory = broil_remote::resolve(project, Some(OsStr::new(&policy.environment)))
        .map_err(|_| Failure::Configuration)?;
    let t = selected.declaration;
    require(
        inventory
            .scripts
            .get(&t.lifecycle_script)
            .is_some_and(|script| script.body.as_bytes() == ADAPTER),
        Failure::Configuration,
    )?;
    let mut source = None;
    let mut references = Vec::new();
    let mut ca = None;
    let mut selectors =
        json!({"issuer":null,"service":null,"principal":null,"origin":null,"recovery":null});
    let action = match operation {
        Operation::InitialServer => {
            require(
                t.members
                    .first()
                    .is_some_and(|m| m.machine == destination && m.role == Role::Server)
                    && t.credentials.server_token != t.credentials.agent_token,
                Failure::Configuration,
            )?;
            references.extend([
                t.credentials.server_token.clone(),
                t.credentials.agent_token.clone(),
            ]);
            Action::Initial
        }
        Operation::ServerJoin { source: machine } => {
            source = Some(machine);
            Action::ServerJoin
        }
        Operation::AgentJoin { source: machine } => {
            source = Some(machine);
            Action::AgentJoin
        }
        Operation::AdministrativeCheck => Action::Admin,
        Operation::Issuer { name } => {
            let issuer = t
                .infrastructure
                .issuers
                .get(&name)
                .ok_or(Failure::Configuration)?;
            selectors["issuer"] = json!(name);
            match issuer {
                Issuer::PrivateCa { certificate, key } => {
                    references.extend([certificate.clone(), key.clone()]);
                    Action::IssuerCa
                }
                Issuer::AcmeHttp01 { account_key, .. } => {
                    references.push(account_key.clone());
                    Action::IssuerAcme
                }
            }
        }
        Operation::RegistrySigning => {
            let registry = t.registry.as_ref().ok_or(Failure::Configuration)?;
            references.push(
                registry
                    .authentication
                    .signing_key
                    .clone()
                    .ok_or(Failure::Configuration)?,
            );
            selectors["service"] = json!(registry.name);
            selectors["origin"] = json!(origin(
                &selected.registries[&registry.endpoint].declaration.endpoint
            ));
            Action::RegistrySigning
        }
        Operation::RegistryPrincipal { name } => {
            let registry = t.registry.as_ref().ok_or(Failure::Configuration)?;
            let principal = registry
                .authentication
                .principals
                .get(&name)
                .ok_or(Failure::Configuration)?;
            references.push(principal.password.clone());
            selectors["service"] = json!(registry.name);
            selectors["principal"] = json!(name);
            selectors["origin"] = json!(origin(
                &selected.registries[&registry.endpoint].declaration.endpoint
            ));
            Action::RegistryPrincipal
        }
        Operation::NodeRegistry { registry } => {
            let declaration = t
                .node_registries
                .iter()
                .find(|r| r.registry == registry)
                .ok_or(Failure::Configuration)?;
            let endpoint = selected
                .registries
                .get(&registry)
                .ok_or(Failure::Configuration)?;
            references.push(declaration.password.clone());
            ca = endpoint.ca.clone();
            selectors["origin"] = json!(origin(&endpoint.declaration.endpoint));
            Action::NodeRegistry
        }
        Operation::RecoveryKey => {
            references.push(t.backup.identity.clone());
            selectors["recovery"] = json!(generation.resource);
            Action::RecoveryKey
        }
        Operation::RecoveryServerToken => {
            references.push(t.credentials.server_token.clone());
            selectors["recovery"] = json!(generation.resource);
            Action::RecoveryServer
        }
    };
    let backup = matches!(action, Action::RecoveryKey | Action::RecoveryServer)
        && destination == t.backup.machine;
    let destination_value = member(&selected, destination, &generation.destination_uid, backup)?;
    let role = destination_value["role"]
        .as_str()
        .ok_or(Failure::Configuration)?;
    require(
        match action {
            Action::AgentJoin => role == "agent",
            Action::NodeRegistry => matches!(role, "server" | "agent"),
            Action::RecoveryKey | Action::RecoveryServer => matches!(role, "server" | "backup"),
            _ => role == "server",
        },
        Failure::Configuration,
    )?;
    let source_value = if let Some(source) = &source {
        let value = member(&selected, source, &generation.source_uid, false)?;
        require(
            source != destination && value["role"] == "server",
            Failure::Configuration,
        )?;
        value
    } else {
        require(generation.source_uid.is_none(), Failure::Configuration)?;
        Value::Null
    };
    for value in [
        &generation.owner,
        &generation.operation,
        &generation.attempt,
        &generation.resource,
        &generation.generation,
    ] {
        require(opaque(value), Failure::Configuration)?;
    }
    require(
        generation.resource_uid.as_deref().is_none_or(opaque),
        Failure::Configuration,
    )?;
    require(
        generation.resource_uid.is_some()
            == matches!(
                action,
                Action::IssuerCa
                    | Action::IssuerAcme
                    | Action::RegistrySigning
                    | Action::RegistryPrincipal
            ),
        Failure::Configuration,
    )?;
    require(t.version == "v1.36.4+k3s1", Failure::Configuration)?;
    let cluster = match &generation.cluster {
        Some(cluster) if action != Action::Initial => {
            require(
                opaque(&cluster.uid)
                    && cluster.ca_sha256.len() == 64
                    && cluster
                        .ca_sha256
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                Failure::Configuration,
            )?;
            json!({"uid":cluster.uid,"ca_sha256":cluster.ca_sha256})
        }
        None if action == Action::Initial => Value::Null,
        _ => return Err(Failure::Configuration),
    };
    let mut base = json!({"project":project.broil_root.to_str().ok_or(Failure::Configuration)?,
        "environment":policy.environment,"target":target,"owner":generation.owner,"operation":generation.operation,
        "attempt":generation.attempt,"source":source_value,"destination":destination_value,"cluster":cluster,
        "resource":{"kind":action.kind(),"id":generation.resource,"generation":generation.generation,"uid":generation.resource_uid},
        "profile_sha256":digest(PROFILE),"script_sha256":digest(ADAPTER)});
    for (key, value) in selectors.as_object().ok_or(Failure::Configuration)? {
        base[key] = value.clone();
    }
    let mut scripts = serde_json::Map::new();
    let mut timeout = selected
        .operation_timeout
        .seconds
        .min(selected.step_timeout.seconds);
    for machine in source
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(destination))
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
        let expected_env = std::collections::BTreeMap::from([
            ("BROIL_ENV".into(), policy.environment.as_bytes().to_vec()),
            ("BROIL_MACHINE".into(), machine.as_bytes().to_vec()),
        ]);
        require(
            script.body == ADAPTER
                && script.interpreter.is_none()
                && script.cwd.is_none()
                && script.env == expected_env
                && script.args.is_empty(),
            Failure::Configuration,
        )?;
        let effective = &inventory.scripts[&t.lifecycle_script];
        timeout = timeout.min(effective.timeout.as_ref().map_or(900, |v| v.seconds));
        scripts.insert(machine.into(), json!({"script_sha256":digest(&script.body),"interpreter":null,
            "cwd":null,"environment":{"BROIL_ENV":policy.environment,"BROIL_MACHINE":machine},"privilege":t.privilege,
            "timeout_seconds":effective.timeout.as_ref().map(|v| v.seconds)}));
    }
    let declaration = config_json(subtree(
        &project.config.normalized,
        &["environments", &policy.environment, "k3s", target],
    )?);
    let mut endpoints = serde_json::Map::new();
    for (name, endpoint) in &selected.registries {
        let raw = subtree(
            &project.config.normalized,
            &["environments", &policy.environment, "registries", name],
        )
        .or_else(|_| subtree(&project.config.normalized, &["registries", name]))?;
        endpoints.insert(
            name.clone(),
            json!({"declaration":config_json(raw),"ca_path":endpoint.ca}),
        );
    }
    let secrets = json!({"root":subtree(&project.config.normalized, &["secrets"]).map(config_json).unwrap_or(Value::Null),
        "environment":subtree(&project.config.normalized, &["environments", &policy.environment, "secrets"]).map(config_json).unwrap_or(Value::Null),
        "effective":{"store":selected.secrets.store,"project":selected.secrets.project,"identity":selected.secrets.identity,
            "vault":{"address":selected.secrets.vault.address,"mount":selected.secrets.vault.mount,"credential":selected.secrets.vault.credential,
                "fallback":match selected.secrets.vault.fallback { Some(broil_core::secrets::Fallback::Local)=>"local", _=>"none" }}}});
    let reference_projection: Vec<Value> = references
        .iter()
        .map(|r| json!({"set":r.set,"key":r.key}))
        .collect();
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    require(
        profile["script_sha256"] == digest(ADAPTER),
        Failure::Configuration,
    )?;
    let projection = json!({"schema":1,"binding":base,"declaration":declaration,"scripts":scripts,"registries":endpoints,"secrets":secrets,
        "references":reference_projection,"profile":profile});
    base["selection_sha256"] = json!(digest(&canonical(&projection)?));
    policy.environment_snapshot = ordinary_snapshot(&policy.environment_snapshot);
    let clock =
        private::ActionClock::new(policy.deadline.min(started + Duration::from_secs(timeout)));
    Ok(Prepared {
        project,
        policy,
        selected,
        inventory,
        action,
        destination: destination.into(),
        source,
        references,
        ca,
        base,
        projection,
        action_timeout: timeout,
        clock,
        authority: None,
        relay_gate: None,
    })
}

impl Prepared<'_> {
    fn refresh_action_clock(&mut self) {
        self.clock = private::ActionClock::new(
            self.policy
                .deadline
                .min(tokio::time::Instant::now() + Duration::from_secs(self.action_timeout)),
        );
    }

    fn deadline(&self) -> tokio::time::Instant {
        self.authority
            .as_ref()
            .map_or_else(|| self.clock.deadline(), |a| a.clock.deadline())
    }

    pub fn projection(&self) -> &Value {
        &self.projection
    }

    fn check(&self) -> Result<()> {
        require(
            !self.policy.cancellation.is_cancelled(),
            Failure::Cancellation,
        )?;
        require(
            tokio::time::Instant::now() < self.deadline(),
            Failure::Deadline,
        )?;
        if let Some(authority) = &self.authority {
            authority
                .clock
                .check(&self.policy.cancellation)
                .map_err(|_| Failure::Transport)?;
        }
        Ok(())
    }

    fn request(&self, action: Action, inspecting: bool, lengths: &[usize]) -> Result<Vec<u8>> {
        self.check()?;
        let mut value = self.base.clone();
        value["protocol"] = json!("broil-k3s-actions");
        value["version"] = json!(1);
        value["action"] = json!(if inspecting { "inspect" } else { action.tag() });
        value["for_action"] = if inspecting {
            json!(action.tag())
        } else {
            Value::Null
        };
        value["request_id"] = if !inspecting {
            self.authority
                .as_ref()
                .and_then(|authority| authority.requests.get(action.tag()))
                .ok_or(Failure::Action)?["request_id"]
                .clone()
        } else {
            json!(sudo_nonce().map_err(|_| Failure::Configuration)?)
        };
        value["remaining_ms"] = json!(
            self.deadline()
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(7_200_000) as u64
        );
        value["slot_lengths"] = json!(lengths);
        let bytes = canonical(&value)?;
        require(
            bytes.len() <= 4096 && value["remaining_ms"] != 0,
            Failure::Bound,
        )?;
        Ok(bytes)
    }

    async fn connect(
        &self,
        machine: &str,
    ) -> std::result::Result<private::StagedConnection, private::Observation> {
        let config_error = || private::Observation {
            failure: Some(FailureClass::Configuration),
            ..Default::default()
        };
        self.check().map_err(|_| config_error())?;
        let target = self
            .inventory
            .machines
            .iter()
            .find(|m| m.name == machine)
            .ok_or_else(config_error)?;
        let backend = crate::remote::builder_backend(
            self.project,
            &self.inventory,
            target,
            &self.policy.cwd,
            &self.policy.environment_snapshot,
            self.policy
                .credentials
                .try_duplicate()
                .map_err(|_| config_error())?,
            self.selected.declaration.privilege.as_deref(),
            self.policy.non_interactive,
        )
        .map_err(|_| config_error())?;
        let plan = private::prepare_k3s(
            &self.project.broil_root,
            &self.inventory,
            machine,
            &self.selected.declaration.lifecycle_script,
            self.selected.declaration.privilege.as_deref(),
        )
        .map_err(|_| config_error())?;
        let staged = match &self.authority {
            Some(authority) => plan.k3s_credential_staging(&authority.clock),
            None => plan.k3s_staging(self.clock.clone()),
        }
        .map_err(|_| config_error())?;
        staged
            .connect(backend, self.policy.cancellation.clone())
            .await
    }

    fn observe(
        &self,
        output: &private::Outcome,
        header: &[u8],
        action: Action,
        inspecting: bool,
    ) -> Step {
        let header: Value = serde_json::from_slice(header).expect("controller header");
        let original = canonical(&header).expect("controller header");
        let parsed = protocol::reply(output.stdout.bytes(), &original, action, inspecting);
        let result = parsed.as_ref().ok().map(|reply| reply.result);
        let transport_ok = output.observation.failure.is_none()
            && output.observation.remote_status == Some(0)
            && output.observation.remote_signal.is_none()
            && !output.observation.possible_staging_residue
            && !output.observation.unresolved_input
            && output.stderr.bytes().is_empty();
        Step {
            request_id: Some(
                header["request_id"]
                    .as_str()
                    .expect("controller nonce")
                    .into(),
            ),
            action: action.tag(),
            inspecting,
            transport: private::Observation {
                failure: output.observation.failure,
                dispatched: output.observation.dispatched,
                remote_status: output.observation.remote_status,
                remote_signal: output.observation.remote_signal.clone(),
                possible_staging_residue: output.observation.possible_staging_residue,
                unresolved_input: output.observation.unresolved_input,
            },
            result,
            possible_consumer_residue: !inspecting
                && !matches!(
                    action,
                    Action::ReadServer | Action::ReadAgent | Action::Admin
                )
                && output.observation.dispatched
                && matches!(
                    result,
                    None | Some(ResultClass::Execution | ResultClass::Unknown)
                ),
            failure: if self.policy.cancellation.is_cancelled() {
                Some(Failure::Cancellation)
            } else if tokio::time::Instant::now() >= self.deadline() {
                Some(Failure::Deadline)
            } else if !transport_ok {
                Some(Failure::Transport)
            } else if parsed.is_err() {
                Some(Failure::Protocol)
            } else if result != Some(ResultClass::Success) {
                Some(Failure::Action)
            } else {
                None
            },
            cancelled: self.policy.cancellation.is_cancelled(),
            deadline_expired: tokio::time::Instant::now() >= self.deadline(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch(
        &self,
        connection: private::StagedConnection,
        action: Action,
        inspecting: bool,
        slots: Zeroizing<Vec<u8>>,
        lengths: &[usize],
        terminal: bool,
        steps: &mut Vec<Step>,
    ) -> Result<(private::Outcome, Vec<u8>)> {
        let header = match self.request(action, inspecting, lengths) {
            Ok(header) => header,
            Err(failure) => {
                drop(slots);
                let observation = connection.close().await;
                self.closed(steps, action, inspecting, observation, failure);
                return Err(failure);
            }
        };
        let output = if terminal && self.authority.is_some() {
            connection
                .run_credential(header.clone(), StaticStdin::secret(slots))
                .await
        } else {
            connection
                .run(header.clone(), StaticStdin::secret(slots), terminal)
                .await
        }
        .map_err(|_| Failure::Transport)?;
        let step = self.observe(&output, &header, action, inspecting);
        let failure = step.failure;
        steps.push(step);
        if let Some(failure) = failure {
            return Err(failure);
        }
        Ok((output, header))
    }

    fn closed(
        &self,
        steps: &mut Vec<Step>,
        action: Action,
        inspecting: bool,
        transport: private::Observation,
        failure: Failure,
    ) {
        steps.push(Step {
            request_id: None,
            action: action.tag(),
            inspecting,
            transport,
            result: None,
            possible_consumer_residue: false,
            failure: Some(failure),
            cancelled: self.policy.cancellation.is_cancelled(),
            deadline_expired: tokio::time::Instant::now() >= self.deadline(),
        });
    }

    async fn connected(
        &self,
        machine: &str,
        action: Action,
        inspecting: bool,
        steps: &mut Vec<Step>,
    ) -> Result<private::StagedConnection> {
        self.connect(machine).await.map_err(|transport| {
            self.closed(steps, action, inspecting, transport, Failure::Transport);
            Failure::Transport
        })
    }

    async fn inspect(
        &self,
        machine: &str,
        action: Action,
        steps: &mut Vec<Step>,
    ) -> Result<Authenticated> {
        let connection = self.connected(machine, action, true, steps).await?;
        let identity = Authenticated::from(&connection);
        self.dispatch(
            connection,
            action,
            true,
            Zeroizing::new(Vec::new()),
            &[],
            false,
            steps,
        )
        .await?;
        self.check()?;
        Ok(identity)
    }

    async fn bound_connection(
        &self,
        machine: &str,
        action: Action,
        identity: &Authenticated,
        steps: &mut Vec<Step>,
    ) -> Result<private::StagedConnection> {
        let connection = self.connected(machine, action, false, steps).await?;
        if !identity.matches(&connection) {
            let transport = connection.close().await;
            self.closed(steps, action, false, transport, Failure::Configuration);
            return Err(Failure::Configuration);
        }
        Ok(connection)
    }

    fn acquisition(&self) -> Result<Acquisition> {
        self.check()?;
        Ok(Acquisition {
            selected: read::Selection::new(
                &self.project.config,
                &self.project.broil_root,
                Some(OsStr::new(&self.policy.environment)),
            )
            .map_err(|_| Failure::Configuration)?,
            cwd: self.policy.cwd.clone(),
            credentials: self
                .policy
                .credentials
                .try_duplicate()
                .map_err(|_| Failure::Acquisition)?,
            non_interactive: self.policy.non_interactive,
            cancellation: self.policy.cancellation.clone(),
            operation_stopped: self
                .authority
                .as_ref()
                .map(|authority| authority.clock.stop_signal()),
            deadline: self.deadline(),
            references: self.references.clone(),
            ca: self.ca.clone(),
            action: self.action,
            backup_recipient: self.selected.declaration.backup.recipient.clone(),
        })
    }

    async fn execute(&mut self, steps: &mut Vec<Step>) -> Result<()> {
        require(self.authority.is_some(), Failure::Action)?;
        let read = match self.action {
            Action::ServerJoin => Some(Action::ReadServer),
            Action::AgentJoin => Some(Action::ReadAgent),
            _ => None,
        };
        let source_identity = if let Some(read) = read {
            Some(
                self.inspect(
                    self.source.as_deref().ok_or(Failure::Configuration)?,
                    read,
                    steps,
                )
                .await?,
            )
        } else {
            None
        };
        let destination_identity = self.inspect(&self.destination, self.action, steps).await?;
        let destination = self
            .bound_connection(&self.destination, self.action, &destination_identity, steps)
            .await?;
        let body = if let Some(read) = read {
            let source = match self
                .bound_connection(
                    self.source.as_deref().ok_or(Failure::Configuration)?,
                    read,
                    source_identity.as_ref().ok_or(Failure::Configuration)?,
                    steps,
                )
                .await
            {
                Ok(source) => source,
                Err(failure) => {
                    let observation = destination.close().await;
                    self.closed(steps, self.action, false, observation, failure);
                    return Err(failure);
                }
            };
            match self
                .dispatch(
                    source,
                    read,
                    false,
                    Zeroizing::new(Vec::new()),
                    &[],
                    false,
                    steps,
                )
                .await
            {
                Ok((output, header)) => {
                    let framed = (|| {
                        let reply = protocol::reply(output.stdout.bytes(), &header, read, false)?;
                        protocol::secure_token(
                            reply.slots[0],
                            read == Action::ReadServer,
                            self.base["cluster"]["ca_sha256"]
                                .as_str()
                                .ok_or(Failure::Configuration)?,
                        )?;
                        if read == Action::ReadServer {
                            let agent = reply.slots[1];
                            require(
                                agent.len() == 64
                                    && agent
                                        .iter()
                                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
                                    && agent != &reply.slots[0][reply.slots[0].len() - 64..],
                                Failure::Credential,
                            )?;
                        }
                        let lengths = reply.slots.iter().map(|s| s.len()).collect();
                        Ok((
                            protocol::frame(&reply.slots, self.action.limits(false))?,
                            lengths,
                        ))
                    })();
                    drop(output);
                    framed
                }
                Err(failure) => Err(failure),
            }
        } else {
            match self.acquisition() {
                Ok(acquisition) => {
                    let mut work = tokio::task::spawn_blocking(move || acquisition.run());
                    let authority = self.authority.as_ref().ok_or(Failure::Action)?;
                    let observed = tokio::select! {
                        biased;
                        _=self.policy.cancellation.cancelled()=>None,
                        _=authority.clock.stopped()=>None,
                        result=tokio::time::timeout_at(self.deadline(),&mut work)=>result.ok(),
                    };
                    match observed {
                        Some(result) => result.map_err(|_| Failure::Acquisition).and_then(|v| v),
                        None => {
                            let until = authority.clock.abort();
                            let ended = tokio::time::timeout_at(until, &mut work).await;
                            Err(if ended.is_err() {
                                Failure::AcquisitionCleanup
                            } else if self.policy.cancellation.is_cancelled() {
                                Failure::Cancellation
                            } else {
                                Failure::Deadline
                            })
                        }
                    }
                }
                Err(failure) => Err(failure),
            }
        };
        let (body, lengths) = match body {
            Ok(body) => body,
            Err(failure) => {
                let observation = destination.close().await;
                self.closed(steps, self.action, false, observation, failure);
                return Err(failure);
            }
        };
        if read.is_some() {
            if let Some(gate) = self.relay_gate.take() {
                let admitted = async {
                    let source = steps.last().ok_or(Failure::Transport)?;
                    gate.reached
                        .send(state::rpc::transport(&source.transport))
                        .map_err(|_| Failure::Transport)?;
                    gate.proceed.await.map_err(|_| Failure::Transport)?;
                    self.check()
                }
                .await;
                if let Err(failure) = admitted {
                    let observation = destination.close().await;
                    self.closed(steps, self.action, false, observation, failure);
                    return Err(failure);
                }
            }
        }

        self.dispatch(destination, self.action, false, body, &lengths, true, steps)
            .await?;
        Ok(())
    }

    pub async fn run(mut self) -> Outcome {
        let mut steps = Vec::new();
        let mut failure = self.execute(&mut steps).await.err();
        if let Some(authority) = &mut self.authority {
            if failure.is_none() {
                failure = authority.clock.complete().err().map(|_| Failure::Transport);
            }
            if failure.is_some() {
                authority.clock.abort();
            }
        }
        Outcome {
            binding: self.base.clone(),
            steps,
            failure,
        }
    }
}

struct Acquisition {
    selected: read::Selection,
    cwd: PathBuf,
    credentials: CredentialInputs,
    non_interactive: bool,
    cancellation: CancellationToken,
    operation_stopped: Option<CancellationToken>,
    deadline: tokio::time::Instant,
    references: Vec<SecretReference>,
    ca: Option<PathBuf>,
    action: Action,
    backup_recipient: String,
}

pub(crate) fn password_form(value: &[u8]) -> Result<()> {
    require(
        (1..=72).contains(&value.len()) && !value.contains(&0),
        Failure::Credential,
    )
}

pub(crate) fn node_password_form(value: &[u8]) -> Result<()> {
    require(
        (1..=4096).contains(&value.len()) && !value.contains(&0),
        Failure::Credential,
    )
}

pub(crate) fn key_form(value: &[u8]) -> Result<()> {
    let text = value.strip_suffix(b"\n").unwrap_or(value);
    let lines: Vec<&[u8]> = text.split(|b| *b == b'\n').collect();
    let body = lines.get(1..lines.len() - 1).unwrap_or_default();
    require(
        lines.len() >= 3
            && lines[0] == b"-----BEGIN PRIVATE KEY-----"
            && lines[lines.len() - 1] == b"-----END PRIVATE KEY-----"
            && body.iter().enumerate().all(|(n, line)| {
                !line.is_empty()
                    && line.len() <= 64
                    && line.len() % 4 == 0
                    && (n + 1 == body.len() || !line.contains(&b'='))
            }),
        Failure::Credential,
    )?;
    let der = decoded(body)?;
    let (info, rest) = der_item(&der, 0x30)?;
    let (version, info) = der_item(info, 0x02)?;
    let (algorithm, info) = der_item(info, 0x30)?;
    let (key, info) = der_item(info, 0x04)?;
    require(
        rest.is_empty()
            && info.is_empty()
            && version == [0]
            && algorithm == b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00",
        Failure::Credential,
    )?;
    let (rsa, rest) = der_item(key, 0x30)?;
    let (version, mut rsa) = der_item(rsa, 0x02)?;
    require(rest.is_empty() && version == [0], Failure::Credential)?;
    let (modulus, _) = der_item(rsa, 0x02)?;
    for _ in 0..8 {
        let (integer, next) = der_item(rsa, 0x02)?;
        require(!integer.is_empty(), Failure::Credential)?;
        rsa = next;
    }
    let bits = match modulus {
        [0, second, ..] if *second >= 0x80 => 8 * (modulus.len() - 1),
        [first, ..] if (1..0x80).contains(first) => {
            8 * modulus.len() - first.leading_zeros() as usize
        }
        _ => 0,
    };
    require(
        rsa.is_empty() && (2048..=4096).contains(&bits),
        Failure::Credential,
    )
}

fn decoded(body: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>> {
    use base64ct::Encoding;
    let mut der = Zeroizing::new(vec![0; body.iter().map(|line| line.len() / 4 * 3).sum()]);
    let mut at = 0;
    for line in body {
        at += base64ct::Base64::decode(line, &mut der[at..])
            .map_err(|_| Failure::Credential)?
            .len();
    }
    der.truncate(at);
    Ok(der)
}

pub(crate) fn certificate_key(block: &str) -> Result<Vec<u8>> {
    use base64ct::Encoding;
    let body: String = block.lines().filter(|l| !l.starts_with("-----")).collect();
    let mut der = vec![0; body.len()];
    let der =
        base64ct::Base64::decode(body.as_bytes(), &mut der).map_err(|_| Failure::Configuration)?;
    let walk = || -> Result<Vec<u8>> {
        let (certificate, rest) = der_item(der, 0x30)?;
        let (mut tbs, certificate) = der_item(certificate, 0x30)?;
        let (_, certificate) = der_item(certificate, 0x30)?;
        let (_, certificate) = der_item(certificate, 0x03)?;
        require(
            rest.is_empty() && certificate.is_empty(),
            Failure::Credential,
        )?;
        if tbs.first() == Some(&0xa0) {
            tbs = der_item(tbs, 0xa0)?.1;
        }
        tbs = der_item(tbs, 0x02)?.1;
        for _ in 0..4 {
            tbs = der_item(tbs, 0x30)?.1;
        }
        let (key, mut tail) = der_item(tbs, 0x30)?;
        let spki = &tbs[..tbs.len() - tail.len()];
        let (algorithm, key) = der_item(key, 0x30)?;
        let (_, key) = der_item(key, 0x03)?;
        for tag in [0x81, 0x82, 0xa3] {
            if tail.first() == Some(&tag) {
                tail = der_item(tail, tag)?.1;
            }
        }
        require(
            key.is_empty()
                && tail.is_empty()
                && algorithm == b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00",
            Failure::Credential,
        )?;
        Ok(spki.to_vec())
    };
    walk().map_err(|_| Failure::Configuration)
}

fn der_item(input: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let (&found, rest) = input.split_first().ok_or(Failure::Credential)?;
    let (&first, rest) = rest.split_first().ok_or(Failure::Credential)?;
    let (length, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 | 0x82 => {
            let count = usize::from(first & 0x7f);
            let octets = rest.get(..count).ok_or(Failure::Credential)?;
            let length = octets.iter().fold(0, |n, b| (n << 8) | usize::from(*b));
            require(length >= 0x80 && octets[0] != 0, Failure::Credential)?;
            (length, &rest[count..])
        }
        _ => return Err(Failure::Credential),
    };
    require(found == tag && rest.len() >= length, Failure::Credential)?;
    Ok(rest.split_at(length))
}

impl Acquisition {
    fn check(&self) -> Result<()> {
        require(!self.cancellation.is_cancelled(), Failure::Cancellation)?;
        require(
            !self
                .operation_stopped
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled),
            Failure::Cancellation,
        )?;
        require(
            tokio::time::Instant::now() < self.deadline,
            Failure::Deadline,
        )
    }

    fn run(self) -> Result<(Zeroizing<Vec<u8>>, Vec<usize>)> {
        self.check()?;
        let cancel = self.cancellation.clone();
        let operation_stopped = self.operation_stopped.clone();
        let deadline = self.deadline;
        let control = AcquisitionControl::new(
            move || {
                cancel.is_cancelled()
                    || operation_stopped
                        .as_ref()
                        .is_some_and(CancellationToken::is_cancelled)
                    || tokio::time::Instant::now() >= deadline
            },
            || Box::new(()),
        );
        let mut values = Vec::with_capacity(self.references.len() + usize::from(self.ca.is_some()));
        for reference in &self.references {
            self.check()?;
            let value = read::resolve_scalar_with_options(
                &self.selected,
                &self.cwd,
                self.credentials
                    .try_duplicate()
                    .map_err(|_| Failure::Acquisition)?,
                &reference.key,
                Some(&reference.set),
                &control,
                self.non_interactive,
            )
            .map_err(|error| {
                if error.cleanup_failed() {
                    Failure::AcquisitionCleanup
                } else {
                    Failure::Acquisition
                }
            })?;
            self.check()?;
            if self.action == Action::RecoveryKey {
                let identity = broil_secrets::age::Identity::parse(value.as_str())
                    .map_err(|_| Failure::Credential)?;
                require(
                    identity.recipient().to_string() == self.backup_recipient,
                    Failure::Credential,
                )?;
            }
            if self.action == Action::RegistrySigning {
                key_form(value.as_str().as_bytes())?;
            }
            if self.action == Action::RegistryPrincipal {
                password_form(value.as_str().as_bytes())?;
            }
            if self.action == Action::NodeRegistry {
                node_password_form(value.as_str().as_bytes())?;
            }
            values.push(value.into_bytes());
        }
        if let Some(path) = &self.ca {
            let ca = read_ca(path, 262_144)
                .map_err(|_| Failure::Configuration)?
                .ok_or(Failure::Bound)?;
            values.push(ca);
        }
        if self.action == Action::Initial {
            require(values[0] != values[1], Failure::Credential)?;
        }
        let lengths = values.iter().map(|v| v.len()).collect();
        let body = protocol::frame(
            &values.iter().map(|v| v.as_slice()).collect::<Vec<_>>(),
            self.action.limits(self.ca.is_some()),
        )?;
        drop(values);
        self.check()?;
        Ok((body, lengths))
    }
}
