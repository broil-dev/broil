// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod access;
mod agent;
mod bootstrap;
mod cert_manager;
mod certificate;
pub(in crate::k3s) mod converge;
pub(in crate::k3s) mod history;
mod ingress;
mod issuer;
mod join;
pub(in crate::k3s) mod member;
mod network;
mod node;
mod node_registry;
mod provenance;
mod recipe;
mod recovery;
mod registry_auth;
mod registry_endpoint;
mod registry_replication;
mod registry_service;
mod registry_storage;
mod registry_token;
pub(in crate::k3s) mod release;
pub(in crate::k3s) mod release_apply;
pub(in crate::k3s) mod release_delivery;
mod release_hooks;
mod release_secret;
pub(in crate::k3s) mod release_status;
mod report;
pub(in crate::k3s) mod rpc;
mod schema;
mod server;
mod session;
mod store;

pub(in crate::k3s) mod views;
pub(in crate::k3s) use agent::wave_plan;
pub use bootstrap::prepare_hosts;
pub use recovery::resume;
pub(super) use recovery::retry;
pub use server::create_first_server;

#[doc(hidden)]
pub async fn reconcile_network(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    network::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn reconcile_ingress(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    ingress::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn reconcile_cert_manager(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    cert_manager::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn reconcile_issuer(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    issuer: &str,
) -> ExecutionResult<Snapshot> {
    issuer::reconcile(project, policy, target, issuer).await
}

#[doc(hidden)]
pub async fn reconcile_certificate(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    certificate: &str,
) -> ExecutionResult<Snapshot> {
    certificate::reconcile(project, policy, target, certificate).await
}

#[doc(hidden)]
pub async fn reconcile_registry_storage(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    registry_storage::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn reconcile_registry_service(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    registry_service::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn reconcile_registry_endpoint(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    registry_endpoint::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn reconcile_registry_auth(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    registry_auth::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn reconcile_registry_principals(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    registry_auth::reconcile_principals(project, policy, target).await
}

#[doc(hidden)]
pub async fn change_registry_principal(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    principal: &str,
) -> ExecutionResult<Snapshot> {
    registry_auth::change_principal(project, policy, target, principal).await
}

#[doc(hidden)]
pub async fn reconcile_registry_token(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    registry_token::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn reconcile_registry_replication(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    registry_replication::reconcile(project, policy, target).await
}

#[doc(hidden)]
pub async fn restart_members(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    node::restart_members(project, policy, target).await
}

#[doc(hidden)]
pub async fn node_registries(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Option<Snapshot>> {
    node_registry::node_registries(project, policy, target).await
}

#[doc(hidden)]
pub async fn change_node_registry(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    registry: &str,
) -> ExecutionResult<Option<Snapshot>> {
    node_registry::change_node_registry(project, policy, target, registry).await
}

pub async fn join_server(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    destination: &str,
    source: &str,
) -> ExecutionResult<Snapshot> {
    session::Session::begin_join(project, policy, target, destination, source, false, None)
        .await?
        .join_server()
        .await
}

pub async fn join_agent(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    destination: &str,
    source: &str,
) -> ExecutionResult<Snapshot> {
    let batch = session::fresh()?;
    session::Session::begin_join(
        project,
        policy,
        target,
        destination,
        source,
        true,
        Some(serde_json::json!({"batch_id":batch,"size":1,"single":true})),
    )
    .await?
    .join_agent()
    .await
}

pub async fn join_agents(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    source: &str,
    destinations: &[String],
    width: u8,
) -> ExecutionResult<Snapshot> {
    agent::join_agents(project, policy, target, source, destinations, width).await
}

pub async fn prepare_metadata(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
) -> ExecutionResult<Snapshot> {
    Box::pin(session::Session::begin(project, policy, target))
        .await?
        .prepare_metadata()
        .await
}

pub async fn prepare_initial_input(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    destination: &str,
) -> ExecutionResult<Snapshot> {
    let session = Box::pin(session::Session::begin_consumer(
        project,
        policy,
        target,
        destination,
        super::Operation::InitialServer,
    ))
    .await?;
    Box::pin(session.prepare_metadata()).await
}

#[doc(hidden)]
pub async fn prepare_server_inputs(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    destination: &str,
    source: &str,
) -> ExecutionResult<Snapshot> {
    Box::pin(session::Session::begin_consumer(
        project,
        policy,
        target,
        destination,
        super::Operation::ServerJoin {
            source: source.into(),
        },
    ))
    .await?
    .prepare_metadata()
    .await
}

pub async fn consume_existing(
    project: &broil_config::LoadedProject,
    policy: super::Policy,
    target: &str,
    destination: &str,
    resource: ResourceSelection,
    operation: super::Operation,
) -> ExecutionResult<Snapshot> {
    Box::pin(session::Session::begin_existing(
        project,
        policy,
        target,
        destination,
        resource,
        operation,
    ))
    .await?
    .prepare_metadata()
    .await
}

#[derive(Clone, Debug)]
pub struct ResourceSelection {
    pub id: String,
    pub generation: String,
}
pub(super) use report::{listed as listed_report, render, report as recorded_report};
pub use store::{Publication, Snapshot, Store};

pub(super) struct CredentialAuthority {
    pub(super) clock: broil_remote::exec::private::CredentialClock,
    pub(super) requests: std::collections::BTreeMap<String, Value>,
}

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Configuration,
    Capability,
    Credential,
    Authentication,
    Trust,
    Ownership,
    Integrity,
    Storage,
    Transport,
    Readiness,
    Timeout,
    Cancelled,
    Bound,
    UnsupportedVersion,
    Busy,
}

pub type Result<T> = std::result::Result<T, Failure>;

#[derive(Debug)]
pub struct ExecutionFailure {
    pub failure: Failure,
    pub completion_unknown: bool,
    pub cleanup_unknown: bool,
    pub snapshot: Option<Box<Snapshot>>,
    pub detail: Option<&'static str>,
}

pub type ExecutionResult<T> = std::result::Result<T, ExecutionFailure>;

impl From<Failure> for ExecutionFailure {
    fn from(failure: Failure) -> Self {
        Self {
            failure,
            completion_unknown: failure == Failure::Transport,
            cleanup_unknown: failure == Failure::Transport,
            snapshot: None,
            detail: None,
        }
    }
}

impl PartialEq<Failure> for ExecutionFailure {
    fn eq(&self, other: &Failure) -> bool {
        self.failure == *other
    }
}

impl ExecutionFailure {
    pub(super) fn report(&self, scope: &Value, view: &str) -> Result<Value> {
        let snapshots = self
            .snapshot
            .as_deref()
            .map(std::slice::from_ref)
            .unwrap_or(&[]);
        let mut value = report::report(
            scope,
            if snapshots.is_empty() { "list" } else { view },
            snapshots,
        )?;
        value["view"] = serde_json::json!(view);
        value["failure"] = serde_json::json!(self.failure.name());
        if let Some(detail) = self.detail {
            value["detail"] = serde_json::json!(detail);
        }
        value["completion_unknown"] =
            serde_json::json!(value["completion_unknown"] == true || self.completion_unknown);
        value["cleanup_unknown"] =
            serde_json::json!(value["cleanup_unknown"] == true || self.cleanup_unknown);
        value["outcome"] = serde_json::json!(if value["completion_unknown"] == true
            || value["cleanup_unknown"] == true
        {
            "unknown"
        } else if self.failure == Failure::Cancelled {
            "cancelled"
        } else {
            "failed"
        });
        value["recovery"] = serde_json::json!({"choice":"operator-recovery","proposal":null});
        Ok(value)
    }
}

impl Failure {
    pub fn name(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Capability => "capability",
            Self::Credential => "credential",
            Self::Authentication => "authentication",
            Self::Trust => "trust",
            Self::Ownership => "ownership",
            Self::Integrity => "integrity",
            Self::Storage => "storage",
            Self::Transport => "transport",
            Self::Readiness => "readiness",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::Bound => "bound",
            Self::UnsupportedVersion => "unsupported-version",
            Self::Busy => "busy",
        }
    }
}

impl From<crate::images::Failure> for Failure {
    fn from(value: crate::images::Failure) -> Self {
        use crate::images::Failure as F;
        match value {
            F::Storage => Self::Storage,
            F::Limit => Self::Bound,
            F::Timeout => Self::Timeout,
            F::Cancellation => Self::Cancelled,
            F::Capacity => Self::Busy,
            F::Authentication => Self::Authentication,
            F::Trust => Self::Trust,
            _ => Self::Integrity,
        }
    }
}

pub(super) fn require(value: bool, failure: Failure) -> Result<()> {
    if value { Ok(()) } else { Err(failure) }
}

pub fn nonce(value: &str) -> bool {
    hex(value, 32)
}
pub(super) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
pub fn operation_id(value: &str) -> bool {
    value.strip_prefix("infra-operation-").is_some_and(nonce)
}

pub(super) fn stable_fingerprints(request: &Value) -> Value {
    let mut fingerprints = request["fingerprints"].clone();
    if request["action"] == "prepare-hosts" {
        if let Some(tools) = fingerprints["tools"].as_array_mut() {
            tools.retain(|t| t["name"] != "bootstrap-recipe");
        }
    }
    fingerprints
}

pub fn canonical(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Failure::Integrity)
}

pub fn join_source(owner: &Value, destination: &str) -> Result<String> {
    first_published(&survivors(owner)?, destination)
        .and_then(|m| m["machine"].as_str().map(str::to_owned))
        .ok_or(Failure::Ownership)
}

pub(super) fn acting_server(owner: &Value) -> Result<Value> {
    first_published(&survivors(owner)?, "")
        .cloned()
        .ok_or(Failure::Integrity)
}

fn first_published<'m>(survivors: &'m [Value], except: &str) -> Option<&'m Value> {
    let servers = || survivors.iter().filter(|m| m["role"] != "agent");
    let any = servers().any(|m| m["node_uid"].is_string());
    servers().find(|m| (!any || m["node_uid"].is_string()) && m["machine"] != except)
}

pub(super) fn acting_first<'m>(members: &'m [Value], machine: &Value) -> Option<&'m Value> {
    members
        .iter()
        .find(|m| m["role"] == "server" && m["node_uid"].is_string() && m["machine"] != *machine)
}

pub(super) fn replacement_window(owner: &Value, prefix: &str) -> Result<()> {
    let planned: Vec<&Value> = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| r["id"].as_str().is_some_and(|id| id.starts_with(prefix)))
        .collect();
    let repeat = !planned.is_empty() && planned.iter().all(|r| r["uid"].is_string());
    require(
        owner["cluster"].is_null()
            || !repeat
            || survivors(owner)?.iter().all(|m| m["node_uid"].is_string()),
        Failure::Readiness,
    )
}

fn installation_recipe<'r>(
    context: &rpc::Context<'_>,
    previous: &'r [Snapshot],
    member: &Value,
    creation: &'r Value,
) -> Result<&'r Value> {
    if creation["member"]["machine"] == member["machine"] {
        Ok(creation)
    } else {
        agent::prior_recipe(context, previous, member)
    }
}

pub(super) fn current_installation<'a>(
    found: impl Iterator<Item = (&'a Snapshot, &'a Value)>,
) -> Result<&'a Value> {
    let found: Vec<_> = found
        .map(|(snapshot, event)| (snapshot.request["sequence"].as_u64(), event))
        .collect();
    let latest = found
        .iter()
        .map(|(sequence, _)| *sequence)
        .max()
        .ok_or(Failure::Ownership)?;
    let chosen: Vec<_> = found
        .iter()
        .filter(|(sequence, _)| *sequence == latest)
        .collect();
    require(
        chosen.len() == 1 && (found.len() == 1 || found.iter().all(|(s, _)| s.is_some())),
        Failure::Ownership,
    )?;
    Ok(chosen[0].1)
}

pub(super) fn latest_assets(records: &[Snapshot], action: &Value) -> Vec<Value> {
    records
        .iter()
        .filter(|s| s.request["action"] == *action)
        .filter(|s| {
            s.observations
                .iter()
                .any(|o| o["event"]["type"] == "component-assets")
        })
        .max_by_key(|s| s.request["sequence"].as_u64())
        .map(component_assets)
        .unwrap_or_default()
}

pub(super) fn survivors(owner: &Value) -> Result<Vec<Value>> {
    let removed = match &owner["removed"] {
        Value::Null => Vec::new(),
        removed => removed.as_array().ok_or(Failure::Integrity)?.clone(),
    };
    Ok(owner["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|m| !removed.iter().any(|r| r["member"] == m["member"]))
        .cloned()
        .collect())
}

fn declares_survivors(context: &rpc::Context<'_>, owner: &Value) -> Result<bool> {
    let survivors = survivors(owner)?;
    let removed: Vec<&Value> = owner["removed"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| &r["member"])
        .collect();
    let declared: Vec<_> = context
        .selected
        .members
        .iter()
        .filter(|m| !removed.iter().any(|r| **r == m.declaration.name.as_str()))
        .collect();
    Ok(declared.len() == survivors.len()
        && declared.iter().all(|m| {
            survivors.iter().any(|o| {
                o["machine"] == m.declaration.machine.as_str()
                    && o["member"] == m.declaration.name.as_str()
            })
        }))
}

pub(super) fn derived_recipe(
    original: &Value,
    request: &Value,
    assets: &[Value],
) -> Result<(Value, Value)> {
    let (label, key) = match request["action"].as_str() {
        Some("reconcile-network") => ("broil-k3s-network-recipe-v1", None),
        Some("reconcile-ingress") => ("broil-k3s-ingress-recipe-v1", Some("ingress_members")),
        Some("reconcile-cert-manager") => ("broil-k3s-cert-manager-recipe-v1", Some("generations")),
        _ => return Err(Failure::Integrity),
    };
    let members = request["members"].as_array().ok_or(Failure::Integrity)?;
    require(
        original["members"] == request["members"]
            || members.iter().all(|m| m["node_uid"].is_string()),
        Failure::Readiness,
    )?;
    let mut recipe = original.clone();
    recipe["members"] = Value::Array(members.clone());
    recipe["first_server"] = members.first().ok_or(Failure::Integrity)?.clone();
    if let Some(key) = key {
        let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
        let mut entries = Vec::new();
        for entry in original[key].as_array().ok_or(Failure::Integrity)? {
            let replaced = original["members"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .iter()
                .find(|o| o["machine"] == entry["machine"])
                .and_then(|o| members.iter().find(|m| m["member"] == o["member"]))
                .filter(|m| m["machine"] != entry["machine"])
                .and_then(|m| assets.iter().find(|a| a["machine"] == m["machine"]));
            if let Some(replacement) = replaced {
                require(
                    resources.iter().any(|r| {
                        r["kind"] == "bootstrap-assets"
                            && r["machine"] == replacement["machine"]
                            && r["generation"] == replacement["generation"]
                    }),
                    Failure::Ownership,
                )?;
                entries.push(replacement.clone());
            } else if members.iter().any(|m| m["machine"] == entry["machine"]) {
                require(
                    resources.iter().any(|r| {
                        r["kind"] == "bootstrap-assets"
                            && r["machine"] == entry["machine"]
                            && r["generation"] == entry["generation"]
                    }),
                    Failure::Ownership,
                )?;
                entries.push(entry.clone());
            }
        }
        recipe[key] = Value::Array(entries);
    }
    if recipe == *original {
        return Ok((recipe, Value::Null));
    }
    Ok((recipe, Value::String(hash(label, original)?)))
}

pub(super) fn original_hash(snapshot: &Snapshot, sent: &Value) -> Result<Value> {
    let kind = match snapshot.request["action"].as_str() {
        Some("reconcile-network") => "network-recipe",
        Some("reconcile-ingress") => "ingress-recipe",
        Some("reconcile-cert-manager") => "cert-manager-recipe",
        _ => return Err(Failure::Integrity),
    };
    let original = &snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == kind)
        .ok_or(Failure::Integrity)?["event"]["recipe"];
    let (derived, hash) = derived_recipe(original, &snapshot.request, &component_assets(snapshot))?;
    require(derived == *sent, Failure::Integrity)?;
    Ok(hash)
}

pub(super) fn component_assets(snapshot: &Snapshot) -> Vec<Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "component-assets")
        .and_then(|o| o["event"]["entries"].as_array().cloned())
        .unwrap_or_default()
}

fn replaced_assets(
    previous: &[Snapshot],
    context: &rpc::Context<'_>,
    original: &Value,
    members: &[Value],
) -> Result<Vec<Value>> {
    let named = original["members"].as_array().ok_or(Failure::Integrity)?;
    let replaced = members.iter().filter(|m| {
        named
            .iter()
            .any(|o| o["member"] == m["member"] && o["machine"] != m["machine"])
    });
    Ok(ingress::generations(previous, context, replaced)?.0)
}

pub fn participants(members: &Value) -> Result<String> {
    let mut projection = Vec::new();
    for member in members.as_array().ok_or(Failure::Integrity)? {
        let mut member = member.clone();
        let fields = member.as_object_mut().ok_or(Failure::Integrity)?;
        fields.insert("node_uid".into(), Value::Null);
        projection.push(member);
    }
    hash("broil-infra-participants-v1", &Value::Array(projection))
}

pub fn hash(label: &str, value: &Value) -> Result<String> {
    let mut bytes = label.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes.extend(canonical(value)?);
    Ok(super::protocol::digest(&bytes))
}

pub fn scope(project: &std::path::Path, environment: &str, target: &str) -> Result<Value> {
    let project = project.to_str().ok_or(Failure::Configuration)?;
    let value = serde_json::json!({"project":project,"environment":environment,"target":target,
        "hash":hash("broil-infra-scope-v1", &serde_json::json!([project,environment,target]))?});
    schema::validate(&canonical(&value)?, "Scope", 65536)?;
    Ok(value)
}
