// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, Snapshot, canonical, report, require};
use super::{
    cert_manager, certificate, issuer, registry_auth, registry_service, registry_storage,
    registry_token, rpc,
};
use crate::k3s::commands::Refusal;
use broil_core::k3s::{Issuer, Role};
use broil_remote::scheduler::CancellationToken;
use serde_json::{Value, json};
use std::time::Duration;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tokio::time::Instant;

pub(in crate::k3s) struct Prepared<'a>(rpc::Context<'a>);

impl<'a> Prepared<'a> {
    pub(in crate::k3s) fn new(
        project: &'a broil_config::LoadedProject,
        policy: &crate::k3s::Policy,
        target: &str,
        action: &str,
    ) -> std::result::Result<Self, Refusal> {
        let selected = broil_config::k3s::select::select(
            project,
            Some(std::ffi::OsStr::new(&policy.environment)),
            target,
        )
        .map_err(|_| Failure::Configuration)?;
        if matches!(action, "create" | "reconcile") {
            if let Some((name, _)) = selected
                .declaration
                .infrastructure
                .issuers
                .iter()
                .find(|(_, i)| issuer::acme(i))
            {
                return Err(Refusal {
                    failure: Failure::Capability,
                    boundary: Some("a later roadmap implements it"),
                    detail: Some(name.clone()),
                });
            }
        }
        let context = rpc::Context::new(project, issuer::duplicate(policy)?, target)?;
        if matches!(action, "create" | "reconcile") {
            gates(&context)?;
        }
        Ok(Self(context))
    }

    pub(in crate::k3s) fn plan(&self, action: &str, member: Option<&str>) -> Result<Value> {
        preview(&self.0, action, member)
    }

    pub(in crate::k3s) async fn run(
        &self,
        action: &str,
        plan: Option<Value>,
        stop: CancellationToken,
    ) -> super::ExecutionResult<(Value, bool)> {
        match plan {
            Some(plan) => observe(&self.0, plan).await,
            None => Ok(execute(&self.0, action, stop).await?),
        }
    }
}

fn gates(context: &rpc::Context<'_>) -> std::result::Result<(), Refusal> {
    let target = context.selected.declaration;
    require(target.members.len() <= 128, Failure::Bound)?;
    require(
        matches!(
            target
                .members
                .iter()
                .filter(|m| m.role == Role::Server)
                .count(),
            1 | 3
        ) && target
            .members
            .first()
            .is_some_and(|m| m.role == Role::Server),
        Failure::Configuration,
    )?;
    let profile: Value =
        serde_json::from_slice(crate::k3s::PROFILE).map_err(|_| Failure::Configuration)?;
    cert_manager::version(&profile, &target.infrastructure.cert_manager_version)?;
    for c in target.infrastructure.certificates.values() {
        let (duration, renew_before) = certificate::lifetime(c);
        certificate::duration_gate(duration, renew_before)?;
    }
    registry_gates(context)?;
    cert_manager::reference_fit(context).map_err(|failure| Refusal {
        failure,
        boundary: None,
        detail: Some(target.members.len().to_string()),
    })
}

pub(super) fn registry_gates(context: &rpc::Context<'_>) -> std::result::Result<(), Refusal> {
    let target = context.selected.declaration;
    let profile: Value =
        serde_json::from_slice(crate::k3s::PROFILE).map_err(|_| Failure::Configuration)?;
    if let Some(registry) = &target.registry {
        registry_storage::gate(Some(&registry.certificate), &target.infrastructure)?;
        for member in &target.members {
            registry_storage::replica_id(&member.name)?;
            super::registry_replication::replication_id(&member.name)?;
        }
        registry_service::gate(registry, &profile["registry"])?;
        registry_auth::gates(Some(registry), &target.infrastructure)?;
        registry_auth::bounds(registry)?;
        registry_token::fit(context)?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stage {
    name: &'static str,
    subject: Option<String>,
    members: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ceiling {
    None,
    Network,
    ServiceUnobserved,
    Certificate,
    RegistryService,
    Replication,
    Switch,
    Publication,
    Grants,
}

#[derive(Clone, Copy)]
struct Call {
    action: &'static str,
    ceiling: Ceiling,
    seconds: u64,
}

impl Stage {
    fn calls(&self) -> Vec<Call> {
        let entries = match self.name {
            "hosts" => vec![("prepare_hosts", Ceiling::None, 0)],
            "first-server" => vec![
                ("prepare_initial_input", Ceiling::None, 0),
                ("create_first_server", Ceiling::None, 0),
            ],
            "servers" => vec![("join_server", Ceiling::None, 0)],
            "agents" => vec![("join_agents", Ceiling::None, 0)],
            "node-join" => vec![("join_agent", Ceiling::None, 0)],
            "network" => vec![("reconcile_network", Ceiling::Network, 900)],
            "ingress" => vec![("reconcile_ingress", Ceiling::ServiceUnobserved, 600)],
            "cert-manager" => vec![("reconcile_cert_manager", Ceiling::ServiceUnobserved, 900)],
            "issuers" => vec![("reconcile_issuer", Ceiling::ServiceUnobserved, 300)],
            "certificates" => vec![("reconcile_certificate", Ceiling::Certificate, 600)],
            "registry" | "registry-only" => vec![
                ("reconcile_registry_storage", Ceiling::None, 0),
                ("reconcile_registry_service", Ceiling::RegistryService, 600),
                ("reconcile_registry_endpoint", Ceiling::None, 0),
                ("reconcile_registry_auth", Ceiling::None, 0),
                ("reconcile_registry_token", Ceiling::Switch, 900),
                ("reconcile_registry_principals", Ceiling::None, 0),
                (
                    "reconcile_registry_token",
                    if self.name == "registry-only" {
                        Ceiling::Grants
                    } else {
                        Ceiling::Publication
                    },
                    600,
                ),
            ],
            "registry-replication" => {
                vec![("reconcile_registry_replication", Ceiling::Replication, 900)]
            }
            "registry-signing" => vec![("reconcile_registry_auth", Ceiling::None, 0)],
            "registry-principal-change" => vec![("change_registry_principal", Ceiling::None, 0)],
            "registry-token-update" => {
                vec![("reconcile_registry_token", Ceiling::Publication, 600)]
            }
            "node-registry-change" => vec![("change_node_registry", Ceiling::None, 0)],
            "node-registries" => vec![("node_registries", Ceiling::None, 0)],
            "declaration" => vec![("rebind_declaration", Ceiling::None, 0)],
            "replace-begin" => vec![("replace_begin", Ceiling::None, 0)],
            "replace-hosts" => vec![("prepare_replacement_host", Ceiling::None, 0)],
            "replace-supply" => vec![("supply_replacement", Ceiling::None, 0)],
            "replace-join" => vec![("join_replacement", Ceiling::None, 0)],
            "replace-complete" => vec![("replace_complete", Ceiling::None, 0)],
            _ => Vec::new(),
        };
        entries
            .into_iter()
            .map(|(action, ceiling, seconds)| Call {
                action,
                ceiling,
                seconds,
            })
            .collect()
    }

    fn public_name(&self) -> &'static str {
        match self.name {
            "registry-only"
            | "registry-signing"
            | "registry-principal-change"
            | "registry-token-update" => "registry",
            "node-registry-change" => "node-registries",
            name => name,
        }
    }
}

fn stages(context: &rpc::Context<'_>, action: &str, member: Option<&str>) -> Result<Vec<Stage>> {
    let target = context.selected.declaration;
    let mut stages = Vec::new();
    let mut add = |name, subject, members| {
        stages.push(Stage {
            name,
            subject,
            members,
        })
    };
    let agents: Vec<_> = target
        .members
        .iter()
        .enumerate()
        .filter(|(_, m)| m.role == Role::Agent)
        .map(|(i, _)| i)
        .collect();
    if action == "registry-reconcile" {
        require(target.registry.is_some(), Failure::Configuration)?;
        add("registry-only", None, Vec::new());
        return Ok(stages);
    }
    if action == "credentials-reconcile" {
        match member.ok_or(Failure::Configuration)? {
            "admin" => add("admin", None, vec![0]),
            "infrastructure-tls" => {
                for name in target.infrastructure.issuers.keys() {
                    add("issuers", Some(name.clone()), Vec::new());
                }
                for name in target.infrastructure.certificates.keys() {
                    add("certificates", Some(name.clone()), Vec::new());
                }
            }
            "registry-auth" => {
                let registry = target.registry.as_ref().ok_or(Failure::Configuration)?;
                add("registry-signing", None, Vec::new());
                for name in registry.authentication.principals.keys() {
                    add("registry-principal-change", Some(name.clone()), Vec::new());
                }
                add("registry-token-update", None, Vec::new());
            }
            "node-pull" => {
                for entry in &target.node_registries {
                    add(
                        "registry-principal-change",
                        Some(entry.username.clone()),
                        Vec::new(),
                    );
                    add("registry-token-update", None, Vec::new());
                    add(
                        "node-registry-change",
                        Some(entry.registry.clone()),
                        (0..target.members.len()).collect(),
                    );
                    add("registry-token-update", None, Vec::new());
                }
            }
            _ => return Err(Failure::Capability),
        }
        return Ok(stages);
    }
    if action == "node-join" {
        let i = target
            .members
            .iter()
            .position(|m| Some(m.name.as_str()) == member)
            .ok_or(Failure::Configuration)?;
        require(i != 0, Failure::Configuration)?;
        add(
            if target.members[i].role == Role::Server {
                "servers"
            } else {
                "node-join"
            },
            Some(target.members[i].name.clone()),
            vec![i],
        );
        return Ok(stages);
    }
    if action == "node-join-agents" {
        add("agents", None, agents);
        return Ok(stages);
    }
    require(
        matches!(action, "create" | "reconcile"),
        Failure::Capability,
    )?;
    if action == "create" {
        add("hosts", None, (0..target.members.len()).collect());
        add(
            "first-server",
            Some(target.members[0].name.clone()),
            vec![0],
        );
        for (i, m) in target
            .members
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, m)| m.role == Role::Server)
        {
            add("servers", Some(m.name.clone()), vec![i]);
        }
        if !agents.is_empty() {
            add("agents", None, agents);
        }
    }
    for name in ["network", "ingress", "cert-manager"] {
        add(name, None, Vec::new());
    }
    for name in target.infrastructure.issuers.keys() {
        add("issuers", Some(name.clone()), Vec::new());
    }
    for name in target.infrastructure.certificates.keys() {
        add("certificates", Some(name.clone()), Vec::new());
    }
    if target.registry.is_some() {
        add("registry", None, Vec::new());
        add("registry-replication", None, Vec::new());
    }
    if !target.node_registries.is_empty() {
        add("node-registries", None, (0..target.members.len()).collect());
    }
    Ok(stages)
}

fn reference(r: &broil_core::images::SecretReference) -> Value {
    json!({"set":r.set,"key":r.key})
}

use crate::k3s::origin;

fn resource(
    kind: &str,
    subject: Option<&str>,
    member: Option<&str>,
    namespace: Option<&str>,
    name: Option<&str>,
    identity_source: &str,
    attributes: Value,
) -> Value {
    json!({"kind":kind,"subject":subject,"member":member,"namespace":namespace,
        "name":name,"identity_source":identity_source,"attributes":attributes})
}

fn resources(context: &rpc::Context<'_>, stage: &Stage) -> Result<Vec<Value>> {
    if stage.name == "admin" {
        let member = &context.selected.declaration.members[0];
        return Ok(vec![resource(
            "administrator-access",
            None,
            Some(&member.machine),
            None,
            None,
            "declaration",
            json!({"api_endpoint":context.selected.declaration.api.endpoint.supplied,"mode":"check"}),
        )]);
    }
    if stage.name.starts_with("replace-") {
        return Ok(Vec::new());
    }
    if stage.name != stage.public_name() {
        let mut mapped = stage.clone();
        mapped.name = stage.public_name();
        mapped.subject = None;
        let mut rows = resources(context, &mapped)?;
        rows.retain(|r| match stage.name {
            "registry-signing" => r["attributes"]["consumer"] == "signing",
            "registry-principal-change" => {
                r["attributes"]["principal"].as_str() == stage.subject.as_deref()
            }
            "registry-token-update" => r["name"] == "broil-registry-token",
            "node-registry-change" => {
                r["kind"] == "node-registry-configuration"
                    || r["subject"].as_str() == stage.subject.as_deref()
            }
            "registry-only" => true,
            _ => false,
        });
        return Ok(rows);
    }
    let t = context.selected.declaration;
    let mut out = Vec::new();
    let subject = stage.subject.as_deref();
    let mut object =
        |kind: &str, namespace: Option<&str>, name: Option<&str>, attributes: Value| {
            out.push(resource(
                kind,
                subject,
                None,
                namespace,
                name,
                if name.is_some() {
                    "profile"
                } else {
                    "execution"
                },
                attributes,
            ))
        };
    match stage.name {
        "network" => {
            let kinds = [
                "ServiceAccount",
                "ClusterRole",
                "ClusterRoleBinding",
                "ConfigMap",
                "Deployment",
                "Service",
                "ServiceAccount",
                "ClusterRole",
                "ClusterRoleBinding",
                "Deployment",
                "StorageClass",
                "ConfigMap",
            ];
            for ((namespace, name), kind) in super::store::NETWORK_OBJECTS.iter().zip(kinds) {
                object(
                    kind,
                    *namespace,
                    Some(*name),
                    json!({"pod_cidr":format!("{}/{}",t.network.pod_cidr.network,t.network.pod_cidr.prefix),
                    "service_cidr":format!("{}/{}",t.network.service_cidr.network,t.network.service_cidr.prefix),
                    "cluster_dns":t.network.cluster_dns.to_string(),"cluster_domain":context.selected.cluster_domain,"storage_class":"local-path"}),
                );
            }
        }
        "ingress" => {
            let attrs = json!({"placement":t.infrastructure.ingress_members,"ports":[80,443],"exposure":"host-ports","observation":"managed"});
            for (kind, name) in [
                ("HelmChart", "traefik-crd"),
                ("HelmChart", "traefik"),
                ("DaemonSet", "svclb-traefik"),
            ] {
                object(kind, Some("kube-system"), Some(name), attrs.clone());
            }
            for chart in ["traefik-crd", "traefik"] {
                for (kind, prefix, namespace) in [
                    ("Job", "helm-install-", Some("kube-system")),
                    ("ServiceAccount", "helm-", Some("kube-system")),
                    ("ClusterRoleBinding", "helm-kube-system-", None),
                    ("Secret", "chart-values-", Some("kube-system")),
                    ("ConfigMap", "chart-content-", Some("kube-system")),
                ] {
                    object(
                        kind,
                        namespace,
                        Some(&format!("{prefix}{chart}")),
                        json!({"observation":"result"}),
                    );
                }
            }
            for chart in ["traefik-crd", "traefik"] {
                object(
                    "Secret",
                    Some("kube-system"),
                    Some(&format!("sh.helm.release.v1.{chart}.v1")),
                    json!({"observation":"result"}),
                );
            }
            for (group, names) in [
                (
                    "traefik.io",
                    "ingressroutes ingressroutetcps ingressrouteudps middlewares middlewaretcps serverstransports serverstransporttcps tlsoptions tlsstores traefikservices",
                ),
                (
                    "hub.traefik.io",
                    "accesscontrolpolicies aiservices apiauths apibundles apicatalogitems apiplans apiportalauths apiportals apiratelimits apis apiversions contentitems managedapplications managedsubscriptions uplinks",
                ),
                (
                    "gateway.networking.k8s.io",
                    "backendtlspolicies gatewayclasses gateways grpcroutes httproutes listenersets referencegrants tlsroutes",
                ),
            ] {
                for name in names.split_whitespace() {
                    object(
                        "CustomResourceDefinition",
                        None,
                        Some(&format!("{name}.{group}")),
                        json!({"observation":"result"}),
                    );
                }
            }
            for (kind, ns, name) in [
                ("ServiceAccount", Some("kube-system"), "traefik"),
                ("ClusterRole", None, "traefik-kube-system"),
                ("ClusterRoleBinding", None, "traefik-kube-system"),
                ("DaemonSet", Some("kube-system"), "traefik"),
                ("Service", Some("kube-system"), "traefik"),
                ("IngressClass", None, "traefik"),
            ] {
                object(kind, ns, Some(name), json!({"observation":"result"}));
            }
        }
        "cert-manager" => {
            for (_, kind, ns, name) in cert_manager::identities() {
                object(kind, ns, Some(name), json!({}));
            }
        }
        "issuers" => {
            let name = subject.ok_or(Failure::Integrity)?;
            let declared = t
                .infrastructure
                .issuers
                .get(name)
                .ok_or(Failure::Configuration)?;
            let refs = match declared {
                Issuer::PrivateCa { certificate, key } => {
                    json!({"certificate":reference(certificate),"key":reference(key)})
                }
                Issuer::AcmeHttp01 { account_key, .. } => {
                    json!({"account_key":reference(account_key)})
                }
            };
            object(
                "ClusterIssuer",
                None,
                None,
                json!({"issuer":name,"kind":if issuer::acme(declared) { "acme-http01" } else { "private-ca" }}),
            );
            object("Secret", Some("cert-manager"), None, refs);
        }
        "certificates" => {
            let c = &t.infrastructure.certificates[subject.ok_or(Failure::Integrity)?];
            let (duration, renew_before) = certificate::lifetime(c);
            let attrs = json!({"issuer":c.issuer,"dns_names":c.dns_names,"duration_seconds":duration,"renew_before_seconds":renew_before});
            for kind in ["Certificate", "Secret"] {
                object(kind, Some("cert-manager"), None, attrs.clone());
            }
        }
        "registry" => {
            let registry = t.registry.as_ref().ok_or(Failure::Configuration)?;
            let entry = &context.selected.registries[&registry.endpoint];
            let attrs = json!({"registry":registry.name,"placement":registry.member,
                "storage_path":registry.storage.path,"storage_class":"","capacity_mib":registry.storage.capacity_mib});
            out.push(resource(
                "storage-directory",
                Some(&registry.name),
                t.members
                    .iter()
                    .find(|m| m.name == registry.member)
                    .map(|m| m.machine.as_str()),
                None,
                Some(&registry.storage.path),
                "declaration",
                attrs.clone(),
            ));
            out.push(resource(
                "PersistentVolume",
                Some(&registry.name),
                None,
                None,
                None,
                "execution",
                attrs,
            ));
            for (kind, ns, name) in [
                ("Namespace", None, Some("broil-registry")),
                (
                    "NetworkPolicy",
                    Some("broil-registry"),
                    Some("broil-registry"),
                ),
                ("ConfigMap", Some("broil-registry"), Some("broil-registry")),
                ("PersistentVolumeClaim", Some("broil-registry"), None),
                ("Service", Some("broil-registry"), Some("broil-registry")),
                ("Deployment", Some("broil-registry"), Some("broil-registry")),
            ] {
                out.push(resource(
                    kind,
                    Some(&registry.name),
                    None,
                    ns,
                    name,
                    if name.is_some() {
                        "profile"
                    } else {
                        "execution"
                    },
                    json!({"placement":registry.member}),
                ));
            }
            out.push(resource(
                "endpoint",
                Some(&registry.name),
                None,
                None,
                Some(&origin(&entry.declaration.endpoint)),
                "declaration",
                json!({"catalog":registry.endpoint,"ca_path":entry.ca}),
            ));
            for (kind, ns, name) in [
                ("NetworkPolicy", "broil-registry", "broil-registry-endpoint"),
                ("IngressRoute", "cert-manager", "broil-registry-tls"),
                ("IngressRoute", "broil-registry", "broil-registry"),
            ] {
                out.push(resource(
                    kind,
                    Some(&registry.name),
                    None,
                    Some(ns),
                    Some(name),
                    "profile",
                    json!({}),
                ));
            }
            out.push(resource("Secret", Some(&registry.name), None, Some("broil-registry"), None, "execution",
                json!({"consumer":"signing","reference":registry.authentication.signing_key.as_ref().map(reference)})));
            let token = entry
                .declaration
                .auth
                .get(&broil_core::images::RegistryPurpose::Push)
                .and_then(|auth| match &auth.credential {
                    broil_core::images::RegistryCredential::Password { token_service, .. } => {
                        token_service.as_ref()
                    }
                    _ => None,
                });
            for kind in [
                "NetworkPolicy",
                "Secret",
                "Deployment",
                "Service",
                "IngressRoute",
            ] {
                out.push(resource(kind, Some(&registry.name), None, Some("broil-registry"), Some("broil-registry-token"), "profile",
                    json!({"realm":token.map(|t| t.realm.supplied.as_str()),"service":token.map(|t| t.service.as_str())})));
            }
            for (name, p) in &registry.authentication.principals {
                let actions: Vec<_> = p
                    .actions
                    .iter()
                    .map(|a| match a {
                        broil_core::k3s::RegistryAction::Pull => "pull",
                        broil_core::k3s::RegistryAction::Push => "push",
                        broil_core::k3s::RegistryAction::Delete => "delete",
                    })
                    .collect();
                out.push(resource("Secret", Some(name), None, Some("broil-registry"), None, "execution",
                    json!({"principal":name,"repositories":p.repositories,"actions":actions,"reference":reference(&p.password)})));
            }
        }
        "registry-replication" => {
            let registry = t.registry.as_ref().ok_or(Failure::Configuration)?;
            for m in &t.members {
                out.push(resource(
                    "replication-directory",
                    Some(&registry.name),
                    Some(&m.machine),
                    None,
                    Some(super::registry_replication::PATH),
                    "profile",
                    json!({"member":m.name,"storage_path":registry.storage.path}),
                ));
            }
            for kind in ["ConfigMap", "DaemonSet"] {
                out.push(resource(
                    kind,
                    Some(&registry.name),
                    None,
                    Some("broil-registry"),
                    Some("broil-registry-reader"),
                    "profile",
                    json!({"listen":"127.0.0.1:5599"}),
                ));
            }
        }
        _ => {
            for (position, &i) in stage.members.iter().enumerate() {
                let m = &t.members[i];
                let role = if m.role == Role::Server {
                    "server"
                } else {
                    "agent"
                };
                let mut attrs = json!({"role":role,"node_name":m.name,"node_ip":m.node_ip.to_string(),
                    "source":t.members[0].name});
                let kinds: &[&str] = match stage.name {
                    "hosts" => {
                        attrs = json!({"role":role,"profile":"Ubuntu 24.04/systemd amd64","version":t.version,
                            "address":context.inventory.machines.iter().find(|machine| machine.name == m.machine).map(|machine| machine.address.as_str())});
                        &["prepared-host"]
                    }
                    "first-server" => {
                        attrs = json!({"api_endpoint":origin(&t.api.endpoint),"registration_endpoint":origin(&t.registration_endpoint),
                            "pod_cidr":format!("{}/{}",t.network.pod_cidr.network,t.network.pod_cidr.prefix),
                            "service_cidr":format!("{}/{}",t.network.service_cidr.network,t.network.service_cidr.prefix),
                            "cluster_dns":t.network.cluster_dns.to_string(),"cluster_domain":context.selected.cluster_domain});
                        &[
                            "server-configuration",
                            "server-service",
                            "server-datastore",
                            "cluster",
                        ]
                    }
                    "servers" => {
                        attrs["required_prefix"] = json!(
                            t.members[..i]
                                .iter()
                                .filter(|m| m.role == Role::Server)
                                .map(|m| &m.name)
                                .collect::<Vec<_>>()
                        );
                        &[
                            "server-configuration",
                            "server-service",
                            "server-datastore",
                            "Node",
                        ]
                    }
                    "agents" | "node-join" => {
                        attrs["labels"] = json!(m.labels);
                        attrs["taints"] = json!(m.taints.iter().map(|taint| json!({"key":taint.key,"value":taint.value,
                            "effect":match taint.effect { broil_core::k3s::TaintEffect::NoSchedule=>"NoSchedule",
                                broil_core::k3s::TaintEffect::PreferNoSchedule=>"PreferNoSchedule", broil_core::k3s::TaintEffect::NoExecute=>"NoExecute" }})).collect::<Vec<_>>());
                        attrs["wave"] =
                            json!(position / usize::from(context.selected.agent_wave_size) + 1);
                        attrs["wave_size"] = json!(context.selected.agent_wave_size);
                        &["agent-configuration", "agent-service", "Node"]
                    }
                    "node-registries" => {
                        attrs = json!({"action":"controlled-restart"});
                        &["node-registry-configuration"]
                    }
                    _ => return Err(Failure::Integrity),
                };
                for kind in kinds {
                    out.push(resource(
                        kind,
                        Some(&m.name),
                        Some(&m.machine),
                        None,
                        if *kind == "Node" { Some(&m.name) } else { None },
                        if *kind == "Node" {
                            "declaration"
                        } else {
                            "execution"
                        },
                        attrs.clone(),
                    ));
                }
                if stage.name == "node-registries" {
                    for r in &t.node_registries {
                        let entry = &context.selected.registries[&r.registry];
                        out.push(resource("registry-access", Some(&r.registry), Some(&m.machine), None,
                            Some(&r.registry), "declaration", json!({"catalog":r.registry,"origin":origin(&entry.declaration.endpoint),
                                "ca_path":entry.ca,"reference":reference(&r.password),"action":"controlled-restart"})));
                    }
                }
            }
        }
    }
    Ok(out)
}

fn preview(context: &rpc::Context<'_>, action: &str, member: Option<&str>) -> Result<Value> {
    let selected = stages(context, action, member)?;
    preview_stages(context, action, &selected)
}

fn preview_stages(context: &rpc::Context<'_>, action: &str, selected: &[Stage]) -> Result<Value> {
    let mut stages = Vec::new();
    for stage in selected {
        let calls: Vec<_> = stage.calls().iter().map(|call| json!({"action":call.action,"wait_bound_ms":call.seconds*1000,
            "wait_condition":match call.ceiling {
                Ceiling::None => json!(null), Ceiling::Network => json!({"services":"unobserved","storage":"unobserved"}),
                Ceiling::ServiceUnobserved => json!({"services":"unobserved"}), Ceiling::Certificate => json!({"services":"ready"}),
                Ceiling::RegistryService => json!({"services":"ready"}),
                Ceiling::Replication => json!({"services":"ready","storage":"ready"}),
                Ceiling::Switch => json!({"stage":"switch"}),
                Ceiling::Publication | Ceiling::Grants => json!({"services":"ready","publication":"unobserved"})}})).collect();
        stages.push(
            json!({"stage":stage.public_name(),"subject":stage.subject,"operations":calls,
            "resources":resources(context,stage)?}),
        );
    }
    let members: Vec<_> = context
        .selected
        .declaration
        .members
        .iter()
        .map(|m| {
            json!({"machine":m.machine,
        "member":m.name,"role":if m.role == Role::Server { "server" } else { "agent" }})
        })
        .collect();
    let references: Vec<_> = context
        .references
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| {
            let consumer = r["consumer"].as_str().unwrap_or("");
            matches!(action, "create" | "reconcile")
                && !consumer.starts_with("supply-recovery-")
                && (action == "create" || consumer != "supply-initial-server")
        })
        .map(|r| json!({"set":r["set"],"key":r["key"]}))
        .collect();
    let files: Vec<_> = if matches!(action, "create" | "reconcile") {
        context
            .selected
            .registries
            .values()
            .filter_map(|r| r.ca.clone())
            .chain(
                context
                    .selected
                    .declaration
                    .registry
                    .as_ref()
                    .and_then(|r| r.authentication.signing_certificate.as_ref())
                    .map(|p| context.project.broil_root.join(p)),
            )
            .collect()
    } else {
        Vec::new()
    };
    Ok(
        json!({"format_version":1,"scope":context.scope,"view":"plan","action":action,"observed":false,
        "members":members,"stages":stages,"prerequisites":{
            "bootstrap_manifest":context.selected.bootstrap_manifest,"bootstrap_bundle":context.selected.bootstrap_bundle,
            "files":files,"references":references},
        "unknown":["ownership","history","member-identities","resource-identities","readiness","owner-record-fit","store-capacity","live-budgets"]}),
    )
}

pub(super) async fn records(
    context: &rpc::Context<'_>,
) -> super::ExecutionResult<(Option<Value>, Vec<Snapshot>)> {
    let mut local = super::session::Local::new(context)?;
    let result = local
        .work(|store| {
            let snapshots = store.read_operations(None).map_err(|e| e.failure)?;
            require(
                snapshots.iter().all(|s| !s.attempts.is_empty()),
                Failure::Integrity,
            )?;
            Ok((store.observed_owner()?, snapshots))
        })
        .await;
    local.complete(result, &context.clock).await
}

fn newest(snapshots: &[Snapshot]) -> Option<&Snapshot> {
    snapshots.iter().min_by(|a, b| record_order(a, b))
}

pub(super) fn record_order(a: &Snapshot, b: &Snapshot) -> std::cmp::Ordering {
    b.request["created_ms"]
        .as_u64()
        .cmp(&a.request["created_ms"].as_u64())
        .then_with(|| {
            a.request["operation"]
                .as_str()
                .cmp(&b.request["operation"].as_str())
        })
}

async fn observe(
    context: &rpc::Context<'_>,
    mut preview: Value,
) -> super::ExecutionResult<(Value, bool)> {
    let projection_hash = super::hash("broil-infra-plan-v1", &preview)?;
    let (owner, snapshots) = records(context).await?;
    let (operation, attempt) = match newest(&snapshots) {
        Some(s) => (
            s.request["operation"].clone(),
            s.attempts.last().ok_or(Failure::Integrity)?["attempt"].clone(),
        ),
        None => (
            json!(format!("infra-operation-{}", super::session::fresh()?)),
            json!(super::session::fresh()?),
        ),
    };
    let owner_id = match &owner {
        Some(owner) => owner["owner"].clone(),
        None => json!(super::session::fresh()?),
    };
    let mut declared = Vec::new();
    for m in &context.selected.declaration.members {
        let mut member = context.widest_member(&m.machine)?;
        member["node_uid"] = Value::Null;
        declared.push(member);
    }
    let participants = match &owner {
        Some(o) => o["participants_sha256"].clone(),
        None => json!(super::participants(&json!(declared))?),
    };
    let mut summaries: Vec<_> = snapshots.iter().map(report::summary).collect();
    summaries.sort_by(|a, b| {
        b["created_ms"]
            .as_u64()
            .cmp(&a["created_ms"].as_u64())
            .then_with(|| a["operation"].as_str().cmp(&b["operation"].as_str()))
    });
    let mut latest = BTreeMap::new();
    for snapshot in &snapshots {
        let action = snapshot.request["action"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        let subject = snapshot
            .observations
            .iter()
            .find_map(|o| {
                let key = match o["event"]["type"].as_str()? {
                    "issuer-recipe" => "issuer",
                    "certificate-recipe" => "certificate",
                    "server-join-recipe" | "agent-join-recipe" => "member",
                    _ => return None,
                };
                let subject = &o["event"]["recipe"][key];
                Some(if key == "member" {
                    subject["member"].clone()
                } else {
                    subject.clone()
                })
            })
            .unwrap_or(Value::Null);
        let key = (action, canonical(&subject)?);
        let replace = latest
            .get(&key)
            .is_none_or(|old: &&Snapshot| record_order(snapshot, old).is_lt());
        if replace {
            latest.insert(key, snapshot);
        }
    }
    let mut stages = Vec::new();
    for ((action, subject), snapshot) in latest {
        let mut subject: Value =
            serde_json::from_slice(&subject).map_err(|_| Failure::Integrity)?;
        let stage = match action.as_str() {
            "prepare-hosts" => "hosts",
            "create-server" => {
                subject = snapshot.request["members"][0]["member"].clone();
                "first-server"
            }
            "prepare-state"
                if snapshot.request["consumer"]["action"] == "supply-initial-server" =>
            {
                "first-server"
            }
            "join-server" => "servers",
            "join-agent" => "agents",
            "reconcile-network" => "network",
            "reconcile-ingress" => "ingress",
            "reconcile-cert-manager" => "cert-manager",
            "reconcile-issuer" => "issuers",
            "reconcile-certificate" => "certificates",
            "prepare-node-registry" | "configure-node-registries" => "node-registries",
            "reconcile-registry-replication" => "registry-replication",
            a if a.starts_with("reconcile-registry-") => "registry",
            _ => continue,
        };
        stages.push(json!({"stage":stage,"action":action,"subject":subject,"operation":snapshot.request["operation"],"outcome":report::summary(snapshot)["outcome"],
            "readiness":call_readiness(snapshot)?,"recorded_ms":snapshot.observations.last().map(|o| &o["recorded_ms"])}));
    }
    preview["recorded"] = json!({"operations":summaries,"stages":stages,
        "owner":owner.as_ref().map(|o| &o["owner"]),"cluster":owner.as_ref().map(|o| &o["cluster"]),
        "members":owner.as_ref().map(|o| &o["members"])});
    let mut live = Vec::new();
    let mut complete = true;
    for (i, m) in context.selected.declaration.members.iter().enumerate() {
        let single = rpc::Context::new(
            context.project,
            issuer::duplicate(&context.policy)?,
            context.scope["target"].as_str().ok_or(Failure::Integrity)?,
        )?;
        let mut row = json!({"member":m.name,"machine":m.machine,"state":"unreachable","owner":null,
            "active_attempt":null,"identity":null,"failure":null,"completion_unknown":false,"cleanup_unknown":false});
        let recipient = match &owner {
            Some(owner) => owner["members"]
                .as_array()
                .and_then(|members| members.iter().find(|member| member["machine"] == m.machine))
                .cloned(),
            None => {
                let end =
                    Instant::now() + Duration::from_secs(single.selected.step_timeout.seconds);
                match single.connect_bootstrap(&m.machine, end, None).await {
                    Ok(connection) => {
                        let member = single.member(&m.machine, &connection, Value::Null);
                        let closed = connection.close_observation().await;
                        if closed.failure.is_none()
                            && !closed.possible_staging_residue
                            && !closed.unresolved_input
                        {
                            member.ok()
                        } else {
                            row["cleanup_unknown"] = json!(true);
                            None
                        }
                    }
                    Err(failed) => {
                        row["cleanup_unknown"] =
                            json!(failed.possible_staging_residue || failed.unresolved_input);
                        None
                    }
                }
            }
        };
        let Some(recipient) = recipient else {
            if owner.is_some() {
                row["state"] = json!("refused");
            }
            row["failure"] = json!(if owner.is_some() {
                "ownership"
            } else {
                "transport"
            });
            complete = false;
            live.push(row);
            continue;
        };
        let binding = json!({"scope":context.scope,"owner":owner_id,"operation":operation,"attempt":attempt,
            "step":1,"dispatch":super::session::fresh()?,"recipient":recipient,"receiver_generation":0,
            "request_sha256":projection_hash,"participants_sha256":participants,"fingerprints":single.fingerprints});
        for subject in ["owner", "identity"] {
            let mut binding = binding.clone();
            binding["dispatch"] = json!(super::session::fresh()?);
            let observed = single
                .invoke(
                    &binding,
                    "inspect",
                    json!({"subject":subject,"dispatch":null,"resource":null}),
                    Instant::now() + Duration::from_secs(single.selected.step_timeout.seconds),
                )
                .await;
            row["cleanup_unknown"] = json!(
                observed.transport["input_released"] != true
                    || observed.transport["staging_cleanup"] != "clean"
            );
            if let Some(failure) = observed.failure {
                row["failure"] = json!(failure.name());
                complete = false;
                break;
            }
            let reply = observed.response.ok_or(Failure::Integrity)?;
            match (subject, reply["status"].as_str()) {
                ("owner", Some("absent")) => {
                    row["state"] = json!("unclaimed");
                    break;
                }
                ("owner", Some("ok")) => {
                    row["state"] = json!("claimed");
                    row["owner"] = reply["data"]["claim"]["owner"].clone();
                    row["active_attempt"] = reply["data"]["claim"]["active_attempt"].clone();
                }
                ("identity", Some("ok")) => row["identity"] = reply["data"]["identity"].clone(),
                _ => {
                    if subject == "owner" {
                        row["state"] = json!(if reply["status"] == "busy" {
                            "busy"
                        } else {
                            "refused"
                        });
                    }
                    row["failure"] = reply["data"]["failure"].clone();
                    complete = false;
                    break;
                }
            }
        }
        debug_assert_eq!(live.len(), i);
        live.push(row);
    }
    preview["observed"] = json!(true);
    preview["live"] = json!(live);
    Ok((preview, complete))
}

pub(in crate::k3s) fn interrupt(stop: &CancellationToken, active: &CancellationToken) -> bool {
    if stop.is_cancelled() {
        active.cancel();
        false
    } else {
        stop.cancel();
        true
    }
}

async fn invoke(
    context: &rpc::Context<'_>,
    stage: &Stage,
    call: Call,
) -> super::ExecutionResult<Option<Snapshot>> {
    let project = context.project;
    let target = context.scope["target"].as_str().ok_or(Failure::Integrity)?;
    let mut policy = issuer::duplicate(&context.policy)?;
    policy.deadline =
        Instant::now() + Duration::from_secs(context.selected.operation_timeout.seconds);
    let first = &context.selected.declaration.members[0].machine;
    let subject = stage.subject.as_deref().unwrap_or("");
    Ok(Some(match call.action {
        "prepare_hosts" => Box::pin(super::prepare_hosts(project, policy, target)).await?,
        "prepare_initial_input" => {
            Box::pin(super::prepare_initial_input(project, policy, target, first)).await?
        }
        "create_first_server" => {
            Box::pin(super::create_first_server(project, policy, target)).await?
        }
        "join_server" => {
            Box::pin(super::join_server(
                project,
                policy,
                target,
                &context.selected.declaration.members[stage.members[0]].machine,
                first,
            ))
            .await?
        }
        "join_agents" => {
            let agents: Vec<_> = stage
                .members
                .iter()
                .map(|&i| context.selected.declaration.members[i].machine.clone())
                .collect();
            Box::pin(super::join_agents(
                project,
                policy,
                target,
                first,
                &agents,
                context.selected.agent_wave_size,
            ))
            .await?
        }
        "rebind_declaration" => {
            Box::pin(super::member::rebind_declaration(project, policy, target)).await?
        }
        "reconcile_network" => Box::pin(super::reconcile_network(project, policy, target)).await?,
        "reconcile_ingress" => Box::pin(super::reconcile_ingress(project, policy, target)).await?,
        "reconcile_cert_manager" => {
            Box::pin(super::reconcile_cert_manager(project, policy, target)).await?
        }
        "reconcile_issuer" => {
            Box::pin(super::reconcile_issuer(project, policy, target, subject)).await?
        }
        "reconcile_certificate" => {
            Box::pin(super::reconcile_certificate(
                project, policy, target, subject,
            ))
            .await?
        }
        "reconcile_registry_storage" => {
            Box::pin(super::reconcile_registry_storage(project, policy, target)).await?
        }
        "reconcile_registry_service" => {
            Box::pin(super::reconcile_registry_service(project, policy, target)).await?
        }
        "reconcile_registry_endpoint" => {
            Box::pin(super::reconcile_registry_endpoint(project, policy, target)).await?
        }
        "reconcile_registry_auth" => {
            Box::pin(super::reconcile_registry_auth(project, policy, target)).await?
        }
        "reconcile_registry_token" => {
            Box::pin(super::reconcile_registry_token(project, policy, target)).await?
        }
        "reconcile_registry_replication" => {
            Box::pin(super::reconcile_registry_replication(
                project, policy, target,
            ))
            .await?
        }
        "reconcile_registry_principals" => {
            Box::pin(super::reconcile_registry_principals(
                project, policy, target,
            ))
            .await?
        }
        "change_registry_principal" => {
            Box::pin(super::change_registry_principal(
                project, policy, target, subject,
            ))
            .await?
        }
        "change_node_registry" => {
            return Box::pin(super::change_node_registry(
                project, policy, target, subject,
            ))
            .await;
        }
        "node_registries" => {
            return Box::pin(super::node_registries(project, policy, target)).await;
        }
        _ => return Err(Failure::Capability.into()),
    }))
}

fn call_readiness(snapshot: &Snapshot) -> Result<Value> {
    let mut readiness = report::report(
        &snapshot.request["scope"],
        "show",
        std::slice::from_ref(snapshot),
    )?["readiness"]
        .clone();
    if matches!(
        snapshot.request["action"].as_str(),
        Some("create-server" | "join-server" | "join-agent")
    ) {
        let machine = if snapshot.request["action"] == "create-server" {
            &snapshot.request["members"][0]["machine"]
        } else {
            let Some(recipe) = snapshot.observations.iter().find(|o| {
                matches!(
                    o["event"]["type"].as_str(),
                    Some("server-join-recipe" | "agent-join-recipe")
                )
            }) else {
                return Ok(readiness);
            };
            &recipe["event"]["recipe"]["member"]["machine"]
        };
        if let Some(observation) = snapshot.observations.iter().rev().find(|o| {
            o["event"]["type"] == "lifecycle-installation"
                && o["event"]["member"]["machine"] == *machine
                && o["event"]["readiness"].is_object()
        }) {
            readiness = observation["event"]["readiness"].clone();
        }
    }
    Ok(readiness)
}

fn token_stage(snapshot: &Snapshot) -> Option<&str> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "registry-token-recipe")?["event"]["recipe"]["stage"]
        .as_str()
}

fn reached(call: Call, snapshot: Option<&Snapshot>, readiness: &Value) -> bool {
    let observed = |kind| {
        snapshot.is_some_and(|s| {
            s.observations.iter().any(|o| {
                o["source"]["kind"] == "receiver"
                    && o["event"]["type"] == kind
                    && !o["event"]["services"].is_null()
            })
        })
    };
    match call.ceiling {
        Ceiling::None => {
            call.action != "create_first_server"
                || ["api", "quorum", "nodes"]
                    .iter()
                    .all(|k| readiness[k] == "ready")
        }
        Ceiling::Network => {
            observed("network-observation")
                && readiness["services"] == "unobserved"
                && readiness["storage"] == "unobserved"
        }
        Ceiling::ServiceUnobserved => {
            readiness["services"] == "unobserved"
                && observed(match call.action {
                    "reconcile_ingress" => "ingress-observation",
                    "reconcile_cert_manager" => "cert-manager-observation",
                    _ => "issuer-observation",
                })
        }
        Ceiling::Certificate => readiness["services"] == "ready",
        Ceiling::RegistryService => readiness["services"] == "ready",
        Ceiling::Replication => readiness["services"] == "ready" && readiness["storage"] == "ready",
        Ceiling::Publication => {
            readiness["services"] == "ready" && readiness["publication"] == "unobserved"
        }
        Ceiling::Grants => {
            readiness["services"] == "ready"
                && readiness["publication"] == "unobserved"
                && snapshot.is_some_and(|s| token_stage(s) == Some("observe"))
        }
        Ceiling::Switch => snapshot
            .is_some_and(|s| matches!(token_stage(s), Some("switch" | "principals" | "observe"))),
    }
}

fn recovery(
    failure: Failure,
    unknown: bool,
    action: Option<&str>,
    operation: Value,
    credential: Option<&str>,
    full: bool,
    settled: bool,
) -> Value {
    let choice = if unknown {
        if action == Some("prepare-state") && operation.is_string() {
            "resume"
        } else {
            "operator-recovery"
        }
    } else if credential.is_some() {
        "credential-change"
    } else if (failure == Failure::Ownership && !settled) || full {
        "operator-recovery"
    } else {
        "rerun"
    };
    json!({"choice":choice,"operation":operation,"subject":credential})
}

pub(super) fn recorded_failure(value: &Value) -> Failure {
    [
        Failure::Configuration,
        Failure::Capability,
        Failure::Credential,
        Failure::Authentication,
        Failure::Trust,
        Failure::Ownership,
        Failure::Integrity,
        Failure::Storage,
        Failure::Transport,
        Failure::Readiness,
        Failure::Timeout,
        Failure::Cancelled,
        Failure::Bound,
        Failure::UnsupportedVersion,
        Failure::Busy,
    ]
    .into_iter()
    .find(|f| value == f.name())
    .unwrap_or(Failure::Integrity)
}

fn changed_registry(context: &rpc::Context<'_>, known: &[Snapshot]) -> Result<Option<String>> {
    let owner = &known.last().ok_or(Failure::Integrity)?.owner;
    let inputs = super::node_registry::inputs(context, known, owner, &[])?;
    let completed =
        super::node_registry::configured(known, &|s| report::summary(s)["outcome"] == "succeeded");
    for (member, entries) in inputs.entries {
        let mut prior: Vec<_> = known
            .iter()
            .filter_map(|s| {
                let recipe = &s
                    .observations
                    .iter()
                    .find(|o| o["event"]["type"] == "restart-recipe")?["event"]["recipe"];
                (recipe["member"]["member"] == member
                    && recipe["plan_sha256"]
                        .as_str()
                        .is_some_and(|p| completed.contains(p)))
                .then_some((s, recipe))
            })
            .collect();
        prior.sort_by(|a, b| record_order(a.0, b.0));
        if let Some((_, recipe)) = prior.first() {
            for entry in entries.as_array().ok_or(Failure::Integrity)? {
                if !recipe["registries"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .contains(entry)
                {
                    return Ok(entry["registry"].as_str().map(str::to_owned));
                }
            }
        }
    }
    Ok(None)
}

fn settling_retry(
    action: &str,
    call: Call,
    failure: Option<Failure>,
    snapshot: bool,
    detail: Option<&str>,
) -> bool {
    action == "create"
        && call.action == "reconcile_network"
        && failure == Some(Failure::Readiness)
        && !snapshot
        && detail == Some("settling")
}

fn wait_end(
    now: Instant,
    began: Instant,
    bound: Duration,
    interval: u64,
    deadline: Instant,
) -> Option<Instant> {
    let end = began + bound;
    (now < end && now < deadline)
        .then(|| (now + Duration::from_secs(interval)).min(end).min(deadline))
}

pub(super) fn selected_plan(
    context: &rpc::Context<'_>,
    action: &str,
    consumer: Option<&str>,
) -> Result<Value> {
    preview(context, action, consumer)
}

pub(super) async fn selected_observe(
    context: &rpc::Context<'_>,
    plan: Value,
) -> super::ExecutionResult<(Value, bool)> {
    observe(context, plan).await
}

pub(super) fn workflow(
    context: &rpc::Context<'_>,
    action: &str,
    member: Option<&str>,
) -> Result<Value> {
    let mut wave = Vec::new();
    for stage in stages(context, action, member)? {
        let hosts: Vec<&str> = stage
            .members
            .iter()
            .map(|&i| context.selected.declaration.members[i].machine.as_str())
            .collect();
        for call in stage.calls() {
            wave.push(json!({"action": call.action, "hosts": hosts}));
        }
    }
    Ok(json!({"waves": [wave]}))
}

pub(super) async fn selected_run(
    context: &rpc::Context<'_>,
    action: &str,
    consumer: Option<&str>,
    stop: CancellationToken,
) -> Result<(Value, bool)> {
    let selected = stages(context, action, consumer)?;
    execute_calls(context, action, stop, selected, |stage, call| async move {
        invoke(context, &stage, call).await
    })
    .await
}

pub(super) async fn replace_sequence(
    context: &rpc::Context<'_>,
    member: &str,
    approve: &str,
    stop: CancellationToken,
) -> Result<(Value, bool)> {
    let (owner, previous) = records(context).await.map_err(|e| e.failure)?;
    let owner = owner.ok_or(Failure::Ownership)?;
    let position = super::member::position(context, &previous, &owner, member)?;
    let target = context.selected.declaration;
    let index = target
        .members
        .iter()
        .position(|m| m.name == member)
        .ok_or(Failure::Configuration)?;
    let all: Vec<usize> = (0..target.members.len()).collect();
    let mut selected = Vec::new();
    let mut add = |name, members| {
        selected.push(Stage {
            name,
            subject: Some(member.to_owned()),
            members,
        })
    };
    if position.begun.is_none() {
        add("replace-begin", all.clone());
    }
    if !position.prepared {
        add("replace-hosts", vec![index]);
    }
    if position.joined.is_none() {
        if !target.node_registries.is_empty() {
            add("replace-supply", vec![index]);
        }
        add("replace-join", vec![index]);
    }
    let mut stages: Vec<Stage> = stages(context, "reconcile", None)?;
    if let Some(joined) = position.joined {
        let mut after: Vec<&Snapshot> = previous
            .iter()
            .filter(|s| {
                s.request["sequence"].as_u64() > Some(joined)
                    && report::summary(s)["outcome"] == "succeeded"
            })
            .collect();
        after.sort_by_key(|s| s.request["sequence"].as_u64());
        let mut next = 0;
        let mut done = 0;
        'stages: for stage in &stages {
            for call in stage.calls() {
                let action = call.action.replace('_', "-");
                match after[next..]
                    .iter()
                    .position(|s| s.request["action"] == action.as_str())
                {
                    Some(found) => next += found + 1,
                    None => break 'stages,
                }
            }
            done += 1;
        }
        stages.drain(..done);
    }
    selected.extend(stages);
    selected.push(Stage {
        name: "replace-complete",
        subject: Some(member.to_owned()),
        members: all,
    });
    let project = context.project;
    let name = context.scope["target"].as_str().ok_or(Failure::Integrity)?;
    execute_calls(
        context,
        "node-replace",
        stop,
        selected,
        |stage, call| async move {
            let mut policy = issuer::duplicate(&context.policy)?;
            policy.deadline =
                Instant::now() + Duration::from_secs(context.selected.operation_timeout.seconds);
            match call.action {
                "replace_begin" => Ok(Some(
                    Box::pin(super::member::replacement_begin(
                        project, policy, name, member, approve,
                    ))
                    .await?,
                )),
                "prepare_replacement_host" => Ok(Some(
                    Box::pin(super::bootstrap::prepare_replacement(
                        project, policy, name, member,
                    ))
                    .await?,
                )),
                "supply_replacement" => {
                    Box::pin(super::node_registry::supply_replacement(
                        project, policy, name, member,
                    ))
                    .await
                }
                "join_replacement" => Ok(Some(
                    Box::pin(super::member::join_replacement(
                        project, policy, name, member,
                    ))
                    .await?,
                )),
                "replace_complete" => Ok(Some(
                    Box::pin(super::member::replacement_complete(
                        project, policy, name, member,
                    ))
                    .await?,
                )),
                _ => invoke(context, &stage, call).await,
            }
        },
    )
    .await
}

async fn execute(
    context: &rpc::Context<'_>,
    action: &str,
    stop: CancellationToken,
) -> Result<(Value, bool)> {
    let selected = stages(context, action, None)?;
    execute_calls(context, action, stop, selected, |stage, call| async move {
        invoke(context, &stage, call).await
    })
    .await
}

async fn execute_calls<F, Fut>(
    context: &rpc::Context<'_>,
    action: &str,
    stop: CancellationToken,
    mut selected: Vec<Stage>,
    mut invoke: F,
) -> Result<(Value, bool)>
where
    F: FnMut(Stage, Call) -> Fut,
    Fut: std::future::Future<Output = super::ExecutionResult<Option<Snapshot>>>,
{
    let intended = preview_stages(context, action, &selected)?;
    let row = |stage: &Stage| {
        json!({"stage":stage.public_name(),"subject":stage.subject,"operations":[],"calls":[],
            "members":stage.members.iter().map(|&i| json!({"member":context.selected.declaration.members[i].name,
                "outcome":"not-run","operation":null})).collect::<Vec<_>>(),
            "outcome":"not-run","readiness":null,"failure":null,"detail":null,"waited_ms":0})
    };
    let rows: Vec<Value> = selected.iter().map(row).collect();
    let mut output = json!({"format_version":1,"scope":context.scope,"view":action,"action":action,
        "members":intended["members"],"stages_requested":selected.iter().map(|s| json!({"stage":s.public_name(),"subject":s.subject})).collect::<Vec<_>>(),
        "resources":intended["stages"].as_array().ok_or(Failure::Integrity)?.iter().flat_map(|s| s["resources"].as_array().into_iter().flatten().cloned()).collect::<Vec<_>>(),
        "stages":rows,"operations":[],"recorded":0,"possibly_recorded":[],"outcome":"succeeded","failure":null,"detail":null,
        "completion_unknown":false,"cleanup_unknown":false,"stopped":null,"truncated":false,
        "recovery":{"choice":"none","operation":null,"subject":null}});
    report::render(&output, false)?;
    let initial = records(context).await;
    let (owner, previous) = match initial {
        Ok(records) => records,
        Err(failure) => {
            output["outcome"] = json!("refused");
            output["failure"] = json!(failure.failure.name());
            output["completion_unknown"] = json!(failure.completion_unknown);
            output["cleanup_unknown"] = json!(failure.cleanup_unknown);
            output["stopped"] = json!({"stage":selected.first().map(Stage::public_name),"subject":selected.first().and_then(|s|s.subject.as_ref())});
            if !selected.is_empty() {
                output["stages"][0]["outcome"] = json!("refused");
                output["stages"][0]["failure"] = output["failure"].clone();
            }
            output["recovery"] = recovery(
                failure.failure,
                failure.completion_unknown || failure.cleanup_unknown,
                None,
                Value::Null,
                None,
                false,
                false,
            );
            return Ok((output, false));
        }
    };
    if action != "create" && owner.as_ref().is_none_or(|o| o["cluster"].is_null()) {
        output["outcome"] = json!("refused");
        output["failure"] = json!("readiness");
        output["stopped"] =
            json!({"stage":selected.first().map(Stage::public_name),"subject":null});
        if !selected.is_empty() {
            output["stages"][0]["outcome"] = json!("refused");
            output["stages"][0]["failure"] = json!("readiness");
        }
        output["recovery"] = json!({"choice":"create","operation":null,"subject":null});
        return Ok((output, false));
    }
    if action == "create" && owner.as_ref().is_some_and(|o| o["maintained"] == true) {
        output["outcome"] = json!("refused");
        output["failure"] = json!("configuration");
        output["detail"] = json!("maintained");
        output["stopped"] =
            json!({"stage":selected.first().map(Stage::public_name),"subject":null});
        if !selected.is_empty() {
            output["stages"][0]["outcome"] = json!("refused");
            output["stages"][0]["failure"] = json!("configuration");
            output["stages"][0]["detail"] = json!("maintained");
        }
        output["recovery"] = json!({"choice":"rerun","operation":null,"subject":null});
        return Ok((output, false));
    }
    if let Some(owner) = owner.as_ref().filter(|o| !o["cluster"].is_null()) {
        if action == "reconcile"
            && owner["fingerprints"]["config_sha256"] != context.owner_fingerprints["config_sha256"]
        {
            if super::member::deleted_agents(context, &previous, owner)
                .ok()
                .flatten()
                .is_some()
            {
                let stage = Stage {
                    name: "declaration",
                    subject: None,
                    members: Vec::new(),
                };
                output["stages"]
                    .as_array_mut()
                    .ok_or(Failure::Integrity)?
                    .insert(0, row(&stage));
                output["stages_requested"]
                    .as_array_mut()
                    .ok_or(Failure::Integrity)?
                    .insert(0, json!({"stage":stage.public_name(),"subject":null}));
                selected.insert(0, stage);
            } else if let Some(member) = super::member::transition_of(context, &previous, owner)
                .ok()
                .flatten()
            {
                output["outcome"] = json!("refused");
                output["failure"] = json!("configuration");
                output["stopped"] =
                    json!({"stage":selected.first().map(Stage::public_name),"subject":null});
                if !selected.is_empty() {
                    output["stages"][0]["outcome"] = json!("refused");
                    output["stages"][0]["failure"] = json!("configuration");
                }
                output["recovery"] = json!({"choice":"replace","operation":null,"subject":member});
                return Ok((output, false));
            }
        }
        let removed: Vec<Value> = owner["removed"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| r["member"].clone())
            .collect();
        for stage in output["stages"].as_array_mut().ok_or(Failure::Integrity)? {
            let members = stage["members"].as_array_mut().ok_or(Failure::Integrity)?;
            for name in &removed {
                match members.iter_mut().find(|m| m["member"] == *name) {
                    Some(member) => member["outcome"] = json!("skipped"),
                    None => {
                        members.push(json!({"member":name,"outcome":"skipped","operation":null}))
                    }
                }
            }
        }
    }
    let input_needed = owner.as_ref().is_none_or(|o| o["cluster"].is_null())
        && !previous.iter().any(|s| {
            s.request["action"] == "prepare-state"
                && s.request["consumer"]["action"] == "supply-initial-server"
                && report::summary(s)["outcome"] == "succeeded"
        });
    let mut operations = 0u64;
    let mut attempts = BTreeMap::<String, u64>::new();
    for stage in &selected {
        let calls = stage
            .calls()
            .iter()
            .filter(|call| call.action != "prepare_initial_input" || input_needed)
            .count() as u64;
        operations += calls;
        for &member in &stage.members {
            *attempts
                .entry(context.selected.declaration.members[member].machine.clone())
                .or_default() += calls;
        }
    }
    let target = context.scope["target"].as_str().unwrap_or("");
    if super::history::capacity(target, action, &previous, operations, &attempts).is_some() {
        output["outcome"] = json!("refused");
        output["failure"] = json!("bound");
        output["detail"] = json!("store-full");
        output["stopped"] =
            json!({"stage":selected.first().map(Stage::public_name),"subject":null});
        if !selected.is_empty() {
            output["stages"][0]["outcome"] = json!("refused");
            output["stages"][0]["failure"] = json!("bound");
            output["stages"][0]["detail"] = json!("store-full");
        }
        output["recovery"] = json!({"choice":"rerun","operation":null,
            "subject":format!("k3s plan {target} --action operation-prune --observe")});
        return Ok((output, false));
    }
    let deadline = context.policy.deadline;
    let mut known = previous;
    let mut operation_positions = BTreeMap::<String, usize>::new();
    let mut publications = std::collections::BTreeSet::new();
    for (index, stage) in selected.iter().enumerate() {
        let mut call_number = 0;
        for call in stage.calls() {
            if call.action == "prepare_initial_input" && !input_needed {
                continue;
            }
            let began = Instant::now();
            let mut interval = 10u64;
            loop {
                let stopped = stop.is_cancelled();
                if stopped || Instant::now() >= deadline {
                    let failure = if stopped {
                        Failure::Cancelled
                    } else {
                        Failure::Timeout
                    };
                    output["stages"][index]["outcome"] =
                        json!(if stopped { "cancelled" } else { "waiting" });
                    output["failure"] = json!(failure.name());
                    output["recovery"] =
                        recovery(failure, false, None, Value::Null, None, false, false);
                    break;
                }
                let receipts = Receipts::default();
                let result = RECEIPTS
                    .scope(receipts.clone(), invoke(stage.clone(), call))
                    .await;
                let returned = match &result {
                    Ok(s) => s.as_ref(),
                    Err(e) => e.snapshot.as_deref(),
                };
                let snapshot = returned.filter(|s| receipts.owns(s));
                if let Some(snapshot) = snapshot {
                    receipts.capture(std::slice::from_ref(snapshot));
                }
                let captured = receipts.take()?;
                if let Some(snapshot) = snapshot {
                    known.retain(|s| s.request["operation"] != snapshot.request["operation"]);
                    known.push(snapshot.clone());
                }
                call_number += 1;
                let mut evidence = Vec::new();
                let mut unknown = result.is_ok() && returned.is_some() && snapshot.is_none();
                let mut cleanup = false;
                let mut settled_failure = None;
                let mut last_action = None;
                let mut last_operation = Value::Null;
                let mut last_readiness = Value::Null;
                let member_action = match stage.name {
                    "hosts" => "prepare-hosts",
                    "first-server" => "create-server",
                    "servers" => "join-server",
                    "agents" => "join-agent",
                    "node-registries" | "node-registry-change" => "configure-node-registries",
                    _ => "",
                };
                let mut member_evidence = Vec::new();
                for (facts, summary) in captured {
                    let operation = facts["operation"]
                        .as_str()
                        .ok_or(Failure::Integrity)?
                        .to_owned();
                    publications.insert(operation.clone());
                    require(publications.len() <= 1024, Failure::Bound)?;
                    last_operation = facts["operation"].clone();
                    last_readiness = facts["readiness"].clone();
                    last_action = summary
                        .as_ref()
                        .and_then(|s| s["action"].as_str())
                        .or((call.action == "prepare_initial_input").then_some("prepare-state"))
                        .map(str::to_owned);
                    if !output["stages"][index]["operations"]
                        .as_array()
                        .ok_or(Failure::Integrity)?
                        .contains(&json!(operation))
                    {
                        output["stages"][index]["operations"]
                            .as_array_mut()
                            .ok_or(Failure::Integrity)?
                            .push(json!(operation));
                    }
                    let uncertain = facts["publication"] != "durable" || summary.is_none();
                    unknown |= uncertain;
                    if uncertain
                        && !output["possibly_recorded"]
                            .as_array()
                            .ok_or(Failure::Integrity)?
                            .contains(&json!(operation))
                    {
                        output["possibly_recorded"]
                            .as_array_mut()
                            .ok_or(Failure::Integrity)?
                            .push(json!(operation));
                    }
                    if let Some(summary) = summary {
                        if summary["action"] == member_action && !uncertain {
                            member_evidence.push(facts.clone());
                        }
                        if matches!(facts["outcome"].as_str(), Some("failed" | "cancelled")) {
                            settled_failure = Some(recorded_failure(&summary["failure"]));
                        }
                        unknown |= summary["completion_unknown"] == true;
                        cleanup |= summary["cleanup_unknown"] == true;
                        if facts["publication"] == "durable" {
                            let position = match operation_positions.get(&operation) {
                                Some(&position) => position,
                                None => {
                                    let position = operation_positions.len();
                                    require(position < 1024, Failure::Bound)?;
                                    operation_positions.insert(operation, position);
                                    output["operations"]
                                        .as_array_mut()
                                        .ok_or(Failure::Integrity)?
                                        .push(Value::Null);
                                    position
                                }
                            };
                            output["operations"][position] = summary;
                        }
                    }
                    evidence.push(facts);
                }
                let readiness = snapshot
                    .map(call_readiness)
                    .transpose()?
                    .unwrap_or(last_readiness);
                let failure = result.as_ref().err().map(|e| e.failure).or(settled_failure);
                let detail = result.as_ref().err().and_then(|e| e.detail);
                unknown |= result.as_ref().err().is_some_and(|e| e.completion_unknown);
                cleanup |= result.as_ref().err().is_some_and(|e| e.cleanup_unknown);
                let call_outcome = if unknown || cleanup {
                    "unknown"
                } else if failure == Some(Failure::Cancelled) {
                    "cancelled"
                } else if failure.is_some() {
                    "failed"
                } else {
                    "succeeded"
                };
                output["stages"][index]["calls"].as_array_mut().ok_or(Failure::Integrity)?.push(json!({"call":call_number,
                    "action":call.action,"outcome":call_outcome,"failure":failure.map(Failure::name),"detail":detail,
                    "completion_unknown":unknown,"cleanup_unknown":cleanup,"evidence":evidence}));
                output["stages"][index]["readiness"] = readiness.clone();
                output["recorded"] = json!(operation_positions.len());
                output["completion_unknown"] =
                    json!(output["completion_unknown"] == true || unknown);
                output["cleanup_unknown"] = json!(output["cleanup_unknown"] == true || cleanup);
                let latest_operation = snapshot
                    .map(|s| s.request["operation"].clone())
                    .unwrap_or(last_operation);
                if unknown
                    && latest_operation.is_string()
                    && !output["possibly_recorded"]
                        .as_array()
                        .ok_or(Failure::Integrity)?
                        .contains(&latest_operation)
                {
                    output["possibly_recorded"]
                        .as_array_mut()
                        .ok_or(Failure::Integrity)?
                        .push(latest_operation.clone());
                }
                for (row, &member) in stage.members.iter().enumerate() {
                    if output["stages"][index]["members"][row]["outcome"] == "skipped" {
                        continue;
                    }
                    let name = &context.selected.declaration.members[member].name;
                    let observed = member_evidence.iter().rev().find_map(|e| {
                        e["members"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find(|m| {
                                m["member"]["member"] == name.as_str() && m["outcome"] != "pending"
                            })
                            .map(|m| (m["outcome"].clone(), e["operation"].clone()))
                    });
                    if let Some((outcome, operation)) = observed {
                        output["stages"][index]["members"][row]["outcome"] = outcome;
                        output["stages"][index]["members"][row]["operation"] = operation;
                    } else if result.is_ok()
                        && !unknown
                        && !cleanup
                        && failure.is_none()
                        && call.action == "node_registries"
                    {
                        output["stages"][index]["members"][row]["outcome"] = json!("succeeded");
                    } else if output["stages"][index]["members"][row]["outcome"] != "succeeded" {
                        output["stages"][index]["members"][row]["outcome"] =
                            json!(if unknown || cleanup {
                                "unknown"
                            } else if failure.is_some() {
                                "refused"
                            } else {
                                "pending"
                            });
                    }
                }
                let mut retry_switch = false;
                let mut full = known.len() >= 1024;
                let pending = if detail == Some("change_node_registry") {
                    changed_registry(context, &known)?
                } else {
                    None
                };
                let mut credential = detail.and_then(|d| d.strip_prefix("change_node_registry "));
                credential = credential.or(pending.as_deref());
                if failure.is_some()
                    && !unknown
                    && !cleanup
                    && snapshot.is_none()
                    && Instant::now() < deadline
                {
                    match records(context).await {
                        Err(_) => full = true,
                        Ok((_, history)) => {
                            full = history.len() >= 1024;
                            let owner = known.last().map(|s| s.owner.clone());
                            let history = &known;
                            let token: Vec<_> = history
                                .iter()
                                .filter(|s| s.request["action"] == "reconcile-registry-token")
                                .cloned()
                                .collect();
                            retry_switch = call.ceiling == Ceiling::Switch
                                && failure == Some(Failure::Readiness)
                                && newest(&token).is_some_and(|s| {
                                    report::summary(s)["outcome"] == "succeeded"
                                        && matches!(token_stage(s), Some("create" | "configure"))
                                });
                            if call.action == "reconcile_registry_principals"
                                && failure == Some(Failure::Ownership)
                            {
                                if let (Some(owner), Some(name)) = (owner, detail) {
                                    let id = registry_auth::principal_id(name, 1);
                                    let settled_failure = history.iter().any(|s| {
                                        matches!(
                                            report::summary(s)["outcome"].as_str(),
                                            Some("failed" | "cancelled")
                                        ) && s.request["resources"]
                                            .as_array()
                                            .is_some_and(|rs| rs.iter().any(|r| r["id"] == id))
                                    });
                                    if settled_failure
                                        && registry_auth::current(history, &owner, name, &|s| {
                                            report::summary(s)["outcome"] == "succeeded"
                                        })
                                        .is_ok_and(|v| v.is_none())
                                    {
                                        credential = Some(name);
                                    }
                                }
                            }
                        }
                    }
                }
                let retry_settling = !unknown
                    && !cleanup
                    && settling_retry(action, call, failure, returned.is_some(), detail);
                let retry = retry_switch || retry_settling;
                if (failure.is_some() && !retry) || unknown || cleanup {
                    let failed = failure.unwrap_or(Failure::Readiness);
                    output["stages"][index]["outcome"] = json!(call_outcome);
                    output["failure"] = json!(failed.name());
                    output["detail"] = json!(detail);
                    output["recovery"] = recovery(
                        failed,
                        unknown || cleanup,
                        last_action.as_deref(),
                        latest_operation,
                        credential,
                        full,
                        settled_failure.is_some(),
                    );
                    break;
                }
                report::render(&output, false)?;
                let end = began + Duration::from_secs(call.seconds);
                if !retry
                    && reached(call, snapshot, &readiness)
                    && (call.seconds == 0 || Instant::now() < end)
                {
                    break;
                }
                if call.seconds == 0 || Instant::now() >= end {
                    output["stages"][index]["outcome"] = json!("waiting");
                    output["failure"] = json!("readiness");
                    if retry_settling {
                        output["detail"] = json!("settling");
                    }
                    output["recovery"] = recovery(
                        Failure::Readiness,
                        false,
                        None,
                        Value::Null,
                        None,
                        false,
                        false,
                    );
                    break;
                }
                let before = Instant::now();
                let until = wait_end(
                    before,
                    began,
                    Duration::from_secs(call.seconds),
                    interval,
                    deadline,
                )
                .unwrap_or(before);
                tokio::select! { _=stop.cancelled()=>{}, _=tokio::time::sleep_until(until)=>{} }
                let waited = output["stages"][index]["waited_ms"]
                    .as_u64()
                    .ok_or(Failure::Integrity)?;
                output["stages"][index]["waited_ms"] =
                    json!(waited.saturating_add(before.elapsed().as_millis() as u64));
                interval = (interval * 2).min(60);
                if Instant::now() >= end && !stop.is_cancelled() && Instant::now() < deadline {
                    output["stages"][index]["outcome"] = json!("waiting");
                    output["failure"] = json!("readiness");
                    if retry_settling {
                        output["detail"] = json!("settling");
                    }
                    output["recovery"] = recovery(
                        Failure::Readiness,
                        false,
                        None,
                        Value::Null,
                        None,
                        false,
                        false,
                    );
                    break;
                }
            }
            if !output["failure"].is_null() {
                output["stages"][index]["failure"] = output["failure"].clone();
                output["stages"][index]["detail"] = output["detail"].clone();
                output["outcome"] = output["stages"][index]["outcome"].clone();
                output["stopped"] = json!({"stage":stage.public_name(),"subject":stage.subject});
                return Ok((output, false));
            }
        }
        output["stages"][index]["outcome"] = json!("succeeded");
    }
    Ok((output, true))
}

tokio::task_local! {
    static RECEIPTS: Receipts;
}

#[derive(Clone, Default)]
pub(super) struct Receipts(Arc<Mutex<ReceiptState>>);

#[derive(Default)]
struct ReceiptState {
    entries: Vec<Receipt>,
    failure: Option<Failure>,
}

struct Receipt {
    scope: Value,
    operation: Value,
    attempt: Value,
    durable: bool,
    started: bool,
    captured: Option<(Value, Value)>,
}

impl Receipts {
    pub(super) fn current() -> Option<Self> {
        RECEIPTS.try_with(Clone::clone).ok()
    }

    fn owns(&self, snapshot: &Snapshot) -> bool {
        self.0.lock().is_ok_and(|s| {
            s.entries.iter().any(|r| {
                r.scope == snapshot.request["scope"]
                    && r.operation == snapshot.request["operation"]
                    && snapshot
                        .attempts
                        .last()
                        .is_some_and(|a| r.attempt == a["attempt"])
            })
        })
    }

    pub(super) fn publication(&self, scope: &Value, attempt: &Value, durable: bool) -> Result<()> {
        self.record(scope, attempt, durable, true)
    }

    pub(super) fn dispatched(&self, scope: &Value, attempt: &Value) -> Result<()> {
        self.record(scope, attempt, false, false)
    }

    pub(super) fn returned(&self, scope: &Value, attempt: &Value) {
        if let Ok(mut state) = self.0.lock() {
            state.entries.retain(|r| {
                r.started
                    || r.scope != *scope
                    || r.operation != attempt["operation"]
                    || r.attempt != attempt["attempt"]
            });
        }
    }

    fn record(&self, scope: &Value, attempt: &Value, durable: bool, started: bool) -> Result<()> {
        let mut state = self.0.lock().map_err(|_| Failure::Integrity)?;
        if let Some(entry) = state.entries.iter_mut().find(|r| {
            r.scope == *scope
                && r.operation == attempt["operation"]
                && r.attempt == attempt["attempt"]
        }) {
            entry.durable |= durable;
            entry.started |= started;
        } else {
            require(state.entries.len() < 1024 * 128, Failure::Bound)?;
            state.entries.push(Receipt {
                scope: scope.clone(),
                operation: attempt["operation"].clone(),
                attempt: attempt["attempt"].clone(),
                durable,
                started,
                captured: None,
            });
        }
        Ok(())
    }

    pub(super) fn capture(&self, snapshots: &[Snapshot]) {
        let Ok(mut state) = self.0.lock() else { return };
        let mut failure = None;
        for entry in &mut state.entries {
            if let Some(snapshot) = snapshots.iter().find(|s| {
                s.request["scope"] == entry.scope
                    && s.request["operation"] == entry.operation
                    && s.attempts
                        .last()
                        .is_some_and(|a| a["attempt"] == entry.attempt)
            }) {
                match attempt_evidence(snapshot, &entry.attempt) {
                    Ok(captured) => entry.captured = Some(captured),
                    Err(error) => failure = Some(error),
                }
            }
        }
        state.failure = state.failure.or(failure);
    }

    fn take(&self) -> Result<Vec<(Value, Option<Value>)>> {
        let mut state = self.0.lock().map_err(|_| Failure::Integrity)?;
        if let Some(error) = state.failure {
            return Err(error);
        }
        Ok(std::mem::take(&mut state.entries)
            .into_iter()
            .map(|entry| {
                let (mut evidence, summary) = match entry.captured {
                    Some((evidence, summary)) => (evidence, Some(summary)),
                    None => (
                        json!({"operation":entry.operation,"attempt":entry.attempt,
                    "outcome":null,"readiness":null,"members":[],"observations":[]}),
                        None,
                    ),
                };
                evidence["publication"] = json!(if entry.durable { "durable" } else { "possible" });
                (evidence, summary)
            })
            .collect())
    }
}

fn attempt_evidence(snapshot: &Snapshot, attempt: &Value) -> Result<(Value, Value)> {
    let mut current = snapshot.clone();
    current.attempts.retain(|a| a["attempt"] == *attempt);
    current.steps.retain(|s| s["attempt"] == *attempt);
    current.observations.retain(|o| o["attempt"] == *attempt);
    require(current.attempts.len() == 1, Failure::Integrity)?;
    let summary = report::summary(&current);
    let readiness = call_readiness(&current)?;
    let mut latest = BTreeMap::new();
    let mut observations = Vec::new();
    for observation in &current.observations {
        let event = &observation["event"];
        let kind = event["type"].as_str().unwrap_or("");
        let Some(step) = current
            .steps
            .iter()
            .find(|s| s["step"] == observation["step"] && s["dispatch"] == observation["dispatch"])
        else {
            continue;
        };
        let projected = json!({"sequence":observation["sequence"],"recorded_ms":observation["recorded_ms"],
            "source":observation["source"],"step":observation["step"],"dispatch":observation["dispatch"],"event":event});
        if kind == "dispatch" {
            observations.push(projected);
        } else if observation["source"]["kind"] == "receiver"
            && matches!(
                kind,
                "bootstrap-host"
                    | "lifecycle-installation"
                    | "server-membership"
                    | "agent-membership"
                    | "network-observation"
                    | "ingress-observation"
                    | "cert-manager-observation"
                    | "issuer-observation"
                    | "certificate-observation"
                    | "registry-storage-observation"
                    | "registry-service-observation"
                    | "registry-endpoint-observation"
                    | "registry-auth-observation"
                    | "registry-token-observation"
                    | "replication-observation"
                    | "node-observation"
            )
        {
            let key = canonical(&json!([
                kind,
                step["action"],
                observation["source"]["machine"],
                event["member"]
            ]))?;
            latest.insert(key, projected);
        }
    }
    observations.extend(latest.into_values());
    observations.sort_by_key(|o| o["sequence"].as_u64());
    let members: Vec<_> = current.request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .map(|member| {
            let steps: Vec<_> = current
                .steps
                .iter()
                .filter(|s| s["recipient"] == *member)
                .collect();
            let failed = current.observations.iter().any(|o| {
                steps.iter().any(|s| s["step"] == o["step"])
                    && o["event"]["type"] == "failure"
                    && o["event"]["outcome"] == "failed"
            });
            let member_observed = current
                .observations
                .iter()
                .rev()
                .find(|o| o["event"]["type"] == "agent-membership")
                .is_some_and(|o| {
                    o["event"]["view"]["members"]
                        .as_array()
                        .is_some_and(|members| {
                            members.iter().any(|m| {
                                m["member"]["machine"] == member["machine"]
                                    && m["present"] == true
                                    && m["ready"] == true
                            })
                        })
                });
            let configure_member = current
                .observations
                .iter()
                .find(|o| o["event"]["type"] == "restart-recipe")
                .map(|o| &o["event"]["recipe"]["member"]);
            let outcome = if current.request["action"] == "configure-node-registries"
                && configure_member != Some(member)
            {
                "pending"
            } else if failed {
                "failed"
            } else if summary["outcome"] == "succeeded"
                && (if current.request["action"] == "join-agent" {
                    member_observed
                } else {
                    !steps.is_empty() || member_observed
                })
            {
                "succeeded"
            } else if summary["outcome"] == "unknown" && !steps.is_empty() {
                "unknown"
            } else {
                "pending"
            };
            json!({"member":member,"outcome":outcome})
        })
        .collect();
    let evidence = json!({"operation":current.request["operation"],"attempt":attempt,
        "outcome":summary["outcome"],"readiness":readiness,"members":members,"observations":observations});
    report::render(&evidence, false)?;
    Ok((evidence, summary))
}

