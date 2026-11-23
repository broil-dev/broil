// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, Snapshot, canonical, hash, require, rpc};
use super::{
    cert_manager, certificate, converge, issuer, network, registry_auth, registry_endpoint,
    registry_replication, registry_service, registry_storage, registry_token, server, session,
};
use broil_config::LoadedProject;
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use tokio::time::Instant;

const INVENTORY: network::Family = network::Family {
    name: "node-view",
    protocol: "broil-k3s-node",
    magic: b"BK3SNOD1\n",
    header: "NodeViewHeader",
    result: "NodeViewResult",
    body: crate::k3s::NODE,
    planned: 0,
    reserve: 32768,
    version: 1,
};

pub(in crate::k3s) fn supported(verb: &str) -> bool {
    matches!(
        verb,
        "status" | "diagnose" | "nodes" | "workloads" | "services" | "registry inspect"
    )
}

pub(in crate::k3s) fn preflight(
    target: &broil_core::k3s::Target,
    verb: &str,
    component: Option<&str>,
) -> std::result::Result<(), crate::k3s::commands::Refusal> {
    require(
        (verb == "diagnose") == component.is_some()
            && component.is_none_or(|c| {
                matches!(
                    c,
                    "api"
                        | "datastore"
                        | "network"
                        | "dns"
                        | "storage"
                        | "ingress"
                        | "certificates"
                        | "registry"
                )
            }),
        Failure::Configuration,
    )?;
    let registry = verb == "registry inspect" || component == Some("registry");
    require(
        !registry || target.registry.is_some(),
        Failure::Configuration,
    )?;
    let selected = if verb == "status" || component == Some("certificates") {
        target
            .infrastructure
            .issuers
            .iter()
            .find(|(_, i)| issuer::acme(i))
    } else if registry {
        target
            .registry
            .as_ref()
            .and_then(|r| target.infrastructure.certificates.get(&r.certificate))
            .and_then(|c| target.infrastructure.issuers.get_key_value(&c.issuer))
            .filter(|(_, i)| issuer::acme(i))
    } else {
        None
    };
    if let Some((name, _)) = selected {
        return Err(crate::k3s::commands::Refusal {
            failure: Failure::Capability,
            boundary: Some("a later roadmap implements it"),
            detail: Some(name.clone()),
        });
    }
    Ok(())
}

struct Read {
    value: Value,
    time: Value,
    failure: Option<Failure>,
    transport: Value,
    cleanup: bool,
}

impl Read {
    fn unavailable(failure: Failure) -> Self {
        Self {
            value: Value::Null,
            time: Value::Null,
            failure: Some(failure),
            transport: Value::Null,
            cleanup: false,
        }
    }
    fn observed(observed: rpc::Observed) -> Self {
        let failure = observed.failure.or_else(|| {
            observed.response.as_ref().and_then(|v| {
                (!matches!(v["status"].as_str(), Some("ok" | "absent"))).then(|| {
                    server::refused(if v.get("failure").is_some() {
                        v
                    } else {
                        &v["data"]
                    })
                })
            })
        });
        let cleanup = network::unclean(&observed.transport);
        Self {
            value: observed.response.unwrap_or(Value::Null),
            time: json!(session::now().ok()),
            failure,
            transport: observed.transport,
            cleanup,
        }
    }
    fn nested(&self) -> Value {
        json!({"observed_ms":self.time,"failure":self.failure.map(Failure::name),
            "transport":self.transport,"cleanup_unknown":self.cleanup})
    }
}

struct Reader<'a> {
    context: rpc::Context<'a>,
    owner: Value,
    records: Vec<Snapshot>,
    view: String,
    component: Option<String>,
    limit: Option<usize>,
    failed: BTreeMap<String, Failure>,
    rows: Vec<Value>,
    truncated: bool,
}

fn select(value: &Value, fields: &[&str]) -> Value {
    Value::Object(
        fields
            .iter()
            .map(|key| ((*key).to_owned(), value[*key].clone()))
            .collect(),
    )
}

pub(super) fn read_member(original: &Value, current: &Value) -> bool {
    original == current
        || original["node_uid"].is_null()
            && ["machine", "member", "role", "route", "jump"]
                .iter()
                .all(|key| original[*key] == current[*key])
}

fn row(
    kind: &str,
    subject: Value,
    member: Value,
    facts: Value,
    readiness: Value,
    read: &Read,
) -> Value {
    json!({"kind":kind,"subject":subject,"member":member,"source":"live","observed_ms":read.time,
        "operation":null,"facts":facts,"readiness":readiness,
        "failure":read.failure.map(Failure::name),"transport":read.transport,"cleanup_unknown":read.cleanup})
}

impl Reader<'_> {
    fn deadline(&self) -> Instant {
        self.context.clock.deadline().min(
            Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds.min(30)),
        )
    }

    fn isolated(&self, member: &Value) -> Result<rpc::Context<'_>> {
        self.context.check()?;
        if let Some(failure) = self
            .failed
            .get(member["machine"].as_str().ok_or(Failure::Integrity)?)
        {
            return Err(*failure);
        }
        let context = rpc::Context::new(
            self.context.project,
            issuer::duplicate(&self.context.policy)?,
            self.context.scope["target"]
                .as_str()
                .ok_or(Failure::Integrity)?,
        )?;
        Ok(context)
    }

    fn binding(
        &self,
        snapshot: &Snapshot,
        member: &Value,
        recipe: Option<(&str, &Value)>,
        query: &str,
    ) -> Result<Value> {
        let attempt = &snapshot.attempts.last().ok_or(Failure::Integrity)?["attempt"];
        let step = snapshot
            .steps
            .iter()
            .filter(|s| s["attempt"] == *attempt)
            .filter_map(|s| s["step"].as_u64())
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Failure::Bound)?;
        require(step <= u32::MAX as u64, Failure::Bound)?;
        require(
            snapshot.request["scope"] == self.context.scope
                && snapshot.request["owner"] == self.owner["owner"]
                && snapshot.request["members"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|original| read_member(original, member))),
            Failure::Ownership,
        )?;
        let participants = match current_request(&snapshot.request, &self.owner)? {
            Some(current) => current["participants_sha256"].clone(),
            None => snapshot.request["participants_sha256"].clone(),
        };
        let projection = json!({"scope":self.context.scope,"view":self.view,"component":self.component,"limit":self.limit,
            "owner":self.owner["owner"],"cluster":self.owner["cluster"],"member":member,
            "source_operation":snapshot.request["operation"],"source_attempt":attempt,
            "recipe_sha256":recipe.map(|(domain,r)|hash(domain,r)).transpose()?,"query":query});
        Ok(
            json!({"scope":self.context.scope,"owner":self.owner["owner"],"operation":snapshot.request["operation"],
            "attempt":attempt,"step":step,"dispatch":session::fresh()?,"recipient":member,"receiver_generation":0,
            "request_sha256":hash("broil-infra-view-v1",&projection)?,"participants_sha256":participants,
            "fingerprints":self.context.fingerprints}),
        )
    }

    fn finish_read(&mut self, member: &Value, observed: rpc::Observed) -> Read {
        let terminal = observed.failure;
        let read = Read::observed(observed);
        if let Some(failure) = terminal {
            if let Some(machine) = member["machine"].as_str() {
                self.failed.insert(machine.to_owned(), failure);
            }
        }
        read
    }

    async fn family_read(
        &mut self,
        snapshot: &Snapshot,
        family: &network::Family,
        member: &Value,
        tag: &str,
        payload: Value,
        domain: &str,
    ) -> Read {
        if let Err(failure) = self.context.check() {
            return Read::unavailable(failure);
        }
        let prepared = self.binding(
            snapshot,
            member,
            Some((domain, &payload["recipe"])),
            &if family.name == "node-view" {
                format!("node:view:{}", payload["query"].as_str().unwrap_or(""))
            } else {
                format!("{}:{tag}", family.name)
            },
        );
        let binding = match prepared {
            Ok(v) => v,
            Err(f) => return Read::unavailable(f),
        };
        let observed = match self.isolated(member) {
            Ok(context) => {
                network::invoke(
                    &context,
                    family,
                    &binding,
                    tag,
                    &payload,
                    self.deadline(),
                    None,
                )
                .await
            }
            Err(f) => return Read::unavailable(f),
        };
        self.finish_read(member, observed)
    }

    async fn inventory(&mut self, query: &str, limit: usize) -> Read {
        if let Err(failure) = self.context.check() {
            return Read::unavailable(failure);
        }
        let Some(snapshot) = self.records.first().cloned() else {
            return Read::unavailable(Failure::Readiness);
        };
        let Some(member) = super::survivors(&self.owner)
            .ok()
            .and_then(|s| s.into_iter().next())
        else {
            return Read::unavailable(Failure::Integrity);
        };
        let recipe = json!({"scope":self.context.scope,"owner":self.owner["owner"],"operation":snapshot.request["operation"],
            "cluster":self.owner["cluster"],"member":member,"first_server":member,
            "version":self.context.selected.declaration.version,"profile_sha256":self.context.fingerprints["profile_sha256"]});
        let mut read = self
            .family_read(
                &snapshot,
                &INVENTORY,
                &member,
                "view",
                json!({"recipe":recipe,"query":query,"limit":limit}),
                "broil-k3s-node-view-recipe-v1",
            )
            .await;
        if !read.value.is_null() {
            if let Err(failure) = validate_inventory(query, limit, &read.value) {
                read.value = Value::Null;
                read.failure = Some(failure);
            }
        }
        self.truncated |= read.value["truncated"] == true;
        read
    }

    async fn state_read(&mut self, snapshot: &Snapshot, member: &Value, subject: &str) -> Read {
        if let Err(failure) = self.context.check() {
            return Read::unavailable(failure);
        }
        let binding =
            match self.binding(snapshot, member, None, &format!("state:inspect-{subject}")) {
                Ok(v) => v,
                Err(f) => return Read::unavailable(f),
            };
        let observed = match self.isolated(member) {
            Ok(context) => {
                context
                    .invoke(
                        &binding,
                        "inspect",
                        json!({"subject":subject,"dispatch":null,"resource":null}),
                        self.deadline(),
                    )
                    .await
            }
            Err(f) => return Read::unavailable(f),
        };
        self.finish_read(member, observed)
    }

    async fn members(&mut self, nodes: &Read) -> Result<()> {
        let members = self.owner["members"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let snapshot = self.records.first().ok_or(Failure::Readiness)?.clone();
        let removed = self.owner["removed"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for member in &members {
            if let Some(removal) = removed.iter().find(|r| r["member"] == member["member"]) {
                self.rows.push(removed_row(member, removal));
                continue;
            }
            let claim = self.state_read(&snapshot, member, "owner").await;
            let claimed = claim.failure.is_none() && claim.value["status"] == "ok";
            let identity = if claimed {
                self.state_read(&snapshot, member, "identity").await
            } else {
                Read::unavailable(claim.failure.unwrap_or(Failure::Readiness))
            };
            let (labels, taints) = network::declared(&self.context, member)?;
            self.rows.push(member_row(
                member,
                &self.owner["cluster"],
                &json!(self.context.selected.declaration.version),
                &labels,
                &taints,
                &claim,
                &identity,
                nodes,
            ));
        }
        let servers: Vec<&Value> = members.iter().filter(|m| m["role"] == "server").collect();
        let gone: Vec<Value> = servers
            .iter()
            .filter(|m| removed.iter().any(|r| r["member"] == m["member"]))
            .map(|m| m["member"].clone())
            .collect();
        if !gone.is_empty() && matches!(self.view.as_str(), "status" | "nodes") {
            let declared = self
                .context
                .selected
                .declaration
                .members
                .iter()
                .filter(|m| m.role == broil_core::k3s::Role::Server)
                .count();
            let mut r = row(
                "servers",
                Value::Null,
                Value::Null,
                json!({"active":servers.len() - gone.len(),"declared":declared,"removed":gone}),
                Value::Null,
                &Read {
                    value: Value::Null,
                    time: Value::Null,
                    failure: None,
                    transport: Value::Null,
                    cleanup: false,
                },
            );
            r["source"] = json!("recorded");
            self.rows.push(r);
        }
        if let Some(items) = nodes.value["data"]["items"].as_array() {
            for item in items {
                if !members.iter().any(|m| m["member"] == item["name"]) {
                    self.rows.push(row(
                        "foreign-node",
                        item["name"].clone(),
                        Value::Null,
                        json!({"node":item}),
                        Value::Null,
                        nodes,
                    ));
                }
            }
        }
        Ok(())
    }

    fn source(&self, family: &str, subject: Option<&str>) -> Result<(Snapshot, Value)> {
        let action = format!("reconcile-{family}");
        let event = format!("{family}-recipe");
        for snapshot in self
            .records
            .iter()
            .filter(|s| s.request["action"] == action)
        {
            let recipe = snapshot
                .observations
                .iter()
                .find(|o| o["event"]["type"] == event)
                .ok_or(Failure::Readiness)?["event"]["recipe"]
                .clone();
            if self.view == "credentials-inspect"
                && family == "registry-token"
                && recipe["stage"] != "observe"
            {
                continue;
            }
            if let Some(subject) = subject {
                let key = match family {
                    "issuer" => "issuer",
                    "certificate" => "certificate",
                    _ => "principal",
                };
                if family == "registry-auth" {
                    if recipe["resource"]["id"]
                        .as_str()
                        .and_then(registry_auth::principal_of)
                        .map(|(name, _)| name)
                        != Some(subject)
                    {
                        continue;
                    }
                } else if recipe[key] != subject {
                    continue;
                }
            } else if family == "registry-auth"
                && recipe["resource"]["id"]
                    .as_str()
                    .is_some_and(|s| registry_auth::principal_of(s).is_some())
            {
                continue;
            }
            require(
                recipe["scope"] == self.context.scope
                    && recipe["owner"] == self.owner["owner"]
                    && recipe["cluster"] == self.owner["cluster"]
                    && recipe["profile_sha256"] == self.context.fingerprints["profile_sha256"],
                Failure::Ownership,
            )?;
            let source = if recipe["operation"] != snapshot.request["operation"] {
                require(
                    matches!(family, "network" | "ingress" | "cert-manager"),
                    Failure::Ownership,
                )?;
                let resources: Vec<Value> = snapshot.request["resources"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .iter()
                    .filter(|r| r["kind"] != "bootstrap-assets")
                    .cloned()
                    .collect();
                require(!resources.is_empty(), Failure::Ownership)?;
                let source = network::original_request(&self.records, &resources, &action)?;
                require(
                    source.request["operation"] == recipe["operation"]
                        && source
                            .observations
                            .iter()
                            .any(|o| o["event"]["type"] == event && o["event"]["recipe"] == recipe),
                    Failure::Ownership,
                )?;
                source
            } else {
                snapshot
            };
            return Ok((source.clone(), recipe));
        }
        Err(Failure::Readiness)
    }

    async fn component(&mut self, family: &str, subject: Option<&str>) {
        let kind = match (family, subject) {
            ("registry-auth", Some(_)) => "registry-principals",
            ("registry-auth", None) => "registry-signing",
            _ => family,
        };
        let source = self
            .context
            .check()
            .and_then(|_| self.source(family, subject));
        let (snapshot, recipe) = match source {
            Ok(v) => v,
            Err(f) => {
                self.rows.push(row(
                    kind,
                    json!(subject),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    &Read::unavailable(f),
                ));
                return;
            }
        };
        let descriptor = network::family(&snapshot.request["action"]);
        let setup = component_payload(family, &snapshot, &recipe, &self.owner, &self.records);
        let (payload, domain) = match setup {
            Ok(v) => v,
            Err(f) => {
                self.rows.push(row(
                    kind,
                    json!(subject),
                    Value::Null,
                    Value::Null,
                    Value::Null,
                    &Read::unavailable(f),
                ));
                return;
            }
        };
        let host_tag = match family {
            "network" | "ingress" | "registry-service" => Some("inspect-host"),
            "registry-storage" => Some("inspect-storage"),
            _ => None,
        };
        let mut storage = Vec::new();
        let mut hosts_read = Vec::new();
        let mut replicas = Vec::new();
        let survivors = super::survivors(&self.owner).unwrap_or_default();
        let sent = sent_recipe(family, &payload, &recipe).clone();
        if let Some(tag) = host_tag {
            let hosts: Vec<Value> = sent["members"].as_array().cloned().unwrap_or_default();
            for (index, member) in hosts.into_iter().enumerate() {
                if !survivors.iter().any(|s| s["machine"] == member["machine"]) {
                    continue;
                }
                let mut host_payload = payload.clone();
                if family == "cert-manager" {
                    host_payload["uids"] = Value::Null;
                }
                if family == "registry-storage" {
                    host_payload = registry_storage::read_payload(&recipe, Some(index));
                }
                if family == "registry-service" {
                    host_payload = registry_service::read_payload(
                        &recipe,
                        Some(index),
                        &payload["expected"]["objects"],
                    );
                }
                let read = self
                    .family_read(&snapshot, descriptor, &member, tag, host_payload, domain)
                    .await;
                if read.failure.is_none() {
                    storage.push(read.value["storage"].clone());
                    hosts_read.push(read.value.clone());
                }
                if family == "registry-storage" {
                    let fact = &read.value["storage"];
                    replicas.push(json!({"member":member["member"],"path":recipe["path"],
                        "owner_record":fact["class"],"free_mib":fact["available_mib"]}));
                }
                self.push_component(
                    kind,
                    json!(subject),
                    member["member"].clone(),
                    family,
                    tag,
                    &read,
                );
            }
        }
        let member = sent["first_server"].clone();
        let mut read = self
            .family_read(
                &snapshot,
                descriptor,
                &member,
                "inspect-objects",
                payload.clone(),
                domain,
            )
            .await;
        if family == "registry-token" && read.failure.is_none() {
            if let Err(failure) = registry_token::counted(
                &recipe,
                &payload["expected"],
                payload["probe"] == true,
                &read.value,
            ) {
                read.failure = Some(failure);
                read.value = Value::Null;
            }
        }
        self.push_component(
            kind,
            json!(subject),
            Value::Null,
            family,
            "inspect-objects",
            &read,
        );
        if family == "registry-storage" {
            if let Some(facts) = self.rows.last_mut().map(|r| &mut r["facts"]) {
                if facts.is_object() {
                    facts["replicas"] = json!(replicas);
                }
            }
        }
        if family == "registry-service" {
            let member = self
                .context
                .selected
                .declaration
                .registry
                .as_ref()
                .and_then(|r| registry_service::writer(&self.owner, r).ok())
                .map(|(member, _)| member);
            if let Some(facts) = self.rows.last_mut().map(|r| &mut r["facts"]) {
                if facts.is_object() {
                    let state = &facts["process"]["state"];
                    let ready = if state.is_string() {
                        json!(state == "ready")
                    } else {
                        Value::Null
                    };
                    facts["writer"] = json!({"member":member,"deployment_ready":ready});
                }
            }
        }
        let ready = match family {
            "registry-storage" => {
                json!({"storage":registry_storage::readiness(&storage, &read.value["nodes"])})
            }
            "registry-service" => {
                json!({"services":registry_service::readiness(&hosts_read, &read.value)})
            }
            "registry-endpoint" => json!({"services":registry_endpoint::readiness(&read.value)}),
            "registry-token" => {
                json!({"services":registry_token::readiness(&read.value,registry_token::probed(&payload["expected"]["principals"]))})
            }
            _ => return,
        };
        if read.failure.is_none() {
            if let Some(last) = self.rows.last_mut() {
                last["readiness"] = ready;
            }
        }
    }

    fn replication_source(&self) -> Result<(Snapshot, Value, Value, Vec<Value>)> {
        let snapshot = self
            .records
            .iter()
            .filter(|s| s.request["action"] == "reconcile-registry-replication")
            .max_by_key(|s| s.request["created_ms"].as_u64())
            .ok_or(Failure::Readiness)?;
        let (recipe, objects) = registry_replication::view_inputs(&self.owner, snapshot)?;
        require(
            recipe["scope"] == self.context.scope
                && recipe["owner"] == self.owner["owner"]
                && recipe["cluster"] == self.owner["cluster"]
                && recipe["profile_sha256"] == self.context.fingerprints["profile_sha256"],
            Failure::Ownership,
        )?;
        let survivors = super::survivors(&self.owner)?;
        let members: Vec<Value> = snapshot.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .filter(|m| survivors.iter().any(|s| s["member"] == m["member"]))
            .cloned()
            .collect();
        Ok((snapshot.clone(), recipe, objects, members))
    }

    async fn replication_components(&mut self) {
        let kinds = [
            "registry-writer",
            "registry-replica",
            "registry-reader",
            "registry-token-local",
        ];
        let source = self.context.check().and_then(|_| self.replication_source());
        let (snapshot, recipe, objects, members) = match source {
            Ok(v) => v,
            Err(f) => {
                for kind in kinds {
                    self.rows.push(row(
                        kind,
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        Value::Null,
                        &Read::unavailable(f),
                    ));
                }
                return;
            }
        };
        let family = &registry_replication::FAMILY;
        let label = crate::k3s::replication::RECIPE_LABEL;
        let request: Vec<Value> = snapshot.request["members"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for member in &members {
            let Some(index) = request.iter().position(|m| m == member) else {
                continue;
            };
            let payload = registry_replication::read_payload(&recipe, Some(index), &objects);
            let read = self
                .family_read(
                    &snapshot,
                    family,
                    member,
                    "inspect-replication",
                    payload,
                    label,
                )
                .await;
            let shaped = read.failure.is_none()
                && registry_replication::shape("inspect-replication", &read.value).is_ok();
            let facts = if shaped {
                select(
                    &read.value["replication"],
                    &[
                        "completion",
                        "folder",
                        "local_changes",
                        "need_bytes",
                        "need_deletes",
                        "need_items",
                        "peers_connected",
                        "peers_expected",
                        "service",
                        "state",
                    ],
                )
            } else {
                Value::Null
            };
            let mut r = row(
                "registry-replica",
                Value::Null,
                member["member"].clone(),
                facts,
                Value::Null,
                &read,
            );
            if !shaped && read.failure.is_none() {
                r["failure"] = json!("integrity");
            }
            self.rows.push(r);
        }
        let Some(first) = request.iter().find(|m| m["role"] == "server").cloned() else {
            return;
        };
        let payload = registry_replication::read_payload(&recipe, None, &objects);
        let read = self
            .family_read(&snapshot, family, &first, "inspect-objects", payload, label)
            .await;
        let api = if read.failure.is_none()
            && registry_replication::shape("inspect-objects", &read.value).is_ok()
        {
            Some(&read.value)
        } else {
            None
        };
        let initial = self
            .context
            .selected
            .declaration
            .registry
            .as_ref()
            .map(|r| r.member.clone());
        let moved = &self.owner["writer"];
        let moved_ms = moved["operation"].as_str().and_then(|operation| {
            self.records
                .iter()
                .find(|s| s.request["operation"] == operation)
                .and_then(|s| {
                    s.observations
                        .iter()
                        .find(|o| o["event"]["type"] == "writer-move")
                })
                .map(|o| o["recorded_ms"].clone())
        });
        let writer = if moved.is_null() {
            json!(initial)
        } else {
            moved["member"].clone()
        };
        let facts = api.map_or(Value::Null, |api| {
            json!({"writer":{"member":writer,"initial":initial,"moved_ms":moved_ms,
                "operation":moved["operation"]},
                "pushes":if api["writer"]["process"]["state"] == "ready" {"accepted"} else {"stopped"}})
        });
        let mut r = row(
            "registry-writer",
            Value::Null,
            Value::Null,
            facts,
            Value::Null,
            &read,
        );
        if api.is_none() && read.failure.is_none() {
            r["failure"] = json!("integrity");
        }
        self.rows.push(r);
        let read_only = api.is_some_and(|api| api["objects"][0]["class"] == "owned");
        for (key, kind) in [
            ("readers", "registry-reader"),
            ("tokens", "registry-token-local"),
        ] {
            for member in &members {
                let pod = api.and_then(|api| {
                    api[key]
                        .as_array()?
                        .iter()
                        .find(|p| p["member"] == member["member"])
                        .cloned()
                });
                let facts = pod.map_or(Value::Null, |pod| {
                    if kind == "registry-reader" {
                        json!({"pod":pod["pod"],"ready":pod["ready"],"listen":"127.0.0.1:5599",
                            "read_only":read_only})
                    } else {
                        json!({"pod":pod["pod"],"ready":pod["ready"],"listen":"127.0.0.1:5598",
                            "issuer":"broil-registry-token"})
                    }
                });
                let mut r = row(
                    kind,
                    Value::Null,
                    member["member"].clone(),
                    facts,
                    Value::Null,
                    &read,
                );
                if api.is_none() && read.failure.is_none() {
                    r["failure"] = json!("integrity");
                }
                self.rows.push(r);
            }
        }
    }

    fn push_component(
        &mut self,
        kind: &str,
        subject: Value,
        member: Value,
        family: &str,
        tag: &str,
        read: &Read,
    ) {
        let fields: &[&str] = match family {
            "network" => &["hosts", "objects", "services", "storage"],
            "ingress" => &["hosts", "objects", "results", "ingress", "services"],
            "cert-manager" => &["objects", "webhook", "services"],
            "issuer" => &["objects", "issuer", "services"],
            "certificate" => &["objects", "certificate", "services"],
            "registry-storage" => &["storage", "nodes"],
            "registry-service" => &["objects", "process", "storage", "nodes"],
            "registry-endpoint" => &["objects", "issued", "served"],
            "registry-auth" => &["objects", "signing"],
            "registry-token" => &[
                "objects",
                "signing",
                "token",
                "registry",
                "nodes",
                "enforcement",
                "principals",
                "grants",
            ],
            _ => &[],
        };
        let mut facts = if read.value.is_null() {
            Value::Null
        } else {
            select(&read.value, fields)
        };
        let invalid = match family {
            "network" | "ingress" | "cert-manager" => {
                let keys: &[&str] = if tag == "inspect-host" {
                    &["hosts"]
                } else {
                    match family {
                        "network" => &["objects", "services", "storage"],
                        "ingress" => &["objects", "results", "ingress", "services"],
                        _ => &["objects", "webhook", "services"],
                    }
                };
                require(
                    keys.iter().all(|k| !read.value[*k].is_null())
                        && read.value["terminal"].is_null(),
                    Failure::Integrity,
                )
            }
            "certificate" => require(
                ["objects", "certificate", "services"]
                    .iter()
                    .all(|k| !read.value[*k].is_null())
                    && read.value["terminal"].is_null(),
                Failure::Integrity,
            ),
            "registry-storage" => registry_storage::shape(tag, &read.value),
            "registry-service" => registry_service::shape(tag, &read.value),
            "registry-endpoint" => registry_endpoint::shape(tag, &read.value),
            "registry-token" => registry_token::shape(tag, &read.value),
            "registry-auth" => registry_auth::shape(tag, &read.value),
            "issuer" => issuer::shape(tag, &read.value),
            _ => Ok(()),
        };
        let readiness = if read.value.is_null() {
            Value::Null
        } else if !read.value["services"].is_null() {
            json!({"services":read.value["services"]})
        } else {
            Value::Null
        };
        let source_operation = if self.view == "credentials-inspect" {
            self.source(family, subject.as_str())
                .ok()
                .map(|(s, _)| s.request["operation"].clone())
        } else {
            None
        };
        let mut observation = row(kind, subject, member, facts.clone(), readiness, read);
        if let Some(operation) = source_operation {
            observation["operation"] = operation;
        }
        if invalid.is_err() && read.failure.is_none() {
            facts = Value::Null;
            observation["facts"] = facts;
            observation["failure"] = json!("integrity");
        }
        if observation["failure"].is_null() && component_unobservable(family, &read.value) {
            observation["failure"] = json!("readiness");
        }
        self.rows.push(observation);
    }

    fn recorded(&mut self) {
        if let Some(s) = self.records.iter().find(|s| {
            s.request["action"] == "reconcile-registry-token"
                && s.observations.iter().any(|o| {
                    o["event"]["type"] == "registry-token-recipe"
                        && o["event"]["recipe"]["stage"] == "observe"
                })
        }) {
            let time = s
                .observations
                .iter()
                .rev()
                .find(|o| o["event"]["type"] == "registry-token-observation")
                .map(|o| o["recorded_ms"].clone());
            let mut r = row(
                "publication",
                Value::Null,
                Value::Null,
                json!({"publication":super::report::token_readiness(s).1}),
                Value::Null,
                &Read::unavailable(Failure::Readiness),
            );
            if let Some(time) = time {
                r["observed_ms"] = time;
                r["failure"] = Value::Null;
            }
            r["source"] = json!("recorded");
            r["operation"] = s.request["operation"].clone();
            self.rows.push(r);
        } else if self.context.selected.declaration.registry.is_some() {
            self.rows.push(row(
                "publication",
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                &Read::unavailable(Failure::Readiness),
            ));
        }
        if !self.context.selected.declaration.node_registries.is_empty() {
            let source = self
                .records
                .iter()
                .find(|s| s.request["action"] == "configure-node-registries");
            let mut r = row(
                "node-registries",
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                &Read::unavailable(Failure::Readiness),
            );
            if let Some(s) = source {
                if let Ok(configured) = super::node_registry::observed_configuration(
                    &self.context,
                    &self.records,
                    &self.owner,
                ) {
                    r["facts"] = json!({"configured":configured});
                }
                r["source"] = json!("recorded");
                r["operation"] = s.request["operation"].clone();
                r["observed_ms"] = s
                    .observations
                    .last()
                    .map(|o| o["recorded_ms"].clone())
                    .unwrap_or(Value::Null);
                if !r["facts"]["configured"].is_null() {
                    r["failure"] = Value::Null;
                }
            }
            self.rows.push(r);
        }
    }

    async fn datastore(&mut self) -> Result<()> {
        let members: Vec<Value> = super::survivors(&self.owner)?
            .iter()
            .filter(|m| m["role"] == "server")
            .cloned()
            .collect();
        let start = self.rows.len();
        for member in &members {
            let source = self.records.iter().find_map(|s| {
                s.observations
                    .iter()
                    .find(|o| {
                        o["event"]["type"] == "server-recipe"
                            && o["event"]["recipe"]["member"] == *member
                    })
                    .map(|o| (s.clone(), o["event"].clone()))
            });
            let observed = match source {
                None => Read::unavailable(Failure::Readiness),
                Some((snapshot, event)) => {
                    let recorded = &event["recipe"];
                    let prepared = (|| {
                        require(
                            recorded["operation"] == snapshot.request["operation"]
                                && snapshot.request["cluster"] == self.owner["cluster"]
                                && recorded
                                    .get("cluster")
                                    .is_none_or(|c| *c == self.owner["cluster"]),
                            Failure::Ownership,
                        )?;
                        let recipe = datastore_recipe(recorded, &self.owner)?;
                        let mut binding = self.binding(
                            &snapshot,
                            member,
                            Some((
                                if event["recipe_kind"] == "initial" {
                                    "broil-k3s-server-recipe-v2"
                                } else {
                                    "broil-k3s-join-recipe-v2"
                                },
                                &recipe,
                            )),
                            "lifecycle:observe-membership",
                        )?;
                        if recipe != *recorded {
                            binding["participants_sha256"] =
                                json!(super::participants(&recipe["members"])?);
                        }
                        Ok((binding, recipe))
                    })();
                    match prepared {
                        Err(f) => Read::unavailable(f),
                        Ok((binding, recipe)) => {
                            let result = match self.isolated(member) {
                                Ok(context) => {
                                    let result=server::invoke(&context,&binding,"observe-membership",
                                        &json!({"recipe_kind":event["recipe_kind"],"recipe":recipe,"identity":null,"membership":null,"removed":null}),self.deadline(),None).await;
                                    rpc::Observed {
                                        response: result.result,
                                        transport: result.transport,
                                        failure: result.failure,
                                    }
                                }
                                Err(f) => rpc::Observed {
                                    response: None,
                                    transport: super::provenance::undispatched_transport(),
                                    failure: Some(f),
                                },
                            };
                            self.finish_read(member, result)
                        }
                    }
                }
            };
            let membership = &observed.value["membership"];
            let mut r = row(
                "datastore",
                member["member"].clone(),
                member["member"].clone(),
                if membership.is_null() {
                    Value::Null
                } else {
                    json!({"membership":membership})
                },
                json!({"quorum":"unobserved"}),
                &observed,
            );
            if observed.failure.is_none()
                && (membership.is_null()
                    || membership["cluster"] != self.owner["cluster"]
                    || membership["node_uid"] != member["node_uid"]
                    || membership["observer"] != member["machine"])
            {
                r["failure"] = json!("readiness");
            }
            self.rows.push(r);
        }
        let rows = &mut self.rows[start..];
        let complete = rows.iter().all(|r| r["failure"].is_null());
        let stable = complete
            && rows.first().is_some_and(|first| {
                rows.iter().all(|r| {
                    r["facts"]["membership"]["healthy"] == true
                        && r["facts"]["membership"]["members"]
                            == first["facts"]["membership"]["members"]
                        && r["facts"]["membership"]["members"]
                            .as_array()
                            .is_some_and(|a| a.len() == members.len())
                })
            });
        for r in rows {
            r["readiness"] = json!({"quorum":if !complete {"unobserved"} else if stable {"ready"} else {"not-ready"}});
        }
        Ok(())
    }

    async fn service_ownership(&mut self, items: &[Value]) -> BTreeMap<(String, String), Read> {
        if let Err(failure) = self.context.check() {
            return items
                .iter()
                .map(|i| {
                    (
                        (
                            i["namespace"].as_str().unwrap_or("").into(),
                            i["name"].as_str().unwrap_or("").into(),
                        ),
                        Read::unavailable(failure),
                    )
                })
                .collect();
        }
        let mut result = BTreeMap::new();
        for family in [
            "network",
            "ingress",
            "cert-manager",
            "registry-service",
            "registry-token",
        ] {
            let kind = format!("{family}-observation");
            let candidates: Vec<(String, String)> = items
                .iter()
                .filter(|item| {
                    self.records.iter().any(|s| {
                        s.observations
                            .iter()
                            .filter(|o| o["event"]["type"] == kind)
                            .any(|o| {
                                o["event"]["objects"].as_array().is_some_and(|objects| {
                                    objects.iter().any(|o| {
                                        o["kind"] == "Service"
                                            && o["namespace"] == item["namespace"]
                                            && o["name"] == item["name"]
                                            && matches!(
                                                o["class"].as_str(),
                                                Some("owned" | "owned-ready" | "owned-drifted")
                                            )
                                    })
                                })
                            })
                    })
                })
                .map(|i| {
                    (
                        i["namespace"].as_str().unwrap_or("").into(),
                        i["name"].as_str().unwrap_or("").into(),
                    )
                })
                .collect();
            if candidates.is_empty() {
                continue;
            }
            let read = match self.source(family, None).and_then(|(s, r)| {
                component_payload(family, &s, &r, &self.owner, &self.records)
                    .map(|(p, d)| (s, r, p, d))
            }) {
                Err(f) => Read::unavailable(f),
                Ok((snapshot, recipe, payload, domain)) => {
                    let first = sent_recipe(family, &payload, &recipe)["first_server"].clone();
                    self.family_read(
                        &snapshot,
                        network::family(&snapshot.request["action"]),
                        &first,
                        "inspect-objects",
                        payload,
                        domain,
                    )
                    .await
                }
            };
            for key in candidates {
                let object = read.value["objects"]
                    .as_array()
                    .and_then(|objects| {
                        objects.iter().find(|o| {
                            o["kind"] == "Service" && o["namespace"] == key.0 && o["name"] == key.1
                        })
                    })
                    .cloned()
                    .unwrap_or(Value::Null);
                result.insert(
                    key,
                    Read {
                        value: object,
                        time: read.time.clone(),
                        failure: read.failure,
                        transport: read.transport.clone(),
                        cleanup: read.cleanup,
                    },
                );
            }
        }
        result
    }

    async fn components(&mut self) {
        let full = self.view == "status";
        let domain = self.component.clone().unwrap_or_default();
        for (family, needed) in [
            (
                "network",
                full || matches!(domain.as_str(), "network" | "dns" | "storage"),
            ),
            ("ingress", full || domain == "ingress"),
            ("cert-manager", full || domain == "certificates"),
        ] {
            if needed {
                self.component(family, None).await;
            }
        }
        if full || domain == "certificates" {
            let issuers: Vec<String> = self
                .context
                .selected
                .declaration
                .infrastructure
                .issuers
                .keys()
                .cloned()
                .collect();
            let certificates: Vec<String> = self
                .context
                .selected
                .declaration
                .infrastructure
                .certificates
                .keys()
                .cloned()
                .collect();
            for name in issuers {
                self.component("issuer", Some(&name)).await;
            }
            for name in certificates {
                self.component("certificate", Some(&name)).await;
            }
        }
        let registry = self.context.selected.declaration.registry.as_ref();
        if registry.is_some()
            && (full
                || self.view == "registry-inspect"
                || matches!(domain.as_str(), "registry" | "storage"))
        {
            let principals: Vec<String> = registry
                .map(|r| r.authentication.principals.keys().cloned().collect())
                .unwrap_or_default();
            for family in ["registry-storage", "registry-service"] {
                self.component(family, None).await;
            }
            if domain != "storage" {
                for family in ["registry-endpoint", "registry-auth", "registry-token"] {
                    self.component(family, None).await;
                }
                for principal in principals {
                    self.component("registry-auth", Some(&principal)).await;
                }
                self.replication_components().await;
                self.recorded();
            }
        }
    }

    fn report(mut self) -> (Value, bool) {
        let cleanup = self.rows.iter().any(|r| r["cleanup_unknown"] == true);
        let first_failure = self
            .rows
            .iter()
            .find_map(|r| r["failure"].as_str())
            .map(str::to_owned);
        if let Some(limit) = self
            .limit
            .filter(|_| matches!(self.view.as_str(), "nodes" | "diagnose"))
        {
            self.truncated |= self.rows.len() > limit;
            self.rows.truncate(limit);
        }
        let mut failure = first_failure;
        if failure.is_none() && self.truncated {
            failure = Some("bound".into());
        }
        if failure.is_none() && cleanup {
            failure = Some("transport".into());
        }
        let missing = self.owner.is_null() || self.owner["cluster"].is_null();
        if failure.is_none() && missing {
            failure = Some("readiness".into());
        }
        let cancelled = self.context.policy.cancellation.is_cancelled();
        if cancelled {
            failure = Some("cancelled".into());
        }
        let complete = failure.is_none();
        let members:Vec<Value>=self.context.selected.declaration.members.iter().map(|m|
            json!({"machine":m.machine,"member":m.name,"role":if m.role == broil_core::k3s::Role::Server {"server"} else {"agent"}})).collect();
        (
            json!({"format_version":1,"scope":self.context.scope,"view":self.view,"component":self.component,"limit":self.limit,
            "members_requested":members,"observations":self.rows,"outcome":if cancelled {"cancelled"} else if complete {"complete"}
                else if missing {"refused"} else {"incomplete"},"failure":failure,"completion_unknown":!complete,
            "cleanup_unknown":cleanup,"truncated":self.truncated,"recovery":{"choice":if complete {"none"} else if missing {"create"}
                else {"operator-recovery"},"reason":failure}}),
            complete,
        )
    }
}

fn component_unobservable(family: &str, value: &Value) -> bool {
    match family {
        "issuer" => {
            unobservable(&value["objects"]) || unobservable(&value["issuer"]["registration"])
        }
        "certificate" => unobservable(&value["objects"]),
        _ => unobservable(value),
    }
}

fn unobservable(value: &Value) -> bool {
    match value {
        Value::String(s) => matches!(s.as_str(), "unobservable" | "unreachable" | "untrusted"),
        Value::Array(a) => a.iter().any(unobservable),
        Value::Object(o) => {
            let process = o.len() == 4
                && ["state", "reason", "node", "restarts"]
                    .iter()
                    .all(|k| o.contains_key(*k));
            o.iter().any(|(key, value)| {
                !(matches!(
                    key.as_str(),
                    "name" | "namespace" | "uid" | "member" | "machine" | "subject" | "kind" | "id"
                ) || process && key == "node")
                    && unobservable(value)
            })
        }
        _ => false,
    }
}

fn validate_inventory(query: &str, limit: usize, reply: &Value) -> Result<()> {
    require(canonical(reply)?.len() <= 32768, Failure::Bound)?;
    let data = &reply["data"];
    if data.is_null() {
        return require(reply["status"] != "ok", Failure::Integrity);
    }
    if query == "api" {
        return require(
            data.get("api").is_some() && data.get("datastore").is_some(),
            Failure::Integrity,
        );
    }
    let items = data["items"].as_array().ok_or(Failure::Integrity)?;
    require(items.len() <= limit, Failure::Bound)?;
    let mut previous = None;
    for item in items {
        let kind = match query {
            "nodes" => {
                require(item.get("version").is_some(), Failure::Integrity)?;
                0
            }
            "services" => {
                require(item.get("ports").is_some(), Failure::Integrity)?;
                0
            }
            _ => ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job"]
                .iter()
                .position(|k| item["kind"] == *k)
                .ok_or(Failure::Integrity)?,
        };
        let key = (
            kind,
            item["namespace"].as_str().unwrap_or(""),
            item["name"].as_str().ok_or(Failure::Integrity)?,
            item["uid"].as_str().ok_or(Failure::Integrity)?,
        );
        require(previous.is_none_or(|p| p < key), Failure::Integrity)?;
        previous = Some(key);
    }
    Ok(())
}

fn removed_row(member: &Value, removal: &Value) -> Value {
    let unread =
        json!({"observed_ms":null,"failure":null,"transport":null,"cleanup_unknown":false});
    let mut ownership = unread.clone();
    ownership["state"] = json!("removed");
    ownership["owner"] = Value::Null;
    ownership["active_attempt"] = Value::Null;
    let mut identity = unread.clone();
    identity["value"] = Value::Null;
    let mut node = unread;
    node["state"] = json!("absent");
    node["item"] = Value::Null;
    let comparison = json!({"uid":"absent","version":"absent","role":"absent","labels":"absent",
        "taints":"absent","cluster":"absent"});
    let mut r = row(
        "member",
        member["member"].clone(),
        member["member"].clone(),
        json!({"machine":member["machine"],"member":member["member"],
        "role":member["role"],"published_uid":member["node_uid"],"ownership":ownership,"identity":identity,"node":node,"comparison":comparison}),
        json!({"node":null}),
        &Read {
            value: Value::Null,
            time: Value::Null,
            failure: None,
            transport: Value::Null,
            cleanup: false,
        },
    );
    r["source"] = json!("recorded");
    r["operation"] = removal["operation"].clone();
    r
}

#[allow(clippy::too_many_arguments)]
fn member_row(
    member: &Value,
    cluster: &Value,
    version: &Value,
    labels: &Value,
    taints: &Value,
    claim: &Read,
    identity: &Read,
    nodes: &Read,
) -> Value {
    let state = if claim.failure.is_none() {
        if claim.value["status"] == "absent" {
            "unclaimed"
        } else {
            "claimed"
        }
    } else {
        match claim.failure {
            Some(Failure::Busy) => "busy",
            Some(
                Failure::Transport | Failure::Authentication | Failure::Trust | Failure::Timeout,
            ) => "unreachable",
            _ => "refused",
        }
    };
    let mut ownership = claim.nested();
    ownership["state"] = json!(state);
    ownership["owner"] = if state == "claimed" {
        claim.value["data"]["claim"]["owner"].clone()
    } else {
        Value::Null
    };
    ownership["active_attempt"] = if state == "claimed" {
        claim.value["data"]["claim"]["active_attempt"].clone()
    } else {
        Value::Null
    };
    let mut ident = identity.nested();
    ident["value"] = identity.value["data"]["identity"].clone();
    let item = nodes.value["data"]["items"]
        .as_array()
        .and_then(|a| a.iter().find(|n| n["name"] == member["member"]));
    let node_state = if item.is_some() {
        "present"
    } else if nodes.failure.is_none() && nodes.value["truncated"] == false {
        "absent"
    } else {
        "unobserved"
    };
    let mut node = nodes.nested();
    node["state"] = json!(node_state);
    node["item"] = json!(item);
    if node_state == "unobserved" && node["failure"].is_null() {
        node["failure"] = json!("bound");
    }
    let compare = |field: &str, expected: &Value| -> Value {
        json!(match item {
            None =>
                if node_state == "absent" {
                    "absent"
                } else {
                    "unobserved"
                },
            Some(_) if expected.is_null() => "unobserved",
            Some(i) =>
                if i[field] == *expected {
                    "match"
                } else {
                    "mismatch"
                },
        })
    };
    let mut comparison = json!({"uid":compare("uid",&member["node_uid"]),"version":compare("version",version),
        "role":compare("roles",&json!([member["role"]])),"labels":compare("labels",labels),"taints":compare("taints",taints),
        "cluster":if ident["value"]["cluster"].is_null() || cluster.is_null() {"unobserved"} else if ident["value"]["cluster"] == *cluster {"match"} else {"mismatch"}});
    let comparisons = comparison.as_object_mut().expect("closed object");
    let readiness = if node_state == "absent"
        || state == "unclaimed"
        || item.is_some_and(|i| i["ready"] == false)
        || comparisons.values().any(|v| v == "mismatch")
    {
        "not-ready"
    } else if state == "claimed"
        && item.is_some_and(|i| i["ready"] == true)
        && comparisons.values().all(|v| v == "match")
    {
        "ready"
    } else {
        "unobserved"
    };
    let failure = claim
        .failure
        .or(identity.failure)
        .or(nodes.failure)
        .or_else(|| {
            (node_state == "unobserved"
                || comparison
                    .as_object()
                    .is_some_and(|c| c.values().any(|v| v == "unobserved")))
            .then_some(Failure::Readiness)
        });
    let read = Read {
        value: Value::Null,
        time: [&claim.time, &identity.time, &nodes.time]
            .iter()
            .filter_map(|v| v.as_u64())
            .max()
            .map_or(Value::Null, |v| json!(v)),
        failure,
        transport: Value::Null,
        cleanup: claim.cleanup || identity.cleanup || nodes.cleanup,
    };
    row(
        "member",
        member["member"].clone(),
        member["member"].clone(),
        json!({"machine":member["machine"],"member":member["member"],
        "role":member["role"],"published_uid":member["node_uid"],"ownership":ownership,"identity":ident,"node":node,"comparison":comparison}),
        json!({"node":readiness}),
        &read,
    )
}

fn datastore_recipe(recorded: &Value, owner: &Value) -> Result<Value> {
    let survivors = super::survivors(owner)?;
    let members = recorded["members"].as_array().ok_or(Failure::Integrity)?;
    let machines = |list: &[Value], servers: bool| -> Vec<Value> {
        list.iter()
            .filter(|m| !servers || m["role"] == "server")
            .map(|m| m["machine"].clone())
            .collect()
    };
    if machines(members, false) == machines(&survivors, false) {
        return Ok(recorded.clone());
    }
    require(
        machines(members, true) == machines(&survivors, true),
        Failure::Readiness,
    )?;
    let mut recipe = recorded.clone();
    if !recipe["source"].is_null() {
        recipe["source"] = super::acting_first(&survivors, &recipe["member"]["machine"])
            .cloned()
            .ok_or(Failure::Readiness)?;
    }
    recipe["members"] = json!(survivors);
    Ok(recipe)
}

fn current_request(request: &Value, owner: &Value) -> Result<Option<Value>> {
    let survivors = super::survivors(owner)?;
    let changed = request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .any(|m| !survivors.iter().any(|s| s["machine"] == m["machine"]))
        || survivors.iter().any(|s| !s["node_uid"].is_string());
    if !changed {
        return Ok(None);
    }
    let mut current = request.clone();
    current["participants_sha256"] = json!(super::participants(&json!(survivors))?);
    current["members"] = json!(survivors);
    Ok(Some(current))
}

fn sent_recipe<'v>(family: &str, payload: &'v Value, recipe: &'v Value) -> &'v Value {
    if matches!(family, "network" | "ingress" | "cert-manager") {
        &payload["recipe"]
    } else {
        recipe
    }
}

fn component_payload(
    family: &str,
    snapshot: &Snapshot,
    recipe: &Value,
    owner: &Value,
    records: &[Snapshot],
) -> Result<(Value, &'static str)> {
    let assets = super::latest_assets(records, &snapshot.request["action"]);
    let derive = |recipe: &Value| match current_request(&snapshot.request, owner)? {
        Some(current) => super::derived_recipe(recipe, &current, &assets),
        None => super::derived_recipe(recipe, &snapshot.request, &assets),
    };
    let pair = match family {
        "network" | "ingress" => (
            {
                let (sent, original) = derive(recipe)?;
                json!({"recipe":sent,"original_recipe_sha256":original,"object_ordinal":null,
                    "resource":null,"preflight":null})
            },
            if family == "network" {
                "broil-k3s-network-recipe-v1"
            } else {
                "broil-k3s-ingress-recipe-v1"
            },
        ),
        "cert-manager" => {
            let objects = snapshot
                .observations
                .iter()
                .rev()
                .find(|o| {
                    o["event"]["type"] == "cert-manager-observation"
                        && o["event"]["objects"].is_array()
                })
                .ok_or(Failure::Readiness)?["event"]["objects"]
                .as_array()
                .ok_or(Failure::Integrity)?;
            require(
                objects.len() == cert_manager::identities().len()
                    && objects
                        .iter()
                        .all(|o| o["uid"].is_string() && o["class"] == "owned-ready"),
                Failure::Readiness,
            )?;
            let (sent, original) = derive(recipe)?;
            (
                json!({"recipe":sent,"original_recipe_sha256":original,"uids":objects.iter().map(|o|o["uid"].clone()).collect::<Vec<_>>(),"resource":null,"preflight":null}),
                "broil-k3s-cert-manager-recipe-v1",
            )
        }
        "issuer" | "registry-auth" => {
            let values = if family == "issuer" {
                issuer::resumed(snapshot, &snapshot.steps, recipe).0
            } else {
                registry_auth::resumed(snapshot, &snapshot.steps, recipe).0
            };
            require(values["secret"].is_string(), Failure::Readiness)?;
            (
                json!({"recipe":recipe,"expected":values,"resource":null,"preflight":null,"projection":null}),
                if family == "issuer" {
                    "broil-k3s-issuer-recipe-v1"
                } else {
                    "broil-k3s-registry-auth-recipe-v1"
                },
            )
        }
        "certificate" => {
            let expected = certificate::resumed(snapshot, &snapshot.steps, recipe).0;
            require(expected["certificate"].is_string(), Failure::Readiness)?;
            (
                json!({"recipe":recipe,"expected":expected,"resource":null,"preflight":null}),
                "broil-k3s-certificate-recipe-v1",
            )
        }
        "registry-storage" => (
            registry_storage::read_payload(recipe, None),
            "broil-k3s-registry-storage-recipe-v1",
        ),
        "registry-service" => (
            registry_service::read_payload(
                recipe,
                None,
                &created_uids(family, snapshot, registry_service::expected(recipe, None))?["objects"],
            ),
            "broil-k3s-registry-service-recipe-v2",
        ),
        "registry-endpoint" => (
            json!({"recipe":recipe,"expected":created_uids(family,snapshot,registry_endpoint::expected(recipe))?,"resource":null,"preflight":null,"object_ordinal":null}),
            "broil-k3s-registry-endpoint-recipe-v1",
        ),
        "registry-token" => {
            let expected = registry_token::resumed(snapshot, recipe)?;
            let probe = registry_token::probed(&expected["principals"]).is_some();
            (
                json!({"recipe":recipe,"expected":expected,"resource":null,"preflight":null,"object_ordinal":null,"probe":probe,"member":null}),
                "broil-k3s-registry-token-recipe-v2",
            )
        }
        _ => return Err(Failure::Capability),
    };
    Ok(pair)
}

fn created_uids(family: &str, snapshot: &Snapshot, mut expected: Value) -> Result<Value> {
    for step in snapshot.steps.iter().filter(|s| {
        s["action"] == format!("lifecycle:{family}-create-object") && snapshot.succeeded(s)
    }) {
        let receipt = &issuer::recorded(snapshot, step, "receiver")?["event"]["receipt"];
        let uid = &receipt["resource_identity"];
        require(
            receipt["outcome"] == "succeeded"
                && receipt["effect"] == "complete"
                && uid.is_string()
                && snapshot.owner["resources"].as_array().is_some_and(|a| {
                    a.iter()
                        .any(|r| r["id"] == step["resource"]["id"] && r["uid"] == *uid)
                }),
            Failure::Readiness,
        )?;
        {
            let id = step["resource"]["id"].as_str().ok_or(Failure::Integrity)?;
            let ordinal = id
                .rsplit('-')
                .next()
                .and_then(|n| n.parse::<usize>().ok())
                .and_then(|n| n.checked_sub(1))
                .ok_or(Failure::Integrity)?;
            let objects = expected["objects"]
                .as_array_mut()
                .ok_or(Failure::Integrity)?;
            *objects.get_mut(ordinal).ok_or(Failure::Integrity)? = uid.clone();
        }
    }
    let available = if family == "registry-storage" {
        expected["volume"].is_string()
    } else {
        expected["objects"]
            .as_array()
            .is_some_and(|a| !a.is_empty() && a.iter().all(Value::is_string))
    };
    require(available, Failure::Readiness)?;
    Ok(expected)
}

pub(super) async fn owned_records(
    context: &rpc::Context<'_>,
) -> super::ExecutionResult<(Option<Value>, Vec<Snapshot>)> {
    let (owner, mut records) = converge::records(context).await?;
    records.sort_by(converge::record_order);
    if let Some(owner) = &owner {
        require(
            owner["scope"] == context.scope && owner["fingerprints"] == context.owner_fingerprints,
            Failure::Ownership,
        )?;
        let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
        require(
            members.len() == context.selected.declaration.members.len()
                && members
                    .iter()
                    .zip(&context.selected.declaration.members)
                    .all(|(m, d)| {
                        m["machine"] == d.machine
                            && m["member"] == d.name
                            && m["role"]
                                == if d.role == broil_core::k3s::Role::Server {
                                    "server"
                                } else {
                                    "agent"
                                }
                    }),
            Failure::Ownership,
        )?;
    }
    Ok((owner, records))
}

pub(super) async fn credentials(
    context: rpc::Context<'_>,
    consumer: &str,
) -> super::ExecutionResult<(Value, bool)> {
    let (owner, records) = owned_records(&context).await?;
    let mut reader = Reader {
        context,
        owner: owner.unwrap_or(Value::Null),
        records,
        view: "credentials-inspect".into(),
        component: Some(consumer.into()),
        limit: None,
        failed: BTreeMap::new(),
        rows: Vec::new(),
        truncated: false,
    };
    if reader.owner["cluster"].is_null() {
        return Ok(reader.report());
    }
    let target = reader.context.selected.declaration;
    if consumer == "infrastructure-tls" {
        for name in target.infrastructure.issuers.keys() {
            reader.component("issuer", Some(name)).await;
        }
        for name in target.infrastructure.certificates.keys() {
            reader.component("certificate", Some(name)).await;
        }
    } else {
        let registry = target.registry.as_ref();
        if consumer == "registry-auth" {
            reader.component("registry-auth", None).await;
            for name in registry
                .ok_or(Failure::Configuration)?
                .authentication
                .principals
                .keys()
            {
                reader.component("registry-auth", Some(name)).await;
            }
        } else {
            reader.recorded();
            let configured = reader
                .rows
                .iter()
                .find(|r| r["kind"] == "node-registries")
                .cloned();
            reader.rows.clear();
            for entry in &target.node_registries {
                let admitted =
                    super::access::managed_entry(&reader.context.selected, &entry.registry);
                for member in &target.members {
                    let mut observation = configured.clone().unwrap_or_else(|| {
                        row(
                            "node-registries",
                            Value::Null,
                            Value::Null,
                            Value::Null,
                            Value::Null,
                            &Read::unavailable(Failure::Readiness),
                        )
                    });
                    observation["subject"] = json!(entry.registry);
                    observation["member"] = json!(member.name);
                    if !admitted {
                        observation["failure"] = json!("capability");
                    }
                    reader.rows.push(observation);
                }
                if admitted {
                    reader
                        .component("registry-auth", Some(&entry.username))
                        .await;
                }
            }
        }
        if registry.is_some_and(|_| {
            consumer == "registry-auth"
                || target
                    .node_registries
                    .iter()
                    .any(|e| super::access::managed_entry(&reader.context.selected, &e.registry))
        }) {
            reader.component("registry-token", None).await;
        }
    }
    Ok(reader.report())
}

pub(super) async fn replication_rows<'a>(
    project: &'a LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
) -> super::ExecutionResult<(rpc::Context<'a>, Value, Vec<Snapshot>, Vec<Value>)> {
    let context = rpc::Context::new(project, policy, target)?;
    require(
        context.selected.declaration.registry.is_some(),
        Failure::Configuration,
    )?;
    let (owner, records) = owned_records(&context).await?;
    let mut reader = Reader {
        context,
        owner: owner.unwrap_or(Value::Null),
        records,
        view: "delivery-check".into(),
        component: None,
        limit: None,
        failed: BTreeMap::new(),
        rows: Vec::new(),
        truncated: false,
    };
    require(!reader.owner["cluster"].is_null(), Failure::Readiness)?;
    reader.replication_components().await;
    Ok((reader.context, reader.owner, reader.records, reader.rows))
}

pub(in crate::k3s) async fn run(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    verb: &str,
    component: Option<&str>,
    limit: Option<usize>,
) -> super::ExecutionResult<(Value, bool)> {
    let context = rpc::Context::new(project, policy, target)?;
    let full = verb == "status";
    let registry = verb == "registry inspect" || component == Some("registry");
    require(
        !registry || context.selected.declaration.registry.is_some(),
        Failure::Configuration,
    )?;
    let uses_issuers = full || component == Some("certificates");
    if uses_issuers {
        require(
            !context
                .selected
                .declaration
                .infrastructure
                .issuers
                .values()
                .any(issuer::acme),
            Failure::Capability,
        )?;
    }
    if registry {
        registry_storage::gate(
            context
                .selected
                .declaration
                .registry
                .as_ref()
                .map(|r| r.certificate.as_str()),
            &context.selected.declaration.infrastructure,
        )?;
    }
    let (owner, records) = owned_records(&context).await?;
    let mut reader = Reader {
        context,
        owner: owner.unwrap_or(Value::Null),
        records,
        view: verb.replace(' ', "-"),
        component: component.map(str::to_owned),
        limit,
        failed: BTreeMap::new(),
        rows: Vec::new(),
        truncated: false,
    };
    if reader.owner["cluster"].is_null() {
        return Ok(reader.report());
    }
    if full {
        let no_read = Read {
            value: Value::Null,
            time: Value::Null,
            failure: None,
            transport: Value::Null,
            cleanup: false,
        };
        let mut declaration = row(
            "cluster",
            Value::Null,
            Value::Null,
            json!({"version":reader.context.selected.declaration.version,
            "api_endpoint":reader.context.selected.declaration.api.endpoint.supplied,"identity":null}),
            Value::Null,
            &no_read,
        );
        declaration["source"] = json!("declaration");
        reader.rows.push(declaration);
        if let Some(s) = reader.records.iter().find(|s| {
            s.observations.iter().any(|o| {
                o["event"]["type"] == "identity" && o["event"]["cluster"] == reader.owner["cluster"]
            })
        }) {
            let observed = s
                .observations
                .iter()
                .find(|o| {
                    o["event"]["type"] == "identity"
                        && o["event"]["cluster"] == reader.owner["cluster"]
                })
                .ok_or(Failure::Integrity)?;
            let mut r = row(
                "cluster",
                Value::Null,
                Value::Null,
                json!({"version":null,"api_endpoint":null,"identity":reader.owner["cluster"]}),
                Value::Null,
                &no_read,
            );
            r["source"] = json!("recorded");
            r["operation"] = s.request["operation"].clone();
            r["observed_ms"] = observed["recorded_ms"].clone();
            reader.rows.push(r);
        }
    }
    if matches!(verb, "workloads" | "services") {
        let read = reader.inventory(verb, limit.unwrap_or(100)).await;
        if let Some(items) = read.value["data"]["items"].as_array() {
            let ownership = if verb == "services" {
                reader.service_ownership(items).await
            } else {
                BTreeMap::new()
            };
            for item in items {
                let mut facts = item.clone();
                let key = (
                    item["namespace"].as_str().unwrap_or("").to_owned(),
                    item["name"].as_str().unwrap_or("").to_owned(),
                );
                let compared = ownership.get(&key);
                if verb == "services" {
                    facts["ownership"] = json!(match compared {
                        None => "foreign",
                        Some(r) if r.failure.is_some() || r.value.is_null() => "unobservable",
                        Some(r) if r.value["uid"] != item["uid"] => "foreign",
                        Some(r) => match r.value["class"].as_str() {
                            Some("owned" | "owned-ready") => "owned-ready",
                            Some("owned-drifted") => "owned-drifted",
                            Some("foreign" | "absent") => "foreign",
                            _ => "unobservable",
                        },
                    });
                }
                let unavailable = facts["ownership"] == "unobservable";
                let mut observation = row(
                    if verb == "workloads" {
                        "workload"
                    } else {
                        "service"
                    },
                    item["name"].clone(),
                    Value::Null,
                    facts,
                    Value::Null,
                    compared.unwrap_or(&read),
                );
                if unavailable && observation["failure"].is_null() {
                    observation["failure"] = json!("readiness");
                }
                reader.rows.push(observation);
            }
        }
        if read.failure.is_some() {
            reader.rows.push(row(
                if verb == "workloads" {
                    "workload"
                } else {
                    "service"
                },
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                &read,
            ));
        }
    } else {
        if full || verb == "nodes" || matches!(component, Some("api" | "datastore")) {
            let nodes = reader
                .inventory(
                    "nodes",
                    if verb == "nodes" {
                        limit.unwrap_or(100)
                    } else {
                        1000
                    },
                )
                .await;
            reader.members(&nodes).await?;
        }
        if full || matches!(component, Some("api" | "datastore")) {
            let api = reader.inventory("api", 1).await;
            reader.rows.push(row(
                "api",
                Value::Null,
                Value::Null,
                if api.value["data"].is_null() {
                    Value::Null
                } else {
                    json!({"api":api.value["data"]["api"]})
                },
                Value::Null,
                &api,
            ));
            reader.datastore().await?;
        }
        if verb != "nodes" {
            reader.components().await;
        }
    }
    Ok(reader.report())
}

