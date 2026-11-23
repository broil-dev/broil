// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::network::{self, Family};
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{CERT_MANAGER, PROFILE};
use broil_config::LoadedProject;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "cert-manager",
    protocol: "broil-k3s-cert-manager",
    magic: b"BK3SCMG1\n",
    header: "CertManagerHeader",
    result: "CertManagerResult",
    body: CERT_MANAGER,
    planned: 1,
    reserve: RESERVE,
    version: 1,
};

const RESERVE: usize = 24_576;

const ANCHOR: &str = "cert-manager-object-01";

const GROUPS: &str = "\
v1 Namespace cert-manager
apiextensions.k8s.io/v1 CustomResourceDefinition challenges.acme.cert-manager.io \
orders.acme.cert-manager.io certificaterequests.cert-manager.io certificates.cert-manager.io \
clusterissuers.cert-manager.io issuers.cert-manager.io
v1 ServiceAccount cert-manager/cert-manager-cainjector cert-manager/cert-manager \
cert-manager/cert-manager-webhook
rbac.authorization.k8s.io/v1 ClusterRole cert-manager-cainjector cert-manager-controller-issuers \
cert-manager-controller-clusterissuers cert-manager-controller-certificates \
cert-manager-controller-orders cert-manager-controller-challenges cert-manager-controller-ingress-shim \
cert-manager-cluster-view cert-manager-view cert-manager-edit cert-manager-controller-approve:cert-manager-io \
cert-manager-controller-certificatesigningrequests cert-manager-webhook:subjectaccessreviews
rbac.authorization.k8s.io/v1 ClusterRoleBinding cert-manager-cainjector cert-manager-controller-issuers \
cert-manager-controller-clusterissuers cert-manager-controller-certificates \
cert-manager-controller-orders cert-manager-controller-challenges cert-manager-controller-ingress-shim \
cert-manager-controller-approve:cert-manager-io cert-manager-controller-certificatesigningrequests \
cert-manager-webhook:subjectaccessreviews
rbac.authorization.k8s.io/v1 Role kube-system/cert-manager-cainjector:leaderelection \
kube-system/cert-manager:leaderelection cert-manager/cert-manager-webhook:dynamic-serving
rbac.authorization.k8s.io/v1 RoleBinding kube-system/cert-manager-cainjector:leaderelection \
kube-system/cert-manager:leaderelection cert-manager/cert-manager-webhook:dynamic-serving
v1 Service cert-manager/cert-manager-cainjector cert-manager/cert-manager cert-manager/cert-manager-webhook
apps/v1 Deployment cert-manager/cert-manager-cainjector cert-manager/cert-manager cert-manager/cert-manager-webhook
admissionregistration.k8s.io/v1 MutatingWebhookConfiguration cert-manager-webhook
admissionregistration.k8s.io/v1 ValidatingWebhookConfiguration cert-manager-webhook";

type Identity = (
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
);

pub(super) fn identities() -> Vec<Identity> {
    let mut identities = Vec::new();
    for line in GROUPS.lines() {
        let mut words = line.split_whitespace();
        let (version, kind) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        for name in words {
            identities.push(match name.split_once('/') {
                Some((namespace, name)) => (version, kind, Some(namespace), name),
                None => (version, kind, None, name),
            });
        }
    }
    identities
}

#[derive(Clone, Copy)]
enum Scope {
    Full,
    Import(usize),
}

fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    generations: &[Value],
) -> Result<Value> {
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"members":members,
        "first_server":members.first().ok_or(Failure::Integrity)?,
        "version":context.selected.declaration.version,"generations":generations,
        "profile_sha256":context.fingerprints["profile_sha256"],
        "manifest_sha256":profile["cert_manager"]["manifest"],
        "render_sha256":profile["cert_manager"]["render"]});
    schema::validate(&canonical(&recipe)?, "CertManagerRecipe", 32_768)?;
    Ok(recipe)
}

fn records(value: &Value) -> Result<&Vec<Value>> {
    let records = value["objects"].as_array().ok_or(Failure::Integrity)?;
    let expected = identities();
    require(
        records.len() == expected.len()
            && records
                .iter()
                .zip(&expected)
                .all(|(record, (_, kind, namespace, name))| {
                    record["kind"] == *kind
                        && record["namespace"] == json!(namespace)
                        && record["name"] == *name
                }),
        Failure::Integrity,
    )?;
    Ok(records)
}

fn uids(value: &Value) -> Result<Value> {
    Ok(Value::Array(
        records(value)?.iter().map(|r| r["uid"].clone()).collect(),
    ))
}

fn admit_objects(result: &Value, recovered: Option<&Value>) -> Result<()> {
    let records = records(result)?;
    require(
        match recovered.map(Value::as_array) {
            None => records
                .iter()
                .all(|r| r["class"] == "absent" && r["uid"].is_null()),
            Some(Some(uids)) => {
                uids.len() == records.len()
                    && records
                        .iter()
                        .zip(uids)
                        .all(|(r, uid)| r["class"] == "owned-ready" && r["uid"] == *uid)
            }
            Some(None) => false,
        },
        Failure::Ownership,
    )
}

fn admit_host(hosts: &Value, member: &Value, repeat: bool) -> Result<()> {
    require(hosts["member"] == *member, Failure::Integrity)?;
    let ready = |key: &str| hosts[key]["state"] == "ready";
    require(
        ready("generation") && ready("runtime") && (!repeat || ready("images")),
        Failure::Readiness,
    )
}

fn claimed(reply: &Value, uid: &Value) -> Result<()> {
    let records = records(reply)?;
    require(
        uid.as_str().is_some_and(crate::k3s::protocol::opaque)
            && records[0]["uid"] == *uid
            && records.iter().all(|r| {
                r["class"] == "owned-ready"
                    && r["uid"].is_string()
                    && r["spec_sha256"].is_string()
                    && r["available"] == "unobserved"
            }),
        Failure::Ownership,
    )
}

fn confirms(reply: &Value, observed: &Value) -> Result<bool> {
    let (reply, observed) = (records(reply)?, records(observed)?);
    Ok(reply.iter().zip(observed).all(|(a, b)| {
        ["kind", "namespace", "name", "uid", "class", "spec_sha256"]
            .iter()
            .all(|key| a[*key] == b[*key])
    }))
}

fn identity(resource: &Value, cluster: &Value, reply: &Value, read: &Value) -> Result<Value> {
    require(confirms(reply, read)?, Failure::Ownership)?;
    let event = json!({"type":"identity","member":null,"cluster":cluster,
        "resources":[resource],"readiness":super::report::readiness()});
    Ok(event)
}

fn resume_uids(
    snapshot: &Snapshot,
    create: Option<&Value>,
    receipt: Option<&Value>,
) -> Result<Value> {
    let set = snapshot.observations.iter().find(|o| {
        o["event"]["type"] == "cert-manager-observation"
            && match create {
                Some(step) => o["step"] == step["step"] && o["attempt"] == step["attempt"],
                None => o["step"].is_null(),
            }
    });
    if let Some(set) = set {
        return uids(&set["event"]);
    }
    if create.is_none() {
        return Ok(Value::Null);
    }
    let mut uids = vec![Value::Null; identities().len()];
    if let Some(receipt) = receipt {
        uids[0] = receipt["resource_identity"].clone();
    }
    Ok(Value::Array(uids))
}

fn latest_objects(snapshot: &Snapshot) -> Option<&Value> {
    snapshot.observations.iter().rev().find(|o| {
        o["event"]["type"] == "cert-manager-observation"
            && o["event"]["member"].is_null()
            && !o["event"]["services"].is_null()
    })
}

fn latest_host<'s>(snapshot: &'s Snapshot, member: &Value) -> Option<&'s Value> {
    snapshot
        .observations
        .iter()
        .rev()
        .find(|o| {
            o["event"]["type"] == "cert-manager-observation" && o["event"]["member"] == *member
        })
        .map(|o| &o["event"]["hosts"])
}

#[allow(clippy::too_many_arguments)]
async fn preflight(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    original: &Value,
    recovered: Option<&Value>,
    imports: &[Value],
    source_events: &[Value],
    durable: Option<&Snapshot>,
    scope: Scope,
    cleanup: &mut bool,
) -> Result<usize> {
    let members = request["members"].as_array().ok_or(Failure::Integrity)?;
    let mut imported = 0;
    let binding = |index: usize| network::read_binding(request, attempt, last, index);
    let deadline = || {
        context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(context.selected.step_timeout.seconds),
        )
    };
    let payload = |uids: Value| {
        json!({"recipe":recipe,"original_recipe_sha256":original,"uids":uids,
            "resource":null,"preflight":null})
    };
    let observed = network::invoke(
        context,
        &FAMILY,
        &binding(0)?,
        "inspect-objects",
        &payload(recovered.cloned().unwrap_or(Value::Null)),
        deadline(),
        None,
    )
    .await;
    *cleanup |= network::unclean(&observed.transport);
    let result = observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", super::server::refused(&result))?;
    admit_objects(&result, recovered)?;
    network::membership_reads(context, request, attempt, last, source_events, cleanup).await?;
    let selected: Vec<usize> = match scope {
        Scope::Full => (0..members.len()).collect(),
        Scope::Import(index) => vec![index],
    };
    for index in selected {
        let member = &members[index];
        let observed = network::invoke(
            context,
            &FAMILY,
            &binding(index)?,
            "inspect-host",
            &payload(Value::Null),
            deadline(),
            None,
        )
        .await;
        *cleanup |= network::unclean(&observed.transport);
        let result = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(result["status"] == "ok", super::server::refused(&result))?;
        let import = imports.contains(&member["machine"]) && !ready_images(&result["hosts"]);
        match durable.and_then(|snapshot| latest_host(snapshot, member)) {
            Some(facts) => require(result["hosts"] == *facts, Failure::Readiness)?,
            None => admit_host(&result["hosts"], member, recovered.is_some() && !import)?,
        }
        imported += usize::from(import);
    }
    Ok(imported)
}

fn ready_images(hosts: &Value) -> bool {
    hosts["images"]["state"] == "ready"
}

fn step_count(members: &[Value], repeat: bool) -> Result<usize> {
    let servers = members.iter().filter(|m| m["role"] == "server").count();
    members
        .len()
        .checked_mul(7)
        .and_then(|n| n.checked_add(servers.checked_mul(2)?))
        .and_then(|n| n.checked_add(if repeat { 5 } else { 8 }))
        .and_then(|n| n.checked_sub(if servers == members.len() { 2 } else { 0 }))
        .filter(|n| *n <= 1024)
        .ok_or(Failure::Bound)
}

fn fits(request: &Value, attempt: &str, count: usize, recipe: &Value) -> Result<()> {
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let mut binding = network::read_binding(request, attempt, last, 0)?;
    binding["receiver_generation"] = json!(u64::MAX);
    let absent: Vec<Value> = identities()
        .iter()
        .map(|(_, kind, namespace, name)| {
            json!({"kind":kind,"namespace":namespace,"name":name,"uid":null,"class":"absent",
                "spec_sha256":null,"available":"unobserved"})
        })
        .collect();
    let anchor = request["resources"]
        .as_array()
        .and_then(|r| r.last())
        .ok_or(Failure::Integrity)?;
    let header = json!({"protocol":FAMILY.protocol,"version":1,"action":"create-objects",
        "request_id":fresh()?,"binding":binding,"remaining_ms":7_200_000,"recipe":recipe,
        "original_recipe_sha256":null,"uids":null,"resource":anchor,"preflight":absent});
    require(
        canonical(&header)?
            .len()
            .checked_add(17 + RESERVE)
            .is_some_and(|n| n <= 65_536),
        Failure::Bound,
    )
}

fn unchanged(original: &Value, expected: &Value) -> Result<()> {
    require(original == expected, Failure::Configuration)
}

pub(super) fn version(profile: &Value, declared: &str) -> Result<()> {
    require(
        profile["cert_manager"]["version"] == declared,
        Failure::Configuration,
    )
}

pub(super) fn reference_fit(context: &rpc::Context<'_>) -> Result<()> {
    let members = context
        .selected
        .members
        .iter()
        .map(|m| {
            let mut member = context.widest_member(&m.declaration.machine)?;
            member["node_uid"] = json!("f".repeat(36));
            Ok(member)
        })
        .collect::<Result<Vec<_>>>()?;
    let owner_id = "f".repeat(32);
    let operation = format!("infra-operation-{owner_id}");
    let owner = json!({"owner":owner_id,"members":members,
        "cluster":{"uid":"f".repeat(36),"ca_sha256":"f".repeat(64)}});
    let generations: Vec<_> = members
        .iter()
        .map(|m| {
            json!({"machine":m["machine"],
        "generation":owner_id,"marker_sha256":"f".repeat(64)})
        })
        .collect();
    let recipe = recipe(context, &owner, &operation, &generations)?;
    let anchor = json!({"kind":"service","id":ANCHOR,"owner":owner_id,"generation":owner_id,
        "machine":null,"path":null,"namespace":null,"name":"cert-manager","uid":null});
    let request = json!({"scope":context.scope,"owner":owner_id,"operation":operation,
        "members":members,"participants_sha256":"f".repeat(64),
        "fingerprints":context.fingerprints,"resources":[anchor]});
    fits(&request, &owner_id, step_count(&members, false)?, &recipe)
}

fn anchor(owner: &Value) -> Result<Vec<Value>> {
    let planned: Vec<Value> = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| {
            r["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("cert-manager-object-"))
        })
        .cloned()
        .collect();
    require(
        planned.is_empty()
            || planned.len() == 1
                && planned[0]["id"] == ANCHOR
                && planned[0]["kind"] == "service"
                && planned[0]["namespace"].is_null()
                && planned[0]["name"] == "cert-manager"
                && planned[0]["owner"] == owner["owner"]
                && (planned[0]["uid"].is_null() || planned[0]["uid"].is_string()),
        Failure::Ownership,
    )?;
    Ok(planned)
}

fn recovered(original: &Snapshot, anchor: &Value) -> Result<Value> {
    let create = original
        .steps
        .iter()
        .find(|s| s["action"] == "lifecycle:cert-manager-create-objects")
        .ok_or(Failure::Ownership)?;
    let of_create = |o: &&Value| o["step"] == create["step"] && o["attempt"] == create["attempt"];
    let receipt = original
        .observations
        .iter()
        .filter(of_create)
        .find(|o| o["event"]["type"] == "receiver")
        .ok_or(Failure::Ownership)?;
    let reply = original
        .observations
        .iter()
        .filter(of_create)
        .find(|o| o["event"]["type"] == "cert-manager-observation")
        .ok_or(Failure::Ownership)?;
    let identity = original
        .observations
        .iter()
        .find(|o| {
            o["event"]["type"] == "identity"
                && o["event"]["resources"][0]["id"] == ANCHOR
                && o["event"]["resources"][0]["uid"] == anchor["uid"]
        })
        .ok_or(Failure::Ownership)?;
    let independent = original
        .observations
        .iter()
        .rev()
        .filter(|o| o["sequence"].as_u64() < identity["sequence"].as_u64())
        .find(|o| {
            o["event"]["type"] == "cert-manager-observation"
                && o["event"]["member"].is_null()
                && !o["event"]["services"].is_null()
        })
        .ok_or(Failure::Ownership)?;
    let records = records(&independent["event"])?;
    require(
        original.succeeded(create)
            && receipt["event"]["receipt"]["resource_identity"] == anchor["uid"]
            && confirms(&reply["event"], &independent["event"])?
            && records[0]["uid"] == anchor["uid"]
            && records.iter().all(|r| r["class"] == "owned-ready"),
        Failure::Ownership,
    )?;
    Ok(Value::Array(records.clone()))
}

pub(super) async fn resume_objects(
    context: &rpc::Context<'_>,
    local: &mut Local,
    original: &Snapshot,
    recipe: &Value,
) -> Result<()> {
    let Some(inspect_step) = original
        .steps
        .iter()
        .rev()
        .find(|s| s["action"] == "lifecycle:cert-manager-inspect-objects")
    else {
        return Ok(());
    };
    let create = original
        .steps
        .iter()
        .find(|s| s["action"] == "lifecycle:cert-manager-create-objects");
    let snapshot = local.snapshot()?.clone();
    let of_create = |o: &&Value| {
        create.is_some_and(|step| o["step"] == step["step"] && o["attempt"] == step["attempt"])
    };
    let receipt = snapshot
        .observations
        .iter()
        .filter(of_create)
        .rev()
        .find(|o| o["event"]["type"] == "receiver")
        .map(|o| &o["event"]["receipt"])
        .filter(|r| r["outcome"] == "succeeded" && r["effect"] == "complete");
    let (sent, original_hash) = super::derived_recipe(
        recipe,
        &original.request,
        &super::component_assets(original),
    )?;
    let payload = json!({"recipe":sent,"original_recipe_sha256":original_hash,
        "uids":resume_uids(&snapshot, create, receipt)?,"resource":null,"preflight":null});
    let observed = network::invoke(
        context,
        &FAMILY,
        &original.binding(inspect_step),
        "inspect-objects",
        &payload,
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
        None,
    )
    .await;
    let result = observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", super::server::refused(&result))?;
    let first = &original.request["members"][0]["machine"];
    local
        .append(
            Some(inspect_step),
            json!({"type":"cert-manager-observation","member":null,"hosts":null,
                "objects":result["objects"],"webhook":result["webhook"],"services":result["services"]}),
            Some(first),
            Value::Null,
        )
        .await?;
    let (Some(step), Some(receipt)) = (create, receipt) else {
        return Ok(());
    };
    let uid = &receipt["resource_identity"];
    let prior = snapshot.owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == ANCHOR)
        .ok_or(Failure::Ownership)?;
    if prior["uid"].is_string() {
        return require(prior["uid"] == *uid, Failure::Ownership);
    }
    let records = records(&result)?;
    require(
        snapshot.succeeded(step)
            && records[0]["uid"] == *uid
            && records[0]["class"] == "owned-ready",
        Failure::Ownership,
    )?;
    let mut published = step["resource"].clone();
    published["uid"] = uid.clone();
    local
        .append(
            Some(step),
            json!({"type":"identity","member":null,"cluster":snapshot.request["cluster"],
                "resources":[published],"readiness":super::report::readiness()}),
            None,
            Value::Null,
        )
        .await?;
    super::ingress::publish(local, &published).await
}

impl Session<'_> {
    async fn cert_manager_preflight(
        &mut self,
        recipe: &Value,
        recovered: Option<&Value>,
        scope: Scope,
    ) -> Result<()> {
        let snapshot = self.local.snapshot()?.clone();
        let source_events: Vec<Value> = snapshot
            .observations
            .iter()
            .filter(|o| {
                matches!(
                    o["event"]["type"].as_str(),
                    Some("server-recipe" | "agent-join-recipe")
                )
            })
            .map(|o| o["event"].clone())
            .collect();
        let last = self.attempt["steps"]
            .as_array()
            .and_then(|steps| steps.last())
            .and_then(Value::as_u64)
            .ok_or(Failure::Integrity)?;
        let mut cleanup = false;
        let checked = preflight(
            &self.context,
            &snapshot.request,
            self.attempt["attempt"].as_str().ok_or(Failure::Integrity)?,
            last,
            recipe,
            &super::original_hash(&snapshot, recipe)?,
            recovered,
            &[],
            &source_events,
            Some(&snapshot),
            scope,
            &mut cleanup,
        )
        .await;
        self.local.cleanup_unknown |= cleanup;
        checked.map(drop)
    }

    async fn inspect_objects(
        &mut self,
        recipe: &Value,
        recipe_seq: &Value,
        source: Option<&Value>,
    ) -> Result<Value> {
        let (uids, refs) = match source {
            None => (Value::Null, vec![recipe_seq.clone()]),
            Some(observation) => (
                uids(&observation["event"])?,
                vec![recipe_seq.clone(), observation["sequence"].clone()],
            ),
        };
        let original = super::original_hash(self.local.snapshot()?, recipe)?;
        let payload = json!({"recipe":recipe,"original_recipe_sha256":original,"uids":uids,
            "resource":null,"preflight":null});
        Ok(self
            .family_step(0, "inspect-objects", payload, refs)
            .await?
            .1)
    }

    async fn cert_manager_run(&mut self, recipe: Value, repeat: bool) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, "cert-manager-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let copied = if repeat {
            let observation = self
                .local
                .snapshot()?
                .observations
                .iter()
                .find(|o| o["event"]["type"] == "cert-manager-observation" && o["step"].is_null())
                .ok_or(Failure::Integrity)?
                .clone();
            Some(observation)
        } else {
            None
        };
        let recovered = copied.as_ref().map(|o| uids(&o["event"])).transpose()?;
        for &index in &order {
            let owner = self
                .inspect_step(index, "owner", Value::Null, Value::Null)
                .await?;
            require(
                owner["status"] == "ok"
                    && owner["data"]["claim"]["active_attempt"].is_null()
                    && owner["data"]["ownership"]["cluster"] == cluster
                    && owner["data"]["ownership"]["machine"]["node_uid"]
                        == self.members[index]["node_uid"],
                Failure::Ownership,
            )?;
            self.generations[index] = owner["data"]["claim"]["generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?;
            let writer = self
                .inspect_step(index, "writer", Value::Null, Value::Null)
                .await?;
            require(
                writer["status"] == "absent" || writer["status"] == "ok",
                Failure::Ownership,
            )?;
        }
        self.network_source_gate().await?;
        let first = self
            .inspect_objects(&recipe, &recipe_seq, copied.as_ref())
            .await?;
        admit_objects(&first, recovered.as_ref())?;
        for &index in &order {
            self.dispatch(
                index,
                "reserve-owner",
                json!({"members":self.members,"excluded":null,"cluster":cluster,
                "fingerprints":self.context.fingerprints}),
                Vec::new(),
            )
            .await?;
        }
        for &index in &order {
            self.dispatch(
                index,
                "acquire-writer",
                super::session::acquire_payload(self.local.snapshot()?, &self.members)?,
                Vec::new(),
            )
            .await?;
        }
        self.acquired()?;
        self.mode = Mode::Work;
        self.context
            .authenticate_owned(&Value::Array(self.members.clone()))
            .await?;
        self.network_source_gate().await?;
        let second = self
            .inspect_objects(&recipe, &recipe_seq, copied.as_ref())
            .await?;
        admit_objects(&second, recovered.as_ref())?;
        let bound = if let Some(copied) = copied {
            let imports: Vec<Value> = super::component_assets(self.local.snapshot()?)
                .iter()
                .map(|a| a["machine"].clone())
                .collect();
            let original = super::original_hash(self.local.snapshot()?, &recipe)?;
            let payload = json!({"recipe":recipe,"original_recipe_sha256":original,
                "uids":null,"resource":null,"preflight":null});
            let mut selected = Vec::new();
            for index in 0..self.members.len() {
                let member = self.members[index].clone();
                let (_, result) = self
                    .family_step(
                        index,
                        "inspect-host",
                        payload.clone(),
                        vec![recipe_seq.clone()],
                    )
                    .await?;
                let import =
                    imports.contains(&member["machine"]) && !ready_images(&result["hosts"]);
                admit_host(&result["hosts"], &member, !import)?;
                if import {
                    selected.push(index);
                }
            }
            let admitted = self.attempt["steps"]
                .as_array()
                .map_or(0, Vec::len)
                .checked_sub(step_count(&self.members, true)?)
                .ok_or(Failure::Integrity)?;
            require(admitted == 2 * selected.len(), Failure::Readiness)?;
            for index in selected {
                let member = self.members[index].clone();
                self.cert_manager_preflight(&recipe, recovered.as_ref(), Scope::Import(index))
                    .await?;
                let resource = self.local.snapshot()?.request["resources"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .iter()
                    .find(|r| r["kind"] == "bootstrap-assets" && r["machine"] == member["machine"])
                    .cloned()
                    .ok_or(Failure::Ownership)?;
                let mut imported = payload.clone();
                imported["resource"] = resource;
                self.family_step(index, "import-images", imported, vec![recipe_seq.clone()])
                    .await?;
                let (_, result) = self
                    .family_step(
                        index,
                        "inspect-host",
                        payload.clone(),
                        vec![recipe_seq.clone()],
                    )
                    .await?;
                admit_host(&result["hosts"], &member, true)?;
            }
            copied
        } else {
            let resources = request["resources"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .clone();
            for index in 0..self.members.len() {
                self.cert_manager_preflight(&recipe, None, Scope::Import(index))
                    .await?;
                let resource = resources
                    .iter()
                    .find(|r| {
                        r["kind"] == "bootstrap-assets"
                            && r["machine"] == self.members[index]["machine"]
                    })
                    .cloned()
                    .ok_or(Failure::Ownership)?;
                let original = super::original_hash(self.local.snapshot()?, &recipe)?;
                let payload = json!({"recipe":recipe,"original_recipe_sha256":original,
                    "uids":null,"resource":resource,"preflight":null});
                self.family_step(index, "import-images", payload, vec![recipe_seq.clone()])
                    .await?;
            }
            self.cert_manager_preflight(&recipe, None, Scope::Full)
                .await?;
            let snapshot = self.local.snapshot()?;
            let latest = latest_objects(snapshot).ok_or(Failure::Integrity)?;
            admit_objects(&latest["event"], None)?;
            let mut refs = vec![
                recipe_seq.clone(),
                network::latest_sequence(snapshot, "server-membership")?,
            ];
            if self.members.iter().any(|member| member["role"] == "agent") {
                refs.push(network::latest_sequence(snapshot, "agent-membership")?);
            }
            refs.push(latest["sequence"].clone());
            let anchor = resources.last().ok_or(Failure::Integrity)?;
            let payload = json!({"recipe":recipe,
                "original_recipe_sha256":super::original_hash(snapshot, &recipe)?,
                "uids":null,"resource":anchor,"preflight":latest["event"]["objects"]});
            let (step, created) = self.family_step(0, "create-objects", payload, refs).await?;
            let uid = created["terminal"]["resource_identity"].clone();
            claimed(&created, &uid)?;
            let reply = self
                .local
                .snapshot()?
                .observations
                .iter()
                .rev()
                .find(|o| {
                    o["step"] == step["step"] && o["event"]["type"] == "cert-manager-observation"
                })
                .ok_or(Failure::Integrity)?
                .clone();
            let receipt = self
                .inspect_step(0, "dispatch", step["dispatch"].clone(), Value::Null)
                .await?;
            require(receipt["status"] == "ok", Failure::Ownership)?;
            let independent = self
                .inspect_objects(&recipe, &recipe_seq, Some(&reply))
                .await?;
            let mut resource = step["resource"].clone();
            resource["uid"] = uid;
            let event = identity(&resource, &cluster, &reply["event"], &independent)?;
            self.append(&step, event, false, Value::Null).await?;
            super::ingress::publish(&mut self.local, &resource).await?;
            reply
        };
        let expected = uids(&bound["event"])?;
        let last = self
            .inspect_objects(&recipe, &recipe_seq, Some(&bound))
            .await?;
        admit_objects(&last, Some(&expected))?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let (mut session, recipe, repeat) = begin(project, policy, target).await?;
    let result = Box::pin(session.cert_manager_run(recipe, repeat)).await;
    session.local.complete(result, &session.context.clock).await
}

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<(Session<'a>, Value, bool)> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let prepared: Result<_> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e| e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        super::replacement_window(&owner, "cert-manager-object-")?;
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()
                && v.iter().all(|m| m["node_uid"].is_string())), Failure::Ownership)?;
        for snapshot in &previous {
            let result = super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?;
            require(matches!(result["outcome"].as_str(), Some("succeeded" | "failed" | "cancelled"))
                && result["completion_unknown"] == false
                && result["cleanup_unknown"] == false, Failure::Busy)?;
        }
        let baseline: Vec<Value> = owner["resources"].as_array().ok_or(Failure::Integrity)?.iter()
            .filter(|r| r["id"].as_str().is_some_and(|id| id.starts_with("network-object-")))
            .cloned().collect();
        require(baseline.len() == 12 && baseline.iter().all(|r| r["uid"].is_string()), Failure::Ownership)?;
        network::original_request(&previous, &baseline, "reconcile-network")?;
        let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
        version(&profile, context.selected.declaration.infrastructure.cert_manager_version.as_str())?;
        context.authenticate_owned(&json!(super::survivors(&owner)?)).await?;
        let mut planned = anchor(&owner)?;
        let mut pending_owner = None;
        if planned.is_empty() {
            let mut successor = owner.clone();
            successor["previous_generation"] = successor["generation"].clone();
            successor["generation"] = json!(fresh()?);
            successor["created_ms"] = json!(now()?);
            successor["resources"].as_array_mut().ok_or(Failure::Integrity)?.push(json!({
                "kind":"service","id":ANCHOR,"owner":owner["owner"],"generation":fresh()?,
                "machine":null,"path":null,"namespace":null,"name":"cert-manager","uid":null}));
            planned = anchor(&successor)?;
            pending_owner = Some(successor);
        }
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        require(planned.len() == 1, Failure::Ownership)?;
        let bound = planned[0]["uid"].is_string();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let members = super::survivors(&current_owner)?;
        let mut survivors = current_owner.clone();
        survivors["members"] = json!(members);
        let (generations, assets) = super::ingress::generations(&previous, &context, members.iter())?;
        let created = now()?;
        let participants = super::participants(&json!(members))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let (cert_manager_recipe, recovered) = if bound {
            let source = network::original_request(&previous, &planned, "reconcile-cert-manager")?;
            let recipe = source.observations.iter().find(|o| o["event"]["type"] == "cert-manager-recipe")
                .ok_or(Failure::Ownership)?["event"]["recipe"].clone();
            (recipe, Some(recovered(source, &planned[0])?))
        } else {
            (recipe(&context, &survivors, &operation, &generations)?, None)
        };
        let expected = recipe(&context, &survivors,
            cert_manager_recipe["operation"].as_str().ok_or(Failure::Integrity)?, &generations)?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-cert-manager",
            "members":members,"cluster":current_owner["cluster"],
            "resources":assets.into_iter().chain(planned.iter().cloned()).collect::<Vec<_>>(),
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let assets = super::replaced_assets(&previous, &context, &cert_manager_recipe, &members)?;
        let (sent, original) = super::derived_recipe(&cert_manager_recipe, &request, &assets)?;
        unchanged(&sent, &expected)?;
        let imports: Vec<Value> = if bound {
            assets.iter().map(|a| a["machine"].clone()).collect()
        } else {
            Vec::new()
        };
        let count = step_count(&members, bound)? + 2 * imports.len();
        require(count <= 1024, Failure::Bound)?;
        fits(&request, &attempt_id, count, &sent)?;
        let expected_uids = recovered.as_ref().map(|records| uids(&json!({"objects":records}))).transpose()?;
        let mut cleanup = false;
        let checked = preflight(&context, &request, &attempt_id, count as u64, &sent, &original,
            expected_uids.as_ref(), &imports, &source_events, None, Scope::Full, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        let count = step_count(&members, bound)? + 2 * checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_cert_manager(successor)).await?;
            require(local.snapshot()?.owner["resources"].as_array()
                .is_some_and(|resources| resources.last() == planned.first()), Failure::Ownership)?;
            local.snapshot()?.owner.clone()
        } else {
            current_owner
        };
        let attempt = json!({"schema":1,"kind":"attempt","scope":context.scope,
            "owner":current_owner["owner"],"operation":operation,"attempt":attempt_id,
            "created_ms":created,"request_sha256":hash("broil-infra-request-v1",&request)?,
            "parent_attempt":null,"original_step":null,"approval":null,
            "steps":(1..=count).collect::<Vec<_>>()});
        let stored_owner = current_owner.clone();
        let stored_attempt = attempt.clone();
        local.work(move |store| store.create(stored_owner,request,stored_attempt)).await?;
        let copied = recovered.map(|records| json!({"type":"cert-manager-observation","member":null,
            "hosts":null,"objects":records,"webhook":null,"services":null}));
        for event in std::iter::once(json!({"type":"cert-manager-recipe","recipe":cert_manager_recipe}))
            .chain((!assets.is_empty()).then(|| json!({"type":"component-assets","entries":assets})))
            .chain(source_events).chain(copied) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members, attempt_id, sent, bound))
    }.await;
    let (members, attempt_id, cert_manager_recipe, repeat) = match prepared {
        Ok(value) => value,
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
    };
    let attempt = local
        .snapshot()?
        .attempts
        .iter()
        .find(|a| a["attempt"] == attempt_id)
        .ok_or(Failure::Integrity)?
        .clone();
    let generations = vec![0; members.len()];
    Ok((
        Session {
            context,
            local,
            attempt,
            members,
            generations,
            next_step: 1,
            consumer: None,
            existing_resources: true,
            mode: Mode::Acquiring,
            retry_input: None,
            agent_view_wait: false,
            wave_boundary: None,
            wave_operations: Vec::new(),
            wave_gate_needed: false,
        },
        cert_manager_recipe,
        repeat,
    ))
}

