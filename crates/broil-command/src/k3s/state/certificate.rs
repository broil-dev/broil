// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::issuer::{self, ANCHOR};
use super::network::{self, Family};
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{CERT_MANAGER, PROFILE, protocol};
use broil_config::LoadedProject;
use broil_core::k3s::Certificate;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "certificate",
    protocol: "broil-k3s-certificate",
    magic: b"BK3SCRT1\n",
    header: "CertificateHeader",
    result: "CertificateResult",
    body: CERT_MANAGER,
    planned: 1,
    reserve: 8_192,
    version: 1,
};

pub(super) fn action(tag: &str) -> String {
    format!("lifecycle:certificate-{tag}")
}

pub(super) fn lifetime(certificate: &Certificate) -> (u64, u64) {
    (
        certificate
            .duration
            .as_ref()
            .map_or(7_776_000, |d| d.seconds),
        certificate
            .renew_before
            .as_ref()
            .map_or(2_592_000, |d| d.seconds),
    )
}

pub(super) fn duration_gate(duration: u64, renew_before: u64) -> Result<()> {
    require(
        duration >= 3_600 && renew_before >= 300,
        Failure::Configuration,
    )
}

pub(super) fn gates(
    infrastructure: &broil_core::k3s::Infrastructure,
    certificate: &str,
) -> Result<Certificate> {
    issuer::acme_gate(&infrastructure.issuers)?;
    let declared = infrastructure
        .certificates
        .get(certificate)
        .ok_or(Failure::Configuration)?;
    let (duration, renew_before) = lifetime(declared);
    duration_gate(duration, renew_before)?;
    Ok(declared.clone())
}

pub(super) fn resource_id(certificate: &str) -> Result<String> {
    let id = format!("certificate-object-{certificate}");
    require(id.len() <= 128, Failure::Bound)?;
    require(protocol::opaque(&id), Failure::Configuration)?;
    Ok(id)
}

pub(super) fn names(owner: &Value, id: &Value) -> Result<(String, String)> {
    let digest = protocol::digest(&canonical(&json!([owner, {"kind":"certificate","id":id}]))?);
    Ok((
        format!("broil-certificate-{}", &digest[..40]),
        format!("broil-tls-{}", &digest[..40]),
    ))
}

pub(super) fn stage(origins: &Value) -> &'static str {
    if origins["certificate"].is_null() {
        "create"
    } else {
        "observe"
    }
}

pub(super) fn effects(stage: &str) -> usize {
    usize::from(stage == "create")
}

pub(super) fn confirms(stage: &str, reply: &Value) -> Result<()> {
    let classes: Vec<&str> = (0..3)
        .map(|i| reply["objects"][i]["class"].as_str().unwrap_or(""))
        .collect();
    require(
        !classes
            .iter()
            .any(|c| *c == "foreign" || *c == "owned-drifted"),
        Failure::Ownership,
    )?;
    require(!classes.contains(&"unobservable"), Failure::Readiness)?;
    require(
        match stage {
            "create" => classes == ["absent", "absent", "owned"],
            "observe" => {
                classes[0] == "owned"
                    && matches!(classes[1], "absent" | "owned")
                    && classes[2] == "owned"
            }
            _ => false,
        },
        Failure::Ownership,
    )?;
    require(
        stage != "create" || reply["certificate"]["ready"]["reason"] != "issuer",
        Failure::Readiness,
    )
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let read = tag == "inspect-objects";
    require(
        ["objects", "certificate", "services"]
            .iter()
            .all(|key| result[*key].is_null() != read)
            && result["terminal"].is_null() == read,
        Failure::Integrity,
    )
}

pub(super) fn expected(recipe: &Value) -> Value {
    json!({"certificate":recipe["resource"]["uid"]})
}

fn recipe_of(snapshot: &Snapshot) -> Result<&Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "certificate-recipe")
        .map(|o| &o["event"]["recipe"])
        .ok_or(Failure::Integrity)
}

fn reads_after<'s>(snapshot: &'s Snapshot, sequence: &Value) -> impl Iterator<Item = &'s Value> {
    let after = sequence.as_u64().unwrap_or(u64::MAX);
    snapshot.observations.iter().filter(move |o| {
        o["event"]["type"] == "certificate-observation"
            && !o["event"]["services"].is_null()
            && o["sequence"].as_u64().is_some_and(|s| s > after)
    })
}

pub(super) fn refused(snapshot: &Snapshot) -> bool {
    let receipt = snapshot
        .steps
        .iter()
        .filter(|s| s["action"] == action("create-object"))
        .any(|step| {
            issuer::recorded(snapshot, step, "receiver").is_ok_and(|o| {
                let r = &o["event"]["receipt"];
                r["outcome"] == "failed" && r["effect"] == "absent" && r["failure"] == "readiness"
            })
        });
    receipt
        && snapshot.observations.iter().any(|o| {
            let event = &o["event"];
            event["type"] == "failure"
                && event["failure"] == "readiness"
                && event["outcome"] == "failed"
                && event["completion_unknown"] == false
                && event["cleanup_unknown"] == false
        })
}

pub(super) fn origins(
    previous: &[Snapshot],
    resource: &Value,
    cluster_issuer: &Value,
) -> Result<Value> {
    let uid = &resource["uid"];
    let creates: Vec<(&Snapshot, &Value)> = previous
        .iter()
        .filter(|s| {
            s.request["action"] == "reconcile-certificate"
                && s.request["resources"][0]["id"] == resource["id"]
                && s.request["resources"][0]["generation"] == resource["generation"]
        })
        .flat_map(|s| {
            s.steps
                .iter()
                .filter(move |step| step["action"] == action("create-object") && s.succeeded(step))
                .map(move |step| (s, step))
        })
        .collect();
    require(creates.len() <= 1, Failure::Ownership)?;
    let mut certificate = Value::Null;
    if let Some((snapshot, step)) = creates.first() {
        let receipt = issuer::recorded(snapshot, step, "receiver")?;
        let identity = snapshot.observations.iter().any(|o| {
            o["event"]["type"] == "identity"
                && o["event"]["resources"][0]["id"] == resource["id"]
                && o["event"]["resources"][0]["uid"] == *uid
        });
        let read = reads_after(snapshot, &receipt["sequence"]).any(|o| {
            o["event"]["objects"][0]["class"] == "owned" && o["event"]["objects"][0]["uid"] == *uid
        });
        require(
            uid.is_string()
                && receipt["event"]["receipt"]["resource_identity"] == *uid
                && identity
                && read,
            Failure::Ownership,
        )?;
        certificate = json!({"operation":snapshot.request["operation"],
            "recipe_sha256":hash("broil-k3s-certificate-recipe-v1", recipe_of(snapshot)?)?});
    } else {
        require(uid.is_null(), Failure::Ownership)?;
    }
    Ok(json!({"certificate":certificate,"cluster_issuer":cluster_issuer}))
}

pub(super) fn planned(
    owner: &Value,
    certificate: &str,
    previous: &[Snapshot],
) -> Result<(Value, Option<Value>)> {
    let id = resource_id(certificate)?;
    let (name, _) = names(&owner["owner"], &json!(id))?;
    let existing: Vec<&Value> = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| r["id"] == id.as_str())
        .collect();
    require(existing.len() <= 1, Failure::Ownership)?;
    if let Some(resource) = existing.first() {
        require(
            resource["kind"] == "service"
                && resource["owner"] == owner["owner"]
                && resource["machine"].is_null()
                && resource["path"].is_null()
                && resource["namespace"] == "cert-manager"
                && resource["name"] == name.as_str(),
            Failure::Ownership,
        )?;
        if resource["uid"].is_null() {
            for snapshot in previous {
                let resources = snapshot.request["resources"]
                    .as_array()
                    .ok_or(Failure::Integrity)?;
                if resources.iter().any(|r| r["id"] == resource["id"]) {
                    require(refused(snapshot), Failure::Ownership)?;
                }
            }
        }
        return Ok(((*resource).clone(), None));
    }
    let resource = json!({"kind":"service","id":id,"owner":owner["owner"],
        "generation":fresh()?,"machine":null,"path":null,"namespace":"cert-manager",
        "name":name,"uid":null});
    let mut successor = owner.clone();
    successor["previous_generation"] = successor["generation"].clone();
    successor["generation"] = json!(fresh()?);
    successor["created_ms"] = json!(now()?);
    successor["resources"]
        .as_array_mut()
        .ok_or(Failure::Integrity)?
        .push(resource.clone());
    Ok((resource, Some(successor)))
}

#[allow(clippy::too_many_arguments)]
fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    certificate: &str,
    declared: &Certificate,
    resource: &Value,
    issuer_resource: &Value,
    stage: &str,
    origins: &Value,
) -> Result<Value> {
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let anchor = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == ANCHOR)
        .ok_or(Failure::Ownership)?;
    let (certificate_name, secret_name) = names(&owner["owner"], &resource["id"])?;
    let (duration, renew_before) = lifetime(declared);
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"first_server":members.first().ok_or(Failure::Integrity)?,
        "anchor_uid":anchor["uid"],"version":context.selected.declaration.version,
        "certificate":certificate,"resource":resource,"certificate_name":certificate_name,
        "secret_name":secret_name,"issuer":{"name":declared.issuer,
            "cluster_issuer_name":issuer::cluster_issuer_name(&owner["owner"], &issuer_resource["id"])?,
            "secret_name":issuer_resource["name"]},
        "spec":{"dns_names":declared.dns_names,"duration_s":duration,"renew_before_s":renew_before},
        "stage":stage,"origins":origins,"profile_sha256":context.fingerprints["profile_sha256"]});
    schema::validate(&canonical(&recipe)?, "CertificateRecipe", 32_768)?;
    Ok(recipe)
}

fn fits(request: &Value, attempt: &str, count: usize, recipe: &Value) -> Result<()> {
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let mut binding = network::read_binding(request, attempt, last, 0)?;
    binding["receiver_generation"] = json!(u64::MAX);
    let wide = "f".repeat(128);
    let record = json!({"kind":"ClusterIssuer","namespace":"cert-manager","name":"f".repeat(58),
        "uid":wide,"class":"owned-drifted","spec_sha256":"0".repeat(64)});
    let time = "0000-00-00T00:00:00Z";
    let preflight = json!({"objects":[record,record,record],"certificate":{
        "ready":{"state":"not-ready","reason":"unobservable"},
        "issued":{"not_before":time,"not_after":time,"renewal_time":time,"chain_not_after":time,
            "renewal":"scheduled","last_failure_time":time}}});
    let header = json!({"protocol":FAMILY.protocol,"version":1,"action":"create-object",
        "request_id":fresh()?,"binding":binding,"remaining_ms":7_200_000,"recipe":recipe,
        "expected":{"certificate":wide},"resource":request["resources"][0],"preflight":preflight});
    require(
        canonical(&header)?
            .len()
            .checked_add(17 + FAMILY.reserve)
            .is_some_and(|n| n <= 65_536),
        Failure::Bound,
    )
}

#[allow(clippy::too_many_arguments)]
async fn preflight(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    stage: &str,
    source_events: &[Value],
    cleanup: &mut bool,
) -> Result<()> {
    let payload =
        json!({"recipe":recipe,"expected":expected(recipe),"resource":null,"preflight":null});
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
    );
    let observed = network::invoke(
        context,
        &FAMILY,
        &network::read_binding(request, attempt, last, 0)?,
        "inspect-objects",
        &payload,
        deadline,
        None,
    )
    .await;
    *cleanup |= network::unclean(&observed.transport);
    let result = observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", super::server::refused(&result))?;
    confirms(stage, &result)?;
    network::membership_reads(context, request, attempt, last, source_events, cleanup).await
}

pub(super) fn bound_issuer(
    scope: &Value,
    previous: &[Snapshot],
    owner: &Value,
    name: &str,
) -> Result<(Value, Value)> {
    let id = issuer::resource_id(name)?;
    let resource = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == id.as_str() && r["uid"].is_string())
        .ok_or(Failure::Readiness)?
        .clone();
    let succeeded = |snapshot: &Snapshot| {
        super::report::report(scope, "show", std::slice::from_ref(snapshot))
            .is_ok_and(|r| r["outcome"] == "succeeded")
    };
    let origins = issuer::origins(previous, name, &resource, &succeeded)?;
    let cluster_issuer = origins["cluster_issuer"].clone();
    require(!cluster_issuer.is_null(), Failure::Readiness)?;
    Ok((resource, cluster_issuer))
}

fn issuer_ready(
    previous: &[Snapshot],
    resource: &Value,
    report: &dyn Fn(&Snapshot) -> Result<Value>,
) -> Result<()> {
    let latest = previous
        .iter()
        .filter(|s| {
            s.request["action"] == "reconcile-issuer"
                && s.request["resources"][0]["id"] == resource["id"]
        })
        .max_by_key(|s| s.request["created_ms"].as_u64())
        .ok_or(Failure::Readiness)?;
    require(
        report(latest)?["readiness"]["services"] == "unobserved",
        Failure::Readiness,
    )
}

fn staged(
    origins: Result<Value>,
    ready: impl FnOnce() -> Result<()>,
    budget: impl FnOnce() -> Result<()>,
) -> Result<(Value, &'static str)> {
    let origins = origins?;
    let stage = stage(&origins);
    if stage == "create" {
        ready()?;
        budget()?;
    }
    Ok((origins, stage))
}

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
    certificate: &str,
) -> super::ExecutionResult<(Box<Session<'a>>, Value, &'static str)> {
    let context = rpc::Context::new(project, policy, target)?;
    let declared = gates(&context.selected.declaration.infrastructure, certificate)?;
    let mut local = Local::new(&context)?;
    let prepared: Result<_> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e| e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()
                && v.iter().all(|m| m["node_uid"].is_string())), Failure::Ownership)?;
        let report = |snapshot: &Snapshot| {
            super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        };
        for snapshot in &previous {
            super::session::settled(&report(snapshot)?)?;
        }
        issuer::prerequisites(&context.scope, &previous, &owner)?;
        let (issuer_resource, cluster_issuer) =
            bound_issuer(&context.scope, &previous, &owner, &declared.issuer)?;
        let (resource, pending_owner) = planned(&owner, certificate, &previous)?;
        let fixed = origins(&previous, &resource, &cluster_issuer).and_then(|origins| {
            require((stage(&origins) == "create") == resource["uid"].is_null(), Failure::Ownership)?;
            Ok(origins)
        });
        let (origins, stage) = staged(fixed, || issuer_ready(&previous, &issuer_resource, &report), || {
            let machine = owner["members"][0]["machine"].as_str().ok_or(Failure::Integrity)?;
            let target = context.inventory.machines.iter().find(|m| m.name == machine)
                .ok_or(Failure::Configuration)?;
            let script = context.inventory.scripts.get(&context.selected.declaration.lifecycle_script)
                .ok_or(Failure::Configuration)?;
            let remaining = context.clock.deadline()
                .saturating_duration_since(tokio::time::Instant::now()).as_secs();
            issuer::budget(context.selected.step_timeout.seconds,
                script.timeout.as_ref().map_or(target.timeouts.command.seconds, |d| d.seconds),
                remaining)
        })?;
        context.authenticate_owned(&json!(super::survivors(&owner)?)).await?;
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let members = super::survivors(&current_owner)?;
        let participants = super::participants(&json!(members))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let mut survivors = current_owner.clone();
        survivors["members"] = json!(members);
        let certificate_recipe = recipe(&context, &survivors, &operation, certificate, &declared,
            &resource, &issuer_resource, stage, &origins)?;
        let created = now()?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-certificate",
            "members":members,"cluster":current_owner["cluster"],"resources":[resource],
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let count = issuer::step_count(&members, effects(stage))?;
        fits(&request, &attempt_id, count, &certificate_recipe)?;
        let mut cleanup = false;
        let checked = preflight(&context, &request, &attempt_id, count as u64, &certificate_recipe, stage,
            &source_events, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_certificate(successor)).await?;
            require(local.snapshot()?.owner["resources"].as_array()
                .is_some_and(|resources| resources.last() == Some(&resource)), Failure::Ownership)?;
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
        local.work(move |store| store.create(stored_owner, request, stored_attempt)).await?;
        for event in std::iter::once(json!({"type":"certificate-recipe","recipe":certificate_recipe}))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members, attempt_id, certificate_recipe, stage))
    }.await;
    let (members, attempt_id, certificate_recipe, stage) = match prepared {
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
        Box::new(Session {
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
        }),
        certificate_recipe,
        stage,
    ))
}

pub(super) fn resumed(
    snapshot: &Snapshot,
    steps: &[Value],
    recipe: &Value,
) -> (Value, Option<Value>) {
    let mut values = expected(recipe);
    let created = steps
        .iter()
        .find(|s| s["action"] == action("create-object"))
        .and_then(|step| issuer::recorded(snapshot, step, "receiver").ok())
        .map(|o| o["event"]["receipt"].clone())
        .filter(|r| r["outcome"] == "succeeded" && r["effect"] == "complete");
    if let Some(receipt) = &created {
        values["certificate"] = receipt["resource_identity"].clone();
    }
    (values, created)
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
        .find(|s| s["action"] == action("inspect-objects"))
    else {
        return Ok(());
    };
    let snapshot = local.snapshot()?.clone();
    let create = original
        .steps
        .iter()
        .find(|s| s["action"] == action("create-object"));
    let (values, created) = resumed(&snapshot, &original.steps, recipe);
    let payload = json!({"recipe":recipe,"expected":values,"resource":null,"preflight":null});
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
    local
        .append(
            Some(inspect_step),
            json!({"type":"certificate-observation","member":null,"objects":result["objects"],
                "certificate":result["certificate"],"services":result["services"]}),
            Some(&original.request["members"][0]["machine"]),
            Value::Null,
        )
        .await?;
    let (Some(step), Some(receipt)) = (create, created) else {
        return Ok(());
    };
    let uid = &receipt["resource_identity"];
    let prior = snapshot.owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == step["resource"]["id"])
        .ok_or(Failure::Ownership)?;
    if prior["uid"].is_string() {
        return require(prior["uid"] == *uid, Failure::Ownership);
    }
    require(
        result["objects"][0]["uid"] == *uid && result["objects"][0]["class"] == "owned",
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
    async fn certificate_read(
        &mut self,
        recipe: &Value,
        recipe_seq: &Value,
        expected: &Value,
        cited: &[Value],
    ) -> Result<Value> {
        let mut refs: Vec<Value> = std::iter::once(recipe_seq.clone())
            .chain(cited.iter().cloned())
            .collect();
        refs.sort_by_key(Value::as_u64);
        refs.dedup();
        let payload = json!({"recipe":recipe,"expected":expected,"resource":null,"preflight":null});
        Ok(self
            .family_step(0, "inspect-objects", payload, refs)
            .await?
            .1)
    }

    async fn certificate_effect(
        &mut self,
        recipe: &Value,
        recipe_seq: &Value,
        expected: &Value,
        resource: &Value,
    ) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let latest = snapshot
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == "certificate-observation" && !o["event"]["services"].is_null()
            })
            .ok_or(Failure::Integrity)?
            .clone();
        let mut refs = vec![
            recipe_seq.clone(),
            network::latest_sequence(snapshot, "server-membership")?,
            latest["sequence"].clone(),
        ];
        if self.members.iter().any(|member| member["role"] == "agent") {
            refs.push(network::latest_sequence(snapshot, "agent-membership")?);
        }
        refs.sort_by_key(Value::as_u64);
        refs.dedup();
        let preflight = json!({"objects":latest["event"]["objects"],
            "certificate":latest["event"]["certificate"]});
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight});
        self.family_step(0, "create-object", payload, refs).await
    }

    async fn certificate_run(&mut self, recipe: Value, stage: &str) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, "certificate-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let resource = request["resources"][0].clone();
        let mut values = expected(&recipe);
        let mut cited: Vec<Value> = Vec::new();
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
            .certificate_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms(stage, &first)?;
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
            .certificate_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms(stage, &second)?;
        if stage == "create" {
            let (step, created) = self
                .certificate_effect(&recipe, &recipe_seq, &values, &resource)
                .await?;
            if self.mode == Mode::SettlementOnly {
                self.deselect_read(
                    "inspect",
                    json!({"subject":"dispatch","dispatch":step["dispatch"],"resource":null}),
                    Vec::new(),
                )
                .await?;
                let payload =
                    json!({"recipe":recipe,"expected":values,"resource":null,"preflight":null});
                for _ in 0..2 {
                    self.deselect_read(
                        &action("inspect-objects"),
                        payload.clone(),
                        vec![recipe_seq.clone()],
                    )
                    .await?;
                }
                return self.settle(&order).await;
            }
            let uid = created["terminal"]["resource_identity"].clone();
            require(
                uid.as_str().is_some_and(protocol::opaque),
                Failure::Ownership,
            )?;
            let receipt = self
                .inspect_step(0, "dispatch", step["dispatch"].clone(), Value::Null)
                .await?;
            require(receipt["status"] == "ok", Failure::Ownership)?;
            values["certificate"] = uid.clone();
            cited.push(
                issuer::recorded(self.local.snapshot()?, &step, "receiver")?["sequence"].clone(),
            );
            let read = self
                .certificate_read(&recipe, &recipe_seq, &values, &cited)
                .await?;
            require(
                read["objects"][0]["class"] == "owned" && read["objects"][0]["uid"] == uid,
                Failure::Ownership,
            )?;
            let mut published = resource.clone();
            published["uid"] = uid;
            self.append(
                &step,
                json!({"type":"identity","member":null,"cluster":cluster,
                    "resources":[published],"readiness":super::report::readiness()}),
                false,
                Value::Null,
            )
            .await?;
            super::ingress::publish(&mut self.local, &published).await?;
        }
        let last = self
            .certificate_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms("observe", &last)?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
    certificate: &str,
) -> super::ExecutionResult<Snapshot> {
    let (mut session, recipe, stage) = begin(project, policy, target, certificate).await?;
    let result = Box::pin(session.certificate_run(recipe, stage)).await;
    session.local.complete(result, &session.context.clock).await
}

