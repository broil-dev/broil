// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::network::{self, Family};
use super::provenance::undispatched_transport;
use super::release::{
    EVIDENCE, HOOK, OBSERVATION, RECIPE, SETTLEMENT, applied_release, event, lifecycle_envelope,
    list, ordered, roles,
};
use super::release_delivery::{
    self as delivery, Leaf, Refused, Reported, owned, records, refused, releases, settled,
    store_usage,
};
use super::release_hooks;
use super::release_secret;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::release::{self, record};
use crate::k3s::{PROFILE, RELEASE, delivery as rules};
use broil_config::LoadedProject;
use broil_core::applications::{Hook, HookLocation};
use broil_core::images::SecretReference;
use broil_core::remote::DurationValue;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "release",
    protocol: "broil-k3s-release",
    magic: b"BK3SREL1\n",
    header: "ReleaseHeader",
    result: "ReleaseResult",
    body: RELEASE,
    planned: 0,
    reserve: 0,
    version: 1,
};

const TAGS: [&str; 4] = [
    "discover-kinds",
    "apply-objects",
    "inspect-workloads",
    "observe-release",
];
const WORKLOADS: [(&str, &str); 6] = [
    ("apps/v1", "Deployment"),
    ("apps/v1", "StatefulSet"),
    ("apps/v1", "DaemonSet"),
    ("apps/v1", "ReplicaSet"),
    ("batch/v1", "Job"),
    ("v1", "Pod"),
];
const READ_MARGIN: Duration = Duration::from_secs(5);

fn action(tag: &str) -> String {
    format!("lifecycle:release-{tag}")
}


fn documents(input: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(input).map_err(|_| Failure::Integrity)?;
    let mut documents = Vec::new();
    let mut current = String::new();
    let flush = |current: &mut String, documents: &mut Vec<String>| {
        let meaningful: String = current
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .collect();
        if !meaningful.is_empty() && !matches!(meaningful.trim(), "null" | "~") {
            documents.push(std::mem::take(current));
        }
        current.clear();
    };
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end_matches(['\r', '\n']);
        if bare == "---" || bare.starts_with("--- ") {
            flush(&mut current, &mut documents);
            if let Some(rest) = bare.strip_prefix("--- ").filter(|r| !r.trim().is_empty()) {
                current.push_str(rest);
                current.push('\n');
            }
        } else if bare == "..." {
            flush(&mut current, &mut documents);
        } else {
            current.push_str(line);
        }
    }
    flush(&mut current, &mut documents);
    Ok(documents)
}

struct Ordered {
    objects: Vec<Value>,
    documents: Vec<Vec<u8>>,
    namespace_first: bool,
}

fn order(record: &Value, manifests: &[u8]) -> Result<Ordered> {
    let objects = list(&record["manifests"]["objects"]).to_vec();
    let documents = documents(manifests)?;
    require(documents.len() == objects.len(), Failure::Integrity)?;
    let namespace = &record["namespace"];
    let position = objects.iter().position(|o| {
        o["kind"] == "Namespace" && o["api_version"] == "v1" && o["name"] == *namespace
    });
    let mut indices: Vec<usize> = (0..objects.len()).collect();
    if let Some(position) = position {
        indices.remove(position);
        indices.insert(0, position);
    }
    let body = |document: &str| {
        let mut bytes = b"---\n".to_vec();
        bytes.extend_from_slice(document.as_bytes());
        if !document.ends_with('\n') {
            bytes.push(b'\n');
        }
        bytes
    };
    Ok(Ordered {
        objects: indices.iter().map(|&i| objects[i].clone()).collect(),
        documents: indices.iter().map(|&i| body(&documents[i])).collect(),
        namespace_first: position.is_some(),
    })
}

impl Ordered {
    fn parts(&self) -> Vec<Value> {
        self.objects
            .iter()
            .zip(&self.documents)
            .map(|(object, document)| {
                let mut part = identity(object);
                part["document"] = json!(String::from_utf8_lossy(document));
                part
            })
            .collect()
    }

    fn workload_groups(&self, namespace: &Value) -> Vec<Vec<Value>> {
        let workloads: Vec<Value> = self
            .objects
            .iter()
            .filter(|o| workload(o))
            .map(|o| {
                let mut w = identity(o);
                if w["namespace"].is_null() {
                    w["namespace"] = namespace.clone();
                }
                w
            })
            .collect();
        workloads
            .chunks(release::WORKLOAD_GROUP)
            .map(<[Value]>::to_vec)
            .collect()
    }
}

fn identity(object: &Value) -> Value {
    json!({"api_version":object["api_version"],"kind":object["kind"],
        "namespace":object["namespace"],"name":object["name"]})
}

fn workload(object: &Value) -> bool {
    WORKLOADS
        .iter()
        .any(|(v, k)| object["api_version"] == *v && object["kind"] == *k)
}

pub(super) fn workload_group_count(record: &Value) -> usize {
    list(&record["manifests"]["objects"])
        .iter()
        .filter(|o| workload(o))
        .count()
        .div_ceil(release::WORKLOAD_GROUP)
}


fn recorded_hook(entry: &Value) -> Result<Hook> {
    let text = |key: &str| {
        entry[key]
            .as_str()
            .map(str::to_owned)
            .ok_or(Failure::Integrity)
    };
    let location = match entry["location"].as_str() {
        Some("controller") => HookLocation::Controller,
        Some(machine) => HookLocation::Machine(machine.to_owned()),
        None => return Err(Failure::Integrity),
    };
    let seconds = entry["timeout_ms"].as_u64().ok_or(Failure::Integrity)? / 1000;
    Ok(Hook {
        name: text("name")?,
        location,
        argv: list(&entry["argv"])
            .iter()
            .map(|a| a.as_str().map(str::to_owned).ok_or(Failure::Integrity))
            .collect::<Result<_>>()?,
        timeout: DurationValue {
            source: format!("{seconds}s"),
            seconds,
        },
        repeatable: entry["repeatable"] == true,
        secrets: list(&entry["secrets"])
            .iter()
            .map(|s| {
                Ok((
                    s["variable"].as_str().ok_or(Failure::Integrity)?.to_owned(),
                    SecretReference {
                        set: s["set"].as_str().ok_or(Failure::Integrity)?.to_owned(),
                        key: s["key"].as_str().ok_or(Failure::Integrity)?.to_owned(),
                    },
                ))
            })
            .collect::<Result<_>>()?,
    })
}

fn latest_run<'s>(previous: &'s [Snapshot], release: &Value, name: &Value) -> Option<&'s Value> {
    ordered(
        previous
            .iter()
            .filter(|s| applied_release(s) == Some(release))
            .collect(),
    )
    .into_iter()
    .find_map(|s| {
        s.observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == HOOK
                    && o["event"]["stage"] == "before_apply"
                    && o["event"]["name"] == *name
            })
            .map(|o| &o["event"])
    })
}

fn settleable(snapshot: &Snapshot, release: &Value) -> Option<Vec<Value>> {
    if snapshot.request["action"] != "release-apply"
        || applied_release(snapshot) != Some(release)
        || event(snapshot, SETTLEMENT).is_some()
    {
        return None;
    }
    let unknown: Vec<Value> = snapshot
        .observations
        .iter()
        .filter(|o| {
            o["event"]["type"] == HOOK
                && o["event"]["stage"] == "before_apply"
                && o["event"]["outcome"] == "unknown"
        })
        .map(|o| o["event"]["name"].clone())
        .collect();
    let retired = list(&snapshot.request["members"]).iter().all(|member| {
        snapshot.steps.iter().any(|s| {
            s["action"] == "retire-writer"
                && s["recipient"] == *member
                && snapshot.observations.iter().any(|o| {
                    o["step"] == s["step"]
                        && o["attempt"] == s["attempt"]
                        && o["event"]["type"] == "receiver"
                        && o["event"]["receipt"]["outcome"] == "succeeded"
                })
        })
    });
    let cleaned = super::report::summary(snapshot)["cleanup_unknown"] == false;
    (!unknown.is_empty() && retired && cleaned).then_some(unknown)
}


struct Admission {
    owner: Value,
    members: Vec<Value>,
    recipe: Value,
    count: usize,
    record: Value,
    ordered: Ordered,
    hooks: Vec<(Value, &'static str)>,
    required: Vec<usize>,
    api_server: usize,
    settles: Option<(String, Vec<Value>, Value)>,
    from: Value,
    resources: Vec<Value>,
}

#[derive(Clone, Copy)]
enum Subject<'a> {
    Apply(&'a str),
    Rollback(&'a str),
}

struct Observed {
    settles: Option<(String, Vec<Value>)>,
    approval: Option<String>,
    hooks: Vec<(Value, &'static str)>,
}

fn decision(
    context: &rpc::Context<'_>,
    owner: &Value,
    record: &Value,
    members: &[Value],
    settles: &(String, Vec<Value>),
    hooks: &[(Value, &'static str)],
) -> Result<String> {
    let decision = json!({"schema":1,"scope":context.scope,"owner":owner["owner"],
        "action":"release-apply","release":record["release"],
        "release_sha256":record::release_sha256(record),
        "settles":{"operation":settles.0,"hooks":settles.1.iter()
            .map(|n| json!({"name":n,"outcome":"unknown"})).collect::<Vec<_>>()},
        "hooks":hooks.iter().map(|(h, a)| json!({"action":a,"name":h["name"],"stage":"before_apply"}))
            .collect::<Vec<_>>(),
        "objects_sha256":record["manifests"]["sha256"],"members":members,
        "fingerprints":context.fingerprints});
    Ok(format!(
        "sha256:{}",
        hash("broil-infra-approval-v1", &decision)?
    ))
}

fn observe(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    members: &[Value],
    record: &Value,
    target: &str,
    rollback: bool,
) -> Leaf<Observed> {
    let release = &record["release"];
    let mut candidate = None;
    let mut others = Vec::new();
    for snapshot in previous {
        let summary = super::report::summary(snapshot);
        let unsettled = !matches!(
            summary["outcome"].as_str(),
            Some("succeeded" | "failed" | "cancelled")
        ) || summary["completion_unknown"] != false
            || summary["cleanup_unknown"] != false;
        if !unsettled {
            continue;
        }
        match settleable(snapshot, release) {
            Some(names) if !rollback && candidate.is_none() => {
                candidate = Some((
                    snapshot.request["operation"]
                        .as_str()
                        .unwrap_or("")
                        .to_owned(),
                    names,
                ));
            }
            _ => others.push(snapshot.clone()),
        }
    }
    settled(&others, target)?;
    let mut hooks = Vec::new();
    if !rollback {
        for entry in list(&record["hooks"])
            .iter()
            .filter(|h| h["stage"] == "before_apply")
        {
            let plan = match latest_run(previous, release, &entry["name"]).map(|e| &e["outcome"]) {
                Some(outcome) if outcome == "succeeded" => "skip",
                Some(outcome) if outcome == "unknown" => "rerun",
                _ => "run",
            };
            hooks.push((entry.clone(), plan));
        }
    }
    let approval = match &candidate {
        Some(settles)
            if settles.1.iter().any(|name| {
                list(&record["hooks"]).iter().any(|h| {
                    h["stage"] == "before_apply" && h["name"] == *name && h["repeatable"] != true
                })
            }) =>
        {
            Some(decision(context, owner, record, members, settles, &hooks)?)
        }
        _ => None,
    };
    Ok(Observed {
        settles: candidate,
        approval,
        hooks,
    })
}

fn hook_unknown(target: &str, record: &Value, settles: &(String, Vec<Value>)) -> Refused {
    let name = settles
        .1
        .iter()
        .find(|name| {
            list(&record["hooks"])
                .iter()
                .any(|h| h["name"] == **name && h["repeatable"] != true)
        })
        .and_then(Value::as_str)
        .unwrap_or("");
    refused(
        Failure::Readiness,
        "hook-unknown",
        format!(
            "hook {name} has an unknown earlier outcome and is not repeatable; run k3s plan {target} --action release-apply --release {} --observe",
            record["release"].as_str().unwrap_or("")
        ),
    )
}

fn manifests(context: &rpc::Context<'_>, record: &Value) -> Leaf<Vec<u8>> {
    let path = delivery::release_store(context)?
        .join(record["release"].as_str().ok_or(Failure::Integrity)?)
        .join("manifests.yaml");
    let bytes = std::fs::read(path).map_err(|_| Failure::Storage)?;
    require(
        record["manifests"]["sha256"] == release::sha256_hex(&[&bytes]),
        Failure::Integrity,
    )?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
async fn admit(
    project: &LoadedProject,
    context: &rpc::Context<'_>,
    local: &mut Local,
    target: &str,
    subject: Subject<'_>,
    approve: Option<&str>,
) -> Leaf<(Admission, Vec<Snapshot>, usize)> {
    let (previous, owner) = records(local).await?;
    let stored = releases(context)?;
    let declared = |application: &str| -> Leaf<()> {
        let found = project
            .config
            .environments
            .get(&context.policy.environment)
            .and_then(|e| e.applications.get(application))
            .is_some_and(|a| a.target == target);
        if found {
            return Ok(());
        }
        Err(refused(
            Failure::Configuration,
            "application",
            format!(
                "{application} is not declared for target {target} in environment {}",
                context.policy.environment
            ),
        ))
    };
    if let Subject::Rollback(application) = subject {
        declared(application)?;
    }
    let (record, from) = match subject {
        Subject::Apply(id) => (
            stored
                .iter()
                .find(|r| r["release"] == id)
                .cloned()
                .ok_or_else(|| {
                    refused(
                        Failure::Configuration,
                        "release",
                        format!("{id} is not recorded for target {target}"),
                    )
                })?,
            Value::Null,
        ),
        Subject::Rollback(application) => {
            let roles = roles(&previous, &stored, application);
            let record = stored
                .iter()
                .find(|r| !roles["rollback"].is_null() && r["release"] == roles["rollback"])
                .cloned()
                .ok_or_else(|| {
                    refused(
                        Failure::Readiness,
                        "rollback",
                        format!("application {application} has no rollback release"),
                    )
                })?;
            (record, roles["active"].clone())
        }
    };
    declared(record["application"].as_str().unwrap_or(""))?;
    require(
        record["scope"] == context.scope
            && record["target"]["owner"] == owner["owner"]
            && record["target"]["cluster"] == owner["cluster"],
        Failure::Ownership,
    )?;
    let members = owned(context, &owner)?;
    let rollback = matches!(subject, Subject::Rollback(_));
    let observed = observe(
        context, &previous, &owner, &members, &record, target, rollback,
    )?;
    if let Some(settles) = &observed.settles {
        if observed.approval.is_some() && approve.is_none() {
            return Err(hook_unknown(target, &record, settles));
        }
    }
    if approve.is_some() && observed.approval.as_deref() != approve {
        return Err(refused(
            Failure::Ownership,
            "stale-approval",
            format!(
                "the observed plan changed; run k3s plan {target} --action release-apply --release {} --observe",
                record["release"].as_str().unwrap_or("")
            ),
        ));
    }
    let resources = release_secret::resources(&record, &owner)?;
    let removed: Vec<Value> = list(&owner["removed"])
        .iter()
        .map(|r| r["member"].clone())
        .collect();
    let set = rules::required_set(&json!({"policy_members":record["policy"]["members"],
        "removed":removed}))?;
    let mut required = Vec::new();
    for name in list(&set["required"]) {
        required.push(
            members
                .iter()
                .position(|m| m["member"] == *name)
                .ok_or(Failure::Ownership)?,
        );
    }
    let api_server = members
        .iter()
        .position(|m| m["role"] == "server")
        .ok_or(Failure::Ownership)?;
    let bytes = manifests(context, &record)?;
    let ordered = order(&record, &bytes)?;
    let chunks = release::chunks(&ordered.parts(), ordered.namespace_first)?;
    let step_ms = context.selected.step_timeout.seconds * 1000;
    for hook in list(&record["hooks"]) {
        if hook["timeout_ms"].as_u64().unwrap_or(u64::MAX) > step_ms {
            return Err(refused(
                Failure::Bound,
                "size",
                format!(
                    "hook {} has a {} ms timeout; the target's step timeout is {step_ms} ms",
                    hook["name"].as_str().unwrap_or(""),
                    hook["timeout_ms"]
                ),
            ));
        }
    }
    let health_ms = record["health_timeout_ms"].as_u64().unwrap_or(0);
    if step_ms < health_ms + 60_000 {
        return Err(refused(
            Failure::Bound,
            "size",
            format!(
                "the health timeout needs a step timeout of at least {} ms; the target's is {step_ms} ms",
                health_ms + 60_000
            ),
        ));
    }
    let operation = format!("infra-operation-{}", fresh()?);
    let hooks: Vec<Value> = observed
        .hooks
        .iter()
        .map(|(h, a)| json!({"stage":"before_apply","name":h["name"],"sha256":h["sha256"],"action":a}))
        .chain(
            list(&record["hooks"])
                .iter()
                .filter(|h| h["stage"] == "health")
                .map(|h| json!({"stage":"health","name":h["name"],"sha256":h["sha256"],"action":"run"})),
        )
        .collect();
    let mut recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],
        "action":if rollback {"release-rollback"} else {"release-apply"},
        "api_server":members[api_server],"release":record["release"],
        "release_sha256":record::release_sha256(&record),"application":record["application"],
        "namespace":record["namespace"],"required":set["required"],"excluded":set["excluded"],
        "objects_sha256":record["manifests"]["sha256"],"chunks":chunks,
        "secrets":release_secret::recipe_secrets(&record, &resources),
        "hooks":hooks,"settles":observed.settles.as_ref().map(|s| json!(s.0)),"version":1,
        "profile_sha256":context.fingerprints["profile_sha256"]});
    release::check_recipe(&recipe)?;
    schema::validate(&canonical(&recipe)?, "ReleaseRecipe", release::RECIPE_LIMIT)?;
    let runs = observed.hooks.iter().filter(|(_, a)| *a != "skip").count();
    let health = list(&record["hooks"])
        .iter()
        .filter(|h| h["stage"] == "health")
        .count();
    let workloads = ordered.objects.iter().filter(|o| workload(o)).count();
    let count = release::apply_steps(&json!({"participants":members.len(),
        "required":required.len(),"secrets":list(&record["secrets"]).len(),
        "chunks":chunks.len(),"workloads":workloads,"before_apply":runs,"health":health}))?;
    release::report_price(&release::report_input(
        &record,
        if rollback { "rollback" } else { "apply" },
        list(&set["required"]),
        list(&set["excluded"]),
    ))?;
    recipe["attempt"] = json!(fresh()?);
    let stored_count = stored.len();
    Ok((
        Admission {
            owner,
            members,
            recipe,
            count,
            record,
            ordered,
            hooks: observed.hooks,
            required,
            api_server,
            settles: observed.settles.map(|(operation, names)| {
                (operation, names, approve.map_or(Value::Null, |a| json!(a)))
            }),
            from,
            resources,
        },
        previous,
        stored_count,
    ))
}

fn request(
    context: &rpc::Context<'_>,
    admission: &Admission,
    created: u64,
    sequence: u64,
    resources: &[Value],
) -> Value {
    let owner = &admission.owner;
    json!({"schema":2,"kind":"request","scope":context.scope,"owner":owner["owner"],
        "operation":admission.recipe["operation"],"created_ms":created,"sequence":sequence,
        "action":admission.recipe["action"],"members":admission.members,"cluster":owner["cluster"],
        "resources":resources,"config":context.config,"references":context.references,"consumer":null,
        "fingerprints":context.fingerprints,"participants_sha256":owner["participants_sha256"],
        "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
        "step_timeout_ms":context.selected.step_timeout.seconds*1000})
}

async fn gate(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    admission: &Admission,
    provisional: &Value,
    cleanup: &mut bool,
) -> Result<Vec<Value>> {
    let operation = provisional["operation"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    let attempt = admission.recipe["attempt"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    let last = admission.count as u64;
    let sources = network::source_recipes(previous, context, &admission.owner, operation, attempt)?;
    context
        .authenticate_participants(&provisional["members"])
        .await?;
    network::membership_reads(context, provisional, attempt, last, &sources, cleanup).await?;
    let mut resources = admission.resources.clone();
    if resources.is_empty() {
        return Ok(resources);
    }
    let record = &admission.record;
    let mut recipe = admission.recipe.clone();
    recipe
        .as_object_mut()
        .ok_or(Failure::Integrity)?
        .remove("attempt");
    let names: Vec<Value> = list(&record["secrets"])
        .iter()
        .map(|s| s["secret"].clone())
        .collect();
    let payload = json!({"recipe":recipe,
        "expected":{"namespace":record["namespace"],"kinds":[],"secrets":names},"wait_ms":null});
    let deadline = context.clock.deadline().min(
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds),
    );
    let observed = network::invoke(
        context,
        &FAMILY,
        &network::read_binding(provisional, attempt, last, admission.api_server)?,
        "observe-release",
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
    let found = list(&result["secrets"]);
    require(found.len() == resources.len(), Failure::Integrity)?;
    for (resource, seen) in resources.iter_mut().zip(found) {
        require(seen["name"] == resource["name"], Failure::Integrity)?;
        resource["uid"] = seen["uid"].clone();
    }
    Ok(resources)
}

async fn record(
    context: &rpc::Context<'_>,
    local: &mut Local,
    admission: &Admission,
    request: Value,
) -> Result<Value> {
    if let Some((operation, names, approval)) = &admission.settles {
        let settlement = json!({"schema":1,"kind":"observation","scope":context.scope,
            "owner":admission.owner["owner"],"operation":operation,"sequence":1,
            "recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
            "attempt":null,"step":null,"dispatch":null,
            "event":{"type":SETTLEMENT,"operation":operation,"approval":approval,
                "hooks":names.iter().map(|n| json!({"name":n,"outcome":"unknown"})).collect::<Vec<_>>()}});
        local.work(move |store| store.append(settlement)).await?;
    }
    let owner = &admission.owner;
    let recipe = &admission.recipe;
    let created = request["created_ms"].clone();
    let attempt = json!({"schema":1,"kind":"attempt","scope":context.scope,"owner":owner["owner"],
        "operation":recipe["operation"],"attempt":recipe["attempt"],"created_ms":created,
        "request_sha256":hash("broil-infra-request-v1",&request)?,"parent_attempt":null,
        "original_step":null,"approval":null,"steps":(1..=admission.count).collect::<Vec<_>>()});
    let mut stored = recipe.clone();
    stored
        .as_object_mut()
        .ok_or(Failure::Integrity)?
        .remove("attempt");
    let stored_owner = owner.clone();
    let stored_attempt = attempt.clone();
    local
        .work(move |store| store.create(stored_owner, request, stored_attempt))
        .await?;
    let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
        "owner":owner["owner"],"operation":recipe["operation"],"sequence":1,
        "recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
        "attempt":attempt["attempt"],"step":null,"dispatch":null,
        "event":{"type":RECIPE,"recipe":stored}});
    local.work(move |store| store.append(observation)).await?;
    Ok(attempt)
}


#[derive(Clone, Copy)]
struct Stop {
    failure: Failure,
    detail: &'static str,
    unknown: bool,
}

struct Reply {
    step: Value,
    result: Value,
}

struct Run<'r> {
    project: &'r LoadedProject,
    admission: &'r Admission,
    artifacts: Value,
}

enum Unit {
    Chunk(usize),
    Secret(usize),
}

impl Session<'_> {
    fn recipe_sequence(&self) -> Result<Value> {
        network::latest_sequence(self.local.snapshot()?, RECIPE)
    }

    fn sequence_of(&self, step: &Value, kind: &str) -> Result<Value> {
        self.local
            .snapshot()?
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["step"] == step["step"]
                    && o["attempt"] == step["attempt"]
                    && o["event"]["type"] == kind
            })
            .map(|o| o["sequence"].clone())
            .ok_or(Failure::Integrity)
    }

    async fn release_deselect(&mut self, step: Value) -> Result<()> {
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.append(
            &step,
            json!({"type":"dispatch","transport":undispatched_transport(),"outcome":"succeeded",
                "failure":null}),
            false,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok(())
    }

    fn hook_step(&self, stage: &str, entry: &Value) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let attempt = format!(
            "{}/{}",
            snapshot.request["operation"].as_str().unwrap_or(""),
            self.next_step
        );
        let payload = json!({"stage":stage,"name":entry["name"],"sha256":entry["sha256"],
            "attempt":attempt});
        let step = json!({"schema":1,"kind":"step","scope":snapshot.request["scope"],
            "owner":snapshot.request["owner"],"operation":snapshot.request["operation"],
            "attempt":self.attempt["attempt"],"step":self.next_step,
            "original_step":self.attempt["original_step"],"created_ms":now()?,"dispatch":fresh()?,
            "action":format!("hook:{stage}"),"recipient":null,"resource":null,
            "expected_receiver_generation":0,"request_sha256":self.attempt["request_sha256"],
            "payload_sha256":hash("broil-infra-step-v1",&payload)?,"payload_observations":[]});
        Ok((step, payload))
    }

    async fn release_hook(
        &mut self,
        project: &LoadedProject,
        stage: &'static str,
        entry: &Value,
    ) -> Result<release_hooks::Run> {
        self.context.check()?;
        let (step, payload) = self.hook_step(stage, entry)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        let snapshot = self.local.snapshot()?;
        let recipe = event(snapshot, RECIPE).ok_or(Failure::Integrity)?["recipe"].clone();
        let operation = snapshot.request["operation"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let hook = recorded_hook(entry)?;
        let target = self.context.scope["target"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let variables = release_hooks::Variables {
            target: &target,
            application: recipe["application"].as_str().unwrap_or(""),
            stage,
            run: Some((
                recipe["release"].as_str().unwrap_or(""),
                &operation,
                payload["attempt"].as_str().unwrap_or("").to_owned(),
            )),
        };
        let run =
            release_hooks::run(project, &self.context.policy, &hook, &variables, false).await?;
        self.append(
            &step,
            json!({"type":HOOK,"stage":stage,"name":entry["name"],"location":entry["location"],
                "attempt":payload["attempt"],"exit":run.exit.and_then(|c| u64::try_from(c).ok()),
                "signal":signal_name(&run.signal),"duration_ms":run.duration_ms,
                "outcome":run.outcome}),
            false,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok(run)
    }

    fn release_payload(
        &self,
        expected: Value,
        wait_ms: Value,
        data: &[u8],
    ) -> Result<(Value, Value)> {
        let recipe =
            event(self.local.snapshot()?, RECIPE).ok_or(Failure::Integrity)?["recipe"].clone();
        let header = json!({"recipe":recipe,"expected":expected,"wait_ms":wait_ms});
        let mut payload = header.clone();
        payload["payload_sha256"] = json!(release::sha256_hex(&[data]));
        Ok((header, payload))
    }

    #[allow(clippy::too_many_arguments)]
    async fn release_step(
        &mut self,
        index: usize,
        tag: &str,
        expected: Value,
        wait_ms: Option<u64>,
        data: &[u8],
        refs: Vec<Value>,
        wait_until: Option<tokio::time::Instant>,
    ) -> Result<(Reply, Option<Stop>)> {
        self.context.check()?;
        let mutation = tag == "apply-objects";
        require(!mutation || self.mode == Mode::Work, Failure::Capability)?;
        let tagged = action(tag);
        let previous = self.local.step_deadline;
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        self.local.step_deadline = Some(deadline);
        let wait = |until: Option<tokio::time::Instant>| {
            until.map_or(json!(wait_ms), |u| {
                json!(
                    u.saturating_duration_since(tokio::time::Instant::now())
                        .as_millis() as u64
                )
            })
        };
        let (header, payload) = self.release_payload(expected.clone(), wait(wait_until), data)?;
        let step = self.intended(index, &tagged, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let child = mutation.then(|| self.context.clock.for_credential_action(deadline));
        let mut header = header;
        let mut settled: Option<(Value, Value)>;
        loop {
            let observed = network::invoke_with(
                &self.context,
                &FAMILY,
                &binding,
                tag,
                &header,
                Some(data),
                deadline,
                child.as_ref(),
            )
            .await;
            self.local.completion_unknown |=
                mutation && observed.failure.is_some() && observed.transport["dispatch"] != "none";
            if observed.failure.is_some()
                || observed.response.as_ref().is_some_and(|result| {
                    result["status"] != "ok" && !(mutation && result["status"] == "failed")
                })
            {
                self.local
                    .limit_observation(self.context.clock.terminal_deadline());
            }
            self.append(
                &step,
                json!({"type":"dispatch","transport":observed.transport,
                    "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                    "failure":observed.failure.map(Failure::name)}),
                false,
                Value::Null,
            )
            .await?;
            let Some(result) = observed.response else {
                return Err(observed.failure.unwrap_or(Failure::Transport));
            };
            self.local.completion_unknown |= mutation
                && (result["status"] == "unknown" || result["terminal"]["effect"] == "unknown");
            require(
                result["kind"] == "result"
                    && (result["failure"].is_null() == (result["status"] == "ok")),
                Failure::Integrity,
            )?;
            if let Some(receipt) = result["terminal"].as_object() {
                let receipt = Value::Object(receipt.clone());
                require(
                    receipt["binding"] == binding
                        && receipt["action"] == tagged
                        && receipt["payload_sha256"] == step["payload_sha256"]
                        && receipt["resource"].is_null(),
                    Failure::Ownership,
                )?;
                self.append(
                    &step,
                    json!({"type":"receiver","receipt":receipt,"transport":observed.transport}),
                    true,
                    receipt["completed_ms"].clone(),
                )
                .await?;
            }
            let waiting = tag == "inspect-workloads"
                && result["status"] == "ok"
                && list(&result["workloads"])
                    .iter()
                    .any(|w| w["outcome"] != "succeeded")
                && !list(&result["workloads"]).iter().any(|w| {
                    matches!(w["outcome"].as_str(), Some("failed" | "paused" | "stalled"))
                })
                && list(&result["pods"]).is_empty()
                && wait_until.is_some_and(|u| {
                    tokio::time::Instant::now() + READ_MARGIN < u
                        && deadline.saturating_duration_since(tokio::time::Instant::now())
                            > Duration::from_secs(35)
                });
            settled = Some((result, observed.transport));
            if !waiting {
                break;
            }
            self.context.check()?;
            header["wait_ms"] = wait(wait_until);
        }
        self.local.step_deadline = previous;
        let (result, transport) = settled.ok_or(Failure::Integrity)?;
        let stop = if result["status"] == "ok" {
            if mutation {
                require(
                    result["terminal"]["outcome"] == "succeeded"
                        && result["terminal"]["effect"] == "complete"
                        && result["terminal"]["writer_ended"] == true,
                    Failure::Readiness,
                )?;
            }
            None
        } else if mutation
            && result["status"] == "failed"
            && result["terminal"]["outcome"] == "failed"
            && matches!(
                result["terminal"]["effect"].as_str(),
                Some("absent" | "partial")
            )
            && matches!(
                result["terminal"]["failure"].as_str(),
                Some("ownership" | "configuration")
            )
            && result["terminal"]["writer_ended"] == true
            && !network::unclean(&transport)
            && tokio::time::Instant::now() < deadline
        {
            Some(if result["terminal"]["failure"] == "ownership" {
                Stop {
                    failure: Failure::Ownership,
                    detail: "field-conflict",
                    unknown: false,
                }
            } else {
                Stop {
                    failure: Failure::Configuration,
                    detail: "rejected-object",
                    unknown: false,
                }
            })
        } else {
            self.context.clock.terminal_deadline();
            return Err(super::server::refused(&result));
        };
        if let Some(mut child) = child {
            child.complete().map_err(|_| Failure::Timeout)?;
        }
        let member = self.members[index].clone();
        self.append(
            &step,
            json!({"type":OBSERVATION,"member":member,"action":tag,
                "facts":{"kinds":result["kinds"],"objects":result["objects"],
                    "secrets":result["secrets"],"workloads":result["workloads"],"pods":result["pods"],
                    "presence":result["presence"]}}),
            true,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok((Reply { step, result }, stop))
    }

    fn recomputed(&self, admitted: &Value, position: usize) -> Result<(Vec<u8>, Vec<Value>)> {
        let recipe =
            event(self.local.snapshot()?, RECIPE).ok_or(Failure::Integrity)?["recipe"].clone();
        let stored = releases(&self.context).map_err(|r| r.failure)?;
        let record = stored
            .into_iter()
            .find(|r| r["release"] == admitted["release"])
            .ok_or(Failure::Integrity)?;
        let bytes = manifests(&self.context, &record).map_err(|r| r.failure)?;
        let ordered = order(&record, &bytes)?;
        let payloads = release::step_payloads(&recipe, &record, &ordered.parts())
            .map_err(|_| Failure::Integrity)?;
        let chunk = &list(&recipe["chunks"])
            .get(position)
            .ok_or(Failure::Integrity)?;
        let first = chunk["first"].as_u64().ok_or(Failure::Integrity)? as usize;
        let count = chunk["count"].as_u64().ok_or(Failure::Integrity)? as usize;
        let identities = ordered
            .objects
            .get(first..first + count)
            .ok_or(Failure::Integrity)?
            .iter()
            .map(identity)
            .collect();
        let payload = payloads
            .into_iter()
            .nth(position)
            .ok_or(Failure::Integrity)?;
        Ok((payload, identities))
    }

    async fn release_secret(
        &mut self,
        run: &Run<'_>,
        api: usize,
        position: usize,
        refs: Vec<Value>,
        stopped: bool,
    ) -> Result<(Option<Value>, Option<Stop>, bool)> {
        self.context.check()?;
        let record = &run.admission.record;
        let secret = list(&record["secrets"])
            .get(position)
            .ok_or(Failure::Integrity)?
            .clone();
        let request = self.local.snapshot()?.request.clone();
        let id = release_secret::resource_id(&record["application"], &secret["secret"])?;
        let resource = list(&request["resources"])
            .iter()
            .find(|r| r["id"] == id.as_str())
            .cloned()
            .ok_or(Failure::Integrity)?;
        let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
        let request_id = fresh()?;
        let admission = release_secret::admission(
            &request,
            &self.attempt["attempt"],
            &self.members[api],
            &resource,
            record,
            &secret,
            &request_id,
            &profile,
        )?;
        let mut credential =
            self.intended(api, "credential:apply-secret", &admission, refs.clone())?;
        credential["step"] = json!(self.next_step + 1);
        credential["dispatch"] = json!(request_id);
        credential["resource"] = resource.clone();
        let grant = json!({"action":"apply-secret","request_id":request_id,
            "credential_step":credential["step"],
            "admission_sha256":hash("broil-infra-credential-admission-v1",&admission)?,
            "selection_sha256":admission["selection_sha256"],"resource":resource});
        let stored = credential.clone();
        self.local.work(move |store| store.step(stored)).await?;
        if stopped {
            let admit = self.intended(api, "admit-credential", &grant, refs)?;
            self.release_deselect(admit).await?;
            self.append(
                &credential,
                json!({"type":"dispatch","transport":undispatched_transport(),
                    "outcome":"succeeded","failure":null}),
                false,
                Value::Null,
            )
            .await?;
            self.next_step += 1;
            let inspect = self.intended(
                api,
                "inspect",
                &json!({"subject":"dispatch","dispatch":request_id,"resource":null}),
                Vec::new(),
            )?;
            self.release_deselect(inspect).await?;
            return Ok((None, None, false));
        }
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let mut clock = self.context.clock.for_credential_action(deadline);
        let previous = self.local.step_deadline;
        self.local.step_deadline = Some(deadline);
        self.dispatch(api, "admit-credential", grant, refs).await?;
        let sets: Vec<String> = list(&secret["keys"])
            .iter()
            .filter_map(|k| k["set"].as_str().map(str::to_owned))
            .collect();
        let mut versions =
            super::release::Versions::new(run.project, &self.context.policy, sets).await;
        let version = list(&secret["keys"]).first().map_or(Value::Null, |k| {
            versions
                .version(
                    k["set"].as_str().unwrap_or(""),
                    k["key"].as_str().unwrap_or(""),
                    secret["secret"].as_str().unwrap_or(""),
                )
                .unwrap_or(Value::Null)
        });
        let (slots, lengths) =
            release_secret::acquire(run.project, &self.context.policy, &secret, clock.deadline())
                .await?;
        let dispatched = release_secret::dispatch(
            &self.context,
            &self.members[api],
            &admission,
            slots,
            &lengths,
            deadline,
            &clock,
        )
        .await;
        self.local.completion_unknown |=
            dispatched.failure.is_some() && dispatched.transport["dispatch"] != "none";
        self.append(
            &credential,
            json!({"type":"dispatch","transport":dispatched.transport,
                "outcome":if dispatched.failure.is_some() {"unknown"} else {"running"},
                "failure":dispatched.failure.map(Failure::name)}),
            false,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        self.local.step_deadline = previous;
        let Some((status, reply)) = dispatched.reply else {
            self.local
                .limit_observation(self.context.clock.terminal_deadline());
            return Err(dispatched.failure.unwrap_or(Failure::Transport));
        };
        let response = self
            .inspect_step(api, "dispatch", json!(request_id), Value::Null)
            .await?;
        let receipt = response["data"]["terminal"].clone();
        require(
            response["status"] == "ok" && receipt["writer_ended"] == true,
            Failure::Readiness,
        )?;
        self.append(
            &credential,
            json!({"type":"receiver","receipt":receipt,"transport":dispatched.transport}),
            true,
            receipt["completed_ms"].clone(),
        )
        .await?;
        let (fact, stop) = if status == 0 {
            require(
                receipt["outcome"] == "succeeded" && receipt["effect"] == "complete",
                Failure::Readiness,
            )?;
            (
                json!({"name":secret["secret"],"uid":reply["uid"],"outcome":reply["outcome"],
                    "version":version}),
                None,
            )
        } else if status == 2
            && receipt["outcome"] == "failed"
            && receipt["effect"] == "absent"
            && matches!(
                receipt["failure"].as_str(),
                Some("ownership" | "configuration" | "integrity")
            )
            && !network::unclean(&dispatched.transport)
            && tokio::time::Instant::now() < deadline
        {
            let stop = match receipt["failure"].as_str() {
                Some("ownership") => Stop {
                    failure: Failure::Ownership,
                    detail: "field-conflict",
                    unknown: false,
                },
                Some("configuration") => Stop {
                    failure: Failure::Configuration,
                    detail: "rejected-object",
                    unknown: false,
                },
                _ => Stop {
                    failure: Failure::Integrity,
                    detail: "secret-metadata",
                    unknown: false,
                },
            };
            (
                json!({"name":secret["secret"],"uid":resource["uid"]}),
                Some(stop),
            )
        } else {
            self.local
                .limit_observation(self.context.clock.terminal_deadline());
            return Err(Failure::Credential);
        };
        clock.complete().map_err(|_| Failure::Timeout)?;
        let changed = matches!(receipt["effect"].as_str(), Some("complete" | "partial"));
        self.append(
            &credential,
            json!({"type":OBSERVATION,"member":self.members[api],"action":"apply-secret",
                "facts":{"kinds":null,"objects":null,"secrets":[fact],"workloads":null,
                    "pods":null,"presence":null}}),
            true,
            Value::Null,
        )
        .await?;
        Ok((stop.is_some().then_some(credential), stop, changed))
    }

    async fn release_stopped(&mut self, step: &Value, stop: Stop) -> Result<()> {
        self.local.failure_detail.get_or_insert(stop.detail);
        self.append(
            step,
            json!({"type":"failure","failure":stop.failure.name(),
                "outcome":if stop.unknown {"unknown"} else {"failed"},
                "completion_unknown":stop.unknown,"cleanup_unknown":false}),
            false,
            Value::Null,
        )
        .await
    }

    async fn release_inspect(&mut self, order: &[usize]) -> Result<()> {
        let cluster = self.local.snapshot()?.request["cluster"].clone();
        for &member in order {
            let owner = self
                .inspect_step(member, "owner", Value::Null, Value::Null)
                .await?;
            require(
                owner["status"] == "ok"
                    && owner["data"]["claim"]["active_attempt"].is_null()
                    && owner["data"]["ownership"]["cluster"] == cluster
                    && owner["data"]["ownership"]["machine"]["node_uid"]
                        == self.members[member]["node_uid"],
                Failure::Ownership,
            )?;
            self.generations[member] = owner["data"]["claim"]["generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?;
            let writer = self
                .inspect_step(member, "writer", Value::Null, Value::Null)
                .await?;
            require(
                writer["status"] == "absent" || writer["status"] == "ok",
                Failure::Ownership,
            )?;
        }
        Ok(())
    }

    async fn release_acquire(&mut self, order: &[usize]) -> Result<()> {
        let cluster = self.local.snapshot()?.request["cluster"].clone();
        for &member in order {
            self.dispatch(
                member,
                "reserve-owner",
                json!({"members":self.members,"excluded":null,"cluster":cluster,
                    "fingerprints":self.context.fingerprints}),
                Vec::new(),
            )
            .await?;
        }
        for &member in order {
            self.dispatch(
                member,
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
            .await
    }

    async fn recheck(
        &mut self,
        run: &Run<'_>,
        recipe_seq: &Value,
    ) -> Result<Option<(Value, Stop)>> {
        let record = &run.admission.record;
        let references: Vec<Value> = list(&record["images"])
            .iter()
            .map(|i| i["reference"].clone())
            .collect();
        let recipe =
            event(self.local.snapshot()?, RECIPE).ok_or(Failure::Integrity)?["recipe"].clone();
        let mut failed: Option<Value> = None;
        for &index in &run.admission.required {
            let member = self.members[index]["member"].clone();
            let payload = json!({"recipe":recipe,"expected":{"references":references},
                "resource":null,"preflight":null,"wait_ms":null,"member":member});
            let step = self.intended(
                index,
                &delivery::action("inspect-images"),
                &payload,
                vec![recipe_seq.clone()],
            )?;
            if failed.is_some() {
                self.release_deselect(step).await?;
                continue;
            }
            let recorded = step.clone();
            self.local.work(move |store| store.step(recorded)).await?;
            self.local.work(|store| store.verify()).await?;
            let binding = self.local.snapshot()?.binding(&step);
            let deadline = self.context.clock.deadline().min(
                tokio::time::Instant::now()
                    + Duration::from_secs(self.context.selected.step_timeout.seconds),
            );
            let observed = network::invoke(
                &self.context,
                &delivery::FAMILY,
                &binding,
                "inspect-images",
                &payload,
                deadline,
                None,
            )
            .await;
            self.append(
                &step,
                json!({"type":"dispatch","transport":observed.transport,
                    "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                    "failure":observed.failure.map(Failure::name)}),
                false,
                Value::Null,
            )
            .await?;
            let reply = match observed.response {
                Some(reply) if reply["status"] == "ok" => reply,
                Some(reply) => return Err(super::server::refused(&reply)),
                None => return Err(observed.failure.unwrap_or(Failure::Transport)),
            };
            self.append(
                &step,
                json!({"type":"delivery-observation","member":self.members[index],"kind":"inspect",
                    "facts":{"node":reply["node"],"images":reply["images"],"closure":null,"log":null}}),
                true,
                Value::Null,
            )
            .await?;
            self.next_step += 1;
            let delivered = {
                let r = &reply;
                let platform = r["node"]["architecture"]
                    .as_str()
                    .map(|a| format!("linux/{a}"));
                list(&record["images"]).iter().all(|image| {
                    let config =
                        list(&run.artifacts[image["artifact"].as_str().unwrap_or("")]["platforms"])
                            .iter()
                            .find(|p| p["platform"].as_str() == platform.as_deref())
                            .map(|p| p["config"].clone());
                    list(&r["images"]).iter().any(|seen| {
                        seen["reference"] == image["reference"]
                            && seen["present"] == true
                            && seen["pinned"] == true
                            && config.as_ref().is_some_and(|c| seen["image_id"] == *c)
                    })
                })
            };
            if !delivered {
                failed = Some(step.clone());
            }
        }
        Ok(failed.map(|step| {
            (
                step,
                Stop {
                    failure: Failure::Readiness,
                    detail: "incomplete-delivery",
                    unknown: false,
                },
            )
        }))
    }

    async fn release_run(&mut self, run: &Run<'_>) -> Result<Snapshot> {
        let admission = run.admission;
        let record = &admission.record;
        let api = admission.api_server;
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = self.recipe_sequence()?;
        self.release_inspect(&order).await?;
        let mut stop: Option<Stop> = None;
        if let Some((step, found)) = self.recheck(run, &recipe_seq).await? {
            self.release_stopped(&step, found).await?;
            stop = Some(found);
        }
        let mut kinds: Vec<Value> = Vec::new();
        for object in &admission.ordered.objects {
            let kind = json!({"api_version":object["api_version"],"kind":object["kind"]});
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        let discovery_seq;
        if stop.is_none() {
            let (reply, _) = self
                .release_step(
                    api,
                    "discover-kinds",
                    json!({"kinds":kinds}),
                    None,
                    &[],
                    vec![recipe_seq.clone()],
                    None,
                )
                .await?;
            discovery_seq = Some(self.sequence_of(&reply.step, OBSERVATION)?);
            let facts = list(&reply.result["kinds"]);
            let scoped = admission.ordered.objects.iter().any(|o| {
                facts.iter().any(|k| {
                    k["api_version"] == o["api_version"]
                        && k["kind"] == o["kind"]
                        && k["served"] == true
                        && k["namespaced"] == false
                }) && !(o["kind"] == "Namespace" && o["name"] == record["namespace"])
            });
            let unserved = facts.iter().any(|k| k["served"] != true);
            let found = if scoped {
                Some("cluster-scoped")
            } else if unserved {
                Some("rejected-object")
            } else {
                None
            };
            if let Some(detail) = found {
                let found = Stop {
                    failure: Failure::Configuration,
                    detail,
                    unknown: false,
                };
                self.release_stopped(&reply.step, found).await?;
                stop = Some(found);
            }
        } else {
            let (_, payload) = self.release_payload(json!({"kinds":kinds}), Value::Null, &[])?;
            let step = self.intended(
                api,
                &action("discover-kinds"),
                &payload,
                vec![recipe_seq.clone()],
            )?;
            self.release_deselect(step).await?;
            discovery_seq = None;
        }
        self.release_acquire(&order).await?;
        let mut changed = false;
        for (entry, plan) in &admission.hooks {
            if *plan == "skip" {
                continue;
            }
            if stop.is_some() {
                let (step, _) = self.hook_step("before_apply", entry)?;
                self.release_deselect(step).await?;
                continue;
            }
            let ran = self
                .release_hook(run.project, "before_apply", entry)
                .await?;
            let step = self
                .local
                .snapshot()?
                .steps
                .last()
                .cloned()
                .ok_or(Failure::Integrity)?;
            let found = match ran.outcome {
                "succeeded" => None,
                "unknown" => Some(Stop {
                    failure: Failure::Transport,
                    detail: "hook-unknown",
                    unknown: true,
                }),
                _ => Some(Stop {
                    failure: if timed_out(&ran, entry) {
                        Failure::Timeout
                    } else {
                        Failure::Readiness
                    },
                    detail: "hook",
                    unknown: false,
                }),
            };
            if let Some(found) = found {
                self.release_stopped(&step, found).await?;
                stop = Some(found);
            }
        }
        let chunks = list(
            &event(self.local.snapshot()?, RECIPE).ok_or(Failure::Integrity)?["recipe"]["chunks"],
        )
        .to_vec();
        let mut applied = stop.is_none();
        let split = usize::from(admission.ordered.namespace_first).min(chunks.len());
        let units = (0..split)
            .map(Unit::Chunk)
            .chain((0..list(&record["secrets"]).len()).map(Unit::Secret))
            .chain((split..chunks.len()).map(Unit::Chunk));
        for unit in units {
            let mut refs = vec![recipe_seq.clone()];
            refs.extend(discovery_seq.clone());
            let position = match unit {
                Unit::Chunk(position) => position,
                Unit::Secret(position) => {
                    let (step, found, wrote) = self
                        .release_secret(run, api, position, refs, stop.is_some())
                        .await?;
                    changed |= wrote;
                    if let (Some(step), Some(found)) = (step, found) {
                        self.release_stopped(&step, found).await?;
                        stop = Some(found);
                        applied = false;
                    }
                    continue;
                }
            };
            let chunk = &chunks[position];
            let first = chunk["first"].as_u64().unwrap_or(0) as usize;
            let count = chunk["count"].as_u64().unwrap_or(0) as usize;
            let objects: Vec<Value> = admission.ordered.objects[first..first + count]
                .iter()
                .map(identity)
                .collect();
            let data: Vec<u8> = admission.ordered.documents[first..first + count].concat();
            let expected =
                json!({"chunk":position,"namespace":record["namespace"],"objects":objects});
            if stop.is_some() {
                let (_, payload) = self.release_payload(expected, Value::Null, &data)?;
                let step = self.intended(api, &action("apply-objects"), &payload, refs)?;
                let dispatch = step["dispatch"].clone();
                self.release_deselect(step).await?;
                let inspect = self.intended(
                    api,
                    "inspect",
                    &json!({"subject":"dispatch","dispatch":dispatch,"resource":null}),
                    Vec::new(),
                )?;
                self.release_deselect(inspect).await?;
                continue;
            }
            let (bytes, identities) = self.recomputed(record, position)?;
            require(bytes == data && identities == objects, Failure::Integrity)?;
            let (reply, found) = self
                .release_step(api, "apply-objects", expected, None, &data, refs, None)
                .await?;
            changed |= reply.result["terminal"]["effect"] == "partial"
                || list(&reply.result["objects"])
                    .iter()
                    .any(|o| matches!(o["outcome"].as_str(), Some("created" | "configured")));
            let response = self
                .inspect_step(api, "dispatch", reply.step["dispatch"].clone(), Value::Null)
                .await?;
            require(
                response["status"] == "ok" && response["data"]["terminal"]["writer_ended"] == true,
                Failure::Readiness,
            )?;
            if let Some(found) = found {
                self.release_stopped(&reply.step, found).await?;
                stop = Some(found);
                applied = false;
            }
        }
        let mut healthy = false;
        let bound: Vec<Value> = list(&record["images"])
            .iter()
            .map(|i| {
                json!({"reference":i["reference"],"root":i["root"],
                    "manifests":list(&i["platforms"]).iter().map(|p| p["manifest"].clone()).collect::<Vec<_>>()})
            })
            .collect();
        let health_ms = record["health_timeout_ms"].as_u64().unwrap_or(0);
        let until = tokio::time::Instant::now() + Duration::from_millis(health_ms);
        let step_timeout = Duration::from_secs(self.context.selected.step_timeout.seconds);
        let mut established: Option<Value> = None;
        for group in admission.ordered.workload_groups(&record["namespace"]) {
            let expected = json!({"workloads":group,"bound":bound});
            if established.is_some() {
                self.context.check()?;
            }
            let lacking = established.is_some()
                && tokio::time::Instant::now() + step_timeout > self.context.clock.deadline();
            if stop.is_some() || lacking {
                let wait = if lacking { 0 } else { health_ms };
                let (_, payload) = self.release_payload(expected, json!(wait), &[])?;
                let step = self.intended(
                    api,
                    &action("inspect-workloads"),
                    &payload,
                    vec![recipe_seq.clone()],
                )?;
                self.release_deselect(step).await?;
                continue;
            }
            let (wait, wait_until) = if established.is_some() {
                (0, None)
            } else {
                let remaining = until
                    .saturating_duration_since(tokio::time::Instant::now())
                    .as_millis() as u64;
                (remaining, Some(until))
            };
            let (reply, _) = self
                .release_step(
                    api,
                    "inspect-workloads",
                    expected,
                    Some(wait),
                    &[],
                    vec![recipe_seq.clone()],
                    wait_until,
                )
                .await?;
            let failing = !list(&reply.result["pods"]).is_empty()
                || reply.result["presence"]["truncated"] == true;
            if failing {
                self.local.failure_detail.get_or_insert("undelivered-node");
            }
            if failing || established.is_some() {
                established = Some(reply.step);
                continue;
            }
            let workloads = list(&reply.result["workloads"]);
            if workloads.iter().any(|w| w["outcome"] != "succeeded") {
                let halted = workloads.iter().any(|w| {
                    matches!(w["outcome"].as_str(), Some("failed" | "paused" | "stalled"))
                });
                let found = Stop {
                    failure: if halted {
                        Failure::Readiness
                    } else {
                        Failure::Timeout
                    },
                    detail: "rollout",
                    unknown: false,
                };
                self.release_stopped(&reply.step, found).await?;
                stop = Some(found);
            }
        }
        if let Some(step) = established.filter(|_| stop.is_none()) {
            let found = Stop {
                failure: Failure::Readiness,
                detail: "undelivered-node",
                unknown: false,
            };
            self.release_stopped(&step, found).await?;
            stop = Some(found);
        }
        let mut checks_passed = stop.is_none();
        for entry in list(&record["hooks"])
            .iter()
            .filter(|h| h["stage"] == "health")
        {
            if stop.is_some() {
                let (step, _) = self.hook_step("health", entry)?;
                self.release_deselect(step).await?;
                continue;
            }
            let ran = self.release_hook(run.project, "health", entry).await?;
            if ran.outcome != "succeeded" {
                let step = self
                    .local
                    .snapshot()?
                    .steps
                    .last()
                    .cloned()
                    .ok_or(Failure::Integrity)?;
                let found = Stop {
                    failure: if ran.outcome == "failed" && timed_out(&ran, entry) {
                        Failure::Timeout
                    } else {
                        Failure::Readiness
                    },
                    detail: "health-check",
                    unknown: false,
                };
                self.release_stopped(&step, found).await?;
                stop = Some(found);
                checks_passed = false;
            }
        }
        if stop.is_none() && checks_passed {
            healthy = true;
        }
        applied &= !matches!(
            stop.map(|s| s.detail),
            Some(
                "incomplete-delivery"
                    | "cluster-scoped"
                    | "rejected-object"
                    | "hook"
                    | "hook-unknown"
            )
        );
        let snapshot = self.local.snapshot()?;
        let evidence = json!({"schema":1,"kind":"observation","scope":snapshot.request["scope"],
            "owner":snapshot.request["owner"],"operation":snapshot.request["operation"],"sequence":1,
            "recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
            "attempt":null,"step":null,"dispatch":null,
            "event":{"type":EVIDENCE,"release":record["release"],"applied":applied,
                "healthy":healthy,"changed":changed,"detail":stop.map(|s| s.detail)}});
        self.local.work(move |store| store.append(evidence)).await?;
        self.settle(&order).await
    }
}

fn timed_out(run: &release_hooks::Run, entry: &Value) -> bool {
    !run.signal.is_null() && run.duration_ms >= entry["timeout_ms"].as_u64().unwrap_or(u64::MAX)
}

fn signal_name(signal: &Value) -> Value {
    match signal {
        Value::Number(n) => json!(format!("SIG{n}")),
        other => other.clone(),
    }
}


fn session<'a>(
    context: rpc::Context<'a>,
    local: Local,
    attempt: Value,
    members: Vec<Value>,
) -> Session<'a> {
    let generations = vec![0; members.len()];
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
    }
}

pub async fn apply(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    release: &str,
    approve: Option<&str>,
) -> Leaf<Reported> {
    operate(project, policy, target, Subject::Apply(release), approve).await
}

pub async fn rollback(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    application: &str,
) -> Leaf<Reported> {
    operate(
        project,
        policy,
        target,
        Subject::Rollback(application),
        None,
    )
    .await
}

async fn operate(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    subject: Subject<'_>,
    approve: Option<&str>,
) -> Leaf<Reported> {
    let context = rpc::Context::new(project, policy, target)?;
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let mut local = Local::new(&context)?;
    let admitted = admit(project, &context, &mut local, target, subject, approve).await;
    let (admission, previous, stored) = match admitted {
        Ok(value) => value,
        Err(refusal) => {
            let _ = local.failure(refusal.failure, &context.clock).await;
            return Err(refusal);
        }
    };
    let artifacts = match delivery::artifacts(project, &admission.record) {
        Ok(value) => value,
        Err(refusal) => {
            let _ = local.failure(refusal.failure, &context.clock).await;
            return Err(refusal);
        }
    };
    let mut admission = admission;
    let gated: Result<Value> = async {
        let created = now()?;
        let sequence = local.work(|store| store.next_sequence()).await?;
        let provisional = request(
            &context,
            &admission,
            created,
            sequence,
            &admission.resources,
        );
        let mut cleanup = false;
        let resources = gate(&context, &previous, &admission, &provisional, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        admission.resources = resources?;
        Ok(request(
            &context,
            &admission,
            created,
            sequence,
            &admission.resources,
        ))
    }
    .await;
    let recorded = match gated {
        Ok(request) => record(&context, &mut local, &admission, request).await,
        Err(failure) => Err(failure),
    };
    let attempt = match recorded {
        Ok(attempt) => attempt,
        Err(failure) => return Err(local.failure(failure, &context.clock).await.into()),
    };
    let mut session = session(context, local, attempt, admission.members.clone());
    let run = Run {
        project,
        admission: &admission,
        artifacts,
    };
    let result = Box::pin(session.release_run(&run)).await;
    session.unknown_run(&result).await;
    let detail = session.local.failure_detail;
    let finished = session.local.complete(result, &session.context.clock).await;
    let (snapshot, failed) = match finished {
        Ok(snapshot) => (Some(snapshot), None),
        Err(failure) => (failure.snapshot.map(|s| *s), Some(failure.failure)),
    };
    let snapshot = snapshot.ok_or(Failure::Integrity)?;
    let all = releases(&session.context)?;
    let store = store_usage(&previous, Some(&snapshot), &admission.members, stored);
    let mut report = report(
        &session.context,
        &previous,
        &snapshot,
        &admission,
        &all,
        store,
        detail,
    );
    if let Some(failure) = failed {
        if report["outcome"] == "unknown" && report["failure"].is_null() {
            report["failure"] = json!(failure.name());
        }
    }
    let complete = report["outcome"] == "succeeded";
    Ok((report, complete))
}

fn hook_row(snapshot: &Snapshot, entry: &Value, stage: &str, plan: &str) -> Value {
    let ran = snapshot
        .observations
        .iter()
        .rev()
        .find(|o| {
            o["event"]["type"] == HOOK
                && o["event"]["stage"] == stage
                && o["event"]["name"] == entry["name"]
        })
        .map(|o| &o["event"]);
    match ran {
        Some(e) => {
            json!({"duration_ms":e["duration_ms"],"exit":e["exit"],"location":entry["location"],
            "name":entry["name"],"outcome":e["outcome"],"stage":stage})
        }
        None => {
            json!({"duration_ms":null,"exit":null,"location":entry["location"],"name":entry["name"],
            "outcome":if plan == "skip" {"skipped"} else {"not-run"},"stage":stage})
        }
    }
}

fn replies<'s>(snapshot: &'s Snapshot, tag: &str) -> Vec<&'s Value> {
    snapshot
        .observations
        .iter()
        .filter(|o| o["event"]["type"] == OBSERVATION && o["event"]["action"] == tag)
        .collect()
}

pub(super) fn health_workloads(snapshot: &Snapshot) -> Vec<Value> {
    replies(snapshot, "inspect-workloads")
        .iter()
        .flat_map(|o| list(&o["event"]["facts"]["workloads"]).to_vec())
        .collect()
}

pub(super) fn undelivered_rows(
    snapshot: &Snapshot,
    members: &[&str],
    groups: usize,
) -> (Vec<Value>, bool) {
    let replies = replies(snapshot, "inspect-workloads");
    let rows: Vec<Vec<Value>> = replies
        .iter()
        .map(|o| {
            list(&o["event"]["facts"]["pods"])
                .iter()
                .map(|p| {
                    let member = if members.iter().any(|m| p["node"] == *m) {
                        p["node"].clone()
                    } else {
                        Value::Null
                    };
                    json!({"member":member,"namespace":p["namespace"],"pod":p["pod"],
                        "reason":p["reason"],"container":p["container"],"image_id":p["image_id"]})
                })
                .collect()
        })
        .collect();
    let node = |group: &[Value]| group.iter().any(|r| r["reason"] == "node");
    let mut order: Vec<usize> = (0..rows.len()).filter(|&g| !rows[g].is_empty()).collect();
    order.sort_by_key(|&g| (!node(&rows[g]), g));
    let mut used = 0;
    let mut omitted = false;
    let mut selected: Vec<(usize, &Value)> = Vec::new();
    for g in order {
        let size: usize = rows[g].iter().map(|r| r.to_string().len() + 1).sum();
        if used + size <= release::UNDELIVERED_BUDGET + 1 {
            used += size;
            selected.extend(rows[g].iter().map(|r| (g, r)));
        } else {
            omitted = true;
        }
    }
    selected.sort_by(|(a, x), (b, y)| {
        (
            x["reason"] != "node",
            a,
            x["namespace"].as_str(),
            x["pod"].as_str(),
        )
            .cmp(&(
                y["reason"] != "node",
                b,
                y["namespace"].as_str(),
                y["pod"].as_str(),
            ))
    });
    let established = rows.iter().any(|r| !r.is_empty());
    let cut = omitted
        || replies
            .iter()
            .any(|o| o["event"]["facts"]["presence"]["truncated"] == true);
    let uncovered = replies.len() < groups
        || health_workloads(snapshot)
            .iter()
            .any(|w| w["outcome"] != "succeeded");
    (
        selected.into_iter().map(|(_, r)| r.clone()).collect(),
        established && (cut || uncovered),
    )
}

#[allow(clippy::too_many_arguments)]
fn report(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    snapshot: &Snapshot,
    admission: &Admission,
    stored: &[Value],
    store: Value,
    detail: Option<&'static str>,
) -> Value {
    let record = &admission.record;
    let recipe = event(snapshot, RECIPE).map_or(Value::Null, |e| e["recipe"].clone());
    let rollback = recipe["action"] == "release-rollback";
    let view = if rollback {
        "release-rollback"
    } else {
        "release-apply"
    };
    let mut report = lifecycle_envelope(context, view, store);
    let summary = super::report::summary(snapshot);
    report["application"] = record["application"].clone();
    report["release"] = record["release"].clone();
    if rollback {
        report["from"] = admission.from.clone();
    }
    report["settled"] = admission
        .settles
        .as_ref()
        .map_or(Value::Null, |s| json!(s.0));
    let inspected: Vec<&Value> = snapshot
        .observations
        .iter()
        .filter(|o| o["event"]["type"] == "delivery-observation")
        .collect();
    let recheck_failed = detail == Some("incomplete-delivery");
    report["delivery_recheck"] = json!({"excluded":recipe["excluded"],"members":recipe["required"],
        "observed_ms":inspected.last().map_or(Value::Null, |o| o["recorded_ms"].clone()),
        "outcome":if inspected.is_empty() {"not-run"} else if recheck_failed {"failed"} else {"succeeded"}});
    report["hooks"] = Value::Array(
        admission
            .hooks
            .iter()
            .map(|(entry, plan)| hook_row(snapshot, entry, "before_apply", plan))
            .collect(),
    );
    report["secrets"] = json!(super::release::secret_rows(snapshot, record));
    let applied: Vec<Value> = replies(snapshot, "apply-objects")
        .into_iter()
        .flat_map(|o| list(&o["event"]["facts"]["objects"]).to_vec())
        .collect();
    report["objects"] = Value::Array(
        admission
            .ordered
            .objects
            .iter()
            .enumerate()
            .map(|(index, o)| {
                let outcome = applied
                    .get(index)
                    .map_or(json!("not-run"), |a| a["outcome"].clone());
                let namespace = if o["namespace"].is_null() && o["kind"] != "Namespace" {
                    record["namespace"].clone()
                } else {
                    o["namespace"].clone()
                };
                json!({"kind":o["kind"],"name":o["name"],"namespace":namespace,"outcome":outcome})
            })
            .collect(),
    );
    let evidence = event(snapshot, EVIDENCE);
    let groups = replies(snapshot, "inspect-workloads");
    let waited = groups.last().copied();
    let workloads = health_workloads(snapshot);
    let declared: Vec<&str> = context
        .selected
        .declaration
        .members
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    let (undelivered, truncated) = undelivered_rows(
        snapshot,
        &declared,
        admission
            .ordered
            .workload_groups(&record["namespace"])
            .len(),
    );
    let checks: Vec<Value> = list(&record["hooks"])
        .iter()
        .filter(|h| h["stage"] == "health")
        .map(|h| {
            let row = hook_row(snapshot, h, "health", "run");
            json!({"duration_ms":row["duration_ms"],"exit":row["exit"],"name":row["name"],
                "outcome":row["outcome"]})
        })
        .collect();
    let healthy = evidence.is_some_and(|e| e["healthy"] == true);
    report["health"] = json!({"checks":checks,
        "observed_ms":waited.map_or(Value::Null, |o| o["recorded_ms"].clone()),
        "outcome":if healthy {"succeeded"} else if waited.is_some() {"failed"} else {"not-run"},
        "undelivered_pods":undelivered,"undelivered_truncated":truncated,"workloads":workloads});
    report["truncated"] = json!(truncated);
    report["evidence"] = json!({"applied":evidence.is_some_and(|e| e["applied"] == true),
        "healthy":healthy});
    let mut all: Vec<Snapshot> = previous.to_vec();
    all.push(snapshot.clone());
    let roles = roles(&all, stored, record["application"].as_str().unwrap_or(""));
    report["active"] = roles["active"].clone();
    report["rollback"] = roles["rollback"].clone();
    let operation = summary["operation"].clone();
    report["outcome"] = summary["outcome"].clone();
    report["failure"] = summary["failure"].clone();
    report["completion_unknown"] = summary["completion_unknown"].clone();
    report["cleanup_unknown"] = summary["cleanup_unknown"].clone();
    report["operations"] = json!([delivery::operation_summary(snapshot)]);
    let changed = evidence.is_some_and(|e| e["changed"] == true);
    let application = record["application"].clone();
    let (choice, subject) = match (summary["outcome"].as_str(), detail) {
        (Some("succeeded"), _) => ("none", Value::Null),
        (_, Some("hook-unknown")) => {
            let hook = snapshot
                .observations
                .iter()
                .rev()
                .find(|o| o["event"]["type"] == HOOK && o["event"]["outcome"] == "unknown")
                .map(|o| o["event"]["name"].clone())
                .unwrap_or(Value::Null);
            let repeatable = list(&record["hooks"])
                .iter()
                .any(|h| h["name"] == hook && h["repeatable"] == true);
            if repeatable {
                ("resume", Value::Null)
            } else {
                ("approve", hook)
            }
        }
        (Some("unknown"), _) => {
            report["detail"] = Value::Null;
            let member = snapshot
                .steps
                .last()
                .map_or(Value::Null, |s| s["recipient"]["member"].clone());
            ("resume", member)
        }
        (_, Some("incomplete-delivery")) => ("deliver", record["release"].clone()),
        (_, Some("cluster-scoped" | "rejected-object" | "hook" | "secret-metadata")) => {
            ("rerun", Value::Null)
        }
        (_, Some("field-conflict")) if changed => ("rollback", application),
        (_, Some("field-conflict")) => ("rerun", Value::Null),
        (_, Some("rollout"))
            if list(&report["health"]["workloads"])
                .iter()
                .any(|w| w["outcome"] == "paused") =>
        {
            ("rerun", Value::Null)
        }
        (_, Some("undelivered-node"))
            if !list(&report["health"]["undelivered_pods"])
                .iter()
                .any(|p| p["reason"] == "node") =>
        {
            ("rerun", Value::Null)
        }
        (_, Some("rollout" | "undelivered-node" | "health-check")) => ("rollback", application),
        _ => ("rerun", Value::Null),
    };
    if summary["outcome"] != "unknown"
        || matches!(detail, Some("hook-unknown" | "undelivered-node"))
    {
        report["detail"] = detail.map_or(Value::Null, |d| json!(d));
    }
    if summary["outcome"] == "succeeded" {
        report["detail"] = Value::Null;
    }
    report["recovery"] = json!({"choice":choice,
        "operation":if choice == "none" {Value::Null} else {operation},"subject":subject});
    report
}

pub async fn plan(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    id: &str,
    observe: bool,
) -> Leaf<Value> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let loaded = records(&mut local).await;
    let _ = local.finish(&context.clock).await;
    let (previous, owner) = loaded?;
    let stored = releases(&context)?;
    let record = stored
        .iter()
        .find(|r| r["release"] == id)
        .cloned()
        .ok_or_else(|| {
            refused(
                Failure::Configuration,
                "release",
                format!("{id} is not recorded for target {target}"),
            )
        })?;
    let objects: Vec<Value> = list(&record["manifests"]["objects"])
        .iter()
        .map(|o| json!({"kind":o["kind"],"name":o["name"],"namespace":o["namespace"]}))
        .collect();
    let mut report = json!({"format_version":1,"scope":context.scope,"view":"plan",
        "action":"release-apply","observed":observe,"application":record["application"],
        "member":null,"release":id,"effects":null,"pods":null,"checks":null,"writer_move":null,
        "hooks":null,"objects":objects,"settles":null,"keep":null,"policy":null,"prune":null,
        "refusals":[],"approval":null,"store":null});
    let members = owned(&context, &owner)?;
    let observed = if observe {
        let mut refusals = Vec::new();
        let observed = match observe_plan(&context, &previous, &owner, &members, &record, target) {
            Ok(observed) => Some(observed),
            Err(refusal) => {
                refusals.push(
                    json!({"failure":refusal.failure.name(),"boundary":refusal.boundary,
                    "detail":refusal.detail}),
                );
                None
            }
        };
        report["refusals"] = Value::Array(refusals);
        report["store"] = store_usage(&previous, None, &members, stored.len());
        observed
    } else {
        Some(Observed {
            settles: None,
            approval: None,
            hooks: list(&record["hooks"])
                .iter()
                .filter(|h| h["stage"] == "before_apply")
                .map(|h| (h.clone(), "run"))
                .collect(),
        })
    };
    if let Some(observed) = observed {
        report["hooks"] = Value::Array(
            observed
                .hooks
                .iter()
                .map(|(h, a)| json!({"action":a,"name":h["name"],"stage":"before_apply"}))
                .chain(
                    list(&record["hooks"])
                        .iter()
                        .filter(|h| h["stage"] == "health")
                        .map(|h| json!({"action":"run","name":h["name"],"stage":"health"})),
                )
                .collect(),
        );
        report["settles"] = observed
            .settles
            .as_ref()
            .map_or(Value::Null, |(operation, names)| {
                json!({"operation":operation,"hooks":names.iter()
                .map(|n| json!({"name":n,"outcome":"unknown"})).collect::<Vec<_>>()})
            });
        report["approval"] = observed.approval.map_or(Value::Null, |a| json!(a));
    }
    Ok(report)
}

fn observe_plan(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    members: &[Value],
    record: &Value,
    target: &str,
) -> Leaf<Observed> {
    observe(context, previous, owner, members, record, target, false)
}

impl Snapshot {
    pub(super) fn release_secret_payload(&self, step: &Value) -> Result<()> {
        let refs = list(&step["payload_observations"]);
        let recipe_event = self
            .observations
            .iter()
            .find(|o| refs.first() == Some(&o["sequence"]))
            .ok_or(Failure::Integrity)?;
        require(
            recipe_event["event"]["type"] == RECIPE
                && recipe_event["operation"] == step["operation"]
                && recipe_event["attempt"] == step["attempt"],
            Failure::Ownership,
        )?;
        let recipe = &recipe_event["event"]["recipe"];
        let resource = &step["resource"];
        require(
            step["recipient"] == recipe["api_server"]
                && resource["kind"] == "application-secret"
                && list(&self.request["resources"]).contains(resource)
                && list(&recipe["secrets"])
                    .iter()
                    .any(|s| s["resource"] == resource["id"] && s["secret"] == resource["name"]),
            Failure::Ownership,
        )?;
        for sequence in &refs[1..] {
            require(
                self.observations.iter().any(|o| {
                    o["sequence"] == *sequence
                        && o["attempt"] == step["attempt"]
                        && o["event"]["type"] == OBSERVATION
                        && o["event"]["action"] == "discover-kinds"
                }),
                Failure::Integrity,
            )?;
        }
        if step["action"] == "admit-credential" {
            let id = step["step"]
                .as_u64()
                .and_then(|s| s.checked_add(1))
                .ok_or(Failure::Bound)?;
            require(
                self.steps.iter().any(|s| {
                    s["step"] == id
                        && s["attempt"] == step["attempt"]
                        && s["action"] == "credential:apply-secret"
                        && s["recipient"] == step["recipient"]
                        && s["resource"] == *resource
                }),
                Failure::Integrity,
            )?;
        }
        Ok(())
    }

    pub(super) fn release_payload(&self, step: &Value) -> Result<()> {
        let refs = list(&step["payload_observations"]);
        require(
            !refs.is_empty()
                && matches!(
                    self.request["action"].as_str(),
                    Some("release-apply" | "release-rollback")
                ),
            Failure::Integrity,
        )?;
        let observed = |sequence: &Value| -> Result<&Value> {
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == *sequence)
                .ok_or(Failure::Integrity)?;
            require(
                observation["operation"] == step["operation"]
                    && observation["attempt"] == step["attempt"],
                Failure::Ownership,
            )?;
            Ok(observation)
        };
        let recipe_event = observed(&refs[0])?;
        require(recipe_event["event"]["type"] == RECIPE, Failure::Ownership)?;
        let recipe = &recipe_event["event"]["recipe"];
        let tag = step["action"]
            .as_str()
            .and_then(|a| a.strip_prefix("lifecycle:release-"));
        let recipient = match tag {
            Some(tag) => TAGS.contains(&tag) && step["recipient"] == recipe["api_server"],
            None => {
                step["action"] == delivery::action("inspect-images")
                    && list(&recipe["required"]).contains(&step["recipient"]["member"])
            }
        };
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["action"] == self.request["action"]
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && list(&self.request["members"]).contains(&step["recipient"])
                && step["resource"].is_null()
                && recipient,
            Failure::Ownership,
        )?;
        for sequence in &refs[1..] {
            let observation = observed(sequence)?;
            require(
                tag == Some("apply-objects")
                    && observation["event"]["type"] == OBSERVATION
                    && observation["event"]["action"] == "discover-kinds",
                Failure::Integrity,
            )?;
        }
        Ok(())
    }
}

