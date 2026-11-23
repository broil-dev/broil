// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::network::{self, Family};
use super::provenance::undispatched_transport;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::release::{self, kept, record};
use crate::k3s::{DELIVERY, PROFILE, delivery as rules};
use broil_config::LoadedProject;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "delivery",
    protocol: "broil-k3s-delivery",
    magic: b"BK3SRRP1\n",
    header: "DeliveryHeader",
    result: "DeliveryResult",
    body: DELIVERY,
    planned: 0,
    reserve: 8192,
    version: 1,
};

pub(super) const OBSERVATION: &str = "delivery-observation";
pub(super) const RECIPE: &str = "delivery-recipe";
const TAGS: [&str; 6] = [
    "inspect-images",
    "check-closure",
    "pull-image",
    "pin-image",
    "unpin-image",
    "read-origin-log",
];
pub(super) const MUTATIONS: [&str; 3] = ["pull-image", "pin-image", "unpin-image"];
const CLOSURE_CAP: usize = 24;
const CLOSURE_WAIT_MS: u64 = 25_000;
const CLOSURE_GUARD: Duration = Duration::from_secs(30);
const RECORD_LIMIT: usize = 16_384;
const WARNING: usize = 14_746;

pub(super) fn action(tag: &str) -> String {
    format!("lifecycle:delivery-{tag}")
}

#[derive(Debug)]
pub struct Refused {
    pub failure: Failure,
    pub boundary: Option<&'static str>,
    pub detail: Option<String>,
}

impl From<Failure> for Refused {
    fn from(failure: Failure) -> Self {
        Self {
            failure,
            boundary: None,
            detail: None,
        }
    }
}

impl From<super::ExecutionFailure> for Refused {
    fn from(failure: super::ExecutionFailure) -> Self {
        Self {
            failure: failure.failure,
            boundary: None,
            detail: failure.detail.map(str::to_owned),
        }
    }
}

impl From<release::Refusal> for Refused {
    fn from(refusal: release::Refusal) -> Self {
        Self {
            failure: failure_of(refusal.failure),
            boundary: Some(refusal.boundary),
            detail: Some(refusal.detail),
        }
    }
}

fn failure_of(name: &str) -> Failure {
    match name {
        "configuration" => Failure::Configuration,
        "readiness" => Failure::Readiness,
        "ownership" => Failure::Ownership,
        "bound" => Failure::Bound,
        "busy" => Failure::Busy,
        "storage" => Failure::Storage,
        "credential" => Failure::Credential,
        "timeout" => Failure::Timeout,
        _ => Failure::Integrity,
    }
}

pub(super) type Leaf<T> = std::result::Result<T, Refused>;

pub(super) fn refused(failure: Failure, boundary: &'static str, detail: String) -> Refused {
    Refused {
        failure,
        boundary: Some(boundary),
        detail: Some(detail),
    }
}


fn list(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn platform_of<'v>(image: &'v Value, platform: &Value) -> Option<&'v Value> {
    list(&image["platforms"])
        .iter()
        .find(|p| p["platform"] == *platform)
}

fn member_platform<'v>(recipe: &'v Value, member: &Value) -> Option<&'v Value> {
    list(&recipe["members"])
        .iter()
        .find(|m| m["member"] == *member)
        .map(|m| &m["platform"])
}

fn inspected<'v>(facts: &'v Value, reference: &Value) -> Option<&'v Value> {
    list(&facts["images"])
        .iter()
        .find(|i| i["reference"] == *reference)
}

fn present(entry: Option<&Value>, config: &Value) -> bool {
    entry.is_some_and(|e| {
        e["present"] == true && e["repo_digests_match"] == true && e["image_id"] == *config
    })
}

fn unpinned<'v>(recipe: &'v Value, member: &Value) -> &'v [Value] {
    list(&recipe["unpin"])
        .iter()
        .find(|u| u["member"] == *member)
        .map_or(&[], |u| list(&u["references"]))
}

fn push_once(values: &mut Vec<Value>, value: &Value) {
    if !values.contains(value) {
        values.push(value.clone());
    }
}

fn repositories(recipe: &Value) -> Vec<Value> {
    let mut repositories = Vec::new();
    for image in list(&recipe["images"])
        .iter()
        .filter(|i| i["managed"] == true)
    {
        push_once(&mut repositories, &image["repository"]);
    }
    repositories
}

fn origin_digests(recipe: &Value, artifacts: &Value) -> Result<Value> {
    let mut digests: Vec<Value> = Vec::new();
    for image in list(&recipe["images"])
        .iter()
        .filter(|i| i["managed"] == true)
    {
        let artifact = &artifacts[image["artifact"].as_str().ok_or(Failure::Integrity)?];
        let mut listed = vec![&image["root"]];
        for platform in list(&image["platforms"]) {
            listed.push(&platform["manifest"]);
            listed.push(&platform["config"]);
            let recorded = list(&artifact["platforms"])
                .iter()
                .find(|p| p["platform"] == platform["platform"])
                .ok_or(Failure::Integrity)?;
            listed.extend(list(&recorded["layers"]));
        }
        for digest in listed {
            let size = &artifact["descriptors"][digest.as_str().ok_or(Failure::Integrity)?];
            require(size.is_u64(), Failure::Integrity)?;
            push_once(&mut digests, &json!({"digest":digest,"size":size}));
        }
    }
    Ok(Value::Array(digests))
}

pub(super) fn payload(
    request: &Value,
    recipe: &Value,
    tag: &str,
    member: &Value,
    cited: &[&Value],
) -> Result<Value> {
    let deliver = recipe["action"] == "release-deliver";
    let images = list(&recipe["images"]);
    let platform = member_platform(recipe, member)
        .cloned()
        .unwrap_or(Value::Null);
    let inspection = cited
        .iter()
        .find(|o| o["event"]["kind"] == "inspect")
        .map(|o| &o["event"]["facts"]);
    let chosen = |image: &Value, key: &str| {
        platform_of(image, &platform).map_or(Value::Null, |p| p[key].clone())
    };
    let needs = |image: &Value, pin: bool| {
        let Some(facts) = inspection else {
            return true;
        };
        let entry = inspected(facts, &image["reference"]);
        !(present(entry, &chosen(image, "config"))
            && (!pin || entry.is_some_and(|e| e["pinned"] == true)))
    };
    let expected = match tag {
        "inspect-images" => {
            let references: Vec<Value> = if deliver {
                images.iter().map(|i| i["reference"].clone()).collect()
            } else {
                unpinned(recipe, member).to_vec()
            };
            json!({"references":references})
        }
        "check-closure" => {
            let listed: Vec<Value> = images
                .iter()
                .filter(|i| i["managed"] == true)
                .map(|i| {
                    json!({"reference":i["reference"],"repository":i["repository"],
                        "root":i["root"],"manifest":chosen(i, "manifest"),
                        "config":chosen(i, "config")})
                })
                .collect();
            json!({"platform":platform,"images":listed})
        }
        "pull-image" | "pin-image" => {
            let listed: Vec<Value> = images
                .iter()
                .filter(|i| needs(i, tag == "pin-image"))
                .map(|i| json!({"reference":i["reference"],"config":chosen(i, "config")}))
                .collect();
            if tag == "pull-image" {
                json!({"platform":platform,"images":listed})
            } else {
                json!({"images":listed})
            }
        }
        "unpin-image" => json!({"references":unpinned(recipe, member)}),
        "read-origin-log" => {
            let since = match cited.iter().find(|o| o["event"]["kind"] == "origin-log") {
                Some(start) => start["recorded_ms"].clone(),
                None => request["created_ms"].clone(),
            };
            json!({"since_ms":since,"repositories":repositories(recipe),"digests":null})
        }
        _ => return Err(Failure::Capability),
    };
    let wait = if tag == "check-closure" {
        json!(CLOSURE_WAIT_MS)
    } else {
        Value::Null
    };
    Ok(
        json!({"recipe":recipe,"expected":expected,"resource":null,"preflight":null,
        "wait_ms":wait,"member":member}),
    )
}

fn shape(tag: &str, result: &Value) -> Result<()> {
    let set = |key: &str| !result[key].is_null();
    let shaped = match tag {
        "inspect-images" => set("node") && set("images") && !set("closure") && !set("log"),
        "check-closure" => set("closure") && !set("node") && !set("images") && !set("log"),
        "read-origin-log" => set("log") && !set("node") && !set("images") && !set("closure"),
        "pull-image" => set("images") && !set("node") && !set("closure") && !set("log"),
        _ => !set("node") && !set("images") && !set("closure") && !set("log"),
    };
    require(
        shaped && result["terminal"].is_null() != MUTATIONS.contains(&tag),
        Failure::Integrity,
    )
}

fn facts(result: Option<&Value>) -> Value {
    let field = |key: &str| result.map_or(Value::Null, |r| r[key].clone());
    json!({"node":field("node"),"images":field("images"),"closure":field("closure"),
        "log":field("log")})
}

fn kind(tag: &str) -> &'static str {
    match tag {
        "inspect-images" => "inspect",
        "check-closure" => "closure",
        "pull-image" => "pull",
        "pin-image" => "pin",
        "unpin-image" => "unpin",
        _ => "origin-log",
    }
}

impl Snapshot {
    pub(super) fn delivery_payload(&self, step: &Value) -> Result<Value> {
        let tag = step["action"]
            .as_str()
            .and_then(|a| a.strip_prefix("lifecycle:delivery-"))
            .filter(|tag| TAGS.contains(tag))
            .ok_or(Failure::Capability)?;
        let refs = list(&step["payload_observations"]);
        require(
            !refs.is_empty()
                && matches!(
                    self.request["action"].as_str(),
                    Some("release-deliver" | "release-retain")
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
        let member = &step["recipient"]["member"];
        let listed = if tag == "read-origin-log" {
            recipe["writer"] == *member && recipe["action"] == "release-deliver"
        } else {
            member_platform(recipe, member).is_some()
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
                && listed,
            Failure::Ownership,
        )?;
        let mut cited = Vec::with_capacity(refs.len() - 1);
        for sequence in &refs[1..] {
            let observation = observed(sequence)?;
            require(
                observation["event"]["type"] == OBSERVATION
                    && observation["event"]["member"] == step["recipient"],
                Failure::Integrity,
            )?;
            cited.push(observation);
        }
        let payload = payload(&self.request, recipe, tag, member, &cited)?;
        require(
            tag == "read-origin-log"
                || hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }
}


pub(super) fn release_store(context: &rpc::Context<'_>) -> Result<std::path::PathBuf> {
    Ok(context
        .project
        .broil_root
        .join("state/releases")
        .join(context.scope["hash"].as_str().ok_or(Failure::Integrity)?))
}

pub(super) fn releases(context: &rpc::Context<'_>) -> Leaf<Vec<Value>> {
    let store = release_store(context)?;
    if matches!(std::fs::symlink_metadata(&store), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(Vec::new());
    }
    Ok(release::store::enumerate(&store)?)
}

pub(super) fn artifacts(project: &LoadedProject, record: &Value) -> Leaf<Value> {
    let mut ids: Vec<String> = Vec::new();
    for image in list(&record["images"]) {
        let id = image["artifact"].as_str().ok_or(Failure::Integrity)?;
        if !ids.iter().any(|i| i == id) {
            ids.push(id.to_owned());
        }
    }
    let read = crate::images::records::step(
        &project.broil_root,
        30_000,
        5_000,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        move |root, active| {
            let store = crate::images::records::Store::new(root);
            let mut out = Vec::new();
            for id in &ids {
                let record = store.read(id, active).ok().flatten();
                out.push((id.clone(), record.and_then(|r| r.encode().ok())));
            }
            Ok(out)
        },
    )
    .map_err(|_| Failure::Storage)?;
    let mut map = serde_json::Map::new();
    for (id, bytes) in read {
        let Some(bytes) = bytes else { continue };
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| Failure::Integrity)?;
        let mut platforms = Vec::new();
        let mut descriptors = serde_json::Map::new();
        let mut describe = |d: &Value| {
            if let (Some(digest), Some(size)) = (d["digest"].as_str(), d["size"].as_u64()) {
                descriptors.insert(digest.to_owned(), json!(size));
            }
        };
        describe(&value["root"]);
        for p in list(&value["platforms"]) {
            describe(&p["manifest"]);
            describe(&p["config"]);
            for layer in list(&p["layers"]) {
                describe(layer);
            }
            let layers: Vec<Value> = list(&p["layers"])
                .iter()
                .map(|l| l["digest"].clone())
                .collect();
            platforms.push(
                json!({"platform":p["platform"],"manifest":p["manifest"]["digest"],
                "config":p["config"]["digest"],"layers":layers}),
            );
        }
        map.insert(id, json!({"platforms":platforms,"descriptors":descriptors}));
    }
    Ok(Value::Object(map))
}

pub(super) fn settled(previous: &[Snapshot], target: &str) -> Leaf<()> {
    for snapshot in previous {
        let summary = super::report::summary(snapshot);
        if !matches!(
            summary["outcome"].as_str(),
            Some("succeeded" | "failed" | "cancelled")
        ) || summary["completion_unknown"] != false
            || summary["cleanup_unknown"] != false
        {
            let operation = summary["operation"].as_str().unwrap_or("");
            return Err(refused(
                Failure::Busy,
                "operation",
                format!(
                    "{operation} of target {target} is unsettled; run k3s operation show {target} {operation}, and if no broil process runs it, k3s operation resume {target} {operation}"
                ),
            ));
        }
    }
    Ok(())
}

fn managed_fallback(context: &rpc::Context<'_>) -> Value {
    let selected = &context.selected;
    let managed = selected
        .declaration
        .registry
        .as_ref()
        .and_then(|r| selected.registries.get(&r.endpoint))
        .map(|e| e.declaration.endpoint.origin());
    let entries: Vec<Value> = selected
        .declaration
        .node_registries
        .iter()
        .zip(&selected.node_registry_fallbacks)
        .filter_map(|(node, fallback)| {
            let catalog = selected.registries.get(&node.registry)?;
            Some(
                json!({"managed":managed.as_ref() == Some(&catalog.declaration.endpoint.origin()),
                "fallback":match fallback {
                    broil_core::k3s::RegistryFallback::Disabled => "disabled",
                    broil_core::k3s::RegistryFallback::SameOrigin => "same-origin",
                }}),
            )
        })
        .collect();
    rules::fallback(&Value::Array(entries))
}

fn writer(context: &rpc::Context<'_>, owner: &Value) -> Result<Option<String>> {
    match context.selected.declaration.registry.as_ref() {
        Some(registry) => Ok(Some(super::registry_service::writer(owner, registry)?.0)),
        None => Ok(None),
    }
}

pub(super) fn owned(context: &rpc::Context<'_>, owner: &Value) -> Result<Vec<Value>> {
    require(
        !owner["cluster"].is_null() && owner["fingerprints"] == context.owner_fingerprints,
        Failure::Ownership,
    )?;
    let members = super::survivors(owner)?;
    require(
        !members.is_empty()
            && owner["participants_sha256"] == super::participants(&Value::Array(members.clone()))?,
        Failure::Ownership,
    )?;
    require(
        members.iter().all(|m| m["node_uid"].is_string()),
        Failure::Readiness,
    )?;
    Ok(members)
}

pub(super) fn store_usage(
    previous: &[Snapshot],
    extra: Option<&Snapshot>,
    members: &[Value],
    releases: usize,
) -> Value {
    let all: Vec<&Snapshot> = previous.iter().chain(extra).collect();
    let mut host = json!({"member":members.first().map_or(Value::Null, |m| m["member"].clone()),
        "attempts":0,"limit":RECORD_LIMIT});
    let mut most = 0;
    for member in members {
        let attempts: usize = all
            .iter()
            .filter(|s| {
                list(&s.request["members"])
                    .iter()
                    .any(|m| m["machine"] == member["machine"])
            })
            .map(|s| s.attempts.len())
            .sum();
        if attempts > most {
            most = attempts;
            host = json!({"member":member["member"],"attempts":attempts,"limit":RECORD_LIMIT});
        }
    }
    let operations = all.len();
    json!({"operations":operations,"limit":RECORD_LIMIT,"releases":releases,
        "release_limit":RECORD_LIMIT,"hosts":host,
        "warning":operations >= WARNING || releases >= WARNING || most >= WARNING})
}

pub(super) fn kept_history(previous: &[Snapshot], records: &[Value]) -> Value {
    let mut operations = Vec::new();
    for snapshot in previous.iter().filter(|s| {
        matches!(
            s.request["action"].as_str(),
            Some("release-apply" | "release-rollback")
        )
    }) {
        let event = |kind: &str| {
            snapshot
                .observations
                .iter()
                .find(|o| o["event"]["type"] == kind)
                .map(|o| &o["event"])
        };
        let Some(recipe) = event("release-recipe").map(|e| &e["recipe"]) else {
            continue;
        };
        let evidence = event("release-evidence");
        let changed = evidence.map_or_else(
            || {
                snapshot.steps.iter().any(|s| {
                    matches!(
                        s["action"].as_str(),
                        Some("lifecycle:release-apply-objects" | "credential:apply-secret")
                    )
                })
            },
            |e| e["changed"] == true,
        );
        operations.push(json!({"operation":snapshot.request["operation"],
            "action":snapshot.request["action"],"release":recipe["release"],
            "application":recipe["application"],"created_ms":snapshot.request["created_ms"],
            "changed":changed,"healthy":evidence.is_some_and(|e| e["healthy"] == true)}));
    }
    let mut images = serde_json::Map::new();
    let mut releases = Vec::new();
    for record in records {
        let id = record["release"].as_str().unwrap_or("").to_owned();
        releases.push(json!({"release":id,"application":record["application"],
            "created_ms":record["created_ms"]}));
        images.insert(
            id,
            Value::Array(
                list(&record["images"])
                    .iter()
                    .map(|i| json!({"image":i["image"],"reference":i["reference"]}))
                    .collect(),
            ),
        );
    }
    json!({"operations":operations,"releases":releases,"images":images})
}


enum Settled {
    Done(Value),
    Conclusive(Value, Failure),
    Unread,
}

impl Session<'_> {
    fn delivery_sequence(&self, member: &Value, kind: &str) -> Result<Option<Value>> {
        Ok(self
            .local
            .snapshot()?
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["attempt"] == self.attempt["attempt"]
                    && o["event"]["type"] == OBSERVATION
                    && o["event"]["member"] == *member
                    && o["event"]["kind"] == kind
            })
            .map(|o| o["sequence"].clone()))
    }

    fn delivery_payload(
        &self,
        index: usize,
        tag: &str,
        recipe_seq: &Value,
        kinds: &[&str],
    ) -> Result<(Value, Vec<Value>)> {
        let member = &self.members[index];
        let mut refs = vec![recipe_seq.clone()];
        for kind in kinds {
            if let Some(sequence) = self.delivery_sequence(member, kind)? {
                refs.push(sequence);
            }
        }
        refs[1..].sort_by_key(Value::as_u64);
        let snapshot = self.local.snapshot()?;
        let recipe = &snapshot
            .observations
            .iter()
            .find(|o| o["sequence"] == *recipe_seq)
            .ok_or(Failure::Integrity)?["event"]["recipe"];
        let cited: Vec<&Value> = refs[1..]
            .iter()
            .map(|s| {
                snapshot
                    .observations
                    .iter()
                    .find(|o| o["sequence"] == *s)
                    .ok_or(Failure::Integrity)
            })
            .collect::<Result<_>>()?;
        let payload = payload(&snapshot.request, recipe, tag, &member["member"], &cited)?;
        Ok((payload, refs))
    }

    async fn delivery_deselect(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<()> {
        self.context.check()?;
        let step = self.intended(index, &action(tag), &payload, refs)?;
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

    async fn delivery_step(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<(Value, Settled)> {
        self.context.check()?;
        let mutation = MUTATIONS.contains(&tag);
        require(!mutation || self.mode == Mode::Work, Failure::Capability)?;
        let previous = self.local.step_deadline;
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        self.local.step_deadline = Some(deadline);
        let tagged = action(tag);
        let step = self.intended(index, &tagged, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let child = mutation.then(|| self.context.clock.for_credential_action(deadline));
        let cap = if tag == "check-closure" {
            CLOSURE_CAP
        } else {
            1
        };
        let mut settled: Option<(Value, Value)> = None;
        for dispatch in 0..cap {
            if dispatch > 0
                && deadline.saturating_duration_since(tokio::time::Instant::now()) <= CLOSURE_GUARD
            {
                break;
            }
            let observed = network::invoke(
                &self.context,
                &FAMILY,
                &binding,
                tag,
                &payload,
                deadline,
                child.as_ref(),
            )
            .await;
            self.local.completion_unknown |=
                mutation && observed.failure.is_some() && observed.transport["dispatch"] != "none";
            if observed.failure.is_some()
                || observed
                    .response
                    .as_ref()
                    .is_some_and(|result| result["status"] != "ok")
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
            if tag == "read-origin-log" {
                let cancelled = self.context.policy.cancellation.is_cancelled();
                let recordable = !cancelled && tokio::time::Instant::now() < deadline;
                match rules::origin_read(&json!({"recordable":recordable,
                    "failure":observed.failure.map(Failure::name),"response":observed.response}))
                {
                    "settled" => settled = observed.response.map(|r| (r, observed.transport)),
                    "unread" => {}
                    "report-only" if cancelled => return Err(Failure::Cancelled),
                    "report-only" => return Err(Failure::Timeout),
                    _ => return Err(Failure::Integrity),
                }
                break;
            }
            let Some(result) = observed.response else {
                return Err(observed.failure.unwrap_or(Failure::Transport));
            };
            self.local.completion_unknown |= mutation
                && (result["status"] == "unknown" || result["terminal"]["effect"] == "unknown");
            require(
                result["kind"] == "result"
                    && result["failure"].is_null() == (result["status"] == "ok"),
                Failure::Integrity,
            )?;
            if result["status"] == "ok" {
                shape(tag, &result)?;
            }
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
            let waiting = tag == "check-closure"
                && result["status"] == "ok"
                && result["closure"]["ready"] != true;
            settled = Some((result, observed.transport));
            if !waiting {
                break;
            }
            self.context.check()?;
        }
        self.local.step_deadline = previous;
        let member = self.members[index].clone();
        let outcome = match settled {
            None => Settled::Unread,
            Some((result, _)) if result["status"] == "ok" => {
                if mutation {
                    require(
                        result["terminal"]["outcome"] == "succeeded"
                            && result["terminal"]["effect"] == "complete"
                            && result["terminal"]["writer_ended"] == true,
                        Failure::Readiness,
                    )?;
                }
                Settled::Done(result)
            }
            Some((result, transport))
                if mutation
                    && matches!(tag, "pull-image" | "pin-image")
                    && result["status"] == "failed"
                    && result["terminal"]["outcome"] == "failed"
                    && matches!(
                        result["terminal"]["effect"].as_str(),
                        Some("absent" | "partial")
                    )
                    && matches!(
                        result["terminal"]["failure"].as_str(),
                        Some("integrity" | "readiness" | "ownership")
                    )
                    && result["terminal"]["writer_ended"] == true
                    && !network::unclean(&transport)
                    && tokio::time::Instant::now() < deadline =>
            {
                let failure = super::server::refused(&result["terminal"]);
                Settled::Conclusive(result, failure)
            }
            Some((_, _)) if tag == "read-origin-log" => Settled::Unread,
            Some((result, _)) => return Err(super::server::refused(&result)),
        };
        if let Some(mut child) = child {
            child.complete().map_err(|_| Failure::Timeout)?;
        }
        let reply = match &outcome {
            Settled::Done(result) | Settled::Conclusive(result, _) => Some(result),
            Settled::Unread => None,
        };
        self.append(
            &step,
            json!({"type":OBSERVATION,"member":member,"kind":kind(tag),"facts":facts(reply)}),
            true,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok((step, outcome))
    }

    async fn delivery_failed(
        &mut self,
        step: &Value,
        failure: Failure,
        detail: &'static str,
    ) -> Result<()> {
        self.local.failure_detail.get_or_insert(detail);
        self.append(
            step,
            json!({"type":"failure","failure":failure.name(),"outcome":"failed",
                "completion_unknown":false,"cleanup_unknown":false}),
            false,
            Value::Null,
        )
        .await
    }

    async fn delivery_acquire(&mut self, order: &[usize]) -> Result<()> {
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

    fn order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        order
    }

    async fn origin_read(
        &mut self,
        origin: &Origin,
        recipe_seq: &Value,
        kinds: &[&str],
        read: bool,
    ) -> Result<bool> {
        let Some(writer) = origin.writer else {
            return Ok(false);
        };
        let (mut payload, refs) =
            self.delivery_payload(writer, "read-origin-log", recipe_seq, kinds)?;
        payload["expected"]["digests"] = origin.digests.clone();
        if !read {
            self.delivery_deselect(writer, "read-origin-log", payload, refs)
                .await?;
            return Ok(false);
        }
        let (_, settled) = self
            .delivery_step(writer, "read-origin-log", payload, refs)
            .await?;
        Ok(matches!(settled, Settled::Done(_)))
    }

    async fn deliver_run(&mut self, required: Vec<usize>, origin: Origin) -> Result<Snapshot> {
        let order = self.order();
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, RECIPE)?;
        let recipe = self
            .local
            .snapshot()?
            .observations
            .iter()
            .find(|o| o["sequence"] == recipe_seq)
            .ok_or(Failure::Integrity)?["event"]["recipe"]
            .clone();
        self.delivery_acquire(&order).await?;
        let opened = self
            .origin_read(&origin, &recipe_seq, &[], origin.reads)
            .await?;
        let mut stopped = false;
        let images = list(&recipe["images"]).to_vec();
        for &index in &required {
            let (payload, refs) =
                self.delivery_payload(index, "inspect-images", &recipe_seq, &[])?;
            if stopped {
                self.delivery_deselect(index, "inspect-images", payload, refs)
                    .await?;
                continue;
            }
            let (step, settled) = self
                .delivery_step(index, "inspect-images", payload, refs)
                .await?;
            let Settled::Done(result) = settled else {
                return Err(Failure::Integrity);
            };
            let member = &self.members[index]["member"];
            let platform = member_platform(&recipe, member)
                .cloned()
                .unwrap_or(Value::Null);
            let observed = result["node"]["architecture"]
                .as_str()
                .map(|arch| format!("linux/{arch}"));
            let lacking = images.iter().any(|i| platform_of(i, &platform).is_none());
            if observed.as_deref() != platform.as_str() || lacking {
                self.delivery_failed(&step, Failure::Integrity, "platform")
                    .await?;
                stopped = true;
                continue;
            }
            let expected: serde_json::Map<String, Value> = images
                .iter()
                .filter_map(|i| {
                    let config = platform_of(i, &platform)?["config"].clone();
                    Some((i["reference"].as_str()?.to_owned(), config))
                })
                .collect();
            let settled = rules::present_images(&json!({"expected":expected,
                "images":result["images"]}));
            if settled.is_err() {
                self.delivery_failed(&step, Failure::Integrity, "digest")
                    .await?;
                stopped = true;
            }
        }
        let fallback = recipe["fallback"] == "same-origin";
        for &index in &required {
            let (payload, refs) =
                self.delivery_payload(index, "check-closure", &recipe_seq, &["inspect"])?;
            let needed = !list(&payload["expected"]["images"]).is_empty();
            if stopped || !needed {
                self.delivery_deselect(index, "check-closure", payload, refs)
                    .await?;
            } else {
                let (step, settled) = self
                    .delivery_step(index, "check-closure", payload, refs)
                    .await?;
                let Settled::Done(result) = settled else {
                    return Err(Failure::Integrity);
                };
                if result["closure"]["ready"] != true && !fallback {
                    self.delivery_failed(&step, Failure::Timeout, "replica-incomplete")
                        .await?;
                    stopped = true;
                }
            }
            let (payload, refs) =
                self.delivery_payload(index, "pull-image", &recipe_seq, &["inspect", "closure"])?;
            let needed = !list(&payload["expected"]["images"]).is_empty();
            if stopped || !needed {
                self.delivery_deselect(index, "pull-image", payload, refs)
                    .await?;
            } else if let (step, Settled::Conclusive(result, failure)) = self
                .delivery_step(index, "pull-image", payload, refs)
                .await?
            {
                let digest = list(&result["images"])
                    .iter()
                    .any(|i| i["failed"] == "digest");
                self.delivery_failed(
                    &step,
                    failure,
                    if digest {
                        "digest"
                    } else {
                        "incomplete-delivery"
                    },
                )
                .await?;
                stopped = true;
            }
            let (payload, refs) =
                self.delivery_payload(index, "pin-image", &recipe_seq, &["inspect", "pull"])?;
            let needed = !list(&payload["expected"]["images"]).is_empty();
            if stopped || !needed {
                self.delivery_deselect(index, "pin-image", payload, refs)
                    .await?;
            } else if let (step, Settled::Conclusive(_, failure)) = self
                .delivery_step(index, "pin-image", payload, refs)
                .await?
            {
                self.delivery_failed(&step, failure, "incomplete-delivery")
                    .await?;
                stopped = true;
            }
        }
        self.origin_read(&origin, &recipe_seq, &["origin-log"], opened)
            .await?;
        self.settle(&order).await
    }

    async fn retain_run(&mut self, members: Vec<usize>) -> Result<Snapshot> {
        let order = self.order();
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, RECIPE)?;
        self.delivery_acquire(&order).await?;
        for index in members {
            let (payload, refs) =
                self.delivery_payload(index, "inspect-images", &recipe_seq, &[])?;
            self.delivery_step(index, "inspect-images", payload, refs)
                .await?;
            let (payload, refs) =
                self.delivery_payload(index, "unpin-image", &recipe_seq, &["inspect"])?;
            self.delivery_step(index, "unpin-image", payload, refs)
                .await?;
        }
        self.settle(&order).await
    }
}

struct Admission {
    owner: Value,
    members: Vec<Value>,
    recipe: Value,
    count: usize,
}

async fn record(
    context: &rpc::Context<'_>,
    local: &mut Local,
    admission: &Admission,
    action: &str,
) -> Result<Value> {
    let created = now()?;
    let sequence = local.work(|store| store.next_sequence()).await?;
    let owner = &admission.owner;
    let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":owner["owner"],
        "operation":admission.recipe["operation"],"created_ms":created,"sequence":sequence,
        "action":action,"members":admission.members,"cluster":owner["cluster"],"resources":[],
        "config":context.config,"references":context.references,"consumer":null,
        "fingerprints":context.fingerprints,"participants_sha256":owner["participants_sha256"],
        "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
        "step_timeout_ms":context.selected.step_timeout.seconds*1000});
    let attempt_id = admission.recipe["attempt"].clone();
    let attempt = json!({"schema":1,"kind":"attempt","scope":context.scope,"owner":owner["owner"],
        "operation":admission.recipe["operation"],"attempt":attempt_id,"created_ms":created,
        "request_sha256":hash("broil-infra-request-v1",&request)?,"parent_attempt":null,
        "original_step":null,"approval":null,"steps":(1..=admission.count).collect::<Vec<_>>()});
    let mut recipe = admission.recipe.clone();
    recipe
        .as_object_mut()
        .ok_or(Failure::Integrity)?
        .remove("attempt");
    let stored_owner = owner.clone();
    let stored_attempt = attempt.clone();
    local
        .work(move |store| store.create(stored_owner, request, stored_attempt))
        .await?;
    let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
        "owner":owner["owner"],"operation":admission.recipe["operation"],"sequence":1,
        "recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
        "attempt":attempt["attempt"],"step":null,"dispatch":null,
        "event":{"type":RECIPE,"recipe":recipe}});
    local.work(move |store| store.append(observation)).await?;
    Ok(attempt)
}

fn recipe(context: &rpc::Context<'_>, fields: Value) -> Leaf<Value> {
    let mut recipe = fields;
    recipe["scope"] = context.scope.clone();
    recipe["profile_sha256"] = context.fingerprints["profile_sha256"].clone();
    rules::check_recipe(&recipe)?;
    schema::validate(&canonical(&recipe)?, "DeliveryRecipe", rules::RECIPE_LIMIT)?;
    recipe["attempt"] = json!(fresh()?);
    Ok(recipe)
}

fn fits(recipe: &Value, participants: usize, required: usize, origin: bool) -> Leaf<usize> {
    let bound = |detail: String| refused(Failure::Bound, "size", detail);
    let images = list(&recipe["images"]);
    let layout = rules::deliver_layout(&json!({"participants":participants,"required":required,
        "managed_origin":origin,"managed_images":images.iter().any(|i| i["managed"] == true)}))?;
    let steps = layout["steps"].as_u64().ok_or(Failure::Integrity)? as usize;
    let widest = json!({"protocol":FAMILY.protocol,"version":1,"action":"check-closure",
        "request_id":"f".repeat(32),"binding":{"pad":"f".repeat(2048)},"remaining_ms":7_200_000u64,
        "wait_ms":CLOSURE_WAIT_MS,"recipe":recipe,"expected":{"platform":"linux/amd64",
            "images":images.iter().map(|i| json!({"reference":i["reference"],
                "repository":i["repository"],"root":i["root"],"manifest":i["root"],
                "config":i["root"]})).collect::<Vec<_>>()},
        "resource":null,"preflight":null,"member":"f".repeat(64)});
    let frame = canonical(&widest)?.len() + 17 + FAMILY.reserve;
    if frame > 65_536 {
        return Err(bound(format!(
            "a delivery header needs a {frame}-byte frame; the limit is 65536"
        )));
    }
    let report = 16_384 + required * (512 + images.len() * 640);
    if report > crate::k3s::report::REPORT_LIMIT {
        return Err(bound(format!(
            "the report can need {report} bytes; the limit is {}",
            crate::k3s::report::REPORT_LIMIT
        )));
    }
    Ok(steps)
}

struct Origin {
    writer: Option<usize>,
    digests: Value,
    reads: bool,
}

fn platform(previous: &[Snapshot], record: &Value, member: &Value) -> Result<Value> {
    let platforms = list(&record["policy"]["platforms"]);
    if platforms.len() == 1 {
        return Ok(platforms[0].clone());
    }
    let newest = previous
        .iter()
        .filter_map(|s| {
            s.observations.iter().rev().find(|o| {
                o["event"]["type"] == "bootstrap-host"
                    && o["event"]["member"]["machine"] == member["machine"]
            })
        })
        .max_by_key(|o| o["recorded_ms"].as_u64());
    match newest.and_then(|o| o["event"]["facts"]["architecture"].as_str()) {
        Some("amd64") => Ok(json!("linux/amd64")),
        _ => Err(Failure::Readiness),
    }
}

pub(super) async fn records(local: &mut Local) -> Result<(Vec<Snapshot>, Value)> {
    let previous = local
        .work(|store| store.inspect(None).map_err(|e| e.failure))
        .await?;
    let owner = previous.first().ok_or(Failure::Ownership)?.owner.clone();
    Ok((previous, owner))
}

pub type Reported = (Value, bool);

pub(super) fn envelope(context: &rpc::Context<'_>, view: &str, store: Value) -> Value {
    json!({"format_version":1,"scope":context.scope,"view":view,"outcome":"complete",
        "failure":null,"detail":null,"completion_unknown":false,"cleanup_unknown":false,
        "truncated":false,"operations":[],"store":store,
        "recovery":{"choice":"none","reason":null}})
}

pub async fn deliver(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    release: &str,
) -> Leaf<Reported> {
    let context = rpc::Context::new(project, policy, target)?;
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let mut local = Local::new(&context)?;
    let admitted: Leaf<_> = async {
        let (previous, owner) = records(&mut local).await?;
        let members = owned(&context, &owner)?;
        settled(&previous, target)?;
        let stored = releases(&context)?;
        let record = stored
            .iter()
            .find(|r| r["release"] == release)
            .cloned()
            .ok_or_else(|| {
                refused(
                    Failure::Configuration,
                    "release",
                    format!("{release} is not recorded for target {target}"),
                )
            })?;
        require(
            record["scope"] == context.scope
                && record["target"]["owner"] == owner["owner"]
                && record["target"]["cluster"] == owner["cluster"],
            Failure::Ownership,
        )?;
        let removed: Vec<Value> = list(&owner["removed"])
            .iter()
            .map(|r| r["member"].clone())
            .collect();
        let set = rules::required_set(&json!({"policy_members":record["policy"]["members"],
            "removed":removed}))?;
        let mut listed = Vec::new();
        let mut required = Vec::new();
        for name in list(&set["required"]) {
            let index = members
                .iter()
                .position(|m| m["member"] == *name)
                .ok_or(Failure::Ownership)?;
            required.push(index);
            listed.push(json!({"member":name,"role":members[index]["role"],
                "platform":platform(&previous, &record, &members[index])?}));
        }
        let artifacts = artifacts(project, &record)?;
        let images = rules::recipe_images(&record["images"], &artifacts)?;
        let writer = writer(&context, &owner)?;
        let writer_index = match &writer {
            Some(writer) => Some(
                members
                    .iter()
                    .position(|m| m["member"] == writer.as_str())
                    .ok_or(Failure::Ownership)?,
            ),
            None => None,
        };
        let operation = format!("infra-operation-{}", fresh()?);
        let recipe = recipe(
            &context,
            json!({"owner":owner["owner"],"operation":operation,"cluster":owner["cluster"],
                "action":"release-deliver","release":release,
                "release_sha256":record::release_sha256(&record),"writer":writer,
                "fallback":managed_fallback(&context),"members":listed,"excluded":set["excluded"],
                "images":images,"unpin":[]}),
        )?;
        let digests = origin_digests(&recipe, &artifacts)?;
        let reads = rules::origin_reads(&json!({"managed_origin":writer.is_some(),
            "digests":digests,"repositories":repositories(&recipe),
            "recipe_bytes":canonical(&recipe)?.len()}))
            == "dispatch";
        let count = fits(&recipe, members.len(), required.len(), writer.is_some())?;
        Ok((
            Admission {
                owner,
                members,
                recipe,
                count,
            },
            previous,
            stored.len(),
            record,
            required,
            Origin {
                writer: writer_index,
                digests,
                reads,
            },
        ))
    }
    .await;
    let (admission, previous, stored, record, required, origin) = match admitted {
        Ok(value) => value,
        Err(refusal) => {
            let _ = local.failure(refusal.failure, &context.clock).await;
            return Err(refusal);
        }
    };
    let attempt = match record_request(&context, &mut local, &admission, "release-deliver").await {
        Ok(attempt) => attempt,
        Err(failure) => return Err(local.failure(failure, &context.clock).await.into()),
    };
    let mut session = session(context, local, attempt, admission.members.clone());
    let result = Box::pin(session.deliver_run(required, origin)).await;
    session.unknown_run(&result).await;
    let detail = session.local.failure_detail;
    let finished = session.local.complete(result, &session.context.clock).await;
    let (snapshot, failed) = match finished {
        Ok(snapshot) => (Some(snapshot), None),
        Err(failure) => (failure.snapshot.map(|s| *s), Some(failure.failure)),
    };
    let snapshot = snapshot.ok_or(Failure::Integrity)?;
    let store = store_usage(&previous, Some(&snapshot), &admission.members, stored);
    let mut report = deliver_report(&session.context, &snapshot, &record, store, detail);
    if let Some(failure) = failed {
        if report["outcome"] == "unknown" && report["failure"].is_null() {
            report["failure"] = json!(failure.name());
        }
    }
    let complete = report["outcome"] == "succeeded";
    Ok((report, complete))
}

async fn record_request(
    context: &rpc::Context<'_>,
    local: &mut Local,
    admission: &Admission,
    action: &str,
) -> Result<Value> {
    record(context, local, admission, action).await
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


fn of_step<'s>(snapshot: &'s Snapshot, step: &'s Value) -> impl Iterator<Item = &'s Value> {
    snapshot.observations.iter().filter(move |o| {
        o["attempt"] == step["attempt"]
            && o["step"] == step["step"]
            && o["dispatch"] == step["dispatch"]
    })
}

struct NodeFacts<'s> {
    inspect: Option<&'s Value>,
    closure: Option<&'s Value>,
    pull: Option<&'s Value>,
    pin_receipt: Option<&'s Value>,
    pull_receipt: Option<&'s Value>,
    failed: bool,
    dispatched: bool,
}

fn node_facts<'s>(snapshot: &'s Snapshot, member: &Value) -> NodeFacts<'s> {
    let mut facts = NodeFacts {
        inspect: None,
        closure: None,
        pull: None,
        pin_receipt: None,
        pull_receipt: None,
        failed: false,
        dispatched: false,
    };
    for step in snapshot
        .steps
        .iter()
        .filter(|s| s["recipient"]["member"] == *member)
    {
        let tag = step["action"]
            .as_str()
            .and_then(|a| a.strip_prefix("lifecycle:delivery-"));
        let Some(tag) = tag.filter(|t| *t != "read-origin-log") else {
            continue;
        };
        for observation in of_step(snapshot, step) {
            let event = &observation["event"];
            match event["type"].as_str() {
                Some("dispatch") if event["transport"]["dispatch"] != "none" => {
                    facts.dispatched = true
                }
                Some("failure") => facts.failed = true,
                Some("receiver") if tag == "pin-image" => {
                    facts.pin_receipt = Some(&event["receipt"])
                }
                Some("receiver") if tag == "pull-image" => {
                    facts.pull_receipt = Some(&event["receipt"])
                }
                Some(OBSERVATION) => match tag {
                    "inspect-images" => facts.inspect = Some(observation),
                    "check-closure" => facts.closure = Some(observation),
                    "pull-image" => facts.pull = Some(observation),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    facts
}

fn succeeded_receipt(receipt: Option<&Value>) -> bool {
    receipt.is_some_and(|r| r["outcome"] == "succeeded" && r["effect"] == "complete")
}

fn delivery_nodes(snapshot: &Snapshot, recipe: &Value) -> Vec<(Value, Value, Value)> {
    let images = list(&recipe["images"]);
    let fallback = recipe["fallback"] == "same-origin";
    let mut nodes = Vec::new();
    for entry in list(&recipe["members"]) {
        let member = &entry["member"];
        let platform = &entry["platform"];
        let facts = node_facts(snapshot, member);
        let inspection = facts.inspect.map(|o| &o["event"]["facts"]);
        let ready_at = facts
            .closure
            .filter(|o| o["event"]["facts"]["closure"]["ready"] == true)
            .map(|o| o["recorded_ms"].clone());
        let fell_back = fallback
            && facts
                .closure
                .is_some_and(|o| o["event"]["facts"]["closure"]["ready"] == false);
        let pinned_all = succeeded_receipt(facts.pin_receipt);
        let mut delivered = inspection.is_some();
        let mut rows = Vec::new();
        let mut brief = Vec::new();
        for image in images {
            let config = platform_of(image, platform).map_or(Value::Null, |p| p["config"].clone());
            let seen = inspection.and_then(|f| inspected(f, &image["reference"]));
            let held = present(seen, &config);
            let pulled = facts
                .pull
                .map(|o| &o["event"]["facts"])
                .and_then(|f| inspected(f, &image["reference"]))
                .filter(|p| p["image_id"] == config && p["failed"].is_null());
            let pinned = pinned_all || held && seen.is_some_and(|e| e["pinned"] == true);
            let arrived = held || pulled.is_some() && succeeded_receipt(facts.pull_receipt);
            delivered &= arrived && pinned;
            let source = if held {
                json!("present")
            } else if !arrived {
                Value::Null
            } else if image["managed"] != true {
                json!("external")
            } else if fell_back {
                json!("origin-fallback")
            } else {
                json!("replica")
            };
            let image_id = if held {
                seen.map_or(Value::Null, |e| e["image_id"].clone())
            } else {
                pulled.map_or(Value::Null, |p| p["image_id"].clone())
            };
            rows.push(
                json!({"image":image["image"],"image_id":image_id,"pinned":pinned,
                "reference":image["reference"],"source":source}),
            );
            brief.push(json!({"image":image["image"],"pinned":pinned,"source":source}));
        }
        let completed = if !delivered {
            Value::Null
        } else if let Some(receipt) = facts.pin_receipt {
            receipt["completed_ms"].clone()
        } else {
            facts
                .inspect
                .map_or(Value::Null, |o| o["recorded_ms"].clone())
        };
        let outcome = if facts.failed {
            "failed"
        } else if delivered {
            "succeeded"
        } else if !facts.dispatched {
            "not-run"
        } else {
            "unknown"
        };
        let managed_needed = facts.closure.is_some();
        let counters = |o: Option<&Value>, path: &str| {
            o.map(|o| &o["event"]["facts"]).map_or(Value::Null, |f| {
                if path == "inspect" {
                    f["node"]["counters"].clone()
                } else {
                    f["closure"]["counters"].clone()
                }
            })
        };
        let before = counters(facts.inspect, "inspect");
        let after = counters(facts.closure, "closure");
        let received = match (
            before["in_bytes_total"].as_u64(),
            after["in_bytes_total"].as_u64(),
        ) {
            (Some(b), Some(a)) => json!(a.saturating_sub(b)),
            _ => Value::Null,
        };
        nodes.push((
            json!({"completed_ms":completed,"images":rows,"member":member,"outcome":outcome,
                "platform":platform,"replica_ready_ms":ready_at}),
            json!({"member":member,"replica_ready":!managed_needed || ready_at.is_some(),
                "origin_fallback":fell_back,"delivered":delivered}),
            json!({"completed_ms":completed,"images":brief,"member":member,
                "pulled_ms":facts.pull_receipt.map_or(Value::Null, |r| r["completed_ms"].clone()),
                "replica_ready_ms":ready_at,
                "syncthing":{"bytes_received":received,"connections":after["connections"]}}),
        ));
    }
    nodes
}

fn window(snapshot: &Snapshot) -> (Value, Value, Value) {
    let tagged = |s: &Value, tag: &str| s["action"] == action(tag);
    let mut reads = Vec::new();
    let mut aggregate = Value::Null;
    for step in snapshot
        .steps
        .iter()
        .filter(|s| tagged(s, "read-origin-log"))
    {
        let settled = of_step(snapshot, step)
            .find(|o| o["event"]["type"] == OBSERVATION && o["event"]["facts"]["log"].is_object());
        let deselected = of_step(snapshot, step).any(|o| {
            o["event"]["type"] == "dispatch" && o["event"]["transport"]["dispatch"] == "none"
        });
        reads.push(match settled {
            Some(o) => {
                aggregate = o["event"]["facts"]["log"].clone();
                json!({"read":"settled","ms":o["recorded_ms"]})
            }
            None if deselected => json!({"read":"deselected"}),
            None => json!({"read":"unread"}),
        });
    }
    let first_inspect = snapshot
        .steps
        .iter()
        .filter(|s| tagged(s, "inspect-images"))
        .flat_map(|s| of_step(snapshot, s))
        .find(|o| o["event"]["type"] == "dispatch" && o["event"]["transport"]["dispatch"] != "none")
        .map_or(Value::Null, |o| o["recorded_ms"].clone());
    let last_settled = snapshot
        .observations
        .iter()
        .filter(|o| o["event"]["type"] == OBSERVATION && o["event"]["kind"] != "origin-log")
        .filter_map(|o| o["recorded_ms"].as_u64())
        .max()
        .map_or(Value::Null, |ms| json!(ms));
    let end = reads.get(1).cloned().unwrap_or(Value::Null);
    let times = rules::window(&json!({"start":reads.first(),"end":end,
        "first_inspect_ms":first_inspect,"last_settled_ms":last_settled}));
    let origin = if times["end"] == "dispatch" && end["read"] == "settled" {
        rules::origin(&aggregate)
    } else {
        Value::Null
    };
    (
        origin,
        times["started_ms"].clone(),
        times["ended_ms"].clone(),
    )
}

pub(super) fn recipe_of(snapshot: &Snapshot) -> Option<&Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == RECIPE)
        .map(|o| &o["event"]["recipe"])
}

pub(super) fn operation_summary(snapshot: &Snapshot) -> Value {
    let summary = super::report::summary(snapshot);
    json!({"action":summary["action"],"cleanup_unknown":summary["cleanup_unknown"],
        "completion_unknown":summary["completion_unknown"],"created_ms":summary["created_ms"],
        "failure":summary["failure"],"operation":summary["operation"],"outcome":summary["outcome"]})
}

fn lifecycle(
    report: &mut Value,
    snapshot: &Snapshot,
    detail: Option<&'static str>,
    subject: Value,
) {
    let summary = super::report::summary(snapshot);
    let operation = &summary["operation"];
    report["outcome"] = summary["outcome"].clone();
    report["failure"] = summary["failure"].clone();
    report["completion_unknown"] = summary["completion_unknown"].clone();
    report["cleanup_unknown"] = summary["cleanup_unknown"].clone();
    report["operations"] = json!([operation_summary(snapshot)]);
    let (choice, subject) = match summary["outcome"].as_str() {
        Some("succeeded") => ("none", Value::Null),
        Some("unknown") => {
            report["detail"] = Value::Null;
            let member = snapshot
                .steps
                .last()
                .map_or(Value::Null, |s| s["recipient"]["member"].clone());
            ("resume", member)
        }
        _ => {
            report["detail"] = detail.map_or(Value::Null, |d| json!(d));
            match detail {
                Some("replica-incomplete" | "platform") => ("rerun", Value::Null),
                Some("digest") => ("operator-recovery", Value::Null),
                Some(_) => ("deliver", subject),
                None => ("rerun", Value::Null),
            }
        }
    };
    let operation = if choice == "none" {
        Value::Null
    } else {
        operation.clone()
    };
    report["recovery"] = json!({"choice":choice,"operation":operation,"subject":subject});
}

pub(super) fn delivery_evidence(snapshot: &Snapshot) -> Option<(Value, Value)> {
    let recipe = recipe_of(snapshot)?;
    let nodes = delivery_nodes(snapshot, recipe);
    let evidence = rules::evidence(&json!({
        "managed":list(&recipe["images"]).iter().any(|i| i["managed"] == true),
        "fallback":recipe["fallback"],
        "nodes":nodes.iter().map(|(_, e, _)| e.clone()).collect::<Vec<_>>()}));
    Some((recipe["release"].clone(), evidence["evidence"].clone()))
}

fn deliver_report(
    context: &rpc::Context<'_>,
    snapshot: &Snapshot,
    record: &Value,
    store: Value,
    detail: Option<&'static str>,
) -> Value {
    let recipe = recipe_of(snapshot).cloned().unwrap_or(Value::Null);
    let nodes = delivery_nodes(snapshot, &recipe);
    let evidence = rules::evidence(&json!({
        "managed":list(&recipe["images"]).iter().any(|i| i["managed"] == true),
        "fallback":recipe["fallback"],
        "nodes":nodes.iter().map(|(_, e, _)| e.clone()).collect::<Vec<_>>()}));
    let (origin, _, _) = window(snapshot);
    let mut report = envelope(context, "release-deliver", store);
    report["application"] = record["application"].clone();
    report["release"] = record["release"].clone();
    report["writer"] = recipe["writer"].clone();
    report["evidence"] = evidence["evidence"].clone();
    report["excluded"] = recipe["excluded"].clone();
    report["nodes"] = Value::Array(nodes.into_iter().map(|(n, _, _)| n).collect());
    report["origin"] = origin;
    lifecycle(&mut report, snapshot, detail, record["release"].clone());
    if report["outcome"] == "succeeded" && evidence["outcome"] != "succeeded" {
        report["outcome"] = json!("failed");
        report["failure"] = json!("readiness");
        report["detail"] = json!("incomplete-delivery");
        report["recovery"] = json!({"choice":"deliver","operation":snapshot.request["operation"],
            "subject":record["release"]});
    }
    report
}

pub async fn delivery_report(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    release: &str,
) -> Leaf<Reported> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let loaded = records(&mut local).await;
    let _ = local.finish(&context.clock).await;
    let (previous, owner) = loaded?;
    let stored = releases(&context)?;
    if !stored.iter().any(|r| r["release"] == release) {
        return Err(refused(
            Failure::Configuration,
            "release",
            format!("{release} is not recorded for target {target}"),
        ));
    }
    let mut deliveries = Vec::new();
    let mut ordered: Vec<&Snapshot> = previous
        .iter()
        .filter(|s| s.request["action"] == "release-deliver")
        .filter(|s| recipe_of(s).is_some_and(|r| r["release"] == release))
        .collect();
    ordered.sort_by(|a, b| {
        (
            a.request["created_ms"].as_u64(),
            a.request["operation"].as_str(),
        )
            .cmp(&(
                b.request["created_ms"].as_u64(),
                b.request["operation"].as_str(),
            ))
    });
    for snapshot in ordered {
        let recipe = recipe_of(snapshot).cloned().unwrap_or(Value::Null);
        let (origin, started, ended) = window(snapshot);
        let ready = match (started.as_u64(), ended.as_u64()) {
            (Some(s), Some(e)) => json!(e.saturating_sub(s)),
            _ => Value::Null,
        };
        deliveries.push(json!({"ended_ms":ended,
            "nodes":delivery_nodes(snapshot, &recipe).into_iter().map(|(_, _, d)| d).collect::<Vec<_>>(),
            "operation":snapshot.request["operation"],"origin":origin,"started_ms":started,
            "time_to_ready_ms":ready,"writer":recipe["writer"]}));
    }
    let selected = rules::report(&json!({"target":target,"release":release,
        "deliveries":deliveries}))?;
    let members = super::survivors(&owner)?;
    let mut report = envelope(
        &context,
        "delivery-report",
        store_usage(&previous, None, &members, stored.len()),
    );
    report["release"] = selected["release"].clone();
    report["deliveries"] = selected["deliveries"].clone();
    report["truncated"] = selected["truncated"].clone();
    Ok((report, true))
}

pub async fn delivery_check(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
) -> Leaf<Reported> {
    let (context, owner, previous, rows) =
        super::views::replication_rows(project, policy, target).await?;
    let stored = releases(&context)?;
    let removed: Vec<Value> = list(&owner["removed"])
        .iter()
        .map(|r| r["member"].clone())
        .collect();
    let state = |row: Option<&Value>| -> Value {
        match row {
            Some(r) if r["failure"].is_null() && r["facts"].is_object() => {
                json!(if r["facts"]["ready"] == true {
                    "running"
                } else {
                    "stopped"
                })
            }
            Some(r) if r["failure"].is_null() => json!("absent"),
            _ => json!("unobserved"),
        }
    };
    let row = |kind: &str, member: &Value| {
        rows.iter()
            .find(|r| r["kind"] == kind && r["member"] == *member)
    };
    let mut members = Vec::new();
    let mut complete = true;
    for declared in &context.selected.declaration.members {
        let member = json!(declared.name);
        if removed.contains(&member) {
            members.push(
                json!({"completion":null,"folder":null,"member":member,"need_bytes":null,
                "peers_connected":null,"peers_expected":null,"reader":null,"replica":"removed",
                "token":null}),
            );
            continue;
        }
        let replica = row("registry-replica", &member);
        let facts = replica
            .filter(|r| r["failure"].is_null())
            .map_or(Value::Null, |r| r["facts"].clone());
        complete &= facts.is_object()
            && row("registry-reader", &member).is_some_and(|r| r["failure"].is_null())
            && row("registry-token-local", &member).is_some_and(|r| r["failure"].is_null());
        members.push(
            json!({"completion":facts["completion"],"folder":facts["folder"],
            "member":member,"need_bytes":facts["need_bytes"],
            "peers_connected":facts["peers_connected"],"peers_expected":facts["peers_expected"],
            "reader":state(row("registry-reader", &member)),
            "replica":if facts.is_object() { facts["state"].clone() } else { json!("unobserved") },
            "token":state(row("registry-token-local", &member))}),
        );
    }
    let survivors = super::survivors(&owner)?;
    let mut report = envelope(
        &context,
        "delivery-check",
        store_usage(&previous, None, &survivors, stored.len()),
    );
    report["writer"] = rows
        .iter()
        .find(|r| r["kind"] == "registry-writer")
        .map_or(Value::Null, |r| r["facts"]["writer"]["member"].clone());
    if report["writer"].is_null() {
        report["writer"] = json!(writer(&context, &owner).ok().flatten());
    }
    report["observed_ms"] = json!(now()?);
    report["members"] = Value::Array(members);
    if !complete {
        report["outcome"] = json!("incomplete");
        report["failure"] = json!("readiness");
        report["completion_unknown"] = json!(true);
        report["recovery"] = json!({"choice":"operator-recovery","reason":"readiness"});
    }
    Ok((report, complete))
}


struct Retention {
    owner: Value,
    members: Vec<Value>,
    previous: Vec<Snapshot>,
    stored: usize,
    keep: Value,
    released: Vec<Value>,
    effects: Vec<Value>,
    active: Value,
    approval: String,
    writer: Option<String>,
    platforms: Vec<Value>,
}

async fn retention(
    context: &rpc::Context<'_>,
    local: &mut Local,
    target: &str,
    application: &str,
) -> Leaf<Retention> {
    let (previous, owner) = records(local).await?;
    let members = owned(context, &owner)?;
    settled(&previous, target)?;
    let stored = releases(context)?;
    let history = kept_history(&previous, &stored);
    let derived = kept::derive(application, &history);
    let released = kept::released(application, &history);
    let by_id = |id: &Value| stored.iter().find(|r| r["release"] == *id);
    let mut candidates: Vec<(Value, Value, Value)> = Vec::new();
    for entry in list(&released) {
        let record = by_id(&entry["release"]).ok_or(Failure::Integrity)?;
        for image in list(&record["images"]) {
            if list(&entry["images"]).contains(&image["image"]) {
                candidates.push((
                    entry["release"].clone(),
                    image["image"].clone(),
                    image["reference"].clone(),
                ));
            }
        }
    }
    let mut references: Vec<Value> = Vec::new();
    for (_, _, reference) in &candidates {
        push_once(&mut references, reference);
    }
    let writer = writer(context, &owner)?;
    let operation = format!("infra-operation-{}", fresh()?);
    let mut effects = Vec::new();
    let mut platforms = Vec::new();
    if !references.is_empty() {
        platforms = members
            .iter()
            .map(|m| platform(&previous, &Value::Null, m))
            .collect::<Result<Vec<_>>>()?;
        let admission = recipe(
            context,
            json!({"owner":owner["owner"],"operation":operation,"cluster":owner["cluster"],
                "action":"release-retain","release":null,"release_sha256":null,"writer":writer,
                "fallback":managed_fallback(context),
                "members":members.iter().zip(&platforms).map(|(m, p)| json!({"member":m["member"],
                    "role":m["role"],"platform":p})).collect::<Vec<_>>(),
                "excluded":[],"images":[],
                "unpin":members.iter().map(|m| json!({"member":m["member"],"references":references}))
                    .collect::<Vec<_>>()}),
        )?;
        let request = json!({"scope":context.scope,"owner":owner["owner"],
            "operation":operation,"members":members,"participants_sha256":owner["participants_sha256"],
            "fingerprints":context.fingerprints});
        let mut stored_recipe = admission.clone();
        let attempt = stored_recipe["attempt"].as_str().unwrap_or("").to_owned();
        stored_recipe.as_object_mut().map(|r| r.remove("attempt"));
        let last = rules::retain_steps(members.len(), members.len()) as u64;
        for (index, member) in members.iter().enumerate() {
            let payload = payload(
                &request,
                &stored_recipe,
                "inspect-images",
                &member["member"],
                &[],
            )?;
            let mut cleanup = false;
            let read = super::registry_service::admission_read(
                context,
                &FAMILY,
                shape,
                &network::read_binding(&request, &attempt, last, index)?,
                "inspect-images",
                &payload,
                &mut cleanup,
            )
            .await;
            local.cleanup_unknown |= cleanup;
            let read = read?;
            for (release, image, reference) in &candidates {
                if inspected(&read, reference).is_some_and(|i| i["pinned"] == true) {
                    effects.push(
                        json!({"action":"unpin","image":image,"member":member["member"],
                        "release":release}),
                    );
                }
            }
        }
    }
    effects.sort_by_key(|e| {
        let member = members.iter().position(|m| m["member"] == e["member"]);
        let at = candidates
            .iter()
            .position(|(r, i, _)| *r == e["release"] && *i == e["image"]);
        (member, at)
    });
    let records: serde_json::Map<String, Value> = stored
        .iter()
        .filter_map(|r| {
            Some((
                r["release"].as_str()?.to_owned(),
                json!({"release_sha256":record::release_sha256(r)}),
            ))
        })
        .collect();
    let active = rules::retain_release(&derived, &Value::Object(records));
    let decision = json!({"schema":1,"scope":context.scope,"owner":owner["owner"],
        "action":"release-retain","application":application,"keep":derived["kept"],
        "released":released,"effects":effects,"members":members,
        "fingerprints":context.fingerprints});
    let approval = format!("sha256:{}", hash("broil-infra-approval-v1", &decision)?);
    Ok(Retention {
        owner,
        members,
        previous,
        stored: stored.len(),
        keep: derived["kept"].clone(),
        released: list(&released).to_vec(),
        effects,
        active,
        approval,
        writer,
        platforms,
    })
}

fn plan_report(
    context: &rpc::Context<'_>,
    application: &str,
    retention: Option<&Retention>,
) -> Value {
    let store = retention.map_or(Value::Null, |r| {
        store_usage(&r.previous, None, &r.members, r.stored)
    });
    let members: Vec<Value> = match retention {
        Some(r) => r.members.iter().map(|m| m["member"].clone()).collect(),
        None => context
            .selected
            .declaration
            .members
            .iter()
            .map(|m| json!(m.name))
            .collect(),
    };
    let unknown = if retention.is_some() {
        json!([])
    } else {
        json!(["ownership", "history", "pins"])
    };
    json!({"format_version":1,"scope":context.scope,"view":"plan","action":"release-retain",
        "members":members,"stages":[],"prerequisites":[],"unknown":unknown,
        "observed":retention.is_some(),"application":application,"member":null,"release":null,
        "effects":retention.map(|r| json!(r.effects)),"pods":null,"checks":null,
        "writer_move":null,"hooks":null,"objects":null,"settles":null,
        "keep":retention.map(|r| r.keep.clone()),"policy":null,"prune":null,"refusals":[],
        "approval":retention.map(|r| json!(r.approval)),"store":store})
}

pub async fn retain_plan(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    application: &str,
    observe: bool,
) -> Leaf<Value> {
    let context = rpc::Context::new(project, policy, target)?;
    if !observe {
        return Ok(plan_report(&context, application, None));
    }
    let mut local = Local::new(&context)?;
    let observed = retention(&context, &mut local, target, application).await;
    let _ = local.finish(&context.clock).await;
    Ok(plan_report(&context, application, Some(&observed?)))
}

pub async fn retain(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    application: &str,
    approve: &str,
) -> Leaf<Reported> {
    let context = rpc::Context::new(project, policy, target)?;
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let mut local = Local::new(&context)?;
    let admitted: Leaf<_> = async {
        let retention = retention(&context, &mut local, target, application).await?;
        if retention.approval != approve {
            return Err(refused(
                Failure::Ownership,
                "stale-approval",
                format!(
                    "the observed plan changed; run k3s plan {target} --action release-retain --application {application} --observe"
                ),
            ));
        }
        let mut with_effects = Vec::new();
        let mut unpin = Vec::new();
        for (index, member) in retention.members.iter().enumerate() {
            let mut references = Vec::new();
            for effect in retention.effects.iter().filter(|e| e["member"] == member["member"]) {
                let record = releases(&context)?
                    .into_iter()
                    .find(|r| r["release"] == effect["release"])
                    .ok_or(Failure::Integrity)?;
                let image = list(&record["images"])
                    .iter()
                    .find(|i| i["image"] == effect["image"])
                    .ok_or(Failure::Integrity)?
                    .clone();
                push_once(&mut references, &image["reference"]);
            }
            if !references.is_empty() {
                with_effects.push(index);
                unpin.push(json!({"member":member["member"],"references":references}));
            }
        }
        let operation = format!("infra-operation-{}", fresh()?);
        let recipe = recipe(
            &context,
            json!({"owner":retention.owner["owner"],"operation":operation,
                "cluster":retention.owner["cluster"],"action":"release-retain",
                "release":retention.active["release"],
                "release_sha256":retention.active["release_sha256"],
                "writer":retention.writer,"fallback":managed_fallback(&context),
                "members":with_effects.iter().map(|&i| json!({"member":retention.members[i]["member"],
                    "role":retention.members[i]["role"],"platform":retention.platforms[i]}))
                    .collect::<Vec<_>>(),
                "excluded":[],"images":[],"unpin":unpin}),
        )?;
        let count = rules::retain_steps(retention.members.len(), with_effects.len());
        if count > rules::STEP_LIMIT {
            return Err(refused(
                Failure::Bound,
                "size",
                format!("the operation needs {count} steps; the limit is {}", rules::STEP_LIMIT),
            ));
        }
        Ok((
            Admission {
                owner: retention.owner.clone(),
                members: retention.members.clone(),
                recipe,
                count,
            },
            retention,
            with_effects,
        ))
    }
    .await;
    let (admission, retention, with_effects) = match admitted {
        Ok(value) => value,
        Err(refusal) => {
            let _ = local.failure(refusal.failure, &context.clock).await;
            return Err(refusal);
        }
    };
    let attempt = match record_request(&context, &mut local, &admission, "release-retain").await {
        Ok(attempt) => attempt,
        Err(failure) => return Err(local.failure(failure, &context.clock).await.into()),
    };
    let mut session = session(context, local, attempt, admission.members.clone());
    let result = Box::pin(session.retain_run(with_effects)).await;
    session.unknown_run(&result).await;
    let finished = session.local.complete(result, &session.context.clock).await;
    let (snapshot, failed) = match finished {
        Ok(snapshot) => (Some(snapshot), None),
        Err(failure) => (failure.snapshot.map(|s| *s), Some(failure.failure)),
    };
    let snapshot = snapshot.ok_or(Failure::Integrity)?;
    let store = store_usage(
        &retention.previous,
        Some(&snapshot),
        &retention.members,
        retention.stored,
    );
    let mut report = envelope(&session.context, "release-retain", store);
    report["application"] = json!(application);
    report["keep"] = retention.keep.clone();
    let unpinned: Vec<Value> = snapshot
        .steps
        .iter()
        .filter(|s| s["action"] == action("unpin-image"))
        .filter(|s| {
            of_step(&snapshot, s).any(|o| {
                o["event"]["type"] == "receiver" && succeeded_receipt(Some(&o["event"]["receipt"]))
            })
        })
        .map(|s| s["recipient"]["member"].clone())
        .collect();
    report["released"] = Value::Array(
        retention
            .released
            .iter()
            .map(|entry| {
                let members: Vec<Value> = retention
                    .members
                    .iter()
                    .map(|m| m["member"].clone())
                    .filter(|m| {
                        unpinned.contains(m)
                            && retention
                                .effects
                                .iter()
                                .any(|e| e["member"] == *m && e["release"] == entry["release"])
                    })
                    .collect();
                json!({"images":entry["images"],"members_unpinned":members,
                    "release":entry["release"]})
            })
            .collect(),
    );
    lifecycle(
        &mut report,
        &snapshot,
        session.local.failure_detail,
        json!(application),
    );
    if let Some(failure) = failed {
        if report["outcome"] == "unknown" && report["failure"].is_null() {
            report["failure"] = json!(failure.name());
        }
    }
    let complete = report["outcome"] == "succeeded";
    Ok((report, complete))
}

