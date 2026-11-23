// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::release_delivery::{
    self as delivery, Leaf, Refused, Reported, envelope, operation_summary, records, refused,
    releases, store_usage,
};
use super::release_hooks;
use super::session::{Local, fresh, now};
use super::{Failure, Snapshot, rpc};
use crate::k3s::release::{self, binding, kept, record, select};
use broil_config::LoadedProject;
use broil_core::applications::{Application, DeliveryNodes, Hook, ManifestSource};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(super) const RECIPE: &str = "release-recipe";
pub(super) const OBSERVATION: &str = "release-observation";
pub(super) const HOOK: &str = "release-hook";
pub(super) const EVIDENCE: &str = "release-evidence";
pub(super) const SETTLEMENT: &str = "release-settlement";

pub(super) fn list(value: &Value) -> &[Value] {
    value.as_array().map_or(&[], Vec::as_slice)
}

fn manifest(detail: String) -> Refused {
    refused(Failure::Configuration, "manifest", detail)
}

fn size(bytes: usize) -> Refused {
    refused(
        Failure::Bound,
        "size",
        format!(
            "manifests are {bytes} bytes; the limit is {}",
            binding::MANIFEST_LIMIT
        ),
    )
}


struct Contribution {
    path: String,
    bytes: Vec<u8>,
}

fn contributions(root: &Path, declared: &[String]) -> Leaf<Vec<Contribution>> {
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut take = |path: String, out: &mut Vec<Contribution>| -> Leaf<()> {
        let full = root.join(&path);
        let length = std::fs::metadata(&full)
            .map_err(|_| manifest(format!("{path}: cannot be read")))?
            .len();
        total = total.saturating_add(usize::try_from(length).unwrap_or(usize::MAX));
        if total > binding::MANIFEST_LIMIT {
            return Err(size(total));
        }
        let bytes =
            std::fs::read(&full).map_err(|_| manifest(format!("{path}: cannot be read")))?;
        out.push(Contribution { path, bytes });
        Ok(())
    };
    for entry in declared {
        let full = root.join(entry);
        let metadata =
            std::fs::metadata(&full).map_err(|_| manifest(format!("{entry}: cannot be read")))?;
        if metadata.is_file() {
            take(entry.clone(), &mut out)?;
        } else if metadata.is_dir() {
            let mut names: Vec<Vec<u8>> = std::fs::read_dir(&full)
                .map_err(|_| manifest(format!("{entry}: cannot be read")))?
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                .map(|e| {
                    use std::os::unix::ffi::OsStrExt;
                    e.file_name().as_bytes().to_vec()
                })
                .filter(|n| n.ends_with(b".yaml") || n.ends_with(b".yml"))
                .collect();
            names.sort();
            if names.is_empty() {
                return Err(manifest(format!("{entry}: holds no .yaml or .yml file")));
            }
            let prefix = entry.trim_end_matches('/');
            for name in names {
                let name = String::from_utf8(name)
                    .map_err(|_| manifest(format!("{entry}: a file name is not UTF-8")))?;
                take(format!("{prefix}/{name}"), &mut out)?;
            }
        } else {
            return Err(manifest(format!("{entry}: is not a file or directory")));
        }
    }
    Ok(out)
}

fn concatenate(contributions: &[Contribution]) -> Leaf<Vec<u8>> {
    let parts: Vec<&[u8]> = contributions.iter().map(|c| c.bytes.as_slice()).collect();
    let input = release::concatenate(&parts);
    if input.len() > binding::MANIFEST_LIMIT {
        return Err(size(input.len()));
    }
    Ok(input)
}

fn hook_record(stage: &str, hook: &Hook, versions: &[Value]) -> Value {
    let secrets: Vec<Value> = hook
        .secrets
        .iter()
        .map(|(variable, r)| json!({"variable":variable,"set":r.set,"key":r.key}))
        .collect();
    let declaration = json!({"stage":stage,"name":hook.name,
        "location":release_hooks::location(hook),"argv":hook.argv,
        "timeout_ms":hook.timeout.seconds * 1000,"repeatable":hook.repeatable,
        "secrets":secrets});
    let sha256 = release::labeled("broil-k3s-release-hook-v1", &declaration);
    let secrets: Vec<Value> = hook
        .secrets
        .iter()
        .zip(versions)
        .map(|((variable, r), version)| {
            json!({"variable":variable,"set":r.set,"key":r.key,"version":version})
        })
        .collect();
    json!({"stage":stage,"name":hook.name,"location":release_hooks::location(hook),
        "argv":hook.argv,"timeout_ms":hook.timeout.seconds * 1000,
        "repeatable":hook.repeatable,"secrets":secrets,"sha256":sha256})
}

pub(super) struct Versions {
    vault: bool,
    vaulted: BTreeMap<String, Value>,
    store: Option<broil_secrets::store::Store>,
    sets: BTreeMap<String, Option<(Vec<String>, String)>>,
}

impl Versions {
    pub(super) async fn new(
        project: &LoadedProject,
        policy: &crate::k3s::Policy,
        sets: Vec<String>,
    ) -> Self {
        let selection = broil_secrets::read::Selection::new(
            &project.config,
            &project.broil_root,
            Some(std::ffi::OsStr::new(&policy.environment)),
        )
        .ok();
        let vault = selection
            .as_ref()
            .is_some_and(|s| s.config.vault.address.is_some());
        let store = selection
            .as_ref()
            .and_then(|s| broil_secrets::store::Store::open(&s.store_root()).ok());
        let vaulted = match selection {
            Some(selection) if vault => vault_versions(selection, policy, sets).await,
            _ => BTreeMap::new(),
        };
        Self {
            vault,
            vaulted,
            store,
            sets: BTreeMap::new(),
        }
    }

    pub(super) fn version(&mut self, set: &str, key: &str, subject: &str) -> Leaf<Value> {
        let store = &self.store;
        let metadata = self
            .sets
            .entry(set.to_owned())
            .or_insert_with(|| {
                let id = broil_secrets::store::SetId::new(set).ok()?;
                store.as_ref()?.plaintext_metadata(&id).ok()
            })
            .clone();
        if let Some((keys, _)) = &metadata {
            if !keys.iter().any(|k| k == key) {
                return Err(refused(
                    Failure::Credential,
                    "secret",
                    format!("{subject}: set {set} has no key {key}"),
                ));
            }
        }
        if self.vault {
            return Ok(self.vaulted.get(set).cloned().unwrap_or(Value::Null));
        }
        Ok(metadata
            .and_then(|(_, modified)| {
                release::version::secret_version(&json!({"sops":{"lastmodified":modified}}))
            })
            .map_or(Value::Null, |v| json!(v)))
    }
}

async fn vault_versions(
    selection: broil_secrets::read::Selection,
    policy: &crate::k3s::Policy,
    sets: Vec<String>,
) -> BTreeMap<String, Value> {
    let none = || sets.iter().map(|s| (s.clone(), Value::Null)).collect();
    let Ok(mut inputs) = policy.credentials.try_duplicate() else {
        return none();
    };
    let cwd = policy.cwd.clone();
    let non_interactive = policy.non_interactive;
    let cancellation = policy.cancellation.clone();
    let deadline = policy.deadline;
    let wanted = sets.clone();
    let work = tokio::task::spawn_blocking(move || {
        let control = broil_secrets::identity::AcquisitionControl::new(
            move || cancellation.is_cancelled() || tokio::time::Instant::now() >= deadline,
            || Box::new(()),
        );
        let mut found = BTreeMap::new();
        let mut keys = None;
        let Ok(mut session) = broil_secrets::vault::Session::open_controlled(
            &selection,
            &cwd,
            &mut inputs,
            non_interactive,
            &mut keys,
            false,
            &control,
        ) else {
            return found;
        };
        let mount = selection
            .config
            .vault
            .mount
            .clone()
            .unwrap_or_else(|| "secret".to_owned());
        let token = zeroize::Zeroizing::new(session.token().to_owned());
        for set in wanted {
            let version = broil_secrets::store::SetId::new(&set)
                .ok()
                .and_then(|id| {
                    session
                        .client
                        .read_metadata_optional(&token, &mount, id.as_str())
                        .ok()
                        .flatten()
                })
                .and_then(|metadata| {
                    metadata
                        .get("current_version")
                        .and_then(|v| v.scalar())
                        .and_then(|v| {
                            release::version::secret_version(
                                &json!({"vault":{"current_version":v}}),
                            )
                        })
                        .map(|v| json!(v))
                });
            found.insert(set, version.unwrap_or(Value::Null));
        }
        drop(token);
        let _ = session.cleanup();
        found
    });
    match tokio::time::timeout_at(policy.deadline, work).await {
        Ok(Ok(found)) => found,
        _ => none(),
    }
}

fn host_platform(previous: &[Snapshot], machine: &Value) -> Option<String> {
    previous
        .iter()
        .flat_map(|s| s.observations.iter())
        .filter(|o| {
            o["event"]["type"] == "bootstrap-host" && o["event"]["member"]["machine"] == *machine
        })
        .max_by_key(|o| o["recorded_ms"].as_u64())
        .and_then(|o| o["event"]["facts"]["architecture"].as_str())
        .map(|arch| format!("linux/{arch}"))
}

fn policy(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    owner: &Value,
    application: &Application,
    name: &str,
) -> Leaf<Value> {
    let removed: BTreeSet<&str> = list(&owner["removed"])
        .iter()
        .filter_map(|r| r["member"].as_str())
        .collect();
    let declared = &context.selected.declaration.members;
    let nodes = match &application.delivery_nodes {
        DeliveryNodes::All => json!("all"),
        DeliveryNodes::Members(members) => json!({"members":members}),
        DeliveryNodes::Labels(labels) => json!({"labels":labels}),
    };
    if let DeliveryNodes::Members(members) = &application.delivery_nodes {
        if let Some(gone) = members.iter().find(|m| removed.contains(m.as_str())) {
            return Err(refused(
                Failure::Configuration,
                "removed",
                format!(
                    "applications.{name}.delivery.nodes names {gone}, which is recorded as removed; replace it or edit the list"
                ),
            ));
        }
    }
    let mut members = Vec::new();
    let mut platforms = BTreeSet::new();
    for member in declared
        .iter()
        .filter(|m| !removed.contains(m.name.as_str()))
    {
        let chosen = match &application.delivery_nodes {
            DeliveryNodes::All => true,
            DeliveryNodes::Members(listed) => listed.contains(&member.name),
            DeliveryNodes::Labels(pairs) => pairs
                .iter()
                .all(|(k, v)| member.labels.get(k).is_some_and(|l| l == v)),
        };
        if !chosen {
            continue;
        }
        let machine = json!(member.machine);
        let platform = host_platform(previous, &machine).ok_or(Failure::Readiness)?;
        platforms.insert(platform);
        members.push(json!(member.name));
    }
    if members.is_empty() {
        return Err(refused(
            Failure::Readiness,
            "delivery",
            format!("applications.{name}.delivery.nodes selects no member of the target"),
        ));
    }
    Ok(json!({"nodes":nodes,"members":members,"platforms":platforms}))
}

fn origin_text(origin: &broil_core::images::reference::Origin) -> String {
    format!("{}://{}:{}", origin.scheme, origin.host, origin.port)
}

fn target_origins(context: &rpc::Context<'_>) -> (Vec<String>, Value) {
    let selected = &context.selected;
    let origins = selected
        .declaration
        .node_registries
        .iter()
        .filter_map(|n| selected.registries.get(&n.registry))
        .map(|c| origin_text(&c.declaration.endpoint.origin()))
        .collect();
    let managed = selected
        .declaration
        .registry
        .as_ref()
        .and_then(|r| selected.registries.get(&r.endpoint))
        .map_or(Value::Null, |e| {
            json!(origin_text(&e.declaration.endpoint.origin()))
        });
    (origins, managed)
}

fn candidates(project: &LoadedProject) -> Leaf<Vec<Value>> {
    let read = crate::images::records::step(
        &project.broil_root,
        30_000,
        5_000,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        move |root, active| {
            crate::images::records::release_candidates(root, active).map_err(Into::into)
        },
    )
    .map_err(|_| Failure::Storage)?;
    Ok(read
        .into_iter()
        .map(|mut record| {
            let publications: Vec<Value> = list(&record["publications"])
                .iter()
                .filter_map(|p| {
                    let endpoint = broil_core::images::reference::Endpoint::registry(
                        p["endpoint"].as_str()?,
                        true,
                    )?;
                    Some(json!({"origin":origin_text(&endpoint.origin()),
                        "repository":p["repository"],"root":p["root"],"bound":true}))
                })
                .collect();
            record["publications"] = Value::Array(publications);
            record
        })
        .collect())
}

fn explicit(option: Option<&str>) -> BTreeMap<String, String> {
    option
        .into_iter()
        .flat_map(|v| v.split(','))
        .filter_map(|pair| pair.split_once('='))
        .map(|(image, id)| (image.to_owned(), id.to_owned()))
        .collect()
}

fn scan(
    input: &[u8],
    contributions: &[Contribution],
    declared: &str,
    name: &str,
    namespace: &str,
    catalog: &BTreeSet<String>,
) -> Leaf<binding::Scan> {
    binding::scan_application(input, name, namespace, catalog).map_err(|whole| {
        let single = contributions.iter().find_map(|c| {
            binding::scan_application(&c.bytes, name, namespace, catalog)
                .err()
                .map(|r| (c.path.clone(), r))
        });
        let (source, refusal) = single.unwrap_or_else(|| (declared.to_owned(), whole));
        refused(
            delivery_failure(refusal.failure),
            refusal.boundary,
            format!("{source}: {}", refusal.detail),
        )
    })
}

fn delivery_failure(name: &str) -> Failure {
    match name {
        "configuration" => Failure::Configuration,
        "readiness" => Failure::Readiness,
        "bound" => Failure::Bound,
        "credential" => Failure::Credential,
        _ => Failure::Integrity,
    }
}

pub async fn prepare(
    project: &LoadedProject,
    policy_inputs: crate::k3s::Policy,
    target: &str,
    name: &str,
    artifacts: Option<&str>,
) -> Leaf<Reported> {
    let environment = policy_inputs.environment.clone();
    let application = project
        .config
        .environments
        .get(&environment)
        .and_then(|e| e.applications.get(name))
        .cloned()
        .ok_or(Failure::Configuration)?;
    let context = rpc::Context::new(project, policy_inputs, target)?;
    let mut local = Local::new(&context)?;
    let loaded = records(&mut local).await;
    let _ = local.finish(&context.clock).await;
    let (previous, owner) = loaded.map_err(|_| Failure::Readiness)?;
    if owner["cluster"].is_null() || owner["owner"].is_null() {
        return Err(Failure::Readiness.into());
    }
    let policy = policy(&context, &previous, &owner, &application, name)?;
    let root = &project.broil_root;
    let (input, contributions, source, files, render_hook) = match &application.source {
        ManifestSource::Manifests(declared) => {
            let contributions = contributions(root, declared)?;
            let input = concatenate(&contributions)?;
            let files: Vec<&str> = contributions.iter().map(|c| c.path.as_str()).collect();
            let files = json!(files);
            (input, contributions, "files", files, Value::Null)
        }
        ManifestSource::Render(hook) => {
            let variables = release_hooks::Variables {
                target,
                application: name,
                stage: "render",
                run: None,
            };
            let run = release_hooks::run(project, &context.policy, hook, &variables, true).await?;
            if run.outcome != "succeeded" {
                let detail = match (run.exit, run.signal.as_str()) {
                    (Some(code), _) => format!("render hook exited with status {code}"),
                    (None, Some(signal)) => format!("render hook ended by signal {signal}"),
                    _ => "render hook did not complete; check its argv and timeout".to_owned(),
                };
                return Err(refused(Failure::Readiness, "render-hook", detail));
            }
            let output = run.output.unwrap_or_default();
            if output.len() > release_hooks::RENDER_LIMIT {
                return Err(size(output.len()));
            }
            let hash = hook_record("render", hook, &[])["sha256"].clone();
            (output, Vec::new(), "render", json!([]), hash)
        }
    };
    if std::str::from_utf8(&input).is_err() {
        return Err(manifest("the manifests are not valid UTF-8".to_owned()));
    }
    let declared = match &application.source {
        ManifestSource::Manifests(declared) => declared.join(", "),
        ManifestSource::Render(_) => "render hook output".to_owned(),
    };
    let catalog: BTreeSet<String> =
        broil_config::images::select::select(project, Some(&environment))
            .map_err(|_| Failure::Configuration)?
            .images
            .keys()
            .cloned()
            .collect();
    let scanned = scan(
        &input,
        &contributions,
        &declared,
        name,
        &application.namespace,
        &catalog,
    )?;
    let chosen = explicit(artifacts);
    if let Some(unused) = chosen.keys().find(|image| !scanned.images.contains(image)) {
        return Err(refused(
            Failure::Configuration,
            "artifact",
            format!("--artifacts names image {unused}, which no manifest references"),
        ));
    }
    let records = candidates(project)?;
    let (origins, managed) = target_origins(&context);
    let mut images = Vec::new();
    let mut references = BTreeMap::new();
    for image in &scanned.images {
        let selected = select::artifact(&json!({"image":image,
            "explicit":chosen.get(image),"origins":origins,"target":target,
            "managed_origin":managed,"records":records}))?;
        references.insert(
            image.clone(),
            selected["reference"].as_str().unwrap_or("").to_owned(),
        );
        images.push(json!({"image":image,"artifact":selected["artifact"],
            "origin":selected["origin"],"managed":selected["managed"],
            "repository":selected["repository"],"root":selected["root"],
            "reference":selected["reference"],"platforms":selected["platforms"]}));
    }
    let bound = binding::substitute(&input, &references)?;
    if bound.len() > binding::MANIFEST_LIMIT {
        return Err(size(bound.len()));
    }
    let sets: BTreeSet<String> = application
        .secrets
        .iter()
        .flat_map(|s| s.keys.iter().map(|(_, r)| r.set.clone()))
        .chain(
            application
                .before_apply
                .iter()
                .chain(&application.health)
                .flat_map(|h| h.secrets.iter().map(|(_, r)| r.set.clone())),
        )
        .collect();
    let mut versions = Versions::new(project, &context.policy, sets.into_iter().collect()).await;
    let mut secrets = Vec::new();
    for secret in &application.secrets {
        let mut keys = Vec::new();
        for (data_key, reference) in &secret.keys {
            let version = versions.version(
                &reference.set,
                &reference.key,
                &format!("secret {}", secret.name),
            )?;
            keys.push(json!({"data_key":data_key,"set":reference.set,
                "key":reference.key,"version":version}));
        }
        release::check_secret_header(&json!({"application":name,
            "namespace":application.namespace,"secret":secret.name,
            "keys":secret.keys.iter().map(|(k, _)| k).collect::<Vec<_>>()}))?;
        secrets.push(json!({"secret":secret.name,"keys":keys}));
    }
    let mut hooks = Vec::new();
    for (stage, list) in [
        ("before_apply", &application.before_apply),
        ("health", &application.health),
    ] {
        for hook in list {
            let mut versions_of = Vec::new();
            for (variable, reference) in &hook.secrets {
                versions_of.push(versions.version(
                    &reference.set,
                    &reference.key,
                    &format!("hook {} variable {variable}", hook.name),
                )?);
            }
            hooks.push(hook_record(stage, hook, &versions_of));
        }
    }
    let objects = scanned.objects.clone();
    let manifests = json!({"source":source,"files":files,"render_hook":render_hook,
        "bytes":bound.len(),"sha256":release::sha256_hex(&[&bound]),"objects":objects});
    let mut record = json!({"schema":1,"kind":"release","scope":context.scope,
        "owner":owner["owner"],"release":null,"application":name,"created_ms":0,
        "namespace":application.namespace,
        "target":{"cluster":{"uid":owner["cluster"]["uid"],"ca_sha256":owner["cluster"]["ca_sha256"]},
            "owner":owner["owner"]},
        "images":images,"manifests":manifests,"secrets":secrets,"hooks":hooks,"policy":policy,
        "health_timeout_ms":application.health_timeout.seconds * 1000,"content_sha256":null});
    record["content_sha256"] = json!(record::content_sha256(&record));
    let mut priced = record.clone();
    priced["release"] = json!(format!("release-{}", "f".repeat(32)));
    release::report_price(&release::report_input(
        &priced,
        "prepare",
        list(&record["policy"]["members"]),
        &[],
    ))?;
    let store = delivery::release_store(&context)?;
    let mut local = Local::new(&context)?;
    let held = local
        .work(|store| store.history_records().map(|_| ()))
        .await;
    let published: Leaf<(Value, bool, usize)> = async {
        held?;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&store)
            .map_err(|_| Failure::Storage)?;
        let stored = releases(&context)?;
        if let Some(existing) = stored.iter().find(|r| {
            r["content_sha256"] == record["content_sha256"] && r["scope"] == context.scope
        }) {
            return Ok((existing.clone(), true, stored.len()));
        }
        if stored.len() >= release::store::RELEASE_LIMIT {
            return Err(refused(
                Failure::Bound,
                "store-full",
                format!(
                    "target {target} holds {} of {} release records and release prepare needs 1; run k3s plan {target} --action operation-prune --observe",
                    stored.len(),
                    release::store::RELEASE_LIMIT
                ),
            ));
        }
        record["release"] = json!(format!("release-{}", fresh()?));
        record["created_ms"] = json!(now()?);
        release::store::publish(&store, &record, &bound)?;
        Ok((record.clone(), false, stored.len() + 1))
    }
    .await;
    let _ = local.finish(&context.clock).await;
    let (record, existing, count) = published?;
    let members = super::survivors(&owner)?;
    let mut report = lifecycle_envelope(
        &context,
        "release-prepare",
        store_usage(&previous, None, &members, count),
    );
    report["outcome"] = json!("succeeded");
    report["existing"] = json!(existing);
    prepared_fields(&mut report, &record);
    Ok((report, true))
}

use std::os::unix::fs::DirBuilderExt;

pub(super) fn lifecycle_envelope(context: &rpc::Context<'_>, view: &str, store: Value) -> Value {
    let mut report = envelope(context, view, store);
    report["recovery"] = json!({"choice":"none","operation":null,"subject":null});
    report
}

fn prepared_fields(report: &mut Value, record: &Value) {
    report["application"] = record["application"].clone();
    report["release"] = record["release"].clone();
    report["created_ms"] = record["created_ms"].clone();
    report["images"] = Value::Array(
        list(&record["images"])
            .iter()
            .map(|i| {
                json!({"artifact":i["artifact"],"image":i["image"],"platforms":i["platforms"],
                "reference":i["reference"],"repository":i["repository"],"root":i["root"]})
            })
            .collect(),
    );
    let m = &record["manifests"];
    report["manifests"] = json!({"bytes":m["bytes"],"files":m["files"],
        "objects":list(&m["objects"]).iter().map(|o| json!({"kind":o["kind"],"name":o["name"],
            "namespace":o["namespace"]})).collect::<Vec<_>>(),
        "render_hook":m["render_hook"],"sha256":m["sha256"],"source":m["source"]});
    report["secrets"] = record["secrets"].clone();
    report["hooks"] = Value::Array(
        list(&record["hooks"])
            .iter()
            .map(|h| {
                json!({"location":h["location"],"name":h["name"],"secrets":h["secrets"],
                "sha256":h["sha256"],"stage":h["stage"]})
            })
            .collect(),
    );
    report["policy"] = record["policy"].clone();
    report["target"] = record["target"].clone();
}


pub(super) fn event<'s>(snapshot: &'s Snapshot, kind: &str) -> Option<&'s Value> {
    snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == kind)
        .map(|o| &o["event"])
}

pub(super) fn applied_release(snapshot: &Snapshot) -> Option<&Value> {
    if !matches!(
        snapshot.request["action"].as_str(),
        Some("release-apply" | "release-rollback")
    ) {
        return None;
    }
    event(snapshot, RECIPE).map(|e| &e["recipe"]["release"])
}

pub(super) fn ordered(mut snapshots: Vec<&Snapshot>) -> Vec<&Snapshot> {
    snapshots.sort_by(|a, b| {
        (
            b.request["created_ms"].as_u64(),
            b.request["operation"].as_str(),
        )
            .cmp(&(
                a.request["created_ms"].as_u64(),
                a.request["operation"].as_str(),
            ))
    });
    snapshots
}

fn evidence_records(previous: &[Snapshot], release: &Value) -> Value {
    let mut found = json!({"applied":null,"delivered":null,"healthy":null,"seeded":null});
    for snapshot in ordered(previous.iter().collect()) {
        let operation = &snapshot.request["operation"];
        if applied_release(snapshot) == Some(release) {
            if let Some(o) = snapshot
                .observations
                .iter()
                .find(|o| o["event"]["type"] == EVIDENCE)
            {
                for key in ["applied", "healthy"] {
                    if found[key].is_null() && o["event"][key] == true {
                        found[key] = json!({"observed_ms":o["recorded_ms"],"operation":operation});
                    }
                }
            }
        } else if snapshot.request["action"] == "release-deliver"
            && super::report::summary(snapshot)["outcome"] == "succeeded"
        {
            let Some((delivered, evidence)) = delivery::delivery_evidence(snapshot) else {
                continue;
            };
            if delivered != *release {
                continue;
            }
            let ended = snapshot
                .observations
                .last()
                .map_or(Value::Null, |o| o["recorded_ms"].clone());
            for key in ["delivered", "seeded"] {
                if found[key].is_null() && evidence[key] == true {
                    found[key] = json!({"observed_ms":ended,"operation":operation});
                }
            }
        }
    }
    found
}

pub(super) fn roles(previous: &[Snapshot], records: &[Value], application: &str) -> Value {
    kept::derive(application, &delivery::kept_history(previous, records))
}

fn role(roles: &Value, release: &Value) -> &'static str {
    if roles["active"] == *release {
        "active"
    } else if roles["rollback"] == *release {
        "rollback"
    } else if list(&roles["kept"]).contains(release) {
        "prepared"
    } else {
        "superseded"
    }
}

pub(super) fn secret_rows(snapshot: &Snapshot, record: &Value) -> Vec<Value> {
    let facts: Vec<&Value> = snapshot
        .observations
        .iter()
        .filter(|o| o["event"]["type"] == OBSERVATION && o["event"]["action"] == "apply-secret")
        .flat_map(|o| list(&o["event"]["facts"]["secrets"]))
        .collect();
    list(&record["secrets"])
        .iter()
        .map(|secret| {
            let keys: Vec<Value> = list(&secret["keys"])
                .iter()
                .map(|k| k["data_key"].clone())
                .collect();
            let fact = facts.iter().find(|f| f["name"] == secret["secret"]);
            let outcome = fact.map_or(json!("not-run"), |f| {
                if f["outcome"].is_null() {
                    json!("failed")
                } else {
                    f["outcome"].clone()
                }
            });
            json!({"keys":keys,"outcome":outcome,
                "prepared_version":secret["keys"][0]["version"],"secret":secret["secret"],
                "version":fact.map_or(Value::Null, |f| f["version"].clone())})
        })
        .collect()
}

pub(super) fn apply_run(snapshot: &Snapshot, record: &Value) -> Value {
    let evidence = event(snapshot, EVIDENCE);
    let hooks: Vec<Value> = snapshot
        .observations
        .iter()
        .filter(|o| o["event"]["type"] == HOOK && o["event"]["stage"] == "before_apply")
        .map(|o| {
            let e = &o["event"];
            json!({"duration_ms":e["duration_ms"],"exit":e["exit"],"location":e["location"],
                "name":e["name"],"outcome":e["outcome"],"stage":e["stage"]})
        })
        .collect();
    let checks: Vec<Value> = snapshot
        .observations
        .iter()
        .filter(|o| o["event"]["type"] == HOOK && o["event"]["stage"] == "health")
        .map(|o| {
            let e = &o["event"];
            json!({"duration_ms":e["duration_ms"],"exit":e["exit"],"name":e["name"],
                "outcome":e["outcome"]})
        })
        .collect();
    let replies = |action: &str| -> Vec<&Value> {
        snapshot
            .observations
            .iter()
            .filter(|o| o["event"]["type"] == OBSERVATION && o["event"]["action"] == action)
            .map(|o| &o["event"]["facts"])
            .collect()
    };
    let objects: Vec<Value> = replies("apply-objects")
        .into_iter()
        .flat_map(|f| list(&f["objects"]).to_vec())
        .map(|o| {
            json!({"kind":o["kind"],"name":o["name"],"namespace":o["namespace"],
            "outcome":o["outcome"]})
        })
        .collect();
    let secrets = secret_rows(snapshot, record);
    let workloads = super::release_apply::health_workloads(snapshot);
    let groups = super::release_apply::workload_group_count(record);
    let members: Vec<&str> = list(&snapshot.request["members"])
        .iter()
        .filter_map(|m| m["member"].as_str())
        .collect();
    let (_, truncated) = super::release_apply::undelivered_rows(snapshot, &members, groups);
    json!({"action":snapshot.request["action"],"operation":snapshot.request["operation"],
        "evidence":{"applied":evidence.is_some_and(|e| e["applied"] == true),
            "healthy":evidence.is_some_and(|e| e["healthy"] == true)},
        "health":{"checks":checks,"undelivered_truncated":truncated,"workloads":workloads},
        "hooks":hooks,"objects":objects,"secrets":secrets})
}

pub(super) async fn reads<'p>(
    project: &'p LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
) -> Leaf<(rpc::Context<'p>, Vec<Snapshot>, Value, Vec<Value>)> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let loaded = records(&mut local).await;
    let _ = local.finish(&context.clock).await;
    let (previous, owner) = loaded?;
    let stored = releases(&context)?;
    Ok((context, previous, owner, stored))
}

pub async fn list_releases(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    application: &str,
    limit: usize,
) -> Leaf<Reported> {
    let (context, previous, owner, stored) = reads(project, policy, target).await?;
    let mut own: Vec<&Value> = stored
        .iter()
        .filter(|r| r["application"] == application)
        .collect();
    if own.is_empty() {
        return Err(refused(
            Failure::Configuration,
            "release",
            format!("application {application} has no recorded release"),
        ));
    }
    own.sort_by(|a, b| {
        (b["created_ms"].as_u64(), b["release"].as_str())
            .cmp(&(a["created_ms"].as_u64(), a["release"].as_str()))
    });
    let roles = roles(&previous, &stored, application);
    let truncated = own.len() > limit;
    let rows: Vec<Value> = own
        .iter()
        .take(limit)
        .map(|r| {
            let found = evidence_records(&previous, &r["release"]);
            let evidence: serde_json::Map<String, Value> =
                ["applied", "delivered", "healthy", "seeded"]
                    .iter()
                    .map(|k| ((*k).to_owned(), json!(!found[*k].is_null())))
                    .collect();
            json!({"created_ms":r["created_ms"],"evidence":evidence,
                "images":list(&r["images"]).iter().map(|i| json!({"artifact":i["artifact"],
                    "image":i["image"]})).collect::<Vec<_>>(),
                "release":r["release"],"role":role(&roles, &r["release"])})
        })
        .collect();
    let members = super::survivors(&owner)?;
    let mut report = envelope(
        &context,
        "release-list",
        store_usage(&previous, None, &members, stored.len()),
    );
    report["application"] = json!(application);
    report["limit"] = json!(limit);
    report["releases"] = Value::Array(rows);
    report["truncated"] = json!(truncated);
    Ok((report, true))
}

pub async fn show(
    project: &LoadedProject,
    policy: crate::k3s::Policy,
    target: &str,
    release: &str,
) -> Leaf<Reported> {
    let (context, previous, owner, stored) = reads(project, policy, target).await?;
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
    let id = json!(release);
    let application = record["application"].as_str().unwrap_or("");
    let roles = roles(&previous, &stored, application);
    let mine: Vec<&Snapshot> = ordered(
        previous
            .iter()
            .filter(|s| {
                applied_release(s) == Some(&id)
                    || delivery::recipe_of(s).is_some_and(|r| r["release"] == id)
            })
            .collect(),
    );
    let runs: Vec<&&Snapshot> = mine
        .iter()
        .filter(|s| applied_release(s).is_some())
        .collect();
    let applies: Vec<Value> = runs
        .iter()
        .take(16)
        .map(|s| apply_run(s, &record))
        .collect();
    let truncated = runs.len() > 16
        || applies
            .iter()
            .any(|a| a["health"]["undelivered_truncated"] == true);
    let mut history: Vec<Value> = mine.iter().map(|s| operation_summary(s)).collect();
    history.reverse();
    let members = super::survivors(&owner)?;
    let mut report = envelope(
        &context,
        "release-show",
        store_usage(&previous, None, &members, stored.len()),
    );
    prepared_fields(&mut report, &record);
    report["existing"] = json!(true);
    report["role"] = json!(role(&roles, &id));
    report["evidence_records"] = evidence_records(&previous, &id);
    report["applies"] = Value::Array(applies);
    report["truncated"] = json!(truncated);
    report["history"] = Value::Array(history);
    Ok((report, true))
}
