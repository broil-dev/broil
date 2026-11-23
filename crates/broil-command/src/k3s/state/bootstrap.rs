// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::hosts::{self, index, local, manifest};
use broil_config::LoadedProject;
use broil_core::k3s::BootstrapMode;
use broil_remote::exec::private;
use serde_json::{Value, json};
use std::time::Duration;

const RECIPE_DOMAIN: &str = "broil-k3s-bootstrap-recipe-v1";
const CONTROL_LIMIT: usize = 65_536;
const RESERVE: usize = 16_266;
const BINDING_LIMIT: usize = 4096;
const RESOURCE_LIMIT: usize = 512;

pub(super) struct Manifest {
    pub(super) embedded: &'static index::Embedded,
    pub(super) mode: manifest::Mode,
    pub(super) document: Value,
    selected: Vec<(String, Option<String>)>,
}

struct Admitted {
    manifest: Manifest,
    selected: Vec<(String, Option<String>)>,
    bundle: Vec<(String, local::Held)>,
    bundle_directory: Option<std::path::PathBuf>,
}

const INPUT_DOMAIN: &str = "broil-k3s-bootstrap-input-v1";

pub(super) fn admit_manifest(context: &rpc::Context<'_>) -> Result<Manifest> {
    let embedded = index::embedded()?;
    let t = context.selected.declaration;
    require(embedded.index.version == t.version, Failure::Configuration)?;
    let mode = match t.bootstrap.mode {
        BootstrapMode::Online => manifest::Mode::Online,
        BootstrapMode::Bundle => manifest::Mode::Bundle,
    };
    let registry = match &t.registry {
        None => None,
        Some(r) => {
            let effective = context
                .selected
                .registries
                .get(&r.endpoint)
                .ok_or(Failure::Configuration)?;
            let origin = effective.declaration.endpoint.origin();
            Some(format!(
                "{}://{}:{}",
                origin.scheme, origin.host, origin.port
            ))
        }
    };
    let root = &context.project.broil_root;
    let held = local::open(
        root,
        &context.selected.bootstrap_manifest,
        manifest::MANIFEST_LIMIT as u64,
    )?;
    let bytes = held.read_all()?;
    let profile_sha256 = context.fingerprints["profile_sha256"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    let admitted = manifest::admit(
        &bytes,
        &embedded.index,
        mode,
        profile_sha256,
        registry.as_deref(),
    )?;
    let selected: Vec<&index::Asset> = admitted.assets.iter().map(|s| s.asset).collect();
    index::totals(&selected)?;
    Ok(Manifest {
        embedded,
        mode,
        document: admitted.document.clone(),
        selected: admitted
            .assets
            .iter()
            .map(|s| (s.asset.id.clone(), s.url.clone()))
            .collect(),
    })
}

fn admit(context: &rpc::Context<'_>) -> Result<Admitted> {
    let manifest = admit_manifest(context)?;
    let embedded = manifest.embedded;
    let root = &context.project.broil_root;
    let mut bundle = Vec::new();
    if manifest.mode == manifest::Mode::Bundle {
        let directory = context
            .selected
            .bootstrap_bundle
            .as_ref()
            .ok_or(Failure::Configuration)?;
        for (id, _) in &manifest.selected {
            let asset = embedded.index.asset(id).ok_or(Failure::Integrity)?;
            let file = local::open(root, &directory.join(&asset.filename), asset.size)?;
            require(file.size == asset.size, Failure::Configuration)?;
            match asset.format {
                index::Format::Raw => {
                    use std::io::Read;
                    let mut reader = (&file.file).take(asset.size + 1);
                    let mut buffer = vec![0u8; 65_536];
                    let mut digest = <sha2::Sha256 as sha2::Digest>::new();
                    let mut total = 0u64;
                    loop {
                        let count = reader.read(&mut buffer).map_err(|_| Failure::Storage)?;
                        if count == 0 {
                            break;
                        }
                        total += count as u64;
                        sha2::Digest::update(&mut digest, &buffer[..count]);
                    }
                    let hex: String = sha2::Digest::finalize(digest)
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    require(
                        total == asset.size && hex == asset.sha256,
                        Failure::Integrity,
                    )?;
                }
                _ => {
                    use std::io::Read;
                    let mut reader = &file.file;
                    let mut read = |buffer: &mut [u8]| -> Result<usize> {
                        reader.read(buffer).map_err(|_| Failure::Storage)
                    };
                    hosts::verify_archive(asset, Some(&embedded.policy), &mut read)?;
                }
            }
            file.recheck()?;
            bundle.push((asset.id.clone(), file));
        }
    }
    Ok(Admitted {
        selected: manifest.selected.clone(),
        manifest,
        bundle,
        bundle_directory: context.selected.bootstrap_bundle.clone(),
    })
}

fn accepted(facts: &Value) -> bool {
    facts["checks"]
        .as_array()
        .is_some_and(|checks| checks.iter().all(|c| c["status"] == "pass"))
}

struct Reply {
    ready: Option<Value>,
    result: Value,
}

fn reply(bytes: &[u8], header: &[u8], action: &str) -> Result<Reply> {
    require(
        bytes.len() <= CONTROL_LIMIT && bytes.starts_with(b"BK3SBOOT1\n"),
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
    let mut input = &bytes[10..];
    require(field(&mut input)? == header, Failure::Integrity)?;
    let mut frames = Vec::new();
    while !input.is_empty() {
        frames.push(field(&mut input)?);
        require(frames.len() <= 2, Failure::Integrity)?;
    }
    let result = frames.pop().ok_or(Failure::Integrity)?;
    let result = schema::decode(result, "BootstrapResult", CONTROL_LIMIT)?;
    let ready = match frames.pop() {
        None => None,
        Some(frame) => {
            require(action == "receive-asset", Failure::Integrity)?;
            Some(schema::decode(frame, "BootstrapReady", CONTROL_LIMIT)?)
        }
    };
    Ok(Reply { ready, result })
}

struct Observed {
    transport: Value,
    reply: Option<Reply>,
    failure: Option<Failure>,
}

async fn invoke(
    context: &rpc::Context<'_>,
    binding: &Value,
    action: &str,
    payload: &Value,
    deadline: tokio::time::Instant,
    child: Option<&private::CredentialClock>,
    ready: Option<&private::ReadySignal>,
) -> Observed {
    let mut observed = Observed {
        transport: json!({"dispatch":"none","exit":null,"signal":null,"input_released":true,"staging_cleanup":"clean"}),
        reply: None,
        failure: None,
    };
    let result = async {
        context.check()?;
        schema::validate(&canonical(binding)?, "Binding", 65536)?;
        require(
            binding["scope"] == context.scope && binding["fingerprints"] == context.fingerprints,
            Failure::Ownership,
        )?;
        let machine = binding["recipient"]["machine"]
            .as_str()
            .ok_or(Failure::Integrity)?;
        let connection = match Box::pin(context.connect_bootstrap(machine, deadline, child)).await {
            Ok(connection) => connection,
            Err(failure) => {
                observed.transport = rpc::transport(&failure);
                return Err(Failure::Transport);
            }
        };
        let prepared = (|| {
            require(
                context.member(machine, &connection, binding["recipient"]["node_uid"].clone())?
                    == binding["recipient"],
                Failure::Trust,
            )?;
            let cap = if child.is_some() { 7_200_000 } else { 30_000 };
            let remaining = connection
                .deadline()
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(cap) as u64;
            require(remaining > 0, Failure::Timeout)?;
            let request_id = if child.is_some() {
                binding["dispatch"].clone()
            } else {
                json!(fresh()?)
            };
            let header = json!({"protocol":"broil-k3s-bootstrap","version":1,"action":action,
                "request_id":request_id,"binding":binding,"remaining_ms":remaining,"payload":payload});
            let bytes = canonical(&header)?;
            schema::validate(&bytes, "BootstrapHeader", CONTROL_LIMIT)?;
            Ok(bytes)
        })();
        let bytes = match prepared {
            Ok(bytes) => bytes,
            Err(failure) => {
                let closed = connection.close().await;
                observed.transport = rpc::transport(&closed);
                return Err(failure);
            }
        };
        let output = match ready {
            Some(signal) => connection.run_bootstrap_ready(bytes.clone(), signal).await,
            None => connection.run_bootstrap(bytes.clone(), false).await,
        }
        .map_err(|_| Failure::Transport)?;
        observed.transport = rpc::transport(&output.observation);
        require(
            output.observation.failure.is_none()
                && output.observation.remote_status == Some(0)
                && output.observation.remote_signal.is_none()
                && !output.observation.unresolved_input
                && !output.observation.possible_staging_residue
                && output.stderr.bytes().is_empty(),
            Failure::Transport,
        )?;
        observed.reply = Some(reply(output.stdout.bytes(), &bytes, action)?);
        Ok(())
    }
    .await;
    observed.failure = result.err();
    observed
}

#[allow(clippy::too_many_arguments)]
async fn relay(
    context: &rpc::Context<'_>,
    mut receiver: tokio::sync::watch::Receiver<Option<zeroize::Zeroizing<Vec<u8>>>>,
    binding: &Value,
    payload: &Value,
    machine: &str,
    held: &local::Held,
    path: std::path::PathBuf,
    deadline: tokio::time::Instant,
) -> Result<()> {
    let frame = tokio::select! {
        biased;
        _ = context.policy.cancellation.cancelled() => return Err(Failure::Cancelled),
        changed = tokio::time::timeout_at(deadline, receiver.wait_for(Option::is_some)) => {
            let guard = changed.map_err(|_| Failure::Timeout)?.map_err(|_| Failure::Transport)?;
            guard.clone().ok_or(Failure::Transport)?
        }
    };
    let ready = schema::decode(&frame, "BootstrapReady", CONTROL_LIMIT)?;
    let input = &ready["input"];
    let asset = payload["asset"].as_str().ok_or(Failure::Integrity)?;
    let embedded = index::embedded()?;
    let pinned = embedded.index.asset(asset).ok_or(Failure::Integrity)?;
    let recipe_hash = hash(RECIPE_DOMAIN, &payload["recipe"])?;
    let account = binding["recipient"]["route"]["account"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    require(
        input["binding"] == *binding
            && input["resource"] == payload["resource"]
            && input["asset"] == asset
            && input["size"] == pinned.size
            && input["sha256"] == pinned.sha256
            && input["recipe_sha256"] == recipe_hash
            && input["account"] == account
            && input["temporary"] == "upload.tmp"
            && input["destination"] == "received"
            && ready["binding_sha256"] == hash(INPUT_DOMAIN, input)?,
        Failure::Ownership,
    )?;
    held.recheck()?;
    let upload = private::K3sUploadBinding {
        owner: binding["owner"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_string(),
        dispatch: binding["dispatch"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_string(),
        binding_sha256: ready["binding_sha256"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_string(),
        size: pinned.size,
    };
    let job = context.transfer_job(machine, path, &upload.destination())?;
    let connection = context.public_connection(machine).await?;
    let outcome = connection
        .upload_k3s(job, upload, deadline)
        .await
        .map_err(|_| Failure::Transport)?;
    held.recheck()?;
    require(
        outcome.failure.is_none() && outcome.transfer_complete && !outcome.unresolved_session,
        Failure::Transport,
    )
}

impl Session<'_> {
    fn bootstrap_step(
        &self,
        index: usize,
        tag: &str,
        payload: &Value,
        recipe: u64,
    ) -> Result<Value> {
        self.intended(
            index,
            &format!("bootstrap:{tag}"),
            payload,
            vec![json!(recipe)],
        )
    }

    async fn bootstrap_dispatch(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        recipe: u64,
        mutation: bool,
        source: Option<(&local::Held, std::path::PathBuf)>,
    ) -> Result<Value> {
        self.context.check()?;
        require(
            (self.mode == Mode::Work) == mutation && self.mode != Mode::SettlementOnly,
            Failure::Capability,
        )?;
        let previous_deadline = self.local.step_deadline;
        let mut deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        if tag == "receive-asset" {
            let machine = self.members[index]["machine"]
                .as_str()
                .ok_or(Failure::Integrity)?;
            let transfer = self
                .context
                .inventory
                .machines
                .iter()
                .find(|m| m.name == machine)
                .ok_or(Failure::Configuration)?
                .timeouts
                .transfer
                .seconds;
            deadline = deadline.min(tokio::time::Instant::now() + Duration::from_secs(transfer));
        }
        self.local.step_deadline = Some(deadline);
        let step = self.bootstrap_step(index, tag, &payload, recipe)?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let child = mutation.then(|| self.context.clock.for_credential_action(deadline));
        let observed = if tag == "receive-asset" {
            let (held, path) = source.ok_or(Failure::Capability)?;
            let (signal, receiver) = tokio::sync::watch::channel(None);
            let machine = step["recipient"]["machine"]
                .as_str()
                .ok_or(Failure::Integrity)?
                .to_string();
            let (observed, uploaded) = tokio::join!(
                invoke(
                    &self.context,
                    &binding,
                    tag,
                    &payload,
                    deadline,
                    child.as_ref(),
                    Some(&signal)
                ),
                relay(
                    &self.context,
                    receiver,
                    &binding,
                    &payload,
                    &machine,
                    held,
                    path,
                    deadline
                ),
            );
            if let Err(failure) = uploaded {
                if observed.failure.is_none()
                    && observed
                        .reply
                        .as_ref()
                        .is_some_and(|r| r.result["status"] == "ok")
                {
                    return Err(failure);
                }
            }
            observed
        } else {
            invoke(
                &self.context,
                &binding,
                tag,
                &payload,
                deadline,
                child.as_ref(),
                None,
            )
            .await
        };
        self.local.step_deadline = previous_deadline;
        if observed.failure.is_some() {
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
        let reply = observed
            .reply
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        let result = &reply.result;
        if !result["terminal"].is_null() {
            let receipt = &result["terminal"];
            require(
                receipt["binding"] == binding
                    && receipt["action"] == step["action"]
                    && receipt["payload_sha256"] == step["payload_sha256"],
                Failure::Ownership,
            )?;
            self.append(
                &step,
                json!({"type":"receiver","receipt":receipt,"transport":self.local_transport()}),
                true,
                receipt["completed_ms"].clone(),
            )
            .await?;
        }
        let ok = result["status"] == "ok";
        require(
            reply.ready.is_some() == (tag == "receive-asset" && ok) || !ok,
            Failure::Integrity,
        )?;
        match tag {
            "inspect-host" => {
                require(result["terminal"].is_null(), Failure::Integrity)?;
                if let Some(facts) = result.get("facts").filter(|f| !f.is_null()) {
                    self.append(
                        &step,
                        json!({"type":"bootstrap-host","member":self.members[index],"facts":facts}),
                        true,
                        Value::Null,
                    )
                    .await?;
                }
                let refused = match result["failure"].as_str() {
                    Some("ownership") => Failure::Ownership,
                    Some("busy") => Failure::Busy,
                    _ => Failure::Readiness,
                };
                require(ok && !result["facts"].is_null(), refused)?;
            }
            "prepare-generation" | "complete-generation" => {
                let marker = &result["marker"];
                if tag == "complete-generation" && ok {
                    let recipe_hash = self.recipe_hash()?;
                    require(
                        marker["scope"] == self.local.snapshot()?.request["scope"]
                            && marker["owner"] == self.local.snapshot()?.request["owner"]
                            && marker["operation"] == self.local.snapshot()?.request["operation"]
                            && marker["attempt"] == self.attempt["attempt"]
                            && marker["resource"] == payload["resource"]
                            && marker["recipe_sha256"] == recipe_hash,
                        Failure::Ownership,
                    )?;
                }
                self.append(
                    &step,
                    json!({"type":"bootstrap-generation","resource":payload["resource"],
                        "marker":if tag == "complete-generation" {marker.clone()} else {Value::Null},
                        "identity":result["terminal"]["resource_identity"]}),
                    true,
                    Value::Null,
                )
                .await?;
            }
            "download-asset" | "receive-asset" => {
                let events = result["assets"].as_array().ok_or(Failure::Integrity)?;
                for event in events {
                    require(
                        event["resource"] == payload["resource"]
                            && event["asset"] == payload["asset"],
                        Failure::Ownership,
                    )?;
                    self.append(
                        &step,
                        json!({"type":"bootstrap-asset","resource":event["resource"],"asset":event["asset"],
                            "identity":event["identity"],"state":event["state"]}),
                        true,
                        Value::Null,
                    )
                    .await?;
                }
                require(
                    !ok || events
                        .iter()
                        .any(|e| e["state"] == "verified" && !e["identity"].is_null()),
                    Failure::Readiness,
                )?;
            }
            _ => return Err(Failure::Capability),
        }
        require(ok, Failure::Readiness)?;
        if mutation {
            let receipt = &result["terminal"];
            require(
                receipt["outcome"] == "succeeded"
                    && receipt["effect"] == "complete"
                    && receipt["writer_ended"] == true,
                Failure::Readiness,
            )?;
            if let Some(mut child) = child {
                child.complete().map_err(|_| Failure::Timeout)?;
            }
        }
        self.next_step += 1;
        Ok(reply.result)
    }

    fn local_transport(&self) -> Value {
        json!({"dispatch":"confirmed","exit":0,"signal":null,"input_released":true,"staging_cleanup":"clean"})
    }

    fn recipe_hash(&self) -> Result<String> {
        let snapshot = self.local.snapshot()?;
        snapshot.request["fingerprints"]["tools"]
            .as_array()
            .and_then(|tools| tools.iter().find(|t| t["name"] == "bootstrap-recipe"))
            .and_then(|t| t["sha256"].as_str())
            .map(str::to_owned)
            .ok_or(Failure::Integrity)
    }
}

pub(super) fn declared(context: &rpc::Context<'_>, members: &Value) -> Result<(Value, Value)> {
    let target = context.selected.declaration;
    let mut hosts = Vec::new();
    for member in members.as_array().ok_or(Failure::Integrity)? {
        let machine = member["machine"].as_str().ok_or(Failure::Integrity)?;
        let declared = target
            .members
            .iter()
            .find(|m| m.machine == machine)
            .ok_or(Failure::Configuration)?;
        hosts.push(json!({"machine":machine,"interface":declared.interface,
            "node_ip":declared.node_ip.to_string()}));
    }
    let literal = |host: &str| {
        host.parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == host)
    };
    let mut endpoints: Vec<String> = [
        target.api.endpoint.authority.host.as_str(),
        target.registration_endpoint.authority.host.as_str(),
    ]
    .into_iter()
    .chain(target.api.tls_sans.iter().map(String::as_str))
    .filter(|host| !literal(host))
    .map(str::to_ascii_lowercase)
    .collect();
    endpoints.sort();
    endpoints.dedup();
    let cidr = |c: broil_core::k3s::Ipv4Cidr| format!("{}/{}", c.network, c.prefix);
    let network = json!({"pod_cidr":cidr(target.network.pod_cidr),
        "service_cidr":cidr(target.network.service_cidr),"endpoints":endpoints});
    Ok((Value::Array(hosts), network))
}

struct Assembled {
    pub owner: String,
    pub operation: String,
    pub attempt: String,
    pub resources: Vec<Value>,
    pub participants: String,
    pub recipe: Value,
    pub recipe_hash: String,
}

type Attributed<T> = std::result::Result<T, (Failure, Option<&'static str>)>;

fn admit_recipe(recipe: &Value) -> Attributed<()> {
    let bytes = canonical(recipe).map_err(|f| (f, None))?;
    if bytes.len() > 65536 {
        return Err((Failure::Bound, Some("record")));
    }
    schema::validate(&bytes, "BootstrapRecipe", 65536).map_err(|f| (f, None))
}

fn assemble(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    members: &Value,
    owner: String,
) -> Attributed<Assembled> {
    assemble_selected(context, admitted, members, members, owner)
}

fn assemble_selected(
    context: &rpc::Context<'_>,
    admitted: &Admitted,
    members: &Value,
    selected: &Value,
    owner: String,
) -> Attributed<Assembled> {
    let plain = |f: Failure| (f, None);
    let operation = format!("infra-operation-{}", fresh().map_err(plain)?);
    let attempt = fresh().map_err(plain)?;
    let participants = super::participants(members).map_err(plain)?;
    let mut resources = Vec::new();
    for member in selected.as_array().ok_or(plain(Failure::Integrity))? {
        let machine = member["machine"]
            .as_str()
            .ok_or(plain(Failure::Integrity))?;
        require(
            crate::k3s::protocol::opaque(machine),
            Failure::Configuration,
        )
        .map_err(plain)?;
        let generation = fresh().map_err(plain)?;
        resources.push(json!({"kind":"bootstrap-assets","id":machine,"owner":owner,"generation":generation,
            "machine":machine,"path":format!("/var/lib/broil/k3s/owners/{owner}/assets/{generation}/"),
            "namespace":null,"name":null,"uid":null}));
    }
    let (hosts, network) = declared(context, selected).map_err(plain)?;
    let recipe = json!({"schema":1,"scope":context.scope,"owner":owner,"operation":operation,"attempt":attempt,
        "members":members,"resources":resources,"mode":admitted.manifest.mode.name(),"manifest":admitted.manifest.document,
        "index_sha256":admitted.manifest.embedded.index.sha256,"hosts":hosts,"network":network});
    admit_recipe(&recipe)?;
    let recipe_hash = hash(RECIPE_DOMAIN, &recipe).map_err(plain)?;
    Ok(Assembled {
        owner,
        operation,
        attempt,
        resources,
        participants,
        recipe,
        recipe_hash,
    })
}

fn recipe_observation(scope: &Value, assembled: &Assembled, recorded_ms: u64) -> Value {
    json!({"schema":1,"kind":"observation","scope":scope,"owner":assembled.owner,"operation":assembled.operation,
        "sequence":1,"recorded_ms":recorded_ms,"producer_ms":null,"source":{"kind":"controller","machine":null},
        "attempt":assembled.attempt,"step":null,"dispatch":null,"event":{"type":"bootstrap-recipe","recipe":assembled.recipe}})
}

fn bounds(
    scope: &Value,
    fingerprints: &Value,
    assembled: &Assembled,
    members: &[Value],
    asset_ids: &[String],
    recorded_ms: u64,
) -> std::result::Result<(), &'static str> {
    let length = |value: &Value| canonical(value).map_or(usize::MAX, |bytes| bytes.len());
    let observation = recipe_observation(scope, assembled, recorded_ms);
    if length(&observation).saturating_add(1) > 65536 {
        return Err("record");
    }
    let longest_id = asset_ids.iter().max_by_key(|id| id.len()).cloned();
    let (mut header, mut binding, mut resource) = (0usize, 0usize, 0usize);
    for (member, owned) in members.iter().zip(&assembled.resources) {
        let candidate = json!({"scope":scope,"owner":assembled.owner,"operation":assembled.operation,
            "attempt":assembled.attempt,"step":u32::MAX,"dispatch":"0".repeat(32),"recipient":member,
            "receiver_generation":u64::MAX,"request_sha256":"0".repeat(64),
            "participants_sha256":assembled.participants,"fingerprints":fingerprints});
        binding = binding.max(length(&candidate));
        resource = resource.max(length(owned));
        for (action, asset) in [
            ("inspect-host", None),
            ("inspect-generation", None),
            ("prepare-generation", None),
            ("download-asset", longest_id.as_deref()),
            ("receive-asset", longest_id.as_deref()),
            ("complete-generation", None),
        ] {
            let value = json!({"protocol":"broil-k3s-bootstrap","version":1,"action":action,
                "request_id":"0".repeat(32),"binding":candidate,"remaining_ms":7_200_000,
                "payload":{"recipe":assembled.recipe,"resource":owned,"asset":asset}});
            header = header.max(length(&value));
        }
    }
    if binding > BINDING_LIMIT {
        return Err("binding");
    }
    if resource > RESOURCE_LIMIT {
        return Err("resource");
    }
    if header > CONTROL_LIMIT {
        return Err("header");
    }
    if 14usize.saturating_add(header).saturating_add(RESERVE) > CONTROL_LIMIT {
        return Err("header-reply");
    }
    Ok(())
}

pub(super) fn repeat_candidate(
    snapshot: &Snapshot,
    admitted: &Manifest,
    members: &Value,
    hosts: &Value,
    network: &Value,
) -> bool {
    if snapshot.request["action"] != "prepare-hosts"
        || super::report::summary(snapshot)["outcome"] != "succeeded"
    {
        return false;
    }
    let Some(recipe) = snapshot
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "bootstrap-recipe")
        .map(|o| &o["event"]["recipe"])
    else {
        return false;
    };
    recipe["members"] == *members
        && recipe["hosts"] == *hosts
        && recipe["network"] == *network
        && recipe["mode"] == admitted.mode.name()
        && recipe["manifest"] == admitted.document
        && recipe["index_sha256"] == admitted.embedded.index.sha256
        && members.as_array().is_some_and(|ms| {
            ms.iter().all(|m| {
                snapshot.observations.iter().any(|o| {
                    o["event"]["type"] == "bootstrap-generation"
                        && !o["event"]["marker"].is_null()
                        && o["source"]["machine"] == m["machine"]
                })
            })
        })
}

pub(super) fn selection_generation<'p>(
    context: &rpc::Context<'_>,
    previous: &'p [Snapshot],
    members: &Value,
    machine: &str,
) -> Result<Option<&'p Value>> {
    let manifest = admit_manifest(context)?;
    let mut projection = members.clone();
    for member in projection.as_array_mut().ok_or(Failure::Integrity)? {
        member["node_uid"] = Value::Null;
    }
    let (hosts, network) = declared(context, members)?;
    Ok(previous
        .iter()
        .filter(|s| completed(context, s))
        .find(|s| repeat_candidate(s, &manifest, &projection, &hosts, &network))
        .and_then(|s| marker_event(s, machine)))
}

pub(super) fn replacement_generation<'p>(
    context: &rpc::Context<'_>,
    previous: &'p [Snapshot],
    machine: &str,
) -> Option<&'p Value> {
    previous
        .iter()
        .filter(|s| {
            s.request["action"] == "prepare-hosts"
                && !s.request["cluster"].is_null()
                && s.request["resources"]
                    .as_array()
                    .is_some_and(|r| r.len() == 1 && r[0]["machine"] == machine)
                && completed(context, s)
        })
        .max_by_key(|s| s.request["sequence"].as_u64())
        .and_then(|s| marker_event(s, machine))
}

fn completed(context: &rpc::Context<'_>, snapshot: &Snapshot) -> bool {
    super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        .is_ok_and(|report| report["outcome"] == "succeeded" && report["cleanup_unknown"] == false)
}

fn marker_event<'p>(snapshot: &'p Snapshot, machine: &str) -> Option<&'p Value> {
    snapshot.observations.iter().find(|o| {
        o["event"]["type"] == "bootstrap-generation"
            && !o["event"]["marker"].is_null()
            && o["source"]["machine"] == machine
    })
}

async fn repeat(
    context: &mut rpc::Context<'_>,
    local: &mut Local,
    prior: Snapshot,
) -> Result<Snapshot> {
    let recipe_hash = prior.request["fingerprints"]["tools"]
        .as_array()
        .and_then(|tools| tools.iter().find(|t| t["name"] == "bootstrap-recipe"))
        .and_then(|t| t["sha256"].as_str())
        .ok_or(Failure::Integrity)?
        .to_string();
    context.bind_recipe(&recipe_hash)?;
    let id = prior.request["operation"]
        .as_str()
        .ok_or(Failure::Integrity)?
        .to_string();
    local.work(move |store| store.lock(&id)).await?;
    let resources = prior.request["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    let members: Vec<Value> = prior.request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|m| resources.iter().any(|r| r["machine"] == m["machine"]))
        .cloned()
        .collect();
    for member in &members {
        let step = prior
            .steps
            .iter()
            .filter(|s| s["action"] == "bootstrap:complete-generation" && s["recipient"] == *member)
            .max_by_key(|s| s["step"].as_u64())
            .ok_or(Failure::Integrity)?
            .clone();
        let recorded = prior
            .observations
            .iter()
            .find(|o| {
                o["step"] == step["step"]
                    && o["dispatch"] == step["dispatch"]
                    && o["event"]["type"] == "bootstrap-generation"
                    && !o["event"]["marker"].is_null()
            })
            .map(|o| o["event"]["marker"].clone())
            .ok_or(Failure::Integrity)?;
        let payload = prior.bootstrap_payload(&step)?;
        let binding = prior.binding(&step);
        let deadline = context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(context.selected.step_timeout.seconds),
        );
        local.step_deadline = Some(deadline);
        let observed = invoke(
            context,
            &binding,
            "inspect-generation",
            &payload,
            deadline,
            None,
            None,
        )
        .await;
        local
            .append(
                Some(&step),
                json!({"type":"dispatch","transport":observed.transport,
                    "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                    "failure":observed.failure.map(Failure::name)}),
                None,
                Value::Null,
            )
            .await?;
        let reply = observed
            .reply
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        let result = &reply.result;
        require(
            result["status"] == "ok"
                && result["terminal"].is_null()
                && result["marker"] == recorded,
            Failure::Integrity,
        )?;
        let assets = result["assets"].as_array().ok_or(Failure::Integrity)?;
        for entry in recorded["assets"].as_array().ok_or(Failure::Integrity)? {
            require(
                assets.iter().any(|a| {
                    a["asset"] == entry["id"]
                        && a["state"] == "verified"
                        && a["identity"] == entry["identity"]
                        && a["resource"] == payload["resource"]
                }),
                Failure::Integrity,
            )?;
        }
        local
            .append(
                Some(&step),
                json!({"type":"bootstrap-generation","resource":payload["resource"],
                    "marker":recorded,"identity":recorded["directory"]}),
                Some(&member["machine"]),
                Value::Null,
            )
            .await?;
    }
    Ok(local.snapshot()?.clone())
}

pub async fn prepare_hosts(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let mut context = rpc::Context::new(project, policy, target)?;
    let admitted = admit(&context)?;
    let members = context.authenticate().await?;
    let mut local = Local::new(&context)?;
    let (hosts, network) = match declared(&context, &members) {
        Ok(declared) => declared,
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
    };
    let previous = match local
        .work(|store| store.read_operations(None).map_err(|e| e.failure))
        .await
    {
        Ok(previous) => previous,
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
    };
    let checked: Result<Option<Snapshot>> = (|| {
        for snapshot in &previous {
            let report =
                super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?;
            super::session::settled(&report)?;
        }
        Ok(previous
            .iter()
            .find(|s| repeat_candidate(s, &admitted.manifest, &members, &hosts, &network))
            .cloned())
    })();
    match checked {
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
        Ok(Some(prior)) => {
            let result = Box::pin(repeat(&mut context, &mut local, prior)).await;
            return local.complete(result, &context.clock).await;
        }
        Ok(None) => {}
    }
    let refused: std::cell::Cell<Option<&'static str>> = std::cell::Cell::new(None);
    let prepared: Result<_> = async {
        let owner = previous
            .first()
            .map(|s| {
                s.owner["owner"]
                    .as_str()
                    .ok_or(Failure::Integrity)
                    .map(str::to_owned)
            })
            .transpose()?
            .map_or_else(fresh, Ok)?;
        let assembled = match assemble(&context, &admitted, &members, owner) {
            Ok(assembled) => assembled,
            Err((failure, detail)) => {
                refused.set(detail);
                return Err(failure);
            }
        };
        context.bind_recipe(&assembled.recipe_hash)?;
        let created = now()?;
        let asset_ids: Vec<String> = admitted.selected.iter().map(|(id, _)| id.clone()).collect();
        let member_list = members.as_array().ok_or(Failure::Integrity)?;
        if let Err(bound) = bounds(
            &context.scope,
            &context.fingerprints,
            &assembled,
            member_list,
            &asset_ids,
            created,
        ) {
            refused.set(Some(bound));
            return Err(Failure::Bound);
        }
        let Assembled {
            owner,
            operation,
            attempt,
            resources,
            participants,
            recipe,
            ..
        } = assembled;
        let member_list = member_list.clone();
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":owner,"operation":operation,
            "created_ms":created,"sequence":request_sequence,"action":"prepare-hosts","members":members,"cluster":null,"resources":resources,
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,"step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let owned = if let Some(snapshot) = previous.first() {
            let owned = &snapshot.owner;
            require(
                owned["members"] == members
                    && owned["cluster"].is_null()
                    && owned["fingerprints"] == context.owner_fingerprints
                    && owned["participants_sha256"] == participants,
                Failure::Ownership,
            )?;
            owned.clone()
        } else {
            json!({"schema":1,"kind":"owner","scope":context.scope,"owner":owner,"generation":fresh()?,"previous_generation":null,
                "created_ms":created,"members":members,"cluster":null,"resources":[],"fingerprints":context.owner_fingerprints,
                "participants_sha256":participants,"lock_identity":[0,0],"writer":null,"removed":[],
                "maintained":false})
        };
        let generations: Vec<u64> = member_list
            .iter()
            .map(|member| {
                previous
                    .iter()
                    .flat_map(|s| &s.observations)
                    .filter(|o| {
                        o["event"]["type"] == "reservation"
                            && o["event"]["state"] == "retired"
                            && o["event"]["member"] == *member
                    })
                    .filter_map(|o| o["event"]["generation"].as_u64())
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let per_member = admitted.selected.len().checked_add(7).ok_or(Failure::Bound)?;
        let count = member_list.len().checked_mul(per_member).ok_or(Failure::Bound)?;
        require(count <= 1024, Failure::Bound)?;
        let attempt_record = json!({"schema":1,"kind":"attempt","scope":context.scope,"owner":owner,"operation":operation,"attempt":attempt,
            "created_ms":created,"request_sha256":hash("broil-infra-request-v1",&request)?,"parent_attempt":null,"original_step":null,
            "approval":null,"steps":(1..=count).collect::<Vec<_>>()});
        let stored = attempt_record.clone();
        local
            .work(move |store| store.create(owned, request, stored))
            .await?;
        let observation = json!({"schema":1,"kind":"observation","scope":context.scope,"owner":owner,"operation":operation,
            "sequence":1,"recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
            "attempt":attempt,"step":null,"dispatch":null,"event":{"type":"bootstrap-recipe","recipe":recipe}});
        local.work(move |store| store.append(observation)).await?;
        let sequence = local
            .snapshot()?
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "bootstrap-recipe")
            .and_then(|o| o["sequence"].as_u64())
            .ok_or(Failure::Integrity)?;
        Ok((attempt_record, generations, member_list, resources, sequence))
    }
    .await;
    let (attempt, generations, member_list, resources, recipe_sequence) = match prepared {
        Ok(value) => value,
        Err(failure) => {
            let mut failed = local.failure(failure, &context.clock).await;
            failed.detail = refused.get();
            return Err(failed);
        }
    };
    let mut session = Session {
        context,
        local,
        attempt,
        members: member_list,
        generations,
        next_step: 1,
        consumer: None,
        existing_resources: false,
        mode: Mode::Acquiring,
        retry_input: None,
        agent_view_wait: false,
        wave_boundary: None,
        wave_operations: Vec::new(),
        wave_gate_needed: false,
    };
    let selected = (0..session.members.len()).collect();
    let result =
        Box::pin(session.prepare_hosts(&admitted, resources, selected, recipe_sequence)).await;
    session.local.complete(result, &session.context.clock).await
}

pub async fn prepare_replacement(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
    member: &str,
) -> super::ExecutionResult<Snapshot> {
    let mut context = rpc::Context::new(project, policy, target)?;
    let admitted = admit(&context)?;
    let mut local = Local::new(&context)?;
    let previous = match local
        .work(|store| store.read_operations(None).map_err(|e| e.failure))
        .await
    {
        Ok(previous) => previous,
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
    };
    let checked: Result<(Value, Value, Value)> = async {
        for snapshot in &previous {
            let report =
                super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?;
            super::session::settled(&report)?;
        }
        let owner = previous.first().ok_or(Failure::Ownership)?.owner.clone();
        let transition =
            super::member::replacing(&previous, member).ok_or(Failure::Configuration)?;
        let members = json!(super::survivors(&owner)?);
        let entry = members
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .find(|m| m["member"] == member)
            .cloned()
            .ok_or(Failure::Ownership)?;
        require(
            transition["same_machine"] == false
                && entry["machine"] == transition["new_machine"]
                && entry["node_uid"].is_null()
                && !owner["cluster"].is_null()
                && owner["fingerprints"] == context.owner_fingerprints
                && owner["participants_sha256"] == json!(super::participants(&members)?),
            Failure::Ownership,
        )?;
        let original = previous
            .iter()
            .filter(|s| s.request["action"] == "prepare-hosts" && s.request["cluster"].is_null())
            .filter(|s| super::report::summary(s)["outcome"] == "succeeded")
            .find_map(|s| {
                s.observations
                    .iter()
                    .find(|o| o["event"]["type"] == "bootstrap-recipe")
                    .map(|o| o["event"]["recipe"].clone())
            })
            .ok_or(Failure::Ownership)?;
        require(
            original["mode"] == admitted.manifest.mode.name()
                && original["manifest"] == admitted.manifest.document
                && original["index_sha256"] == admitted.manifest.embedded.index.sha256,
            Failure::Ownership,
        )?;
        let machine = entry["machine"].as_str().ok_or(Failure::Integrity)?;
        let mut probed = context.probe(machine).await?;
        probed["node_uid"] = Value::Null;
        require(probed == entry, Failure::Ownership)?;
        Ok((owner, members, entry))
    }
    .await;
    let (owner, members, entry) = match checked {
        Ok(checked) => checked,
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
    };
    let selection = json!([entry]);
    let (hosts, network) = match declared(&context, &selection) {
        Ok(declared) => declared,
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
    };
    if let Some(prior) = previous
        .iter()
        .find(|s| {
            repeat_candidate(s, &admitted.manifest, &members, &hosts, &network)
                && s.request["resources"]
                    .as_array()
                    .is_some_and(|r| r.len() == 1)
        })
        .cloned()
    {
        let result = Box::pin(repeat(&mut context, &mut local, prior)).await;
        return local.complete(result, &context.clock).await;
    }
    let refused: std::cell::Cell<Option<&'static str>> = std::cell::Cell::new(None);
    let prepared: Result<_> = async {
        let name = owner["owner"].as_str().ok_or(Failure::Integrity)?.to_owned();
        let assembled = match assemble_selected(&context, &admitted, &members, &selection, name) {
            Ok(assembled) => assembled,
            Err((failure, detail)) => {
                refused.set(detail);
                return Err(failure);
            }
        };
        context.bind_recipe(&assembled.recipe_hash)?;
        let created = now()?;
        let asset_ids: Vec<String> = admitted.selected.iter().map(|(id, _)| id.clone()).collect();
        if let Err(bound) = bounds(
            &context.scope,
            &context.fingerprints,
            &assembled,
            std::slice::from_ref(&entry),
            &asset_ids,
            created,
        ) {
            refused.set(Some(bound));
            return Err(Failure::Bound);
        }
        let Assembled {
            owner: name,
            operation,
            attempt,
            resources,
            participants,
            recipe,
            ..
        } = assembled;
        let member_list = members.as_array().ok_or(Failure::Integrity)?.clone();
        let index = member_list
            .iter()
            .position(|m| *m == entry)
            .ok_or(Failure::Integrity)?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":name,"operation":operation,
            "created_ms":created,"sequence":request_sequence,"action":"prepare-hosts","members":members,
            "cluster":owner["cluster"],"resources":resources,
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,"step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let generation = previous
            .iter()
            .flat_map(|s| &s.observations)
            .filter(|o| {
                o["event"]["type"] == "reservation"
                    && o["event"]["state"] == "retired"
                    && o["event"]["member"] == entry
            })
            .filter_map(|o| o["event"]["generation"].as_u64())
            .max()
            .unwrap_or(0);
        let mut generations = vec![0; member_list.len()];
        generations[index] = generation;
        let count = admitted.selected.len().checked_add(7).ok_or(Failure::Bound)?;
        let attempt_record = json!({"schema":1,"kind":"attempt","scope":context.scope,"owner":name,"operation":operation,"attempt":attempt,
            "created_ms":created,"request_sha256":hash("broil-infra-request-v1",&request)?,"parent_attempt":null,"original_step":null,
            "approval":null,"steps":(1..=count).collect::<Vec<_>>()});
        let stored = attempt_record.clone();
        let owned = owner.clone();
        local
            .work(move |store| store.create(owned, request, stored))
            .await?;
        let observation = json!({"schema":1,"kind":"observation","scope":context.scope,"owner":name,"operation":operation,
            "sequence":1,"recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
            "attempt":attempt,"step":null,"dispatch":null,"event":{"type":"bootstrap-recipe","recipe":recipe}});
        local.work(move |store| store.append(observation)).await?;
        let sequence = local
            .snapshot()?
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "bootstrap-recipe")
            .and_then(|o| o["sequence"].as_u64())
            .ok_or(Failure::Integrity)?;
        Ok((attempt_record, generations, member_list, resources, index, sequence))
    }
    .await;
    let (attempt, generations, member_list, resources, index, recipe_sequence) = match prepared {
        Ok(value) => value,
        Err(failure) => {
            let mut failed = local.failure(failure, &context.clock).await;
            failed.detail = refused.get();
            return Err(failed);
        }
    };
    let mut session = Session {
        context,
        local,
        attempt,
        members: member_list,
        generations,
        next_step: 1,
        consumer: None,
        existing_resources: false,
        mode: Mode::Acquiring,
        retry_input: None,
        agent_view_wait: false,
        wave_boundary: None,
        wave_operations: Vec::new(),
        wave_gate_needed: false,
    };
    let result =
        Box::pin(session.prepare_hosts(&admitted, resources, vec![index], recipe_sequence)).await;
    session.local.complete(result, &session.context.clock).await
}

impl Session<'_> {
    async fn prepare_hosts(
        &mut self,
        admitted: &Admitted,
        resources: Vec<Value>,
        selected: Vec<usize>,
        recipe: u64,
    ) -> Result<Snapshot> {
        let mut order: Vec<usize> = selected.clone();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_value = self
            .local
            .snapshot()?
            .observations
            .iter()
            .find(|o| o["sequence"] == recipe)
            .map(|o| o["event"]["recipe"].clone())
            .ok_or(Failure::Integrity)?;
        let resource = |index: usize| {
            selected
                .iter()
                .position(|&s| s == index)
                .and_then(|position| resources.get(position))
                .cloned()
                .unwrap_or(Value::Null)
        };
        let payload = |index: usize, asset: Option<&str>| json!({"recipe":recipe_value,"resource":resource(index),"asset":asset});
        for &index in &order {
            self.bootstrap_dispatch(
                index,
                "inspect-host",
                payload(index, None),
                recipe,
                false,
                None,
            )
            .await?;
        }
        let snapshot = self.local.snapshot()?;
        let hosts: Vec<Value> = snapshot
            .observations
            .iter()
            .filter(|o| {
                o["event"]["type"] == "bootstrap-host" && o["attempt"] == self.attempt["attempt"]
            })
            .cloned()
            .collect();
        require(hosts.len() == selected.len(), Failure::Readiness)?;
        if let Some(rejected) = hosts.iter().find(|o| !accepted(&o["event"]["facts"])) {
            let step = snapshot
                .steps
                .iter()
                .find(|s| s["step"] == rejected["step"] && s["dispatch"] == rejected["dispatch"])
                .cloned()
                .ok_or(Failure::Integrity)?;
            self.context.clock.abort();
            let event = json!({"type":"failure","failure":"readiness","outcome":"failed",
                "completion_unknown":false,"cleanup_unknown":false});
            let _ = self.append(&step, event, false, Value::Null).await;
            return Err(Failure::Readiness);
        }
        let cluster = self.local.snapshot()?.request["cluster"].clone();
        for &index in &order {
            let probe_payload = json!({"members":self.members,"excluded":null,"cluster":cluster,"fingerprints":self.context.fingerprints});
            let probe = self.intended(index, "reserve-owner", &probe_payload, Vec::new())?;
            let binding = self.local.snapshot()?.binding(&probe);
            let deadline = tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds);
            let observed = self
                .context
                .invoke(
                    &binding,
                    "inspect",
                    json!({"subject":"owner","dispatch":null,"resource":null}),
                    deadline,
                )
                .await;
            let response = observed
                .response
                .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
            let generation = match response["status"].as_str() {
                Some("absent") => 0,
                Some("ok") => response["data"]["claim"]["generation"]
                    .as_u64()
                    .ok_or(Failure::Integrity)?,
                _ => return Err(Failure::Ownership),
            };
            self.generations[index] = generation;
            self.dispatch(index, "reserve-owner", probe_payload, Vec::new())
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
        self.acquired_of(&order)?;
        self.mode = Mode::Work;
        for &index in &order {
            self.bootstrap_dispatch(
                index,
                "prepare-generation",
                payload(index, None),
                recipe,
                true,
                None,
            )
            .await?;
            for (id, _url) in &admitted.selected {
                let source = match admitted.manifest.mode {
                    manifest::Mode::Online => None,
                    manifest::Mode::Bundle => {
                        let held = admitted
                            .bundle
                            .iter()
                            .find(|(held_id, _)| held_id == id)
                            .map(|(_, held)| held)
                            .ok_or(Failure::Configuration)?;
                        let filename = &admitted
                            .manifest
                            .embedded
                            .index
                            .asset(id)
                            .ok_or(Failure::Integrity)?
                            .filename;
                        let directory = admitted
                            .bundle_directory
                            .as_ref()
                            .ok_or(Failure::Configuration)?;
                        Some((held, directory.join(filename)))
                    }
                };
                let tag = if source.is_some() {
                    "receive-asset"
                } else {
                    "download-asset"
                };
                self.bootstrap_dispatch(index, tag, payload(index, Some(id)), recipe, true, source)
                    .await?;
            }
            self.bootstrap_dispatch(
                index,
                "complete-generation",
                payload(index, None),
                recipe,
                true,
                None,
            )
            .await?;
        }
        self.settle(&order).await
    }
}
