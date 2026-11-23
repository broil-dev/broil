// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::provenance::{
    lifecycle_inspection, recipe_hash, recipe_identity, undispatched_transport,
};
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, bootstrap, canonical, hash, require, rpc, schema};
use crate::k3s::hosts::index;
use crate::k3s::{GUARD, PROFILE, protocol};
use broil_config::LoadedProject;
use broil_core::k3s::{Role, TaintEffect};
use broil_remote::exec::private;
use serde_json::{Value, json};
use std::time::Duration;

const CONTROL_LIMIT: usize = 65_536;
const BINDING_LIMIT: usize = 4096;
const RESOURCE_LIMIT: usize = 512;
pub(super) const RESERVE: usize = 6_249;
const DISABLED: [&str; 5] = [
    "coredns",
    "local-storage",
    "metrics-server",
    "servicelb",
    "traefik",
];
const PROTOCOL: &str = "broil-k3s-lifecycle";

type Attributed<T> = std::result::Result<T, (Failure, Option<&'static str>)>;

fn plain<T>(result: Result<T>) -> Attributed<T> {
    result.map_err(|f| (f, None))
}

pub(super) fn owner_path(owner: &str, name: &str) -> String {
    format!("/var/lib/broil/k3s/owners/{owner}/{name}")
}

pub(super) fn unit_text(owner: &str) -> String {
    let log = owner_path(owner, "service/service.log");
    format!(
        "[Unit]\nDescription=Broil K3s server ({owner})\nAfter=network-online.target\nWants=network-online.target\n\
StartLimitIntervalSec=300s\nStartLimitBurst=5\n\n[Service]\nType=simple\nUMask=0022\n\
ExecStartPre=/usr/bin/python3 {guard}\nExecStart=/usr/local/libexec/broil-k3s server --config /etc/rancher/k3s/config.yaml\n\
StandardOutput=append:{log}\nStandardError=append:{log}\nKillMode=process\nDelegate=yes\nLimitNOFILE=1048576\n\
LimitNPROC=infinity\nLimitCORE=0\nTasksMax=infinity\nTimeoutStartSec=0\nRestart=always\nRestartSec=5s\n\n\
[Install]\nWantedBy=multi-user.target\n",
        guard = owner_path(owner, "service/guard.py"),
    )
}

pub(super) fn rendered_config(
    context: &rpc::Context<'_>,
    owner: &str,
    member: &broil_core::k3s::Member,
) -> Value {
    let t = context.selected.declaration;
    let cidr = |c: broil_core::k3s::Ipv4Cidr| format!("{}/{}", c.network, c.prefix);
    let labels: Vec<String> = member
        .labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let taints: Vec<String> = member
        .taints
        .iter()
        .map(|t| {
            let effect = match t.effect {
                TaintEffect::NoSchedule => "NoSchedule",
                TaintEffect::PreferNoSchedule => "PreferNoSchedule",
                TaintEffect::NoExecute => "NoExecute",
            };
            format!("{}={}:{effect}", t.key, t.value)
        })
        .collect();
    json!({
        "cluster-init": true,
        "token-file": owner_path(owner, "active/server-token"),
        "agent-token-file": owner_path(owner, "active/agent-token"),
        "node-name": member.name,
        "node-ip": member.node_ip.to_string(),
        "advertise-address": member.node_ip.to_string(),
        "tls-san": t.api.tls_sans,
        "cluster-cidr": cidr(t.network.pod_cidr),
        "service-cidr": cidr(t.network.service_cidr),
        "cluster-dns": t.network.cluster_dns.to_string(),
        "cluster-domain": context.selected.cluster_domain,
        "flannel-backend": "vxlan",
        "secrets-encryption": true,
        "write-kubeconfig": owner_path(owner, "admin-raw.yaml"),
        "write-kubeconfig-mode": "0600",
        "disable": DISABLED,
        "disable-default-registry-endpoint": true,
        "etcd-expose-metrics": false,
        "kube-apiserver-arg": ["anonymous-auth=false"],
        "node-label": labels,
        "node-taint": taints,
    })
}

struct Prerequisites {
    generation: String,
    marker_sha256: String,
    input: Value,
}

fn succeeded(scope: &Value, snapshot: &Snapshot) -> bool {
    super::report::report(scope, "show", std::slice::from_ref(snapshot))
        .is_ok_and(|r| r["outcome"] == "succeeded")
}

fn prerequisites(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    members: &Value,
    owner: &str,
) -> Attributed<Prerequisites> {
    let manifest = plain(bootstrap::admit_manifest(context))?;
    let declared = plain(bootstrap::declared(context, members))?;
    let (hosts, network) = declared;
    let first = &members[0];
    let mut candidates: Vec<&Snapshot> = previous
        .iter()
        .filter(|s| s.request["owner"] == owner)
        .filter(|s| succeeded(&context.scope, s))
        .collect();
    candidates.sort_by_key(|s| std::cmp::Reverse(s.request["created_ms"].as_u64()));
    let projection = Value::Array(
        members
            .as_array()
            .map(|ms| {
                ms.iter()
                    .map(|m| {
                        let mut m = m.clone();
                        m["node_uid"] = Value::Null;
                        m
                    })
                    .collect()
            })
            .unwrap_or_default(),
    );
    let prepared = candidates
        .iter()
        .find(|s| bootstrap::repeat_candidate(s, &manifest, &projection, &hosts, &network))
        .ok_or((Failure::Readiness, Some("assets")))?;
    let generation = prepared
        .observations
        .iter()
        .filter(|o| {
            o["event"]["type"] == "bootstrap-generation"
                && !o["event"]["marker"].is_null()
                && o["source"]["machine"] == first["machine"]
        })
        .max_by_key(|o| o["sequence"].as_u64())
        .ok_or((Failure::Readiness, Some("assets")))?;
    let marker = &generation["event"]["marker"];
    let pinned = |id: &str| manifest.embedded.index.asset(id);
    let entry = |id: &str| {
        marker["assets"]
            .as_array()
            .and_then(|a| a.iter().find(|e| e["id"] == id))
    };
    for id in ["k3s", "k3s-airgap"] {
        let (asset, recorded) = (pinned(id), entry(id));
        let agrees = match (asset, recorded) {
            (Some(asset), Some(recorded)) => {
                recorded["size"] == asset.size && recorded["sha256"] == asset.sha256
            }
            _ => false,
        };
        if !agrees {
            return Err((Failure::Readiness, Some("assets")));
        }
    }
    let generation_id = generation["event"]["resource"]["generation"]
        .as_str()
        .ok_or((Failure::Integrity, None))?
        .to_owned();
    let marker_sha256 = protocol::digest(&plain(canonical(marker))?);
    let input = candidates
        .iter()
        .filter(|s| {
            s.request["action"] == "prepare-state"
                && s.request["consumer"]["action"] == "supply-initial-server"
        })
        .find_map(|s| {
            s.request["resources"]
                .as_array()
                .and_then(|r| r.first())
                .filter(|r| r["kind"] == "server-input" && r["machine"] == first["machine"])
                .cloned()
        })
        .ok_or((Failure::Readiness, Some("input")))?;
    if previous.iter().any(|s| s.request["owner"] != owner) {
        return Err((Failure::Ownership, None));
    }
    Ok(Prerequisites {
        generation: generation_id,
        marker_sha256,
        input,
    })
}

pub(super) struct Assembled {
    pub(super) owner: String,
    pub(super) operation: String,
    pub(super) attempt: String,
    pub(super) participants: String,
    pub(super) recipe: Value,
    pub(super) identity: String,
    pub(super) resource: Value,
}

pub(super) fn assemble(
    context: &rpc::Context<'_>,
    members: &Value,
    owner: String,
    generation: &str,
    marker_sha256: &str,
    input: Value,
) -> Result<Assembled> {
    let operation = format!("infra-operation-{}", fresh()?);
    let attempt = fresh()?;
    let participants = super::participants(members)?;
    let list = members.as_array().ok_or(Failure::Integrity)?;
    let first = list.first().ok_or(Failure::Configuration)?;
    let machine = first["machine"].as_str().ok_or(Failure::Integrity)?;
    let declared = context
        .selected
        .declaration
        .members
        .iter()
        .find(|m| m.machine == machine)
        .ok_or(Failure::Configuration)?;
    require(declared.role == Role::Server, Failure::Configuration)?;
    let embedded = index::embedded()?;
    let entry = |id: &str| -> Result<Value> {
        let asset = embedded.index.asset(id).ok_or(Failure::Integrity)?;
        Ok(json!({"id":asset.id,"filename":asset.filename,"size":asset.size,"sha256":asset.sha256}))
    };
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    require(
        profile["k3s_version"] == embedded.index.version
            && entry("k3s")?["sha256"] == profile["k3s_sha256"],
        Failure::Configuration,
    )?;
    let unit = unit_text(&owner);
    let recipe = json!({"schema":2,"scope":context.scope,"owner":owner,"operation":operation,"attempt":attempt,
        "member":first,"members":members,"assets":{"generation":generation,"marker_sha256":marker_sha256},
        "input":{"generation":input["generation"]},"version":embedded.index.version,
        "api_endpoint":crate::k3s::origin(&context.selected.declaration.api.endpoint),
        "executable":entry("k3s")?,"archive":entry("k3s-airgap")?,
        "guard_sha256":protocol::digest(GUARD),"unit_sha256":protocol::digest(unit.as_bytes()),
        "config":rendered_config(context, &owner, declared)});
    schema::validate(&canonical(&recipe)?, "ServerRecipe", CONTROL_LIMIT)?;
    require(
        input["generation"] == recipe["input"]["generation"]
            && input["kind"] == "server-input"
            && input["owner"] == owner
            && input["machine"] == machine,
        Failure::Integrity,
    )?;
    recipe_hash(&recipe)?;
    Ok(Assembled {
        identity: recipe_identity(&recipe)?,
        owner,
        operation,
        attempt,
        participants,
        recipe,
        resource: input,
    })
}

fn recipe_observation(scope: &Value, assembled: &Assembled, recorded_ms: u64) -> Value {
    json!({"schema":1,"kind":"observation","scope":scope,"owner":assembled.owner,"operation":assembled.operation,
        "sequence":1,"recorded_ms":recorded_ms,"producer_ms":null,"source":{"kind":"controller","machine":null},
        "attempt":assembled.attempt,"step":null,"dispatch":null,"event":{"type":"lifecycle-recipe","recipe":assembled.recipe}})
}

pub(super) fn widest_identity() -> Value {
    json!({"cluster":{"uid":"x".repeat(128),"ca_sha256":"0".repeat(64)},"node_uid":"x".repeat(128),
        "data":[u64::MAX,u64::MAX]})
}

pub(super) fn bounds(
    scope: &Value,
    fingerprints: &Value,
    assembled: &Assembled,
    members: &[Value],
    recorded_ms: u64,
) -> std::result::Result<(), &'static str> {
    let length = |value: &Value| canonical(value).map_or(usize::MAX, |bytes| bytes.len());
    let observation = recipe_observation(scope, assembled, recorded_ms);
    if length(&observation).saturating_add(1) > CONTROL_LIMIT {
        return Err("record");
    }
    let (mut header, mut binding) = (0usize, 0usize);
    let resource = length(&assembled.resource);
    for member in members {
        let candidate = json!({"scope":scope,"owner":assembled.owner,"operation":assembled.operation,
            "attempt":assembled.attempt,"step":u32::MAX,"dispatch":"0".repeat(32),"recipient":member,
            "receiver_generation":u64::MAX,"request_sha256":"0".repeat(64),
            "participants_sha256":assembled.participants,"fingerprints":fingerprints});
        binding = binding.max(length(&candidate));
        for (action, identity) in [
            ("inspect-installation", Value::Null),
            ("activate-server", Value::Null),
            ("start-server", Value::Null),
            ("observe-server", Value::Null),
            ("publish-identity", widest_identity()),
            ("publish-cluster", widest_identity()),
        ] {
            let value = json!({"protocol":PROTOCOL,"version":1,"action":action,
                "request_id":"0".repeat(32),"binding":candidate,"remaining_ms":7_200_000,
                "payload":{"recipe":assembled.recipe,"identity":identity}});
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

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Layout {
    pub(super) inspect: Vec<(usize, u64)>,
    pub(super) reserve: Vec<(usize, u64)>,
    pub(super) acquire: Vec<(usize, u64)>,
    pub(super) first: [u64; 4],
    pub(super) propagate: Vec<(usize, u64)>,
    pub(super) seal: Vec<(usize, u64)>,
    pub(super) retire: Vec<(usize, u64)>,
    pub(super) count: u64,
}

pub(super) fn layout(members: &[Value], order: &[usize]) -> Result<Layout> {
    require(
        !members.is_empty() && order.len() == members.len(),
        Failure::Integrity,
    )?;
    let servers: Vec<usize> = order
        .iter()
        .copied()
        .filter(|&i| members[i]["role"] == "server")
        .collect();
    let mut next = 0u64;
    let mut allocate = |indices: &[usize]| -> Vec<(usize, u64)> {
        indices
            .iter()
            .map(|&i| {
                next += 1;
                (i, next)
            })
            .collect()
    };
    let inspect = allocate(&servers);
    let reserve = allocate(order);
    let acquire = allocate(order);
    let first: Vec<(usize, u64)> = allocate(&[0, 0, 0, 0]);
    let others: Vec<usize> = order.iter().copied().filter(|&i| i != 0).collect();
    let propagate = allocate(&others);
    let seal = allocate(order);
    let retire = allocate(order);
    require(next <= 1024, Failure::Bound)?;
    Ok(Layout {
        inspect,
        reserve,
        acquire,
        first: [first[0].1, first[1].1, first[2].1, first[3].1],
        propagate,
        seal,
        retire,
        count: next,
    })
}

pub(super) fn reply(bytes: &[u8], header: &[u8]) -> Result<Value> {
    require(
        bytes.len() <= CONTROL_LIMIT && bytes.starts_with(b"BK3SLIFE1\n"),
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
    let result = field(&mut input)?;
    require(input.is_empty(), Failure::Integrity)?;
    let request = schema::decode(header, "Public", CONTROL_LIMIT)?;
    let joined = matches!(
        request["action"].as_str(),
        Some(
            "inspect-owned-server"
                | "inspect-join"
                | "observe-membership"
                | "activate-join"
                | "start-join"
                | "observe-join"
                | "publish-member"
        )
    );
    let agent = matches!(
        request["action"].as_str(),
        Some(
            "inspect-agent"
                | "observe-agent-membership"
                | "activate-agent"
                | "start-agent"
                | "observe-agent"
                | "publish-agent"
        )
    );
    let result = schema::decode(
        result,
        if agent {
            "AgentLifecycleResult"
        } else if joined {
            "JoinLifecycleResult"
        } else {
            "LifecycleResult"
        },
        CONTROL_LIMIT,
    )?;
    if joined || agent {
        require(canonical(&result)?.len() <= 16_384, Failure::Bound)?;
    }
    if agent {
        let view_action = matches!(
            request["action"].as_str(),
            Some("observe-agent-membership" | "publish-agent")
        );
        require(
            (result["status"] == "ok" && view_action) != result["agent_view"].is_null(),
            Failure::Integrity,
        )?;
        if request["action"] == "observe-agent-membership" {
            require(
                result["installation"].is_null() && result["identity"].is_null(),
                Failure::Integrity,
            )?;
        }
    }
    if !result["detail"].is_null() {
        require(
            matches!(
                request["action"].as_str(),
                Some("inspect-installation" | "activate-server" | "inspect-join" | "activate-join")
            ) && result["status"] == "refused"
                && result["failure"] == "readiness"
                && [
                    "terminal",
                    "installation",
                    "readiness",
                    "identity",
                    "membership",
                ]
                .iter()
                .all(|field| result[*field].is_null()),
            Failure::Integrity,
        )?;
    }
    Ok(result)
}

pub(super) struct Observed {
    pub(super) transport: Value,
    pub(super) result: Option<Value>,
    pub(super) failure: Option<Failure>,
}

pub(super) async fn invoke(
    context: &rpc::Context<'_>,
    binding: &Value,
    action: &str,
    payload: &Value,
    deadline: tokio::time::Instant,
    child: Option<&private::CredentialClock>,
) -> Observed {
    let mut observed = Observed {
        transport: undispatched_transport(),
        result: None,
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

        let connection = match Box::pin(context.connect_lifecycle(machine, deadline, child)).await {
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
            let header = json!({"protocol":PROTOCOL,"version":1,"action":action,
                "request_id":request_id,"binding":binding,"remaining_ms":remaining,"payload":payload});
            let bytes = canonical(&header)?;
            schema::validate(&bytes, "LifecycleHeader", CONTROL_LIMIT)?;
            let reserve = if action == "prepare-join-source" { 8_196 } else if matches!(action, "inspect-owned-server" | "inspect-join" | "observe-membership" | "activate-join" | "start-join" | "observe-join" | "publish-member" | "inspect-agent" | "observe-agent-membership" | "activate-agent" | "start-agent" | "observe-agent" | "publish-agent") {16_388} else { RESERVE };
            require(
                14usize.saturating_add(bytes.len()).saturating_add(reserve) <= CONTROL_LIMIT,
                Failure::Bound,
            )?;
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
        let output = connection
            .run_lifecycle(bytes.clone(), false)
            .await
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
        observed.result = Some(reply(output.stdout.bytes(), &bytes)?);
        Ok(())
    }
    .await;
    observed.failure = result.err();
    observed
}

pub(super) fn refused(result: &Value) -> Failure {
    match result["failure"].as_str() {
        Some("ownership") => Failure::Ownership,
        Some("busy") => Failure::Busy,
        Some("bound") => Failure::Bound,
        Some("configuration") => Failure::Configuration,
        Some("capability") => Failure::Capability,
        Some("credential") => Failure::Credential,
        Some("authentication") => Failure::Authentication,
        Some("trust") => Failure::Trust,
        Some("integrity") => Failure::Integrity,
        Some("storage") => Failure::Storage,
        Some("transport") => Failure::Transport,
        Some("unsupported-version") => Failure::UnsupportedVersion,
        Some("timeout") => Failure::Timeout,
        Some("cancelled") => Failure::Cancelled,
        Some("readiness") => Failure::Readiness,
        _ => Failure::Integrity,
    }
}

fn ready(readiness: &Value) -> bool {
    ["api", "quorum", "nodes"]
        .iter()
        .all(|k| readiness[*k] == "ready")
}

fn installation_event(member: &Value, result: &Value, fallback: (&str, &str), tag: &str) -> Value {
    let installation = &result["installation"];
    let (class, publication) = if installation.is_null() {
        (json!(fallback.0), json!(fallback.1))
    } else {
        (
            installation["class"].clone(),
            installation["publication_state"].clone(),
        )
    };
    let activation = if installation["operation"].is_null() {
        Value::Null
    } else {
        installation.clone()
    };
    let readiness = if result["readiness"].is_null() {
        super::report::readiness()
    } else {
        result["readiness"].clone()
    };
    let identity = if tag != "observe-server" && result["identity"].is_null() {
        installation["identity"].clone()
    } else {
        result["identity"].clone()
    };
    json!({"type":"lifecycle-installation","member":member,"class":class,"publication_state":publication,
        "activation":activation,"readiness":readiness,"identity":identity})
}

pub(super) fn settlement(snapshot: &Snapshot, step: &Value, result: &Value) -> Result<()> {
    let action = step["action"].as_str().ok_or(Failure::Integrity)?;
    let installation = &result["installation"];
    if lifecycle_inspection(action) {
        require(result["terminal"].is_null(), Failure::Integrity)?;
        if matches!(
            action,
            "lifecycle:inspect-installation"
                | "lifecycle:inspect-owned-server"
                | "lifecycle:inspect-join"
                | "lifecycle:inspect-agent"
        ) {
            require(!installation.is_null(), Failure::Integrity)?;
        } else if matches!(
            action,
            "lifecycle:observe-membership" | "lifecycle:observe-agent-membership"
        ) {
            require(installation.is_null(), Failure::Integrity)?;
        } else {
            require(!result["readiness"].is_null(), Failure::Integrity)?;
        }
        return Ok(());
    }
    let receipt = &result["terminal"];
    require(
        receipt["binding"] == snapshot.binding(step)
            && receipt["action"] == step["action"]
            && receipt["payload_sha256"] == step["payload_sha256"]
            && receipt["writer_ended"] == true,
        Failure::Ownership,
    )?;
    if result["status"] != "ok" {
        return Ok(());
    }
    require(
        receipt["outcome"] == "succeeded" && receipt["effect"] == "complete",
        Failure::Readiness,
    )?;
    if action == "lifecycle:prepare-join-source" {
        require(
            installation.is_null()
                && result["readiness"].is_null()
                && result["identity"].is_null()
                && result["detail"].is_null()
                && receipt["resource"] == step["resource"]
                && receipt["resource_identity"].is_array(),
            Failure::Ownership,
        )?;
        return Ok(());
    }
    let expected = match action {
        "lifecycle:activate-server" => ("activated", None),
        "lifecycle:start-server" => ("started", None),
        "lifecycle:publish-identity" => ("owned", Some("published")),
        "lifecycle:publish-cluster" => ("absent", Some("published")),
        "lifecycle:activate-join" => ("activated", None),
        "lifecycle:start-join" => ("started", None),
        "lifecycle:publish-member" => ("owned", Some("published")),
        "lifecycle:activate-agent" => ("activated", None),
        "lifecycle:start-agent" => ("started", None),
        "lifecycle:publish-agent" => ("owned", Some("published")),
        _ => return Err(Failure::Capability),
    };
    require(
        installation["class"] == expected.0
            && expected
                .1
                .is_none_or(|state| installation["publication_state"] == state),
        Failure::Ownership,
    )?;
    if matches!(
        action,
        "lifecycle:publish-identity" | "lifecycle:publish-member" | "lifecycle:publish-agent"
    ) {
        require(!installation["identity"].is_null(), Failure::Ownership)?;
    }
    Ok(())
}

fn observed_class(snapshot: &Snapshot, attempt: &Value, member: &Value) -> (String, String) {
    snapshot
        .observations
        .iter()
        .rev()
        .find(|o| {
            o["attempt"] == *attempt
                && o["event"]["type"] == "lifecycle-installation"
                && o["event"]["member"] == *member
        })
        .map(|o| {
            (
                o["event"]["class"].as_str().unwrap_or("foreign").to_owned(),
                o["event"]["publication_state"]
                    .as_str()
                    .unwrap_or("unpublished")
                    .to_owned(),
            )
        })
        .unwrap_or_else(|| ("foreign".to_owned(), "unpublished".to_owned()))
}

fn installation_sequence(snapshot: &Snapshot, step: &Value) -> Result<u64> {
    snapshot
        .observations
        .iter()
        .rev()
        .find(|o| {
            o["attempt"] == step["attempt"]
                && o["step"] == step["step"]
                && o["dispatch"] == step["dispatch"]
                && o["event"]["type"] == "lifecycle-installation"
        })
        .and_then(|o| o["sequence"].as_u64())
        .ok_or(Failure::Integrity)
}

pub(super) struct Dispatched {
    pub(super) result: Value,
    pub(super) observation: Option<u64>,
}

fn agent_ready(view: &Value, selected: &Value) -> bool {
    view["members"].as_array().is_some_and(|members| {
        members.iter().any(|member| {
            &member["member"]["machine"] == selected
                && member["present"] == true
                && member["ready"] == true
                && member["taints"].as_array().is_some_and(|taints| {
                    !taints.iter().any(|taint| {
                        taint == "node.kubernetes.io/not-ready=:NoExecute"
                            || taint == "node.kubernetes.io/not-ready=:NoSchedule"
                    })
                })
        })
    })
}

impl Session<'_> {
    pub(super) fn confirmed_transport(&self) -> Value {
        json!({"dispatch":"confirmed","exit":0,"signal":null,"input_released":true,"staging_cleanup":"clean"})
    }

    pub(super) async fn lifecycle_dispatch(
        &mut self,
        id: u64,
        index: usize,
        tag: &str,
        payload: Value,
        references: Vec<Value>,
        mutation: bool,
    ) -> Result<Dispatched> {
        self.context.check()?;
        require(
            self.mode != Mode::SettlementOnly && (!mutation || self.mode == Mode::Work),
            Failure::Capability,
        )?;
        let previous_deadline = self.local.step_deadline;
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        self.local.step_deadline = Some(deadline);
        self.next_step = id;
        let action = format!("lifecycle:{tag}");
        let step = self.intended(index, &action, &payload, references)?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let child = mutation.then(|| self.context.clock.for_credential_action(deadline));
        let member = self.members[index].clone();
        let fallback = observed_class(self.local.snapshot()?, &self.attempt["attempt"], &member);
        let mut observed;
        loop {
            observed = invoke(
                &self.context,
                &binding,
                tag,
                &payload,
                deadline,
                child.as_ref(),
            )
            .await;
            self.local.step_deadline = previous_deadline;
            if observed.failure.is_some() {
                self.local
                    .limit_observation(self.context.clock.terminal_deadline());
            }
            self.local.completion_unknown |=
                mutation && observed.failure.is_some() && observed.transport["dispatch"] != "none";
            self.append(
                &step,
                json!({"type":"dispatch","transport":observed.transport,
                    "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                    "failure":observed.failure.map(Failure::name)}),
                false,
                Value::Null,
            )
            .await?;
            let settled = match &observed.result {
                None => true,
                Some(result) => {
                    let waiting_agent = tag == "observe-agent-membership" && self.agent_view_wait;
                    let observed_ready = if waiting_agent {
                        let selected = &self.local.snapshot()?.request["resources"][1]["machine"];
                        agent_ready(&result["agent_view"], selected)
                    } else {
                        ready(&result["readiness"])
                    };
                    !(matches!(tag, "observe-server" | "observe-join") || waiting_agent)
                        || result["status"] != "ok"
                        || observed_ready
                        || tokio::time::Instant::now() + Duration::from_secs(3) >= deadline
                }
            };
            if settled {
                break;
            }
            self.context.check()?;
            self.local.step_deadline = Some(deadline);
        }
        let result = observed
            .result
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
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
                json!({"type":"receiver","receipt":receipt,"transport":self.confirmed_transport()}),
                true,
                receipt["completed_ms"].clone(),
            )
            .await?;
        }
        let ok = result["status"] == "ok";
        let mut observation = None;
        if !result["installation"].is_null()
            || (ok && matches!(tag, "observe-server" | "observe-join" | "observe-agent"))
        {
            let event = installation_event(
                &member,
                &result,
                (fallback.0.as_str(), fallback.1.as_str()),
                tag,
            );
            self.append(&step, event, true, Value::Null).await?;
            observation = Some(installation_sequence(self.local.snapshot()?, &step)?);
        }
        if ok
            && matches!(
                tag,
                "observe-membership" | "observe-join" | "publish-member"
            )
        {
            self.append(
                &step,
                json!({"type":"server-membership","member":member,
                "membership":result["membership"]}),
                true,
                Value::Null,
            )
            .await?;
        }
        if ok && matches!(tag, "observe-agent-membership" | "publish-agent") {
            self.append(
                &step,
                json!({"type":"agent-membership","view":result["agent_view"]}),
                true,
                Value::Null,
            )
            .await?;
        }
        if ok {
            self.settlement(&step, &result, &payload)?;
        }
        if !ok {
            self.local.failure_detail = match result["detail"].as_str() {
                Some("assets") => Some("assets"),
                Some("input") => Some("input"),
                _ => None,
            };
            return Err(refused(&result));
        }
        if mutation {
            if let Some(mut child) = child {
                child.complete().map_err(|_| Failure::Timeout)?;
            }
        }
        Ok(Dispatched {
            result,
            observation,
        })
    }

    pub(super) async fn deselect(
        &mut self,
        id: u64,
        index: usize,
        tag: &str,
        recipe: u64,
    ) -> Result<()> {
        self.context.check()?;
        self.next_step = id;
        let payload = json!({"recipe":self.recipe_value()?,"identity":null});
        let step = self.intended(
            index,
            &format!("lifecycle:{tag}"),
            &payload,
            vec![json!(recipe)],
        )?;
        let intent = step.clone();
        self.local.work(move |store| store.step(intent)).await?;
        self.append(
            &step,
            json!({"type":"dispatch","transport":undispatched_transport(),"outcome":"succeeded","failure":null}),
            false,
            Value::Null,
        )
        .await
    }

    fn recipe_value(&self) -> Result<Value> {
        Ok(self.local.snapshot()?.lifecycle_recipe()?["event"]["recipe"].clone())
    }

    async fn publish_locally(
        &mut self,
        step: &Value,
        index: usize,
        identity: &Value,
        readiness: &Value,
    ) -> Result<()> {
        let member = self.members[index].clone();
        let readiness = if readiness.is_null() {
            super::report::readiness()
        } else {
            readiness.clone()
        };
        self.append(
            step,
            json!({"type":"identity","member":member,"cluster":identity["cluster"],"resources":[],"readiness":readiness}),
            true,
            Value::Null,
        )
        .await?;
        let snapshot = self.local.snapshot()?;
        let owner = published_owner(&snapshot.owner, index, identity)?;
        let operation = snapshot.request["operation"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        self.local
            .work(move |store| store.replace_owner(owner, &operation))
            .await
    }

    async fn create_server(&mut self, layout: &Layout, recipe: u64) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_value = self.recipe_value()?;
        let payload = |identity: Value| json!({"recipe":recipe_value,"identity":identity});
        let references = vec![json!(recipe)];
        let mut first_class = (String::new(), String::new());
        let mut first_inspection = None;
        for &(index, id) in &layout.inspect {
            let joined = index != 0 && !self.members[index]["node_uid"].is_null();
            let (tag, inspection_payload, refs) = if joined {
                let event = self
                    .local
                    .snapshot()?
                    .observations
                    .iter()
                    .find(|o| {
                        o["event"]["type"] == "server-recipe"
                            && o["event"]["recipe_kind"] == "join"
                            && o["event"]["recipe"]["member"] == self.members[index]
                    })
                    .ok_or(Failure::Integrity)?;
                (
                    "inspect-owned-server",
                    json!({"recipe_kind":"join","recipe":event["event"]["recipe"],
                    "identity":null,"membership":null,"removed":null}),
                    vec![event["sequence"].clone()],
                )
            } else {
                (
                    "inspect-installation",
                    payload(Value::Null),
                    references.clone(),
                )
            };
            let dispatched = self
                .lifecycle_dispatch(id, index, tag, inspection_payload, refs, false)
                .await?;
            let facts = &dispatched.result["installation"];
            let class = facts["class"].as_str().unwrap_or("foreign");
            if index == 0 {
                if class == "foreign" {
                    let step = self
                        .local
                        .snapshot()?
                        .steps
                        .last()
                        .ok_or(Failure::Integrity)?
                        .clone();
                    self.append(
                        &step,
                        json!({"type":"failure","failure":"ownership",
                        "outcome":"failed","completion_unknown":false,"cleanup_unknown":false}),
                        false,
                        Value::Null,
                    )
                    .await?;
                }
                require(
                    matches!(class, "absent" | "activated" | "started" | "owned"),
                    Failure::Ownership,
                )?;
                first_class = (
                    class.to_owned(),
                    facts["publication_state"]
                        .as_str()
                        .unwrap_or("unpublished")
                        .to_owned(),
                );
                first_inspection = dispatched.observation;
            } else {
                require(
                    class == if joined { "owned" } else { "absent" },
                    Failure::Ownership,
                )?;
            }
        }
        require(!first_class.0.is_empty(), Failure::Integrity)?;
        let request_cluster = self.local.snapshot()?.request["cluster"].clone();
        let mut unpropagated = vec![false; self.members.len()];
        for &(index, id) in &layout.reserve {
            let probe_payload = json!({"members":self.members,"excluded":null,"cluster":request_cluster,"fingerprints":self.context.fingerprints});
            self.next_step = id;
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
            self.next_step = id;
            let response = self
                .dispatch(index, "reserve-owner", probe_payload, Vec::new())
                .await?;
            unpropagated[index] = response["data"]["ownership"]["cluster"].is_null();
        }
        for &(index, id) in &layout.acquire {
            self.next_step = id;
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
        let [activate, start, observe, publish] = layout.first;
        let mut class = first_class.0.as_str();
        if matches!(class, "absent" | "activated") {
            self.lifecycle_dispatch(
                activate,
                0,
                "activate-server",
                payload(Value::Null),
                references.clone(),
                true,
            )
            .await?;
            class = "activated";
        } else {
            self.deselect(activate, 0, "activate-server", recipe)
                .await?;
        }
        if class == "activated" {
            self.lifecycle_dispatch(
                start,
                0,
                "start-server",
                payload(Value::Null),
                references.clone(),
                true,
            )
            .await?;
            class = "started";
        } else {
            self.deselect(start, 0, "start-server", recipe).await?;
        }
        let observed = self
            .lifecycle_dispatch(
                observe,
                0,
                "observe-server",
                payload(Value::Null),
                references.clone(),
                false,
            )
            .await?;
        let observation = observed.observation.ok_or(Failure::Integrity)?;
        let readiness = observed.result["readiness"].clone();
        let propagated: (u64, Value);
        if class == "started" {
            if ready(&readiness) && !observed.result["identity"].is_null() {
                let identity = observed.result["identity"].clone();
                self.lifecycle_dispatch(
                    publish,
                    0,
                    "publish-identity",
                    payload(identity.clone()),
                    vec![json!(recipe), json!(observation)],
                    true,
                )
                .await?;
                let step = self
                    .local
                    .snapshot()?
                    .steps
                    .iter()
                    .find(|s| s["step"] == publish && s["attempt"] == self.attempt["attempt"])
                    .cloned()
                    .ok_or(Failure::Integrity)?;
                self.publish_locally(&step, 0, &identity, &readiness)
                    .await?;
                propagated = (observation, identity);
            } else {
                let step = self
                    .local
                    .snapshot()?
                    .steps
                    .iter()
                    .find(|s| s["step"] == observe && s["attempt"] == self.attempt["attempt"])
                    .cloned()
                    .ok_or(Failure::Integrity)?;
                self.append(
                    &step,
                    json!({"type":"failure","failure":"readiness","outcome":"failed",
                    "completion_unknown":false,"cleanup_unknown":false}),
                    false,
                    Value::Null,
                )
                .await?;
                self.local.work(|store| store.verify()).await?;
                self.context.check()?;
                self.mode = Mode::SettlementOnly;
                self.deselect(publish, 0, "publish-identity", recipe)
                    .await?;
                for &(index, id) in &layout.propagate {
                    self.deselect(id, index, "publish-cluster", recipe).await?;
                }
                self.next_step = layout.seal[0].1;
                return self.settle(&order).await;
            }
        } else {
            self.deselect(publish, 0, "publish-identity", recipe)
                .await?;
            let sequence = first_inspection.ok_or(Failure::Integrity)?;
            let identity = self
                .local
                .snapshot()?
                .observations
                .iter()
                .find(|o| o["sequence"] == sequence)
                .map(|o| o["event"]["identity"].clone())
                .ok_or(Failure::Integrity)?;
            require(!identity.is_null(), Failure::Ownership)?;
            if self.local.snapshot()?.owner["cluster"].is_null() {
                let step = self
                    .local
                    .snapshot()?
                    .steps
                    .iter()
                    .find(|s| s["step"] == observe && s["attempt"] == self.attempt["attempt"])
                    .cloned()
                    .ok_or(Failure::Integrity)?;
                self.publish_locally(&step, 0, &identity, &readiness)
                    .await?;
            }
            propagated = (sequence, identity);
        }
        let (sequence, identity) = propagated;
        for &(index, id) in &layout.propagate {
            if unpropagated[index] {
                self.lifecycle_dispatch(
                    id,
                    index,
                    "publish-cluster",
                    payload(identity.clone()),
                    vec![json!(recipe), json!(sequence)],
                    true,
                )
                .await?;
            } else {
                self.deselect(id, index, "publish-cluster", recipe).await?;
            }
        }
        self.next_step = layout.seal[0].1;
        self.settle(&order).await
    }
}

pub(super) fn published_owner(owner: &Value, index: usize, identity: &Value) -> Result<Value> {
    let mut next = owner.clone();
    next["previous_generation"] = owner["generation"].clone();
    next["generation"] = json!(fresh()?);
    next["created_ms"] = json!(now()?);
    next["cluster"] = identity["cluster"].clone();
    let members = next["members"].as_array_mut().ok_or(Failure::Integrity)?;
    let member = members.get_mut(index).ok_or(Failure::Integrity)?;
    member["node_uid"] = identity["node_uid"].clone();
    require(
        next["participants_sha256"] == super::participants(&next["members"])?,
        Failure::Integrity,
    )?;
    rebind_restored(owner, &mut next, index)?;
    Ok(next)
}

pub(super) fn rebind_restored(prior: &Value, next: &mut Value, index: usize) -> Result<()> {
    let before = super::acting_server(prior)
        .map(|m| m["machine"].clone())
        .ok();
    let after = super::acting_server(next)?;
    if before.as_ref() == Some(&after["machine"])
        || after["member"] != next["members"][index]["member"]
    {
        return Ok(());
    }
    for resource in next["resources"]
        .as_array_mut()
        .ok_or(Failure::Integrity)?
        .iter_mut()
        .filter(|r| matches!(r["kind"].as_str(), Some("issuer" | "registry-auth")))
    {
        resource["machine"] = after["machine"].clone();
    }
    Ok(())
}

fn restore_recorded_uids(declared: &Value, recorded: &Value, published: bool) -> Result<Value> {
    let mut expected = declared.clone();
    let current = recorded.as_array().ok_or(Failure::Integrity)?;
    let selected = expected.as_array_mut().ok_or(Failure::Integrity)?;
    require(current.len() == selected.len(), Failure::Ownership)?;
    for (member, saved) in selected.iter_mut().zip(current) {
        let mut without_uid = saved.clone();
        without_uid["node_uid"] = Value::Null;
        require(*member == without_uid, Failure::Ownership)?;
        if published {
            member["node_uid"] = saved["node_uid"].clone();
        }
    }
    Ok(expected)
}

pub async fn create_first_server(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let context = rpc::Context::new(project, policy, target)?;
    let declaration = context.selected.declaration;
    let servers = declaration
        .members
        .iter()
        .filter(|m| m.role == Role::Server)
        .count();
    require(
        matches!(servers, 1 | 3)
            && declaration
                .members
                .first()
                .is_some_and(|m| m.role == Role::Server),
        Failure::Configuration,
    )?;
    let members = context.authenticate().await?;
    let mut local = Local::new(&context)?;
    let previous = match local
        .work(|store| store.read_operations(None).map_err(|e| e.failure))
        .await
    {
        Ok(previous) => previous,
        Err(failure) => return Err(local.failure(failure, &context.clock).await),
    };
    let refused: std::cell::Cell<Option<&'static str>> = std::cell::Cell::new(None);
    let prepared: Result<_> = async {
        for snapshot in &previous {
            let report =
                super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))?;
            super::session::settled(&report)?;
        }
        let first = previous.first().ok_or(Failure::Readiness)?;
        let owner = first.owner["owner"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        let owned = &first.owner;
        let participants = super::participants(&members)?;
        let published = !owned["cluster"].is_null();
        let expected = restore_recorded_uids(&members, &owned["members"], published)?;
        if published {
            require(!expected[0]["node_uid"].is_null(), Failure::Ownership)?;
        }
        let mut identity_pins = owned["fingerprints"].clone();
        identity_pins["config_sha256"] = context.owner_fingerprints["config_sha256"].clone();
        require(
            owned["members"] == expected
                && identity_pins == context.owner_fingerprints
                && owned["participants_sha256"] == participants,
            Failure::Ownership,
        )?;
        require(owned["fingerprints"]["config_sha256"] == context.owner_fingerprints["config_sha256"],
            Failure::Configuration)?;
        let members = owned["members"].clone();
        let prerequisites = match prerequisites(&context, &previous, &members, &owner) {
            Ok(prerequisites) => prerequisites,
            Err((failure, detail)) => {
                refused.set(detail);
                return Err(failure);
            }
        };
        let assembled = assemble(
            &context,
            &members,
            owner,
            &prerequisites.generation,
            &prerequisites.marker_sha256,
            prerequisites.input,
        )?;
        for snapshot in previous
            .iter()
            .filter(|s| s.request["action"] == "create-server" && !super::report::clean_refused(s))
        {
            let recorded = &snapshot.lifecycle_recipe()?["event"]["recipe"];
            require(
                recipe_identity(recorded)? == assembled.identity,
                Failure::Configuration,
            )?;
        }
        let created = now()?;
        let member_list = members.as_array().ok_or(Failure::Integrity)?.clone();
        if let Err(bound) = bounds(
            &context.scope,
            &context.fingerprints,
            &assembled,
            &member_list,
            created,
        ) {
            refused.set(Some(bound));
            return Err(Failure::Bound);
        }
        let mut order: Vec<usize> = (0..member_list.len()).collect();
        order.sort_by(|a, b| {
            member_list[*a]["machine"]
                .as_str()
                .cmp(&member_list[*b]["machine"].as_str())
        });
        let layout = layout(&member_list, &order)?;
        let Assembled {
            owner,
            operation,
            attempt,
            participants,
            recipe,
            resource,
            ..
        } = assembled;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":owner,"operation":operation,
            "created_ms":created,"sequence":request_sequence,"action":"create-server","members":members,"cluster":owned["cluster"],"resources":[resource],
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,"step_timeout_ms":context.selected.step_timeout.seconds*1000});
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
        let attempt_record = json!({"schema":1,"kind":"attempt","scope":context.scope,"owner":owner,"operation":operation,"attempt":attempt,
            "created_ms":created,"request_sha256":hash("broil-infra-request-v1",&request)?,"parent_attempt":null,"original_step":null,
            "approval":null,"steps":(1..=layout.count).collect::<Vec<_>>()});
        let joined_events = super::join::owned_events_for_create(&context, &previous, &members,
            &operation, &attempt, &recipe)?;
        let stored = attempt_record.clone();
        let owned = owned.clone();
        local
            .work(move |store| store.create(owned, request, stored))
            .await?;
        let observation = json!({"schema":1,"kind":"observation","scope":context.scope,"owner":owner,"operation":operation,
            "sequence":1,"recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
            "attempt":attempt,"step":null,"dispatch":null,"event":{"type":"lifecycle-recipe","recipe":recipe}});
        local.work(move |store| store.append(observation)).await?;
        for event in joined_events {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,"owner":owner,"operation":operation,
                "sequence":1,"recorded_ms":now()?,"producer_ms":null,"source":{"kind":"controller","machine":null},
                "attempt":attempt,"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        let sequence = local
            .snapshot()?
            .lifecycle_recipe()?["sequence"]
            .as_u64()
            .ok_or(Failure::Integrity)?;
        Ok((attempt_record, generations, member_list, layout, sequence))
    }
    .await;
    let (attempt, generations, member_list, layout, recipe) = match prepared {
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
    let result = Box::pin(session.create_server(&layout, recipe)).await;
    let mut completed = session.local.complete(result, &session.context.clock).await;
    if let Err(failed) = &mut completed {
        if failed.failure == Failure::Ownership && failed.detail.is_none() {
            let foreign = failed.snapshot.as_deref().is_some_and(|s| {
                s.observations.iter().any(|o| {
                    o["event"]["type"] == "lifecycle-installation"
                        && o["event"]["class"] == "foreign"
                        && o["event"]["member"] == s.request["members"][0]
                })
            });
            if foreign {
                failed.detail = Some("foreign");
            }
        }
    }
    completed
}

async fn observe(
    context: &rpc::Context<'_>,
    local: &mut Local,
    binding: &Value,
    payload: &Value,
    deadline: tokio::time::Instant,
    tag: &str,
    step: &Value,
) -> Result<Value> {
    let observed = invoke(context, binding, tag, payload, deadline, None).await;
    local
        .append(
            Some(step),
            json!({"type":"dispatch","transport":observed.transport,
                "outcome":if observed.failure.is_some() {"unknown"} else {"running"},
                "failure":observed.failure.map(Failure::name)}),
            None,
            Value::Null,
        )
        .await?;
    let result = observed
        .result
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", refused(&result))?;
    Ok(result)
}

pub(super) async fn resume_member(
    context: &rpc::Context<'_>,
    local: &mut Local,
    snapshot: &Snapshot,
    index: usize,
    binding: &Value,
    ownership: &Value,
    published: &mut Option<Value>,
) -> Result<()> {
    let request = &snapshot.request;
    let member = &request["members"][index];
    let recipe = snapshot.lifecycle_recipe()?["event"]["recipe"].clone();
    let first = member["machine"] == recipe["member"]["machine"];
    let cluster = &ownership["cluster"];
    if first {
        require(cluster.is_null() || cluster.is_object(), Failure::Ownership)?;
        if !cluster.is_null() {
            *published = Some(cluster.clone());
        }
    } else {
        require(
            cluster.is_null()
                || *cluster == request["cluster"]
                || published.as_ref() == Some(cluster),
            Failure::Ownership,
        )?;
    }
    if member["role"] != "server" {
        return Ok(());
    }
    let attempt = &binding["attempt"];
    let recorded = |action: &str| {
        snapshot
            .steps
            .iter()
            .rev()
            .find(|s| {
                s["attempt"] == *attempt
                    && s["action"] == action
                    && s["recipient"]["machine"] == member["machine"]
            })
            .cloned()
    };
    let Some(inspection) = recorded("lifecycle:inspect-installation") else {
        return Ok(());
    };
    let payload = json!({"recipe":recipe,"identity":null});
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds);
    let step = inspection.clone();
    let result = observe(
        context,
        local,
        binding,
        &payload,
        deadline,
        "inspect-installation",
        &step,
    )
    .await?;
    settlement(snapshot, &step, &result)?;
    let event = installation_event(
        member,
        &result,
        ("foreign", "unpublished"),
        "inspect-installation",
    );
    let class = event["class"].as_str().unwrap_or("foreign").to_owned();
    let state = event["publication_state"]
        .as_str()
        .unwrap_or("unpublished")
        .to_owned();
    let mut identity = event["identity"].clone();
    let mut readiness = event["readiness"].clone();
    local
        .append(Some(&step), event, Some(&member["machine"]), Value::Null)
        .await?;
    if first && matches!(class.as_str(), "started" | "owned") {
        let step = recorded("lifecycle:observe-server").unwrap_or(inspection);
        let result = observe(
            context,
            local,
            binding,
            &payload,
            deadline,
            "observe-server",
            &step,
        )
        .await?;
        let event = installation_event(member, &result, (&class, &state), "observe-server");
        if identity.is_null() {
            identity = event["identity"].clone();
        }
        readiness = event["readiness"].clone();
        local
            .append(Some(&step), event, Some(&member["machine"]), Value::Null)
            .await?;
    }
    if first && class == "owned" && snapshot.owner["cluster"].is_null() && !identity.is_null() {
        local
            .append(
                Some(&step),
                json!({"type":"identity","member":member,"cluster":identity["cluster"],"resources":[],"readiness":readiness}),
                Some(&member["machine"]),
                Value::Null,
            )
            .await?;
        let owner = published_owner(&local.snapshot()?.owner, index, &identity)?;
        let operation = request["operation"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        local
            .work(move |store| store.replace_owner(owner, &operation))
            .await?;
    }
    Ok(())
}

pub(super) async fn resume_join_member(
    context: &rpc::Context<'_>,
    local: &mut Local,
    snapshot: &Snapshot,
    index: usize,
    binding: &Value,
    ownership: &Value,
) -> Result<Option<Value>> {
    let member = &snapshot.request["members"][index];
    let agent = snapshot.request["action"] == "join-agent";
    let recipe = snapshot
        .observations
        .iter()
        .find(|o| {
            o["event"]["type"]
                == if agent {
                    "agent-join-recipe"
                } else {
                    "server-join-recipe"
                }
        })
        .ok_or(Failure::Integrity)?["event"]["recipe"]
        .clone();
    require(
        recipe["member"] == *member
            && ownership["cluster"] == snapshot.request["cluster"]
            && ["machine", "member", "role"]
                .iter()
                .all(|key| ownership["machine"][*key] == member[*key]),
        Failure::Ownership,
    )?;
    let inspection = snapshot.steps.iter().find(|step| {
        step["attempt"] == binding["attempt"]
            && step["recipient"] == *member
            && step["action"]
                == if agent {
                    "lifecycle:inspect-agent"
                } else {
                    "lifecycle:inspect-join"
                }
    });
    let Some(step) = inspection else {
        return Ok(None);
    };
    let payload = if agent {
        json!({"recipe":recipe,"identity":null,"agent_view":null})
    } else {
        json!({"recipe_kind":"join","recipe":recipe,"identity":null,"membership":null,"removed":null})
    };
    let deadline =
        tokio::time::Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds);
    let original_binding = snapshot.binding(step);
    let result = observe(
        context,
        local,
        &original_binding,
        &payload,
        deadline,
        if agent {
            "inspect-agent"
        } else {
            "inspect-join"
        },
        step,
    )
    .await?;
    settlement(snapshot, step, &result)?;
    let event = installation_event(
        member,
        &result,
        ("foreign", "unpublished"),
        if agent {
            "inspect-agent"
        } else {
            "inspect-join"
        },
    );
    let identity = if event["class"] == "owned" {
        let identity = event["identity"].clone();
        require(
            !identity.is_null()
                && ownership["machine"]["node_uid"] == identity["node_uid"]
                && ownership["cluster"] == identity["cluster"]
                && ownership["data"] == identity["data"],
            Failure::Ownership,
        )?;
        Some(identity)
    } else {
        None
    };
    local
        .append(Some(step), event, Some(&member["machine"]), Value::Null)
        .await?;
    Ok(identity)
}
