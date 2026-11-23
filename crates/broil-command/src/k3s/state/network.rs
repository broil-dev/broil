// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::provenance::undispatched_transport;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{COREDNS_TEMPLATE, LOCAL_STORAGE_TEMPLATE, NETWORK, PROFILE, protocol};
use broil_config::LoadedProject;
use broil_remote::exec::private;
use serde_json::{Value, json};
use std::time::Duration;

const LIMIT: usize = 65_536;
pub(super) const FRAME_RESERVE: usize = 20_480;

pub(super) struct Family {
    pub(super) name: &'static str,
    pub(super) protocol: &'static str,
    pub(super) magic: &'static [u8],
    pub(super) header: &'static str,
    pub(super) result: &'static str,
    pub(super) body: &'static [u8],
    pub(super) planned: usize,
    pub(super) reserve: usize,
    pub(super) version: u64,
}

const FAMILY: Family = Family {
    name: "network",
    protocol: "broil-k3s-network",
    magic: b"BK3SNET1\n",
    header: "NetworkHeader",
    result: "NetworkResult",
    body: NETWORK,
    planned: 12,
    reserve: FRAME_RESERVE,
    version: 1,
};

pub(super) fn replyless(family: &str) -> bool {
    matches!(
        family,
        "registry-storage"
            | "registry-service"
            | "registry-endpoint"
            | "registry-replication"
            | "delivery"
            | "release"
    )
}

pub(super) fn family(action: &Value) -> &'static Family {
    match action.as_str() {
        Some("reconcile-ingress") => &super::ingress::FAMILY,
        Some("reconcile-cert-manager") => &super::cert_manager::FAMILY,
        Some("reconcile-issuer") => &super::issuer::FAMILY,
        Some("reconcile-certificate") => &super::certificate::FAMILY,
        Some("reconcile-registry-storage") => &super::registry_storage::FAMILY,
        Some("reconcile-registry-service") => &super::registry_service::FAMILY,
        Some("reconcile-registry-endpoint") => &super::registry_endpoint::FAMILY,
        Some("reconcile-registry-auth") => &super::registry_auth::FAMILY,
        Some("reconcile-registry-token") => &super::registry_token::FAMILY,
        Some("reconcile-registry-replication") => &super::registry_replication::FAMILY,
        Some("release-deliver" | "release-retain") => &super::release_delivery::FAMILY,
        Some("release-apply" | "release-rollback") => &super::release_apply::FAMILY,
        Some(action) if super::node::ACTIONS.contains(&action) => &super::node::FAMILY,
        _ => &FAMILY,
    }
}

pub(super) fn replaced(mut source: String, substitutions: &[(&str, &str)]) -> Result<Vec<u8>> {
    for (before, after) in substitutions {
        require(source.matches(before).count() == 1, Failure::Integrity)?;
        source = source.replace(before, after);
    }
    require(
        !source.contains("%{") && !source.contains("%}"),
        Failure::Integrity,
    )?;
    Ok(source.into_bytes())
}

fn render_hashes(network: &Value, profile: &Value) -> Result<(String, String)> {
    let text = |field: &str| network[field].as_str().ok_or(Failure::Configuration);
    let dns = text("cluster_dns")?;
    let domain = text("cluster_domain")?;
    let list = format!("[{dns}]");
    let images = &profile["network_images"];
    let image = |name: &str, path: &str| -> Result<String> {
        let digest = images[name].as_str().ok_or(Failure::Configuration)?;
        require(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            Failure::Configuration,
        )?;
        Ok(format!("docker.io/{path}@sha256:{digest}"))
    };
    let core_image = image("coredns", "rancher/mirrored-coredns-coredns")?;
    let provisioner = image("provisioner", "rancher/local-path-provisioner")?;
    let helper = image("helper", "rancher/mirrored-library-busybox")?;
    let coredns = replaced(
        std::str::from_utf8(COREDNS_TEMPLATE)
            .map_err(|_| Failure::Integrity)?
            .into(),
        &[
            (
                "data:\n  Corefile: |",
                "data:\n  NodeHosts: \"\"\n  Corefile: |",
            ),
            ("%{CLUSTER_DOMAIN}%", domain),
            ("%{CLUSTER_DNS}%", dns),
            ("%{CLUSTER_DNS_LIST}%", &list),
            ("%{CLUSTER_DNS_IPFAMILYPOLICY}%", "SingleStack"),
            (
                "%{SYSTEM_DEFAULT_REGISTRY}%rancher/mirrored-coredns-coredns:1.14.6",
                &core_image,
            ),
        ],
    )?;
    let local = replaced(
        std::str::from_utf8(LOCAL_STORAGE_TEMPLATE)
            .map_err(|_| Failure::Integrity)?
            .into(),
        &[
            (
                "%{SYSTEM_DEFAULT_REGISTRY}%rancher/local-path-provisioner:v0.0.37",
                &provisioner,
            ),
            (
                "%{SYSTEM_DEFAULT_REGISTRY}%rancher/mirrored-library-busybox:1.37.0",
                &helper,
            ),
            (
                "%{DEFAULT_LOCAL_STORAGE_PATH}%",
                "/var/lib/rancher/k3s/storage",
            ),
        ],
    )?;
    Ok((protocol::digest(&coredns), protocol::digest(&local)))
}

fn recipe(context: &rpc::Context<'_>, owner: &Value, operation: &str) -> Result<Value> {
    let selected = context.selected.declaration;
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let cidr = |value: broil_core::k3s::Ipv4Cidr| format!("{}/{}", value.network, value.prefix);
    let network = json!({"pod_cidr":cidr(selected.network.pod_cidr),
        "service_cidr":cidr(selected.network.service_cidr),
        "cluster_dns":selected.network.cluster_dns.to_string(),
        "cluster_domain":context.selected.cluster_domain,"flannel":"vxlan"});
    let (coredns, local) = render_hashes(&network, &profile)?;
    let members = &owner["members"];
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"members":members,"first_server":members[0],
        "version":selected.version,"network":network,
        "profile_sha256":context.fingerprints["profile_sha256"],
        "coredns_template_sha256":profile["network_templates"]["coredns"],
        "local_storage_template_sha256":profile["network_templates"]["local_storage"],
        "coredns_render_sha256":coredns,"local_storage_render_sha256":local});
    schema::validate(&canonical(&recipe)?, "NetworkRecipe", 32_768)?;
    Ok(recipe)
}

fn frame(bytes: &[u8], header: &[u8], family: &Family) -> Result<Value> {
    require(
        bytes.len() <= LIMIT && bytes.starts_with(family.magic),
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
        let end = 4usize.checked_add(size).ok_or(Failure::Bound)?;
        let value = bytes.get(4..end).ok_or(Failure::Integrity)?;
        *bytes = bytes.get(end..).ok_or(Failure::Integrity)?;
        Ok(value)
    }
    let mut rest = &bytes[family.magic.len()..];
    require(field(&mut rest)? == header, Failure::Integrity)?;
    let result = field(&mut rest)?;
    require(rest.is_empty(), Failure::Integrity)?;
    schema::decode(result, family.result, LIMIT)
}

pub(super) async fn invoke(
    context: &rpc::Context<'_>,
    family: &Family,
    binding: &Value,
    tag: &str,
    payload: &Value,
    deadline: tokio::time::Instant,
    child: Option<&private::CredentialClock>,
) -> rpc::Observed {
    let data: Option<&[u8]> = (family.name == "release").then_some(&[]);
    invoke_with(
        context, family, binding, tag, payload, data, deadline, child,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn invoke_with(
    context: &rpc::Context<'_>,
    family: &Family,
    binding: &Value,
    tag: &str,
    payload: &Value,
    data: Option<&[u8]>,
    deadline: tokio::time::Instant,
    child: Option<&private::CredentialClock>,
) -> rpc::Observed {
    let mut observed = rpc::Observed {
        response: None,
        transport: undispatched_transport(),
        failure: None,
    };
    let ended = |failure: Failure| {
        if family.name == "release" && child.is_none() && tokio::time::Instant::now() >= deadline {
            Failure::Timeout
        } else {
            failure
        }
    };
    let result: Result<()> = async {
        context.check()?;
        schema::validate(&canonical(binding)?, "Binding", 4096)?;
        require(binding["scope"] == context.scope && binding["fingerprints"] == context.fingerprints,
            Failure::Ownership)?;
        let machine = binding["recipient"]["machine"].as_str().ok_or(Failure::Integrity)?;

        let connection = match context.connect_body(machine, deadline, child, family.body).await {
            Ok(value) => value,
            Err(failure) => { observed.transport = rpc::transport(&failure); return Err(ended(Failure::Transport)); }
        };
        let prepared = (|| {
            require(context.member(machine, &connection, binding["recipient"]["node_uid"].clone())?
                == binding["recipient"], Failure::Trust)?;
            let remaining = connection.deadline().saturating_duration_since(tokio::time::Instant::now())
                .as_millis().min(if child.is_some() {7_200_000} else {30_000}) as u64;
            require(remaining > 0, Failure::Timeout)?;
            let mut header = json!({"protocol":family.protocol,"version":family.version,"action":tag,
                "request_id":if child.is_some() {binding["dispatch"].clone()} else {json!(fresh()?)},
                "binding":binding,"remaining_ms":remaining});
            for (key, value) in payload.as_object().ok_or(Failure::Integrity)? { header[key.as_str()] = value.clone(); }
            let bytes = canonical(&header)?;
            schema::validate(&bytes, family.header, LIMIT)?;
            require(17usize.saturating_add(bytes.len()).saturating_add(family.reserve) <= LIMIT,
                Failure::Bound)?;
            Ok(bytes)
        })();
        let bytes = match prepared {
            Ok(value) => value,
            Err(failure) => { observed.transport = rpc::transport(&connection.close().await);
                return Err(failure); }
        };
        let output = match data {
            Some(data) => connection.run_release(bytes.clone(), data, false).await,
            None => connection.run_lifecycle(bytes.clone(), false).await,
        }
        .map_err(|_| ended(Failure::Transport))?;
        observed.transport = rpc::transport(&output.observation);
        require(output.observation.failure.is_none() && output.observation.remote_status == Some(0)
            && output.observation.remote_signal.is_none() && !output.observation.unresolved_input
            && !output.observation.possible_staging_residue && output.stderr.bytes().is_empty(),
            ended(Failure::Transport))?;
        observed.response = Some(frame(output.stdout.bytes(), &bytes, family)?);
        Ok(())
    }.await;
    observed.failure = result.err();
    observed
}

pub(super) fn observation(family: &Family, member: Value, result: &Value) -> Value {
    match family.name {
        "ingress" => json!({"type":"ingress-observation","member":member,"hosts":result["hosts"],
            "objects":result["objects"],"results":result["results"],
            "ingress":result["ingress"],"services":result["services"]}),
        "cert-manager" => json!({"type":"cert-manager-observation","member":member,
            "hosts":result["hosts"],"objects":result["objects"],"webhook":result["webhook"],
            "services":result["services"]}),
        "issuer" => json!({"type":"issuer-observation","member":member,
            "objects":result["objects"],"issuer":result["issuer"],"services":result["services"]}),
        "certificate" => json!({"type":"certificate-observation","member":member,
            "objects":result["objects"],"certificate":result["certificate"],
            "services":result["services"]}),
        "registry-storage" => json!({"type":"registry-storage-observation","member":member,
            "storage":result["storage"],"nodes":result["nodes"]}),
        "registry-endpoint" => json!({"type":"registry-endpoint-observation",
            "objects":result["objects"],"issued":result["issued"],"served":result["served"]}),
        "registry-auth" => json!({"type":"registry-auth-observation","member":member,
            "objects":result["objects"],"registration":result["registration"],
            "signing":result["signing"],"services":result["services"]}),
        "registry-token" => json!({"type":"registry-token-observation","member":member,
            "generation":result["generation"],"image":result["image"],"runtime":result["runtime"],
            "objects":result["objects"],"signing":result["signing"],"token":result["token"],
            "registry":result["registry"],"nodes":result["nodes"],
            "enforcement":result["enforcement"],"principals":result["principals"],
            "grants":result["grants"]}),
        "node" => json!({"type":"node-observation","member":member,
            "kind":if !result["node"].is_null() {"node"} else if result["unit"].is_null() {"configure"}
                else {"restart"},"unit":result["unit"],"node":result["node"]}),
        "registry-replication" => json!({"type":super::registry_replication::OBSERVATION,
            "member":member,"replication":result["replication"],"objects":result["objects"],
            "readers":result["readers"],"tokens":result["tokens"],"writer":result["writer"],
            "node":result["node"],"cordoned":result["cordoned"]}),
        "registry-service" => json!({"type":"registry-service-observation","member":member,
            "generation":result["generation"],"image":result["image"],"runtime":result["runtime"],
            "storage":result["storage"],"objects":result["objects"],"process":result["process"],
            "nodes":result["nodes"]}),
        _ => json!({"type":"network-observation","member":member,"hosts":result["hosts"],
            "objects":result["objects"],"services":result["services"],"storage":result["storage"]}),
    }
}

pub(super) fn latest_sequence(snapshot: &Snapshot, tag: &str) -> Result<Value> {
    snapshot
        .observations
        .iter()
        .rev()
        .find(|o| o["event"]["type"] == tag)
        .map(|o| o["sequence"].clone())
        .ok_or(Failure::Integrity)
}

fn checked_objects(snapshot: &Snapshot, records: &Value, repeat: bool) -> Result<()> {
    let records = records.as_array().ok_or(Failure::Integrity)?;
    let planned = snapshot.request["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    let owner = snapshot.owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    require(
        records.len() == 12 && planned.len() == 12,
        Failure::Integrity,
    )?;
    for (index, record) in records.iter().enumerate() {
        let resource = &planned[index];
        require(
            record["name"] == resource["name"] && record["namespace"] == resource["namespace"],
            Failure::Ownership,
        )?;
        let bound = owner
            .iter()
            .find(|r| r["id"] == resource["id"])
            .ok_or(Failure::Ownership)?;
        match record["class"].as_str() {
            Some("absent") if !repeat && bound["uid"].is_null() && record["uid"].is_null() => {}
            Some("owned-ready") if bound["uid"].is_string() && record["uid"] == bound["uid"] => {}
            _ => return Err(Failure::Ownership),
        }
    }
    Ok(())
}

pub(super) fn check_agent_view(
    context: &rpc::Context<'_>,
    members: &[Value],
    cluster: &Value,
    view: &Value,
) -> Result<()> {
    require(
        view["cluster"] == *cluster
            && &view["observer"] == members.first().ok_or(Failure::Integrity)?
            && view["foreign"].as_array().is_some_and(Vec::is_empty)
            && view["members"]
                .as_array()
                .is_some_and(|items| items.len() == members.len()),
        Failure::Ownership,
    )?;
    for (index, expected) in members.iter().enumerate() {
        let item = &view["members"][index];
        require(
            item["member"] == *expected
                && item["present"] == true
                && item["uid"] == expected["node_uid"]
                && item["ready"] == true
                && item["roles"] == json!([expected["role"]]),
            Failure::Readiness,
        )?;
        let (labels, taints) = declared(context, expected)?;
        require(item["labels"] == labels, Failure::Ownership)?;
        require(item["taints"] == taints, Failure::Ownership)?;
    }
    Ok(())
}

pub(super) fn declared(context: &rpc::Context<'_>, member: &Value) -> Result<(Value, Value)> {
    let declared = context
        .selected
        .members
        .iter()
        .find(|m| m.declaration.machine == member["machine"])
        .ok_or(Failure::Configuration)?
        .declaration;
    let mut labels: Vec<_> = declared
        .labels
        .iter()
        .map(|(key, value)| json!(format!("{key}={value}")))
        .collect();
    labels.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    let mut taints = Vec::new();
    for taint in &declared.taints {
        let effect = match taint.effect {
            broil_core::k3s::TaintEffect::NoSchedule => "NoSchedule",
            broil_core::k3s::TaintEffect::PreferNoSchedule => "PreferNoSchedule",
            broil_core::k3s::TaintEffect::NoExecute => "NoExecute",
        };
        taints.push(json!(format!("{}={}:{effect}", taint.key, taint.value)));
    }
    taints.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
    Ok((json!(labels), json!(taints)))
}

const HOST_FACTS: [&str; 9] = [
    "configuration",
    "interface",
    "routes",
    "ports",
    "flannel",
    "proxy",
    "policy",
    "capacity",
    "service",
];

pub(super) fn settling(hosts: &Value) -> bool {
    let pending: Vec<_> = HOST_FACTS
        .into_iter()
        .filter(|key| hosts[*key]["state"] != "ready")
        .collect();
    pending
        .iter()
        .all(|key| matches!(*key, "flannel" | "proxy" | "policy" | "ports"))
        && pending
            .iter()
            .any(|key| matches!(*key, "flannel" | "proxy" | "policy"))
}

pub(super) fn host_refusal(hosts: &[Value]) -> Option<Option<&'static str>> {
    let mut refusing = hosts
        .iter()
        .filter(|hosts| !HOST_FACTS.iter().all(|key| hosts[*key]["state"] == "ready"))
        .peekable();
    refusing
        .peek()
        .is_some()
        .then(|| refusing.all(settling).then_some("settling"))
}

pub(super) fn unclean(transport: &Value) -> bool {
    transport["input_released"] != true || transport["staging_cleanup"] != "clean"
}

pub(super) fn read_binding(
    request: &Value,
    attempt: &str,
    last: u64,
    index: usize,
) -> Result<Value> {
    let step = last
        .checked_add(1)
        .filter(|step| *step <= u64::from(u32::MAX))
        .ok_or(Failure::Bound)?;
    Ok(json!({"scope":request["scope"],"owner":request["owner"],
        "operation":request["operation"],"attempt":attempt,"step":step,
        "dispatch":fresh()?,"recipient":request["members"][index],"receiver_generation":0,
        "request_sha256":hash("broil-infra-request-v1", request)?,
        "participants_sha256":request["participants_sha256"],"fingerprints":request["fingerprints"]}))
}

pub(super) async fn membership_reads(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    source_events: &[Value],
    cleanup: &mut bool,
) -> Result<()> {
    let members = request["members"].as_array().ok_or(Failure::Integrity)?;
    let binding = |index: usize| read_binding(request, attempt, last, index);
    let deadline = || {
        context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(context.selected.step_timeout.seconds),
        )
    };
    let servers: Vec<_> = source_events
        .iter()
        .filter(|event| event["type"] == "server-recipe")
        .collect();
    require(
        servers.len()
            == members
                .iter()
                .filter(|member| member["role"] == "server")
                .count(),
        Failure::Integrity,
    )?;
    let mut quorum = None;
    for event in servers {
        let index = members
            .iter()
            .position(|member| member == &event["recipe"]["member"])
            .ok_or(Failure::Ownership)?;
        let source = json!({"recipe_kind":event["recipe_kind"],"recipe":event["recipe"],
            "identity":null,"membership":null,"removed":null});
        let observed = super::server::invoke(
            context,
            &binding(index)?,
            "observe-membership",
            &source,
            deadline(),
            None,
        )
        .await;
        *cleanup |= unclean(&observed.transport);
        let result = observed
            .result
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(result["status"] == "ok", super::server::refused(&result))?;
        let membership = &result["membership"];
        require(
            membership["healthy"] == true
                && membership["cluster"] == request["cluster"]
                && membership["node_uid"] == members[index]["node_uid"]
                && membership["observer"] == members[index]["machine"]
                && membership["members"].as_array().is_some_and(|items| {
                    items.len()
                        == source_events
                            .iter()
                            .filter(|event| event["type"] == "server-recipe")
                            .count()
                }),
            Failure::Readiness,
        )?;
        if let Some(previous) = &quorum {
            require(previous == &membership["members"], Failure::Ownership)?;
        } else {
            quorum = Some(membership["members"].clone());
        }
    }
    if let Some(agent) = source_events
        .iter()
        .find(|event| event["type"] == "agent-join-recipe")
    {
        let source = json!({"recipe":agent["recipe"],"identity":null,"agent_view":null});
        let observed = super::server::invoke(
            context,
            &binding(0)?,
            "observe-agent-membership",
            &source,
            deadline(),
            None,
        )
        .await;
        *cleanup |= unclean(&observed.transport);
        let result = observed
            .result
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(result["status"] == "ok", super::server::refused(&result))?;
        check_agent_view(context, members, &request["cluster"], &result["agent_view"])
    } else {
        require(
            members.iter().all(|member| member["role"] == "server"),
            Failure::Integrity,
        )
    }
}

#[allow(clippy::too_many_arguments)]
async fn preflight(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    original: &Value,
    repeat: bool,
    source_events: &[Value],
    prior_objects: Option<&Value>,
    cleanup: &mut bool,
    detail: &mut Option<&'static str>,
) -> Result<()> {
    membership_reads(context, request, attempt, last, source_events, cleanup).await?;
    let members = request["members"].as_array().ok_or(Failure::Integrity)?;
    let planned = request["resources"].as_array().ok_or(Failure::Integrity)?;
    let binding = |index: usize| read_binding(request, attempt, last, index);
    let payload = json!({"recipe":recipe,"original_recipe_sha256":original,"object_ordinal":null,
        "resource":null,"preflight":null});
    let deadline = || {
        context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(context.selected.step_timeout.seconds),
        )
    };
    let mut inspected = Vec::new();
    for (index, member) in members.iter().enumerate() {
        let observed = invoke(
            context,
            &FAMILY,
            &binding(index)?,
            "inspect-host",
            &payload,
            deadline(),
            None,
        )
        .await;
        *cleanup |= unclean(&observed.transport);
        let result = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(result["status"] == "ok", super::server::refused(&result))?;
        require(result["hosts"]["member"] == *member, Failure::Readiness)?;
        inspected.push(result["hosts"].clone());
    }
    if let Some(refusal) = host_refusal(&inspected) {
        *detail = refusal;
        return Err(Failure::Readiness);
    }
    let observed = invoke(
        context,
        &FAMILY,
        &binding(0)?,
        "inspect-objects",
        &payload,
        deadline(),
        None,
    )
    .await;
    *cleanup |= unclean(&observed.transport);
    let result = observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", super::server::refused(&result))?;
    let records = result["objects"].as_array().ok_or(Failure::Integrity)?;
    require(
        records.len() == 12 && planned.len() == 12,
        Failure::Integrity,
    )?;
    for (index, (record, resource)) in records.iter().zip(planned).enumerate() {
        let prior_matches = prior_objects.is_some_and(|prior| {
            let earlier = &prior[index];
            record == earlier
                || (record["class"] == "owned-ready"
                    && earlier["class"] == "owned-ready"
                    && ["kind", "namespace", "name", "uid", "class", "spec_sha256"]
                        .iter()
                        .all(|key| record[*key] == earlier[*key]))
        });
        require(
            record["name"] == resource["name"]
                && record["namespace"] == resource["namespace"]
                && if prior_objects.is_some() {
                    prior_matches
                } else if repeat {
                    record["class"] == "owned-ready" && record["uid"] == resource["uid"]
                } else {
                    record["class"] == "absent" && record["uid"].is_null()
                },
            Failure::Ownership,
        )?;
    }
    Ok(())
}

pub(super) fn source_recipes(
    previous: &[Snapshot],
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    attempt: &str,
) -> Result<Vec<Value>> {
    let members = &super::survivors(owner)?;
    let mut events = Vec::new();
    for member in members.iter().filter(|m| m["role"] == "server") {
        let matches = previous
            .iter()
            .filter(|snapshot| {
                matches!(
                    snapshot.request["action"].as_str(),
                    Some("create-server" | "join-server")
                ) && super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
                    .is_ok_and(|report| report["outcome"] == "succeeded")
            })
            .flat_map(|snapshot| snapshot.observations.iter().map(move |o| (snapshot, o)))
            .filter(|(_, observation)| {
                matches!(
                    observation["event"]["type"].as_str(),
                    Some("lifecycle-recipe" | "server-join-recipe")
                ) && observation["event"]["recipe"]["member"]["machine"] == member["machine"]
                    && observation["event"]["recipe"]["member"]["node_uid"].is_null()
            });
        let mut source = super::current_installation(matches)?["event"]["recipe"].clone();
        require(
            source["scope"] == context.scope
                && source["owner"] == owner["owner"]
                && source["version"] == context.selected.declaration.version,
            Failure::Ownership,
        )?;
        source["operation"] = json!(operation);
        source["attempt"] = json!(attempt);
        source["members"] = json!(members);
        source["member"] = member.clone();
        if !source["source"].is_null() {
            source["source"] = members[0].clone();
        }
        events.push(json!({"type":"server-recipe",
            "recipe_kind":if source["source"].is_null() {"initial"} else {"join"},
            "recipe":source}));
    }
    let Some(member) = members.iter().rfind(|m| m["role"] == "agent") else {
        return Ok(events);
    };
    let matches = previous
        .iter()
        .filter(|snapshot| {
            snapshot.request["action"] == "join-agent"
                && super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
                    .is_ok_and(|report| report["outcome"] == "succeeded")
        })
        .flat_map(|snapshot| snapshot.observations.iter().map(move |o| (snapshot, o)))
        .filter(|(_, observation)| {
            observation["event"]["type"] == "agent-join-recipe"
                && observation["event"]["recipe"]["member"]["machine"] == member["machine"]
                && observation["event"]["recipe"]["member"]["node_uid"].is_null()
        });
    let mut source = super::current_installation(matches)?["event"]["recipe"].clone();
    require(
        source["scope"] == context.scope
            && source["owner"] == owner["owner"]
            && source["cluster"] == owner["cluster"]
            && source["version"] == context.selected.declaration.version,
        Failure::Ownership,
    )?;
    source["operation"] = json!(operation);
    source["attempt"] = json!(attempt);
    source["members"] = json!(members);
    source["source"] = members[0].clone();
    source["member"] = member.clone();
    let recorded = source["installed"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .clone();
    let mut installed = Vec::new();
    for current in members
        .iter()
        .take_while(|m| m["member"] != member["member"])
        .filter(|m| m["role"] != "backup" && !m["node_uid"].is_null())
    {
        let identity = match recorded.iter().find(|entry| {
            entry["member"]["member"] == current["member"]
                && entry["member"]["machine"] == current["machine"]
        }) {
            Some(entry) => entry["recipe_identity_sha256"].clone(),
            None => json!(super::provenance::recipe_identity(
                super::agent::prior_recipe(context, previous, current)?
            )?),
        };
        installed.push(json!({"member":current,"recipe_identity_sha256":identity}));
    }
    source["installed"] = json!(installed);
    events.push(json!({"type":"agent-join-recipe","recipe":source}));
    Ok(events)
}

pub(super) fn original_request<'a>(
    previous: &'a [Snapshot],
    planned: &[Value],
    action: &str,
) -> Result<&'a Snapshot> {
    let create = format!("lifecycle:{}-create-object", &action["reconcile-".len()..]);
    let created = |step: &Value| {
        step["action"]
            .as_str()
            .is_some_and(|a| a == create || a.strip_suffix('s') == Some(&create))
    };
    let creates = |snapshot: &Snapshot| snapshot.steps.iter().any(created);
    let binds = |source: &Snapshot| {
        planned.iter().all(|resource| {
            source.steps.iter().any(|step| {
                created(step) && step["resource"]["id"] == resource["id"] && source.succeeded(step)
            }) && source.observations.iter().any(|o| {
                o["event"]["type"] == "identity"
                    && o["event"]["resources"][0]["uid"] == resource["uid"]
            })
        })
    };
    let (bound, others): (Vec<&Snapshot>, Vec<&Snapshot>) = previous
        .iter()
        .filter(|s| {
            s.request["action"] == action
                && s.request["resources"].as_array().is_some_and(|r| {
                    r.iter()
                        .filter(|v| v["kind"] != "bootstrap-assets")
                        .all(|v| v["uid"].is_null())
                })
        })
        .partition(|&s| binds(s));
    require(
        bound.len() == 1 && !others.into_iter().any(creates),
        Failure::Ownership,
    )?;
    Ok(bound[0])
}

pub(super) async fn resume_recorded(
    context: &rpc::Context<'_>,
    local: &mut Local,
    original: &Snapshot,
) -> Result<Vec<Value>> {
    let family = family(&original.request["action"]);
    let (name, count) = (family.name, family.planned);
    let create = format!("lifecycle:{name}-create-object");
    let mutations = [
        create.clone(),
        format!("{create}s"),
        format!("lifecycle:{name}-import-image"),
        format!("lifecycle:{name}-import-images"),
        format!("lifecycle:{name}-register-input"),
        format!("lifecycle:{name}-activate"),
        format!("lifecycle:{name}-create-issuer"),
        format!("lifecycle:{name}-create-storage"),
    ];
    let mutations: Vec<String> = if name == "registry-replication" {
        super::registry_replication::MUTATIONS
            .iter()
            .map(|tag| super::registry_replication::action(tag))
            .collect()
    } else if name == "delivery" {
        super::release_delivery::MUTATIONS
            .iter()
            .map(|tag| super::release_delivery::action(tag))
            .collect()
    } else if name == "release" {
        vec!["lifecycle:release-apply-objects".to_owned()]
    } else {
        mutations.to_vec()
    };
    let recipe_event = if name == "registry-replication" {
        "replication-recipe".to_owned()
    } else if name == "delivery" {
        super::release_delivery::RECIPE.to_owned()
    } else {
        format!("{name}-recipe")
    };
    let recipe = original
        .observations
        .iter()
        .find(|o| o["event"]["type"] == recipe_event.as_str())
        .map(|o| o["event"]["recipe"].clone())
        .ok_or(Failure::Integrity)?;
    let attempt = original.attempts.last().ok_or(Failure::Integrity)?;
    let members = original.request["members"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    let mut writers = Vec::with_capacity(members.len());
    for member in members {
        let binding = super::recovery::member_binding(original, member, &attempt["attempt"])?;
        let owner = super::recovery::inspect(
            context,
            original,
            &binding,
            "owner",
            Value::Null,
            Value::Null,
        )
        .await?
        .response
        .ok_or(Failure::Transport)?;
        require(
            owner["status"] == "ok"
                && owner["data"]["ownership"]["cluster"] == original.request["cluster"]
                && owner["data"]["ownership"]["machine"]["node_uid"] == member["node_uid"],
            Failure::Ownership,
        )?;
        let writer = super::recovery::inspect(
            context,
            original,
            &binding,
            "writer",
            Value::Null,
            Value::Null,
        )
        .await?
        .response
        .ok_or(Failure::Transport)?;
        require(
            matches!(writer["status"].as_str(), Some("ok" | "absent")),
            Failure::Readiness,
        )?;
        writers.push(writer["data"].clone());
    }
    for step in original
        .steps
        .iter()
        .filter(|s| mutations.iter().any(|m| s["action"] == m.as_str()) && !original.deselected(s))
    {
        let observed = context
            .receipt(
                original,
                step,
                tokio::time::Instant::now()
                    + Duration::from_secs(context.selected.step_timeout.seconds),
            )
            .await;
        let response = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(
            response["status"] == "ok" && !response["data"]["terminal"].is_null(),
            Failure::Readiness,
        )?;
        let receipt = response["data"]["terminal"].clone();
        local
            .append(
                Some(step),
                json!({"type":"receiver","receipt":receipt,
            "transport":observed.transport}),
                Some(&step["recipient"]["machine"]),
                receipt["completed_ms"].clone(),
            )
            .await?;
    }
    if name == "cert-manager" {
        super::cert_manager::resume_objects(context, local, original, &recipe).await?;
        return Ok(writers);
    }
    if name == "issuer" {
        super::issuer::resume_objects(context, local, original, &recipe).await?;
        return Ok(writers);
    }
    if name == "certificate" {
        super::certificate::resume_objects(context, local, original, &recipe).await?;
        return Ok(writers);
    }
    if name == "registry-auth" {
        super::registry_auth::resume_objects(context, local, original, &recipe).await?;
        return Ok(writers);
    }
    if name == "registry-token" {
        super::registry_token::resume_objects(context, local, original, &recipe).await?;
        return Ok(writers);
    }
    if replyless(name) {
        return Ok(writers);
    }
    let inspect_step = original
        .steps
        .iter()
        .rev()
        .find(|s| s["action"] == format!("lifecycle:{name}-inspect-objects"));
    if let Some(inspect_step) = inspect_step {
        let binding = original.binding(inspect_step);
        let (sent, original_hash) = super::derived_recipe(
            &recipe,
            &original.request,
            &super::component_assets(original),
        )?;
        let payload = json!({"recipe":sent,"original_recipe_sha256":original_hash,
            "object_ordinal":null,"resource":null,"preflight":null});
        let observed = invoke(
            context,
            family,
            &binding,
            "inspect-objects",
            &payload,
            tokio::time::Instant::now()
                + Duration::from_secs(context.selected.step_timeout.seconds),
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
                observation(family, Value::Null, &result),
                Some(&members[0]["machine"]),
                Value::Null,
            )
            .await?;
        for step in original.steps.iter().filter(|s| s["action"] == create) {
            let snapshot = local.snapshot()?;
            let resource = &step["resource"];
            let prior = snapshot.owner["resources"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .iter()
                .find(|r| r["id"] == resource["id"])
                .ok_or(Failure::Ownership)?;
            let receipt = snapshot
                .observations
                .iter()
                .rev()
                .find(|o| o["step"] == step["step"] && o["event"]["type"] == "receiver")
                .ok_or(Failure::Readiness)?["event"]["receipt"]
                .clone();
            require(
                receipt["outcome"] == "succeeded"
                    && receipt["effect"] == "complete"
                    && snapshot.succeeded(step),
                Failure::Readiness,
            )?;
            let uid = &receipt["resource_identity"];
            if prior["uid"].is_string() {
                require(prior["uid"] == *uid, Failure::Ownership)?;
                continue;
            }
            let ordinal = resource["id"]
                .as_str()
                .and_then(|id| id.strip_prefix(&format!("{name}-object-")))
                .and_then(|part| part.parse::<usize>().ok())
                .ok_or(Failure::Integrity)?;
            require(
                (1..=count).contains(&ordinal)
                    && result["objects"][ordinal - 1]["uid"] == *uid
                    && result["objects"][ordinal - 1]["class"] == "owned-ready",
                Failure::Ownership,
            )?;
            let mut published = resource.clone();
            published["uid"] = uid.clone();
            local
                .append(
                    Some(step),
                    json!({"type":"identity","member":null,
                "cluster":snapshot.request["cluster"],"resources":[published],
                "readiness":super::report::readiness()}),
                    None,
                    Value::Null,
                )
                .await?;
            let snapshot = local.snapshot()?;
            let mut owner = snapshot.owner.clone();
            owner["previous_generation"] = owner["generation"].clone();
            owner["generation"] = json!(fresh()?);
            owner["created_ms"] = json!(now()?);
            let resources = owner["resources"]
                .as_array_mut()
                .ok_or(Failure::Integrity)?;
            let selected = resources
                .iter_mut()
                .find(|r| r["id"] == resource["id"])
                .ok_or(Failure::Ownership)?;
            *selected = published;
            let operation = snapshot.request["operation"]
                .as_str()
                .ok_or(Failure::Integrity)?
                .to_owned();
            local
                .work(move |store| store.replace_owner(owner, &operation))
                .await?;
        }
    }
    Ok(writers)
}

impl Session<'_> {
    pub(super) async fn network_source_gate(&mut self) -> Result<()> {
        let snapshot = self.local.snapshot()?;
        let cluster = snapshot.request["cluster"].clone();
        let sources: Vec<_> = snapshot
            .observations
            .iter()
            .filter(|o| o["event"]["type"] == "server-recipe")
            .map(|o| (o["sequence"].clone(), o["event"].clone()))
            .collect();
        let agent = snapshot
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "agent-join-recipe")
            .map(|o| (o["sequence"].clone(), o["event"]["recipe"].clone()));
        let servers: Vec<_> = self
            .members
            .iter()
            .enumerate()
            .filter(|(_, member)| member["role"] == "server")
            .map(|(index, _)| index)
            .collect();
        require(sources.len() == servers.len(), Failure::Integrity)?;
        let mut quorum = None;
        for index in servers {
            let (sequence, event) = sources
                .iter()
                .find(|(_, event)| event["recipe"]["member"] == self.members[index])
                .ok_or(Failure::Integrity)?;
            let payload = json!({"recipe_kind":event["recipe_kind"],"recipe":event["recipe"],
                "identity":null,"membership":null,"removed":null});
            let result = self
                .lifecycle_dispatch(
                    self.next_step,
                    index,
                    "observe-membership",
                    payload,
                    vec![sequence.clone()],
                    false,
                )
                .await?
                .result;
            self.next_step += 1;
            let membership = &result["membership"];
            require(
                membership["healthy"] == true
                    && membership["cluster"] == cluster
                    && membership["node_uid"] == self.members[index]["node_uid"]
                    && membership["observer"] == self.members[index]["machine"]
                    && membership["members"]
                        .as_array()
                        .is_some_and(|items| items.len() == sources.len()),
                Failure::Readiness,
            )?;
            if let Some(previous) = &quorum {
                require(previous == &membership["members"], Failure::Ownership)?;
            } else {
                quorum = Some(membership["members"].clone());
            }
        }
        let Some(agent) = agent else {
            return require(
                self.members.iter().all(|member| member["role"] == "server"),
                Failure::Integrity,
            );
        };
        let result = self
            .lifecycle_dispatch(
                self.next_step,
                0,
                "observe-agent-membership",
                json!({"recipe":agent.1,"identity":null,"agent_view":null}),
                vec![agent.0],
                false,
            )
            .await?
            .result;
        self.next_step += 1;
        let view = &result["agent_view"];
        check_agent_view(&self.context, &self.members, &cluster, view)
    }

    pub(super) async fn network_step(
        &mut self,
        index: usize,
        tag: &str,
        recipe: &Value,
        ordinal: Option<usize>,
        preflight: Option<&Value>,
        refs: Vec<Value>,
    ) -> Result<(Value, Value)> {
        let family = family(&self.local.snapshot()?.request["action"]);
        let resources = self.local.snapshot()?.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let resource = match ordinal {
            Some(ordinal) => (resources.len() + ordinal)
                .checked_sub(family.planned + 1)
                .and_then(|position| resources.get(position))
                .cloned()
                .ok_or(Failure::Integrity)?,
            None if tag == "import-image" => resources
                .iter()
                .find(|r| {
                    r["kind"] == "bootstrap-assets"
                        && r["machine"] == self.members[index]["machine"]
                })
                .cloned()
                .ok_or(Failure::Ownership)?,
            None => Value::Null,
        };
        let original = super::original_hash(self.local.snapshot()?, recipe)?;
        let payload = json!({"recipe":recipe,"original_recipe_sha256":original,
            "object_ordinal":ordinal,"resource":resource,"preflight":preflight});
        self.family_step(index, tag, payload, refs).await
    }

    pub(super) async fn family_step(
        &mut self,
        index: usize,
        tag: &str,
        payload: Value,
        refs: Vec<Value>,
    ) -> Result<(Value, Value)> {
        self.context.check()?;
        let family = if tag == "configure-registries" {
            &super::node::FAMILY
        } else {
            family(&self.local.snapshot()?.request["action"])
        };
        let mutation = matches!(
            tag,
            "create-object"
                | "import-image"
                | "create-objects"
                | "import-images"
                | "register-input"
                | "activate"
                | "create-issuer"
                | "create-storage"
                | "configure-token"
                | "switch-registry"
                | "configure-principals"
                | "restart"
                | "configure-registries"
        ) || family.name == "registry-replication"
            && super::registry_replication::mutation(tag);
        require(!mutation || self.mode == Mode::Work, Failure::Capability)?;
        let resource = payload["resource"].clone();
        let action = format!("lifecycle:{}-{tag}", family.name);
        let step = self.intended(index, &action, &payload, refs)?;
        let recorded = step.clone();
        self.local.work(move |store| store.step(recorded)).await?;
        self.local.work(|store| store.verify()).await?;
        let binding = self.local.snapshot()?.binding(&step);
        let deadline = self.context.clock.deadline().min(
            tokio::time::Instant::now()
                + Duration::from_secs(self.context.selected.step_timeout.seconds),
        );
        let child = mutation.then(|| self.context.clock.for_credential_action(deadline));
        let observed = invoke(
            &self.context,
            family,
            &binding,
            tag,
            &payload,
            deadline,
            child.as_ref(),
        )
        .await;
        let settled = matches!(
            (family.name, tag),
            ("issuer", "create-issuer") | ("certificate", "create-object")
        ) && observed.failure.is_none()
            && observed.response.as_ref().is_some_and(|result| {
                super::issuer::conclusive(result, &observed.transport, &binding, &step, &resource)
            })
            && tokio::time::Instant::now() < deadline;
        self.local.completion_unknown |=
            mutation && observed.failure.is_some() && observed.transport["dispatch"] != "none";
        if !settled
            && (observed.failure.is_some()
                || observed
                    .response
                    .as_ref()
                    .is_some_and(|result| result["status"] != "ok"))
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
        let result = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        self.local.completion_unknown |= mutation
            && (result["status"] == "unknown" || result["terminal"]["effect"] == "unknown");
        require(
            result["kind"] == "result"
                && (result["failure"].is_null() == (result["status"] == "ok")),
            Failure::Integrity,
        )?;
        let hosts = matches!(tag, "inspect-host" | "import-image" | "import-images");
        if result["status"] == "ok" && family.name == "issuer" {
            super::issuer::shape(tag, &result)?;
        } else if result["status"] == "ok" && family.name == "certificate" {
            super::certificate::shape(tag, &result)?;
        } else if result["status"] == "ok" && family.name == "registry-storage" {
            super::registry_storage::shape(tag, &result)?;
        } else if result["status"] == "ok" && family.name == "registry-service" {
            super::registry_service::shape(tag, &result)?;
        } else if result["status"] == "ok" && family.name == "registry-endpoint" {
            super::registry_endpoint::shape(tag, &result)?;
        } else if result["status"] == "ok" && family.name == "registry-auth" {
            super::registry_auth::shape(tag, &result)?;
        } else if result["status"] == "ok" && family.name == "registry-token" {
            super::registry_token::shape(tag, &result)?;
        } else if result["status"] == "ok" && family.name == "node" {
            super::node::shape(tag, &result)?;
        } else if result["status"] == "ok" && family.name == "registry-replication" {
            super::registry_replication::shape(tag, &result)?;
        } else if result["status"] == "ok" {
            require(
                (result["hosts"].is_null() != hosts)
                    && (result["objects"].is_null() == hosts)
                    && match family.name {
                        "ingress" => ["results", "ingress", "services"]
                            .iter()
                            .all(|key| result[*key].is_null() == hosts),
                        "cert-manager" => ["webhook", "services"]
                            .iter()
                            .all(|key| result[*key].is_null() != (tag == "inspect-objects")),
                        _ => true,
                    }
                    && (result["terminal"].is_null() != mutation),
                Failure::Integrity,
            )?;
        }
        if let Some(receipt) = result["terminal"].as_object() {
            let receipt = Value::Object(receipt.clone());
            require(
                receipt["binding"] == binding
                    && receipt["action"] == action
                    && receipt["payload_sha256"] == step["payload_sha256"]
                    && receipt["resource"] == resource,
                Failure::Ownership,
            )?;
            self.append(
                &step,
                json!({"type":"receiver","receipt":receipt,
                "transport":observed.transport}),
                true,
                receipt["completed_ms"].clone(),
            )
            .await?;
        }
        if settled {
            self.append(
                &step,
                json!({"type":"failure","failure":"readiness","outcome":"failed",
                    "completion_unknown":false,"cleanup_unknown":false}),
                false,
                Value::Null,
            )
            .await?;
            if let Some(mut child) = child {
                child.complete().map_err(|_| Failure::Timeout)?;
            }
            self.local.work(|store| store.verify()).await?;
            self.context.check()?;
            require(tokio::time::Instant::now() < deadline, Failure::Timeout)?;
            self.mode = Mode::SettlementOnly;
            self.next_step += 1;
            return Ok((step, result));
        }
        require(result["status"] == "ok", super::server::refused(&result))?;
        if mutation {
            require(
                result["terminal"]["outcome"] == "succeeded"
                    && result["terminal"]["effect"] == "complete"
                    && result["terminal"]["writer_ended"] == true,
                Failure::Readiness,
            )?;
            if let Some(mut child) = child {
                child.complete().map_err(|_| Failure::Timeout)?;
            }
        }
        if tag != "create-object" && !(replyless(family.name) && mutation) {
            let member = if hosts
                || tag == "inspect-storage"
                || family.name == "node"
                || family.name == "registry-replication" && super::registry_replication::host(tag)
            {
                self.members[index].clone()
            } else {
                Value::Null
            };
            let fact = if family.name == "cert-manager" {
                "images"
            } else {
                "image"
            };
            require(
                !matches!(tag, "import-image" | "import-images")
                    || if family.name == "registry-token" {
                        result["image"] == "ready"
                    } else {
                        result["hosts"]["member"] == member
                            && result["hosts"][fact]["state"] == "ready"
                    },
                Failure::Readiness,
            )?;
            self.append(
                &step,
                observation(family, member, &result),
                true,
                Value::Null,
            )
            .await?;
        }
        self.next_step += 1;
        Ok((step, result))
    }

    async fn network_run(&mut self, recipe: Value, repeat: bool) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = latest_sequence(self.local.snapshot()?, "network-recipe")?;
        let cluster = self.local.snapshot()?.request["cluster"].clone();
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
        let mut inspected = Vec::new();
        for &index in &order {
            let (_, result) = self
                .network_step(
                    index,
                    "inspect-host",
                    &recipe,
                    None,
                    None,
                    vec![recipe_seq.clone()],
                )
                .await?;
            require(
                result["hosts"]["member"] == self.members[index],
                Failure::Readiness,
            )?;
            inspected.push(result["hosts"].clone());
        }
        if let Some(refusal) = host_refusal(&inspected) {
            self.local.failure_detail = refusal;
            return Err(Failure::Readiness);
        }
        self.network_source_gate().await?;
        let (_, first) = self
            .network_step(
                0,
                "inspect-objects",
                &recipe,
                None,
                None,
                vec![recipe_seq.clone()],
            )
            .await?;
        checked_objects(self.local.snapshot()?, &first["objects"], repeat)?;
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
        let (_, mut observed) = self
            .network_step(
                0,
                "inspect-objects",
                &recipe,
                None,
                None,
                vec![recipe_seq.clone()],
            )
            .await?;
        checked_objects(self.local.snapshot()?, &observed["objects"], repeat)?;
        if !repeat {
            for ordinal in 1..=12 {
                let records = observed["objects"].clone();
                require(
                    records[ordinal - 1]["class"] == "absent",
                    Failure::Ownership,
                )?;
                let snapshot = self.local.snapshot()?;
                let mut refs = vec![
                    recipe_seq.clone(),
                    snapshot
                        .observations
                        .iter()
                        .rev()
                        .find(|o| {
                            o["event"]["type"] == "network-observation"
                                && !o["event"]["member"].is_null()
                        })
                        .map(|o| o["sequence"].clone())
                        .ok_or(Failure::Integrity)?,
                    latest_sequence(snapshot, "server-membership")?,
                ];
                if self.members.iter().any(|member| member["role"] == "agent") {
                    refs.push(latest_sequence(snapshot, "agent-membership")?);
                }
                refs.push(latest_sequence(snapshot, "network-observation")?);
                let request = snapshot.request.clone();
                let source_events = snapshot
                    .observations
                    .iter()
                    .filter(|o| {
                        matches!(
                            o["event"]["type"].as_str(),
                            Some("server-recipe" | "agent-join-recipe")
                        )
                    })
                    .map(|o| o["event"].clone())
                    .collect::<Vec<_>>();
                let mut cleanup = false;
                let mut detail = None;
                let checked = preflight(
                    &self.context,
                    &request,
                    self.attempt["attempt"].as_str().ok_or(Failure::Integrity)?,
                    self.attempt["steps"]
                        .as_array()
                        .and_then(|steps| steps.last())
                        .and_then(Value::as_u64)
                        .ok_or(Failure::Integrity)?,
                    &recipe,
                    &super::original_hash(self.local.snapshot()?, &recipe)?,
                    false,
                    &source_events,
                    Some(&records),
                    &mut cleanup,
                    &mut detail,
                )
                .await;
                self.local.cleanup_unknown |= cleanup;
                if checked.is_err() {
                    self.local.failure_detail = detail;
                }
                checked?;
                let (step, created) = self
                    .network_step(
                        0,
                        "create-object",
                        &recipe,
                        Some(ordinal),
                        Some(&records),
                        refs,
                    )
                    .await?;
                let uid = created["terminal"]["resource_identity"].clone();
                require(uid.is_string(), Failure::Integrity)?;
                let receipt = self
                    .inspect_step(0, "dispatch", step["dispatch"].clone(), Value::Null)
                    .await?;
                require(receipt["status"] == "ok", Failure::Ownership)?;
                let (_, next) = self
                    .network_step(
                        0,
                        "inspect-objects",
                        &recipe,
                        None,
                        None,
                        vec![recipe_seq.clone()],
                    )
                    .await?;
                require(
                    next["objects"][ordinal - 1]["uid"] == uid
                        && next["objects"][ordinal - 1]["class"] == "owned-ready",
                    Failure::Ownership,
                )?;
                let mut resource = self.local.snapshot()?.request["resources"][ordinal - 1].clone();
                resource["uid"] = uid;
                self.append(
                    &step,
                    json!({"type":"identity","member":null,"cluster":cluster,
                    "resources":[resource],"readiness":super::report::readiness()}),
                    false,
                    Value::Null,
                )
                .await?;
                let snapshot = self.local.snapshot()?;
                let mut owner = snapshot.owner.clone();
                owner["previous_generation"] = owner["generation"].clone();
                owner["generation"] = json!(fresh()?);
                owner["created_ms"] = json!(now()?);
                let resources = owner["resources"]
                    .as_array_mut()
                    .ok_or(Failure::Integrity)?;
                let found = resources
                    .iter_mut()
                    .find(|r| r["id"] == resource["id"])
                    .ok_or(Failure::Integrity)?;
                require(found["uid"].is_null(), Failure::Ownership)?;
                *found = resource;
                let operation = snapshot.request["operation"]
                    .as_str()
                    .ok_or(Failure::Integrity)?
                    .to_owned();
                self.local
                    .work(move |store| store.replace_owner(owner, &operation))
                    .await?;
                observed = next;
                checked_objects(self.local.snapshot()?, &observed["objects"], false)?;
            }
        }
        let (_, final_objects) = self
            .network_step(0, "inspect-objects", &recipe, None, None, vec![recipe_seq])
            .await?;
        checked_objects(self.local.snapshot()?, &final_objects["objects"], true)?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let mut session = begin(project, policy, target).await?;
    let recipe = session
        .local
        .snapshot()
        .map_err(super::ExecutionFailure::from)?
        .observations
        .iter()
        .find(|o| o["event"]["type"] == "network-recipe")
        .ok_or(Failure::Integrity)
        .map_err(super::ExecutionFailure::from)?["event"]["recipe"]
        .clone();
    let snapshot = session
        .local
        .snapshot()
        .map_err(super::ExecutionFailure::from)?;
    let repeat = snapshot.request["resources"]
        .as_array()
        .is_some_and(|items| items.iter().all(|r| r["uid"].is_string()));
    let (recipe, _) = super::derived_recipe(
        &recipe,
        &snapshot.request,
        &super::component_assets(snapshot),
    )?;
    let result = Box::pin(session.network_run(recipe, repeat)).await;
    session.local.complete(result, &session.context.clock).await
}

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Session<'a>> {
    let context = rpc::Context::new(project, policy, target)?;
    let mut local = Local::new(&context)?;
    let mut detail = None;
    let prepared: Result<_> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e|e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        super::replacement_window(&owner, "network-object-")?;
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()
                && v.iter().all(|m| m["node_uid"].is_string())), Failure::Ownership)?;
        for snapshot in &previous {
            let result = super::report::report(&context.scope,"show",std::slice::from_ref(snapshot))?;
            require(matches!(result["outcome"].as_str(), Some("succeeded" | "failed" | "cancelled"))
                && result["completion_unknown"] == false
                && result["cleanup_unknown"] == false, Failure::Busy)?;
        }
        context.authenticate_owned(&json!(super::survivors(&owner)?)).await?;
        let mut planned = owner["resources"].as_array().ok_or(Failure::Integrity)?
            .iter().filter(|r| r["id"].as_str().is_some_and(|id| id.starts_with("network-object-")))
            .cloned().collect::<Vec<_>>();
        let mut pending_owner = None;
        if planned.is_empty() {
            let mut successor = owner.clone();
            successor["previous_generation"] = successor["generation"].clone();
            successor["generation"] = json!(fresh()?);
            successor["created_ms"] = json!(now()?);
            for (index,(namespace,name)) in super::store::NETWORK_OBJECTS.iter().enumerate() {
                successor["resources"].as_array_mut().ok_or(Failure::Integrity)?.push(json!({
                    "kind":if index < 6 {"service"} else {"storage"},
                    "id":format!("network-object-{:02}",index+1),"owner":owner["owner"],
                    "generation":fresh()?,"machine":null,"path":null,
                    "namespace":namespace,"name":name,"uid":null}));
            }
            planned = successor["resources"].as_array().ok_or(Failure::Integrity)?
                .iter().filter(|r| r["id"].as_str().is_some_and(|id| id.starts_with("network-object-")))
                .cloned().collect();
            pending_owner = Some(successor);
        }
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        require(planned.len() == 12 && planned.iter().enumerate().all(|(index, r)| {
            let (namespace,name) = super::store::NETWORK_OBJECTS[index];
            r["id"] == format!("network-object-{:02}",index+1)
                && r["namespace"] == json!(namespace) && r["name"] == json!(name)
                && r["owner"] == current_owner["owner"]
        }), Failure::Ownership)?;
        let all_null = planned.iter().all(|r| r["uid"].is_null());
        let all_bound = planned.iter().all(|r| r["uid"].is_string());
        require(all_null || all_bound, Failure::Ownership)?;
        let operation = format!("infra-operation-{}",fresh()?);
        let attempt_id = fresh()?;
        let source_events = source_recipes(&previous,&context,&current_owner,&operation,&attempt_id)?;
        let created = now()?;
        let members = super::survivors(&current_owner)?;
        let participants = super::participants(&json!(members))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let mut survivors = current_owner.clone();
        survivors["members"] = json!(members);
        let original = if all_bound {
            let source = original_request(&previous, &planned, "reconcile-network")?;
            let recipe_event = source.observations.iter().find(|o| o["event"]["type"] == "network-recipe")
                .ok_or(Failure::Ownership)?;
            Some(recipe_event["event"]["recipe"].clone())
        } else { None };
        let network_recipe = if let Some(value) = original { value } else { recipe(&context,&survivors,&operation)? };
        let expected_recipe = recipe(&context,&survivors,
            network_recipe["operation"].as_str().ok_or(Failure::Integrity)?)?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-network",
            "members":members,"cluster":current_owner["cluster"],"resources":planned,
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let servers = members.iter().filter(|member| member["role"] == "server").count();
        let count = members.len().checked_mul(7)
            .and_then(|n| n.checked_add(servers.checked_mul(2)?))
            .and_then(|n| n.checked_add(if all_null {41} else {5}))
            .and_then(|n| n.checked_sub(if servers == members.len() {2} else {0}))
            .ok_or(Failure::Bound)?;
        require(count <= 943, Failure::Bound)?;
        let mut cleanup = false;
        let assets = super::replaced_assets(&previous, &context, &network_recipe, &members)?;
        let (sent, original) = super::derived_recipe(&network_recipe, &request, &assets)?;
        require(sent == expected_recipe, Failure::Ownership)?;
        let checked = preflight(&context, &request, &attempt_id, count as u64, &sent, &original,
            all_bound, &source_events, None, &mut cleanup, &mut detail).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_network(successor)).await?;
            require(local.snapshot()?.owner["resources"].as_array().is_some_and(|resources|
                resources.len() >= 12 && resources[resources.len()-12..] == planned), Failure::Ownership)?;
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
        for event in std::iter::once(json!({"type":"network-recipe","recipe":network_recipe}))
            .chain((!assets.is_empty()).then(|| json!({"type":"component-assets","entries":assets})))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members,attempt_id,count))
    }.await;
    let (members, attempt_id, _) = match prepared {
        Ok(value) => value,
        Err(failure) => {
            local.failure_detail = detail;
            return Err(local.failure(failure, &context.clock).await);
        }
    };
    let attempt = local
        .snapshot()?
        .attempts
        .iter()
        .find(|a| a["attempt"] == attempt_id)
        .ok_or(Failure::Integrity)?
        .clone();
    let generations = vec![0; members.len()];
    Ok(Session {
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
    })
}

