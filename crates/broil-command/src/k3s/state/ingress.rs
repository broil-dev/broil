// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::network::{self, Family};
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{INGRESS, INGRESS_TEMPLATE, PROFILE, protocol};
use broil_config::LoadedProject;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "ingress",
    protocol: "broil-k3s-ingress",
    magic: b"BK3SING1\n",
    header: "IngressHeader",
    result: "IngressResult",
    body: INGRESS,
    planned: INGRESS_OBJECTS.len(),
    reserve: network::FRAME_RESERVE,
    version: 1,
};

pub(super) const INGRESS_OBJECTS: [&str; 3] = ["traefik-crd", "traefik", "svclb-traefik"];

#[derive(Clone, Copy)]
enum Scope {
    Full,
    Import(usize),
}

fn effect(effect: broil_core::k3s::TaintEffect) -> &'static str {
    match effect {
        broil_core::k3s::TaintEffect::NoSchedule => "NoSchedule",
        broil_core::k3s::TaintEffect::PreferNoSchedule => "PreferNoSchedule",
        broil_core::k3s::TaintEffect::NoExecute => "NoExecute",
    }
}

fn render(api: &str, image: &str, names: &[&str], taints: &[(&str, &str, &str)]) -> Result<String> {
    let quoted = |value: &str| -> Result<String> {
        require(
            value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._/:=-".contains(&b)),
            Failure::Configuration,
        )?;
        Ok(format!("\"{value}\""))
    };
    let mut tolerations = String::new();
    for (key, value, effect) in taints {
        tolerations.push_str(&format!(
            "    - key: {}\n      operator: \"Equal\"\n      value: {}\n      effect: {}\n",
            quoted(key)?,
            quoted(value)?,
            quoted(effect)?
        ));
    }
    let charts = |name: &str| format!("/static/charts/{name}-40.1.4+up40.1.0.tgz");
    let sites = [
        (
            format!("https://%{{KUBERNETES_API}}%{}", charts("traefik-crd")),
            format!("https://{api}{}", charts("traefik-crd")),
        ),
        (
            format!("https://%{{KUBERNETES_API}}%{}", charts("traefik")),
            format!("https://{api}{}", charts("traefik")),
        ),
        ("\"%{SYSTEM_DEFAULT_REGISTRY_RAW}%\"".into(), "\"\"".into()),
        (
            "    deployment:\n      podAnnotations:\n".into(),
            "    deployment:\n      kind: \"DaemonSet\"\n      podAnnotations:\n".into(),
        ),
        (
            "      kubernetesIngress:\n        publishedService:\n".into(),
            "      kubernetesIngress:\n        ingressClass: \"traefik\"\n        publishedService:\n"
                .into(),
        ),
        (
            "    image:\n      repository: \"rancher/mirrored-library-traefik\"\n      tag: \"3.7.8\"\n"
                .into(),
            format!(
                "    image:\n      registry: \"docker.io\"\n      repository: \"library/traefik\"\n      digest: \"sha256:{image}\"\n"
            ),
        ),
        (
            "      effect: \"NoSchedule\"\n    service:\n".into(),
            format!("      effect: \"NoSchedule\"\n{tolerations}    service:\n"),
        ),
        (
            "      spec:\n        ipFamilyPolicy: \"PreferDualStack\"\n".into(),
            "      spec:\n        type: \"ClusterIP\"\n        ipFamilyPolicy: \"PreferDualStack\"\n"
                .into(),
        ),
    ];
    let pairs: Vec<(&str, &str)> = sites
        .iter()
        .map(|(site, value)| (site.as_str(), value.as_str()))
        .collect();
    let source = std::str::from_utf8(INGRESS_TEMPLATE).map_err(|_| Failure::Integrity)?;
    let mut text = String::from_utf8(network::replaced(source.into(), &pairs)?)
        .map_err(|_| Failure::Integrity)?;
    require(text.ends_with("\"PreferDualStack\"\n"), Failure::Integrity)?;
    text.push_str(
        "    versionOverride: \"v3.7.13\"\n    affinity:\n      nodeAffinity:\n        \
         requiredDuringSchedulingIgnoredDuringExecution:\n          nodeSelectorTerms:\n          \
         - matchExpressions:\n            - key: \"kubernetes.io/hostname\"\n              \
         operator: \"In\"\n              values:\n",
    );
    for name in names {
        text.push_str(&format!("              - {}\n", quoted(name)?));
    }
    text.push_str("    ingressClass:\n      enabled: true\n      isDefaultClass: false\n");
    Ok(text)
}

fn servicelb(klipper: &str, names: &[&str], taints: &[(&str, &str, &str)]) -> Value {
    let mut tolerations = vec![
        json!({"key":"CriticalAddonsOnly","operator":"Exists"}),
        json!({"key":"node-role.kubernetes.io/control-plane","operator":"Exists","effect":"NoSchedule"}),
    ];
    for (key, value, effect) in taints {
        let mut toleration = json!({"key":key,"operator":"Equal","effect":effect});
        if !value.is_empty() {
            toleration["value"] = json!(value);
        }
        tolerations.push(toleration);
    }
    let containers: Vec<Value> = [80, 443]
        .iter()
        .map(|port| {
            json!({"name":format!("lb-tcp-{port}"),
                "image":format!("docker.io/rancher/klipper-lb@sha256:{klipper}"),
                "imagePullPolicy":"Never",
                "ports":[{"name":format!("lb-tcp-{port}"),"containerPort":port,"hostPort":port,
                    "protocol":"TCP"}],
                "env":[{"name":"SRC_PORT","value":port.to_string()},
                    {"name":"SRC_RANGES","value":"0.0.0.0/0"},{"name":"DEST_PROTO","value":"TCP"},
                    {"name":"DEST_PORT","value":port.to_string()},
                    {"name":"DEST_IPS","value":"$(TRAEFIK_SERVICE_HOST)"}],
                "securityContext":{"capabilities":{"add":["NET_ADMIN"]}}})
        })
        .collect();
    let labels = json!({"app":INGRESS_OBJECTS[2]});
    json!({"apiVersion":"apps/v1","kind":"DaemonSet",
        "metadata":{"name":INGRESS_OBJECTS[2],"namespace":"kube-system","labels":labels},
        "spec":{"selector":{"matchLabels":labels},"template":{"metadata":{"labels":labels},"spec":{
            "priorityClassName":"system-node-critical","serviceAccountName":"default",
            "automountServiceAccountToken":false,"enableServiceLinks":true,
            "affinity":{"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{
                "nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/hostname",
                    "operator":"In","values":names}]}]}}},
            "tolerations":tolerations,"containers":containers}}}})
}

fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    entries: &[Value],
) -> Result<Value> {
    let selected = context.selected.declaration;
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let cidr = selected.network.service_cidr;
    require(cidr.prefix <= 30, Failure::Configuration)?;
    let api = format!(
        "{}:443",
        std::net::Ipv4Addr::from(u32::from(cidr.network) + 1)
    );
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let mut names = Vec::new();
    let mut taints = Vec::new();
    for member in members
        .iter()
        .filter(|m| entries.iter().any(|e| e["machine"] == m["machine"]))
    {
        names.push(member["member"].as_str().ok_or(Failure::Integrity)?);
        let declared = context
            .selected
            .members
            .iter()
            .find(|m| m.declaration.machine == member["machine"])
            .ok_or(Failure::Configuration)?
            .declaration;
        for taint in &declared.taints {
            taints.push((
                taint.key.as_str(),
                taint.value.as_str(),
                effect(taint.effect),
            ));
        }
    }
    taints.sort_by(|a, b| {
        (a.0.as_bytes(), a.1.as_bytes(), a.2.as_bytes()).cmp(&(
            b.0.as_bytes(),
            b.1.as_bytes(),
            b.2.as_bytes(),
        ))
    });
    taints.dedup();
    let image = profile["ingress_images"]["traefik"]
        .as_str()
        .ok_or(Failure::Configuration)?;
    let klipper = profile["ingress_images"]["klipper_lb"]
        .as_str()
        .ok_or(Failure::Configuration)?;
    let rendered = render(&api, image, &names, &taints)?;
    let workload = canonical(&servicelb(klipper, &names, &taints))?;
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"members":members,"first_server":members[0],
        "ingress_members":entries,"version":selected.version,
        "network":{"service_cidr":format!("{}/{}", cidr.network, cidr.prefix),"api":api},
        "profile_sha256":context.fingerprints["profile_sha256"],
        "template_sha256":profile["ingress_templates"]["traefik"],
        "render_sha256":protocol::digest(rendered.as_bytes()),
        "servicelb_sha256":protocol::digest(&workload)});
    schema::validate(&canonical(&recipe)?, "IngressRecipe", 32_768)?;
    Ok(recipe)
}

fn succeeded(context: &rpc::Context<'_>, snapshot: &Snapshot) -> bool {
    super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        .is_ok_and(|report| report["outcome"] == "succeeded")
}

fn ingress_members(
    previous: &[Snapshot],
    context: &rpc::Context<'_>,
    owner: &Value,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let declared = &context.selected.declaration.infrastructure.ingress_members;
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let removed = |name: &String| {
        owner["removed"]
            .as_array()
            .is_some_and(|r| r.iter().any(|r| r["member"] == *name))
    };
    require(
        !declared.is_empty()
            && declared
                .iter()
                .all(|name| members.iter().any(|m| m["member"] == *name) || removed(name)),
        Failure::Configuration,
    )?;
    generations(
        previous,
        context,
        members
            .iter()
            .filter(|m| declared.iter().any(|name| m["member"] == *name)),
    )
}

pub(super) fn generations<'m>(
    previous: &[Snapshot],
    context: &rpc::Context<'_>,
    selected: impl Iterator<Item = &'m Value>,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut entries = Vec::new();
    let mut resources = Vec::new();
    for member in selected {
        let consumed = super::current_installation(
            previous
                .iter()
                .filter(|s| {
                    matches!(
                        s.request["action"].as_str(),
                        Some("create-server" | "join-server" | "join-agent")
                    ) && succeeded(context, s)
                })
                .flat_map(|s| s.observations.iter().map(move |o| (s, o)))
                .filter(|(_, o)| {
                    matches!(
                        o["event"]["type"].as_str(),
                        Some("lifecycle-recipe" | "server-join-recipe" | "agent-join-recipe")
                    ) && o["event"]["recipe"]["member"]["machine"] == member["machine"]
                        && o["event"]["recipe"]["member"]["node_uid"].is_null()
                }),
        )?;
        let assets = &consumed["event"]["recipe"]["assets"];
        let prepared: Vec<&Value> = previous
            .iter()
            .filter(|s| s.request["action"] == "prepare-hosts" && succeeded(context, s))
            .flat_map(|s| &s.observations)
            .filter(|o| {
                o["event"]["type"] == "bootstrap-generation"
                    && o["source"]["machine"] == member["machine"]
                    && !o["event"]["marker"].is_null()
                    && o["event"]["resource"]["generation"] == assets["generation"]
            })
            .collect();
        require(!prepared.is_empty(), Failure::Readiness)?;
        for event in &prepared {
            require(
                assets["marker_sha256"] == protocol::digest(&canonical(&event["event"]["marker"])?)
                    && event["event"]["resource"] == prepared[0]["event"]["resource"],
                Failure::Ownership,
            )?;
        }
        entries.push(
            json!({"machine":member["machine"],"generation":assets["generation"],
            "marker_sha256":assets["marker_sha256"]}),
        );
        resources.push(prepared[0]["event"]["resource"].clone());
    }
    Ok((entries, resources))
}

fn chart(index: usize) -> usize {
    match index {
        0..=4 | 10 | 12..=44 => 0,
        _ => 1,
    }
}

fn positions(recipe: &Value) -> Result<Vec<u64>> {
    let entries = recipe["ingress_members"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    Ok(recipe["members"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .zip(1u64..)
        .filter(|(m, _)| entries.iter().any(|e| e["machine"] == m["machine"]))
        .map(|(_, position)| position)
        .collect())
}

fn progress(earlier: &Value, current: &Value, created: usize) -> Result<()> {
    let records = |value: &Value, key: &str| -> Result<Vec<Value>> {
        Ok(value[key].as_array().ok_or(Failure::Integrity)?.clone())
    };
    let admitted = |new: &Value| matches!(new["class"].as_str(), Some("absent" | "owned-ready"));
    let (old, new) = (records(earlier, "objects")?, records(current, "objects")?);
    require(old.len() == 3 && new.len() == 3, Failure::Integrity)?;
    for (old, new) in old.iter().zip(&new) {
        require(admitted(new), Failure::Ownership)?;
        require(
            old == new
                || old["class"] == "owned-ready"
                    && new["class"] == "owned-ready"
                    && ["kind", "namespace", "name", "uid", "spec_sha256"]
                        .iter()
                        .all(|key| old[*key] == new[*key]),
            Failure::Ownership,
        )?;
    }
    let (old, new) = (records(earlier, "results")?, records(current, "results")?);
    require(old.len() == 51 && new.len() == 51, Failure::Integrity)?;
    for (index, (old, new)) in old.iter().zip(&new).enumerate() {
        require(
            admitted(new) && (chart(index) < created || new["class"] == "absent"),
            Failure::Ownership,
        )?;
        require(
            old == new
                || chart(index) < created
                    && (old["class"] == "absent" && new["class"] == "owned-ready"
                        || old["class"] == "owned-ready"
                            && new["class"] == "owned-ready"
                            && old["uid"] == new["uid"]),
            Failure::Ownership,
        )?;
    }
    Ok(())
}

fn admit_objects(
    result: &Value,
    request: &Value,
    recipe: &Value,
    repeat: bool,
    prior: Option<(&Value, usize)>,
) -> Result<()> {
    require(
        result["ingress"]["api"]["state"] == "ready",
        Failure::Configuration,
    )?;
    let ingress = positions(recipe)?;
    let cordoned = result["ingress"]["cordoned"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    for position in cordoned {
        require(
            position.as_u64().is_some_and(|p| ingress.contains(&p)),
            Failure::Ownership,
        )?;
    }
    require(cordoned.is_empty(), Failure::Readiness)?;
    require(
        result["ingress"]["host_ports"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && result["ingress"]["selector"]["state"] == "ready",
        Failure::Ownership,
    )?;
    let objects = result["objects"].as_array().ok_or(Failure::Integrity)?;
    let results = result["results"].as_array().ok_or(Failure::Integrity)?;
    let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
    let charts = resources
        .get(resources.len().saturating_sub(INGRESS_OBJECTS.len())..)
        .ok_or(Failure::Integrity)?;
    require(
        objects.len() == INGRESS_OBJECTS.len()
            && results.len() == 51
            && objects
                .iter()
                .zip(charts)
                .all(|(o, r)| o["name"] == r["name"] && o["namespace"] == r["namespace"]),
        Failure::Ownership,
    )?;
    match prior {
        Some((earlier, created)) => progress(earlier, result, created),
        None if repeat => require(
            objects
                .iter()
                .zip(charts)
                .all(|(o, r)| o["class"] == "owned-ready" && o["uid"] == r["uid"])
                && results
                    .iter()
                    .all(|r| matches!(r["class"].as_str(), Some("absent" | "owned-ready"))),
            Failure::Ownership,
        ),
        None => require(
            objects
                .iter()
                .chain(results)
                .all(|r| r["class"] == "absent" && r["uid"].is_null()),
            Failure::Ownership,
        ),
    }
}

fn admit_listeners(hosts: &Value, ingress: bool) -> Result<()> {
    require(
        !ingress || hosts["listeners"]["state"] == "ready",
        Failure::Ownership,
    )
}

fn admit_host(hosts: &Value, member: &Value, server: bool, ingress: bool) -> Result<()> {
    require(hosts["member"] == *member, Failure::Integrity)?;
    admit_listeners(hosts, ingress)?;
    let ready = |key: &str| hosts[key]["state"] == "ready";
    require(
        (!server || ready("charts"))
            && (!ingress
                || ["generation", "runtime", "lb_image", "forwarding"]
                    .iter()
                    .all(|key| ready(key))),
        Failure::Readiness,
    )
}

fn latest_objects(snapshot: &Snapshot) -> Option<&Value> {
    snapshot
        .observations
        .iter()
        .rev()
        .find(|o| o["event"]["type"] == "ingress-observation" && o["event"]["member"].is_null())
        .map(|o| &o["event"])
}

fn latest_host<'s>(snapshot: &'s Snapshot, member: &Value) -> Option<&'s Value> {
    snapshot
        .observations
        .iter()
        .rev()
        .find(|o| o["event"]["type"] == "ingress-observation" && o["event"]["member"] == *member)
        .map(|o| &o["event"]["hosts"])
}

fn hosts(members: &[Value], entries: &[Value], scope: Scope) -> Vec<usize> {
    let ingress = |m: &Value| entries.iter().any(|e| e["machine"] == m["machine"]);
    members
        .iter()
        .enumerate()
        .filter(|&(index, m)| match scope {
            Scope::Full => m["role"] == "server" || ingress(m),
            Scope::Import(selected) => index == selected,
        })
        .map(|(index, _)| index)
        .collect()
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
    durable: Option<(&Snapshot, usize)>,
    imports: &[Value],
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
    let payload = json!({"recipe":recipe,"original_recipe_sha256":original,"object_ordinal":null,
        "resource":null,"preflight":null});
    let observed = network::invoke(
        context,
        &FAMILY,
        &binding(0)?,
        "inspect-objects",
        &payload,
        deadline(),
        None,
    )
    .await;
    *cleanup |= network::unclean(&observed.transport);
    let result = observed
        .response
        .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
    require(result["status"] == "ok", super::server::refused(&result))?;
    let prior = match durable {
        Some((snapshot, created)) => {
            Some((latest_objects(snapshot).ok_or(Failure::Integrity)?, created))
        }
        None => None,
    };
    admit_objects(&result, request, recipe, repeat, prior)?;
    network::membership_reads(context, request, attempt, last, source_events, cleanup).await?;
    let entries = recipe["ingress_members"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    for index in hosts(members, entries, scope) {
        let member = &members[index];
        let server = member["role"] == "server";
        let ingress = entries.iter().any(|e| e["machine"] == member["machine"]);
        let observed = network::invoke(
            context,
            &FAMILY,
            &binding(index)?,
            "inspect-host",
            &payload,
            deadline(),
            None,
        )
        .await;
        *cleanup |= network::unclean(&observed.transport);
        let result = observed
            .response
            .ok_or(observed.failure.unwrap_or(Failure::Transport))?;
        require(result["status"] == "ok", super::server::refused(&result))?;
        admit_reply(
            &result["hosts"],
            durable.and_then(|(snapshot, _)| latest_host(snapshot, member)),
            member,
            server,
            ingress,
        )?;
        imported +=
            usize::from(imports.contains(&member["machine"]) && !ready_image(&result["hosts"]));
    }
    Ok(imported)
}

fn ready_image(hosts: &Value) -> bool {
    hosts["image"]["state"] == "ready"
}

fn admit_reply(
    hosts: &Value,
    durable: Option<&Value>,
    member: &Value,
    server: bool,
    ingress: bool,
) -> Result<()> {
    admit_listeners(hosts, ingress)?;
    match durable {
        Some(facts) => require(hosts == facts, Failure::Readiness),
        None => admit_host(hosts, member, server, ingress),
    }
}

fn step_count(members: &[Value], entries: &[Value], repeat: bool) -> Result<usize> {
    let servers = members.iter().filter(|m| m["role"] == "server").count();
    let hosts = members
        .iter()
        .filter(|m| m["role"] == "server" || entries.iter().any(|e| e["machine"] == m["machine"]))
        .count();
    let (per, fixed) = if repeat {
        (hosts + servers * 2, 5)
    } else {
        (entries.len() + servers * 3, 14)
    };
    members
        .len()
        .checked_mul(6)
        .and_then(|n| n.checked_add(per))
        .and_then(|n| n.checked_add(fixed))
        .and_then(|n| n.checked_sub(if servers == members.len() { 2 } else { 0 }))
        .filter(|n| *n <= 1024)
        .ok_or(Failure::Bound)
}

fn unchanged(original: &Value, expected: &Value) -> Result<()> {
    require(original == expected, Failure::Configuration)
}

fn charts(owner: &Value) -> Result<Vec<Value>> {
    let planned: Vec<Value> = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| {
            r["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("ingress-object-"))
        })
        .cloned()
        .collect();
    require(
        planned.is_empty()
            || planned.len() == INGRESS_OBJECTS.len()
                && planned.iter().enumerate().all(|(index, r)| {
                    r["id"] == format!("ingress-object-{:02}", index + 1)
                        && r["kind"] == "service"
                        && r["namespace"] == "kube-system"
                        && r["name"] == INGRESS_OBJECTS[index]
                        && r["owner"] == owner["owner"]
                })
                && (planned.iter().all(|r| r["uid"].is_null())
                    || planned.iter().all(|r| r["uid"].is_string())),
        Failure::Ownership,
    )?;
    Ok(planned)
}

pub(super) async fn publish(local: &mut Local, published: &Value) -> Result<()> {
    let snapshot = local.snapshot()?;
    let mut owner = snapshot.owner.clone();
    owner["previous_generation"] = owner["generation"].clone();
    owner["generation"] = json!(fresh()?);
    owner["created_ms"] = json!(now()?);
    let found = owner["resources"]
        .as_array_mut()
        .ok_or(Failure::Integrity)?
        .iter_mut()
        .find(|r| r["id"] == published["id"])
        .ok_or(Failure::Ownership)?;
    require(found["uid"].is_null(), Failure::Ownership)?;
    *found = published.clone();
    let operation = snapshot.request["operation"]
        .as_str()
        .ok_or(Failure::Integrity)?
        .to_owned();
    local
        .work(move |store| store.replace_owner(owner, &operation))
        .await
}

impl Session<'_> {
    async fn ingress_preflight(
        &mut self,
        recipe: &Value,
        created: usize,
        repeat: bool,
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
            repeat,
            &source_events,
            Some((&snapshot, created)),
            &[],
            scope,
            &mut cleanup,
        )
        .await;
        self.local.cleanup_unknown |= cleanup;
        checked.map(drop)
    }

    async fn ingress_run(&mut self, recipe: Value, repeat: bool) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, "ingress-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let entries = recipe["ingress_members"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let ingress = |member: &Value| entries.iter().any(|e| e["machine"] == member["machine"]);
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
        for index in 0..self.members.len() {
            let member = self.members[index].clone();
            let server = member["role"] == "server";
            if !(server || repeat && ingress(&member)) {
                continue;
            }
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
            admit_host(&result["hosts"], &member, server, ingress(&member))?;
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
        admit_objects(&first, &request, &recipe, repeat, None)?;
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
        let (_, second) = self
            .network_step(
                0,
                "inspect-objects",
                &recipe,
                None,
                None,
                vec![recipe_seq.clone()],
            )
            .await?;
        admit_objects(&second, &request, &recipe, repeat, None)?;
        if repeat {
            let imports: Vec<Value> = super::component_assets(self.local.snapshot()?)
                .iter()
                .map(|a| a["machine"].clone())
                .collect();
            let mut selected = Vec::new();
            for (index, member) in self.members.iter().enumerate() {
                let absent = latest_host(self.local.snapshot()?, member)
                    .is_some_and(|hosts| !ready_image(hosts));
                if ingress(member) && imports.contains(&member["machine"]) && absent {
                    selected.push(index);
                }
            }
            let admitted = self.attempt["steps"]
                .as_array()
                .map_or(0, Vec::len)
                .checked_sub(step_count(&self.members, &entries, true)?)
                .ok_or(Failure::Integrity)?;
            require(admitted == 2 * selected.len(), Failure::Readiness)?;
            for index in selected {
                let member = self.members[index].clone();
                self.ingress_preflight(&recipe, INGRESS_OBJECTS.len(), true, Scope::Import(index))
                    .await?;
                self.network_step(
                    index,
                    "import-image",
                    &recipe,
                    None,
                    None,
                    vec![recipe_seq.clone()],
                )
                .await?;
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
                admit_host(&result["hosts"], &member, member["role"] == "server", true)?;
            }
        }
        if !repeat {
            for index in 0..self.members.len() {
                if !ingress(&self.members[index]) {
                    continue;
                }
                self.ingress_preflight(&recipe, 0, false, Scope::Import(index))
                    .await?;
                self.network_step(
                    index,
                    "import-image",
                    &recipe,
                    None,
                    None,
                    vec![recipe_seq.clone()],
                )
                .await?;
            }
            for ordinal in 1..=INGRESS_OBJECTS.len() {
                self.ingress_preflight(&recipe, ordinal - 1, false, Scope::Full)
                    .await?;
                let snapshot = self.local.snapshot()?;
                let latest = latest_objects(snapshot).ok_or(Failure::Integrity)?;
                require(
                    latest["objects"][ordinal - 1]["class"] == "absent",
                    Failure::Ownership,
                )?;
                let preflight = json!({"objects":latest["objects"],"results":latest["results"]});
                let mut refs = vec![
                    recipe_seq.clone(),
                    network::latest_sequence(snapshot, "server-membership")?,
                ];
                if self.members.iter().any(|member| member["role"] == "agent") {
                    refs.push(network::latest_sequence(snapshot, "agent-membership")?);
                }
                refs.push(
                    snapshot
                        .observations
                        .iter()
                        .rev()
                        .find(|o| {
                            o["event"]["type"] == "ingress-observation"
                                && o["event"]["member"].is_null()
                        })
                        .map(|o| o["sequence"].clone())
                        .ok_or(Failure::Integrity)?,
                );
                let (step, created) = self
                    .network_step(
                        0,
                        "create-object",
                        &recipe,
                        Some(ordinal),
                        Some(&preflight),
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
                let mut resource = step["resource"].clone();
                resource["uid"] = uid;
                self.append(
                    &step,
                    json!({"type":"identity","member":null,"cluster":cluster,
                    "resources":[resource],"readiness":super::report::readiness()}),
                    false,
                    Value::Null,
                )
                .await?;
                publish(&mut self.local, &resource).await?;
            }
        }
        let (_, last) = self
            .network_step(0, "inspect-objects", &recipe, None, None, vec![recipe_seq])
            .await?;
        let owned = self.local.snapshot()?.owner["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .filter(|r| {
                r["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("ingress-object-"))
            })
            .cloned()
            .collect::<Vec<_>>();
        require(
            owned.len() == INGRESS_OBJECTS.len()
                && last["objects"].as_array().is_some_and(|objects| {
                    objects
                        .iter()
                        .zip(&owned)
                        .all(|(o, r)| o["class"] == "owned-ready" && o["uid"] == r["uid"])
                })
                && last["results"].as_array().is_some_and(|results| {
                    results
                        .iter()
                        .all(|r| matches!(r["class"].as_str(), Some("absent" | "owned-ready")))
                }),
            Failure::Ownership,
        )?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let (mut session, recipe, repeat) = begin(project, policy, target).await?;
    let result = Box::pin(session.ingress_run(recipe, repeat)).await;
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
        super::replacement_window(&owner, "ingress-object-")?;
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
        let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
        let bound = |prefix: &str| resources.iter()
            .filter(|r| r["id"].as_str().is_some_and(|id| id.starts_with(prefix)))
            .cloned().collect::<Vec<_>>();
        let baseline = bound("network-object-");
        require(baseline.len() == 12 && baseline.iter().all(|r| r["uid"].is_string()), Failure::Ownership)?;
        network::original_request(&previous, &baseline, "reconcile-network")?;
        context.authenticate_owned(&json!(super::survivors(&owner)?)).await?;
        let mut planned = charts(&owner)?;
        let mut pending_owner = None;
        if planned.is_empty() {
            let mut successor = owner.clone();
            successor["previous_generation"] = successor["generation"].clone();
            successor["generation"] = json!(fresh()?);
            successor["created_ms"] = json!(now()?);
            for (index, name) in INGRESS_OBJECTS.iter().enumerate() {
                successor["resources"].as_array_mut().ok_or(Failure::Integrity)?.push(json!({
                    "kind":"service","id":format!("ingress-object-{:02}",index+1),"owner":owner["owner"],
                    "generation":fresh()?,"machine":null,"path":null,
                    "namespace":"kube-system","name":name,"uid":null}));
            }
            planned = charts(&successor)?;
            pending_owner = Some(successor);
        }
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        require(planned.len() == INGRESS_OBJECTS.len(), Failure::Ownership)?;
        let all_bound = planned.iter().all(|r| r["uid"].is_string());
        let operation = format!("infra-operation-{}",fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous,&context,&current_owner,&operation,&attempt_id)?;
        let members = super::survivors(&current_owner)?;
        let mut survivors = current_owner.clone();
        survivors["members"] = json!(members);
        let (entries, assets) = ingress_members(&previous, &context, &survivors)?;
        let created = now()?;
        let participants = super::participants(&json!(members))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let ingress_recipe = if all_bound {
            let source = network::original_request(&previous, &planned, "reconcile-ingress")?;
            source.observations.iter().find(|o| o["event"]["type"] == "ingress-recipe")
                .ok_or(Failure::Ownership)?["event"]["recipe"].clone()
        } else {
            recipe(&context, &survivors, &operation, &entries)?
        };
        let expected = recipe(&context, &survivors,
            ingress_recipe["operation"].as_str().ok_or(Failure::Integrity)?, &entries)?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-ingress",
            "members":members,"cluster":current_owner["cluster"],
            "resources":assets.into_iter().chain(planned.iter().cloned()).collect::<Vec<_>>(),
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let assets = super::replaced_assets(&previous, &context, &ingress_recipe, &members)?;
        let (sent, original) = super::derived_recipe(&ingress_recipe, &request, &assets)?;
        unchanged(&sent, &expected)?;
        let imports: Vec<Value> = if all_bound {
            assets.iter().map(|a| a["machine"].clone())
                .filter(|machine| entries.iter().any(|e| e["machine"] == *machine)).collect()
        } else {
            Vec::new()
        };
        let count = step_count(&members, &entries, all_bound)? + 2 * imports.len();
        require(count <= 1024, Failure::Bound)?;
        let mut cleanup = false;
        let checked = preflight(&context, &request, &attempt_id, count as u64, &sent, &original,
            all_bound, &source_events, None, &imports, Scope::Full, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        let count = step_count(&members, &entries, all_bound)? + 2 * checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_ingress(successor)).await?;
            let count = INGRESS_OBJECTS.len();
            require(local.snapshot()?.owner["resources"].as_array().is_some_and(|resources|
                resources.len() >= count && resources[resources.len()-count..] == planned), Failure::Ownership)?;
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
        for event in std::iter::once(json!({"type":"ingress-recipe","recipe":ingress_recipe}))
            .chain((!assets.is_empty()).then(|| json!({"type":"component-assets","entries":assets})))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok((members, attempt_id, sent, all_bound))
    }.await;
    let (members, attempt_id, ingress_recipe, repeat) = match prepared {
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
        ingress_recipe,
        repeat,
    ))
}

