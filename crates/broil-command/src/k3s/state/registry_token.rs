// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::issuer;
use super::network::{self, Family};
use super::registry_auth as auth;
use super::registry_endpoint as endpoint;
use super::registry_service as service;
use super::registry_storage as storage;
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{PROFILE, REGISTRY, protocol};
use broil_config::LoadedProject;
use broil_config::images::select::EffectiveRegistry;
use broil_core::images::reference::ImageReference;
use broil_core::images::{RegistryCredential, RegistryPurpose};
use broil_core::k3s::{Infrastructure, ManagedRegistry, PrincipalPurpose};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

pub(super) const FAMILY: Family = Family {
    name: "registry-token",
    protocol: "broil-k3s-registry-token",
    magic: b"BK3SRTK2\n",
    header: "RegistryTokenHeader",
    result: "RegistryTokenResult",
    body: REGISTRY,
    planned: 5,
    reserve: 16_384,
    version: 2,
};

const BASE: &str = "version: 0.1\nlog:\n  level: error\nstorage:\n  filesystem:\n    \
    rootdirectory: /data\n  delete:\n    enabled: false\n  maintenance:\n    uploadpurging:\n      \
    enabled: false\nhttp:\n  addr: \":5000\"\n";

pub(super) fn action(tag: &str) -> String {
    format!("lifecycle:registry-token-{tag}")
}

pub(super) struct Declared {
    pub(super) pem: String,
    pub(super) sha256: String,
    pub(super) key: Vec<u8>,
}

pub(super) fn certificate(bytes: &[u8]) -> Result<Declared> {
    let mut blocks = endpoint::certificate_blocks(bytes)?;
    require(blocks.len() == 1, Failure::Configuration)?;
    let pem = blocks.remove(0);
    let key = crate::k3s::certificate_key(&pem).map_err(|_| Failure::Configuration)?;
    Ok(Declared {
        sha256: protocol::digest(format!("{pem}\n").as_bytes()),
        pem,
        key,
    })
}

fn resolved(root: &Path, declared: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for part in root.join(declared).components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                path.pop();
            }
            part => path.push(part),
        }
    }
    path
}

pub(super) fn token(entry: &EffectiveRegistry) -> Result<Value> {
    let Some(RegistryCredential::Password {
        token_service: Some(token),
        ..
    }) = entry
        .declaration
        .auth
        .get(&RegistryPurpose::Push)
        .map(|auth| &auth.credential)
    else {
        return Err(Failure::Configuration);
    };
    let path = token.realm.path.as_str();
    require(
        matches!(path, "/auth" | "/auth/token") && !token.service.contains(['"', '\\']),
        Failure::Configuration,
    )?;
    Ok(
        json!({"realm":token.realm.supplied,"path":path,"service":token.service,
        "issuer":"broil-registry-token"}),
    )
}

pub(super) fn gates(
    root: &Path,
    registry: Option<&ManagedRegistry>,
    infrastructure: &Infrastructure,
    registries: &BTreeMap<String, EffectiveRegistry>,
    profile: &Value,
) -> Result<(ManagedRegistry, Value, Value, Value, Declared)> {
    let (registry, endpoint, trust) =
        endpoint::gates(registry, infrastructure, registries, profile)?;
    auth::gates(Some(&registry), infrastructure)?;
    let path = registry
        .authentication
        .signing_certificate
        .as_deref()
        .ok_or(Failure::Configuration)?;
    let bytes = crate::k3s::read_ca(&resolved(root, path), 8_192)
        .map_err(|_| Failure::Configuration)?
        .ok_or(Failure::Configuration)?;
    let declared = certificate(&bytes)?;
    let entry = registries
        .get(&registry.endpoint)
        .ok_or(Failure::Configuration)?;
    let token = token(entry)?;
    Ok((registry, endpoint, trust, token, declared))
}

pub(super) fn stage(origins: &Value, declared: &str, principals: &Value) -> Result<&'static str> {
    let (certificate, switch) = (&origins["certificate"], &origins["switch"]);
    match origins["objects"].as_array() {
        None if certificate.is_null() && switch.is_null() => Ok("create"),
        Some(objects) if objects.len() == 5 && certificate.is_object() => {
            Ok(if certificate["sha256"] != declared {
                "configure"
            } else if switch["certificate_sha256"] == declared {
                if principals.is_null()
                    || *principals == installed(principals, &origins["principals"])
                {
                    "observe"
                } else {
                    "principals"
                }
            } else {
                "switch"
            })
        }
        _ => Err(Failure::Ownership),
    }
}

pub(super) fn effects(stage: &str) -> usize {
    match stage {
        "create" => 5,
        "configure" | "switch" | "principals" => 1,
        _ => 0,
    }
}

pub(super) fn budgets(
    stage: &str,
    step: u64,
    storage_script: u64,
    first_script: u64,
    remaining: u64,
    n: u64,
    replicas: u64,
) -> Result<()> {
    let child = step.min(storage_script).min(first_script);
    let (reads, verify) = match (stage, n) {
        ("create" | "observe", _) | (_, 0) => (0, 0),
        ("configure", _) => (3, n),
        ("switch", _) => (2, n),
        _ => (3, 2 * n),
    };
    let evictions = match stage {
        "configure" | "principals" => 20 * replicas.saturating_sub(1),
        _ => 0,
    };
    match stage {
        "create" => service::budgets(1, 4, step, storage_script, first_script, remaining),
        "configure" | "switch" | "principals" => require(
            child >= 70 + 2 * reads + verify + evictions
                && remaining >= (10 + reads) * 20 + 2 * 30 + verify + evictions,
            Failure::Bound,
        ),
        _ => Ok(()),
    }
}

pub(super) fn item7(
    stage: &str,
    owner: &Value,
    step: u64,
    script: u64,
    remaining: u64,
    n: u64,
) -> Result<()> {
    let replicas = super::survivors(owner)?.len() as u64;
    budgets(stage, step, script, script, remaining, n, replicas)
}

pub(super) fn configuration_sha256(recipe: &Value) -> Result<String> {
    let quoted = |value: &Value| {
        serde_json::to_string(value.as_str().ok_or(Failure::Integrity)?)
            .map_err(|_| Failure::Integrity)
    };
    let pem = recipe["certificate"]["pem"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    let config = format!(
        "{BASE}auth:\n  token:\n    realm: {}\n    service: {}\n    issuer: \
         \"broil-registry-token\"\n    rootcertbundle: /config/token.crt\n",
        quoted(&recipe["token"]["realm"])?,
        quoted(&recipe["token"]["service"])?
    );
    hash(
        "broil-k3s-registry-service-object-v1",
        &json!({"data":{"config.yml":config,"token.crt":format!("{pem}\n")},
            "binaryData":null,"immutable":null}),
    )
}

fn latest<'s>(previous: &'s [Snapshot], tag: &str) -> Option<(&'s Snapshot, &'s Value)> {
    let action = action(tag);
    previous
        .iter()
        .filter(|s| s.request["action"] == "reconcile-registry-token")
        .flat_map(|s| {
            s.steps
                .iter()
                .filter(|step| step["action"] == action.as_str() && s.succeeded(step))
                .map(move |step| (s, step))
        })
        .max_by_key(|(s, _)| s.request["created_ms"].as_u64())
}

fn proved(
    snapshot: &Snapshot,
    step: &Value,
    uid: &Value,
    check: impl Fn(&Value) -> bool,
) -> Result<()> {
    let receipt = issuer::recorded(snapshot, step, "receiver")?;
    require(
        uid.is_string()
            && receipt["event"]["receipt"]["resource_identity"] == *uid
            && service::reads_after("registry-token", snapshot, &receipt["sequence"])
                .any(|o| check(&o["event"])),
        Failure::Ownership,
    )
}

pub(super) fn switch_origin(previous: &[Snapshot], configmap: &Value) -> Result<Value> {
    let Some((snapshot, step)) = latest(previous, "switch-registry") else {
        return Ok(Value::Null);
    };
    let recipe = service::recipe_of("registry-token", snapshot)?;
    let configuration = configuration_sha256(recipe)?;
    proved(snapshot, step, &configmap["uid"], |event| {
        event["registry"]["configmap"] == "switched"
            && event["registry"]["configuration_sha256"] == configuration.as_str()
    })?;
    Ok(
        json!({"operation":snapshot.request["operation"],"configuration_sha256":configuration,
        "certificate_sha256":recipe["certificate"]["sha256"]}),
    )
}

fn principals_origin(previous: &[Snapshot], secret: &Value) -> Result<Value> {
    let Some((snapshot, step)) = latest(previous, "configure-principals") else {
        return Ok(Value::Null);
    };
    let recipe = service::recipe_of("registry-token", snapshot)?;
    proved(snapshot, step, &secret["uid"], |event| {
        event["objects"][1]["class"] == "owned" && event["objects"][1]["uid"] == secret["uid"]
    })?;
    let secrets: Vec<Value> = recipe["principals"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .map(|p| p["secret"].clone())
        .collect();
    Ok(json!({"operation":snapshot.request["operation"],
        "recipe_sha256":hash(&service::recipe_label("registry-token"), recipe)?,"secrets":secrets}))
}

pub(super) fn installed(listed: &Value, origin: &Value) -> Value {
    match (listed.as_array(), origin["secrets"].as_array()) {
        (Some(entries), Some(secrets)) if entries.len() == secrets.len() => entries
            .iter()
            .zip(secrets)
            .map(|(entry, secret)| {
                let mut entry = entry.clone();
                entry["secret"] = secret.clone();
                entry
            })
            .collect(),
        _ => Value::Null,
    }
}

fn path(repository: &str) -> Result<String> {
    let reference = ImageReference::parse(repository).ok_or(Failure::Configuration)?;
    let authority = format!("{}/", reference.authority);
    let path = reference.repository.strip_prefix(authority.as_str());
    path.map(str::to_owned).ok_or(Failure::Configuration)
}

pub(super) fn listed(
    registry: &ManagedRegistry,
    secret: impl Fn(&str) -> Result<Value>,
) -> Result<Value> {
    let mut list = Vec::new();
    for (name, principal) in &registry.authentication.principals {
        let (purpose, actions) = match principal.purpose {
            PrincipalPurpose::Publication => ("publication", json!(["pull", "push"])),
            PrincipalPurpose::NodePull => ("node-pull", json!(["pull"])),
            PrincipalPurpose::Maintenance => ("maintenance", json!(["pull", "delete"])),
        };
        let paths = principal
            .repositories
            .iter()
            .map(|r| path(r))
            .collect::<Result<Vec<_>>>()?;
        list.push(
            json!({"name":name,"purpose":purpose,"repositories":paths,"actions":actions,
            "secret":secret(name)?}),
        );
    }
    Ok(Value::Array(list))
}

pub(super) fn origins(
    previous: &[Snapshot],
    resources: &[Value],
    configmap: &Value,
) -> Result<Value> {
    let objects = service::objects("registry-token", previous, resources)?;
    let switch = switch_origin(previous, configmap)?;
    if objects.iter().all(Value::is_null) {
        return Ok(json!({"objects":null,"certificate":null,"switch":switch,"principals":null}));
    }
    require(objects.iter().all(Value::is_object), Failure::Ownership)?;
    let secret = &resources[1];
    let creating = previous
        .iter()
        .filter(|s| s.request["action"] == "reconcile-registry-token")
        .find_map(|s| {
            s.steps
                .iter()
                .find(|step| {
                    step["action"] == action("create-object").as_str()
                        && step["resource"]["id"] == secret["id"]
                        && s.succeeded(step)
                })
                .map(|step| (s, step))
        });
    let (snapshot, step) = latest(previous, "configure-token")
        .or(creating)
        .ok_or(Failure::Ownership)?;
    proved(snapshot, step, &secret["uid"], |event| {
        event["objects"][1]["class"] == "owned" && event["objects"][1]["uid"] == secret["uid"]
    })?;
    let sha = service::recipe_of("registry-token", snapshot)?["certificate"]["sha256"].clone();
    Ok(json!({"objects":objects,
        "certificate":{"operation":snapshot.request["operation"],"sha256":sha},"switch":switch,
        "principals":principals_origin(previous, secret)?}))
}

fn switched_key(previous: &[Snapshot], origins: &Value, declared: &Declared) -> Result<()> {
    let operation = &origins["switch"]["operation"];
    if operation.is_null() {
        return Ok(());
    }
    let snapshot = previous
        .iter()
        .find(|s| s.request["operation"] == *operation)
        .ok_or(Failure::Integrity)?;
    let pem = service::recipe_of("registry-token", snapshot)?["certificate"]["pem"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    require(
        crate::k3s::certificate_key(pem).map_err(|_| Failure::Configuration)? == declared.key,
        Failure::Configuration,
    )
}

pub(super) fn expected(recipe: &Value) -> Value {
    let origins = &recipe["origins"];
    let objects: Vec<Value> = origins["objects"].as_array().map_or_else(
        || vec![Value::Null; 5],
        |o| o.iter().map(|x| x["uid"].clone()).collect(),
    );
    json!({"objects":objects,"certificate":origins["certificate"]["sha256"],
        "configuration":origins["switch"]["configuration_sha256"],
        "principals":installed(&recipe["principals"], &origins["principals"])})
}

fn precedence(
    stage: &str,
    hosts: &[(Value, bool)],
    api: &Value,
    expected: &Value,
    nodes: bool,
) -> Result<()> {
    let objects = api["objects"].as_array().ok_or(Failure::Integrity)?;
    require(objects.len() == 5, Failure::Integrity)?;
    let (create, configmap, switched) = (
        stage == "create",
        &api["registry"]["configmap"],
        &expected["configuration"],
    );
    let importing: Vec<&Value> = hosts
        .iter()
        .filter(|(_, imports)| *imports && matches!(stage, "create" | "extend"))
        .map(|(host, _)| host)
        .collect();
    let observed = &api["registry"]["configuration_sha256"];
    let facts = if stage == "principals" {
        api["principals"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .collect()
    } else {
        Vec::new()
    };
    let unobservable = |v: &&Value| v["class"] == "unobservable";
    if nodes && stage != "observe" {
        let states: Vec<&Value> = api["nodes"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .map(|n| &n["node"])
            .collect();
        require(
            !states.iter().any(|n| *n == "unobservable"),
            Failure::Readiness,
        )?;
        require(!states.iter().any(|n| *n == "drifted"), Failure::Ownership)?;
        require(states.iter().all(|n| *n == "ready"), Failure::Readiness)?;
    }
    let class = |wanted: &[&str]| {
        objects
            .iter()
            .any(|o| wanted.iter().any(|w| o["class"] == *w))
    };
    require(
        !class(&["foreign", "owned-drifted"])
            && (create || !class(&["absent"]))
            && !matches!(configmap.as_str(), Some("drifted" | "absent"))
            && (configmap != "base" || switched.is_null())
            && (configmap != "switched" || observed == switched)
            && importing.iter().all(|h| h["image"] != "conflicting")
            && facts
                .iter()
                .all(|f| unobservable(f) || f["class"] == "owned" && f["activation"] == "active"),
        Failure::Ownership,
    )?;
    require(
        !facts.iter().any(unobservable)
            && !class(&["unobservable"])
            && configmap != "unobservable"
            && importing
                .iter()
                .all(|h| h["image"] != "unobservable" && h["runtime"] == "ready"),
        Failure::Readiness,
    )?;
    require(
        importing.iter().all(|h| h["generation"] == "ready"),
        Failure::Readiness,
    )?;
    require(
        !nodes
            || stage != "switch"
            || api["token"]["state"] == "ready" && api["registry"]["process"]["state"] == "ready",
        Failure::Readiness,
    )?;
    let wanted = if create { "absent" } else { "owned" };
    require(
        objects.iter().all(|o| o["class"] == wanted)
            && (stage == "extend"
                || configmap
                    == if switched.is_null() {
                        "base"
                    } else {
                        "switched"
                    }),
        Failure::Ownership,
    )
}

pub(super) fn admits(
    stage: &str,
    hosts: &[(Value, bool)],
    api: &Value,
    expected: &Value,
) -> Result<()> {
    precedence(stage, hosts, api, expected, true)
}

pub(super) fn columns(
    stage: &str,
    hosts: &[(Value, bool)],
    api: &Value,
    expected: &Value,
) -> Result<()> {
    precedence(stage, hosts, api, expected, false)
}

pub(super) fn confirms(hosts: &[Value], api: &Value, expected: &Value) -> Result<()> {
    let objects = api["objects"].as_array().ok_or(Failure::Integrity)?;
    let registry = &api["registry"];
    require(
        hosts.iter().all(|h| h["image"] != "conflicting"),
        Failure::Ownership,
    )?;
    require(
        !objects.iter().any(|o| o["class"] == "unobservable")
            && registry["configmap"] != "unobservable"
            && hosts.iter().all(|h| h["image"] == "ready"),
        Failure::Readiness,
    )?;
    let configmap = if expected["configuration"].is_null() {
        registry["configmap"] == "base"
    } else {
        registry["configmap"] == "switched"
            && registry["configuration_sha256"] == expected["configuration"]
    };
    require(
        objects.len() == 5 && objects.iter().all(|o| o["class"] == "owned") && configmap,
        Failure::Ownership,
    )
}

pub(super) fn readiness(read: &Value, probed: Option<usize>) -> &'static str {
    let owned = read["objects"]
        .as_array()
        .is_some_and(|o| o.len() == 5 && o.iter().all(|o| o["class"] == "owned"));
    let enforced = read["enforcement"].as_array().is_some_and(|e| {
        !e.is_empty()
            && e.iter()
                .all(|e| *e == json!({"registry":"challenge","token":"refused"}))
    });
    if owned
        && read["signing"] == json!({"class":"owned","activation":"active"})
        && read["token"]["state"] == "ready"
        && read["registry"]["configmap"] == "switched"
        && read["registry"]["process"]["state"] == "ready"
        && enforced
        && probed.is_none_or(|n| {
            read["grants"]
                .as_array()
                .is_some_and(|g| g.len() == n && g.iter().all(|g| g == "granted"))
        })
    {
        "ready"
    } else {
        "not-ready"
    }
}

pub(super) fn probed(installed: &Value) -> Option<usize> {
    let listed = installed.as_array()?;
    Some(
        listed
            .iter()
            .filter(|p| p["purpose"] != "maintenance")
            .count(),
    )
}

pub(super) fn publication(services: &str, installed: &Value) -> &'static str {
    if services == "ready" && !installed.is_null() {
        "unobserved"
    } else {
        "not-ready"
    }
}

pub(super) fn counted(recipe: &Value, expected: &Value, probe: bool, reply: &Value) -> Result<()> {
    let length = |value: &Value| value.as_array().map(Vec::len);
    let grants = if probe {
        probed(&expected["principals"])
    } else {
        None
    };
    require(
        length(&reply["principals"]) == length(&recipe["principals"])
            && length(&reply["grants"]) == grants,
        Failure::Integrity,
    )
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let host = matches!(tag, "inspect-host" | "import-image");
    let read = tag == "inspect-objects";
    require(
        ["generation", "image", "runtime"]
            .iter()
            .all(|key| result[*key].is_null() != host)
            && [
                "objects",
                "signing",
                "token",
                "registry",
                "nodes",
                "enforcement",
            ]
            .iter()
            .all(|key| result[*key].is_null() != read)
            && (!read || result["nodes"].is_array() && result["token"]["pods"].is_array())
            && (read || result["principals"].is_null() && result["grants"].is_null())
            && result["terminal"].is_null() == matches!(tag, "inspect-host" | "inspect-objects"),
        Failure::Integrity,
    )
}

pub(super) fn planned(owner: &Value, previous: &[Snapshot]) -> Result<(Vec<Value>, Option<Value>)> {
    let shaped = |n: usize, generation: Value, uid: Value| {
        json!({"kind":"service","id":format!("registry-token-object-{:02}", n + 1),
            "owner":owner["owner"],"generation":generation,"machine":null,"path":null,
            "namespace":"broil-registry","name":"broil-registry-token","uid":uid})
    };
    let token = |r: &Value| {
        r["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("registry-token-object-"))
    };
    let held: Vec<&Value> = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|r| token(r))
        .collect();
    if held.is_empty() {
        let planned = (0..5)
            .map(|n| Ok(shaped(n, json!(fresh()?), Value::Null)))
            .collect::<Result<Vec<_>>>()?;
        let mut successor = owner.clone();
        successor["previous_generation"] = successor["generation"].clone();
        successor["generation"] = json!(fresh()?);
        successor["created_ms"] = json!(now()?);
        successor["resources"]
            .as_array_mut()
            .ok_or(Failure::Integrity)?
            .extend(planned.iter().cloned());
        return Ok((planned, Some(successor)));
    }
    require(
        held.len() == 5
            && held
                .iter()
                .enumerate()
                .all(|(n, r)| **r == shaped(n, r["generation"].clone(), r["uid"].clone())),
        Failure::Ownership,
    )?;
    if held.iter().any(|r| r["uid"].is_null()) {
        require(
            held.iter().all(|r| r["uid"].is_null())
                && !previous.iter().any(|s| {
                    s.request["resources"]
                        .as_array()
                        .is_some_and(|r| r.iter().any(token))
                }),
            Failure::Ownership,
        )?;
    }
    Ok((held.into_iter().cloned().collect(), None))
}

fn established(owner: &Value) -> Result<(Vec<Value>, Value)> {
    let services = auth::prerequisites(owner)?;
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    let bound = |id: &str| {
        resources
            .iter()
            .find(|r| r["id"] == id && r["uid"].is_string())
            .cloned()
    };
    require(
        (1..=3).all(|n| bound(&format!("registry-endpoint-object-{n:02}")).is_some()),
        Failure::Readiness,
    )?;
    Ok((services, bound(auth::ID).ok_or(Failure::Readiness)?))
}

fn fits(request: &Value, attempt: &str, count: usize, recipe: &Value, index: usize) -> Result<()> {
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let binding = |member: usize| -> Result<Value> {
        let mut binding = network::read_binding(request, attempt, last, member)?;
        binding["receiver_generation"] = json!(u64::MAX);
        Ok(binding)
    };
    let (wide, zero) = ("f".repeat(128), "0".repeat(64));
    let object = json!({"kind":"NetworkPolicy","namespace":"broil-registry",
        "name":"broil-registry-token","uid":wide,"class":"owned-drifted","spec_sha256":zero});
    let host = json!({"generation":"not-ready","image":"unobservable","runtime":"not-ready"});
    let api = json!({"objects":vec![object; 5],
        "registry":{"configmap":"unobservable","configuration_sha256":zero}});
    let replicas = recipe["members"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    let listed = &recipe["principals"];
    let entries = listed.as_array().map_or(0, Vec::len);
    let fact = json!(vec![
        json!({"class":"owned-drifted","activation":"inactive"});
        entries
    ]);
    let mut principals = api.clone();
    principals["principals"] = fact.clone();
    let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
    let resource = resources
        .iter()
        .max_by_key(|r| canonical(r).map_or(0, |c| c.len()))
        .ok_or(Failure::Integrity)?;
    for tag in [
        "import-image",
        "create-object",
        "configure-token",
        "switch-registry",
        "configure-principals",
    ] {
        let import = tag == "import-image";
        let preflight = match tag {
            "import-image" => &host,
            "configure-principals" => &principals,
            _ => &api,
        };
        let header = json!({"protocol":FAMILY.protocol,"version":FAMILY.version,"action":tag,
            "request_id":fresh()?,"binding":binding(if import {index} else {0})?,
            "remaining_ms":7_200_000,"recipe":recipe,
            "expected":{"objects":vec![json!(wide); 5],"certificate":zero,"configuration":zero,
                "principals":listed},
            "resource":resource,"preflight":preflight,
            "object_ordinal":if tag == "create-object" {json!(5)} else {Value::Null},"probe":false,
            "member":if import {recipe["members"][index].clone()} else {Value::Null}});
        require(
            canonical(&header)?
                .len()
                .checked_add(17 + FAMILY.reserve)
                .is_some_and(|n| n <= 65_536),
            Failure::Bound,
        )?;
    }
    let terminal = json!({"schema":1,"kind":"terminal","binding":binding(index)?,
        "action":action("import-image"),"payload_sha256":zero,"outcome":"succeeded",
        "failure":"unsupported-version","effect":"complete","writer_ended":true,"resource":resource,
        "resource_identity":[u64::MAX,u64::MAX],"completed_ms":u64::MAX});
    let process =
        json!({"state":"not-ready","reason":"unobservable","node":wide,"restarts":u64::MAX});
    let members = recipe["ingress"].as_array().map_or(0, Vec::len);
    let mut import = json!({"kind":"result","status":"unsupported-version","terminal":null,
        "generation":null,"image":null,"runtime":null,"objects":null,"signing":null,"token":null,
        "registry":null,"nodes":null,"enforcement":null,"principals":null,
        "grants":null,"failure":"unsupported-version"});
    let mut objects = import.clone();
    for (key, value) in [
        ("objects", api["objects"].clone()),
        (
            "signing",
            json!({"class":"owned-drifted","activation":"inactive"}),
        ),
        (
            "token",
            json!({"state":"not-ready","reason":"unobservable","pods":replicas.iter()
                .map(|m| json!({"member":m["member"],"ready":false,"restarts":u64::MAX}))
                .collect::<Vec<_>>()}),
        ),
        (
            "registry",
            json!({"configmap":"unobservable","configuration_sha256":zero,"process":process}),
        ),
        (
            "nodes",
            json!(
                replicas
                    .iter()
                    .map(|m| json!({"member":m["member"],"node":"unobservable"}))
                    .collect::<Vec<_>>()
            ),
        ),
        (
            "enforcement",
            json!(vec![
                json!({"registry":"unobservable","token":"unobservable"});
                members
            ]),
        ),
        ("principals", fact),
        ("grants", json!(vec!["unobservable"; entries])),
    ] {
        objects[key] = value;
    }
    for (key, value) in [
        ("terminal", terminal),
        ("generation", json!("not-ready")),
        ("image", json!("unobservable")),
        ("runtime", json!("not-ready")),
    ] {
        import[key] = value;
    }
    for reply in [import, objects] {
        require(canonical(&reply)?.len() <= FAMILY.reserve, Failure::Bound)?;
    }
    Ok(())
}

fn declared(
    registry: Option<&ManagedRegistry>,
    infrastructure: &Infrastructure,
    registries: &BTreeMap<String, EffectiveRegistry>,
    profile: &Value,
) -> Result<(ManagedRegistry, Value, Value)> {
    let registry = service::gates(registry, infrastructure, profile)?;
    let entry = registries
        .get(&registry.endpoint)
        .ok_or(Failure::Configuration)?;
    let (endpoint, _) = endpoint::declared_trust(&registry.endpoint, entry)?;
    auth::gates(Some(&registry), infrastructure)?;
    require(
        registry.authentication.signing_certificate.is_some(),
        Failure::Configuration,
    )?;
    let token = token(entry)?;
    Ok((registry, endpoint, token))
}

pub(super) fn fit(context: &rpc::Context<'_>) -> Result<()> {
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    let d = context.selected.declaration;
    let (registry, endpoint, token) = declared(
        d.registry.as_ref(),
        &d.infrastructure,
        &context.selected.registries,
        &profile,
    )?;
    widest(context, &profile, &registry, &endpoint, &token)
}

fn widest(
    context: &rpc::Context<'_>,
    profile: &Value,
    registry: &ManagedRegistry,
    endpoint: &Value,
    token: &Value,
) -> Result<()> {
    let block = |bytes: usize| {
        (0..bytes)
            .map(|i| if i % 65 == 64 { '\n' } else { 'f' })
            .collect::<String>()
    };
    let (hex, uid) = (|n: usize| "f".repeat(n), "f".repeat(128));
    let operation = format!("infra-operation-{}", hex(32));
    let members = (context.selected.members.iter())
        .map(|m| context.widest_member(&m.declaration.machine))
        .collect::<Result<Vec<_>>>()?;
    let index = 0;
    let secret = json!({"id":uid,"generation":hex(32),"name":format!("broil-input-{}", hex(40)),
        "uid":uid,"operation":operation,"recipe_sha256":hex(64)});
    let principals = listed(registry, |_| Ok(secret.clone()))?;
    let secrets = vec![secret.clone(); principals.as_array().map_or(0, Vec::len)];
    let annotated = json!({"uid":uid,"annotations":{"broil.dev/owner":hex(32),
        "broil.dev/creation-operation":operation,"broil.dev/cluster-uid":uid,
        "broil.dev/recipe-sha256":hex(64),"broil.dev/profile-sha256":hex(64)}});
    let pin = &profile["registry"];
    let recipe = json!({"scope":context.scope,"owner":hex(32),"operation":operation,
        "cluster":{"uid":uid,"ca_sha256":hex(64)},"first_server":members[0],
        "members":members,"anchor_uid":uid,"version":context.selected.declaration.version,
        "registry":registry.name,"image":profile["auth"],
        "assets":members.iter().map(|m| json!({"member":m["member"],"generation":hex(32),
            "marker_sha256":hex(64)})).collect::<Vec<_>>(),
        "tolerations":service::replica_tolerations(context, &members)?,"endpoint":endpoint,
        "trust":{"certificates":[block(4096), block(4096)],"sha256":hex(64)},
        "ingress":endpoint::ingress(context, &Value::Null)?,"token":token,
        "certificate":{"pem":block(4096),"sha256":hex(64)},
        "signing":{"name":secret["name"],"uid":uid,"generation":hex(32),"operation":operation,
            "recipe_sha256":hex(64)},
        "service":{"configmap":annotated,"deployment":annotated,
            "image":format!("{}@sha256:{}", pin["image"].as_str().unwrap_or_default(),
                pin["digest"].as_str().unwrap_or_default()),"path":registry.storage.path,
            "writer":members.iter().map(|m| m["member"].clone()).max_by_key(|m| m.as_str().map_or(0, str::len)),
            "writer_generation":u64::MAX},
        "principals":principals,"stage":"principals",
        "origins":{"objects":vec![json!({"operation":operation,"recipe_sha256":hex(64),"uid":uid}); 5],
            "certificate":{"operation":operation,"sha256":hex(64)},
            "switch":{"operation":operation,"configuration_sha256":hex(64),"certificate_sha256":hex(64)},
            "principals":{"operation":operation,"recipe_sha256":hex(64),"secrets":secrets}},
        "profile_sha256":hex(64)});
    require(canonical(&recipe)?.len() <= 32_768, Failure::Bound)?;
    let resource = json!({"kind":"service","id":"registry-token-object-05","owner":hex(32),
        "generation":hex(32),"machine":null,"path":null,"namespace":"broil-registry",
        "name":"broil-registry-token","uid":uid});
    let request = json!({"scope":context.scope,"owner":hex(32),"operation":operation,
        "members":members,"participants_sha256":hex(64),"fingerprints":context.fingerprints,
        "resources":[resource]});
    let count = storage::step_count(&members, members.len(), effects("create") + members.len())?;
    fits(&request, &hex(32), count, &recipe, index)
}

#[allow(clippy::too_many_arguments)]
async fn preflight(
    context: &rpc::Context<'_>,
    request: &Value,
    attempt: &str,
    last: u64,
    recipe: &Value,
    imports: &[bool],
    source_events: &[Value],
    cleanup: &mut bool,
) -> Result<()> {
    let stage = recipe["stage"].as_str().ok_or(Failure::Integrity)?;
    let values = expected(recipe);
    require(
        matches!(stage, "create" | "configure" | "extend")
            || values["certificate"] == recipe["certificate"]["sha256"],
        Failure::Ownership,
    )?;
    let binding = |member| network::read_binding(request, attempt, last, member);
    let mut hosts = Vec::new();
    for (index, imports) in imports.iter().enumerate() {
        if !imports {
            continue;
        }
        let payload = payload(
            recipe,
            &values,
            &Value::Null,
            &Value::Null,
            &Value::Null,
            false,
        )
        .with_member(&recipe["members"][index]);
        let host = service::admission_read(
            context,
            &FAMILY,
            shape,
            &binding(index)?,
            "inspect-host",
            &payload,
            cleanup,
        )
        .await?;
        hosts.push((host, true));
    }
    let payload = payload(
        recipe,
        &values,
        &Value::Null,
        &Value::Null,
        &Value::Null,
        false,
    );
    let api = service::admission_read(
        context,
        &FAMILY,
        shape,
        &binding(service::first_server(request)?)?,
        "inspect-objects",
        &payload,
        cleanup,
    )
    .await?;
    counted(recipe, &values, false, &api)?;
    admits(stage, &hosts, &api, &values)?;
    network::membership_reads(context, request, attempt, last, source_events, cleanup).await
}

fn payload(
    recipe: &Value,
    expected: &Value,
    resource: &Value,
    preflight: &Value,
    ordinal: &Value,
    probe: bool,
) -> Value {
    json!({"recipe":recipe,"expected":expected,"resource":resource,"preflight":preflight,
        "object_ordinal":ordinal,"probe":probe,"member":null})
}

trait WithMember {
    fn with_member(self, member: &Value) -> Value;
}

impl WithMember for Value {
    fn with_member(mut self, member: &Value) -> Value {
        self["member"] = member.clone();
        self
    }
}

pub(super) fn preflight_of(tag: &str, read: &Value) -> Value {
    if tag == "import-image" {
        return json!({"generation":read["generation"],"image":read["image"],"runtime":read["runtime"]});
    }
    let mut api = json!({"objects":read["objects"],"registry":{"configmap":read["registry"]["configmap"],
        "configuration_sha256":read["registry"]["configuration_sha256"]}});
    if tag == "configure-principals" {
        api["principals"] = read["principals"].clone();
    }
    api
}

type Admitted = (Vec<Value>, String, Value, &'static str, Vec<bool>);

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
    only: Option<&str>,
) -> super::ExecutionResult<Option<(Box<Session<'a>>, Value, &'static str, Vec<bool>)>> {
    let context = rpc::Context::new(project, policy, target)?;
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let declaration = context.selected.declaration;
    let (registry, endpoint, trust, token, declared) = gates(
        &project.broil_root,
        declaration.registry.as_ref(),
        &declaration.infrastructure,
        &context.selected.registries,
        &profile,
    )?;
    auth::bounds(&registry)?;
    widest(&context, &profile, &registry, &endpoint, &token)?;
    let mut local = Local::new(&context)?;
    let prepared: Result<Option<Admitted>> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e| e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()), Failure::Ownership)?;
        let members = super::survivors(&owner)?;
        let (services, signing) = established(&owner)?;
        let report = |snapshot: &Snapshot| {
            super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        };
        for snapshot in &previous {
            super::session::settled(&report(snapshot)?)?;
        }
        let service_origins = endpoint::prerequisite(service::object_origins(&previous, &services))?;
        require(service_origins["objects"].as_array()
            .is_some_and(|o| o.iter().all(Value::is_object)), Failure::Readiness)?;
        let succeeded = |snapshot: &Snapshot| report(snapshot).is_ok_and(|r| r["outcome"] == "succeeded");
        let secret = endpoint::prerequisite(auth::origins(&previous, &signing, &succeeded))?;
        require(!secret["activation"].is_null(), Failure::Readiness)?;
        let mut current = BTreeMap::new();
        for name in registry.authentication.principals.keys() {
            if let Some(found) = endpoint::prerequisite(auth::current(&previous, &owner, name, &succeeded))? {
                current.insert(name.as_str(), found);
            }
        }
        let principals = if current.len() == registry.authentication.principals.len() {
            listed(&registry, |name| current.get(name).cloned().ok_or(Failure::Integrity))?
        } else {
            Value::Null
        };
        let (resources, pending_owner) = planned(&owner, &previous)?;
        let origins = origins(&previous, &resources, &services[2])?;
        let base = stage(&origins, &declared.sha256, &principals)?;
        switched_key(&previous, &origins, &declared)?;
        require(members.iter().all(|m| m["node_uid"].is_string()), Failure::Readiness)?;
        let found: Vec<Result<(Value, Value)>> = members.iter()
            .map(|m| service::evidence(super::ingress::generations(&previous, &context, std::iter::once(m))))
            .collect();
        let held_assets: Vec<Value> = found.iter()
            .map(|f| f.as_ref().map_or(Value::Null, |(_, resource)| resource.clone()))
            .collect();
        let images = service::imported("registry-token", &previous, &held_assets)?;
        let imports: Vec<bool> = images.iter().map(|i| base == "create" || i.is_null()).collect();
        let stage = if base != "create" && imports.iter().any(|i| *i) { "extend" } else { base };
        let mut assets = Vec::with_capacity(members.len());
        for (member, found) in members.iter().zip(found) {
            let (entry, _) = found?;
            assets.push(json!({"member":member["member"],"generation":entry["generation"],
                "marker_sha256":entry["marker_sha256"]}));
        }
        let remaining = context.clock.deadline()
            .saturating_duration_since(tokio::time::Instant::now()).as_secs();
        let installed_list = installed(&principals, &origins["principals"]);
        let counted = if stage == "principals" { &principals } else { &installed_list };
        let n = counted.as_array().map_or(0, Vec::len) as u64;
        let (mut importing, mut every) = (u64::MAX, u64::MAX);
        for (member, imports) in members.iter().zip(&imports) {
            let seconds = service::script_seconds(&context, member)?;
            every = every.min(seconds);
            if *imports {
                importing = importing.min(seconds);
            }
        }
        let count_imports = imports.iter().filter(|i| **i).count();
        if matches!(stage, "create" | "extend") {
            service::budgets(count_imports as u64, if stage == "create" { 4 } else { 0 },
                context.selected.step_timeout.seconds, importing, every, remaining)?;
        } else {
            item7(stage, &owner, context.selected.step_timeout.seconds, every, remaining, n)?;
        }
        if only.is_some_and(|wanted| wanted != stage) {
            return Ok(None);
        }
        context.authenticate_owned(&Value::Array(members.clone())).await?;
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let participants = super::participants(&Value::Array(members.clone()))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let annotated = |n: usize| {
            let origin = &service_origins["objects"][n];
            json!({"uid":services[n]["uid"],"annotations":{"broil.dev/owner":current_owner["owner"],
                "broil.dev/creation-operation":origin["operation"],
                "broil.dev/cluster-uid":current_owner["cluster"]["uid"],
                "broil.dev/recipe-sha256":origin["recipe_sha256"],
                "broil.dev/profile-sha256":context.fingerprints["profile_sha256"]}})
        };
        let pin = &profile["registry"];
        let anchor = current_owner["resources"].as_array().ok_or(Failure::Integrity)?.iter()
            .find(|r| r["id"] == auth::ANCHOR).ok_or(Failure::Readiness)?;
        let first_server = members.iter().find(|m| m["role"] == "server").ok_or(Failure::Ownership)?;
        let (writer, writer_generation) = service::writer(&current_owner, &registry)?;
        let recipe = json!({"scope":context.scope,"owner":current_owner["owner"],"operation":operation,
            "cluster":current_owner["cluster"],"first_server":first_server,"members":members,
            "anchor_uid":anchor["uid"],"version":declaration.version,"registry":registry.name,
            "image":profile["auth"],"assets":assets,
            "tolerations":service::creation_tolerations(&previous, &service_origins)?,
            "endpoint":endpoint,"trust":trust,"ingress":endpoint::ingress(&context, &current_owner["removed"])?,"token":token,
            "certificate":{"pem":declared.pem,"sha256":declared.sha256},
            "signing":{"name":signing["name"],"uid":signing["uid"],"generation":signing["generation"],
                "operation":secret["secret"]["operation"],"recipe_sha256":secret["secret"]["recipe_sha256"]},
            "service":{"configmap":annotated(2),"deployment":annotated(4),
                "image":format!("{}@sha256:{}", pin["image"].as_str().unwrap_or_default(),
                    pin["digest"].as_str().unwrap_or_default()),
                "path":registry.storage.path,"writer":writer,"writer_generation":writer_generation},
            "principals":principals,"stage":stage,"origins":origins,
            "profile_sha256":context.fingerprints["profile_sha256"]});
        schema::validate(&canonical(&recipe)?, "RegistryTokenRecipe", 32_768)?;
        let mut held: Vec<Value> = held_assets.iter().zip(&imports)
            .filter(|(_, i)| **i && matches!(stage, "create" | "extend"))
            .map(|(r, _)| r.clone()).collect();
        held.extend(resources.iter().cloned());
        if stage == "switch" {
            held.push(services[2].clone());
        }
        let created = now()?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-registry-token",
            "members":members,"cluster":current_owner["cluster"],"resources":held,
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let count = if matches!(stage, "create" | "extend") {
            storage::step_count(&members, count_imports, effects(stage) + count_imports)?
        } else {
            issuer::step_count(&members, effects(stage))?
        };
        for index in 0..members.len() {
            fits(&request, &attempt_id, count, &recipe, index)?;
        }
        let mut cleanup = false;
        let checked = preflight(&context, &request, &attempt_id, count as u64, &recipe,
            &imports, &source_events, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_registry_token(successor)).await?;
            require(local.snapshot()?.owner["resources"].as_array().is_some_and(|all|
                all.ends_with(&resources)), Failure::Ownership)?;
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
        for event in std::iter::once(json!({"type":"registry-token-recipe","recipe":recipe}))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        let imports = if matches!(stage, "create" | "extend") { imports } else { vec![false; members.len()] };
        Ok(Some((members, attempt_id, recipe, stage, imports)))
    }.await;
    let (members, attempt_id, recipe, stage, imports) = match prepared {
        Ok(Some(value)) => value,
        Ok(None) => {
            local
                .finish(&context.clock)
                .await
                .map_err(|failure| super::ExecutionFailure {
                    failure,
                    completion_unknown: false,
                    cleanup_unknown: true,
                    snapshot: None,
                    detail: None,
                })?;
            return Ok(None);
        }
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
    Ok(Some((
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
        recipe,
        stage,
        imports,
    )))
}

pub(super) fn resumed(original: &Snapshot, recipe: &Value) -> Result<Value> {
    let mut values = expected(recipe);
    for done in original.steps.iter().filter(|s| original.succeeded(s)) {
        let tag = done["action"]
            .as_str()
            .and_then(|a| a.strip_prefix("lifecycle:registry-token-"))
            .unwrap_or_default();
        if !matches!(
            tag,
            "create-object" | "configure-token" | "switch-registry" | "configure-principals"
        ) {
            continue;
        }
        let receipt = &issuer::recorded(original, done, "receiver")?["event"]["receipt"];
        if tag == "switch-registry" {
            values["configuration"] = json!(configuration_sha256(recipe)?);
            continue;
        }
        if tag == "configure-principals" {
            values["principals"] = recipe["principals"].clone();
            continue;
        }
        let id = receipt["resource"]["id"].as_str().unwrap_or_default();
        if let Some(n) = id
            .strip_prefix("registry-token-object-")
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| (1..=5).contains(n))
        {
            values["objects"][n - 1] = receipt["resource_identity"].clone();
        }
        if id == "registry-token-object-02" {
            values["certificate"] = recipe["certificate"]["sha256"].clone();
        }
    }
    Ok(values)
}

pub(super) async fn resume_objects(
    context: &rpc::Context<'_>,
    local: &mut Local,
    original: &Snapshot,
    recipe: &Value,
) -> Result<()> {
    let Some(step) = original
        .steps
        .iter()
        .rev()
        .find(|s| s["action"] == action("inspect-objects").as_str())
    else {
        return Ok(());
    };
    let values = resumed(original, recipe)?;
    let payload = payload(
        recipe,
        &values,
        &Value::Null,
        &Value::Null,
        &Value::Null,
        false,
    );
    let observed = network::invoke(
        context,
        &FAMILY,
        &original.binding(step),
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
    shape("inspect-objects", &result)?;
    local
        .append(
            Some(step),
            network::observation(&FAMILY, Value::Null, &result),
            Some(&step["recipient"]["machine"]),
            Value::Null,
        )
        .await
}

impl Session<'_> {
    async fn token_read(
        &mut self,
        index: usize,
        tag: &str,
        recipe: &Value,
        refs: &[Value],
        expected: &Value,
        probe: bool,
    ) -> Result<Value> {
        let null = Value::Null;
        let mut payload = payload(recipe, expected, &null, &null, &null, probe);
        if tag == "inspect-host" {
            payload = payload.with_member(&recipe["members"][index]);
        }
        let (_, read) = self.family_step(index, tag, payload, refs.to_vec()).await?;
        if tag == "inspect-objects" {
            counted(recipe, expected, probe, &read)?;
        }
        Ok(read)
    }

    async fn token_points(
        &mut self,
        imports: &[bool],
        recipe: &Value,
        refs: &[Value],
        expected: &Value,
        probe: bool,
    ) -> Result<(Vec<Value>, Value)> {
        let mut hosts = Vec::new();
        for (index, imports) in imports.iter().enumerate() {
            if *imports {
                hosts.push(
                    self.token_read(index, "inspect-host", recipe, refs, expected, false)
                        .await?,
                );
            }
        }
        let first = service::first_server(&self.local.snapshot()?.request)?;
        let api = self
            .token_read(first, "inspect-objects", recipe, refs, expected, probe)
            .await?;
        Ok((hosts, api))
    }

    async fn token_reads(
        &mut self,
        imports: &[bool],
        recipe: &Value,
        refs: &[Value],
        expected: &Value,
    ) -> Result<(Vec<(Value, bool)>, Value)> {
        self.network_source_gate().await?;
        let (hosts, api) = self
            .token_points(imports, recipe, refs, expected, false)
            .await?;
        Ok((hosts.into_iter().map(|h| (h, true)).collect(), api))
    }

    #[allow(clippy::too_many_arguments)]
    async fn token_effect(
        &mut self,
        index: usize,
        tag: &str,
        recipe: &Value,
        refs: &[Value],
        expected: &Value,
        resource: &Value,
        ordinal: Value,
    ) -> Result<(Value, Value)> {
        let snapshot = self.local.snapshot()?;
        let host = tag == "import-image";
        let recipient = &self.members[index];
        let latest = snapshot
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == "registry-token-observation"
                    && if host {
                        o["event"]["member"] == *recipient
                    } else {
                        o["event"]["member"].is_null() && !o["event"]["objects"].is_null()
                    }
            })
            .ok_or(Failure::Integrity)?;
        let mut refs = refs.to_vec();
        refs.push(network::latest_sequence(snapshot, "server-membership")?);
        refs.push(latest["sequence"].clone());
        if self.members.iter().any(|member| member["role"] == "agent") {
            refs.push(network::latest_sequence(snapshot, "agent-membership")?);
        }
        refs.sort_by_key(Value::as_u64);
        refs.dedup();
        let preflight = preflight_of(tag, &latest["event"]);
        let mut payload = payload(recipe, expected, resource, &preflight, &ordinal, false);
        if host {
            payload = payload.with_member(&recipe["members"][index]);
        }
        let (step, result) = self.family_step(index, tag, payload, refs).await?;
        let receipt = self
            .inspect_step(index, "dispatch", step["dispatch"].clone(), Value::Null)
            .await?;
        require(receipt["status"] == "ok", Failure::Ownership)?;
        Ok((step, result))
    }

    async fn token_run(&mut self, recipe: Value, imports: Vec<bool>) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, "registry-token-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let stage = recipe["stage"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        let create = stage == "create";
        let first = service::first_server(&request)?;
        let mut values = expected(&recipe);
        let mut refs = vec![recipe_seq];
        for &member in &order {
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
        let (hosts, api) = self.token_reads(&imports, &recipe, &refs, &values).await?;
        columns(&stage, &hosts, &api, &values)?;
        let reserve = json!({"members":self.members,"excluded":null,"cluster":cluster,
            "fingerprints":self.context.fingerprints});
        let acquire = super::session::acquire_payload(self.local.snapshot()?, &self.members)?;
        for (tag, payload) in [("reserve-owner", reserve), ("acquire-writer", acquire)] {
            for &member in &order {
                self.dispatch(member, tag, payload.clone(), Vec::new())
                    .await?;
            }
        }
        self.acquired()?;
        self.mode = Mode::Work;
        self.context
            .authenticate_owned(&Value::Array(self.members.clone()))
            .await?;
        let (hosts, api) = self.token_reads(&imports, &recipe, &refs, &values).await?;
        columns(&stage, &hosts, &api, &values)?;
        let resources = request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let mut assets = resources.iter();
        for (index, imports) in imports.iter().enumerate() {
            if !imports {
                continue;
            }
            let resource = assets.next().ok_or(Failure::Integrity)?.clone();
            self.token_effect(
                index,
                "import-image",
                &recipe,
                &refs,
                &values,
                &resource,
                Value::Null,
            )
            .await?;
            self.token_read(index, "inspect-host", &recipe, &refs, &values, false)
                .await?;
        }
        let offset = imports.iter().filter(|i| **i).count();
        let effects: Vec<(&str, usize)> = match stage.as_str() {
            "create" => (1..=5).map(|n| ("create-object", n)).collect(),
            "configure" => vec![("configure-token", 2)],
            "switch" => vec![("switch-registry", 6)],
            "principals" => vec![("configure-principals", 2)],
            _ => Vec::new(),
        };
        for (tag, n) in effects {
            let ordinal = if create { json!(n) } else { Value::Null };
            let resource = &resources[offset + n - 1];
            let (step, done) = self
                .token_effect(first, tag, &recipe, &refs, &values, resource, ordinal)
                .await?;
            let identity = done["terminal"]["resource_identity"].clone();
            match tag {
                "create-object" => values["objects"][n - 1] = identity.clone(),
                "switch-registry" => {
                    values["configuration"] = json!(configuration_sha256(&recipe)?)
                }
                "configure-principals" => values["principals"] = recipe["principals"].clone(),
                _ => {}
            }
            if tag == "configure-token" || (create && n == 2) {
                values["certificate"] = recipe["certificate"]["sha256"].clone();
            }
            refs.push(
                issuer::recorded(self.local.snapshot()?, &step, "receiver")?["sequence"].clone(),
            );
            let read = self
                .token_read(first, "inspect-objects", &recipe, &refs, &values, false)
                .await?;
            if !create {
                continue;
            }
            let object = &read["objects"][n - 1];
            require(
                identity.as_str().is_some_and(protocol::opaque)
                    && object["class"] == "owned"
                    && object["uid"] == identity,
                Failure::Ownership,
            )?;
            let mut published = resource.clone();
            published["uid"] = identity;
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
        let probe = stage == "observe" && !values["principals"].is_null();
        let (hosts, api) = self
            .token_points(&imports, &recipe, &refs, &values, probe)
            .await?;
        confirms(&hosts, &api, &values)?;
        self.settle(&order).await
    }
}

fn next(stage: &str, ready: bool) -> Option<&'static str> {
    match stage {
        "create" | "configure" if ready => Some("switch"),
        "switch" => Some("principals"),
        _ => None,
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let mut last: Option<Snapshot> = None;
    let mut only = None;
    loop {
        let Some((mut session, recipe, stage, imports)) =
            begin(project, issuer::duplicate(&policy)?, target, only).await?
        else {
            return last.ok_or_else(|| Failure::Integrity.into());
        };
        let result = Box::pin(session.token_run(recipe, imports)).await;
        let snapshot = session
            .local
            .complete(result, &session.context.clock)
            .await?;
        let ready = snapshot
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == "registry-token-observation"
                    && !o["event"]["objects"].is_null()
            })
            .is_some_and(|o| o["event"]["token"]["state"] == "ready");
        only = next(stage, ready);
        if only.is_none() {
            return Ok(snapshot);
        }
        last = Some(snapshot);
    }
}

