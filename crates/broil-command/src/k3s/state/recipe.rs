// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, Snapshot, canonical, hash, require};
use crate::k3s::{Cluster, Generation, Operation, Policy, protocol};
use serde_json::{Value, json};

fn text(value: &Value) -> Result<&str> {
    value.as_str().ok_or(Failure::Integrity)
}

fn origin(projection: &Value, name: &str) -> Result<String> {
    let endpoint = text(&projection["registries"][name]["declaration"]["endpoint"])?;
    let endpoint = broil_core::images::reference::Endpoint::registry(endpoint, true)
        .ok_or(Failure::Integrity)?;
    Ok(crate::k3s::origin(&endpoint))
}

fn selection(recipe: &Value) -> Result<(Operation, &'static str, Vec<Value>)> {
    let p = &recipe["projection"];
    let b = &p["binding"];
    let d = &p["declaration"];
    let mut selectors =
        json!({"issuer":null,"service":null,"principal":null,"origin":null,"recovery":null});
    let (operation, kind, references) = match text(&recipe["action"])? {
        "supply-initial-server" => {
            require(
                b["cluster"].is_null() && b["destination"]["machine"] == d["members"][0]["machine"],
                Failure::Ownership,
            )?;
            require(
                d["credentials"]["server_token"] != d["credentials"]["agent_token"],
                Failure::Integrity,
            )?;
            (
                Operation::InitialServer,
                "server-input",
                vec![
                    d["credentials"]["server_token"].clone(),
                    d["credentials"]["agent_token"].clone(),
                ],
            )
        }
        "supply-server-join" => (
            Operation::ServerJoin {
                source: text(&b["source"]["machine"])?.into(),
            },
            "server-input",
            vec![],
        ),
        "supply-agent-join" => (
            Operation::AgentJoin {
                source: text(&b["source"]["machine"])?.into(),
            },
            "agent-input",
            vec![],
        ),
        "check-admin" => (Operation::AdministrativeCheck, "admin-access", vec![]),
        action @ ("supply-issuer-ca" | "supply-issuer-acme") => {
            let name = text(&b["issuer"])?;
            let issuer = &d["infrastructure"]["issuers"][name];
            selectors["issuer"] = json!(name);
            let references = if action == "supply-issuer-ca" {
                require(issuer["kind"] == "private-ca", Failure::Integrity)?;
                vec![issuer["certificate"].clone(), issuer["key"].clone()]
            } else {
                require(issuer["kind"] == "acme-http01", Failure::Integrity)?;
                vec![issuer["account_key"].clone()]
            };
            (
                Operation::Issuer { name: name.into() },
                "issuer",
                references,
            )
        }
        action @ ("supply-registry-signing" | "supply-registry-principal") => {
            let registry = &d["registry"];
            selectors["service"] = registry["name"].clone();
            selectors["origin"] = json!(origin(p, text(&registry["endpoint"])?)?);
            if action == "supply-registry-signing" {
                (
                    Operation::RegistrySigning,
                    "registry-auth",
                    vec![registry["authentication"]["signing_key"].clone()],
                )
            } else {
                let name = text(&b["principal"])?;
                selectors["principal"] = json!(name);
                (
                    Operation::RegistryPrincipal { name: name.into() },
                    "registry-auth",
                    vec![registry["authentication"]["principals"][name]["password"].clone()],
                )
            }
        }
        "supply-node-registry" => {
            let mut matches = Vec::new();
            for node in d["node_registries"].as_array().ok_or(Failure::Integrity)? {
                if json!(origin(p, text(&node["registry"])?)?) == b["origin"] {
                    matches.push(node);
                }
            }
            require(matches.len() == 1, Failure::Integrity)?;
            selectors["origin"] = b["origin"].clone();
            (
                Operation::NodeRegistry {
                    registry: text(&matches[0]["registry"])?.into(),
                },
                "node-registry",
                vec![matches[0]["password"].clone()],
            )
        }
        action @ ("supply-recovery-key" | "supply-recovery-server-token") => {
            selectors["recovery"] = b["resource"]["id"].clone();
            if action == "supply-recovery-key" {
                (
                    Operation::RecoveryKey,
                    "recovery",
                    vec![d["backup"]["identity"].clone()],
                )
            } else {
                (
                    Operation::RecoveryServerToken,
                    "recovery",
                    vec![d["credentials"]["server_token"].clone()],
                )
            }
        }
        _ => return Err(Failure::Integrity),
    };
    for (name, value) in selectors.as_object().ok_or(Failure::Integrity)? {
        require(b[name] == *value, Failure::Integrity)?;
    }
    let relay = matches!(
        operation,
        Operation::ServerJoin { .. } | Operation::AgentJoin { .. }
    );
    require(relay != b["source"].is_null(), Failure::Integrity)?;
    if relay {
        require(
            b["source"]["role"] == "server"
                && b["source"]["machine"] != b["destination"]["machine"],
            Failure::Ownership,
        )?;
    }
    require(
        matches!(operation, Operation::InitialServer) == b["cluster"].is_null(),
        Failure::Ownership,
    )?;
    let role = text(&b["destination"]["role"])?;
    require(
        match operation {
            Operation::AgentJoin { .. } => role == "agent",
            Operation::NodeRegistry { .. } => matches!(role, "server" | "agent"),
            Operation::RecoveryKey | Operation::RecoveryServerToken => {
                matches!(role, "server" | "backup")
            }
            _ => role == "server",
        },
        Failure::Ownership,
    )?;
    require(
        b["resource"]["kind"] == kind && p["references"] == json!(references),
        Failure::Integrity,
    )?;
    require(
        b["resource"]["uid"].is_null() != matches!(kind, "issuer" | "registry-auth"),
        Failure::Integrity,
    )?;
    Ok((operation, kind, references))
}

pub(super) fn validate_request(request: &Value) -> Result<()> {
    let recipe = request.get("consumer").ok_or(Failure::Integrity)?;
    if recipe.is_null() {
        return Ok(());
    }
    selection(recipe)?;
    let p = &recipe["projection"];
    let references = request["references"].as_array().ok_or(Failure::Integrity)?;
    for reference in p["references"].as_array().ok_or(Failure::Integrity)? {
        require(
            references.contains(
                &json!({"consumer":recipe["action"],"set":reference["set"],"key":reference["key"]}),
            ),
            Failure::Integrity,
        )?;
    }
    let b = &p["binding"];
    for key in ["owner", "operation", "cluster"] {
        require(b[key] == request[key], Failure::Ownership)?;
    }
    for key in ["project", "environment", "target"] {
        require(b[key] == request["scope"][key], Failure::Ownership)?;
    }
    for key in ["profile_sha256", "script_sha256"] {
        require(b[key] == request["fingerprints"][key], Failure::Ownership)?;
    }
    require(
        p["declaration"] == request["config"]["target"]
            && p["registries"] == request["config"]["registries"]
            && p["secrets"] == request["config"]["secrets"]
            && p["profile"]["script_sha256"] == b["script_sha256"],
        Failure::Integrity,
    )?;
    let members = request["members"].as_array().ok_or(Failure::Integrity)?;
    let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
    let mut scripts = serde_json::Map::new();
    let mut count = 0;
    for selected in [&b["source"], &b["destination"]] {
        if selected.is_null() {
            continue;
        }
        count += 1;
        let member = members
            .iter()
            .find(|m| m["machine"] == selected["machine"])
            .ok_or(Failure::Ownership)?;
        for key in ["machine", "member", "role", "node_uid"] {
            require(member[key] == selected[key], Failure::Ownership)?;
        }
        let matches = resources
            .iter()
            .filter(|r| {
                r["machine"] == selected["machine"]
                    && r["owner"] == request["owner"]
                    && ["kind", "id", "generation", "uid"]
                        .iter()
                        .all(|k| r[*k] == b["resource"][*k])
            })
            .count();
        require(matches == 1, Failure::Ownership)?;
        let name = text(&selected["machine"])?;
        let mut script = request["config"]["scripts"][name].clone();
        let fields = script.as_object_mut().ok_or(Failure::Integrity)?;
        require(
            fields.remove("name") == Some(p["declaration"]["lifecycle_script"].clone())
                && fields.remove("pty") == Some(json!("never")),
            Failure::Integrity,
        )?;
        scripts.insert(name.into(), script);
    }
    require(
        resources.len() == count && p["scripts"] == Value::Object(scripts),
        Failure::Integrity,
    )
}

pub(super) fn revalidate(context: &super::rpc::Context<'_>, request: &Value) -> Result<()> {
    validate_request(request)?;
    let recipe = &request["consumer"];
    if recipe.is_null() {
        return Ok(());
    }
    let b = &recipe["projection"]["binding"];
    let generation = Generation {
        owner: text(&b["owner"])?.into(),
        operation: text(&b["operation"])?.into(),
        attempt: text(&b["attempt"])?.into(),
        resource: text(&b["resource"]["id"])?.into(),
        generation: text(&b["resource"]["generation"])?.into(),
        resource_uid: b["resource"]["uid"].as_str().map(str::to_owned),
        cluster: if b["cluster"].is_null() {
            None
        } else {
            Some(Cluster {
                uid: text(&b["cluster"]["uid"])?.into(),
                ca_sha256: text(&b["cluster"]["ca_sha256"])?.into(),
            })
        },
        destination_uid: b["destination"]["node_uid"].as_str().map(str::to_owned),
        source_uid: b["source"]["node_uid"].as_str().map(str::to_owned),
    };
    let p = &context.policy;
    let prepared = crate::k3s::prepare(
        context.project,
        Policy {
            environment: p.environment.clone(),
            cwd: p.cwd.clone(),
            environment_snapshot: p.environment_snapshot.clone(),
            credentials: p
                .credentials
                .try_duplicate()
                .map_err(|_| Failure::Credential)?,
            non_interactive: p.non_interactive,
            deadline: context.clock.deadline(),
            cancellation: p.cancellation.clone(),
        },
        text(&request["scope"]["target"])?,
        text(&b["destination"]["machine"])?,
        generation,
        selection(recipe)?.0,
    )
    .map_err(|_| Failure::Configuration)?;
    require(
        prepared.projection() == &recipe["projection"] && recipe["action"] == prepared.action.tag(),
        Failure::Ownership,
    )
}

impl Snapshot {
    pub(super) fn consumer_projection(&self, attempt: &Value) -> Result<Value> {
        let recipe = &self.request["consumer"];
        require(!recipe.is_null(), Failure::Integrity)?;
        let mut projection = recipe["projection"].clone();
        if attempt["parent_attempt"].is_null() {
            require(
                projection["binding"]["attempt"] == attempt["attempt"],
                Failure::Integrity,
            )?;
        } else {
            let decision = &attempt["approval"]["decision"];
            require(decision["action"] == "prepare-input", Failure::Capability)?;
            let resources = decision["resources"].as_array().ok_or(Failure::Integrity)?;
            require(resources.len() == 1, Failure::Integrity)?;
            let destination = &resources[0];
            let original = self.request["resources"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .iter()
                .find(|r| r["machine"] == projection["binding"]["destination"]["machine"])
                .ok_or(Failure::Integrity)?;
            let mut expected = original.clone();
            expected["generation"] = destination["generation"].clone();
            expected["path"] = json!(format!(
                "/var/lib/broil/k3s/owners/{}/resources/{}/{}",
                text(&expected["owner"])?,
                text(&expected["id"])?,
                text(&expected["generation"])?
            ));
            require(
                expected == *destination && destination["generation"] != original["generation"],
                Failure::Ownership,
            )?;
            projection["binding"]["attempt"] = attempt["attempt"].clone();
            projection["binding"]["resource"]["generation"] = destination["generation"].clone();
        }
        Ok(projection)
    }

    pub(super) fn consumer_payload(&self, step: &Value) -> Result<Value> {
        let attempt = self
            .attempts
            .iter()
            .find(|a| a["attempt"] == step["attempt"])
            .ok_or(Failure::Integrity)?;
        let projection = self.consumer_projection(attempt)?;
        let action = text(&step["action"])?;
        let payload = if action == "prepare-input" {
            require(
                matches!(
                    projection["binding"]["resource"]["kind"].as_str(),
                    Some("server-input" | "agent-input" | "node-registry" | "recovery")
                ),
                Failure::Capability,
            )?;
            let resources = if attempt["parent_attempt"].is_null() {
                &self.request["resources"]
            } else {
                &attempt["approval"]["decision"]["resources"]
            };
            let resource = resources
                .as_array()
                .ok_or(Failure::Integrity)?
                .iter()
                .find(|r| r["machine"] == projection["binding"]["destination"]["machine"])
                .ok_or(Failure::Integrity)?;
            require(
                step["resource"] == *resource
                    && step["recipient"]["machine"] == resource["machine"],
                Failure::Ownership,
            )?;
            json!({"resource":resource,"projection":projection})
        } else if let Some(action) = action.strip_prefix("credential:") {
            require(attempt["parent_attempt"].is_null(), Failure::Capability)?;
            let final_action = text(&self.request["consumer"]["action"])?;
            let source = match (final_action, action) {
                ("supply-server-join", "read-server-join")
                | ("supply-agent-join", "read-agent-join") => true,
                _ => {
                    require(action == final_action, Failure::Integrity)?;
                    false
                }
            };
            let recipient = &projection["binding"][if source { "source" } else { "destination" }];
            require(
                !recipient.is_null() && step["recipient"]["machine"] == recipient["machine"],
                Failure::Ownership,
            )?;
            require(
                self.request["resources"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .contains(&step["resource"])
                    && step["resource"]["machine"] == recipient["machine"],
                Failure::Ownership,
            )?;
            let mut admission = projection["binding"].clone();
            admission["selection_sha256"] = json!(protocol::digest(&canonical(&projection)?));
            admission["protocol"] = json!("broil-k3s-actions");
            admission["version"] = json!(1);
            admission["action"] = json!(action);
            admission["for_action"] = Value::Null;
            admission["request_id"] = step["dispatch"].clone();
            admission
        } else if action == "admit-credential" {
            let id = step["step"]
                .as_u64()
                .ok_or(Failure::Integrity)?
                .checked_add(
                    if matches!(
                        self.request["action"].as_str(),
                        Some("prepare-server-inputs" | "join-server" | "join-agent")
                    ) {
                        2
                    } else {
                        1
                    },
                )
                .ok_or(Failure::Bound)?;
            let credential = self
                .steps
                .iter()
                .find(|s| {
                    s["step"] == id
                        && s["attempt"] == step["attempt"]
                        && s["recipient"] == step["recipient"]
                        && s["resource"] == step["resource"]
                        && s["action"]
                            .as_str()
                            .is_some_and(|s| s.starts_with("credential:"))
                })
                .ok_or(Failure::Integrity)?;
            let admission = self.consumer_payload(credential)?;
            json!({"action":admission["action"],"request_id":admission["request_id"],"credential_step":id,
                "admission_sha256":hash("broil-infra-credential-admission-v1",&admission)?,
                "selection_sha256":admission["selection_sha256"],"resource":credential["resource"]})
        } else {
            return Err(Failure::Capability);
        };
        require(
            step["payload_sha256"] == hash("broil-infra-step-v1", &payload)?,
            Failure::Integrity,
        )?;
        Ok(payload)
    }
}
