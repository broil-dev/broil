// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::issuer::Lifecycle;
use super::{Failure, Result, Snapshot, hash, require};
use serde_json::{Value, json};

pub(super) const RECIPE_DOMAIN: &str = "broil-k3s-server-recipe-v2";
pub(super) const IDENTITY_DOMAIN: &str = "broil-k3s-server-recipe-identity-v2";

pub(super) fn recipe_hash(recipe: &Value) -> Result<String> {
    hash(
        if recipe["schema"] == 3 {
            "broil-k3s-agent-recipe-v1"
        } else if recipe.get("source").is_some() {
            "broil-k3s-join-recipe-v2"
        } else {
            RECIPE_DOMAIN
        },
        recipe,
    )
}

pub(super) fn recipe_identity_projection(recipe: &Value) -> Result<Value> {
    let mut projection = recipe.clone();
    let fields = projection.as_object_mut().ok_or(Failure::Integrity)?;
    for key in ["operation", "attempt", "members"] {
        fields.remove(key).ok_or(Failure::Integrity)?;
    }
    if fields.contains_key("source") {
        fields.remove("installed").ok_or(Failure::Integrity)?;
    }
    if recipe["schema"] == 3 {
        fields.remove("wave").ok_or(Failure::Integrity)?;
    }
    let member = fields
        .get_mut("member")
        .and_then(Value::as_object_mut)
        .ok_or(Failure::Integrity)?;
    member.insert("node_uid".into(), Value::Null);
    Ok(projection)
}

pub(super) fn recipe_identity(recipe: &Value) -> Result<String> {
    hash(
        if recipe["schema"] == 3 {
            "broil-k3s-agent-recipe-identity-v1"
        } else if recipe.get("source").is_some() {
            "broil-k3s-join-recipe-identity-v2"
        } else {
            IDENTITY_DOMAIN
        },
        &recipe_identity_projection(recipe)?,
    )
}

fn joins(action: &Value) -> bool {
    matches!(action.as_str(), Some("join-server" | "join-agent"))
}

pub(super) fn first_server_action(action: &str) -> bool {
    matches!(
        action,
        "lifecycle:activate-server"
            | "lifecycle:start-server"
            | "lifecycle:observe-server"
            | "lifecycle:publish-identity"
    )
}

pub(super) fn lifecycle_inspection(action: &str) -> bool {
    matches!(
        action,
        "lifecycle:inspect-installation"
            | "lifecycle:observe-server"
            | "lifecycle:inspect-owned-server"
            | "lifecycle:inspect-join"
            | "lifecycle:observe-membership"
            | "lifecycle:observe-join"
            | "lifecycle:inspect-agent"
            | "lifecycle:observe-agent-membership"
            | "lifecycle:observe-agent"
            | "lifecycle:network-inspect-host"
            | "lifecycle:network-inspect-objects"
            | "lifecycle:ingress-inspect-host"
            | "lifecycle:ingress-inspect-objects"
            | "lifecycle:cert-manager-inspect-host"
            | "lifecycle:cert-manager-inspect-objects"
            | "lifecycle:issuer-inspect-objects"
            | "lifecycle:certificate-inspect-objects"
            | "lifecycle:registry-storage-inspect-storage"
            | "lifecycle:registry-storage-inspect-objects"
            | "lifecycle:registry-service-inspect-host"
            | "lifecycle:registry-service-inspect-objects"
            | "lifecycle:registry-endpoint-inspect-objects"
            | "lifecycle:registry-auth-inspect-objects"
            | "lifecycle:registry-token-inspect-host"
            | "lifecycle:registry-token-inspect-objects"
            | "lifecycle:registry-replication-inspect-replication"
            | "lifecycle:registry-replication-inspect-objects"
            | "lifecycle:delivery-inspect-images"
            | "lifecycle:delivery-check-closure"
            | "lifecycle:delivery-read-origin-log"
            | "lifecycle:node-observe-node"
            | "lifecycle:node-observe-drain"
    )
}

pub(super) fn undispatched_transport() -> Value {
    json!({"dispatch":"none","exit":null,"signal":null,"input_released":true,"staging_cleanup":"clean"})
}

impl Snapshot {
    fn cited_assets(&self, step: &Value) -> Result<(Vec<Value>, Vec<Value>)> {
        let mut refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        let Some(event) = self
            .observations
            .iter()
            .find(|o| o["event"]["type"] == "component-assets")
        else {
            return Ok((refs, Vec::new()));
        };
        require(
            refs.len() >= 2
                && refs[1] == event["sequence"]
                && event["operation"] == step["operation"],
            Failure::Ownership,
        )?;
        refs.remove(1);
        Ok((refs, super::component_assets(self)))
    }

    pub(super) fn network_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        require(
            action.starts_with("lifecycle:network-"),
            Failure::Capability,
        )?;
        let (refs, assets) = self.cited_assets(step)?;
        let refs = &refs;
        require(
            (1..=5).contains(&refs.len()) && self.request["action"] == "reconcile-network",
            Failure::Integrity,
        )?;
        let recipe_event = self
            .observations
            .iter()
            .find(|o| o["sequence"] == refs[0])
            .ok_or(Failure::Integrity)?;
        require(
            recipe_event["event"]["type"] == "network-recipe"
                && recipe_event["attempt"] == step["attempt"]
                && recipe_event["operation"] == step["operation"],
            Failure::Ownership,
        )?;
        let (recipe, original) =
            super::derived_recipe(&recipe_event["event"]["recipe"], &self.request, &assets)?;
        let recipe = &recipe;
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["members"] == self.request["members"]
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"],
            Failure::Ownership,
        )?;
        let (ordinal, resource, preflight) = if action == "lifecycle:network-create-object" {
            let kinds: &[&str] = if self.request["members"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .iter()
                .any(|member| member["role"] == "agent")
            {
                &[
                    "network-observation",
                    "server-membership",
                    "agent-membership",
                    "network-observation",
                ]
            } else {
                &[
                    "network-observation",
                    "server-membership",
                    "network-observation",
                ]
            };
            require(refs.len() == kinds.len() + 1, Failure::Integrity)?;
            for (index, kind) in kinds
                .iter()
                .enumerate()
                .map(|(index, kind)| (index + 1, *kind))
            {
                let observed = self
                    .observations
                    .iter()
                    .find(|o| o["sequence"] == refs[index])
                    .ok_or(Failure::Integrity)?;
                require(
                    observed["event"]["type"] == kind
                        && observed["attempt"] == step["attempt"]
                        && observed["operation"] == step["operation"],
                    Failure::Integrity,
                )?;
            }
            require(
                !self
                    .observations
                    .iter()
                    .find(|o| o["sequence"] == refs[1])
                    .ok_or(Failure::Integrity)?["event"]["member"]
                    .is_null(),
                Failure::Integrity,
            )?;
            let resource = &step["resource"];
            let request_resources = self.request["resources"]
                .as_array()
                .ok_or(Failure::Integrity)?;
            let ordinal = request_resources
                .iter()
                .position(|r| r == resource)
                .ok_or(Failure::Ownership)?
                + 1;
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == refs[refs.len() - 1])
                .ok_or(Failure::Integrity)?;
            require(
                observation["event"]["type"] == "network-observation"
                    && observation["event"]["member"].is_null()
                    && observation["attempt"] == step["attempt"]
                    && observation["operation"] == step["operation"],
                Failure::Integrity,
            )?;
            (
                json!(ordinal),
                resource.clone(),
                observation["event"]["objects"].clone(),
            )
        } else {
            require(
                refs.len() == 1 && step["resource"].is_null(),
                Failure::Integrity,
            )?;
            (Value::Null, Value::Null, Value::Null)
        };
        let payload = json!({"recipe":recipe,"original_recipe_sha256":original,
            "object_ordinal":ordinal,"resource":resource,"preflight":preflight});
        self.shaped("network", payload, step)
    }

    fn shaped(&self, family: &str, payload: Value, step: &Value) -> Result<Value> {
        for shape in crate::k3s::shapes::candidates(&self.request["schema"], true, family, &payload)
        {
            if hash("broil-infra-step-v1", &shape)? == step["payload_sha256"] {
                return Ok(shape);
            }
        }
        Err(Failure::Integrity)
    }

    pub(super) fn ingress_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        require(
            action.starts_with("lifecycle:ingress-"),
            Failure::Capability,
        )?;
        let (refs, assets) = self.cited_assets(step)?;
        let refs = &refs;
        require(
            (1..=4).contains(&refs.len()) && self.request["action"] == "reconcile-ingress",
            Failure::Integrity,
        )?;
        let observed = |index: usize| -> Result<&Value> {
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == refs[index])
                .ok_or(Failure::Integrity)?;
            require(
                observation["attempt"] == step["attempt"]
                    && observation["operation"] == step["operation"],
                Failure::Ownership,
            )?;
            Ok(observation)
        };
        let recipe_event = observed(0)?;
        require(
            recipe_event["event"]["type"] == "ingress-recipe",
            Failure::Ownership,
        )?;
        let (recipe, original) =
            super::derived_recipe(&recipe_event["event"]["recipe"], &self.request, &assets)?;
        let recipe = &recipe;
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["members"] == self.request["members"]
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"],
            Failure::Ownership,
        )?;
        let resources = self.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let resource = &step["resource"];
        let (ordinal, preflight) = match action {
            "lifecycle:ingress-create-object" => {
                let agents = recipe["members"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .iter()
                    .any(|member| member["role"] == "agent");
                let kinds: &[&str] = if agents {
                    &[
                        "server-membership",
                        "agent-membership",
                        "ingress-observation",
                    ]
                } else {
                    &["server-membership", "ingress-observation"]
                };
                require(refs.len() == kinds.len() + 1, Failure::Integrity)?;
                for (index, kind) in kinds.iter().enumerate() {
                    require(
                        observed(index + 1)?["event"]["type"] == *kind,
                        Failure::Integrity,
                    )?;
                }
                let objects = &observed(refs.len() - 1)?["event"];
                require(objects["member"].is_null(), Failure::Integrity)?;
                let ordinal = resources
                    .iter()
                    .skip(
                        resources
                            .len()
                            .saturating_sub(super::ingress::INGRESS_OBJECTS.len()),
                    )
                    .position(|r| r == resource)
                    .ok_or(Failure::Ownership)?
                    + 1;
                (
                    json!(ordinal),
                    json!({"objects":objects["objects"],"results":objects["results"]}),
                )
            }
            "lifecycle:ingress-import-image" => {
                require(
                    refs.len() == 1
                        && resource["kind"] == "bootstrap-assets"
                        && resource["machine"] == step["recipient"]["machine"]
                        && resources.contains(resource),
                    Failure::Ownership,
                )?;
                (Value::Null, Value::Null)
            }
            _ => {
                require(refs.len() == 1 && resource.is_null(), Failure::Integrity)?;
                (Value::Null, Value::Null)
            }
        };
        let payload = json!({"recipe":recipe,"original_recipe_sha256":original,
            "object_ordinal":ordinal,"resource":resource,"preflight":preflight});
        self.shaped("ingress", payload, step)
    }

    pub(super) fn cert_manager_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        require(
            action.starts_with("lifecycle:cert-manager-"),
            Failure::Capability,
        )?;
        let (refs, assets) = self.cited_assets(step)?;
        let refs = &refs;
        require(
            (1..=4).contains(&refs.len()) && self.request["action"] == "reconcile-cert-manager",
            Failure::Integrity,
        )?;
        let observed = |index: usize| -> Result<&Value> {
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == refs[index])
                .ok_or(Failure::Integrity)?;
            require(
                observation["operation"] == step["operation"]
                    && (observation["attempt"] == step["attempt"]
                        || observation["step"].is_null()
                            && observation["event"]["type"] == "cert-manager-observation"),
                Failure::Ownership,
            )?;
            Ok(observation)
        };
        let recipe_event = observed(0)?;
        require(
            recipe_event["event"]["type"] == "cert-manager-recipe",
            Failure::Ownership,
        )?;
        let (recipe, original) =
            super::derived_recipe(&recipe_event["event"]["recipe"], &self.request, &assets)?;
        let recipe = &recipe;
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["members"] == self.request["members"]
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"],
            Failure::Ownership,
        )?;
        let resources = self.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let resource = &step["resource"];
        let objects = |observation: &Value| -> Result<Value> {
            let event = &observation["event"];
            require(
                event["type"] == "cert-manager-observation"
                    && event["member"].is_null()
                    && event["objects"].is_array(),
                Failure::Integrity,
            )?;
            Ok(event["objects"].clone())
        };
        let (uids, preflight) = match action {
            "lifecycle:cert-manager-create-objects" => {
                let agents = recipe["members"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .iter()
                    .any(|member| member["role"] == "agent");
                let kinds: &[&str] = if agents {
                    &["server-membership", "agent-membership"]
                } else {
                    &["server-membership"]
                };
                require(
                    refs.len() == kinds.len() + 2
                        && resources.last() == Some(resource)
                        && resource["id"] == "cert-manager-object-01",
                    Failure::Integrity,
                )?;
                for (index, kind) in kinds.iter().enumerate() {
                    require(
                        observed(index + 1)?["event"]["type"] == *kind,
                        Failure::Integrity,
                    )?;
                }
                let latest = observed(refs.len() - 1)?;
                require(!latest["event"]["services"].is_null(), Failure::Integrity)?;
                (Value::Null, objects(latest)?)
            }
            "lifecycle:cert-manager-import-images" => {
                require(
                    refs.len() == 1
                        && resource["kind"] == "bootstrap-assets"
                        && resource["machine"] == step["recipient"]["machine"]
                        && resources.contains(resource),
                    Failure::Ownership,
                )?;
                (Value::Null, Value::Null)
            }
            "lifecycle:cert-manager-inspect-objects" if refs.len() == 2 => {
                require(resource.is_null(), Failure::Integrity)?;
                let source = objects(observed(1)?)?;
                let uids = source
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .iter()
                    .map(|record| record["uid"].clone())
                    .collect();
                (Value::Array(uids), Value::Null)
            }
            _ => {
                require(refs.len() == 1 && resource.is_null(), Failure::Integrity)?;
                (Value::Null, Value::Null)
            }
        };
        let payload = json!({"recipe":recipe,"original_recipe_sha256":original,"uids":uids,
            "resource":resource,"preflight":preflight});
        self.shaped("cert-manager", payload, step)
    }

    pub(super) fn issuer_payload(&self, step: &Value) -> Result<Value> {
        let reproduce = |recipe: &Value, bound: &Value| {
            let issuer = recipe["issuer"].as_str().ok_or(Failure::Integrity)?;
            super::issuer::projection(
                &self.request,
                issuer,
                &step["operation"],
                &step["attempt"],
                bound,
            )
        };
        let lifecycle = &super::issuer::LIFECYCLE;
        self.secret_payload(lifecycle, step, super::issuer::expected, &reproduce)
    }

    pub(super) fn registry_auth_payload(&self, step: &Value) -> Result<Value> {
        let reproduce = |_: &Value, bound: &Value| {
            super::registry_auth::projection(
                &self.request,
                &step["operation"],
                &step["attempt"],
                bound,
            )
        };
        let lifecycle = &super::registry_auth::LIFECYCLE;
        self.secret_payload(lifecycle, step, super::registry_auth::expected, &reproduce)
    }

    fn secret_payload(
        &self,
        lifecycle: &Lifecycle,
        step: &Value,
        expected: fn(&Value) -> Value,
        reproduce: &dyn Fn(&Value, &Value) -> Result<Value>,
    ) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        let tag = action
            .strip_prefix(lifecycle.action("").as_str())
            .ok_or(Failure::Capability)?;
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let observation = lifecycle.event("observation");
        require(
            (1..=5).contains(&refs.len())
                && self.request["action"] == format!("reconcile-{}", lifecycle.family.name),
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
        require(
            recipe_event["event"]["type"] == lifecycle.event("recipe"),
            Failure::Ownership,
        )?;
        let recipe = &recipe_event["event"]["recipe"];
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["first_server"] == self.request["members"][0]
                && recipe["resource"] == self.request["resources"][0]
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && step["recipient"] == self.request["members"][0],
            Failure::Ownership,
        )?;
        let mutation = tag != "inspect-objects";
        let mut expected = expected(recipe);
        let (mut read, mut identity, mut memberships) = (None, false, 0);
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            let reply = event["type"] == observation.as_str() && event["services"].is_null();
            match event["type"].as_str() {
                Some("server-membership" | "agent-membership") if mutation => memberships += 1,
                Some(kind) if kind == observation && mutation && !reply && read.is_none() => {
                    read = Some(event);
                }
                Some("identity") if tag == "register-input" && !identity => {
                    expected["secret"] = event["resources"][0]["uid"].clone();
                    identity = true;
                }
                Some("receiver")
                    if !mutation
                        && event["receipt"]["action"] == lifecycle.action("create-object") =>
                {
                    expected["secret"] = event["receipt"]["resource_identity"].clone();
                }
                Some(kind)
                    if kind == observation
                        && !mutation
                        && reply
                        && !lifecycle.registration(event).is_null() =>
                {
                    let fact = lifecycle.registration(event);
                    expected["registration"] = json!({"directory":fact["directory"],"record_sha256":fact["record_sha256"]});
                }
                Some("issuer-observation") if !mutation && reply && !event["objects"].is_null() => {
                    expected["cluster_issuer"] = event["objects"][0]["uid"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let agents = self.request["members"]
            .as_array()
            .is_some_and(|members| members.iter().any(|m| m["role"] == "agent"));
        let (resource, preflight, projection) = if mutation {
            let read = read.ok_or(Failure::Integrity)?;
            require(
                memberships == 1 + usize::from(agents) && identity == (tag == "register-input"),
                Failure::Integrity,
            )?;
            let resource = self.request["resources"][0].clone();
            let projection = if identity {
                let mut bound = resource.clone();
                bound["uid"] = expected["secret"].clone();
                reproduce(recipe, &bound)?
            } else {
                Value::Null
            };
            let mut preflight = json!({"objects":read["objects"]});
            for fact in lifecycle.facts {
                preflight[*fact] = read[*fact].clone();
            }
            (resource, preflight, projection)
        } else {
            (Value::Null, Value::Null, Value::Null)
        };
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight,"projection":projection});
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    pub(super) fn certificate_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        let tag = action
            .strip_prefix("lifecycle:certificate-")
            .ok_or(Failure::Capability)?;
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            (1..=4).contains(&refs.len()) && self.request["action"] == "reconcile-certificate",
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
        require(
            recipe_event["event"]["type"] == "certificate-recipe",
            Failure::Ownership,
        )?;
        let recipe = &recipe_event["event"]["recipe"];
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["first_server"] == self.request["members"][0]
                && recipe["resource"] == self.request["resources"][0]
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && step["recipient"] == self.request["members"][0],
            Failure::Ownership,
        )?;
        let mutation = tag != "inspect-objects";
        let mut expected = super::certificate::expected(recipe);
        let (mut read, mut memberships) = (None, 0);
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            match event["type"].as_str() {
                Some("server-membership" | "agent-membership") if mutation => memberships += 1,
                Some("certificate-observation") if mutation && read.is_none() => read = Some(event),
                Some("receiver")
                    if !mutation
                        && event["receipt"]["action"] == "lifecycle:certificate-create-object" =>
                {
                    expected["certificate"] = event["receipt"]["resource_identity"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let agents = self.request["members"]
            .as_array()
            .is_some_and(|members| members.iter().any(|m| m["role"] == "agent"));
        let (resource, preflight) = if mutation {
            let read = read.ok_or(Failure::Integrity)?;
            require(memberships == 1 + usize::from(agents), Failure::Integrity)?;
            (
                self.request["resources"][0].clone(),
                json!({"objects":read["objects"],"certificate":read["certificate"]}),
            )
        } else {
            (Value::Null, Value::Null)
        };
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight});
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    pub(super) fn registry_storage_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        let tag = action
            .strip_prefix("lifecycle:registry-storage-")
            .ok_or(Failure::Capability)?;
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            (1..=4).contains(&refs.len()) && self.request["action"] == "reconcile-registry-storage",
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
        require(
            recipe_event["event"]["type"] == "registry-storage-recipe",
            Failure::Ownership,
        )?;
        let recipe = &recipe_event["event"]["recipe"];
        let host = matches!(tag, "inspect-storage" | "create-storage");
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        if recipe.get("storage_member").is_none() {
            return self.replica_storage_payload(step, tag, refs, recipe, &observed);
        }
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["first_server"] == members[0]
                && members.contains(&recipe["storage_member"])
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && step["recipient"]
                    == recipe[if host {
                        "storage_member"
                    } else {
                        "first_server"
                    }],
            Failure::Ownership,
        )?;
        let mutation = tag.starts_with("create-");
        let origin = &recipe["origins"]["directory"];
        let directory = if origin.is_null() {
            Value::Null
        } else {
            json!({"record_sha256":origin["record_sha256"],"directory":origin["directory"],
                "data":origin["data"],"fsid":origin["fsid"]})
        };
        let mut expected =
            json!({"directory":directory,"volume":recipe["origins"]["volume"]["uid"]});
        let (mut read, mut memberships) = (None, 0);
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            match event["type"].as_str() {
                Some("server-membership" | "agent-membership") if mutation => memberships += 1,
                Some("registry-storage-observation")
                    if mutation && read.is_none() && event["member"].is_null() != host =>
                {
                    read = Some(event);
                }
                Some("receiver")
                    if !mutation
                        && event["receipt"]["action"]
                            == "lifecycle:registry-storage-create-object" =>
                {
                    expected["volume"] = event["receipt"]["resource_identity"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let agents = members.iter().any(|m| m["role"] == "agent");
        let (resource, preflight) = if mutation {
            let read = read.ok_or(Failure::Integrity)?;
            require(memberships == 1 + usize::from(agents), Failure::Integrity)?;
            (
                self.request["resources"][usize::from(!host)].clone(),
                if host {
                    read["storage"].clone()
                } else {
                    json!({"objects":read["objects"],"volume":read["volume"],"node":read["node"],
                        "cordoned":read["cordoned"]})
                },
            )
        } else {
            (Value::Null, Value::Null)
        };
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight});
        self.shaped("registry-storage", payload, step)
    }

    fn replica_storage_payload<'s>(
        &'s self,
        step: &Value,
        tag: &str,
        refs: &[Value],
        recipe: &Value,
        observed: &dyn Fn(&Value) -> Result<&'s Value>,
    ) -> Result<Value> {
        let host = matches!(tag, "inspect-storage" | "create-storage");
        let mutation = tag == "create-storage";
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let first = members
            .iter()
            .find(|m| m["role"] == "server")
            .ok_or(Failure::Integrity)?;
        let index = members.iter().position(|m| *m == step["recipient"]);
        require(
            matches!(
                tag,
                "inspect-storage" | "create-storage" | "inspect-objects"
            ) && recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["members"] == self.request["members"]
                && recipe["first_server"] == *first
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && (host && index.is_some() || !host && step["recipient"] == *first),
            Failure::Ownership,
        )?;
        let index = index.filter(|_| host);
        let mut payload = super::registry_storage::read_payload(recipe, index);
        require(
            refs.len()
                == if mutation { 3 } else { 1 }
                    + usize::from(mutation && members.iter().any(|m| m["role"] == "agent")),
            Failure::Integrity,
        )?;
        if mutation {
            let index = index.ok_or(Failure::Integrity)?;
            let (mut read, mut memberships) = (None, 0);
            for sequence in &refs[1..] {
                let event = &observed(sequence)?["event"];
                match event["type"].as_str() {
                    Some("server-membership" | "agent-membership") => memberships += 1,
                    Some("registry-storage-observation")
                        if read.is_none() && event["member"] == step["recipient"] =>
                    {
                        read = Some(event);
                    }
                    _ => return Err(Failure::Integrity),
                }
            }
            let read = read.ok_or(Failure::Integrity)?;
            require(memberships == refs.len() - 2, Failure::Integrity)?;
            payload["resource"] = self.request["resources"][index].clone();
            payload["preflight"] = read["storage"].clone();
        }
        self.shaped("registry-storage", payload, step)
    }

    pub(super) fn registry_service_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        let tag = action
            .strip_prefix("lifecycle:registry-service-")
            .ok_or(Failure::Capability)?;
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            (1..=10).contains(&refs.len())
                && self.request["action"] == "reconcile-registry-service",
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
        require(
            recipe_event["event"]["type"] == "registry-service-recipe",
            Failure::Ownership,
        )?;
        let recipe = &recipe_event["event"]["recipe"];
        let host = matches!(tag, "inspect-host" | "import-image");
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let resources = self.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        if recipe.get("storage_member").is_none() {
            return self.writer_service_payload(step, tag, refs, recipe, &observed);
        }
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["first_server"] == members[0]
                && members.contains(&recipe["storage_member"])
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && step["recipient"]
                    == recipe[if host {
                        "storage_member"
                    } else {
                        "first_server"
                    }]
                && resources.len() == 7,
            Failure::Ownership,
        )?;
        let mutation = matches!(tag, "import-image" | "create-object");
        let origin = &recipe["storage"]["origins"]["directory"];
        let directory = if origin.is_null() {
            Value::Null
        } else {
            json!({"record_sha256":origin["record_sha256"],"directory":origin["directory"],
                "data":origin["data"],"fsid":origin["fsid"]})
        };
        let objects: Vec<Value> = recipe["origins"]["objects"]
            .as_array()
            .map_or_else(Vec::new, |o| o.iter().map(|o| o["uid"].clone()).collect());
        let mut expected = json!({"storage":{"directory":directory,
            "volume":recipe["storage"]["origins"]["volume"]["uid"]},"objects":objects});
        let (mut read, mut memberships) = (None, 0);
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            match event["type"].as_str() {
                Some("server-membership" | "agent-membership") if mutation => memberships += 1,
                Some("registry-service-observation")
                    if mutation && read.is_none() && event["member"].is_null() != host =>
                {
                    read = Some(event);
                }
                Some("receiver")
                    if event["receipt"]["action"] == "lifecycle:registry-service-create-object" =>
                {
                    let ordinal = resources
                        .iter()
                        .position(|r| r["id"] == event["receipt"]["resource"]["id"])
                        .filter(|n| *n > 0)
                        .ok_or(Failure::Integrity)?;
                    require(
                        expected["objects"][ordinal - 1].is_null(),
                        Failure::Integrity,
                    )?;
                    expected["objects"][ordinal - 1] =
                        event["receipt"]["resource_identity"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let agents = members.iter().any(|m| m["role"] == "agent");
        let (resource, preflight, ordinal) = if mutation {
            let read = read.ok_or(Failure::Integrity)?;
            require(memberships == 1 + usize::from(agents), Failure::Integrity)?;
            if host {
                (
                    resources[0].clone(),
                    json!({"generation":read["generation"],"image":read["image"],
                        "runtime":read["runtime"]}),
                    Value::Null,
                )
            } else {
                let ordinal = resources
                    .iter()
                    .position(|r| *r == step["resource"])
                    .filter(|n| *n > 0)
                    .ok_or(Failure::Integrity)?;
                (
                    resources[ordinal].clone(),
                    json!({"objects":read["objects"],"volume":read["volume"],"node":read["node"],
                        "cordoned":read["cordoned"]}),
                    json!(ordinal),
                )
            }
        } else {
            (Value::Null, Value::Null, Value::Null)
        };
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight,"object_ordinal":ordinal});
        self.shaped("registry-service", payload, step)
    }

    fn writer_service_payload<'s>(
        &'s self,
        step: &Value,
        tag: &str,
        refs: &[Value],
        recipe: &Value,
        observed: &dyn Fn(&Value) -> Result<&'s Value>,
    ) -> Result<Value> {
        let host = matches!(tag, "inspect-host" | "import-image");
        let mutation = matches!(tag, "import-image" | "create-object");
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let resources = self.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let offset = resources.len().checked_sub(5).ok_or(Failure::Integrity)?;
        let first = members
            .iter()
            .find(|m| m["role"] == "server")
            .ok_or(Failure::Integrity)?;
        let index = members.iter().position(|m| *m == step["recipient"]);
        require(
            matches!(
                tag,
                "inspect-host" | "import-image" | "inspect-objects" | "create-object"
            ) && recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["members"] == self.request["members"]
                && recipe["first_server"] == *first
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && (host && index.is_some() || !host && step["recipient"] == *first),
            Failure::Ownership,
        )?;
        let index = index.filter(|_| host);
        let mut objects = super::registry_service::expected(recipe, None)["objects"].clone();
        let (mut read, mut memberships) = (None, 0);
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            match event["type"].as_str() {
                Some("server-membership" | "agent-membership") if mutation => memberships += 1,
                Some("registry-service-observation")
                    if mutation
                        && read.is_none()
                        && if host {
                            event["member"] == step["recipient"]
                        } else {
                            event["member"].is_null()
                        } =>
                {
                    read = Some(event);
                }
                Some("receiver")
                    if event["receipt"]["action"] == "lifecycle:registry-service-create-object" =>
                {
                    let ordinal = resources[offset..]
                        .iter()
                        .position(|r| r["id"] == event["receipt"]["resource"]["id"])
                        .ok_or(Failure::Integrity)?;
                    require(objects[ordinal].is_null(), Failure::Integrity)?;
                    objects[ordinal] = event["receipt"]["resource_identity"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let mut payload = super::registry_service::read_payload(recipe, index, &objects);
        if mutation {
            let read = read.ok_or(Failure::Integrity)?;
            let agents = members.iter().any(|m| m["role"] == "agent");
            require(memberships == 1 + usize::from(agents), Failure::Integrity)?;
            let position = resources
                .iter()
                .position(|r| *r == step["resource"])
                .ok_or(Failure::Integrity)?;
            if host {
                require(
                    position < offset
                        && step["resource"]["machine"] == step["recipient"]["machine"],
                    Failure::Integrity,
                )?;
                payload["preflight"] = json!({"generation":read["generation"],
                    "image":read["image"],"runtime":read["runtime"]});
            } else {
                require(position >= offset, Failure::Integrity)?;
                payload["preflight"] = json!({"objects":read["objects"],"nodes":read["nodes"]});
                payload["object_ordinal"] = json!(position - offset + 1);
            }
            payload["resource"] = step["resource"].clone();
        }
        self.shaped("registry-service", payload, step)
    }

    pub(super) fn registry_endpoint_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        let tag = action
            .strip_prefix("lifecycle:registry-endpoint-")
            .ok_or(Failure::Capability)?;
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            (1..=6).contains(&refs.len())
                && self.request["action"] == "reconcile-registry-endpoint",
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
        require(
            recipe_event["event"]["type"] == "registry-endpoint-recipe",
            Failure::Ownership,
        )?;
        let recipe = &recipe_event["event"]["recipe"];
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let resources = self.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["first_server"] == members[0]
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && step["recipient"] == recipe["first_server"]
                && resources.len() == 4,
            Failure::Ownership,
        )?;
        let create = tag == "create-object";
        let mut expected = super::registry_endpoint::expected(recipe);
        let (mut read, mut memberships) = (None, 0);
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            match event["type"].as_str() {
                Some("server-membership" | "agent-membership") if create => memberships += 1,
                Some("registry-endpoint-observation") if create && read.is_none() => {
                    read = Some(event);
                }
                Some("receiver")
                    if event["receipt"]["action"]
                        == "lifecycle:registry-endpoint-create-object" =>
                {
                    let ordinal = resources
                        .iter()
                        .position(|r| r["id"] == event["receipt"]["resource"]["id"])
                        .filter(|n| *n > 0)
                        .ok_or(Failure::Integrity)?;
                    require(
                        expected["objects"][ordinal - 1].is_null(),
                        Failure::Integrity,
                    )?;
                    expected["objects"][ordinal - 1] =
                        event["receipt"]["resource_identity"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let (resource, preflight, ordinal) = if create {
            let read = read.ok_or(Failure::Integrity)?;
            let agents = members.iter().any(|m| m["role"] == "agent");
            require(memberships == 1 + usize::from(agents), Failure::Integrity)?;
            let ordinal = resources
                .iter()
                .position(|r| *r == step["resource"])
                .filter(|n| *n > 0)
                .ok_or(Failure::Integrity)?;
            (
                resources[ordinal].clone(),
                json!({"objects":read["objects"],"issued":read["issued"]}),
                json!(ordinal),
            )
        } else {
            (Value::Null, Value::Null, Value::Null)
        };
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight,"object_ordinal":ordinal});
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    fn recipient(&self, recipe: &Value, host: bool, recipient: &Value) -> bool {
        if !host {
            recipe["first_server"] == *recipient
        } else if recipe.get("storage_member").is_some() {
            recipe["storage_member"] == *recipient
        } else {
            self.request["members"]
                .as_array()
                .is_some_and(|m| m.contains(recipient))
        }
    }

    pub(super) fn registry_replication_payload(&self, step: &Value) -> Result<Value> {
        use super::registry_replication as replication;
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        let tag = action
            .strip_prefix("lifecycle:registry-replication-")
            .ok_or(Failure::Capability)?;
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        if super::member::carries(&self.request["action"]) {
            return self.member_device_payload(step);
        }
        require(
            !refs.is_empty() && self.request["action"] == "reconcile-registry-replication",
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
        require(
            recipe_event["event"]["type"] == "replication-recipe",
            Failure::Ownership,
        )?;
        let recipe = &recipe_event["event"]["recipe"];
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let resources = self.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let m = members.len();
        let listed = recipe["members"].as_array().ok_or(Failure::Integrity)?;
        let first = members
            .iter()
            .find(|m| m["role"] == "server")
            .ok_or(Failure::Integrity)?;
        let index = members.iter().position(|m| *m == step["recipient"]);
        let host = replication::host(tag);
        let mutation = replication::mutation(tag);
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["first_server"] == *first
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && resources.len() == 2 * m + 2
                && listed.len() == m
                && listed.iter().zip(members).all(|(entry, member)| {
                    let mut entry = entry.clone();
                    entry.as_object_mut().map(|e| e.remove("node_ip"));
                    entry == *member
                })
                && (host && index.is_some() || !host && step["recipient"] == *first),
            Failure::Ownership,
        )?;
        let mut objects = replication::origin_uids(recipe);
        let mut filled = vec![Value::Null; m];
        let mut memberships = 0;
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            match event["type"].as_str() {
                Some("server-membership" | "agent-membership") if mutation => memberships += 1,
                Some(replication::OBSERVATION) if !event["member"].is_null() => {
                    let n = members
                        .iter()
                        .position(|m| *m == event["member"])
                        .ok_or(Failure::Integrity)?;
                    require(
                        event["replication"]["record"] == "owned"
                            && event["replication"]["device_id"].is_string()
                            && recipe["devices"][n]["device_id"].is_null()
                            && filled[n].is_null(),
                        Failure::Integrity,
                    )?;
                    filled[n] = event["replication"]["device_id"].clone();
                }
                Some("receiver")
                    if event["receipt"]["action"]
                        == "lifecycle:registry-replication-create-object" =>
                {
                    let n = crate::k3s::replication::OBJECTS
                        .iter()
                        .position(|id| event["receipt"]["resource"]["id"] == *id)
                        .ok_or(Failure::Integrity)?;
                    require(objects[n].is_null(), Failure::Integrity)?;
                    objects[n] = event["receipt"]["resource_identity"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let resource = if mutation {
            let agents = members.iter().any(|m| m["role"] == "agent");
            require(memberships == 1 + usize::from(agents), Failure::Integrity)?;
            let position = resources
                .iter()
                .position(|r| *r == step["resource"])
                .ok_or(Failure::Integrity)?;
            let admitted = match index.filter(|_| host) {
                Some(index) if tag == "create-replica" => position == index,
                Some(index) => position == m + index,
                None => position >= 2 * m,
            };
            require(admitted, Failure::Integrity)?;
            step["resource"].clone()
        } else {
            Value::Null
        };
        let member = match index.filter(|_| host) {
            Some(index) => members[index]["member"].clone(),
            None => Value::Null,
        };
        let payload = json!({"recipe":replication::effective(recipe, &filled),
            "expected":replication::expected(&objects),"resource":resource,"preflight":null,
            "wait_ms":replication::wait_ms(tag, &self.request),"member":member});
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    pub(super) fn registry_token_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        let tag = action
            .strip_prefix("lifecycle:registry-token-")
            .ok_or(Failure::Capability)?;
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            (1..=12).contains(&refs.len()) && self.request["action"] == "reconcile-registry-token",
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
        require(
            recipe_event["event"]["type"] == "registry-token-recipe",
            Failure::Ownership,
        )?;
        let recipe = &recipe_event["event"]["recipe"];
        let host = matches!(tag, "inspect-host" | "import-image");
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let resources = self.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        if recipe.get("storage_member").is_none() {
            return self.token_v2_payload(step, tag, refs, recipe, &observed);
        }
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["first_server"] == members[0]
                && members.contains(&recipe["storage_member"])
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && step["recipient"]
                    == recipe[if host {
                        "storage_member"
                    } else {
                        "first_server"
                    }],
            Failure::Ownership,
        )?;
        let mutation = !tag.starts_with("inspect-");
        let mut expected = super::registry_token::expected(recipe);
        let (mut read, mut memberships) = (None, 0);
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            let receipt = &event["receipt"];
            match (event["type"].as_str(), receipt["action"].as_str()) {
                (Some("server-membership" | "agent-membership"), _) if mutation => memberships += 1,
                (Some("registry-token-observation"), _)
                    if mutation
                        && read.is_none()
                        && event["member"].is_null() != host
                        && (host || !event["objects"].is_null()) =>
                {
                    read = Some(event);
                }
                (Some("receiver"), Some("lifecycle:registry-token-create-object")) => {
                    let ordinal = resources
                        .iter()
                        .position(|r| r["id"] == receipt["resource"]["id"])
                        .filter(|n| *n > 0)
                        .ok_or(Failure::Integrity)?;
                    require(
                        expected["objects"][ordinal - 1].is_null(),
                        Failure::Integrity,
                    )?;
                    expected["objects"][ordinal - 1] = receipt["resource_identity"].clone();
                    if ordinal == 2 {
                        expected["certificate"] = recipe["certificate"]["sha256"].clone();
                    }
                }
                (Some("receiver"), Some("lifecycle:registry-token-configure-token")) => {
                    expected["certificate"] = recipe["certificate"]["sha256"].clone();
                }
                (Some("receiver"), Some("lifecycle:registry-token-switch-registry")) => {
                    expected["configuration"] =
                        json!(super::registry_token::configuration_sha256(recipe)?);
                }
                (Some("receiver"), Some("lifecycle:registry-token-configure-principals")) => {
                    expected["principals"] = recipe["principals"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let (resource, preflight, ordinal) = if mutation {
            let read = read.ok_or(Failure::Integrity)?;
            let agents = members.iter().any(|m| m["role"] == "agent");
            require(memberships == 1 + usize::from(agents), Failure::Integrity)?;
            let position = resources
                .iter()
                .position(|r| *r == step["resource"])
                .ok_or(Failure::Integrity)?;
            let id = resources[position]["id"].as_str().unwrap_or_default();
            require(
                match tag {
                    "import-image" => position == 0 && resources[0]["kind"] == "bootstrap-assets",
                    "create-object" => id.starts_with("registry-token-object-"),
                    "configure-token" | "configure-principals" => id == "registry-token-object-02",
                    _ => id == "registry-service-object-03",
                },
                Failure::Integrity,
            )?;
            let preflight = super::registry_token::preflight_of(tag, read);
            let ordinal = if tag == "create-object" {
                json!(position)
            } else {
                Value::Null
            };
            (resources[position].clone(), preflight, ordinal)
        } else {
            (Value::Null, Value::Null, Value::Null)
        };
        let earlier = self.steps.iter().filter(|s| {
            s["attempt"] == step["attempt"]
                && s["action"] == step["action"]
                && s["step"].as_u64() < step["step"].as_u64()
        });
        let probe = tag == "inspect-objects"
            && recipe["stage"] == "observe"
            && !expected["principals"].is_null()
            && earlier.count() == 2;
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight,"object_ordinal":ordinal,"probe":probe});
        self.shaped("registry-token", payload, step)
    }

    fn token_v2_payload<'s>(
        &'s self,
        step: &Value,
        tag: &str,
        refs: &[Value],
        recipe: &Value,
        observed: &dyn Fn(&Value) -> Result<&'s Value>,
    ) -> Result<Value> {
        let host = matches!(tag, "inspect-host" | "import-image");
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let resources = self.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let offset = resources
            .iter()
            .take_while(|r| r["kind"] == "bootstrap-assets")
            .count();
        let first = members
            .iter()
            .find(|m| m["role"] == "server")
            .ok_or(Failure::Integrity)?;
        let index = members.iter().position(|m| *m == step["recipient"]);
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["members"] == self.request["members"]
                && recipe["first_server"] == *first
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && (host && index.is_some() || !host && step["recipient"] == *first),
            Failure::Ownership,
        )?;
        let mutation = !tag.starts_with("inspect-");
        let mut expected = super::registry_token::expected(recipe);
        let (mut read, mut memberships) = (None, 0);
        for sequence in &refs[1..] {
            let event = &observed(sequence)?["event"];
            let receipt = &event["receipt"];
            match (event["type"].as_str(), receipt["action"].as_str()) {
                (Some("server-membership" | "agent-membership"), _) if mutation => memberships += 1,
                (Some("registry-token-observation"), _)
                    if mutation
                        && read.is_none()
                        && if host {
                            event["member"] == step["recipient"]
                        } else {
                            event["member"].is_null() && !event["objects"].is_null()
                        } =>
                {
                    read = Some(event);
                }
                (Some("receiver"), Some("lifecycle:registry-token-create-object")) => {
                    let ordinal = resources[offset..]
                        .iter()
                        .position(|r| r["id"] == receipt["resource"]["id"])
                        .ok_or(Failure::Integrity)?;
                    require(expected["objects"][ordinal].is_null(), Failure::Integrity)?;
                    expected["objects"][ordinal] = receipt["resource_identity"].clone();
                    if ordinal == 1 {
                        expected["certificate"] = recipe["certificate"]["sha256"].clone();
                    }
                }
                (Some("receiver"), Some("lifecycle:registry-token-configure-token")) => {
                    expected["certificate"] = recipe["certificate"]["sha256"].clone();
                }
                (Some("receiver"), Some("lifecycle:registry-token-switch-registry")) => {
                    expected["configuration"] =
                        json!(super::registry_token::configuration_sha256(recipe)?);
                }
                (Some("receiver"), Some("lifecycle:registry-token-configure-principals")) => {
                    expected["principals"] = recipe["principals"].clone();
                }
                _ => return Err(Failure::Integrity),
            }
        }
        let (resource, preflight, ordinal) = if mutation {
            let read = read.ok_or(Failure::Integrity)?;
            let agents = members.iter().any(|m| m["role"] == "agent");
            require(memberships == 1 + usize::from(agents), Failure::Integrity)?;
            let position = resources
                .iter()
                .position(|r| *r == step["resource"])
                .ok_or(Failure::Integrity)?;
            let id = resources[position]["id"].as_str().unwrap_or_default();
            require(
                match tag {
                    "import-image" => {
                        position < offset
                            && resources[position]["machine"] == step["recipient"]["machine"]
                    }
                    "create-object" => {
                        position >= offset && id.starts_with("registry-token-object-")
                    }
                    "configure-token" | "configure-principals" => id == "registry-token-object-02",
                    _ => id == "registry-service-object-03",
                },
                Failure::Integrity,
            )?;
            let preflight = super::registry_token::preflight_of(tag, read);
            let ordinal = if tag == "create-object" {
                json!(position - offset + 1)
            } else {
                Value::Null
            };
            (resources[position].clone(), preflight, ordinal)
        } else {
            (Value::Null, Value::Null, Value::Null)
        };
        let earlier = self.steps.iter().filter(|s| {
            s["attempt"] == step["attempt"]
                && s["action"] == step["action"]
                && s["step"].as_u64() < step["step"].as_u64()
        });
        let probe = tag == "inspect-objects"
            && recipe["stage"] == "observe"
            && !expected["principals"].is_null()
            && earlier.count() == 2;
        let member = match index.filter(|_| host) {
            Some(index) => recipe["members"][index].clone(),
            None => Value::Null,
        };
        let payload = json!({"recipe":recipe,"expected":expected,"resource":resource,
            "preflight":preflight,"object_ordinal":ordinal,"probe":probe,"member":member});
        self.shaped("registry-token", payload, step)
    }

    fn join_round(&self, step: &Value, count: usize) -> Result<Vec<Value>> {
        let servers: Vec<_> = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .iter()
            .filter(|m| m["role"] == "server")
            .take(count)
            .collect();
        require(servers.len() == count, Failure::Integrity)?;
        let mut round: Vec<_> = self
            .observations
            .iter()
            .rev()
            .filter(|o| {
                o["event"]["type"] == "server-membership"
                    && o["attempt"] == step["attempt"]
                    && o["step"].as_u64() < step["step"].as_u64()
                    && self.steps.iter().any(|source| {
                        source["step"] == o["step"]
                            && source["attempt"] == o["attempt"]
                            && source["action"] == "lifecycle:observe-membership"
                    })
            })
            .take(count)
            .collect();
        round.reverse();
        require(
            round.len() == count
                && round.iter().zip(servers).all(|(o, member)| {
                    o["event"]["member"] == *member && o["event"]["membership"]["healthy"] == true
                }),
            Failure::Integrity,
        )?;
        Ok(round.iter().map(|o| o["sequence"].clone()).collect())
    }

    pub(super) fn deselected(&self, step: &Value) -> bool {
        self.observations.iter().any(|o| {
            o["attempt"] == step["attempt"]
                && o["step"] == step["step"]
                && o["dispatch"] == step["dispatch"]
                && o["source"]["kind"] == "controller"
                && o["event"]["type"] == "dispatch"
                && o["event"]["transport"] == undispatched_transport()
                && o["event"]["outcome"] == "succeeded"
                && o["event"]["failure"].is_null()
        })
    }

    pub(super) fn sealed_work(&self, attempt: &Value, recipient: &Value) -> Vec<&Value> {
        let mut work: Vec<&Value> = self
            .steps
            .iter()
            .filter(|s| {
                s["attempt"] == *attempt
                    && s["recipient"] == *recipient
                    && !matches!(
                        s["action"].as_str(),
                        Some(
                            "seal-writer"
                                | "retire-writer"
                                | "rebind-claim"
                                | "bootstrap:inspect-host"
                                | "bootstrap:inspect-generation"
                                | "lifecycle:inspect-installation"
                                | "lifecycle:observe-server"
                                | "lifecycle:inspect-owned-server"
                                | "lifecycle:inspect-join"
                                | "lifecycle:observe-membership"
                                | "lifecycle:observe-join"
                                | "lifecycle:inspect-agent"
                                | "lifecycle:observe-agent-membership"
                                | "lifecycle:observe-agent"
                                | "lifecycle:network-inspect-host"
                                | "lifecycle:network-inspect-objects"
                                | "lifecycle:ingress-inspect-host"
                                | "lifecycle:ingress-inspect-objects"
                                | "lifecycle:cert-manager-inspect-host"
                                | "lifecycle:cert-manager-inspect-objects"
                                | "lifecycle:issuer-inspect-objects"
                                | "lifecycle:certificate-inspect-objects"
                                | "lifecycle:registry-storage-inspect-storage"
                                | "lifecycle:registry-storage-inspect-objects"
                                | "lifecycle:registry-service-inspect-host"
                                | "lifecycle:registry-service-inspect-objects"
                                | "lifecycle:registry-endpoint-inspect-objects"
                                | "lifecycle:registry-auth-inspect-objects"
                                | "lifecycle:registry-token-inspect-host"
                                | "lifecycle:registry-token-inspect-objects"
                                | "lifecycle:registry-replication-inspect-replication"
                                | "lifecycle:registry-replication-inspect-objects"
                                | "lifecycle:delivery-inspect-images"
                                | "lifecycle:delivery-check-closure"
                                | "lifecycle:delivery-read-origin-log"
                                | "lifecycle:node-observe-node"
                                | "lifecycle:node-observe-drain"
                                | "lifecycle:release-discover-kinds"
                                | "lifecycle:release-inspect-workloads"
                                | "lifecycle:release-observe-release"
                                | "inspect"
                        )
                    )
                    && !self.deselected(s)
            })
            .collect();
        work.sort_by_key(|s| s["step"].as_u64());
        work
    }

    pub(super) fn lifecycle_recipe(&self) -> Result<&Value> {
        let events: Vec<&Value> = self
            .observations
            .iter()
            .filter(|o| o["event"]["type"] == "lifecycle-recipe")
            .collect();
        require(events.len() == 1, Failure::Integrity)?;
        Ok(events[0])
    }

    fn agent_payload(&self, step: &Value, references: &[Value], action: &str) -> Result<Value> {
        let event = self
            .observations
            .iter()
            .find(|o| o["sequence"] == references[0])
            .ok_or(Failure::Integrity)?;
        let recipe = &event["event"]["recipe"];
        let selected = &recipe["member"];
        let recipient = if action == "lifecycle:observe-agent-membership" {
            &recipe["source"]
        } else {
            selected
        };
        require(
            event["event"]["type"] == "agent-join-recipe"
                && event["attempt"] == step["attempt"]
                && event["operation"] == step["operation"]
                && self.request["members"].as_array().is_some_and(|members| {
                    members.first() == Some(&recipe["source"]) && members.contains(selected)
                })
                && step["recipient"] == *recipient,
            Failure::Ownership,
        )?;
        let observed = |index: usize, kind: &str| -> Result<&Value> {
            let result = self
                .observations
                .iter()
                .find(|o| o["sequence"] == references[index])
                .ok_or(Failure::Integrity)?;
            require(
                result["event"]["type"] == kind
                    && result["attempt"] == step["attempt"]
                    && result["operation"] == step["operation"],
                Failure::Integrity,
            )?;
            Ok(result)
        };
        let mut identity = Value::Null;
        let mut agent_view = Value::Null;
        match action {
            "lifecycle:inspect-agent" | "lifecycle:activate-agent" => {
                require(references.len() == 1, Failure::Integrity)?;
            }
            "lifecycle:observe-agent-membership" => {
                require((1..=2).contains(&references.len()), Failure::Integrity)?;
                if references.len() == 2 {
                    observed(1, "agent-membership")?;
                }
            }
            "lifecycle:start-agent" => {
                require(references.len() == 2, Failure::Integrity)?;
                observed(1, "agent-membership")?;
            }
            "lifecycle:observe-agent" => {
                require(references.len() == 2, Failure::Integrity)?;
                agent_view = observed(1, "agent-membership")?["event"]["view"].clone();
            }
            "lifecycle:publish-agent" => {
                require(references.len() == 4, Failure::Integrity)?;
                let sequences: Vec<u64> = references
                    .iter()
                    .map(|value| value.as_u64().ok_or(Failure::Integrity))
                    .collect::<Result<_>>()?;
                let post_start = observed(1, "agent-membership")?;
                let installation = observed(2, "lifecycle-installation")?;
                let final_view = observed(3, "agent-membership")?;
                let observed_step = self
                    .steps
                    .iter()
                    .find(|s| s["step"] == installation["step"])
                    .ok_or(Failure::Integrity)?;
                require(
                    sequences.windows(2).all(|pair| pair[0] < pair[1])
                        && observed_step["action"] == "lifecycle:observe-agent"
                        && observed_step["attempt"] == step["attempt"]
                        && observed_step["payload_observations"]
                            == json!([references[0], references[1]])
                        && installation["event"]["member"] == *selected
                        && (installation["event"]["class"] == "started"
                            || installation["event"]["class"] == "owned"
                                && self.request["consumer"].is_null()
                                && selected["node_uid"].is_null())
                        && !installation["event"]["identity"].is_null()
                        && post_start["event"]["view"] == final_view["event"]["view"],
                    Failure::Integrity,
                )?;
                identity = installation["event"]["identity"].clone();
                agent_view = final_view["event"]["view"].clone();
                let member = agent_view["members"]
                    .as_array()
                    .and_then(|entries| entries.iter().find(|entry| entry["member"] == *selected))
                    .ok_or(Failure::Integrity)?;
                require(
                    member["uid"] == identity["node_uid"]
                        && agent_view["cluster"] == identity["cluster"],
                    Failure::Ownership,
                )?;
            }
            _ => return Err(Failure::Capability),
        }
        let payload = json!({"recipe":recipe,"identity":identity,"agent_view":agent_view});
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    pub(super) fn lifecycle_payload(&self, step: &Value) -> Result<Value> {
        let action = step["action"].as_str().ok_or(Failure::Integrity)?;
        require(action.starts_with("lifecycle:"), Failure::Capability)?;
        let references = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require((1..=5).contains(&references.len()), Failure::Integrity)?;
        let event = self
            .observations
            .iter()
            .find(|o| o["sequence"] == references[0])
            .ok_or(Failure::Integrity)?;
        if (matches!(
            self.request["action"].as_str(),
            Some(
                "reconcile-network"
                    | "reconcile-ingress"
                    | "reconcile-cert-manager"
                    | "reconcile-issuer"
                    | "reconcile-certificate"
                    | "reconcile-registry-storage"
                    | "reconcile-registry-service"
                    | "reconcile-registry-endpoint"
                    | "reconcile-registry-auth"
                    | "reconcile-registry-token"
                    | "reconcile-registry-replication"
            )
        ) || super::node::carries(&self.request["action"])
            || super::member::carries(&self.request["action"]))
            && matches!(
                action,
                "lifecycle:observe-membership" | "lifecycle:observe-agent-membership"
            )
        {
            let agent = action == "lifecycle:observe-agent-membership";
            let (event, removal) = match references.get(1) {
                Some(sequence)
                    if !agent
                        && super::member::carries(&self.request["action"])
                        && event["event"]["type"] == "member-recipe" =>
                {
                    let recipe = self
                        .observations
                        .iter()
                        .find(|o| o["sequence"] == *sequence)
                        .ok_or(Failure::Integrity)?;
                    (recipe, Some(event["event"].clone()))
                }
                _ => (event, None),
            };
            require(
                references.len() == 1 + usize::from(removal.is_some())
                    && event["attempt"] == step["attempt"]
                    && event["operation"] == step["operation"],
                Failure::Integrity,
            )?;
            require(
                event["event"]["type"]
                    == if agent {
                        "agent-join-recipe"
                    } else {
                        "server-recipe"
                    }
                    && step["recipient"]
                        == if agent && super::member::carries(&self.request["action"]) {
                            event["event"]["recipe"]["source"].clone()
                        } else if agent {
                            self.request["members"][0].clone()
                        } else {
                            event["event"]["recipe"]["member"].clone()
                        },
                Failure::Ownership,
            )?;
            let recipe = &event["event"]["recipe"];
            require(
                recipe["members"] == self.request["members"]
                    && recipe["scope"] == self.request["scope"]
                    && recipe["owner"] == self.request["owner"],
                Failure::Ownership,
            )?;
            let payload = if agent {
                json!({"recipe":recipe,"identity":null,"agent_view":null})
            } else if let Some(member_recipe) = &removal {
                let target = super::member::removal_target(
                    &self.observations,
                    &member_recipe["recipe"]["member"],
                );
                crate::k3s::members::removal_payload(&event["event"], member_recipe, &target)
                    .map_err(|_| Failure::Integrity)?
            } else {
                json!({"recipe_kind":event["event"]["recipe_kind"],"recipe":recipe,
                    "identity":null,"membership":null,"removed":null})
            };
            return self.shaped("observe-membership", payload, step);
        }
        if self.request["action"] == "join-agent"
            && matches!(
                action,
                "lifecycle:inspect-agent"
                    | "lifecycle:observe-agent-membership"
                    | "lifecycle:activate-agent"
                    | "lifecycle:start-agent"
                    | "lifecycle:observe-agent"
                    | "lifecycle:publish-agent"
            )
        {
            return self.agent_payload(step, references, action);
        }
        if action == "lifecycle:prepare-join-source" {
            require(
                (references.len() == 1
                    && matches!(
                        self.request["action"].as_str(),
                        Some("prepare-server-inputs" | "join-agent")
                    )
                    || references.len() > 1 && self.request["action"] == "join-server")
                    && event["event"]["type"] == "server-recipe"
                    && event["event"]["recipe_kind"] == "initial"
                    && event["attempt"] == step["attempt"]
                    && event["operation"] == step["operation"],
                Failure::Integrity,
            )?;
            let resource = self.request["resources"]
                .as_array()
                .and_then(|resources| resources.first())
                .ok_or(Failure::Integrity)?;
            let recipe = &event["event"]["recipe"];
            require(
                step["resource"] == *resource
                    && step["recipient"] == recipe["member"]
                    && step["recipient"]["machine"] == resource["machine"],
                Failure::Ownership,
            )?;
            if self.request["action"] == "join-server" {
                let installed = self.request["members"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .iter()
                    .filter(|m| m["role"] == "server" && !m["node_uid"].is_null())
                    .count();
                require(
                    references.len() == installed + 1
                        && references[1..] == self.join_round(step, installed)?,
                    Failure::Integrity,
                )?;
            }
            let payload = json!({"resource":resource,
                "projection":self.request["consumer"]["projection"],"recipe":recipe});
            require(
                hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
                Failure::Integrity,
            )?;
            return Ok(payload);
        }
        if action == "lifecycle:inspect-installation"
            && matches!(
                self.request["action"].as_str(),
                Some("prepare-server-inputs" | "join-server" | "join-agent")
            )
        {
            require(
                references.len() == 1
                    && event["event"]["type"] == "server-recipe"
                    && event["event"]["recipe_kind"] == "initial"
                    && event["attempt"] == step["attempt"]
                    && event["operation"] == step["operation"],
                Failure::Integrity,
            )?;
            let recipe = &event["event"]["recipe"];
            require(
                recipe["members"]
                    .as_array()
                    .is_some_and(|members| members.contains(&step["recipient"])),
                Failure::Ownership,
            )?;
            let payload = json!({"recipe":recipe,"identity":null});
            require(
                hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
                Failure::Integrity,
            )?;
            return Ok(payload);
        }
        if action == "lifecycle:inspect-owned-server" && self.request["action"] == "create-server" {
            require(
                references.len() == 1
                    && event["event"]["type"] == "server-recipe"
                    && event["event"]["recipe_kind"] == "join"
                    && event["attempt"] == step["attempt"]
                    && event["operation"] == step["operation"]
                    && event["event"]["recipe"]["member"] == step["recipient"],
                Failure::Integrity,
            )?;
            let payload = json!({"recipe_kind":"join","recipe":event["event"]["recipe"],
                "identity":null,"membership":null,"removed":null});
            return self.shaped("observe-membership", payload, step);
        }
        if self.request["action"] == "join-server" || self.request["action"] == "join-agent" {
            let recipe_kind = if event["event"]["type"] == "server-join-recipe" {
                "join"
            } else {
                require(
                    event["event"]["type"] == "server-recipe",
                    Failure::Integrity,
                )?;
                event["event"]["recipe_kind"]
                    .as_str()
                    .ok_or(Failure::Integrity)?
            };
            let recipe = &event["event"]["recipe"];
            let member_slot = matches!(
                action,
                "lifecycle:inspect-installation" | "lifecycle:observe-membership"
            ) && recipe_kind == "initial"
                && recipe["members"]
                    .as_array()
                    .is_some_and(|members| members.contains(&step["recipient"]));
            require(
                event["attempt"] == step["attempt"]
                    && event["operation"] == step["operation"]
                    && (step["recipient"] == recipe["member"] || member_slot),
                Failure::Ownership,
            )?;
            let publication = action == "lifecycle:publish-member";
            if matches!(
                action,
                "lifecycle:activate-join" | "lifecycle:start-join" | "lifecycle:publish-member"
            ) {
                let voters = recipe["installed"]
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .len()
                    + usize::from(publication);
                let memberships: Vec<Value> = references
                    .iter()
                    .skip(1)
                    .filter(|sequence| {
                        self.observations.iter().any(|o| {
                            o["sequence"] == **sequence && o["event"]["type"] == "server-membership"
                        })
                    })
                    .cloned()
                    .collect();
                require(
                    references.len() == voters + 1 + usize::from(publication)
                        && memberships == self.join_round(step, voters)?,
                    Failure::Integrity,
                )?;
            } else {
                require(references.len() == 1, Failure::Integrity)?;
            }
            let mut identity = Value::Null;
            let mut membership = Value::Null;
            for sequence in references.iter().skip(1) {
                let observed = self
                    .observations
                    .iter()
                    .find(|o| o["sequence"] == *sequence)
                    .ok_or(Failure::Integrity)?;
                require(observed["attempt"] == step["attempt"], Failure::Integrity)?;
                if observed["event"]["type"] == "lifecycle-installation" {
                    require(
                        publication
                            && observed["event"]["member"] == recipe["member"]
                            && observed["event"]["class"] == "started"
                            && !observed["event"]["identity"].is_null()
                            && self.steps.iter().any(|source| {
                                source["action"] == "lifecycle:observe-join"
                                    && source["step"] == observed["step"]
                                    && source["attempt"] == observed["attempt"]
                            }),
                        Failure::Integrity,
                    )?;
                    identity = observed["event"]["identity"].clone();
                } else {
                    require(
                        observed["event"]["type"] == "server-membership",
                        Failure::Integrity,
                    )?;
                    if observed["event"]["member"] == recipe["member"] {
                        membership = observed["event"]["membership"].clone();
                    }
                }
            }
            require(
                !publication || (!identity.is_null() && !membership.is_null()),
                Failure::Integrity,
            )?;
            let payload = json!({"recipe_kind":recipe_kind,"recipe":recipe,"identity":identity,
                "membership":membership,"removed":null});
            return self.shaped("observe-membership", payload, step);
        }
        require(
            event["event"]["type"] == "lifecycle-recipe"
                && event["attempt"] == step["attempt"]
                && event["operation"] == step["operation"],
            Failure::Integrity,
        )?;
        let recipe = &event["event"]["recipe"];
        let members = recipe["members"].as_array().ok_or(Failure::Integrity)?;
        require(members.contains(&step["recipient"]), Failure::Integrity)?;
        if first_server_action(action) {
            require(step["recipient"] == recipe["member"], Failure::Integrity)?;
        }
        if action == "lifecycle:publish-cluster" {
            require(step["recipient"] != recipe["member"], Failure::Integrity)?;
        }
        let publishes = matches!(
            action,
            "lifecycle:publish-identity" | "lifecycle:publish-cluster"
        );
        let identity = if references.len() == 2 {
            require(publishes, Failure::Integrity)?;
            let observation = self
                .observations
                .iter()
                .find(|o| o["sequence"] == references[1])
                .ok_or(Failure::Integrity)?;
            let source = self
                .steps
                .iter()
                .find(|s| {
                    s["attempt"] == observation["attempt"]
                        && s["step"] == observation["step"]
                        && s["dispatch"] == observation["dispatch"]
                })
                .ok_or(Failure::Integrity)?;
            let installation = &observation["event"];
            require(
                installation["type"] == "lifecycle-installation"
                    && observation["attempt"] == step["attempt"]
                    && observation["operation"] == step["operation"]
                    && installation["member"] == recipe["member"]
                    && source["recipient"] == recipe["member"]
                    && !installation["identity"].is_null(),
                Failure::Integrity,
            )?;
            let admitted = match action {
                "lifecycle:publish-identity" => {
                    source["action"] == "lifecycle:observe-server"
                        && installation["class"] == "started"
                }
                _ => {
                    (source["action"] == "lifecycle:observe-server"
                        && installation["class"] == "started")
                        || (source["action"] == "lifecycle:inspect-installation"
                            && installation["class"] == "owned")
                }
            };
            require(admitted, Failure::Integrity)?;
            installation["identity"].clone()
        } else {
            let dispatched = self.observations.iter().any(|o| {
                o["attempt"] == step["attempt"]
                    && o["step"] == step["step"]
                    && o["dispatch"] == step["dispatch"]
                    && o["event"]["type"] == "dispatch"
            });
            require(
                !publishes || self.deselected(step) || !dispatched,
                Failure::Integrity,
            )?;
            Value::Null
        };
        let payload = json!({"recipe":recipe,"identity":identity});
        require(
            hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
            Failure::Integrity,
        )?;
        Ok(payload)
    }

    pub(super) fn binding(&self, step: &Value) -> Value {
        json!({"scope":self.request["scope"],"owner":self.request["owner"],
            "operation":self.request["operation"],"attempt":step["attempt"],
            "step":step["step"],"dispatch":step["dispatch"],"recipient":step["recipient"],
            "receiver_generation":step["expected_receiver_generation"],
            "request_sha256":step["request_sha256"],
            "participants_sha256":self.request["participants_sha256"],
            "fingerprints":self.request["fingerprints"]})
    }

    pub(super) fn node_payload(&self, step: &Value) -> Result<Value> {
        if super::member::carries(&self.request["action"]) {
            return self.member_payload(step);
        }
        if joins(&self.request["action"]) {
            return self.render_payload(step);
        }
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            super::node::carries(&self.request["action"]) && !refs.is_empty(),
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
            Ok(&observation["event"])
        };
        let recipe_event = observed(&refs[0])?;
        require(recipe_event["type"] == "restart-recipe", Failure::Ownership)?;
        let recipe = &recipe_event["recipe"];
        let agents = members.iter().any(|m| m["role"] == "agent");
        let servers = members.iter().filter(|m| m["role"] == "server").count();
        require(
            recipe["scope"] == self.request["scope"]
                && recipe["owner"] == self.request["owner"]
                && recipe["operation"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe["first_server"] == members[0]
                && members.contains(&recipe["member"])
                && recipe["profile_sha256"] == self.request["fingerprints"]["profile_sha256"]
                && recipe.get("registries").is_some()
                    == (self.request["action"] == "configure-node-registries"),
            Failure::Ownership,
        )?;
        let payload = match step["action"].as_str() {
            Some("lifecycle:node-restart" | "lifecycle:node-configure-registries") => {
                let gate = refs[1..].iter().map(observed).collect::<Result<Vec<_>>>()?;
                let count = |kind: &str| gate.iter().filter(|e| e["type"] == kind).count();
                require(
                    step["recipient"] == recipe["member"]
                        && gate.len() == servers + usize::from(agents)
                        && count("server-membership") == servers
                        && count("agent-membership") == usize::from(agents),
                    Failure::Integrity,
                )?;
                json!({"recipe":recipe,"expected":null,"wait_ms":null})
            }
            Some("lifecycle:node-observe-node") => {
                let (mut receipt, mut view) = (None, None);
                for sequence in &refs[1..] {
                    let event = observed(sequence)?;
                    match event["type"].as_str() {
                        Some("receiver")
                            if receipt.is_none()
                                && event["receipt"]["action"] == "lifecycle:node-restart" =>
                        {
                            receipt = Some(event);
                        }
                        Some("agent-membership") if agents && view.is_none() => view = Some(event),
                        _ => return Err(Failure::Integrity),
                    }
                }
                let receipt = receipt.ok_or(Failure::Integrity)?;
                let server = recipe["member"]["role"] == "server";
                require(
                    view.is_some() == agents
                        && step["recipient"]
                            == recipe[if server { "member" } else { "first_server" }],
                    Failure::Integrity,
                )?;
                let entry = match view {
                    Some(view) => Some(
                        view["view"]["members"]
                            .as_array()
                            .and_then(|items| {
                                items.iter().find(|i| i["member"] == recipe["member"])
                            })
                            .ok_or(Failure::Integrity)?,
                    ),
                    None => None,
                };
                let expected = super::node::expected(
                    &recipe["member"],
                    entry,
                    &receipt["receipt"]["completed_ms"],
                );
                json!({"recipe":recipe,"expected":expected,"wait_ms":super::node::WAIT_MS})
            }
            _ => return Err(Failure::Capability),
        };
        self.shaped("node-registry", payload, step)
    }

    fn render_payload(&self, step: &Value) -> Result<Value> {
        let refs = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        if step["action"] == "lifecycle:node-start-member" {
            return self.start_payload(step, refs);
        }
        require(
            step["action"] == "lifecycle:node-configure-registries" && refs.len() == 1,
            Failure::Integrity,
        )?;
        let event = self
            .observations
            .iter()
            .find(|o| o["sequence"] == refs[0])
            .ok_or(Failure::Integrity)?;
        let recipe = &event["event"]["recipe"];
        require(
            event["event"]["type"] == "restart-recipe"
                && event["operation"] == step["operation"]
                && event["attempt"] == step["attempt"]
                && recipe["operation"] == self.request["operation"]
                && recipe["run"] == self.request["operation"]
                && recipe["cluster"] == self.request["cluster"]
                && recipe.get("registries").is_some()
                && recipe["member"] == step["recipient"]
                && recipe["member"]["node_uid"].is_null()
                && self.request["members"]
                    .as_array()
                    .is_some_and(|members| members.contains(&recipe["member"])),
            Failure::Ownership,
        )?;
        let payload = json!({"recipe":recipe,"expected":null,"wait_ms":null});
        self.shaped("node-registry", payload, step)
    }

    fn start_payload(&self, step: &Value, refs: &[Value]) -> Result<Value> {
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
            Ok(&observation["event"])
        };
        require(refs.len() == 2, Failure::Integrity)?;
        let (recipe, installed) = (observed(&refs[0])?, observed(&refs[1])?);
        let uid = &installed["identity"]["node_uid"];
        require(
            self.request["action"] == "join-agent"
                && recipe["type"] == "agent-join-recipe"
                && recipe["recipe"]["member"] == step["recipient"]
                && recipe["recipe"]["member"]["node_uid"].is_null()
                && installed["type"] == "lifecycle-installation"
                && installed["member"] == step["recipient"]
                && installed["class"] == "owned"
                && uid.is_string(),
            Failure::Ownership,
        )?;
        let payload = json!({"recipe":recipe["recipe"],"expected":{"node_uid":uid,"pods":null,
            "after":null,"view":null},"wait_ms":null});
        self.shaped("node-registry", payload, step)
    }

    pub(super) fn validate_observation(&self, observation: &Value) -> Result<()> {
        let source = &observation["source"];
        let members = self.request["members"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        if source["kind"] == "controller" {
            require(source["machine"].is_null(), Failure::Integrity)?;
        } else {
            require(
                members.iter().any(|m| m["machine"] == source["machine"]),
                Failure::Ownership,
            )?;
        }
        let step = self.steps.iter().find(|s| s["step"] == observation["step"]);
        let event = &observation["event"];
        if event["type"] == "receiver" {
            let step = step.ok_or(Failure::Integrity)?;
            let receipt = &event["receipt"];
            require(
                source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && receipt["binding"] == self.binding(step)
                    && receipt["action"] == step["action"]
                    && receipt["payload_sha256"] == step["payload_sha256"],
                Failure::Ownership,
            )?;
            for prior in &self.observations {
                if prior["event"]["type"] == "receiver"
                    && prior["dispatch"] == observation["dispatch"]
                {
                    require(prior["event"]["receipt"] == *receipt, Failure::Integrity)?;
                }
            }
        }
        if event["type"] == "inspection" {
            let step = step.ok_or(Failure::Integrity)?;
            let payload = json!({"subject":event["subject"],
                "dispatch":event["observed_dispatch"],"resource":event["resource"]});
            require(
                step["action"] == "inspect"
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && step["resource"] == event["resource"]
                    && hash("broil-infra-step-v1", &payload)? == step["payload_sha256"],
                Failure::Ownership,
            )?;
        }
        if event["type"] == "lifecycle-installation" {
            require(
                members.contains(&event["member"])
                    && source["kind"] == "receiver"
                    && source["machine"] == event["member"]["machine"],
                Failure::Ownership,
            )?;
            let activation = &event["activation"];
            if !activation.is_null()
                && matches!(
                    event["class"].as_str(),
                    Some("activated" | "started" | "owned")
                )
            {
                let recipe = if self.request["action"] == "join-agent"
                    && event["member"]["role"] == "agent"
                {
                    &self
                        .observations
                        .iter()
                        .find(|o| {
                            o["event"]["type"] == "agent-join-recipe"
                                && o["event"]["recipe"]["member"] == event["member"]
                        })
                        .ok_or(Failure::Integrity)?["event"]["recipe"]
                } else if self.request["action"] == "join-server"
                    || self.request["action"] == "join-agent"
                    || self.request["action"] == "create-server"
                        && event["member"] != self.request["members"][0]
                {
                    &self
                        .observations
                        .iter()
                        .find(|o| {
                            o["event"]["type"] == "server-recipe"
                                && o["event"]["recipe"]["member"] == event["member"]
                        })
                        .or_else(|| {
                            self.observations.iter().find(|o| {
                                o["event"]["type"] == "server-join-recipe"
                                    && o["event"]["recipe"]["member"] == event["member"]
                            })
                        })
                        .ok_or(Failure::Integrity)?["event"]["recipe"]
                } else if self.request["action"] == "prepare-server-inputs" {
                    &self
                        .observations
                        .iter()
                        .find(|o| o["event"]["type"] == "server-recipe")
                        .ok_or(Failure::Integrity)?["event"]["recipe"]
                } else {
                    &self.lifecycle_recipe()?["event"]["recipe"]
                };
                require(
                    activation["recipe_identity_sha256"] == recipe_identity(recipe)?,
                    Failure::Ownership,
                )?;
                if let Some(step) = step {
                    if matches!(
                        step["action"].as_str(),
                        Some(
                            "lifecycle:activate-server"
                                | "lifecycle:activate-join"
                                | "lifecycle:activate-agent"
                        )
                    ) && step["recipient"] == event["member"]
                    {
                        require(
                            activation["recipe_sha256"] == recipe_hash(recipe)?,
                            Failure::Ownership,
                        )?;
                    }
                }
            }
        }
        if event["type"] == "server-membership" {
            let step = step.ok_or(Failure::Integrity)?;
            require(
                event["member"] == step["recipient"]
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && matches!(
                        step["action"].as_str(),
                        Some(
                            "lifecycle:observe-membership"
                                | "lifecycle:observe-join"
                                | "lifecycle:publish-member"
                        )
                    )
                    && (event["membership"].is_null()
                        || event["membership"]["observer"] == step["recipient"]["machine"]),
                Failure::Ownership,
            )?;
        }
        if event["type"] == "agent-membership" {
            let step = step.ok_or(Failure::Integrity)?;
            require(
                (matches!(
                    self.request["action"].as_str(),
                    Some(
                        "join-agent"
                            | "reconcile-network"
                            | "reconcile-ingress"
                            | "reconcile-cert-manager"
                            | "reconcile-issuer"
                            | "reconcile-certificate"
                            | "reconcile-registry-storage"
                            | "reconcile-registry-service"
                            | "reconcile-registry-endpoint"
                            | "reconcile-registry-auth"
                            | "reconcile-registry-token"
                            | "reconcile-registry-replication"
                    )
                ) || super::node::carries(&self.request["action"])
                    || super::member::carries(&self.request["action"]))
                    && matches!(
                        step["action"].as_str(),
                        Some("lifecycle:observe-agent-membership" | "lifecycle:publish-agent")
                    )
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && (event["view"]["observer"] == self.request["members"][0]
                        || super::member::carries(&self.request["action"])
                            && event["view"]["observer"] == step["recipient"])
                    && event["view"]["cluster"] == self.request["cluster"],
                Failure::Ownership,
            )?;
        }
        if event["type"] == "network-observation" {
            let step = step.ok_or(Failure::Integrity)?;
            let host = !event["member"].is_null();
            require(
                self.request["action"] == "reconcile-network"
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && if host {
                        step["action"] == "lifecycle:network-inspect-host"
                            && event["member"] == step["recipient"]
                            && event["hosts"]["member"] == event["member"]
                            && event["objects"].is_null()
                    } else {
                        matches!(
                            step["action"].as_str(),
                            Some(
                                "lifecycle:network-inspect-objects"
                                    | "lifecycle:network-create-object"
                            )
                        ) && step["recipient"] == self.request["members"][0]
                            && event["hosts"].is_null()
                            && event["objects"]
                                .as_array()
                                .is_some_and(|objects| objects.len() == 12)
                    },
                Failure::Ownership,
            )?;
        }
        if event["type"] == "ingress-observation" {
            let step = step.ok_or(Failure::Integrity)?;
            let host = !event["member"].is_null();
            require(
                self.request["action"] == "reconcile-ingress"
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && if host {
                        matches!(
                            step["action"].as_str(),
                            Some(
                                "lifecycle:ingress-inspect-host" | "lifecycle:ingress-import-image"
                            )
                        ) && event["member"] == step["recipient"]
                            && event["hosts"]["member"] == event["member"]
                            && event["objects"].is_null()
                    } else {
                        step["action"] == "lifecycle:ingress-inspect-objects"
                            && step["recipient"] == self.request["members"][0]
                            && event["hosts"].is_null()
                            && event["objects"].as_array().is_some_and(|objects| {
                                objects.len() == super::ingress::INGRESS_OBJECTS.len()
                            })
                    },
                Failure::Ownership,
            )?;
        }
        if event["type"] == "cert-manager-observation" {
            let host = !event["member"].is_null();
            let first = &self.request["members"][0];
            require(
                self.request["action"] == "reconcile-cert-manager"
                    && match step {
                        Some(step) => {
                            source["kind"] == "receiver"
                                && source["machine"] == step["recipient"]["machine"]
                                && if host {
                                    matches!(
                                        step["action"].as_str(),
                                        Some(
                                            "lifecycle:cert-manager-inspect-host"
                                                | "lifecycle:cert-manager-import-images"
                                        )
                                    ) && event["member"] == step["recipient"]
                                        && event["hosts"]["member"] == event["member"]
                                        && event["objects"].is_null()
                                } else {
                                    matches!(
                                        step["action"].as_str(),
                                        Some(
                                            "lifecycle:cert-manager-inspect-objects"
                                                | "lifecycle:cert-manager-create-objects"
                                        )
                                    ) && step["recipient"] == *first
                                        && event["hosts"].is_null()
                                        && event["webhook"].is_null()
                                            == (step["action"]
                                                == "lifecycle:cert-manager-create-objects")
                                }
                        }
                        None => {
                            source["kind"] == "controller"
                                && !host
                                && event["hosts"].is_null()
                                && event["webhook"].is_null()
                                && event["services"].is_null()
                                && self.request["resources"]
                                    .as_array()
                                    .and_then(|resources| resources.last())
                                    .is_some_and(|anchor| anchor["uid"].is_string())
                        }
                    }
                    && (host
                        || event["objects"]
                            .as_array()
                            .is_some_and(|objects| objects.len() == 47)),
                Failure::Ownership,
            )?;
        }
        if event["type"] == "issuer-observation" {
            let step = step.ok_or(Failure::Integrity)?;
            let tag = step["action"].as_str().unwrap_or("");
            let read = tag == "lifecycle:issuer-inspect-objects";
            require(
                self.request["action"] == "reconcile-issuer"
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && step["recipient"] == self.request["members"][0]
                    && event["member"].is_null()
                    && tag.starts_with("lifecycle:issuer-")
                    && tag != "lifecycle:issuer-create-object"
                    && event["objects"].is_null()
                        != (read || tag == "lifecycle:issuer-create-issuer")
                    && event["issuer"].is_null()
                        != (read || tag == "lifecycle:issuer-register-input")
                    && event["services"].is_null() != read,
                Failure::Ownership,
            )?;
        }
        if event["type"] == "registry-auth-observation" {
            let step = step.ok_or(Failure::Integrity)?;
            let tag = step["action"].as_str().unwrap_or("");
            let read = tag == "lifecycle:registry-auth-inspect-objects";
            require(
                self.request["action"] == "reconcile-registry-auth"
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && step["recipient"] == self.request["members"][0]
                    && event["member"].is_null()
                    && tag.starts_with("lifecycle:registry-auth-")
                    && tag != "lifecycle:registry-auth-create-object"
                    && event["objects"].is_null() != read
                    && event["registration"].is_null()
                        != (read || tag == "lifecycle:registry-auth-register-input")
                    && event["signing"].is_null() != read
                    && event["services"].is_null() != read,
                Failure::Ownership,
            )?;
        }
        if event["type"] == "member-observation" {
            self.member_observation(observation, step.ok_or(Failure::Integrity)?)?;
        }
        if event["type"] == "node-observation" {
            let step = step.ok_or(Failure::Integrity)?;
            let kind = match step["action"].as_str() {
                Some("lifecycle:node-restart") => "restart",
                Some("lifecycle:node-observe-node") => "node",
                Some("lifecycle:node-configure-registries") => "configure",
                _ => return Err(Failure::Ownership),
            };
            let recipe = self
                .observations
                .iter()
                .find(|o| o["event"]["type"] == "restart-recipe")
                .map(|o| &o["event"]["recipe"]);
            require(
                (super::node::carries(&self.request["action"])
                    || joins(&self.request["action"]) && kind == "configure")
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && event["kind"] == kind
                    && recipe.is_some_and(|r| event["member"] == r["member"])
                    && (kind != "node" || event["node"]["member"] == event["member"]["member"]),
                Failure::Ownership,
            )?;
        }
        if event["type"] == "restart-recipe"
            && self.request["action"] == "configure-node-registries"
        {
            let recipe = &event["recipe"];
            let named: Vec<Value> = recipe["registries"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .iter()
                .map(|entry| entry["resource"].clone())
                .collect();
            let resources = self.request["resources"]
                .as_array()
                .ok_or(Failure::Integrity)?;
            require(
                named.len() == resources.len()
                    && named.iter().zip(resources).all(|(entry, r)| {
                        *entry == json!({"id":r["id"],"generation":r["generation"]})
                            && r["machine"] == recipe["member"]["machine"]
                    }),
                Failure::Ownership,
            )?;
        }
        if event["type"] == "registry-token-observation" {
            let step = step.ok_or(Failure::Integrity)?;
            let tag = step["action"]
                .as_str()
                .and_then(|a| a.strip_prefix("lifecycle:registry-token-"))
                .unwrap_or("create-object");
            let host = matches!(tag, "inspect-host" | "import-image");
            let recipient = self
                .observations
                .iter()
                .find(|o| o["event"]["type"] == "registry-token-recipe")
                .is_some_and(|o| self.recipient(&o["event"]["recipe"], host, &step["recipient"]));
            require(
                self.request["action"] == "reconcile-registry-token"
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && recipient
                    && tag != "create-object"
                    && (event["member"] == step["recipient"]) == host
                    && event["member"].is_null() != host
                    && event["objects"].is_null() != (tag == "inspect-objects"),
                Failure::Ownership,
            )?;
        }
        if event["type"] == super::registry_replication::OBSERVATION {
            let step = step.ok_or(Failure::Integrity)?;
            let host = step["action"] == "lifecycle:registry-replication-inspect-replication";
            let maintained = super::member::carries(&self.request["action"]);
            let first = if maintained {
                self.observations
                    .iter()
                    .find(|o| o["event"]["type"] == "member-recipe")
                    .map(|o| &o["event"]["recipe"]["first_server"])
            } else {
                self.request["members"]
                    .as_array()
                    .and_then(|m| m.iter().find(|m| m["role"] == "server"))
            };
            let members = self.request["members"].as_array();
            require(
                (self.request["action"] == "reconcile-registry-replication" || maintained)
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && (host || step["action"] == "lifecycle:registry-replication-inspect-objects")
                    && if host {
                        members.is_some_and(|m| m.contains(&step["recipient"]))
                    } else {
                        first == Some(&step["recipient"])
                    }
                    && (event["member"] == step["recipient"]) == host
                    && event["member"].is_null() != host,
                Failure::Ownership,
            )?;
        }
        if event["type"] == "certificate-observation" {
            let step = step.ok_or(Failure::Integrity)?;
            require(
                self.request["action"] == "reconcile-certificate"
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && step["recipient"] == self.request["members"][0]
                    && event["member"].is_null()
                    && step["action"] == "lifecycle:certificate-inspect-objects"
                    && !event["objects"].is_null()
                    && !event["certificate"].is_null()
                    && !event["services"].is_null(),
                Failure::Ownership,
            )?;
        }
        if let Some(family) = event["type"]
            .as_str()
            .and_then(|kind| kind.strip_suffix("-observation"))
            .filter(|family| {
                matches!(
                    *family,
                    "registry-storage" | "registry-service" | "registry-endpoint"
                )
            })
        {
            let step = step.ok_or(Failure::Integrity)?;
            let host = step["action"].as_str().is_some_and(|a| {
                a == format!("lifecycle:{family}-inspect-storage")
                    || a == format!("lifecycle:{family}-inspect-host")
            });
            let recipient = self
                .observations
                .iter()
                .find(|o| o["event"]["type"] == format!("{family}-recipe"))
                .is_some_and(|o| self.recipient(&o["event"]["recipe"], host, &step["recipient"]));
            require(
                self.request["action"] == format!("reconcile-{family}")
                    && source["kind"] == "receiver"
                    && source["machine"] == step["recipient"]["machine"]
                    && recipient
                    && (host || step["action"] == format!("lifecycle:{family}-inspect-objects"))
                    && (event["member"] == step["recipient"]) == host
                    && event["member"].is_null() != host,
                Failure::Ownership,
            )?;
        }
        if event["type"] == "identity" && event["member"].is_null() {
            let prefix = match self.request["action"].as_str() {
                Some("reconcile-ingress") => "ingress-object-",
                Some("reconcile-cert-manager") => "cert-manager-object-",
                Some("reconcile-issuer") => "issuer-object-",
                Some("reconcile-certificate") => "certificate-object-",
                Some("reconcile-registry-storage") => "registry-volume-",
                Some("reconcile-registry-service") => "registry-service-object-",
                Some("reconcile-registry-endpoint") => "registry-endpoint-object-",
                Some("reconcile-registry-auth") => "registry-auth-object-",
                Some("reconcile-registry-token") => "registry-token-object-",
                Some("reconcile-registry-replication") => "registry-reader-object-",
                _ => "network-object-",
            };
            require(
                matches!(
                    self.request["action"].as_str(),
                    Some(
                        "reconcile-network"
                            | "reconcile-ingress"
                            | "reconcile-cert-manager"
                            | "reconcile-issuer"
                            | "reconcile-certificate"
                            | "reconcile-registry-storage"
                            | "reconcile-registry-service"
                            | "reconcile-registry-endpoint"
                            | "reconcile-registry-auth"
                            | "reconcile-registry-token"
                            | "reconcile-registry-replication"
                    )
                ) && source["kind"] == "controller"
                    && event["cluster"] == self.request["cluster"]
                    && event["resources"].as_array().is_some_and(|resources| {
                        resources.len() == 1
                            && resources[0]["id"]
                                .as_str()
                                .is_some_and(|id| id.starts_with(prefix))
                            && resources[0]["uid"].is_string()
                    }),
                Failure::Ownership,
            )?;
        }
        if event["type"] == "reservation" {
            require(
                members.contains(&event["member"])
                    && source["kind"] == "receiver"
                    && source["machine"] == event["member"]["machine"],
                Failure::Ownership,
            )?;
            if matches!(event["state"].as_str(), Some("sealed" | "retired")) {
                let step = step.ok_or(Failure::Integrity)?;
                let acquired = step["expected_receiver_generation"]
                    .as_u64()
                    .ok_or(Failure::Integrity)?;
                let expected = if event["state"] == "retired" {
                    require(step["action"] == "retire-writer", Failure::Integrity)?;
                    acquired.checked_add(1).ok_or(Failure::Bound)?
                } else {
                    require(step["action"] == "seal-writer", Failure::Integrity)?;
                    acquired
                };
                require(
                    acquired > 0
                        && event["generation"] == expected
                        && !event["receipt_sha256"].is_null()
                        && step["recipient"] == event["member"],
                    Failure::Ownership,
                )?;
                for prior in &self.observations {
                    if prior["event"]["type"] == "reservation"
                        && prior["dispatch"] == observation["dispatch"]
                        && prior["event"]["state"] == event["state"]
                    {
                        require(prior["event"] == *event, Failure::Integrity)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn bootstrap_payload(&self, step: &Value) -> Result<Value> {
        let references = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(references.len() == 1, Failure::Integrity)?;
        let observation = self
            .observations
            .iter()
            .find(|o| o["sequence"] == references[0])
            .ok_or(Failure::Integrity)?;
        require(
            observation["event"]["type"] == "bootstrap-recipe"
                && observation["attempt"] == step["attempt"]
                && observation["operation"] == step["operation"],
            Failure::Integrity,
        )?;
        let recipe = &observation["event"]["recipe"];
        require(
            recipe["resources"]
                .as_array()
                .is_some_and(|r| r.contains(&step["resource"]))
                && step["resource"]["machine"] == step["recipient"]["machine"],
            Failure::Integrity,
        )?;
        let single = matches!(
            step["action"].as_str(),
            Some("bootstrap:download-asset" | "bootstrap:receive-asset")
        );
        let candidates: Vec<Value> = if single {
            recipe["manifest"]["assets"]
                .as_array()
                .ok_or(Failure::Integrity)?
                .iter()
                .map(|a| a["id"].clone())
                .collect()
        } else {
            vec![Value::Null]
        };
        for asset in candidates {
            let payload = json!({"recipe":recipe,"resource":step["resource"],"asset":asset});
            if hash("broil-infra-step-v1", &payload)? == step["payload_sha256"] {
                return Ok(payload);
            }
        }
        Err(Failure::Integrity)
    }

    pub(super) fn succeeded(&self, step: &Value) -> bool {
        self.observations.iter().any(|o| {
            o["attempt"] == step["attempt"]
                && o["step"] == step["step"]
                && o["dispatch"] == step["dispatch"]
                && o["event"]["type"] == "receiver"
                && o["event"]["receipt"]["binding"] == self.binding(step)
                && o["event"]["receipt"]["action"] == step["action"]
                && o["event"]["receipt"]["payload_sha256"] == step["payload_sha256"]
                && o["event"]["receipt"]["outcome"] == "succeeded"
                && o["event"]["receipt"]["effect"] == "complete"
                && o["event"]["receipt"]["writer_ended"] == true
        })
    }

    pub(super) fn retirement_evidence(
        &self,
        attempt: &Value,
        references: &[Value],
    ) -> Result<Value> {
        let (all, excluded) = super::session::selection(self)?;
        let members = &match super::session::replacement_host(self)? {
            Some(host) => vec![host],
            None => all.clone(),
        };
        require(
            references.len() == members.len().checked_mul(2).ok_or(Failure::Bound)?
                && references.windows(2).all(|p| p[0].as_u64() < p[1].as_u64()),
            Failure::Integrity,
        )?;
        let mut proof = Vec::with_capacity(references.len());
        for reference in references {
            let sequence = reference.as_u64().ok_or(Failure::Integrity)?;
            let event = self
                .observations
                .iter()
                .find(|o| o["sequence"] == sequence)
                .ok_or(Failure::Integrity)?;
            require(
                event["attempt"] == *attempt && event["source"]["kind"] == "receiver",
                Failure::Ownership,
            )?;
            for field in ["scope", "owner", "operation"] {
                require(event[field] == self.request[field], Failure::Ownership)?;
            }
            self.validate_observation(event)?;
            proof.push(event);
        }
        let mut seals = Vec::with_capacity(members.len());
        for member in members {
            let sealed: Vec<_> = proof
                .iter()
                .copied()
                .filter(|o| {
                    o["event"]["type"] == "reservation"
                        && o["event"]["state"] == "sealed"
                        && o["event"]["member"] == *member
                })
                .collect();
            let terminals: Vec<_> = proof
                .iter()
                .copied()
                .filter(|o| {
                    o["event"]["type"] == "receiver"
                        && o["event"]["receipt"]["binding"]["recipient"] == *member
                })
                .collect();
            require(
                sealed.len() == 1 && terminals.len() == 1,
                Failure::Integrity,
            )?;
            let sealed = sealed[0];
            let terminal = terminals[0];
            require(
                sealed["step"] == terminal["step"] && sealed["dispatch"] == terminal["dispatch"],
                Failure::Integrity,
            )?;
            let step = self
                .steps
                .iter()
                .find(|s| s["step"] == sealed["step"] && s["attempt"] == *attempt)
                .ok_or(Failure::Integrity)?;
            require(
                step["action"] == "seal-writer"
                    && terminal["event"]["receipt"]["outcome"] == "succeeded"
                    && terminal["event"]["receipt"]["effect"] == "complete"
                    && terminal["event"]["receipt"]["writer_ended"] == true,
                Failure::Integrity,
            )?;
            let generation = sealed["event"]["generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?;
            let acquired = self
                .steps
                .iter()
                .find(|s| {
                    s["attempt"] == *attempt
                        && s["recipient"] == *member
                        && s["action"] == "acquire-writer"
                        && s["expected_receiver_generation"]
                            .as_u64()
                            .and_then(|g| g.checked_add(1))
                            == Some(generation)
                })
                .ok_or(Failure::Ownership)?;
            require(
                self.succeeded(acquired)
                    && self.observations.iter().any(|o| {
                        o["attempt"] == *attempt
                            && o["step"] == acquired["step"]
                            && o["dispatch"] == acquired["dispatch"]
                            && o["event"]["type"] == "reservation"
                            && o["event"]["member"] == *member
                            && matches!(o["event"]["state"].as_str(), Some("reserved" | "active"))
                            && o["event"]["generation"] == generation
                    }),
                Failure::Ownership,
            )?;
            seals.push(json!({"machine":member["machine"],"generation":generation,
                "seal_sha256":sealed["event"]["receipt_sha256"]}));
        }
        Ok(json!({"seals":seals,"members":all,"excluded":excluded}))
    }

    pub(super) fn retirement_payload(&self, step: &Value) -> Result<Value> {
        require(step["action"] == "retire-writer", Failure::Capability)?;
        let references = step["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        let payload = self.retirement_evidence(&step["attempt"], references)?;
        require(
            step["payload_sha256"] == hash("broil-infra-step-v1", &payload)?,
            Failure::Integrity,
        )?;
        Ok(payload)
    }
}
