// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::issuer::{self, Begun, Lifecycle};
use super::network::{self, Family};
use super::session::{Local, Mode, Session, fresh, now};
use super::{Failure, Result, Snapshot, canonical, hash, require, rpc, schema};
use crate::k3s::{PROFILE, REGISTRY};
use broil_config::LoadedProject;
use broil_core::images::reference::Endpoint;
use broil_core::k3s::{Infrastructure, ManagedRegistry};
use serde_json::{Value, json};

pub(super) const FAMILY: Family = Family {
    name: "registry-auth",
    protocol: "broil-k3s-registry-auth",
    magic: b"BK3SRAU1\n",
    header: "RegistryAuthHeader",
    result: "RegistryAuthResult",
    body: REGISTRY,
    planned: 1,
    reserve: 8_192,
    version: 1,
};

pub(super) const LIFECYCLE: Lifecycle = Lifecycle {
    family: &FAMILY,
    consumer: "supply-registry-signing",
    wrapper: None,
    facts: &["registration", "signing"],
};

pub(super) const PRINCIPAL: Lifecycle = Lifecycle {
    family: &FAMILY,
    consumer: "supply-registry-principal",
    wrapper: None,
    facts: &["registration", "signing"],
};

pub(super) const ANCHOR: &str = "registry-service-object-01";

pub(super) const ID: &str = "registry-auth-object-signing";

const PRINCIPAL_ID: &str = "registry-auth-object-principal-";

pub(super) fn principal_of(id: &str) -> Option<(&str, u64)> {
    let rest = id.strip_prefix(PRINCIPAL_ID)?;
    let (name, k) = match rest.split_once('.') {
        None => (rest, 1),
        Some((name, k)) => (
            name,
            k.parse::<u64>().ok().filter(|n| {
                *n >= 2 && !k.starts_with('0') && k.bytes().all(|b| b.is_ascii_digit())
            })?,
        ),
    };
    let mut bytes = name.bytes();
    let named = bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    named.then_some((name, k))
}

pub(super) fn principal_id(name: &str, k: u64) -> String {
    if k == 1 {
        format!("{PRINCIPAL_ID}{name}")
    } else {
        format!("{PRINCIPAL_ID}{name}.{k}")
    }
}

pub(super) fn lifecycle(resource: &Value) -> (&'static Lifecycle, &'static str) {
    if resource["id"] == ID {
        (&LIFECYCLE, "signing-key")
    } else {
        (&PRINCIPAL, "password")
    }
}

pub(super) fn action(tag: &str) -> String {
    format!("lifecycle:registry-auth-{tag}")
}

pub(super) fn gates(
    registry: Option<&ManagedRegistry>,
    infrastructure: &Infrastructure,
) -> Result<ManagedRegistry> {
    super::registry_storage::gate(registry.map(|r| r.certificate.as_str()), infrastructure)?;
    let registry = registry.cloned().ok_or(Failure::Configuration)?;
    require(
        registry.authentication.profile == "docker-auth"
            && registry.authentication.signing_key.is_some(),
        Failure::Configuration,
    )?;
    Ok(registry)
}

pub(super) fn projection(
    request: &Value,
    operation: &Value,
    attempt: &Value,
    resource: &Value,
) -> Result<Value> {
    let config = &request["config"];
    let registry = &config["target"]["registry"];
    let endpoint = registry["endpoint"]
        .as_str()
        .ok_or(Failure::Configuration)?;
    let declared = config["registries"][endpoint]["declaration"]["endpoint"]
        .as_str()
        .and_then(|text| Endpoint::registry(text, true))
        .ok_or(Failure::Configuration)?;
    let mut selectors =
        json!({"issuer":null,"service":registry["name"],"origin":crate::k3s::origin(&declared)});
    let references = match principal_of(resource["id"].as_str().unwrap_or_default()) {
        None => json!([registry["authentication"]["signing_key"]]),
        Some((name, _)) => {
            selectors["principal"] = json!(name);
            json!([registry["authentication"]["principals"][name]["password"]])
        }
    };
    issuer::secret_projection(
        request,
        (operation, attempt, resource),
        selectors,
        references,
    )
}

pub(super) fn stage(origins: &Value) -> Result<&'static str> {
    let set = |key: &str| !origins[key].is_null();
    match (
        set("secret"),
        set("registration"),
        set("supply"),
        set("activation"),
    ) {
        (false, false, false, false) => Ok("create"),
        (true, true, false, false) => Ok("supply"),
        (true, true, true, false) => Ok("activate"),
        (true, true, true, true) => Ok("observe"),
        _ => Err(Failure::Ownership),
    }
}

pub(super) fn effects(stage: &str) -> usize {
    match stage {
        "create" => 2,
        "activate" => 1,
        _ => 0,
    }
}

pub(super) fn budget(stage: &str, remaining: u64) -> Result<()> {
    let needed = u64::try_from(effects(stage)).map_err(|_| Failure::Bound)? * (3 * 20 + 2 * 30);
    require(remaining >= needed, Failure::Bound)
}

pub(super) fn confirms(stage: &str, reply: &Value) -> Result<()> {
    keyed("signing-key", stage, reply)
}

pub(super) fn confirms_password(stage: &str, reply: &Value) -> Result<()> {
    keyed("password", stage, reply)
}

fn keyed(key: &str, stage: &str, reply: &Value) -> Result<()> {
    let secret = &reply["objects"][0];
    let registration = &reply["registration"]["class"];
    let classes = [&secret["class"], registration];
    require(
        !classes
            .iter()
            .any(|c| **c == "foreign" || **c == "owned-drifted"),
        Failure::Ownership,
    )?;
    require(
        !classes.iter().any(|c| **c == "unobservable"),
        Failure::Readiness,
    )?;
    let owned = |activation: &str, keys: Value| {
        secret["class"] == "owned" && secret["activation"] == activation && secret["keys"] == keys
    };
    require(
        match stage {
            "create" => secret["class"] == "absent" && *registration == "absent",
            "supply" => owned("inactive", json!([])) && *registration == "present",
            "activate" => owned("inactive", json!([key])) && *registration == "present",
            "observe" => owned("active", json!([key])),
            _ => false,
        },
        Failure::Ownership,
    )
}

pub(super) fn shape(tag: &str, result: &Value) -> Result<()> {
    let read = tag == "inspect-objects";
    require(
        result["objects"].is_null() != read
            && result["registration"].is_null() != (read || tag == "register-input")
            && result["signing"].is_null() != read
            && result["services"].is_null() != read
            && result["terminal"].is_null() == read
            && (result["services"] == "unobserved") == (result["signing"]["state"] == "active"),
        Failure::Integrity,
    )
}

pub(super) fn expected(recipe: &Value) -> Value {
    let registration = &recipe["origins"]["registration"];
    json!({"secret":recipe["resource"]["uid"],
        "registration":if registration.is_null() {Value::Null} else {
            json!({"directory":registration["directory"],"record_sha256":registration["record_sha256"]})}})
}

pub(super) fn origins(
    previous: &[Snapshot],
    resource: &Value,
    succeeded_supply: &dyn Fn(&Snapshot) -> bool,
) -> Result<Value> {
    let reproduce = |request: &Value, attempt: &Value| {
        projection(request, &request["operation"], attempt, resource)
    };
    issuer::secret_origins(
        lifecycle(resource).0,
        previous,
        resource,
        succeeded_supply,
        &reproduce,
    )
}

fn service_ready(origins: Result<Value>) -> Result<()> {
    let service = super::registry_endpoint::prerequisite(origins)?;
    require(
        service["objects"]
            .as_array()
            .is_some_and(|o| o.iter().all(Value::is_object)),
        Failure::Readiness,
    )
}

fn first_server(owner: &Value) -> Result<()> {
    require(
        super::acting_server(owner)?["node_uid"].is_string(),
        Failure::Readiness,
    )
}

pub(super) fn prerequisites(owner: &Value) -> Result<Vec<Value>> {
    let resources = owner["resources"].as_array().ok_or(Failure::Integrity)?;
    let networked = resources
        .iter()
        .filter(|r| {
            r["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("network-object-"))
                && r["uid"].is_string()
        })
        .count();
    require(networked == 12, Failure::Ownership)?;
    (1..=5)
        .map(|n| {
            let id = format!("registry-service-object-{n:02}");
            resources
                .iter()
                .find(|r| r["id"] == id.as_str() && r["uid"].is_string())
                .cloned()
                .ok_or(Failure::Readiness)
        })
        .collect()
}

fn recipe(
    context: &rpc::Context<'_>,
    owner: &Value,
    operation: &str,
    registry: &str,
    resource: &Value,
    stage: &str,
    origins: &Value,
) -> Result<Value> {
    let profile: Value = serde_json::from_slice(PROFILE).map_err(|_| Failure::Configuration)?;
    rpc::body_pins(&profile)?;
    let members = owner["members"].as_array().ok_or(Failure::Integrity)?;
    let anchor = owner["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .find(|r| r["id"] == ANCHOR)
        .ok_or(Failure::Readiness)?;
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"first_server":members.first().ok_or(Failure::Integrity)?,
        "anchor_uid":anchor["uid"],"version":context.selected.declaration.version,
        "registry":registry,"resource":resource,
        "principal":principal_of(resource["id"].as_str().unwrap_or_default()).map(|(name, _)| name),
        "stage":stage,"origins":origins,
        "profile_sha256":context.fingerprints["profile_sha256"]});
    schema::validate(&canonical(&recipe)?, "RegistryAuthRecipe", 32_768)?;
    Ok(recipe)
}

fn fits(
    request: &Value,
    attempt: &str,
    count: usize,
    recipe: &Value,
    projection: &Value,
) -> Result<()> {
    let last = u64::try_from(count)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .ok_or(Failure::Bound)?;
    let mut binding = network::read_binding(request, attempt, last, 0)?;
    binding["receiver_generation"] = json!(u64::MAX);
    let wide = "f".repeat(128);
    let registration = json!({"directory":[u64::MAX,u64::MAX],"record_sha256":"0".repeat(64)});
    let preflight = json!({"objects":[{"kind":"Secret","namespace":"broil-registry",
            "name":"f".repeat(52),"uid":wide,"class":"owned-drifted","activation":"inactive",
            "keys":["signing-key"]}],
        "registration":{"class":"unobservable","directory":[u64::MAX,u64::MAX],
            "record_sha256":"0".repeat(64)},
        "signing":{"state":"unobservable","generation":"f".repeat(32)}});
    let header = json!({"protocol":FAMILY.protocol,"version":1,"action":"register-input",
        "request_id":fresh()?,"binding":binding,"remaining_ms":7_200_000,"recipe":recipe,
        "expected":{"secret":wide,"registration":registration},
        "resource":request["resources"][0],"preflight":preflight,"projection":projection});
    require(
        canonical(&header)?
            .len()
            .checked_add(17 + FAMILY.reserve)
            .is_some_and(|n| n <= 65_536),
        Failure::Bound,
    )
}

pub(super) enum Which {
    Signing,
    Install(String),
    Change(String),
    Continue(String),
    Current(String),
}

impl Which {
    fn name(&self) -> Option<&str> {
        match self {
            Self::Signing => None,
            Self::Install(name) | Self::Change(name) | Self::Current(name) => Some(name),
            Self::Continue(id) => principal_of(id).map(|(name, _)| name),
        }
    }
}

pub(super) fn naming(failure: super::ExecutionFailure, name: &str) -> super::ExecutionFailure {
    if failure.detail.is_some() || !matches!(failure.failure, Failure::Bound | Failure::Ownership) {
        return failure;
    }
    super::ExecutionFailure {
        detail: Some(Box::leak(name.to_owned().into_boxed_str())),
        ..failure
    }
}

fn checked(
    project: &LoadedProject,
    policy: &super::super::Policy,
    target: &str,
    principal: Option<&str>,
) -> super::ExecutionResult<Vec<String>> {
    let context = rpc::Context::new(project, issuer::duplicate(policy)?, target)?;
    let declaration = context.selected.declaration;
    let registry = gates(declaration.registry.as_ref(), &declaration.infrastructure)?;
    match principal {
        Some(name) => admitted(&registry, &Which::Change(name.into()))?,
        None => bounds(&registry)?,
    }
    super::registry_token::fit(&context)?;
    Ok(registry.authentication.principals.into_keys().collect())
}

pub(super) fn bounds(registry: &ManagedRegistry) -> super::ExecutionResult<()> {
    let principals = &registry.authentication.principals;
    if let Some((name, _)) = principals
        .iter()
        .enumerate()
        .find(|(n, (name, p))| *n >= 8 || name.len() > 93 || p.repositories.len() > 64)
        .map(|(_, found)| found)
    {
        return Err(naming(Failure::Bound.into(), name));
    }
    Ok(())
}

fn admitted(registry: &ManagedRegistry, which: &Which) -> super::ExecutionResult<()> {
    let declared = which
        .name()
        .is_some_and(|name| registry.authentication.principals.contains_key(name));
    require(declared, Failure::Configuration)?;
    bounds(registry)
}

fn generations(
    previous: &[Snapshot],
    owner: &Value,
    name: &str,
    succeeded: &dyn Fn(&Snapshot) -> bool,
) -> Result<Vec<(u64, Value, bool, bool)>> {
    let mut found = Vec::new();
    for resource in owner["resources"].as_array().ok_or(Failure::Integrity)? {
        let Some((principal, k)) = resource["id"].as_str().and_then(principal_of) else {
            continue;
        };
        if principal != name {
            continue;
        }
        let abandoned = previous.iter().any(|s| {
            let carried = &s.request["resources"][0];
            let stage = s.observations.iter().find_map(|o| {
                (o["event"]["type"] == "registry-auth-recipe")
                    .then(|| &o["event"]["recipe"]["stage"])
            });
            carried["id"] == resource["id"]
                && carried["generation"] == resource["generation"]
                && !succeeded(s)
                && (s.request["action"] == "prepare-state"
                    && s.request["consumer"]["action"] == PRINCIPAL.consumer
                    || s.request["action"] == "reconcile-registry-auth"
                        && stage.is_some_and(|s| s == "create" || s == "activate"))
        });
        let active = match origins(previous, resource, succeeded) {
            Ok(origins) => !origins["activation"].is_null(),
            Err(failure) if abandoned && failure != Failure::Integrity => false,
            Err(failure) => return Err(failure),
        };
        found.push((k, resource.clone(), active, abandoned));
    }
    found.sort_by_key(|g| g.0);
    require(
        found.windows(2).all(|w| w[0].0 < w[1].0),
        Failure::Integrity,
    )?;
    Ok(found)
}

pub(super) fn current(
    previous: &[Snapshot],
    owner: &Value,
    name: &str,
    succeeded: &dyn Fn(&Snapshot) -> bool,
) -> Result<Option<Value>> {
    let found = generations(previous, owner, name, succeeded)?;
    let Some((_, resource, ..)) = found.iter().rev().find(|g| g.2) else {
        return Ok(None);
    };
    let secret = &origins(previous, resource, succeeded)?["secret"];
    Ok(Some(
        json!({"id":resource["id"],"generation":resource["generation"],
        "name":resource["name"],"uid":resource["uid"],"operation":secret["operation"],
        "recipe_sha256":secret["recipe_sha256"]}),
    ))
}

fn chosen(which: &Which, generations: &[(u64, Value, bool, bool)]) -> Result<Option<String>> {
    let id = |g: &(u64, Value, bool, bool)| g.1["id"].as_str().map(str::to_owned);
    let latest = generations.last();
    let current = generations.iter().rev().find(|g| g.2);
    let resumable = latest.filter(|g| !g.2 && !g.3);
    Ok(match which {
        Which::Signing => Some(ID.into()),
        Which::Continue(continued) => Some(continued.clone()),
        Which::Current(_) => Some(current.and_then(id).ok_or(Failure::Ownership)?),
        Which::Install(name) => match (latest, resumable, current) {
            (None, ..) => Some(principal_id(name, 1)),
            (_, Some(g), _) => Some(id(g).ok_or(Failure::Integrity)?),
            (_, None, Some(_)) => None,
            (_, None, None) => return Err(Failure::Ownership),
        },
        Which::Change(name) => match (latest, resumable) {
            (None, _) => Some(principal_id(name, 1)),
            (_, Some(g)) => Some(id(g).ok_or(Failure::Integrity)?),
            (Some(g), None) => {
                let next = principal_id(name, g.0.checked_add(1).ok_or(Failure::Bound)?);
                require(next.len() <= 128, Failure::Bound)?;
                Some(next)
            }
        },
    })
}

async fn begin<'a>(
    project: &'a LoadedProject,
    policy: super::super::Policy,
    target: &str,
    which: &Which,
    observe: bool,
) -> super::ExecutionResult<Begun<'a>> {
    let context = rpc::Context::new(project, policy, target)?;
    let declaration = context.selected.declaration;
    let registry = gates(declaration.registry.as_ref(), &declaration.infrastructure)?;
    if which.name().is_some() {
        admitted(&registry, which)?;
    }
    let mut local = Local::new(&context)?;
    let prepared: Result<_> = async {
        let previous = local.work(|store| store.read_operations(None).map_err(|e| e.failure)).await?;
        let first = previous.first().ok_or(Failure::Ownership)?;
        let owner = first.owner.clone();
        require(!owner["cluster"].is_null()
            && owner["fingerprints"] == context.owner_fingerprints
            && owner["members"].as_array().is_some_and(|v| !v.is_empty()
                && v.iter().all(|m| m["node_uid"].is_string())), Failure::Ownership)?;
        let services = prerequisites(&owner)?;
        let report = |snapshot: &Snapshot| {
            super::report::report(&context.scope, "show", std::slice::from_ref(snapshot))
        };
        for snapshot in &previous {
            super::session::settled(&report(snapshot)?)?;
        }
        service_ready(super::registry_service::object_origins(&previous, &services))?;
        let succeeded = |snapshot: &Snapshot| report(snapshot).is_ok_and(|r| r["outcome"] == "succeeded");
        let id = match which.name() {
            None => Some(ID.to_owned()),
            Some(name) => chosen(which, &generations(&previous, &owner, name, &succeeded)?)?,
        };
        let Some(id) = id else {
            return Ok(Err(Value::Null));
        };
        let (resource, pending_owner) =
            issuer::planned_secret(&owner, &id, "registry-auth", "broil-registry")?;
        let origins = origins(&previous, &resource, &succeeded)?;
        let stage = stage(&origins)?;
        require((stage == "create") == resource["uid"].is_null(), Failure::Ownership)?;
        first_server(&owner)?;
        if stage == "supply" {
            return Ok(Err(resource));
        }
        if stage == "observe" && !observe {
            return Ok(Err(Value::Null));
        }
        budget(stage, context.clock.deadline()
            .saturating_duration_since(tokio::time::Instant::now()).as_secs())?;
        context.authenticate_owned(&json!(super::survivors(&owner)?)).await?;
        let current_owner = pending_owner.as_ref().unwrap_or(&owner).clone();
        let operation = format!("infra-operation-{}", fresh()?);
        let attempt_id = fresh()?;
        let source_events = network::source_recipes(&previous, &context, &current_owner, &operation, &attempt_id)?;
        let members = super::survivors(&current_owner)?;
        let participants = super::participants(&json!(members))?;
        require(current_owner["participants_sha256"] == participants, Failure::Ownership)?;
        let mut survivors = current_owner.clone();
        survivors["members"] = json!(members);
        let auth_recipe = recipe(&context, &survivors, &operation, &registry.name, &resource, stage, &origins)?;
        let created = now()?;
        let request_sequence = local.work(|store| store.next_sequence()).await?;
        let request = json!({"schema":2,"kind":"request","scope":context.scope,"owner":current_owner["owner"],
            "operation":operation,"created_ms":created,"sequence":request_sequence,"action":"reconcile-registry-auth",
            "members":members,"cluster":current_owner["cluster"],"resources":[resource],
            "config":context.config,"references":context.references,"consumer":null,
            "fingerprints":context.fingerprints,"participants_sha256":participants,
            "operation_timeout_ms":context.selected.operation_timeout.seconds*1000,
            "step_timeout_ms":context.selected.step_timeout.seconds*1000});
        let count = issuer::step_count(&members, effects(stage))?;
        let widest = if stage == "create" {
            let mut bound = resource.clone();
            bound["uid"] = json!("f".repeat(128));
            let ours = projection(&request, &json!(operation), &json!(attempt_id), &bound)?;
            let consumer = match principal_of(&id) {
                None => crate::k3s::Operation::RegistrySigning,
                Some((name, _)) => crate::k3s::Operation::RegistryPrincipal { name: name.into() },
            };
            require(ours == issuer::prepared_projection(&context, &current_owner, &operation, &attempt_id, &bound, consumer)?,
                Failure::Configuration)?;
            ours
        } else {
            Value::Null
        };
        fits(&request, &attempt_id, count, &auth_recipe, &widest)?;
        let mut cleanup = false;
        let checked = issuer::preflight(&FAMILY, &context, &request, &attempt_id, count as u64,
            &auth_recipe, expected(&auth_recipe), stage, checker(&resource), &source_events, &mut cleanup).await;
        local.cleanup_unknown |= cleanup;
        checked?;
        let current_owner = if let Some(successor) = pending_owner {
            local.work(move |store| store.plan_registry_auth(successor)).await?;
            require(local.snapshot()?.owner["resources"].as_array()
                .is_some_and(|resources| resources.last() == Some(&resource)), Failure::Ownership)?;
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
        for event in std::iter::once(json!({"type":"registry-auth-recipe","recipe":auth_recipe}))
            .chain(source_events) {
            let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
                "owner":current_owner["owner"],"operation":operation,"sequence":1,
                "recorded_ms":now()?,"producer_ms":null,
                "source":{"kind":"controller","machine":null},
                "attempt":attempt["attempt"],"step":null,"dispatch":null,"event":event});
            local.work(move |store| store.append(observation)).await?;
        }
        Ok(Ok((members, attempt_id, auth_recipe, stage)))
    }.await;
    let (members, attempt_id, auth_recipe, stage) = match prepared {
        Ok(Ok(value)) => value,
        Ok(Err(resource)) => {
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
            return Ok(if resource.is_null() {
                Begun::Done
            } else {
                Begun::Supply(resource)
            });
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
    Ok(Begun::Request(
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
        auth_recipe,
        stage,
    ))
}

fn checker(resource: &Value) -> fn(&str, &Value) -> Result<()> {
    if resource["id"] == ID {
        confirms
    } else {
        confirms_password
    }
}

pub(super) fn resumed(
    snapshot: &Snapshot,
    steps: &[Value],
    recipe: &Value,
) -> (Value, Option<Value>) {
    let mut values = expected(recipe);
    let step = |tag: &str| steps.iter().find(|s| s["action"] == action(tag));
    let created = step("create-object")
        .and_then(|step| issuer::recorded(snapshot, step, "receiver").ok())
        .map(|o| o["event"]["receipt"].clone())
        .filter(|r| r["outcome"] == "succeeded" && r["effect"] == "complete");
    if let Some(receipt) = &created {
        values["secret"] = receipt["resource_identity"].clone();
    }
    if let Some(reply) = step("register-input")
        .and_then(|s| issuer::recorded(snapshot, s, "registry-auth-observation").ok())
    {
        let fact = &reply["event"]["registration"];
        values["registration"] =
            json!({"directory":fact["directory"],"record_sha256":fact["record_sha256"]});
    }
    (values, created)
}

pub(super) async fn resume_objects(
    context: &rpc::Context<'_>,
    local: &mut Local,
    original: &Snapshot,
    recipe: &Value,
) -> Result<()> {
    let lifecycle = lifecycle(&recipe["resource"]).0;
    issuer::resume_secret(lifecycle, context, local, original, recipe, resumed).await
}

impl Session<'_> {
    async fn auth_run(&mut self, recipe: Value, stage: &str) -> Result<Snapshot> {
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let recipe_seq = network::latest_sequence(self.local.snapshot()?, "registry-auth-recipe")?;
        let request = self.local.snapshot()?.request.clone();
        let cluster = request["cluster"].clone();
        let resource = request["resources"][0].clone();
        let (lifecycle, confirms) = (lifecycle(&resource).0, checker(&resource));
        let mut values = expected(&recipe);
        let mut cited: Vec<Value> = Vec::new();
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
        self.network_source_gate().await?;
        let first = self
            .secret_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms(stage, &first)?;
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
        let second = self
            .secret_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms(stage, &second)?;
        if stage == "create" {
            let (step, created) = self
                .secret_effect(
                    lifecycle,
                    "create-object",
                    &recipe,
                    &recipe_seq,
                    &values,
                    &resource,
                    Value::Null,
                    None,
                )
                .await?;
            let uid = created["terminal"]["resource_identity"].clone();
            require(
                uid.as_str().is_some_and(crate::k3s::protocol::opaque),
                Failure::Ownership,
            )?;
            self.secret_receipt(&step).await?;
            values["secret"] = uid.clone();
            cited.push(self.recorded_sequence(&step, "receiver")?);
            let read = self
                .secret_read(&recipe, &recipe_seq, &values, &cited)
                .await?;
            require(
                read["objects"][0]["class"] == "owned"
                    && read["objects"][0]["uid"] == uid
                    && read["objects"][0]["activation"] == "inactive",
                Failure::Ownership,
            )?;
            let mut published = resource.clone();
            published["uid"] = uid;
            self.append(
                &step,
                json!({"type":"identity","member":null,"cluster":cluster,
                    "resources":[published],"readiness":super::report::readiness()}),
                false,
                Value::Null,
            )
            .await?;
            super::ingress::publish(&mut self.local, &published).await?;
            let identity = network::latest_sequence(self.local.snapshot()?, "identity")?;
            let projection = projection(
                &request,
                &request["operation"],
                &self.attempt["attempt"],
                &published,
            )?;
            let (step, registered) = self
                .secret_effect(
                    lifecycle,
                    "register-input",
                    &recipe,
                    &recipe_seq,
                    &values,
                    &resource,
                    projection.clone(),
                    Some(identity),
                )
                .await?;
            let fact = registered["registration"].clone();
            require(
                fact["class"] == "present"
                    && issuer::record_sha256(&fact["directory"], &projection)?
                        == fact["record_sha256"],
                Failure::Ownership,
            )?;
            self.secret_receipt(&step).await?;
            values["registration"] =
                json!({"directory":fact["directory"],"record_sha256":fact["record_sha256"]});
            cited.push(self.recorded_sequence(&step, "registry-auth-observation")?);
            let read = self
                .secret_read(&recipe, &recipe_seq, &values, &cited)
                .await?;
            require(read["registration"] == fact, Failure::Ownership)?;
        } else if stage == "activate" {
            let (step, _) = self
                .secret_effect(
                    lifecycle,
                    "activate",
                    &recipe,
                    &recipe_seq,
                    &values,
                    &resource,
                    Value::Null,
                    None,
                )
                .await?;
            self.secret_receipt(&step).await?;
            let read = self
                .secret_read(&recipe, &recipe_seq, &values, &cited)
                .await?;
            require(
                read["objects"][0]["class"] == "owned"
                    && read["objects"][0]["activation"] == "active",
                Failure::Ownership,
            )?;
        }
        let last = self
            .secret_read(&recipe, &recipe_seq, &values, &cited)
            .await?;
        confirms(
            if stage == "create" {
                "supply"
            } else {
                "observe"
            },
            &last,
        )?;
        self.settle(&order).await
    }
}

pub(super) async fn reconcile(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let (last, _) = run(project, &policy, target, Which::Signing, true).await?;
    last.ok_or_else(|| Failure::Integrity.into())
}

async fn run(
    project: &LoadedProject,
    policy: &super::super::Policy,
    target: &str,
    mut which: Which,
    observe: bool,
) -> super::ExecutionResult<(Option<Snapshot>, bool)> {
    let mut last: Option<Snapshot> = None;
    loop {
        let begun = begin(
            project,
            issuer::duplicate(policy)?,
            target,
            &which,
            observe && last.is_none(),
        );
        match begun.await? {
            Begun::Request(mut session, recipe, stage) => {
                let id = recipe["resource"]["id"]
                    .as_str()
                    .ok_or(Failure::Integrity)?
                    .to_owned();
                let result = Box::pin(session.auth_run(recipe, stage)).await;
                let snapshot = session
                    .local
                    .complete(result, &session.context.clock)
                    .await?;
                if stage != "create" {
                    return Ok((Some(snapshot), stage == "activate"));
                }
                last = Some(snapshot);
                which = Which::Continue(id);
            }
            Begun::Supply(resource) => {
                let text = |key: &str| -> Result<String> {
                    Ok(resource[key].as_str().ok_or(Failure::Integrity)?.to_owned())
                };
                let id = text("id")?;
                let operation = match principal_of(&id) {
                    None => super::super::Operation::RegistrySigning,
                    Some((name, _)) => {
                        super::super::Operation::RegistryPrincipal { name: name.into() }
                    }
                };
                let selection = super::ResourceSelection {
                    id: id.clone(),
                    generation: text("generation")?,
                };
                last = Some(
                    super::consume_existing(
                        project,
                        issuer::duplicate(policy)?,
                        target,
                        &text("machine")?,
                        selection,
                        operation,
                    )
                    .await?,
                );
                which = Which::Continue(id);
            }
            Begun::Done => return Ok((last, false)),
        }
    }
}

pub(super) async fn reconcile_principals(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
) -> super::ExecutionResult<Snapshot> {
    let names = checked(project, &policy, target, None)?;
    let mut last = None;
    for name in &names {
        let found = run(
            project,
            &policy,
            target,
            Which::Install(name.clone()),
            false,
        )
        .await;
        last = found.map_err(|failure| naming(failure, name))?.0.or(last);
    }
    if let Some(snapshot) = last {
        return Ok(snapshot);
    }
    let first = names.first().ok_or(Failure::Configuration)?;
    let observed = run(
        project,
        &policy,
        target,
        Which::Current(first.clone()),
        true,
    )
    .await;
    observed
        .map_err(|failure| naming(failure, first))?
        .0
        .ok_or_else(|| Failure::Integrity.into())
}

pub(super) async fn change_principal(
    project: &LoadedProject,
    policy: super::super::Policy,
    target: &str,
    principal: &str,
) -> super::ExecutionResult<Snapshot> {
    checked(project, &policy, target, Some(principal))?;
    let changed = run(
        project,
        &policy,
        target,
        Which::Change(principal.into()),
        false,
    )
    .await;
    changed
        .map_err(|failure| naming(failure, principal))?
        .0
        .ok_or_else(|| Failure::Integrity.into())
}

