// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::provenance::{recipe_hash, recipe_identity, undispatched_transport};
use super::session::{Mode, Session};
use super::{Failure, Result, Snapshot, bootstrap, canonical, require, rpc, schema, server};
use crate::k3s::protocol;
use serde_json::{Value, json};

fn succeeded(scope: &Value, snapshot: &Snapshot) -> bool {
    super::report::report(scope, "show", std::slice::from_ref(snapshot))
        .is_ok_and(|report| report["outcome"] == "succeeded" && report["cleanup_unknown"] == false)
}

pub(super) fn join_selection(servers: &[&Value], destination: &str) -> Result<bool> {
    require(
        servers.len() == 3 && servers[0]["node_uid"].is_string(),
        Failure::Configuration,
    )?;
    let selected = servers
        .iter()
        .position(|member| member["machine"] == destination)
        .ok_or(Failure::Configuration)?;
    let pending = servers
        .iter()
        .position(|member| member["node_uid"].is_null())
        .unwrap_or(servers.len());
    require(
        selected > 0
            && servers[..pending]
                .iter()
                .all(|member| member["node_uid"].is_string())
            && servers[pending..]
                .iter()
                .all(|member| member["node_uid"].is_null())
            && (selected < pending || selected == pending && pending < 3),
        Failure::Configuration,
    )?;
    Ok(selected < pending)
}

pub(super) fn replacement_order<T>(
    servers: &mut Vec<T>,
    selected: usize,
    published: impl Fn(&T) -> bool,
) -> bool {
    let replacing =
        !published(&servers[selected]) && servers[selected + 1..].iter().any(&published);
    if replacing {
        let moved = servers.remove(selected);
        servers.push(moved);
    }
    replacing
}

pub(super) fn replacement_selection(servers: &[&Value], destination: &str) -> Result<bool> {
    let selected = servers
        .iter()
        .position(|member| member["machine"] == destination)
        .ok_or(Failure::Configuration)?;
    require(
        servers.len() == 3
            && servers
                .iter()
                .enumerate()
                .all(|(index, m)| index == selected || m["node_uid"].is_string()),
        Failure::Configuration,
    )?;
    Ok(servers[selected]["node_uid"].is_string())
}

pub(super) fn admit_views(views: &[Value], expected_peers: &[String]) -> Result<()> {
    let first = views.first().ok_or(Failure::Readiness)?["members"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    let voters = first.len();
    require(
        (1..=3).contains(&voters)
            && voters == expected_peers.len()
            && views.len() > voters / 2
            && views.len() == voters
            && views
                .iter()
                .all(|view| view["healthy"] == true && view["members"].as_array() == Some(first))
            && first.iter().all(|member| {
                member["learner"] == false
                    && member["name"].as_str().is_some_and(|name| !name.is_empty())
                    && member["client_urls"]
                        .as_array()
                        .is_some_and(|urls| urls.len() == 1)
                    && member["peer_urls"].as_array().is_some_and(|urls| {
                        urls.len() == 1 && expected_peers.iter().any(|peer| urls[0] == *peer)
                    })
            })
            && expected_peers.iter().all(|peer| {
                first
                    .iter()
                    .filter(|member| member["peer_urls"][0] == *peer)
                    .count()
                    == 1
            }),
        Failure::Readiness,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn recipe_events(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    members: &Value,
    resources: &[Value],
    operation: &str,
    attempt: &str,
    source_recipe: &Value,
    repeat: bool,
) -> Result<Vec<Value>> {
    let selected_machine = resources.get(1).ok_or(Failure::Integrity)?["machine"]
        .as_str()
        .ok_or(Failure::Integrity)?;
    let mut servers: Vec<_> = members
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|m| m["role"] == "server")
        .collect();
    let mut selected = servers
        .iter()
        .position(|m| m["machine"] == selected_machine)
        .ok_or(Failure::Configuration)?;
    let replacing = replacement_order(&mut servers, selected, |m| m["node_uid"].is_string());
    if replacing {
        selected = servers.len() - 1;
    }
    let published = servers
        .iter()
        .take_while(|m| !m["node_uid"].is_null())
        .count();
    require(
        servers.len() == 3
            && (1..3).contains(&selected)
            && (repeat && selected < published || !repeat && selected == published)
            && servers[published..].iter().all(|m| m["node_uid"].is_null()),
        Failure::Configuration,
    )?;
    let mut installed = Vec::new();
    let mut events = Vec::new();
    let published_servers: Vec<Value> = servers
        .iter()
        .take(published)
        .map(|m| (*m).clone())
        .collect();
    for member in servers.iter().take(published) {
        let initial = source_recipe["member"]["machine"] == member["machine"];
        let mut recipe = if initial {
            source_recipe.clone()
        } else {
            let prior = previous
                .iter()
                .filter(|s| s.request["action"] == "join-server" && succeeded(&context.scope, s))
                .find(|s| {
                    s.observations.iter().any(|o| {
                        o["event"]["type"] == "server-join-recipe"
                            && o["event"]["recipe"]["member"]["machine"] == member["machine"]
                    })
                })
                .ok_or(Failure::Ownership)?;
            let original = &prior
                .observations
                .iter()
                .find(|o| o["event"]["type"] == "server-join-recipe")
                .ok_or(Failure::Integrity)?["event"]["recipe"];
            let mut recipe = original.clone();
            recipe["operation"] = json!(operation);
            recipe["attempt"] = json!(attempt);
            recipe["members"] = members.clone();
            recipe["member"] = (*member).clone();
            recipe["source"] = super::acting_first(&published_servers, &member["machine"])
                .ok_or(Failure::Ownership)?
                .clone();
            recipe
        };
        if initial {
            recipe["operation"] = json!(operation);
            recipe["attempt"] = json!(attempt);
            recipe["members"] = members.clone();
            recipe["member"] = (*member).clone();
        } else {
            recipe["installed"] = json!(installed.clone());
        }
        let identity = recipe_identity(&recipe)?;
        if !initial {
            let original = previous
                .iter()
                .filter(|s| s.request["action"] == "join-server")
                .flat_map(|s| &s.observations)
                .find(|o| {
                    o["event"]["type"] == "server-join-recipe"
                        && o["event"]["recipe"]["member"]["machine"] == member["machine"]
                })
                .ok_or(Failure::Ownership)?;
            require(
                identity == recipe_identity(&original["event"]["recipe"])?,
                Failure::Ownership,
            )?;
        }
        installed.push(json!({"member":member,"recipe_identity_sha256":identity}));
        events.push(json!({"type":"server-recipe","recipe_kind":if initial {"initial"} else {"join"},"recipe":recipe}));
    }
    for event in events.iter_mut().filter(|e| e["recipe_kind"] == "join") {
        event["recipe"]["installed"] = json!(installed.clone());
    }

    if repeat {
        let mut selected_recipe = events[selected]["recipe"].clone();
        selected_recipe["installed"] = json!(installed);
        require(
            recipe_identity(&selected_recipe)? == recipe_identity(&events[selected]["recipe"])?,
            Failure::Ownership,
        )?;
        events.push(json!({"type":"server-join-recipe","recipe":selected_recipe}));
        return Ok(events);
    }
    let prepared = if replacing {
        bootstrap::replacement_generation(context, previous, selected_machine)
    } else {
        bootstrap::selection_generation(context, previous, members, selected_machine)?
    }
    .ok_or(Failure::Readiness)?;
    let marker = &prepared["event"]["marker"];
    let generation = prepared["event"]["resource"]["generation"].clone();
    let declared = context
        .selected
        .declaration
        .members
        .iter()
        .find(|m| m.machine == selected_machine)
        .ok_or(Failure::Configuration)?;
    let mut config = server::rendered_config(context, context_owner(source_recipe)?, declared);
    config
        .as_object_mut()
        .ok_or(Failure::Integrity)?
        .remove("cluster-init");
    config["server"] = json!(crate::k3s::origin(
        &context.selected.declaration.registration_endpoint
    ));
    let source = &events[0]["recipe"];
    let recipe = json!({"schema":2,"scope":context.scope,"owner":source["owner"],
        "operation":operation,"attempt":attempt,"source":servers[0],"member":servers[selected],
        "members":members,"cluster":context_owner_cluster(previous)?,"installed":installed,
        "assets":{"generation":generation,"marker_sha256":protocol::digest(&canonical(marker)?)},
        "input":{"generation":resources[1]["generation"]},"source_input":resources[0],
        "version":source["version"],"executable":source["executable"],"archive":source["archive"],
        "guard_sha256":source["guard_sha256"],"unit_sha256":source["unit_sha256"],
        "config":config,"api_endpoint":source["api_endpoint"]});
    schema::validate(&canonical(&recipe)?, "JoinRecipe", 65_536)?;
    recipe_hash(&recipe)?;
    recipe_identity(&recipe)?;
    events.push(json!({"type":"server-join-recipe","recipe":recipe}));
    Ok(events)
}

fn context_owner(recipe: &Value) -> Result<&str> {
    recipe["owner"].as_str().ok_or(Failure::Integrity)
}

fn context_owner_cluster(previous: &[Snapshot]) -> Result<Value> {
    let cluster = previous.first().ok_or(Failure::Ownership)?.owner["cluster"].clone();
    require(!cluster.is_null(), Failure::Ownership)?;
    Ok(cluster)
}

pub(super) fn preflight(
    context: &rpc::Context<'_>,
    owner: &Value,
    request: &Value,
    attempt: &Value,
    recipes: &[Value],
    members: &[Value],
) -> Result<()> {
    fn length(value: &Value) -> Result<usize> {
        Ok(canonical(value)?.len())
    }
    fn add(parts: &[usize]) -> Result<usize> {
        parts.iter().try_fold(0usize, |total, part| {
            total.checked_add(*part).ok_or(Failure::Bound)
        })
    }
    let request_bytes = canonical(request)?;
    schema::validate(&request_bytes, "request", 262_144)?;
    require(request_bytes.len() < 262_144, Failure::Bound)?;
    let owner_bytes = canonical(owner)?;
    schema::validate(&owner_bytes, "owner", 65_536)?;
    require(owner_bytes.len() < 65_536, Failure::Bound)?;
    let attempt_bytes = canonical(attempt)?;
    schema::validate(&attempt_bytes, "attempt", 65_536)?;
    require(attempt_bytes.len() < 65_536, Failure::Bound)?;
    let resources = request["resources"].as_array().ok_or(Failure::Integrity)?;
    require(resources.len() == 2 && members.len() <= 128, Failure::Bound)?;
    let widest_resource = resources
        .iter()
        .max_by_key(|resource| length(resource).unwrap_or(usize::MAX))
        .ok_or(Failure::Integrity)?;
    require(length(widest_resource)? <= 512, Failure::Bound)?;
    let repeat = request["consumer"].is_null();
    let mut recipe_bytes = 0usize;
    let mut recipe_records = 0usize;
    for event in recipes {
        recipe_bytes = recipe_bytes.max(length(&event["recipe"])?);
        let observation = json!({"schema":1,"kind":"observation","scope":context.scope,
            "owner":request["owner"],"operation":request["operation"],"sequence":4096,
            "recorded_ms":u64::MAX,"producer_ms":null,
            "source":{"kind":"controller","machine":null},"attempt":attempt["attempt"],
            "step":null,"dispatch":null,"event":event});
        let bytes = canonical(&observation)?;
        schema::validate(&bytes, "observation", 65_536)?;
        require(bytes.len() < 65_536, Failure::Bound)?;
        recipe_records = add(&[recipe_records, bytes.len() + 1])?;
    }
    let mut binding_bytes = 0usize;
    for member in members {
        let binding = json!({"scope":context.scope,"owner":request["owner"],
            "operation":request["operation"],"attempt":attempt["attempt"],
            "step":u32::MAX,"dispatch":"f".repeat(32),"recipient":member,
            "receiver_generation":u64::MAX,"request_sha256":"f".repeat(64),
            "participants_sha256":request["participants_sha256"],
            "fingerprints":context.fingerprints});
        let size = length(&binding)?;
        require(size <= 4096, Failure::Bound)?;
        binding_bytes = binding_bytes.max(size);
        let widest_membership = json!({"cluster":server::widest_identity()["cluster"],
            "observer":member["machine"],"node_uid":"x".repeat(128),"healthy":true,
            "members":(0..3).map(|id| json!({"id":u64::MAX - id,"name":"x".repeat(262),
                "peer_urls":["https://255.255.255.255:2380"],
                "client_urls":["https://255.255.255.255:2379"],"learner":false}))
                .collect::<Vec<_>>()});
        for event in recipes {
            for (action, reserve) in [
                ("inspect-owned-server", 16_388usize),
                ("inspect-join", 16_388),
                ("observe-membership", 16_388),
                ("activate-join", 16_388),
                ("start-join", 16_388),
                ("observe-join", 16_388),
                ("publish-member", 16_388),
                ("prepare-join-source", 8_196),
            ] {
                if repeat && action == "prepare-join-source" {
                    continue;
                }
                let payload = if action == "prepare-join-source" {
                    json!({"recipe":event["recipe"],"resource":widest_resource,
                        "projection":request["consumer"]["projection"]})
                } else {
                    json!({"recipe_kind":event["recipe_kind"],"recipe":event["recipe"],
                        "identity":server::widest_identity(),"membership":widest_membership,"removed":null})
                };
                let header = json!({"protocol":"broil-k3s-lifecycle","version":1,
                    "action":action,"request_id":"f".repeat(32),"binding":binding,
                    "remaining_ms":7_200_000,"payload":payload});
                require(
                    add(&[14, length(&header)?, reserve])? <= 65_536,
                    Failure::Bound,
                )?;
            }
        }
    }
    require(
        add(&[binding_bytes * 3, recipe_bytes, 16_384, 2048])? < 65_536,
        Failure::Bound,
    )?;
    let count = attempt["steps"].as_array().ok_or(Failure::Integrity)?.len();
    let servers = 3usize;
    let lifecycle_slots = if repeat {
        3 + 2 * servers + 1
    } else {
        3 + 5 * servers + 4
    };
    let membership_slots = if repeat {
        2 * servers + 1
    } else {
        5 * servers + 1
    };
    let fixed_slot = add(&[binding_bytes * 3, 2048])?;
    let report_bound = add(&[
        request_bytes.len() + 1,
        attempt_bytes.len() + 1,
        owner_bytes.len() + 1,
        recipe_records * 2,
        count.checked_mul(fixed_slot).ok_or(Failure::Bound)?,
        lifecycle_slots
            .checked_mul(recipe_bytes * 2)
            .ok_or(Failure::Bound)?,
        membership_slots.checked_mul(16_384).ok_or(Failure::Bound)?,
    ])?;
    require(report_bound <= 1_048_576, Failure::Bound)
}

pub(super) fn owned_events_for_create(
    context: &rpc::Context<'_>,
    previous: &[Snapshot],
    members: &Value,
    operation: &str,
    attempt: &str,
    source_recipe: &Value,
) -> Result<Vec<Value>> {
    let published: Vec<_> = members
        .as_array()
        .ok_or(Failure::Integrity)?
        .iter()
        .filter(|m| m["role"] == "server" && !m["node_uid"].is_null())
        .collect();
    if published.len() <= 1 {
        return Ok(Vec::new());
    }
    let last = published.last().ok_or(Failure::Integrity)?;
    let prior = previous
        .iter()
        .find(|s| {
            s.request["action"] == "join-server"
                && succeeded(&context.scope, s)
                && s.observations.iter().any(|o| {
                    o["event"]["type"] == "server-join-recipe"
                        && o["event"]["recipe"]["member"]["machine"] == last["machine"]
                })
        })
        .ok_or(Failure::Ownership)?;
    let pair = prior.request["resources"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    Ok(recipe_events(
        context,
        previous,
        members,
        pair,
        operation,
        attempt,
        source_recipe,
        true,
    )?
    .into_iter()
    .filter(|event| event["type"] == "server-recipe" && event["recipe_kind"] == "join")
    .collect())
}

impl Session<'_> {
    pub(super) async fn join_server(mut self) -> super::ExecutionResult<Snapshot> {
        let result = self.join().await;
        self.local.complete(result, &self.context.clock).await
    }

    async fn join(&mut self) -> Result<Snapshot> {
        require(
            self.local.snapshot()?.request["action"] == "join-server",
            Failure::Capability,
        )?;
        let mut order: Vec<usize> = (0..self.members.len()).collect();
        order.sort_by(|a, b| {
            self.members[*a]["machine"]
                .as_str()
                .cmp(&self.members[*b]["machine"].as_str())
        });
        let mut servers: Vec<usize> = (0..self.members.len())
            .filter(|&i| self.members[i]["role"] == "server")
            .collect();
        require(servers.len() == 3, Failure::Configuration)?;
        let source = self.local.snapshot()?.request["resources"][0]["machine"].clone();
        let destination = self.local.snapshot()?.request["resources"][1]["machine"].clone();
        let selected = self
            .members
            .iter()
            .position(|m| m["machine"] == destination)
            .ok_or(Failure::Integrity)?;
        if let Some(position) = servers.iter().position(|&i| i == selected) {
            replacement_order(&mut servers, position, |&i| {
                self.members[i]["node_uid"].is_string()
            });
        }
        require(
            self.members[servers[0]]["machine"] == source && servers.contains(&selected),
            Failure::Ownership,
        )?;
        let installed = servers
            .iter()
            .take_while(|&&i| !self.members[i]["node_uid"].is_null())
            .count();
        let repeat = self.local.snapshot()?.request["consumer"].is_null();
        require(
            installed >= 1
                && (repeat && servers[..installed].contains(&selected)
                    || !repeat && installed < 3 && servers[installed] == selected),
            Failure::Configuration,
        )?;

        let cluster = self.local.snapshot()?.request["cluster"].clone();
        for &index in &order {
            let owner = self
                .inspect_step(index, "owner", Value::Null, Value::Null)
                .await?;
            require(
                owner["status"] == "ok"
                    && owner["data"]["claim"]["active_attempt"].is_null()
                    && owner["data"]["ownership"]["cluster"] == cluster
                    && ["machine", "member", "role", "node_uid"].iter().all(|key| {
                        owner["data"]["ownership"]["machine"][*key] == self.members[index][*key]
                    }),
                Failure::Ownership,
            )?;
            self.generations[index] = owner["data"]["claim"]["generation"]
                .as_u64()
                .ok_or(Failure::Integrity)?;
            let writer = self
                .inspect_step(index, "writer", Value::Null, Value::Null)
                .await?;
            require(
                matches!(writer["status"].as_str(), Some("ok" | "absent")),
                Failure::Ownership,
            )?;
        }
        for (position, &index) in servers.iter().enumerate() {
            let tag = if position < installed {
                "inspect-owned-server"
            } else if index == selected {
                "inspect-join"
            } else {
                "inspect-installation"
            };
            let (recipe, kind, sequence) =
                self.join_recipe(index, position >= installed && index != selected)?;
            let payload = if tag == "inspect-installation" {
                json!({"recipe":recipe,"identity":null})
            } else {
                json!({"recipe_kind":kind,"recipe":recipe,"identity":null,"membership":null,"removed":null})
            };
            let id = self.next_step;
            let observed = self
                .lifecycle_dispatch(id, index, tag, payload, vec![json!(sequence)], false)
                .await?;
            require(
                observed.result["installation"]["class"]
                    == if position < installed {
                        "owned"
                    } else {
                        "absent"
                    },
                Failure::Ownership,
            )?;
            self.next_step += 1;
        }
        let pair = self.local.snapshot()?.request["resources"]
            .as_array()
            .ok_or(Failure::Integrity)?
            .clone();
        if !repeat {
            for resource in &pair {
                let index = self
                    .members
                    .iter()
                    .position(|m| m["machine"] == resource["machine"])
                    .ok_or(Failure::Integrity)?;
                let result = self
                    .inspect_step(index, "resource", Value::Null, resource.clone())
                    .await?;
                require(result["status"] == "absent", Failure::Ownership)?;
            }
        }
        self.membership_round(&servers, installed, false).await?;
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
        let under_writer = self.membership_round(&servers, installed, false).await?;
        if repeat {
            let (recipe, kind, sequence) = self.join_recipe(selected, false)?;
            require(kind == "join", Failure::Integrity)?;
            let id = self.next_step;
            let result = self
                .lifecycle_dispatch(
                    id,
                    selected,
                    "observe-join",
                    json!({"recipe_kind":"join","recipe":recipe,"identity":null,"membership":null,"removed":null}),
                    vec![json!(sequence)],
                    false,
                )
                .await?;
            require(
                result.result["installation"]["class"] == "owned"
                    && result.result["membership"]["healthy"] == true
                    && result.result["identity"]["node_uid"] == self.members[selected]["node_uid"],
                Failure::Readiness,
            )?;
            self.next_step += 1;
            let final_round = self.membership_round(&servers, installed, true).await?;
            require(
                self.round_members(&under_writer)? == self.round_members(&final_round)?,
                Failure::Readiness,
            )?;
            return self.settle(&order).await;
        }
        self.consume().await?;
        for resource in &pair {
            let index = self
                .members
                .iter()
                .position(|m| m["machine"] == resource["machine"])
                .ok_or(Failure::Integrity)?;
            let result = self
                .inspect_step(index, "resource", Value::Null, resource.clone())
                .await?;
            require(
                result["status"] == "ok"
                    && result["data"]["resource"]["resource"] == *resource
                    && result["data"]["resource"]["identity"].is_array()
                    && result["data"]["resource"]["inactive"] == true,
                Failure::Ownership,
            )?;
        }
        let (recipe, kind, sequence) = self.join_recipe(selected, false)?;
        require(kind == "join", Failure::Integrity)?;
        let payload = |identity: Value, membership: Value| {
            json!({"recipe_kind":"join","recipe":recipe.clone(),
            "identity":identity,"membership":membership,"removed":null})
        };
        let id = self.next_step;
        self.lifecycle_dispatch(
            id,
            selected,
            "activate-join",
            payload(Value::Null, Value::Null),
            self.join_references(sequence, &under_writer),
            true,
        )
        .await?;
        self.next_step += 1;
        self.pre_start_render(selected).await?;
        let before_start = self.membership_round(&servers, installed, false).await?;
        require(
            self.round_members(&before_start)? == self.round_members(&under_writer)?,
            Failure::Readiness,
        )?;
        let id = self.next_step;
        self.lifecycle_dispatch(
            id,
            selected,
            "start-join",
            payload(Value::Null, Value::Null),
            self.join_references(sequence, &before_start),
            true,
        )
        .await?;
        self.next_step += 1;
        let id = self.next_step;
        let observed = self
            .lifecycle_dispatch(
                id,
                selected,
                "observe-join",
                payload(Value::Null, Value::Null),
                vec![json!(sequence)],
                false,
            )
            .await?;
        let identity = observed.result["identity"].clone();
        let installation = observed.observation.ok_or(Failure::Readiness)?;
        require(
            observed.result["installation"]["class"] == "started"
                && !identity.is_null()
                && observed.result["membership"]["healthy"] == true,
            Failure::Readiness,
        )?;
        self.next_step += 1;
        let after_start = self.membership_round(&servers, installed + 1, true).await?;
        let final_round = self.membership_round(&servers, installed + 1, true).await?;
        let prior = self.round_members(&under_writer)?;
        let after = self.round_members(&after_start)?;
        require(
            self.round_members(&final_round)? == after
                && prior
                    .as_array()
                    .ok_or(Failure::Integrity)?
                    .iter()
                    .all(|member| after.as_array().is_some_and(|items| items.contains(member))),
            Failure::Readiness,
        )?;
        let selected_membership = self
            .local
            .snapshot()?
            .observations
            .iter()
            .rev()
            .find(|o| {
                o["event"]["type"] == "server-membership"
                    && o["event"]["member"] == self.members[selected]
            })
            .ok_or(Failure::Integrity)?["event"]["membership"]
            .clone();
        require(
            selected_membership["node_uid"] == identity["node_uid"],
            Failure::Ownership,
        )?;
        let id = self.next_step;
        let mut references = self.join_references(sequence, &final_round);
        references.push(json!(installation));
        references.sort_by_key(|v| v.as_u64());
        let published = self
            .lifecycle_dispatch(
                id,
                selected,
                "publish-member",
                payload(identity.clone(), selected_membership),
                references,
                true,
            )
            .await?;
        let step = self
            .local
            .snapshot()?
            .steps
            .iter()
            .find(|step| step["step"] == id)
            .ok_or(Failure::Integrity)?
            .clone();
        self.append(
            &step,
            json!({"type":"identity","member":self.members[selected],
                "cluster":identity["cluster"],"resources":[],
                "readiness":published.result["readiness"]}),
            true,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        let snapshot = self.local.snapshot()?;
        let mut owner = server::published_owner(&snapshot.owner, selected, &identity)?;
        owner["resources"]
            .as_array_mut()
            .ok_or(Failure::Integrity)?
            .extend(pair);
        let operation = snapshot.request["operation"]
            .as_str()
            .ok_or(Failure::Integrity)?
            .to_owned();
        self.local
            .work(move |store| store.replace_owner(owner, &operation))
            .await?;
        self.settle(&order).await
    }

    pub(super) fn join_recipe(
        &self,
        index: usize,
        absent: bool,
    ) -> Result<(Value, &'static str, u64)> {
        let snapshot = self.local.snapshot()?;
        let machine = &self.members[index]["machine"];
        let event = snapshot
            .observations
            .iter()
            .find(|o| {
                o["event"]["type"] == "server-recipe"
                    && o["event"]["recipe"]["member"]["machine"] == *machine
            })
            .or_else(|| {
                if absent {
                    snapshot.observations.iter().find(|o| {
                        o["event"]["type"] == "server-recipe"
                            && o["event"]["recipe_kind"] == "initial"
                    })
                } else {
                    snapshot.observations.iter().find(|o| {
                        o["event"]["type"] == "server-join-recipe"
                            && o["event"]["recipe"]["member"]["machine"] == *machine
                    })
                }
            })
            .ok_or(Failure::Integrity)?;
        let kind = if event["event"]["recipe_kind"] == "initial" {
            "initial"
        } else {
            "join"
        };
        Ok((
            event["event"]["recipe"].clone(),
            kind,
            event["sequence"].as_u64().ok_or(Failure::Integrity)?,
        ))
    }

    fn join_references(&self, recipe: u64, round: &[Value]) -> Vec<Value> {
        let mut references = vec![json!(recipe)];
        references.extend_from_slice(round);
        references
    }

    pub(super) fn round_members(&self, round: &[Value]) -> Result<Value> {
        let sequence = round.first().ok_or(Failure::Readiness)?;
        Ok(self
            .local
            .snapshot()?
            .observations
            .iter()
            .find(|o| o["sequence"] == *sequence && o["event"]["type"] == "server-membership")
            .ok_or(Failure::Integrity)?["event"]["membership"]["members"]
            .clone())
    }

    async fn join_deselect(
        &mut self,
        index: usize,
        tag: &str,
        recipe: Value,
        kind: &str,
        sequence: u64,
    ) -> Result<()> {
        let payload = json!({"recipe_kind":kind,"recipe":recipe,"identity":null,"membership":null,"removed":null});
        let step = self.intended(
            index,
            &format!("lifecycle:{tag}"),
            &payload,
            vec![json!(sequence)],
        )?;
        let stored = step.clone();
        self.local.work(move |store| store.step(stored)).await?;
        self.append(
            &step,
            json!({"type":"dispatch","transport":undispatched_transport(),
            "outcome":"succeeded","failure":null}),
            false,
            Value::Null,
        )
        .await?;
        self.next_step += 1;
        Ok(())
    }

    pub(super) async fn membership_round(
        &mut self,
        servers: &[usize],
        installed: usize,
        _added: bool,
    ) -> Result<Vec<Value>> {
        let mut evidence = Vec::new();
        let mut views = Vec::new();
        for (position, &index) in servers.iter().enumerate() {
            let (recipe, kind, sequence) = self.join_recipe(index, position >= installed)?;
            if position >= installed {
                self.join_deselect(index, "observe-membership", recipe, kind, sequence)
                    .await?;
                continue;
            }
            let payload = json!({"recipe_kind":kind,"recipe":recipe,"identity":null,"membership":null,"removed":null});
            let id = self.next_step;
            let result = self
                .lifecycle_dispatch(
                    id,
                    index,
                    "observe-membership",
                    payload,
                    vec![json!(sequence)],
                    false,
                )
                .await?;
            let view = result.result["membership"].clone();
            require(
                !view.is_null()
                    && view["healthy"] == true
                    && view["observer"] == self.members[index]["machine"]
                    && view["cluster"] == self.local.snapshot()?.request["cluster"]
                    && (self.members[index]["node_uid"].is_null()
                        || view["node_uid"] == self.members[index]["node_uid"]),
                Failure::Readiness,
            )?;
            let event = self
                .local
                .snapshot()?
                .observations
                .iter()
                .rev()
                .find(|o| o["step"] == id && o["event"]["type"] == "server-membership")
                .ok_or(Failure::Integrity)?;
            evidence.push(event["sequence"].clone());
            views.push(view);
            self.next_step += 1;
        }
        let expected_peers: Vec<String> = servers
            .iter()
            .take(installed)
            .map(|&index| {
                let machine = self.members[index]["machine"].as_str().unwrap_or("");
                self.context
                    .selected
                    .declaration
                    .members
                    .iter()
                    .find(|m| m.machine == machine)
                    .map(|m| format!("https://{}:2380", m.node_ip))
                    .unwrap_or_default()
            })
            .collect();
        admit_views(&views, &expected_peers)?;
        Ok(evidence)
    }
}

