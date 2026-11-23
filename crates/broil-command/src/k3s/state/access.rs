// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Failure, Result, canonical, converge, hash, issuer, network, require, rpc, schema, session,
    views,
};
use crate::images::infrastructure_io::{self as supervise, Active, Clock, Permit};
use broil_config::LoadedProject;
use broil_core::secret::path_safety::effective_uid;
use broil_remote::scheduler::CancellationToken;
use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::Write,
    ops::Range,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub(in crate::k3s) fn supported(verb: &str) -> bool {
    matches!(
        verb,
        "credentials inspect"
            | "credentials reconcile"
            | "access check"
            | "access export"
            | "registry reconcile"
    )
}

pub(in crate::k3s) fn preflight(
    selected: &broil_config::k3s::select::SelectedTarget<'_>,
    verb: &str,
    consumer: Option<&str>,
) -> std::result::Result<(), crate::k3s::commands::Refusal> {
    let target = selected.declaration;
    let credentials = verb.starts_with("credentials");
    require(
        !credentials
            || consumer.is_some_and(|c| {
                matches!(
                    c,
                    "admin" | "infrastructure-tls" | "registry-auth" | "node-pull"
                )
            }),
        Failure::Capability,
    )?;
    if consumer == Some("infrastructure-tls") {
        views::preflight(target, "diagnose", Some("certificates"))?;
    }
    if verb.starts_with("registry") || matches!(consumer, Some("registry-auth" | "node-pull")) {
        if verb.starts_with("registry") || consumer == Some("registry-auth") {
            require(target.registry.is_some(), Failure::Configuration)?;
        }
        if target.registry.is_some()
            && (consumer != Some("node-pull")
                || target
                    .node_registries
                    .iter()
                    .any(|r| managed_entry(selected, &r.registry)))
        {
            views::preflight(target, "registry inspect", None)?;
        }
    }
    if matches!(verb, "credentials reconcile" | "credentials-reconcile")
        && consumer == Some("node-pull")
    {
        require(
            target.node_registries.iter().all(|entry| {
                target.registry.as_ref().is_some_and(|r| {
                    managed_entry(selected, &entry.registry)
                        && r.authentication
                            .principals
                            .get(&entry.username)
                            .is_some_and(|p| {
                                p.purpose == broil_core::k3s::PrincipalPurpose::NodePull
                            })
                })
            }),
            Failure::Capability,
        )?;
    }
    Ok(())
}

pub(super) fn managed_entry(
    selected: &broil_config::k3s::select::SelectedTarget<'_>,
    catalog: &str,
) -> bool {
    let origin = selected
        .declaration
        .registry
        .as_ref()
        .and_then(|r| selected.registries.get(&r.endpoint))
        .map(|r| r.declaration.endpoint.origin());
    selected
        .registries
        .get(catalog)
        .is_some_and(|r| origin.as_ref() == Some(&r.declaration.endpoint.origin()))
}

fn references(context: &rpc::Context<'_>, consumer: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut add = |purpose: &str,
                   subject: Option<&str>,
                   registry: Option<&str>,
                   r: &broil_core::images::SecretReference| {
        rows.push(json!({"purpose":purpose,"subject":subject,"registry":registry,"set":r.set,"key":r.key}))
    };
    let t = context.selected.declaration;
    if consumer == "infrastructure-tls" {
        for (name, issuer) in &t.infrastructure.issuers {
            if let broil_core::k3s::Issuer::PrivateCa { certificate, key } = issuer {
                add("issuer-certificate", Some(name), None, certificate);
                add("issuer-key", Some(name), None, key);
            }
        }
    } else if consumer == "registry-auth" {
        if let Some(r) = &t.registry {
            if let Some(key) = &r.authentication.signing_key {
                add("registry-signing", None, Some(&r.endpoint), key);
            }
            for (name, p) in &r.authentication.principals {
                add(
                    "registry-principal",
                    Some(name),
                    Some(&r.endpoint),
                    &p.password,
                );
            }
        }
    } else if consumer == "node-pull" {
        for r in &t.node_registries {
            add("node-pull", None, Some(&r.registry), &r.password);
        }
    }
    rows
}

pub(in crate::k3s) struct Prepared<'a> {
    context: rpc::Context<'a>,
    consumer: Option<String>,
    verb: String,
    output: Option<PathBuf>,
}

impl<'a> Prepared<'a> {
    pub(in crate::k3s) fn new(
        project: &'a LoadedProject,
        policy: &crate::k3s::Policy,
        target: &str,
        verb: &str,
        consumer: Option<&str>,
        output: Option<&str>,
    ) -> std::result::Result<Self, crate::k3s::commands::Refusal> {
        let context = rpc::Context::new(project, issuer::duplicate(policy)?, target)?;
        preflight(&context.selected, verb, consumer)?;
        if verb.starts_with("registry") {
            converge::registry_gates(&context)?;
        }
        if consumer == Some("infrastructure-tls")
            && matches!(verb, "credentials reconcile" | "credentials-reconcile")
        {
            let profile: Value =
                serde_json::from_slice(crate::k3s::PROFILE).map_err(|_| Failure::Configuration)?;
            super::cert_manager::version(
                &profile,
                &context
                    .selected
                    .declaration
                    .infrastructure
                    .cert_manager_version,
            )?;
            for certificate in context
                .selected
                .declaration
                .infrastructure
                .certificates
                .values()
            {
                let (duration, renew) = super::certificate::lifetime(certificate);
                super::certificate::duration_gate(duration, renew)?;
            }
            super::cert_manager::reference_fit(&context)?;
        }
        if consumer == Some("registry-auth")
            || consumer == Some("node-pull")
                && context
                    .selected
                    .declaration
                    .node_registries
                    .iter()
                    .any(|r| managed_entry(&context.selected, &r.registry))
        {
            if let Some(registry) = &context.selected.declaration.registry {
                super::registry_auth::gates(
                    Some(registry),
                    &context.selected.declaration.infrastructure,
                )?;
                super::registry_auth::bounds(registry)?;
                super::registry_token::fit(&context)?;
            }
        }
        let output = output
            .map(|s| {
                let raw = Path::new(s);
                let path = if raw.is_absolute() {
                    raw.to_owned()
                } else {
                    policy.cwd.join(raw)
                };
                require(
                    !path.components().any(|c| matches!(c, Component::ParentDir)),
                    Failure::Configuration,
                )?;
                let path: PathBuf = path
                    .components()
                    .filter(|c| !matches!(c, Component::CurDir))
                    .collect();
                for (key, value) in &policy.environment_snapshot {
                    if key == "HOME" {
                        require(
                            path != Path::new(value).join(".kube/config"),
                            Failure::Ownership,
                        )?;
                    }
                    if key == "KUBECONFIG" {
                        for candidate in std::env::split_paths(value) {
                            let candidate = if candidate.is_absolute() {
                                candidate
                            } else {
                                policy.cwd.join(candidate)
                            };
                            require(path != candidate, Failure::Ownership)?;
                        }
                    }
                }
                Ok::<_, Failure>(path)
            })
            .transpose()?;
        require(
            (verb == "access export") == output.is_some(),
            Failure::Configuration,
        )?;
        Ok(Self {
            context,
            consumer: consumer.map(str::to_owned),
            verb: verb.into(),
            output,
        })
    }
    pub(in crate::k3s) fn plan(&self) -> Result<Value> {
        let mut plan =
            converge::selected_plan(&self.context, &self.verb, self.consumer.as_deref())?;
        let consumer = self.consumer.as_deref().unwrap_or("registry-auth");
        plan["prerequisites"]["references"] = json!(
            references(&self.context, consumer)
                .iter()
                .map(|r| json!({"set":r["set"],"key":r["key"]}))
                .collect::<Vec<_>>()
        );
        let target = self.context.selected.declaration;
        let mut files = Vec::new();
        if consumer == "registry-auth" {
            if let Some(path) = target
                .registry
                .as_ref()
                .and_then(|r| r.authentication.signing_certificate.as_ref())
            {
                files.push(self.context.project.broil_root.join(path));
            }
        }
        if consumer == "node-pull" {
            for entry in &target.node_registries {
                if let Some(path) = &self.context.selected.registries[&entry.registry].ca {
                    files.push(path.clone());
                }
            }
        }
        if self.verb == "registry-reconcile" {
            if let Some(path) = target
                .registry
                .as_ref()
                .and_then(|r| self.context.selected.registries.get(&r.endpoint))
                .and_then(|r| r.ca.clone())
            {
                files.push(path);
            }
        }
        plan["prerequisites"]["files"] = json!(files);
        Ok(plan)
    }
    pub(in crate::k3s) fn workflow(&self) -> Result<Value> {
        converge::workflow(
            &self.context,
            "credentials-reconcile",
            self.consumer.as_deref(),
        )
    }
    pub(in crate::k3s) async fn run(
        self,
        plan: Option<Value>,
        stop: CancellationToken,
    ) -> super::ExecutionResult<(Value, bool)> {
        if let Some(plan) = plan {
            return converge::selected_observe(&self.context, plan).await;
        }
        let context = &self.context;
        let consumer = self
            .consumer
            .as_deref()
            .unwrap_or(if self.verb.starts_with("access") {
                "admin"
            } else {
                "registry-auth"
            });
        let mut execution = Value::Null;
        let mut exec_complete = true;
        if self.verb == "registry reconcile"
            || self.verb == "credentials reconcile" && consumer != "admin"
        {
            let action = self.verb.replace(' ', "-");
            (execution, exec_complete) =
                converge::selected_run(context, &action, self.consumer.as_deref(), stop.clone())
                    .await?;
        }
        let mut observations = Vec::new();
        let mut failure = None;
        let mut cleanup = false;
        let mut unknown = execution["completion_unknown"] == true;
        let mut export = Value::Null;
        let mut recovery = Value::Null;
        let mut missing_cluster = false;
        if consumer == "admin" {
            let mut destination = self
                .output
                .clone()
                .map(|path| Destination::new(path, context))
                .transpose()?;
            if let Some(d) = &mut destination {
                if let Err(f) = d.run(context, FileAction::Open, None).await {
                    failure = Some(f);
                }
            }
            if failure.is_none() {
                let read = administrator(context, destination.is_some()).await;
                failure = read.failure;
                missing_cluster = read.missing_cluster;
                if missing_cluster {
                    recovery = json!({"choice":"create","operation":null,"subject":null,"reason":"readiness"});
                }
                cleanup = read.row["cleanup_unknown"] == true;
                unknown |= read.completion_unknown
                    || cleanup
                    || read.failure == Some(Failure::Transport)
                        && read.row["transport"]["dispatch"] == "possible";
                observations.push(read.row);
                if let Some(d) = &mut destination {
                    if failure.is_none() {
                        if let Err(f) = d.run(context, FileAction::Publish, read.material).await {
                            failure = Some(f);
                        }
                    }
                }
            }
            if let Some(d) = &mut destination {
                if d.work.is_some() {
                    if let Err(f) = d.run(context, FileAction::Close, None).await {
                        failure.get_or_insert(f);
                        cleanup = true;
                    }
                } else {
                    cleanup = true;
                }
                if let Err(f) = context.check() {
                    failure.get_or_insert(f);
                }
                cleanup |= d.residue.load(Ordering::Acquire);
                unknown |=
                    d.unknown || failure.is_some() && d.publication.load(Ordering::Acquire) != 0;
                export = d.report(failure.is_none() && !cleanup);
                if failure.is_some() && (!missing_cluster || cleanup || unknown) {
                    recovery = json!({"choice":"operator-recovery","operation":null,"subject":d.path,"reason":failure.map(Failure::name)});
                }
            }
        } else if exec_complete && stop.is_cancelled() {
            failure = Some(Failure::Cancelled);
        } else if exec_complete {
            let reader = rpc::Context::new(
                context.project,
                issuer::duplicate(&context.policy)?,
                context.scope["target"].as_str().ok_or(Failure::Integrity)?,
            )?;
            match views::credentials(reader, consumer).await {
                Ok((view, complete)) => {
                    observations = view["observations"]
                        .as_array()
                        .cloned()
                        .ok_or(Failure::Integrity)?;
                    if !complete {
                        failure = Some(failure_name(view["failure"].as_str()));
                    }
                    cleanup = view["cleanup_unknown"] == true;
                    unknown |= view["completion_unknown"] == true;
                    recovery = json!({"choice":view["recovery"]["choice"],"operation":null,"subject":null,"reason":view["failure"]});
                }
                Err(e) => {
                    failure = Some(e.failure);
                    cleanup = e.cleanup_unknown;
                    unknown |= e.completion_unknown;
                }
            }
        }
        let access = access_evidence(&observations, consumer);
        if !exec_complete {
            failure = Some(failure_name(execution["failure"].as_str()));
        }
        if self.verb != "credentials inspect"
            && access.iter().any(|a| a["state"] != "verified")
            && failure.is_none()
        {
            failure = Some(Failure::Readiness);
        }
        let complete = failure.is_none() && !cleanup && exec_complete;
        let failed = failure.map(Failure::name);
        if !execution.is_null() {
            cleanup |= execution["cleanup_unknown"] == true;
            if !exec_complete {
                recovery = execution["recovery"].clone();
                recovery["reason"] = json!(failed);
            }
        }
        if complete {
            recovery = json!({"choice":"none","operation":null,"subject":null,"reason":null});
        } else if recovery.is_null() || recovery["choice"] == "none" {
            recovery = json!({"choice":"operator-recovery","operation":null,"subject":null,"reason":failed});
        }
        let members: Vec<Value> = context
            .selected
            .declaration
            .members
            .iter()
            .map(|m| {
                json!({"machine":m.machine,"member":m.name,
            "role":if m.role==broil_core::k3s::Role::Server {"server"}else{"agent"}})
            })
            .collect();
        Ok((
            json!({"format_version":1,"scope":context.scope,"view":self.verb.replace(' ',"-"),
            "consumer":if self.verb=="registry reconcile" {None}else{Some(consumer)},"references":references(context,consumer),
            "members_requested":members,"observations":observations,"access":access,"execution":execution,"export":export,
            "outcome":if complete {"complete"}else if failure==Some(Failure::Cancelled){"cancelled"}
                else if missing_cluster && recovery["choice"]=="create" {"refused"}else{"incomplete"},
            "failure":failed,"completion_unknown":unknown,"cleanup_unknown":cleanup,"recovery":recovery}),
            complete,
        ))
    }
}

fn failure_name(name: Option<&str>) -> Failure {
    [
        Failure::Configuration,
        Failure::Capability,
        Failure::Credential,
        Failure::Authentication,
        Failure::Trust,
        Failure::Ownership,
        Failure::Integrity,
        Failure::Storage,
        Failure::Transport,
        Failure::Readiness,
        Failure::Timeout,
        Failure::Cancelled,
        Failure::Bound,
        Failure::UnsupportedVersion,
        Failure::Busy,
    ]
    .into_iter()
    .find(|f| Some(f.name()) == name)
    .unwrap_or(Failure::Readiness)
}

fn access_evidence(rows: &[Value], _consumer: &str) -> Vec<Value> {
    let token = rows.iter().position(|r| r["kind"] == "registry-token");
    rows.iter().enumerate().map(|(index,row)| {
        let mut evidence=vec![index];
        let ready=row["failure"].is_null() && row["cleanup_unknown"]!=true && match row["kind"].as_str() {
            Some("admin")=>!row["facts"].is_null(),
            Some("issuer")=>row["facts"]["issuer"]["ready"]["state"]=="ready",
            Some("certificate")=>row["readiness"]["services"]=="ready",
            Some("registry-signing"|"registry-principals"|"node-registries")=>{
                let native=if row["kind"]=="node-registries" {
                    let principals:Vec<_>=rows.iter().enumerate().filter(|(_,r)|r["kind"]=="registry-principals").collect();
                    evidence.extend(principals.iter().map(|(i,_)|*i));
                    row["facts"]["configured"]==true && !principals.is_empty() && principals.iter().all(|(_,r)|
                        r["failure"].is_null() && r["cleanup_unknown"]!=true && r["facts"]["signing"]["state"]=="active")
                }
                    else {row["facts"]["signing"]["state"]=="active"};
                native && token.is_some_and(|i| {evidence.push(i);rows[i]["failure"].is_null() &&
                    rows[i]["cleanup_unknown"]!=true && rows[i]["readiness"]["services"]=="ready"})
            }
            Some("registry-token")=>row["readiness"]["services"]=="ready",
            _=>false,
        };
        json!({"subject":row["subject"],"member":row["member"],"state":if ready {"verified"}else{"unknown"},"evidence":evidence})
    }).collect()
}

fn frame(
    raw: &[u8],
    header: &[u8],
    export: bool,
) -> Result<std::result::Result<Range<usize>, Failure>> {
    let word = |offset: usize| -> Result<usize> {
        Ok(u32::from_be_bytes(
            raw.get(offset..offset + 4)
                .ok_or(Failure::Integrity)?
                .try_into()
                .map_err(|_| Failure::Integrity)?,
        ) as usize)
    };
    require(
        raw.len() <= 65536 && raw.starts_with(b"BK3SACC1\n"),
        Failure::Integrity,
    )?;
    let echo = word(9)?;
    require(
        echo == header.len() && raw.get(13..13 + echo) == Some(header),
        Failure::Integrity,
    )?;
    let code = *raw.get(13 + echo).ok_or(Failure::Integrity)?;
    let kind = *raw.get(14 + echo).ok_or(Failure::Integrity)?;
    let len = word(15 + echo)?;
    let start = 19 + echo;
    require(raw.len() == start + len, Failure::Integrity)?;
    let codes = [
        Failure::Readiness,
        Failure::Ownership,
        Failure::Credential,
        Failure::Bound,
        Failure::Integrity,
        Failure::Timeout,
        Failure::Cancelled,
        Failure::Busy,
        Failure::UnsupportedVersion,
        Failure::Storage,
    ];
    if code != 0 {
        require(kind == 0 && len == 0, Failure::Integrity)?;
        return Ok(Err(*codes
            .get(usize::from(code) - 1)
            .ok_or(Failure::Integrity)?));
    }
    require(
        if export {
            kind == 1 && len > 0
        } else {
            kind == 0 && len == 0
        },
        Failure::Integrity,
    )?;
    Ok(Ok(start..raw.len()))
}

pub(super) async fn published(
    context: &rpc::Context<'_>,
    owner: &Value,
    server: &Value,
    operation: &str,
    attempt: &str,
    cleanup: &mut bool,
) -> Result<Option<Failure>> {
    context.check()?;
    let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "cluster":owner["cluster"],"member":server,"first_server":server,
        "version":context.selected.declaration.version,"profile_sha256":context.fingerprints["profile_sha256"],
        "api_endpoint":context.selected.declaration.api.endpoint.supplied});
    let projection = json!({"scope":context.scope,"mode":"check","owner":owner["owner"],
        "cluster":owner["cluster"],"member":server,"source_operation":operation,
        "source_attempt":attempt,"recipe_sha256":hash("broil-k3s-node-access-recipe-v1", &recipe)?});
    let binding = json!({"scope":context.scope,"owner":owner["owner"],"operation":operation,
        "attempt":attempt,"step":1,"dispatch":session::fresh()?,"recipient":server,"receiver_generation":0,
        "request_sha256":hash("broil-infra-access-v1", &projection)?,
        "participants_sha256":owner["participants_sha256"],"fingerprints":owner["fingerprints"]});
    schema::validate(&canonical(&binding)?, "Binding", 4096)?;
    schema::validate(&canonical(&recipe)?, "NodeAccessRecipe", 32768)?;
    let deadline = context
        .clock
        .deadline()
        .min(Instant::now() + Duration::from_secs(context.selected.step_timeout.seconds.min(30)));
    let machine = server["machine"].as_str().ok_or(Failure::Integrity)?;
    let connection = match context
        .connect_body(machine, deadline, None, crate::k3s::NODE)
        .await
    {
        Ok(c) => c,
        Err(o) => {
            *cleanup |= network::unclean(&rpc::transport(&o));
            return Err(Failure::Transport);
        }
    };
    let prepared = (|| {
        require(
            context.member(machine, &connection, server["node_uid"].clone())? == *server,
            Failure::Trust,
        )?;
        let header = json!({"protocol":"broil-k3s-node","version":1,"action":"access",
            "request_id":session::fresh()?,"binding":binding,
            "remaining_ms":connection.deadline().saturating_duration_since(Instant::now()).as_millis().min(30000) as u64,
            "recipe":recipe,"mode":"check"});
        let header = canonical(&header)?;
        schema::validate(&header, "NodeAccessHeader", 32751)?;
        Ok(header)
    })();
    let header = match prepared {
        Ok(h) => h,
        Err(f) => {
            *cleanup |= network::unclean(&rpc::transport(&connection.close().await));
            return Err(f);
        }
    };
    let output = connection
        .run_lifecycle(header.clone(), false)
        .await
        .map_err(|_| Failure::Transport)?;
    let o = &output.observation;
    *cleanup |= network::unclean(&rpc::transport(o));
    require(
        o.failure.is_none()
            && o.remote_status == Some(0)
            && o.remote_signal.is_none()
            && !o.unresolved_input
            && !o.possible_staging_residue
            && output.stderr.bytes().is_empty(),
        Failure::Transport,
    )?;
    match frame(output.stdout.bytes(), &header, false)? {
        Ok(_) => Ok(None),
        Err(
            failure @ (Failure::Busy
            | Failure::Timeout
            | Failure::Cancelled
            | Failure::Bound
            | Failure::UnsupportedVersion),
        ) => Err(failure),
        Err(failure) => Ok(Some(failure)),
    }
}

struct AccessRead {
    row: Value,
    material: Option<Zeroizing<Vec<u8>>>,
    failure: Option<Failure>,
    completion_unknown: bool,
    missing_cluster: bool,
}

async fn administrator(context: &rpc::Context<'_>, export: bool) -> AccessRead {
    let mut row = json!({"kind":"admin","subject":null,"member":null,"source":"live","observed_ms":null,
        "operation":null,"facts":null,"readiness":null,
        "failure":null,"transport":null,"cleanup_unknown":false});
    let mut completion_unknown = false;
    let mut missing_cluster = false;
    let read: Result<Option<Zeroizing<Vec<u8>>>> = async {
        context.check()?;
        let (owner, records) = match views::owned_records(context).await {
            Ok(records)=>records,
            Err(e)=>{completion_unknown=e.completion_unknown;row["cleanup_unknown"]=json!(e.cleanup_unknown);return Err(e.failure);}
        };
        let owner = match owner {
            Some(owner) if !owner["cluster"].is_null() => owner,
            _ => { missing_cluster = true; return Err(Failure::Readiness); }
        };
        let source = records.first().ok_or(Failure::Readiness)?;
        let attempt = &source.attempts.last().ok_or(Failure::Integrity)?["attempt"];
        let member = &owner["members"][0];
        let step = source.steps.iter().filter(|s|s["attempt"] == *attempt).filter_map(|s|s["step"].as_u64())
            .max().unwrap_or(0).checked_add(1).filter(|s| *s<=u32::MAX as u64).ok_or(Failure::Bound)?;
        require(source.request["owner"] == owner["owner"] && source.request["members"].as_array().is_some_and(|ms|
            ms.iter().any(|m| views::read_member(m, member))), Failure::Ownership)?;
        let mode = if export { "export" } else { "check" };
        let recipe = json!({"scope":context.scope,"owner":owner["owner"],"operation":source.request["operation"],
            "cluster":owner["cluster"],"member":member,"first_server":member,
            "version":context.selected.declaration.version,"profile_sha256":context.fingerprints["profile_sha256"],
            "api_endpoint":context.selected.declaration.api.endpoint.supplied});
        let projection = json!({"scope":context.scope,"mode":mode,"owner":owner["owner"],"cluster":owner["cluster"],
            "member":member,"source_operation":source.request["operation"],"source_attempt":attempt,
            "recipe_sha256":hash("broil-k3s-node-access-recipe-v1", &recipe)?});
        let binding = json!({"scope":context.scope,"owner":owner["owner"],"operation":source.request["operation"],
            "attempt":attempt,"step":step,"dispatch":session::fresh()?,"recipient":member,"receiver_generation":0,
            "request_sha256":hash("broil-infra-access-v1", &projection)?,
            "participants_sha256":source.request["participants_sha256"],"fingerprints":context.fingerprints});
        schema::validate(&canonical(&binding)?, "Binding", 4096)?;
        schema::validate(&canonical(&recipe)?, "NodeAccessRecipe", 32768)?;
        let deadline = context.clock.deadline().min(Instant::now()+Duration::from_secs(context.selected.step_timeout.seconds.min(30)));
        let machine = member["machine"].as_str().ok_or(Failure::Integrity)?;
        let connection = match context.connect_body(machine, deadline, None, crate::k3s::NODE).await {
            Ok(c) => c,
            Err(o) => { row["transport"] = rpc::transport(&o); return Err(Failure::Transport); }
        };
        let prepared = (|| {
            require(context.member(machine, &connection, member["node_uid"].clone())? == *member, Failure::Trust)?;
            let header = json!({"protocol":"broil-k3s-node","version":1,"action":"access","request_id":session::fresh()?,
                "binding":binding,"remaining_ms":connection.deadline().saturating_duration_since(Instant::now()).as_millis().min(30000) as u64,
                "recipe":recipe,"mode":mode});
            let header = canonical(&header)?;
            schema::validate(&header, "NodeAccessHeader", 32751)?;
            Ok(header)
        })();
        let header = match prepared {
            Ok(h) => h,
            Err(f) => { row["transport"]=rpc::transport(&connection.close().await); return Err(f); }
        };
        row["transport"]=json!({"dispatch":"possible","exit":null,"signal":null,"input_released":false,"staging_cleanup":"unknown"});
        let output = connection.run_lifecycle(header.clone(), false).await.map_err(|_|Failure::Transport)?;
        let o = &output.observation;
        row["transport"]=rpc::transport(o);
        require(o.failure.is_none() && o.remote_status == Some(0) && o.remote_signal.is_none() &&
            !o.unresolved_input && !o.possible_staging_residue && output.stderr.bytes().is_empty(), Failure::Transport)?;
        let range = frame(output.stdout.bytes(), &header, export)??;
        context.check()?;
        row["member"]=member["member"].clone();
        row["operation"]=source.request["operation"].clone();
        row["observed_ms"]=json!(session::now()?);
        row["facts"]=json!({"cluster":owner["cluster"],"member":member,
            "api_endpoint":context.selected.declaration.api.endpoint.supplied,"credential_identity":null,"expires_ms":null});
        if !export {return Ok(None);}
        let mut bytes=Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(range.len()).map_err(|_|Failure::Bound)?;
        bytes.extend_from_slice(&output.stdout.bytes()[range]);
        Ok(Some(bytes))
    }.await;
    let failure = read.as_ref().err().copied();
    row["failure"] = json!(failure.map(Failure::name));
    row["cleanup_unknown"] = json!(
        row["cleanup_unknown"] == true
            || !row["transport"].is_null() && network::unclean(&row["transport"])
    );
    AccessRead {
        row,
        material: read.ok().flatten(),
        failure,
        completion_unknown,
        missing_cluster,
    }
}

#[derive(Clone, Copy)]
enum FileAction {
    Open,
    Publish,
    Close,
}

pub(crate) struct FileWork {

    temporary: String,
    parents: Vec<File>,
    parts: Vec<std::ffi::OsString>,
    action: FileAction,
    material: Option<Zeroizing<Vec<u8>>>,
    publication: Arc<AtomicU8>,
    residue: Arc<AtomicBool>,
    failure: Option<Failure>,

}

impl Drop for FileWork {
    fn drop(&mut self) {
        if !self.parents.is_empty() || self.material.is_some() {
            std::mem::forget(std::mem::take(&mut self.parents));
            std::mem::forget(self.material.take());
        }
    }
}

impl FileWork {
    fn new(path: PathBuf) -> Result<Self> {
        require(
            path.is_absolute()
                && path
                    .to_str()
                    .is_some_and(|s| !s.is_empty() && s.len() <= 4096 && !s.contains('\0')),
            Failure::Configuration,
        )?;
        let mut parts = Vec::new();
        for part in path.components() {
            match part {
                Component::Normal(p) => parts.push(p.to_owned()),
                Component::RootDir => {}
                _ => return Err(Failure::Configuration),
            }
        }
        require(!parts.is_empty(), Failure::Configuration)?;
        Ok(Self {

            temporary: format!(".broil-access-{}", session::fresh()?),
            parents: Vec::new(),
            parts,
            action: FileAction::Open,
            material: None,
            publication: Arc::new(AtomicU8::new(0)),
            residue: Arc::new(AtomicBool::new(false)),
            failure: None,

        })
    }

    fn identity(file: &File) -> Result<(u64, u64)> {
        let m = file.metadata().map_err(|_| Failure::Storage)?;
        Ok((m.dev(), m.ino()))
    }
    fn recheck(&self, active: &Active) -> Result<()> {
        active.check()?;
        for (i, fd) in self.parents.iter().enumerate() {
            let m = active.io(|| fd.metadata())?;
            require(
                m.is_dir() && (m.uid() == 0 || m.uid() == effective_uid()) && m.mode() & 0o022 == 0,
                Failure::Ownership,
            )?;
            if i > 0 {
                let found = active.sys(|| {
                    rustix::fs::statat(
                        &self.parents[i - 1],
                        &self.parts[i - 1],
                        AtFlags::SYMLINK_NOFOLLOW,
                    )
                })?;
                require(
                    (found.st_dev, found.st_ino) == (m.dev(), m.ino()),
                    Failure::Ownership,
                )?;
            }
        }
        let m = active.io(|| {
            self.parents
                .last()
                .ok_or_else(|| std::io::Error::other("parent"))?
                .metadata()
        })?;
        require(
            m.uid() == effective_uid() && m.mode() & 0o7777 == 0o700,
            Failure::Ownership,
        )
    }
    fn open(&mut self, active: &Active) -> Result<()> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        self.parents.push(File::from(
            active.sys(|| rustix::fs::open("/", flags, Mode::empty()))?,
        ));
        for part in &self.parts[..self.parts.len() - 1] {
            self.parents.push(File::from(active.sys(|| {
                rustix::fs::openat(
                    self.parents.last().expect("root"),
                    part,
                    flags,
                    Mode::empty(),
                )
            })?));
        }
        self.recheck(active)?;
        let found = rustix::fs::statat(
            self.parents.last().ok_or(Failure::Integrity)?,
            self.parts.last().ok_or(Failure::Integrity)?,
            AtFlags::SYMLINK_NOFOLLOW,
        );
        active.check()?;
        require(
            matches!(found, Err(rustix::io::Errno::NOENT)),
            Failure::Ownership,
        )
    }
    fn content(file: &File, bytes: &[u8], active: &Active) -> Result<()> {
        use std::io::{Read, Seek};
        let before = active.io(|| file.metadata())?;
        let mut readback = Zeroizing::new(vec![0; bytes.len()]);
        let mut reader = file;
        active.io(|| reader.rewind())?;
        active.io(|| reader.read_exact(&mut readback))?;
        let after = active.io(|| file.metadata())?;
        require(
            readback.as_slice() == bytes
                && before.len() == bytes.len() as u64
                && after.len() == before.len()
                && (
                    after.mtime(),
                    after.mtime_nsec(),
                    after.ctime(),
                    after.ctime_nsec(),
                ) == (
                    before.mtime(),
                    before.mtime_nsec(),
                    before.ctime(),
                    before.ctime_nsec(),
                ),
            Failure::Integrity,
        )
    }
    fn write(&mut self, active: &Active) -> Result<()> {
        self.recheck(active)?;
        let parent = self.parents.last().ok_or(Failure::Integrity)?;
        active.check()?;
        self.residue.store(true, Ordering::Release);
        let file = File::from(
            rustix::fs::openat(
                parent,
                self.temporary.as_str(),
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    self.residue.store(false, Ordering::Release);
                }
                Failure::Storage
            })?,
        );
        let identity = Self::identity(&file)?;
        let result = (|| {
            let bytes = self.material.as_ref().ok_or(Failure::Integrity)?;
            require(!bytes.is_empty() && bytes.len() <= 65536, Failure::Bound)?;
            active.io(|| (&file).write_all(bytes))?;

            active.io(|| file.sync_all())?;

            self.recheck(active)?;
            let m = active.io(|| file.metadata())?;
            require(
                m.is_file()
                    && m.uid() == effective_uid()
                    && m.mode() & 0o7777 == 0o600
                    && m.nlink() == 1
                    && m.len() == bytes.len() as u64
                    && (m.dev(), m.ino()) == identity,
                Failure::Ownership,
            )?;
            let found = active.sys(|| {
                rustix::fs::statat(parent, self.temporary.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            })?;
            require((found.st_dev, found.st_ino) == identity, Failure::Ownership)?;
            Self::content(&file, bytes, active)?;
            active.check()?;
            self.publication.store(1, Ordering::Release);
            let renamed = rustix::fs::renameat_with(
                parent,
                self.temporary.as_str(),
                parent,
                self.parts.last().ok_or(Failure::Integrity)?,
                RenameFlags::NOREPLACE,
            );
            if let Err(error) = renamed {
                if matches!(
                    error,
                    rustix::io::Errno::NOSYS | rustix::io::Errno::INVAL | rustix::io::Errno::EXIST
                ) {
                    self.publication.store(0, Ordering::Release);
                }
                return Err(
                    if error == rustix::io::Errno::NOSYS || error == rustix::io::Errno::INVAL {
                        Failure::Capability
                    } else if error == rustix::io::Errno::EXIST {
                        Failure::Ownership
                    } else {
                        Failure::Storage
                    },
                );
            }
            self.residue.store(false, Ordering::Release);
            active.check()?;

            active.io(|| parent.sync_all())?;
            self.recheck(active)?;
            let found = active.sys(|| {
                rustix::fs::statat(
                    parent,
                    self.parts.last().ok_or(rustix::io::Errno::INVAL)?,
                    AtFlags::SYMLINK_NOFOLLOW,
                )
            })?;
            Self::content(&file, bytes, active)?;
            let m = active.io(|| file.metadata())?;
            require(
                (found.st_dev, found.st_ino) == identity
                    && m.uid() == effective_uid()
                    && m.mode() & 0o7777 == 0o600
                    && m.nlink() == 1
                    && m.len() == bytes.len() as u64,
                Failure::Ownership,
            )?;
            Ok(())
        })();
        if result.is_err() && self.publication.load(Ordering::Acquire) == 0 {
            let grace = active.cleanup_grace();
            let cleanup = (|| {
                grace.check()?;
                let found =
                    rustix::fs::statat(parent, self.temporary.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|_| Failure::Storage)?;
                require((found.st_dev, found.st_ino) == identity, Failure::Ownership)?;
                grace.check()?;
                rustix::fs::unlinkat(parent, self.temporary.as_str(), AtFlags::empty())
                    .map_err(|_| Failure::Storage)?;
                grace.check()?;
                parent.sync_all().map_err(|_| Failure::Storage)?;
                grace.check()?;
                Ok::<_, Failure>(())
            })();
            if cleanup.is_ok() {
                self.residue.store(false, Ordering::Release);
            }
        }
        drop(file);
        self.material = None;
        result
    }
    pub(crate) fn apply(
        &mut self,
        active: &Active,
    ) -> std::result::Result<(), crate::images::Failure> {
        let result = match self.action {
            FileAction::Open => self.open(active),
            FileAction::Publish => self.write(active),
            FileAction::Close => {
                self.material = None;
                self.parents.clear();
                Ok(())
            }
        };
        self.failure = result.as_ref().err().copied();

        result.map_err(|_| crate::images::Failure::Integrity)
    }
}

struct PendingFile(Option<(FileWork, Clock, Arc<Permit>)>);
impl Drop for PendingFile {
    fn drop(&mut self) {
        std::mem::forget(self.0.take());
    }
}

struct Destination {
    work: Option<(FileWork, Clock)>,
    permit: Arc<Permit>,
    cancelled: Arc<AtomicBool>,
    publication: Arc<AtomicU8>,
    residue: Arc<AtomicBool>,
    path: PathBuf,
    temporary: PathBuf,
    unknown: bool,
    publishing: bool,

}

impl Drop for Destination {
    fn drop(&mut self) {
        if let Some((work, clock)) = self.work.take() {
            if !work.parents.is_empty() || work.material.is_some() {
                std::mem::forget((work, clock, self.permit.clone()));
            }
        }
    }
}

impl Destination {
    fn new(path: PathBuf, context: &rpc::Context<'_>) -> Result<Self> {
        let work = FileWork::new(path.clone())?;
        let ms = context
            .clock
            .deadline()
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(7_200_000) as u64;
        Ok(Self {
            permit: Permit::acquire()?,
            cancelled: Arc::new(AtomicBool::new(false)),
            publication: work.publication.clone(),
            residue: work.residue.clone(),
            temporary: path.with_file_name(&work.temporary),
            path,
            work: Some((work, Clock::new(ms)?)),
            unknown: false,
            publishing: false,

        })
    }
    async fn run(
        &mut self,
        context: &rpc::Context<'_>,
        action: FileAction,
        material: Option<Zeroizing<Vec<u8>>>,
    ) -> Result<()> {
        if !matches!(action, FileAction::Close) {
            context.check()?;
        }
        let (mut work, mut clock) = self.work.take().ok_or(Failure::Busy)?;
        work.action = action;
        self.publishing |= matches!(action, FileAction::Publish);
        work.material = material;
        work.failure = None;
        let closing = matches!(action, FileAction::Close);
        let until = if closing {
            context
                .clock
                .local_release_deadline(&context.policy.cancellation)
        } else {
            context
                .clock
                .deadline()
                .min(Instant::now() + Duration::from_secs(30))
        };
        if closing {
            clock.end = clock.cleanup(
                until
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(5000) as u64,
            );
            self.cancelled.store(false, Ordering::Release);
        }
        let mut pending = PendingFile(Some((work, clock, self.permit.clone())));
        let cancelled = self.cancelled.clone();
        let mut task = tokio::task::spawn_blocking(move || {
            let (work, mut clock, permit) = pending.0.take().expect("owned export work");
            let (work, result) = supervise::access_local(work, &mut clock, &cancelled, &permit);
            (PendingFile(work.map(|work| (work, clock, permit))), result)
        });

        let completed = tokio::select! {
            biased;
            _=context.policy.cancellation.cancelled(), if !closing => Err(Failure::Cancelled),
            result=tokio::time::timeout_at(until,&mut task)=>match result {
                Ok(Ok(result))=>Ok(result),Ok(Err(_))=>Err(Failure::Storage),Err(_)=>Err(Failure::Timeout),
            }
        };
        match completed {
            Ok((mut pending, result)) => {
                self.work = pending.0.take().map(|(work, clock, _)| (work, clock));
                match self.work.as_ref() {
                    Some((work, _)) => result.map_err(|e| work.failure.unwrap_or(e.into())),
                    None => {
                        self.unknown = true;
                        Err(result
                            .err()
                            .map(Failure::from)
                            .unwrap_or(Failure::Integrity))
                    }
                }
            }
            Err(f) => {
                self.cancelled.store(true, Ordering::Release);
                self.unknown = true;
                context.clock.abort();
                Err(f)
            }
        }
    }
    fn report(&self, complete: bool) -> Value {
        json!({"path":self.path,"publication":if complete {"published"}
            else if self.unknown || self.publication.load(Ordering::Acquire)!=0 {"unknown"}else{"not-published"},
            "temporary_residue":(self.residue.load(Ordering::Acquire) || self.unknown && self.publishing).then_some(&self.temporary)})
    }
}

