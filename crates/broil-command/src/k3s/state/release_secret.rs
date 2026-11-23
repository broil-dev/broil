// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::provenance::undispatched_transport;
use super::release::list;
use super::session::fresh;
use super::{Failure, Result, canonical, require, rpc};
use crate::k3s::{RELEASE, protocol};
use broil_config::LoadedProject;
use broil_remote::exec::{StaticStdin, private};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"BK3SRS1\n";
const HEADER_LIMIT: usize = 8192;
const INPUT_LIMIT: usize = 1_048_576;

pub(super) fn resource_id(application: &Value, secret: &Value) -> Result<String> {
    let digest = protocol::digest(&canonical(&json!([application, secret]))?);
    Ok(format!("application-secret-{}", &digest[..40]))
}

pub(super) fn resources(record: &Value, owner: &Value) -> Result<Vec<Value>> {
    list(&record["secrets"])
        .iter()
        .map(|secret| {
            Ok(json!({"kind":"application-secret",
                "id":resource_id(&record["application"], &secret["secret"])?,
                "owner":owner["owner"],"generation":fresh()?,"machine":null,"path":null,
                "namespace":record["namespace"],"name":secret["secret"],"uid":null}))
        })
        .collect()
}

pub(super) fn recipe_secrets(record: &Value, resources: &[Value]) -> Vec<Value> {
    list(&record["secrets"])
        .iter()
        .zip(resources)
        .map(|(secret, resource)| {
            json!({"secret":secret["secret"],"resource":resource["id"],
                "keys":list(&secret["keys"]).iter().map(|k| k["data_key"].clone()).collect::<Vec<_>>()})
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn admission(
    request: &Value,
    attempt: &Value,
    destination: &Value,
    resource: &Value,
    record: &Value,
    secret: &Value,
    request_id: &str,
    profile: &Value,
) -> Result<Value> {
    let scope = &request["scope"];
    let binding = json!({"project":scope["project"],"environment":scope["environment"],
        "target":scope["target"],"owner":request["owner"],"operation":request["operation"],
        "attempt":attempt,
        "destination":{"machine":destination["machine"],"member":destination["member"],
            "role":destination["role"],"node_uid":destination["node_uid"]},
        "cluster":request["cluster"],
        "resource":{"kind":resource["kind"],"id":resource["id"],
            "generation":resource["generation"],"uid":resource["uid"]}});
    let keys: Vec<Value> = list(&secret["keys"])
        .iter()
        .map(|k| k["data_key"].clone())
        .collect();
    let references: Vec<Value> = list(&secret["keys"])
        .iter()
        .map(|k| json!({"data_key":k["data_key"],"set":k["set"],"key":k["key"]}))
        .collect();
    let selection = json!({"schema":1,"binding":binding,"application":record["application"],
        "namespace":record["namespace"],"secret":secret["secret"],"keys":keys,
        "references":references,"profile":profile});
    let mut header = binding;
    for (key, value) in [
        ("protocol", json!("broil-k3s-release-secret")),
        ("version", json!(1)),
        ("action", json!("apply-secret")),
        ("request_id", json!(request_id)),
        ("application", record["application"].clone()),
        ("namespace", record["namespace"].clone()),
        ("secret", secret["secret"].clone()),
        ("keys", json!(keys)),
        (
            "profile_sha256",
            request["fingerprints"]["profile_sha256"].clone(),
        ),
        (
            "script_sha256",
            request["fingerprints"]["script_sha256"].clone(),
        ),
        (
            "selection_sha256",
            json!(protocol::digest(&canonical(&selection)?)),
        ),
    ] {
        header[key] = value;
    }
    Ok(header)
}

pub(super) async fn acquire(
    project: &LoadedProject,
    policy: &crate::k3s::Policy,
    secret: &Value,
    deadline: tokio::time::Instant,
) -> Result<(Zeroizing<Vec<u8>>, Vec<usize>)> {
    let selection = broil_secrets::read::Selection::new(
        &project.config,
        &project.broil_root,
        Some(std::ffi::OsStr::new(&policy.environment)),
    )
    .map_err(|_| Failure::Configuration)?;
    let references: Vec<(String, String)> = list(&secret["keys"])
        .iter()
        .map(|k| {
            Ok((
                k["set"].as_str().ok_or(Failure::Integrity)?.to_owned(),
                k["key"].as_str().ok_or(Failure::Integrity)?.to_owned(),
            ))
        })
        .collect::<Result<_>>()?;
    let credentials = policy
        .credentials
        .try_duplicate()
        .map_err(|_| Failure::Credential)?;
    let cwd = policy.cwd.clone();
    let non_interactive = policy.non_interactive;
    let cancellation = policy.cancellation.clone();
    let work = tokio::task::spawn_blocking(move || -> Result<(Zeroizing<Vec<u8>>, Vec<usize>)> {
        let stop = cancellation.clone();
        let control = broil_secrets::identity::AcquisitionControl::new(
            move || stop.is_cancelled() || tokio::time::Instant::now() >= deadline,
            || Box::new(()),
        );
        let mut values = Vec::with_capacity(references.len());
        for (set, key) in &references {
            let value = broil_secrets::read::resolve_scalar_with_options(
                &selection,
                &cwd,
                credentials
                    .try_duplicate()
                    .map_err(|_| Failure::Credential)?,
                key,
                Some(set),
                &control,
                non_interactive,
            )
            .map_err(|_| Failure::Credential)?;
            values.push(value.into_bytes());
        }
        let lengths: Vec<usize> = values.iter().map(|v| v.len()).collect();
        let total: usize = lengths.iter().map(|n| n + 4).sum();
        require(
            lengths.iter().all(|n| (1..=INPUT_LIMIT).contains(n)) && total <= INPUT_LIMIT,
            Failure::Bound,
        )?;
        let mut slots = Zeroizing::new(Vec::new());
        slots.try_reserve_exact(total).map_err(|_| Failure::Bound)?;
        for value in &values {
            slots.extend_from_slice(&(value.len() as u32).to_be_bytes());
            slots.extend_from_slice(value);
        }
        Ok((slots, lengths))
    });
    match tokio::time::timeout_at(deadline, work).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(Failure::Credential),
        Err(_) => Err(Failure::Timeout),
    }
}

pub(super) struct Dispatched {
    pub(super) transport: Value,
    pub(super) reply: Option<(u8, Value)>,
    pub(super) failure: Option<Failure>,
}

pub(super) async fn dispatch(
    context: &rpc::Context<'_>,
    destination: &Value,
    admission: &Value,
    slots: Zeroizing<Vec<u8>>,
    lengths: &[usize],
    deadline: tokio::time::Instant,
    child: &private::CredentialClock,
) -> Dispatched {
    let mut observed = Dispatched {
        transport: undispatched_transport(),
        reply: None,
        failure: None,
    };
    let result: Result<()> = async {
        context.check()?;
        let machine = destination["machine"].as_str().ok_or(Failure::Integrity)?;
        let connection = match context
            .connect_body(machine, deadline, Some(child), RELEASE)
            .await
        {
            Ok(connection) => connection,
            Err(failure) => {
                observed.transport = rpc::transport(&failure);
                return Err(Failure::Transport);
            }
        };
        let prepared = (|| {
            require(
                context.member(machine, &connection, destination["node_uid"].clone())?
                    == *destination,
                Failure::Trust,
            )?;
            let remaining = connection
                .deadline()
                .saturating_duration_since(tokio::time::Instant::now())
                .as_millis()
                .min(7_200_000) as u64;
            require(remaining > 0, Failure::Timeout)?;
            let mut header = admission.clone();
            header["remaining_ms"] = json!(remaining);
            header["slot_lengths"] = json!(lengths);
            let bytes = canonical(&header)?;
            let input = lengths
                .iter()
                .map(|n| n + 4)
                .sum::<usize>()
                .saturating_add(4 + bytes.len());
            require(
                bytes.len() <= HEADER_LIMIT && input <= INPUT_LIMIT,
                Failure::Bound,
            )?;
            Ok(bytes)
        })();
        let bytes = match prepared {
            Ok(bytes) => bytes,
            Err(failure) => {
                observed.transport = rpc::transport(&connection.close().await);
                return Err(failure);
            }
        };
        let output = connection
            .run_release_secret(bytes.clone(), StaticStdin::secret(slots), false)
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
        observed.reply = Some(reply(output.stdout.bytes(), &bytes)?);
        Ok(())
    }
    .await;
    observed.failure = result.err();
    observed
}

fn reply(bytes: &[u8], header: &[u8]) -> Result<(u8, Value)> {
    let rest = bytes.strip_prefix(MAGIC).ok_or(Failure::Integrity)?;
    let length = |at: &[u8]| -> Result<usize> {
        Ok(u32::from_be_bytes(
            at.get(..4)
                .ok_or(Failure::Integrity)?
                .try_into()
                .map_err(|_| Failure::Integrity)?,
        ) as usize)
    };
    let echo = length(rest)?;
    require(rest.get(4..4 + echo) == Some(header), Failure::Integrity)?;
    let rest = &rest[4 + echo..];
    let (status, kind) = (
        *rest.first().ok_or(Failure::Integrity)?,
        *rest.get(1).ok_or(Failure::Integrity)?,
    );
    let size = length(rest.get(2..).ok_or(Failure::Integrity)?)?;
    let payload = rest.get(6..).ok_or(Failure::Integrity)?;
    require(payload.len() == size, Failure::Integrity)?;
    match (status, kind) {
        (0, 3) => {
            require(size <= 256, Failure::Bound)?;
            let value: Value = serde_json::from_slice(payload).map_err(|_| Failure::Integrity)?;
            require(
                canonical(&value)? == payload
                    && value.as_object().is_some_and(|o| o.len() == 2)
                    && matches!(
                        value["outcome"].as_str(),
                        Some("created" | "configured" | "unchanged")
                    )
                    && value["uid"].as_str().is_some_and(protocol::opaque),
                Failure::Integrity,
            )?;
            Ok((0, value))
        }
        (status, 0) if status != 0 && size == 0 => Ok((status, Value::Null)),
        _ => Err(Failure::Integrity),
    }
}
