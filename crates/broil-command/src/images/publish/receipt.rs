// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    ClosureMember, PublicationCheck, PublicationClass, PublicationObservation, PublicationOutcome,
    ServerIdentity, TagAssociation, Unproved,
};
use crate::images::{RegistryOutcome, StageError};
use crate::images::{
    common::*,
    content,
    json::Value,
    outputs::{NodeChain, Source, plan},
};
use broil_core::images::reference::ImageReference;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub(crate) struct Planned {
    pub(crate) root: Descriptor,
    pub(crate) index: Option<Vec<u8>>,
    pub(crate) wrapper: Vec<u8>,
    pub(crate) blobs: Vec<(Descriptor, &'static str, Entry)>,
    pub(crate) closure: Vec<(Descriptor, &'static str)>,
    pub(crate) descriptors: u64,
    pub(crate) content_bytes: u64,
}

impl Planned {
    pub(crate) fn members(&self, local: &'static str) -> Vec<ClosureMember> {
        self.closure
            .iter()
            .map(|(descriptor, role)| ClosureMember {
                descriptor: descriptor.clone(),
                role,
                local,
                endpoint: "receipt-readback",
            })
            .collect()
    }
}

fn role(media_type: &str, root: bool) -> &'static str {
    if root {
        "root"
    } else if content::root_media(media_type) {
        "manifest"
    } else if media_type.ends_with("+json") || media_type.contains("image.config") {
        "config"
    } else {
        "layer"
    }
}

pub(crate) fn plan_target(
    chains: &[NodeChain],
    reference: &ImageReference,
    limits: &ContentLimits,
) -> Result<Planned> {
    let assembly = plan(chains, reference, limits)?;
    let mut closure = Vec::new();
    let mut blobs = Vec::new();
    for (descriptor, source) in &assembly.blobs {
        let named = role(&descriptor.media_type, *descriptor == assembly.root);
        closure.push((descriptor.clone(), named));
        match source {
            Source::Node(entry) => blobs.push((descriptor.clone(), named, entry.clone())),
            Source::Index => {}
        }
    }
    if !closure.iter().any(|(d, _)| *d == assembly.root) {
        closure.push((assembly.root.clone(), "root"));
    }
    Ok(Planned {
        root: assembly.root,
        index: assembly.index,
        wrapper: assembly.wrapper,
        blobs,
        closure,
        descriptors: assembly.descriptors,
        content_bytes: assembly.content_bytes,
    })
}

pub(crate) fn retained_chain(
    entry: &Entry,
    root: &Descriptor,
    platform: &str,
    manifest: &Descriptor,
    end: u64,
) -> Result<(Descriptor, Vec<Descriptor>)> {
    manifest.validate()?;
    let chain = crate::images::graph::read_chain(entry, root, platform, end)?;
    require(
        crate::images::analysis::hash(chain.manifest.get()) == manifest.digest,
        Failure::Integrity,
    )?;
    let value = Value::parse_bounded(chain.manifest.get(), 16_777_216, 128)?;
    let config = content::descriptor(value.field("config")?, false)?;
    let mut layers = Vec::new();
    for layer in value.field("layers")?.array()? {
        layers.push(content::descriptor(layer, false)?);
    }
    Ok((config, layers))
}

pub(crate) fn plan_retained(
    root: &Descriptor,
    manifests: &[(String, Descriptor)],
    chains: &[(Descriptor, Vec<Descriptor>)],
) -> Result<Planned> {
    root.validate()?;
    require(content::root_media(&root.media_type), Failure::Policy)?;
    require(
        !manifests.is_empty() && manifests.len() == chains.len() && manifests.len() <= 64,
        Failure::Policy,
    )?;
    let mut unique: BTreeMap<String, (Descriptor, &'static str)> = BTreeMap::new();
    let mut add = |descriptor: &Descriptor, named: &'static str| -> Result<()> {
        descriptor.validate()?;
        match unique.get(&descriptor.digest) {
            Some((known, _)) => require(known == descriptor, Failure::Integrity),
            None => {
                unique.insert(descriptor.digest.clone(), (descriptor.clone(), named));
                Ok(())
            }
        }
    };
    add(root, "root")?;
    for ((_, manifest), (config, layers)) in manifests.iter().zip(chains) {
        add(manifest, "manifest")?;
        add(config, "config")?;
        for layer in layers {
            add(layer, "layer")?;
        }
    }
    let content_bytes = unique
        .values()
        .try_fold(0u64, |total, (descriptor, _)| {
            total.checked_add(descriptor.size)
        })
        .ok_or(Failure::Limit)?;
    Ok(Planned {
        root: root.clone(),
        index: None,
        wrapper: Vec::new(),
        blobs: Vec::new(),
        descriptors: unique.len() as u64,
        content_bytes,
        closure: unique.into_values().collect(),
    })
}

pub(crate) enum Agreement {
    Established,
    Disagreed(PublicationCheck),
}

pub(crate) struct Receipt {
    pub(crate) root: Option<Descriptor>,
    pub(crate) closure_complete: bool,
    pub(crate) verified_descriptors: u64,
    pub(crate) verified_bytes: u64,
    pub(crate) completion_uncertain: bool,
    pub(crate) cleanup_uncertain: bool,
    pub(crate) tag: Option<String>,
    pub(crate) tag_observed: bool,
}

pub(crate) fn agreement(receipt: &Receipt, planned: &Planned) -> Agreement {
    let root = match &receipt.root {
        Some(root) if *root == planned.root => root,
        _ => return Agreement::Disagreed(PublicationCheck::Association),
    };
    let _ = root;
    if receipt.completion_uncertain || receipt.cleanup_uncertain || !receipt.closure_complete {
        return Agreement::Disagreed(PublicationCheck::Closure);
    }
    if receipt.verified_descriptors != planned.descriptors
        || receipt.verified_bytes != planned.content_bytes
    {
        return Agreement::Disagreed(PublicationCheck::Closure);
    }
    if receipt.tag.is_some() && !receipt.tag_observed {
        return Agreement::Disagreed(PublicationCheck::Association);
    }
    Agreement::Established
}

pub(crate) fn server(
    endpoint: &str,
    development_http: bool,
    pinned_ca: bool,
    auth: &'static str,
) -> ServerIdentity {
    let authority = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    ServerIdentity {
        authority: authority.trim_end_matches('/').to_owned(),
        transport: if development_http {
            "development-http"
        } else if pinned_ca {
            "tls-pinned-ca"
        } else {
            "tls-system-ca"
        },
        authentication: auth,
    }
}

pub(crate) struct Binding {
    pub(crate) endpoint: String,
    pub(crate) server: ServerIdentity,
    pub(crate) repository: String,
    pub(crate) operation_id: String,
    pub(crate) artifact_id: Option<String>,
}

pub(crate) fn observation(
    binding: &Binding,
    planned: &Planned,
    receipt: &Receipt,
    local: &'static str,
    observed_ns: u64,
    observed_at: String,
) -> PublicationObservation {
    PublicationObservation {
        artifact_id: binding.artifact_id.clone(),
        root: planned.root.clone(),
        endpoint: binding.endpoint.clone(),
        server: binding.server.clone(),
        repository: binding.repository.clone(),
        association: receipt.root.clone().unwrap_or_else(|| planned.root.clone()),
        closure: planned.members(local),
        tag: receipt
            .tag
            .as_ref()
            .filter(|_| receipt.tag_observed)
            .map(|tag| TagAssociation {
                tag: tag.clone(),
                root: planned.root.clone(),
            }),
        observed_ns,
        observed_at,
        method: "digest-checked-readback",
        operation_id: binding.operation_id.clone(),
        auxiliary: Vec::new(),
        predicate: "artifact-id-deferred",
    }
}

pub(crate) fn unproved(
    binding: &Binding,
    planned: &Planned,
    class: PublicationClass,
    check: Option<PublicationCheck>,
    tag: Option<String>,
    completion_uncertain: bool,
    cleanup_uncertain: bool,
) -> Unproved {
    Unproved {
        class,
        check,
        endpoint: binding.endpoint.clone(),
        server: binding.server.clone(),
        repository: binding.repository.clone(),
        expected_root: planned.root.clone(),
        tag,
        completion_uncertain,
        cleanup_uncertain,
        recovery: "read-only-observation",
        local_content: "none",
    }
}

fn check_of(failure: Failure, dispatched: bool) -> PublicationCheck {
    match failure {
        Failure::Integrity => PublicationCheck::Closure,
        Failure::Policy | Failure::Credential | Failure::Authentication | Failure::Trust => {
            PublicationCheck::Request
        }
        _ if dispatched => PublicationCheck::Transfer,
        _ => PublicationCheck::Request,
    }
}

pub(crate) fn resolve(
    binding: &Binding,
    planned: &Planned,
    result: std::result::Result<&RegistryOutcome, &StageError>,
    tag: Option<String>,
    standalone: bool,
    dispatched: bool,
) -> PublicationOutcome {
    let local = if standalone {
        "inspect-prepared"
    } else {
        "verify-staged"
    };
    match result {
        Ok(outcome) => {
            let receipt = Receipt {
                root: outcome.root.clone(),
                closure_complete: outcome.closure_complete,
                verified_descriptors: outcome.verified.0,
                verified_bytes: outcome.verified.1,
                completion_uncertain: outcome.observation.completion_uncertain,
                cleanup_uncertain: outcome.observation.cleanup_uncertain,
                tag_observed: outcome
                    .root
                    .as_ref()
                    .is_some_and(|root| *root == planned.root),
                tag,
            };
            match agreement(&receipt, planned) {
                Agreement::Established => PublicationOutcome::Published(Box::new(observation(
                    binding,
                    planned,
                    &receipt,
                    local,
                    monotonic_ns(),
                    crate::images::records::now_utc(),
                ))),
                Agreement::Disagreed(check) => PublicationOutcome::Failed {
                    class: PublicationClass::Publication,
                    check: Some(check),
                },
            }
        }
        Err(error) => {
            let class = PublicationClass::of(error.failure);
            let unproved_outcome = || {
                PublicationOutcome::Unknown(Box::new(unproved(
                    binding,
                    planned,
                    class,
                    Some(PublicationCheck::Transfer),
                    tag.clone(),
                    error.observation.completion_uncertain,
                    error.observation.cleanup_uncertain,
                )))
            };
            match error.failure {
                Failure::Cancellation if !dispatched => PublicationOutcome::Cancelled,
                Failure::Cancellation
                | Failure::Timeout
                | Failure::Indeterminate
                | Failure::Protocol
                    if dispatched =>
                {
                    unproved_outcome()
                }
                Failure::Cancellation => PublicationOutcome::Cancelled,
                failure => PublicationOutcome::Failed {
                    class,
                    check: Some(check_of(failure, dispatched)),
                },
            }
        }
    }
}
