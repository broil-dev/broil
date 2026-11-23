// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::upstream::{self, Descriptor, hex};
use super::{Failure, Result, require};
use crate::images::infrastructure_io::json::Value as Private;
use crate::k3s::state::canonical;
use serde_json::Value;
use std::sync::OnceLock;

const INDEX_BYTES: &[u8] = include_bytes!("../../../../../tools/k3s/bootstrap-index.lock.json");
const POLICY_BYTES: &[u8] =
    include_bytes!("../../../../../tools/k3s/airgap-descriptor-policy.lock.json");
pub(crate) const POLICY_INPUT: &str = "airgap-descriptor-policy.lock.json";
pub(crate) const PLATFORM: &str = "linux/amd64";
pub(crate) const SYNCTHING: &str = "syncthing";

pub(crate) const ASSET_LIMIT: usize = 32;
pub(crate) const ENCODED_ASSET_LIMIT: u64 = 268_435_456;
pub(crate) const ENCODED_SUM_LIMIT: u64 = 2_147_483_648;
pub(crate) const EXPANDED_SUM_LIMIT: u64 = 4_294_967_296;
pub(crate) const OUTER_ENTRY_LIMIT: u64 = 65_536;
const DOCUMENT_LIMIT: usize = 65_536;
const ROOT_LIMIT: usize = 64;
const EDGE_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum When {
    Always,
    Registry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Raw,
    Tar,
    TarGzip,
}

#[derive(Clone, Debug)]
pub(crate) struct Asset {
    pub id: String,
    pub filename: String,
    pub when: When,
    pub size: u64,
    pub sha256: String,
    pub origin: String,
    pub format: Format,
    pub expanded_bytes: u64,
    pub members: u64,
    pub content_sha256: String,
}

pub(crate) struct Index {
    pub sha256: String,
    pub version: String,
    pub inputs: Vec<(String, String)>,
    pub assets: Vec<Asset>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    OtherPlatform,
    Attestation,
}

#[derive(Clone, Debug)]
pub(crate) struct Edge {
    pub parent: String,
    pub ordinal: u64,
    pub descriptor: Value,
    pub reason: Option<Reason>,
}

pub(crate) struct Policy {
    pub asset: String,
    pub roots: Vec<Value>,
    pub runtime: Vec<Edge>,
    pub metadata: Vec<Edge>,
}

pub(crate) struct Embedded {
    pub index: Index,
    pub policy: Policy,
}

pub(crate) fn embedded() -> Result<&'static Embedded> {
    static EMBEDDED: OnceLock<Result<Embedded>> = OnceLock::new();
    match EMBEDDED.get_or_init(|| {
        let index = index(INDEX_BYTES)?;
        let policy = policy(POLICY_BYTES, &index)?;
        Ok(Embedded { index, policy })
    }) {
        Ok(value) => Ok(value),
        Err(failure) => Err(*failure),
    }
}

fn canonical_document(bytes: &'static [u8]) -> Result<(&'static [u8], Value)> {
    let body = bytes.strip_suffix(b"\n").ok_or(Failure::Integrity)?;
    require(body.len() <= DOCUMENT_LIMIT, Failure::Bound)?;
    Private::parse_bounded(body, DOCUMENT_LIMIT, 16)?;
    let value: Value = serde_json::from_slice(body).map_err(|_| Failure::Integrity)?;
    require(canonical(&value)? == body, Failure::Integrity)?;
    Ok((body, value))
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a serde_json::Map<String, Value>> {
    let members = value.as_object().ok_or(Failure::Integrity)?;
    require(
        members.len() == fields.len() && fields.iter().all(|f| members.contains_key(*f)),
        Failure::Integrity,
    )?;
    Ok(members)
}

fn text(value: &Value, limit: usize) -> Result<&str> {
    let text = value.as_str().ok_or(Failure::Integrity)?;
    require(!text.is_empty() && text.len() <= limit, Failure::Bound)?;
    Ok(text)
}

fn hash(value: &Value) -> Result<String> {
    let text = text(value, 64)?;
    require(hex(text, 64), Failure::Integrity)?;
    Ok(text.into())
}

fn identifier(value: &Value) -> Result<String> {
    let text = text(value, 64)?;
    let bytes = text.as_bytes();
    require(
        bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit(),
        Failure::Integrity,
    )?;
    require(
        bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-'),
        Failure::Integrity,
    )?;
    Ok(text.into())
}

pub(crate) fn filename(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !text.starts_with('.')
        && !matches!(text, "binding.json" | "complete.json")
}

pub(crate) fn origin(text: &str) -> bool {
    text.len() <= 1024
        && !text.is_empty()
        && text
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'?' && b != b'#')
        && match text.strip_prefix("https://") {
            Some(rest) => {
                let authority = rest.split('/').next().unwrap_or("");
                !authority.is_empty() && !authority.contains('@')
            }
            None => !text.contains("://"),
        }
}

fn input_name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 255
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && !text.starts_with('/')
        && !text.ends_with('/')
        && text
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn index(bytes: &'static [u8]) -> Result<Index> {
    let (body, value) = canonical_document(bytes)?;
    let members = object(
        &value,
        &["schema", "platform", "version", "inputs", "assets"],
    )?;
    require(
        members["schema"] == 1 && members["platform"] == PLATFORM,
        Failure::Integrity,
    )?;
    let version = text(&members["version"], 64)?.to_string();
    let mut inputs = Vec::new();
    let mut previous: Option<&str> = None;
    for input in members["inputs"].as_array().ok_or(Failure::Integrity)? {
        let fields = object(input, &["name", "sha256"])?;
        let name = text(&fields["name"], 255)?;
        require(input_name(name), Failure::Integrity)?;
        require(previous.is_none_or(|p| p < name), Failure::Integrity)?;
        previous = Some(name);
        inputs.push((name.to_string(), hash(&fields["sha256"])?));
    }
    require(!inputs.is_empty() && inputs.len() <= 128, Failure::Bound)?;
    let mut assets = Vec::new();
    let mut encoded = 0u64;
    let mut expanded = 0u64;
    for asset in members["assets"].as_array().ok_or(Failure::Integrity)? {
        let fields = object(
            asset,
            &[
                "id",
                "filename",
                "when",
                "size",
                "sha256",
                "origin",
                "format",
                "expanded_bytes",
                "members",
                "content_sha256",
            ],
        )?;
        let id = identifier(&fields["id"])?;
        let name = text(&fields["filename"], 128)?;
        require(filename(name), Failure::Integrity)?;
        let when = match fields["when"].as_str() {
            Some("always") => When::Always,
            Some("registry") => When::Registry,
            _ => return Err(Failure::Integrity),
        };
        let format = match fields["format"].as_str() {
            Some("raw") => Format::Raw,
            Some("tar") => Format::Tar,
            Some("tar-gzip") => Format::TarGzip,
            _ => return Err(Failure::Integrity),
        };
        let size = fields["size"].as_u64().ok_or(Failure::Integrity)?;
        require((1..=ENCODED_ASSET_LIMIT).contains(&size), Failure::Bound)?;
        let origin_text = text(&fields["origin"], 1024)?;
        require(origin(origin_text), Failure::Integrity)?;
        let expanded_bytes = fields["expanded_bytes"]
            .as_u64()
            .ok_or(Failure::Integrity)?;
        let count = fields["members"].as_u64().ok_or(Failure::Integrity)?;
        match format {
            Format::Raw => require(expanded_bytes == 0 && count == 0, Failure::Integrity)?,
            Format::Tar => require(
                expanded_bytes == size && (1..=OUTER_ENTRY_LIMIT).contains(&count),
                Failure::Integrity,
            )?,
            Format::TarGzip => require(
                (1..=EXPANDED_SUM_LIMIT).contains(&expanded_bytes)
                    && (1..=OUTER_ENTRY_LIMIT).contains(&count),
                Failure::Integrity,
            )?,
        }
        require(
            assets
                .iter()
                .all(|a: &Asset| a.id != id && a.filename != name),
            Failure::Integrity,
        )?;
        encoded = encoded.checked_add(size).ok_or(Failure::Bound)?;
        expanded = expanded.checked_add(expanded_bytes).ok_or(Failure::Bound)?;
        assets.push(Asset {
            id,
            filename: name.to_string(),
            when,
            size,
            sha256: hash(&fields["sha256"])?,
            origin: origin_text.to_string(),
            format,
            expanded_bytes,
            members: count,
            content_sha256: hash(&fields["content_sha256"])?,
        });
    }
    require(
        !assets.is_empty()
            && assets.len() <= ASSET_LIMIT
            && encoded <= ENCODED_SUM_LIMIT
            && expanded <= EXPANDED_SUM_LIMIT,
        Failure::Bound,
    )?;
    Ok(Index {
        sha256: crate::k3s::protocol::digest(body),
        version,
        inputs,
        assets,
    })
}

fn edge(value: &Value, reason: bool) -> Result<(Edge, Descriptor<'_>)> {
    let fields = if reason {
        object(value, &["parent", "ordinal", "descriptor", "reason"])?
    } else {
        object(value, &["parent", "ordinal", "descriptor"])?
    };
    let parent = fields["parent"]
        .as_str()
        .and_then(|p| p.strip_prefix("sha256:"))
        .filter(|p| hex(p, 64))
        .ok_or(Failure::Integrity)?;
    let ordinal = fields["ordinal"].as_u64().ok_or(Failure::Integrity)?;
    require(ordinal < EDGE_LIMIT as u64, Failure::Bound)?;
    let descriptor = upstream::descriptor(&fields["descriptor"])?;
    let reason = match fields.get("reason").and_then(Value::as_str) {
        None if !reason => None,
        Some("other-platform") => Some(Reason::OtherPlatform),
        Some("attestation") => Some(Reason::Attestation),
        _ => return Err(Failure::Integrity),
    };
    Ok((
        Edge {
            parent: format!("sha256:{parent}"),
            ordinal,
            descriptor: fields["descriptor"].clone(),
            reason,
        },
        descriptor,
    ))
}

fn policy(bytes: &'static [u8], index: &Index) -> Result<Policy> {
    let (_, value) = canonical_document(bytes)?;
    let sha256 = crate::k3s::protocol::digest(bytes);
    require(
        index
            .inputs
            .iter()
            .any(|(name, hash)| name == POLICY_INPUT && *hash == sha256),
        Failure::Integrity,
    )?;
    let members = object(
        &value,
        &[
            "schema",
            "kind",
            "platform",
            "asset",
            "size",
            "sha256",
            "roots",
            "runtime_manifests",
            "metadata_only",
        ],
    )?;
    require(
        members["schema"] == 1
            && members["kind"] == "k3s-airgap-descriptor-policy"
            && members["platform"] == PLATFORM,
        Failure::Integrity,
    )?;
    let asset = identifier(&members["asset"])?;
    let size = members["size"].as_u64().ok_or(Failure::Integrity)?;
    let archive_sha256 = hash(&members["sha256"])?;
    let pinned = index
        .assets
        .iter()
        .find(|a| a.id == asset)
        .ok_or(Failure::Integrity)?;
    require(
        pinned.format == Format::TarGzip && pinned.size == size && pinned.sha256 == archive_sha256,
        Failure::Integrity,
    )?;
    let roots = members["roots"].as_array().ok_or(Failure::Integrity)?;
    require(
        !roots.is_empty() && roots.len() <= ROOT_LIMIT,
        Failure::Bound,
    )?;
    let mut root_digests = Vec::new();
    for root in roots {
        let descriptor = upstream::descriptor(root)?;
        require(
            upstream::ROOT_TYPES.contains(&descriptor.media_type)
                && !root_digests.contains(&descriptor.digest),
            Failure::Integrity,
        )?;
        root_digests.push(descriptor.digest);
    }
    let runtime_values = members["runtime_manifests"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    require(runtime_values.len() == roots.len(), Failure::Integrity)?;
    let mut runtime = Vec::new();
    for (position, value) in runtime_values.iter().enumerate() {
        let (edge, descriptor) = edge(value, false)?;
        require(
            edge.parent == format!("sha256:{}", root_digests[position])
                && upstream::MANIFEST_TYPES.contains(&descriptor.media_type)
                && descriptor.platform.is_some_and(upstream::admitted_tuple),
            Failure::Integrity,
        )?;
        runtime.push(edge);
    }
    let metadata_values = members["metadata_only"]
        .as_array()
        .ok_or(Failure::Integrity)?;
    require(metadata_values.len() <= EDGE_LIMIT, Failure::Bound)?;
    let mut metadata: Vec<Edge> = Vec::new();
    let mut previous: Option<(usize, u64)> = None;
    for value in metadata_values {
        let (edge, descriptor) = edge(value, true)?;
        let position = root_digests
            .iter()
            .position(|d| format!("sha256:{d}") == edge.parent)
            .ok_or(Failure::Integrity)?;
        let key = (position, edge.ordinal);
        require(
            previous.is_none_or(|p| p < key) && runtime[position].ordinal != edge.ordinal,
            Failure::Integrity,
        )?;
        previous = Some(key);
        let platform = descriptor.platform.ok_or(Failure::Integrity)?;
        match edge.reason {
            Some(Reason::OtherPlatform) => require(
                upstream::platform_pair(platform).is_some_and(|pair| pair != ("linux", "amd64")),
                Failure::Integrity,
            )?,
            Some(Reason::Attestation) => {
                let annotations = descriptor.annotations.ok_or(Failure::Integrity)?;
                let reference = annotations["vnd.docker.reference.digest"]
                    .as_str()
                    .ok_or(Failure::Integrity)?;
                let sibling = runtime[position].descriptor["digest"] == reference
                    || metadata.iter().any(|m| {
                        m.parent == edge.parent
                            && m.reason == Some(Reason::OtherPlatform)
                            && m.descriptor["digest"] == reference
                    });
                require(
                    platform.as_object().is_some_and(|p| p.len() == 2)
                        && upstream::platform_pair(platform) == Some(("unknown", "unknown"))
                        && annotations["vnd.docker.reference.type"] == "attestation-manifest"
                        && sibling,
                    Failure::Integrity,
                )?;
            }
            None => return Err(Failure::Integrity),
        }
        metadata.push(edge);
    }
    Ok(Policy {
        asset,
        roots: roots.clone(),
        runtime,
        metadata,
    })
}

impl Index {
    pub(crate) fn selected(&self, registry: bool) -> Vec<&Asset> {
        self.assets
            .iter()
            .filter(|a| a.when == When::Always || registry)
            .collect()
    }

    pub(crate) fn asset(&self, id: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.id == id)
    }
}

pub(crate) fn totals(assets: &[&Asset]) -> Result<(u64, u64, u64)> {
    let mut totals = (0u64, 0u64, 0u64);
    for asset in assets {
        totals.0 = totals.0.checked_add(asset.size).ok_or(Failure::Bound)?;
        totals.1 = totals
            .1
            .checked_add(asset.expanded_bytes)
            .ok_or(Failure::Bound)?;
        totals.2 = totals.2.checked_add(asset.members).ok_or(Failure::Bound)?;
    }
    require(
        totals.0 <= ENCODED_SUM_LIMIT
            && totals.1 <= EXPANDED_SUM_LIMIT
            && totals.2 <= OUTER_ENTRY_LIMIT,
        Failure::Bound,
    )?;
    Ok(totals)
}

