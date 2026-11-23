// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::index::{Asset, Format, Policy, Reason, SYNCTHING};
use super::upstream::{self, Descriptor};
use super::{Failure, Result, require};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const BLOCK: usize = 512;
const NAME_LIMIT: usize = 4096;
const RETAINED_LIMIT: usize = 16_777_216;
const SMALL: u64 = 262_144;
pub(crate) const CONTENT_DOMAIN: &str = "broil-k3s-bootstrap-content-v1";

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Header,
    Data,
    Padding,
    Trailer,
}

struct Current {
    name: String,
    size: u64,
    retain: Option<Vec<u8>>,
}

pub(super) struct Walker<'a> {
    asset: &'a Asset,
    state: State,
    header: Vec<u8>,
    remaining: u64,
    padding: usize,
    hasher: Sha256,
    current: Option<Current>,
    inventory: Vec<Value>,
    names: BTreeSet<String>,
    retained: BTreeMap<String, Vec<u8>>,
    retained_bytes: usize,
    consumed: u64,
    trailer: u64,
}

pub(super) struct Walked {
    pub files: BTreeMap<String, (u64, String)>,
    pub retained: BTreeMap<String, Vec<u8>>,
}

fn octal(field: &[u8]) -> Result<u64> {
    require(field.first().is_some_and(|b| b & 0x80 == 0), Failure::Bound)?;
    let mut value = 0u64;
    let mut digits = 0;
    for &byte in field {
        match byte {
            b'0'..=b'7' => {
                value = value
                    .checked_mul(8)
                    .and_then(|v| v.checked_add(u64::from(byte - b'0')))
                    .ok_or(Failure::Bound)?;
                digits += 1;
            }
            b' ' if digits == 0 => {}
            0 | b' ' => break,
            _ => return Err(Failure::Integrity),
        }
    }
    require(digits > 0, Failure::Integrity)?;
    Ok(value)
}

fn text(field: &[u8]) -> Result<&str> {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    std::str::from_utf8(&field[..end]).map_err(|_| Failure::Integrity)
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_LIMIT
        && !name.starts_with('/')
        && name.bytes().all(|b| b >= 0x20 && b != 0x7f)
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

impl<'a> Walker<'a> {
    pub(super) fn new(asset: &'a Asset) -> Result<Self> {
        require(asset.format != Format::Raw, Failure::Configuration)?;
        let mut header = Vec::new();
        header
            .try_reserve_exact(BLOCK)
            .map_err(|_| Failure::Bound)?;
        Ok(Self {
            asset,
            state: State::Header,
            header,
            remaining: 0,
            padding: 0,
            hasher: Sha256::new(),
            current: None,
            inventory: Vec::new(),
            names: BTreeSet::new(),
            retained: BTreeMap::new(),
            retained_bytes: 0,
            consumed: 0,
            trailer: 0,
        })
    }

    fn account(&mut self, count: usize) -> Result<()> {
        self.consumed = self
            .consumed
            .checked_add(count as u64)
            .ok_or(Failure::Bound)?;
        require(self.consumed <= self.asset.expanded_bytes, Failure::Bound)?;
        Ok(())
    }

    fn entry(&mut self) -> Result<()> {
        let header = std::mem::take(&mut self.header);
        let mut sum = 0u32;
        for (index, byte) in header.iter().enumerate() {
            sum += u32::from(if (148..156).contains(&index) {
                b' '
            } else {
                *byte
            });
        }
        require(
            octal(&header[148..156])? == u64::from(sum),
            Failure::Integrity,
        )?;
        let mut name = text(&header[..100])?.to_string();
        if &header[257..263] == b"ustar\0" {
            let prefix = text(&header[345..500])?;
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let size = octal(&header[124..136])?;
        require(size <= upstream::SIZE_CEILING, Failure::Bound)?;
        let directory = match header[156] {
            b'0' | 0 => false,
            b'5' => true,
            _ => return Err(Failure::Integrity),
        };
        if directory {
            require(size == 0, Failure::Integrity)?;
            while name.ends_with('/') {
                name.pop();
            }
        } else {
            require(!name.ends_with('/'), Failure::Integrity)?;
        }
        require(
            safe_name(&name)
                && self.names.insert(name.clone())
                && (self.inventory.len() as u64) < self.asset.members,
            Failure::Integrity,
        )?;
        self.header = header;
        self.header.clear();
        if directory {
            self.inventory
                .push(json!({"name":name,"type":"directory","size":0,"sha256":null}));
            self.state = State::Header;
            return Ok(());
        }
        let retain = (size <= SMALL
            && (matches!(name.as_str(), "index.json" | "oci-layout" | "manifest.json")
                || name.starts_with("blobs/sha256/")))
        .then(|| {
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(size as usize).map(|()| buffer)
        })
        .transpose()
        .map_err(|_| Failure::Bound)?;
        self.hasher = Sha256::new();
        self.remaining = size;
        self.padding = (BLOCK - (size % BLOCK as u64) as usize) % BLOCK;
        self.current = Some(Current { name, size, retain });
        self.state = if size > 0 {
            State::Data
        } else {
            self.complete()?;
            State::Header
        };
        Ok(())
    }

    fn complete(&mut self) -> Result<()> {
        let current = self.current.take().ok_or(Failure::Integrity)?;
        let digest: String = std::mem::take(&mut self.hasher)
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if let Some(bytes) = current.retain {
            self.retained_bytes = self
                .retained_bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= RETAINED_LIMIT)
                .ok_or(Failure::Bound)?;
            self.retained.insert(current.name.clone(), bytes);
        }
        self.inventory
            .push(json!({"name":current.name,"type":"file","size":current.size,"sha256":digest}));
        Ok(())
    }

    pub(super) fn push(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            match self.state {
                State::Header => {
                    let take = bytes.len().min(BLOCK - self.header.len());
                    self.header.extend_from_slice(&bytes[..take]);
                    bytes = &bytes[take..];
                    if self.header.len() == BLOCK {
                        if self.header.iter().all(|b| *b == 0) {
                            self.header.clear();
                            self.trailer = BLOCK as u64;
                            self.state = State::Trailer;
                        } else {
                            self.account(BLOCK)?;
                            self.entry()?;
                        }
                    }
                }
                State::Data => {
                    let take = (bytes.len() as u64).min(self.remaining) as usize;
                    self.hasher.update(&bytes[..take]);
                    if let Some(retain) = self.current.as_mut().and_then(|c| c.retain.as_mut()) {
                        retain.extend_from_slice(&bytes[..take]);
                    }
                    self.account(take)?;
                    self.remaining -= take as u64;
                    bytes = &bytes[take..];
                    if self.remaining == 0 {
                        self.complete()?;
                        self.state = if self.padding > 0 {
                            State::Padding
                        } else {
                            State::Header
                        };
                    }
                }
                State::Padding => {
                    let take = bytes.len().min(self.padding);
                    require(bytes[..take].iter().all(|b| *b == 0), Failure::Integrity)?;
                    self.account(take)?;
                    self.padding -= take;
                    bytes = &bytes[take..];
                    if self.padding == 0 {
                        self.state = State::Header;
                    }
                }
                State::Trailer => {
                    require(bytes.iter().all(|b| *b == 0), Failure::Integrity)?;
                    self.trailer = self
                        .trailer
                        .checked_add(bytes.len() as u64)
                        .ok_or(Failure::Bound)?;
                    require(
                        self.consumed
                            .checked_add(self.trailer)
                            .ok_or(Failure::Bound)?
                            <= self.asset.expanded_bytes,
                        Failure::Bound,
                    )?;
                    bytes = &[];
                }
            }
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Walked> {
        require(
            self.state == State::Trailer
                && self.trailer >= 2 * BLOCK as u64
                && self.trailer.is_multiple_of(BLOCK as u64)
                && self.consumed.checked_add(self.trailer) == Some(self.asset.expanded_bytes)
                && self.inventory.len() as u64 == self.asset.members,
            Failure::Integrity,
        )?;
        let inventory = Value::Array(self.inventory);
        require(
            crate::k3s::state::hash(CONTENT_DOMAIN, &inventory)? == self.asset.content_sha256,
            Failure::Integrity,
        )?;
        let mut files = BTreeMap::new();
        for entry in inventory.as_array().into_iter().flatten() {
            if entry["type"] == "file" {
                files.insert(
                    entry["name"].as_str().unwrap_or("").to_string(),
                    (
                        entry["size"].as_u64().unwrap_or(0),
                        entry["sha256"].as_str().unwrap_or("").to_string(),
                    ),
                );
            }
        }
        Ok(Walked {
            files,
            retained: self.retained,
        })
    }
}

struct Closure<'a> {
    walked: &'a Walked,
    visited: BTreeSet<String>,
}

impl Closure<'_> {
    fn present(&mut self, descriptor: &Descriptor<'_>, roles: &[&str]) -> Result<String> {
        let name = format!("blobs/sha256/{}", descriptor.digest);
        let (size, sha256) = self.walked.files.get(&name).ok_or(Failure::Integrity)?;
        require(
            *size == descriptor.size
                && sha256 == descriptor.digest
                && roles.contains(&descriptor.media_type),
            Failure::Integrity,
        )?;
        self.visited.insert(name.clone());
        Ok(name)
    }

    fn document(&self, name: &str, descriptor: &Descriptor<'_>) -> Result<Value> {
        let bytes = self.walked.retained.get(name).ok_or(Failure::Bound)?;
        let value = upstream::parse(bytes)?;
        require(
            value
                .get("mediaType")
                .is_none_or(|m| m == descriptor.media_type),
            Failure::Integrity,
        )?;
        Ok(value)
    }

    fn runtime(&mut self, descriptor: &Descriptor<'_>, layers: &[&str]) -> Result<()> {
        let name = self.present(descriptor, &upstream::MANIFEST_TYPES)?;
        let manifest = self.document(&name, descriptor)?;
        require(manifest["schemaVersion"] == 2, Failure::Integrity)?;
        require(
            manifest.get("subject").is_none() && manifest.get("artifactType").is_none(),
            Failure::Integrity,
        )?;
        let config = upstream::descriptor(&manifest["config"])?;
        let config_name = self.present(&config, &upstream::CONFIG_TYPES)?;
        let document = self.document(&config_name, &config)?;
        require(
            document["os"] == "linux"
                && document["architecture"] == "amd64"
                && document.get("variant").is_none(),
            Failure::Integrity,
        )?;
        for layer in manifest["layers"].as_array().ok_or(Failure::Integrity)? {
            self.present(&upstream::descriptor(layer)?, layers)?;
        }
        Ok(())
    }

    fn only_referenced(&self) -> Result<()> {
        require(
            self.walked
                .files
                .keys()
                .filter(|name| name.starts_with("blobs/"))
                .all(|name| self.visited.contains(name)),
            Failure::Integrity,
        )
    }

    fn index(&self) -> Result<Value> {
        let bytes = self
            .walked
            .retained
            .get("index.json")
            .ok_or(Failure::Integrity)?;
        let index = upstream::parse(bytes)?;
        require(index["schemaVersion"] == 2, Failure::Integrity)?;
        Ok(index)
    }
}

pub(super) fn generic_closure(walked: &Walked) -> Result<()> {
    let mut closure = Closure {
        walked,
        visited: BTreeSet::new(),
    };
    let index = closure.index()?;
    let roots = index["manifests"].as_array().ok_or(Failure::Integrity)?;
    require(!roots.is_empty(), Failure::Integrity)?;
    for root in roots {
        let descriptor = upstream::descriptor(root)?;
        closure.runtime(&descriptor, &upstream::GENERIC_LAYER_TYPES)?;
    }
    closure.only_referenced()
}

pub(super) fn official_closure(walked: &Walked, policy: &Policy) -> Result<()> {
    let mut closure = Closure {
        walked,
        visited: BTreeSet::new(),
    };
    require(
        walked.files.contains_key("manifest.json") && walked.files.contains_key("oci-layout"),
        Failure::Integrity,
    )?;
    let index = closure.index()?;
    let roots = index["manifests"].as_array().ok_or(Failure::Integrity)?;
    require(*roots == policy.roots, Failure::Integrity)?;
    for (position, root) in roots.iter().enumerate() {
        let root_descriptor = upstream::descriptor(root)?;
        let name = closure.present(&root_descriptor, &upstream::ROOT_TYPES)?;
        let document = closure.document(&name, &root_descriptor)?;
        require(document["schemaVersion"] == 2, Failure::Integrity)?;
        let entries = document["manifests"].as_array().ok_or(Failure::Integrity)?;
        let admitted: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.get("platform")
                    .and_then(upstream::platform_pair)
                    .is_some_and(|pair| pair == ("linux", "amd64"))
            })
            .map(|(i, _)| i)
            .collect();
        require(admitted.len() == 1, Failure::Integrity)?;
        let runtime = &policy.runtime[position];
        let parent = format!("sha256:{}", root_descriptor.digest);
        require(
            runtime.parent == parent
                && runtime.ordinal == admitted[0] as u64
                && entries[admitted[0]] == runtime.descriptor,
            Failure::Integrity,
        )?;
        let mut edges = policy.metadata.iter().filter(|e| e.parent == parent);
        for (ordinal, entry) in entries.iter().enumerate() {
            let descriptor = upstream::descriptor(entry)?;
            if ordinal == admitted[0] {
                require(
                    descriptor.platform.is_some_and(upstream::admitted_tuple),
                    Failure::Integrity,
                )?;
                closure.runtime(&descriptor, &upstream::LAYER_TYPES)?;
                continue;
            }
            let edge = edges.next().ok_or(Failure::Integrity)?;
            require(
                edge.ordinal == ordinal as u64
                    && edge.descriptor == *entry
                    && !walked
                        .files
                        .contains_key(&format!("blobs/sha256/{}", descriptor.digest)),
                Failure::Integrity,
            )?;
            let platform = descriptor.platform.ok_or(Failure::Integrity)?;
            match edge.reason {
                Some(Reason::OtherPlatform) => require(
                    upstream::platform_pair(platform)
                        .is_some_and(|pair| pair != ("linux", "amd64")),
                    Failure::Integrity,
                )?,
                Some(Reason::Attestation) => {
                    let annotations = descriptor.annotations.ok_or(Failure::Integrity)?;
                    let reference = annotations["vnd.docker.reference.digest"]
                        .as_str()
                        .ok_or(Failure::Integrity)?;
                    let referenced = entries.iter().enumerate().any(|(i, e)| {
                        e["digest"] == reference
                            && (i == admitted[0]
                                || policy.metadata.iter().any(|m| {
                                    m.parent == parent
                                        && m.ordinal == i as u64
                                        && m.reason == Some(Reason::OtherPlatform)
                                }))
                    });
                    require(
                        upstream::platform_pair(platform) == Some(("unknown", "unknown"))
                            && annotations["vnd.docker.reference.type"] == "attestation-manifest"
                            && referenced,
                        Failure::Integrity,
                    )?;
                }
                None => return Err(Failure::Integrity),
            }
        }
        require(edges.next().is_none(), Failure::Integrity)?;
    }
    closure.only_referenced()
}

pub(super) fn verify(walked: &Walked, asset: &Asset, policy: Option<&Policy>) -> Result<()> {
    match policy {
        Some(policy) if policy.asset == asset.id => official_closure(walked, policy),
        _ if asset.id == SYNCTHING => Ok(()),
        _ => generic_closure(walked),
    }
}

