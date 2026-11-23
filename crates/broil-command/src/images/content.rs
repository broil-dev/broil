// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Independent encoded OCI closure verification; no network, extraction or raw output.

use super::{buffer::Bytes, common::*, files, json::Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::File};
use zeroize::Zeroize;

pub(crate) const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_CONFIG: &str = "application/vnd.oci.image.config.v1+json";
const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";
const CACHE_CONFIG: &str = "application/vnd.buildkit.cacheconfig.v0";
const LAYERS: &[&str] = &[
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];

pub(crate) fn root_media(media: &str) -> bool {
    matches!(
        media,
        OCI_INDEX | OCI_MANIFEST | DOCKER_INDEX | DOCKER_MANIFEST
    )
}

fn one_of(value: Value<'_>, options: &[&str]) -> Result<String> {
    for option in options {
        if value.equals(option)? {
            return Ok((*option).into());
        }
    }
    Err(Failure::Integrity)
}

pub(crate) fn digest_text(value: Value<'_>) -> Result<String> {
    let value = value.text()?;
    let bytes = value.get();
    require(
        bytes.len() == 71 && bytes.starts_with(b"sha256:") && hex(&bytes[7..]),
        Failure::Integrity,
    )?;
    // Only a syntactically validated content identity crosses into public storage.
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| Failure::Protocol)?
        .into())
}

pub(crate) fn descriptor(value: Value<'_>, wire: bool) -> Result<Descriptor> {
    let media_name = if wire { "media_type" } else { "mediaType" };
    for (key, item) in value.members()? {
        let key = key.text()?;
        match key.get() {
            b"digest" | b"size" => {}
            key if key == media_name.as_bytes() => {}
            b"platform" if !wire => {
                platform(item)?;
            }
            b"annotations" if !wire => {
                annotations(item)?;
            }
            _ => return Err(Failure::Protocol),
        }
    }
    let mut known = vec![
        OCI_INDEX,
        OCI_MANIFEST,
        DOCKER_INDEX,
        DOCKER_MANIFEST,
        OCI_CONFIG,
        DOCKER_CONFIG,
        CACHE_CONFIG,
    ];
    known.extend_from_slice(LAYERS);
    let result = Descriptor {
        digest: digest_text(value.field("digest")?)?,
        size: value.field("size")?.number()?,
        media_type: one_of(value.field(media_name)?, &known)?,
    };
    result.validate()?;
    Ok(result)
}

fn annotations(value: Value<'_>) -> Result<()> {
    for (key, value) in value.members()? {
        key.text()?;
        value.text()?;
    }
    Ok(())
}

struct Platform {
    os: Bytes,
    arch: Bytes,
    variant: Option<Bytes>,
    version: Option<Bytes>,
    features: Vec<Bytes>,
}

fn platform(value: Value<'_>) -> Result<Platform> {
    let os = value.field("os")?.text()?;
    let arch = value.field("architecture")?.text()?;
    require(
        !os.get().is_empty()
            && !arch.get().is_empty()
            && !os.get().iter().chain(arch.get()).any(u8::is_ascii_control),
        Failure::Integrity,
    )?;
    let mut result = Platform {
        os,
        arch,
        variant: None,
        version: None,
        features: Vec::new(),
    };
    for (key, item) in value.members()? {
        let key = key.text()?;
        match key.get() {
            b"os" | b"architecture" => {}
            b"variant" => result.variant = Some(item.text()?),
            b"os.version" => result.version = Some(item.text()?),
            b"os.features" => {
                for feature in item.array()? {
                    result.features.push(feature.text()?);
                }
            }
            _ => {}
        }
    }
    Ok(result)
}

fn platform_matches(actual: &Platform, expected: &Platform) -> Result<()> {
    require(
        actual.os.get() == expected.os.get() && actual.arch.get() == expected.arch.get(),
        Failure::Integrity,
    )?;
    for (have, want) in [
        (&actual.variant, &expected.variant),
        (&actual.version, &expected.version),
    ] {
        if let Some(want) = want.as_ref().filter(|v| !v.get().is_empty()) {
            require(
                have.as_ref().is_some_and(|v| v.get() == want.get()),
                Failure::Integrity,
            )?;
        }
    }
    for want in &expected.features {
        require(
            actual.features.iter().any(|v| v.get() == want.get()),
            Failure::Integrity,
        )?;
    }
    Ok(())
}

pub(crate) fn verified_metadata(
    file: &File,
    expected: &Descriptor,
    limits: &ContentLimits,
    end: u64,
) -> Result<Bytes> {
    let bytes = files::metadata(file, limits.metadata_bytes, end)?;
    require(
        bytes.get().len() as u64 == expected.size,
        Failure::Integrity,
    )?;
    let mut output = Sha256::digest(bytes.get());
    let same = output.iter().enumerate().all(|(i, b)| {
        const DIGITS: &[u8] = b"0123456789abcdef";
        expected.digest.as_bytes()[7 + i * 2] == DIGITS[(b >> 4) as usize]
            && expected.digest.as_bytes()[8 + i * 2] == DIGITS[(b & 15) as usize]
    });
    output.as_mut_slice().zeroize();
    require(same, Failure::Integrity)?;
    before(end)?;
    Ok(bytes)
}

struct Node {
    descriptor: Descriptor,
    done: bool,
    platforms: Vec<String>,
    platform: Option<Platform>,
    layers: usize,
}

struct Graph<'a> {
    directory: &'a Entry,
    blobs: File,
    limits: &'a ContentLimits,
    end: u64,
    cache: bool,
    complete: bool,
    nodes: BTreeMap<String, Node>,
    edges: u64,
    content: u64,
    verified_bytes: u64,
    verified_files: u64,
}

impl Graph<'_> {
    fn parse<'a>(&self, bytes: &'a Bytes) -> Result<Value<'a>> {
        before(self.end)?;
        Value::parse_bounded(
            bytes.get(),
            self.limits.metadata_bytes as usize,
            self.limits.content_json_depth as usize,
        )
    }

    fn visit(
        &mut self,
        d: Descriptor,
        depth: u64,
        expected: Option<Platform>,
    ) -> Result<Vec<String>> {
        before(self.end)?;
        require(depth <= self.limits.graph_depth, Failure::Limit)?;
        self.edges = self.edges.checked_add(1).ok_or(Failure::Limit)?;
        require(self.edges <= self.limits.descriptor_edges, Failure::Limit)?;
        if let Some(node) = self.nodes.get(&d.digest) {
            require(node.descriptor == d && node.done, Failure::Integrity)?;
            self.check_platforms(&node.platforms, expected.as_ref())?;
            return Ok(node.platforms.clone());
        }
        require(
            (self.nodes.len() as u64) < self.limits.descriptors,
            Failure::Limit,
        )?;
        self.content = self.content.checked_add(d.size).ok_or(Failure::Limit)?;
        require(self.content <= self.limits.content_bytes, Failure::Limit)?;
        let layer = LAYERS.contains(&d.media_type.as_str());
        require(
            d.size
                <= if layer {
                    self.limits.blob_bytes
                } else {
                    self.limits.metadata_bytes
                },
            Failure::Limit,
        )?;
        self.nodes.insert(
            d.digest.clone(),
            Node {
                descriptor: d.clone(),
                done: false,
                platforms: Vec::new(),
                platform: None,
                layers: 0,
            },
        );
        let mut platforms = Vec::new();
        if !layer || self.complete {
            let path = self
                .directory
                .path
                .join("blobs/sha256")
                .join(&d.digest[7..]);
            let (file, entry) = files::child(&self.blobs, &path, self.directory.ownership)?;
            require(entry.kind == Kind::File, Failure::Integrity)?;
            if layer {
                files::verify_file(&file, &d.digest, d.size, self.limits.blob_bytes, self.end)?;
            } else {
                let bytes = verified_metadata(&file, &d, self.limits, self.end)?;
                let value = self.parse(&bytes)?;
                match d.media_type.as_str() {
                    OCI_CONFIG | DOCKER_CONFIG => {
                        let p = platform(value)?;
                        let rootfs = value.field("rootfs")?;
                        require(rootfs.field("type")?.equals("layers")?, Failure::Integrity)?;
                        let diff_ids = rootfs.field("diff_ids")?.array()?;
                        for id in &diff_ids {
                            digest_text(*id)?;
                        }
                        let node = self.nodes.get_mut(&d.digest).ok_or(Failure::Integrity)?;
                        node.layers = diff_ids.len();
                        node.platform = Some(p);
                        platforms.push(d.digest.clone());
                    }
                    CACHE_CONFIG => {
                        value.field("layers")?.array()?;
                    }
                    OCI_INDEX | DOCKER_INDEX | OCI_MANIFEST | DOCKER_MANIFEST => {
                        let mut children = Vec::new();
                        for (key, item) in value.members()? {
                            let key = key.text()?;
                            match key.get() {
                                b"schemaVersion" | b"mediaType" | b"manifests" | b"config"
                                | b"layers" => {}
                                b"annotations" => annotations(item)?,
                                _ => return Err(Failure::Protocol),
                            }
                        }
                        require(
                            value.field("schemaVersion")?.number()? == 2
                                && value.field("mediaType")?.equals(&d.media_type)?,
                            Failure::Integrity,
                        )?;
                        let index = matches!(d.media_type.as_str(), OCI_INDEX | DOCKER_INDEX);
                        let mut configuration = None;
                        let mut layer_count = 0;
                        if index {
                            require(
                                !self.cache
                                    && value.optional("config")?.is_none()
                                    && value.optional("layers")?.is_none(),
                                Failure::Integrity,
                            )?;
                            for child in value.field("manifests")?.array()? {
                                let cd = descriptor(child, false)?;
                                require(root_media(&cd.media_type), Failure::Integrity)?;
                                let p = child.optional("platform")?.map(platform).transpose()?;
                                require(
                                    d.media_type != DOCKER_INDEX || p.is_some(),
                                    Failure::Integrity,
                                )?;
                                children.push((cd, p));
                            }
                            require(!children.is_empty(), Failure::Integrity)?;
                        } else {
                            require(value.optional("manifests")?.is_none(), Failure::Integrity)?;
                            let config = value.field("config")?;
                            require(config.optional("platform")?.is_none(), Failure::Integrity)?;
                            let cd = descriptor(config, false)?;
                            let want = if self.cache {
                                CACHE_CONFIG
                            } else if d.media_type == DOCKER_MANIFEST {
                                DOCKER_CONFIG
                            } else {
                                OCI_CONFIG
                            };
                            require(
                                cd.media_type == want
                                    && (!self.cache || d.media_type == OCI_MANIFEST),
                                Failure::Integrity,
                            )?;
                            configuration = Some(cd.digest.clone());
                            children.push((cd, None));
                            for layer in value.field("layers")?.array()? {
                                let ld = descriptor(layer, false)?;
                                require(
                                    LAYERS.contains(&ld.media_type.as_str())
                                        && (d.media_type == DOCKER_MANIFEST)
                                            == ld.media_type.starts_with("application/vnd.docker.")
                                        && layer.optional("platform")?.is_none(),
                                    Failure::Integrity,
                                )?;
                                children.push((ld, None));
                                layer_count += 1;
                            }
                        }
                        // No raw parent metadata survives into recursive work.
                        drop(bytes);
                        for (child, p) in children {
                            for config in self.visit(child, depth + 1, p)? {
                                if !platforms.contains(&config) {
                                    platforms.push(config);
                                }
                            }
                        }
                        if !self.cache {
                            if let Some(config) = configuration {
                                require(
                                    self.nodes
                                        .get(&config)
                                        .is_some_and(|n| n.layers == layer_count),
                                    Failure::Integrity,
                                )?;
                            }
                        }
                    }
                    _ => return Err(Failure::Integrity),
                }
            }
            self.verified_files += 1;
            self.verified_bytes = self
                .verified_bytes
                .checked_add(d.size)
                .ok_or(Failure::Limit)?;
        }
        self.check_platforms(&platforms, expected.as_ref())?;
        let node = self.nodes.get_mut(&d.digest).ok_or(Failure::Integrity)?;
        node.done = true;
        node.platforms = platforms.clone();
        Ok(platforms)
    }

    fn check_platforms(&self, platforms: &[String], expected: Option<&Platform>) -> Result<()> {
        if let Some(expected) = expected {
            for config in platforms {
                let actual = self
                    .nodes
                    .get(config)
                    .and_then(|n| n.platform.as_ref())
                    .ok_or(Failure::Integrity)?;
                platform_matches(actual, expected)?;
            }
        }
        Ok(())
    }
}

fn public_file(
    directory: &Entry,
    fd: &File,
    name: &str,
    limits: &ContentLimits,
    end: u64,
) -> Result<Bytes> {
    let (file, entry) = files::child(fd, &directory.path.join(name), directory.ownership)?;
    require(entry.kind == Kind::File, Failure::Integrity)?;
    files::metadata(&file, limits.metadata_bytes, end)
}

fn parse_content<'a>(bytes: &'a Bytes, limits: &ContentLimits) -> Result<Value<'a>> {
    Value::parse_bounded(
        bytes.get(),
        limits.metadata_bytes as usize,
        limits.content_json_depth as usize,
    )
}

/// Only newly produced Bake layouts may discover a previously unknown root.
pub(crate) fn produced_root(entry: &Entry, limits: &ContentLimits, end: u64) -> Result<Descriptor> {
    let fd = files::open(entry, false)?;
    let bytes = public_file(entry, &fd, "oci-layout", limits, end)?;
    let layout = parse_content(&bytes, limits)?.object(&[b"imageLayoutVersion"])?;
    require(layout[0].equals("1.0.0")?, Failure::Integrity)?;
    let bytes = public_file(entry, &fd, "index.json", limits, end)?;
    let value = parse_content(&bytes, limits)?;
    for (key, item) in value.members()? {
        match key.text()?.get() {
            b"schemaVersion" | b"mediaType" | b"manifests" => {}
            b"annotations" => annotations(item)?,
            _ => return Err(Failure::Integrity),
        }
    }
    require(
        value.field("schemaVersion")?.number()? == 2
            && value.field("mediaType")?.equals(OCI_INDEX)?,
        Failure::Integrity,
    )?;
    let roots = value.field("manifests")?.array()?;
    require(roots.len() == 1, Failure::Integrity)?;
    let root = descriptor(roots[0], false)?;
    require(root_media(&root.media_type), Failure::Integrity)?;
    files::open(entry, false)?;
    before(end)?;
    Ok(root)
}

pub(crate) fn verify(
    entry: &Entry,
    content: &Content,
    limits: &ContentLimits,
    end: u64,
) -> Result<(u64, u64)> {
    before(end)?;
    let fd = files::open(entry, false)?;
    match content {
        Content::File { digest, size } => {
            require(entry.kind == Kind::File, Failure::Policy)?;
            files::verify_file(&fd, digest, *size, limits.staging_bytes, end)?;
            files::open(entry, false)?;
            Ok((1, *size))
        }
        Content::Oci {
            root,
            cache,
            complete,
            registry_receipt,
        } => {
            root.validate()?;
            require(
                entry.kind == Kind::Directory && root_media(&root.media_type),
                Failure::Policy,
            )?;
            if *registry_receipt {
                let bytes = public_file(entry, &fd, "verified.json", limits, end)?;
                let receipt =
                    parse_content(&bytes, limits)?.object(&[b"root", b"closure_complete"])?;
                require(
                    receipt[0].matches(&root.wire())? && receipt[1].boolean()? == *complete,
                    Failure::Integrity,
                )?;
            }
            if *complete {
                require(
                    produced_root(entry, limits, end)? == *root,
                    Failure::Integrity,
                )?;
            }
            let (blobs, _) = files::child(&fd, &entry.path.join("blobs"), entry.ownership)?;
            let (blobs, _) =
                files::child(&blobs, &entry.path.join("blobs/sha256"), entry.ownership)?;
            let mut graph = Graph {
                directory: entry,
                blobs,
                limits,
                end,
                cache: *cache,
                complete: *complete,
                nodes: BTreeMap::new(),
                edges: 0,
                content: 0,
                verified_bytes: 0,
                verified_files: 0,
            };
            graph.visit(root.clone(), 1, None)?;
            files::open(entry, false)?;
            before(end)?;
            Ok((graph.verified_files, graph.verified_bytes))
        }
    }
}
