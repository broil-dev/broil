// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    analysis,
    buffer::Bytes,
    common::*,
    content, files,
    graph::Hasher,
    json::Value,
    supervise::{Active, PublicAction},
};
use super::context::{Point, Watch};
use super::inputs::{create_directory, write_file};
use broil_config::images::select::EffectiveImage;
use broil_core::{
    images::{CacheConfig, SecretReference},
    secret::path_safety,
};
use rustix::fs::{Mode, OFlags, RenameFlags};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::unix::fs::MetadataExt,
    path::Path,
};

pub(crate) const MAX_READS: usize = 16;
pub(crate) const MAX_READ_PATHS: usize = 126;
pub(crate) const MAX_TAG: usize = 74;
const OCI_LAYOUT: &[u8] = b"{\"imageLayoutVersion\":\"1.0.0\"}";

pub(crate) fn project_id(root: &Path) -> Result<String> {
    require(valid_path(root), Failure::Policy)?;
    let text = root.to_str().ok_or(Failure::Policy)?;
    Ok(format!("project-{}", &analysis::hash(text.as_bytes())[7..]))
}

pub(crate) fn namespace_id(
    project: &str,
    environment: &str,
    producer: &str,
    platform: &str,
    repository: &str,
    tag: &str,
) -> Result<String> {
    let mut h = Hasher::new(b"broil.image.cache-namespace.v1");
    for value in [project, environment, producer, platform, repository, tag] {
        h.text(value)?;
    }
    Ok(h.finish())
}

pub(crate) fn namespace_reference(repository: &str, tag: &str, id: &str) -> String {
    format!("{repository}:{tag}--n{}", &id[7..31])
}

pub(crate) fn writer_reference(namespace: &str, root: &Descriptor) -> String {
    format!("{namespace}--r{}", &root.digest[7..31])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Freshness {
    NotApplicable,
    Refreshed,
    NotEstablished,
}

impl Freshness {
    pub fn name(self) -> &'static str {
        match self {
            Self::NotApplicable => "not-applicable",
            Self::Refreshed => "refreshed",
            Self::NotEstablished => "not-established",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportMode {
    Min,
    Max,
}

impl ExportMode {
    pub fn name(self) -> &'static str {
        match self {
            Self::Min => "min",
            Self::Max => "max",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Location {
    pub registry: String,
    pub reference: String,
}

#[derive(Clone, Debug)]
pub(crate) struct NodePlan {
    pub(crate) declaration: CacheConfig,
    pub(crate) no_cache: bool,
    pub(crate) reads: Vec<Location>,
    pub(crate) skipped: Vec<Location>,
    pub(crate) write: Option<(Location, ExportMode)>,
    pub(crate) freshness: Freshness,
    pub(crate) secrets: Vec<SecretReference>,
}

pub(crate) struct Agreement<'a> {
    pub(crate) root: &'a Path,
    pub(crate) environment: Option<&'a str>,
    pub(crate) registries: Option<&'a [String]>,
    pub(crate) refresh: bool,
    pub(crate) images: &'a BTreeMap<String, EffectiveImage>,
}

pub(crate) fn plan(
    agreement: &Agreement<'_>,
    producer: &str,
    platform: &str,
) -> std::result::Result<NodePlan, Failure> {
    let image = agreement.images.get(producer).ok_or(Failure::Policy)?;
    let cache = &image.declaration.cache;
    let locations: Vec<_> = cache.read.iter().chain(cache.write.iter()).collect();
    require(
        image.builder_cache || cache.read.is_empty(),
        Failure::Policy,
    )?;
    require(
        locations.iter().all(|l| l.reference.digest.is_none()),
        Failure::Policy,
    )?;
    let mut seen = BTreeSet::new();
    for location in &cache.read {
        require(
            seen.insert((
                location.reference.repository.as_str(),
                location.reference.tag.as_deref(),
            )),
            Failure::Policy,
        )?;
    }
    if let Some(allowed) = agreement.registries {
        require(
            locations.iter().all(|l| allowed.contains(&l.registry)),
            Failure::Policy,
        )?;
    }
    let mut namespaces = Vec::new();
    if !locations.is_empty() {
        let project = project_id(agreement.root)?;
        for location in &locations {
            let repository = &location.reference.repository;
            let tag = location.reference.tag.as_deref().ok_or(Failure::Policy)?;
            let id = namespace_id(
                &project,
                agreement.environment.unwrap_or(""),
                producer,
                platform,
                repository,
                tag,
            )?;
            let reference = namespace_reference(repository, tag, &id);
            let namespace_tag = &reference[repository.len() + 1..];
            let writers = format!("{namespace_tag}--r");
            for other in agreement.images.values() {
                let output = &other.declaration.image;
                require(
                    output.repository != *repository
                        || output
                            .effective_tag()
                            .is_none_or(|t| t != namespace_tag && !t.starts_with(&writers)),
                    Failure::Policy,
                )?;
            }
            namespaces.push(Location {
                registry: location.registry.clone(),
                reference,
            });
        }
    }
    require(
        locations.iter().all(|l| {
            l.reference
                .tag
                .as_deref()
                .is_some_and(|t| t.len() <= MAX_TAG)
        }) && cache.read.len() <= MAX_READS
            && image.contexts.len() + cache.read.len() <= MAX_READ_PATHS,
        Failure::Limit,
    )?;
    let refresh = image.refresh || agreement.refresh;
    let write = cache.write.as_ref().map(|_| {
        let location = namespaces[cache.read.len()].clone();
        let mode = if image.declaration.secrets.is_empty() && image.declaration.ssh.is_empty() {
            ExportMode::Max
        } else {
            ExportMode::Min
        };
        (location, mode)
    });
    namespaces.truncate(cache.read.len());
    let (reads, skipped) = if refresh {
        (Vec::new(), namespaces)
    } else {
        (namespaces, Vec::new())
    };
    let freshness = if image.declaration.secrets.is_empty() && image.declaration.ssh.is_empty() {
        Freshness::NotApplicable
    } else if refresh {
        Freshness::Refreshed
    } else {
        Freshness::NotEstablished
    };
    Ok(NodePlan {
        declaration: cache.clone(),
        no_cache: refresh || !image.builder_cache,
        reads,
        skipped,
        write,
        freshness,
        secrets: image.declaration.secrets.values().cloned().collect(),
    })
}

pub(crate) fn csv_safe(path: &Path) -> bool {
    path.to_str()
        .is_some_and(|text| !text.contains([',', '"', '\r', '\n']))
}

pub(crate) fn read_verified<W: Watch>(
    watch: &W,
    file: &File,
    descriptor: &Descriptor,
    limit: u64,
) -> Result<Bytes> {
    use std::io::Read;
    require(
        descriptor.size <= limit && descriptor.size <= 16_777_216,
        Failure::Limit,
    )?;
    let mut input = watch.io(|| {
        path_safety::reopen_for_read(file)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    })?;
    let mut bytes = Bytes::new(descriptor.size as usize)?;
    let mut offset = 0;
    while offset < bytes.get().len() {
        let count = watch.io(|| input.read(&mut bytes.get_mut()[offset..]))?;
        require(count > 0, Failure::Integrity)?;
        offset += count;
    }
    let mut tail = [0u8; 1];
    require(watch.io(|| input.read(&mut tail))? == 0, Failure::Integrity)?;
    require(
        analysis::hash(bytes.get()) == descriptor.digest,
        Failure::Integrity,
    )?;
    Ok(bytes)
}

pub(crate) struct UploadWork {
    workspace: Entry,
    export: Entry,
    root: Descriptor,
    limits: ContentLimits,
    result: Option<Entry>,
}

impl UploadWork {
    pub(crate) fn new(
        workspace: Entry,
        export: Entry,
        root: Descriptor,
        limits: ContentLimits,
    ) -> Result<Self> {
        root.validate()?;
        require(
            workspace.kind == Kind::Directory
                && workspace.ownership == Ownership::Operation
                && export.kind == Kind::Directory
                && export.ownership == Ownership::Operation
                && export.path.starts_with(&workspace.path)
                && root.media_type == "application/vnd.oci.image.manifest.v1+json",
            Failure::Policy,
        )?;
        Ok(Self {
            workspace,
            export,
            root,
            limits,
            result: None,
        })
    }

    pub(crate) fn take(self) -> Option<Entry> {
        self.result
    }

    fn closure<W: Watch>(&self, watch: &W, sha: &File) -> Result<Vec<Descriptor>> {
        let (file, item) = files::child(
            sha,
            &self
                .export
                .path
                .join("blobs/sha256")
                .join(&self.root.digest[7..]),
            Ownership::Operation,
        )?;
        require(item.kind == Kind::File, Failure::Policy)?;
        let bytes = read_verified(watch, &file, &self.root, self.limits.metadata_bytes)?;
        let value = Value::parse_bounded(
            bytes.get(),
            self.limits.metadata_bytes as usize,
            self.limits.content_json_depth as usize,
        )?;
        let mut unique = BTreeMap::new();
        unique.insert(self.root.digest.clone(), self.root.clone());
        let config = content::descriptor(value.field("config")?, false)?;
        require(
            config.media_type == "application/vnd.buildkit.cacheconfig.v0",
            Failure::Integrity,
        )?;
        unique.entry(config.digest.clone()).or_insert(config);
        for layer in value.field("layers")?.array()? {
            let layer = content::descriptor(layer, false)?;
            match unique.get(&layer.digest) {
                Some(known) => require(*known == layer, Failure::Integrity)?,
                None => {
                    unique.insert(layer.digest.clone(), layer);
                }
            }
        }
        require(
            unique.len() as u64 <= self.limits.descriptors,
            Failure::Limit,
        )?;
        Ok(unique.into_values().collect())
    }

    pub(crate) fn run<W: Watch>(&mut self, watch: &W) -> Result<()> {
        require(self.result.is_none(), Failure::Policy)?;
        watch.watch()?;
        let workspace = files::private_directory(&self.workspace)?;
        let export = files::open(&self.export, false)?;
        let (export_blobs, _) = files::child(
            &export,
            &self.export.path.join("blobs"),
            Ownership::Operation,
        )?;
        let (export_sha, _) = files::child(
            &export_blobs,
            &self.export.path.join("blobs/sha256"),
            Ownership::Operation,
        )?;
        let closure = self.closure(watch, &export_sha)?;
        let base = self.workspace.path.join("cache-upload");
        let (layout, entry) = create_directory(watch, &workspace, &base)?;
        let mut created = vec![entry.clone()];
        created.push(write_file(
            watch,
            &layout,
            &base.join("oci-layout"),
            OCI_LAYOUT,
        )?);
        let wrapper = serde_json::to_vec(&json!({"schemaVersion":2,
            "mediaType":content::OCI_INDEX,"manifests":[{"digest":self.root.digest,
            "mediaType":self.root.media_type,"size":self.root.size}]}))
        .map_err(|_| Failure::Protocol)?;
        created.push(write_file(
            watch,
            &layout,
            &base.join("index.json"),
            &wrapper,
        )?);
        let (blobs, blobs_entry) = create_directory(watch, &layout, &base.join("blobs"))?;
        created.push(blobs_entry);
        let (sha, sha_entry) = create_directory(watch, &blobs, &base.join("blobs/sha256"))?;
        created.push(sha_entry);
        for descriptor in &closure {
            let name = &descriptor.digest[7..];
            let handle = File::from(watch.sys(|| {
                rustix::fs::openat(
                    &export_sha,
                    name,
                    OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
            })?);
            let metadata = watch.io(|| handle.metadata())?;
            require(
                metadata.is_file() && metadata.uid() == path_safety::effective_uid(),
                Failure::Policy,
            )?;
            require(
                metadata.nlink() == 1 && metadata.len() == descriptor.size,
                Failure::Integrity,
            )?;
            let opened = watch.io(|| {
                path_safety::reopen_for_read(&handle)
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            })?;
            watch.sys(|| rustix::fs::fchmod(&opened, Mode::from_raw_mode(0o600)))?;
            watch.at(Point::Renaming(
                &self.export.path.join("blobs/sha256").join(name),
            ))?;
            watch.sys(|| {
                rustix::fs::renameat_with(&export_sha, name, &sha, name, RenameFlags::NOREPLACE)
            })?;
            let (_, moved) = files::child(
                &sha,
                &base.join("blobs/sha256").join(name),
                Ownership::Operation,
            )?;
            require(
                moved.kind == Kind::File
                    && moved.device == metadata.dev()
                    && moved.inode == metadata.ino(),
                Failure::Integrity,
            )?;
            created.push(moved);
        }
        for item in &created {
            watch.watch()?;
            files::open(item, false)?;
        }
        watch.watch()?;
        self.result = Some(entry);
        Ok(())
    }
}

impl PublicAction for UploadWork {
    fn apply(&mut self, active: &Active) -> Result<()> {
        self.run(active)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
