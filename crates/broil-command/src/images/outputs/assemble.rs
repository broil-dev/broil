// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    VerifiedOutput, analysis,
    common::*,
    content, files,
    solve::{Watch, create_directory, write_file},
    supervise::{Active, PublicAction},
};
use broil_core::images::reference::ImageReference;
use rustix::fs::AtFlags;
use serde_json::{Map, Value as Public, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const OCI_LAYOUT: &[u8] = b"{\"imageLayoutVersion\":\"1.0.0\"}";
const MANIFESTS: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

#[derive(Clone, Debug)]
pub(crate) struct NodeChain {
    pub(crate) platform: String,
    pub(crate) output: VerifiedOutput,
    pub(crate) config: Descriptor,
    pub(crate) layers: Vec<Descriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    Node(Entry),
    Index,
}

#[derive(Clone, Debug)]
pub(crate) struct Assembly {
    pub(crate) root: Descriptor,
    pub(crate) index: Option<Vec<u8>>,
    pub(crate) wrapper: Vec<u8>,
    pub(crate) links: Vec<(Entry, Descriptor)>,
    pub(crate) blobs: Vec<(Descriptor, Source)>,
    pub(crate) descriptors: u64,
    pub(crate) content_bytes: u64,
}

pub(crate) fn platform_object(platform: &str) -> Result<Public> {
    let parts: Vec<_> = platform.split('/').collect();
    require((2..=3).contains(&parts.len()), Failure::Policy)?;
    let mut object = Map::new();
    object.insert("os".into(), json!(parts[0]));
    object.insert("architecture".into(), json!(parts[1]));
    if let Some(variant) = parts.get(2) {
        object.insert("variant".into(), json!(variant));
    }
    Ok(Public::Object(object))
}

pub(crate) fn annotations(reference: &ImageReference) -> Result<Public> {
    let mut object = Map::new();
    match (reference.effective_tag(), &reference.digest) {
        (Some(tag), _) => {
            object.insert(
                "io.containerd.image.name".into(),
                json!(format!("{}:{tag}", reference.repository)),
            );
            object.insert("org.opencontainers.image.ref.name".into(), json!(tag));
        }
        (None, Some(digest)) => {
            object.insert(
                "io.containerd.image.name".into(),
                json!(format!("{}@{digest}", reference.repository)),
            );
        }
        (None, None) => return Err(Failure::Policy),
    }
    Ok(Public::Object(object))
}

fn encoded(value: &Public) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Failure::Protocol)
}

pub(crate) fn plan(
    chains: &[NodeChain],
    reference: &ImageReference,
    limits: &ContentLimits,
) -> std::result::Result<Assembly, Failure> {
    require(!chains.is_empty() && chains.len() <= 64, Failure::Limit)?;
    for chain in chains {
        require(
            MANIFESTS.contains(&chain.output.root().media_type.as_str()),
            Failure::Integrity,
        )?;
    }
    let mut unique: BTreeMap<String, (Descriptor, Source)> = BTreeMap::new();
    let mut edges = 0u64;
    let mut add = |descriptor: &Descriptor, source: Source| -> Result<()> {
        edges = edges.checked_add(1).ok_or(Failure::Limit)?;
        match unique.get(&descriptor.digest) {
            Some((known, _)) => require(known == descriptor, Failure::Integrity),
            None => {
                unique.insert(descriptor.digest.clone(), (descriptor.clone(), source));
                Ok(())
            }
        }
    };
    let (root, index) = if chains.len() == 1 {
        (chains[0].output.root().clone(), None)
    } else {
        let mut manifests = Vec::new();
        for chain in chains {
            let root = chain.output.root();
            manifests.push(json!({"digest":root.digest,"mediaType":root.media_type,
                "size":root.size,"platform":platform_object(&chain.platform)?}));
        }
        let bytes = encoded(&json!({"schemaVersion":2,"mediaType":content::OCI_INDEX,
            "manifests":manifests}))?;
        let root = Descriptor {
            digest: analysis::hash(&bytes),
            size: bytes.len() as u64,
            media_type: content::OCI_INDEX.into(),
        };
        add(&root, Source::Index)?;
        (root, Some(bytes))
    };
    let mut links = Vec::new();
    let mut linked = BTreeSet::new();
    for chain in chains {
        let source = chain.output.retained().entry().clone();
        for metadata in [chain.output.root(), &chain.config] {
            add(metadata, Source::Node(source.clone()))?;
            if linked.insert(metadata.digest.clone()) {
                links.push((source.clone(), metadata.clone()));
            }
        }
        for layer in &chain.layers {
            add(layer, Source::Node(source.clone()))?;
        }
    }
    let content_bytes = unique
        .values()
        .try_fold(0u64, |total, (d, _)| total.checked_add(d.size))
        .ok_or(Failure::Limit)?;
    require(
        unique.len() as u64 <= limits.descriptors
            && edges <= limits.descriptor_edges
            && content_bytes <= limits.content_bytes,
        Failure::Limit,
    )?;
    let wrapper = encoded(&json!({"schemaVersion":2,"mediaType":content::OCI_INDEX,
        "manifests":[{"digest":root.digest,"mediaType":root.media_type,"size":root.size,
            "annotations":annotations(reference)?}]}))?;
    Ok(Assembly {
        root,
        index,
        wrapper,
        links,
        descriptors: unique.len() as u64,
        content_bytes,
        blobs: unique.into_values().collect(),
    })
}

pub(crate) struct AssembleWork {
    workspace: Entry,
    wrapper: Vec<u8>,
    index: Option<(Descriptor, Vec<u8>)>,
    links: Vec<(Entry, Descriptor)>,
    result: Option<Entry>,
}

impl AssembleWork {
    pub(crate) fn new(workspace: Entry, assembly: &Assembly) -> Result<Self> {
        require(
            workspace.kind == Kind::Directory && workspace.ownership == Ownership::Operation,
            Failure::Policy,
        )?;
        Ok(Self {
            workspace,
            wrapper: assembly.wrapper.clone(),
            index: assembly
                .index
                .as_ref()
                .map(|bytes| (assembly.root.clone(), bytes.clone())),
            links: assembly.links.clone(),
            result: None,
        })
    }

    pub(crate) fn take(self) -> Option<Entry> {
        self.result
    }

    pub(crate) fn run<W: Watch>(&mut self, watch: &W) -> Result<()> {
        require(self.result.is_none(), Failure::Policy)?;
        watch.watch()?;
        let workspace = files::private_directory(&self.workspace)?;
        let root = self.workspace.path.join("outputs");
        let (outputs, outputs_entry) = create_directory(watch, &workspace, &root)?;
        let base = root.join("layout");
        let (layout, entry) = create_directory(watch, &outputs, &base)?;
        let mut created = vec![outputs_entry, entry.clone()];
        created.push(write_file(
            watch,
            &layout,
            &base.join("oci-layout"),
            OCI_LAYOUT,
        )?);
        created.push(write_file(
            watch,
            &layout,
            &base.join("index.json"),
            &self.wrapper,
        )?);
        let (blobs, blobs_entry) = create_directory(watch, &layout, &base.join("blobs"))?;
        created.push(blobs_entry);
        let sha_path = base.join("blobs/sha256");
        let (sha, sha_entry) = create_directory(watch, &blobs, &sha_path)?;
        created.push(sha_entry);
        if let Some((descriptor, bytes)) = &self.index {
            created.push(write_file(
                watch,
                &sha,
                &sha_path.join(&descriptor.digest[7..]),
                bytes,
            )?);
        }
        for (source, descriptor) in &self.links {
            watch.watch()?;
            let name = &descriptor.digest[7..];
            let directory = files::open(source, false)?;
            let (source_blobs, _) =
                files::child(&directory, &source.path.join("blobs"), source.ownership)?;
            let (source_sha, _) = files::child(
                &source_blobs,
                &source.path.join("blobs/sha256"),
                source.ownership,
            )?;
            let (blob, original) = files::child(
                &source_sha,
                &source.path.join("blobs/sha256").join(name),
                source.ownership,
            )?;
            require(original.kind == Kind::File, Failure::Policy)?;
            let metadata = watch.io(|| blob.metadata())?;
            require(metadata.len() == descriptor.size, Failure::Integrity)?;
            watch.sys(|| rustix::fs::linkat(&source_sha, name, &sha, name, AtFlags::empty()))?;
            let (_, linked) = files::child(&sha, &sha_path.join(name), Ownership::Operation)?;
            require(
                linked.kind == Kind::File
                    && linked.device == original.device
                    && linked.inode == original.inode,
                Failure::Integrity,
            )?;
            created.push(linked);
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

impl PublicAction for AssembleWork {
    fn apply(&mut self, active: &Active) -> Result<()> {
        self.run(active)
    }
    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
