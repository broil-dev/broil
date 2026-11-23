// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    ContentLimits, Entry, Kind,
    analysis::{self, Metadata, Options, Snapshot, Source, Status},
    buffer::Bytes,
    content, files,
    json::Value,
    supervise::SourceBytes,
};
use super::{identity, *};
use broil_config::images::select::{EffectiveImage, ProducerMatch, SelectedCatalogs};
use broil_core::images::reference::ImageReference;
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct NodeKey {
    pub producer: String,
    pub platform: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SourceKey {
    pub reference: String,
    pub platform: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum ClosureKind {
    Inspect,
    Fetch,
}

pub(crate) struct Closure {
    pub(crate) source: SourceKey,
    pub(crate) kind: ClosureKind,
    pub(crate) output: VerifiedOutput,
    pub(crate) endpoint: String,
    pub(crate) repository: String,
    pub(crate) reference: String,
    pub(crate) registry: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    Node(Failure),
    Session(Failure),
}

pub(crate) enum Retained {
    Verified,
    Missing,
}

enum Verdict {
    Verified,
    Missing,
    Changed,
}

fn verdict(result: Result<Retained>) -> Result<Verdict> {
    match result {
        Ok(Retained::Verified) => Ok(Verdict::Verified),
        Ok(Retained::Missing) => Ok(Verdict::Missing),
        Err(
            failure @ (Failure::Cancellation
            | Failure::Timeout
            | Failure::Capacity
            | Failure::Limit
            | Failure::Storage),
        ) => Err(failure),
        Err(_) => Ok(Verdict::Changed),
    }
}

pub(crate) trait Driver {
    fn check(&self) -> Result<()>;
    fn deadline(&self) -> Result<u64>;
    fn snapshot(&mut self, path: &Path, limit: usize) -> std::result::Result<SourceBytes, Refusal>;
    fn attempt(&mut self, stage: &str, snapshot: Snapshot) -> Result<Outcome>;
    fn inspect(
        &mut self,
        stage: &str,
        source: &SourceKey,
        pinned: Option<&Descriptor>,
    ) -> std::result::Result<Closure, Refusal>;
    fn fetch(
        &mut self,
        stage: &str,
        source: &SourceKey,
        pinned: &Descriptor,
    ) -> std::result::Result<Closure, Refusal>;
    fn recheck(&mut self, stage: &str, output: &VerifiedOutput) -> Result<Retained>;
}

pub(crate) struct Inputs<'a> {
    pub catalogs: &'a SelectedCatalogs<'a>,
    pub root: &'a Path,
    pub request: Request,
    pub limits: Limits,
    pub registries: Option<BTreeSet<String>>,
    pub producer_outputs: BTreeMap<NodeKey, VerifiedOutput>,
    pub prior: Option<(Resolution, Material)>,
    pub catalog_id: String,
}

#[derive(Clone)]
pub(crate) struct Associations {
    pub(crate) sources: BTreeSet<SourceKey>,
    pub(crate) producers: BTreeMap<NodeKey, BTreeSet<String>>,
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum Resolved {
    Graph(Resolution, Material),
    Stale(Vec<Diagnostic>, Resolution, Material),
}

struct Rechecked {
    stale: Vec<Diagnostic>,
    verified: Vec<bool>,
}

impl Rechecked {
    fn new(mut stale: Vec<Diagnostic>, verified: Vec<bool>) -> Self {
        stale.sort_by(identity::cmp_diagnostic);
        stale.dedup();
        Self { stale, verified }
    }
}

enum Work {
    Open,
    Complete,
    Pending(BTreeSet<NodeKey>),
    Invalid,
    Unsupported,
    Refused,
    Exhausted,
}

#[derive(Clone)]
enum EdgeTarget {
    Node(NodeKey),
    Source(SourceKey),
}

#[derive(Clone)]
struct EdgeWork {
    target: EdgeTarget,
    role: Role,
    instruction: Instruction,
    tag_origin: TagOrigin,
    location: Location,
}

struct NodeWork {
    key: NodeKey,
    image: EffectiveImage,
    path: String,
    snapshot: Option<SourceBytes>,
    size: u64,
    digest: String,
    resolution_id: Option<String>,
    work: Work,
    attempts: u64,
    edges: Vec<EdgeWork>,
    diagnostics: Vec<(&'static str, Location)>,
    sources: BTreeSet<SourceKey>,
    producers: BTreeMap<NodeKey, BTreeSet<String>>,
}

struct SourceWork {
    root: Option<Descriptor>,
    registry: Option<String>,
    inspect: Option<Closure>,
    fetch: Option<Closure>,
}

struct Classified {
    edges: Vec<EdgeWork>,
    refusals: Vec<(&'static str, Location)>,
    pending: BTreeSet<NodeKey>,
    externals: BTreeSet<SourceKey>,
    producers: BTreeMap<NodeKey, BTreeSet<String>>,
}

pub(crate) fn reason_for(failure: Failure) -> &'static str {
    match failure {
        Failure::Integrity => "integrity",
        Failure::Limit => "limit",
        Failure::Storage => "storage",
        _ => "policy",
    }
}

pub(crate) struct Chain {
    pub config: Bytes,
    pub manifest: Bytes,
    pub indexes: Vec<Bytes>,
}

fn platform_matches(value: Value<'_>, platform: &str) -> Result<bool> {
    let parts: Vec<_> = platform.split('/').collect();
    require((2..=3).contains(&parts.len()), Failure::Integrity)?;
    let variant = match value.optional("variant")? {
        Some(v) if !v.is_null() => Some(v),
        _ => None,
    };
    Ok(value.field("os")?.equals(parts[0])?
        && value.field("architecture")?.equals(parts[1])?
        && match variant {
            Some(v) => v.equals(parts.get(2).copied().unwrap_or(""))?,
            None => parts.len() == 2,
        })
}

pub(crate) fn read_chain(
    entry: &Entry,
    root: &Descriptor,
    platform: &str,
    end: u64,
) -> Result<Chain> {
    let limits = ContentLimits {
        metadata_bytes: analysis::OBJECT as u64,
        ..ContentLimits::default()
    };
    let directory = files::open(entry, false)?;
    let (blobs, _) = files::child(&directory, &entry.path.join("blobs"), entry.ownership)?;
    let (sha, _) = files::child(&blobs, &entry.path.join("blobs/sha256"), entry.ownership)?;
    let read = |descriptor: &Descriptor| -> Result<Bytes> {
        before(end)?;
        descriptor.validate()?;
        let path = entry
            .path
            .join("blobs/sha256")
            .join(&descriptor.digest[7..]);
        let (file, item) = files::child(&sha, &path, entry.ownership)?;
        require(item.kind == Kind::File, Failure::Integrity)?;
        content::verified_metadata(&file, descriptor, &limits, end)
    };
    let mut current = root.clone();
    let mut indexes = Vec::new();
    loop {
        require(indexes.len() <= 32, Failure::Limit)?;
        let bytes = read(&current)?;
        let value = Value::parse_bounded(bytes.get(), analysis::OBJECT, 128)?;
        require(
            value.field("schemaVersion")?.number()? == 2
                && value.field("mediaType")?.equals(&current.media_type)?
                && content::root_media(&current.media_type),
            Failure::Integrity,
        )?;
        if let Some(children) = value.optional("manifests")? {
            let mut selected = None;
            let mut matching = 0;
            for child in children.array()? {
                let descriptor = content::descriptor(child, false)?;
                let matches = match child.optional("platform")? {
                    Some(p) if !p.is_null() => platform_matches(p, platform)?,
                    _ => true,
                };
                if matches {
                    matching += 1;
                    selected = Some(descriptor);
                }
            }
            require(matching <= 1, Failure::Integrity)?;
            current = selected.ok_or(Failure::Storage)?;
            indexes.push(bytes);
            continue;
        }
        let config_descriptor = content::descriptor(value.field("config")?, false)?;
        let config = read(&config_descriptor)?;
        return Ok(Chain {
            config,
            manifest: bytes,
            indexes,
        });
    }
}

struct Engine<'a> {
    catalogs: &'a SelectedCatalogs<'a>,
    root: &'a Path,
    request: Request,
    limits: Limits,
    registries: Option<BTreeSet<String>>,
    producer_outputs: BTreeMap<NodeKey, VerifiedOutput>,
    catalog_id: String,
    nodes: BTreeMap<NodeKey, NodeWork>,
    sources: BTreeMap<SourceKey, SourceWork>,
    outcomes: BTreeMap<NodeKey, Outcome>,
    queue: VecDeque<NodeKey>,
    stages: u64,
    retained_bytes: usize,
}

impl<'a> Engine<'a> {
    fn new(inputs: &Inputs<'a>) -> Self {
        Self {
            catalogs: inputs.catalogs,
            root: inputs.root,
            request: inputs.request.clone(),
            limits: inputs.limits.clone(),
            registries: inputs.registries.clone(),
            producer_outputs: BTreeMap::new(),
            catalog_id: inputs.catalog_id.clone(),
            nodes: BTreeMap::new(),
            sources: BTreeMap::new(),
            outcomes: BTreeMap::new(),
            queue: VecDeque::new(),
            stages: 0,
            retained_bytes: 0,
        }
    }

    fn stage(&mut self, kind: &str) -> String {
        self.stages += 1;
        format!("graph-{kind}-{}", self.stages)
    }

    fn rendered_path(&self, dockerfile: &Path) -> Result<String> {
        let path = dockerfile.strip_prefix(self.root).unwrap_or(dockerfile);
        let text = path.to_str().ok_or(Failure::Policy)?;
        require(!text.is_empty() && !text.contains('\0'), Failure::Policy)?;
        Ok(text.into())
    }

    fn ensure_node(&mut self, key: NodeKey) -> Result<()> {
        if self.nodes.contains_key(&key) {
            return Ok(());
        }
        require(
            (self.nodes.len() as u64) < self.limits.nodes,
            Failure::Limit,
        )?;
        let image = self
            .catalogs
            .images
            .get(&key.producer)
            .ok_or(Failure::Policy)?
            .clone();
        require(image.platforms.contains(&key.platform), Failure::Policy)?;
        let path = self.rendered_path(&image.dockerfile)?;
        self.nodes.insert(
            key.clone(),
            NodeWork {
                key: key.clone(),
                image,
                path,
                snapshot: None,
                size: 0,
                digest: String::new(),
                resolution_id: None,
                work: Work::Open,
                attempts: 0,
                edges: Vec::new(),
                diagnostics: Vec::new(),
                sources: BTreeSet::new(),
                producers: BTreeMap::new(),
            },
        );
        self.queue.push_back(key);
        Ok(())
    }

    fn options(&self, node: &NodeWork) -> Options {
        Options {
            path: node.path.clone(),
            stage: node.image.declaration.stage.clone().unwrap_or_default(),
            args: node.image.declaration.args.clone(),
            build_platform: self.request.build_platform.clone(),
            platform: node.key.platform.clone(),
            contexts: node.image.contexts.keys().cloned().collect(),
            frontend: analysis::FRONTEND.into(),
        }
    }

    fn metadata(&self, node: &NodeWork, end: u64) -> Result<Vec<Metadata>> {
        let mut result = Vec::new();
        for key in &node.sources {
            let source = self.sources.get(key).ok_or(Failure::Integrity)?;
            let closure = source.inspect.as_ref().ok_or(Failure::Storage)?;
            let root = source.root.as_ref().ok_or(Failure::Integrity)?;
            let chain = read_chain(closure.output.entry(), root, &key.platform, end)?;
            let views: Vec<&[u8]> = chain.indexes.iter().map(Bytes::get).collect();
            result.push(if closure.reference == key.reference {
                Metadata::from_verified(
                    &closure.output,
                    &key.platform,
                    chain.config.get(),
                    chain.manifest.get(),
                    &views,
                )?
            } else {
                Metadata::from_pinned(
                    &closure.output,
                    &key.reference,
                    &key.platform,
                    root,
                    chain.config.get(),
                    chain.manifest.get(),
                    &views,
                )?
            });
        }
        for (producer, uses) in &node.producers {
            let output = self
                .producer_outputs
                .get(producer)
                .ok_or(Failure::Integrity)?;
            let chain = read_chain(output.entry(), output.root(), &producer.platform, end)?;
            let views: Vec<&[u8]> = chain.indexes.iter().map(Bytes::get).collect();
            for reference in uses {
                result.push(Metadata::from_producer(
                    output,
                    reference,
                    &producer.platform,
                    chain.config.get(),
                    chain.manifest.get(),
                    &views,
                )?);
            }
        }
        Ok(result)
    }

    fn classify(&self, sources: &[Source]) -> Result<Classified> {
        let mut result = Classified {
            edges: Vec::new(),
            refusals: Vec::new(),
            pending: BTreeSet::new(),
            externals: BTreeSet::new(),
            producers: BTreeMap::new(),
        };
        for source in sources {
            let reference = ImageReference::parse(&source.reference).ok_or(Failure::Integrity)?;
            match self.catalogs.match_producer(&reference, &source.platform) {
                ProducerMatch::Producer {
                    name,
                    platform_declared: true,
                } => {
                    let key = NodeKey {
                        producer: name,
                        platform: source.platform.clone(),
                    };
                    for u in &source.uses {
                        result.edges.push(EdgeWork {
                            target: EdgeTarget::Node(key.clone()),
                            role: u.role,
                            instruction: u.instruction,
                            tag_origin: u.tag_origin,
                            location: u.location.clone(),
                        });
                    }
                    if self.producer_outputs.contains_key(&key) {
                        result
                            .producers
                            .entry(key)
                            .or_default()
                            .insert(source.reference.clone());
                    } else {
                        result.pending.insert(key);
                    }
                }
                ProducerMatch::Producer {
                    platform_declared: false,
                    ..
                } => {
                    for u in &source.uses {
                        result
                            .refusals
                            .push(("platform-unsupported", u.location.clone()));
                    }
                }
                ProducerMatch::Ambiguous => {
                    for u in &source.uses {
                        result
                            .refusals
                            .push(("ambiguous-producer", u.location.clone()));
                    }
                }
                ProducerMatch::PinMismatch => {
                    for u in &source.uses {
                        result.refusals.push(("pin-mismatch", u.location.clone()));
                    }
                }
                ProducerMatch::External => {
                    let key = SourceKey {
                        reference: source.reference.clone(),
                        platform: source.platform.clone(),
                    };
                    for u in &source.uses {
                        result.edges.push(EdgeWork {
                            target: EdgeTarget::Source(key.clone()),
                            role: u.role,
                            instruction: u.instruction,
                            tag_origin: u.tag_origin,
                            location: u.location.clone(),
                        });
                    }
                    result.externals.insert(key);
                }
            }
        }
        Ok(result)
    }

    fn edge_count(&self) -> u64 {
        self.nodes.values().map(|n| n.edges.len() as u64).sum()
    }

    fn refuse(node: &mut NodeWork, reason: &'static str, location: Location) {
        node.work = Work::Refused;
        node.diagnostics.push((reason, location));
        node.edges
            .retain(|edge| matches!(edge.target, EdgeTarget::Node(_)));
    }

    fn refuse_matching(node: &mut NodeWork, refusals: Vec<(&'static str, Location)>) {
        node.work = Work::Refused;
        node.diagnostics.extend(refusals);
        node.edges
            .retain(|edge| matches!(edge.target, EdgeTarget::Node(_)));
    }

    fn acquire(
        &mut self,
        key: &SourceKey,
        driver: &mut dyn Driver,
    ) -> std::result::Result<(), Refusal> {
        if self.sources.get(key).is_some_and(|s| s.inspect.is_some()) {
            return Ok(());
        }
        if !self.sources.contains_key(key) {
            if self.sources.len() as u64 >= self.limits.sources {
                return Err(Refusal::Session(Failure::Limit));
            }
            self.sources.insert(
                key.clone(),
                SourceWork {
                    root: None,
                    registry: None,
                    inspect: None,
                    fetch: None,
                },
            );
        }
        let pinned = self.sources[key].root.clone();
        let stage = self.stage(if pinned.is_some() {
            "reinspect"
        } else {
            "inspect"
        });
        let closure = driver.inspect(&stage, key, pinned.as_ref())?;
        if let Some(pinned) = &pinned {
            if closure.output.root() != pinned {
                return Err(Refusal::Node(Failure::Integrity));
            }
        }
        let source = self
            .sources
            .get_mut(key)
            .ok_or(Refusal::Session(Failure::Integrity))?;
        source.root = Some(closure.output.root().clone());
        source.registry = closure.registry.clone();
        source.inspect = Some(closure);
        Ok(())
    }

    fn take_snapshot(
        &mut self,
        key: &NodeKey,
        driver: &mut dyn Driver,
    ) -> Result<Option<(&'static str, Location)>> {
        let (dockerfile, limit) = {
            let node = &self.nodes[key];
            (
                node.image.dockerfile.clone(),
                self.limits.snapshot_bytes as usize,
            )
        };
        match driver.snapshot(&dockerfile, limit) {
            Ok(bytes) => {
                let node = self.nodes.get_mut(key).ok_or(Failure::Integrity)?;
                node.size = bytes.size;
                node.digest = bytes.digest.clone();
                node.snapshot = Some(bytes);
                Ok(None)
            }
            Err(Refusal::Node(failure)) => Ok(Some((reason_for(failure), Location::Unavailable))),
            Err(Refusal::Session(failure)) => Err(failure),
        }
    }

    fn prepare(&self, key: &NodeKey, end: u64) -> std::result::Result<Snapshot, &'static str> {
        let node = &self.nodes[key];
        let metadata = self.metadata(node, end).map_err(|failure| match failure {
            Failure::Integrity => "integrity",
            Failure::Limit => "limit",
            _ => "missing-metadata",
        })?;
        let bytes = node.snapshot.as_ref().ok_or("storage")?;
        Snapshot::new(bytes.bytes.get(), self.options(node), metadata).map_err(reason_for)
    }

    fn supersede(&mut self, key: &NodeKey) -> Result<()> {
        if self.producer_outputs.remove(key).is_none() {
            return Ok(());
        }
        let consumers: Vec<NodeKey> = self
            .nodes
            .iter()
            .filter(|(_, node)| node.producers.contains_key(key))
            .map(|(consumer, _)| consumer.clone())
            .collect();
        for consumer in consumers {
            let node = self.nodes.get_mut(&consumer).ok_or(Failure::Integrity)?;
            match node.work {
                Work::Complete => {
                    node.work = Work::Open;
                    node.resolution_id = None;
                    if let Some(outcome) = self.outcomes.remove(&consumer) {
                        self.retained_bytes =
                            self.retained_bytes.saturating_sub(outcome.retained_bytes());
                    }
                    self.queue.push_back(consumer);
                }
                Work::Open => {
                    node.resolution_id = None;
                    self.outcomes.remove(&consumer);
                }
                Work::Pending(ref mut awaited) => {
                    awaited.insert(key.clone());
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn process(&mut self, key: NodeKey, driver: &mut dyn Driver) -> Result<()> {
        driver.check()?;
        if !matches!(self.nodes[&key].work, Work::Open) {
            return Ok(());
        }
        if let Some((reason, location)) = self.take_snapshot(&key, driver)? {
            Self::refuse(
                self.nodes.get_mut(&key).ok_or(Failure::Integrity)?,
                reason,
                location,
            );
            self.outcomes.remove(&key);
            self.supersede(&key)?;
            return Ok(());
        }
        if let Some(prior) = self.outcomes.remove(&key) {
            let reuse = match self.prepare(&key, driver.deadline()?) {
                Ok(snapshot) => analysis::resolution_identity(&snapshot)
                    .ok()
                    .is_some_and(|id| {
                        Some(id.as_str()) == self.nodes[&key].resolution_id.as_deref()
                    }),
                Err(_) => false,
            };
            let node = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
            if reuse {
                self.retained_bytes = self
                    .retained_bytes
                    .checked_add(prior.retained_bytes())
                    .ok_or(Failure::Limit)?;
                require(
                    self.retained_bytes as u64 <= self.limits.retained_bytes,
                    Failure::Limit,
                )?;
                node.work = Work::Complete;
                node.snapshot = None;
                self.outcomes.insert(key, prior);
                return Ok(());
            }
            drop(prior);
            node.resolution_id = None;
        }
        self.supersede(&key)?;
        {
            let node = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
            node.edges.clear();
            node.sources.clear();
            node.producers.clear();
        }
        loop {
            driver.check()?;
            let node = &self.nodes[&key];
            if node.attempts >= self.limits.attempts {
                let node = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
                node.work = Work::Exhausted;
                node.diagnostics.push(("limit", Location::Unavailable));
                break;
            }
            let snapshot = match self.prepare(&key, driver.deadline()?) {
                Ok(snapshot) => snapshot,
                Err(reason) => {
                    Self::refuse(
                        self.nodes.get_mut(&key).ok_or(Failure::Integrity)?,
                        reason,
                        Location::Unavailable,
                    );
                    break;
                }
            };
            let stage = self.stage("analyze");
            self.nodes.get_mut(&key).ok_or(Failure::Integrity)?.attempts += 1;
            let outcome = driver.attempt(&stage, snapshot)?;
            let node = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
            node.resolution_id = Some(outcome.resolution_id().into());
            match outcome.status() {
                Status::Complete => {
                    let classified = self.classify(outcome.sources())?;
                    let node = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
                    node.edges = classified.edges;
                    if !classified.refusals.is_empty() {
                        Self::refuse_matching(node, classified.refusals);
                        break;
                    }
                    require(
                        classified.pending.is_empty()
                            && classified
                                .externals
                                .iter()
                                .all(|s| node.sources.contains(s))
                            && classified.producers.iter().all(|(producer, uses)| {
                                node.producers
                                    .get(producer)
                                    .is_some_and(|known| uses.is_subset(known))
                            }),
                        Failure::Integrity,
                    )?;
                    self.retained_bytes = self
                        .retained_bytes
                        .checked_add(outcome.retained_bytes())
                        .ok_or(Failure::Limit)?;
                    require(
                        self.retained_bytes as u64 <= self.limits.retained_bytes,
                        Failure::Limit,
                    )?;
                    node.work = Work::Complete;
                    self.outcomes.insert(key.clone(), outcome);
                    break;
                }
                Status::MetadataRequired => {
                    let classified = self.classify(outcome.sources())?;
                    drop(outcome);
                    let known = {
                        let node = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
                        node.edges = classified.edges;
                        if !classified.refusals.is_empty() {
                            Self::refuse_matching(node, classified.refusals);
                            break;
                        }
                        let known = node.sources.len()
                            + node.producers.values().map(BTreeSet::len).sum::<usize>();
                        for (producer, uses) in classified.producers {
                            node.producers.entry(producer).or_default().extend(uses);
                        }
                        known
                    };
                    for producer in &classified.pending {
                        self.ensure_node(producer.clone())?;
                    }
                    let mut refusal = None;
                    for source in &classified.externals {
                        match self.acquire(source, driver) {
                            Ok(()) => {
                                self.nodes
                                    .get_mut(&key)
                                    .ok_or(Failure::Integrity)?
                                    .sources
                                    .insert(source.clone());
                            }
                            Err(Refusal::Node(failure)) => {
                                refusal = Some(reason_for(failure));
                                break;
                            }
                            Err(Refusal::Session(failure)) => return Err(failure),
                        }
                    }
                    let node = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
                    if let Some(reason) = refusal {
                        Self::refuse(node, reason, Location::Unavailable);
                        break;
                    }
                    if !classified.pending.is_empty() {
                        node.work = Work::Pending(classified.pending);
                        break;
                    }
                    let now = node.sources.len()
                        + node.producers.values().map(BTreeSet::len).sum::<usize>();
                    if now == known {
                        Self::refuse(node, "missing-metadata", Location::Unavailable);
                        break;
                    }
                }
                Status::Invalid | Status::Unsupported => {
                    node.work = if outcome.status() == Status::Invalid {
                        Work::Invalid
                    } else {
                        Work::Unsupported
                    };
                    for d in outcome.diagnostics() {
                        node.diagnostics.push((d.reason, d.location.clone()));
                    }
                    node.edges.clear();
                    break;
                }
            }
            require(self.edge_count() <= self.limits.edges, Failure::Limit)?;
        }
        self.nodes.get_mut(&key).ok_or(Failure::Integrity)?.snapshot = None;
        require(self.edge_count() <= self.limits.edges, Failure::Limit)?;
        Ok(())
    }

    fn stage_content(&mut self, driver: &mut dyn Driver) -> Result<()> {
        let keys: Vec<_> = self.nodes.keys().cloned().collect();
        for key in keys {
            driver.check()?;
            if !matches!(self.nodes[&key].work, Work::Complete) {
                continue;
            }
            let sources: Vec<_> = self.nodes[&key].sources.iter().cloned().collect();
            for source in sources {
                if self.sources[&source].fetch.is_some() {
                    continue;
                }
                let pinned = self.sources[&source]
                    .root
                    .clone()
                    .ok_or(Failure::Integrity)?;
                let stage = self.stage("fetch");
                match driver.fetch(&stage, &source, &pinned) {
                    Ok(closure) => {
                        require(*closure.output.root() == pinned, Failure::Integrity)?;
                        self.sources
                            .get_mut(&source)
                            .ok_or(Failure::Integrity)?
                            .fetch = Some(closure);
                    }
                    Err(Refusal::Node(failure)) => {
                        if let Some(outcome) = self.outcomes.remove(&key) {
                            self.retained_bytes =
                                self.retained_bytes.saturating_sub(outcome.retained_bytes());
                        }
                        let node = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
                        node.work = Work::Refused;
                        node.diagnostics
                            .push((reason_for(failure), Location::Unavailable));
                        break;
                    }
                    Err(Refusal::Session(failure)) => return Err(failure),
                }
            }
        }
        Ok(())
    }

    fn seed_sources(&mut self, prior: &Resolution) -> Result<()> {
        for source in &prior.external_sources {
            require(
                (self.sources.len() as u64) < self.limits.sources,
                Failure::Limit,
            )?;
            self.sources.insert(
                SourceKey {
                    reference: source.reference.clone(),
                    platform: source.platform.clone(),
                },
                SourceWork {
                    root: Some(source.root.clone()),
                    registry: source.registry.clone(),
                    inspect: None,
                    fetch: None,
                },
            );
        }
        Ok(())
    }

    fn recheck_prior(
        &mut self,
        prior: &Resolution,
        material: &Material,
        driver: &mut dyn Driver,
    ) -> Result<Rechecked> {
        let unavailable = |subject| Diagnostic {
            subject,
            reason: "stale",
            location: Location::Unavailable,
            cycle: Vec::new(),
        };
        let mut stale = Vec::new();
        let mut verified = vec![false; material.closures.len()];
        for (index, closure) in material.closures.iter().enumerate() {
            driver.check()?;
            let ordinal = prior
                .external_sources
                .iter()
                .position(|s| {
                    s.reference == closure.source.reference && s.platform == closure.source.platform
                })
                .ok_or(Failure::Integrity)?;
            let stage = self.stage("recheck");
            let source = self
                .sources
                .get(&closure.source)
                .ok_or(Failure::Integrity)?;
            let root = source.root.clone().ok_or(Failure::Integrity)?;
            let registry = source.registry.clone();
            let bound = closure_bound(
                self.catalogs,
                &closure.source,
                &root,
                registry.as_deref(),
                closure,
            );
            match verdict(driver.recheck(&stage, &closure.output))? {
                Verdict::Verified if bound => verified[index] = true,
                Verdict::Missing if closure.kind == ClosureKind::Inspect => {
                    match self.acquire(&closure.source, driver) {
                        Ok(()) => {}
                        Err(Refusal::Session(
                            failure @ (Failure::Cancellation
                            | Failure::Timeout
                            | Failure::Capacity
                            | Failure::Limit
                            | Failure::Storage),
                        )) => return Err(failure),
                        Err(Refusal::Node(_) | Refusal::Session(_)) => {
                            stale.push(unavailable(Subject::Source(ordinal as u64)));
                            return Ok(Rechecked::new(stale, verified));
                        }
                    }
                    let replacement = self
                        .sources
                        .get(&closure.source)
                        .and_then(|s| s.inspect.as_ref())
                        .ok_or(Failure::Integrity)?;
                    if !closure_bound(
                        self.catalogs,
                        &closure.source,
                        &root,
                        registry.as_deref(),
                        replacement,
                    ) {
                        stale.push(unavailable(Subject::Source(ordinal as u64)));
                        return Ok(Rechecked::new(stale, verified));
                    }
                }
                Verdict::Missing => {}
                Verdict::Verified | Verdict::Changed => {
                    stale.push(unavailable(Subject::Source(ordinal as u64)))
                }
            }
        }
        for (key, output) in &material.producer_outputs {
            driver.check()?;
            let ordinal = prior
                .nodes
                .iter()
                .position(|n| n.producer == key.producer && n.platform == key.platform)
                .ok_or(Failure::Integrity)?;
            let stage = self.stage("recheck");
            match verdict(driver.recheck(&stage, output))? {
                Verdict::Verified => {}
                Verdict::Missing | Verdict::Changed => {
                    stale.push(unavailable(Subject::Node(ordinal as u64)))
                }
            }
        }
        Ok(Rechecked::new(stale, verified))
    }

    fn seed(&mut self, prior: Resolution, material: Material, verified: &[bool]) -> Result<()> {
        let Material {
            outcomes,
            associations,
            closures,
            producer_outputs,
            ..
        } = material;
        require(verified.len() == closures.len(), Failure::Integrity)?;
        for (closure, verified) in closures.into_iter().zip(verified.iter().copied()) {
            if !verified {
                continue;
            }
            let source = self
                .sources
                .get_mut(&closure.source)
                .ok_or(Failure::Integrity)?;
            require(
                source.root.as_ref() == Some(closure.output.root()),
                Failure::Integrity,
            )?;
            let slot = match closure.kind {
                ClosureKind::Inspect => &mut source.inspect,
                ClosureKind::Fetch => &mut source.fetch,
            };
            require(slot.replace(closure).is_none(), Failure::Integrity)?;
        }
        for (key, output) in producer_outputs {
            self.producer_outputs.entry(key).or_insert(output);
        }
        let node_keys: Vec<NodeKey> = prior
            .nodes
            .iter()
            .map(|n| NodeKey {
                producer: n.producer.clone(),
                platform: n.platform.clone(),
            })
            .collect();
        let source_keys: Vec<SourceKey> = prior
            .external_sources
            .iter()
            .map(|s| SourceKey {
                reference: s.reference.clone(),
                platform: s.platform.clone(),
            })
            .collect();
        for (ordinal, node) in prior.nodes.iter().enumerate() {
            let key = node_keys[ordinal].clone();
            self.ensure_node(key.clone())?;
            let work = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
            work.resolution_id = node.resolution_id.clone();
            for edge in prior.edges.iter().filter(|e| e.source == ordinal as u64) {
                let target = match edge.target {
                    Target::Node(n) => EdgeTarget::Node(
                        node_keys
                            .get(n as usize)
                            .cloned()
                            .ok_or(Failure::Integrity)?,
                    ),
                    Target::Source(n) => EdgeTarget::Source(
                        source_keys
                            .get(n as usize)
                            .cloned()
                            .ok_or(Failure::Integrity)?,
                    ),
                };
                work.edges.push(EdgeWork {
                    target,
                    role: edge.role,
                    instruction: edge.instruction,
                    tag_origin: edge.tag_origin,
                    location: edge.location.clone(),
                });
            }
        }
        for (key, outcome) in outcomes {
            let association = associations.get(&key).ok_or(Failure::Integrity)?;
            let work = self.nodes.get_mut(&key).ok_or(Failure::Integrity)?;
            require(
                outcome.has_private_material()
                    && Some(outcome.resolution_id()) == work.resolution_id.as_deref()
                    && association
                        .sources
                        .iter()
                        .all(|s| self.sources.contains_key(s))
                    && association
                        .producers
                        .keys()
                        .all(|p| self.producer_outputs.contains_key(p)),
                Failure::Integrity,
            )?;
            work.sources = association.sources.clone();
            work.producers = association.producers.clone();
            self.outcomes.insert(key, outcome);
        }
        Ok(())
    }

    fn project(self) -> Result<(Resolution, Material)> {
        let node_ordinals: BTreeMap<&NodeKey, u64> = self
            .nodes
            .keys()
            .enumerate()
            .map(|(i, k)| (k, i as u64))
            .collect();
        let mut external_sources = Vec::new();
        let mut source_ordinals = BTreeMap::new();
        for (key, source) in &self.sources {
            let Some(root) = &source.root else {
                continue;
            };
            source_ordinals.insert(key, external_sources.len() as u64);
            external_sources.push(ExternalSource {
                reference: key.reference.clone(),
                platform: key.platform.clone(),
                root: root.clone(),
                registry: source.registry.clone(),
                staging: if source.fetch.is_some() {
                    Staging::Content
                } else {
                    Staging::Metadata
                },
            });
        }
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut diagnostics = Vec::new();
        for (ordinal, node) in self.nodes.values().enumerate() {
            let ordinal = ordinal as u64;
            let state = match &node.work {
                Work::Open => return Err(Failure::Integrity),
                Work::Complete => State::Complete,
                Work::Pending(awaited) => State::Pending(
                    awaited
                        .iter()
                        .map(|k| node_ordinals.get(k).copied().ok_or(Failure::Integrity))
                        .collect::<Result<_>>()?,
                ),
                Work::Invalid => State::Invalid,
                Work::Unsupported => State::Unsupported,
                Work::Refused => State::Refused,
                Work::Exhausted => State::Exhausted,
            };
            nodes.push(Node {
                producer: node.key.producer.clone(),
                platform: node.key.platform.clone(),
                path: node.path.clone(),
                snapshot_size: node.size,
                snapshot_digest: node.digest.clone(),
                resolution_id: node.resolution_id.clone(),
                state,
            });
            for edge in &node.edges {
                let target = match &edge.target {
                    EdgeTarget::Node(k) => {
                        Target::Node(*node_ordinals.get(k).ok_or(Failure::Integrity)?)
                    }
                    EdgeTarget::Source(k) => {
                        Target::Source(*source_ordinals.get(k).ok_or(Failure::Integrity)?)
                    }
                };
                edges.push(Edge {
                    source: ordinal,
                    target,
                    role: edge.role,
                    instruction: edge.instruction,
                    tag_origin: edge.tag_origin,
                    location: edge.location.clone(),
                });
            }
            for (reason, location) in &node.diagnostics {
                diagnostics.push(Diagnostic {
                    subject: Subject::Node(ordinal),
                    reason,
                    location: location.clone(),
                    cycle: Vec::new(),
                });
            }
        }
        let mut resolution = Resolution {
            request: self.request,
            catalog_id: self.catalog_id,
            nodes,
            edges,
            external_sources,
            diagnostics,
            complete: false,
            graph_id: String::new(),
        };
        identity::canonical(&mut resolution)?;
        require(
            resolution.edges.len() as u64 <= self.limits.edges,
            Failure::Limit,
        )?;
        for cycle in cycles(&resolution, self.limits.diagnostics as usize)? {
            require(
                cycle.len() as u64 <= self.limits.cycle_edges,
                Failure::Limit,
            )?;
            let first = &resolution.edges[cycle[0] as usize];
            resolution.diagnostics.push(Diagnostic {
                subject: Subject::Node(first.source),
                reason: "cycle",
                location: first.location.clone(),
                cycle,
            });
        }
        identity::canonical(&mut resolution)?;
        require(
            resolution.diagnostics.len() as u64 <= self.limits.diagnostics,
            Failure::Limit,
        )?;
        resolution.complete = resolution.diagnostics.is_empty()
            && resolution.nodes.iter().all(|n| n.state == State::Complete);
        resolution.graph_id = identity::graph_id(&resolution)?;
        let mut material = Material::new(self.registries);
        for (key, outcome) in self.outcomes {
            let node = self.nodes.get(&key).ok_or(Failure::Integrity)?;
            material.associations.insert(
                key.clone(),
                Associations {
                    sources: node.sources.clone(),
                    producers: node.producers.clone(),
                },
            );
            material.outcomes.insert(key, outcome);
        }
        material.producer_outputs = self.producer_outputs;
        for (_, source) in self.sources {
            material.closures.extend(source.inspect);
            material.closures.extend(source.fetch);
        }
        Ok((resolution, material))
    }
}

pub(crate) fn cycles(resolution: &Resolution, limit: usize) -> Result<Vec<Vec<u64>>> {
    let n = resolution.nodes.len();
    let mut hops: BTreeMap<(usize, usize), Vec<u64>> = BTreeMap::new();
    let mut adjacency = vec![BTreeSet::new(); n];
    for (ordinal, edge) in resolution.edges.iter().enumerate() {
        if let Target::Node(target) = edge.target {
            let (a, b) = (edge.source as usize, target as usize);
            require(a < n && b < n, Failure::Integrity)?;
            adjacency[a].insert(b);
            hops.entry((a, b)).or_default().push(ordinal as u64);
        }
    }
    let mut reverse = vec![BTreeSet::new(); n];
    for (v, successors) in adjacency.iter().enumerate() {
        for w in successors {
            reverse[*w].insert(v);
        }
    }
    let mut result = Vec::new();
    for start in 0..n {
        let component = strongly_connected(start, &adjacency, &reverse);
        let mut search = Search {
            adjacency: &adjacency,
            component: &component,
            blocked: vec![false; n],
            blocks: vec![BTreeSet::new(); n],
            stack: Vec::new(),
            found: Vec::new(),
            remaining: limit.checked_sub(result.len()).ok_or(Failure::Limit)?,
        };
        search.circuit(start, start)?;
        for vertices in search.found {
            let mut sequence = Vec::new();
            for i in 0..vertices.len() {
                let hop = (vertices[i], vertices[(i + 1) % vertices.len()]);
                sequence.push(hops.get(&hop).cloned().ok_or(Failure::Integrity)?);
            }
            let lowest = sequence
                .iter()
                .enumerate()
                .min_by_key(|(_, edges)| edges[0])
                .map(|(i, _)| i)
                .ok_or(Failure::Integrity)?;
            sequence.rotate_left(lowest);
            result.push(sequence.into_iter().flatten().collect());
        }
    }
    Ok(result)
}

fn strongly_connected(
    start: usize,
    adjacency: &[BTreeSet<usize>],
    reverse: &[BTreeSet<usize>],
) -> BTreeSet<usize> {
    let forward = reach(start, adjacency);
    let backward = reach(start, reverse);
    forward.intersection(&backward).copied().collect()
}

fn reach(start: usize, next: &[BTreeSet<usize>]) -> BTreeSet<usize> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![start];
    while let Some(v) = pending.pop() {
        if v < start || !seen.insert(v) {
            continue;
        }
        pending.extend(next[v].iter().copied().filter(|w| *w >= start));
    }
    seen
}

struct Search<'a> {
    adjacency: &'a [BTreeSet<usize>],
    component: &'a BTreeSet<usize>,
    blocked: Vec<bool>,
    blocks: Vec<BTreeSet<usize>>,
    stack: Vec<usize>,
    found: Vec<Vec<usize>>,
    remaining: usize,
}

impl Search<'_> {
    fn circuit(&mut self, v: usize, start: usize) -> Result<bool> {
        let mut found = false;
        self.stack.push(v);
        self.blocked[v] = true;
        let successors: Vec<_> = self.adjacency[v]
            .iter()
            .copied()
            .filter(|w| self.component.contains(w))
            .collect();
        for w in &successors {
            if *w == start {
                require(self.found.len() < self.remaining, Failure::Limit)?;
                self.found.push(self.stack.clone());
                found = true;
            } else if !self.blocked[*w] && self.circuit(*w, start)? {
                found = true;
            }
        }
        if found {
            self.unblock(v);
        } else {
            for w in successors {
                self.blocks[w].insert(v);
            }
        }
        self.stack.pop();
        Ok(found)
    }
    fn unblock(&mut self, u: usize) {
        self.blocked[u] = false;
        let pending: Vec<_> = std::mem::take(&mut self.blocks[u]).into_iter().collect();
        for w in pending {
            if self.blocked[w] {
                self.unblock(w);
            }
        }
    }
}

pub(crate) fn resolve(inputs: Inputs<'_>, driver: &mut dyn Driver) -> Result<Resolved> {
    inputs.limits.validate()?;
    let mut engine = Engine::new(&inputs);
    let Inputs {
        request,
        producer_outputs,
        prior,
        catalog_id,
        registries,
        ..
    } = inputs;
    engine.producer_outputs = producer_outputs;
    if let Some((prior_resolution, prior_material)) = prior {
        require(
            prior_resolution.request == request
                && prior_material.registries() == registries.as_ref(),
            Failure::Policy,
        )?;
        if prior_resolution.catalog_id != catalog_id {
            return Ok(Resolved::Stale(
                vec![Diagnostic {
                    subject: Subject::Catalogs,
                    reason: "stale",
                    location: Location::Unavailable,
                    cycle: Vec::new(),
                }],
                prior_resolution,
                prior_material,
            ));
        }
        let awaited: BTreeSet<NodeKey> = prior_resolution
            .nodes
            .iter()
            .filter_map(|n| match &n.state {
                State::Pending(awaited) => Some(awaited),
                _ => None,
            })
            .flatten()
            .filter_map(|ordinal| prior_resolution.nodes.get(*ordinal as usize))
            .map(|n| NodeKey {
                producer: n.producer.clone(),
                platform: n.platform.clone(),
            })
            .collect();
        require(
            engine.producer_outputs.keys().all(|k| awaited.contains(k)),
            Failure::Policy,
        )?;
        engine.seed_sources(&prior_resolution)?;
        let rechecked = engine.recheck_prior(&prior_resolution, &prior_material, driver)?;
        if !rechecked.stale.is_empty() {
            return Ok(Resolved::Stale(
                rechecked.stale,
                prior_resolution,
                prior_material,
            ));
        }
        engine.seed(prior_resolution, prior_material, &rechecked.verified)?;
    } else {
        require(engine.producer_outputs.is_empty(), Failure::Policy)?;
    }
    for target in &request.targets {
        let image = engine.catalogs.images.get(target).ok_or(Failure::Policy)?;
        let platforms: Vec<_> = image
            .platforms
            .iter()
            .filter(|p| {
                request
                    .platforms
                    .as_ref()
                    .is_none_or(|subset| subset.contains(*p))
            })
            .cloned()
            .collect();
        require(!platforms.is_empty(), Failure::Policy)?;
        for platform in platforms {
            engine.ensure_node(NodeKey {
                producer: target.clone(),
                platform,
            })?;
        }
    }
    while let Some(key) = engine.queue.pop_front() {
        engine.process(key, driver)?;
    }
    if request.staging == Staging::Content {
        engine.stage_content(driver)?;
    }
    driver.check()?;
    let (resolution, material) = engine.project()?;
    Ok(Resolved::Graph(resolution, material))
}

fn closure_bound(
    catalogs: &SelectedCatalogs<'_>,
    source: &SourceKey,
    root: &Descriptor,
    registry: Option<&str>,
    closure: &Closure,
) -> bool {
    let Some(reference) = ImageReference::parse(&source.reference) else {
        return false;
    };
    let policy = catalogs
        .registry_policy(
            &reference,
            broil_core::images::RegistryPurpose::Metadata,
            None,
        )
        .ok();
    policy.as_ref().is_some_and(|p| {
        p.endpoint.supplied == closure.endpoint && p.registry.as_deref() == registry
    }) && closure.output.root() == root
        && closure.repository == reference.repository
        && (closure.reference == source.reference
            || closure.reference == format!("{}@{}", reference.repository, root.digest))
}

pub(crate) fn recheck(
    resolution: &Resolution,
    material: &Material,
    catalogs: &SelectedCatalogs<'_>,
    root: &Path,
    catalog_id: &str,
    limits: &Limits,
    driver: &mut dyn Driver,
) -> Result<Vec<Diagnostic>> {
    let mut stale = Vec::new();
    let unavailable = |subject| Diagnostic {
        subject,
        reason: "stale",
        location: Location::Unavailable,
        cycle: Vec::new(),
    };
    if resolution.catalog_id != catalog_id {
        stale.push(unavailable(Subject::Catalogs));
    }
    let mut fresh = resolution.clone();
    for (ordinal, node) in fresh.nodes.iter_mut().enumerate() {
        driver.check()?;
        let path = PathBuf::from(&node.path);
        let path = if path.is_absolute() {
            path
        } else {
            root.join(path)
        };
        match driver.snapshot(&path, limits.snapshot_bytes as usize) {
            Ok(bytes)
                if bytes.size == node.snapshot_size && bytes.digest == node.snapshot_digest => {}
            Ok(bytes) => {
                node.snapshot_size = bytes.size;
                node.snapshot_digest = bytes.digest;
                stale.push(unavailable(Subject::Node(ordinal as u64)));
            }
            Err(Refusal::Node(_)) => stale.push(unavailable(Subject::Node(ordinal as u64))),
            Err(Refusal::Session(failure)) => return Err(failure),
        }
    }
    let mut stage = 0u64;
    for closure in &material.closures {
        driver.check()?;
        stage += 1;
        let ordinal = resolution
            .external_sources
            .iter()
            .position(|s| {
                s.reference == closure.source.reference && s.platform == closure.source.platform
            })
            .ok_or(Failure::Integrity)?;
        let source = &resolution.external_sources[ordinal];
        let checked = closure_bound(
            catalogs,
            &closure.source,
            &source.root,
            source.registry.as_deref(),
            closure,
        );
        match verdict(driver.recheck(&format!("graph-recheck-{stage}"), &closure.output))? {
            Verdict::Verified if checked => {}
            _ => stale.push(unavailable(Subject::Source(ordinal as u64))),
        }
    }
    for (key, output) in &material.producer_outputs {
        driver.check()?;
        stage += 1;
        let ordinal = resolution
            .nodes
            .iter()
            .position(|n| n.producer == key.producer && n.platform == key.platform)
            .ok_or(Failure::Integrity)?;
        match verdict(driver.recheck(&format!("graph-recheck-{stage}"), output))? {
            Verdict::Verified => {}
            _ => stale.push(unavailable(Subject::Node(ordinal as u64))),
        }
    }
    if stale.is_empty() {
        fresh.catalog_id = catalog_id.into();
        fresh.graph_id = String::new();
        if identity::graph_id(&fresh)? != resolution.graph_id {
            stale.push(unavailable(Subject::Catalogs));
        }
    }
    stale.sort_by(identity::cmp_diagnostic);
    stale.dedup();
    Ok(stale)
}
