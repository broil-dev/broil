// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod identity;
mod resolve;

use super::{
    Descriptor, VerifiedOutput,
    analysis::{Instruction, Location, Outcome, Role, TagOrigin},
    common::*,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) use identity::{Hasher, catalog_id};
pub(crate) use resolve::{
    Associations, Closure, ClosureKind, Driver, Inputs, NodeKey, Refusal, Resolved, Retained,
    SourceKey, read_chain, recheck, resolve,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Staging {
    Metadata,
    Content,
}

impl Staging {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Content => "content",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub environment: Option<String>,
    pub targets: Vec<String>,
    pub platforms: Option<Vec<String>>,
    pub build_platform: String,
    pub staging: Staging,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum State {
    Complete,
    Pending(Vec<u64>),
    Invalid,
    Unsupported,
    Refused,
    Exhausted,
}

impl State {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Pending(_) => "pending",
            Self::Invalid => "invalid",
            Self::Unsupported => "unsupported",
            Self::Refused => "refused",
            Self::Exhausted => "exhausted",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    pub producer: String,
    pub platform: String,
    pub path: String,
    pub snapshot_size: u64,
    pub snapshot_digest: String,
    pub resolution_id: Option<String>,
    pub state: State,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Node(u64),
    Source(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edge {
    pub source: u64,
    pub target: Target,
    pub role: Role,
    pub instruction: Instruction,
    pub tag_origin: TagOrigin,
    pub location: Location,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalSource {
    pub reference: String,
    pub platform: String,
    pub root: Descriptor,
    pub registry: Option<String>,
    pub staging: Staging,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Subject {
    Node(u64),
    Source(u64),
    Catalogs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub subject: Subject,
    pub reason: &'static str,
    pub location: Location,
    pub cycle: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    pub request: Request,
    pub catalog_id: String,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub external_sources: Vec<ExternalSource>,
    pub diagnostics: Vec<Diagnostic>,
    pub complete: bool,
    pub graph_id: String,
}

pub struct Material {
    outcomes: BTreeMap<NodeKey, Outcome>,
    associations: BTreeMap<NodeKey, Associations>,
    closures: Vec<Closure>,
    producer_outputs: BTreeMap<NodeKey, VerifiedOutput>,
    registries: Option<BTreeSet<String>>,
}

impl Material {
    pub(crate) fn new(registries: Option<BTreeSet<String>>) -> Self {
        Self {
            outcomes: BTreeMap::new(),
            associations: BTreeMap::new(),
            closures: Vec::new(),
            producer_outputs: BTreeMap::new(),
            registries,
        }
    }
    pub fn closures(&self) -> impl Iterator<Item = &VerifiedOutput> {
        self.closures.iter().map(|closure| &closure.output)
    }
    pub fn producer_outputs(&self) -> impl Iterator<Item = (&str, &str, &VerifiedOutput)> {
        self.producer_outputs
            .iter()
            .map(|(key, output)| (key.producer.as_str(), key.platform.as_str(), output))
    }
    pub fn complete_nodes(&self) -> usize {
        self.outcomes.len()
    }
    pub fn has_private_material(&self) -> bool {
        self.outcomes.values().any(Outcome::has_private_material)
    }
    pub(crate) fn registries(&self) -> Option<&BTreeSet<String>> {
        self.registries.as_ref()
    }
    pub(crate) fn retain_closures(&mut self) {
        for closure in &mut self.closures {
            closure.output = closure.output.retained();
        }
    }
    pub(crate) fn outcome(&self, key: &NodeKey) -> Option<&Outcome> {
        self.outcomes.get(key)
    }
    pub(crate) fn associations(&self, key: &NodeKey) -> Option<&Associations> {
        self.associations.get(key)
    }
    pub(crate) fn fetch_closure(&self, source: &SourceKey) -> Option<&Closure> {
        self.closures
            .iter()
            .find(|closure| closure.kind == ClosureKind::Fetch && closure.source == *source)
    }
    pub(crate) fn producer_output(&self, key: &NodeKey) -> Option<&VerifiedOutput> {
        self.producer_outputs.get(key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub nodes: u64,
    pub edges: u64,
    pub attempts: u64,
    pub sources: u64,
    pub stages: u64,
    pub diagnostics: u64,
    pub cycle_edges: u64,
    pub snapshot_bytes: u64,
    pub retained_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            nodes: 1024,
            edges: 8192,
            attempts: 64,
            sources: 1024,
            stages: 2048,
            diagnostics: 1024,
            cycle_edges: 1024,
            snapshot_bytes: 1_048_576,
            retained_bytes: 268_435_456,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        let maximum = Self::default();
        for (value, max) in [
            (self.nodes, maximum.nodes),
            (self.edges, maximum.edges),
            (self.attempts, maximum.attempts),
            (self.sources, maximum.sources),
            (self.stages, maximum.stages),
            (self.diagnostics, maximum.diagnostics),
            (self.cycle_edges, maximum.cycle_edges),
            (self.snapshot_bytes, maximum.snapshot_bytes),
            (self.retained_bytes, maximum.retained_bytes),
        ] {
            require(value > 0 && value <= max, Failure::Limit)?;
        }
        Ok(())
    }
}

