// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Typed Broil config model produced by schema validation.
//!
//! Maps are `BTreeMap`s: UTF-8 byte order equals Unicode-scalar-value
//! order, which is the sorted-key order that `get` needs for its
//! output. Absent and null optional sections are materialized as empty
//! maps at both the root and per-environment levels.

use std::collections::BTreeMap;

use crate::remote::{EnvironmentRemoteConfig, RemoteConfig};

/// A normalized validated configuration value exposed by `get cfg`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigValue {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Sequence(Vec<ConfigValue>),
    Mapping(BTreeMap<String, ConfigValue>),
}

impl Default for ConfigValue {
    fn default() -> Self {
        Self::Mapping(BTreeMap::new())
    }
}

/// The validated Broil config.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BroilConfig {
    pub tools: crate::images::ToolsDefinition,
    pub images: BTreeMap<String, crate::images::ImageDefinition>,
    pub builders: BTreeMap<String, crate::images::BuilderDefinition>,
    pub registries: BTreeMap<String, crate::images::RegistryDefinition>,
    pub aliases: BTreeMap<String, AliasNode>,
    pub scripts: BTreeMap<String, String>,
    pub env_vars: BTreeMap<String, String>,
    pub environments: BTreeMap<String, EnvironmentConfig>,
    pub remote: RemoteConfig,
    pub secrets: crate::secrets::SecretsConfig,
    pub normalized: ConfigValue,
}

/// One validated `environments.<name>` mapping.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvironmentConfig {
    pub k3s: BTreeMap<String, crate::k3s::Target>,
    pub applications: BTreeMap<String, crate::applications::Application>,
    pub tools: crate::images::ToolsDefinition,
    pub images: BTreeMap<String, crate::images::ImageDefinition>,
    pub builders: BTreeMap<String, crate::images::BuilderDefinition>,
    pub registries: BTreeMap<String, crate::images::RegistryDefinition>,
    pub aliases: BTreeMap<String, AliasNode>,
    pub scripts: BTreeMap<String, String>,
    pub env_vars: BTreeMap<String, String>,
    pub remote: EnvironmentRemoteConfig,
    pub secrets: crate::secrets::SecretsConfig,
}

/// One entry in a validated alias map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasNode {
    /// An alias leaf: the raw command body plus its validated tokens.
    Leaf { raw: String, tokens: Vec<String> },
    /// A non-empty alias group.
    Group(BTreeMap<String, AliasNode>),
}
