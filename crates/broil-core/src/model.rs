// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::remote::{EnvironmentRemoteConfig, RemoteConfig};

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BroilConfig {
    pub aliases: BTreeMap<String, AliasNode>,
    pub scripts: BTreeMap<String, String>,
    pub env_vars: BTreeMap<String, String>,
    pub environments: BTreeMap<String, EnvironmentConfig>,
    pub remote: RemoteConfig,
    pub normalized: ConfigValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvironmentConfig {
    pub aliases: BTreeMap<String, AliasNode>,
    pub scripts: BTreeMap<String, String>,
    pub env_vars: BTreeMap<String, String>,
    pub remote: EnvironmentRemoteConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasNode {
    Leaf { raw: String, tokens: Vec<String> },
    Group(BTreeMap<String, AliasNode>),
}
