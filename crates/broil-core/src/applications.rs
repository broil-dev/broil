// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Environment-owned application declarations. These
//! types hold paths and references, never manifest bytes or secret values.

use std::collections::BTreeMap;

use crate::images::SecretReference;
use crate::remote::DurationValue;

/// One `environments.<env>.applications.<name>` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Application {
    pub target: String,
    pub namespace: String,
    pub source: ManifestSource,
    pub delivery_nodes: DeliveryNodes,
    /// `health.timeout`, default `10m`.
    pub health_timeout: DurationValue,
    pub before_apply: Vec<Hook>,
    pub health: Vec<Hook>,
    /// Secrets in declaration order, each with its data keys in declaration order.
    pub secrets: Vec<ApplicationSecret>,
}

/// Exactly one of `manifests` and `render`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestSource {
    /// `BROIL_ROOT`-relative paths in declaration order.
    Manifests(Vec<String>),
    /// The render hook: always `controller`, without name, repeatable or secrets.
    Render(Hook),
}

/// `delivery.nodes`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DeliveryNodes {
    #[default]
    All,
    /// Distinct declared members of the target, in declaration order.
    Members(Vec<String>),
    /// Pairs matched against the members' declared labels.
    Labels(BTreeMap<String, String>),
}

/// One declared hook. `name` is empty for `render`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hook {
    pub name: String,
    pub location: HookLocation,
    pub argv: Vec<String>,
    pub timeout: DurationValue,
    pub repeatable: bool,
    /// Controller-only variables in declaration order.
    pub secrets: Vec<(String, SecretReference)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookLocation {
    Controller,
    /// A machine of the environment-owned `remote.machines` inventory.
    Machine(String),
}

/// One declared Kubernetes Secret and its data keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationSecret {
    pub name: String,
    pub keys: Vec<(String, SecretReference)>,
}
