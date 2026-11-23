// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Public image catalog declarations. These types contain references, never acquired secrets.

pub mod reference;

use std::collections::BTreeMap;

use reference::{Endpoint, ImageReference};

/// Explicit executable paths. Loading and selection never access the installation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ToolsDefinition {
    pub filesystem_helper: Option<String>,
    pub registry: Option<String>,
    pub analyzer: Option<String>,
    pub docker: Option<String>,
    pub buildx: Option<String>,
    pub buildctl: Option<String>,
}

impl ToolsDefinition {
    pub fn overlay(&self, selected: &Self) -> Self {
        Self {
            filesystem_helper: selected
                .filesystem_helper
                .clone()
                .or_else(|| self.filesystem_helper.clone()),
            registry: selected.registry.clone().or_else(|| self.registry.clone()),
            analyzer: selected.analyzer.clone().or_else(|| self.analyzer.clone()),
            docker: selected.docker.clone().or_else(|| self.docker.clone()),
            buildx: selected.buildx.clone().or_else(|| self.buildx.clone()),
            buildctl: selected.buildctl.clone().or_else(|| self.buildctl.clone()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretReference {
    pub set: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageDefinition {
    pub image: ImageReference,
    pub builder: String,
    pub registry: Option<String>,
    pub context: Option<String>,
    pub dockerfile: Option<String>,
    pub stage: Option<String>,
    pub contexts: BTreeMap<String, String>,
    pub args: BTreeMap<String, String>,
    pub platforms: Option<Vec<String>>,
    pub output: OutputConfig,
    pub cache: CacheConfig,
    pub secrets: BTreeMap<String, SecretReference>,
    pub ssh: BTreeMap<String, String>,
    pub entitlements: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputKind {
    #[default]
    Registry,
    OciArchive,
    OciLayout,
    DockerLoad,
    CacheOnly,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputConfig {
    pub kind: Option<OutputKind>,
    pub path: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CacheConfig {
    pub builder: Option<bool>,
    pub read: Vec<CacheLocation>,
    pub write: Option<CacheLocation>,
    pub refresh: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheLocation {
    pub registry: String,
    pub reference: ImageReference,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuilderDefinition {
    pub kind: BuilderKind,
    pub endpoint: Endpoint,
    pub tls: ClientTls,
    pub machine: Option<String>,
    pub privilege: Option<String>,
    pub server_tls: Option<ServerTls>,
    pub lifecycle_script: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuilderKind {
    Managed,
    External,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientTls {
    pub ca: String,
    pub certificate: SecretReference,
    pub key: SecretReference,
    pub server_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerTls {
    pub certificate: SecretReference,
    pub key: SecretReference,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryDefinition {
    pub endpoint: Endpoint,
    pub development_http: Option<bool>,
    pub ca: Option<String>,
    pub auth: BTreeMap<RegistryPurpose, RegistryAuth>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistryPurpose {
    Metadata,
    Pull,
    CacheRead,
    CacheWrite,
    Push,
}

impl RegistryPurpose {
    pub fn name(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Pull => "pull",
            Self::CacheRead => "cache_read",
            Self::CacheWrite => "cache_write",
            Self::Push => "push",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "metadata" => Self::Metadata,
            "pull" => Self::Pull,
            "cache_read" => Self::CacheRead,
            "cache_write" => Self::CacheWrite,
            "push" => Self::Push,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryAuth {
    pub repositories: Vec<String>,
    pub credential: RegistryCredential,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryCredential {
    Token(SecretReference),
    Password {
        username: String,
        password: SecretReference,
        token_service: Option<TokenService>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenService {
    pub realm: Endpoint,
    pub service: String,
}

pub fn valid_name(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

pub fn valid_platform(value: &str) -> bool {
    let parts: Vec<_> = value.split('/').collect();
    (2..=3).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.-".contains(&c))
        })
}

pub fn valid_local_context(value: &str) -> bool {
    !value.is_empty()
        && value != "-"
        && !value.contains('\0')
        && !value.contains("://")
        && !value.starts_with("git@")
}
