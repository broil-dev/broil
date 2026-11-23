// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Fixed public copy identities. This input deliberately excludes the worker's own hash.

use super::common::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Tool {
    Docker,
    Buildx,
    Buildctl,
    Registry,
    Analyzer,
}

impl Tool {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Buildx => "buildx",
            Self::Buildctl => "buildctl",
            Self::Registry => "registry",
            Self::Analyzer => "analyzer",
        }
    }
    #[allow(dead_code)] // The filesystem binary parses copy-tool jobs.
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "docker" => Ok(Self::Docker),
            "buildx" => Ok(Self::Buildx),
            "buildctl" => Ok(Self::Buildctl),
            "registry" => Ok(Self::Registry),
            "analyzer" => Ok(Self::Analyzer),
            _ => Err(Failure::Policy),
        }
    }
    pub(crate) fn identity(self) -> Result<(String, u64)> {
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tools/image-client/public-tools.json"
        ))
        .map_err(|_| Failure::Policy)?;
        let value = &manifest["tools"][self.name()];
        let digest = value["sha256"].as_str().ok_or(Failure::Policy)?;
        let size = value["size"].as_u64().ok_or(Failure::Policy)?;
        require(
            size > 0 && digest.len() == 64 && hex(digest.as_bytes()),
            Failure::Policy,
        )?;
        Ok((format!("sha256:{digest}"), size))
    }
}
