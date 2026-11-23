// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

mod discovery;
mod extends;
mod fragments;
pub mod images;
pub mod k3s;
mod raw;
mod remote;
mod validate;

use std::fs;
use std::io;
use std::path::PathBuf;

use broil_core::error::ConfigError;
use broil_core::model::BroilConfig;

use crate::raw::RawValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadMode {
    Discover { cwd: PathBuf },
    ExplicitFile { path: PathBuf, cwd: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedProject {
    pub broil_root: PathBuf,
    pub config: BroilConfig,
}

pub fn load(mode: &LoadMode) -> Result<LoadedProject, ConfigError> {
    let selection = match mode {
        LoadMode::Discover { cwd } => discovery::discover(cwd)?,
        LoadMode::ExplicitFile { path, cwd } => discovery::select_file(path, cwd)?,
    };
    let content = fs::read_to_string(&selection.file).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidData {
            return ConfigError::YamlParse {
                path: selection.file.clone(),
                message: "config file is not valid UTF-8".to_string(),
            };
        }
        match mode {
            LoadMode::Discover { .. } => ConfigError::DefaultNotReadableRegularFile {
                path: selection.file.clone(),
            },
            LoadMode::ExplicitFile { .. } => ConfigError::ExplicitFileUnreadable {
                path: selection.file.clone(),
            },
        }
    })?;
    let mut root = match raw::parse_str(&content, &selection.file)? {
        None | Some(RawValue::Null) => RawValue::Map(Vec::new()),
        Some(map @ RawValue::Map(_)) => map,
        Some(_) => {
            return Err(ConfigError::NonMappingRoot {
                path: selection.file.clone(),
            });
        }
    };
    fragments::merge_fragments(&mut root, &selection.broil_root)?;
    let resolved = extends::resolve_root(&root)?;
    let config = validate::validate(&resolved)?;
    Ok(LoadedProject {
        broil_root: selection.broil_root,
        config,
    })
}

mod secrets;
