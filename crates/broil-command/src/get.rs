// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use broil_core::error::GetError;
use broil_core::model::{BroilConfig, ConfigValue};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Plain,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Root,
    Name,
    Cfg {
        dot_path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub mode: OutputMode,
    pub selector: Selector,
}

pub fn execute(
    broil_root: &Path,
    config: &BroilConfig,
    request: &Request,
) -> Result<Vec<u8>, GetError> {
    match &request.selector {
        Selector::Root => {
            let root = broil_root.to_str().ok_or(GetError::NonUtf8Path)?;
            Ok(render_string(root, request.mode))
        }
        Selector::Name => {
            let name = match broil_root.file_name() {
                None => "/",
                Some(name) => name.to_str().ok_or(GetError::NonUtf8Path)?,
            };
            Ok(render_string(name, request.mode))
        }
        Selector::Cfg { dot_path } => Ok(match resolve(config, dot_path)? {
            ConfigValue::String(text) => render_string(text, request.mode),
            value => render_json(&to_json(value)),
        }),
    }
}

fn resolve<'a>(config: &'a BroilConfig, dot_path: &str) -> Result<&'a ConfigValue, GetError> {
    let segments: Vec<&str> = dot_path.split('.').collect();
    let mut current = &config.normalized;
    for (index, segment) in segments.iter().enumerate() {
        let ConfigValue::Mapping(map) = current else {
            return Err(GetError::NonMappingTraversal {
                prefix: segments[..index].join("."),
            });
        };
        current = map.get(*segment).ok_or_else(|| GetError::MissingPath {
            dot_path: dot_path.to_string(),
        })?;
    }
    Ok(current)
}

fn to_json(value: &ConfigValue) -> Value {
    match value {
        ConfigValue::Null => Value::Null,
        ConfigValue::Bool(value) => Value::Bool(*value),
        ConfigValue::Integer(value) => Value::Number((*value).into()),
        ConfigValue::String(value) => Value::String(value.clone()),
        ConfigValue::Sequence(values) => Value::Array(values.iter().map(to_json).collect()),
        ConfigValue::Mapping(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), to_json(value)))
                .collect(),
        ),
    }
}

fn render_string(value: &str, mode: OutputMode) -> Vec<u8> {
    let mut bytes = match mode {
        OutputMode::Plain => value.as_bytes().to_vec(),
        OutputMode::Json => json_bytes(&Value::String(value.to_string())),
    };
    bytes.push(b'\n');
    bytes
}

fn render_json(value: &Value) -> Vec<u8> {
    let mut bytes = json_bytes(value);
    bytes.push(b'\n');
    bytes
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_string(value)
        .expect("string-and-mapping trees always serialize")
        .into_bytes()
}
