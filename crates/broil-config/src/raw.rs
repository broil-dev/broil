// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use broil_core::error::ConfigError;
use saphyr::{LoadableYamlNode, Scalar, Yaml};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RawValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<RawValue>),
    Map(Vec<(RawValue, RawValue)>),
}

impl RawValue {
    pub(crate) fn get(&self, key: &str) -> Option<&RawValue> {
        match self {
            RawValue::Map(pairs) => pairs.iter().find_map(|(k, v)| match k {
                RawValue::Str(name) if name == key => Some(v),
                _ => None,
            }),
            _ => None,
        }
    }
}

pub(crate) fn parse_str(content: &str, path: &Path) -> Result<Option<RawValue>, ConfigError> {
    let documents = Yaml::load_from_str(content).map_err(|error| ConfigError::YamlParse {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    match documents.len() {
        0 => Ok(None),
        1 => from_yaml(&documents[0], path).map(Some),
        _ => Err(ConfigError::YamlParse {
            path: path.to_path_buf(),
            message: "multiple YAML documents in one stream".to_string(),
        }),
    }
}

fn parse_error(path: &Path, message: String) -> ConfigError {
    ConfigError::YamlParse {
        path: path.to_path_buf(),
        message,
    }
}

fn from_yaml(node: &Yaml<'_>, path: &Path) -> Result<RawValue, ConfigError> {
    match node {
        Yaml::Value(Scalar::Null) => Ok(RawValue::Null),
        Yaml::Value(Scalar::Boolean(value)) => Ok(RawValue::Bool(*value)),
        Yaml::Value(Scalar::Integer(value)) => Ok(RawValue::Int(*value)),
        Yaml::Value(Scalar::FloatingPoint(value)) => Ok(RawValue::Float(value.into_inner())),
        Yaml::Value(Scalar::String(value)) => Ok(RawValue::Str(value.to_string())),
        Yaml::Sequence(items) => {
            let mut converted = Vec::with_capacity(items.len());
            for item in items {
                converted.push(from_yaml(item, path)?);
            }
            Ok(RawValue::Seq(converted))
        }
        Yaml::Mapping(mapping) => {
            let mut pairs = Vec::with_capacity(mapping.len());
            for (key, value) in mapping {
                pairs.push((from_yaml(key, path)?, from_yaml(value, path)?));
            }
            Ok(RawValue::Map(pairs))
        }
        Yaml::Tagged(tag, _) => Err(parse_error(path, format!("unsupported tag {tag}"))),
        Yaml::Alias(_) => Err(parse_error(path, "unresolved YAML alias".to_string())),
        Yaml::BadValue => Err(parse_error(path, "invalid YAML value".to_string())),
        Yaml::Representation(..) => Err(parse_error(
            path,
            "unresolved YAML representation".to_string(),
        )),
    }
}
