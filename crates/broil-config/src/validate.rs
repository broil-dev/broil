// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use broil_core::error::{ConfigError, SchemaError};
use broil_core::model::{AliasNode, BroilConfig, ConfigValue, EnvironmentConfig};
use broil_core::segment::is_valid_alias_path_segment;
use broil_core::tokens::tokenize_alias_command;

use crate::raw::RawValue;

const RESERVED_ENV_VARS: [&str; 2] = ["BROIL_ROOT", "BROIL_ENV"];

const PROMPT_OWNED_ENV_VARS: [&str; 3] =
    ["BROIL_PROMPT_NAMES", "BROIL_PS1_BASE", "BROIL_LAST_STATUS"];

pub(crate) fn validate(root: &RawValue) -> Result<BroilConfig, ConfigError> {
    let RawValue::Map(pairs) = root else {
        unreachable!("load ensures a mapping root");
    };
    let mut config = BroilConfig::default();
    for (key, value) in pairs {
        let name = string_key(key, "config root")?;
        match name {
            "aliases" => config.aliases = alias_map(value, "aliases")?,
            "scripts" => config.scripts = script_map(value, "scripts")?,
            "env_vars" => config.env_vars = env_var_map(value, "env_vars")?,
            "environments" => config.environments = environments(value)?,
            "remote" => config.remote = crate::remote::root(value, "remote")?,
            _ => {
                return Err(schema(SchemaError::UnknownKey {
                    key_path: name.to_string(),
                }));
            }
        }
    }
    crate::remote::validate_references_and_routes(&config)?;
    config.normalized = normalized_config(root)?;
    Ok(config)
}

pub(crate) fn schema(error: SchemaError) -> ConfigError {
    ConfigError::Schema(error)
}

pub(crate) fn string_key<'raw>(
    key: &'raw RawValue,
    container: &str,
) -> Result<&'raw str, ConfigError> {
    match key {
        RawValue::Str(name) => Ok(name),
        other => Err(schema(SchemaError::NonStringKey {
            key_path: container.to_string(),
            key_repr: scalar_repr(other),
        })),
    }
}

pub(crate) fn scalar_repr(value: &RawValue) -> String {
    match value {
        RawValue::Null => "null".to_string(),
        RawValue::Bool(value) => value.to_string(),
        RawValue::Int(value) => value.to_string(),
        RawValue::Float(value) => value.to_string(),
        RawValue::Str(value) => value.clone(),
        RawValue::Seq(_) => "sequence".to_string(),
        RawValue::Map(_) => "mapping".to_string(),
    }
}

pub(crate) fn section_pairs<'raw>(
    value: &'raw RawValue,
    key_path: &str,
) -> Result<Option<&'raw [(RawValue, RawValue)]>, ConfigError> {
    match value {
        RawValue::Null => Ok(None),
        RawValue::Map(pairs) => Ok(Some(pairs)),
        _ => Err(schema(SchemaError::NonMappingSection {
            key_path: key_path.to_string(),
        })),
    }
}

fn script_map(value: &RawValue, key_path: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let Some(pairs) = section_pairs(value, key_path)? else {
        return Ok(BTreeMap::new());
    };
    let mut scripts = BTreeMap::new();
    for (key, value) in pairs {
        let name = string_key(key, key_path)?;
        if name.is_empty() {
            return Err(schema(SchemaError::EmptyScriptName {
                key_path: key_path.to_string(),
            }));
        }
        let RawValue::Str(body) = value else {
            return Err(schema(SchemaError::NonStringValue {
                key_path: format!("{key_path}.{name}"),
            }));
        };
        scripts.insert(name.to_string(), body.clone());
    }
    Ok(scripts)
}

fn env_var_map(value: &RawValue, key_path: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let Some(pairs) = section_pairs(value, key_path)? else {
        return Ok(BTreeMap::new());
    };
    let mut env_vars = BTreeMap::new();
    for (key, value) in pairs {
        let name = string_key(key, key_path)?;
        if !is_env_var_name(name) {
            return Err(schema(SchemaError::InvalidEnvVarName {
                key_path: key_path.to_string(),
                name: name.to_string(),
            }));
        }
        if RESERVED_ENV_VARS.contains(&name) {
            return Err(schema(SchemaError::ReservedEnvVarName {
                key_path: key_path.to_string(),
                name: name.to_string(),
            }));
        }
        if PROMPT_OWNED_ENV_VARS.contains(&name) {
            return Err(schema(SchemaError::PromptOwnedEnvVarName {
                key_path: key_path.to_string(),
                name: name.to_string(),
            }));
        }
        let RawValue::Str(body) = value else {
            return Err(schema(SchemaError::NonStringValue {
                key_path: format!("{key_path}.{name}"),
            }));
        };
        env_vars.insert(name.to_string(), body.clone());
    }
    Ok(env_vars)
}

fn is_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn environments(value: &RawValue) -> Result<BTreeMap<String, EnvironmentConfig>, ConfigError> {
    let Some(pairs) = section_pairs(value, "environments")? else {
        return Ok(BTreeMap::new());
    };
    let mut environments = BTreeMap::new();
    for (key, value) in pairs {
        let name = string_key(key, "environments")?;
        if name.is_empty() {
            return Err(schema(SchemaError::EmptyEnvironmentName));
        }
        if name.contains('.') {
            return Err(schema(SchemaError::EnvironmentNameWithDot {
                name: name.to_string(),
            }));
        }
        let env_path = format!("environments.{name}");
        let Some(env_pairs) = section_pairs(value, &env_path)? else {
            environments.insert(name.to_string(), EnvironmentConfig::default());
            continue;
        };
        let mut environment = EnvironmentConfig::default();
        for (env_key, env_value) in env_pairs {
            let section = string_key(env_key, &env_path)?;
            let section_path = format!("{env_path}.{section}");
            match section {
                "aliases" => environment.aliases = alias_map(env_value, &section_path)?,
                "scripts" => environment.scripts = script_map(env_value, &section_path)?,
                "env_vars" => environment.env_vars = env_var_map(env_value, &section_path)?,
                "remote" => {
                    environment.remote = crate::remote::environment(env_value, &section_path)?
                }
                _ => {
                    return Err(schema(SchemaError::UnknownKey {
                        key_path: section_path,
                    }));
                }
            }
        }
        environments.insert(name.to_string(), environment);
    }
    Ok(environments)
}

fn normalized_config(root: &RawValue) -> Result<ConfigValue, ConfigError> {
    let mut value = normalized_value(root, "config root")?;
    let ConfigValue::Mapping(root) = &mut value else {
        unreachable!("load guarantees a mapping root");
    };
    for section in ["aliases", "scripts", "env_vars", "environments"] {
        materialize_mapping(root, section);
    }
    materialize_remote(root, false);
    if let Some(ConfigValue::Mapping(environments)) = root.get_mut("environments") {
        for environment in environments.values_mut() {
            if !matches!(environment, ConfigValue::Mapping(_)) {
                *environment = ConfigValue::Mapping(BTreeMap::new());
            }
            let ConfigValue::Mapping(environment) = environment else {
                unreachable!()
            };
            for section in ["aliases", "scripts", "env_vars"] {
                materialize_mapping(environment, section);
            }
            materialize_remote(environment, true);
        }
    }
    Ok(value)
}

fn materialize_mapping(map: &mut BTreeMap<String, ConfigValue>, name: &str) {
    if !matches!(map.get(name), Some(ConfigValue::Mapping(_))) {
        map.insert(name.to_string(), ConfigValue::Mapping(BTreeMap::new()));
    }
}

fn materialize_remote(map: &mut BTreeMap<String, ConfigValue>, environment: bool) {
    materialize_mapping(map, "remote");
    let Some(ConfigValue::Mapping(remote)) = map.get_mut("remote") else {
        unreachable!();
    };
    for section in [
        "defaults",
        "secret_providers",
        "auth_profiles",
        "privilege_profiles",
        "jump_hosts",
        "scripts",
        "provision_profiles",
    ] {
        materialize_mapping(remote, section);
    }
    materialize_mapping(
        remote,
        if environment {
            "machines"
        } else {
            "machine_templates"
        },
    );
}

fn normalized_value(value: &RawValue, key_path: &str) -> Result<ConfigValue, ConfigError> {
    Ok(match value {
        RawValue::Null => ConfigValue::Null,
        RawValue::Bool(value) => ConfigValue::Bool(*value),
        RawValue::Int(value) => ConfigValue::Integer(*value),
        RawValue::Float(_) => {
            return Err(schema(SchemaError::InvalidRemoteValue {
                key_path: key_path.to_string(),
                expected: "a non-floating-point value".to_string(),
            }));
        }
        RawValue::Str(value) => ConfigValue::String(value.clone()),
        RawValue::Seq(values) => ConfigValue::Sequence(
            values
                .iter()
                .enumerate()
                .map(|(index, value)| normalized_value(value, &format!("{key_path}.{index}")))
                .collect::<Result<_, _>>()?,
        ),
        RawValue::Map(pairs) => {
            let mut map = BTreeMap::new();
            for (key, value) in pairs {
                let name = string_key(key, key_path)?;
                map.insert(
                    name.to_string(),
                    normalized_value(value, &format!("{key_path}.{name}"))?,
                );
            }
            ConfigValue::Mapping(map)
        }
    })
}

fn alias_map(value: &RawValue, key_path: &str) -> Result<BTreeMap<String, AliasNode>, ConfigError> {
    let Some(pairs) = section_pairs(value, key_path)? else {
        return Ok(BTreeMap::new());
    };
    alias_map_pairs(pairs, key_path)
}

fn alias_map_pairs(
    pairs: &[(RawValue, RawValue)],
    key_path: &str,
) -> Result<BTreeMap<String, AliasNode>, ConfigError> {
    let mut aliases = BTreeMap::new();
    for (key, value) in pairs {
        let segment = string_key(key, key_path)?;
        if !is_valid_alias_path_segment(segment) {
            return Err(schema(SchemaError::InvalidAliasPathSegment {
                key_path: key_path.to_string(),
                segment: segment.to_string(),
            }));
        }
        let node_path = format!("{key_path}.{segment}");
        let node = match value {
            RawValue::Str(raw) => {
                let tokens = tokenize_alias_command(raw).map_err(|error| {
                    schema(SchemaError::AliasTokenization {
                        key_path: node_path.clone(),
                        error,
                    })
                })?;
                if tokens.is_empty() {
                    return Err(schema(SchemaError::EmptyAliasTokenList {
                        key_path: node_path,
                    }));
                }
                AliasNode::Leaf {
                    raw: raw.clone(),
                    tokens,
                }
            }
            RawValue::Map(group_pairs) => {
                if group_pairs.is_empty() {
                    return Err(schema(SchemaError::EmptyAliasGroup {
                        key_path: node_path,
                    }));
                }
                AliasNode::Group(alias_map_pairs(group_pairs, &node_path)?)
            }
            _ => {
                return Err(schema(SchemaError::NonStringValue {
                    key_path: node_path,
                }));
            }
        };
        aliases.insert(segment.to_string(), node);
    }
    Ok(aliases)
}
