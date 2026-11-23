// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    raw::RawValue,
    validate::{schema, section_pairs, string_key},
};
use broil_core::{
    error::{ConfigError, SchemaError},
    secrets::*,
};

fn invalid(path: &str, expected: &str) -> ConfigError {
    schema(SchemaError::InvalidSecretsValue {
        key_path: path.into(),
        expected: expected.into(),
    })
}
fn string(
    value: &RawValue,
    path: &str,
    valid: impl FnOnce(&str) -> bool,
) -> Result<String, ConfigError> {
    match value {
        RawValue::Str(s) if valid(s) => Ok(s.clone()),
        _ => Err(invalid(path, "a valid nonempty reference")),
    }
}
fn literal(s: &str) -> bool {
    !s.is_empty() && !s.contains('\0')
}
fn unknown(path: String) -> ConfigError {
    schema(SchemaError::UnknownKey { key_path: path })
}

pub(crate) fn validate(value: &RawValue, path: &str) -> Result<SecretsConfig, ConfigError> {
    let mut config = SecretsConfig::default();
    for (key, value) in section_pairs(value, path)?.into_iter().flatten() {
        let key = string_key(key, path)?;
        let p = format!("{path}.{key}");
        match key {
            "store" => config.store = Some(string(value, &p, literal)?),
            "project" => config.project = Some(string(value, &p, valid_project)?),
            "set" => config.set = Some(string(value, &p, |s| valid_set(s, false))?),
            "identity" => config.identity = Some(string(value, &p, valid_component)?),
            "inject" => {
                config.inject = Some(match value {
                    RawValue::Bool(b) => *b,
                    _ => return Err(invalid(&p, "a boolean")),
                })
            }
            "exports" => {
                for (name, entry) in section_pairs(value, &p)?.into_iter().flatten() {
                    let name = string_key(name, &p)?;
                    if !valid_export_name(name) {
                        return Err(invalid(&p, "a non-reserved export name"));
                    }
                    config
                        .exports
                        .insert(name.into(), export(entry, &format!("{p}.{name}"))?);
                }
            }
            "vault" => {
                for (key, value) in section_pairs(value, &p)?.into_iter().flatten() {
                    let key = string_key(key, &p)?;
                    let p = format!("{p}.{key}");
                    match key {
                        "address" => config.vault.address = Some(string(value, &p, valid_address)?),
                        "mount" => {
                            config.vault.mount = Some(string(value, &p, valid_relative_file)?)
                        }
                        "credential" => {
                            config.vault.credential = Some(string(value, &p, valid_relative_file)?)
                        }
                        "fallback" => {
                            config.vault.fallback = Some(match value {
                                RawValue::Str(s) if s == "none" => Fallback::None,
                                RawValue::Str(s) if s == "local" => Fallback::Local,
                                _ => return Err(invalid(&p, "none or local")),
                            })
                        }
                        _ => return Err(unknown(p)),
                    }
                }
            }
            "rotation" => {
                for (key, value) in section_pairs(value, &p)?.into_iter().flatten() {
                    let key = string_key(key, &p)?;
                    let p = format!("{p}.{key}");
                    match key {
                        "deploy" => config.rotation.deploy = Some(string(value, &p, literal)?),
                        "handlers" => {
                            for (name, argv) in section_pairs(value, &p)?.into_iter().flatten() {
                                let name = string_key(name, &p)?;
                                if !valid_component(name) {
                                    return Err(invalid(&p, "a handler name"));
                                }
                                let RawValue::Seq(argv) = argv else {
                                    return Err(invalid(&p, "a nonempty argv sequence"));
                                };
                                if argv.is_empty() {
                                    return Err(invalid(&p, "a nonempty argv sequence"));
                                }
                                let argv = argv
                                    .iter()
                                    .map(|v| string(v, &p, |s| !s.contains('\0')))
                                    .collect::<Result<Vec<_>, _>>()?;
                                if argv[0].is_empty() {
                                    return Err(invalid(&p, "a nonempty executable"));
                                }
                                config.rotation.handlers.insert(name.into(), argv);
                            }
                        }
                        _ => return Err(unknown(p)),
                    }
                }
            }
            _ => return Err(unknown(p)),
        }
    }
    Ok(config)
}

fn export(value: &RawValue, path: &str) -> Result<Export, ConfigError> {
    if let RawValue::Str(_) = value {
        return Ok(Export {
            set: None,
            value: ExportValue::Key(string(value, path, valid_key)?),
        });
    }
    let RawValue::Map(pairs) = value else {
        return Err(invalid(path, "an export declaration"));
    };
    let (mut set, mut key, mut compiled) = (None, None, None);
    for (name, value) in pairs {
        let name = string_key(name, path)?;
        let p = format!("{path}.{name}");
        match name {
            "set" => set = Some(string(value, &p, |s| valid_set(s, true))?),
            "key" => key = Some(string(value, &p, valid_key)?),
            "template" => {
                compiled = Some(match value {
                    RawValue::Str(s) => {
                        template(s).ok_or_else(|| invalid(&p, "a bounded literal template"))?
                    }
                    _ => return Err(invalid(&p, "a template string")),
                })
            }
            _ => return Err(unknown(p)),
        }
    }
    let value = match (key, compiled) {
        (Some(key), None) if set.is_some() => ExportValue::Key(key),
        (None, Some(parts)) => ExportValue::Template(parts),
        _ => return Err(invalid(path, "exactly one complete key or template form")),
    };
    Ok(Export { set, value })
}
