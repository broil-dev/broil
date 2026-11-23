// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use broil_core::error::{ConfigError, SchemaError};
use broil_core::model::BroilConfig;
use broil_core::remote::*;

use crate::raw::RawValue;
use crate::validate::{schema, section_pairs, string_key};

const REMOTE_ENV_NAMES: [&str; 5] = [
    "BROIL_ROOT",
    "BROIL_ENV",
    "BROIL_MACHINE",
    "BROIL_SSH_CONFIG",
    "BROIL_SSH_HOST",
];

pub(crate) fn root(value: &RawValue, path: &str) -> Result<RemoteConfig, ConfigError> {
    let Some(pairs) = section_pairs(value, path)? else {
        return Ok(RemoteConfig::default());
    };
    let mut config = RemoteConfig::default();
    for (key, value) in pairs {
        let name = string_key(key, path)?;
        let field = format!("{path}.{name}");
        match name {
            "defaults" => config.definitions.defaults = defaults(value, &field)?,
            "secret_providers" => {
                config.definitions.secret_providers = named_map(value, &field, secret_provider)?
            }
            "auth_profiles" => {
                config.definitions.auth_profiles = named_map(value, &field, auth_profile)?
            }
            "privilege_profiles" => {
                config.definitions.privilege_profiles = named_map(value, &field, privilege_profile)?
            }
            "jump_hosts" => {
                let (map, order) = ordered_named_map(value, &field, jump_host)?;
                config.definitions.jump_hosts = map;
                config.definitions.jump_order = order;
            }
            "scripts" => config.definitions.scripts = named_map(value, &field, remote_script)?,
            "provision_profiles" => {
                config.definitions.provision_profiles = named_map(value, &field, provision_profile)?
            }
            "machine_templates" => {
                config.machine_templates = named_map(value, &field, |value, path| {
                    machine_layer(value, path, false)
                })?
            }
            _ => return Err(unknown(&field)),
        }
    }
    Ok(config)
}

pub(crate) fn environment(
    value: &RawValue,
    path: &str,
) -> Result<EnvironmentRemoteConfig, ConfigError> {
    let Some(pairs) = section_pairs(value, path)? else {
        return Ok(EnvironmentRemoteConfig::default());
    };
    let mut config = EnvironmentRemoteConfig::default();
    for (key, value) in pairs {
        let name = string_key(key, path)?;
        let field = format!("{path}.{name}");
        match name {
            "defaults" => config.definitions.defaults = defaults(value, &field)?,
            "secret_providers" => {
                config.definitions.secret_providers = named_map(value, &field, secret_provider)?
            }
            "auth_profiles" => {
                config.definitions.auth_profiles = named_map(value, &field, auth_profile)?
            }
            "privilege_profiles" => {
                config.definitions.privilege_profiles = named_map(value, &field, privilege_profile)?
            }
            "jump_hosts" => {
                let (map, order) = ordered_named_map(value, &field, jump_host)?;
                config.definitions.jump_hosts = map;
                config.definitions.jump_order = order;
            }
            "scripts" => config.definitions.scripts = named_map(value, &field, remote_script)?,
            "provision_profiles" => {
                config.definitions.provision_profiles = named_map(value, &field, provision_profile)?
            }
            "machines" => {
                let (map, order) = ordered_named_map(value, &field, machine)?;
                config.machines = map;
                config.machine_order = order;
            }
            _ => return Err(unknown(&field)),
        }
    }
    Ok(config)
}

fn unknown(path: &str) -> ConfigError {
    schema(SchemaError::UnknownKey {
        key_path: path.to_string(),
    })
}

fn invalid(path: &str, expected: impl Into<String>) -> ConfigError {
    schema(SchemaError::InvalidRemoteValue {
        key_path: path.to_string(),
        expected: expected.into(),
    })
}

fn missing(path: &str) -> ConfigError {
    schema(SchemaError::MissingRequiredRemoteField {
        key_path: path.to_string(),
    })
}

fn reference(path: &str, target: &str) -> ConfigError {
    schema(SchemaError::UnknownRemoteReference {
        key_path: path.to_string(),
        target: target.to_string(),
    })
}

fn mapping<'a>(value: &'a RawValue, path: &str) -> Result<&'a [(RawValue, RawValue)], ConfigError> {
    match value {
        RawValue::Map(pairs) => Ok(pairs),
        _ => Err(invalid(path, "a mapping")),
    }
}

fn named_map<T>(
    value: &RawValue,
    path: &str,
    parse: fn(&RawValue, &str) -> Result<T, ConfigError>,
) -> Result<BTreeMap<String, T>, ConfigError> {
    ordered_named_map(value, path, parse).map(|(map, _)| map)
}

fn ordered_named_map<T>(
    value: &RawValue,
    path: &str,
    parse: fn(&RawValue, &str) -> Result<T, ConfigError>,
) -> Result<(BTreeMap<String, T>, Vec<String>), ConfigError> {
    let Some(pairs) = section_pairs(value, path)? else {
        return Ok((BTreeMap::new(), Vec::new()));
    };
    let mut map = BTreeMap::new();
    let mut order = Vec::new();
    for (key, value) in pairs {
        let name = string_key(key, path)?;
        if name.is_empty() {
            return Err(invalid(path, "a mapping with non-empty names"));
        }
        let item_path = format!("{path}.{name}");
        if map.contains_key(name) {
            return Err(invalid(
                &item_path,
                "a name that is unique within this mapping",
            ));
        }
        map.insert(name.to_string(), parse(value, &item_path)?);
        order.push(name.to_string());
    }
    Ok((map, order))
}

fn map_fields<'a>(
    value: &'a RawValue,
    path: &str,
    allowed: &[&str],
) -> Result<BTreeMap<&'a str, &'a RawValue>, ConfigError> {
    let pairs = mapping(value, path)?;
    let mut fields = BTreeMap::new();
    for (key, value) in pairs {
        let name = string_key(key, path)?;
        if !allowed.contains(&name) {
            return Err(unknown(&format!("{path}.{name}")));
        }
        if fields.contains_key(name) {
            return Err(invalid(
                &format!("{path}.{name}"),
                "a field that occurs only once",
            ));
        }
        fields.insert(name, value);
    }
    Ok(fields)
}

fn required_string(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<String, ConfigError> {
    let field = format!("{path}.{name}");
    let value = fields.get(name).ok_or_else(|| missing(&field))?;
    string(value, &field)
}

fn optional_string(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<Option<String>, ConfigError> {
    fields
        .get(name)
        .map(|value| string(value, &format!("{path}.{name}")))
        .transpose()
}

fn string(value: &RawValue, path: &str) -> Result<String, ConfigError> {
    match value {
        RawValue::Str(value) if !value.is_empty() => Ok(value.clone()),
        _ => Err(invalid(path, "a non-empty string")),
    }
}

fn optional_setting(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<Setting<String>, ConfigError> {
    let Some(value) = fields.get(name) else {
        return Ok(Setting::Inherit);
    };
    if matches!(value, RawValue::Null) {
        Ok(Setting::Null)
    } else {
        Ok(Setting::Value(string(value, &format!("{path}.{name}"))?))
    }
}

fn optional_bool(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<Option<bool>, ConfigError> {
    let Some(value) = fields.get(name) else {
        return Ok(None);
    };
    match value {
        RawValue::Bool(value) => Ok(Some(*value)),
        _ => Err(invalid(&format!("{path}.{name}"), "a boolean")),
    }
}

fn optional_port(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<Option<u16>, ConfigError> {
    let Some(value) = fields.get(name) else {
        return Ok(None);
    };
    match value {
        RawValue::Int(port) if (1..=65_535).contains(port) => Ok(Some(*port as u16)),
        _ => Err(invalid(
            &format!("{path}.{name}"),
            "an integer in 1..=65535",
        )),
    }
}

fn required_argv(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<Vec<String>, ConfigError> {
    let field = format!("{path}.{name}");
    let value = fields.get(name).ok_or_else(|| missing(&field))?;
    string_sequence(value, &field, false, true)
}

fn optional_argv(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<Option<Vec<String>>, ConfigError> {
    fields
        .get(name)
        .map(|value| string_sequence(value, &format!("{path}.{name}"), false, true))
        .transpose()
}

fn optional_string_sequence(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
    unique: bool,
) -> Result<Option<Vec<String>>, ConfigError> {
    fields
        .get(name)
        .map(|value| string_sequence(value, &format!("{path}.{name}"), unique, false))
        .transpose()
}

fn string_sequence(
    value: &RawValue,
    path: &str,
    unique: bool,
    require_non_empty: bool,
) -> Result<Vec<String>, ConfigError> {
    let RawValue::Seq(values) = value else {
        return Err(invalid(path, "a sequence of non-empty strings"));
    };
    if require_non_empty && values.is_empty() {
        return Err(invalid(path, "a non-empty sequence of non-empty strings"));
    }
    let mut result = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let item = string(value, &format!("{path}.{index}"))?;
        if unique && !seen.insert(item.clone()) {
            return Err(invalid(path, "a sequence of unique non-empty strings"));
        }
        result.push(item);
    }
    Ok(result)
}

fn duration(value: &RawValue, path: &str) -> Result<DurationValue, ConfigError> {
    let source = string(value, path)?;
    let split = source
        .find(|character: char| !character.is_ascii_digit())
        .ok_or_else(|| invalid(path, "a positive duration with s, m, or h units"))?;
    let (number, unit) = source.split_at(split);
    if number.is_empty() || !matches!(unit, "s" | "m" | "h") {
        return Err(invalid(path, "a positive duration with s, m, or h units"));
    }
    let value: u64 = number
        .parse()
        .map_err(|_| invalid(path, "a positive duration with s, m, or h units"))?;
    if value == 0 {
        return Err(invalid(path, "a positive duration with s, m, or h units"));
    }
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => unreachable!(),
    };
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| invalid(path, "a duration small enough to represent"))?;
    Ok(DurationValue { source, seconds })
}

fn optional_duration(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<Option<DurationValue>, ConfigError> {
    fields
        .get(name)
        .map(|value| duration(value, &format!("{path}.{name}")))
        .transpose()
}

fn defaults(value: &RawValue, path: &str) -> Result<RemoteDefaults, ConfigError> {
    if matches!(value, RawValue::Null) {
        return Ok(RemoteDefaults::default());
    }
    let fields = map_fields(
        value,
        path,
        &[
            "port",
            "canonical_auth",
            "bootstrap_auth",
            "privilege",
            "interpreter",
            "via",
            "known_hosts",
            "stats_script",
            "provision",
            "parallelism",
            "timeouts",
        ],
    )?;
    let mut result = RemoteDefaults {
        port: optional_port(&fields, "port", path)?,
        canonical_auth: optional_string(&fields, "canonical_auth", path)?,
        bootstrap_auth: optional_string_sequence(&fields, "bootstrap_auth", path, true)?,
        privilege: optional_setting(&fields, "privilege", path)?,
        interpreter: optional_argv(&fields, "interpreter", path)?,
        via: optional_string(&fields, "via", path)?,
        known_hosts: optional_string(&fields, "known_hosts", path)?,
        stats_script: optional_setting(&fields, "stats_script", path)?,
        ..RemoteDefaults::default()
    };
    if let Some(value) = fields.get("provision") {
        let provision = map_fields(value, &format!("{path}.provision"), &["profiles"])?;
        result.provision_profiles =
            optional_string_sequence(&provision, "profiles", &format!("{path}.provision"), true)?;
    }
    if let Some(value) = fields.get("parallelism") {
        result.parallelism = parallelism_defaults(value, &format!("{path}.parallelism"))?;
    }
    if let Some(value) = fields.get("timeouts") {
        result.timeouts = timeouts(value, &format!("{path}.timeouts"))?;
    }
    Ok(result)
}

fn parallelism_defaults(value: &RawValue, path: &str) -> Result<ParallelismDefaults, ConfigError> {
    let fields = map_fields(value, path, &["operations", "provision"])?;
    Ok(ParallelismDefaults {
        operations: fields
            .get("operations")
            .map(|value| parallelism(value, &format!("{path}.operations")))
            .transpose()?,
        provision: fields
            .get("provision")
            .map(|value| parallelism(value, &format!("{path}.provision")))
            .transpose()?,
    })
}

fn parallelism(value: &RawValue, path: &str) -> Result<Parallelism, ConfigError> {
    match value {
        RawValue::Int(value) if *value > 0 => usize::try_from(*value)
            .map(Parallelism::Limit)
            .map_err(|_| invalid(path, "a positive integer or all")),
        RawValue::Str(value) if value == "all" => Ok(Parallelism::All),
        _ => Err(invalid(path, "a positive integer or all")),
    }
}

fn timeouts(value: &RawValue, path: &str) -> Result<Timeouts, ConfigError> {
    let fields = map_fields(
        value,
        path,
        &[
            "connect",
            "command",
            "transfer",
            "reboot_disconnect",
            "reboot_readiness",
            "reboot_poll",
        ],
    )?;
    Ok(Timeouts {
        connect: optional_duration(&fields, "connect", path)?,
        command: optional_duration(&fields, "command", path)?,
        transfer: optional_duration(&fields, "transfer", path)?,
        reboot_disconnect: optional_duration(&fields, "reboot_disconnect", path)?,
        reboot_readiness: optional_duration(&fields, "reboot_readiness", path)?,
        reboot_poll: optional_duration(&fields, "reboot_poll", path)?,
    })
}

fn secret_provider(value: &RawValue, path: &str) -> Result<SecretProvider, ConfigError> {
    let fields = map_fields(value, path, &["prompt", "file", "helper", "store"])?;
    if fields.len() != 1 {
        return Err(invalid(
            path,
            "exactly one of prompt, file, helper, or store",
        ));
    }
    if let Some(value) = fields.get("prompt") {
        let prompt = map_fields(value, &format!("{path}.prompt"), &["label"])?;
        return Ok(SecretProvider::Prompt {
            label: required_string(&prompt, "label", &format!("{path}.prompt"))?,
        });
    }
    if let Some(value) = fields.get("file") {
        let file = map_fields(value, &format!("{path}.file"), &["path"])?;
        return Ok(SecretProvider::File {
            path: required_string(&file, "path", &format!("{path}.file"))?,
        });
    }
    if let Some(value) = fields.get("store") {
        let store_path = format!("{path}.store");
        let fields = map_fields(value, &store_path, &["key", "set"])?;
        let key = required_string(&fields, "key", &store_path)?;
        let set = optional_string(&fields, "set", &store_path)?;
        if !broil_core::secrets::valid_key(&key) {
            return Err(invalid(&format!("{store_path}.key"), "a user key"));
        }
        if set
            .as_deref()
            .is_some_and(|id| !broil_core::secrets::valid_set(id, true))
        {
            return Err(invalid(
                &format!("{store_path}.set"),
                "a qualified store-relative set",
            ));
        }
        return Ok(SecretProvider::Store { key, set });
    }
    let helper_path = format!("{path}.helper");
    let helper = map_fields(fields["helper"], &helper_path, &["command"])?;
    Ok(SecretProvider::Helper {
        command: required_argv(&helper, "command", &helper_path)?,
    })
}

fn secret_ref(value: &RawValue, path: &str) -> Result<SecretRef, ConfigError> {
    let fields = map_fields(value, path, &["secret"])?;
    Ok(SecretRef {
        secret: required_string(&fields, "secret", path)?,
    })
}

fn auth_profile(value: &RawValue, path: &str) -> Result<AuthProfile, ConfigError> {
    let fields = map_fields(
        value,
        path,
        &["user", "public_key", "password", "keyboard_interactive"],
    )?;
    let user = required_string(&fields, "user", path)?;
    let method_count = ["public_key", "password", "keyboard_interactive"]
        .iter()
        .filter(|name| fields.contains_key(**name))
        .count();
    if method_count != 1 {
        return Err(invalid(path, "user and exactly one authentication method"));
    }
    let method = if let Some(value) = fields.get("public_key") {
        let key_path = format!("{path}.public_key");
        let key = map_fields(value, &key_path, &["identities"])?;
        let identities_value = key
            .get("identities")
            .ok_or_else(|| missing(&format!("{key_path}.identities")))?;
        let RawValue::Seq(values) = identities_value else {
            return Err(invalid(
                &format!("{key_path}.identities"),
                "a non-empty sequence of identities",
            ));
        };
        if values.is_empty() {
            return Err(invalid(
                &format!("{key_path}.identities"),
                "a non-empty sequence of identities",
            ));
        }
        AuthMethod::PublicKey {
            identities: values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    public_key_identity(value, &format!("{key_path}.identities.{index}"))
                })
                .collect::<Result<_, _>>()?,
        }
    } else if let Some(value) = fields.get("password") {
        AuthMethod::Password(secret_ref(value, &format!("{path}.password"))?)
    } else {
        AuthMethod::KeyboardInteractive(secret_ref(
            fields["keyboard_interactive"],
            &format!("{path}.keyboard_interactive"),
        )?)
    };
    Ok(AuthProfile { user, method })
}

fn public_key_identity(value: &RawValue, path: &str) -> Result<PublicKeyIdentity, ConfigError> {
    let fields = map_fields(value, path, &["agent", "file"])?;
    if fields.len() != 1 {
        return Err(invalid(path, "exactly one of agent or file"));
    }
    if let Some(value) = fields.get("agent") {
        let agent_path = format!("{path}.agent");
        let agent = map_fields(value, &agent_path, &["fingerprint", "public_key"])?;
        if agent.len() != 1 {
            return Err(invalid(
                &agent_path,
                "exactly one of fingerprint or public_key",
            ));
        }
        let selector = if let Some(value) = agent.get("fingerprint") {
            AgentSelector::Fingerprint(string(value, &format!("{agent_path}.fingerprint"))?)
        } else {
            let public_path = format!("{agent_path}.public_key");
            let public_key = map_fields(agent["public_key"], &public_path, &["path"])?;
            AgentSelector::PublicKeyPath(required_string(&public_key, "path", &public_path)?)
        };
        return Ok(PublicKeyIdentity::Agent { selector });
    }
    let file_path = format!("{path}.file");
    let file = map_fields(fields["file"], &file_path, &["path", "passphrase"])?;
    Ok(PublicKeyIdentity::File {
        path: required_string(&file, "path", &file_path)?,
        passphrase: file
            .get("passphrase")
            .map(|value| secret_ref(value, &format!("{file_path}.passphrase")))
            .transpose()?,
    })
}

fn privilege_profile(value: &RawValue, path: &str) -> Result<PrivilegeProfile, ConfigError> {
    let fields = map_fields(value, path, &["method", "password"])?;
    let method = required_string(&fields, "method", path)?;
    if method != "sudo" {
        return Err(invalid(&format!("{path}.method"), "sudo"));
    }
    Ok(PrivilegeProfile {
        password: fields
            .get("password")
            .map(|value| secret_ref(value, &format!("{path}.password")))
            .transpose()?,
    })
}

fn jump_host(value: &RawValue, path: &str) -> Result<JumpHost, ConfigError> {
    let fields = map_fields(value, path, &["address", "port", "auth"])?;
    Ok(JumpHost {
        address: required_string(&fields, "address", path)?,
        port: optional_port(&fields, "port", path)?.unwrap_or(22),
        auth: required_string(&fields, "auth", path)?,
    })
}

fn remote_script(value: &RawValue, path: &str) -> Result<RemoteScript, ConfigError> {
    let fields = map_fields(
        value,
        path,
        &[
            "body",
            "interpreter",
            "cwd",
            "privilege",
            "pty",
            "timeout",
            "env",
        ],
    )?;
    let body = required_string_allow_empty(&fields, "body", path)?;
    let interpreter = optional_argv(&fields, "interpreter", path)?;
    if interpreter.is_some() && body.starts_with("#!") {
        return Err(invalid(path, "a shebang body or interpreter, but not both"));
    }
    let pty = match fields.get("pty") {
        None => PtyMode::Auto,
        Some(RawValue::Str(value)) if value == "auto" => PtyMode::Auto,
        Some(RawValue::Str(value)) if value == "always" => PtyMode::Always,
        Some(RawValue::Str(value)) if value == "never" => PtyMode::Never,
        Some(_) => return Err(invalid(&format!("{path}.pty"), "auto, always, or never")),
    };
    Ok(RemoteScript {
        body,
        interpreter,
        cwd: optional_string(&fields, "cwd", path)?,
        privilege: optional_string(&fields, "privilege", path)?,
        pty,
        timeout: optional_duration(&fields, "timeout", path)?,
        env: fields
            .get("env")
            .map(|value| remote_env(value, &format!("{path}.env")))
            .transpose()?
            .unwrap_or_default(),
    })
}

fn required_string_allow_empty(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<String, ConfigError> {
    let field = format!("{path}.{name}");
    match fields.get(name).ok_or_else(|| missing(&field))? {
        RawValue::Str(value) => Ok(value.clone()),
        _ => Err(invalid(&field, "a string")),
    }
}

fn remote_env(
    value: &RawValue,
    path: &str,
) -> Result<BTreeMap<String, RemoteEnvValue>, ConfigError> {
    let pairs = mapping(value, path)?;
    let mut env = BTreeMap::new();
    for (key, value) in pairs {
        let name = string_key(key, path)?;
        if !is_env_name(name) || REMOTE_ENV_NAMES.contains(&name) {
            return Err(invalid(
                &format!("{path}.{name}"),
                "a non-reserved environment variable name",
            ));
        }
        let item_path = format!("{path}.{name}");
        let fields = map_fields(value, &item_path, &["value", "from_env", "from_machine"])?;
        if fields.len() != 1 {
            return Err(invalid(
                &item_path,
                "exactly one of value, from_env, or from_machine",
            ));
        }
        let source = if let Some(value) = fields.get("value") {
            match value {
                RawValue::Str(value) => RemoteEnvValue::Value(value.clone()),
                _ => return Err(invalid(&format!("{item_path}.value"), "a string")),
            }
        } else if let Some(value) = fields.get("from_env") {
            RemoteEnvValue::FromEnv(string(value, &format!("{item_path}.from_env"))?)
        } else {
            RemoteEnvValue::FromMachine(string(
                fields["from_machine"],
                &format!("{item_path}.from_machine"),
            )?)
        };
        env.insert(name.to_string(), source);
    }
    Ok(env)
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn machine(value: &RawValue, path: &str) -> Result<MachineConfig, ConfigError> {
    let fields = map_fields(
        value,
        path,
        &[
            "template",
            "address",
            "port",
            "tags",
            "via",
            "canonical_auth",
            "bootstrap_auth",
            "privilege",
            "stats_script",
            "provision",
            "vars",
            "timeouts",
        ],
    )?;
    Ok(MachineConfig {
        template: optional_string(&fields, "template", path)?,
        settings: machine_layer_fields(&fields, path)?,
    })
}

fn machine_layer(
    value: &RawValue,
    path: &str,
    allow_template: bool,
) -> Result<MachineLayer, ConfigError> {
    let mut allowed = vec![
        "address",
        "port",
        "tags",
        "via",
        "canonical_auth",
        "bootstrap_auth",
        "privilege",
        "stats_script",
        "provision",
        "vars",
        "timeouts",
    ];
    if allow_template {
        allowed.push("template");
    }
    let fields = map_fields(value, path, &allowed)?;
    machine_layer_fields(&fields, path)
}

fn machine_layer_fields(
    fields: &BTreeMap<&str, &RawValue>,
    path: &str,
) -> Result<MachineLayer, ConfigError> {
    let mut layer = MachineLayer {
        address: optional_string(fields, "address", path)?,
        port: optional_port(fields, "port", path)?,
        tags: optional_string_sequence(fields, "tags", path, true)?,
        via: optional_string(fields, "via", path)?,
        canonical_auth: optional_string(fields, "canonical_auth", path)?,
        bootstrap_auth: optional_string_sequence(fields, "bootstrap_auth", path, true)?,
        privilege: optional_setting(fields, "privilege", path)?,
        stats_script: optional_setting(fields, "stats_script", path)?,
        ..MachineLayer::default()
    };
    if let Some(value) = fields.get("provision") {
        let provision_path = format!("{path}.provision");
        let provision = map_fields(value, &provision_path, &["profiles"])?;
        layer.provision_profiles =
            optional_string_sequence(&provision, "profiles", &provision_path, true)?;
    }
    if let Some(value) = fields.get("vars") {
        layer.vars = string_mapping(value, &format!("{path}.vars"))?;
    }
    if let Some(value) = fields.get("timeouts") {
        layer.timeouts = timeouts(value, &format!("{path}.timeouts"))?;
    }
    Ok(layer)
}

fn string_mapping(value: &RawValue, path: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let pairs = mapping(value, path)?;
    let mut result = BTreeMap::new();
    for (key, value) in pairs {
        let name = string_key(key, path)?;
        if name.is_empty() {
            return Err(invalid(path, "a mapping with non-empty string names"));
        }
        let value = match value {
            RawValue::Str(value) => value.clone(),
            _ => return Err(invalid(&format!("{path}.{name}"), "a string")),
        };
        result.insert(name.to_string(), value);
    }
    Ok(result)
}

fn provision_profile(value: &RawValue, path: &str) -> Result<ProvisionProfile, ConfigError> {
    let fields = map_fields(
        value,
        path,
        &[
            "bootstrap",
            "secure",
            "configure",
            "ssh_transition",
            "security",
        ],
    )?;
    let mut profile = ProvisionProfile {
        bootstrap: optional_steps(&fields, "bootstrap", path, "bootstrap")?,
        secure: optional_steps(&fields, "secure", path, "secure")?,
        configure: optional_steps(&fields, "configure", path, "configure")?,
        ..ProvisionProfile::default()
    };
    if let Some(value) = fields.get("ssh_transition") {
        profile.ssh_transition = Some(ssh_transition(value, &format!("{path}.ssh_transition"))?);
    }
    if let Some(value) = fields.get("security") {
        let security_path = format!("{path}.security");
        let security = map_fields(value, &security_path, &["verify"])?;
        let verify_path = format!("{security_path}.verify");
        let verify = security
            .get("verify")
            .ok_or_else(|| missing(&verify_path))?;
        let RawValue::Seq(values) = verify else {
            return Err(invalid(
                &verify_path,
                "a non-empty sequence of script actions",
            ));
        };
        if values.is_empty() {
            return Err(invalid(
                &verify_path,
                "a non-empty sequence of script actions",
            ));
        }
        profile.security_verify = values
            .iter()
            .enumerate()
            .map(|(index, value)| script_action(value, &format!("{verify_path}.{index}")))
            .collect::<Result<_, _>>()?;
    }
    Ok(profile)
}

fn optional_steps(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
    phase: &str,
) -> Result<Vec<ProvisionStep>, ConfigError> {
    let Some(value) = fields.get(name) else {
        return Ok(Vec::new());
    };
    let steps_path = format!("{path}.{name}");
    let RawValue::Seq(values) = value else {
        return Err(invalid(&steps_path, "a sequence of provisioning steps"));
    };
    let mut names = BTreeSet::new();
    let mut steps = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let step_path = format!("{steps_path}.{index}");
        let step = provision_step(value, &step_path, phase)?;
        if !names.insert(step.name.clone()) {
            return Err(invalid(
                &format!("{step_path}.name"),
                "a name unique within this profile phase",
            ));
        }
        steps.push(step);
    }
    Ok(steps)
}

fn provision_step(value: &RawValue, path: &str, phase: &str) -> Result<ProvisionStep, ConfigError> {
    let fields = map_fields(value, path, &["name", "check", "run", "verify", "always"])?;
    let check = fields
        .get("check")
        .map(|value| script_action(value, &format!("{path}.check")))
        .transpose()?;
    let always = optional_bool(&fields, "always", path)?;
    match (&check, always) {
        (None, Some(true)) | (Some(_), None) => {}
        (None, _) => {
            return Err(invalid(path, "always: true when check is absent"));
        }
        (Some(_), Some(_)) => {
            return Err(invalid(path, "no always field when check is present"));
        }
    }
    let run_path = format!("{path}.run");
    let run = provision_action(
        fields.get("run").ok_or_else(|| missing(&run_path))?,
        &run_path,
    )?;
    if phase != "configure"
        && matches!(&run, ProvisionAction::Reboot(_) | ProvisionAction::Local(_))
    {
        return Err(invalid(
            &run_path,
            "a script or transfer action before configure",
        ));
    }
    Ok(ProvisionStep {
        name: required_string(&fields, "name", path)?,
        check,
        run,
        verify: fields
            .get("verify")
            .map(|value| script_action(value, &format!("{path}.verify")))
            .transpose()?,
    })
}

fn provision_action(value: &RawValue, path: &str) -> Result<ProvisionAction, ConfigError> {
    let fields = map_fields(
        value,
        path,
        &[
            "script",
            "privilege",
            "stdin",
            "timeout",
            "copy_to",
            "copy_from",
            "reboot",
            "local",
        ],
    )?;
    let action_count = ["script", "copy_to", "copy_from", "reboot", "local"]
        .iter()
        .filter(|name| fields.contains_key(**name))
        .count();
    if action_count != 1
        || (!fields.contains_key("script")
            && (fields.contains_key("privilege")
                || fields.contains_key("stdin")
                || fields.contains_key("timeout")))
    {
        return Err(invalid(
            path,
            "exactly one of script, copy_to, copy_from, reboot, or local",
        ));
    }
    if fields.contains_key("script") {
        return Ok(ProvisionAction::Script(script_action(value, path)?));
    }
    if let Some(value) = fields.get("copy_to") {
        return Ok(ProvisionAction::CopyTo(copy_to_action(
            value,
            &format!("{path}.copy_to"),
        )?));
    }
    if let Some(value) = fields.get("copy_from") {
        return Ok(ProvisionAction::CopyFrom(copy_from_action(
            value,
            &format!("{path}.copy_from"),
        )?));
    }
    if let Some(value) = fields.get("reboot") {
        return Ok(ProvisionAction::Reboot(reboot_action(
            value,
            &format!("{path}.reboot"),
        )?));
    }
    Ok(ProvisionAction::Local(local_action(
        fields["local"],
        &format!("{path}.local"),
    )?))
}

fn script_action(value: &RawValue, path: &str) -> Result<ScriptAction, ConfigError> {
    let fields = map_fields(value, path, &["script", "privilege", "stdin", "timeout"])?;
    Ok(ScriptAction {
        script: required_string(&fields, "script", path)?,
        privilege: optional_string(&fields, "privilege", path)?,
        stdin: fields
            .get("stdin")
            .map(|value| provision_script_stdin(value, &format!("{path}.stdin")))
            .transpose()?,
        timeout: optional_duration(&fields, "timeout", path)?,
    })
}

fn provision_script_stdin(
    value: &RawValue,
    path: &str,
) -> Result<ProvisionScriptStdin, ConfigError> {
    let fields = map_fields(value, path, &["secret"])?;
    Ok(ProvisionScriptStdin::Secret(SecretRef {
        secret: required_string(&fields, "secret", path)?,
    }))
}

fn transfer_fields<'a>(
    value: &'a RawValue,
    path: &str,
    upload: bool,
) -> Result<BTreeMap<&'a str, &'a RawValue>, ConfigError> {
    if upload {
        map_fields(
            value,
            path,
            &[
                "source",
                "destination",
                "recursive",
                "overwrite",
                "mode",
                "owner",
                "privilege",
                "timeout",
            ],
        )
    } else {
        map_fields(
            value,
            path,
            &[
                "source",
                "destination",
                "recursive",
                "overwrite",
                "mode",
                "timeout",
            ],
        )
    }
}

fn copy_to_action(value: &RawValue, path: &str) -> Result<CopyToAction, ConfigError> {
    let fields = transfer_fields(value, path, true)?;
    let mode = optional_string(&fields, "mode", path)?;
    validate_mode(mode.as_deref(), &format!("{path}.mode"))?;
    let owner = optional_string(&fields, "owner", path)?;
    validate_owner(owner.as_deref(), &format!("{path}.owner"))?;
    Ok(CopyToAction {
        source: required_string(&fields, "source", path)?,
        destination: required_string(&fields, "destination", path)?,
        recursive: optional_bool(&fields, "recursive", path)?.unwrap_or(false),
        overwrite: optional_bool(&fields, "overwrite", path)?.unwrap_or(false),
        mode,
        owner,
        privilege: optional_string(&fields, "privilege", path)?,
        timeout: optional_duration(&fields, "timeout", path)?,
    })
}

fn copy_from_action(value: &RawValue, path: &str) -> Result<CopyFromAction, ConfigError> {
    let fields = transfer_fields(value, path, false)?;
    let mode = optional_string(&fields, "mode", path)?;
    validate_mode(mode.as_deref(), &format!("{path}.mode"))?;
    Ok(CopyFromAction {
        source: required_string(&fields, "source", path)?,
        destination: required_string(&fields, "destination", path)?,
        recursive: optional_bool(&fields, "recursive", path)?.unwrap_or(false),
        overwrite: optional_bool(&fields, "overwrite", path)?.unwrap_or(false),
        mode,
        timeout: optional_duration(&fields, "timeout", path)?,
    })
}

fn validate_mode(value: Option<&str>, path: &str) -> Result<(), ConfigError> {
    if let Some(value) = value {
        if value.len() != 4
            || !value.starts_with('0')
            || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
        {
            return Err(invalid(path, "an octal string matching 0[0-7]{3}"));
        }
    }
    Ok(())
}

fn validate_owner(value: Option<&str>, path: &str) -> Result<(), ConfigError> {
    if let Some(value) = value {
        let mut parts = value.split(':');
        let user = parts.next().unwrap_or_default();
        let group = parts.next();
        if parts.next().is_some()
            || !owner_component(user)
            || group.is_some_and(|group| !owner_component(group))
        {
            return Err(invalid(path, "user or user:group with symbolic names"));
        }
    }
    Ok(())
}

fn owner_component(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn reboot_action(value: &RawValue, path: &str) -> Result<RebootAction, ConfigError> {
    let fields = map_fields(
        value,
        path,
        &[
            "when",
            "privilege",
            "disconnect_timeout",
            "readiness_timeout",
            "poll_interval",
        ],
    )?;
    Ok(RebootAction {
        when: fields
            .get("when")
            .map(|value| script_action(value, &format!("{path}.when")))
            .transpose()?,
        privilege: optional_string(&fields, "privilege", path)?,
        disconnect_timeout: optional_duration(&fields, "disconnect_timeout", path)?,
        readiness_timeout: optional_duration(&fields, "readiness_timeout", path)?,
        poll_interval: optional_duration(&fields, "poll_interval", path)?,
    })
}

fn local_action(value: &RawValue, path: &str) -> Result<LocalAction, ConfigError> {
    let fields = map_fields(value, path, &["command", "timeout"])?;
    Ok(LocalAction {
        command: required_argv(&fields, "command", path)?,
        timeout: optional_duration(&fields, "timeout", path)?,
    })
}

fn ssh_transition(value: &RawValue, path: &str) -> Result<SshTransition, ConfigError> {
    let fields = map_fields(
        value,
        path,
        &["prepare", "apply", "validate", "reload", "rollback"],
    )?;
    Ok(SshTransition {
        prepare: required_script_action(&fields, "prepare", path)?,
        apply: required_script_action(&fields, "apply", path)?,
        validate: required_script_action(&fields, "validate", path)?,
        reload: required_script_action(&fields, "reload", path)?,
        rollback: required_script_action(&fields, "rollback", path)?,
    })
}

fn required_script_action(
    fields: &BTreeMap<&str, &RawValue>,
    name: &str,
    path: &str,
) -> Result<ScriptAction, ConfigError> {
    let field = format!("{path}.{name}");
    script_action(fields.get(name).ok_or_else(|| missing(&field))?, &field)
}

#[derive(Clone)]
struct EffectiveDefinitions {
    secret_providers: BTreeMap<String, SecretProvider>,
    auth_profiles: BTreeMap<String, AuthProfile>,
    privilege_profiles: BTreeMap<String, PrivilegeProfile>,
    jump_hosts: BTreeMap<String, JumpHost>,
    scripts: BTreeMap<String, RemoteScript>,
    provision_profiles: BTreeMap<String, ProvisionProfile>,
}

#[derive(Clone)]
struct ResolvedMachine {
    address: String,
    port: u16,
    via: String,
    canonical_auth: String,
    bootstrap_auth: Vec<String>,
    privilege: Option<String>,
    stats_script: Option<String>,
    provision_profiles: Vec<String>,
}

pub(crate) fn validate_references_and_routes(config: &BroilConfig) -> Result<(), ConfigError> {
    let root = definitions(&config.remote.definitions, None);
    validate_definitions(&config.remote.definitions, &root, "remote")?;

    let mut routes: BTreeMap<(String, u16, String, u16), String> = BTreeMap::new();
    for (environment_name, environment) in &config.environments {
        let env_path = format!("environments.{environment_name}.remote");
        let effective = definitions(
            &config.remote.definitions,
            Some(&environment.remote.definitions),
        );
        validate_definitions(&environment.remote.definitions, &effective, &env_path)?;
        for machine_name in &environment.remote.machine_order {
            let machine = &environment.remote.machines[machine_name];
            let machine_path = format!("{env_path}.machines.{machine_name}");
            let resolved = resolve_machine(config, environment_name, machine_name, machine)?;
            validate_machine(&effective, &resolved, &machine_path)?;
            let (jump_address, jump_port) = if resolved.via == "direct" {
                ("\0direct".to_string(), 0)
            } else {
                let jump = effective
                    .jump_hosts
                    .get(&resolved.via)
                    .ok_or_else(|| reference(&format!("{machine_path}.via"), &resolved.via))?;
                (normalize_address(&jump.address), jump.port)
            };
            let route = (
                normalize_address(&resolved.address),
                resolved.port,
                jump_address,
                jump_port,
            );
            let current = format!("{environment_name}.{machine_name}");
            if let Some(first) = routes.insert(route, current.clone()) {
                return Err(schema(SchemaError::DuplicateRemoteRoute {
                    first,
                    second: current,
                }));
            }
        }
    }
    Ok(())
}

fn definitions(
    root: &RemoteDefinitions,
    environment: Option<&RemoteDefinitions>,
) -> EffectiveDefinitions {
    let mut result = EffectiveDefinitions {
        secret_providers: root.secret_providers.clone(),
        auth_profiles: root.auth_profiles.clone(),
        privilege_profiles: root.privilege_profiles.clone(),
        jump_hosts: root.jump_hosts.clone(),
        scripts: root.scripts.clone(),
        provision_profiles: root.provision_profiles.clone(),
    };
    if let Some(environment) = environment {
        result
            .secret_providers
            .extend(environment.secret_providers.clone());
        result
            .auth_profiles
            .extend(environment.auth_profiles.clone());
        result
            .privilege_profiles
            .extend(environment.privilege_profiles.clone());
        result.jump_hosts.extend(environment.jump_hosts.clone());
        result.scripts.extend(environment.scripts.clone());
        result
            .provision_profiles
            .extend(environment.provision_profiles.clone());
    }
    result
}

fn overlay_defaults(base: &mut RemoteDefaults, overlay: &RemoteDefaults) {
    replace_option(&mut base.port, &overlay.port);
    replace_option(&mut base.canonical_auth, &overlay.canonical_auth);
    replace_option(&mut base.bootstrap_auth, &overlay.bootstrap_auth);
    replace_setting(&mut base.privilege, &overlay.privilege);
    replace_option(&mut base.interpreter, &overlay.interpreter);
    replace_option(&mut base.via, &overlay.via);
    replace_option(&mut base.known_hosts, &overlay.known_hosts);
    replace_setting(&mut base.stats_script, &overlay.stats_script);
    replace_option(&mut base.provision_profiles, &overlay.provision_profiles);
    replace_option(
        &mut base.parallelism.operations,
        &overlay.parallelism.operations,
    );
    replace_option(
        &mut base.parallelism.provision,
        &overlay.parallelism.provision,
    );
    overlay_timeouts(&mut base.timeouts, &overlay.timeouts);
}

fn replace_option<T: Clone>(base: &mut Option<T>, overlay: &Option<T>) {
    if let Some(value) = overlay {
        *base = Some(value.clone());
    }
}

fn replace_setting<T: Clone>(base: &mut Setting<T>, overlay: &Setting<T>) {
    if !matches!(overlay, Setting::Inherit) {
        *base = overlay.clone();
    }
}

fn overlay_timeouts(base: &mut Timeouts, overlay: &Timeouts) {
    replace_option(&mut base.connect, &overlay.connect);
    replace_option(&mut base.command, &overlay.command);
    replace_option(&mut base.transfer, &overlay.transfer);
    replace_option(&mut base.reboot_disconnect, &overlay.reboot_disconnect);
    replace_option(&mut base.reboot_readiness, &overlay.reboot_readiness);
    replace_option(&mut base.reboot_poll, &overlay.reboot_poll);
}

fn validate_definitions(
    declared: &RemoteDefinitions,
    effective: &EffectiveDefinitions,
    path: &str,
) -> Result<(), ConfigError> {
    for (name, auth) in &declared.auth_profiles {
        let auth_path = format!("{path}.auth_profiles.{name}");
        match &auth.method {
            AuthMethod::PublicKey { identities } => {
                for (index, identity) in identities.iter().enumerate() {
                    if let PublicKeyIdentity::File {
                        passphrase: Some(secret),
                        ..
                    } = identity
                    {
                        require_name(
                            &effective.secret_providers,
                            &secret.secret,
                            &format!(
                                "{auth_path}.public_key.identities.{index}.file.passphrase.secret"
                            ),
                        )?;
                    }
                }
            }
            AuthMethod::Password(secret) => require_name(
                &effective.secret_providers,
                &secret.secret,
                &format!("{auth_path}.password.secret"),
            )?,
            AuthMethod::KeyboardInteractive(secret) => require_name(
                &effective.secret_providers,
                &secret.secret,
                &format!("{auth_path}.keyboard_interactive.secret"),
            )?,
        }
    }
    for (name, privilege) in &declared.privilege_profiles {
        if let Some(secret) = &privilege.password {
            require_name(
                &effective.secret_providers,
                &secret.secret,
                &format!("{path}.privilege_profiles.{name}.password.secret"),
            )?;
        }
    }
    for (name, jump) in &declared.jump_hosts {
        let jump_path = format!("{path}.jump_hosts.{name}.auth");
        require_name(&effective.auth_profiles, &jump.auth, &jump_path)?;
        if !matches!(
            &effective.auth_profiles[&jump.auth].method,
            AuthMethod::PublicKey { .. }
        ) {
            return Err(invalid(&jump_path, "a public-key authentication profile"));
        }
    }
    for (name, script) in &declared.scripts {
        if let Some(privilege) = &script.privilege {
            require_name(
                &effective.privilege_profiles,
                privilege,
                &format!("{path}.scripts.{name}.privilege"),
            )?;
        }
    }
    for (name, profile) in &declared.provision_profiles {
        validate_profile_references(
            effective,
            profile,
            &format!("{path}.provision_profiles.{name}"),
        )?;
    }
    Ok(())
}

fn require_name<T>(map: &BTreeMap<String, T>, name: &str, path: &str) -> Result<(), ConfigError> {
    if map.contains_key(name) {
        Ok(())
    } else {
        Err(reference(path, name))
    }
}

fn require_public_key_auth(
    definitions: &EffectiveDefinitions,
    name: &str,
    path: &str,
) -> Result<(), ConfigError> {
    require_name(&definitions.auth_profiles, name, path)?;
    if !matches!(
        &definitions.auth_profiles[name].method,
        AuthMethod::PublicKey { .. }
    ) {
        return Err(invalid(path, "a public-key authentication profile"));
    }
    Ok(())
}

fn require_route(
    definitions: &EffectiveDefinitions,
    via: &str,
    path: &str,
) -> Result<(), ConfigError> {
    if via == "direct" {
        Ok(())
    } else {
        require_name(&definitions.jump_hosts, via, path)?;
        require_public_key_auth(definitions, &definitions.jump_hosts[via].auth, path)
    }
}

fn resolve_machine(
    config: &BroilConfig,
    environment_name: &str,
    machine_name: &str,
    machine: &MachineConfig,
) -> Result<ResolvedMachine, ConfigError> {
    let environment = &config.environments[environment_name];
    let mut defaults = config.remote.definitions.defaults.clone();
    overlay_defaults(&mut defaults, &environment.remote.definitions.defaults);
    let template = match &machine.template {
        Some(name) => Some(config.remote.machine_templates.get(name).ok_or_else(|| {
            reference(
                &format!("environments.{environment_name}.remote.machines.{machine_name}.template"),
                name,
            )
        })?),
        None => None,
    };
    let mut address = None;
    let mut port = defaults.port.unwrap_or(22);
    let mut via = defaults.via.unwrap_or_else(|| "direct".to_string());
    let mut canonical_auth = defaults.canonical_auth;
    let mut bootstrap_auth = defaults.bootstrap_auth.unwrap_or_default();
    let mut privilege = setting_value(&defaults.privilege, None);
    let mut stats_script = setting_value(&defaults.stats_script, None);
    let mut provision_profiles = defaults.provision_profiles.unwrap_or_default();
    let mut vars = BTreeMap::new();
    if let Some(template) = template {
        apply_machine_layer(
            template,
            &mut address,
            &mut port,
            &mut via,
            &mut canonical_auth,
            &mut bootstrap_auth,
            &mut privilege,
            &mut stats_script,
            &mut provision_profiles,
            &mut vars,
        );
    }
    apply_machine_layer(
        &machine.settings,
        &mut address,
        &mut port,
        &mut via,
        &mut canonical_auth,
        &mut bootstrap_auth,
        &mut privilege,
        &mut stats_script,
        &mut provision_profiles,
        &mut vars,
    );
    let machine_path = format!("environments.{environment_name}.remote.machines.{machine_name}");
    Ok(ResolvedMachine {
        address: address.ok_or_else(|| missing(&format!("{machine_path}.address")))?,
        port,
        via,
        canonical_auth: canonical_auth
            .ok_or_else(|| missing(&format!("{machine_path}.canonical_auth")))?,
        bootstrap_auth,
        privilege,
        stats_script,
        provision_profiles,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_machine_layer(
    layer: &MachineLayer,
    address: &mut Option<String>,
    port: &mut u16,
    via: &mut String,
    canonical_auth: &mut Option<String>,
    bootstrap_auth: &mut Vec<String>,
    privilege: &mut Option<String>,
    stats_script: &mut Option<String>,
    provision_profiles: &mut Vec<String>,
    vars: &mut BTreeMap<String, String>,
) {
    if let Some(value) = &layer.address {
        *address = Some(value.clone());
    }
    if let Some(value) = layer.port {
        *port = value;
    }
    if let Some(value) = &layer.via {
        *via = value.clone();
    }
    if let Some(value) = &layer.canonical_auth {
        *canonical_auth = Some(value.clone());
    }
    if let Some(value) = &layer.bootstrap_auth {
        *bootstrap_auth = value.clone();
    }
    apply_setting(&layer.privilege, privilege);
    apply_setting(&layer.stats_script, stats_script);
    if let Some(value) = &layer.provision_profiles {
        *provision_profiles = value.clone();
    }
    vars.extend(layer.vars.clone());
}

fn setting_value(setting: &Setting<String>, inherited: Option<String>) -> Option<String> {
    match setting {
        Setting::Inherit => inherited,
        Setting::Value(value) => Some(value.clone()),
        Setting::Null => None,
    }
}

fn apply_setting(setting: &Setting<String>, value: &mut Option<String>) {
    match setting {
        Setting::Inherit => {}
        Setting::Value(new) => *value = Some(new.clone()),
        Setting::Null => *value = None,
    }
}

fn validate_machine(
    definitions: &EffectiveDefinitions,
    machine: &ResolvedMachine,
    path: &str,
) -> Result<(), ConfigError> {
    require_public_key_auth(
        definitions,
        &machine.canonical_auth,
        &format!("{path}.canonical_auth"),
    )?;
    for (index, name) in machine.bootstrap_auth.iter().enumerate() {
        require_name(
            &definitions.auth_profiles,
            name,
            &format!("{path}.bootstrap_auth.{index}"),
        )?;
    }
    if let Some(name) = &machine.privilege {
        require_name(
            &definitions.privilege_profiles,
            name,
            &format!("{path}.privilege"),
        )?;
    }
    if let Some(name) = &machine.stats_script {
        require_name(&definitions.scripts, name, &format!("{path}.stats_script"))?;
    }
    require_route(definitions, &machine.via, &format!("{path}.via"))?;
    for (index, name) in machine.provision_profiles.iter().enumerate() {
        require_name(
            &definitions.provision_profiles,
            name,
            &format!("{path}.provision.profiles.{index}"),
        )?;
    }
    Ok(())
}

fn normalize_address(address: &str) -> String {
    address
        .parse::<IpAddr>()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| address.to_ascii_lowercase())
}

fn validate_profile_references(
    definitions: &EffectiveDefinitions,
    profile: &ProvisionProfile,
    path: &str,
) -> Result<(), ConfigError> {
    for (phase_name, steps) in [
        ("bootstrap", &profile.bootstrap),
        ("secure", &profile.secure),
        ("configure", &profile.configure),
    ] {
        for (index, step) in steps.iter().enumerate() {
            let step_path = format!("{path}.{phase_name}.{index}");
            if let Some(action) = &step.check {
                validate_script_action(definitions, action, &format!("{step_path}.check"))?;
            }
            validate_provision_action(definitions, &step.run, &format!("{step_path}.run"))?;
            if let Some(action) = &step.verify {
                validate_script_action(definitions, action, &format!("{step_path}.verify"))?;
            }
        }
    }
    if let Some(transition) = &profile.ssh_transition {
        for (name, action) in [
            ("prepare", &transition.prepare),
            ("apply", &transition.apply),
            ("validate", &transition.validate),
            ("reload", &transition.reload),
            ("rollback", &transition.rollback),
        ] {
            validate_script_action(
                definitions,
                action,
                &format!("{path}.ssh_transition.{name}"),
            )?;
        }
    }
    for (index, action) in profile.security_verify.iter().enumerate() {
        validate_script_action(
            definitions,
            action,
            &format!("{path}.security.verify.{index}"),
        )?;
    }
    Ok(())
}

fn validate_script_action(
    definitions: &EffectiveDefinitions,
    action: &ScriptAction,
    path: &str,
) -> Result<(), ConfigError> {
    require_name(
        &definitions.scripts,
        &action.script,
        &format!("{path}.script"),
    )?;
    if let Some(privilege) = &action.privilege {
        require_name(
            &definitions.privilege_profiles,
            privilege,
            &format!("{path}.privilege"),
        )?;
    }
    Ok(())
}

fn validate_provision_action(
    definitions: &EffectiveDefinitions,
    action: &ProvisionAction,
    path: &str,
) -> Result<(), ConfigError> {
    match action {
        ProvisionAction::Script(action) => validate_script_action(definitions, action, path),
        ProvisionAction::CopyTo(action) => {
            if let Some(privilege) = &action.privilege {
                require_name(
                    &definitions.privilege_profiles,
                    privilege,
                    &format!("{path}.copy_to.privilege"),
                )?;
            }
            Ok(())
        }
        ProvisionAction::CopyFrom(_) | ProvisionAction::Local(_) => Ok(()),
        ProvisionAction::Reboot(action) => {
            if let Some(privilege) = &action.privilege {
                require_name(
                    &definitions.privilege_profiles,
                    privilege,
                    &format!("{path}.reboot.privilege"),
                )?;
            }
            if let Some(when) = &action.when {
                validate_script_action(definitions, when, &format!("{path}.reboot.when"))?;
            }
            Ok(())
        }
    }
}
