// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use super::syntax::{dns, duration, label_key, label_value};
use crate::raw::RawValue;
use broil_core::{
    applications::*,
    error::{ConfigError, SchemaError},
    images::{SecretReference, valid_name},
    model::EnvironmentConfig,
    remote::DurationValue,
    secrets::{valid_export_name, valid_key, valid_set},
};

const PROFILE: &str = include_str!("../../../../tools/k3s/action-profile.json");
const RESERVED_NAMESPACES: [&str; 4] = ["kube-system", "kube-public", "kube-node-lease", "default"];
const HOOK: &str = "a hook stage of at most 16 hooks";

fn invalid(path: &str, expected: &str) -> ConfigError {
    ConfigError::Schema(SchemaError::InvalidApplicationValue {
        key_path: path.into(),
        expected: expected.into(),
    })
}

fn unknown(path: &str) -> ConfigError {
    ConfigError::Schema(SchemaError::UnknownKey {
        key_path: path.into(),
    })
}

fn entries<'a>(v: &'a RawValue, path: &str) -> Result<Vec<(&'a str, &'a RawValue)>, ConfigError> {
    let RawValue::Map(pairs) = v else {
        return Err(invalid(path, "a mapping"));
    };
    pairs
        .iter()
        .map(|(k, v)| match k {
            RawValue::Str(k) => Ok((k.as_str(), v)),
            _ => Err(invalid(path, "a mapping with string keys")),
        })
        .collect()
}

fn string<'a>(v: &'a RawValue, path: &str, expected: &str) -> Result<&'a str, ConfigError> {
    match v {
        RawValue::Str(s) if !s.is_empty() && !s.contains('\0') => Ok(s),
        _ => Err(invalid(path, expected)),
    }
}

fn list<'a>(v: &'a RawValue, path: &str, expected: &str) -> Result<&'a [RawValue], ConfigError> {
    match v {
        RawValue::Seq(items) => Ok(items),
        _ => Err(invalid(path, expected)),
    }
}

fn required<T>(v: Option<T>, path: &str) -> Result<T, ConfigError> {
    v.ok_or_else(|| invalid(path, "present"))
}

fn bounded_duration(v: &RawValue, path: &str) -> Result<DurationValue, ConfigError> {
    duration(v, path, 2).map_err(|_| invalid(path, "a duration in s, m or h of at most 2h"))
}

pub(crate) fn applications(
    v: &RawValue,
    path: &str,
) -> Result<BTreeMap<String, Application>, ConfigError> {
    if matches!(v, RawValue::Null) {
        return Ok(BTreeMap::new());
    }
    let mut applications = BTreeMap::new();
    for (name, v) in entries(v, path)? {
        let p = format!("{path}.{name}");
        if !valid_name(name) {
            return Err(invalid(&p, "a catalog name"));
        }
        applications.insert(name.to_string(), application(v, &p)?);
    }
    Ok(applications)
}

fn application(v: &RawValue, path: &str) -> Result<Application, ConfigError> {
    let (mut target, mut namespace, mut manifests, mut render) = (None, None, None, None);
    let (mut nodes, mut health_timeout) = (DeliveryNodes::All, DurationValue::builtin("10m", 600));
    let (mut before_apply, mut health, mut secrets) = (Vec::new(), Vec::new(), Vec::new());
    for (k, v) in entries(v, path)? {
        let p = format!("{path}.{k}");
        match k {
            "target" => target = Some(string(v, &p, "a k3s target name")?.to_string()),
            "namespace" => namespace = Some(parse_namespace(v, &p)?),
            "manifests" => manifests = Some(parse_manifests(v, &p)?),
            "render" => render = Some(hook(v, &p, Stage::Render)?),
            "delivery" => {
                for (k, v) in entries(v, &p)? {
                    let p = format!("{p}.{k}");
                    match k {
                        "nodes" => nodes = delivery_nodes(v, &p)?,
                        _ => return Err(unknown(&p)),
                    }
                }
            }
            "health" => {
                for (k, v) in entries(v, &p)? {
                    let p = format!("{p}.{k}");
                    match k {
                        "timeout" => health_timeout = bounded_duration(v, &p)?,
                        _ => return Err(unknown(&p)),
                    }
                }
            }
            "hooks" => {
                for (k, v) in entries(v, &p)? {
                    let p = format!("{p}.{k}");
                    let (stage, hooks) = match k {
                        "before_apply" => (Stage::BeforeApply, &mut before_apply),
                        "health" => (Stage::Health, &mut health),
                        _ => return Err(unknown(&p)),
                    };
                    let items = list(v, &p, HOOK)?;
                    if items.len() > 16 {
                        return Err(invalid(&p, HOOK));
                    }
                    *hooks = items
                        .iter()
                        .enumerate()
                        .map(|(i, v)| hook(v, &format!("{p}[{i}]"), stage))
                        .collect::<Result<_, _>>()?;
                }
            }
            "secrets" => secrets = parse_secrets(v, &p)?,
            _ => return Err(unknown(&p)),
        }
    }
    let target = required(target, &format!("{path}.target"))?;
    let namespace = required(namespace, &format!("{path}.namespace"))?;
    let source = match (manifests, render) {
        (Some(files), None) => ManifestSource::Manifests(files),
        (None, Some(hook)) => ManifestSource::Render(hook),
        _ => return Err(invalid(path, "exactly one of manifests or render")),
    };
    let mut names = BTreeSet::new();
    for (stage, hooks) in [("before_apply", &before_apply), ("health", &health)] {
        for (i, hook) in hooks.iter().enumerate() {
            if !names.insert(hook.name.as_str()) {
                return Err(invalid(
                    &format!("{path}.hooks.{stage}[{i}].name"),
                    "unique within the application",
                ));
            }
        }
    }
    Ok(Application {
        target,
        namespace,
        source,
        delivery_nodes: nodes,
        health_timeout,
        before_apply,
        health,
        secrets,
    })
}

fn consumer_namespaces() -> &'static [String] {
    static NAMESPACES: OnceLock<Vec<String>> = OnceLock::new();
    NAMESPACES.get_or_init(|| {
        let profile = crate::raw::parse_str(PROFILE, Path::new("tools/k3s/action-profile.json"))
            .ok()
            .flatten()
            .expect("the pinned action profile parses");
        let Some(RawValue::Map(pairs)) = profile.get("consumer_namespaces") else {
            panic!("the pinned action profile names its consumer namespaces");
        };
        pairs
            .iter()
            .map(|(_, v)| match v {
                RawValue::Str(namespace) => namespace.clone(),
                _ => panic!("a consumer namespace is a string"),
            })
            .collect()
    })
}

fn parse_namespace(v: &RawValue, path: &str) -> Result<String, ConfigError> {
    let expected = "a DNS label outside the reserved and Broil-owned namespaces";
    let namespace = string(v, path, expected)?;
    if namespace.len() > 63
        || namespace.contains('.')
        || !dns(namespace)
        || RESERVED_NAMESPACES.contains(&namespace)
        || consumer_namespaces().iter().any(|n| n == namespace)
    {
        return Err(invalid(path, expected));
    }
    Ok(namespace.to_string())
}

fn parse_manifests(v: &RawValue, path: &str) -> Result<Vec<String>, ConfigError> {
    let items = list(v, path, "a list of at least one path")?;
    if items.is_empty() {
        return Err(invalid(path, "a list of at least one path"));
    }
    items
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let expected = "a BROIL_ROOT-relative path without empty, . or .. components";
            let p = format!("{path}[{i}]");
            let file = string(v, &p, expected)?;
            let body = file.strip_suffix('/').unwrap_or(file);
            if file.starts_with('/')
                || body.is_empty()
                || body.split('/').any(|c| matches!(c, "" | "." | ".."))
            {
                return Err(invalid(&p, expected));
            }
            Ok(file.to_string())
        })
        .collect()
}

fn delivery_nodes(v: &RawValue, path: &str) -> Result<DeliveryNodes, ConfigError> {
    let expected = "all, {members: [...]} or {labels: {...}}";
    if let RawValue::Str(s) = v {
        return match s.as_str() {
            "all" => Ok(DeliveryNodes::All),
            _ => Err(invalid(path, expected)),
        };
    }
    let mut choice = None;
    for (k, v) in entries(v, path).map_err(|_| invalid(path, expected))? {
        let p = format!("{path}.{k}");
        let parsed = match k {
            "members" => {
                let members = list(v, &p, "1–128 distinct members")?;
                if !(1..=128).contains(&members.len()) {
                    return Err(invalid(&p, "1–128 distinct members"));
                }
                let mut seen = BTreeSet::new();
                let mut names = Vec::new();
                for (i, v) in members.iter().enumerate() {
                    let item = format!("{p}[{i}]");
                    let name = string(v, &item, "a member name")?;
                    if !seen.insert(name) {
                        return Err(invalid(&item, "a distinct member"));
                    }
                    names.push(name.to_string());
                }
                DeliveryNodes::Members(names)
            }
            "labels" => {
                let pairs = entries(v, &p)?;
                if !(1..=16).contains(&pairs.len()) {
                    return Err(invalid(&p, "1–16 label pairs"));
                }
                let mut labels = BTreeMap::new();
                for (key, v) in pairs {
                    let item = format!("{p}.{key}");
                    if !label_key(key) {
                        return Err(invalid(&item, "a label key"));
                    }
                    let value = match v {
                        RawValue::Str(s) if label_value(s) => s.clone(),
                        _ => return Err(invalid(&item, "a label value")),
                    };
                    labels.insert(key.to_string(), value);
                }
                DeliveryNodes::Labels(labels)
            }
            _ => return Err(unknown(&p)),
        };
        if choice.replace(parsed).is_some() {
            return Err(invalid(path, expected));
        }
    }
    choice.ok_or_else(|| invalid(path, expected))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Render,
    BeforeApply,
    Health,
}

fn hook(v: &RawValue, path: &str, stage: Stage) -> Result<Hook, ConfigError> {
    let (mut name, mut location, mut argv, mut timeout) = (None, None, None, None);
    let (mut repeatable, mut secrets) = (false, None);
    for (k, v) in entries(v, path)? {
        let p = format!("{path}.{k}");
        match k {
            "name" if stage != Stage::Render => {
                name = Some(
                    string(v, &p, "a catalog name")
                        .ok()
                        .filter(|s| valid_name(s))
                        .ok_or_else(|| invalid(&p, "a catalog name"))?
                        .to_string(),
                )
            }
            "location" => {
                location = Some(match string(v, &p, "controller or a machine name")? {
                    "controller" => HookLocation::Controller,
                    _ if stage == Stage::Render => return Err(invalid(&p, "controller")),
                    machine => HookLocation::Machine(machine.to_string()),
                })
            }
            "argv" => argv = Some(parse_argv(v, &p)?),
            "timeout" => timeout = Some(bounded_duration(v, &p)?),
            "repeatable" if stage == Stage::BeforeApply => {
                repeatable = match v {
                    RawValue::Bool(b) => *b,
                    _ => return Err(invalid(&p, "a boolean")),
                }
            }
            "secrets" if stage != Stage::Render => secrets = Some(variables(v, &p)?),
            _ => return Err(unknown(&p)),
        }
    }
    let name = match stage {
        Stage::Render => String::new(),
        _ => required(name, &format!("{path}.name"))?,
    };
    let location = required(location, &format!("{path}.location"))?;
    let argv = required(argv, &format!("{path}.argv"))?;
    let timeout = required(timeout, &format!("{path}.timeout"))?;
    if secrets.is_some() && location != HookLocation::Controller {
        return Err(invalid(
            &format!("{path}.secrets"),
            "absent unless location is controller",
        ));
    }
    Ok(Hook {
        name,
        location,
        argv,
        timeout,
        repeatable,
        secrets: secrets.unwrap_or_default(),
    })
}

fn parse_argv(v: &RawValue, path: &str) -> Result<Vec<String>, ConfigError> {
    let expected = "1–64 strings of at most 65536 bytes together";
    let items = list(v, path, expected)?;
    if !(1..=64).contains(&items.len()) {
        return Err(invalid(path, expected));
    }
    let mut argv = Vec::with_capacity(items.len());
    let mut bytes = 0usize;
    for (i, v) in items.iter().enumerate() {
        let RawValue::Str(item) = v else {
            return Err(invalid(&format!("{path}[{i}]"), "a NUL-free string"));
        };
        if item.contains('\0') {
            return Err(invalid(&format!("{path}[{i}]"), "a NUL-free string"));
        }
        bytes += item.len();
        if bytes > 65536 {
            return Err(invalid(path, expected));
        }
        argv.push(item.clone());
    }
    Ok(argv)
}

fn variables(v: &RawValue, path: &str) -> Result<Vec<(String, SecretReference)>, ConfigError> {
    let pairs = entries(v, path)?;
    if pairs.len() > 32 {
        return Err(invalid(path, "at most 32 variables"));
    }
    pairs
        .into_iter()
        .map(|(variable, v)| {
            let p = format!("{path}.{variable}");
            if !valid_export_name(variable) || variable.starts_with("BROIL_") {
                return Err(invalid(
                    &p,
                    "a variable name outside Broil's reserved names",
                ));
            }
            Ok((variable.to_string(), reference(v, &p)?))
        })
        .collect()
}

fn reference(v: &RawValue, path: &str) -> Result<SecretReference, ConfigError> {
    let expected = "a secret reference {set, key}";
    let (mut set, mut key) = (None, None);
    for (k, v) in entries(v, path).map_err(|_| invalid(path, expected))? {
        let p = format!("{path}.{k}");
        match k {
            "set" => {
                set = Some(
                    string(v, &p, "an explicit project/set reference")
                        .ok()
                        .filter(|s| valid_set(s, true))
                        .ok_or_else(|| invalid(&p, "an explicit project/set reference"))?
                        .to_string(),
                )
            }
            "key" => {
                key = Some(match v {
                    RawValue::Str(s) if valid_key(s) => s.clone(),
                    _ => return Err(invalid(&p, "an addressable literal secret key")),
                })
            }
            _ => return Err(unknown(&p)),
        }
    }
    match (set, key) {
        (Some(set), Some(key)) => Ok(SecretReference { set, key }),
        _ => Err(invalid(path, expected)),
    }
}

fn parse_secrets(v: &RawValue, path: &str) -> Result<Vec<ApplicationSecret>, ConfigError> {
    let pairs = entries(v, path)?;
    if pairs.len() > 32 {
        return Err(invalid(path, "at most 32 Secrets"));
    }
    pairs
        .into_iter()
        .map(|(name, v)| {
            let p = format!("{path}.{name}");
            if !dns(name) {
                return Err(invalid(&p, "a DNS subdomain of at most 253 bytes"));
            }
            let data = entries(v, &p)?;
            if !(1..=64).contains(&data.len()) {
                return Err(invalid(&p, "1–64 data keys"));
            }
            let keys = data
                .into_iter()
                .map(|(data_key, v)| {
                    let item = format!("{p}.{data_key}");
                    if data_key.is_empty()
                        || data_key.len() > 253
                        || !data_key
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c))
                    {
                        return Err(invalid(
                            &item,
                            "a data key of [-._a-zA-Z0-9] of at most 253 bytes",
                        ));
                    }
                    Ok((data_key.to_string(), reference(v, &item)?))
                })
                .collect::<Result<_, _>>()?;
            Ok(ApplicationSecret {
                name: name.to_string(),
                keys,
            })
        })
        .collect()
}

pub(crate) fn cross_check(environment: &EnvironmentConfig, env: &str) -> Result<(), ConfigError> {
    for (name, application) in &environment.applications {
        let path = format!("environments.{env}.applications.{name}");
        let Some(target) = environment.k3s.get(&application.target) else {
            return Err(invalid(
                &format!("{path}.target"),
                &format!("a k3s target of environment {env}"),
            ));
        };
        if let DeliveryNodes::Members(members) = &application.delivery_nodes {
            for (i, member) in members.iter().enumerate() {
                if !target.members.iter().any(|m| &m.name == member) {
                    return Err(invalid(
                        &format!("{path}.delivery.nodes.members[{i}]"),
                        &format!("a member of target {}", application.target),
                    ));
                }
            }
        }
        for (stage, hooks) in [
            ("before_apply", &application.before_apply),
            ("health", &application.health),
        ] {
            for (i, hook) in hooks.iter().enumerate() {
                if let HookLocation::Machine(machine) = &hook.location {
                    if !environment.remote.machines.contains_key(machine) {
                        return Err(invalid(
                            &format!("{path}.hooks.{stage}[{i}].location"),
                            &format!("controller or a machine of environment {env}"),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
