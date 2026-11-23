// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::syntax::*;
use crate::{images::secret_reference, raw::RawValue};
use broil_core::{error::ConfigError, images::reference::ImageReference, k3s::*};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn managed(v: &RawValue, path: &str) -> Result<Option<ManagedRegistry>, ConfigError> {
    let fields = pairs(v, path, true)?;
    if fields.is_empty() {
        return Ok(None);
    }
    let (
        mut service_name,
        mut endpoint,
        mut version,
        mut image,
        mut member,
        mut storage,
        mut certificate,
        mut authentication,
        mut backup_max_age,
    ) = (None, None, None, None, None, None, None, None, None);
    for (k, v) in fields {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "name" => service_name = Some(name(v, &p)?),
            "endpoint" => endpoint = Some(name(v, &p)?),
            "version" => {
                version = Some(checked(
                    v,
                    &p,
                    exact_version,
                    "an exact Distribution version",
                )?)
            }
            "image" => {
                let r = ImageReference::parse(&nonempty(v, &p)?)
                    .filter(|r| {
                        r.explicit_authority
                            && r.digest.is_some()
                            && r.tag.is_none()
                            && r.supplied
                                == format!(
                                    "{}@{}",
                                    r.repository,
                                    r.digest.as_deref().unwrap_or_default()
                                )
                    })
                    .ok_or_else(|| invalid(&p, "a normalized digest-pinned image"))?;
                image = Some(r);
            }
            "member" => member = Some(checked(v, &p, dns, "a member node name")?),
            "storage" => storage = Some(parse_storage(v, &p)?),
            "certificate" => certificate = Some(name(v, &p)?),
            "authentication" => authentication = Some(auth(v, &p)?),
            "backup_max_age" => backup_max_age = Some(duration(v, &p, 168)?),
            _ => return Err(unknown(&p)),
        }
    }
    Ok(Some(ManagedRegistry {
        name: required(service_name, &format!("{path}.name"))?,
        endpoint: required(endpoint, &format!("{path}.endpoint"))?,
        version: required(version, &format!("{path}.version"))?,
        image: required(image, &format!("{path}.image"))?,
        member: required(member, &format!("{path}.member"))?,
        storage: required(storage, &format!("{path}.storage"))?,
        certificate: required(certificate, &format!("{path}.certificate"))?,
        authentication: required(authentication, &format!("{path}.authentication"))?,
        backup_max_age,
    }))
}

fn parse_storage(v: &RawValue, path: &str) -> Result<Storage, ConfigError> {
    let (mut directory, mut capacity_mib) = (None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "path" => directory = Some(path_value(v, &p, true)?),
            "capacity_mib" => capacity_mib = Some(integer(v, &p, 2147483647)? as u32),
            _ => return Err(unknown(&p)),
        }
    }
    Ok(Storage {
        path: required(directory, &format!("{path}.path"))?,
        capacity_mib: required(capacity_mib, &format!("{path}.capacity_mib"))?,
    })
}

fn auth(v: &RawValue, path: &str) -> Result<Authentication, ConfigError> {
    let (mut profile, mut principals, mut signing_key, mut signing_certificate) =
        (None, None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "profile" => profile = Some(name(v, &p)?),
            "principals" => {
                if pairs(v, &p, false)?.is_empty() {
                    return Err(invalid(&p, "a nonempty principal mapping"));
                }
                principals = Some(named(v, &p, principal)?);
            }
            "signing_key" => signing_key = Some(secret_reference(v, &p)?),
            "signing_certificate" => signing_certificate = Some(nonempty(v, &p)?),
            _ => return Err(unknown(&p)),
        }
    }
    let principals: BTreeMap<String, Principal> =
        required(principals, &format!("{path}.principals"))?;
    let purposes: BTreeSet<_> = principals.values().map(|p| p.purpose).collect();
    if purposes.len() != 3 {
        return Err(invalid(
            &format!("{path}.principals"),
            "publication, node-pull and maintenance principals",
        ));
    }
    let mut credentials = BTreeMap::new();
    for (name, p) in &principals {
        if credentials
            .insert((&p.password.set, &p.password.key), p.purpose)
            .is_some_and(|purpose| purpose != p.purpose)
        {
            return Err(invalid(
                &format!("{path}.principals.{name}.password"),
                "a credential distinct from other purposes",
            ));
        }
    }
    Ok(Authentication {
        profile: required(profile, &format!("{path}.profile"))?,
        principals,
        signing_key,
        signing_certificate,
    })
}

fn principal(v: &RawValue, path: &str) -> Result<Principal, ConfigError> {
    let (mut purpose, mut password, mut repos, mut actions) = (None, None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "purpose" => {
                purpose = Some(match text(v, &p)?.as_str() {
                    "publication" => PrincipalPurpose::Publication,
                    "node-pull" => PrincipalPurpose::NodePull,
                    "maintenance" => PrincipalPurpose::Maintenance,
                    _ => return Err(invalid(&p, "a supported principal purpose")),
                })
            }
            "password" => password = Some(secret_reference(v, &p)?),
            "repositories" => repos = Some(repositories(v, &p)?),
            "actions" => {
                actions = Some(
                    strings(v, &p, false, |s| matches!(s, "pull" | "push" | "delete"))?
                        .iter()
                        .map(|s| match s.as_str() {
                            "pull" => RegistryAction::Pull,
                            "push" => RegistryAction::Push,
                            _ => RegistryAction::Delete,
                        })
                        .collect::<Vec<_>>(),
                )
            }
            _ => return Err(unknown(&p)),
        }
    }
    let purpose = required(purpose, &format!("{path}.purpose"))?;
    let actions = required(actions, &format!("{path}.actions"))?;
    let allowed: &[RegistryAction] = match purpose {
        PrincipalPurpose::Publication => &[RegistryAction::Pull, RegistryAction::Push],
        PrincipalPurpose::NodePull => &[RegistryAction::Pull],
        PrincipalPurpose::Maintenance => &[RegistryAction::Pull, RegistryAction::Delete],
    };
    if actions.len() != allowed.len() || !allowed.iter().all(|a| actions.contains(a)) {
        return Err(invalid(
            &format!("{path}.actions"),
            "the exact permissions for this purpose",
        ));
    }
    Ok(Principal {
        purpose,
        password: required(password, &format!("{path}.password"))?,
        repositories: required(repos, &format!("{path}.repositories"))?,
        actions,
    })
}

pub(super) fn node(v: &RawValue, path: &str) -> Result<NodeRegistry, ConfigError> {
    let (mut registry, mut repos, mut username, mut password, mut fallback) =
        (None, None, None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "registry" => registry = Some(name(v, &p)?),
            "repositories" => repos = Some(repositories(v, &p)?),
            "username" => username = Some(name(v, &p)?),
            "password" => password = Some(secret_reference(v, &p)?),
            "fallback" => {
                fallback = Some(match text(v, &p)?.as_str() {
                    "disabled" => RegistryFallback::Disabled,
                    "same-origin" => RegistryFallback::SameOrigin,
                    _ => return Err(invalid(&p, "disabled or same-origin")),
                })
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(NodeRegistry {
        registry: required(registry, &format!("{path}.registry"))?,
        repositories: required(repos, &format!("{path}.repositories"))?,
        username: required(username, &format!("{path}.username"))?,
        password: required(password, &format!("{path}.password"))?,
        fallback,
    })
}
