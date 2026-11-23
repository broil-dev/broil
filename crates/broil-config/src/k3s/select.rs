// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::syntax::{bounded_path, invalid};
use crate::{
    LoadedProject,
    discovery::normalize,
    images::select::{EffectiveRegistry, registry_catalogs},
};
use broil_core::{
    error::ConfigError,
    images::{
        RegistryCredential, RegistryDefinition, RegistryPurpose,
        reference::{Endpoint, ImageReference, Origin},
    },
    k3s::*,
    model::{BroilConfig, EnvironmentConfig},
    remote::{DurationValue, MachineConfig, PrivilegeProfile, RemoteScript},
    secrets::SecretsConfig,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug)]
pub struct SelectedMember<'a> {
    pub declaration: &'a Member,
    pub machine: &'a MachineConfig,
}

#[derive(Clone, Debug)]
pub struct EffectiveCertificate<'a> {
    pub declaration: &'a Certificate,
    pub issuer: &'a Issuer,
    pub duration: DurationValue,
    pub renew_before: DurationValue,
}

#[derive(Clone, Debug)]
pub struct SelectedTarget<'a> {
    pub environment: &'a str,
    pub declaration: &'a Target,
    pub config_path: String,
    pub members: Vec<SelectedMember<'a>>,
    pub backup_machine: &'a MachineConfig,
    pub privilege: Option<&'a PrivilegeProfile>,
    pub lifecycle_script: &'a RemoteScript,
    pub secrets: SecretsConfig,
    pub registries: BTreeMap<String, EffectiveRegistry>,
    pub bootstrap_manifest: PathBuf,
    pub bootstrap_bundle: Option<PathBuf>,
    pub agent_wave_size: u8,
    pub operation_timeout: DurationValue,
    pub step_timeout: DurationValue,
    pub backup_max_age: DurationValue,
    pub registry_backup_max_age: Option<DurationValue>,
    pub cluster_domain: &'a str,
    pub flannel: Flannel,
    pub certificates: BTreeMap<String, EffectiveCertificate<'a>>,
    pub node_registry_fallbacks: Vec<RegistryFallback>,
}

fn default_duration(value: &Option<DurationValue>, source: &str, seconds: u64) -> DurationValue {
    value
        .clone()
        .unwrap_or_else(|| DurationValue::builtin(source, seconds))
}

pub fn select<'a>(
    project: &'a LoadedProject,
    environment: Option<&OsStr>,
    target: &str,
) -> Result<SelectedTarget<'a>, ConfigError> {
    let name = environment
        .and_then(OsStr::to_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("BROIL_ENV", "a nonempty exact UTF-8 environment name"))?;
    let (environment, env) = project
        .config
        .environments
        .get_key_value(name)
        .ok_or_else(|| invalid("BROIL_ENV", "a declared environment name"))?;
    let (target, t) = env.k3s.get_key_value(target).ok_or_else(|| {
        invalid(
            &format!("environments.{environment}.k3s"),
            "a declared target name",
        )
    })?;
    let path = format!("environments.{environment}.k3s.{target}");
    validate_ownership(&project.config)?;
    let members = t
        .members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let machine = env.remote.machines.get(&m.machine).ok_or_else(|| {
                invalid(
                    &format!("{path}.members.{i}.machine"),
                    "a machine in the selected environment",
                )
            })?;
            Ok(SelectedMember {
                declaration: m,
                machine,
            })
        })
        .collect::<Result<Vec<_>, ConfigError>>()?;
    let backup_machine = env.remote.machines.get(&t.backup.machine).ok_or_else(|| {
        invalid(
            &format!("{path}.backup.machine"),
            "a machine in the selected environment",
        )
    })?;
    let root = &project.config.remote.definitions;
    let local = &env.remote.definitions;
    let privilege = t
        .privilege
        .as_ref()
        .map(|name| {
            local
                .privilege_profiles
                .get(name)
                .or_else(|| root.privilege_profiles.get(name))
                .ok_or_else(|| {
                    invalid(
                        &format!("{path}.privilege"),
                        "an effective privilege profile",
                    )
                })
        })
        .transpose()?;
    let lifecycle_script = local
        .scripts
        .get(&t.lifecycle_script)
        .or_else(|| root.scripts.get(&t.lifecycle_script))
        .ok_or_else(|| {
            invalid(
                &format!("{path}.lifecycle_script"),
                "an effective remote script",
            )
        })?;
    let catalogs = registry_catalogs(project, Some(environment));
    let mut registries = BTreeMap::new();
    let mut consume = |name: &str, p: &str| -> Result<&EffectiveRegistry, ConfigError> {
        let r = catalogs
            .get(name)
            .ok_or_else(|| invalid(p, "an effective registry endpoint"))?;
        if let Some(ca) = &r.declaration.ca {
            controller_path(&project.broil_root, ca, &format!("{}.ca", r.config_path))?;
        }
        registries.insert(name.to_string(), r.clone());
        Ok(r)
    };
    let managed_endpoint = t
        .registry
        .as_ref()
        .map(|r| {
            let endpoint = consume(&r.endpoint, &format!("{path}.registry.endpoint"))?;
            validate_managed(t, r, &endpoint.declaration, &path)?;
            Ok(endpoint.declaration.endpoint.origin())
        })
        .transpose()?;
    let mut origins = BTreeSet::new();
    for (i, node) in t.node_registries.iter().enumerate() {
        let p = format!("{path}.node_registries.{i}");
        let r = consume(&node.registry, &format!("{p}.registry"))?;
        let origin = r.declaration.endpoint.origin();
        if !origins.insert(origin.clone()) {
            return Err(invalid(&p, "a distinct registry origin"));
        }
        validate_repositories(
            &node.repositories,
            &r.declaration.endpoint,
            &format!("{p}.repositories"),
        )?;
        if managed_endpoint.as_ref() == Some(&origin) {
            let managed = t.registry.as_ref().expect("selected managed origin");
            let principal = managed
                .authentication
                .principals
                .get(&node.username)
                .ok_or_else(|| {
                    invalid(&format!("{p}.username"), "a managed node-pull principal")
                })?;
            if principal.purpose != PrincipalPurpose::NodePull
                || principal.password != node.password
                || !same_set(&principal.repositories, &node.repositories)
            {
                return Err(invalid(
                    &p,
                    "the managed node-pull principal's exact references and repositories",
                ));
            }
        }
    }
    let backup_max_age = default_duration(&t.backup.max_age, "24h", 24 * 3600);
    let certificates = t
        .infrastructure
        .certificates
        .iter()
        .map(|(name, c)| {
            (
                name.clone(),
                EffectiveCertificate {
                    declaration: c,
                    issuer: &t.infrastructure.issuers[&c.issuer],
                    duration: default_duration(&c.duration, "2160h", 2160 * 3600),
                    renew_before: default_duration(&c.renew_before, "720h", 720 * 3600),
                },
            )
        })
        .collect();
    Ok(SelectedTarget {
        environment,
        declaration: t,
        config_path: path.clone(),
        members,
        backup_machine,
        privilege,
        lifecycle_script,
        secrets: project.config.secrets.overlay(&env.secrets),
        registries,
        bootstrap_manifest: controller_path(
            &project.broil_root,
            &t.bootstrap.manifest,
            &format!("{path}.bootstrap.manifest"),
        )?,
        bootstrap_bundle: t
            .bootstrap
            .bundle
            .as_ref()
            .map(|p| controller_path(&project.broil_root, p, &format!("{path}.bootstrap.bundle")))
            .transpose()?,
        agent_wave_size: t.agent_wave_size.unwrap_or(1),
        operation_timeout: default_duration(&t.operation_timeout, "2h", 7200),
        step_timeout: default_duration(&t.step_timeout, "15m", 900),
        registry_backup_max_age: t.registry.as_ref().map(|r| {
            r.backup_max_age
                .clone()
                .unwrap_or_else(|| backup_max_age.clone())
        }),
        backup_max_age,
        cluster_domain: t
            .network
            .cluster_domain
            .as_deref()
            .unwrap_or("cluster.local"),
        flannel: t.network.flannel.unwrap_or(Flannel::Vxlan),
        certificates,
        node_registry_fallbacks: t
            .node_registries
            .iter()
            .map(|r| r.fallback.unwrap_or(RegistryFallback::Disabled))
            .collect(),
    })
}

fn controller_path(root: &Path, declared: &str, path: &str) -> Result<PathBuf, ConfigError> {
    let result = normalize(&root.join(declared));
    if !bounded_path(declared, false)
        || result.as_os_str().as_encoded_bytes().len() > 4096
        || result
            .components()
            .any(|c| c.as_os_str().as_encoded_bytes().len() > 255)
    {
        return Err(invalid(path, "a bounded controller path"));
    }
    Ok(result)
}

fn same_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|v| b.contains(v))
}

fn validate_repositories(
    repos: &[String],
    endpoint: &Endpoint,
    path: &str,
) -> Result<(), ConfigError> {
    for (i, repo) in repos.iter().enumerate() {
        if !ImageReference::parse(repo).is_some_and(|r| endpoint.matches_repository(&r)) {
            return Err(invalid(
                &format!("{path}.{i}"),
                "a repository on this endpoint authority",
            ));
        }
    }
    Ok(())
}

fn validate_managed(
    t: &Target,
    managed: &ManagedRegistry,
    endpoint: &RegistryDefinition,
    path: &str,
) -> Result<(), ConfigError> {
    let path = format!("{path}.registry");
    if endpoint.endpoint.scheme != "https" {
        return Err(invalid(
            &format!("{path}.endpoint"),
            "HTTPS for a managed origin",
        ));
    }
    let certificate = &t.infrastructure.certificates[&managed.certificate];
    if !certificate
        .dns_names
        .contains(&endpoint.endpoint.authority.host)
    {
        return Err(invalid(
            &format!("{path}.certificate"),
            "covering the managed endpoint host",
        ));
    }
    for (name, p) in &managed.authentication.principals {
        validate_repositories(
            &p.repositories,
            &endpoint.endpoint,
            &format!("{path}.authentication.principals.{name}.repositories"),
        )?;
    }
    let auth = endpoint.auth.get(&RegistryPurpose::Push).ok_or_else(|| {
        invalid(
            &format!("{path}.endpoint"),
            "a catalog publication entry matching a managed principal",
        )
    })?;
    let RegistryCredential::Password {
        username,
        password,
        token_service,
    } = &auth.credential
    else {
        return Err(invalid(
            &format!("{path}.endpoint"),
            "an explicit publication username/password and same-origin token policy",
        ));
    };
    let principal = managed
        .authentication
        .principals
        .get(username)
        .ok_or_else(|| {
            invalid(
                &format!("{path}.endpoint"),
                "a declared publication principal",
            )
        })?;
    if principal.purpose != PrincipalPurpose::Publication
        || &principal.password != password
        || !same_set(&principal.repositories, &auth.repositories)
        || token_service
            .as_ref()
            .is_none_or(|s| Endpoint::token_realm(&s.realm.supplied, &endpoint.endpoint).is_none())
    {
        return Err(invalid(
            &format!("{path}.endpoint"),
            "the publication principal's exact credential, repositories and same-origin token policy",
        ));
    }
    Ok(())
}

fn registry<'a>(
    config: &'a BroilConfig,
    env: &'a EnvironmentConfig,
    name: &str,
) -> Option<&'a RegistryDefinition> {
    env.registries
        .get(name)
        .or_else(|| config.registries.get(name))
}

const RESERVED_TREES: [&str; 10] = [
    "/etc/rancher",
    "/run",
    "/var/lib/rancher",
    "/var/lib/kubelet",
    "/var/lib/cni",
    "/var/log/pods",
    "/var/log/containers",
    "/var/lib/broil",
    "/var/lib/broil-k3s-incoming",
    "/root/.broil",
];

pub(crate) fn validate_ownership(config: &BroilConfig) -> Result<(), ConfigError> {
    let mut endpoints: BTreeMap<Origin, String> = BTreeMap::new();
    let mut storage: Vec<(&str, &str, &str, String)> = Vec::new();
    for (env_name, env) in &config.environments {
        let mut machines = BTreeMap::new();
        for (name, t) in &env.k3s {
            let path = format!("environments.{env_name}.k3s.{name}");
            for (i, m) in t.members.iter().enumerate() {
                let p = format!("{path}.members.{i}.machine");
                if let Some(other) = machines.insert(&m.machine, p.clone()) {
                    return Err(invalid(
                        &p,
                        &format!("owned by only one target; conflicts with {other}"),
                    ));
                }
            }
            let mut origins =
                BTreeSet::from([t.api.endpoint.origin(), t.registration_endpoint.origin()]);
            if let Some(managed) = &t.registry {
                if let Some(endpoint) = registry(config, env, &managed.endpoint) {
                    let origin = endpoint.endpoint.origin();
                    if !origins.insert(origin) {
                        return Err(invalid(
                            &format!("{path}.registry.endpoint"),
                            "separate from API/registration endpoint ownership",
                        ));
                    }
                }
                if let Some(root) = RESERVED_TREES
                    .iter()
                    .find(|root| Path::new(&managed.storage.path).starts_with(root))
                {
                    return Err(invalid(
                        &format!("{path}.registry.storage.path"),
                        &format!(
                            "disjoint storage ownership; conflicts with the runtime- or uninstall-owned tree {root}"
                        ),
                    ));
                }
                let member = t
                    .members
                    .iter()
                    .find(|m| m.name == managed.member)
                    .expect("validated member");
                storage.push((
                    env_name,
                    &member.machine,
                    &managed.storage.path,
                    format!("{path}.registry.storage.path"),
                ));
            }
            storage.push((
                env_name,
                &t.backup.machine,
                &t.backup.path,
                format!("{path}.backup.path"),
            ));
            for origin in origins {
                if let Some(other) = endpoints.insert(origin, path.clone()) {
                    return Err(invalid(
                        &path,
                        &format!("distinct endpoint/port ownership; conflicts with {other}"),
                    ));
                }
            }
        }
    }
    for (i, (env, machine, path, location)) in storage.iter().enumerate() {
        for (other_env, other_machine, other_path, other_location) in &storage[..i] {
            if env == other_env
                && machine == other_machine
                && (Path::new(path).starts_with(other_path)
                    || Path::new(other_path).starts_with(path))
            {
                return Err(invalid(
                    location,
                    &format!("disjoint storage ownership; conflicts with {other_location}"),
                ));
            }
        }
    }
    Ok(())
}
