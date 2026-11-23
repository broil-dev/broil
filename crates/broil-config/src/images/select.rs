// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use broil_core::error::ConfigError;
use broil_core::images::reference::{Endpoint, ImageIdentity, ImageReference, Origin};
use broil_core::images::*;
use broil_core::remote::{MachineConfig, PrivilegeProfile};

use super::{ambiguous, invalid};
use crate::{LoadedProject, discovery::normalize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveImage {
    pub declaration: ImageDefinition,
    pub config_path: String,
    pub context: PathBuf,
    pub dockerfile: PathBuf,
    pub contexts: BTreeMap<String, PathBuf>,
    pub ssh: BTreeMap<String, PathBuf>,
    pub platforms: Vec<String>,
    pub output_kind: OutputKind,
    pub output_path: Option<PathBuf>,
    pub builder_cache: bool,
    pub refresh: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveBuilder {
    pub declaration: BuilderDefinition,
    pub config_path: String,
    pub ca: PathBuf,
    pub server_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveRegistry {
    pub declaration: RegistryDefinition,
    pub config_path: String,
    pub ca: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CredentialScope {
    pub endpoint: Origin,
    pub repository: String,
    pub purpose: RegistryPurpose,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialCandidate {
    pub registry: String,
    pub config_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryPolicy {
    pub registry: Option<String>,
    pub endpoint: Endpoint,
    pub ca: Option<PathBuf>,
    pub credential: Option<RegistryCredential>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProducerMatch {
    External,
    Producer {
        name: String,
        platform_declared: bool,
    },
    Ambiguous,
    PinMismatch,
}

#[derive(Clone, Debug)]
pub struct SelectedCatalogs<'a> {
    project: &'a LoadedProject,
    pub tools: ToolsDefinition,
    pub environment: Option<String>,
    pub images: BTreeMap<String, EffectiveImage>,
    pub builders: BTreeMap<String, EffectiveBuilder>,
    pub registries: BTreeMap<String, EffectiveRegistry>,
    pub credentials: BTreeMap<CredentialScope, CredentialCandidate>,
}

#[derive(Clone, Debug)]
pub struct ManagedBuilderReferences<'a> {
    pub environment: &'a str,
    pub machine: &'a MachineConfig,
    pub privilege: Option<&'a PrivilegeProfile>,
}

fn path(root: &Path, declared: &str) -> PathBuf {
    normalize(&root.join(declared))
}

fn overlay<T: Clone>(
    root: &BTreeMap<String, T>,
    environment: Option<&BTreeMap<String, T>>,
    section: &str,
    env_name: Option<&str>,
) -> BTreeMap<String, (T, String)> {
    let mut values: BTreeMap<_, _> = root
        .iter()
        .map(|(name, value)| (name.clone(), (value.clone(), format!("{section}.{name}"))))
        .collect();
    if let (Some(environment), Some(env_name)) = (environment, env_name) {
        for (name, value) in environment {
            values.insert(
                name.clone(),
                (
                    value.clone(),
                    format!("environments.{env_name}.{section}.{name}"),
                ),
            );
        }
    }
    values
}

pub(crate) fn registry_catalogs(
    project: &LoadedProject,
    environment: Option<&str>,
) -> BTreeMap<String, EffectiveRegistry> {
    let env = environment.and_then(|name| project.config.environments.get(name));
    let root = &project.broil_root;
    overlay(
        &project.config.registries,
        env.map(|e| &e.registries),
        "registries",
        environment,
    )
    .into_iter()
    .map(|(name, (declaration, config_path))| {
        let ca = declaration.ca.as_ref().map(|p| path(root, p));
        (
            name,
            EffectiveRegistry {
                declaration,
                config_path,
                ca,
            },
        )
    })
    .collect()
}

pub fn select<'a>(
    project: &'a LoadedProject,
    environment: Option<&str>,
) -> Result<SelectedCatalogs<'a>, ConfigError> {
    let environment = environment.filter(|name| !name.is_empty());
    let env = environment
        .map(|name| {
            project
                .config
                .environments
                .get(name)
                .ok_or_else(|| invalid("BROIL_ENV", "a declared environment name"))
        })
        .transpose()?;
    let root = &project.broil_root;
    let images = overlay(
        &project.config.images,
        env.map(|e| &e.images),
        "images",
        environment,
    )
    .into_iter()
    .map(|(name, (declaration, config_path))| {
        let context = path(root, declaration.context.as_deref().unwrap_or("."));
        let dockerfile = declaration
            .dockerfile
            .as_ref()
            .map_or_else(|| context.join("Dockerfile"), |p| path(root, p));
        let contexts = declaration
            .contexts
            .iter()
            .map(|(name, p)| (name.clone(), path(root, p)))
            .collect();
        let ssh = declaration
            .ssh
            .iter()
            .map(|(name, p)| (name.clone(), path(root, p)))
            .collect();
        let platforms = declaration
            .platforms
            .clone()
            .unwrap_or_else(|| vec!["linux/amd64".into()]);
        let output_kind = declaration.output.kind.unwrap_or_default();
        let output_path = declaration.output.path.as_ref().map(|p| path(root, p));
        let builder_cache = declaration.cache.builder.unwrap_or(true);
        let refresh = declaration.cache.refresh.unwrap_or(false);
        (
            name,
            EffectiveImage {
                declaration,
                config_path,
                context,
                dockerfile,
                contexts,
                ssh,
                platforms,
                output_kind,
                output_path,
                builder_cache,
                refresh,
            },
        )
    })
    .collect();
    let builders = overlay(
        &project.config.builders,
        env.map(|e| &e.builders),
        "builders",
        environment,
    )
    .into_iter()
    .map(|(name, (declaration, config_path))| {
        let ca = path(root, &declaration.tls.ca);
        let server_name = declaration
            .tls
            .server_name
            .clone()
            .unwrap_or_else(|| declaration.endpoint.authority.host.clone());
        (
            name,
            EffectiveBuilder {
                declaration,
                config_path,
                ca,
                server_name,
            },
        )
    })
    .collect();
    let registries = registry_catalogs(project, environment);
    let mut selected = SelectedCatalogs {
        project,
        tools: env.map_or_else(
            || project.config.tools.clone(),
            |e| project.config.tools.overlay(&e.tools),
        ),
        environment: environment.map(String::from),
        images,
        builders,
        registries,
        credentials: BTreeMap::new(),
    };
    selected.validate_references()?;
    selected.index_credentials()?;
    Ok(selected)
}

impl SelectedCatalogs<'_> {
    fn validate_references(&self) -> Result<(), ConfigError> {
        let mut outputs: BTreeMap<ImageIdentity, String> = BTreeMap::new();
        for image in self.images.values() {
            let p = &image.config_path;
            if !self.builders.contains_key(&image.declaration.builder) {
                return Err(invalid(
                    &format!("{p}.builder"),
                    "a builder in the selected catalog",
                ));
            }
            if let Some(registry) = &image.declaration.registry {
                self.require_registry(
                    registry,
                    &image.declaration.image,
                    &format!("{p}.registry"),
                )?;
            } else if image.output_kind == OutputKind::Registry {
                return Err(invalid(
                    &format!("{p}.registry"),
                    "present for registry output",
                ));
            }
            let identity = image.declaration.image.identity();
            if let Some(first) = outputs.insert(identity, p.clone()) {
                return Err(ambiguous(&format!("{first}.image"), &format!("{p}.image")));
            }
            for (i, location) in image.declaration.cache.read.iter().enumerate() {
                self.require_registry(
                    &location.registry,
                    &location.reference,
                    &format!("{p}.cache.read.{i}"),
                )?;
            }
            if let Some(location) = &image.declaration.cache.write {
                self.require_registry(
                    &location.registry,
                    &location.reference,
                    &format!("{p}.cache.write"),
                )?;
            }
        }
        for image in self.images.values() {
            if let Some(write) = &image.declaration.cache.write {
                for producer in self.images.values() {
                    let output = &producer.declaration.image;
                    if write.reference.repository == output.repository
                        && write.reference.effective_tag() == output.effective_tag()
                    {
                        return Err(ambiguous(
                            &format!("{}.cache.write.ref", image.config_path),
                            &format!("{}.image", producer.config_path),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn require_registry(
        &self,
        name: &str,
        reference: &ImageReference,
        p: &str,
    ) -> Result<&EffectiveRegistry, ConfigError> {
        let registry = self
            .registries
            .get(name)
            .ok_or_else(|| invalid(p, "a registry in the selected catalog"))?;
        if !registry.declaration.endpoint.matches_repository(reference) {
            return Err(invalid(p, "a registry matching the reference authority"));
        }
        Ok(registry)
    }

    fn index_credentials(&mut self) -> Result<(), ConfigError> {
        for (name, registry) in &self.registries {
            for (purpose, auth) in &registry.declaration.auth {
                for repository in &auth.repositories {
                    let scope = CredentialScope {
                        endpoint: registry.declaration.endpoint.origin(),
                        repository: repository.clone(),
                        purpose: *purpose,
                    };
                    let candidate = CredentialCandidate {
                        registry: name.clone(),
                        config_path: format!("{}.auth.{}", registry.config_path, purpose.name()),
                    };
                    if let Some(first) = self.credentials.insert(scope, candidate.clone()) {
                        return Err(ambiguous(&first.config_path, &candidate.config_path));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn registry_policy(
        &self,
        reference: &ImageReference,
        purpose: RegistryPurpose,
        explicit: Option<&str>,
    ) -> Result<RegistryPolicy, ConfigError> {
        let make = |name: &str, registry: &EffectiveRegistry| RegistryPolicy {
            registry: Some(name.into()),
            endpoint: registry.declaration.endpoint.clone(),
            ca: registry.ca.clone(),
            credential: registry
                .declaration
                .auth
                .get(&purpose)
                .filter(|auth| auth.repositories.contains(&reference.repository))
                .map(|auth| auth.credential.clone()),
        };
        if let Some(name) = explicit {
            return Ok(make(
                name,
                self.require_registry(name, reference, "registries")?,
            ));
        }
        let matching: Vec<_> = self
            .registries
            .iter()
            .filter(|(_, registry)| registry.declaration.endpoint.matches_repository(reference))
            .collect();
        let candidates: Vec<_> = matching
            .iter()
            .filter(|(_, registry)| {
                registry
                    .declaration
                    .auth
                    .get(&purpose)
                    .is_some_and(|auth| auth.repositories.contains(&reference.repository))
            })
            .collect();
        if candidates.len() > 1 {
            return Err(ambiguous(
                &candidates[0].1.config_path,
                &candidates[1].1.config_path,
            ));
        }
        if let Some((name, registry)) = candidates.first() {
            return Ok(make(name, registry));
        }
        if let Some((name, first)) = matching.first() {
            for (_, other) in &matching[1..] {
                if first.declaration.endpoint.origin() != other.declaration.endpoint.origin()
                    || first.ca != other.ca
                {
                    return Err(ambiguous(&first.config_path, &other.config_path));
                }
            }
            return Ok(make(name, first));
        }
        Ok(RegistryPolicy {
            registry: None,
            endpoint: Endpoint::registry(&format!("https://{}", reference.authority), false)
                .ok_or_else(|| invalid("registries", "a valid reference authority"))?,
            ca: None,
            credential: None,
        })
    }

    pub fn match_producer(&self, reference: &ImageReference, platform: &str) -> ProducerMatch {
        let mut candidates = Vec::new();
        let mut mismatch = false;
        for (name, image) in &self.images {
            let output = &image.declaration.image;
            if output.repository != reference.repository {
                continue;
            }
            match &reference.digest {
                None => {
                    if reference.effective_tag() == output.effective_tag() {
                        candidates.push((name, image));
                    }
                }
                Some(digest) => {
                    if output.digest.as_deref() != Some(digest.as_str()) {
                        continue;
                    }
                    match reference.tag.as_deref() {
                        Some(tag) if Some(tag) != output.effective_tag() => mismatch = true,
                        _ => candidates.push((name, image)),
                    }
                }
            }
        }
        match candidates.as_slice() {
            [] if mismatch => ProducerMatch::PinMismatch,
            [] => ProducerMatch::External,
            [(name, image)] => ProducerMatch::Producer {
                name: (*name).clone(),
                platform_declared: image.platforms.iter().any(|p| p == platform),
            },
            _ => ProducerMatch::Ambiguous,
        }
    }

    pub fn managed_builder(
        &self,
        name: &str,
    ) -> Result<Option<ManagedBuilderReferences<'_>>, ConfigError> {
        let builder = self
            .builders
            .get(name)
            .ok_or_else(|| invalid("builders", "a builder in the selected catalog"))?;
        if builder.declaration.kind == BuilderKind::External {
            return Ok(None);
        }
        let environment = self.environment.as_deref().ok_or_else(|| {
            invalid(
                "BROIL_ENV",
                "a selected environment for managed-machine work",
            )
        })?;
        let env = &self.project.config.environments[environment];
        let machine_name = builder
            .declaration
            .machine
            .as_deref()
            .expect("validated managed builder");
        let machine = env.remote.machines.get(machine_name).ok_or_else(|| {
            invalid(
                &format!("{}.machine", builder.config_path),
                "a machine in the selected environment's inventory",
            )
        })?;
        let privilege = builder
            .declaration
            .privilege
            .as_ref()
            .map(|name| {
                env.remote
                    .definitions
                    .privilege_profiles
                    .get(name)
                    .or_else(|| {
                        self.project
                            .config
                            .remote
                            .definitions
                            .privilege_profiles
                            .get(name)
                    })
                    .ok_or_else(|| {
                        invalid(
                            &format!("{}.privilege", builder.config_path),
                            "a privilege profile in the selected environment",
                        )
                    })
            })
            .transpose()?;
        Ok(Some(ManagedBuilderReferences {
            environment,
            machine,
            privilege,
        }))
    }
}
