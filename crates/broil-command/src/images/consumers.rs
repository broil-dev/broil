// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    BuilderCapabilities, Cancellation, Observation, Operation, RegistryOutcome, StageError, Tool,
    VerifiedOutput,
    client::{self, BakeFailure, Baked, CacheArguments, Kept, ProtectedOptions},
    common::*,
    files,
    graph::{
        self, Closure, ClosureKind, Diagnostic, Driver, Material, NodeKey, Refusal, Resolution,
        Resolved, Retained, SourceKey, Staging,
    },
    outputs,
    policy::*,
    protected::{self, Action, Lease},
    publish, records, solve,
    supervise::SourceBytes,
};
use broil_config::{
    LoadedProject,
    images::select::{self, EffectiveBuilder, EffectiveImage, RegistryPolicy},
};
use broil_core::{
    images::{
        RegistryCredential, RegistryPurpose, SecretReference, reference::ImageReference,
        valid_name, valid_platform,
    },
    secret::{OwnedSecret, environment::CredentialInputs},
};
use broil_secrets::{identity::AcquisitionControl, read};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    path::{Path, PathBuf},
};

pub struct Inputs {
    pub cwd: PathBuf,
    pub credentials: CredentialInputs,
    pub non_interactive: bool,
}

#[derive(Debug)]
pub struct ProtectedObservation {
    pub session: PathBuf,
    pub residue: bool,
    pub unresolved_owner: bool,
}

#[derive(Debug)]
pub struct Outcome<T> {
    pub result: std::result::Result<T, StageError>,
    pub cleanup: std::result::Result<Observation, StageError>,
    pub protected: ProtectedObservation,
    pub release: Option<Kept>,
}

#[derive(Clone, Debug)]
pub struct RegistrySelection {
    pub stage: String,
    pub reference: String,
    pub purpose: RegistryPurpose,
    pub registry: Option<String>,
    pub optional: bool,
    pub expected_root: Option<Descriptor>,
    pub input: Option<Entry>,
    pub inspect_input: bool,
    pub limits: BTreeMap<String, u64>,
}

pub struct Registry<'a> {
    project: &'a LoadedProject,
    checked: Preflight,
    selection: RegistrySelection,
    policy: RegistryPolicy,
    request: RegistryRequest,
}

fn bound(project: &LoadedProject, policy: &Policy) -> Result<()> {
    require(
        project.broil_root == policy.root && project.config.env_vars == policy.root_env,
        Failure::Policy,
    )?;
    let expected = policy
        .environment
        .as_ref()
        .map(|name| {
            project
                .config
                .environments
                .get(name)
                .map(|env| &env.env_vars)
                .ok_or(Failure::Policy)
        })
        .transpose()?;
    require(
        expected.map_or(policy.selected_env.is_empty(), |env| {
            *env == policy.selected_env
        }),
        Failure::Policy,
    )
}

fn reference(value: &SecretReference) -> Result<()> {
    require(
        broil_core::secrets::valid_set(&value.set, true)
            && value.set.contains('/')
            && broil_core::secrets::valid_key(&value.key),
        Failure::Policy,
    )
}

fn registry_request(
    selected: &RegistrySelection,
    policy: &RegistryPolicy,
) -> Result<RegistryRequest> {
    let auth = match &policy.credential {
        None => RegistryAuth::Anonymous,
        Some(RegistryCredential::Token(secret)) => {
            reference(secret)?;
            RegistryAuth::Bearer
        }
        Some(RegistryCredential::Password {
            username,
            password,
            token_service,
        }) => {
            reference(password)?;
            RegistryAuth::Password {
                username: username.clone(),
                token_service: token_service
                    .as_ref()
                    .map(|service| (service.realm.supplied.clone(), service.service.clone())),
            }
        }
    };
    let request = RegistryRequest {
        endpoint: policy.endpoint.supplied.clone(),
        development_http: policy.endpoint.supplied.starts_with("http://"),
        ca: policy.ca.clone(),
        reference: selected.reference.clone(),
        action: match selected.purpose {
            RegistryPurpose::Metadata => RegistryAction::Inspect,
            RegistryPurpose::Pull | RegistryPurpose::CacheRead => RegistryAction::Fetch,
            RegistryPurpose::Push | RegistryPurpose::CacheWrite => RegistryAction::Upload,
        },
        cache: matches!(
            selected.purpose,
            RegistryPurpose::CacheRead | RegistryPurpose::CacheWrite
        ),
        optional: selected.optional,
        auth,
        expected_root: selected.expected_root.clone(),
        input: selected.input.clone(),
        inspect_input: selected.inspect_input,
        limits: selected.limits.clone(),
    };
    require(
        valid_name(&selected.stage) && selected.stage.len() <= 255,
        Failure::Policy,
    )?;
    request.validate()?;
    Ok(request)
}

pub fn registry(
    project: &LoadedProject,
    policy: Policy,
    selection: RegistrySelection,
) -> Result<Registry<'_>> {
    bound(project, &policy)?;
    let selected =
        select::select(project, policy.environment.as_deref()).map_err(|_| Failure::Policy)?;
    let image = ImageReference::parse(&selection.reference).ok_or(Failure::Policy)?;
    let registry = selected
        .registry_policy(&image, selection.purpose, selection.registry.as_deref())
        .map_err(|_| Failure::Policy)?;
    let request = registry_request(&selection, &registry)?;
    let header = request.header(
        &policy.operation_id,
        &policy.workspace_path().join("staging/producer-1/content"),
        policy.limits.content.staging_bytes,
        policy.limits.solve_ms,
    )?;
    require(
        serde_json::to_vec(&header)
            .map_err(|_| Failure::Policy)?
            .len()
            <= request.limit("header_bytes") as usize,
        Failure::Limit,
    )?;
    require(policy.tools.contains_key(&Tool::Registry), Failure::Policy)?;
    Ok(Registry {
        project,
        checked: preflight(policy)?,
        selection,
        policy: registry,
        request,
    })
}

fn unavailable(cancellation: &Cancellation) -> Failure {
    if cancellation.requested() {
        Failure::Cancellation
    } else {
        Failure::Credential
    }
}

pub(super) fn acquire(
    selected: &read::Selection,
    inputs: &Inputs,
    secret: &SecretReference,
    cancellation: &Cancellation,
) -> Result<OwnedSecret> {
    reference(secret)?;
    require(!cancellation.requested(), Failure::Cancellation)?;
    let token = cancellation.clone();
    let control = AcquisitionControl::new(move || token.requested(), || Box::new(()));
    let scalar = read::resolve_scalar_with_options(
        selected,
        &inputs.cwd,
        inputs
            .credentials
            .try_duplicate()
            .map_err(|_| Failure::Limit)?,
        &secret.key,
        Some(&secret.set),
        &control,
        inputs.non_interactive,
    )
    .map_err(|_| unavailable(cancellation))?;
    require(!cancellation.requested(), Failure::Cancellation)?;
    Ok(scalar)
}

fn error(failure: Failure) -> StageError {
    let mut observation = Observation::new(monotonic_ns());
    observation.failure = Some(failure);
    observation.cancellation_requested = failure == Failure::Cancellation;
    StageError {
        failure,
        observation,
    }
}

fn action(
    operation: &mut Operation,
    lease: &mut Option<Lease>,
    action: Action,
) -> std::result::Result<(), StageError> {
    let owned = lease.take().ok_or_else(|| error(Failure::Indeterminate))?;
    let (returned, result) = operation.protected_action(owned, action);
    *lease = returned;
    result
}

fn finish<T>(
    operation: Operation,
    lease: Option<Lease>,
    path: PathBuf,
    result: std::result::Result<T, StageError>,
    keep: &[VerifiedOutput],
) -> Outcome<T> {
    let abandoned = lease.is_none();
    let close = operation.close(lease, keep);
    Outcome {
        result,
        cleanup: close.result,
        protected: ProtectedObservation {
            session: path,
            residue: abandoned || close.private_residue,
            unresolved_owner: abandoned || close.unresolved_private_owner,
        },
        release: close.kept,
    }
}

impl Registry<'_> {
    pub fn run(
        self,
        inputs: Inputs,
        cancellation: Cancellation,
    ) -> std::result::Result<Outcome<RegistryOutcome>, StageError> {
        require(
            valid_path(&inputs.cwd) && !cancellation.requested(),
            if cancellation.requested() {
                Failure::Cancellation
            } else {
                Failure::Policy
            },
        )
        .map_err(error)?;
        let environment = self.checked.0.environment.clone();
        let operation_id = self.checked.0.operation_id.clone();
        let selected = read::Selection::new(
            &self.project.config,
            &self.project.broil_root,
            environment.as_deref().map(OsStr::new),
        )
        .map_err(|_| error(Failure::Policy))?;
        let mut operation = Operation::open(self.checked, cancellation.clone())?;
        let owned = Lease::new(
            PathBuf::from("/dev/shm"),
            &operation_id,
            self.policy.ca.clone(),
            Vec::new(),
            false,
        )
        .map_err(error)?;
        let path = owned.path.clone();
        let mut lease = Some(owned);
        let result = (|| {
            action(&mut operation, &mut lease, Action::Prepare)?;
            let scalar = match &self.policy.credential {
                Some(RegistryCredential::Token(secret))
                | Some(RegistryCredential::Password {
                    password: secret, ..
                }) => Some(acquire(&selected, &inputs, secret, &cancellation).map_err(error)?),
                None => None,
            };
            drop(inputs);
            let catalogs = select::select(self.project, environment.as_deref())
                .map_err(|_| error(Failure::Policy))?;
            let reference = ImageReference::parse(&self.selection.reference)
                .ok_or_else(|| error(Failure::Policy))?;
            let current = catalogs
                .registry_policy(
                    &reference,
                    self.selection.purpose,
                    self.selection.registry.as_deref(),
                )
                .map_err(|_| error(Failure::Policy))?;
            require(
                current == self.policy
                    && registry_request(&self.selection, &current).map_err(error)? == self.request,
                Failure::Policy,
            )
            .map_err(error)?;
            action(&mut operation, &mut lease, Action::Recheck)?;
            operation.registry(&self.selection.stage, self.request, scalar)
        })();
        if let Err(failure) = &result {
            operation.acquisition_failed(failure.failure);
        }
        let keep: Vec<_> = result
            .as_ref()
            .ok()
            .and_then(|outcome| outcome.output.clone())
            .into_iter()
            .collect();
        Ok(finish(operation, lease, path, result, &keep))
    }
}

#[derive(Clone, Debug)]
pub struct Solve {
    pub image: String,
    pub target: String,
    pub bake: Entry,
    pub digest: String,
    pub size: u64,
    pub read_paths: Vec<PathBuf>,
    pub secret_ids: Vec<String>,
    pub ssh_ids: Vec<String>,
    pub expected_root: Option<Descriptor>,
}

#[derive(Clone, Debug)]
pub struct BuilderSelection {
    pub builder: String,
    pub stage: String,
    pub protected_parent: PathBuf,
    pub solve: Option<Solve>,
}

pub struct Builder<'a> {
    project: &'a LoadedProject,
    checked: Preflight,
    selection: BuilderSelection,
    builder: EffectiveBuilder,
    image: Option<EffectiveImage>,
    policy: BuilderPolicy,
    secrets: Vec<SecretReference>,
    options: ProtectedOptions,
}

pub fn builder(
    project: &LoadedProject,
    policy: Policy,
    selection: BuilderSelection,
) -> Result<Builder<'_>> {
    bound(project, &policy)?;
    let catalogs =
        select::select(project, policy.environment.as_deref()).map_err(|_| Failure::Policy)?;
    let builder = catalogs
        .builders
        .get(&selection.builder)
        .cloned()
        .ok_or(Failure::Policy)?;
    require(
        valid_name(&selection.stage)
            && selection.stage.len() <= 255
            && valid_path(&selection.protected_parent),
        Failure::Policy,
    )?;
    let mut secrets = vec![
        builder.declaration.tls.certificate.clone(),
        builder.declaration.tls.key.clone(),
    ];
    let mut options = ProtectedOptions {
        selected: true,
        ..ProtectedOptions::default()
    };
    let image = selection
        .solve
        .as_ref()
        .map(|solve| -> Result<EffectiveImage> {
            let image = catalogs
                .images
                .get(&solve.image)
                .cloned()
                .ok_or(Failure::Policy)?;
            require(
                image.declaration.builder == selection.builder
                    && valid_name(&solve.target)
                    && solve.target.len() <= 255
                    && solve.bake.kind == Kind::File
                    && solve.bake.ownership != Ownership::Operation
                    && valid_path(&solve.bake.path)
                    && solve.size > 0
                    && solve.size <= policy.limits.content.staging_bytes
                    && solve.digest.len() == 71
                    && solve.digest.starts_with("sha256:")
                    && hex(&solve.digest.as_bytes()[7..])
                    && solve.read_paths.len() <= 128
                    && solve.read_paths.iter().all(|path| valid_path(path))
                    && solve.secret_ids.len() <= protected::MAX_FILES - 2
                    && solve.ssh_ids.len() <= 128,
                Failure::Policy,
            )?;
            let mut ids = BTreeSet::new();
            for id in &solve.secret_ids {
                require(
                    valid_name(id) && id.len() <= 255 && ids.insert(id),
                    Failure::Policy,
                )?;
                let secret = image.declaration.secrets.get(id).ok_or(Failure::Policy)?;
                options.secrets.insert(
                    id.clone(),
                    selection
                        .protected_parent
                        .join(&policy.operation_id)
                        .join(format!("input-{}", secrets.len())),
                );
                secrets.push(secret.clone());
            }
            ids.clear();
            for id in &solve.ssh_ids {
                require(
                    valid_name(id) && id.len() <= 255 && ids.insert(id),
                    Failure::Policy,
                )?;
                let path = image.ssh.get(id).ok_or(Failure::Policy)?;
                require(
                    valid_path(path) && !path.to_string_lossy().contains([',', '\n', '\r']),
                    Failure::Policy,
                )?;
                options.ssh.insert(id.clone(), path.clone());
            }
            options.stage = image.declaration.stage.clone();
            if let Some(root) = &solve.expected_root {
                root.validate()?;
            }
            Ok(image)
        })
        .transpose()?;
    for secret in &secrets {
        reference(secret)?;
    }
    let base = selection.protected_parent.join(&policy.operation_id);
    let disjoint = |path: &std::path::Path| !base.starts_with(path) && !path.starts_with(&base);
    require(disjoint(&policy.workspace_path()), Failure::Policy)?;
    if let Some(solve) = &selection.solve {
        require(
            disjoint(&solve.bake.path) && solve.read_paths.iter().all(|path| disjoint(path)),
            Failure::Policy,
        )?;
    }
    if let Some(image) = &image {
        require(
            image
                .contexts
                .values()
                .chain([&image.context, &image.dockerfile])
                .chain(image.output_path.iter())
                .all(|path| disjoint(path)),
            Failure::Policy,
        )?;
    }
    let builder_policy = BuilderPolicy {
        endpoint: builder.declaration.endpoint.supplied.clone(),
        server_name: builder.server_name.clone(),
        ca: builder.ca.clone(),
        certificate: base.join("input-0"),
        key: base.join("input-1"),
        platforms: image
            .as_ref()
            .map(|image| image.platforms.clone())
            .unwrap_or_else(|| vec!["linux/amd64".into()]),
        entitlements: image
            .as_ref()
            .map(|image| image.declaration.entitlements.clone())
            .unwrap_or_default(),
    };
    builder_policy.validate()?;
    if let Some(solve) = &selection.solve {
        super::client::bake_arguments(
            &policy,
            &builder_policy,
            &solve.target,
            &solve.bake,
            &solve.read_paths,
            &policy.workspace_path().join("staging/producer-1"),
            &builder_policy.platforms,
            &options,
            &CacheArguments::default(),
            None,
        )?;
    }
    require(
        policy.tools.contains_key(&Tool::Buildx) && policy.tools.contains_key(&Tool::Buildctl),
        Failure::Policy,
    )?;
    Ok(Builder {
        project,
        checked: preflight(policy)?,
        selection,
        builder,
        image,
        policy: builder_policy,
        secrets,
        options,
    })
}

#[derive(Debug)]
pub struct BuilderOutcome {
    pub discovery: Observation,
    pub capabilities: super::BuilderCapabilities,
    pub output: Option<VerifiedOutput>,
}

impl Builder<'_> {
    pub fn run(
        self,
        inputs: Inputs,
        cancellation: Cancellation,
    ) -> std::result::Result<Outcome<BuilderOutcome>, StageError> {
        require(
            valid_path(&inputs.cwd) && !cancellation.requested(),
            if cancellation.requested() {
                Failure::Cancellation
            } else {
                Failure::Policy
            },
        )
        .map_err(error)?;
        let environment = self.checked.0.environment.clone();
        let owned = Lease::new(
            self.selection.protected_parent.clone(),
            &self.checked.0.operation_id,
            Some(self.policy.ca.clone()),
            self.options.ssh.values().cloned().collect(),
            true,
        )
        .map_err(error)?;
        let path = owned.path.clone();
        let selected = read::Selection::new(
            &self.project.config,
            &self.project.broil_root,
            environment.as_deref().map(OsStr::new),
        )
        .map_err(|_| error(Failure::Policy))?;
        let mut operation = Operation::open(self.checked, cancellation.clone())?;
        let mut lease = Some(owned);
        let result: std::result::Result<BuilderOutcome, StageError> = (|| {
            action(&mut operation, &mut lease, Action::Prepare)?;
            for secret in &self.secrets {
                let scalar = acquire(&selected, &inputs, secret, &cancellation).map_err(error)?;
                action(&mut operation, &mut lease, Action::Materialize(scalar))?;
            }
            drop(inputs);
            let catalogs = select::select(self.project, environment.as_deref())
                .map_err(|_| error(Failure::Policy))?;
            require(
                catalogs.builders.get(&self.selection.builder) == Some(&self.builder),
                Failure::Policy,
            )
            .map_err(error)?;
            if let Some(solve) = &self.selection.solve {
                require(
                    catalogs.images.get(&solve.image) == self.image.as_ref(),
                    Failure::Policy,
                )
                .map_err(error)?;
            }
            action(&mut operation, &mut lease, Action::Recheck)?;
            let platforms = self.policy.platforms.clone();
            operation.create_builder(&self.selection.stage, self.policy)?;
            let discovery = operation.inspect_builder(&self.selection.stage)?;
            let capabilities = operation
                .builder_capabilities()
                .cloned()
                .ok_or_else(|| error(Failure::Protocol))?;
            let output = if let Some(solve) = self.selection.solve {
                Some(
                    operation
                        .bake_selected(
                            &self.selection.stage,
                            &solve.target,
                            solve.bake,
                            solve.digest,
                            solve.size,
                            &solve.read_paths,
                            solve.expected_root,
                            &platforms,
                            &self.options,
                            &CacheArguments::default(),
                        )?
                        .image,
                )
            } else {
                None
            };
            Ok(BuilderOutcome {
                discovery,
                capabilities,
                output,
            })
        })();
        if let Err(failure) = &result {
            operation.acquisition_failed(failure.failure);
        }
        let keep: Vec<_> = result
            .as_ref()
            .ok()
            .and_then(|outcome| outcome.output.clone())
            .into_iter()
            .collect();
        Ok(finish(operation, lease, path, result, &keep))
    }
}

pub struct ProducerOutput {
    pub producer: String,
    pub platform: String,
    pub output: VerifiedOutput,
}

pub struct Prior {
    pub resolution: Resolution,
    pub material: Material,
}

pub struct GraphSelection {
    pub targets: Vec<String>,
    pub platforms: Option<Vec<String>>,
    pub build_platform: String,
    pub staging: Staging,
    pub registries: Option<Vec<String>>,
    pub limits: graph::Limits,
    pub producer_outputs: Vec<ProducerOutput>,
    pub prior: Option<Prior>,
}

pub struct Graph<'a> {
    project: &'a LoadedProject,
    checked: Preflight,
    request: graph::Request,
    registries: Option<BTreeSet<String>>,
    limits: graph::Limits,
    producer_outputs: BTreeMap<NodeKey, VerifiedOutput>,
    prior: Option<(Resolution, Material)>,
    catalog_id: String,
}

#[allow(clippy::large_enum_variant)]
pub enum GraphResult {
    Resolved {
        resolution: Resolution,
        material: Material,
    },
    Stale {
        diagnostics: Vec<Diagnostic>,
        prior: Prior,
    },
}

pub struct GraphOutcome {
    pub result: GraphResult,
    pub acquisitions: u64,
    pub registry_stages: u64,
    pub attempts: u64,
}

pub struct RecheckOutcome {
    pub stale: Vec<Diagnostic>,
}

fn unique_sorted(values: &[String], valid: impl Fn(&str) -> bool) -> Result<Vec<String>> {
    let set: BTreeSet<&String> = values.iter().collect();
    require(
        !values.is_empty() && set.len() == values.len() && values.iter().all(|v| valid(v)),
        Failure::Policy,
    )?;
    Ok(set.into_iter().cloned().collect())
}

pub fn graph(
    project: &LoadedProject,
    policy: Policy,
    selection: GraphSelection,
) -> Result<Graph<'_>> {
    bound(project, &policy)?;
    let catalogs =
        select::select(project, policy.environment.as_deref()).map_err(|_| Failure::Policy)?;
    selection.limits.validate()?;
    let targets = unique_sorted(&selection.targets, |name| {
        catalogs.images.contains_key(name)
    })?;
    let platforms = selection
        .platforms
        .as_deref()
        .map(|platforms| unique_sorted(platforms, valid_platform))
        .transpose()?;
    for target in &targets {
        let image = &catalogs.images[target];
        require(
            image
                .platforms
                .iter()
                .any(|p| platforms.as_ref().is_none_or(|subset| subset.contains(p))),
            Failure::Policy,
        )?;
    }
    require(valid_platform(&selection.build_platform), Failure::Policy)?;
    let registries = selection
        .registries
        .as_deref()
        .map(|names| unique_sorted(names, |name| catalogs.registries.contains_key(name)))
        .transpose()?
        .map(|names| names.into_iter().collect::<BTreeSet<_>>());
    require(
        selection.producer_outputs.is_empty() || selection.prior.is_some(),
        Failure::Policy,
    )?;
    let mut producer_outputs = BTreeMap::new();
    for supplied in selection.producer_outputs {
        let image = catalogs
            .images
            .get(&supplied.producer)
            .ok_or(Failure::Policy)?;
        require(
            supplied.output.producer_image()
                && supplied.output.closure_complete()
                && image.platforms.contains(&supplied.platform),
            Failure::Policy,
        )?;
        require(
            image
                .declaration
                .image
                .digest
                .as_deref()
                .is_none_or(|digest| digest == supplied.output.root().digest.as_str()),
            Failure::Integrity,
        )?;
        require(
            producer_outputs
                .insert(
                    NodeKey {
                        producer: supplied.producer,
                        platform: supplied.platform,
                    },
                    supplied.output,
                )
                .is_none(),
            Failure::Policy,
        )?;
    }
    require(
        policy.tools.contains_key(&Tool::Registry) && policy.tools.contains_key(&Tool::Analyzer),
        Failure::Policy,
    )?;
    let catalog_id = graph::catalog_id(&catalogs)?;
    Ok(Graph {
        project,
        checked: preflight(policy)?,
        request: graph::Request {
            environment: catalogs.environment.clone(),
            targets,
            platforms,
            build_platform: selection.build_platform,
            staging: selection.staging,
        },
        registries,
        limits: selection.limits,
        producer_outputs,
        prior: selection
            .prior
            .map(|prior| (prior.resolution, prior.material)),
        catalog_id,
    })
}

struct Session<'a> {
    operation: Operation,
    project: &'a LoadedProject,
    environment: Option<String>,
    operation_id: String,
    selected: read::Selection,
    inputs: Option<Inputs>,
    cancellation: Cancellation,
    catalogs: &'a select::SelectedCatalogs<'a>,
    registries: Option<BTreeSet<String>>,
    dockerfiles: BTreeSet<PathBuf>,
    lease: Option<Lease>,
    keep: Vec<VerifiedOutput>,
    stage_limit: u64,
    stages: u64,
    acquisitions: u64,
    attempts: u64,
    last_error: Option<StageError>,
}

impl Session<'_> {
    fn stage_error(&mut self, error: StageError) -> Failure {
        let failure = error.failure;
        self.last_error = Some(error);
        failure
    }

    fn registry_stage(
        &mut self,
        stage: &str,
        source: &SourceKey,
        purpose: RegistryPurpose,
        pinned: Option<&Descriptor>,
        kind: ClosureKind,
    ) -> std::result::Result<Closure, Refusal> {
        if self.stages >= self.stage_limit {
            return Err(Refusal::Session(Failure::Limit));
        }
        let reference =
            ImageReference::parse(&source.reference).ok_or(Refusal::Node(Failure::Policy))?;
        let policy = self
            .catalogs
            .registry_policy(&reference, purpose, None)
            .map_err(|_| Refusal::Node(Failure::Policy))?;
        if let Some(allowed) = &self.registries {
            if !policy
                .registry
                .as_ref()
                .is_some_and(|name| allowed.contains(name))
            {
                return Err(Refusal::Node(Failure::Policy));
            }
        }
        let request_reference = match pinned {
            Some(root) => format!("{}@{}", reference.repository, root.digest),
            None => source.reference.clone(),
        };
        let selection = RegistrySelection {
            stage: stage.into(),
            reference: request_reference.clone(),
            purpose,
            registry: None,
            optional: false,
            expected_root: pinned.cloned(),
            input: None,
            inspect_input: false,
            limits: BTreeMap::new(),
        };
        let request =
            registry_request(&selection, &policy).map_err(|_| Refusal::Node(Failure::Policy))?;
        let lease = Lease::new(
            PathBuf::from("/dev/shm"),
            &self.operation_id,
            policy.ca.clone(),
            Vec::new(),
            false,
        )
        .map_err(|_| Refusal::Node(Failure::Policy))?;
        self.lease = Some(lease);
        if let Err(error) = action(&mut self.operation, &mut self.lease, Action::Prepare) {
            return Err(Refusal::Session(self.stage_error(error)));
        }
        let scalar = match &policy.credential {
            Some(RegistryCredential::Token(secret))
            | Some(RegistryCredential::Password {
                password: secret, ..
            }) => {
                let inputs = self.inputs.as_ref().ok_or(Refusal::Node(Failure::Policy))?;
                let scalar = acquire(&self.selected, inputs, secret, &self.cancellation).map_err(
                    |failure| {
                        if failure == Failure::Cancellation {
                            Refusal::Session(failure)
                        } else {
                            Refusal::Node(failure)
                        }
                    },
                )?;
                self.acquisitions += 1;
                Some(scalar)
            }
            None => None,
        };
        let catalogs = select::select(self.project, self.environment.as_deref())
            .map_err(|_| Refusal::Session(Failure::Policy))?;
        let current = catalogs
            .registry_policy(&reference, purpose, None)
            .map_err(|_| Refusal::Node(Failure::Policy))?;
        if current != policy
            || registry_request(&selection, &current).ok().as_ref() != Some(&request)
        {
            return Err(Refusal::Node(Failure::Policy));
        }
        if let Err(error) = action(&mut self.operation, &mut self.lease, Action::Recheck) {
            return Err(Refusal::Session(self.stage_error(error)));
        }
        self.stages += 1;
        let outcome = match self.operation.registry(&selection.stage, request, scalar) {
            Ok(outcome) => outcome,
            Err(error) => return Err(Refusal::Session(self.stage_error(error))),
        };
        let output = outcome.output.ok_or(Refusal::Session(Failure::Integrity))?;
        self.keep.push(output.clone());
        Ok(Closure {
            source: source.clone(),
            kind,
            output,
            endpoint: policy.endpoint.supplied.clone(),
            repository: reference.repository.clone(),
            reference: request_reference,
            registry: policy.registry.clone(),
        })
    }
}

impl Driver for Session<'_> {
    fn check(&self) -> Result<()> {
        require(!self.cancellation.requested(), Failure::Cancellation)
    }
    fn deadline(&self) -> Result<u64> {
        deadline(monotonic_ns(), Limits::default().metadata_ms)
    }
    fn snapshot(&mut self, path: &Path, limit: usize) -> std::result::Result<SourceBytes, Refusal> {
        if !self.dockerfiles.contains(path) {
            return Err(Refusal::Node(Failure::Policy));
        }
        match self.operation.source_snapshot(path, limit) {
            Ok(bytes) => Ok(bytes),
            Err(error) if self.operation.usable() => Err(Refusal::Node(error.failure)),
            Err(error) => Err(Refusal::Session(self.stage_error(error))),
        }
    }
    fn attempt(
        &mut self,
        stage: &str,
        snapshot: super::analysis::Snapshot,
    ) -> Result<super::analysis::Outcome> {
        self.attempts += 1;
        self.operation
            .analyze(stage, snapshot)
            .map_err(|error| self.stage_error(error))
    }
    fn inspect(
        &mut self,
        stage: &str,
        source: &SourceKey,
        pinned: Option<&Descriptor>,
    ) -> std::result::Result<Closure, Refusal> {
        self.registry_stage(
            stage,
            source,
            RegistryPurpose::Metadata,
            pinned,
            ClosureKind::Inspect,
        )
    }
    fn fetch(
        &mut self,
        stage: &str,
        source: &SourceKey,
        pinned: &Descriptor,
    ) -> std::result::Result<Closure, Refusal> {
        self.registry_stage(
            stage,
            source,
            RegistryPurpose::Pull,
            Some(pinned),
            ClosureKind::Fetch,
        )
    }
    fn recheck(&mut self, stage: &str, output: &VerifiedOutput) -> Result<Retained> {
        if files::open(output.retained().entry(), false).is_err() {
            return Ok(Retained::Missing);
        }
        self.operation
            .recheck_retained(stage, output)
            .map(|()| Retained::Verified)
            .map_err(|error| self.stage_error(error))
    }
}

impl Graph<'_> {
    fn session<'a>(
        project: &'a LoadedProject,
        checked: Preflight,
        catalogs: &'a select::SelectedCatalogs<'a>,
        registries: Option<BTreeSet<String>>,
        inputs: Option<Inputs>,
        stage_limit: u64,
        cancellation: Cancellation,
    ) -> std::result::Result<Session<'a>, StageError> {
        let environment = checked.0.environment.clone();
        let operation_id = checked.0.operation_id.clone();
        let selected = read::Selection::new(
            &project.config,
            &project.broil_root,
            environment.as_deref().map(OsStr::new),
        )
        .map_err(|_| error(Failure::Policy))?;
        let dockerfiles = catalogs
            .images
            .values()
            .map(|image| image.dockerfile.clone())
            .collect();
        let lease = Lease::new(
            PathBuf::from("/dev/shm"),
            &operation_id,
            None,
            Vec::new(),
            false,
        )
        .map_err(error)?;
        let operation = Operation::open(checked, cancellation.clone())?;
        Ok(Session {
            operation,
            project,
            environment,
            operation_id,
            selected,
            inputs,
            cancellation,
            catalogs,
            registries,
            dockerfiles,
            lease: Some(lease),
            keep: Vec::new(),
            stage_limit,
            stages: 0,
            acquisitions: 0,
            attempts: 0,
            last_error: None,
        })
    }

    pub fn run(
        self,
        inputs: Inputs,
        cancellation: Cancellation,
    ) -> std::result::Result<Outcome<GraphOutcome>, StageError> {
        require(
            valid_path(&inputs.cwd) && !cancellation.requested(),
            if cancellation.requested() {
                Failure::Cancellation
            } else {
                Failure::Policy
            },
        )
        .map_err(error)?;
        let catalogs = select::select(self.project, self.checked.0.environment.as_deref())
            .map_err(|_| error(Failure::Policy))?;
        require(
            graph::catalog_id(&catalogs).map_err(error)? == self.catalog_id,
            Failure::Policy,
        )
        .map_err(error)?;
        let mut session = Self::session(
            self.project,
            self.checked,
            &catalogs,
            self.registries.clone(),
            Some(inputs),
            self.limits.stages,
            cancellation,
        )?;
        let path = PathBuf::from("/dev/shm").join(&session.operation_id);
        let resolved = graph::resolve(
            graph::Inputs {
                catalogs: &catalogs,
                root: &self.project.broil_root,
                request: self.request,
                limits: self.limits,
                registries: self.registries,
                producer_outputs: self.producer_outputs,
                prior: self.prior,
                catalog_id: self.catalog_id,
            },
            &mut session,
        );
        session.inputs = None;
        let Session {
            operation,
            lease,
            keep,
            acquisitions,
            stages,
            attempts,
            last_error,
            ..
        } = session;
        let mut operation = operation;
        let (result, keep): (
            std::result::Result<GraphOutcome, StageError>,
            Vec<VerifiedOutput>,
        ) = match resolved {
            Ok(Resolved::Graph(resolution, material)) => (
                Ok(GraphOutcome {
                    result: GraphResult::Resolved {
                        resolution,
                        material,
                    },
                    acquisitions,
                    registry_stages: stages,
                    attempts,
                }),
                keep,
            ),
            Ok(Resolved::Stale(diagnostics, resolution, material)) => (
                Ok(GraphOutcome {
                    result: GraphResult::Stale {
                        diagnostics,
                        prior: Prior {
                            resolution,
                            material,
                        },
                    },
                    acquisitions,
                    registry_stages: stages,
                    attempts,
                }),
                Vec::new(),
            ),
            Err(failure) => {
                let error = match last_error {
                    Some(error) if error.failure == failure => error,
                    _ => error(failure),
                };
                if operation.usable() {
                    operation.acquisition_failed(failure);
                }
                (Err(error), Vec::new())
            }
        };
        let outcome = finish(operation, lease, path, result, &keep);
        Ok(retain(outcome))
    }

    pub fn recheck(
        project: &LoadedProject,
        policy: Policy,
        resolution: &Resolution,
        material: &Material,
        cancellation: Cancellation,
    ) -> std::result::Result<Outcome<RecheckOutcome>, StageError> {
        require(!cancellation.requested(), Failure::Cancellation).map_err(error)?;
        bound(project, &policy).map_err(error)?;
        let catalogs = select::select(project, policy.environment.as_deref())
            .map_err(|_| error(Failure::Policy))?;
        let catalog_id = graph::catalog_id(&catalogs).map_err(error)?;
        let checked = preflight(policy).map_err(error)?;
        let mut session = Self::session(
            project,
            checked,
            &catalogs,
            material.registries().cloned(),
            None,
            graph::Limits::default().stages,
            cancellation,
        )?;
        let path = PathBuf::from("/dev/shm").join(&session.operation_id);
        let checked = graph::recheck(
            resolution,
            material,
            &catalogs,
            &project.broil_root,
            &catalog_id,
            &graph::Limits::default(),
            &mut session,
        );
        let Session {
            operation,
            lease,
            last_error,
            ..
        } = session;
        let mut operation = operation;
        let result = match checked {
            Ok(stale) => Ok(RecheckOutcome { stale }),
            Err(failure) => {
                if operation.usable() {
                    operation.acquisition_failed(failure);
                }
                Err(match last_error {
                    Some(error) if error.failure == failure => error,
                    _ => error(failure),
                })
            }
        };
        Ok(finish(operation, lease, path, result, &[]))
    }
}

#[derive(Clone, Debug)]
pub struct SolveSelection {
    pub targets: Vec<String>,
    pub platforms: Option<Vec<String>>,
    pub build_platform: Option<String>,
    pub builder: String,
    pub registries: Option<Vec<String>>,
    pub lease_parent: PathBuf,
    pub graph_limits: graph::Limits,
    pub limits: solve::Limits,
    pub expected_contexts: BTreeMap<(String, String), String>,
    pub refresh: bool,
    pub optional_cache_reads: bool,
    pub docker_daemon: Option<PathBuf>,
}

pub use outputs::{
    Handoff, Loaded, NotExported as OutputNotExported, OutputCheck, Retained as RetainedOutput,
    TargetOutcome, TargetReport, Unpublished,
};
pub use publish::{
    ClosureMember, NotPublished, PublicationCheck, PublicationClass, PublicationObservation,
    PublicationOutcome, PublicationRelease, PublicationReport, Residue, RetainedArtifact,
    ServerIdentity, StagingDelta, StandaloneSource, TagAssociation, Unproved,
};
pub use solve::{
    BuiltNode, ExportMode, FailedCheck, Freshness, FrontendGap, IgnoreEntry, IgnoreReport,
    Location as CacheLocationReport, NodeCache, NodeOutcome, NodeReport, NotDispatched,
    ReadOutcome, ReadReport, ReleaseOutcome, SessionObservation, SolveReport, Stop, WriteOutcome,
    WriteReport,
};

pub struct SolveLoop<'a> {
    project: &'a LoadedProject,
    policy: Policy,
    selection: SolveSelection,
    targets: Vec<String>,
    platforms: Option<Vec<String>>,
    registries: Option<Vec<String>>,
    catalog_id: String,
    outputs: BTreeMap<String, broil_core::images::OutputConfig>,
}

const SOLVE_TOOLS: [Tool; 4] = [Tool::Registry, Tool::Analyzer, Tool::Buildx, Tool::Buildctl];
const CLIENT_METADATA_RESERVE: u64 = 1_048_576;

pub fn solve(
    project: &LoadedProject,
    policy: Policy,
    selection: SolveSelection,
) -> Result<SolveLoop<'_>> {
    bound(project, &policy)?;
    policy.validate()?;
    let catalogs =
        select::select(project, policy.environment.as_deref()).map_err(|_| Failure::Policy)?;
    selection.graph_limits.validate()?;
    selection.limits.validate()?;
    let targets = unique_sorted(&selection.targets, |name| {
        catalogs.images.contains_key(name)
    })?;
    let platforms = selection
        .platforms
        .as_deref()
        .map(|platforms| unique_sorted(platforms, valid_platform))
        .transpose()?;
    for target in &targets {
        let image = &catalogs.images[target];
        require(
            image
                .platforms
                .iter()
                .any(|p| platforms.as_ref().is_none_or(|subset| subset.contains(p))),
            Failure::Policy,
        )?;
    }
    require(
        selection
            .build_platform
            .as_deref()
            .is_none_or(valid_platform)
            && catalogs.builders.contains_key(&selection.builder)
            && valid_path(&selection.lease_parent)
            && selection
                .expected_contexts
                .iter()
                .all(|((producer, platform), id)| {
                    valid_name(producer)
                        && valid_platform(platform)
                        && id.len() == 71
                        && id.starts_with("sha256:")
                        && hex(&id.as_bytes()[7..])
                }),
        Failure::Policy,
    )?;
    let registries = selection
        .registries
        .as_deref()
        .map(|names| unique_sorted(names, |name| catalogs.registries.contains_key(name)))
        .transpose()?;
    require(
        SOLVE_TOOLS
            .iter()
            .all(|tool| policy.tools.contains_key(tool)),
        Failure::Policy,
    )?;
    let base = selection.lease_parent.join(&policy.operation_id);
    require(
        !base.starts_with(policy.workspace_path()) && !policy.workspace_path().starts_with(&base),
        Failure::Policy,
    )?;
    let requested: Vec<(String, EffectiveImage)> = targets
        .iter()
        .map(|target| (target.clone(), catalogs.images[target].clone()))
        .collect();
    outputs::matrix(&outputs::Matrix {
        targets: &requested,
        platforms: platforms.as_deref(),
        docker_daemon: selection.docker_daemon.as_deref(),
        docker_tool: policy.tools.contains_key(&Tool::Docker),
        lease_parent: &selection.lease_parent,
        workspace_parent: &policy.parent.path,
    })?;
    let catalog_id = graph::catalog_id(&catalogs)?;
    let outputs = requested
        .into_iter()
        .map(|(target, image)| (target, image.declaration.output))
        .collect();
    Ok(SolveLoop {
        project,
        policy,
        selection,
        targets,
        platforms,
        registries,
        catalog_id,
        outputs,
    })
}

impl SolveLoop<'_> {
    pub fn run(
        self,
        inputs: Inputs,
        cancellation: Cancellation,
    ) -> std::result::Result<SolveReport, StageError> {
        self.run_with_recorder(inputs, cancellation)
            .map(|(report, _)| report)
    }

    pub(crate) fn run_with_recorder(
        self,
        inputs: Inputs,
        cancellation: Cancellation,
    ) -> std::result::Result<(SolveReport, records::Recorder), StageError> {
        require(
            valid_path(&inputs.cwd) && !cancellation.requested(),
            if cancellation.requested() {
                Failure::Cancellation
            } else {
                Failure::Policy
            },
        )
        .map_err(error)?;
        let recorder = (|| {
            let tools = records::capture_tools(&records::pinned_buildkit_version()?)
                .map_err(|refusal| refusal.failure)?;
            let outputs: BTreeMap<&str, &str> = self
                .outputs
                .iter()
                .map(|(target, output)| {
                    (
                        target.as_str(),
                        outputs::kind_name(output.kind.unwrap_or_default()),
                    )
                })
                .collect();
            let request = serde_json::json!({
                "build_platform": self.selection.build_platform,
                "builder": self.selection.builder,
                "catalog_id": self.catalog_id,
                "environment": self.policy.environment,
                "optional_cache_reads": self.selection.optional_cache_reads,
                "outputs": outputs,
                "platforms": self.platforms,
                "refresh": self.selection.refresh,
                "registries": self.registries,
                "targets": self.targets,
            });
            records::Recorder::open(
                &self.project.broil_root,
                "build",
                "solve-loop",
                &request,
                self.policy.environment.clone(),
                tools,
                cancellation.clone(),
                &self.policy.limits,
            )
        })()
        .map_err(error)?;
        let mut sessions = LoopSessions {
            project: self.project,
            policy: self.policy,
            selection: self.selection,
            targets: self.targets,
            platforms: self.platforms,
            registries: self.registries,
            inputs: Some(inputs),
            cancellation,
            recorder,
        };
        let targets = sessions.targets.clone();
        let registries = sessions.registries.clone();
        let build_platform = sessions.selection.build_platform.clone();
        let builder = sessions.selection.builder.clone();
        let expected_contexts = sessions.selection.expected_contexts.clone();
        let limits = sessions.selection.limits.clone();
        let docker_daemon = sessions.selection.docker_daemon.clone();
        let environment = sessions.policy.environment.clone();
        let request = solve::LoopRequest {
            targets: &targets,
            build_platform: build_platform.as_deref(),
            builder: &builder,
            expected_contexts: &expected_contexts,
            limits: &limits,
            recorded: solve::Recorded {
                catalog_id: &self.catalog_id,
                outputs: &self.outputs,
                root: &self.project.broil_root,
                environment: environment.as_deref(),
                registries: registries.as_deref(),
                refresh: sessions.selection.refresh,
                optional_cache_reads: sessions.selection.optional_cache_reads,
                docker_daemon: docker_daemon.as_deref(),
            },
        };
        let mut report = solve::run_loop(&mut sessions, &request);
        sessions.inputs = None;
        sessions.record(&mut report);
        Ok((report, sessions.recorder))
    }
}

fn observation<T>(outcome: &Outcome<T>, operation_id: &str) -> SessionObservation {
    SessionObservation {
        operation_id: operation_id.into(),
        cleanup: outcome.cleanup.clone(),
        residue: outcome.protected.residue,
        unresolved_owner: outcome.protected.unresolved_owner,
    }
}

struct LoopSessions<'a> {
    project: &'a LoadedProject,
    policy: Policy,
    selection: SolveSelection,
    targets: Vec<String>,
    platforms: Option<Vec<String>>,
    registries: Option<Vec<String>>,
    inputs: Option<Inputs>,
    cancellation: Cancellation,
    recorder: records::Recorder,
}

fn policy_for(template: &Policy, tools: &[Tool]) -> Result<Policy> {
    let mut policy = template.clone();
    policy.operation_id = format!(
        "operation-{}",
        broil_core::secret::path_safety::sudo_nonce().map_err(|_| Failure::Capacity)?
    );
    policy.tools = tools
        .iter()
        .map(|tool| {
            template
                .tools
                .get(tool)
                .cloned()
                .map(|entry| (*tool, entry))
                .ok_or(Failure::Policy)
        })
        .collect::<Result<_>>()?;
    policy.validate()?;
    Ok(policy)
}

fn duplicate_inputs(inputs: Option<&Inputs>) -> Result<Inputs> {
    let inputs = inputs.ok_or(Failure::Policy)?;
    Ok(Inputs {
        cwd: inputs.cwd.clone(),
        credentials: inputs
            .credentials
            .try_duplicate()
            .map_err(|_| Failure::Limit)?,
        non_interactive: inputs.non_interactive,
    })
}

impl LoopSessions<'_> {
    fn policy_for(&self, tools: &[Tool]) -> Result<Policy> {
        policy_for(&self.policy, tools)
    }
    fn inputs(&self) -> Result<Inputs> {
        duplicate_inputs(self.inputs.as_ref())
    }
    fn graph_session(
        &self,
        build_platform: &str,
        prior: Option<(Resolution, Material)>,
        outputs: BTreeMap<NodeKey, VerifiedOutput>,
    ) -> std::result::Result<(Outcome<GraphOutcome>, String), StageError> {
        let policy = self
            .policy_for(&[Tool::Registry, Tool::Analyzer])
            .map_err(failed)?;
        let operation_id = policy.operation_id.clone();
        let session = graph(
            self.project,
            policy,
            GraphSelection {
                targets: self.targets.clone(),
                platforms: self.platforms.clone(),
                build_platform: build_platform.into(),
                staging: Staging::Content,
                registries: self.registries.clone(),
                limits: self.selection.graph_limits.clone(),
                producer_outputs: outputs
                    .into_iter()
                    .map(|(key, output)| ProducerOutput {
                        producer: key.producer,
                        platform: key.platform,
                        output,
                    })
                    .collect(),
                prior: prior.map(|(resolution, material)| Prior {
                    resolution,
                    material,
                }),
            },
        )
        .map_err(failed)?;
        let inputs = self.inputs().map_err(failed)?;
        Ok((
            session.run(inputs, self.cancellation.clone())?,
            operation_id,
        ))
    }
}

fn failed(failure: Failure) -> StageError {
    error(failure)
}

#[derive(Clone, Debug)]
enum Commit {
    Bound(String),
    NoRecord,
    Unproved,
}

impl LoopSessions<'_> {
    fn record(&mut self, report: &mut SolveReport) {
        let mut commits: Vec<(String, Commit)> = Vec::new();
        for index in 0..report.targets.len() {
            let target = report.targets[index].target.clone();
            if let TargetOutcome::Retained(retained) = &report.targets[index].outcome {
                let _ = self.recorder.retention(&target, retained);
            }
            let commit = self.commit(report, index);
            commits.push((target, commit));
        }
        for publication in &mut report.publications {
            let commit = commits
                .iter()
                .find(|(target, _)| *target == publication.target)
                .map(|(_, commit)| commit.clone())
                .unwrap_or(Commit::NoRecord);
            let artifact_id = match &commit {
                Commit::Bound(artifact_id) => Some(artifact_id.clone()),
                _ => None,
            };
            if let (Some(artifact_id), PublicationOutcome::Published(observation)) =
                (&artifact_id, &mut publication.outcome)
            {
                observation.artifact_id = Some(artifact_id.clone());
                observation.predicate = "published";
            }
            if let PublicationOutcome::Published(observation) = &publication.outcome {
                let reason = match commit {
                    Commit::NoRecord => Some(records::BindingReason {
                        disposition: records::Disposition::NoRecord,
                        windows: None,
                        candidates: None,
                    }),
                    Commit::Bound(_) | Commit::Unproved => None,
                };
                let _ = self.recorder.publication(
                    &publication.target,
                    observation,
                    publication,
                    artifact_id,
                    reason,
                );
            }
        }
        self.loop_end(report);
        let _ = self.recorder.rebuild_index();
    }

    fn commit(&mut self, report: &SolveReport, index: usize) -> Commit {
        self.try_commit(report, index).unwrap_or_else(|proved| {
            if proved {
                Commit::NoRecord
            } else {
                Commit::Unproved
            }
        })
    }

    fn try_commit(
        &mut self,
        report: &SolveReport,
        index: usize,
    ) -> std::result::Result<Commit, bool> {
        let target_report = &report.targets[index];
        let target = target_report.target.as_str();
        let resolution = report.resolution.as_ref().ok_or(true)?;
        let built: Vec<(
            &str,
            &BuiltNode,
            Option<&SessionObservation>,
            Option<&NodeCache>,
        )> = report
            .nodes
            .iter()
            .filter(|node| node.producer == target)
            .filter_map(|node| match &node.outcome {
                NodeOutcome::Built(built) => Some((
                    node.platform.as_str(),
                    built.as_ref(),
                    node.session.as_ref(),
                    node.cache.as_ref(),
                )),
                _ => None,
            })
            .collect();
        let (_, first, _, _) = built.first().copied().ok_or(true)?;
        let platforms =
            outputs::effective_platforms(&first.image, resolution.request.platforms.as_deref());
        let nodes: Vec<_> = platforms
            .iter()
            .filter_map(|platform| built.iter().find(|(p, ..)| p == platform).copied())
            .collect();
        if nodes.is_empty() || nodes.len() != platforms.len() {
            return Err(true);
        }
        let output_session = || {
            target_report
                .session
                .as_ref()
                .map(|session| session.operation_id.clone())
                .ok_or(true)
        };
        let (root, output_acquisition) = match &target_report.outcome {
            TargetOutcome::Retained(retained) => (retained.root.clone(), output_session()?),
            TargetOutcome::Unpublished(_) => {
                let publication = report
                    .publications
                    .iter()
                    .find(|publication| publication.target == target)
                    .ok_or(true)?;
                let (_, root) = publication.layout.as_ref().ok_or(true)?;
                let layout = publication
                    .staging
                    .iter()
                    .find(|delta| delta.operation == "layout")
                    .ok_or(true)?;
                (root.clone(), layout.operation_id.clone())
            }
            TargetOutcome::Loaded(_) if nodes.len() == 1 => {
                (nodes[0].1.output.root().clone(), output_session()?)
            }
            _ => return Err(true),
        };
        let platforms = self.recorder.chains(target).ok_or(true)?;
        let evidence = records::Evidence {
            target,
            image: &first.image,
            resolution,
            nodes,
            root,
            platforms,
            report: target_report,
            output_acquisition,
        };
        let record = evidence.record(&self.recorder).map_err(|_| true)?;
        match self.recorder.commit(record) {
            Ok(records::Committed::Complete { artifact_id }) => Ok(Commit::Bound(artifact_id)),
            Ok(records::Committed::Abandoned { .. }) => Err(true),
            Err(_) => Err(false),
        }
    }

    fn loop_end(&mut self, report: &SolveReport) {
        let reads: Vec<&ReadReport> = report
            .nodes
            .iter()
            .filter_map(|node| node.cache.as_ref())
            .flat_map(|cache| cache.reads.iter())
            .collect();
        for kept in &report.retained {
            let id = kept.token.operation_id();
            let read_attempted = reads.iter().any(|read| {
                read.operation_id.as_deref() == Some(id)
                    && !matches!(read.release, ReleaseOutcome::Unreleased(None))
            });
            let layout_attempted = report.publications.iter().any(|publication| {
                !matches!(publication.release, PublicationRelease::None)
                    && publication
                        .staging
                        .iter()
                        .any(|delta| delta.operation == "layout" && delta.operation_id == id)
            });
            if read_attempted || layout_attempted {
                continue;
            }
            let graph_resolution = report
                .graph_sessions
                .iter()
                .any(|session| session.operation_id == id);
            let node_build = report
                .nodes
                .iter()
                .any(|node| node.session.as_ref().is_some_and(|s| s.operation_id == id));
            let unattempted_read = reads.iter().any(|read| {
                read.operation_id.as_deref() == Some(id)
                    && matches!(read.release, ReleaseOutcome::Unreleased(None))
            });
            if !(graph_resolution || node_build || unattempted_read) {
                continue;
            }
            if let Some(acquisition) = self.recorder.recorded(id).cloned() {
                let _ = self.recorder.staging_lifecycle(id, &acquisition, false);
            }
        }
    }

    fn read_completion(
        &mut self,
        read: &solve::ReadInput<'_>,
        operation_id: &str,
        result: solve::ReadResult,
    ) -> solve::ReadResult {
        let (outcome, failure_class) = records::Outcome::of_read(result.outcome);
        let helper_identity = Tool::Registry
            .identity()
            .map(|(sha256, _)| sha256)
            .unwrap_or_default();
        let cache_read = records::CacheRead {
            registry: read.location.registry.clone(),
            namespace_reference: read.location.reference.clone(),
            helper_identity,
            optional_read: read.optional,
            continued_without_import: (failure_class == Some(records::FailureClass::CacheMiss))
                .then_some(result.outcome == ReadOutcome::OptionalMiss),
        };
        if let Some((_, Some(kept))) = &result.fetched {
            self.recorder.record_acquisition(
                kept.token.operation_id(),
                records::Acquisition {
                    phase: Some(records::Boundary::CacheRead.name()),
                    role: "cache-read",
                    dispatched: Some(true),
                    outcome,
                    failure_class,
                    source: "cache-read",
                    method: "read-outcome",
                    target: read.target.map(str::to_owned),
                },
            );
        }
        let appended = self.recorder.completion(
            records::Boundary::CacheRead,
            read.target,
            (outcome, failure_class),
            "cache-read",
            "read-outcome",
            result.session.as_ref(),
            vec![records::StageAcquisition {
                role: "cache-read".to_owned(),
                acquisition_id: operation_id.to_owned(),
            }],
            Some(cache_read),
        );
        let _ = appended;
        result
    }
}

impl solve::Sessions for LoopSessions<'_> {
    fn cancelled(&self) -> bool {
        self.cancellation.requested()
    }

    fn probe(&mut self) -> solve::SessionResult<String> {
        let prepared = (|| {
            let policy = self.policy_for(&[Tool::Buildx, Tool::Buildctl])?;
            let operation_id = policy.operation_id.clone();
            let probe = builder(
                self.project,
                policy,
                BuilderSelection {
                    builder: self.selection.builder.clone(),
                    stage: "probe".into(),
                    protected_parent: self.selection.lease_parent.clone(),
                    solve: None,
                },
            )?;
            Ok((probe, operation_id, self.inputs()?))
        })();
        let (probe, operation_id, inputs) = match prepared {
            Ok(prepared) => prepared,
            Err(failure) => return (Err(failed(failure)), None),
        };
        let outcome = match probe.run(inputs, self.cancellation.clone()) {
            Ok(outcome) => outcome,
            Err(error) => return (Err(error), None),
        };
        let observation = observation(&outcome, &operation_id);
        (
            outcome
                .result
                .map(|result| result.capabilities.build_platform),
            Some(observation),
        )
    }

    fn resolve(
        &mut self,
        build_platform: &str,
        prior: Option<(Resolution, Material)>,
        outputs: BTreeMap<NodeKey, VerifiedOutput>,
    ) -> (solve::SessionResult<Resolved>, Option<Kept>) {
        match self.graph_session(build_platform, prior, outputs) {
            Ok((mut outcome, operation_id)) => {
                let observation = observation(&outcome, &operation_id);
                let kept = outcome.release.take();
                let resolved = outcome.result.map(|result| match result.result {
                    GraphResult::Resolved {
                        resolution,
                        material,
                    } => Resolved::Graph(resolution, material),
                    GraphResult::Stale { diagnostics, prior } => {
                        Resolved::Stale(diagnostics, prior.resolution, prior.material)
                    }
                });
                if kept.is_some() {
                    let (result, failure_class) = records::Outcome::of_resolved(&resolved);
                    self.recorder.record_acquisition(
                        &operation_id,
                        records::Acquisition {
                            phase: None,
                            role: "graph-resolution",
                            dispatched: None,
                            outcome: result,
                            failure_class,
                            source: "graph-session",
                            method: "session-result",
                            target: None,
                        },
                    );
                }
                ((resolved, Some(observation)), kept)
            }
            Err(error) => ((Err(error), None), None),
        }
    }

    fn catalogs(&mut self) -> Result<solve::Catalogs> {
        let catalogs = select::select(self.project, self.policy.environment.as_deref())
            .map_err(|_| Failure::Policy)?;
        Ok(solve::Catalogs {
            catalog_id: graph::catalog_id(&catalogs)?,
            images: catalogs.images,
        })
    }

    fn build(&mut self, input: &solve::NodeInput<'_>) -> solve::NodeResult {
        match self.node(&input.key) {
            Ok(driver) => {
                let result = solve::node_session(driver, input);
                if let Some(kept) = &result.kept {
                    let (outcome, failure_class) = records::Outcome::of_node(&result.outcome);
                    let target = self
                        .targets
                        .iter()
                        .find(|t| **t == input.key.producer)
                        .cloned();
                    self.recorder.record_acquisition(
                        kept.token.operation_id(),
                        records::Acquisition {
                            phase: Some(records::NODE_BUILD_PHASE),
                            role: "node-build",
                            dispatched: Some(result.dispatched),
                            outcome,
                            failure_class,
                            source: "node-session",
                            method: "session-result",
                            target,
                        },
                    );
                }
                result
            }
            Err(failure) => solve::NodeResult {
                outcome: NodeOutcome::Failed {
                    class: failure,
                    check: None,
                },
                session: None,
                stale: Vec::new(),
                dispatched: false,
                carried: false,
                kept: None,
            },
        }
    }

    fn cache_read(&mut self, read: &solve::ReadInput<'_>) -> solve::ReadResult {
        let failed = |failure, operation_id, session| solve::ReadResult {
            outcome: if failure == Failure::Cancellation {
                ReadOutcome::Cancelled
            } else {
                ReadOutcome::Failed(failure)
            },
            fetched: None,
            operation_id,
            session,
        };
        let prepared = (|| {
            let policy = self.policy_for(&[Tool::Registry])?;
            let operation_id = policy.operation_id.clone();
            let consumer = registry(
                self.project,
                policy,
                RegistrySelection {
                    stage: "cache-read".into(),
                    reference: read.location.reference.clone(),
                    purpose: RegistryPurpose::CacheRead,
                    registry: Some(read.location.registry.clone()),
                    optional: read.optional,
                    expected_root: None,
                    input: None,
                    inspect_input: false,
                    limits: BTreeMap::new(),
                },
            )?;
            Ok((consumer, operation_id, self.inputs()?))
        })();
        let (consumer, operation_id, inputs) = match prepared {
            Ok(prepared) => prepared,
            Err(failure) => return failed(failure, None, None),
        };
        if let Err(failure) = self.recorder.marker(
            records::Boundary::CacheRead,
            read.target,
            Some(("cache-read", &operation_id)),
        ) {
            return failed(failure, Some(operation_id), None);
        }
        let result = match consumer.run(inputs, self.cancellation.clone()) {
            Ok(mut outcome) => {
                let session = observation(&outcome, &operation_id);
                let kept = outcome.release.take();
                match outcome.result {
                    Ok(result) if result.optional_cache_miss => solve::ReadResult {
                        outcome: ReadOutcome::OptionalMiss,
                        fetched: None,
                        operation_id: Some(operation_id.clone()),
                        session: Some(session),
                    },
                    Ok(RegistryOutcome {
                        output: Some(output),
                        ..
                    }) => solve::ReadResult {
                        outcome: ReadOutcome::Fetched,
                        fetched: Some((output.retained(), kept)),
                        operation_id: Some(operation_id.clone()),
                        session: Some(session),
                    },
                    Ok(_) => failed(
                        Failure::Integrity,
                        Some(operation_id.clone()),
                        Some(session),
                    ),
                    Err(error) => failed(error.failure, Some(operation_id.clone()), Some(session)),
                }
            }
            Err(error) => failed(error.failure, Some(operation_id.clone()), None),
        };
        self.read_completion(read, &operation_id, result)
    }

    fn cache_write(&mut self, write: &solve::WriteInput<'_>) -> solve::WriteResult {
        let prepared = (|| {
            let policy = self.policy_for(&[Tool::Registry])?;
            let operation_id = policy.operation_id.clone();
            let consumer = registry(
                self.project,
                policy,
                RegistrySelection {
                    stage: "cache-write".into(),
                    reference: write.reference.into(),
                    purpose: RegistryPurpose::CacheWrite,
                    registry: Some(write.registry.into()),
                    optional: false,
                    expected_root: Some(write.layout.root().clone()),
                    input: Some(write.layout.retained().entry().clone()),
                    inspect_input: true,
                    limits: BTreeMap::new(),
                },
            )?;
            Ok((consumer, operation_id, self.inputs()?))
        })();
        let (consumer, operation_id, inputs) = match prepared {
            Ok(prepared) => prepared,
            Err(failure) => {
                return solve::WriteResult {
                    outcome: WriteOutcome::Failed(failure),
                    session: None,
                };
            }
        };
        if let Err(failure) = self.recorder.marker(
            records::Boundary::CacheWrite,
            write.target,
            Some(("cache-write", &operation_id)),
        ) {
            return solve::WriteResult {
                outcome: WriteOutcome::Failed(failure),
                session: None,
            };
        }
        let result = match consumer.run(inputs, self.cancellation.clone()) {
            Ok(outcome) => solve::WriteResult {
                session: Some(observation(&outcome, &operation_id)),
                outcome: match &outcome.result {
                    Ok(_) => WriteOutcome::Written,
                    Err(error) => write_outcome(error),
                },
            },
            Err(error) => solve::WriteResult {
                outcome: write_outcome(&error),
                session: None,
            },
        };
        let appended = self.recorder.completion(
            records::Boundary::CacheWrite,
            write.target,
            records::Outcome::of_write(result.outcome),
            "cache-write",
            "write-outcome",
            result.session.as_ref(),
            vec![records::StageAcquisition {
                role: "cache-write".to_owned(),
                acquisition_id: operation_id.clone(),
            }],
            None,
        );
        let _ = appended;
        result
    }

    fn release(&mut self, kept: Kept) -> std::result::Result<(), (Option<Kept>, Failure)> {
        let acquisition_id = kept.token.operation_id().to_owned();
        let Some(acquisition) = self.recorder.recorded(&acquisition_id).cloned() else {
            return Err((Some(kept), Failure::Protocol));
        };
        let result = release(&self.policy, kept, self.cancellation.clone())
            .map(|_| ())
            .map_err(|unreleased| (unreleased.kept, unreleased.error.failure));
        let _ = self
            .recorder
            .staging_lifecycle(&acquisition_id, &acquisition, result.is_ok());
        result
    }

    fn output(&mut self, input: &outputs::OutputInput<'_>) -> TargetReport {
        if let Err(failure) =
            self.recorder
                .marker(records::Boundary::Export, Some(input.target), None)
        {
            return TargetReport::new(
                input.target,
                input.image.output_kind,
                TargetOutcome::Failed {
                    class: failure,
                    check: None,
                    published: None,
                },
            );
        }
        let _ = self.recorder.stash_chains(input.target, input.nodes);
        let driver = OutputSession {
            project: self.project,
            policy: self.policy.clone(),
            cancellation: self.cancellation.clone(),
            operation: None,
            succeeded: false,
        };
        let report = outputs::output_stage(driver, input);
        let acquisitions = report
            .session
            .iter()
            .map(|session| records::StageAcquisition {
                role: "output".to_owned(),
                acquisition_id: session.operation_id.clone(),
            })
            .collect();
        let appended = self.recorder.completion(
            records::Boundary::Export,
            Some(input.target),
            records::Outcome::of_target(&report.outcome),
            "output-stage",
            "target-report",
            report.session.as_ref(),
            acquisitions,
            None,
        );
        let _ = appended;
        report
    }

    fn publish(&mut self, input: &publish::PublishInput<'_>) -> (PublicationReport, Option<Kept>) {
        let (reference, registry) = match input {
            publish::PublishInput::Target { image, .. } => (
                image.declaration.image.supplied.clone(),
                image.declaration.registry.clone(),
            ),
            publish::PublishInput::Standalone { .. } => (String::new(), None),
        };
        if let Err(failure) =
            self.recorder
                .marker(records::Boundary::Publication, Some(input.target()), None)
        {
            return (
                PublicationReport::new(
                    input.target(),
                    PublicationOutcome::Failed {
                        class: PublicationClass::of(failure),
                        check: None,
                    },
                ),
                None,
            );
        }
        let driver = PublishSession {
            project: self.project,
            policy: self.policy.clone(),
            inputs: self.inputs().ok(),
            cancellation: self.cancellation.clone(),
            operation: None,
            reference,
            registry,
            artifact_id: None,
            keep: None,
        };
        let (mut report, kept) = publish::publication_stage(driver, input);
        publication_boundary(&mut self.recorder, input.target(), &mut report);
        (report, kept)
    }
}

fn publication_boundary(
    recorder: &mut records::Recorder,
    target: &str,
    report: &mut PublicationReport,
) {
    if !matches!(report.outcome, PublicationOutcome::Published(_)) {
        let appended = recorder.completion(
            records::Boundary::Publication,
            Some(target),
            records::Outcome::of_publication(&report.outcome),
            "publication-stage",
            "publication-report",
            report.sessions.last(),
            records::publication_acquisitions(report),
            None,
        );
        let _ = appended;
    }
    if matches!(report.release, PublicationRelease::None) {
        return;
    }
    let Some(layout) = report
        .staging
        .iter()
        .find(|delta| delta.operation == "layout")
    else {
        return;
    };
    let (outcome, failure_class) = records::Outcome::of_publication(&report.outcome);
    let acquisition = records::Acquisition {
        phase: Some(records::Boundary::Publication.name()),
        role: "layout",
        dispatched: Some(true),
        outcome,
        failure_class,
        source: "publication-stage",
        method: "publication-report",
        target: Some(target.to_owned()),
    };
    let _ = recorder.staging_lifecycle(
        &layout.operation_id,
        &acquisition,
        matches!(report.release, PublicationRelease::Released),
    );
}

fn write_outcome(error: &StageError) -> WriteOutcome {
    let dispatched = error.observation.dispatch != super::Dispatch::None;
    match error.failure {
        Failure::Cancellation if !dispatched => WriteOutcome::Cancelled,
        Failure::Cancellation | Failure::Timeout | Failure::Indeterminate | Failure::Protocol
            if dispatched =>
        {
            WriteOutcome::Unknown(error.failure)
        }
        failure => WriteOutcome::Failed(failure),
    }
}

pub fn release(
    policy: &Policy,
    kept: Kept,
    cancellation: Cancellation,
) -> std::result::Result<Observation, Box<client::Unreleased>> {
    let mut owner = policy.clone();
    owner.operation_id = kept.token.operation_id().to_owned();
    owner.tools = BTreeMap::new();
    client::release(owner, kept, cancellation)
}

struct OutputSession<'a> {
    project: &'a LoadedProject,
    policy: Policy,
    cancellation: Cancellation,
    operation: Option<(Operation, String)>,
    succeeded: bool,
}

impl OutputSession<'_> {
    fn operation(&mut self) -> std::result::Result<&mut Operation, StageError> {
        self.operation
            .as_mut()
            .map(|(operation, _)| operation)
            .ok_or_else(|| error(Failure::Policy))
    }
}

impl outputs::OutputDriver for OutputSession<'_> {
    fn cancelled(&self) -> bool {
        self.cancellation.requested()
    }

    fn select(&mut self, target: &str) -> Result<(String, Option<EffectiveImage>)> {
        let catalogs = select::select(self.project, self.policy.environment.as_deref())
            .map_err(|_| Failure::Policy)?;
        Ok((
            graph::catalog_id(&catalogs)?,
            catalogs.images.get(target).cloned(),
        ))
    }

    fn open(&mut self, docker: bool) -> std::result::Result<(), StageError> {
        let mut policy = self.policy.clone();
        policy.operation_id = format!(
            "operation-{}",
            broil_core::secret::path_safety::sudo_nonce().map_err(|_| error(Failure::Capacity))?
        );
        policy.tools = if docker {
            let entry = self
                .policy
                .tools
                .get(&Tool::Docker)
                .cloned()
                .ok_or_else(|| error(Failure::Policy))?;
            BTreeMap::from([(Tool::Docker, entry)])
        } else {
            BTreeMap::new()
        };
        let operation_id = policy.operation_id.clone();
        let checked = preflight(policy).map_err(error)?;
        let operation = Operation::open(checked, self.cancellation.clone())?;
        self.operation = Some((operation, operation_id));
        Ok(())
    }

    fn operation(&self) -> Option<(String, Entry)> {
        self.operation
            .as_ref()
            .map(|(operation, id)| (id.clone(), operation.workspace().clone()))
    }

    fn daemon(&mut self, socket: &Path) -> std::result::Result<(), StageError> {
        self.operation()?.daemon_socket(socket)
    }

    fn recheck(&mut self, output: &VerifiedOutput) -> std::result::Result<(), StageError> {
        self.operation()?.recheck_complete("recheck-output", output)
    }

    fn chain(
        &mut self,
        output: &VerifiedOutput,
        platform: &str,
    ) -> std::result::Result<(Descriptor, Vec<Descriptor>), StageError> {
        self.operation()?.node_chain("read-chain", output, platform)
    }

    fn allowance(&self) -> u64 {
        self.operation
            .as_ref()
            .map_or(0, |(operation, _)| operation.remaining())
            .saturating_sub(CLIENT_METADATA_RESERVE)
    }

    fn limits(&self) -> ContentLimits {
        self.policy.limits.content.clone()
    }

    fn assemble(
        &mut self,
        work: outputs::AssembleWork,
        root: &Descriptor,
    ) -> std::result::Result<Entry, StageError> {
        self.operation()?.assemble(work, root)
    }

    fn retain(
        &mut self,
        work: outputs::RetainWork,
    ) -> (
        Option<outputs::RetainWork>,
        std::result::Result<(), StageError>,
    ) {
        match self.operation() {
            Ok(operation) => {
                let (work, result) = operation.retain(work);
                self.succeeded = result.is_ok();
                (work, result)
            }
            Err(error) => (Some(work), Err(error)),
        }
    }

    fn inspect(
        &mut self,
        entry: &Entry,
        root: &Descriptor,
    ) -> std::result::Result<(u64, u64), StageError> {
        let result = self.operation()?.inspect_published(entry, root);
        self.succeeded = result.is_ok();
        result
    }

    fn archive(
        &mut self,
        work: outputs::ArchiveWork,
    ) -> std::result::Result<(Entry, String, u64), StageError> {
        self.operation()?.docker_archive(work)
    }

    fn load(
        &mut self,
        archive: &Entry,
        digest: &str,
        size: u64,
        reference: &str,
    ) -> std::result::Result<(), StageError> {
        let (repository, tag) = reference
            .rsplit_once(':')
            .ok_or_else(|| error(Failure::Policy))?;
        let familiar = format!("{}:{tag}", outputs::familiar(repository));
        self.operation()?
            .docker_load(archive, digest, size, &familiar)
    }

    fn inspect_image(
        &mut self,
        reference: &str,
    ) -> std::result::Result<outputs::Inspected, StageError> {
        let result = self.operation()?.docker_inspect(reference);
        self.succeeded = result.is_ok();
        result
    }

    fn close(mut self) -> Option<SessionObservation> {
        let (mut operation, operation_id) = self.operation.take()?;
        if !self.succeeded {
            operation.refusal_deadline();
        }
        let close = operation.close(None, &[]);
        Some(SessionObservation {
            operation_id,
            cleanup: close.result,
            residue: close.private_residue,
            unresolved_owner: close.unresolved_private_owner,
        })
    }
}

impl<'a> LoopSessions<'a> {
    fn node(&mut self, key: &NodeKey) -> Result<NodeSession<'a>> {
        let policy = self.policy_for(&[Tool::Buildx, Tool::Buildctl])?;
        Ok(NodeSession {
            project: self.project,
            policy,
            key: key.clone(),
            builder: self.selection.builder.clone(),
            lease_parent: self.selection.lease_parent.clone(),
            inputs: Some(self.inputs()?),
            cancellation: self.cancellation.clone(),
            catalogs: None,
            bound: None,
            operation: None,
            lease: None,
            lease_path: None,
            secrets: Vec::new(),
            options: ProtectedOptions::default(),
            builder_policy: None,
            dispatched: false,
            carried: false,
        })
    }
}

pub struct NodeSession<'a> {
    project: &'a LoadedProject,
    policy: Policy,
    key: NodeKey,
    builder: String,
    lease_parent: PathBuf,
    inputs: Option<Inputs>,
    cancellation: Cancellation,
    catalogs: Option<select::SelectedCatalogs<'a>>,
    bound: Option<(EffectiveImage, EffectiveBuilder)>,
    operation: Option<Operation>,
    lease: Option<Lease>,
    lease_path: Option<PathBuf>,
    secrets: Vec<SecretReference>,
    options: ProtectedOptions,
    builder_policy: Option<BuilderPolicy>,
    dispatched: bool,
    carried: bool,
}

impl NodeSession<'_> {
    fn operation(&mut self) -> std::result::Result<&mut Operation, StageError> {
        self.operation
            .as_mut()
            .ok_or_else(|| error(Failure::Policy))
    }
}

struct RecheckDriver<'o> {
    operation: &'o mut Operation,
    cancellation: Cancellation,
    dockerfiles: BTreeSet<PathBuf>,
    last_error: Option<StageError>,
}

impl RecheckDriver<'_> {
    fn stage_error(&mut self, error: StageError) -> Failure {
        let failure = error.failure;
        self.last_error = Some(error);
        failure
    }
}

impl Driver for RecheckDriver<'_> {
    fn check(&self) -> Result<()> {
        require(!self.cancellation.requested(), Failure::Cancellation)
    }
    fn deadline(&self) -> Result<u64> {
        deadline(monotonic_ns(), Limits::default().metadata_ms)
    }
    fn snapshot(&mut self, path: &Path, limit: usize) -> std::result::Result<SourceBytes, Refusal> {
        if !self.dockerfiles.contains(path) {
            return Err(Refusal::Node(Failure::Policy));
        }
        match self.operation.source_snapshot(path, limit) {
            Ok(bytes) => Ok(bytes),
            Err(error) if self.operation.usable() => Err(Refusal::Node(error.failure)),
            Err(error) => Err(Refusal::Session(self.stage_error(error))),
        }
    }
    fn attempt(
        &mut self,
        _stage: &str,
        _snapshot: super::analysis::Snapshot,
    ) -> Result<super::analysis::Outcome> {
        Err(Failure::Policy)
    }
    fn inspect(
        &mut self,
        _stage: &str,
        _source: &SourceKey,
        _pinned: Option<&Descriptor>,
    ) -> std::result::Result<Closure, Refusal> {
        Err(Refusal::Session(Failure::Policy))
    }
    fn fetch(
        &mut self,
        _stage: &str,
        _source: &SourceKey,
        _pinned: &Descriptor,
    ) -> std::result::Result<Closure, Refusal> {
        Err(Refusal::Session(Failure::Policy))
    }
    fn recheck(&mut self, stage: &str, output: &VerifiedOutput) -> Result<Retained> {
        if files::open(output.retained().entry(), false).is_err() {
            return Ok(Retained::Missing);
        }
        self.operation
            .recheck_retained(stage, output)
            .map(|()| Retained::Verified)
            .map_err(|error| self.stage_error(error))
    }
}

impl<'a> solve::NodeDriver for NodeSession<'a> {
    fn select(&mut self) -> Result<solve::Selection> {
        let catalogs = select::select(self.project, self.policy.environment.as_deref())
            .map_err(|_| Failure::Policy)?;
        let catalog_id = graph::catalog_id(&catalogs)?;
        let image = catalogs.images.get(&self.key.producer).cloned();
        let builder = catalogs
            .builders
            .get(&self.builder)
            .cloned()
            .ok_or(Failure::Policy)?;
        if self.bound.is_none() {
            self.bound = image.clone().map(|image| (image, builder.clone()));
        }
        self.catalogs = Some(catalogs);
        Ok(solve::Selection {
            catalog_id,
            image,
            builder_name: self.builder.clone(),
            builder,
        })
    }

    fn workspace(&self) -> PathBuf {
        self.policy.workspace_path()
    }

    fn allowance(&self) -> u64 {
        let tools: u64 = self
            .policy
            .tools
            .keys()
            .filter_map(|tool| tool.identity().ok())
            .map(|(_, size)| size)
            .sum();
        self.policy
            .limits
            .content
            .staging_bytes
            .saturating_sub(tools)
            .saturating_sub(CLIENT_METADATA_RESERVE)
    }

    fn deadline(&self) -> Result<u64> {
        deadline(monotonic_ns(), self.policy.limits.metadata_ms)
    }

    fn open(&mut self) -> std::result::Result<(), StageError> {
        let (image, builder) = self.bound.clone().ok_or_else(|| error(Failure::Policy))?;
        require(!self.cancellation.requested(), Failure::Cancellation).map_err(error)?;
        let base = self.lease_parent.join(&self.policy.operation_id);
        let mut secrets = vec![
            builder.declaration.tls.certificate.clone(),
            builder.declaration.tls.key.clone(),
        ];
        let mut options = ProtectedOptions {
            selected: true,
            ..ProtectedOptions::default()
        };
        for (id, secret) in &image.declaration.secrets {
            require(valid_name(id) && id.len() <= 255, Failure::Policy).map_err(error)?;
            options
                .secrets
                .insert(id.clone(), base.join(format!("input-{}", secrets.len())));
            secrets.push(secret.clone());
        }
        for (id, path) in &image.ssh {
            require(
                valid_name(id)
                    && id.len() <= 255
                    && valid_path(path)
                    && !path.to_string_lossy().contains([',', '\n', '\r']),
                Failure::Policy,
            )
            .map_err(error)?;
            options.ssh.insert(id.clone(), path.clone());
        }
        options.stage = image.declaration.stage.clone();
        for secret in &secrets {
            reference(secret).map_err(error)?;
        }
        require(
            secrets.len() <= protected::MAX_FILES && options.ssh.len() <= 128,
            Failure::Limit,
        )
        .map_err(error)?;
        let workspace = self.policy.workspace_path();
        let disjoint = |path: &Path| !base.starts_with(path) && !path.starts_with(&base);
        require(
            disjoint(&workspace)
                && image
                    .contexts
                    .values()
                    .chain([&image.context, &image.dockerfile])
                    .chain(image.output_path.iter())
                    .all(|path| disjoint(path)),
            Failure::Policy,
        )
        .map_err(error)?;
        let builder_policy = BuilderPolicy {
            endpoint: builder.declaration.endpoint.supplied.clone(),
            server_name: builder.server_name.clone(),
            ca: builder.ca.clone(),
            certificate: base.join("input-0"),
            key: base.join("input-1"),
            platforms: image.platforms.clone(),
            entitlements: image.declaration.entitlements.clone(),
        };
        builder_policy.validate().map_err(error)?;
        let owned = Lease::new(
            self.lease_parent.clone(),
            &self.policy.operation_id,
            Some(builder_policy.ca.clone()),
            options.ssh.values().cloned().collect(),
            true,
        )
        .map_err(error)?;
        self.lease_path = Some(owned.path.clone());
        let checked = preflight(self.policy.clone()).map_err(error)?;
        let operation = Operation::open(checked, self.cancellation.clone())?;
        self.operation = Some(operation);
        self.lease = Some(owned);
        self.secrets = secrets;
        self.options = options;
        self.builder_policy = Some(builder_policy);
        Ok(())
    }

    fn snapshot(
        &mut self,
        request: &solve::ContextRequest,
    ) -> std::result::Result<
        std::result::Result<solve::ContextSnapshot, solve::ContextRefused>,
        StageError,
    > {
        self.operation()?.context_snapshot(request.clone())
    }

    fn recheck(
        &mut self,
        resolution: &Resolution,
        material: &Material,
        selection: &solve::Selection,
    ) -> std::result::Result<Vec<Diagnostic>, StageError> {
        let catalogs = self
            .catalogs
            .as_ref()
            .ok_or_else(|| error(Failure::Policy))?;
        let dockerfiles = catalogs
            .images
            .values()
            .map(|image| image.dockerfile.clone())
            .collect();
        let root = &self.project.broil_root;
        let cancellation = self.cancellation.clone();
        let operation = self
            .operation
            .as_mut()
            .ok_or_else(|| error(Failure::Policy))?;
        let mut driver = RecheckDriver {
            operation,
            cancellation,
            dockerfiles,
            last_error: None,
        };
        let checked = graph::recheck(
            resolution,
            material,
            catalogs,
            root,
            &selection.catalog_id,
            &graph::Limits::default(),
            &mut driver,
        );
        match checked {
            Ok(stale) => Ok(stale),
            Err(failure) => Err(match driver.last_error.take() {
                Some(error) if error.failure == failure => error,
                _ => error(failure),
            }),
        }
    }

    fn acquire(&mut self, image: &EffectiveImage) -> std::result::Result<(), StageError> {
        let environment = self.policy.environment.clone();
        let selected = read::Selection::new(
            &self.project.config,
            &self.project.broil_root,
            environment.as_deref().map(OsStr::new),
        )
        .map_err(|_| error(Failure::Policy))?;
        let inputs = self.inputs.take().ok_or_else(|| error(Failure::Policy))?;
        require(
            self.bound
                .as_ref()
                .is_some_and(|(bound, _)| bound.declaration.secrets == image.declaration.secrets),
            Failure::Policy,
        )
        .map_err(error)?;
        let secrets = self.secrets.clone();
        let cancellation = self.cancellation.clone();
        let result: std::result::Result<(), StageError> = (|| {
            let operation = self
                .operation
                .as_mut()
                .ok_or_else(|| error(Failure::Policy))?;
            action(operation, &mut self.lease, Action::Prepare)?;
            for secret in &secrets {
                let scalar = acquire(&selected, &inputs, secret, &cancellation).map_err(error)?;
                let operation = self
                    .operation
                    .as_mut()
                    .ok_or_else(|| error(Failure::Policy))?;
                action(operation, &mut self.lease, Action::Materialize(scalar))?;
            }
            Ok(())
        })();
        drop(inputs);
        if let Err(failure) = &result {
            if let Some(operation) = self.operation.as_mut() {
                operation.acquisition_failed(failure.failure);
            }
        }
        result
    }

    fn discover(
        &mut self,
        _builder: &EffectiveBuilder,
        _image: &EffectiveImage,
    ) -> std::result::Result<BuilderCapabilities, StageError> {
        let policy = self
            .builder_policy
            .clone()
            .ok_or_else(|| error(Failure::Policy))?;
        let lease_recheck = {
            let operation = self
                .operation
                .as_mut()
                .ok_or_else(|| error(Failure::Policy))?;
            action(operation, &mut self.lease, Action::Recheck)
        };
        lease_recheck?;
        let operation = self.operation()?;
        operation.create_builder("builder", policy)?;
        operation.inspect_builder("inspect")?;
        operation
            .builder_capabilities()
            .cloned()
            .ok_or_else(|| error(Failure::Protocol))
    }

    fn materialize(
        &mut self,
        plan: solve::Plan,
        ignore: Option<solve::IgnoreCopy>,
    ) -> std::result::Result<
        std::result::Result<(solve::Materialized, solve::PlanFacts), solve::Refusal>,
        StageError,
    > {
        let ignore_identity = ignore.as_ref().map(|copy| (copy.digest.clone(), copy.size));
        let workspace = self.operation()?.workspace().clone();
        let (work, facts) = solve::MaterializeWork::new(workspace, plan, ignore).map_err(error)?;
        let materialized = match self.operation()?.materialize_inputs(work)? {
            Ok(materialized) => materialized,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let layouts: Vec<(Entry, Content)> = materialized
            .layouts
            .iter()
            .zip(&facts.layouts)
            .map(|(entry, root)| {
                (
                    entry.clone(),
                    Content::Oci {
                        root: root.clone(),
                        cache: false,
                        complete: true,
                        registry_receipt: false,
                    },
                )
            })
            .collect();
        if let Err(error) = self.operation()?.verify_inputs("verify-layouts", &layouts) {
            let refused = matches!(
                error.failure,
                Failure::Policy
                    | Failure::Protocol
                    | Failure::Integrity
                    | Failure::Storage
                    | Failure::Limit
            );
            return Ok(Err(solve::Refusal {
                failure: error.failure,
                check: refused.then_some(solve::FailedCheck::Link),
            }));
        }
        let mut files = vec![
            (
                materialized.dockerfile.clone(),
                Content::File {
                    digest: facts.dockerfile_digest.clone(),
                    size: facts.dockerfile_size,
                },
            ),
            (
                materialized.bake.clone(),
                Content::File {
                    digest: facts.bake_digest.clone(),
                    size: facts.bake_size,
                },
            ),
        ];
        if let (Some(entry), Some((digest, size))) = (&materialized.ignore, ignore_identity) {
            files.push((entry.clone(), Content::File { digest, size }));
        }
        self.operation()?.verify_inputs("verify-files", &files)?;
        Ok(Ok((materialized, facts)))
    }

    fn recheck_imports(
        &mut self,
        imports: &[VerifiedOutput],
    ) -> std::result::Result<(), StageError> {
        for staging in imports {
            self.operation()?
                .recheck_complete("recheck-cache", staging)?;
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        target: &str,
        bake: &Entry,
        facts: &solve::PlanFacts,
        platform: &str,
        cache: &CacheArguments,
    ) -> std::result::Result<Baked, BakeFailure> {
        let options = std::mem::take(&mut self.options);
        let operation = self.operation().map_err(|error| BakeFailure {
            error,
            export: false,
            launched: false,
        })?;
        let baked = operation.bake_selected(
            "solve",
            target,
            bake.clone(),
            facts.bake_digest.clone(),
            facts.bake_size,
            &facts.read_paths,
            None,
            &[platform.to_owned()],
            &options,
            cache,
        );
        self.dispatched = true;
        self.carried = match &baked {
            Ok(_) => true,
            Err(failure) => failure.launched,
        };
        baked
    }

    fn upload_layout(
        &mut self,
        export: &VerifiedOutput,
    ) -> std::result::Result<VerifiedOutput, StageError> {
        self.operation()?.upload_layout(export)
    }

    fn exported_config(
        &mut self,
        output: &VerifiedOutput,
        platform: &str,
    ) -> std::result::Result<super::buffer::Bytes, StageError> {
        self.operation()?
            .exported_config("exported-config", output, platform)
    }

    fn dispatched(&self) -> bool {
        self.dispatched
    }

    fn carried(&self) -> bool {
        self.carried
    }

    fn close(mut self, keep: &[VerifiedOutput]) -> (Option<SessionObservation>, Option<Kept>) {
        self.inputs = None;
        let Some(mut operation) = self.operation.take() else {
            return (None, None);
        };
        if keep.is_empty() {
            operation.refusal_deadline();
        }
        let lease = self.lease.take();
        let path = self
            .lease_path
            .take()
            .unwrap_or_else(|| self.lease_parent.join(&self.policy.operation_id));
        let mut outcome = finish(operation, lease, path, Ok::<(), StageError>(()), keep);
        let kept = outcome.release.take();
        (Some(observation(&outcome, &self.policy.operation_id)), kept)
    }
}

#[derive(Clone, Debug)]
pub struct PublishSelection {
    pub target: String,
    pub artifact: RetainedArtifact,
    pub registry: Option<String>,
    pub artifact_id: Option<String>,
}

pub struct Publication<'a> {
    project: &'a LoadedProject,
    policy: Policy,
    selection: PublishSelection,
    reference: String,
    registry: Option<String>,
}

pub fn publication(
    project: &LoadedProject,
    policy: Policy,
    selection: PublishSelection,
) -> Result<Publication<'_>> {
    bound(project, &policy)?;
    policy.validate()?;
    require(policy.tools.contains_key(&Tool::Registry), Failure::Policy)?;
    let catalogs =
        select::select(project, policy.environment.as_deref()).map_err(|_| Failure::Policy)?;
    let image = catalogs
        .images
        .get(&selection.target)
        .ok_or(Failure::Policy)?;
    let reference = image.declaration.image.supplied.clone();
    let registry = selection
        .registry
        .clone()
        .or_else(|| image.declaration.registry.clone());
    catalogs
        .registry_policy(
            &image.declaration.image,
            RegistryPurpose::Push,
            registry.as_deref(),
        )
        .map_err(|_| Failure::Policy)?;
    let artifact = &selection.artifact;
    artifact.root.validate()?;
    require(
        matches!(
            artifact.kind,
            broil_core::images::OutputKind::OciLayout | broil_core::images::OutputKind::OciArchive
        ) && valid_path(&artifact.location)
            && artifact.archive.is_some()
                == (artifact.kind == broil_core::images::OutputKind::OciArchive),
        Failure::Policy,
    )?;
    require(
        artifact.verified_files <= policy.limits.content.descriptors
            && artifact.verified_bytes <= policy.limits.content.content_bytes
            && artifact.manifests.len() <= 64,
        Failure::Limit,
    )?;
    for (platform, manifest) in &artifact.manifests {
        require(valid_platform(platform), Failure::Policy)?;
        manifest.validate()?;
    }
    if let Some(artifact_id) = &selection.artifact_id {
        require(records::valid_artifact(artifact_id), Failure::Policy)?;
    }
    Ok(Publication {
        project,
        policy,
        selection,
        reference,
        registry,
    })
}

impl Publication<'_> {
    pub fn run(
        self,
        inputs: Inputs,
        cancellation: Cancellation,
    ) -> (PublicationReport, Option<Kept>) {
        let target = self.selection.target.clone();
        let artifact = &self.selection.artifact;
        let failed = |failure: Failure| {
            (
                PublicationReport::new(
                    &target,
                    PublicationOutcome::Failed {
                        class: PublicationClass::of(failure),
                        check: None,
                    },
                ),
                None,
            )
        };
        let opened = (|| {
            let tools = records::capture_tools(&records::pinned_buildkit_version()?)
                .map_err(|refusal| refusal.failure)?;
            let request = serde_json::json!({
                "artifact": {
                    "kind": outputs::kind_name(artifact.kind),
                    "location": artifact.location,
                    "manifests": artifact
                        .manifests
                        .iter()
                        .map(|(platform, manifest)| serde_json::json!({
                            "digest": manifest.digest,
                            "platform": platform,
                        }))
                        .collect::<Vec<_>>(),
                    "root": artifact.root.digest,
                },
                "caller_artifact_id": self.selection.artifact_id,
                "environment": self.policy.environment,
                "reference": self.reference,
                "registry": self.registry,
                "target": target,
            });
            records::Recorder::open(
                &self.project.broil_root,
                "publication",
                "standalone-publication",
                &request,
                self.policy.environment.clone(),
                tools,
                cancellation.clone(),
                &self.policy.limits,
            )
        })();
        let mut recorder = match opened {
            Ok(recorder) => recorder,
            Err(failure) => return failed(failure),
        };
        let (bound, reason, candidates) = match recorder.bind(
            &artifact.location,
            outputs::kind_name(artifact.kind),
            &artifact.root,
        ) {
            Ok(records::Binding::Bound(candidate)) => (Some(candidate.artifact_id), None, None),
            Ok(records::Binding::Unbound(reason)) => (None, Some(reason), None),
            Ok(records::Binding::Ambiguous(candidates)) => (None, None, Some(candidates)),
            Err(_) => (None, None, None),
        };
        let proved = bound.is_some();
        let artifact_id = bound.or_else(|| self.selection.artifact_id.clone());
        if let Err(failure) = recorder.marker(records::Boundary::Publication, Some(&target), None) {
            return failed(failure);
        }
        let driver = PublishSession {
            project: self.project,
            policy: self.policy,
            inputs: Some(inputs),
            cancellation,
            operation: None,
            reference: self.reference,
            registry: self.registry,
            artifact_id: artifact_id.clone(),
            keep: None,
        };
        let (mut report, kept) = publish::publication_stage(
            driver,
            &publish::PublishInput::Standalone {
                target: &target,
                artifact,
            },
        );
        publication_boundary(&mut recorder, &target, &mut report);
        if let (true, PublicationOutcome::Published(observation)) = (proved, &mut report.outcome) {
            observation.predicate = "published";
        }
        if let PublicationOutcome::Published(observation) = &report.outcome {
            let reason = artifact_id.is_none().then_some(reason).flatten();
            let appended =
                recorder.publication(&target, observation, &report, artifact_id.clone(), reason);
            if let (Ok(published), Some(candidates), None) = (appended, candidates, &artifact_id) {
                let _ = recorder.ambiguity(published.seq, candidates);
            }
        }
        let _ = recorder.rebuild_index();
        (report, kept)
    }
}

struct PublishSession<'a> {
    project: &'a LoadedProject,
    policy: Policy,
    inputs: Option<Inputs>,
    cancellation: Cancellation,
    operation: Option<(Operation, String)>,
    reference: String,
    registry: Option<String>,
    artifact_id: Option<String>,
    keep: Option<VerifiedOutput>,
}

impl PublishSession<'_> {
    fn policy_for(&self, tools: &[Tool]) -> Result<Policy> {
        policy_for(&self.policy, tools)
    }

    fn inputs(&self) -> Result<Inputs> {
        duplicate_inputs(self.inputs.as_ref())
    }

    fn operation(&mut self) -> std::result::Result<&mut Operation, StageError> {
        self.operation
            .as_mut()
            .map(|(operation, _)| operation)
            .ok_or_else(|| error(Failure::Policy))
    }

    fn selected(&self) -> Result<(RegistryPolicy, ImageReference)> {
        let catalogs = select::select(self.project, self.policy.environment.as_deref())
            .map_err(|_| Failure::Policy)?;
        let image = ImageReference::parse(&self.reference).ok_or(Failure::Policy)?;
        let policy = catalogs
            .registry_policy(&image, RegistryPurpose::Push, self.registry.as_deref())
            .map_err(|_| Failure::Policy)?;
        Ok((policy, image))
    }

    fn binding(&self, operation_id: &str) -> Result<publish::Binding> {
        let (policy, image) = self.selected()?;
        let authentication = match &policy.credential {
            None => "anonymous",
            Some(RegistryCredential::Token(_)) => "bearer",
            Some(RegistryCredential::Password { .. }) => "password",
        };
        let development_http = policy.endpoint.supplied.starts_with("http://");
        Ok(publish::Binding {
            endpoint: policy.endpoint.supplied.clone(),
            server: publish::server(
                &policy.endpoint.supplied,
                development_http,
                policy.ca.is_some(),
                authentication,
            ),
            repository: image.repository.clone(),
            operation_id: operation_id.into(),
            artifact_id: self.artifact_id.clone(),
        })
    }
}

impl publish::PublishDriver for PublishSession<'_> {
    fn cancelled(&self) -> bool {
        self.cancellation.requested()
    }

    fn open_layout(&mut self) -> std::result::Result<(), StageError> {
        let mut policy = self.policy.clone();
        policy.operation_id = format!(
            "operation-{}",
            broil_core::secret::path_safety::sudo_nonce().map_err(|_| error(Failure::Capacity))?
        );
        policy.tools = BTreeMap::new();
        let operation_id = policy.operation_id.clone();
        let checked = preflight(policy).map_err(error)?;
        let operation = Operation::open(checked, self.cancellation.clone())?;
        self.operation = Some((operation, operation_id));
        Ok(())
    }

    fn layout_operation(&self) -> Option<(String, Entry)> {
        self.operation
            .as_ref()
            .map(|(operation, id)| (id.clone(), operation.workspace().clone()))
    }

    fn allowance(&self) -> u64 {
        self.operation
            .as_ref()
            .map_or(0, |(operation, _)| operation.remaining())
            .saturating_sub(CLIENT_METADATA_RESERVE)
    }

    fn limits(&self) -> ContentLimits {
        self.policy.limits.content.clone()
    }

    fn recheck(&mut self, output: &VerifiedOutput) -> std::result::Result<(), StageError> {
        self.operation()?.recheck_complete("recheck-output", output)
    }

    fn chain(
        &mut self,
        output: &VerifiedOutput,
        platform: &str,
    ) -> std::result::Result<(Descriptor, Vec<Descriptor>), StageError> {
        self.operation()?.node_chain("read-chain", output, platform)
    }

    fn retained_closure(
        &mut self,
        entry: &Entry,
        root: &Descriptor,
        manifests: &[(String, Descriptor)],
    ) -> std::result::Result<Vec<(Descriptor, Vec<Descriptor>)>, StageError> {
        if self.operation.is_some() {
            return self
                .operation()?
                .retained_closure("read-retained", entry, root, manifests);
        }
        let end = deadline(monotonic_ns(), self.policy.limits.metadata_ms).map_err(error)?;
        let mut chains = Vec::new();
        for (platform, manifest) in manifests {
            require(!self.cancellation.requested(), Failure::Cancellation).map_err(error)?;
            before(end).map_err(error)?;
            chains.push(
                publish::retained_chain(entry, root, platform, manifest, end).map_err(error)?,
            );
        }
        Ok(chains)
    }

    fn layout(
        &mut self,
        work: publish::PublishWork,
        root: &Descriptor,
    ) -> std::result::Result<(Entry, u64, u64), StageError> {
        let (layout, files, bytes) = self.operation()?.publication_layout(work, root)?;
        let entry = layout.entry().clone();
        self.keep = Some(layout);
        Ok((entry, files, bytes))
    }

    fn unpack(
        &mut self,
        work: publish::UnpackWork,
        root: &Descriptor,
    ) -> std::result::Result<(Entry, u64, u64), StageError> {
        let (layout, files, bytes) = self.operation()?.publication_unpack(work, root)?;
        let entry = layout.entry().clone();
        self.keep = Some(layout);
        Ok((entry, files, bytes))
    }

    fn close_layout(
        &mut self,
        layout: Option<&Entry>,
    ) -> (Option<Kept>, Option<SessionObservation>) {
        let Some((mut operation, operation_id)) = self.operation.take() else {
            return (None, None);
        };
        let keep: Vec<VerifiedOutput> = match (layout, self.keep.take()) {
            (Some(entry), Some(output)) if output.entry() == entry => vec![output],
            _ => {
                operation.refusal_deadline();
                Vec::new()
            }
        };
        let close = operation.close(None, &keep);
        let session = SessionObservation {
            operation_id,
            cleanup: close.result,
            residue: close.private_residue,
            unresolved_owner: close.unresolved_private_owner,
        };
        (close.kept, Some(session))
    }

    fn upload(&mut self, request: &publish::UploadRequest<'_>) -> publish::UploadResult {
        let prepared = (|| {
            let policy = self.policy_for(&[Tool::Registry])?;
            let operation_id = policy.operation_id.clone();
            let binding = self.binding(&operation_id)?;
            let consumer = registry(
                self.project,
                policy,
                RegistrySelection {
                    stage: "publish-upload".into(),
                    reference: self.reference.clone(),
                    purpose: RegistryPurpose::Push,
                    registry: self.registry.clone(),
                    optional: false,
                    expected_root: Some(request.expected_root.clone()),
                    input: Some(request.input.clone()),
                    inspect_input: request.inspect.is_some(),
                    limits: BTreeMap::new(),
                },
            )?;
            Ok((consumer, operation_id, binding, self.inputs()?))
        })();
        let (consumer, operation_id, binding, inputs) = match prepared {
            Ok(prepared) => prepared,
            Err(failure) => {
                return publish::UploadResult {
                    outcome: publish::PublicationOutcome::Failed {
                        class: PublicationClass::of(failure),
                        check: Some(PublicationCheck::Request),
                    },
                    session: None,
                    staging: None,
                    tag: None,
                    resolved: true,
                };
            }
        };
        let tag = ImageReference::parse(&self.reference)
            .and_then(|image| image.effective_tag().map(str::to_owned));
        let outcome = match consumer.run(inputs, self.cancellation.clone()) {
            Ok(outcome) => outcome,
            Err(error) => {
                return publish::UploadResult {
                    outcome: publish::resolve(
                        &binding,
                        request.planned,
                        Err(&error),
                        tag.clone(),
                        request.inspect.is_some(),
                        false,
                    ),
                    session: None,
                    staging: None,
                    tag: None,
                    resolved: true,
                };
            }
        };
        let session = observation(&outcome, &operation_id);
        let resolved = session.cleanup.is_ok() && !session.unresolved_owner;
        let dispatched = outcome.result.as_ref().map_or_else(
            |error| error.observation.dispatch != super::Dispatch::None,
            |value| value.observation.dispatch != super::Dispatch::None,
        );
        let maximum = self.policy.limits.content.staging_bytes;
        let staging = outcome.result.as_ref().ok().map(|value| StagingDelta {
            operation: "upload",
            operation_id: operation_id.clone(),
            counted_bytes: maximum.saturating_sub(value.helper_allowance),
            allowance_bytes: value.helper_allowance,
        });
        let result = match &outcome.result {
            Ok(value) => publish::resolve(
                &binding,
                request.planned,
                Ok(value),
                tag.clone(),
                request.inspect.is_some(),
                dispatched,
            ),
            Err(error) => publish::resolve(
                &binding,
                request.planned,
                Err(error),
                tag.clone(),
                request.inspect.is_some(),
                dispatched,
            ),
        };
        let association = match (&result, &tag) {
            (publish::PublicationOutcome::Published(observed), _) => observed.tag.clone(),
            (_, _) => None,
        };
        publish::UploadResult {
            outcome: result,
            session: Some(session),
            staging,
            tag: association,
            resolved,
        }
    }

    fn release(&mut self, kept: Kept) -> std::result::Result<(), (Option<Kept>, Failure)> {
        release(&self.policy, kept, self.cancellation.clone())
            .map(|_| ())
            .map_err(|unreleased| (unreleased.kept, unreleased.error.failure))
    }
}

fn retain(mut outcome: Outcome<GraphOutcome>) -> Outcome<GraphOutcome> {
    if let Ok(GraphOutcome {
        result: GraphResult::Resolved { material, .. },
        ..
    }) = &mut outcome.result
    {
        material.retain_closures();
    }
    outcome
}

