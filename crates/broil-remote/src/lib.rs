// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

pub mod alias;
pub mod auth;
pub mod check;
pub mod exec;
mod jobs;
pub mod known_hosts;
pub use broil_core::secret::path_safety;
pub mod provision;
pub mod scheduler;
pub mod secret;
pub mod ssh;
pub mod staging;
pub mod stats;
pub mod sudo;
pub mod transfer;
mod transfer_path;
mod transfer_sftp;
pub mod transport;
pub mod trust;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;

use broil_config::LoadedProject;
use broil_core::error::{RemoteError, UsageError};
use broil_core::remote::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    Configuration,
    Selector,
    SecretUnavailable,
    Dns,
    ConnectTimeout,
    AuthenticationTimeout,
    UnknownHostKey,
    ChangedHostKey,
    AuthenticationRejected,
    AuthenticationLocallyUnavailable,
    JumpFailure,
    RemoteNonzero,
    Sftp,
    TransferPathSafety,
    Sudo,
    CapabilityUnsupported,
    StatisticsCollection,
    Protocol,
    ReadinessNegative,
    SecurityGate,
    Rollback,
    RebootTimeout,
    FailFast,
    Cancellation,
    IndeterminateAfterDispatch,
}

impl FailureClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Selector => "selector",
            Self::SecretUnavailable => "secret unavailable",
            Self::Dns => "DNS",
            Self::ConnectTimeout => "connect timeout",
            Self::AuthenticationTimeout => "authentication timeout",
            Self::UnknownHostKey => "unknown host key",
            Self::ChangedHostKey => "changed host key",
            Self::AuthenticationRejected => "authentication rejected",
            Self::AuthenticationLocallyUnavailable => "authentication locally unavailable",
            Self::JumpFailure => "jump failure",
            Self::RemoteNonzero => "remote nonzero",
            Self::Sftp => "SFTP",
            Self::TransferPathSafety => "transfer/path safety",
            Self::Sudo => "sudo",
            Self::CapabilityUnsupported => "capability unsupported",
            Self::StatisticsCollection => "statistics collection",
            Self::Protocol => "protocol",
            Self::ReadinessNegative => "readiness negative",
            Self::SecurityGate => "security gate",
            Self::Rollback => "rollback",
            Self::RebootTimeout => "reboot timeout",
            Self::FailFast => "fail-fast",
            Self::Cancellation => "cancellation",
            Self::IndeterminateAfterDispatch => "indeterminate after dispatch",
        }
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    pub algorithm: String,
    pub base64: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveInventory {
    pub environment: String,
    pub known_hosts: Option<String>,
    pub operations_parallelism: Parallelism,
    pub provision_parallelism: Parallelism,
    pub default_interpreter: Vec<String>,
    pub env_vars: BTreeMap<String, String>,
    pub scripts: BTreeMap<String, EffectiveRemoteScript>,
    pub jumps: Vec<EffectiveJump>,
    pub machines: Vec<EffectiveMachine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRemoteScript {
    pub body: String,
    pub interpreter: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub privilege: Option<String>,
    pub pty: PtyMode,
    pub timeout: Option<DurationValue>,
    pub env: BTreeMap<String, RemoteEnvValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JumpScope {
    Root,
    Environment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveJump {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub auth_profile: String,
    pub scope: JumpScope,
    pub connect_timeout: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveMachine {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub tags: Vec<String>,
    pub route: String,
    pub canonical_profile: String,
    pub canonical_user: String,
    pub bootstrap_profiles: Vec<EffectiveAuth>,
    pub privilege_profile: Option<String>,
    pub stats_script: Option<String>,
    pub provision_profiles: Vec<String>,
    pub vars: BTreeMap<String, String>,
    pub timeouts: EffectiveTimeouts,
    pub plan: Result<Option<EffectivePlan>, PlanValidationError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAuth {
    pub profile: String,
    pub user: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveTimeouts {
    pub connect: DurationValue,
    pub command: DurationValue,
    pub transfer: DurationValue,
    pub reboot_disconnect: DurationValue,
    pub reboot_readiness: DurationValue,
    pub reboot_poll: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePlan {
    pub steps: Vec<EffectivePlanStep>,
    pub transition_owner: String,
    pub transition_actions: Vec<EffectiveNamedScriptAction>,
    pub security_verifiers: Vec<EffectiveNamedScriptAction>,
    pub runtime_steps: Vec<provision::ProvisionStep>,
    pub runtime_transition_actions: Vec<provision::NamedScriptAction>,
    pub runtime_security_verifiers: Vec<provision::NamedScriptAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanValidationError {
    TransitionOwnerCount { count: usize },
    MissingSecurityVerifier,
    MissingScriptBinding { action: String, binding: String },
    UnprivilegedSecurityVerifier { action: String },
    UploadOwnerRequiresRoot { action: String },
    MissingSecretStdinProvider { action: String, provider: String },
    MissingActionPrivilege { action: String, privilege: String },
    PasswordSudoWithSecretStdin { action: String },
    UnprivilegedReboot { action: String },
    ActionBeforeConfigure { action: String },
}

impl fmt::Display for PlanValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransitionOwnerCount { count } => {
                write!(
                    f,
                    "expected exactly one SSH transition owner, found {count}"
                )
            }
            Self::MissingSecurityVerifier => {
                f.write_str("expected at least one server-side security verifier")
            }
            Self::MissingScriptBinding { action, binding } => {
                write!(
                    f,
                    "action {action} has unavailable script binding {binding}"
                )
            }
            Self::UnprivilegedSecurityVerifier { action } => {
                write!(f, "security verifier {action} does not execute as root")
            }
            Self::UploadOwnerRequiresRoot { action } => {
                write!(
                    f,
                    "upload action {action} configures owner without root execution"
                )
            }
            Self::MissingSecretStdinProvider { action, provider } => {
                write!(
                    f,
                    "action {action} references unavailable stdin secret provider {provider}"
                )
            }
            Self::MissingActionPrivilege { action, privilege } => {
                write!(
                    f,
                    "action {action} references unavailable privilege profile {privilege}"
                )
            }
            Self::PasswordSudoWithSecretStdin { action } => {
                write!(
                    f,
                    "action {action} combines provisioning secret stdin with password sudo"
                )
            }
            Self::UnprivilegedReboot { action } => {
                write!(f, "reboot action {action} does not execute as root")
            }
            Self::ActionBeforeConfigure { action } => {
                write!(f, "action {action} is only valid in configure")
            }
        }
    }
}

impl std::error::Error for PlanValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePlanStep {
    pub id: String,
    pub phase: String,
    pub check: Option<EffectiveTimedAction>,
    pub run: EffectivePlanAction,
    pub verify: Option<EffectiveTimedAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNamedScriptAction {
    pub name: String,
    pub script: String,
    pub stdin_secret: bool,
    pub timeout: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveTimedAction {
    pub kind: String,
    pub script: Option<String>,
    pub stdin_secret: bool,
    pub timeout: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveRebootAction {
    pub when: Option<EffectiveTimedAction>,
    pub disconnect_timeout: DurationValue,
    pub readiness_timeout: DurationValue,
    pub poll_interval: DurationValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectivePlanAction {
    Timed(EffectiveTimedAction),
    Reboot(EffectiveRebootAction),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selectors {
    pub machines: Vec<String>,
    pub tags: Vec<String>,
    pub all: bool,
}

struct Definitions<'a> {
    secret_providers: BTreeMap<&'a str, &'a SecretProvider>,
    auth_profiles: BTreeMap<&'a str, &'a AuthProfile>,
    privilege_profiles: BTreeMap<&'a str, &'a PrivilegeProfile>,
    scripts: BTreeMap<&'a str, &'a RemoteScript>,
    provision_profiles: BTreeMap<&'a str, &'a ProvisionProfile>,
}

pub fn resolve(
    project: &LoadedProject,
    ambient_environment: Option<&OsStr>,
) -> Result<EffectiveInventory, RemoteError> {
    let value = ambient_environment.ok_or(RemoteError::MissingEnvironment)?;
    if value.is_empty() {
        return Err(RemoteError::MissingEnvironment);
    }
    let name = value.to_str().ok_or(RemoteError::NonUtf8Environment)?;
    let environment =
        project
            .config
            .environments
            .get(name)
            .ok_or_else(|| RemoteError::UnknownEnvironment {
                name: name.to_string(),
            })?;

    let mut defaults = project.config.remote.definitions.defaults.clone();
    overlay_defaults(&mut defaults, &environment.remote.definitions.defaults);
    let definitions = Definitions {
        secret_providers: overlay_map(
            &project.config.remote.definitions.secret_providers,
            &environment.remote.definitions.secret_providers,
        ),
        auth_profiles: overlay_map(
            &project.config.remote.definitions.auth_profiles,
            &environment.remote.definitions.auth_profiles,
        ),
        privilege_profiles: overlay_map(
            &project.config.remote.definitions.privilege_profiles,
            &environment.remote.definitions.privilege_profiles,
        ),
        scripts: overlay_map(
            &project.config.remote.definitions.scripts,
            &environment.remote.definitions.scripts,
        ),
        provision_profiles: overlay_map(
            &project.config.remote.definitions.provision_profiles,
            &environment.remote.definitions.provision_profiles,
        ),
    };
    let order = if environment.remote.machine_order.is_empty() {
        environment.remote.machines.keys().cloned().collect()
    } else {
        environment.remote.machine_order.clone()
    };
    let mut env_vars = project.config.env_vars.clone();
    env_vars.extend(environment.env_vars.clone());
    let machines = order
        .iter()
        .map(|machine_name| {
            effective_machine(
                machine_name,
                &environment.remote.machines[machine_name],
                &project.config.remote.machine_templates,
                &defaults,
                &definitions,
                &env_vars,
            )
        })
        .collect();
    let root_jumps = &project.config.remote.definitions.jump_hosts;
    let environment_jumps = &environment.remote.definitions.jump_hosts;
    let mut jumps = Vec::new();
    let root_order = if project.config.remote.definitions.jump_order.is_empty() {
        root_jumps.keys().cloned().collect::<Vec<_>>()
    } else {
        project.config.remote.definitions.jump_order.clone()
    };
    for jump_name in root_order {
        if environment_jumps.contains_key(&jump_name) {
            continue;
        }
        let jump = &root_jumps[&jump_name];
        jumps.push(EffectiveJump {
            name: jump_name,
            address: jump.address.clone(),
            port: jump.port,
            auth_profile: jump.auth.clone(),
            scope: JumpScope::Root,
            connect_timeout: effective_timeouts(&defaults.timeouts).connect,
        });
    }
    let environment_order = if environment.remote.definitions.jump_order.is_empty() {
        environment_jumps.keys().cloned().collect::<Vec<_>>()
    } else {
        environment.remote.definitions.jump_order.clone()
    };
    for jump_name in environment_order {
        let jump = &environment_jumps[&jump_name];
        jumps.push(EffectiveJump {
            name: jump_name,
            address: jump.address.clone(),
            port: jump.port,
            auth_profile: jump.auth.clone(),
            scope: JumpScope::Environment,
            connect_timeout: effective_timeouts(&defaults.timeouts).connect,
        });
    }
    let operations_parallelism = defaults
        .parallelism
        .operations
        .clone()
        .unwrap_or(Parallelism::Limit(8));
    let provision_parallelism = defaults
        .parallelism
        .provision
        .clone()
        .unwrap_or(Parallelism::Limit(1));
    Ok(EffectiveInventory {
        environment: name.to_string(),
        known_hosts: defaults.known_hosts,
        operations_parallelism,
        provision_parallelism,
        default_interpreter: defaults
            .interpreter
            .clone()
            .unwrap_or_else(|| vec!["/bin/sh".to_string()]),
        env_vars,
        scripts: definitions
            .scripts
            .iter()
            .map(|(name, script)| {
                (
                    (*name).to_string(),
                    EffectiveRemoteScript {
                        body: script.body.clone(),
                        interpreter: script.interpreter.clone(),
                        cwd: script.cwd.clone(),
                        privilege: script.privilege.clone(),
                        pty: script.pty,
                        timeout: script.timeout.clone(),
                        env: script.env.clone(),
                    },
                )
            })
            .collect(),
        jumps,
        machines,
    })
}

pub fn select<'a>(
    inventory: &'a EffectiveInventory,
    selectors: &Selectors,
    default_all: bool,
) -> Result<Vec<&'a EffectiveMachine>, UsageError> {
    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    if !default_all && !selectors.all && selectors.machines.is_empty() && selectors.tags.is_empty()
    {
        return Err(UsageError::RemoteMissingSelector);
    }
    let mut selected = BTreeSet::new();
    if selectors.all || selectors.machines.is_empty() {
        selected.extend(0..inventory.machines.len());
    } else {
        for selector in &selectors.machines {
            let matches: Vec<usize> = inventory
                .machines
                .iter()
                .enumerate()
                .filter(|(_, machine)| machine.name == *selector || machine.address == *selector)
                .map(|(index, _)| index)
                .collect();
            match matches.as_slice() {
                [] => {
                    return Err(UsageError::RemoteUnknownMachine {
                        selector: selector.clone(),
                    });
                }
                [index] => {
                    selected.insert(*index);
                }
                _ => {
                    return Err(UsageError::RemoteAmbiguousMachine {
                        selector: selector.clone(),
                    });
                }
            }
        }
    }
    let result: Vec<_> = inventory
        .machines
        .iter()
        .enumerate()
        .filter(|(index, machine)| {
            selected.contains(index) && selectors.tags.iter().all(|tag| machine.tags.contains(tag))
        })
        .map(|(_, machine)| machine)
        .collect();
    if result.is_empty() {
        Err(UsageError::RemoteEmptySelection)
    } else {
        Ok(result)
    }
}

fn overlay_map<'a, T>(
    root: &'a BTreeMap<String, T>,
    environment: &'a BTreeMap<String, T>,
) -> BTreeMap<&'a str, &'a T> {
    let mut result: BTreeMap<&str, &T> = root
        .iter()
        .map(|(name, value)| (name.as_str(), value))
        .collect();
    result.extend(
        environment
            .iter()
            .map(|(name, value)| (name.as_str(), value)),
    );
    result
}

fn effective_machine(
    name: &str,
    machine: &MachineConfig,
    templates: &BTreeMap<String, MachineTemplate>,
    defaults: &RemoteDefaults,
    definitions: &Definitions<'_>,
    env_vars: &BTreeMap<String, String>,
) -> EffectiveMachine {
    let template = machine.template.as_ref().map(|template| {
        templates
            .get(template)
            .expect("config validation requires a known machine template")
    });
    let mut state = MachineState::new(defaults);
    if let Some(template) = template {
        state.apply(template);
    }
    state.apply(&machine.settings);
    let plan = effective_plan(&state, definitions, env_vars);
    let canonical_profile = state
        .canonical_auth
        .expect("config validation requires canonical auth");
    let canonical_user = definitions.auth_profiles[canonical_profile.as_str()]
        .user
        .clone();
    let bootstrap_profiles = state
        .bootstrap_auth
        .iter()
        .map(|profile| EffectiveAuth {
            profile: profile.clone(),
            user: definitions.auth_profiles[profile.as_str()].user.clone(),
        })
        .collect();
    EffectiveMachine {
        name: name.to_string(),
        address: state.address.expect("config validation requires address"),
        port: state.port,
        tags: state.tags,
        route: state.via,
        canonical_profile,
        canonical_user,
        bootstrap_profiles,
        privilege_profile: state.privilege,
        stats_script: state.stats_script,
        provision_profiles: state.provision_profiles,
        vars: state.vars,
        timeouts: state.timeouts,
        plan,
    }
}

struct MachineState {
    address: Option<String>,
    port: u16,
    tags: Vec<String>,
    via: String,
    canonical_auth: Option<String>,
    bootstrap_auth: Vec<String>,
    privilege: Option<String>,
    stats_script: Option<String>,
    provision_profiles: Vec<String>,
    vars: BTreeMap<String, String>,
    timeouts: EffectiveTimeouts,
}

impl MachineState {
    fn new(defaults: &RemoteDefaults) -> Self {
        Self {
            address: None,
            port: defaults.port.unwrap_or(22),
            tags: Vec::new(),
            via: defaults.via.clone().unwrap_or_else(|| "direct".to_string()),
            canonical_auth: defaults.canonical_auth.clone(),
            bootstrap_auth: defaults.bootstrap_auth.clone().unwrap_or_default(),
            privilege: setting_value(&defaults.privilege, None),
            stats_script: setting_value(&defaults.stats_script, None),
            provision_profiles: defaults.provision_profiles.clone().unwrap_or_default(),
            vars: BTreeMap::new(),
            timeouts: effective_timeouts(&defaults.timeouts),
        }
    }

    fn apply(&mut self, layer: &MachineLayer) {
        replace_option(&mut self.address, &layer.address);
        if let Some(port) = layer.port {
            self.port = port;
        }
        if let Some(tags) = &layer.tags {
            self.tags = tags.clone();
        }
        if let Some(via) = &layer.via {
            self.via = via.clone();
        }
        replace_option(&mut self.canonical_auth, &layer.canonical_auth);
        if let Some(auth) = &layer.bootstrap_auth {
            self.bootstrap_auth = auth.clone();
        }
        apply_setting(&layer.privilege, &mut self.privilege);
        apply_setting(&layer.stats_script, &mut self.stats_script);
        if let Some(profiles) = &layer.provision_profiles {
            self.provision_profiles = profiles.clone();
        }
        self.vars.extend(layer.vars.clone());
        apply_timeout_layer(&mut self.timeouts, &layer.timeouts);
    }
}

fn overlay_defaults(base: &mut RemoteDefaults, overlay: &RemoteDefaults) {
    replace_option(&mut base.port, &overlay.port);
    replace_option(&mut base.canonical_auth, &overlay.canonical_auth);
    replace_option(&mut base.bootstrap_auth, &overlay.bootstrap_auth);
    if !matches!(overlay.privilege, Setting::Inherit) {
        base.privilege = overlay.privilege.clone();
    }
    replace_option(&mut base.interpreter, &overlay.interpreter);
    replace_option(&mut base.via, &overlay.via);
    replace_option(&mut base.known_hosts, &overlay.known_hosts);
    if !matches!(overlay.stats_script, Setting::Inherit) {
        base.stats_script = overlay.stats_script.clone();
    }
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

fn overlay_timeouts(base: &mut Timeouts, overlay: &Timeouts) {
    replace_option(&mut base.connect, &overlay.connect);
    replace_option(&mut base.command, &overlay.command);
    replace_option(&mut base.transfer, &overlay.transfer);
    replace_option(&mut base.reboot_disconnect, &overlay.reboot_disconnect);
    replace_option(&mut base.reboot_readiness, &overlay.reboot_readiness);
    replace_option(&mut base.reboot_poll, &overlay.reboot_poll);
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

fn effective_timeouts(configured: &Timeouts) -> EffectiveTimeouts {
    EffectiveTimeouts {
        connect: configured
            .connect
            .clone()
            .unwrap_or_else(|| DurationValue::builtin("20s", 20)),
        command: configured
            .command
            .clone()
            .unwrap_or_else(|| DurationValue::builtin("10m", 600)),
        transfer: configured
            .transfer
            .clone()
            .unwrap_or_else(|| DurationValue::builtin("20m", 1200)),
        reboot_disconnect: configured
            .reboot_disconnect
            .clone()
            .unwrap_or_else(|| DurationValue::builtin("2m", 120)),
        reboot_readiness: configured
            .reboot_readiness
            .clone()
            .unwrap_or_else(|| DurationValue::builtin("15m", 900)),
        reboot_poll: configured
            .reboot_poll
            .clone()
            .unwrap_or_else(|| DurationValue::builtin("5s", 5)),
    }
}

fn apply_timeout_layer(effective: &mut EffectiveTimeouts, layer: &Timeouts) {
    if let Some(value) = &layer.connect {
        effective.connect = value.clone();
    }
    if let Some(value) = &layer.command {
        effective.command = value.clone();
    }
    if let Some(value) = &layer.transfer {
        effective.transfer = value.clone();
    }
    if let Some(value) = &layer.reboot_disconnect {
        effective.reboot_disconnect = value.clone();
    }
    if let Some(value) = &layer.reboot_readiness {
        effective.reboot_readiness = value.clone();
    }
    if let Some(value) = &layer.reboot_poll {
        effective.reboot_poll = value.clone();
    }
}

fn effective_plan(
    state: &MachineState,
    definitions: &Definitions<'_>,
    env_vars: &BTreeMap<String, String>,
) -> Result<Option<EffectivePlan>, PlanValidationError> {
    let profiles = &state.provision_profiles;
    if profiles.is_empty() {
        return Ok(None);
    }
    let transition_owners: Vec<_> = profiles
        .iter()
        .filter(|name| {
            definitions.provision_profiles[name.as_str()]
                .ssh_transition
                .is_some()
        })
        .collect();
    if transition_owners.len() != 1 {
        return Err(PlanValidationError::TransitionOwnerCount {
            count: transition_owners.len(),
        });
    }
    if profiles.iter().all(|name| {
        definitions.provision_profiles[name.as_str()]
            .security_verify
            .is_empty()
    }) {
        return Err(PlanValidationError::MissingSecurityVerifier);
    }
    for profile_name in profiles {
        validate_profile_plan(
            profile_name,
            definitions.provision_profiles[profile_name.as_str()],
            state,
            definitions,
            env_vars,
        )?;
    }
    let mut steps = Vec::new();
    let mut runtime_steps = Vec::new();
    append_phase(
        &mut steps,
        &mut runtime_steps,
        profiles,
        definitions,
        state,
        "bootstrap",
        |profile| &profile.bootstrap,
    );
    append_phase(
        &mut steps,
        &mut runtime_steps,
        profiles,
        definitions,
        state,
        "secure",
        |profile| &profile.secure,
    );
    append_phase(
        &mut steps,
        &mut runtime_steps,
        profiles,
        definitions,
        state,
        "configure",
        |profile| &profile.configure,
    );
    let transition_owner = (*transition_owners[0]).clone();
    let transition = definitions.provision_profiles[transition_owner.as_str()]
        .ssh_transition
        .as_ref()
        .expect("plan validation requires a transition owner");
    let transition_actions = [
        ("prepare", &transition.prepare),
        ("apply", &transition.apply),
        ("validate", &transition.validate),
        ("reload", &transition.reload),
        ("rollback", &transition.rollback),
    ]
    .into_iter()
    .map(|(name, action)| effective_named_script(name, action, definitions, &state.timeouts))
    .collect();
    let runtime_transition_actions = [
        ("prepare", &transition.prepare),
        ("apply", &transition.apply),
        ("validate", &transition.validate),
        ("reload", &transition.reload),
        ("rollback", &transition.rollback),
    ]
    .into_iter()
    .map(|(name, action)| effective_runtime_named_script(name, action, definitions, state))
    .collect();
    let mut security_verifiers = Vec::new();
    let mut runtime_security_verifiers = Vec::new();
    for profile_name in profiles {
        for (index, action) in definitions.provision_profiles[profile_name.as_str()]
            .security_verify
            .iter()
            .enumerate()
        {
            security_verifiers.push(effective_named_script(
                &format!("{profile_name}.security.verify.{index}"),
                action,
                definitions,
                &state.timeouts,
            ));
            runtime_security_verifiers.push(effective_runtime_named_script(
                &format!("{profile_name}.security.verify.{index}"),
                action,
                definitions,
                state,
            ));
        }
    }
    Ok(Some(EffectivePlan {
        steps,
        transition_owner,
        transition_actions,
        security_verifiers,
        runtime_steps,
        runtime_transition_actions,
        runtime_security_verifiers,
    }))
}

fn validate_profile_plan(
    profile_name: &str,
    profile: &ProvisionProfile,
    state: &MachineState,
    definitions: &Definitions<'_>,
    env_vars: &BTreeMap<String, String>,
) -> Result<(), PlanValidationError> {
    for (phase, steps) in [
        ("bootstrap", &profile.bootstrap),
        ("secure", &profile.secure),
        ("configure", &profile.configure),
    ] {
        for step in steps {
            let step_id = format!("{profile_name}.{phase}.{}", step.name);
            if let Some(action) = &step.check {
                validate_script_bindings(
                    &format!("{step_id}.check"),
                    action,
                    state,
                    definitions,
                    env_vars,
                )?;
            }
            match &step.run {
                ProvisionAction::Reboot(_) | ProvisionAction::Local(_) if phase != "configure" => {
                    return Err(PlanValidationError::ActionBeforeConfigure {
                        action: format!("{step_id}.run.{}", step.run.kind()),
                    });
                }
                ProvisionAction::Script(action) => validate_script_bindings(
                    &format!("{step_id}.run"),
                    action,
                    state,
                    definitions,
                    env_vars,
                )?,
                ProvisionAction::Reboot(
                    action @ RebootAction {
                        when: Some(when), ..
                    },
                ) => {
                    validate_script_bindings(
                        &format!("{step_id}.run.reboot.when"),
                        when,
                        state,
                        definitions,
                        env_vars,
                    )?;
                    validate_reboot_privilege(
                        &format!("{step_id}.run.reboot"),
                        action,
                        state,
                        definitions,
                    )?;
                }
                ProvisionAction::Reboot(action) => validate_reboot_privilege(
                    &format!("{step_id}.run.reboot"),
                    action,
                    state,
                    definitions,
                )?,
                ProvisionAction::CopyTo(action)
                    if action.owner.is_some()
                        && action.privilege.is_none()
                        && state.privilege.is_none()
                        && !authenticated_accounts_are_root(definitions, state, phase) =>
                {
                    return Err(PlanValidationError::UploadOwnerRequiresRoot {
                        action: format!("{step_id}.run.copy_to"),
                    });
                }
                ProvisionAction::CopyTo(action) => validate_effective_privilege(
                    &format!("{step_id}.run.copy_to"),
                    action.privilege.as_ref().or(state.privilege.as_ref()),
                    definitions,
                )?,
                _ => {}
            }
            if let Some(action) = &step.verify {
                validate_script_bindings(
                    &format!("{step_id}.verify"),
                    action,
                    state,
                    definitions,
                    env_vars,
                )?;
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
            validate_script_bindings(
                &format!("{profile_name}.ssh_transition.{name}"),
                action,
                state,
                definitions,
                env_vars,
            )?;
        }
    }
    for (index, action) in profile.security_verify.iter().enumerate() {
        let action_name = format!("{profile_name}.security.verify.{index}");
        validate_script_bindings(&action_name, action, state, definitions, env_vars)?;
        let script = definitions.scripts[action.script.as_str()];
        let privileged = action
            .privilege
            .as_ref()
            .or(script.privilege.as_ref())
            .or(state.privilege.as_ref())
            .is_some()
            || definitions.auth_profiles[state
                .canonical_auth
                .as_deref()
                .expect("config validation requires canonical auth")]
            .user
                == "root";
        if !privileged {
            return Err(PlanValidationError::UnprivilegedSecurityVerifier {
                action: action_name,
            });
        }
    }
    Ok(())
}

fn validate_script_bindings(
    action_name: &str,
    action: &ScriptAction,
    state: &MachineState,
    definitions: &Definitions<'_>,
    env_vars: &BTreeMap<String, String>,
) -> Result<(), PlanValidationError> {
    let script = definitions.scripts[action.script.as_str()];
    let privilege = action
        .privilege
        .as_ref()
        .or(script.privilege.as_ref())
        .or(state.privilege.as_ref());
    validate_effective_privilege(action_name, privilege, definitions)?;
    if let Some(provider) = stdin_secret_provider(action) {
        if !definitions.secret_providers.contains_key(provider) {
            return Err(PlanValidationError::MissingSecretStdinProvider {
                action: action_name.to_string(),
                provider: provider.to_string(),
            });
        }
        if privilege
            .and_then(|name| definitions.privilege_profiles.get(name.as_str()))
            .is_some_and(|profile| profile.password.is_some())
        {
            return Err(PlanValidationError::PasswordSudoWithSecretStdin {
                action: action_name.to_string(),
            });
        }
    }
    for source in script.env.values() {
        let (binding, available) = match source {
            RemoteEnvValue::Value(_) => continue,
            RemoteEnvValue::FromEnv(name) => (name, env_vars.contains_key(name)),
            RemoteEnvValue::FromMachine(name) => (name, state.vars.contains_key(name)),
        };
        if !available {
            return Err(PlanValidationError::MissingScriptBinding {
                action: action_name.to_string(),
                binding: binding.clone(),
            });
        }
    }
    Ok(())
}

fn validate_effective_privilege(
    action_name: &str,
    privilege: Option<&String>,
    definitions: &Definitions<'_>,
) -> Result<(), PlanValidationError> {
    let Some(privilege) = privilege else {
        return Ok(());
    };
    if definitions
        .privilege_profiles
        .contains_key(privilege.as_str())
    {
        Ok(())
    } else {
        Err(PlanValidationError::MissingActionPrivilege {
            action: action_name.to_string(),
            privilege: privilege.clone(),
        })
    }
}

fn validate_reboot_privilege(
    action_name: &str,
    action: &RebootAction,
    state: &MachineState,
    definitions: &Definitions<'_>,
) -> Result<(), PlanValidationError> {
    let privilege = action.privilege.as_ref().or(state.privilege.as_ref());
    validate_effective_privilege(action_name, privilege, definitions)?;
    if privilege.is_none() && !canonical_account_is_root(definitions, state) {
        return Err(PlanValidationError::UnprivilegedReboot {
            action: action_name.to_string(),
        });
    }
    Ok(())
}

fn stdin_secret_provider(action: &ScriptAction) -> Option<&str> {
    match action.stdin.as_ref()? {
        ProvisionScriptStdin::Secret(secret) => Some(secret.secret.as_str()),
    }
}

fn canonical_account_is_root(definitions: &Definitions<'_>, state: &MachineState) -> bool {
    let canonical = state
        .canonical_auth
        .as_deref()
        .expect("config validation requires canonical auth");
    definitions.auth_profiles[canonical].user == "root"
}

fn authenticated_accounts_are_root(
    definitions: &Definitions<'_>,
    state: &MachineState,
    phase: &str,
) -> bool {
    let canonical = state
        .canonical_auth
        .as_deref()
        .expect("config validation requires canonical auth");
    definitions.auth_profiles[canonical].user == "root"
        && (phase == "configure"
            || state
                .bootstrap_auth
                .iter()
                .all(|name| definitions.auth_profiles[name.as_str()].user == "root"))
}

fn append_phase<'config>(
    output: &mut Vec<EffectivePlanStep>,
    runtime_output: &mut Vec<provision::ProvisionStep>,
    profiles: &[String],
    definitions: &Definitions<'config>,
    state: &MachineState,
    phase: &str,
    steps: fn(&ProvisionProfile) -> &[ProvisionStep],
) {
    for profile_name in profiles {
        let profile = definitions.provision_profiles[profile_name.as_str()];
        for step in steps(profile) {
            let id = format!("{profile_name}.{phase}.{}", step.name);
            output.push(EffectivePlanStep {
                id: id.clone(),
                phase: phase.to_string(),
                check: step
                    .check
                    .as_ref()
                    .map(|action| effective_script(action, definitions, &state.timeouts)),
                run: effective_action(&step.run, definitions, &state.timeouts),
                verify: step
                    .verify
                    .as_ref()
                    .map(|action| effective_script(action, definitions, &state.timeouts)),
            });
            runtime_output.push(provision::ProvisionStep {
                id,
                phase: phase.to_string(),
                check: step
                    .check
                    .as_ref()
                    .map(|action| effective_runtime_script(action, definitions, state)),
                run: effective_runtime_action(&step.run, definitions, state),
                verify: step
                    .verify
                    .as_ref()
                    .map(|action| effective_runtime_script(action, definitions, state)),
            });
        }
    }
}

fn effective_named_script(
    name: &str,
    action: &ScriptAction,
    definitions: &Definitions<'_>,
    timeouts: &EffectiveTimeouts,
) -> EffectiveNamedScriptAction {
    let action = effective_script(action, definitions, timeouts);
    EffectiveNamedScriptAction {
        name: name.to_string(),
        script: action
            .script
            .expect("effective script actions always include their script name"),
        stdin_secret: action.stdin_secret,
        timeout: action.timeout,
    }
}

fn effective_script(
    action: &ScriptAction,
    definitions: &Definitions<'_>,
    timeouts: &EffectiveTimeouts,
) -> EffectiveTimedAction {
    let timeout = action
        .timeout
        .clone()
        .or_else(|| definitions.scripts[action.script.as_str()].timeout.clone())
        .unwrap_or_else(|| timeouts.command.clone());
    EffectiveTimedAction {
        kind: "script".to_string(),
        script: Some(action.script.clone()),
        stdin_secret: action.stdin.is_some(),
        timeout,
    }
}

fn effective_runtime_named_script(
    name: &str,
    action: &ScriptAction,
    definitions: &Definitions<'_>,
    state: &MachineState,
) -> provision::NamedScriptAction {
    provision::NamedScriptAction {
        name: name.to_string(),
        action: effective_runtime_script(action, definitions, state),
    }
}

fn effective_runtime_script(
    action: &ScriptAction,
    definitions: &Definitions<'_>,
    state: &MachineState,
) -> provision::ScriptAction {
    let script = definitions.scripts[action.script.as_str()];
    let timeout = action
        .timeout
        .clone()
        .or_else(|| script.timeout.clone())
        .unwrap_or_else(|| state.timeouts.command.clone());
    provision::ScriptAction {
        script: action.script.clone(),
        privilege: action
            .privilege
            .clone()
            .or_else(|| script.privilege.clone())
            .or_else(|| state.privilege.clone()),
        stdin: action.stdin.as_ref().map(|stdin| match stdin {
            ProvisionScriptStdin::Secret(secret) => provision::ScriptStdin::Secret {
                provider: secret.secret.clone(),
            },
        }),
        timeout,
    }
}

fn effective_runtime_action(
    action: &ProvisionAction,
    definitions: &Definitions<'_>,
    state: &MachineState,
) -> provision::ProvisionAction {
    match action {
        ProvisionAction::Script(action) => {
            provision::ProvisionAction::Script(effective_runtime_script(action, definitions, state))
        }
        ProvisionAction::CopyTo(action) => {
            provision::ProvisionAction::CopyTo(provision::CopyToAction {
                source: action.source.clone(),
                destination: action.destination.clone(),
                recursive: action.recursive,
                overwrite: action.overwrite,
                mode: action.mode.clone(),
                owner: action.owner.clone(),
                privilege: action.privilege.clone().or_else(|| state.privilege.clone()),
                timeout: action
                    .timeout
                    .clone()
                    .unwrap_or_else(|| state.timeouts.transfer.clone()),
            })
        }
        ProvisionAction::CopyFrom(action) => {
            provision::ProvisionAction::CopyFrom(provision::CopyFromAction {
                source: action.source.clone(),
                destination: action.destination.clone(),
                recursive: action.recursive,
                overwrite: action.overwrite,
                mode: action.mode.clone(),
                timeout: action
                    .timeout
                    .clone()
                    .unwrap_or_else(|| state.timeouts.transfer.clone()),
            })
        }
        ProvisionAction::Reboot(action) => {
            provision::ProvisionAction::Reboot(provision::RebootAction {
                when: action
                    .when
                    .as_ref()
                    .map(|when| effective_runtime_script(when, definitions, state)),
                privilege: action.privilege.clone().or_else(|| state.privilege.clone()),
                disconnect_timeout: action
                    .disconnect_timeout
                    .clone()
                    .unwrap_or_else(|| state.timeouts.reboot_disconnect.clone()),
                readiness_timeout: action
                    .readiness_timeout
                    .clone()
                    .unwrap_or_else(|| state.timeouts.reboot_readiness.clone()),
                poll_interval: action
                    .poll_interval
                    .clone()
                    .unwrap_or_else(|| state.timeouts.reboot_poll.clone()),
            })
        }
        ProvisionAction::Local(action) => {
            provision::ProvisionAction::Local(provision::LocalAction {
                command: action.command.clone(),
                timeout: action
                    .timeout
                    .clone()
                    .unwrap_or_else(|| state.timeouts.command.clone()),
            })
        }
    }
}

fn effective_action(
    action: &ProvisionAction,
    definitions: &Definitions<'_>,
    timeouts: &EffectiveTimeouts,
) -> EffectivePlanAction {
    match action {
        ProvisionAction::Script(action) => {
            EffectivePlanAction::Timed(effective_script(action, definitions, timeouts))
        }
        ProvisionAction::CopyTo(action) => EffectivePlanAction::Timed(EffectiveTimedAction {
            kind: "copy_to".to_string(),
            script: None,
            stdin_secret: false,
            timeout: action
                .timeout
                .clone()
                .unwrap_or_else(|| timeouts.transfer.clone()),
        }),
        ProvisionAction::CopyFrom(action) => EffectivePlanAction::Timed(EffectiveTimedAction {
            kind: "copy_from".to_string(),
            script: None,
            stdin_secret: false,
            timeout: action
                .timeout
                .clone()
                .unwrap_or_else(|| timeouts.transfer.clone()),
        }),
        ProvisionAction::Local(action) => EffectivePlanAction::Timed(EffectiveTimedAction {
            kind: "local".to_string(),
            script: None,
            stdin_secret: false,
            timeout: action
                .timeout
                .clone()
                .unwrap_or_else(|| timeouts.command.clone()),
        }),
        ProvisionAction::Reboot(action) => EffectivePlanAction::Reboot(EffectiveRebootAction {
            when: action
                .when
                .as_ref()
                .map(|when| effective_script(when, definitions, timeouts)),
            disconnect_timeout: action
                .disconnect_timeout
                .clone()
                .unwrap_or_else(|| timeouts.reboot_disconnect.clone()),
            readiness_timeout: action
                .readiness_timeout
                .clone()
                .unwrap_or_else(|| timeouts.reboot_readiness.clone()),
            poll_interval: action
                .poll_interval
                .clone()
                .unwrap_or_else(|| timeouts.reboot_poll.clone()),
        }),
    }
}
