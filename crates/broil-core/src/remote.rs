// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Setting<T> {
    #[default]
    Inherit,
    Value(T),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurationValue {
    pub source: String,
    pub seconds: u64,
}

impl DurationValue {
    pub fn builtin(source: &str, seconds: u64) -> Self {
        Self {
            source: source.to_string(),
            seconds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parallelism {
    Limit(usize),
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Timeouts {
    pub connect: Option<DurationValue>,
    pub command: Option<DurationValue>,
    pub transfer: Option<DurationValue>,
    pub reboot_disconnect: Option<DurationValue>,
    pub reboot_readiness: Option<DurationValue>,
    pub reboot_poll: Option<DurationValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParallelismDefaults {
    pub operations: Option<Parallelism>,
    pub provision: Option<Parallelism>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteDefaults {
    pub port: Option<u16>,
    pub canonical_auth: Option<String>,
    pub bootstrap_auth: Option<Vec<String>>,
    pub privilege: Setting<String>,
    pub interpreter: Option<Vec<String>>,
    pub via: Option<String>,
    pub known_hosts: Option<String>,
    pub stats_script: Setting<String>,
    pub provision_profiles: Option<Vec<String>>,
    pub parallelism: ParallelismDefaults,
    pub timeouts: Timeouts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretProvider {
    Prompt { label: String },
    File { path: String },
    Helper { command: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSelector {
    Fingerprint(String),
    PublicKeyPath(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyIdentity {
    Agent {
        selector: AgentSelector,
    },
    File {
        path: String,
        passphrase: Option<SecretRef>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    PublicKey { identities: Vec<PublicKeyIdentity> },
    Password(SecretRef),
    KeyboardInteractive(SecretRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProfile {
    pub user: String,
    pub method: AuthMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrivilegeProfile {
    pub password: Option<SecretRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpHost {
    pub address: String,
    pub port: u16,
    pub auth: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PtyMode {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEnvValue {
    Value(String),
    FromEnv(String),
    FromMachine(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteScript {
    pub body: String,
    pub interpreter: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub privilege: Option<String>,
    pub pty: PtyMode,
    pub timeout: Option<DurationValue>,
    pub env: BTreeMap<String, RemoteEnvValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MachineLayer {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub tags: Option<Vec<String>>,
    pub via: Option<String>,
    pub canonical_auth: Option<String>,
    pub bootstrap_auth: Option<Vec<String>>,
    pub privilege: Setting<String>,
    pub stats_script: Setting<String>,
    pub provision_profiles: Option<Vec<String>>,
    pub vars: BTreeMap<String, String>,
    pub timeouts: Timeouts,
}

pub type MachineTemplate = MachineLayer;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MachineConfig {
    pub template: Option<String>,
    pub settings: MachineLayer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptAction {
    pub script: String,
    pub privilege: Option<String>,
    pub stdin: Option<ProvisionScriptStdin>,
    pub timeout: Option<DurationValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionScriptStdin {
    Secret(SecretRef),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyToAction {
    pub source: String,
    pub destination: String,
    pub recursive: bool,
    pub overwrite: bool,
    pub mode: Option<String>,
    pub owner: Option<String>,
    pub privilege: Option<String>,
    pub timeout: Option<DurationValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyFromAction {
    pub source: String,
    pub destination: String,
    pub recursive: bool,
    pub overwrite: bool,
    pub mode: Option<String>,
    pub timeout: Option<DurationValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RebootAction {
    pub when: Option<ScriptAction>,
    pub privilege: Option<String>,
    pub disconnect_timeout: Option<DurationValue>,
    pub readiness_timeout: Option<DurationValue>,
    pub poll_interval: Option<DurationValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAction {
    pub command: Vec<String>,
    pub timeout: Option<DurationValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionAction {
    Script(ScriptAction),
    CopyTo(CopyToAction),
    CopyFrom(CopyFromAction),
    Reboot(RebootAction),
    Local(LocalAction),
}

impl ProvisionAction {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Script(_) => "script",
            Self::CopyTo(_) => "copy_to",
            Self::CopyFrom(_) => "copy_from",
            Self::Reboot(_) => "reboot",
            Self::Local(_) => "local",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionStep {
    pub name: String,
    pub check: Option<ScriptAction>,
    pub run: ProvisionAction,
    pub verify: Option<ScriptAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTransition {
    pub prepare: ScriptAction,
    pub apply: ScriptAction,
    pub validate: ScriptAction,
    pub reload: ScriptAction,
    pub rollback: ScriptAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProvisionProfile {
    pub bootstrap: Vec<ProvisionStep>,
    pub secure: Vec<ProvisionStep>,
    pub configure: Vec<ProvisionStep>,
    pub ssh_transition: Option<SshTransition>,
    pub security_verify: Vec<ScriptAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteDefinitions {
    pub defaults: RemoteDefaults,
    pub secret_providers: BTreeMap<String, SecretProvider>,
    pub auth_profiles: BTreeMap<String, AuthProfile>,
    pub privilege_profiles: BTreeMap<String, PrivilegeProfile>,
    pub jump_hosts: BTreeMap<String, JumpHost>,
    pub jump_order: Vec<String>,
    pub scripts: BTreeMap<String, RemoteScript>,
    pub provision_profiles: BTreeMap<String, ProvisionProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RemoteConfig {
    pub definitions: RemoteDefinitions,
    pub machine_templates: BTreeMap<String, MachineTemplate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvironmentRemoteConfig {
    pub definitions: RemoteDefinitions,
    pub machines: BTreeMap<String, MachineConfig>,
    pub machine_order: Vec<String>,
}
