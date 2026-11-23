// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Tool, common::*};
use broil_core::images::{
    reference::{Endpoint, ImageReference},
    valid_name, valid_platform,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub operation_id: String,
    pub root: PathBuf,
    pub environment: Option<String>,
    pub root_env: BTreeMap<String, String>,
    pub selected_env: BTreeMap<String, String>,
    pub parent: Entry,
    pub helper: Entry,
    pub tools: BTreeMap<Tool, Entry>,
    pub limits: Limits,
}

#[derive(Clone, Debug)]
pub struct Preflight(pub(crate) Policy);

fn replaced(key: &str) -> bool {
    matches!(
        key,
        "BROIL_ROOT"
            | "BROIL_ENV"
            | "HOME"
            | "DOCKER_CONFIG"
            | "BUILDX_CONFIG"
            | "XDG_CONFIG_HOME"
            | "XDG_CACHE_HOME"
            | "XDG_DATA_HOME"
            | "XDG_STATE_HOME"
            | "XDG_RUNTIME_DIR"
            | "TMPDIR"
            | "PATH"
            | "LC_ALL"
            | "LANG"
    )
}

fn credential(key: &str) -> bool {
    matches!(
        key,
        "SOPS_AGE_KEY"
            | "SOPS_AGE_KEY_FILE"
            | "BROIL_SECRETS_IDENTITY"
            | "BROIL_SECRETS_PASSPHRASE"
            | "BAO_TOKEN"
    )
}

fn conflict(key: &str) -> bool {
    [
        "DOCKER_",
        "BUILDX_",
        "BUILDKIT_",
        "BUILDKITD_",
        "XDG_",
        "LD_",
        "DYLD_",
        "SSL_",
        "OTEL_",
    ]
    .iter()
    .any(|p| key.starts_with(p))
        || key.ends_with("_PROXY")
        || matches!(
            key,
            "SSLKEYLOGFILE"
                | "GODEBUG"
                | "GOGC"
                | "GOMEMLIMIT"
                | "GOENV"
                | "GOTOOLCHAIN"
                | "SSH_AUTH_SOCK"
                | "SSH_AGENT_PID"
                | "TRACEPARENT"
                | "TRACESTATE"
        )
}

pub(crate) fn bounded_text(value: &str, maximum: usize) -> Result<()> {
    require(
        value.len() <= maximum && !value.contains('\0'),
        Failure::Policy,
    )
}

pub(crate) fn entry_policy(entry: &Entry) -> Result<()> {
    require(valid_path(&entry.path), Failure::Policy)
}

pub fn preflight(policy: Policy) -> Result<Preflight> {
    policy.validate()?;
    Ok(Preflight(policy))
}

pub(crate) fn helper_identity() -> Result<(String, u64)> {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../tools/image-client/compatibility.json"
    ))
    .map_err(|_| Failure::Policy)?;
    let helper = &manifest["filesystem_helper"];
    require(
        helper["protocol_version"] == 3
            && helper["target"] == "x86_64-unknown-linux-gnu"
            && helper["build_script"] == "tools/image-client/build-worker.sh"
            && helper["compiler"]
                .as_array()
                .is_some_and(|items| items.iter().any(|value| value == "release: 1.92.0"))
            && helper["source_inputs"].as_object().is_some_and(|inputs| {
                [
                    "Cargo.lock",
                    "Cargo.toml",
                    "crates/broil-command/Cargo.toml",
                    "crates/broil-core/Cargo.toml",
                    "crates/broil-command/src/image_client_worker.rs",
                    "tools/image-client/public-tools.json",
                    "tools/image-client/build-worker.sh",
                ]
                .iter()
                .all(|path| inputs.contains_key(*path))
                    && inputs.iter().all(|(path, value)| {
                        !path.contains("/tests/")
                            && value
                                .as_str()
                                .is_some_and(|value| value.len() == 64 && hex(value.as_bytes()))
                    })
            })
            && ["normal_closure_sha256", "legal_notice_sha256"]
                .iter()
                .all(|key| {
                    helper[*key]
                        .as_str()
                        .is_some_and(|value| value.len() == 64 && hex(value.as_bytes()))
                })
            && helper["capabilities"].as_array().is_some_and(|items| {
                ["prepare-slot", "verify-produced"]
                    .iter()
                    .all(|action| items.contains(&json!(action)))
            }),
        Failure::Policy,
    )?;
    let hash = helper["sha256"].as_str().ok_or(Failure::Policy)?;
    require(hash.len() == 64 && hex(hash.as_bytes()), Failure::Policy)?;
    Ok((
        format!("sha256:{hash}"),
        helper["size"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or(Failure::Policy)?,
    ))
}

impl Policy {
    pub(crate) fn workspace_path(&self) -> PathBuf {
        self.parent.path.join(&self.operation_id)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        helper_identity()?;
        require(
            cfg!(all(target_os = "linux", target_arch = "x86_64"))
                && valid_operation(&self.operation_id)
                && valid_path(&self.root),
            Failure::Policy,
        )?;
        if let Some(env) = &self.environment {
            require(valid_name(env), Failure::Policy)?;
        }
        require(
            self.environment.is_some() || self.selected_env.is_empty(),
            Failure::Policy,
        )?;
        for entry in [&self.parent, &self.helper]
            .into_iter()
            .chain(self.tools.values())
        {
            entry_policy(entry)?;
            require(entry.ownership != Ownership::Operation, Failure::Policy)?;
        }
        require(
            self.parent.kind == Kind::Directory
                && self.parent.ownership == Ownership::Borrowed
                && self.helper.kind == Kind::File
                && self.tools.values().all(|e| e.kind == Kind::File),
            Failure::Policy,
        )?;
        require(valid_path(&self.workspace_path()), Failure::Policy)?;
        self.child_environment()?;
        Ok(())
    }

    pub(crate) fn child_environment(&self) -> Result<BTreeMap<String, String>> {
        require(
            self.root_env.len() <= 4096 && self.selected_env.len() <= 4096,
            Failure::Limit,
        )?;
        let source_bytes = self.root_env.iter().chain(&self.selected_env).try_fold(
            0usize,
            |n, (key, value)| {
                n.checked_add(key.len())
                    .and_then(|n| n.checked_add(value.len()))
                    .ok_or(Failure::Limit)
            },
        )?;
        require(source_bytes <= 131_072, Failure::Limit)?;
        let mut input = self.root_env.clone();
        input.extend(self.selected_env.clone());
        let mut bytes = 0usize;
        require(input.len() <= 4096, Failure::Limit)?;
        let mut env = BTreeMap::new();
        for (key, value) in input {
            require(
                !key.is_empty() && !key.contains(['=', '\0']) && key.is_ascii(),
                Failure::Policy,
            )?;
            bounded_text(&value, 65_536)?;
            bytes = bytes
                .checked_add(key.len())
                .and_then(|n| n.checked_add(value.len()))
                .ok_or(Failure::Limit)?;
            require(bytes <= 65_536, Failure::Limit)?;
            let upper = key.to_ascii_uppercase();
            if credential(&upper) || replaced(&upper) {
                continue;
            }
            require(!conflict(&upper), Failure::Policy)?;
            env.insert(key, value);
        }
        let workspace = self.workspace_path();
        for (key, path) in [
            ("HOME", "home"),
            ("DOCKER_CONFIG", "docker"),
            ("BUILDX_CONFIG", "buildx"),
            ("XDG_CONFIG_HOME", "xdg/config"),
            ("XDG_CACHE_HOME", "xdg/cache"),
            ("XDG_DATA_HOME", "xdg/data"),
            ("XDG_STATE_HOME", "xdg/state"),
            ("XDG_RUNTIME_DIR", "xdg/runtime"),
            ("TMPDIR", "tmp"),
            ("PATH", "tools"),
        ] {
            env.insert(
                key.into(),
                workspace.join(path).to_str().ok_or(Failure::Policy)?.into(),
            );
        }
        env.insert(
            "BROIL_ROOT".into(),
            self.root.to_str().ok_or(Failure::Policy)?.into(),
        );
        if let Some(name) = &self.environment {
            env.insert("BROIL_ENV".into(), name.clone());
        }
        env.insert("LANG".into(), "C".into());
        env.insert("LC_ALL".into(), "C".into());
        Ok(env)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuilderPolicy {
    pub endpoint: String,
    pub server_name: String,
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub platforms: Vec<String>,
    pub entitlements: Vec<String>,
}

impl BuilderPolicy {
    pub fn validate(&self) -> Result<()> {
        require(
            Endpoint::builder(&self.endpoint).is_some()
                && !self.server_name.is_empty()
                && self.server_name.len() <= 253
                && self
                    .server_name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-:".contains(&c)),
            Failure::Policy,
        )?;
        for path in [&self.ca, &self.certificate, &self.key] {
            require(
                valid_path(path) && !path.as_os_str().as_encoded_bytes().contains(&b','),
                Failure::Policy,
            )?;
        }
        require(
            !self.platforms.is_empty()
                && self.platforms.len() <= 64
                && self.platforms.iter().all(|p| valid_platform(p))
                && self.entitlements.len() <= 2
                && self
                    .entitlements
                    .iter()
                    .all(|e| matches!(e.as_str(), "network.host" | "security.insecure")),
            Failure::Policy,
        )
    }

    pub(crate) fn driver_options(&self) -> String {
        format!(
            "servername={},cacert={},cert={},key={}",
            self.server_name,
            self.ca.display(),
            self.certificate.display(),
            self.key.display()
        )
    }

    pub(crate) fn worker_args(&self) -> Vec<String> {
        vec![
            "--addr".into(),
            self.endpoint.clone(),
            "--tlsservername".into(),
            self.server_name.clone(),
            "--tlscacert".into(),
            self.ca.display().to_string(),
            "--tlscert".into(),
            self.certificate.display().to_string(),
            "--tlskey".into(),
            self.key.display().to_string(),
            "debug".into(),
            "workers".into(),
            "--format".into(),
            "{{json .}}".into(),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryAuth {
    Anonymous,
    Bearer,
    Password {
        username: String,
        token_service: Option<(String, String)>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryAction {
    Inspect,
    Fetch,
    Upload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistryRequest {
    pub endpoint: String,
    pub development_http: bool,
    pub ca: Option<PathBuf>,
    pub reference: String,
    pub action: RegistryAction,
    pub cache: bool,
    pub optional: bool,
    pub auth: RegistryAuth,
    pub expected_root: Option<Descriptor>,
    pub input: Option<Entry>,
    pub inspect_input: bool,
    pub limits: BTreeMap<String, u64>,
}

pub(crate) const REGISTRY_LIMITS: &[(&str, u64)] = &[
    ("header_bytes", 65_536),
    ("result_bytes", 65_536),
    ("http_header_bytes", 65_536),
    ("stderr_bytes", 65_536),
    ("credential_bytes", 1_048_576),
    ("token_response_bytes", 1_048_576),
    ("metadata_bytes", 16_777_216),
    ("blob_bytes", 1_073_741_824),
    ("content_bytes", 4_294_967_296),
    ("staging_bytes", 5_368_709_120),
    ("network_bytes", 17_179_869_184),
    ("descriptors", 4096),
    ("descriptor_edges", 8192),
    ("graph_depth", 32),
    ("requests", 16_384),
    ("redirects", 3),
    ("token_exchanges", 2),
    ("operation_ms", 1_800_000),
    ("frame_ms", 10_000),
    ("connect_ms", 20_000),
    ("request_ms", 300_000),
    ("idle_ms", 30_000),
    ("cleanup_ms", 5000),
];

impl RegistryRequest {
    pub fn validate(&self) -> Result<()> {
        let endpoint =
            Endpoint::registry(&self.endpoint, self.development_http).ok_or(Failure::Policy)?;
        let reference = ImageReference::parse(&self.reference).ok_or(Failure::Policy)?;
        require(endpoint.matches_repository(&reference), Failure::Policy)?;
        if let Some(path) = &self.ca {
            require(valid_path(path), Failure::Policy)?;
        }
        if let Some(root) = &self.expected_root {
            root.validate()?;
            require(
                super::content::root_media(&root.media_type)
                    && reference.digest.as_ref().is_none_or(|d| d == &root.digest),
                Failure::Policy,
            )?;
        }
        let upload = self.action == RegistryAction::Upload;
        require(
            self.input.is_some() == upload
                && (!self.inspect_input || upload)
                && (!upload || self.expected_root.is_some())
                && (!self.cache || self.action != RegistryAction::Inspect)
                && (!self.optional || self.cache && self.action == RegistryAction::Fetch),
            Failure::Policy,
        )?;
        if let Some(input) = &self.input {
            entry_policy(input)?;
            require(
                input.kind == Kind::Directory && input.ownership != Ownership::Operation,
                Failure::Policy,
            )?;
        }
        if let RegistryAuth::Password {
            username,
            token_service,
        } = &self.auth
        {
            require(
                !username.is_empty()
                    && username.len() <= 4096
                    && !username.chars().any(|c| c == ':' || c.is_control()),
                Failure::Policy,
            )?;
            if let Some((realm, service)) = token_service {
                require(
                    Endpoint::token_realm(realm, &endpoint).is_some()
                        && !service.is_empty()
                        && service.len() <= 255
                        && service.bytes().all(|c| (33..=126).contains(&c)),
                    Failure::Policy,
                )?;
            }
        }
        for (key, value) in &self.limits {
            require(
                REGISTRY_LIMITS
                    .iter()
                    .any(|(name, max)| name == key && *value > 0 && value <= max),
                Failure::Limit,
            )?;
        }
        Ok(())
    }

    pub(crate) fn limit(&self, name: &str) -> u64 {
        self.limits.get(name).copied().unwrap_or_else(|| {
            REGISTRY_LIMITS
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| *value)
                .unwrap_or(0)
        })
    }

    pub(crate) fn action_name(&self) -> &'static str {
        match self.action {
            RegistryAction::Inspect => "inspect",
            RegistryAction::Fetch => "fetch",
            RegistryAction::Upload => "upload",
        }
    }

    pub(crate) fn header(
        &self,
        operation: &str,
        output: &Path,
        allowance: u64,
        remaining_ms: u64,
    ) -> Result<Value> {
        self.validate()?;
        require(allowance > 0 && remaining_ms > 0, Failure::Limit)?;
        let mut limits = self.limits.clone();
        limits.insert(
            "staging_bytes".into(),
            self.limit("staging_bytes").min(allowance),
        );
        limits.insert(
            "operation_ms".into(),
            self.limit("operation_ms").min(remaining_ms),
        );
        let auth = match &self.auth {
            RegistryAuth::Anonymous => json!({"kind":"none"}),
            RegistryAuth::Bearer => json!({"kind":"bearer"}),
            RegistryAuth::Password {
                username,
                token_service,
            } => json!({"kind":"password", "username":username,
                "token_service":token_service.as_ref().map(|(realm,service)| json!({"realm":realm,"service":service}))}),
        };
        let purpose = match (&self.action, self.cache) {
            (RegistryAction::Inspect, _) => "metadata",
            (RegistryAction::Fetch, false) => "pull",
            (RegistryAction::Fetch, true) => "cache_read",
            (RegistryAction::Upload, false) => "push",
            (RegistryAction::Upload, true) => "cache_write",
        };
        Ok(
            json!({"protocol_version":1,"operation_id":operation,"endpoint":self.endpoint,
            "development_http":self.development_http,"ca":self.ca,
            "repository":ImageReference::parse(&self.reference).ok_or(Failure::Policy)?.repository,
            "reference":self.reference,"expected_root":self.expected_root.as_ref().map(Descriptor::wire),
            "purpose":purpose,"action":self.action_name(),"content_kind":if self.cache {"cache"} else {"image"},
            "auth":auth,"staging_dir":output,"input_dir":self.input.as_ref().map(|e| &e.path),"limits":limits}),
        )
    }
}
