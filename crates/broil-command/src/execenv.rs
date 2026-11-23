// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;

use broil_core::error::ExecutionError;
use broil_core::model::BroilConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedExecution {
    pub env_name: Option<String>,
    pub scripts: BTreeMap<String, String>,
    pub env_vars: BTreeMap<String, String>,
}

pub fn select_execution_env(
    explicit_file: bool,
    ambient_broil_env: Option<&OsStr>,
) -> Option<&OsStr> {
    if explicit_file {
        return None;
    }
    ambient_broil_env.filter(|value| !value.is_empty())
}

pub fn resolve(
    config: &BroilConfig,
    active: Option<&OsStr>,
) -> Result<ResolvedExecution, ExecutionError> {
    let mut resolved = ResolvedExecution {
        env_name: None,
        scripts: config.scripts.clone(),
        env_vars: config.env_vars.clone(),
    };
    let Some(name) = active else {
        return Ok(resolved);
    };
    let Some(environment) = name.to_str().and_then(|utf8| config.environments.get(utf8)) else {
        return Err(ExecutionError::UnknownEnvironment {
            name: name.to_string_lossy().into_owned(),
        });
    };
    resolved.env_name = name.to_str().map(str::to_string);
    resolved.scripts.extend(environment.scripts.clone());
    resolved.env_vars.extend(environment.env_vars.clone());
    Ok(resolved)
}

fn is_reserved(name: &OsStr) -> bool {
    name == "BROIL_ROOT" || name == "BROIL_ENV"
}

pub fn child_env(
    base: &[(OsString, OsString)],
    resolved: &ResolvedExecution,
    broil_root: &Path,
) -> BTreeMap<OsString, OsString> {
    let mut env: BTreeMap<OsString, OsString> = base
        .iter()
        .filter(|(name, _)| {
            !is_reserved(name) && !broil_core::secret::environment::is_credential_input(name)
        })
        .cloned()
        .collect();
    for (name, value) in &resolved.env_vars {
        env.insert(OsString::from(name), OsString::from(value));
    }
    env.insert(
        OsString::from("BROIL_ROOT"),
        broil_root.as_os_str().to_os_string(),
    );
    if let Some(name) = &resolved.env_name {
        env.insert(OsString::from("BROIL_ENV"), OsString::from(name));
    }
    env
}

pub fn status_code(status: ExitStatus) -> Result<i32, ExecutionError> {
    if let Some(code) = status.code() {
        return Ok(code);
    }
    if let Some(signal) = status.signal() {
        return Ok(128 + signal);
    }
    Err(ExecutionError::Spawn {
        message: "child status is neither an exit code nor a signal".to_string(),
    })
}
