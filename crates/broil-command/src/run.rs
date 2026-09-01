// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;
use std::process::Command;

use broil_core::error::ExecutionError;
use broil_core::model::BroilConfig;

use crate::execenv;

pub fn execute(
    broil_root: &Path,
    config: &BroilConfig,
    active: Option<&OsStr>,
    script: &OsStr,
    args: &[OsString],
    base_env: &[(OsString, OsString)],
) -> Result<i32, ExecutionError> {
    let resolved = execenv::resolve(config, active)?;
    let Some(body) = script.to_str().and_then(|name| resolved.scripts.get(name)) else {
        return Err(ExecutionError::UnknownScript {
            name: script.to_string_lossy().into_owned(),
        });
    };
    let env = execenv::child_env(base_env, &resolved, broil_root);
    let mut child = Command::new("bash")
        .arg("-c")
        .arg("--")
        .arg(body)
        .arg("dummy")
        .args(args)
        .current_dir(broil_root)
        .env_clear()
        .envs(&env)
        .spawn()
        .map_err(|error| spawn_error("run", error))?;
    let status = child
        .wait()
        .map_err(|error| spawn_error("wait for", error))?;
    execenv::status_code(status)
}

fn spawn_error(action: &str, error: io::Error) -> ExecutionError {
    ExecutionError::Spawn {
        message: format!("cannot {action} bash: {error}"),
    }
}
