// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use broil_core::{
    error::ExecutionError, model::BroilConfig, secret::environment::CredentialInputs,
};
use broil_secrets::{
    output::{self, Prepared},
    read::{self, Options, Selection},
};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io,
    os::unix::ffi::OsStrExt,
    path::Path,
    process::{Child, Command},
};

pub struct Inputs<'a> {
    pub cwd: &'a Path,
    pub credentials: CredentialInputs,
}
impl<'a> Inputs<'a> {
    pub fn borrowed(cwd: &'a Path, env: &[(OsString, OsString)]) -> Self {
        Self {
            cwd,
            credentials: CredentialInputs::borrowed(env),
        }
    }
}

pub(crate) struct Injection {
    pub enabled: bool,
    values: BTreeMap<String, Prepared>,
}
pub(crate) fn error(error: impl std::fmt::Display) -> ExecutionError {
    ExecutionError::Injection {
        message: error.to_string(),
    }
}
impl Injection {
    pub fn resolve(
        config: &BroilConfig,
        root: &Path,
        active: Option<&OsStr>,
        inputs: Inputs<'_>,
    ) -> Result<Self, ExecutionError> {
        let selected = Selection::new(config, root, active).map_err(error)?;
        let enabled = selected.config.inject.unwrap_or(false);
        let values = if enabled {
            read::resolve_exports(
                &selected,
                &Options::default(),
                inputs.cwd,
                inputs.credentials,
            )
            .map_err(error)?
        } else {
            drop(inputs);
            BTreeMap::new()
        };
        Ok(Self { enabled, values })
    }

    pub fn spawn(
        self,
        mut command: Command,
        ordinary: &BTreeMap<OsString, OsString>,
    ) -> io::Result<Child> {
        command.env_clear().envs(ordinary);
        for (name, value) in &self.values {
            command.env(name, OsStr::from_bytes(value.as_bytes()));
        }
        for name in ["BROIL_ROOT", "BROIL_ENV"] {
            match ordinary.get(OsStr::new(name)) {
                Some(value) => {
                    command.env(name, value);
                }
                None => {
                    command.env_remove(name);
                }
            }
        }
        drop(self);
        let result = command.spawn();
        drop(command);
        result
    }

    pub fn rcfile(&self, before: &[u8], after: &[u8]) -> Result<Prepared, ExecutionError> {
        output::prepare(output::MAX_OUTPUT_BYTES, |writer| {
            writer.bytes(before)?;
            for (name, value) in &self.values {
                writer.text("export ")?;
                writer.text(name)?;
                writer.text("='")?;
                for (i, part) in value.as_str().split('\'').enumerate() {
                    if i > 0 {
                        writer.text("'\\''")?;
                    }
                    writer.text(part)?;
                }
                writer.text("'\n")?;
            }
            writer.bytes(after)
        })
        .map_err(error)
    }
}
