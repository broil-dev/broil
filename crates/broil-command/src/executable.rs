// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use broil_core::error::{ExecutionError, UsageError};
use broil_core::model::BroilConfig;
use broil_core::segment::is_valid_alias_path_segment;
use rustix::fs::{Access, AtFlags, CWD, accessat};

use crate::execenv;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    NoMatch,
    Selected { path: PathBuf, consumed: usize },
    Usage(UsageError),
}

pub fn resolve(broil_root: &Path, tokens: &[OsString]) -> Result<Resolution, ExecutionError> {
    let Some(_) = tokens.first() else {
        return Ok(Resolution::NoMatch);
    };

    let dir = broil_root.join("broil").join("bin");
    match fs::symlink_metadata(&dir) {
        Ok(_) => {}
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                || error.kind() == io::ErrorKind::NotADirectory =>
        {
            return Ok(Resolution::NoMatch);
        }
        Err(error) => return Err(unreadable(dir, &error)),
    }
    match fs::metadata(&dir) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(ExecutionError::ExecutableDirNotDirectory { path: dir }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ExecutionError::ExecutableDirNotDirectory { path: dir });
        }
        Err(error) => return Err(unreadable(dir, &error)),
    }
    if let Err(errno) = accessat(
        CWD,
        &dir,
        Access::READ_OK | Access::EXEC_OK,
        AtFlags::EACCESS,
    ) {
        let error = io::Error::from(errno);
        return Err(unreadable(dir, &error));
    }

    let mut current = dir;
    let mut chain = Vec::new();
    for (level, token) in tokens.iter().enumerate() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(error) if level == 0 => return Err(unreadable(current, &error)),
            Err(error) => return Err(unenumerable(current, &error)),
        };
        let mut matched = None;
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if level == 0 => return Err(unreadable(current, &error)),
                Err(error) => return Err(unenumerable(current, &error)),
            };
            let name = entry.file_name();
            if name.as_os_str() == token.as_os_str() {
                matched = Some(name);
                break;
            }
        }

        let Some(name) = matched else {
            return Ok(no_match(level, &chain, token));
        };
        match eligible_entry(&current, &name) {
            Some(EligibleEntry::File(path)) => {
                return Ok(Resolution::Selected {
                    path,
                    consumed: level + 1,
                });
            }
            Some(EligibleEntry::Group(path)) => {
                chain.push(name.into_string().expect("eligible group name is UTF-8"));
                if level + 1 == tokens.len() {
                    return Ok(Resolution::Usage(UsageError::IncompleteExecutableGroup {
                        chain: chain.join(" "),
                    }));
                }
                current = path;
            }
            None => return Ok(no_match(level, &chain, token)),
        }
    }
    unreachable!("a non-empty token stream returns from the resolution walk")
}

fn no_match(level: usize, chain: &[String], token: &OsStr) -> Resolution {
    if level == 0 {
        Resolution::NoMatch
    } else {
        Resolution::Usage(UsageError::UnknownExecutableChain {
            chain: chain.join(" "),
            token: token.to_string_lossy().into_owned(),
        })
    }
}

enum EligibleEntry {
    File(PathBuf),
    Group(PathBuf),
}

fn eligible_entry(dir: &Path, name: &OsStr) -> Option<EligibleEntry> {
    let segment = name.to_str()?;
    if !is_valid_alias_path_segment(segment) {
        return None;
    }
    let path = dir.join(name);
    let metadata = fs::metadata(&path).ok()?;
    accessat(CWD, &path, Access::EXEC_OK, AtFlags::EACCESS).ok()?;
    if metadata.is_file() {
        Some(EligibleEntry::File(path))
    } else if metadata.is_dir() {
        Some(EligibleEntry::Group(path))
    } else {
        None
    }
}

fn unreadable(path: PathBuf, error: &io::Error) -> ExecutionError {
    ExecutionError::ExecutableDirUnreadable {
        path,
        message: error.to_string(),
    }
}

fn unenumerable(path: PathBuf, error: &io::Error) -> ExecutionError {
    ExecutionError::ExecutableGroupUnenumerable {
        path,
        message: error.to_string(),
    }
}

pub fn execute(
    path: &Path,
    broil_root: &Path,
    config: &BroilConfig,
    active: Option<&OsStr>,
    args: &[OsString],
    base_env: &[(OsString, OsString)],
) -> Result<i32, ExecutionError> {
    execute_with_inputs(
        path,
        broil_root,
        config,
        active,
        args,
        base_env,
        crate::injection::Inputs::borrowed(broil_root, base_env),
    )
}

pub fn execute_with_inputs(
    path: &Path,
    broil_root: &Path,
    config: &BroilConfig,
    active: Option<&OsStr>,
    args: &[OsString],
    base_env: &[(OsString, OsString)],
    inputs: crate::injection::Inputs<'_>,
) -> Result<i32, ExecutionError> {
    let resolved = execenv::resolve(config, active)?;
    let env = execenv::child_env(base_env, &resolved, broil_root);
    let injection = crate::injection::Injection::resolve(config, broil_root, active, inputs)?;
    let mut command = Command::new(path);
    command.args(args).current_dir(broil_root);
    let mut child = injection
        .spawn(command, &env)
        .map_err(|error| spawn_error("launch", path, &error))?;
    let status = child
        .wait()
        .map_err(|error| spawn_error("wait for", path, &error))?;
    execenv::status_code(status)
}

fn spawn_error(action: &str, path: &Path, error: &io::Error) -> ExecutionError {
    ExecutionError::Spawn {
        message: format!("cannot {action} {}: {error}", path.display()),
    }
}
