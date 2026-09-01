// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use crate::path_safety::{self, CapabilityError, SafePathFinal};
use crate::transfer::{TransferDirection, TransferJob};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalPathValidation {
    ExistingNoSymlink,
    ExistingOrAbsentFinalNoSymlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedLocalPath {
    pub(crate) path: PathBuf,
    pub(crate) final_component: Option<SafePathFinal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteTransferPath {
    path: String,
    absolute: bool,
}

impl RemoteTransferPath {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn is_relative(&self) -> bool {
        !self.absolute
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransferPathPreflight {
    pub(crate) local: NormalizedLocalPath,
    pub(crate) remote: RemoteTransferPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransferPathError {
    diagnostic: &'static str,
}

impl TransferPathError {
    pub(crate) fn new(diagnostic: &'static str) -> Self {
        Self { diagnostic }
    }

    pub(crate) fn diagnostic(&self) -> &'static str {
        self.diagnostic
    }
}

pub(crate) fn preflight_transfer_paths(
    job: &TransferJob,
) -> Result<TransferPathPreflight, TransferPathError> {
    match job.direction {
        TransferDirection::Upload => Ok(TransferPathPreflight {
            local: normalize_local_operand(
                &job.caller_cwd,
                &job.source,
                LocalPathValidation::ExistingNoSymlink,
            )?,
            remote: parse_remote_operand(&job.destination)?,
        }),
        TransferDirection::Download => Ok(TransferPathPreflight {
            local: normalize_local_operand(
                &job.caller_cwd,
                &job.destination,
                LocalPathValidation::ExistingOrAbsentFinalNoSymlink,
            )?,
            remote: parse_remote_operand(&job.source)?,
        }),
    }
}

pub(crate) fn normalize_local_operand(
    caller_cwd: &Path,
    raw: &[u8],
    validation: LocalPathValidation,
) -> Result<NormalizedLocalPath, TransferPathError> {
    reject_bad_path_bytes(raw, "local")?;
    reject_non_normal_bytes(raw, "local")?;
    if !caller_cwd.is_absolute() || !path_components_are_normal(caller_cwd) {
        return Err(TransferPathError::new(
            "caller cwd for transfer operands is not normalized",
        ));
    }
    let operand = PathBuf::from(OsString::from_vec(raw.to_vec()));
    let path = if operand.is_absolute() {
        operand
    } else {
        caller_cwd.join(operand)
    };
    let final_component = match validation {
        LocalPathValidation::ExistingNoSymlink => Some(SafePathFinal::Existing(
            path_safety::defensive_classify(&path).map_err(local_safety_error)?,
        )),
        LocalPathValidation::ExistingOrAbsentFinalNoSymlink => Some(
            path_safety::defensive_classify_or_absent_final(&path).map_err(local_safety_error)?,
        ),
    };
    Ok(NormalizedLocalPath {
        path,
        final_component,
    })
}

pub(crate) fn parse_remote_operand(raw: &[u8]) -> Result<RemoteTransferPath, TransferPathError> {
    reject_bad_path_bytes(raw, "remote")?;
    let path = std::str::from_utf8(raw)
        .map_err(|_| TransferPathError::new("remote transfer operand is not valid UTF-8"))?;
    parse_remote_path(path, "remote transfer operand")
}

pub(crate) fn parse_remote_base_result(path: &str) -> Result<String, TransferPathError> {
    if path.contains('\u{fffd}') {
        return Err(TransferPathError::new(
            "remote login-directory base is not byte-faithful",
        ));
    }
    let parsed = parse_remote_path(path, "remote login-directory base")?;
    if parsed.is_relative() {
        return Err(TransferPathError::new(
            "remote login-directory base is not absolute",
        ));
    }
    Ok(parsed.path)
}

pub(crate) fn join_remote_base(base: &str, operand: &RemoteTransferPath) -> String {
    if !operand.is_relative() {
        return operand.path.clone();
    }
    if base == "/" {
        format!("/{}", operand.path)
    } else {
        format!("{base}/{}", operand.path)
    }
}

pub(crate) fn remote_component_prefixes(path: &str) -> Result<Vec<String>, TransferPathError> {
    let parsed = parse_remote_path(path, "remote path")?;
    if parsed.is_relative() {
        return Err(TransferPathError::new("remote path is not absolute"));
    }
    if parsed.path == "/" {
        return Ok(vec!["/".to_string()]);
    }
    let mut prefixes = vec!["/".to_string()];
    let mut current = String::new();
    for part in parsed.path.trim_start_matches('/').split('/') {
        current.push('/');
        current.push_str(part);
        prefixes.push(current.clone());
    }
    Ok(prefixes)
}

fn parse_remote_path(
    path: &str,
    label: &'static str,
) -> Result<RemoteTransferPath, TransferPathError> {
    reject_bad_remote_path_str(path, label)?;
    reject_non_normal_str(path, label)?;
    Ok(RemoteTransferPath {
        path: path.to_string(),
        absolute: path.starts_with('/'),
    })
}

fn reject_bad_path_bytes(raw: &[u8], side: &'static str) -> Result<(), TransferPathError> {
    if raw.is_empty() {
        return Err(TransferPathError::new(match side {
            "local" => "local transfer operand is empty",
            _ => "remote transfer operand is empty",
        }));
    }
    if raw.contains(&0) {
        return Err(TransferPathError::new(match side {
            "local" => "local transfer operand contains NUL",
            _ => "remote transfer operand contains NUL",
        }));
    }
    Ok(())
}

fn reject_non_normal_bytes(raw: &[u8], side: &'static str) -> Result<(), TransferPathError> {
    if raw == b"/" {
        return Ok(());
    }
    let absolute = raw.starts_with(b"/");
    for (index, part) in raw.split(|byte| *byte == b'/').enumerate() {
        if part.is_empty() {
            if absolute && index == 0 {
                continue;
            }
            return Err(TransferPathError::new(match side {
                "local" => "local transfer operand is not normalized",
                _ => "remote transfer operand is not normalized",
            }));
        }
        if part == b"." {
            return Err(TransferPathError::new(match side {
                "local" => "local transfer operand is not normalized",
                _ => "remote transfer operand is not normalized",
            }));
        }
        if part == b".." {
            return Err(TransferPathError::new(match side {
                "local" => "local transfer operand contains traversal",
                _ => "remote transfer operand contains traversal",
            }));
        }
    }
    Ok(())
}

fn reject_non_normal_str(path: &str, label: &'static str) -> Result<(), TransferPathError> {
    if path == "/" {
        return Ok(());
    }
    let absolute = path.starts_with('/');
    for (index, part) in path.split('/').enumerate() {
        if part.is_empty() {
            if absolute && index == 0 {
                continue;
            }
            return Err(TransferPathError::new(non_normal_diagnostic(label, false)));
        }
        if part == "." {
            return Err(TransferPathError::new(non_normal_diagnostic(label, false)));
        }
        if part == ".." {
            return Err(TransferPathError::new(non_normal_diagnostic(label, true)));
        }
    }
    Ok(())
}

fn reject_bad_remote_path_str(path: &str, label: &'static str) -> Result<(), TransferPathError> {
    if path.is_empty() {
        return Err(TransferPathError::new(empty_diagnostic(label)));
    }
    if path.contains('\0') {
        return Err(TransferPathError::new(nul_diagnostic(label)));
    }
    Ok(())
}

fn empty_diagnostic(label: &'static str) -> &'static str {
    match label {
        "remote login-directory base" => "remote login-directory base is empty",
        "remote path" => "remote path is empty",
        _ => "remote transfer operand is empty",
    }
}

fn nul_diagnostic(label: &'static str) -> &'static str {
    match label {
        "remote login-directory base" => "remote login-directory base contains NUL",
        "remote path" => "remote path contains NUL",
        _ => "remote transfer operand contains NUL",
    }
}

fn non_normal_diagnostic(label: &'static str, traversal: bool) -> &'static str {
    match (label, traversal) {
        ("remote login-directory base", true) => "remote login-directory base contains traversal",
        ("remote login-directory base", false) => "remote login-directory base is not normalized",
        ("remote path", true) => "remote path contains traversal",
        ("remote path", false) => "remote path is not normalized",
        (_, true) => "remote transfer operand contains traversal",
        (_, false) => "remote transfer operand is not normalized",
    }
}

fn path_components_are_normal(path: &Path) -> bool {
    path.components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn local_safety_error(error: CapabilityError) -> TransferPathError {
    match error {
        CapabilityError::UnsafePath => TransferPathError::new("local transfer path is unsafe"),
        _ => TransferPathError::new("local transfer path is not permitted"),
    }
}

