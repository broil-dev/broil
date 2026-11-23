// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use broil_core::error::ConfigError;

const DEFAULT_NAMES: [&str; 2] = ["broil.yaml", "broil.yml"];

pub(crate) struct Selection {
    pub(crate) file: PathBuf,
    pub(crate) broil_root: PathBuf,
}

pub(crate) fn discover(cwd: &Path) -> Result<Selection, ConfigError> {
    let start = normalize(&absolutize(cwd, None));
    let mut dir = start.clone();
    loop {
        let mut existing = Vec::new();
        for name in DEFAULT_NAMES {
            let candidate = dir.join(name);
            match fs::symlink_metadata(&candidate) {
                Ok(_) => existing.push(candidate),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(ConfigError::DefaultNotReadableRegularFile { path: candidate });
                }
            }
        }
        for candidate in &existing {
            require_readable_regular_file(candidate).map_err(|_| {
                ConfigError::DefaultNotReadableRegularFile {
                    path: candidate.clone(),
                }
            })?;
        }
        match existing.len() {
            1 => {
                let file = existing.remove(0);
                let broil_root = dir.clone();
                return Ok(Selection { file, broil_root });
            }
            2 => return Err(ConfigError::BothDefaultsPresent { dir }),
            _ => {}
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => return Err(ConfigError::NoConfigFound { start_dir: start }),
        }
    }
}

pub(crate) fn select_file(path: &Path, cwd: &Path) -> Result<Selection, ConfigError> {
    let file = absolutize(path, Some(cwd));
    match fs::symlink_metadata(&file) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(ConfigError::ExplicitFileMissing { path: file });
        }
        Err(_) => return Err(ConfigError::ExplicitFileUnreadable { path: file }),
    }
    match require_readable_regular_file(&file) {
        Ok(()) => {}
        Err(NotReadableRegular::Missing) => {
            return Err(ConfigError::ExplicitFileMissing { path: file });
        }
        Err(NotReadableRegular::NotRegular) => {
            return Err(ConfigError::ExplicitFileNotRegular { path: file });
        }
        Err(NotReadableRegular::Unreadable) => {
            return Err(ConfigError::ExplicitFileUnreadable { path: file });
        }
    }
    let parent = file.parent().unwrap_or(Path::new("/"));
    let broil_root = normalize(parent);
    Ok(Selection { file, broil_root })
}

pub(crate) enum NotReadableRegular {
    Missing,
    NotRegular,
    Unreadable,
}

fn require_readable_regular_file(path: &Path) -> Result<(), NotReadableRegular> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            NotReadableRegular::Missing
        } else {
            NotReadableRegular::Unreadable
        }
    })?;
    if !metadata.is_file() {
        return Err(NotReadableRegular::NotRegular);
    }
    fs::File::open(path).map_err(|_| NotReadableRegular::Unreadable)?;
    Ok(())
}

fn absolutize(path: &Path, base: Option<&Path>) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match base {
        Some(base) => absolutize(base, None).join(path),
        None => match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => PathBuf::from("/").join(path),
        },
    }
}

pub(crate) fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}
