// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use broil_core::error::ConfigError;

use crate::raw::{self, RawValue};

struct Fragment {
    filename: String,
    key_path: Vec<String>,
    content: RawValue,
}

pub(crate) fn merge_fragments(root: &mut RawValue, broil_root: &Path) -> Result<(), ConfigError> {
    for fragment in enumerate(broil_root)? {
        place(root, &fragment)?;
    }
    Ok(())
}

fn enumerate(broil_root: &Path) -> Result<Vec<Fragment>, ConfigError> {
    let broil_dir = broil_root.join("broil");
    if !resolve_directory(&broil_dir)? {
        return Ok(Vec::new());
    }
    let cfg_dir = broil_dir.join("cfg");
    if !resolve_directory(&cfg_dir)? {
        return Ok(Vec::new());
    }

    let entries = fs::read_dir(&cfg_dir).map_err(|error| ConfigError::FragmentDirUnreadable {
        path: cfg_dir.clone(),
        message: error.to_string(),
    })?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| ConfigError::FragmentDirUnreadable {
            path: cfg_dir.clone(),
            message: error.to_string(),
        })?;
        let name = entry.file_name();
        let bytes = name.as_bytes();
        if bytes.ends_with(b".yaml") || bytes.ends_with(b".yml") {
            names.push(name);
        }
    }
    names.sort_unstable();

    let mut fragments = Vec::new();
    for name in names {
        let candidate = cfg_dir.join(&name);
        let metadata =
            fs::metadata(&candidate).map_err(|error| ConfigError::FragmentFileUnusable {
                path: candidate.clone(),
                message: error.to_string(),
            })?;
        if metadata.is_dir() {
            continue;
        }
        if !metadata.is_file() {
            return Err(ConfigError::FragmentFileUnusable {
                path: candidate,
                message: "not a regular file".to_string(),
            });
        }
        let Some(filename) = name.to_str().map(str::to_string) else {
            return Err(ConfigError::FragmentFilenameNotUtf8 {
                filename_lossy: name.to_string_lossy().into_owned(),
            });
        };
        let stem = filename
            .strip_suffix(".yaml")
            .or_else(|| filename.strip_suffix(".yml"))
            .expect("candidate suffix");
        let key_path: Vec<String> = stem.split('.').map(str::to_string).collect();
        if key_path.iter().any(String::is_empty) {
            return Err(ConfigError::FragmentEmptyPathSegment { filename });
        }
        let content =
            fs::read_to_string(&candidate).map_err(|error| ConfigError::FragmentFileUnusable {
                path: candidate.clone(),
                message: error.to_string(),
            })?;
        match raw::parse_str(&content, &candidate)? {
            None | Some(RawValue::Null) => {}
            Some(value) => fragments.push(Fragment {
                filename,
                key_path,
                content: value,
            }),
        }
    }

    fragments.sort_by(|a, b| {
        a.key_path
            .len()
            .cmp(&b.key_path.len())
            .then_with(|| a.filename.as_bytes().cmp(b.filename.as_bytes()))
    });
    Ok(fragments)
}

fn resolve_directory(path: &Path) -> Result<bool, ConfigError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(ConfigError::FragmentDirUnreadable {
                path: path.to_path_buf(),
                message: error.to_string(),
            });
        }
    }
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(ConfigError::FragmentDirNotDirectory {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(ConfigError::FragmentDirNotDirectory {
                path: path.to_path_buf(),
            })
        }
        Err(error) => Err(ConfigError::FragmentDirUnreadable {
            path: path.to_path_buf(),
            message: error.to_string(),
        }),
    }
}

fn place(root: &mut RawValue, fragment: &Fragment) -> Result<(), ConfigError> {
    let mut current = root;
    let (last, parents) = fragment.key_path.split_last().expect("non-empty key path");
    let mut walked = Vec::new();
    for segment in parents {
        walked.push(segment.clone());
        let RawValue::Map(pairs) = current else {
            unreachable!("walk starts and stays at mappings");
        };
        let position = pairs.iter().position(|(key, _)| match key {
            RawValue::Str(name) => name == segment,
            _ => false,
        });
        let index = match position {
            Some(index) => {
                if !matches!(pairs[index].1, RawValue::Map(_)) {
                    return Err(ConfigError::FragmentParentNotMapping {
                        key_path: walked.join("."),
                        filename: fragment.filename.clone(),
                    });
                }
                index
            }
            None => {
                pairs.push((RawValue::Str(segment.clone()), RawValue::Map(Vec::new())));
                pairs.len() - 1
            }
        };
        current = &mut pairs[index].1;
    }
    let RawValue::Map(pairs) = current else {
        unreachable!("walk starts and stays at mappings");
    };
    let exists = pairs.iter().any(|(key, _)| match key {
        RawValue::Str(name) => name == last,
        _ => false,
    });
    if exists {
        return Err(ConfigError::FragmentTargetAlreadyDefined {
            key_path: fragment.key_path.join("."),
            filename: fragment.filename.clone(),
        });
    }
    pairs.push((RawValue::Str(last.clone()), fragment.content.clone()));
    Ok(())
}
