// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use broil_core::error::ConfigError;

use crate::raw::RawValue;

const EXTENDS_KEY: &str = "$extends";

pub(crate) fn resolve_root(root: &RawValue) -> Result<RawValue, ConfigError> {
    let mut stack = Vec::new();
    resolve_node(root, root, &mut Vec::new(), &mut stack)
}

fn resolve_node(
    node: &RawValue,
    root: &RawValue,
    key_path: &mut Vec<String>,
    stack: &mut Vec<String>,
) -> Result<RawValue, ConfigError> {
    match node {
        RawValue::Map(pairs) => {
            let extends = pairs.iter().find_map(|(key, value)| match key {
                RawValue::Str(name) if name == EXTENDS_KEY => Some(value),
                _ => None,
            });
            match extends {
                Some(directive) => {
                    let RawValue::Str(target_path) = directive else {
                        return Err(ConfigError::ExtendsNonString {
                            key_path: context(key_path),
                        });
                    };
                    let base = resolve_target(target_path, root, key_path, stack)?;
                    let RawValue::Map(mut merged) = base else {
                        unreachable!("resolve_target returns mappings");
                    };
                    for (key, value) in pairs {
                        if matches!(key, RawValue::Str(name) if name == EXTENDS_KEY) {
                            continue;
                        }
                        let pushed = match key {
                            RawValue::Str(name) => {
                                key_path.push(name.clone());
                                true
                            }
                            _ => false,
                        };
                        let resolved_value = resolve_node(value, root, key_path, stack);
                        if pushed {
                            key_path.pop();
                        }
                        merge_pair(&mut merged, key, &resolved_value?);
                    }
                    Ok(RawValue::Map(merged))
                }
                None => resolve_children(pairs.clone(), root, key_path, stack),
            }
        }
        RawValue::Seq(items) => {
            let mut resolved = Vec::with_capacity(items.len());
            for item in items {
                resolved.push(resolve_node(item, root, key_path, stack)?);
            }
            Ok(RawValue::Seq(resolved))
        }
        other => Ok(other.clone()),
    }
}

fn resolve_children(
    pairs: Vec<(RawValue, RawValue)>,
    root: &RawValue,
    key_path: &mut Vec<String>,
    stack: &mut Vec<String>,
) -> Result<RawValue, ConfigError> {
    let mut resolved = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let pushed = match &key {
            RawValue::Str(name) => {
                key_path.push(name.clone());
                true
            }
            _ => false,
        };
        let value = resolve_node(&value, root, key_path, stack);
        if pushed {
            key_path.pop();
        }
        resolved.push((key, value?));
    }
    Ok(RawValue::Map(resolved))
}

fn resolve_target(
    target_path: &str,
    root: &RawValue,
    key_path: &[String],
    stack: &mut Vec<String>,
) -> Result<RawValue, ConfigError> {
    if stack.iter().any(|entry| entry == target_path) {
        let mut chain = stack.clone();
        chain.push(target_path.to_string());
        return Err(ConfigError::ExtendsCycle { chain });
    }

    let mut node = root;
    for segment in target_path.split('.') {
        match node.get(segment) {
            Some(child) => node = child,
            None => {
                return Err(ConfigError::ExtendsMissingTarget {
                    key_path: context(key_path),
                    target: target_path.to_string(),
                });
            }
        }
    }
    if !matches!(node, RawValue::Map(_)) {
        return Err(ConfigError::ExtendsNonMappingTarget {
            key_path: context(key_path),
            target: target_path.to_string(),
        });
    }

    stack.push(target_path.to_string());
    let mut target_key_path: Vec<String> = target_path.split('.').map(str::to_string).collect();
    let resolved = resolve_node(node, root, &mut target_key_path, stack);
    stack.pop();
    resolved
}

fn context(key_path: &[String]) -> String {
    if key_path.is_empty() {
        "<root>".to_string()
    } else {
        key_path.join(".")
    }
}

fn merge_pair(base: &mut Vec<(RawValue, RawValue)>, key: &RawValue, value: &RawValue) {
    let position = base.iter().position(|(existing, _)| existing == key);
    match position {
        Some(index) => {
            let existing = &mut base[index].1;
            if let (RawValue::Map(base_children), RawValue::Map(current_children)) =
                (&mut *existing, value)
            {
                for (child_key, child_value) in current_children {
                    merge_pair(base_children, child_key, child_value);
                }
            } else {
                *existing = value.clone();
            }
        }
        None => base.push((key.clone(), value.clone())),
    }
}
