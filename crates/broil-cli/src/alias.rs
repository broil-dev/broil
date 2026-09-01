// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use broil_core::error::UsageError;
use broil_core::model::{AliasNode, BroilConfig};

pub fn active_map(
    config: &BroilConfig,
    ambient_env: Option<&OsStr>,
) -> BTreeMap<String, AliasNode> {
    let mut map = config.aliases.clone();
    let named = ambient_env
        .filter(|value| !value.is_empty())
        .and_then(OsStr::to_str)
        .and_then(|name| config.environments.get(name));
    if let Some(environment) = named {
        overlay(&mut map, &environment.aliases);
    }
    map
}

fn overlay(base: &mut BTreeMap<String, AliasNode>, environment: &BTreeMap<String, AliasNode>) {
    for (name, node) in environment {
        let merged = match (base.remove(name), node) {
            (Some(AliasNode::Group(mut base_children)), AliasNode::Group(children)) => {
                overlay(&mut base_children, children);
                AliasNode::Group(base_children)
            }
            (_, node) => node.clone(),
        };
        base.insert(name.clone(), merged);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Resolution {
    NoMatch,
    Complete(Vec<OsString>),
    Partial(UsageError),
}

pub fn resolve(map: &BTreeMap<String, AliasNode>, tokens: &[OsString]) -> Resolution {
    let Some((first, mut rest)) = tokens.split_first() else {
        return Resolution::NoMatch;
    };
    let Some((first_name, mut node)) = first.to_str().and_then(|name| map.get_key_value(name))
    else {
        return Resolution::NoMatch;
    };
    let mut chain = vec![first_name.clone()];
    loop {
        match node {
            AliasNode::Leaf { tokens: stored, .. } => {
                let mut expanded: Vec<OsString> = stored.iter().map(OsString::from).collect();
                expanded.extend(rest.iter().cloned());
                return Resolution::Complete(expanded);
            }
            AliasNode::Group(children) => {
                let Some((next, remaining)) = rest.split_first() else {
                    return Resolution::Partial(UsageError::IncompleteAliasGroup {
                        chain: chain.join(" "),
                    });
                };
                match next.to_str().and_then(|name| children.get_key_value(name)) {
                    Some((name, child)) => {
                        chain.push(name.clone());
                        node = child;
                        rest = remaining;
                    }
                    None => {
                        return Resolution::Partial(UsageError::UnknownAliasChain {
                            chain: chain.join(" "),
                            token: next.to_string_lossy().into_owned(),
                        });
                    }
                }
            }
        }
    }
}
