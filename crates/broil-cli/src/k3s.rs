// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{BuiltinLeaf, BuiltinMatch, Context, HelpLeaf};
use broil_command::{
    help,
    k3s::{commands as command, state},
};
use broil_core::{error::UsageError, images::valid_name};
use std::{collections::BTreeMap, ffi::OsString, io::Write};

pub(super) struct Leaf<'a> {
    verb: command::Verb,
    operands: &'a [OsString],
}

fn usage(reason: String) -> UsageError {
    UsageError::K3s { reason }
}

pub(super) fn resolve(tokens: &[OsString], topic: bool) -> BuiltinMatch<'_> {
    let (mut path, mut index) = (String::new(), 0);
    loop {
        let leaf = command::Verb::named(&path);
        let known = command::group(&path).or_else(|| leaf.map(command::Verb::name));
        if topic && (leaf.is_some() || index == tokens.len()) {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: known
                    .map(help::Topic::K3s)
                    .ok_or_else(|| format!("k3s {path}")),
                operands: &tokens[index..],
            }));
        }
        if let (Some(known), true) = (
            known,
            !topic && tokens.get(index).is_some_and(|v| v == "--help"),
        ) {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::K3s(known)),
                operands: &tokens[index + 1..],
            }));
        }
        if let Some(verb) = leaf {
            return BuiltinMatch::Complete(BuiltinLeaf::K3s(Leaf {
                verb,
                operands: &tokens[index..],
            }));
        }
        if known.is_none() || index == tokens.len() {
            let path = if path.is_empty() {
                "k3s".into()
            } else {
                format!("k3s {path}")
            };
            if topic {
                return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                    topic: Err(path),
                    operands: &tokens[index..],
                }));
            }
            return BuiltinMatch::Partial(usage(format!(
                "{} k3s command {:?}",
                if known.is_none() {
                    "unknown"
                } else {
                    "incomplete"
                },
                path
            )));
        }
        if !path.is_empty() {
            path.push(' ');
        }
        path.push_str(&tokens[index].to_string_lossy());
        index += 1;
    }
}

fn valid(kind: &str, value: &str) -> bool {
    let bounded = |minimum: u64, maximum: u64| {
        !value.is_empty()
            && !value.starts_with('0')
            && value.bytes().all(|b| b.is_ascii_digit())
            && value
                .parse::<u64>()
                .is_ok_and(|n| (minimum..=maximum).contains(&n))
    };
    let decimal = |maximum: u64| bounded(1, maximum);
    match kind {
        "--format" => matches!(value, "table" | "json"),
        "--scope" => matches!(value, "runtime" | "registry" | "all"),
        "--consumer" => matches!(
            value,
            "server-token"
                | "agent-token"
                | "admin"
                | "node-pull"
                | "registry-auth"
                | "infrastructure-tls"
        ),
        "--component" => matches!(
            value,
            "api"
                | "datastore"
                | "network"
                | "dns"
                | "storage"
                | "ingress"
                | "certificates"
                | "registry"
        ),
        "--purpose" => matches!(value, "publication" | "active" | "rollback" | "seed"),
        "--step" => decimal(u32::MAX.into()),
        "--limit" => decimal(1000),
        "--keep-days" => bounded(1, 3650),
        "--keep-last" => bounded(100, 16_384),
        "<release>" | "--release" => value.strip_prefix("release-").is_some_and(|v| {
            v.len() == 32
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }),
        "--artifacts" => {
            let mut images = std::collections::BTreeSet::new();
            value.split(',').all(|pair| {
                pair.split_once('=').is_some_and(|(image, artifact)| {
                    valid_name(image)
                        && broil_command::images::commands::valid_artifact_id(artifact)
                        && images.insert(image)
                })
            })
        }
        "--approve" => value.strip_prefix("sha256:").is_some_and(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }),
        "<operation-id>" => state::operation_id(value),
        "--backup" => value
            .strip_prefix("infra-backup-")
            .is_some_and(state::nonce),
        "--artifact" => broil_command::images::commands::valid_artifact_id(value),
        "<member>" | "--member" => broil_config::k3s::valid_member_name(value),
        "--output" => {
            !value.is_empty()
                && value.len() <= 4096
                && !value.contains('\0')
                && value.split('/').all(|part| part.len() <= 255)
        }
        "--version" => {
            value.len() <= 128
                && (broil_config::k3s::valid_k3s_version(value)
                    || broil_config::k3s::valid_registry_version(value))
        }
        "--repository" => {
            broil_core::images::reference::ImageReference::parse(value).is_some_and(|r| {
                r.explicit_authority
                    && r.tag.is_none()
                    && r.digest.is_none()
                    && r.repository == value
            })
        }
        "--action" => plan_options(value).is_some(),
        _ => valid_name(value),
    }
}

fn plan_options(action: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match action {
        "create" | "reconcile" | "node-join-agents" | "backup-create" | "remove"
        | "registry-reconcile" | "registry-backup" | "registry-remove" => (&[], &[]),
        "node-join" | "node-drain" | "node-uncordon" | "node-remove" | "node-replace" => {
            (&["--member"], &[])
        }
        "release-retain" => (&["--application"], &[]),
        "release-apply" => (&["--release"], &[]),
        "operation-prune" => (&[], &["--keep-days", "--keep-last"]),
        "credentials-reconcile" => (&["--consumer"], &[]),
        "backup-restore" | "registry-restore" => (&["--backup"], &[]),
        "upgrade" | "registry-upgrade" => (&["--version"], &[]),
        "purge" => (&["--scope"], &[]),
        "retention-hold" | "retention-release" => {
            (&["--owner", "--purpose", "--artifact", "--repository"], &[])
        }
        _ => return None,
    })
}

fn parse(verb: command::Verb, tokens: &[OsString]) -> Result<command::Invocation, UsageError> {
    let grammar: Vec<_> = verb.grammar().split_whitespace().collect();
    let positional: Vec<_> = grammar
        .iter()
        .copied()
        .take_while(|v| v.starts_with('<'))
        .collect();
    let (mut operands, mut options) = (Vec::new(), BTreeMap::new());
    let (mut index, mut ended) = (0, false);
    while let Some(token) = tokens.get(index) {
        index += 1;
        if !ended && token == "--" {
            ended = true;
            continue;
        }
        if !ended && token.as_encoded_bytes().starts_with(b"-") {
            let flag = token.to_str().unwrap_or("");
            if !matches!(flag, "--format" | "--non-interactive")
                && !grammar.iter().any(|v| v.trim_matches(['[', ']']) == flag)
            {
                return Err(usage(format!(
                    "unknown k3s {} option {:?}",
                    verb.name(),
                    token
                )));
            }
            if options.contains_key(flag) {
                return Err(usage(format!("repeated k3s option {flag}")));
            }
            let value = if matches!(flag, "--observe" | "--non-interactive") {
                String::new()
            } else {
                let value = tokens
                    .get(index)
                    .filter(|v| !v.as_encoded_bytes().starts_with(b"--"))
                    .ok_or_else(|| usage(format!("missing value for k3s option {flag}")))?;
                index += 1;
                value
                    .to_str()
                    .filter(|v| valid(flag, v))
                    .ok_or_else(|| usage(format!("invalid k3s {flag} value {:?}", value)))?
                    .to_owned()
            };
            options.insert(flag.to_owned(), value);
        } else {
            let kind = positional.get(operands.len()).ok_or_else(|| {
                usage(format!(
                    "unexpected k3s {} operand {:?}",
                    verb.name(),
                    token
                ))
            })?;
            operands.push(
                token
                    .to_str()
                    .filter(|v| valid(kind, v))
                    .ok_or_else(|| usage(format!("invalid k3s {kind} value {:?}", token)))?
                    .to_owned(),
            );
        }
    }
    if let Some(kind) = positional.get(operands.len()) {
        return Err(usage(format!("missing k3s {} operand {kind}", verb.name())));
    }
    for flag in grammar.iter().filter(|v| v.starts_with("--")) {
        if !options.contains_key(*flag) {
            return Err(usage(format!("missing required k3s option {flag}")));
        }
    }
    if verb.name() == "plan" {
        let (required, optional) =
            plan_options(&options["--action"]).expect("validated plan action");
        for flag in required {
            if !options.contains_key(*flag) {
                return Err(usage(format!("missing required k3s plan option {flag}")));
            }
        }
        for flag in options.keys() {
            if !matches!(
                flag.as_str(),
                "--action" | "--observe" | "--format" | "--non-interactive"
            ) && !required.contains(&flag.as_str())
                && !optional.contains(&flag.as_str())
            {
                return Err(usage(format!(
                    "unexpected option {flag} for this k3s plan action"
                )));
            }
        }
    }
    if let Some(version) = options.get("--version") {
        let registry = verb.name() == "registry upgrade"
            || options
                .get("--action")
                .is_some_and(|a| a == "registry-upgrade");
        let valid = if registry {
            broil_config::k3s::valid_registry_version(version)
        } else {
            broil_config::k3s::valid_k3s_version(version)
        };
        if !valid {
            return Err(usage(
                "version does not match the selected K3s action".into(),
            ));
        }
    }
    if options.get("--purpose").is_some_and(|p| p != "publication")
        && !options
            .get("--owner")
            .is_some_and(|o| o.starts_with("synthetic-"))
    {
        return Err(usage(
            "this retention purpose requires a synthetic- owner".into(),
        ));
    }
    Ok(command::Invocation {
        verb,
        operands,
        options,
    })
}

pub(super) fn dispatch(
    leaf: Leaf<'_>,
    context: &Context<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let invocation = match parse(leaf.verb, leaf.operands) {
        Ok(v) => v,
        Err(e) => return super::usage(stderr, &e),
    };
    let inputs = command::Inputs {
        cwd: context.cwd,
        environment: super::ambient_broil_env(context.env_snapshot),
        env_snapshot: context.env_snapshot,
        credentials: context.credentials.take(),
    };
    match command::run(context.project, invocation, inputs) {
        Ok(output) => {
            if stdout
                .write_all(&output.payload)
                .and_then(|()| stdout.flush())
                .is_err()
            {
                let _ = writeln!(
                    stderr,
                    "broil: k3s output failed; operation and cleanup uncertainty remain recorded"
                );
                return 1;
            }
            output.status
        }
        Err(error) => {
            let _ = writeln!(
                stderr,
                "broil: k3s {}: {}{}{}",
                leaf.verb.name(),
                if error == state::Failure::Capability {
                    "unavailable capability"
                } else {
                    error.failure.name()
                },
                error.boundary.map(|b| format!(": {b}")).unwrap_or_default(),
                error
                    .detail
                    .map(|d| format!(" ({})", d.escape_debug()))
                    .unwrap_or_default()
            );
            1
        }
    }
}
