// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{BuiltinLeaf, BuiltinMatch, Context, HelpLeaf};
use broil_command::{
    help,
    images::{
        Cancellation,
        commands::{self as command, Format, Invocation, Verb},
    },
};
use broil_core::{
    error::UsageError,
    images::{valid_name, valid_platform},
};
use std::{collections::BTreeMap, ffi::OsString, io::Write, path::Path};

pub(super) struct Leaf<'a> {
    pub verb: Verb,
    pub operands: &'a [OsString],
}

fn group(path: &str) -> Option<&'static str> {
    match path {
        "" => Some(""),
        "record" => Some("record"),
        "builder" => Some("builder"),
        _ => None,
    }
}

pub(super) fn resolve(tokens: &[OsString], topic: bool) -> BuiltinMatch<'_> {
    let (mut path, mut index) = (String::new(), 0);
    loop {
        let leaf = Verb::named(&path);
        let known = group(&path).or_else(|| leaf.map(Verb::name));
        if topic && (leaf.is_some() || index == tokens.len()) {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: known
                    .map(help::Topic::Image)
                    .ok_or_else(|| format!("image {path}")),
                operands: &tokens[index..],
            }));
        }
        if let (Some(known), true) = (
            known,
            !topic && tokens.get(index).is_some_and(|s| s == "--help"),
        ) {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::Image(known)),
                operands: &tokens[index + 1..],
            }));
        }
        if let Some(verb) = leaf {
            return BuiltinMatch::Complete(BuiltinLeaf::Image(Leaf {
                verb,
                operands: &tokens[index..],
            }));
        }
        let unknown = known.is_none();
        if unknown || index == tokens.len() {
            let path = if path.is_empty() {
                "image".into()
            } else {
                format!("image {path}")
            };
            if topic {
                return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                    topic: Err(path),
                    operands: &tokens[index..],
                }));
            }
            return BuiltinMatch::Partial(UsageError::ImagePartial { path, unknown });
        }
        if !path.is_empty() {
            path.push(' ');
        }
        path.push_str(&tokens[index].to_string_lossy());
        index += 1;
    }
}

fn allowed(verb: Verb, flag: &str) -> bool {
    use Verb::*;
    match flag {
        "--format" => true,
        "--target" | "--registry" => matches!(verb, Graph | Build | Publish),
        "--platform" | "--build-platform" => matches!(verb, Graph | Build),
        "--staging" => verb == Graph,
        "--builder" | "--refresh" | "--optional-cache-reads" | "--docker-daemon" => verb == Build,
        "--operation" => matches!(verb, Publish | Status),
        "--artifact" => matches!(verb, Publish | Settle),
        "--ambiguity" => verb == Settle,
        "--archive" | "--arm64-emulation" => matches!(verb, BuilderSetup | BuilderReconcile),
        "--purge" => verb == BuilderRemove,
        "--non-interactive" => matches!(verb, Build | Publish) || verb.builder(),
        _ => false,
    }
}

fn boolean(flag: &str) -> bool {
    matches!(
        flag,
        "--refresh"
            | "--optional-cache-reads"
            | "--non-interactive"
            | "--arm64-emulation"
            | "--purge"
    )
}

fn valid(flag: &str, value: &str) -> bool {
    match flag {
        "--target" | "--builder" | "--registry" | "<builder>" => valid_name(value),
        "--platform" | "--build-platform" => valid_platform(value),
        "--operation" | "<operation-id>" => command::valid_operation_id(value),
        "--artifact" | "<artifact-id>" => command::valid_artifact_id(value),
        "--archive" | "--docker-daemon" => command::valid_operand_path(Path::new(value)),
        "--format" => matches!(value, "table" | "json"),
        "--staging" => matches!(value, "metadata" | "content"),
        "--ambiguity" => {
            !value.is_empty()
                && value.len() <= 9
                && value.bytes().all(|b| b.is_ascii_digit())
                && (value == "0" || !value.starts_with('0'))
        }
        _ => boolean(flag),
    }
}

fn parse(verb: Verb, tokens: &[OsString]) -> Result<Invocation, UsageError> {
    let mut flags: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut operands = Vec::new();
    let (mut index, mut ended) = (0, false);
    while let Some(token) = tokens.get(index) {
        index += 1;
        if !ended && token == "--" {
            ended = true;
            continue;
        }
        if !ended && token.as_encoded_bytes().starts_with(b"-") {
            let flag = token.to_str().unwrap_or("");
            if !allowed(verb, flag) {
                return Err(UsageError::ImageUnknownOption {
                    path: verb.name().into(),
                    token: token.to_string_lossy().into_owned(),
                });
            }
            let repeatable = matches!(verb, Verb::Graph | Verb::Build)
                && matches!(flag, "--target" | "--platform" | "--registry");
            if flags.contains_key(flag) && !repeatable {
                return Err(UsageError::ImageRepeatedOption {
                    option: flag.into(),
                });
            }
            let value = if boolean(flag) {
                String::new()
            } else {
                let token = tokens
                    .get(index)
                    .filter(|s| !s.as_encoded_bytes().starts_with(b"--"))
                    .ok_or_else(|| UsageError::ImageMissingValue {
                        option: flag.into(),
                    })?;
                index += 1;
                let value = token.to_str().filter(|s| valid(flag, s)).ok_or_else(|| {
                    UsageError::ImageInvalidValue {
                        option: flag.into(),
                        value: token.to_string_lossy().into_owned(),
                    }
                })?;
                value.to_owned()
            };
            let values = flags.entry(flag).or_default();
            if values.contains(&value) {
                return Err(UsageError::ImageRepeatedOption {
                    option: flag.into(),
                });
            }
            values.push(value);
        } else {
            operands.push(token);
        }
    }
    let operand_kind = match verb {
        Verb::RecordShow => Some("<artifact-id>"),
        Verb::Resume | Verb::Settle => Some("<operation-id>"),
        v if v.builder() => Some("<builder>"),
        _ => None,
    };
    let missing = |operand: &str| UsageError::ImageMissingOperand {
        path: verb.name().into(),
        operand: operand.into(),
    };
    let operand = if let Some(kind) = operand_kind {
        let token = operands.first().ok_or_else(|| missing(kind))?;
        Some(
            token
                .to_str()
                .filter(|s| valid(kind, s))
                .ok_or_else(|| UsageError::ImageInvalidValue {
                    option: kind.into(),
                    value: token.to_string_lossy().into_owned(),
                })?
                .to_owned(),
        )
    } else {
        None
    };
    if let Some(extra) = operands.get(usize::from(operand_kind.is_some())) {
        return Err(UsageError::ImageUnexpectedOperand {
            path: verb.name().into(),
            token: extra.to_string_lossy().into_owned(),
        });
    }
    let required: &[&str] = match verb {
        Verb::Graph => &["--target"],
        Verb::Build => &["--target", "--builder"],
        Verb::Publish => &["--target", "--operation"],
        Verb::Settle => &["--ambiguity", "--artifact"],
        Verb::BuilderSetup | Verb::BuilderReconcile => &["--archive"],
        _ => &[],
    };
    for flag in required {
        if !flags.contains_key(flag) {
            return Err(missing(flag));
        }
    }
    let one = |flag: &str| flags.get(flag).map(|v| v[0].clone());
    Ok(Invocation {
        verb,
        format: if one("--format").as_deref() == Some("json") {
            Format::Json
        } else {
            Format::Table
        },
        targets: flags.get("--target").cloned().unwrap_or_default(),
        platforms: flags.get("--platform").cloned(),
        registries: flags.get("--registry").cloned(),
        builder: if verb.builder() {
            operand.clone()
        } else {
            one("--builder")
        },
        operation: if matches!(verb, Verb::Resume | Verb::Settle) {
            operand.clone()
        } else {
            one("--operation")
        },
        artifact: if verb == Verb::RecordShow {
            operand
        } else {
            one("--artifact")
        },
        build_platform: one("--build-platform"),
        content_staging: one("--staging").as_deref() == Some("content"),
        archive: one("--archive").map(Into::into),
        docker_daemon: one("--docker-daemon").map(Into::into),
        ambiguity: one("--ambiguity").map(|v| v.parse().expect("validated sequence")),
        refresh: flags.contains_key("--refresh"),
        optional_cache_reads: flags.contains_key("--optional-cache-reads"),
        non_interactive: flags.contains_key("--non-interactive"),
        arm64_emulation: flags.contains_key("--arm64-emulation"),
        purge: flags.contains_key("--purge"),
    })
}

pub(super) fn dispatch(
    leaf: Leaf<'_>,
    context: &Context<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let invocation = match parse(leaf.verb, leaf.operands) {
        Ok(invocation) => invocation,
        Err(error) => return super::usage(stderr, &error),
    };
    let inputs = command::Inputs {
        cwd: context.cwd,
        environment: if leaf.verb.dispatching() {
            super::ambient_broil_env(context.env_snapshot)
        } else {
            None
        },
        env_snapshot: context.env_snapshot,
        credentials: context.credentials.take(),
    };
    match command::run(context.project, invocation, inputs, Cancellation::default()) {
        Ok(output) => {
            if stdout
                .write_all(&output.payload)
                .and_then(|()| stdout.flush())
                .is_err()
            {
                super::report(stderr, &command::Error::output_write(), 1);
                return 1;
            }
            if let Some(diagnostic) = output.diagnostic {
                super::report(stderr, &diagnostic, 1);
            }
            output.status
        }
        Err(error) => {
            super::report(stderr, &error, 1);
            1
        }
    }
}
