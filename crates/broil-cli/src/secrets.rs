// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{BuiltinLeaf, BuiltinMatch, Context, HelpLeaf};
use broil_command::{
    help,
    secrets::{self as command, ExportFormat, Options, Verb},
};
use broil_core::{
    error::UsageError,
    secrets::{valid_component, valid_key, valid_set},
};
use std::{collections::BTreeMap, ffi::OsString, io::Write};

pub(super) struct Leaf<'a> {
    pub verb: Verb,
    pub operands: &'a [OsString],
}

fn group(path: &str) -> Option<&'static str> {
    match path {
        "" => Some(""),
        "user" => Some("user"),
        "vault" => Some("vault"),
        "rotate" => Some("rotate"),
        _ => None,
    }
}
fn public_path(path: &str) -> String {
    command::public_name(path)
}
pub(super) fn resolve(tokens: &[OsString], topic: bool) -> BuiltinMatch<'_> {
    let (mut path, mut index) = (String::new(), 0);
    loop {
        let leaf = Verb::named(&path);
        let known = group(&path).or_else(|| leaf.map(Verb::name));
        if topic && (leaf.is_some() || index == tokens.len()) {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: known
                    .map(help::Topic::Secrets)
                    .ok_or_else(|| format!("secrets {}", public_path(&path))),
                operands: &tokens[index..],
            }));
        }
        if let (Some(known), true) = (
            known,
            tokens.get(index).is_some_and(|s| s == "--help") && !topic,
        ) {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::Secrets(known)),
                operands: &tokens[index + 1..],
            }));
        }
        if let Some(verb) = leaf {
            return BuiltinMatch::Complete(BuiltinLeaf::Secrets(Leaf {
                verb,
                operands: &tokens[index..],
            }));
        }
        let unknown = known.is_none();
        if unknown || index == tokens.len() {
            let path = if path.is_empty() {
                "secrets".into()
            } else {
                format!("secrets {}", public_path(&path))
            };
            if topic {
                return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                    topic: Err(path),
                    operands: &tokens[index..],
                }));
            }
            return BuiltinMatch::Partial(UsageError::SecretsPartial { path, unknown });
        }
        if !path.is_empty() {
            path.push(' ');
        }
        path.push_str(&tokens[index].to_string_lossy());
        index += 1;
    }
}

pub(super) fn dispatch(
    leaf: Leaf<'_>,
    context: &Context<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let options = match parse(leaf.verb, leaf.operands) {
        Ok(options) => options,
        Err(class) => return command::failure(leaf.verb, stderr, class, 2),
    };
    command::run(
        leaf.verb,
        &options,
        command::Invocation {
            config: &context.project.config,
            root: &context.project.broil_root,
            cwd: context.cwd,
            environment: super::ambient_broil_env(context.env_snapshot),
            env_snapshot: context.env_snapshot,
            explicit_file: context.explicit_file,
        },
        context.credentials.take(),
        stdout,
        stderr,
    )
}

fn allowed(verb: Verb, flag: &str) -> bool {
    use Verb::*;
    match flag {
        "--non-interactive" => true,
        "--quiet" => verb.writes_store(),
        "--set" => matches!(
            verb,
            Get | List
                | Set
                | Edit
                | Export
                | Check
                | Sync
                | Rekey
                | RotateNew
                | RotateResume
                | RotateStatus
                | RotateRollback
                | RotateCleanup
                | RotateClearPrevious
        ),
        "--all" => matches!(verb, Check | Sync | Rekey | RotateStatus),
        "--local" => matches!(verb, Get | List | Export | Check),
        "--plain" | "--json" => verb == Get,
        "--slots" => verb == List,
        "--format" => verb == Export,
        "--identity" => verb == Init,
        "--team" => verb == UserAdd,
        "--machine" => matches!(verb, UserAdd | UserRotate),
        "--yes" => matches!(verb, UserRemove | VaultReconcile),
        "--generator" | "--type" | "--keep-previous" => verb == RotateNew,
        "--force" => matches!(verb, RotateResume | RotateRollback | RotateCleanup),
        _ => false,
    }
}
pub fn parse(verb: Verb, tokens: &[OsString]) -> Result<Options, &'static str> {
    let mut flags = BTreeMap::new();
    let mut operands = Vec::new();
    let (mut index, mut ended) = (0, false);
    while index < tokens.len() {
        let value = tokens[index].to_str().ok_or("non-UTF-8 syntax")?;
        index += 1;
        if !ended && value == "--" {
            ended = true;
            if verb == Verb::VaultExec {
                if !operands.is_empty() {
                    return Err("unexpected operand before child separator");
                }
                if index == tokens.len() {
                    return Err("child argv required");
                }
                return Ok(Options {
                    non_interactive: flags.contains_key("--non-interactive"),
                    child: tokens[index..].to_vec(),
                    ..Options::default()
                });
            }
            continue;
        }
        if !ended && value.starts_with('-') {
            if !allowed(verb, value) {
                return Err("unknown option");
            }
            if flags.contains_key(value) {
                return Err("repeated option");
            }
            let argument = if matches!(
                value,
                "--set" | "--format" | "--identity" | "--team" | "--generator" | "--type"
            ) {
                let arg = tokens
                    .get(index)
                    .and_then(|s| s.to_str())
                    .ok_or("option value required")?;
                if arg.is_empty() || (value != "--set" && arg.starts_with("--")) {
                    return Err("option value required");
                }
                index += 1;
                arg
            } else {
                ""
            };
            flags.insert(value, argument);
        } else {
            operands.push(value);
        }
    }
    use Verb::*;
    if verb == VaultExec {
        return Err("child separator required");
    }
    let range = match verb {
        Get | Set | UserAdd | UserRemove | UserRotate | RotateNew | RotateResume
        | RotateRollback | RotateCleanup | RotateClearPrevious => 1..=1,
        UserRename => 2..=2,
        RotateStatus => 0..=1,
        _ => 0..=0,
    };
    if !range.contains(&operands.len()) {
        return Err("invalid operands");
    }
    if flags.contains_key("--set") && flags.contains_key("--all")
        || flags.contains_key("--plain") && flags.contains_key("--json")
    {
        return Err("conflicting options");
    }
    for required in match verb {
        UserAdd => &["--team"][..],
        RotateNew => &["--generator"][..],
        RotateCleanup => &["--force"][..],
        _ => &[],
    } {
        if !flags.contains_key(required) {
            return Err("required option missing");
        }
    }
    if flags.get("--set").is_some_and(|s| !valid_set(s, false)) {
        return Err("invalid set selector");
    }
    for name in ["--identity", "--team", "--type"] {
        if flags.get(name).is_some_and(|s| !valid_component(s)) {
            return Err("invalid name");
        }
    }
    if let Some(generator) = flags.get("--generator") {
        let valid = matches!(*generator, "ssh-ed25519" | "prompt" | "handler")
            || generator.split_once(':').is_some_and(|(kind, count)| {
                !count.starts_with('0')
                    && count.bytes().all(|b| b.is_ascii_digit())
                    && count.parse::<usize>().is_ok_and(|n| {
                        n > 0
                            && match kind {
                                "hex" => n.checked_mul(2).is_some_and(|size| size <= 1024 * 1024),
                                "base64" => n
                                    .checked_add(2)
                                    .and_then(|n| (n / 3).checked_mul(4))
                                    .is_some_and(|size| size <= 1024 * 1024),
                                _ => false,
                            }
                    })
            });
        if !valid || (*generator == "handler" && !flags.contains_key("--type")) {
            return Err("invalid generator");
        }
    }
    for operand in &operands {
        if matches!(verb, UserAdd | UserRemove | UserRotate | UserRename) {
            if !valid_component(operand) {
                return Err("invalid name");
            }
        } else if !valid_key(operand) {
            return Err("invalid key");
        }
    }
    let format = match flags.get("--format").copied().unwrap_or("sh") {
        "sh" => ExportFormat::Sh,
        "env" => ExportFormat::Env,
        "json" => ExportFormat::Json,
        _ => return Err("invalid export format"),
    };
    Ok(Options {
        key: operands.first().map(|s| s.to_string()),
        set: flags.get("--set").map(|s| s.to_string()),
        all: flags.contains_key("--all"),
        local: flags.contains_key("--local"),
        non_interactive: flags.contains_key("--non-interactive"),
        json: flags.contains_key("--json"),
        slots: flags.contains_key("--slots"),
        format,
        quiet: flags.contains_key("--quiet"),
        identity: flags.get("--identity").map(|s| s.to_string()),
        team: flags.get("--team").map(|s| s.to_string()),
        machine: flags.contains_key("--machine"),
        yes: flags.contains_key("--yes"),
        new_name: operands.get(1).map(|s| s.to_string()),
        child: Vec::new(),
        generator: flags.get("--generator").map(|s| s.to_string()),
        handler_type: flags.get("--type").map(|s| s.to_string()),
        keep_previous: flags.contains_key("--keep-previous"),
        force: flags.contains_key("--force"),
    })
}
