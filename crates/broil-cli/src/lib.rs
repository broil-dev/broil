// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub mod alias;
mod image;
mod k3s;
pub mod secrets;

use broil_core::secret::environment::CredentialInputs;
use std::cell::RefCell;

use broil_command::{execenv, executable, get, help, remote, version};
use broil_config::{LoadMode, LoadedProject};
use broil_core::error::{GetError, UsageError};

pub fn run() -> ExitCode {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    if let Some(code) = try_dispatch_config_independent(&args, &mut stdout, &mut stderr) {
        return ExitCode::from(code as u8);
    }

    let (env_snapshot, credentials) = CredentialInputs::capture(env::vars_os());
    let cwd = match env::current_dir() {
        Ok(cwd) => cwd,
        Err(error) => {
            if let Some(verb) = selected_secrets(&args) {
                return ExitCode::from(broil_command::secrets::failure(
                    verb,
                    &mut stderr,
                    "current directory",
                    1,
                ) as u8);
            }
            let _ = writeln!(
                stderr,
                "broil: cannot determine the current directory: {error}"
            );
            return ExitCode::from(1);
        }
    };
    let code = run_protected(
        &args,
        &cwd,
        &env_snapshot,
        credentials,
        &mut stdout,
        &mut stderr,
    );
    ExitCode::from(code as u8)
}

pub fn run_with(
    args: &[OsString],
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if let Some(code) = try_dispatch_config_independent(args, stdout, stderr) {
        return code;
    }
    let credentials = CredentialInputs::borrowed(env_snapshot);
    let ordinary = broil_core::secret::environment::ordinary_snapshot(env_snapshot);
    run_protected(args, cwd, &ordinary, credentials, stdout, stderr)
}

fn run_protected(
    args: &[OsString],
    cwd: &Path,
    env_snapshot: &[(OsString, OsString)],
    credentials: CredentialInputs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if let Some(code) = try_dispatch_config_independent(args, stdout, stderr) {
        return code;
    }

    let mut index = 0;
    let mut explicit_file: Option<PathBuf> = None;
    while index < args.len() && args[index] == "--file" {
        match args.get(index + 1) {
            Some(value) => {
                explicit_file = Some(PathBuf::from(value.clone()));
                index += 2;
            }
            None => {
                index += 1;
            }
        }
    }

    let Some(command) = args.get(index) else {
        return usage(stderr, &UsageError::AbsentCommand);
    };
    let tokens = &args[index..];
    let builtin = resolve_builtin(tokens);

    let explicit_file_used = explicit_file.is_some();
    let mode = match explicit_file {
        Some(path) => LoadMode::ExplicitFile {
            path,
            cwd: cwd.to_path_buf(),
        },
        None => LoadMode::Discover {
            cwd: cwd.to_path_buf(),
        },
    };
    let project = match broil_config::load(&mode) {
        Ok(project) => project,
        Err(error) => {
            if let BuiltinMatch::Complete(BuiltinLeaf::Secrets(leaf)) = &builtin {
                return broil_command::secrets::failure(
                    leaf.verb,
                    stderr,
                    "configuration",
                    error.class().exit_code(),
                );
            }
            return report(stderr, &error, error.class().exit_code());
        }
    };

    let context = Context {
        project: &project,
        explicit_file: explicit_file_used,
        cwd,
        env_snapshot,
        credentials: RefCell::new(credentials),
    };

    let builtin_partial = match builtin {
        BuiltinMatch::Complete(leaf) => {
            return dispatch_builtin(leaf, &context, stdout, stderr);
        }
        BuiltinMatch::Partial(error) => Some(error),
        BuiltinMatch::NoMatch => None,
    };

    let map = alias::active_map(&project.config, ambient_broil_env(env_snapshot));
    let alias_partial = match alias::resolve(&map, &args[index..]) {
        alias::Resolution::NoMatch => None,
        alias::Resolution::Complete(expanded) => {
            return dispatch_expanded(&expanded, &context, stdout, stderr);
        }
        alias::Resolution::Partial(error) => Some(error),
    };

    if let Some(code) = try_executable(tokens, &context, stderr) {
        return code;
    }

    if let Some(error) = builtin_partial.as_ref().or(alias_partial.as_ref()) {
        usage(stderr, error)
    } else {
        usage(
            stderr,
            &UsageError::UnknownCommand {
                token: command.to_string_lossy().into_owned(),
            },
        )
    }
}

fn try_dispatch_config_independent(
    args: &[OsString],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Option<i32> {
    if args.is_empty() {
        return Some(write_builtin_payload(
            stdout,
            stderr,
            help::render(help::Topic::General),
        ));
    }

    let mut index = 0;
    while index < args.len() && args[index] == "--file" {
        index += if args.get(index + 1).is_some() { 2 } else { 1 };
    }
    if index == args.len() {
        return None;
    }

    match resolve_builtin(&args[index..]) {
        BuiltinMatch::Complete(leaf) if leaf.is_config_independent() => {
            Some(dispatch_config_independent(&leaf, stdout, stderr))
        }
        BuiltinMatch::Complete(_) | BuiltinMatch::Partial(_) | BuiltinMatch::NoMatch => None,
    }
}

struct Context<'a> {
    project: &'a LoadedProject,
    explicit_file: bool,
    cwd: &'a Path,
    env_snapshot: &'a [(OsString, OsString)],
    credentials: RefCell<CredentialInputs>,
}

enum BuiltinMatch<'a> {
    Complete(BuiltinLeaf<'a>),
    Partial(UsageError),
    NoMatch,
}

enum BuiltinLeaf<'a> {
    Run(&'a [OsString]),
    Env(&'a [OsString]),
    Get(GetLeaf<'a>),
    Remote(RemoteLeaf<'a>),
    Secrets(secrets::Leaf<'a>),
    Image(image::Leaf<'a>),
    K3s(k3s::Leaf<'a>),
    Help(HelpLeaf<'a>),
    Version(&'a [OsString]),
}

impl BuiltinLeaf<'_> {
    fn is_config_independent(&self) -> bool {
        matches!(self, Self::Help(_) | Self::Version(_))
    }
}

struct HelpLeaf<'a> {
    topic: Result<help::Topic, String>,
    operands: &'a [OsString],
}

struct GetLeaf<'a> {
    mode: get::OutputMode,
    selector: GetSelector,
    operands: &'a [OsString],
    retained_option_error: Option<UsageError>,
}

struct RemoteLeaf<'a> {
    verb: RemoteVerb,
    operands: &'a [OsString],
}

#[derive(Clone, Copy)]
enum RemoteVerb {
    List,
    Trust,
    Check,
    Stats,
    Ssh,
    Exec,
    Run,
    CopyTo,
    CopyFrom,
    Provision,
}

impl RemoteVerb {
    fn named(value: &OsStr) -> Option<Self> {
        match value.to_str()? {
            "list" => Some(Self::List),
            "trust" => Some(Self::Trust),
            "check" => Some(Self::Check),
            "stats" => Some(Self::Stats),
            "ssh" => Some(Self::Ssh),
            "exec" => Some(Self::Exec),
            "run" => Some(Self::Run),
            "copy-to" => Some(Self::CopyTo),
            "copy-from" => Some(Self::CopyFrom),
            "provision" => Some(Self::Provision),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Trust => "trust",
            Self::Check => "check",
            Self::Stats => "stats",
            Self::Ssh => "ssh",
            Self::Exec => "exec",
            Self::Run => "run",
            Self::CopyTo => "copy-to",
            Self::CopyFrom => "copy-from",
            Self::Provision => "provision",
        }
    }

    fn help_topic(self) -> help::Topic {
        help::Topic::remote_named(self.name()).expect("every remote verb has help")
    }
}

#[derive(Clone, Copy)]
enum GetSelector {
    Root,
    Name,
    Cfg,
}

fn resolve_builtin(tokens: &[OsString]) -> BuiltinMatch<'_> {
    let Some((command, rest)) = tokens.split_first() else {
        return BuiltinMatch::NoMatch;
    };
    if command == "--help" {
        return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
            topic: Ok(help::Topic::General),
            operands: rest,
        }));
    }
    if command == "--version" {
        return BuiltinMatch::Complete(BuiltinLeaf::Version(rest));
    }
    if command == "help" {
        if rest.first().is_some_and(|token| token == "--help") {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::Help),
                operands: &rest[1..],
            }));
        }
        let Some((topic, operands)) = rest.split_first() else {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::General),
                operands: rest,
            }));
        };
        if topic == "secrets" {
            return secrets::resolve(operands, true);
        }
        if topic == "image" {
            return image::resolve(operands, true);
        }
        if topic == "k3s" {
            return k3s::resolve(operands, true);
        }
        if topic == "remote" {
            let Some((verb, trailing)) = operands.split_first() else {
                return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                    topic: Ok(help::Topic::Remote),
                    operands,
                }));
            };
            let topic = verb
                .to_str()
                .and_then(help::Topic::remote_named)
                .ok_or_else(|| format!("remote {}", verb.to_string_lossy()));
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic,
                operands: trailing,
            }));
        }
        let topic = topic
            .to_str()
            .and_then(help::Topic::named)
            .ok_or_else(|| topic.to_string_lossy().into_owned());
        return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf { topic, operands }));
    }
    if command == "version" {
        if rest.first().is_some_and(|token| token == "--help") {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::Version),
                operands: &rest[1..],
            }));
        }
        return BuiltinMatch::Complete(BuiltinLeaf::Version(rest));
    }
    if command == "run" {
        if rest.first().is_some_and(|token| token == "--help") {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::Run),
                operands: &rest[1..],
            }));
        }
        return if rest.is_empty() {
            BuiltinMatch::Partial(UsageError::MissingRunScript)
        } else {
            BuiltinMatch::Complete(BuiltinLeaf::Run(rest))
        };
    }
    if command == "env" {
        if rest.first().is_some_and(|token| token == "--help") {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::Env),
                operands: &rest[1..],
            }));
        }
        return if rest.is_empty() {
            BuiltinMatch::Partial(UsageError::MissingEnvName)
        } else {
            BuiltinMatch::Complete(BuiltinLeaf::Env(rest))
        };
    }
    if command == "get" {
        if rest.first().is_some_and(|token| token == "--help") {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::Get),
                operands: &rest[1..],
            }));
        }
        return resolve_get(rest);
    }
    if command == "secrets" {
        return secrets::resolve(rest, false);
    }
    if command == "image" {
        return image::resolve(rest, false);
    }
    if command == "k3s" {
        return k3s::resolve(rest, false);
    }
    if command == "remote" {
        if rest.first().is_some_and(|token| token == "--help") {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(help::Topic::Remote),
                operands: &rest[1..],
            }));
        }
        let Some((verb, operands)) = rest.split_first() else {
            return BuiltinMatch::Partial(UsageError::RemoteMissingCommand);
        };
        let Some(verb) = RemoteVerb::named(verb) else {
            return BuiltinMatch::Partial(UsageError::RemoteUnknownCommand {
                token: verb.to_string_lossy().into_owned(),
            });
        };
        if operands.first().is_some_and(|token| token == "--help") {
            return BuiltinMatch::Complete(BuiltinLeaf::Help(HelpLeaf {
                topic: Ok(verb.help_topic()),
                operands: &operands[1..],
            }));
        }
        return BuiltinMatch::Complete(BuiltinLeaf::Remote(RemoteLeaf { verb, operands }));
    }
    BuiltinMatch::NoMatch
}

fn resolve_get(tokens: &[OsString]) -> BuiltinMatch<'_> {
    let mut index = 0;
    let mut plain = false;
    let mut json = false;
    let mut retained_option_error = None;

    while let Some(token) = tokens.get(index) {
        if !token.as_encoded_bytes().starts_with(b"--") {
            break;
        }
        let error = if token == "--plain" {
            let error = if plain {
                Some(UsageError::GetRepeatedOutputOption {
                    option: token.to_string_lossy().into_owned(),
                })
            } else if json {
                Some(UsageError::GetCombinedOutputOptions)
            } else {
                None
            };
            plain = true;
            error
        } else if token == "--json" {
            let error = if json {
                Some(UsageError::GetRepeatedOutputOption {
                    option: token.to_string_lossy().into_owned(),
                })
            } else if plain {
                Some(UsageError::GetCombinedOutputOptions)
            } else {
                None
            };
            json = true;
            error
        } else {
            Some(UsageError::GetUnknownOption {
                token: token.to_string_lossy().into_owned(),
            })
        };
        if retained_option_error.is_none() {
            retained_option_error = error;
        }
        index += 1;
    }

    let selector = match tokens.get(index) {
        Some(token) if token == "root" => GetSelector::Root,
        Some(token) if token == "name" => GetSelector::Name,
        Some(token) if token == "cfg" => GetSelector::Cfg,
        Some(token) => {
            return BuiltinMatch::Partial(retained_option_error.unwrap_or_else(|| {
                UsageError::GetUnknownSelector {
                    token: token.to_string_lossy().into_owned(),
                }
            }));
        }
        None => {
            return BuiltinMatch::Partial(
                retained_option_error.unwrap_or(UsageError::GetMissingSelector),
            );
        }
    };

    BuiltinMatch::Complete(BuiltinLeaf::Get(GetLeaf {
        mode: if json {
            get::OutputMode::Json
        } else {
            get::OutputMode::Plain
        },
        selector,
        operands: &tokens[index + 1..],
        retained_option_error,
    }))
}

fn dispatch_builtin(
    leaf: BuiltinLeaf<'_>,
    context: &Context<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if !matches!(
        &leaf,
        BuiltinLeaf::Secrets(_)
            | BuiltinLeaf::Image(_)
            | BuiltinLeaf::K3s(_)
            | BuiltinLeaf::Run(_)
            | BuiltinLeaf::Env(_)
            | BuiltinLeaf::Remote(_)
    ) {
        drop(context.credentials.take());
    }
    match leaf {
        BuiltinLeaf::Secrets(leaf) => secrets::dispatch(leaf, context, stdout, stderr),
        BuiltinLeaf::Image(leaf) => image::dispatch(leaf, context, stdout, stderr),
        BuiltinLeaf::K3s(leaf) => k3s::dispatch(leaf, context, stdout, stderr),
        BuiltinLeaf::Run(rest) => run_run(rest, context, stderr),
        BuiltinLeaf::Env(rest) => run_env(rest, context, stderr),
        BuiltinLeaf::Get(leaf) => run_get(leaf, context.project, stdout, stderr),
        BuiltinLeaf::Remote(leaf) => run_remote(leaf, context, stdout, stderr),
        leaf @ (BuiltinLeaf::Help(_) | BuiltinLeaf::Version(_)) => {
            dispatch_config_independent(&leaf, stdout, stderr)
        }
    }
}

fn dispatch_config_independent(
    leaf: &BuiltinLeaf<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    match leaf {
        BuiltinLeaf::Help(leaf) => {
            let topic = match &leaf.topic {
                Ok(topic) => *topic,
                Err(topic) => {
                    return usage(
                        stderr,
                        &UsageError::UnknownHelpTopic {
                            topic: topic.clone(),
                        },
                    );
                }
            };
            if let Some(extra) = leaf.operands.first() {
                return usage(
                    stderr,
                    &UsageError::UnexpectedOperand {
                        token: extra.to_string_lossy().into_owned(),
                    },
                );
            }
            write_builtin_payload(stdout, stderr, help::render(topic))
        }
        BuiltinLeaf::Version(operands) => {
            if let Some(extra) = operands.first() {
                return usage(
                    stderr,
                    &UsageError::UnexpectedOperand {
                        token: extra.to_string_lossy().into_owned(),
                    },
                );
            }
            write_builtin_payload(stdout, stderr, &version::render())
        }
        BuiltinLeaf::Run(_)
        | BuiltinLeaf::Image(_)
        | BuiltinLeaf::K3s(_)
        | BuiltinLeaf::Env(_)
        | BuiltinLeaf::Get(_)
        | BuiltinLeaf::Remote(_)
        | BuiltinLeaf::Secrets(_) => {
            unreachable!("config-dependent leaf sent to config-independent dispatch")
        }
    }
}

fn write_builtin_payload(stdout: &mut dyn Write, stderr: &mut dyn Write, payload: &[u8]) -> i32 {
    match write_payload(stdout, payload) {
        Ok(()) => 0,
        Err(error) => {
            let message = format!("cannot write to stdout: {error}");
            report(stderr, &message, 1)
        }
    }
}

fn dispatch_expanded(
    expanded: &[OsString],
    context: &Context<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let Some(target) = expanded.first() else {
        unreachable!("expanded alias commands are never empty");
    };
    dispatch_without_alias(
        expanded,
        UsageError::ExpandedAliasTargetUnknown {
            target: target.to_string_lossy().into_owned(),
        },
        context,
        stdout,
        stderr,
    )
}

fn dispatch_without_alias(
    tokens: &[OsString],
    fallback: UsageError,
    context: &Context<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let builtin_partial = match resolve_builtin(tokens) {
        BuiltinMatch::Complete(leaf) => {
            return dispatch_builtin(leaf, context, stdout, stderr);
        }
        BuiltinMatch::Partial(error) => Some(error),
        BuiltinMatch::NoMatch => None,
    };

    if let Some(code) = try_executable(tokens, context, stderr) {
        return code;
    }

    if let Some(error) = builtin_partial.as_ref() {
        usage(stderr, error)
    } else {
        usage(stderr, &fallback)
    }
}

fn ambient_broil_env(env_snapshot: &[(OsString, OsString)]) -> Option<&OsStr> {
    env_snapshot
        .iter()
        .find(|(name, _)| name.as_os_str() == "BROIL_ENV")
        .map(|(_, value)| value.as_os_str())
}

fn try_executable(
    tokens: &[OsString],
    context: &Context<'_>,
    stderr: &mut dyn Write,
) -> Option<i32> {
    match executable::resolve(&context.project.broil_root, tokens) {
        Ok(executable::Resolution::Selected { path, consumed }) => {
            Some(run_executable(&path, &tokens[consumed..], context, stderr))
        }
        Ok(executable::Resolution::NoMatch) => None,
        Ok(executable::Resolution::Usage(error)) => Some(usage(stderr, &error)),
        Err(error) => Some(report(stderr, &error, error.class().exit_code())),
    }
}

fn run_executable(
    path: &Path,
    args: &[OsString],
    context: &Context<'_>,
    stderr: &mut dyn Write,
) -> i32 {
    let active = execenv::select_execution_env(
        context.explicit_file,
        ambient_broil_env(context.env_snapshot),
    );
    match executable::execute_with_inputs(
        path,
        &context.project.broil_root,
        &context.project.config,
        active,
        args,
        context.env_snapshot,
        broil_command::injection::Inputs {
            cwd: context.cwd,
            credentials: context.credentials.take(),
        },
    ) {
        Ok(code) => code,
        Err(error) => report(stderr, &error, error.class().exit_code()),
    }
}

fn run_run(rest: &[OsString], context: &Context<'_>, stderr: &mut dyn Write) -> i32 {
    let Some((script, child_args)) = rest.split_first() else {
        return usage(stderr, &UsageError::MissingRunScript);
    };
    let active = execenv::select_execution_env(
        context.explicit_file,
        ambient_broil_env(context.env_snapshot),
    );
    match broil_command::run::execute_with_inputs(
        &context.project.broil_root,
        &context.project.config,
        active,
        script,
        child_args,
        context.env_snapshot,
        broil_command::injection::Inputs {
            cwd: context.cwd,
            credentials: context.credentials.take(),
        },
    ) {
        Ok(code) => code,
        Err(error) => report(stderr, &error, error.class().exit_code()),
    }
}

fn run_env(rest: &[OsString], context: &Context<'_>, stderr: &mut dyn Write) -> i32 {
    let Some((name, command_tokens)) = rest.split_first() else {
        return usage(stderr, &UsageError::MissingEnvName);
    };
    let project = context.project;
    let cwd = context.cwd;
    let env_snapshot = context.env_snapshot;
    let inputs = broil_command::injection::Inputs {
        cwd,
        credentials: context.credentials.take(),
    };
    let result = if command_tokens.is_empty() {
        broil_command::env::execute_interactive_with_inputs(
            &project.broil_root,
            &project.config,
            name,
            cwd,
            &tmp_parent(env_snapshot),
            env_snapshot,
            inputs,
        )
    } else {
        broil_command::env::execute_one_shot_with_inputs(
            &project.broil_root,
            &project.config,
            name,
            cwd,
            command_tokens,
            env_snapshot,
            inputs,
        )
    };
    match result {
        Ok(code) => code,
        Err(error) => report(stderr, &error, error.class().exit_code()),
    }
}

fn tmp_parent(env_snapshot: &[(OsString, OsString)]) -> PathBuf {
    env_snapshot
        .iter()
        .find(|(name, _)| name.as_os_str() == "TMPDIR")
        .map(|(_, value)| value.as_os_str())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn run_remote(
    leaf: RemoteLeaf<'_>,
    context: &Context<'_>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if matches!(leaf.verb, RemoteVerb::List) {
        drop(context.credentials.take());
        let request = match parse_remote_list(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::list(
            context.project,
            ambient_broil_env(context.env_snapshot),
            &request,
        ) {
            Ok(output) => match write_payload(stdout, &output.payload) {
                Ok(()) => {
                    if output.invalid_plan_count == 0 {
                        0
                    } else {
                        let count = output.invalid_plan_count;
                        let message = if count == 1 {
                            "1 selected machine has an invalid provisioning plan".to_string()
                        } else {
                            format!("{count} selected machines have invalid provisioning plans")
                        };
                        report(stderr, &message, 1)
                    }
                }
                Err(error) => report(stderr, &format!("cannot write to stdout: {error}"), 1),
            },
            Err(remote::ListError::Usage(error)) => usage(stderr, &error),
            Err(remote::ListError::Runtime(error)) => {
                report(stderr, &error, error.class().exit_code())
            }
        };
    }

    if matches!(leaf.verb, RemoteVerb::Trust) {
        let request = match parse_remote_trust(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::trust_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
            stderr,
        ) {
            Ok(output) => match write_payload(stdout, &output.payload) {
                Ok(()) => output.status,
                Err(error) => report(stderr, &format!("cannot write to stdout: {error}"), 1),
            },
            Err(remote::TrustCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::TrustCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    if matches!(leaf.verb, RemoteVerb::Check) {
        let request = match parse_remote_check(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::check_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
        ) {
            Ok(output) => match write_payload(stdout, &output.payload) {
                Ok(()) => output.status,
                Err(error) => report(stderr, &format!("cannot write to stdout: {error}"), 1),
            },
            Err(remote::CheckCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::CheckCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    if matches!(leaf.verb, RemoteVerb::Stats) {
        let request = match parse_remote_stats_args(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::stats_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
        ) {
            Ok(output) => match write_payload(stdout, &output.payload) {
                Ok(()) => output.status,
                Err(error) => report(stderr, &format!("cannot write to stdout: {error}"), 1),
            },
            Err(remote::StatsCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::StatsCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    if matches!(leaf.verb, RemoteVerb::Exec) {
        let request = match parse_remote_exec(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::exec_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
        ) {
            Ok(output) => {
                if let Err(error) = write_payload(stdout, &output.stdout) {
                    return report(stderr, &format!("cannot write to stdout: {error}"), 1);
                }
                if let Err(error) = write_payload(stderr, &output.stderr) {
                    return report(stderr, &format!("cannot write to stderr: {error}"), 1);
                }
                output.status
            }
            Err(remote::ExecCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::ExecCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    if matches!(leaf.verb, RemoteVerb::Ssh) {
        let request = match parse_remote_ssh(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::ssh_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
        ) {
            Ok(output) => output.status,
            Err(remote::SshCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::SshCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    if matches!(leaf.verb, RemoteVerb::Run) {
        let request = match parse_remote_run(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::run_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
        ) {
            Ok(output) => {
                if let Err(error) = write_payload(stdout, &output.stdout) {
                    return report(stderr, &format!("cannot write to stdout: {error}"), 1);
                }
                if let Err(error) = write_payload(stderr, &output.stderr) {
                    return report(stderr, &format!("cannot write to stderr: {error}"), 1);
                }
                output.status
            }
            Err(remote::RunCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::RunCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    if matches!(leaf.verb, RemoteVerb::CopyTo) {
        let request = match parse_remote_copy_to_args(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::copy_to_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
        ) {
            Ok(output) => match write_payload(stdout, &output.payload) {
                Ok(()) => output.status,
                Err(error) => report(stderr, &format!("cannot write to stdout: {error}"), 1),
            },
            Err(remote::TransferCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::TransferCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    if matches!(leaf.verb, RemoteVerb::CopyFrom) {
        let request = match parse_remote_copy_from_args(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::copy_from_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
        ) {
            Ok(output) => match write_payload(stdout, &output.payload) {
                Ok(()) => output.status,
                Err(error) => report(stderr, &format!("cannot write to stdout: {error}"), 1),
            },
            Err(remote::TransferCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::TransferCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    if matches!(leaf.verb, RemoteVerb::Provision) {
        let request = match parse_remote_provision(leaf.operands) {
            Ok(request) => request,
            Err(error) => return usage(stderr, &error),
        };
        return match remote::execute_provision_protected(
            context.project,
            ambient_broil_env(context.env_snapshot),
            context.cwd,
            context.env_snapshot,
            context.credentials.take(),
            &request,
        ) {
            Ok(output) => match write_payload(stdout, &output.payload) {
                Ok(()) => output.status,
                Err(error) => report(stderr, &format!("cannot write to stdout: {error}"), 1),
            },
            Err(remote::ProvisionCommandError::Usage(error)) => usage(stderr, &error),
            Err(error @ remote::ProvisionCommandError::Runtime { .. }) => report(stderr, &error, 1),
        };
    }

    let error = remote::unavailable(
        context.project,
        ambient_broil_env(context.env_snapshot),
        leaf.verb.name(),
    );
    report(stderr, &error, error.class().exit_code())
}

fn parse_remote_ssh(tokens: &[OsString]) -> Result<remote::SshRequest, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut bootstrap = false;
    let mut pty = false;
    let mut no_pty = false;
    let mut known_hosts = None;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--bootstrap" {
            if bootstrap {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--bootstrap".to_string(),
                });
            }
            bootstrap = true;
            index += 1;
        } else if token == "--pty" {
            if pty {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--pty".to_string(),
                });
            }
            pty = true;
            index += 1;
        } else if token == "--no-pty" {
            if no_pty {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--no-pty".to_string(),
                });
            }
            no_pty = true;
            index += 1;
        } else if token == "--known-hosts" {
            set_single_pathless(
                &mut known_hosts,
                tokens.get(index + 1),
                "--known-hosts",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: "ssh".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteUnexpectedOperand {
                verb: "ssh".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        }
    }
    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    if !selectors.all && selectors.machines.is_empty() && selectors.tags.is_empty() {
        return Err(UsageError::RemoteMissingSelector);
    }
    if pty && no_pty {
        return Err(UsageError::RemotePtyConflict);
    }
    let pty = if no_pty {
        remote::PtyRequest::Disable
    } else {
        remote::PtyRequest::Force
    };
    Ok(remote::SshRequest {
        selectors,
        bootstrap,
        pty,
        known_hosts,
    })
}

fn parse_remote_trust(tokens: &[OsString]) -> Result<remote::TrustRequest, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut jump = None;
    let mut known_hosts = None;
    let mut fingerprint = None;
    let mut replace = false;
    let mut report_path = None;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--jump" {
            set_single_pathless(&mut jump, tokens.get(index + 1), "--jump", |value| {
                value.to_string_lossy().into_owned()
            })?;
            index += 2;
        } else if token == "--known-hosts" {
            set_single_pathless(
                &mut known_hosts,
                tokens.get(index + 1),
                "--known-hosts",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token == "--fingerprint" {
            set_single_pathless(
                &mut fingerprint,
                tokens.get(index + 1),
                "--fingerprint",
                |value| value.to_string_lossy().into_owned(),
            )?;
            index += 2;
        } else if token == "--replace" {
            if replace {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--replace".to_string(),
                });
            }
            replace = true;
            index += 1;
        } else if token == "--report" {
            set_single_pathless(
                &mut report_path,
                tokens.get(index + 1),
                "--report",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: "trust".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteUnexpectedOperand {
                verb: "trust".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        }
    }
    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    if jump.is_some()
        && (selectors.all || !selectors.machines.is_empty() || !selectors.tags.is_empty())
    {
        return Err(UsageError::RemoteJumpSelectorConflict);
    }
    if jump.is_none()
        && !selectors.all
        && selectors.machines.is_empty()
        && selectors.tags.is_empty()
    {
        return Err(UsageError::RemoteMissingSelector);
    }
    if let Some(value) = &fingerprint {
        if !valid_sha256_fingerprint(value) {
            return Err(UsageError::RemoteInvalidFingerprint {
                value: value.clone(),
            });
        }
    }
    Ok(remote::TrustRequest {
        selectors,
        jump,
        known_hosts,
        fingerprint,
        replace,
        report: report_path,
    })
}

fn parse_remote_check(tokens: &[OsString]) -> Result<remote::CheckRequest, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut sudo = false;
    let mut output = remote::OutputMode::Table;
    let mut format_seen = false;
    let mut jobs = None;
    let mut fail_fast = false;
    let mut known_hosts = None;
    let mut report_path = None;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--sudo" {
            if sudo {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--sudo".to_string(),
                });
            }
            sudo = true;
            index += 1;
        } else if token == "--fail-fast" {
            if fail_fast {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--fail-fast".to_string(),
                });
            }
            fail_fast = true;
            index += 1;
        } else if token == "--format" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--format".to_string(),
                    })?;
            if format_seen {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--format".to_string(),
                });
            }
            output = if value == "table" {
                remote::OutputMode::Table
            } else if value == "json" {
                remote::OutputMode::Json
            } else {
                return Err(UsageError::RemoteInvalidOptionValue {
                    option: "--format".to_string(),
                    value: value.to_string_lossy().into_owned(),
                });
            };
            format_seen = true;
            index += 2;
        } else if token == "--jobs" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--jobs".to_string(),
                    })?;
            if jobs.is_some() {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--jobs".to_string(),
                });
            }
            jobs = Some(parse_jobs_value(value)?);
            index += 2;
        } else if token == "--known-hosts" {
            set_single_pathless(
                &mut known_hosts,
                tokens.get(index + 1),
                "--known-hosts",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token == "--report" {
            set_single_pathless(
                &mut report_path,
                tokens.get(index + 1),
                "--report",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: "check".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteUnexpectedOperand {
                verb: "check".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        }
    }
    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    if !selectors.all && selectors.machines.is_empty() && selectors.tags.is_empty() {
        return Err(UsageError::RemoteMissingSelector);
    }
    Ok(remote::CheckRequest {
        selectors,
        sudo,
        output,
        jobs,
        fail_fast,
        known_hosts,
        report: report_path,
    })
}

#[doc(hidden)]
pub fn parse_remote_stats_args(tokens: &[OsString]) -> Result<remote::StatsRequest, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut output = remote::OutputMode::Table;
    let mut format_seen = false;
    let mut jobs = None;
    let mut fail_fast = false;
    let mut known_hosts = None;
    let mut report_path = None;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--fail-fast" {
            if fail_fast {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--fail-fast".to_string(),
                });
            }
            fail_fast = true;
            index += 1;
        } else if token == "--format" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--format".to_string(),
                    })?;
            if format_seen {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--format".to_string(),
                });
            }
            output = if value == "table" {
                remote::OutputMode::Table
            } else if value == "json" {
                remote::OutputMode::Json
            } else {
                return Err(UsageError::RemoteInvalidOptionValue {
                    option: "--format".to_string(),
                    value: value.to_string_lossy().into_owned(),
                });
            };
            format_seen = true;
            index += 2;
        } else if token == "--jobs" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--jobs".to_string(),
                    })?;
            if jobs.is_some() {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--jobs".to_string(),
                });
            }
            jobs = Some(parse_jobs_value(value)?);
            index += 2;
        } else if token == "--known-hosts" {
            set_single_pathless(
                &mut known_hosts,
                tokens.get(index + 1),
                "--known-hosts",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token == "--report" {
            set_single_pathless(
                &mut report_path,
                tokens.get(index + 1),
                "--report",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: "stats".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteUnexpectedOperand {
                verb: "stats".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        }
    }
    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    if !selectors.all && selectors.machines.is_empty() && selectors.tags.is_empty() {
        return Err(UsageError::RemoteMissingSelector);
    }
    Ok(remote::StatsRequest {
        selectors,
        output,
        jobs,
        fail_fast,
        known_hosts,
        report: report_path,
    })
}

fn parse_remote_provision(tokens: &[OsString]) -> Result<remote::ProvisionRequest, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut jobs = None;
    let mut fail_fast = false;
    let mut known_hosts = None;
    let mut report_path = None;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--fail-fast" {
            if fail_fast {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--fail-fast".to_string(),
                });
            }
            fail_fast = true;
            index += 1;
        } else if token == "--jobs" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--jobs".to_string(),
                    })?;
            if jobs.is_some() {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--jobs".to_string(),
                });
            }
            jobs = Some(parse_jobs_value(value)?);
            index += 2;
        } else if token == "--known-hosts" {
            set_single_pathless(
                &mut known_hosts,
                tokens.get(index + 1),
                "--known-hosts",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token == "--report" {
            set_single_pathless(
                &mut report_path,
                tokens.get(index + 1),
                "--report",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: "provision".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteUnexpectedOperand {
                verb: "provision".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        }
    }
    validate_remote_selectors(&selectors)?;
    Ok(remote::ProvisionRequest {
        selectors,
        jobs,
        fail_fast,
        known_hosts,
        report: report_path,
    })
}

fn parse_jobs_value(value: &OsString) -> Result<remote::RequestedJobs, UsageError> {
    if value == "all" {
        return Ok(remote::RequestedJobs::All);
    }
    let text = value.to_string_lossy();
    match text.parse::<usize>() {
        Ok(limit) if limit > 0 => Ok(remote::RequestedJobs::Limit(limit)),
        _ => Err(UsageError::RemoteInvalidOptionValue {
            option: "--jobs".to_string(),
            value: text.into_owned(),
        }),
    }
}

fn parse_remote_exec(tokens: &[OsString]) -> Result<remote::ExecRequest, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut pty = false;
    let mut no_pty = false;
    let mut shell = false;
    let mut privilege = None;
    let mut jobs = None;
    let mut fail_fast = false;
    let mut known_hosts = None;
    let mut report_path = None;
    let mut boundary = None;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "--" {
            boundary = Some(index);
            break;
        } else if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--pty" {
            if pty {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--pty".to_string(),
                });
            }
            pty = true;
            index += 1;
        } else if token == "--no-pty" {
            if no_pty {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--no-pty".to_string(),
                });
            }
            no_pty = true;
            index += 1;
        } else if token == "--shell" {
            if shell {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--shell".to_string(),
                });
            }
            shell = true;
            index += 1;
        } else if token == "--privilege" {
            set_single_pathless(
                &mut privilege,
                tokens.get(index + 1),
                "--privilege",
                |value| value.to_string_lossy().into_owned(),
            )?;
            index += 2;
        } else if token == "--fail-fast" {
            if fail_fast {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--fail-fast".to_string(),
                });
            }
            fail_fast = true;
            index += 1;
        } else if token == "--jobs" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--jobs".to_string(),
                    })?;
            if jobs.is_some() {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--jobs".to_string(),
                });
            }
            jobs = Some(parse_jobs_value(value)?);
            index += 2;
        } else if token == "--known-hosts" {
            set_single_pathless(
                &mut known_hosts,
                tokens.get(index + 1),
                "--known-hosts",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token == "--report" {
            set_single_pathless(
                &mut report_path,
                tokens.get(index + 1),
                "--report",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: "exec".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteUnexpectedOperand {
                verb: "exec".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        }
    }

    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    if !selectors.all && selectors.machines.is_empty() && selectors.tags.is_empty() {
        return Err(UsageError::RemoteMissingSelector);
    }
    if pty && no_pty {
        return Err(UsageError::RemotePtyConflict);
    }
    let boundary = boundary.ok_or_else(|| UsageError::RemoteMissingOperandBoundary {
        verb: "exec".to_string(),
    })?;
    let operands = &tokens[boundary + 1..];
    let command = if shell {
        if operands.len() != 1 {
            return Err(UsageError::RemoteShellBodyCardinality);
        }
        remote::ExecCommand::Shell(operands[0].as_encoded_bytes().to_vec())
    } else {
        if operands.is_empty() {
            return Err(UsageError::RemoteMissingExecCommand);
        }
        remote::ExecCommand::Argv(
            operands
                .iter()
                .map(|token| token.as_encoded_bytes().to_vec())
                .collect(),
        )
    };
    let pty = if pty {
        remote::PtyRequest::Force
    } else if no_pty {
        remote::PtyRequest::Disable
    } else {
        remote::PtyRequest::Auto
    };
    Ok(remote::ExecRequest {
        selectors,
        pty,
        privilege,
        jobs,
        fail_fast,
        known_hosts,
        report: report_path,
        command,
    })
}

fn parse_remote_run(tokens: &[OsString]) -> Result<remote::RunRequest, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut pty = false;
    let mut no_pty = false;
    let mut jobs = None;
    let mut fail_fast = false;
    let mut known_hosts = None;
    let mut report_path = None;
    let mut boundary = None;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "--" {
            boundary = Some(index);
            break;
        } else if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--pty" {
            if pty {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--pty".to_string(),
                });
            }
            pty = true;
            index += 1;
        } else if token == "--no-pty" {
            if no_pty {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--no-pty".to_string(),
                });
            }
            no_pty = true;
            index += 1;
        } else if token == "--fail-fast" {
            if fail_fast {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--fail-fast".to_string(),
                });
            }
            fail_fast = true;
            index += 1;
        } else if token == "--jobs" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--jobs".to_string(),
                    })?;
            if jobs.is_some() {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--jobs".to_string(),
                });
            }
            jobs = Some(parse_jobs_value(value)?);
            index += 2;
        } else if token == "--known-hosts" {
            set_single_pathless(
                &mut known_hosts,
                tokens.get(index + 1),
                "--known-hosts",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token == "--report" {
            set_single_pathless(
                &mut report_path,
                tokens.get(index + 1),
                "--report",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: "run".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteUnexpectedOperand {
                verb: "run".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        }
    }

    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    if !selectors.all && selectors.machines.is_empty() && selectors.tags.is_empty() {
        return Err(UsageError::RemoteMissingSelector);
    }
    if pty && no_pty {
        return Err(UsageError::RemotePtyConflict);
    }
    let boundary = boundary.ok_or_else(|| UsageError::RemoteMissingOperandBoundary {
        verb: "run".to_string(),
    })?;
    let operands = &tokens[boundary + 1..];
    if operands.is_empty() {
        return Err(UsageError::RemoteMissingRunScript);
    }
    let pty = if pty {
        remote::PtyRequest::Force
    } else if no_pty {
        remote::PtyRequest::Disable
    } else {
        remote::PtyRequest::Auto
    };
    Ok(remote::RunRequest {
        selectors,
        pty,
        jobs,
        fail_fast,
        known_hosts,
        report: report_path,
        script: operands[0].as_encoded_bytes().to_vec(),
        args: operands[1..]
            .iter()
            .map(|token| token.as_encoded_bytes().to_vec())
            .collect(),
    })
}

#[doc(hidden)]
pub fn parse_remote_copy_to_args(tokens: &[OsString]) -> Result<remote::CopyToRequest, UsageError> {
    let parsed = parse_remote_copy_args(tokens, RemoteCopyVerb::CopyTo)?;
    let ParsedRemoteCopy {
        selectors,
        recursive,
        overwrite,
        mode,
        owner,
        privilege,
        jobs,
        fail_fast,
        known_hosts,
        report,
        operands,
    } = parsed;
    Ok(remote::CopyToRequest {
        selectors,
        recursive,
        overwrite,
        mode,
        owner,
        privilege,
        jobs,
        fail_fast,
        known_hosts,
        report,
        source: PathBuf::from(operands[0].clone()),
        destination: operands[1].clone(),
    })
}

#[doc(hidden)]
pub fn parse_remote_copy_from_args(
    tokens: &[OsString],
) -> Result<remote::CopyFromRequest, UsageError> {
    let parsed = parse_remote_copy_args(tokens, RemoteCopyVerb::CopyFrom)?;
    let ParsedRemoteCopy {
        selectors,
        recursive,
        overwrite,
        mode,
        jobs,
        fail_fast,
        known_hosts,
        report,
        operands,
        ..
    } = parsed;
    Ok(remote::CopyFromRequest {
        selectors,
        recursive,
        overwrite,
        mode,
        jobs,
        fail_fast,
        known_hosts,
        report,
        source: operands[0].clone(),
        destination: PathBuf::from(operands[1].clone()),
    })
}

#[derive(Clone, Copy)]
enum RemoteCopyVerb {
    CopyTo,
    CopyFrom,
}

impl RemoteCopyVerb {
    fn name(self) -> &'static str {
        match self {
            Self::CopyTo => "copy-to",
            Self::CopyFrom => "copy-from",
        }
    }

    fn accepts_upload_option(self) -> bool {
        matches!(self, Self::CopyTo)
    }
}

struct ParsedRemoteCopy {
    selectors: remote::Selectors,
    recursive: bool,
    overwrite: bool,
    mode: Option<String>,
    owner: Option<String>,
    privilege: Option<String>,
    jobs: Option<remote::RequestedJobs>,
    fail_fast: bool,
    known_hosts: Option<PathBuf>,
    report: Option<PathBuf>,
    operands: Vec<OsString>,
}

fn parse_remote_copy_args(
    tokens: &[OsString],
    verb: RemoteCopyVerb,
) -> Result<ParsedRemoteCopy, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut recursive = false;
    let mut overwrite = false;
    let mut mode = None;
    let mut owner = None;
    let mut privilege = None;
    let mut jobs = None;
    let mut fail_fast = false;
    let mut known_hosts = None;
    let mut report_path = None;
    let mut boundary = None;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "--" {
            boundary = Some(index);
            break;
        } else if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--recursive" {
            if recursive {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--recursive".to_string(),
                });
            }
            recursive = true;
            index += 1;
        } else if token == "--overwrite" {
            if overwrite {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--overwrite".to_string(),
                });
            }
            overwrite = true;
            index += 1;
        } else if token == "--fail-fast" {
            if fail_fast {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--fail-fast".to_string(),
                });
            }
            fail_fast = true;
            index += 1;
        } else if token == "--jobs" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--jobs".to_string(),
                    })?;
            if jobs.is_some() {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--jobs".to_string(),
                });
            }
            jobs = Some(parse_jobs_value(value)?);
            index += 2;
        } else if token == "--known-hosts" {
            set_single_pathless(
                &mut known_hosts,
                tokens.get(index + 1),
                "--known-hosts",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token == "--report" {
            set_single_pathless(
                &mut report_path,
                tokens.get(index + 1),
                "--report",
                |value| PathBuf::from(value.to_os_string()),
            )?;
            index += 2;
        } else if token == "--mode" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--mode".to_string(),
                    })?;
            if mode.is_some() {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--mode".to_string(),
                });
            }
            if !valid_transfer_mode(value) {
                return Err(UsageError::RemoteInvalidOptionValue {
                    option: "--mode".to_string(),
                    value: value.to_string_lossy().into_owned(),
                });
            }
            mode = Some(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--owner" {
            if !verb.accepts_upload_option() {
                return Err(UsageError::RemoteUnknownOption {
                    verb: verb.name().to_string(),
                    token: "--owner".to_string(),
                });
            }
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--owner".to_string(),
                    })?;
            if owner.is_some() {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--owner".to_string(),
                });
            }
            if !valid_transfer_owner(value) {
                return Err(UsageError::RemoteInvalidOptionValue {
                    option: "--owner".to_string(),
                    value: value.to_string_lossy().into_owned(),
                });
            }
            owner = Some(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--privilege" {
            if !verb.accepts_upload_option() {
                return Err(UsageError::RemoteUnknownOption {
                    verb: verb.name().to_string(),
                    token: "--privilege".to_string(),
                });
            }
            set_single_pathless(
                &mut privilege,
                tokens.get(index + 1),
                "--privilege",
                |value| value.to_string_lossy().into_owned(),
            )?;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: verb.name().to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteMissingOperandBoundary {
                verb: verb.name().to_string(),
            });
        }
    }

    validate_remote_selectors(&selectors)?;
    let boundary = boundary.ok_or_else(|| UsageError::RemoteMissingOperandBoundary {
        verb: verb.name().to_string(),
    })?;
    let operands = &tokens[boundary + 1..];
    if operands.len() != 2 {
        return Err(UsageError::RemoteTransferOperandCardinality {
            verb: verb.name().to_string(),
        });
    }
    Ok(ParsedRemoteCopy {
        selectors,
        recursive,
        overwrite,
        mode,
        owner,
        privilege,
        jobs,
        fail_fast,
        known_hosts,
        report: report_path,
        operands: operands.to_vec(),
    })
}

fn validate_remote_selectors(selectors: &remote::Selectors) -> Result<(), UsageError> {
    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    if !selectors.all && selectors.machines.is_empty() && selectors.tags.is_empty() {
        return Err(UsageError::RemoteMissingSelector);
    }
    Ok(())
}

fn valid_transfer_mode(value: &OsString) -> bool {
    let bytes = value.as_encoded_bytes();
    bytes.len() == 4
        && bytes[0] == b'0'
        && bytes[1..].iter().all(|byte| matches!(byte, b'0'..=b'7'))
}

fn valid_transfer_owner(value: &OsString) -> bool {
    let bytes = value.as_encoded_bytes();
    let Some(colon) = bytes.iter().position(|byte| *byte == b':') else {
        return valid_transfer_owner_component(bytes);
    };
    valid_transfer_owner_component(&bytes[..colon])
        && valid_transfer_owner_component(&bytes[colon + 1..])
}

fn valid_transfer_owner_component(bytes: &[u8]) -> bool {
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    matches!(first, b'A'..=b'Z' | b'a'..=b'z' | b'_')
        && rest.iter().all(
            |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'),
        )
}

fn set_single_pathless<T>(
    slot: &mut Option<T>,
    value: Option<&OsString>,
    option: &str,
    convert: impl FnOnce(&OsString) -> T,
) -> Result<(), UsageError> {
    let value = value.ok_or_else(|| UsageError::RemoteMissingOptionValue {
        option: option.to_string(),
    })?;
    if slot.is_some() {
        return Err(UsageError::RemoteRepeatedOption {
            option: option.to_string(),
        });
    }
    *slot = Some(convert(value));
    Ok(())
}

fn valid_sha256_fingerprint(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("SHA256:") else {
        return false;
    };
    encoded.len() == 43
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
}

fn parse_remote_list(tokens: &[OsString]) -> Result<remote::ListRequest, UsageError> {
    let mut selectors = remote::Selectors::default();
    let mut plan = false;
    let mut output = remote::OutputMode::Table;
    let mut format_seen = false;
    let mut index = 0;
    while let Some(token) = tokens.get(index) {
        if token == "-m" || token == "--machine" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors
                .machines
                .push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "-t" || token == "--tag" {
            let option = token.to_string_lossy().into_owned();
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: option.clone(),
                    })?;
            selectors.tags.push(value.to_string_lossy().into_owned());
            index += 2;
        } else if token == "--all" {
            selectors.all = true;
            index += 1;
        } else if token == "--plan" {
            plan = true;
            index += 1;
        } else if token == "--format" {
            let value =
                tokens
                    .get(index + 1)
                    .ok_or_else(|| UsageError::RemoteMissingOptionValue {
                        option: "--format".to_string(),
                    })?;
            if format_seen {
                return Err(UsageError::RemoteRepeatedOption {
                    option: "--format".to_string(),
                });
            }
            output = if value == "table" {
                remote::OutputMode::Table
            } else if value == "json" {
                remote::OutputMode::Json
            } else {
                return Err(UsageError::RemoteInvalidOptionValue {
                    option: "--format".to_string(),
                    value: value.to_string_lossy().into_owned(),
                });
            };
            format_seen = true;
            index += 2;
        } else if token.as_encoded_bytes().starts_with(b"-") {
            return Err(UsageError::RemoteUnknownOption {
                verb: "list".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        } else {
            return Err(UsageError::RemoteUnexpectedOperand {
                verb: "list".to_string(),
                token: token.to_string_lossy().into_owned(),
            });
        }
    }
    if selectors.all && (!selectors.machines.is_empty() || !selectors.tags.is_empty()) {
        return Err(UsageError::RemoteSelectorConflict);
    }
    Ok(remote::ListRequest {
        selectors,
        plan,
        output,
    })
}

fn run_get(
    leaf: GetLeaf<'_>,
    project: &LoadedProject,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let GetLeaf {
        mode,
        selector,
        operands,
        retained_option_error,
    } = leaf;
    if let Some(error) = retained_option_error {
        return usage(stderr, &error);
    }

    let selector = if matches!(selector, GetSelector::Root | GetSelector::Name) {
        if let Some(extra) = operands.first() {
            return usage(
                stderr,
                &UsageError::GetExtraOperands {
                    token: extra.to_string_lossy().into_owned(),
                },
            );
        }
        if matches!(selector, GetSelector::Root) {
            get::Selector::Root
        } else {
            get::Selector::Name
        }
    } else {
        let Some(operand) = operands.first() else {
            return usage(stderr, &UsageError::GetMissingCfgPath);
        };
        if let Some(extra) = operands.get(1) {
            return usage(
                stderr,
                &UsageError::GetExtraOperands {
                    token: extra.to_string_lossy().into_owned(),
                },
            );
        }
        let lossy = operand.to_string_lossy();
        if lossy.split('.').any(str::is_empty) {
            return usage(
                stderr,
                &UsageError::GetEmptyDotPathSegment {
                    dot_path: lossy.into_owned(),
                },
            );
        }
        match operand.to_str() {
            Some(dot_path) => get::Selector::Cfg {
                dot_path: dot_path.to_string(),
            },
            None => {
                let error = GetError::MissingPath {
                    dot_path: lossy.into_owned(),
                };
                return report(stderr, &error, error.class().exit_code());
            }
        }
    };

    let request = get::Request { mode, selector };
    match get::execute(&project.broil_root, &project.config, &request) {
        Ok(payload) => match write_payload(stdout, &payload) {
            Ok(()) => 0,
            Err(error) => {
                let message = format!("cannot write to stdout: {error}");
                report(stderr, &message, 1)
            }
        },
        Err(error) => report(stderr, &error, error.class().exit_code()),
    }
}

fn write_payload(stdout: &mut dyn Write, payload: &[u8]) -> io::Result<()> {
    stdout.write_all(payload)?;
    stdout.flush()
}

fn report(stderr: &mut dyn Write, message: &dyn fmt::Display, code: i32) -> i32 {
    let _ = writeln!(stderr, "broil: {message}");
    code
}

fn usage(stderr: &mut dyn Write, error: &UsageError) -> i32 {
    report(stderr, error, error.class().exit_code())
}

fn selected_secrets(args: &[OsString]) -> Option<broil_command::secrets::Verb> {
    let mut index = 0;
    while args.get(index).is_some_and(|s| s == "--file") {
        index += if args.get(index + 1).is_some() { 2 } else { 1 };
    }
    match resolve_builtin(&args[index..]) {
        BuiltinMatch::Complete(BuiltinLeaf::Secrets(leaf)) => Some(leaf.verb),
        _ => None,
    }
}

