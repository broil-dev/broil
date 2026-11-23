// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result};
use broil_config::LoadedProject;
use broil_core::applications::{Hook, HookLocation};
use serde_json::{Value, json};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub(super) const RENDER_LIMIT: usize = 4_194_304;
const GRACE: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(super) struct Run {
    pub outcome: &'static str,
    pub exit: Option<i32>,
    pub signal: Value,
    pub duration_ms: u64,
    pub output: Option<Vec<u8>>,
}

pub(super) struct Variables<'a> {
    pub target: &'a str,
    pub application: &'a str,
    pub stage: &'static str,
    pub run: Option<(&'a str, &'a str, String)>,
}

impl Variables<'_> {
    fn pairs(&self) -> Vec<(String, String)> {
        let mut pairs = vec![
            ("BROIL_TARGET".to_owned(), self.target.to_owned()),
            ("BROIL_APPLICATION".to_owned(), self.application.to_owned()),
            ("BROIL_HOOK_STAGE".to_owned(), self.stage.to_owned()),
        ];
        if let Some((release, operation, attempt)) = &self.run {
            pairs.push(("BROIL_RELEASE".to_owned(), (*release).to_owned()));
            pairs.push(("BROIL_OPERATION".to_owned(), (*operation).to_owned()));
            pairs.push(("BROIL_HOOK_ATTEMPT".to_owned(), attempt.clone()));
        }
        pairs
    }
}

pub(super) fn location(hook: &Hook) -> &str {
    match &hook.location {
        HookLocation::Controller => "controller",
        HookLocation::Machine(machine) => machine,
    }
}

fn acquire(
    project: &LoadedProject,
    policy: &crate::k3s::Policy,
    hook: &Hook,
) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    if hook.secrets.is_empty() {
        return Ok(Vec::new());
    }
    let selection = broil_secrets::read::Selection::new(
        &project.config,
        &project.broil_root,
        Some(OsStr::new(&policy.environment)),
    )
    .map_err(|_| Failure::Credential)?;
    let token = policy.cancellation.clone();
    let control = broil_secrets::identity::AcquisitionControl::new(
        move || token.is_cancelled(),
        || Box::new(()),
    );
    let mut values = Vec::with_capacity(hook.secrets.len());
    for (variable, reference) in &hook.secrets {
        let scalar = broil_secrets::read::resolve_scalar_with_options(
            &selection,
            &policy.cwd,
            policy
                .credentials
                .try_duplicate()
                .map_err(|_| Failure::Credential)?,
            &reference.key,
            Some(&reference.set),
            &control,
            policy.non_interactive,
        )
        .map_err(|_| {
            if policy.cancellation.is_cancelled() {
                Failure::Cancelled
            } else {
                Failure::Credential
            }
        })?;
        values.push((variable.clone(), scalar.into_bytes()));
    }
    Ok(values)
}

fn controller_environment(
    project: &LoadedProject,
    policy: &crate::k3s::Policy,
    variables: &Variables<'_>,
) -> Result<Vec<(OsString, OsString)>> {
    let resolved = crate::execenv::resolve(&project.config, Some(OsStr::new(&policy.environment)))
        .map_err(|_| Failure::Configuration)?;
    let mut env =
        crate::execenv::child_env(&policy.environment_snapshot, &resolved, &project.broil_root);
    for (name, value) in variables.pairs() {
        env.insert(name.into(), value.into());
    }
    Ok(env.into_iter().collect())
}

pub(super) async fn run(
    project: &LoadedProject,
    policy: &crate::k3s::Policy,
    hook: &Hook,
    variables: &Variables<'_>,
    capture: bool,
) -> Result<Run> {
    let timeout = Duration::from_secs(hook.timeout.seconds);
    match &hook.location {
        HookLocation::Controller => {
            let env = controller_environment(project, policy, variables)?;
            let secrets = acquire(project, policy, hook)?;
            let root = project.broil_root.clone();
            let argv = hook.argv.clone();
            let cancel = policy.cancellation.clone();
            tokio::task::spawn_blocking(move || {
                controller(&argv, root, env, secrets, timeout, capture, &cancel)
            })
            .await
            .map_err(|_| Failure::Integrity)
        }
        HookLocation::Machine(machine) => {
            remote(project, policy, machine, hook, variables, timeout).await
        }
    }
}

fn elapsed(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn controller(
    argv: &[String],
    root: PathBuf,
    env: Vec<(OsString, OsString)>,
    secrets: Vec<(String, Zeroizing<Vec<u8>>)>,
    timeout: Duration,
    capture: bool,
    cancel: &broil_remote::scheduler::CancellationToken,
) -> Run {
    let started = Instant::now();
    let failed = |exit, signal| Run {
        outcome: "failed",
        exit,
        signal,
        duration_ms: elapsed(started),
        output: None,
    };
    let Some(first) = argv.first() else {
        return failed(None, Value::Null);
    };
    let program = if first.starts_with('/') {
        PathBuf::from(first)
    } else {
        root.join(first)
    };
    let mut command = std::process::Command::new(program);
    command
        .args(&argv[1..])
        .env_clear()
        .envs(env)
        .current_dir(&root)
        .stdin(std::process::Stdio::null())
        .stdout(if capture {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stderr(std::process::Stdio::null());
    for (name, value) in &secrets {
        command.env(name, OsStr::from_bytes(value));
    }
    let spawned = command.spawn();
    drop(command);
    drop(secrets);
    let Ok(mut child) = spawned else {
        return failed(None, Value::Null);
    };
    let reader = child.stdout.take().map(|stdout| {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut limited = stdout.take(RENDER_LIMIT as u64 + 1);
            let _ = limited.read_to_end(&mut kept);
            let mut rest = limited.into_inner();
            let _ = std::io::copy(&mut rest, &mut std::io::sink());
            kept
        })
    });
    let deadline = started + timeout;
    let mut terminated: Option<Instant> = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }
        let now = Instant::now();
        if terminated.is_none() && (now >= deadline || cancel.is_cancelled()) {
            let pid = rustix::process::Pid::from_child(&child);
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
            terminated = Some(now);
        } else if terminated.is_some_and(|t| now >= t + GRACE) {
            let _ = child.kill();
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let output = reader.and_then(|r| r.join().ok());
    let duration_ms = elapsed(started);
    match status {
        None => Run {
            outcome: "unknown",
            exit: None,
            signal: Value::Null,
            duration_ms,
            output: None,
        },
        Some(status) => {
            let exit = status.code();
            let signal = status.signal().map_or(Value::Null, |s| json!(s));
            Run {
                outcome: if exit == Some(0) && terminated.is_none() {
                    "succeeded"
                } else {
                    "failed"
                },
                exit,
                signal,
                duration_ms,
                output,
            }
        }
    }
}

async fn remote(
    project: &LoadedProject,
    policy: &crate::k3s::Policy,
    machine: &str,
    hook: &Hook,
    variables: &Variables<'_>,
    timeout: Duration,
) -> Result<Run> {
    let started = Instant::now();
    let inventory = broil_remote::resolve(project, Some(OsStr::new(&policy.environment)))
        .map_err(|_| Failure::Configuration)?;
    let effective = inventory
        .machines
        .iter()
        .find(|m| m.name == machine)
        .ok_or(Failure::Configuration)?;
    let backend = crate::remote::argv_backend(
        project,
        &inventory,
        effective,
        &policy.cwd,
        &policy.environment_snapshot,
        policy
            .credentials
            .try_duplicate()
            .map_err(|_| Failure::Credential)?,
    )
    .ok_or(Failure::Configuration)?;
    let mut argv: Vec<Vec<u8>> = vec![
        b"/usr/bin/env".to_vec(),
        format!("BROIL_ENV={}", policy.environment).into_bytes(),
        format!("BROIL_MACHINE={machine}").into_bytes(),
    ];
    for (name, value) in variables.pairs() {
        argv.push(format!("{name}={value}").into_bytes());
    }
    argv.extend(hook.argv.iter().map(|a| a.as_bytes().to_vec()));
    let result = broil_remote::exec::run_argv(
        &project.broil_root,
        &inventory,
        effective,
        argv,
        backend,
        timeout.as_secs().max(1),
        policy.cancellation.clone(),
    )
    .await;
    let duration_ms = elapsed(started);
    let Ok(result) = result else {
        return Ok(Run {
            outcome: "failed",
            exit: None,
            signal: Value::Null,
            duration_ms,
            output: None,
        });
    };
    let signal = result
        .remote_signal
        .as_ref()
        .map_or(Value::Null, |s| json!(s.name));
    let outcome = if result.remote_status == Some(0) && result.failure_class.is_none() {
        "succeeded"
    } else if result.remote_status.is_some() || result.remote_signal.is_some() {
        "failed"
    } else if !result.dispatched {
        "failed"
    } else {
        "unknown"
    };
    Ok(Run {
        outcome,
        exit: result.remote_status,
        signal,
        duration_ms,
        output: None,
    })
}
