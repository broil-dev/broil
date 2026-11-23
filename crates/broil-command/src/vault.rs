// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    execenv,
    secrets::{Invocation, Options, Verb, failure, public_name},
};
use broil_core::secret::environment::{CredentialInputs, is_credential_input};
use broil_secrets::{
    output,
    read::Selection,
    vault::{Client, Error, Result, Session, session},
};
use std::{ffi::OsStr, io::Write, process::Command, time::Duration};

pub(crate) fn run(
    verb: Verb,
    options: &Options,
    context: Invocation<'_>,
    selected: &Selection,
    mut inputs: CredentialInputs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if verb == Verb::Sync {
        let report = session::sync(selected, options, context.cwd, inputs);
        let mut io_failed = false;
        for set in &report.completed {
            io_failed |= writeln!(stderr, "{}", public_name(set)).is_err();
        }
        io_failed |= stderr.flush().is_err();
        if let Some(error) = report.error {
            return fail(verb, stderr, error);
        }
        if io_failed {
            return failure(verb, stderr, "output I/O", 1);
        }
        return emit(verb, b"ok\n", stdout, stderr);
    }
    if matches!(verb, Verb::VaultStatus | Verb::VaultUnseal) {
        let result = (|| {
            let address = session::address(selected, &mut inputs, true)?;
            let mut client = Client::new(&address)?;
            let mut health = client.health()?;
            if verb == Verb::VaultUnseal {
                if !health.initialized {
                    return Err(Error::runtime(
                        "vault is not initialized; server setup required",
                    ));
                }
                let mut keys = None;
                let mut credential = session::credentials(
                    selected,
                    context.cwd,
                    &mut inputs,
                    options.non_interactive,
                    &mut keys,
                )?;
                drop(keys);
                let key = credential
                    .unseal
                    .take()
                    .ok_or(Error::runtime("unseal key unavailable"))?;
                drop(credential);
                client.unseal(key.as_str())?;
                drop(key);
                health = client.health()?;
                if !health.initialized || health.sealed {
                    return Err(Error::runtime("vault remains sealed or uninitialized"));
                }
                return Ok(b"ok\n".to_vec());
            }
            let reconcile = if health.initialized && !health.sealed {
                broil_secrets::users::reconcile_needed(
                    selected,
                    context.cwd,
                    inputs,
                    client.address(),
                )
            } else {
                None
            };
            Ok(format!(
                "address: {}\ninitialized: {}\nsealed: {}\nreconcile_needed: {}\n",
                public_name(client.address()),
                health.initialized,
                health.sealed,
                match reconcile {
                    Some(true) => "true",
                    Some(false) => "false",
                    None => "unknown",
                }
            )
            .into_bytes())
        })();
        return match result {
            Ok(bytes) => emit(verb, &bytes, stdout, stderr),
            Err(error) => fail(verb, stderr, error),
        };
    }
    let mut keys = None;
    let session = Session::open(
        selected,
        context.cwd,
        &mut inputs,
        options.non_interactive,
        &mut keys,
        true,
    );
    drop(keys);
    drop(inputs);
    let mut session = match session {
        Ok(s) => s,
        Err(error) => return fail(verb, stderr, error),
    };
    if verb == Verb::Login {
        let result = (|| {
            let output = output::prepare(output::MAX_OUTPUT_BYTES, |w| {
                w.text(session.token())?;
                w.text("\n")
            })?;
            stdout
                .write_all(output.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|_| Error::runtime("output I/O"))
        })();
        match result {
            Ok(()) => {
                session.handoff();
                return 0;
            }
            Err(error) => return fail(verb, stderr, session.finish::<()>(Err(error)).unwrap_err()),
        }
    }
    let result = exec(options, context, &mut session);
    let cleanup = session.cleanup();
    match result {
        Ok(status) => {
            if cleanup.is_err() {
                let _ = writeln!(
                    stderr,
                    "broil: secrets vault exec: owned token revocation failed"
                );
            }
            status
        }
        Err(mut error) => {
            error.cleanup_failed = cleanup.is_err();
            fail(verb, stderr, error)
        }
    }
}

fn exec(options: &Options, context: Invocation<'_>, session: &mut Session) -> Result<i32> {
    let (program, args) = options
        .child
        .split_first()
        .ok_or(Error::runtime("child argv required"))?;
    let active = execenv::select_execution_env(context.explicit_file, context.environment);
    let resolved = execenv::resolve(context.config, active)
        .map_err(|_| Error::runtime("execution environment unavailable"))?;
    let mut ordinary = execenv::child_env(context.env_snapshot, &resolved, context.root);
    ordinary.retain(|name, _| !is_credential_input(name));
    session.client.executor.run(async { Ok(()) }, None, false)?;
    let mut child = {
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(context.cwd)
            .env_clear()
            .envs(&ordinary)
            .env("BAO_ADDR", session.client.address())
            .env("BAO_TOKEN", OsStr::new(session.token()));
        drop(ordinary);
        drop(resolved);
        let mut command = tokio::process::Command::from(command);
        command.kill_on_drop(true);
        let _entered = session.client.executor.enter();
        command
            .spawn()
            .map_err(|_| Error::runtime("vault child spawn failed"))?
    };
    session.child_spawned();
    let result = session.client.executor.run(
        async {
            child
                .wait()
                .await
                .map_err(|_| Error::runtime("vault child wait failed"))
        },
        None,
        false,
    );
    let status = match result {
        Ok(status) => status,
        Err(_) => {
            child
                .start_kill()
                .map_err(|_| Error::runtime("vault child termination failed"))?;
            session.client.executor.run(
                async {
                    child
                        .wait()
                        .await
                        .map_err(|_| Error::runtime("vault child reap failed"))
                },
                Some(Duration::from_secs(60)),
                true,
            )?
        }
    };
    execenv::status_code(status).map_err(|_| Error::runtime("vault child status unavailable"))
}
fn emit(verb: Verb, bytes: &[u8], stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    if stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .is_err()
    {
        failure(verb, stderr, "output I/O", 1)
    } else {
        0
    }
}
fn fail(verb: Verb, stderr: &mut dyn Write, error: Error) -> i32 {
    let _ = writeln!(stderr, "broil: secrets {}: {error}", verb.name());
    if verb == Verb::Login {
        let _ = writeln!(stderr, "failure class: {}", error.failure_class());
        error.login_status()
    } else {
        1
    }
}
