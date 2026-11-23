// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    execenv,
    secrets::{self, Invocation, Options, Verb},
};
use broil_core::secret::{
    OwnedSecret,
    environment::{CredentialInputs, is_credential_input},
};
use broil_secrets::{
    read::{Error, Result, Selection},
    rotation::{
        self, Call, Interaction, Kind,
        protocol::{CAPABILITY_LIMIT, CAPTURE_LIMIT, Capture},
    },
    sops::Plaintext,
    store::{Marker, SetId, State},
};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

pub(crate) fn run(
    verb: Verb,
    options: &Options,
    context: Invocation<'_>,
    selected: &Selection,
    inputs: CredentialInputs,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let state_home = match state_home(context.env_snapshot) {
        Ok(path) => path,
        Err(e) => return secrets::failure(verb, stderr, &e.to_string(), 1),
    };
    if verb == Verb::RotateStatus {
        drop(inputs);
        return match rotation::status(selected, options, &state_home) {
            Ok(text) => {
                if stdout
                    .write_all(text.as_bytes())
                    .and_then(|()| stdout.flush())
                    .is_ok()
                {
                    0
                } else {
                    secrets::failure(verb, stderr, "output I/O", 1)
                }
            }
            Err(e) => secrets::failure(verb, stderr, &e.to_string(), 1),
        };
    }
    let kind = match verb {
        Verb::RotateNew => Kind::New,
        Verb::RotateResume => Kind::Resume,
        Verb::RotateRollback => Kind::Rollback,
        Verb::RotateCleanup => Kind::Cleanup,
        _ => Kind::ClearPrevious,
    };
    let mut adapter = Adapter {
        context: &context,
        non_interactive: options.non_interactive,
        stderr,
        handler: None,
        environment: BTreeMap::new(),
        execution: None,
        selected: None,
    };
    let report = rotation::run(
        kind,
        rotation::Request {
            selected,
            options,
            cwd: context.cwd,
            state_home: &state_home,
        },
        inputs,
        &mut adapter,
    );
    secrets::write_report(verb, options.quiet, &report, stderr)
}
fn state_home(env: &[(OsString, OsString)]) -> Result<PathBuf> {
    let get = |name| {
        env.iter()
            .find(|(k, v)| k == name && !v.is_empty())
            .map(|(_, v)| PathBuf::from(v))
    };
    let path = get("XDG_STATE_HOME")
        .or_else(|| get("HOME").map(|p| p.join(".local/state")))
        .ok_or(Error::class("state directory unavailable"))?;
    if !path.is_absolute() {
        return Err(Error::class("state directory must be absolute"));
    }
    Ok(path)
}
struct Adapter<'a, 'b> {
    context: &'a Invocation<'b>,
    non_interactive: bool,
    stderr: &'a mut dyn Write,
    handler: Option<Vec<OsString>>,
    environment: BTreeMap<OsString, OsString>,
    execution: Option<execenv::ResolvedExecution>,
    selected: Option<Selection>,
}
impl Interaction for Adapter<'_, '_> {
    fn configure(
        &mut self,
        marker: &Marker,
        store: &Path,
        set: &SetId,
        key: &str,
        cursor: &Path,
    ) -> Result<Selection> {
        let active = marker.environment.as_deref().map(OsStr::new);
        let selected = Selection::new(self.context.config, self.context.root, active)?;
        let resolved = execenv::resolve(self.context.config, active).map_err(|_| {
            Error::class("recorded environment unavailable; restore configuration before recovery")
        })?;
        let mut env = execenv::child_env(self.context.env_snapshot, &resolved, self.context.root);
        env.retain(|k, _| !is_credential_input(k) && !k.as_bytes().starts_with(b"BROIL_ROTATION_"));
        for (key, value) in [
            ("BROIL_ROTATION_ID", marker.id.as_str()),
            ("BROIL_ROTATION_KEY", key),
            ("BROIL_ROTATION_SET", set.as_str()),
            ("BROIL_ROTATION_PROJECT", selected.project()?),
            ("BROIL_ROTATION_TYPE", marker.handler_type.as_str()),
        ] {
            env.insert(key.into(), value.into());
        }
        env.insert(
            "BROIL_ROTATION_STATE_FILE".into(),
            cursor.as_os_str().into(),
        );
        if self.non_interactive {
            env.insert("BROIL_ROTATION_NON_INTERACTIVE".into(), "1".into());
        }
        if !marker.handler_type.is_empty() {
            let mut args: Vec<OsString> =
                if let Some(args) = selected.config.rotation.handlers.get(&marker.handler_type) {
                    args.iter().map(OsString::from).collect()
                } else {
                    vec![
                        store
                            .join("handlers")
                            .join(&marker.handler_type)
                            .into_os_string(),
                    ]
                };
            let first = args
                .first_mut()
                .ok_or(Error::class("handler argv unavailable"))?;
            *first = executable(first, &env, self.context.root)?.into_os_string();
            self.handler = Some(args);
        }
        self.environment = env;
        self.execution = Some(resolved);
        self.selected = Some(selected.clone());
        Ok(selected)
    }
    fn invoke(
        &mut self,
        marker: &Marker,
        state: State,
        call: Call,
        input: Plaintext,
    ) -> Result<Capture> {
        let args = self
            .handler
            .as_ref()
            .ok_or(Error::class("handler unavailable"))?;
        let mut command = Command::new(&args[0]);
        command.args(&args[1..]);
        if call == Call::Capabilities {
            command.arg("capabilities");
        } else {
            command.arg(state.as_str()).arg(call.as_str());
        }
        command
            .current_dir(self.context.root)
            .env_clear()
            .envs(&self.environment);
        if let Some(note) = &marker.note {
            command.env("BROIL_ROTATION_NOTE", note);
        }
        launch(
            command,
            input,
            if call == Call::Capabilities {
                CAPABILITY_LIMIT
            } else {
                CAPTURE_LIMIT
            },
            self.non_interactive.then_some(Duration::from_secs(300)),
        )
    }
    fn deploy(&mut self, _marker: &Marker) -> Result<bool> {
        let selected = self
            .selected
            .as_ref()
            .ok_or(Error::class("recorded configuration unavailable"))?;
        let Some(name) = &selected.config.rotation.deploy else {
            return Ok(false);
        };
        let body = self
            .execution
            .as_ref()
            .and_then(|e| e.scripts.get(name))
            .ok_or(Error::class("configured deploy script unavailable"))?;
        let mut command = Command::new(executable(
            OsStr::new("bash"),
            &self.environment,
            self.context.root,
        )?);
        command
            .args(["-c", "--", body, "dummy"])
            .current_dir(self.context.root)
            .env_clear()
            .envs(&self.environment);
        launch(
            command,
            Plaintext::copy_from("").map_err(|_| Error::class("allocation"))?,
            CAPTURE_LIMIT,
            self.non_interactive.then_some(Duration::from_secs(300)),
        )?;
        Ok(true)
    }
    fn prompt(&mut self, label: &str, hidden: bool, limit: usize) -> Result<OwnedSecret> {
        if self.non_interactive {
            return Err(Error::class("private terminal input required"));
        }
        broil_core::secret::prompt_private_bounded(label, hidden, limit)
            .map_err(|_| Error::class("terminal input cancelled or unavailable"))
    }
    fn message(&mut self, message: &str) -> Result<()> {
        writeln!(self.stderr, "{message}")
            .and_then(|()| self.stderr.flush())
            .map_err(|_| Error::class("output I/O"))
    }
}
fn executable(name: &OsStr, env: &BTreeMap<OsString, OsString>, root: &Path) -> Result<PathBuf> {
    let good = |path: &Path| {
        std::fs::metadata(path).is_ok_and(|m| m.is_file())
            && rustix::fs::accessat(
                rustix::fs::CWD,
                path,
                rustix::fs::Access::EXEC_OK,
                rustix::fs::AtFlags::EACCESS,
            )
            .is_ok()
    };
    if name.is_empty() || name.as_bytes().contains(&0) {
        return Err(Error::class("handler executable unavailable"));
    }
    if name.as_bytes().contains(&b'/') {
        let path = broil_core::secret::normalize_path(root, Path::new(name));
        return if good(&path) {
            Ok(path)
        } else {
            Err(Error::class("handler executable unavailable"))
        };
    }
    for directory in std::env::split_paths(
        env.get(OsStr::new("PATH"))
            .map(OsString::as_os_str)
            .unwrap_or(OsStr::new("/usr/bin:/bin")),
    ) {
        let path = broil_core::secret::normalize_path(root, &directory).join(name);
        if good(&path) {
            return Ok(path);
        }
    }
    Err(Error::class("handler executable unavailable"))
}
fn launch(
    mut command: Command,
    input: Plaintext,
    limit: usize,
    deadline: Option<Duration>,
) -> Result<Capture> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::class("handler runtime"))?;
    runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| Error::class("handler cancellation setup"))?;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Error::class("handler spawn"))?;
        let mut stdin = child.stdin.take().ok_or(Error::class("handler stdin"))?;
        let mut stdout = child.stdout.take().ok_or(Error::class("handler stdout"))?;
        let work = async {
            let writer = async move {
                let result = stdin.write_all(input.as_bytes()).await;
                drop(input);
                result.map_err(|_| Error::class("handler stdin"))?;
                stdin
                    .shutdown()
                    .await
                    .map_err(|_| Error::class("handler stdin"))
            };
            let reader = async move {
                let mut output = Capture::new(limit)?;
                loop {
                    let count = stdout
                        .read(output.spare())
                        .await
                        .map_err(|_| Error::class("handler stdout"))?;
                    if count == 0 {
                        break;
                    }
                    output.advance(count)?;
                }
                Ok(output)
            };
            let pipes = async {
                let ((), output) = tokio::try_join!(writer, reader)?;
                Ok(output)
            };
            tokio::pin!(pipes);
            let completed = tokio::select! {
                output=&mut pipes=>Some(output?),
                status=child.wait()=>{check_exit(status)?;None},
            };
            if let Some(output) = completed {
                check_exit(child.wait().await)?;
                Ok(output)
            } else {
                tokio::time::timeout(Duration::from_secs(2), &mut pipes)
                    .await
                    .map_err(|_| Error::class("handler retained pipe after exit"))?
            }
        };
        let bound = async {
            if let Some(deadline) = deadline {
                tokio::time::sleep(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let result = tokio::select! {
            result=work=>result,
            _=bound=>Err(Error::class("handler timed out")),
            _=tokio::signal::ctrl_c()=>Err(Error::class("handler cancelled")),
            _=term.recv()=>Err(Error::class("handler cancelled")),
        };
        if result.is_err() {
            let _ = child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
        }
        result
    })
}

fn check_exit(status: std::io::Result<std::process::ExitStatus>) -> Result<()> {
    if status.map_err(|_| Error::class("handler wait"))?.success() {
        Ok(())
    } else {
        Err(Error::class("handler exited unsuccessfully"))
    }
}
