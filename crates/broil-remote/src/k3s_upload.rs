// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::private_staging::Binding;
use super::public_upload::{PublicRead, UploadOutcome};
use super::*;
use crate::transfer::{TransferDirection, TransferJob};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

pub const K3S_INCOMING: &str = "/var/lib/broil-k3s-incoming";

#[derive(Clone, Debug)]
pub struct K3sUploadBinding {
    pub owner: String,
    pub dispatch: String,
    pub binding_sha256: String,
    pub size: u64,
}

impl K3sUploadBinding {
    pub fn directory(&self) -> String {
        format!("{K3S_INCOMING}/{}/{}/data", self.owner, self.dispatch)
    }

    pub fn temporary(&self) -> String {
        format!("{}/upload.tmp", self.directory())
    }

    pub fn destination(&self) -> String {
        format!("{}/received", self.directory())
    }

    fn args(&self) -> Result<Vec<Vec<u8>>, FailureClass> {
        let hex = |text: &str, size: usize| {
            text.len() == size
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !hex(&self.owner, 32)
            || !hex(&self.dispatch, 32)
            || !hex(&self.binding_sha256, 64)
            || self.size == 0
            || self.size > 268_435_456
        {
            return Err(FailureClass::Configuration);
        }
        let args = vec![
            "--broil-k3s-sftp-v1".to_string(),
            self.owner.clone(),
            self.dispatch.clone(),
            self.binding_sha256.clone(),
        ];
        if args.iter().map(|a| a.len() + 1).sum::<usize>() > 256 {
            return Err(FailureClass::Configuration);
        }
        Ok(args.into_iter().map(String::into_bytes).collect())
    }
}

fn helper_ok(result: &RemoteCommand, stdout: &[u8]) -> Result<(), FailureClass> {
    if result.status != Some(0) || result.stdout != stdout || !result.stderr.is_empty() {
        return Err(FailureClass::Protocol);
    }
    Ok(())
}

impl Connection {
    pub async fn upload_k3s(
        mut self,
        job: TransferJob,
        binding: K3sUploadBinding,
        deadline: tokio::time::Instant,
    ) -> Result<UploadOutcome, FailureClass> {
        let args = binding.args()?;
        if self.plan.preparation != Preparation::K3s
            || job.direction != TransferDirection::Upload
            || job.recursive
            || job.overwrite
            || job.privilege.is_some()
            || job.owner.is_some()
            || job.mode.as_deref() != Some("0600")
            || job.machine != self.plan.target.name
            || job.address != self.plan.target.address
            || job.port != self.plan.target.port
            || job.target_alias != self.plan.target.target_alias
            || job.canonical_profile != self.plan.target.canonical_profile
            || job.canonical_user != self.plan.target.canonical_user
            || job.destination != binding.destination().as_bytes()
        {
            return Err(FailureClass::Configuration);
        }
        let staging = Binding::new(&self.plan.target.canonical_user)?;
        let mut outcome = UploadOutcome {
            temporary: binding.temporary(),
            destination: binding.destination(),
            ..UploadOutcome::default()
        };
        let mut staged = false;
        let status = Arc::new(AtomicI32::new(-1));
        let ended = Arc::new(AtomicBool::new(true));
        let mut writer = None;
        let mut raw = None;
        let work = async {
            let mut configured = self.plan.command.clone();
            configured.args = args;
            if !crate::staging::body_has_shebang(&configured.body) {
                return Err(FailureClass::Configuration);
            }
            let launcher = crate::staging::launcher_for_script(
                true,
                configured.interpreter.as_deref(),
                configured.cwd.as_deref(),
                &configured.cwd_nonce,
                &configured.env,
                &configured.args,
            );
            let input = staging.input(&launcher, &configured.body, None)?;
            let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
            outcome.possible_staging_residue = true;
            staged = true;
            let received = run_helper_command(
                &mut self.session,
                &staging.command("receive", None),
                Some(input),
                remaining(),
                true,
                true,
                &self.cancel,
            )
            .await
            .map_err(|e| e.class)?;
            helper_ok(&received, format!("{}\n", staging.launcher).as_bytes())?;
            let armed = run_helper_command(
                &mut self.session,
                &staging.command("arm", Some("1".into())),
                None,
                remaining(),
                true,
                true,
                &self.cancel,
            )
            .await
            .map_err(|e| e.class)?;
            helper_ok(&armed, b"")?;
            let milliseconds = remaining().as_millis().clamp(1, 7_200_000);
            let mut channel = self
                .session
                .channel_open_session()
                .await
                .map_err(|_| FailureClass::Protocol)?;
            outcome.launcher_dispatched = true;
            channel
                .exec(
                    true,
                    staging
                        .command("use-public", Some(milliseconds.to_string()))
                        .into_bytes(),
                )
                .await
                .map_err(|_| FailureClass::Protocol)?;
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Success) => break,
                    Some(ChannelMsg::WindowAdjusted { .. }) => {}
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        status.store(i32::try_from(exit_status).unwrap_or(-2), Ordering::Release);
                        return Err(FailureClass::Protocol);
                    }
                    _ => return Err(FailureClass::Protocol),
                }
            }
            let (read, write) = channel.split();
            ended.store(false, Ordering::Release);
            let stream = tokio::io::join(
                PublicRead {
                    channel: read,
                    buffered: vec![],
                    offset: 0,
                    total: 0,
                    status: status.clone(),
                    ended: ended.clone(),
                },
                write.make_writer(),
            );
            writer = Some(write);
            let (sftp, extensions) =
                crate::transfer_sftp::initialize_raw_sftp_session(stream, remaining())
                    .await
                    .map_err(|_| FailureClass::Sftp)?;
            raw = Some(sftp);
            outcome.mutation_dispatched = true;
            let result = crate::transfer_sftp::k3s_upload_reserved(
                raw.as_ref().ok_or(FailureClass::Protocol)?,
                &job,
                &extensions,
                &outcome.temporary,
                binding.size,
                &self.cancel,
            )
            .await;
            outcome.transfer_complete = result.is_ok();
            result
        };
        let result = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(FailureClass::Cancellation),
            result = tokio::time::timeout_at(deadline, work) => result.unwrap_or(Err(FailureClass::IndeterminateAfterDispatch)),
        };
        outcome.failure = result.err();
        let until = tokio::time::Instant::now() + CANCEL_CLEANUP_TIMEOUT;
        if let Some(raw) = raw {
            let _ = raw.close_session();
        }
        let _ = tokio::time::timeout_at(until, async {
            if let Some(writer) = writer {
                let _ = writer.eof().await;
                let _ = writer.close().await;
            }
            if staged {
                let cleaned = run_helper_command(
                    &mut self.session,
                    &staging.command("cleanup", None),
                    None,
                    until.saturating_duration_since(tokio::time::Instant::now()),
                    true,
                    true,
                    &CancellationToken::default(),
                )
                .await
                .map_err(|e| e.class)?;
                outcome.possible_staging_residue = helper_ok(&cleaned, b"").is_err();
            }
            while !ended.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            Ok::<(), FailureClass>(())
        })
        .await;
        let _ = tokio::time::timeout_at(
            until,
            self.session
                .disconnect(russh::Disconnect::ByApplication, "", ""),
        )
        .await;
        let session_ended = tokio::time::timeout_at(until, &mut self.session)
            .await
            .is_ok();
        outcome.unresolved_session = !ended.load(Ordering::Acquire) || !session_ended;
        outcome.remote_status = match status.load(Ordering::Acquire) {
            n if n >= 0 => Some(n),
            _ => None,
        };
        if !outcome.mutation_dispatched {
            outcome.failure = match outcome.remote_status {
                Some(76) => Some(FailureClass::TransferPathSafety),
                Some(77) => Some(FailureClass::Sftp),
                Some(125) => Some(FailureClass::Configuration),
                _ => outcome.failure,
            };
        }
        if outcome.unresolved_session || outcome.possible_staging_residue {
            outcome
                .failure
                .get_or_insert(FailureClass::IndeterminateAfterDispatch);
        }
        Ok(outcome)
    }
}
