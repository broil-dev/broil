// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::transfer::{TransferDirection, TransferJob};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};

#[derive(Clone, Debug)]
pub struct UploadBinding {
    pub owner: String,
    pub operation: String,
    pub step: u64,
    pub scope: String,
    pub device: u64,
    pub inode: u64,
    pub purpose: String,
    pub size: u64,
    pub sha256: String,
}

impl UploadBinding {
    pub fn directory(&self) -> String {
        format!(
            "/var/lib/broil/builders/{}/incoming/{}",
            self.owner, self.step
        )
    }

    pub fn destination(&self) -> String {
        format!("{}/{}", self.directory(), self.purpose)
    }

    fn args(&self) -> Result<Vec<Vec<u8>>, FailureClass> {
        let hex = |text: &str, size: usize| {
            text.len() == size
                && text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !hex(&self.owner, 32)
            || !hex(&self.operation, 32)
            || !hex(&self.scope, 64)
            || !hex(&self.sha256, 64)
            || self.step == 0
            || self.inode == 0
            || !matches!(self.purpose.as_str(), "archive" | "ca")
            || self.size == 0
            || self.size
                > if self.purpose == "ca" {
                    1_048_576
                } else {
                    268_435_456
                }
        {
            return Err(FailureClass::Configuration);
        }
        Ok(vec![
            "--broil-builder-sftp-v1".into(),
            self.owner.clone(),
            self.operation.clone(),
            self.step.to_string(),
            self.scope.clone(),
            self.device.to_string(),
            self.inode.to_string(),
            self.purpose.clone(),
            "upload.tmp".into(),
            self.purpose.clone(),
            self.size.to_string(),
            self.sha256.clone(),
        ]
        .into_iter()
        .map(String::into_bytes)
        .collect())
    }
}

#[derive(Debug, Default)]
pub struct UploadOutcome {
    pub failure: Option<FailureClass>,
    pub launcher_dispatched: bool,
    pub mutation_dispatched: bool,
    pub transfer_complete: bool,
    pub remote_status: Option<i32>,
    pub possible_staging_residue: bool,
    pub unresolved_session: bool,
    pub temporary: String,
    pub destination: String,
}

pub(super) struct PublicRead {
    pub(super) channel: russh::ChannelReadHalf,
    pub(super) buffered: Vec<u8>,
    pub(super) offset: usize,
    pub(super) total: usize,
    pub(super) status: Arc<AtomicI32>,
    pub(super) ended: Arc<AtomicBool>,
}

impl Drop for PublicRead {
    fn drop(&mut self) {
        self.ended.store(true, Ordering::Release);
    }
}

impl AsyncRead for PublicRead {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        use std::future::Future;
        let this = self.get_mut();
        loop {
            if output.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if this.offset < this.buffered.len() {
                let count = output.remaining().min(this.buffered.len() - this.offset);
                output.put_slice(&this.buffered[this.offset..this.offset + count]);
                this.offset += count;
                return Poll::Ready(Ok(()));
            }
            let message = {
                let mut next = std::pin::pin!(this.channel.wait());
                std::task::ready!(next.as_mut().poll(cx))
            };
            match message {
                Some(ChannelMsg::Data { data }) => {
                    this.total = this.total.saturating_add(data.len());
                    if data.len() > 65_536 || this.total > 2_097_152 {
                        return Poll::Ready(Err(std::io::ErrorKind::InvalidData.into()));
                    }
                    this.buffered = data.to_vec();
                    this.offset = 0;
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    this.status
                        .store(i32::try_from(exit_status).unwrap_or(-2), Ordering::Release);
                }
                Some(ChannelMsg::WindowAdjusted { .. } | ChannelMsg::Eof) => {}
                Some(ChannelMsg::Close) | None => return Poll::Ready(Ok(())),
                _ => return Poll::Ready(Err(std::io::ErrorKind::InvalidData.into())),
            }
        }
    }
}

impl Connection {
    pub async fn upload_public(
        mut self,
        job: TransferJob,
        binding: UploadBinding,
    ) -> Result<UploadOutcome, FailureClass> {
        let args = binding.args()?;
        if job.direction != TransferDirection::Upload
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
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(job.transfer_timeout.seconds);
        let mut outcome = UploadOutcome {
            temporary: format!("{}/upload.tmp", binding.directory()),
            destination: binding.destination(),
            ..UploadOutcome::default()
        };
        let mut staged = None;
        let status = Arc::new(AtomicI32::new(-1));
        let ended = Arc::new(AtomicBool::new(true));
        let mut writer = None;
        let mut raw = None;
        let work = async {
            let mut configured = self.plan.command.clone();
            configured.args = args;
            let executable = crate::staging::body_has_shebang(&configured.body);
            let launcher = crate::staging::launcher_for_script(
                executable,
                configured.interpreter.as_deref(),
                configured.cwd.as_deref(),
                &configured.cwd_nonce,
                &configured.env,
                &configured.args,
            );
            let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());
            outcome.possible_staging_residue = true;
            let prepared = self
                .backend
                .stage_launcher(
                    &mut self.session,
                    &launcher,
                    Some(&configured.body),
                    None,
                    remaining(),
                )
                .await
                .map_err(|e| e.class)?;
            staged = Some(prepared.clone());
            self.backend
                .make_launcher_executable(&mut self.session, &prepared.launcher, remaining())
                .await
                .map_err(|e| e.class)?;
            if executable {
                self.backend
                    .make_script_body_executable(
                        &mut self.session,
                        prepared.body.as_deref().ok_or(FailureClass::Protocol)?,
                        remaining(),
                    )
                    .await
                    .map_err(|e| e.class)?;
            }
            let mut channel = self
                .session
                .channel_open_session()
                .await
                .map_err(|_| FailureClass::Protocol)?;
            outcome.launcher_dispatched = true;
            channel
                .exec(
                    true,
                    crate::staging::shell_join(&[prepared.launcher]).into_bytes(),
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
            let result = crate::transfer_sftp::builder_upload_reserved(
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
            if let Some(staged) = staged {
                let cleanup =
                    crate::staging::cleanup_command(&staged.launcher).map_err(|e| e.class)?;
                let cleaned = run_helper_command(
                    &mut self.session,
                    &cleanup,
                    None,
                    until.saturating_duration_since(tokio::time::Instant::now()),
                    false,
                    false,
                    &CancellationToken::default(),
                )
                .await
                .map_err(|e| e.class)?;
                outcome.possible_staging_residue = cleaned.status != Some(0);
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
                Some(75) => Some(FailureClass::CapabilityUnsupported),
                Some(76) => Some(FailureClass::TransferPathSafety),
                Some(77) => Some(FailureClass::Sftp),
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
