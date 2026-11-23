// Modified by the Broil project from russh 0.62.5; see LICENSE.txt and docs/provenance/russh-0.62.5.md for provenance.
// SPDX-License-Identifier: Apache-2.0
//! Bounded, non-printable channel custody after canonical authentication.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use bytes::Bytes;
use ssh_encoding::{Decode, Encode};
use tokio::sync::mpsc::channel;
use zeroize::{Zeroize, Zeroizing};

use super::{Handle, Handler, Msg, Session};
use crate::channels::ChannelRef;
use crate::{Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, Error, Sig, msg};

pub(crate) const PACKET_LIMIT: usize = 65_536;
const STREAM_LIMIT: usize = 65_536;
const STATE_STDOUT_LIMIT: usize = 1_048_576;
const QUEUE_LIMIT: usize = 16;
const MESSAGE_LIMIT: usize = 4096;

/// Selected by a typed local entry point, never by peer data or a numeric limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    Ordinary,
    State,
}

/// Original zeroizing storage, shared by queued slices until their final use.
pub struct PrivateInput {
    bytes: Bytes,
    use_state: PrivateInputUse,
}

/// Observation of the final owner drop, independent of the sending future.
#[derive(Clone)]
pub struct PrivateInputUse(Arc<AtomicBool>);

impl PrivateInputUse {
    pub fn released(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

struct InputOwner {
    bytes: Zeroizing<Vec<u8>>,
    done: PrivateInputUse,
}

impl AsRef<[u8]> for InputOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for InputOwner {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.done.0.store(true, Ordering::Release);
    }
}

impl PrivateInput {
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Result<Self, Error> {
        if bytes.len() > 1_048_576 || bytes.capacity() > 1_048_576 {
            return Err(Error::Inconsistent);
        }
        let use_state = PrivateInputUse(Arc::new(AtomicBool::new(false)));
        let bytes = Bytes::from_owner(InputOwner {
            bytes,
            done: use_state.clone(),
        });
        Ok(Self { bytes, use_state })
    }

    pub fn use_state(&self) -> PrivateInputUse {
        self.use_state.clone()
    }
}

/// Received bytes have no printable representation or ordinary-result conversion.
pub struct PrivateData(Bytes);
impl AsRef<[u8]> for PrivateData {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub enum PrivateMessage {
    Data(PrivateData),
    Stderr(PrivateData),
    Eof,
    Close,
    ExitStatus(u32),
    ExitSignal(Sig),
    Success,
    Failure,
    WindowAdjusted,
}

pub struct PrivateChannel(Channel<Msg>);
pub struct PrivateRead(ChannelReadHalf);
pub struct PrivateWrite(ChannelWriteHalf<Msg>);

impl PrivateChannel {
    pub fn split(self) -> (PrivateRead, PrivateWrite) {
        let (read, write) = self.0.split();
        (PrivateRead(read), PrivateWrite(write))
    }
}

impl PrivateRead {
    pub async fn wait(&mut self) -> Result<Option<PrivateMessage>, Error> {
        Ok(match self.0.wait().await {
            Some(ChannelMsg::Data { data }) => Some(PrivateMessage::Data(PrivateData(data))),
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                Some(PrivateMessage::Stderr(PrivateData(data)))
            }
            Some(ChannelMsg::Eof) => Some(PrivateMessage::Eof),
            Some(ChannelMsg::Close) => Some(PrivateMessage::Close),
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                Some(PrivateMessage::ExitStatus(exit_status))
            }
            Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                Some(PrivateMessage::ExitSignal(signal_name))
            }
            Some(ChannelMsg::Success) => Some(PrivateMessage::Success),
            Some(ChannelMsg::Failure) => Some(PrivateMessage::Failure),
            Some(ChannelMsg::WindowAdjusted { .. }) => Some(PrivateMessage::WindowAdjusted),
            None => None,
            Some(_) => return Err(Error::Inconsistent),
        })
    }
}

impl PrivateWrite {
    pub async fn exec(&self, command: Vec<u8>) -> Result<(), Error> {
        self.0.exec(true, command).await
    }
    pub async fn data(&self, input: PrivateInput) -> Result<(), Error> {
        self.0.data_bytes(input.bytes).await
    }
    pub async fn eof(&self) -> Result<(), Error> {
        self.0.eof().await
    }
    pub async fn close(&self) -> Result<(), Error> {
        self.0.close().await
    }
    pub async fn signal(&self, signal: Sig) -> Result<(), Error> {
        self.0.signal(signal).await
    }
}

impl<H: Handler> Handle<H> {
    /// Open the only channel on an authenticated connection with guarded decoding.
    /// This mode is permanent for the connection. Rekey and unsolicited protocols
    /// terminate privately; use one connection per finite private action.
    pub async fn channel_open_private_session(&self) -> Result<PrivateChannel, Error> {
        self.open_private_session(Profile::Ordinary).await
    }

    /// One scalar-free state response, with a separate fixed stdout allowance.
    /// The connection can admit this profile only once, even after cancellation.
    pub async fn channel_open_private_state_session(&self) -> Result<PrivateChannel, Error> {
        self.open_private_session(Profile::State).await
    }

    async fn open_private_session(&self, profile: Profile) -> Result<PrivateChannel, Error> {
        let (sender, mut receiver) = channel(QUEUE_LIMIT);
        let channel_ref = ChannelRef::private(sender, profile);
        let window_size = channel_ref.window_size().clone();
        self.sender
            .send(Msg::ChannelOpenSession { channel_ref })
            .await
            .map_err(|_| Error::SendError)?;
        match receiver.recv().await {
            Some(ChannelMsg::Open {
                id,
                max_packet_size,
                window_size: size,
            }) => {
                window_size.update(size).await;
                Ok(PrivateChannel(Channel {
                    write_half: ChannelWriteHalf {
                        id,
                        sender: self.sender.clone(),
                        max_packet_size: max_packet_size.min(32_768),
                        window_size,
                    },
                    read_half: ChannelReadHalf { receiver },
                }))
            }
            Some(ChannelMsg::OpenFailure(reason)) => Err(Error::ChannelOpenFailure(reason)),
            _ => Err(Error::Disconnect),
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct PrivateState {
    stdout: usize,
    stderr: usize,
    messages: usize,
    state_channel: Option<ChannelId>,
    state_stdout: usize,
}

impl PrivateState {
    pub(crate) fn admit(&mut self, id: ChannelId, profile: Profile) -> Result<(), Error> {
        if profile == Profile::State {
            if self.state_channel.is_some() {
                return Err(Error::Inconsistent);
            }
            self.state_channel = Some(id);
        }
        Ok(())
    }
}

/// Allocate before the first retained copy; no reallocating secret owner.
pub(crate) fn guarded(bytes: &[u8]) -> Result<Bytes, Error> {
    if bytes.len() > PACKET_LIMIT {
        return Err(Error::Inconsistent);
    }
    let mut data = Zeroizing::new(Vec::new());
    data.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Inconsistent)?;
    data.extend_from_slice(bytes);
    Ok(PrivateInput::new(data)?.bytes)
}

fn field<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let len = u32::decode(input)? as usize;
    if len > input.len() {
        return Err(Error::Inconsistent);
    }
    let (value, rest) = input.split_at(len);
    *input = rest;
    Ok(value)
}

fn end(input: &[u8]) -> Result<(), Error> {
    if input.is_empty() {
        Ok(())
    } else {
        Err(Error::Inconsistent)
    }
}

impl Session {
    pub(crate) async fn read_private<H: Handler>(
        &mut self,
        handler: &mut H,
        bytes: &[u8],
    ) -> Result<(), H::Error> {
        let state = self.private.as_mut().ok_or(Error::Inconsistent)?;
        state.messages = state.messages.checked_add(1).ok_or(Error::Inconsistent)?;
        if state.messages > MESSAGE_LIMIT || bytes.len() > PACKET_LIMIT {
            return Err(Error::Inconsistent.into());
        }
        let (&kind, mut input) = bytes.split_first().ok_or(Error::Inconsistent)?;
        match kind {
            msg::DEBUG => {
                if u8::decode(&mut input).map_err(Error::from)? > 1 {
                    return Err(Error::Inconsistent.into());
                }
                field(&mut input)?;
                field(&mut input)?;
                end(input)?;
                Ok(())
            }
            msg::IGNORE => {
                field(&mut input)?;
                end(input)?;
                Ok(())
            }
            msg::CHANNEL_DATA | msg::CHANNEL_EXTENDED_DATA => {
                let id = ChannelId::decode(&mut input).map_err(Error::from)?;
                let stderr = kind == msg::CHANNEL_EXTENDED_DATA;
                if stderr && u32::decode(&mut input).map_err(Error::from)? != 1 {
                    return Err(Error::Inconsistent.into());
                }
                let data = field(&mut input)?;
                end(input)?;
                let profile = self.channels.get(&id)
                    .and_then(|channel| channel.private).ok_or(Error::Inconsistent)?;
                if (profile == Profile::State) != (state.state_channel == Some(id)) {
                    return Err(Error::Inconsistent.into());
                }
                let (count, limit) = if stderr {
                    (&mut state.stderr, STREAM_LIMIT)
                } else if profile == Profile::State {
                    (&mut state.state_stdout, STATE_STDOUT_LIMIT)
                } else {
                    (&mut state.stdout, STREAM_LIMIT)
                };
                *count = count
                    .checked_add(data.len())
                    .filter(|n| *n <= limit)
                    .ok_or(Error::Inconsistent)?;
                let enc = self.common.encrypted.as_mut().ok_or(Error::Inconsistent)?;
                let params = enc.channels.get(&id).ok_or(Error::Inconsistent)?;
                if !params.confirmed || data.len() > params.sender_window_size as usize {
                    return Err(Error::Inconsistent.into());
                }
                enc.adjust_window_size(id, data, STREAM_LIMIT as u32)?;
                let data = guarded(data)?;
                let message = if stderr {
                    ChannelMsg::ExtendedData { data, ext: 1 }
                } else {
                    ChannelMsg::Data { data }
                };
                self.channels
                    .get(&id)
                    .ok_or(Error::Inconsistent)?
                    .try_send(message)
                    .map_err(|_| Error::Inconsistent)?;
                // Never deliver private bytes through arbitrary ordinary handler callbacks.
                Ok(())
            }
            msg::CHANNEL_OPEN_CONFIRMATION if input.len() == 16 => {
                self.client_read_authenticated(handler, bytes).await
            }
            msg::CHANNEL_EOF | msg::CHANNEL_CLOSE | msg::CHANNEL_SUCCESS | msg::CHANNEL_FAILURE
                if input.len() == 4 =>
            {
                self.client_read_authenticated(handler, bytes).await
            }
            msg::CHANNEL_WINDOW_ADJUST if input.len() == 8 => {
                self.client_read_authenticated(handler, bytes).await
            }
            msg::GLOBAL_REQUEST => {
                let request = field(&mut input)?;
                let reply = u8::decode(&mut input).map_err(Error::from)?;
                if reply > 1 {
                    return Err(Error::Inconsistent.into());
                }
                if request == b"hostkeys-00@openssh.com" && reply == 0 {
                    while !input.is_empty() {
                        field(&mut input)?;
                    }
                    Ok(())
                } else if request == b"keepalive@openssh.com" && input.is_empty() {
                    if reply == 1 {
                        let enc = self.common.encrypted.as_mut().ok_or(Error::Inconsistent)?;
                        push_packet!(enc.write, {
                            enc.write.push(msg::REQUEST_SUCCESS);
                        });
                    }
                    Ok(())
                } else {
                    Err(Error::Inconsistent.into())
                }
            }
            msg::CHANNEL_REQUEST => {
                let id = ChannelId::decode(&mut input).map_err(Error::from)?;
                let request = field(&mut input)?;
                if u8::decode(&mut input).map_err(Error::from)? != 0 {
                    return Err(Error::Inconsistent.into());
                }
                let mut public = vec![kind];
                id.encode(&mut public).map_err(Error::from)?;
                match request {
                    b"exit-status" => {
                        let status = u32::decode(&mut input).map_err(Error::from)?;
                        end(input)?;
                        "exit-status".encode(&mut public).map_err(Error::from)?;
                        0u8.encode(&mut public).map_err(Error::from)?;
                        status.encode(&mut public).map_err(Error::from)?;
                    }
                    b"exit-signal" => {
                        let signal = field(&mut input)?;
                        let known = [
                            "ABRT", "ALRM", "FPE", "HUP", "ILL", "INT", "KILL", "PIPE", "QUIT",
                            "SEGV", "TERM", "USR1", "USR2",
                        ];
                        let signal = known
                            .iter()
                            .find(|name| name.as_bytes() == signal)
                            .ok_or(Error::Inconsistent)?;
                        let core = u8::decode(&mut input).map_err(Error::from)?;
                        if core > 1 {
                            return Err(Error::Inconsistent.into());
                        }
                        field(&mut input)?; // free-form error is borrowed and discarded privately
                        field(&mut input)?; // language is likewise never decoded to a String
                        end(input)?;
                        "exit-signal".encode(&mut public).map_err(Error::from)?;
                        0u8.encode(&mut public).map_err(Error::from)?;
                        signal.encode(&mut public).map_err(Error::from)?;
                        core.encode(&mut public).map_err(Error::from)?;
                        "".encode(&mut public).map_err(Error::from)?;
                        "".encode(&mut public).map_err(Error::from)?;
                    }
                    _ => return Err(Error::Inconsistent.into()),
                }
                self.client_read_authenticated(handler, &public).await
            }
            // Reject unsolicited metadata, disconnect text and rekey before any
            // generic decoder, diagnostic or retained ordinary string sees it.
            _ => Err(Error::Inconsistent.into()),
        }
    }
}
