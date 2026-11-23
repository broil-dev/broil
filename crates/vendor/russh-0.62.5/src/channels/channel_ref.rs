// Modified by the Broil project from russh 0.62.5; see LICENSE.txt and docs/provenance/russh-0.62.5.md for provenance.
use tokio::sync::mpsc::Sender;

use super::WindowSizeRef;
use crate::ChannelMsg;

/// A handle to the [`super::Channel`]'s to be able to transmit messages
/// to it and update it's `window_size`.
#[derive(Debug)]
pub struct ChannelRef {
    pub(super) sender: Sender<ChannelMsg>,
    pub(crate) private: Option<crate::client::private::Profile>,
    pub(super) window_size: WindowSizeRef,
}

impl ChannelRef {
    pub fn new(sender: Sender<ChannelMsg>) -> Self {
        Self {
            sender,
            private: None,
            window_size: WindowSizeRef::new(0),
        }
    }

    pub(crate) fn private(sender: Sender<ChannelMsg>, profile: crate::client::private::Profile) -> Self {
        Self { sender, private: Some(profile), window_size: WindowSizeRef::new(0) }
    }

    pub(crate) fn window_size(&self) -> &WindowSizeRef {
        &self.window_size
    }
}

impl std::ops::Deref for ChannelRef {
    type Target = Sender<ChannelMsg>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}
