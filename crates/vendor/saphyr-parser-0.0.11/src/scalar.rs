//! Broil modification: protected scalar ownership from scanner to consumer.
//! Provenance: docs/provenance/saphyr-parser-0.0.11.md in the Broil source tree.

use alloc::{string::String, vec::Vec};
use core::{fmt, ops::Deref};
use zeroize::{Zeroize, Zeroizing};

/// An owned, redacted UTF-8 scalar, wiped even when scanning fails or an event is abandoned.
#[derive(Default, PartialEq, Eq)]
pub struct Scalar(Zeroizing<Vec<u8>>);

impl Scalar {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(Zeroizing::new(Vec::with_capacity(capacity)))
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        self.0.reserve(additional);
    }

    pub(crate) fn push_str(&mut self, text: &str) {
        self.0.extend_from_slice(text.as_bytes());
    }

    pub(crate) fn push(&mut self, ch: char) {
        let mut encoded = Zeroizing::new([0; 4]);
        self.push_str(ch.encode_utf8(&mut *encoded));
    }

    /// Move the final allocation into its consumer's protected UTF-8 owner.
    /// No mutable unprotected buffer or plaintext copy escapes this handoff.
    #[must_use]
    pub fn into_zeroizing(mut self) -> Zeroizing<String> {
        let bytes = core::mem::take(&mut *self.0);
        Zeroizing::new(String::from_utf8(bytes).expect("scalar UTF-8 invariant"))
    }
}

impl Deref for Scalar {
    type Target = str;
    fn deref(&self) -> &str {
        core::str::from_utf8(&self.0).expect("scalar UTF-8 invariant")
    }
}

impl AsRef<str> for Scalar {
    fn as_ref(&self) -> &str {
        self
    }
}

impl PartialEq<str> for Scalar {
    fn eq(&self, other: &str) -> bool {
        &**self == other
    }
}

impl From<String> for Scalar {
    fn from(text: String) -> Self {
        Self(Zeroizing::new(text.into_bytes()))
    }
}

impl From<&str> for Scalar {
    fn from(text: &str) -> Self {
        let mut scalar = Self::with_capacity(text.len());
        scalar.push_str(text);
        scalar
    }
}

// Retain upstream event comparison/clone compatibility, but never an unprotected copy.
// Broil itself must not clone parsers, tokens or scalar events.
impl Clone for Scalar {
    fn clone(&self) -> Self {
        Self::from(&**self)
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar([REDACTED])")
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        #[cfg(feature = "wipe-observer")]
        OBSERVER.with(|observer| {
            if let Some(callback) = observer.get() {
                callback(&self.0);
            }
        });
    }
}

#[cfg(feature = "wipe-observer")]
std::thread_local! {
    static OBSERVER: core::cell::Cell<Option<fn(&[u8])>> = const { core::cell::Cell::new(None) };
}

/// Set a thread-local test observer, called after wiping and before freeing a scalar.
/// The observer receives only live, already-zeroed bytes. Absent from normal builds.
#[cfg(feature = "wipe-observer")]
pub fn set_wipe_observer(observer: Option<fn(&[u8])>) {
    OBSERVER.with(|slot| slot.set(observer));
}
