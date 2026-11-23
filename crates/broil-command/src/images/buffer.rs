// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Fixed-capacity private storage; no growth or printable byte representation.

use super::common::{Failure, Result};
use zeroize::Zeroize;

#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Bytes(Vec<u8>);

impl Bytes {
    pub(crate) fn new(size: usize) -> Result<Self> {
        if size > 16_777_224 {
            return Err(Failure::Limit);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| Failure::Limit)?;
        if bytes.capacity() != size {
            return Err(Failure::Limit);
        }
        bytes.resize(bytes.capacity(), 0);
        Ok(Self(bytes))
    }
    pub(crate) fn get(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn get_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
    pub(crate) fn clear(&mut self) {
        self.0.as_mut_slice().zeroize();
    }
}

impl Drop for Bytes {
    fn drop(&mut self) {
        self.clear();
    }
}
