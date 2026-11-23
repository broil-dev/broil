// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInOut};
use zeroize::Zeroizing;

use super::{Error, Plaintext, check_size};

const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;

fn nonce(index: usize, last: bool) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[3..11].copy_from_slice(&(index as u64).to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

pub(super) fn encrypted_len(length: usize) -> Result<usize, Error> {
    check_size(length)?;
    let tags = length
        .div_ceil(CHUNK)
        .max(1)
        .checked_mul(TAG)
        .ok_or(Error::SizeLimit)?;
    length.checked_add(tags).ok_or(Error::SizeLimit)
}

pub(super) fn encrypt(key: &[u8; 32], input: &[u8], output: &mut Vec<u8>) -> Result<(), Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("fixed key");
    let mut chunk = Zeroizing::new(Vec::new());
    chunk
        .try_reserve_exact(CHUNK)
        .map_err(|_| Error::Allocation)?;
    chunk.resize(CHUNK, 0);
    let count = input.len().div_ceil(CHUNK).max(1);
    for index in 0..count {
        let start = index * CHUNK;
        let part = &input[start..input.len().min(start + CHUNK)];
        chunk[..part.len()].copy_from_slice(part);
        let tag = cipher
            .encrypt_inout_detached(
                &nonce(index, index + 1 == count).into(),
                b"",
                (&mut chunk[..part.len()]).into(),
            )
            .map_err(|_| Error::PayloadAuthentication)?;
        output.extend_from_slice(&chunk[..part.len()]);
        output.extend_from_slice(&tag);
    }
    Ok(())
}

pub(super) fn decrypt(key: &[u8; 32], input: &[u8]) -> Result<Plaintext, Error> {
    check_size(input.len())?;
    if input.len() < TAG {
        return Err(Error::PayloadAuthentication);
    }
    let count = input.len().div_ceil(CHUNK + TAG);
    let last_len = input.len() - (count - 1) * (CHUNK + TAG);
    if last_len < TAG || (count > 1 && last_len == TAG) {
        return Err(Error::PayloadAuthentication);
    }
    let mut result = Plaintext::allocate(input.len() - count * TAG)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("fixed key");
    for (index, part) in input.chunks(CHUNK + TAG).enumerate() {
        let length = part.len() - TAG;
        let out = &mut result.0[index * CHUNK..][..length];
        out.copy_from_slice(&part[..length]);
        let tag =
            poly1305::Tag::try_from(&part[length..]).map_err(|_| Error::PayloadAuthentication)?;
        cipher
            .decrypt_inout_detached(
                &nonce(index, index + 1 == count).into(),
                b"",
                out.into(),
                &tag,
            )
            .map_err(|_| Error::PayloadAuthentication)?;
    }
    Ok(result)
}
