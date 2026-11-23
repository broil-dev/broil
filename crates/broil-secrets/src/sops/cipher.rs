// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Error, MAX_SCALAR_BYTES,
    tree::{Bytes, Plaintext},
};
use aes_gcm::{
    AesGcm, KeyInit,
    aead::{AeadInOut, consts::U32},
};
use base64ct::{Base64, Encoding};
use zeroize::Zeroizing;

type Cipher = AesGcm<aes::Aes256, U32>;

pub(super) fn random_key() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *key).map_err(|_| Error::Randomness)?;
    Ok(key)
}

pub(super) fn encrypt(
    text: &str,
    kind: &str,
    key: &[u8; 32],
    aad: &str,
) -> Result<Plaintext, Error> {
    if text.len() > MAX_SCALAR_BYTES {
        return Err(Error::SizeLimit);
    }
    if text.is_empty() {
        return Plaintext::copy_from("");
    }
    let iv = random_key()?;
    let cipher = Cipher::new_from_slice(key).expect("fixed key size");
    let mut data = Bytes::copy_from(text.as_bytes())?;
    let tag = cipher
        .encrypt_inout_detached((&*iv).into(), aad.as_bytes(), data.0.as_mut_slice().into())
        .map_err(|_| Error::Authentication)?;
    let mut output = Zeroizing::new(String::with_capacity(Base64::encoded_len(&data.0) + 160));
    output.push_str("ENC[AES256_GCM,data:");
    append_base64(&data.0, &mut output)?;
    output.push_str(",iv:");
    append_base64(&*iv, &mut output)?;
    output.push_str(",tag:");
    append_base64(&tag, &mut output)?;
    output.push_str(",type:");
    output.push_str(kind);
    output.push(']');
    Plaintext::from_zeroizing(output)
}

fn append_base64(bytes: &[u8], output: &mut String) -> Result<(), Error> {
    let mut encoded = Bytes::allocate(Base64::encoded_len(bytes))?;
    let text = Base64::encode(bytes, &mut encoded.0).map_err(|_| Error::InvalidEnvelope)?;
    if output.len() + text.len() > output.capacity() {
        return Err(Error::SizeLimit);
    }
    output.push_str(text);
    Ok(())
}

pub(super) fn decrypt<'a>(
    envelope: &'a str,
    key: &[u8; 32],
    aad: &str,
) -> Result<(Plaintext, &'a str), Error> {
    let inner = envelope
        .strip_prefix("ENC[AES256_GCM,data:")
        .and_then(|text| text.strip_suffix(']'))
        .ok_or(Error::InvalidEnvelope)?;
    let (data, rest) = inner.split_once(",iv:").ok_or(Error::InvalidEnvelope)?;
    let (iv, rest) = rest.split_once(",tag:").ok_or(Error::InvalidEnvelope)?;
    let (tag, kind) = rest.split_once(",type:").ok_or(Error::InvalidEnvelope)?;
    if !matches!(kind, "str" | "int" | "float" | "bool" | "comment") {
        return Err(Error::InvalidType);
    }
    if data.len() > MAX_SCALAR_BYTES.div_ceil(3) * 4 {
        return Err(Error::SizeLimit);
    }
    let padding = data.bytes().rev().take_while(|byte| *byte == b'=').count();
    if data.len() % 4 != 0 || padding > 2 {
        return Err(Error::InvalidEnvelope);
    }
    let decoded_length = (data.len() / 4 * 3)
        .checked_sub(padding)
        .ok_or(Error::InvalidEnvelope)?;
    if decoded_length > MAX_SCALAR_BYTES {
        return Err(Error::SizeLimit);
    }
    let mut iv_bytes = [0; 32];
    let mut tag_bytes = [0; 16];
    if Base64::decode(iv, &mut iv_bytes)
        .map_err(|_| Error::InvalidEnvelope)?
        .len()
        != 32
        || Base64::decode(tag, &mut tag_bytes)
            .map_err(|_| Error::InvalidEnvelope)?
            .len()
            != 16
    {
        return Err(Error::InvalidEnvelope);
    }
    let mut data_bytes = Bytes::allocate(decoded_length)?;
    Base64::decode(data, &mut data_bytes.0).map_err(|_| Error::InvalidEnvelope)?;
    let cipher = Cipher::new_from_slice(key).expect("fixed key size");
    cipher
        .decrypt_inout_detached(
            (&iv_bytes).into(),
            aad.as_bytes(),
            data_bytes.0.as_mut_slice().into(),
            (&tag_bytes).into(),
        )
        .map_err(|_| Error::Authentication)?;
    Ok((data_bytes.into_text()?, kind))
}
