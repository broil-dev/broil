// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Interaction, protocol};
use crate::{
    read::{Error, Result},
    sops::{MAX_SCALAR_BYTES, Plaintext},
};
use base64ct::{Base64, Encoding};
use curve25519_dalek::edwards::EdwardsPoint;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(super) enum Generator {
    Hex(usize),
    Base64(usize),
    Ssh,
    Prompt,
    Handler,
}
impl Generator {
    pub(super) fn parse(text: &str, has_handler: bool) -> Result<Self> {
        match text {
            "ssh-ed25519" => Ok(Self::Ssh),
            "prompt" => Ok(Self::Prompt),
            "handler" if has_handler => Ok(Self::Handler),
            _ => {
                let (kind, count) = text
                    .split_once(':')
                    .ok_or(Error::class("invalid generator"))?;
                if count.is_empty()
                    || count.starts_with('0')
                    || !count.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(Error::class("invalid generator"));
                }
                let n = count
                    .parse::<usize>()
                    .map_err(|_| Error::class("invalid generator"))?;
                let (value, size) = match kind {
                    "hex" => (Self::Hex(n), n.checked_mul(2)),
                    "base64" => (
                        Self::Base64(n),
                        n.checked_add(2).and_then(|n| (n / 3).checked_mul(4)),
                    ),
                    _ => return Err(Error::class("invalid generator")),
                };
                if size.is_none_or(|n| n > MAX_SCALAR_BYTES) {
                    return Err(Error::class("generator size"));
                }
                Ok(value)
            }
        }
    }
    pub(super) fn generate(
        self,
        io: &mut dyn Interaction,
        non_interactive: bool,
    ) -> Result<Plaintext> {
        match self {
            Self::Hex(n) => {
                let random = random(n)?;
                let mut out = buffer(n * 2)?;
                for (i, b) in random.iter().enumerate() {
                    out[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
                    out[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
                }
                Plaintext::from_bytes(out).map_err(|_| Error::class("generator encoding"))
            }
            Self::Base64(n) => {
                let random = random(n)?;
                base64(&random)
            }
            Self::Ssh => ssh(io),
            Self::Prompt => {
                if non_interactive {
                    return Err(Error::class("private terminal input required"));
                }
                let value = io.prompt("New rotation value", true, MAX_SCALAR_BYTES)?;
                protocol::candidate(value.as_str().as_bytes())
            }
            Self::Handler => Err(Error::class("handler generation required")),
        }
    }
}
fn buffer(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(len)
        .map_err(|_| Error::class("allocation"))?;
    out.resize(len, 0);
    Ok(out)
}
fn random(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = buffer(len)?;

    getrandom::fill(&mut bytes).map_err(|_| Error::class("randomness unavailable"))?;
    Ok(bytes)
}
fn base64(bytes: &[u8]) -> Result<Plaintext> {
    let mut encoded = buffer(Base64::encoded_len(bytes))?;
    Base64::encode(bytes, &mut encoded).map_err(|_| Error::class("generator encoding"))?;
    Plaintext::from_bytes(encoded).map_err(|_| Error::class("generator encoding"))
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn ssh(io: &mut dyn Interaction) -> Result<Plaintext> {
    let seed = random(32)?;
    let expanded = Zeroizing::new(Sha512::digest(&seed));
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&expanded[..32]);
    let public = EdwardsPoint::mul_base_clamped(*scalar)
        .compress()
        .to_bytes();
    drop(scalar);
    drop(expanded);
    let mut public_blob = Vec::with_capacity(51);
    field(&mut public_blob, b"ssh-ed25519");
    field(&mut public_blob, &public);
    let public_text = base64(&public_blob)?;
    io.message(&format!("ssh-ed25519 {}", public_text.as_str()))?;
    drop(public_text);
    let mut inner = Zeroizing::new(Vec::with_capacity(256));
    let check = random(4)?;
    inner.extend_from_slice(&check);
    inner.extend_from_slice(&check);
    drop(check);
    field(&mut inner, b"ssh-ed25519");
    field(&mut inner, &public);
    inner.extend_from_slice(&64u32.to_be_bytes());
    inner.extend_from_slice(&seed);
    inner.extend_from_slice(&public);
    drop(seed);
    field(&mut inner, b"");
    let padding = 8 - inner.len() % 8;
    for i in 1..=padding {
        inner.push(i as u8);
    }
    let mut outer = Zeroizing::new(Vec::with_capacity(512));
    outer.extend_from_slice(b"openssh-key-v1\0");
    field(&mut outer, b"none");
    field(&mut outer, b"none");
    field(&mut outer, b"");
    outer.extend_from_slice(&1u32.to_be_bytes());
    field(&mut outer, &public_blob);
    field(&mut outer, &inner);
    drop(inner);
    let encoded = base64(&outer)?;
    drop(outer);
    let mut text = Zeroizing::new(String::new());
    text.try_reserve_exact(1024)
        .map_err(|_| Error::class("allocation"))?;
    text.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(70) {
        text.push_str(std::str::from_utf8(line).expect("base64"));
        text.push('\n');
    }
    text.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    Plaintext::from_zeroizing(text).map_err(|_| Error::class("private key encoding"))
}
