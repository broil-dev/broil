// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod format;
mod kdf;
mod keys;
mod stream;

pub use format::{armor, dearmor};
pub use keys::{Identity, Recipient, parse_identity_file};

use broil_core::secret::OwnedSecret;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::AeadInOut};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

use format::Stanza;

pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
const X25519_LABEL: &[u8] = b"age-encryption.org/v1/X25519";
const SCRYPT_LABEL: &[u8] = b"age-encryption.org/v1/scrypt";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidKey,
    InvalidHeader,
    InvalidArmor,
    NoMatchingIdentity,
    HeaderAuthentication,
    PayloadAuthentication,
    EmptyPassphrase,
    WorkFactor,
    SizeLimit,
    Allocation,
    Randomness,
    InvalidPlaintext,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "invalid age key",
            Self::InvalidHeader => "invalid age header",
            Self::InvalidArmor => "invalid age armor",
            Self::NoMatchingIdentity => "age identity or passphrase did not match",
            Self::HeaderAuthentication => "age header authentication failed",
            Self::PayloadAuthentication => "age payload authentication failed",
            Self::EmptyPassphrase => "empty age passphrase",
            Self::WorkFactor => "age scrypt work factor exceeds limit",
            Self::SizeLimit => "age document exceeds size limit",
            Self::Allocation => "age memory allocation failed",
            Self::Randomness => "age randomness unavailable",
            Self::InvalidPlaintext => "age plaintext is not UTF-8",
        })
    }
}
impl std::error::Error for Error {}

pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Drop for Plaintext {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();

    }
}

impl Plaintext {
    fn allocate(length: usize) -> Result<Self, Error> {
        check_size(length)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        bytes.resize(length, 0);
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_secret(mut self) -> Result<OwnedSecret, Error> {
        std::str::from_utf8(&self.0).map_err(|_| Error::InvalidPlaintext)?;
        Ok(OwnedSecret::from_zeroizing(Zeroizing::new(
            String::from_utf8(std::mem::take(&mut *self.0)).expect("validated UTF-8"),
        )))
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Plaintext([REDACTED])")
    }
}

fn check_size(length: usize) -> Result<(), Error> {
    if length > MAX_DOCUMENT_BYTES {
        Err(Error::SizeLimit)
    } else {
        Ok(())
    }
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, Error> {
    let mut bytes = Zeroizing::new([0; N]);
    getrandom::fill(&mut *bytes).map_err(|_| Error::Randomness)?;
    Ok(bytes)
}

fn wrapping_key(
    identity: &Identity,
    share: &[u8; 32],
    recipient: &[u8; 32],
    ephemeral: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let shared = Zeroizing::new(MontgomeryPoint(*share).mul_clamped(*identity.0));
    if *shared == MontgomeryPoint([0; 32]) {
        return Err(Error::InvalidHeader);
    }
    let mut salt = [0; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    Ok(kdf::hkdf(shared.as_bytes(), &salt, X25519_LABEL))
}

fn scrypt_key(
    passphrase: &OwnedSecret,
    salt: &[u8; 16],
    log_n: u8,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if passphrase.is_empty() {
        return Err(Error::EmptyPassphrase);
    }
    check_size(passphrase.len())?;
    let mut full_salt = [0; SCRYPT_LABEL.len() + 16];
    full_salt[..SCRYPT_LABEL.len()].copy_from_slice(SCRYPT_LABEL);
    full_salt[SCRYPT_LABEL.len()..].copy_from_slice(salt);
    kdf::scrypt(passphrase.as_str().as_bytes(), &full_salt, log_n)
}

fn wrap(key: &[u8; 32], file_key: &[u8; 16], header: &mut Vec<u8>) -> Result<(), Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("fixed key");
    let mut body = Zeroizing::new([0; 32]);
    body[..16].copy_from_slice(file_key);
    let tag = cipher
        .encrypt_inout_detached(&[0; 12].into(), b"", (&mut body[..16]).into())
        .map_err(|_| Error::HeaderAuthentication)?;
    body[16..].copy_from_slice(&tag);
    format::encode(&*body, header);
    header.push(b'\n');
    Ok(())
}

fn unwrap(key: &[u8; 32], body: &[u8; 32]) -> Result<Zeroizing<[u8; 16]>, Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("fixed key");
    let mut file_key = Zeroizing::new([0; 16]);
    file_key.copy_from_slice(&body[..16]);
    let tag = poly1305::Tag::try_from(&body[16..]).expect("fixed tag");
    cipher
        .decrypt_inout_detached(&[0; 12].into(), b"", file_key.as_mut_slice().into(), &tag)
        .map_err(|_| Error::NoMatchingIdentity)?;
    Ok(file_key)
}

fn header_mac(file_key: &[u8; 16], header: &[u8]) -> Hmac<Sha256> {
    let key = kdf::hkdf(file_key, b"", b"header");
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&*key).expect("HMAC key");
    mac.update(header);
    mac
}

fn output_buffer(header_length: usize, plaintext_length: usize) -> Result<Vec<u8>, Error> {
    let length = header_length
        .checked_add(16)
        .and_then(|n| {
            stream::encrypted_len(plaintext_length)
                .ok()
                .and_then(|p| n.checked_add(p))
        })
        .ok_or(Error::SizeLimit)?;
    check_size(length)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| Error::Allocation)?;
    output.extend_from_slice(format::INTRO);
    Ok(output)
}

fn finish(mut header: Vec<u8>, file_key: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    header.extend_from_slice(b"---");
    let tag = header_mac(file_key, &header).finalize().into_bytes();
    header.push(b' ');
    format::encode(&tag, &mut header);
    header.push(b'\n');
    let nonce = random::<16>()?;
    let key = kdf::hkdf(file_key, &*nonce, b"payload");
    header.extend_from_slice(&*nonce);
    stream::encrypt(&key, plaintext, &mut header)?;
    Ok(header)
}

pub fn encrypt(plaintext: &[u8], recipients: &[Recipient]) -> Result<Vec<u8>, Error> {
    if recipients.is_empty() {
        return Err(Error::InvalidKey);
    }
    let header_length = recipients
        .len()
        .checked_mul(98)
        .and_then(|n| n.checked_add(format::INTRO.len() + 48))
        .ok_or(Error::SizeLimit)?;
    let mut output = output_buffer(header_length, plaintext.len())?;
    let file_key = random()?;
    for recipient in recipients {
        let ephemeral = Identity::generate()?;
        let public = ephemeral.recipient();
        let key = wrapping_key(&ephemeral, &recipient.0, &recipient.0, &public.0)?;
        output.extend_from_slice(b"-> X25519 ");
        format::encode(&public.0, &mut output);
        output.push(b'\n');
        wrap(&key, &file_key, &mut output)?;
    }
    finish(output, &file_key, plaintext)
}

pub fn encrypt_with_passphrase(
    plaintext: &[u8],
    passphrase: &OwnedSecret,
) -> Result<Vec<u8>, Error> {
    if passphrase.is_empty() {
        return Err(Error::EmptyPassphrase);
    }
    let mut output = output_buffer(format::INTRO.len() + 80 + 48, plaintext.len())?;
    let file_key = random()?;
    let salt = random::<16>()?;
    let key = scrypt_key(passphrase, &salt, kdf::DEFAULT_LOG_N)?;
    output.extend_from_slice(b"-> scrypt ");
    format::encode(&*salt, &mut output);
    output.extend_from_slice(b" 18\n");
    wrap(&key, &file_key, &mut output)?;
    finish(output, &file_key, plaintext)
}

pub fn decrypt(
    input: &[u8],
    identities: &[Identity],
    passphrase: Option<&OwnedSecret>,
) -> Result<Plaintext, Error> {
    let input = format::input_bytes(input)?;
    let header = format::header(&input)?;
    let mut stanzas = header.stanzas;
    let mut found = None;
    while !stanzas.is_empty() {
        match format::stanza(&mut stanzas)? {
            Stanza::X25519 { share, body } => {
                for identity in identities {
                    let key = wrapping_key(identity, &share, &identity.recipient().0, &share)?;
                    if let Ok(file_key) = unwrap(&key, &body) {
                        found = Some(file_key);
                        break;
                    }
                }
            }
            Stanza::Scrypt { salt, log_n, body } => {
                if let Some(passphrase) = passphrase {
                    found = Some(unwrap(&*scrypt_key(passphrase, &salt, log_n)?, &body)?);
                }
            }
            Stanza::Unknown => {}
        }
        if found.is_some() {
            break;
        }
    }
    let file_key = found.ok_or(Error::NoMatchingIdentity)?;
    header_mac(&file_key, header.authenticated)
        .verify_slice(&header.mac)
        .map_err(|_| Error::HeaderAuthentication)?;
    if header.payload.len() < 16 {
        return Err(Error::InvalidHeader);
    }
    let key = kdf::hkdf(&*file_key, &header.payload[..16], b"payload");
    stream::decrypt(&key, &header.payload[16..])
}

pub(crate) fn validate_identity_envelope(input: &[u8]) -> Result<(), Error> {
    let input = format::input_bytes(input)?;
    let header = format::header(&input)?;
    let mut stanzas = header.stanzas;
    if !matches!(
        format::stanza(&mut stanzas)?,
        Stanza::Scrypt { log_n: 1..=22, .. }
    ) || !stanzas.is_empty()
        || header.payload.len() < 32
    {
        return Err(Error::InvalidHeader);
    }
    Ok(())
}
