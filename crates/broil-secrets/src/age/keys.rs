// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use bech32::{Bech32, ByteIterExt, Fe32IterExt, Hrp, primitives::decode::CheckedHrpstring};
use broil_core::secret::OwnedSecret;
use curve25519_dalek::montgomery::MontgomeryPoint;
use std::{fmt, str::FromStr};
use zeroize::{Zeroize, Zeroizing};

use super::{Error, MAX_DOCUMENT_BYTES, check_size, random};

pub struct Identity(pub(super) Zeroizing<[u8; 32]>);

impl Drop for Identity {
    fn drop(&mut self) {
        self.0.zeroize();

    }
}

impl Identity {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self(random()?))
    }

    pub fn parse(encoded: &str) -> Result<Self, Error> {
        Ok(Self(decode_key(encoded, "age-secret-key-")?))
    }

    pub fn recipient(&self) -> Recipient {
        Recipient(MontgomeryPoint::mul_base_clamped(*self.0).to_bytes())
    }

    pub fn encode(&self) -> Result<OwnedSecret, Error> {
        let hrp = Hrp::parse("age-secret-key-").expect("constant HRP");
        let mut output = Zeroizing::new(String::new());
        output
            .try_reserve_exact(74)
            .map_err(|_| Error::Allocation)?;
        for ch in self
            .0
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32>(&hrp)
            .chars()
        {
            output.push(ch.to_ascii_uppercase());
        }
        Ok(OwnedSecret::from_zeroizing(output))
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identity([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipient(pub(super) [u8; 32]);

impl FromStr for Recipient {
    type Err = Error;
    fn from_str(encoded: &str) -> Result<Self, Error> {
        broil_core::secrets::parse_age_recipient(encoded)
            .map(Self)
            .ok_or(Error::InvalidKey)
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bech32::encode_lower_to_fmt::<Bech32, _>(
            f,
            Hrp::parse("age").expect("constant HRP"),
            &self.0,
        )
        .map_err(|_| fmt::Error)
    }
}

fn decode_key(encoded: &str, hrp: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    if encoded.len() != hrp.len() + 1 + 52 + 6 {
        return Err(Error::InvalidKey);
    }
    let checked = CheckedHrpstring::new::<Bech32>(encoded).map_err(|_| Error::InvalidKey)?;
    if checked.hrp() != Hrp::parse(hrp).expect("constant HRP") {
        return Err(Error::InvalidKey);
    }
    checked
        .validate_segwit_padding()
        .map_err(|_| Error::InvalidKey)?;
    let mut key = Zeroizing::new([0; 32]);
    let mut bytes = checked.byte_iter();
    for out in key.iter_mut() {
        *out = bytes.next().ok_or(Error::InvalidKey)?;
    }
    if bytes.next().is_some() {
        return Err(Error::InvalidKey);
    }
    Ok(key)
}

pub fn parse_identity_file(text: &OwnedSecret) -> Result<Vec<Identity>, Error> {
    check_size(text.len())?;
    let count = text
        .as_str()
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count();
    if count == 0 || count > MAX_DOCUMENT_BYTES / std::mem::size_of::<Identity>() {
        return Err(Error::InvalidKey);
    }
    let mut identities = Vec::new();
    identities
        .try_reserve_exact(count)
        .map_err(|_| Error::Allocation)?;
    for line in text
        .as_str()
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        identities.push(Identity::parse(line)?);
    }
    Ok(identities)
}
