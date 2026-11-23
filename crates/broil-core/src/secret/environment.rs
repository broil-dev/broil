// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Credential environment capture. Production moves allocations; injected inputs are borrowed.

use super::OwnedSecret;
use crate::secrets::CREDENTIAL_INPUTS;
use std::{
    ffi::{OsStr, OsString},
    fmt,
    os::unix::ffi::{OsStrExt, OsStringExt},
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    SizeLimit,
    Allocation,
    InvalidUtf8,
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);
impl SecretBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn into_secret(mut self) -> Result<OwnedSecret, InputError> {
        std::str::from_utf8(&self.0).map_err(|_| InputError::InvalidUtf8)?;
        Ok(OwnedSecret::from_zeroizing(Zeroizing::new(
            String::from_utf8(std::mem::take(&mut *self.0)).expect("validated UTF-8"),
        )))
    }
    fn copy_from(value: &[u8]) -> Result<Self, InputError> {
        if value.len() > MAX_INPUT_BYTES {
            return Err(InputError::SizeLimit);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(value.len())
            .map_err(|_| InputError::Allocation)?;
        bytes.extend_from_slice(value);
        Ok(Self(bytes))
    }
}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();
        debug_assert!(
            self.0.iter().all(|b| *b == 0),
            "credential wipe before deallocation"
        );
    }
}

#[derive(Default)]
pub struct CredentialInputs {
    values: [Option<Result<SecretBytes, InputError>>; 5],
    /// Public ambient selection input; config child env_vars never populate it.
    pub vault_address: Option<OsString>,
}
impl fmt::Debug for CredentialInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialInputs([REDACTED])")
    }
}
pub fn is_credential_input(name: &OsStr) -> bool {
    CREDENTIAL_INPUTS.iter().any(|n| name == *n)
}

/// Copy only ordinary inputs; never create printable copies of credential values.
pub fn ordinary_snapshot(env: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    env.iter()
        .filter(|(name, _)| !is_credential_input(name))
        .cloned()
        .collect()
}

impl CredentialInputs {
    /// Independent bounded holders for one consumer. Capture errors remain tied
    /// to their source so an unused, lower-priority input cannot fail selection.
    pub fn try_duplicate(&self) -> Result<Self, InputError> {
        let mut inputs = Self {
            vault_address: self.vault_address.clone(),
            ..Self::default()
        };
        for (target, source) in inputs.values.iter_mut().zip(&self.values) {
            *target = match source {
                Some(Ok(value)) => Some(Ok(SecretBytes::copy_from(value.as_bytes())?)),
                Some(Err(error)) => Some(Err(*error)),
                None => None,
            };
        }
        Ok(inputs)
    }

    /// Selection/prompt estimation only; failed capture is still an explicit source.
    pub fn contains(&self, name: &str) -> bool {
        let index = CREDENTIAL_INPUTS
            .iter()
            .position(|n| *n == name)
            .expect("known input name");
        match &self.values[index] {
            Some(Ok(value)) => !value.as_bytes().is_empty(),
            Some(Err(_)) => true,
            None => false,
        }
    }

    /// Retain the optional identity-name input for a later credential-file lookup
    /// without consuming the identity acquisition caller's copy.
    pub fn duplicate_identity_name(&self) -> Result<Option<OwnedSecret>, InputError> {
        let index = CREDENTIAL_INPUTS
            .iter()
            .position(|name| *name == "BROIL_SECRETS_IDENTITY")
            .expect("known input name");
        match self.values[index].as_ref() {
            None => Ok(None),
            Some(Err(error)) => Err(*error),
            Some(Ok(value)) if value.as_bytes().is_empty() => Ok(None),
            Some(Ok(value)) => Ok(Some(
                SecretBytes::copy_from(value.as_bytes())?.into_secret()?,
            )),
        }
    }

    pub fn capture(
        env: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> (Vec<(OsString, OsString)>, Self) {
        let (mut ordinary, mut inputs) = (Vec::new(), Self::default());
        for (name, value) in env {
            if let Some(index) = CREDENTIAL_INPUTS.iter().position(|n| name == *n) {
                let value = SecretBytes(Zeroizing::new(value.into_vec()));
                if inputs.values[index].is_none() {
                    inputs.values[index] = Some(if value.as_bytes().len() > MAX_INPUT_BYTES {
                        Err(InputError::SizeLimit)
                    } else {
                        Ok(value)
                    });
                }
            } else {
                if name == "BAO_ADDR" && inputs.vault_address.is_none() {
                    inputs.vault_address = Some(value.clone());
                }
                ordinary.push((name, value));
            }
        }
        (ordinary, inputs)
    }
    pub fn borrowed(env: &[(OsString, OsString)]) -> Self {
        let mut inputs = Self::default();
        for (name, value) in env {
            if name == "BAO_ADDR" && inputs.vault_address.is_none() {
                inputs.vault_address = Some(value.clone());
            }
            if let Some(index) = CREDENTIAL_INPUTS.iter().position(|n| name == *n) {
                if inputs.values[index].is_none() {
                    inputs.values[index] = Some(SecretBytes::copy_from(value.as_bytes()));
                }
            }
        }
        inputs
    }
    /// Empty inputs count as absent; a failed bounded capture counts as selected.
    pub fn take(&mut self, name: &str) -> Result<Option<SecretBytes>, InputError> {
        let index = CREDENTIAL_INPUTS
            .iter()
            .position(|n| *n == name)
            .expect("known input name");
        Ok(self.values[index]
            .take()
            .transpose()?
            .filter(|v| !v.as_bytes().is_empty()))
    }
}

