// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{ErrorKind, Result, Store, filesystem, validate_component};
use crate::age::{self, Identity, Recipient};
use broil_core::secret::{OwnedSecret, path_safety as safe};
use std::{ffi::OsStr, path::Path};
use zeroize::Zeroizing;

#[derive(Debug, Eq, PartialEq)]
pub enum IdentityNames {
    None,
    Sole(String),
    Multiple(Vec<String>),
}

impl Store {
    pub fn identity_names(&self) -> Result<IdentityNames> {
        self.root_current()?;
        if filesystem::open_entry(&self.directory, OsStr::new("keys"))?.is_none() {
            return Ok(IdentityNames::None);
        }
        let keys = filesystem::open_dir(&self.directory, OsStr::new("keys"))?;
        let mut names = Vec::new();
        for filename in filesystem::names(&keys)? {
            let filename = filename.to_str().ok_or(ErrorKind::InvalidName)?;
            let Some(name) = filename.strip_suffix(".key.age") else {
                continue;
            };
            validate_component(name)?;
            let file =
                filesystem::open_entry(&keys, OsStr::new(filename))?.ok_or(ErrorKind::Stale)?;
            safe::recheck_open_metadata(&file, false).map_err(|_| ErrorKind::UnsafePath)?;
            names.push(name.to_owned());
        }
        let current = filesystem::open_dir(&self.directory, OsStr::new("keys"))?;
        if !filesystem::same_inode(&keys, &current)? {
            return Err(ErrorKind::Stale.into());
        }
        self.root_current()?;
        names.sort();
        Ok(match names.len() {
            0 => IdentityNames::None,
            1 => IdentityNames::Sole(names.remove(0)),
            _ => IdentityNames::Multiple(names),
        })
    }

    pub fn unlock_identity(&self, name: &str, passphrase: &OwnedSecret) -> Result<Vec<Identity>> {
        validate_component(name)?;
        if passphrase.is_empty() {
            return Err(ErrorKind::Identity.into());
        }
        let mut target = self.target(format!("keys/{name}.key.age"), true, false)?;
        let bytes = target.load_bytes()?;
        let plaintext =
            age::decrypt(&bytes, &[], Some(passphrase)).map_err(|_| ErrorKind::Identity)?;
        drop(bytes);
        target.fresh(self)?;
        let secret = plaintext.into_secret().map_err(|_| ErrorKind::Identity)?;
        age::parse_identity_file(&secret).map_err(|_| ErrorKind::Identity.into())
    }

    pub fn recipient(&self, name: &str) -> Result<Recipient> {
        validate_component(name)?;
        let mut target = self.target(format!("keys/{name}.pub"), false, false)?;
        let text = target.load()?;
        let recipient = text
            .as_str()
            .trim()
            .parse()
            .map_err(|_| ErrorKind::Identity)?;
        target.fresh(self)?;
        Ok(recipient)
    }
}

pub fn read_raw_identity(path: &Path) -> Result<Vec<Identity>> {
    filesystem::absolute(path)?;
    let file = safe::defensive_open_validated(path, false).map_err(|_| ErrorKind::UnsafePath)?;
    let (mut bytes, snapshot) = filesystem::read(&file, true)?;
    std::str::from_utf8(&bytes).map_err(|_| ErrorKind::Identity)?;
    let current = safe::defensive_open_validated(path, false).map_err(|_| ErrorKind::Stale)?;
    let (_, actual) = filesystem::read(&current, true)?;
    if snapshot != actual {
        return Err(ErrorKind::Stale.into());
    }
    let secret = OwnedSecret::from_zeroizing(Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes)).expect("validated UTF-8"),
    ));
    age::parse_identity_file(&secret).map_err(|_| ErrorKind::Identity.into())
}
