// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use data_encoding::BASE64;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::path_safety::{
    CapabilityError, defensive_open, defensive_open_parent, effective_uid, random_bytes,
};
use crate::{FailureClass, HostKey};

pub const HASHED_HOST_SALT_LEN: usize = 20;
const VERIFIABLE: &[&str] = &[
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

#[derive(Debug)]
pub struct StoreError {
    class: FailureClass,
    diagnostic: String,
}

impl StoreError {
    fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn class(&self) -> FailureClass {
        self.class
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.diagnostic)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasState {
    Unknown,
    Pinned(HostKey),
    Replaceable {
        prior: Vec<HostKey>,
        duplicate: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    Enroll,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    Applied,
    AlreadyTrusted,
}

#[derive(Debug, Clone)]
pub struct KnownHostsStore {
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    bytes: Vec<u8>,
}

impl KnownHostsStore {
    pub fn open_default(home: &Path) -> Result<Self, StoreError> {
        let broil = home.join(".broil");
        create_private_dir_if_absent(&broil)?;
        validate_owned_dir(&broil, false)?;
        let ssh = broil.join("ssh");
        create_private_dir_if_absent(&ssh)?;
        validate_owned_dir(&ssh, true)?;
        Self::open_path(ssh.join("known_hosts"))
    }

    pub fn open_override(path: &Path) -> Result<Self, StoreError> {
        Self::open_path(path.to_path_buf())
    }

    fn open_path(path: PathBuf) -> Result<Self, StoreError> {
        open_or_create_store_file(&path).map(drop)?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot(&self) -> Result<Snapshot, StoreError> {
        validate_store_file(&self.path)?;
        let mut file = defensive_open(&self.path, false).map_err(capability_error)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(path_error)?;
        Ok(Snapshot { bytes })
    }

    pub fn commit(
        &self,
        alias: &str,
        expected: &AliasState,
        key: &HostKey,
        mutation: Mutation,
    ) -> Result<CommitOutcome, StoreError> {
        let lock_path = self.path.with_extension("lock");
        let lock = open_private_file(&lock_path)?;
        rustix::fs::flock(lock.as_fd(), rustix::fs::FlockOperation::LockExclusive)
            .map_err(path_error)?;
        let current = self.snapshot()?;
        let observed = current.inspect(alias, matches!(mutation, Mutation::Replace))?;
        if &observed != expected {
            if matches!(&observed, AliasState::Pinned(current) if same_key(current, key)) {
                return Ok(CommitOutcome::AlreadyTrusted);
            }
            return Err(StoreError::new(
                FailureClass::ChangedHostKey,
                "known-hosts state changed while trust was being confirmed",
            ));
        }

        let mut output = Vec::with_capacity(current.bytes.len() + 256);
        if matches!(mutation, Mutation::Replace) {
            for raw in current.bytes.split_inclusive(|byte| *byte == b'\n') {
                if !line_matches_alias(raw, alias) {
                    output.extend_from_slice(raw);
                }
            }
        } else {
            output.extend_from_slice(&current.bytes);
        }
        if !output.is_empty() && !output.ends_with(b"\n") {
            output.push(b'\n');
        }
        let mut salt = [0u8; HASHED_HOST_SALT_LEN];
        random_bytes(&mut salt).map_err(capability_error)?;
        let host = hashed_host(&salt, alias).map_err(capability_error)?;
        writeln!(output, "{host} {} {}", key.algorithm, key.base64).map_err(path_error)?;

        let nonce = getrandom::u64().map_err(|_| {
            StoreError::new(
                FailureClass::TransferPathSafety,
                "cannot create known-hosts temporary file",
            )
        })?;
        let temp = self.path.with_extension(format!("tmp.{nonce:016x}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(path_error)?;
        file.write_all(&output).map_err(path_error)?;
        file.sync_all().map_err(path_error)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(path_error)?;
        fs::rename(&temp, &self.path).map_err(path_error)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(path_error)?;
        }
        Ok(CommitOutcome::Applied)
    }
}

impl Snapshot {
    pub fn inspect(&self, alias: &str, replace: bool) -> Result<AliasState, StoreError> {
        let matches = matching_lines(&self.bytes, alias);
        if matches.iter().any(|line| line.marker) {
            return Err(StoreError::new(
                FailureClass::Configuration,
                "matching known-hosts marker requires manual remediation",
            ));
        }
        if matches.is_empty() {
            return Ok(AliasState::Unknown);
        }
        let keys = matches
            .iter()
            .filter_map(|line| line.key.clone())
            .collect::<Vec<_>>();
        if matches.len() == 1 && keys.len() == 1 && VERIFIABLE.contains(&keys[0].algorithm.as_str())
        {
            return Ok(AliasState::Pinned(keys[0].clone()));
        }
        if replace {
            return Ok(AliasState::Replaceable {
                prior: keys,
                duplicate: matches.len() > 1,
            });
        }
        let diagnostic = matches
            .iter()
            .filter_map(|line| line.algorithm.as_deref())
            .find(|algorithm| !VERIFIABLE.contains(algorithm))
            .map(|algorithm| {
                format!(
                    "stored key type {} is outside the v1 verifiable-algorithm boundary; use --replace after inspection",
                    algorithm
                )
            })
            .unwrap_or_else(|| {
                if keys.is_empty() {
                    "matching known-hosts entry is malformed; use --replace after inspection"
                        .to_string()
                } else {
                    "matching known-hosts entries are duplicated; use --replace after inspection"
                        .to_string()
                }
            });
        Err(StoreError::new(FailureClass::Configuration, diagnostic))
    }

    pub fn matching_line_count(&self, alias: &str) -> usize {
        matching_lines(&self.bytes, alias).len()
    }
}

#[derive(Clone)]
struct ParsedLine {
    marker: bool,
    algorithm: Option<String>,
    key: Option<HostKey>,
}

fn matching_lines(bytes: &[u8], alias: &str) -> Vec<ParsedLine> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| parse_matching_line(line, alias))
        .collect()
}

fn line_matches_alias(line: &[u8], alias: &str) -> bool {
    parse_matching_line(line.strip_suffix(b"\n").unwrap_or(line), alias).is_some()
}

fn parse_matching_line(line: &[u8], alias: &str) -> Option<ParsedLine> {
    let text = std::str::from_utf8(line).ok()?;
    let fields = text.split_whitespace().collect::<Vec<_>>();
    if fields.is_empty() || fields[0].starts_with('#') {
        return None;
    }
    let (marker, host_index) = if fields[0].starts_with('@') {
        (true, 1)
    } else {
        (false, 0)
    };
    let hosts = *fields.get(host_index)?;
    if !hosts.split(',').any(|host| host_matches(host, alias)) {
        return None;
    }
    let algorithm = fields.get(host_index + 1).map(|value| (*value).to_string());
    let base64 = fields.get(host_index + 2).map(|value| (*value).to_string());
    let key = algorithm
        .as_ref()
        .zip(base64)
        .and_then(|(algorithm, base64)| {
            let parsed = russh::keys::parse_public_key_base64(&base64).ok()?;
            if parsed.algorithm().to_string() != *algorithm {
                return None;
            }
            Some(HostKey {
                fingerprint: parsed.fingerprint(russh::keys::HashAlg::Sha256).to_string(),
                algorithm: algorithm.clone(),
                base64,
            })
        });
    Some(ParsedLine {
        marker,
        algorithm,
        key,
    })
}

fn host_matches(host: &str, alias: &str) -> bool {
    if host == alias {
        return true;
    }
    let Some(encoded) = host.strip_prefix("|1|") else {
        return false;
    };
    let Some((salt, _)) = encoded.split_once('|') else {
        return false;
    };
    let Ok(salt) = BASE64.decode(salt.as_bytes()) else {
        return false;
    };
    hashed_host(&salt, alias).is_ok_and(|candidate| candidate == host)
}

type HmacSha1 = Hmac<Sha1>;

pub fn hashed_host(salt: &[u8], host: &str) -> Result<String, CapabilityError> {
    if salt.len() != HASHED_HOST_SALT_LEN {
        return Err(CapabilityError::Randomness);
    }
    let mut mac = HmacSha1::new_from_slice(salt).map_err(|_| CapabilityError::Randomness)?;
    mac.update(host.as_bytes());
    Ok(format!(
        "|1|{}|{}",
        BASE64.encode(salt),
        BASE64.encode(&mac.finalize().into_bytes())
    ))
}

fn create_private_dir_if_absent(path: &Path) -> Result<(), StoreError> {
    if !path.exists() {
        fs::create_dir(path).map_err(path_error)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(path_error)?;
    }
    Ok(())
}

fn validate_owned_dir(path: &Path, private: bool) -> Result<(), StoreError> {
    let metadata = fs::symlink_metadata(path).map_err(path_error)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()
        || (private && metadata.mode() & 0o077 != 0)
    {
        return Err(StoreError::new(
            FailureClass::TransferPathSafety,
            "known-hosts directory must be owned by the current user with mode 0700",
        ));
    }
    Ok(())
}

fn validate_store_file(path: &Path) -> Result<(), StoreError> {
    let file = defensive_open(path, false).map_err(capability_error)?;
    validate_store_descriptor(&file)
}

fn open_or_create_store_file(path: &Path) -> Result<File, StoreError> {
    let (parent, name) = defensive_open_parent(path).map_err(capability_error)?;
    let flags =
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC;
    let (descriptor, created) =
        match rustix::fs::openat(&parent, &name, flags, rustix::fs::Mode::empty()) {
            Ok(descriptor) => (descriptor, false),
            Err(rustix::io::Errno::NOENT) => (
                rustix::fs::openat(
                    &parent,
                    &name,
                    flags | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                )
                .map_err(path_error)?,
                true,
            ),
            Err(error) => return Err(path_error(error)),
        };
    let file = File::from(descriptor);
    if created {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(path_error)?;
    }
    validate_store_descriptor(&file)?;
    Ok(file)
}

fn validate_store_descriptor(file: &File) -> Result<(), StoreError> {
    let metadata = file.metadata().map_err(path_error)?;
    if !metadata.is_file() || metadata.uid() != effective_uid() || metadata.mode() & 0o777 != 0o600
    {
        return Err(StoreError::new(
            FailureClass::TransferPathSafety,
            "known-hosts store must be a user-owned regular file with mode 0600",
        ));
    }
    Ok(())
}

fn same_key(left: &HostKey, right: &HostKey) -> bool {
    left.algorithm == right.algorithm && left.base64 == right.base64
}

fn open_private_file(path: &Path) -> Result<File, StoreError> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .map_err(path_error)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(path_error)?;
    if !metadata.is_file() || metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
        return Err(StoreError::new(
            FailureClass::TransferPathSafety,
            "known-hosts lock file is unsafe",
        ));
    }
    Ok(file)
}

fn capability_error(error: CapabilityError) -> StoreError {
    StoreError::new(
        FailureClass::TransferPathSafety,
        format!("unsafe known-hosts path: {error:?}"),
    )
}

fn path_error(error: impl fmt::Display) -> StoreError {
    StoreError::new(
        FailureClass::TransferPathSafety,
        format!("known-hosts path operation failed: {error}"),
    )
}
