// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Public identities and finite bounds shared with the one-job filesystem helper.

use std::path::{Component, Path, PathBuf};

use serde_json::{Value, json};

pub type Result<T> = std::result::Result<T, Failure>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Policy,
    Credential,
    Authentication,
    Trust,
    CacheMiss,
    Protocol,
    Integrity,
    Storage,
    Limit,
    Timeout,
    Cancellation,
    Indeterminate,
    Capacity,
    Tool,
}

impl Failure {
    #[allow(dead_code)] // The filesystem binary serializes this closed failure subset.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Protocol => "protocol",
            Self::Integrity => "integrity",
            Self::Storage => "storage",
            Self::Limit => "limit",
            Self::Timeout => "timeout",
            Self::Cancellation => "cancellation",
            Self::Indeterminate
            | Self::Capacity
            | Self::Tool
            | Self::Credential
            | Self::Authentication
            | Self::Trust
            | Self::CacheMiss => "indeterminate",
        }
    }
}

pub(crate) fn require(ok: bool, failure: Failure) -> Result<()> {
    if ok { Ok(()) } else { Err(failure) }
}

pub(crate) fn monotonic_ns() -> u64 {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}

pub(crate) fn before(deadline: u64) -> Result<()> {
    require(monotonic_ns() < deadline, Failure::Timeout)
}

pub(crate) fn deadline(start: u64, milliseconds: u64) -> Result<u64> {
    start
        .checked_add(milliseconds.checked_mul(1_000_000).ok_or(Failure::Limit)?)
        .ok_or(Failure::Limit)
}

pub(crate) fn valid_operation(value: &str) -> bool {
    value.len() == 42 && value.starts_with("operation-") && hex(&value.as_bytes()[10..])
}

pub(crate) fn hex(value: &[u8]) -> bool {
    value
        .iter()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

pub(crate) fn valid_path(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    if !path.is_absolute() || text.len() > 4096 || text.contains('\0') {
        return false;
    }
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::RootDir => normalized.push("/"),
            Component::Normal(part) if part.len() <= 255 => normalized.push(part),
            _ => return false,
        }
    }
    normalized.as_os_str() == path.as_os_str()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ownership {
    Operation,
    Borrowed,
    Retained,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub kind: Kind,
    pub ownership: Ownership,
}

impl Entry {
    pub(crate) fn wire(&self) -> Value {
        json!({
            "path": self.path,
            "device": self.device,
            "inode": self.inode,
            "kind": if self.kind == Kind::File { "file" } else { "directory" },
            "ownership": match self.ownership {
                Ownership::Operation => "operation", Ownership::Borrowed => "borrowed",
                Ownership::Retained => "retained",
            },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

impl Descriptor {
    pub(crate) fn validate(&self) -> Result<()> {
        require(
            self.digest.len() == 71
                && self.digest.starts_with("sha256:")
                && hex(&self.digest.as_bytes()[7..])
                && self.media_type.len() <= 128,
            Failure::Policy,
        )
    }
    pub(crate) fn wire(&self) -> Value {
        json!({"digest": self.digest, "size": self.size, "media_type": self.media_type})
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Content {
    File {
        digest: String,
        size: u64,
    },
    Oci {
        root: Descriptor,
        cache: bool,
        complete: bool,
        registry_receipt: bool,
    },
}

impl Content {
    pub(crate) fn wire(&self) -> Value {
        match self {
            Self::File { digest, size } => json!({"kind":"file", "digest":digest, "size":size}),
            Self::Oci {
                root,
                cache,
                complete,
                registry_receipt,
            } => json!({
                "kind":"oci", "root":root.wire(), "content_kind":if *cache {"cache"} else {"image"},
                "completeness":if *complete {"complete"} else {"metadata"},
                "registry_receipt":registry_receipt,
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentLimits {
    pub staging_bytes: u64,
    pub entries: u64,
    pub metadata_bytes: u64,
    pub blob_bytes: u64,
    pub content_bytes: u64,
    pub descriptors: u64,
    pub descriptor_edges: u64,
    pub graph_depth: u64,
    pub content_json_depth: u64,
}

impl Default for ContentLimits {
    fn default() -> Self {
        Self {
            staging_bytes: 5_368_709_120,
            entries: 65_536,
            metadata_bytes: 16_777_216,
            blob_bytes: 1_073_741_824,
            content_bytes: 4_294_967_296,
            descriptors: 4096,
            descriptor_edges: 8192,
            graph_depth: 32,
            content_json_depth: 128,
        }
    }
}

impl ContentLimits {
    pub(crate) fn wire(&self) -> Value {
        json!({"staging_bytes":self.staging_bytes, "entries":self.entries,
            "metadata_bytes":self.metadata_bytes, "blob_bytes":self.blob_bytes,
            "content_bytes":self.content_bytes, "descriptors":self.descriptors,
            "descriptor_edges":self.descriptor_edges, "graph_depth":self.graph_depth,
            "content_json_depth":self.content_json_depth})
    }
    pub fn validate(&self) -> Result<()> {
        let maximum = Self::default().wire();
        for (key, value) in self.wire().as_object().ok_or(Failure::Policy)? {
            let n = value.as_u64().ok_or(Failure::Policy)?;
            require(
                n > 0 && n <= maximum[key].as_u64().ok_or(Failure::Policy)?,
                Failure::Limit,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub solve_ms: u64,
    pub metadata_ms: u64,
    pub handoff_ms: u64,
    pub idle_ms: u64,
    pub drain_ms: u64,
    pub cleanup_ms: u64,
    pub record_bytes: usize,
    pub stream_bytes: usize,
    pub records: usize,
    pub json_depth: usize,
    pub content: ContentLimits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            solve_ms: 1_800_000,
            metadata_ms: 30_000,
            handoff_ms: 10_000,
            idle_ms: 30_000,
            drain_ms: 100,
            cleanup_ms: 5000,
            record_bytes: 65_536,
            stream_bytes: 16_777_216,
            records: 65_536,
            json_depth: 16,
            content: ContentLimits::default(),
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        for (n, max) in [
            (self.solve_ms, 1_800_000),
            (self.metadata_ms, 30_000),
            (self.handoff_ms, 10_000),
            (self.idle_ms, 30_000),
            (self.drain_ms, 100),
            (self.cleanup_ms, 5000),
            (self.record_bytes as u64, 65_536),
            (self.stream_bytes as u64, 16_777_216),
            (self.records as u64, 65_536),
            (self.json_depth as u64, 16),
        ] {
            require(n > 0 && n <= max, Failure::Limit)?;
        }
        self.content.validate()
    }
}
