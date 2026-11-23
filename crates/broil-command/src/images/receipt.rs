// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    common::*,
    content,
    json::Value,
    policy::{RegistryAction, RegistryRequest},
    supervise::Output,
};
use broil_core::images::reference::ImageReference;

pub(crate) fn frame(bytes: &[u8], maximum: u64) -> Result<Value<'_>> {
    require(bytes.len() >= 4, Failure::Protocol)?;
    let n = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| Failure::Protocol)?) as usize;
    require(
        n > 0 && n as u64 <= maximum && n <= 65_536 && bytes.len() == n + 4,
        Failure::Protocol,
    )?;
    Value::parse(&bytes[4..])
}

pub(crate) fn discovered(value: Value<'_>, path: &std::path::Path, kind: Kind) -> Result<Entry> {
    let f = value.object(&[b"path", b"device", b"inode", b"kind", b"ownership"])?;
    let entry = Entry {
        path: path.into(),
        device: f[1].number()?,
        inode: f[2].number()?,
        kind,
        ownership: Ownership::Operation,
    };
    require(value.matches(&entry.wire())?, Failure::Integrity)?;
    Ok(entry)
}

pub(crate) struct RegistryReceipt {
    pub failure: Option<Failure>,
    pub completion_uncertain: bool,
    pub cleanup_uncertain: bool,
    pub root: Option<Descriptor>,
    pub complete: bool,
    pub cache_miss: bool,
    pub verified_files: u64,
    pub verified_bytes: u64,
}

pub(crate) fn registry(
    output: &Output,
    request: &RegistryRequest,
    header: &serde_json::Value,
) -> Result<RegistryReceipt> {
    require(
        !output.observation.cancellation_requested
            && !output.observation.cleanup_uncertain
            && !output.observation.completion_uncertain
            && output.observation.signal.is_none(),
        Failure::Indeterminate,
    )?;
    let value = frame(
        &output.stdout.get()[..output.stdout_used],
        request.limit("result_bytes"),
    )?;
    let f = value.object(&[
        b"protocol_version",
        b"operation_id",
        b"status",
        b"failure_class",
        b"dispatch",
        b"completion_uncertain",
        b"cleanup_uncertain",
        b"root",
        b"closure_complete",
        b"verified_descriptors",
        b"verified_bytes",
        b"peak_staging_bytes",
    ])?;
    require(
        f[0].number()? == 1
            && f[1].matches(&header["operation_id"])?
            && f[11].number()?
                <= header["limits"]["staging_bytes"]
                    .as_u64()
                    .ok_or(Failure::Policy)?
            && f[9].number()? <= request.limit("descriptors")
            && f[10].number()? <= request.limit("content_bytes"),
        Failure::Protocol,
    )?;
    let succeeded = f[2].equals("succeeded")?;
    let failed = f[2].equals("failed")?;
    let cancelled = f[2].equals("cancelled")?;
    let unknown = f[2].equals("unknown")?;
    require(
        succeeded || failed || cancelled || unknown,
        Failure::Protocol,
    )?;
    let mut class = None;
    for name in [
        "none",
        "policy",
        "credential",
        "authentication",
        "trust",
        "protocol",
        "integrity",
        "cache-miss",
        "storage",
        "limit",
        "timeout",
        "cancellation",
        "indeterminate",
    ] {
        if f[3].equals(name)? {
            class = Some(name);
        }
    }
    let class = class.ok_or(Failure::Protocol)?;
    require(
        succeeded == (class == "none")
            && succeeded == (output.observation.exit_code == Some(0))
            && output.observation.exit_code.is_some()
            && (!unknown || f[5].boolean()?)
            && (!cancelled || class == "cancellation"),
        Failure::Protocol,
    )?;
    let read = f[4].equals("read")?;
    let write = f[4].equals("write")?;
    require(read || write || f[4].equals("none")?, Failure::Protocol)?;
    require(
        !write || request.action == RegistryAction::Upload,
        Failure::Protocol,
    )?;
    let complete = f[8].boolean()?;
    if !succeeded {
        require(f[7].is_null() && !complete, Failure::Protocol)?;
        if class == "cache-miss" {
            require(
                failed
                    && read
                    && !write
                    && !f[5].boolean()?
                    && !f[6].boolean()?
                    && f[9].number()? == 0
                    && f[10].number()? == 0
                    && request.cache
                    && request.action == RegistryAction::Fetch,
                Failure::Protocol,
            )?;
            return Ok(RegistryReceipt {
                failure: (!request.optional).then_some(Failure::CacheMiss),
                completion_uncertain: false,
                cleanup_uncertain: false,
                root: None,
                complete: false,
                cache_miss: request.optional,
                verified_files: 0,
                verified_bytes: 0,
            });
        }
        let failure = match class {
            "policy" => Failure::Policy,
            "credential" => Failure::Credential,
            "authentication" => Failure::Authentication,
            "trust" => Failure::Trust,
            "integrity" => Failure::Integrity,
            "storage" => Failure::Storage,
            "limit" => Failure::Limit,
            "timeout" => Failure::Timeout,
            "cancellation" => Failure::Cancellation,
            "protocol" => Failure::Protocol,
            _ => Failure::Indeterminate,
        };
        return Ok(RegistryReceipt {
            failure: Some(failure),
            completion_uncertain: f[5].boolean()?,
            cleanup_uncertain: f[6].boolean()?,
            root: None,
            complete: false,
            cache_miss: false,
            verified_files: f[9].number()?,
            verified_bytes: f[10].number()?,
        });
    }
    require(
        !f[5].boolean()?
            && !f[6].boolean()?
            && f[9].number()? > 0
            && f[10].number()? > 0
            && (if request.action == RegistryAction::Upload {
                write
            } else {
                read
            })
            && complete == (request.action != RegistryAction::Inspect),
        Failure::Protocol,
    )?;
    let root = content::descriptor(f[7], true)?;
    require(
        content::root_media(&root.media_type)
            && request.expected_root.as_ref().is_none_or(|d| *d == root)
            && ImageReference::parse(&request.reference)
                .ok_or(Failure::Policy)?
                .digest
                .as_ref()
                .is_none_or(|digest| *digest == root.digest),
        Failure::Integrity,
    )?;
    Ok(RegistryReceipt {
        failure: None,
        completion_uncertain: false,
        cleanup_uncertain: false,
        root: Some(root),
        complete,
        cache_miss: false,
        verified_files: f[9].number()?,
        verified_bytes: f[10].number()?,
    })
}
