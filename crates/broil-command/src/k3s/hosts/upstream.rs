// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, require};
use crate::images::infrastructure_io::json::Value as Private;
use serde_json::Value;

pub(super) const DOCUMENT_LIMIT: usize = 262_144;
pub(super) const SIZE_CEILING: u64 = 4_294_967_296;
const ENTRY_LIMIT: usize = 256;
const STRING_LIMIT: usize = 4096;
const ANNOTATION_LIMIT: usize = 16;
const ANNOTATION_KEY_LIMIT: usize = 256;
const ANNOTATION_VALUE_LIMIT: usize = 1024;

pub(super) const ROOT_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];
pub(super) const MANIFEST_TYPES: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];
pub(super) const CONFIG_TYPES: [&str; 2] = [
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
];
pub(super) const LAYER_TYPES: [&str; 2] = [
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
];
pub(super) const GENERIC_LAYER_TYPES: [&str; 3] = [
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.oci.image.layer.v1.tar",
];

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    require(bytes.len() <= DOCUMENT_LIMIT, Failure::Bound)?;
    let strict = Private::parse_bounded(bytes, DOCUMENT_LIMIT, 16)?;
    require(strict.raw().first() == Some(&b'{'), Failure::Integrity)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Failure::Integrity)?;
    bounded(&value, 1)?;
    Ok(value)
}

fn bounded(value: &Value, depth: usize) -> Result<()> {
    require(depth <= 16, Failure::Bound)?;
    match value {
        Value::Object(members) => {
            require(members.len() <= ENTRY_LIMIT, Failure::Bound)?;
            for (key, member) in members {
                require(key.len() <= STRING_LIMIT, Failure::Bound)?;
                bounded(member, depth + 1)?;
            }
        }
        Value::Array(items) => {
            require(items.len() <= ENTRY_LIMIT, Failure::Bound)?;
            for item in items {
                bounded(item, depth + 1)?;
            }
        }
        Value::String(text) => require(text.len() <= STRING_LIMIT, Failure::Bound)?,
        Value::Number(number) => require(
            number.as_u64().is_some_and(|n| n <= SIZE_CEILING),
            Failure::Integrity,
        )?,
        Value::Bool(_) | Value::Null => {}
    }
    Ok(())
}

pub(super) fn hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) struct Descriptor<'a> {
    pub media_type: &'a str,
    pub digest: &'a str,
    pub size: u64,
    pub platform: Option<&'a Value>,
    pub annotations: Option<&'a Value>,
}

pub(super) fn descriptor(value: &Value) -> Result<Descriptor<'_>> {
    let members = value.as_object().ok_or(Failure::Integrity)?;
    require(
        members.keys().all(|k| {
            matches!(
                k.as_str(),
                "mediaType" | "digest" | "size" | "platform" | "annotations"
            )
        }),
        Failure::Integrity,
    )?;
    let media_type = members
        .get("mediaType")
        .and_then(Value::as_str)
        .ok_or(Failure::Integrity)?;
    let digest = members
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|d| d.strip_prefix("sha256:"))
        .filter(|d| hex(d, 64))
        .ok_or(Failure::Integrity)?;
    let size = members
        .get("size")
        .and_then(Value::as_u64)
        .filter(|s| *s <= SIZE_CEILING)
        .ok_or(Failure::Integrity)?;
    let platform = members.get("platform");
    if let Some(platform) = platform {
        let fields = platform.as_object().ok_or(Failure::Integrity)?;
        require(
            fields.keys().all(|k| {
                matches!(
                    k.as_str(),
                    "os" | "architecture" | "variant" | "os.version" | "os.features" | "features"
                )
            }) && fields.get("os").is_some_and(Value::is_string)
                && fields.get("architecture").is_some_and(Value::is_string),
            Failure::Integrity,
        )?;
    }
    let annotations = members.get("annotations");
    if let Some(annotations) = annotations {
        let map = annotations.as_object().ok_or(Failure::Integrity)?;
        require(map.len() <= ANNOTATION_LIMIT, Failure::Bound)?;
        for (key, item) in map {
            require(
                key.len() <= ANNOTATION_KEY_LIMIT
                    && item
                        .as_str()
                        .is_some_and(|v| v.len() <= ANNOTATION_VALUE_LIMIT),
                Failure::Integrity,
            )?;
        }
    }
    Ok(Descriptor {
        media_type,
        digest,
        size,
        platform,
        annotations,
    })
}

pub(super) fn platform_pair(platform: &Value) -> Option<(&str, &str)> {
    Some((
        platform.get("os")?.as_str()?,
        platform.get("architecture")?.as_str()?,
    ))
}

pub(super) fn admitted_tuple(platform: &Value) -> bool {
    platform.as_object().is_some_and(|fields| {
        fields.len() == 2 && platform_pair(platform) == Some(("linux", "amd64"))
    })
}

