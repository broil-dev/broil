// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::index::{Asset, Index};
use super::upstream::hex;
use super::{Failure, Result, require};
use crate::images::infrastructure_io::json::Value as Private;
use crate::k3s::state::canonical;
use serde_json::Value;

pub(crate) const MANIFEST_LIMIT: usize = 32_768;
const URL_LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Online,
    Bundle,
}

impl Mode {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Bundle => "bundle",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Selected<'a> {
    pub asset: &'a Asset,
    pub url: Option<String>,
}

pub(crate) struct Manifest<'a> {
    pub document: Value,
    pub assets: Vec<Selected<'a>>,
}

fn label(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 63
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-')
}

fn ipv4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
                && p.parse::<u16>().is_ok_and(|v| v <= 255)
        })
}

fn host(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 253
        && (ipv4(text)
            || (text.split('.').all(label)
                && !text.bytes().all(|b| b.is_ascii_digit() || b == b'.')))
}

pub(crate) fn url(text: &str) -> Option<String> {
    if text.len() > URL_LIMIT || !text.is_ascii() {
        return None;
    }
    let rest = text.strip_prefix("https://")?;
    let (authority, path) = rest.split_at(rest.find('/')?);
    if authority.contains('@') || path.is_empty() {
        return None;
    }
    let (host_text, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if !host(host_text) {
        return None;
    }
    let port_value = match port {
        None => 443,
        Some(p) => {
            if p.is_empty()
                || p.len() > 5
                || !p.bytes().all(|b| b.is_ascii_digit())
                || p.starts_with('0')
            {
                return None;
            }
            p.parse::<u32>().ok().filter(|v| (1..=65535).contains(v))?
        }
    };
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'%' => {
                let code = bytes.get(index + 1..index + 3)?;
                let value = u8::from_str_radix(std::str::from_utf8(code).ok()?, 16).ok()?;
                if !code.iter().all(|c| c.is_ascii_hexdigit())
                    || value <= 0x20
                    || value >= 0x7f
                    || b"/\\?#@:.%".contains(&value)
                {
                    return None;
                }
                index += 3;
            }
            b'?' | b'#' | b'\\' => return None,
            0x21..=0x7e => index += 1,
            _ => return None,
        }
    }
    if path
        .split('/')
        .skip(1)
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return None;
    }
    Some(format!(
        "https://{}:{port_value}",
        host_text.to_ascii_lowercase()
    ))
}

pub(crate) fn admit<'a>(
    bytes: &[u8],
    index: &'a Index,
    mode: Mode,
    profile_sha256: &str,
    registry_origin: Option<&str>,
) -> Result<Manifest<'a>> {
    require(bytes.len() <= MANIFEST_LIMIT, Failure::Bound)?;
    let body = bytes.strip_suffix(b"\n").ok_or(Failure::Integrity)?;
    Private::parse_bounded(body, MANIFEST_LIMIT, 16)?;
    let document: Value = serde_json::from_slice(body).map_err(|_| Failure::Integrity)?;
    require(canonical(&document)? == body, Failure::Integrity)?;
    let members = document.as_object().ok_or(Failure::Integrity)?;
    require(
        members.len() == 5
            && ["schema", "profile_sha256", "platform", "version", "assets"]
                .iter()
                .all(|k| members.contains_key(*k)),
        Failure::Integrity,
    )?;
    require(
        members["schema"] == 1
            && members["platform"] == super::index::PLATFORM
            && members["version"] == index.version
            && members["profile_sha256"] == profile_sha256,
        Failure::Configuration,
    )?;
    let selected = index.selected(registry_origin.is_some());
    let entries = members["assets"].as_array().ok_or(Failure::Integrity)?;
    require(entries.len() == selected.len(), Failure::Configuration)?;
    let mut assets = Vec::new();
    for (entry, asset) in entries.iter().zip(selected) {
        let fields = entry.as_object().ok_or(Failure::Integrity)?;
        require(
            fields.len() == 5
                && ["id", "size", "sha256", "origin", "url"]
                    .iter()
                    .all(|k| fields.contains_key(*k)),
            Failure::Integrity,
        )?;
        require(
            fields["id"] == asset.id
                && fields["size"] == asset.size
                && fields["sha256"]
                    .as_str()
                    .is_some_and(|h| hex(h, 64) && h == asset.sha256)
                && fields["origin"] == asset.origin,
            Failure::Configuration,
        )?;
        let url = match (mode, &fields["url"]) {
            (Mode::Bundle, Value::Null) => None,
            (Mode::Online, Value::String(text)) => {
                let origin = url(text).ok_or(Failure::Configuration)?;
                require(
                    registry_origin.is_none_or(|registry| registry != origin),
                    Failure::Configuration,
                )?;
                Some(text.clone())
            }
            _ => return Err(Failure::Configuration),
        };
        assets.push(Selected { asset, url });
    }
    Ok(Manifest { document, assets })
}

