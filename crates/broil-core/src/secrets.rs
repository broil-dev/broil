// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Reference-only secrets declarations and pure syntax rules. No secret I/O.

use std::{collections::BTreeMap, path::Path};

/// Decode only a public age X25519 recipient. Private identity parsing stays in
/// broil-secrets and its zeroizing boundary.
pub fn parse_age_recipient(encoded: &str) -> Option<[u8; 32]> {
    use bech32::{Bech32, Hrp, primitives::decode::CheckedHrpstring};
    if encoded.len() != 62 {
        return None;
    }
    let checked = CheckedHrpstring::new::<Bech32>(encoded).ok()?;
    if checked.hrp() != Hrp::parse("age").expect("constant HRP") {
        return None;
    }
    checked.validate_segwit_padding().ok()?;
    let mut key = [0; 32];
    let mut bytes = checked.byte_iter();
    for out in &mut key {
        *out = bytes.next()?;
    }
    bytes.next().is_none().then_some(key)
}

pub const CREDENTIAL_INPUTS: [&str; 5] = [
    "SOPS_AGE_KEY",
    "SOPS_AGE_KEY_FILE",
    "BROIL_SECRETS_IDENTITY",
    "BROIL_SECRETS_PASSPHRASE",
    "BAO_TOKEN",
];
pub const MAX_TEMPLATE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SecretsConfig {
    pub store: Option<String>,
    pub project: Option<String>,
    pub set: Option<String>,
    pub identity: Option<String>,
    pub inject: Option<bool>,
    pub exports: BTreeMap<String, Export>,
    pub vault: VaultConfig,
    pub rotation: RotationConfig,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VaultConfig {
    pub address: Option<String>,
    pub mount: Option<String>,
    pub credential: Option<String>,
    pub fallback: Option<Fallback>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Fallback {
    #[default]
    None,
    Local,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RotationConfig {
    pub deploy: Option<String>,
    pub handlers: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Export {
    pub set: Option<String>,
    pub value: ExportValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportValue {
    Key(String),
    Template(Vec<TemplatePart>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TemplatePart {
    Literal(String),
    Key(String),
}

impl SecretsConfig {
    /// Overlay an already selected environment; retain declaration presence.
    pub fn overlay(&self, env: &Self) -> Self {
        let mut result = self.clone();
        macro_rules! scalar {
            ($($field:ident).+) => {
                if env.$($field).+.is_some() { result.$($field).+ = env.$($field).+.clone(); }
            };
        }
        scalar!(store);
        scalar!(project);
        scalar!(set);
        scalar!(identity);
        result.inject = env.inject.or(self.inject);
        scalar!(vault.address);
        scalar!(vault.mount);
        scalar!(vault.credential);
        result.vault.fallback = env.vault.fallback.or(self.vault.fallback);
        scalar!(rotation.deploy);
        result.exports.extend(env.exports.clone());
        result
            .rotation
            .handlers
            .extend(env.rotation.handlers.clone());
        result
    }
}

pub fn valid_component(name: &str) -> bool {
    !name.is_empty()
        && !matches!(name, "." | "..")
        && !name.starts_with('-')
        && !name.contains(['/', '\\', '\0'])
}
pub fn valid_project(name: &str) -> bool {
    valid_component(name) && !matches!(name, "keys" | "credentials" | "policies" | "handlers")
}
pub fn valid_relative_file(name: &str) -> bool {
    !name.contains(['\\', '\0']) && name.split('/').all(|p| !matches!(p, "" | "." | ".."))
}
pub fn valid_set(name: &str, explicit: bool) -> bool {
    let count = name.split('/').count();
    valid_relative_file(name)
        && count <= 128
        && (!explicit || count >= 2)
        && Path::new(name).extension().is_none()
        && (count == 1 || valid_project(name.split('/').next().unwrap()))
}
pub fn valid_key(name: &str) -> bool {
    !name.is_empty()
        && !matches!(name, "_broil" | "sops")
        && !name.contains('\0')
        && name.len() <= 1024 * 1024
}
pub fn identifier(name: &str) -> bool {
    let mut chars = name.bytes();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}
pub fn valid_export_name(name: &str) -> bool {
    identifier(name)
        && !CREDENTIAL_INPUTS.contains(&name)
        && !matches!(
            name,
            "BROIL_ROOT"
                | "BROIL_ENV"
                | "BROIL_PROMPT_NAMES"
                | "BROIL_PS1_BASE"
                | "BROIL_LAST_STATUS"
        )
}

/// Parse only public configuration text; returned tokens contain no resolved values.
pub fn template(text: &str) -> Option<Vec<TemplatePart>> {
    if text.len() > MAX_TEMPLATE_BYTES {
        return None;
    }
    let mut parts = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find('$') {
        if at > 0 {
            parts.push(TemplatePart::Literal(rest[..at].into()));
        }
        rest = &rest[at + 1..];
        if let Some(tail) = rest.strip_prefix('$') {
            parts.push(TemplatePart::Literal("$".into()));
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('{') {
            let end = tail.find('}')?;
            let key = &tail[..end];
            if !identifier(key) || !valid_key(key) {
                return None;
            }
            parts.push(TemplatePart::Key(key.into()));
            rest = &tail[end + 1..];
        } else {
            return None;
        }
    }
    if !rest.is_empty() {
        parts.push(TemplatePart::Literal(rest.into()));
    }
    Some(parts)
}

/// Absolute HTTP(S) address syntax, without credentials or URL suffix state.
pub fn valid_address(address: &str) -> bool {
    let Some((scheme, rest)) = address.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    if !address.is_ascii()
        || address.bytes().any(|c| c <= 32 || c == 127)
        || rest.contains(['?', '#', '\\'])
    {
        return false;
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.contains('@') {
        return false;
    }
    let port = if let Some(ip) = authority.strip_prefix('[') {
        let Some((host, tail)) = ip.split_once(']') else {
            return false;
        };
        let future = host
            .strip_prefix('v')
            .or_else(|| host.strip_prefix('V'))
            .and_then(|h| h.split_once('.'))
            .is_some_and(|(version, address)| {
                !version.is_empty()
                    && version.bytes().all(|b| b.is_ascii_hexdigit())
                    && !address.is_empty()
                    && address
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:".contains(&b))
            });
        if host.parse::<std::net::Ipv6Addr>().is_err() && !future {
            return false;
        }
        if tail.is_empty() {
            None
        } else if let Some(port) = tail.strip_prefix(':') {
            Some(port)
        } else {
            return false;
        }
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(h, p)| (h, Some(p)));
        if host.is_empty() || !uri_component(host, false) {
            return false;
        }
        port
    };
    if port.is_some_and(|p| {
        !p.is_empty() && (!p.bytes().all(|c| c.is_ascii_digit()) || p.parse::<u16>().is_err())
    }) {
        return false;
    }
    uri_component(path, true)
}

// RFC 3986, sections 3.2.2 and 3.3: reg-name and path syntax. Resolution is deferred.
fn uri_component(value: &str, path: bool) -> bool {
    let mut bytes = value.bytes();
    while let Some(c) = bytes.next() {
        if c == b'%' {
            if !bytes.next().is_some_and(|c| c.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|c| c.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !(c.is_ascii_alphanumeric()
            || b"-._~!$&'()*+,;=".contains(&c)
            || path && b":/@".contains(&c))
        {
            return false;
        }
    }
    true
}
