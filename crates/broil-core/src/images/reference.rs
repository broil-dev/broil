// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Pure image identity and endpoint syntax.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Authority {
    /// Lowercase DNS name or canonical IP, without IPv6 brackets.
    pub host: String,
    /// Explicit port presence is retained; no default is inserted here.
    pub port: Option<u16>,
}

impl Authority {
    pub fn parse(value: &str) -> Option<Self> {
        if !public_ascii(value) || value.contains(['@', '/', '?', '#', '\\', '%']) {
            return None;
        }
        let (host, port) = if let Some(ip) = value.strip_prefix('[') {
            let (host, tail) = ip.split_once(']')?;
            let host = host.parse::<Ipv6Addr>().ok()?.to_string();
            let port = if tail.is_empty() {
                None
            } else {
                Some(parse_port(tail.strip_prefix(':')?)?)
            };
            (host, port)
        } else {
            let (host, port) = value
                .split_once(':')
                .map_or((value, None), |(h, p)| (h, Some(p)));
            let host = if let Ok(ip) = host.parse::<Ipv4Addr>() {
                if ip.to_string() != host {
                    return None;
                }
                ip.to_string()
            } else {
                if !valid_dns_name(host) {
                    return None;
                }
                host.to_ascii_lowercase()
            };
            (
                host,
                match port {
                    Some(port) => Some(parse_port(port)?),
                    None => None,
                },
            )
        };
        Some(Self { host, port })
    }
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            f.write_str(&self.host)?;
        }
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || !port.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().filter(|p| *p != 0)
}

pub fn valid_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // Reject alternate numeric-address spellings, including octal/hex and short IPv4.
    if host.split('.').all(|label| {
        !label.is_empty()
            && (label.bytes().all(|c| c.is_ascii_digit())
                || label
                    .strip_prefix("0x")
                    .or_else(|| label.strip_prefix("0X"))
                    .is_some_and(|v| !v.is_empty() && v.bytes().all(|c| c.is_ascii_hexdigit())))
    }) {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    })
}

fn public_ascii(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|c| (33..=126).contains(&c))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageReference {
    pub supplied: String,
    pub repository: String,
    pub authority: Authority,
    /// Only a declared tag is stored here. See `effective_tag` for latest.
    pub tag: Option<String>,
    pub digest: Option<String>,
    pub latest_defaulted: bool,
    pub explicit_authority: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImageIdentity {
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl ImageReference {
    pub fn parse(value: &str) -> Option<Self> {
        if !public_ascii(value) {
            return None;
        }
        let (named, digest) = match value.split_once('@') {
            Some((name, digest)) => {
                let hex = digest.strip_prefix("sha256:")?;
                if hex.len() != 64
                    || !hex
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                {
                    return None;
                }
                (name, Some(digest.to_string()))
            }
            None => (value, None),
        };
        let (repository, tag) = match named.rfind(':') {
            Some(colon) if named.rfind('/').is_none_or(|slash| colon > slash) => {
                let tag = &named[colon + 1..];
                if !valid_tag(tag) {
                    return None;
                }
                (&named[..colon], Some(tag.to_string()))
            }
            _ => (named, None),
        };
        let explicit = repository
            .split_once('/')
            .filter(|(head, _)| head.contains(['.', ':']) || *head == "localhost");
        let (authority, path) = if let Some((host, path)) = explicit {
            (Authority::parse(host)?, path.to_string())
        } else {
            (Authority::parse("docker.io")?, repository.to_string())
        };
        if !path.split('/').all(valid_repository_component) {
            return None;
        }
        let path = if authority.host == "docker.io" && !path.contains('/') {
            format!("library/{path}")
        } else {
            path
        };
        let repository = format!("{authority}/{path}");
        if repository.len() > 255 {
            return None;
        }
        let latest_defaulted = tag.is_none() && digest.is_none();
        Some(Self {
            supplied: value.into(),
            repository,
            authority,
            tag,
            digest,
            latest_defaulted,
            explicit_authority: explicit.is_some(),
        })
    }

    pub fn effective_tag(&self) -> Option<&str> {
        self.tag.as_deref().or(if self.latest_defaulted {
            Some("latest")
        } else {
            None
        })
    }

    pub fn identity(&self) -> ImageIdentity {
        ImageIdentity {
            repository: self.repository.clone(),
            tag: self.effective_tag().map(String::from),
            digest: self.digest.clone(),
        }
    }

    pub fn is_normalized_repository(&self) -> bool {
        self.explicit_authority
            && self.supplied == self.repository
            && self.tag.is_none()
            && self.digest.is_none()
    }
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= 128
        && tag
            .as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        && tag
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

fn valid_repository_component(part: &str) -> bool {
    fn atom(c: u8) -> bool {
        c.is_ascii_lowercase() || c.is_ascii_digit()
    }
    let bytes = part.as_bytes();
    let mut i = 0;
    if !bytes.first().is_some_and(|c| atom(*c)) {
        return false;
    }
    while i < bytes.len() {
        if atom(bytes[i]) {
            i += 1;
            continue;
        }
        match bytes[i] {
            b'.' => i += 1,
            b'_' => {
                i += 1;
                if bytes.get(i) == Some(&b'_') {
                    i += 1;
                }
            }
            b'-' => {
                while bytes.get(i) == Some(&b'-') {
                    i += 1;
                }
            }
            _ => return false,
        }
        if !bytes.get(i).is_some_and(|c| atom(*c)) {
            return false;
        }
    }
    true
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub supplied: String,
    pub scheme: String,
    pub authority: Authority,
    pub path: String,
}

impl Endpoint {
    fn parse(value: &str) -> Option<Self> {
        if !public_ascii(value) || value.contains(['@', '?', '#', '%', '\\']) {
            return None;
        }
        let (scheme, rest) = value.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        let (authority, path) = rest
            .find('/')
            .map_or((rest, ""), |i| (&rest[..i], &rest[i..]));
        Some(Self {
            supplied: value.into(),
            scheme,
            authority: Authority::parse(authority)?,
            path: path.into(),
        })
    }

    pub fn builder(value: &str) -> Option<Self> {
        Self::parse(value).filter(|e| {
            e.scheme == "tcp" && e.authority.port.is_some() && matches!(e.path.as_str(), "" | "/")
        })
    }

    pub fn registry(value: &str, development_http: bool) -> Option<Self> {
        Self::parse(value).filter(|e| {
            (e.scheme == "https" || development_http && e.scheme == "http")
                && matches!(e.path.as_str(), "" | "/")
        })
    }

    pub fn token_realm(value: &str, registry: &Self) -> Option<Self> {
        Self::parse(value).filter(|e| {
            e.origin() == registry.origin()
                && e.path.strip_prefix('/').is_some_and(|path| {
                    path.split('/').all(|part| {
                        !part.is_empty()
                            && part
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                    })
                })
        })
    }

    pub fn origin(&self) -> Origin {
        Origin {
            scheme: self.scheme.clone(),
            host: self.authority.host.clone(),
            port: self
                .authority
                .port
                .unwrap_or(if self.scheme == "https" { 443 } else { 80 }),
        }
    }

    pub fn matches_repository(&self, reference: &ImageReference) -> bool {
        self.authority == reference.authority
    }
}
