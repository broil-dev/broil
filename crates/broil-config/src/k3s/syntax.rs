// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
};

use crate::raw::RawValue;
use broil_core::{
    error::{ConfigError, SchemaError},
    images::{
        reference::{Endpoint, ImageReference},
        valid_name,
    },
    k3s::Ipv4Cidr,
    remote::DurationValue,
};

pub(super) fn invalid(path: &str, expected: &str) -> ConfigError {
    ConfigError::Schema(SchemaError::InvalidK3sValue {
        key_path: path.into(),
        expected: expected.into(),
    })
}

pub(super) fn unknown(path: &str) -> ConfigError {
    ConfigError::Schema(SchemaError::UnknownKey {
        key_path: path.into(),
    })
}

pub(super) fn pairs<'a>(
    v: &'a RawValue,
    path: &str,
    nullable: bool,
) -> Result<&'a [(RawValue, RawValue)], ConfigError> {
    let result = match v {
        RawValue::Map(pairs) => pairs.as_slice(),
        RawValue::Null if nullable => &[],
        _ => return Err(invalid(path, "a mapping")),
    };
    let mut seen = BTreeSet::new();
    for (k, _) in result {
        if !seen.insert(key(k, path)?) {
            return Err(invalid(path, "a mapping with unique keys"));
        }
    }
    Ok(result)
}

pub(super) fn key<'a>(v: &'a RawValue, path: &str) -> Result<&'a str, ConfigError> {
    match v {
        RawValue::Str(s) if !s.contains('\0') => Ok(s),
        _ => Err(invalid(path, "a NUL-free string key")),
    }
}

pub(super) fn text(v: &RawValue, path: &str) -> Result<String, ConfigError> {
    key(v, path).map(String::from)
}

pub(super) fn checked(
    v: &RawValue,
    path: &str,
    valid: impl Fn(&str) -> bool,
    expected: &str,
) -> Result<String, ConfigError> {
    let s = text(v, path)?;
    if !valid(&s) {
        return Err(invalid(path, expected));
    }
    Ok(s)
}

pub(super) fn nonempty(v: &RawValue, path: &str) -> Result<String, ConfigError> {
    checked(v, path, |s| !s.is_empty(), "a nonempty string")
}

pub(super) fn name(v: &RawValue, path: &str) -> Result<String, ConfigError> {
    checked(v, path, valid_name, "a catalog name")
}

pub(super) fn required<T>(v: Option<T>, path: &str) -> Result<T, ConfigError> {
    v.ok_or_else(|| invalid(path, "present (required field)"))
}

pub(super) fn sequence<'a>(v: &'a RawValue, path: &str) -> Result<&'a [RawValue], ConfigError> {
    match v {
        RawValue::Seq(s) => Ok(s),
        _ => Err(invalid(path, "a non-null sequence")),
    }
}

pub(super) fn strings(
    v: &RawValue,
    path: &str,
    empty: bool,
    valid: impl Fn(&str) -> bool,
) -> Result<Vec<String>, ConfigError> {
    let values = sequence(v, path)?;
    if !empty && values.is_empty() {
        return Err(invalid(path, "a nonempty sequence"));
    }
    let mut seen = BTreeSet::new();
    values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let p = format!("{path}.{i}");
            let s = checked(v, &p, &valid, "a valid public value")?;
            if !seen.insert(s.clone()) {
                return Err(invalid(&p, "unique in the sequence"));
            }
            Ok(s)
        })
        .collect()
}

pub(super) fn named<T>(
    v: &RawValue,
    path: &str,
    parse: impl Fn(&RawValue, &str) -> Result<T, ConfigError>,
) -> Result<BTreeMap<String, T>, ConfigError> {
    pairs(v, path, true)?
        .iter()
        .map(|(k, v)| {
            let k = name(k, path)?;
            let value = parse(v, &format!("{path}.{k}"))?;
            Ok((k, value))
        })
        .collect()
}

pub(super) fn integer(v: &RawValue, path: &str, max: i64) -> Result<i64, ConfigError> {
    match v {
        RawValue::Int(n) if (1..=max).contains(n) => Ok(*n),
        _ => Err(invalid(
            path,
            "an integer within the documented positive range",
        )),
    }
}

pub(super) fn duration(
    v: &RawValue,
    path: &str,
    max_hours: u64,
) -> Result<DurationValue, ConfigError> {
    let source = nonempty(v, path)?;
    let seconds = source
        .get(..source.len().saturating_sub(1))
        .and_then(|digits| {
            if !digits.starts_with(|c: char| ('1'..='9').contains(&c))
                || !digits.bytes().all(|c| c.is_ascii_digit())
            {
                return None;
            }
            let factor = match source.as_bytes().last()? {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                _ => return None,
            };
            digits.parse::<u64>().ok()?.checked_mul(factor)
        })
        .filter(|s| *s <= max_hours * 3600)
        .ok_or_else(|| invalid(path, "a bounded positive duration in s, m or h"))?;
    Ok(DurationValue { source, seconds })
}

pub fn exact_version(s: &str) -> bool {
    let Some(s) = s.strip_prefix('v') else {
        return false;
    };
    s.split('.').count() == 3 && s.split('.').all(digits)
}

pub fn k3s_version(s: &str) -> bool {
    s.split_once("+k3s")
        .is_some_and(|(v, n)| exact_version(v) && digits(n))
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

pub fn dns(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}

pub(super) fn label_value(s: &str) -> bool {
    s.is_empty()
        || s.len() <= 63
            && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
            && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

pub(super) const RESERVED_KEY_PREFIX: &str = "broil.dev/";

pub(super) fn label_key(s: &str) -> bool {
    if s.starts_with(RESERVED_KEY_PREFIX) {
        return false;
    }
    let name = match s.split_once('/') {
        Some((prefix, name)) if dns(prefix) => name,
        Some(_) => return false,
        None => s,
    };
    !name.is_empty() && label_value(name)
}

pub(super) fn ipv4(s: &str) -> Option<Ipv4Addr> {
    s.parse::<Ipv4Addr>().ok().filter(|ip| ip.to_string() == s)
}

pub(super) fn unicast(v: &RawValue, path: &str) -> Result<Ipv4Addr, ConfigError> {
    ipv4(&nonempty(v, path)?)
        .filter(|ip| ip.octets()[0] != 0 && ip.octets()[0] < 224)
        .ok_or_else(|| invalid(path, "a canonical unicast IPv4 literal"))
}

pub(super) fn cidr(v: &RawValue, path: &str) -> Result<Ipv4Cidr, ConfigError> {
    let s = nonempty(v, path)?;
    let result = s.split_once('/').and_then(|(address, prefix)| {
        let network = ipv4(address)?;
        let n = prefix.parse::<u8>().ok()?;
        if n > 32 || n.to_string() != prefix {
            return None;
        }
        let cidr = Ipv4Cidr { network, prefix: n };
        let mask = u32::MAX.checked_shl(32 - u32::from(n)).unwrap_or(0);
        (u32::from(network) & mask == u32::from(network)).then_some(cidr)
    });
    result.ok_or_else(|| invalid(path, "a canonical IPv4 CIDR with zero host bits"))
}

pub(super) fn endpoint(v: &RawValue, path: &str) -> Result<Endpoint, ConfigError> {
    Endpoint::registry(&nonempty(v, path)?, false)
        .filter(|e| e.authority.port.is_some() && !e.authority.host.contains(':'))
        .ok_or_else(|| invalid(path, "an HTTPS DNS/IPv4 endpoint with explicit port"))
}

pub(super) fn bounded_path(s: &str, remote: bool) -> bool {
    if s.is_empty() || s.len() > 4096 || s.contains('\0') {
        return false;
    }
    if remote {
        let Some(tail) = s.strip_prefix('/') else {
            return false;
        };
        return tail
            .split('/')
            .all(|p| !matches!(p, "" | "." | "..") && p.len() <= 255);
    }
    s.split('/').all(|p| p.len() <= 255)
}

pub(super) fn path_value(v: &RawValue, path: &str, remote: bool) -> Result<String, ConfigError> {
    checked(
        v,
        path,
        |s| bounded_path(s, remote),
        "a bounded path of the declared kind",
    )
}

pub(super) fn repositories(v: &RawValue, path: &str) -> Result<Vec<String>, ConfigError> {
    strings(v, path, false, |s| {
        ImageReference::parse(s).is_some_and(|r| r.is_normalized_repository())
    })
}
