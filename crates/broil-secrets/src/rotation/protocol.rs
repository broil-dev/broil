// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    read::{Error, Result},
    sops::{MAX_SCALAR_BYTES, Plaintext},
    store::State,
};
use zeroize::Zeroizing;

pub const CAPTURE_LIMIT: usize = MAX_SCALAR_BYTES + 4200;
pub const CAPABILITY_LIMIT: usize = 4096;

pub struct Capture {
    bytes: Zeroizing<Vec<u8>>,
    used: usize,
}
impl Capture {
    pub fn new(limit: usize) -> Result<Self> {
        if limit > CAPTURE_LIMIT {
            return Err(Error::class("handler output bound"));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(limit + 1)
            .map_err(|_| Error::class("allocation"))?;
        bytes.resize(limit + 1, 0);
        Ok(Self { bytes, used: 0 })
    }
    pub fn spare(&mut self) -> &mut [u8] {
        &mut self.bytes[self.used..]
    }
    pub fn advance(&mut self, count: usize) -> Result<()> {
        self.used = self
            .used
            .checked_add(count)
            .ok_or(Error::class("handler output bound"))?;
        if self.used >= self.bytes.len() {
            return Err(Error::class("handler output bound"));
        }
        Ok(())
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}
pub fn candidate(bytes: &[u8]) -> Result<Plaintext> {
    if bytes.is_empty() || bytes.len() > MAX_SCALAR_BYTES || bytes.contains(&0) {
        return Err(Error::class("invalid rotation candidate"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::class("rotation candidate must be UTF-8"))?;
    Plaintext::copy_from(text).map_err(|_| Error::class("candidate allocation"))
}
fn note(bytes: &[u8], prefix: &[u8]) -> Result<Option<String>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let bytes = bytes
        .strip_prefix(prefix)
        .and_then(|b| b.strip_suffix(b"\n"))
        .ok_or(Error::class("handler framing"))?;
    if bytes.len() > 4096 || bytes.iter().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(Error::class("handler note"));
    }
    Ok(Some(
        std::str::from_utf8(bytes)
            .map_err(|_| Error::class("handler note"))?
            .into(),
    ))
}
pub fn generated(output: &Capture) -> Result<(Plaintext, Option<String>)> {
    let bytes = output
        .bytes()
        .strip_prefix(b"BROIL_ROTATION_VALUE_BYTES=")
        .ok_or(Error::class("handler framing"))?;
    let end = bytes
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(Error::class("handler framing"))?;
    let digits = &bytes[..end];
    if digits.is_empty() || digits[0] == b'0' || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Error::class("handler framing"));
    }
    let len = std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n <= MAX_SCALAR_BYTES)
        .ok_or(Error::class("handler framing"))?;
    let rest = &bytes[end + 1..];
    let value = candidate(rest.get(..len).ok_or(Error::class("handler framing"))?)?;
    Ok((value, note(&rest[len..], b"\nBROIL_ROTATION_NOTE=")?))
}
pub fn builtin_note(output: &Capture) -> Result<Option<String>> {
    note(output.bytes(), b"BROIL_ROTATION_NOTE=")
}

pub fn recreates(output: &Capture, state: State) -> bool {
    if output.bytes().len() > CAPABILITY_LIMIT {
        return false;
    }
    use crate::vault::json::{Raw, Value};
    let Ok(value) = Raw::parse(output.bytes()).and_then(Raw::decode) else {
        return false;
    };
    let Value::Object(fields) = &value else {
        return false;
    };
    if fields.len() != 1 || fields[0].0.as_str() != "recreate" {
        return false;
    }
    let Some(Value::Array(items)) = value.get("recreate") else {
        return false;
    };
    let mut seen = Vec::new();
    for item in items {
        let Value::String(text) = item else {
            return false;
        };
        let name = text.as_str();
        if !matches!(name, "OLD_REVOKED" | "VERIFIED") || seen.contains(&name) {
            return false;
        }
        seen.push(name);
    }
    seen.contains(&state.as_str())
}
