// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Error, Result};
use crate::{
    output::{self, Prepared, Writer},
    sops::{MAX_DOCUMENT_BYTES, MAX_SCALAR_BYTES},
};
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

pub struct Text(Zeroizing<String>);
impl Text {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn copy(text: &str) -> Result<Self> {
        if text.len() > MAX_SCALAR_BYTES {
            return Err(bounds());
        }
        let mut out = Zeroizing::new(String::new());
        out.try_reserve_exact(text.len()).map_err(|_| bounds())?;
        out.push_str(text);
        Ok(Self(out))
    }
}
impl std::fmt::Debug for Text {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Text([REDACTED])")
    }
}
impl Drop for Text {
    fn drop(&mut self) {
        self.0.zeroize();

    }
}
fn invalid() -> Error {
    Error::runtime("malformed vault JSON")
}
fn bounds() -> Error {
    Error::runtime("vault JSON size, depth or item limit")
}

#[derive(Clone, Copy)]
pub struct Raw<'a>(&'a str);
impl<'a> Raw<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(bounds());
        }
        prescan(bytes)?;
        let raw: &'a RawValue = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        Ok(Self(raw.get()))
    }
    pub fn as_bytes(self) -> &'a [u8] {
        self.0.as_bytes()
    }
    pub fn text(self) -> Result<Text> {
        unescape(self.0)
    }
    pub fn boolean(self) -> Result<bool> {
        match self.0 {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(invalid()),
        }
    }
    pub fn fields(self) -> Result<Vec<(Text, Self)>> {
        let bytes = self.0.as_bytes();
        if bytes.first() != Some(&b'{') {
            return Err(invalid());
        }
        let mut pos = 1;
        let mut fields = Vec::new();
        loop {
            whitespace(bytes, &mut pos);
            if bytes.get(pos) == Some(&b'}') {
                break;
            }
            let end = end_value(bytes, pos)?;
            let key = unescape(&self.0[pos..end])?;
            pos = end;
            whitespace(bytes, &mut pos);
            if bytes.get(pos) != Some(&b':') {
                return Err(invalid());
            }
            pos += 1;
            whitespace(bytes, &mut pos);
            let end = end_value(bytes, pos)?;
            fields.push((key, Self(&self.0[pos..end])));
            if fields.len() > 65536 {
                return Err(bounds());
            }
            pos = end;
            whitespace(bytes, &mut pos);
            match bytes.get(pos) {
                Some(b',') => pos += 1,
                Some(b'}') => break,
                _ => return Err(invalid()),
            }
        }
        fields.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
        if fields
            .windows(2)
            .any(|w| w[0].0.as_str() == w[1].0.as_str())
        {
            return Err(invalid());
        }
        Ok(fields)
    }
    pub fn field(self, name: &str) -> Result<Self> {
        self.optional(name)?.ok_or_else(invalid)
    }
    pub fn optional(self, name: &str) -> Result<Option<Self>> {
        Ok(self
            .fields()?
            .into_iter()
            .find_map(|(key, raw)| (key.as_str() == name).then_some(raw)))
    }
    pub fn decode(self) -> Result<Value> {
        self.decode_inner(&mut 0)
    }
    pub(crate) fn user_data(self) -> Result<Value> {
        let mut used = 0;
        let mut values = Vec::new();
        for (key, raw) in self.fields()? {
            if matches!(key.as_str(), "_broil" | "sops") {
                continue;
            }
            budget(&mut used, key.as_str().len())?;
            values.push((key, raw.decode_inner(&mut used)?));
        }
        Ok(Value::Object(values))
    }
    fn decode_inner(self, used: &mut usize) -> Result<Value> {
        let value = match self.0.as_bytes().first() {
            Some(b'{') => {
                let mut values = Vec::new();
                for (key, raw) in self.fields()? {
                    budget(used, key.as_str().len())?;
                    values.push((key, raw.decode_inner(used)?));
                }
                Value::Object(values)
            }
            Some(b'[') => {
                let mut values = Vec::new();
                let bytes = self.0.as_bytes();
                let mut pos = 1;
                loop {
                    whitespace(bytes, &mut pos);
                    if bytes.get(pos) == Some(&b']') {
                        break;
                    }
                    let end = end_value(bytes, pos)?;
                    values.push(Self(&self.0[pos..end]).decode_inner(used)?);
                    pos = end;
                    whitespace(bytes, &mut pos);
                    match bytes.get(pos) {
                        Some(b',') => pos += 1,
                        Some(b']') => break,
                        _ => return Err(invalid()),
                    }
                }
                Value::Array(values)
            }
            Some(b'"') => {
                let text = self.text()?;
                budget(used, text.as_str().len())?;
                Value::String(text)
            }
            _ if self.0 == "null" => Value::Null,
            _ => {
                if !matches!(self.0, "true" | "false") {
                    let number = Zeroizing::new(self.0.parse::<f64>().map_err(|_| invalid())?);
                    if !number.is_finite() {
                        return Err(invalid());
                    }
                }
                budget(used, self.0.len())?;
                Value::Literal(Text::copy(self.0)?)
            }
        };
        Ok(value)
    }
}
fn budget(used: &mut usize, n: usize) -> Result<()> {
    *used = used.checked_add(n).ok_or_else(bounds)?;
    if *used > MAX_DOCUMENT_BYTES {
        Err(bounds())
    } else {
        Ok(())
    }
}
fn whitespace(bytes: &[u8], pos: &mut usize) {
    while bytes
        .get(*pos)
        .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
    {
        *pos += 1;
    }
}
fn end_value(bytes: &[u8], start: usize) -> Result<usize> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
                if depth == 0 {
                    return Ok(i + 1);
                }
            }
        } else {
            match b {
                b'"' => quoted = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' if depth > 0 => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(i + 1);
                    }
                }
                b',' | b'}' | b']' | b' ' | b'\n' | b'\r' | b'\t' if depth == 0 => return Ok(i),
                _ => (),
            }
        }
    }
    if !quoted && depth == 0 {
        Ok(bytes.len())
    } else {
        Err(invalid())
    }
}
fn prescan(bytes: &[u8]) -> Result<()> {
    let (mut depth, mut items, mut quoted, mut escaped) = (0usize, 0usize, false, false);
    for &b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
        } else {
            match b {
                b'"' => {
                    quoted = true;
                    items += 1;
                }
                b'{' | b'[' => {
                    depth += 1;
                    items += 1;
                }
                b'}' | b']' => depth = depth.checked_sub(1).ok_or_else(invalid)?,
                b',' | b':' => items += 1,
                _ => (),
            }
            if depth > 128 || items > 65536 {
                return Err(bounds());
            }
        }
    }
    if quoted || depth != 0 {
        return Err(invalid());
    }
    Ok(())
}

pub fn unescape(raw: &str) -> Result<Text> {
    fn pass(raw: &str, mut emit: impl FnMut(&str) -> Result<()>) -> Result<()> {
        let content = raw
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(invalid)?;
        let mut chars = content.chars();
        while let Some(c) = chars.next() {
            let value = Zeroizing::new(if c == '\\' {
                match chars.next().ok_or_else(invalid)? {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => {
                        fn hex(chars: &mut std::str::Chars<'_>) -> Result<u32> {
                            let mut n = Zeroizing::new(0u32);
                            for _ in 0..4 {
                                *n = *n * 16
                                    + chars
                                        .next()
                                        .and_then(|c| c.to_digit(16))
                                        .ok_or_else(invalid)?;
                            }
                            Ok(*n)
                        }
                        let mut n = Zeroizing::new(hex(&mut chars)?);
                        if (0xd800..=0xdbff).contains(&*n) {
                            if chars.next() != Some('\\') || chars.next() != Some('u') {
                                return Err(invalid());
                            }
                            let low = Zeroizing::new(hex(&mut chars)?);
                            if !(0xdc00..=0xdfff).contains(&*low) {
                                return Err(invalid());
                            }
                            *n = 0x10000 + ((*n - 0xd800) << 10) + (*low - 0xdc00);
                        }
                        char::from_u32(*n).ok_or_else(invalid)?
                    }
                    _ => return Err(invalid()),
                }
            } else {
                if c == '"' || c < '\u{20}' {
                    return Err(invalid());
                }
                c
            });
            let mut scratch = Zeroizing::new([0; 4]);
            emit(value.encode_utf8(&mut *scratch))?;
        }
        Ok(())
    }
    let mut length = 0;
    pass(raw, |s| {
        length += s.len();
        if length > MAX_SCALAR_BYTES {
            Err(bounds())
        } else {
            Ok(())
        }
    })?;
    let mut output = Zeroizing::new(String::new());
    output.try_reserve_exact(length).map_err(|_| bounds())?;
    pass(raw, |s| {
        output.push_str(s);
        Ok(())
    })?;
    Ok(Text(output))
}

#[derive(Debug)]
pub enum Value {
    Object(Vec<(Text, Value)>),
    Array(Vec<Value>),
    String(Text),
    Literal(Text),
    Null,
}
impl Value {
    pub fn get(&self, name: &str) -> Option<&Self> {
        let Self::Object(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find_map(|(key, value)| (key.as_str() == name).then_some(value))
    }
    pub fn scalar(&self) -> Option<&str> {
        match self {
            Self::String(t) | Self::Literal(t) => Some(t.as_str()),
            _ => None,
        }
    }
    pub fn keys(&self) -> Result<Vec<&str>> {
        let Self::Object(entries) = self else {
            return Err(invalid());
        };
        Ok(entries
            .iter()
            .map(|(key, _)| key.as_str())
            .filter(|k| !matches!(*k, "_broil" | "sops"))
            .collect())
    }
    pub fn decoded_bytes(&self) -> usize {
        match self {
            Self::Object(values) => values
                .iter()
                .map(|(k, v)| k.as_str().len() + v.decoded_bytes())
                .sum(),
            Self::Array(values) => values.iter().map(Self::decoded_bytes).sum(),
            Self::String(t) | Self::Literal(t) => t.as_str().len(),
            Self::Null => 0,
        }
    }
    fn emit(&self, writer: &mut Writer) -> crate::read::Result<()> {
        match self {
            Self::String(t) => output::json_string(writer, t.as_str()),
            Self::Literal(t) => writer.text(t.as_str()),
            Self::Null => writer.text("null"),
            Self::Object(entries) => {
                writer.text("{")?;
                for (i, (key, value)) in entries.iter().enumerate() {
                    if i > 0 {
                        writer.text(",")?;
                    }
                    output::json_string(writer, key.as_str())?;
                    writer.text(":")?;
                    value.emit(writer)?;
                }
                writer.text("}")
            }
            Self::Array(values) => {
                writer.text("[")?;
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        writer.text(",")?;
                    }
                    value.emit(writer)?;
                }
                writer.text("]")
            }
        }
    }
    pub fn render(&self, json: bool, newline: bool) -> crate::read::Result<Prepared> {
        output::prepare(output::MAX_OUTPUT_BYTES, |writer| {
            match self {
                Self::String(t) if !json => writer.text(t.as_str())?,
                _ => self.emit(writer)?,
            }
            if newline {
                writer.text("\n")?;
            }
            Ok(())
        })
    }
}

