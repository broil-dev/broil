// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

//! Borrowed control values with direct-to-zeroizing string decoding.
//! No library reader, unescape scratch, owned String or formatted parse error.

use super::buffer::Bytes;
use super::common::{Failure, Result};

#[derive(Clone, Copy)]
pub(crate) struct Value<'a>(&'a [u8], usize, usize);

fn space(input: &[u8], pos: &mut usize) {
    while input
        .get(*pos)
        .is_some_and(|c| matches!(c, b' ' | b'\n' | b'\r' | b'\t'))
    {
        *pos += 1;
    }
}

fn hex(input: &[u8], pos: &mut usize) -> Result<u32> {
    let mut value = 0;
    for _ in 0..4 {
        value = value * 16
            + match input.get(*pos) {
                Some(b'0'..=b'9') => u32::from(input[*pos] - b'0'),
                Some(b'a'..=b'f') => u32::from(input[*pos] - b'a' + 10),
                Some(b'A'..=b'F') => u32::from(input[*pos] - b'A' + 10),
                _ => return Err(Failure::Protocol),
            };
        *pos += 1;
    }
    Ok(value)
}

fn string(input: &[u8], pos: &mut usize, mut output: Option<&mut [u8]>) -> Result<usize> {
    if input.get(*pos) != Some(&b'"') {
        return Err(Failure::Protocol);
    }
    *pos += 1;
    let mut count = 0;
    let mut emit = |byte: u8| -> Result<()> {
        if let Some(bytes) = output.as_deref_mut() {
            *bytes.get_mut(count).ok_or(Failure::Limit)? = byte;
        }
        count += 1;
        Ok(())
    };
    loop {
        match input.get(*pos).copied().ok_or(Failure::Protocol)? {
            b'"' => {
                *pos += 1;
                return Ok(count);
            }
            b'\\' => {
                *pos += 1;
                match input.get(*pos).copied().ok_or(Failure::Protocol)? {
                    b'"' | b'\\' | b'/' => emit(input[*pos])?,
                    b'b' => emit(8)?,
                    b'f' => emit(12)?,
                    b'n' => emit(b'\n')?,
                    b'r' => emit(b'\r')?,
                    b't' => emit(b'\t')?,
                    b'u' => {
                        *pos += 1;
                        let mut code = hex(input, pos)?;
                        if (0xd800..=0xdbff).contains(&code) {
                            if input.get(*pos..*pos + 2) != Some(b"\\u") {
                                return Err(Failure::Protocol);
                            }
                            *pos += 2;
                            let low = hex(input, pos)?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return Err(Failure::Protocol);
                            }
                            code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
                        } else if (0xdc00..=0xdfff).contains(&code) {
                            return Err(Failure::Protocol);
                        }
                        if code < 0x80 {
                            emit(code as u8)?;
                        } else if code < 0x800 {
                            emit(0xc0 | (code >> 6) as u8)?;
                            emit(0x80 | (code & 63) as u8)?;
                        } else if code < 0x10000 {
                            emit(0xe0 | (code >> 12) as u8)?;
                            emit(0x80 | ((code >> 6) & 63) as u8)?;
                            emit(0x80 | (code & 63) as u8)?;
                        } else {
                            emit(0xf0 | (code >> 18) as u8)?;
                            emit(0x80 | ((code >> 12) & 63) as u8)?;
                            emit(0x80 | ((code >> 6) & 63) as u8)?;
                            emit(0x80 | (code & 63) as u8)?;
                        }
                        continue;
                    }
                    _ => return Err(Failure::Protocol),
                }
                *pos += 1;
            }
            0..=31 => return Err(Failure::Protocol),
            byte => {
                emit(byte)?;
                *pos += 1;
            }
        }
    }
}

fn skip(input: &[u8], pos: &mut usize, depth: usize, maximum: usize, items: usize) -> Result<()> {
    if depth > maximum {
        return Err(Failure::Limit);
    }
    space(input, pos);
    match input.get(*pos).copied().ok_or(Failure::Protocol)? {
        b'"' => {
            string(input, pos, None)?;
        }
        b'{' | b'[' => {
            let object = input[*pos] == b'{';
            let end = if object { b'}' } else { b']' };
            *pos += 1;
            space(input, pos);
            if input.get(*pos) == Some(&end) {
                *pos += 1;
                return Ok(());
            }
            let mut count = 0;
            let mut keys = std::collections::BTreeSet::new();
            loop {
                count += 1;
                if count > items {
                    return Err(Failure::Limit);
                }
                if object {
                    let start = *pos;
                    string(input, pos, None)?;
                    let key = Value(&input[start..*pos], maximum, items);
                    if !keys.insert(key.text()?) {
                        return Err(Failure::Protocol);
                    }
                    space(input, pos);
                    if input.get(*pos) != Some(&b':') {
                        return Err(Failure::Protocol);
                    }
                    *pos += 1;
                }
                skip(input, pos, depth + 1, maximum, items)?;
                space(input, pos);
                match input.get(*pos) {
                    Some(byte) if *byte == end => {
                        *pos += 1;
                        break;
                    }
                    Some(b',') => {
                        *pos += 1;
                        space(input, pos);
                    }
                    _ => return Err(Failure::Protocol),
                }
            }
        }
        b'-' | b'0'..=b'9' => {
            if input.get(*pos) == Some(&b'-') {
                *pos += 1;
            }
            let first = *pos;
            while input.get(*pos).is_some_and(u8::is_ascii_digit) {
                *pos += 1;
            }
            if *pos == first || (*pos - first > 1 && input[first] == b'0') {
                return Err(Failure::Protocol);
            }
            if input.get(*pos) == Some(&b'.') {
                *pos += 1;
                let first = *pos;
                while input.get(*pos).is_some_and(u8::is_ascii_digit) {
                    *pos += 1;
                }
                if *pos == first {
                    return Err(Failure::Protocol);
                }
            }
            if matches!(input.get(*pos), Some(b'e' | b'E')) {
                *pos += 1;
                if matches!(input.get(*pos), Some(b'+' | b'-')) {
                    *pos += 1;
                }
                let first = *pos;
                while input.get(*pos).is_some_and(u8::is_ascii_digit) {
                    *pos += 1;
                }
                if *pos == first {
                    return Err(Failure::Protocol);
                }
            }
        }
        b't' | b'f' | b'n' => {
            let literal: &[u8] = match input[*pos] {
                b't' => b"true",
                b'f' => b"false",
                _ => b"null",
            };
            if input.get(*pos..*pos + literal.len()) != Some(literal) {
                return Err(Failure::Protocol);
            }
            *pos += literal.len();
        }
        _ => return Err(Failure::Protocol),
    }
    Ok(())
}

impl<'a> Value<'a> {
    pub(crate) fn parse(input: &'a [u8]) -> Result<Self> {
        Self::parse_bounded(input, 65_536, 16)
    }

    pub(crate) fn parse_bounded(input: &'a [u8], bytes: usize, depth: usize) -> Result<Self> {
        Self::parse_limits(input, bytes, depth, 4096)
    }

    pub(crate) fn parse_analysis(input: &'a [u8]) -> Result<Self> {
        Self::parse_limits(input, 16_777_216, 128, 8192)
    }

    fn parse_limits(input: &'a [u8], bytes: usize, depth: usize, items: usize) -> Result<Self> {
        if input.len() > bytes || bytes > 16_777_216 || depth == 0 || depth > 128 {
            return Err(Failure::Limit);
        }
        std::str::from_utf8(input).map_err(|_| Failure::Protocol)?;
        let mut start = 0;
        space(input, &mut start);
        let mut end = start;
        skip(input, &mut end, 1, depth, items)?;
        let value = Self(&input[start..end], depth, items);
        space(input, &mut end);
        if end != input.len() {
            return Err(Failure::Protocol);
        }
        Ok(value)
    }

    pub(crate) fn raw(self) -> &'a [u8] {
        self.0
    }

    pub(crate) fn text(self) -> Result<Bytes> {
        let mut pos = 0;
        let count = string(self.0, &mut pos, None)?;
        if pos != self.0.len() {
            return Err(Failure::Protocol);
        }
        let mut bytes = Bytes::new(count)?;
        string(self.0, &mut 0, Some(bytes.get_mut()))?;
        Ok(bytes)
    }

    pub(crate) fn number(self) -> Result<u64> {
        if self.0.is_empty() || !self.0.iter().all(u8::is_ascii_digit) {
            return Err(Failure::Protocol);
        }
        self.0.iter().try_fold(0u64, |n, c| {
            n.checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(*c - b'0')))
                .ok_or(Failure::Limit)
        })
    }

    pub(crate) fn boolean(self) -> Result<bool> {
        match self.0 {
            b"true" => Ok(true),
            b"false" => Ok(false),
            _ => Err(Failure::Protocol),
        }
    }

    pub(crate) fn is_null(self) -> bool {
        self.0 == b"null"
    }

    /// Exact key set, including duplicate escaped-key rejection. Returned
    /// values borrow the original zeroizing frame; the Vec contains only views.
    pub(crate) fn object(self, fields: &[&[u8]]) -> Result<Vec<Self>> {
        if self.0.first() != Some(&b'{') || fields.len() > 64 {
            return Err(Failure::Protocol);
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(fields.len())
            .map_err(|_| Failure::Limit)?;
        values.resize(fields.len(), Self(b"", self.1, self.2));
        let mut seen = 0u64;
        let mut pos = 1;
        space(self.0, &mut pos);
        while self.0.get(pos) != Some(&b'}') {
            let start = pos;
            string(self.0, &mut pos, None)?;
            let key = Self(&self.0[start..pos], self.1, self.2).text()?;
            let index = fields
                .iter()
                .position(|field| *field == key.get())
                .ok_or(Failure::Protocol)?;
            if seen & (1u64 << index) != 0 {
                return Err(Failure::Protocol);
            }
            seen |= 1u64 << index;
            space(self.0, &mut pos);
            if self.0.get(pos) != Some(&b':') {
                return Err(Failure::Protocol);
            }
            pos += 1;
            space(self.0, &mut pos);
            let start = pos;
            skip(self.0, &mut pos, 1, self.1, self.2)?;
            values[index] = Self(&self.0[start..pos], self.1, self.2);
            space(self.0, &mut pos);
            if self.0.get(pos) == Some(&b',') {
                pos += 1;
                space(self.0, &mut pos);
            } else if self.0.get(pos) != Some(&b'}') {
                return Err(Failure::Protocol);
            }
        }
        if seen.count_ones() as usize != fields.len() {
            return Err(Failure::Protocol);
        }
        Ok(values)
    }

    pub(crate) fn array(self) -> Result<Vec<Self>> {
        if self.0.first() != Some(&b'[') {
            return Err(Failure::Protocol);
        }
        let mut values = Vec::new();
        let mut pos = 1;
        space(self.0, &mut pos);
        while self.0.get(pos) != Some(&b']') {
            if values.len() == self.2 {
                return Err(Failure::Limit);
            }
            let start = pos;
            skip(self.0, &mut pos, 1, self.1, self.2)?;
            values.try_reserve_exact(1).map_err(|_| Failure::Limit)?;
            values.push(Self(&self.0[start..pos], self.1, self.2));
            space(self.0, &mut pos);
            if self.0.get(pos) == Some(&b',') {
                pos += 1;
                space(self.0, &mut pos);
            } else if self.0.get(pos) != Some(&b']') {
                return Err(Failure::Protocol);
            }
        }
        Ok(values)
    }

    pub(crate) fn equals(self, text: &str) -> Result<bool> {
        Ok(self.text()?.get() == text.as_bytes())
    }

    pub(crate) fn members(self) -> Result<Vec<(Self, Self)>> {
        if self.0.first() != Some(&b'{') {
            return Err(Failure::Protocol);
        }
        let mut values = Vec::new();
        let mut pos = 1;
        space(self.0, &mut pos);
        while self.0.get(pos) != Some(&b'}') {
            if values.len() == self.2 {
                return Err(Failure::Limit);
            }
            let start = pos;
            string(self.0, &mut pos, None)?;
            let key = Self(&self.0[start..pos], self.1, self.2);
            space(self.0, &mut pos);
            if self.0.get(pos) != Some(&b':') {
                return Err(Failure::Protocol);
            }
            pos += 1;
            space(self.0, &mut pos);
            let start = pos;
            skip(self.0, &mut pos, 1, self.1, self.2)?;
            values.try_reserve(1).map_err(|_| Failure::Limit)?;
            values.push((key, Self(&self.0[start..pos], self.1, self.2)));
            space(self.0, &mut pos);
            if self.0.get(pos) == Some(&b',') {
                pos += 1;
                space(self.0, &mut pos);
            } else if self.0.get(pos) != Some(&b'}') {
                return Err(Failure::Protocol);
            }
        }
        Ok(values)
    }

    pub(crate) fn field(self, name: &str) -> Result<Self> {
        self.optional(name)?.ok_or(Failure::Protocol)
    }

    pub(crate) fn optional(self, name: &str) -> Result<Option<Self>> {
        for (key, value) in self.members()? {
            if key.equals(name)? {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }

    /// Compare a private response against an already-public request. No child
    /// string is promoted into ordinary storage or an error.
    pub(crate) fn matches(self, expected: &serde_json::Value) -> Result<bool> {
        use serde_json::Value as Public;
        match expected {
            Public::Null => Ok(self.is_null()),
            Public::Bool(value) => Ok(self.boolean()? == *value),
            Public::Number(value) => Ok(Some(self.number()?) == value.as_u64()),
            Public::String(value) => self.equals(value),
            Public::Array(expected) => {
                let values = self.array()?;
                if values.len() != expected.len() {
                    return Ok(false);
                }
                for (value, expected) in values.into_iter().zip(expected) {
                    if !value.matches(expected)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Public::Object(expected) => {
                let values = self.members()?;
                if values.len() != expected.len() {
                    return Ok(false);
                }
                for (key, value) in values {
                    let decoded = key.text()?;
                    let name = std::str::from_utf8(decoded.get()).map_err(|_| Failure::Protocol)?;
                    let Some(expected) = expected.get(name) else {
                        return Ok(false);
                    };
                    if !value.matches(expected)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }
}
