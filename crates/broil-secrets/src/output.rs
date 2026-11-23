// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    read::{Error, Result},
    sops::{Entry, MAX_DOCUMENT_BYTES, Scalar, ScalarKind, Value},
};
use std::{collections::BTreeMap, fmt, fmt::Write as _};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_OUTPUT_BYTES: usize = 6 * MAX_DOCUMENT_BYTES + 2 * 65536 + 1;

pub struct Prepared(Zeroizing<Vec<u8>>);
impl Prepared {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("UTF-8 renderer")
    }
    pub fn into_secret(mut self) -> Result<broil_core::secret::OwnedSecret> {
        std::str::from_utf8(&self.0).map_err(|_| Error::class("scalar encoding"))?;
        Ok(broil_core::secret::OwnedSecret::from_zeroizing(
            Zeroizing::new(
                String::from_utf8(std::mem::take(&mut *self.0)).expect("validated scalar"),
            ),
        ))
    }
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Prepared([REDACTED])")
    }
}
impl Drop for Prepared {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();

    }
}

pub struct Writer {
    output: Option<Prepared>,
    length: usize,
    limit: usize,
}
impl Writer {
    pub fn text(&mut self, text: &str) -> Result<()> {
        self.bytes(text.as_bytes())
    }
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.length = self
            .length
            .checked_add(bytes.len())
            .ok_or(Error::class("size limit"))?;
        if self.length > self.limit {
            return Err(Error::class("size limit"));
        }
        if let Some(output) = &mut self.output {
            output.0.extend_from_slice(bytes);
        }
        Ok(())
    }
}
impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.text(s).map_err(|_| fmt::Error)
    }
}
pub fn prepare(limit: usize, emit: impl Fn(&mut Writer) -> Result<()>) -> Result<Prepared> {
    let mut counter = Writer {
        output: None,
        length: 0,
        limit,
    };
    emit(&mut counter)?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(counter.length)
        .map_err(|_| Error::class("allocation"))?;
    let mut writer = Writer {
        output: Some(Prepared(bytes)),
        length: 0,
        limit: counter.length,
    };
    emit(&mut writer)?;
    if writer.length != writer.limit {
        return Err(Error::class("output preparation"));
    }
    Ok(writer.output.take().unwrap())
}

pub(crate) fn json_string(writer: &mut Writer, value: &str) -> Result<()> {
    writer.text("\"")?;
    escaped(writer, value, true)?;
    writer.text("\"")
}
fn escaped(writer: &mut Writer, value: &str, quote: bool) -> Result<()> {
    let mut start = 0;
    for (i, c) in value.char_indices() {
        let replacement = match c {
            '"' if quote => Some("\\\""),
            '\\' if quote => Some("\\\\"),
            '\n' => Some("\\n"),
            '\r' => Some("\\r"),
            '\t' => Some("\\t"),
            '\u{8}' => Some("\\b"),
            '\u{c}' => Some("\\f"),
            _ => None,
        };
        if replacement.is_some() || c.is_control() {
            writer.text(&value[start..i])?;
            if let Some(replacement) = replacement {
                writer.text(replacement)?;
            } else if c <= '\u{1f}' || !quote {
                let code = Zeroizing::new(c as u32);
                write!(writer, "\\u{:04x}", *code).map_err(|_| Error::class("size limit"))?;
            } else {
                writer.text(&value[i..i + c.len_utf8()])?;
            }
            start = i + c.len_utf8();
        }
    }
    writer.text(&value[start..])
}
pub fn public_name(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_control() => {
                write!(out, "\\u{:04x}", c as u32).expect("public name");
            }
            c => out.push(c),
        }
    }
    out
}

pub(crate) fn scalar(writer: &mut Writer, value: &Scalar, json: bool) -> Result<()> {
    match value.kind() {
        ScalarKind::String if json => json_string(writer, value.as_str()),
        ScalarKind::String => writer.text(value.as_str()),
        ScalarKind::Boolean => writer.text(match value.as_str() {
            "True" | "true" => "true",
            "False" | "false" => "false",
            _ => return Err(Error::class("non-JSON value")),
        }),
        ScalarKind::Integer => {
            let value = Zeroizing::new(
                value
                    .as_str()
                    .parse::<i64>()
                    .map_err(|_| Error::class("non-JSON value"))?,
            );
            write!(writer, "{}", *value).map_err(|_| Error::class("size limit"))
        }
        ScalarKind::Float => {
            let text = value.as_str();
            let value = Zeroizing::new(
                value
                    .as_str()
                    .parse::<f64>()
                    .map_err(|_| Error::class("non-JSON value"))?,
            );
            if !value.is_finite() {
                return Err(Error::class("non-JSON value"));
            }
            writer.text(text)?;
            if !text.contains(['.', 'e', 'E']) {
                writer.text(".0")?;
            }
            Ok(())
        }
    }
}
pub(crate) fn json(writer: &mut Writer, value: &Value) -> Result<()> {
    match value {
        Value::Null => writer.text("null"),
        Value::Scalar(value) => scalar(writer, value, true),
        Value::Comment(_) => Err(Error::class("non-JSON value")),
        Value::Mapping(entries) => {
            let sorted: BTreeMap<_, _> = entries
                .iter()
                .filter_map(|e| match e {
                    Entry::Pair(k, v) => Some((k, v)),
                    _ => None,
                })
                .collect();
            writer.text("{")?;
            for (i, (key, value)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    writer.text(",")?;
                }
                json_string(writer, key)?;
                writer.text(":")?;
                json(writer, value)?;
            }
            writer.text("}")
        }
        Value::Sequence(values) => {
            writer.text("[")?;
            for (i, value) in values
                .iter()
                .filter(|v| !matches!(v, Value::Comment(_)))
                .enumerate()
            {
                if i > 0 {
                    writer.text(",")?;
                }
                json(writer, value)?;
            }
            writer.text("]")
        }
    }
}
pub fn get(value: &Value, as_json: bool) -> Result<Prepared> {
    prepare(MAX_OUTPUT_BYTES, |writer| {
        match value.scalar() {
            Some(s) if !as_json && s.kind() == ScalarKind::String => writer.text(s.as_str())?,
            _ => json(writer, value)?,
        }
        writer.text("\n")
    })
}
pub fn list(names: Vec<String>) -> Result<Prepared> {
    list_refs(names.iter().map(String::as_str).collect())
}
pub(crate) fn list_refs(mut names: Vec<&str>) -> Result<Prepared> {
    names.sort();
    prepare(MAX_OUTPUT_BYTES, |writer| {
        for name in &names {
            escaped(writer, name, false)?;
            writer.text("\n")?;
        }
        if names.is_empty() {
            writer.text("\n")?;
        }
        Ok(())
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExportFormat {
    #[default]
    Sh,
    Env,
    Json,
}
pub fn exports(values: &BTreeMap<String, Prepared>, format: ExportFormat) -> Result<Prepared> {
    prepare(MAX_OUTPUT_BYTES, |writer| {
        if format == ExportFormat::Json {
            writer.text("{")?;
        }
        for (i, (name, value)) in values.iter().enumerate() {
            let value = value.as_str();
            match format {
                ExportFormat::Json => {
                    if i > 0 {
                        writer.text(",")?;
                    }
                    json_string(writer, name)?;
                    writer.text(":")?;
                    json_string(writer, value)?;
                }
                ExportFormat::Env => {
                    if value.contains(['\r', '\n']) {
                        return Err(Error::class("env newline"));
                    }
                    writer.text(name)?;
                    writer.text("=")?;
                    writer.text(value)?;
                    writer.text("\n")?;
                }
                ExportFormat::Sh => {
                    writer.text("export ")?;
                    writer.text(name)?;
                    writer.text("='")?;
                    for (i, part) in value.split('\'').enumerate() {
                        if i > 0 {
                            writer.text("'\\''")?;
                        }
                        writer.text(part)?;
                    }
                    writer.text("'\n")?;
                }
            }
        }
        if format == ExportFormat::Json {
            writer.text("}\n")?;
        } else if values.is_empty() {
            writer.text("\n")?;
        }
        Ok(())
    })
}

