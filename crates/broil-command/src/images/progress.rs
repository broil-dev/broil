// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{common::*, json::Value};

fn event(value: Value<'_>, kind: u8) -> Result<()> {
    require(!value.members()?.is_empty(), Failure::Protocol)?;
    for (key, item) in value.members()? {
        let key = key.text()?;
        match (kind, key.get()) {
            (1, b"digest") | (2 | 3, b"vertex") => {
                super::content::digest_text(item)?;
            }
            (1, b"inputs") => {
                for input in item.array()? {
                    super::content::digest_text(input)?;
                }
            }
            (1, b"name" | b"started" | b"completed")
            | (2, b"id" | b"name" | b"timestamp" | b"started" | b"completed")
            | (3, b"data" | b"timestamp")
            | (4, b"id" | b"name") => {
                item.text()?;
            }
            (1, b"cached") | (4, b"weak") => {
                item.boolean()?;
            }
            (1, b"error") => {
                require(item.equals("")?, Failure::Tool)?;
            }
            (1, b"progressGroup") => event(item, 4)?,
            (2, b"current" | b"total") => {
                item.number()?;
            }
            (3, b"stream") => {
                require(item.number()? <= 2, Failure::Protocol)?;
            }
            _ => return Err(Failure::Protocol),
        }
    }
    if kind == 1 {
        super::content::digest_text(value.field("digest")?)?;
    }
    if kind == 3 {
        value.field("data")?.text()?;
    }
    Ok(())
}

pub(crate) fn validate(bytes: &[u8], limits: &Limits, end: u64) -> Result<()> {
    require(bytes.len() <= limits.stream_bytes, Failure::Limit)?;
    let mut records = 0;
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        before(end)?;
        records += 1;
        require(records <= limits.records, Failure::Limit)?;
        let value = Value::parse_bounded(line, limits.record_bytes, limits.json_depth)?;
        let fields = value.members()?;
        require(!fields.is_empty(), Failure::Protocol)?;
        for (key, item) in fields {
            let key = key.text()?;
            match key.get() {
                b"vertexes" | b"statuses" | b"logs" => {
                    let kind = match key.get() {
                        b"vertexes" => 1,
                        b"statuses" => 2,
                        _ => 3,
                    };
                    for value in item.array()? {
                        event(value, kind)?;
                    }
                }
                b"warnings" => require(item.array()?.is_empty(), Failure::Protocol)?,
                _ => return Err(Failure::Protocol),
            }
        }
    }
    require(records > 0, Failure::Protocol)
}
