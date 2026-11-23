// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

pub fn secret_version(source: &Value) -> Option<String> {
    if let Some(vault) = source.get("vault") {
        let digits = match &vault["current_version"] {
            Value::Number(n) => n.as_u64().map(|n| n.to_string()),
            Value::String(s) => Some(s.clone()),
            _ => None,
        }?;
        return (!digits.is_empty()
            && digits.len() <= 20
            && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("vault:{digits}"));
    }
    source
        .get("sops")
        .and_then(|sops| sops["lastmodified"].as_str())
        .and_then(utc_seconds)
        .map(|modified| format!("sops:{modified}"))
}

fn utc_seconds(time: &str) -> Option<String> {
    let bytes = time.as_bytes();
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = time.get(range)?;
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let mut rest = &time[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        rest = &fraction[digits..];
    }
    if !matches!(rest, "Z" | "z" | "+00:00" | "-00:00") {
        return None;
    }
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return None,
    };
    if day < 1 || day > days_in_month || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(format!("{}Z", &time[..19]).replacen('t', "T", 1))
}
