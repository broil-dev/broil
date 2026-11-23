// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use base64ct::{Base64, Base64Unpadded, Encoding};
use std::borrow::Cow;

use super::{Error, check_size, kdf::parse_work_factor};

pub(super) const INTRO: &[u8] = b"age-encryption.org/v1\n";
const ARMOR_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const ARMOR_END: &[u8] = b"-----END AGE ENCRYPTED FILE-----";

pub(super) enum Stanza {
    X25519 {
        share: [u8; 32],
        body: [u8; 32],
    },
    Scrypt {
        salt: [u8; 16],
        log_n: u8,
        body: [u8; 32],
    },
    Unknown,
}

pub(super) struct Header<'a> {
    pub stanzas: &'a [u8],
    pub authenticated: &'a [u8],
    pub mac: [u8; 32],
    pub payload: &'a [u8],
}

pub(super) fn line<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let end = input
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(Error::InvalidHeader)?;
    let result = &input[..end];
    *input = &input[end + 1..];
    Ok(result)
}

pub(super) fn decode<const N: usize>(text: &[u8]) -> Result<[u8; N], Error> {
    let mut output = [0; N];
    if Base64Unpadded::decode(text, &mut output)
        .map_err(|_| Error::InvalidHeader)?
        .len()
        != N
    {
        return Err(Error::InvalidHeader);
    }
    Ok(output)
}

pub(super) fn encode(input: &[u8], output: &mut Vec<u8>) {
    let mut buffer = [0; 64];
    output.extend_from_slice(
        Base64Unpadded::encode(input, &mut buffer)
            .expect("bounded field")
            .as_bytes(),
    );
}

pub(super) fn stanza(input: &mut &[u8]) -> Result<Stanza, Error> {
    let opening = line(input)?
        .strip_prefix(b"-> ")
        .ok_or(Error::InvalidHeader)?;
    if opening.is_empty()
        || opening
            .split(|b| *b == b' ')
            .any(|arg| arg.is_empty() || !arg.iter().all(|b| (33..=126).contains(b)))
    {
        return Err(Error::InvalidHeader);
    }
    let mut args = std::str::from_utf8(opening)
        .map_err(|_| Error::InvalidHeader)?
        .split(' ');
    let kind = args.next().ok_or(Error::InvalidHeader)?;
    let mut body = [0; 32];
    let mut size = 0usize;
    loop {
        let text = line(input)?;
        if text.len() > 64 {
            return Err(Error::InvalidHeader);
        }
        let mut buffer = [0; 48];
        let decoded =
            Base64Unpadded::decode(text, &mut buffer).map_err(|_| Error::InvalidHeader)?;
        if size == 0 && decoded.len() == 32 {
            body.copy_from_slice(decoded);
        }
        size = size.checked_add(decoded.len()).ok_or(Error::SizeLimit)?;
        if text.len() < 64 {
            break;
        }
    }
    match kind {
        "X25519" => {
            let share = decode(args.next().ok_or(Error::InvalidHeader)?.as_bytes())?;
            if args.next().is_some() || size != 32 {
                return Err(Error::InvalidHeader);
            }
            Ok(Stanza::X25519 { share, body })
        }
        "scrypt" => {
            let salt = decode(args.next().ok_or(Error::InvalidHeader)?.as_bytes())?;
            let log_n = parse_work_factor(args.next().ok_or(Error::InvalidHeader)?)?;
            if args.next().is_some() || size != 32 {
                return Err(Error::InvalidHeader);
            }
            Ok(Stanza::Scrypt { salt, log_n, body })
        }
        _ => Ok(Stanza::Unknown),
    }
}

pub(super) fn header(input: &[u8]) -> Result<Header<'_>, Error> {
    check_size(input.len())?;
    let start = input.strip_prefix(INTRO).ok_or(Error::InvalidHeader)?;
    let mut cursor = start;
    let mut count = 0;
    let mut has_scrypt = false;
    while !cursor.starts_with(b"---") {
        has_scrypt |= matches!(stanza(&mut cursor)?, Stanza::Scrypt { .. });
        count += 1;
    }
    if count == 0 || (has_scrypt && count != 1) {
        return Err(Error::InvalidHeader);
    }
    let stanzas = &start[..start.len() - cursor.len()];
    let authenticated = &input[..input.len() - cursor.len() + 3];
    let mac = decode(
        line(&mut cursor)?
            .strip_prefix(b"--- ")
            .ok_or(Error::InvalidHeader)?,
    )?;
    Ok(Header {
        stanzas,
        authenticated,
        mac,
        payload: cursor,
    })
}

pub(super) fn input_bytes(input: &[u8]) -> Result<Cow<'_, [u8]>, Error> {
    check_size(input.len())?;
    if input.starts_with(b"age-encryption.org/") {
        return Ok(Cow::Borrowed(input));
    }
    if input.iter().copied().find(|b| !b.is_ascii_whitespace()) == Some(b'-')
        || std::str::from_utf8(input).is_ok_and(|text| text.trim_start().starts_with('-'))
    {
        return Ok(Cow::Owned(dearmor(input)?));
    }
    Ok(Cow::Borrowed(input))
}

fn armor_line<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    if input.is_empty() {
        return Err(Error::InvalidArmor);
    }
    let end = input
        .iter()
        .position(|b| *b == b'\n')
        .unwrap_or(input.len());
    let result = &input[..end];
    *input = &input[(end + 1).min(input.len())..];
    Ok(result.strip_suffix(b"\r").unwrap_or(result))
}

fn whitespace(input: &[u8]) -> bool {
    std::str::from_utf8(input).is_ok_and(|s| s.chars().all(char::is_whitespace))
}

pub fn dearmor(mut input: &[u8]) -> Result<Vec<u8>, Error> {
    check_size(input.len())?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| Error::Allocation)?;
    let mut removed = 0;
    loop {
        let opening = armor_line(&mut input)?;
        if whitespace(opening) {
            removed += opening.len() + 1;
            if removed > 1024 {
                return Err(Error::InvalidArmor);
            }
        } else if opening == ARMOR_BEGIN {
            break;
        } else {
            return Err(Error::InvalidArmor);
        }
    }
    let mut short = false;
    loop {
        let text = armor_line(&mut input)?;
        if text == ARMOR_END {
            if input.len() >= 1024 || !whitespace(input) {
                return Err(Error::InvalidArmor);
            }
            return Ok(output);
        }
        if short || text.len() > 64 {
            return Err(Error::InvalidArmor);
        }
        let mut buffer = [0; 48];
        let decoded = Base64::decode(text, &mut buffer).map_err(|_| Error::InvalidArmor)?;
        short = decoded.len() < 48;
        output.extend_from_slice(decoded);
    }
}

pub fn armor(input: &[u8]) -> Result<Vec<u8>, Error> {
    check_size(input.len())?;
    let encoded = input
        .len()
        .div_ceil(3)
        .checked_mul(4)
        .ok_or(Error::SizeLimit)?;
    let length = encoded
        .checked_add(encoded.div_ceil(64))
        .and_then(|n| n.checked_add(ARMOR_BEGIN.len() + ARMOR_END.len() + 2))
        .ok_or(Error::SizeLimit)?;
    check_size(length)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| Error::Allocation)?;
    output.extend_from_slice(ARMOR_BEGIN);
    output.push(b'\n');
    for part in input.chunks(48) {
        let mut buffer = [0; 64];
        output.extend_from_slice(
            Base64::encode(part, &mut buffer)
                .expect("bounded armor line")
                .as_bytes(),
        );
        output.push(b'\n');
    }
    output.extend_from_slice(ARMOR_END);
    output.push(b'\n');
    Ok(output)
}
