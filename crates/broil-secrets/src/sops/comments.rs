// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Error, MAX_ITEMS};
use std::ops::Range;

pub(super) struct SpanComment {
    pub range: Range<usize>,
    pub line: usize,
    pub column: usize,
    pub inline: bool,
}

pub(super) fn scan(
    source: &str,
    mut scalars: Vec<Range<usize>>,
) -> Result<Vec<SpanComment>, Error> {
    scalars.sort_by_key(|range| range.start);
    let mut ranges = scalars.into_iter().peekable();
    let mut comments = Vec::new();
    let mut line_start = 0;
    let mut line = 1;
    let mut offset = 0;
    while offset < source.len() {
        while ranges.peek().is_some_and(|range| range.end <= offset) {
            ranges.next();
        }
        let covered = ranges.peek().is_some_and(|range| range.contains(&offset));
        let byte = source.as_bytes()[offset];
        if byte == b'#'
            && !covered
            && (offset == line_start || source.as_bytes()[offset - 1].is_ascii_whitespace())
        {
            let end = source[offset..]
                .find(['\r', '\n'])
                .map_or(source.len(), |n| offset + n);
            comments.push(SpanComment {
                range: offset + 1..end,
                line,
                column: source[line_start..offset].chars().count(),
                inline: !source[line_start..offset].trim().is_empty(),
            });
            if comments.len() > MAX_ITEMS {
                return Err(Error::SizeLimit);
            }
            offset = end;
        } else if byte == b'\r' || byte == b'\n' {
            if byte == b'\r' && source.as_bytes().get(offset + 1) == Some(&b'\n') {
                offset += 1;
            }
            offset += 1;
            line_start = offset;
            line += 1;
        } else {
            offset += 1;
        }
    }
    Ok(comments)
}

pub(super) fn quoted_end(source: &str, start: usize, single: bool) -> Result<usize, Error> {
    let bytes = source.as_bytes();
    let quote = if single { b'\'' } else { b'"' };
    if bytes.get(start) != Some(&quote) {
        return Err(Error::InvalidYaml);
    }
    let mut i = start + 1;
    while i < bytes.len() {
        if bytes[i] == quote {
            if single && bytes.get(i + 1) == Some(&quote) {
                i += 2;
            } else {
                return Ok(i + 1);
            }
        } else if !single && bytes[i] == b'\\' {
            i += 2;
        } else {
            i += 1;
        }
    }
    Err(Error::InvalidYaml)
}
