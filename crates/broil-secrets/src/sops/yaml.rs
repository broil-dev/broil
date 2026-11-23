// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::comments::{self, SpanComment};
use super::tree::{Budget, Comment, Entry, Plaintext, Scalar, ScalarKind, Value};
use super::{Error, MAX_DOCUMENT_BYTES, MAX_ITEMS, MAX_SCALAR_BYTES};
use saphyr_parser::{Event as ParserEvent, Marker, Parser, ScalarStyle, Span, Tag};
use std::borrow::Cow;
use std::{
    collections::{BTreeMap, HashSet},
    fmt::Write as _,
    iter::Peekable,
    vec::IntoIter,
};
use zeroize::Zeroizing;

enum Event<'a> {
    StreamStart,
    StreamEnd,
    DocumentStart,
    DocumentEnd,
    Alias(usize),
    Scalar(Plaintext, ScalarStyle, usize, Option<Cow<'a, Tag>>),
    MappingStart(usize, Option<Cow<'a, Tag>>),
    MappingEnd,
    SequenceStart(usize, Option<Cow<'a, Tag>>),
    SequenceEnd,
}

fn protect_event(event: ParserEvent<'_>, encrypted: bool) -> Result<Event<'_>, Error> {
    Ok(match event {
        ParserEvent::Scalar(value, style, anchor, tag) => {
            if value.len()
                > if encrypted {
                    MAX_SCALAR_BYTES * 2
                } else {
                    MAX_SCALAR_BYTES
                }
            {
                return Err(Error::SizeLimit);
            }
            Event::Scalar(
                Plaintext::from_zeroizing(value.into_zeroizing())?,
                style,
                anchor,
                tag,
            )
        }
        ParserEvent::MappingStart(anchor, tag) => Event::MappingStart(anchor, tag),
        ParserEvent::SequenceStart(anchor, tag) => Event::SequenceStart(anchor, tag),
        ParserEvent::StreamStart => Event::StreamStart,
        ParserEvent::StreamEnd => Event::StreamEnd,
        ParserEvent::DocumentStart(_) => Event::DocumentStart,
        ParserEvent::DocumentEnd => Event::DocumentEnd,
        ParserEvent::Alias(anchor) => Event::Alias(anchor),
        ParserEvent::MappingEnd => Event::MappingEnd,
        ParserEvent::SequenceEnd => Event::SequenceEnd,
        ParserEvent::Nothing => return Err(Error::InvalidYaml),
    })
}

struct Located<'a> {
    event: Event<'a>,
    span: Span,
    start: usize,
}

pub(super) fn parse(input: &Plaintext, encrypted: bool) -> Result<Value, Error> {
    let source = input.as_str();
    if source.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::SizeLimit);
    }
    let mut offsets: Vec<_> = source.char_indices().map(|(offset, _)| offset).collect();
    offsets.push(source.len());
    let offset = |marker: Marker| {
        offsets
            .get(marker.index())
            .copied()
            .ok_or(Error::InvalidYaml)
    };
    let mut events = Vec::new();
    let mut scalar_ranges = Vec::new();
    let mut depth = 0usize;
    for event in Parser::new_from_str(source) {
        let (event, span) = event.map_err(|_| Error::InvalidYaml)?;
        let event = protect_event(event, encrypted)?;
        match event {
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                depth += 1;
                if depth > 129 {
                    return Err(Error::SizeLimit);
                }
            }
            Event::MappingEnd | Event::SequenceEnd => {
                depth = depth.checked_sub(1).ok_or(Error::InvalidYaml)?;
            }
            _ => {}
        }
        let start = offset(span.start)?;
        let end = offset(span.end)?;
        if let Event::Scalar(_, style, ..) = &event {
            let last = match style {
                ScalarStyle::SingleQuoted => comments::quoted_end(source, start, true)?,
                ScalarStyle::DoubleQuoted => comments::quoted_end(source, start, false)?,
                _ => end,
            };
            scalar_ranges.push(start..last);
        }
        events.push(Located { event, span, start });
        if events.len() > 2 * MAX_ITEMS + 4 {
            return Err(Error::SizeLimit);
        }
    }
    let mut reader = Reader {
        source,
        events: events.into_iter().peekable(),
        comments: comments::scan(source, scalar_ranges)?
            .into_iter()
            .peekable(),
        budget: Budget::default(),
        anchors: BTreeMap::new(),
        encrypted,
    };
    reader.expect(|event| matches!(event, Event::StreamStart))?;
    reader.expect(|event| matches!(event, Event::DocumentStart))?;
    let (mut root, _) = reader.value(0)?;
    reader.expect(|event| matches!(event, Event::DocumentEnd))?;
    reader.expect(|event| matches!(event, Event::StreamEnd))?;
    if reader.events.next().is_some() {
        return Err(Error::InvalidYaml);
    }
    let Value::Mapping(entries) = &mut root else {
        return Err(Error::InvalidYaml);
    };
    while let Some(comment) = reader.comments.next() {
        entries.push(Entry::Comment(reader.comment(comment, 0)?));
    }
    Ok(root)
}

struct Reader<'a> {
    source: &'a str,
    events: Peekable<IntoIter<Located<'a>>>,
    comments: Peekable<IntoIter<SpanComment>>,
    anchors: BTreeMap<usize, Value>,
    budget: Budget,
    encrypted: bool,
}

impl Reader<'_> {
    fn expect(&mut self, predicate: impl FnOnce(&Event<'_>) -> bool) -> Result<(), Error> {
        if self
            .events
            .next()
            .is_some_and(|event| predicate(&event.event))
        {
            Ok(())
        } else {
            Err(Error::InvalidYaml)
        }
    }
    fn comment(&mut self, comment: SpanComment, depth: usize) -> Result<Comment, Error> {
        self.budget.item(depth)?;
        let value = &self.source[comment.range];
        self.budget.bytes(value.len())?;
        if value.len()
            > if self.encrypted {
                MAX_SCALAR_BYTES * 2
            } else {
                MAX_SCALAR_BYTES
            }
        {
            return Err(Error::SizeLimit);
        }
        Ok(Comment {
            text: Plaintext::copy_from(value)?,
            inline: comment.inline,
        })
    }
    fn preceding(
        &mut self,
        before: usize,
        column: usize,
        depth: usize,
    ) -> Result<Vec<Comment>, Error> {
        let mut output = Vec::new();
        while self.comments.peek().is_some_and(|comment| {
            comment.range.start <= before && (depth == 0 || comment.column >= column)
        }) {
            let comment = self.comments.next().expect("peeked comment");
            output.push(self.comment(comment, depth)?);
        }
        Ok(output)
    }
    fn value(&mut self, depth: usize) -> Result<(Value, Span), Error> {
        self.budget.item(depth)?;
        let Located {
            event,
            mut span,
            start: _,
        } = self.events.next().ok_or(Error::InvalidYaml)?;
        let (value, anchor) = match event {
            Event::Scalar(scalar, style, anchor, tag) => {
                self.budget.bytes(scalar.as_bytes().len())?;
                let limit = if self.encrypted {
                    MAX_SCALAR_BYTES * 2
                } else {
                    MAX_SCALAR_BYTES
                };
                if scalar.as_bytes().len() > limit {
                    return Err(Error::SizeLimit);
                }
                (resolve(scalar, style, tag.as_deref())?, anchor)
            }
            Event::Alias(anchor) => {
                let value = self.anchors.get(&anchor).ok_or(Error::InvalidYaml)?;
                (value.copy_bounded(&mut self.budget, depth)?, 0)
            }
            Event::MappingStart(anchor, tag) => {
                check_collection_tag(tag.as_deref(), "map")?;
                let mut entries = Vec::new();
                let mut keys = HashSet::new();
                loop {
                    let next = self.events.peek().ok_or(Error::InvalidYaml)?;
                    let before = next.start;
                    let end = matches!(next.event, Event::MappingEnd);
                    for comment in self.preceding(before, span.start.col(), depth)? {
                        entries.push(Entry::Comment(comment));
                    }
                    if end {
                        span.end = self.events.next().expect("peeked event").span.end;
                        break;
                    }
                    let (key, key_span) = self.value(depth + 1)?;
                    let key = key.string_value()?.to_owned();
                    if !keys.insert(key.clone()) {
                        return Err(Error::DuplicateKey);
                    }
                    let value_start = self.events.peek().ok_or(Error::InvalidYaml)?.start;
                    let is_collection = matches!(
                        self.events.peek().expect("peeked").event,
                        Event::SequenceStart(..) | Event::MappingStart(..)
                    );
                    if !is_collection {
                        for comment in self.preceding(value_start, span.start.col(), depth)? {
                            entries.push(Entry::Comment(comment));
                        }
                    }
                    let (value, value_span) = self.value(depth + 1)?;
                    if !is_collection {
                        while self.comments.peek().is_some_and(|comment| {
                            comment.inline
                                && comment.line >= key_span.start.line()
                                && comment.line <= value_span.end.line()
                        }) {
                            let comment = self.comments.next().expect("peeked");
                            entries.push(Entry::Comment(self.comment(comment, depth)?));
                        }
                    }
                    entries.push(Entry::Pair(key, value));
                }
                (Value::Mapping(entries), anchor)
            }
            Event::SequenceStart(anchor, tag) => {
                check_collection_tag(tag.as_deref(), "seq")?;
                let mut values = Vec::new();
                loop {
                    let next = self.events.peek().ok_or(Error::InvalidYaml)?;
                    let before = next.start;
                    let end = matches!(next.event, Event::SequenceEnd);
                    for comment in self.preceding(before, span.start.col(), depth)? {
                        values.push(Value::Comment(comment));
                    }
                    if end {
                        span.end = self.events.next().expect("peeked").span.end;
                        break;
                    }
                    let (value, value_span) = self.value(depth + 1)?;
                    while self.comments.peek().is_some_and(|comment| {
                        comment.inline && comment.line <= value_span.end.line()
                    }) {
                        let comment = self.comments.next().expect("peeked");
                        values.push(Value::Comment(self.comment(comment, depth)?));
                    }
                    values.push(value);
                }
                (Value::Sequence(values), anchor)
            }
            _ => return Err(Error::InvalidYaml),
        };
        if anchor != 0 {
            self.anchors
                .insert(anchor, value.copy_bounded(&mut self.budget, depth)?);
        }
        Ok((value, span))
    }
}

fn check_collection_tag(tag: Option<&Tag>, kind: &str) -> Result<(), Error> {
    if tag.is_some_and(|tag| !tag.is_yaml_core_schema() || tag.suffix != kind) {
        Err(Error::InvalidType)
    } else {
        Ok(())
    }
}

fn resolve(text: Plaintext, style: ScalarStyle, tag: Option<&Tag>) -> Result<Value, Error> {
    let explicit = if let Some(tag) = tag {
        if !tag.is_yaml_core_schema() {
            return Err(Error::InvalidType);
        }
        Some(tag.suffix.as_str())
    } else {
        None
    };
    if explicit == Some("str") || (explicit.is_none() && style != ScalarStyle::Plain) {
        return Ok(Value::Scalar(Scalar::new(ScalarKind::String, text)));
    }
    let value = text.as_str();
    let null = matches!(value, "" | "~" | "null" | "Null" | "NULL");
    if null && explicit.is_none_or(|kind| kind == "null") {
        return Ok(Value::Null);
    }
    if let Some(boolean) = match value {
        "true" | "True" | "TRUE" => Some("True"),
        "false" | "False" | "FALSE" => Some("False"),
        _ => None,
    } {
        if explicit.is_none_or(|kind| kind == "bool") {
            return Ok(Value::Scalar(Scalar::new(
                ScalarKind::Boolean,
                Plaintext::copy_from(boolean)?,
            )));
        }
    }
    if !value
        .as_bytes()
        .first()
        .is_some_and(|byte| matches!(byte, b'+' | b'-' | b'.' | b'0'..=b'9'))
    {
        return if explicit.is_some() {
            Err(Error::InvalidType)
        } else {
            Ok(Value::Scalar(Scalar::new(ScalarKind::String, text)))
        };
    }
    let mut clean = Zeroizing::new(String::with_capacity(value.len()));
    for ch in value.chars().filter(|ch| *ch != '_') {
        clean.push(ch);
    }
    let unsigned = clean.strip_prefix(['+', '-']).unwrap_or(&clean);
    let radix = if unsigned.starts_with("0x") || unsigned.starts_with("0X") {
        16
    } else if unsigned.starts_with("0b") || unsigned.starts_with("0B") {
        2
    } else if unsigned.starts_with("0o")
        || unsigned.starts_with("0O")
        || (unsigned.len() > 1 && unsigned.starts_with('0'))
    {
        8
    } else {
        10
    };
    let digits = if ["0x", "0o", "0b", "0X", "0O", "0B"]
        .iter()
        .any(|prefix| unsigned.starts_with(prefix))
    {
        &unsigned[2..]
    } else {
        unsigned
    };
    if explicit.is_none_or(|kind| kind == "int") {
        if let Ok(number) = i128::from_str_radix(digits, radix).and_then(|number| {
            if digits.bytes().any(|byte| matches!(byte, b'+' | b'-')) {
                "invalid".parse::<i128>()
            } else {
                Ok(number)
            }
        }) {
            let mut number = Zeroizing::new(number);
            if clean.starts_with('-') {
                *number = -*number;
            }
            if i64::try_from(*number).is_ok() {
                let mut canonical = Zeroizing::new(String::with_capacity(32));
                write!(&mut *canonical, "{}", *number).expect("bounded integer rendering");
                return Ok(Value::Scalar(Scalar::new(
                    ScalarKind::Integer,
                    Plaintext::from_zeroizing(canonical)?,
                )));
            }
            if u64::try_from(*number).is_ok() {
                return Err(Error::InvalidType);
            }
        }
    }
    if explicit.is_none_or(|kind| kind == "float") {
        let number = match clean.as_str() {
            ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => Some(f64::INFINITY),
            "-.inf" | "-.Inf" | "-.INF" => Some(f64::NEG_INFINITY),
            ".nan" | ".NaN" | ".NAN" => Some(f64::NAN),
            _ if decimal_float(&clean) => clean
                .parse::<f64>()
                .ok()
                .filter(|number| number.is_finite()),
            _ => None,
        };
        if let Some(number) = number {
            let number = Zeroizing::new(number);
            let mut canonical = Zeroizing::new(String::with_capacity(384));
            if number.is_nan() {
                canonical.push_str("NaN");
            } else if *number == f64::INFINITY {
                canonical.push_str("+Inf");
            } else if *number == f64::NEG_INFINITY {
                canonical.push_str("-Inf");
            } else {
                write!(&mut *canonical, "{}", *number).expect("bounded float rendering");
            }
            return Ok(Value::Scalar(Scalar::new(
                ScalarKind::Float,
                Plaintext::from_zeroizing(canonical)?,
            )));
        }
    }
    if explicit.is_some() {
        Err(Error::InvalidType)
    } else {
        Ok(Value::Scalar(Scalar::new(ScalarKind::String, text)))
    }
}

fn decimal_float(text: &str) -> bool {
    let text = text.strip_prefix(['+', '-']).unwrap_or(text);
    let mut parts = text.split(['e', 'E']);
    let mantissa = parts.next().unwrap_or("");
    let mut digits = false;
    let mut dot = false;
    for byte in mantissa.bytes() {
        if byte.is_ascii_digit() {
            digits = true;
        } else if byte == b'.' && !dot {
            dot = true;
        } else {
            return false;
        }
    }
    if !digits {
        return false;
    }
    if let Some(exponent) = parts.next() {
        let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        if exponent.is_empty() || !exponent.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    parts.next().is_none()
}

struct Writer {
    output: Option<Zeroizing<String>>,
    length: usize,
}
impl Writer {
    fn text(&mut self, text: &str) -> Result<(), Error> {
        self.length = self
            .length
            .checked_add(text.len())
            .ok_or(Error::SizeLimit)?;
        if self.length > MAX_DOCUMENT_BYTES {
            return Err(Error::SizeLimit);
        }
        if let Some(output) = &mut self.output {
            if self.length > output.capacity() {
                return Err(Error::SizeLimit);
            }
            output.push_str(text);
        }
        Ok(())
    }
    fn indent(&mut self, indent: usize) -> Result<(), Error> {
        for _ in 0..indent {
            self.text(" ")?;
        }
        Ok(())
    }
    fn quoted(&mut self, text: &str) -> Result<(), Error> {
        self.text("\"")?;
        for ch in text.chars() {
            match ch {
                '"' => self.text("\\\"")?,
                '\\' => self.text("\\\\")?,
                '\n' => self.text("\\n")?,
                '\r' => self.text("\\r")?,
                '\t' => self.text("\\t")?,
                ch if ch.is_control() => {
                    let mut encoded = Zeroizing::new(String::with_capacity(12));
                    write!(&mut *encoded, "\\U{:08X}", ch as u32).expect("fixed escape");
                    self.text(&encoded)?;
                }
                ch => {
                    let mut encoded = Zeroizing::new([0; 4]);
                    self.text(ch.encode_utf8(&mut *encoded))?;
                }
            }
        }
        self.text("\"")
    }
    fn comment(&mut self, comment: &Comment, indent: usize) -> Result<(), Error> {
        for line in comment.as_str().split('\n') {
            self.indent(indent)?;
            self.text("#")?;
            self.text(line)?;
            self.text("\n")?;
        }
        Ok(())
    }
    fn newline(&mut self, inline: &[&Comment]) -> Result<(), Error> {
        for comment in inline {
            self.text(" #")?;
            self.text(comment.as_str())?;
        }
        self.text("\n")
    }
    fn value(
        &mut self,
        value: &Value,
        indent: usize,
        depth: usize,
        inline: &[&Comment],
    ) -> Result<(), Error> {
        if depth > 128 {
            return Err(Error::SizeLimit);
        }
        match value {
            Value::Mapping(entries) if !entries.is_empty() => {
                self.newline(inline)?;
                let mut pending = Vec::new();
                for entry in entries {
                    match entry {
                        Entry::Comment(comment) if comment.inline => pending.push(comment),
                        Entry::Comment(comment) => self.comment(comment, indent)?,
                        Entry::Pair(key, value) => {
                            self.indent(indent)?;
                            self.quoted(key)?;
                            self.text(": ")?;
                            self.value(value, indent + 4, depth + 1, &pending)?;
                            pending.clear();
                        }
                    }
                }
                for comment in pending {
                    self.comment(comment, indent)?;
                }
                Ok(())
            }
            Value::Sequence(values) if !values.is_empty() => {
                self.newline(inline)?;
                let mut pending = Vec::new();
                for value in values {
                    if let Value::Comment(comment) = value {
                        if comment.inline {
                            pending.push(comment);
                        } else {
                            self.comment(comment, indent)?;
                        }
                    } else {
                        self.indent(indent)?;
                        self.text("- ")?;
                        self.value(value, indent + 4, depth + 1, &pending)?;
                        pending.clear();
                    }
                }
                for comment in pending {
                    self.comment(comment, indent)?;
                }
                Ok(())
            }
            Value::Scalar(scalar) => {
                match scalar.kind {
                    ScalarKind::String
                        if scalar.as_str().contains('\n') && !scalar.as_str().contains('\r') =>
                    {
                        let text = scalar.as_str();
                        let trailing = text.bytes().rev().take_while(|byte| *byte == b'\n').count();
                        self.text(match trailing {
                            0 => "|-",
                            1 => "|",
                            _ => "|+",
                        })?;
                        self.newline(inline)?;
                        for line in text.split_terminator('\n') {
                            self.indent(indent)?;
                            self.text(line)?;
                            self.text("\n")?;
                        }
                        return Ok(());
                    }
                    ScalarKind::String => self.quoted(scalar.as_str())?,
                    ScalarKind::Integer | ScalarKind::Boolean => self.text(scalar.as_str())?,
                    ScalarKind::Float => {
                        let text = scalar.as_str();
                        match text {
                            "NaN" => self.text(".nan")?,
                            "+Inf" => self.text(".inf")?,
                            "-Inf" => self.text("-.inf")?,
                            _ => {
                                self.text(text)?;
                                if !text.contains(['.', 'e', 'E']) {
                                    self.text(".0")?;
                                }
                            }
                        }
                    }
                }
                self.newline(inline)
            }
            Value::Mapping(_) => {
                self.text("{}")?;
                self.newline(inline)
            }
            Value::Sequence(_) => {
                self.text("[]")?;
                self.newline(inline)
            }
            Value::Null => {
                self.text("null")?;
                self.newline(inline)
            }
            Value::Comment(comment) => self.comment(comment, indent),
        }
    }
}

pub(super) fn render(tree: &Value) -> Result<Plaintext, Error> {
    let mut writer = Writer {
        output: None,
        length: 0,
    };
    writer.value(tree, 0, 0, &[])?;
    let mut output = Zeroizing::new(String::new());
    output
        .try_reserve_exact(writer.length)
        .map_err(|_| Error::Allocation)?;
    let mut writer = Writer {
        output: Some(output),
        length: 0,
    };
    writer.value(tree, 0, 0, &[])?;
    Plaintext::from_zeroizing(writer.output.expect("render buffer"))
}
