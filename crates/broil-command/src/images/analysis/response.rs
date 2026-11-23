// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{Observation, content};
use super::*;

pub(super) struct Bound<'a> {
    snapshot: &'a Snapshot,
    identity: Identity<'a>,
    end: u64,
}

enum Identity<'a> {
    Attempt(&'a Attempt),
    Retained {
        operation: &'a str,
        number: u64,
        resolution: &'a str,
    },
}

impl Bound<'_> {
    fn identity(&self, fields: &[Value<'_>]) -> Result<()> {
        match self.identity {
            Identity::Attempt(attempt) => attempt.identity(fields),
            Identity::Retained {
                operation,
                number,
                resolution,
            } => require(
                fields[0].number()? == 2
                    && fields[1].equals(operation)?
                    && fields[2].number()? == number
                    && fields[3].equals(resolution)?,
                Failure::Integrity,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    Complete,
    MetadataRequired,
    Invalid,
    Unsupported,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Inheritance,
    FileSource,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Instruction {
    From,
    Copy,
    RunMount,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagOrigin {
    Declared,
    Default,
    Absent,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Range {
    pub start_line: u64,
    pub end_line: u64,
    pub start_column: Option<u64>,
    pub end_column: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Location {
    Dockerfile(Vec<Range>),
    Inherited {
        parent_reference: String,
        parent_root: String,
        parent_platform: String,
        trigger_index: u64,
        consuming_from: Vec<Range>,
    },
    Unavailable,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Use {
    pub role: Role,
    pub instruction: Instruction,
    pub tag_origin: TagOrigin,
    pub location: Location,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Source {
    pub reference: String,
    pub platform: String,
    pub root: Option<String>,
    pub uses: Vec<Use>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Diagnostic {
    pub reason: &'static str,
    pub location: Location,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphOperation {
    pub id: String,
    pub kind: &'static str,
    pub inputs: Vec<String>,
    pub source: Option<usize>,
    pub context: Option<String>,
    pub locations: Vec<Location>,
}

struct Candidate {
    _frame: Bytes,
    _snapshot: Snapshot,
}
pub struct Outcome {
    status: Status,
    operation_id: String,
    analysis_id: u64,
    resolution_id: String,
    path: String,
    sources: Vec<Source>,
    operations: Vec<GraphOperation>,
    diagnostics: Vec<Diagnostic>,
    observation: Observation,
    candidate: Option<Candidate>,
}
impl Outcome {
    pub fn status(&self) -> Status {
        self.status
    }
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub fn analysis_id(&self) -> u64 {
        self.analysis_id
    }
    pub fn resolution_id(&self) -> &str {
        &self.resolution_id
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn sources(&self) -> &[Source] {
        &self.sources
    }
    pub fn operations(&self) -> &[GraphOperation] {
        &self.operations
    }
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }
    pub fn observation(&self) -> &Observation {
        &self.observation
    }
    pub fn has_private_material(&self) -> bool {
        self.candidate.is_some()
    }
    pub(crate) fn retained_bytes(&self) -> usize {
        self.candidate
            .as_ref()
            .map_or(0, |c| c._frame.get().len() + c._snapshot.retained_bytes())
    }
}

fn choice(value: Value<'_>, choices: &[&'static str]) -> Result<&'static str> {
    for &candidate in choices {
        if value.equals(candidate)? {
            return Ok(candidate);
        }
    }
    Err(Failure::Protocol)
}
fn reference(value: Value<'_>) -> Result<String> {
    let text = value.text()?;
    require(text.get().len() <= 512, Failure::Limit)?;
    let raw = std::str::from_utf8(text.get()).map_err(|_| Failure::Protocol)?;
    let normalized = normalize(raw)?;
    require(normalized == raw, Failure::Integrity)?;
    Ok(normalized)
}
fn platform(value: Value<'_>) -> Result<String> {
    let text = value.text()?;
    let text = std::str::from_utf8(text.get()).map_err(|_| Failure::Protocol)?;
    require(
        text.len() <= 128 && valid_platform(text),
        Failure::Integrity,
    )?;
    Ok(text.into())
}
fn array(value: Value<'_>, maximum: usize) -> Result<Vec<Value<'_>>> {
    let items = value.array()?;
    require(items.len() <= maximum, Failure::Limit)?;
    Ok(items)
}
fn ranges(value: Value<'_>, a: &Bound<'_>) -> Result<Vec<Range>> {
    let items = array(value, 1024)?;
    require(!items.is_empty(), Failure::Protocol)?;
    let document = a.snapshot.document.get();
    let lines: Vec<_> = document.split(|b| *b == b'\n').collect();
    let count = lines.len() - usize::from(document.is_empty() || document.ends_with(b"\n"));
    let mut result = Vec::new();
    for item in items {
        let f = item.object(&[b"start_line", b"end_line", b"start_column", b"end_column"])?;
        let (start, end) = (f[0].number()?, f[1].number()?);
        require(
            start > 0 && end >= start && end <= count as u64,
            Failure::Integrity,
        )?;
        let column = |v: Value<'_>| -> Result<Option<u64>> {
            if v.is_null() {
                Ok(None)
            } else {
                Ok(Some(v.number()?))
            }
        };
        let (sc, ec) = (column(f[2])?, column(f[3])?);
        require(sc.is_some() == ec.is_some(), Failure::Protocol)?;
        if let (Some(sc), Some(ec)) = (sc, ec) {
            let first =
                std::str::from_utf8(lines[start as usize - 1]).map_err(|_| Failure::Integrity)?;
            let last =
                std::str::from_utf8(lines[end as usize - 1]).map_err(|_| Failure::Integrity)?;
            require(
                sc <= first.len() as u64
                    && ec <= last.len() as u64
                    && first.is_char_boundary(sc as usize)
                    && last.is_char_boundary(ec as usize)
                    && (start != end || sc <= ec),
                Failure::Integrity,
            )?;
        }
        result.push(Range {
            start_line: start,
            end_line: end,
            start_column: sc,
            end_column: ec,
        });
    }
    Ok(result)
}
fn location(value: Value<'_>, a: &Bound<'_>) -> Result<Location> {
    match choice(
        value.field("kind")?,
        &["dockerfile", "inherited", "unavailable"],
    )? {
        "dockerfile" => {
            let f = value.object(&[b"kind", b"ranges"])?;
            Ok(Location::Dockerfile(ranges(f[1], a)?))
        }
        "inherited" => {
            let f = value.object(&[
                b"kind",
                b"parent_reference",
                b"parent_root",
                b"parent_platform",
                b"trigger_index",
                b"consuming_from",
            ])?;
            let parent_reference = reference(f[1])?;
            let parent_root = content::digest_text(f[2])?;
            let parent_platform = platform(f[3])?;
            let trigger_index = f[4].number()?;
            let parent = a
                .snapshot
                .metadata
                .iter()
                .find(|m| {
                    m.reference == parent_reference
                        && m.platform == parent_platform
                        && m.root.digest == parent_root
                })
                .ok_or(Failure::Integrity)?;
            require(
                trigger_index < parent.triggers()?.len() as u64,
                Failure::Integrity,
            )?;
            Ok(Location::Inherited {
                parent_reference,
                parent_root,
                parent_platform,
                trigger_index,
                consuming_from: ranges(f[5], a)?,
            })
        }
        _ => {
            value.object(&[b"kind"])?;
            Ok(Location::Unavailable)
        }
    }
}
fn uses(value: Value<'_>, a: &Bound<'_>, reference: &str) -> Result<Vec<Use>> {
    let items = array(value, 1024)?;
    require(!items.is_empty(), Failure::Protocol)?;
    let named = ImageReference::parse(reference).ok_or(Failure::Integrity)?;
    let mut result = Vec::new();
    for item in items {
        let f = item.object(&[b"role", b"instruction", b"tag_origin", b"location"])?;
        let role = if choice(f[0], &["inheritance", "file-source"])? == "inheritance" {
            Role::Inheritance
        } else {
            Role::FileSource
        };
        let instruction = match choice(f[1], &["from", "copy", "run-mount"])? {
            "from" => Instruction::From,
            "copy" => Instruction::Copy,
            _ => Instruction::RunMount,
        };
        require(
            (role == Role::Inheritance) == (instruction == Instruction::From),
            Failure::Integrity,
        )?;
        let tag_origin = match choice(f[2], &["declared", "default", "absent"])? {
            "declared" => {
                require(named.tag.is_some(), Failure::Integrity)?;
                TagOrigin::Declared
            }
            "default" => {
                require(
                    named.tag.as_deref() == Some("latest") && named.digest.is_none(),
                    Failure::Integrity,
                )?;
                TagOrigin::Default
            }
            _ => {
                require(
                    named.tag.is_none() && named.digest.is_some(),
                    Failure::Integrity,
                )?;
                TagOrigin::Absent
            }
        };
        let location = location(f[3], a)?;
        require(location != Location::Unavailable, Failure::Integrity)?;
        let value = Use {
            role,
            instruction,
            tag_origin,
            location,
        };
        require(!result.contains(&value), Failure::Integrity)?;
        result.push(value);
    }
    Ok(result)
}
fn check_inherited(location: &Location, sources: &[Source]) -> Result<()> {
    if let Location::Inherited {
        parent_reference,
        parent_root,
        parent_platform,
        consuming_from,
        ..
    } = location
    {
        let parent = sources
            .iter()
            .find(|s| {
                s.reference == *parent_reference
                    && s.platform == *parent_platform
                    && s.root.as_ref() == Some(parent_root)
            })
            .ok_or(Failure::Integrity)?;
        require(
            consuming_from.iter().all(|range| {
                parent.uses.iter().any(|u| u.role == Role::Inheritance
            && matches!(&u.location,Location::Dockerfile(ranges) if ranges.contains(range)))
            }),
            Failure::Integrity,
        )?;
    }
    Ok(())
}
fn sources(value: Value<'_>, a: &Bound<'_>) -> Result<Vec<Source>> {
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for item in array(value, 1024)? {
        let f = item.object(&[b"reference", b"platform", b"root", b"uses"])?;
        let reference = reference(f[0])?;
        let platform = platform(f[1])?;
        require(
            seen.insert((reference.clone(), platform.clone())),
            Failure::Integrity,
        )?;
        let root = if f[2].is_null() {
            None
        } else {
            Some(content::digest_text(f[2])?)
        };
        let known = a
            .snapshot
            .metadata
            .iter()
            .find(|m| m.reference == reference && m.platform == platform);
        require(
            root.as_deref() == known.map(|m| m.root.digest.as_str()),
            Failure::Integrity,
        )?;
        if reference.starts_with("broil-bind.invalid/s") {
            let needle = reference.as_bytes();
            let in_bytes = |bytes: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
            require(
                in_bytes(a.snapshot.document.get())
                    || a.snapshot
                        .options
                        .args
                        .values()
                        .any(|v| in_bytes(v.as_bytes()))
                    || a.snapshot.metadata.iter().any(|m| in_bytes(m.config.get())),
                Failure::Integrity,
            )?;
        }
        let uses = uses(f[3], a, &reference)?;
        result.push(Source {
            reference,
            platform,
            root,
            uses,
        });
    }
    for source in &result {
        for u in &source.uses {
            check_inherited(&u.location, &result)?;
        }
    }
    Ok(result)
}
fn operations(value: Value<'_>, a: &Bound<'_>, sources: &[Source]) -> Result<Vec<GraphOperation>> {
    let mut result = Vec::new();
    let mut ids = BTreeSet::new();
    let mut edges = 0usize;
    for item in array(value, 8192)? {
        let f = item.object(&[
            b"id",
            b"kind",
            b"inputs",
            b"source",
            b"context",
            b"locations",
        ])?;
        let id = content::digest_text(f[0])?;
        require(ids.insert(id.clone()), Failure::Integrity)?;
        let kind = choice(f[1], &["source", "file", "exec", "merge", "diff", "result"])?;
        let inputs = array(f[2], 8192)?
            .into_iter()
            .map(content::digest_text)
            .collect::<Result<Vec<_>>>()?;
        edges = edges.checked_add(inputs.len()).ok_or(Failure::Limit)?;
        require(edges <= 65536, Failure::Limit)?;
        let source = if f[3].is_null() {
            None
        } else {
            let n = f[3].number()?;
            require(
                n < sources.len() as u64 && kind == "source",
                Failure::Integrity,
            )?;
            Some(n as usize)
        };
        let context = if f[4].is_null() {
            None
        } else {
            let mut matched = None;
            for name in &a.snapshot.options.contexts {
                if f[4].equals(name)? {
                    matched = Some(name.clone());
                }
            }
            require(kind == "source" && source.is_none(), Failure::Integrity)?;
            Some(matched.ok_or(Failure::Integrity)?)
        };
        let locations = array(f[5], 1024)?
            .into_iter()
            .map(|v| location(v, a))
            .collect::<Result<Vec<_>>>()?;
        for location in &locations {
            check_inherited(location, sources)?;
        }
        result.push(GraphOperation {
            id,
            kind,
            inputs,
            source,
            context,
            locations,
        });
    }
    for op in &result {
        require(
            op.inputs.iter().all(|id| ids.contains(id) && *id != op.id),
            Failure::Integrity,
        )?;
    }
    let mut done = BTreeSet::new();
    for op in &result {
        require(
            op.inputs.iter().all(|id| done.contains(id)),
            Failure::Integrity,
        )?;
        done.insert(op.id.clone());
    }
    Ok(result)
}

pub(crate) fn same(a: Value<'_>, b: Value<'_>) -> Result<bool> {
    if a.raw().first() != b.raw().first() {
        return Ok(false);
    }
    match a.raw().first() {
        Some(b'"') => Ok(a.text()?.get() == b.text()?.get()),
        Some(b'{') => {
            let left = a.members()?;
            let right = b.members()?;
            if left.len() != right.len() {
                return Ok(false);
            }
            for (key, value) in left {
                let key = key.text()?;
                let mut matching = None;
                for (other, v) in &right {
                    if other.text()?.get() == key.get() {
                        matching = Some(*v);
                        break;
                    }
                }
                if !matching
                    .map(|v| same(value, v))
                    .transpose()?
                    .unwrap_or(false)
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Some(b'[') => {
            let (left, right) = (a.array()?, b.array()?);
            if left.len() != right.len() {
                return Ok(false);
            }
            for (a, b) in left.into_iter().zip(right) {
                if !same(a, b)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(a.raw() == b.raw()),
    }
}

fn preserved(a: Value<'_>, b: Value<'_>, exceptions: &[&[u8]]) -> Result<()> {
    for (first, second) in [(a, b), (b, a)] {
        for (key, value) in first.members()? {
            let key = key.text()?;
            if exceptions.contains(&key.get()) {
                continue;
            }
            let key = std::str::from_utf8(key.get()).map_err(|_| Failure::Protocol)?;
            require(same(value, second.field(key)?)?, Failure::Integrity)?;
        }
    }
    Ok(())
}

fn history(
    value: Value<'_>,
    original: Value<'_>,
    derived: Value<'_>,
    manifest: Value<'_>,
) -> Result<()> {
    let fields = [
        b"protocol_version".as_slice(),
        b"source_sha256",
        b"convention",
        b"original_config",
        b"original_form",
        b"original_entries",
        b"original_nonempty",
        b"layer_count",
        b"added",
    ];
    let missing = value.optional("missing_history")?;
    let mut exact = fields.to_vec();
    if missing.is_some() {
        exact.push(b"missing_history");
    }
    value.object(&exact)?;
    require(
        value.field("protocol_version")?.number()? == 1
            && value.field("source_sha256")?.equals(&history_identity()?)?
            && value
                .field("convention")?
                .equals("buildkit-v0.24.0-tail-completion")?
            && same(value.field("original_config")?, manifest.field("config")?)?,
        Failure::Integrity,
    )?;
    let old = original.optional("history")?;
    let entries = match old {
        Some(v) if !v.is_null() => v.array()?,
        _ => Vec::new(),
    };
    let form = match old {
        None => "absent",
        Some(v) if v.is_null() => "null",
        _ if entries.is_empty() => "empty",
        _ => "non-empty",
    };
    let nonempty = entries.iter().try_fold(0usize, |n, v| -> Result<usize> {
        let empty = match v.optional("empty_layer")? {
            Some(v) if !v.is_null() => v.boolean()?,
            _ => false,
        };
        Ok(n + usize::from(!empty))
    })?;
    let layers = manifest.field("layers")?.array()?;
    let ids = original.field("rootfs")?.field("diff_ids")?.array()?;
    require(
        nonempty <= layers.len()
            && layers.len() == ids.len()
            && value.field("original_form")?.equals(form)?
            && value.field("original_entries")?.number()? == entries.len() as u64
            && value.field("original_nonempty")?.number()? == nonempty as u64
            && value.field("layer_count")?.number()? == layers.len() as u64,
        Failure::Integrity,
    )?;
    let added = value.field("added")?.array()?;
    let count = layers.len() - nonempty;
    require(
        added.len() == count && missing.is_some() == (count != 0),
        Failure::Integrity,
    )?;
    if let Some(missing) = missing {
        require(missing.equals("unavailable")?, Failure::Integrity)?;
    }
    if count == 0 {
        require(
            match (old, derived.optional("history")?) {
                (None, None) => true,
                (Some(a), Some(b)) => same(a, b)?,
                _ => false,
            },
            Failure::Integrity,
        )?;
        return Ok(());
    }
    let new = derived.field("history")?.array()?;
    require(new.len() == entries.len() + count, Failure::Integrity)?;
    for (a, b) in entries.iter().zip(&new) {
        require(same(*a, *b)?, Failure::Integrity)?;
    }
    let synthetic = b"{\"comment\":\"broil.input.history.v1\",\"created_by\":\"Broil synthetic history: original history unavailable\",\"empty_layer\":false}";
    let synthetic_value = metadata::parse(synthetic)?;
    for (i, item) in added.into_iter().enumerate() {
        let f = item.object(&[
            b"history_ordinal",
            b"layer_ordinal",
            b"layer",
            b"diff_id",
            b"entry_sha256",
        ])?;
        require(
            f[0].number()? == (entries.len() + i) as u64
                && f[1].number()? == (nonempty + i) as u64
                && same(f[2], layers[nonempty + i])?
                && same(f[3], ids[nonempty + i])?
                && f[4].equals(&hash(synthetic))?
                && same(new[entries.len() + i], synthetic_value)?,
            Failure::Integrity,
        )?;
    }
    Ok(())
}

struct Rewrite {
    alias: Bytes,
    reference: String,
    location: Location,
}

fn history_completion(value: Value<'_>) -> Result<HistoryCompletion> {
    let text = |value: Value<'_>, limit: usize| -> Result<String> {
        let text = value.text()?;
        require(text.get().len() <= limit, Failure::Limit)?;
        Ok(std::str::from_utf8(text.get())
            .map_err(|_| Failure::Protocol)?
            .into())
    };
    let mut added = Vec::new();
    for item in array(value.field("added")?, 1024)? {
        let f = item.object(&[
            b"history_ordinal",
            b"layer_ordinal",
            b"layer",
            b"diff_id",
            b"entry_sha256",
        ])?;
        added.push(HistoryAddition {
            history_ordinal: f[0].number()?,
            layer_ordinal: f[1].number()?,
            layer: content::descriptor(f[2], false)?,
            diff_id: content::digest_text(f[3])?,
            entry_sha256: text(f[4], 128)?,
        });
    }
    Ok(HistoryCompletion {
        protocol_version: value.field("protocol_version")?.number()?,
        source_sha256: text(value.field("source_sha256")?, 128)?,
        convention: text(value.field("convention")?, 128)?,
        original_form: choice(
            value.field("original_form")?,
            &["absent", "null", "empty", "non-empty"],
        )?
        .into(),
        original_entries: value.field("original_entries")?.number()?,
        original_nonempty: value.field("original_nonempty")?.number()?,
        layer_count: value.field("layer_count")?.number()?,
        missing_history: match value.optional("missing_history")? {
            Some(value) => Some(text(value, 128)?),
            None => None,
        },
        added,
    })
}

fn rewritten(original: &[u8], generated: &[u8], mappings: &[&Rewrite], end: u64) -> Result<()> {
    let mut segments = Vec::new();
    let mut position = 0;
    while position < generated.len() {
        before(end)?;
        let mut next = None;
        for mapping in mappings {
            if let Some(offset) = generated[position..]
                .windows(mapping.alias.get().len())
                .position(|v| v == mapping.alias.get())
            {
                let at = position + offset;
                if next.as_ref().is_none_or(|(previous, _)| at < *previous) {
                    next = Some((at, *mapping));
                }
            }
        }
        let Some((at, mapping)) = next else {
            break;
        };
        require(segments.len() < 1024, Failure::Limit)?;
        segments.push((at, mapping));
        position = at + mapping.alias.get().len();
    }
    let (mut old, mut new) = (0usize, 0usize);
    for (index, (at, mapping)) in segments.iter().enumerate() {
        let prefix = &generated[new..*at];
        require(
            original.get(old..old.checked_add(prefix.len()).ok_or(Failure::Limit)?) == Some(prefix),
            Failure::Integrity,
        )?;
        old += prefix.len();
        new = at + mapping.alias.get().len();
        let next = segments
            .get(index + 1)
            .map_or(generated.len(), |(at, _)| *at);
        let suffix = &generated[new..next];
        let length = if suffix.is_empty() {
            original.len() - old
        } else {
            original[old..]
                .windows(suffix.len())
                .position(|s| s == suffix)
                .ok_or(Failure::Integrity)?
        };
        let operand = &original[old..old + length];
        let operand = if operand.len() >= 2
            && matches!(operand[0], b'\'' | b'"')
            && operand.last() == operand.first()
        {
            &operand[1..operand.len() - 1]
        } else {
            operand
        };
        let operand = std::str::from_utf8(operand).map_err(|_| Failure::Integrity)?;
        require(normalize(operand)? == mapping.reference, Failure::Integrity)?;
        old += length;
    }
    require(
        original.get(old..) == Some(&generated[new..]),
        Failure::Integrity,
    )
}

fn private(value: Value<'_>, a: &Bound<'_>, sources: &[Source]) -> Result<()> {
    let f = value.object(&[
        b"protocol_version",
        b"operation_id",
        b"analysis_id",
        b"resolution_id",
        b"image",
        b"dockerfile",
        b"bindings",
    ])?;
    a.identity(&f)?;
    require(f[4].raw().len() <= OBJECT, Failure::Limit)?;
    f[4].members()?;
    if let Some(history) = f[4].optional("history")?.filter(|v| !v.is_null()) {
        array(history, 4096)?;
    }
    if let Some(config) = f[4].optional("config")?.filter(|v| !v.is_null()) {
        if let Some(triggers) = config.optional("OnBuild")?.filter(|v| !v.is_null()) {
            for trigger in array(triggers, 256)? {
                trigger.text()?;
            }
        }
    }
    let generated = f[5].text()?;
    require(
        !generated.get().is_empty()
            && generated.get().len() <= 2 * OBJECT
            && generated.get().iter().filter(|b| **b == b'\n').count()
                == a.snapshot
                    .document
                    .get()
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count(),
        Failure::Integrity,
    )?;
    let mut aliases = BTreeSet::new();
    let mut covered = Vec::new();
    let mut rewrites = Vec::new();
    let mut inheritance = Vec::new();
    for binding in array(f[6], 1024)? {
        before(a.end)?;
        let b = binding.object(&[
            b"alias",
            b"context",
            b"source",
            b"role",
            b"root",
            b"config",
            b"manifest",
            b"uses",
            b"history_completion",
        ])?;
        let s = b[2].object(&[b"reference", b"platform", b"root"])?;
        let reference = reference(s[0])?;
        let platform = platform(s[1])?;
        let root = content::digest_text(s[2])?;
        let original = a
            .snapshot
            .metadata
            .iter()
            .find(|m| m.reference == reference && m.platform == platform && m.root.digest == root)
            .ok_or(Failure::Integrity)?;
        let source_index = sources
            .iter()
            .position(|s| s.reference == reference && s.platform == platform)
            .ok_or(Failure::Integrity)?;
        let uses = uses(b[7], a, &reference)?;
        let role = if choice(b[3], &["inheritance", "file-source"])? == "inheritance" {
            Role::Inheritance
        } else {
            Role::FileSource
        };
        require(
            uses.iter()
                .all(|u| u.role == role && sources[source_index].uses.contains(u)),
            Failure::Integrity,
        )?;
        for u in &uses {
            covered.push((source_index, u.clone()));
        }
        let alias = b[0].text()?;
        let context = b[1].text()?;
        const PREFIX: &[u8] = b"broil-bind.invalid/s";
        let stem_length = PREFIX.len() + 64;
        let generated_alias = alias.get().len() == stem_length + 7
            && alias.get().starts_with(PREFIX)
            && hex(&alias.get()[PREFIX.len()..stem_length])
            && alias.get().ends_with(b":latest");
        let portable = role == Role::FileSource && alias.get() == reference.as_bytes();
        let stem = alias.get().strip_suffix(b":latest").unwrap_or(alias.get());
        require(
            (portable || generated_alias)
                && alias.get().len() <= 512
                && context.get().len() == stem.len() + 2 + platform.len()
                && context.get().starts_with(stem)
                && &context.get()[stem.len()..stem.len() + 2] == b"::"
                && &context.get()[stem.len() + 2..] == platform.as_bytes()
                && (portable
                    || !sources
                        .iter()
                        .any(|s| s.reference.as_bytes() == alias.get()))
                && aliases.insert((copy(alias.get())?, platform.clone())),
            Failure::Integrity,
        )?;
        for u in &uses {
            if matches!(u.location, Location::Inherited { .. }) {
                rewrites.push(Rewrite {
                    alias: copy(alias.get())?,
                    reference: reference.clone(),
                    location: u.location.clone(),
                });
            }
        }
        let config = codec::decode64(b[5])?;
        let manifest = codec::decode64(b[6])?;
        let derived = metadata::parse(config.get())?;
        let dm = metadata::parse(manifest.get())?;
        let descriptor = metadata::object_descriptor(manifest.get(), false)?;
        require(
            b[4].equals(&descriptor.digest)?
                && descriptor.media_type == original.manifest_descriptor.media_type,
            Failure::Integrity,
        )?;
        let cd = content::descriptor(dm.field("config")?, false)?;
        require(
            cd.media_type == original.config_descriptor.media_type,
            Failure::Integrity,
        )?;
        metadata::check_bytes(config.get(), &cd)?;
        metadata::check_platform(derived, &platform)?;
        metadata::check_layers(derived, dm, &descriptor.media_type)?;
        let oc = metadata::parse(original.config.get())?;
        let om = metadata::parse(original.manifest.get())?;
        preserved(om, dm, &[b"config"])?;
        preserved(
            om.field("config")?,
            dm.field("config")?,
            &[b"digest", b"size"],
        )?;
        preserved(oc, derived, &[b"config", b"history"])?;
        if role == Role::Inheritance {
            history(b[8], oc, derived, om)?;
            inheritance.push((original, b[5], uses));
        } else {
            require(b[8].is_null(), Failure::Integrity)?;
            require(
                match (oc.optional("history")?, derived.optional("history")?) {
                    (None, None) => true,
                    (Some(x), Some(y)) => same(x, y)?,
                    _ => false,
                },
                Failure::Integrity,
            )?;
        }
        match (oc.optional("config")?, derived.optional("config")?) {
            (None, None) => {}
            (Some(x), Some(y)) if x.is_null() || y.is_null() => {
                require(same(x, y)?, Failure::Integrity)?
            }
            (Some(x), Some(y)) => {
                preserved(x, y, &[b"OnBuild"])?;
                if role == Role::FileSource {
                    let old = original.triggers()?;
                    if old.is_empty() {
                        require(
                            match (x.optional("OnBuild")?, y.optional("OnBuild")?) {
                                (None, None) => true,
                                (Some(x), Some(y)) => same(x, y)?,
                                _ => false,
                            },
                            Failure::Integrity,
                        )?;
                    } else {
                        require(y.field("OnBuild")?.array()?.is_empty(), Failure::Integrity)?;
                    }
                } else {
                    let old = original.triggers()?;
                    let new = match y.optional("OnBuild")? {
                        Some(v) if !v.is_null() => v.array()?,
                        _ => Vec::new(),
                    };
                    require(old.len() == new.len(), Failure::Integrity)?;
                }
            }
            _ => return Err(Failure::Integrity),
        }
    }
    for (original, encoded, uses) in inheritance {
        let bytes = codec::decode64(encoded)?;
        let image = metadata::parse(bytes.get())?;
        let old = original.triggers()?;
        let old_config = metadata::parse(original.config.get())?.optional("config")?;
        let config = image.optional("config")?;
        if old.is_empty() {
            require(
                match (old_config, config) {
                    (None, None) => true,
                    (Some(x), Some(y)) => same(x, y)?,
                    _ => false,
                },
                Failure::Integrity,
            )?;
            continue;
        }
        let new = config
            .ok_or(Failure::Integrity)?
            .field("OnBuild")?
            .array()?;
        let consuming: Vec<_> = uses
            .iter()
            .flat_map(|u| match &u.location {
                Location::Dockerfile(r) => r.clone(),
                _ => Vec::new(),
            })
            .collect();
        for (index, (old, new)) in old.into_iter().zip(new).enumerate() {
            let mappings:Vec<_> = rewrites.iter().filter(|r| matches!(&r.location,Location::Inherited {
                parent_reference,parent_root,parent_platform,trigger_index,consuming_from }
                if *parent_reference == original.reference && *parent_root == original.root.digest
                    && *parent_platform == original.platform && *trigger_index == index as u64 && *consuming_from == consuming)).collect();
            rewritten(old.text()?.get(), new.text()?.get(), &mappings, a.end)?;
        }
    }
    for (i, source) in sources.iter().enumerate() {
        require(
            source
                .uses
                .iter()
                .all(|u| covered.contains(&(i, u.clone()))),
            Failure::Integrity,
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryAddition {
    pub history_ordinal: u64,
    pub layer_ordinal: u64,
    pub layer: Descriptor,
    pub diff_id: String,
    pub entry_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryCompletion {
    pub protocol_version: u64,
    pub source_sha256: String,
    pub convention: String,
    pub original_form: String,
    pub original_entries: u64,
    pub original_nonempty: u64,
    pub layer_count: u64,
    pub missing_history: Option<String>,
    pub added: Vec<HistoryAddition>,
}

pub(crate) struct PrivateBinding {
    pub(crate) alias: String,
    pub(crate) context: String,
    pub(crate) reference: String,
    pub(crate) platform: String,
    pub(crate) source_root: String,
    pub(crate) role: Role,
    pub(crate) generated: bool,
    pub(crate) root: String,
    pub(crate) config: Bytes,
    pub(crate) manifest: Bytes,
    pub(crate) uses: Vec<Use>,
    pub(crate) history_completion: Option<HistoryCompletion>,
}

pub(crate) struct PrivateMaterial<'a> {
    pub(crate) document: &'a [u8],
    pub(crate) dockerfile: Bytes,
    pub(crate) image: Value<'a>,
    pub(crate) bindings: Vec<PrivateBinding>,
}

impl Outcome {
    pub(crate) fn private_material(&self) -> Result<PrivateMaterial<'_>> {
        let candidate = self.candidate.as_ref().ok_or(Failure::Policy)?;
        let bound = Bound {
            snapshot: &candidate._snapshot,
            identity: Identity::Retained {
                operation: &self.operation_id,
                number: self.analysis_id,
                resolution: &self.resolution_id,
            },
            end: deadline(monotonic_ns(), Limits::default().metadata_ms)?,
        };
        let value = Value::parse_analysis(candidate._frame.get())?;
        private(value, &bound, &self.sources)?;
        let f = value.object(&[
            b"protocol_version",
            b"operation_id",
            b"analysis_id",
            b"resolution_id",
            b"image",
            b"dockerfile",
            b"bindings",
        ])?;
        let mut bindings = Vec::new();
        for binding in array(f[6], 1024)? {
            before(bound.end)?;
            let b = binding.object(&[
                b"alias",
                b"context",
                b"source",
                b"role",
                b"root",
                b"config",
                b"manifest",
                b"uses",
                b"history_completion",
            ])?;
            let s = b[2].object(&[b"reference", b"platform", b"root"])?;
            let reference = reference(s[0])?;
            let platform = platform(s[1])?;
            let source_root = content::digest_text(s[2])?;
            let role = if choice(b[3], &["inheritance", "file-source"])? == "inheritance" {
                Role::Inheritance
            } else {
                Role::FileSource
            };
            let alias = b[0].text()?;
            let context = b[1].text()?;
            let text = |bytes: &Bytes| -> Result<String> {
                Ok(std::str::from_utf8(bytes.get())
                    .map_err(|_| Failure::Protocol)?
                    .into())
            };
            let generated = alias.get() != reference.as_bytes();
            let history_completion = if b[8].is_null() {
                None
            } else {
                Some(history_completion(b[8])?)
            };
            bindings.push(PrivateBinding {
                alias: text(&alias)?,
                context: text(&context)?,
                reference: reference.clone(),
                platform,
                source_root,
                role,
                generated,
                root: content::digest_text(b[4])?,
                config: codec::decode64(b[5])?,
                manifest: codec::decode64(b[6])?,
                uses: uses(b[7], &bound, &reference)?,
                history_completion,
            });
        }
        Ok(PrivateMaterial {
            document: candidate._snapshot.document.get(),
            dockerfile: f[5].text()?,
            image: f[4],
            bindings,
        })
    }
}

pub(super) fn decode(a: Attempt, output: Output) -> Result<Outcome> {
    before(a.end)?;
    require(
        output.observation.exit_code == Some(0)
            && output.observation.signal.is_none()
            && output.observation.failure.is_none()
            && !output.observation.completion_uncertain
            && !output.observation.cleanup_uncertain
            && !output.observation.cancellation_requested
            && output.stdout_used <= a.limit
            && output.stderr_used <= a.limit,
        Failure::Protocol,
    )?;
    let bytes = &output.stdout.get()[..output.stdout_used];
    let frame = |position: &mut usize| -> Result<&[u8]> {
        let prefix = bytes
            .get(*position..position.checked_add(4).ok_or(Failure::Limit)?)
            .ok_or(Failure::Protocol)?;
        let n = u32::from_be_bytes(prefix.try_into().map_err(|_| Failure::Protocol)?) as usize;
        *position += 4;
        let end = position.checked_add(n).ok_or(Failure::Limit)?;
        let result = bytes.get(*position..end).ok_or(Failure::Protocol)?;
        *position = end;
        Ok(result)
    };
    let mut position = 0;
    let public = frame(&mut position)?;
    let material = frame(&mut position)?;
    require(
        position == bytes.len() && !public.is_empty(),
        Failure::Protocol,
    )?;
    let bound = Bound {
        snapshot: &a.snapshot,
        identity: Identity::Attempt(&a),
        end: a.end,
    };
    let value = Value::parse_analysis(public)?;
    let f = value.object(&[
        b"protocol_version",
        b"operation_id",
        b"analysis_id",
        b"resolution_id",
        b"status",
        b"sources",
        b"operations",
        b"diagnostics",
    ])?;
    bound.identity(&f)?;
    let status = match choice(
        f[4],
        &["complete", "metadata-required", "invalid", "unsupported"],
    )? {
        "complete" => Status::Complete,
        "metadata-required" => Status::MetadataRequired,
        "invalid" => Status::Invalid,
        _ => Status::Unsupported,
    };
    let sources = sources(f[5], &bound)?;
    let operations = operations(f[6], &bound, &sources)?;
    let mut diagnostics = Vec::new();
    for item in array(f[7], 1024)? {
        let f = item.object(&[b"reason", b"location"])?;
        let reason = choice(
            f[0],
            &[
                "invalid-dockerfile",
                "invalid-instruction",
                "unresolved-argument",
                "unresolved-source",
                "missing-stage",
                "missing-metadata",
                "unsupported-frontend",
                "unsupported-semantics",
                "integrity",
                "limit",
            ],
        )?;
        let location = location(f[1], &bound)?;
        check_inherited(&location, &sources)?;
        diagnostics.push(Diagnostic { reason, location });
    }
    match status {
        Status::Complete => {
            require(
                !material.is_empty()
                    && diagnostics.is_empty()
                    && sources.iter().all(|s| s.root.is_some()),
                Failure::Protocol,
            )?;
            private(Value::parse_analysis(material)?, &bound, &sources)?;
        }
        Status::MetadataRequired => require(
            material.is_empty()
                && operations.is_empty()
                && sources.iter().any(|s| s.root.is_none()),
            Failure::Protocol,
        )?,
        Status::Invalid | Status::Unsupported => require(
            material.is_empty() && operations.is_empty() && !diagnostics.is_empty(),
            Failure::Protocol,
        )?,
    }
    before(a.end)?;
    let path = a.snapshot.options.path.clone();
    let candidate = if status == Status::Complete {
        Some(Candidate {
            _frame: copy(material)?,
            _snapshot: a.snapshot,
        })
    } else {
        None
    };
    Ok(Outcome {
        status,
        operation_id: a.operation,
        analysis_id: a.number,
        resolution_id: a.resolution,
        path,
        sources,
        operations,
        diagnostics,
        observation: output.observation,
        candidate,
    })
}
