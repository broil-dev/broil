// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{ErrorKind, Result, validate_component, validate_user_key};
use crate::sops::{self, Document, Entry, Plaintext, Scalar, ScalarKind, Selector, Value};
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Created,
    TransitionReady,
    StoreUpdated,
    Deployed,
    OldRevoked,
    Verified,
}
impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::TransitionReady => "TRANSITION_READY",
            Self::StoreUpdated => "STORE_UPDATED",
            Self::Deployed => "DEPLOYED",
            Self::OldRevoked => "OLD_REVOKED",
            Self::Verified => "VERIFIED",
        }
    }
    fn parse(value: &str) -> Result<Self> {
        [
            Self::Created,
            Self::TransitionReady,
            Self::StoreUpdated,
            Self::Deployed,
            Self::OldRevoked,
            Self::Verified,
        ]
        .into_iter()
        .find(|state| state.as_str() == value)
        .ok_or(ErrorKind::OwnedSchema.into())
    }
    pub(crate) fn rank(self) -> usize {
        match self {
            Self::Created => 0,
            Self::TransitionReady => 1,
            Self::StoreUpdated => 2,
            Self::Deployed => 3,
            Self::OldRevoked => 4,
            Self::Verified => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackStage {
    Handlers,
    Sync,
    Finish,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rollback {
    pub stage: RollbackStage,
    pub from_state: State,
    pub remaining: Vec<State>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Marker {
    pub state: State,
    pub in_progress: bool,
    pub operator: String,
    pub host: String,
    pub started: String,
    pub id: String,
    pub handler_type: String,
    pub generator: String,
    pub environment: Option<String>,
    pub keep_previous: bool,
    pub note: Option<String>,
    pub rollback: Option<Rollback>,
}
impl fmt::Debug for Marker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Marker([REDACTED])")
    }
}

#[derive(Debug)]
pub struct UnauthenticatedStatus {
    markers: Vec<(String, Marker)>,
}
impl UnauthenticatedStatus {
    pub fn authenticated(&self) -> bool {
        false
    }
    pub fn markers(&self) -> &[(String, Marker)] {
        &self.markers
    }
}

fn pairs(value: &Value) -> Result<impl Iterator<Item = (&str, &Value)>> {
    Ok(value
        .entries()
        .ok_or(ErrorKind::OwnedSchema)?
        .iter()
        .filter_map(|entry| {
            if let Entry::Pair(key, value) = entry {
                Some((key.as_str(), value))
            } else {
                None
            }
        }))
}
fn fields(value: &Value, allowed: &[&str]) -> Result<()> {
    for (key, _) in pairs(value)? {
        if !allowed.contains(&key) {
            return Err(ErrorKind::OwnedSchema.into());
        }
    }
    Ok(())
}
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(ErrorKind::OwnedSchema.into())
}
fn text(value: &Value) -> Result<&str> {
    value
        .scalar()
        .filter(|s| s.kind() == ScalarKind::String)
        .map(Scalar::as_str)
        .ok_or(ErrorKind::OwnedSchema.into())
}
fn boolean(value: &Value) -> Result<bool> {
    match value
        .scalar()
        .filter(|s| s.kind() == ScalarKind::Boolean)
        .map(Scalar::as_str)
    {
        Some("true" | "True") => Ok(true),
        Some("false" | "False") => Ok(false),
        _ => Err(ErrorKind::OwnedSchema.into()),
    }
}
fn metadata_text(value: &str, allow_empty: bool, limit: usize) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > limit
        || value.chars().any(char::is_control)
    {
        return Err(ErrorKind::OwnedSchema.into());
    }
    Ok(())
}

impl Marker {
    fn parse(value: &Value) -> Result<Self> {
        fields(
            value,
            &[
                "state",
                "in_progress",
                "operator",
                "host",
                "started",
                "id",
                "type",
                "generator",
                "environment",
                "keep_previous",
                "note",
                "rollback",
            ],
        )?;
        let get_text = |key| -> Result<String> { Ok(text(required(value, key)?)?.to_owned()) };
        let environment = match required(value, "environment")? {
            Value::Null => None,
            value => Some(text(value)?.to_owned()),
        };
        let rollback = value
            .get("rollback")
            .map(|r| -> Result<Rollback> {
                fields(r, &["stage", "from_state", "remaining"])?;
                let stage = match text(required(r, "stage")?)? {
                    "handlers" => RollbackStage::Handlers,
                    "sync" => RollbackStage::Sync,
                    "finish" => RollbackStage::Finish,
                    _ => return Err(ErrorKind::OwnedSchema.into()),
                };
                let from_state = State::parse(text(required(r, "from_state")?)?)?;
                let remaining = required(r, "remaining")?
                    .sequence()
                    .ok_or(ErrorKind::OwnedSchema)?
                    .iter()
                    .filter(|v| !matches!(v, Value::Comment(_)))
                    .map(|v| State::parse(text(v)?))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Rollback {
                    stage,
                    from_state,
                    remaining,
                })
            })
            .transpose()?;
        let marker = Self {
            state: State::parse(&get_text("state")?)?,
            in_progress: boolean(required(value, "in_progress")?)?,
            operator: get_text("operator")?,
            host: get_text("host")?,
            started: get_text("started")?,
            id: get_text("id")?,
            handler_type: get_text("type")?,
            generator: get_text("generator")?,
            environment,
            keep_previous: boolean(required(value, "keep_previous")?)?,
            note: value.get("note").map(text).transpose()?.map(str::to_owned),
            rollback,
        };
        marker.validate()?;
        Ok(marker)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for value in [&self.operator, &self.host] {
            metadata_text(value, false, 4096)?;
        }
        if self.started.len() != 20
            || !self.started.ends_with('Z')
            || chrono::NaiveDateTime::parse_from_str(&self.started, "%Y-%m-%dT%H:%M:%SZ").is_err()
        {
            return Err(ErrorKind::OwnedSchema.into());
        }
        let digits: String = self.started.chars().filter(char::is_ascii_digit).collect();
        if self.id.len() != 22
            || !self.id.starts_with(&digits)
            || !self.id.as_bytes()[14..]
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        {
            return Err(ErrorKind::OwnedSchema.into());
        }
        if !self.handler_type.is_empty() {
            validate_component(&self.handler_type)?;
        }
        if let Some(environment) = &self.environment {
            metadata_text(environment, false, 4096)?;
        }
        if let Some(note) = &self.note {
            if note.len() > 4096 || note.contains(['\r', '\n', '\0']) {
                return Err(ErrorKind::OwnedSchema.into());
            }
        }
        match self.generator.as_str() {
            "prompt" | "ssh-ed25519" => {}
            "handler" if !self.handler_type.is_empty() => {}
            value => {
                let (kind, count) = value.split_once(':').ok_or(ErrorKind::OwnedSchema)?;
                if count.is_empty()
                    || count.starts_with('0')
                    || !count.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(ErrorKind::OwnedSchema.into());
                }
                let count: usize = count.parse().map_err(|_| ErrorKind::OwnedSchema)?;
                let length = match kind {
                    "hex" => count.checked_mul(2),
                    "base64" => count.checked_add(2).and_then(|n| (n / 3).checked_mul(4)),
                    _ => None,
                }
                .ok_or(ErrorKind::OwnedSchema)?;
                if length > sops::MAX_SCALAR_BYTES {
                    return Err(ErrorKind::OwnedSchema.into());
                }
            }
        }
        if let Some(rollback) = &self.rollback {
            if rollback.from_state != self.state
                || rollback
                    .remaining
                    .iter()
                    .any(|s| *s == State::StoreUpdated || s.rank() > rollback.from_state.rank())
                || rollback
                    .remaining
                    .windows(2)
                    .any(|p| p[0].rank() <= p[1].rank())
            {
                return Err(ErrorKind::OwnedSchema.into());
            }
        }
        Ok(())
    }

    fn value(&self) -> Result<Value> {
        self.validate()?;
        let mut value = Value::Mapping(Vec::new());
        for (key, text) in [
            ("state", self.state.as_str()),
            ("operator", &self.operator),
            ("host", &self.host),
            ("started", &self.started),
            ("id", &self.id),
            ("type", &self.handler_type),
            ("generator", &self.generator),
        ] {
            value.put(key, Value::string(text)?)?;
        }
        value.put("in_progress", bool_value(self.in_progress)?)?;
        value.put("keep_previous", bool_value(self.keep_previous)?)?;
        value.put(
            "environment",
            self.environment
                .as_ref()
                .map(|s| Value::string(s))
                .transpose()?
                .unwrap_or(Value::Null),
        )?;
        if let Some(note) = &self.note {
            value.put("note", Value::string(note)?)?;
        }
        if let Some(r) = &self.rollback {
            let mut rollback = Value::Mapping(Vec::new());
            rollback.put(
                "stage",
                Value::string(match r.stage {
                    RollbackStage::Handlers => "handlers",
                    RollbackStage::Sync => "sync",
                    RollbackStage::Finish => "finish",
                })?,
            )?;
            rollback.put("from_state", Value::string(r.from_state.as_str())?)?;
            rollback.put(
                "remaining",
                Value::Sequence(
                    r.remaining
                        .iter()
                        .map(|s| Value::string(s.as_str()))
                        .collect::<std::result::Result<_, _>>()?,
                ),
            )?;
            value.put("rollback", rollback)?;
        }
        Ok(value)
    }
}
fn bool_value(value: bool) -> Result<Value> {
    Ok(Value::Scalar(Scalar::new(
        ScalarKind::Boolean,
        Plaintext::copy_from(if value { "True" } else { "False" })?,
    )))
}

pub(super) fn marker_key(selector: &Selector) -> String {
    format!("state{}", selector.expression())
}

pub(super) fn validate(data: &Value, selector: &Selector) -> Result<()> {
    validate_layout(data, selector, false)
}

fn validate_layout(data: &Value, selector: &Selector, encoded: bool) -> Result<()> {
    let Some(owned) = data.get("_broil") else {
        return Ok(());
    };
    fields(owned, &["version", "rotation"])?;
    let version = required(owned, "version")?
        .scalar()
        .ok_or(ErrorKind::OwnedSchema)?;
    let visible_version = version.kind() == ScalarKind::Integer && version.as_str() == "1";
    let encrypted_version = encoded
        && version.kind() == ScalarKind::String
        && version.as_str().starts_with("ENC[AES256_GCM,")
        && version.as_str().ends_with(",type:int]");
    if !visible_version && !encrypted_version {
        return Err(ErrorKind::OwnedSchema.into());
    }
    let marker_key = marker_key(selector);
    for (key, record) in pairs(required(owned, "rotation")?)? {
        validate_user_key(key)?;
        if data.get(key).is_none() {
            return Err(ErrorKind::OwnedSchema.into());
        }
        fields(record, &["pending", "previous", &marker_key])?;
        for name in ["pending", "previous"] {
            if let Some(slot) = record.get(name) {
                if encoded {
                    let slot = slot.scalar().ok_or(ErrorKind::OwnedSchema)?;
                    if slot.as_str().is_empty() || slot.as_str().len() > sops::MAX_DOCUMENT_BYTES {
                        return Err(ErrorKind::OwnedSchema.into());
                    }
                } else {
                    valid_slot(slot)?;
                }
            }
        }
        if let Some(marker) = record.get(&marker_key) {
            Marker::parse(marker)?;
        }
        if record.get("pending").is_some() && record.get(&marker_key).is_none() {
            return Err(ErrorKind::OwnedSchema.into());
        }
    }
    Ok(())
}
fn valid_slot(value: &Value) -> Result<()> {
    let value = value.scalar().ok_or(ErrorKind::OwnedSchema)?.as_str();
    if value.is_empty() || value.contains('\0') || value.len() > sops::MAX_SCALAR_BYTES {
        return Err(ErrorKind::OwnedSchema.into());
    }
    Ok(())
}

pub(super) fn entries(data: &Value) -> Result<impl Iterator<Item = (&str, &Value)>> {
    let rotation = data.get("_broil").and_then(|v| v.get("rotation"));
    Ok(rotation.map(pairs).transpose()?.into_iter().flatten())
}

pub(super) fn active(data: &Value, selector: &Selector, key: &str) -> bool {
    data.get("_broil")
        .and_then(|v| v.get("rotation"))
        .and_then(|v| v.get(key))
        .and_then(|v| v.get(&marker_key(selector)))
        .is_some()
}

pub(super) fn generic_candidate(original: &Document, candidate: &Value) -> Result<()> {
    validate(original.data(), original.selector())?;
    validate(candidate, original.selector())?;
    match (original.data().get("_broil"), candidate.get("_broil")) {
        (None, None) => {}
        (Some(a), Some(b)) if a.same(b) => {}
        _ => return Err(ErrorKind::OwnedMutation.into()),
    }
    if !attachment_same(original.data(), candidate, "_broil") {
        return Err(ErrorKind::OwnedMutation.into());
    }
    for (key, _) in entries(original.data())? {
        if active(original.data(), original.selector(), key)
            && (!original
                .data()
                .get(key)
                .zip(candidate.get(key))
                .is_some_and(|(a, b)| a.same(b))
                || !attachment_same(original.data(), candidate, key))
        {
            return Err(ErrorKind::ActiveRotation.into());
        }
    }
    Ok(())
}

fn attachment_same(a: &Value, b: &Value, key: &str) -> bool {
    fn context<'a>(value: &'a Value, key: &str) -> Vec<&'a sops::Comment> {
        let Some(entries) = value.entries() else {
            return Vec::new();
        };
        let Some(index) = entries
            .iter()
            .position(|e| matches!(e, Entry::Pair(k, _) if k == key))
        else {
            return Vec::new();
        };
        let start = entries[..index]
            .iter()
            .rposition(|e| matches!(e, Entry::Pair(_, _)))
            .map_or(0, |i| i + 1);
        let end = entries[index + 1..]
            .iter()
            .position(|e| matches!(e, Entry::Pair(_, _)))
            .map_or(entries.len(), |i| index + 1 + i);
        entries[start..end]
            .iter()
            .filter_map(|e| {
                if let Entry::Comment(c) = e {
                    Some(c)
                } else {
                    None
                }
            })
            .collect()
    }
    let a = context(a, key);
    let b = context(b, key);
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(a, b)| a.as_str() == b.as_str() && a.is_inline() == b.is_inline())
}

pub(super) fn capability(document: &Document, key: &str) -> Result<()> {
    validate_user_key(key)?;
    capability_paths(document, Some(key))
}

pub(super) fn document_capability(document: &Document) -> Result<()> {
    capability_paths(document, None)
}

fn capability_paths(document: &Document, key: Option<&str>) -> Result<()> {
    document.ensure_writable()?;
    validate(document.data(), document.selector())?;
    let selector = document.selector();
    if !matches!(selector.recorded_key(), None | Some("unencrypted_suffix"))
        || selector.expression().is_empty()
        || document.empty_recorded_suffix()
        || document.mac_only_encrypted().is_some()
        || !document.unsupported_metadata().is_empty()
    {
        let subject = if document.mac_only_encrypted().is_some() {
            "mac_only_encrypted"
        } else {
            selector.recorded_key().unwrap_or("unencrypted_suffix")
        };
        return Err(ErrorKind::RotationPolicy(subject.to_owned()).into());
    }
    let marker = marker_key(selector);
    if ["pending", "previous", "version", "rotation"].contains(&marker.as_str()) {
        return Err(ErrorKind::RotationPolicy(marker).into());
    }
    for (leaf, expected) in [
        ("pending", true),
        ("previous", true),
        (marker.as_str(), false),
    ] {
        let path: Vec<_> = [Some("_broil"), Some("rotation"), key, Some(leaf)]
            .into_iter()
            .flatten()
            .map(str::to_owned)
            .collect();
        if selector.store_path_encrypted(&path) != expected {
            return Err(
                ErrorKind::RotationPolicy(format!("_broil.rotation.{key:?}.{leaf}")).into(),
            );
        }
    }
    Ok(())
}

pub(super) fn status(input: &Plaintext) -> Result<UnauthenticatedStatus> {
    let (data, selector) = sops::inspect(input)?;
    validate_layout(&data, &selector, true)?;
    let marker_key = marker_key(&selector);
    let mut markers = Vec::new();
    for (key, value) in entries(&data)? {
        if let Some(marker) = value.get(&marker_key) {
            markers.push((key.to_owned(), Marker::parse(marker)?));
        }
    }
    markers.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(UnauthenticatedStatus { markers })
}

pub(crate) struct RotationUpdate {
    pub current: Option<Value>,
    pub pending: Option<Value>,
    pub previous: Option<Value>,
    pub marker: Option<Marker>,
}

pub(super) fn projection(document: &Document, key: &str) -> Result<RotationUpdate> {
    capability(document, key)?;
    let current = document.data().get(key).ok_or(ErrorKind::Missing)?;
    valid_slot(current)?;
    let record = document
        .data()
        .get("_broil")
        .and_then(|v| v.get("rotation"))
        .and_then(|v| v.get(key));
    let slot = |name| {
        record
            .and_then(|r| r.get(name))
            .map(Value::duplicate)
            .transpose()
            .map_err(super::Error::from)
    };
    Ok(RotationUpdate {
        current: Some(current.duplicate()?),
        pending: slot("pending")?,
        previous: slot("previous")?,
        marker: record
            .and_then(|r| r.get(&marker_key(document.selector())))
            .map(Marker::parse)
            .transpose()?,
    })
}

pub(super) fn updated(document: &Document, key: &str, update: RotationUpdate) -> Result<Value> {
    capability(document, key)?;
    let mut data = document.data().duplicate()?;
    if let Some(current) = update.current {
        valid_slot(&current)?;
        data.put(key, current)?;
    }
    let mut owned = if data.get("_broil").is_some() {
        data.take("_broil")?
    } else {
        let mut owned = Value::Mapping(Vec::new());
        owned.put(
            "version",
            Value::Scalar(Scalar::new(ScalarKind::Integer, Plaintext::copy_from("1")?)),
        )?;
        owned.put("rotation", Value::Mapping(Vec::new()))?;
        owned
    };
    let mut rotation = owned.take("rotation")?;
    if rotation.get(key).is_some() {
        rotation.take(key)?;
    }
    let mut entry = Value::Mapping(Vec::new());
    for (name, slot) in [("pending", update.pending), ("previous", update.previous)] {
        if let Some(slot) = slot {
            valid_slot(&slot)?;
            entry.put(name, slot)?;
        }
    }
    if let Some(marker) = update.marker {
        entry.put(&marker_key(document.selector()), marker.value()?)?;
    }
    if pairs(&entry)?.next().is_some() {
        rotation.put(key, entry)?;
    }
    if pairs(&rotation)?.next().is_some() {
        owned.put("rotation", rotation)?;
        data.put("_broil", owned)?;
    }
    validate(&data, document.selector())?;
    Ok(data)
}
