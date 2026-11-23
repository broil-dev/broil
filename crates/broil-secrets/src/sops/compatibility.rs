// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Comment, Entry, Error, MAC_ONLY_SEED, MAX_SCALAR_BYTES, Metadata, Plaintext, Scalar, Selector,
    Value, aad, cipher, decoded_scalar, go_regex::Profile, tree,
};
use sha2::{Digest, Sha512};

pub(super) fn local_failure(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidEnvelope | Error::InvalidType | Error::Authentication | Error::MacMismatch
    )
}

pub(super) fn authenticate(
    encoded: &Value,
    metadata: &Metadata,
    key: &[u8; 32],
    profile: Profile,
    expected: Option<&Value>,
) -> Result<(Option<Value>, bool), Error> {
    let mut reader = Reader {
        metadata,
        key,
        profile,
        retain: expected.is_none(),
        equal: true,
        hash: Sha512::new(),
        budget: tree::Budget::default(),
    };
    if metadata.mac_only == Some(true) {
        reader.hash.update(MAC_ONLY_SEED);
    }
    let data = reader.value(encoded, expected, &mut Vec::new(), &mut Vec::new(), 0)?;
    let digest = super::finish_digest(reader.hash)?;
    let mac = metadata
        .raw
        .get("mac")
        .ok_or(Error::InvalidMetadata)?
        .string_value()?;
    let (expected_mac, kind) = cipher::decrypt(mac, key, &metadata.timestamp_aad)?;
    if kind != "str" || expected_mac.as_bytes().len() != digest.as_bytes().len() {
        return Err(Error::MacMismatch);
    }
    let difference = expected_mac
        .as_bytes()
        .iter()
        .zip(digest.as_bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b));
    if difference != 0 {
        return Err(Error::MacMismatch);
    }
    Ok((data, reader.equal))
}

struct Reader<'a> {
    metadata: &'a Metadata,
    key: &'a [u8; 32],
    profile: Profile,
    retain: bool,
    equal: bool,
    hash: Sha512,
    budget: tree::Budget,
}
impl Reader<'_> {
    fn value(
        &mut self,
        encoded: &Value,
        expected: Option<&Value>,
        path: &mut Vec<String>,
        context: &mut Vec<bool>,
        depth: usize,
    ) -> Result<Option<Value>, Error> {
        self.budget.item(depth)?;
        Ok(match encoded {
            Value::Mapping(entries) => {
                let other = expected.and_then(Value::entries);
                if !self.retain && other.is_none_or(|other| other.len() != entries.len()) {
                    self.equal = false;
                }
                let mut output = Vec::new();
                if self.retain {
                    output
                        .try_reserve_exact(entries.len())
                        .map_err(|_| Error::Allocation)?;
                }
                context.push(false);
                for (index, entry) in entries.iter().enumerate() {
                    let other = other.and_then(|items| items.get(index));
                    match entry {
                        Entry::Pair(name, value) => {
                            self.budget.bytes(name.len())?;
                            let expected = match other {
                                Some(Entry::Pair(key, value)) => {
                                    self.equal &= name == key;
                                    Some(value)
                                }
                                _ => {
                                    if !self.retain {
                                        self.equal = false;
                                    }
                                    None
                                }
                            };
                            path.push(name.clone());
                            if let Some(value) =
                                self.value(value, expected, path, context, depth + 1)?
                            {
                                output.push(Entry::Pair(name.clone(), value));
                            }
                            path.pop();
                            *context.last_mut().ok_or(Error::InvalidYaml)? = false;
                        }
                        Entry::Comment(comment) => {
                            self.budget.item(depth + 1)?;
                            let expected = match other {
                                Some(Entry::Comment(c)) => Some(c),
                                _ => None,
                            };
                            if let Some(comment) = self.comment(comment, expected, path, context)? {
                                output.push(Entry::Comment(comment));
                            }
                        }
                    }
                }
                context.pop();
                self.retain.then_some(Value::Mapping(output))
            }
            Value::Sequence(values) => {
                let other = expected.and_then(Value::sequence);
                if !self.retain && other.is_none_or(|other| other.len() != values.len()) {
                    self.equal = false;
                }
                let mut output = Vec::new();
                if self.retain {
                    output
                        .try_reserve_exact(values.len())
                        .map_err(|_| Error::Allocation)?;
                }
                context.push(false);
                for (index, value) in values.iter().enumerate() {
                    if let Some(result) = self.value(
                        value,
                        other.and_then(|items| items.get(index)),
                        path,
                        context,
                        depth + 1,
                    )? {
                        output.push(result);
                    }
                    if !matches!(value, Value::Comment(_)) {
                        *context.last_mut().ok_or(Error::InvalidYaml)? = false;
                    }
                }
                context.pop();
                self.retain.then_some(Value::Sequence(output))
            }
            Value::Null => {
                if !self.retain && !matches!(expected, Some(Value::Null)) {
                    self.equal = false;
                }
                self.retain.then_some(Value::Null)
            }
            Value::Comment(comment) => {
                let other = match expected {
                    Some(Value::Comment(c)) => Some(c),
                    _ => None,
                };
                self.comment(comment, other, path, context)?
                    .map(Value::Comment)
            }
            Value::Scalar(scalar) => {
                let selected = self
                    .metadata
                    .selector
                    .encrypted(path, context, self.profile);
                let decoded = if selected && !scalar.as_str().is_empty() {
                    let (text, kind) = cipher::decrypt(scalar.as_str(), self.key, &aad(path))?;
                    Some(decoded_scalar(text, kind)?)
                } else {
                    None
                };
                let plain = decoded.as_ref().unwrap_or(scalar);
                self.scalar_bytes(plain.as_str())?;
                if self.metadata.mac_only != Some(true) || selected {
                    self.hash.update(plain.text.as_bytes());
                }
                if !self.retain {
                    self.equal &= expected.and_then(Value::scalar).is_some_and(|other| {
                        other.kind == plain.kind && other.text.as_bytes() == plain.text.as_bytes()
                    });
                    None
                } else {
                    Some(Value::Scalar(match decoded {
                        Some(scalar) => scalar,
                        None => Scalar::new(scalar.kind, Plaintext::copy_from(scalar.as_str())?),
                    }))
                }
            }
        })
    }
    fn scalar_bytes(&mut self, text: &str) -> Result<(), Error> {
        if text.len() > MAX_SCALAR_BYTES {
            return Err(Error::SizeLimit);
        }
        self.budget.bytes(text.len())
    }
    fn comment(
        &mut self,
        comment: &Comment,
        expected: Option<&Comment>,
        path: &[String],
        context: &mut [bool],
    ) -> Result<Option<Comment>, Error> {
        *context.last_mut().ok_or(Error::InvalidYaml)? |= self
            .metadata
            .selector
            .comment_match(comment.as_str(), self.profile);
        let decoded = if comment.as_str().starts_with("ENC[") {
            let (text, kind) = cipher::decrypt(comment.as_str(), self.key, &aad(path))?;
            if kind != "comment" {
                return Err(Error::InvalidType);
            }
            Some(text)
        } else {
            None
        };
        let text = decoded.as_ref().unwrap_or(&comment.text);
        self.scalar_bytes(text.as_str())?;
        if !self.retain {
            self.equal &= expected.is_some_and(|other| {
                other.inline == comment.inline && other.text.as_bytes() == text.as_bytes()
            });
            Ok(None)
        } else {
            Ok(Some(Comment {
                inline: comment.inline,
                text: match decoded {
                    Some(text) => text,
                    None => Plaintext::copy_from(comment.as_str())?,
                },
            }))
        }
    }
}

pub(super) fn policy(
    data: &Value,
    left: &Selector,
    right: &Selector,
    refusal: Error,
) -> Result<(), Error> {
    if !left.supports(Profile::Legacy) || !right.supports(Profile::Current) {
        return Err(refusal);
    }
    let mut state = Policy {
        selectors: [left, right],
        budget: tree::Budget::default(),
        equal: true,
    };
    state.value(data, &mut Vec::new(), &mut [Vec::new(), Vec::new()], 0)?;
    if state.equal { Ok(()) } else { Err(refusal) }
}
struct Policy<'a> {
    selectors: [&'a Selector; 2],
    budget: tree::Budget,
    equal: bool,
}
impl Policy<'_> {
    fn decisions(&mut self, path: &[String], contexts: &[Vec<bool>; 2]) {
        self.equal &= self.selectors[0].encrypted(path, &contexts[0], Profile::Legacy)
            == self.selectors[1].encrypted(path, &contexts[1], Profile::Current);
    }
    fn comment(
        &mut self,
        comment: &Comment,
        path: &[String],
        contexts: &mut [Vec<bool>; 2],
    ) -> Result<(), Error> {
        self.budget.bytes(comment.as_str().len())?;
        let mut selected = [false; 2];
        let mut matches = [false; 2];
        for profile in Profile::ALL {
            let i = profile.index();
            let selector = self.selectors[i];
            selected[i] = selector.encrypted(path, &contexts[i], profile);
            matches[i] = selector.comment_match(comment.as_str(), profile);
            *contexts[i].last_mut().ok_or(Error::InvalidYaml)? |= matches[i];
            if !selector.skip_current_comment() {
                selected[i] = selector.encrypted(path, &contexts[i], profile);
            }
        }
        self.equal &= selected[0] == selected[1] && matches[0] == matches[1];
        Ok(())
    }
    fn value(
        &mut self,
        data: &Value,
        path: &mut Vec<String>,
        contexts: &mut [Vec<bool>; 2],
        depth: usize,
    ) -> Result<(), Error> {
        self.budget.item(depth)?;
        self.decisions(path, contexts);
        match data {
            Value::Mapping(entries) => {
                for context in contexts.iter_mut() {
                    context.push(false);
                }
                for entry in entries {
                    match entry {
                        Entry::Pair(name, value) => {
                            self.budget.bytes(name.len())?;
                            path.push(name.clone());
                            self.value(value, path, contexts, depth + 1)?;
                            path.pop();
                            for context in contexts.iter_mut() {
                                *context.last_mut().ok_or(Error::InvalidYaml)? = false;
                            }
                        }
                        Entry::Comment(comment) => {
                            self.budget.item(depth + 1)?;
                            self.comment(comment, path, contexts)?;
                        }
                    }
                }
                for context in contexts.iter_mut() {
                    context.pop();
                }
            }
            Value::Sequence(values) => {
                for context in contexts.iter_mut() {
                    context.push(false);
                }
                for value in values {
                    self.value(value, path, contexts, depth + 1)?;
                    if !matches!(value, Value::Comment(_)) {
                        for context in contexts.iter_mut() {
                            *context.last_mut().ok_or(Error::InvalidYaml)? = false;
                        }
                    }
                }
                for context in contexts.iter_mut() {
                    context.pop();
                }
            }
            Value::Comment(comment) => self.comment(comment, path, contexts)?,
            Value::Scalar(scalar) => self.budget.bytes(scalar.as_str().len())?,
            Value::Null => {}
        }
        Ok(())
    }
}
