// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Error, MAX_DOCUMENT_BYTES, MAX_ITEMS, MAX_SCALAR_BYTES};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub struct Plaintext(pub(super) Zeroizing<Vec<u8>>);

impl Plaintext {
    pub(crate) fn from_bytes(mut bytes: Zeroizing<Vec<u8>>) -> Result<Self, Error> {
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::SizeLimit);
        }
        std::str::from_utf8(&bytes).map_err(|_| Error::InvalidType)?;
        Self::from_zeroizing(Zeroizing::new(
            String::from_utf8(std::mem::take(&mut *bytes)).expect("validated UTF-8"),
        ))
    }
    pub fn from_zeroizing(mut text: Zeroizing<String>) -> Result<Self, Error> {
        if text.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::SizeLimit);
        }

        Ok(Self(Zeroizing::new(
            std::mem::take(&mut *text).into_bytes(),
        )))
    }

    pub fn copy_from(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::SizeLimit);
        }
        let mut output = Zeroizing::new(String::new());
        output
            .try_reserve_exact(text.len())
            .map_err(|_| Error::Allocation)?;
        output.push_str(text);
        Self::from_zeroizing(output)
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("protected UTF-8 invariant")
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {

        self.0.as_mut_slice().zeroize();

    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Plaintext([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarKind {
    String,
    Integer,
    Float,
    Boolean,
}

pub struct Scalar {
    pub(super) kind: ScalarKind,
    pub(super) text: Plaintext,
}

impl Scalar {
    pub fn kind(&self) -> ScalarKind {
        self.kind
    }
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }
    pub(crate) fn new(kind: ScalarKind, text: Plaintext) -> Self {
        Self { kind, text }
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar([REDACTED])")
    }
}

pub struct Comment {
    pub(super) text: Plaintext,
    pub(super) inline: bool,
}

impl Comment {
    pub fn as_str(&self) -> &str {
        self.text.as_str()
    }
    pub fn is_inline(&self) -> bool {
        self.inline
    }
}

impl fmt::Debug for Comment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Comment([REDACTED])")
    }
}

pub enum Entry {
    Pair(String, Value),
    Comment(Comment),
}

pub enum Value {
    Mapping(Vec<Entry>),
    Sequence(Vec<Value>),
    Scalar(Scalar),
    Null,
    Comment(Comment),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Value([REDACTED])")
    }
}
impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Entry([REDACTED])")
    }
}

impl Value {
    pub fn string(value: &str) -> Result<Self, Error> {
        if value.len() > MAX_SCALAR_BYTES {
            return Err(Error::SizeLimit);
        }
        Ok(Self::Scalar(Scalar::new(
            ScalarKind::String,
            Plaintext::copy_from(value)?,
        )))
    }
    pub fn get(&self, key: &str) -> Option<&Self> {
        self.entries()?.iter().find_map(|entry| match entry {
            Entry::Pair(name, value) if name == key => Some(value),
            _ => None,
        })
    }
    pub fn entries(&self) -> Option<&[Entry]> {
        match self {
            Self::Mapping(entries) => Some(entries),
            _ => None,
        }
    }
    pub fn sequence(&self) -> Option<&[Self]> {
        match self {
            Self::Sequence(values) => Some(values),
            _ => None,
        }
    }
    pub fn scalar(&self) -> Option<&Scalar> {
        match self {
            Self::Scalar(scalar) => Some(scalar),
            _ => None,
        }
    }
    pub(super) fn string_value(&self) -> Result<&str, Error> {
        match self {
            Self::Scalar(scalar) if scalar.kind == ScalarKind::String => Ok(scalar.as_str()),
            _ => Err(Error::InvalidType),
        }
    }
    pub(crate) fn put(&mut self, key: &str, value: Self) -> Result<(), Error> {
        let Self::Mapping(entries) = self else {
            return Err(Error::InvalidType);
        };
        if let Some(Entry::Pair(_, old)) = entries
            .iter_mut()
            .find(|e| matches!(e, Entry::Pair(k, _) if k == key))
        {
            *old = value;
        } else {
            entries.push(Entry::Pair(key.to_owned(), value));
        }
        Ok(())
    }
    pub(crate) fn take(&mut self, key: &str) -> Result<Self, Error> {
        let Self::Mapping(entries) = self else {
            return Err(Error::InvalidType);
        };
        let position = entries
            .iter()
            .position(|e| matches!(e, Entry::Pair(k, _) if k == key))
            .ok_or(Error::InvalidMetadata)?;
        match entries.remove(position) {
            Entry::Pair(_, value) => Ok(value),
            _ => unreachable!(),
        }
    }
    pub fn duplicate(&self) -> Result<Self, Error> {
        self.copy_bounded(&mut Budget::default(), 0)
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Scalar(a), Self::Scalar(b)) => a.kind == b.kind && a.as_str() == b.as_str(),
            (Self::Comment(a), Self::Comment(b)) => a.same(b),
            (Self::Sequence(a), Self::Sequence(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.same(b))
            }
            (Self::Mapping(a), Self::Mapping(b)) => {
                a.len() == b.len()
                    && a.iter().zip(b).all(|(a, b)| match (a, b) {
                        (Entry::Pair(ak, av), Entry::Pair(bk, bv)) => ak == bk && av.same(bv),
                        (Entry::Comment(a), Entry::Comment(b)) => a.same(b),
                        _ => false,
                    })
            }
            _ => false,
        }
    }
    pub(super) fn copy_bounded(&self, budget: &mut Budget, depth: usize) -> Result<Self, Error> {
        budget.item(depth)?;
        Ok(match self {
            Self::Mapping(entries) => Self::Mapping(
                entries
                    .iter()
                    .map(|entry| {
                        Ok(match entry {
                            Entry::Pair(key, value) => {
                                budget.bytes(key.len())?;
                                Entry::Pair(key.clone(), value.copy_bounded(budget, depth + 1)?)
                            }
                            Entry::Comment(comment) => {
                                budget.item(depth + 1)?;
                                budget.bytes(comment.as_str().len())?;
                                Entry::Comment(Comment {
                                    text: Plaintext::copy_from(comment.as_str())?,
                                    inline: comment.inline,
                                })
                            }
                        })
                    })
                    .collect::<Result<_, Error>>()?,
            ),
            Self::Sequence(values) => Self::Sequence(
                values
                    .iter()
                    .map(|value| value.copy_bounded(budget, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            Self::Scalar(scalar) => {
                budget.bytes(scalar.as_str().len())?;
                Self::Scalar(Scalar::new(
                    scalar.kind,
                    Plaintext::copy_from(scalar.as_str())?,
                ))
            }
            Self::Comment(comment) => {
                budget.bytes(comment.as_str().len())?;
                Self::Comment(Comment {
                    text: Plaintext::copy_from(comment.as_str())?,
                    inline: comment.inline,
                })
            }
            Self::Null => Self::Null,
        })
    }
}

impl Comment {
    fn same(&self, other: &Self) -> bool {
        self.inline == other.inline && self.as_str() == other.as_str()
    }
}

#[derive(Default)]
pub(super) struct Budget {
    bytes: usize,
    items: usize,
}
impl Budget {
    pub(super) fn item(&mut self, depth: usize) -> Result<(), Error> {
        self.items += 1;
        if depth > 128 || self.items > MAX_ITEMS {
            Err(Error::SizeLimit)
        } else {
            Ok(())
        }
    }
    pub(super) fn bytes(&mut self, bytes: usize) -> Result<(), Error> {
        self.bytes = self.bytes.checked_add(bytes).ok_or(Error::SizeLimit)?;
        if self.bytes > MAX_DOCUMENT_BYTES {
            Err(Error::SizeLimit)
        } else {
            Ok(())
        }
    }
}

pub(super) struct Bytes(pub(super) Zeroizing<Vec<u8>>);
impl Bytes {
    pub(super) fn allocate(length: usize) -> Result<Self, Error> {
        if length > MAX_DOCUMENT_BYTES {
            return Err(Error::SizeLimit);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::Allocation)?;
        bytes.resize(length, 0);

        Ok(Self(bytes))
    }
    pub(super) fn copy_from(input: &[u8]) -> Result<Self, Error> {
        let mut bytes = Self::allocate(input.len())?;
        bytes.0.copy_from_slice(input);
        Ok(bytes)
    }
    pub(super) fn into_text(mut self) -> Result<Plaintext, Error> {
        std::str::from_utf8(&self.0).map_err(|_| Error::InvalidType)?;

        Plaintext::from_zeroizing(Zeroizing::new(
            String::from_utf8(std::mem::take(&mut *self.0)).expect("validated UTF-8"),
        ))
    }
}
impl Drop for Bytes {
    fn drop(&mut self) {

        self.0.as_mut_slice().zeroize();

    }
}
