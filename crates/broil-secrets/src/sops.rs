// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod cipher;
mod comments;
mod compatibility;
mod go_regex;
mod metadata;
mod rules;
pub(crate) use rules::validate_admin_rule;
mod tree;
mod yaml;

use crate::age;
use go_regex::Profile;
use metadata::Metadata;
pub use rules::{CreationRule, Selector, recipients_for};
use sha2::{Digest, Sha512};
use std::fmt;
pub use tree::{Comment, Entry, Plaintext, Scalar, ScalarKind, Value};
use zeroize::Zeroizing;

pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SCALAR_BYTES: usize = 1024 * 1024;
const MAX_ITEMS: usize = 65536;
const MAC_ONLY_SEED: [u8; 32] = [
    0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0x0b,
    0x0b, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6, 0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69,
];

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidYaml,
    DuplicateKey,
    InvalidType,
    InvalidMetadata,
    InvalidSelector,
    InvalidRule,
    RegexImplementation,
    IncompatibleOriginal,
    IncompatibleCandidate,
    IncompatibleRule,
    AmbiguousAuthentication,
    InvalidPath,
    InvalidEnvelope,
    NoRecipients,
    NoMatchingRule,
    NoMatchingIdentity,
    Authentication,
    MacMismatch,
    SizeLimit,
    Allocation,
    Randomness,
    Age,
    UnsupportedMetadata(Vec<String>),
    UnsupportedRule(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMetadata(keys) => {
                write!(f, "unsupported SOPS metadata keys: {keys:?}")
            }
            Self::UnsupportedRule(key) => write!(f, "unsupported SOPS creation-rule key: {key:?}"),
            Self::IncompatibleOriginal | Self::IncompatibleCandidate | Self::IncompatibleRule => {
                write!(
                    f,
                    "SOPS compatibility refusal: {self:?}; manually migrate to a portable selector"
                )
            }
            _ => write!(f, "SOPS operation failed: {self:?}"),
        }
    }
}
impl std::error::Error for Error {}

pub struct Document {
    data: Value,
    metadata: Metadata,
    key: Zeroizing<[u8; 32]>,
    original: Plaintext,
    compatible_original: bool,
}
impl fmt::Debug for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Document([REDACTED])")
    }
}

impl Document {
    pub(crate) fn recipients(&self) -> Result<std::collections::BTreeSet<String>, Error> {
        self.metadata
            .raw
            .get("age")
            .and_then(Value::sequence)
            .ok_or(Error::InvalidMetadata)?
            .iter()
            .filter(|v| !matches!(v, Value::Comment(_)))
            .map(|v| {
                Ok(v.get("recipient")
                    .ok_or(Error::InvalidMetadata)?
                    .string_value()?
                    .parse::<age::Recipient>()
                    .map_err(|_| Error::InvalidMetadata)?
                    .to_string())
            })
            .collect()
    }
    pub fn data(&self) -> &Value {
        &self.data
    }
    pub fn selector(&self) -> &Selector {
        &self.metadata.selector
    }
    pub fn mac_only_encrypted(&self) -> Option<bool> {
        self.metadata.mac_only
    }
    pub(crate) fn empty_recorded_suffix(&self) -> bool {
        self.metadata
            .raw
            .get("unencrypted_suffix")
            .and_then(Value::scalar)
            .is_some_and(|value| value.as_str().is_empty())
    }
    pub fn unsupported_metadata(&self) -> &[String] {
        &self.metadata.unsupported
    }
    pub fn ensure_writable(&self) -> Result<(), Error> {
        self.metadata.writable()?;
        if self.compatible_original {
            Ok(())
        } else {
            Err(Error::IncompatibleOriginal)
        }
    }
    pub fn render_editor(&self) -> Result<Plaintext, Error> {
        yaml::render(&self.data)
    }
    pub fn rewrite_editor(&self, editor: &Plaintext) -> Result<Plaintext, Error> {
        self.ensure_writable()?;
        self.rewrite(yaml::parse(editor, false)?)
    }
    pub fn rewrite(&self, data: Value) -> Result<Plaintext, Error> {
        self.ensure_writable()?;
        if data.get("sops").is_some() || !matches!(data, Value::Mapping(_)) {
            return Err(Error::InvalidMetadata);
        }
        let metadata = Metadata::parse(self.metadata.raw.duplicate()?)?;
        encode(&data, metadata, &self.key)
    }
    pub fn rewrap(&self, rule: &CreationRule) -> Result<Plaintext, Error> {
        self.ensure_writable()?;
        rule.check(&self.data)?;
        let mut tree = yaml::parse(&self.original, true)?;
        let mut metadata = tree.take("sops")?;
        metadata.put("age", metadata::wraps(&self.key, rule.recipients())?)?;
        tree.put("sops", metadata)?;
        let encoded = yaml::render(&tree)?;
        drop(tree);
        verify_candidate(&encoded, &self.data, &self.key)?;
        Ok(encoded)
    }
}

pub fn decrypt(input: Plaintext, identities: &[age::Identity]) -> Result<Document, Error> {
    let mut encoded = yaml::parse(&input, true)?;
    let metadata = Metadata::parse(encoded.take("sops")?)?;
    let key = metadata.key(identities)?;
    let mut retained = None;
    let mut succeeded = 0;
    let mut last_failure = Error::Authentication;
    for profile in Profile::ALL {
        match compatibility::authenticate(&encoded, &metadata, &key, profile, retained.as_ref()) {
            Ok((result, equal)) => {
                if !equal {
                    return Err(Error::AmbiguousAuthentication);
                }
                if let Some(result) = result {
                    retained = Some(result);
                }
                succeeded += 1;
            }
            Err(error) if compatibility::local_failure(&error) => last_failure = error,
            Err(error) => return Err(error),
        }
    }
    let data = retained.ok_or(last_failure)?;
    let compatible_original = if succeeded == 2 {
        let mut compatible = true;
        for tree in [&encoded, &data] {
            match compatibility::policy(
                tree,
                &metadata.selector,
                &metadata.selector,
                Error::IncompatibleOriginal,
            ) {
                Ok(()) => {}
                Err(Error::IncompatibleOriginal) => compatible = false,
                Err(error) => return Err(error),
            }
        }
        compatible
    } else {
        false
    };
    Ok(Document {
        data,
        metadata,
        key,
        original: input,
        compatible_original,
    })
}

pub fn create(plaintext: &Plaintext, rule: &CreationRule) -> Result<Plaintext, Error> {
    let data = yaml::parse(plaintext, false)?;
    if data.get("sops").is_some() {
        return Err(Error::InvalidMetadata);
    }
    rule.check(&data)?;
    let key = cipher::random_key()?;
    let metadata = Metadata::new(rule, &key)?;
    encode(&data, metadata, &key)
}

pub(crate) fn parse_plaintext(input: &Plaintext) -> Result<Value, Error> {
    yaml::parse(input, false)
}

pub(crate) fn inspect(input: &Plaintext) -> Result<(Value, Selector), Error> {
    let mut tree = yaml::parse(input, true)?;
    let metadata = Metadata::parse(tree.take("sops")?)?;
    Ok((tree, metadata.selector))
}

pub(crate) fn plaintext_metadata(input: &Plaintext) -> Result<(Vec<String>, String), Error> {
    let mut tree = yaml::parse(input, true)?;
    let metadata = Metadata::parse(tree.take("sops")?)?;
    let mut keys: Vec<String> = tree
        .entries()
        .into_iter()
        .flatten()
        .filter_map(|entry| match entry {
            Entry::Pair(key, _) if key != "_broil" => Some(key.clone()),
            _ => None,
        })
        .collect();
    keys.sort();
    Ok((keys, metadata.timestamp_aad))
}

pub(crate) fn render(data: &Value) -> Result<Plaintext, Error> {
    yaml::render(data)
}

fn encode(data: &Value, mut metadata: Metadata, key: &[u8; 32]) -> Result<Plaintext, Error> {
    metadata.writable()?;
    compatibility::policy(
        data,
        &metadata.selector,
        &metadata.selector,
        Error::IncompatibleCandidate,
    )?;
    let mut encrypted = data.duplicate()?;
    let digest = walk(&mut encrypted, &metadata, key, true)?;
    metadata.timestamp_aad = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mac = cipher::encrypt(digest.as_str(), "str", key, &metadata.timestamp_aad)?;
    metadata
        .raw
        .put("lastmodified", Value::string(&metadata.timestamp_aad)?)?;
    metadata
        .raw
        .put("mac", Value::Scalar(Scalar::new(ScalarKind::String, mac)))?;
    encrypted.put("sops", metadata.raw)?;
    let output = yaml::render(&encrypted)?;
    drop(encrypted);
    verify_candidate(&output, data, key)?;
    Ok(output)
}

fn verify_candidate(output: &Plaintext, intended: &Value, key: &[u8; 32]) -> Result<(), Error> {
    let mut tree = yaml::parse(output, true)?;
    let metadata = Metadata::parse(tree.take("sops")?)?;
    metadata.writable()?;
    compatibility::policy(
        &tree,
        &metadata.selector,
        &metadata.selector,
        Error::IncompatibleCandidate,
    )?;
    for profile in Profile::ALL {
        match compatibility::authenticate(&tree, &metadata, key, profile, Some(intended)) {
            Ok((None, true)) => {}
            Ok(_) => return Err(Error::IncompatibleCandidate),
            Err(error) if compatibility::local_failure(&error) => {
                return Err(Error::IncompatibleCandidate);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn walk(
    data: &mut Value,
    metadata: &Metadata,
    key: &[u8; 32],
    encrypt: bool,
) -> Result<Plaintext, Error> {
    let mut state = Walk {
        metadata,
        key,
        encrypt,
        hash: Sha512::new(),
        budget: tree::Budget::default(),
    };
    if metadata.mac_only == Some(true) {
        state.hash.update(MAC_ONLY_SEED);
    }
    state.value(data, &mut Vec::new(), &mut Vec::new(), 0)?;
    finish_digest(state.hash)
}

fn finish_digest(hash: Sha512) -> Result<Plaintext, Error> {
    let mut digest = Zeroizing::new([0u8; 64]);
    hash.finalize_into((&mut *digest).into());
    let mut encoded = tree::Bytes::allocate(128)?;
    for (i, byte) in digest.iter().enumerate() {
        encoded.0[i * 2] = b"0123456789ABCDEF"[(byte >> 4) as usize];
        encoded.0[i * 2 + 1] = b"0123456789ABCDEF"[(byte & 15) as usize];
    }
    encoded.into_text()
}

struct Walk<'a> {
    metadata: &'a Metadata,
    key: &'a [u8; 32],
    encrypt: bool,
    hash: Sha512,
    budget: tree::Budget,
}
impl Walk<'_> {
    fn value(
        &mut self,
        value: &mut Value,
        path: &mut Vec<String>,
        context: &mut Vec<bool>,
        depth: usize,
    ) -> Result<(), Error> {
        self.budget.item(depth)?;
        match value {
            Value::Mapping(entries) => {
                context.push(false);
                for entry in entries {
                    match entry {
                        Entry::Comment(comment) => {
                            self.budget.item(depth + 1)?;
                            self.comment(comment, path, context)?;
                        }
                        Entry::Pair(key, value) => {
                            self.budget.bytes(key.len())?;
                            if key.len() > MAX_SCALAR_BYTES {
                                return Err(Error::SizeLimit);
                            }
                            path.push(key.clone());
                            self.value(value, path, context, depth + 1)?;
                            path.pop();
                            *context.last_mut().expect("container context") = false;
                        }
                    }
                }
                context.pop();
            }
            Value::Sequence(values) => {
                context.push(false);
                for value in values {
                    self.value(value, path, context, depth + 1)?;
                    if !matches!(value, Value::Comment(_)) {
                        *context.last_mut().expect("container context") = false;
                    }
                }
                context.pop();
            }
            Value::Comment(comment) => self.comment(comment, path, context)?,
            Value::Null => {}
            Value::Scalar(scalar) => {
                let selected = self
                    .metadata
                    .selector
                    .encrypted(path, context, Profile::Current);
                if !self.encrypt && selected && !scalar.as_str().is_empty() {
                    let (text, kind) = cipher::decrypt(scalar.as_str(), self.key, &aad(path))?;
                    *scalar = decoded_scalar(text, kind)?;
                }
                self.budget.bytes(scalar.as_str().len())?;
                if scalar.as_str().len() > MAX_SCALAR_BYTES {
                    return Err(Error::SizeLimit);
                }
                if self.metadata.mac_only != Some(true) || selected {
                    self.hash.update(scalar.text.as_bytes());
                }
                if self.encrypt && selected {
                    let kind = match scalar.kind {
                        ScalarKind::String => "str",
                        ScalarKind::Integer => "int",
                        ScalarKind::Float => "float",
                        ScalarKind::Boolean => "bool",
                    };
                    scalar.text = cipher::encrypt(scalar.as_str(), kind, self.key, &aad(path))?;
                    scalar.kind = ScalarKind::String;
                }
            }
        }
        Ok(())
    }
    fn comment(
        &mut self,
        comment: &mut Comment,
        path: &[String],
        context: &mut [bool],
    ) -> Result<(), Error> {
        let matches = self
            .metadata
            .selector
            .comment_match(comment.as_str(), Profile::Current);
        let mut selected = self
            .metadata
            .selector
            .encrypted(path, context, Profile::Current);
        *context.last_mut().ok_or(Error::InvalidYaml)? |= matches;
        if !self.metadata.selector.skip_current_comment() {
            selected = self
                .metadata
                .selector
                .encrypted(path, context, Profile::Current);
        }
        if self.encrypt && selected {
            self.budget.bytes(comment.as_str().len())?;
            comment.text = cipher::encrypt(comment.as_str(), "comment", self.key, &aad(path))?;
            if self
                .metadata
                .selector
                .reject_encrypted_comment_match(comment.as_str(), Profile::Current)
            {
                return Err(Error::InvalidSelector);
            }
        } else if !self.encrypt && comment.as_str().starts_with("ENC[") {
            let (text, kind) = cipher::decrypt(comment.as_str(), self.key, &aad(path))?;
            if kind != "comment" {
                return Err(Error::InvalidType);
            }
            comment.text = text;
            self.budget.bytes(comment.as_str().len())?;
        }
        Ok(())
    }
}

fn aad(path: &[String]) -> String {
    let mut aad = path.join(":");
    aad.push(':');
    aad
}

fn decoded_scalar(text: Plaintext, kind: &str) -> Result<Scalar, Error> {
    use std::fmt::Write as _;
    let scalar_kind = match kind {
        "str" => ScalarKind::String,
        "int" => ScalarKind::Integer,
        "float" => ScalarKind::Float,
        "bool" => ScalarKind::Boolean,
        _ => return Err(Error::InvalidType),
    };
    if scalar_kind == ScalarKind::String {
        return Ok(Scalar::new(scalar_kind, text));
    }
    let mut canonical = Zeroizing::new(String::with_capacity(384));
    match scalar_kind {
        ScalarKind::Integer => {
            let number = Zeroizing::new(
                text.as_str()
                    .parse::<i64>()
                    .map_err(|_| Error::InvalidType)?,
            );
            write!(&mut *canonical, "{}", *number).expect("bounded integer");
        }
        ScalarKind::Float => {
            let number = Zeroizing::new(match text.as_str() {
                "+Inf" => f64::INFINITY,
                "-Inf" => f64::NEG_INFINITY,
                "NaN" => f64::NAN,
                value => value.parse::<f64>().map_err(|_| Error::InvalidType)?,
            });
            if number.is_nan() {
                canonical.push_str("NaN");
            } else if *number == f64::INFINITY {
                canonical.push_str("+Inf");
            } else if *number == f64::NEG_INFINITY {
                canonical.push_str("-Inf");
            } else {
                write!(&mut *canonical, "{}", *number).expect("bounded float");
            }
        }
        ScalarKind::Boolean => canonical.push_str(match text.as_str() {
            "1" | "t" | "T" | "TRUE" | "true" | "True" => "True",
            "0" | "f" | "F" | "FALSE" | "false" | "False" => "False",
            _ => return Err(Error::InvalidType),
        }),
        ScalarKind::String => unreachable!(),
    }
    Ok(Scalar::new(
        scalar_kind,
        Plaintext::from_zeroizing(canonical)?,
    ))
}
