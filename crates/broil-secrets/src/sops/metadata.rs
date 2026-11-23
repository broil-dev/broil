// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Error,
    age::{self, Identity, Recipient},
    rules::{self, CreationRule, Selector},
    tree::{Entry, Plaintext, Scalar, ScalarKind, Value},
};
use chrono::{DateTime, SecondsFormat, Utc};
use zeroize::Zeroizing;

pub(super) struct Metadata {
    pub raw: Value,
    pub selector: Selector,
    pub mac_only: Option<bool>,
    pub timestamp_aad: String,
    pub unsupported: Vec<String>,
}

impl Metadata {
    pub fn parse(raw: Value) -> Result<Self, Error> {
        let version = raw
            .get("version")
            .ok_or(Error::InvalidMetadata)?
            .string_value()?;
        semver::Version::parse(version).map_err(|_| Error::InvalidMetadata)?;
        let timestamp = raw
            .get("lastmodified")
            .ok_or(Error::InvalidMetadata)?
            .string_value()?;
        let time = DateTime::parse_from_rfc3339(timestamp).map_err(|_| Error::InvalidMetadata)?;
        if time.offset().local_minus_utc() != 0 {
            return Err(Error::InvalidMetadata);
        }
        let timestamp_aad = time.to_rfc3339_opts(SecondsFormat::Secs, true);
        raw.get("mac")
            .ok_or(Error::InvalidMetadata)?
            .string_value()?;
        let ages = raw
            .get("age")
            .and_then(Value::sequence)
            .ok_or(Error::InvalidMetadata)?;
        let mut recipients = 0;
        for age in ages {
            if matches!(age, Value::Comment(_)) {
                continue;
            }
            let recipient = age
                .get("recipient")
                .ok_or(Error::InvalidMetadata)?
                .string_value()?;
            recipient
                .parse::<Recipient>()
                .map_err(|_| Error::InvalidMetadata)?;
            age.get("enc")
                .ok_or(Error::InvalidMetadata)?
                .string_value()?;
            recipients += 1;
        }
        if recipients == 0 {
            return Err(Error::NoRecipients);
        }
        let selector = rules::selector_from(&raw)?;
        let mac_only = rules::mac_only_from(&raw)?;
        let mut unsupported = Vec::new();
        for entry in raw.entries().ok_or(Error::InvalidMetadata)? {
            if let Entry::Pair(key, value) = entry {
                if matches!(
                    key.as_str(),
                    "age" | "lastmodified" | "mac" | "version" | "mac_only_encrypted"
                ) || rules::SELECTORS.contains(&key.as_str())
                {
                    continue;
                }
                if matches!(
                    key.as_str(),
                    "kms" | "gcp_kms" | "azure_kv" | "hc_vault" | "pgp"
                ) && value.sequence().is_some_and(|values| {
                    values
                        .iter()
                        .all(|value| matches!(value, Value::Comment(_)))
                }) {
                    continue;
                }
                unsupported.push(key.clone());
            }
        }
        Ok(Self {
            raw,
            selector,
            mac_only,
            timestamp_aad,
            unsupported,
        })
    }
    pub fn writable(&self) -> Result<(), Error> {
        if self.unsupported.is_empty() {
            Ok(())
        } else {
            Err(Error::UnsupportedMetadata(self.unsupported.clone()))
        }
    }
    pub fn key(&self, identities: &[Identity]) -> Result<Zeroizing<[u8; 32]>, Error> {
        for entry in self
            .raw
            .get("age")
            .and_then(Value::sequence)
            .ok_or(Error::InvalidMetadata)?
        {
            if matches!(entry, Value::Comment(_)) {
                continue;
            }
            let wrap = entry
                .get("enc")
                .ok_or(Error::InvalidMetadata)?
                .string_value()?;
            if let Ok(plain) = age::decrypt(wrap.as_bytes(), identities, None) {
                if plain.as_bytes().len() != 32 {
                    return Err(Error::InvalidMetadata);
                }
                let mut key = Zeroizing::new([0; 32]);
                key.copy_from_slice(plain.as_bytes());
                return Ok(key);
            }
        }
        Err(Error::NoMatchingIdentity)
    }
    pub fn new(rule: &CreationRule, key: &[u8; 32]) -> Result<Self, Error> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut raw = Value::Mapping(vec![
            Entry::Pair("age".to_owned(), wraps(key, rule.recipients())?),
            Entry::Pair("lastmodified".to_owned(), Value::string(&now)?),
            Entry::Pair("mac".to_owned(), Value::string("")?),
            Entry::Pair("version".to_owned(), Value::string("3.13.1")?),
        ]);
        let selector = rule.selector();
        raw.put(
            selector.recorded_key().unwrap_or("unencrypted_suffix"),
            Value::string(selector.expression())?,
        )?;
        if rule.mac_only_encrypted() == Some(true) {
            raw.put(
                "mac_only_encrypted",
                Value::Scalar(Scalar::new(
                    ScalarKind::Boolean,
                    Plaintext::copy_from("True")?,
                )),
            )?;
        }
        if let Value::Mapping(entries) = &mut raw {
            entries.sort_by(|left, right| match (left, right) {
                (Entry::Pair(left, _), Entry::Pair(right, _)) => left.cmp(right),
                _ => std::cmp::Ordering::Equal,
            });
        }
        Self::parse(raw)
    }
}

pub(super) fn wraps(key: &[u8; 32], recipients: &[Recipient]) -> Result<Value, Error> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }
    let mut output = Vec::new();
    for recipient in recipients {
        let encrypted = age::encrypt(key, std::slice::from_ref(recipient))
            .and_then(|bytes| age::armor(&bytes))
            .map_err(|_| Error::Age)?;
        output.push(Value::Mapping(vec![
            Entry::Pair(
                "recipient".to_owned(),
                Value::string(&recipient.to_string())?,
            ),
            Entry::Pair(
                "enc".to_owned(),
                Value::string(std::str::from_utf8(&encrypted).map_err(|_| Error::Age)?)?,
            ),
        ]));
    }
    Ok(Value::Sequence(output))
}
