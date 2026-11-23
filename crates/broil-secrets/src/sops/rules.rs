// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Error,
    age::Recipient,
    go_regex::{self, Profile},
    tree::{Entry, Plaintext, Value},
    yaml,
};
use regex::Regex;

pub(super) const SELECTORS: [&str; 6] = [
    "unencrypted_suffix",
    "encrypted_suffix",
    "unencrypted_regex",
    "encrypted_regex",
    "encrypted_comment_regex",
    "unencrypted_comment_regex",
];

#[derive(Debug)]
pub struct Selector {
    key: Option<String>,
    value: String,
    effective: usize,
    regex: [Option<Regex>; 2],
}

impl Selector {
    pub fn new(key: Option<&str>, value: &str) -> Result<Self, Error> {
        let mut effective = match key {
            Some(key) => SELECTORS
                .iter()
                .position(|item| *item == key)
                .ok_or(Error::InvalidSelector)?,
            None => 0,
        };
        let value = if key.is_none() || value.is_empty() {
            effective = 0;
            "_unencrypted"
        } else {
            value
        };
        let mut regex = [None, None];
        if effective >= 2 {
            for profile in Profile::ALL {
                regex[profile.index()] = match go_regex::compile(value, profile) {
                    Ok(regex) => Some(regex),
                    Err(Error::InvalidSelector) => None,
                    Err(error) => return Err(error),
                };
            }
            if regex.iter().all(Option::is_none) {
                return Err(Error::InvalidSelector);
            }
        }
        Ok(Self {
            key: key.map(str::to_owned),
            value: value.to_owned(),
            effective,
            regex,
        })
    }
    pub fn recorded_key(&self) -> Option<&str> {
        self.key.as_deref()
    }
    pub fn expression(&self) -> &str {
        &self.value
    }
    pub(crate) fn store_path_encrypted(&self, path: &[String]) -> bool {
        self.encrypted(path, &[], Profile::Current)
    }
    pub(super) fn supports(&self, profile: Profile) -> bool {
        self.effective < 2 || self.regex[profile.index()].is_some()
    }
    pub(super) fn comment_match(&self, text: &str, profile: Profile) -> bool {
        self.effective >= 4
            && self.regex[profile.index()]
                .as_ref()
                .is_some_and(|regex| regex.is_match(text))
    }
    pub(super) fn encrypted(
        &self,
        path: &[String],
        comment_context: &[bool],
        profile: Profile,
    ) -> bool {
        let matched = match self.effective {
            0 | 1 => path.iter().any(|key| key.ends_with(&self.value)),
            2 | 3 => path.iter().any(|key| {
                self.regex[profile.index()]
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(key))
            }),
            _ => comment_context.iter().any(|matched| *matched),
        };
        if matches!(self.effective, 0 | 2 | 5) {
            !matched
        } else {
            matched
        }
    }
    pub(super) fn skip_current_comment(&self) -> bool {
        self.effective == 4
    }
    pub(super) fn reject_encrypted_comment_match(&self, text: &str, profile: Profile) -> bool {
        self.effective == 5 && self.comment_match(text, profile)
    }
}

pub struct CreationRule {
    recipients: Vec<Recipient>,
    selector: Selector,
    mac_only: Option<bool>,
    alternative: Option<(Selector, Option<bool>)>,
    final_path: String,
}
impl CreationRule {
    pub fn recipients(&self) -> &[Recipient] {
        &self.recipients
    }
    pub fn selector(&self) -> &Selector {
        &self.selector
    }
    pub fn mac_only_encrypted(&self) -> Option<bool> {
        self.mac_only
    }
    pub fn final_path(&self) -> &str {
        &self.final_path
    }
    pub(super) fn check(&self, data: &Value) -> Result<(), Error> {
        super::compatibility::policy(
            data,
            &self.selector,
            &self.selector,
            Error::IncompatibleRule,
        )?;
        if let Some((selector, mac)) = &self.alternative {
            if self.mac_only.unwrap_or(false) != mac.unwrap_or(false) {
                return Err(Error::IncompatibleRule);
            }
            super::compatibility::policy(data, selector, selector, Error::IncompatibleRule)?;
            super::compatibility::policy(data, &self.selector, selector, Error::IncompatibleRule)?;
        }
        Ok(())
    }
}

pub fn recipients_for(
    config: &Plaintext,
    final_relative_path: &str,
) -> Result<CreationRule, Error> {
    if final_relative_path.starts_with('/')
        || final_relative_path.contains(['\\', '\0'])
        || !final_relative_path.ends_with(".yaml")
        || final_relative_path
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(Error::InvalidPath);
    }
    let root = yaml::parse(config, false)?;
    let rules = root
        .get("creation_rules")
        .and_then(Value::sequence)
        .ok_or(Error::InvalidRule)?;
    let mut selected = [None, None];
    for rule in rules {
        if matches!(rule, Value::Comment(_)) {
            continue;
        }
        let pattern = rule
            .get("path_regex")
            .map(Value::string_value)
            .transpose()?
            .unwrap_or("");
        for profile in Profile::ALL {
            if selected[profile.index()].is_some() {
                continue;
            }
            let regex = go_regex::compile(pattern, profile).map_err(|error| {
                if error == Error::InvalidSelector {
                    Error::IncompatibleRule
                } else {
                    error
                }
            })?;
            if regex.is_match(final_relative_path) {
                selected[profile.index()] = Some(rule);
            }
        }
        if selected.iter().all(Option::is_some) {
            break;
        }
    }
    let [Some(first), Some(second)] = selected else {
        return Err(Error::NoMatchingRule);
    };
    let parse = |rule: &Value| -> Result<(Vec<Recipient>, Selector, Option<bool>), Error> {
        for entry in rule.entries().ok_or(Error::InvalidRule)? {
            if let Entry::Pair(key, _) = entry {
                if !SELECTORS.contains(&key.as_str())
                    && !matches!(key.as_str(), "path_regex" | "age" | "mac_only_encrypted")
                {
                    return Err(Error::UnsupportedRule(key.clone()));
                }
            }
        }
        let mut recipients = rule
            .get("age")
            .ok_or(Error::NoRecipients)?
            .string_value()?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.parse::<Recipient>().map_err(|_| Error::InvalidRule))
            .collect::<Result<Vec<_>, _>>()?;
        recipients.sort_by_key(ToString::to_string);
        recipients.dedup_by_key(|recipient| recipient.to_string());
        if recipients.is_empty() {
            return Err(Error::NoRecipients);
        }
        Ok((recipients, selector_from(rule)?, mac_only_from(rule)?))
    };
    let (recipients, selector, mac_only) = parse(first)?;
    let alternative = if std::ptr::eq(first, second) {
        None
    } else {
        let (other_recipients, other_selector, other_mac) = parse(second)?;
        if !recipients
            .iter()
            .map(ToString::to_string)
            .eq(other_recipients.iter().map(ToString::to_string))
        {
            return Err(Error::IncompatibleRule);
        }
        Some((other_selector, other_mac))
    };
    Ok(CreationRule {
        recipients,
        selector,
        mac_only,
        alternative,
        final_path: final_relative_path.to_owned(),
    })
}

pub(super) fn selector_from(tree: &Value) -> Result<Selector, Error> {
    let mut found = None;
    for key in SELECTORS {
        if let Some(value) = tree.get(key) {
            if found.is_some() {
                return Err(Error::InvalidSelector);
            }
            found = Some((key, value.string_value()?));
        }
    }
    match found {
        Some((key, value)) => Selector::new(Some(key), value),
        None => Selector::new(None, "_unencrypted"),
    }
}

pub(super) fn mac_only_from(tree: &Value) -> Result<Option<bool>, Error> {
    match tree.get("mac_only_encrypted") {
        None => Ok(None),
        Some(Value::Scalar(scalar)) if scalar.kind == super::ScalarKind::Boolean => {
            Ok(Some(scalar.as_str() == "True"))
        }
        _ => Err(Error::InvalidMetadata),
    }
}

pub(crate) fn validate_admin_rule(rule: &Value) -> Result<(), Error> {
    for entry in rule.entries().ok_or(Error::InvalidRule)? {
        if let Entry::Pair(key, _) = entry {
            if !SELECTORS.contains(&key.as_str())
                && !matches!(key.as_str(), "path_regex" | "age" | "mac_only_encrypted")
            {
                return Err(Error::UnsupportedRule(key.clone()));
            }
        }
    }
    let pattern = rule
        .get("path_regex")
        .map(Value::string_value)
        .transpose()?
        .unwrap_or("");
    let selector = selector_from(rule)?;
    for profile in Profile::ALL {
        go_regex::compile(pattern, profile).map_err(|e| {
            if e == Error::InvalidSelector {
                Error::IncompatibleRule
            } else {
                e
            }
        })?;
        if !selector.supports(profile) {
            return Err(Error::IncompatibleRule);
        }
    }
    mac_only_from(rule)?;
    let recipients = rule.get("age").ok_or(Error::NoRecipients)?.string_value()?;
    if recipients.trim().is_empty() {
        return Err(Error::NoRecipients);
    }
    for recipient in recipients.split(',') {
        recipient
            .trim()
            .parse::<Recipient>()
            .map_err(|_| Error::InvalidRule)?;
    }
    Ok(())
}
