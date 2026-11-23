// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{common::*, graph::Hasher};
use super::context::{ContextEntry, IgnoreEntry};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BindingIdentity {
    pub(crate) alias: String,
    pub(crate) context: String,
    pub(crate) reference: String,
    pub(crate) platform: String,
    pub(crate) source_root: String,
    pub(crate) role: &'static str,
    pub(crate) derived_root: String,
}

pub(crate) struct GeneratedIdentity<'a> {
    pub(crate) producer: &'a str,
    pub(crate) platform: &'a str,
    pub(crate) build_platform: &'a str,
    pub(crate) resolution_id: &'a str,
    pub(crate) dockerfile_digest: &'a str,
    pub(crate) bindings: &'a [BindingIdentity],
    pub(crate) contexts: &'a [String],
    pub(crate) args: &'a [(String, String)],
    pub(crate) stage: &'a str,
    pub(crate) context_id: &'a str,
}

pub(crate) fn context_id(entries: &[ContextEntry], record: &IgnoreEntry) -> Result<String> {
    let mut h = Hasher::new(b"broil.image.context.v1");
    h.count(entries.len())?;
    for entry in entries {
        h.text(&entry.directory)?;
        h.bytes(&entry.path)?;
        h.text(entry.kind)?;
        h.number(u64::from(entry.mode));
        h.number(entry.size);
        h.bytes(&entry.target)?;
        h.text(&entry.digest)?;
    }
    ignore(&mut h, record)?;
    Ok(h.finish())
}

fn ignore(h: &mut Hasher, record: &IgnoreEntry) -> Result<()> {
    match record {
        IgnoreEntry::Absent => h.text("absent"),
        IgnoreEntry::File { mode, size, digest } => {
            h.text("file")?;
            h.number(u64::from(*mode));
            h.number(*size);
            h.text(digest)
        }
    }
}

pub(crate) fn generated_inputs_id(identity: &GeneratedIdentity<'_>) -> Result<String> {
    let mut h = Hasher::new(b"broil.image.generated.v1");
    h.text(identity.producer)?;
    h.text(identity.platform)?;
    h.text(identity.build_platform)?;
    h.text(identity.resolution_id)?;
    h.text(identity.dockerfile_digest)?;
    require(
        identity
            .bindings
            .windows(2)
            .all(|w| (&w[0].alias, &w[0].platform) < (&w[1].alias, &w[1].platform)),
        Failure::Integrity,
    )?;
    h.count(identity.bindings.len())?;
    for binding in identity.bindings {
        h.text(&binding.alias)?;
        h.text(&binding.context)?;
        h.text(&binding.reference)?;
        h.text(&binding.platform)?;
        h.text(&binding.source_root)?;
        h.text(binding.role)?;
        h.text(&binding.derived_root)?;
    }
    require(
        identity.contexts.windows(2).all(|w| w[0] < w[1])
            && identity.args.windows(2).all(|w| w[0].0 < w[1].0),
        Failure::Integrity,
    )?;
    h.count(identity.contexts.len())?;
    for name in identity.contexts {
        h.text(name)?;
    }
    h.count(identity.args.len())?;
    for (name, value) in identity.args {
        h.text(name)?;
        h.text(value)?;
    }
    h.text(identity.stage)?;
    h.text(identity.context_id)?;
    Ok(h.finish())
}
