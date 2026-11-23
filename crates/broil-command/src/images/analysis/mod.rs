// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod codec;
mod metadata;
mod response;

use super::{buffer::Bytes, common::*, json::Value, supervise::Output};
use broil_core::images::{reference::ImageReference, valid_platform};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

pub use metadata::Metadata;
pub use response::{
    Diagnostic, GraphOperation, HistoryAddition, HistoryCompletion, Instruction, Location, Outcome,
    Range, Role, Source, Status, TagOrigin, Use,
};
pub(crate) use response::{PrivateBinding, PrivateMaterial, same};

pub const FRONTEND: &str = "docker.io/docker/dockerfile@sha256:6ce6616ec35021075551c55e604374e8b47a66d157bc55ec2f2d2326450a9ae1";
pub(crate) const OBJECT: usize = 1 << 20;
pub(crate) const FRAME: usize = 16 << 20;

#[derive(Clone, Debug)]
pub struct Options {
    pub path: String,
    pub stage: String,
    pub args: BTreeMap<String, String>,
    pub build_platform: String,
    pub platform: String,
    pub contexts: BTreeSet<String>,
    pub frontend: String,
}

pub struct Snapshot {
    document: Bytes,
    options: Options,
    metadata: Vec<Metadata>,
}

impl Snapshot {
    pub fn new(document: &[u8], options: Options, mut metadata: Vec<Metadata>) -> Result<Self> {
        require(
            !document.is_empty() && document.len() <= OBJECT,
            Failure::Limit,
        )?;
        std::str::from_utf8(document).map_err(|_| Failure::Policy)?;
        require(
            !options.path.is_empty()
                && options.path.len() <= 4096
                && !options.path.contains('\0')
                && options.stage.len() <= OBJECT
                && !options.stage.contains('\0')
                && options.args.len() <= 256
                && options.contexts.len() <= 256
                && metadata.len() <= 1024,
            Failure::Policy,
        )?;
        require(
            valid_platform(&options.platform) && valid_platform(&options.build_platform),
            Failure::Policy,
        )?;
        let frontend = ImageReference::parse(&options.frontend).ok_or(Failure::Policy)?;
        require(
            frontend.digest.as_deref()
                == Some("sha256:6ce6616ec35021075551c55e604374e8b47a66d157bc55ec2f2d2326450a9ae1"),
            Failure::Policy,
        )?;
        let mut total = document
            .len()
            .checked_add(options.path.len())
            .ok_or(Failure::Limit)?;
        for text in options
            .args
            .iter()
            .flat_map(|(k, v)| [k, v])
            .chain(options.contexts.iter())
            .chain([&options.stage, &options.frontend])
        {
            total = total.checked_add(text.len()).ok_or(Failure::Limit)?;
            require(!text.contains('\0') && total <= FRAME, Failure::Limit)?;
        }
        for name in &options.contexts {
            require(
                !name.is_empty()
                    && name.len() <= 255
                    && name != "context"
                    && name != "scratch"
                    && name.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b)
                    }),
                Failure::Policy,
            )?;
        }
        metadata.sort_by(|a, b| (&a.reference, &a.platform).cmp(&(&b.reference, &b.platform)));
        require(
            !metadata
                .windows(2)
                .any(|v| v[0].reference == v[1].reference && v[0].platform == v[1].platform),
            Failure::Integrity,
        )?;
        for item in &metadata {
            total = total
                .checked_add(item.encoded_bytes())
                .ok_or(Failure::Limit)?;
            require(total <= FRAME, Failure::Limit)?;
        }
        Ok(Self {
            document: copy(document)?,
            options,
            metadata,
        })
    }
}

impl Snapshot {
    pub(crate) fn retained_bytes(&self) -> usize {
        let o = &self.options;
        self.document.get().len()
            + o.path.len()
            + o.stage.len()
            + o.build_platform.len()
            + o.platform.len()
            + o.frontend.len()
            + o.args.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
            + o.contexts.iter().map(String::len).sum::<usize>()
            + self
                .metadata
                .iter()
                .map(Metadata::encoded_bytes)
                .sum::<usize>()
    }
}

pub(crate) fn resolution_identity(snapshot: &Snapshot) -> Result<String> {
    codec::resolution(snapshot, &tool_identity()?)
}

pub(crate) fn copy(input: &[u8]) -> Result<Bytes> {
    let mut result = Bytes::new(input.len())?;
    result.get_mut().copy_from_slice(input);
    Ok(result)
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    let mut digest = Sha256::digest(bytes);
    let text = digest_string(digest.as_slice());
    digest.as_mut_slice().zeroize();
    text
}

fn digest_string(digest: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

pub(crate) fn normalize(text: &str) -> Result<String> {
    let value = ImageReference::parse(text).ok_or(Failure::Integrity)?;
    let mut result = value.repository.clone();
    if let Some(tag) = value.effective_tag() {
        result.push(':');
        result.push_str(tag);
    }
    if let Some(digest) = value.digest {
        result.push('@');
        result.push_str(&digest);
    }
    Ok(result)
}

pub(crate) fn tool_identity() -> Result<String> {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tools/image-client/public-tools.json"
    ))
    .map_err(|_| Failure::Policy)?;
    let record = &manifest["tools"]["analyzer"];
    require(
        record["protocol_version"] == 2
            && record["buildkit_source"] == "b772c318368090fb2ffc9c0fed92e0a35bf82389"
            && record["frontend"]
                == "sha256:6ce6616ec35021075551c55e604374e8b47a66d157bc55ec2f2d2326450a9ae1"
            && record["source_inputs"].is_object(),
        Failure::Policy,
    )?;
    super::Tool::Analyzer.identity()?;
    fn canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            serde_json::Value::Object(map) => {
                out.push(b'{');
                let sorted: BTreeMap<_, _> = map.iter().collect();
                for (i, (key, value)) in sorted.into_iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key).map_err(|_| Failure::Policy)?;
                    out.push(b':');
                    canonical(value, out)?;
                }
                out.push(b'}');
            }
            serde_json::Value::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    canonical(item, out)?;
                }
                out.push(b']');
            }
            _ => serde_json::to_writer(out, value).map_err(|_| Failure::Policy)?,
        }
        Ok(())
    }
    let mut bytes = Vec::new();
    canonical(record, &mut bytes)?;
    Ok(hash(&bytes))
}

fn history_identity() -> Result<String> {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tools/image-client/public-tools.json"
    ))
    .map_err(|_| Failure::Policy)?;
    let hash = manifest["tools"]["analyzer"]["source_inputs"]["tools/image-analyzer/history.go"]
        .as_str()
        .ok_or(Failure::Policy)?;
    require(hash.len() == 64 && hex(hash.as_bytes()), Failure::Policy)?;
    Ok(format!("sha256:{hash}"))
}

pub(crate) struct Attempt {
    snapshot: Snapshot,
    operation: String,
    number: u64,
    resolution: String,
    analyzer: String,
    limit: usize,
    end: u64,
}

impl Attempt {
    pub(crate) fn new(
        snapshot: Snapshot,
        operation: &str,
        number: u64,
        limit: usize,
        end: u64,
    ) -> Result<Self> {
        before(end)?;
        require(
            valid_operation(operation) && number > 0 && limit <= FRAME && limit > 8,
            Failure::Policy,
        )?;
        let analyzer = tool_identity()?;
        let resolution = codec::resolution(&snapshot, &analyzer)?;
        before(end)?;
        Ok(Self {
            snapshot,
            operation: operation.into(),
            number,
            resolution,
            analyzer,
            limit,
            end,
        })
    }
    pub(crate) fn encode(&self) -> Result<Bytes> {
        codec::encode(self)
    }
    pub(crate) fn decode(self, output: Output) -> Result<Outcome> {
        response::decode(self, output)
    }
    fn identity(&self, fields: &[Value<'_>]) -> Result<()> {
        require(
            fields[0].number()? == 2
                && fields[1].equals(&self.operation)?
                && fields[2].number()? == self.number
                && fields[3].equals(&self.resolution)?,
            Failure::Integrity,
        )
    }
}

