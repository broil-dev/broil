// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{VerifiedOutput, content};
use super::*;

pub(crate) const INDEX: &str = "application/vnd.oci.image.index.v1+json";
pub(crate) const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const CONFIG: &str = "application/vnd.oci.image.config.v1+json";
pub(crate) const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
pub(crate) const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_CONFIG: &str = "application/vnd.docker.container.image.v1+json";

pub struct Metadata {
    pub(super) reference: String,
    pub(super) platform: String,
    pub(super) root: Descriptor,
    pub(super) config: Bytes,
    pub(super) manifest: Bytes,
    pub(super) indexes: Vec<Bytes>,
    pub(super) config_descriptor: Descriptor,
    pub(super) manifest_descriptor: Descriptor,
    pub(super) index_descriptors: Vec<Descriptor>,
}

impl Metadata {
    pub fn from_producer(
        output: &VerifiedOutput,
        reference: &str,
        platform: &str,
        config: &[u8],
        manifest: &[u8],
        indexes: &[&[u8]],
    ) -> Result<Self> {
        require(output.producer_image(), Failure::Policy)?;
        Self::checked(
            reference,
            platform,
            output.root(),
            config,
            manifest,
            indexes,
        )
    }
    pub fn from_verified(
        output: &VerifiedOutput,
        platform: &str,
        config: &[u8],
        manifest: &[u8],
        indexes: &[&[u8]],
    ) -> Result<Self> {
        let reference = output.original_reference().ok_or(Failure::Policy)?;
        Self::checked(
            reference,
            platform,
            output.root(),
            config,
            manifest,
            indexes,
        )
    }
    pub(crate) fn from_pinned(
        output: &VerifiedOutput,
        reference: &str,
        platform: &str,
        pinned: &Descriptor,
        config: &[u8],
        manifest: &[u8],
        indexes: &[&[u8]],
    ) -> Result<Self> {
        require(
            !output.producer_image()
                && output.original_reference().is_some()
                && output.root() == pinned,
            Failure::Policy,
        )?;
        Self::checked(
            reference,
            platform,
            output.root(),
            config,
            manifest,
            indexes,
        )
    }
    pub(super) fn checked(
        reference: &str,
        platform: &str,
        root: &Descriptor,
        config: &[u8],
        manifest: &[u8],
        indexes: &[&[u8]],
    ) -> Result<Self> {
        require(
            valid_platform(platform) && indexes.len() <= 32,
            Failure::Policy,
        )?;
        root.validate()?;
        let reference = normalize(reference)?;
        let named = ImageReference::parse(&reference).ok_or(Failure::Integrity)?;
        require(
            named.digest.as_ref().is_none_or(|d| *d == root.digest),
            Failure::Integrity,
        )?;
        let mut size = 0usize;
        for input in [config, manifest]
            .into_iter()
            .chain(indexes.iter().copied())
        {
            size = size.checked_add(input.len()).ok_or(Failure::Limit)?;
            require(
                !input.is_empty() && input.len() <= OBJECT && size <= FRAME,
                Failure::Limit,
            )?;
        }
        let config_value = parse(config)?;
        let manifest_value = parse(manifest)?;
        let manifest_descriptor = object_descriptor(manifest, false)?;
        let config_descriptor = content::descriptor(manifest_value.field("config")?, false)?;
        let expected_config = if manifest_descriptor.media_type == MANIFEST {
            CONFIG
        } else {
            DOCKER_CONFIG
        };
        require(
            config_descriptor.media_type == expected_config,
            Failure::Integrity,
        )?;
        check_bytes(config, &config_descriptor)?;
        check_platform(config_value, platform)?;
        check_layers(
            config_value,
            manifest_value,
            &manifest_descriptor.media_type,
        )?;
        let mut next = manifest_descriptor.clone();
        let mut reverse = Vec::new();
        for &input in indexes.iter().rev() {
            let value = parse(input)?;
            let index = object_descriptor(input, true)?;
            let entries = value.field("manifests")?.array()?;
            require(!entries.is_empty(), Failure::Integrity)?;
            let mut matching = 0;
            let mut selected = 0;
            for entry in entries {
                let d = content::descriptor(entry, false)?;
                require(
                    content::root_media(&d.media_type) && d.size > 0 && d.size <= OBJECT as u64,
                    Failure::Integrity,
                )?;
                let p = entry.optional("platform")?;
                require(
                    index.media_type != DOCKER_INDEX || p.is_some(),
                    Failure::Integrity,
                )?;
                let matches = match p {
                    Some(p) => check_platform(p, platform).is_ok(),
                    None => true,
                };
                if matches {
                    matching += 1;
                }
                if d.digest == next.digest {
                    require(d == next && matches, Failure::Integrity)?;
                    selected += 1;
                }
            }
            require(selected == 1 && matching == 1, Failure::Integrity)?;
            reverse.push(index.clone());
            next = index;
        }
        require(*root == next, Failure::Integrity)?;
        reverse.reverse();
        Ok(Self {
            reference,
            platform: platform.into(),
            root: root.clone(),
            config: copy(config)?,
            manifest: copy(manifest)?,
            indexes: indexes.iter().map(|b| copy(b)).collect::<Result<_>>()?,
            config_descriptor,
            manifest_descriptor,
            index_descriptors: reverse,
        })
    }
    pub(super) fn encoded_bytes(&self) -> usize {
        self.config.get().len()
            + self.manifest.get().len()
            + self.indexes.iter().map(|b| b.get().len()).sum::<usize>()
    }
    pub(super) fn triggers(&self) -> Result<Vec<Value<'_>>> {
        let image = parse(self.config.get())?;
        match image.optional("config")? {
            Some(config) if !config.is_null() => match config.optional("OnBuild")? {
                Some(triggers) if !triggers.is_null() => triggers.array(),
                _ => Ok(Vec::new()),
            },
            _ => Ok(Vec::new()),
        }
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value<'_>> {
    Value::parse_bounded(bytes, OBJECT, 128)
}
pub(super) fn check_bytes(bytes: &[u8], d: &Descriptor) -> Result<()> {
    require(
        bytes.len() as u64 == d.size && bytes.len() <= OBJECT && hash(bytes) == d.digest,
        Failure::Integrity,
    )
}
pub(super) fn object_descriptor(bytes: &[u8], index: bool) -> Result<Descriptor> {
    let value = parse(bytes)?;
    require(
        value.field("schemaVersion")?.number()? == 2,
        Failure::Integrity,
    )?;
    let options = if index {
        [INDEX, DOCKER_INDEX]
    } else {
        [MANIFEST, DOCKER_MANIFEST]
    };
    let mut media = None;
    for m in options {
        if value.field("mediaType")?.equals(m)? {
            media = Some(m);
        }
    }
    let media_type = media.ok_or(Failure::Integrity)?.to_owned();
    for (key, item) in value.members()? {
        match key.text()?.get() {
            b"schemaVersion" | b"mediaType" => {}
            b"manifests" if index => {
                item.array()?;
            }
            b"config" | b"layers" if !index => {}
            b"annotations" => {
                for (k, v) in item.members()? {
                    k.text()?;
                    v.text()?;
                }
            }
            _ => return Err(Failure::Integrity),
        }
    }
    Ok(Descriptor {
        digest: hash(bytes),
        size: bytes.len() as u64,
        media_type,
    })
}
pub(super) fn check_platform(value: Value<'_>, platform: &str) -> Result<()> {
    let parts: Vec<_> = platform.split('/').collect();
    require((2..=3).contains(&parts.len()), Failure::Integrity)?;
    let variant = value.optional("variant")?;
    require(
        value.field("os")?.equals(parts[0])?
            && value.field("architecture")?.equals(parts[1])?
            && match variant {
                Some(v) => v.equals(parts.get(2).copied().unwrap_or(""))?,
                None => parts.len() == 2,
            },
        Failure::Integrity,
    )
}
pub(super) fn check_layers(config: Value<'_>, manifest: Value<'_>, media: &str) -> Result<()> {
    let rootfs = config.field("rootfs")?;
    require(rootfs.field("type")?.equals("layers")?, Failure::Integrity)?;
    let ids = rootfs.field("diff_ids")?.array()?;
    let layers = manifest.field("layers")?.array()?;
    require(ids.len() == layers.len(), Failure::Integrity)?;
    for (id, layer) in ids.into_iter().zip(&layers) {
        content::digest_text(id)?;
        let d = content::descriptor(*layer, false)?;
        require(
            d.size <= 1_073_741_824
                && if media == DOCKER_MANIFEST {
                    d.media_type == "application/vnd.docker.image.rootfs.diff.tar.gzip"
                } else {
                    matches!(
                        d.media_type.as_str(),
                        "application/vnd.oci.image.layer.v1.tar"
                            | "application/vnd.oci.image.layer.v1.tar+gzip"
                            | "application/vnd.oci.image.layer.v1.tar+zstd"
                    )
                },
            Failure::Integrity,
        )?;
    }
    let mut nonempty = 0;
    if let Some(history) = config.optional("history")?.filter(|v| !v.is_null()) {
        for item in history.array()? {
            item.members()?;
            let empty = match item.optional("empty_layer")? {
                Some(v) if !v.is_null() => v.boolean()?,
                _ => false,
            };
            if !empty {
                nonempty += 1;
            }
        }
    }
    require(nonempty <= layers.len(), Failure::Integrity)?;
    if let Some(config) = config.optional("config")?.filter(|v| !v.is_null()) {
        config.members()?;
        if let Some(triggers) = config.optional("OnBuild")?.filter(|v| !v.is_null()) {
            let triggers = triggers.array()?;
            require(triggers.len() <= 256, Failure::Limit)?;
            for trigger in triggers {
                trigger.text()?;
            }
        }
    }
    Ok(())
}
