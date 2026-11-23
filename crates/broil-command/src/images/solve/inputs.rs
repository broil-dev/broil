// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    analysis::{self, Location, PrivateBinding, PrivateMaterial, Role},
    buffer::Bytes,
    common::*,
    content, files,
    graph::{self, Associations, Material, NodeKey},
    json::Value,
};
use super::context::Watch;
use super::identity::BindingIdentity;
use super::{FailedCheck, Refusal};
use broil_config::images::select::EffectiveImage;
use broil_core::secret::path_safety;
use rustix::fs::{AtFlags, Mode, OFlags};
use serde_json::{Map, Value as Public, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

pub(crate) const MAX_BINDINGS: usize = 1024;
pub(crate) const MAX_DOCKERFILE: usize = 2_097_152;
pub(crate) const MAX_BAKE: usize = 1_048_576;
pub(crate) const MAX_LAYOUTS: usize = 256;
pub(crate) const MAX_DERIVED_ENTRIES: u64 = 32_768;
pub(crate) const MAX_NAMED_DIRECTORIES: usize = 126;
const FIXED_INPUT_ENTRIES: u64 = 6;
const LAYOUT_ENTRIES: u64 = 7;
const OCI_LAYOUT: &[u8] = b"{\"imageLayoutVersion\": \"1.0.0\"}";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

fn refuse(failure: Failure, check: FailedCheck) -> Refusal {
    Refusal {
        failure,
        check: Some(check),
    }
}

fn hex(digest: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

fn reference_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"._-:/@[]+".contains(&byte)
}

fn comment_line(line: &[u8]) -> bool {
    String::from_utf8_lossy(line)
        .chars()
        .find(|c| !c.is_whitespace())
        == Some('#')
}

pub(crate) fn portable_operand_check(document: &[u8], binding: &PrivateBinding) -> Result<()> {
    let stem = binding
        .alias
        .strip_suffix(":latest")
        .unwrap_or(&binding.alias)
        .as_bytes();
    require(!stem.is_empty(), Failure::Integrity)?;
    let lines: Vec<&[u8]> = document.split(|b| *b == b'\n').collect();
    for u in &binding.uses {
        let Location::Dockerfile(ranges) = &u.location else {
            return Err(Failure::Policy);
        };
        let mut kept = Vec::new();
        for range in ranges {
            for number in range.start_line..=range.end_line {
                let line = lines
                    .get(
                        usize::try_from(number)
                            .map_err(|_| Failure::Limit)?
                            .checked_sub(1)
                            .ok_or(Failure::Integrity)?,
                    )
                    .ok_or(Failure::Integrity)?;
                if comment_line(line) {
                    continue;
                }
                kept.extend(line.iter().copied().filter(|b| reference_byte(*b)));
            }
        }
        let mut found = false;
        if kept.len() >= stem.len() {
            for offset in 0..=kept.len() - stem.len() {
                let window = &kept[offset..offset + stem.len()];
                if window.eq_ignore_ascii_case(stem) {
                    found = true;
                    require(window == stem, Failure::Policy)?;
                }
            }
        }
        require(found, Failure::Policy)?;
    }
    Ok(())
}

fn directive(line: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let space = |b: &u8| matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | b' ');
    let rest = line.strip_prefix(b"#")?;
    let mut i = rest.iter().take_while(|b| space(b)).count();
    let start = i;
    if !rest.get(i)?.is_ascii_alphabetic() {
        return None;
    }
    i += rest[i..]
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric())
        .count();
    let name = rest[start..i].to_ascii_lowercase();
    i += rest[i..].iter().take_while(|b| space(b)).count();
    if rest.get(i) != Some(&b'=') {
        return None;
    }
    let tail = &rest[i + 1..];
    let leading = tail.iter().take_while(|b| space(b)).count();
    let value = if leading == tail.len() {
        tail.get(tail.len().checked_sub(1)?..)?
    } else {
        let trailing = tail.iter().rev().take_while(|b| space(b)).count();
        &tail[leading..tail.len() - trailing]
    };
    Some((name, value))
}

pub(crate) fn frontend(dockerfile: &[u8]) -> Result<Option<String>> {
    let mut text = dockerfile
        .strip_prefix(b"\xef\xbb\xbf".as_slice())
        .unwrap_or(dockerfile);
    let first = text.split(|b| *b == b'\n').next().unwrap_or_default();
    if first.starts_with(b"#!") {
        text = text.get(first.len() + 1..).unwrap_or_default();
    }
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for line in text.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some((name, value)) = directive(line) else {
            break;
        };
        if !matches!(name.as_slice(), b"syntax" | b"escape" | b"check") || seen.contains(&name) {
            break;
        }
        if name == b"syntax" {
            let selected = value.split(|b| *b == b' ').next().unwrap_or_default();
            require(
                selected == analysis::FRONTEND.as_bytes(),
                Failure::Integrity,
            )?;
            return Ok(Some(analysis::FRONTEND.into()));
        }
        seen.push(name);
    }
    Ok(None)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedInputProvenance {
    pub ordinal: u64,
    pub original_reference: String,
    pub original_platform: String,
    pub original_root: String,
    pub original_manifest: Descriptor,
    pub original_config: Descriptor,
    pub role: &'static str,
    pub uses: Vec<analysis::Use>,
    pub derived_root: Descriptor,
    pub derived_manifest: Descriptor,
    pub derived_config: Descriptor,
    pub layers: Vec<Descriptor>,
    pub history_completion: Option<analysis::HistoryCompletion>,
}

pub(crate) struct LayoutPlan {
    pub(crate) ordinal: usize,
    pub(crate) root: Descriptor,
    pub(crate) manifest: Bytes,
    pub(crate) config: Descriptor,
    pub(crate) config_bytes: Bytes,
    pub(crate) layers: Vec<Descriptor>,
    pub(crate) source: Entry,
}

pub(crate) struct Plan {
    pub(crate) dockerfile_name: String,
    pub(crate) dockerfile: Bytes,
    pub(crate) dockerfile_digest: String,
    pub(crate) bake: Vec<u8>,
    pub(crate) bake_digest: String,
    pub(crate) layouts: Vec<LayoutPlan>,
    pub(crate) bindings: Vec<BindingIdentity>,
    pub(crate) derived_provenance: Vec<DerivedInputProvenance>,
    pub(crate) generated_aliases: Vec<(String, String)>,
    pub(crate) frontend: Option<String>,
    pub(crate) derived_entries: u64,
    pub(crate) derived_bytes: u64,
    pub(crate) read_paths: Vec<PathBuf>,
    pub(crate) image_config: Bytes,
}

pub(crate) struct PlanInputs<'a> {
    pub(crate) key: &'a NodeKey,
    pub(crate) image: &'a EffectiveImage,
    pub(crate) associations: &'a Associations,
    pub(crate) material: &'a Material,
    pub(crate) workspace: &'a Path,
    pub(crate) allowance: u64,
    pub(crate) end: u64,
    pub(crate) no_cache: bool,
}

struct AssociatedSource {
    entry: Entry,
    root: Descriptor,
}

fn descriptor_of(manifest: &[u8]) -> Result<Descriptor> {
    let value = Value::parse_bounded(manifest, analysis::OBJECT, 128)?;
    let media = value.field("mediaType")?.text()?;
    Ok(Descriptor {
        digest: analysis::hash(manifest),
        size: manifest.len() as u64,
        media_type: std::str::from_utf8(media.get())
            .map_err(|_| Failure::Integrity)?
            .into(),
    })
}

fn layers_of(manifest: &[u8]) -> Result<(Descriptor, Vec<Descriptor>)> {
    let value = Value::parse_bounded(manifest, analysis::OBJECT, 128)?;
    let config = content::descriptor(value.field("config")?, false)?;
    let mut layers = Vec::new();
    for layer in value.field("layers")?.array()? {
        layers.push(content::descriptor(layer, false)?);
    }
    Ok((config, layers))
}

pub(crate) fn plan(inputs: &PlanInputs<'_>) -> std::result::Result<Plan, Refusal> {
    let outcome = inputs
        .material
        .outcome(inputs.key)
        .ok_or_else(|| refuse(Failure::Integrity, FailedCheck::Material))?;
    let material = outcome
        .private_material()
        .map_err(|failure| refuse(failure, FailedCheck::Material))?;
    let PrivateMaterial {
        document,
        dockerfile,
        image,
        bindings,
    } = material;
    require(bindings.len() <= MAX_BINDINGS, Failure::Limit)
        .map_err(|f| refuse(f, FailedCheck::Budget))?;
    require(
        !dockerfile.get().is_empty() && dockerfile.get().len() <= MAX_DOCKERFILE,
        Failure::Limit,
    )
    .map_err(|f| refuse(f, FailedCheck::Budget))?;
    let mut associated: BTreeMap<(String, String, String), AssociatedSource> = BTreeMap::new();
    for source in &inputs.associations.sources {
        let closure = inputs
            .material
            .fetch_closure(source)
            .ok_or_else(|| refuse(Failure::Policy, FailedCheck::Bindings))?;
        let key = (
            source.reference.clone(),
            source.platform.clone(),
            closure.output.root().digest.clone(),
        );
        let value = AssociatedSource {
            entry: closure.output.entry().clone(),
            root: closure.output.root().clone(),
        };
        require(associated.insert(key, value).is_none(), Failure::Integrity)
            .map_err(|f| refuse(f, FailedCheck::Bindings))?;
    }
    for (producer, uses) in &inputs.associations.producers {
        let output = inputs
            .material
            .producer_output(producer)
            .ok_or_else(|| refuse(Failure::Integrity, FailedCheck::Bindings))?;
        for reference in uses {
            let key = (
                reference.clone(),
                producer.platform.clone(),
                output.root().digest.clone(),
            );
            let value = AssociatedSource {
                entry: output.entry().clone(),
                root: output.root().clone(),
            };
            require(associated.insert(key, value).is_none(), Failure::Integrity)
                .map_err(|f| refuse(f, FailedCheck::Bindings))?;
        }
    }
    let mut named: BTreeSet<(String, String, String)> = BTreeSet::new();
    for binding in &bindings {
        let key = (
            binding.reference.clone(),
            binding.platform.clone(),
            binding.source_root.clone(),
        );
        require(associated.contains_key(&key), Failure::Integrity)
            .map_err(|f| refuse(f, FailedCheck::Bindings))?;
        named.insert(key);
    }
    require(
        named.len() == associated.len() && associated.keys().all(|k| named.contains(k)),
        Failure::Integrity,
    )
    .map_err(|f| refuse(f, FailedCheck::Bindings))?;
    for binding in &bindings {
        if !binding.generated {
            portable_operand_check(document, binding)
                .map_err(|f| refuse(f, FailedCheck::Operand))?;
        }
    }
    require(bindings.len() <= MAX_LAYOUTS, Failure::Limit)
        .map_err(|f| refuse(f, FailedCheck::Budget))?;
    require(
        inputs.image.contexts.len() <= MAX_NAMED_DIRECTORIES,
        Failure::Limit,
    )
    .map_err(|f| refuse(f, FailedCheck::Budget))?;
    let mut layouts = Vec::new();
    let mut identities = Vec::new();
    let mut derived_provenance = Vec::new();
    let mut generated_aliases = Vec::new();
    let mut derived_entries = FIXED_INPUT_ENTRIES;
    let mut derived_bytes = 0u64;
    let mut counted: BTreeSet<(u64, u64, String)> = BTreeSet::new();
    let mut contexts: Map<String, Public> = Map::new();
    for (name, path) in &inputs.image.contexts {
        require(valid_path(path), Failure::Policy).map_err(Refusal::from)?;
        contexts.insert(name.clone(), json!(path));
    }
    for (ordinal, binding) in bindings.iter().enumerate() {
        before(inputs.end).map_err(Refusal::from)?;
        let key = (
            binding.reference.clone(),
            binding.platform.clone(),
            binding.source_root.clone(),
        );
        let source = &associated[&key];
        let root =
            descriptor_of(binding.manifest.get()).map_err(|f| refuse(f, FailedCheck::Material))?;
        require(root.digest == binding.root, Failure::Integrity)
            .map_err(|f| refuse(f, FailedCheck::Material))?;
        let (config, layers) =
            layers_of(binding.manifest.get()).map_err(|f| refuse(f, FailedCheck::Material))?;
        require(
            config.size == binding.config.get().len() as u64
                && config.digest == analysis::hash(binding.config.get()),
            Failure::Integrity,
        )
        .map_err(|f| refuse(f, FailedCheck::Material))?;
        let chain = graph::read_chain(&source.entry, &source.root, &binding.platform, inputs.end)
            .map_err(|f| refuse(f, FailedCheck::Link))?;
        let original_manifest =
            descriptor_of(chain.manifest.get()).map_err(|f| refuse(f, FailedCheck::Link))?;
        let (original_config, original) =
            layers_of(chain.manifest.get()).map_err(|f| refuse(f, FailedCheck::Link))?;
        require(original == layers, Failure::Integrity)
            .map_err(|f| refuse(f, FailedCheck::Link))?;
        let directory =
            files::open(&source.entry, false).map_err(|f| refuse(f, FailedCheck::Link))?;
        let (blobs, _) = files::child(
            &directory,
            &source.entry.path.join("blobs"),
            source.entry.ownership,
        )
        .map_err(|f| refuse(f, FailedCheck::Link))?;
        let (sha, _) = files::child(
            &blobs,
            &source.entry.path.join("blobs/sha256"),
            source.entry.ownership,
        )
        .map_err(|f| refuse(f, FailedCheck::Link))?;
        for layer in &layers {
            let path = source
                .entry
                .path
                .join("blobs/sha256")
                .join(&layer.digest[7..]);
            let (file, item) = files::child(&sha, &path, source.entry.ownership)
                .map_err(|f| refuse(f, FailedCheck::Link))?;
            let metadata = file
                .metadata()
                .map_err(|_| refuse(Failure::Storage, FailedCheck::Link))?;
            require(
                item.kind == Kind::File && metadata.len() == layer.size,
                Failure::Integrity,
            )
            .map_err(|f| refuse(f, FailedCheck::Link))?;
            if counted.insert((item.device, item.inode, layer.digest.clone())) {
                derived_bytes = derived_bytes
                    .checked_add(layer.size)
                    .ok_or_else(|| refuse(Failure::Limit, FailedCheck::Budget))?;
            }
        }
        derived_bytes = derived_bytes
            .checked_add(root.size)
            .and_then(|n| n.checked_add(config.size))
            .ok_or_else(|| refuse(Failure::Limit, FailedCheck::Budget))?;
        derived_entries = derived_entries
            .checked_add(LAYOUT_ENTRIES)
            .and_then(|n| n.checked_add(layers.len() as u64))
            .ok_or_else(|| refuse(Failure::Limit, FailedCheck::Budget))?;
        let layout = inputs
            .workspace
            .join("inputs/derived")
            .join(ordinal.to_string());
        require(
            contexts
                .insert(
                    binding.context.clone(),
                    json!(format!("oci-layout://{}@{}", layout.display(), root.digest)),
                )
                .is_none(),
            Failure::Integrity,
        )
        .map_err(|f| refuse(f, FailedCheck::Bindings))?;
        identities.push(BindingIdentity {
            alias: binding.alias.clone(),
            context: binding.context.clone(),
            reference: binding.reference.clone(),
            platform: binding.platform.clone(),
            source_root: binding.source_root.clone(),
            role: match binding.role {
                Role::Inheritance => "inheritance",
                Role::FileSource => "file-source",
            },
            derived_root: root.digest.clone(),
        });
        derived_provenance.push(DerivedInputProvenance {
            ordinal: ordinal as u64,
            original_reference: binding.reference.clone(),
            original_platform: binding.platform.clone(),
            original_root: binding.source_root.clone(),
            original_manifest,
            original_config,
            role: match binding.role {
                Role::Inheritance => "inheritance",
                Role::FileSource => "file-source",
            },
            uses: binding.uses.clone(),
            derived_root: root.clone(),
            derived_manifest: root.clone(),
            derived_config: config.clone(),
            layers: layers.clone(),
            history_completion: binding.history_completion.clone(),
        });
        if binding.generated {
            generated_aliases.push((binding.alias.clone(), binding.context.clone()));
        }
        layouts.push(LayoutPlan {
            ordinal,
            root,
            manifest: analysis::copy(binding.manifest.get()).map_err(Refusal::from)?,
            config,
            config_bytes: analysis::copy(binding.config.get()).map_err(Refusal::from)?,
            layers,
            source: source.entry.clone(),
        });
    }
    require(
        derived_entries <= MAX_DERIVED_ENTRIES && derived_bytes <= inputs.allowance,
        Failure::Limit,
    )
    .map_err(|f| refuse(f, FailedCheck::Budget))?;
    identities.sort_by(|a, b| (&a.alias, &a.platform).cmp(&(&b.alias, &b.platform)));
    let dockerfile_name = inputs
        .image
        .dockerfile
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| Refusal::from(Failure::Policy))?
        .to_owned();
    require(valid_path(&inputs.image.context), Failure::Policy).map_err(Refusal::from)?;
    let generated_path = inputs
        .workspace
        .join("inputs/dockerfile")
        .join(&dockerfile_name);
    let mut target: Map<String, Public> = Map::new();
    target.insert("context".into(), json!(inputs.image.context));
    target.insert("dockerfile".into(), json!(generated_path));
    target.insert("contexts".into(), Public::Object(contexts));
    target.insert("args".into(), json!(inputs.image.declaration.args));
    if let Some(stage) = &inputs.image.declaration.stage {
        target.insert("target".into(), json!(stage));
    }
    target.insert("platforms".into(), json!([inputs.key.platform]));
    if inputs.no_cache {
        target.insert("no-cache".into(), json!(true));
    }
    if !inputs.image.declaration.entitlements.is_empty() {
        target.insert(
            "entitlements".into(),
            json!(inputs.image.declaration.entitlements),
        );
    }
    target.insert(
        "attest".into(),
        json!(["type=provenance,disabled=true", "type=sbom,disabled=true"]),
    );
    let mut targets: Map<String, Public> = Map::new();
    targets.insert(inputs.key.producer.clone(), Public::Object(target));
    let bake = serde_json::to_vec(&json!({"target": Public::Object(targets)}))
        .map_err(|_| Refusal::from(Failure::Protocol))?;
    require(bake.len() <= MAX_BAKE, Failure::Limit).map_err(|f| refuse(f, FailedCheck::Budget))?;
    let frontend = frontend(dockerfile.get()).map_err(|f| refuse(f, FailedCheck::Material))?;
    let mut read_paths = vec![inputs.image.context.clone()];
    read_paths.extend(inputs.image.contexts.values().cloned());
    read_paths.push(inputs.workspace.join("inputs"));
    let image_config = analysis::copy(image.raw()).map_err(Refusal::from)?;
    Ok(Plan {
        dockerfile_name,
        dockerfile_digest: analysis::hash(dockerfile.get()),
        dockerfile,
        bake_digest: analysis::hash(&bake),
        bake,
        layouts,
        bindings: identities,
        derived_provenance,
        generated_aliases,
        frontend,
        derived_entries,
        derived_bytes,
        read_paths,
        image_config,
    })
}

#[derive(Clone)]
pub(crate) struct IgnoreCopy {
    pub(crate) source: PathBuf,
    pub(crate) size: u64,
    pub(crate) digest: String,
}

pub(crate) struct Materialized {
    pub(crate) dockerfile: Entry,
    pub(crate) ignore: Option<Entry>,
    pub(crate) bake: Entry,
    pub(crate) layouts: Vec<Entry>,
}

pub(crate) struct MaterializeWork {
    workspace: Entry,
    dockerfile_name: String,
    dockerfile: Bytes,
    ignore: Option<IgnoreCopy>,
    bake: Vec<u8>,
    layouts: Vec<LayoutPlan>,
    result: Option<Materialized>,
    check: Option<FailedCheck>,
}

impl MaterializeWork {
    pub(crate) fn new(
        workspace: Entry,
        plan: Plan,
        ignore: Option<IgnoreCopy>,
    ) -> Result<(Self, PlanFacts)> {
        require(
            workspace.kind == Kind::Directory
                && workspace.ownership == Ownership::Operation
                && valid_path(&workspace.path)
                && ignore.as_ref().is_none_or(|copy| valid_path(&copy.source)),
            Failure::Policy,
        )?;
        let facts = PlanFacts {
            dockerfile_digest: plan.dockerfile_digest,
            dockerfile_size: plan.dockerfile.get().len() as u64,
            bake_digest: plan.bake_digest,
            bake_size: plan.bake.len() as u64,
            bindings: plan.bindings,
            derived_provenance: plan.derived_provenance,
            generated_aliases: plan.generated_aliases,
            frontend: plan.frontend,
            derived_entries: plan.derived_entries,
            derived_bytes: plan.derived_bytes,
            read_paths: plan.read_paths,
            image_config: plan.image_config,
            layouts: plan
                .layouts
                .iter()
                .map(|layout| layout.root.clone())
                .collect(),
        };
        Ok((
            Self {
                workspace,
                dockerfile_name: plan.dockerfile_name,
                dockerfile: plan.dockerfile,
                ignore,
                bake: plan.bake,
                layouts: plan.layouts,
                result: None,
                check: None,
            },
            facts,
        ))
    }

    pub(crate) fn take(self) -> (Option<Materialized>, Option<FailedCheck>) {
        (self.result, self.check)
    }

    pub(crate) fn apply<W: Watch>(&mut self, active: &W) -> Result<()> {
        self.materialize(active)
    }

    fn materialize<W: Watch>(&mut self, active: &W) -> Result<()> {
        require(self.result.is_none(), Failure::Policy)?;
        active.watch()?;
        let workspace = files::private_directory(&self.workspace)?;
        let root = self.workspace.path.clone();
        let mut created = Vec::new();
        let (inputs_fd, inputs) = create_directory(active, &workspace, &root.join("inputs"))?;
        created.push(inputs);
        let (dockerfile_fd, dockerfile_dir) =
            create_directory(active, &inputs_fd, &root.join("inputs/dockerfile"))?;
        created.push(dockerfile_dir);
        let dockerfile_path = root.join("inputs/dockerfile").join(&self.dockerfile_name);
        let dockerfile = write_file(
            active,
            &dockerfile_fd,
            &dockerfile_path,
            self.dockerfile.get(),
        )?;
        created.push(dockerfile.clone());
        let ignore = match &self.ignore {
            Some(copy) => {
                let mut name = self.dockerfile_name.clone();
                name.push_str(".dockerignore");
                let path = root.join("inputs/dockerfile").join(name);
                let entry = copy_ignore(active, &dockerfile_fd, &path, copy, &mut self.check)?;
                created.push(entry.clone());
                Some(entry)
            }
            None => None,
        };
        let bake = write_file(
            active,
            &inputs_fd,
            &root.join("inputs/bake.json"),
            &self.bake,
        )?;
        created.push(bake.clone());
        let (derived_fd, derived) =
            create_directory(active, &inputs_fd, &root.join("inputs/derived"))?;
        created.push(derived);
        let mut layouts = Vec::new();
        for layout in &self.layouts {
            active.watch()?;
            let base = root.join("inputs/derived").join(layout.ordinal.to_string());
            let (layout_fd, layout_entry) = create_directory(active, &derived_fd, &base)?;
            created.push(layout_entry.clone());
            created.push(write_file(
                active,
                &layout_fd,
                &base.join("oci-layout"),
                OCI_LAYOUT,
            )?);
            let index = serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_INDEX,
                "manifests":[{"mediaType":layout.root.media_type,"digest":layout.root.digest,"size":layout.root.size}]}))
            .map_err(|_| Failure::Protocol)?;
            created.push(write_file(
                active,
                &layout_fd,
                &base.join("index.json"),
                &index,
            )?);
            let (blobs_fd, blobs) = create_directory(active, &layout_fd, &base.join("blobs"))?;
            created.push(blobs);
            let (sha_fd, sha) = create_directory(active, &blobs_fd, &base.join("blobs/sha256"))?;
            created.push(sha);
            created.push(write_file(
                active,
                &sha_fd,
                &base.join("blobs/sha256").join(&layout.root.digest[7..]),
                layout.manifest.get(),
            )?);
            created.push(write_file(
                active,
                &sha_fd,
                &base.join("blobs/sha256").join(&layout.config.digest[7..]),
                layout.config_bytes.get(),
            )?);
            let source = files::open(&layout.source, false)?;
            let (source_blobs, _) = files::child(
                &source,
                &layout.source.path.join("blobs"),
                layout.source.ownership,
            )?;
            let (source_sha, _) = files::child(
                &source_blobs,
                &layout.source.path.join("blobs/sha256"),
                layout.source.ownership,
            )?;
            for descriptor in &layout.layers {
                let name = &descriptor.digest[7..];
                let (blob, original) = files::child(
                    &source_sha,
                    &layout.source.path.join("blobs/sha256").join(name),
                    layout.source.ownership,
                )?;
                let metadata = active.io(|| blob.metadata())?;
                require(
                    original.kind == Kind::File && metadata.len() == descriptor.size,
                    Failure::Integrity,
                )?;
                let destination = base.join("blobs/sha256").join(name);
                let linked = active
                    .sys(|| rustix::fs::linkat(&source_sha, name, &sha_fd, name, AtFlags::empty()));
                match linked {
                    Ok(()) => {}
                    Err(Failure::Storage) => {
                        let (_, existing) =
                            files::child(&sha_fd, &destination, Ownership::Operation)
                                .map_err(|_| Failure::Storage)?;
                        require(
                            existing.device == original.device && existing.inode == original.inode,
                            Failure::Policy,
                        )?;
                    }
                    Err(failure) => return Err(failure),
                }
                let (_, entry) = files::child(&sha_fd, &destination, Ownership::Operation)?;
                require(
                    entry.kind == Kind::File
                        && entry.device == original.device
                        && entry.inode == original.inode,
                    Failure::Integrity,
                )?;
                created.push(entry);
            }
            layouts.push(layout_entry);
        }
        for entry in &created {
            active.watch()?;
            files::open(entry, false)?;
        }
        active.watch()?;
        self.result = Some(Materialized {
            dockerfile,
            ignore,
            bake,
            layouts,
        });
        Ok(())
    }
}

fn copy_ignore<W: Watch>(
    active: &W,
    directory: &File,
    destination: &Path,
    copy: &IgnoreCopy,
    check: &mut Option<FailedCheck>,
) -> Result<Entry> {
    let (parent, name) =
        path_safety::defensive_open_parent(&copy.source).map_err(|_| Failure::Storage)?;
    let handle = File::from(active.sys(|| {
        rustix::fs::openat(
            &parent,
            &name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })?);
    let metadata = active.io(|| handle.metadata())?;
    if !metadata.is_file() || metadata.len() != copy.size {
        *check = Some(FailedCheck::Ignore);
        return Err(Failure::Integrity);
    }
    let mut input = active.io(|| {
        path_safety::reopen_for_read(&handle)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    })?;
    let mut output = create_file(active, directory, destination)?;
    let mut scratch = Bytes::new(65_536)?;
    let mut hash = Sha256::new();
    let mut used = 0u64;
    loop {
        let count = active.io(|| input.read(scratch.get_mut()))?;
        if count == 0 {
            break;
        }
        used = used.checked_add(count as u64).ok_or(Failure::Limit)?;
        if used > copy.size {
            *check = Some(FailedCheck::Ignore);
            return Err(Failure::Integrity);
        }
        hash.update(&scratch.get()[..count]);
        active.io(|| output.write_all(&scratch.get()[..count]))?;
        scratch.clear();
    }
    let mut digest = hash.finalize();
    let same = used == copy.size && hex(digest.as_slice()) == copy.digest;
    digest.as_mut_slice().zeroize();
    if !same {
        *check = Some(FailedCheck::Ignore);
        return Err(Failure::Integrity);
    }
    files::identity(&output, destination, Ownership::Operation, false)
}

pub(crate) struct PlanFacts {
    pub(crate) dockerfile_digest: String,
    pub(crate) dockerfile_size: u64,
    pub(crate) bake_digest: String,
    pub(crate) bake_size: u64,
    pub(crate) bindings: Vec<BindingIdentity>,
    pub(crate) derived_provenance: Vec<DerivedInputProvenance>,
    pub(crate) generated_aliases: Vec<(String, String)>,
    pub(crate) frontend: Option<String>,
    pub(crate) derived_entries: u64,
    pub(crate) derived_bytes: u64,
    pub(crate) read_paths: Vec<PathBuf>,
    pub(crate) image_config: Bytes,
    pub(crate) layouts: Vec<Descriptor>,
}

fn absent<W: Watch>(active: &W, parent: &File, path: &Path) -> Result<()> {
    let name = path.file_name().ok_or(Failure::Policy)?;
    active.watch()?;
    match rustix::fs::openat(
        parent,
        name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(_) => Err(Failure::Policy),
        Err(rustix::io::Errno::NOENT) => {
            active.watch()?;
            Ok(())
        }
        Err(_) => Err(Failure::Storage),
    }
}

pub(crate) fn create_directory<W: Watch>(
    active: &W,
    parent: &File,
    path: &Path,
) -> Result<(File, Entry)> {
    absent(active, parent, path)?;
    active.watch()?;
    let (file, entry) = files::mkdir(parent, path)?;
    active.watch()?;
    Ok((file, entry))
}

pub(crate) fn create_file<W: Watch>(active: &W, parent: &File, path: &Path) -> Result<File> {
    let name = path.file_name().ok_or(Failure::Policy)?;
    active.watch()?;
    let file = match rustix::fs::openat(
        parent,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::EXIST) => return Err(Failure::Policy),
        Err(_) => return Err(Failure::Storage),
    };
    active.watch()?;
    let metadata = active.io(|| file.metadata())?;
    require(
        metadata.is_file()
            && metadata.mode() & 0o777 == 0o600
            && metadata.uid() == path_safety::effective_uid(),
        Failure::Policy,
    )?;
    Ok(file)
}

pub(crate) fn write_file<W: Watch>(
    active: &W,
    parent: &File,
    path: &Path,
    bytes: &[u8],
) -> Result<Entry> {
    let mut file = create_file(active, parent, path)?;
    let mut offset = 0;
    while offset < bytes.len() {
        let count = active.io(|| file.write(&bytes[offset..]))?;
        require(count != 0, Failure::Storage)?;
        offset += count;
    }
    let metadata = active.io(|| file.metadata())?;
    require(metadata.len() == bytes.len() as u64, Failure::Integrity)?;
    files::identity(&file, path, Ownership::Operation, false)
}
