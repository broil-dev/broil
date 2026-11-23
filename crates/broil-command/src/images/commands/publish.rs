// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::images::{
    Descriptor,
    buffer::Bytes,
    common::{ContentLimits, require},
    content,
    json::Value,
    publish::{self, Member, NotPublished, PublicationOutcome, RetainedArtifact},
};
use broil_core::images::{OutputKind, valid_platform};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Seek, SeekFrom},
};
use zeroize::Zeroize;

const METADATA: usize = 1_048_576;
const PLATFORMS: usize = 64;
const MANIFESTS: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

pub(super) fn class(outcome: &PublicationOutcome) -> Option<FailureClass> {
    match outcome {
        PublicationOutcome::Published(_) => None,
        PublicationOutcome::Failed { .. } => {
            let (outcome, class) = records::Outcome::of_publication(outcome);
            class.or((outcome == records::Outcome::Cancelled).then_some(FailureClass::Cancellation))
        }
        PublicationOutcome::Unknown(_) => Some(FailureClass::Indeterminate),
        PublicationOutcome::Cancelled
        | PublicationOutcome::NotPublished(NotPublished::Cancelled) => {
            Some(FailureClass::Cancellation)
        }
        PublicationOutcome::NotPublished(NotPublished::Stale) => Some(FailureClass::SourceDrift),
        PublicationOutcome::NotPublished(_) => Some(FailureClass::of(Failure::Protocol)),
    }
}

fn parse(bytes: &Bytes) -> common::Result<Value<'_>> {
    Value::parse_bounded(bytes.get(), METADATA, 128)
}

pub(super) fn platform(value: Value<'_>) -> common::Result<String> {
    let component = |name: &str, required: bool| -> common::Result<Option<Bytes>> {
        let Some(value) = value.optional(name).map_err(|_| Failure::Integrity)? else {
            return if required {
                Err(Failure::Integrity)
            } else {
                Ok(None)
            };
        };
        require(value.raw().first() == Some(&b'"'), Failure::Integrity)?;
        let bytes = value.text()?;
        require(!required || !bytes.get().is_empty(), Failure::Integrity)?;
        require(
            bytes
                .get()
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(b)),
            Failure::Integrity,
        )?;
        Ok(Some(bytes))
    };
    let os = component("os", true)?.ok_or(Failure::Integrity)?;
    let architecture = component("architecture", true)?.ok_or(Failure::Integrity)?;
    let variant = component("variant", false)?;
    let mut result = String::new();
    for bytes in [&os, &architecture]
        .into_iter()
        .chain(variant.as_ref().filter(|v| !v.get().is_empty()))
    {
        if !result.is_empty() {
            result.push('/');
        }
        result.push_str(std::str::from_utf8(bytes.get()).map_err(|_| Failure::Integrity)?);
    }
    require(valid_platform(&result), Failure::Integrity)?;
    Ok(result)
}

pub(super) fn manifests(
    closure: &records::RetentionClosure,
    wrapper: &Bytes,
    mut read: impl FnMut(&Descriptor) -> common::Result<Bytes>,
) -> common::Result<Vec<(String, Descriptor)>> {
    require(
        !closure.manifests.is_empty() && closure.manifests.len() <= PLATFORMS,
        Failure::Limit,
    )?;
    closure.root.validate()?;
    let wrapper = parse(wrapper)?;
    let roots = wrapper.field("manifests")?.array()?;
    require(roots.len() == 1, Failure::Integrity)?;
    require(
        content::descriptor(roots[0], false)? == closure.root,
        Failure::Integrity,
    )?;
    let bytes = read(&closure.root)?;
    let root = parse(&bytes)?;
    if MANIFESTS.contains(&closure.root.media_type.as_str()) {
        require(
            closure.manifests == [closure.root.clone()],
            Failure::Integrity,
        )?;
        let config = content::descriptor(root.field("config")?, false)?;
        let bytes = read(&config)?;
        return Ok(vec![(platform(parse(&bytes)?)?, closure.root.clone())]);
    }
    require(
        closure.root.media_type == content::OCI_INDEX,
        Failure::Integrity,
    )?;
    let entries = root.field("manifests")?.array()?;
    require(entries.len() <= PLATFORMS, Failure::Limit)?;
    require(entries.len() == closure.manifests.len(), Failure::Integrity)?;
    let mut labels = BTreeMap::new();
    let mut platforms = BTreeSet::new();
    for entry in entries {
        let label = platform(
            entry
                .optional("platform")
                .map_err(|_| Failure::Integrity)?
                .ok_or(Failure::Integrity)?,
        )?;
        let descriptor = content::descriptor(entry, false)?;
        require(
            MANIFESTS.contains(&descriptor.media_type.as_str())
                && closure.manifests.contains(&descriptor),
            Failure::Integrity,
        )?;
        require(
            platforms.insert(label.clone()) && !labels.contains_key(&descriptor.digest),
            Failure::Integrity,
        )?;
        labels.insert(descriptor.digest.clone(), label);
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(closure.manifests.len())
        .map_err(|_| Failure::Limit)?;
    for descriptor in &closure.manifests {
        result.push((
            labels
                .remove(&descriptor.digest)
                .ok_or(Failure::Integrity)?,
            descriptor.clone(),
        ));
    }
    require(labels.is_empty(), Failure::Integrity)?;
    Ok(result)
}

pub(super) fn layout(
    location: &Path,
    closure: &records::RetentionClosure,
    active: &Active,
) -> common::Result<Vec<(String, Descriptor)>> {
    active.check()?;
    let (directory, entry) = files::open_path(location, Ownership::Retained, false)?;
    require(entry.kind == Kind::Directory, Failure::Policy)?;
    let (wrapper, entry) = files::child(
        &directory,
        &location.join("index.json"),
        Ownership::Retained,
    )?;
    require(entry.kind == Kind::File, Failure::Policy)?;
    active.check()?;
    let wrapper = files::metadata(&wrapper, METADATA as u64, active.end())?;
    active.check()?;
    let (blobs, _) = files::child(&directory, &location.join("blobs"), Ownership::Retained)?;
    let (sha, _) = files::child(&blobs, &location.join("blobs/sha256"), Ownership::Retained)?;
    let limits = ContentLimits {
        metadata_bytes: METADATA as u64,
        ..Default::default()
    };
    manifests(closure, &wrapper, |descriptor| {
        active.check()?;
        descriptor.validate()?;
        require(descriptor.size <= METADATA as u64, Failure::Limit)?;
        let path = location.join("blobs/sha256").join(&descriptor.digest[7..]);
        let (file, entry) = files::child(&sha, &path, Ownership::Retained)?;
        require(entry.kind == Kind::File, Failure::Policy)?;
        let bytes = content::verified_metadata(&file, descriptor, &limits, active.end())?;
        active.check()?;
        Ok(bytes)
    })
}

fn read_at(file: &mut File, offset: u64, bytes: &mut [u8], active: &Active) -> common::Result<()> {
    active.io(|| file.seek(SeekFrom::Start(offset)))?;
    let mut used = 0;
    while used < bytes.len() {
        let count = active.io(|| file.read(&mut bytes[used..]))?;
        require(count > 0, Failure::Integrity)?;
        used += count;
    }
    Ok(())
}

pub(super) fn archive(
    location: &Path,
    closure: &records::RetentionClosure,
    active: &Active,
) -> common::Result<Vec<(String, Descriptor)>> {
    let (length, _) = closure.archive.as_ref().ok_or(Failure::Integrity)?;
    let length = *length;
    let limits = ContentLimits::default();
    require(length <= limits.staging_bytes, Failure::Limit)?;
    active.check()?;
    let (file, entry) = files::open_path(location, Ownership::Retained, false)?;
    require(entry.kind == Kind::File, Failure::Policy)?;
    require(
        active.io(|| file.metadata())?.len() == length,
        Failure::Integrity,
    )?;
    let mut file = files::read(&file)?;
    let mut blobs = BTreeMap::new();
    let (mut offset, mut stage, mut headers) = (0u64, 0, 0);
    let mut previous = String::new();
    let mut wrapper = None;
    loop {
        let next = offset.checked_add(512).ok_or(Failure::Limit)?;
        require(next <= length, Failure::Integrity)?;
        let mut block = [0u8; 512];
        read_at(&mut file, offset, &mut block, active)?;
        let Some(member) = publish::header(&block)? else {
            require(
                stage == 4 && next.checked_add(512) == Some(length),
                Failure::Integrity,
            )?;
            read_at(&mut file, next, &mut block, active)?;
            require(block.iter().all(|b| *b == 0), Failure::Integrity)?;
            break;
        };
        headers += 1;
        require(headers <= 4100, Failure::Limit)?;
        let size = match member {
            Member::Directory(name) => {
                require(
                    (stage == 0 && name == "blobs/") || (stage == 1 && name == "blobs/sha256/"),
                    Failure::Policy,
                )?;
                stage += 1;
                0
            }
            Member::Blob(digest, size) => {
                require(stage == 2 && digest > previous, Failure::Integrity)?;
                require(
                    blobs.len() < limits.descriptors as usize && size <= limits.blob_bytes,
                    Failure::Limit,
                )?;
                previous = digest.clone();
                blobs.insert(digest, (next, size));
                size
            }
            Member::Metadata(name, size) => {
                require(
                    (stage == 2 && name == "index.json") || (stage == 3 && name == "oci-layout"),
                    Failure::Policy,
                )?;
                require(size <= METADATA as u64, Failure::Limit)?;
                if stage == 2 {
                    wrapper = Some((next, size));
                }
                stage += 1;
                size
            }
        };
        let padded = size.checked_add(511).ok_or(Failure::Limit)? / 512 * 512;
        offset = next.checked_add(padded).ok_or(Failure::Limit)?;
        require(offset <= length, Failure::Integrity)?;
    }
    let (offset, size) = wrapper.ok_or(Failure::Integrity)?;
    let mut wrapper = Bytes::new(size as usize)?;
    read_at(&mut file, offset, wrapper.get_mut(), active)?;
    manifests(closure, &wrapper, |descriptor| {
        descriptor.validate()?;
        require(descriptor.size <= METADATA as u64, Failure::Limit)?;
        let (offset, size) = blobs
            .get(&descriptor.digest)
            .copied()
            .ok_or(Failure::Integrity)?;
        require(size == descriptor.size, Failure::Integrity)?;
        let mut bytes = Bytes::new(size as usize)?;
        read_at(&mut file, offset, bytes.get_mut(), active)?;
        let mut hash = Sha256::digest(bytes.get());
        const HEX: &[u8] = b"0123456789abcdef";
        let same = hash.iter().enumerate().all(|(i, b)| {
            descriptor.digest.as_bytes()[7 + i * 2] == HEX[(b >> 4) as usize]
                && descriptor.digest.as_bytes()[8 + i * 2] == HEX[(b & 15) as usize]
        });
        hash.as_mut_slice().zeroize();
        require(same, Failure::Integrity)?;
        active.check()?;
        Ok(bytes)
    })
}

pub(super) fn retained(
    root: &Path,
    operation_id: &str,
    target: &str,
    active: &Active,
) -> Result<RetainedArtifact> {
    let verb = Verb::Publish;
    operation(root, operation_id, verb, active)?;
    let journal = records::Journal::open(root, operation_id, false, active)
        .map_err(|f| Error::failure(verb, f))?;
    let observations = journal
        .observations(active)
        .map_err(|f| Error::failure(verb, f.into()))?;
    let mut retentions = observations.iter().filter(|o| {
        o.kind == records::Kind::Retention
            && o.target
                .as_ref()
                .is_some_and(|t| t.logical_target == target)
    });
    let observation = retentions.next().ok_or_else(|| {
        Error::new(
            FailureClass::Configuration,
            format!("no retention recorded for {target} in {operation_id}"),
        )
    })?;
    if retentions.next().is_some() {
        return Err(Error::failure(verb, Failure::Integrity));
    }
    let Some(records::ObservationDetail::Retention {
        location,
        output_kind,
        closure,
        ..
    }) = &observation.detail
    else {
        return Err(Error::failure(verb, Failure::Integrity));
    };
    let kind = match output_kind.as_str() {
        "oci-layout" => OutputKind::OciLayout,
        "oci-archive" => OutputKind::OciArchive,
        _ => return Err(Error::failure(verb, Failure::Integrity)),
    };
    let manifests = if kind == OutputKind::OciLayout {
        layout(Path::new(location), closure, active)
    } else {
        archive(Path::new(location), closure, active)
    }
    .map_err(|f| Error::failure(verb, f))?;
    Ok(RetainedArtifact {
        location: location.into(),
        kind,
        root: closure.root.clone(),
        manifests,
        verified_files: closure.verified_descriptors,
        verified_bytes: closure.verified_bytes,
        archive: closure
            .archive
            .as_ref()
            .map(|(size, digest)| (digest.clone(), *size)),
    })
}

pub(super) fn run(
    project: &LoadedProject,
    invocation: Invocation,
    inputs: Inputs<'_>,
    cancellation: Cancellation,
) -> Result<Output> {
    let verb = invocation.verb;
    let assembly = assemble_before_store(project, verb, &inputs)?;
    let id = invocation
        .operation
        .clone()
        .ok_or_else(|| Error::failure(verb, Failure::Policy))?;
    let target = invocation
        .targets
        .first()
        .cloned()
        .ok_or_else(|| Error::failure(verb, Failure::Policy))?;
    let (artifact, parent) = step(
        &project.broil_root,
        verb,
        &cancellation,
        move |root, active| {
            let artifact = retained(root, &id, &target, active)?;
            Ok((artifact, workspace(root, verb, active)?))
        },
    )?;
    let policy = finish_assembly(project, verb, assembly, parent)?;
    let selection = consumers::PublishSelection {
        target: invocation.targets[0].clone(),
        artifact,
        registry: invocation
            .registries
            .as_ref()
            .and_then(|r| r.first().cloned()),
        artifact_id: invocation.artifact.clone(),
    };
    let (report, _retained) = consumers::publication(project, policy, selection)
        .map_err(|f| Error::failure(verb, f))?
        .run(inputs.consumer(invocation.non_interactive), cancellation);
    output(
        &invocation,
        render::publication(&report),
        class(&report.outcome),
        None,
    )
}
