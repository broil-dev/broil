// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::analysis;
use super::*;
use broil_config::images::select::SelectedCatalogs;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use zeroize::Zeroize;

pub(crate) fn role_name(role: Role) -> &'static str {
    match role {
        Role::Inheritance => "inheritance",
        Role::FileSource => "file-source",
    }
}
pub(crate) fn instruction_name(instruction: Instruction) -> &'static str {
    match instruction {
        Instruction::From => "from",
        Instruction::Copy => "copy",
        Instruction::RunMount => "run-mount",
    }
}
pub(crate) fn tag_origin_name(origin: TagOrigin) -> &'static str {
    match origin {
        TagOrigin::Declared => "declared",
        TagOrigin::Default => "default",
        TagOrigin::Absent => "absent",
    }
}
fn location_kind(location: &Location) -> &'static str {
    match location {
        Location::Dockerfile(_) => "dockerfile",
        Location::Inherited { .. } => "inherited",
        Location::Unavailable => "unavailable",
    }
}
fn subject_parts(subject: Subject) -> (&'static str, u64) {
    match subject {
        Subject::Node(n) => ("node", n),
        Subject::Source(n) => ("source", n),
        Subject::Catalogs => ("catalogs", 0),
    }
}
fn target_parts(target: Target) -> (&'static str, u64) {
    match target {
        Target::Node(n) => ("node", n),
        Target::Source(n) => ("source", n),
    }
}

fn cmp_seq<T>(a: &[T], b: &[T], item: impl Fn(&T, &T) -> Ordering) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| {
        a.iter()
            .zip(b)
            .map(|(x, y)| item(x, y))
            .find(|o| *o != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    })
}
fn range_key(r: &analysis::Range) -> (u64, u64, u64, u64, u64) {
    match (r.start_column, r.end_column) {
        (Some(s), Some(e)) => (r.start_line, r.end_line, 1, s, e),
        _ => (r.start_line, r.end_line, 0, 0, 0),
    }
}
fn cmp_ranges(a: &[analysis::Range], b: &[analysis::Range]) -> Ordering {
    cmp_seq(a, b, |x, y| range_key(x).cmp(&range_key(y)))
}
pub(crate) fn cmp_location(a: &Location, b: &Location) -> Ordering {
    location_kind(a)
        .as_bytes()
        .cmp(location_kind(b).as_bytes())
        .then_with(|| match (a, b) {
            (Location::Dockerfile(x), Location::Dockerfile(y)) => cmp_ranges(x, y),
            (
                Location::Inherited {
                    parent_reference: r1,
                    parent_root: d1,
                    parent_platform: p1,
                    trigger_index: t1,
                    consuming_from: c1,
                },
                Location::Inherited {
                    parent_reference: r2,
                    parent_root: d2,
                    parent_platform: p2,
                    trigger_index: t2,
                    consuming_from: c2,
                },
            ) => r1
                .as_bytes()
                .cmp(r2.as_bytes())
                .then_with(|| d1.as_bytes().cmp(d2.as_bytes()))
                .then_with(|| p1.as_bytes().cmp(p2.as_bytes()))
                .then_with(|| t1.cmp(t2))
                .then_with(|| cmp_ranges(c1, c2)),
            _ => Ordering::Equal,
        })
}
pub(crate) fn cmp_target(a: Target, b: Target) -> Ordering {
    let (x, y) = (target_parts(a), target_parts(b));
    x.0.as_bytes()
        .cmp(y.0.as_bytes())
        .then_with(|| x.1.cmp(&y.1))
}
pub(crate) fn cmp_subject(a: Subject, b: Subject) -> Ordering {
    let (x, y) = (subject_parts(a), subject_parts(b));
    x.0.as_bytes()
        .cmp(y.0.as_bytes())
        .then_with(|| x.1.cmp(&y.1))
}
pub(crate) fn cmp_edge(a: &Edge, b: &Edge) -> Ordering {
    a.source
        .cmp(&b.source)
        .then_with(|| cmp_target(a.target, b.target))
        .then_with(|| cmp_location(&a.location, &b.location))
        .then_with(|| {
            role_name(a.role)
                .as_bytes()
                .cmp(role_name(b.role).as_bytes())
        })
        .then_with(|| {
            instruction_name(a.instruction)
                .as_bytes()
                .cmp(instruction_name(b.instruction).as_bytes())
        })
        .then_with(|| {
            tag_origin_name(a.tag_origin)
                .as_bytes()
                .cmp(tag_origin_name(b.tag_origin).as_bytes())
        })
}
pub(crate) fn cmp_diagnostic(a: &Diagnostic, b: &Diagnostic) -> Ordering {
    cmp_subject(a.subject, b.subject)
        .then_with(|| a.reason.as_bytes().cmp(b.reason.as_bytes()))
        .then_with(|| cmp_location(&a.location, &b.location))
        .then_with(|| cmp_seq(&a.cycle, &b.cycle, |x, y| x.cmp(y)))
}

pub(crate) struct Hasher(Sha256);
impl Hasher {
    pub(crate) fn new(version: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(version);
        h.update(b"\0");
        Self(h)
    }
    pub(crate) fn number(&mut self, n: u64) {
        self.0.update(n.to_be_bytes());
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) -> Result<()> {
        self.number(u64::try_from(b.len()).map_err(|_| Failure::Limit)?);
        self.0.update(b);
        Ok(())
    }
    pub(crate) fn text(&mut self, s: &str) -> Result<()> {
        self.bytes(s.as_bytes())
    }
    pub(crate) fn count(&mut self, n: usize) -> Result<()> {
        self.number(u64::try_from(n).map_err(|_| Failure::Limit)?);
        Ok(())
    }
    pub(crate) fn descriptor(&mut self, d: &Descriptor) -> Result<()> {
        self.text(&d.digest)?;
        self.number(d.size);
        self.text(&d.media_type)
    }
    fn ranges(&mut self, ranges: &[analysis::Range]) -> Result<()> {
        self.count(ranges.len())?;
        for r in ranges {
            self.number(r.start_line);
            self.number(r.end_line);
            match (r.start_column, r.end_column) {
                (Some(s), Some(e)) => {
                    self.number(1);
                    self.number(s);
                    self.number(e);
                }
                _ => self.number(0),
            }
        }
        Ok(())
    }
    fn location(&mut self, location: &Location) -> Result<()> {
        self.text(location_kind(location))?;
        match location {
            Location::Dockerfile(ranges) => self.ranges(ranges),
            Location::Inherited {
                parent_reference,
                parent_root,
                parent_platform,
                trigger_index,
                consuming_from,
            } => {
                self.text(parent_reference)?;
                self.text(parent_root)?;
                self.text(parent_platform)?;
                self.number(*trigger_index);
                self.ranges(consuming_from)
            }
            Location::Unavailable => Ok(()),
        }
    }
    pub(crate) fn finish(self) -> String {
        let mut digest = self.0.finalize();
        const HEX: &[u8] = b"0123456789abcdef";
        let mut text = String::with_capacity(71);
        text.push_str("sha256:");
        for byte in digest.iter() {
            text.push(HEX[(byte >> 4) as usize] as char);
            text.push(HEX[(byte & 15) as usize] as char);
        }
        digest.as_mut_slice().zeroize();
        text
    }
}

pub(crate) fn catalog_id(catalogs: &SelectedCatalogs<'_>) -> Result<String> {
    let mut h = Hasher::new(b"broil.image.catalogs.v1");
    h.count(catalogs.images.len())?;
    for (name, image) in &catalogs.images {
        let output = &image.declaration.image;
        h.text(name)?;
        h.text(&output.repository)?;
        h.text(output.effective_tag().unwrap_or(""))?;
        h.text(output.digest.as_deref().unwrap_or(""))?;
        let mut platforms = image.platforms.clone();
        platforms.sort();
        h.count(platforms.len())?;
        for platform in &platforms {
            h.text(platform)?;
        }
        h.text(image.dockerfile.to_str().ok_or(Failure::Policy)?)?;
        h.text(image.declaration.stage.as_deref().unwrap_or(""))?;
        h.count(image.declaration.args.len())?;
        for (key, value) in &image.declaration.args {
            h.text(key)?;
            h.text(value)?;
        }
        h.count(image.contexts.len())?;
        for context in image.contexts.keys() {
            h.text(context)?;
        }
    }
    Ok(h.finish())
}

pub(crate) fn graph_id(r: &Resolution) -> Result<String> {
    let mut h = Hasher::new(b"broil.image.graph.v1");
    h.text(r.request.environment.as_deref().unwrap_or(""))?;
    h.count(r.request.targets.len())?;
    for target in &r.request.targets {
        h.text(target)?;
    }
    let platforms = r.request.platforms.as_deref().unwrap_or(&[]);
    h.count(platforms.len())?;
    for platform in platforms {
        h.text(platform)?;
    }
    h.text(&r.request.build_platform)?;
    h.text(r.request.staging.name())?;
    h.text(&r.catalog_id)?;
    h.count(r.nodes.len())?;
    for node in &r.nodes {
        h.text(&node.producer)?;
        h.text(&node.platform)?;
        h.text(&node.path)?;
        h.text(&node.snapshot_digest)?;
        h.text(node.resolution_id.as_deref().unwrap_or(""))?;
        h.text(node.state.name())?;
    }
    h.count(r.edges.len())?;
    for edge in &r.edges {
        h.number(edge.source);
        let (kind, ordinal) = target_parts(edge.target);
        h.text(kind)?;
        h.number(ordinal);
        h.text(role_name(edge.role))?;
        h.text(instruction_name(edge.instruction))?;
        h.text(tag_origin_name(edge.tag_origin))?;
        h.location(&edge.location)?;
    }
    h.count(r.external_sources.len())?;
    for source in &r.external_sources {
        h.text(&source.reference)?;
        h.text(&source.platform)?;
        h.descriptor(&source.root)?;
    }
    h.count(r.diagnostics.len())?;
    for diagnostic in &r.diagnostics {
        let (kind, ordinal) = subject_parts(diagnostic.subject);
        h.text(kind)?;
        h.number(ordinal);
        h.text(diagnostic.reason)?;
        h.location(&diagnostic.location)?;
        h.count(diagnostic.cycle.len())?;
        for edge in &diagnostic.cycle {
            h.number(*edge);
        }
    }
    Ok(h.finish())
}

pub(crate) fn canonical(r: &mut Resolution) -> Result<()> {
    r.nodes.sort_by(|a, b| {
        a.producer
            .as_bytes()
            .cmp(b.producer.as_bytes())
            .then_with(|| a.platform.as_bytes().cmp(b.platform.as_bytes()))
    });
    require(
        r.nodes
            .windows(2)
            .all(|w| (&w[0].producer, &w[0].platform) != (&w[1].producer, &w[1].platform)),
        Failure::Integrity,
    )?;
    r.external_sources.sort_by(|a, b| {
        a.reference
            .as_bytes()
            .cmp(b.reference.as_bytes())
            .then_with(|| a.platform.as_bytes().cmp(b.platform.as_bytes()))
    });
    require(
        r.external_sources
            .windows(2)
            .all(|w| (&w[0].reference, &w[0].platform) != (&w[1].reference, &w[1].platform)),
        Failure::Integrity,
    )?;
    r.edges.sort_by(cmp_edge);
    r.edges.dedup();
    r.diagnostics.sort_by(cmp_diagnostic);
    r.diagnostics.dedup();
    Ok(())
}
