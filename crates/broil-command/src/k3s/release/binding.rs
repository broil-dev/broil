// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::Refusal;
use saphyr_parser::{Event, Marker, Parser, ScalarStyle};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const PREFIX: &str = "broil-image://";
pub const MANIFEST_LIMIT: usize = 4_194_304;
pub const OBJECT_LIMIT: usize = 512;
pub const IMAGE_LIMIT: usize = 32;
const DEPTH_LIMIT: usize = 128;

const CLUSTER_SCOPED: [(&str, &str); 23] = [
    ("", "Namespace"),
    ("", "Node"),
    ("", "PersistentVolume"),
    ("", "ComponentStatus"),
    ("rbac.authorization.k8s.io", "ClusterRole"),
    ("rbac.authorization.k8s.io", "ClusterRoleBinding"),
    ("storage.k8s.io", "StorageClass"),
    ("storage.k8s.io", "CSIDriver"),
    ("storage.k8s.io", "CSINode"),
    ("storage.k8s.io", "VolumeAttachment"),
    ("apiextensions.k8s.io", "CustomResourceDefinition"),
    ("apiregistration.k8s.io", "APIService"),
    (
        "admissionregistration.k8s.io",
        "MutatingWebhookConfiguration",
    ),
    (
        "admissionregistration.k8s.io",
        "ValidatingWebhookConfiguration",
    ),
    ("admissionregistration.k8s.io", "ValidatingAdmissionPolicy"),
    (
        "admissionregistration.k8s.io",
        "ValidatingAdmissionPolicyBinding",
    ),
    ("scheduling.k8s.io", "PriorityClass"),
    ("node.k8s.io", "RuntimeClass"),
    ("networking.k8s.io", "IngressClass"),
    ("flowcontrol.apiserver.k8s.io", "FlowSchema"),
    ("flowcontrol.apiserver.k8s.io", "PriorityLevelConfiguration"),
    ("certificates.k8s.io", "CertificateSigningRequest"),
    ("cert-manager.io", "ClusterIssuer"),
];

const POD_SPECS: [(&str, &str, &[&str]); 7] = [
    ("v1", "Pod", &["spec"]),
    ("apps/v1", "Deployment", &["spec", "template", "spec"]),
    ("apps/v1", "StatefulSet", &["spec", "template", "spec"]),
    ("apps/v1", "DaemonSet", &["spec", "template", "spec"]),
    ("apps/v1", "ReplicaSet", &["spec", "template", "spec"]),
    ("batch/v1", "Job", &["spec", "template", "spec"]),
    (
        "batch/v1",
        "CronJob",
        &["spec", "jobTemplate", "spec", "template", "spec"],
    ),
];

const CONTAINER_LISTS: [&str; 3] = ["containers", "initContainers", "ephemeralContainers"];

#[derive(Debug, Clone, PartialEq)]
pub struct Scan {
    pub images: Vec<String>,
    pub objects: Vec<Value>,
}

enum Kind {
    Scalar(String, ScalarStyle),
    Sequence(Vec<Node>),
    Mapping(Vec<(Node, Node)>),
    Alias,
}

struct Node {
    kind: Kind,
    decorated: bool,
    start: usize,
    end: usize,
}

impl Node {
    fn get(&self, key: &str) -> Option<&Node> {
        match &self.kind {
            Kind::Mapping(entries) => entries
                .iter()
                .find(|(k, _)| matches!(&k.kind, Kind::Scalar(v, _) if v == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    fn path(&self, keys: &[&str]) -> Option<&Node> {
        keys.iter().try_fold(self, |node, key| node.get(key))
    }

    fn string(&self) -> Option<&str> {
        match &self.kind {
            Kind::Scalar(value, ScalarStyle::Plain) if !plain_non_string(value) => Some(value),
            Kind::Scalar(_, ScalarStyle::Plain) => None,
            Kind::Scalar(value, _) => Some(value),
            _ => None,
        }
    }

    fn is_null(&self) -> bool {
        matches!(&self.kind, Kind::Scalar(v, ScalarStyle::Plain)
            if matches!(v.as_str(), "" | "~" | "null" | "Null" | "NULL"))
    }

    fn reference(&self) -> Option<&str> {
        match &self.kind {
            Kind::Scalar(value, ScalarStyle::Literal | ScalarStyle::Folded) => {
                Some(value.trim_end_matches('\n'))
            }
            Kind::Scalar(value, _) => Some(value),
            _ => None,
        }
    }

    fn render(&self) -> String {
        match &self.kind {
            Kind::Scalar(value, _) => value.clone(),
            Kind::Sequence(items) => {
                let items: Vec<String> = items.iter().map(Node::render).collect();
                format!("[{}]", items.join(", "))
            }
            Kind::Mapping(entries) => {
                let entries: Vec<String> = entries
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k.render(), v.render()))
                    .collect();
                format!("{{{}}}", entries.join(", "))
            }
            Kind::Alias => "*".to_owned(),
        }
    }

    fn scalars<'a>(&'a self, out: &mut Vec<&'a Node>) {
        match &self.kind {
            Kind::Scalar(..) => out.push(self),
            Kind::Sequence(items) => items.iter().for_each(|item| item.scalars(out)),
            Kind::Mapping(entries) => entries.iter().for_each(|(k, v)| {
                k.scalars(out);
                v.scalars(out);
            }),
            Kind::Alias => {}
        }
    }
}

fn plain_non_string(value: &str) -> bool {
    if matches!(
        value,
        "" | "~"
            | "null"
            | "Null"
            | "NULL"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | ".inf"
            | ".Inf"
            | ".INF"
            | "+.inf"
            | "+.Inf"
            | "+.INF"
            | "-.inf"
            | "-.Inf"
            | "-.INF"
            | ".nan"
            | ".NaN"
            | ".NAN"
    ) {
        return true;
    }
    let digits = |s: &str, radix: u32| !s.is_empty() && s.chars().all(|c| c.is_digit(radix));
    if let Some(rest) = value.strip_prefix("0o") {
        return digits(rest, 8);
    }
    if let Some(rest) = value.strip_prefix("0x") {
        return digits(rest, 16);
    }
    let unsigned = value.strip_prefix(['-', '+']).unwrap_or(value);
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(at) => (&unsigned[..at], Some(&unsigned[at + 1..])),
        None => (unsigned, None),
    };
    let mantissa_ok = match mantissa.split_once('.') {
        Some((whole, fraction)) => {
            (whole.is_empty() || digits(whole, 10))
                && (fraction.is_empty() || digits(fraction, 10))
                && !(whole.is_empty() && fraction.is_empty())
        }
        None => digits(mantissa, 10),
    };
    let exponent_ok = exponent.is_none_or(|e| digits(e.strip_prefix(['-', '+']).unwrap_or(e), 10));
    mantissa_ok && exponent_ok
}

fn manifest(document: usize, reason: impl std::fmt::Display) -> Refusal {
    Refusal::new(
        "configuration",
        "manifest",
        format!("document {document}: {reason}"),
    )
}

struct Located<'a> {
    event: Event<'a>,
    start: usize,
    end: usize,
}

struct Stream<'a> {
    source: &'a str,
    documents: Vec<(usize, Node)>,
}

fn parse(input: &[u8]) -> Result<Stream<'_>, Refusal> {
    if input.len() > MANIFEST_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!(
                "manifests are {} bytes; the limit is {MANIFEST_LIMIT}",
                input.len()
            ),
        ));
    }
    let source = std::str::from_utf8(input)
        .map_err(|_| Refusal::new("configuration", "manifest", "manifests are not valid UTF-8"))?;
    let offsets: Option<Vec<usize>> = (!source.is_ascii()).then(|| {
        let mut offsets: Vec<usize> = source.char_indices().map(|(offset, _)| offset).collect();
        offsets.push(source.len());
        offsets
    });
    let offset = |marker: &Marker| match &offsets {
        None => marker.index().min(source.len()),
        Some(table) => table.get(marker.index()).copied().unwrap_or(source.len()),
    };
    let mut events = Vec::new();
    let mut document = 0;
    let mut depth = 0usize;
    for event in Parser::new_from_str(source) {
        let (event, span) = event.map_err(|error| {
            manifest(
                document.max(1),
                format_args!("invalid YAML at line {}", error.marker().line()),
            )
        })?;
        match &event {
            Event::DocumentStart(_) => document += 1,
            Event::MappingStart(..) | Event::SequenceStart(..) => {
                depth += 1;
                if depth > DEPTH_LIMIT {
                    return Err(manifest(
                        document,
                        format_args!("nesting exceeds {DEPTH_LIMIT} levels"),
                    ));
                }
            }
            Event::MappingEnd | Event::SequenceEnd => depth = depth.saturating_sub(1),
            _ => {}
        }
        events.push(Located {
            start: offset(&span.start),
            end: offset(&span.end),
            event,
        });
    }
    let mut reader = Reader {
        events: events.into_iter(),
        document: 0,
    };
    let mut documents = Vec::new();
    while let Some(located) = reader.events.next() {
        match located.event {
            Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart(_) => {
                reader.document += 1;
                let root = reader.node()?;
                documents.push((reader.document, root));
            }
            _ => return Err(manifest(reader.document.max(1), "invalid YAML stream")),
        }
    }
    Ok(Stream { source, documents })
}

struct Reader<'a> {
    events: std::vec::IntoIter<Located<'a>>,
    document: usize,
}

impl Reader<'_> {
    fn node(&mut self) -> Result<Node, Refusal> {
        let invalid = |document| manifest(document, "invalid YAML structure");
        let Located { event, start, end } = self.events.next().ok_or(invalid(self.document))?;
        let decorated = |anchor: usize, tag: bool| anchor != 0 || tag;
        let kind_decorated = match event {
            Event::Scalar(value, style, anchor, tag) => (
                Kind::Scalar(value.to_string(), style),
                decorated(anchor, tag.is_some()),
            ),
            Event::Alias(_) => (Kind::Alias, true),
            Event::SequenceStart(anchor, tag) => {
                let mut items = Vec::new();
                loop {
                    if matches!(
                        self.events.as_slice().first().map(|l| &l.event),
                        Some(Event::SequenceEnd)
                    ) {
                        self.events.next();
                        break;
                    }
                    items.push(self.node()?);
                }
                (Kind::Sequence(items), decorated(anchor, tag.is_some()))
            }
            Event::MappingStart(anchor, tag) => {
                let mut entries: Vec<(Node, Node)> = Vec::new();
                let mut keys = BTreeSet::new();
                loop {
                    if matches!(
                        self.events.as_slice().first().map(|l| &l.event),
                        Some(Event::MappingEnd)
                    ) {
                        self.events.next();
                        break;
                    }
                    let key = self.node()?;
                    let value = self.node()?;
                    let rendered = key.render();
                    if !keys.insert(rendered.clone()) {
                        let shown: String = rendered.chars().take(64).collect();
                        return Err(manifest(
                            self.document,
                            format_args!("duplicate key {shown}"),
                        ));
                    }
                    entries.push((key, value));
                }
                (Kind::Mapping(entries), decorated(anchor, tag.is_some()))
            }
            _ => return Err(invalid(self.document)),
        };
        Ok(Node {
            kind: kind_decorated.0,
            decorated: kind_decorated.1,
            start,
            end,
        })
    }
}

fn bindings(root: &Node) -> Vec<(&Node, &Node)> {
    let (Some(api_version), Some(kind)) = (
        root.get("apiVersion").and_then(Node::string),
        root.get("kind").and_then(Node::string),
    ) else {
        return Vec::new();
    };
    let Some((_, _, path)) = POD_SPECS
        .iter()
        .find(|(a, k, _)| *a == api_version && *k == kind)
    else {
        return Vec::new();
    };
    let Some(Node {
        kind: Kind::Mapping(entries),
        ..
    }) = root.path(path)
    else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (key, list) in entries {
        let named =
            matches!(&key.kind, Kind::Scalar(k, _) if CONTAINER_LISTS.contains(&k.as_str()));
        let Kind::Sequence(containers) = &list.kind else {
            continue;
        };
        if !named {
            continue;
        }
        for container in containers {
            if let Some(image) = container
                .get("image")
                .filter(|image| image.reference().is_some_and(|r| r.starts_with(PREFIX)))
            {
                found.push((image, container));
            }
        }
    }
    found
}

fn mention(text: &str) -> String {
    let at = text.find(PREFIX).unwrap_or(0);
    text[at..]
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, ',' | ']' | '}' | '"' | '\''))
        .take(PREFIX.len() + 128)
        .collect()
}

pub fn scan(input: &[u8], namespace: &str, catalog: &BTreeSet<String>) -> Result<Scan, Refusal> {
    scan_application(input, namespace, namespace, catalog)
}

pub fn scan_application(
    input: &[u8],
    application: &str,
    namespace: &str,
    catalog: &BTreeSet<String>,
) -> Result<Scan, Refusal> {
    let stream = parse(input)?;
    let mut images: Vec<String> = Vec::new();
    let mut objects = Vec::new();
    let mut identities = BTreeSet::new();
    for (document, root) in &stream.documents {
        let document = *document;
        if root.is_null() {
            continue;
        }
        if !matches!(root.kind, Kind::Mapping(_)) {
            return Err(manifest(document, "is not a Kubernetes object mapping"));
        }
        let api_version = root
            .get("apiVersion")
            .and_then(Node::string)
            .ok_or_else(|| manifest(document, "apiVersion must be a string"))?;
        let kind = root
            .get("kind")
            .and_then(Node::string)
            .ok_or_else(|| manifest(document, "kind must be a string"))?;
        let metadata = root
            .get("metadata")
            .filter(|m| matches!(m.kind, Kind::Mapping(_)))
            .ok_or_else(|| manifest(document, "metadata must be a mapping"))?;
        let name = metadata
            .get("name")
            .and_then(Node::string)
            .ok_or_else(|| manifest(document, "metadata.name must be a string"))?;
        let declared = match metadata.get("namespace") {
            None => None,
            Some(node) => Some(
                node.string()
                    .ok_or_else(|| manifest(document, "metadata.namespace must be a string"))?,
            ),
        };
        let group = api_version.split_once('/').map_or("", |(group, _)| group);
        if group.is_empty() && kind == "Secret" {
            return Err(Refusal::new(
                "configuration",
                "secret-kind",
                format!(
                    "document {document} is a Secret; declare it under applications.{application}.secrets"
                ),
            ));
        }
        if kind.ends_with("List") {
            return Err(manifest(
                document,
                format_args!("{kind} is a list kind; write its items as separate documents"),
            ));
        }
        let own_namespace = group.is_empty() && kind == "Namespace" && name == namespace;
        if !own_namespace && CLUSTER_SCOPED.contains(&(group, kind)) {
            return Err(Refusal::new(
                "configuration",
                "cluster-scoped",
                format!(
                    "{kind} {name} is cluster-scoped; apply it outside Broil, only Namespace {namespace} may be cluster-scoped"
                ),
            ));
        }
        let resolved = if own_namespace {
            if declared.is_some() {
                return Err(manifest(
                    document,
                    format_args!("Namespace {namespace} must not set metadata.namespace"),
                ));
            }
            None
        } else {
            match declared {
                Some(other) if other != namespace => {
                    return Err(manifest(
                        document,
                        format_args!(
                            "{kind} {name} is in namespace {other}; only namespace {namespace} is admitted"
                        ),
                    ));
                }
                _ => Some(namespace),
            }
        };
        if !identities.insert((
            group.to_owned(),
            kind.to_owned(),
            resolved.map(str::to_owned),
            name.to_owned(),
        )) {
            let subject = match resolved {
                Some(ns) => format!("{kind} {ns}/{name}"),
                None => format!("{kind} {name}"),
            };
            return Err(Refusal::new(
                "configuration",
                "duplicate",
                format!("{subject} is declared twice"),
            ));
        }
        if objects.len() == OBJECT_LIMIT {
            return Err(Refusal::new(
                "bound",
                "size",
                format!(
                    "manifests hold more than {OBJECT_LIMIT} objects; the limit is {OBJECT_LIMIT}"
                ),
            ));
        }
        objects.push(
            json!({"api_version": api_version, "kind": kind, "namespace": resolved, "name": name}),
        );

        let bound = bindings(root);
        for (image, container) in &bound {
            let reference = image.reference().expect("a binding is a scalar");
            if image.decorated {
                return Err(Refusal::new(
                    "configuration",
                    "binding",
                    format!(
                        "document {document}: {} carries a YAML anchor, alias or tag; write it as a plain value",
                        mention(reference)
                    ),
                ));
            }
            let image_name = &reference[PREFIX.len()..];
            if !catalog.contains(image_name) {
                return Err(Refusal::new(
                    "configuration",
                    "binding",
                    format!("{reference} is not in the image catalog"),
                ));
            }
            if container.get("imagePullPolicy").and_then(Node::string) == Some("Always") {
                let container_name = container
                    .get("name")
                    .and_then(Node::string)
                    .unwrap_or("<unnamed>");
                return Err(Refusal::new(
                    "configuration",
                    "pull-policy",
                    format!(
                        "container {container_name} sets imagePullPolicy Always with a broil-image reference; use IfNotPresent"
                    ),
                ));
            }
            if !images.iter().any(|known| known == image_name) {
                if images.len() == IMAGE_LIMIT {
                    return Err(Refusal::new(
                        "bound",
                        "size",
                        format!(
                            "manifests reference more than {IMAGE_LIMIT} images; the limit is {IMAGE_LIMIT}"
                        ),
                    ));
                }
                images.push(image_name.to_owned());
            }
        }
        let mut scalars = Vec::new();
        root.scalars(&mut scalars);
        for scalar in scalars {
            let Kind::Scalar(value, _) = &scalar.kind else {
                continue;
            };
            if value.contains(PREFIX) && !bound.iter().any(|(b, _)| std::ptr::eq(*b, scalar)) {
                return Err(Refusal::new(
                    "configuration",
                    "binding",
                    format!(
                        "document {document}: {} is not a container image; use it only as a container image value",
                        mention(value)
                    ),
                ));
            }
        }
    }
    Ok(Scan { images, objects })
}

fn node_span(source: &str, node: &Node) -> Option<(usize, usize)> {
    let Kind::Scalar(value, style) = &node.kind else {
        return None;
    };
    let bytes = source.as_bytes();
    match style {
        ScalarStyle::Plain => source[node.start..]
            .starts_with(value.as_str())
            .then_some((node.start, node.start + value.len())),
        ScalarStyle::SingleQuoted | ScalarStyle::DoubleQuoted => {
            let single = *style == ScalarStyle::SingleQuoted;
            let quote = if single { b'\'' } else { b'"' };
            if bytes.get(node.start) != Some(&quote) {
                return None;
            }
            let mut i = node.start + 1;
            while i < bytes.len() {
                if bytes[i] == quote {
                    if single && bytes.get(i + 1) == Some(&quote) {
                        i += 2;
                    } else {
                        return Some((node.start, i + 1));
                    }
                } else if !single && bytes[i] == b'\\' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            None
        }
        ScalarStyle::Literal | ScalarStyle::Folded => block_span(source, node),
    }
}

fn block_span(source: &str, node: &Node) -> Option<(usize, usize)> {
    let content_line = source[..node.start].rfind('\n').map_or(0, |n| n + 1);
    let mut header_end = content_line.checked_sub(1)?;
    loop {
        let header_start = source[..header_end].rfind('\n').map_or(0, |n| n + 1);
        if !source[header_start..header_end].trim().is_empty() {
            break;
        }
        header_end = header_start.checked_sub(1)?;
    }
    let header_start = source[..header_end].rfind('\n').map_or(0, |n| n + 1);
    let line = &source[header_start..header_end];
    let uncommented = line
        .char_indices()
        .find(|&(i, c)| c == '#' && line[..i].ends_with([' ', '\t']))
        .map_or(line, |(i, _)| &line[..i])
        .trim_end();
    let indicator = uncommented.rfind([' ', '\t']).map_or(0, |n| n + 1);
    let header = &uncommented[indicator..];
    if !header.starts_with(['|', '>']) {
        return None;
    }
    let start = header_start + indicator;
    let explicit = header.chars().any(|c| c.is_ascii_digit());
    let required = node.start - content_line;
    let mut end = None;
    let mut at = content_line;
    while at < source.len() {
        let line_end = source[at..].find('\n').map_or(source.len(), |n| at + n);
        let line = &source[at..line_end];
        if !line.trim().is_empty() {
            let spaces = line.len() - line.trim_start_matches(' ').len();
            if (explicit && at >= node.end && end.is_some()) || (!explicit && spaces < required) {
                break;
            }
            end = Some(line_end);
        }
        at = line_end + 1;
    }
    Some((start, end?))
}

pub fn substitute(input: &[u8], references: &BTreeMap<String, String>) -> Result<Vec<u8>, Refusal> {
    let stream = parse(input)?;
    let mut spans = Vec::new();
    for (document, root) in &stream.documents {
        for (image, _) in bindings(root) {
            let reference = image.reference().expect("a binding is a scalar");
            let name = &reference[PREFIX.len()..];
            let bound = references
                .get(name)
                .filter(|_| !image.decorated)
                .ok_or_else(|| {
                    Refusal::new(
                        "integrity",
                        "binding",
                        format!(
                            "document {document}: {} has no bound image",
                            mention(reference)
                        ),
                    )
                })?;
            let (start, end) = node_span(stream.source, image).ok_or_else(|| {
                Refusal::new(
                    "integrity",
                    "binding",
                    format!(
                        "document {document}: {} has no source span",
                        mention(reference)
                    ),
                )
            })?;
            spans.push((start, end, bound));
        }
    }
    spans.sort_by_key(|(start, ..)| *start);
    let source = stream.source;
    let mut output = Vec::with_capacity(source.len());
    let mut at = 0;
    for (start, end, bound) in spans {
        if start < at {
            return Err(Refusal::new(
                "integrity",
                "binding",
                "overlapping binding spans",
            ));
        }
        output.extend_from_slice(&source.as_bytes()[at..start]);
        output.extend_from_slice(
            serde_json::to_string(bound)
                .expect("strings encode")
                .as_bytes(),
        );
        at = end;
    }
    output.extend_from_slice(&source.as_bytes()[at..]);
    Ok(output)
}
