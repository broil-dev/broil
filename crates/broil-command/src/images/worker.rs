// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Closed protocol-3, one-job filesystem worker. All request strings are public policy.

use super::{buffer::Bytes, common::*, content, files, json::Value, tool_policy::Tool};
use serde_json::{Value as Public, json};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::AsFd,
    path::PathBuf,
};

fn public_text(value: Value<'_>) -> Result<String> {
    let decoded = value.text()?;
    Ok(std::str::from_utf8(decoded.get())
        .map_err(|_| Failure::Protocol)?
        .into())
}

fn path(value: Value<'_>) -> Result<PathBuf> {
    let result = PathBuf::from(public_text(value)?);
    require(valid_path(&result), Failure::Policy)?;
    Ok(result)
}

fn entry(value: Value<'_>) -> Result<Entry> {
    let fields = value.object(&[b"path", b"device", b"inode", b"kind", b"ownership"])?;
    let kind = if fields[3].equals("file")? {
        Kind::File
    } else {
        require(fields[3].equals("directory")?, Failure::Protocol)?;
        Kind::Directory
    };
    let ownership = if fields[4].equals("operation")? {
        Ownership::Operation
    } else if fields[4].equals("borrowed")? {
        Ownership::Borrowed
    } else {
        require(fields[4].equals("retained")?, Failure::Protocol)?;
        Ownership::Retained
    };
    Ok(Entry {
        path: path(fields[0])?,
        device: fields[1].number()?,
        inode: fields[2].number()?,
        kind,
        ownership,
    })
}

fn content(value: Value<'_>) -> Result<Content> {
    if value.field("kind")?.equals("file")? {
        let fields = value.object(&[b"kind", b"digest", b"size"])?;
        Ok(Content::File {
            digest: content::digest_text(fields[1])?,
            size: fields[2].number()?,
        })
    } else {
        let fields = value.object(&[
            b"kind",
            b"root",
            b"content_kind",
            b"completeness",
            b"registry_receipt",
        ])?;
        require(fields[0].equals("oci")?, Failure::Protocol)?;
        let cache = fields[2].equals("cache")?;
        require(cache || fields[2].equals("image")?, Failure::Protocol)?;
        let complete = fields[3].equals("complete")?;
        require(complete || fields[3].equals("metadata")?, Failure::Protocol)?;
        Ok(Content::Oci {
            root: content::descriptor(fields[1], true)?,
            cache,
            complete,
            registry_receipt: fields[4].boolean()?,
        })
    }
}

enum Body {
    Prepare(Entry),
    Slot {
        staging: Entry,
        name: String,
        producer: u64,
        kind: &'static str,
    },
    Produced {
        slot: Entry,
        producer: u64,
        kind: &'static str,
        root: Option<Descriptor>,
        cache: bool,
        complete: bool,
    },
    Copy {
        source: Entry,
        destination: PathBuf,
        tool: Tool,
        digest: String,
        size: u64,
    },
    Inspect {
        entry: Entry,
        content: Content,
        staged: bool,
    },
    Cleanup {
        roots: Vec<Entry>,
        preserve: Vec<Entry>,
    },
}

struct Job {
    operation: String,
    number: u64,
    action: &'static str,
    workspace: Public,
    root: Option<Entry>,
    path: PathBuf,
    end: u64,
    limits: ContentLimits,
    body: Body,
}

impl Job {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let fields = Value::parse(bytes)?.object(&[
            b"protocol_version",
            b"operation_id",
            b"job_id",
            b"action",
            b"workspace",
            b"deadline_ns",
            b"limits",
            b"body",
        ])?;
        require(fields[0].number()? == 3, Failure::Protocol)?;
        let operation = public_text(fields[1])?;
        require(valid_operation(&operation), Failure::Protocol)?;
        let number = fields[2].number()?;
        require(number > 0, Failure::Protocol)?;
        let mut action = None;
        for name in [
            "prepare",
            "prepare-slot",
            "copy-tool",
            "inspect-prepared",
            "verify-staged",
            "verify-produced",
            "cleanup",
        ] {
            if fields[3].equals(name)? {
                action = Some(name);
            }
        }
        let action = action.ok_or(Failure::Protocol)?;
        let root_fields =
            fields[4].object(&[b"path", b"device", b"inode", b"kind", b"ownership"])?;
        let path = path(root_fields[0])?;
        require(
            path.file_name().and_then(|p| p.to_str()) == Some(&operation)
                && root_fields[3].equals("directory")?
                && root_fields[4].equals("operation")?,
            Failure::Policy,
        )?;
        let root = if action == "prepare" {
            require(
                root_fields[1].is_null() && root_fields[2].is_null(),
                Failure::Protocol,
            )?;
            None
        } else {
            Some(entry(fields[4])?)
        };
        let end = fields[5].number()?;
        require(
            end > 0 && end <= deadline(monotonic_ns(), 1_805_000)?,
            Failure::Limit,
        )?;
        let l = fields[6].object(&[
            b"staging_bytes",
            b"entries",
            b"metadata_bytes",
            b"blob_bytes",
            b"content_bytes",
            b"descriptors",
            b"descriptor_edges",
            b"graph_depth",
            b"content_json_depth",
        ])?;
        let limits = ContentLimits {
            staging_bytes: l[0].number()?,
            entries: l[1].number()?,
            metadata_bytes: l[2].number()?,
            blob_bytes: l[3].number()?,
            content_bytes: l[4].number()?,
            descriptors: l[5].number()?,
            descriptor_edges: l[6].number()?,
            graph_depth: l[7].number()?,
            content_json_depth: l[8].number()?,
        };
        limits.validate()?;
        let body = match action {
            "prepare" => {
                let f = fields[7].object(&[b"parent"])?;
                Body::Prepare(entry(f[0])?)
            }
            "prepare-slot" => {
                let f = fields[7].object(&[
                    b"staging",
                    b"slot_name",
                    b"producer_id",
                    b"producer_kind",
                ])?;
                let staging = entry(f[0])?;
                require(
                    staging.kind == Kind::Directory
                        && staging.ownership == Ownership::Operation
                        && staging.path == path.join("staging"),
                    Failure::Policy,
                )?;
                let name = public_text(f[1])?;
                require(valid_slot(&name), Failure::Policy)?;
                let (producer, kind) = producer(f[2], f[3])?;
                Body::Slot {
                    staging,
                    name,
                    producer,
                    kind,
                }
            }
            "verify-produced" => {
                let f =
                    fields[7].object(&[b"slot", b"producer_id", b"producer_kind", b"content"])?;
                let slot = entry(f[0])?;
                require(
                    slot.kind == Kind::Directory
                        && slot.ownership == Ownership::Operation
                        && slot.path.parent() == Some(path.join("staging").as_path())
                        && slot
                            .path
                            .file_name()
                            .and_then(|p| p.to_str())
                            .is_some_and(valid_slot),
                    Failure::Policy,
                )?;
                let (producer, kind) = producer(f[1], f[2])?;
                let c = f[3].object(&[
                    b"kind",
                    b"root",
                    b"content_kind",
                    b"completeness",
                    b"registry_receipt",
                ])?;
                require(c[0].equals("oci")?, Failure::Protocol)?;
                let root = if c[1].is_null() {
                    None
                } else {
                    Some(content::descriptor(c[1], true)?)
                };
                let cache = c[2].equals("cache")?;
                let complete = c[3].equals("complete")?;
                require(
                    (cache || c[2].equals("image")?) && (complete || c[3].equals("metadata")?),
                    Failure::Protocol,
                )?;
                require(
                    if kind == "registry" {
                        root.is_some() && c[4].boolean()? && (!cache || complete)
                    } else {
                        complete && !c[4].boolean()?
                    },
                    Failure::Policy,
                )?;
                Body::Produced {
                    slot,
                    producer,
                    kind,
                    root,
                    cache,
                    complete,
                }
            }
            "copy-tool" => {
                let f =
                    fields[7].object(&[b"source", b"destination", b"tool", b"digest", b"size"])?;
                let tool = Tool::parse(&public_text(f[2])?)?;
                let digest = content::digest_text(f[3])?;
                let size = f[4].number()?;
                require(tool.identity()? == (digest.clone(), size), Failure::Policy)?;
                let destination = path_value(f[1])?;
                require(
                    destination == path.join("tools").join(tool.name()),
                    Failure::Policy,
                )?;
                Body::Copy {
                    source: entry(f[0])?,
                    destination,
                    tool,
                    digest,
                    size,
                }
            }
            "inspect-prepared" | "verify-staged" => {
                let f = fields[7].object(&[b"entry", b"content"])?;
                let entry = entry(f[0])?;
                let staged = action == "verify-staged";
                require(
                    if staged {
                        entry.ownership == Ownership::Operation && entry.path.starts_with(&path)
                    } else {
                        entry.ownership != Ownership::Operation
                    },
                    Failure::Policy,
                )?;
                Body::Inspect {
                    entry,
                    content: content(f[1])?,
                    staged,
                }
            }
            "cleanup" => {
                let f = fields[7].object(&[b"roots", b"preserve"])?;
                let roots = f[0]
                    .array()?
                    .into_iter()
                    .map(entry)
                    .collect::<Result<_>>()?;
                let preserve = f[1]
                    .array()?
                    .into_iter()
                    .map(entry)
                    .collect::<Result<_>>()?;
                Body::Cleanup { roots, preserve }
            }
            _ => return Err(Failure::Protocol),
        };
        let workspace = root.as_ref().map(Entry::wire).unwrap_or_else(|| json!({
            "path":path, "device":null, "inode":null, "kind":"directory", "ownership":"operation",
        }));
        Ok(Self {
            operation,
            number,
            action,
            workspace,
            root,
            path,
            end,
            limits,
            body,
        })
    }

    fn run(&mut self) -> Result<Public> {
        before(self.end)?;
        match &self.body {
            Body::Prepare(parent) => {
                let (root, directories) = files::prepare(parent, &self.path, self.end)?;
                self.workspace = root.wire();
                self.root = Some(root);
                Ok(json!({"directories":directories.iter().map(Entry::wire).collect::<Vec<_>>()}))
            }
            Body::Slot {
                staging,
                name,
                producer,
                kind,
            } => {
                let workspace = self.root.as_ref().ok_or(Failure::Policy)?;
                files::private_directory(workspace)?;
                let staging_fd = files::private_directory(staging)?;
                let (_, slot) = files::mkdir(&staging_fd, &staging.path.join(name))?;
                files::open(workspace, false)?;
                files::open(staging, false)?;
                files::open(&slot, false)?;
                Ok(json!({"slot":slot.wire(), "producer_id":producer, "producer_kind":kind}))
            }
            Body::Produced {
                slot,
                producer,
                kind,
                root,
                cache,
                complete,
            } => {
                let workspace = self.root.as_ref().ok_or(Failure::Policy)?;
                files::private_directory(workspace)?;
                let slot_fd = files::private_directory(slot)?;
                let (_, entry) =
                    files::child(&slot_fd, &slot.path.join("content"), Ownership::Operation)?;
                require(entry.kind == Kind::Directory, Failure::Integrity)?;
                let root = match root {
                    Some(root) => root.clone(),
                    None => {
                        require(*kind == "bake", Failure::Policy)?;
                        content::produced_root(&entry, &self.limits, self.end)?
                    }
                };
                let expected = Content::Oci {
                    root: root.clone(),
                    cache: *cache,
                    complete: *complete,
                    registry_receipt: *kind == "registry",
                };
                let (verified_files, verified_bytes) =
                    content::verify(&entry, &expected, &self.limits, self.end)?;
                files::scan(workspace, &self.limits, self.end, &[])?;
                files::open(workspace, false)?;
                files::open(slot, false)?;
                let (_, current) = files::child(&slot_fd, &entry.path, Ownership::Operation)?;
                require(current == entry, Failure::Integrity)?;
                Ok(
                    json!({"slot":slot.wire(), "producer_id":producer, "producer_kind":kind,
                    "entry":entry.wire(), "verified_files":verified_files, "verified_bytes":verified_bytes,
                    "root":root.wire(), "closure_complete":complete}),
                )
            }
            Body::Copy {
                source,
                destination,
                tool,
                digest,
                size,
            } => {
                require(tool.identity()? == (digest.clone(), *size), Failure::Policy)?;
                let entry = files::copy_tool(
                    self.root.as_ref().ok_or(Failure::Policy)?,
                    source,
                    destination,
                    digest,
                    *size,
                    &self.limits,
                    self.end,
                )?;
                Ok(json!({"entry":entry.wire()}))
            }
            Body::Inspect {
                entry,
                content,
                staged,
            } => {
                let root = self.root.as_ref().ok_or(Failure::Policy)?;
                files::open(root, false)?;
                let (verified_files, verified_bytes) =
                    content::verify(entry, content, &self.limits, self.end)?;
                if *staged {
                    files::scan(root, &self.limits, self.end, &[])?;
                }
                let (root, complete) = match content {
                    Content::File { .. } => (Public::Null, false),
                    Content::Oci { root, complete, .. } => (root.wire(), *complete),
                };
                Ok(
                    json!({"entry":entry.wire(), "verified_files":verified_files,
                    "verified_bytes":verified_bytes, "root":root, "closure_complete":complete}),
                )
            }
            Body::Cleanup { roots, preserve } => {
                let root = self.root.as_ref().ok_or(Failure::Policy)?;
                let removed = files::cleanup(root, roots, preserve, &self.limits, self.end)?;
                Ok(json!({"removed_entries":removed, "preserved_entries":preserve.len()}))
            }
        }
    }

    fn account(&self) -> Result<(u64, u64)> {
        let Some(root) = &self.root else {
            return Ok((0, 0));
        };
        let preserve = if let Body::Cleanup { roots, preserve } = &self.body {
            if roots.contains(root) && !preserve.iter().any(|p| p.path.starts_with(&root.path)) {
                return Ok((0, 0)); // run() observed removal of this exact root.
            }
            preserve.as_slice()
        } else {
            &[]
        };
        let scan = files::scan(root, &self.limits, self.end, preserve)?;
        Ok((scan.bytes, scan.entries))
    }
}

fn path_value(value: Value<'_>) -> Result<PathBuf> {
    path(value)
}

fn valid_slot(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn producer(number: Value<'_>, kind: Value<'_>) -> Result<(u64, &'static str)> {
    let number = number.number()?;
    require(number > 0, Failure::Protocol)?;
    let kind = if kind.equals("registry")? {
        "registry"
    } else {
        require(kind.equals("bake")?, Failure::Protocol)?;
        "bake"
    };
    Ok((number, kind))
}

fn invalid_response() -> Public {
    json!({"protocol_version":3, "operation_id":null, "job_id":null, "action":null,
        "workspace":null, "status":"failed", "failure_class":"protocol", "effects":"none",
        "completion_uncertain":false, "cleanup_uncertain":false, "accounting_complete":true,
        "owned_bytes":0, "owned_entries":0, "result":null})
}

pub(crate) fn run() -> i32 {
    let request = (|| {
        require(std::env::args_os().count() == 1, Failure::Protocol)?;
        let mut input = File::from(
            std::io::stdin()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| Failure::Storage)?,
        );
        let mut prefix = [0u8; 4];
        input
            .read_exact(&mut prefix)
            .map_err(|_| Failure::Protocol)?;
        let length = u32::from_be_bytes(prefix) as usize;
        require(length > 0 && length <= 65_536, Failure::Limit)?;
        let mut bytes = Bytes::new(length)?;
        input
            .read_exact(bytes.get_mut())
            .map_err(|_| Failure::Protocol)?;
        let mut tail = Bytes::new(1)?;
        require(
            input.read(tail.get_mut()).map_err(|_| Failure::Protocol)? == 0,
            Failure::Protocol,
        )?;
        Job::parse(bytes.get())
    })();
    let mut response = invalid_response();
    let mut success = false;
    if let Ok(mut job) = request {
        let result = job.run().and_then(|result| {
            let (bytes, entries) = job.account()?;
            Ok((result, bytes, entries))
        });
        success = result.is_ok();
        let mutates = matches!(
            job.body,
            Body::Prepare(_) | Body::Slot { .. } | Body::Copy { .. } | Body::Cleanup { .. }
        );
        let (result, bytes, entries, failure) = match result {
            Ok((result, bytes, entries)) => (result, bytes, entries, None),
            Err(failure) => (Public::Null, 0, 0, Some(failure)),
        };
        response = json!({"protocol_version":3, "operation_id":job.operation, "job_id":job.number,
            "action":job.action, "workspace":job.workspace, "status":if success {"succeeded"} else {"failed"},
            "failure_class":failure.map(Failure::name).unwrap_or("none"),
            "effects":if !mutates {"none"} else if success {"completed"} else {"possible"},
            "completion_uncertain":!success && mutates, "cleanup_uncertain":!success,
            "accounting_complete":success, "owned_bytes":bytes, "owned_entries":entries, "result":result});
    }
    let written = (|| {
        let bytes = serde_json::to_vec(&response).map_err(|_| Failure::Protocol)?;
        require(bytes.len() <= 65_536, Failure::Limit)?;
        let mut output = File::from(
            std::io::stdout()
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| Failure::Storage)?,
        );
        output
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .map_err(|_| Failure::Storage)?;
        output.write_all(&bytes).map_err(|_| Failure::Storage)?;
        Ok::<_, Failure>(())
    })();
    i32::from(!success || written.is_err())
}

