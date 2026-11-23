// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Refusal, labeled};
use serde_json::Value;

pub const RECORD_LIMIT: usize = 262_144;

const KEYS: [&str; 16] = [
    "application",
    "content_sha256",
    "created_ms",
    "health_timeout_ms",
    "hooks",
    "images",
    "kind",
    "manifests",
    "namespace",
    "owner",
    "policy",
    "release",
    "schema",
    "scope",
    "secrets",
    "target",
];
const IMAGE_KEYS: [&str; 8] = [
    "artifact",
    "image",
    "managed",
    "origin",
    "platforms",
    "reference",
    "repository",
    "root",
];
const MANIFEST_KEYS: [&str; 6] = [
    "bytes",
    "files",
    "objects",
    "render_hook",
    "sha256",
    "source",
];
const OBJECT_KEYS: [&str; 4] = ["api_version", "kind", "name", "namespace"];
const SECRET_KEYS: [&str; 2] = ["keys", "secret"];
const SECRET_KEY_KEYS: [&str; 4] = ["data_key", "key", "set", "version"];
const HOOK_KEYS: [&str; 8] = [
    "argv",
    "location",
    "name",
    "repeatable",
    "secrets",
    "sha256",
    "stage",
    "timeout_ms",
];
const HOOK_SECRET_KEYS: [&str; 4] = ["key", "set", "variable", "version"];
const POLICY_KEYS: [&str; 3] = ["members", "nodes", "platforms"];
const TARGET_KEYS: [&str; 2] = ["cluster", "owner"];
const CLUSTER_KEYS: [&str; 2] = ["ca_sha256", "uid"];
const SCOPE_KEYS: [&str; 4] = ["environment", "hash", "project", "target"];
const PLATFORM_KEYS: [&str; 2] = ["manifest", "platform"];

fn invalid(detail: &str) -> Refusal {
    Refusal::new("integrity", "release", format!("release record: {detail}"))
}

fn exact(value: &Value, keys: &[&str], what: &str) -> Result<(), Refusal> {
    let fields = value
        .as_object()
        .ok_or_else(|| invalid(&format!("{what} is not an object")))?;
    if fields.len() != keys.len() || keys.iter().any(|key| !fields.contains_key(*key)) {
        return Err(invalid(&format!("{what} does not hold exactly its fields")));
    }
    Ok(())
}

fn each(value: &Value, keys: &[&str], what: &str) -> Result<(), Refusal> {
    value
        .as_array()
        .ok_or_else(|| invalid(&format!("{what} is not a list")))?
        .iter()
        .try_for_each(|item| exact(item, keys, what))
}

fn string(value: &Value, what: &str) -> Result<(), Refusal> {
    value
        .is_string()
        .then_some(())
        .ok_or_else(|| invalid(&format!("{what} is not a string")))
}

pub fn check(record: &Value) -> Result<(), Refusal> {
    exact(record, &KEYS, "record")?;
    if record["schema"] != 1 || record["kind"] != "release" {
        return Err(invalid("schema or kind"));
    }
    for key in ["application", "namespace", "owner", "content_sha256"] {
        string(&record[key], key)?;
    }
    let id = record["release"].as_str().unwrap_or("");
    let nonce = id.strip_prefix("release-").unwrap_or("");
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid("release is not a release ID"));
    }
    for key in ["created_ms", "health_timeout_ms"] {
        if !record[key].is_u64() {
            return Err(invalid(&format!("{key} is not a time")));
        }
    }
    exact(&record["scope"], &SCOPE_KEYS, "scope")?;
    exact(&record["target"], &TARGET_KEYS, "target")?;
    exact(
        &record["target"]["cluster"],
        &CLUSTER_KEYS,
        "target.cluster",
    )?;
    each(&record["images"], &IMAGE_KEYS, "images")?;
    for image in record["images"].as_array().into_iter().flatten() {
        each(&image["platforms"], &PLATFORM_KEYS, "images.platforms")?;
    }
    exact(&record["manifests"], &MANIFEST_KEYS, "manifests")?;
    each(
        &record["manifests"]["objects"],
        &OBJECT_KEYS,
        "manifests.objects",
    )?;
    if !record["manifests"]["bytes"].is_u64() {
        return Err(invalid("manifests.bytes is not a length"));
    }
    string(&record["manifests"]["sha256"], "manifests.sha256")?;
    each(&record["secrets"], &SECRET_KEYS, "secrets")?;
    for secret in record["secrets"].as_array().into_iter().flatten() {
        each(&secret["keys"], &SECRET_KEY_KEYS, "secrets.keys")?;
    }
    each(&record["hooks"], &HOOK_KEYS, "hooks")?;
    for hook in record["hooks"].as_array().into_iter().flatten() {
        each(&hook["secrets"], &HOOK_SECRET_KEYS, "hooks.secrets")?;
    }
    exact(&record["policy"], &POLICY_KEYS, "policy")?;
    Ok(())
}

pub fn encode(record: &Value) -> Result<Vec<u8>, Refusal> {
    check(record)?;
    let mut bytes = serde_json::to_vec(record).expect("JSON values encode");
    bytes.push(b'\n');
    if bytes.len() > RECORD_LIMIT {
        return Err(Refusal::new(
            "bound",
            "size",
            format!(
                "the release record is {} bytes; the limit is {RECORD_LIMIT}",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Value, Refusal> {
    if bytes.len() > RECORD_LIMIT {
        return Err(invalid("over 262144 bytes"));
    }
    let body = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| invalid("no final line feed"))?;
    let record: Value = serde_json::from_slice(body).map_err(|_| invalid("not one JSON value"))?;
    if serde_json::to_vec(&record).expect("JSON values encode") != body {
        return Err(invalid("not in canonical form"));
    }
    check(&record)?;
    Ok(record)
}

pub fn content_sha256(record: &Value) -> String {
    let mut content = record.clone();
    if let Some(fields) = content.as_object_mut() {
        for key in ["release", "created_ms", "content_sha256"] {
            fields.remove(key);
        }
    }
    labeled("broil-k3s-release-content-v1", &content)
}

pub fn release_sha256(record: &Value) -> String {
    labeled("broil-k3s-release-v1", record)
}
