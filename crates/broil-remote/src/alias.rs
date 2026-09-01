// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use sha2::{Digest, Sha256};

const TRUST_ALIAS_DOMAIN: &[u8] = b"broil-remote-trust-alias-v1";

pub fn target_alias(root: &Path, environment: &str, name: &str) -> String {
    alias_digest(&[
        b"target",
        root.as_os_str().as_bytes(),
        environment.as_bytes(),
        name.as_bytes(),
    ])
}

pub fn root_jump_alias(root: &Path, name: &str) -> String {
    alias_digest(&[b"jump-root", root.as_os_str().as_bytes(), name.as_bytes()])
}

pub fn env_jump_alias(root: &Path, environment: &str, name: &str) -> String {
    alias_digest(&[
        b"jump-env",
        root.as_os_str().as_bytes(),
        environment.as_bytes(),
        name.as_bytes(),
    ])
}

fn alias_digest(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TRUST_ALIAS_DOMAIN);
    for part in parts {
        hasher.update(b"\0");
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        write!(hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    format!("broil-{hex}")
}
