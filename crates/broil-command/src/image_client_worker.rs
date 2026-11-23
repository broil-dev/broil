// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! One-job support executable. It does not link the controller's compatibility identity.
#![forbid(unsafe_code)]

// Shared types have additional controller-only methods. Keeping these modules
// directly in this binary makes its build independent of its own recorded hash.
#[path = "images/buffer.rs"]
mod buffer;
#[allow(dead_code)]
#[path = "images/common.rs"]
mod common;
#[path = "images/content.rs"]
mod content;
#[path = "images/files.rs"]
mod files;
#[allow(dead_code)]
#[path = "images/json.rs"]
mod json;
#[path = "images/tool_policy.rs"]
mod tool_policy;
#[path = "images/worker.rs"]
mod worker;

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(worker::run() as u8)
}
