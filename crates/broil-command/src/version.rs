// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub fn render() -> Vec<u8> {
    format!("broil version {}\n", env!("CARGO_PKG_VERSION")).into_bytes()
}
