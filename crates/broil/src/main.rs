// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    broil_cli::run()
}
