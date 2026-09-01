// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub fn is_valid_alias_path_segment(segment: &str) -> bool {
    !segment.is_empty() && !segment.contains('.') && !segment.starts_with('-')
}
