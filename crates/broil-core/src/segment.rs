// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Alias path segment validity, shared by config
//! validation and executable command eligibility.

/// A valid alias path segment: a non-empty string that contains no `.`
/// and does not begin with `-`. Digit-leading names such as `2test` are
/// valid.
///
/// Deliberately disposition-free: config validation maps a failure to a
/// config validation error, while executable command lookup silently
/// ignores the candidate. Callers own that choice, and the executable
/// side's `OsStr` → `str` decode (its non-UTF-8 gate) stays outside
/// this helper.
pub fn is_valid_alias_path_segment(segment: &str) -> bool {
    !segment.is_empty() && !segment.contains('.') && !segment.starts_with('-')
}
