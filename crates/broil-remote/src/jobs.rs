// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use broil_core::remote::Parallelism;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedJobs {
    Limit(usize),
    All,
}

pub(crate) fn resolve_jobs(
    requested: Option<RequestedJobs>,
    configured: &Parallelism,
    selected: usize,
) -> usize {
    match requested {
        Some(RequestedJobs::Limit(limit)) => limit,
        Some(RequestedJobs::All) => selected.max(1),
        None => match configured {
            Parallelism::Limit(limit) => *limit,
            Parallelism::All => selected.max(1),
        },
    }
}

