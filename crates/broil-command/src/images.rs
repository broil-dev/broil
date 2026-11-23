// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub mod analysis;
mod buffer;
pub mod builders;
mod client;
pub mod commands;
mod common;
pub mod consumers;
#[allow(dead_code)]
mod content;
#[allow(dead_code)]
mod files;
pub mod graph;
mod json;
mod outputs;
mod policy;
mod progress;
mod protected;
pub mod publish;
mod receipt;
pub mod records;
pub mod solve;
mod store;
mod supervise;
mod tool_policy;

pub(crate) mod infrastructure_io {
    pub(crate) mod json {
        pub(crate) use super::super::json::Value;
    }
    pub(crate) mod store {
        pub(crate) use super::super::store::*;
    }
    pub(crate) use super::supervise::{
        Active, Clock, Permit, PublicAction, access_local, public_local,
    };
}

pub use client::{
    BuilderCapabilities, Cancellation, Dispatch, Kept, Observation, Operation, RegistryOutcome,
    ReleaseToken, StageError, VerifiedOutput,
};
pub use common::{Content, ContentLimits, Descriptor, Entry, Failure, Kind, Limits, Ownership};
pub use outputs::{
    Handoff, Loaded, NotExported, OutputCheck, Retained, TargetOutcome, TargetReport, Unpublished,
};
pub use policy::{
    BuilderPolicy, Policy, Preflight, RegistryAction, RegistryAuth, RegistryRequest, preflight,
};
pub use publish::{
    ClosureMember, NotPublished, PublicationCheck, PublicationClass, PublicationObservation,
    PublicationOutcome, PublicationRelease, PublicationReport, Residue, RetainedArtifact,
    ServerIdentity, StagingDelta, StandaloneSource, TagAssociation, Unproved,
};
pub use tool_policy::Tool;

