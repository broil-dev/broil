// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::images::builders;

pub(super) fn class(outcome: &builders::Outcome, verb: Verb) -> Option<FailureClass> {
    if let Err(failure) = outcome.result {
        return Some(FailureClass::of(failure));
    }
    if let Some(endpoint) = &outcome.endpoint {
        if let Err(error) = &endpoint.result {
            return Some(FailureClass::of(error.failure));
        }
    } else if matches!(verb, Verb::BuilderAccess | Verb::BuilderInspect) {
        return Some(FailureClass::of(Failure::Protocol));
    }
    if let Some(failure) = outcome.steps.iter().find_map(|step| step.local_failure) {
        return Some(FailureClass::of(failure));
    }
    outcome
        .ownership_uncertain
        .then_some(FailureClass::Indeterminate)
}
pub(super) fn run(
    project: &LoadedProject,
    invocation: Invocation,
    inputs: Inputs<'_>,
    cancellation: Cancellation,
) -> Result<Output> {
    let verb = invocation.verb;
    let policy = policy(project, verb, &inputs, &cancellation)?;
    let action = match verb {
        Verb::BuilderAccess => builders::Action::Access,
        Verb::BuilderInspect => builders::Action::Inspect,
        Verb::BuilderSetup => builders::Action::Setup {
            archive: invocation
                .archive
                .clone()
                .ok_or_else(|| Error::failure(verb, Failure::Policy))?,
            arm64_emulation: invocation.arm64_emulation,
        },
        Verb::BuilderReconcile => builders::Action::Reconcile {
            archive: invocation
                .archive
                .clone()
                .ok_or_else(|| Error::failure(verb, Failure::Policy))?,
            arm64_emulation: invocation.arm64_emulation,
        },
        Verb::BuilderRemove => builders::Action::Remove {
            purge: invocation.purge,
        },
        _ => return Err(Error::failure(verb, Failure::Policy)),
    };
    let selection = builders::Selection {
        builder: invocation
            .builder
            .clone()
            .ok_or_else(|| Error::failure(verb, Failure::Policy))?,
        stage: verb
            .name()
            .strip_prefix("builder ")
            .expect("builder verb")
            .into(),
        protected_parent: "/dev/shm".into(),
        action,
    };
    let environment = inputs.env_snapshot;
    let outcome = builders::prepare(project, policy, selection)
        .map_err(|f| Error::failure(verb, f))?
        .run(
            inputs.consumer(invocation.non_interactive),
            environment,
            cancellation,
        )
        .map_err(|f| Error::failure(verb, f))?;
    output(
        &invocation,
        render::builder(&outcome),
        class(&outcome, verb),
        None,
    )
}
