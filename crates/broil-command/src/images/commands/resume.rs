// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use super::*;

pub(super) fn run(
    project: &LoadedProject,
    invocation: Invocation,
    cancellation: Cancellation,
) -> Result<Output> {
    let verb = invocation.verb;
    let id = invocation
        .operation
        .clone()
        .ok_or_else(|| Error::failure(verb, Failure::Policy))?;
    let (resumed, decision) = step(
        &project.broil_root,
        verb,
        &cancellation,
        move |root, active| {
            operation(root, &id, verb, active)?;
            let now = records::now_utc();
            let resumed = records::resume(root, &id, &now, active)
                .map_err(|f| Error::failure(verb, f.into()))?;
            let journal = records::Journal::open(root, &id, false, active)
                .map_err(|f| Error::failure(verb, f))?;
            let observations = journal
                .observations(active)
                .map_err(|f| Error::failure(verb, f.into()))?;
            let decision = records::requires_explicit_decision(&observations);
            Ok((resumed, decision))
        },
    )?;
    output(
        &invocation,
        render::resumed(&resumed, decision),
        decision.then_some(FailureClass::Indeterminate),
        decision.then(|| "image resume decision required".into()),
    )
}
