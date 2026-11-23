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
    let artifact = invocation
        .artifact
        .clone()
        .ok_or_else(|| Error::failure(verb, Failure::Policy))?;
    let seq = invocation
        .ambiguity
        .ok_or_else(|| Error::failure(verb, Failure::Policy))?;
    let outcome = step(
        &project.broil_root,
        verb,
        &cancellation,
        move |root, active| {
            operation(root, &id, verb, active)?;
            let journal = records::Journal::open(root, &id, false, active)
                .map_err(|f| Error::failure(verb, f))?;
            let observations = journal
                .observations(active)
                .map_err(|f| Error::failure(verb, f.into()))?;
            let ambiguous = observations
                .iter()
                .find(|o| o.seq == seq && o.kind == records::Kind::BindingAmbiguous)
                .ok_or_else(|| {
                    Error::new(
                        FailureClass::Configuration,
                        format!("no binding ambiguity {seq} in {id}; candidates: none"),
                    )
                })?;
            let Some(records::ObservationDetail::BindingAmbiguous { candidates, .. }) =
                &ambiguous.detail
            else {
                return Err(Error::failure(verb, Failure::Integrity));
            };
            let chosen = candidates
                .iter()
                .find(|c| c.artifact_id == artifact)
                .ok_or_else(|| {
                    Error::new(
                        FailureClass::Configuration,
                        format!(
                            "artifact is not a settlement candidate; candidates: {}",
                            candidates
                                .iter()
                                .map(|c| c.artifact_id.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    )
                })?;
            records::settle(&journal, ambiguous, chosen, &records::now_utc(), active)
                .map_err(|f| Error::failure(verb, f.into()))
        },
    )?;
    let class = matches!(outcome, records::SettleOutcome::Refused { .. })
        .then_some(FailureClass::Configuration);
    output(&invocation, render::settled(&outcome), class, None)
}
