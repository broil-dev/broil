// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use super::*;

pub(super) fn run(
    project: &LoadedProject,
    invocation: Invocation,
    cancellation: Cancellation,
) -> Result<Output> {
    let id = invocation.operation.clone();
    let index = step(
        &project.broil_root,
        invocation.verb,
        &cancellation,
        move |root, active| {
            if let Some(id) = &id {
                operation(root, id, Verb::Status, active)?;
            }
            let mut index = records::rebuild(root, active).map_err(|f| {
                let failure = Failure::from(f);
                if failure == Failure::Capacity {
                    Error::new(
                        FailureClass::of(failure),
                        "image status cannot take state/index/current.lock",
                    )
                } else {
                    Error::failure(Verb::Status, failure)
                }
            })?;
            if let Some(id) = id {
                index.operations.retain(|p| p.operation_id == id);
                if index.operations.is_empty() {
                    return Err(Error::new(
                        FailureClass::Configuration,
                        format!("no operation {id}"),
                    ));
                }
            }
            Ok(index)
        },
    )?;
    output(&invocation, render::index(&index), None, None)
}
