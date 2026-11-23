// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use super::*;

pub(super) fn run(
    project: &LoadedProject,
    invocation: Invocation,
    cancellation: Cancellation,
) -> Result<Output> {
    let verb = invocation.verb;
    if verb == Verb::RecordList {
        let ids = step(
            &project.broil_root,
            verb,
            &cancellation,
            move |root, active| {
                let store = records::Store::new(root);
                let ids = store.list(active).map_err(|f| Error::failure(verb, f))?;
                for id in &ids {
                    let record = store.read(id, active).map_err(|f| {
                        Error::new(
                            FailureClass::of(Failure::from(f)),
                            format!("cannot read record {id}"),
                        )
                    })?;
                    if record.is_none() {
                        return Err(Error::new(
                            FailureClass::Integrity,
                            format!("listed record disappeared {id}"),
                        ));
                    }
                }
                Ok(ids)
            },
        )?;
        if invocation.format == Format::Table {
            return Ok(Output {
                payload: ids
                    .iter()
                    .map(|id| format!("{id}\n"))
                    .collect::<String>()
                    .into_bytes(),
                status: 0,
                diagnostic: None,
            });
        }
        output(
            &invocation,
            serde_json::json!({"artifacts": ids}),
            None,
            None,
        )
    } else {
        let id = invocation
            .artifact
            .clone()
            .ok_or_else(|| Error::failure(verb, Failure::Policy))?;
        let record = step(
            &project.broil_root,
            verb,
            &cancellation,
            move |root, active| {
                records::Store::new(root)
                    .read(&id, active)
                    .map_err(|f| Error::failure(verb, f.into()))?
                    .ok_or_else(|| {
                        Error::new(FailureClass::Configuration, format!("no record {id}"))
                    })
            },
        )?;
        let payload = if invocation.format == Format::Json {
            record.encode().map_err(|f| Error::failure(verb, f))?
        } else {
            render::record_table(&record)
        };
        Ok(Output {
            payload,
            status: 0,
            diagnostic: None,
        })
    }
}
