// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    identity,
    output::public_name,
    read::{Error, Options, Result, Selection},
    sops,
    store::{self, BatchFailure, Disposition, Initialization, SetId, Store},
};
use broil_core::secret::{
    MAX_CREDENTIAL_PROMPT_VALUE_BYTES, OwnedSecret, environment::CredentialInputs,
};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Set,
    Edit,
    Init,
    Rekey,
}

pub trait Interaction {
    fn prompt(&mut self, label: &str, hidden: bool, limit: usize) -> Result<OwnedSecret>;
    fn editor(&mut self, path: &Path) -> Result<()>;
    fn runtime_dir(&self) -> Option<&Path>;
}

#[derive(Debug, Default)]
pub struct Report {
    pub details: Vec<String>,
    pub changed: Vec<String>,
    pub uncertain: Vec<String>,
    pub cleanup_failed: bool,
    pub error: Option<Error>,
    pub failed_path: Option<String>,
}
impl Report {
    pub(crate) fn record(&mut self, path: &str, result: store::Result<Disposition>) -> Result<()> {
        match result {
            Ok(Disposition::Unchanged) => Ok(()),
            Ok(Disposition::Changed) => {
                self.changed.push(path.into());
                Ok(())
            }
            Ok(Disposition::MayHaveChanged) => {
                self.uncertain.push(path.into());
                Ok(())
            }
            Err(error) => {
                self.failed_path = Some(path.into());
                match error.disposition {
                    Disposition::Unchanged => (),
                    Disposition::Changed => self.changed.push(path.into()),
                    Disposition::MayHaveChanged => self.uncertain.push(path.into()),
                }
                self.cleanup_failed |= error.cleanup_failed;
                Err(Error::store(error))
            }
        }
    }
    fn batch(&mut self, result: std::result::Result<Vec<String>, BatchFailure>) -> Result<()> {
        match result {
            Ok(paths) => {
                self.changed.extend(paths);
                Ok(())
            }
            Err(error) => {
                self.changed.extend(error.completed);
                self.record(&error.failing, Err(error.error))
            }
        }
    }
}

pub fn run(
    kind: Kind,
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    inputs: CredentialInputs,
    interaction: &mut dyn Interaction,
) -> Report {
    let mut report = Report::default();
    report.error = perform(
        kind,
        selected,
        options,
        cwd,
        inputs,
        interaction,
        &mut report,
    )
    .err();
    report
}

fn perform(
    kind: Kind,
    selected: &Selection,
    options: &Options,
    cwd: &Path,
    inputs: CredentialInputs,
    interaction: &mut dyn Interaction,
    report: &mut Report,
) -> Result<()> {
    if matches!(kind, Kind::Set | Kind::Init) && options.non_interactive {
        return Err(Error::class("private terminal input required"));
    }
    if kind == Kind::Init {
        drop(inputs);
        let project = selected.project()?;
        let name = match options
            .identity
            .as_ref()
            .or(selected.config.identity.as_ref())
        {
            Some(name) => name.clone(),
            None => interaction
                .prompt("Identity name", false, MAX_CREDENTIAL_PROMPT_VALUE_BYTES)?
                .as_str()
                .to_owned(),
        };
        let prepared = Initialization::prepare(&selected.store_root(), project, &name)
            .map_err(Error::store)?;
        let passphrase =
            interaction.prompt("New passphrase", true, MAX_CREDENTIAL_PROMPT_VALUE_BYTES)?;
        if passphrase.is_empty() {
            return Err(Error::class("empty passphrase"));
        }
        let confirmation = interaction.prompt(
            "Confirm passphrase",
            true,
            MAX_CREDENTIAL_PROMPT_VALUE_BYTES,
        )?;
        if passphrase.as_str() != confirmation.as_str() {
            return Err(Error::class("passphrase confirmation"));
        }
        drop(confirmation);
        return report.batch(prepared.create(passphrase));
    }
    if kind == Kind::Set {
        store::validate_user_key(options.key.as_deref().ok_or(Error::class("key required"))?)
            .map_err(Error::store)?;
    }
    let store = Store::open(&selected.store_root()).map_err(Error::store)?;
    let session = store.write().map_err(Error::store)?;
    if kind == Kind::Set {
        let key = options.key.as_deref().ok_or(Error::class("key required"))?;
        let sets = if options.set.is_some() {
            vec![selected.default_set(options.set.as_deref())?]
        } else {
            let project = selected.project()?;
            let mut sets = store.project_sets(project).map_err(Error::store)?;
            let prefix_len = project.len() + 1;
            sets.sort_by(|a, b| {
                let rank = |id: &SetId| match &id.as_str()[prefix_len..] {
                    "dev" => 0,
                    "ci" => 1,
                    "test" => 2,
                    "prod" => 4,
                    _ => 3,
                };
                rank(a).cmp(&rank(b)).then_with(|| a.cmp(b))
            });
            if sets.is_empty() {
                return Err(Error::class("no project sets"));
            }
            sets
        };
        let targets = session
            .prepare_sets(&sets, key, options.set.is_some())
            .map_err(Error::store)?;
        let keys = if targets.iter().any(store::PreparedSet::needs_identity) {
            identity::acquire(
                &store,
                cwd,
                selected.config.identity.as_deref(),
                inputs,
                options.non_interactive,
            )?
        } else {
            drop(inputs);
            Vec::new()
        };
        for target in &targets {
            session
                .preflight_set(target, &keys, key)
                .map_err(Error::store)?;
        }
        for (index, target) in targets.iter().enumerate() {
            let name = public_name(target.id().as_str());
            let value =
                interaction.prompt(&format!("Value for {name}"), true, sops::MAX_SCALAR_BYTES)?;
            if value.is_empty() {
                continue;
            }
            if value.len() > sops::MAX_SCALAR_BYTES || value.as_str().contains('\0') {
                return Err(Error::class("invalid value"));
            }
            let answer = interaction.prompt(&format!("Confirm {name} [y/N]"), false, 32)?;
            let yes = answer.as_str().trim().eq_ignore_ascii_case("y")
                || answer.as_str().trim().eq_ignore_ascii_case("yes");
            drop(answer);
            if !yes {
                continue;
            }
            for pending in &targets[index..] {
                pending.fresh(&session).map_err(Error::store)?;
            }
            report.batch(session.apply_set(target, &keys, key, value.as_str()))?;
            drop(value);
        }
        drop(keys);
        return Ok(());
    }
    let sets = if options.all {
        store.sets().map_err(Error::store)?
    } else {
        vec![selected.default_set(options.set.as_deref())?]
    };
    let keys = identity::acquire(
        &store,
        cwd,
        selected.config.identity.as_deref(),
        inputs,
        options.non_interactive,
    )?;
    match kind {
        Kind::Rekey => {
            let result = session.rekey(&sets, &keys);
            drop(keys);
            report.batch(result)
        }
        Kind::Edit => {
            let id = &sets[0];
            let prepared = session.edit(id, &keys, interaction.runtime_dir());
            drop(keys);
            let edit = match prepared {
                Ok(edit) => edit,
                Err(error) => return report.record(&id.file_path(), Err(error)),
            };
            match interaction.editor(&edit.path()) {
                Ok(()) => report.record(&id.file_path(), edit.finish()),
                Err(error) => {
                    report.record(&id.file_path(), edit.abort())?;
                    Err(error)
                }
            }
        }
        _ => unreachable!(),
    }
}
