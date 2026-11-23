// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

mod cursor;
mod generator;
pub mod protocol;
mod vault;

use crate::{
    age::Identity,
    identity,
    output::public_name,
    read::{Error, Options, Result, Selection},
    sops::{Plaintext, Value},
    store::{Marker, Rollback, RollbackStage, RotationUpdate, SetId, State, Store, WriteSession},
    write::Report,
};
use broil_core::secret::{OwnedSecret, environment::CredentialInputs};
use cursor::Cursor;
use generator::Generator;
use protocol::Capture;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Kind {
    New,
    Resume,
    Rollback,
    Cleanup,
    ClearPrevious,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Call {
    Action,
    Verify,
    Rollback,
    Capabilities,
}
impl Call {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Verify => "verify",
            Self::Rollback => "rollback",
            Self::Capabilities => "capabilities",
        }
    }
}

pub trait Interaction {
    fn configure(
        &mut self,
        marker: &Marker,
        store: &Path,
        set: &SetId,
        key: &str,
        cursor: &Path,
    ) -> Result<Selection>;
    fn invoke(
        &mut self,
        marker: &Marker,
        state: State,
        call: Call,
        input: Plaintext,
    ) -> Result<Capture>;
    fn deploy(&mut self, marker: &Marker) -> Result<bool>;
    fn prompt(&mut self, label: &str, hidden: bool, limit: usize) -> Result<OwnedSecret>;
    fn message(&mut self, message: &str) -> Result<()>;
}
pub struct Request<'a> {
    pub selected: &'a Selection,
    pub options: &'a Options,
    pub cwd: &'a Path,
    pub state_home: &'a Path,
}

pub fn run(
    kind: Kind,
    request: Request<'_>,
    mut inputs: CredentialInputs,
    io: &mut dyn Interaction,
) -> Report {
    let mut report = Report::default();
    let result = (|| {
        let selected = request.selected;
        let options = request.options;
        let key = options.key.as_deref().ok_or(Error::class("key required"))?;
        let set = selected.default_set(options.set.as_deref())?;
        let store = Store::open(&selected.store_root()).map_err(Error::store)?;
        let write = store.write().map_err(Error::store)?;
        let caller = if matches!(kind, Kind::Resume | Kind::Rollback)
            || (kind == Kind::New && selected.config.vault.address.is_some())
        {
            inputs.take("BAO_TOKEN")
        } else {
            drop(inputs.take("BAO_TOKEN"));
            Ok(None)
        };
        let address = inputs.vault_address.take();
        let name_hint = if matches!(kind, Kind::Resume | Kind::Rollback)
            || (kind == Kind::New && selected.config.vault.address.is_some())
        {
            inputs
                .duplicate_identity_name()
                .map_err(|_| Error::class("vault credential identity input"))
        } else {
            Ok(None)
        };
        let acquired = identity::acquire_named(
            &store,
            request.cwd,
            selected.config.identity.as_deref(),
            inputs,
            options.non_interactive,
            false,
        )?;
        let mut record = write
            .read_rotation(&set, &acquired.keys, key)
            .map_err(Error::store)?;
        validate(&record)?;
        let cursor = Cursor::new(request.state_home, store.root())?;
        if kind == Kind::Cleanup && record.marker.is_none() {
            if !options.force {
                return Err(Error::class("cleanup requires --force"));
            }
            io.message("Warning: cleanup removes local rotation records; external credentials may remain live.")?;
            if record.previous.take().is_some() {
                report.record(
                    &set.file_path(),
                    write.update_rotation(&set, &acquired.keys, key, record),
                )?;
            }
            return Ok(());
        }
        if kind == Kind::ClearPrevious {
            if record.marker.is_some() {
                return Err(Error::class(
                    "active rotation; use status, resume, rollback or cleanup --force",
                ));
            }
            if record.previous.take().is_some() {
                report.record(
                    &set.file_path(),
                    write.update_rotation(&set, &acquired.keys, key, record),
                )?;
            }
            return Ok(());
        }
        if kind == Kind::New && record.marker.is_some() {
            return Err(Error::class(
                "active rotation; use status, origin-scoped resume, rollback or cleanup --force",
            ));
        }
        let marker = if kind == Kind::New {
            let generator = options
                .generator
                .as_deref()
                .ok_or(Error::class("generator required"))?;
            Generator::parse(generator, options.handler_type.is_some())?;
            if generator == "prompt" && options.non_interactive {
                return Err(Error::class("private terminal input required"));
            }
            let (operator, host) = origin()?;
            let started = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            Marker {
                id: rotation_id(&started, &set, key),
                state: State::Created,
                in_progress: true,
                operator,
                host,
                started,
                handler_type: options.handler_type.clone().unwrap_or_default(),
                generator: generator.into(),
                environment: selected.environment.clone(),
                keep_previous: options.keep_previous,
                note: None,
                rollback: None,
            }
        } else {
            record.marker.clone().ok_or(Error::class(
                "no active rotation; a historical cursor cannot resume",
            ))?
        };
        marker.validate().map_err(Error::store)?;
        if kind != Kind::New && cursor.reconcile(&set, key, &marker, true, true)? {
            io.message("Rotation cursor rebuilt from the authoritative store record.")?;
        }
        if matches!(kind, Kind::Resume | Kind::Rollback) {
            let (operator, host) = origin()?;
            if operator != marker.operator || host != marker.host {
                if !options.force {
                    return Err(Error::class(
                        "rotation belongs to another host or operator; explicit --force takeover required",
                    ));
                }
                io.message("Warning: forced rotation takeover from the recorded origin; all authenticated gates still apply.")?;
            }
        }
        if kind == Kind::Resume && marker.rollback.is_some() {
            return Err(Error::class(
                "rollback is in progress; continue rollback or cleanup --force",
            ));
        }
        if kind == Kind::Cleanup {
            if !options.force {
                return Err(Error::class("cleanup requires --force"));
            }
            io.message("Warning: cleanup removes local rotation records; external credentials may remain live.")?;
            cursor.reconcile(&set, key, &marker, true, true)?;
            record.pending = None;
            record.previous = None;
            record.marker = None;
            report.record(
                &set.file_path(),
                write.update_rotation(&set, &acquired.keys, key, record),
            )?;
            cursor.reconcile(&set, key, &marker, true, false)?;
            return Ok(());
        }
        let effective =
            io.configure(&marker, store.root(), &set, key, &cursor.path(&marker.id)?)?;
        if effective.store_root() != *store.root() {
            return Err(Error::class(
                "recorded environment selects another store; restore its configuration before recovery",
            ));
        }
        Generator::parse(&marker.generator, !marker.handler_type.is_empty())?;
        let caller = if effective.config.vault.address.is_some() {
            caller
                .map_err(|_| Error::class("vault token input"))?
                .map(|v| {
                    v.into_secret()
                        .map_err(|_| Error::class("vault token input"))
                })
                .transpose()?
        } else {
            drop(caller);
            None
        };
        let mut engine = Engine {
            store: &store,
            write: &write,
            keys: &acquired.keys,
            set: &set,
            key,
            marker,
            non_interactive: options.non_interactive,
            cursor,
            io,
            report: &mut report,
            vault: vault::Remote::new(effective, acquired.name, name_hint, caller, address),
        };
        let result = (|| {
            if kind == Kind::New {
                record.marker = Some(engine.marker.clone());
                engine.save(record, true)?;
            } else {
                drop(record);
                engine.reconcile(true)?;
            }
            if kind == Kind::Rollback {
                engine.rollback()
            } else {
                engine.forward(kind == Kind::Resume)
            }
        })();
        let cleanup = engine.vault.finish();
        if cleanup.is_err() {
            engine.report.details.push(
                "Owned vault token cleanup failed; inspect vault access before retrying.".into(),
            );
        }
        if let Err(error) = &result {
            engine.report.details.push(format!("Rotation {} last confirmed at {}{}: {}; inspect authoritative status and any uncertain write before resume or rollback; cleanup --force discards local recovery data.",engine.marker.id,engine.marker.state.as_str(),if engine.marker.rollback.is_some(){" (rollback)"}else{""},error));
        }
        match (result, cleanup) {
            (Err(e), _) => Err(e),
            (Ok(()), Err(e)) => Err(e),
            (Ok(()), Ok(())) => Ok(()),
        }
    })();
    report.changed.sort();
    report.changed.dedup();
    report.uncertain.sort();
    report.uncertain.dedup();
    report.error = result.err();
    report
}
struct Engine<'a> {
    store: &'a Store,
    write: &'a WriteSession<'a>,
    keys: &'a [Identity],
    set: &'a SetId,
    key: &'a str,
    marker: Marker,
    non_interactive: bool,
    cursor: Cursor,
    io: &'a mut dyn Interaction,
    report: &'a mut Report,
    vault: vault::Remote,
}
const ORDER: [State; 6] = [
    State::Created,
    State::TransitionReady,
    State::StoreUpdated,
    State::Deployed,
    State::OldRevoked,
    State::Verified,
];
impl Engine<'_> {
    fn read(&self) -> Result<RotationUpdate> {
        let record = self
            .write
            .read_rotation(self.set, self.keys, self.key)
            .map_err(Error::store)?;
        validate(&record)?;
        if record.marker.as_ref() != Some(&self.marker) {
            return Err(Error::class(
                "authoritative rotation marker changed; inspect status",
            ));
        }
        Ok(record)
    }
    fn reconcile(&mut self, active: bool) -> Result<()> {
        if self
            .cursor
            .reconcile(self.set, self.key, &self.marker, true, active)?
        {
            self.io
                .message("Rotation cursor rebuilt from the authoritative store record.")?;
        }
        Ok(())
    }
    fn save(&mut self, record: RotationUpdate, active: bool) -> Result<()> {
        let marker = record.marker.clone();
        self.report.record(
            &self.set.file_path(),
            self.write
                .update_rotation(self.set, self.keys, self.key, record),
        )?;
        if let Some(marker) = marker {
            self.marker = marker;
        }
        self.reconcile(active).inspect_err(|_| {
            self.report.details.push(format!(
                "Store committed {} {}; cursor update failed. Inspect status before resuming.",
                self.marker.id,
                self.marker.state.as_str()
            ))
        })
    }
    fn mark(&mut self, state: State, in_progress: bool) -> Result<()> {
        let mut record = self.read()?;
        let marker = record.marker.as_mut().unwrap();
        marker.state = state;
        marker.in_progress = in_progress;
        self.save(record, true)
    }
    fn value(&self) -> Result<Plaintext> {
        let record = self.read()?;
        let value = if self.marker.rollback.is_some()
            || self.marker.state.rank() < State::StoreUpdated.rank()
        {
            record.pending.as_ref()
        } else {
            record.current.as_ref()
        };
        match value {
            Some(value) => protocol::candidate(
                value
                    .scalar()
                    .ok_or(Error::class("rotation scalar required"))?
                    .as_str()
                    .as_bytes(),
            ),
            None if self.marker.state == State::Created && self.marker.in_progress => empty(),
            None => Err(Error::class("impossible rotation slot state")),
        }
    }
    fn call(&mut self, state: State, call: Call) -> Result<()> {
        let value = self.value()?;
        self.io.invoke(&self.marker, state, call, value)?;
        Ok(())
    }
    fn confirm(&mut self, state: State, reverse: bool) -> Result<()> {
        if self.non_interactive {
            return Err(Error::class("private terminal verification required"));
        }
        self.io.message(if reverse {"Undo the named external step before confirming. The store restoration is owned by Broil."}else{match state {State::Created=>"Confirm the candidate is valid.",State::TransitionReady=>"Make the external service accept the candidate alongside the old credential.",State::Deployed=>"Deploy consumers and verify they use the candidate.",State::OldRevoked=>"Revoke old external access and verify it is rejected.",State::Verified=>"Verify end-to-end service health.",State::StoreUpdated=>"Verify the store update."}})?;
        let label = format!(
            "Confirm {} for {}:{} (yes/no)",
            state.as_str(),
            public_name(self.set.as_str()),
            public_name(self.key)
        );
        if self.io.prompt(&label, false, 16)?.as_str() != "yes" {
            return Err(Error::class("rotation verification not confirmed"));
        }
        Ok(())
    }
    fn verify(&mut self, state: State) -> Result<()> {
        if self.marker.handler_type.is_empty() {
            self.confirm(state, false)
        } else {
            self.call(state, Call::Verify)
        }
    }
    fn created(&mut self) -> Result<()> {
        let generated =
            Generator::parse(&self.marker.generator, !self.marker.handler_type.is_empty())?;
        let has_handler = !self.marker.handler_type.is_empty();
        let mut attempted = false;
        let result = (|| {
            let (value, note) = if matches!(generated, Generator::Handler) {
                attempted = true;
                let output =
                    self.io
                        .invoke(&self.marker, State::Created, Call::Action, empty()?)?;
                protocol::generated(&output)?
            } else {
                let value = generated.generate(self.io, self.non_interactive)?;
                let note = if has_handler {
                    attempted = true;
                    let output = self.io.invoke(
                        &self.marker,
                        State::Created,
                        Call::Action,
                        copy(&value)?,
                    )?;
                    protocol::builtin_note(&output)?
                } else {
                    None
                };
                (value, note)
            };
            if has_handler {
                self.io
                    .invoke(&self.marker, State::Created, Call::Verify, copy(&value)?)?;
            } else {
                self.confirm(State::Created, false)?;
            }
            let mut record = self.read()?;
            record.pending = Some(
                Value::string(value.as_str()).map_err(|_| Error::class("candidate encoding"))?,
            );
            drop(value);
            let marker = record.marker.as_mut().unwrap();
            marker.note = note;
            marker.in_progress = false;
            self.save(record, true)
        })();
        if result.is_err()
            && !attempted
            && self.report.uncertain.is_empty()
            && self.marker.state == State::Created
            && self.marker.in_progress
        {
            let cleanup = (|| {
                let mut record = self.read()?;
                record.marker = None;
                record.pending = None;
                self.save(record, false)
            })();
            if cleanup.is_err() {
                self.report.details.push(
                    "Initial marker cleanup failed; use status and recover the marked rotation."
                        .into(),
                );
            }
        }
        result
    }
    fn forward(&mut self, mut resumed: bool) -> Result<()> {
        loop {
            if !self.marker.in_progress {
                let next = *ORDER
                    .get(self.marker.state.rank() + 1)
                    .ok_or(Error::class("impossible completed rotation state"))?;
                if next == State::StoreUpdated {
                    let mut record = self.read()?;
                    record.previous = record.current.take();
                    record.current = record.pending.take();
                    let marker = record.marker.as_mut().unwrap();
                    marker.state = next;
                    marker.in_progress = true;
                    self.save(record, true)?;
                } else {
                    self.mark(next, true)?;
                }
                resumed = false;
            }
            let state = self.marker.state;
            match state {
                State::Created => self.created()?,
                State::StoreUpdated => {
                    self.vault.gate(self.store, self.keys, self.set, self.key)?;
                    self.mark(state, false)?;
                }
                State::TransitionReady | State::OldRevoked => {
                    if self.marker.handler_type.is_empty() {
                        self.confirm(state, false)?;
                    } else if !resumed || self.call(state, Call::Verify).is_err() {
                        self.call(state, Call::Action)?;
                        self.call(state, Call::Verify)?;
                    }
                    self.mark(state, false)?;
                }
                State::Deployed => {
                    let proved = resumed
                        && !self.marker.handler_type.is_empty()
                        && self.call(state, Call::Verify).is_ok();
                    if !proved {
                        if !self.io.deploy(&self.marker)? {
                            self.io.message(
                                "Deploy consumers using the promoted value before verification.",
                            )?;
                        }
                        self.verify(state)?;
                    }
                    self.mark(state, false)?;
                }
                State::Verified => {
                    self.verify(state)?;
                    let mut record = self.read()?;
                    record.marker = None;
                    if !self.marker.keep_previous {
                        record.previous = None;
                    }
                    self.save(record, false)?;
                    self.io.message("Rotation verified and complete.")?;
                    return Ok(());
                }
            }
            resumed = false;
        }
    }
    fn rollback(&mut self) -> Result<()> {
        if self.marker.state.rank() >= State::OldRevoked.rank() {
            let supported = if self.marker.handler_type.is_empty() {
                false
            } else {
                self.io
                    .invoke(
                        &self.marker,
                        self.marker.state,
                        Call::Capabilities,
                        empty()?,
                    )
                    .is_ok_and(|o| protocol::recreates(&o, self.marker.state))
            };
            if !supported {
                return Err(Error::class(
                    "post-revocation rollback requires exact recreation capability; cleanup --force or a fresh rotation cannot promise restored access",
                ));
            }
        }
        if self.marker.rollback.is_none() {
            let mut record = self.read()?;
            let promoted = self.marker.state.rank() >= State::StoreUpdated.rank();
            if promoted {
                record.pending = record.current.take();
                record.current = record.previous.take();
            }
            record.marker.as_mut().unwrap().rollback = Some(Rollback {
                stage: if promoted {
                    RollbackStage::Sync
                } else {
                    RollbackStage::Handlers
                },
                from_state: self.marker.state,
                remaining: reverse_states(self.marker.state),
            });
            self.save(record, true)?;
        }
        loop {
            let rollback = self.marker.rollback.as_ref().unwrap().clone();
            match rollback.stage {
                RollbackStage::Sync => {
                    self.vault.gate(self.store, self.keys, self.set, self.key)?;
                    let mut record = self.read()?;
                    record
                        .marker
                        .as_mut()
                        .unwrap()
                        .rollback
                        .as_mut()
                        .unwrap()
                        .stage = RollbackStage::Handlers;
                    self.save(record, true)?;
                }
                RollbackStage::Handlers => {
                    if let Some(state) = rollback.remaining.first().copied() {
                        if self.marker.handler_type.is_empty() {
                            self.confirm(state, true)?;
                        } else {
                            self.call(state, Call::Rollback)?;
                        }
                        let mut record = self.read()?;
                        record
                            .marker
                            .as_mut()
                            .unwrap()
                            .rollback
                            .as_mut()
                            .unwrap()
                            .remaining
                            .remove(0);
                        self.save(record, true)?;
                    } else {
                        let mut record = self.read()?;
                        record
                            .marker
                            .as_mut()
                            .unwrap()
                            .rollback
                            .as_mut()
                            .unwrap()
                            .stage = RollbackStage::Finish;
                        self.save(record, true)?;
                    }
                }
                RollbackStage::Finish => {
                    let mut record = self.read()?;
                    record.marker = None;
                    record.pending = None;
                    self.save(record, false)?;
                    self.io
                        .message("Rotation rollback complete; distribute the restored store.")?;
                    return Ok(());
                }
            }
        }
    }
}
fn empty() -> Result<Plaintext> {
    Plaintext::copy_from("").map_err(|_| Error::class("allocation"))
}
fn copy(value: &Plaintext) -> Result<Plaintext> {
    Plaintext::copy_from(value.as_str()).map_err(|_| Error::class("allocation"))
}
fn reverse_states(state: State) -> Vec<State> {
    ORDER[..=state.rank()]
        .iter()
        .copied()
        .rev()
        .filter(|s| *s != State::StoreUpdated)
        .collect()
}
fn validate(record: &RotationUpdate) -> Result<()> {
    let Some(marker) = &record.marker else {
        return Ok(());
    };
    if marker.state == State::Verified && !marker.in_progress && marker.rollback.is_none() {
        return Err(Error::class(
            "completed verification must not retain an active marker",
        ));
    }
    let promoted = marker.state.rank() >= State::StoreUpdated.rank();
    let valid = if let Some(rollback) = &marker.rollback {
        let all = reverse_states(marker.state);
        all.ends_with(&rollback.remaining)
            && (rollback.stage != RollbackStage::Finish || rollback.remaining.is_empty())
            && (rollback.stage != RollbackStage::Sync || (promoted && rollback.remaining == all))
            && if promoted {
                record.pending.is_some() && record.previous.is_none()
            } else {
                rollback.stage != RollbackStage::Sync
                    && (record.pending.is_some()
                        || (marker.state == State::Created && marker.in_progress))
            }
    } else if promoted {
        record.pending.is_none() && record.previous.is_some()
    } else if marker.state == State::Created && marker.in_progress {
        record.pending.is_none()
    } else {
        record.pending.is_some()
    };
    if !valid {
        return Err(Error::class(
            "impossible rotation marker and slot combination",
        ));
    }
    Ok(())
}
pub fn rotation_id(started: &str, set: &SetId, key: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(set.file_path().as_bytes());
    hash.update([0]);
    hash.update(key.as_bytes());
    let digest = hash.finalize();
    let mut id: String = started.chars().filter(char::is_ascii_digit).collect();
    for byte in &digest[..4] {
        use std::fmt::Write;
        write!(id, "{byte:02x}").expect("String write");
    }
    id
}
fn origin() -> Result<(String, String)> {
    fn bounded(path: &str) -> Result<String> {
        let mut text = String::new();
        std::fs::File::open(path)
            .map_err(|_| Error::class("trusted origin unavailable"))?
            .take(1024 * 1024 + 1)
            .read_to_string(&mut text)
            .map_err(|_| Error::class("trusted origin unavailable"))?;
        if text.len() > 1024 * 1024 {
            return Err(Error::class("trusted origin unavailable"));
        }
        Ok(text)
    }
    let uid = broil_core::secret::path_safety::effective_uid().to_string();
    let accounts = bounded("/etc/passwd")?;
    let operator = accounts
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.len() == 7 && fields[2] == uid).then(|| fields[0].to_owned())
        })
        .ok_or(Error::class("trusted account unavailable"))?;
    let host = bounded("/proc/sys/kernel/hostname")?
        .trim_end_matches('\n')
        .to_owned();
    if operator.is_empty()
        || host.is_empty()
        || operator.chars().chain(host.chars()).any(char::is_control)
    {
        return Err(Error::class("trusted origin unavailable"));
    }
    Ok((operator, host))
}
pub fn status(selected: &Selection, options: &Options, state_home: &Path) -> Result<String> {
    let store = Store::open(&selected.store_root()).map_err(Error::store)?;
    let sets = if options.all {
        store.sets().map_err(Error::store)?
    } else {
        match selected.default_set(options.set.as_deref()) {
            Ok(s) => vec![s],
            Err(_)
                if options.key.is_none()
                    && options.set.is_none()
                    && selected.config.set.is_none()
                    && selected.environment.is_none() =>
            {
                store.sets().map_err(Error::store)?
            }
            Err(e) => return Err(e),
        }
    };
    let cursor = Cursor::new(state_home, store.root())?;
    let mut output = String::new();
    let mut active_ids = Vec::new();
    for set in &sets {
        let status = store.status(set).map_err(Error::store)?;
        for (key, marker) in status.markers() {
            if options.key.as_ref().is_some_and(|k| k != key) {
                continue;
            }
            use std::fmt::Write;
            writeln!(output,"set: {}\nkey: {}\nid: {}\nstate: {}\nin_progress: {}\noperator: {}\nhost: {}\nauthenticated: false",public_name(set.as_str()),public_name(key),marker.id,marker.state.as_str(),marker.in_progress,public_name(&marker.operator),public_name(&marker.host)).expect("String write");
            if let Some(r) = &marker.rollback {
                writeln!(
                    output,
                    "rollback: {}",
                    match r.stage {
                        RollbackStage::Sync => "sync",
                        RollbackStage::Handlers => "handlers",
                        RollbackStage::Finish => "finish",
                    }
                )
                .expect("String write");
            }
            if cursor.reconcile(set, key, marker, false, true)? {
                output.push_str("cursor: rebuilt from unauthenticated marker\n");
            }
            active_ids.push(marker.id.clone());
        }
    }
    if active_ids.is_empty() {
        output.push_str("no active rotation\n");
    }
    for id in cursor.historical(&sets, options.key.as_deref(), &active_ids)? {
        output.push_str(&format!("cursor: {id} historical/unverified\n"));
    }
    Ok(output)
}
