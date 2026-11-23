// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{OwnedSecret, PacedClock, SecretFailure, cancelled_provider, provider_failure};
use crate::scheduler::CancellationToken;
use broil_config::LoadedProject;
use broil_core::secret::environment::CredentialInputs;
use broil_secrets::{identity::AcquisitionControl, read::Selection};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
};
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct StoreContext {
    selected: Selection,
    cwd: PathBuf,
    inputs: Arc<CredentialInputs>,
    pub(super) non_interactive: bool,
}
impl StoreContext {
    pub fn from_project(
        project: &LoadedProject,
        environment: &str,
        cwd: &Path,
        inputs: CredentialInputs,
    ) -> Self {
        Self::new(
            Selection::new(
                &project.config,
                &project.broil_root,
                Some(environment.as_ref()),
            )
            .expect("validated remote inventory environment"),
            cwd.to_path_buf(),
            inputs,
        )
    }

    pub fn new(selected: Selection, cwd: PathBuf, inputs: CredentialInputs) -> Self {
        Self {
            selected,
            cwd,
            inputs: Arc::new(inputs),
            non_interactive: false,
        }
    }

    pub(super) fn may_prompt(&self) -> bool {
        if self.non_interactive {
            return false;
        }
        let Ok(store) = broil_secrets::store::Store::open(&self.selected.store_root()) else {
            return false;
        };
        broil_secrets::identity::may_prompt(
            &store,
            self.selected.config.identity.as_deref(),
            &self.inputs,
            self.selected.config.vault.address.is_some()
                && self.selected.config.vault.credential.is_none(),
        )
    }

    pub(super) fn resolve(
        &self,
        name: &str,
        key: &str,
        set: Option<&str>,
        cancel: &CancellationToken,
        clock: Option<PacedClock>,
    ) -> Result<OwnedSecret, SecretFailure> {
        if cancel.is_cancelled() {
            return Err(cancelled_provider(name));
        }
        let controlled_cancel = cancel.clone();
        let control = AcquisitionControl::new(
            move || controlled_cancel.is_cancelled(),
            move || Box::new(clock.as_ref().map(PacedClock::pause)),
        );
        let inputs = self
            .inputs
            .try_duplicate()
            .map_err(|_| provider_failure(name, "secret unavailable"))?;
        let result = broil_secrets::read::resolve_scalar_with_options(
            &self.selected,
            &self.cwd,
            inputs,
            key,
            set,
            &control,
            self.non_interactive,
        );
        if cancel.is_cancelled() {
            return Err(cancelled_provider(name));
        }
        result.map_err(|_| provider_failure(name, "secret unavailable"))
    }
}

struct Job {
    context: StoreContext,
    name: String,
    key: String,
    set: Option<String>,
    cancel: CancellationToken,
    clock: Option<PacedClock>,
}
impl Job {
    fn run(self) -> Result<OwnedSecret, SecretFailure> {
        self.context.resolve(
            &self.name,
            &self.key,
            self.set.as_deref(),
            &self.cancel,
            self.clock,
        )
    }
}

struct Work {
    job: Option<Job>,
    done: bool,
}
type SharedWork = Arc<(Mutex<Work>, Condvar)>;

struct Worker {
    cleanup: Arc<dyn Fn() + Send + Sync>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        (self.cleanup)();
    }
}
fn drain(work: &SharedWork, cancel: &CancellationToken) {
    cancel.cancel();
    let (state, done) = &**work;
    let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(job) = state.job.take() {
        drop(state);
        drop(job);
        work.0.lock().unwrap_or_else(|p| p.into_inner()).done = true;
        done.notify_all();
        return;
    }
    while !state.done {
        state = done.wait(state).unwrap_or_else(|p| p.into_inner());
    }
}

struct Completion(SharedWork);
impl Drop for Completion {
    fn drop(&mut self) {
        let (state, done) = &*self.0;
        state.lock().unwrap_or_else(|p| p.into_inner()).done = true;
        done.notify_all();
    }
}

pub(super) async fn resolve_owned(
    context: StoreContext,
    name: &str,
    key: String,
    set: Option<String>,
    cancel: &CancellationToken,
    clock: Option<PacedClock>,
) -> Result<OwnedSecret, SecretFailure> {
    let child = cancel.child();
    let work = Arc::new((
        Mutex::new(Work {
            job: Some(Job {
                context,
                name: name.to_owned(),
                key,
                set,
                cancel: child.clone(),
                clock,
            }),
            done: false,
        }),
        Condvar::new(),
    ));
    let (send, receive) = oneshot::channel();
    let cleanup_work = work.clone();
    let owner = Worker {
        cleanup: Arc::new(move || drain(&cleanup_work, &child)),
    };
    if !cancel.register_store_cleanup(&owner.cleanup) {
        return Err(cancelled_provider(name));
    }
    tokio::task::spawn_blocking(move || {
        let job = work.0.lock().unwrap_or_else(|p| p.into_inner()).job.take();
        if let Some(job) = job {
            let _completion = Completion(work.clone());
            let result = job.run();
            let _ = send.send(result);
        }
    });
    let result = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancelled_provider(name)),
        result = receive => result.map_err(|_| provider_failure(name, "secret unavailable"))?,
    };
    drop(owner);
    if cancel.is_cancelled() {
        return Err(cancelled_provider(name));
    }
    result
}

