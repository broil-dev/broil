// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::Poll;

use tokio::sync::watch;
use tokio::task::JoinSet;

type StoreCleanup = dyn Fn() + Send + Sync;

#[derive(Clone)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
    parents: Vec<Arc<CancellationState>>,
}

struct CancellationState {
    cancelled: AtomicBool,
    sender: watch::Sender<bool>,
    store_cleanups: Mutex<Vec<Weak<StoreCleanup>>>,
}

impl std::fmt::Debug for CancellationToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        let (sender, _receiver) = watch::channel(false);
        Self {
            state: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                sender,
                store_cleanups: Mutex::new(Vec::new()),
            }),
            parents: Vec::new(),
        }
    }
}

impl CancellationToken {
    pub fn child(&self) -> Self {
        let (sender, _receiver) = watch::channel(false);
        let mut parents = Vec::with_capacity(self.parents.len() + 1);
        parents.push(Arc::clone(&self.state));
        parents.extend(self.parents.iter().map(Arc::clone));
        Self {
            state: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                sender,
                store_cleanups: Mutex::new(Vec::new()),
            }),
            parents,
        }
    }

    pub fn cancel(&self) {
        if !self.state.cancelled.swap(true, Ordering::SeqCst) {
            let _ = self.state.sender.send(true);
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::SeqCst)
            || self
                .parents
                .iter()
                .any(|parent| parent.cancelled.load(Ordering::SeqCst))
    }

    pub(crate) fn register_store_cleanup(&self, cleanup: &Arc<StoreCleanup>) -> bool {
        for state in self
            .parents
            .iter()
            .rev()
            .chain(std::iter::once(&self.state))
        {
            let mut cleanups = state
                .store_cleanups
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if self.is_cancelled() {
                return false;
            }
            cleanups.retain(|item| item.strong_count() != 0);
            cleanups.push(Arc::downgrade(cleanup));
        }
        true
    }

    pub(crate) fn drain_store_workers(&self) {
        let cleanups = self
            .state
            .store_cleanups
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        for cleanup in cleanups {
            if let Some(cleanup) = cleanup.upgrade() {
                cleanup();
            }
        }
    }

    pub async fn cancelled(&self) {
        let mut receivers: Vec<watch::Receiver<bool>> = std::iter::once(&self.state)
            .chain(self.parents.iter())
            .map(|state| state.sender.subscribe())
            .collect();
        loop {
            if self.is_cancelled() {
                return;
            }
            let mut changes: Vec<_> = receivers
                .iter_mut()
                .map(|receiver| Box::pin(receiver.changed()))
                .collect();
            let changed = std::future::poll_fn(|context| {
                for change in changes.iter_mut() {
                    if let Poll::Ready(outcome) = change.as_mut().poll(context) {
                        return Poll::Ready(outcome);
                    }
                }
                Poll::Pending
            })
            .await;
            drop(changes);
            if changed.is_err() {
                return;
            }
        }
    }
}

pub async fn run_bounded<I, O, Run, Fut, Failed, Suppressed>(
    mut items: Vec<Option<I>>,
    limit: usize,
    fail_fast: bool,
    token: CancellationToken,
    run: Run,
    failed: Failed,
    suppressed: Suppressed,
) -> Vec<O>
where
    I: Send + 'static,
    O: Send + 'static,
    Run: Fn(I, CancellationToken) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = O> + Send + 'static,
    Failed: Fn(&O) -> bool + Clone + Send + Sync + 'static,
    Suppressed: Fn(I, crate::FailureClass) -> O + Clone + Send + Sync + 'static,
{
    let len = items.len();
    let limit = effective_limit(limit, len);
    let mut output = Vec::with_capacity(len);
    output.resize_with(len, || None);
    let mut set = JoinSet::new();
    let mut next = 0usize;
    let mut running = 0usize;
    let mut stop_scheduling = token.is_cancelled();
    let mut suppression_class = token
        .is_cancelled()
        .then_some(crate::FailureClass::Cancellation);

    while next < len && running < limit && !stop_scheduling {
        spawn_one(&mut set, &mut items, next, token.clone(), run.clone());
        next += 1;
        running += 1;
    }

    while running > 0 {
        let Some(joined) = set.join_next().await else {
            break;
        };
        running -= 1;
        let (index, result) = joined.expect("remote check worker panicked");
        if fail_fast && failed(&result) {
            stop_scheduling = true;
            if !token.is_cancelled() {
                suppression_class.get_or_insert(crate::FailureClass::FailFast);
            }
        }
        output[index] = Some(result);

        while next < len && running < limit && !stop_scheduling && !token.is_cancelled() {
            spawn_one(&mut set, &mut items, next, token.clone(), run.clone());
            next += 1;
            running += 1;
        }
    }

    let class = suppression_class.unwrap_or_else(|| {
        if token.is_cancelled() {
            crate::FailureClass::Cancellation
        } else {
            crate::FailureClass::FailFast
        }
    });
    while next < len {
        if let Some(item) = items[next].take() {
            output[next] = Some(suppressed.clone()(item, class));
        }
        next += 1;
    }

    output
        .into_iter()
        .map(|item| item.expect("every scheduled item produced an output"))
        .collect()
}

pub fn effective_limit(limit: usize, len: usize) -> usize {
    limit.max(1).min(len.max(1))
}

fn spawn_one<I, O, Run, Fut>(
    set: &mut JoinSet<(usize, O)>,
    items: &mut [Option<I>],
    index: usize,
    token: CancellationToken,
    run: Run,
) where
    I: Send + 'static,
    O: Send + 'static,
    Run: Fn(I, CancellationToken) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = O> + Send + 'static,
{
    let item = items[index]
        .take()
        .expect("scheduler item exists before spawn");
    set.spawn(async move { (index, run(item, token).await) });
}

