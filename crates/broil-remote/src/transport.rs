// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::client;
use russh::keys::{Algorithm, HashAlg, PublicKeyBase64};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::auth::{self, AuthContext};
use crate::scheduler::CancellationToken;
use crate::trust::EntityKind;
use crate::{FailureClass, HostKey};

#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub entity_kind: EntityKind,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub timeout: Duration,
    pub algorithms: Vec<String>,
    pub pin_constrained: bool,
    pub jump: Option<JumpFetchRequest>,
}

#[derive(Debug, Clone)]
pub struct JumpFetchRequest {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub auth_profile: String,
    pub expected_key: HostKey,
}

#[derive(Debug, Clone)]
pub struct FetchFailure {
    pub class: FailureClass,
    pub diagnostic: String,
}

impl fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.diagnostic)
    }
}

impl std::error::Error for FetchFailure {}

pub trait HostKeyFetcher {
    fn fetch(&mut self, request: &FetchRequest) -> Result<HostKey, FetchFailure>;

    fn fetch_cancellable(
        &mut self,
        request: &FetchRequest,
        _cancel: &CancellationToken,
    ) -> Result<HostKey, FetchFailure> {
        self.fetch(request)
    }
}

pub struct RusshHostKeyFetcher {
    runtime: tokio::runtime::Runtime,
    auth_context: Option<AuthContext>,
}

impl RusshHostKeyFetcher {
    pub fn new() -> Result<Self, std::io::Error> {
        Self::with_auth_context(None)
    }

    pub fn with_auth_context(auth_context: Option<AuthContext>) -> Result<Self, std::io::Error> {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map(|runtime| Self {
                runtime,
                auth_context,
            })
    }
}

impl HostKeyFetcher for RusshHostKeyFetcher {
    fn fetch(&mut self, request: &FetchRequest) -> Result<HostKey, FetchFailure> {
        self.fetch_cancellable(request, &CancellationToken::default())
    }

    fn fetch_cancellable(
        &mut self,
        request: &FetchRequest,
        cancel: &CancellationToken,
    ) -> Result<HostKey, FetchFailure> {
        self.runtime
            .block_on(fetch(request, self.auth_context.as_ref(), cancel))
    }
}

#[derive(Clone)]
struct CaptureHandler {
    key: Arc<Mutex<Option<HostKey>>>,
}

impl client::Handler for CaptureHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        *self.key.lock().expect("host-key capture mutex poisoned") =
            Some(host_key(server_public_key));
        Ok(true)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum LinkLoss {
    ServerDisconnect { reason: String, message: String },
    TransportError(String),
}

#[derive(Clone, Default)]
pub(crate) struct LinkState(Arc<Mutex<Option<LinkLoss>>>);

impl LinkState {
    pub(crate) fn loss(&self) -> Option<LinkLoss> {
        match self.0.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn record(&self, loss: LinkLoss) {
        match self.0.lock() {
            Ok(mut guard) => *guard = Some(loss),
            Err(poisoned) => *poisoned.into_inner() = Some(loss),
        }
    }

}

#[derive(Clone)]
pub(crate) struct StrictHandler {
    expected: HostKey,
    link: LinkState,
}

impl StrictHandler {
    pub(crate) fn new(expected: HostKey) -> Self {
        Self {
            expected,
            link: LinkState::default(),
        }
    }

    pub(crate) fn link(&self) -> LinkState {
        self.link.clone()
    }
}

impl client::Handler for StrictHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(same_key(&host_key(server_public_key), &self.expected))
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        self.link.record(match &reason {
            client::DisconnectReason::ReceivedDisconnect(info) => LinkLoss::ServerDisconnect {
                reason: format!("{:?}", info.reason_code),
                message: info.message.clone(),
            },
            client::DisconnectReason::Error(error) => LinkLoss::TransportError(error.to_string()),
        });
        match reason {
            client::DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            client::DisconnectReason::Error(error) => Err(error),
        }
    }
}

async fn fetch(
    request: &FetchRequest,
    auth_context: Option<&AuthContext>,
    cancel: &CancellationToken,
) -> Result<HostKey, FetchFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    let deadline = tokio::time::Instant::now() + request.timeout;
    if let Some(jump) = &request.jump {
        fetch_via_jump(request, jump, auth_context, deadline, cancel).await
    } else {
        let stream = cancellable(
            cancel,
            connect_tcp(&request.address, request.port, deadline),
        )
        .await?;
        cancellable(cancel, fetch_stream(request, stream, deadline)).await
    }
}

pub(crate) async fn connect_tcp(
    address: &str,
    port: u16,
    deadline: tokio::time::Instant,
) -> Result<tokio::net::TcpStream, FetchFailure> {
    let addresses = tokio::time::timeout_at(deadline, tokio::net::lookup_host((address, port)))
        .await
        .map_err(|_| failure(FailureClass::Dns, "DNS resolution timed out"))?
        .map_err(|error| failure(FailureClass::Dns, format!("DNS resolution failed: {error}")))?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(failure(
            FailureClass::Dns,
            "DNS resolution returned no addresses",
        ));
    }

    let mut stream = None;
    for address in addresses {
        match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(candidate)) => {
                stream = Some(candidate);
                break;
            }
            Ok(Err(_)) => {}
            Err(_) => break,
        }
    }
    stream.ok_or_else(|| {
        failure(
            FailureClass::ConnectTimeout,
            format!("cannot connect to {address}:{port} within the configured timeout"),
        )
    })
}

async fn fetch_via_jump(
    request: &FetchRequest,
    jump: &JumpFetchRequest,
    auth_context: Option<&AuthContext>,
    deadline: tokio::time::Instant,
    cancel: &CancellationToken,
) -> Result<HostKey, FetchFailure> {
    let auth_context = auth_context.ok_or_else(|| {
        failure(
            FailureClass::JumpFailure,
            format!("jump host {} authentication is unavailable", jump.name),
        )
    })?;
    let stream = cancellable(cancel, connect_tcp(&jump.address, jump.port, deadline))
        .await
        .map_err(|error| {
            failure(
                error.class,
                format!(
                    "jump host {} endpoint failed before target trust: {}",
                    jump.name, error.diagnostic
                ),
            )
        })?;
    let config = client_config(
        std::slice::from_ref(&jump.expected_key.algorithm),
        request.timeout,
    )?;
    let mut jump_session = cancellable(cancel, async {
        tokio::time::timeout_at(
            deadline,
            client::connect_stream(
                Arc::new(config),
                stream,
                StrictHandler::new(jump.expected_key.clone()),
            ),
        )
        .await
        .map_err(|_| {
            failure(
                FailureClass::JumpFailure,
                format!("jump host {} key exchange timed out", jump.name),
            )
        })?
        .map_err(|error| {
            failure(
                FailureClass::JumpFailure,
                format!(
                    "jump host {} strict host-key verification failed: {error}",
                    jump.name
                ),
            )
        })
    })
    .await?;
    cancellable(cancel, async {
        tokio::time::timeout_at(
            deadline,
            auth::authenticate_profile_cancellable(
                &mut jump_session,
                auth_context,
                &jump.auth_profile,
                cancel,
            ),
        )
        .await
        .map_err(|_| {
            failure(
                FailureClass::JumpFailure,
                format!("jump host {} authentication timed out", jump.name),
            )
        })?
        .map_err(|error| error.into_jump_failure(&jump.name))
        .map_err(|error| failure(error.class(), error.to_string()))
    })
    .await?;
    let channel = cancellable(cancel, async {
        tokio::time::timeout_at(
            deadline,
            jump_session.channel_open_direct_tcpip(
                request.address.clone(),
                u32::from(request.port),
                "127.0.0.1",
                0,
            ),
        )
        .await
        .map_err(|_| {
            failure(
                FailureClass::JumpFailure,
                format!(
                    "jump host {} timed out opening target channel to {}:{}",
                    jump.name, request.address, request.port
                ),
            )
        })?
        .map_err(|error| {
            failure(
                FailureClass::JumpFailure,
                format!(
                    "jump host {} could not open target channel to {}:{}: {error}",
                    jump.name, request.address, request.port
                ),
            )
        })
    })
    .await?;
    let target = cancellable(
        cancel,
        fetch_stream(request, channel.into_stream(), deadline),
    )
    .await;
    let _ = jump_session
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await;
    target
}

async fn fetch_stream<R>(
    request: &FetchRequest,
    stream: R,
    deadline: tokio::time::Instant,
) -> Result<HostKey, FetchFailure>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let algorithms = request
        .algorithms
        .iter()
        .map(|name| {
            Algorithm::from_str(name).map_err(|_| {
                failure(
                    FailureClass::Configuration,
                    format!("unsupported configured host-key algorithm {name}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let config = client_config_from_algorithms(algorithms, request.timeout);
    let captured = Arc::new(Mutex::new(None));
    let handler = CaptureHandler {
        key: Arc::clone(&captured),
    };
    let connected = tokio::time::timeout_at(
        deadline,
        client::connect_stream(Arc::new(config), stream, handler),
    )
    .await;
    match connected {
        Err(_) => Err(failure(
            FailureClass::Protocol,
            "SSH key exchange timed out",
        )),
        Ok(Err(russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Key,
            theirs,
            ..
        })) => {
            if request.pin_constrained {
                Err(failure(
                    FailureClass::ChangedHostKey,
                    "host no longer offers the pinned host-key algorithm",
                ))
            } else {
                let rsa = theirs.iter().any(|name| name.contains("rsa"));
                let detail = if rsa {
                    " (RSA host keys are outside the automated trust scope)"
                } else {
                    ""
                };
                Err(failure(
                    FailureClass::CapabilityUnsupported,
                    format!(
                        "no supported host-key algorithm; server offered {}{detail}",
                        theirs.join(",")
                    ),
                ))
            }
        }
        Ok(Err(error)) => Err(failure(
            FailureClass::Protocol,
            format!("SSH protocol failure before host-key capture: {error}"),
        )),
        Ok(Ok(handle)) => {
            drop(handle);
            captured
                .lock()
                .expect("host-key capture mutex poisoned")
                .clone()
                .ok_or_else(|| {
                    failure(
                        FailureClass::Protocol,
                        "SSH key exchange completed without a host key",
                    )
                })
        }
    }
}

fn client_config(algorithms: &[String], timeout: Duration) -> Result<client::Config, FetchFailure> {
    let algorithms = algorithms
        .iter()
        .map(|name| {
            Algorithm::from_str(name).map_err(|_| {
                failure(
                    FailureClass::Configuration,
                    format!("unsupported configured host-key algorithm {name}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(client_config_from_algorithms(algorithms, timeout))
}

fn client_config_from_algorithms(algorithms: Vec<Algorithm>, timeout: Duration) -> client::Config {
    strict_client_config_from_algorithms(algorithms, Some(timeout))
}

pub(crate) fn strict_client_config_from_algorithms(
    algorithms: Vec<Algorithm>,
    inactivity_timeout: Option<Duration>,
) -> client::Config {
    let mut config = client::Config::default();
    config.preferred.key = Cow::Owned(algorithms);
    config.inactivity_timeout = inactivity_timeout;
    config.nodelay = true;
    config
}

fn host_key(server_public_key: &russh::keys::ssh_key::PublicKey) -> HostKey {
    HostKey {
        algorithm: server_public_key.algorithm().to_string(),
        base64: server_public_key.public_key_base64(),
        fingerprint: server_public_key.fingerprint(HashAlg::Sha256).to_string(),
    }
}

fn same_key(left: &HostKey, right: &HostKey) -> bool {
    left.algorithm == right.algorithm && left.base64 == right.base64
}

fn failure(class: FailureClass, diagnostic: impl Into<String>) -> FetchFailure {
    FetchFailure {
        class,
        diagnostic: diagnostic.into(),
    }
}

async fn cancellable<T>(
    cancel: &CancellationToken,
    future: impl std::future::Future<Output = Result<T, FetchFailure>>,
) -> Result<T, FetchFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(cancellation_failure()),
        result = future => result,
    }
}

fn cancellation_failure() -> FetchFailure {
    failure(FailureClass::Cancellation, "cancelled")
}

