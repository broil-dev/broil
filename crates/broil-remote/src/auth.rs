// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use broil_config::LoadedProject;
use broil_core::remote::{
    AgentSelector, AuthMethod, AuthProfile, PublicKeyIdentity, SecretProvider,
};
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::ssh_key::PublicKey;
use russh::keys::{
    HashAlg, PrivateKeyWithHashAlg, PublicKeyBase64, decode_secret_key, parse_public_key_base64,
};
use zeroize::Zeroizing;

use crate::FailureClass;
use crate::scheduler::CancellationToken;
use crate::secret::{PacedClock, PromptTerminal, SecretContext, read_secret_file};

pub const MAX_EMPTY_INFO_ROUNDS: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardInteractiveDecision {
    EmptyInfoRound,
    SecretResponse,
}

#[derive(Debug)]
pub struct AuthFailure {
    class: FailureClass,
    diagnostic: String,
}

impl AuthFailure {
    fn new(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self {
            class,
            diagnostic: diagnostic.into(),
        }
    }

    pub fn class(&self) -> FailureClass {
        self.class
    }

    pub fn is_rejection(&self) -> bool {
        self.class == FailureClass::AuthenticationRejected
    }

    pub(crate) fn attempt_timed_out(diagnostic: &'static str) -> Self {
        Self::new(FailureClass::AuthenticationTimeout, diagnostic)
    }

    pub(crate) fn cancelled() -> Self {
        cancellation_failure()
    }

    pub(crate) fn connection_lost(diagnostic: String) -> Self {
        Self::new(FailureClass::Protocol, diagnostic)
    }

    pub(crate) fn connection_failed(class: FailureClass, diagnostic: impl Into<String>) -> Self {
        Self::new(class, diagnostic)
    }

    pub fn into_jump_failure(self, jump: &str) -> Self {
        let class = match self.class {
            FailureClass::AuthenticationRejected | FailureClass::Protocol => {
                FailureClass::JumpFailure
            }
            class => class,
        };
        Self::new(
            class,
            format!("jump host {jump} failed authentication or credential setup"),
        )
    }
}

impl fmt::Display for AuthFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for AuthFailure {}

#[derive(Clone)]
pub struct AuthContext {
    root: PathBuf,
    secret_context: SecretContext,
    auth_profiles: BTreeMap<String, AuthProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSshPublicKeyProfile {
    pub user: String,
    pub identities: Vec<OpenSshPublicKeyIdentity>,
    pub agent_socket: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenSshPublicKeyIdentity {
    Agent { public_key: String },
    File { path: PathBuf },
}

impl AuthContext {
    pub fn from_project(
        project: &LoadedProject,
        environment: &str,
        env_snapshot: &[(OsString, OsString)],
    ) -> Self {
        let env_remote = &project.config.environments[environment].remote.definitions;
        let mut secret_providers = project.config.remote.definitions.secret_providers.clone();
        secret_providers.extend(env_remote.secret_providers.clone());
        let mut auth_profiles = project.config.remote.definitions.auth_profiles.clone();
        auth_profiles.extend(env_remote.auth_profiles.clone());
        Self::new(
            project.broil_root.clone(),
            env_snapshot.to_vec(),
            secret_providers,
            auth_profiles,
        )
    }

    pub fn new(
        root: PathBuf,
        env_snapshot: Vec<(OsString, OsString)>,
        secret_providers: BTreeMap<String, SecretProvider>,
        auth_profiles: BTreeMap<String, AuthProfile>,
    ) -> Self {
        let secret_context = SecretContext::new(root.clone(), env_snapshot, secret_providers);
        Self {
            root,
            secret_context,
            auth_profiles,
        }
    }

    pub fn with_prompt_terminal(mut self, terminal: PromptTerminal) -> Self {
        self.secret_context = self.secret_context.with_prompt_terminal(terminal);
        self
    }

    pub fn with_paced_clock(mut self, clock: PacedClock) -> Self {
        self.secret_context = self.secret_context.with_paced_clock(clock);
        self
    }

    pub fn profile(&self, name: &str) -> Result<&AuthProfile, AuthFailure> {
        self.auth_profiles.get(name).ok_or_else(|| {
            AuthFailure::new(
                FailureClass::Configuration,
                format!("unknown authentication profile {name}"),
            )
        })
    }

    pub fn human_paced_authentication_resolutions(&self, profile: &str) -> usize {
        let Some(profile) = self.auth_profiles.get(profile) else {
            return 0;
        };
        match &profile.method {
            AuthMethod::PublicKey { identities } => identities
                .iter()
                .filter(|identity| match identity {
                    PublicKeyIdentity::File {
                        passphrase: Some(passphrase),
                        ..
                    } => self
                        .secret_context
                        .provider_is_human_paced(&passphrase.secret),
                    PublicKeyIdentity::File {
                        passphrase: None, ..
                    }
                    | PublicKeyIdentity::Agent { .. } => false,
                })
                .count(),
            AuthMethod::Password(secret) | AuthMethod::KeyboardInteractive(secret) => {
                usize::from(self.secret_context.provider_is_human_paced(&secret.secret))
            }
        }
    }

    fn config_path(&self, path: &str) -> PathBuf {
        crate::secret::normalize_path(&self.root, Path::new(path))
    }
}

pub fn openssh_public_key_profile(
    context: &AuthContext,
    profile_name: &str,
) -> Result<OpenSshPublicKeyProfile, AuthFailure> {
    let profile = context.profile(profile_name)?;
    let AuthMethod::PublicKey { identities } = &profile.method else {
        return Err(AuthFailure::new(
            FailureClass::Configuration,
            format!("authentication profile {profile_name} is not public-key based"),
        ));
    };
    let runtime = if identities
        .iter()
        .any(|identity| matches!(identity, PublicKeyIdentity::Agent { .. }))
    {
        Some(
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .map_err(|error| {
                    AuthFailure::new(
                        FailureClass::CapabilityUnsupported,
                        format!("cannot initialize SSH agent runtime: {error}"),
                    )
                })?,
        )
    } else {
        None
    };
    let agent_socket = if runtime.is_some() {
        Some(PathBuf::from(
            ssh_auth_sock(context)
                .ok_or_else(|| {
                    AuthFailure::new(
                        FailureClass::AuthenticationLocallyUnavailable,
                        "SSH_AUTH_SOCK is unavailable for configured agent identity",
                    )
                })?
                .to_os_string(),
        ))
    } else {
        None
    };
    let mut planned = Vec::with_capacity(identities.len());
    for identity in identities {
        match identity {
            PublicKeyIdentity::File { path, .. } => {
                let key_path = context.config_path(path);
                crate::path_safety::defensive_open_validated(&key_path, false).map_err(|_| {
                    AuthFailure::new(
                        FailureClass::AuthenticationLocallyUnavailable,
                        "configured private-key file is unavailable or unsafe",
                    )
                })?;
                planned.push(OpenSshPublicKeyIdentity::File { path: key_path });
            }
            PublicKeyIdentity::Agent { selector } => {
                let key = runtime
                    .as_ref()
                    .expect("agent identity requires a runtime")
                    .block_on(selected_agent_public_key(context, selector))?;
                planned.push(OpenSshPublicKeyIdentity::Agent {
                    public_key: openssh_public_key_line(&key),
                });
            }
        }
    }
    Ok(OpenSshPublicKeyProfile {
        user: profile.user.clone(),
        identities: planned,
        agent_socket,
    })
}

async fn selected_agent_public_key(
    context: &AuthContext,
    selector: &AgentSelector,
) -> Result<PublicKey, AuthFailure> {
    let socket = ssh_auth_sock(context).ok_or_else(|| {
        AuthFailure::new(
            FailureClass::AuthenticationLocallyUnavailable,
            "SSH_AUTH_SOCK is unavailable for configured agent identity",
        )
    })?;
    let mut agent = AgentClient::connect_uds(Path::new(socket))
        .await
        .map_err(|_| {
            AuthFailure::new(
                FailureClass::AuthenticationLocallyUnavailable,
                "configured SSH agent is unavailable",
            )
        })?;
    let identities = agent.request_identities().await.map_err(|_| {
        AuthFailure::new(
            FailureClass::AuthenticationLocallyUnavailable,
            "configured SSH agent did not return identities",
        )
    })?;
    selected_agent_key(context, selector, identities.iter())
}

fn openssh_public_key_line(key: &PublicKey) -> String {
    format!("{} {}\n", key.algorithm(), key.public_key_base64())
}

pub async fn authenticate_profile<H: russh::client::Handler>(
    session: &mut russh::client::Handle<H>,
    context: &AuthContext,
    profile_name: &str,
) -> Result<(), AuthFailure> {
    authenticate_profile_cancellable(
        session,
        context,
        profile_name,
        &CancellationToken::default(),
    )
    .await
}

pub async fn authenticate_profile_cancellable<H: russh::client::Handler>(
    session: &mut russh::client::Handle<H>,
    context: &AuthContext,
    profile_name: &str,
    cancel: &CancellationToken,
) -> Result<(), AuthFailure> {
    let profile = context.profile(profile_name)?;
    authenticate_with_profile(session, context, profile, cancel).await
}

pub trait AttemptConnections: Sync {
    type Handler: russh::client::Handler;
    type Connection: AsMut<russh::client::Handle<Self::Handler>> + Send;
    fn connect(&self) -> ConnectFuture<'_, Self::Connection>;
    fn lost(&self, connection: &Self::Connection) -> Option<String>;
}

pub type ConnectFuture<'a, C> = Pin<Box<dyn Future<Output = Result<C, AuthFailure>> + Send + 'a>>;

pub struct Authenticated<C> {
    pub profile: String,
    pub connection: C,
}

impl<C> fmt::Debug for Authenticated<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Authenticated")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

pub async fn authenticate_canonical_then_bootstrap<T>(
    first: T::Connection,
    connections: &T,
    context: &AuthContext,
    canonical_profile: &str,
    bootstrap_profiles: &[String],
) -> Result<Authenticated<T::Connection>, AuthFailure>
where
    T: AttemptConnections + ?Sized,
{
    authenticate_canonical_then_bootstrap_cancellable(
        first,
        connections,
        context,
        canonical_profile,
        bootstrap_profiles,
        &CancellationToken::default(),
    )
    .await
}

pub async fn authenticate_canonical_then_bootstrap_cancellable<T>(
    first: T::Connection,
    connections: &T,
    context: &AuthContext,
    canonical_profile: &str,
    bootstrap_profiles: &[String],
    cancel: &CancellationToken,
) -> Result<Authenticated<T::Connection>, AuthFailure>
where
    T: AttemptConnections + ?Sized,
{
    authenticate_canonical_then_bootstrap_bounded_cancellable(
        first,
        connections,
        context,
        canonical_profile,
        bootstrap_profiles,
        cancel,
        &Unbounded,
    )
    .await
}

pub type AttemptFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AuthFailure>> + Send + 'a>>;

pub trait AttemptBound: Sync {
    fn bound<'a>(&'a self, attempt: AttemptFuture<'a>) -> AttemptFuture<'a>;
}

pub struct Unbounded;

impl AttemptBound for Unbounded {
    fn bound<'a>(&'a self, attempt: AttemptFuture<'a>) -> AttemptFuture<'a> {
        attempt
    }
}

pub async fn authenticate_canonical_then_bootstrap_bounded_cancellable<T, B>(
    first: T::Connection,
    connections: &T,
    context: &AuthContext,
    canonical_profile: &str,
    bootstrap_profiles: &[String],
    cancel: &CancellationToken,
    bound: &B,
) -> Result<Authenticated<T::Connection>, AuthFailure>
where
    T: AttemptConnections + ?Sized,
    B: AttemptBound + ?Sized,
{
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    let mut first = first;
    let canonical = bound.bound(Box::pin(authenticate_profile_cancellable(
        first.as_mut(),
        context,
        canonical_profile,
        cancel,
    )));
    match canonical.await {
        Ok(()) => Ok(Authenticated {
            profile: canonical_profile.to_string(),
            connection: first,
        }),
        Err(error) if error.is_rejection() => {
            if let Some(diagnostic) = connections.lost(&first) {
                return Err(AuthFailure::connection_lost(diagnostic));
            }
            drop(first);
            let mut last = error;
            for profile in bootstrap_profiles {
                if cancel.is_cancelled() {
                    return Err(cancellation_failure());
                }
                let mut connection = connections.connect().await?;
                let attempt = bound.bound(Box::pin(authenticate_profile_cancellable(
                    connection.as_mut(),
                    context,
                    profile,
                    cancel,
                )));
                match attempt.await {
                    Ok(()) => {
                        return Ok(Authenticated {
                            profile: profile.clone(),
                            connection,
                        });
                    }
                    Err(error) if error.is_rejection() => {
                        if let Some(diagnostic) = connections.lost(&connection) {
                            return Err(AuthFailure::connection_lost(diagnostic));
                        }
                        last = error;
                    }
                    Err(error) => {
                        return Err(with_lost_connection(connections, &connection, error));
                    }
                }
            }
            Err(last)
        }
        Err(error) => Err(with_lost_connection(connections, &first, error)),
    }
}

fn with_lost_connection<T: AttemptConnections + ?Sized>(
    connections: &T,
    connection: &T::Connection,
    error: AuthFailure,
) -> AuthFailure {
    if error.class() == FailureClass::Protocol {
        if let Some(diagnostic) = connections.lost(connection) {
            return AuthFailure::connection_lost(diagnostic);
        }
    }
    error
}

pub fn keyboard_interactive_prompt_decision(
    empty_rounds: &mut u8,
    answered_secret: bool,
    prompt_echoes: &[bool],
) -> Result<KeyboardInteractiveDecision, AuthFailure> {
    if prompt_echoes.is_empty() {
        *empty_rounds = empty_rounds.saturating_add(1);
        if *empty_rounds > MAX_EMPTY_INFO_ROUNDS {
            return Err(AuthFailure::new(
                FailureClass::AuthenticationLocallyUnavailable,
                "keyboard-interactive sent too many empty prompt rounds",
            ));
        }
        return Ok(KeyboardInteractiveDecision::EmptyInfoRound);
    }

    if answered_secret || prompt_echoes.len() != 1 || prompt_echoes[0] {
        return Err(AuthFailure::new(
            FailureClass::AuthenticationLocallyUnavailable,
            "keyboard-interactive prompt shape is unsupported",
        ));
    }
    Ok(KeyboardInteractiveDecision::SecretResponse)
}

async fn authenticate_with_profile<H: russh::client::Handler>(
    session: &mut russh::client::Handle<H>,
    context: &AuthContext,
    profile: &AuthProfile,
    cancel: &CancellationToken,
) -> Result<(), AuthFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    match &profile.method {
        AuthMethod::PublicKey { identities } => {
            authenticate_public_key(session, context, &profile.user, identities, cancel).await
        }
        AuthMethod::Password(secret) => {
            let password = context
                .resolve_secret_cancellable(&secret.secret, cancel)
                .await
                .map_err(|error| {
                    AuthFailure::new(
                        error.class(),
                        format!("secret {} unavailable", secret.secret),
                    )
                })?;
            let result = session
                .authenticate_password(profile.user.as_str(), password.as_str())
                .await
                .map_err(protocol_failure)?;
            auth_result(result)
        }
        AuthMethod::KeyboardInteractive(secret) => {
            authenticate_keyboard_interactive(
                session,
                context,
                &profile.user,
                &secret.secret,
                cancel,
            )
            .await
        }
    }
}

async fn authenticate_public_key<H: russh::client::Handler>(
    session: &mut russh::client::Handle<H>,
    context: &AuthContext,
    user: &str,
    identities: &[PublicKeyIdentity],
    cancel: &CancellationToken,
) -> Result<(), AuthFailure> {
    let mut rejected = false;
    for identity in identities {
        if cancel.is_cancelled() {
            return Err(cancellation_failure());
        }
        match authenticate_identity(session, context, user, identity, cancel).await {
            Ok(()) => return Ok(()),
            Err(error) if error.is_rejection() => rejected = true,
            Err(error) => return Err(error),
        }
    }
    if rejected {
        Err(AuthFailure::new(
            FailureClass::AuthenticationRejected,
            "public-key authentication was rejected",
        ))
    } else {
        Err(AuthFailure::new(
            FailureClass::AuthenticationLocallyUnavailable,
            "no usable public-key identity was available",
        ))
    }
}

async fn authenticate_identity<H: russh::client::Handler>(
    session: &mut russh::client::Handle<H>,
    context: &AuthContext,
    user: &str,
    identity: &PublicKeyIdentity,
    cancel: &CancellationToken,
) -> Result<(), AuthFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    match identity {
        PublicKeyIdentity::File { path, passphrase } => {
            let key_path = context.config_path(path);
            let mut encoded_bytes = read_secret_file(&key_path, false).map_err(|_| {
                AuthFailure::new(
                    FailureClass::AuthenticationLocallyUnavailable,
                    "configured private-key file is unavailable",
                )
            })?;
            std::str::from_utf8(&encoded_bytes).map_err(|_| {
                AuthFailure::new(
                    FailureClass::AuthenticationLocallyUnavailable,
                    "configured private-key file is not UTF-8",
                )
            })?;
            let encoded = Zeroizing::new(
                String::from_utf8(std::mem::take(&mut *encoded_bytes))
                    .expect("private-key bytes were validated as UTF-8"),
            );
            let key = {
                let passphrase_value = if let Some(passphrase) = passphrase {
                    Some(
                        context
                            .resolve_secret_cancellable(&passphrase.secret, cancel)
                            .await
                            .map_err(|error| {
                                AuthFailure::new(
                                    error.class(),
                                    format!(
                                        "private-key passphrase {} unavailable",
                                        passphrase.secret
                                    ),
                                )
                            })?,
                    )
                } else {
                    None
                };
                decode_secret_key(
                    &encoded,
                    passphrase_value.as_ref().map(|secret| secret.as_str()),
                )
            }
            .map_err(|_| {
                AuthFailure::new(
                    FailureClass::AuthenticationLocallyUnavailable,
                    "configured private-key file could not be decoded",
                )
            })?;
            let hash = session
                .best_supported_rsa_hash()
                .await
                .map_err(protocol_failure)?
                .flatten();
            let result = session
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(protocol_failure)?;
            auth_result(result)
        }
        PublicKeyIdentity::Agent { selector } => {
            let socket = ssh_auth_sock(context).ok_or_else(|| {
                AuthFailure::new(
                    FailureClass::AuthenticationLocallyUnavailable,
                    "SSH_AUTH_SOCK is unavailable for configured agent identity",
                )
            })?;
            let mut agent = AgentClient::connect_uds(Path::new(socket))
                .await
                .map_err(|_| {
                    AuthFailure::new(
                        FailureClass::AuthenticationLocallyUnavailable,
                        "configured SSH agent is unavailable",
                    )
                })?;
            let identities = agent.request_identities().await.map_err(|_| {
                AuthFailure::new(
                    FailureClass::AuthenticationLocallyUnavailable,
                    "configured SSH agent did not return identities",
                )
            })?;
            let selected = selected_agent_key(context, selector, identities.iter())?;
            let hash = session
                .best_supported_rsa_hash()
                .await
                .map_err(protocol_failure)?
                .flatten();
            let result = session
                .authenticate_publickey_with(user, selected, hash, &mut agent)
                .await
                .map_err(agent_sign_failure)?;
            auth_result(result)
        }
    }
}

async fn authenticate_keyboard_interactive<H: russh::client::Handler>(
    session: &mut russh::client::Handle<H>,
    context: &AuthContext,
    user: &str,
    secret_name: &str,
    cancel: &CancellationToken,
) -> Result<(), AuthFailure> {
    if cancel.is_cancelled() {
        return Err(cancellation_failure());
    }
    let mut response = session
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .map_err(protocol_failure)?;
    let mut empty_rounds = 0u8;
    let mut answered_secret = false;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(()),
            KeyboardInteractiveAuthResponse::Failure { .. } => {
                return Err(AuthFailure::new(
                    FailureClass::AuthenticationRejected,
                    "keyboard-interactive authentication was rejected",
                ));
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } if prompts.is_empty() => {
                keyboard_interactive_prompt_decision(&mut empty_rounds, answered_secret, &[])?;
                response = session
                    .authenticate_keyboard_interactive_respond_secure(Zeroizing::new(Vec::new()))
                    .await
                    .map_err(protocol_failure)?;
            }
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let prompt_echoes = prompts.iter().map(|prompt| prompt.echo).collect::<Vec<_>>();
                keyboard_interactive_prompt_decision(
                    &mut empty_rounds,
                    answered_secret,
                    &prompt_echoes,
                )?;
                let secret = context
                    .resolve_secret_cancellable(secret_name, cancel)
                    .await
                    .map_err(|error| {
                        AuthFailure::new(error.class(), format!("secret {secret_name} unavailable"))
                    })?;
                let mut responses = Zeroizing::new(Vec::with_capacity(1));
                let mut secret_response = String::with_capacity(secret.len());
                secret_response.push_str(secret.as_str());
                responses.push(secret_response);
                response = session
                    .authenticate_keyboard_interactive_respond_secure(responses)
                    .await
                    .map_err(protocol_failure)?;
                answered_secret = true;
            }
        }
    }
}

fn selected_agent_key<'a>(
    context: &AuthContext,
    selector: &AgentSelector,
    identities: impl Iterator<Item = &'a russh::keys::agent::AgentIdentity>,
) -> Result<PublicKey, AuthFailure> {
    match selector {
        AgentSelector::Fingerprint(expected) => identities
            .map(|identity| identity.public_key().into_owned())
            .find(|key| key.fingerprint(HashAlg::Sha256).to_string() == *expected)
            .ok_or_else(missing_agent_identity),
        AgentSelector::PublicKeyPath(path) => {
            let expected = load_selector_public_key(&context.config_path(path))?;
            identities
                .map(|identity| identity.public_key().into_owned())
                .find(|key| key.key_data() == expected.key_data())
                .ok_or_else(missing_agent_identity)
        }
    }
}

fn load_selector_public_key(path: &Path) -> Result<PublicKey, AuthFailure> {
    let bytes = read_secret_file(path, true).map_err(|_| {
        AuthFailure::new(
            FailureClass::AuthenticationLocallyUnavailable,
            "configured public-key selector file is unavailable",
        )
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        AuthFailure::new(
            FailureClass::AuthenticationLocallyUnavailable,
            "configured public-key selector file is not UTF-8",
        )
    })?;
    let key = text
        .split_whitespace()
        .nth(1)
        .or_else(|| text.split_whitespace().next())
        .ok_or_else(|| {
            AuthFailure::new(
                FailureClass::AuthenticationLocallyUnavailable,
                "configured public-key selector file is empty",
            )
        })?;
    parse_public_key_base64(key).map_err(|_| {
        AuthFailure::new(
            FailureClass::AuthenticationLocallyUnavailable,
            "configured public-key selector file could not be decoded",
        )
    })
}

fn ssh_auth_sock(context: &AuthContext) -> Option<&OsString> {
    context
        .secret_context
        .env_snapshot()
        .iter()
        .find(|(name, value)| name.as_os_str() == "SSH_AUTH_SOCK" && !value.is_empty())
        .map(|(_, value)| value)
}

fn auth_result(result: AuthResult) -> Result<(), AuthFailure> {
    if result.success() {
        Ok(())
    } else {
        Err(AuthFailure::new(
            FailureClass::AuthenticationRejected,
            "authentication was rejected",
        ))
    }
}

fn protocol_failure(error: russh::Error) -> AuthFailure {
    AuthFailure::new(
        FailureClass::Protocol,
        format!("SSH authentication protocol failure: {error}"),
    )
}

fn agent_sign_failure(error: russh::AgentAuthError) -> AuthFailure {
    match error {
        russh::AgentAuthError::Send(_) => protocol_failure(russh::Error::SendError),
        russh::AgentAuthError::Key(_) => AuthFailure::new(
            FailureClass::AuthenticationLocallyUnavailable,
            "configured SSH agent could not sign",
        ),
    }
}

impl AuthContext {
    async fn resolve_secret_cancellable(
        &self,
        name: &str,
        cancel: &CancellationToken,
    ) -> Result<crate::secret::OwnedSecret, crate::secret::SecretFailure> {
        self.secret_context
            .resolve_owned_cancellable(name, cancel)
            .await
    }
}

fn cancellation_failure() -> AuthFailure {
    AuthFailure::new(FailureClass::Cancellation, "cancelled")
}

fn missing_agent_identity() -> AuthFailure {
    AuthFailure::new(
        FailureClass::AuthenticationLocallyUnavailable,
        "configured agent identity was not offered by SSH agent",
    )
}

