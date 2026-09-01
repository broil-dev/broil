// Modified by the Broil project from russh 0.62.5; see LICENSE.txt and docs/provenance/russh-0.62.5.md for provenance.
// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std::future::Future;
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use ssh_key::{Certificate, HashAlg, PrivateKey};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::helpers::NameList;
use crate::keys::PrivateKeyWithHashAlg;
use crate::keys::agent::AgentIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    None,
    Password,
    PublicKey,
    HostBased,
    KeyboardInteractive,
}

impl From<&MethodKind> for &'static str {
    fn from(value: &MethodKind) -> Self {
        match value {
            MethodKind::None => "none",
            MethodKind::Password => "password",
            MethodKind::PublicKey => "publickey",
            MethodKind::HostBased => "hostbased",
            MethodKind::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

impl FromStr for MethodKind {
    fn from_str(b: &str) -> Result<MethodKind, Self::Err> {
        match b {
            "none" => Ok(MethodKind::None),
            "password" => Ok(MethodKind::Password),
            "publickey" => Ok(MethodKind::PublicKey),
            "hostbased" => Ok(MethodKind::HostBased),
            "keyboard-interactive" => Ok(MethodKind::KeyboardInteractive),
            _ => Err(()),
        }
    }

    type Err = ();
}

impl From<&MethodKind> for String {
    fn from(value: &MethodKind) -> Self {
        <&str>::from(value).to_string()
    }
}

/// An ordered set of authentication methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSet {
    methods: Vec<MethodKind>,
    has_unknown: bool,
}

impl Deref for MethodSet {
    type Target = [MethodKind];

    fn deref(&self) -> &Self::Target {
        &self.methods
    }
}

impl From<&[MethodKind]> for MethodSet {
    fn from(value: &[MethodKind]) -> Self {
        let mut this = Self::empty();
        for method in value {
            this.push(*method);
        }
        this
    }
}

impl From<&MethodSet> for NameList {
    fn from(value: &MethodSet) -> Self {
        Self(value.iter().map(|x| x.into()).collect())
    }
}

impl From<&NameList> for MethodSet {
    fn from(value: &NameList) -> Self {
        let mut methods = Vec::new();
        let mut has_unknown = false;
        for method in value.iter() {
            match MethodKind::from_str(method) {
                Ok(method) => methods.push(method),
                Err(()) => has_unknown = true,
            }
        }
        Self {
            methods,
            has_unknown,
        }
    }
}

impl MethodSet {
    pub fn empty() -> Self {
        Self {
            methods: Vec::new(),
            has_unknown: false,
        }
    }

    pub fn all() -> Self {
        Self {
            methods: vec![
                MethodKind::None,
                MethodKind::Password,
                MethodKind::PublicKey,
                MethodKind::HostBased,
                MethodKind::KeyboardInteractive,
            ],
            has_unknown: false,
        }
    }

    pub fn has_unknown(&self) -> bool {
        self.has_unknown
    }

    pub fn remove(&mut self, method: MethodKind) {
        self.methods.retain(|x| *x != method);
    }

    /// Push a method to the end of the list.
    /// If the method is already in the list, it is moved to the end.
    pub fn push(&mut self, method: MethodKind) {
        self.remove(method);
        self.methods.push(method);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_set_preserves_unknown_method_signal() {
        let names = NameList(vec![
            "publickey".to_string(),
            "future-method".to_string(),
            "hostbased".to_string(),
        ]);

        let methods = MethodSet::from(&names);

        assert_eq!(&*methods, [MethodKind::PublicKey, MethodKind::HostBased]);
        assert!(methods.has_unknown());
    }

    #[test]
    fn method_set_known_names_have_no_unknown_signal() {
        let names = NameList(vec!["publickey".to_string()]);

        let methods = MethodSet::from(&names);

        assert_eq!(&*methods, [MethodKind::PublicKey]);
        assert!(!methods.has_unknown());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Success,
    Failure {
        /// The server suggests to proceed with these auth methods
        remaining_methods: MethodSet,
        /// The server says that though auth method has been accepted,
        /// further authentication is required
        partial_success: bool,
    },
}

impl AuthResult {
    pub fn success(&self) -> bool {
        matches!(self, AuthResult::Success)
    }
}

#[cfg_attr(feature = "async-trait", async_trait::async_trait)]
pub trait Signer: Sized {
    type Error: From<crate::SendError>;

    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send;
}

#[derive(Debug, Error)]
pub enum AgentAuthError {
    #[error(transparent)]
    Send(#[from] crate::SendError),
    #[error(transparent)]
    Key(#[from] crate::keys::Error),
}

#[cfg_attr(feature = "async-trait", async_trait::async_trait)]
impl<R: AsyncRead + AsyncWrite + Unpin + Send> Signer
    for crate::keys::agent::client::AgentClient<R>
{
    type Error = AgentAuthError;

    #[allow(clippy::manual_async_fn)]
    fn auth_sign(
        &mut self,
        key: &AgentIdentity,
        hash_alg: Option<HashAlg>,
        to_sign: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>> {
        async move {
            self.sign_request(key, hash_alg, to_sign)
                .await
                .map_err(Into::into)
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum Method {
    None,
    Password {
        password: Zeroizing<String>,
    },
    PublicKey {
        key: PrivateKeyWithHashAlg,
    },
    OpenSshCertificate {
        key: Arc<PrivateKey>,
        cert: Certificate,
    },
    FuturePublicKey {
        key: ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
    },
    /// Certificate-based authentication using an external signer (e.g., SSH agent).
    /// The certificate is sent to the server, but signing is delegated to the signer.
    FutureCertificate {
        cert: Certificate,
        hash_alg: Option<HashAlg>,
    },
    KeyboardInteractive {
        submethods: String,
    },
    // Hostbased,
}

impl Debug for Method {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Password { .. } => f
                .debug_struct("Password")
                .field("password", &"[REDACTED]")
                .finish(),
            Self::PublicKey { .. } => f
                .debug_struct("PublicKey")
                .field("key", &"[REDACTED]")
                .finish(),
            Self::OpenSshCertificate { cert, .. } => f
                .debug_struct("OpenSshCertificate")
                .field("key", &"[REDACTED]")
                .field("cert", cert)
                .finish(),
            Self::FuturePublicKey { key, hash_alg } => f
                .debug_struct("FuturePublicKey")
                .field("key", key)
                .field("hash_alg", hash_alg)
                .finish(),
            Self::FutureCertificate { cert, hash_alg } => f
                .debug_struct("FutureCertificate")
                .field("cert", cert)
                .field("hash_alg", hash_alg)
                .finish(),
            Self::KeyboardInteractive { submethods } => f
                .debug_struct("KeyboardInteractive")
                .field("submethods", submethods)
                .finish(),
        }
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct AuthRequest {
    initial_methods: MethodSet,
    pub methods: MethodSet,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub partial_success: bool,
    pub current: Option<CurrentRequest>,
    pub(crate) principal: Option<AuthPrincipal>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub rejection_count: usize,
}

#[doc(hidden)]
#[derive(Debug)]
pub(crate) struct AuthPrincipal {
    user: String,
    service: String,
}

#[doc(hidden)]
#[derive(Debug)]
pub enum CurrentRequest {
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    PublicKey {
        #[allow(dead_code)]
        key: Vec<u8>,
        #[allow(dead_code)]
        algo: Vec<u8>,
        sent_pk_ok: bool,
    },
    KeyboardInteractive {
        #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
        submethods: String,
    },
}

impl AuthRequest {
    pub(crate) fn server(methods: MethodSet) -> Self {
        Self {
            initial_methods: methods.clone(),
            methods,
            partial_success: false,
            current: None,
            principal: None,
            rejection_count: 0,
        }
    }

    pub(crate) fn new(method: &Method) -> Self {
        match method {
            Method::KeyboardInteractive { submethods } => Self {
                initial_methods: MethodSet::all(),
                methods: MethodSet::all(),
                partial_success: false,
                current: Some(CurrentRequest::KeyboardInteractive {
                    submethods: submethods.to_string(),
                }),
                principal: None,
                rejection_count: 0,
            },
            _ => Self {
                initial_methods: MethodSet::all(),
                methods: MethodSet::all(),
                partial_success: false,
                current: None,
                principal: None,
                rejection_count: 0,
            },
        }
    }

    pub(crate) fn bind_or_reset_principal(&mut self, user: &str, service: &str) -> bool {
        match &self.principal {
            Some(bound) if bound.user == user && bound.service == service => false,
            _ => {
                self.principal = Some(AuthPrincipal {
                    user: user.to_owned(),
                    service: service.to_owned(),
                });
                self.methods = self.initial_methods.clone();
                self.partial_success = false;
                self.current = None;
                true
            }
        }
    }
}
