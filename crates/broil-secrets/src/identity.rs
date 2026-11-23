// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    age::{self, Identity},
    read::{Error, Result},
    store::{self, IdentityNames, Store},
};
use broil_core::{
    secret::{
        OwnedSecret, environment::CredentialInputs, normalize_path,
        prompt_private_bounded_cancellable,
    },
    secrets::valid_component,
};
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path, sync::Arc};

type WaitingHook = Arc<dyn Fn() -> Box<dyn Send> + Send + Sync>;

#[derive(Clone, Default)]
pub struct AcquisitionControl {
    cancelled: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    waiting: Option<WaitingHook>,
}
impl AcquisitionControl {
    pub fn new(
        cancelled: impl Fn() -> bool + Send + Sync + 'static,
        waiting: impl Fn() -> Box<dyn Send> + Send + Sync + 'static,
    ) -> Self {
        Self {
            cancelled: Some(Arc::new(cancelled)),
            waiting: Some(Arc::new(waiting)),
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.as_ref().is_some_and(|f| f())
    }
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::class("secret acquisition cancelled"))
        } else {
            Ok(())
        }
    }
    fn prompt(&self, label: &str, hidden: bool) -> Result<OwnedSecret> {
        self.check()?;
        let _waiting = self.waiting.as_ref().map(|f| f());
        let value = prompt_private_bounded_cancellable(
            label,
            hidden,
            broil_core::secret::MAX_CREDENTIAL_PROMPT_VALUE_BYTES,
            &|| self.is_cancelled(),
        )
        .map_err(|_| Error::class("identity prompt"))?;
        self.check()?;
        if value.is_empty() {
            return Err(Error::class("identity prompt"));
        }
        Ok(value)
    }
}

pub fn may_prompt(
    store: &Store,
    configured: Option<&str>,
    inputs: &CredentialInputs,
    need_name: bool,
) -> bool {
    let raw = inputs.contains("SOPS_AGE_KEY") || inputs.contains("SOPS_AGE_KEY_FILE");
    if raw && !need_name {
        return false;
    }
    if configured.is_none() && !inputs.contains("BROIL_SECRETS_IDENTITY") {
        match store.identity_names() {
            Ok(IdentityNames::Multiple(_)) => return true,
            Ok(IdentityNames::Sole(_)) => (),
            _ => return false,
        }
    }
    !raw && !inputs.contains("BROIL_SECRETS_PASSPHRASE")
}

pub fn acquire(
    store: &Store,
    cwd: &Path,
    configured: Option<&str>,
    inputs: CredentialInputs,
    non_interactive: bool,
) -> Result<Vec<Identity>> {
    Ok(acquire_named(store, cwd, configured, inputs, non_interactive, false)?.keys)
}

pub struct Acquired {
    pub keys: Vec<Identity>,
    pub name: Option<String>,
}
pub fn acquire_named(
    store: &Store,
    cwd: &Path,
    configured: Option<&str>,
    inputs: CredentialInputs,
    non_interactive: bool,
    need_name: bool,
) -> Result<Acquired> {
    acquire_named_controlled(
        store,
        cwd,
        configured,
        inputs,
        non_interactive,
        need_name,
        &AcquisitionControl::default(),
    )
}

pub fn acquire_named_controlled(
    store: &Store,
    cwd: &Path,
    configured: Option<&str>,
    mut inputs: CredentialInputs,
    non_interactive: bool,
    need_name: bool,
    control: &AcquisitionControl,
) -> Result<Acquired> {
    control.check()?;
    if let Some(raw) = inputs
        .take("SOPS_AGE_KEY")
        .map_err(|_| Error::class("identity input"))?
    {
        let raw = raw
            .into_secret()
            .map_err(|_| Error::class("identity input"))?;
        let keys = age::parse_identity_file(&raw).map_err(|_| Error::class("identity input"))?;
        drop(raw);
        control.check()?;
        let name = if need_name {
            Some(select_name(
                store,
                configured,
                &mut inputs,
                non_interactive,
                control,
            )?)
        } else {
            None
        };
        return Ok(Acquired { keys, name });
    }
    if let Some(file) = inputs
        .take("SOPS_AGE_KEY_FILE")
        .map_err(|_| Error::class("identity input"))?
    {
        let path = normalize_path(cwd, Path::new(OsStr::from_bytes(file.as_bytes())));
        let keys = store::read_raw_identity(&path).map_err(|_| Error::class("identity file"))?;
        control.check()?;
        let name = if need_name {
            Some(select_name(
                store,
                configured,
                &mut inputs,
                non_interactive,
                control,
            )?)
        } else {
            None
        };
        return Ok(Acquired { keys, name });
    }
    let named = select_name(store, configured, &mut inputs, non_interactive, control)?;
    let passphrase: OwnedSecret = if let Some(pass) = inputs
        .take("BROIL_SECRETS_PASSPHRASE")
        .map_err(|_| Error::class("passphrase input"))?
    {
        drop(inputs);
        pass.into_secret()
            .map_err(|_| Error::class("passphrase input"))?
    } else {
        drop(inputs);
        if non_interactive {
            return Err(Error::class("passphrase unavailable"));
        }
        control
            .prompt(
                &format!("Passphrase for {}", super::output::public_name(&named)),
                true,
            )
            .map_err(|_| Error::class("passphrase prompt"))?
    };
    if passphrase.is_empty() || passphrase.as_str().contains('\0') {
        return Err(Error::class("passphrase input"));
    }
    control.check()?;
    let keys = store
        .unlock_identity(&named, &passphrase)
        .map_err(|_| Error::class("identity decrypt"))?;
    control.check()?;
    Ok(Acquired {
        keys,
        name: Some(named),
    })
}

fn select_name(
    store: &Store,
    configured: Option<&str>,
    inputs: &mut CredentialInputs,
    non_interactive: bool,
    control: &AcquisitionControl,
) -> Result<String> {
    control.check()?;
    let named = if let Some(name) = configured {
        name.to_owned()
    } else if let Some(name) = inputs
        .take("BROIL_SECRETS_IDENTITY")
        .map_err(|_| Error::class("identity input"))?
    {
        let name =
            std::str::from_utf8(name.as_bytes()).map_err(|_| Error::class("identity name"))?;
        if !valid_component(name) {
            return Err(Error::class("identity name"));
        }
        name.to_owned()
    } else {
        match store.identity_names().map_err(Error::store)? {
            IdentityNames::Sole(name) => name,
            IdentityNames::None => return Err(Error::class("no identity")),
            IdentityNames::Multiple(names) => {
                if non_interactive {
                    return Err(Error::class("ambiguous identity"));
                }
                let label = format!(
                    "Identity ({})",
                    names
                        .iter()
                        .map(|n| super::output::public_name(n))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                let name = control.prompt(&label, false)?;
                if !names.iter().any(|n| n == name.as_str()) {
                    return Err(Error::class("identity name"));
                }
                name.as_str().to_owned()
            }
        }
    };
    Ok(named)
}
