// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Client, Error, Result, json::Text, transport::token_valid};
use crate::{
    age::Identity,
    identity,
    output::{self, Prepared},
    read::Selection,
    sops::ScalarKind,
    store::{SetId, Store},
};
use broil_core::secret::environment::CredentialInputs;
use std::path::Path;

pub struct Credentials {
    pub role: Text,
    pub secret: Text,
    pub unseal: Option<Text>,
}
pub struct Session {
    pub client: Client,
    token: Option<Text>,
    owned: bool,
}

pub fn address(
    selected: &Selection,
    inputs: &mut CredentialInputs,
    explicit: bool,
) -> Result<String> {
    if !explicit && selected.config.vault.address.is_none() {
        return Err(Error::runtime("no configured vault"));
    }
    let ambient = inputs.vault_address.take().filter(|v| !v.is_empty());
    if let Some(ambient) = ambient {
        return ambient
            .into_string()
            .map_err(|_| Error::runtime("invalid vault address"));
    }
    selected
        .config
        .vault
        .address
        .clone()
        .ok_or(Error::runtime("no selected vault address"))
}
pub fn credentials(
    selected: &Selection,
    cwd: &Path,
    inputs: &mut CredentialInputs,
    non_interactive: bool,
    keys: &mut Option<Vec<Identity>>,
) -> Result<Credentials> {
    credentials_controlled(
        selected,
        cwd,
        inputs,
        non_interactive,
        keys,
        &identity::AcquisitionControl::default(),
    )
}

fn credentials_controlled(
    selected: &Selection,
    cwd: &Path,
    inputs: &mut CredentialInputs,
    non_interactive: bool,
    keys: &mut Option<Vec<Identity>>,
    control: &identity::AcquisitionControl,
) -> Result<Credentials> {
    control.check()?;
    let store = Store::open(&selected.store_root())
        .map_err(|_| Error::runtime("credential store access failed"))?;
    let acquired = identity::acquire_named_controlled(
        &store,
        cwd,
        selected.config.identity.as_deref(),
        std::mem::take(inputs),
        non_interactive,
        selected.config.vault.credential.is_none(),
        control,
    )
    .map_err(|_| Error::identity())?;
    let path = if let Some(path) = &selected.config.vault.credential {
        path.clone()
    } else {
        let name = acquired.name.as_deref().ok_or(Error::runtime(
            "vault credential path or identity name required",
        ))?;
        format!("credentials/{name}.yaml")
    };
    control.check()?;
    let document = store
        .read_private_document(&path, &acquired.keys)
        .map_err(|e| match e.kind {
            crate::store::ErrorKind::Sops(_) | crate::store::ErrorKind::Identity => {
                Error::identity()
            }
            _ => Error::runtime("private credential file access failed"),
        })?;
    control.check()?;
    let field = |key: &str| -> Result<Option<Text>> {
        let Some(value) = document.get(key) else {
            return Ok(None);
        };
        let value = value
            .scalar()
            .filter(|s| s.kind() == ScalarKind::String)
            .ok_or(Error::runtime("invalid credential fields"))?;
        if value.as_str().is_empty() || value.as_str().contains('\0') {
            return Err(Error::runtime("invalid credential fields"));
        }
        Ok(Some(Text::copy(value.as_str())?))
    };
    let result = Credentials {
        role: field("role_id")?.ok_or(Error::runtime("missing credential fields"))?,
        secret: field("secret_id")?.ok_or(Error::runtime("missing credential fields"))?,
        unseal: field("unseal_key")?,
    };
    drop(document);
    *keys = Some(acquired.keys);
    Ok(result)
}
impl Session {
    pub(crate) fn administrative(
        address: &str,
        caller: Option<&str>,
        credentials: Option<&Credentials>,
    ) -> Result<Self> {
        if caller.is_some_and(|t| !token_valid(t)) {
            return Err(Error::runtime("invalid vault token input"));
        }
        let mut client = Client::new(address)?;
        let health = client.health()?;
        if !health.initialized {
            return Err(Error::runtime("vault server setup required"));
        }
        if health.sealed {
            let key = credentials
                .and_then(|c| c.unseal.as_ref())
                .ok_or(Error::runtime("vault sealed; unseal key unavailable"))?;
            client.unseal(key.as_str())?;
            let health = client.health()?;
            if !health.initialized || health.sealed {
                return Err(Error::runtime("vault remains sealed or uninitialized"));
            }
        }
        let token = if let Some(token) = caller {
            Text::copy(token)?
        } else {
            let credentials = credentials.ok_or(Error::runtime("operator credentials required"))?;
            client.login(credentials.role.as_str(), credentials.secret.as_str())?
        };
        Ok(Self {
            client,
            token: Some(token),
            owned: caller.is_none(),
        })
    }
    pub(crate) fn parts(&mut self) -> (&mut Client, &str) {
        (
            &mut self.client,
            self.token
                .as_ref()
                .expect("live administrative session")
                .as_str(),
        )
    }
    pub(crate) fn inspection(
        address: &str,
        caller: Option<&str>,
        credentials: Option<&Credentials>,
    ) -> Result<Self> {
        if caller.is_some_and(|t| !token_valid(t)) {
            return Err(Error::runtime("invalid vault token input"));
        }
        let mut client = Client::new(address)?;
        let health = client.health()?;
        if !health.initialized || health.sealed {
            return Err(Error::runtime("vault inspection unavailable"));
        }
        let token = if let Some(caller) = caller {
            Text::copy(caller)?
        } else {
            let credentials =
                credentials.ok_or(Error::runtime("inspection credentials unavailable"))?;
            client.login(credentials.role.as_str(), credentials.secret.as_str())?
        };
        Ok(Self {
            client,
            token: Some(token),
            owned: caller.is_none(),
        })
    }
    pub fn open(
        selected: &Selection,
        cwd: &Path,
        inputs: &mut CredentialInputs,
        non_interactive: bool,
        keys: &mut Option<Vec<Identity>>,
        explicit: bool,
    ) -> Result<Self> {
        Self::open_controlled(
            selected,
            cwd,
            inputs,
            non_interactive,
            keys,
            explicit,
            &identity::AcquisitionControl::default(),
        )
    }
    pub fn open_controlled(
        selected: &Selection,
        cwd: &Path,
        inputs: &mut CredentialInputs,
        non_interactive: bool,
        keys: &mut Option<Vec<Identity>>,
        explicit: bool,
        control: &identity::AcquisitionControl,
    ) -> Result<Self> {
        control.check()?;
        let address = address(selected, inputs, explicit)?;
        let caller = inputs
            .take("BAO_TOKEN")
            .map_err(|_| Error::runtime("invalid vault token input"))?;
        let token = caller
            .map(|b| {
                let text = std::str::from_utf8(b.as_bytes())
                    .map_err(|_| Error::runtime("invalid vault token"))?;
                if !token_valid(text) {
                    return Err(Error::runtime("invalid vault token"));
                }
                Text::copy(text)
            })
            .transpose()?;
        let mut client = Client::new(&address)?.with_acquisition_control(control.clone());
        let health = client.health()?;
        if !health.initialized {
            return Err(Error::setup(
                "vault is not initialized; server setup required",
                health.status,
            ));
        }
        let mut credential = if token.is_none() || health.sealed {
            Some(credentials_controlled(
                selected,
                cwd,
                inputs,
                non_interactive,
                keys,
                control,
            )?)
        } else {
            None
        };
        if health.sealed {
            let key = credential
                .as_mut()
                .and_then(|c| c.unseal.take())
                .ok_or(Error::runtime("vault sealed; unseal key unavailable"))?;
            client.unseal(key.as_str())?;
            drop(key);
            let health = client.health()?;
            if !health.initialized || health.sealed {
                return Err(Error::setup(
                    "vault remains sealed or uninitialized",
                    health.status,
                ));
            }
        }
        if let Some(credential) = &mut credential {
            credential.unseal.take();
        }
        let owned = token.is_none();
        let token = if let Some(token) = token {
            token
        } else {
            let credential = credential.as_ref().unwrap();
            client.login(credential.role.as_str(), credential.secret.as_str())?
        };
        drop(credential);
        Ok(Self {
            client,
            token: Some(token),
            owned,
        })
    }
    pub fn token(&self) -> &str {
        self.token.as_ref().expect("live session").as_str()
    }
    pub fn child_spawned(&mut self) {
        if !self.owned {
            self.token.take();
        }
    }
    pub fn handoff(mut self) {
        self.owned = false;
        self.token.take();
    }
    pub fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        let cleanup = self.cleanup();
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (result, Err(_)) => {
                let mut error = result
                    .err()
                    .unwrap_or(Error::runtime("owned token cleanup failed"));
                error.cleanup_failed = true;
                error.fallback = false;
                Err(error)
            }
        }
    }
    pub fn cleanup(&mut self) -> Result<()> {
        let result = if self.owned {
            self.client.revoke(self.token.as_ref().unwrap().as_str())
        } else {
            Ok(())
        };
        self.owned = false;
        self.token.take();
        result
    }
    pub fn read_set(&mut self, mount: &str, set: &SetId) -> Result<super::json::Value> {
        let token = self.token.as_ref().unwrap();
        self.client.read_set(token.as_str(), mount, set.as_str())
    }
    pub fn write_set(&mut self, mount: &str, set: &SetId, values: &Prepared) -> Result<()> {
        let token = self.token.as_ref().unwrap();
        self.client
            .write_set(token.as_str(), mount, set.as_str(), values)
    }
}

#[derive(Default, Debug)]
pub struct SyncReport {
    pub completed: Vec<String>,
    pub error: Option<Error>,
}
pub fn sync(
    selected: &Selection,
    options: &crate::read::Options,
    cwd: &Path,
    mut inputs: CredentialInputs,
) -> SyncReport {
    let mut report = SyncReport::default();
    let result = (|| {
        if selected.config.vault.address.is_none() {
            return Err(Error::runtime("sync requires a configured vault"));
        }
        let store = Store::open(&selected.store_root())
            .map_err(|_| Error::runtime("sync store access failed"))?;
        let sets = if options.all {
            store
                .sets()
                .map_err(|_| Error::runtime("sync set enumeration failed"))?
        } else {
            vec![selected.default_set(options.set.as_deref())?]
        };
        let mut keys = None;
        let mut session = Session::open(
            selected,
            cwd,
            &mut inputs,
            options.non_interactive,
            &mut keys,
            false,
        )?;
        let result = (|| {
            if keys.is_none() {
                keys = Some(
                    identity::acquire(
                        &store,
                        cwd,
                        selected.config.identity.as_deref(),
                        inputs,
                        options.non_interactive,
                    )
                    .map_err(|_| Error::identity())?,
                );
            }
            for set_id in sets {
                let set = store
                    .read(&set_id, keys.as_ref().unwrap())
                    .map_err(|_| Error::runtime("sync authenticated local read failed"))?;
                let values = output::prepare(crate::sops::MAX_DOCUMENT_BYTES, |w| {
                    w.text("{")?;
                    for (i, key) in set.keys().iter().enumerate() {
                        if i > 0 {
                            w.text(",")?;
                        }
                        output::json_string(w, key)?;
                        w.text(":")?;
                        output::json(w, set.get(key).unwrap())?;
                    }
                    w.text("}")
                })?;
                session.write_set(
                    selected.config.vault.mount.as_deref().unwrap_or("secret"),
                    &set_id,
                    &values,
                )?;
                report.completed.push(set_id.as_str().to_owned());
            }
            Ok(())
        })();
        drop(keys);
        session.finish(result)
    })();
    report.error = result.err();
    report
}
