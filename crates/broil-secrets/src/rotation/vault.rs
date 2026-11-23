// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    age::Identity,
    output,
    read::{Error, Result, Selection},
    sops::{MAX_DOCUMENT_BYTES, ScalarKind},
    store::{IdentityNames, SetId, Store},
    vault::{Client, Session, json::Text, session::Credentials},
};
use broil_core::secret::OwnedSecret;
use std::ffi::OsString;

pub(super) struct Remote {
    selected: Selection,
    name: Option<String>,
    name_hint: Result<Option<OwnedSecret>>,
    caller: Option<OwnedSecret>,
    address: Option<OsString>,
    session: Option<Session>,
}
impl Remote {
    pub(super) fn new(
        selected: Selection,
        name: Option<String>,
        name_hint: Result<Option<OwnedSecret>>,
        caller: Option<OwnedSecret>,
        address: Option<OsString>,
    ) -> Self {
        let configured = selected.config.vault.address.is_some();
        let need_hint = configured
            && selected.config.vault.credential.is_none()
            && name.is_none()
            && selected.config.identity.is_none();
        Self {
            selected,
            name,
            name_hint: if need_hint {
                name_hint
            } else {
                drop(name_hint);
                Ok(None)
            },
            caller: if configured { caller } else { None },
            address: if configured { address } else { None },
            session: None,
        }
    }
    fn open(&mut self, store: &Store, keys: &[Identity]) -> Result<()> {
        if self.session.is_some() || self.selected.config.vault.address.is_none() {
            return Ok(());
        }
        let address = self
            .address
            .take()
            .filter(|a| !a.is_empty())
            .map(|a| a.into_string().map_err(|_| Error::class("vault address")))
            .transpose()?
            .unwrap_or_else(|| self.selected.config.vault.address.clone().unwrap());
        let sealed = Client::new(&address)?.health()?.sealed;
        let credentials = if self.caller.is_none() || sealed {
            let path = if let Some(path) = &self.selected.config.vault.credential {
                path.clone()
            } else {
                let name = if let Some(name) = self
                    .name
                    .clone()
                    .or_else(|| self.selected.config.identity.clone())
                {
                    name
                } else if let Some(hint) = std::mem::replace(&mut self.name_hint, Ok(None))? {
                    crate::store::validate_component(hint.as_str())
                        .map_err(|_| Error::class("vault credential identity input"))?;
                    hint.as_str().to_owned()
                } else {
                    match store.identity_names().map_err(Error::store)? {
                        IdentityNames::Sole(name) => name,
                        _ => {
                            return Err(Error::class(
                                "recorded vault credential identity unavailable",
                            ));
                        }
                    }
                };
                format!("credentials/{name}.yaml")
            };
            let document = store
                .read_private_document(&path, keys)
                .map_err(Error::store)?;
            let field = |name| -> Result<Option<Text>> {
                document
                    .get(name)
                    .map(|value| {
                        let value = value
                            .scalar()
                            .filter(|v| {
                                v.kind() == ScalarKind::String
                                    && !v.as_str().is_empty()
                                    && !v.as_str().contains('\0')
                            })
                            .ok_or(Error::class("vault credential fields"))?;
                        Ok(Text::copy(value.as_str())?)
                    })
                    .transpose()
            };
            Some(Credentials {
                role: field("role_id")?.ok_or(Error::class("vault credential fields"))?,
                secret: field("secret_id")?.ok_or(Error::class("vault credential fields"))?,
                unseal: field("unseal_key")?,
            })
        } else {
            None
        };
        let result = Session::administrative(
            &address,
            self.caller.as_ref().map(OwnedSecret::as_str),
            credentials.as_ref(),
        );
        self.caller.take();
        self.name_hint = Ok(None);
        drop(credentials);
        self.session = Some(result?);
        Ok(())
    }
    pub(super) fn gate(
        &mut self,
        store: &Store,
        keys: &[Identity],
        set: &SetId,
        key: &str,
    ) -> Result<()> {
        self.open(store, keys)?;
        let document = store.read(set, keys).map_err(Error::store)?;
        document.check_rotation(key).map_err(Error::store)?;
        let expected = document
            .get(key)
            .ok_or(Error::class("missing current value"))?
            .duplicate()
            .map_err(|_| Error::class("current value allocation"))?;
        let values = if self.session.is_some() {
            Some(output::prepare(MAX_DOCUMENT_BYTES, |w| {
                w.text("{")?;
                for (i, key) in document.keys().iter().enumerate() {
                    if i > 0 {
                        w.text(",")?;
                    }
                    output::json_string(w, key)?;
                    w.text(":")?;
                    output::json(w, document.get(key).unwrap())?;
                }
                w.text("}")
            })?)
        } else {
            None
        };
        drop(document);
        let mount = self
            .selected
            .config
            .vault
            .mount
            .as_deref()
            .unwrap_or("secret");
        if let (Some(session), Some(values)) = (&mut self.session, values) {
            session.write_set(mount, set, &values)?;
        }
        let fresh = store.read(set, keys).map_err(Error::store)?;
        fresh.check_rotation(key).map_err(Error::store)?;
        if !fresh.get(key).is_some_and(|v| v.same(&expected)) {
            return Err(Error::class("authenticated current readback mismatch"));
        }
        drop(fresh);
        if let Some(session) = &mut self.session {
            let values = session.read_set(mount, set)?;
            let actual = values
                .get(key)
                .ok_or(Error::class("vault current readback missing"))?
                .render(true, false)?;
            drop(values);
            let expected = output::prepare(MAX_DOCUMENT_BYTES, |w| output::json(w, &expected))?;
            if actual.as_bytes() != expected.as_bytes() {
                return Err(Error::class("vault current readback mismatch"));
            }
        }
        Ok(())
    }
    pub(super) fn finish(&mut self) -> Result<()> {
        if let Some(mut session) = self.session.take() {
            session.cleanup()?;
        }
        Ok(())
    }
}
