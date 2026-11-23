// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    Error, Result,
    json::{Raw, Text, Value},
    transport::{self, Address, Response},
};
use crate::{
    identity::AcquisitionControl,
    output::{self, Prepared},
    sops::MAX_DOCUMENT_BYTES,
};
use std::{future::Future, time::Duration};
use tokio::{
    runtime::{Builder, Runtime},
    signal::unix::{Signal, SignalKind},
};

pub struct Executor {
    runtime: Option<Runtime>,
    interrupt: Signal,
    terminate: Signal,
    cancelled: bool,
    control: AcquisitionControl,
}
impl Executor {
    fn new() -> Result<Self> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::runtime("vault runtime unavailable"))?;
        let (interrupt, terminate) = {
            let _entered = runtime.enter();
            (
                tokio::signal::unix::signal(SignalKind::interrupt()),
                tokio::signal::unix::signal(SignalKind::terminate()),
            )
        };
        Ok(Self {
            runtime: Some(runtime),
            interrupt: interrupt.map_err(|_| Error::runtime("signal handler unavailable"))?,
            terminate: terminate.map_err(|_| Error::runtime("signal handler unavailable"))?,
            cancelled: false,
            control: AcquisitionControl::default(),
        })
    }
    pub fn enter(&self) -> tokio::runtime::EnterGuard<'_> {
        self.runtime.as_ref().unwrap().enter()
    }
    pub fn run<T>(
        &mut self,
        future: impl Future<Output = Result<T>>,
        timeout: Option<Duration>,
        cleanup: bool,
    ) -> Result<T> {
        if (self.cancelled || self.control.is_cancelled()) && !cleanup {
            return Err(Error::runtime("vault operation cancelled"));
        }
        let cancelled = &mut self.cancelled;
        let interrupt = &mut self.interrupt;
        let terminate = &mut self.terminate;
        let control = &self.control;
        self.runtime.as_ref().unwrap().block_on(async {
            let operation = async {
                if let Some(duration) = timeout {
                    tokio::time::timeout(duration, future).await.map_err(|_| Error::unavailable())?
                } else { future.await }
            };
            if cleanup { return operation.await; }
            tokio::select! {
                biased;
                _ = async {
                    while !control.is_cancelled() {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                } => { *cancelled = true; Err(Error::runtime("vault operation cancelled")) }
                _ = interrupt.recv() => { *cancelled = true; Err(Error::runtime("vault operation cancelled")) }
                _ = terminate.recv() => { *cancelled = true; Err(Error::runtime("vault operation cancelled")) }
                result = operation => result,
            }
        })
    }
}
impl Drop for Executor {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

pub struct Client {
    address: Address,
    pub executor: Executor,
    administrative_cleanup: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct Health {
    pub initialized: bool,
    pub sealed: bool,
    pub status: u16,
}
impl Client {
    pub fn with_acquisition_control(mut self, control: AcquisitionControl) -> Self {
        self.executor.control = control;
        self
    }

    pub fn require_capabilities(
        &mut self,
        token: &str,
        required: &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
    ) -> Result<()> {
        if required.is_empty() || required.len() > 65536 {
            return Err(Error::runtime("invalid capability request"));
        }
        let body = output::prepare(MAX_DOCUMENT_BYTES, |w| {
            w.text("{\"paths\":[")?;
            for (i, path) in required.keys().enumerate() {
                if i > 0 {
                    w.text(",")?;
                }
                output::json_string(w, path)?;
            }
            w.text("]}")
        })?;
        let response = self.success(
            "POST",
            &["sys", "capabilities-self"],
            token,
            Some(&body),
            false,
        )?;
        let data = Raw::parse(response.body.as_bytes())?
            .field("data")?
            .decode()?;
        for (path, needed) in required {
            let Some(Value::Array(values)) = data.get(path) else {
                return Err(Error::runtime("missing vault capability result"));
            };
            let mut capabilities = std::collections::BTreeSet::new();
            for value in values {
                let Value::String(value) = value else {
                    return Err(Error::runtime("malformed vault capability result"));
                };
                if !capabilities.insert(value.as_str()) {
                    return Err(Error::runtime("duplicate vault capability result"));
                }
            }
            if capabilities.contains("deny")
                || (!capabilities.contains("root")
                    && needed.iter().any(|c| !capabilities.contains(c.as_str())))
            {
                return Err(Error::runtime("vault capability preflight denied"));
            }
        }
        Ok(())
    }
    fn optional_data(&mut self, token: &str, path: &[&str]) -> Result<Option<Value>> {
        let response = self.request("GET", path, Some(token), None, false)?;
        if response.status == 404 {
            return Ok(None);
        }
        http_status(response.status)?;
        let data = Raw::parse(response.body.as_bytes())?.field("data")?;
        data.fields()?;
        Ok(Some(data.decode()?))
    }
    pub fn read_role_optional(&mut self, token: &str, role: &str) -> Result<Option<Value>> {
        self.optional_data(token, &["auth", "approle", "role", role])
    }
    pub fn read_policy_optional(&mut self, token: &str, policy: &str) -> Result<Option<Text>> {
        let response = self.request(
            "GET",
            &["sys", "policies", "acl", policy],
            Some(token),
            None,
            false,
        )?;
        if response.status == 404 {
            return Ok(None);
        }
        http_status(response.status)?;
        Ok(Some(
            Raw::parse(response.body.as_bytes())?
                .field("data")?
                .field("policy")?
                .text()?,
        ))
    }
    pub fn read_metadata_optional(
        &mut self,
        token: &str,
        mount: &str,
        set: &str,
    ) -> Result<Option<Value>> {
        self.optional_data(token, &kv_path(mount, "metadata", set))
    }
    pub fn new(address: &str) -> Result<Self> {
        Ok(Self {
            address: Address::parse(address)?,
            executor: Executor::new()?,
            administrative_cleanup: false,
        })
    }
    pub(crate) fn administrative_cleanup(&mut self, enabled: bool) {
        self.administrative_cleanup = enabled;
    }
    pub fn address(&self) -> &str {
        &self.address.display
    }
    fn request(
        &mut self,
        method: &str,
        path: &[&str],
        token: Option<&str>,
        body: Option<&Prepared>,
        cleanup: bool,
    ) -> Result<Response> {
        self.executor.run(
            transport::exchange(
                &self.address,
                method,
                path,
                token,
                body,
                Duration::from_secs(20),
            ),
            Some(Duration::from_secs(60)),
            cleanup || self.administrative_cleanup,
        )
    }
    fn success(
        &mut self,
        method: &str,
        path: &[&str],
        token: &str,
        body: Option<&Prepared>,
        cleanup: bool,
    ) -> Result<Response> {
        let result = self.request(method, path, Some(token), body, cleanup)?;
        http_status(result.status)?;
        Ok(result)
    }
    pub fn health(&mut self) -> Result<Health> {
        let response = self.request("GET", &["sys", "health"], None, None, false)?;
        if !matches!(response.status, 200 | 429 | 472 | 473 | 501 | 503) {
            http_status(response.status)?;
        }
        let raw = Raw::parse(response.body.as_bytes())?;
        let initialized = raw.field("initialized")?.boolean()?;
        let sealed = raw.field("sealed")?.boolean()?;
        if response.status == 501 && initialized || response.status == 503 && !sealed {
            return Err(Error::runtime("inconsistent vault health response"));
        }
        Ok(Health {
            initialized,
            sealed,
            status: response.status,
        })
    }
    pub fn unseal(&mut self, key: &str) -> Result<()> {
        let body = strings(&[("key", key)])?;
        let response = self.request("PUT", &["sys", "unseal"], None, Some(&body), false)?;
        http_status(response.status)?;
        Raw::parse(response.body.as_bytes())?
            .field("sealed")?
            .boolean()?;
        Ok(())
    }
    pub fn login(&mut self, role: &str, secret: &str) -> Result<Text> {
        let body = strings(&[("role_id", role), ("secret_id", secret)])?;
        let response = self.request(
            "POST",
            &["auth", "approle", "login"],
            None,
            Some(&body),
            false,
        )?;
        if (400..500).contains(&response.status) {
            return Err(Error::rejected());
        }
        http_status(response.status)?;
        let token = (|| {
            Raw::parse(response.body.as_bytes())?
                .field("auth")?
                .field("client_token")?
                .text()
        })()
        .map_err(|_| Error::rejected())?;
        if !transport::token_valid(token.as_str()) {
            return Err(Error::rejected());
        }
        Ok(token)
    }
    pub fn revoke(&mut self, token: &str) -> Result<()> {
        self.success("POST", &["auth", "token", "revoke-self"], token, None, true)
            .map(|_| ())
    }
    pub fn read_set(&mut self, token: &str, mount: &str, set: &str) -> Result<Value> {
        let path = kv_path(mount, "data", set);
        let response = self.success("GET", &path, token, None, false)?;
        let data = Raw::parse(response.body.as_bytes())?
            .field("data")?
            .field("data")?;
        data.user_data()
    }
    pub(crate) fn read_machine_record(
        &mut self,
        token: &str,
        mount: &str,
        set: &str,
    ) -> Result<Value> {
        let response = self.success("GET", &kv_path(mount, "data", set), token, None, false)?;
        let data = Raw::parse(response.body.as_bytes())?
            .field("data")?
            .field("data")?;
        let fields = data.fields()?;
        if fields.len() != 2
            || !fields
                .iter()
                .all(|(k, v)| matches!(k.as_str(), "name" | "passphrase") && v.text().is_ok())
        {
            return Err(Error::runtime("invalid machine KV record"));
        }
        data.decode()
    }
    pub fn write_set(
        &mut self,
        token: &str,
        mount: &str,
        set: &str,
        values: &Prepared,
    ) -> Result<()> {
        Raw::parse(values.as_bytes())?.fields()?;
        let body = output::prepare(MAX_DOCUMENT_BYTES, |w| {
            w.text("{\"data\":")?;
            w.bytes(values.as_bytes())?;
            w.text("}")
        })?;
        let path = kv_path(mount, "data", set);
        let response = self.success("POST", &path, token, Some(&body), false)?;
        optional_json(&response)
    }
    pub fn delete_metadata(&mut self, token: &str, mount: &str, path: &str) -> Result<()> {
        let path = kv_path(mount, "metadata", path);
        let response = self.success("DELETE", &path, token, None, false)?;
        optional_json(&response)
    }
    pub fn write_set_cas(
        &mut self,
        token: &str,
        mount: &str,
        set: &str,
        values: &Prepared,
        version: u64,
    ) -> Result<()> {
        Raw::parse(values.as_bytes())?.fields()?;
        let body = output::prepare(MAX_DOCUMENT_BYTES, |w| {
            w.text(&format!("{{\"options\":{{\"cas\":{version}}},\"data\":"))?;
            w.bytes(values.as_bytes())?;
            w.text("}")
        })?;
        let response = self.success(
            "POST",
            &kv_path(mount, "data", set),
            token,
            Some(&body),
            false,
        )?;
        optional_json(&response)
    }
    pub fn read_role(&mut self, token: &str, role: &str) -> Result<Value> {
        let response = self.success(
            "GET",
            &["auth", "approle", "role", role],
            token,
            None,
            false,
        )?;
        Raw::parse(response.body.as_bytes())?
            .field("data")?
            .decode()
    }
    pub fn write_role(&mut self, token: &str, role: &str, settings: &Prepared) -> Result<()> {
        Raw::parse(settings.as_bytes())?.fields()?;
        let response = self.success(
            "POST",
            &["auth", "approle", "role", role],
            token,
            Some(settings),
            false,
        )?;
        optional_json(&response)
    }
    pub fn delete_role(&mut self, token: &str, role: &str) -> Result<()> {
        let response = self.success(
            "DELETE",
            &["auth", "approle", "role", role],
            token,
            None,
            false,
        )?;
        optional_json(&response)
    }
    pub fn role_id(&mut self, token: &str, role: &str) -> Result<Text> {
        let response = self.success(
            "GET",
            &["auth", "approle", "role", role, "role-id"],
            token,
            None,
            false,
        )?;
        Raw::parse(response.body.as_bytes())?
            .field("data")?
            .field("role_id")?
            .text()
    }
    pub fn mint_secret_id(&mut self, token: &str, role: &str) -> Result<Value> {
        let response = self.success(
            "POST",
            &["auth", "approle", "role", role, "secret-id"],
            token,
            None,
            false,
        )?;
        Raw::parse(response.body.as_bytes())?
            .field("data")?
            .decode()
    }
    pub fn destroy_secret_id(&mut self, token: &str, role: &str, secret_id: &str) -> Result<()> {
        let body = strings(&[("secret_id", secret_id)])?;
        let response = self.success(
            "POST",
            &["auth", "approle", "role", role, "secret-id", "destroy"],
            token,
            Some(&body),
            false,
        )?;
        optional_json(&response)
    }
    pub fn read_policy(&mut self, token: &str, policy: &str) -> Result<Text> {
        let response = self.success(
            "GET",
            &["sys", "policies", "acl", policy],
            token,
            None,
            false,
        )?;
        Raw::parse(response.body.as_bytes())?
            .field("data")?
            .field("policy")?
            .text()
    }
    pub fn write_policy(&mut self, token: &str, policy: &str, rules: &str) -> Result<()> {
        let body = strings(&[("policy", rules)])?;
        let response = self.success(
            "PUT",
            &["sys", "policies", "acl", policy],
            token,
            Some(&body),
            false,
        )?;
        optional_json(&response)
    }
    pub fn delete_policy(&mut self, token: &str, policy: &str) -> Result<()> {
        let response = self.success(
            "DELETE",
            &["sys", "policies", "acl", policy],
            token,
            None,
            false,
        )?;
        optional_json(&response)
    }
}
fn kv_path<'a>(mount: &'a str, kind: &'a str, set: &'a str) -> Vec<&'a str> {
    mount
        .split('/')
        .chain([kind])
        .chain(set.split('/'))
        .collect()
}
pub fn strings(fields: &[(&str, &str)]) -> Result<Prepared> {
    Ok(output::prepare(MAX_DOCUMENT_BYTES, |w| {
        w.text("{")?;
        for (i, (key, value)) in fields.iter().enumerate() {
            if value.len() > crate::sops::MAX_SCALAR_BYTES {
                return Err(crate::read::Error::class("size limit"));
            }
            if i > 0 {
                w.text(",")?;
            }
            output::json_string(w, key)?;
            w.text(":")?;
            output::json_string(w, value)?;
        }
        w.text("}")
    })?)
}
fn optional_json(response: &Response) -> Result<()> {
    if !response.body.as_bytes().is_empty() {
        Raw::parse(response.body.as_bytes())?.fields()?;
    }
    Ok(())
}
fn http_status(status: u16) -> Result<()> {
    match status {
        200..=299 => Ok(()),
        500..=599 => Err(Error::unavailable()),
        401 | 403 => Err(Error::runtime("vault authorization denied")),
        404 => Err(Error::runtime(
            "vault path or required server setup missing",
        )),
        300..=399 => Err(Error::runtime("vault redirect refused")),
        _ => Err(Error::runtime("vault request rejected")),
    }
}

