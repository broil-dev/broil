// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::output::Prepared;
use crate::vault::{
    Session,
    api::Client,
    json::{Text, Value},
    session::Credentials,
};

struct Policy {
    name: String,
    before: Option<Text>,
    wanted: String,
    attempted: bool,
}
pub(super) struct Role {
    pub settings: Value,
    pub id: Text,
}

pub(super) fn caller(inputs: &mut CredentialInputs) -> Result<Option<OwnedSecret>> {
    inputs
        .take("BAO_TOKEN")
        .map_err(|_| Error::class("invalid caller token"))?
        .map(|value| {
            value
                .into_secret()
                .map_err(|_| Error::class("invalid caller token"))
        })
        .transpose()
        .map(|value| value.filter(|v| !v.is_empty()))
}
struct Machine {
    path: String,
    old: Option<Prepared>,
    original_metadata: Option<Prepared>,
    installed_metadata: Option<Prepared>,
    attempted: bool,
}
pub(super) struct Remote {
    session: Session,
    kind: Kind,
    old_name: String,
    new_name: String,
    new_role: bool,
    before: Option<Role>,
    installed: Option<Role>,
    role_attempted: bool,
    settings: Option<Prepared>,
    policies: Vec<Policy>,
    self_before: Option<Text>,
    credentials: Option<Credentials>,
    unseal: Option<Text>,
    verification_token: Option<Text>,
    machine: Option<Machine>,
    mount: String,
    pub retired: bool,
}

pub(super) fn backend_name(name: &str) -> Result<()> {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    if name.is_empty()
        || name.len() > 4096
        || !name.bytes().all(|b| word(b) || matches!(b, b'.' | b'-'))
        || !word(*name.as_bytes().last().unwrap())
    {
        return Err(Error::class(
            "user or policy name is not representable by the configured vault",
        )
        .subject(name));
    }
    Ok(())
}
pub(super) fn role_name(name: &str) -> String {
    format!("approle-{name}")
}
pub(super) fn self_name(name: &str) -> String {
    format!("rotate-{name}")
}
pub(super) fn self_policy(name: &str) -> String {
    format!(
        "path \"auth/approle/role/approle-{name}/secret-id\" {{ capabilities = [\"create\", \"update\"] }}\npath \"auth/approle/role/approle-{name}/secret-id/destroy\" {{ capabilities = [\"create\", \"update\"] }}\n"
    )
}
pub(super) fn credentials(
    batch: &mut Admin<'_>,
    path: &str,
    keys: &[Identity],
) -> Result<Credentials> {
    let document = batch.document(path, true, keys).map_err(Error::store)?;
    if model::fields(document.data())?
        .iter()
        .any(|(name, _)| !matches!(*name, "role_id" | "secret_id" | "unseal_key" | "_broil"))
    {
        return Err(Error::class("unsupported administrative credential fields"));
    }
    let field = |key: &str| -> Result<Option<Text>> {
        document
            .data()
            .get(key)
            .map(|v| {
                let value = model::text(v)?;
                if value.is_empty() || value.contains('\0') {
                    return Err(Error::class("invalid credential fields"));
                }
                Text::copy(value).map_err(Into::into)
            })
            .transpose()
    };
    Ok(Credentials {
        role: field("role_id")?.ok_or(Error::class("missing credential fields"))?,
        secret: field("secret_id")?.ok_or(Error::class("missing credential fields"))?,
        unseal: field("unseal_key")?,
    })
}
pub(super) fn role(client: &mut Client, token: &str, name: &str) -> Result<Option<Role>> {
    let Some(settings) = client.read_role_optional(token, name)? else {
        return Ok(None);
    };
    for name in [
        "bind_secret_id",
        "secret_id_num_uses",
        "secret_id_ttl",
        "local_secret_ids",
        "token_policies",
        "token_ttl",
        "token_max_ttl",
        "token_period",
        "token_type",
    ] {
        if settings.get(name).is_none() {
            return Err(Error::class("malformed AppRole settings response"));
        }
    }
    for name in settings.keys()? {
        let value = settings.get(name).unwrap();
        let valid = match name {
            "bind_secret_id"
            | "local_secret_ids"
            | "token_no_default_policy"
            | "token_strictly_bind_ip" => {
                matches!(value, Value::Literal(t) if matches!(t.as_str(), "true" | "false"))
            }
            "token_policies" | "policies" | "secret_id_bound_cidrs" | "token_bound_cidrs" => {
                matches!(value, Value::Null)
                    || matches!(value, Value::Array(a) if a.iter().all(|v| matches!(v, Value::String(_))))
            }
            "token_type" => {
                matches!(value, Value::String(t) if matches!(t.as_str(), "default" | "service" | "batch" | "default-service" | "default-batch"))
            }
            "secret_id_num_uses" | "token_num_uses" => {
                matches!(value, Value::Literal(t) if t.as_str().parse::<u64>().is_ok())
            }
            "secret_id_ttl"
            | "token_ttl"
            | "token_max_ttl"
            | "token_explicit_max_ttl"
            | "token_period"
            | "period" => duration(value).is_ok(),
            _ => true,
        };
        if !valid {
            return Err(Error::class("malformed AppRole settings response"));
        }
    }
    let id = client.role_id(token, name)?;
    if id.as_str().is_empty() {
        return Err(Error::class("empty vault role ID"));
    }
    Ok(Some(Role { settings, id }))
}
pub(super) fn same_role(a: &Role, b: &Role) -> Result<bool> {
    Ok(a.id.as_str() == b.id.as_str()
        && a.settings.render(true, false)?.as_bytes() == b.settings.render(true, false)?.as_bytes())
}
pub(super) fn duration(value: &Value) -> Result<u64> {
    let value = value
        .scalar()
        .ok_or(Error::class("malformed role duration"))?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Ok(seconds);
    }
    let mut rest = value;
    let mut total = 0u64;
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .ok_or(Error::class("malformed role duration"))?;
        let number = rest[..end]
            .parse::<u64>()
            .map_err(|_| Error::class("malformed role duration"))?;
        let factor = match rest.as_bytes()[end] {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            _ => return Err(Error::class("malformed role duration")),
        };
        total = number
            .checked_mul(factor)
            .and_then(|n| total.checked_add(n))
            .ok_or(Error::class("malformed role duration"))?;
        rest = &rest[end + 1..];
    }
    if value.is_empty() {
        return Err(Error::class("malformed role duration"));
    }
    Ok(total)
}
fn checked_role_settings(actual: &Value, request: &Prepared) -> Result<()> {
    let requested = crate::vault::json::Raw::parse(request.as_bytes())?.decode()?;
    for name in requested.keys()? {
        let expected = requested.get(name).unwrap();
        let actual = actual
            .get(name)
            .ok_or(Error::class("vault omitted a requested role setting"))?;
        let equal = if name.ends_with("_ttl") || matches!(name, "token_period" | "period") {
            let seconds = |value: &Value| -> Result<u64> {
                let value = value
                    .scalar()
                    .ok_or(Error::class("malformed role duration"))?;
                let (number, factor) = value.strip_suffix('h').map_or((value, 1u64), |v| (v, 3600));
                number
                    .parse::<u64>()
                    .ok()
                    .and_then(|n| n.checked_mul(factor))
                    .ok_or(Error::class("malformed role duration"))
            };
            seconds(expected)? == seconds(actual)?
        } else if matches!(name, "secret_id_bound_cidrs" | "token_bound_cidrs")
            && matches!(expected, Value::Null)
        {
            matches!(actual, Value::Null) || matches!(actual, Value::Array(a) if a.is_empty())
        } else {
            expected.render(true, false)?.as_bytes() == actual.render(true, false)?.as_bytes()
        };
        if !equal {
            return Err(
                Error::class("vault did not preserve requested role settings").subject(name),
            );
        }
    }
    Ok(())
}
fn restore_settings(value: &Value) -> Result<Prepared> {
    output::prepare(sops::MAX_DOCUMENT_BYTES, |w| {
        w.text("{")?;
        for (i, name) in value
            .keys()
            .map_err(Error::from)?
            .into_iter()
            .filter(|k| *k != "local_secret_ids")
            .enumerate()
        {
            if i > 0 {
                w.text(",")?;
            }
            output::json_string(w, name)?;
            w.text(":")?;
            w.bytes(value.get(name).unwrap().render(true, false)?.as_bytes())?;
        }
        w.text("}")
    })
}
pub(super) fn metadata(
    client: &mut Client,
    token: &str,
    mount: &str,
    path: &str,
) -> Result<Option<Prepared>> {
    client
        .read_metadata_optional(token, mount, path)?
        .map(|v| v.render(true, false))
        .transpose()
}
pub(super) fn version(value: Option<&Prepared>) -> Result<u64> {
    match value {
        None => Ok(0),
        Some(value) => crate::vault::json::Raw::parse(value.as_bytes())?
            .field("current_version")?
            .decode()?
            .scalar()
            .ok_or(Error::class("invalid KV version"))?
            .parse()
            .map_err(|_| Error::class("invalid KV version")),
    }
}
pub(super) fn same(a: Option<&Prepared>, b: Option<&Prepared>) -> bool {
    a.map(Prepared::as_bytes) == b.map(Prepared::as_bytes)
}

fn role_settings(
    old: Option<&Value>,
    roster: &Roster,
    user: &str,
    creating: bool,
) -> Result<Prepared> {
    const OWNED: &[&str] = &[
        "token_policies",
        "policies",
        "token_ttl",
        "token_max_ttl",
        "token_period",
        "period",
    ];
    const CARRIED: &[&str] = &[
        "bind_secret_id",
        "secret_id_bound_cidrs",
        "secret_id_num_uses",
        "secret_id_ttl",
        "local_secret_ids",
        "token_bound_cidrs",
        "token_explicit_max_ttl",
        "token_no_default_policy",
        "token_strictly_bind_ip",
        "token_num_uses",
        "token_type",
    ];
    if let Some(old) = old {
        for name in old.keys()? {
            if !OWNED.contains(&name) && !CARRIED.contains(&name) {
                return Err(Error::class("unsupported existing AppRole restriction"));
            }
        }
        if old
            .get("secret_id_num_uses")
            .and_then(Value::scalar)
            .is_some_and(|s| s != "0")
            || old
                .get("token_type")
                .and_then(Value::scalar)
                .is_some_and(|s| s.contains("batch"))
        {
            return Err(Error::class(
                "existing AppRole cannot support nondestructive login and token-cleanup verification",
            ));
        }
    }
    let policies = roster.policies(user);
    output::prepare(sops::MAX_DOCUMENT_BYTES, |w| {
        w.text("{")?;
        if let Some(old) = old {
            for name in CARRIED {
                if !creating && *name == "local_secret_ids" {
                    continue;
                }
                if let Some(value) = old.get(name) {
                    output::json_string(w, name)?;
                    w.text(":")?;
                    w.bytes(value.render(true, false)?.as_bytes())?;
                    w.text(",")?;
                }
            }
        } else {
            w.text("\"bind_secret_id\":true,")?;
        }
        w.text("\"token_policies\":[")?;
        for (i, name) in policies.iter().enumerate() {
            if i > 0 {
                w.text(",")?;
            }
            output::json_string(w, name)?;
        }
        w.text(if roster.service(user) {
            "],\"token_ttl\":0,\"token_max_ttl\":0,\"token_period\":\"8760h\"}"
        } else {
            "],\"token_ttl\":\"24h\",\"token_max_ttl\":\"72h\",\"token_period\":0}"
        })
    })
}

impl Remote {
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        address: &str,
        caller: Option<OwnedSecret>,
        selected: &Selection,
        operator: &str,
        before: &Roster,
        after: &Roster,
        op: &Operation,
        batch: &mut Admin<'_>,
        keys: &[Identity],
        candidate_rules: &Rules,
    ) -> Result<Self> {
        backend_name(&role_name(&op.name))?;
        backend_name(&role_name(&op.target))?;
        let mut all_policy_names = BTreeMap::new();
        for name in before.teams.values().flat_map(|t| t.policies.iter()) {
            backend_name(name)?;
            if let Some(other) = all_policy_names.insert(name.to_ascii_lowercase(), name) {
                if other != name {
                    return Err(Error::class("vault policy case-fold collision"));
                }
            }
        }
        let mut folded = BTreeSet::new();
        for name in after.members.keys().chain(before.members.keys()) {
            backend_name(&role_name(name))?;
            if after
                .members
                .keys()
                .chain(before.members.keys())
                .any(|n| n != name && n.eq_ignore_ascii_case(name))
            {
                return Err(Error::class("vault role case-fold collision"));
            }
        }
        if op.kind == Kind::Rename && op.name.eq_ignore_ascii_case(&op.target) {
            return Err(Error::class("vault case-only rename is ambiguous"));
        }
        let policy_names = if op.kind == Kind::Remove {
            BTreeSet::new()
        } else {
            after.policies(&op.target)
        };
        let mut policies = Vec::new();
        for name in &policy_names {
            backend_name(name)?;
            if !folded.insert(name.to_ascii_lowercase()) {
                return Err(Error::class("vault policy case-fold collision"));
            }
            let generated = name == &self_name(&op.target);
            if !generated
                && (name.eq_ignore_ascii_case("root")
                    || name.eq_ignore_ascii_case("default")
                    || before
                        .members
                        .keys()
                        .chain(after.members.keys())
                        .any(|n| name.eq_ignore_ascii_case(&self_name(n))))
            {
                return Err(Error::class(
                    "team policy collides with a self or built-in policy",
                ));
            }
            if generated
                && after
                    .teams
                    .values()
                    .any(|team| team.policies.iter().any(|p| p.eq_ignore_ascii_case(name)))
            {
                return Err(Error::class(
                    "team policy collides with self-rotation policy",
                ));
            }
            let wanted = if generated {
                self_policy(&op.target)
            } else {
                let body = batch
                    .read(&format!("policies/{name}.hcl"), false)
                    .map_err(Error::store)?
                    .ok_or(Error::class("missing team policy").subject(name))?;
                if body.as_str().trim().is_empty() || body.as_str().contains('\0') {
                    return Err(Error::class("invalid team policy body"));
                }
                body.as_str().into()
            };
            crate::vault::api::strings(&[("policy", &wanted)])?;
            policies.push(Policy {
                name: name.clone(),
                before: None,
                wanted,
                attempted: false,
            });
        }
        let operator_path = selected
            .config
            .vault
            .credential
            .clone()
            .unwrap_or_else(|| format!("credentials/{operator}.yaml"));
        let operator_credentials = if batch
            .read(&operator_path, true)
            .map_err(Error::store)?
            .is_some()
        {
            let document = batch
                .document(&operator_path, true, keys)
                .map_err(Error::store)?;
            if document.recipients().map_err(crypto)? != before.credential(operator) {
                return Err(Error::class("operator credential recipients are ambiguous"));
            }
            Some(credentials(batch, &operator_path, keys)?)
        } else {
            None
        };
        let mut session = Session::administrative(
            address,
            caller.as_ref().map(OwnedSecret::as_str),
            operator_credentials.as_ref(),
        )?;
        let result = (|| {
            let (client, token) = session.parts();
            let new_role = op.fresh || op.kind == Kind::Rename;
            let old_name = role_name(&op.name);
            let new_name = role_name(&op.target);
            let mount = selected
                .config
                .vault
                .mount
                .clone()
                .unwrap_or_else(|| "secret".into());
            let self_before = client.read_policy_optional(token, &self_name(&op.name))?;
            if op.fresh && self_before.is_some() {
                return Err(Error::class("vault self-policy name already exists"));
            }
            for policy in &mut policies {
                policy.before = client.read_policy_optional(token, &policy.name)?;
                if new_role && policy.name == self_name(&op.target) && policy.before.is_some() {
                    return Err(Error::class("vault self-policy destination collision"));
                }
            }
            let mut required: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            let mut need = |path: String, caps: &[&str]| {
                required
                    .entry(path)
                    .or_default()
                    .extend(caps.iter().map(|s| s.to_string()));
            };
            if caller.is_none() {
                need("auth/token/revoke-self".into(), &["update"]);
            }
            need(format!("auth/approle/role/{old_name}"), &["read"]);
            if !op.fresh {
                need(format!("auth/approle/role/{old_name}/role-id"), &["read"]);
            }
            if op.kind != Kind::Remove {
                need(
                    format!("auth/approle/role/{new_name}"),
                    if new_role {
                        &["read", "create", "delete"]
                    } else {
                        &["read", "update"]
                    },
                );
                need(format!("auth/approle/role/{new_name}/role-id"), &["read"]);
                if new_role {
                    need(
                        format!("auth/approle/role/{new_name}/secret-id"),
                        &["update"],
                    );
                }
            }
            if op.kind != Kind::Add {
                need(format!("auth/approle/role/{old_name}"), &["delete"]);
                need(
                    format!("sys/policies/acl/{}", self_name(&op.name)),
                    if self_before.is_some() {
                        &["read", "delete"]
                    } else {
                        &["read"]
                    },
                );
            }
            for policy in &policies {
                need(
                    format!("sys/policies/acl/{}", policy.name),
                    if policy
                        .before
                        .as_ref()
                        .is_some_and(|p| p.as_str() == policy.wanted)
                    {
                        &["read"]
                    } else if policy.before.is_some() {
                        &["read", "update"]
                    } else {
                        &["read", "update", "delete"]
                    },
                );
            }
            if caller.is_none() {
                need(
                    format!("auth/approle/role/{}/role-id", role_name(operator)),
                    &["read"],
                );
            }
            let machine_path = before
                .machines
                .get(&op.name)
                .or_else(|| after.machines.get(&op.target))
                .map(|p| p.strip_suffix(".yaml").unwrap().to_owned());
            if let Some(path) = &machine_path {
                need(
                    format!("{mount}/metadata/{path}"),
                    if op.kind == Kind::Remove || op.fresh {
                        &["read", "delete"]
                    } else {
                        &["read"]
                    },
                );
                need(
                    format!("{mount}/data/{path}"),
                    if op.kind == Kind::Remove {
                        &["read"]
                    } else if op.fresh {
                        &["read", "create"]
                    } else {
                        &["read", "update"]
                    },
                );
            }
            client.require_capabilities(token, &required)?;
            if caller.is_none() {
                let id = client.role_id(token, &role_name(operator))?;
                if operator_credentials
                    .as_ref()
                    .is_none_or(|c| c.role.as_str() != id.as_str())
                {
                    return Err(Error::class("operator credential role identity mismatch"));
                }
            }
            let old = role(client, token, &old_name)?;
            if op.fresh && old.is_some() {
                return Err(Error::class("vault role name already exists"));
            }
            if !op.fresh && old.is_none() {
                return Err(Error::class(
                    "existing user role is missing; inspect prior recovery",
                ));
            }
            if op.kind == Kind::Rename && role(client, token, &new_name)?.is_some() {
                return Err(Error::class("vault rename destination already exists"));
            }
            let mut target_credentials = if !op.fresh {
                let c = credentials(batch, &format!("credentials/{}.yaml", op.name), keys)?;
                if c.role.as_str() != old.as_ref().unwrap().id.as_str() {
                    return Err(Error::class("existing user credential role mismatch"));
                }
                Some(c)
            } else {
                None
            };
            let settings = if op.kind == Kind::Remove {
                None
            } else {
                Some(role_settings(
                    old.as_ref().map(|r| &r.settings),
                    after,
                    &op.target,
                    new_role,
                )?)
            };
            let machine = if let Some(path) = machine_path {
                let original_metadata = metadata(client, token, &mount, &path)?;
                let old = if before.machines.contains_key(&op.name) {
                    if original_metadata.is_none() {
                        return Err(Error::class("machine vault record missing"));
                    }
                    let remote = client.read_machine_record(token, &mount, &path)?;
                    let document = batch
                        .document(&format!("{path}.yaml"), false, keys)
                        .map_err(Error::store)?;
                    if remote.keys()?.len() != 2
                        || ["name", "passphrase"].iter().any(|k| {
                            remote.get(k).and_then(Value::scalar)
                                != document
                                    .data()
                                    .get(k)
                                    .and_then(sops::Value::scalar)
                                    .map(sops::Scalar::as_str)
                        })
                    {
                        return Err(Error::class("machine vault/local record mismatch"));
                    }
                    Some(remote.render(true, false)?)
                } else {
                    if original_metadata.is_some() {
                        return Err(Error::class("new machine KV path has existing history"));
                    }
                    None
                };
                Some(Machine {
                    path,
                    old,
                    original_metadata,
                    installed_metadata: None,
                    attempted: false,
                })
            } else {
                None
            };
            let unseal = if new_role && op.kind != Kind::Remove && after.all(&op.target) {
                operator_credentials
                    .as_ref()
                    .and_then(|c| c.unseal.as_ref())
                    .or_else(|| target_credentials.as_ref().and_then(|c| c.unseal.as_ref()))
                    .map(|s| Text::copy(s.as_str()))
                    .transpose()?
            } else {
                None
            };
            if new_role {
                target_credentials = None;
            } else if let Some(credential) = &mut target_credentials {
                credential.unseal.take();
            }
            if new_role {
                let path = format!("credentials/{}.yaml", op.target);
                let mut fields = vec![("role_id", "preflight"), ("secret_id", "preflight")];
                if let Some(unseal) = &unseal {
                    fields.push(("unseal_key", unseal.as_str()));
                }
                let fields_to_check = fields.iter().map(|(k, _)| *k).collect::<Vec<_>>();
                if op.kind == Kind::Rename {
                    let encoded = batch
                        .credential_replacement(
                            &format!("credentials/{}.yaml", op.name),
                            keys,
                            &fields,
                            &candidate_rules.select(&path)?,
                        )
                        .map_err(Error::store)?;
                    rules::protected_fields(&encoded, &path, &fields_to_check)?;
                } else {
                    rules::protected_create(
                        candidate_rules,
                        &path,
                        &secret_mapping(&fields)?,
                        &fields_to_check,
                    )?;
                }
            }
            batch.fresh().map_err(Error::store)?;
            Ok((
                old_name,
                new_name,
                new_role,
                old,
                settings,
                policies,
                self_before,
                target_credentials,
                unseal,
                machine,
                mount,
            ))
        })();
        drop(caller);
        drop(operator_credentials);
        let (
            old_name,
            new_name,
            new_role,
            before,
            settings,
            policies,
            self_before,
            credentials,
            unseal,
            machine,
            mount,
        ) = match result {
            Ok(value) => value,
            Err(error) => {
                if session.cleanup().is_err() {
                    return Err(Error::class(
                        "vault preflight failed and operator token cleanup failed",
                    ));
                }
                return Err(error);
            }
        };
        Ok(Self {
            session,
            kind: op.kind,
            old_name,
            new_name,
            new_role,
            before,
            installed: None,
            role_attempted: false,
            settings,
            policies,
            self_before,
            credentials,
            unseal,
            verification_token: None,
            machine,
            mount,
            retired: false,
        })
    }
    fn check_role(&mut self, installed: bool) -> Result<()> {
        let expected = if installed {
            &self.installed
        } else {
            &self.before
        };
        let name = if installed {
            &self.new_name
        } else {
            &self.old_name
        };
        let (client, token) = self.session.parts();
        let actual = role(client, token, name)?;
        let matches = match (expected, actual.as_ref()) {
            (None, None) => true,
            (Some(a), Some(b)) => same_role(a, b)?,
            _ => false,
        };
        if !matches {
            return Err(Error::class("vault role changed since preflight"));
        }
        Ok(())
    }
    fn retire(&mut self, report: &mut Report) -> Result<()> {
        self.check_role(false)?;
        let (client, token) = self.session.parts();
        let policy = client
            .read_policy_optional(token, &self.old_name.replacen("approle-", "rotate-", 1))?;
        if policy.as_ref().map(Text::as_str) != self.self_before.as_ref().map(Text::as_str) {
            return Err(Error::class("old self-policy changed since preflight"));
        }
        self.retired = true;
        report.details.push(format!(
            "Vault role retirement attempted: {}",
            self.old_name
        ));
        client.delete_role(token, &self.old_name)?;
        report.details.push(format!(
            "Vault role removed: {} (old SecretIDs invalidated)",
            self.old_name
        ));
        if self.self_before.is_some() {
            client.delete_policy(token, &self.old_name.replacen("approle-", "rotate-", 1))?;
        }
        Ok(())
    }
    pub fn before_local(
        &mut self,
        batch: &mut Admin<'_>,
        rules: &Rules,
        keys: &[Identity],
        report: &mut Report,
    ) -> Result<()> {
        batch.fresh().map_err(Error::store)?;
        self.check_role(false)?;
        let mut recovery_index = format!(
            "operation\t{:?}\nold-role\t{}\nnew-role\t{}\n",
            self.kind, self.old_name, self.new_name
        );
        for (i, policy) in self.policies.iter().enumerate() {
            recovery_index.push_str(&format!(
                "policy-{i}\t{}\t{}\n",
                policy.name,
                if policy.before.is_some() {
                    "original-present"
                } else {
                    "original-absent"
                }
            ));
            if let Some(old) = &policy.before {
                batch
                    .recovery_public(&format!("vault-policy-{i}.hcl"), old.as_str().as_bytes())
                    .map_err(Error::store)?;
            }
        }
        batch
            .recovery_public("vault-actions.tsv", recovery_index.as_bytes())
            .map_err(Error::store)?;
        if let Some(settings) = &self.settings {
            batch
                .recovery_public("vault-role-candidate.json", settings.as_bytes())
                .map_err(Error::store)?;
        }
        if let Some(old) = &self.before {
            batch
                .recovery_public(
                    "vault-role-settings.json",
                    old.settings.render(true, false)?.as_bytes(),
                )
                .map_err(Error::store)?;
        }
        if self.kind == Kind::Remove {
            return self.retire(report);
        }
        for policy in &mut self.policies {
            let (client, token) = self.session.parts();
            let current = client.read_policy_optional(token, &policy.name)?;
            if current.as_ref().map(Text::as_str) != policy.before.as_ref().map(Text::as_str) {
                return Err(Error::class("vault policy changed since preflight"));
            }
            if current
                .as_ref()
                .is_some_and(|p| p.as_str() == policy.wanted)
            {
                continue;
            }
            batch.fresh().map_err(Error::store)?;
            policy.attempted = true;
            report
                .details
                .push(format!("Vault policy write attempted: {}", policy.name));
            client.write_policy(token, &policy.name, &policy.wanted)?;
        }
        batch.fresh().map_err(Error::store)?;
        self.check_role(false)?;
        let (client, token) = self.session.parts();
        if self.new_role && client.read_role_optional(token, &self.new_name)?.is_some() {
            return Err(Error::class("new vault role appeared during preflight"));
        }
        self.role_attempted = true;
        report
            .details
            .push(format!("Vault role write attempted: {}", self.new_name));
        client.write_role(token, &self.new_name, self.settings.as_ref().unwrap())?;
        self.installed = role(client, token, &self.new_name)?;
        if self.installed.is_none() {
            return Err(Error::class("written vault role could not be verified"));
        }
        checked_role_settings(
            &self.installed.as_ref().unwrap().settings,
            self.settings.as_ref().unwrap(),
        )?;
        if !self.new_role
            && self.installed.as_ref().unwrap().id.as_str()
                != self.before.as_ref().unwrap().id.as_str()
        {
            return Err(Error::class("team update changed role identity"));
        }
        if self.new_role {
            let minted = client.mint_secret_id(token, &self.new_name)?;
            let secret = minted
                .get("secret_id")
                .filter(|value| matches!(value, Value::String(_)))
                .and_then(Value::scalar)
                .filter(|s| !s.is_empty())
                .ok_or(Error::class("missing minted secret ID"))?;
            let credential = Credentials {
                role: Text::copy(self.installed.as_ref().unwrap().id.as_str())?,
                secret: Text::copy(secret)?,
                unseal: self.unseal.take(),
            };
            drop(minted);
            let mut fields = vec![
                ("role_id", credential.role.as_str()),
                ("secret_id", credential.secret.as_str()),
            ];
            if let Some(unseal) = &credential.unseal {
                fields.push(("unseal_key", unseal.as_str()));
            }
            let path = format!(
                "credentials/{}.yaml",
                self.new_name.strip_prefix("approle-").unwrap()
            );
            let fields_to_check = fields.iter().map(|(k, _)| *k).collect::<Vec<_>>();
            let encoded = if self.kind == Kind::Rename {
                let encoded = batch
                    .credential_replacement(
                        &format!(
                            "credentials/{}.yaml",
                            self.old_name.strip_prefix("approle-").unwrap()
                        ),
                        keys,
                        &fields,
                        &rules.select(&path)?,
                    )
                    .map_err(Error::store)?;
                rules::protected_fields(&encoded, &path, &fields_to_check)?;
                encoded
            } else {
                rules::protected_create(rules, &path, &secret_mapping(&fields)?, &fields_to_check)?
            };
            batch
                .set(&path, true, encoded.as_bytes())
                .map_err(Error::store)?;
            self.credentials = Some(credential);
        }
        let credentials = self
            .credentials
            .as_ref()
            .ok_or(Error::class("target credentials missing"))?;
        self.verification_token =
            Some(client.login(credentials.role.as_str(), credentials.secret.as_str())?);
        self.credentials = None;
        let verification = self.verification_token.as_ref().unwrap();
        client.revoke(verification.as_str())?;
        self.verification_token = None;
        if let Some(machine) = &mut self.machine {
            let current = metadata(client, token, &self.mount, &machine.path)?;
            if !same(current.as_ref(), machine.original_metadata.as_ref()) {
                return Err(Error::class("machine KV changed since preflight"));
            }
            let document = batch
                .candidate_document(&format!("{}.yaml", machine.path), keys)
                .map_err(Error::store)?;
            let body = output::get(document.data(), true)?;
            drop(document);
            machine.attempted = true;
            report.details.push(format!(
                "Machine KV write attempted: {}",
                output::public_name(&machine.path)
            ));
            client.write_set_cas(
                token,
                &self.mount,
                &machine.path,
                &body,
                version(machine.original_metadata.as_ref())?,
            )?;
            machine.installed_metadata = metadata(client, token, &self.mount, &machine.path)?;
            let persisted = client
                .read_machine_record(token, &self.mount, &machine.path)?
                .render(true, true)?;
            if persisted.as_bytes() != body.as_bytes() {
                return Err(Error::class("machine KV verification mismatch"));
            }
        }
        Ok(())
    }
    pub fn after_local(&mut self, batch: &mut Admin<'_>, report: &mut Report) -> Result<()> {
        batch.fresh().map_err(Error::store)?;
        if self.kind == Kind::Rename {
            self.retire(report)?;
        }
        if self.kind == Kind::Remove {
            if let Some(machine) = &self.machine {
                let (client, token) = self.session.parts();
                let current = metadata(client, token, &self.mount, &machine.path)?;
                if !same(current.as_ref(), machine.original_metadata.as_ref()) {
                    return Err(Error::class("machine KV changed before deletion"));
                }
                report.details.push(format!(
                    "Machine KV metadata deletion attempted: {}",
                    output::public_name(&machine.path)
                ));
                client.delete_metadata(token, &self.mount, &machine.path)?;
            }
        }
        Ok(())
    }
    pub fn compensate(&mut self, report: &mut Report) -> bool {
        self.session.client.administrative_cleanup(true);
        let result = (|| -> Result<()> {
            if let Some(machine) = &self.machine {
                if machine.attempted {
                    let expected = machine
                        .installed_metadata
                        .as_ref()
                        .ok_or(Error::class("uncertain machine KV write; inspect recovery"))?;
                    let (client, token) = self.session.parts();
                    let current = metadata(client, token, &self.mount, &machine.path)?;
                    if !same(current.as_ref(), Some(expected)) {
                        return Err(Error::class("machine KV drift prevents restoration"));
                    }
                    if let Some(old) = &machine.old {
                        client.write_set_cas(
                            token,
                            &self.mount,
                            &machine.path,
                            old,
                            version(Some(expected))?,
                        )?;
                    } else {
                        client.delete_metadata(token, &self.mount, &machine.path)?;
                    }
                    report
                        .details
                        .push("Machine KV original restored or new record deleted.".into());
                }
            }
            if self.role_attempted {
                if self.installed.is_none() {
                    return Err(Error::class(
                        "new or updated role is uncertain; inspect vault before cleanup",
                    ));
                }
                self.check_role(true)?;
                let (client, token) = self.session.parts();
                if self.new_role {
                    client.delete_role(token, &self.new_name)?;
                    report
                        .details
                        .push("New AppRole and its SecretIDs removed.".into());
                } else {
                    let before = self.before.as_ref().unwrap();
                    client.write_role(
                        token,
                        &self.old_name,
                        &restore_settings(&before.settings)?,
                    )?;
                    report.details.push(
                        "Original role settings restored; existing credential IDs retained.".into(),
                    );
                }
            }
            for policy in self.policies.iter().rev().filter(|p| p.attempted) {
                let (client, token) = self.session.parts();
                let current = client.read_policy_optional(token, &policy.name)?;
                if current.as_ref().map(Text::as_str) == policy.before.as_ref().map(Text::as_str) {
                    continue;
                }
                if current.as_ref().is_none_or(|p| p.as_str() != policy.wanted) {
                    return Err(Error::class("policy drift prevents restoration"));
                }
                if let Some(before) = &policy.before {
                    client.write_policy(token, &policy.name, before.as_str())?;
                } else {
                    client.delete_policy(token, &policy.name)?;
                }
            }
            Ok(())
        })();
        self.session.client.administrative_cleanup(false);
        if let Err(error) = result {
            report.details.push(format!(
                "Outstanding vault recovery: {error}; new credentials may remain live."
            ));
            return false;
        }
        true
    }
    pub fn finish(&mut self, report: &mut Report) -> Result<()> {
        let mut failed = false;
        if let Some(token) = self.verification_token.take() {
            if self.session.client.revoke(token.as_str()).is_err() {
                report.details.push(
                    "Verification token revocation failed; an issued token may remain live.".into(),
                );
                failed = true;
            }
        }
        if self.session.cleanup().is_err() {
            report.details.push(
                "Operator-owned token revocation failed; caller tokens are caller-owned.".into(),
            );
            failed = true;
        }
        if failed {
            Err(Error::class("vault token cleanup failed"))
        } else {
            Ok(())
        }
    }
}
