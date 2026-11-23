// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub mod select;

use std::collections::{BTreeMap, BTreeSet};

use broil_core::error::{ConfigError, SchemaError};
use broil_core::images::reference::{Endpoint, ImageReference, valid_dns_name};
use broil_core::images::*;
use broil_core::model::ConfigValue;
use broil_core::secrets::{identifier, valid_key, valid_set};

use crate::raw::RawValue;

pub(super) fn invalid(path: &str, expected: &str) -> ConfigError {
    ConfigError::Schema(SchemaError::InvalidImageValue {
        key_path: path.into(),
        expected: expected.into(),
    })
}

pub(super) fn ambiguous(first: &str, second: &str) -> ConfigError {
    ConfigError::Schema(SchemaError::AmbiguousImageDefinition {
        first: first.into(),
        second: second.into(),
    })
}

fn pairs<'a>(
    value: &'a RawValue,
    path: &str,
    nullable: bool,
) -> Result<&'a [(RawValue, RawValue)], ConfigError> {
    match value {
        RawValue::Map(pairs) => Ok(pairs),
        RawValue::Null if nullable => Ok(&[]),
        _ => Err(invalid(
            path,
            if nullable {
                "a mapping or null"
            } else {
                "a non-null mapping"
            },
        )),
    }
}

fn key<'a>(value: &'a RawValue, path: &str) -> Result<&'a str, ConfigError> {
    match value {
        RawValue::Str(s) if !s.contains('\0') => Ok(s),
        _ => Err(invalid(path, "a mapping with NUL-free string keys")),
    }
}

fn text(value: &RawValue, path: &str) -> Result<String, ConfigError> {
    match value {
        RawValue::Str(s) if !s.contains('\0') => Ok(s.clone()),
        _ => Err(invalid(path, "a NUL-free string")),
    }
}

fn nonempty(value: &RawValue, path: &str) -> Result<String, ConfigError> {
    let s = text(value, path)?;
    if s.is_empty() {
        return Err(invalid(path, "a non-empty string"));
    }
    Ok(s)
}

fn name(value: &RawValue, path: &str) -> Result<String, ConfigError> {
    let name = nonempty(value, path)?;
    if !valid_name(&name) {
        return Err(invalid(path, "a catalog name"));
    }
    Ok(name)
}

fn local_context(value: &RawValue, path: &str) -> Result<String, ConfigError> {
    let s = nonempty(value, path)?;
    if !valid_local_context(&s) {
        return Err(invalid(
            path,
            "a local directory path, without URL or stdin context syntax",
        ));
    }
    Ok(s)
}

fn boolean(value: &RawValue, path: &str) -> Result<bool, ConfigError> {
    match value {
        RawValue::Bool(b) => Ok(*b),
        _ => Err(invalid(path, "a boolean")),
    }
}

fn required<T>(value: Option<T>, path: &str) -> Result<T, ConfigError> {
    value.ok_or_else(|| invalid(path, "present (required field)"))
}

fn unknown(path: &str) -> ConfigError {
    ConfigError::Schema(SchemaError::UnknownKey {
        key_path: path.into(),
    })
}

fn sequence<'a>(value: &'a RawValue, path: &str) -> Result<&'a [RawValue], ConfigError> {
    match value {
        RawValue::Seq(s) => Ok(s),
        _ => Err(invalid(path, "a sequence")),
    }
}

fn unique_strings(
    value: &RawValue,
    path: &str,
    nonempty_list: bool,
    valid: fn(&str) -> bool,
) -> Result<Vec<String>, ConfigError> {
    let values = sequence(value, path)?;
    if nonempty_list && values.is_empty() {
        return Err(invalid(path, "a non-empty sequence"));
    }
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for (i, value) in values.iter().enumerate() {
        let p = format!("{path}.{i}");
        let s = nonempty(value, &p)?;
        if !valid(&s) {
            return Err(invalid(&p, "a supported value"));
        }
        if !seen.insert(s.clone()) {
            return Err(invalid(&p, "unique in the sequence"));
        }
        result.push(s);
    }
    Ok(result)
}

fn named_map<T>(
    value: &RawValue,
    path: &str,
    valid: fn(&str) -> bool,
    parse: impl Fn(&RawValue, &str) -> Result<T, ConfigError>,
) -> Result<BTreeMap<String, T>, ConfigError> {
    let mut result = BTreeMap::new();
    for (k, v) in pairs(value, path, true)? {
        let k = key(k, path)?;
        if !valid(k) {
            return Err(invalid(path, "a mapping with valid names"));
        }
        let p = format!("{path}.{k}");
        if result.contains_key(k) {
            return Err(invalid(&p, "a unique mapping key"));
        }
        result.insert(k.into(), parse(v, &p)?);
    }
    Ok(result)
}

pub(crate) fn images(
    value: &RawValue,
    path: &str,
) -> Result<BTreeMap<String, ImageDefinition>, ConfigError> {
    named_map(value, path, valid_name, image)
}

pub(crate) fn builders(
    value: &RawValue,
    path: &str,
) -> Result<BTreeMap<String, BuilderDefinition>, ConfigError> {
    named_map(value, path, valid_name, builder)
}

pub(crate) fn registries(
    value: &RawValue,
    path: &str,
) -> Result<BTreeMap<String, RegistryDefinition>, ConfigError> {
    named_map(value, path, valid_name, registry)
}

fn image(value: &RawValue, path: &str) -> Result<ImageDefinition, ConfigError> {
    let (
        mut image,
        mut builder,
        mut registry,
        mut context,
        mut dockerfile,
        mut stage,
        mut platforms,
    ) = (None, None, None, None, None, None, None);
    let (mut contexts, mut args, mut secrets, mut ssh) = (
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    let (mut output, mut cache, mut entitlements) =
        (OutputConfig::default(), CacheConfig::default(), Vec::new());
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "image" => image = Some(image_reference(v, &p)?),
            "builder" => builder = Some(name(v, &p)?),
            "registry" => registry = Some(name(v, &p)?),
            "context" => context = Some(local_context(v, &p)?),
            "dockerfile" => dockerfile = Some(nonempty(v, &p)?),
            "stage" => stage = Some(nonempty(v, &p)?),
            "contexts" => contexts = named_map(v, &p, valid_name, local_context)?,
            "args" => args = named_map(v, &p, identifier, text)?,
            "platforms" => platforms = Some(unique_strings(v, &p, true, valid_platform)?),
            "output" => output = output_config(v, &p)?,
            "cache" => cache = cache_config(v, &p)?,
            "secrets" => secrets = named_map(v, &p, valid_name, secret_reference)?,
            "ssh" => ssh = named_map(v, &p, valid_name, ssh_agent)?,
            "entitlements" => {
                entitlements = unique_strings(v, &p, false, |s| {
                    matches!(s, "network.host" | "security.insecure")
                })?
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(ImageDefinition {
        image: required(image, &format!("{path}.image"))?,
        builder: required(builder, &format!("{path}.builder"))?,
        registry,
        context,
        dockerfile,
        stage,
        contexts,
        args,
        platforms,
        output,
        cache,
        secrets,
        ssh,
        entitlements,
    })
}

fn image_reference(value: &RawValue, path: &str) -> Result<ImageReference, ConfigError> {
    ImageReference::parse(&nonempty(value, path)?)
        .ok_or_else(|| invalid(path, "a supported image reference"))
}

pub(crate) fn secret_reference(
    value: &RawValue,
    path: &str,
) -> Result<SecretReference, ConfigError> {
    let (mut set, mut secret_key) = (None, None);
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "set" => {
                let s = nonempty(v, &p)?;
                if !valid_set(&s, true) {
                    return Err(invalid(&p, "an explicit project/set reference"));
                }
                set = Some(s);
            }
            "key" => {
                let s = nonempty(v, &p)?;
                if !valid_key(&s) {
                    return Err(invalid(&p, "an addressable literal secret key"));
                }
                secret_key = Some(s);
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(SecretReference {
        set: required(set, &format!("{path}.set"))?,
        key: required(secret_key, &format!("{path}.key"))?,
    })
}

fn ssh_agent(value: &RawValue, path: &str) -> Result<String, ConfigError> {
    let mut agent = None;
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        if k != "agent" {
            return Err(unknown(&p));
        }
        agent = Some(nonempty(v, &p)?);
    }
    required(agent, &format!("{path}.agent"))
}

fn output_config(value: &RawValue, path: &str) -> Result<OutputConfig, ConfigError> {
    let mut output = OutputConfig::default();
    for (k, v) in pairs(value, path, true)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "type" => {
                output.kind = Some(match nonempty(v, &p)?.as_str() {
                    "registry" => OutputKind::Registry,
                    "oci-archive" => OutputKind::OciArchive,
                    "oci-layout" => OutputKind::OciLayout,
                    "docker-load" => OutputKind::DockerLoad,
                    "cache-only" => OutputKind::CacheOnly,
                    _ => return Err(invalid(&p, "a supported output type")),
                })
            }
            "path" => output.path = Some(nonempty(v, &p)?),
            _ => return Err(unknown(&p)),
        }
    }
    let retained = matches!(
        output.kind,
        Some(OutputKind::OciArchive | OutputKind::OciLayout)
    );
    if retained != output.path.is_some() {
        return Err(invalid(
            &format!("{path}.path"),
            "present exactly for OCI archive/layout output",
        ));
    }
    Ok(output)
}

fn cache_config(value: &RawValue, path: &str) -> Result<CacheConfig, ConfigError> {
    let mut cache = CacheConfig::default();
    for (k, v) in pairs(value, path, true)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "builder" => cache.builder = Some(boolean(v, &p)?),
            "refresh" => cache.refresh = Some(boolean(v, &p)?),
            "read" => {
                cache.read = sequence(v, &p)?
                    .iter()
                    .enumerate()
                    .map(|(i, v)| cache_location(v, &format!("{p}.{i}")))
                    .collect::<Result<_, _>>()?
            }
            "write" if matches!(v, RawValue::Null) => {}
            "write" => cache.write = Some(cache_location(v, &p)?),
            _ => return Err(unknown(&p)),
        }
    }
    Ok(cache)
}

fn cache_location(value: &RawValue, path: &str) -> Result<CacheLocation, ConfigError> {
    let (mut registry, mut reference) = (None, None);
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "registry" => registry = Some(name(v, &p)?),
            "ref" => {
                let r = image_reference(v, &p)?;
                if !r.explicit_authority || r.tag.is_none() {
                    return Err(invalid(&p, "a tagged fully qualified cache reference"));
                }
                reference = Some(r);
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(CacheLocation {
        registry: required(registry, &format!("{path}.registry"))?,
        reference: required(reference, &format!("{path}.ref"))?,
    })
}

fn builder(value: &RawValue, path: &str) -> Result<BuilderDefinition, ConfigError> {
    let (mut kind, mut endpoint, mut tls, mut machine, mut privilege, mut server_tls) =
        (None, None, None, None, None, None);
    let mut lifecycle_script = None;
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "kind" => {
                kind = Some(match nonempty(v, &p)?.as_str() {
                    "managed" => BuilderKind::Managed,
                    "external" => BuilderKind::External,
                    _ => return Err(invalid(&p, "managed or external")),
                })
            }
            "endpoint" => {
                endpoint = Some(
                    Endpoint::builder(&nonempty(v, &p)?)
                        .ok_or_else(|| invalid(&p, "an explicit TCP host and port endpoint"))?,
                )
            }
            "tls" => tls = Some(client_tls(v, &p)?),
            "machine" => machine = Some(nonempty(v, &p)?),
            "privilege" => privilege = Some(nonempty(v, &p)?),
            "server_tls" => server_tls = Some(server_tls_config(v, &p)?),
            "lifecycle_script" => lifecycle_script = Some(nonempty(v, &p)?),
            _ => return Err(unknown(&p)),
        }
    }
    let kind = required(kind, &format!("{path}.kind"))?;
    match kind {
        BuilderKind::External => {
            for (field, present) in [
                ("machine", machine.is_some()),
                ("privilege", privilege.is_some()),
                ("server_tls", server_tls.is_some()),
                ("lifecycle_script", lifecycle_script.is_some()),
            ] {
                if present {
                    return Err(invalid(
                        &format!("{path}.{field}"),
                        "absent for an external builder",
                    ));
                }
            }
        }
        BuilderKind::Managed => {
            if machine.is_none() {
                return Err(invalid(
                    &format!("{path}.machine"),
                    "present for a managed builder",
                ));
            }
            if server_tls.is_none() {
                return Err(invalid(
                    &format!("{path}.server_tls"),
                    "present for a managed builder",
                ));
            }
        }
    }
    Ok(BuilderDefinition {
        kind,
        endpoint: required(endpoint, &format!("{path}.endpoint"))?,
        tls: required(tls, &format!("{path}.tls"))?,
        machine,
        privilege,
        server_tls,
        lifecycle_script,
    })
}

fn client_tls(value: &RawValue, path: &str) -> Result<ClientTls, ConfigError> {
    let (mut ca, mut certificate, mut secret_key, mut server_name) = (None, None, None, None);
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "ca" => ca = Some(nonempty(v, &p)?),
            "certificate" => certificate = Some(secret_reference(v, &p)?),
            "key" => secret_key = Some(secret_reference(v, &p)?),
            "server_name" => {
                let s = nonempty(v, &p)?;
                if !valid_dns_name(&s) {
                    return Err(invalid(&p, "a DNS server identity"));
                }
                server_name = Some(s);
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(ClientTls {
        ca: required(ca, &format!("{path}.ca"))?,
        certificate: required(certificate, &format!("{path}.certificate"))?,
        key: required(secret_key, &format!("{path}.key"))?,
        server_name,
    })
}

fn server_tls_config(value: &RawValue, path: &str) -> Result<ServerTls, ConfigError> {
    let (mut certificate, mut secret_key) = (None, None);
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "certificate" => certificate = Some(secret_reference(v, &p)?),
            "key" => secret_key = Some(secret_reference(v, &p)?),
            _ => return Err(unknown(&p)),
        }
    }
    Ok(ServerTls {
        certificate: required(certificate, &format!("{path}.certificate"))?,
        key: required(secret_key, &format!("{path}.key"))?,
    })
}

fn registry(value: &RawValue, path: &str) -> Result<RegistryDefinition, ConfigError> {
    let (mut endpoint, mut development_http, mut ca, mut auth) =
        (None, None, None, BTreeMap::new());
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "endpoint" => {
                endpoint = Some(
                    Endpoint::registry(&nonempty(v, &p)?, true)
                        .ok_or_else(|| invalid(&p, "an absolute registry HTTP(S) endpoint"))?,
                )
            }
            "development_http" => development_http = Some(boolean(v, &p)?),
            "ca" => ca = Some(nonempty(v, &p)?),
            "auth" => {
                for (k, v) in pairs(v, &p, true)? {
                    let k = key(k, &p)?;
                    let purpose =
                        RegistryPurpose::parse(k).ok_or_else(|| unknown(&format!("{p}.{k}")))?;
                    auth.insert(purpose, registry_auth(v, &format!("{p}.{k}"))?);
                }
            }
            _ => return Err(unknown(&p)),
        }
    }
    let endpoint = required(endpoint, &format!("{path}.endpoint"))?;
    if endpoint.scheme == "http" && development_http != Some(true) {
        return Err(invalid(
            &format!("{path}.endpoint"),
            "HTTPS unless development_http is explicitly true",
        ));
    }
    for (purpose, entry) in &auth {
        let p = format!("{path}.auth.{}", purpose.name());
        for (i, repository) in entry.repositories.iter().enumerate() {
            let r = ImageReference::parse(repository).expect("validated repository");
            if !endpoint.matches_repository(&r) {
                return Err(invalid(
                    &format!("{p}.repositories.{i}"),
                    "a repository on the declared endpoint authority",
                ));
            }
        }
        if let RegistryCredential::Password {
            token_service: Some(service),
            ..
        } = &entry.credential
        {
            if Endpoint::token_realm(&service.realm.supplied, &endpoint).is_none() {
                return Err(invalid(
                    &format!("{p}.token_service.realm"),
                    "a canonical realm on the registry's exact origin",
                ));
            }
        }
    }
    Ok(RegistryDefinition {
        endpoint,
        development_http,
        ca,
        auth,
    })
}

fn registry_auth(value: &RawValue, path: &str) -> Result<RegistryAuth, ConfigError> {
    let (mut repositories, mut token, mut username, mut password, mut token_service) =
        (None, None, None, None, None);
    let mut service_present = false;
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "repositories" => {
                repositories = Some(unique_strings(v, &p, true, |s| {
                    ImageReference::parse(s).is_some_and(|r| r.is_normalized_repository())
                })?)
            }
            "token" => token = Some(secret_reference(v, &p)?),
            "username" => {
                let s = nonempty(v, &p)?;
                if s.contains(':') || s.chars().any(char::is_control) {
                    return Err(invalid(
                        &p,
                        "a public username without colon or control characters",
                    ));
                }
                username = Some(s);
            }
            "password" => password = Some(secret_reference(v, &p)?),
            "token_service" => {
                service_present = true;
                if !matches!(v, RawValue::Null) {
                    token_service = Some(service_config(v, &p)?);
                }
            }
            _ => return Err(unknown(&p)),
        }
    }
    let credential = if let Some(token) = token {
        if username.is_some() || password.is_some() || service_present {
            return Err(invalid(
                path,
                "a token alone, without password or token-service fields",
            ));
        }
        RegistryCredential::Token(token)
    } else {
        RegistryCredential::Password {
            username: required(username, &format!("{path}.username"))?,
            password: required(password, &format!("{path}.password"))?,
            token_service,
        }
    };
    Ok(RegistryAuth {
        repositories: required(repositories, &format!("{path}.repositories"))?,
        credential,
    })
}

fn service_config(value: &RawValue, path: &str) -> Result<TokenService, ConfigError> {
    let (mut realm, mut service) = (None, None);
    for (k, v) in pairs(value, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "realm" => {
                let s = nonempty(v, &p)?;
                let Some((scheme, rest)) = s.split_once("://") else {
                    return Err(invalid(&p, "an absolute token realm"));
                };
                let authority = rest.split('/').next().unwrap_or("");
                let origin = Endpoint::registry(&format!("{scheme}://{authority}"), true)
                    .ok_or_else(|| invalid(&p, "a canonical token realm"))?;
                realm = Some(
                    Endpoint::token_realm(&s, &origin)
                        .ok_or_else(|| invalid(&p, "a canonical token realm"))?,
                );
            }
            "service" => {
                let s = nonempty(v, &p)?;
                if s.len() > 255 || !s.bytes().all(|c| (33..=126).contains(&c)) {
                    return Err(invalid(
                        &p,
                        "1 to 255 printable ASCII bytes without whitespace",
                    ));
                }
                service = Some(s);
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(TokenService {
        realm: required(realm, &format!("{path}.realm"))?,
        service: required(service, &format!("{path}.service"))?,
    })
}

pub(crate) fn tools(value: &RawValue, path: &str) -> Result<ToolsDefinition, ConfigError> {
    use std::path::{Component, Path, PathBuf};
    let mut tools = ToolsDefinition::default();
    for (k, v) in pairs(value, path, true)? {
        let member = key(k, path)?;
        let p = format!("{path}.{member}");
        let slot = match member {
            "filesystem_helper" => &mut tools.filesystem_helper,
            "registry" => &mut tools.registry,
            "analyzer" => &mut tools.analyzer,
            "docker" => &mut tools.docker,
            "buildx" => &mut tools.buildx,
            "buildctl" => &mut tools.buildctl,
            _ => return Err(invalid(&p, "a supported image tool member")),
        };
        let value = nonempty(v, &p)?;
        let input = Path::new(&value);
        let mut normalized = PathBuf::new();
        for component in input.components() {
            match component {
                Component::RootDir => normalized.push("/"),
                Component::Normal(name) if name.len() <= 255 => normalized.push(name),
                _ => return Err(invalid(&p, "an absolute normalized executable path")),
            }
        }
        if !input.is_absolute() || value.len() > 4096 || normalized.as_os_str() != input.as_os_str()
        {
            return Err(invalid(&p, "an absolute normalized executable path"));
        }
        *slot = Some(value);
    }
    Ok(tools)
}

pub(crate) fn normalize(layer: &mut BTreeMap<String, ConfigValue>) {
    fn mapping<'a>(
        map: &'a mut BTreeMap<String, ConfigValue>,
        key: &str,
    ) -> &'a mut BTreeMap<String, ConfigValue> {
        let value = map.entry(key.into()).or_default();
        if matches!(value, ConfigValue::Null) {
            *value = ConfigValue::default();
        }
        let ConfigValue::Mapping(map) = value else {
            unreachable!("validated mapping");
        };
        map
    }
    for value in mapping(layer, "images").values_mut() {
        let ConfigValue::Mapping(image) = value else {
            unreachable!()
        };
        for key in ["contexts", "args", "output", "cache", "secrets", "ssh"] {
            mapping(image, key);
        }
        let ConfigValue::Mapping(cache) = image.get_mut("cache").unwrap() else {
            unreachable!()
        };
        if matches!(cache.get("write"), Some(ConfigValue::Null)) {
            mapping(cache, "write");
        }
    }
    mapping(layer, "tools");
    mapping(layer, "builders");
    for value in mapping(layer, "registries").values_mut() {
        let ConfigValue::Mapping(registry) = value else {
            unreachable!()
        };
        for value in mapping(registry, "auth").values_mut() {
            let ConfigValue::Mapping(auth) = value else {
                unreachable!()
            };
            if matches!(auth.get("token_service"), Some(ConfigValue::Null)) {
                mapping(auth, "token_service");
            }
        }
    }
}
