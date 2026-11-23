// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod applications;
mod registry;
pub mod select;
mod syntax;
pub use syntax::{
    dns as valid_member_name, exact_version as valid_registry_version,
    k3s_version as valid_k3s_version,
};

use crate::{images::secret_reference, raw::RawValue};
use broil_core::{
    error::ConfigError,
    images::reference::Authority,
    k3s::*,
    model::ConfigValue,
    secrets::{parse_age_recipient, valid_address},
};
use std::collections::{BTreeMap, BTreeSet};
use syntax::*;

pub(crate) fn targets(v: &RawValue, path: &str) -> Result<BTreeMap<String, Target>, ConfigError> {
    named(v, path, target)
}

fn target(v: &RawValue, path: &str) -> Result<Target, ConfigError> {
    let (
        mut version,
        mut members,
        mut api,
        mut registration_endpoint,
        mut network,
        mut infrastructure,
        mut credentials,
        mut lifecycle_script,
        mut bootstrap,
        mut backup,
    ) = (None, None, None, None, None, None, None, None, None, None);
    let (mut privilege, mut agent_wave_size, mut operation_timeout, mut step_timeout, mut registry) =
        (None, None, None, None, None);
    let mut node_registries = Vec::new();
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "version" => version = Some(checked(v, &p, k3s_version, "an exact K3s version")?),
            "members" => {
                let s = sequence(v, &p)?;
                if !(1..=128).contains(&s.len()) {
                    return Err(invalid(&p, "1–128 members"));
                }
                members = Some(
                    s.iter()
                        .enumerate()
                        .map(|(i, v)| member(v, &format!("{p}.{i}")))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            "api" => api = Some(parse_api(v, &p)?),
            "registration_endpoint" => registration_endpoint = Some(endpoint(v, &p)?),
            "network" => network = Some(parse_network(v, &p)?),
            "infrastructure" => infrastructure = Some(parse_infrastructure(v, &p)?),
            "credentials" => credentials = Some(parse_credentials(v, &p)?),
            "privilege" => privilege = Some(nonempty(v, &p)?),
            "lifecycle_script" => lifecycle_script = Some(nonempty(v, &p)?),
            "bootstrap" => bootstrap = Some(parse_bootstrap(v, &p)?),
            "backup" => backup = Some(parse_backup(v, &p)?),
            "agent_wave_size" => agent_wave_size = Some(integer(v, &p, 16)? as u8),
            "operation_timeout" => operation_timeout = Some(duration(v, &p, 24)?),
            "step_timeout" => step_timeout = Some(duration(v, &p, 2)?),
            "registry" => registry = registry::managed(v, &p)?,
            "node_registries" => {
                node_registries = sequence(v, &p)?
                    .iter()
                    .enumerate()
                    .map(|(i, v)| registry::node(v, &format!("{p}.{i}")))
                    .collect::<Result<_, _>>()?
            }
            _ => return Err(unknown(&p)),
        }
    }
    let result = Target {
        version: required(version, &format!("{path}.version"))?,
        members: required(members, &format!("{path}.members"))?,
        api: required(api, &format!("{path}.api"))?,
        registration_endpoint: required(
            registration_endpoint,
            &format!("{path}.registration_endpoint"),
        )?,
        network: required(network, &format!("{path}.network"))?,
        infrastructure: required(infrastructure, &format!("{path}.infrastructure"))?,
        credentials: required(credentials, &format!("{path}.credentials"))?,
        privilege,
        lifecycle_script: required(lifecycle_script, &format!("{path}.lifecycle_script"))?,
        bootstrap: required(bootstrap, &format!("{path}.bootstrap"))?,
        backup: required(backup, &format!("{path}.backup"))?,
        agent_wave_size,
        operation_timeout,
        step_timeout,
        registry,
        node_registries,
    };
    consistent(&result, path)?;
    Ok(result)
}

fn member(v: &RawValue, path: &str) -> Result<Member, ConfigError> {
    let (mut machine, mut role, mut member_name, mut node_ip, mut interface) =
        (None, None, None, None, None);
    let mut labels = BTreeMap::new();
    let mut taints = Vec::new();
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "machine" => machine = Some(nonempty(v, &p)?),
            "role" => {
                role = Some(match text(v, &p)?.as_str() {
                    "server" => Role::Server,
                    "agent" => Role::Agent,
                    _ => return Err(invalid(&p, "server or agent")),
                })
            }
            "name" => member_name = Some(checked(v, &p, dns, "a lowercase DNS node name")?),
            "node_ip" => node_ip = Some(unicast(v, &p)?),
            "interface" => {
                interface = Some(checked(
                    v,
                    &p,
                    |s| {
                        !s.is_empty()
                            && s.len() <= 15
                            && s.bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
                    },
                    "a Linux interface name",
                )?)
            }
            "labels" => {
                for (k, v) in pairs(v, &p, true)? {
                    let label = checked(k, &p, label_key, "a label key")?;
                    labels.insert(
                        label.clone(),
                        checked(v, &format!("{p}.{label}"), label_value, "a label value")?,
                    );
                }
            }
            "taints" => {
                let mut seen = BTreeSet::new();
                for (i, v) in sequence(v, &p)?.iter().enumerate() {
                    let p = format!("{p}.{i}");
                    let t = taint(v, &p)?;
                    if !seen.insert((t.key.clone(), t.effect)) {
                        return Err(invalid(&p, "a unique taint key/effect pair"));
                    }
                    taints.push(t);
                }
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(Member {
        machine: required(machine, &format!("{path}.machine"))?,
        role: required(role, &format!("{path}.role"))?,
        name: required(member_name, &format!("{path}.name"))?,
        node_ip: required(node_ip, &format!("{path}.node_ip"))?,
        interface: required(interface, &format!("{path}.interface"))?,
        labels,
        taints,
    })
}

fn taint(v: &RawValue, path: &str) -> Result<Taint, ConfigError> {
    let (mut name, mut value, mut effect) = (None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "key" => name = Some(checked(v, &p, label_key, "a taint key")?),
            "value" => value = Some(checked(v, &p, label_value, "a taint value")?),
            "effect" => {
                effect = Some(match text(v, &p)?.as_str() {
                    "NoSchedule" => TaintEffect::NoSchedule,
                    "PreferNoSchedule" => TaintEffect::PreferNoSchedule,
                    "NoExecute" => TaintEffect::NoExecute,
                    _ => return Err(invalid(&p, "a supported taint effect")),
                })
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(Taint {
        key: required(name, &format!("{path}.key"))?,
        value: required(value, &format!("{path}.value"))?,
        effect: required(effect, &format!("{path}.effect"))?,
    })
}

fn parse_api(v: &RawValue, path: &str) -> Result<Api, ConfigError> {
    let (mut url, mut tls_sans) = (None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "endpoint" => url = Some(endpoint(v, &p)?),
            "tls_sans" => {
                tls_sans = Some(strings(v, &p, false, |s| {
                    Authority::parse(s).is_some_and(|a| a.port.is_none() && !a.host.contains(':'))
                })?)
            }
            _ => return Err(unknown(&p)),
        }
    }
    Ok(Api {
        endpoint: required(url, &format!("{path}.endpoint"))?,
        tls_sans: required(tls_sans, &format!("{path}.tls_sans"))?,
    })
}

fn parse_network(v: &RawValue, path: &str) -> Result<Network, ConfigError> {
    let (mut pod_cidr, mut service_cidr, mut cluster_dns, mut cluster_domain, mut flannel) =
        (None, None, None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "pod_cidr" => pod_cidr = Some(cidr(v, &p)?),
            "service_cidr" => service_cidr = Some(cidr(v, &p)?),
            "cluster_dns" => cluster_dns = Some(unicast(v, &p)?),
            "cluster_domain" => {
                cluster_domain = Some(checked(v, &p, dns, "a lowercase DNS subdomain")?)
            }
            "flannel" => {
                checked(v, &p, |s| s == "vxlan", "vxlan")?;
                flannel = Some(Flannel::Vxlan);
            }
            _ => return Err(unknown(&p)),
        }
    }
    let result = Network {
        pod_cidr: required(pod_cidr, &format!("{path}.pod_cidr"))?,
        service_cidr: required(service_cidr, &format!("{path}.service_cidr"))?,
        cluster_dns: required(cluster_dns, &format!("{path}.cluster_dns"))?,
        cluster_domain,
        flannel,
    };
    if result.pod_cidr.contains(result.service_cidr.network)
        || result.service_cidr.contains(result.pod_cidr.network)
    {
        return Err(invalid(path, "nonoverlapping pod/service CIDRs"));
    }
    if !result.service_cidr.contains(result.cluster_dns)
        || result.cluster_dns == result.service_cidr.network
        || result.cluster_dns == result.service_cidr.broadcast()
    {
        return Err(invalid(
            &format!("{path}.cluster_dns"),
            "inside the service CIDR, excluding network and broadcast",
        ));
    }
    Ok(result)
}

fn parse_infrastructure(v: &RawValue, path: &str) -> Result<Infrastructure, ConfigError> {
    let (mut version, mut ingress_members) = (None, None);
    let (mut issuers, mut certificates) = (BTreeMap::new(), BTreeMap::new());
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "cert_manager_version" => {
                version = Some(checked(v, &p, exact_version, "an exact component version")?)
            }
            "ingress_members" => ingress_members = Some(strings(v, &p, false, dns)?),
            "issuers" => issuers = named(v, &p, issuer)?,
            "certificates" => certificates = named(v, &p, certificate)?,
            _ => return Err(unknown(&p)),
        }
    }
    for (name, cert) in &certificates {
        if !issuers.contains_key(&cert.issuer) {
            return Err(invalid(
                &format!("{path}.certificates.{name}.issuer"),
                "a declared issuer in this target",
            ));
        }
    }
    Ok(Infrastructure {
        cert_manager_version: required(version, &format!("{path}.cert_manager_version"))?,
        ingress_members: required(ingress_members, &format!("{path}.ingress_members"))?,
        issuers,
        certificates,
    })
}

fn issuer(v: &RawValue, path: &str) -> Result<Issuer, ConfigError> {
    let (mut kind, mut cert, mut private_key, mut server, mut email, mut account_key) =
        (None, None, None, None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "kind" => {
                kind = Some(checked(
                    v,
                    &p,
                    |s| matches!(s, "private-ca" | "acme-http01"),
                    "private-ca or acme-http01",
                )?)
            }
            "certificate" => cert = Some(secret_reference(v, &p)?),
            "key" => private_key = Some(secret_reference(v, &p)?),
            "server" => {
                server = Some(checked(
                    v,
                    &p,
                    |s| {
                        s.get(..8)
                            .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
                            && valid_address(s)
                    },
                    "an HTTPS issuer URL without userinfo, query or fragment",
                )?)
            }
            "email" => {
                email = Some(checked(
                    v,
                    &p,
                    |s| {
                        s.split_once('@').is_some_and(|(a, b)| {
                            !a.is_empty() && !b.is_empty() && !b.contains('@')
                        }) && !s.chars().any(|c| c.is_control() || c.is_whitespace())
                    },
                    "a public email contact",
                )?)
            }
            "account_key" => account_key = Some(secret_reference(v, &p)?),
            _ => return Err(unknown(&p)),
        }
    }
    match required(kind, &format!("{path}.kind"))?.as_str() {
        "private-ca" => {
            if server.is_some() || email.is_some() || account_key.is_some() {
                return Err(invalid(path, "private-CA fields only"));
            }
            Ok(Issuer::PrivateCa {
                certificate: required(cert, &format!("{path}.certificate"))?,
                key: required(private_key, &format!("{path}.key"))?,
            })
        }
        _ => {
            if cert.is_some() || private_key.is_some() {
                return Err(invalid(path, "ACME fields only"));
            }
            Ok(Issuer::AcmeHttp01 {
                server: required(server, &format!("{path}.server"))?,
                email: required(email, &format!("{path}.email"))?,
                account_key: required(account_key, &format!("{path}.account_key"))?,
            })
        }
    }
}

fn certificate(v: &RawValue, path: &str) -> Result<Certificate, ConfigError> {
    let (mut issuer, mut dns_names, mut lifetime, mut renew_before) = (None, None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "issuer" => issuer = Some(name(v, &p)?),
            "dns_names" => dns_names = Some(strings(v, &p, false, dns)?),
            "duration" => lifetime = Some(duration(v, &p, 8760)?),
            "renew_before" => renew_before = Some(duration(v, &p, 8760)?),
            _ => return Err(unknown(&p)),
        }
    }
    if renew_before.as_ref().map_or(720 * 3600, |d| d.seconds)
        >= lifetime.as_ref().map_or(2160 * 3600, |d| d.seconds)
    {
        return Err(invalid(
            &format!("{path}.renew_before"),
            "less than the certificate duration",
        ));
    }
    Ok(Certificate {
        issuer: required(issuer, &format!("{path}.issuer"))?,
        dns_names: required(dns_names, &format!("{path}.dns_names"))?,
        duration: lifetime,
        renew_before,
    })
}

fn parse_credentials(v: &RawValue, path: &str) -> Result<Credentials, ConfigError> {
    let (mut server_token, mut agent_token) = (None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "server_token" => server_token = Some(secret_reference(v, &p)?),
            "agent_token" => agent_token = Some(secret_reference(v, &p)?),
            _ => return Err(unknown(&p)),
        }
    }
    let result = Credentials {
        server_token: required(server_token, &format!("{path}.server_token"))?,
        agent_token: required(agent_token, &format!("{path}.agent_token"))?,
    };
    if result.server_token == result.agent_token {
        return Err(invalid(path, "distinct server and agent token references"));
    }
    Ok(result)
}

fn parse_bootstrap(v: &RawValue, path: &str) -> Result<Bootstrap, ConfigError> {
    let (mut mode, mut manifest, mut bundle) = (None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "mode" => {
                mode = Some(match text(v, &p)?.as_str() {
                    "online" => BootstrapMode::Online,
                    "bundle" => BootstrapMode::Bundle,
                    _ => return Err(invalid(&p, "online or bundle")),
                })
            }
            "manifest" => manifest = Some(path_value(v, &p, false)?),
            "bundle" => bundle = Some(path_value(v, &p, false)?),
            _ => return Err(unknown(&p)),
        }
    }
    let mode = required(mode, &format!("{path}.mode"))?;
    if (mode == BootstrapMode::Bundle) != bundle.is_some() {
        return Err(invalid(
            &format!("{path}.bundle"),
            "present exactly when mode is bundle",
        ));
    }
    Ok(Bootstrap {
        mode,
        manifest: required(manifest, &format!("{path}.manifest"))?,
        bundle,
    })
}

fn parse_backup(v: &RawValue, path: &str) -> Result<Backup, ConfigError> {
    let (mut machine, mut directory, mut recipient, mut identity, mut max_age) =
        (None, None, None, None, None);
    for (k, v) in pairs(v, path, false)? {
        let k = key(k, path)?;
        let p = format!("{path}.{k}");
        match k {
            "machine" => machine = Some(nonempty(v, &p)?),
            "path" => directory = Some(path_value(v, &p, true)?),
            "recipient" => {
                recipient = Some(checked(
                    v,
                    &p,
                    |s| parse_age_recipient(s).is_some(),
                    "a public age X25519 recipient",
                )?)
            }
            "identity" => identity = Some(secret_reference(v, &p)?),
            "max_age" => max_age = Some(duration(v, &p, 168)?),
            _ => return Err(unknown(&p)),
        }
    }
    Ok(Backup {
        machine: required(machine, &format!("{path}.machine"))?,
        path: required(directory, &format!("{path}.path"))?,
        recipient: required(recipient, &format!("{path}.recipient"))?,
        identity: required(identity, &format!("{path}.identity"))?,
        max_age,
    })
}

fn consistent(t: &Target, path: &str) -> Result<(), ConfigError> {
    let (mut machines, mut names, mut ips) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for (i, m) in t.members.iter().enumerate() {
        let p = format!("{path}.members.{i}");
        for (field, unique) in [
            ("machine", machines.insert(&m.machine)),
            ("name", names.insert(&m.name)),
            ("node_ip", ips.insert(m.node_ip)),
        ] {
            if !unique {
                return Err(invalid(&format!("{p}.{field}"), "unique in this target"));
            }
        }
        if t.network.pod_cidr.contains(m.node_ip) || t.network.service_cidr.contains(m.node_ip) {
            return Err(invalid(
                &format!("{p}.node_ip"),
                "outside the pod and service CIDRs",
            ));
        }
    }
    if !matches!(
        t.members.iter().filter(|m| m.role == Role::Server).count(),
        1 | 3
    ) {
        return Err(invalid(
            &format!("{path}.members"),
            "exactly one or three servers",
        ));
    }
    if machines.contains(&t.backup.machine) {
        return Err(invalid(
            &format!("{path}.backup.machine"),
            "outside this target's member set",
        ));
    }
    for (i, name) in t.infrastructure.ingress_members.iter().enumerate() {
        if !names.contains(name) {
            return Err(invalid(
                &format!("{path}.infrastructure.ingress_members.{i}"),
                "a member name in this target",
            ));
        }
    }
    for host in [
        &t.api.endpoint.authority.host,
        &t.registration_endpoint.authority.host,
    ] {
        if !t.api.tls_sans.iter().any(|s| s.eq_ignore_ascii_case(host)) {
            return Err(invalid(
                &format!("{path}.api.tls_sans"),
                "covering both API and registration endpoint hosts",
            ));
        }
    }
    if t.step_timeout.as_ref().map_or(900, |d| d.seconds)
        > t.operation_timeout.as_ref().map_or(7200, |d| d.seconds)
    {
        return Err(invalid(
            &format!("{path}.step_timeout"),
            "no greater than the operation timeout",
        ));
    }
    if let Some(r) = &t.registry {
        if !names.contains(&r.member) {
            return Err(invalid(
                &format!("{path}.registry.member"),
                "a member name in this target",
            ));
        }
        if !t.infrastructure.certificates.contains_key(&r.certificate) {
            return Err(invalid(
                &format!("{path}.registry.certificate"),
                "a certificate in this target",
            ));
        }
    }
    Ok(())
}

pub(crate) fn normalize(environment: &mut BTreeMap<String, ConfigValue>) {
    fn map<'a>(
        m: &'a mut BTreeMap<String, ConfigValue>,
        name: &str,
    ) -> &'a mut BTreeMap<String, ConfigValue> {
        let v = m.entry(name.into()).or_default();
        if matches!(v, ConfigValue::Null) {
            *v = ConfigValue::default();
        }
        let ConfigValue::Mapping(m) = v else {
            unreachable!("validated mapping")
        };
        m
    }
    for target in map(environment, "k3s").values_mut() {
        let ConfigValue::Mapping(t) = target else {
            unreachable!("validated target")
        };
        map(t, "registry");
        let infrastructure = map(t, "infrastructure");
        map(infrastructure, "issuers");
        map(infrastructure, "certificates");
        if let Some(ConfigValue::Sequence(members)) = t.get_mut("members") {
            for member in members {
                let ConfigValue::Mapping(m) = member else {
                    unreachable!("validated member")
                };
                map(m, "labels");
            }
        }
    }
}
