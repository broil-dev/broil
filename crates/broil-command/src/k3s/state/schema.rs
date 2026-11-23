// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, hash, hex, nonce, operation_id, require};
use crate::images::infrastructure_io::json::Value as Private;
use serde_json::{Value, json};
use std::path::{Component, Path};
use zeroize::Zeroizing;

pub(in crate::k3s) const HOST_CHECKS: [&str; 17] = [
    "host-profile",
    "canonical-access",
    "privilege",
    "tools",
    "sftp",
    "cgroups",
    "kernel",
    "swap",
    "capacity",
    "destination-storage",
    "interface",
    "dns",
    "routes",
    "clock",
    "ports",
    "foreign-installation",
    "existing-generation",
];

fn text(value: Private<'_>, check: impl FnOnce(&str) -> bool) -> Result<()> {
    let bytes = value.text()?;
    let value = std::str::from_utf8(bytes.get()).map_err(|_| Failure::Integrity)?;
    require(
        value.len() <= 4096 && !value.contains('\0') && check(value),
        Failure::Integrity,
    )
}

fn named(value: Private<'_>, names: &str) -> Result<()> {
    text(value, |s| names.split('|').any(|n| s == n))
}

fn integer(value: Private<'_>, minimum: u64, maximum: u64) -> Result<()> {
    require(
        (minimum..=maximum).contains(&value.number()?),
        Failure::Bound,
    )
}

fn object(value: Private<'_>, fields: &[(&str, &str)]) -> Result<()> {
    let names: Vec<&[u8]> = fields.iter().map(|(n, _)| n.as_bytes()).collect();
    let values = value.object(&names)?;
    for ((_, kind), value) in fields.iter().zip(values) {
        check(value, kind)?;
    }
    Ok(())
}

fn array(value: Private<'_>, kind: &str, minimum: usize, maximum: usize) -> Result<()> {
    let values = value.array()?;
    require((minimum..=maximum).contains(&values.len()), Failure::Bound)?;
    for value in values {
        check(value, kind)?;
    }
    Ok(())
}

fn path(value: &str) -> bool {
    let p = Path::new(value);
    if !p.is_absolute() || value.contains('\0') {
        return false;
    }
    let mut normalized = std::path::PathBuf::new();
    for part in p.components() {
        match part {
            Component::RootDir => normalized.push("/"),
            Component::Normal(n) if n.len() <= 255 => normalized.push(n),
            _ => return false,
        }
    }
    normalized.as_os_str() == p.as_os_str()
}

fn ipv4(value: &str) -> bool {
    value
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|address| address.to_string() == value)
}

fn cidr(value: &str) -> bool {
    let Some((network, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix > 32 || prefix.to_string() != value[network.len() + 1..] || !ipv4(network) {
        return false;
    }
    let Ok(address) = network.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(address) & !mask == 0
}

fn version(value: Private<'_>) -> Result<()> {
    match value.number()? {
        1 => Ok(()),
        n if n > 1 => Err(Failure::UnsupportedVersion),
        _ => Err(Failure::Integrity),
    }
}

fn version_2(value: Private<'_>) -> Result<()> {
    match value.number()? {
        2 => Ok(()),
        n if n > 2 => Err(Failure::UnsupportedVersion),
        _ => Err(Failure::Integrity),
    }
}

fn storage_fact(value: Private<'_>) -> Result<()> {
    object(
        value,
        &[
            ("class", "absent|owned|owned-drifted|foreign|unobservable"),
            (
                "parent",
                "reserved|safe|absent|unsafe|closed|untraversable|unobservable",
            ),
            ("ancestor", "?RegistryStorageAncestor"),
            ("filesystem", "supported|unsupported|unobservable"),
            ("available_mib", "?uint"),
            ("record_sha256", "?hash"),
            ("directory", "?FileIdentity"),
            ("data", "?FileIdentity"),
            ("fsid", "?uint"),
        ],
    )?;
    let parent = value.field("parent")?;
    let named =
        parent.equals("unsafe")? || parent.equals("closed")? || parent.equals("untraversable")?;
    require(
        value.field("ancestor")?.is_null() != named,
        Failure::Integrity,
    )
}

fn check(value: Private<'_>, kind: &str) -> Result<()> {
    if let Some(kind) = kind.strip_prefix('?') {
        return if value.is_null() {
            Ok(())
        } else {
            check(value, kind)
        };
    }
    if kind.contains('|') {
        return named(value, kind);
    }
    if let Some(kind) = kind.strip_prefix('=') {
        return named(value, kind);
    }
    match kind {
        "null" => require(value.is_null(), Failure::Integrity),
        "bool" => {
            value.boolean()?;
            Ok(())
        }
        "true" => require(value.boolean()?, Failure::Integrity),
        "false" => require(!value.boolean()?, Failure::Integrity),
        "version" => version(value),
        "version-2" => version_2(value),
        "request-version" => match value.number()? {
            1 | 2 => Ok(()),
            n if n > 2 => Err(Failure::UnsupportedVersion),
            _ => Err(Failure::Integrity),
        },
        "server-version" => integer(value, 2, 2),
        "agent-version" => integer(value, 3, 3),
        "api-endpoint" => text(value, |s| {
            s.starts_with("https://") && !s.starts_with("https://127.0.0.1:") && s.len() <= 512
        }),
        "uint" => integer(value, 0, u64::MAX),
        "counter" => integer(value, 1, u64::MAX),
        "https-port" => integer(value, 443, 443),
        "step" => integer(value, 1, u32::MAX.into()),
        "sequence" => integer(value, 1, 4096),
        "text" => text(value, |_| true),
        "name" => text(value, |s| !s.is_empty()),
        "uid" => text(value, super::super::protocol::opaque),
        "nonce" => text(value, nonce),
        "hash" => text(value, |s| hex(s, 64)),
        "operation" => text(value, operation_id),
        "path" => text(value, path),
        "approval" => text(value, |s| {
            s.strip_prefix("sha256:").is_some_and(|s| hex(s, 64))
        }),
        "failure" => named(
            value,
            "configuration|capability|credential|authentication|trust|ownership|integrity|storage|transport|readiness|timeout|cancelled|bound|unsupported-version|busy",
        ),
        "outcome" => named(value, "pending|running|succeeded|failed|cancelled|unknown"),
        "action" => named(
            value,
            "inspect|reserve-owner|acquire-writer|prepare-input|admit-credential|seal-writer|retire-writer|rebind-claim|prune-attempts|credential:supply-initial-server|credential:read-server-join|credential:supply-server-join|credential:read-agent-join|credential:supply-agent-join|credential:check-admin|credential:supply-issuer-ca|credential:supply-issuer-acme|credential:supply-registry-signing|credential:supply-registry-principal|credential:supply-node-registry|credential:supply-recovery-key|credential:supply-recovery-server-token|credential:apply-secret|bootstrap:inspect-host|bootstrap:inspect-generation|bootstrap:prepare-generation|bootstrap:download-asset|bootstrap:receive-asset|bootstrap:complete-generation|lifecycle:inspect-installation|lifecycle:activate-server|lifecycle:start-server|lifecycle:observe-server|lifecycle:publish-identity|lifecycle:publish-cluster|lifecycle:prepare-join-source|lifecycle:inspect-owned-server|lifecycle:inspect-join|lifecycle:observe-membership|lifecycle:activate-join|lifecycle:start-join|lifecycle:observe-join|lifecycle:publish-member|lifecycle:inspect-agent|lifecycle:observe-agent-membership|lifecycle:activate-agent|lifecycle:start-agent|lifecycle:observe-agent|lifecycle:publish-agent|lifecycle:network-inspect-host|lifecycle:network-inspect-objects|lifecycle:network-create-object|lifecycle:ingress-inspect-host|lifecycle:ingress-import-image|lifecycle:ingress-inspect-objects|lifecycle:ingress-create-object|lifecycle:cert-manager-inspect-host|lifecycle:cert-manager-import-images|lifecycle:cert-manager-inspect-objects|lifecycle:cert-manager-create-objects|lifecycle:issuer-inspect-objects|lifecycle:issuer-create-object|lifecycle:issuer-register-input|lifecycle:issuer-activate|lifecycle:issuer-create-issuer|lifecycle:certificate-inspect-objects|lifecycle:certificate-create-object|lifecycle:registry-storage-inspect-storage|lifecycle:registry-storage-create-storage|lifecycle:registry-storage-inspect-objects|lifecycle:registry-storage-create-object|lifecycle:registry-service-inspect-host|lifecycle:registry-service-import-image|lifecycle:registry-service-inspect-objects|lifecycle:registry-service-create-object|lifecycle:registry-endpoint-inspect-objects|lifecycle:registry-endpoint-create-object|lifecycle:registry-auth-inspect-objects|lifecycle:registry-auth-create-object|lifecycle:registry-auth-register-input|lifecycle:registry-auth-activate|lifecycle:registry-token-inspect-host|lifecycle:registry-token-import-image|lifecycle:registry-token-inspect-objects|lifecycle:registry-token-create-object|lifecycle:registry-token-configure-token|lifecycle:registry-token-switch-registry|lifecycle:registry-token-configure-principals|lifecycle:node-restart|lifecycle:node-observe-node|lifecycle:node-configure-registries|lifecycle:registry-replication-inspect-replication|lifecycle:registry-replication-create-replication|lifecycle:registry-replication-create-replica|lifecycle:registry-replication-configure-replication|lifecycle:registry-replication-scan-replica|lifecycle:registry-replication-revert-replica|lifecycle:registry-replication-remove-device|lifecycle:registry-replication-stop-replication|lifecycle:registry-replication-inspect-objects|lifecycle:registry-replication-create-object|lifecycle:registry-replication-configure-reader|lifecycle:registry-replication-stop-writer|lifecycle:registry-replication-start-writer|lifecycle:delivery-inspect-images|lifecycle:delivery-check-closure|lifecycle:delivery-pull-image|lifecycle:delivery-pin-image|lifecycle:delivery-unpin-image|lifecycle:delivery-read-origin-log|lifecycle:node-cordon|lifecycle:node-uncordon|lifecycle:node-observe-drain|lifecycle:node-evict|lifecycle:node-delete-node|lifecycle:node-stop-member|lifecycle:node-start-member|lifecycle:release-discover-kinds|lifecycle:release-apply-objects|lifecycle:release-inspect-workloads|lifecycle:release-observe-release|hook:before_apply|hook:health",
        ),
        "credential" => named(
            value,
            "supply-initial-server|read-server-join|supply-server-join|read-agent-join|supply-agent-join|check-admin|supply-issuer-ca|supply-issuer-acme|supply-registry-signing|supply-registry-principal|supply-node-registry|supply-recovery-key|supply-recovery-server-token|apply-secret",
        ),
        "FileIdentity" => {
            let v = value.array()?;
            require(v.len() == 2, Failure::Integrity)?;
            for n in v {
                check(n, "uint")?;
            }
            Ok(())
        }
        "ResourceIdentity" => {
            if value.raw().first() == Some(&b'[') {
                check(value, "FileIdentity")
            } else {
                check(value, "uid")
            }
        }
        "Scope" => object(
            value,
            &[
                ("project", "path"),
                ("environment", "name"),
                ("target", "uid"),
                ("hash", "hash"),
            ],
        ),
        "Cluster" => object(value, &[("uid", "uid"), ("ca_sha256", "hash")]),
        "AgentWaveBoundary" => {
            object(
                value,
                &[
                    ("schema", "version"),
                    ("kind", "=agent-wave-boundary"),
                    ("scope", "Scope"),
                    ("owner", "nonce"),
                    ("id", "nonce"),
                    ("batch_id", "nonce"),
                    ("ordinal", "counter"),
                    ("previous_gate", "?AgentWavePreviousGate"),
                    ("cluster", "Cluster"),
                    ("members", "Members"),
                    ("installed", "InstalledMembers"),
                    ("selected", "AgentWaveSelected"),
                    ("agent_wave_size", "AgentWaveWidth"),
                ],
            )?;
            let members = value.field("members")?.array()?;
            let installed = value.field("installed")?.array()?;
            let selected = value.field("selected")?.array()?;
            let active: Vec<_> = members
                .iter()
                .filter(|m| {
                    !m.field("role")
                        .is_ok_and(|r| r.equals("backup").unwrap_or(false))
                })
                .collect();
            require(
                installed.len() < active.len()
                    && selected.len() <= value.field("agent_wave_size")?.number()? as usize
                    && installed.iter().enumerate().all(|(i, e)| {
                        active.get(i).is_some_and(|m| {
                            e.field("member").is_ok_and(|v| v.raw() == m.raw())
                                && m.field("node_uid").is_ok_and(|v| !v.is_null())
                        })
                    })
                    && selected.iter().enumerate().all(|(i, name)| {
                        active.get(installed.len() + i).is_some_and(|m| {
                            m.field("role")
                                .is_ok_and(|v| v.equals("agent").unwrap_or(false))
                                && m.field("member").is_ok_and(|v| v.raw() == name.raw())
                                && m.field("node_uid").is_ok_and(|v| v.is_null())
                        })
                    }),
                Failure::Integrity,
            )
        }
        "AgentWavePreviousGate" => object(value, &[("id", "nonce"), ("gate_sha256", "hash")]),
        "AgentWaveSelected" => array(value, "name", 1, 16),
        "AgentWaveWidth" => integer(value, 1, 16),
        "AgentWaveGate" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=agent-wave-gate"),
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("id", "nonce"),
                ("boundary_sha256", "hash"),
                ("operations", "AgentWaveOperations"),
                ("observer_operation", "operation"),
                ("agent_view_ref", "AgentWaveRef"),
                ("server_membership_refs", "AgentWaveServerRefs"),
            ],
        ),
        "AgentWaveOperations" => array(value, "operation", 1, 16),
        "AgentWaveRef" => object(
            value,
            &[("operation", "operation"), ("sequence", "sequence")],
        ),
        "AgentWaveServerRefs" => array(value, "AgentWaveRef", 1, 3),
        "Route" => {
            object(
                value,
                &[
                    ("address", "name"),
                    ("port", "uint"),
                    ("account", "name"),
                    ("host_key_sha256", "hash"),
                ],
            )?;
            integer(value.field("port")?, 1, 65535)
        }
        "Member" => object(
            value,
            &[
                ("machine", "name"),
                ("member", "?name"),
                ("role", "server|agent|backup"),
                ("route", "Route"),
                ("jump", "?Route"),
                ("node_uid", "?uid"),
            ],
        ),
        "Members" => array(value, "Member", 1, 128),
        "Excluded" => object(value, &[("member", "Member"), ("reason", "=unreachable")]),
        "OwnerWriter" => object(
            value,
            &[
                ("member", "name"),
                ("operation", "operation"),
                ("moves", "counter"),
            ],
        ),
        "OwnerRemoval" => object(
            value,
            &[
                ("member", "name"),
                ("machine", "name"),
                ("operation", "operation"),
            ],
        ),
        "OwnerRemovals" => array(value, "OwnerRemoval", 0, 128),
        "Resource" => {
            object(
                value,
                &[
                    (
                        "kind",
                        "installation|node|server-input|agent-input|admin-access|issuer|registry-auth|node-registry|recovery|service|endpoint|storage|bootstrap-assets|replica|replication|application-secret",
                    ),
                    ("id", "uid"),
                    ("owner", "nonce"),
                    ("generation", "nonce"),
                    ("machine", "?name"),
                    ("path", "?text"),
                    ("namespace", "?uid"),
                    ("name", "?name"),
                    ("uid", "?uid"),
                ],
            )?;
            let location = value.field("path")?;
            if location.is_null() {
                return Ok(());
            }
            let bytes = location.text()?;
            let text = std::str::from_utf8(bytes.get()).map_err(|_| Failure::Integrity)?;
            if value.field("kind")?.equals("bootstrap-assets")? {
                require(
                    text.strip_suffix('/')
                        .is_some_and(|p| path(p) && p.contains("/assets/")),
                    Failure::Integrity,
                )
            } else {
                require(path(text), Failure::Integrity)
            }
        }
        "Resources" => array(value, "Resource", 0, 1024),
        "Reference" => object(
            value,
            &[("consumer", "credential"), ("set", "name"), ("key", "name")],
        ),
        "References" => array(value, "Reference", 0, 1024),
        "Tool" => object(value, &[("name", "uid"), ("sha256", "hash")]),
        "Tools" => array(value, "Tool", 1, 128),
        "Fingerprints" => object(
            value,
            &[
                ("config_sha256", "hash"),
                ("references_sha256", "hash"),
                ("profile_sha256", "hash"),
                ("script_sha256", "hash"),
                ("tools", "Tools"),
            ],
        ),
        "Binding" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("attempt", "nonce"),
                ("step", "step"),
                ("dispatch", "nonce"),
                ("recipient", "Member"),
                ("receiver_generation", "uint"),
                ("request_sha256", "hash"),
                ("participants_sha256", "hash"),
                ("fingerprints", "Fingerprints"),
            ],
        ),
        "Header" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-state"),
                    ("version", "version"),
                    ("action", "action"),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("payload", "Public"),
                ],
            )?;
            integer(value.field("remaining_ms")?, 1, 30000)?;
            let action = value.field("action")?.text()?;
            let fields: &[(&str, &str)] = match action.get() {
                b"inspect" => &[
                    ("subject", "owner|writer|dispatch|resource|identity"),
                    ("dispatch", "?nonce"),
                    ("resource", "?Resource"),
                ],
                b"reserve-owner" => &[
                    ("members", "Members"),
                    ("excluded", "?Excluded"),
                    ("cluster", "?Cluster"),
                    ("fingerprints", "Fingerprints"),
                ],
                b"acquire-writer" => &[
                    ("members", "Members"),
                    ("excluded", "?Excluded"),
                    ("sequence", "counter"),
                    ("reserve", "bool"),
                ],
                b"prepare-input" => &[("resource", "Resource"), ("projection", "Public")],
                b"admit-credential" => &[
                    ("action", "credential"),
                    ("request_id", "nonce"),
                    ("credential_step", "step"),
                    ("admission_sha256", "hash"),
                    ("selection_sha256", "hash"),
                    ("resource", "Resource"),
                ],
                b"seal-writer" => &[("members", "Members"), ("excluded", "?Excluded")],
                b"retire-writer" => &[
                    ("seals", "Seals"),
                    ("members", "Members"),
                    ("excluded", "?Excluded"),
                ],
                b"rebind-claim" => &[("members", "Members"), ("participants_sha256", "hash")],
                b"prune-attempts" => &[("attempts", "Nonces"), ("watermark_sequence", "counter")],
                _ => return Err(Failure::Capability),
            };
            object(value.field("payload")?, fields)
        }
        "asset-id" => text(value, |s| {
            s.len() <= 64
                && s.bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        }),
        "BootstrapRecipe" => {
            object(
                value,
                &[
                    ("schema", "version"),
                    ("scope", "Scope"),
                    ("owner", "nonce"),
                    ("operation", "operation"),
                    ("attempt", "nonce"),
                    ("members", "Members"),
                    ("resources", "Resources"),
                    ("mode", "online|bundle"),
                    ("manifest", "BootstrapManifest"),
                    ("index_sha256", "hash"),
                    ("hosts", "BootstrapHosts"),
                    ("network", "BootstrapNetwork"),
                ],
            )?;
            let members = value.field("members")?.array()?;
            let hosts = value.field("hosts")?.array()?;
            let mut machines = Vec::with_capacity(members.len());
            for member in members {
                machines.push(member.field("machine")?.text()?.get().to_vec());
            }
            let mut declared = Vec::with_capacity(hosts.len());
            for host in hosts {
                declared.push(host.field("machine")?.text()?.get().to_vec());
            }
            require(
                declared == machines || declared.len() == 1 && machines.contains(&declared[0]),
                Failure::Integrity,
            )?;
            Ok(())
        }
        "BootstrapHosts" => array(value, "BootstrapHost", 1, 128),
        "BootstrapHost" => object(
            value,
            &[
                ("machine", "name"),
                ("interface", "interface"),
                ("node_ip", "ipv4"),
            ],
        ),
        "BootstrapNetwork" => object(
            value,
            &[
                ("pod_cidr", "cidr"),
                ("service_cidr", "cidr"),
                ("endpoints", "DnsNames"),
            ],
        ),
        "DnsNames" => {
            array(value, "dns-name", 0, 4096)?;
            let mut previous: Option<Vec<u8>> = None;
            for name in value.array()? {
                let bytes = name.text()?;
                let current = bytes.get();
                require(
                    previous.as_deref().is_none_or(|p| p < current),
                    Failure::Integrity,
                )?;
                previous = Some(current.to_vec());
            }
            Ok(())
        }
        "interface" => text(value, |s| {
            !s.is_empty()
                && s.len() <= 15
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        }),
        "ipv4" => text(value, ipv4),
        "cidr" => text(value, cidr),
        "dns-name" => text(value, |s| {
            !s.is_empty()
                && s.len() <= 253
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        }),
        "utc-time" => text(value, |s| {
            s.len() == 20
                && s.bytes().enumerate().all(|(i, b)| match i {
                    4 | 7 => b == b'-',
                    10 => b == b'T',
                    13 | 16 => b == b':',
                    19 => b == b'Z',
                    _ => b.is_ascii_digit(),
                })
        }),
        "BootstrapManifest" => object(
            value,
            &[
                ("schema", "version"),
                ("profile_sha256", "hash"),
                ("platform", "=linux/amd64"),
                ("version", "name"),
                ("assets", "BootstrapManifestAssets"),
            ],
        ),
        "BootstrapManifestAssets" => array(value, "BootstrapManifestAsset", 1, 32),
        "BootstrapManifestAsset" => object(
            value,
            &[
                ("id", "asset-id"),
                ("size", "counter"),
                ("sha256", "hash"),
                ("origin", "name"),
                ("url", "?name"),
            ],
        ),
        "HostFacts" => object(
            value,
            &[
                ("os", "ubuntu|other|unknown"),
                ("release", "24.04|other|unknown"),
                ("architecture", "amd64|other|unknown"),
                ("init", "systemd|other|unknown"),
                ("logical_cpus", "?uint"),
                ("memory_bytes", "?uint"),
                ("available_bytes", "?uint"),
                ("available_inodes", "?uint"),
                ("required_bytes", "?uint"),
                ("required_inodes", "?uint"),
                ("mount_identity", "?FileIdentity"),
                ("checks", "HostChecks"),
            ],
        ),
        "HostChecks" => {
            array(value, "HostCheck", HOST_CHECKS.len(), HOST_CHECKS.len())?;
            for (check, name) in value.array()?.into_iter().zip(HOST_CHECKS) {
                require(check.field("check")?.equals(name)?, Failure::Integrity)?;
            }
            Ok(())
        }
        "HostCheck" => object(value, &[("check", "name"), ("status", "pass|fail|unknown")]),
        "CompleteMarker" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=bootstrap-complete"),
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("attempt", "nonce"),
                ("resource", "Resource"),
                ("recipe_sha256", "hash"),
                ("directory", "FileIdentity"),
                ("inactive", "true"),
                ("assets", "MarkerAssets"),
            ],
        ),
        "MarkerAssets" => array(value, "MarkerAsset", 1, 32),
        "MarkerAsset" => object(
            value,
            &[
                ("id", "asset-id"),
                ("size", "counter"),
                ("sha256", "hash"),
                ("identity", "FileIdentity"),
            ],
        ),
        "BootstrapHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-bootstrap"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-host|inspect-generation|prepare-generation|download-asset|receive-asset|complete-generation",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("payload", "BootstrapPayload"),
                ],
            )?;
            let action = value.field("action")?.text()?;
            let single = matches!(action.get(), b"download-asset" | b"receive-asset");
            let long = single
                || action.get() == b"complete-generation"
                || action.get() == b"prepare-generation";
            integer(
                value.field("remaining_ms")?,
                1,
                if long { 7_200_000 } else { 30_000 },
            )?;
            require(
                value.field("payload")?.field("asset")?.is_null() != single,
                Failure::Integrity,
            )
        }
        "BootstrapPayload" => object(
            value,
            &[
                ("recipe", "BootstrapRecipe"),
                ("resource", "Resource"),
                ("asset", "?asset-id"),
            ],
        ),
        "BootstrapResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|absent|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("facts", "?HostFacts"),
                ("assets", "BootstrapAssetEvents"),
                ("marker", "?CompleteMarker"),
                ("failure", "?failure"),
            ],
        ),
        "BootstrapAssetEvents" => array(value, "BootstrapAssetEvent", 0, 32),
        "BootstrapAssetEvent" => object(
            value,
            &[
                ("resource", "Resource"),
                ("asset", "asset-id"),
                ("identity", "?FileIdentity"),
                ("state", "absent|received|verified|unknown"),
            ],
        ),
        "BootstrapReady" => object(
            value,
            &[
                ("kind", "=ready"),
                ("input", "BootstrapInput"),
                ("binding_sha256", "hash"),
            ],
        ),
        "BootstrapInput" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=bootstrap-input"),
                ("binding", "Binding"),
                ("resource", "Resource"),
                ("asset", "asset-id"),
                ("size", "counter"),
                ("sha256", "hash"),
                ("recipe_sha256", "hash"),
                ("account", "name"),
                ("uid", "uint"),
                ("gid", "uint"),
                ("directory", "FileIdentity"),
                ("socket", "FileIdentity"),
                ("temporary", "=upload.tmp"),
                ("destination", "=received"),
            ],
        ),
        "ServerRecipe" => {
            object(
                value,
                &[
                    ("schema", "server-version"),
                    ("scope", "Scope"),
                    ("owner", "nonce"),
                    ("operation", "operation"),
                    ("attempt", "nonce"),
                    ("member", "Member"),
                    ("members", "Members"),
                    ("assets", "ServerAssets"),
                    ("input", "ServerInput"),
                    ("version", "name"),
                    ("executable", "IndexEntry"),
                    ("archive", "IndexEntry"),
                    ("guard_sha256", "hash"),
                    ("unit_sha256", "hash"),
                    ("config", "ServerConfig"),
                    ("api_endpoint", "api-endpoint"),
                ],
            )?;
            let members = value.field("members")?.array()?;
            let first = members.first().ok_or(Failure::Integrity)?;
            require(
                value.field("member")?.raw() == first.raw()
                    && first.field("role")?.equals("server")?,
                Failure::Integrity,
            )
        }
        "JoinRecipe" => {
            object(
                value,
                &[
                    ("schema", "server-version"),
                    ("scope", "Scope"),
                    ("owner", "nonce"),
                    ("operation", "operation"),
                    ("attempt", "nonce"),
                    ("source", "Member"),
                    ("member", "Member"),
                    ("members", "Members"),
                    ("cluster", "Cluster"),
                    ("installed", "InstalledServers"),
                    ("assets", "ServerAssets"),
                    ("input", "ServerInput"),
                    ("source_input", "Resource"),
                    ("version", "name"),
                    ("executable", "IndexEntry"),
                    ("archive", "IndexEntry"),
                    ("guard_sha256", "hash"),
                    ("unit_sha256", "hash"),
                    ("config", "JoinServerConfig"),
                    ("api_endpoint", "api-endpoint"),
                ],
            )?;
            let members = value.field("members")?.array()?;
            let servers: Vec<_> = members
                .iter()
                .copied()
                .filter(|m| {
                    m.field("role")
                        .is_ok_and(|r| r.equals("server").unwrap_or(false))
                })
                .collect();
            let installed = value.field("installed")?.array()?;
            let (source, member) = (value.field("source")?, value.field("member")?);
            let machine = member.field("machine")?.raw();
            let published: Vec<_> = servers
                .iter()
                .copied()
                .filter(|m| m.field("node_uid").is_ok_and(|uid| !uid.is_null()))
                .collect();
            require(
                servers.len() == 3
                    && published
                        .iter()
                        .find(|m| m.field("machine").is_ok_and(|v| v.raw() != machine))
                        .is_some_and(|m| m.raw() == source.raw())
                    && servers.iter().any(|m| m.raw() == member.raw())
                    && member.raw() != source.raw()
                    && installed.iter().enumerate().all(|(i, entry)| {
                        published.get(i).is_some_and(|m| {
                            entry.field("member").is_ok_and(|v| v.raw() == m.raw())
                        })
                    }),
                Failure::Integrity,
            )
        }
        "AgentJoinRecipe" => {
            object(
                value,
                &[
                    ("schema", "agent-version"),
                    ("scope", "Scope"),
                    ("owner", "nonce"),
                    ("operation", "operation"),
                    ("attempt", "nonce"),
                    ("source", "Member"),
                    ("member", "Member"),
                    ("members", "Members"),
                    ("cluster", "Cluster"),
                    ("installed", "InstalledMembers"),
                    ("wave", "AgentWave"),
                    ("assets", "ServerAssets"),
                    ("input", "ServerInput"),
                    ("source_input", "Resource"),
                    ("version", "name"),
                    ("executable", "IndexEntry"),
                    ("archive", "IndexEntry"),
                    ("guard_sha256", "hash"),
                    ("unit_sha256", "hash"),
                    ("config", "AgentConfig"),
                    ("api_endpoint", "api-endpoint"),
                ],
            )?;
            let members = value.field("members")?.array()?;
            let installed = value.field("installed")?.array()?;
            let active: Vec<_> = members
                .iter()
                .filter(|m| {
                    !m.field("role")
                        .is_ok_and(|v| v.equals("backup").unwrap_or(false))
                })
                .collect();
            require(
                members.first().is_some_and(|m| {
                    m.raw() == value.field("source").map(|v| v.raw()).unwrap_or_default()
                }) && value.field("source")?.field("role")?.equals("server")?
                    && !value.field("source")?.field("node_uid")?.is_null()
                    && value.field("member")?.field("role")?.equals("agent")?
                    && members.iter().any(|m| {
                        m.raw() == value.field("member").map(|v| v.raw()).unwrap_or_default()
                    })
                    && installed.iter().enumerate().all(|(i, entry)| {
                        active.get(i).is_some_and(|m| {
                            entry.field("member").is_ok_and(|v| v.raw() == m.raw())
                                && m.field("node_uid").is_ok_and(|v| !v.is_null())
                        })
                    }),
                Failure::Integrity,
            )
        }
        "InstalledMembers" => array(value, "InstalledServer", 1, 128),
        "AgentWave" => object(
            value,
            &[
                ("id", "nonce"),
                ("index", "uint"),
                ("boundary_sha256", "hash"),
            ],
        ),
        "InstalledServers" => array(value, "InstalledServer", 1, 3),
        "InstalledServer" => object(
            value,
            &[("member", "Member"), ("recipe_identity_sha256", "hash")],
        ),
        "ServerAssets" => object(value, &[("generation", "nonce"), ("marker_sha256", "hash")]),
        "ServerInput" => object(value, &[("generation", "nonce")]),
        "IndexEntry" => object(
            value,
            &[
                ("id", "asset-id"),
                ("filename", "name"),
                ("size", "counter"),
                ("sha256", "hash"),
            ],
        ),
        "ServerConfig" => object(
            value,
            &[
                ("cluster-init", "true"),
                ("token-file", "path"),
                ("agent-token-file", "path"),
                ("node-name", "dns-name"),
                ("node-ip", "ipv4"),
                ("advertise-address", "ipv4"),
                ("tls-san", "TlsSans"),
                ("cluster-cidr", "cidr"),
                ("service-cidr", "cidr"),
                ("cluster-dns", "ipv4"),
                ("cluster-domain", "dns-name"),
                ("flannel-backend", "=vxlan"),
                ("secrets-encryption", "true"),
                ("write-kubeconfig", "path"),
                ("write-kubeconfig-mode", "=0600"),
                ("disable", "DisabledComponents"),
                ("disable-default-registry-endpoint", "true"),
                ("etcd-expose-metrics", "false"),
                ("kube-apiserver-arg", "ApiServerArgs"),
                ("node-label", "NodeEntries"),
                ("node-taint", "NodeEntries"),
            ],
        ),
        "JoinServerConfig" => object(
            value,
            &[
                ("server", "api-endpoint"),
                ("token-file", "path"),
                ("agent-token-file", "path"),
                ("node-name", "dns-name"),
                ("node-ip", "ipv4"),
                ("advertise-address", "ipv4"),
                ("tls-san", "TlsSans"),
                ("cluster-cidr", "cidr"),
                ("service-cidr", "cidr"),
                ("cluster-dns", "ipv4"),
                ("cluster-domain", "dns-name"),
                ("flannel-backend", "=vxlan"),
                ("secrets-encryption", "true"),
                ("write-kubeconfig", "path"),
                ("write-kubeconfig-mode", "=0600"),
                ("disable", "DisabledComponents"),
                ("disable-default-registry-endpoint", "true"),
                ("etcd-expose-metrics", "false"),
                ("kube-apiserver-arg", "ApiServerArgs"),
                ("node-label", "NodeEntries"),
                ("node-taint", "NodeEntries"),
            ],
        ),
        "AgentConfig"
            if value
                .optional("disable-default-registry-endpoint")?
                .is_some() =>
        {
            object(
                value,
                &[
                    ("server", "api-endpoint"),
                    ("token-file", "path"),
                    ("node-name", "dns-name"),
                    ("node-ip", "ipv4"),
                    ("node-label", "NodeEntries"),
                    ("node-taint", "NodeEntries"),
                    ("disable-default-registry-endpoint", "true"),
                ],
            )
        }
        "AgentConfig" => object(
            value,
            &[
                ("server", "api-endpoint"),
                ("token-file", "path"),
                ("node-name", "dns-name"),
                ("node-ip", "ipv4"),
                ("node-label", "NodeEntries"),
                ("node-taint", "NodeEntries"),
            ],
        ),
        "TlsSans" => array(value, "name", 0, 4096),
        "NodeEntries" => array(value, "name", 0, 1024),
        "DisabledComponents" => {
            let names = [
                "coredns",
                "local-storage",
                "metrics-server",
                "servicelb",
                "traefik",
            ];
            let entries = value.array()?;
            require(entries.len() == names.len(), Failure::Integrity)?;
            for (entry, name) in entries.into_iter().zip(names) {
                require(entry.equals(name)?, Failure::Integrity)?;
            }
            Ok(())
        }
        "ApiServerArgs" => {
            let entries = value.array()?;
            require(entries.len() == 1, Failure::Integrity)?;
            require(
                entries[0].equals("anonymous-auth=false")?,
                Failure::Integrity,
            )
        }
        "LifecycleIdentity" => object(
            value,
            &[
                ("cluster", "Cluster"),
                ("node_uid", "uid"),
                ("data", "FileIdentity"),
            ],
        ),
        "LifecyclePayload" => object(
            value,
            &[
                ("recipe", "ServerRecipe"),
                ("identity", "?LifecycleIdentity"),
            ],
        ),
        "JoinLifecyclePayload" => {
            object(
                value,
                &[
                    ("recipe_kind", "initial|join"),
                    ("recipe", "Public"),
                    ("identity", "?LifecycleIdentity"),
                    ("membership", "?Membership"),
                    ("removed", "?MembershipRemoved"),
                ],
            )?;
            check(
                value.field("recipe")?,
                if value.field("recipe_kind")?.equals("join")? {
                    "JoinRecipe"
                } else {
                    "ServerRecipe"
                },
            )
        }
        "MembershipRemoved" => object(value, &[("member", "name"), ("node_ip", "ipv4")]),
        "AgentLifecyclePayload" => object(
            value,
            &[
                ("recipe", "AgentJoinRecipe"),
                ("identity", "?LifecycleIdentity"),
                ("agent_view", "?AgentView"),
            ],
        ),
        "AgentSourcePayload" => object(
            value,
            &[
                ("recipe", "AgentJoinRecipe"),
                ("identity", "null"),
                ("agent_view", "null"),
            ],
        ),
        "AgentView" => object(
            value,
            &[
                ("cluster", "Cluster"),
                ("observer", "Member"),
                ("members", "AgentViewMembers"),
                ("foreign", "ForeignNodes"),
            ],
        ),
        "AgentViewMembers" => array(value, "AgentViewMember", 1, 128),
        "AgentViewMember" => object(
            value,
            &[
                ("member", "Member"),
                ("present", "bool"),
                ("uid", "?uid"),
                ("ready", "bool"),
                ("roles", "NodeEntries"),
                ("labels", "NodeEntries"),
                ("taints", "NodeEntries"),
            ],
        ),
        "ForeignNodes" => array(value, "ForeignNode", 0, 128),
        "ForeignNode" => object(value, &[("name", "name"), ("uid", "uid")]),
        "Membership" => object(
            value,
            &[
                ("cluster", "Cluster"),
                ("observer", "name"),
                ("node_uid", "uid"),
                ("healthy", "bool"),
                ("members", "EtcdMembers"),
            ],
        ),
        "EtcdMembers" => array(value, "EtcdMember", 1, 3),
        "EtcdMember" => object(
            value,
            &[
                ("id", "counter"),
                ("name", "text"),
                ("peer_urls", "PeerUrls"),
                ("client_urls", "ClientUrls"),
                ("learner", "bool"),
            ],
        ),
        "PeerUrls" => array(value, "name", 1, 1),
        "ClientUrls" => array(value, "name", 0, 1),
        "LifecycleSourcePayload" => object(
            value,
            &[
                ("resource", "Resource"),
                ("projection", "Projection"),
                ("recipe", "ServerRecipe"),
            ],
        ),
        "NetworkRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("members", "Members"),
                ("first_server", "Member"),
                ("version", "name"),
                ("network", "NetworkDeclaration"),
                ("profile_sha256", "hash"),
                ("coredns_template_sha256", "hash"),
                ("local_storage_template_sha256", "hash"),
                ("coredns_render_sha256", "hash"),
                ("local_storage_render_sha256", "hash"),
            ],
        ),
        "NetworkDeclaration" => object(
            value,
            &[
                ("pod_cidr", "name"),
                ("service_cidr", "name"),
                ("cluster_dns", "name"),
                ("cluster_domain", "name"),
                ("flannel", "=vxlan"),
            ],
        ),
        "NetworkObject" => object(
            value,
            &[
                ("kind", "name"),
                ("namespace", "?uid"),
                ("name", "name"),
                ("uid", "?uid"),
                (
                    "class",
                    "absent|owned-ready|owned-drifted|foreign|unobservable",
                ),
                ("spec_sha256", "?hash"),
                ("available", "ready|not-ready|unobserved"),
            ],
        ),
        "NetworkObjects" => array(value, "NetworkObject", 12, 12),
        "NetworkFact" => object(
            value,
            &[
                ("state", "ready|not-ready|unobserved"),
                (
                    "reason",
                    "observed|missing|insufficient|inaccessible|mismatch",
                ),
            ],
        ),
        "NetworkHost" => object(
            value,
            &[
                ("member", "Member"),
                ("configuration", "NetworkFact"),
                ("interface", "NetworkFact"),
                ("routes", "NetworkFact"),
                ("ports", "NetworkFact"),
                ("flannel", "NetworkFact"),
                ("proxy", "NetworkFact"),
                ("policy", "NetworkFact"),
                ("capacity", "NetworkFact"),
                ("service", "NetworkFact"),
            ],
        ),
        "NetworkHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-network"),
                    ("version", "version"),
                    ("action", "inspect-host|inspect-objects|create-object"),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "NetworkRecipe"),
                    ("original_recipe_sha256", "?hash"),
                    ("object_ordinal", "?counter"),
                    ("resource", "?Resource"),
                    ("preflight", "?NetworkObjects"),
                ],
            )?;
            let create = value.field("action")?.equals("create-object")?;
            require(
                value.field("object_ordinal")?.is_null() != create
                    && value.field("resource")?.is_null() != create
                    && value.field("preflight")?.is_null() != create,
                Failure::Integrity,
            )?;
            integer(
                value.field("remaining_ms")?,
                1,
                if create { 7_200_000 } else { 30_000 },
            )
        }
        "NetworkResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("hosts", "?NetworkHost"),
                ("objects", "?NetworkObjects"),
                ("services", "unobserved|ready|not-ready|unknown"),
                ("storage", "unobserved|ready|not-ready|unknown"),
                ("failure", "?failure"),
            ],
        ),
        "IngressRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("members", "Members"),
                ("first_server", "Member"),
                ("ingress_members", "IngressMembers"),
                ("version", "name"),
                ("network", "IngressNetwork"),
                ("profile_sha256", "hash"),
                ("template_sha256", "hash"),
                ("render_sha256", "hash"),
                ("servicelb_sha256", "hash"),
            ],
        ),
        "IngressMembers" => array(value, "IngressMember", 1, 128),
        "IngressMember" => object(
            value,
            &[
                ("machine", "name"),
                ("generation", "nonce"),
                ("marker_sha256", "hash"),
            ],
        ),
        "IngressNetwork" => object(value, &[("service_cidr", "name"), ("api", "name")]),
        "IngressObject" => object(
            value,
            &[
                ("kind", "HelmChart|DaemonSet"),
                ("namespace", "=kube-system"),
                ("name", "traefik-crd|traefik|svclb-traefik"),
                ("uid", "?uid"),
                (
                    "class",
                    "absent|owned-ready|owned-drifted|foreign|unobservable",
                ),
                ("spec_sha256", "?hash"),
                ("available", "ready|not-ready|unobserved"),
            ],
        ),
        "IngressObjects" => array(value, "IngressObject", 3, 3),
        "IngressRecord" => object(
            value,
            &[
                ("uid", "?uid"),
                (
                    "class",
                    "absent|owned-ready|owned-drifted|foreign|unobservable",
                ),
                ("available", "ready|not-ready|unobserved"),
            ],
        ),
        "IngressRecords" => array(value, "IngressRecord", 51, 51),
        "IngressFact" => object(
            value,
            &[
                ("state", "ready|not-ready|unobserved"),
                (
                    "reason",
                    "observed|missing|mismatch|absent|placement|collision|unobservable|not-applicable",
                ),
            ],
        ),
        "IngressHost" => object(
            value,
            &[
                ("member", "Member"),
                ("charts", "IngressFact"),
                ("generation", "IngressFact"),
                ("image", "IngressFact"),
                ("runtime", "IngressFact"),
                ("listeners", "IngressFact"),
                ("forwarding", "IngressFact"),
                ("lb_image", "IngressFact"),
            ],
        ),
        "IngressFacts" => object(
            value,
            &[
                ("api", "IngressFact"),
                ("cordoned", "Positions"),
                ("host_ports", "Positions"),
                ("placement", "IngressFact"),
                ("servicelb", "IngressFact"),
                ("selector", "IngressFact"),
                ("ingress_class", "IngressFact"),
            ],
        ),
        "Positions" => array(value, "counter", 0, 128),
        "IngressPreflight" => object(
            value,
            &[("objects", "IngressObjects"), ("results", "IngressRecords")],
        ),
        "IngressHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-ingress"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-host|import-image|inspect-objects|create-object",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "IngressRecipe"),
                    ("original_recipe_sha256", "?hash"),
                    ("object_ordinal", "?counter"),
                    ("resource", "?Resource"),
                    ("preflight", "?IngressPreflight"),
                ],
            )?;
            let create = value.field("action")?.equals("create-object")?;
            let mutation = create || value.field("action")?.equals("import-image")?;
            require(
                value.field("object_ordinal")?.is_null() != create
                    && value.field("preflight")?.is_null() != create
                    && value.field("resource")?.is_null() != mutation,
                Failure::Integrity,
            )?;
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "IngressResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("hosts", "?IngressHost"),
                ("objects", "?IngressObjects"),
                ("results", "?IngressRecords"),
                ("ingress", "?IngressFacts"),
                ("services", "?unobserved|not-ready"),
                ("failure", "?failure"),
            ],
        ),
        "CertManagerRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("members", "Members"),
                ("first_server", "Member"),
                ("version", "name"),
                ("generations", "IngressMembers"),
                ("profile_sha256", "hash"),
                ("manifest_sha256", "hash"),
                ("render_sha256", "hash"),
            ],
        ),
        "CertManagerObject" => object(
            value,
            &[
                (
                    "kind",
                    "Namespace|CustomResourceDefinition|ServiceAccount|ClusterRole|ClusterRoleBinding|Role|RoleBinding|Service|Deployment|MutatingWebhookConfiguration|ValidatingWebhookConfiguration",
                ),
                ("namespace", "?cert-manager|kube-system"),
                ("name", "name"),
                ("uid", "?uid"),
                (
                    "class",
                    "absent|owned-ready|owned-drifted|foreign|unobservable",
                ),
                ("spec_sha256", "?hash"),
                ("available", "ready|not-ready|unobserved"),
            ],
        ),
        "CertManagerObjects" => array(value, "CertManagerObject", 47, 47),
        "CertManagerUids" => array(value, "?uid", 47, 47),
        "CertManagerFact" => object(
            value,
            &[
                ("state", "ready|not-ready"),
                (
                    "reason",
                    "observed|missing|unobservable|objects|ca-bundle|budget|timeout|mutated|crd|dry-run|denied|endpoints|certificate|call|other-webhook",
                ),
            ],
        ),
        "CertManagerHost" => object(
            value,
            &[
                ("member", "Member"),
                ("generation", "CertManagerFact"),
                ("images", "CertManagerFact"),
                ("runtime", "CertManagerFact"),
            ],
        ),
        "CertManagerHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-cert-manager"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-host|import-images|inspect-objects|create-objects",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "CertManagerRecipe"),
                    ("original_recipe_sha256", "?hash"),
                    ("uids", "?CertManagerUids"),
                    ("resource", "?Resource"),
                    ("preflight", "?CertManagerObjects"),
                ],
            )?;
            let action = value.field("action")?;
            let create = action.equals("create-objects")?;
            let mutation = create || action.equals("import-images")?;
            require(
                (value.field("uids")?.is_null() || action.equals("inspect-objects")?)
                    && value.field("preflight")?.is_null() != create
                    && value.field("resource")?.is_null() != mutation,
                Failure::Integrity,
            )?;
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "CertManagerResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("hosts", "?CertManagerHost"),
                ("objects", "?CertManagerObjects"),
                ("webhook", "?CertManagerFact"),
                ("services", "?unobserved|not-ready"),
                ("failure", "?failure"),
            ],
        ),
        "IssuerSecretOrigin" => object(
            value,
            &[("operation", "operation"), ("recipe_sha256", "hash")],
        ),
        "IssuerRegistrationOrigin" => object(
            value,
            &[
                ("operation", "operation"),
                ("attempt", "nonce"),
                ("directory", "FileIdentity"),
                ("record_sha256", "hash"),
            ],
        ),
        "IssuerOperation" => object(value, &[("operation", "operation")]),
        "IssuerClusterOrigin" => object(
            value,
            &[
                ("operation", "operation"),
                ("recipe_sha256", "hash"),
                ("uid", "uid"),
            ],
        ),
        "IssuerOrigins" => object(
            value,
            &[
                ("secret", "?IssuerSecretOrigin"),
                ("registration", "?IssuerRegistrationOrigin"),
                ("supply", "?IssuerOperation"),
                ("activation", "?IssuerOperation"),
                ("cluster_issuer", "?IssuerClusterOrigin"),
            ],
        ),
        "IssuerRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("anchor_uid", "uid"),
                ("version", "name"),
                ("issuer", "name"),
                ("resource", "Resource"),
                ("cluster_issuer_name", "name"),
                ("stage", "create|activate|finish-activation|observe"),
                ("origins", "IssuerOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "IssuerObject" => object(
            value,
            &[
                ("kind", "Secret|ClusterIssuer"),
                ("namespace", "?=cert-manager"),
                ("name", "name"),
                ("uid", "?uid"),
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("activation", "?inactive|active"),
                ("spec_sha256", "?hash"),
            ],
        ),
        "IssuerObjects" => array(value, "IssuerObject", 1, 2),
        "IssuerRegistration" => object(
            value,
            &[
                ("class", "absent|present|foreign|unobservable"),
                ("directory", "?FileIdentity"),
                ("record_sha256", "?hash"),
            ],
        ),
        "IssuerReady" => object(
            value,
            &[
                ("state", "ready|not-ready"),
                (
                    "reason",
                    "observed|inactive|absent|pending|rejected|unobservable",
                ),
            ],
        ),
        "IssuerFact" => object(
            value,
            &[
                ("registration", "IssuerRegistration"),
                ("ready", "IssuerReady"),
            ],
        ),
        "IssuerExpectedRegistration" => object(
            value,
            &[("directory", "FileIdentity"), ("record_sha256", "hash")],
        ),
        "IssuerExpected" => object(
            value,
            &[
                ("secret", "?uid"),
                ("cluster_issuer", "?uid"),
                ("registration", "?IssuerExpectedRegistration"),
            ],
        ),
        "IssuerPreflight" => object(
            value,
            &[("objects", "IssuerObjects"), ("issuer", "IssuerFact")],
        ),
        "IssuerHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-issuer"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-objects|create-object|register-input|activate|create-issuer",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "IssuerRecipe"),
                    ("expected", "IssuerExpected"),
                    ("resource", "?Resource"),
                    ("preflight", "?IssuerPreflight"),
                    ("projection", "?Projection"),
                ],
            )?;
            let action = value.field("action")?;
            let mutation = !action.equals("inspect-objects")?;
            require(
                value.field("resource")?.is_null() != mutation
                    && value.field("preflight")?.is_null() != mutation
                    && value.field("projection")?.is_null() != action.equals("register-input")?,
                Failure::Integrity,
            )?;
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "IssuerResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("objects", "?IssuerObjects"),
                ("issuer", "?IssuerFact"),
                ("services", "?unobserved|not-ready"),
                ("failure", "?failure"),
            ],
        ),
        "RegistryAuthOrigins" => object(
            value,
            &[
                ("secret", "?IssuerSecretOrigin"),
                ("registration", "?IssuerRegistrationOrigin"),
                ("supply", "?IssuerOperation"),
                ("activation", "?IssuerOperation"),
            ],
        ),
        "RegistryAuthRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("anchor_uid", "uid"),
                ("version", "name"),
                ("registry", "name"),
                ("resource", "Resource"),
                ("principal", "?name"),
                ("stage", "create|activate|observe"),
                ("origins", "RegistryAuthOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryAuthObject" => object(
            value,
            &[
                ("kind", "=Secret"),
                ("namespace", "=broil-registry"),
                ("name", "name"),
                ("uid", "?uid"),
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("activation", "?inactive|active"),
                ("keys", "?RegistryAuthKeys"),
            ],
        ),
        "RegistryAuthKeys" => array(value, "signing-key|password", 0, 1),
        "RegistryAuthObjects" => array(value, "RegistryAuthObject", 1, 1),
        "RegistryAuthSigning" => object(
            value,
            &[
                ("state", "unobservable|active|inactive|absent"),
                ("generation", "nonce"),
            ],
        ),
        "RegistryAuthExpected" => object(
            value,
            &[
                ("secret", "?uid"),
                ("registration", "?IssuerExpectedRegistration"),
            ],
        ),
        "RegistryAuthPreflight" => object(
            value,
            &[
                ("objects", "RegistryAuthObjects"),
                ("registration", "IssuerRegistration"),
                ("signing", "RegistryAuthSigning"),
            ],
        ),
        "RegistryAuthHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-registry-auth"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-objects|create-object|register-input|activate",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "RegistryAuthRecipe"),
                    ("expected", "RegistryAuthExpected"),
                    ("resource", "?Resource"),
                    ("preflight", "?RegistryAuthPreflight"),
                    ("projection", "?Projection"),
                ],
            )?;
            let action = value.field("action")?;
            let mutation = !action.equals("inspect-objects")?;
            require(
                value.field("resource")?.is_null() != mutation
                    && value.field("preflight")?.is_null() != mutation
                    && value.field("projection")?.is_null() != action.equals("register-input")?,
                Failure::Integrity,
            )?;
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "RegistryAuthResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("objects", "?RegistryAuthObjects"),
                ("registration", "?IssuerRegistration"),
                ("signing", "?RegistryAuthSigning"),
                ("services", "?unobserved|not-ready"),
                ("failure", "?failure"),
            ],
        ),
        "RegistryTokenOriginList" => array(value, "RegistryServiceOrigin", 5, 5),
        "RegistryTokenCertificateOrigin" => {
            object(value, &[("operation", "operation"), ("sha256", "hash")])
        }
        "RegistryTokenSwitchOrigin" => object(
            value,
            &[
                ("operation", "operation"),
                ("configuration_sha256", "hash"),
                ("certificate_sha256", "hash"),
            ],
        ),
        "RegistryTokenOrigins" => object(
            value,
            &[
                ("objects", "?RegistryTokenOriginList"),
                ("certificate", "?RegistryTokenCertificateOrigin"),
                ("switch", "?RegistryTokenSwitchOrigin"),
                ("principals", "?RegistryTokenPrincipalsOrigin"),
            ],
        ),
        "RegistryTokenPrincipalsOrigin" => object(
            value,
            &[
                ("operation", "operation"),
                ("recipe_sha256", "hash"),
                ("secrets", "RegistryTokenPrincipalSecrets"),
            ],
        ),
        "RegistryTokenPrincipalSecrets" => array(value, "RegistryTokenPrincipalSecret", 1, 8),
        "RegistryTokenPrincipalSecret" => object(
            value,
            &[
                ("id", "uid"),
                ("generation", "nonce"),
                ("name", "name"),
                ("uid", "uid"),
                ("operation", "operation"),
                ("recipe_sha256", "hash"),
            ],
        ),
        "RegistryTokenPrincipals" => array(value, "RegistryTokenPrincipal", 1, 8),
        "RegistryTokenPrincipal" => object(
            value,
            &[
                ("name", "name"),
                ("purpose", "publication|node-pull|maintenance"),
                ("repositories", "RegistryTokenPaths"),
                ("actions", "RegistryTokenActions"),
                ("secret", "RegistryTokenPrincipalSecret"),
            ],
        ),
        "RegistryTokenPaths" => array(value, "name", 1, 64),
        "RegistryTokenActions" => array(value, "pull|push|delete", 1, 3),
        "RegistryTokenPrincipalFact" => object(
            value,
            &[
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("activation", "?inactive|active"),
            ],
        ),
        "RegistryTokenPrincipalFacts" => array(value, "RegistryTokenPrincipalFact", 1, 8),
        "RegistryTokenGrants" => array(
            value,
            "granted|other|unreachable|untrusted|unobservable",
            0,
            8,
        ),
        "RegistryTokenImage" => object(
            value,
            &[
                ("image", "=broil.invalid/candidate/auth"),
                ("digest", "hash"),
            ],
        ),
        "RegistryTokenToken" => object(
            value,
            &[
                ("realm", "name"),
                ("path", "/auth|/auth/token"),
                ("service", "name"),
                ("issuer", "=broil-registry-token"),
            ],
        ),
        "RegistryTokenCertificate" => object(value, &[("pem", "name"), ("sha256", "hash")]),
        "RegistryTokenSigning" => object(
            value,
            &[
                ("name", "name"),
                ("uid", "uid"),
                ("generation", "nonce"),
                ("operation", "operation"),
                ("recipe_sha256", "hash"),
            ],
        ),
        "RegistryTokenAnnotations" => object(
            value,
            &[
                ("broil.dev/cluster-uid", "uid"),
                ("broil.dev/creation-operation", "operation"),
                ("broil.dev/owner", "nonce"),
                ("broil.dev/profile-sha256", "hash"),
                ("broil.dev/recipe-sha256", "hash"),
            ],
        ),
        "RegistryTokenServiceObject" => object(
            value,
            &[("uid", "uid"), ("annotations", "RegistryTokenAnnotations")],
        ),
        "RegistryTokenService" => object(
            value,
            &[
                ("configmap", "RegistryTokenServiceObject"),
                ("deployment", "RegistryTokenServiceObject"),
                ("image", "name"),
                ("path", "path"),
                ("writer", "name"),
                ("writer_generation", "counter"),
            ],
        ),
        "RegistryTokenServiceV1" => object(
            value,
            &[
                ("configmap", "RegistryTokenServiceObject"),
                ("deployment", "RegistryTokenServiceObject"),
                ("image", "name"),
                ("volume", "name"),
            ],
        ),
        "RegistryTokenRecipe" if value.optional("storage_member")?.is_some() => {
            check(value, "RegistryTokenRecipeV1")
        }
        "RegistryTokenRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("members", "Members"),
                ("anchor_uid", "uid"),
                ("version", "name"),
                ("registry", "uid"),
                ("image", "RegistryTokenImage"),
                ("assets", "RegistryServiceAssetList"),
                ("tolerations", "RegistryServiceTolerations"),
                ("endpoint", "RegistryEndpointEndpoint"),
                ("trust", "RegistryEndpointTrust"),
                ("ingress", "RegistryEndpointIngress"),
                ("token", "RegistryTokenToken"),
                ("certificate", "RegistryTokenCertificate"),
                ("signing", "RegistryTokenSigning"),
                ("service", "RegistryTokenService"),
                ("principals", "?RegistryTokenPrincipals"),
                ("stage", "create|extend|configure|switch|observe|principals"),
                ("origins", "RegistryTokenOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryTokenRecipeV1" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("storage_member", "Member"),
                ("anchor_uid", "uid"),
                ("version", "name"),
                ("registry", "uid"),
                ("image", "RegistryTokenImage"),
                ("assets", "RegistryServiceAssets"),
                ("tolerations", "RegistryServiceTolerations"),
                ("endpoint", "RegistryEndpointEndpoint"),
                ("trust", "RegistryEndpointTrust"),
                ("ingress", "RegistryEndpointIngress"),
                ("token", "RegistryTokenToken"),
                ("certificate", "RegistryTokenCertificate"),
                ("signing", "RegistryTokenSigning"),
                ("service", "RegistryTokenServiceV1"),
                ("principals", "?RegistryTokenPrincipals"),
                ("stage", "create|configure|switch|observe|principals"),
                ("origins", "RegistryTokenOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryTokenExpectedObjects" => array(value, "?uid", 5, 5),
        "RegistryTokenExpected" => object(
            value,
            &[
                ("objects", "RegistryTokenExpectedObjects"),
                ("certificate", "?hash"),
                ("configuration", "?hash"),
                ("principals", "?RegistryTokenPrincipals"),
            ],
        ),
        "RegistryTokenObject" => object(
            value,
            &[
                (
                    "kind",
                    "NetworkPolicy|Secret|DaemonSet|Deployment|Service|IngressRoute",
                ),
                ("namespace", "=broil-registry"),
                ("name", "=broil-registry-token"),
                ("uid", "?uid"),
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("spec_sha256", "?hash"),
            ],
        ),
        "RegistryTokenObjects" => array(value, "RegistryTokenObject", 5, 5),
        "RegistryTokenSigningFact" => object(
            value,
            &[
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("activation", "?inactive|active"),
            ],
        ),
        "RegistryTokenConfigMap" => object(
            value,
            &[
                ("configmap", "unobservable|absent|drifted|base|switched"),
                ("configuration_sha256", "?hash"),
            ],
        ),
        "RegistryTokenRegistry" => object(
            value,
            &[
                ("configmap", "unobservable|absent|drifted|base|switched"),
                ("configuration_sha256", "?hash"),
                ("process", "RegistryServiceProcess"),
            ],
        ),
        "RegistryTokenEnforcement" => object(
            value,
            &[
                (
                    "registry",
                    "challenge|open|other|unreachable|untrusted|unobservable",
                ),
                ("token", "refused|other|unreachable|untrusted|unobservable"),
            ],
        ),
        "RegistryTokenEnforcementList" => array(value, "RegistryTokenEnforcement", 1, 128),
        "RegistryTokenPod" => object(
            value,
            &[("member", "name"), ("ready", "bool"), ("restarts", "?uint")],
        ),
        "RegistryTokenPods" => array(value, "RegistryTokenPod", 1, 128),
        "RegistryTokenProcess" => object(
            value,
            &[
                ("state", "ready|not-ready"),
                (
                    "reason",
                    "?unobservable|daemonset|absent|pods|failed|pending|starting",
                ),
                ("pods", "RegistryTokenPods"),
            ],
        ),
        "RegistryTokenApi" => object(
            value,
            &[
                ("objects", "RegistryTokenObjects"),
                ("registry", "RegistryTokenConfigMap"),
            ],
        ),
        "RegistryTokenPrincipalsApi" => object(
            value,
            &[
                ("objects", "RegistryTokenObjects"),
                ("principals", "RegistryTokenPrincipalFacts"),
                ("registry", "RegistryTokenConfigMap"),
            ],
        ),
        "RegistryTokenPreflight" => {
            if value.raw().starts_with(b"{\"generation\":") {
                check(value, "RegistryServiceHost")
            } else {
                check(value, "RegistryTokenApi")
                    .or_else(|_| check(value, "RegistryTokenPrincipalsApi"))
            }
        }
        "RegistryTokenHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-registry-token"),
                    ("version", "version-2"),
                    (
                        "action",
                        "inspect-host|import-image|inspect-objects|create-object|configure-token|switch-registry|configure-principals",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "RegistryTokenRecipe"),
                    ("expected", "RegistryTokenExpected"),
                    ("resource", "?Resource"),
                    ("preflight", "?RegistryTokenPreflight"),
                    ("object_ordinal", "?uint"),
                    ("probe", "bool"),
                    ("member", "?Member"),
                ],
            )?;
            let action = value.field("action")?;
            let create = action.equals("create-object")?;
            let import = action.equals("import-image")?;
            require(
                value.field("member")?.is_null() != (import || action.equals("inspect-host")?)
                    && value.field("recipe")?.optional("storage_member")?.is_none(),
                Failure::Integrity,
            )?;
            let mutation = !(action.equals("inspect-host")? || action.equals("inspect-objects")?);
            let preflight = value.field("preflight")?;
            let ordinal = value.field("object_ordinal")?;
            let principals = action.equals("configure-principals")?;
            require(
                value.field("resource")?.is_null() != mutation
                    && preflight.is_null() != mutation
                    && (!mutation || preflight.raw().starts_with(b"{\"generation\":") == import)
                    && (!mutation
                        || preflight
                            .raw()
                            .windows(14)
                            .any(|w| w == b"\"principals\":[")
                            == principals)
                    && ordinal.is_null() != create,
                Failure::Integrity,
            )?;
            if create {
                integer(ordinal, 1, 5)?;
            }
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "RegistryTokenResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("generation", "?ready|not-ready"),
                ("image", "?ready|conflicting|not-ready|unobservable"),
                ("runtime", "?ready|not-ready"),
                ("objects", "?RegistryTokenObjects"),
                ("signing", "?RegistryTokenSigningFact"),
                ("token", "?RegistryTokenProcess"),
                ("registry", "?RegistryTokenRegistry"),
                ("nodes", "?RegistryStorageNodes"),
                ("enforcement", "?RegistryTokenEnforcementList"),
                ("principals", "?RegistryTokenPrincipalFacts"),
                ("grants", "?RegistryTokenGrants"),
                ("failure", "?failure"),
            ],
        ),
        "RegistryReplicationMember" => object(
            value,
            &[
                ("machine", "name"),
                ("member", "name"),
                ("role", "server|agent"),
                ("route", "Route"),
                ("jump", "?Route"),
                ("node_uid", "?uid"),
                ("node_ip", "ipv4"),
            ],
        ),
        "RegistryReplicationMembers" => array(value, "RegistryReplicationMember", 1, 128),
        "RegistryReplicationDevice" => object(value, &[("member", "name"), ("device_id", "?name")]),
        "RegistryReplicationDevices" => array(value, "RegistryReplicationDevice", 1, 128),
        "RegistryReplicationDetached" => array(value, "name", 0, 128),
        "RegistryReplicationAssets" => array(value, "RegistryServiceAssets", 1, 128),
        "RegistryReplicationReader" => object(
            value,
            &[
                ("realm_path", "name"),
                ("service", "name"),
                ("certificate", "name"),
                ("switch_operation", "operation"),
            ],
        ),
        "RegistryReplicationOrigin" => object(value, &[("operation", "operation")]),
        "RegistryReplicationOriginList" => array(value, "?RegistryReplicationOrigin", 1, 128),
        "RegistryReaderOriginList" => array(value, "?RegistryServiceOrigin", 2, 2),
        "RegistryReplicationOrigins" => object(
            value,
            &[
                ("replication", "?RegistryReplicationOriginList"),
                ("objects", "?RegistryReaderOriginList"),
            ],
        ),
        "RegistryReplicationRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("version", "name"),
                ("registry", "uid"),
                ("path", "path"),
                ("writer", "name"),
                ("members", "RegistryReplicationMembers"),
                ("devices", "?RegistryReplicationDevices"),
                ("detached", "RegistryReplicationDetached"),
                ("assets", "RegistryReplicationAssets"),
                ("reader", "RegistryReplicationReader"),
                ("tolerations", "RegistryServiceTolerations"),
                ("stage", "create|extend|configure|observe|move"),
                ("origins", "RegistryReplicationOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryReplicationExpectedObjects" => array(value, "?uid", 2, 2),
        "RegistryReplicationExpected" => object(
            value,
            &[
                ("objects", "RegistryReplicationExpectedObjects"),
                ("device", "?name"),
                ("writer_generation", "?counter"),
            ],
        ),
        "RegistryReplicationCompletion" => object(
            value,
            &[
                ("completion", "uint"),
                ("need_bytes", "uint"),
                ("need_items", "uint"),
                ("need_deletes", "uint"),
            ],
        ),
        "RegistryReplicationFact" => object(
            value,
            &[
                ("record", "absent|owned|owned-drifted|foreign|unobservable"),
                ("service", "running|stopped|unobservable"),
                ("device_id", "?name"),
                ("configuration", "?owned|differs"),
                ("folder", "?sendonly|receiveonly"),
                (
                    "state",
                    "in-sync|syncing|local-changes|stopped|removed|unobserved",
                ),
                ("completion", "?uint"),
                ("need_bytes", "?uint"),
                ("need_items", "?uint"),
                ("need_deletes", "?uint"),
                ("local_changes", "?uint"),
                ("peers_connected", "?uint"),
                ("peers_expected", "?uint"),
                ("bytes_received", "?uint"),
                ("bytes_sent", "?uint"),
                ("peer_completion", "?RegistryReplicationCompletion"),
            ],
        ),
        "RegistryReaderObject" => object(
            value,
            &[
                ("kind", "ConfigMap|DaemonSet"),
                ("namespace", "=broil-registry"),
                ("name", "=broil-registry-reader"),
                ("uid", "?uid"),
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
            ],
        ),
        "RegistryReaderObjects" => array(value, "RegistryReaderObject", 2, 2),
        "RegistryReplicationPod" => object(
            value,
            &[("member", "name"), ("pod", "?name"), ("ready", "?bool")],
        ),
        "RegistryReplicationPods" => array(value, "RegistryReplicationPod", 1, 128),
        "RegistryReplicationProcess" => {
            object(value, &[("state", "ready|not-ready"), ("node", "?name")])
        }
        "RegistryReplicationWriter" => object(
            value,
            &[
                ("class", "absent|owned|foreign|unobservable"),
                ("uid", "?uid"),
                ("generation", "?uint"),
                ("process", "RegistryReplicationProcess"),
            ],
        ),
        "RegistryReplicationApi" => object(
            value,
            &[
                ("objects", "RegistryReaderObjects"),
                ("writer", "RegistryReplicationWriter"),
            ],
        ),
        "RegistryReplicationPreflight" => {
            if value.raw().starts_with(b"{\"objects\":") {
                check(value, "RegistryReplicationApi")
            } else {
                check(value, "RegistryReplicationFact")
            }
        }
        "RegistryReplicationHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-registry-replication"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-replication|create-replication|create-replica|configure-replication|scan-replica|revert-replica|remove-device|stop-replication|inspect-objects|create-object|configure-reader|stop-writer|start-writer",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("wait_ms", "?uint"),
                    ("recipe", "RegistryReplicationRecipe"),
                    ("expected", "RegistryReplicationExpected"),
                    ("resource", "?Resource"),
                    ("preflight", "?RegistryReplicationPreflight"),
                    ("member", "?name"),
                ],
            )?;
            let action = value.field("action")?;
            let read = action.equals("inspect-replication")? || action.equals("inspect-objects")?;
            let host = action.equals("inspect-replication")?
                || action.equals("create-replication")?
                || action.equals("create-replica")?
                || action.equals("configure-replication")?
                || action.equals("scan-replica")?
                || action.equals("revert-replica")?
                || action.equals("remove-device")?
                || action.equals("stop-replication")?;
            require(
                value.field("resource")?.is_null() == read
                    && value.field("member")?.is_null() != host,
                Failure::Integrity,
            )?;
            integer(
                value.field("remaining_ms")?,
                1,
                if read { 30_000 } else { 7_200_000 },
            )
        }
        "RegistryReplicationResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("replication", "?RegistryReplicationFact"),
                ("objects", "?RegistryReaderObjects"),
                ("readers", "?RegistryReplicationPods"),
                ("tokens", "?RegistryReplicationPods"),
                ("writer", "?RegistryReplicationWriter"),
                ("node", "?RegistryStorageNodes"),
                ("cordoned", "?bool"),
                ("failure", "?failure"),
            ],
        ),
        "DeliveryMember" => object(
            value,
            &[
                ("member", "name"),
                ("role", "server|agent"),
                ("platform", "name"),
            ],
        ),
        "DeliveryMembers" => array(value, "DeliveryMember", 0, 128),
        "DeliveryExcluded" => array(value, "name", 0, 128),
        "DeliveryPlatform" => object(
            value,
            &[
                ("platform", "name"),
                ("manifest", "name"),
                ("config", "name"),
            ],
        ),
        "DeliveryPlatforms" => array(value, "DeliveryPlatform", 1, 64),
        "DeliveryImage" => object(
            value,
            &[
                ("image", "name"),
                ("artifact", "name"),
                ("reference", "name"),
                ("repository", "name"),
                ("root", "name"),
                ("managed", "bool"),
                ("platforms", "DeliveryPlatforms"),
            ],
        ),
        "DeliveryRecipeImages" => array(value, "DeliveryImage", 0, 32),
        "DeliveryReferences" => array(value, "name", 1, 1024),
        "DeliveryUnpinEntry" => object(
            value,
            &[("member", "name"), ("references", "DeliveryReferences")],
        ),
        "DeliveryUnpin" => array(value, "DeliveryUnpinEntry", 0, 128),
        "DeliveryRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("action", "release-deliver|release-retain"),
                ("release", "?name"),
                ("release_sha256", "?hash"),
                ("writer", "?name"),
                ("fallback", "?disabled|same-origin"),
                ("members", "DeliveryMembers"),
                ("excluded", "DeliveryExcluded"),
                ("images", "DeliveryRecipeImages"),
                ("unpin", "DeliveryUnpin"),
                ("profile_sha256", "hash"),
            ],
        ),
        "DeliveryCounters" => object(
            value,
            &[("in_bytes_total", "?uint"), ("connections", "?uint")],
        ),
        "DeliveryNode" => object(
            value,
            &[("architecture", "name"), ("counters", "DeliveryCounters")],
        ),
        "DeliveryImageFact" => {
            if value.raw().starts_with(b"{\"attempts\":") {
                object(
                    value,
                    &[
                        ("attempts", "uint"),
                        ("failed", "?pull|digest"),
                        ("image_id", "?name"),
                        ("reference", "name"),
                    ],
                )
            } else {
                object(
                    value,
                    &[
                        ("image_id", "?name"),
                        ("pinned", "bool"),
                        ("present", "bool"),
                        ("reference", "name"),
                        ("repo_digests_match", "bool"),
                    ],
                )
            }
        }
        "DeliveryImageFacts" => array(value, "DeliveryImageFact", 0, 1024),
        "DeliveryMissing" => object(
            value,
            &[
                ("reference", "name"),
                ("class", "root|manifest|config|layer|authorization"),
            ],
        ),
        "DeliveryMissingList" => array(value, "DeliveryMissing", 0, 32),
        "DeliveryClosure" => object(
            value,
            &[
                ("ready", "bool"),
                ("missing", "DeliveryMissingList"),
                ("counters", "DeliveryCounters"),
            ],
        ),
        "DeliveryLog" => object(
            value,
            &[
                ("complete", "bool"),
                ("requests", "uint"),
                ("bytes", "uint"),
                ("all_sized", "bool"),
                ("estimate_bytes", "uint"),
            ],
        ),
        "DeliveryFacts" => object(
            value,
            &[
                ("node", "?DeliveryNode"),
                ("images", "?DeliveryImageFacts"),
                ("closure", "?DeliveryClosure"),
                ("log", "?DeliveryLog"),
            ],
        ),
        "DeliveryHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-delivery"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-images|check-closure|pull-image|pin-image|unpin-image|read-origin-log",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("wait_ms", "?uint"),
                    ("recipe", "DeliveryHeaderRecipe"),
                    ("expected", "Public"),
                    ("resource", "null"),
                    ("preflight", "null"),
                    ("member", "name"),
                ],
            )?;
            let action = value.field("action")?;
            let read = action.equals("inspect-images")?
                || action.equals("check-closure")?
                || action.equals("read-origin-log")?;
            integer(
                value.field("remaining_ms")?,
                1,
                if read { 30_000 } else { 7_200_000 },
            )
        }
        "DeliveryHeaderRecipe" => match value.optional("api_server")? {
            Some(_) => check(value, "ReleaseRecipe"),
            None => check(value, "DeliveryRecipe"),
        },
        "ReleaseChunk" => object(
            value,
            &[("first", "uint"), ("count", "counter"), ("sha256", "hash")],
        ),
        "ReleaseChunks" => array(value, "ReleaseChunk", 0, 512),
        "ReleaseSecretKeys" => array(value, "name", 1, 64),
        "ReleaseSecret" => object(
            value,
            &[
                ("secret", "name"),
                ("resource", "uid"),
                ("keys", "ReleaseSecretKeys"),
            ],
        ),
        "ReleaseSecrets" => array(value, "ReleaseSecret", 0, 32),
        "ReleaseHookPlan" => object(
            value,
            &[
                ("stage", "before_apply|health"),
                ("name", "name"),
                ("sha256", "hash"),
                ("action", "run|rerun|skip"),
            ],
        ),
        "ReleaseHookPlans" => array(value, "ReleaseHookPlan", 0, 32),
        "ReleaseRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("action", "release-apply|release-rollback"),
                ("api_server", "Member"),
                ("release", "name"),
                ("release_sha256", "hash"),
                ("application", "name"),
                ("namespace", "name"),
                ("required", "DeliveryExcluded"),
                ("excluded", "DeliveryExcluded"),
                ("objects_sha256", "hash"),
                ("chunks", "ReleaseChunks"),
                ("secrets", "ReleaseSecrets"),
                ("hooks", "ReleaseHookPlans"),
                ("settles", "?operation"),
                ("version", "version"),
                ("profile_sha256", "hash"),
            ],
        ),
        "ReleaseKindFact" => object(
            value,
            &[
                ("api_version", "name"),
                ("kind", "name"),
                ("served", "bool"),
                ("namespaced", "?bool"),
            ],
        ),
        "ReleaseKindFacts" => array(value, "ReleaseKindFact", 0, 1024),
        "ReleaseObjectFact" => match value.optional("outcome")? {
            Some(_) => object(
                value,
                &[
                    ("kind", "name"),
                    ("name", "name"),
                    ("namespace", "?name"),
                    ("outcome", "created|configured|unchanged|failed|not-run"),
                    ("uid", "?uid"),
                    ("reason", "?conflict|rejected"),
                ],
            ),
            None => object(
                value,
                &[
                    ("kind", "name"),
                    ("name", "?name"),
                    ("namespace", "?name"),
                    ("uid", "?uid"),
                ],
            ),
        },
        "ReleaseObjectFacts" => array(value, "ReleaseObjectFact", 0, 1024),
        "ReleaseWorkload" => object(
            value,
            &[
                ("kind", "name"),
                ("name", "name"),
                ("namespace", "name"),
                ("desired", "?uint"),
                ("updated", "?uint"),
                ("ready", "?uint"),
                ("available", "?uint"),
                ("outcome", "succeeded|failed|not-ready|paused|stalled"),
            ],
        ),
        "ReleaseWorkloads" => array(value, "ReleaseWorkload", 0, 1024),
        "ReleasePod" => object(
            value,
            &[
                ("namespace", "?name"),
                ("pod", "?name"),
                ("node", "?name"),
                ("reason", "node|digest"),
                ("container", "?name"),
                ("image_id", "?text"),
            ],
        ),
        "ReleasePods" => array(value, "ReleasePod", 0, 4096),
        "ReleasePresence" => object(value, &[("truncated", "bool")]),
        "ReleaseSecretFact" => match value.optional("outcome")? {
            Some(_) => object(
                value,
                &[
                    ("name", "name"),
                    ("uid", "?uid"),
                    ("outcome", "created|configured|unchanged"),
                    ("version", "?text"),
                ],
            ),
            None => object(value, &[("name", "name"), ("uid", "?uid")]),
        },
        "ReleaseSecretFacts" => array(value, "ReleaseSecretFact", 0, 32),
        "ReleaseFacts" => object(
            value,
            &[
                ("kinds", "?ReleaseKindFacts"),
                ("objects", "?ReleaseObjectFacts"),
                ("secrets", "?ReleaseSecretFacts"),
                ("workloads", "?ReleaseWorkloads"),
                ("pods", "?ReleasePods"),
                ("presence", "?ReleasePresence"),
            ],
        ),
        "ReleaseHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-release"),
                    ("version", "version"),
                    (
                        "action",
                        "discover-kinds|apply-objects|inspect-workloads|observe-release",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("wait_ms", "?uint"),
                    ("recipe", "ReleaseRecipe"),
                    ("expected", "Public"),
                ],
            )?;
            let mutation = value.field("action")?.equals("apply-objects")?;
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "ReleaseResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("kinds", "?ReleaseKindFacts"),
                ("objects", "?ReleaseObjectFacts"),
                ("secrets", "?ReleaseSecretFacts"),
                ("workloads", "?ReleaseWorkloads"),
                ("pods", "?ReleasePods"),
                ("presence", "?ReleasePresence"),
                ("failure", "?failure"),
            ],
        ),
        "ReleaseSettledHook" => object(value, &[("name", "name"), ("outcome", "=unknown")]),
        "ReleaseSettledHooks" => array(value, "ReleaseSettledHook", 1, 16),
        "DeliveryResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("node", "?DeliveryNode"),
                ("images", "?DeliveryImageFacts"),
                ("closure", "?DeliveryClosure"),
                ("log", "?DeliveryLog"),
                ("failure", "?failure"),
            ],
        ),
        "NodeAccessRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("member", "Member"),
                ("first_server", "Member"),
                ("version", "name"),
                ("profile_sha256", "hash"),
                ("api_endpoint", "api-endpoint"),
            ],
        ),
        "NodeAccessHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-node"),
                    ("version", "version"),
                    ("action", "=access"),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "uint"),
                    ("recipe", "NodeAccessRecipe"),
                    ("mode", "check|export"),
                ],
            )?;
            integer(value.field("remaining_ms")?, 1, 30000)
        }
        "NodeViewRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("member", "Member"),
                ("first_server", "Member"),
                ("version", "name"),
                ("profile_sha256", "hash"),
            ],
        ),
        "NodeViewHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-node"),
                    ("version", "version"),
                    ("action", "=view"),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "uint"),
                    ("recipe", "NodeViewRecipe"),
                    ("query", "api|nodes|workloads|services"),
                    ("limit", "uint"),
                ],
            )?;
            integer(value.field("remaining_ms")?, 1, 30000)?;
            integer(
                value.field("limit")?,
                1,
                if value.field("query")?.equals("api")? {
                    1
                } else {
                    1000
                },
            )
        }
        "NodeViewResult" => {
            object(
                value,
                &[
                    ("kind", "=result"),
                    ("status", "ok|refused|busy|bound|unsupported-version"),
                    ("failure", "?failure"),
                    ("data", "?NodeViewData"),
                    ("truncated", "bool"),
                ],
            )?;
            require(
                value.field("status")?.equals("ok")? == value.field("failure")?.is_null(),
                Failure::Integrity,
            )
        }
        "NodeViewData" => {
            if value.optional("api")?.is_some() {
                object(
                    value,
                    &[
                        ("api", "ready|not-ready|unobserved"),
                        ("datastore", "ready|not-ready|unobserved"),
                    ],
                )
            } else {
                object(value, &[("items", "ViewItems")])
            }
        }
        "ViewItems" => array(value, "ViewItem", 0, 1000),
        "ViewStrings" => array(value, "text", 0, 4096),
        "ViewRoles" => array(value, "server|agent", 1, 1),
        "ViewItem" => {
            if value.optional("version")?.is_some() {
                object(
                    value,
                    &[
                        ("name", "name"),
                        ("uid", "uid"),
                        ("version", "name"),
                        ("ready", "bool"),
                        ("roles", "ViewRoles"),
                        ("labels", "ViewStrings"),
                        ("taints", "ViewStrings"),
                    ],
                )
            } else if value.optional("kind")?.is_some() {
                object(
                    value,
                    &[
                        ("kind", "Pod|Deployment|StatefulSet|DaemonSet|Job"),
                        ("namespace", "name"),
                        ("name", "name"),
                        ("uid", "uid"),
                        ("generation", "?uint"),
                        ("observed_generation", "?uint"),
                        ("owner", "?ViewController"),
                        ("phase", "?Pending|Running|Succeeded|Failed|Unknown"),
                        ("desired", "?uint"),
                        ("ready", "?uint"),
                        ("available", "?uint"),
                        ("succeeded", "?uint"),
                        ("failed", "?uint"),
                    ],
                )
            } else {
                object(
                    value,
                    &[
                        ("namespace", "name"),
                        ("name", "name"),
                        ("uid", "uid"),
                        ("type", "ClusterIP|NodePort|LoadBalancer|ExternalName"),
                        ("ports", "ViewPorts"),
                        ("cluster_ips", "ViewStrings"),
                        ("external_ips", "ViewStrings"),
                        ("load_balancer", "ViewAddresses"),
                    ],
                )
            }
        }
        "ViewController" => object(value, &[("kind", "name"), ("name", "name"), ("uid", "uid")]),
        "ViewPorts" => array(value, "ViewPort", 0, 4096),
        "ViewPort" => {
            object(
                value,
                &[
                    ("name", "?name"),
                    ("protocol", "TCP|UDP|SCTP"),
                    ("port", "uint"),
                    ("target_port", "ViewTargetPort"),
                    ("node_port", "?uint"),
                ],
            )?;
            integer(value.field("port")?, 1, 65535)?;
            if !value.field("node_port")?.is_null() {
                integer(value.field("node_port")?, 1, 65535)?;
            }
            Ok(())
        }
        "ViewTargetPort" => {
            if value.number().is_ok() {
                integer(value, 1, 65535)
            } else {
                text(value, |s| !s.is_empty())
            }
        }
        "ViewAddresses" => array(value, "ViewAddress", 0, 4096),
        "ViewAddress" => object(value, &[("ip", "?name"), ("hostname", "?name")]),
        "RestartRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("version", "name"),
                ("run", "operation"),
                ("position", "uint"),
                ("plan", "NodePlan"),
                ("plan_sha256", "hash"),
                ("member", "Member"),
                ("wave_end", "bool"),
                ("profile_sha256", "hash"),
            ],
        ),
        "NodeRecipe" => match value.optional("registries")? {
            Some(_) => check(value, "ConfigureRecipe"),
            None if value.optional("participants")?.is_some() => check(value, "MemberRecipe"),
            None if value.optional("schema")?.is_some() => check(value, "AgentJoinRecipe"),
            None => check(value, "RestartRecipe"),
        },
        "MemberRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("version", "name"),
                (
                    "action",
                    "node-drain|node-uncordon|node-remove|node-replace|rebind-declaration",
                ),
                ("phase", "?begin|complete"),
                ("member", "Member"),
                ("participants", "Members"),
                ("removed", "OwnerRemovals"),
                ("writer", "?OwnerWriter"),
                ("reachability", "reachable|unreachable"),
                ("writer_move", "?Public"),
                ("transition", "?Public"),
                ("decision_sha256", "?hash"),
                ("profile_sha256", "hash"),
            ],
        ),
        "MemberExpected" => object(
            value,
            &[
                ("node_uid", "?uid"),
                ("pods", "?MemberEvictPods"),
                ("after", "?MemberCursor"),
                ("view", "?classify|wait|remaining"),
            ],
        ),
        "MemberEvictPods" => array(value, "MemberCursor", 1, 32),
        "ConfigureRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("version", "name"),
                ("run", "operation"),
                ("position", "uint"),
                ("plan", "ConfigurePlan"),
                ("plan_sha256", "hash"),
                ("member", "Member"),
                ("wave_end", "bool"),
                ("profile_sha256", "hash"),
                ("registries", "NodeRegistryEntries"),
            ],
        ),
        "ConfigurePlan" => object(
            value,
            &[
                ("members", "ConfigurePlanMembers"),
                ("wave_width", "AgentWaveWidth"),
                ("waves", "NodeWaves"),
                ("profile_sha256", "hash"),
            ],
        ),
        "ConfigurePlanMembers" => array(value, "ConfigurePlanMember", 1, 128),
        "ConfigurePlanMember" => object(
            value,
            &[
                ("member", "name"),
                ("role", "server|agent"),
                ("recipe_identity_sha256", "hash"),
                ("registries_sha256", "hash"),
            ],
        ),
        "NodeRegistryEntries" => array(value, "NodeRegistryEntry", 1, 8),
        "NodeRegistryEntry" if value.optional("managed")?.is_some() => object(
            value,
            &[
                ("registry", "uid"),
                ("authority", "name"),
                ("origin", "name"),
                ("managed", "bool"),
                ("username", "name"),
                ("fallback", "disabled|same-origin"),
                ("principal", "?NodeRegistryGeneration"),
                ("resource", "NodeRegistryGeneration"),
                ("ca", "bool"),
            ],
        ),
        "NodeRegistryEntry" => object(
            value,
            &[
                ("registry", "uid"),
                ("authority", "name"),
                ("origin", "name"),
                ("username", "name"),
                ("fallback", "disabled|same-origin"),
                ("principal", "?NodeRegistryGeneration"),
                ("resource", "NodeRegistryGeneration"),
                ("ca", "bool"),
            ],
        ),
        "NodeRegistryGeneration" => object(value, &[("id", "uid"), ("generation", "nonce")]),
        "NodeExpectation" => match value.optional("registries")? {
            Some(_) => object(value, &[("registries", "NodeRegistryEntries")]),
            None if value.optional("pods")?.is_some() => check(value, "MemberExpected"),
            None => check(value, "NodeExpected"),
        },
        "NodePlan" => object(
            value,
            &[
                ("members", "NodePlanMembers"),
                ("wave_width", "AgentWaveWidth"),
                ("waves", "NodeWaves"),
                ("profile_sha256", "hash"),
            ],
        ),
        "NodePlanMembers" => array(value, "NodePlanMember", 1, 128),
        "NodePlanMember" => object(
            value,
            &[
                ("member", "name"),
                ("role", "server|agent"),
                ("recipe_identity_sha256", "hash"),
            ],
        ),
        "NodeWaves" => array(value, "NodeWave", 0, 128),
        "NodeWave" => array(value, "name", 1, 16),
        "NodeExpected" => object(
            value,
            &[
                ("member", "name"),
                ("node_uid", "uid"),
                ("labels", "?NodeEntries"),
                ("taints", "?NodeEntries"),
                ("lease_after_ms", "uint"),
            ],
        ),
        "NodeHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-node"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-member|observe-node|restart|configure-registries|cordon|\
                         uncordon|observe-drain|evict|delete-node|stop-member|start-member",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "NodeRecipe"),
                    ("expected", "?NodeExpectation"),
                    ("wait_ms", "?uint"),
                ],
            )?;
            let action = value.field("action")?;
            let member = value.field("recipe")?.optional("participants")?.is_some()
                || action.equals("start-member")?
                    && value.field("recipe")?.optional("schema")?.is_some();
            let tags = [
                "cordon",
                "uncordon",
                "observe-drain",
                "evict",
                "delete-node",
                "stop-member",
                "start-member",
            ];
            let mut tagged = None;
            for tag in tags {
                if action.equals(tag)? {
                    tagged = Some(tag);
                }
            }
            if member || tagged.is_some() {
                let expected = value.field("expected")?;
                let evict = tagged == Some("evict");
                require(
                    member
                        && tagged.is_some()
                        && !expected.is_null()
                        && expected.optional("pods")?.is_some()
                        && expected.field("pods")?.is_null() != evict
                        && value.field("wait_ms")?.is_null(),
                    Failure::Integrity,
                )?;
                return integer(
                    value.field("remaining_ms")?,
                    1,
                    if tagged == Some("observe-drain") {
                        30_000
                    } else {
                        7_200_000
                    },
                );
            }
            let observe = action.equals("observe-node")?;
            let configure = value.field("recipe")?.optional("registries")?.is_some();
            let listed = configure && action.equals("inspect-member")?;
            let expected = value.field("expected")?;
            let entries = !expected.is_null() && expected.optional("registries")?.is_some();
            require(
                expected.is_null() != (observe || listed)
                    && entries == listed
                    && value.field("wait_ms")?.is_null() != observe
                    && (configure || !action.equals("configure-registries")?),
                Failure::Integrity,
            )?;
            if observe {
                integer(value.field("wait_ms")?, 25_000, 25_000)?;
            }
            integer(
                value.field("remaining_ms")?,
                1,
                if action.equals("restart")? || action.equals("configure-registries")? {
                    7_200_000
                } else {
                    30_000
                },
            )
        }
        "NodeUnit" => object(
            value,
            &[
                ("name", "broil-k3s.service|broil-k3s-agent.service"),
                ("active", "name"),
                ("sub", "name"),
                ("result", "name"),
                ("invocation", "?nonce"),
                ("previous_invocation", "?nonce"),
                ("n_restarts", "uint"),
            ],
        ),
        "NodeFacts" => object(
            value,
            &[
                ("member", "name"),
                ("present", "bool"),
                ("condition", "ready|not-ready|unobserved"),
                ("uid", "ready|not-ready|unobserved"),
                ("kubelet", "ready|not-ready|unobserved"),
                ("labels", "ready|not-ready|unobserved"),
                ("taints", "ready|not-ready|unobserved"),
                ("lease", "ready|not-ready|unobserved"),
                ("api", "ready|not-ready|unobserved"),
                ("etcd", "ready|not-ready|unobserved"),
                ("ready", "bool"),
            ],
        ),
        "NodeResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("unit", "?NodeUnit"),
                ("guard", "?pass|fail"),
                ("node", "?NodeFacts"),
                ("member", "?MemberNode"),
                ("failure", "?failure"),
            ],
        ),
        "MemberNode" => object(
            value,
            &[
                ("name", "name"),
                ("present", "bool"),
                ("uid", "?uid"),
                ("cordoned", "bool"),
                ("pods", "MemberPods"),
                ("total", "?uint"),
                ("evictable", "?uint"),
                ("next", "?MemberCursor"),
            ],
        ),
        "MemberCursor" => object(value, &[("namespace", "name"), ("pod", "name")]),
        "MemberPods" => array(value, "MemberPod", 0, 1024),
        "MemberPod" => object(
            value,
            &[
                ("namespace", "name"),
                ("pod", "name"),
                ("class", "daemon|writer|local-storage|unmanaged|evictable"),
                ("terminating", "bool"),
            ],
        ),
        "CertificateOrigins" => object(
            value,
            &[
                ("certificate", "?IssuerSecretOrigin"),
                ("cluster_issuer", "IssuerClusterOrigin"),
            ],
        ),
        "CertificateIssuer" => object(
            value,
            &[
                ("name", "name"),
                ("cluster_issuer_name", "name"),
                ("secret_name", "name"),
            ],
        ),
        "CertificateNames" => array(value, "dns-name", 1, 1024),
        "CertificateSpec" => object(
            value,
            &[
                ("dns_names", "CertificateNames"),
                ("duration_s", "counter"),
                ("renew_before_s", "counter"),
            ],
        ),
        "CertificateRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("anchor_uid", "uid"),
                ("version", "name"),
                ("certificate", "name"),
                ("resource", "Resource"),
                ("certificate_name", "name"),
                ("secret_name", "name"),
                ("issuer", "CertificateIssuer"),
                ("spec", "CertificateSpec"),
                ("stage", "create|observe"),
                ("origins", "CertificateOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "CertificateObject" => object(
            value,
            &[
                ("kind", "Certificate|Secret|ClusterIssuer"),
                ("namespace", "?=cert-manager"),
                ("name", "name"),
                ("uid", "?uid"),
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("spec_sha256", "?hash"),
            ],
        ),
        "CertificateObjects" => array(value, "CertificateObject", 3, 3),
        "CertificateReady" => object(
            value,
            &[
                ("state", "ready|not-ready"),
                (
                    "reason",
                    "observed|unobservable|issuer|absent|expired|rejected|pending|names|lifetime",
                ),
            ],
        ),
        "CertificateIssued" => object(
            value,
            &[
                ("not_before", "utc-time"),
                ("not_after", "utc-time"),
                ("renewal_time", "utc-time"),
                ("chain_not_after", "utc-time"),
                ("renewal", "issuer|failed|overdue|issuing|scheduled"),
                ("last_failure_time", "?utc-time"),
            ],
        ),
        "CertificateFact" => object(
            value,
            &[
                ("ready", "CertificateReady"),
                ("issued", "?CertificateIssued"),
            ],
        ),
        "CertificatePreflight" => object(
            value,
            &[
                ("objects", "CertificateObjects"),
                ("certificate", "CertificateFact"),
            ],
        ),
        "CertificateHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-certificate"),
                    ("version", "version"),
                    ("action", "inspect-objects|create-object"),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "CertificateRecipe"),
                    ("expected", "CertificateExpected"),
                    ("resource", "?Resource"),
                    ("preflight", "?CertificatePreflight"),
                ],
            )?;
            let mutation = value.field("action")?.equals("create-object")?;
            require(
                value.field("resource")?.is_null() != mutation
                    && value.field("preflight")?.is_null() != mutation,
                Failure::Integrity,
            )?;
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "CertificateExpected" => object(value, &[("certificate", "?uid")]),
        "CertificateResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("objects", "?CertificateObjects"),
                ("certificate", "?CertificateFact"),
                ("services", "?ready|not-ready"),
                ("failure", "?failure"),
            ],
        ),
        "RegistryStorageDirectoryOrigin" => object(
            value,
            &[
                ("operation", "operation"),
                ("recipe_sha256", "hash"),
                ("record_sha256", "hash"),
                ("directory", "FileIdentity"),
                ("data", "FileIdentity"),
                ("fsid", "uint"),
            ],
        ),
        "RegistryStorageVolumeOrigin" => object(
            value,
            &[
                ("operation", "operation"),
                ("recipe_sha256", "hash"),
                ("uid", "uid"),
            ],
        ),
        "RegistryStorageOrigins" => {
            object(value, &[("directories", "RegistryStorageDirectoryOrigins")])
        }
        "RegistryStorageDirectoryOrigins" => {
            array(value, "?RegistryStorageDirectoryOrigin", 1, 128)
        }
        "RegistryStorageOriginsV1" => object(
            value,
            &[
                ("directory", "?RegistryStorageDirectoryOrigin"),
                ("volume", "?RegistryStorageVolumeOrigin"),
            ],
        ),
        "RegistryStorageClaim" => object(
            value,
            &[
                ("apiVersion", "=v1"),
                ("kind", "=PersistentVolumeClaim"),
                ("namespace", "=broil-registry"),
                ("name", "name"),
            ],
        ),
        "RegistryStorageRecipe" if value.optional("storage_member")?.is_some() => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("storage_member", "Member"),
                ("version", "name"),
                ("registry", "uid"),
                ("path", "path"),
                ("capacity_mib", "counter"),
                ("volume", "name"),
                ("claim", "RegistryStorageClaim"),
                ("runtime", "RegistryStorageRuntime"),
                ("stage", "create|observe"),
                ("origins", "RegistryStorageOriginsV1"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryStorageRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("members", "Members"),
                ("version", "name"),
                ("registry", "uid"),
                ("path", "path"),
                ("capacity_mib", "counter"),
                ("runtime", "RegistryStorageRuntime"),
                ("stage", "create|extend|observe"),
                ("origins", "RegistryStorageOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryStorageRuntime" => object(value, &[("uid", "uint"), ("gid", "uint")]),
        "RegistryStorageExpectedDirectory" => object(
            value,
            &[
                ("record_sha256", "hash"),
                ("directory", "FileIdentity"),
                ("data", "FileIdentity"),
                ("fsid", "uint"),
            ],
        ),
        "RegistryStorageExpectedV1" => object(
            value,
            &[
                ("directory", "?RegistryStorageExpectedDirectory"),
                ("volume", "?uid"),
            ],
        ),
        "RegistryStorageAncestor" => {
            object(
                value,
                &[
                    ("depth", "uint"),
                    ("uid", "uint"),
                    ("gid", "uint"),
                    ("mode", "uint"),
                ],
            )?;
            integer(value.field("uid")?, 0, u64::from(u32::MAX))?;
            integer(value.field("gid")?, 0, u64::from(u32::MAX))?;
            integer(value.field("mode")?, 0, 0o7777)
        }
        "RegistryStorageFact" => storage_fact(value),
        "RegistryStorageNode" => object(
            value,
            &[
                ("member", "name"),
                ("node", "ready|not-ready|drifted|unobservable"),
            ],
        ),
        "RegistryStorageNodes" => array(value, "RegistryStorageNode", 1, 128),
        "RegistryStorageFactV1" => object(
            value,
            &[
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("parent", "reserved|safe|absent|unsafe|unobservable"),
                ("filesystem", "supported|unsupported|unobservable"),
                ("available_mib", "?uint"),
                ("record_sha256", "?hash"),
                ("directory", "?FileIdentity"),
                ("data", "?FileIdentity"),
                ("fsid", "?uint"),
            ],
        ),
        "RegistryStorageObject" => object(
            value,
            &[
                ("kind", "=PersistentVolume"),
                ("namespace", "null"),
                ("name", "name"),
                ("uid", "?uid"),
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("spec_sha256", "?hash"),
            ],
        ),
        "RegistryStorageObjects" => array(value, "RegistryStorageObject", 1, 1),
        "RegistryStorageVolume" => object(
            value,
            &[
                ("phase", "?name"),
                ("binding", "pending|reserved|bound|released|failed"),
            ],
        ),
        "RegistryStorageHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-registry-storage"),
                    ("version", "version-2"),
                    ("action", "inspect-storage|create-storage|inspect-objects"),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "RegistryStorageRecipe"),
                    ("expected", "?RegistryStorageExpectedDirectory"),
                    ("resource", "?Resource"),
                    ("preflight", "?RegistryStorageFact"),
                    ("member", "?Member"),
                ],
            )?;
            let action = value.field("action")?;
            let mutation = action.equals("create-storage")?;
            require(
                value.field("resource")?.is_null() != mutation
                    && value.field("preflight")?.is_null() != mutation
                    && value.field("member")?.is_null() == action.equals("inspect-objects")?
                    && value.field("recipe")?.optional("storage_member")?.is_none(),
                Failure::Integrity,
            )?;
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "RegistryStorageResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("storage", "?RegistryStorageFact"),
                ("nodes", "?RegistryStorageNodes"),
                ("failure", "?failure"),
            ],
        ),
        "RegistryServiceOrigin" => object(
            value,
            &[
                ("operation", "operation"),
                ("recipe_sha256", "hash"),
                ("uid", "uid"),
            ],
        ),
        "RegistryServiceOriginList" => array(value, "?RegistryServiceOrigin", 5, 5),
        "RegistryServiceImageOrigin" => object(value, &[("operation", "operation")]),
        "RegistryServiceImageOrigins" => array(value, "?RegistryServiceImageOrigin", 1, 128),
        "RegistryServiceOrigins" => object(
            value,
            &[
                ("objects", "RegistryServiceOriginList"),
                ("configuration", "?hash"),
                ("images", "RegistryServiceImageOrigins"),
            ],
        ),
        "RegistryServiceMemberAssets" => object(
            value,
            &[
                ("member", "name"),
                ("generation", "nonce"),
                ("marker_sha256", "hash"),
            ],
        ),
        "RegistryServiceAssetList" => array(value, "RegistryServiceMemberAssets", 1, 128),
        "RegistryServiceStorage" => object(
            value,
            &[
                ("path", "path"),
                ("capacity_mib", "counter"),
                ("runtime", "RegistryStorageRuntime"),
                ("origins", "RegistryStorageOrigins"),
            ],
        ),
        "RegistryServiceOriginListV1" => array(value, "?RegistryServiceOrigin", 6, 6),
        "RegistryServiceOriginsV1" => object(
            value,
            &[
                ("objects", "RegistryServiceOriginListV1"),
                ("configuration", "?hash"),
            ],
        ),
        "RegistryServiceAssets" => {
            object(value, &[("generation", "nonce"), ("marker_sha256", "hash")])
        }
        "RegistryServiceStorageV1" => object(
            value,
            &[
                ("path", "path"),
                ("capacity_mib", "counter"),
                ("volume", "name"),
                ("claim", "RegistryStorageClaim"),
                ("runtime", "RegistryStorageRuntime"),
                ("origins", "RegistryStorageOriginsV1"),
            ],
        ),
        "RegistryServiceToleration" => object(
            value,
            &[
                ("key", "name"),
                ("value", "text"),
                ("effect", "NoSchedule|PreferNoSchedule|NoExecute"),
            ],
        ),
        "RegistryServiceTolerations" => array(value, "RegistryServiceToleration", 0, 64),
        "RegistryServiceRecipe" if value.optional("storage_member")?.is_some() => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("storage_member", "Member"),
                ("version", "name"),
                ("registry", "uid"),
                ("registry_version", "name"),
                ("image", "name"),
                ("assets", "RegistryServiceAssets"),
                ("storage", "RegistryServiceStorageV1"),
                ("tolerations", "RegistryServiceTolerations"),
                ("stage", "create|observe"),
                ("origins", "RegistryServiceOriginsV1"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryServiceRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("members", "Members"),
                ("writer", "name"),
                ("writer_generation", "counter"),
                ("version", "name"),
                ("registry", "uid"),
                ("registry_version", "name"),
                ("image", "name"),
                ("assets", "RegistryServiceAssetList"),
                ("storage", "RegistryServiceStorage"),
                ("tolerations", "RegistryServiceTolerations"),
                ("stage", "create|extend|observe"),
                ("origins", "RegistryServiceOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryServiceExpectedObjects" => array(value, "?uid", 5, 5),
        "RegistryServiceExpected" => object(
            value,
            &[
                ("storage", "?RegistryStorageExpectedDirectory"),
                ("objects", "RegistryServiceExpectedObjects"),
            ],
        ),
        "RegistryServiceObject" => object(
            value,
            &[
                (
                    "kind",
                    "Namespace|NetworkPolicy|ConfigMap|PersistentVolumeClaim|Service|Deployment",
                ),
                ("namespace", "?=broil-registry"),
                ("name", "name"),
                ("uid", "?uid"),
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("spec_sha256", "?hash"),
            ],
        ),
        "RegistryServiceObjects" => array(value, "RegistryServiceObject", 5, 5),
        "RegistryServiceObjectsV1" => array(value, "RegistryServiceObject", 6, 6),
        "RegistryServiceProcess" => object(
            value,
            &[
                ("state", "ready|not-ready"),
                (
                    "reason",
                    "?unobservable|stopped|deployment|absent|pods|node|failed|pending|starting",
                ),
                ("node", "?uid"),
                ("restarts", "?uint"),
            ],
        ),
        "RegistryServiceVolume" => object(
            value,
            &[
                ("record", "RegistryStorageObject"),
                ("phase", "?name"),
                ("binding", "?pending|reserved|bound|released|failed"),
                ("claim_uid", "?uid"),
            ],
        ),
        "RegistryServiceHost" => object(
            value,
            &[
                ("generation", "ready|not-ready"),
                ("image", "ready|conflicting|not-ready|unobservable"),
                ("runtime", "ready|not-ready"),
            ],
        ),
        "RegistryServiceApiFacts" => object(
            value,
            &[
                ("nodes", "RegistryStorageNodes"),
                ("objects", "RegistryServiceObjects"),
            ],
        ),
        "RegistryServicePreflight" => {
            if value.raw().starts_with(b"{\"nodes\":") {
                check(value, "RegistryServiceApiFacts")
            } else {
                check(value, "RegistryServiceHost")
            }
        }
        "RegistryServiceHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-registry-service"),
                    ("version", "version-2"),
                    (
                        "action",
                        "inspect-host|import-image|inspect-objects|create-object",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "RegistryServiceRecipe"),
                    ("expected", "RegistryServiceExpected"),
                    ("resource", "?Resource"),
                    ("preflight", "?RegistryServicePreflight"),
                    ("object_ordinal", "?uint"),
                    ("member", "?Member"),
                ],
            )?;
            let action = value.field("action")?;
            let create = action.equals("create-object")?;
            let mutation = create || action.equals("import-image")?;
            let host = action.equals("inspect-host")? || action.equals("import-image")?;
            let preflight = value.field("preflight")?;
            let ordinal = value.field("object_ordinal")?;
            require(
                value.field("resource")?.is_null() != mutation
                    && preflight.is_null() != mutation
                    && (!mutation || preflight.raw().starts_with(b"{\"nodes\":") == create)
                    && ordinal.is_null() != create
                    && value.field("member")?.is_null() != host
                    && value.field("recipe")?.optional("storage_member")?.is_none(),
                Failure::Integrity,
            )?;
            if create {
                integer(ordinal, 1, 5)?;
            }
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )
        }
        "RegistryServiceResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("generation", "?ready|not-ready"),
                ("image", "?ready|conflicting|not-ready|unobservable"),
                ("runtime", "?ready|not-ready"),
                ("storage", "?RegistryStorageFact"),
                ("objects", "?RegistryServiceObjects"),
                ("process", "?RegistryServiceProcess"),
                ("nodes", "?RegistryStorageNodes"),
                ("failure", "?failure"),
            ],
        ),
        "RegistryEndpointOriginList" => array(value, "?RegistryServiceOrigin", 3, 3),
        "RegistryEndpointServiceOrigins" => array(value, "RegistryServiceOrigin", 5, 6),
        "RegistryEndpointOrigins" => object(
            value,
            &[
                ("objects", "RegistryEndpointOriginList"),
                ("service", "RegistryEndpointServiceOrigins"),
                ("certificate", "CertificateOrigins"),
            ],
        ),
        "RegistryEndpointEndpoint" => object(
            value,
            &[
                ("name", "name"),
                ("host", "dns-name"),
                ("port", "https-port"),
                ("origin", "name"),
            ],
        ),
        "RegistryEndpointCertificates" => array(value, "name", 1, 256),
        "RegistryEndpointTrust" => object(
            value,
            &[
                ("certificates", "RegistryEndpointCertificates"),
                ("sha256", "hash"),
            ],
        ),
        "RegistryEndpointCertificate" => object(
            value,
            &[
                ("name", "name"),
                ("certificate", "uid"),
                ("secret", "uid"),
                ("uid", "uid"),
                ("cluster_issuer", "uid"),
            ],
        ),
        "RegistryEndpointIngress" => array(value, "ipv4", 1, 128),
        "RegistryEndpointRecipe" => object(
            value,
            &[
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("cluster", "Cluster"),
                ("first_server", "Member"),
                ("anchor_uid", "uid"),
                ("version", "name"),
                ("registry", "uid"),
                ("endpoint", "RegistryEndpointEndpoint"),
                ("trust", "RegistryEndpointTrust"),
                ("certificate", "RegistryEndpointCertificate"),
                ("ingress", "RegistryEndpointIngress"),
                ("stage", "create|observe"),
                ("origins", "RegistryEndpointOrigins"),
                ("profile_sha256", "hash"),
            ],
        ),
        "RegistryEndpointExpectedObjects" => array(value, "?uid", 3, 3),
        "RegistryEndpointExpected" => {
            object(value, &[("objects", "RegistryEndpointExpectedObjects")])
        }
        "RegistryEndpointObject" => object(
            value,
            &[
                ("kind", "NetworkPolicy|IngressRoute"),
                ("namespace", "broil-registry|cert-manager"),
                ("name", "name"),
                ("uid", "?uid"),
                ("class", "absent|owned|owned-drifted|foreign|unobservable"),
                ("spec_sha256", "?hash"),
            ],
        ),
        "RegistryEndpointObjects" => array(value, "RegistryEndpointObject", 3, 3),
        "RegistryEndpointIssued" => object(
            value,
            &[
                ("state", "present|deleted|absent|unobservable"),
                ("leaf_sha256", "?hash"),
            ],
        ),
        "RegistryEndpointServed" => object(
            value,
            &[
                ("state", "ready|not-ready"),
                (
                    "reason",
                    "?unreachable|untrusted|name|stale|unobservable|backend",
                ),
            ],
        ),
        "RegistryEndpointServedList" => array(value, "RegistryEndpointServed", 1, 128),
        "RegistryEndpointPreflight" => object(
            value,
            &[
                ("objects", "RegistryEndpointObjects"),
                ("issued", "RegistryEndpointIssued"),
            ],
        ),
        "RegistryEndpointHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-registry-endpoint"),
                    ("version", "version"),
                    ("action", "inspect-objects|create-object"),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("recipe", "RegistryEndpointRecipe"),
                    ("expected", "RegistryEndpointExpected"),
                    ("resource", "?Resource"),
                    ("preflight", "?RegistryEndpointPreflight"),
                    ("object_ordinal", "?uint"),
                ],
            )?;
            let create = value.field("action")?.equals("create-object")?;
            let ordinal = value.field("object_ordinal")?;
            require(
                value.field("resource")?.is_null() != create
                    && value.field("preflight")?.is_null() != create
                    && ordinal.is_null() != create,
                Failure::Integrity,
            )?;
            if create {
                integer(ordinal, 1, 3)?;
            }
            integer(
                value.field("remaining_ms")?,
                1,
                if create { 7_200_000 } else { 30_000 },
            )
        }
        "RegistryEndpointResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("terminal", "?Terminal"),
                ("objects", "?RegistryEndpointObjects"),
                ("issued", "?RegistryEndpointIssued"),
                ("served", "?RegistryEndpointServedList"),
                ("failure", "?failure"),
            ],
        ),
        "LifecycleHeader" => {
            object(
                value,
                &[
                    ("protocol", "=broil-k3s-lifecycle"),
                    ("version", "version"),
                    (
                        "action",
                        "inspect-installation|activate-server|start-server|observe-server|publish-identity|publish-cluster|prepare-join-source|inspect-owned-server|inspect-join|observe-membership|activate-join|start-join|observe-join|publish-member|inspect-agent|observe-agent-membership|activate-agent|start-agent|observe-agent|publish-agent",
                    ),
                    ("request_id", "nonce"),
                    ("binding", "Binding"),
                    ("remaining_ms", "counter"),
                    ("payload", "Public"),
                ],
            )?;
            let action = value.field("action")?.text()?;
            let source = action.get() == b"prepare-join-source";
            let join = matches!(
                action.get(),
                b"inspect-owned-server"
                    | b"inspect-join"
                    | b"observe-membership"
                    | b"activate-join"
                    | b"start-join"
                    | b"observe-join"
                    | b"publish-member"
            );
            let agent = matches!(
                action.get(),
                b"inspect-agent"
                    | b"observe-agent-membership"
                    | b"activate-agent"
                    | b"start-agent"
                    | b"observe-agent"
                    | b"publish-agent"
            );
            check(
                value.field("payload")?,
                if source {
                    "LifecycleSourcePayload"
                } else if action.get() == b"observe-agent-membership" {
                    "AgentSourcePayload"
                } else if agent {
                    "AgentLifecyclePayload"
                } else if join {
                    "JoinLifecyclePayload"
                } else {
                    "LifecyclePayload"
                },
            )?;
            let mutation = !matches!(
                action.get(),
                b"inspect-installation"
                    | b"observe-server"
                    | b"inspect-owned-server"
                    | b"inspect-join"
                    | b"observe-membership"
                    | b"observe-join"
                    | b"inspect-agent"
                    | b"observe-agent-membership"
                    | b"observe-agent"
            );
            integer(
                value.field("remaining_ms")?,
                1,
                if mutation { 7_200_000 } else { 30_000 },
            )?;
            let publishes = matches!(
                action.get(),
                b"publish-identity" | b"publish-cluster" | b"publish-member" | b"publish-agent"
            );
            if source {
                Ok(())
            } else {
                require(
                    value.field("payload")?.field("identity")?.is_null() != publishes,
                    Failure::Integrity,
                )?;
                if join {
                    require(
                        value.field("payload")?.field("membership")?.is_null()
                            != (action.get() == b"publish-member"),
                        Failure::Integrity,
                    )?;
                }
                if agent {
                    require(
                        value.field("payload")?.field("agent_view")?.is_null()
                            != matches!(action.get(), b"observe-agent" | b"publish-agent"),
                        Failure::Integrity,
                    )?;
                }
                Ok(())
            }
        }
        "Installation" => object(
            value,
            &[
                ("class", "absent|activated|started|owned|foreign"),
                ("publication_state", "unpublished|interrupted|published"),
                ("operation", "?operation"),
                ("attempt", "?nonce"),
                ("recipe_sha256", "?hash"),
                ("recipe_identity_sha256", "?hash"),
                ("marker_sha256", "?hash"),
                ("config_sha256", "?hash"),
                ("unit_sha256", "?hash"),
                ("guard_sha256", "?hash"),
                ("identity", "?LifecycleIdentity"),
            ],
        ),
        "LifecycleResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|failed|refused|bound|busy|unsupported-version|unknown",
                ),
                ("terminal", "?Terminal"),
                ("installation", "?Installation"),
                ("readiness", "?Readiness"),
                ("identity", "?LifecycleIdentity"),
                ("failure", "?failure"),
                ("detail", "?assets|input"),
            ],
        ),
        "JoinLifecycleResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|failed|refused|bound|busy|unsupported-version|unknown",
                ),
                ("terminal", "?Terminal"),
                ("installation", "?Installation"),
                ("readiness", "?Readiness"),
                ("identity", "?LifecycleIdentity"),
                ("membership", "?Membership"),
                ("failure", "?failure"),
                ("detail", "?assets|input"),
            ],
        ),
        "AgentLifecycleResult" => object(
            value,
            &[
                ("kind", "=result"),
                (
                    "status",
                    "ok|failed|refused|bound|busy|unsupported-version|unknown",
                ),
                ("terminal", "?Terminal"),
                ("installation", "?Installation"),
                ("readiness", "?Readiness"),
                ("identity", "?LifecycleIdentity"),
                ("agent_view", "?AgentView"),
                ("failure", "?failure"),
                ("detail", "?assets|input"),
            ],
        ),
        "Transport" => object(
            value,
            &[
                ("dispatch", "none|possible|confirmed"),
                ("exit", "?uint"),
                ("signal", "?uid"),
                ("input_released", "bool"),
                ("staging_cleanup", "clean|residue|unknown"),
            ],
        ),
        "Readiness" => object(
            value,
            &[
                ("api", "unobserved|ready|not-ready|unknown"),
                ("quorum", "unobserved|ready|not-ready|unknown"),
                ("nodes", "unobserved|ready|not-ready|unknown"),
                ("services", "unobserved|ready|not-ready|unknown"),
                ("storage", "unobserved|ready|not-ready|unknown"),
                ("publication", "unobserved|ready|not-ready|unknown"),
            ],
        ),
        "Recovery" => object(
            value,
            &[
                ("choice", "observe|retry|operator-recovery|none"),
                ("proposal", "?Proposal"),
            ],
        ),
        "Proposal" => object(value, &[("decision", "Decision"), ("digest", "approval")]),
        "Decision" => object(
            value,
            &[
                ("schema", "version"),
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("failed_attempt", "nonce"),
                ("original_step", "step"),
                ("action", "reserve-owner|prepare-input"),
                ("request_sha256", "hash"),
                ("local_generation", "nonce"),
                ("members", "Members"),
                ("cluster", "?Cluster"),
                ("resources", "Resources"),
                ("fingerprints", "Fingerprints"),
                ("participants_sha256", "hash"),
                ("receivers", "Receivers"),
                ("effects", "Effects"),
                ("gates", "Gates"),
            ],
        ),
        "Receivers" => array(value, "Receiver", 1, 128),
        "Receiver" => object(
            value,
            &[
                ("machine", "name"),
                ("generation", "uint"),
                ("state", "absent|reserved|active|sealed|retired|unknown"),
                ("terminal_sha256", "?hash"),
                ("retirement_sha256", "?hash"),
            ],
        ),
        "Effects" => array(value, "Effect", 1, 1024),
        "Effect" => object(
            value,
            &[
                ("action", "action"),
                ("machine", "name"),
                ("resource", "?Resource"),
            ],
        ),
        "Gates" => {
            object(
                value,
                &[
                    ("writers_settled", "true"),
                    ("original_selection_intact", "true"),
                    ("destination_absent", "true"),
                    ("lifecycle_required", "bool"),
                ],
            )?;
            require(
                !value.field("lifecycle_required")?.boolean()?,
                Failure::Integrity,
            )
        }
        "Nonces" => array(value, "nonce", 0, 1024),
        "Hashes" => array(value, "hash", 0, 1024),
        "Steps" => array(value, "step", 1, 1024),
        "Sequences" => array(value, "sequence", 0, 4096),
        "Seals" => array(value, "SealEntry", 1, 128),
        "SealEntry" => object(
            value,
            &[
                ("machine", "name"),
                ("generation", "counter"),
                ("seal_sha256", "hash"),
            ],
        ),
        "Source" => object(
            value,
            &[("kind", "controller|receiver"), ("machine", "?name")],
        ),
        "Public" => public(value),
        "Consumer" => object(
            value,
            &[("action", "consumer-action"), ("projection", "Projection")],
        ),
        "consumer-action" => named(
            value,
            "supply-initial-server|supply-server-join|supply-agent-join|check-admin|supply-issuer-ca|supply-issuer-acme|supply-registry-signing|supply-registry-principal|supply-node-registry|supply-recovery-key|supply-recovery-server-token",
        ),
        "Projection" => object(
            value,
            &[
                ("schema", "version"),
                ("binding", "ProjectionBinding"),
                ("declaration", "Public"),
                ("scripts", "Public"),
                ("registries", "Public"),
                ("secrets", "Public"),
                ("references", "ConsumerReferences"),
                ("profile", "Public"),
            ],
        ),
        "ConsumerReferences" => array(value, "ConsumerReference", 0, 1024),
        "ConsumerReference" => object(value, &[("set", "name"), ("key", "name")]),
        "CredentialResource" => object(
            value,
            &[
                (
                    "kind",
                    "server-input|agent-input|admin-access|issuer|registry-auth|node-registry|recovery",
                ),
                ("id", "uid"),
                ("generation", "nonce"),
                ("uid", "?uid"),
            ],
        ),
        "ProjectionBinding" => object(
            value,
            &[
                ("project", "path"),
                ("environment", "name"),
                ("target", "uid"),
                ("owner", "nonce"),
                ("operation", "operation"),
                ("attempt", "nonce"),
                ("source", "?PublicMember"),
                ("destination", "PublicMember"),
                ("cluster", "?Cluster"),
                ("resource", "CredentialResource"),
                ("issuer", "?name"),
                ("service", "?name"),
                ("principal", "?name"),
                ("origin", "?name"),
                ("recovery", "?uid"),
                ("profile_sha256", "hash"),
                ("script_sha256", "hash"),
            ],
        ),
        "Config" => object(
            value,
            &[
                ("target", "Public"),
                ("registries", "Public"),
                ("secrets", "Public"),
                ("scripts", "Public"),
            ],
        ),
        "Terminal" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=terminal"),
                ("binding", "Binding"),
                ("action", "action"),
                ("payload_sha256", "hash"),
                ("outcome", "succeeded|failed|cancelled"),
                ("failure", "?failure"),
                ("effect", "absent|complete|partial|unknown"),
                ("writer_ended", "true"),
                ("resource", "?Resource"),
                ("resource_identity", "?ResourceIdentity"),
                ("completed_ms", "uint"),
            ],
        ),
        "Claim" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=machine-claim"),
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("member", "Member"),
                ("participants_sha256", "hash"),
                ("generation", "counter"),
                ("active_attempt", "?nonce"),
                ("root_identity", "FileIdentity"),
                ("lock_identity", "FileIdentity"),
            ],
        ),
        "Reservation" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=reservation"),
                ("binding", "Binding"),
                ("state", "reserved|active|sealed|retired"),
                ("members", "Members"),
                ("dispatches", "Nonces"),
                ("seal_sha256", "?hash"),
                ("retirement_sha256", "?hash"),
            ],
        ),
        "Intent" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=intent"),
                ("binding", "Binding"),
                ("action", "action"),
                ("payload_sha256", "hash"),
                ("admitted_ms", "uint"),
            ],
        ),
        "Seal" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=seal"),
                ("binding", "Binding"),
                ("dispatches", "Nonces"),
                ("terminal_sha256s", "Hashes"),
                ("sealed_ms", "uint"),
            ],
        ),
        "Retirement" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=retirement"),
                ("binding", "Binding"),
                ("seals", "Seals"),
                ("next_generation", "counter"),
                ("retired_ms", "uint"),
            ],
        ),
        "Grant" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=credential-grant"),
                ("binding", "Binding"),
                ("action", "credential"),
                ("admission_sha256", "hash"),
                ("selection_sha256", "hash"),
                ("resource", "Resource"),
            ],
        ),
        "Ownership" => object(
            value,
            &[
                ("schema", "version"),
                ("owner", "nonce"),
                ("scope", "PublicScope"),
                ("machine", "PublicMember"),
                ("cluster", "?Cluster"),
                ("data", "?FileIdentity"),
            ],
        ),
        "PublicScope" => object(
            value,
            &[
                ("project", "path"),
                ("environment", "name"),
                ("target", "uid"),
            ],
        ),
        "PublicMember" => object(
            value,
            &[
                ("machine", "name"),
                ("member", "?name"),
                ("role", "server|agent|backup"),
                ("node_uid", "?uid"),
            ],
        ),
        "ResourceWitness" => object(
            value,
            &[
                ("resource", "Resource"),
                ("identity", "?ResourceIdentity"),
                ("inactive", "?bool"),
            ],
        ),
        "Identity" => object(
            value,
            &[
                ("member", "Member"),
                ("cluster", "?Cluster"),
                ("readiness", "Readiness"),
            ],
        ),
        "Response" => object(
            value,
            &[
                ("version", "version"),
                (
                    "status",
                    "ok|absent|busy|refused|bound|unsupported-version|failed|unknown",
                ),
                ("data", "Data"),
            ],
        ),
        "Data" => {
            let mut fields = vec![
                ("claim", "?Claim"),
                ("reservation", "?Reservation"),
                ("terminal", "?Terminal"),
                ("seal", "?Seal"),
                ("retirement", "?Retirement"),
                ("ownership", "?Ownership"),
                ("resource", "?ResourceWitness"),
                ("identity", "?Identity"),
                ("failure", "?failure"),
            ];
            if value.optional("history")?.is_some() {
                fields.push(("history", "?HostHistoryReply"));
            }
            object(value, &fields)
        }
        "HostHistoryReply" => object(
            value,
            &[("attempts", "uint"), ("checkpoint", "HostHistory")],
        ),
        "HostHistory" => object(
            value,
            &[
                ("schema", "version"),
                ("kind", "=host-history"),
                ("scope", "Scope"),
                ("owner", "nonce"),
                ("attempts_removed", "uint"),
                ("watermark_sequence", "uint"),
                ("chain_sha256", "hash"),
            ],
        ),
        "Event" => event(value),
        "owner" | "request" | "attempt" | "step-record" | "observation" => record(value, kind),
        _ => Err(Failure::Integrity),
    }
}

fn event(value: Private<'_>) -> Result<()> {
    let kind = value.field("type")?.text()?;
    let kind = std::str::from_utf8(kind.get()).map_err(|_| Failure::Integrity)?;
    let mut fields = vec![("type", "name")];
    fields.extend_from_slice(match kind {
        "local-publication" => &[
            ("record", "owner|request|attempt|step|observation"),
            ("identity", "?FileIdentity"),
            ("state", "durable|not-published|possibly-published"),
        ][..],
        "dispatch" => &[
            ("transport", "Transport"),
            ("outcome", "outcome"),
            ("failure", "?failure"),
        ],
        "receiver" => &[("receipt", "Terminal"), ("transport", "Transport")],
        "identity" => &[
            ("member", "?Member"),
            ("cluster", "?Cluster"),
            ("resources", "Resources"),
            ("readiness", "Readiness"),
        ],
        "reservation" => &[
            ("member", "Member"),
            ("generation", "uint"),
            ("state", "absent|reserved|active|sealed|retired|unknown"),
            ("receipt_sha256", "?hash"),
        ],
        "recovery" => &[
            ("choice", "observe|retry|operator-recovery|none"),
            ("proposal", "?Proposal"),
        ],
        "failure" => &[
            ("failure", "?failure"),
            ("outcome", "outcome"),
            ("completion_unknown", "bool"),
            ("cleanup_unknown", "bool"),
        ],
        "bootstrap-recipe" => &[("recipe", "BootstrapRecipe")],
        "bootstrap-host" => &[("member", "Member"), ("facts", "HostFacts")],
        "bootstrap-asset" => &[
            ("resource", "Resource"),
            ("asset", "asset-id"),
            ("identity", "?FileIdentity"),
            ("state", "absent|received|verified|unknown"),
        ],
        "bootstrap-generation" => &[
            ("resource", "Resource"),
            ("marker", "?CompleteMarker"),
            ("identity", "?FileIdentity"),
        ],
        "lifecycle-recipe" => &[("recipe", "ServerRecipe")],
        "server-recipe" => &[("recipe_kind", "initial|join"), ("recipe", "Public")],
        "server-join-recipe" => &[("recipe", "JoinRecipe")],
        "server-membership" => &[("member", "Member"), ("membership", "?Membership")],
        "agent-recipe" | "agent-join-recipe" => &[("recipe", "AgentJoinRecipe")],
        "agent-membership" => &[("view", "AgentView")],
        "network-recipe" => &[("recipe", "NetworkRecipe")],
        "ingress-recipe" => &[("recipe", "IngressRecipe")],
        "cert-manager-recipe" => &[("recipe", "CertManagerRecipe")],
        "issuer-recipe" => &[("recipe", "IssuerRecipe")],
        "certificate-recipe" => &[("recipe", "CertificateRecipe")],
        "registry-storage-recipe" => &[("recipe", "RegistryStorageRecipe")],
        "registry-service-recipe" => &[("recipe", "RegistryServiceRecipe")],
        "registry-endpoint-recipe" => &[("recipe", "RegistryEndpointRecipe")],
        "registry-auth-recipe" => &[("recipe", "RegistryAuthRecipe")],
        "registry-token-recipe" => &[("recipe", "RegistryTokenRecipe")],
        "replication-recipe" => &[("recipe", "RegistryReplicationRecipe")],
        "replication-observation" => &[
            ("member", "?Member"),
            ("replication", "?RegistryReplicationFact"),
            ("objects", "?RegistryReaderObjects"),
            ("readers", "?RegistryReplicationPods"),
            ("tokens", "?RegistryReplicationPods"),
            ("writer", "?RegistryReplicationWriter"),
            ("node", "?RegistryStorageNodes"),
            ("cordoned", "?bool"),
        ],
        "delivery-recipe" => &[("recipe", "DeliveryRecipe")],
        "release-recipe" => &[("recipe", "ReleaseRecipe")],
        "release-observation" => &[
            ("member", "Member"),
            (
                "action",
                "discover-kinds|apply-objects|inspect-workloads|observe-release|apply-secret",
            ),
            ("facts", "ReleaseFacts"),
        ],
        "release-hook" => &[
            ("stage", "before_apply|health"),
            ("name", "name"),
            ("location", "name"),
            ("attempt", "name"),
            ("exit", "?uint"),
            ("signal", "?name"),
            ("duration_ms", "uint"),
            ("outcome", "succeeded|failed|unknown"),
        ],
        "release-evidence" => &[
            ("release", "name"),
            ("applied", "bool"),
            ("healthy", "bool"),
            ("changed", "bool"),
            ("detail", "?name"),
        ],
        "release-settlement" => &[
            ("operation", "operation"),
            ("approval", "?approval"),
            ("hooks", "ReleaseSettledHooks"),
        ],
        "delivery-observation" => &[
            ("member", "Member"),
            ("kind", "inspect|closure|pull|pin|unpin|origin-log"),
            ("facts", "DeliveryFacts"),
        ],
        "restart-recipe" => &[("recipe", "NodeRecipe")],
        "component-assets" => &[("entries", "IngressMembers")],
        "member-recipe" => &[("recipe", "MemberRecipe")],
        "writer-move" => &[
            ("from", "name"),
            ("to", "name"),
            ("operation", "operation"),
            ("loss_possible", "bool"),
        ],
        "member-observation" => &[
            ("member", "Member"),
            (
                "kind",
                "cordon|uncordon|observe-drain|evict|delete-node|stop-member|start-member",
            ),
            ("node", "?MemberNode"),
            ("unit", "?NodeUnit"),
        ],
        "node-observation" => &[
            ("member", "Member"),
            ("kind", "restart|node|configure"),
            ("unit", "?NodeUnit"),
            ("node", "?NodeFacts"),
        ],
        "node-registry-supply" => &[("principal", "?NodeRegistryGeneration")],
        "registry-token-observation" if value.optional("nodes")?.is_some() => &[
            ("member", "?Member"),
            ("generation", "?ready|not-ready"),
            ("image", "?ready|conflicting|not-ready|unobservable"),
            ("runtime", "?ready|not-ready"),
            ("objects", "?RegistryTokenObjects"),
            ("signing", "?RegistryTokenSigningFact"),
            ("token", "?RegistryTokenProcess"),
            ("registry", "?RegistryTokenRegistry"),
            ("nodes", "?RegistryStorageNodes"),
            ("enforcement", "?RegistryTokenEnforcementList"),
            ("principals", "?RegistryTokenPrincipalFacts"),
            ("grants", "?RegistryTokenGrants"),
        ],
        "registry-token-observation" => &[
            ("member", "?Member"),
            ("generation", "?ready|not-ready"),
            ("image", "?ready|conflicting|not-ready|unobservable"),
            ("runtime", "?ready|not-ready"),
            ("objects", "?RegistryTokenObjects"),
            ("signing", "?RegistryTokenSigningFact"),
            ("token", "?RegistryServiceProcess"),
            ("registry", "?RegistryTokenRegistry"),
            ("node", "?ready|not-ready|drifted|unobservable"),
            ("cordoned", "?bool"),
            ("enforcement", "?RegistryTokenEnforcementList"),
            ("principals", "?RegistryTokenPrincipalFacts"),
            ("grants", "?RegistryTokenGrants"),
        ],
        "registry-auth-observation" => &[
            ("member", "null"),
            ("objects", "?RegistryAuthObjects"),
            ("registration", "?IssuerRegistration"),
            ("signing", "?RegistryAuthSigning"),
            ("services", "?unobserved|not-ready"),
        ],
        "registry-endpoint-observation" => &[
            ("objects", "RegistryEndpointObjects"),
            ("issued", "RegistryEndpointIssued"),
            ("served", "RegistryEndpointServedList"),
        ],
        "registry-service-observation" if value.optional("nodes")?.is_some() => &[
            ("member", "?Member"),
            ("generation", "?ready|not-ready"),
            ("image", "?ready|conflicting|not-ready|unobservable"),
            ("runtime", "?ready|not-ready"),
            ("storage", "?RegistryStorageFact"),
            ("objects", "?RegistryServiceObjects"),
            ("process", "?RegistryServiceProcess"),
            ("nodes", "?RegistryStorageNodes"),
        ],
        "registry-service-observation" => &[
            ("member", "?Member"),
            ("generation", "?ready|not-ready"),
            ("image", "?ready|conflicting|not-ready|unobservable"),
            ("runtime", "?ready|not-ready"),
            ("storage", "?RegistryStorageFactV1"),
            ("objects", "?RegistryServiceObjectsV1"),
            ("process", "?RegistryServiceProcess"),
            ("volume", "?RegistryServiceVolume"),
            ("node", "?ready|not-ready|drifted|unobservable"),
            ("cordoned", "?bool"),
        ],
        "registry-storage-observation" if value.optional("nodes")?.is_some() => &[
            ("member", "?Member"),
            ("storage", "?RegistryStorageFact"),
            ("nodes", "?RegistryStorageNodes"),
        ],
        "registry-storage-observation" => &[
            ("member", "?Member"),
            ("storage", "?RegistryStorageFactV1"),
            ("objects", "?RegistryStorageObjects"),
            ("volume", "?RegistryStorageVolume"),
            ("node", "?ready|not-ready|drifted|unobservable"),
            ("cordoned", "?bool"),
        ],
        "certificate-observation" => &[
            ("member", "null"),
            ("objects", "?CertificateObjects"),
            ("certificate", "?CertificateFact"),
            ("services", "?ready|not-ready"),
        ],
        "issuer-observation" => &[
            ("member", "null"),
            ("objects", "?IssuerObjects"),
            ("issuer", "?IssuerFact"),
            ("services", "?unobserved|not-ready"),
        ],
        "cert-manager-observation" => &[
            ("member", "?Member"),
            ("hosts", "?CertManagerHost"),
            ("objects", "?CertManagerObjects"),
            ("webhook", "?CertManagerFact"),
            ("services", "?unobserved|not-ready"),
        ],
        "ingress-observation" => &[
            ("member", "?Member"),
            ("hosts", "?IngressHost"),
            ("objects", "?IngressObjects"),
            ("results", "?IngressRecords"),
            ("ingress", "?IngressFacts"),
            ("services", "?unobserved|not-ready"),
        ],
        "network-observation" => &[
            ("member", "?Member"),
            ("hosts", "?NetworkHost"),
            ("objects", "?NetworkObjects"),
            ("services", "unobserved|ready|not-ready|unknown"),
            ("storage", "unobserved|ready|not-ready|unknown"),
        ],
        "inspection" => &[
            ("subject", "owner|writer|dispatch|resource"),
            ("observed_dispatch", "?nonce"),
            ("resource", "?Resource"),
            ("status", "ok|absent"),
            ("data", "Public"),
        ],
        "lifecycle-installation" => &[
            ("member", "Member"),
            ("class", "absent|activated|started|owned|foreign"),
            ("publication_state", "unpublished|interrupted|published"),
            ("activation", "?Installation"),
            ("readiness", "Readiness"),
            ("identity", "?LifecycleIdentity"),
        ],
        _ => return Err(Failure::Integrity),
    });
    object(value, &fields)?;
    if kind == "server-recipe" {
        check(
            value.field("recipe")?,
            if value.field("recipe_kind")?.equals("initial")? {
                "ServerRecipe"
            } else {
                "JoinRecipe"
            },
        )?;
    }
    Ok(())
}

fn record(value: Private<'_>, kind: &str) -> Result<()> {
    let stored_kind = if kind == "step-record" { "step" } else { kind };
    require(
        value.field("kind")?.equals(stored_kind)?,
        Failure::Integrity,
    )?;
    let mut fields = vec![
        (
            "schema",
            if kind == "request" {
                "request-version"
            } else {
                "version"
            },
        ),
        ("kind", "name"),
        ("scope", "Scope"),
        ("owner", "nonce"),
    ];
    fields.extend_from_slice(match kind {
        "owner" if value.optional("maintained")?.is_some() => &[
            ("generation", "nonce"),
            ("previous_generation", "?nonce"),
            ("created_ms", "uint"),
            ("members", "Members"),
            ("cluster", "?Cluster"),
            ("resources", "Resources"),
            ("fingerprints", "Fingerprints"),
            ("participants_sha256", "hash"),
            ("lock_identity", "FileIdentity"),
            ("writer", "?OwnerWriter"),
            ("removed", "OwnerRemovals"),
            ("maintained", "bool"),
        ][..],
        "owner" => &[
            ("generation", "nonce"),
            ("previous_generation", "?nonce"),
            ("created_ms", "uint"),
            ("members", "Members"),
            ("cluster", "?Cluster"),
            ("resources", "Resources"),
            ("fingerprints", "Fingerprints"),
            ("participants_sha256", "hash"),
            ("lock_identity", "FileIdentity"),
        ],
        "request" => &[
            ("operation", "operation"),
            ("created_ms", "uint"),
            ("sequence", "counter"),
            ("action", "uid"),
            ("members", "Members"),
            ("cluster", "?Cluster"),
            ("resources", "Resources"),
            ("config", "Config"),
            ("references", "References"),
            ("consumer", "?Consumer"),
            ("fingerprints", "Fingerprints"),
            ("participants_sha256", "hash"),
            ("operation_timeout_ms", "counter"),
            ("step_timeout_ms", "counter"),
        ],
        "attempt" => &[
            ("operation", "operation"),
            ("attempt", "nonce"),
            ("created_ms", "uint"),
            ("request_sha256", "hash"),
            ("parent_attempt", "?nonce"),
            ("original_step", "?step"),
            ("approval", "?Proposal"),
            ("steps", "Steps"),
        ],
        "step-record" => &[
            ("operation", "operation"),
            ("attempt", "nonce"),
            ("step", "step"),
            ("original_step", "?step"),
            ("created_ms", "uint"),
            ("dispatch", "nonce"),
            ("action", "action"),
            ("recipient", "?Member"),
            ("resource", "?Resource"),
            ("expected_receiver_generation", "uint"),
            ("request_sha256", "hash"),
            ("payload_sha256", "hash"),
            ("payload_observations", "Sequences"),
        ],
        "observation" => &[
            ("operation", "operation"),
            ("sequence", "sequence"),
            ("recorded_ms", "uint"),
            ("producer_ms", "?uint"),
            ("source", "Source"),
            ("attempt", "?nonce"),
            ("step", "?step"),
            ("dispatch", "?nonce"),
            ("event", "Event"),
        ],
        _ => return Err(Failure::Integrity),
    });
    object(value, &fields)
}

fn public(value: Private<'_>) -> Result<()> {
    match value.raw().first() {
        Some(b'"') => text(value, |_| true),
        Some(b'{') => {
            for (k, v) in value.members()? {
                text(k, |_| true)?;
                public(v)?;
            }
            Ok(())
        }
        Some(b'[') => {
            for v in value.array()? {
                public(v)?;
            }
            Ok(())
        }
        Some(b't' | b'f') => {
            value.boolean()?;
            Ok(())
        }
        Some(b'n') => require(value.is_null(), Failure::Integrity),
        _ => {
            value.number()?;
            Ok(())
        }
    }
}

fn encode(value: Private<'_>, out: &mut Zeroizing<Vec<u8>>) -> Result<()> {
    match value.raw().first() {
        Some(b'"') => {
            let text = value.text()?;
            require(text.get().len() <= 4096, Failure::Bound)?;
            let s = std::str::from_utf8(text.get()).map_err(|_| Failure::Integrity)?;
            serde_json::to_writer(&mut **out, s).map_err(|_| Failure::Integrity)?;
        }
        Some(b'{') => {
            let mut pairs = Vec::new();
            for (k, v) in value.members()? {
                pairs.push((k.text()?, k, v));
            }
            pairs.sort_by(|a, b| a.0.get().cmp(b.0.get()));
            out.push(b'{');
            for (i, (_, k, v)) in pairs.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode(k, out)?;
                out.push(b':');
                encode(v, out)?;
            }
            out.push(b'}');
        }
        Some(b'[') => {
            out.push(b'[');
            for (i, v) in value.array()?.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                encode(v, out)?;
            }
            out.push(b']');
        }
        _ => out.extend_from_slice(value.raw()),
    }
    require(out.len() <= 1_048_576, Failure::Bound)
}

pub(in crate::k3s) fn validate(bytes: &[u8], kind: &str, limit: usize) -> Result<()> {
    let value = Private::parse_bounded(bytes, limit, 17)?;
    fn containers(value: Private<'_>, depth: usize) -> Result<()> {
        if matches!(value.raw().first(), Some(b'{' | b'[')) {
            require(depth < 16, Failure::Bound)?;
            if value.raw().first() == Some(&b'{') {
                for (_, child) in value.members()? {
                    containers(child, depth + 1)?;
                }
            } else {
                for child in value.array()? {
                    containers(child, depth + 1)?;
                }
            }
        }
        Ok(())
    }
    containers(value, 0)?;
    public(value)?;
    check(value, kind)?;
    let mut encoded = Zeroizing::new(Vec::new());
    encode(value, &mut encoded)?;
    require(encoded.as_slice() == bytes, Failure::Integrity)
}

pub(in crate::k3s) fn decode(bytes: &[u8], kind: &str, limit: usize) -> Result<Value> {
    validate(bytes, kind, limit)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Failure::Integrity)?;
    semantic(&value)?;
    Ok(value)
}

fn published(request: &Value) -> Result<bool> {
    let members = request["members"].as_array().ok_or(Failure::Integrity)?;
    Ok(members.first().is_some_and(|m| m["role"] == "server")
        && members
            .iter()
            .all(|m| (m["role"] == "server" || m["role"] == "agent") && m["node_uid"].is_string()))
}

pub(super) fn join_shape(value: &Value) -> Result<()> {
    if value["action"] == "join-server" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let servers: Vec<_> = members.iter().filter(|m| m["role"] == "server").collect();
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let binding = &value["consumer"]["projection"]["binding"];
        let selected = |m: &Value, p: &Value| {
            ["machine", "member", "role", "node_uid"]
                .iter()
                .all(|key| m[*key] == p[*key])
        };
        let pending = servers
            .iter()
            .position(|m| m["node_uid"].is_null())
            .unwrap_or(servers.len());
        let destination = resources
            .get(1)
            .map(|r| &r["machine"])
            .ok_or(Failure::Integrity)?;
        let selected_index = servers
            .iter()
            .position(|m| &m["machine"] == destination)
            .ok_or(Failure::Integrity)?;
        let repeat = value["consumer"].is_null();
        let first = (1..3).contains(&selected_index)
            && servers[..pending].iter().all(|m| !m["node_uid"].is_null())
            && servers[pending..].iter().all(|m| m["node_uid"].is_null())
            && (repeat && selected_index < pending
                || !repeat
                    && selected_index == pending
                    && value["consumer"]["action"] == "supply-server-join"
                    && selected(servers[0], &binding["source"])
                    && selected(servers[pending], &binding["destination"]))
            && resources[0]["machine"] == servers[0]["machine"];
        let acting = servers.iter().find(|m| m["node_uid"].is_string());
        let replacement = !repeat
            && servers.iter().enumerate().all(|(n, m)| {
                if n == selected_index {
                    m["node_uid"].is_null()
                } else {
                    m["node_uid"].is_string()
                }
            })
            && value["consumer"]["action"] == "supply-server-join"
            && acting.is_some_and(|source| {
                selected(source, &binding["source"]) && resources[0]["machine"] == source["machine"]
            })
            && selected(servers[selected_index], &binding["destination"]);
        require(
            servers.len() == 3
                && !value["cluster"].is_null()
                && resources.len() == 2
                && (first || replacement)
                && resources[1]["machine"] == servers[selected_index]["machine"]
                && resources.iter().all(|r| {
                    r["kind"] == "server-input"
                        && r["owner"] == value["owner"]
                        && r["id"] == resources[0]["id"]
                        && r["generation"] == resources[0]["generation"]
                        && r["uid"].is_null()
                        && r["namespace"].is_null()
                        && r["name"].is_null()
                        && r["path"]
                            == format!(
                                "/var/lib/broil/k3s/owners/{}/resources/{}/{}",
                                value["owner"].as_str().unwrap_or(""),
                                r["id"].as_str().unwrap_or(""),
                                r["generation"].as_str().unwrap_or("")
                            )
                        && (repeat
                            || ["kind", "id", "generation", "uid"]
                                .iter()
                                .all(|key| r[*key] == binding["resource"][*key]))
                }),
            Failure::Ownership,
        )?;
    }
    if value["action"] == "join-agent" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let servers: Vec<_> = members.iter().filter(|m| m["role"] == "server").collect();
        let agents: Vec<_> = members.iter().filter(|m| m["role"] == "agent").collect();
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let destination = resources.get(1).ok_or(Failure::Integrity)?["machine"].clone();
        let selected = agents
            .iter()
            .position(|m| m["machine"] == destination)
            .ok_or(Failure::Integrity)?;
        let pending = agents
            .iter()
            .position(|m| m["node_uid"].is_null())
            .unwrap_or(agents.len());
        let repeat = value["consumer"].is_null();
        let binding = &value["consumer"]["projection"]["binding"];
        let same = |a: &Value, b: &Value| {
            ["machine", "member", "role", "node_uid"]
                .iter()
                .all(|key| a[*key] == b[*key])
        };
        let bound = value["consumer"]["action"] == "supply-agent-join"
            && same(&members[0], &binding["source"])
            && same(agents[selected], &binding["destination"]);
        let first = agents[..pending].iter().all(|m| m["node_uid"].is_string())
            && agents[pending..].iter().all(|m| m["node_uid"].is_null())
            && (repeat && selected < pending || !repeat && selected == pending && bound);
        let replacement = agents[selected]["node_uid"].is_null() && (repeat || bound);
        require(
            matches!(servers.len(), 1 | 3)
                && !agents.is_empty()
                && servers.iter().all(|m| m["node_uid"].is_string())
                && (first || replacement)
                && !value["cluster"].is_null()
                && resources.len() == 2
                && resources[0]["machine"] == members[0]["machine"]
                && resources[1]["machine"] == agents[selected]["machine"]
                && resources.iter().all(|r| {
                    r["kind"] == "agent-input"
                        && r["owner"] == value["owner"]
                        && r["id"] == resources[0]["id"]
                        && r["generation"] == resources[0]["generation"]
                        && r["uid"].is_null()
                        && r["namespace"].is_null()
                        && r["name"].is_null()
                        && r["path"]
                            == format!(
                                "/var/lib/broil/k3s/owners/{}/resources/{}/{}",
                                value["owner"].as_str().unwrap_or(""),
                                r["id"].as_str().unwrap_or(""),
                                r["generation"].as_str().unwrap_or("")
                            )
                        && (repeat
                            || ["kind", "id", "generation", "uid"]
                                .iter()
                                .all(|key| r[*key] == binding["resource"][*key]))
                }),
            Failure::Ownership,
        )?;
    }
    Ok(())
}

fn supply_published(request: &Value, machine: &Value) -> Result<bool> {
    let members = request["members"].as_array().ok_or(Failure::Integrity)?;
    let unpublished: Vec<_> = members.iter().filter(|m| m["node_uid"].is_null()).collect();
    Ok(members.first().is_some_and(|m| m["role"] == "server")
        && members.iter().all(|m| {
            (m["role"] == "server" || m["role"] == "agent")
                && (m["node_uid"].is_string() || m["node_uid"].is_null())
        })
        && unpublished.len() <= 1
        && unpublished.iter().all(|m| m["machine"] == *machine))
}

fn node_registry(request: &Value, r: &Value) -> bool {
    let text = |value: &Value| value.as_str().unwrap_or("").to_owned();
    r["kind"] == "node-registry"
        && r["owner"] == request["owner"]
        && text(&r["id"]).starts_with("node-registry-")
        && request["members"]
            .as_array()
            .is_some_and(|members| members.iter().any(|m| m["machine"] == r["machine"]))
        && r["path"]
            == format!(
                "/var/lib/broil/k3s/owners/{}/resources/{}/{}",
                text(&request["owner"]),
                text(&r["id"]),
                text(&r["generation"])
            )
        && r["namespace"].is_null()
        && r["name"].is_null()
        && r["uid"].is_null()
}

fn leading_assets(request: &Value) -> Option<usize> {
    let members = request["members"].as_array()?;
    let positions: Vec<Option<usize>> = request["resources"]
        .as_array()?
        .iter()
        .take_while(|r| r["kind"] == "bootstrap-assets")
        .map(|r| members.iter().position(|m| m["machine"] == r["machine"]))
        .collect();
    (positions.iter().all(Option::is_some) && positions.windows(2).all(|pair| pair[0] < pair[1]))
        .then_some(positions.len())
}

fn semantic(value: &Value) -> Result<()> {
    if value.get("project").is_some()
        && value.get("environment").is_some()
        && value.get("target").is_some()
        && value.get("hash").is_some()
    {
        require(
            value["hash"]
                == hash(
                    "broil-infra-scope-v1",
                    &json!([value["project"], value["environment"], value["target"]]),
                )?,
            Failure::Integrity,
        )?;
    }
    if let Some(scope) = value.get("scope") {
        if scope.get("hash").is_some() {
            require(
                scope["hash"]
                    == hash(
                        "broil-infra-scope-v1",
                        &json!([scope["project"], scope["environment"], scope["target"]]),
                    )?,
                Failure::Integrity,
            )?;
        }
    }
    if let (Some(members), Some(expected)) =
        (value.get("members"), value.get("participants_sha256"))
    {
        require(
            *expected == super::participants(&json!(super::survivors(value)?))?,
            Failure::Integrity,
        )?;
        let mut machines = std::collections::BTreeSet::new();
        for m in members.as_array().ok_or(Failure::Integrity)? {
            require(
                machines.insert(m["machine"].as_str().ok_or(Failure::Integrity)?),
                Failure::Integrity,
            )?;
        }
    }
    if value.get("decision").is_some() {
        require(
            value["digest"]
                == format!(
                    "sha256:{}",
                    hash("broil-infra-approval-v1", &value["decision"])?
                ),
            Failure::Integrity,
        )?;
    }
    if value["kind"] == "request" {
        super::recipe::validate_request(value)?;
        if value["action"] == "prepare-server-inputs" {
            let members = value["members"].as_array().ok_or(Failure::Integrity)?;
            let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
            let binding = &value["consumer"]["projection"]["binding"];
            let selected = |member: &Value, selected: &Value| {
                ["machine", "member", "role", "node_uid"]
                    .iter()
                    .all(|key| member[*key] == selected[*key])
            };
            require(
                (3..=128).contains(&members.len())
                    && resources.len() == 2
                    && members.iter().filter(|m| m["role"] == "server").count() == 3
                    && members[0]["role"] == "server"
                    && !value["cluster"].is_null()
                    && value["consumer"]["action"] == "supply-server-join"
                    && selected(&members[0], &binding["source"])
                    && !members[0]["node_uid"].is_null()
                    && members[1..].iter().all(|m| m["node_uid"].is_null())
                    && members[1..].iter().any(|member| {
                        member["role"] == "server" && selected(member, &binding["destination"])
                    })
                    && resources[0]["machine"] == members[0]["machine"]
                    && resources[1]["machine"] == binding["destination"]["machine"]
                    && resources.iter().all(|r| {
                        r["owner"] == value["owner"]
                            && r["kind"] == "server-input"
                            && r["id"] == resources[0]["id"]
                            && r["generation"] == resources[0]["generation"]
                            && r["uid"].is_null()
                            && r["namespace"].is_null()
                            && r["name"].is_null()
                            && r["path"]
                                == format!(
                                    "/var/lib/broil/k3s/owners/{}/resources/{}/{}",
                                    value["owner"].as_str().unwrap_or(""),
                                    r["id"].as_str().unwrap_or(""),
                                    r["generation"].as_str().unwrap_or("")
                                )
                            && ["kind", "id", "generation", "uid"]
                                .iter()
                                .all(|key| r[*key] == binding["resource"][*key])
                    }),
                Failure::Ownership,
            )?;
        }
        join_shape(value)?;
        require(
            value["fingerprints"]["config_sha256"]
                == hash("broil-infra-config-v1", &value["config"])?
                && value["fingerprints"]["references_sha256"]
                    == hash("broil-infra-references-v1", &value["references"])?
                && value["operation_timeout_ms"]
                    .as_u64()
                    .is_some_and(|v| v <= 7_200_000)
                && value["step_timeout_ms"]
                    .as_u64()
                    .is_some_and(|v| v <= 7_200_000),
            Failure::Integrity,
        )?;
    }
    if value["kind"] == "terminal" {
        require(
            value["outcome"] != "succeeded"
                || (value["effect"] == "complete" && value["failure"].is_null()),
            Failure::Integrity,
        )?;
    }
    if value["kind"] == "step" {
        let references = value["payload_observations"]
            .as_array()
            .ok_or(Failure::Integrity)?;
        require(
            references.windows(2).all(|v| v[0].as_u64() < v[1].as_u64()),
            Failure::Integrity,
        )?;
        let action = value["action"].as_str().unwrap_or("");
        let admitted = if action == "retire-writer" {
            true
        } else if action.starts_with("bootstrap:") {
            references.len() == 1
        } else if action.starts_with("lifecycle:registry-service-") {
            (1..=10).contains(&references.len())
        } else if action.starts_with("lifecycle:registry-endpoint-") {
            (1..=6).contains(&references.len())
        } else if action.starts_with("lifecycle:registry-replication-") {
            (1..=132).contains(&references.len())
        } else if action.starts_with("lifecycle:registry-token-") {
            (1..=8).contains(&references.len())
        } else if action.starts_with("lifecycle:") {
            (1..=5).contains(&references.len())
        } else if action == "credential:apply-secret" {
            (1..=2).contains(&references.len())
        } else if action == "admit-credential" {
            references.len() <= 2
        } else {
            references.is_empty()
        };
        require(admitted, Failure::Integrity)?;
    }
    if value["kind"] == "observation" {
        let event = &value["event"];
        match event["type"].as_str() {
            Some(
                "bootstrap-recipe" | "lifecycle-recipe" | "server-recipe" | "server-join-recipe"
                | "agent-recipe" | "agent-join-recipe",
            ) => require(
                value["source"]["kind"] == "controller"
                    && !value["attempt"].is_null()
                    && value["step"].is_null()
                    && value["dispatch"].is_null()
                    && event["recipe"]["attempt"] == value["attempt"]
                    && event["recipe"]["scope"] == value["scope"]
                    && event["recipe"]["owner"] == value["owner"]
                    && event["recipe"]["operation"] == value["operation"],
                Failure::Integrity,
            )?,
            Some("bootstrap-host") => require(
                value["source"]["kind"] == "receiver"
                    && value["source"]["machine"] == event["member"]["machine"]
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some("lifecycle-installation" | "server-membership") => require(
                value["source"]["kind"] == "receiver"
                    && value["source"]["machine"] == event["member"]["machine"]
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some("agent-membership") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some(
                "network-recipe"
                | "ingress-recipe"
                | "cert-manager-recipe"
                | "issuer-recipe"
                | "certificate-recipe"
                | "registry-storage-recipe"
                | "registry-service-recipe"
                | "registry-endpoint-recipe"
                | "registry-auth-recipe"
                | "registry-token-recipe"
                | "replication-recipe"
                | "delivery-recipe"
                | "release-recipe"
                | "restart-recipe",
            ) => require(
                value["source"]["kind"] == "controller"
                    && !value["attempt"].is_null()
                    && value["step"].is_null()
                    && value["dispatch"].is_null()
                    && event["recipe"]["scope"] == value["scope"]
                    && event["recipe"]["owner"] == value["owner"],
                Failure::Integrity,
            )?,
            Some("cert-manager-observation") if value["source"]["kind"] == "controller" => require(
                !value["attempt"].is_null()
                    && value["step"].is_null()
                    && value["dispatch"].is_null()
                    && event["member"].is_null()
                    && !event["objects"].is_null(),
                Failure::Integrity,
            )?,
            Some("network-observation" | "ingress-observation" | "cert-manager-observation") => {
                require(
                    value["source"]["kind"] == "receiver"
                        && !value["attempt"].is_null()
                        && !value["step"].is_null()
                        && !value["dispatch"].is_null()
                        && (event["member"].is_null()
                            || event["member"]["machine"] == value["source"]["machine"])
                        && (event["member"].is_null() != event["objects"].is_null()),
                    Failure::Integrity,
                )?
            }
            Some("registry-storage-observation") if event.get("nodes").is_some() => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null()
                    && (event["member"].is_null()
                        || event["member"]["machine"] == value["source"]["machine"])
                    && event["member"].is_null() == event["storage"].is_null()
                    && event["member"].is_null() != event["nodes"].is_null(),
                Failure::Integrity,
            )?,
            Some("registry-storage-observation" | "registry-service-observation") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null()
                    && (event["member"].is_null()
                        || event["member"]["machine"] == value["source"]["machine"])
                    && event["member"].is_null() == event["storage"].is_null()
                    && event["member"].is_null() != event["objects"].is_null(),
                Failure::Integrity,
            )?,
            Some("registry-token-observation") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null()
                    && (event["member"].is_null()
                        || event["member"]["machine"] == value["source"]["machine"])
                    && event["member"].is_null() == event["generation"].is_null()
                    && (event["member"].is_null() || event["objects"].is_null()),
                Failure::Integrity,
            )?,
            Some("replication-observation") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null()
                    && (event["member"].is_null()
                        || event["member"]["machine"] == value["source"]["machine"])
                    && event["member"].is_null() == event["replication"].is_null()
                    && event["member"].is_null() != event["objects"].is_null(),
                Failure::Integrity,
            )?,
            Some("release-observation") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null()
                    && event["member"]["machine"] == value["source"]["machine"],
                Failure::Integrity,
            )?,
            Some("release-hook") => require(
                value["source"]["kind"] == "controller"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some("release-evidence" | "release-settlement") => require(
                value["source"]["kind"] == "controller"
                    && value["attempt"].is_null()
                    && value["step"].is_null()
                    && value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some("delivery-observation") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null()
                    && event["member"]["machine"] == value["source"]["machine"],
                Failure::Integrity,
            )?,
            Some("node-observation") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null()
                    && match event["kind"].as_str() {
                        Some("restart") => event["unit"].is_object() && event["node"].is_null(),
                        Some("node") => event["unit"].is_null() && event["node"].is_object(),
                        _ => event["unit"].is_null() && event["node"].is_null(),
                    },
                Failure::Integrity,
            )?,
            Some("node-registry-supply" | "component-assets") => require(
                value["source"]["kind"] == "controller"
                    && !value["attempt"].is_null()
                    && value["step"].is_null()
                    && value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some("registry-endpoint-observation") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some(
                "issuer-observation" | "certificate-observation" | "registry-auth-observation",
            ) => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some("inspection") => require(
                value["source"]["kind"] == "receiver"
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            Some("bootstrap-asset" | "bootstrap-generation") => require(
                value["source"]["kind"] == "receiver"
                    && value["source"]["machine"] == event["resource"]["machine"]
                    && event["resource"]["kind"] == "bootstrap-assets"
                    && event["resource"]["owner"] == value["owner"]
                    && !value["attempt"].is_null()
                    && !value["step"].is_null()
                    && !value["dispatch"].is_null(),
                Failure::Integrity,
            )?,
            _ => {}
        }
    }
    if value["kind"] == "request" && value["action"] == "prepare-hosts" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let selected: Vec<&Value> = if value["cluster"].is_null() {
            members.iter().collect()
        } else {
            resources
                .iter()
                .filter_map(|r| {
                    members
                        .iter()
                        .find(|m| m["machine"] == r["machine"] && m["node_uid"].is_null())
                })
                .collect()
        };
        require(
            value["consumer"].is_null()
                && resources.len() == selected.len()
                && (value["cluster"].is_null() || resources.len() == 1)
                && selected.into_iter().zip(resources).all(|(m, r)| {
                    r["kind"] == "bootstrap-assets"
                        && r["id"] == m["machine"]
                        && r["machine"] == m["machine"]
                        && r["owner"] == value["owner"]
                        && r["path"]
                            == format!(
                                "/var/lib/broil/k3s/owners/{}/assets/{}/",
                                value["owner"].as_str().unwrap_or(""),
                                r["generation"].as_str().unwrap_or("")
                            )
                        && r["namespace"].is_null()
                        && r["name"].is_null()
                        && r["uid"].is_null()
                })
                && value["fingerprints"]["tools"]
                    .as_array()
                    .is_some_and(|tools| tools.iter().any(|t| t["name"] == "bootstrap-recipe")),
            Failure::Integrity,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "reconcile-network" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let all_null = resources.iter().all(|r| r["uid"].is_null());
        let all_bound = resources.iter().all(|r| r["uid"].is_string());
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| {
                    (m["role"] == "server" || m["role"] == "agent") && m["node_uid"].is_string()
                })
                && resources.len() == 12
                && (all_null || all_bound)
                && resources.iter().enumerate().all(|(index, resource)| {
                    let (namespace, name) = super::store::NETWORK_OBJECTS[index];
                    resource["kind"] == if index < 6 { "service" } else { "storage" }
                        && resource["id"] == format!("network-object-{:02}", index + 1)
                        && resource["owner"] == value["owner"]
                        && resource["machine"].is_null()
                        && resource["path"].is_null()
                        && resource["namespace"] == serde_json::json!(namespace)
                        && resource["name"] == serde_json::json!(name)
                }),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "reconcile-ingress" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let objects = super::ingress::INGRESS_OBJECTS.len();
        let (assets, charts) = resources.split_at(resources.len().saturating_sub(objects));
        let positions: Vec<Option<usize>> = assets
            .iter()
            .map(|r| members.iter().position(|m| m["machine"] == r["machine"]))
            .collect();
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| {
                    (m["role"] == "server" || m["role"] == "agent") && m["node_uid"].is_string()
                })
                && !assets.is_empty()
                && charts.len() == objects
                && positions.iter().all(Option::is_some)
                && positions.windows(2).all(|pair| pair[0] < pair[1])
                && assets.iter().all(|r| {
                    r["kind"] == "bootstrap-assets"
                        && r["owner"] == value["owner"]
                        && r["id"] == r["machine"]
                        && r["uid"].is_null()
                })
                && (charts.iter().all(|r| r["uid"].is_null())
                    || charts.iter().all(|r| r["uid"].is_string()))
                && charts.iter().enumerate().all(|(index, resource)| {
                    resource["kind"] == "service"
                        && resource["id"] == format!("ingress-object-{:02}", index + 1)
                        && resource["owner"] == value["owner"]
                        && resource["machine"].is_null()
                        && resource["path"].is_null()
                        && resource["namespace"] == "kube-system"
                        && resource["name"] == super::ingress::INGRESS_OBJECTS[index]
                }),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "reconcile-cert-manager" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let (anchor, assets) = resources.split_last().ok_or(Failure::Ownership)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| {
                    (m["role"] == "server" || m["role"] == "agent") && m["node_uid"].is_string()
                })
                && assets.len() == members.len()
                && assets.iter().zip(members).all(|(r, m)| {
                    r["kind"] == "bootstrap-assets"
                        && r["owner"] == value["owner"]
                        && r["id"] == m["machine"]
                        && r["machine"] == m["machine"]
                        && r["uid"].is_null()
                })
                && anchor["kind"] == "service"
                && anchor["id"] == "cert-manager-object-01"
                && anchor["owner"] == value["owner"]
                && anchor["machine"].is_null()
                && anchor["path"].is_null()
                && anchor["namespace"].is_null()
                && anchor["name"] == "cert-manager",
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "reconcile-issuer" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && resources.len() == 1
                && resources[0]["kind"] == "issuer"
                && resources[0]["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("issuer-object-"))
                && resources[0]["owner"] == value["owner"]
                && resources[0]["machine"] == members[0]["machine"]
                && resources[0]["path"].is_null()
                && resources[0]["namespace"] == "cert-manager"
                && resources[0]["name"].is_string(),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "reconcile-registry-auth" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && resources.len() == 1
                && resources[0]["kind"] == "registry-auth"
                && (resources[0]["id"] == "registry-auth-object-signing"
                    || resources[0]["id"]
                        .as_str()
                        .and_then(super::registry_auth::principal_of)
                        .is_some_and(|(name, _)| {
                            value["config"]["target"]["registry"]["authentication"]["principals"]
                                .get(name)
                                .is_some()
                        }))
                && resources[0]["owner"] == value["owner"]
                && resources[0]["machine"] == members[0]["machine"]
                && resources[0]["path"].is_null()
                && resources[0]["namespace"] == "broil-registry"
                && resources[0]["name"].is_string(),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "reconcile-certificate" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && resources.len() == 1
                && resources[0]["kind"] == "service"
                && resources[0]["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("certificate-object-"))
                && resources[0]["owner"] == value["owner"]
                && resources[0]["machine"].is_null()
                && resources[0]["path"].is_null()
                && resources[0]["namespace"] == "cert-manager"
                && resources[0]["name"].is_string(),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request"
        && value["action"] == "reconcile-registry-storage"
        && value["schema"] != 1
    {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && resources.len() == members.len()
                && resources.iter().zip(members).all(|(r, m)| {
                    r["kind"] == "replica"
                        && m["member"]
                            .as_str()
                            .is_some_and(|m| r["id"] == format!("registry-replica-{m}"))
                        && r["owner"] == value["owner"]
                        && r["machine"] == m["machine"]
                        && r["path"].is_string()
                        && r["namespace"].is_null()
                        && r["name"].is_null()
                        && r["uid"].is_null()
                }),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request"
        && value["action"] == "reconcile-registry-storage"
        && value["schema"] == 1
    {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let prefixed = |resource: &Value, prefix: &str| {
            resource["kind"] == "storage"
                && resource["owner"] == value["owner"]
                && resource["namespace"].is_null()
                && resource["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with(prefix))
        };
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && resources.len() == 2
                && prefixed(&resources[0], "registry-storage-")
                && members
                    .iter()
                    .any(|m| m["machine"] == resources[0]["machine"])
                && resources[0]["path"].is_string()
                && resources[0]["name"].is_null()
                && resources[0]["uid"].is_null()
                && prefixed(&resources[1], "registry-volume-")
                && resources[1]["machine"].is_null()
                && resources[1]["path"].is_null()
                && resources[1]["name"].is_string(),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request"
        && value["action"] == "reconcile-registry-service"
        && value["schema"] != 1
    {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let objects = leading_assets(value)
            .and_then(|first| resources.get(first..))
            .unwrap_or_default();
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && objects.len() == 5
                && objects.iter().enumerate().all(|(n, r)| {
                    r["kind"] == "service"
                        && r["owner"] == value["owner"]
                        && r["id"] == format!("registry-service-object-{:02}", n + 1)
                        && r["machine"].is_null()
                        && r["path"].is_null()
                        && r["name"] == "broil-registry"
                }),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request"
        && value["action"] == "reconcile-registry-service"
        && value["schema"] == 1
    {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && resources.len() == 7
                && resources[0]["kind"] == "bootstrap-assets"
                && members
                    .iter()
                    .any(|m| m["machine"] == resources[0]["machine"])
                && resources[1..].iter().enumerate().all(|(n, r)| {
                    r["kind"] == if n == 3 { "storage" } else { "service" }
                        && r["owner"] == value["owner"]
                        && r["id"] == format!("registry-service-object-{:02}", n + 1)
                        && r["machine"].is_null()
                        && r["path"].is_null()
                        && r["name"].is_string()
                }),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "restart-member" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && value["resources"].as_array().is_some_and(Vec::is_empty)
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| {
                    (m["role"] == "server" || m["role"] == "agent") && m["node_uid"].is_string()
                }),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "prepare-node-registry" {
        let binding = &value["consumer"]["projection"]["binding"];
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"]["action"] == "supply-node-registry"
                && resources
                    .first()
                    .map(|r| supply_published(value, &r["machine"]))
                    .transpose()?
                    .unwrap_or(false)
                && resources.len() == 1
                && node_registry(value, &resources[0])
                && resources[0]["machine"] == binding["destination"]["machine"]
                && ["kind", "id", "generation", "uid"]
                    .iter()
                    .all(|key| resources[0][*key] == binding["resource"][*key]),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "configure-node-registries" {
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && published(value)?
                && (1..=8).contains(&resources.len())
                && resources
                    .iter()
                    .all(|r| node_registry(value, r) && r["machine"] == resources[0]["machine"]),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "reconcile-registry-token" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let first = leading_assets(value).ok_or(Failure::Ownership)?;
        let objects = resources.get(first..first + 5).unwrap_or_default();
        let rest = resources.get(first + 5..).unwrap_or_default();
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && objects.len() == 5
                && objects.iter().enumerate().all(|(n, r)| {
                    r["kind"] == "service"
                        && r["owner"] == value["owner"]
                        && r["id"] == format!("registry-token-object-{:02}", n + 1)
                        && r["machine"].is_null()
                        && r["path"].is_null()
                        && r["namespace"] == "broil-registry"
                        && r["name"] == "broil-registry-token"
                })
                && (rest.is_empty()
                    || first == 0
                        && rest.len() == 1
                        && rest[0]["id"] == "registry-service-object-03"
                        && rest[0]["uid"].is_string()),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "reconcile-registry-endpoint" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        require(
            !value["cluster"].is_null()
                && value["consumer"].is_null()
                && members.first().is_some_and(|m| m["role"] == "server")
                && members.iter().all(|m| m["node_uid"].is_string())
                && resources.len() == 4
                && resources.iter().all(|r| {
                    r["owner"] == value["owner"]
                        && r["machine"].is_null()
                        && r["path"].is_null()
                        && r["name"].is_string()
                })
                && resources[0]["kind"] == "endpoint"
                && resources[0]["id"] == "registry-endpoint-origin"
                && resources[0]["namespace"].is_null()
                && resources[0]["uid"].is_null()
                && resources[1..].iter().enumerate().all(|(n, r)| {
                    r["kind"] == "service"
                        && r["id"] == format!("registry-endpoint-object-{:02}", n + 1)
                }),
            Failure::Ownership,
        )?;
    }
    if value["kind"] == "request" && value["action"] == "create-server" {
        let members = value["members"].as_array().ok_or(Failure::Integrity)?;
        let resources = value["resources"].as_array().ok_or(Failure::Integrity)?;
        let first = members.first().ok_or(Failure::Integrity)?;
        require(
            value["consumer"].is_null()
                && first["role"] == "server"
                && resources.len() == 1
                && resources.iter().all(|r| {
                    r["kind"] == "server-input"
                        && r["machine"] == first["machine"]
                        && r["owner"] == value["owner"]
                        && r["path"]
                            == format!(
                                "/var/lib/broil/k3s/owners/{}/resources/{}/{}",
                                value["owner"].as_str().unwrap_or(""),
                                r["id"].as_str().unwrap_or(""),
                                r["generation"].as_str().unwrap_or("")
                            )
                        && r["namespace"].is_null()
                        && r["name"].is_null()
                }),
            Failure::Integrity,
        )?;
    }
    match value {
        Value::Object(v) => {
            for (key, child) in v {
                if value["kind"] == "request" && matches!(key.as_str(), "config" | "consumer") {
                    continue;
                }
                semantic(child)?;
            }
        }
        Value::Array(v) => {
            for v in v {
                semantic(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}
