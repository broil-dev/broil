// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0
//! Reference-only K3s declarations. Defaults and external access belong to callers.

use std::{collections::BTreeMap, net::Ipv4Addr};

use crate::images::{
    SecretReference,
    reference::{Endpoint, ImageReference},
};
use crate::remote::DurationValue;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub version: String,
    pub members: Vec<Member>,
    pub api: Api,
    pub registration_endpoint: Endpoint,
    pub network: Network,
    pub infrastructure: Infrastructure,
    pub credentials: Credentials,
    pub privilege: Option<String>,
    pub lifecycle_script: String,
    pub bootstrap: Bootstrap,
    pub backup: Backup,
    pub agent_wave_size: Option<u8>,
    pub operation_timeout: Option<DurationValue>,
    pub step_timeout: Option<DurationValue>,
    pub registry: Option<ManagedRegistry>,
    pub node_registries: Vec<NodeRegistry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub machine: String,
    pub role: Role,
    pub name: String,
    pub node_ip: Ipv4Addr,
    pub interface: String,
    pub labels: BTreeMap<String, String>,
    pub taints: Vec<Taint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Server,
    Agent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taint {
    pub key: String,
    pub value: String,
    pub effect: TaintEffect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Api {
    pub endpoint: Endpoint,
    pub tls_sans: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl Ipv4Cidr {
    pub fn contains(self, address: Ipv4Addr) -> bool {
        u32::from(address) & self.mask() == u32::from(self.network)
    }

    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) | !self.mask())
    }

    fn mask(self) -> u32 {
        u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub pod_cidr: Ipv4Cidr,
    pub service_cidr: Ipv4Cidr,
    pub cluster_dns: Ipv4Addr,
    pub cluster_domain: Option<String>,
    pub flannel: Option<Flannel>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flannel {
    Vxlan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Infrastructure {
    pub cert_manager_version: String,
    pub ingress_members: Vec<String>,
    pub issuers: BTreeMap<String, Issuer>,
    pub certificates: BTreeMap<String, Certificate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issuer {
    PrivateCa {
        certificate: SecretReference,
        key: SecretReference,
    },
    AcmeHttp01 {
        server: String,
        email: String,
        account_key: SecretReference,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub issuer: String,
    pub dns_names: Vec<String>,
    pub duration: Option<DurationValue>,
    pub renew_before: Option<DurationValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub server_token: SecretReference,
    pub agent_token: SecretReference,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bootstrap {
    pub mode: BootstrapMode,
    pub manifest: String,
    pub bundle: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapMode {
    Online,
    Bundle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Backup {
    pub machine: String,
    pub path: String,
    pub recipient: String,
    pub identity: SecretReference,
    pub max_age: Option<DurationValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedRegistry {
    pub name: String,
    pub endpoint: String,
    pub version: String,
    pub image: ImageReference,
    pub member: String,
    pub storage: Storage,
    pub certificate: String,
    pub authentication: Authentication,
    pub backup_max_age: Option<DurationValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Storage {
    pub path: String,
    pub capacity_mib: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authentication {
    pub profile: String,
    pub principals: BTreeMap<String, Principal>,
    pub signing_key: Option<SecretReference>,
    pub signing_certificate: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub purpose: PrincipalPurpose,
    pub password: SecretReference,
    pub repositories: Vec<String>,
    pub actions: Vec<RegistryAction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrincipalPurpose {
    Publication,
    NodePull,
    Maintenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistryAction {
    Pull,
    Push,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRegistry {
    pub registry: String,
    pub repositories: Vec<String>,
    pub username: String,
    pub password: SecretReference,
    pub fallback: Option<RegistryFallback>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryFallback {
    Disabled,
    SameOrigin,
}
