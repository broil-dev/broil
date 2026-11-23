// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Initial,
    ReadServer,
    ServerJoin,
    ReadAgent,
    AgentJoin,
    Admin,
    IssuerCa,
    IssuerAcme,
    RegistrySigning,
    RegistryPrincipal,
    NodeRegistry,
    RecoveryKey,
    RecoveryServer,
}

impl Action {
    pub(super) fn tag(self) -> &'static str {
        match self {
            Self::Initial => "supply-initial-server",
            Self::ReadServer => "read-server-join",
            Self::ServerJoin => "supply-server-join",
            Self::ReadAgent => "read-agent-join",
            Self::AgentJoin => "supply-agent-join",
            Self::Admin => "check-admin",
            Self::IssuerCa => "supply-issuer-ca",
            Self::IssuerAcme => "supply-issuer-acme",
            Self::RegistrySigning => "supply-registry-signing",
            Self::RegistryPrincipal => "supply-registry-principal",
            Self::NodeRegistry => "supply-node-registry",
            Self::RecoveryKey => "supply-recovery-key",
            Self::RecoveryServer => "supply-recovery-server-token",
        }
    }

    pub(super) fn kind(self) -> &'static str {
        match self {
            Self::Initial | Self::ReadServer | Self::ServerJoin => "server-input",
            Self::ReadAgent | Self::AgentJoin => "agent-input",
            Self::Admin => "admin-access",
            Self::IssuerCa | Self::IssuerAcme => "issuer",
            Self::RegistrySigning | Self::RegistryPrincipal => "registry-auth",
            Self::NodeRegistry => "node-registry",
            Self::RecoveryKey | Self::RecoveryServer => "recovery",
        }
    }

    pub(super) fn limits(self, node_ca: bool) -> &'static [usize] {
        match self {
            Self::Initial | Self::ServerJoin => &[4096, 4096],
            Self::AgentJoin | Self::RecoveryServer => &[4096],
            Self::IssuerCa => &[262_144, 262_144],
            Self::NodeRegistry if node_ca => &[262_144, 262_144],
            Self::IssuerAcme
            | Self::RegistrySigning
            | Self::RegistryPrincipal
            | Self::NodeRegistry
            | Self::RecoveryKey => &[262_144],
            Self::ReadServer | Self::ReadAgent | Self::Admin => &[],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultClass {
    Success,
    Prerequisite,
    Identity,
    Credential,
    Bound,
    Execution,
    Unknown,
}

pub(super) struct Reply<'a> {
    pub(super) result: ResultClass,
    pub(super) slots: Vec<&'a [u8]>,
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    if length > bytes.len() {
        return Err(Failure::Protocol);
    }
    let (value, rest) = bytes.split_at(length);
    *bytes = rest;
    Ok(value)
}

fn number(bytes: &mut &[u8]) -> Result<usize> {
    let value: [u8; 4] = take(bytes, 4)?.try_into().map_err(|_| Failure::Protocol)?;
    usize::try_from(u32::from_be_bytes(value)).map_err(|_| Failure::Protocol)
}

pub(super) fn reply<'a>(
    mut bytes: &'a [u8],
    header: &[u8],
    action: Action,
    inspect: bool,
) -> Result<Reply<'a>> {
    if take(&mut bytes, 6)? != b"BK3S1\n"
        || number(&mut bytes)? != header.len()
        || take(&mut bytes, header.len())? != header
    {
        return Err(Failure::Protocol);
    }
    let status = take(&mut bytes, 1)?[0];
    let result = match status {
        0 => ResultClass::Success,
        1 => ResultClass::Prerequisite,
        2 => ResultClass::Identity,
        3 => ResultClass::Credential,
        4 => ResultClass::Bound,
        5 => ResultClass::Execution,
        6 => ResultClass::Unknown,
        _ => return Err(Failure::Protocol),
    };
    let kind = take(&mut bytes, 1)?[0];
    let length = number(&mut bytes)?;
    if length > 16_384 || bytes.len() != length {
        return Err(Failure::Protocol);
    }
    let expected = if status != 0 || inspect {
        0
    } else {
        match action {
            Action::ReadServer => 1,
            Action::ReadAgent => 2,
            _ => 0,
        }
    };
    if kind != expected {
        return Err(Failure::Protocol);
    }
    let slots = match kind {
        0 if bytes.is_empty() => Vec::new(),
        1 => {
            let mut slots = Vec::with_capacity(2);
            for _ in 0..2 {
                let n = number(&mut bytes)?;
                if n == 0 || n > 4096 {
                    return Err(Failure::Protocol);
                }
                slots.push(take(&mut bytes, n)?);
            }
            if !bytes.is_empty() {
                return Err(Failure::Protocol);
            }
            slots
        }
        2 if (1..=4096).contains(&length) => vec![bytes],
        _ => return Err(Failure::Protocol),
    };
    Ok(Reply { result, slots })
}

pub(super) fn frame(slots: &[&[u8]], limits: &[usize]) -> Result<Zeroizing<Vec<u8>>> {
    if slots.len() != limits.len() || slots.len() > 8 {
        return Err(Failure::Bound);
    }
    let mut total = 0usize;
    for (slot, limit) in slots.iter().zip(limits) {
        if slot.is_empty() || slot.len() > *limit {
            return Err(Failure::Bound);
        }
        total = total
            .checked_add(4)
            .and_then(|n| n.checked_add(slot.len()))
            .filter(|n| *n <= 1_048_576)
            .ok_or(Failure::Bound)?;
    }
    let mut body = Zeroizing::new(Vec::new());
    body.try_reserve_exact(total).map_err(|_| Failure::Bound)?;
    for slot in slots {
        body.extend_from_slice(
            &u32::try_from(slot.len())
                .map_err(|_| Failure::Bound)?
                .to_be_bytes(),
        );
        body.extend_from_slice(slot);
    }
    Ok(body)
}

pub(super) fn secure_token(bytes: &[u8], server: bool, ca: &str) -> Result<()> {
    let role: &[u8] = if server { b"::server:" } else { b"::node:" };
    if bytes.len() != 3 + 64 + role.len() + 64
        || !bytes.starts_with(b"K10")
        || &bytes[3..67] != ca.as_bytes()
        || &bytes[67..67 + role.len()] != role
        || !bytes[67 + role.len()..]
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    {
        return Err(Failure::Credential);
    }
    Ok(())
}

pub(super) fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(super) fn canonical(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Failure::Configuration)
}

pub(super) fn opaque(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}
