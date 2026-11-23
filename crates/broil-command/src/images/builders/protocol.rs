// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{common::*, json::Value};
use serde_json::{Value as Json, json};

pub(crate) const ACTIONS: &[&str] = &[
    "inspect",
    "prepare",
    "install",
    "certificate",
    "key",
    "activate",
    "reconcile",
    "remove",
];
pub(super) const STATES: &[&str] = &[
    "missing",
    "prepared",
    "installed",
    "ready",
    "retained",
    "purged",
    "conflict",
    "busy",
    "uncertain",
    "prerequisite",
];
pub(super) const PARTS: &[&str] = &[
    "unknown", "present", "absent", "removed", "retained", "conflict",
];

#[derive(Clone, Debug)]
pub struct Receipt {
    pub state: &'static str,
    pub service: &'static str,
    pub credentials: &'static str,
    pub storage: &'static str,
    pub resources: Vec<Resource>,
    pub generation: String,
    pub unit_digest: String,
    pub resumed: bool,
    pub upload: Json,
    pub pending: bool,
    pub inputs: Json,
    pub arm64_emulation: bool,
}

#[derive(Clone, Debug)]
pub struct Resource {
    pub name: String,
    pub device: u64,
    pub inode: u64,
    pub mode: u64,
    pub uid: u64,
    pub size: u64,
}

impl Resource {
    fn wire(&self) -> Json {
        json!({"name":self.name,"device":self.device,"inode":self.inode,"mode":self.mode,"uid":self.uid,"size":self.size})
    }
}

impl Receipt {
    pub(crate) fn wire(&self) -> Json {
        json!({"state":self.state,"service":self.service,"credentials":self.credentials,"storage":self.storage,
            "resources":self.resources.iter().map(Resource::wire).collect::<Vec<_>>(),
            "generation":self.generation,"unit_digest":self.unit_digest,"resumed":self.resumed,
            "upload":self.upload,"pending":self.pending,"inputs":self.inputs,"arm64_emulation":self.arm64_emulation})
    }
}

pub(super) fn known(value: Value<'_>, choices: &'static [&'static str]) -> Result<&'static str> {
    for choice in choices {
        if value.equals(choice)? {
            return Ok(choice);
        }
    }
    Err(Failure::Protocol)
}

pub(crate) fn unit(owner: &str, generation: &str, endpoint: &str, arm64: bool) -> String {
    let root = format!("/var/lib/broil/builders/{owner}");
    let platforms = if arm64 {
        " --oci-worker-platform=linux/amd64 --oci-worker-platform=linux/arm64"
    } else {
        " --oci-worker-platform=linux/amd64"
    };
    format!(
        "[Unit]\nDescription=Broil owned BuildKit {owner}\nAfter=network.target\n\n[Service]\nType=simple\nUser=root\nEnvironment=PATH={root}/bin:/usr/sbin:/usr/bin:/sbin:/bin\nExecStart={root}/bin/buildkitd --root {root}/state --addr {endpoint} --tlscacert {root}/ca.pem --tlscert {root}/tls/{generation}/certificate --tlskey {root}/tls/{generation}/key --oci-worker=true --oci-worker-binary={root}/bin/buildkit-runc --containerd-worker=false{platforms}\nRestart=on-failure\nTimeoutStopSec=10\nLimitCORE=0\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=multi-user.target\n"
    )
}

pub(crate) fn request(
    record: &Json,
    scope_digest: &str,
    action: &str,
    payload_length: usize,
    purge: bool,
    arm64: bool,
) -> Result<Json> {
    require(
        ACTIONS.contains(&action)
            && payload_length <= 1_048_576
            && (matches!(action, "certificate" | "key") || payload_length == 0),
        Failure::Policy,
    )?;
    let owner = record["owner"].as_str().ok_or(Failure::Policy)?;
    let operation = record["operation"].as_str().ok_or(Failure::Policy)?;
    let endpoint = record["scope"]["endpoint"]
        .as_str()
        .ok_or(Failure::Policy)?;
    let old = record["observation"]["generation"].as_str().unwrap_or("");
    require(
        owner.len() == 32
            && hex(owner.as_bytes())
            && operation.len() == 32
            && hex(operation.as_bytes())
            && (old.is_empty() || (old.len() == 32 && hex(old.as_bytes()))),
        Failure::Integrity,
    )?;
    let desired_unit = unit(owner, operation, endpoint, arm64);
    Ok(
        json!({"protocol":1,"action":action,"owner":owner,"operation":operation,
        "step":record["step"],"scope":scope_digest,"endpoint":endpoint,
        "account":record["scope"]["account"],"payload_length":payload_length,
        "generation":operation,"previous_generation":old,"purge":purge,"arm64_emulation":arm64,
        "expected":record["observation"],"unit":desired_unit,"manifest":record["scope"]["manifest"],
        "ca_sha256":record["scope"]["ca_sha256"],"upload":record["upload_request"]}),
    )
}

pub(crate) fn receipt(
    bytes: &[u8],
    request: &Json,
    status: Option<i32>,
    signal: bool,
) -> Result<Receipt> {
    require(status == Some(0) && !signal, Failure::Protocol)?;
    let fields = Value::parse(bytes)?.object(&[
        b"protocol",
        b"action",
        b"owner",
        b"operation",
        b"step",
        b"scope",
        b"endpoint",
        b"state",
        b"service",
        b"credentials",
        b"storage",
        b"resources",
        b"generation",
        b"unit_digest",
        b"resumed",
        b"upload",
        b"pending",
        b"inputs",
        b"arm64_emulation",
    ])?;
    require(
        fields[0].number()? == 1
            && fields[4].number()? == request["step"].as_u64().ok_or(Failure::Policy)?,
        Failure::Protocol,
    )?;
    for (index, name) in [
        (1, "action"),
        (2, "owner"),
        (3, "operation"),
        (5, "scope"),
        (6, "endpoint"),
    ] {
        require(
            fields[index].equals(request[name].as_str().ok_or(Failure::Policy)?)?,
            Failure::Protocol,
        )?;
    }
    let owner = request["owner"].as_str().ok_or(Failure::Policy)?;
    let generation = [
        request["generation"].as_str().unwrap_or(""),
        request["previous_generation"].as_str().unwrap_or(""),
        "",
    ];
    let mut actual_generation = None;
    for allowed in generation {
        if fields[12].equals(allowed)? {
            actual_generation = Some(allowed.to_string());
            break;
        }
    }
    let actual_generation = actual_generation.ok_or(Failure::Protocol)?;
    let unit_digest = {
        use sha2::{Digest, Sha256};
        let digest = super::public_hex(&Sha256::digest(
            unit(
                owner,
                &actual_generation,
                request["endpoint"].as_str().ok_or(Failure::Policy)?,
                fields[18].boolean()?,
            )
            .as_bytes(),
        ));
        if fields[13].equals(&digest)? {
            digest
        } else {
            require(fields[13].equals("")?, Failure::Protocol)?;
            String::new()
        }
    };
    let mut allowed: Vec<String> = [
        "root",
        "bin",
        "state",
        "incoming",
        "tls",
        "owner.json",
        "ca.pem",
        "unit",
        "bin/buildkitd",
        "bin/buildkit-runc",
        "bin/buildkit-qemu-aarch64",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    for generation in generation.into_iter().filter(|s| !s.is_empty()) {
        for suffix in ["", "/certificate", "/key"] {
            allowed.push(format!("tls/{generation}{suffix}"));
        }
    }
    for resource in request["expected"]["resources"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(name) = resource["name"]
            .as_str()
            .filter(|name| name.starts_with("tls/"))
        {
            let mut parts = name.split('/');
            parts.next();
            let generation = parts.next().ok_or(Failure::Protocol)?;
            require(
                generation.len() == 32
                    && hex(generation.as_bytes())
                    && matches!(parts.next(), None | Some("certificate" | "key"))
                    && parts.next().is_none(),
                Failure::Protocol,
            )?;
            allowed.push(name.to_string());
        }
    }
    let resources = fields[11].array()?;
    require(resources.len() <= 128, Failure::Limit)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut output = Vec::new();
    for resource in resources {
        let r = resource.object(&[b"name", b"device", b"inode", b"mode", b"uid", b"size"])?;
        let mut name = None;
        for candidate in &allowed {
            if r[0].equals(candidate)? {
                name = Some(candidate.clone());
                break;
            }
        }
        let name = match name {
            Some(name) => name,
            None => scoped_resource(r[0], request["step"].as_u64().ok_or(Failure::Protocol)?)?,
        };
        require(seen.insert(name.clone()), Failure::Protocol)?;
        let mode = r[3].number()?;
        let uid = r[4].number()?;
        require(
            mode <= 0o177777
                && matches!(mode & 0o170000, 0o040000 | 0o100000)
                && uid <= u32::MAX as u64
                && r[2].number()? > 0
                && r[5].number()? <= 536_870_912,
            Failure::Protocol,
        )?;
        output.push(Resource {
            name,
            device: r[1].number()?,
            inode: r[2].number()?,
            mode,
            uid,
            size: r[5].number()?,
        });
    }
    let upload = upload_receipt(fields[15], request)?;
    let mut inputs = serde_json::Map::new();
    for (key, value) in fields[17].members()? {
        let purpose = known(key, &["archive", "ca"])?;
        let path = scoped_resource(value, request["step"].as_u64().ok_or(Failure::Protocol)?)?;
        require(
            path.starts_with("incoming/") && path.ends_with(&format!("/{purpose}")),
            Failure::Protocol,
        )?;
        require(
            output.iter().any(|resource| resource.name == path),
            Failure::Protocol,
        )?;
        inputs.insert(purpose.into(), json!(path));
    }
    let receipt = Receipt {
        state: known(fields[7], STATES)?,
        service: known(fields[8], PARTS)?,
        credentials: known(fields[9], PARTS)?,
        storage: known(fields[10], PARTS)?,
        resources: output,
        generation: actual_generation,
        unit_digest,
        resumed: fields[14].boolean()?,
        upload,
        pending: fields[16].boolean()?,
        inputs: Json::Object(inputs),
        arm64_emulation: fields[18].boolean()?,
    };
    postconditions(&receipt, request)?;
    Ok(receipt)
}

pub(super) fn scoped_resource(value: Value<'_>, maximum: u64) -> Result<String> {
    let text = value.text()?;
    let text = std::str::from_utf8(text.get()).map_err(|_| Failure::Protocol)?;
    let (number, prefix, suffix) = if let Some(body) = text.strip_prefix("incoming/") {
        match body.split_once('/') {
            Some((number, suffix)) if matches!(suffix, "archive" | "ca" | "upload.tmp") => {
                (number, "incoming/", format!("/{suffix}"))
            }
            None => (body, "incoming/", String::new()),
            _ => return Err(Failure::Protocol),
        }
    } else if let Some(number) = text
        .strip_prefix("claim-")
        .and_then(|s| s.strip_suffix(".json"))
    {
        (number, "claim-", ".json".into())
    } else {
        return Err(Failure::Protocol);
    };
    require(
        !number.is_empty() && number.len() <= 20 && number.bytes().all(|b| b.is_ascii_digit()),
        Failure::Protocol,
    )?;
    let step = number.parse::<u64>().map_err(|_| Failure::Protocol)?;
    require(
        step > 0 && step <= maximum && number == step.to_string(),
        Failure::Protocol,
    )?;
    Ok(format!("{prefix}{step}{suffix}"))
}

fn identity(value: Value<'_>, directory: bool) -> Result<Json> {
    let keys: &[&[u8]] = &[b"device", b"inode", b"mode", b"uid", b"gid", b"links"];
    let fields = value.object(keys)?;
    let values = fields
        .into_iter()
        .map(Value::number)
        .collect::<Result<Vec<_>>>()?;
    require(
        values[1] > 0
            && values[2] == if directory { 0o40700 } else { 0o100600 }
            && values[3] <= u32::MAX as u64
            && values[4] <= u32::MAX as u64
            && if directory {
                values[5] > 0
            } else {
                values[5] == 1
            },
        Failure::Protocol,
    )?;
    Ok(
        json!({"device":values[0],"inode":values[1],"mode":values[2],"uid":values[3],"gid":values[4],"links":values[5]}),
    )
}

fn upload_receipt(value: Value<'_>, request: &Json) -> Result<Json> {
    use sha2::{Digest, Sha256};
    if value.is_null() {
        return Ok(Json::Null);
    }
    let upload = value.object(&[b"binding", b"claim", b"identity", b"length", b"sha256"])?;
    let binding = upload[0].object(&[
        b"protocol",
        b"owner",
        b"operation",
        b"step",
        b"scope",
        b"container",
        b"purpose",
        b"temporary",
        b"final",
        b"size",
        b"sha256",
    ])?;
    let step = binding[3].number()?;
    require(
        binding[0].number()? == 1
            && step > 0
            && step <= request["step"].as_u64().ok_or(Failure::Protocol)?,
        Failure::Protocol,
    )?;
    for (i, name) in [(1, "owner"), (2, "operation"), (4, "scope")] {
        require(
            binding[i].equals(request[name].as_str().ok_or(Failure::Protocol)?)?,
            Failure::Protocol,
        )?;
    }
    let purpose = known(binding[6], &["archive", "ca"])?;
    require(
        binding[7].equals("upload.tmp")? && binding[8].equals(purpose)?,
        Failure::Protocol,
    )?;
    let sha = if purpose == "archive" {
        &request["manifest"]["archive_sha256"]
    } else {
        &request["ca_sha256"]
    };
    require(
        binding[10].equals(sha.as_str().ok_or(Failure::Protocol)?)?,
        Failure::Protocol,
    )?;
    let size = binding[9].number()?;
    require(
        size > 0
            && size
                <= if purpose == "archive" {
                    268_435_456
                } else {
                    1_048_576
                },
        Failure::Protocol,
    )?;
    if purpose == "archive" {
        require(
            Some(size) == request["manifest"]["archive_size"].as_u64(),
            Failure::Protocol,
        )?;
    }
    let container = identity(binding[5], true)?;
    let claim_identity = identity(upload[2], false)?;
    require(
        container["uid"] == claim_identity["uid"] && container["gid"] == claim_identity["gid"],
        Failure::Protocol,
    )?;
    let body = json!({"protocol":1,"owner":request["owner"],"operation":request["operation"],"step":step,"scope":request["scope"],
        "container":container,"purpose":purpose,"temporary":"upload.tmp","final":purpose,"size":size,"sha256":sha});
    let encoded = serde_json::to_vec(&body).map_err(|_| Failure::Protocol)?;
    let digest = super::public_hex(&Sha256::digest(&encoded));
    let claim = format!("claim-{step}.json");
    require(
        upload[1].equals(&claim)?
            && upload[3].number()? == encoded.len() as u64
            && upload[4].equals(&digest)?,
        Failure::Protocol,
    )?;
    Ok(
        json!({"binding":body,"claim":claim,"identity":claim_identity,"length":encoded.len(),"sha256":digest}),
    )
}

fn postconditions(receipt: &Receipt, request: &Json) -> Result<()> {
    if matches!(
        receipt.state,
        "conflict" | "busy" | "uncertain" | "prerequisite"
    ) {
        return Ok(());
    }
    let action = request["action"].as_str().ok_or(Failure::Protocol)?;
    if receipt.state == "missing" {
        return require(
            action == "inspect" && receipt.resources.is_empty() && !receipt.pending,
            Failure::Protocol,
        );
    }
    require(
        receipt
            .resources
            .iter()
            .any(|r| r.name == "root" && r.mode == 0o40711 && r.uid == 0 && r.inode > 0),
        Failure::Protocol,
    )?;
    require(
        receipt
            .resources
            .iter()
            .any(|r| r.name == "owner.json" && r.mode == 0o100644 && r.uid == 0 && r.inode > 0),
        Failure::Protocol,
    )?;
    for old in request["expected"]["resources"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(current) = receipt
            .resources
            .iter()
            .find(|r| old["name"].as_str() == Some(r.name.as_str()))
        {
            if current.name == "unit" && action == "activate" {
                continue;
            }
            require(
                old["device"] == json!(current.device)
                    && old["inode"] == json!(current.inode)
                    && old["mode"] == json!(current.mode)
                    && old["uid"] == json!(current.uid),
                Failure::Protocol,
            )?;
        }
    }
    if action == "prepare" && !request["upload"].is_null() {
        let binding = &receipt.upload["binding"];
        require(
            receipt.pending && binding["step"] == request["step"],
            Failure::Protocol,
        )?;
        for key in ["purpose", "size", "sha256", "temporary", "final"] {
            require(binding[key] == request["upload"][key], Failure::Protocol)?;
        }
    }
    if matches!(action, "certificate" | "key") {
        let name = format!(
            "tls/{}/{}",
            request["generation"].as_str().ok_or(Failure::Protocol)?,
            action
        );
        require(
            receipt.resources.iter().any(|r| {
                r.name == name
                    && r.uid == 0
                    && r.mode == 0o100600
                    && Some(r.size) == request["payload_length"].as_u64()
            }),
            Failure::Protocol,
        )?;
    }
    if action == "activate" {
        require(
            receipt.state == "ready"
                && !receipt.pending
                && receipt.service == "present"
                && receipt.credentials == "present"
                && receipt.storage == "retained"
                && !receipt.generation.is_empty()
                && !receipt.unit_digest.is_empty()
                && request["arm64_emulation"] == receipt.arm64_emulation,
            Failure::Protocol,
        )?;
    }
    if receipt.state == "ready" {
        let owned = |name: &str, mode| {
            receipt
                .resources
                .iter()
                .any(|resource| resource.name == name && resource.mode == mode && resource.uid == 0)
        };
        require(
            !receipt.generation.is_empty()
                && !receipt.unit_digest.is_empty()
                && receipt.service == "present"
                && receipt.credentials == "present"
                && owned("unit", 0o100600)
                && owned("state", 0o40700)
                && owned(&format!("tls/{}", receipt.generation), 0o40700)
                && owned(&format!("tls/{}/certificate", receipt.generation), 0o100600)
                && owned(&format!("tls/{}/key", receipt.generation), 0o100600),
            Failure::Protocol,
        )?;
    }
    if action == "remove" {
        require(
            !receipt.pending
                && receipt.service == "removed"
                && receipt.credentials == "removed"
                && receipt.storage
                    == if request["purge"] == true {
                        "removed"
                    } else {
                        "retained"
                    },
            Failure::Protocol,
        )?;
    }
    Ok(())
}
