// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::*;
use base64ct::{Base64, Encoding};

struct Writer<'a> {
    output: Option<&'a mut [u8]>,
    used: usize,
    limit: usize,
}
impl Writer<'_> {
    fn bytes(&mut self, value: &[u8]) -> Result<()> {
        let end = self.used.checked_add(value.len()).ok_or(Failure::Limit)?;
        require(end <= self.limit, Failure::Limit)?;
        if let Some(output) = &mut self.output {
            output
                .get_mut(self.used..end)
                .ok_or(Failure::Limit)?
                .copy_from_slice(value);
        }
        self.used = end;
        Ok(())
    }
    fn text(&mut self, value: &[u8]) -> Result<()> {
        self.bytes(b"\"")?;
        for &byte in value {
            match byte {
                b'"' => self.bytes(b"\\\"")?,
                b'\\' => self.bytes(b"\\\\")?,
                0..=31 => {
                    const HEX: &[u8] = b"0123456789abcdef";
                    self.bytes(b"\\u00")?;
                    self.bytes(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]])?;
                }
                _ => self.bytes(&[byte])?,
            }
        }
        self.bytes(b"\"")
    }
    fn base64(&mut self, value: &[u8]) -> Result<()> {
        self.bytes(b"\"")?;
        let size = value
            .len()
            .checked_add(2)
            .and_then(|n| (n / 3).checked_mul(4))
            .ok_or(Failure::Limit)?;
        let end = self.used.checked_add(size).ok_or(Failure::Limit)?;
        require(end <= self.limit, Failure::Limit)?;
        if let Some(output) = &mut self.output {
            Base64::encode(value, output.get_mut(self.used..end).ok_or(Failure::Limit)?)
                .map_err(|_| Failure::Protocol)?;
        }
        self.used = end;
        self.bytes(b"\"")
    }
}

fn request(w: &mut Writer<'_>, a: &Attempt) -> Result<()> {
    let s = &a.snapshot;
    let o = &s.options;
    w.bytes(b"{\"protocol_version\":2,\"operation_id\":")?;
    w.text(a.operation.as_bytes())?;
    w.bytes(b",\"analysis_id\":")?;
    w.bytes(a.number.to_string().as_bytes())?;
    for (key, value) in [
        (b",\"resolution_id\":".as_slice(), a.resolution.as_bytes()),
        (b",\"dockerfile\":", s.document.get()),
        (b",\"path\":", o.path.as_bytes()),
        (b",\"stage\":", o.stage.as_bytes()),
        (b",\"build_platform\":", o.build_platform.as_bytes()),
        (b",\"platform\":", o.platform.as_bytes()),
        (b",\"frontend\":", o.frontend.as_bytes()),
        (b",\"analyzer_identity\":", a.analyzer.as_bytes()),
    ] {
        w.bytes(key)?;
        w.text(value)?;
    }
    w.bytes(b",\"args\":{")?;
    for (i, (key, value)) in o.args.iter().enumerate() {
        if i != 0 {
            w.bytes(b",")?;
        }
        w.text(key.as_bytes())?;
        w.bytes(b":")?;
        w.text(value.as_bytes())?;
    }
    w.bytes(b"},\"contexts\":[")?;
    for (i, name) in o.contexts.iter().enumerate() {
        if i != 0 {
            w.bytes(b",")?;
        }
        w.text(name.as_bytes())?;
    }
    w.bytes(b"],\"metadata\":[")?;
    for (i, m) in s.metadata.iter().enumerate() {
        if i != 0 {
            w.bytes(b",")?;
        }
        w.bytes(b"{\"reference\":")?;
        w.text(m.reference.as_bytes())?;
        w.bytes(b",\"platform\":")?;
        w.text(m.platform.as_bytes())?;
        w.bytes(b",\"root\":")?;
        w.text(m.root.digest.as_bytes())?;
        w.bytes(b",\"config\":")?;
        w.base64(m.config.get())?;
        w.bytes(b",\"manifest\":")?;
        w.base64(m.manifest.get())?;
        w.bytes(b",\"indexes\":[")?;
        for (i, index) in m.indexes.iter().enumerate() {
            if i != 0 {
                w.bytes(b",")?;
            }
            w.base64(index.get())?;
        }
        w.bytes(b"]}")?;
        before(a.end)?;
    }
    w.bytes(b"]}")
}

pub(super) fn encode(a: &Attempt) -> Result<Bytes> {
    let mut count = Writer {
        output: None,
        used: 0,
        limit: a.limit - 4,
    };
    request(&mut count, a)?;
    before(a.end)?;
    let size = count.used;
    let mut bytes = Bytes::new(size.checked_add(4).ok_or(Failure::Limit)?)?;
    bytes.get_mut()[..4].copy_from_slice(
        &u32::try_from(size)
            .map_err(|_| Failure::Limit)?
            .to_be_bytes(),
    );
    let mut writer = Writer {
        output: Some(&mut bytes.get_mut()[4..]),
        used: 0,
        limit: size,
    };
    request(&mut writer, a)?;
    require(writer.used == size, Failure::Integrity)?;
    before(a.end)?;
    Ok(bytes)
}

pub(super) fn resolution(s: &Snapshot, analyzer: &str) -> Result<String> {
    fn number(h: &mut Sha256, n: usize) -> Result<()> {
        h.update(u64::try_from(n).map_err(|_| Failure::Limit)?.to_be_bytes());
        Ok(())
    }
    fn bytes(h: &mut Sha256, b: &[u8]) -> Result<()> {
        number(h, b.len())?;
        h.update(b);
        Ok(())
    }
    fn descriptor(h: &mut Sha256, d: &Descriptor) -> Result<()> {
        bytes(h, d.digest.as_bytes())?;
        h.update(d.size.to_be_bytes());
        bytes(h, d.media_type.as_bytes())
    }
    let mut h = Sha256::new();
    h.update(b"broil.image.analysis.v2\0");
    let o = &s.options;
    bytes(&mut h, s.document.get())?;
    bytes(&mut h, o.path.as_bytes())?;
    bytes(&mut h, o.stage.as_bytes())?;
    number(&mut h, o.args.len())?;
    for (key, value) in &o.args {
        bytes(&mut h, key.as_bytes())?;
        bytes(&mut h, value.as_bytes())?;
    }
    bytes(&mut h, o.build_platform.as_bytes())?;
    bytes(&mut h, o.platform.as_bytes())?;
    number(&mut h, o.contexts.len())?;
    for name in &o.contexts {
        bytes(&mut h, name.as_bytes())?;
    }
    bytes(&mut h, o.frontend.as_bytes())?;
    bytes(&mut h, analyzer.as_bytes())?;
    number(&mut h, s.metadata.len())?;
    for m in &s.metadata {
        bytes(&mut h, m.reference.as_bytes())?;
        bytes(&mut h, m.platform.as_bytes())?;
        descriptor(&mut h, &m.root)?;
        number(&mut h, m.index_descriptors.len())?;
        for d in &m.index_descriptors {
            descriptor(&mut h, d)?;
        }
        descriptor(&mut h, &m.manifest_descriptor)?;
        descriptor(&mut h, &m.config_descriptor)?;
    }
    let mut digest = h.finalize();
    let text = digest_string(digest.as_slice());
    digest.as_mut_slice().zeroize();
    Ok(text)
}

pub(super) fn decode64(value: Value<'_>) -> Result<Bytes> {
    let encoded = value.text()?;
    let n = encoded.get().len();
    require(
        n > 0
            && n % 4 == 0
            && n <= OBJECT.div_ceil(3) * 4
            && encoded
                .get()
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(b)),
        Failure::Limit,
    )?;
    let capacity = (n / 4).checked_mul(3).ok_or(Failure::Limit)?;
    let padding = encoded
        .get()
        .iter()
        .rev()
        .take_while(|b| **b == b'=')
        .count();
    require(
        padding <= 2 && capacity >= padding && capacity - padding <= OBJECT,
        Failure::Protocol,
    )?;
    let mut decoded = Bytes::new(capacity - padding)?;
    let length = Base64::decode(encoded.get(), decoded.get_mut())
        .map_err(|_| Failure::Protocol)?
        .len();
    require(length == decoded.get().len(), Failure::Protocol)?;
    Ok(decoded)
}
