// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Error, Result};
use crate::{
    output::{self, Prepared},
    sops::{MAX_DOCUMENT_BYTES, MAX_SCALAR_BYTES},
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, client::Resumption, pki_types::ServerName,
};
use std::{
    io::{self, Read, Write},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::{Zeroize, Zeroizing};

const HEADER_LIMIT: usize = 64 * 1024;
const REQUEST_HEADER_LIMIT: usize = MAX_SCALAR_BYTES + HEADER_LIMIT;
const CHUNK_WORK_LIMIT: usize = 1024 * 1024;

fn framing() -> Error {
    Error::runtime("invalid vault HTTP framing")
}
fn limit() -> Error {
    Error::runtime("vault HTTP size limit")
}
fn tls_error() -> Error {
    Error::runtime("vault TLS verification or protocol failure")
}

#[derive(Debug)]
pub struct Address {
    pub display: String,
    host: String,
    authority: String,
    port: u16,
    prefix: String,
    tls: bool,
}
impl Address {
    pub fn parse(address: &str) -> Result<Self> {
        if !broil_core::secrets::valid_address(address) {
            return Err(Error::runtime("invalid vault address"));
        }
        let (scheme, rest) = address.split_once("://").unwrap();
        let tls = scheme.eq_ignore_ascii_case("https");
        let (authority, prefix) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, rest) = rest.split_once(']').unwrap();
            if host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(Error::runtime("unsupported vault address form"));
            }
            (host.to_owned(), rest.strip_prefix(':').unwrap_or(""))
        } else {
            let (host, port) = authority.split_once(':').unwrap_or((authority, ""));
            let mut decoded = Vec::with_capacity(host.len());
            let bytes = host.as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'%' {
                    decoded
                        .push(u8::from_str_radix(&host[i + 1..i + 3], 16).map_err(|_| framing())?);
                    i += 3;
                } else {
                    decoded.push(bytes[i]);
                    i += 1;
                }
            }
            if decoded
                .iter()
                .any(|b| !b.is_ascii_alphanumeric() && !b"-._".contains(b))
            {
                return Err(Error::runtime("unsupported vault hostname"));
            }
            (String::from_utf8(decoded).map_err(|_| framing())?, port)
        };
        let port = if port.is_empty() {
            if tls { 443 } else { 80 }
        } else {
            port.parse().map_err(|_| framing())?
        };
        let prefix = if prefix.trim_end_matches('/').is_empty() {
            String::new()
        } else {
            format!("/{}", prefix.trim_end_matches('/'))
        };
        Ok(Self {
            display: address.to_owned(),
            host,
            authority: authority.to_owned(),
            port,
            prefix,
            tls,
        })
    }
    pub fn path(&self, components: &[&str]) -> Result<String> {
        let mut path = format!("{}/v1", self.prefix);
        for component in components {
            path.push('/');
            for b in component.bytes() {
                if (b.is_ascii_alphanumeric() || b"-._~".contains(&b))
                    && !matches!(*component, "." | "..")
                {
                    path.push(b as char);
                } else {
                    use std::fmt::Write as _;
                    write!(path, "%{b:02X}").map_err(|_| limit())?;
                }
                if path.len() > HEADER_LIMIT {
                    return Err(limit());
                }
            }
        }
        Ok(path)
    }
}
pub fn token_valid(token: &str) -> bool {
    !token.is_empty() && token.len() <= MAX_SCALAR_BYTES && token.bytes().all(|b| b > 32 && b < 127)
}
fn request(
    address: &Address,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Prepared>,
) -> Result<Prepared> {
    if !matches!(method, "GET" | "POST" | "PUT" | "DELETE")
        || !path.starts_with('/')
        || path.bytes().any(|b| b <= 32 || b >= 127)
    {
        return Err(framing());
    }
    if token.is_some_and(|t| !token_valid(t)) {
        return Err(Error::runtime("invalid vault token"));
    }
    let length = body.map_or(0, |b| b.as_bytes().len());
    if length > MAX_DOCUMENT_BYTES {
        return Err(limit());
    }
    let header = output::prepare(REQUEST_HEADER_LIMIT, |w| {
        w.text(method)?;
        w.text(" ")?;
        w.text(path)?;
        w.text(" HTTP/1.1\r\nHost: ")?;
        w.text(&address.authority)?;
        w.text("\r\nConnection: close\r\nAccept: application/json\r\n")?;
        if let Some(token) = token {
            w.text("X-Vault-Token: ")?;
            w.text(token)?;
            w.text("\r\n")?;
        }
        w.text("Content-Type: application/json\r\nContent-Length: ")?;
        w.text(&length.to_string())?;
        w.text("\r\n\r\n")
    })?;
    Ok(output::prepare(
        REQUEST_HEADER_LIMIT + MAX_DOCUMENT_BYTES,
        |w| {
            w.bytes(header.as_bytes())?;
            if let Some(body) = body {
                w.bytes(body.as_bytes())?;
            }
            Ok(())
        },
    )?)
}

pub struct Body(Zeroizing<Vec<u8>>);
impl Body {
    fn new(capacity: usize) -> Result<Self> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(capacity).map_err(|_| limit())?;
        Ok(Self(bytes))
    }
    fn append(&mut self, bytes: &[u8], limit: usize) -> Result<()> {
        let length = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or_else(limit_error)?;
        if length > limit || length > self.0.capacity() {
            return Err(limit_error());
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
fn limit_error() -> Error {
    limit()
}
impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Body([REDACTED])")
    }
}
impl Drop for Body {
    fn drop(&mut self) {
        self.0.as_mut_slice().zeroize();

    }
}
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Body,
}

struct Wire {
    socket: TcpStream,
    tls: Option<ClientConnection>,
}
impl Wire {
    async fn connect(address: &Address, connect_budget: Duration) -> Result<Self> {
        let socket = tokio::time::timeout(connect_budget, async {
            let addresses = tokio::net::lookup_host((address.host.as_str(), address.port))
                .await
                .map_err(|_| Error::unavailable())?;
            for address in addresses {
                if let Ok(stream) = TcpStream::connect(address).await {
                    return Ok(stream);
                }
            }
            Err(Error::unavailable())
        })
        .await
        .map_err(|_| Error::unavailable())??;
        let tls = if address.tls {
            let mut roots = RootCertStore::empty();
            let native = tokio::task::spawn_blocking(rustls_native_certs::load_native_certs)
                .await
                .map_err(|_| tls_error())?;
            for cert in native.certs {
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                return Err(tls_error());
            }
            let mut config = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|_| tls_error())?
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.resumption = Resumption::disabled();
            config.enable_early_data = false;
            config.key_log = Arc::new(rustls::NoKeyLog {});
            let name = ServerName::try_from(address.host.clone()).map_err(|_| tls_error())?;
            let mut connection =
                ClientConnection::new(Arc::new(config), name).map_err(|_| tls_error())?;
            connection.set_buffer_limit(Some(64 * 1024));
            Some(connection)
        } else {
            None
        };
        let mut wire = Self { socket, tls };
        while wire.tls.as_ref().is_some_and(|c| c.is_handshaking()) {
            wire.flush_tls().await?;
            if wire.receive_tls().await? == 0 {
                return Err(tls_error());
            }
        }
        wire.flush_tls().await?;
        Ok(wire)
    }
    async fn flush_tls(&mut self) -> Result<()> {
        if let Some(tls) = &mut self.tls {
            while tls.wants_write() {
                let mut encrypted = Vec::new();
                tls.write_tls(&mut encrypted).map_err(|_| tls_error())?;
                self.socket
                    .write_all(&encrypted)
                    .await
                    .map_err(|_| Error::unavailable())?;
            }
        }
        Ok(())
    }
    async fn receive_tls(&mut self) -> Result<usize> {
        let mut encrypted = [0; 16384];
        let n = self
            .socket
            .read(&mut encrypted)
            .await
            .map_err(|_| Error::unavailable())?;
        let tls = self.tls.as_mut().ok_or_else(tls_error)?;
        tls.read_tls(&mut io::Cursor::new(&encrypted[..n]))
            .map_err(|_| tls_error())?;
        tls.process_new_packets().map_err(|_| tls_error())?;
        Ok(n)
    }
    async fn send(&mut self, mut request: &[u8]) -> Result<()> {
        if self.tls.is_none() {
            return self
                .socket
                .write_all(request)
                .await
                .map_err(|_| Error::unavailable());
        }
        while !request.is_empty() {
            let n = self
                .tls
                .as_mut()
                .unwrap()
                .writer()
                .write(request)
                .map_err(|_| tls_error())?;
            if n == 0 {
                return Err(tls_error());
            }
            request = &request[n..];
            self.flush_tls().await?;
        }
        Ok(())
    }
    async fn read(&mut self, output: &mut [u8]) -> Result<usize> {
        if self.tls.is_none() {
            return self
                .socket
                .read(output)
                .await
                .map_err(|_| Error::unavailable());
        }
        loop {
            match self.tls.as_mut().unwrap().reader().read(output) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                Err(_) => return Err(tls_error()),
            }
            self.flush_tls().await?;
            self.receive_tls().await?;
        }
    }
}

struct Reader {
    wire: Wire,
    block: Zeroizing<[u8; 8192]>,
    pos: usize,
    end: usize,
}
impl Reader {
    async fn fill(&mut self) -> Result<bool> {
        if self.pos == self.end {
            self.block.zeroize();
            self.end = self.wire.read(&mut *self.block).await?;
            self.pos = 0;
        }
        Ok(self.end != 0)
    }
    async fn line(&mut self, limit: usize) -> Result<Body> {
        let mut line = Body::new(limit)?;
        loop {
            if !self.fill().await? {
                return Err(framing());
            }
            let b = self.block[self.pos];
            self.pos += 1;
            line.append(&[b], limit)?;
            if b == b'\n' {
                if !line.0.ends_with(b"\r\n") {
                    return Err(framing());
                }
                return Ok(line);
            }
        }
    }
    async fn exact(&mut self, n: usize, out: &mut Body) -> Result<()> {
        let mut left = n;
        while left > 0 {
            if !self.fill().await? {
                return Err(framing());
            }
            let n = left.min(self.end - self.pos);
            out.append(&self.block[self.pos..self.pos + n], MAX_DOCUMENT_BYTES)?;
            self.pos += n;
            left -= n;
        }
        Ok(())
    }
    async fn headers(&mut self, used: &mut usize) -> Result<Body> {
        let mut header = Body::new(HEADER_LIMIT)?;
        loop {
            let line = self.line(HEADER_LIMIT.saturating_sub(*used)).await?;
            *used += line.0.len();
            header.append(&line.0, HEADER_LIMIT)?;
            if line.as_bytes() == b"\r\n" {
                return Ok(header);
            }
        }
    }
}
#[derive(Clone, Copy)]
enum Framing {
    Length(usize),
    Chunked,
    Close,
}
fn header_line(line: &[u8]) -> Result<(&str, &[u8])> {
    let split = line.iter().position(|b| *b == b':').ok_or_else(framing)?;
    let name = &line[..split];
    if name.is_empty()
        || !name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
    {
        return Err(framing());
    }
    let value = &line[split + 1..];
    if value.iter().any(|b| *b < 32 && *b != b'\t' || *b == 127) {
        return Err(framing());
    }
    Ok((
        std::str::from_utf8(name).map_err(|_| framing())?,
        value.trim_ascii(),
    ))
}
fn parse_headers(header: &[u8]) -> Result<(u16, Framing)> {
    let mut lines = header
        .split(|b| *b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status = lines.next().ok_or_else(framing)?;
    if status.len() < 12
        || !matches!(&status[..9], b"HTTP/1.1 " | b"HTTP/1.0 ")
        || !status[9..12].iter().all(u8::is_ascii_digit)
        || status.get(12).is_some_and(|b| *b != b' ')
        || status.iter().any(|b| *b < 32 || *b == 127)
    {
        return Err(framing());
    }
    let status: u16 = std::str::from_utf8(&status[9..12])
        .map_err(|_| framing())?
        .parse()
        .map_err(|_| framing())?;
    if !(100..600).contains(&status) {
        return Err(framing());
    }
    let (mut length, mut chunked) = (None, false);
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = header_line(line)?;
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
                return Err(framing());
            }
            let n = std::str::from_utf8(value)
                .map_err(|_| framing())?
                .parse::<usize>()
                .map_err(|_| limit())?;
            if n > MAX_DOCUMENT_BYTES {
                return Err(limit());
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case(b"chunked") {
                return Err(framing());
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case(b"identity")
        {
            return Err(Error::runtime("unsupported vault response encoding"));
        }
    }
    if chunked && length.is_some() {
        return Err(framing());
    }
    if status < 200 || matches!(status, 204 | 304) {
        if chunked || length.is_some_and(|n| n != 0) {
            return Err(framing());
        }
        return Ok((status, Framing::Length(0)));
    }
    Ok((
        status,
        if chunked {
            Framing::Chunked
        } else {
            length.map_or(Framing::Close, Framing::Length)
        },
    ))
}

pub async fn exchange(
    address: &Address,
    method: &str,
    components: &[&str],
    token: Option<&str>,
    body: Option<&Prepared>,
    connect_budget: Duration,
) -> Result<Response> {
    let path = address.path(components)?;
    let request = request(address, method, &path, token, body)?;
    let mut wire = Wire::connect(address, connect_budget).await?;
    wire.send(request.as_bytes()).await?;
    drop(request);
    let mut reader = Reader {
        wire,
        block: Zeroizing::new([0; 8192]),
        pos: 0,
        end: 0,
    };
    let mut header_bytes = 0;
    let mut informational = 0;
    let (status, framing_kind) = loop {
        let headers = reader.headers(&mut header_bytes).await?;
        let (status, kind) = parse_headers(headers.as_bytes())?;
        if status >= 200 {
            break (status, kind);
        }
        informational += 1;
        if status == 101 || informational > 8 {
            return Err(framing());
        }
    };
    let capacity = match framing_kind {
        Framing::Length(n) => n,
        _ => MAX_DOCUMENT_BYTES,
    };
    let mut body = Body::new(capacity)?;
    match framing_kind {
        Framing::Length(n) => reader.exact(n, &mut body).await?,
        Framing::Close => {
            while reader.fill().await? {
                body.append(&reader.block[reader.pos..reader.end], MAX_DOCUMENT_BYTES)?;
                reader.pos = reader.end;
            }
        }
        Framing::Chunked => {
            let (mut work, mut chunks) = (0usize, 0usize);
            loop {
                let line = reader
                    .line(HEADER_LIMIT.min(CHUNK_WORK_LIMIT.saturating_sub(work)))
                    .await?;
                work += line.0.len();
                chunks += 1;
                if chunks > 65536 || work > CHUNK_WORK_LIMIT {
                    return Err(limit());
                }
                let text = &line.as_bytes()[..line.0.len() - 2];
                let size = text.split(|b| *b == b';').next().ok_or_else(framing)?;
                if size.is_empty()
                    || !size.iter().all(u8::is_ascii_hexdigit)
                    || text.iter().any(|b| *b < 32 || *b == 127)
                {
                    return Err(framing());
                }
                let n =
                    usize::from_str_radix(std::str::from_utf8(size).map_err(|_| framing())?, 16)
                        .map_err(|_| limit())?;
                if n > MAX_DOCUMENT_BYTES.saturating_sub(body.0.len()) {
                    return Err(limit());
                }
                if n == 0 {
                    let mut trailer_bytes = 0;
                    let trailers = reader.headers(&mut trailer_bytes).await?;
                    for line in trailers.as_bytes().split(|b| *b == b'\n') {
                        let line = line.strip_suffix(b"\r").unwrap_or(line);
                        if line.is_empty() {
                            break;
                        }
                        let (name, _) = header_line(line)?;
                        if ["content-length", "transfer-encoding", "content-encoding"]
                            .iter()
                            .any(|n| name.eq_ignore_ascii_case(n))
                        {
                            return Err(framing());
                        }
                    }
                    break;
                }
                reader.exact(n, &mut body).await?;
                if reader.line(2).await?.as_bytes() != b"\r\n" {
                    return Err(framing());
                }
                work += 2;
            }
        }
    }
    Ok(Response { status, body })
}

