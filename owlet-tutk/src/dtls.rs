//! OpenSSL DTLS over one IOTC channel. Each DATA packet carries one DTLS record.
use crate::{
    invalid,
    iotc::session::{Role, Session},
    sha256::sha256,
    timeout, Config,
};
use openssl::ssl::{
    ErrorCode, Ssl, SslContextBuilder, SslMethod, SslOptions, SslStream, SslVersion,
};
use std::{
    io::{self, Read, Write},
    time::Instant,
};

const MTU: usize = 0x56c;
const RECORD_HEADER: usize = 13;
// The captured vendor ClientHello offers DTLS 1.2 (fe fd). The PSK callbacks
// and the 13-byte record header below apply through DTLS 1.2.
const MAX_DTLS_VERSION: SslVersion = SslVersion::DTLS1_2;
// C_session_dtls 5.2 and SPEC.md: split a BIO flight at each record boundary.
const SPLIT_DTLS_RECORDS: bool = true;
const DTLS_METHOD: fn() -> SslMethod = SslMethod::dtls;
// C_session_dtls 5.4: the digest is assumed to be standard SHA-256.
// Binary strncpy stops at the first zero byte and pads the remaining bytes.
pub fn password_psk(password: &str) -> [u8; 32] {
    let mut key = sha256(password.as_bytes());
    if let Some(zero) = key.iter().position(|&b| b == 0) {
        key[zero..].fill(0);
    }
    key
}
struct Records<'a> {
    session: &'a Session,
    remaining: Vec<u8>,
    plain_peer: bool,
}
impl Read for Records<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining.is_empty() {
            match self.session.recv()? {
                Some((1, record)) if !record.is_empty() => self.remaining = record,
                Some((0, b)) => {
                    self.plain_peer = b == b"recv dtls data!";
                    return Err(invalid("plain packet on the DTLS channel"));
                }
                _ => return Err(io::ErrorKind::WouldBlock.into()),
            }
        }
        let n = out.len().min(self.remaining.len());
        out[..n].copy_from_slice(&self.remaining[..n]);
        self.remaining.drain(..n);
        Ok(n)
    }
}
impl Write for Records<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // OpenSSL can pack several handshake records into one BIO write.
        if !SPLIT_DTLS_RECORDS && bytes.len() <= MTU {
            self.session.send(1, bytes)?;
            return Ok(bytes.len());
        }
        let mut rest = bytes;
        while !rest.is_empty() {
            let header = rest
                .get(..RECORD_HEADER)
                .ok_or_else(|| invalid("short DTLS record"))?;
            let len = RECORD_HEADER + usize::from(u16::from_be_bytes([header[11], header[12]]));
            let record = rest
                .get(..len)
                .ok_or_else(|| invalid("incomplete DTLS record"))?;
            self.session.send(1, record)?;
            rest = &rest[len..];
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) struct Secure<'a>(SslStream<Records<'a>>);
impl<'a> Secure<'a> {
    pub fn open(session: &'a Session, cfg: &Config) -> io::Result<Self> {
        if cfg.account.is_empty()
            || cfg.account.len() + 8 >= 120
            || cfg.account.as_bytes().contains(&0)
            || cfg.password.as_bytes().contains(&0)
        {
            return Err(invalid("invalid DTLS credential length (-20024)"));
        }
        let mut ctx = SslContextBuilder::new(DTLS_METHOD()).map_err(io::Error::other)?;
        ctx.set_max_proto_version(Some(MAX_DTLS_VERSION))
            .map_err(io::Error::other)?;
        ctx.set_options(SslOptions::NO_QUERY_MTU);
        if cfg.cipher_list.as_bytes().contains(&0) {
            return Err(invalid("invalid cipher list"));
        }
        ctx.set_cipher_list(&cfg.cipher_list)
            .map_err(io::Error::other)?;
        let identity = format!("AUTHPWD_{}", cfg.account).into_bytes();
        let key = password_psk(&cfg.password);
        if session.role == Role::Client {
            // C_session_dtls 5.4: the callback ignores the unknown identity hint.
            ctx.set_psk_client_callback(move |_, _, id, out| {
                if id.len() <= identity.len() || out.len() < key.len() {
                    return Ok(0);
                }
                id[..identity.len()].copy_from_slice(&identity);
                id[identity.len()] = 0;
                out[..32].copy_from_slice(&key);
                Ok(32)
            });
        } else {
            ctx.set_psk_server_callback(move |_, id, out| {
                if id != Some(identity.as_slice()) || out.len() < 32 {
                    return Ok(0);
                }
                out[..32].copy_from_slice(&key);
                Ok(32)
            });
        }
        let mut ssl = Ssl::new(&ctx.build()).map_err(io::Error::other)?;
        ssl.set_mtu(MTU as u32).map_err(io::Error::other)?;
        let mut stream = SslStream::new(
            ssl,
            Records {
                session,
                remaining: Vec::new(),
                plain_peer: false,
            },
        )
        .map_err(io::Error::other)?;
        let start = Instant::now();
        while start.elapsed() < cfg.timeout {
            let result = if session.role == Role::Client {
                stream.connect()
            } else {
                stream.accept()
            };
            match result {
                Ok(()) => return Ok(Self(stream)),
                Err(_) if stream.get_ref().plain_peer => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "peer requires plain mode (-20039)",
                    ))
                }
                Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => {
                    continue
                }
                // A PSK peer can silently discard a bad MAC and close its IOTC
                // session when its own handshake timer expires (C_session_dtls 5.5).
                Err(e)
                    if e.io_error()
                        .is_some_and(|e| e.kind() == io::ErrorKind::ConnectionAborted) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "peer closed before DTLS handshake completed (-20011)",
                    ));
                }
                Err(e) => {
                    if e.ssl_error().is_some_and(|s| {
                        s.errors().iter().any(|e| {
                            e.reason().is_some_and(|r| {
                                r.contains("decrypt")
                                    || r.contains("bad record mac")
                                    || r.contains("psk identity")
                            })
                        })
                    }) {
                        return Err(invalid("DTLS password rejected (-20040)"));
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("DTLS handshake failed: {e} (-20041)"),
                    ));
                }
            }
        }
        Err(timeout("DTLS handshake timeout (-20011)"))
    }
    pub fn send(&mut self, b: &[u8]) -> io::Result<()> {
        if self.0.ssl_write(b).map_err(io::Error::other)? != b.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    pub fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut b = [0; MTU];
        match self.0.ssl_read(&mut b) {
            Ok(0) => Err(io::ErrorKind::ConnectionAborted.into()),
            Ok(n) => Ok(Some(b[..n].to_vec())),
            Err(e) if matches!(e.code(), ErrorCode::WANT_READ | ErrorCode::WANT_WRITE) => Ok(None),
            Err(e) if e.code() == ErrorCode::ZERO_RETURN => {
                Err(io::ErrorKind::ConnectionAborted.into())
            }
            Err(e) => Err(e.into_io_error().unwrap_or_else(io::Error::other)),
        }
    }
}
