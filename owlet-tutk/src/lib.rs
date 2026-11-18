pub mod av;
pub mod client;
pub mod device;
#[cfg(feature = "dtls")]
pub mod dtls;
pub mod iotc;
pub mod sha256;
pub mod transcode;

use std::{
    fmt::Write as _,
    io,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

pub(crate) fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
pub(crate) fn timeout(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, msg)
}
pub(crate) fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes(b[i..i + 2].try_into().unwrap())
}
pub(crate) fn u32le(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
pub(crate) fn put16(b: &mut [u8], i: usize, n: u16) {
    b[i..i + 2].copy_from_slice(&n.to_le_bytes());
}
pub(crate) fn put32(b: &mut [u8], i: usize, n: u32) {
    b[i..i + 4].copy_from_slice(&n.to_le_bytes());
}
pub(crate) fn c_bytes(b: &[u8]) -> &[u8] {
    b.split(|&c| c == 0).next().unwrap_or_default()
}
pub fn hex(buf: &[u8]) -> String {
    let mut s = String::with_capacity(buf.len() * 2);
    for v in buf {
        write!(s, "{v:02x}").unwrap();
    }
    s
}
pub fn hex_decode(s: &str) -> io::Result<Vec<u8>> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return Err(invalid("expected pairs of hexadecimal digits"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| invalid("invalid hexadecimal digit"))
        })
        .collect()
}

/// Datagram boundaries and the UDP source address are part of the wire protocol.
/// Return TimedOut or WouldBlock after a short poll so session timers can run.
pub trait Datagram: Send + Sync {
    fn send_to(&self, bytes: &[u8], dest: SocketAddr) -> io::Result<()>;
    fn receive(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}
impl Datagram for UdpSocket {
    fn send_to(&self, b: &[u8], dest: SocketAddr) -> io::Result<()> {
        if self.send_to(b, dest)? != b.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    fn receive(&self, b: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(b)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Simple,
    Dtls,
    Auto,
}

// B_dispatch 6.7: device bind port was not traced. Use the observed LAN destination.
pub const LAN_PORT: u16 = 32761;
// C_session_dtls 5.3, 5.5: the application cipher list and timeout are unknown.
pub const DEFAULT_CIPHER_LIST: &str = "DEFAULT:@SECLEVEL=0";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
// D_av 8.12: the start command body belongs to the camera application.
pub const DEFAULT_START: (u32, [u8; 8]) = (0x01ff, [0; 8]);
#[derive(Clone)]
pub struct Config {
    pub dest: SocketAddr,
    pub uid: String,
    pub name: String,
    pub account: String,
    pub password: String,
    pub auth_key: Option<[u8; 8]>,
    pub key_mask: [u8; 16],
    pub security: Security,
    pub cipher_list: String,
    pub timeout: Duration,
    pub duration: Option<Duration>,
    pub start: (u32, Vec<u8>),
    pub trace: bool,
    pub fps: u32,
    pub repeat: bool,
    pub resend: bool,
    pub start_on_login: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            dest: ([255, 255, 255, 255], LAN_PORT).into(),
            uid: String::new(),
            name: "Fake camera".into(),
            account: "admin".into(),
            password: String::new(),
            auth_key: None,
            key_mask: transcode::DEFAULT_MASK,
            security: Security::Simple,
            cipher_list: DEFAULT_CIPHER_LIST.into(),
            timeout: DEFAULT_TIMEOUT,
            duration: None,
            start: (DEFAULT_START.0, DEFAULT_START.1.to_vec()),
            trace: false,
            fps: 15,
            repeat: false,
            resend: av::login::REQUEST_RESEND,
            start_on_login: false,
        }
    }
}
impl Config {
    pub(crate) fn checked_uid(&self) -> io::Result<[u8; 20]> {
        if !self.uid.bytes().all(|c| c.is_ascii_alphanumeric()) {
            return Err(invalid("UID must be alphanumeric"));
        }
        self.uid
            .to_ascii_uppercase()
            .as_bytes()
            .try_into()
            .map_err(|_| invalid("UID must contain 20 ASCII characters"))
    }
}
