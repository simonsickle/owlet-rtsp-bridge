pub mod header;
pub mod lan;
pub mod session;

use crate::{hex, transcode::Transcode, Config, Datagram};
use header::{Opcode::*, Packet};
use std::{io, net::SocketAddr, sync::Arc};

#[derive(Clone)]
pub(crate) struct Wire {
    socket: Arc<dyn Datagram>,
    codec: Transcode,
    trace: bool,
}
impl Wire {
    pub fn new(socket: Arc<dyn Datagram>, cfg: &Config) -> Self {
        Self {
            socket,
            codec: Transcode::new(cfg.key_mask),
            trace: cfg.trace,
        }
    }
    pub fn send(&self, p: &Packet, addr: SocketAddr) -> io::Result<()> {
        let wire = p.encode(&self.codec)?;
        self.socket.send_to(&wire, addr)?;
        self.log("tx", p, addr);
        Ok(())
    }
    pub fn recv(&self) -> io::Result<Option<(Packet, SocketAddr)>> {
        // One spare byte distinguishes an oversized, truncated datagram.
        let mut buf = [0; 16 + 0x579];
        match self.socket.receive(&mut buf) {
            Ok((n, addr)) => match Packet::decode(&buf[..n], &self.codec) {
                Some(p) => {
                    self.log("rx", &p, addr);
                    Ok(Some((p, addr)))
                }
                None => Ok(None),
            },
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    fn log(&self, direction: &str, p: &Packet, addr: SocketAddr) {
        if !self.trace {
            return;
        }
        eprintln!("{}", p.trace_line(direction, addr));
    }
}
impl Packet {
    /// Return the decoded wire image with credential fields masked.
    pub fn trace_line(&self, direction: &str, addr: SocketAddr) -> String {
        let mut bytes = self.header.bytes(self.payload.len() as u16).to_vec();
        bytes.extend_from_slice(&self.payload);
        match self.header.opcode {
            Search | FilteredSearch | PortSearch => {
                if bytes.len() > 0x4a {
                    let end = bytes.len().min(0x52);
                    bytes[0x4a..end].fill(0);
                }
            }
            ClientData if self.header.dtype & 3 == 0 => {
                let offset = if self.header.flags & header::HAS_RID != 0 {
                    session::extension_len(&self.payload)
                } else {
                    Some(0)
                };
                if let Some(start) = offset {
                    let av = &mut bytes[16 + start..];
                    if av.first() == Some(&0) && matches!(av.get(1), Some(0 | 0x20)) {
                        crate::av::login::mask_credentials(av);
                    }
                } else {
                    bytes[16..].fill(0);
                }
            }
            _ => {}
        }
        format!(
            "{direction} {addr} opcode={:04x} {}",
            self.header.opcode as u16,
            hex(&bytes)
        )
    }
}
