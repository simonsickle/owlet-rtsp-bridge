use crate::{invalid, put16, transcode::Transcode, u16le};
use std::io;

// A_lan U3: direction values are observed. Their role names are inferred.
pub const CLIENT: u16 = 0x21;
pub const DEVICE: u16 = 0x12;
pub const PUNCH: u16 = 0x33;
pub const VERSION: u8 = 0x1d;
pub const PARTIAL: u8 = 0x01;
pub const SENDER: u8 = 0x02; // B_dispatch 6.3: all senders set this bit.
pub const IGNORE_DATA: u8 = 0x04; // A_lan U4: the discard rule is observed.
pub const HAS_RID: u8 = 0x08; // C_session_dtls 7.8: inferred receive selector.
pub const MAX_PAYLOAD: usize = 0x578;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Search = 0x601,
    Reply = 0x602,
    FilteredSearch = 0x603,
    PortSearch = 0x604,
    Knock = 0x402,
    KnockAck = 0x404,
    ClientData = 0x407,
    DeviceData = 0x408,
    ClientAlive = 0x427,
    DeviceAlive = 0x428,
    ClientClose = 0x417,
    DeviceClose = 0x418,
}
impl Opcode {
    fn parse(n: u16) -> Option<Self> {
        use Opcode::*;
        Some(match n {
            0x601 => Search,
            0x602 => Reply,
            0x603 => FilteredSearch,
            0x604 => PortSearch,
            0x402 => Knock,
            0x404 => KnockAck,
            0x407 => ClientData,
            0x408 => DeviceData,
            0x427 => ClientAlive,
            0x428 => DeviceAlive,
            0x417 => ClientClose,
            0x418 => DeviceClose,
            _ => return None,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub seq: u16,
    pub opcode: Opcode,
    pub direction: u16,
    pub short_id: u16,
    pub channel: u8,
    pub dtype: u8,
}
impl Header {
    pub fn new(opcode: Opcode, direction: u16) -> Self {
        Self {
            version: VERSION,
            flags: SENDER,
            seq: 0,
            opcode,
            direction,
            short_id: 0,
            channel: 0,
            dtype: 0,
        }
    }
    pub fn bytes(&self, len: u16) -> [u8; 16] {
        let mut b = [0; 16];
        put16(&mut b, 0, 0x0204);
        b[2] = self.version;
        b[3] = self.flags;
        put16(&mut b, 4, len);
        put16(&mut b, 6, self.seq);
        put16(&mut b, 8, self.opcode as u16);
        put16(&mut b, 10, self.direction);
        put16(&mut b, 12, self.short_id);
        b[14] = self.channel;
        b[15] = self.dtype;
        b
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
}
impl Packet {
    pub fn new(op: Opcode, dir: u16, payload: Vec<u8>) -> Self {
        Self {
            header: Header::new(op, dir),
            payload,
        }
    }
    pub fn encode(&self, codec: &Transcode) -> io::Result<Vec<u8>> {
        if self.payload.len() > MAX_PAYLOAD {
            return Err(invalid("IOTC payload is too large"));
        }
        let mut out = codec.encode(&self.header.bytes(self.payload.len() as u16), 16);
        let n = if self.header.flags & PARTIAL != 0 {
            48
        } else {
            self.payload.len()
        };
        out.extend(codec.encode(&self.payload, n));
        Ok(out)
    }
    pub fn decode(bytes: &[u8], codec: &Transcode) -> Option<Self> {
        let b = codec.decode(bytes.get(..16)?, 16);
        let len = u16le(&b, 4) as usize;
        if u16le(&b, 0) != 0x204 || len > MAX_PAYLOAD || bytes.len() != 16 + len {
            return None;
        }
        let header = Header {
            version: b[2],
            flags: b[3],
            seq: u16le(&b, 6),
            opcode: Opcode::parse(u16le(&b, 8))?,
            direction: u16le(&b, 10),
            short_id: u16le(&b, 12),
            channel: b[14],
            dtype: b[15],
        };
        let n = if header.flags & PARTIAL != 0 { 48 } else { len };
        Some(Self {
            header,
            payload: codec.decode(&bytes[16..], n),
        })
    }
}
