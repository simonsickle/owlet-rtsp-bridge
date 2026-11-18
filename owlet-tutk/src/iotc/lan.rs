use super::header::{
    Opcode::{self, *},
    Packet, CLIENT, DEVICE, PUNCH,
};
use crate::{c_bytes, put16, put32, u16le, u32le};
pub const SDK_VERSION: u32 = 0x04030800;
// A_lan U7: logical listen port zero selects the default listener.
pub const DEFAULT_PORT_ID: u16 = 0;
// A_lan 2: the absent key in the stage-2 confirm is inferred.
pub const CONFIRM_KEY: [u8; 8] = [0; 8];

pub struct Request {
    pub uid: [u8; 20],
    pub rid: u64,
    pub stage: u32,
    pub round: u32,
    pub port_id: u16,
    pub auth_key: [u8; 8],
}
impl Request {
    pub fn search(round: u32) -> Self {
        Self {
            uid: [0; 20],
            rid: 0,
            stage: 0,
            round: round & 15,
            port_id: DEFAULT_PORT_ID,
            auth_key: [0; 8],
        }
    }
    pub fn connect(uid: [u8; 20], rid: u64, auth_key: [u8; 8]) -> Self {
        Self {
            uid,
            rid,
            stage: 1,
            auth_key,
            ..Self::search(0)
        }
    }
    pub fn confirm(uid: [u8; 20], rid: u64) -> Self {
        Self {
            stage: 2,
            ..Self::connect(uid, rid, CONFIRM_KEY)
        }
    }
    pub fn packet(&self) -> Packet {
        let op = if self.port_id != 0 {
            PortSearch
        } else if self.stage == 0 && self.round != 0 {
            FilteredSearch
        } else {
            Search
        };
        let mut b = vec![0; 0x48];
        b[..20].copy_from_slice(&self.uid);
        put32(&mut b, 0x24, SDK_VERSION);
        b[0x28..0x30].copy_from_slice(&self.rid.to_le_bytes());
        put32(&mut b, 0x30, self.stage);
        if self.stage == 0 {
            put32(&mut b, 0x34, self.round);
        }
        put16(&mut b, 0x38, self.port_id);
        b[0x3a..0x42].copy_from_slice(&self.auth_key);
        let mut p = Packet::new(op, CLIENT, b);
        p.header.dtype = u8::from(self.stage == 0);
        p
    }
    pub fn parse(p: &Packet) -> Option<Self> {
        let b = &p.payload;
        if !matches!(p.header.opcode, Search | PortSearch | FilteredSearch)
            || b.len() != 0x48
            || p.header.direction != CLIENT
        {
            return None;
        }
        Some(Self {
            uid: b[..20].try_into().ok()?,
            rid: u64::from_le_bytes(b[0x28..0x30].try_into().ok()?),
            stage: u32le(b, 0x30),
            round: u32le(b, 0x34),
            port_id: u16le(b, 0x38),
            auth_key: b[0x3a..0x42].try_into().ok()?,
        })
    }
}
pub struct Response {
    pub uid: [u8; 20],
    pub name: String,
    pub sdk_version: Option<u32>,
    pub rid: u64,
    pub result: u32,
}
impl Response {
    pub fn packet(uid: &[u8; 20], name: &str, rid: u64, result: u32) -> Packet {
        let mut b = vec![0; 0xb8];
        b[..20].copy_from_slice(uid);
        let n = name.len().min(128);
        b[0x24..0x24 + n].copy_from_slice(&name.as_bytes()[..n]);
        put32(&mut b, 0xa8, SDK_VERSION);
        b[0xac..0xb4].copy_from_slice(&rid.to_le_bytes());
        put32(&mut b, 0xb4, result);
        Packet::new(Reply, DEVICE, b)
    }
    pub fn parse(p: &Packet) -> Option<Self> {
        let b = &p.payload;
        if p.header.opcode != Opcode::Reply || p.header.direction & 0xff != DEVICE {
            return None;
        }
        let (name, sdk_version, rid, result) = match b.len() {
            0x24 => (&b" "[..], None, 0, 0),
            0xa8 => (&b[0x24..0xa4], None, 0, 0),
            0xb8.. => (
                &b[0x24..0xa4],
                Some(u32le(b, 0xa8)),
                u64::from_le_bytes(b[0xac..0xb4].try_into().ok()?),
                u32le(b, 0xb4),
            ),
            _ => return None,
        };
        Some(Self {
            uid: b[..20].try_into().ok()?,
            name: String::from_utf8_lossy(c_bytes(name)).into_owned(),
            sdk_version,
            rid,
            result,
        })
    }
}
pub fn knock(uid: &[u8; 20], rid: u64, version: u8) -> Packet {
    let mut b = vec![0; if version < 10 { 24 } else { 36 }];
    b[..20].copy_from_slice(uid);
    put32(&mut b, 20, rid as u32);
    if version >= 10 {
        b[20..28].copy_from_slice(&rid.to_le_bytes());
        put32(&mut b, 32, SDK_VERSION);
    }
    Packet::new(Knock, PUNCH, b)
}
