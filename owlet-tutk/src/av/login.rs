use super::VERSION;
use crate::{c_bytes, invalid, put16, put32, u16le, u32le};
use std::io;
pub const NEW_REPLY: u8 = 0x21; // D_av 8.1: actual camera transport depends on its login reply.
pub const REQUEST_RESEND: bool = false; // D_av 8.2: the camera policy is unknown.
pub const CAPABILITIES: [u32; 5] = [4, 0x001f07fb, 0, 0, 0x00030000]; // D_av 8.5: observed bits, unknown meanings.
const ON_CONNECT: [u8; 2] = [0, 0]; // D_av 8.4: packet B application flags.
pub const LOGIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50); // D_av 1.3, inferred LAN mode.
fn caps(b: &mut [u8]) {
    for (dst, n) in b.as_chunks_mut::<4>().0.iter_mut().zip(CAPABILITIES) {
        dst.copy_from_slice(&n.to_le_bytes());
    }
}
pub fn requests(
    account: &str,
    password: &str,
    peer_version: u8,
    resend: bool,
    nonce: u32,
) -> io::Result<Vec<Vec<u8>>> {
    let n = if peer_version > 8 { 257 } else { 16 };
    if nonce == 0
        || [account, password]
            .iter()
            .any(|s| s.len() >= n || s.as_bytes().contains(&0))
    {
        return Err(invalid("invalid AV login fields (-20024)"));
    }
    let mut packets = Vec::new();
    for variant in 0..=usize::from(resend) {
        let len = 2 * n + 32 + 2 * variant;
        let mut b = vec![0; 24 + len];
        b[1] = if variant == 0 { 0 } else { 0x20 };
        put16(&mut b, 2, VERSION);
        put16(&mut b, 16, len as u16);
        b[18] = u8::from(resend && variant == 0);
        put32(&mut b, 20, nonce.wrapping_add(variant as u32));
        b[24..24 + account.len()].copy_from_slice(account.as_bytes());
        b[24 + n..24 + n + password.len()].copy_from_slice(password.as_bytes());
        let tail = &mut b[24 + 2 * n..];
        tail[0] = u8::from(resend);
        caps(&mut tail[4..24]);
        if variant != 0 {
            tail[32..34].copy_from_slice(&ON_CONNECT);
        }
        packets.push(b);
    }
    Ok(packets)
}
pub fn reply(request: &[u8], account: &str, password: &str) -> Option<(Vec<u8>, bool)> {
    if request.len() < 24 || request[0] != 0 || !matches!(request[1], 0 | 0x20) {
        return None;
    }
    let version = u16le(request, 2);
    let n = if version >= 3 { 257 } else { 16 };
    let variant = request[1] == 0x20;
    let len = 2 * n + 32 + if variant { 2 } else { 0 };
    if u16le(request, 16) as usize != len
        || request.len() != 24 + len
        || (!variant && request[18] != 0 && version >= 9)
        || (variant && version < 9)
    {
        return None;
    }
    let accepted = request[24 + 2 * n + 24] == 0
        && c_bytes(&request[24..24 + n]) == account.as_bytes()
        && c_bytes(&request[24 + n..24 + 2 * n]) == password.as_bytes();
    let response_len = if variant && version >= 12 { 0x26 } else { 0x24 };
    let mut b = request[..24].to_vec();
    b.resize(24 + response_len, 0);
    b[1] = if variant || version >= 10 {
        NEW_REPLY
    } else if version >= 2 {
        0x14
    } else {
        1
    };
    put16(&mut b, 2, VERSION);
    put32(&mut b, 4, 0);
    put16(&mut b, 16, response_len as u16);
    b[24] = if accepted { 0 } else { 3 };
    caps(&mut b[0x24..0x38]);
    b[0x20] = u8::from(accepted && request[24 + 2 * n] == 1 && b[1] == NEW_REPLY);
    Some((b, accepted))
}
pub struct Reply {
    pub subtype: u8,
    pub result: u8,
    pub resend: bool,
    pub server_type: u32,
}
impl Reply {
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 25
            || b[0] != 0
            || !matches!(b[1], NEW_REPLY | 0x14 | 1)
            || b.len() != 24 + usize::from(u16le(b, 16))
        {
            return None;
        }
        if b[1] != 1 && b.len() < 0x38 {
            return None;
        }
        Some(Self {
            subtype: b[1],
            result: b[24],
            resend: b.get(32).is_some_and(|&x| x != 0),
            server_type: u32le(b, 4),
        })
    }
}

pub(crate) fn mask_credentials(b: &mut [u8]) {
    if b.len() <= 24 {
        return;
    }
    let variant_bytes = if b[1] == 0x20 { 2 } else { 0 };
    for width in [16, 257] {
        let size = 2 * width + 32 + variant_bytes;
        if u16le(b, 16) as usize == size && b.len() == 24 + size {
            b[24 + width..24 + 2 * width].fill(0);
            return;
        }
    }
    // Unknown or truncated credential layout. Hide the whole login payload.
    b[24..].fill(0);
}
