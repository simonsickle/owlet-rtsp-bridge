use super::{
    frame::{Pieces, Reassembly},
    packet::{newer16, take, Fragment, Sender, FRAGMENT},
    VERSION,
};
use crate::{invalid, put16, u16le, u32le};
use std::{collections::HashSet, io};
pub const USER: u8 = 0x70;
pub const INNER: u8 = 0x10;
impl Sender {
    pub fn control(&mut self, subtype: u8, kind: u32, data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        let count = u16::try_from((data.len() + 4).div_ceil(FRAGMENT))
            .map_err(|_| invalid("IOCtrl too large"))?;
        let body = [&kind.to_le_bytes()[..], data].concat();
        let mut out = Vec::new();
        for (pos, bytes) in body.chunks(FRAGMENT).enumerate() {
            let f = Fragment {
                kind: 0,
                flags: subtype,
                number: take(&mut self.io_packet),
                count,
                position: pos as u16,
                info_len: 0,
                frame: self.io_frame,
                stream: 0,
                bytes,
            };
            out.push(self.fragment(&f));
        }
        self.io_frame = self.io_frame.wrapping_add(1);
        Ok(out)
    }
}
#[derive(Default)]
pub(crate) struct Controls {
    next: u32,
    pieces: Option<(u8, Pieces)>,
    reset_id: Option<u16>,
}
impl Controls {
    /// Apply an inner control. A new reset ID needs a 0x23 reply (D_av 4.4).
    pub fn apply_inner(
        &mut self,
        kind: u32,
        body: &[u8],
        frames: &mut Reassembly,
        ack: &mut Ack,
    ) -> Option<[u8; 8]> {
        match kind {
            0x22 if body.len() >= 8 => {
                let id = u16le(body, 0);
                if self.reset_id == Some(id) {
                    return None;
                }
                self.reset_id = Some(id);
                let base = u16le(body, 2);
                frames.reset(u32le(body, 4));
                ack.reset(base);
                let mut reply = [0; 8];
                put16(&mut reply, 0, id);
                put16(&mut reply, 2, ack.previous);
                crate::put32(&mut reply, 4, frames.next.wrapping_sub(1));
                Some(reply)
            }
            0x40 if body.len() >= 4 => {
                frames.set_limit((u32le(body, 0).wrapping_mul(0xa00) & 0x7ffffe00) as usize);
                None
            }
            _ => None,
        }
    }
    pub fn accept(&mut self, p: Fragment<'_>) -> Option<(u32, Vec<u8>, u16)> {
        if p.kind != 0 || !matches!(p.flags, USER | INNER) || p.frame != self.next {
            return None;
        }
        let (subtype, pieces) = self
            .pieces
            .get_or_insert_with(|| (p.flags, Pieces::new(p.count)));
        if *subtype != p.flags {
            return None;
        }
        let bytes = pieces.insert(p)?;
        let number = pieces.last_packet;
        self.pieces = None;
        if bytes.len() < 4 {
            return None;
        }
        self.next = self.next.wrapping_add(1);
        Some((u32le(&bytes, 0), bytes[4..].to_vec(), number))
    }
}
pub(crate) struct Ack {
    pub highest: u16,
    pub previous: u16,
    pub io: u16,
    seq: u16,
    // D_av 5.1: packets above the highest contiguous packet (resend only).
    received: HashSet<u16>,
    resend: bool,
}
impl Default for Ack {
    fn default() -> Self {
        Self {
            highest: u16::MAX,
            previous: u16::MAX,
            io: u16::MAX,
            seq: 0,
            received: HashSet::new(),
            resend: false,
        }
    }
}
impl Ack {
    pub fn new(resend: bool) -> Self {
        Self {
            resend,
            ..Self::default()
        }
    }
    fn reset(&mut self, base: u16) {
        if newer16(base, self.previous) {
            self.previous = base;
            self.received.retain(|n| newer16(*n, base));
        }
        self.observe(base);
    }
    pub fn observe(&mut self, n: u16) {
        if self.resend && newer16(n, self.previous) {
            self.received.insert(n);
            while self.received.remove(&self.previous.wrapping_add(1)) {
                self.previous = self.previous.wrapping_add(1);
            }
        }
        if newer16(n, self.highest) {
            self.highest = n;
        }
    }
    pub fn packet(&mut self, tx: &mut Sender, ms: u16) -> Vec<u8> {
        let mut b = vec![0; 24];
        b[0] = 9;
        put16(&mut b, 2, VERSION);
        put16(&mut b, 4, take(&mut tx.seq));
        put16(&mut b, 8, self.previous);
        put16(&mut b, 10, self.highest);
        put16(&mut b, 12, self.io);
        put16(&mut b, 18, take(&mut self.seq));
        put16(&mut b, 20, ms);
        if self.resend {
            // D_av 5.1 permits the contiguous base. Offsets are relative to it,
            // including across 0xffff. Never acknowledge holes omitted by the cap.
            let mut count = 0;
            for offset in 1..=self.highest.wrapping_sub(self.previous) {
                let number = self.previous.wrapping_add(offset);
                if !self.received.contains(&number) {
                    b.resize(24 + 2 * count, 0);
                    put16(&mut b, 22 + 2 * count, offset);
                    count += 1;
                    if count == MAX_LOST {
                        put16(&mut b, 10, number);
                        break;
                    }
                }
            }
            put16(&mut b, 14, count as u16);
        } else {
            self.previous = self.highest;
        }
        b
    }
    pub fn valid(b: &[u8]) -> bool {
        b.len() >= 22
            && b[0] == 9
            && super::version_ok(u16le(b, 2))
            && b.len() == (22 + 2 * usize::from(u16le(b, 14))).max(24)
            && usize::from(u16le(b, 14)) <= MAX_LOST
    }
    pub fn acknowledges(b: &[u8], number: u16) -> bool {
        Self::valid(b) && !newer16(number, u16le(b, 12))
    }
}

const MAX_LOST: usize = (0x500 - 0x10) / 2; // D_av 5.1
