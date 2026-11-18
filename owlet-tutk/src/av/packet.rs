use super::VERSION;
use crate::{put16, put32, u16le, u32le};
pub const FRAGMENT: usize = 1024;
// D_av 8.6: bytes the sender does not set have no known meaning.
const RESERVED: u8 = 0;
#[derive(Clone, Copy)]
pub struct Fragment<'a> {
    pub kind: u8,
    pub flags: u8,
    pub number: u16,
    pub count: u16,
    pub position: u16,
    pub info_len: u16,
    pub frame: u32,
    pub stream: u32,
    pub bytes: &'a [u8],
}
impl<'a> Fragment<'a> {
    pub fn parse(b: &'a [u8]) -> Option<Self> {
        if b.len() < 8 || !super::version_ok(u16le(b, 2)) || !matches!(b[0], 0 | 3..=8 | 12) {
            return None;
        }
        let extension = b[0] != 0 && b[1] & 8 != 0;
        let wrapper = b[0] == 12;
        let h = b.get(8 + 8 * usize::from(extension) + 8 * usize::from(wrapper)..)?;
        // D_av 3.3: parity has a different layout. Only systematic data is used.
        if h.len() < 20
            || !matches!(h[0], 0 | 3..=8)
            || (!wrapper && (b[0] != h[0] || (h[0] == 0 && b[1] != h[1])))
        {
            return None;
        }
        let count = u16le(h, 4);
        let field = u16le(h, 6);
        let len = u16le(h, 8) as usize;
        let last = h[0] != 0 && h[1] & 1 != 0;
        if count == 0
            || len > FRAGMENT
            || h.len() < 20 + len
            || (last && field as usize > len)
            || (!last && field >= count)
        {
            return None;
        }
        if h[0] != 0 && !last && field == count - 1 {
            return None;
        }
        Some(Self {
            kind: h[0],
            flags: h[1],
            number: u16le(h, 2),
            count,
            position: if last { count - 1 } else { field },
            info_len: if last { field } else { 0 },
            frame: u32le(h, 12),
            stream: u32le(h, 16),
            bytes: &h[20..20 + len],
        })
    }
    pub fn encode(&self, seq: u16) -> Vec<u8> {
        let mut b = vec![RESERVED; 28];
        b[0] = self.kind;
        b[1] = self.flags;
        put16(&mut b, 2, VERSION);
        put16(&mut b, 4, seq);
        b[8] = self.kind;
        b[9] = self.flags;
        put16(&mut b, 10, self.number);
        put16(&mut b, 12, self.count);
        put16(
            &mut b,
            14,
            if self.kind != 0 && self.flags & 1 != 0 {
                self.info_len
            } else {
                self.position
            },
        );
        put16(&mut b, 16, self.bytes.len() as u16);
        put32(&mut b, 20, self.frame);
        put32(&mut b, 24, self.stream);
        b.extend_from_slice(self.bytes);
        b
    }
}
#[derive(Default)]
pub(crate) struct Sender {
    pub seq: u16,
    pub media_packet: u16,
    pub media_frame: u32,
    pub io_packet: u16,
    pub io_frame: u32,
    pub resend: bool,
    group: u16,
    group_index: u8,
}
impl Sender {
    pub fn new(resend: bool) -> Self {
        Self {
            resend,
            ..Self::default()
        }
    }

    pub fn fragment(&mut self, f: &Fragment<'_>) -> Vec<u8> {
        let mut packet = f.encode(take(&mut self.seq));
        if self.resend {
            // D_av 3.3, 8.8: use systematic wrappers with parity off in resend mode.
            let mut fec = [0; 8];
            if f.kind != 0 {
                const GROUP_SIZE: u8 = 20; // D_av 2.2, initial data group.
                put16(&mut fec, 0, self.group);
                fec[2] = self.group_index;
                fec[3] = GROUP_SIZE;
                self.group_index += 1;
                if self.group_index == GROUP_SIZE {
                    self.group_index = 0;
                    self.group = self.group.wrapping_add(1);
                }
            }
            let checksum = packet[8..]
                .iter()
                .fold(0u16, |sum, &v| sum.wrapping_add(u16::from(v)));
            put16(&mut packet, 18, checksum);
            packet[0] = 12;
            packet[1] = if f.kind == 0 { 0 } else { f.flags };
            packet.splice(8..8, fec);
        }
        packet
    }
}
pub(crate) fn take(counter: &mut u16) -> u16 {
    let n = *counter;
    *counter = counter.wrapping_add(1);
    n
}
pub(crate) fn newer16(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) > 0
}
pub(crate) fn newer32(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
