use super::packet::{newer16, newer32, take, Fragment, Sender, FRAGMENT};
use crate::invalid;
use std::{collections::HashMap, io, ops::Range};

// D_av 8.12: the fake application uses only the observed key-frame marker at byte 2.
pub const FRAME_INFO_BYTES: usize = 3;
pub fn annex_b_units(file: &[u8]) -> io::Result<Vec<Range<usize>>> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i + 3 <= file.len() {
        let prefix = if file[i..].starts_with(&[0, 0, 0, 1]) {
            4
        } else if file[i..].starts_with(&[0, 0, 1]) {
            3
        } else {
            i += 1;
            continue;
        };
        starts.push((i, i + prefix));
        i += prefix;
    }
    if starts.is_empty() || file[..starts[0].0].iter().any(|&b| b != 0) {
        return Err(invalid("expected an Annex B start code"));
    }
    let mut ranges = Vec::new();
    for (n, &(start, header)) in starts.iter().enumerate() {
        let end = starts.get(n + 1).map_or(file.len(), |s| s.0);
        if header >= end {
            return Err(invalid("empty Annex B NAL unit"));
        }
        ranges.push(if n == 0 { 0 } else { start }..end);
    }
    Ok(ranges)
}
/// Cursor over one access unit. Assign packet numbers only when a fragment is sent.
pub(crate) struct MediaFrame<'a> {
    data: &'a [u8],
    info: [u8; FRAME_INFO_BYTES],
    pub count: u16,
    pub position: u16,
}
impl<'a> MediaFrame<'a> {
    pub fn new(data: &'a [u8]) -> io::Result<Self> {
        let key = data
            .iter()
            .position(|&v| v == 1)
            .and_then(|i| data.get(i + 1))
            .is_some_and(|v| v & 31 == 5);
        let count = u16::try_from((data.len() + FRAME_INFO_BYTES).div_ceil(FRAGMENT))
            .map_err(|_| invalid("media frame too large"))?;
        let mut info = [0; FRAME_INFO_BYTES];
        info[2] = u8::from(key);
        Ok(Self {
            data,
            info,
            count,
            position: 0,
        })
    }
    pub fn packet(&mut self, tx: &mut Sender) -> (u16, Vec<u8>) {
        let last = self.position + 1 == self.count;
        let (part, rest) = self.data.split_at(self.data.len().min(FRAGMENT));
        self.data = rest;
        let tail;
        let bytes = if last {
            tail = [part, &self.info].concat();
            &tail
        } else {
            part
        };
        let number = take(&mut tx.media_packet);
        let packet = tx.fragment(&Fragment {
            kind: if self.info[2] == 1 { 5 } else { 7 },
            flags: u8::from(last),
            number,
            count: self.count,
            position: self.position,
            info_len: self.info.len() as u16,
            frame: tx.media_frame,
            stream: tx.media_frame,
            bytes,
        });
        self.position += 1;
        if last {
            tx.media_frame = tx.media_frame.wrapping_add(1);
        }
        (number, packet)
    }
}
pub(crate) struct Pieces {
    count: u16,
    parts: HashMap<u16, Vec<u8>>,
    pub last_packet: u16,
}
impl Pieces {
    pub fn new(count: u16) -> Self {
        Self {
            count,
            parts: HashMap::new(),
            last_packet: 0,
        }
    }
    pub fn insert(&mut self, p: Fragment<'_>) -> Option<Vec<u8>> {
        if p.count != self.count || self.parts.contains_key(&p.position) {
            return None;
        }
        if p.position == p.count - 1 {
            self.last_packet = p.number;
        }
        self.parts.insert(
            p.position,
            p.bytes[..p.bytes.len() - p.info_len as usize].to_vec(),
        );
        if self.parts.len() != usize::from(self.count) {
            return None;
        }
        let mut out = Vec::with_capacity(self.parts.values().map(Vec::len).sum());
        for i in 0..self.count {
            out.extend(self.parts.remove(&i)?);
        }
        Some(out)
    }
}
#[derive(Default)]
pub struct Reassembly {
    frames: HashMap<u32, (u8, Pieces)>,
    pub next: u32,
    limit: Option<usize>,
    buffered: usize,
    highest_packet: Option<u16>,
    resend: bool,
    ready: HashMap<u32, (u8, Vec<u8>)>,
}
impl Reassembly {
    pub(crate) fn new(resend: bool) -> Self {
        Self {
            resend,
            ..Self::default()
        }
    }
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = Some(limit);
    }
    pub fn reset(&mut self, last: u32) {
        if newer32(last, self.next.wrapping_sub(1)) {
            self.next = last.wrapping_add(1);
        }
        self.frames.retain(|n, _| !newer32(self.next, *n));
        self.ready.retain(|n, _| !newer32(self.next, *n));
        self.buffered = self
            .frames
            .values()
            .flat_map(|(_, p)| p.parts.values())
            .map(Vec::len)
            .chain(self.ready.values().map(|(_, b)| b.len()))
            .sum();
    }
    pub fn accept(&mut self, p: Fragment<'_>) -> Option<Vec<u8>> {
        if !(3..=8).contains(&p.kind)
            || newer32(self.next, p.frame)
            || self.ready.contains_key(&p.frame)
        {
            return None;
        }
        // D_av 3.2: with resend off, discard incomplete frames once a newer frame advances.
        if !self.resend && newer32(p.frame, self.next.wrapping_add(1)) {
            self.reset(p.frame.wrapping_sub(2));
        }
        let class = (p.kind - 3) / 2;
        let (old, pieces) = self
            .frames
            .entry(p.frame)
            .or_insert_with(|| (class, Pieces::new(p.count)));
        if *old != class {
            return None;
        }
        if pieces.parts.contains_key(&p.position) || pieces.count != p.count {
            return None;
        }
        let added = p.bytes.len() - p.info_len as usize;
        let advances = self.highest_packet.is_none_or(|n| newer16(p.number, n));
        if !advances && self.limit.is_some_and(|limit| self.buffered >= limit) {
            return None;
        }
        if advances {
            self.highest_packet = Some(p.number);
        }
        self.buffered += added;
        let bytes = pieces.insert(p)?;
        if self.resend {
            self.frames.remove(&p.frame);
            self.ready.insert(p.frame, (class, bytes));
            return self.pop_ready();
        }
        self.reset(p.frame);
        (class != 0).then_some(bytes)
    }
    pub(crate) fn check_receive_window(&self) -> io::Result<()> {
        // Resend streams deliver in order. A permanent gap cannot hold all later
        // frames in memory. Allow a maximum-sized fragmented frame and its overhead.
        const MAX_BUFFERED_BYTES: usize = (u16::MAX as usize + 1) * FRAGMENT;
        const MAX_BUFFERED_FRAMES: usize = 2048;
        if self.buffered > MAX_BUFFERED_BYTES
            || self.frames.len() + self.ready.len() > MAX_BUFFERED_FRAMES
        {
            return Err(invalid(
                "AV receive window exhausted at an incomplete frame",
            ));
        }
        Ok(())
    }
    pub(crate) fn incomplete(&self) -> bool {
        !self.frames.is_empty() || !self.ready.is_empty()
    }
    pub(crate) fn pop_ready(&mut self) -> Option<Vec<u8>> {
        while let Some((class, bytes)) = self.ready.remove(&self.next) {
            self.next = self.next.wrapping_add(1);
            self.buffered -= bytes.len();
            if class != 0 {
                return Some(bytes);
            }
        }
        None
    }
}
