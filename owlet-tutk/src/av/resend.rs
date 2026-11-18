//! ACK processing and link measurements for the new AV transport (D_av 5).
use super::{
    ioctrl::Ack,
    packet::{newer16, take, Fragment, Sender},
    VERSION,
};
use crate::{put16, u16le};
use std::{
    collections::{HashSet, VecDeque},
    io,
    time::{Duration, Instant},
};

pub(crate) const ACK_INTERVAL: Duration = Duration::from_millis(100);
const PROBE_INTERVAL: Duration = Duration::from_millis(200);
const INITIAL_RTT_MS: u16 = 200;
const MAX_RETRY: Duration = Duration::from_secs(30);
// Local retention policy. Keep at most this many unacknowledged media fragments.
const SEND_WINDOW: usize = 2048;

pub(crate) struct Link {
    start: Instant,
    last_probe: Instant,
    last_extension: Instant,
    rtt: u16,
    highest: Option<u16>,
    seen: u128,
    last_report: u16,
    received: u16,
    duplicates: u16,
    old: u16,
}
impl Link {
    pub fn new() -> Self {
        let start = Instant::now();
        Self {
            start,
            last_probe: start,
            last_extension: start,
            rtt: INITIAL_RTT_MS,
            highest: None,
            seen: 0,
            last_report: u16::MAX,
            received: 0,
            duplicates: 0,
            old: 0,
        }
    }
    fn ms(&self) -> u16 {
        self.start.elapsed().as_millis() as u16
    }
    pub fn retry_interval(&self) -> Duration {
        Duration::from_millis(u64::from(self.rtt.max(INITIAL_RTT_MS)) + 100).min(MAX_RETRY)
    }
    pub fn idle_ack_interval(&self) -> Duration {
        Duration::from_millis(u64::from(self.rtt / 2).max(10))
    }
    fn extension(&self) -> [u8; 8] {
        let mut ext = [0; 8];
        put16(&mut ext, 0, self.ms());
        put16(&mut ext, 2, self.rtt);
        ext
    }
    pub fn stamp_media(&mut self, packet: &mut Vec<u8>) {
        if self.last_extension.elapsed() >= PROBE_INTERVAL {
            packet[1] |= 8;
            packet.splice(8..8, self.extension());
            self.last_extension = Instant::now();
        }
    }
    pub fn probe(&mut self, tx: &mut Sender) -> Option<Vec<u8>> {
        if self.last_probe.elapsed() < PROBE_INTERVAL {
            return None;
        }
        let mut b = vec![0; 8];
        b[0] = 10;
        b[1] = 8;
        put16(&mut b, 2, VERSION);
        put16(&mut b, 4, take(&mut tx.seq));
        b.extend(self.extension());
        self.last_probe = Instant::now();
        Some(b)
    }
    // D_av 5.2. Count packet sequence numbers, independent of AV media numbers.
    pub fn receive(&mut self, b: &[u8]) -> Option<Vec<u8>> {
        if b.len() < 8 || !super::version_ok(u16le(b, 2)) {
            return None;
        }
        if b[0] == 11 {
            if b.len() == 20 {
                self.rtt = self.ms().wrapping_sub(u16le(b, 8)).clamp(1, 30000);
            }
            return None;
        }
        let seq = u16le(b, 4);
        self.received = self.received.saturating_add(1);
        match self.highest {
            Some(n) if newer16(seq, n) => {
                self.seen = self
                    .seen
                    .checked_shl(u32::from(seq.wrapping_sub(n)))
                    .unwrap_or(0)
                    | 1;
                self.highest = Some(seq);
            }
            Some(n) => {
                if let Some(bit) = 1u128.checked_shl(u32::from(n.wrapping_sub(seq))) {
                    if self.seen & bit != 0 {
                        self.duplicates = self.duplicates.saturating_add(1);
                    }
                    self.seen |= bit;
                } else {
                    self.old = self.old.saturating_add(1);
                }
            }
            None => {
                self.seen = 1;
                self.highest = Some(seq);
            }
        }
        if !matches!(b[0], 3..=8 | 10 | 12) || b[1] & 8 == 0 || b.len() < 16 {
            return None;
        }
        let mut stats = vec![0; 20];
        stats[0] = 11;
        put16(&mut stats, 2, VERSION);
        put16(&mut stats, 8, u16le(b, 8));
        let delta = seq.wrapping_sub(self.last_report);
        let pct = |n| {
            ((u32::from(n) * 100)
                .checked_div(u32::from(delta))
                .unwrap_or(0))
            .min(100) as u16
        };
        put16(&mut stats, 10, delta);
        put16(&mut stats, 12, self.received);
        put16(
            &mut stats,
            14,
            if delta > 0 {
                100 - pct(self.received)
            } else {
                0
            },
        );
        put16(&mut stats, 16, pct(self.duplicates));
        put16(&mut stats, 18, pct(self.old));
        self.last_report = seq;
        self.received = 0;
        self.duplicates = 0;
        self.old = 0;
        Some(stats)
    }
}

struct Stored {
    number: u16,
    packet: Vec<u8>,
    due: Instant,
    interval: Duration,
    retried: bool,
}
#[derive(Default)]
pub(crate) struct SendBuffer(VecDeque<Stored>);
impl SendBuffer {
    pub fn remember(&mut self, number: u16, packet: Vec<u8>, interval: Duration) {
        // Even a repeatedly requested hole must expire before its u16 number is reused.
        while self
            .0
            .front()
            .is_some_and(|old| usize::from(number.wrapping_sub(old.number)) >= SEND_WINDOW)
        {
            self.0.pop_front();
        }
        self.0.push_back(Stored {
            number,
            packet,
            due: Instant::now() + interval,
            interval,
            retried: false,
        });
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn acknowledge(&mut self, b: &[u8]) {
        if !Ack::valid(b) {
            return;
        }
        let base = u16le(b, 8);
        let max = u16le(b, 10);
        let lost: HashSet<u16> = (0..usize::from(u16le(b, 14)))
            .map(|i| base.wrapping_add(u16le(b, 22 + 2 * i)))
            .collect();
        self.0.retain_mut(|s| {
            if !newer16(s.number, base) {
                return false;
            }
            if newer16(s.number, max) {
                return true;
            }
            if !lost.contains(&s.number) {
                return false;
            }
            if !s.retried {
                s.due = Instant::now();
            }
            true
        });
    }
    pub fn retry(
        &mut self,
        tx: &mut Sender,
        mut send: impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let now = Instant::now();
        // Bound each burst so new frames and incoming controls still get service.
        for s in self.0.iter_mut().filter(|s| s.due <= now).take(8) {
            let mut f = Fragment::parse(&s.packet).expect("stored media fragment");
            f.kind += 1; // D_av 2.3: retransmits preserve packet and frame numbers.
            send(&tx.fragment(&f))?;
            s.retried = true;
            s.due = now + s.interval;
            s.interval = (s.interval * 2).min(MAX_RETRY);
        }
        Ok(())
    }
}
