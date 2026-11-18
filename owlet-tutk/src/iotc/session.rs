use super::{
    header::{self, Opcode::*, Packet},
    lan, Wire,
};
use crate::{invalid, timeout, u32le, Config, Security};
use std::{
    cell::{Cell, RefCell},
    collections::hash_map::RandomState,
    hash::BuildHasher,
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{Receiver, RecvTimeoutError},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

pub const INITIAL_SEQUENCE: u16 = 0; // C_session_dtls 7.7.
pub const ALIVE_INTERVAL: Duration = Duration::from_secs(2); // B_dispatch 4.2, inferred from ticks.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60); // C_session_dtls 2.1, inferred tick unit.
pub const POLL: Duration = Duration::from_millis(5);
// A_lan 4.2: a nonzero low word suffices for LAN lookup.
pub const RID_REQUIRED_BITS: u64 = 1;
pub(crate) fn new_rid() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    RandomState::new().hash_one(NEXT.fetch_add(1, Ordering::Relaxed)) | RID_REQUIRED_BITS
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Device,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Id {
    Long(u64),
    Short(u16),
}
pub(crate) fn extension_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 12 {
        return None;
    }
    let n = u32le(bytes, 0) as usize;
    (12..=bytes.len()).contains(&n).then_some(n)
}
pub fn data(role: Role, id: Id, seq: u16, dtype: u8, bytes: &[u8]) -> Packet {
    let (op, dir) = match role {
        Role::Client => (ClientData, header::CLIENT),
        Role::Device => (DeviceData, header::DEVICE),
    };
    let mut p = Packet::new(op, dir, Vec::new());
    p.header.seq = seq;
    p.header.dtype = dtype & 3;
    p.header.short_id = match id {
        Id::Long(v) => {
            p.header.flags |= header::HAS_RID;
            p.payload.extend(12u32.to_le_bytes());
            p.payload.extend(v.to_le_bytes());
            v as u16
        }
        Id::Short(v) => v,
    };
    if dtype == 1 {
        p.header.flags |= header::PARTIAL;
    }
    p.payload.extend_from_slice(bytes);
    p
}
pub fn signal(role: Role, id: Id, close: bool) -> Packet {
    let (op, dir) = match (role, close) {
        (Role::Client, false) => (ClientAlive, header::CLIENT),
        (Role::Client, true) => (ClientClose, header::CLIENT),
        (Role::Device, false) => (DeviceAlive, header::DEVICE),
        (Role::Device, true) => (DeviceClose, header::DEVICE),
    };
    let mut p = Packet::new(op, dir, Vec::new());
    match id {
        Id::Long(v) => {
            p.header.flags |= header::HAS_RID;
            p.payload.extend(v.to_le_bytes());
        }
        Id::Short(v) if close => p.header.short_id = v,
        _ => {}
    }
    p
}
pub enum Event<'a> {
    Data(u8, &'a [u8]),
    Alive,
    Close,
}
pub fn parse(p: &Packet, sender: Role, id: Id) -> Option<Event<'_>> {
    let h = &p.header;
    let (data, alive, close, dir) = match sender {
        Role::Device => (DeviceData, DeviceAlive, DeviceClose, header::DEVICE),
        Role::Client => (ClientData, ClientAlive, ClientClose, header::CLIENT),
    };
    if h.channel != 0 || h.direction != dir {
        return None;
    }
    let b = &p.payload;
    if h.opcode == data {
        if h.flags & header::IGNORE_DATA != 0 {
            return None;
        }
        let offset = match id {
            Id::Long(v) if h.flags & header::HAS_RID != 0 && b.get(4..12)? == v.to_le_bytes() => {
                extension_len(b)?
            }
            Id::Short(v) if h.flags & header::HAS_RID == 0 && h.short_id == v => 0,
            _ => return None,
        };
        return Some(Event::Data(h.dtype & 3, &b[offset..]));
    }
    if h.opcode != alive && h.opcode != close {
        return None;
    }
    match id {
        Id::Long(v) if h.flags & header::HAS_RID != 0 && b[..] == v.to_le_bytes() => {}
        Id::Short(v)
            if h.flags & header::HAS_RID == 0
                && b.is_empty()
                && (h.short_id == v || (h.opcode == alive && h.short_id == 0)) => {}
        _ => return None,
    }
    Some(if h.opcode == alive {
        Event::Alive
    } else {
        Event::Close
    })
}
pub(crate) struct Session {
    pub role: Role,
    pub version: u8,
    wire: Wire,
    pub(crate) peer: Arc<RwLock<SocketAddr>>,
    id: Id,
    inbox: Option<Receiver<Packet>>,
    pending: RefCell<Option<(u8, Vec<u8>)>>,
    seq: Cell<u16>,
    last_rx: Cell<Instant>,
    last_alive: Cell<Instant>,
    knock: Option<(Packet, Packet)>,
    next_knock: Cell<Option<Instant>>,
    created: Instant,
}
impl Session {
    pub fn new(
        wire: Wire,
        peer: SocketAddr,
        rid: u64,
        version: u8,
        inbox: Option<Receiver<Packet>>,
        uid: &[u8; 20],
    ) -> Self {
        let now = Instant::now();
        let role = if inbox.is_some() {
            Role::Device
        } else {
            Role::Client
        };
        Self {
            role,
            version,
            wire,
            peer: Arc::new(RwLock::new(peer)),
            id: Id::Long(rid),
            inbox,
            pending: RefCell::new(None),
            seq: Cell::new(INITIAL_SEQUENCE),
            last_rx: Cell::new(now),
            last_alive: Cell::new(now),
            created: now,
            knock: (role == Role::Client).then(|| {
                (
                    lan::knock(uid, rid, version),
                    lan::Request::confirm(*uid, rid).packet(),
                )
            }),
            next_knock: Cell::new((role == Role::Client).then_some(now)),
        }
    }
    fn destination(&self) -> SocketAddr {
        *self.peer.read().unwrap()
    }
    pub fn alive(&self) -> io::Result<()> {
        self.last_alive.set(Instant::now());
        self.wire
            .send(&signal(self.role, self.id, false), self.destination())
    }
    pub fn send(&self, dtype: u8, bytes: &[u8]) -> io::Result<()> {
        self.tick()?;
        let seq = self.seq.get();
        self.seq.set(seq.wrapping_add(1));
        self.wire.send(
            &data(self.role, self.id, seq, dtype, bytes),
            self.destination(),
        )
    }
    fn tick(&self) -> io::Result<()> {
        if self.last_rx.get().elapsed() > IDLE_TIMEOUT {
            return Err(timeout("session idle timeout (-23)"));
        }
        if self.last_alive.get().elapsed() >= ALIVE_INTERVAL {
            self.alive()?;
        }
        if let (Some((knock, _)), Some(next)) = (&self.knock, self.next_knock.get()) {
            if next <= Instant::now() {
                self.wire.send(knock, self.destination())?;
                self.next_knock.set(
                    (self.created.elapsed() < Duration::from_millis(4500))
                        .then(|| Instant::now() + Duration::from_millis(500)),
                );
            }
        }
        Ok(())
    }
    pub fn put_back(&self, item: (u8, Vec<u8>)) {
        self.pending.replace(Some(item));
    }
    pub fn recv(&self) -> io::Result<Option<(u8, Vec<u8>)>> {
        self.tick()?;
        if let Some(item) = self.pending.take() {
            return Ok(Some(item));
        }
        let packet = if let Some(receiver) = &self.inbox {
            match receiver.recv_timeout(POLL) {
                Ok(p) => p,
                Err(RecvTimeoutError::Timeout) => return Ok(None),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::ErrorKind::ConnectionAborted.into())
                }
            }
        } else {
            let Some((p, addr)) = self.wire.recv()? else {
                return Ok(None);
            };
            if addr != self.destination() {
                return Ok(None);
            }
            if let Some((_, confirm)) = &self.knock {
                if lan::Response::parse(&p).is_some_and(|r| {
                    self.id == Id::Long(r.rid)
                        && matches!(r.result, 1 | 7)
                        && r.uid[..] == confirm.payload[..20]
                }) {
                    self.wire.send(confirm, self.destination())?;
                }
            }
            p
        };
        let sender = if self.role == Role::Client {
            Role::Device
        } else {
            Role::Client
        };
        let Some(event) = parse(&packet, sender, self.id) else {
            return Ok(None);
        };
        self.last_rx.set(Instant::now());
        self.next_knock.set(None);
        match event {
            Event::Data(t, b) => Ok(Some((t, b.to_vec()))),
            Event::Alive => Ok(None),
            Event::Close => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "peer closed the session",
            )),
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let p = signal(self.role, self.id, true);
        for _ in 0..3 {
            let _ = self.wire.send(&p, self.destination());
        }
    }
}
pub(crate) enum Channel<'a> {
    Plain(&'a Session),
    #[cfg(feature = "dtls")]
    Secure(crate::dtls::Secure<'a>),
}
impl<'a> Channel<'a> {
    pub fn open(s: &'a Session, cfg: &Config, mode: Security) -> io::Result<Self> {
        if mode == Security::Simple {
            return Ok(Self::Plain(s));
        }
        if s.version < 0x17 {
            return if mode == Security::Auto {
                Ok(Self::Plain(s))
            } else {
                Err(invalid("peer does not support DTLS (-20039)"))
            };
        }
        #[cfg(feature = "dtls")]
        {
            match crate::dtls::Secure::open(s, cfg) {
                Ok(channel) => Ok(Self::Secure(channel)),
                Err(e) if e.kind() == io::ErrorKind::Unsupported && mode == Security::Auto => {
                    Ok(Self::Plain(s))
                }
                Err(e) => Err(e),
            }
        }
        #[cfg(not(feature = "dtls"))]
        {
            let _ = cfg;
            if mode == Security::Auto {
                Ok(Self::Plain(s))
            } else {
                Err(invalid("DTLS requires the dtls Cargo feature"))
            }
        }
    }
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.send(0, bytes),
            #[cfg(feature = "dtls")]
            Self::Secure(c) => c.send(bytes),
        }
    }
    pub fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self {
            Self::Plain(s) => match s.recv()? {
                Some((0, b)) => Ok(Some(b)),
                Some((1, _)) => Err(invalid("unexpected DTLS data (-20049)")),
                _ => Ok(None),
            },
            #[cfg(feature = "dtls")]
            Self::Secure(c) => c.recv(),
        }
    }
}
