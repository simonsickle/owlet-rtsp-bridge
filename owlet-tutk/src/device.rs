use crate::{
    av::{
        frame::{annex_b_units, MediaFrame},
        ioctrl::{Ack, Controls},
        login,
        packet::{Fragment, Sender},
        resend::{Link, SendBuffer},
    },
    invalid,
    iotc::{
        header::{Opcode, Packet, PUNCH},
        lan::{Request, Response, DEFAULT_PORT_ID},
        session::{new_rid, parse, signal, Channel, Event, Id, Role, Session, IDLE_TIMEOUT},
        Wire,
    },
    timeout, Config, Datagram, Security,
};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    ops::Range,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
        Arc, RwLock,
    },
    thread,
    time::{Duration, Instant},
};

// B_dispatch 6.6: whether the device schedules the observed precheck repeat is unknown.
const PRECHECK_REPEAT: Duration = Duration::from_millis(100);
// B_dispatch 6.2: model the unknown busy condition with a bounded session table.
const SESSION_CAPACITY: usize = 32;
struct Media {
    file: Vec<u8>,
    units: Vec<Range<usize>>,
}
struct Pending {
    address: SocketAddr,
    result: u32,
    created: Instant,
    last: Instant,
}
struct Active {
    version: u8,
    peer: Arc<RwLock<SocketAddr>>,
    inbox: SyncSender<Packet>,
    thread: thread::JoinHandle<()>,
}
pub fn serve(
    socket: Arc<dyn Datagram>,
    cfg: &Config,
    file: &[u8],
    stop: &AtomicBool,
) -> io::Result<()> {
    let uid = cfg.checked_uid()?;
    let media = Arc::new(Media {
        file: file.to_vec(),
        units: annex_b_units(file)?,
    });
    if cfg.fps == 0 || cfg.fps > 1000 {
        return Err(invalid("fps must be 1 to 1000"));
    }
    let wire = Wire::new(socket, cfg);
    let slot = (new_rid() % 15 + 1) as u32;
    let mut pending: HashMap<u64, Pending> = HashMap::new();
    let mut active: HashMap<u64, Active> = HashMap::new();
    while !stop.load(Ordering::Acquire) {
        active.retain(|_, s| !s.thread.is_finished());
        pending.retain(|_, s| s.created.elapsed() < IDLE_TIMEOUT);
        for (&rid, s) in &mut pending {
            if s.last.elapsed() >= PRECHECK_REPEAT && s.created.elapsed() < Duration::from_secs(30)
            {
                wire.send(&Response::packet(&uid, &cfg.name, rid, s.result), s.address)?;
                s.last = Instant::now();
            }
        }
        let Some((p, addr)) = wire.recv()? else {
            continue;
        };
        if let Some(r) = Request::parse(&p) {
            if p.header.opcode == Opcode::FilteredSearch && r.round != slot {
                continue;
            }
            let result = match r.stage {
                0 if r.port_id == DEFAULT_PORT_ID => 0,
                1 if r.uid == uid && r.rid as u32 != 0 => {
                    if cfg.auth_key.is_some_and(|k| r.auth_key != k) {
                        5
                    } else if cfg.auth_key.is_none()
                        && r.auth_key.iter().all(u8::is_ascii_alphanumeric)
                        && r.auth_key != *b"00000000"
                    {
                        6
                    } else if r.port_id != DEFAULT_PORT_ID {
                        4
                    } else if active.contains_key(&r.rid) {
                        // A delayed stage 1 cannot restart precheck on the discovery port.
                        continue;
                    } else if active.len() + pending.len() >= SESSION_CAPACITY
                        && !pending.contains_key(&r.rid)
                    {
                        3
                    } else {
                        let code = if cfg.auth_key.is_none() && p.header.version >= 0x1b {
                            7
                        } else {
                            1
                        };
                        pending.insert(
                            r.rid,
                            Pending {
                                address: addr,
                                result: code,
                                created: Instant::now(),
                                last: Instant::now(),
                            },
                        );
                        code
                    }
                }
                2 if r.uid == uid => {
                    if pending.remove(&r.rid).is_none() {
                        continue;
                    }
                    let (tx, rx) = mpsc::sync_channel(256);
                    let session =
                        Session::new(wire.clone(), addr, r.rid, p.header.version, Some(rx), &uid);
                    let peer = session.peer.clone();
                    let config = cfg.clone();
                    let source = media.clone();
                    let thread = thread::spawn(move || {
                        if let Err(e) = run_session(&session, &config, &source) {
                            if e.kind() != io::ErrorKind::ConnectionAborted {
                                eprintln!("camera session: {e}");
                            }
                        }
                    });
                    active.insert(
                        r.rid,
                        Active {
                            version: p.header.version,
                            peer,
                            inbox: tx,
                            thread,
                        },
                    );
                    continue;
                }
                _ => continue,
            };
            wire.send(&Response::packet(&uid, &cfg.name, r.rid, result), addr)?;
        } else if p.header.opcode == Opcode::Knock {
            if p.header.direction != PUNCH || p.payload.get(..20) != Some(&uid) {
                continue;
            }
            // B_dispatch 2: the default LAN port uses 0x404 (0x406 is for 0x405).
            let mut matches = active
                .iter()
                .filter(|(rid, session)| match p.payload.len() {
                    36 => p.payload[20..28] == rid.to_le_bytes(),
                    24 if session.version < 10 => p.payload[20..24] == (**rid as u32).to_le_bytes(),
                    _ => false,
                });
            if let Some((&rid, session)) = matches.next() {
                if matches.next().is_none() {
                    *session.peer.write().unwrap() = addr;
                    let mut reply = crate::iotc::lan::knock(&uid, rid, session.version);
                    reply.header.seq = p.header.seq;
                    reply.header.opcode = Opcode::KnockAck;
                    wire.send(&reply, addr)?;
                    wire.send(&signal(Role::Device, Id::Long(rid), false), addr)?;
                }
            }
        } else {
            for (&rid, session) in &active {
                let Some(event) = parse(&p, Role::Client, Id::Long(rid)) else {
                    continue;
                };
                let mut peer = session.peer.write().unwrap();
                if matches!(event, Event::Close) && *peer != addr {
                    break;
                }
                if *peer != addr {
                    *peer = addr;
                    wire.send(&signal(Role::Device, Id::Long(rid), false), addr)?;
                }
                drop(peer);
                let _ = session.inbox.try_send(p);
                break;
            }
        }
    }
    for (_, session) in active {
        drop(session.inbox);
        let _ = session.thread.join();
    }
    Ok(())
}
fn run_session(s: &Session, cfg: &Config, media: &Media) -> io::Result<()> {
    s.alive()?;
    let begin = Instant::now();
    let mode = loop {
        if begin.elapsed() >= cfg.timeout {
            return Err(timeout("camera login timeout"));
        }
        if let Some((t, b)) = s.recv()? {
            match (t, cfg.security) {
                (1, Security::Simple) => {
                    s.send(0, b"recv dtls data!")?;
                    continue;
                }
                (1, Security::Auto) if !cfg!(feature = "dtls") => {
                    s.send(0, b"recv dtls data!")?;
                    continue;
                }
                (0, Security::Dtls) => return Err(invalid("camera requires DTLS")),
                (0, _) => {
                    s.put_back((t, b));
                    break Security::Simple;
                }
                (1, _) => {
                    s.put_back((t, b));
                    break Security::Dtls;
                }
                _ => {}
            }
        }
    };
    let mut channel = Channel::open(s, cfg, mode)?;
    let mut login_nonce = None;
    let mut streaming = false;
    let mut tx = Sender::default();
    let mut controls = Controls::default();
    let mut ack = Ack::default();
    let mut link = Link::new();
    let mut buffer = SendBuffer::default();
    let mut index = 0;
    let mut frame = MediaFrame::new(&media.file[media.units[0].clone()])?;
    let mut frame_start = Instant::now();
    let interval = Duration::from_secs_f64(1.0 / f64::from(cfg.fps));
    let mut eof = None;
    loop {
        if login_nonce.is_none() && begin.elapsed() >= cfg.timeout {
            return Err(timeout("camera AV login timeout"));
        }
        if let Some(end) = eof {
            // Leave the channel open for final ACKs and missing tail fragments.
            if !tx.resend
                || buffer.is_empty()
                || Instant::now() - end >= cfg.timeout.max(2 * link.retry_interval())
            {
                return Ok(());
            }
        }
        if tx.resend {
            if let Some(probe) = link.probe(&mut tx) {
                channel.send(&probe)?;
            }
            buffer.retry(&mut tx, |packet| channel.send(packet))?;
        }
        if streaming && eof.is_none() {
            while Instant::now()
                >= frame_start
                    + interval.mul_f64(f64::from(frame.position) / f64::from(frame.count))
            {
                let (number, mut packet) = frame.packet(&mut tx);
                if tx.resend {
                    link.stamp_media(&mut packet);
                }
                channel.send(&packet)?;
                if tx.resend {
                    buffer.remember(number, packet, link.retry_interval());
                }
                if frame.position == frame.count {
                    index += 1;
                    if index == media.units.len() {
                        if !cfg.repeat {
                            eof = Some(Instant::now());
                            break;
                        }
                        index = 0;
                    }
                    frame = MediaFrame::new(&media.file[media.units[index].clone()])?;
                    frame_start = (frame_start + interval).max(Instant::now());
                    break;
                }
            }
        }
        let Some(b) = channel.recv()? else {
            continue;
        };
        if let Some((response, accepted)) = login::reply(&b, &cfg.account, &cfg.password) {
            let nonce = crate::u32le(&b, 20);
            if login_nonce.is_some_and(|previous| previous != nonce) {
                continue;
            }
            channel.send(&response)?;
            if !accepted {
                return Ok(());
            }
            if login_nonce.is_none() {
                login_nonce = Some(nonce);
                tx = Sender::new(response[0x20] == 1);
                if cfg.start_on_login {
                    streaming = true;
                    frame_start = Instant::now();
                }
            }
            continue;
        }
        if login_nonce.is_none() {
            continue;
        }
        if tx.resend {
            if let Some(stats) = link.receive(&b) {
                channel.send(&stats)?;
            }
            buffer.acknowledge(&b);
        }
        let Some(f) = Fragment::parse(&b) else {
            continue;
        };
        if f.kind == 0 {
            if let Some((kind, body, number)) = controls.accept(f) {
                ack.io = number;
                if !streaming && kind == cfg.start.0 && body == cfg.start.1 {
                    streaming = true;
                    frame_start = Instant::now();
                }
            }
            channel.send(&ack.packet(&mut tx, begin.elapsed().as_millis() as u16))?;
        }
    }
}
