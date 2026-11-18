use crate::{
    av::{
        frame::Reassembly,
        ioctrl::{Ack, Controls, INNER, USER},
        login,
        packet::{Fragment, Sender},
        resend::{Link, ACK_INTERVAL},
    },
    c_bytes, invalid,
    iotc::{
        lan::{Request, Response},
        session::{new_rid, Channel, Session},
        Wire,
    },
    put16, timeout, Config, Datagram,
};
use std::{
    collections::HashSet,
    io::{self, Write},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct DeviceInfo {
    pub uid: String,
    pub address: SocketAddr,
    pub name: String,
    pub version: Option<u32>,
}
/// Finds the UDP port a device listens on by sending the search request to every port of one
/// host. The real Owlet camera does not use LAN_PORT or the app's search port; it answers on
/// the port its firmware bound at start (evidence/real_camera.md).
pub fn scan_ports(
    socket: Arc<dyn Datagram>,
    cfg: &Config,
    ip: std::net::Ipv4Addr,
    hint: Option<u16>,
) -> io::Result<Vec<DeviceInfo>> {
    let wire = Wire::new(socket, cfg);
    let mut seen = HashSet::new();
    let mut devices = Vec::new();
    let mut found = false;
    let mut collect = |wire: &Wire, found: &mut bool| -> io::Result<()> {
        while let Some((p, address)) = wire.recv()? {
            if let Some(r) = Response::parse(&p) {
                if r.result == 0 && seen.insert((r.uid, address)) {
                    *found = true;
                    devices.push(DeviceInfo {
                        uid: String::from_utf8_lossy(c_bytes(&r.uid)).into_owned(),
                        address,
                        name: r.name,
                        version: r.sdk_version,
                    });
                }
            }
        }
        Ok(())
    };
    let request = Request::search(0).packet();
    // A device that binds port 0 on Linux gets a port from 32768..=60999, so that range goes
    // first. The sweep stops at the first answer.
    let order = (32768..=60999u16)
        .chain(1024..32768)
        .chain(61000..=u16::MAX);
    // The port seen last time is tried first; a device keeps its port until it restarts.
    if let Some(port) = hint {
        for _ in 0..HINT_TRIES {
            let _ = wire.send(&request, std::net::SocketAddrV4::new(ip, port).into());
            let end = Instant::now() + Duration::from_millis(600);
            while Instant::now() < end && !found {
                collect(&wire, &mut found)?;
            }
            if found {
                break;
            }
        }
    }
    'sweep: for _pass in 0..SCAN_PASSES {
        if found {
            break;
        }
        for (i, port) in order.clone().enumerate() {
            // A refused send is not an error for a sweep; the next pass covers the gap.
            let _ = wire.send(&request, std::net::SocketAddrV4::new(ip, port).into());
            if i % SCAN_BURST == SCAN_BURST - 1 {
                // Pace the sweep (see SCAN_BURST).
                std::thread::sleep(SCAN_PAUSE);
                collect(&wire, &mut found)?;
                if found {
                    break 'sweep;
                }
            }
        }
        let end = Instant::now() + Duration::from_millis(1500);
        while Instant::now() < end && !found {
            collect(&wire, &mut found)?;
        }
    }
    drop(collect);
    Ok(devices)
}
const SCAN_PASSES: usize = 3;
// 250 probes per second. Measured on a real camera: an idle Wi-Fi camera receives about 200
// datagrams per second; a faster sweep loses probes, also the one for the right port.
const SCAN_BURST: usize = 4;
const SCAN_PAUSE: Duration = Duration::from_millis(16);
const HINT_TRIES: usize = 5;
pub fn search(socket: Arc<dyn Datagram>, cfg: &Config) -> io::Result<Vec<DeviceInfo>> {
    let wire = Wire::new(socket, cfg);
    let begin = Instant::now();
    let mut due = begin;
    let mut round = 0;
    let mut seen = HashSet::new();
    let mut devices = Vec::new();
    while begin.elapsed() < cfg.timeout {
        if Instant::now() >= due {
            wire.send(&Request::search(round).packet(), cfg.dest)?;
            round = (round + 1) & 15;
            due = Instant::now() + Duration::from_millis(50);
        }
        let Some((p, address)) = wire.recv()? else {
            continue;
        };
        let Some(r) = Response::parse(&p) else {
            continue;
        };
        if r.result == 0 && seen.insert((r.uid, address)) {
            devices.push(DeviceInfo {
                uid: String::from_utf8_lossy(c_bytes(&r.uid)).into_owned(),
                address,
                name: r.name,
                version: r.sdk_version,
            });
        }
    }
    Ok(devices)
}
fn connect(wire: Wire, cfg: &Config) -> io::Result<Session> {
    let uid = cfg.checked_uid()?;
    let rid = new_rid();
    let request = Request::connect(uid, rid, cfg.auth_key.unwrap_or([0; 8])).packet();
    let start = Instant::now();
    let mut due = start;
    while start.elapsed() < cfg.timeout {
        if Instant::now() >= due {
            wire.send(&request, cfg.dest)?;
            due = Instant::now() + Duration::from_millis(100);
        }
        let Some((p, addr)) = wire.recv()? else {
            continue;
        };
        let Some(r) = Response::parse(&p) else {
            continue;
        };
        if r.uid != uid || r.rid != rid {
            continue;
        }
        match r.result {
            1 | 7 if p.header.direction & 0x200 == 0 => {
                wire.send(&Request::confirm(uid, rid).packet(), addr)?;
                return Ok(Session::new(wire, addr, rid, p.header.version, None, &uid));
            }
            1 | 7 if p.header.version < 7 => return Err(invalid("device busy (-24)")),
            1 | 3 | 7 => return Err(invalid("device busy (-48)")),
            4 => return Err(invalid("port rejected (-67)")),
            5 => return Err(invalid("auth key mismatch (-68)")),
            6 => return Err(invalid("device has no auth key (-69)")),
            _ => {}
        }
    }
    Err(timeout("LAN connect timeout (-13)"))
}
fn login(channel: &mut Channel<'_>, cfg: &Config, version: u8, begin: Instant) -> io::Result<bool> {
    let packets = login::requests(
        &cfg.account,
        &cfg.password,
        version,
        cfg.resend,
        new_rid() as u32,
    )?;
    let mut due = Instant::now();
    while begin.elapsed() < cfg.timeout {
        if Instant::now() >= due {
            for p in &packets {
                channel.send(p)?;
            }
            due = Instant::now() + login::LOGIN_INTERVAL;
        }
        let Some(b) = channel.recv()? else {
            continue;
        };
        let Some(reply) = login::Reply::parse(&b) else {
            continue;
        };
        match reply.result {
            3 => return Err(invalid("AV account or password rejected (-20009)")),
            0 if reply.subtype != login::NEW_REPLY => {
                return Err(invalid("legacy AV transport is unsupported"))
            }
            0 if reply.resend && !cfg.resend => {
                return Err(invalid("peer did not accept resend=0"))
            }
            0 => return Ok(reply.resend),
            _ => {} // D_av 8.11: unmapped results keep the login pending.
        }
    }
    Err(timeout("AV login timeout (-20011)"))
}
pub fn stream(socket: Arc<dyn Datagram>, cfg: &Config, out: &mut dyn Write) -> io::Result<()> {
    let session = connect(Wire::new(socket, cfg), cfg)?;
    let begin = Instant::now();
    let mut channel = Channel::open(&session, cfg, cfg.security)?;
    let resend = login(&mut channel, cfg, session.version, begin)?;
    let mut tx = Sender::new(resend);
    let mut controls = Controls::default();
    let mut frames = Reassembly::new(resend);
    let mut ack = Ack::new(resend);
    let mut link = Link::new();
    let mut last_ack = Instant::now();
    let mut new_media = false;
    let mut start = tx.control(USER, cfg.start.0, &cfg.start.1)?;
    let end_io = tx.io_packet.wrapping_sub(1);
    let streaming = Instant::now();
    let mut wait = Duration::from_millis(50);
    let mut due = streaming;
    let mut sent = false;
    let mut started = false;
    loop {
        if !started && streaming.elapsed() >= cfg.timeout {
            return Err(timeout("start IOCtrl ACK timeout (-20011)"));
        }
        if started && cfg.duration.is_some_and(|d| streaming.elapsed() >= d) {
            break;
        }
        if !started && Instant::now() >= due {
            for b in &mut start {
                if sent {
                    put16(b, 4, crate::av::packet::take(&mut tx.seq));
                }
                channel.send(b)?;
            }
            sent = true;
            due = Instant::now() + wait;
            wait = (wait * 2).min(Duration::from_secs(30));
        }
        if resend {
            if let Some(probe) = link.probe(&mut tx) {
                channel.send(&probe)?;
            }
            let interval = if new_media {
                ACK_INTERVAL
            } else {
                link.idle_ack_interval()
            };
            if last_ack.elapsed() >= interval {
                channel.send(&ack.packet(&mut tx, streaming.elapsed().as_millis() as u16))?;
                last_ack = Instant::now();
                new_media = false;
            }
        }
        let b = match channel.recv() {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) if started && e.kind() == io::ErrorKind::ConnectionAborted => {
                if resend && frames.incomplete() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed with incomplete AV frames",
                    ));
                }
                break;
            }
            Err(e) => return Err(e),
        };
        if resend {
            if let Some(stats) = link.receive(&b) {
                channel.send(&stats)?;
            }
        }
        if Ack::acknowledges(&b, end_io) {
            started = true;
            continue;
        }
        let Some(f) = Fragment::parse(&b) else {
            continue;
        };
        if f.kind == 0 {
            if let Some((kind, body, last)) = controls.accept(f) {
                ack.io = last;
                if let Some(reply) = controls.apply_inner(kind, &body, &mut frames, &mut ack) {
                    for packet in tx.control(INNER, 0x23, &reply)? {
                        channel.send(&packet)?;
                    }
                }
            }
        } else {
            new_media = true;
            ack.observe(f.number);
            if let Some(frame) = frames.accept(f) {
                out.write_all(&frame)?;
            }
        }
        if resend {
            while let Some(next) = frames.pop_ready() {
                out.write_all(&next)?;
            }
            frames.check_receive_window()?;
        }
        // ACK duplicate controls too. The previous ACK may have been lost.
        if f.kind == 0 || b[1] & 4 != 0 {
            channel.send(&ack.packet(&mut tx, streaming.elapsed().as_millis() as u16))?;
            last_ack = Instant::now();
            new_media = false;
        }
    }
    out.flush()
}
