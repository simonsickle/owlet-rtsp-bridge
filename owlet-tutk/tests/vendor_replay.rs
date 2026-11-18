// Replay decoded client datagrams through the regular camera listener and wire codec.
use owlet_tutk::{
    av::{login, packet::Fragment},
    device, hex_decode,
    iotc::{
        header::{Opcode, Packet},
        session::{data, signal, Id, Role},
    },
    transcode::Transcode,
    Config, Datagram, Security,
};
use std::{
    fs, io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

type Message = (Vec<u8>, SocketAddr);
const VIDEO: [u8; 10] = [0, 0, 1, 0x65, 42, 0, 0, 1, 0x41, 43];
struct CameraSocket {
    input: Mutex<mpsc::Receiver<Message>>,
    output: mpsc::Sender<Message>,
}
impl Datagram for CameraSocket {
    fn send_to(&self, bytes: &[u8], dest: SocketAddr) -> io::Result<()> {
        self.output
            .send((bytes.to_vec(), dest))
            .map_err(io::Error::other)
    }
    fn receive(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (wire, addr) = self
            .input
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_millis(5))
            .map_err(|_| io::ErrorKind::TimedOut)?;
        buf[..wire.len()].copy_from_slice(&wire);
        Ok((wire.len(), addr))
    }
}
fn capture() -> impl Iterator<Item = Message> {
    let codec = Transcode::new([0; 16]);
    include_str!("../evidence/vendor_interop_1.trace")
        .lines()
        .filter(|l| l.starts_with("rx "))
        .map(move |l| {
            let fields: Vec<_> = l.split_whitespace().collect();
            let bytes = hex_decode(fields[3]).unwrap();
            let addr = fields[1].parse().unwrap();
            let prefix = if bytes[3] & 1 == 0 {
                bytes.len() - 16
            } else {
                48
            };
            let mut wire = codec.encode(&bytes[..16], 16);
            wire.extend(codec.encode(&bytes[16..], prefix));
            (wire, addr)
        })
}
struct Camera {
    input: mpsc::Sender<Message>,
    output: mpsc::Receiver<Message>,
    stop: Arc<AtomicBool>,
    worker: thread::JoinHandle<io::Result<()>>,
    trace: String,
}
impl Camera {
    fn new() -> Self {
        let (input, to_cam) = mpsc::channel();
        let (to_test, output) = mpsc::channel();
        let socket = Arc::new(CameraSocket {
            input: Mutex::new(to_cam),
            output: to_test,
        });
        let stop = Arc::new(AtomicBool::new(false));
        let camera_stop = stop.clone();
        let cfg = Config {
            uid: "FAKECAM0000000000001".into(),
            name: "RustCam".into(),
            security: Security::Auto,
            auth_key: Some([0; 8]),
            password: "fixture".into(),
            start_on_login: true,
            timeout: Duration::from_secs(3),
            ..Config::default()
        };
        let worker = thread::spawn(move || device::serve(socket, &cfg, &VIDEO, &camera_stop));
        Self {
            input,
            output,
            stop,
            worker,
            trace: String::new(),
        }
    }
    fn send(&self, p: Packet, source: SocketAddr) {
        self.input
            .send((p.encode(&Transcode::new([0; 16])).unwrap(), source))
            .unwrap();
    }
    fn read(&mut self, dest: SocketAddr, timeout: Duration) -> Option<Packet> {
        let (wire, addr) = self.output.recv_timeout(timeout).ok()?;
        let p = Packet::decode(&wire, &Transcode::new([0; 16])).unwrap();
        assert_eq!(addr, dest);
        self.trace.push_str(&p.trace_line("tx", addr));
        self.trace.push('\n');
        Some(p)
    }
    fn next(&mut self, dest: SocketAddr) -> Packet {
        self.read(dest, Duration::from_secs(1))
            .expect("camera reply")
    }
    fn connect(&mut self, capture: &mut impl Iterator<Item = Message>) -> (u64, SocketAddr) {
        for _ in 0..2 {
            let msg = capture.next().unwrap();
            let a = msg.1;
            self.input.send(msg).unwrap();
            assert_eq!(self.next(a).header.opcode, Opcode::Reply);
        }
        let confirm = capture.next().unwrap();
        let b = confirm.1;
        self.input.send(confirm).unwrap();
        let alive = self.next(b);
        assert_eq!(alive.header.opcode, Opcode::DeviceAlive);
        (u64::from_le_bytes(alive.payload.try_into().unwrap()), b)
    }
    fn finish(self, artifact: &str) {
        self.stop.store(true, Ordering::Release);
        self.worker.join().unwrap().unwrap();
        let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
        fs::write(target.join(artifact), self.trace).unwrap();
    }
}

#[test]
fn vendor_replay() {
    let mut camera = Camera::new();
    let mut rx = capture();
    let (rid, b) = camera.connect(&mut rx);
    let hello = rx.next().unwrap();
    let knock = rx.next().unwrap();
    assert_eq!(hello.1, b);
    assert_eq!(knock.1, b);
    camera.input.send(hello).unwrap();
    camera.input.send(knock.clone()).unwrap();
    let mut server_hello = false;
    let mut knock_ack = false;
    let mut knock_alive = false;
    let deadline = Instant::now() + Duration::from_millis(220);
    while Instant::now() < deadline {
        let Some(p) = camera.read(b, Duration::from_millis(10)) else {
            continue;
        };
        assert_ne!(
            p.header.opcode,
            Opcode::Reply,
            "precheck repeated after stage 2"
        );
        knock_ack |= p.header.opcode == Opcode::KnockAck;
        knock_alive |= p.header.opcode == Opcode::DeviceAlive;
        if p.header.opcode == Opcode::DeviceData && p.header.dtype == 1 {
            assert_eq!(p.header.flags, 0x0b);
            assert_eq!(&p.payload[..4], &12u32.to_le_bytes());
            assert_eq!(&p.payload[4..12], &rid.to_le_bytes());
            let record = &p.payload[12..];
            assert_eq!(
                record.len(),
                13 + usize::from(u16::from_be_bytes([record[11], record[12]]))
            );
            server_hello |= record[0] == 22 && record[1] == 0xfe && matches!(record[13], 2 | 3);
        }
    }
    assert!(knock_ack && knock_alive);
    assert_eq!(server_hello, cfg!(feature = "dtls"));
    let c = "127.0.0.1:45003".parse().unwrap();
    camera.input.send((knock.0, c)).unwrap();
    assert_eq!(camera.next(c).header.opcode, Opcode::KnockAck);
    assert_eq!(camera.next(c).header.opcode, Opcode::DeviceAlive);
    camera.finish(if cfg!(feature = "dtls") {
        "vendor-replay-dtls.trace"
    } else {
        "vendor-replay-simple.trace"
    });
}

#[test]
fn start_on_login_without_ioctrl() {
    let mut camera = Camera::new();
    let (rid, b) = camera.connect(&mut capture());
    let id = Id::Long(rid);
    // Move by ALIVE, then by the first login DATA. Stay silent while receiving the video.
    let other = "127.0.0.1:45004".parse().unwrap();
    camera.send(signal(Role::Client, id, false), other);
    assert_eq!(camera.next(other).header.opcode, Opcode::DeviceAlive);
    for (seq, request) in login::requests("admin", "fixture", 29, true, 123)
        .unwrap()
        .iter()
        .enumerate()
    {
        camera.send(data(Role::Client, id, seq as u16, 0, request), b);
    }
    assert_eq!(camera.next(b).header.opcode, Opcode::DeviceAlive);
    let login = camera.next(b);
    let av = &login.payload[12..];
    assert_eq!(login.header.opcode, Opcode::DeviceData);
    assert_eq!(&av[..4], &[0, 0x21, 12, 0]);
    assert_eq!(av.len(), 0x3e);
    assert_eq!(&av[20..24], &124u32.to_le_bytes());
    assert_eq!((av[0x18], av[0x20]), (0, 1));
    let mut media = Vec::new();
    for frame in 0..2 {
        let p = camera.next(b);
        assert_eq!(p.header.opcode, Opcode::DeviceData);
        let av = &p.payload[12..];
        assert_eq!(av[0], 12);
        let f = Fragment::parse(av).unwrap();
        assert_eq!((f.count, f.frame), (1, frame));
        media.extend_from_slice(&f.bytes[..f.bytes.len() - usize::from(f.info_len)]);
    }
    assert_eq!(media, VIDEO);
    let mut probe = [0; 16];
    probe[..5].copy_from_slice(&[10, 8, 12, 0, 1]);
    probe[8..10].copy_from_slice(&513u16.to_le_bytes());
    camera.send(data(Role::Client, id, 2, 0, &probe), b);
    let stats = camera.next(b);
    let stat = &stats.payload[12..];
    assert_eq!(stat.len(), 20);
    assert_eq!(stat[0], 11);
    assert_eq!(&stat[8..10], &513u16.to_le_bytes());

    let mut ack = [0; 24];
    ack[..4].copy_from_slice(&[9, 0, 12, 0]);
    ack[10..12].copy_from_slice(&1u16.to_le_bytes());
    ack[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
    ack[14] = 1;
    ack[22] = 1; // base 0 + offset 1
    camera.send(data(Role::Client, id, 3, 0, &ack), b);
    let retry = camera.next(b);
    let f = Fragment::parse(&retry.payload[12..]).unwrap();
    assert_eq!((f.kind, f.number, f.frame), (8, 1, 1));
    camera.finish("start-on-login.trace");
}
