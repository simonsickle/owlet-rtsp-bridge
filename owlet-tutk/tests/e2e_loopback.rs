use owlet_tutk::{hex, sha256::sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Output, Stdio},
    time::Duration,
};

const UID: &str = "FAKECAM0000000000001";
const KEY: &str = "Auth4321";
const PASSWORD: &str = "test-camera-password";
const FRAMES: usize = 60;
// Independent fixture digest, calculated with Python hashlib.sha256.
const SOURCE_DIGEST: &str = "4a0ea628210b026e0e60f5990f53696b2d5e084b44d9c208b998b75fa02d5084";
const BIN: &str = env!("CARGO_BIN_EXE_owlet-tutk");

fn fixture() -> Vec<u8> {
    let mut stream = Vec::new();
    for i in 0..FRAMES {
        let size = match i {
            0 => 200,
            1 => 1024,
            2 => 1023,
            3 => 40000,
            _ => 200 + i * 7919 % 39801,
        };
        let prefix: &[u8] = if i % 2 == 0 {
            &[0, 0, 0, 1]
        } else {
            &[0, 0, 1]
        };
        stream.extend_from_slice(prefix);
        stream.push([0x67, 0x68, 0x65, 0x41][i.min(3)]);
        for j in prefix.len() + 1..size {
            stream.push((1 + (i * 17 + j * 31) % 255) as u8);
        }
    }
    stream
}

struct Camera(Child);
impl Drop for Camera {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(mode: &str, port: &str, uid: &str, password: &str, args: &[&str]) -> Output {
    Command::new(BIN)
        .args([
            mode,
            "--ip",
            "127.0.0.1",
            "--port",
            port,
            "--uid",
            uid,
            "--timeout",
            "1",
            "--trace",
        ])
        .args(args)
        .env("OWLET_TUTK_PASSWORD", password)
        .env("OWLET_TUTK_AUTHKEY", KEY)
        .output()
        .unwrap()
}

fn success(result: &Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
            .lines()
            .last()
            .unwrap_or("")
    );
}

fn run_udp(mode: &str) {
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    let dir = target.join(format!("e2e-{mode}"));
    fs::create_dir_all(&dir).unwrap();
    let source = fixture();
    let path = dir.join("source.h264");
    fs::write(&path, &source).unwrap();
    let mut camera = Camera(
        Command::new(BIN)
            .args([
                "fake-camera",
                "--ip",
                "127.0.0.1",
                "--port",
                "0",
                "--uid",
                UID,
                "--name",
                "Test camera",
                "--fps",
                "30",
                "--security",
                mode,
                "--h264",
            ])
            .arg(&path)
            .env("OWLET_TUTK_PASSWORD", PASSWORD)
            .env("OWLET_TUTK_AUTHKEY", KEY)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut ready = String::new();
    BufReader::new(camera.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    let addr: std::net::SocketAddr = ready
        .trim()
        .strip_prefix("listening ")
        .expect("camera failed to bind its UDP socket")
        .parse()
        .unwrap();
    assert!(addr.ip().is_loopback());
    let port = addr.port().to_string();
    let search = cli("search", &port, UID, PASSWORD, &[]);
    success(&search);
    let found = String::from_utf8(search.stdout).unwrap();
    assert_eq!(found.lines().count(), 1);
    assert!(found.contains(UID) && found.contains("Test camera") && found.contains(&port));
    let sink = dir.join("received.h264");
    let normal = cli(
        "stream",
        &port,
        UID,
        PASSWORD,
        &[
            "--out",
            sink.to_str().unwrap(),
            "--security",
            mode,
            "--duration",
            "5",
        ],
    );
    success(&normal);
    let received = fs::read(sink).unwrap();
    assert_eq!(received.len(), source.len());
    assert_eq!(sha256(&received), sha256(&source));
    assert!(received == source);
    let bad = cli(
        "stream",
        &port,
        UID,
        "wrong-password",
        &["--security", mode],
    );
    assert!(!bad.status.success());
    let error = String::from_utf8(bad.stderr).unwrap();
    let reason = error.lines().last().unwrap();
    if mode == "dtls" {
        // A DTLS receiver can silently discard a record with a bad MAC.
        assert!(
            reason.ends_with("(-20040)") || reason.ends_with("(-20011)"),
            "{reason}"
        );
    } else {
        assert!(reason.ends_with("(-20009)"), "{reason}");
    }
    check_trace(error.as_bytes());
    let missing = cli(
        "stream",
        &port,
        "UNKNOWN0000000000000",
        PASSWORD,
        &["--security", mode],
    );
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("timeout"));
    let traces = [
        search.stderr,
        normal.stderr,
        error.into_bytes(),
        missing.stderr,
    ]
    .concat();
    write_report(&target, mode, &source, &received, &traces);
}

fn check_trace(trace: &[u8]) {
    let trace = String::from_utf8_lossy(trace);
    for secret in [KEY, PASSWORD, "wrong-password"] {
        assert!(!trace.contains(secret) && !trace.contains(&hex(secret.as_bytes())));
    }
}

fn write_report(dir: &Path, mode: &str, source: &[u8], received: &[u8], trace: &[u8]) {
    assert_eq!(hex(&sha256(source)), SOURCE_DIGEST);
    check_trace(trace);
    let suffix = if mode == "simple" {
        String::new()
    } else {
        format!("-{mode}")
    };
    fs::write(dir.join(format!("e2e-trace{suffix}.txt")), trace).unwrap();
    let mut counts = BTreeMap::new();
    for line in String::from_utf8_lossy(trace).lines() {
        if let Some(op) = line
            .split_whitespace()
            .find_map(|s| s.strip_prefix("opcode="))
        {
            *counts.entry(op.to_string()).or_insert(0usize) += 1;
        }
    }
    for op in ["0601", "0602", "0402", "0407", "0408", "0428", "0417"] {
        assert!(counts.contains_key(op), "missing {op}");
    }
    let counts = counts
        .into_iter()
        .map(|(op, count)| format!("    \"{op}\": {count}"))
        .collect::<Vec<_>>()
        .join(",\n");
    let report = dir.join(format!("e2e-report{suffix}.json"));
    let frame_count = received.windows(3).filter(|w| *w == [0, 0, 1]).count();
    let byte_count = received.len();
    let source_sha = hex(&sha256(source));
    let received_sha = hex(&sha256(received));
    let json = format!(
        r#"{{
  "mode": "{mode}",
  "uid": "{UID}",
  "frame_count": {frame_count},
  "byte_count": {byte_count},
  "source_sha256": "{source_sha}",
  "received_sha256": "{received_sha}",
  "packet_counts": {{
{counts}
  }}
}}
"#
    );
    fs::write(&report, json).unwrap();
    assert_eq!(frame_count, FRAMES, "see {}", report.display());
}

#[test]
fn simple_loopback() {
    run_udp("simple");
}

#[cfg(feature = "dtls")]
#[test]
fn dtls_loopback() {
    run_udp("dtls");
}

// The same state machines can also run on a pair of in-process datagram queues.
// This check remains available on build hosts that prohibit UDP bind().
#[test]
fn process_local_stream() {
    run_process_local("process-local", owlet_tutk::Security::Simple, false);
}

#[cfg(feature = "dtls")]
#[test]
fn process_local_dtls() {
    run_process_local("process-local-dtls", owlet_tutk::Security::Dtls, false);
}

#[test]
fn process_local_resend() {
    run_process_local("process-local-resend", owlet_tutk::Security::Simple, true);
}

#[cfg(feature = "dtls")]
#[test]
fn process_local_dtls_resend() {
    run_process_local(
        "process-local-dtls-resend",
        owlet_tutk::Security::Dtls,
        true,
    );
}

fn run_process_local(mode: &str, security: owlet_tutk::Security, resend: bool) {
    use owlet_tutk::{client, device, Config, Datagram};
    use std::{
        io,
        net::SocketAddr,
        sync::{mpsc, Arc, Mutex},
        thread,
    };
    type Message = (Vec<u8>, SocketAddr);
    struct Endpoint {
        address: SocketAddr,
        sender: mpsc::Sender<Message>,
        receiver: Mutex<mpsc::Receiver<Message>>,
        trace: Arc<Mutex<Vec<u8>>>,
        codec: owlet_tutk::transcode::Transcode,
        held_fragment: Mutex<Option<Vec<u8>>>,
        lost_ack: std::sync::atomic::AtomicBool,
        resend: bool,
        dropped_media: std::sync::atomic::AtomicBool,
        recovered_media: std::sync::atomic::AtomicBool,
    }
    impl Datagram for Endpoint {
        fn send_to(&self, bytes: &[u8], dest: SocketAddr) -> io::Result<()> {
            use owlet_tutk::{
                av::packet::Fragment,
                iotc::header::{Opcode, Packet},
            };
            use std::io::Write as _;
            let p = Packet::decode(bytes, &self.codec).unwrap();
            writeln!(self.trace.lock().unwrap(), "{}", p.trace_line("tx", dest)).unwrap();
            let deliver = |b: &[u8]| {
                self.sender
                    .send((b.to_vec(), self.address))
                    .map_err(io::Error::other)
            };
            if p.header.opcode == Opcode::DeviceData && p.header.dtype == 0 {
                let av = &p.payload[12..];
                // Lose the final ACK for the three-fragment start command once.
                if av.first() == Some(&9)
                    && av.get(12..14) == Some(&[2, 0])
                    && !self
                        .lost_ack
                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                {
                    return Ok(());
                }
                if let Some(f) = Fragment::parse(av) {
                    if self.resend
                        && ((f.frame == 3 && f.position == 2)
                            || (f.frame == FRAMES as u32 - 1 && f.position == f.count - 1))
                    {
                        if f.kind == 7 {
                            self.dropped_media
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            return Ok(());
                        }
                        if f.kind == 8 {
                            self.recovered_media
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    // Move position zero behind position one and duplicate position one.
                    if f.kind != 0 && f.count > 1 {
                        let mut held = self.held_fragment.lock().unwrap();
                        if f.position == 0 {
                            *held = Some(bytes.to_vec());
                            return Ok(());
                        }
                        if f.position == 1 {
                            deliver(bytes)?;
                            if let Some(first) = held.take() {
                                deliver(&first)?;
                            }
                        }
                    }
                }
            }
            deliver(bytes)
        }
        fn receive(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let (msg, addr) = self
                .receiver
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_millis(5))
                .map_err(|_| io::ErrorKind::TimedOut)?;
            buf[..msg.len()].copy_from_slice(&msg);
            Ok((msg.len(), addr))
        }
    }
    let (tx_a, rx_a) = mpsc::channel();
    let (tx_b, rx_b) = mpsc::channel();
    let addr = "127.0.0.1:32761".parse().unwrap();
    let capture = Arc::new(Mutex::new(Vec::new()));
    let mask = [0xa7; 16];
    let endpoint = |address, sender, receiver| {
        Arc::new(Endpoint {
            address,
            sender,
            receiver: Mutex::new(receiver),
            trace: capture.clone(),
            codec: owlet_tutk::transcode::Transcode::new(mask),
            held_fragment: Mutex::new(None),
            lost_ack: false.into(),
            resend,
            dropped_media: false.into(),
            recovered_media: false.into(),
        })
    };
    let client_socket = endpoint("127.0.0.1:40000".parse().unwrap(), tx_b, rx_a);
    let camera_socket = endpoint(addr, tx_a, rx_b);
    let cfg = Config {
        uid: UID.into(),
        password: PASSWORD.into(),
        auth_key: Some(KEY.as_bytes().try_into().unwrap()),
        dest: addr,
        timeout: Duration::from_millis(250),
        fps: 25,
        key_mask: mask,
        security,
        resend,
        start: (0x200, vec![0xab; 2400]),
        ..Config::default()
    };
    let source = fixture();
    let mut camera_cfg = cfg.clone();
    if resend {
        camera_cfg.security = owlet_tutk::Security::Auto;
        camera_cfg.start_on_login = true;
    }
    let media = source.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let camera_stop = stop.clone();
    let sender = camera_socket.clone();
    let handle =
        thread::spawn(move || device::serve(camera_socket, &camera_cfg, &media, &camera_stop));
    let result = client::search(client_socket.clone(), &cfg).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].uid, UID);
    let mut sink = Vec::new();
    client::stream(client_socket.clone(), &cfg, &mut sink).unwrap();
    assert_eq!(hex(&sha256(&sink)), hex(&sha256(&source)));
    assert!(source == sink);
    if resend && security == owlet_tutk::Security::Simple {
        assert!(sender
            .dropped_media
            .load(std::sync::atomic::Ordering::Relaxed));
        assert!(sender
            .recovered_media
            .load(std::sync::atomic::Ordering::Relaxed));
    }
    let mut invalid = cfg.clone();
    invalid.password = "wrong-password".into();
    let rejection = client::stream(client_socket.clone(), &invalid, &mut Vec::new())
        .unwrap_err()
        .to_string();
    if security == owlet_tutk::Security::Dtls {
        assert!(
            rejection.contains("-20040") || rejection.contains("-20011"),
            "{rejection}"
        );
    } else {
        assert!(rejection.contains("-20009"), "{rejection}");
    }
    invalid.auth_key = Some(*b"Invalid1");
    assert!(
        client::stream(client_socket.clone(), &invalid, &mut Vec::new())
            .unwrap_err()
            .to_string()
            .contains("-68")
    );
    invalid.uid = "UNKNOWN0000000000000".into();
    assert!(client::stream(client_socket, &invalid, &mut Vec::new())
        .unwrap_err()
        .to_string()
        .contains("timeout"));
    stop.store(true, std::sync::atomic::Ordering::Release);
    handle.join().unwrap().unwrap();
    let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("target");
    write_report(&target, mode, &source, &sink, &capture.lock().unwrap());
}
