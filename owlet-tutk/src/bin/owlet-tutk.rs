use owlet_tutk::{client, device, hex_decode, iotc::session::POLL, Config, Security};
use std::{
    env, fs,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

const USAGE: &str = "owlet-tutk search|stream|fake-camera [options]
  --uid UID              20 alphanumeric characters
  --ip ADDRESS           unicast destination or fake-camera bind address
  --port PORT|scan       UDP destination or camera listen port (default 32761);
                         scan finds the port of the host given by --ip
  --port-hint PORT       with --port scan: try this port before the sweep
  --bind-port PORT       client source port (default 0)
  --name NAME            name returned by the camera
  --account NAME         AV account (default admin)
  --password PASSWORD    or set OWLET_TUTK_PASSWORD
  --auth-key KEY         8 alphanumeric characters or set OWLET_TUTK_AUTHKEY
  --security MODE        simple, dtls, or auto (camera default auto, client default simple)
  --cipher-list LIST     OpenSSL cipher list
  --start-ioctrl T:HEX   IOCtrl type in hex and payload in hex
  --out DEST             -, a file path, or tcp://host:port (default -)
  --h264 FILE            camera input in Annex B format
  --fps N                camera frames per second (default 15)
  --start-on-login       stream camera input immediately after AV login
  --resend               request packet retransmission (stream)
  --loop                 repeat camera input
  --timeout SECONDS      search or handshake timeout (default 5)
  --duration SECONDS     limit stream duration
  --key-mask HEX         mask for the 16-byte transcode key
  --trace                print decoded datagrams to stderr with credentials masked";

fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s)
}
fn auth_key(s: &str) -> io::Result<[u8; 8]> {
    if !s.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return Err(bad("invalid auth key"));
    }
    s.as_bytes()
        .try_into()
        .map_err(|_| bad("auth key must be 8 characters"))
}
fn seconds(s: &str) -> io::Result<Duration> {
    let v = s
        .parse::<f64>()
        .map_err(|_| bad("invalid time in seconds"))?;
    let d = Duration::try_from_secs_f64(v).map_err(|_| bad("invalid time in seconds"))?;
    if d.is_zero() {
        return Err(bad("time must be positive"));
    }
    Ok(d)
}
fn main() {
    if let Err(e) = run() {
        eprintln!("owlet-tutk: {e}");
        std::process::exit(1);
    }
}
fn run() -> io::Result<()> {
    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        println!("{USAGE}");
        return Ok(());
    };
    if matches!(cmd.as_str(), "help" | "-h" | "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    if !matches!(cmd.as_str(), "search" | "stream" | "fake-camera") {
        return Err(bad("expected search, stream, or fake-camera"));
    }
    let mut cfg = Config::default();
    if cmd == "fake-camera" {
        cfg.security = Security::Auto;
    }
    let mut ip = None;
    let mut port = owlet_tutk::LAN_PORT;
    let mut bind_port = 0;
    let mut scan = false;
    let mut port_hint = None;
    let mut output = "-".to_owned();
    let mut source = None;
    let mut auth = env::var("OWLET_TUTK_AUTHKEY").ok();
    cfg.password = env::var("OWLET_TUTK_PASSWORD").unwrap_or_default();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            "--trace" => {
                cfg.trace = true;
                continue;
            }
            "--resend" if cmd == "stream" => {
                cfg.resend = true;
                continue;
            }
            "--start-on-login" if cmd == "fake-camera" => {
                cfg.start_on_login = true;
                continue;
            }
            "--loop" => {
                cfg.repeat = true;
                continue;
            }
            _ => {}
        }
        let v = args.next().ok_or_else(|| bad("missing option value"))?;
        match flag.as_str() {
            "--ip" => {
                ip = Some(
                    v.parse::<Ipv4Addr>()
                        .map_err(|_| bad("invalid IPv4 address"))?,
                )
            }
            "--port" if v == "scan" && cmd != "fake-camera" => scan = true,
            "--port" => port = v.parse().map_err(|_| bad("invalid UDP port"))?,
            "--port-hint" => {
                port_hint = Some(v.parse().map_err(|_| bad("invalid port hint"))?)
            }
            "--bind-port" => bind_port = v.parse().map_err(|_| bad("invalid bind port"))?,
            "--timeout" => cfg.timeout = seconds(&v)?,
            "--duration" => cfg.duration = Some(seconds(&v)?),
            "--uid" => cfg.uid = v,
            "--name" => cfg.name = v,
            "--password" => cfg.password = v,
            "--auth-key" => auth = Some(v),
            "--account" => cfg.account = v,
            "--cipher-list" => cfg.cipher_list = v,
            "--key-mask" => {
                cfg.key_mask = hex_decode(&v)?
                    .try_into()
                    .map_err(|_| bad("key mask must be 16 bytes"))?
            }
            "--fps" => cfg.fps = v.parse().map_err(|_| bad("invalid fps"))?,
            "--h264" => source = Some(v),
            "--out" => output = v,
            "--security" => {
                cfg.security = match v.as_str() {
                    "simple" => Security::Simple,
                    "dtls" => Security::Dtls,
                    "auto" => Security::Auto,
                    _ => return Err(bad("invalid security mode")),
                }
            }
            "--start-ioctrl" => {
                let (kind, body) = v
                    .split_once(':')
                    .ok_or_else(|| bad("expected type:payload"))?;
                cfg.start = (
                    u32::from_str_radix(kind.trim_start_matches("0x"), 16)
                        .map_err(|_| bad("invalid IOCtrl type"))?,
                    hex_decode(body)?,
                );
            }
            _ => return Err(bad("unknown command option")),
        }
    }
    cfg.auth_key = auth.as_deref().map(auth_key).transpose()?;
    if cfg.security == Security::Dtls && !cfg!(feature = "dtls") {
        return Err(bad("DTLS requires the dtls Cargo feature"));
    }
    // A_lan 7: unicast discovery and connect are inferred; --ip selects the destination.
    cfg.dest = SocketAddrV4::new(ip.unwrap_or(Ipv4Addr::BROADCAST), port).into();
    let bind = if cmd == "fake-camera" {
        SocketAddrV4::new(ip.unwrap_or(Ipv4Addr::UNSPECIFIED), port)
    } else {
        SocketAddrV4::new(
            if ip.is_some_and(|a| a.is_loopback()) {
                Ipv4Addr::LOCALHOST
            } else {
                Ipv4Addr::UNSPECIFIED
            },
            bind_port,
        )
    };
    let socket = Arc::new(UdpSocket::bind(bind)?);
    socket.set_read_timeout(Some(POLL))?;
    if scan {
        let ip = ip.ok_or_else(|| bad("--port scan requires --ip"))?;
        let trace = std::mem::replace(&mut cfg.trace, false);
        let found = client::scan_ports(socket.clone(), &cfg, ip, port_hint)?;
        cfg.trace = trace;
        let device = found
            .iter()
            .find(|d| cfg.uid.is_empty() || d.uid.eq_ignore_ascii_case(&cfg.uid))
            .ok_or_else(|| bad("port scan found no device"))?;
        eprintln!("device port {}", device.address.port());
        cfg.dest = device.address;
    }
    match cmd.as_str() {
        "fake-camera" => {
            let data = fs::read(source.ok_or_else(|| bad("fake-camera requires --h264"))?)?;
            println!("listening {}", socket.local_addr()?);
            io::stdout().flush()?;
            device::serve(socket, &cfg, &data, &AtomicBool::new(false))
        }
        "search" => {
            socket.set_broadcast(true)?;
            for d in client::search(socket, &cfg)? {
                let version = d
                    .version
                    .map_or_else(|| "unknown".into(), |v| format!("{v:#010x}"));
                println!(
                    "{} {} {} {} {}",
                    d.uid,
                    d.address.ip(),
                    d.address.port(),
                    d.name.escape_default(),
                    version
                );
            }
            Ok(())
        }
        _ => {
            socket.set_broadcast(true)?;
            let mut sink: Box<dyn Write> = if output == "-" {
                Box::new(io::stdout().lock())
            } else if let Some(addr) = output.strip_prefix("tcp://") {
                Box::new(TcpStream::connect(addr)?)
            } else {
                Box::new(fs::File::create(output)?)
            };
            client::stream(socket, &cfg, &mut sink)
        }
    }
}
