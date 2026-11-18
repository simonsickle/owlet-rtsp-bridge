# owlet-tutk

This Rust client reads H.264 video from an Owlet camera on the LAN. It implements the TUTK IOTC and AV protocols. It uses OpenSSL for DTLS. See the protocol notes in [spec/](spec/).

## Build

Install a Rust toolchain, OpenSSL development files, and pkg-config. Run this command in the crate directory.

```sh
cargo build --locked --release --features dtls
```

## Commands

- `search` looks for cameras on the LAN.
- `stream` writes the camera video to standard output, a file, or a TCP connection.
- `fake-camera` serves a local Annex B H.264 file for tests.

Set `OWLET_TUTK_PASSWORD` and `OWLET_TUTK_AUTHKEY` in the environment for the client. Replace the example UID and IP with the values for your camera.

```sh
target/release/owlet-tutk search
target/release/owlet-tutk stream --uid ABCDEFGHJKLMNPRSTUVW --ip 192.0.2.10 --port scan --security dtls --resend --out video.h264
target/release/owlet-tutk fake-camera --ip 127.0.0.1 --uid FAKECAM0000000000001 --h264 clip.h264 --loop --start-on-login
```

## Tests

```sh
cargo test --release --features dtls
cargo clippy --all-targets --features dtls -- -D warnings
```

The tests check the wire format against captured data. They compare the transmitted and received video on UDP loopback and on in-process connections. The loopback tests write reports in `target/e2e-report*.json`.

The vendor-client interop result is in [evidence/vendor_interop_report.json](evidence/vendor_interop_report.json).

## Limits

The client supports LAN video only. Hardware testing covered model E96LM72 with firmware 4.2.146. Audio, two-way talk, and relay streaming are outside the release. See the [camera test record](evidence/real_camera.md).
