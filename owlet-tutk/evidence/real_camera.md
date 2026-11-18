# Real camera test (Owlet Cam, model E96LM72, firmware 4.2.146)

Date: 2026-11-18. Client: `owlet-tutk` (Rust only, no vendor library). Network: same LAN.

| Step | Result |
|---|---|
| Transcode key | Plain `Charlie is the d`. A LAN packet from the licensed Owlet app decodes with it; licence key mask is zero. |
| App packet vs Rust packet | The app's 88-byte connect request and the Rust request are equal in all fields other than the random ID. |
| LAN port | The camera does not answer on 32761 or on 63616 (the app's search port). It answers on the port its firmware bound at start (37567 in this run). `--port scan` finds it in about 4 s. |
| LAN search | 0x602, 200 bytes, device SDK version 0x04030406. |
| LAN connect | 0x601 type 1 -> 0x602 -> type 2 -> 0x402 -> 0x404 + 0x408. |
| Plain AV login | Refused. The camera sends DATA with dataType 1 and the text `recv dtls data!`. |
| DTLS-PSK | Handshake OK. Identity `AUTHPWD_admin`, key from SHA-256(password), cipher list `DEFAULT:@SECLEVEL=0`. |
| AV version | The camera sends version 0x0b (vendor 4.3.8 client: 0x0c). Receivers must not compare versions. |
| Video | H.264 Baseline 1920x1080, 15 frames/s. 299 frames in 20 s with the Owlet app closed. ffmpeg reports 0 decode errors. |
| RTSP | `owlet-tutk stream ... --out - \| ffmpeg -f h264 -i - -c copy -f rtsp ...` gives `h264,1920,1080,15/1` on MediaMTX. |

Command (secrets from the environment):

```
OWLET_TUTK_PASSWORD=... OWLET_TUTK_AUTHKEY=... owlet-tutk stream --uid <UID> \
  --ip <camera-ip> --port scan --security dtls --resend --out -
```

Not tested: audio output, two-way talk, IOCtrl commands other than start, P2P or relay.
The camera sent video after login in this run; it is not known if the start IOCtrl is necessary.
