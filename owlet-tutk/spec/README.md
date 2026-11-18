# Protocol notes

These files record the wire protocol that `owlet-tutk` implements. The data comes from static
analysis of the client libraries `libIOTCAPIs.so` and `libAVAPIs.so` (version 4.3.8, aarch64)
with Ghidra. The libraries and the decompiler output are not in this repository.

| File | Subject |
|---|---|
| [A_lan.md](A_lan.md) | Packet header, transcode rules, LAN search, LAN connect |
| [B_dispatch.md](B_dispatch.md) | Opcode table, device-side replies, session structure |
| [C_session_dtls.md](C_session_dtls.md) | Session DATA, ALIVE and CLOSE packets, DTLS-PSK channel |
| [D_av.md](D_av.md) | AV login, packet format, IOCtrl, frame transport, ACK |

## How to read the notes

- `name@00123456` is a function and its Ghidra address. The image base is `0x100000`.
- `iotc_all.c` and `av_all.c` are the decompiler output files. Line numbers that refer to them
  are only for a person who makes the same output again with the scripts in `../re/`.
- **OBSERVED** means the code shows the fact directly. **INFERRED** means a conclusion from the
  code. **UNKNOWN** means not resolved at the time of the analysis.

## Corrections from tests with real devices

The notes were written before the tests. Where a note and this list disagree, this list is correct.

| Subject | Result |
|---|---|
| Transcode key | The key is the 16 bytes `Charlie is the d`. A packet from the licensed vendor app decodes with this key. The licence key mask is zero for this app. |
| LAN port | The camera does not answer on 32761 or 63616. It answers on the UDP port that its firmware bound at start. The client finds it with `--port scan`. |
| Sweep rate | An idle Wi-Fi camera receives about 200 datagrams each second. A faster sweep loses probes. |
| LAN connect | The three-packet sequence in A_lan section 7 is correct. The device answers 0x402 with 0x404 and then sends 0x408 or 0x428. |
| AV security | The camera refuses a plain login. It replies with DATA of type 1 and the text `recv dtls data!`. DTLS-PSK is necessary. |
| DTLS | DTLS 1.2. Identity `AUTHPWD_<account>`. Key: SHA-256 of the password, cut at the first zero byte, zero-padded to 32 bytes. Cipher list `DEFAULT:@SECLEVEL=0`. |
| AV version | The camera sends version `0x0b`. The 4.3.8 client sends `0x0c`. A receiver must accept other versions. |
| Client source port | The vendor client sends stage 2 and all later packets from a different UDP port than the search. A device must follow the new address. |
| Resend mode | The vendor client and the camera use `resend = 1`. |
| Video | H.264 Baseline, 1920x1080, 15 frames each second. The camera sent video after login. It is not known if the start IOCtrl is necessary. |

Test records: [../evidence/](../evidence/).
