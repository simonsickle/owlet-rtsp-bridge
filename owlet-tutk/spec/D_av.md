# D. TUTK AV layer (libAVAPIs.so 4.3.8.0, aarch64) - client-side wire specification

Source: Ghidra decompiler output `av_all.c`. The file `av_all.c` does not contain the
`IKalayAV` virtual methods (addresses 0x1310bc to 0x133858) or the channel virtual methods.
These were decompiled again from the same Ghidra project into
`av_extra.c`.
Citations are `function@address`. `FUN_xxxxxxxx` names are Ghidra names.

Tags: **OBSERVED** = read directly in the decompiled code. **INFERRED** = a conclusion from
the code that is not a direct read (names, intent, the behaviour of the remote side).

Version string in `.rodata`: `4.3.8.0-0-gfd8c136-R1_openssl_android` (0x10ba98). OBSERVED.

## 0. General rules

| Item | Value | Evidence |
|---|---|---|
| Byte order | Little-endian for all multi-byte fields. All `*_Swap` functions are empty (`AVPacket_Header_Swap@0012c6fc`, `AVNewPacket_Header_Swap@0011cc44`, `IOFrame_ACK_Swap@0011cc48`, `AVFrame_Header_Swap@0011cc4c`, `AVFrameAck_*@0011cc50/54`, `AVFECHead_Swap@0011cc58`, `AVStatistic_Swap@0011cc5c`). `OpCodeBigEndianExchange@00122720` is a plain copy. | OBSERVED |
| AV protocol version sent by this library | u16 `0x000C` at offset 2 of each packet | OBSERVED (`assemblePackHead(...,0xc)`, `local_576 = 0xc`) |
| Maximum datagram that the receive thread reads | 0x56C (1388) bytes | OBSERVED `FUN_00133da8@00133da8` |
| Transport, plain mode | `IOTC_Session_Write(sid, buf, len, ch)`; `IOTC_Session_Read_Data_And_Datatype(sid, buf, len, timeout=0x14 ms, ch, &datatype)` | OBSERVED `FUN_00129328`, `FUN_001292bc@001292bc` |
| Transport, DTLS mode | `IOTC_sCHL_write` / `IOTC_sCHL_read` on the handle from `IOTC_sCHL_new(ctx, sid, ch)` | OBSERVED `FUN_00127138/00127140/0012715c` |
| Plain read that returns datatype 1 | The read returns -20195 (0xFFFFB11D). On a client this sets a flag and login fails with -20049. A server writes the 15 ASCII bytes `recv dtls data!` in reply. | OBSERVED `FUN_001292bc`, `FUN_00133da8` |
| One AV packet = one IOTC channel write | No stream framing in the AV layer | OBSERVED (all senders call the channel write one time for each packet) |

Fragment payload size is 1024 bytes (0x400). OBSERVED `FUN_00137704@00137704`, `avPutDataToIOFrameFifo@0012056c`.

### 0.1 Native layout of the start structures

The native code reads `account_or_identity`, `password_or_token` and `dtls_cipher_suites` as
**pointers**, not as inline character arrays. OBSERVED `avClientStartEx@0011bc60`,
JNI `Java_com_tutk_IOTC_AVAPIs_avClientStartEx@00113f6c` (sets `cb=0x40`, out `cb=0x20`).

`AVClientStartInConfig` (aarch64, 0x40 bytes):

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 4 | LE | cb | Must be >= 0x40, else -20000 | OBSERVED `avClientStartEx` |
| 0x04 | 4 | LE | iotc_session_id | IOTC SID | OBSERVED |
| 0x08 | 1 | - | iotc_channel_id | Must be < 0x20 | OBSERVED |
| 0x0C | 4 | LE | timeout_sec | Login timeout. 0 is rejected (-20000) in `FUN_0013187c` | OBSERVED |
| 0x10 | 8 | LE | account_or_identity | `const char *` | OBSERVED |
| 0x18 | 8 | LE | password_or_token | `const char *` | OBSERVED |
| 0x20 | 4 | LE | resend | 0 or 1 | OBSERVED |
| 0x24 | 4 | LE | security_mode | 0 simple, 1 DTLS, 2 auto. Value 3 makes a plain channel and records mode 3 | OBSERVED `IKalayAVNew@0013084c` |
| 0x28 | 4 | LE | auth_type | 0 password, 1 token. Value 2 with DTLS gives -20033 | OBSERVED |
| 0x2C | 4 | LE | sync_recv_data | Local behaviour only | OBSERVED |
| 0x30 | 8 | LE | dtls_cipher_suites | `const char *` or NULL | OBSERVED |
| 0x38 | 4 | LE | (name not in Java class) | Sent as byte at login payload +2N+0x20 | OBSERVED; name INFERRED: request_video_on_connect |
| 0x3C | 4 | LE | (name not in Java class) | Sent as byte at login payload +2N+0x21 | OBSERVED; name INFERRED: request_audio_on_connect |

`AVClientStartOutConfig` (0x20 bytes): `+0 cb (>=0x20)`, `+4 server_type`, `+8 resend`,
`+0xC two_way_streaming`, `+0x10 sync_recv_data`, `+0x14 security_mode (1 if DTLS is in use)`,
`+0x18`, `+0x1C` = results for the two fields at in+0x38/in+0x3C. OBSERVED
`avClientStartEx`, `avClientStart_inner@0011a944`, `FUN_0013187c@0013187c`.

## 1. Login handshake

Call chain: `avClientStartEx@0011bc60` -> `avClientStart_inner@0011a944` ->
`FUN_00119008@00119008` (slot allocation, `IKalayAVNew@0013084c`, `IOTC_Session_Channel_ON`)
-> virtual method +8 = `FUN_0013187c@0013187c` (the client login).

### 1.1 Security mode selection

| Step | Rule | Evidence |
|---|---|---|
| `IKalayAVNew` mode 0 | `IOTCChannelNew` (plain) | OBSERVED |
| `IKalayAVNew` mode 1 | `ClientDTLSChannelNew@00126f74`. Failure is returned | OBSERVED |
| `IKalayAVNew` mode 2 (auto) | `ClientDTLSChannelNew`. If it returns -21334 (0xFFFFACAA, from `IOTC_sCHL_CTX_new` = -50005), use the plain channel | OBSERVED |
| `FUN_0013187c`, mode 1 | If `IOTC_Get_Remote_ProtocolVersion() < 0x17`: return -20039 | OBSERVED |
| `FUN_0013187c`, mode 2 | If remote protocol version < 0x17: replace the DTLS channel with a plain channel, mode becomes 0 | OBSERVED |
| Channel connect (virtual +0x10) | Plain: `IOTC_Session_Channel_ON`, returns 0. DTLS: `IOTC_Session_Channel_ON`, `IOTC_sCHL_new`, `IOTC_sCHL_set_dtls_connect_timeout`, `IOTC_sCHL_connect` | OBSERVED `FUN_00129334`, `FUN_0012715c@0012715c` |
| Connect result -50001, mode 2, version >= 0x17 | Remove PSK callback, shut down, swap to plain channel (`FUN_00136ec4`), mode becomes 0, continue with plain login | OBSERVED |
| Connect result -50001, mode 1 | Return -20039 | OBSERVED |
| Connect result -50002 | Return -20040 | OBSERVED |
| Connect result -50003 | Return -20041 | OBSERVED |
| Connect result -50006 or -13 | Return -20011 | OBSERVED |
| Time used by the connect | Subtracted from `timeout_sec`. If none remains: -20011 | OBSERVED |

The login packets of section 1.3 are sent through the selected channel. In DTLS mode they are
DTLS application data. The account and the password are in the login packet in the two modes.
OBSERVED (one code path).

### 1.2 DTLS PSK

| Item | Value | Evidence |
|---|---|---|
| PSK identity | ASCII `"AUTHPWD_" + account` (auth_type 0) or `"AUTHTKN_" + account` (auth_type 1). Format string `"%s%s"`, buffer 0x78 bytes | OBSERVED `IKalayAVNew@0013084c`, strings 0x10b7aa, 0x10b7fb, 0x10b4fe |
| PSK | `TUTK3rdSHA256(password, strlen(password))` (32 bytes), then copied with `strncpy(dst, digest, 0x20)` two times | OBSERVED `IKalayAVNew`, `ClientDTLSChannelNew@00126f74` |
| PSK quirk | Because of `strncpy`, the PSK is the digest **up to, not including, the first 0x00 byte**, then zero bytes up to 32 | OBSERVED (code), effect INFERRED |
| PSK length given to the DTLS stack | Always 0x20 | OBSERVED `FUN_001272a0@001272a0` (returns 0x20) |
| Identity given to the DTLS stack | `strcpy` of the identity string | OBSERVED `FUN_001272a0` |
| Server side | Callback receives the identity, finds the password or token through the app callback, uses `SHA256` with the same `strncpy` rule | OBSERVED `FUN_00130f00@00130f00` |
| Base64 | Not used in the AV login or PSK path | OBSERVED (no call in these functions) |
| Cipher list | `IOTC_sCHL_CTX_set_cipher_list(ctx, dtls_cipher_suites)` only if the pointer is not NULL | OBSERVED |
| Account limits, mode 1 | account length 1..0x78, password length 1..0x401 | OBSERVED `FUN_0013187c` |

The DTLS record transport (`IOTC_sCHL_*`) is in libIOTCAPIs. It is not part of this document.

### 1.3 Login request packets (client to server)

Field width `N` for the account and password fields:

| Condition | N | Evidence |
|---|---|---|
| `IOTC_Session_Check_Ex` mode byte (struct +4) == 1 (INFERRED: relay) and remote IOTC version (struct +0x54) > 0x010D04FF | 0x101 | OBSERVED |
| mode != 1 and `IOTC_Get_Remote_ProtocolVersion() > 8` | 0x101 | OBSERVED |
| else | 0x10 | OBSERVED |

The server side of this library reads with N = 0x101 when the client AV version is >= 3
(`FUN_0011dda0@0011dda0`, field `+0x88 = 0x10100000101`). OBSERVED.

Common 24-byte header (`assemblePackHead@001183e4` clears 24 bytes):

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 1 | - | type | 0x00 (control) | OBSERVED |
| 0x01 | 1 | - | subtype | 0x00 = login, 0x20 = login variant 2 | OBSERVED |
| 0x02 | 2 | LE | version | 0x000C | OBSERVED |
| 0x04 | 12 | - | zero | In the response, +4 is the server type | OBSERVED |
| 0x10 | 2 | LE | payload_size | Packet A: 2N+0x20. Packet B: 2N+0x22 | OBSERVED |
| 0x12 | 1 | - | has_variant2 | Packet A: 1 if resend == 1, else 0. Packet B: 0 | OBSERVED |
| 0x13 | 1 | - | zero | | OBSERVED |
| 0x14 | 4 | LE | nonce | Random, not zero. Packet A = r, packet B = r+1. Kept for all retransmissions. The server uses it to ignore a different second login | OBSERVED `FUN_0013187c`, `FUN_0011dda0` |

Payload (starts at packet offset 0x18):

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0 | N | - | account | Bytes of the C string, zero fill. No terminator is necessary if full | OBSERVED |
| N | N | - | password | auth_type 0: password string, zero fill. auth_type 1 (see below): raw SHA-256 of the token, copied up to the first 0x00 byte | OBSERVED |
| 2N | 1 | - | resend | 0 or 1 | OBSERVED |
| 2N+1 | 3 | - | zero | | OBSERVED |
| 2N+4 | 4 | LE | opcode_count | 4 | OBSERVED `GetOpCodeSupportCurrent@00122840` |
| 2N+8 | 4 | LE | opcode_word[0] | 0x001F07FB | OBSERVED (0x10c090) |
| 2N+0xC | 4 | LE | opcode_word[1] | 0 | OBSERVED |
| 2N+0x10 | 4 | LE | opcode_word[2] | 0 | OBSERVED |
| 2N+0x14 | 4 | LE | opcode_word[3] | 0x00030000 | OBSERVED |
| 2N+0x18 | 1 | - | auth_type | 0, 1 or 2 | OBSERVED |
| 2N+0x19 | 3 | - | zero | | OBSERVED |
| 2N+0x1C | 1 | - | two_way | Always 1 from `avClientStartEx` (`local_38 = 1`) | OBSERVED |
| 2N+0x1D | 3 | - | zero | | OBSERVED |
| 2N+0x20 | 1 | - | in+0x38 | Packet B only | OBSERVED |
| 2N+0x21 | 1 | - | in+0x3C | Packet B only | OBSERVED |

Packet A: type 0x00, subtype 0x00, total length 2N+0x38 (570 bytes for N = 0x101).
Packet B: type 0x00, subtype 0x20, total length 2N+0x3A (572 bytes). Packet B is sent only if
resend == 1, immediately after packet A. OBSERVED.

Token hash rule: the password field is `SHA256(token)` only if auth_type == 1 and
((mode byte == 1 and remote IOTC version > 0x030108FF) or (mode byte != 1 and remote protocol
version > 0x16)). Limits: token length < 0x401, account length < 0x78; else -20024. OBSERVED.
For auth_type 0 and 1 without the hash, a string longer than N-1 gives -20024. OBSERVED.

Retransmission: a 50 ms loop. The packets are sent again each `interval/50` loop turns.
`interval` = 400 ms (mode byte 1), 50 ms (mode byte 2, INFERRED: LAN), else 100 ms.
Loop count = `remaining_sec*1000/50 + 2`. Timeout result: -20011. OBSERVED.

### 1.4 How the server selects the reply (server code of this library)

`FUN_0011dda0@0011dda0`, called from `_doAVTransNew@0011cda8` for subtype 0x00 and 0x20. OBSERVED.

| Request | Client version (u16 at +2) | Reply subtype |
|---|---|---|
| 0x20 | >= 9 | 0x21 |
| 0x20 | < 9 | no reply |
| 0x00 with byte 0x12 != 0 | >= 9 | no reply (the server waits for packet B) |
| 0x00 with byte 0x12 == 0 | >= 10 | 0x21 |
| 0x00 | 2..9 | 0x14 |
| 0x00 | < 2 | 0x01 |

Reply 0x21 from a server makes the two sides use the "new" transport (section 2 and later).
The version of the camera firmware library is UNKNOWN. A reply 0x01 or 0x14 selects the
legacy transport (section 7).

### 1.5 Login response (server to client)

Subtype 0x21 parser: `_doAVTransNew@0011cda8` (branch `uVar22 == 0x21`). Subtype 0x01/0x14
parser: `FUN_001346b0@001346b0`. Builder: `FUN_0011dda0`. OBSERVED.

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 1 | - | type | 0x00 | OBSERVED |
| 0x01 | 1 | - | subtype | 0x21, 0x14 or 0x01 | OBSERVED |
| 0x02 | 2 | LE | version | Server AV version | OBSERVED |
| 0x04 | 4 | LE | server_type | Copied to out config +4 | OBSERVED |
| 0x08 | 8 | - | copy of request bytes 8..15 | | OBSERVED |
| 0x10 | 2 | LE | payload_size | 0x24, or 0x26 (reply to 0x20 from a client version >= 12) | OBSERVED |
| 0x12 | 6 | - | copy of request bytes 0x12..0x17 | Contains the nonce | OBSERVED |
| 0x18 | 1 | - | result | 0 = accepted. 3 = rejected: client returns -20009. Other values: the client waits | OBSERVED `FUN_0013187c` |
| 0x1C | 4 | - | firmware version | Byte-reversed `g_stFirmVer`. Client does not read it | OBSERVED builder |
| 0x20 | 1 | - | resend | Accepted resend mode. The client uses this value | OBSERVED |
| 0x24 | 4 | LE | opcode_count | Client uses min(count, 4) | OBSERVED |
| 0x28 | 16 | LE | opcode_word[0..3] | Server capability bits | OBSERVED |
| 0x38 | 1 | - | two_way capability | Read if server version > 9 | OBSERVED |
| 0x3C | 1 | - | result for in+0x38 | Read if server version > 11 | OBSERVED |
| 0x3D | 1 | - | result for in+0x3C | Read if server version > 11 | OBSERVED |

Total length 0x3C or 0x3E. The client does not check the nonce. OBSERVED.
Reply 0x14: the same offsets up to 0x38 are used; `resend` at 0x20, opcodes at 0x24. Reply 0x01:
no opcode list, the client uses `GetOpCodeSupportVer1` values. OBSERVED `FUN_001346b0`.

After acceptance (result 0) the client: sets the close callback, starts `threadBBR@0012039c`
if the reply was 0x21, and sets "wrapper mode" (object +0x1F7C = 1) if the accepted resend
value is not 0. `avClientStart_inner` then stores the client buffer limit locally
(`FUN_0013256c@0013256c` case 5). No more packets are necessary for login. OBSERVED.

### 1.6 Error codes (signed 32-bit)

Values are OBSERVED. Names are INFERRED from the public TUTK SDK headers.

| Value | Name | Where |
|---|---|---|
| -20000 | AV_ER_INVALID_ARG | Many |
| -20001 | AV_ER_BUFPARA_MAXSIZE_INSUFF | Frame larger than the caller buffer |
| -20002 | AV_ER_EXCEED_MAX_CHANNEL | `FUN_00119008` |
| -20003 | AV_ER_MEM_INSUFF | Allocation |
| -20004 | AV_ER_FAIL_CREATE_THREAD | `FUN_0013187c` |
| -20006 | AV_ER_EXCEED_MAX_SIZE | Buffer full |
| -20009 | AV_ER_WRONG_VIEWACCorPWD | Login result 3 |
| -20010 | AV_ER_INVALID_SID | IOTC -14 |
| -20011 | AV_ER_TIMEOUT | Login timeout |
| -20012 | AV_ER_DATA_NOREADY | No complete frame |
| -20013 | AV_ER_INCOMPLETE_FRAME | `FUN_001216f8` |
| -20014 | AV_ER_LOSED_THIS_FRAME | `FUN_001216f8` |
| -20015 | AV_ER_SESSION_CLOSE_BY_REMOTE | IOTC -22 |
| -20016 | AV_ER_REMOTE_TIMEOUT_DISCONNECT | IOTC -23 |
| -20017 / -20018 | AV_ER_SERVER_EXIT / AV_ER_CLIENT_EXIT | Stop flags |
| -20019 | AV_ER_NOT_INITIALIZED | |
| -20021 / -20022 | SENDIOCTRL_ALREADY_CALLED / SENDIOCTRL_EXIT | `avSendIOCtrlFrame` |
| -20024 | AV_ER_WRONG_ACCPWD_LENGTH | Login field too long |
| -20027 | AV_ER_IOTC_CHANNEL_IN_USED | `FUN_00119008` |
| -20033 | AV_ER_NOT_SUPPORT | auth_type 2 with DTLS |
| -20035 | AV_ER_FAIL_CREATE_DTLS | `IOTC_sCHL_new` returned NULL |
| -20039 | AV_ER_REMOTE_NOT_SUPPORT_DTLS | See 1.1 |
| -20040 | AV_ER_DTLS_WRONG_PWD | sCHL -50002 |
| -20041 | AV_ER_DTLS_AUTH_FAIL | sCHL -50003 |
| -20049 | (name UNKNOWN) | Plain client received DTLS-typed data during login |

## 2. New transport: packet format

Used when the object field +0x1F84 is 1 (reply 0x21). Dispatcher: `_doAVTransNew@0011cda8`.
Senders: `_sendAVFrameFifo@0011f000`, `_sendIOorIOInnerFrame@0011ff28`,
`_resendAVFrameFifo@0011f86c`, `FUN_0011e9fc@0011e9fc`.

### 2.1 Outer header (8 bytes, or 16 bytes with the extension)

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0 | 1 | - | type | 0x00 control/IOCtrl, 0x03..0x08 media data, 0x09 ACK, 0x0A probe, 0x0B statistics, 0x0C wrapper (FEC head follows) | OBSERVED |
| 1 | 1 | - | flags | type 0x00: the subtype (0x70, 0x10, 0x72, 0x00, 0x20, 0x21). Other types: bit 0 (0x01) last fragment of a frame, bit 2 (0x04) "send an ACK now", bit 3 (0x08) 8-byte extension present | OBSERVED |
| 2 | 2 | LE | version | 0x000C | OBSERVED |
| 4 | 2 | LE | tx_seq | Counter for each transmitted packet (object +0x1F30), starts at 0 | OBSERVED |
| 6 | 2 | - | not set | Stack bytes that the senders do not write. Receivers do not read it. Send 0 | OBSERVED |

Extension (present if flags bit 3 is set; only on types 0x03..0x08, 0x0A and 0x0C with media):

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 8 | 2 | LE | ts_ms | Low 16 bits of the sender clock in ms | OBSERVED `_sendAVFrameFifo` |
| 10 | 2 | LE | rtt_ms | Sender RTT estimate (+0x192C) | OBSERVED |
| 12 | 4 | - | not set | | OBSERVED |

The sender adds the extension when 200 ms or more passed since the last one. OBSERVED.

### 2.2 FEC head (8 bytes, only when type == 0x0C)

Position: offset 8, or offset 16 if the extension is present. OBSERVED `_doAVTransNew`.

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0 | 2 | LE | group_no | FEC group number (+0x2078) | OBSERVED `_sendAVFrameFifo` |
| 2 | 1 | - | index | Index in the group (+0x207A) | OBSERVED |
| 3 | 1 | - | group_size | Data packets in a group (+0x207B, initial 0x14) | OBSERVED |
| 4 | 1 | - | fec_on | +0x207C. 0 at start (no parity packets) | OBSERVED |
| 5 | 3 | - | zero | | OBSERVED |

For IOCtrl packets in wrapper mode the 8 bytes are all zero. OBSERVED `avPutDataToIOFrameFifo`.

### 2.3 Inner header (20 bytes) = AVFrame header

Position: offset 8 (no extension, no wrapper), 16 (extension or wrapper), 24 (the two).
Builders: `avPutDataToAVFrameFifo@0012076c`, `avPutDataToIOFrameFifo@0012056c`,
fields completed in `_sendAVFrameFifo`. Reader: `FUN_0011d810@0011d810`.

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0 | 1 | - | type | Media: 3 audio, 5 video key frame, 7 video other frame. 4, 6, 8 = retransmission of 3, 5, 7. Control: 0. FEC parity: 0x0C | OBSERVED (`FUN_001329b4`, `FUN_00136f7c`, `_resendAVFrameFifo`); "key frame" = frame-info byte 2 == 1 |
| 1 | 1 | - | flag / subtype | Media: bit 0 = last fragment. Control: subtype 0x70 (user IOCtrl), 0x10 (inner control), 0x72 (IOCtrl cancel) | OBSERVED |
| 2 | 2 | LE | packet_no | Media: data packet counter (+0x1F32), starts at 0, one per packet. Control: IO packet counter (+0x1F34), a different number space | OBSERVED |
| 4 | 2 | LE | frag_count | Number of fragments of this frame | OBSERVED |
| 6 | 2 | LE | frag_pos or info_len | If flag bit 0 == 0: fragment position (0-based). If flag bit 0 == 1 (media): frame-info length; the position is `frag_count-1` | OBSERVED `FUN_0011d810`, `avPutDataToAVFrameFifo` |
| 8 | 2 | LE | payload_len | Bytes that follow this header (`get_AVFrame_Payload@0011cc64` returns this field) | OBSERVED |
| 10 | 2 | LE | checksum | 0 unless wrapper mode. See 3.4 | OBSERVED |
| 12 | 4 | LE | frame_no | Media: counter for all media frames (+0x1F54), first value 0. Control: IOCtrl frame counter (+0x1F68), first value 0 | OBSERVED |
| 16 | 4 | LE | stream_index | Media: frame counter for the stream class (audio counter for type 3, video counter for types 5/7). Control: 0 | OBSERVED |

The outer type byte equals the inner type byte, except in wrapper mode where the outer type
is 0x0C. For control packets the outer bytes 0..1 equal the inner bytes 0..1. OBSERVED.

## 3. Media frame transport (server to client)

### 3.1 Fragmentation (sender, `FUN_00137704@00137704`)

- `frag_count = (data_len + info_len + 0x3FF) >> 10`. OBSERVED.
- Fragments 0..count-2 contain frame data only, 1024 bytes each. The fragment before the last
  can be shorter (it then contains the end of the data). OBSERVED.
- The last fragment (position count-1) contains the remaining data bytes and then the complete
  frame-info block. Its flag bit 0 is 1 and its field +6 is `info_len`. OBSERVED.
- One frame uses one `frame_no`. `packet_no` increases by 1 for each fragment. OBSERVED.

### 3.2 Reassembly (receiver)

Functions: `FUN_0011d810@0011d810` (accept), `FUN_00121340@00121340`,
`FUN_0012140c@0012140c` (complete frames), `FUN_001216f8@001216f8` (copy to the caller),
`avRecvData_new@00121140`, virtual +0x38 `FUN_00132d78@00132d78`.

1. Class of a packet: types 3,4 -> class 3 (audio); 5,6 -> class 5; 7,8 -> class 7 (video). OBSERVED.
2. Key = (`frame_no`, position). A second copy of the same key is ignored and counted as a duplicate. OBSERVED.
3. A frame is complete when `frag_count` packets with that `frame_no` are present. OBSERVED.
4. Output = payloads in position order. From the last fragment, the last `info_len` bytes are
   the frame info, the bytes before them are frame data. OBSERVED `FUN_001216f8`.
5. `avRecvFrameData2@0011ae7c` reads class 5/7 frames, `avRecvAudioData@0011af9c` reads class 3
   frames. OBSERVED.
6. Delivery order: the expected frame is `last_frame_no + 1` (+0x1F58, initial 0xFFFFFFFF).
   resend == 1: only this frame is delivered, when complete. resend == 0: if packets of frame
   `expected+1` are present and the expected frame is not complete, the expected frame is
   reported as lost (-20014) or incomplete (-20013). OBSERVED `FUN_0012140c`, `FUN_001216f8`.
7. All 16-bit and 32-bit number comparisons use wrap-around (serial number) arithmetic with
   windows 0x8000 and 0x80000000. OBSERVED.
8. If the buffered bytes are at or above the client buffer limit (+0x2288), packets that are
   not newer than the highest packet number are dropped. OBSERVED `FUN_0011d810`.

Frame-info content (codec, flags, timestamp) is application data. The AV layer reads only
byte 2 of it on the sender (value 1 selects type 5). OBSERVED `FUN_00136f7c@00136f7c`.

### 3.3 FEC (Reed-Solomon)

- Parity is carried in wrapper packets with inner type 0x0C. Data packets in a wrapper are
  not changed (systematic code). A receiver can ignore the parity packets. OBSERVED
  `_doAVTransNew` (data packets go to `FUN_0011d810` with no decode step).
- Recovery: `FUN_0011dccc@0011dccc` -> `avCheckDecode@00128cb8` -> `reed_solomon_new`,
  `reed_solomon_decode` with block size 0x414 (20-byte inner header + 1024 payload bytes,
  zero padded). Recovered packets are accepted only if `payload_len` is 1..1024 and the
  checksum is correct. OBSERVED.
- FEC is not mandatory. Wrapper mode is set on the client when accepted resend != 0
  (`FUN_0013187c`), and on the server when resend != 0 and one more local condition is true
  (`FUN_001310bc@001310bc`). Parity is produced only when the sender flag +0x207C is not 0,
  which the sender sets from the loss rate reported in type 0x0B packets. OBSERVED.
- A receiver MUST parse type 0x0C packets (skip the FEC head) even if it does not decode
  parity. INFERRED from the above.

### 3.4 Checksum (`avCalculate_checksum@001286b0`)

16-bit sum (mod 65536) of all payload bytes plus the inner header bytes 0..9 and 12..19, with
the checksum field counted as zero. OBSERVED (vector code; header byte 11 is not added, it is
the high byte of the checksum field). Written only in wrapper mode. Verified only for packets
recovered by FEC. A receiver that does not decode parity can ignore it. OBSERVED.

### 3.5 Encryption

No AES operation exists on media or IOCtrl data in this library. `TUTK3rdAESEncrypt` and
`TUTK3rdAESDecrypt` are called only in the push-notification code (`NewPushInterface@00139de4`,
`FUN_0013a40c@0013a40c`). `avCheckDecode` is FEC decode, not decryption. `FUN_0012905c` is a
GF(256) table operation for Reed-Solomon. Confidentiality comes only from DTLS. OBSERVED.

## 4. IOCtrl framing (new transport)

Functions: `avSendIOCtrl@00118b94` -> virtual +0x40 `FUN_00133420` -> `avSendIOCtrlFrame@001208d0`
-> `avPutDataToIOFrameFifo@0012056c` -> `_sendIOorIOInnerFrame@0011ff28`.
Receive: `_doAVTransNew` -> `FUN_0011d810` (branch `param_4 < 2`) -> `FUN_0011e1dc@0011e1dc`
-> `avRecvIOCtrl_new@00121978`.

### 4.1 Packet

`[outer 8][FEC head 8, only in wrapper mode][inner 20][payload]`

| Part | Value | Evidence |
|---|---|---|
| Outer, plain mode | `00 70 0C 00 <tx_seq u16> 00 00` (subtype 0x10 for inner control) | OBSERVED |
| Outer, wrapper mode (accepted resend != 0) | `0C 00 0C 00 <tx_seq u16> 00 00`, then 8 zero bytes | OBSERVED |
| Inner +0 | 0x00 | OBSERVED |
| Inner +1 | 0x70 user IOCtrl; 0x10 inner control; 0x72 cancel | OBSERVED |
| Inner +2 | IO packet number, starts at 0, +1 for each fragment | OBSERVED |
| Inner +4 | Fragment count = `(len + 0x403) >> 10` (1 if there is no data) | OBSERVED |
| Inner +6 | Fragment position | OBSERVED |
| Inner +8 | Payload length. Fragment 0: `data_bytes + 4` | OBSERVED |
| Inner +12 | IOCtrl frame number: starts at 0, +1 for each IOCtrl frame sent | OBSERVED `__getIOCtrlFrmNo@0012c718` |
| Inner +16 | 0 | OBSERVED |
| Payload, fragment 0 | u32 LE IOCtrl type, then up to 0x3FC data bytes | OBSERVED |
| Payload, fragment n > 0 | Up to 0x400 data bytes | OBSERVED |

To start video, send one IOCtrl frame with the application type (0x1FF) and the application
payload in this framing. The AV layer adds no other field.

### 4.2 Receiver rules

- IO frames must arrive in frame-number order: expected = last + 1 (+0x1F6C, initial
  0xFFFFFFFF). A frame with an older number is deleted. OBSERVED `FUN_0011e1dc`.
- Subtype 0x70 with position 0 and type < 0x100, or subtype 0x10: inner control. It is
  handled in `FUN_0011e1dc` and not given to the application. OBSERVED.
- `avRecvIOCtrl_new` returns the u32 type and the data. Frames with type < 0x100 are dropped.
  It polls each 10 ms. Timeout: -20011. OBSERVED.
- After an IO frame is accepted, the receiver sets "ACK now". OBSERVED `_doAVTransNew`.

### 4.3 Acknowledgement and retransmission of IOCtrl

- The ACK is the type 0x09 packet (section 5.1), field `io_ack` (+12) = packet number of the
  last fragment of the last IO frame accepted in order. No separate IOCtrl ACK packet exists
  in the new transport. OBSERVED `FUN_0011e9fc`, `FUN_0011e1dc`.
- The sender deletes IO packets with number <= `io_ack`. `avSendIOCtrlFrame` returns when
  `io_ack + 1` is at or after its next IO packet number. It polls each 5 ms and has no timeout
  of its own. OBSERVED `_doAVTransNew` type 9 branch, `avSendIOCtrlFrame`.
- IO retransmission timer: initial 50 ms (+0x1F8E), doubled after each expiry. OBSERVED
  `_resendAVFrameFifo`, `FUN_001339f8` (`+0x1F8C = 0x003200C8`).

### 4.4 Inner control opcodes (subtype 0x10, payload = u32 opcode + body)

| Opcode | Direction | Body | Meaning | Evidence |
|---|---|---|---|---|
| 0x22 | server -> client | u16 id, u16 packet_no, u32 frame_no | Reset buffer. The client moves its receive state forward and replies 0x23 | OBSERVED `_avNewServResetBuffer@00121ff8`, `FUN_0011e1dc` |
| 0x23 | client -> server | u16 id, u16 ack_base (+0x1F46), u32 last_frame_no (+0x1F58) | Reply to 0x22 | OBSERVED |
| 0x24 | client -> server | u16 id, u16 ack_base, u32 0 | Clean buffer request (`avClientCleanBuf`) | OBSERVED `avClientCleanBufNew@00121ce8` |
| 0x25 | server -> client | u16 id, u16 packet_no, u32 frame_no | Reply to 0x24. The client moves its receive state as for 0x22 | OBSERVED |
| 0x26 / 0x27 | | | Token request / reply | OBSERVED names of handlers |
| 0x28 / 0x29 | | | Token delete request / reply | OBSERVED |
| 0x30 / 0x31 | | | Identity array request / reply | OBSERVED |
| 0x32 / 0x33 | | | Ability request / reply | OBSERVED |
| 0x34 / 0x35 | | | Change password request / reply | OBSERVED |
| 0x36 / 0x37, 0x38 / 0x39 | | | JSON set / JSON request and replies | OBSERVED |
| 0x40 | server -> client | u32 kb | Client buffer limit. Client sets limit = `kb * 0xA00 & 0x7FFFFE00` unless the app set one | OBSERVED `_avSetClientMaxBufSize@00122698`, `FUN_0011e1dc` |

0x22 handling detail: a repeated `id` (equal to the stored +0x1FA4) is ignored and not answered.
For a new `id`: highest/lowest packet markers are set to `packet_no` if it is newer,
`last_frame_no` is set to `frame_no` if it is newer, buffered packets up to these numbers are
deleted. OBSERVED.

`avSendIOCtrlExit` (`FUN_00133748`) and `avClientStop` (`FUN_00132444`) send no AV packet.
A cancel of a blocked `avSendIOCtrl` sends subtype 0x72 (`FUN_00120bd0@00120bd0`). OBSERVED.
Opcode 0xFF (`IOTYPE_INNER_SND_DATA_DELAY`) was not found as a wire constant in the new
transport. UNKNOWN (see section 8).

## 5. ACK, probe and statistics packets (new transport)

### 5.1 Type 0x09: ACK (receiver -> sender), `FUN_0011e9fc@0011e9fc`

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0 | 4 | LE | 0x000C0009 | type 9, flags 0, version 0xC | OBSERVED |
| 4 | 2 | LE | tx_seq | | OBSERVED |
| 6 | 2 | - | not set | | OBSERVED |
| 8 | 2 | LE | ack_base | The sender deletes all media packets with packet_no <= ack_base | OBSERVED (sender side in `_doAVTransNew`) |
| 10 | 2 | LE | ack_max | Highest media packet number received. If the lost list was cut: highest number in the list | OBSERVED |
| 12 | 2 | LE | io_ack | See 4.3 (initial 0xFFFF) | OBSERVED |
| 14 | 2 | LE | lost_count | Number of entries in the lost list | OBSERVED |
| 16 | 2 | LE | clean_flag | 1 while a clean-buffer request (0x24) waits for 0x25 | OBSERVED |
| 18 | 2 | LE | ack_seq | Counter of ACK packets (+0x1F36) | OBSERVED |
| 20 | 2 | LE | ts_ms | Low 16 bits of the clock in ms | OBSERVED |
| 22 | 2*n | LE | lost[i] | `lost_packet_no - ack_base` (u16) for each missing packet | OBSERVED |

Length: 0x18 if `lost_count == 0`; else `2*lost_count + 0x16`. At most (0x500-0x10)/2 entries. OBSERVED.

Rules of the original receiver (OBSERVED):
- If no packet is missing: `ack_base` = the `ack_max` of the ACK before this one; `ack_max` = highest received.
- If packets are missing: `ack_base` = the newer of (packet number of the last packet of the
  last completed frame, the last `ack_base` sent).
- Missing packets are found only when resend != 0: on a jump of the packet number, each number
  between is put in the lost list; an entry is removed when the packet arrives (`FUN_0011d810`).
- When sent: the 10 ms sender thread calls it (resend != 0), or it is called after each
  control packet (resend == 0). It sends if "ACK now" is set (flag bit 2 received, or an IO
  frame was accepted), or 100 ms passed since the last ACK and new packets arrived. With no new
  packets, it sends again after RTT/2 of silence.

Sender use (OBSERVED `_doAVTransNew`): delete packets <= `ack_base`; delete IO packets <=
`io_ack`; packets in the lost list are marked for retransmission (type 3->4, 5->6, 7->8) if
they are old enough; other packets up to `ack_max` count as delivered; `OnACK@0012620c` (BBR).

A simpler rule that is consistent with the sender code (INFERRED): `ack_base` = highest number
with all packets up to it received, `ack_max` = highest received, list = holes between.

### 5.2 Type 0x0A: probe, and type 0x0B: statistics

Type 0x0A (16 bytes), sent by a media sender each 200 ms or more when resend == 1:
`0A 08 0C 00 <tx_seq u16> <2 not set> <ts_ms u16> <rtt_ms u16> <4 not set>`. OBSERVED `_sendAVFrameFifo`.

Type 0x0B (20 bytes), the reply to each packet that has flags bit 3 (types 3..8 and 0x0A) when
resend != 0. It is queued and sent by the sender thread. OBSERVED `_doAVTransNew`:

| Offset | Size | Endian | Field | Meaning |
|---|---|---|---|---|
| 0 | 2 | LE | 0x000B | type 0x0B, flags 0 |
| 2 | 2 | LE | 0x000C | version |
| 4 | 2 | LE | 0 | |
| 6 | 2 | - | not set | |
| 8 | 2 | LE | echo_ts | Copy of `ts_ms` from the extension of the packet |
| 10 | 2 | LE | seq_delta | `tx_seq(this packet) - tx_seq(packet of the last report)` |
| 12 | 2 | LE | recv_count | Packets received since the last report |
| 14 | 2 | LE | loss_pct | `100 - recv_count*100/seq_delta` if `recv_count <= seq_delta`, else 0 |
| 16 | 2 | LE | dup_pct | Duplicates*100/seq_delta |
| 18 | 2 | LE | old_pct | Out-of-window packets*100/seq_delta |

The sender computes RTT = `now_ms16 - echo_ts`, uses `loss_pct` to set the FEC group size, and
sets its retransmission timer from the RTT (range 200..30000 ms). OBSERVED.
Media retransmission timer: `max(+0x1F8C, RTT) + 100` ms, +0x1F8C initial 200 ms, doubled on
expiry up to 30000. OBSERVED `_resendAVFrameFifo`.

### 5.3 Periodic messages

| Message | Condition | Interval | Evidence |
|---|---|---|---|
| Login A (and B) | Until a reply | 400 / 100 / 50 ms (relay / other / LAN) | OBSERVED |
| ACK 0x09 | resend != 0 | 100 ms when packets arrive; at once on flag bit 2 or IO frame; RTT/2 when idle | OBSERVED |
| ACK 0x09 | resend == 0 | Only after a control packet is processed, with the same 100 ms gate | OBSERVED |
| Probe 0x0A | resend == 1, from each side that runs the sender thread | >= 200 ms | OBSERVED |
| Statistics 0x0B | resend != 0 | One for each received packet with flags bit 3 | OBSERVED |
| Sender thread tick | New transport | 10 ms loop, minimum 5 ms between sends | OBSERVED `threadBBR`, `AVAPI_BBR_DoSend@00120110` |

No AV-layer keep-alive exists when resend == 0. Session keep-alive is an IOTC-layer function. OBSERVED / INFERRED.

`AVFrameAck_*`, `Statistical_Data_Swap`, `Statistical_ClientData_Swap`, `AVStatistic_Swap` are
empty functions. `_avCheckResendRequest@0012d3dc` and the `Statistical_*` data belong to the
legacy transport (section 7). OBSERVED.

## 6. Minimum viable client (LAN)

Preconditions: an IOTC session and channel (other sections), remote protocol version known.

Smallest sequence, plain channel, resend == 0 (all OBSERVED in the code paths above; that the
camera accepts it is INFERRED):

1. `IOTC_Session_Channel_ON(sid, ch)`.
2. Send login packet A (section 1.3) with `resend = 0`, byte 0x12 = 0, N = 0x101, auth_type 0,
   opcode words `4, 0x001F07FB, 0, 0, 0x00030000`. Repeat each 50 ms (LAN).
3. Receive type 0x00 subtype 0x21 (or 0x14 / 0x01: legacy, section 7). Check byte 0x18 == 0.
   Read byte 0x20 (accepted resend).
4. Send the start-video IOCtrl: outer `00 70 0C 00 seq 00 00`, inner header with packet_no 0,
   frag_count 1, pos 0, payload_len = 4 + n, frame_no 0, then u32 type and n data bytes.
   Send it again (50 ms, then doubled) until a type 0x09 packet has `io_ack` == its packet number.
5. For each control packet received (inner type 0): accept it in frame-number order, give
   type >= 0x100 to the application, handle 0x22 (reply 0x23) and 0x40, then send a type 0x09
   ACK with `io_ack` set.
6. For each media packet (outer type 3..8, or 0x0C with inner type 3..8): skip the extension
   (flags bit 3) and the FEC head (type 0x0C), parse the inner header, reassemble by
   (`frame_no`, position), split the frame info from the last fragment. Ignore inner type 0x0C
   (parity) and types 0x0A / 0x0B.

If DTLS is necessary (security_mode 1, or the camera refuses plain): do the PSK handshake of
section 1.2 first, then steps 2 to 6 inside DTLS.

Features that the client can decline:

| Feature | How | Effect | Evidence |
|---|---|---|---|
| Resend | Login `resend = 0`; do not send packet B | The server sets its resend to 0 and replies resend 0. No lost list, no 0x0A/0x0B, no wrapper mode on the client. Lost fragments make lost frames | OBSERVED `FUN_0011dda0`, `FUN_0013187c` |
| FEC | No capability bit was found for it. With resend 0 the wrapper mode is not set. With resend 1, parity can be ignored | See 3.3 | OBSERVED / INFERRED |
| DASA | Local quality-level logic only (`_can_use_DASA`, `avDASASetting`). No wire field is necessary on a receive-only client | | OBSERVED (no packet sender in the DASA functions) |
| Two-way streaming | Login byte 2N+0x1C = 0 | Server reports capability 0 | OBSERVED |
| Token, identity, ability, JSON requests | Not sent | | OBSERVED |

If resend == 1 is used, the client MUST also: send packet B, send type 0x09 ACKs with the lost
list, reply 0x0B to each packet with flags bit 3, wrap its IOCtrl packets in type 0x0C with a
zero FEC head, and parse type 0x0C. OBSERVED.

## 7. Legacy transport (reply 0x01 / 0x14) - partial

Used when +0x1F84 is 0. Not fully analysed. OBSERVED items only:

- Dispatch: packet byte 0 == 0 -> `FUN_001346b0@001346b0`; byte 0 == 1 -> `FUN_00134cf0@00134cf0`.
- All packets use the 24-byte header of 1.3: `+0 kind (0 control, 1 data)`, `+1 type`,
  `+2 version`, `+4 u32 number`, `+0x10 u16 payload size`, `+0x14 u32`.
- IOCtrl send (`_avSendIOCtrl_Old@0012e950`): header type 0x70, `+4` = IO sequence (starts at
  1), `+0x10` = data length + 4, `+0x14` = clock ms, `+0x18` = u32 IOCtrl type, `+0x1C` = data
  (maximum 0x4FC). Total length = data length + 0x1C. Sent again each `+0x1978` ms (half of the
  login interval, then RTT based) until the ACK.
- IOCtrl ACK (IOFrame ACK): the receiver returns the 24-byte header with type 0x71 and
  payload size 0. The sender accepts it when `+4` equals its sequence. OBSERVED `FUN_001346b0`.
- Control types seen in `FUN_001346b0`: 0x11 (ACK with RTT field at +0x14), 0x12 (server
  reset, payload `u32 kind, u32 a, u32 b`; client replies type 0x13, 0x2C bytes),
  0x70, 0x71, 0x01/0x14.
- Data packets (`FUN_00134cf0`): `+1` type 3 or 6 = video, 4 or 5 = audio; `+4` frame number;
  `+8` frame size; `+0xC` position; `+0xE` frame-info size; `+0x10` payload size; payload at
  0x18. With resend, the client sends type 0x08 (0x20 bytes) and resend requests
  (`_avCheckResendRequest@0012d3dc`: `u32 frame_no, u32 ms, u16 count, u16 pos[count]`).

## 8. UNKNOWNS

1. AV library version of the camera. It selects new (0x21) or legacy transport, the N value,
   and if the server ignores login packet A.
2. If the camera application accepts `resend = 0` and plain mode. The library does; the
   firmware policy is not in this binary.
3. `IOTC_sCHL_*` internals (DTLS version, record transport, default cipher list, the meaning
   of -50001..-50006). They are in libIOTCAPIs.
4. The names of in-config fields 0x38 / 0x3C and out-config 0x18 / 0x1C (not in the Java class).
5. The meaning of the capability bits in `opcode_word[]` (0x001F07FB, 0x00030000). The values
   are OBSERVED; no per-bit use was found for the client receive path.
6. Outer header bytes 6..7 and extension bytes 12..15: the senders do not write them.
7. FEC head byte 4 and the exact Reed-Solomon parameters (data/parity counts given to
   `reed_solomon_new`), and the parity packet layout after the inner header.
8. The second local condition that sets wrapper mode on the server (`FUN_001310bc`).
9. Full legacy data, resend and statistics formats (section 7 is partial).
10. `IOTYPE_INNER_SND_DATA_DELAY` (0xFF) wire use; not located in the new transport.
11. Login result values other than 0 and 3 (set by `_AvDoAuthCheck@0012d740`, not analysed).
12. Layout of the frame-info block and of the IPCAM_START payload (application level).
13. Subtype 0x72 (IOCtrl cancel) receiver semantics: only partly read.
