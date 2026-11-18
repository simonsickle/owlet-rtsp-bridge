# C. TUTK IOTC session data path and secure channel (DTLS / AES record)

Source: Ghidra output `iotc_all.c` (libIOTCAPIs.so) and `av_all.c` (libAVAPIs.so), plus AArch64 disassembly of regions that Ghidra did not decompile.
Addresses are Ghidra addresses (ELF address + 0x100000).
All multi-byte fields are little-endian unless the table says otherwise.

Tags:
- **OBSERVED**: read directly from the code or data.
- **INFERRED**: a conclusion from the code that the code does not state directly.
- **UNKNOWN**: not found. Do not guess.

Session structure: `gSessionInfo[sid]`, element size 0x1c30. "S+0xNN" below is an offset in this structure.

| S offset | Size | Meaning | Evidence |
|---|---|---|---|
| S+0x00 | 20 | UID (ASCII) | FUN_0012df60@0012df60 (`%.*s` with length 0x14) INFERRED |
| S+0x19 | 1 | Session state. 1 = connecting, 2 = connected, 3 = closed by remote, 4 = alive timeout | IOTC_Session_Write_Data_And_Datatype@00124700, alive thread@0013a3d4 OBSERVED |
| S+0x1c | 4 | Role. 0 = client, 1 = device | iotcRecordHandler@0012ea9c, IOTC_GetAuthenticationType@00132fa8. Meaning INFERRED |
| S+0x20 | 8 | Session identifier (two u32 at +0x20 and +0x24) | write@00124700, _IOTC_Packet_Handler OBSERVED |
| S+0x28 | 4 | Identifier type. 0 = 8-byte identifier is sent in an extension. 1 = only the low 16 bits are sent | write@00124700 OBSERVED |
| S+0x75 | 0x1d | HMAC key string for Record2 (see section 4) | FUN_0012df60@0012df60 OBSERVED |
| S+0x99 | 1 | Alive counter (seconds without a received packet) | alive thread@0013a3d4, __Fill_ReadBuf@0011778c OBSERVED |
| S+0x9a + ch*2 | 2 | Next expected receive sequence number for channel ch | Read_Check_Lost@00124168 OBSERVED |
| S+0xdc | 0x14 | Remote address | write@00124700 OBSERVED |
| S+0x13c + ch*4 | 4 | Transmit sequence counter for channel ch | write@00124700 OBSERVED |
| S+0x1bc + ch*4 | 4 | Local receive counter for channel ch | __Fill_ReadBuf@0011778c OBSERVED |
| S+0x23c + ch | 1 | Channel-on flag | IOTC_Session_Channel_ON@00124d94 OBSERVED |
| S+0x2a0 + ch*0x10 | 8+8 | Read queue head and tail for channel ch | __Fill_ReadBuf@0011778c OBSERVED |
| S+0x4a4 | 2 | Relay session number (used on relay paths) | write@00124700 OBSERVED |
| S+0x4a8 + ch*8 | 8 | Optional receive callback for channel ch | _IOTC_Packet_Handler (line 5311 of iotc_all.c) OBSERVED |
| S+0xb04 | 1 | Remote supports partial encryption (bit 1 of the flags byte of a received packet) | _IOTC_Packet_Handler (many sites, for example line 4992) OBSERVED |
| S+0xb05 | 1 | Partial encryption is on | IOTC_Set_Partial_Encryption@00125a10 OBSERVED |
| S+0xb38 | 8 | Connection object (send = vtable+0x28) | write@00124700 OBSERVED |
| S+0xb40 | 4 | Send path. -1 = none, 0 and 1 = direct (LAN / P2P), 2 and 3 = relay | write@00124700 OBSERVED. Names INFERRED from _IOTC_LAN_Connection_Check@00118204 (sets 0) |
| S+0x16c4 | 0xa0 | Copy of St_IOTCConnectInput | IOTC_Connect_UDP_Inner@0012b408 OBSERVED |
| S+0x16cc | 8 | authKey | same OBSERVED |
| S+0x1764 | 4 | Authentication type | IOTC_GetAuthenticationType@00132fa8 OBSERVED |
| S+0x1782, S+0x1784 | 2+2 | Nonces (random 1..0xffff, unique in the process) | iotcUpdateNonce@00121b00 OBSERVED |
| S+0x1786 | 16 | Master AES key (4 x rand()) | iotcUpdateAESInfo@00121c34 OBSERVED |
| S+0x1796 | 12 | Master AES IV (3 x rand()) | iotcUpdateAESInfo@00121c34 OBSERVED |
| S+0x17a8 + n*0x60 | 0x60 | P2P key slot n (n = 0..11): AES key at +4 (16 bytes), IV at +0x14 (12 bytes), peer address string at +0x20 (0x2e) | iotcUpdateP2PAESKeys@0012c438, iotcGetP2PKeyInfo@0012c5d8 OBSERVED |
| S+0x1c28 | 8 | Local ECDH key pair handle | IOTC_Connect_UDP_Inner@0012b408 OBSERVED |

---

## 1. Session DATA packet

### 1.1 Transmit: IOTC_Session_Write_Data_And_Datatype@00124700

Signature (OBSERVED): `(int sid, const void *buf, uint len, u8 channel, u8 dataType)`.

`IOTC_Session_Write@00124d84` and `IOTC_Session_Write_DTLS@00124d8c` are 8-byte tail calls to this function. The caller sets the dataType register. The plain AV channel calls `IOTC_Session_Write` (AV LAB_00129328). The DTLS BIO calls with dataType = 1 (FUN_001416cc@001416cc).

Preconditions (OBSERVED):
- `len` must be < 0x56d. Maximum payload = **0x56c (1388) bytes**. If not, the result is -46 (0xffffffd2).
- Session state must be 2. State 3 gives -22. State 4 gives -23.
- No connection object or send path = -1 gives -55 (0xffffffc9).

Wire layout before transcode:

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | 0x0204 (bytes `04 02`) | write@00124700 `local_c3c = 0x204` OBSERVED |
| 0x02 | 1 | - | version | 0x1d | `local_c3a = 0x1d` OBSERVED |
| 0x03 | 1 | - | flags | bit 0 (0x01) = partial encryption. bit 1 (0x02) = always set (sender supports partial encryption). bit 3 (0x08) = identifier extension is present | `bVar11 = 2 or 3`, `\| 8`, `\| 2` OBSERVED. Meaning of bit 1 INFERRED from S+0xb04 |
| 0x04 | 2 | LE | size | Number of bytes after the 16-byte header = payload length (+ 0x0c if the extension is present) | `local_c38` OBSERVED |
| 0x06 | 2 | LE | seq | Low 16 bits of the transmit counter S+0x13c+ch*4. The counter increments by 1 for each packet. First value 0 (INFERRED) | `local_c36` OBSERVED |
| 0x08 | 2 | LE | cmd | Direct path: 0x0407 (client to device), 0x0408 (device to client). Relay path: 0x0504 (client), 0x0502 (device) | `local_c34` low half OBSERVED |
| 0x0a | 2 | LE | cmd flags | Direct: 0x0021 (client), 0x0012 (device). Relay: 0x0024 (client), 0x0014 (device) | `local_c34` high half OBSERVED |
| 0x0c | 2 | LE | sid16 | Direct: low 16 bits of S+0x20. Relay: S+0x4a4 | `local_c30` OBSERVED |
| 0x0e | 1 | - | channel | Channel identifier 0..31 | `local_c2e = param_4` OBSERVED |
| 0x0f | 1 | - | dataType | `dataType & 3`. 0 = plain data, 1 = DTLS record | `local_c2d = param_5 & 3` OBSERVED. Values: section 5 |
| 0x10 | 4 | LE | extLen | Only if S+0x28 == 0: value 0x0000000c | `local_c2c = 0xc` OBSERVED |
| 0x14 | 8 | LE | sessionId | Only if S+0x28 == 0: 8 bytes from S+0x20 | `local_c28` OBSERVED |
| 0x10 or 0x1c | len | - | payload | User data. Offset 0x1c with the extension, 0x10 without it | `puVar10` OBSERVED |

Total datagram length = `len + 0x10` (+ 0x0c with the extension).

Transcode (OBSERVED): `FUN_00116eac(header, out, total, encLen)`.
- `encLen = total` when flags bit 0 is clear. The full packet is transcoded.
- `encLen = 0x40` when flags bit 0 is set. Only the first 0x40 bytes are transcoded (16-byte header + first 0x30 body bytes). The remaining bytes are copied without change (FUN_00116eac@00116eac: `memcpy(out+encLen, in+encLen, total-encLen)`).
- If `total < encLen`, the function transcodes `total` bytes.

The return value is the payload length when the send is successful.

### 1.2 Partial encryption: IOTC_Set_Partial_Encryption@00125a10

`(int sid, char enable)`. OBSERVED:
- If S+0xb04 == 0 the function returns -47 (0xffffffd1) and does not change S+0xb05.
- If not, S+0xb05 = (enable != 0).
- S+0xb04 is set from bit 1 of the flags byte of received packets (`flags >> 1 & 1`).
- `IOTC_sCHL_new@00141a54` calls `IOTC_Set_Partial_Encryption(sid, 1)`. Thus DTLS sessions use partial transcode when the remote set flag bit 1. The result is ignored.

### 1.3 Receive

Entry points (OBSERVED): FUN_00138f10@00138f10 (datagram) and FUN_00138784@00138784 (stream).

1. If the length is >= 12 and the first u32 is 0x0000cc51, the data goes to `iotcRecordHandler` (section 4).
2. If not, the first 16 bytes are decoded: `FUN_00117168(in, out, len, 0x10)`.
3. The magic must be 0x0204. `size` (offset 4) must be < 0x579 (maximum 0x578 = 1400).
4. Datagram mode: `size + 0x10` must be equal to the datagram length.
5. Body decode: `FUN_00117168(in+0x10, out+0x10, size, n)` with `n = size` if flags bit 0 is clear, and `n = 0x30` if flags bit 0 is set.
6. The decoded packet goes to `_IOTC_Packet_Handler`.

Data handling in `_IOTC_Packet_Handler` (iotc_all.c lines 5239-5320 and 5425-5470, OBSERVED):
- If flags bit 3 is set (INFERRED from the branch structure; the code checks `size >= 0x0c`): the session is found by the 8-byte identifier at packet offset 0x14 (S+0x28 == 0, S+0x20 and S+0x24 equal). Then `extLen = u32 at 0x10`, `payload = packet + 0x10 + extLen`, `payloadLen = size - extLen`.
- `channel = byte at 0x0e`. It must be < 0x20.
- If S+0x4a8+ch*8 is not null, the callback gets `(sid, ch, payload, payloadLen, status)`.
- If not, and `payloadLen > 0`: `__Fill_ReadBuf(sid, payload, payloadLen, seq = u16 at 0x06, ch, dataType = byte at 0x0f)`.

`__Fill_ReadBuf@0011778c` (OBSERVED) makes a 0x20-byte queue node:

| Node offset | Size | Field |
|---|---|---|
| 0x00 | 2 | payload length |
| 0x02 | 2 | wire sequence number |
| 0x04 | 4 | local receive counter (S+0x1bc+ch*4, then incremented) |
| 0x08 | 8 | pointer to a copy of the payload |
| 0x10 | 1 | dataType & 3 |
| 0x18 | 8 | next node |

It appends the node to the queue S+0x2a0+ch*0x10, increments S+0x25e+ch*2, and sets S+0x99 = 0.

`IOTC_Session_Read_Check_Lost_Data_And_Datatype@00124168` (OBSERVED):
- Signature: `(sid, buf, maxLen, timeout_ms, u16 *seqOut, bool *lostOut, u8 channel, uint *dataTypeOut)`.
- It removes one node. It copies `min(maxLen, nodeLen)` bytes. One packet = one read. Extra bytes are discarded.
- `*seqOut = node.seq`. `*lostOut = (S+0x9a+ch*2 != node.seq)`. Then S+0x9a+ch*2 = node.seq + 1.
- `*dataTypeOut = node.dataType & 3`.
- There is no reorder and no retransmit in this layer.
- Poll interval 10 ms. The loop count is `timeout_ms / 10 + 1`. Timeout result -13 (0xfffffff3). `timeout_ms == 0` gives 0 immediately when the queue is empty.

---

## 2. Session alive and session close

### 2.1 Alive thread (LAB_0013a3d4, not decompiled; disassembly 0x13a3d4..0x13a6d4)

OBSERVED:
- Created in IOTC_Initialize2 with `tutk_TaskMng_Create(1000, 0, 0, 0x13a3d4, 0)`. Period 1000 ms (INFERRED from the first argument).
- For each session with state 2:
  1. If `timeout < S+0x99`: state = 4, then the callbacks get error -23. `timeout` is `DAT_0014c5a0`. Default **0x3c = 60** (read from .data). `IOTC_Setup_Session_Alive_Timeout@00125b4c` sets it (minimum 1).
  2. If not: S+0x99 += 1.
  3. If the new S+0x99 is <= 4 and S+0xba8 < 1: S+0xba8 += 1 and no packet is sent.
  4. If not: S+0xba8 = 0 and one alive packet is sent.
- Result: one alive packet each 2 seconds while the remote answers. One alive packet each second when no packet was received for more than 4 seconds.
- A received data packet, alive packet, and other session packets set S+0x99 = 0 (for example __Fill_ReadBuf@0011778c, handler for 0x427/0x428 at iotc_all.c line 7640).

Alive packet before transcode (full transcode, `encLen = total`):

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | 0x0204 | 0x13a55c OBSERVED |
| 0x02 | 1 | - | version | 0x1d | 0x13a568 OBSERVED |
| 0x03 | 1 | - | flags | 0x02, or 0x0a with the identifier | 0x13a62c, 0x13a640 OBSERVED |
| 0x04 | 2 | LE | size | 0, or 8 with the identifier | 0x13a644 OBSERVED |
| 0x06 | 2 | LE | seq | 0 | zeroed at 0x13a56c OBSERVED |
| 0x08 | 2 | LE | cmd | Direct: 0x0427 (client), 0x0428 (device). Relay: 0x0524 (client), 0x0522 (device) | 0x13a5b4..0x13a608 OBSERVED |
| 0x0a | 2 | LE | cmd flags | Direct: 0x0021 (client), 0x0012 (device). Relay: 0x0024 (client), 0x0014 (device) | same OBSERVED |
| 0x0c | 2 | LE | sid16 | Direct: 0. Relay: S+0x4a4 | 0x13a610 OBSERVED |
| 0x0e | 2 | - | zero | 0 | zeroed OBSERVED |
| 0x10 | 8 | LE | sessionId | Only if S+0x28 == 0: 8 bytes from S+0x20 (no length prefix) | 0x13a634..0x13a648 OBSERVED |

Total length 0x10 or 0x18.

Receive of 0x0427 / 0x0428 (iotc_all.c lines 7550-7660, OBSERVED): the handler finds the session, sets S+0x99 = 0 and S+0xb08 = 1, and updates the remote address. No reply packet is sent in this branch.

UNKNOWN: a `timeout` argument unit other than "ticks of the 1000 ms task".

### 2.2 Session close: IOTC_Session_Close@00123098

OBSERVED:
- Direct path (S+0xb40 < 2): `FUN_001235e4@001235e4` is called 3 times.
- Relay path or no connection object: `FUN_0012376c@0012376c` is called 5 times.
- Then the function clears the session. There is no wait for an acknowledgement.

Close packet, direct path (FUN_001235e4), full transcode:

| Offset | Size | Endian | Field | Meaning |
|---|---|---|---|---|
| 0x00 | 2 | LE | magic | 0x0204 |
| 0x02 | 1 | - | version | 0x1d |
| 0x03 | 1 | - | flags | 0x02, or 0x0a with the identifier |
| 0x04 | 2 | LE | size | 0, or 8 with the identifier |
| 0x06 | 2 | LE | seq | 0 |
| 0x08 | 2 | LE | cmd | 0x0417 (client), 0x0418 (device) |
| 0x0a | 2 | LE | cmd flags | 0x0021 (client), 0x0012 (device) |
| 0x0c | 4 | LE | sid | If S+0x28 != 0: low 16 bits of S+0x20, zero-extended. If S+0x28 == 0: 0 |
| 0x10 | 8 | LE | sessionId | Only if S+0x28 == 0: 8 bytes from S+0x20 |

All rows OBSERVED in FUN_001235e4@001235e4. Total length 0x10 or 0x18.

Close packet, relay path (FUN_0012376c@0012376c, OBSERVED): same layout, but cmd = 0x0514 (client) or 0x0512 (device), byte 0x0a = 0x24 (client) or 0x14 (device), byte 0x0b = 0, u16 at 0x0c = S+0x4a4, u16 at 0x0e = 0.

---

## 3. Channel ON / OFF

No wire messages. OBSERVED:
- `IOTC_Session_Channel_ON@00124d94 (sid, ch)`: sets S+0x23c+ch = 1. `ch` must be < 32 (if not, -26).
- `IOTC_Session_Channel_OFF@00124ea8 (sid, ch)`: for ch != 0, sets S+0x23c+ch = 0 and S+0x9a+ch*2 = 0. Channel 0 cannot be set to off.
- The transmit and receive functions in section 1 do not read S+0x23c.

---

## 4. iotcRecord / Record2

### 4.1 Summary

- "iotcRecord" is a second frame format with magic 0x0000cc51. It carries RSA or AES protected messages, or HMAC-SHA1 authenticated messages.
- Record types 1, 3, 4, 5 and 0x0e are received by this library. They are used for master / P2P server handshake and P2P keep-alive (iotcRecordSendMasterHandshake@00127e64, iotcRecordSendP2PHandshake@0012648c, iotcRecordSendP2PKeepAlive@0012e39c). OBSERVED.
- "Record2" for the session (types 0x10..0x17: LAN command, knock, alive, close, data) is **not used** by this build. OBSERVED:
  - `isIotcSessionEnableRecord2@00123394` returns 0.
  - `iotcRecord2SupportCheck@0012c204` returns 0.
  - `iotcRecordSendDataPacket`, `iotcRecordSendSessionAlive`, `iotcRecordSendSessionClose`, `iotcRecordSendLanCommand`, `iotcRecordSendP2PKnock` are exported, but no `bl` instruction in libIOTCAPIs.so refers to them, and libAVAPIs.so does not import them.
  - `iotcRecordHandler@0012ea9c` rejects types other than 1, 3, 4, 5, 0x0e with 0xffffe0bb.
- LAN mode: the data path, alive and close use only the legacy transcode (sections 1 and 2). The record layer is not necessary for a LAN-only client. INFERRED from the points above.

### 4.2 Record frame

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 4 | LE | magic | 0x0000cc51 (bytes `51 cc 00 00`) | isIotcRecord@0012c20c, FUN_0012e8d4@0012e8d4 OBSERVED |
| 0x04 | 1 | - | version | 2 | FUN_0012e8d4 OBSERVED |
| 0x05 | 1 | - | type | See below | OBSERVED |
| 0x06 | 2 | LE | length | Number of bytes after the 12-byte header | iotcRecordHandler: `len + 0xc == datagram length` OBSERVED |
| 0x08 | 4 | LE | recordSid | Session index of the sender, or 0xffff for the device login context | FUN_0012e8d4, iotcRecordHandler OBSERVED |
| 0x0c | length | - | body | Depends on the type | |

iotcRecordHandler limits (OBSERVED): datagram length >= 12 and <= 0x588. Magic error = 0xffffe0bc. Length error = 0xffffe0be.

Types (OBSERVED unless tagged):

| Type | Direction and use | Protection |
|---|---|---|
| 1 | Master handshake request. Body = RSA encryption of a 0x58-byte legacy packet (cmd 0x100b) that contains the nonce, the 16-byte AES key and the 12-byte IV from S+0x1786 / S+0x1796. Received type 1 = AES decrypt with the master key | `TUTK3rdRSAEncrypt(pubkey PEM at 0x14c5a4, 1, in, 0x58, out, 0x57c)`; iotcRecordSendMasterHandshake@00127e64, FUN_0012ee98@0012ee98 |
| 2 | 0x68 clear bytes after the header, then AES ciphertext. AAD length 0x74 | FUN_0012d73c@0012d73c |
| 3 | Received. AES decrypt with a P2P key from `iotcGetP2PKeyInfo` | FUN_0012f208@0012f208 |
| 4 | P2P handshake. 4 clear bytes after the header, then AES ciphertext. AAD length 0x10 | FUN_0012d73c, iotcRecordSendP2PHandshake@0012648c |
| 5 | P2P keep-alive. Length 0x0c, no encryption. Body: u32, u8 (=1), 3 pad bytes, u32 | iotcRecordSendP2PKeepAlive@0012e39c (`0x000c0502 0000cc51`) |
| 0x0e | Received. AES decrypt with a P2P key | FUN_0012fee4@0012fee4 |
| 0x10 / 0x11 | LAN command / P2P knock. Length 0x28. HMAC at 0x20. Total 0x34. Not sent by this build | FUN_0012e8d4, iotcRecordSendLanCommand@0012dc54, iotcRecordSendP2PKnock@0012e16c |
| 0x12 / 0x13 | Session alive / session close. Length 0x24. HMAC at 0x1c. Total 0x30. Not sent by this build | iotcRecordSendSessionAlive@0012e68c (`0x00241202 0000cc51`), iotcRecordSendSessionClose@0012339c (`0x00241302 0000cc51`) |
| 0x14..0x17 | Session data. Not sent by this build | iotcRecordSendDataPacket@00124ab0 |

### 4.3 Record2 session frames (dead code in this build, given for completeness)

HMAC key (FUN_0012df60@0012df60, OBSERVED): the ASCII string at S+0x75, made with `"%.*s%.*s"` = UID (20 characters) + authKey (8 characters). Total 28 characters.
- Client: authKey = St_IOTCConnectInput.authKey (S+0x16cc). If it is empty, the string is UID + `"00000000"`.
- Device: UID + device authKey (DAT_00150188), or UID + `"00000000"` when the authKey is off (DAT_0015017c == 1).

MAC = `TUTK3rdSHA1HMAC(key, strlen(key), record, n, out, 0x14)`. 20-byte tag.

Session alive (type 0x12) and close (type 0x13), total 0x30 bytes (OBSERVED, iotcRecordSendSessionAlive@0012e68c):

| Offset | Size | Endian | Field |
|---|---|---|---|
| 0x00 | 4 | LE | 0x0000cc51 |
| 0x04 | 1 | - | 2 |
| 0x05 | 1 | - | 0x12 (alive) or 0x13 (close) |
| 0x06 | 2 | LE | 0x0024 |
| 0x08 | 4 | LE | recordSid |
| 0x0c | 1 | - | send path (S+0xb40) |
| 0x0d | 1 | - | 0 |
| 0x0e | 2 | LE | relay session number (S+0x4a4) if path >= 2, else 0 |
| 0x10 | 4 | LE | `time(NULL)` (low 32 bits) |
| 0x14 | 8 | LE | session identifier (S+0x20) |
| 0x1c | 20 | - | HMAC-SHA1 of bytes 0x00..0x1b |

Session data (iotcRecordSendDataPacket@00124ab0 + FUN_0012e8d4, OBSERVED):
- Signature: `(sid, u8 channel, ulong flag, buf, uint len, u8 dataType)`. `len` must be < 0x54d (maximum 0x54c = 1356).
- Type: path < 2: 0x15 if `flag & 1`, else 0x17. Path >= 2: 0x14 if `flag & 1`, else 0x16.

| Offset | Size | Endian | Field |
|---|---|---|---|
| 0x00 | 12 | - | record header. length = len + 0x10 + 0x14 |
| 0x0c | 1 | - | 0x10 |
| 0x0d | 1 | - | channel |
| 0x0e | 2 | LE | S+0x92 (path < 2) or S+0x4a4 (path >= 2) |
| 0x10 | 8 | LE | session identifier (S+0x20) |
| 0x18 | 1 | - | dataType |
| 0x19 | 3 | - | 0 |
| 0x1c | len | - | payload (plain text) |
| 0x1c + len | 20 | - | HMAC-SHA1. Types 0x14/0x15: of bytes 0x00..0x1b only. Types 0x16/0x17: of bytes 0x00..(0x1c+len-1) |

Total length = len + 0x30. The payload is not encrypted in these frames.

### 4.4 Key agreement and AES (master / P2P server path)

OBSERVED:
1. `IOTC_Connect_UDP_Inner@0012b408` calls `iotcUpdateNonce` (S+0x1782, S+0x1784), `iotcUpdateAESInfo`, and `TUTK3rdECDHCreateKeyPair()` (handle to S+0x1c28).
2. `iotcUpdateAESInfo@00121c34`: master AES key = 4 x `rand()` (16 bytes at S+0x1786). IV = 3 x `rand()` (12 bytes at S+0x1796). `iotcUpdateAESKey@0012c288` and `iotcUpdateAESIV@0012c230` do the same for a caller buffer (lengths must be 0x10 and 0x0c).
3. The master key and IV go to the master in a type 1 record, encrypted with an RSA public key (PEM string at 0x14c5a4). The inner legacy packet has cmd 0x100b.
4. Replies of type 1 are decrypted with the master key: `TUTK3rdAESDecryptEx(1, body, length, recordHeader, 0x0c, key, iv, out)`. The plain text is a legacy `04 02` packet (the code checks magic 0x0204 and size <= 0x56c).
5. `iotcGetLocalEccPubKey@0012c2e8`: `TUTK3rdECDHEncodePubKeyDER` must give exactly 0x5b (91) bytes.
6. `iotcUpdateP2PAESKeys@0012c438 (recordSid, slot, peerPubKeyDER, peerAddrString)`: `TUTK3rdECDHDecodePubKeyFromDER(der, 0x5b)`, then `TUTK3rdECDHDecodeSecret(localKeyPair, peerPub, &secret)`. The first 16 bytes of the secret become the AES key of the slot. The IV of the slot is 3 x `rand()` (12 bytes). The peer address string is stored for lookup. Maximum 12 slots.
7. `iotcGetP2PKeyInfo@0012c5d8 (addrString, recordSid, out)`: finds the slot by `strcmp` on the peer address string.
8. Encrypt: `TUTK3rdAESEncryptEx(1, plain, n, aad = record start, aadLen = 0x10 or 0x74, key, key+16 (IV), out, 0, 0, 0, 0)` (FUN_0012d73c@0012d73c).

INFERRED:
- The curve is NIST P-256. A DER SubjectPublicKeyInfo for P-256 has 91 bytes.
- The AES mode is AES-128-GCM: 16-byte key, 12-byte IV, and the record header is passed as additional authenticated data. Mode argument = 1.

UNKNOWN:
- The exact AES mode constant meaning, the tag length and the tag position. `TUTK3rdAESEncryptEx` is in a different library.
- KDF: none seen. The key is the first 16 bytes of the value that `TUTK3rdECDHDecodeSecret` returns. If that function hashes the secret is UNKNOWN.
- How the peer gets the per-slot random IV (the record body layout for types 3, 4, 0x0e was not fully decoded here).

---

## 5. DTLS layer (IOTC_sCHL_*)

### 5.1 Objects and call sequence

OBSERVED:
- `IOTC_sCHL_initialize@00141428`: `OPENSSL_init_ssl(0, 0)`, makes the custom BIO method, makes two lists (server PSK callbacks, client PSK callbacks).
- `IOTC_sCHL_CTX_new@001415c0 (isClient, SSL_CTX **out)`: `SSL_CTX_new(DTLS_method())`. The first argument is not used. No version limit is set. Error = 0xffff3cac.
- `IOTC_sCHL_CTX_set_cipher_list@001425c0`: direct branch to `SSL_CTX_set_cipher_list(ctx, str)`.
- `IOTC_sCHL_CTX_use_certificate_file@001415fc`, `IOTC_sCHL_CTX_use_PrivateKey_file@001415f8`: direct branches. Not called by the AV client path.
- `IOTC_sCHL_CTX_set_psk_client_callback@001424cc (ctx, cb, userData)`: stores `{userData, cb, ctx}` in a list and calls `SSL_CTX_set_psk_client_callback(ctx, sCHL_psk_client_callback)`.
- `sCHL_psk_client_callback@001423ac (ssl, hint, identity, maxIdentityLen, psk, maxPskLen)`: finds the entry for `SSL_get_SSL_CTX(ssl)` and calls `cb(ssl, hint, identity, maxIdentityLen, psk, maxPskLen, userData)`.
- `IOTC_sCHL_new@00141a54 (ctx, sid, channel)`: allocates a 0x5c8-byte BIO context, `SSL_new`, `SSL_set_quiet_shutdown(ssl, 1)`, `DTLS_set_timer_cb(ssl, LAB_00141b54)`, `IOTC_Set_Partial_Encryption(sid, 1)`, `SSL_set_bio(ssl, bio, bio)`.
- `IOTC_sCHL_connect@00141cf0`: loop on `SSL_connect` while the error is WANT_READ (2) or WANT_WRITE (3) and the elapsed time is less than the connect timeout. Timeout result = 0xffff3caa (-50006).
- `IOTC_sCHL_read@00141e74`: `IOTC_Session_Has_Data(sid, ch, 200)` (waits a maximum of 200 ms), then `SSL_read` with a mutex. Returns 0 when there is no data.
- `IOTC_sCHL_write@00141f18`: `SSL_write` with the same mutex.
- `IOTC_sCHL_shutdown@00141f9c`: `SSL_shutdown` only if the handshake was completed.

AV client sequence (AV LAB_0012715c, disassembly 0x2715c..0x27238, OBSERVED):
1. `IOTC_Session_Channel_ON(sid, ch)`.
2. `ssl = IOTC_sCHL_new(ctx, sid, ch)`.
3. `IOTC_sCHL_set_dtls_connect_timeout(ssl, seconds)` (value from channel object +0x114).
4. Client: `IOTC_sCHL_connect(ssl)`. Server: `IOTC_sCHL_accept(ssl)`.

### 5.2 How DTLS records are carried

OBSERVED:
- BIO write (FUN_001416cc@001416cc): `IOTC_Session_Write_Data_And_Datatype(sid, buf, len, channel, 1)`.
- One BIO write = one session DATA packet (section 1.1). **dataType = 1**. The channel is the AV channel. There is no extra frame header.
- BIO read (FUN_0014171c@0014171c): `IOTC_Session_Read_Data_And_Datatype(sid, buf, 0x56c, 0x14, channel, &dataType)`. Poll timeout 20 ms each call.
  - If a packet has dataType == 0, the BIO sets its "plain data" flag and returns 0. A DTLS session does not accept plain packets.
  - One session packet goes to an internal buffer (maximum 0x56c bytes) and is given to OpenSSL in parts if the read size is smaller.
- Plain AV channel read (AV FUN_001292bc@001292bc): if dataType == 1 arrives on a plain channel, the result is -0x4ee3 (-20195). The string "recv dtls data!" is in libAVAPIs.so.
- BIO ctrl (LAB_001419ec): BIO_CTRL_FLUSH (0x0b) returns 1. BIO_CTRL_DGRAM_QUERY_MTU (0x28) returns **0x56c (1388)**. All others return 0.
- The session layer applies the transcode on top of the DTLS record. With partial encryption only the first 0x30 payload bytes (plus the header) are transcoded.

### 5.3 Cipher list

OBSERVED:
- No cipher list string is in libIOTCAPIs.so or libAVAPIs.so.
- `ClientDTLSChannelNew@00126f74` calls `IOTC_sCHL_CTX_set_cipher_list(ctx, cipherStr)` only if `cipherStr` (argument 5, channel object +0x118) is not NULL (disassembly 0x270c4..0x270d0).
- The string comes from the application: field `dtls_cipher_suites` (Java type String) of the avClientStartEx input (Java_com_tutk_IOTC_AVAPIs_avClientStartEx@00113f6c).

UNKNOWN: the string that the application passes, and the default cipher list of the embedded OpenSSL when the string is NULL. Read it from the Java code of the application or from a packet capture (ClientHello).

### 5.4 PSK identity and PSK value

OBSERVED in `IKalayAVNew@0013084c` (AV) and the callback LAB_001272a0:

Inputs of IKalayAVNew: `(securityMode, authType, isServer, sid, channel, account, password, cipherStr, ...)`.

- `securityMode`: 0 = plain channel (`IOTCChannelNew`). 1 = DTLS. 2 = auto: DTLS, and plain if `ClientDTLSChannelNew` returns 0xffffacaa (-21334). 3 = plain channel with mode value 3.
- `authType`: 0 = password, 1 = token. 2 gives error 0xffffb1bf (-20033).

Identity (OBSERVED): `snprintf(identity, 0x78, "%s%s", prefix, account)`.
- Prefix `"AUTHPWD_"` for authType 0.
- Prefix `"AUTHTKN_"` for authType 1.
- `account` is the account or identity string of avClientStartEx (string `account_or_identity` in libAVAPIs.so).
- The callback does `strcpy(identityOut, identity)`.

PSK (OBSERVED):
1. `digest = TUTK3rdSHA256(password, strlen(password), out, 0x20)`. Input = the password or token string, no salt.
2. `strncpy(psk, digest, 0x20)`. This operation occurs 3 times (IKalayAVNew, ClientDTLSChannelNew, callback).
3. The callback sets `psk[0x20] = 0` and returns **0x20**.

Result:
- PSK length = 32 bytes always.
- PSK value = SHA-256(password) **cut at the first 0x00 byte, then filled with 0x00 to 32 bytes** (strncpy semantics). If the digest has no 0x00 byte, the PSK is the full digest.
- The digest is used as raw bytes. There is no hex or Base64 step.

INFERRED: `TUTK3rdSHA256` is plain SHA-256 (name and 0x20 output length).

The authKey of St_IOTCConnectInput is not an input of the PSK or of the identity (OBSERVED: no such data flow in ClientDTLSChannelNew or IKalayAVNew).

UNKNOWN: the PSK identity hint that the device sends, and if the client uses it (the callback ignores the hint argument).

### 5.5 DTLS timeouts

OBSERVED:
- Retransmit timer callback (LAB_00141b54, disassembly): `timer_cb(ssl, us)` returns 500000 if `us == 0`, else `us * 2`. First retransmit after **500 ms**, then the time doubles.
- Connect timeout: `IOTC_sCHL_set_dtls_connect_timeout@00142600 (ssl, seconds)` stores `seconds * 1000` ms (maximum 0x7fffffff) at BIO context +0x0c. `IOTC_sCHL_set_dtls_connect_timeout_ms@001425c4` stores milliseconds.
- BIO read during the handshake: wait = `min(remaining connect time, DTLSv1_get_timeout)` (`SSL_ctrl(ssl, 0x49, 0, &tv)`), polled in 20 ms steps. When the connect time is used, the BIO returns -13.
- BIO read after the handshake: one poll window of about 40 ms. After 5 handshake-phase reads, each read first sleeps 100 ms.
- The session alive timeout (section 2.1) also applies.

UNKNOWN: the default connect timeout value. It comes from the AV layer (channel object +0x114, set by AV LAB_00127280).

---

## 6. Authentication type and authKey

### 6.1 IOTC_GetAuthenticationType@00132fa8 (OBSERVED)

`(int sid)`:
- Library not initialized: -12. Bad sid: -14. State 3: -22. State 4: -23.
- State 2, device role (S+0x1c == 1): returns `-(DAT_0015017c & 1)`. 0 = authKey mode is on. -1 = authKey is off.
- State 2, client role: returns S+0x1764.
- S+0x1764 is -1 at initialization (IOTC_Initialize2, FUN_001212f0) and 0 after IOTC_Connect_UDP_Inner copies the connect input.
- Caller: `avSendRequest` in libAVAPIs.so (av_all.c line 9174).

### 6.2 IOTC_Connect_ByUIDEx@001207b0 (OBSERVED)

`(const char *uid, int sid, St_IOTCConnectInput *in)`.

St_IOTCConnectInput:

| Offset | Size | Field | Rule | Evidence |
|---|---|---|---|---|
| 0x00 | 4 | cb | Must be 0xa0 | `*param_3 == 0xa0` |
| 0x04 | 4 | authenticationType | Must be 0 (authKey) | `param_3[1] == 0` |
| 0x08 | 8 | authKey | 8 characters, each in `[0-9A-Za-z]` | FUN_0012213c@0012213c |
| 0x10..0x97 | - | not decoded | - | - |
| 0x98 | 4 | field | Must be < 3. Value 1 returns -63 (0xffffffc1) | `param_3[0x26]` |

Other rules: session state must be 1 (if not, -14). `uid` = 20 characters, each in `[0-9A-Za-z]` (if not, the session is released and the result is -10). Any other input error = -46.
Then: `IOTC_Connect_UDP_Inner(uid, sid, 0, in, 0, 0)`.

Use of the authKey (OBSERVED):
- `IOTC_Connect_UDP_Inner@0012b408` copies the 0xa0 bytes of the input to S+0x16c4. The authKey is at S+0x16cc.
- `FUN_0012798c@0012798c` gives S+0x16cc to `FUN_001254a0@001254a0`. That function builds the LAN request (legacy packet, cmd 0x0603 or 0x0604, total length 0x58) and writes the 8 authKey bytes at **packet offset 0x4a**.
- Device side: `_IOTC_Packet_Handler` (iotc_all.c line 7997) compares the u64 at packet offset 0x4a with the device authKey (DAT_00150188) when the packet size is >= 0x48. A mismatch gives status 5.
- Client side: `_IOTC_Packet_Handler` (lines 8515 and 8630) checks `S+0x1764 == 0 && authKey != "00000000"`. If true, it stores the remote version byte in S+0xb07 and sets S+0xa38 = 3.
- The authKey is the second part of the Record2 HMAC key (section 4.3). That path is not active in this build.
- The authKey is not used by the DTLS PSK.

UNKNOWN: fields 0x10..0x97 of St_IOTCConnectInput. The meaning of the field at 0x98 and of S+0xa38 = 3.

---

## 7. List of UNKNOWNS

1. DTLS cipher list string (application-supplied) and the default of the embedded OpenSSL.
2. DTLS protocol version in use (only `DTLS_method()` is seen).
3. Default DTLS connect timeout (AV layer value).
4. AES mode, tag length and tag position of `TUTK3rdAESEncryptEx` / `TUTK3rdAESDecryptEx` (mode argument 1; AES-GCM is INFERRED).
5. Output format of `TUTK3rdECDHDecodeSecret` (raw X coordinate or a hash). Curve P-256 is INFERRED.
6. Full body layouts of record types 2, 3, 4 and 0x0e.
7. First value of the per-channel transmit sequence counter (0 is INFERRED). If the remote does a check of the sequence number is UNKNOWN.
8. The exact condition in `_IOTC_Packet_Handler` that selects the "identifier extension" branch (flags bit 3 is INFERRED from the transmit side).
9. Meaning of cmd flag values 0x21 / 0x12 / 0x24 / 0x14 at header offset 0x0a.
10. Fields 0x10..0x98 of St_IOTCConnectInput.
11. If the transcode of a 16-byte header block plus a body block (receive side) is always equal to one call for the full packet (transmit side). The code makes this assumption; it is correct only if the transcode operates on independent 16-byte blocks with the tail handled relative to the end.
