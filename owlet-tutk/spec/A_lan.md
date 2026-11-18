# A. TUTK IOTC LAN search and LAN connect (client side) - wire spec

Source: Ghidra decompile `iotc_all.c` of `libIOTCAPIs.so` (aarch64, SDK version constant `0x04030800` = 4.3.8.0, protocol version byte `0x1d`).
Citations use `name@ghidra_addr`. Ghidra image base is 0x100000.

Labels:
- **OBSERVED**: read directly in the decompile or in the ELF bytes.
- **INFERRED**: a conclusion from the code, not a literal statement in the code.
- **UNKNOWN**: not resolved. See section 8.

All multi-byte integers are **little-endian** unless the table says a different order. `IOTC_Header_hton@00116e84` and `IOTC_Header_ntoh@00116e88` are empty functions (OBSERVED), so the header has host (LE) order on the wire.

---

## 0. Critical items to read first

1. **Transcode key can be changed by the licence key.** `IOTC_Initialize2@0012299c` copies `"Charlie is the designer of P2P!!"` (32 bytes, rodata 0x10b090 + 0x10b080) to 0x1502e0, then calls the import `GetLicenseKeyMask(buf,16)` from `libTUTKGlobalAPIs.so`. If the return value is 0, the first 16 key bytes are XORed with the 16-byte mask (OBSERVED). In `libTUTKGlobalAPIs.so`, `GetLicenseKeyMask@0x264a68` returns 0 only after a valid `TUTK_SDK_Set_License_Key`; `SetLicenseKey@0x2647f0` reads the JSON field `"keyMask"` from the licence payload, base64-decodes it, and requires 16 bytes (OBSERVED by disassembly). If the licence has no `keyMask` field, the mask is 16 zero bytes and the key stays `"Charlie is the d"`.
   - Effective key = `"Charlie is the d"` XOR `keyMask` (or XOR zero). **The value of `keyMask` for the user's app licence is UNKNOWN** (section 8, U1).
2. LAN search and LAN connect use the same request opcode family (0x601/0x603/0x604) and the same response opcode (0x602). The `type` field makes the difference.
3. State value 4 of the LAN state machine is never set in this build. The client goes from state 1 directly to state 6.

---

## 1. Common packet header (16 bytes)

Evidence: `FUN_001254a0@001254a0`, `_IOTC_Send_Punch_To@001179b4`, `_IOTC_SendQuryDevice5@00117bf0`, `FUN_0013699c@0013699c`, `FUN_001354f4@001354f4`, receive path `FUN_00138f10@00138f10`, `_IOTC_Packet_Handler@00118864`.

| Off | Size | Endian | Field | Value / meaning | Evidence | Status |
|---|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | `0x0204` -> bytes `04 02` | all builders write `0x204`; receiver checks `== 0x204` in `FUN_00138f10` | OBSERVED |
| 0x02 | 1 | - | protocol version | `0x1d` in this build. The receiver stores the peer value (session+0xb07) and compares it with 7, 10, 0x17, 0x1b | builders; `_IOTC_Packet_Handler` case 0x602 | OBSERVED |
| 0x03 | 1 | bits | flags | bit0 (0x01) = partial transcode (only the first 0x40 packet bytes are transcoded). bit1 (0x02) = set by each sender before transmit; the receiver stores it as session+0xb04 (gate for `IOTC_Set_Partial_Encryption@00125a10`). bit2 (0x04) = packet ignored by the 0x408 handler. bit3 (0x08) = the payload starts with a random-ID prefix (used by 0x408/0x428/0x521/0x523) | `iotc_SendMessage@00117418`, `Broadcast_Message_By_Netmask@001175fc`, handler lines for 0x408/0x521 | bit0, bit1, bit3 OBSERVED; meaning of bit2 UNKNOWN |
| 0x04 | 2 | LE | payload size | total datagram length - 16. Receiver requires `size < 0x579` and `size + 0x10 == datagram length` | `FUN_00138f10` | OBSERVED |
| 0x06 | 2 | LE | sequence | 0 in all LAN packets. Used as packet number by the 0x408 data handler | handler 0x408 passes `u16@6` to `__Fill_ReadBuf` | OBSERVED (0 for LAN) |
| 0x08 | 2 | LE | opcode | `_IOTC_Packet_Handler` dispatches on `*(u16*)(pkt+8)` | handler line 4237 | OBSERVED |
| 0x0a | 1 | - | direction/role byte | 0x21 in 0x601/0x603/0x604 and 0x301; 0x12 in 0x602; 0x33 in 0x401/0x402/0x403/0x405; 0x24 in 0x801; 0x18 in 0x1007 | constants at 0x10b008, 0x10b040, 0x10afe8, 0x10afa0 | values OBSERVED; meaning INFERRED (low nibble = sender role, high nibble = receiver role; 1 = client, 2 = device) |
| 0x0b | 1 | bits | flags 2 | bit1 (0x02; bit 9 of `u16@0x0a`) = "sender has no free session". The client reads it in 0x602. The knock builder sets it when all session slots are in use | handler 0x602 `(u16@10 >> 9) & 1`; `FUN_0013699c` | OBSERVED |
| 0x0c | 2 | LE | relay session id | 0 in LAN packets. Used for session lookup in 0x408/0x428/0x521 when flags bit3 = 0 | handler 0x408 | OBSERVED (0 for LAN) |
| 0x0e | 1 | - | channel id | 0 in LAN packets. In 0x602 the client resets the sequence counters of channel `pkt[0x0e]` | handler 0x602 | OBSERVED |
| 0x0f | 1 | - | per-opcode byte | In 0x601/0x603/0x604: 1 = search request, 0 = connect request. The device side does not read it | `FUN_001254a0` param_1 | OBSERVED |

There is no extended header in the LAN opcodes. The payload starts at 0x10.

### 1.1 Transcode on send

- All LAN builders call `FUN_00116eac(src, dst, len, enc_len)` with `enc_len = len` (full packet) unless flags bit0 was set before the send, then `enc_len = 0x40` and bytes from 0x40 are copied as plaintext (OBSERVED: `iotc_SendMessage`, `Broadcast_Message_By_Netmask`, `_IOTC_SendQuryDevice5`).
- The sender sets flags bit1 (`|= 2`) in the plaintext before the transcode (OBSERVED).
- No LAN search or LAN connect builder sets bit0. LAN packets are fully transcoded (OBSERVED).
- The output buffer is 1500 bytes, zero-filled before the transcode (OBSERVED). Only `len` bytes are sent.

### 1.2 Decode on receive (`FUN_00138f10@00138f10`, the LAN socket receive callback)

1. Ignore datagrams with length <= 11.
2. If the first u32 (LE, not transcoded) is `0x0000cc51`, the datagram is a "record" envelope. It goes to `iotcRecordHandler@0012ea9c`. That is a different protocol (section 8, U6).
3. If length >= 16: decode the first 16 bytes with `FUN_00117168(pkt, hdr, len, 0x10)`.
4. Require magic `0x0204`, `size < 0x579`, `size + 16 == len`.
5. If flags bit0 = 0: decode `size` payload bytes. If bit0 = 1: decode only the first 0x30 payload bytes; the remainder is plaintext.
6. Call `_IOTC_Packet_Handler(hdr+payload, from_ip_string, from_port, socket, 0)`.

INFERRED: the header block and the payload are decoded in two separate calls, and the encoder makes one call for the full packet. Thus the transcode works on independent 16-byte blocks from offset 0, and the tail (`len mod 16` bytes) is handled alone. A packet encoder that processes 16-byte blocks in sequence gives the same result.

---

## 2. LAN search request (0x601 / 0x603 / 0x604), 88 bytes

Builder: `FUN_001254a0@001254a0(byte15, uid, random_id, type, dst_ip, dst_port, round, port16, auth_key)`. A second inline copy is in `IOTC_Lan_Search2_Ex@00125684`. Total length 0x58, payload size 0x48.

| Off | Size | Endian | Field | Value / meaning | Evidence | Status |
|---|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | `04 02` | `local_bac = 0x204` | OBSERVED |
| 0x02 | 1 | - | version | `1d` | `local_baa = 0x1d` | OBSERVED |
| 0x03 | 1 | - | flags | `02` on the wire | `local_ba9 = 2`, or `|= 2` in `Broadcast_Message_By_Netmask` | OBSERVED |
| 0x04 | 2 | LE | payload size | `48 00` | `DAT_0010b008 = 48 00 00 00 01 06 21 00` | OBSERVED |
| 0x06 | 2 | LE | sequence | `00 00` | same constant | OBSERVED |
| 0x08 | 2 | LE | opcode | `01 06` (0x0601) default. `03 06` if `type == 0` and `round != 0`. `04 06` if `port16 != 0` (this has priority over 0x603) | `uStack_ba4 = 0x603 / 0x604` | OBSERVED |
| 0x0a | 1 | - | direction | `21` | constant | OBSERVED |
| 0x0b | 4 | - | zero | `00 00 00 00` (0x0b..0x0e) | `local_ba1` | OBSERVED |
| 0x0f | 1 | - | byte15 | `01` for search (`IOTC_Lan_Search*`, `IOTC_Search_Device_Start`). `00` for connect | `local_b9d = param_1` | OBSERVED |
| 0x10 | 20 | bytes | UID | Search: 20 zero bytes. Connect: 20-character UID, upper case | `local_b9c`, `uStack_b94`, `local_b8c` | OBSERVED |
| 0x24 | 12 | - | zero | zero | `local_b8c` high half, `uStack_b84` | OBSERVED |
| 0x30 | 4 | - | zero | zero | low half of `local_b7c = 0x0403080000000000` | OBSERVED |
| 0x34 | 4 | LE | SDK version | `00 08 03 04` (0x04030800). The device stores it in its session+0x58 | `local_b7c`; device side handler 0x601 reads `u32@0x34` | OBSERVED |
| 0x38 | 8 | 2 x LE u32 | client random ID | Search: zero. Connect: session+0x20 (u32) then session+0x24 (u32). See 4.2 | `uStack_b74 = *param_3` | OBSERVED |
| 0x40 | 4 | LE | type | 0 = search. 1 = LAN connect request. 2 = LAN connect confirm | `local_b6c = param_4`; device side handler reads `u32@0x40` | OBSERVED |
| 0x44 | 4 | LE | search round | 0 for 0x601. 1..15 for 0x603 (`iteration & 0xf`). Only written when `type == 0` | `local_b6c = round << 32` | OBSERVED |
| 0x48 | 2 | LE | port16 | 0, or the value for 0x604 (`IOTC_Search_Device_Start_ByPort`, `IOTC_Connect_ByUID_Parallel_ByPort`). The device passes it to `is_iotcport_accepted` | `sStack_b64 = param_8` | OBSERVED |
| 0x4a | 8 | bytes | authKey | Search: zero. Connect request (type 1): 8 ASCII characters from `St_IOTCConnectInput.authKey` (session+0x16cc). Connect confirm (type 2): zero | `uStack_b62`, `uStack_b5c` from `*param_9`; confirm call passes NULL | OBSERVED (type 2 NULL argument is INFERRED from the stack write `local_c0 = 0`) |
| 0x52 | 6 | - | zero | zero | `uStack_b5a` | OBSERVED |

Plaintext of the first search packet (before transcode), 88 bytes:

```
04 02 1d 02 48 00 00 00 01 06 21 00 00 00 00 01
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 08 03 04 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
```

For round `n` (1..15): bytes 0x08..0x09 = `03 06` and bytes 0x44..0x47 = `n 00 00 00`.

### 2.1 Variants and schedule

| API | Opcode sequence | Interval | Count | Evidence | Status |
|---|---|---|---|---|---|
| `IOTC_Lan_Search@001258a4`, `IOTC_Lan_Search2@0012536c` | iteration `i` (from 0): `round = i & 0xf`. 0x601 when round = 0, else 0x603 | `usleep(50000)` = 50 ms | `ceil(timeout_ms / 50)` | loop with `(param_3 + 0x31) / 0x32` | OBSERVED |
| `IOTC_Lan_Search2_Ex@00125684` | always 0x601, round 0 | `interval_ms` argument | until `timeout_ms` is used | inline builder | OBSERVED |
| `IOTC_Search_Device_Start@00125ff4` (task `FUN_001261a4@001261a4`) | same as Lan_Search2; 0x604 if a port was set (`DAT_0015222c`) | default 50 ms; a non-zero argument is used with minimum 10 ms | until the timeout argument | `tutk_TaskMng_Create(uVar1,param_1,...)` | OBSERVED |

Device-side rule for 0x603 (same library, handler line 7801): the device makes a random slot `rand() % 15 + 1` one time and answers 0x603 only when `u32@0x44` equals its slot. It answers each 0x601. Thus each device answers 2 of each 16 packets (OBSERVED).

Device-side rule for type 0: the device answers only if "LAN detectable" is on (`DAT_0014cf65 == 0`) and `is_iotcport_accepted(port16)` is true (OBSERVED).

### 2.2 Addressing

| Item | Value | Evidence | Status |
|---|---|---|---|
| Destination UDP port | `DAT_0014c798`, initial value 0x7ff9 = **32761**. `IOTC_Set_LanSearchPort@00131e64` changes it (accepts 0..65535) | ELF .data bytes `f9 7f` at 0x14c798 | OBSERVED |
| Device listen port | `IOTC_Device_Login@00120b94` uses the same global `DAT_0014c798` (byte-swapped) for a socket | line 10084 | OBSERVED use; bind is INFERRED |
| Ports 32768 and 63616 | No reference found in the decompile (no 0x8000 or 0xf880 port constant) | grep | NOT FOUND |
| Destination address | For each local interface from `tutk_Net_GetInterfaceInfo` with `ip != 0` and last netmask octet = 0: `ip OR (NOT netmask)` (directed broadcast). `sin_family = 2` (IPv4 only) | `Broadcast_Message_By_Netmask@001175fc` | OBSERVED |
| 255.255.255.255 | Not used | same | OBSERVED |
| Source socket | One shared UDP socket `DAT_0014e4c8`, created by `FUN_00138d74@00138d74`. Local port = `DAT_0014e498` = the argument of `IOTC_Initialize(port)`; 0 gives an ephemeral port. The port in use is written back to `DAT_0014e498` | `FUN_00138d74`, `IOTC_Initialize2` line 11624 | OBSERVED |
| Receive buffer | 0x588 bytes | `local_40 = 0x588` | OBSERVED |
| Response path | The device sends 0x602 as unicast to the source IP and source port of the request. The client receives it on the same socket | `FUN_001354f4(param_2,param_3,...)` | OBSERVED |
| Unicast variant | If `dst_ip != NULL`, `FUN_001254a0` sends one unicast packet to `dst_ip:dst_port` (used for type 2) | `param_5 != 0` branch | OBSERVED |

---

## 3. LAN search response (0x602)

Parser: `_IOTC_Packet_Handler@00118864`, branch `opcode == 0x602` (decompile lines 8440-8745). Builder on the device side (same library): `FUN_001354f4@001354f4` (0xc8 bytes) and the legacy builder at handler line 7821 (0xb8 bytes).

### 3.1 Current format: total 200 bytes (0xc8), payload size 0xb8

The client takes this branch when `payload size >= 0xb8`.

| Off | Size | Endian | Field | Value / meaning | Evidence | Status |
|---|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | `04 02` | builder | OBSERVED |
| 0x02 | 1 | - | device protocol version | Client stores it in session+0xb07. Compared with 7 and 0x17 | handler | OBSERVED |
| 0x03 | 1 | bits | flags | bit1 -> session+0xb04 | handler line 8667 | OBSERVED |
| 0x04 | 2 | LE | payload size | `b8 00` | `DAT_0010b040 = b8 00 00 00 02 06 12 00` | OBSERVED |
| 0x06 | 2 | LE | sequence | 0 | constant | OBSERVED |
| 0x08 | 2 | LE | opcode | `02 06` | constant | OBSERVED |
| 0x0a | 1 | - | direction | `12` | constant | OBSERVED |
| 0x0b | 1 | bits | flags 2 | bit1 = device has no free session. Client then sets error flag session+0xa30 (device version < 7) or session+0xa31 | handler lines 8640, 8682 | OBSERVED |
| 0x0c | 2 | LE | zero | 0 | `local_ba0 = 0` | OBSERVED |
| 0x0e | 1 | - | channel | 0. Client resets counters of this channel | handler line 8659 | OBSERVED |
| 0x0f | 1 | - | zero | 0 | builder | OBSERVED |
| 0x10 | 20 | bytes | device UID | upper case, no terminator | `local_b9c` from `DAT_0014e51c` | OBSERVED |
| 0x24 | 16 | - | address slot | 16 zero bytes in this format | `local_b88`, `uStack_b80 = 0` | OBSERVED |
| 0x34 | 128 | bytes | device name | from `IOTC_Set_Device_Name` buffer 0x14cee4, zero padded | builder | OBSERVED |
| 0xb4 | 4 | LE | name terminator | byte 0x14cf64 (0) zero-extended | `_local_af8` low half | OBSERVED |
| 0xb8 | 4 | LE | device SDK version | e.g. `00 08 03 04`. Client stores it in session+0x58 | `_local_af8` high half; handler line 8666 | OBSERVED |
| 0xbc | 8 | 2 x LE u32 | random ID echo | copy of request bytes 0x38..0x3f. Zero for a search response | `uStack_af0 = *param_3`; handler lines 8592-8593 | OBSERVED |
| 0xc4 | 4 | LE | result type | see 3.3 | `local_ae8 = param_4`; handler `*(int*)(pkt+0xc4)` | OBSERVED |

Client use for search (OBSERVED):
- A search result is recorded only when a search is active (`DAT_0015194c` bit0 or `DAT_001518d8 != 0`) and `u32@0xc4 == 0`.
- UID = `pkt+0x10`. Device name = C string at `pkt+0x34`. **IP and port are the UDP source address of the datagram**, not a packet field (`FUN_00135e44@00135e44(pkt+0x10, from_ip, from_port, pkt+0x34)`).
- Duplicates with the same UID + IP + port are dropped (`FUN_0013648c@0013648c`).
- If a search with a result buffer is active (`DAT_0015194c` bit0), processing stops after the record. No connect logic runs.

### 3.2 Legacy formats (payload size < 0xb8)

The client accepts them when `payload size > 0x23`.

| Payload size | Total | Layout | Evidence | Status |
|---|---|---|---|---|
| 0xa8 | 0xb8 | header; UID @0x10 (20); @0x24 `02 00`; @0x26 u16 = requester port as the device saw it (byte order as received from the device socket layer); @0x28 u32 = `inet_addr(requester IP)` (network order); @0x2c 8 zero; name @0x34 (128); @0xb4 terminator + 3 zero. The client forces `pkt[0xb4] = 0` | device builder at handler line 7821 (`DAT_0010afa8 = a8 00 00 00 02 06 12 00`); client line 8469 | OBSERVED |
| 0x24 | 0x34 | header; UID @0x10; 16-byte address @0x24. No name; the client records the name `" "` | client line 8474 | OBSERVED (device builder not in this library) |
| other | - | no search record | client line 8474 | OBSERVED |

A device with this library sends the 0xa8 format when the request payload size is < 0x34 (old clients). A request of 88 bytes gets the 0xc8-byte format.

Legacy connect path (client, payload < 0xb8, active connecting session with the same UID): the client sends `_IOTC_Send_Punch_To` (opcode 0x301, 52 bytes) and a knock `FUN_0013699c` (opcode 0x401, or 0x403 with a port). If `St_IOTCConnectInput` was given and authKey is not `"00000000"`, the client sets error state session+0xa38 = 3 instead. This path is for old devices (OBSERVED; not necessary for a device that sends the 0xc8 format).

### 3.3 Result type (`u32@0xc4`) and client reaction

Session match rule (OBSERVED, handler lines 8592-8606): the client finds the session where session+0x28 == 0, session+0x20 == `u32@0xbc`, session+0x24 == `u32@0xc0`; `u32@0xbc` must not be 0; the random ID must not be in the "recently closed" list (`FUN_001359a8`, 20 s window); the UID at 0x10 must be equal to the session UID (`FUN_001356f0`, 20 bytes, stops at NUL).

| Type | Device-side condition (same library, handler lines 7880-8126) | Client reaction | API error from `CheckConnectErrors@0012b0a8` | Status |
|---|---|---|---|---|
| 0 | answer to type 0 search | record search result | - | OBSERVED |
| 1 | connect accepted, authKey check passed | LAN connect success path (4.3). Also sets session+0x1780 = 1 when the device version >= 0x17 | - | OBSERVED |
| 7 | connect accepted; the device has authKey disabled, client version >= 0x1b, and client authKey is not alphanumeric or is `"00000000"` | same as type 1 but session+0x1780 is not set | - | OBSERVED |
| 3 | no free pre-session slot on the device | if LAN state = 1: session+0xa31 = 1 | 0xffffffd0 (-48) | OBSERVED |
| 4 | port not accepted or duplicate random ID | if LAN state = 1: session+0x16c2 = 1 | 0xffffffbd (-67) | OBSERVED |
| 5 | authKey mismatch (device authKey enabled, request authKey != device key) | if LAN state = 1: session+0xa38 = 2 | 0xffffffbc (-68) | OBSERVED |
| 6 | device authKey disabled and client sent a real key | if LAN state = 1: session+0xa38 = 3 | 0xffffffbb (-69) | OBSERVED |

Notes (OBSERVED):
- A device with authKey enabled (`DAT_0015017c` bit0 = 0) does not answer a type 1 request with payload size < 0x48.
- For types 1 and 7 the client ignores the packet when LAN state is -1, 0, 2 or 6.
- For types 1 and 7, if the client has a `St_IOTCConnectInput` (session+0x1764 == 0) and the device version byte is < 0x17: LAN state must be 1, and a client authKey different from `"00000000"` gives session+0xa38 = 3 (error -69).
- For types 1 and 7, if flags-2 bit1 is set, the client does not connect. It sets session+0xa30 (device version < 7, error 0xffffffe8 = -24) or session+0xa31 (error -48).

---

## 4. LAN connect sequence

Entry: `IOTC_Connect_ByUIDEx@001207b0` -> `IOTC_Connect_UDP_Inner@0012b408(uid, sid, 0, input, NULL, 0)`.

### 4.1 `St_IOTCConnectInput` (size 0xa0)

Evidence: JNI wrapper `Java_com_tutk_IOTC_IOTCAPIs_IOTC_1Connect_1ByUIDEx@00112f88` (field names from JNI strings), checks in `IOTC_Connect_ByUIDEx`, copy to session+0x16c4 in `IOTC_Connect_UDP_Inner`.

| Off | Size | Field | Rule / use | Status |
|---|---|---|---|---|
| 0x00 | 4 | cb | must be 0xa0, else 0xffffffd2 (-46) | OBSERVED |
| 0x04 | 4 | authenticationType | must be 0, else -46 | OBSERVED |
| 0x08 | 8 | authKey | 8 characters, each `[0-9A-Za-z]` (`FUN_0012213c@0012213c`), else -46. Sent at request offset 0x4a | OBSERVED |
| 0x10 | 0x81 | deviceRegion | C string, max 128 characters. Not used by LAN | OBSERVED (LAN non-use INFERRED) |
| 0x94 | 4 | timeout | seconds. 0 = no API timeout. On expiry the API returns 0xfffffff3 (-13) | OBSERVED |
| 0x98 | 4 | dataTransmitMode | must be < 3. Value 1 returns 0xffffffc1 (-63). LAN broadcast is sent only for values 0 and 2 | OBSERVED |
| 0x9c | 1 | lanModeDisable | 1 = no LAN search task (LAN state 2) | OBSERVED |
| 0x9d | 1 | p2pModeDisable | not used by the LAN path | OBSERVED name; use not read |
| 0x9e | 2 | padding | - | INFERRED |

Other input rules (OBSERVED): the UID must have 20 characters `[0-9A-Za-z]`, else 0xfffffff6 (-10). The session id must come from `IOTC_Get_SessionID` (slot state 1), else 0xfffffff2 (-14). `IOTC_Connect_ByUID` (no input struct) keeps session+0x1764 = 0xffffffff, which means "no authKey mode".

### 4.2 Setup in `IOTC_Connect_UDP_Inner`

| Step | Detail | Evidence | Status |
|---|---|---|---|
| UID normalisation | each UID byte > 0x5a gets -0x20 (lower case to upper case); 20 bytes stored at session+0x00 | lines 17714-17801 | OBSERVED |
| Socket | `FUN_00138d74` opens the shared UDP socket if it is not open | line 17928 | OBSERVED |
| Random ID low word | session+0x20 (u32) = `seq16 + (gsLocalNetworkInfo[0xac] << 16)`. `seq16 = (rand() + time()) % 0xffff`, 0 becomes 1; later connects use `previous + 1` | lines 17964-17977 | OBSERVED |
| Random ID high word | session+0x24 (u32) = `gsLocalNetworkInfo[0xa8]` | line 17978 | OBSERVED |
| `gsLocalNetworkInfo` | from the interface MAC `m0..m5`: `[0xac] = (m0 << 8) | m1`, `[0xa8] = (m2 << 24) | (m3 << 16) | (m4 << 8) | m5`. If a value is 0, a random non-zero value replaces it | function at lines 13940-14077 | OBSERVED |
| Wire bytes at 0x38 | `seq_lo, seq_hi, m1, m0, m5, m4, m3, m2` | from the two rows above | INFERRED |
| Minimum rule | the first u32 of the random ID must not be 0 (device lookup `FUN_00135890` and client match reject 0) | `FUN_00135890@00135890`, handler line 8597 | OBSERVED |
| Master resolve | `IOTC_Resolve_MasterServer_Name` starts a thread (not when `param_6 & 1`). It does not block the LAN task | lines 17993-17998 | OBSERVED |
| LAN task | `AddLanSearchTask(session)` | line 18000 | OBSERVED |
| Other setup | nonces (`iotcUpdateNonce`), AES info, ECDH key pair are made for the P2P/relay paths. No LAN packet in this spec carries them | lines 17988-17992 | OBSERVED (non-use in LAN packets INFERRED) |

A clean-room client can use any 8 bytes with a non-zero first u32 as the random ID (INFERRED: the device only stores and echoes the value).

### 4.3 LAN state machine (session+0x54)

| Value | Meaning | Set by | Status |
|---|---|---|---|
| 0 | idle | `IOTC_Connect_UDP_Inner` | OBSERVED |
| 1 | LAN search in progress | `AddLanSearchTask@001278ac` | OBSERVED |
| 2 | LAN disabled (`lanModeDisable == 1` or `IOTC_Setup_LANConnection_Timeout(0)`) | `AddLanSearchTask` | OBSERVED |
| 3 | legacy response received (payload < 0xb8) | handler line 8529 | OBSERVED |
| 4 | read by the task (send type 2 to session+0x40) but never written in this build | grep of all `+0x54) =` writes | OBSERVED |
| 5 | device side only (pre-session accepted) | handler line 8038 | OBSERVED |
| 6 | LAN connected | handler line 8672 | OBSERVED |
| -1 | LAN failed or timed out | task `FUN_0012798c@0012798c` | OBSERVED |

### 4.4 Ordered packet list (client view, current-format device)

| # | Direction | Packet | Content | Timing | Evidence | Status |
|---|---|---|---|---|---|---|
| 1 | client -> broadcast:32761 | 0x601 (88 bytes), or 0x604 if a port was given | byte15 = 0; UID; random ID @0x38; type = 1 @0x40; round = 0; port16 = session+0x72; authKey @0x4a | each 100 ms while LAN state is 1 or 3 and `dataTransmitMode` is 0 or 2. Task lifetime = LAN timeout: `DAT_0014c598` ms (`IOTC_Setup_LANConnection_Timeout`); default -1 gives 60000 ms | `AddLanSearchTask`, `FUN_0012798c` | OBSERVED |
| 2 | device -> client (unicast to the source port) | 0x602 (200 bytes) | UID @0x10; random ID echo @0xbc; type @0xc4 = 1 or 7 (or an error type 3/4/5/6) | the device repeats type 1 each 100 ms for up to 30 s until it gets step 3 (`AddLanSearchPrecheckRTask@00127674`, `FUN_00127718`); the device pre-session lives 60 s | handler 0x601 device branch, `FUN_00135b90` | OBSERVED |
| 3 | client -> device (unicast to the source address of step 2) | 0x601 (88 bytes) | byte15 = 0; UID; random ID; type = 2; round = 0; port16 = 0; authKey = zero | sent one time for each accepted 0x602 type 1/7 that arrives while the state is not 6 (so step 2 repeats cause step 3 repeats until state 6). Not sent if flags-2 bit1 is set | handler lines 8640-8643 | OBSERVED |
| 4 | (local) | none | session+0x4a6 = 2; session+0x98 = 2 if the peer IP is private (10/8, 172.16/12, 192.168/16) (`FUN_00136290`); UID copied from the packet; session+0xb07 = device version; session+0xb04 = device flags bit1; session+0x58 = device SDK version; `FUN_00118314(0, sid, socket, ip, port)` stores the peer address at session+0x40 and session+0xdc, send mode session+0xb40 = 0, session state byte +0x19 = 2; LAN state = 6 | - | handler lines 8645-8672 | OBSERVED |
| 5 | (local) | `SendConnectResult@00126400(sid,0,0,0,0,0)` | builds record 0x806 for `iotcRecordSendP2PHandshake@0012648c`. This is a report to P2P servers of the session; with no server entry nothing goes on the wire | - | line 8675 | call OBSERVED; "nothing on the wire" INFERRED |
| 6 | (local) | connect loop exit | the loop in `IOTC_Connect_UDP_Inner` polls each 10 ms (`usleep(10000)`) and exits when LAN state == 6. The API returns the session id | - | lines 18152-18163, 18225 | OBSERVED |
| 7 | client -> server | 0x801 (56 bytes) from `SendConnectSuccess@00127300` | only when a server entry exists (session+0xae8 >= 0 with a non-zero server port, or session+0xb50 == 0x14). Initial session+0xae8 = -1 | after step 6 | `SendConnectSuccess`, line 10403 | OBSERVED; "not sent in LAN-only" INFERRED |
| 8 | client -> device | 0x402 (52 bytes if device version >= 10, else 40 bytes); 0x405 if port16 != 0 | header `04 02 1d 02`, size 0x24 (or 0x18), opcode `02 04`, direction `33`; UID @0x10; random ID @0x24 (8 bytes; only the first u32 when version < 10); u16 port @0x2c (0x405 only); SDK version `00 08 03 04` @0x30 | each 500 ms for max 5000 ms, only if session+0x98 is 0 or 2 and session+0xb08 == 0. Stops when session+0xb08 becomes 1 (any 0x408 data packet or 0x428 packet from the device) | `AddSendKnockRWhenDeviceNotResponseTask@0012ac94`, `FUN_0012ad3c@0012ad3c`; handler lines 5306, 7641 | OBSERVED |
| 9 | both | session traffic (0x407/0x408 data, 0x427/0x428 keep-alive) | not in the scope of this document | - | - | - |

Device-side transition for step 3 (OBSERVED, handler lines 7881-7986): on type 2 with a known random ID, the device moves the pre-session to a real session, sets its LAN state to 6, and stops step 2.

### 4.5 Timeouts and intervals

| Item | Value | Evidence | Status |
|---|---|---|---|
| Connect broadcast interval | 100 ms | `tutk_TaskMng_Create(100, timeout, 0, FUN_0012798c, session)` | OBSERVED |
| LAN task timeout | `DAT_0014c598` ms; if < 1 then 60000 ms; if exactly 0 the LAN stage is skipped | `AddLanSearchTask` | OBSERVED |
| Early LAN stop | when the server path is ready (session+0xb4c == 6 or session+0xb50 == 0xc, and session+0xb60 == 2), LAN state 1 becomes -1 after `DAT_0014c598` ms of task time, or 1500 ms when that value is < 1 | `FUN_0012798c` lines 15377-15384 | OBSERVED |
| Connect poll | 10 ms | `usleep(10000)` | OBSERVED |
| API timeout | `St_IOTCConnectInput.timeout` seconds -> return -13 | lines 18156-18161 | OBSERVED |
| No-master timeout | if master state `DAT_001502c8 == 3` and 60 s passed since connect start -> return 0xfffffffe (-2). `CheckPreConnectState@0012a1a8` returns -2 at once when LAN state == -1 and master state == 3 | lines 18064-18069, 16750-16757 | OBSERVED |
| Device repeat of 0x602 type 1 | 100 ms, 30 s | `AddLanSearchPrecheckRTask` | OBSERVED |
| Recent random ID block | 20 s | `FUN_001359a8@001359a8` | OBSERVED |
| Knock-R after connect | 500 ms, 5 s | `AddSendKnockRWhenDeviceNotResponseTask` | OBSERVED |
| Search interval | 50 ms | `IOTC_Lan_Search2` | OBSERVED |

### 4.6 Auxiliary packet layouts (legacy path, for reference)

`_IOTC_Send_Punch_To@001179b4`, 52 bytes (sent only if the destination is different from the embedded address):

| Off | Size | Field | Value | Status |
|---|---|---|---|---|
| 0x00 | 4 | magic, version, flags | `04 02 1d 02` | OBSERVED |
| 0x04 | 8 | size, seq, opcode, direction | `24 00 00 00 01 03 21 00` (opcode 0x0301) | OBSERVED (0x10afe8) |
| 0x0c | 4 | zero | 0 | OBSERVED |
| 0x10 | 20 | UID | - | OBSERVED |
| 0x24 | 16 | address | 16 bytes copied from 0x602 offset 0x24 | OBSERVED |

`FUN_0013699c@0013699c` knock, 40 or 52 bytes:

| Off | Size | Field | Value | Status |
|---|---|---|---|---|
| 0x00 | 4 | magic, version, flags | `04 02 1d 02` | OBSERVED |
| 0x04 | 2 | payload size | 0x18 (peer version < 10) or 0x24 | OBSERVED |
| 0x08 | 2 | opcode | 0x0401; 0x0403 when a port is given | OBSERVED |
| 0x0a | 1 | direction | 0x33 | OBSERVED |
| 0x0b | 1 | flags 2 | 0x02 if all local session slots are in use, else 0 | OBSERVED |
| 0x0f | 1 | byte15 | caller value (1 in the legacy LAN path) | OBSERVED |
| 0x10 | 20 | UID | - | OBSERVED |
| 0x24 | 8 | random ID | version >= 10: 8 bytes. version < 10: u32 session+0x20 only | OBSERVED |
| 0x2c | 4 | port | u16 port for 0x403, else 0 | OBSERVED |
| 0x30 | 4 | SDK version | `00 08 03 04` | OBSERVED |

`SendConnectSuccess@00127300`, 56 bytes, to a server: `04 02 1d 02`, size 0x28, opcode 0x0801, direction 0x24; UID @0x10; 16-byte peer address (session+0xdc) @0x24; @0x34 session byte +0x1a; @0x35 NAT type; @0x36 session byte +0x98 (OBSERVED).

---

## 5. Search result structures (client API output)

Filled by `FUN_00136758@00136758`. The port is stored as `bswap16(port from receive callback)`.

| API | Entry size | UID | IP string | Port (u16) | Name | Other | Status |
|---|---|---|---|---|---|---|---|
| `IOTC_Lan_Search` | 0x2a | @0x00, 20 + NUL | @0x15, max 16 | @0x26 | none | - | OBSERVED |
| `IOTC_Lan_Search2`, `_Ex` | 0xae | @0x00, 20 + NUL | @0x15, max 16 | @0x26 | @0x28, max 0x84 | - | OBSERVED |
| `IOTC_Search_Device_Result@00126240` | 0xd0 | @0x00, 20 + NUL | @0x15, max 0x2e | @0x44 | @0x46, max 0x84 | @0xcc u32 "new" flag (1 until reported) | OBSERVED |

`gSearchDeviceCB` (pointer at 0x147c08): if set, it is called as `cb(array, count)` for each new device (OBSERVED, `FUN_00135e44`). `stLanSearchRespFieldIDs` is a JNI field-ID cache and has no wire meaning (INFERRED from the name; not read).

---

## 6. Master and licence dependence

| Step | Master / server necessary? | Licence necessary? | Evidence | Status |
|---|---|---|---|---|
| Transcode key | no | The key is XORed with the licence `keyMask` if a licence with that field was set | section 0 | OBSERVED |
| `IOTC_Initialize2` | no network access in the parts read | no check seen that blocks LAN | lines 11419-11650 | INFERRED |
| LAN search (0x601/0x603/0x604 type 0 -> 0x602 type 0) | no. Needs only the initialized module state (`DAT_0014c8d8` not 0 or 3) and the UDP socket | no check in the path | `IOTC_Lan_Search2`, `FUN_001254a0` | OBSERVED |
| LAN connect steps 1-6 | no. The LAN task starts before any master result, and the loop exits on LAN state 6 in each 10 ms cycle | no check in the path | `IOTC_Connect_UDP_Inner` | OBSERVED |
| Connect with master unreachable | LAN connect can still succeed. If LAN does not succeed and master state becomes 3, the API returns -2 (immediately after LAN state -1, or after 60 s) | - | section 4.5 | OBSERVED |
| `_IOTC_SendQuryDevice5` (0x1007), `AddUDPQueryDeviceInfoTask`, `AddUDPPreCheckTask`, `AddUDPP2PConnectTask`, relay tasks | yes, these start only when master state is 1 or 2 (or `param_6 & 1`). They use `GetRealm` (licence realm) | realm string from the licence | lines 18017-18061, 3464 | OBSERVED |
| `SendConnectSuccess` (0x801), `SendConnectResult` (record 0x806) | sent to servers only | - | section 4.4 | INFERRED for LAN-only |
| Device authKey | not a master item. The device compares request bytes 0x4a..0x51 with its local key | - | handler line 7997 | OBSERVED |

---

## 7. Minimum clean-room client procedure (summary)

1. Open one UDP socket (IPv4, broadcast permitted). Use it for all sends and receives.
2. Search: send the 88-byte request (type 0, byte15 = 1, UID zero) to `<directed broadcast>:32761` each 50 ms; opcode 0x601 with round 0, or 0x603 with round 1..15.
3. Decode each datagram: header block (16 bytes), then payload. Accept opcode 0x602 with payload size >= 0xb8 and `u32@0xc4 == 0`. Take UID @0x10, name @0x34, IP and port from the UDP source.
4. Connect: send the 88-byte request (type 1, byte15 = 0, upper-case UID, random ID with non-zero first u32, authKey @0x4a) each 100 ms to broadcast:32761 (INFERRED: a unicast send to the known device IP on port 32761 is also accepted, because the device handler does not check the destination address).
5. On 0x602 with the same random ID @0xbc and the same UID: type 1 or 7 and flags-2 bit1 clear -> send the 88-byte request with type 2 (authKey zero) as unicast to the source address of the 0x602. The session is then open on that address pair. Types 3, 4, 5, 6 are errors.
6. Then send 0x402 each 500 ms (max 5 s) until the first 0x408 or 0x428 arrives from the device.

---

## 8. UNKNOWNS

| Id | Item | Detail |
|---|---|---|
| U1 | Licence `keyMask` | The 16-byte mask that is XORed into the transcode key comes from the app licence key (JSON field `keyMask`, base64). The licence string of the user's app and thus the mask were not examined. If the app does not call `TUTK_SDK_Set_License_Key`, or the licence has no `keyMask`, the key is the plain `"Charlie is the d"`. Check: decode a captured 88-byte broadcast and look for `04 02 1d 02 48 00`. |
| U2 | Ports 32768 and 63616 | No constant found in `libIOTCAPIs.so`. Only 32761 (0x7ff9) is the LAN port default. 63616 can be an ephemeral source port or a value from the app (`IOTC_Initialize(port)` / `IOTC_Set_LanSearchPort`); not resolved. |
| U3 | Header byte 0x0a nibbles | Values are OBSERVED; the role meaning (1 = client, 2 = device, 3, 4) is INFERRED. |
| U4 | Header flags bit2 (0x04) | The 0x408 handler drops packets with this bit. Meaning not resolved. |
| U5 | Byte order of the port in the receive callback and in the legacy 0xa8 response field @0x26 | The socket layer (`TConnManager`, vtable calls +0x10/+0x28/+0x30) is not in the decompile. The code byte-swaps the callback port before it stores it, which suggests network order in the callback. |
| U6 | `0xcc51` record envelope | `FUN_00138f10` routes datagrams that start with u32 0x0000cc51 to `iotcRecordHandler@0012ea9c` (AES-based). `iotcRecordSendLanCommand@0012dc54` exists but has no caller in this decompile. It is not known if some device firmware answers LAN requests in this envelope. |
| U7 | `is_iotcport_accepted` | The device-side rule for `port16` (0x604) was not read. With port16 = 0 the function is called with 0; a current-format device answered path needs it to return true. |
| U8 | Socket vtable call `+0x50` with argument 0x80 before each 0x402 | Purpose not resolved (possibly a socket option). |
| U9 | `St_IOTCConnectInput` bytes 0x91..0x93 and 0x9e..0x9f | Padding is INFERRED. |
| U10 | Device firmware differences | All device-side statements come from the device code in this same client library (version 0x1d). The real camera firmware can have a different version byte and can use the legacy 0xa8 or 0x24 response formats. |
| U11 | Tail handling of the transcode for lengths that are not a multiple of 16 | Not re-derived here (given as established). 88 and 200 have tails of 8 bytes; 52 and 40 have tails of 4 and 8 bytes. `FUN_00135360@00135360` has special permutations for tail lengths 2, 4, 8 and 16 and a plain copy for other lengths. |
| U12 | IPv6 | `Broadcast_Message_By_Netmask` is IPv4 only. IPv6 LAN behaviour was not examined. |
