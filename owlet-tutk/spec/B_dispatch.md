# B. IOTC UDP packet dispatch map and device-side response spec

Source: Ghidra output `iotc_all.c` (line numbers below refer to this file) and raw ELF `libIOTCAPIs.so` (aarch64, Ghidra base 0x100000).
Tags: **OBS** = OBSERVED in code. **INF** = INFERRED from code behavior. All multi-byte fields are little-endian unless the table says otherwise.

Names of opcodes are labels made for this document. They are not vendor names.

---

## 1. Receive path, validation and decode

### 1.1 Callers of `_IOTC_Packet_Handler`

| Path | Function | Evidence |
|---|---|---|
| UDP datagram | `FUN_00138f10(sock, ipStr, port, buf, len)` | line 30562 |
| TCP stream | `FUN_00138784(sock, ipStr, port, buf, len, ...)` | line 30272 |
| Handler | `_IOTC_Packet_Handler(pkt, ipStr, port, sock, isTcp)` @00118864 | line 4064 |

`pkt` is the decoded packet (header + payload). `ipStr` is the sender IP as text. `port` is the sender port. `sock` is the socket object that received the data. `isTcp` is 0 for UDP and 1 for TCP. (OBS)

### 1.2 UDP validation steps (`FUN_00138f10`) (OBS)

1. Drop the datagram if `len < 12`.
2. If the first u32 is `0x0000CC51`, send the datagram to `iotcRecordHandler` @0012ea9c. This is a different framing. See section 6.
3. Drop the datagram if `len < 16`.
4. Decode the first 0x10 bytes: `FUN_00117168(buf, out, len, 0x10)`.
5. Drop if decoded u16 @0 is not `0x0204` (wire bytes `04 02` after decode).
6. Drop if decoded u16 @4 (payload length) is more than `0x578`.
7. Drop if `payloadLen + 0x10 != len`. The length must be exact.
8. Decode the payload with a second call: `FUN_00117168(buf+0x10, out+0x10, payloadLen, N)`.
   - If header flag bit 0 (byte 3) is 0: `N = payloadLen` (full decode).
   - If header flag bit 0 is 1: `N = 0x30` (only the first 0x30 payload bytes are transcoded; the remaining bytes are copied).
9. Call `_IOTC_Packet_Handler(out, ip, port, sock, 0)`.

The version byte (offset 2) is not examined before dispatch. (OBS)

Send side uses one call for the full packet: `FUN_00116eac(pkt, out, total, total)`. With flag bit 0 set the encode length is `0x40` (`iotc_SendMessage` @00117418 line 3026, `IOTC_Session_Write` line 12997). Thus header (0x10) + first 0x30 payload bytes are encoded. (OBS)
The receive side decodes header and payload as two units. Thus the transcode must give the same result when the data is split at offset 0x10. (INF)

### 1.3 TCP validation (`FUN_00138784`) (OBS)

The function moves one byte at a time through the buffer. At each position it decodes 0x10 bytes and looks for `0x0204`. It then applies the same length limit (`<= 0x578`), waits for more bytes if the packet is not complete, decodes the payload (same bit 0 rule), and calls the handler with `isTcp = 1`. Remaining bytes are processed recursively.

### 1.4 Common header (16 bytes, after decode)

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | `0x0204` | OBS line 30604; all builders |
| 0x02 | 1 | - | version | Sender protocol version. This library writes `0x1D`. Receiver stores it in session +0xB07 | OBS line 13550, 7969 |
| 0x03 | 1 | - | hflags | bit0 = partial transcode. bit1 (0x02) = always set by senders; receiver stores it in session +0xB04. bit2 (0x04) = data and punch-data handlers ignore the packet. bit3 (0x08) = 64-bit RandomID sub-header is present in payload | OBS lines 3020, 5190, 5193, 12976 |
| 0x04 | 2 | LE | payloadLen | Total length minus 0x10 | OBS |
| 0x06 | 2 | LE | seq | Data: per-channel TX sequence. Punch: value echoed in the reply (session +0xB02) | OBS lines 12920, 6153 |
| 0x08 | 2 | LE | opcode | Dispatch value. `uVar6 = *(u16*)(pkt+8)` | OBS line 4237 |
| 0x0A | 2 | LE | dir | `0x21` client to device. `0x12` device to client. `0x33` P2P punch. `0x24`/`0x14` relay. `0x18` master. Bit 9 (`0x200`) = device has no free session | OBS lines 12945, 29535, 29551, 8640 |
| 0x0C | 2 | LE | shortId | 16-bit RandomID (old peers) or relay session id. 0 if not used | OBS lines 12950, 5194 |
| 0x0E | 1 | - | channel | Channel id (0..31) for data. 0 in control packets | OBS line 5305 |
| 0x0F | 1 | - | dtype | Data type (`& 3`) for data. In 0x601 from `IOTC_Lan_Search2_Ex` the value is 1 | OBS lines 12970, 13664 |

### 1.5 Dispatch

The handler reads `opcode = u16 @8` and uses a compare tree (line 4244 to 8437). An opcode that is not in the table causes an immediate return. No error reply is sent. (OBS)

Many master/server branches first call `FUN_0012ca68(ip, ...)` when `isTcp == 0`. This function accepts the packet only if the sender is a known server. (INF from use)

---

## 2. Opcode table

Abbreviations: C = client, D = device, S = master / P2P server, R = relay server.
"RID64" = 8-byte RandomID. "sid lookup" = how the session is found.

### 2.1 LAN-relevant opcodes (full detail in sections 3 and 4)

| Opcode | Label | Direction | Handler summary | Payload fields read | Reply | Evidence |
|---|---|---|---|---|---|---|
| 0x0601 | LAN_SEARCH / LAN_CONNECT request | C to D (broadcast or unicast) | Shared label `LAB_00118b84`. Behavior depends on `payloadLen` and `stage` (u32 @0x40) | See 3.1 | 0x0602 by `FUN_001354f4` @001354f4, or legacy 0x0602 built inline | OBS line 7816 |
| 0x0603 | LAN_SEARCH filtered | C to D | Needs `payloadLen >= 0x48` and u32 @0x44 == `DAT_00152234` (device random value 1..15, made on first use). Then same as 0x0601 | u32 @0x44 | Same as 0x0601 | OBS line 7801 |
| 0x0604 | LAN_SEARCH / CONNECT with port | C to D | Same as 0x0601. Sent when the request has a non-zero port @0x48 | Same as 0x0601 | Same as 0x0601 | OBS line 7813, 13562 |
| 0x0602 | LAN_SEARCH response | D to C | Client side. Short form (`0x24 <= len < 0xB8`): legacy. Long form (`len >= 0xB8`): search result and connect result | See 3.3 | Client sends 0x0601 stage 2 by `FUN_001254a0` @001254a0 | OBS line 8437 |
| 0x0407 | SESSION_DATA (client TX) | C to D | Device side. Finds session. Delivers bytes to `__Fill_ReadBuf` @0011778c or to the channel callback | See 4.1 | None | OBS line 5377 |
| 0x0408 | SESSION_DATA (device TX) | D to C | Client side. Same delivery | See 4.1 | None | OBS line 5187 |
| 0x0427 | SESSION_ALIVE (client TX) | C to D | Device side. Resets alive counter (+0x99 = 0). Can complete the session (see 4.2) | hdr 0x0C or RID64 @0x10 | None from handler. Each side sends its own alive | OBS line 7666 |
| 0x0428 | SESSION_ALIVE (device TX) | D to C | Client side. Resets +0x99. Sets +0xB08 = 1 | Same | None | OBS line 7554 |
| 0x0417 | SESSION_CLOSE (client TX) | C to D | Device side. If state is 2: state = 3. Calls close callback with -22 (`0xFFFFFFEA`) and all 32 channel callbacks with -22 | hdr 0x0C or RID64 @0x10 | None | OBS line 7469 |
| 0x0418 | SESSION_CLOSE (device TX) | D to C | Client side. Same | Same | None | OBS line 7388 |

### 2.2 P2P punch opcodes (also work on LAN addresses; brief)

| Opcode | Label | Direction | Handler summary | Fields | Reply (builder) | Evidence |
|---|---|---|---|---|---|---|
| 0x0401 | P2P_PUNCH | both | Shares code with 0x0403. Finds session by UID+address or RID64 @0x24. Sends punch reply | UID @0x10, RID @0x24 (4 or 8 bytes), ver @0x30 | 0x0402 or 0x0405 by `FUN_001376e8` @001376e8 | OBS line 6745 |
| 0x0403 | P2P_PUNCH with port | C to D | Same. Also reads u16 port @0x2C and checks `is_iotcport_accepted` | + u16 @0x2C | Same | OBS line 6895 |
| 0x0402 | P2P_PUNCH reply | both | Shares code with 0x0405 (`LAB_0011b26c`). Marks session connected. Device role replies | UID @0x10, shortId @0x24 or RID64 @0x24, ver @0x30 | 0x0404 or 0x0406, built inline (line 6328, 6460) | OBS line 6088 |
| 0x0405 | P2P_PUNCH reply with port/accept | both | Same. Reads u16 @0x2C (port) or u8 @0x2C (accept flag) | + @0x2C | 0x0406 | OBS line 6459, 6647 |
| 0x0404 | P2P_CONNECT ack | both | Shares code with 0x0406 (`LAB_0011a64c`). Final step. State becomes 2 | UID @0x10, RID64 @0x24 or shortId @0x24, ver @0x30 | None on wire. `iotcRecordSendP2PHandshake` (record 0x806) | OBS line 5544 |
| 0x0406 | P2P_CONNECT ack with accept flag | both | Same. u8 @0x2C == 0 means "port not accepted" (+0x16C2 = 1) | + u8 @0x2C | None | OBS line 5842 |

If the sender IP is a private LAN address (`FUN_00136290` @00136290: 192.168/16, 172.16/12, 10/8) and connect option byte 3 is 0, these handlers store the address as the LAN path (path 0) and set +0x98 = 2 and +0x54 = 6. (OBS line 5583)

Sender of 0x0401/0x0403: `FUN_0013699c` @0013699c (line 28795). Layout: hdr dir `0x33` (or `0x233`), hdr[0x0F] = arg, UID @0x10, RID @0x24, u16 port @0x2C (0x0403 only), u32 `0x04030800` @0x30. Total 0x28 or 0x34. (OBS)

### 2.3 Relay opcodes (relay-only; brief)

| Opcode | Label | Direction | Summary | Evidence |
|---|---|---|---|---|
| 0x0501 | RELAY_DATA | R to peer | Same delivery as 0x0407 to `__Fill_ReadBuf`. Session found by hdr 0x0C + address (`FUN_0013757c`) or RID64 | OBS line 7153 |
| 0x0503 | RELAY_DATA | R to peer | Same as 0x0501 for the other role | OBS line 7051 |
| 0x0502 / 0x0504 | RELAY_DATA TX | peer to R | Sent by `IOTC_Session_Write` when active path is 2 or 3 (device 0x0502, client 0x0504). Not handled on receive | OBS line 12956 |
| 0x0511 / 0x0513 | RELAY_CLOSE | R to peer | State 2 becomes 3. Callbacks get -22 | OBS line 7248 |
| 0x0512 / 0x0514 | RELAY_CLOSE TX | peer to R | `FUN_0012376c` @0012376c | OBS line 12058 |
| 0x0521 / 0x0523 | RELAY_ALIVE | R to peer | Resets +0x99 | OBS line 8360 |
| 0x0522 / 0x0524 | RELAY_ALIVE TX | peer to R | Alive task @0013a3d4 | OBS disasm 0x3a5b4 |

### 2.4 Master / server opcodes (not used in LAN-only operation; brief)

| Opcode | Label | Summary | Evidence |
|---|---|---|---|
| 0x0008 | MASTER reply | Sender must be in `gP2PMasterAddrv6`. Sets login flags. UID @0x10 | OBS line 5090 |
| 0x000A | MASTER notice | Sets flag +0xA35 or device flag. UID @0x10 | OBS line 5049 |
| 0x0123 | SERVER NAT probe | `addNatRecord`. UID @0x10 must be device UID. u32 @0x34 | OBS line 4784 |
| 0x0208 | SERVER connect/knock result | RID64 @0x28. Status i32 @0x24 (0, -1, -5, -7, -9, -22). Can send 0x0209 (const `DAT_0010afb0`) | OBS line 4861 |
| 0x0227 / 0x0229 | SERVER query reply | UID @0x10. Calls `FUN_00137c40`, `FUN_0013791c` | OBS line 4684, 4485 |
| 0x022E | SERVER status | UID @0x10. Byte @0x24 to session +0xA38 | OBS line 4382 |
| 0x0232 | SERVER wake-up info | UID @0x10. u64 big-endian @0x24 | OBS line 4252 |
| 0x1009 | MASTER time stamp | `natReceiveFromOther` | OBS line 8137 |
| 0x8004 | SERVER NAT address | Sockaddr @0x10. `addNatRecord` | OBS line 8258 |
| 0x8005 | SERVER NAT notice | `natReceiveFromOther` | OBS line 8190 |

Opcodes found only in send constants (not handled here): 0x0209, 0x0228, 0x0231, 0x0240, 0x0241, 0x010E, 0x1007, 0x100B, 0x0301 (`_IOTC_Send_Punch_To`). (OBS rodata 0xAFA0..0xB078)

---

## 3. LAN search and LAN connect

### 3.1 Request 0x0601 / 0x0603 / 0x0604 (client to device), total 0x58 bytes

Builder: `FUN_001254a0` @001254a0 (line 13500). Header constant `DAT_0010b008` = `48 00 00 00 01 06 21 00`.

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | 0x0204 | OBS |
| 0x02 | 1 | - | version | 0x1D | OBS |
| 0x03 | 1 | - | hflags | 0x02 | OBS line 13586 |
| 0x04 | 2 | LE | payloadLen | 0x0048 | OBS rodata |
| 0x06 | 2 | LE | seq | 0 | OBS rodata |
| 0x08 | 2 | LE | opcode | 0x0601. 0x0603 if `stage == 0` and filter value is not 0. 0x0604 if port is not 0 (0x0604 has priority) | OBS line 13558 |
| 0x0A | 2 | LE | dir | 0x0021 | OBS rodata |
| 0x0C | 3 | - | zero | 0 | OBS |
| 0x0F | 1 | - | searchFlag | arg 1 of builder. 0 for connect. 1 in `IOTC_Lan_Search2_Ex` | OBS line 13573, 13664 |
| 0x10 | 20 | - | UID | Target UID. All zero for a search | OBS line 13545 |
| 0x24 | 12 | - | zero | 0 | OBS |
| 0x30 | 4 | - | zero | 0 | OBS (`local_b7c` low half) |
| 0x34 | 4 | LE | sdkVersion | 0x04030800 (bytes `00 08 03 04`) | OBS line 13556 |
| 0x38 | 8 | LE | RID64 | Client RandomID (session +0x20). 0 for a search | OBS line 13571 |
| 0x40 | 4 | LE | stage | 0 = search. 1 = connect request. 2 = connect confirm | OBS line 13557 |
| 0x44 | 4 | LE | filter | Only for 0x0603 | OBS line 13559 |
| 0x48 | 2 | LE | iotcPort | Listen-port id (session +0x72). 0 = default | OBS line 13564 |
| 0x4A | 8 | - | authKey | 8 ASCII bytes (session +0x16CC). 0 if not given | OBS line 13567 |
| 0x52 | 6 | - | zero | 0 | OBS |

Destination: unicast if an address is given. If not, `Broadcast_Message_By_Netmask` sends to each interface broadcast address on UDP port `DAT_0014c798`. Default value in `.data` is `0x7FF9` (32761). `IOTC_Set_LanSearchPort` changes it. (OBS line 13596, ELF .data)

### 3.2 Device handling of the request (`LAB_00118b84`, line 7816)

Device globals:

| Global | Meaning | Evidence |
|---|---|---|
| `DAT_0014e51c` (20 bytes) | Device UID (copy made in `IOTC_Device_Login`) | OBS line 10029 |
| `DAT_0014e538` | Device "login session" struct. First 20 bytes = device UID | OBS line 10124, 11520 |
| `DAT_0014cee4` (0x81 bytes) | Device name from `IOTC_Set_Device_Name` (max 0x80 chars + NUL at `DAT_0014cf64`) | OBS line 3249 |
| `DAT_0014cf65` | 1 = not LAN-detectable. `IOTC_Set_Device_Lan_Detectable(x)` stores `x == 0` | OBS line 3294 |
| `DAT_00150188` (8 bytes) | Device authkey from `IOTC_Device_LoginEx` | OBS line 11075 |
| `DAT_0015017c` | 1 = authkey disabled. 0 = authkey enabled | OBS line 11077 |
| `gDeviceIOTCPortList` | List of u16 port ids added by `IOTC_Listen_ByPort_Internal`. `is_iotcport_accepted(p)` @00116560 | OBS line 2140, 9433 |

#### Case A: legacy request, `payloadLen < 0x34` (OBS line 7821)

The device always replies (no check of the detectable flag, no UID check). Reply = 0x0602, total 0xB8 bytes, header constant `DAT_0010afa8` = `A8 00 00 00 02 06 12 00`. Built inline in the handler.

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | 0x0204 | OBS |
| 0x02 | 1 | - | version | 0x1D | OBS |
| 0x03 | 1 | - | hflags | 0x02 | OBS line 7867 |
| 0x04 | 2 | LE | payloadLen | 0x00A8 | OBS rodata |
| 0x06 | 2 | LE | seq | 0 | OBS |
| 0x08 | 2 | LE | opcode | 0x0602 | OBS rodata |
| 0x0A | 2 | LE | dir | 0x0012 | OBS rodata |
| 0x0C | 4 | - | zero | 0 | OBS line 7823 |
| 0x10 | 20 | - | UID | Device UID (`DAT_0014e538`) | OBS line 7836 |
| 0x24 | 2 | LE | family | 0x0002 | OBS line 7850 |
| 0x26 | 2 | LE | port | Sender port as passed to the handler (`param_3`), low byte first | OBS line 7852 |
| 0x28 | 4 | network | ip | `inet_addr(sender IP)` | OBS line 7828 |
| 0x2C | 8 | - | zero | 0 | OBS line 7854 |
| 0x34 | 0x80 | - | deviceName | Bytes of `DAT_0014cee4`, NUL padded | OBS line 7857 |
| 0xB4 | 1 | - | nameEnd | `DAT_0014cf64` (always 0) | OBS line 7855 |
| 0xB5 | 3 | - | zero | 0 | OBS |

#### Case B: `payloadLen >= 0x34`, `stage == 0` (search) (OBS line 8108)

Conditions for a reply:
1. `DAT_0014cf65 == 0` (device is LAN-detectable).
2. `is_iotcport_accepted(port)` is true. `port` = u16 @0x48 if `payloadLen >= 0x48`, else 0. Thus the application must have called `IOTC_Listen` for that port id.

The UID in the request is not compared in this case. (OBS)
Reply: `FUN_001354f4(ip, port, NULL, 0)`. This is the long 0x0602 (section 3.3) with RID64 = 0 and result = 0.

#### Case C: `stage == 1` (connect request) (OBS line 7988)

Steps:
1. UID @0x10 must equal `DAT_0014e51c` (compare `FUN_001356f0`). If not, no reply.
2. `rid = u64 @0x38`. If `FUN_001359a8(rid, 0)` finds `rid` in `gRecentRandomIDList` with the reject flag (entry age less than 20 s), no reply.
3. Authkey decision:

| Device state | Request | Result | Evidence |
|---|---|---|---|
| Authkey enabled (`DAT_0015017c == 0`) | `payloadLen >= 0x48` and 8 bytes @0x4A == `DAT_00150188` | Continue, `okCode = 1` | OBS line 7995 |
| Authkey enabled | `payloadLen >= 0x48`, key different | Reply result 5 | OBS line 7998 |
| Authkey enabled | `payloadLen < 0x48` | No reply | INF (control flow at line 7995 to 8002) |
| Authkey disabled | `payloadLen < 0x48` | Continue, `okCode = 1` | OBS line 8002 |
| Authkey disabled | version byte < 0x1B and key @0x4A is not 8 alphanumeric chars (`FUN_0012213c` false) | Continue, `okCode = 1` | OBS line 8094 |
| Authkey disabled | version byte >= 0x1B and (key not alphanumeric, or key == `"00000000"`) | Continue, `okCode = 7` | OBS line 8097 |
| Authkey disabled | Other (client sent a real key) | Reply result 6 | OBS line 8101 |

4. If a session with this RID64 exists (`FUN_0012de84`) and its state is not 3 or 4: reply `okCode` again (retransmit). (OBS line 8079)
5. Else if a pre-session with this RID64 exists (`FUN_00135890`), state not 3/4, and +0x54 == 5: reply `okCode` again. (OBS line 8075)
6. Else create a pre-session:
   - `port` = u16 @0x48 (0 if `payloadLen < 0x48`). If `is_iotcport_accepted(port)` is false: add `rid` to the recent list with reject flag (`FUN_00123978(rid, type, 1)`) and reply result 4.
   - `FUN_00135c38()` gets a free pre-session slot. If none: reply result 3.
   - If `FUN_0013e7b4()` is not 0: reply result 3 and free the slot.
   - `FUN_00135b90` adds a timeout task (`tutk_TaskMng_Create(10000, 60000, ...)`, callback `FUN_00135cf4`). After 60 s without completion the pre-session is cleared.
   - Fill pre-session: +0x1C = 1 (device role), +0x54 = 5, +0x58 = u32 @0x34, +0x72 = port, +0x00 = UID (20 bytes from request), +0x20 = RID64, +0x28 = 0 (type 64-bit), +0x40 = sender address.
   - Reply `okCode` (1 or 7).

All replies in this case use `FUN_001354f4(ip, port, &rid, result)`.

#### Case D: `stage == 2` (connect confirm) (OBS line 7881)

Steps:
1. UID @0x10 must equal `DAT_0014e51c`.
2. `rid = u64 @0x38` must not be in the reject list.
3. If a session with this RID64 exists, state not 3/4, and +0x54 != 6: call `FUN_00118314(0, sid, sock, ip, port)` and set +0x54 = 6.
4. Else find the pre-session. If state not 3/4 and +0x54 != 6:
   - Remove its tasks. Get a free session id (`FUN_001390d0`).
   - Copy the 0x98-byte pre-session into the session. Clear the pre-session.
   - `FUN_00118314(0, sid, sock, ip, port)`: +0x40 = sender address (LAN path), +0xB20 = socket, and if no better path: +0xDC = address, +0xB38 = socket, +0xB40 = 0. State +0x19 changes from 1 to 2.
   - +0x54 = 6. +0xB04 = hflags bit1. +0x58 = u32 @0x34. +0x98 = 2. +0x4A4 = 0. +0xB07 = version byte. TX and RX counters of channel `hdr[0x0E]` = 0. +0x1780 = 1 if authkey is enabled, else 0.

**The device sends no packet in reply to stage 2.** (OBS: there is no send call in this branch.)

`IOTC_Listen_ByPort_Internal` @0012012c then returns the session: it polls each 10 ms for a session with state 2..4, +0xB13 == 0, +0x1C == 1, and +0x72 == the listen port id. It then sets +0xB13 = 1. (OBS line 9433)

#### Other ways the device completes a pending LAN session (OBS)

- A 0x0407 or 0x0427 packet with hflags bit3 and a RID64 that matches a pre-session: `FUN_00137dbc` @00137dbc promotes the pre-session to a session (same field updates as above).
- A 0x0407 or 0x0427 with a RID64 that matches a session in state 1 with +0x54 == 5: `_IOTC_LAN_Connection_Check` @00118204 sets the LAN address, state 2, +0x54 = 6.

### 3.3 Long LAN response 0x0602 (device to client), total 0xC8 (200) bytes

Builder: `FUN_001354f4(ipStr, port, rid64Ptr, result)` @001354f4 (line 27658). Header constant `DAT_0010b040` = `B8 00 00 00 02 06 12 00`.

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | 0x0204 | OBS line 27712 |
| 0x02 | 1 | - | version | 0x1D | OBS line 27719 |
| 0x03 | 1 | - | hflags | 0x02 | OBS line 27749 |
| 0x04 | 2 | LE | payloadLen | 0x00B8 | OBS rodata |
| 0x06 | 2 | LE | seq | 0 | OBS rodata |
| 0x08 | 2 | LE | opcode | 0x0602 | OBS rodata |
| 0x0A | 2 | LE | dir | 0x0012 | OBS rodata |
| 0x0C | 4 | - | zero | 0 | OBS line 27720 |
| 0x10 | 20 | - | UID | Device UID (`DAT_0014e51c`) | OBS line 27709 |
| 0x24 | 16 | - | zero | 0 (the legacy form has a sockaddr here) | OBS line 27705 |
| 0x34 | 0x80 | - | deviceName | `DAT_0014cee4`, NUL padded | OBS line 27726 |
| 0xB4 | 4 | LE | nameEnd | Byte `DAT_0014cf64` zero-extended. Always 0 | OBS line 27731 |
| 0xB8 | 4 | LE | sdkVersion | 0x04030800 | OBS line 27731 |
| 0xBC | 8 | LE | RID64 | Echo of request RID64 @0x38. 0 for search | OBS line 27733 |
| 0xC4 | 4 | LE | result | See table below | OBS line 27735 |

Result codes and client reaction (client handler line 8592):

| Result | Device meaning | Client action | Evidence |
|---|---|---|---|
| 0 | Search answer | If a LAN search is active: record UID, IP, port, name (`FUN_00135e44` / `FUN_00136080`). No session change | OBS line 8582 |
| 1 | Connect accepted | Send stage 2. Session established (see 3.4) | OBS line 8614 |
| 7 | Connect accepted (device has no authkey, client version >= 0x1B) | Same as 1 | OBS line 8720 |
| 3 | No free pre-session / busy | If +0x54 == 1: +0xA31 = 1 | OBS line 8694 |
| 4 | Port id not listened | If +0x54 == 1: +0x16C2 = 1 | OBS line 8700 |
| 5 | Authkey mismatch | If +0x54 == 1: +0xA38 = 2 | OBS line 8707 |
| 6 | Client sent an authkey, device has none | If +0x54 == 1: +0xA38 = 3 | OBS line 8713 |

Device retransmit: `FUN_00127718` (task of `AddLanSearchPrecheckRTask`, 100 ms period, 30 s limit) sends `FUN_001354f4(addr, port, rid, 1)` again while +0x54 != 6. The caller of `AddLanSearchPrecheckRTask` was not found in the request path. (OBS line 15179; use is UNKNOWN)

### 3.4 Client LAN connect sequence (OBS)

Task `FUN_0012798c` (from `AddLanSearchTask` @001278ac, period 100 ms):

| Session +0x54 | Action |
|---|---|
| 1 or 3 | Broadcast request with `stage = 1`, UID, RID64 (+0x20), port (+0x72), authkey (+0x16CC). Opcode 0x0601, or 0x0604 if port != 0 |
| 4 | Unicast request with `stage = 2` to the address at +0x40 |
| 6 | Delete the task (done) |
| timeout | +0x54 = -1 |

On 0x0602 with result 1 or 7 (line 8614):
1. Find the session by RID64 @0xBC (64-bit type, any state). UID @0x10 must match.
2. Ignore if +0x54 is -1, 0, 2 or 6.
3. If client option +0x1764 == 0 and device version byte < 0x17: continue only if +0x54 == 1 and client authkey is `"00000000"`; if the key is different set +0xA38 = 3 and stop. If version >= 0x17 and result == 1: +0x1780 = 1.
4. If header `dir` bit 9 is set: set +0xA30 (version < 7) or +0xA31, and stop.
5. Send unicast 0x0601 with `stage = 2` to the sender (`FUN_001254a0(0, uid, rid, 2, ip, port, 0, 0, NULL)`). Port and authkey fields are 0.
6. If state is 1: +0x4A6 = 2, +0x98 = 2 for a private IP, copy UID, +0x1C = 0 (client role), +0xB07 = version byte, counters of channel `hdr[0x0E]` = 0, +0x58 = u32 @0xB8, +0xB04 = hflags bit1.
7. `FUN_00118314(0, sid, sock, ip, port)`: state becomes 2. +0x54 = 6.
8. `SendConnectResult(sid, 0,0,0,0,0)` @00126400. This only calls `iotcRecordSendP2PHandshake` with record type 0x806. No 0x0204 packet is sent. (OBS line 14335)

`SendConnectSuccess` @00127300 sends opcode 0x0801 (dir 0x24, total 0x38) to a server address. It is not part of the LAN exchange. (OBS line 15003)

### 3.5 LAN handshake summary

```
C  --0x0601/0x0604 stage=1 (broadcast, 0x58)-->  D     D creates pre-session
C  <--0x0602 result=1 or 7 (unicast, 0xC8)-----  D
C  --0x0601 stage=2 (unicast, 0x58)----------->  D     D creates session, IOTC_Listen returns it
                                                       no reply to stage 2
C  --0x0427 each ~2 s / 0x0407 data----------->  D
C  <--0x0428 each ~2 s / 0x0408 data-----------  D
```

---

## 4. Session packets

### 4.1 SESSION_DATA 0x0407 (client TX) and 0x0408 (device TX)

Builder: `IOTC_Session_Write_Data_And_Datatype` @00124700 (line 12859). Used when active path (+0xB40) is 0 (LAN) or 1 (P2P). Maximum user data: 0x56C bytes.

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | 0x0204 | OBS |
| 0x02 | 1 | - | version | 0x1D | OBS |
| 0x03 | 1 | - | hflags | 0x02. Plus 0x01 if session +0xB05 != 0 (partial transcode). Plus 0x08 if RandomID type (+0x28) == 0 | OBS line 12921, 12976 |
| 0x04 | 2 | LE | payloadLen | dataLen, or dataLen + 0x0C when bit3 is set | OBS line 12973 |
| 0x06 | 2 | LE | seq | Low 16 bits of session `+0x13C + 4*channel`. The counter then increases by 1 | OBS line 12920, 12984 |
| 0x08 | 2 | LE | opcode | 0x0407 if role (+0x1C) == 0. 0x0408 if role != 0 | OBS line 12941 |
| 0x0A | 2 | LE | dir | 0x0021 (client) or 0x0012 (device) | OBS line 12945 |
| 0x0C | 2 | LE | shortId | Low 16 bits of +0x20 | OBS line 12950 |
| 0x0E | 1 | - | channel | Channel id | OBS line 12928 |
| 0x0F | 1 | - | dtype | Data type `& 3` | OBS line 12970 |
| 0x10 | 4 | LE | subHdrLen | 0x0000000C. Only when bit3 is set | OBS line 12974 |
| 0x14 | 8 | LE | RID64 | Session +0x20. Only when bit3 is set | OBS line 12975 |
| 0x1C or 0x10 | n | - | data | User bytes | OBS line 12985 |

Receive (0x0407 line 5377, 0x0408 line 5187):

1. Ignore if hflags bit2 is set.
2. Session lookup:
   - bit3 clear, hdr 0x0C != 0: session with state 2, type (+0x28) == 1, +0x20 == shortId.
   - bit3 clear, hdr 0x0C == 0: `FUN_0013818c(ip, port)`: session with state 2 whose active address (+0xDC) equals the sender.
   - bit3 set: need `payloadLen >= 0x0C`. RID64 = u64 @0x14. Reject list check (0x0408 only shows it). Then:
     - 0x0407 (device): any session with type 0 and this RID64 -> `_IOTC_LAN_Connection_Check`. If none (or RID lo == 0) -> `FUN_00137dbc` (pre-session promotion).
     - 0x0408 (client): session in state 2 with this RID64. If none, session in state 1 with this RID64 -> `FUN_00138298` (marks connected).
   - With bit3: `data = payload + u32@0x10`, `dataLen = payloadLen - u32@0x10`. The receiver uses the sub-header length field. (OBS line 5448)
3. Channel = hdr[0x0E]. Ignore if >= 0x20.
4. If the channel callback (+0x4A8 + 8*channel) is NULL and `dataLen > 0`: `__Fill_ReadBuf(sid, data, dataLen, seq = hdr[6..8], channel, dtype = hdr[0x0F])`.
   Else call the callback `(sid, channel, data, dataLen, status)`.
5. Store the sender address at +0xF0 (path 1). If active path is 1, or more than 1, also update +0xDC (and set path = 1).
6. 0x0408 also sets +0xB08 = 1.

The handler does not check the sequence number and does not send an acknowledge. (OBS)

`__Fill_ReadBuf` @0011778c (line 3163) makes a queue node of 0x20 bytes:

| Node offset | Size | Field | Evidence |
|---|---|---|---|
| 0x00 | 2 | length | OBS |
| 0x02 | 2 | seq from header | OBS |
| 0x04 | 4 | RX index (= session `+0x1BC + 4*ch` before increment) | OBS |
| 0x08 | 8 | pointer to copied data | OBS |
| 0x10 | 1 | dtype & 3 | OBS |
| 0x18 | 8 | next node | OBS |

It appends the node to the list at session `+0x2A0 + 0x10*ch` (head) / `+0x2A8 + 0x10*ch` (tail), increments `+0x25E + 2*ch` (u16) and `+0x1BC + 4*ch`, and sets +0x99 = 0.

### 4.2 SESSION_ALIVE 0x0427 (client TX) / 0x0428 (device TX)

Sender: task function @0013a3d4. Ghidra did not decompile it; fields come from disassembly (file offset 0x3a3d4..0x3a6d4). Registered in `IOTC_Initialize2` with `tutk_TaskMng_Create(1000, 0, 0, LAB_0013a3d4, 0)` (line 11628). (OBS)

Per tick (1000 ms), for each session with state 2:
1. If +0x99 > `DAT_0014c5a0` (alive timeout, default 60, set by `IOTC_Setup_Session_Alive_Timeout`): state = 4, close callback gets -23, channel callbacks get -23.
2. Else +0x99 += 1. If +0x99 <= 4 and +0xBA8 < 1: +0xBA8 += 1 and send nothing. Else +0xBA8 = 0 and send one alive packet.
   Result: one packet each 2 s when the peer answers; one packet each 1 s after 4 missed ticks. (INF from the counter logic)

| Offset | Size | Endian | Field | Meaning | Evidence |
|---|---|---|---|---|---|
| 0x00 | 2 | LE | magic | 0x0204 | OBS 0x3a55c |
| 0x02 | 1 | - | version | 0x1D | OBS 0x3a568 |
| 0x03 | 1 | - | hflags | 0x0A if type (+0x28) == 0. Else 0x02 | OBS 0x3a62c, 0x3a640 |
| 0x04 | 2 | LE | payloadLen | 8 if type == 0. Else 0 | OBS 0x3a644 |
| 0x06 | 2 | LE | seq | 0 | OBS |
| 0x08 | 2 | LE | opcode | 0x0427 if role == 0. 0x0428 if role != 0 (path 0 or 1) | OBS 0x3a5d8, 0x3a5f4 |
| 0x0A | 2 | LE | dir | 0x0021 or 0x0012 | OBS |
| 0x0C | 4 | - | zero | 0 for LAN/P2P (the relay form puts +0x4A4 at 0x0C) | OBS 0x3a56c, 0x3a610 |
| 0x10 | 8 | LE | RID64 | Session +0x20. Only if type == 0 | OBS 0x3a648 |

Total: 0x18 (type 0) or 0x10. Destination: +0xDC through socket +0xB38.

Receive: lookup as in 4.1 (bit3: RID64 is at 0x10, `payloadLen >= 8`). 0x0427 on device: +0x99 = 0, update +0xF0 address, +0x25D = 1, update +0x4A0. 0x0428 on client: +0x99 = 0, +0xB08 = 1, update address. No reply packet. (OBS lines 7666 to 7791, 7554 to 7658)

### 4.3 SESSION_CLOSE 0x0417 (client TX) / 0x0418 (device TX)

Builder: `FUN_001235e4` @001235e4 (line 11924). `IOTC_Session_Close` @00123098 calls it 3 times when active path is 0 or 1 (relay: `FUN_0012376c` 5 times). (OBS line 11717)

Layout is the same as SESSION_ALIVE except:
- opcode 0x0417 (role 0) or 0x0418 (role != 0); dir 0x21 / 0x12.
- If type != 0: u32 @0x0C = `+0x20 & 0xFFFF` (short id in hdr 0x0C), total 0x10, hflags 0x02.
- If type == 0: hflags 0x0A, payloadLen 8, RID64 @0x10, total 0x18.

Receive: only a session in state 2 is changed. State = 3. Bytes +0x9A..+0xD9 = 0. Callbacks get -22. (OBS line 7436)

---

## 5. Session info struct (`gSessionInfo` element, size 0x1C30)

`gPreSessionInfo` elements are 0x98 bytes and have the same layout as the first 0x98 bytes. Counts: `DAT_0014c590` sessions (default 0x80), `DAT_0014c594` pre-sessions (default 0x8A). (OBS .data)

| Offset | Size | Field | Meaning | Tag | Evidence |
|---|---|---|---|---|---|
| 0x00 | 20 | uid | Peer/target UID. Compared by `FUN_001356f0` (stops at NUL) | OBS | line 27766 |
| 0x18 | 1 | slotFlag | Set to 1 when a pre-session is allocated. Read by `FUN_00135cf4` (0 or 1) | OBS / meaning UNKNOWN | line 28239 |
| 0x19 | 1 | state | 0 free. 1 in use / connecting. 2 connected. 3 closed by remote. 4 alive timeout | OBS | lines 3241, 7451, disasm 0x3a4e0 |
| 0x1B | 1 | peerKind | Values < 10 select short packet forms | OBS / meaning UNKNOWN | line 4928 |
| 0x1C | 4 | role | 0 = client. 1 = device | OBS | line 12940, 8037 |
| 0x20 | 8 | randomId | RID64 (lo u32, hi u32). For type 1 only the low 16 bits are used | OBS | line 2195 |
| 0x28 | 4 | randomIdType | 0 = 64-bit. 1 = 16-bit | OBS | line 2213 |
| 0x30 / 0x38 | 8 / 8 | taskHead / taskTail | List of timer tasks | OBS | line 15165 |
| 0x40 | 20 | lanAddr | Remote LAN address (path 0), `iotc_netaddr` form | OBS | line 3792, rodata 0xB230 |
| 0x54 | 4 | lanState | 1 = client sends stage 1. 2 = LAN not used. 3 = legacy response received. 4 = client sends stage 2. 5 = device waits for stage 2. 6 = LAN connected. -1 = failed | OBS (1,4,5,6,-1) / INF (2,3) | lines 15284, 15391, 8038, 3804 |
| 0x58 | 4 | remoteSdkVersion | u32 from request @0x34 or response @0xB8 | OBS | line 7965, 8666 |
| 0x70 | 1 | ? | Values 1 or 2 stop LAN response processing | UNKNOWN | line 8523 |
| 0x72 | 2 | iotcPort | Listen-port id | OBS | line 8047, 9433 |
| 0x75 | 0x1D | uidKeyText | UID + authkey text (`"%.*s%.*s"`) | OBS | line 20112 |
| 0x98 | 1 | mode | 2 = LAN. 0 = P2P | OBS (2 on LAN) / INF | line 7967, 5615 |
| 0x99 | 1 | aliveMiss | Ticks since last packet from peer | OBS | line 3223 |
| 0xDC | 20 | activeAddr | Address for send. Port is at +0xDE | OBS | line 3410, 30012 |
| 0xF0 | 20 | p2pAddr | Path 1 address. Also updated on each data/alive packet | OBS | line 5347 |
| 0x104 / 0x118 | 20 / 20 | relayAddr | Path 2 / path 3 addresses | OBS | rodata 0xB240 |
| 0x13C + 4*ch | 4 | txSeq[32] | Next TX sequence per channel | OBS | line 12920 |
| 0x1BC + 4*ch | 4 | rxCount[32] | RX packet index per channel | OBS | line 3208 |
| 0x23C + ch | 1 | channelOn[32] | Channel ON flag | OBS | line 13224 |
| 0x25D | 1 | connectStage | 1 after confirm, 2 after punch | OBS / meaning INF | line 5568 |
| 0x25E + 2*ch | 2 | rxPending[32] | Queued packets per channel | OBS | line 3207 |
| 0x2A0 + 16*ch | 8+8 | rxQueue[32] | Head / tail of read queue | OBS | line 3209 |
| 0x4A0 | 4 | connectMs | Time stamp / duration in ms | OBS | line 5582 |
| 0x4A4 | 2 | relaySid | Relay session id | OBS | line 12965 |
| 0x4A6 | 1 | ? | 1 or 2 during connect | UNKNOWN | line 8647 |
| 0x4A8 + 8*ch | 8 | rcvCb[32] | Channel receive callbacks | OBS | line 5311 |
| 0xA28 | 8 | closeCb | Session close callback `(sid, code)` | OBS | line 7450 |
| 0xA30, 0xA31, 0xA35..0xA38, 0x16C2 | 1 each | errFlags | Connect error flags (see 3.3) | OBS / exact error codes UNKNOWN | line 8685 |
| 0xB02 | 2 | punchSeq | hdr[6..8] of last punch | OBS | line 6153 |
| 0xB04 | 1 | peerHflagBit1 | `(hflags >> 1) & 1` of peer | OBS | line 7964 |
| 0xB05 | 1 | partialEnc | Not 0: TX sets hflags bit0 | OBS | line 12922 |
| 0xB07 | 1 | remoteProtoVer | Peer header byte 2. Returned by `IOTC_Get_Remote_ProtocolVersion` | OBS | line 13856 |
| 0xB08 | 1 | gotPeerData | Set on 0x0408 / 0x0428 | OBS | line 5306 |
| 0xB13 | 1 | listenReturned | 1 after `IOTC_Listen` returned this session | OBS | line 9433 |
| 0xB18 / 0xB20 / 0xB28 / 0xB30 | 8 each | pathSock[1,0,2,3] | Socket object per path. LAN = +0xB20 | OBS | rodata 0xB250 |
| 0xB38 | 8 | activeSock | Socket for send | OBS | line 3404 |
| 0xB40 | 4 | activePath | -1 none. 0 LAN. 1 P2P. 2, 3 relay | OBS | line 3842, 12937 |
| 0xB44 | 4 | sid | Own index | OBS | line 5737 |
| 0xB48 | 4 | p2pState | 3 = connected | OBS | line 6055 |
| 0xB64 | 4 | lanElapsedMs | Sum of task intervals | OBS | line 15337 |
| 0xBA8 | 4 | aliveDivider | See 4.2 | OBS | disasm 0x3a54c |
| 0x16CC | 8 | authKey | Client authkey bytes | OBS | line 15409 |
| 0x1764 | 4 | ? | Client option used in authkey checks | UNKNOWN | line 8515 |
| 0x1780 | 1 | authFlag | Device: 1 if authkey enabled. Client: 1 if result 1 and peer version >= 0x17 | OBS / meaning INF | line 7973, 8637 |

RandomID reject list (`gRecentRandomIDList`): nodes of 0x30 bytes with RID64, type, time stamp, flag. Entries older than 20000 ms are removed on each lookup. Only entries with flag 1 cause a reject. (OBS lines 27932, 12126)

---

## 6. UNKNOWNS

1. `iotcRecordHandler` @0012ea9c (first u32 `0x0000CC51`, 12-byte header, u8 type @5, u16 length @6, u32 sid @8; types 1, 3, 4, 5, 0x0E). This framing was not analyzed. `iotcRecord2SupportCheck` and `isIotcSessionEnableRecord2` return 0 in this build.
2. `FUN_0013e7b4()` (called in stage 1). A non-zero result gives result code 3. Its condition was not read.
3. Meaning of hflags bit1 and bit2. Only their effects are known.
4. Source of the 0x0603 filter value on the client side, and why the device compares it with a random value 1..15.
5. Exact public error codes for flags +0xA30, +0xA31, +0xA38, +0x16C2.
6. Caller of `AddLanSearchPrecheckRTask` (device retransmit of result 1).
7. Device socket setup for the LAN search port (bind to 32761) was not traced. Only the client broadcast destination port is known.
8. `iotc_netaddr` 20-byte layout is known only in part (+2 = port, +4.. = address words).
9. Session fields +0x1A, +0x1B, +0x70, +0x4A6, +0x1764.
10. Legacy 0x0602 client path (`payloadLen` 0x24 or 0xA8): it calls `_IOTC_Send_Punch_To` (opcode 0x0301) and `FUN_0013699c`. Details were not traced.
11. Whether a device in the field needs `stage = 1` requests on the broadcast address only. The handler does not examine the destination address. (INF: unicast stage 1 is accepted.)
