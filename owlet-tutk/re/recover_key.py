"""Recover the 16-byte transcode key from one captured datagram with a known header.

A LAN search/connect broadcast from any TUTK app has a known first block:
  04 02 1d 02 48 00 00 00 <op lo> 06 21 00 00 00 00 <b15>
so one captured packet gives the effective key (static key XOR licence keyMask).

usage: recover_key.py <captured_first_16_bytes_hex> [known_plain_16_bytes_hex]
"""
import struct, sys
M = 0xffffffff
ror = lambda x, n: ((x >> n) | (x << (32 - n))) & M
rol = lambda x, n: ror(x, 32 - n)

def unshuffle(blk):
    o = struct.unpack('<4I', blk)
    x0, x1, x2, x3 = rol(o[0], 3), rol(o[1], 7), rol(o[2], 11), rol(o[3], 15)
    c = ((x0 >> 8 & 0xff) << 8) | (x0 >> 16 & 0xff) | ((x0 & 0xff) << 24) | ((x1 >> 8 & 0xff) << 16)
    d = (x0 & 0xff000000) | (x1 >> 16 & 0xff) | ((x1 & 0xff) << 8) | ((x1 >> 24) << 16)
    a = (x2 >> 24) | (x2 & 0xff00) | ((x2 & 0xff) << 16) | (x3 & 0xff000000)
    b = ((x2 >> 16 & 0xff) << 8) | (x3 >> 8 & 0xff) | ((x3 & 0xff) << 16) | ((x3 >> 16 & 0xff) << 24)
    return [a, b, c, d]

def recover(cipher, plain):
    v = unshuffle(cipher)
    w = struct.unpack('<4I', plain)
    return struct.pack('<4I', *[v[i] ^ ror(w[i], 1 + 4 * i) for i in range(4)])

if __name__ == '__main__':
    c = bytes.fromhex(sys.argv[1])[:16]
    p = bytes.fromhex(sys.argv[2]) if len(sys.argv) > 2 else bytes.fromhex('04021d02480000000106210000000001')
    k = recover(c, p)
    base = b'Charlie is the d'
    print('key     ', k.hex(), repr(k))
    print('keyMask ', bytes(x ^ y for x, y in zip(k, base)).hex())
