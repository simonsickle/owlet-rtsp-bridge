import struct, json, sys
KEY=b"Charlie is the d"
K=struct.unpack('<4I',KEY)
M=0xffffffff
ror=lambda x,n:((x>>n)|(x<<(32-n)))&M
rol=lambda x,n:ror(x,32-n)
P={2:[1,0],4:[2,3,0,1],8:[7,4,3,2,1,6,5,0],16:[11,9,8,15,13,10,12,14,2,1,5,0,6,4,7,3]}
def enc_block(blk):
    w=struct.unpack('<4I',blk)
    a,b,c,d=[ror(w[i],1+4*i)^K[i] for i in range(4)]
    o0=ror((c&0xff00)|((c&0xff)<<16)|(c>>24)|(d&0xff000000),3)
    o1=ror(((c>>8)&0xff00)|((d&0xff)<<16)|((d>>8)&0xff)|(((d>>16)&0xff)<<24),7)
    o2=ror(((a<<24)&M)|(a&0xff00)|((a>>16)&0xff)|(((b>>8)&0xff)<<16),11)
    o3=ror((a&0xff000000)|((b&0xff)<<8)|((b>>16)&0xff)|((b>>24)<<16),15)
    return struct.pack('<4I',o0,o1,o2,o3)
def dec_block(blk):
    o=struct.unpack('<4I',blk)
    x0,x1,x2,x3=rol(o[0],3),rol(o[1],7),rol(o[2],11),rol(o[3],15)
    c=((x0>>8&0xff)<<8)|(x0>>16&0xff)|((x0&0xff)<<24)|((x1>>8&0xff)<<16)
    d=(x0&0xff000000)|(x1>>16&0xff)|((x1&0xff)<<8)|((x1>>24)<<16)
    a=(x2>>24)|(x2&0xff00)|((x2&0xff)<<16)|(x3&0xff000000)
    b=((x2>>16&0xff)<<8)|(x3>>8&0xff)|((x3&0xff)<<16)|((x3>>16&0xff)<<24)
    v=[a,b,c,d]
    return struct.pack('<4I',*[rol(v[i]^K[i],1+4*i) for i in range(4)])
def tail_enc(t):
    x=bytes(t[i]^KEY[i] for i in range(len(t)))
    p=P.get(len(t)); return bytes(x[i] for i in p) if p else x
def tail_dec(t):
    p=P.get(len(t)); x=bytearray(t)
    if p:
        for i,s in enumerate(p): x[s]=t[i]
    return bytes(x[i]^KEY[i] for i in range(len(x)))
def encode(buf,n=None):
    n=len(buf) if n is None else min(n,len(buf)); nb=n&~15
    return b''.join(enc_block(buf[i:i+16]) for i in range(0,nb,16))+tail_enc(buf[nb:n])+buf[n:]
def decode(buf,n=None):
    n=len(buf) if n is None else min(n,len(buf)); nb=n&~15
    return b''.join(dec_block(buf[i:i+16]) for i in range(0,nb,16))+tail_dec(buf[nb:n])+buf[n:]
if __name__=='__main__':
    v=json.load(open(sys.argv[1])); bad=0
    for x in v:
        p=bytes.fromhex(x['plain']); e=bytes.fromhex(x['encoded'])
        if encode(p,x['enc'])!=e or decode(e,x['enc'])!=p: bad+=1; print('BAD',x['total'],x['enc'])
    print('vectors',len(v),'bad',bad)
