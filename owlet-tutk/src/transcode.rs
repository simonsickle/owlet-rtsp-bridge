//! Independent little-endian 16-byte blocks, followed by one tail.
pub const DEFAULT_MASK: [u8; 16] = [0; 16]; // A_lan U1: the licence mask is application-specific.
#[derive(Clone)]
pub struct Transcode([u8; 16]);
impl Default for Transcode {
    fn default() -> Self {
        Self::new(DEFAULT_MASK)
    }
}
const SHUFFLE: [usize; 16] = [11, 9, 8, 15, 13, 10, 12, 14, 2, 1, 5, 0, 6, 4, 7, 3];

impl Transcode {
    pub fn new(mask: [u8; 16]) -> Self {
        let mut key = *b"Charlie is the d";
        for (k, m) in key.iter_mut().zip(mask) {
            *k ^= m;
        }
        Self(key)
    }
    pub fn encode(&self, buf: &[u8], n: usize) -> Vec<u8> {
        self.transform(buf, n, false)
    }
    pub fn decode(&self, buf: &[u8], n: usize) -> Vec<u8> {
        self.transform(buf, n, true)
    }
    fn transform(&self, buf: &[u8], n: usize, decode: bool) -> Vec<u8> {
        let mut out = buf.to_vec();
        let (blocks, tail) = out[..n.min(buf.len())].as_chunks_mut::<16>();
        for block in blocks {
            let (first, second) = if decode { (3, 1) } else { (1, 3) };
            rotate(block, first, decode);
            if !decode {
                xor(block, &self.0);
            }
            shuffle(block, &SHUFFLE, decode);
            if decode {
                xor(block, &self.0);
            }
            rotate(block, second, decode);
        }
        let order: &[usize] = match tail.len() {
            2 => &[1, 0],
            4 => &[2, 3, 0, 1],
            8 => &[7, 4, 3, 2, 1, 6, 5, 0],
            _ => &[],
        };
        if !decode {
            xor(tail, &self.0);
        }
        shuffle(tail, order, decode);
        if decode {
            xor(tail, &self.0);
        }
        out
    }
}
fn rotate(block: &mut [u8], base: u32, left: bool) {
    for (i, bytes) in block.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        let w = u32::from_le_bytes(*bytes);
        let n = base + i as u32 * 4;
        bytes.copy_from_slice(
            &if left {
                w.rotate_left(n)
            } else {
                w.rotate_right(n)
            }
            .to_le_bytes(),
        );
    }
}
fn xor(block: &mut [u8], key: &[u8; 16]) {
    for (b, k) in block.iter_mut().zip(key) {
        *b ^= k;
    }
}
fn shuffle(block: &mut [u8], order: &[usize], inverse: bool) {
    let mut src = [0; 16];
    src[..block.len()].copy_from_slice(block);
    for (i, &j) in order.iter().enumerate() {
        if inverse {
            block[j] = src[i];
        } else {
            block[i] = src[j];
        }
    }
}
