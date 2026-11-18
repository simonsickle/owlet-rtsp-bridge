// Failure modes for this isolated test, listed before implementation.
// 1. A word rotates in the wrong direction or by the wrong count.
// 2. The key words have the wrong byte order.
// 3. The byte shuffle uses the wrong indices.
// 4. A tail of 2, 4, or 8 bytes misses its permutation, or another tail is permuted.
// 5. Encoding changes bytes after n.
// 6. Decoding does not invert encoding.
// 7. Header and payload transcode boundaries are wrong, including the partial flag.
use owlet_tutk::{
    hex_decode,
    iotc::{header::Packet, lan::Request},
    transcode::Transcode,
};

#[test]
fn vendor_vectors() {
    let codec = Transcode::default();
    for line in include_str!("../testdata/transcode_vectors.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        let total: usize = fields[0].parse().unwrap();
        let n = fields[1].parse().unwrap();
        let plain = hex_decode(fields[2]).unwrap();
        let wire = hex_decode(fields[3]).unwrap();
        assert_eq!(plain.len(), total);
        assert_eq!(codec.encode(&plain, n), wire, "encode {total}/{n}");
        assert_eq!(codec.decode(&wire, n), plain, "decode {total}/{n}");
    }
}

#[test]
fn wire_boundaries() {
    let codec = Transcode::default();
    let captured =
        hex_decode(include_str!("../testdata/captured_lan_search_header.hex").trim()).unwrap();
    assert_eq!(
        codec.decode(&captured, 16),
        hex_decode("04021d02480000000106210000000001").unwrap()
    );
    let mut packet = Request::search(0).packet();
    let wire = packet.encode(&codec).unwrap();
    assert_eq!(wire.len(), 88);
    assert_eq!(&wire[..16], captured);
    assert_eq!(&wire[16..], codec.encode(&packet.payload, 72));
    packet.header.flags |= 1;
    packet.payload = (0..99).collect();
    let wire = packet.encode(&codec).unwrap();
    assert_eq!(&wire[16..], codec.encode(&packet.payload, 48));
    assert_eq!(Packet::decode(&wire, &codec).unwrap(), packet);
}
