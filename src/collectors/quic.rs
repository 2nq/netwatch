//! QUIC Initial packet decryption per RFC 9001 §5.2 (and RFC 9369 §3.3.1
//! for QUIC v2).
//!
//! Real QUIC Initial packets are AEAD-protected with a key derived from the
//! Destination Connection ID via HKDF and a version-specific salt. Even
//! though the salt and derivation are public, the protection prevents naive
//! middleboxes from depending on header structure that future versions may
//! change. Following the spec gets us reliable SNI extraction (versus the
//! prior heuristic that scanned the cleartext payload — which failed because
//! the payload isn't cleartext).
//!
//! Pipeline for a candidate UDP datagram:
//!
//!   parse_long_header_initial → derive_initial_keys → remove header
//!   protection → AEAD decrypt → walk QUIC frames → reassemble CRYPTO frames
//!   into a contiguous TLS ClientHello → extract SNI extension.
//!
//! Failure at any step returns `None` silently. Network noise on UDP/443
//! will routinely produce non-QUIC traffic; we don't want to log per-packet
//! errors.

use ring::aead::quic::{HeaderProtectionKey, AES_128 as HP_AES_128};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use ring::hkdf::{KeyType, Prk, Salt, HKDF_SHA256};

/// Initial salt for QUIC v1 (RFC 9001 §5.2).
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
/// Initial salt for QUIC v2 (RFC 9369 §3.3.1).
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

const QUIC_V1_VERSION: u32 = 0x0000_0001;
const QUIC_V2_VERSION: u32 = 0x6b33_43cf;

/// Read a QUIC variable-length integer (RFC 9000 §16). The two MSBs of the
/// first byte encode the encoded length: 00=1B, 01=2B, 10=4B, 11=8B. The
/// remaining 6 bits of the first byte plus the trailing bytes form the
/// big-endian value. Returns `(value, encoded_length)`.
fn read_varint(buf: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *buf.get(offset)?;
    let len = 1usize << (first >> 6);
    if offset + len > buf.len() {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for i in 1..len {
        value = (value << 8) | buf[offset + i] as u64;
    }
    Some((value, len))
}

/// Parsed long-header fields needed for Initial packet decryption. Field
/// offsets are zero-based into the original packet buffer.
#[derive(Debug, Clone)]
pub struct InitialHeader {
    pub version: u32,
    pub dcid: Vec<u8>,
    /// Offset of the (still-protected) packet number field. The payload
    /// starts immediately after, and `payload_len_with_pn - pn_len` bytes
    /// of ciphertext follow once the pn length is known.
    pub pn_offset: usize,
    /// Length of (packet number + payload) in bytes, from the long-header
    /// `length` varint.
    pub payload_len_with_pn: usize,
}

/// Identify and parse a QUIC v1/v2 long-header Initial packet. Returns
/// `None` for short headers, non-Initial long-header types, unsupported
/// versions, or truncated buffers.
pub fn parse_long_header_initial(packet: &[u8]) -> Option<InitialHeader> {
    if packet.len() < 7 {
        return None;
    }
    let first = packet[0];
    // Long form (bit 7) + fixed bit (bit 6).
    if first & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

    // Packet type encoding moved between v1 and v2 (RFC 9369 §3.2). For v1,
    // Initial = 0b00 in bits 5-4. For v2, Initial = 0b01 in the same bits.
    let pkt_type = (first & 0x30) >> 4;
    let is_initial = match version {
        QUIC_V1_VERSION => pkt_type == 0,
        QUIC_V2_VERSION => pkt_type == 1,
        _ => return None,
    };
    if !is_initial {
        return None;
    }

    let dcid_len = packet[5] as usize;
    if dcid_len > 20 {
        return None;
    }
    let scid_len_offset = 6 + dcid_len;
    if scid_len_offset >= packet.len() {
        return None;
    }
    let dcid = packet[6..scid_len_offset].to_vec();

    let scid_len = packet[scid_len_offset] as usize;
    if scid_len > 20 {
        return None;
    }
    let mut pos = scid_len_offset + 1 + scid_len;
    if pos > packet.len() {
        return None;
    }

    let (token_len, tlen_bytes) = read_varint(packet, pos)?;
    pos += tlen_bytes;
    let token_len = token_len as usize;
    if pos + token_len > packet.len() {
        return None;
    }
    pos += token_len;

    let (length_field, len_bytes) = read_varint(packet, pos)?;
    pos += len_bytes;
    let pn_offset = pos;
    let payload_len_with_pn = length_field as usize;

    if pn_offset + payload_len_with_pn > packet.len() {
        return None;
    }

    Some(InitialHeader {
        version,
        dcid,
        pn_offset,
        payload_len_with_pn,
    })
}

/// HKDF-Expand-Label per RFC 8446 §7.1. The info field is built as
/// `length(2) || label_len(1) || "tls13 " || label || context_len(1) || context`.
/// QUIC reuses the same construction (RFC 9001 §5.1).
fn hkdf_expand_label(prk: &Prk, label: &[u8], context: &[u8], out_len: usize) -> Option<Vec<u8>> {
    const PREFIX: &[u8] = b"tls13 ";
    let prefixed_label_len = PREFIX.len() + label.len();
    if prefixed_label_len > 255 || context.len() > 255 || out_len > 255 {
        return None;
    }
    let mut info = Vec::with_capacity(2 + 1 + prefixed_label_len + 1 + context.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push(prefixed_label_len as u8);
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    struct Len(usize);
    impl KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }

    // `expand` borrows the slice-of-slices for the lifetime of the returned
    // `Okm`; pin it to a local first so it outlives the fill() call.
    let info_slices: [&[u8]; 1] = [&info];
    let okm = prk.expand(&info_slices, Len(out_len)).ok()?;
    let mut out = vec![0u8; out_len];
    okm.fill(&mut out).ok()?;
    Some(out)
}

/// Client-side Initial packet protection keys (RFC 9001 §5.2).
#[derive(Debug, Clone)]
pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

/// Derive the *client* Initial keys from the DCID and version. Server keys
/// use "server in" instead of "client in" — we only care about the client
/// path since SNI lives in the client's ClientHello.
pub fn derive_client_initial_keys(version: u32, dcid: &[u8]) -> Option<InitialKeys> {
    let (salt, key_label, iv_label, hp_label): (&[u8], &[u8], &[u8], &[u8]) = match version {
        QUIC_V1_VERSION => (&INITIAL_SALT_V1, b"quic key", b"quic iv", b"quic hp"),
        QUIC_V2_VERSION => (&INITIAL_SALT_V2, b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
        _ => return None,
    };

    // initial_secret = HKDF-Extract(salt, dcid)
    let prk = Salt::new(HKDF_SHA256, salt).extract(dcid);
    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    let cis = hkdf_expand_label(&prk, b"client in", b"", 32)?;
    let cis_prk = Prk::new_less_safe(HKDF_SHA256, &cis);

    let key_vec = hkdf_expand_label(&cis_prk, key_label, b"", 16)?;
    let iv_vec = hkdf_expand_label(&cis_prk, iv_label, b"", 12)?;
    let hp_vec = hkdf_expand_label(&cis_prk, hp_label, b"", 16)?;

    let mut keys = InitialKeys {
        key: [0u8; 16],
        iv: [0u8; 12],
        hp: [0u8; 16],
    };
    keys.key.copy_from_slice(&key_vec);
    keys.iv.copy_from_slice(&iv_vec);
    keys.hp.copy_from_slice(&hp_vec);
    Some(keys)
}

/// Decrypt the Initial packet payload. Returns the plaintext QUIC frame
/// stream (ready for `extract_crypto_payload`) on success.
pub fn decrypt_initial_payload(
    packet: &[u8],
    header: &InitialHeader,
    keys: &InitialKeys,
) -> Option<Vec<u8>> {
    // Sample for header protection: 16 bytes starting 4 bytes past the pn
    // offset, regardless of the (still-unknown) actual pn length (RFC 9001
    // §5.4.2). The pn field is between 1 and 4 bytes; we always sample as
    // if it were 4 to keep the offset deterministic.
    let sample_offset = header.pn_offset + 4;
    if sample_offset + 16 > packet.len() {
        return None;
    }
    let sample = &packet[sample_offset..sample_offset + 16];

    let hp_key = HeaderProtectionKey::new(&HP_AES_128, &keys.hp).ok()?;
    let mask = hp_key.new_mask(sample).ok()?;

    // Long header: lower 4 bits of first byte are protected.
    let first_unprotected = packet[0] ^ (mask[0] & 0x0f);
    let pn_len = ((first_unprotected & 0x03) + 1) as usize;
    if header.pn_offset + pn_len > packet.len() {
        return None;
    }

    // Build the unprotected header (used as AEAD AAD).
    let mut header_buf = packet[..header.pn_offset + pn_len].to_vec();
    header_buf[0] = first_unprotected;
    for i in 0..pn_len {
        header_buf[header.pn_offset + i] ^= mask[1 + i];
    }

    // Reconstruct the truncated packet number. For Initial packets from a
    // fresh connection the largest acked is 0, so the truncated value is
    // the actual packet number — no decoding ambiguity.
    let mut packet_number: u64 = 0;
    for i in 0..pn_len {
        packet_number = (packet_number << 8) | header_buf[header.pn_offset + i] as u64;
    }

    // Nonce = iv XOR (packet_number padded to 12 bytes, big-endian, right-aligned).
    let mut padded_pn = [0u8; 12];
    let pn_bytes = packet_number.to_be_bytes(); // [u8; 8]
    padded_pn[4..].copy_from_slice(&pn_bytes);
    let mut nonce_bytes = [0u8; 12];
    for i in 0..12 {
        nonce_bytes[i] = keys.iv[i] ^ padded_pn[i];
    }

    // Ciphertext lives between (pn end) and (pn_offset + payload_len_with_pn);
    // the last 16 bytes are the GCM auth tag, but ring handles that internally.
    let ct_start = header.pn_offset + pn_len;
    let ct_end = header.pn_offset + header.payload_len_with_pn;
    if ct_end > packet.len() || ct_end <= ct_start {
        return None;
    }
    let mut buf = packet[ct_start..ct_end].to_vec();

    let unbound = UnboundKey::new(&AES_128_GCM, &keys.key).ok()?;
    let aead_key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = Aad::from(header_buf.as_slice());

    let plaintext = aead_key.open_in_place(nonce, aad, &mut buf).ok()?;
    Some(plaintext.to_vec())
}

/// Walk QUIC frames in a decrypted Initial payload and return the
/// reassembled CRYPTO frame contents (which carry the TLS ClientHello).
/// Frames other than CRYPTO/PADDING/PING/ACK are skipped if recognized,
/// or cause early return otherwise — Initial packets shouldn't carry
/// stream/datagram frames per RFC 9000 §17.2.2.
pub fn extract_crypto_payload(plaintext: &[u8]) -> Option<Vec<u8>> {
    // Reassemble by offset. A single packet typically carries one CRYPTO
    // frame at offset 0, but very large ClientHellos can span multiple
    // frames; we still want to handle the simple case correctly here and
    // be robust to multi-frame layouts in the same packet.
    let mut buffer: Vec<u8> = Vec::new();

    let mut pos = 0;
    while pos < plaintext.len() {
        let frame_type = plaintext[pos];
        pos += 1;
        match frame_type {
            // PADDING (0x00) and PING (0x01) — single byte, no payload.
            0x00 | 0x01 => {}
            // ACK (0x02) and ACK-with-ECN (0x03). Structure:
            //   largest_ack(varint) ack_delay(varint) ack_range_count(varint)
            //   first_ack_range(varint) [gap range]* [ECN counts]
            0x02 | 0x03 => {
                let (_, n) = read_varint(plaintext, pos)?;
                pos += n;
                let (_, n) = read_varint(plaintext, pos)?;
                pos += n;
                let (range_count, n) = read_varint(plaintext, pos)?;
                pos += n;
                let (_, n) = read_varint(plaintext, pos)?;
                pos += n;
                for _ in 0..range_count {
                    let (_, n) = read_varint(plaintext, pos)?;
                    pos += n;
                    let (_, n) = read_varint(plaintext, pos)?;
                    pos += n;
                }
                if frame_type == 0x03 {
                    // ECN counts: 3 varints
                    for _ in 0..3 {
                        let (_, n) = read_varint(plaintext, pos)?;
                        pos += n;
                    }
                }
            }
            // CRYPTO (0x06): offset(varint) length(varint) data
            0x06 => {
                let (offset, n) = read_varint(plaintext, pos)?;
                pos += n;
                let (length, n) = read_varint(plaintext, pos)?;
                pos += n;
                let length = length as usize;
                let offset = offset as usize;
                if pos + length > plaintext.len() {
                    return None;
                }
                let end = offset + length;
                if end > buffer.len() {
                    buffer.resize(end, 0);
                }
                buffer[offset..end].copy_from_slice(&plaintext[pos..pos + length]);
                pos += length;
            }
            // CONNECTION_CLOSE(0x1c, 0x1d) and unknown: stop. We don't need
            // to fully parse Initial packets that contain anything beyond
            // CRYPTO + housekeeping frames for SNI extraction purposes.
            _ => break,
        }
    }

    if buffer.is_empty() {
        None
    } else {
        Some(buffer)
    }
}

/// Top-level convenience: take a raw UDP payload and return the TLS SNI
/// from the embedded ClientHello if the payload is a decryptable client
/// QUIC Initial. Returns `None` for any failure — the caller is expected
/// to treat that as "not a QUIC Initial we can read", not an error.
pub fn try_extract_initial_sni(udp_payload: &[u8]) -> Option<String> {
    let header = parse_long_header_initial(udp_payload)?;
    let keys = derive_client_initial_keys(header.version, &header.dcid)?;
    let plaintext = decrypt_initial_payload(udp_payload, &header, &keys)?;
    let crypto = extract_crypto_payload(&plaintext)?;
    super::packets::extract_sni_for_quic(&crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from RFC 9001 Appendix A.1 (Sample Client Initial keys).
    /// Confirms the HKDF derivation matches the spec byte-for-byte.
    #[test]
    fn rfc9001_appendix_a_client_initial_keys() {
        let dcid = hex_decode("8394c8f03e515708");
        let keys = derive_client_initial_keys(QUIC_V1_VERSION, &dcid).expect("derive");
        assert_eq!(
            hex_encode(&keys.key),
            "1f369613dd76d5467730efcbe3b1a22d",
            "client key mismatch"
        );
        assert_eq!(
            hex_encode(&keys.iv),
            "fa044b2f42a3fd3b46fb255c",
            "client iv mismatch"
        );
        assert_eq!(
            hex_encode(&keys.hp),
            "9f50449e04a0e810283a1e9933adedd2",
            "client hp mismatch"
        );
    }

    #[test]
    fn varint_round_trip_known_values() {
        // RFC 9000 §16, Table 4
        assert_eq!(read_varint(&[0x25], 0), Some((37, 1)));
        assert_eq!(read_varint(&[0x40, 0x25], 0), Some((37, 2)));
        assert_eq!(read_varint(&[0x7b, 0xbd], 0), Some((15293, 2)));
        assert_eq!(
            read_varint(&[0x9d, 0x7f, 0x3e, 0x7d], 0),
            Some((494878333, 4))
        );
    }

    #[test]
    fn parse_long_header_rejects_short_header() {
        // Short header has bit 7 = 0
        let pkt = [0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        assert!(parse_long_header_initial(&pkt).is_none());
    }

    #[test]
    fn parse_long_header_rejects_handshake() {
        // Long header with packet type = Handshake (0b10)
        let mut pkt = vec![0xe0]; // 1100_0000 + (10 << 4) = 0xe0
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version v1
        pkt.extend_from_slice(&[0x00, 0x00]); // empty DCID, empty SCID
        assert!(parse_long_header_initial(&pkt).is_none());
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    /// End-to-end test against RFC 9001 Appendix A.2 (Sample Client Initial).
    /// The packet is the spec's worked example: a real Initial carrying a
    /// ClientHello with `server_name = "example.com"`. If decryption, CRYPTO
    /// reassembly, and SNI extraction are all wired correctly, we should
    /// recover that hostname from the protected wire bytes alone.
    #[test]
    fn rfc9001_appendix_a2_end_to_end_extracts_sni() {
        let packet = hex_decode(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11\
             d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399\
             1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c\
             8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212\
             30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5\
             457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208\
             4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec\
             4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3\
             485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db\
             059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c\
             7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8\
             9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556\
             be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74\
             68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a\
             c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00\
             f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632\
             291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964\
             25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd\
             14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff\
             ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198\
             e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd\
             c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73\
             203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f\
             cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e\
             fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade\
             a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047\
             90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2\
             162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4\
             40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0\
             6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e\
             8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0\
             be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400\
             54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab\
             760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9\
             f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4\
             056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064\
             7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241\
             e221af44860018ab0856972e194cd934",
        );

        // Header parsing recovers the spec's DCID and v1 version.
        let header = parse_long_header_initial(&packet).expect("parse header");
        assert_eq!(header.version, QUIC_V1_VERSION);
        assert_eq!(hex_encode(&header.dcid), "8394c8f03e515708");

        // Full pipeline: keys → unprotect → AEAD decrypt → CRYPTO → SNI.
        let sni = try_extract_initial_sni(&packet).expect("SNI extraction");
        assert_eq!(sni, "example.com");
    }
}
