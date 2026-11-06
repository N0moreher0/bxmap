//! Key-candidate scanning for the `--find-keys` module (Phase 8.5).
//!
//! The carver and the entropy scanner answer "where is the encrypted data?".
//! This module implements the missing "so what can we try next?" lookup: it
//! scans a dump for stored private-key material -- DER PKCS#8 envelopes
//! (RSA / EC) and OpenSSH binary private-key blobs -- and reports every hit
//! as a [`KeyCandidate`] with key family, algorithm label, length and SHA-1
//! fingerprint.
//!
//! Design constraints (same spirit as the rest of the crate):
//! - bxmap never decrypts and never cracks: this module only *finds* candidate
//!   key material so an analyst can try it offline against the container.
//! - Raw key bytes are never surfaced to the caller: only the SHA-1 fingerprint
//!   and metadata, so a candidate can be referenced without leaking the secret.
//! - Everything is bounds-checked and length-limited (headers must decode to
//!   plausible sizes), so hostile input cannot blow up the scanner.

use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::chunk::{self, CHUNK_SIZE};

/// Key family label for RSA private keys found in a DER envelope.
pub const KIND_RSA_PRIVATE_KEY: &str = "rsa_private_key";
/// Key family label for EC private keys found in a DER envelope.
pub const KIND_EC_PRIVATE_KEY: &str = "ec_private_key";
/// Key family label for OpenSSH private keys found as binary blobs.
pub const KIND_OPENSSH_PRIVATE_KEY: &str = "openssh_private_key";

/// Algorithm label inside a PKCS#8 envelope (RFC 8017 algorithm OIDs).
pub const ALGORITHM_RSA: &str = "rsaEncryption";
pub const ALGORITHM_EC: &str = "ecPublicKey";

/// Overlap retained between chunk windows for the key scan. Key headers are
/// short, but a blob can straddle a window boundary, so keep the same overlap
/// convention as the other streaming scanners.
pub const KEY_SCAN_OVERLAP: usize = 64;

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1";

/// One candidate private-key hit inside a dump.
#[derive(Debug, Clone, Serialize)]
pub struct KeyCandidate {
    /// File offset of the key material (start of the DER envelope / blob).
    pub offset: u64,
    /// Key family label, e.g. [`KIND_RSA_PRIVATE_KEY`].
    pub kind: &'static str,
    /// Algorithm label, e.g. [`ALGORITHM_RSA`].
    pub algorithm: String,
    /// Encrypted container this key may belong to, when known. `None` while
    /// the Phase 8.4 container correlation is not wired into the scan.
    pub container: Option<&'static str>,
    /// Byte length of the reported key material.
    pub length: usize,
    /// Lowercase hex SHA-1 fingerprint of the key blob (heuristic over raw
    /// DER; OpenSSH uses the SHA-1 of the parsed key blob).
    pub fingerprint: String,
}

impl KeyCandidate {
    /// Associates a candidate with the encrypted container it may unlock.
    pub fn with_container(mut self, container: &'static str) -> Self {
        self.container = Some(container);
        self
    }
}

/// Cursor-based DER reader. Every accessor is bounds-checked; malformed
/// input yields `None` instead of panicking.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    fn u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.u8()?;
        let first = self.u8()?;
        let len = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 4 {
                return None;
            }
            let mut value = 0u32;
            for _ in 0..count {
                value = (value << 8) | self.u8()? as u32;
            }
            value as usize
        };
        let value = self.take(len)?;
        Some((tag, value))
    }
}

/// Decodes a DER OID body into a dotted string ("1.2.840.113549.1.1.1").
/// The body uses base-128 varint encoding per arc after the first two arcs.
fn oid_dotted(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let first = bytes[0] as u32;
    let mut arcs = vec![first / 40, first % 40];
    let mut current = 0u32;
    for &byte in &bytes[1..] {
        current = current.saturating_mul(128) + (byte & 0x7f) as u32;
        if byte < 0x80 {
            arcs.push(current);
            current = 0;
        }
    }
    if current != 0 {
        return None;
    }
    Some(
        arcs.iter()
            .map(|arc| arc.to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

fn fingerprint_hex(bytes: &[u8]) -> String {
    let digest = Sha1::digest(bytes);
    hex_lower(&digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn starts_with_openssh_magic(data: &[u8], start: usize) -> bool {
    if data.len() < start + 22 {
        return false;
    }
    data[start] == 0
        && data[start + 1] == 0
        && data[start + 2] == 0
        && data[start + 3] == 13
        && data[start + 4..start + 18] == *OPENSSH_MAGIC
}

/// Detects private-key material at `offset` inside `data`.
fn detect_key_at(data: &[u8], offset: u64) -> Option<KeyCandidate> {
    let start = offset as usize;
    if starts_with_openssh_magic(data, start) {
        return detect_openssh_key(data, start);
    }
    detect_der_private_key(data, start)
}

fn detect_openssh_key(data: &[u8], start: usize) -> Option<KeyCandidate> {
    if data.len() < start + 22 {
        return None;
    }
    if data[start..start + 4] != [0, 0, 0, 13] {
        return None;
    }
    if &data[start + 4..start + 18] != OPENSSH_MAGIC {
        return None;
    }
    let mut pos = start + 18;
    let version = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;
    if version != 1 {
        return None;
    }
    let _cipher = read_openssh_string(data, pos)?.1;
    pos = _cipher;
    let _kdf = read_openssh_string(data, pos)?.1;
    pos = _kdf;
    let (kex_algo, new_pos) = read_openssh_string(data, pos)?;
    pos = new_pos;
    // Skip u32 nkeys.
    if data.len() < pos + 4 {
        return None;
    }
    pos += 4;
    let kex_str = std::str::from_utf8(kex_algo).ok()?;
    let blob = &data[start..pos];
    Some(KeyCandidate {
        offset: start as u64,
        kind: KIND_OPENSSH_PRIVATE_KEY,
        algorithm: if kex_str.starts_with("ssh-") {
            kex_str.to_string()
        } else {
            "openssh".to_string()
        },
        container: None,
        length: blob.len(),
        fingerprint: fingerprint_hex(blob),
    })
}

/// Reads an OpenSSH wire-format `string` (u32 length + bytes) at `pos`.
/// Returns `(slice, pos_past_string)`.
fn read_openssh_string(data: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    if data.len() < pos + 4 {
        return None;
    }
    let len = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    let end = pos.checked_add(4)?.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((&data[pos + 4..end], end))
}

fn detect_der_private_key(data: &[u8], start: usize) -> Option<KeyCandidate> {
    if data.get(start) != Some(&0x30) {
        return None;
    }
    let mut outer = Cursor::new(data, start);
    let (outer_tag, outer_value) = outer.tlv()?;
    if outer_tag != 0x30 {
        return None;
    }
    let mut seq = Cursor::new(outer_value, 0);
    let (version_tag, _version_value) = seq.tlv()?;
    if version_tag != 0x02 {
        return None;
    }
    let (alg_tag, alg_value) = seq.tlv()?;
    if alg_tag != 0x30 {
        return None;
    }
    let mut alg = Cursor::new(alg_value, 0);
    let (_, oid_value) = alg.tlv()?;
    let oid = oid_dotted(oid_value)?;
    let (_, key_value) = seq.tlv()?;
    let mut key = Cursor::new(key_value, 0);
    let (key_tag, key_der) = key.tlv()?;
    if key_tag != 0x30 {
        return None;
    }
    let (kind, algorithm) = if oid == "1.2.840.113549.1.1.1" {
        (KIND_RSA_PRIVATE_KEY, ALGORITHM_RSA)
    } else if oid == "1.2.840.10045.2.1" {
        (KIND_EC_PRIVATE_KEY, ALGORITHM_EC)
    } else {
        return None;
    };
    Some(KeyCandidate {
        offset: start as u64,
        kind,
        algorithm: algorithm.to_string(),
        container: None,
        length: key_der.len(),
        fingerprint: fingerprint_hex(key_der),
    })
}

/// Scans a dump file for private-key candidates, streaming in bounded chunks
/// (never loads the whole file into RAM).
///
/// `on_candidate` returning `false` stops the scan early.
pub fn scan_key_candidates_from_file_streaming<F>(
    path: &str,
    mut on_candidate: F,
) -> std::io::Result<usize>
where
    F: FnMut(KeyCandidate) -> bool,
{
    let mut emitted = 0usize;
    chunk::for_each_chunk(path, CHUNK_SIZE, KEY_SCAN_OVERLAP, |chunk| {
        let data = chunk.data;
        let mut index = chunk.overlap;
        while index < data.len() {
            let is_key_start = (data[index] == 0x30 && data.len() >= index + 8)
                || starts_with_openssh_magic(data, index);
            let candidate = if is_key_start {
                detect_key_at(data, chunk.offset + index as u64)
            } else {
                None
            };
            if let Some(found) = candidate {
                if !on_candidate(found) {
                    return false;
                }
                emitted += 1;
            }
            index += 1;
        }
        true
    })?;
    Ok(emitted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(value.len() as u8);
        } else {
            out.push(0x80 | 4);
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(value);
        out
    }

    fn string(value: &[u8]) -> Vec<u8> {
        let mut out = (value.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(value);
        out
    }

    fn u32_be(value: u32) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    fn der_seq(contents: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        for c in contents {
            body.extend_from_slice(c);
        }
        tlv(0x30, &body)
    }

    fn pkcs8_envelope(oid: &[u8], inner: Vec<u8>) -> Vec<u8> {
        let algorithm = der_seq(&[tlv(0x06, oid), tlv(0x05, &[])]);
        der_seq(&[tlv(0x02, &[0]), algorithm, tlv(0x04, &tlv(0x30, &inner))])
    }

    #[test]
    fn detects_pkcs8_rsa_private_key_blob() {
        // SEQUENCE { INTEGER version, SEQUENCE { OID rsaEncryption, NULL },
        //            OCTET STRING { SEQUENCE { INTEGER n, INTEGER e } } }
        let blob = pkcs8_envelope(
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
            [tlv(0x02, &[1]), tlv(0x02, &[5])].concat(),
        );
        let candidate = detect_key_at(&blob, 0).expect("RSA key blob must be detected");
        assert_eq!(candidate.kind, KIND_RSA_PRIVATE_KEY);
        assert_eq!(candidate.algorithm, ALGORITHM_RSA);
        assert_eq!(candidate.offset, 0);
        assert_eq!(candidate.length, 6);
        assert!(!candidate.fingerprint.is_empty());
    }

    #[test]
    fn detects_ec_private_key_blob() {
        let blob = pkcs8_envelope(
            &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
            [tlv(0x02, &[1])].concat(),
        );
        let candidate = detect_key_at(&blob, 0).expect("EC key blob must be detected");
        assert_eq!(candidate.kind, KIND_EC_PRIVATE_KEY);
        assert_eq!(candidate.algorithm, ALGORITHM_EC);
    }

    #[test]
    fn detects_openssh_ed25519_private_key_blob() {
        // OpenSSH private-key v1 header: u32 len "openssh-key-v1", u32 version=1,
        // string cipher, string kdf, string kex_algo, u32 nkeys.
        let mut blob = u32_be(13);
        blob.extend_from_slice(b"openssh-key-v1");
        blob.extend_from_slice(&u32_be(1));
        blob.extend_from_slice(&string(b"none"));
        blob.extend_from_slice(&string(b"none"));
        blob.extend_from_slice(&string(b"ssh-ed25519"));
        blob.extend_from_slice(&u32_be(1));
        let candidate = detect_openssh_key(&blob, 0).expect("OpenSSH key blob must be detected");
        assert_eq!(candidate.kind, KIND_OPENSSH_PRIVATE_KEY);
        assert!(!candidate.fingerprint.is_empty());
    }

    #[test]
    fn rejects_plain_text_and_garbage() {
        assert!(detect_key_at(b"just some plain text, nothing to see here", 0).is_none());
        assert!(detect_key_at(&[0u8; 64], 0).is_none());
        assert!(detect_key_at(b"\x30\x01\x02", 0).is_none());
    }

    #[test]
    fn scan_streams_key_candidates_from_file() {
        let path = std::env::temp_dir().join(format!(
            "bxmap-keys-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            pkcs8_envelope(
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
                [tlv(0x02, &[1]), tlv(0x02, &[5])].concat(),
            ),
        )
        .unwrap();
        let mut found = Vec::new();
        let emitted =
            scan_key_candidates_from_file_streaming(&path.to_string_lossy(), |candidate| {
                found.push(candidate);
                true
            })
            .unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(emitted, 1);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, KIND_RSA_PRIVATE_KEY);
    }
}
