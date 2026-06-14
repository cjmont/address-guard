//! TRON address validation.
//!
//! TRON addresses exist in two interchangeable forms over the same 20-byte body:
//!   * base58check (`T…`): `0x41 ‖ payload(20) ‖ checksum(4)`, checksum =
//!     first 4 bytes of `SHA256(SHA256(0x41 ‖ payload))`.
//!   * hex (`41…`): `0x41 ‖ payload(20)` = 42 hex chars.
//!
//! Either form is validated and cross-converted; `normalized` is always the
//! canonical base58 `T…` form. Wrong version bytes and bad checksums are rejected.

use sha2::{Digest, Sha256};

use crate::types::{AddressResult, Format, Network, Risk};

const VERSION: u8 = 0x41;

fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Build the canonical base58check `T…` form from a 20-byte payload.
pub(crate) fn payload_to_base58(payload: &[u8; 20]) -> String {
    let mut data = Vec::with_capacity(25);
    data.push(VERSION);
    data.extend_from_slice(payload);
    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);
    bs58::encode(data).into_string()
}

/// Parse a TRON hex address (`41…`, optional `0x`), returning the 20-byte payload.
fn tron_hex_payload(input: &str) -> Option<[u8; 20]> {
    let body = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input);
    if body.len() != 42 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(body).ok()?; // 21 bytes
    if bytes[0] != VERSION {
        return None;
    }
    let mut payload = [0u8; 20];
    payload.copy_from_slice(&bytes[1..21]);
    Some(payload)
}

fn ok_result(payload: [u8; 20], format: Format) -> AddressResult {
    AddressResult {
        valid: true,
        format: Some(format),
        normalized: Some(payload_to_base58(&payload)),
        networks: vec![Network::Tron],
        risk: Risk::None,
        warnings: Vec::new(),
    }
}

/// Validate a TRON-shaped address (base58 `T…` or hex `41…`). Returns None if
/// the input is not TRON-shaped, so a dispatcher can try other formats.
pub fn try_validate_tron(input: &str) -> Option<AddressResult> {
    // --- hex form (41… / 0x41…) ---
    if let Some(payload) = tron_hex_payload(input) {
        return Some(ok_result(payload, Format::TronHex));
    }

    // --- base58check form (T…) ---
    // Canonical TRON base58 is 34 chars; gate before decoding.
    if !(30..=40).contains(&input.len()) {
        return None;
    }
    let decoded = bs58::decode(input).into_vec().ok()?;
    if decoded.len() != 25 {
        return None;
    }
    // A 25-byte base58check blob with a non-TRON version byte is some other
    // chain's address — not ours to validate.
    if decoded[0] != VERSION {
        return None;
    }

    let (body, checksum) = decoded.split_at(21);
    let expected = double_sha256(body);
    if checksum != &expected[..4] {
        return Some(AddressResult::invalid(
            "TRON_CHECKSUM_INVALID",
            "TRON address fails its base58check checksum (likely a typo or corruption)",
        ));
    }

    let mut payload = [0u8; 20];
    payload.copy_from_slice(&body[1..21]);
    Some(ok_result(payload, Format::TronBase58))
}
