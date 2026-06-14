//! Solana address validation: base58 (32 bytes), ed25519 on-curve vs off-curve
//! (PDA) detection, and known program/system address flagging.

use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::types::{AddressResult, Format, Network, Risk, Warning};

/// Curated, minimal set of well-known program/system addresses. Sending funds
/// to these is almost always a mistake, so they are flagged `high`.
const KNOWN_PROGRAMS: &[(&str, &str)] = &[
    ("11111111111111111111111111111111", "Solana System Program"),
    (
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "SPL Token Program",
    ),
    (
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "SPL Token-2022 Program",
    ),
    (
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "Associated Token Account Program",
    ),
    (
        "1nc1nerator11111111111111111111111111111111",
        "Solana Incinerator (burn)",
    ),
];

/// An ed25519 public key is "on curve" iff its compressed form decompresses.
/// Off-curve 32-byte values are Program Derived Addresses (no private key).
fn is_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// Validate a Solana-shaped address. Returns None if the input does not decode
/// from base58 to exactly 32 bytes (so a dispatcher can try other formats).
pub fn try_validate_solana(input: &str) -> Option<AddressResult> {
    // base58 of 32 bytes is 32..=44 chars; gate before decoding.
    if !(32..=44).contains(&input.len()) {
        return None;
    }
    // bs58's default alphabet already rejects 0, O, I, l and other non-base58.
    let bytes = bs58::decode(input).into_vec().ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let arr: [u8; 32] = bytes.try_into().unwrap();
    let normalized = bs58::encode(arr).into_string();

    let mut warnings: Vec<Warning> = Vec::new();
    if let Some((_, label)) = KNOWN_PROGRAMS.iter().find(|(a, _)| *a == normalized) {
        warnings.push(Warning::new(
            "SOLANA_KNOWN_PROGRAM",
            &format!("{label}: a program/system address, not a wallet; do not send funds here"),
            Risk::High,
        ));
    } else if !is_on_curve(&arr) {
        warnings.push(Warning::new(
            "SOLANA_OFF_CURVE_PDA",
            "off-curve address (likely a PDA / program address); it cannot sign — verify before sending SPL tokens",
            Risk::Medium,
        ));
    }

    let mut result = AddressResult {
        valid: true,
        format: Some(Format::Solana),
        normalized: Some(normalized),
        networks: vec![Network::Solana],
        risk: Risk::None,
        warnings,
    };
    result.recompute_risk();
    Some(result)
}
