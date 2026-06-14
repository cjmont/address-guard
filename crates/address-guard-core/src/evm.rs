//! EVM address validation: EIP-55 checksum, EIP-1191 (chain-id aware),
//! no-checksum detection, and zero/burn-address flagging.

use sha3::{Digest, Keccak256};

use crate::types::Risk;
use crate::types::{AddressResult, Format, Warning, EVM_NETWORKS};

/// Well-known burn address (lowercased, no `0x`).
const BURN_DEAD: &str = "000000000000000000000000000000000000dead";
const ZERO: &str = "0000000000000000000000000000000000000000";

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Return the 40-char hex body if `addr` has EVM shape (`0x` + 40 hex), else None.
fn evm_body(addr: &str) -> Option<&str> {
    let body = addr
        .strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))?;
    if body.len() == 40 && body.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(body)
    } else {
        None
    }
}

/// Whether the string has valid EVM shape (ignores checksum).
pub fn is_evm_shape(addr: &str) -> bool {
    evm_body(addr).is_some()
}

/// Compute the EIP-55 (or EIP-1191 when `chain_id` is given) checksummed form.
/// Returns None if `addr` is not EVM-shaped.
pub fn checksum_evm(addr: &str, chain_id: Option<u64>) -> Option<String> {
    let body = evm_body(addr)?;
    let lower = body.to_ascii_lowercase();

    // EIP-1191 prefixes the hashed input with `<chainId>0x`.
    let mut to_hash = String::new();
    if let Some(id) = chain_id {
        to_hash.push_str(&id.to_string());
        to_hash.push_str("0x");
    }
    to_hash.push_str(&lower);

    let hash = keccak256(to_hash.as_bytes());
    let hash_hex = hex::encode(hash); // 64 lowercase hex chars

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            let nibble = (hash_hex.as_bytes()[i] as char).to_digit(16).unwrap();
            if nibble >= 8 {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// Validate an EVM-shaped address. Returns None if the input is not EVM-shaped
/// (so a dispatcher can try other formats).
pub fn try_validate_evm(input: &str, chain_id: Option<u64>) -> Option<AddressResult> {
    let body = evm_body(input)?;
    let lower = body.to_ascii_lowercase();
    let has_upper = body.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower_alpha = body.bytes().any(|b| b.is_ascii_lowercase());
    let mixed_case = has_upper && has_lower_alpha;

    let canonical = checksum_evm(input, chain_id).expect("evm-shaped");
    let mut warnings: Vec<Warning> = Vec::new();
    let mut valid = true;
    let mut format = Format::Evm;

    if mixed_case {
        // Mixed case carries an EIP-55/EIP-1191 checksum that must verify.
        if format_eq(input, &canonical) {
            format = Format::Evm;
        } else {
            valid = false;
            warnings.push(Warning::new(
                "EVM_CHECKSUM_MISMATCH",
                "mixed-case address fails EIP-55/EIP-1191 checksum (likely a typo or corruption)",
                Risk::High,
            ));
        }
    } else {
        // All-lower / all-upper / all-digit: valid shape but no checksum protection.
        format = Format::EvmNoChecksum;
        warnings.push(Warning::new(
            "EVM_NO_CHECKSUM",
            "address has no EIP-55 checksum protection (all one case); a typo would not be caught",
            Risk::Medium,
        ));
    }

    // Zero / burn detection (independent of checksum).
    if lower == ZERO {
        warnings.push(Warning::new(
            "EVM_ZERO_ADDRESS",
            "this is the zero address (0x0…0); funds sent here are unrecoverable",
            Risk::High,
        ));
    } else if lower == BURN_DEAD {
        warnings.push(Warning::new(
            "EVM_BURN_ADDRESS",
            "this is a known burn address (0x…dEaD); funds sent here are unrecoverable",
            Risk::High,
        ));
    }

    let mut result = AddressResult {
        valid,
        format: Some(format),
        normalized: if valid { Some(canonical) } else { None },
        networks: if valid {
            EVM_NETWORKS.to_vec()
        } else {
            Vec::new()
        },
        risk: Risk::None,
        warnings,
    };
    result.recompute_risk();
    Some(result)
}

/// Case-sensitive comparison that tolerates a `0X` vs `0x` prefix difference.
fn format_eq(input: &str, canonical: &str) -> bool {
    let i = input
        .strip_prefix("0X")
        .or_else(|| input.strip_prefix("0x"))
        .unwrap_or(input);
    let c = canonical.strip_prefix("0x").unwrap_or(canonical);
    i == c
}
