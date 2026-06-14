//! # address-guard-core
//!
//! Address validation with a transfer-safety focus for EVM, Solana and TRON.
//! Not "is this a valid address?" but "is it safe to send funds here?".
//!
//! Every validation returns a structured [`AddressResult`] with a [`Risk`] level
//! and [`Warning`]s. We fail closed: ambiguity raises risk, never approval.

mod compare;
mod evm;
mod scrub;
mod solana;
mod tron;
mod types;

pub use compare::{compare_addresses, Comparison};
pub use evm::{checksum_evm, is_evm_shape};
pub use types::{AddressResult, Format, Network, Risk, Warning, EVM_NETWORKS};

/// Validate an address across all supported formats (EVM, TRON, Solana).
///
/// Input is first scrubbed (fail-closed): non-ASCII / invisible / confusable
/// characters are rejected outright.
pub fn validate(input: &str) -> AddressResult {
    let clean = match scrub::scrub(input) {
        Ok(c) => c,
        Err(w) => {
            return AddressResult {
                valid: false,
                format: None,
                normalized: None,
                networks: Vec::new(),
                risk: w.severity,
                warnings: vec![w],
            };
        }
    };

    if let Some(result) = evm::try_validate_evm(&clean, None) {
        return result;
    }
    if let Some(result) = tron::try_validate_tron(&clean) {
        return result;
    }
    if let Some(result) = solana::try_validate_solana(&clean) {
        return result;
    }

    AddressResult::invalid(
        "UNRECOGNIZED_FORMAT",
        "address does not match any supported format",
    )
}

/// Validate an address against an expected network, adding a high-severity
/// `NETWORK_MISMATCH` warning when the detected format cannot belong to it.
pub fn validate_for_network(input: &str, network: Network) -> AddressResult {
    let mut result = validate(input);
    if !result.valid {
        return result;
    }

    if !result.networks.contains(&network) {
        result.warnings.push(Warning::new(
            "NETWORK_MISMATCH",
            "address format does not match the requested network — do not send funds",
            Risk::High,
        ));
    } else if network.is_evm() && network != Network::Evm {
        // The address is valid on every EVM chain; being valid is not the same
        // as the funds being safe on this specific chain.
        result.warnings.push(Warning::new(
            "EVM_CHAIN_INFO",
            "valid on all EVM chains; 'valid' does not guarantee the funds are safe on this specific chain",
            Risk::Low,
        ));
    }
    result.recompute_risk();
    result
}

/// Detect which networks an address could belong to (empty if invalid).
pub fn detect_networks(input: &str) -> Vec<Network> {
    validate(input).networks
}

/// Convenience boolean: valid for `network` and free of high-severity warnings.
pub fn is_valid(input: &str, network: Network) -> bool {
    let r = validate_for_network(input, network);
    r.valid && r.risk != Risk::High
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical EIP-55 test vectors (from the EIP-55 specification).
    const EIP55_VALID: [&str; 4] = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    #[test]
    fn eip55_valid_vectors() {
        for a in EIP55_VALID {
            let r = validate(a);
            assert!(r.valid, "{a} should be valid");
            assert_eq!(r.format, Some(Format::Evm));
            assert_eq!(r.normalized.as_deref(), Some(a));
            assert_eq!(r.risk, Risk::None, "{a} should be risk-free");
            assert!(r.networks.contains(&Network::Ethereum));
        }
    }

    #[test]
    fn checksum_is_idempotent() {
        for a in EIP55_VALID {
            let c = checksum_evm(a, None).unwrap();
            assert_eq!(c, a);
            // re-validating the normalized form yields the same string
            let r = validate(&c);
            assert_eq!(r.normalized.as_deref(), Some(c.as_str()));
        }
    }

    #[test]
    fn all_lowercase_is_no_checksum_medium() {
        let r = validate("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
        assert!(r.valid);
        assert_eq!(r.format, Some(Format::EvmNoChecksum));
        assert_eq!(r.risk, Risk::Medium);
        assert!(r.warnings.iter().any(|w| w.code == "EVM_NO_CHECKSUM"));
        // normalized is the proper checksummed form
        assert_eq!(
            r.normalized.as_deref(),
            Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
        );
    }

    #[test]
    fn all_uppercase_is_no_checksum() {
        let r = validate("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED");
        assert!(r.valid);
        assert_eq!(r.format, Some(Format::EvmNoChecksum));
        assert_eq!(r.risk, Risk::Medium);
    }

    #[test]
    fn broken_checksum_is_invalid_high() {
        // last nibble case flipped from the valid vector
        let r = validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD");
        assert!(!r.valid);
        assert_eq!(r.risk, Risk::High);
        assert!(r.warnings.iter().any(|w| w.code == "EVM_CHECKSUM_MISMATCH"));
        assert!(r.normalized.is_none());
    }

    #[test]
    fn zero_address_is_valid_but_high_risk() {
        let r = validate("0x0000000000000000000000000000000000000000");
        assert!(r.valid); // structurally valid
        assert_eq!(r.risk, Risk::High);
        assert!(r.warnings.iter().any(|w| w.code == "EVM_ZERO_ADDRESS"));
    }

    #[test]
    fn burn_dead_address_is_high_risk() {
        let r = validate("0x000000000000000000000000000000000000dEaD");
        assert!(r.valid);
        assert_eq!(r.risk, Risk::High);
        assert!(r.warnings.iter().any(|w| w.code == "EVM_BURN_ADDRESS"));
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let r = validate("  0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed  ");
        assert!(r.valid);
        assert_eq!(r.format, Some(Format::Evm));
    }

    #[test]
    fn bad_shape_is_unrecognized() {
        for a in [
            "0x123",
            "not an address",
            "",
            "0xZZZ6916095ca1df60bB79Ce92cE3Ea74c37c5d35",
        ] {
            let r = validate(a);
            assert!(!r.valid, "{a:?} should be invalid");
        }
    }

    // ---- Solana ----

    #[test]
    fn solana_on_curve_is_valid_no_pda_warning() {
        // The ed25519 basepoint is on-curve by definition.
        let bytes = curve25519_dalek::constants::ED25519_BASEPOINT_POINT
            .compress()
            .to_bytes();
        let addr = bs58::encode(bytes).into_string();
        let r = validate(&addr);
        assert!(r.valid);
        assert_eq!(r.format, Some(Format::Solana));
        assert_eq!(r.networks, vec![Network::Solana]);
        assert_eq!(r.normalized.as_deref(), Some(addr.as_str()));
        assert!(!r.warnings.iter().any(|w| w.code == "SOLANA_OFF_CURVE_PDA"));
        assert_eq!(r.risk, Risk::None);
    }

    #[test]
    fn solana_off_curve_is_pda_medium() {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        // Find a 32-byte value that is NOT on the curve (a PDA-like address).
        let mut b = [1u8; 32];
        let off = (0u8..=255)
            .find_map(|i| {
                b[31] = i;
                if CompressedEdwardsY(b).decompress().is_none() {
                    Some(b)
                } else {
                    None
                }
            })
            .expect("an off-curve value exists");
        let addr = bs58::encode(off).into_string();
        let r = validate(&addr);
        assert!(r.valid);
        assert_eq!(r.format, Some(Format::Solana));
        assert_eq!(r.risk, Risk::Medium);
        assert!(r.warnings.iter().any(|w| w.code == "SOLANA_OFF_CURVE_PDA"));
    }

    #[test]
    fn solana_known_programs_are_high() {
        for prog in [
            "11111111111111111111111111111111",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "1nc1nerator11111111111111111111111111111111",
        ] {
            let r = validate(prog);
            assert_eq!(r.format, Some(Format::Solana), "{prog} should be Solana");
            assert_eq!(r.risk, Risk::High, "{prog} should be high risk");
            assert!(r.warnings.iter().any(|w| w.code == "SOLANA_KNOWN_PROGRAM"));
        }
    }

    #[test]
    fn solana_invalid_alphabet_or_length_unrecognized() {
        // contains base58-invalid chars (0, O, I, l)
        assert!(!validate("0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl").valid);
        // valid base58 but not 32 bytes (too short)
        assert!(!validate("abcdef").valid);
    }

    #[test]
    fn evm_not_misdetected_as_solana() {
        let r = validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert_eq!(r.format, Some(Format::Evm));
    }

    // ---- TRON ----

    #[test]
    fn tron_base58_and_hex_cross_validate() {
        let payload = [0xABu8; 20];
        let b58 = tron::payload_to_base58(&payload); // canonical T…
        assert!(b58.starts_with('T'));

        // base58 form
        let r58 = validate(&b58);
        assert!(r58.valid);
        assert_eq!(r58.format, Some(Format::TronBase58));
        assert_eq!(r58.networks, vec![Network::Tron]);
        assert_eq!(r58.normalized.as_deref(), Some(b58.as_str()));

        // hex form normalizes to the SAME base58 (cross-validation)
        let hexform = format!("41{}", hex::encode(payload));
        let rhex = validate(&hexform);
        assert!(rhex.valid);
        assert_eq!(rhex.format, Some(Format::TronHex));
        assert_eq!(rhex.normalized.as_deref(), Some(b58.as_str()));

        // 0x-prefixed hex also accepted
        let r0x = validate(&format!("0x41{}", hex::encode(payload)));
        assert_eq!(r0x.normalized.as_deref(), Some(b58.as_str()));
    }

    #[test]
    fn tron_known_vector() {
        // USDT-TRON (TRC20) contract address
        let r = validate("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
        assert!(r.valid);
        assert_eq!(r.format, Some(Format::TronBase58));
        assert_eq!(
            r.normalized.as_deref(),
            Some("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
        );
    }

    #[test]
    fn tron_broken_checksum_is_invalid() {
        let payload = [0x11u8; 20];
        let mut b58 = tron::payload_to_base58(&payload);
        // corrupt the last char to a different base58 char
        let last = b58.pop().unwrap();
        b58.push(if last == 'a' { 'b' } else { 'a' });
        let r = validate(&b58);
        assert!(!r.valid);
        assert_eq!(r.risk, Risk::High);
        assert!(r.warnings.iter().any(|w| w.code == "TRON_CHECKSUM_INVALID"));
    }

    #[test]
    fn tron_wrong_version_byte_is_unrecognized() {
        use sha2::{Digest, Sha256};
        // build a base58check blob with a non-TRON version byte (0x00)
        let mut data = vec![0x00u8];
        data.extend_from_slice(&[0x22u8; 20]);
        let c1 = Sha256::digest(&data);
        let c2 = Sha256::digest(c1);
        data.extend_from_slice(&c2[..4]);
        let foreign = bs58::encode(data).into_string();
        let r = validate(&foreign);
        assert!(!r.valid);
        assert!(r.warnings.iter().any(|w| w.code == "UNRECOGNIZED_FORMAT"));
    }

    #[test]
    fn tron_hex_not_misdetected_as_evm() {
        // 0x41 + 40 hex = 42 hex chars; must be TRON hex, not a 40-hex EVM addr
        let payload = [0x33u8; 20];
        let r = validate(&format!("41{}", hex::encode(payload)));
        assert_eq!(r.format, Some(Format::TronHex));
    }

    // ---- Phase 4: transversal transfer-safety ----

    const VALID_EVM: &str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    const VALID_TRON: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

    #[test]
    fn scrub_rejects_zero_width_and_homoglyphs() {
        // trailing zero-width space
        let r = validate("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\u{200B}");
        assert!(!r.valid);
        assert!(r.warnings.iter().any(|w| w.code == "INPUT_NON_ASCII"));
        // Cyrillic 'а' (U+0430) homoglyph swapped for ASCII 'a'
        let r2 = validate("0x5\u{0430}Aeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        assert!(!r2.valid);
        assert!(r2.warnings.iter().any(|w| w.code == "INPUT_NON_ASCII"));
    }

    #[test]
    fn scrub_rejects_internal_whitespace_but_trims_ends() {
        assert!(!validate("0x5aAeb6053F3E94 C9b9A09f33669435E7Ef1BeAed").valid); // internal space
        assert!(validate("\t  0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed \n").valid);
        // trimmed ends
    }

    #[test]
    fn network_mismatch_is_high() {
        // TRON address requested as ethereum
        let r = validate_for_network(VALID_TRON, Network::Ethereum);
        assert_eq!(r.risk, Risk::High);
        assert!(r.warnings.iter().any(|w| w.code == "NETWORK_MISMATCH"));
        // EVM address requested as solana
        let r2 = validate_for_network(VALID_EVM, Network::Solana);
        assert!(r2.warnings.iter().any(|w| w.code == "NETWORK_MISMATCH"));
    }

    #[test]
    fn specific_evm_chain_adds_info_warning() {
        let r = validate_for_network(VALID_EVM, Network::Polygon);
        assert!(r.warnings.iter().any(|w| w.code == "EVM_CHAIN_INFO"));
        assert_eq!(r.risk, Risk::Low); // informational only
    }

    #[test]
    fn detect_networks_and_is_valid() {
        assert!(detect_networks(VALID_EVM).contains(&Network::Ethereum));
        assert_eq!(detect_networks(VALID_TRON), vec![Network::Tron]);
        assert!(is_valid(VALID_EVM, Network::Ethereum));
        assert!(!is_valid(VALID_TRON, Network::Ethereum)); // mismatch → high → false
        assert!(!is_valid(
            "0x0000000000000000000000000000000000000000",
            Network::Ethereum
        )); // zero address → high → false
    }

    #[test]
    fn compare_equal_across_casing() {
        let lower = VALID_EVM.to_ascii_lowercase();
        let c = compare_addresses(VALID_EVM, &lower);
        assert!(c.equal); // same address, different casing
        assert_eq!(c.poisoning_risk, Risk::None);
        assert_eq!(c.edit_distance, 0);
    }

    #[test]
    fn compare_detects_poisoning_high() {
        // same first 6 and last 4 chars, different middle → poisoning signature
        let a = format!("0x{}{}{}", "abcd", "0".repeat(32), "abcd");
        let b = format!("0x{}{}{}", "abcd", "1".repeat(32), "abcd");
        let c = compare_addresses(&a, &b);
        assert!(!c.equal);
        assert!(c.prefix_match >= 4 && c.suffix_match >= 4);
        assert_eq!(c.poisoning_risk, Risk::High);
    }

    #[test]
    fn compare_distinct_addresses_low_poisoning() {
        let a = VALID_EVM;
        let b = "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359";
        let c = compare_addresses(a, b);
        assert!(!c.equal);
        assert_ne!(c.poisoning_risk, Risk::High);
    }

    // ---- EVM (cont.) ----

    #[test]
    fn eip1191_differs_from_eip55_and_roundtrips() {
        let base = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let c55 = checksum_evm(base, None).unwrap();
        let c30 = checksum_evm(base, Some(30)).unwrap();
        let c31 = checksum_evm(base, Some(31)).unwrap();
        // chain-id-aware checksums differ from plain EIP-55 (and from each other)
        assert_ne!(c55, c30);
        assert_ne!(c30, c31);
        // an EIP-1191 address validates under the same chain id
        let r = evm::try_validate_evm(&c30, Some(30)).unwrap();
        assert!(r.valid);
        assert_eq!(r.normalized.as_deref(), Some(c30.as_str()));
        // ...but fails under a different chain id (mixed case, wrong checksum)
        let r_wrong = evm::try_validate_evm(&c30, Some(31)).unwrap();
        assert!(!r_wrong.valid);
    }
}
