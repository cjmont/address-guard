//! Input scrubbing — fail-closed.
//!
//! Every supported address (EVM hex, Solana/TRON base58, TRON hex) is pure
//! ASCII. We therefore reject **any** non-ASCII character, which in one rule
//! covers the whole confusable/invisible attack surface: zero-width characters
//! (U+200B–200D, U+FEFF, …), bidirectional controls (U+202A–202E, U+2066–2069),
//! non-breaking spaces, and unicode homoglyphs (e.g. Cyrillic look-alikes).
//! Leading/trailing ASCII whitespace is trimmed silently; internal whitespace or
//! control characters are rejected.

use crate::types::{Risk, Warning};

/// Trim ASCII whitespace and reject confusable/invisible/non-ASCII input.
/// Returns the cleaned ASCII string, or a high-severity [`Warning`] on rejection.
pub fn scrub(input: &str) -> Result<String, Warning> {
    let trimmed = input.trim_matches(|c: char| c.is_ascii_whitespace());

    for c in trimmed.chars() {
        if !c.is_ascii() {
            return Err(Warning::new(
                "INPUT_NON_ASCII",
                "address contains a non-ASCII, invisible, or confusable character (e.g. zero-width, bidi control, or unicode homoglyph) and was rejected",
                Risk::High,
            ));
        }
        if c.is_ascii_control() || c == ' ' {
            return Err(Warning::new(
                "INPUT_INTERNAL_WHITESPACE",
                "address contains internal whitespace or a control character and was rejected",
                Risk::High,
            ));
        }
    }

    Ok(trimmed.to_string())
}
