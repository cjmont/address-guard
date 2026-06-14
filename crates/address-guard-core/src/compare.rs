//! Address comparison for anti-poisoning and clipboard-hijack defense.

use serde::Serialize;

use crate::types::Risk;

/// Result of comparing two addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Comparison {
    /// True iff the two inputs are the same address (after canonicalization).
    pub equal: bool,
    /// Levenshtein edit distance between the canonical forms.
    pub edit_distance: usize,
    /// Number of identical leading characters.
    pub prefix_match: usize,
    /// Number of identical trailing characters.
    pub suffix_match: usize,
    /// Poisoning risk: `high` when both ends match strongly but the addresses
    /// are NOT equal (the address-poisoning signature).
    pub poisoning_risk: Risk,
}

/// Canonicalize for comparison: use the validated/normalized form when possible,
/// else the trimmed raw input.
fn canonical(s: &str) -> String {
    crate::validate(s)
        .normalized
        .unwrap_or_else(|| s.trim().to_string())
}

fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

fn common_suffix(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

fn levenshtein(a: &[u8], b: &[u8]) -> usize {
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        core::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

/// Threshold (in characters) at which prefix/suffix matching is considered a
/// strong poisoning signal.
const POISON_THRESHOLD: usize = 4;

/// Compare two addresses for equality and poisoning risk.
pub fn compare_addresses(a: &str, b: &str) -> Comparison {
    let ca = canonical(a);
    let cb = canonical(b);
    let equal = ca == cb;

    // Similarity metrics are case-insensitive so EVM checksum casing does not
    // hide a matching hex prefix/suffix.
    let la = ca.to_ascii_lowercase();
    let lb = cb.to_ascii_lowercase();
    let (ba, bb) = (la.as_bytes(), lb.as_bytes());

    let prefix_match = common_prefix(ba, bb);
    let suffix_match = common_suffix(ba, bb);
    let edit_distance = levenshtein(ba, bb);

    let poisoning_risk = if equal {
        Risk::None
    } else if prefix_match >= POISON_THRESHOLD && suffix_match >= POISON_THRESHOLD {
        Risk::High
    } else if prefix_match >= POISON_THRESHOLD || suffix_match >= POISON_THRESHOLD {
        Risk::Medium
    } else {
        Risk::Low
    };

    Comparison {
        equal,
        edit_distance,
        prefix_match,
        suffix_match,
        poisoning_risk,
    }
}
