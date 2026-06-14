//! Shared structured result types.
//!
//! The guiding principle: validation never returns a bare boolean for anything
//! risky. Every result carries a risk level and a list of warnings, and we fail
//! closed — when in doubt, raise risk rather than approve.

use serde::Serialize;

/// Risk level, ordered `None < Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    None,
    Low,
    Medium,
    High,
}

/// Networks an address could belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Ethereum,
    Evm,
    Polygon,
    Bsc,
    Avalanche,
    Arbitrum,
    Optimism,
    Base,
    Solana,
    Tron,
}

/// Every EVM-compatible network an EVM address is simultaneously valid on.
pub const EVM_NETWORKS: [Network; 8] = [
    Network::Ethereum,
    Network::Evm,
    Network::Polygon,
    Network::Bsc,
    Network::Avalanche,
    Network::Arbitrum,
    Network::Optimism,
    Network::Base,
];

impl Network {
    /// Whether this network is EVM-compatible.
    pub fn is_evm(self) -> bool {
        EVM_NETWORKS.contains(&self)
    }

    /// Parse a network name (the canonical lowercase form).
    pub fn parse(s: &str) -> Option<Network> {
        Some(match s {
            "ethereum" => Network::Ethereum,
            "evm" => Network::Evm,
            "polygon" => Network::Polygon,
            "bsc" => Network::Bsc,
            "avalanche" => Network::Avalanche,
            "arbitrum" => Network::Arbitrum,
            "optimism" => Network::Optimism,
            "base" => Network::Base,
            "solana" => Network::Solana,
            "tron" => Network::Tron,
            _ => return None,
        })
    }
}

/// Detected wire format of an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Evm,
    EvmNoChecksum,
    Solana,
    TronBase58,
    TronHex,
}

/// A single structured warning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub code: String,
    pub message: String,
    pub severity: Risk,
}

impl Warning {
    pub fn new(code: &str, message: &str, severity: Risk) -> Self {
        Warning {
            code: code.to_string(),
            message: message.to_string(),
            severity,
        }
    }
}

/// The structured outcome of validating an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressResult {
    pub valid: bool,
    pub format: Option<Format>,
    pub normalized: Option<String>,
    pub networks: Vec<Network>,
    pub risk: Risk,
    pub warnings: Vec<Warning>,
}

impl AddressResult {
    /// An invalid result carrying a single high-severity reason.
    pub fn invalid(code: &str, message: &str) -> Self {
        AddressResult {
            valid: false,
            format: None,
            normalized: None,
            networks: Vec::new(),
            risk: Risk::High,
            warnings: vec![Warning::new(code, message, Risk::High)],
        }
    }

    /// Recompute `risk` as the maximum severity across `warnings`.
    pub fn recompute_risk(&mut self) {
        self.risk = self
            .warnings
            .iter()
            .map(|w| w.severity)
            .max()
            .unwrap_or(Risk::None);
    }
}
