//! Browser/WASM binding for address-guard via wasm-bindgen. Functions return
//! JSON strings; the TypeScript layer parses them into the typed public API.

use address_guard_core as ag;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn validate(address: &str) -> String {
    serde_json::to_string(&ag::validate(address)).unwrap()
}

#[wasm_bindgen(js_name = validateForNetwork)]
pub fn validate_for_network(address: &str, network: &str) -> String {
    let result = match ag::Network::parse(network) {
        Some(n) => ag::validate_for_network(address, n),
        None => ag::validate(address),
    };
    serde_json::to_string(&result).unwrap()
}

#[wasm_bindgen(js_name = detectNetworks)]
pub fn detect_networks(address: &str) -> String {
    serde_json::to_string(&ag::detect_networks(address)).unwrap()
}

#[wasm_bindgen(js_name = checksumEvm)]
pub fn checksum_evm(address: &str, chain_id: Option<f64>) -> Result<String, JsError> {
    let cid = chain_id.map(|v| v as u64);
    ag::checksum_evm(address, cid).ok_or_else(|| JsError::new("not an EVM-shaped address"))
}

#[wasm_bindgen(js_name = compareAddresses)]
pub fn compare_addresses(a: &str, b: &str) -> String {
    serde_json::to_string(&ag::compare_addresses(a, b)).unwrap()
}

#[wasm_bindgen(js_name = isValid)]
pub fn is_valid(address: &str, network: &str) -> bool {
    match ag::Network::parse(network) {
        Some(n) => ag::is_valid(address, n),
        None => false,
    }
}
