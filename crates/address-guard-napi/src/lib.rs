//! Node.js binding for address-guard. Functions are synchronous (validation is
//! pure and fast) and return JSON strings; the TypeScript layer parses them into
//! the richly-typed public API.

use address_guard_core as ag;
use napi_derive::napi;

#[napi]
pub fn validate(address: String) -> String {
    serde_json::to_string(&ag::validate(&address)).unwrap()
}

#[napi(js_name = "validateForNetwork")]
pub fn validate_for_network(address: String, network: String) -> String {
    let result = match ag::Network::parse(&network) {
        Some(n) => ag::validate_for_network(&address, n),
        None => ag::validate(&address),
    };
    serde_json::to_string(&result).unwrap()
}

#[napi(js_name = "detectNetworks")]
pub fn detect_networks(address: String) -> String {
    serde_json::to_string(&ag::detect_networks(&address)).unwrap()
}

#[napi(js_name = "checksumEvm")]
pub fn checksum_evm(address: String, chain_id: Option<f64>) -> napi::Result<String> {
    let cid = chain_id.map(|v| v as u64);
    ag::checksum_evm(&address, cid)
        .ok_or_else(|| napi::Error::from_reason("not an EVM-shaped address"))
}

#[napi(js_name = "compareAddresses")]
pub fn compare_addresses(a: String, b: String) -> String {
    serde_json::to_string(&ag::compare_addresses(&a, &b)).unwrap()
}

#[napi(js_name = "isValid")]
pub fn is_valid(address: String, network: String) -> bool {
    match ag::Network::parse(&network) {
        Some(n) => ag::is_valid(&address, n),
        None => false,
    }
}
