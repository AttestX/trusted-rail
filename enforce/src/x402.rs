//! x402 payments, on any host.
//!
//! An x402 client retries a request with a signed payment in a header:
//! `PAYMENT-SIGNATURE` in version 2, `X-PAYMENT` in version 1. The header is
//! base64 JSON. For the `exact` scheme on an EVM network it holds an EIP-3009
//! authorization: who is paid and how much, in the asset's smallest unit.
//!
//! Version 2 names the asset in `accepted`, so it is typed. Version 1 does not
//! name the asset at all, so its amount cannot be compared with a limit and it
//! is refused.
use crate::{evm, money, refused, Observed, Typed};
use base64::Engine;
use serde_json::{json, Value};

pub(crate) fn type_request(request: &Observed) -> Option<Typed> {
    let (header, version) = match (
        request.header("payment-signature"),
        request.header("x-payment"),
    ) {
        (Some(h), _) => (h, 2),
        (None, Some(h)) => (h, 1),
        (None, None) => return None,
    };
    Some(type_header(header.trim(), version, &request.host_name()))
}

fn type_header(header: &str, version: u8, host: &str) -> Typed {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(header)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(header));
    let Some(payment) = decoded
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    else {
        return refused("an x402 payment header that does not decode");
    };
    if version == 1 || payment.get("x402Version").and_then(Value::as_u64) == Some(1) {
        return refused("an x402 version 1 payment names no asset");
    }
    let accepted = &payment["accepted"];
    let text = |v: &Value| v.as_str().map(str::to_ascii_lowercase);
    let (Some(scheme), Some(network), Some(asset), Some(pay_to), Some(amount)) = (
        text(&accepted["scheme"]),
        text(&accepted["network"]),
        text(&accepted["asset"]),
        text(&accepted["payTo"]),
        accepted["amount"]
            .as_str()
            .and_then(|a| a.parse::<u128>().ok()),
    ) else {
        return refused("an x402 payment without scheme, network, asset, payee and amount");
    };
    if scheme != "exact" {
        return refused(format!("x402 scheme {scheme} is not typed"));
    }
    let Some(chain_id) = network
        .strip_prefix("eip155:")
        .and_then(|id| id.parse::<u64>().ok())
    else {
        return refused(format!("x402 network {network} is not typed"));
    };
    // What is signed is what pays: it must be exactly what was accepted.
    let auth = &payment["payload"]["authorization"];
    let signed_to = text(&auth["to"]);
    let signed_value = auth["value"].as_str().and_then(|v| v.parse::<u128>().ok());
    if signed_to.as_deref() != Some(pay_to.as_str()) || signed_value != Some(amount) {
        return refused("the signed x402 authorization differs from the accepted terms");
    }
    let Some((symbol, decimals)) = evm::token(chain_id, &asset) else {
        return refused(format!("x402 asset {asset} has no known decimals"));
    };
    let Some(amount_micro) = evm::micro(amount, decimals) else {
        return refused("an x402 amount too large to compare");
    };
    if amount_micro == 0 {
        return refused("an x402 payment of nothing");
    }
    money(
        "x402.pay",
        host,
        json!({"host": host, "asset": symbol, "asset_address": asset, "amount_micro": amount_micro,
               "network": network, "pay_to": pay_to, "rail": "x402"}),
    )
}
