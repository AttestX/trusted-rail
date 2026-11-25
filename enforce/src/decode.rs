//! Protocol decoding: what every API of a kind shares, so no API's meaning is
//! here. What a decoded request becomes is defined in JSON (`spec`).
//!
//! Ethereum transactions and ABI data are decoded with alloy, so the encoding
//! rules are the ones the rest of the ecosystem is tested against.
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction, TxEnvelope};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_eips::eip2718::Decodable2718;
use alloy_json_abi::Function;
use alloy_primitives::TxKind;
use base64::Engine;
use serde_json::{json, Map, Value};

/// The largest body or header read.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

pub fn form(body: &[u8]) -> Result<Value, String> {
    if body.len() > MAX_INPUT_BYTES {
        return Err("the form is too large to read".into());
    }
    let mut map = Map::new();
    for (key, value) in form_urlencoded::parse(body) {
        // Which of two values a server uses is its business, not the enforcer's.
        if map
            .insert(key.into_owned(), Value::String(value.into_owned()))
            .is_some()
        {
            return Err("a form field given twice".into());
        }
    }
    Ok(Value::Object(map))
}

pub fn json_body(body: &[u8]) -> Result<Value, String> {
    if body.len() > MAX_INPUT_BYTES {
        return Err("the body is too large to read".into());
    }
    serde_json::from_slice(body).map_err(|_| "the body is not JSON".into())
}

pub fn header_json(header: &str) -> Result<Value, String> {
    let header = header.trim();
    if header.len() > MAX_INPUT_BYTES {
        return Err("the header is too large to read".into());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(header))
        .map_err(|_| "the header is not base64")?;
    serde_json::from_slice(&bytes).map_err(|_| "the header is not base64 JSON".into())
}

/// What a JSON-RPC body is, for an adapter with these methods.
pub enum Rpc {
    /// Not JSON-RPC, or no call that sends.
    Not,
    Refused(String),
    Transaction(Value),
}

pub fn jsonrpc(body: &[u8], methods: &[String], refuse: &[String]) -> Rpc {
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return Rpc::Not;
    };
    let calls: Vec<&Value> = match &body {
        Value::Array(calls) => calls.iter().collect(),
        call @ Value::Object(_) => vec![call],
        _ => return Rpc::Not,
    };
    let sending: Vec<(&str, &Value)> = calls
        .iter()
        .filter_map(|c| c.get("method").and_then(Value::as_str).map(|m| (m, *c)))
        .filter(|(m, _)| methods.iter().chain(refuse).any(|x| x == m))
        .collect();
    let (name, call) = match sending.as_slice() {
        [] => return Rpc::Not,
        [one] if calls.len() == 1 => *one,
        _ => return Rpc::Refused("a JSON-RPC batch that sends a transaction".into()),
    };
    if refuse.iter().any(|m| m == name) {
        return Rpc::Refused(format!("{name} signs or sends out of sight"));
    }
    let raw = call
        .get("params")
        .and_then(Value::as_array)
        .and_then(|p| p.first())
        .and_then(Value::as_str)
        .and_then(|h| hex::decode(h.strip_prefix("0x").unwrap_or(h)).ok());
    let Some(raw) = raw else {
        return Rpc::Refused("the raw transaction is not hex".into());
    };
    match transaction(&raw) {
        Ok(mut tx) => {
            tx["method"] = name.into();
            Rpc::Transaction(tx)
        }
        Err(reason) => Rpc::Refused(reason),
    }
}

/// A signed legacy (EIP-155), EIP-2930 or EIP-1559 transaction, as
/// `{"chain_id", "from", "to", "value", "data", "selector"}`; `from` is the
/// sender recovered from the signature. Contract creation, blob and set-code
/// transactions, and legacy ones without a chain id, are refused.
pub fn transaction(raw: &[u8]) -> Result<Value, String> {
    let mut rest = raw;
    let tx =
        TxEnvelope::decode_2718(&mut rest).map_err(|e| format!("not a signed transaction: {e}"))?;
    if !rest.is_empty() {
        return Err("bytes after the transaction".into());
    }
    match &tx {
        TxEnvelope::Legacy(_) | TxEnvelope::Eip2930(_) | TxEnvelope::Eip1559(_) => {}
        TxEnvelope::Eip4844(_) => return Err("a blob (EIP-4844) transaction is not typed".into()),
        TxEnvelope::Eip7702(_) => {
            return Err("a set-code (EIP-7702) transaction is not typed".into())
        }
    }
    let chain_id = tx
        .chain_id()
        .ok_or("a legacy transaction without a chain id")?;
    let to = match tx.kind() {
        TxKind::Call(to) => to,
        TxKind::Create => return Err("a transaction that creates a contract".into()),
    };
    let from = tx
        .recover_signer()
        .map_err(|_| "a signature that recovers no sender")?;
    let data = tx.input();
    Ok(json!({
        "chain_id": chain_id,
        "from": format!("0x{}", hex::encode(from)),
        "to": format!("0x{}", hex::encode(to)),
        "value": tx.value().to_string(),
        "data": format!("0x{}", hex::encode(data)),
        "selector": (data.len() >= 4).then(|| format!("0x{}", hex::encode(&data[..4]))),
    }))
}

/// `transfer(address,uint256)` → its selector and argument types. The
/// signature must be canonical: no names, spaces or aliases (`uint256`, not
/// `uint`), since the selector is the hash of exactly this text.
pub fn signature(signature: &str) -> Result<(String, Vec<String>), String> {
    let function = Function::parse(signature)
        .map_err(|_| format!("{signature} is not a function signature"))?;
    if function.signature() != signature {
        return Err(format!(
            "{signature} is not canonical: write {}",
            function.signature()
        ));
    }
    let types = function
        .inputs
        .iter()
        .map(|p| p.selector_type().into_owned())
        .collect();
    Ok((format!("0x{}", hex::encode(function.selector())), types))
}

/// The arguments of a call to a function of these types, any ABI type. The
/// call data must be exactly the selector and the canonical encoding of the
/// arguments: nothing after them, nothing encoded two ways.
pub fn arguments(data: &[u8], types: &[String]) -> Result<Vec<Value>, String> {
    let args = data.get(4..).ok_or("call data shorter than a selector")?;
    let types = types
        .iter()
        .map(|t| DynSolType::parse(t).map_err(|_| format!("{t} is not an ABI type")))
        .collect::<Result<Vec<_>, _>>()?;
    let tuple = DynSolType::Tuple(types);
    let decoded = tuple
        .abi_decode_sequence(args)
        .map_err(|_| "call data that does not decode for its function")?;
    if decoded.abi_encode_params() != args {
        return Err("call data of the wrong length for its function".into());
    }
    match decoded {
        DynSolValue::Tuple(values) => Ok(values.iter().map(abi_json).collect()),
        _ => Err("call data that does not decode for its function".into()),
    }
}

/// An ABI value as JSON: addresses and bytes as lower-case hex, numbers as
/// decimal text (they can be larger than JSON numbers), lists as arrays.
fn abi_json(value: &DynSolValue) -> Value {
    match value {
        DynSolValue::Bool(b) => json!(b),
        DynSolValue::Uint(n, _) => json!(n.to_string()),
        DynSolValue::Int(n, _) => json!(n.to_string()),
        DynSolValue::Address(a) => json!(format!("0x{}", hex::encode(a))),
        DynSolValue::FixedBytes(word, size) => json!(format!("0x{}", hex::encode(&word[..*size]))),
        DynSolValue::Function(f) => json!(format!("0x{}", hex::encode(f))),
        DynSolValue::Bytes(b) => json!(format!("0x{}", hex::encode(b))),
        DynSolValue::String(s) => json!(s),
        DynSolValue::Array(items) | DynSolValue::FixedArray(items) | DynSolValue::Tuple(items) => {
            Value::Array(items.iter().map(abi_json).collect())
        }
    }
}
