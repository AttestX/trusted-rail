//! Protocol decoding: what every API of a kind shares, so no API's meaning is
//! here. What a decoded request becomes is defined in JSON (`spec`).
use base64::Engine;
use serde_json::{json, Map, Value};
use sha3::{Digest, Keccak256};

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
/// `{"chain_id", "to", "value", "data", "selector"}`. Contract creation, blob and
/// set-code transactions, and legacy ones without a chain id, are refused.
pub fn transaction(raw: &[u8]) -> Result<Value, String> {
    let first = *raw.first().ok_or("an empty transaction")?;
    let (chain_id, [to, value, data]) = match first {
        0xc0..=0xff => {
            let f = list(raw)?;
            if f.len() != 9 {
                return Err("a legacy transaction without nine fields".into());
            }
            let v = int(f[6])?;
            if v < 35 {
                return Err("a legacy transaction without a chain id".into());
            }
            ((v - 35) / 2, [f[3], f[4], f[5]])
        }
        0x01 => {
            let f = list(&raw[1..])?;
            if f.len() != 11 {
                return Err("an EIP-2930 transaction without eleven fields".into());
            }
            (int(f[0])?, [f[4], f[5], f[6]])
        }
        0x02 => {
            let f = list(&raw[1..])?;
            if f.len() != 12 {
                return Err("an EIP-1559 transaction without twelve fields".into());
            }
            (int(f[0])?, [f[5], f[6], f[7]])
        }
        other => return Err(format!("transaction type {other:#04x} is not typed")),
    };
    if to.len() != 20 {
        return Err("a transaction that creates a contract".into());
    }
    let chain_id = u64::try_from(chain_id).map_err(|_| "a chain id out of range")?;
    Ok(json!({
        "chain_id": chain_id,
        "to": format!("0x{}", hex::encode(to)),
        "value": int(value)?.to_string(),
        "data": format!("0x{}", hex::encode(data)),
        "selector": (data.len() >= 4).then(|| format!("0x{}", hex::encode(&data[..4]))),
    }))
}

/// `transfer(address,uint256)` → its selector and argument types. Only static
/// types: `address`, `bool`, `uint<N>` and `bytes32`.
pub fn signature(signature: &str) -> Result<(String, Vec<String>), String> {
    let (name, rest) = signature
        .split_once('(')
        .filter(|(n, r)| !n.is_empty() && r.ends_with(')'))
        .ok_or_else(|| format!("{signature} is not a function signature"))?;
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("{signature} is not a function signature"));
    }
    let args = &rest[..rest.len() - 1];
    let types: Vec<String> = if args.is_empty() {
        Vec::new()
    } else {
        args.split(',').map(str::to_owned).collect()
    };
    for t in &types {
        let uint = t
            .strip_prefix("uint")
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|n| n > 0 && n <= 256 && n % 8 == 0);
        if !(uint || t == "address" || t == "bool" || t == "bytes32") {
            return Err(format!("{signature}: {t} is not a static type"));
        }
    }
    let hash = Keccak256::digest(signature.as_bytes());
    Ok((format!("0x{}", hex::encode(&hash[..4])), types))
}

/// The arguments of a call to a function of these types. The call data must be
/// exactly the selector and one word per argument.
pub fn arguments(data: &[u8], types: &[String]) -> Result<Vec<Value>, String> {
    let args = data.get(4..).ok_or("call data shorter than a selector")?;
    if args.len() != 32 * types.len() {
        return Err("call data of the wrong length for its function".into());
    }
    types
        .iter()
        .zip(args.chunks(32))
        .map(|(t, w)| match t.as_str() {
            "address" if w[..12].iter().all(|b| *b == 0) => {
                Ok(json!(format!("0x{}", hex::encode(&w[12..]))))
            }
            "bool" if w[..31].iter().all(|b| *b == 0) && w[31] <= 1 => Ok(json!(w[31] == 1)),
            "bytes32" => Ok(json!(format!("0x{}", hex::encode(w)))),
            t if t.starts_with("uint") => match w[..16].iter().all(|b| *b == 0) {
                true => Ok(json!(
                    u128::from_be_bytes(w[16..].try_into().unwrap()).to_string()
                )),
                false => Err("a number too large to compare".to_string()),
            },
            _ => Err(format!("an argument that is not a valid {t}")),
        })
        .collect()
}

/// RLP: one item, and what follows it.
fn item(buf: &[u8]) -> Result<(bool, &[u8], &[u8]), String> {
    let take = |len: usize, at: usize| -> Result<(&[u8], &[u8]), String> {
        let end = at.checked_add(len).ok_or("RLP length overflow")?;
        if end > buf.len() {
            return Err("RLP runs past the end".into());
        }
        Ok((&buf[at..end], &buf[end..]))
    };
    let long = |n: usize| -> Result<usize, String> {
        let bytes = buf.get(1..1 + n).ok_or("RLP runs past the end")?;
        if n > 8 || bytes.first() == Some(&0) {
            return Err("RLP length not canonical".into());
        }
        Ok(bytes.iter().fold(0usize, |a, b| (a << 8) | *b as usize))
    };
    let p = *buf.first().ok_or("RLP runs past the end")?;
    let (list, (payload, rest)) = match p {
        0x00..=0x7f => (false, (&buf[..1], &buf[1..])),
        0x80..=0xb7 => (false, take((p - 0x80) as usize, 1)?),
        0xb8..=0xbf => {
            let n = (p - 0xb7) as usize;
            (false, take(long(n)?, 1 + n)?)
        }
        0xc0..=0xf7 => (true, take((p - 0xc0) as usize, 1)?),
        0xf8..=0xff => {
            let n = (p - 0xf7) as usize;
            (true, take(long(n)?, 1 + n)?)
        }
    };
    Ok((list, payload, rest))
}

fn list(raw: &[u8]) -> Result<Vec<&[u8]>, String> {
    let (is_list, mut payload, rest) = item(raw)?;
    if !is_list || !rest.is_empty() {
        return Err("a transaction that is not one RLP list".into());
    }
    let mut out = Vec::new();
    while !payload.is_empty() {
        let (_, value, rest) = item(payload)?;
        out.push(value);
        payload = rest;
    }
    Ok(out)
}

fn int(bytes: &[u8]) -> Result<u128, String> {
    if bytes.len() > 16 {
        return Err("a number too large".into());
    }
    Ok(bytes.iter().fold(0u128, |a, b| (a << 8) | *b as u128))
}
