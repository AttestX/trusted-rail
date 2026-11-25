//! Hyperliquid's signed actions. An order is signed as EIP-712 typed data
//! whose message holds only `connectionId`, a hash of the action. A signer
//! (Privy, Turnkey, a local key) sees 32 opaque bytes, so a signing request
//! is typed only when it also carries the action it signs, and the action
//! hashes to exactly that `connectionId`.
//!
//! The hash is the Python SDK's `action_hash`: keccak256 of the action in
//! msgpack, in the key order it was written, then the nonce (8 bytes, big
//! endian), then `0x00` without a vault or `0x01` and the vault's 20 bytes,
//! then, with an expiry, `0x00` and the expiry (8 bytes).
use alloy_primitives::keccak256;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;

/// JSON as written: object keys keep their order, since the hash depends on it.
#[derive(Debug, Clone, PartialEq)]
pub enum Ordered {
    Null,
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Text(String),
    List(Vec<Ordered>),
    Object(Vec<(String, Ordered)>),
}

impl<'de> serde::Deserialize<'de> for Ordered {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_unit<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Null)
            }
            fn visit_none<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Null)
            }
            fn visit_bool<E>(self, b: bool) -> Result<Ordered, E> {
                Ok(Ordered::Bool(b))
            }
            fn visit_u64<E>(self, n: u64) -> Result<Ordered, E> {
                Ok(Ordered::Unsigned(n))
            }
            fn visit_i64<E>(self, n: i64) -> Result<Ordered, E> {
                Ok(if n >= 0 {
                    Ordered::Unsigned(n as u64)
                } else {
                    Ordered::Signed(n)
                })
            }
            fn visit_f64<E>(self, n: f64) -> Result<Ordered, E> {
                Ok(Ordered::Float(n))
            }
            fn visit_str<E>(self, s: &str) -> Result<Ordered, E> {
                Ok(Ordered::Text(s.to_owned()))
            }
            fn visit_string<E>(self, s: String) -> Result<Ordered, E> {
                Ok(Ordered::Text(s))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Ordered, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Ordered::List(items))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Ordered, A::Error> {
                let mut entries: Vec<(String, Ordered)> = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, Ordered>()? {
                    // Two readers could take different copies of a key given twice.
                    if entries.iter().any(|(k, _)| *k == key) {
                        return Err(de::Error::custom(format!("{key} given twice")));
                    }
                    entries.push((key, value));
                }
                Ok(Ordered::Object(entries))
            }
        }
        d.deserialize_any(V)
    }
}

impl Ordered {
    pub fn get(&self, key: &str) -> Option<&Ordered> {
        match self {
            Ordered::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// As a `serde_json::Value`, for typing (where order does not matter).
    pub fn to_value(&self) -> Value {
        match self {
            Ordered::Null => Value::Null,
            Ordered::Bool(b) => Value::Bool(*b),
            Ordered::Unsigned(n) => Value::from(*n),
            Ordered::Signed(n) => Value::from(*n),
            Ordered::Float(n) => Value::from(*n),
            Ordered::Text(s) => Value::String(s.clone()),
            Ordered::List(items) => Value::Array(items.iter().map(Ordered::to_value).collect()),
            Ordered::Object(entries) => Value::Object(
                entries
                    .iter()
                    .map(|(k, v)| (k.clone(), v.to_value()))
                    .collect(),
            ),
        }
    }

    /// msgpack as Python's `msgpack.packb` writes it: the smallest encoding
    /// of each value, strings as str, floats as float64.
    pub fn msgpack(&self, out: &mut Vec<u8>) {
        fn len(out: &mut Vec<u8>, n: usize, fix: u8, fix_max: usize, codes: [u8; 3]) {
            if n < fix_max {
                out.push(fix | n as u8);
            } else if codes[0] != 0 && n <= 0xff {
                out.extend([codes[0], n as u8]);
            } else if n <= 0xffff {
                out.push(codes[1]);
                out.extend((n as u16).to_be_bytes());
            } else {
                out.push(codes[2]);
                out.extend((n as u32).to_be_bytes());
            }
        }
        match self {
            Ordered::Null => out.push(0xc0),
            Ordered::Bool(b) => out.push(if *b { 0xc3 } else { 0xc2 }),
            Ordered::Unsigned(n) => {
                let n = *n;
                if n < 0x80 {
                    out.push(n as u8);
                } else if n <= 0xff {
                    out.extend([0xcc, n as u8]);
                } else if n <= 0xffff {
                    out.push(0xcd);
                    out.extend((n as u16).to_be_bytes());
                } else if n <= 0xffff_ffff {
                    out.push(0xce);
                    out.extend((n as u32).to_be_bytes());
                } else {
                    out.push(0xcf);
                    out.extend(n.to_be_bytes());
                }
            }
            Ordered::Signed(n) => {
                let n = *n;
                if n >= -32 {
                    out.push(n as i8 as u8);
                } else if n >= i8::MIN as i64 {
                    out.extend([0xd0, n as i8 as u8]);
                } else if n >= i16::MIN as i64 {
                    out.push(0xd1);
                    out.extend((n as i16).to_be_bytes());
                } else if n >= i32::MIN as i64 {
                    out.push(0xd2);
                    out.extend((n as i32).to_be_bytes());
                } else {
                    out.push(0xd3);
                    out.extend(n.to_be_bytes());
                }
            }
            Ordered::Float(n) => {
                out.push(0xcb);
                out.extend(n.to_be_bytes());
            }
            Ordered::Text(s) => {
                len(out, s.len(), 0xa0, 32, [0xd9, 0xda, 0xdb]);
                out.extend(s.as_bytes());
            }
            Ordered::List(items) => {
                len(out, items.len(), 0x90, 16, [0, 0xdc, 0xdd]);
                for item in items {
                    item.msgpack(out);
                }
            }
            Ordered::Object(entries) => {
                len(out, entries.len(), 0x80, 16, [0, 0xde, 0xdf]);
                for (k, v) in entries {
                    Ordered::Text(k.clone()).msgpack(out);
                    v.msgpack(out);
                }
            }
        }
    }
}

/// The `connectionId` of a signed action: `{action, nonce, vaultAddress?,
/// expiresAfter?}`, as the `/exchange` body carries them.
pub fn connection_id(signed: &Ordered) -> Result<String, String> {
    let action = signed.get("action").ok_or("no action")?;
    if !matches!(action, Ordered::Object(_)) {
        return Err("the action is not an object".into());
    }
    let mut data = Vec::new();
    action.msgpack(&mut data);
    let nonce = match signed.get("nonce") {
        Some(Ordered::Unsigned(n)) => *n,
        _ => return Err("no nonce".into()),
    };
    data.extend(nonce.to_be_bytes());
    match signed.get("vaultAddress") {
        None | Some(Ordered::Null) => data.push(0),
        Some(Ordered::Text(vault)) => {
            let bytes = hex::decode(vault.strip_prefix("0x").unwrap_or(vault))
                .ok()
                .filter(|b| b.len() == 20)
                .ok_or("a vault address that is not an address")?;
            data.push(1);
            data.extend(bytes);
        }
        _ => return Err("a vault address that is not an address".into()),
    }
    match signed.get("expiresAfter") {
        None | Some(Ordered::Null) => {}
        Some(Ordered::Unsigned(n)) => {
            data.push(0);
            data.extend(n.to_be_bytes());
        }
        _ => return Err("an expiry that is not a time".into()),
    }
    Ok(format!("0x{}", hex::encode(keccak256(&data))))
}

/// What a signing request asks to sign, if it is a Hyperliquid action.
pub enum Signing {
    /// Not Hyperliquid typed data.
    Not,
    /// An L1 action (orders, cancels, leverage): `source` is `a` on mainnet,
    /// `b` on testnet; `connection_id` is what is signed.
    Action {
        source: String,
        connection_id: String,
    },
    /// A user-signed action (`HyperliquidSignTransaction`: withdrawals,
    /// transfers, approving agents).
    UserSigned(String),
}

/// EIP-712 typed data in a signing request: Privy's and Turnkey-style
/// `params.typed_data`, or a JSON-RPC `eth_signTypedData*` call's second
/// parameter (an object, or the object as a string).
pub fn typed_data(body: &Value) -> Option<Value> {
    if let Some(t) = body.pointer("/params/typed_data") {
        return Some(t.clone());
    }
    let method = body.get("method")?.as_str()?;
    if !method.starts_with("eth_signTypedData") {
        return None;
    }
    let p = body.pointer("/params/1")?;
    match p {
        Value::String(s) => serde_json::from_str(s).ok(),
        Value::Object(_) => Some(p.clone()),
        _ => None,
    }
}

pub fn signing(typed: &Value) -> Signing {
    let domain = typed.get("domain");
    let name = domain.and_then(|d| d.get("name")).and_then(Value::as_str);
    let chain = domain.and_then(|d| d.get("chainId")).and_then(|c| match c {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s
            .strip_prefix("0x")
            .map(|h| u64::from_str_radix(h, 16).ok())
            .unwrap_or_else(|| s.parse().ok()),
        _ => None,
    });
    let primary = typed
        .get("primaryType")
        .or_else(|| typed.get("primary_type"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    match name {
        Some("Exchange") if chain == Some(1337) => {
            let message = typed.get("message");
            let field = |k: &str| {
                message
                    .and_then(|m| m.get(k))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            };
            if primary != "Agent" {
                return Signing::UserSigned(primary.to_owned());
            }
            Signing::Action {
                source: field("source"),
                connection_id: field("connectionId"),
            }
        }
        Some("HyperliquidSignTransaction") => Signing::UserSigned(primary.to_owned()),
        _ => Signing::Not,
    }
}
