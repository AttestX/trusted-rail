//! Signed hashes of payloads. Some typed data a wallet signs holds only a
//! hash of what it authorizes, so a signer sees opaque bytes. A request to
//! sign such data is typed only when it also carries the payload, and the
//! payload hashes, by the recipe its adapter gives (`signed_payload`), to
//! exactly what is signed.
//!
//! The payload is read as written: object keys keep their order, since a
//! hash over msgpack depends on it, and a key given twice is refused.
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

    /// A JSON pointer (`/a/0/b`): `""` is the whole value.
    pub fn pointer(&self, pointer: &str) -> Option<&Ordered> {
        if pointer.is_empty() {
            return Some(self);
        }
        let mut at = self;
        for token in pointer.strip_prefix('/')?.split('/') {
            let token = token.replace("~1", "/").replace("~0", "~");
            at = match at {
                Ordered::Object(_) => at.get(&token)?,
                Ordered::List(items) => items.get(token.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(at)
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

    /// msgpack in its smallest encoding of each value (as Python's
    /// `msgpack.packb` writes it): strings as str, floats as float64.
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

/// Builds the bytes a signed payload's hash is taken over, part by part, as
/// an adapter's `signed_payload.parts` say, and hashes them.
pub fn digest(payload: &Ordered, spec: &crate::spec::SignedPayload) -> Result<String, String> {
    use crate::spec::{Digest, Encode};
    let mut data = Vec::new();
    for part in &spec.parts {
        let value = payload.pointer(&part.at);
        let present = !matches!(value, None | Some(Ordered::Null));
        if let Some(optional) = &part.optional {
            let marker = if present {
                &optional.prefix
            } else {
                &optional.absent
            };
            data.extend(hex::decode(marker.trim_start_matches("0x")).map_err(|e| e.to_string())?);
            if !present {
                continue;
            }
        }
        let value = value
            .filter(|_| present)
            .ok_or_else(|| format!("{} is missing", part.at))?;
        match part.encode {
            Encode::Msgpack => value.msgpack(&mut data),
            Encode::U64be => match value {
                Ordered::Unsigned(n) => data.extend(n.to_be_bytes()),
                _ => return Err(format!("{} is not a whole number", part.at)),
            },
            Encode::Hex => {
                let bytes = match value {
                    Ordered::Text(text) => {
                        hex::decode(text.strip_prefix("0x").unwrap_or(text)).ok()
                    }
                    _ => None,
                }
                .filter(|b| part.width.is_none_or(|w| b.len() == w))
                .ok_or_else(|| {
                    format!(
                        "{} is not {} bytes of hex",
                        part.at,
                        part.width.unwrap_or(0)
                    )
                })?;
                data.extend(bytes);
            }
        }
    }
    let hash = match spec.digest {
        Digest::Keccak256 => keccak256(&data).0.to_vec(),
    };
    Ok(format!("0x{}", hex::encode(hash)))
}
