//! Signed EVM transactions sent through any JSON-RPC endpoint.
//!
//! The agent may point at any RPC host, so a transaction is recognised by the
//! call, not the host. `eth_sendRawTransaction` carries a signed transaction:
//! it is decoded and typed as a native or ERC-20 transfer, an ERC-20 approval,
//! or a contract call. Every other call that sends or signs is refused: the
//! signing happens elsewhere, out of sight, and the bytes say nothing an
//! enforcer can check. Reads pass as ordinary requests.
use crate::{money, refused, Observed, Typed};
use serde_json::{json, Value};

/// Calls that send or sign something, other than the one that is typed.
const SENDS: &[&str] = &[
    "eth_sendTransaction",
    "eth_signTransaction",
    "eth_sign",
    "personal_sign",
    "eth_signTypedData",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
    "eth_sendBundle",
    "eth_sendPrivateTransaction",
    "eth_sendRawTransactionConditional",
    "wallet_sendCalls",
    "sendTransaction",
    "signTransaction",
];
const RAW: &[&str] = &["eth_sendRawTransaction", "eth_sendRawTransactionSync"];

/// `None` when the body is not a JSON-RPC call that sends anything.
pub(crate) fn type_request(request: &Observed) -> Option<Typed> {
    let body: Value = serde_json::from_slice(request.body).ok()?;
    let calls: Vec<&Value> = match &body {
        Value::Array(calls) => calls.iter().collect(),
        call @ Value::Object(_) => vec![call],
        _ => return None,
    };
    let method = |call: &Value| {
        call.get("method")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let sending: Vec<(String, &Value)> = calls
        .iter()
        .filter_map(|call| method(call).map(|m| (m, *call)))
        .filter(|(m, _)| RAW.contains(&m.as_str()) || SENDS.contains(&m.as_str()))
        .collect();
    let (name, call) = match sending.as_slice() {
        [] => return None,
        [one] if calls.len() == 1 => one,
        _ => return Some(refused("a JSON-RPC batch that sends a transaction")),
    };
    if !RAW.contains(&name.as_str()) {
        return Some(refused(format!("{name} signs or sends out of sight")));
    }
    let raw = call
        .get("params")
        .and_then(Value::as_array)
        .and_then(|p| p.first())
        .and_then(Value::as_str)
        .and_then(|h| hex::decode(h.strip_prefix("0x").unwrap_or(h)).ok());
    Some(match raw {
        Some(raw) => match Transaction::decode(&raw) {
            Ok(tx) => tx.typed(),
            Err(reason) => refused(reason),
        },
        None => refused("the raw transaction is not hex"),
    })
}

/// The fields of a signed transaction an enforcer needs.
#[derive(Debug, PartialEq)]
pub struct Transaction {
    pub chain_id: u64,
    /// Lower-case `0x` address.
    pub to: String,
    pub value_wei: u128,
    pub data: Vec<u8>,
}

impl Transaction {
    /// Legacy (EIP-155), EIP-2930 and EIP-1559 transactions. Contract creation,
    /// blob and set-code transactions, and legacy ones without a chain id, are
    /// refused.
    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        let first = *raw.first().ok_or("an empty transaction")?;
        let (chain_id, fields) = match first {
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
        let [to, value, data] = fields;
        if to.len() != 20 {
            return Err("a transaction that creates a contract".into());
        }
        Ok(Transaction {
            chain_id: u64::try_from(chain_id).map_err(|_| "a chain id out of range")?,
            to: format!("0x{}", hex::encode(to)),
            value_wei: int(value)?,
            data: data.to_vec(),
        })
    }

    pub fn typed(&self) -> Typed {
        let (chain, native) = chain(self.chain_id);
        let rail = json!("evm");
        if self.data.is_empty() {
            let Some(amount) = micro(self.value_wei, 18) else {
                return refused("a native amount too large to compare");
            };
            if amount == 0 {
                return refused("a transfer of nothing");
            }
            return money(
                "token.transfer",
                &self.to,
                json!({"chain": chain, "token": native, "recipient": self.to, "amount_micro": amount, "rail": rail}),
            );
        }
        if self.data.len() < 4 {
            return refused("call data shorter than a selector");
        }
        let selector = hex::encode(&self.data[..4]);
        let args = &self.data[4..];
        match (selector.as_str(), self.value_wei) {
            ("a9059cbb", 0) | ("095ea7b3", 0) => {
                let (Some(who), Some(raw)) = (address(args, 0), word(args, 1)) else {
                    return refused("ERC-20 arguments that do not decode");
                };
                if args.len() != 64 {
                    return refused("ERC-20 call data of the wrong length");
                }
                let Some((symbol, decimals)) = token(self.chain_id, &self.to) else {
                    return refused(format!("token {} has no known decimals", self.to));
                };
                let Some(amount) = micro(raw, decimals) else {
                    return refused("a token amount too large to compare");
                };
                if selector == "a9059cbb" {
                    money(
                        "token.transfer",
                        &who,
                        json!({"chain": chain, "token": symbol, "token_address": self.to, "recipient": who, "amount_micro": amount, "rail": rail}),
                    )
                } else {
                    money(
                        "token.approve",
                        &who,
                        json!({"chain": chain, "token": symbol, "token_address": self.to, "spender": who, "amount_micro": amount, "rail": rail}),
                    )
                }
            }
            _ => {
                let Some(value) = micro(self.value_wei, 18) else {
                    return refused("a native amount too large to compare");
                };
                let function = function(&selector)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("0x{selector}"));
                money(
                    "contract.call",
                    &self.to,
                    json!({"chain": chain, "to": self.to, "function": function, "value_micro": value, "rail": rail}),
                )
            }
        }
    }
}

/// Chain names as a mandate is written with them, and each chain's native token.
fn chain(id: u64) -> (String, &'static str) {
    let known = match id {
        1 => Some(("ethereum", "ETH")),
        10 => Some(("optimism", "ETH")),
        56 => Some(("bsc", "BNB")),
        137 => Some(("polygon", "POL")),
        2345 => Some(("goat", "BTC")),
        8453 => Some(("base", "ETH")),
        42161 => Some(("arbitrum", "ETH")),
        43114 => Some(("avalanche", "AVAX")),
        _ => None,
    };
    match known {
        Some((name, native)) => (name.into(), native),
        None => (format!("eip155:{id}"), "native"),
    }
}

/// Tokens whose decimals are known, so an amount can be put in millionths.
pub(crate) fn token(chain_id: u64, address: &str) -> Option<(&'static str, u32)> {
    const TOKENS: &[(u64, &str, &str, u32)] = &[
        (1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "USDC", 6),
        (1, "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT", 6),
        (10, "0x0b2c639c533813f4aa9d7837caf62653d097ff85", "USDC", 6),
        (56, "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d", "USDC", 18),
        (56, "0x55d398326f99059ff775485246999027b3197955", "USDT", 18),
        (137, "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "USDC", 6),
        (137, "0xc2132d05d31c914a87c6611c10748aeb04b58e8f", "USDT", 6),
        (
            8453,
            "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "USDC",
            6,
        ),
        (
            42161,
            "0xaf88d065e77c8cc2239327c5edb3a432268e5831",
            "USDC",
            6,
        ),
        (
            42161,
            "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9",
            "USDT",
            6,
        ),
    ];
    TOKENS
        .iter()
        .find(|(c, a, _, _)| *c == chain_id && *a == address)
        .map(|(_, _, s, d)| (*s, *d))
}

fn function(selector: &str) -> Option<&'static str> {
    Some(match selector {
        "23b872dd" => "transferFrom",
        "39509351" => "increaseAllowance",
        "d505accf" => "permit",
        "a22cb465" => "setApprovalForAll",
        "42842e0e" | "b88d4fde" => "safeTransferFrom",
        _ => return None,
    })
}

/// An amount of a token with `decimals`, in millionths, rounded up so a limit
/// is never passed by rounding. `None` when it does not fit a policy's numbers.
pub fn micro(raw: u128, decimals: u32) -> Option<u64> {
    let micro = if decimals >= 6 {
        let unit = 10u128.checked_pow(decimals - 6)?;
        raw.div_ceil(unit)
    } else {
        raw.checked_mul(10u128.checked_pow(6 - decimals)?)?
    };
    u64::try_from(micro).ok().filter(|m| *m <= i64::MAX as u64)
}

fn word(args: &[u8], i: usize) -> Option<u128> {
    let w = args.get(i * 32..i * 32 + 32)?;
    if w[..16].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u128::from_be_bytes(w[16..].try_into().ok()?))
}

fn address(args: &[u8], i: usize) -> Option<String> {
    let w = args.get(i * 32..i * 32 + 32)?;
    if w[..12].iter().any(|b| *b != 0) {
        return None;
    }
    Some(format!("0x{}", hex::encode(&w[12..])))
}

/// RLP: one item, and what follows it.
fn item(buf: &[u8]) -> Result<(bool, &[u8], &[u8]), String> {
    let short = |len: usize, at: usize| -> Result<(&[u8], &[u8]), String> {
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
        0x80..=0xb7 => (false, short((p - 0x80) as usize, 1)?),
        0xb8..=0xbf => {
            let n = (p - 0xb7) as usize;
            (false, short(long(n)?, 1 + n)?)
        }
        0xc0..=0xf7 => (true, short((p - 0xc0) as usize, 1)?),
        0xf8..=0xff => {
            let n = (p - 0xf7) as usize;
            (true, short(long(n)?, 1 + n)?)
        }
    };
    Ok((list, payload, rest))
}

/// The byte strings of a top-level RLP list that is the whole of `raw`.
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
