//! The JSON that defines what requests become.
//!
//! One file per API (`adapters/<id>.json`) says which requests it covers, how
//! to read them, and which action each becomes, with which parameters, in
//! which units, and when to refuse. `adapters/common.json` holds what they
//! share: the money hosts, the chains and the tokens. A definition that does
//! not check out is refused when it is loaded, never when a request arrives.
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Common {
    /// Hosts that can move money: a write to one that no adapter types is refused.
    #[serde(default)]
    pub money_hosts: Vec<String>,
    #[serde(default)]
    pub chains: Vec<Chain>,
    #[serde(default)]
    pub tokens: Vec<Token>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub id: u64,
    /// As mandates name it: `base`, `ethereum`, ...
    pub name: String,
    /// The native token's symbol.
    pub native: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub chain: u64,
    pub address: String,
    pub symbol: String,
    pub decimals: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adapter {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    /// How the request is read. See [`Input`].
    pub input: Input,
    /// For `form` and `json`: the hosts it covers. Their reads pass unread.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// For `header_json`: the header that carries the base64 JSON.
    #[serde(default)]
    pub header: Option<String>,
    /// For `jsonrpc_raw_transaction`: the calls whose first parameter is a
    /// signed transaction.
    #[serde(default)]
    pub methods: Vec<String>,
    /// For `jsonrpc_raw_transaction`: calls that sign or send out of sight,
    /// refused outright.
    #[serde(default)]
    pub refuse_methods: Vec<String>,
    /// Function signatures whose names `"as": "function"` gives a selector.
    #[serde(default)]
    pub functions: Vec<String>,
    /// What a request it covers becomes when no action matches it.
    #[serde(default)]
    pub unmatched: Unmatched,
    /// Tried in order; the first whose `when` holds decides.
    pub actions: Vec<Action>,
}

/// How a request is read into the document actions point into. The document is
/// `{"request": {"method", "host", "path", "query"}, "input": ...}`.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Input {
    /// A form-encoded body; `input` is an object of strings. A field given twice
    /// is refused.
    Form,
    /// A JSON body.
    Json,
    /// A header holding base64 JSON, on any host.
    HeaderJson,
    /// A JSON-RPC call carrying a signed EVM transaction, on any host. `input`
    /// is `{"method", "chain_id", "to", "value", "data", "selector"}`, with
    /// `args` once a `when.function` matches.
    JsonrpcRawTransaction,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unmatched {
    #[default]
    Refuse,
    Pass,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    #[serde(default)]
    pub when: When,
    /// Checks that must hold, each with the reason to refuse when it does not.
    #[serde(default)]
    pub require: Vec<Require>,
    /// The action's operation. Exactly one of `operation` and `refuse`.
    #[serde(default)]
    pub operation: Option<String>,
    /// The parameter that is the action's resource.
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub parameters: BTreeMap<String, Source>,
    /// Refuse a request this matches, for this reason.
    #[serde(default)]
    pub refuse: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct When {
    #[serde(default)]
    pub method: Option<String>,
    /// `*` matches one path segment.
    #[serde(default)]
    pub path: Option<String>,
    /// For `jsonrpc_raw_transaction`: a function signature, such as
    /// `transfer(address,uint256)`. Its arguments become `/input/args`.
    #[serde(default)]
    pub function: Option<String>,
    #[serde(default)]
    pub fields: Vec<Is>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Is {
    pub at: String,
    pub is: Vec<Value>,
    #[serde(default)]
    pub case: Case,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Case {
    /// Strings compare exactly.
    #[default]
    Exact,
    /// Strings compare without ASCII case.
    Any,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Require {
    /// The value here must be one of `in`.
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default, rename = "in")]
    pub one_of: Option<Vec<Value>>,
    /// The two values must be equal.
    #[serde(default)]
    pub same: Option<[String; 2]>,
    #[serde(default)]
    pub case: Case,
    pub reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// A JSON pointer into the document.
    #[serde(default)]
    pub at: Option<String>,
    /// The first of these pointers that has a value.
    #[serde(default)]
    pub first: Option<Vec<String>>,
    /// A fixed value.
    #[serde(default, rename = "const")]
    pub constant: Option<Value>,
    /// Used when `at` or `first` finds nothing.
    #[serde(default)]
    pub default: Option<Value>,
    /// How the value is read. Without it, a value found by `at` or `first` is
    /// `text`, and a `const` is used as written.
    #[serde(default, rename = "as")]
    pub convert: Option<Convert>,
    /// For `micro`: the decimals of the units read.
    #[serde(default)]
    pub decimals: Option<u32>,
    /// For `micro` and `token_symbol`: where the token is named.
    #[serde(default)]
    pub token: Option<TokenAt>,
    /// For `count` and `micro`: allow zero.
    #[serde(default)]
    pub or_zero: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenAt {
    /// A chain id: a number, its decimal text, or `eip155:<id>`.
    pub chain: String,
    pub address: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Convert {
    /// Non-empty text; a number becomes its decimal text.
    Text,
    /// Text in lower case.
    Lower,
    /// A positive whole number, from a number or its decimal text.
    Count,
    /// An amount in millionths, from whole or decimal text in units of
    /// `decimals` (or the token's), rounded up.
    Micro,
    /// The symbol of the token at `token`; refused if unknown. Needs no `at`.
    TokenSymbol,
    /// A chain id as the chain's name, or `eip155:<id>` when unknown.
    ChainName,
    /// A chain id as its native token's symbol; refused if unknown.
    NativeSymbol,
    /// A selector as the name of one of `functions`, or as itself.
    Function,
}
