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
    /// Category id → what kind of service an adapter or host is (`crypto`,
    /// `exchange`, `payments`, ...). ClawUp's mandate templates use the same ids.
    pub categories: BTreeMap<String, Category>,
    /// Category → hosts that can move money or act for the owner: a write to
    /// one that no adapter types is refused.
    #[serde(default)]
    pub sensitive_hosts: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub chains: Vec<Chain>,
    #[serde(default)]
    pub tokens: Vec<Token>,
    /// Where signers carry EIP-712 typed data in a request to sign it, for
    /// `typed_data_signature` adapters.
    #[serde(default)]
    pub typed_data_requests: Vec<TypedDataAt>,
}

/// One place a signer's request carries typed data: a pointer into the JSON
/// body, holding the typed data or its JSON text. With `method_prefix`, only
/// when the body's `method` starts with it (a JSON-RPC call).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedDataAt {
    pub at: String,
    #[serde(default)]
    pub method_prefix: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    pub name: String,
    /// The nearest ISIC Rev.5 codes (UN industry classification): a section
    /// letter, or a division, group or class of 2 to 4 digits. Empty for a
    /// category that applies to every industry.
    #[serde(default)]
    pub isic: Vec<String>,
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
    /// One of `common.json`'s categories.
    pub category: String,
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
    /// Name → (key → value), for `"as": "lookup"`: names an API gives by
    /// number, such as an exchange's asset indexes.
    #[serde(default)]
    pub tables: BTreeMap<String, BTreeMap<String, String>>,
    /// For `typed_data_signature`: the typed data's domain fields it covers,
    /// each equal (a chain id as a number or its text alike).
    #[serde(default)]
    pub domain: serde_json::Map<String, Value>,
    /// For `typed_data_signature`: what is signed is a hash of a payload the
    /// request must carry. An action with `check_payload` checks it.
    #[serde(default)]
    pub signed_payload: Option<SignedPayload>,
    /// Tried in order; the first whose `when` holds decides.
    pub actions: Vec<Action>,
}

/// A hash, in the typed data, of a payload carried beside it: in the
/// `x-signed-payload` header (JSON in base64) or a `signed_payload` body field.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPayload {
    /// Where the hash is, in the document (`/input/message/...`).
    pub hash_at: String,
    /// The bytes hashed, in order, read from the payload.
    pub parts: Vec<Part>,
    pub digest: Digest,
    /// The payload, once it hashes to what is signed, is typed as the body of
    /// this request, by the adapter that covers it.
    pub as_request: AsRequest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Part {
    /// A pointer into the payload.
    pub at: String,
    pub encode: Encode,
    /// For `hex`: the number of bytes.
    #[serde(default)]
    pub width: Option<usize>,
    /// The value may be absent or null: these bytes (hex) are written for
    /// absent, and `prefix` before a present value.
    #[serde(default)]
    pub optional: Option<Optional>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Optional {
    pub absent: String,
    pub prefix: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Encode {
    /// The value in msgpack, keys in the order written.
    Msgpack,
    /// A whole number as 8 bytes, big endian.
    U64be,
    /// Hex text as its bytes.
    Hex,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Digest {
    Keccak256,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsRequest {
    pub method: String,
    pub host: String,
    pub path: String,
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
    /// A request, on any host, to sign EIP-712 typed data whose domain has
    /// the adapter's `domain` fields (found where `common.json`'s
    /// `typed_data_requests` say). `input` is `{"domain", "primary_type",
    /// "message"}`.
    TypedDataSignature,
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
    /// Let a request this matches through as an ordinary request: a write
    /// that is a read in all but its method, such as a query sent by POST.
    #[serde(default)]
    pub pass: bool,
    /// For `typed_data_signature`: check that the carried payload hashes to
    /// what is signed (`signed_payload`), and type it as `as_request`.
    #[serde(default)]
    pub check_payload: bool,
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
    /// The value is one of these. Or:
    #[serde(default)]
    pub is: Vec<Value>,
    /// The text matches this regular expression, whole.
    #[serde(default)]
    pub matches: Option<String>,
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
    /// The text at `at` must match this regular expression, whole.
    #[serde(default)]
    pub matches: Option<String>,
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
    /// For `lookup`: the name of one of the adapter's `tables`.
    #[serde(default)]
    pub table: Option<String>,
    /// For `micro`: multiply by the decimal at this pointer (a quantity
    /// times a price), rounding the product up.
    #[serde(default)]
    pub times: Option<String>,
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
    /// The value's text looked up in the adapter's table named `table`;
    /// refused if absent.
    Lookup,
}

/// Checks on requests to model APIs (`adapters/model-requests.json`).
///
/// A provider calls a remote MCP server, a connector or a networked hosted
/// shell from its own servers, out of the enforcer's sight, but only when the
/// request asks it to. So a model request that asks is refused, wherever it
/// goes. A model request is one to a model host, to a model endpoint, or with
/// a model request's shape.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRules {
    #[serde(default)]
    pub summary: String,
    /// Hosts that serve model APIs. `*.` at the start matches any subdomain.
    pub model_hosts: Vec<String>,
    /// On a model host, a write must be to one of these. A write to one of
    /// these on any host is a model request too: gateways keep the paths.
    pub endpoints: Vec<Endpoint>,
    /// A body with every pointer of one of these is a model request, whatever
    /// its host and path.
    pub shapes: Vec<Vec<String>>,
    /// Refused on any host.
    pub refuse: Vec<ModelRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    #[serde(default)]
    pub method: Option<String>,
    /// The path ends with this: base paths differ between providers and proxies.
    pub suffix: String,
}

/// One refusal. Exactly one of: `present` (a pointer, `*` for any array item or
/// object member, that has a value), `at` with `is`, or `header` with `contains`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRule {
    #[serde(default)]
    pub present: Option<String>,
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub is: Option<Vec<Value>>,
    #[serde(default)]
    pub case: Case,
    #[serde(default)]
    pub header: Option<String>,
    /// Refused when the header contains any of these, without case.
    #[serde(default)]
    pub contains: Option<Vec<String>>,
    pub reason: String,
}
