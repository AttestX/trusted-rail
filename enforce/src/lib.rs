//! What an enforcer needs around trusted-rail.
//!
//! A mandate's money templates read typed actions (`payment`, `token.transfer`,
//! `x402.pay`, ...), but an enforcer on the network observes HTTP requests.
//! [`type_request`] turns an observed request into the action a policy decides.
//!
//! **What a request becomes is defined in JSON**, one file per API
//! (`adapters/*.json`, see [`spec`]), the way a mandate's templates are: which
//! requests an adapter covers, which action each becomes, its parameters and
//! their units, and when to refuse. This crate only decodes protocols (forms,
//! JSON, base64 headers, signed EVM transactions) and applies the definitions.
//! Adding an API is a JSON file and a test, with no Rust change.
//!
//! - A request an adapter covers becomes its action, or is refused.
//! - A write to a sensitive host (by category: exchange, payments, ...) that no adapter types is refused.
//! - Anything else is an ordinary `http.request`, for the mandate's host rules.
//!
//! It never reads what the agent says about a request, only the request.
//!
//! [`toolcalls`] reads the tool calls in a model's replies and requests, for the
//! record of which call led to which request. Those calls are evidence, never the
//! basis of a decision.
use base64::Engine;
use serde_json::{json, Map, Value};
use spec::{Case, Convert, Input, Unmatched};
use std::collections::BTreeMap;
use std::path::Path;
use trusted_rail::action::{self, Action, HttpRequest};

pub mod decode;
pub mod hyperliquid;
pub mod spec;
pub mod toolcalls;

/// The built-in definitions, compiled in.
/// The built-in adapters, each in the folder of its category.
const BUILTIN: &[(&str, &str)] = &[
    (
        "crypto/evm.json",
        include_str!("../adapters/crypto/evm.json"),
    ),
    (
        "broker/alpaca.json",
        include_str!("../adapters/broker/alpaca.json"),
    ),
    (
        "exchange/binance.json",
        include_str!("../adapters/exchange/binance.json"),
    ),
    (
        "exchange/hyperliquid.json",
        include_str!("../adapters/exchange/hyperliquid.json"),
    ),
    (
        "crypto/privy.json",
        include_str!("../adapters/crypto/privy.json"),
    ),
    (
        "payments/stripe.json",
        include_str!("../adapters/payments/stripe.json"),
    ),
    (
        "payments/x402.json",
        include_str!("../adapters/payments/x402.json"),
    ),
    (
        "payments/x402-v1.json",
        include_str!("../adapters/payments/x402-v1.json"),
    ),
];
const BUILTIN_COMMON: &str = include_str!("../adapters/common.json");
/// The model-request rules, which apply to every category.
pub const MODEL_RULES_FILE: &str = "security/model-requests.json";
const BUILTIN_MODEL: &str = include_str!("../adapters/security/model-requests.json");

/// The largest model request whose body is checked. A larger one to a model host
/// is refused, since what it asks the provider to do cannot be read.
pub const MAX_MODEL_REQUEST_BYTES: usize = 8 * 1024 * 1024;

/// One HTTP request as the enforcer saw it on the wire, headers included.
/// Credentials may be missing from `headers`: no adapter needs them.
pub struct Observed<'a> {
    pub method: &'a str,
    /// `http` or `https`.
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    /// Starts with `/`; without the query.
    pub path: &'a str,
    pub query: &'a str,
    pub binary: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

impl<'a> Observed<'a> {
    /// The first header of that name, compared without case.
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }

    fn host_name(&self) -> String {
        self.host.trim_end_matches('.').to_ascii_lowercase()
    }

    fn reads(&self) -> bool {
        matches!(
            self.method.to_ascii_uppercase().as_str(),
            "GET" | "HEAD" | "OPTIONS"
        )
    }
}

/// What a request is, for the mandate.
#[derive(Clone, Debug, PartialEq)]
pub enum Typed {
    /// It cannot move money: decide it as an `http.request`.
    Http(Action),
    /// An adapter typed it: decide this action.
    Money(Action),
    /// It could move money and its adapter cannot say how much or to whom, or
    /// no adapter covers it. Refuse it without asking the mandate.
    Refused(String),
}

struct Loaded {
    spec: spec::Adapter,
    hosts: Vec<String>,
    functions: BTreeMap<String, String>,
    /// For each action, its `when.function` as (selector, argument types).
    calls: Vec<Option<(String, Vec<String>)>>,
}

/// A set of loaded definitions.
pub struct Adapters {
    categories: BTreeMap<String, spec::Category>,
    /// Host → category.
    sensitive_hosts: BTreeMap<String, String>,
    chains: Vec<spec::Chain>,
    tokens: Vec<spec::Token>,
    adapters: Vec<Loaded>,
    model: Option<spec::ModelRules>,
}

impl Adapters {
    /// The definitions in `adapters/`, compiled in.
    pub fn builtin() -> Self {
        Adapters::load_files(BUILTIN_COMMON, BUILTIN)
            .and_then(|a| a.with_model_rules(BUILTIN_MODEL))
            .expect("the built-in adapters load")
    }

    /// `common` is `common.json`; `adapters` are one adapter each.
    pub fn load(common: &str, adapters: &[&str]) -> Result<Self, String> {
        let common: spec::Common =
            serde_json::from_str(common).map_err(|e| format!("common: {e}"))?;
        for token in &common.tokens {
            if !evm_address(&token.address) || token.decimals > 36 {
                return Err(format!("common: token {} is not valid", token.symbol));
            }
        }
        if common.categories.is_empty() {
            return Err("common: no categories".into());
        }
        for (id, category) in &common.categories {
            let code = |c: &String| {
                (c.len() == 1 && c.bytes().all(|b| b.is_ascii_uppercase()))
                    || ((2..=4).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_digit()))
            };
            if !valid(&category.name) || !category.isic.iter().all(code) {
                return Err(format!("common: category {id} needs a name and ISIC codes"));
            }
        }
        let mut sensitive_hosts = BTreeMap::new();
        for (category, hosts) in &common.sensitive_hosts {
            if !common.categories.contains_key(category) {
                return Err(format!("common: {category} is not a category"));
            }
            for h in hosts {
                if sensitive_hosts.insert(host(h), category.clone()).is_some() {
                    return Err(format!("common: {h} is listed twice"));
                }
            }
        }
        let mut loaded = Vec::new();
        for text in adapters {
            let adapter: spec::Adapter =
                serde_json::from_str(text).map_err(|e| format!("adapter: {e}"))?;
            let id = adapter.id.clone();
            if !common.categories.contains_key(&adapter.category) {
                return Err(format!(
                    "adapter {id}: {} is not a category",
                    adapter.category
                ));
            }
            if loaded.iter().any(|l: &Loaded| l.spec.id == id) {
                return Err(format!("adapter {id} is defined twice"));
            }
            loaded.push(check(adapter).map_err(|e| format!("adapter {id}: {e}"))?);
        }
        Ok(Adapters {
            categories: common.categories,
            sensitive_hosts,
            chains: common.chains,
            tokens: common
                .tokens
                .into_iter()
                .map(|t| spec::Token {
                    address: t.address.to_ascii_lowercase(),
                    ..t
                })
                .collect(),
            adapters: loaded,
            model: None,
        })
    }

    /// Checks on model requests (`model-requests.json`), refused when loaded if
    /// they do not check out.
    pub fn with_model_rules(mut self, rules: &str) -> Result<Self, String> {
        let mut rules: spec::ModelRules =
            serde_json::from_str(rules).map_err(|e| format!("model requests: {e}"))?;
        for (i, rule) in rules.refuse.iter().enumerate() {
            let shapes = [
                rule.present.is_some(),
                rule.at.is_some() && rule.is.is_some(),
                rule.header.is_some() && rule.contains.is_some(),
            ];
            let loose = rule.at.is_some() != rule.is.is_some()
                || rule.header.is_some() != rule.contains.is_some();
            if shapes.iter().filter(|x| **x).count() != 1 || loose || !valid(&rule.reason) {
                return Err(format!(
                    "model requests: rule {i} must be one of present, at and is, or header and contains, with a reason"
                ));
            }
            for p in rule.present.iter().chain(rule.at.iter()) {
                if !p.starts_with('/') {
                    return Err(format!("model requests: rule {i}: {p} must start with /"));
                }
            }
        }
        if rules.endpoints.iter().any(|e| e.suffix.is_empty()) {
            return Err("model requests: an endpoint without a suffix".into());
        }
        for host in &mut rules.model_hosts {
            *host = host.trim_end_matches('.').to_ascii_lowercase();
        }
        self.model = Some(rules);
        Ok(self)
    }

    /// A host that serves a model API.
    pub fn is_model_host(&self, name: &str) -> bool {
        let name = host(name);
        self.model.as_ref().is_some_and(|m| {
            m.model_hosts.iter().any(|h| match h.strip_prefix("*.") {
                Some(parent) => {
                    name.len() > parent.len() + 1 && name.ends_with(&format!(".{parent}"))
                }
                None => *h == name,
            })
        })
    }

    /// `common.json` and every other `*.json` in `dir`, in name order.
    pub fn from_dir(dir: &Path) -> Result<Self, String> {
        let read =
            |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
        let list = |d: &Path| -> Result<Vec<std::path::PathBuf>, String> {
            let mut found: Vec<_> = std::fs::read_dir(d)
                .map_err(|e| format!("{}: {e}", d.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .collect();
            found.sort();
            Ok(found)
        };
        let common = read(&dir.join("common.json"))?;
        let mut files = Vec::new();
        for entry in list(dir)? {
            let name = entry
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if entry.is_dir() {
                for file in list(&entry)? {
                    let file_name = file
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default();
                    let path = format!("{name}/{file_name}");
                    if file.extension().is_some_and(|x| x == "json") && path != MODEL_RULES_FILE {
                        files.push((path, read(&file)?));
                    }
                }
            } else if entry.extension().is_some_and(|x| x == "json") && name != "common.json" {
                return Err(format!(
                    "{name}: an adapter goes in the folder of its category"
                ));
            }
        }
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, t)| (p.as_str(), t.as_str()))
            .collect();
        let adapters = Adapters::load_files(&common, &files)?;
        let model = dir.join(MODEL_RULES_FILE);
        match model.exists() {
            true => adapters.with_model_rules(&read(&model)?),
            false => Ok(adapters),
        }
    }

    /// Like [`Adapters::load`], for adapters given with their paths
    /// (`<category>/<id>.json`): each must sit in the folder of its category.
    pub fn load_files(common: &str, files: &[(&str, &str)]) -> Result<Self, String> {
        for (path, text) in files {
            let category = serde_json::from_str::<Value>(text)
                .ok()
                .and_then(|v| v["category"].as_str().map(str::to_owned))
                .unwrap_or_default();
            let folder = path.split_once('/').map(|(f, _)| f).unwrap_or_default();
            if folder != category {
                return Err(format!(
                    "{path}: its category is {category:?}, so it goes in {category}/"
                ));
            }
        }
        let texts: Vec<&str> = files.iter().map(|(_, t)| *t).collect();
        Adapters::load(common, &texts)
    }

    /// More sensitive hosts in a category, such as the ones a sandbox policy
    /// opens. Refused if the category is not one of `common.json`'s.
    pub fn with_sensitive_hosts(mut self, category: &str, extra: &[&str]) -> Result<Self, String> {
        if !self.categories.contains_key(category) {
            return Err(format!("{category} is not a category"));
        }
        for h in extra {
            self.sensitive_hosts.insert(host(h), category.to_owned());
        }
        Ok(self)
    }

    /// The category of a sensitive host: listed in `common.json`, added, or
    /// covered by an adapter (the adapter's category).
    pub fn category_of(&self, name: &str) -> Option<&str> {
        let name = host(name);
        self.sensitive_hosts
            .get(&name)
            .map(String::as_str)
            .or_else(|| {
                self.adapters
                    .iter()
                    .find(|a| a.hosts.contains(&name))
                    .map(|a| a.spec.category.as_str())
            })
    }

    /// A category's name, from its id.
    pub fn category_name(&self, id: &str) -> Option<&str> {
        self.categories.get(id).map(|c| c.name.as_str())
    }

    /// The categories, id → name and ISIC codes.
    pub fn categories(&self) -> &BTreeMap<String, spec::Category> {
        &self.categories
    }

    /// Each loaded adapter's id and category, in the order they are tried.
    pub fn categorised(&self) -> Vec<(&str, &str)> {
        self.adapters
            .iter()
            .map(|a| (a.spec.id.as_str(), a.spec.category.as_str()))
            .collect()
    }

    /// The ids of the loaded adapters, in the order they are tried.
    pub fn ids(&self) -> Vec<&str> {
        self.adapters.iter().map(|a| a.spec.id.as_str()).collect()
    }
}

/// Type one observed request.
///
/// Money is recognised by what a request carries as well as where it goes: a
/// payment header or a JSON-RPC call that sends a transaction is money on any
/// host, since an agent can point at any RPC endpoint or paid service.
pub fn type_request(request: &Observed, adapters: &Adapters) -> Typed {
    let name = request.host_name();
    if let Some(reason) = model_refusal(request, adapters, &name) {
        return Typed::Refused(format!("model request: {reason}"));
    }
    // A WebSocket is a channel, not a request: what is sent over it (orders,
    // transfers) never passes as a request the mandate could decide. To a
    // host that can move money, it is refused. (HTTP/2 opens one with
    // CONNECT, which is a write and refused on these hosts below.)
    if request
        .header("upgrade")
        .is_some_and(|u| u.to_ascii_lowercase().contains("websocket"))
    {
        if let Some(category) = adapters.category_of(&name) {
            let kind = adapters.category_name(category).unwrap_or(category);
            return Typed::Refused(format!(
                "a WebSocket to {name}, a {} host ({category}): what is sent over it cannot be decided",
                kind.to_lowercase()
            ));
        }
    }
    let document = |input: Value| {
        let segments: Vec<&str> = request.path.split('/').filter(|s| !s.is_empty()).collect();
        json!({"request": {"method": request.method.to_ascii_uppercase(), "host": name,
                           "path": request.path, "segments": segments,
                           "query": request.query}, "input": input})
    };
    if !request.reads() {
        if let Some(typed) = hyperliquid_signature(request, adapters) {
            return typed;
        }
    }
    let covers = |a: &Loaded| a.hosts.is_empty() || a.hosts.contains(&name);
    for a in adapters
        .adapters
        .iter()
        .filter(|a| a.spec.input == Input::HeaderJson && covers(a))
    {
        let Some(header) = request.header(a.spec.header.as_deref().unwrap_or_default()) else {
            continue;
        };
        let typed = match decode::header_json(header) {
            Ok(input) => apply(a, adapters, request, document(input)),
            Err(reason) => Some(refused(a, &reason)),
        };
        if let Some(typed) = typed {
            return typed;
        }
    }
    for a in adapters
        .adapters
        .iter()
        .filter(|a| a.spec.input == Input::JsonrpcRawTransaction && covers(a))
    {
        let typed = match decode::jsonrpc(request.body, &a.spec.methods, &a.spec.refuse_methods) {
            decode::Rpc::Not => None,
            decode::Rpc::Refused(reason) => Some(refused(a, &reason)),
            decode::Rpc::Transaction(input) => apply(a, adapters, request, document(input)),
        };
        if let Some(typed) = typed {
            return typed;
        }
    }
    if !request.reads() {
        for a in adapters.adapters.iter().filter(|a| {
            matches!(a.spec.input, Input::Form | Input::Json) && a.hosts.contains(&name)
        }) {
            let input = match a.spec.input {
                Input::Form => decode::form_and_query(request.body, request.query),
                _ => decode::json_body(request.body),
            };
            let typed = match input {
                Ok(input) => apply(a, adapters, request, document(input)),
                Err(reason) => Some(refused(a, &reason)),
            };
            if let Some(typed) = typed {
                return typed;
            }
        }
        if let Some(category) = adapters.category_of(&name) {
            let kind = adapters.category_name(category).unwrap_or(category);
            return Typed::Refused(format!(
                "{} {name}: a {} host ({category}) that no adapter types",
                request.method.to_ascii_uppercase(),
                kind.to_lowercase()
            ));
        }
    }
    ordinary(request)
}

/// The header that carries a Hyperliquid action beside a request to sign it:
/// the action's JSON, base64. Privy refuses unknown fields in its RPC body and
/// signs only the body and its app id header, so the action travels here.
pub const HYPERLIQUID_ACTION_HEADER: &str = "x-hyperliquid-action";

/// A request, to any signer on any host, to sign a Hyperliquid action. What
/// is signed is only a hash of the action, so the request must carry the
/// action itself (the `/exchange` body without its signature), in the
/// `x-hyperliquid-action` header or as a `hyperliquid_action` body field for
/// signers that accept one. The action must hash to what is signed, and it is
/// typed as the order it is: as if sent to `/exchange`. Once signed, an action can be
/// sent from anywhere, so the signature, not the send, is where it is decided.
fn hyperliquid_signature(request: &Observed, adapters: &Adapters) -> Option<Typed> {
    let body = request.body;
    let starts_as_object = body
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'{');
    if !starts_as_object || body.len() > decode::MAX_INPUT_BYTES {
        return None;
    }
    let value: Value = serde_json::from_slice(body).ok()?;
    let typed = hyperliquid::typed_data(&value)?;
    let refuse = |r: &str| Some(Typed::Refused(format!("hyperliquid signature: {r}")));
    let (source, connection_id) = match hyperliquid::signing(&typed) {
        hyperliquid::Signing::Not => return None,
        hyperliquid::Signing::UserSigned(kind) => {
            return refuse(&format!(
                "{kind}: a transfer, withdrawal or account change signed by the user is not typed"
            ))
        }
        hyperliquid::Signing::Action {
            source,
            connection_id,
        } => (source, connection_id),
    };
    if source != "a" {
        return refuse(
            "a testnet action: testnet numbers its assets differently, so it is not typed",
        );
    }
    let ordered: hyperliquid::Ordered = match serde_json::from_slice(body) {
        Ok(o) => o,
        Err(e) => return refuse(&format!("the request cannot be read: {e}")),
    };
    let in_header = match request.header(HYPERLIQUID_ACTION_HEADER) {
        None => None,
        Some(text) => {
            let text = text.trim();
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(text)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(text))
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text));
            let Ok(bytes) = bytes else {
                return refuse("x-hyperliquid-action is not base64");
            };
            if bytes.len() > decode::MAX_INPUT_BYTES {
                return refuse("x-hyperliquid-action is too large");
            }
            match serde_json::from_slice::<hyperliquid::Ordered>(&bytes) {
                Ok(action) => Some(action),
                Err(e) => return refuse(&format!("x-hyperliquid-action cannot be read: {e}")),
            }
        }
    };
    let shown = match (ordered.get("hyperliquid_action"), &in_header) {
        (Some(_), Some(_)) => {
            return refuse("the action is given twice, in the body and in x-hyperliquid-action")
        }
        (Some(action), None) | (None, Some(action)) => action,
        (None, None) => return refuse(
            "signing an action blind: the request must carry the action it signs, in x-hyperliquid-action",
        ),
    };
    match hyperliquid::connection_id(shown) {
        Ok(id) if id == connection_id => {}
        Ok(_) => return refuse("the action shown is not the action signed"),
        Err(e) => return refuse(&format!("the action shown: {e}")),
    }
    let exchange = serde_json::to_vec(&shown.to_value()).ok()?;
    let as_sent = Observed {
        method: "POST",
        scheme: "https",
        host: "api.hyperliquid.xyz",
        port: 443,
        path: "/exchange",
        query: "",
        binary: request.binary,
        headers: &[],
        body: &exchange,
    };
    Some(match type_request(&as_sent, adapters) {
        Typed::Money(action) => Typed::Money(action),
        Typed::Refused(r) => Typed::Refused(format!("hyperliquid signature: {r}")),
        Typed::Http(_) => return refuse("no adapter types Hyperliquid actions"),
    })
}

/// A request as an ordinary `http.request`, which the mandate's host and
/// method limits decide.
fn ordinary(request: &Observed) -> Typed {
    let http = HttpRequest {
        method: request.method,
        scheme: request.scheme,
        host: request.host,
        port: request.port,
        path: request.path,
        query: request.query,
        binary: request.binary,
        body: request.body,
    };
    match action::http_request(&http) {
        Ok(action) => Typed::Http(action),
        Err(_) => Typed::Refused("the request cannot be described".into()),
    }
}

/// Why a request asks a model provider for something the enforcer cannot see,
/// or reaches a model host outside its model endpoints.
fn model_refusal(request: &Observed, adapters: &Adapters, name: &str) -> Option<String> {
    let rules = adapters.model.as_ref()?;
    let model_host = adapters.is_model_host(name);
    for rule in &rules.refuse {
        if let (Some(header), Some(words)) = (&rule.header, &rule.contains) {
            let hit = request
                .headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case(header))
                .any(|(_, v)| {
                    let v = v.to_ascii_lowercase();
                    words.iter().any(|w| v.contains(&w.to_ascii_lowercase()))
                });
            if hit {
                return Some(rule.reason.clone());
            }
        }
    }
    let endpoint = !request.reads()
        && rules.endpoints.iter().any(|e| {
            e.method
                .as_ref()
                .is_none_or(|m| m.eq_ignore_ascii_case(request.method))
                && request.path.trim_end_matches('/').ends_with(&e.suffix)
        });
    // A compressed body cannot be read, so it cannot be checked.
    let encoded = request.headers.iter().any(|(n, v)| {
        n.eq_ignore_ascii_case("content-encoding") && !v.trim().eq_ignore_ascii_case("identity")
    });
    // Off a model host, a model endpoint's path alone is weak evidence (many
    // APIs have a `/messages`), so the body must also say it is JSON.
    let json_type = request
        .header("content-type")
        .is_some_and(|t| t.to_ascii_lowercase().contains("json"));
    let checked_whole = model_host || (endpoint && json_type);
    if encoded && checked_whole {
        return Some("a compressed model request, which cannot be checked".into());
    }
    let starts_json = request
        .body
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'{');
    if starts_json {
        if request.body.len() > MAX_MODEL_REQUEST_BYTES {
            if checked_whole {
                return Some("a request too large to check".into());
            }
        } else if let Some(body) = strict_json(request.body) {
            let shaped = rules.shapes.iter().any(|shape| {
                shape
                    .iter()
                    .all(|p| find_all(&body, p).iter().any(|v| !v.is_null()))
            });
            let model_request = model_host || endpoint || shaped;
            if model_request && body.get(DUPLICATE_KEY).is_some() {
                return Some("a key given twice, which providers may read differently".into());
            }
            for rule in rules.refuse.iter().filter(|_| model_request) {
                let hit = match (&rule.present, &rule.at, &rule.is) {
                    (Some(p), _, _) => find_all(&body, p).iter().any(|v| !v.is_null()),
                    (None, Some(p), Some(values)) => find_all(&body, p)
                        .iter()
                        .any(|v| values.iter().any(|x| same(v, x, rule.case))),
                    _ => false,
                };
                if hit {
                    return Some(rule.reason.clone());
                }
            }
        } else if model_host || endpoint {
            return Some("a body that is not JSON".into());
        }
    } else if model_host && !request.reads() && !request.body.is_empty() {
        return Some("a body that is not a JSON object".into());
    }
    if model_host && !request.reads() && !endpoint {
        return Some(format!(
            "{} {} is not a model endpoint",
            request.method.to_ascii_uppercase(),
            request.path
        ));
    }
    None
}

/// Set on the top object of a [`strict_json`] value when some object in it gave
/// a key twice. Not a key a request can carry: it has a NUL in it.
const DUPLICATE_KEY: &str = "\u{0}duplicate";

/// The body as JSON, marking a key given twice anywhere in it. serde_json keeps
/// the last of two, and some providers may keep the first, so a request could
/// show the check one thing and the provider another.
fn strict_json(body: &[u8]) -> Option<Value> {
    use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
    use std::cell::Cell;
    struct Strict<'d>(&'d Cell<bool>);
    impl<'de, 'd> serde::de::DeserializeSeed<'de> for Strict<'d> {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de, 'd> Visitor<'de> for Strict<'d> {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("JSON")
        }
        fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
            Ok(serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number))
        }
        fn visit_str<E>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.into()))
        }
        fn visit_string<E>(self, v: String) -> Result<Value, E> {
            Ok(Value::String(v))
        }
        fn visit_unit<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_none<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut items = Vec::new();
            while let Some(v) = a.next_element_seed(Strict(self.0))? {
                items.push(v);
            }
            Ok(Value::Array(items))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut members = serde_json::Map::new();
            while let Some(key) = a.next_key::<String>()? {
                let value = a.next_value_seed(Strict(self.0))?;
                if members.insert(key, value).is_some() {
                    self.0.set(true);
                }
            }
            Ok(Value::Object(members))
        }
    }
    let twice = Cell::new(false);
    let mut d = serde_json::Deserializer::from_slice(body);
    let mut value = serde::de::DeserializeSeed::deserialize(Strict(&twice), &mut d).ok()?;
    d.end().ok()?;
    if twice.get() {
        if let Value::Object(members) = &mut value {
            members.insert(DUPLICATE_KEY.into(), Value::Bool(true));
        }
    }
    Some(value)
}

/// The values at a pointer whose `*` segments stand for every array item or
/// object member.
fn find_all<'v>(value: &'v Value, pointer: &str) -> Vec<&'v Value> {
    let mut found = vec![value];
    for segment in pointer.split('/').skip(1) {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        found = found
            .into_iter()
            .flat_map(|v| -> Vec<&Value> {
                match (segment.as_str(), v) {
                    ("*", Value::Array(items)) => items.iter().collect(),
                    ("*", Value::Object(members)) => members.values().collect(),
                    (key, Value::Object(members)) => members.get(key).into_iter().collect(),
                    (index, Value::Array(items)) => index
                        .parse::<usize>()
                        .ok()
                        .and_then(|i| items.get(i))
                        .into_iter()
                        .collect(),
                    _ => Vec::new(),
                }
            })
            .collect();
    }
    found
}

fn refused(a: &Loaded, reason: &str) -> Typed {
    Typed::Refused(format!("{}: {reason}", a.spec.id))
}

/// The first action whose `when` holds. `None` passes the request on.
fn apply(a: &Loaded, all: &Adapters, request: &Observed, mut doc: Value) -> Option<Typed> {
    for (action, call) in a.spec.actions.iter().zip(&a.calls) {
        let when = &action.when;
        if when
            .method
            .as_ref()
            .is_some_and(|m| !m.eq_ignore_ascii_case(request.method))
            || when
                .path
                .as_ref()
                .is_some_and(|p| !path_matches(p, request.path))
        {
            continue;
        }
        if let Some((selector, types)) = call {
            if doc.pointer("/input/selector").and_then(Value::as_str) != Some(selector) {
                continue;
            }
            let data = doc
                .pointer("/input/data")
                .and_then(Value::as_str)
                .unwrap_or("0x");
            let data = hex::decode(data.trim_start_matches("0x")).unwrap_or_default();
            match decode::arguments(&data, types) {
                Ok(args) => doc["input"]["args"] = Value::Array(args),
                Err(reason) => return Some(refused(a, &reason)),
            }
        }
        // A field that is absent reads as null, so `[null]` matches it.
        let holds = |is: &spec::Is| {
            let v = doc.pointer(&is.at).unwrap_or(&Value::Null);
            match &is.matches {
                Some(pattern) => match (v.as_str(), whole_pattern(pattern)) {
                    (Some(text), Ok(re)) => re.is_match(text),
                    _ => false,
                },
                None => is.is.iter().any(|x| same(v, x, is.case)),
            }
        };
        if !when.fields.iter().all(holds) {
            continue;
        }
        if let Some(reason) = &action.refuse {
            return Some(refused(a, reason));
        }
        if action.pass {
            return Some(ordinary(request));
        }
        for require in &action.require {
            let ok = match (
                &require.at,
                &require.one_of,
                &require.matches,
                &require.same,
            ) {
                (Some(at), Some(values), None, None) => {
                    let v = doc.pointer(at).unwrap_or(&Value::Null);
                    values.iter().any(|x| same(v, x, require.case))
                }
                (Some(at), None, Some(pattern), None) => {
                    match (
                        doc.pointer(at).and_then(Value::as_str),
                        whole_pattern(pattern),
                    ) {
                        (Some(text), Ok(re)) => re.is_match(text),
                        _ => false,
                    }
                }
                (None, None, None, Some([x, y])) => match (doc.pointer(x), doc.pointer(y)) {
                    (Some(x), Some(y)) => !x.is_null() && same(x, y, require.case),
                    _ => false,
                },
                _ => false,
            };
            if !ok {
                return Some(refused(a, &require.reason));
            }
        }
        let mut parameters = Map::new();
        for (name, source) in &action.parameters {
            match resolve(source, &doc, all, a) {
                Ok(value) => {
                    parameters.insert(name.clone(), value);
                }
                Err(reason) => return Some(refused(a, &format!("{name}: {reason}"))),
            }
        }
        let resource = action
            .resource
            .as_ref()
            .and_then(|r| parameters.get(r))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let operation = action.operation.clone().unwrap_or_default();
        return Some(match resource {
            Some(resource) if valid(&resource) => Typed::Money(Action {
                operation,
                resource,
                parameters: Value::Object(parameters),
            }),
            _ => refused(a, "the action has no usable resource"),
        });
    }
    match a.spec.unmatched {
        Unmatched::Pass => None,
        Unmatched::Refuse => Some(refused(
            a,
            &format!(
                "{} {} is not one of its actions",
                request.method.to_ascii_uppercase(),
                request.path
            ),
        )),
    }
}

fn resolve(
    source: &spec::Source,
    doc: &Value,
    all: &Adapters,
    a: &Loaded,
) -> Result<Value, String> {
    let at = |p: &String| doc.pointer(p).filter(|v| !v.is_null()).cloned();
    if source.convert == Some(Convert::TokenSymbol) && source.at.is_none() && source.first.is_none()
    {
        return convert_value(Convert::TokenSymbol, Value::Null, source, doc, all, a);
    }
    if let Some(constant) = &source.constant {
        return match source.convert {
            None => Ok(constant.clone()),
            Some(convert) => convert_value(convert, constant.clone(), source, doc, all, a),
        };
    }
    let found = match (&source.at, &source.first) {
        (Some(p), _) => at(p),
        (None, Some(ps)) => ps.iter().find_map(at),
        _ => None,
    };
    let value = found
        .or_else(|| source.default.clone())
        .ok_or("not in the request")?;
    convert_value(
        source.convert.unwrap_or(Convert::Text),
        value,
        source,
        doc,
        all,
        a,
    )
}

fn convert_value(
    convert: Convert,
    value: Value,
    source: &spec::Source,
    doc: &Value,
    all: &Adapters,
    a: &Loaded,
) -> Result<Value, String> {
    let text = |v: &Value| -> Result<String, String> {
        let t = match v {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => return Err("not text".into()),
        };
        if valid(&t) {
            Ok(t)
        } else {
            Err("not usable text".into())
        }
    };
    let token = || -> Result<&spec::Token, String> {
        let at = source.token.as_ref().ok_or("no token named")?;
        let chain = doc
            .pointer(&at.chain)
            .and_then(chain_id)
            .ok_or("no chain id")?;
        let address = doc
            .pointer(&at.address)
            .and_then(Value::as_str)
            .ok_or("no token address")?
            .to_ascii_lowercase();
        all.tokens
            .iter()
            .find(|t| t.chain == chain && t.address == address)
            .ok_or_else(|| format!("token {address} on chain {chain} has no known decimals"))
    };
    let chain = |v: &Value| -> Result<(u64, Option<&spec::Chain>), String> {
        let id = chain_id(v).ok_or("not a chain id")?;
        Ok((id, all.chains.iter().find(|c| c.id == id)))
    };
    Ok(match convert {
        Convert::Text => Value::String(text(&value)?),
        Convert::Lower => Value::String(text(&value)?.to_ascii_lowercase()),
        Convert::Count => {
            let n = whole(&value).ok_or("not a whole number")?;
            if n == 0 && !source.or_zero {
                return Err("zero".into());
            }
            json!(n)
        }
        Convert::Micro => {
            let decimals = match source.decimals {
                Some(d) => d,
                None => token()?.decimals,
            };
            let (mut mantissa, mut scale) = decimal(&value).ok_or("not an amount")?;
            scale += decimals;
            if let Some(p) = &source.times {
                let factor = doc
                    .pointer(p)
                    .filter(|v| !v.is_null())
                    .ok_or("its factor is not in the request")?;
                let (m, f) = decimal(factor).ok_or("its factor is not an amount")?;
                mantissa = mantissa
                    .checked_mul(m)
                    .ok_or("an amount too large to compare")?;
                scale += f;
            }
            let m = micro(mantissa, scale).ok_or("an amount too large to compare")?;
            if m == 0 && !source.or_zero {
                return Err("an amount of nothing".into());
            }
            json!(m)
        }
        Convert::TokenSymbol => Value::String(token()?.symbol.clone()),
        Convert::ChainName => match chain(&value)? {
            (_, Some(c)) => Value::String(c.name.clone()),
            (id, None) => Value::String(format!("eip155:{id}")),
        },
        Convert::NativeSymbol => match chain(&value)? {
            (_, Some(c)) => Value::String(c.native.clone()),
            (id, None) => return Err(format!("chain {id} has no known native token")),
        },
        Convert::Lookup => {
            let key = text(&value)?;
            let table = source.table.as_deref().unwrap_or_default();
            match a.spec.tables.get(table).and_then(|t| t.get(&key)) {
                Some(found) => Value::String(found.clone()),
                None => return Err(format!("{key} is not in its {table} table")),
            }
        }
        Convert::Function => {
            let selector = text(&value)?.to_ascii_lowercase();
            Value::String(a.functions.get(&selector).cloned().unwrap_or(selector))
        }
    })
}

/// A non-negative whole number that fits a policy's numbers.
fn whole(v: &Value) -> Option<u64> {
    let n = match v {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            s.parse().ok()?
        }
        _ => return None,
    };
    (n <= i64::MAX as u64).then_some(n)
}

/// `"12.50"` → (1250, 2). No sign, no exponent.
fn decimal(v: &Value) -> Option<(u128, u32)> {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    let (int, frac) = s.split_once('.').unwrap_or((&s, ""));
    if int.is_empty()
        || !int.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some((
        format!("{int}{frac}").parse().ok()?,
        u32::try_from(frac.len()).ok()?,
    ))
}

/// `mantissa / 10^scale` in millionths, rounded up so a limit is never passed by
/// rounding. `None` when it does not fit a policy's numbers.
pub fn micro(mantissa: u128, scale: u32) -> Option<u64> {
    let m = if scale >= 6 {
        mantissa.div_ceil(10u128.checked_pow(scale - 6)?)
    } else {
        mantissa.checked_mul(10u128.checked_pow(6 - scale)?)?
    };
    u64::try_from(m).ok().filter(|m| *m <= i64::MAX as u64)
}

fn chain_id(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.strip_prefix("eip155:").unwrap_or(s).parse().ok(),
        _ => None,
    }
}

fn same(a: &Value, b: &Value, case: Case) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => match case {
            Case::Exact => x == y,
            Case::Any => x.eq_ignore_ascii_case(y),
        },
        (Value::String(s), Value::Number(n)) | (Value::Number(n), Value::String(s)) => {
            *s == n.to_string()
        }
        _ => a == b,
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    let p: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let q: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    p.len() == q.len()
        && p.iter()
            .zip(&q)
            .all(|(p, q)| *p == "*" && !q.is_empty() || p == q)
}

fn host(h: &str) -> String {
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// A definition's pattern, matched against the whole value. Patterns are
/// small and the engine runs in linear time.
fn whole_pattern(pattern: &str) -> Result<regex::Regex, String> {
    if pattern.len() > 256 {
        return Err("longer than 256 characters".into());
    }
    regex::RegexBuilder::new(&format!("^(?:{pattern})$"))
        .size_limit(1 << 16)
        .build()
        .map_err(|e| e.to_string())
}

fn valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control)
}

fn evm_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn pointer(p: &str) -> Result<(), String> {
    if p.starts_with("/request/") || p.starts_with("/input/") || p == "/input" {
        Ok(())
    } else {
        Err(format!("{p} points outside /request and /input"))
    }
}

/// Everything about a definition that can be checked before a request arrives.
fn check(adapter: spec::Adapter) -> Result<Loaded, String> {
    if !valid(&adapter.id)
        || !adapter
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("the id must be letters, digits and dashes".into());
    }
    match adapter.input {
        Input::Form | Input::Json if adapter.hosts.is_empty() => {
            return Err("a form or json adapter must name its hosts".into())
        }
        Input::HeaderJson if adapter.header.is_none() => {
            return Err("header_json needs a header".into())
        }
        Input::JsonrpcRawTransaction if adapter.methods.is_empty() => {
            return Err("jsonrpc_raw_transaction needs methods".into())
        }
        _ => {}
    }
    if adapter.actions.is_empty() {
        return Err("no actions".into());
    }
    let mut functions = BTreeMap::new();
    for signature in &adapter.functions {
        let (selector, _) = decode::signature(signature)?;
        let name = signature.split('(').next().unwrap_or_default().to_owned();
        functions.insert(selector, name);
    }
    let mut calls = Vec::new();
    for (i, action) in adapter.actions.iter().enumerate() {
        let at = |e: String| format!("action {i}: {e}");
        if let Some(f) = &action.when.function {
            if adapter.input != Input::JsonrpcRawTransaction {
                return Err(at(
                    "when.function is only for jsonrpc_raw_transaction".into()
                ));
            }
            calls.push(Some(decode::signature(f).map_err(at)?));
        } else {
            calls.push(None);
        }
        if let Some(path) = &action.when.path {
            if !path.starts_with('/') {
                return Err(at(format!("path {path} must start with /")));
            }
        }
        for is in &action.when.fields {
            pointer(&is.at).map_err(at)?;
            match (&is.matches, is.is.is_empty()) {
                (Some(pattern), true) => {
                    whole_pattern(pattern).map_err(|e| at(format!("pattern {pattern}: {e}")))?;
                }
                (None, false) => {}
                _ => return Err(at("a field is either is or matches".into())),
            }
        }
        match (&action.operation, &action.refuse) {
            (None, None) if action.pass => {
                if !action.parameters.is_empty() || !action.require.is_empty() {
                    return Err(at("a pass takes no parameters or checks".into()));
                }
            }
            _ if action.pass => return Err(at("give one of operation, refuse and pass".into())),
            (Some(op), None) => {
                if !valid(op) || op == action::HTTP_REQUEST {
                    return Err(at(format!("{op} is not an operation an adapter may write")));
                }
                let resource = action
                    .resource
                    .as_ref()
                    .ok_or_else(|| at("no resource".into()))?;
                if !action.parameters.contains_key(resource) {
                    return Err(at(format!("the resource {resource} is not a parameter")));
                }
            }
            (None, Some(reason)) if valid(reason) => {
                if !action.parameters.is_empty() || !action.require.is_empty() {
                    return Err(at("a refusal takes no parameters or checks".into()));
                }
            }
            _ => return Err(at("give exactly one of operation and refuse".into())),
        }
        for require in &action.require {
            match (
                &require.at,
                &require.one_of,
                &require.matches,
                &require.same,
            ) {
                (Some(p), Some(_), None, None) => pointer(p).map_err(at)?,
                (Some(p), None, Some(pattern), None) => {
                    pointer(p).map_err(at)?;
                    whole_pattern(pattern).map_err(|e| at(format!("pattern {pattern}: {e}")))?;
                }
                (None, None, None, Some([x, y])) => {
                    pointer(x).map_err(at)?;
                    pointer(y).map_err(at)?;
                }
                _ => return Err(at("a check is at and in, at and matches, or same".into())),
            }
            if !valid(&require.reason) {
                return Err(at("a check needs a reason".into()));
            }
        }
        for (name, source) in &action.parameters {
            let at = |e: &str| at(format!("parameter {name}: {e}"));
            if !valid(name) {
                return Err(at("not a usable name"));
            }
            let found = [
                source.at.is_some(),
                source.first.is_some(),
                source.constant.is_some(),
            ];
            let found = found.iter().filter(|x| **x).count();
            // A token's symbol is found from `token` alone.
            let token_only = source.convert == Some(Convert::TokenSymbol) && found == 0;
            if found != 1 && !token_only {
                return Err(at("give exactly one of at, first and const"));
            }
            for p in source.at.iter().chain(source.first.iter().flatten()) {
                pointer(p).map_err(|e| at(&e))?;
            }
            if source.constant.is_some() && source.default.is_some() {
                return Err(at("a const has no default"));
            }
            match source.convert {
                Some(Convert::Micro) if source.decimals.is_some() == source.token.is_some() => {
                    return Err(at("micro needs exactly one of decimals and token"))
                }
                Some(Convert::TokenSymbol) if source.token.is_none() => {
                    return Err(at("token_symbol needs token"))
                }
                _ if source.times.is_some() && source.convert != Some(Convert::Micro) => {
                    return Err(at("times is for micro"))
                }
                Some(Convert::Lookup)
                    if !source
                        .table
                        .as_ref()
                        .is_some_and(|t| adapter.tables.contains_key(t)) =>
                {
                    return Err(at("lookup needs one of the adapter's tables"))
                }
                _ if source.table.is_some() && source.convert != Some(Convert::Lookup) => {
                    return Err(at("table is for lookup"))
                }
                _ => {}
            }
            if let Some(p) = &source.times {
                pointer(p).map_err(|e| at(&e))?;
            }
            if let Some(t) = &source.token {
                pointer(&t.chain).map_err(|e| at(&e))?;
                pointer(&t.address).map_err(|e| at(&e))?;
            }
            if source.decimals.is_some_and(|d| d > 36) {
                return Err(at("too many decimals"));
            }
        }
    }
    Ok(Loaded {
        hosts: adapter.hosts.iter().map(|h| host(h)).collect(),
        functions,
        calls,
        spec: adapter,
    })
}
