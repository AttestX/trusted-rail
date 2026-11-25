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
//! - A write to a money host that no adapter types is refused.
//! - Anything else is an ordinary `http.request`, for the mandate's host rules.
//!
//! It never reads what the agent says about a request, only the request.
//!
//! [`toolcalls`] reads the tool calls in a model's replies and requests, for the
//! record of which call led to which request. Those calls are evidence, never the
//! basis of a decision.
use serde_json::{json, Map, Value};
use spec::{Case, Convert, Input, Unmatched};
use std::collections::BTreeMap;
use std::path::Path;
use trusted_rail::action::{self, Action, HttpRequest};

pub mod decode;
pub mod spec;
pub mod toolcalls;

/// The built-in definitions, compiled in.
const BUILTIN: &[(&str, &str)] = &[
    ("stripe.json", include_str!("../adapters/stripe.json")),
    ("evm.json", include_str!("../adapters/evm.json")),
    ("x402.json", include_str!("../adapters/x402.json")),
    ("x402-v1.json", include_str!("../adapters/x402-v1.json")),
];
const BUILTIN_COMMON: &str = include_str!("../adapters/common.json");
const BUILTIN_MODEL: &str = include_str!("../adapters/model-requests.json");

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
    money_hosts: Vec<String>,
    chains: Vec<spec::Chain>,
    tokens: Vec<spec::Token>,
    adapters: Vec<Loaded>,
    model: Option<spec::ModelRules>,
}

impl Adapters {
    /// The definitions in `adapters/`, compiled in.
    pub fn builtin() -> Self {
        let files: Vec<&str> = BUILTIN.iter().map(|(_, s)| *s).collect();
        Adapters::load(BUILTIN_COMMON, &files)
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
        let mut loaded = Vec::new();
        for text in adapters {
            let adapter: spec::Adapter =
                serde_json::from_str(text).map_err(|e| format!("adapter: {e}"))?;
            let id = adapter.id.clone();
            if loaded.iter().any(|l: &Loaded| l.spec.id == id) {
                return Err(format!("adapter {id} is defined twice"));
            }
            loaded.push(check(adapter).map_err(|e| format!("adapter {id}: {e}"))?);
        }
        Ok(Adapters {
            money_hosts: common.money_hosts.iter().map(|h| host(h)).collect(),
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
        let common = read(&dir.join("common.json"))?;
        let model = dir.join("model-requests.json");
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .filter(|p| {
                p.file_name()
                    .is_some_and(|n| n != "common.json" && n != "model-requests.json")
            })
            .collect();
        names.sort();
        let texts = names
            .iter()
            .map(|p| read(p))
            .collect::<Result<Vec<_>, _>>()?;
        let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
        let adapters = Adapters::load(&common, &texts)?;
        match model.exists() {
            true => adapters.with_model_rules(&read(&model)?),
            false => Ok(adapters),
        }
    }

    /// More money hosts, such as the ones a sandbox policy opens.
    pub fn with_money_hosts(mut self, extra: &[&str]) -> Self {
        self.money_hosts.extend(extra.iter().map(|h| host(h)));
        self
    }

    /// A money host: listed in `common.json`, added, or covered by an adapter.
    pub fn is_money(&self, name: &str) -> bool {
        let name = host(name);
        self.money_hosts.contains(&name) || self.adapters.iter().any(|a| a.hosts.contains(&name))
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
    let document = |input: Value| {
        json!({"request": {"method": request.method.to_ascii_uppercase(), "host": name,
                           "path": request.path, "query": request.query}, "input": input})
    };
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
                Input::Form => decode::form(request.body),
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
        if adapters.is_money(&name) {
            return Typed::Refused(format!(
                "{} {name} can move money and no adapter types it",
                request.method.to_ascii_uppercase()
            ));
        }
    }
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
        let holds = |is: &spec::Is| {
            doc.pointer(&is.at)
                .is_some_and(|v| is.is.iter().any(|x| same(v, x, is.case)))
        };
        if !when.fields.iter().all(holds) {
            continue;
        }
        if let Some(reason) = &action.refuse {
            return Some(refused(a, reason));
        }
        for require in &action.require {
            let ok = match (&require.at, &require.one_of, &require.same) {
                (Some(at), Some(values), None) => doc
                    .pointer(at)
                    .is_some_and(|v| values.iter().any(|x| same(v, x, require.case))),
                (None, None, Some([x, y])) => match (doc.pointer(x), doc.pointer(y)) {
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
            match resolve(source, &doc, all, &a.functions) {
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
    functions: &BTreeMap<String, String>,
) -> Result<Value, String> {
    let at = |p: &String| doc.pointer(p).filter(|v| !v.is_null()).cloned();
    if source.convert == Some(Convert::TokenSymbol) && source.at.is_none() && source.first.is_none()
    {
        return convert_value(
            Convert::TokenSymbol,
            Value::Null,
            source,
            doc,
            all,
            functions,
        );
    }
    if let Some(constant) = &source.constant {
        return match source.convert {
            None => Ok(constant.clone()),
            Some(convert) => convert_value(convert, constant.clone(), source, doc, all, functions),
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
        functions,
    )
}

fn convert_value(
    convert: Convert,
    value: Value,
    source: &spec::Source,
    doc: &Value,
    all: &Adapters,
    functions: &BTreeMap<String, String>,
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
            let (mantissa, fraction) = decimal(&value).ok_or("not an amount")?;
            let m = micro(mantissa, decimals + fraction).ok_or("an amount too large to compare")?;
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
        Convert::Function => {
            let selector = text(&value)?.to_ascii_lowercase();
            Value::String(functions.get(&selector).cloned().unwrap_or(selector))
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
        }
        match (&action.operation, &action.refuse) {
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
            match (&require.at, &require.one_of, &require.same) {
                (Some(p), Some(_), None) => pointer(p).map_err(at)?,
                (None, None, Some([x, y])) => {
                    pointer(x).map_err(at)?;
                    pointer(y).map_err(at)?;
                }
                _ => return Err(at("a check is either at and in, or same".into())),
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
                _ => {}
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
