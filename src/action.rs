//! One vocabulary for the actions a policy decides.
//!
//! Launch admission and the checks made while a workload runs share
//! `EvaluationRequest`. Without agreed names and shapes every enforcer would
//! invent its own, and a policy written for one could not judge another's
//! requests. An enforcer builds an [`Action`] here from what it observed, and
//! never from what the workload says it is doing.
use crate::{rego::valid_text, Error, EvaluationRequest, Result};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use trusted_contracts::{ExecutionIdentity, Validity};

/// Admitting a runtime and its fixed sandbox policy.
pub const RUNTIME_CREATE: &str = "runtime.create";
/// One outbound connection, before any byte is sent.
pub const NETWORK_CONNECT: &str = "network.connect";
/// One HTTP request the enforcer can read, with its body.
pub const HTTP_REQUEST: &str = "http.request";

/// The largest JSON body carried into a request. A request is capped at
/// 64 KiB in all, and the rest of it needs room.
pub const MAX_BODY_BYTES: usize = 32 * 1024;

/// What is being done, to what, and with which arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    pub operation: String,
    pub resource: String,
    pub parameters: Value,
}

/// Who acts and when: the authenticated inputs an enforcer adds to an action.
pub struct Subject {
    pub execution: ExecutionIdentity,
    pub principal: String,
    pub action_id: String,
    pub context: Value,
    pub previous_state_root: String,
    /// The state behind `previous_state_root`, when the policy keeps any.
    pub state: Option<Value>,
    pub evaluated_at_unix: u64,
    pub validity: Validity,
}

impl Action {
    pub fn request(self, subject: Subject) -> EvaluationRequest {
        EvaluationRequest {
            execution: subject.execution,
            principal: subject.principal,
            action_id: subject.action_id,
            operation: self.operation,
            resource: self.resource,
            parameters: self.parameters,
            context: subject.context,
            previous_state_root: subject.previous_state_root,
            state: subject.state,
            evaluated_at_unix: subject.evaluated_at_unix,
            validity: subject.validity,
        }
    }
}

/// A host as policies compare it: lower case, no trailing dot.
fn host_name(host: &str) -> Result<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !valid_text(&host) || host.len() > 253 || host.contains(['/', '@', ' ']) {
        return Err(Error::InvalidInput);
    }
    Ok(host)
}

/// `binary` is the program the enforcer resolved for the socket's owner.
pub fn network_connect(host: &str, port: u16, binary: &str) -> Result<Action> {
    let host = host_name(host)?;
    if port == 0 || !valid_text(binary) {
        return Err(Error::InvalidInput);
    }
    Ok(Action {
        operation: NETWORK_CONNECT.into(),
        resource: format!("tcp://{host}:{port}"),
        parameters: json!({"host": host, "port": port, "binary": binary}),
    })
}

/// One HTTP request as the enforcer saw it on the wire.
pub struct HttpRequest<'a> {
    pub method: &'a str,
    /// `http` or `https`.
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    /// Starts with `/`; without the query.
    pub path: &'a str,
    pub query: &'a str,
    pub binary: &'a str,
    pub body: &'a [u8],
}

/// The body is always bound by its length and SHA-256. It is also carried as
/// `body` when it is JSON of at most [`MAX_BODY_BYTES`], so a policy can read
/// the fields. Otherwise `body` is absent: a policy that needs the fields must
/// deny a request without them, or an oversized or malformed body would pass
/// unread.
pub fn http_request(request: &HttpRequest) -> Result<Action> {
    let host = host_name(request.host)?;
    let method = request.method.to_ascii_uppercase();
    if !matches!(request.scheme, "http" | "https")
        || request.port == 0
        || !valid_text(&method)
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !request.path.starts_with('/')
        || !valid_text(request.path)
        || request.path.contains(['?', '#'])
        || request.query.len() > 2048
        || request.query.chars().any(char::is_control)
        || !valid_text(request.binary)
    {
        return Err(Error::InvalidInput);
    }
    let resource = format!(
        "{}://{}:{}{}",
        request.scheme, host, request.port, request.path
    );
    if !valid_text(&resource) {
        return Err(Error::InvalidInput);
    }
    let mut parameters = Map::new();
    parameters.insert("method".into(), method.into());
    parameters.insert("scheme".into(), request.scheme.into());
    parameters.insert("host".into(), host.into());
    parameters.insert("port".into(), request.port.into());
    parameters.insert("path".into(), request.path.into());
    parameters.insert("query".into(), request.query.into());
    parameters.insert("binary".into(), request.binary.into());
    parameters.insert("body_bytes".into(), request.body.len().into());
    parameters.insert(
        "body_sha256".into(),
        hex::encode(Sha256::digest(request.body)).into(),
    );
    if !request.body.is_empty() && request.body.len() <= MAX_BODY_BYTES {
        if let Ok(body) = serde_json::from_slice::<Value>(request.body) {
            parameters.insert("body".into(), decimal_strings(body)?);
        }
    }
    Ok(Action {
        operation: HTTP_REQUEST.into(),
        resource,
        parameters: Value::Object(parameters),
    })
}

/// The canonical encoding has no floating point, so a number that is not an
/// integer becomes its decimal text: `0.5` is `"0.5"`. A policy compares it
/// with `to_number`. Integers and existing strings are untouched.
fn decimal_strings(value: Value) -> Result<Value> {
    Ok(match value {
        Value::Number(n) if !n.is_i64() && !n.is_u64() => Value::String(n.to_string()),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(decimal_strings)
                .collect::<Result<_>>()?,
        ),
        Value::Object(values) => {
            // The evaluator reads this serde_json sentinel as a number.
            if values.contains_key("$serde_json::private::Number") {
                return Err(Error::InvalidInput);
            }
            Value::Object(
                values
                    .into_iter()
                    .map(|(key, value)| Ok((key, decimal_strings(value)?)))
                    .collect::<Result<_>>()?,
            )
        }
        other => other,
    })
}
