//! What an enforcer needs around trusted-rail.
//!
//! A mandate's money templates read typed actions (`payment`, `token.transfer`,
//! `x402.pay`, ...), but an enforcer on the network observes HTTP requests. This
//! crate turns an observed request into the action a policy decides:
//!
//! - a request that can move money is typed by an adapter written for that API
//!   ([`stripe`], [`evm`], [`x402`]);
//! - a request to a money host that no adapter can type is refused;
//! - anything else is an ordinary `http.request`, for the mandate's host rules.
//!
//! It never reads what the agent says about a request, only the request.
//!
//! [`toolcalls`] reads the tool calls in a model's replies and requests, for the
//! record of which call led to which request. Those calls are evidence, never the
//! basis of a decision.
use serde_json::Value;
use trusted_rail::action::{self, Action, HttpRequest};

pub mod evm;
pub mod stripe;
pub mod toolcalls;
pub mod x402;

/// One HTTP request as the enforcer saw it on the wire, headers included.
/// Credentials may be missing from `headers`: no adapter reads them.
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
    fn http(&self) -> HttpRequest<'a> {
        HttpRequest {
            method: self.method,
            scheme: self.scheme,
            host: self.host,
            port: self.port,
            path: self.path,
            query: self.query,
            binary: self.binary,
            body: self.body,
        }
    }

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
    /// It could move money and no adapter can say how much, or to whom.
    /// Refuse it without asking the mandate.
    Refused(String),
}

/// Hosts that can move money. A request to one of them that is not a read is
/// refused unless an adapter types it. The list is a starting point: an
/// enforcer adds the hosts its sandboxes reach.
pub const MONEY_HOSTS: &[&str] = &[
    "api.stripe.com",
    "api.paypal.com",
    "api-m.paypal.com",
    "api.squareup.com",
    "api.wise.com",
    "api.adyen.com",
    "api.hyperliquid.xyz",
    "api.coinbase.com",
    "api.exchange.coinbase.com",
    "api.binance.com",
    "api.kraken.com",
    "api.bybit.com",
    "www.okx.com",
];

/// Which hosts count as money hosts.
pub struct Hosts {
    money: Vec<String>,
}

impl Default for Hosts {
    fn default() -> Self {
        Hosts {
            money: MONEY_HOSTS.iter().map(|h| h.to_string()).collect(),
        }
    }
}

impl Hosts {
    /// The built-in list plus `extra`.
    pub fn with(extra: &[&str]) -> Self {
        let mut hosts = Hosts::default();
        for host in extra {
            hosts
                .money
                .push(host.trim_end_matches('.').to_ascii_lowercase());
        }
        hosts
    }

    pub fn is_money(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.money.contains(&host)
    }
}

/// Type one observed request.
///
/// Money is recognised by what the request carries as well as by where it goes:
/// an x402 payment header or a JSON-RPC call that sends a transaction is money on
/// any host, since an agent can point at any RPC endpoint or paid service.
pub fn type_request(request: &Observed, hosts: &Hosts) -> Typed {
    if let Some(typed) = x402::type_request(request) {
        return typed;
    }
    if let Some(typed) = evm::type_request(request) {
        return typed;
    }
    let host = request.host_name();
    if host == stripe::HOST {
        if let Some(typed) = stripe::type_request(request) {
            return typed;
        }
    }
    if hosts.is_money(&host) && !request.reads() {
        return Typed::Refused(format!(
            "{} {host} can move money and no adapter types it",
            request.method.to_ascii_uppercase()
        ));
    }
    match action::http_request(&request.http()) {
        Ok(action) => Typed::Http(action),
        Err(_) => Typed::Refused("the request cannot be described".into()),
    }
}

pub(crate) fn money(operation: &str, resource: &str, parameters: Value) -> Typed {
    if resource.is_empty() || resource.len() > 512 || resource.chars().any(char::is_control) {
        return Typed::Refused("the action has no usable resource".into());
    }
    Typed::Money(Action {
        operation: operation.into(),
        resource: resource.into(),
        parameters,
    })
}

pub(crate) fn refused(reason: impl Into<String>) -> Typed {
    Typed::Refused(reason.into())
}
