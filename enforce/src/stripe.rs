//! Stripe's API (`api.stripe.com`), as a merchant's agent uses it.
//!
//! Money leaves a Stripe account by a transfer, a payout or a refund. Those are
//! typed; reads pass as ordinary requests; every other write is refused, since
//! many of them can move money too (paying an invoice, confirming a charge).
//! Stripe's bodies are form-encoded.
use crate::{money, refused, Observed, Typed};
use serde_json::{json, Map, Value};

pub const HOST: &str = "api.stripe.com";

pub(crate) fn type_request(request: &Observed) -> Option<Typed> {
    if request.reads() {
        return None;
    }
    let method = request.method.to_ascii_uppercase();
    if method != "POST" {
        return Some(refused(format!("{method} on Stripe is not typed")));
    }
    let form = match form(request.body) {
        Some(form) => form,
        None => return Some(refused("the Stripe request body is not a form")),
    };
    let path = request.path.trim_end_matches('/');
    Some(match path {
        "/v1/transfers" => transfer(&form),
        "/v1/payouts" => payout(&form),
        "/v1/refunds" => refund(&form),
        _ => refused(format!("POST {path} on Stripe is not typed")),
    })
}

fn form(body: &[u8]) -> Option<Map<String, Value>> {
    if body.len() > 64 * 1024 {
        return None;
    }
    let mut map = Map::new();
    for (key, value) in form_urlencoded::parse(body) {
        // A field given twice is ambiguous: which one Stripe uses is its business.
        if map
            .insert(key.into_owned(), Value::String(value.into_owned()))
            .is_some()
        {
            return None;
        }
    }
    Some(map)
}

fn field<'a>(form: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    form.get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
}

/// Amounts are in cents only for USD. Any other currency is refused rather
/// than compared with a limit in US cents.
fn usd_cents(form: &Map<String, Value>) -> Result<u64, Typed> {
    match field(form, "currency") {
        Some(c) if c.eq_ignore_ascii_case("usd") => {}
        Some(c) => return Err(refused(format!("Stripe amount in {c}, not USD"))),
        None => return Err(refused("Stripe request names no currency")),
    }
    amount(form)
}

fn amount(form: &Map<String, Value>) -> Result<u64, Typed> {
    match field(form, "amount").map(str::parse::<u64>) {
        Some(Ok(cents)) if cents > 0 && cents <= i64::MAX as u64 => Ok(cents),
        Some(_) => Err(refused("Stripe amount is not a positive whole number")),
        None => Err(refused("Stripe request names no amount")),
    }
}

fn transfer(form: &Map<String, Value>) -> Typed {
    let cents = match usd_cents(form) {
        Ok(cents) => cents,
        Err(t) => return t,
    };
    let Some(destination) = field(form, "destination") else {
        return refused("Stripe transfer names no destination");
    };
    money(
        "payment",
        destination,
        json!({"recipient": destination, "amount_cents": cents, "currency": "usd", "rail": "stripe.transfer"}),
    )
}

fn payout(form: &Map<String, Value>) -> Typed {
    let cents = match usd_cents(form) {
        Ok(cents) => cents,
        Err(t) => return t,
    };
    // Without a destination Stripe pays out to the account's default bank account.
    let recipient = field(form, "destination").unwrap_or("default-external-account");
    money(
        "payment",
        recipient,
        json!({"recipient": recipient, "amount_cents": cents, "currency": "usd", "rail": "stripe.payout"}),
    )
}

/// A refund is in the charge's currency, which the request does not state. The
/// amount must be given: without it Stripe refunds the whole charge, of an
/// amount the enforcer cannot see.
fn refund(form: &Map<String, Value>) -> Typed {
    let cents = match amount(form) {
        Ok(cents) => cents,
        Err(t) => return t,
    };
    let Some(of) = field(form, "payment_intent").or_else(|| field(form, "charge")) else {
        return refused("Stripe refund names no payment");
    };
    money(
        "refund",
        of,
        json!({"amount_cents": cents, "of": of, "rail": "stripe.refund"}),
    )
}
