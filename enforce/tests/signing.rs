//! Signing a Hyperliquid action through a signer (Privy here): typed only when
//! the request carries the action, and the action hashes to what is signed.
//! The vectors are the Hyperliquid Python SDK's own (`action_hash`, 0.24.1).
use serde_json::Value;
use trusted_rail_enforce::hyperliquid::{connection_id, Ordered};
use trusted_rail_enforce::{type_request, Adapters, Observed, Typed};

const VECTORS: &str = include_str!("data/hyperliquid_signing.json");
const PRIVY_RPC: &str = "/api/oauth/v2/wallets/w1/rpc";

fn vectors() -> Vec<(String, String, String)> {
    let all: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    all.iter()
        .map(|v| {
            (
                v["name"].as_str().unwrap().to_owned(),
                v["connectionId"].as_str().unwrap().to_owned(),
                v["privy"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn sign(host: &str, path: &str, body: &str) -> Typed {
    sign_with(host, path, body, &[])
}

fn sign_with(host: &str, path: &str, body: &str, headers: &[(&str, &str)]) -> Typed {
    type_request(
        &Observed {
            method: "POST",
            scheme: "https",
            host,
            port: 443,
            path,
            query: "",
            binary: "/usr/bin/node",
            headers,
            body: body.as_bytes(),
        },
        &Adapters::builtin(),
    )
}

fn refused(t: Typed) -> String {
    match t {
        Typed::Refused(r) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_hash_is_the_sdks() {
    for (name, id, privy) in vectors() {
        let body: Ordered = serde_json::from_str(&privy).unwrap();
        let shown = body.get("hyperliquid_action").unwrap();
        assert_eq!(connection_id(shown).unwrap(), id, "{name}");
    }
}

#[test]
fn a_signature_over_an_order_it_shows_is_that_order() {
    let (_, _, privy) = vectors().remove(0);
    match sign("auth.privy.io", PRIVY_RPC, &privy) {
        Typed::Money(a) => {
            assert_eq!(
                (a.operation.as_str(), a.resource.as_str()),
                ("order.place", "btc")
            );
            assert_eq!(a.parameters["amount_micro"], 1_212_506_250u64);
            assert_eq!(a.parameters["currency"], "usdc");
        }
        other => panic!("{other:?}"),
    }
    // A vault order and one that expires are typed too; a cancel is a cancel.
    let all = vectors();
    match sign("auth.privy.io", PRIVY_RPC, &all[1].2) {
        Typed::Money(a) => {
            assert_eq!(
                (a.resource.as_str(), a.parameters["side"].as_str()),
                ("eth", Some("sell"))
            );
            assert_eq!(
                a.parameters["account"],
                "0x1234567890abcdef1234567890abcdef12345678"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        sign("auth.privy.io", PRIVY_RPC, &all[2].2),
        Typed::Money(_)
    ));
    match sign("auth.privy.io", PRIVY_RPC, &all[3].2) {
        Typed::Money(a) => assert_eq!(a.operation, "order.cancel"),
        other => panic!("{other:?}"),
    }
    // The same request to any other signer, on any host, is decided the same.
    assert!(matches!(
        sign("signer.example", "/sign", &privy),
        Typed::Money(_)
    ));
}

/// Privy refuses unknown fields in its RPC body ("Unrecognized key(s) in
/// object: 'hyperliquid_action'", seen live), so the action travels in a
/// header, which Privy's request signature does not cover.
#[test]
fn the_action_can_travel_in_a_header() {
    let all: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    for v in &all {
        let (bare, header) = (v["bare"].as_str().unwrap(), v["header"].as_str().unwrap());
        assert!(!bare.contains("hyperliquid_action"));
        let typed = sign_with(
            "auth.privy.io",
            PRIVY_RPC,
            bare,
            &[("X-Hyperliquid-Action", header)],
        );
        assert!(matches!(typed, Typed::Money(_)), "{}: {typed:?}", v["name"]);
    }
    let (bare, header) = (
        all[0]["bare"].as_str().unwrap(),
        all[0]["header"].as_str().unwrap(),
    );
    // Without it, the request is blind.
    assert!(refused(sign("auth.privy.io", PRIVY_RPC, bare)).contains("blind"));
    // Another action in the header than the one signed.
    let other = {
        use base64::Engine;
        let e = base64::engine::general_purpose::STANDARD;
        let text = String::from_utf8(e.decode(header).unwrap()).unwrap();
        e.encode(text.replace("\"0.0125\"", "\"125\""))
    };
    let r = refused(sign_with(
        "auth.privy.io",
        PRIVY_RPC,
        bare,
        &[("x-hyperliquid-action", &other)],
    ));
    assert!(r.contains("not the action signed"), "{r}");
    // Not base64, or not JSON.
    let r = refused(sign_with(
        "auth.privy.io",
        PRIVY_RPC,
        bare,
        &[("x-hyperliquid-action", "%%%")],
    ));
    assert!(r.contains("not base64"), "{r}");
    let r = refused(sign_with(
        "auth.privy.io",
        PRIVY_RPC,
        bare,
        &[("x-hyperliquid-action", "bm90IGpzb24=")],
    ));
    assert!(r.contains("cannot be read"), "{r}");
    // In the body and in the header: refused, whatever they say.
    let both = all[0]["privy"].as_str().unwrap();
    let r = refused(sign_with(
        "auth.privy.io",
        PRIVY_RPC,
        both,
        &[("x-hyperliquid-action", header)],
    ));
    assert!(r.contains("given twice"), "{r}");
}

#[test]
fn signing_blind_or_something_else_is_refused() {
    let (_, id, privy) = vectors().remove(0);
    let mut body: Value = serde_json::from_str(&privy).unwrap();
    // Without the action.
    let mut blind = body.clone();
    blind.as_object_mut().unwrap().remove("hyperliquid_action");
    assert!(refused(sign("auth.privy.io", PRIVY_RPC, &blind.to_string())).contains("blind"));
    // Another action shown than the one signed: a bigger size.
    let other = privy.replace("\"s\": \"0.0125\"", "\"s\": \"125\"");
    assert_ne!(other, privy);
    assert!(refused(sign("auth.privy.io", PRIVY_RPC, &other)).contains("not the action signed"));
    // The same action with its keys in another order hashes differently: what is
    // signed is the action as written. (serde_json sorts keys.)
    assert!(refused(sign("auth.privy.io", PRIVY_RPC, &body.to_string()))
        .contains("not the action signed"));
    // A key given twice could be read two ways.
    let twice = privy.replacen("\"nonce\": ", "\"nonce\": 1, \"nonce\": ", 1);
    assert!(refused(sign("auth.privy.io", PRIVY_RPC, &twice)).contains("given twice"));
    // Testnet.
    body["params"]["typed_data"]["message"]["source"] = "b".into();
    assert!(refused(sign("auth.privy.io", PRIVY_RPC, &body.to_string())).contains("testnet"));
    // A user-signed action: a withdrawal.
    let withdraw = serde_json::json!({"method": "eth_signTypedData_v4", "params": {"typed_data": {
        "domain": {"name": "HyperliquidSignTransaction", "version": "1", "chainId": 421614,
                   "verifyingContract": "0x0000000000000000000000000000000000000000"},
        "primary_type": "HyperliquidTransaction:Withdraw",
        "message": {"destination": "0xabc", "amount": "1000", "time": 1}}}});
    assert!(
        refused(sign("auth.privy.io", PRIVY_RPC, &withdraw.to_string())).contains("withdrawal")
    );
    // The same through a JSON-RPC signer.
    let rpc = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "eth_signTypedData_v4",
        "params": ["0xabc", {"domain": {"name": "Exchange", "chainId": 1337},
                   "primaryType": "Agent", "message": {"source": "a", "connectionId": id}}]});
    assert!(refused(sign("rpc.example", "/", &rpc.to_string())).contains("blind"));
}

#[test]
fn privy_signs_in_and_refuses_what_is_not_typed() {
    for path in [
        "/api/oauth/v2/device_authorization",
        "/api/oauth/v2/token",
        "/api/oauth/v2/wallets/authenticate",
    ] {
        assert!(
            matches!(sign("auth.privy.io", path, "{}"), Typed::Http(_)),
            "{path}"
        );
    }
    let send = r#"{"method": "eth_sendTransaction", "caip2": "eip155:8453", "params": {"transaction": {"to": "0xabc", "value": "0x1"}}}"#;
    let r = refused(sign("auth.privy.io", PRIVY_RPC, send));
    assert!(
        r.contains("not typed yet") || r.contains("out of sight"),
        "{r}"
    );
    let personal = r#"{"method": "personal_sign", "params": {"message": "hello"}}"#;
    let r = refused(sign("auth.privy.io", PRIVY_RPC, personal));
    eprintln!("personal: {r}");
    assert!(
        r.contains("not typed yet") || r.contains("out of sight"),
        "{r}"
    );
    // Signing a raw hash would sign Hyperliquid's digest with no typed data to
    // check: refused on Privy and on any other host.
    for host in ["auth.privy.io", "signer.example"] {
        let raw = r#"{"method": "secp256k1_sign", "params": {"hash": "0x00"}}"#;
        let r = refused(sign(host, PRIVY_RPC, raw));
        assert!(r.contains("out of sight"), "{host}: {r}");
    }
    let r = refused(sign("api.privy.io", "/v1/wallets/w1/rpc", send));
    assert!(
        r.contains("not typed yet") || r.contains("out of sight"),
        "{r}"
    );
}
