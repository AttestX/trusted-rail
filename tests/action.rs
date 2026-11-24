use serde_json::json;
use trusted_rail::{action::*, rego::*, *};

const BINARY: &str = "/usr/bin/agent";

const MANDATE: &str = r#"
package trusted
import rego.v1

default decision := {"decision": "deny", "reason_codes": ["outside_mandate"]}

decision := {"decision": "allow", "reason_codes": ["read_only"]} if {
    input.operation == "http.request"
    input.parameters.host == data.exchange
    input.parameters.path == "/info"
}

decision := {"decision": "allow", "reason_codes": ["within_mandate"]} if {
    input.operation == "http.request"
    input.parameters.host == data.exchange
    input.parameters.path == "/exchange"
    input.parameters.method == "POST"
    action := input.parameters.body.action
    action.type == "order"
    count(action.orders) > 0
    every order in action.orders {
        order.a in data.assets
        to_number(order.s) * to_number(order.p) <= data.max_notional
    }
}
"#;

/// A trading mandate: read anything, place only orders inside the limits.
fn mandate() -> PolicyBundle {
    let mut policy = PolicyBundle {
        policy: serde_json::from_value(
            json!({"issuer":"user","policy_id":"mandate","version":1,"sha256":""}),
        )
        .unwrap(),
        engine: engine_profile(),
        modules: [("mandate.rego".into(), MANDATE.into())].into(),
        data: json!({"exchange": "api.hyperliquid.xyz", "assets": [4], "max_notional": 100}),
    };
    policy.policy.sha256 = policy_digest(&policy).unwrap();
    policy
}

fn subject() -> Subject {
    Subject {
        execution: serde_json::from_value(json!({"namespace":"clawup","workload":"agent","allocation_id":"a1","lease_id":"l1","generation":1,"node_id":"n1"})).unwrap(),
        principal: "alice".into(),
        action_id: "request-1".into(),
        context: json!({}),
        previous_state_root: "0".repeat(64),
        evaluated_at_unix: 100,
        validity: serde_json::from_value(json!({"not_before":100,"expires_at":200})).unwrap(),
    }
}

fn post(path: &'static str, body: &[u8]) -> Result<DecisionRecord> {
    let action = http_request(&HttpRequest {
        method: "post",
        scheme: "https",
        host: "API.Hyperliquid.xyz.",
        port: 443,
        path,
        query: "",
        binary: BINARY,
        body,
    })?;
    RegorusEngine.evaluate(&mandate(), &action.request(subject()))
}

fn order(asset: u32, size: &str, price: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "action": {"type": "order", "grouping": "na", "orders": [
            {"a": asset, "b": true, "p": price, "s": size, "r": false, "t": {"limit": {"tif": "Gtc"}}}
        ]},
        "nonce": 1795557265000u64,
        "signature": {"r": "0x1", "s": "0x2", "v": 27}
    }))
    .unwrap()
}

#[test]
fn an_http_request_is_described_the_same_way_whoever_observed_it() {
    let action = http_request(&HttpRequest {
        method: "post",
        scheme: "https",
        host: "API.Hyperliquid.xyz.",
        port: 443,
        path: "/exchange",
        query: "a=1",
        binary: BINARY,
        body: br#"{"action":{"type":"order"},"price":0.5}"#,
    })
    .unwrap();
    assert_eq!(action.operation, HTTP_REQUEST);
    assert_eq!(action.resource, "https://api.hyperliquid.xyz:443/exchange");
    assert_eq!(action.parameters["method"], "POST");
    assert_eq!(action.parameters["host"], "api.hyperliquid.xyz");
    assert_eq!(action.parameters["query"], "a=1");
    assert_eq!(action.parameters["body_bytes"], 39);
    assert_eq!(action.parameters["body"]["action"]["type"], "order");
    // No floating point reaches the canonical encoding.
    assert_eq!(action.parameters["body"]["price"], "0.5");
    canonical_bytes(&action.parameters).unwrap();

    let connect = network_connect("Example.COM.", 443, BINARY).unwrap();
    assert_eq!(connect.operation, NETWORK_CONNECT);
    assert_eq!(connect.resource, "tcp://example.com:443");
    assert_eq!(
        connect.parameters,
        json!({"host": "example.com", "port": 443, "binary": BINARY})
    );
}

#[test]
fn a_mandate_allows_an_order_inside_its_limits_and_refuses_the_rest() {
    let allow = |record: Result<DecisionRecord>| record.unwrap().decision == Decision::Allow;
    assert!(allow(post("/info", br#"{"type":"allMids"}"#)));
    // 0.02 * 1891.4 = 37.8
    assert!(allow(post("/exchange", &order(4, "0.02", "1891.4"))));
    // 0.1 * 1891.4 = 189.1, over the 100 limit
    assert!(!allow(post("/exchange", &order(4, "0.1", "1891.4"))));
    // A market the mandate does not list.
    assert!(!allow(post("/exchange", &order(7, "0.02", "10"))));
    // An action the mandate does not list: moving funds.
    let transfer = br#"{"action":{"type":"usdSend","destination":"0xabc","amount":"5"}}"#;
    assert!(!allow(post("/exchange", transfer)));
    // An order with no orders in it is not vacuously inside the limits.
    let empty = br#"{"action":{"type":"order","orders":[]}}"#;
    assert!(!allow(post("/exchange", empty)));
}

#[test]
fn a_body_the_policy_cannot_read_is_bound_but_not_trusted() {
    // Too large to carry: the fields are absent, so the mandate denies.
    let mut large = order(4, "0.02", "1891.4");
    large.extend(std::iter::repeat_n(b' ', MAX_BODY_BYTES));
    let action = http_request(&HttpRequest {
        method: "POST",
        scheme: "https",
        host: "api.hyperliquid.xyz",
        port: 443,
        path: "/exchange",
        query: "",
        binary: BINARY,
        body: &large,
    })
    .unwrap();
    assert!(action.parameters.get("body").is_none());
    assert_eq!(action.parameters["body_bytes"], large.len());
    assert_eq!(action.parameters["body_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(post("/exchange", &large).unwrap().decision, Decision::Deny);
    // Not JSON at all.
    assert_eq!(
        post("/exchange", b"type=order").unwrap().decision,
        Decision::Deny
    );
    // A different body is a different request.
    let digest = |body: &[u8]| post("/exchange", body).unwrap().request_sha256;
    assert_ne!(
        digest(&order(4, "0.02", "1891.4")),
        digest(&order(4, "0.02", "1891.5"))
    );
}

#[test]
fn malformed_actions_are_refused_before_evaluation() {
    let base = || HttpRequest {
        method: "GET",
        scheme: "https",
        host: "example.com",
        port: 443,
        path: "/",
        query: "",
        binary: BINARY,
        body: b"",
    };
    let bad = [
        HttpRequest {
            scheme: "ftp",
            ..base()
        },
        HttpRequest { port: 0, ..base() },
        HttpRequest {
            method: "GE T",
            ..base()
        },
        HttpRequest {
            path: "no-slash",
            ..base()
        },
        HttpRequest {
            path: "/a?b=1",
            ..base()
        },
        HttpRequest {
            host: "user@example.com",
            ..base()
        },
        HttpRequest { host: "", ..base() },
        HttpRequest {
            query: "a=1\nb=2",
            ..base()
        },
        HttpRequest {
            binary: "",
            ..base()
        },
        HttpRequest {
            body: br#"{"$serde_json::private::Number":"1"}"#,
            ..base()
        },
    ];
    for request in &bad {
        assert!(matches!(http_request(request), Err(Error::InvalidInput)));
    }
    assert!(http_request(&base()).is_ok());
    assert!(network_connect("example.com", 0, BINARY).is_err());
    assert!(network_connect("exa mple.com", 443, BINARY).is_err());
}
