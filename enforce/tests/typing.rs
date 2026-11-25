use base64::Engine;
use serde_json::{json, Value};
use trusted_rail_enforce::{micro, type_request, Adapters, Observed, Typed};

fn observe<'a>(
    method: &'a str,
    host: &'a str,
    path: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
) -> Observed<'a> {
    Observed {
        method,
        scheme: "https",
        host,
        port: 443,
        path,
        query: "",
        binary: "/usr/bin/python3",
        headers,
        body,
    }
}

fn typed(o: &Observed) -> Typed {
    type_request(o, &Adapters::builtin())
}

fn money(t: Typed) -> (String, String, Value) {
    match t {
        Typed::Money(a) => (a.operation, a.resource, a.parameters),
        other => panic!("expected money, got {other:?}"),
    }
}

fn refused(t: Typed) -> String {
    match t {
        Typed::Refused(r) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

// ---- Stripe

#[test]
fn a_stripe_transfer_in_usd_is_a_payment() {
    let body = b"amount=4200&currency=usd&destination=acct_1Hetzner";
    let (op, resource, p) = money(typed(&observe(
        "POST",
        "api.stripe.com",
        "/v1/transfers",
        &[],
        body,
    )));
    assert_eq!(
        (op.as_str(), resource.as_str()),
        ("payment", "acct_1Hetzner")
    );
    assert_eq!(p["amount_cents"], 4200);
    assert_eq!(p["recipient"], "acct_1Hetzner");
}

#[test]
fn stripe_amounts_outside_usd_cents_are_refused() {
    let jpy = b"amount=4200&currency=jpy&destination=acct_1";
    assert!(refused(typed(&observe(
        "POST",
        "api.stripe.com",
        "/v1/transfers",
        &[],
        jpy
    )))
    .contains("not in USD"));
    let none = b"amount=4200&destination=acct_1";
    refused(typed(&observe(
        "POST",
        "api.stripe.com",
        "/v1/transfers",
        &[],
        none,
    )));
    let twice = b"amount=1&amount=999999&currency=usd&destination=acct_1";
    refused(typed(&observe(
        "POST",
        "api.stripe.com",
        "/v1/transfers",
        &[],
        twice,
    )));
}

#[test]
fn a_stripe_payout_without_a_destination_goes_to_the_default_account() {
    let body = b"amount=10000&currency=usd";
    let (op, resource, _) = money(typed(&observe(
        "POST",
        "api.stripe.com",
        "/v1/payouts",
        &[],
        body,
    )));
    assert_eq!(
        (op.as_str(), resource.as_str()),
        ("payment", "default-external-account")
    );
}

#[test]
fn a_stripe_refund_needs_its_amount() {
    let body = b"payment_intent=pi_1&amount=500";
    let (op, _, p) = money(typed(&observe(
        "POST",
        "api.stripe.com",
        "/v1/refunds",
        &[],
        body,
    )));
    assert_eq!(op, "refund");
    assert_eq!(p["amount_cents"], 500);
    // A whole refund, of an amount the enforcer cannot see.
    refused(typed(&observe(
        "POST",
        "api.stripe.com",
        "/v1/refunds",
        &[],
        b"payment_intent=pi_1",
    )));
}

#[test]
fn other_stripe_writes_are_refused_and_reads_pass() {
    refused(typed(&observe(
        "POST",
        "api.stripe.com",
        "/v1/invoices/in_1/pay",
        &[],
        b"",
    )));
    refused(typed(&observe(
        "DELETE",
        "api.stripe.com",
        "/v1/customers/cus_1",
        &[],
        b"",
    )));
    assert!(matches!(
        typed(&observe("GET", "api.stripe.com", "/v1/balance", &[], b"")),
        Typed::Http(_)
    ));
}

// ---- money hosts without an adapter, and everything else

#[test]
fn a_money_host_without_an_adapter_is_refused_except_for_reads() {
    let order = br#"{"action":{"type":"order","orders":[]}}"#;
    refused(typed(&observe(
        "POST",
        "API.Hyperliquid.xyz.",
        "/exchange",
        &[],
        order,
    )));
    assert!(matches!(
        typed(&observe("GET", "api.hyperliquid.xyz", "/info", &[], b"")),
        Typed::Http(_)
    ));
    let hosts = Adapters::builtin()
        .with_sensitive_hosts("payments", &["pay.example.com"])
        .unwrap();
    assert!(matches!(
        type_request(
            &observe("POST", "pay.example.com", "/send", &[], b"{}"),
            &hosts
        ),
        Typed::Refused(_)
    ));
}

#[test]
fn other_requests_are_ordinary_http_requests() {
    let t = typed(&observe(
        "POST",
        "api.github.com",
        "/repos/a/b/issues",
        &[],
        br#"{"title":"x"}"#,
    ));
    let Typed::Http(action) = t else {
        panic!("{t:?}")
    };
    assert_eq!(action.operation, "http.request");
    assert_eq!(action.parameters["body"]["title"], "x");
}

// ---- EVM

/// Anvil's first public test key and its address. Test transactions are
/// signed with it, so their sender recovers like a real one.
const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const TEST_SENDER: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";

fn addr(a: &str) -> Vec<u8> {
    hex::decode(a.trim_start_matches("0x")).unwrap()
}

fn signed<T>(tx: T) -> String
where
    T: alloy_consensus::SignableTransaction<alloy_primitives::Signature>,
    alloy_consensus::Signed<T>: Into<alloy_consensus::TxEnvelope>,
{
    use alloy_eips::eip2718::Encodable2718;
    use alloy_signer::SignerSync;
    let key: alloy_signer_local::PrivateKeySigner = TEST_KEY.parse().unwrap();
    let signature = key.sign_hash_sync(&tx.signature_hash()).unwrap();
    let envelope: alloy_consensus::TxEnvelope = tx.into_signed(signature).into();
    format!("0x{}", hex::encode(envelope.encoded_2718()))
}

fn to(a: &str) -> alloy_primitives::TxKind {
    alloy_primitives::TxKind::Call(a.parse().unwrap())
}

fn eip1559(chain: u64, dest: &str, value: u128, data: &[u8]) -> String {
    signed(alloy_consensus::TxEip1559 {
        chain_id: chain,
        nonce: 7,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 30_000_000_000,
        gas_limit: 60_000,
        to: to(dest),
        value: alloy_primitives::U256::from(value),
        input: data.to_vec().into(),
        access_list: Default::default(),
    })
}

fn legacy(chain: u64, dest: &str, value: u128) -> String {
    signed(alloy_consensus::TxLegacy {
        chain_id: Some(chain),
        nonce: 3,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: to(dest),
        value: alloy_primitives::U256::from(value),
        input: Default::default(),
    })
}

fn erc20(selector: &str, who: &str, amount: u128) -> Vec<u8> {
    let mut data = hex::decode(selector).unwrap();
    data.extend([0u8; 12]);
    data.extend(addr(who));
    data.extend([0u8; 16]);
    data.extend(amount.to_be_bytes());
    data
}

fn send_raw(raw: &str) -> Vec<u8> {
    json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw]})
        .to_string()
        .into_bytes()
}

const USDC_BASE: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const HETZNER: &str = "0x00000000000000000000000000000000000000aa";

#[test]
fn an_erc20_transfer_is_a_token_transfer_on_any_rpc_host() {
    let raw = eip1559(8453, USDC_BASE, 0, &erc20("a9059cbb", HETZNER, 42_500_000));
    let body = send_raw(&raw);
    let (op, resource, p) = money(typed(&observe(
        "POST",
        "some-rpc.example.net",
        "/v2/key",
        &[],
        &body,
    )));
    assert_eq!(
        (op.as_str(), resource.as_str()),
        ("token.transfer", HETZNER)
    );
    assert_eq!(p["chain"], "base");
    assert_eq!(p["token"], "USDC");
    assert_eq!(p["amount_micro"], 42_500_000);
}

#[test]
fn a_native_transfer_rounds_up_to_millionths() {
    // 0.0100000000001 ETH: a hair over 10_000 millionths.
    let raw = legacy(1, HETZNER, 10_000_000_000_000_100);
    let body = send_raw(&raw);
    let (op, _, p) = money(typed(&observe("POST", "eth.llamarpc.com", "/", &[], &body)));
    assert_eq!(op, "token.transfer");
    assert_eq!(
        (p["chain"].as_str(), p["token"].as_str()),
        (Some("ethereum"), Some("ETH"))
    );
    assert_eq!(p["amount_micro"], 10_001);
}

#[test]
fn an_approval_is_a_token_approval_and_other_calls_are_contract_calls() {
    let raw = eip1559(8453, USDC_BASE, 0, &erc20("095ea7b3", HETZNER, 5_000_000));
    let (op, _, p) = money(typed(&observe("POST", "rpc", "/", &[], &send_raw(&raw))));
    assert_eq!(op, "token.approve");
    assert_eq!(p["spender"], HETZNER);

    let raw = eip1559(
        8453,
        HETZNER,
        2_000_000_000_000,
        &hex::decode("3593564c0000").unwrap(),
    );
    let (op, _, p) = money(typed(&observe("POST", "rpc", "/", &[], &send_raw(&raw))));
    assert_eq!(op, "contract.call");
    assert_eq!(p["function"], "0x3593564c");
    assert_eq!(p["value_micro"], 2);
}

#[test]
fn transactions_that_cannot_be_compared_are_refused() {
    // A token whose decimals are unknown.
    let raw = eip1559(8453, HETZNER, 0, &erc20("a9059cbb", HETZNER, 1));
    assert!(
        refused(typed(&observe("POST", "rpc", "/", &[], &send_raw(&raw)))).contains("decimals")
    );
    // An unlimited approval.
    let raw = eip1559(8453, USDC_BASE, 0, &erc20("095ea7b3", HETZNER, u128::MAX));
    refused(typed(&observe("POST", "rpc", "/", &[], &send_raw(&raw))));
    // Not RLP.
    refused(typed(&observe(
        "POST",
        "rpc",
        "/",
        &[],
        &send_raw("0x02ff"),
    )));
    // Contract creation, signed.
    let raw = signed(alloy_consensus::TxEip1559 {
        chain_id: 8453,
        nonce: 1,
        max_priority_fee_per_gas: 1,
        max_fee_per_gas: 1,
        gas_limit: 1,
        to: alloy_primitives::TxKind::Create,
        value: alloy_primitives::U256::ZERO,
        input: vec![1, 2].into(),
        access_list: Default::default(),
    });
    assert!(refused(typed(&observe("POST", "rpc", "/", &[], &send_raw(&raw)))).contains("creates"));
}

#[test]
fn sending_or_signing_out_of_sight_is_refused_and_reads_pass() {
    let send =
        json!({"jsonrpc":"2.0","id":1,"method":"eth_sendTransaction","params":[{}]}).to_string();
    refused(typed(&observe("POST", "rpc", "/", &[], send.as_bytes())));
    let raw = legacy(1, HETZNER, 1);
    let batch = json!([
        {"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},
        {"jsonrpc":"2.0","id":2,"method":"eth_sendRawTransaction","params":[raw]}
    ])
    .to_string();
    assert!(refused(typed(&observe("POST", "rpc", "/", &[], batch.as_bytes()))).contains("batch"));
    let read =
        json!({"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[HETZNER,"latest"]})
            .to_string();
    assert!(matches!(
        typed(&observe("POST", "rpc", "/", &[], read.as_bytes())),
        Typed::Http(_)
    ));
}

#[test]
fn millionths_round_up_and_overflow_is_none() {
    assert_eq!(micro(1, 18), Some(1));
    assert_eq!(micro(1_000_000_000_000, 18), Some(1));
    assert_eq!(micro(1_000_000_000_001, 18), Some(2));
    assert_eq!(micro(5, 2), Some(50_000));
    assert_eq!(micro(u128::MAX, 6), None);
}

// ---- x402

fn x402_v2(amount: &str, signed: &str, pay_to: &str) -> String {
    let payment = json!({
        "x402Version": 2,
        "accepted": {"scheme": "exact", "network": "eip155:8453", "amount": amount,
                     "asset": USDC_BASE, "payTo": pay_to, "maxTimeoutSeconds": 60},
        "payload": {"signature": "0x00",
                    "authorization": {"from": HETZNER, "to": pay_to, "value": signed,
                                      "validAfter": "0", "validBefore": "9999999999", "nonce": "0x01"}}
    });
    base64::engine::general_purpose::STANDARD.encode(payment.to_string())
}

#[test]
fn an_x402_payment_is_typed_from_its_header() {
    let header = x402_v2(
        "250000",
        "250000",
        "0x00000000000000000000000000000000000000bb",
    );
    let headers = [("Payment-Signature", header.as_str())];
    let (op, resource, p) = money(typed(&observe(
        "GET",
        "data.example.com",
        "/report",
        &headers,
        b"",
    )));
    assert_eq!(
        (op.as_str(), resource.as_str()),
        ("x402.pay", "data.example.com")
    );
    assert_eq!(p["asset"], "USDC");
    assert_eq!(p["amount_micro"], 250_000);
}

#[test]
fn an_x402_payment_that_signs_other_terms_or_names_no_asset_is_refused() {
    let header = x402_v2(
        "250000",
        "9000000",
        "0x00000000000000000000000000000000000000bb",
    );
    let headers = [("payment-signature", header.as_str())];
    assert!(refused(typed(&observe(
        "GET",
        "data.example.com",
        "/",
        &headers,
        b""
    )))
    .contains("differs"));
    let v1 = base64::engine::general_purpose::STANDARD.encode(
        json!({"x402Version":1,"scheme":"exact","network":"base","payload":{}}).to_string(),
    );
    let headers = [("X-PAYMENT", v1.as_str())];
    assert!(refused(typed(&observe(
        "GET",
        "data.example.com",
        "/",
        &headers,
        b""
    )))
    .contains("version 1"));
    let headers = [("X-PAYMENT", "not base64 !")];
    refused(typed(&observe(
        "GET",
        "data.example.com",
        "/",
        &headers,
        b"",
    )));
}

/// Signed by Foundry's `cast mktx` with Anvil's first public test key, so the
/// decoder is checked against transactions a real wallet produces.
#[test]
fn transactions_signed_by_a_real_wallet_decode() {
    let erc20 = "0x02f8b182210580843b9aca00847735940082ea6094833589fcd6edb6e08f4c7c32d4f71b54bda0291380b844a9059cbb00000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000002887fa0c001a0e3e87539cd880a87ad2a1278de834d275d94a36f543fb307b32dba2625c61c33a05d712c1301f23b29999491d8e1d25e7150c658da46755febfef3b6a0a7d4da64";
    let (op, resource, p) = money(typed(&observe(
        "POST",
        "mainnet.base.org",
        "/",
        &[],
        &send_raw(erc20),
    )));
    assert_eq!(
        (op.as_str(), resource.as_str()),
        ("token.transfer", HETZNER)
    );
    assert_eq!(
        (p["chain"].as_str(), p["token"].as_str()),
        (Some("base"), Some("USDC"))
    );
    assert_eq!(p["amount_micro"], 42_500_000);

    // Legacy, EIP-155 on chain 1, 0.01 ETH.
    let native = "0xf86b058504a817c8008252089400000000000000000000000000000000000000aa872386f26fc100008026a02ad51b773b43e433a3285cb1982a31a2d4766db69e93a90165cbd06d6486d018a00658e727910ff9e3e430a555b6a8875fedeb8058f850d78e0dddc7e2e502d9a0";
    let (op, _, p) = money(typed(&observe(
        "POST",
        "eth.llamarpc.com",
        "/",
        &[],
        &send_raw(native),
    )));
    assert_eq!(op, "token.transfer");
    assert_eq!(
        (p["chain"].as_str(), p["token"].as_str()),
        (Some("ethereum"), Some("ETH"))
    );
    assert_eq!(p["amount_micro"], 10_000);
}

// ---- the definitions are JSON

#[test]
fn the_built_in_definitions_load_from_their_directory_too() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("adapters");
    let loaded = Adapters::from_dir(&dir).unwrap();
    let mut ids = loaded.ids();
    ids.sort();
    let mut builtin = Adapters::builtin()
        .ids()
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    builtin.sort();
    assert_eq!(ids, builtin);
}

/// A new API is a JSON file: no Rust change.
#[test]
fn an_api_is_added_by_a_definition_alone() {
    let common = r#"{"categories": {"payments": {"name": "Payments"}}}"#;
    let paypal = r#"{
      "id": "paypal-payouts",
      "category": "payments",
      "input": "json",
      "hosts": ["api-m.paypal.com"],
      "actions": [{
        "when": {"method": "POST", "path": "/v1/payments/payouts"},
        "require": [{"at": "/input/items/0/amount/currency", "in": ["USD"], "reason": "a payout not in USD"}],
        "operation": "payment",
        "resource": "recipient",
        "parameters": {
          "recipient": {"at": "/input/items/0/receiver", "as": "lower"},
          "amount_cents": {"at": "/input/items/0/amount/value", "as": "micro", "decimals": 4},
          "rail": {"const": "paypal.payout"}
        }
      }]
    }"#;
    let adapters = Adapters::load(common, &[paypal]).unwrap();
    let body = br#"{"items":[{"receiver":"Bills@Hetzner.example","amount":{"value":"42.50","currency":"USD"}}]}"#;
    let t = type_request(
        &observe(
            "POST",
            "api-m.paypal.com",
            "/v1/payments/payouts",
            &[],
            body,
        ),
        &adapters,
    );
    let (op, resource, p) = money(t);
    assert_eq!(
        (op.as_str(), resource.as_str()),
        ("payment", "bills@hetzner.example")
    );
    // Dollars with two decimals, read as units of 4 decimals into millionths: cents.
    assert_eq!(p["amount_cents"], 4250);
    // Any other write to its host is refused; a read passes.
    let t = type_request(
        &observe(
            "POST",
            "api-m.paypal.com",
            "/v2/checkout/orders",
            &[],
            b"{}",
        ),
        &adapters,
    );
    assert!(refused(t).starts_with("paypal-payouts:"));
    let t = type_request(
        &observe(
            "GET",
            "api-m.paypal.com",
            "/v1/payments/payouts/x",
            &[],
            b"",
        ),
        &adapters,
    );
    assert!(matches!(t, Typed::Http(_)));
}

#[test]
fn a_definition_that_does_not_check_out_is_refused_when_loaded() {
    let common = r#"{"categories": {"payments": {"name": "Payments"}}}"#;
    let cases = [
        (
            r#"{"id": "a", "category": "payments", "input": "form", "actions": [{"refuse": "x"}]}"#,
            "hosts",
        ),
        (
            r#"{"id": "a", "category": "payments", "input": "form", "hosts": ["h"], "actions": [{"operation": "payment", "resource": "r", "parameters": {}}]}"#,
            "not a parameter",
        ),
        (
            r#"{"id": "a", "category": "payments", "input": "form", "hosts": ["h"], "actions": [{"operation": "http.request", "resource": "r", "parameters": {"r": {"at": "/input/x"}}}]}"#,
            "may write",
        ),
        (
            r#"{"id": "a", "category": "payments", "input": "form", "hosts": ["h"], "actions": [{"operation": "payment", "resource": "r", "parameters": {"r": {"at": "/elsewhere"}}}]}"#,
            "outside",
        ),
        (
            r#"{"id": "a", "category": "payments", "input": "form", "hosts": ["h"], "actions": [{"operation": "payment", "resource": "r", "parameters": {"r": {"at": "/input/x", "as": "micro"}}}]}"#,
            "decimals",
        ),
        (
            r#"{"id": "a", "category": "payments", "input": "json", "hosts": ["h"], "actions": [{"when": {"function": "transfer(address,uint256)"}, "refuse": "x"}]}"#,
            "only for",
        ),
        (
            r#"{"id": "a", "category": "payments", "input": "jsonrpc_raw_transaction", "methods": ["m"], "actions": [{"when": {"function": "transfer(address,uint)"}, "refuse": "x"}]}"#,
            "not canonical",
        ),
        (
            r#"{"id": "a", "category": "payments", "input": "form", "hosts": ["h"], "actions": [{"refuse": "x"}], "typo": 1}"#,
            "unknown field",
        ),
        (
            r#"{"id": "a", "category": "payments", "input": "form", "hosts": ["h"], "actions": [{"operation": "payment", "refuse": "x", "resource": "r", "parameters": {"r": {"const": "x"}}}]}"#,
            "exactly one",
        ),
    ];
    for (adapter, expected) in cases {
        let err = Adapters::load(common, &[adapter])
            .err()
            .unwrap_or_else(|| panic!("{adapter} loaded"));
        assert!(err.contains(expected), "{adapter}: {err}");
    }
    let twice = r#"{"id": "a", "category": "payments", "input": "form", "hosts": ["h"], "actions": [{"refuse": "x"}]}"#;
    assert!(Adapters::load(common, &[twice, twice])
        .err()
        .unwrap()
        .contains("twice"));
}

#[test]
fn decimal_text_amounts_round_up_to_millionths() {
    let common = r#"{"categories": {"payments": {"name": "Payments"}}}"#;
    let adapter = r#"{"id": "ex", "category": "payments", "input": "json", "hosts": ["ex.example"], "actions": [{
        "operation": "payment", "resource": "to",
        "parameters": {"to": {"const": "x"}, "amount_micro": {"at": "/input/amount", "as": "micro", "decimals": 0}}}]}"#;
    let adapters = Adapters::load(common, &[adapter]).unwrap();
    let amount = |a: &str| {
        let body = format!(r#"{{"amount": {a}}}"#);
        match type_request(
            &observe("POST", "ex.example", "/", &[], body.as_bytes()),
            &adapters,
        ) {
            Typed::Money(action) => Ok(action.parameters["amount_micro"].clone()),
            Typed::Refused(r) => Err(r),
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(amount("\"12.5\"").unwrap(), 12_500_000);
    assert_eq!(amount("\"0.0000001\"").unwrap(), 1);
    assert_eq!(amount("3").unwrap(), 3_000_000);
    assert!(amount("\"-1\"").is_err());
    assert!(amount("\"1e3\"").is_err());
    assert!(amount("\"0\"").is_err());
}

#[test]
fn hosts_and_adapters_have_categories() {
    let a = Adapters::builtin();
    assert_eq!(a.category_of("api.binance.com"), Some("exchange"));
    assert_eq!(a.category_of("API.Stripe.com."), Some("payments"));
    assert_eq!(a.category_of("example.com"), None);
    assert!(a.categorised().contains(&("evm", "crypto")));
    let r = refused(typed(&observe(
        "POST",
        "api.bybit.com",
        "/v5/order/create",
        &[],
        b"{}",
    )));
    assert!(r.contains("crypto exchanges host (exchange)"), "{r}");
    assert!(Adapters::builtin()
        .with_sensitive_hosts("casino", &["x.example"])
        .is_err());
    // An adapter or host in an unknown category is refused when loaded.
    let common = r#"{"categories": {"payments": {"name": "Payments"}}}"#;
    let odd = r#"{"id": "odd", "category": "casino", "input": "json", "hosts": ["x.example"], "actions": []}"#;
    assert!(Adapters::load(common, &[odd]).is_err());
    let common = r#"{"categories": {"payments": {"name": "Payments"}}, "sensitive_hosts": {"casino": ["x.example"]}}"#;
    assert!(Adapters::load(common, &[]).is_err());
}

#[test]
fn each_adapter_sits_in_the_folder_of_its_category() {
    let common =
        r#"{"categories": {"payments": {"name": "Payments"}, "crypto": {"name": "Crypto"}}}"#;
    let adapter = r#"{"id": "pp", "category": "payments", "input": "json", "hosts": ["pp.example"], "actions": [{"refuse": "x"}]}"#;
    assert!(Adapters::load_files(common, &[("payments/pp.json", adapter)]).is_ok());
    let wrong = Adapters::load_files(common, &[("crypto/pp.json", adapter)])
        .err()
        .unwrap();
    assert!(wrong.contains("goes in payments/"), "{wrong}");

    // From a directory: an adapter at the top, or in the wrong folder, is refused.
    let dir = std::env::temp_dir().join(format!("rail-adapters-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("crypto")).unwrap();
    std::fs::write(dir.join("common.json"), common).unwrap();
    std::fs::write(dir.join("pp.json"), adapter).unwrap();
    assert!(Adapters::from_dir(&dir)
        .err()
        .unwrap()
        .contains("folder of its category"));
    std::fs::rename(dir.join("pp.json"), dir.join("crypto/pp.json")).unwrap();
    assert!(Adapters::from_dir(&dir)
        .err()
        .unwrap()
        .contains("goes in payments/"));
    std::fs::create_dir_all(dir.join("payments")).unwrap();
    std::fs::rename(dir.join("crypto/pp.json"), dir.join("payments/pp.json")).unwrap();
    assert_eq!(Adapters::from_dir(&dir).unwrap().ids(), vec!["pp"]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_transaction_names_its_sender_and_a_bad_signature_is_refused() {
    let raw = eip1559(8453, USDC_BASE, 0, &erc20("a9059cbb", HETZNER, 1));
    let tx = trusted_rail_enforce::decode::transaction(&addr(&raw)).unwrap();
    assert_eq!(tx["from"], TEST_SENDER);
    assert_eq!(tx["chain_id"], 8453);
    // The same transaction with its signature's r changed recovers no sender,
    // or another one; a made-up signature is refused.
    let mut bytes = addr(&raw);
    let n = bytes.len();
    bytes[n - 40] ^= 0xff;
    match trusted_rail_enforce::decode::transaction(&bytes) {
        Err(_) => {}
        Ok(tx) => assert_ne!(tx["from"], TEST_SENDER),
    }
    // Bytes after the transaction.
    let mut longer = addr(&raw);
    longer.push(0);
    assert!(trusted_rail_enforce::decode::transaction(&longer).is_err());
}

#[test]
fn calls_with_dynamic_arguments_are_read() {
    // A function with bytes, string and an array, which the static-only
    // decoder refused: its arguments are read, and re-encoding must match.
    let (selector, types) =
        trusted_rail_enforce::decode::signature("swap(bytes,string,uint256[])").unwrap();
    assert_eq!(types, ["bytes", "string", "uint256[]"]);
    use alloy_dyn_abi::DynSolValue;
    let args = DynSolValue::Tuple(vec![
        DynSolValue::Bytes(vec![1, 2, 3]),
        DynSolValue::String("usdc".into()),
        DynSolValue::Array(vec![DynSolValue::Uint(
            alloy_primitives::U256::from(5u8),
            256,
        )]),
    ])
    .abi_encode_params();
    let mut data = addr(&selector);
    data.extend(&args);
    let read = trusted_rail_enforce::decode::arguments(&data, &types).unwrap();
    assert_eq!(read, vec![json!("0x010203"), json!("usdc"), json!(["5"])]);
    data.push(0);
    assert!(trusted_rail_enforce::decode::arguments(&data, &types).is_err());
    // A selector is the hash of the canonical signature.
    assert_eq!(
        trusted_rail_enforce::decode::signature("transfer(address,uint256)")
            .unwrap()
            .0,
        "0xa9059cbb"
    );
    assert!(trusted_rail_enforce::decode::signature("transfer(address to, uint256)").is_err());
}
