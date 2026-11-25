//! The exchange adapters, Hyperliquid and Binance, and the WebSocket rule.
use serde_json::{json, Value};
use trusted_rail_enforce::{type_request, Adapters, Observed, Typed};

fn request<'a>(
    method: &'a str,
    host: &'a str,
    path: &'a str,
    query: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
) -> Typed {
    type_request(
        &Observed {
            method,
            scheme: "https",
            host,
            port: 443,
            path,
            query,
            binary: "/usr/bin/python3",
            headers,
            body,
        },
        &Adapters::builtin(),
    )
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

// ---- Hyperliquid

const HL: &str = "api.hyperliquid.xyz";

fn exchange(action: Value) -> Typed {
    let body = json!({"action": action, "nonce": 1_732_000_000_000u64,
                      "signature": {"r": "0x1", "s": "0x2", "v": 27}, "vaultAddress": null});
    request(
        "POST",
        HL,
        "/exchange",
        "",
        &[],
        body.to_string().as_bytes(),
    )
}

fn hl_order(order: Value) -> Value {
    json!({"type": "order", "orders": [order], "grouping": "na"})
}

#[test]
fn a_hyperliquid_order_is_its_price_times_its_size_on_the_named_perpetual() {
    let (op, resource, p) = money(exchange(hl_order(json!({
        "a": 0, "b": true, "p": "97000.5", "s": "0.0125", "r": false,
        "t": {"limit": {"tif": "Gtc"}}
    }))));
    assert_eq!((op.as_str(), resource.as_str()), ("order.place", "btc"));
    // 97000.5 x 0.0125 = 1212.50625 USDC.
    assert_eq!(p["amount_micro"], 1_212_506_250u64);
    assert_eq!(p["side"], "buy");
    assert_eq!(p["currency"], "usdc");
    assert_eq!(p["account"], "main");
    // A sell, an IOC limit (how market orders are sent), and a limit trigger.
    let (_, resource, p) = money(exchange(hl_order(json!({
        "a": 1, "b": false, "p": "3500", "s": "2", "r": true, "t": {"limit": {"tif": "Ioc"}}
    }))));
    assert_eq!(
        (resource.as_str(), p["side"].as_str()),
        ("eth", Some("sell"))
    );
    assert_eq!(p["amount_micro"], 7_000_000_000u64);
    money(exchange(hl_order(json!({
        "a": 0, "b": false, "p": "90000", "s": "0.01", "r": true,
        "t": {"trigger": {"isMarket": false, "triggerPx": "90100", "tpsl": "sl"}}
    }))));
}

#[test]
fn hyperliquid_orders_it_cannot_value_and_account_changes_are_refused() {
    let order =
        json!({"a": 0, "b": true, "p": "1", "s": "1", "r": false, "t": {"limit": {"tif": "Gtc"}}});
    let two = json!({"type": "order", "orders": [order, order], "grouping": "na"});
    assert!(refused(exchange(two)).contains("several orders"));
    let mut grouped = hl_order(order.clone());
    grouped["grouping"] = json!("normalTpsl");
    assert!(refused(exchange(grouped)).contains("take-profit"));
    let mut builder = hl_order(order.clone());
    builder["builder"] = json!({"b": "0xabc", "f": 10});
    assert!(refused(exchange(builder)).contains("third party"));
    let mut market_trigger = order.clone();
    market_trigger["t"] = json!({"trigger": {"isMarket": true, "triggerPx": "1", "tpsl": "tp"}});
    assert!(refused(exchange(hl_order(market_trigger))).contains("not stated"));
    // Spot (10000 and up) and unknown assets are not in the table.
    let mut spot = order.clone();
    spot["a"] = json!(10_107);
    assert!(refused(exchange(hl_order(spot))).contains("perps table"));
    for (kind, why) in [
        ("withdraw3", "moving funds"),
        ("usdSend", "moving funds"),
        ("approveAgent", "account control"),
        ("updateLeverage", "leverage"),
        ("modify", "cancel it"),
        ("twapOrder", "not stated"),
        ("somethingNew", "not one of its actions"),
    ] {
        let reason = refused(exchange(json!({"type": kind})));
        assert!(
            reason.starts_with("hyperliquid: ") && reason.contains(why),
            "{kind}: {reason}"
        );
    }
    // Cancels are typed; reads by POST pass.
    let (op, resource, _) = money(exchange(
        json!({"type": "cancel", "cancels": [{"a": 0, "o": 91490942}]}),
    ));
    assert_eq!(
        (op.as_str(), resource.as_str()),
        ("order.cancel", "91490942")
    );
    let (op, resource, _) = money(exchange(json!({"type": "scheduleCancel", "time": 1})));
    assert_eq!((op.as_str(), resource.as_str()), ("order.cancel", "all"));
    let read = json!({"type": "clearinghouseState", "user": "0xabc"}).to_string();
    assert!(matches!(
        request("POST", HL, "/info", "", &[], read.as_bytes()),
        Typed::Http(_)
    ));
    // Testnet numbers its assets differently, so it has no adapter: writes are refused.
    let body = json!({"action": hl_order(order)}).to_string();
    assert!(refused(request(
        "POST",
        "api.hyperliquid-testnet.xyz",
        "/exchange",
        "",
        &[],
        body.as_bytes()
    ))
    .contains("(exchange)"));
}

// ---- Binance

const BN: &str = "api.binance.com";

fn binance(query: &str, body: &str) -> Typed {
    request("POST", BN, "/api/v3/order", query, &[], body.as_bytes())
}

#[test]
fn a_binance_order_is_typed_from_the_query_and_the_body_in_its_quote_asset() {
    // All in the query, as signed requests usually are.
    let (op, resource, p) = money(binance(
        "symbol=BTCUSDT&side=BUY&type=MARKET&quoteOrderQty=250.5&timestamp=1&signature=ab",
        "",
    ));
    assert_eq!((op.as_str(), resource.as_str()), ("order.place", "btcusdt"));
    assert_eq!(p["amount_micro"], 250_500_000u64);
    assert_eq!(p["currency"], "usdt");
    // Split between the body and the query; a limit order is quantity x price.
    let (_, resource, p) = money(binance(
        "timestamp=1&signature=ab",
        "symbol=ETHUSDC&side=SELL&type=LIMIT&timeInForce=GTC&quantity=0.5&price=3500.10",
    ));
    assert_eq!(resource, "ethusdc");
    assert_eq!(p["amount_micro"], 1_750_050_000u64);
    assert_eq!(
        (p["currency"].as_str(), p["side"].as_str()),
        (Some("usdc"), Some("sell"))
    );
    // USD pairs only on Binance.US.
    let (_, _, p) = money(request(
        "POST",
        "api.binance.us",
        "/api/v3/order",
        "symbol=BTCUSD&side=BUY&type=LIMIT_MAKER&quantity=0.001&price=90000",
        &[],
        b"",
    ));
    assert_eq!(
        (p["currency"].as_str(), p["amount_micro"].as_u64()),
        (Some("usd"), Some(90_000_000))
    );
}

#[test]
fn binance_orders_it_cannot_value_and_other_writes_are_refused() {
    for (query, why) in [
        (
            "symbol=BTCUSDT&side=BUY&type=MARKET&quantity=1",
            "not stated",
        ),
        (
            "symbol=BTCUSDT&side=SELL&type=STOP_LOSS&quantity=1&stopPrice=90000",
            "not stated",
        ),
        (
            "symbol=BTCUSDT&side=BUY&type=LIMIT&quantity=1&price=1&quoteOrderQty=1",
            "not both",
        ),
        (
            "symbol=BTCUSDT&side=BUY&type=LIMIT&quantity=1&price=1&pegPriceType=PRIMARY_PEG",
            "pegged",
        ),
        (
            "symbol=BTCUSDT&side=SELL&type=STOP_LOSS_LIMIT&quantity=1&price=1&trailingDelta=100",
            "trailing",
        ),
        (
            "symbol=ETHBTC&side=BUY&type=MARKET&quoteOrderQty=1",
            "not in dollars",
        ),
        (
            "symbol=BTCFDUSD&side=BUY&type=MARKET&quoteOrderQty=1",
            "not in dollars",
        ),
        (
            "symbol=BTCUSD&side=BUY&type=MARKET&quoteOrderQty=1",
            "not in dollars",
        ),
        (
            "symbol=BTCUSDT&side=BUY&type=MARKET&quoteOrderQty=1&quoteOrderQty=2",
            "given twice",
        ),
    ] {
        let reason = refused(binance(query, ""));
        assert!(reason.contains(why), "{query}: {reason}");
    }
    // The same field in the query and the body: Binance would read the query's.
    assert!(refused(binance(
        "symbol=BTCUSDT&side=BUY&type=MARKET&quoteOrderQty=1",
        "quoteOrderQty=100000"
    ))
    .contains("given twice"));
    let call = |method: &'static str, path: &'static str, query: &'static str| {
        request(method, BN, path, query, &[], b"")
    };
    for (method, path, why) in [
        ("POST", "/api/v3/order/oco", "several orders"),
        ("POST", "/api/v3/orderList/otoco", "several orders"),
        ("POST", "/api/v3/order/cancelReplace", "cancel it"),
        ("POST", "/sapi/v1/capital/withdraw/apply", "withdrawals"),
        ("POST", "/sapi/v1/margin/loan", "not one of its actions"),
    ] {
        let reason = refused(call(method, path, ""));
        assert!(reason.contains(why), "{path}: {reason}");
    }
    let (op, resource, _) = money(call("DELETE", "/api/v3/order", "symbol=BTCUSDT&orderId=28"));
    assert_eq!((op.as_str(), resource.as_str()), ("order.cancel", "28"));
    let (op, resource, _) = money(call("DELETE", "/api/v3/openOrders", "symbol=BTCUSDT"));
    assert_eq!((op.as_str(), resource.as_str()), ("order.cancel", "all"));
    assert!(matches!(
        call("POST", "/api/v3/order/test", "symbol=BTCUSDT"),
        Typed::Http(_)
    ));
    assert!(matches!(
        call("POST", "/api/v3/userDataStream", ""),
        Typed::Http(_)
    ));
    assert!(matches!(
        call("GET", "/api/v3/account", "timestamp=1"),
        Typed::Http(_)
    ));
    // Futures have no adapter yet: refused.
    assert!(refused(request(
        "POST",
        "fapi.binance.com",
        "/fapi/v1/order",
        "symbol=BTCUSDT",
        &[],
        b""
    ))
    .contains("(exchange)"));
}

#[test]
fn a_websocket_to_a_host_that_moves_money_is_refused() {
    let upgrade = [("Upgrade", "websocket"), ("Connection", "Upgrade")];
    for host in ["ws-api.binance.com", HL, "api.alpaca.markets"] {
        let reason = refused(request("GET", host, "/ws", "", &upgrade, b""));
        assert!(reason.contains("WebSocket"), "{host}: {reason}");
    }
    // Market data streams are on other hosts, and pass.
    assert!(matches!(
        request(
            "GET",
            "stream.binance.com",
            "/ws/btcusdt@trade",
            "",
            &upgrade,
            b""
        ),
        Typed::Http(_)
    ));
}

#[test]
fn a_definition_with_a_bad_table_pass_or_field_is_refused() {
    let common = include_str!("../adapters/common.json");
    for (definition, why) in [
        (
            r#"{"id": "a", "category": "exchange", "input": "json", "hosts": ["h"], "actions": [{"operation": "o", "resource": "x", "parameters": {"x": {"at": "/input/x", "as": "lookup", "table": "none"}}}]}"#,
            "tables",
        ),
        (
            r#"{"id": "a", "category": "exchange", "input": "json", "hosts": ["h"], "actions": [{"pass": true, "refuse": "r"}]}"#,
            "pass",
        ),
        (
            r#"{"id": "a", "category": "exchange", "input": "json", "hosts": ["h"], "actions": [{"pass": true, "parameters": {"x": {"const": 1}}}]}"#,
            "pass",
        ),
        (
            r#"{"id": "a", "category": "exchange", "input": "json", "hosts": ["h"], "actions": [{"when": {"fields": [{"at": "/input/x", "is": [1], "matches": "a"}]}, "refuse": "r"}]}"#,
            "is or matches",
        ),
    ] {
        let err = Adapters::load_files(common, &[("exchange/a.json", definition)])
            .err()
            .unwrap_or_else(|| panic!("{definition} loaded"));
        assert!(err.contains(why), "{err}");
    }
}
