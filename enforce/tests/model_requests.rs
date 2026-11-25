//! The model-request rules: a request that would have a provider call a third
//! party from its own servers is refused, wherever it goes.
use serde_json::json;
use trusted_rail_enforce::{type_request, Adapters, Observed, Typed};

fn check(host: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Typed {
    let o = Observed {
        method: "POST",
        scheme: "https",
        host,
        port: 443,
        path,
        query: "",
        binary: "/usr/bin/node",
        headers,
        body: body.as_bytes(),
    };
    type_request(&o, &Adapters::builtin())
}

fn refused(t: Typed) -> String {
    match t {
        Typed::Refused(r) => r,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn passes(t: Typed) {
    match t {
        Typed::Http(a) => assert_eq!(a.operation, "http.request"),
        other => panic!("expected plain http, got {other:?}"),
    }
}

#[test]
fn the_requests_our_runtimes_send_pass() {
    let chat = json!({"model": "anthropic/claude-haiku-4.5", "stream": true,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"type": "function", "function": {"name": "pay", "parameters": {}}}]});
    passes(check(
        "routerbase.com",
        "/v1/chat/completions",
        &[],
        &chat.to_string(),
    ));
    let messages = json!({"model": "claude-haiku-4-5", "max_tokens": 64,
        "messages": [{"role": "user", "content": "hi"}],
        "tools": [{"name": "bash", "input_schema": {"type": "object"}},
                  {"type": "web_search_20250305", "name": "web_search"}]});
    passes(check(
        "api.anthropic.com",
        "/v1/messages",
        &[("anthropic-beta", "prompt-caching-2024-07-31")],
        &messages.to_string(),
    ));
    let gemini = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
        "tools": [{"functionDeclarations": [{"name": "pay"}]}]});
    passes(check(
        "generativelanguage.googleapis.com",
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
        &[],
        &gemini.to_string(),
    ));
}

#[test]
fn a_provider_run_mcp_server_is_refused_on_every_api() {
    let openai = json!({"model": "gpt-5.4", "input": "pay",
        "tools": [{"type": "mcp", "server_label": "pay", "server_url": "https://mcp.pay.example/mcp",
                   "require_approval": "never"}]});
    let r = refused(check(
        "api.openai.com",
        "/v1/responses",
        &[],
        &openai.to_string(),
    ));
    assert!(r.contains("MCP"), "{r}");
    let anthropic = json!({"model": "claude-sonnet-5", "max_tokens": 64, "messages": [],
        "mcp_servers": [{"type": "url", "url": "https://mcp.pay.example/mcp", "name": "pay"}]});
    refused(check(
        "api.anthropic.com",
        "/v1/messages",
        &[],
        &anthropic.to_string(),
    ));
    let header = refused(check(
        "api.anthropic.com",
        "/v1/messages",
        &[
            ("anthropic-beta", "prompt-caching-2024-07-31"),
            ("Anthropic-Beta", "mcp-client-2026-09-15"),
        ],
        r#"{"model":"claude-sonnet-5","messages":[]}"#,
    ));
    assert!(header.contains("beta"), "{header}");
    let connector = json!({"model": "gpt-5.4", "input": "x",
        "tools": [{"type": "mcp", "server_label": "g", "connector_id": "connector_gmail"}]});
    refused(check(
        "api.groq.com",
        "/openai/v1/responses",
        &[],
        &connector.to_string(),
    ));
    let shell = json!({"model": "gpt-5.4", "input": "x", "tools": [{"type": "shell",
        "environment": {"type": "container_auto", "network_policy": {"allowed_domains": ["pay.example"]}}}]});
    let r = refused(check(
        "api.openai.com",
        "/v1/responses",
        &[],
        &shell.to_string(),
    ));
    assert!(r.contains("network"), "{r}");
    // A hosted shell with no network is the provider's sandbox, and passes.
    let offline = json!({"model": "gpt-5.4", "input": "x",
        "tools": [{"type": "shell", "environment": {"type": "container_auto"}}]});
    passes(check(
        "api.openai.com",
        "/v1/responses",
        &[],
        &offline.to_string(),
    ));
}

#[test]
fn a_gateway_on_an_unknown_host_is_checked_by_path_and_shape() {
    let body = json!({"model": "gpt-5.4", "input": "x",
        "tools": [{"type": "mcp", "server_label": "p", "server_url": "litellm_proxy"}]});
    refused(check(
        "llm.internal.example",
        "/v1/responses",
        &[],
        &body.to_string(),
    ));
    refused(check(
        "llm.internal.example",
        "/proxy/anything",
        &[],
        &body.to_string(),
    ));
    // Off a model host and without a model request's shape, the same field
    // names belong to some other API and are left alone.
    passes(check(
        "crm.example",
        "/api/tickets",
        &[],
        &json!({"agent": "alice", "prompt": {"id": "p1"}}).to_string(),
    ));
}

#[test]
fn stored_agents_and_prompts_are_refused_since_their_tools_are_not_shown() {
    let prompt = json!({"model": "gpt-5.4", "input": "x", "prompt": {"id": "pmpt_1"}});
    refused(check(
        "api.openai.com",
        "/v1/responses",
        &[],
        &prompt.to_string(),
    ));
    let gemini = json!({"agent": "antigravity-preview-09-2026", "input": "x"});
    refused(check(
        "llm.internal.example",
        "/v1beta/interactions",
        &[],
        &gemini.to_string(),
    ));
}

#[test]
fn model_hosts_take_only_model_endpoints() {
    let r = refused(check(
        "api.anthropic.com",
        "/v1/sessions",
        &[],
        r#"{"session":"s1"}"#,
    ));
    assert!(r.contains("not a model endpoint"), "{r}");
    refused(check(
        "api.mistral.ai",
        "/v1/conversations",
        &[],
        r#"{"agent_id":"a","inputs":"x"}"#,
    ));
    refused(check(
        "my-resource.openai.azure.com",
        "/openai/v1/files",
        &[],
        "",
    ));
    refused(check("api.x.ai", "/v1/responses", &[], "not json"));
}

#[test]
fn what_cannot_be_read_is_refused() {
    let body = r#"{"model":"gpt-5.4","input":"x","tools":[]}"#;
    refused(check(
        "api.openai.com",
        "/v1/responses",
        &[("Content-Encoding", "gzip")],
        body,
    ));
    // The same compressed body to a gateway, sent as JSON.
    refused(check(
        "llm.internal.example",
        "/v1/responses",
        &[
            ("content-type", "application/json"),
            ("content-encoding", "gzip"),
        ],
        body,
    ));
    // Some other app's `/messages`, not JSON: not a model request.
    passes(check(
        "chat.example",
        "/api/messages",
        &[
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-encoding", "gzip"),
        ],
        "text=hello",
    ));
    // Two `tools`: a provider that keeps the first would see the MCP server.
    let twice = r#"{"model":"gpt-5.4","input":"x","tools":[{"type":"mcp","server_url":"https://p.example"}],"tools":[]}"#;
    let r = refused(check("api.openai.com", "/v1/responses", &[], twice));
    assert!(r.contains("twice"), "{r}");
}

#[test]
fn the_rules_are_checked_when_loaded() {
    let common = r#"{"categories":{"security":"Security"}}"#;
    let base = Adapters::load(common, &[]).unwrap();
    let loose = r#"{"model_hosts":[],"endpoints":[],"shapes":[],"refuse":[{"at":"/tools/*/type","reason":"x"}]}"#;
    assert!(base.with_model_rules(loose).is_err());
    let base = Adapters::load(common, &[]).unwrap();
    let unknown = r#"{"model_hosts":[],"endpoints":[],"shapes":[],"refuse":[],"allow_mcp":true}"#;
    assert!(base.with_model_rules(unknown).is_err());
    let base = Adapters::load(common, &[]).unwrap();
    let both = r#"{"model_hosts":[],"endpoints":[],"shapes":[],"refuse":[{"present":"/a","header":"h","contains":["x"],"reason":"x"}]}"#;
    assert!(base.with_model_rules(both).is_err());
}
