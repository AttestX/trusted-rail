use serde_json::json;
use trusted_rail_enforce::toolcalls::{
    calls_in_request, Format, Open, ReplyReader, Runs, ToolCall,
};

/// Feed a body in awkward pieces, as a stream arrives.
fn read(format: Format, body: &str, piece: usize) -> Vec<ToolCall> {
    let mut reader = ReplyReader::new(format);
    for chunk in body.as_bytes().chunks(piece) {
        reader.feed(chunk);
    }
    let (calls, complete) = reader.finish();
    assert!(complete);
    calls
}

fn sse(events: &[serde_json::Value]) -> String {
    events
        .iter()
        .map(|e| format!("event: x\ndata: {e}\n\n"))
        .collect()
}

#[test]
fn anthropic_streamed_tool_use_is_rebuilt() {
    let body = sse(&[
        json!({"type":"message_start","message":{"id":"msg_1"}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Paying."}}),
        json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}),
        json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\": \"curl -X POST"}}),
        json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":" https://api.stripe.com/v1/transfers\"}"}}),
        json!({"type":"content_block_stop","index":1}),
        json!({"type":"message_stop"}),
    ]);
    for piece in [1, 7, 64, 100_000] {
        let calls = read(Format::Anthropic, &body, piece);
        assert_eq!(calls.len(), 1, "piece {piece}");
        assert_eq!(calls[0].id, "toolu_1");
        assert_eq!(calls[0].name, "bash");
        let args: serde_json::Value = serde_json::from_str(&calls[0].arguments).unwrap();
        assert_eq!(
            args["command"],
            "curl -X POST https://api.stripe.com/v1/transfers"
        );
    }
}

#[test]
fn openai_chat_streamed_tool_calls_are_rebuilt() {
    let body = sse(&[
        json!({"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"pay","arguments":""}}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"to\":\"hetz"}}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"read_file","arguments":"{}"}}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ner\"}"}}]}}]}),
    ]) + "data: [DONE]\n\n";
    let calls = read(Format::OpenAiChat, &body, 5);
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (calls[0].id.as_str(), calls[0].name.as_str()),
        ("call_a", "pay")
    );
    assert_eq!(calls[0].arguments, r#"{"to":"hetzner"}"#);
    assert_eq!(calls[1].name, "read_file");
}

#[test]
fn openai_responses_streamed_calls_use_the_finished_item() {
    let body = sse(&[
        json!({"type":"response.output_item.added","item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"shell","arguments":""}}),
        json!({"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"cmd\":"}),
        json!({"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"\"ls\"}"}),
        json!({"type":"response.output_item.done","item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"shell","arguments":"{\"cmd\":\"ls\"}"}}),
        json!({"type":"response.output_item.done","item":{"type":"local_shell_call","id":"ls_1","call_id":"call_2","action":{"type":"exec","command":["python","run.py"]}}}),
    ]);
    let calls = read(Format::OpenAiResponses, &body, 3);
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (calls[0].id.as_str(), calls[0].arguments.as_str()),
        ("call_1", r#"{"cmd":"ls"}"#)
    );
    assert_eq!(calls[1].name, "local_shell");
    assert!(calls[1].arguments.contains("run.py"));
}

#[test]
fn whole_json_replies_are_read() {
    let anthropic = json!({"content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"toolu_9","name":"pay","input":{"amount":42}}]});
    let calls = read(Format::Anthropic, &anthropic.to_string(), 10);
    assert_eq!(
        calls,
        vec![ToolCall {
            id: "toolu_9".into(),
            name: "pay".into(),
            arguments: r#"{"amount":42}"#.into(),
            runs: Runs::Agent,
        }]
    );
    let chat = json!({"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_z","type":"function","function":{"name":"pay","arguments":"{}"}}]}}]});
    assert_eq!(
        read(Format::OpenAiChat, &chat.to_string(), 4)[0].id,
        "call_z"
    );
    let responses = json!({"output":[{"type":"message"},{"type":"function_call","call_id":"call_r","name":"pay","arguments":"{}"}]});
    assert_eq!(
        read(Format::OpenAiResponses, &responses.to_string(), 4)[0].id,
        "call_r"
    );
}

#[test]
fn a_reply_too_large_to_hold_is_reported_incomplete() {
    let mut reader = ReplyReader::new(Format::Anthropic);
    reader.feed(b"{\"content\":\"");
    reader.feed(&vec![b'a'; trusted_rail_enforce::toolcalls::MAX_HELD + 1]);
    let (calls, complete) = reader.finish();
    assert!(calls.is_empty() && !complete);
}

#[test]
fn the_next_request_shows_calls_and_their_results() {
    let anthropic = json!({"messages":[
        {"role":"user","content":"pay hetzner"},
        {"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"bash","input":{"command":"./pay"}}]},
        {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"paid"}]}
    ]});
    let (calls, results) = calls_in_request(Format::Anthropic, anthropic.to_string().as_bytes());
    assert_eq!(
        (calls[0].id.as_str(), results),
        ("toolu_1", vec!["toolu_1".to_string()])
    );

    let chat = json!({"messages":[
        {"role":"assistant","tool_calls":[{"id":"call_a","type":"function","function":{"name":"pay","arguments":"{}"}}]},
        {"role":"tool","tool_call_id":"call_a","content":"ok"}
    ]});
    let (calls, results) = calls_in_request(Format::OpenAiChat, chat.to_string().as_bytes());
    assert_eq!((calls.len(), results), (1, vec!["call_a".to_string()]));

    let responses = json!({"input":[
        {"type":"function_call","call_id":"call_r","name":"pay","arguments":"{}"},
        {"type":"function_call_output","call_id":"call_r","output":"ok"}
    ]});
    let (calls, results) =
        calls_in_request(Format::OpenAiResponses, responses.to_string().as_bytes());
    assert_eq!((calls.len(), results), (1, vec!["call_r".to_string()]));
}

#[test]
fn requests_are_linked_to_the_calls_still_open() {
    let call = |id: &str| ToolCall {
        id: id.into(),
        name: "bash".into(),
        arguments: "{}".into(),
        runs: Runs::Agent,
    };
    let mut open = Open::default();
    open.asked(&[call("a"), call("b")]);
    assert_eq!(open.link().len(), 2);
    open.answered(&["a".into()]);
    assert_eq!(open.link(), vec![call("b")]);
    open.answered(&["b".into()]);
    assert!(open.link().is_empty());
}

#[test]
fn formats_follow_the_api_path() {
    assert_eq!(Format::of("/v1/messages"), Some(Format::Anthropic));
    assert_eq!(
        Format::of("/api/v1/chat/completions"),
        Some(Format::OpenAiChat)
    );
    assert_eq!(
        Format::of("/backend-api/codex/responses"),
        Some(Format::OpenAiResponses)
    );
    assert_eq!(Format::of("/v1/models"), None);
}

#[test]
fn every_responses_call_is_read_with_who_runs_it() {
    let body = json!({"output": [
        {"type": "shell_call", "id": "sh_1", "call_id": "call_s", "action": {"commands": ["ls"]}},
        {"type": "apply_patch_call", "id": "ap_1", "call_id": "call_p", "operation": {"type": "update_file", "path": "a.py"}},
        {"type": "computer_call", "id": "cu_1", "call_id": "call_c", "action": {"type": "click", "x": 1, "y": 2}},
        {"type": "mcp_call", "id": "mcp_1", "server_label": "pay", "name": "transfer", "arguments": "{\"amount\":5}"},
        {"type": "mcp_approval_request", "id": "mcpr_1", "server_label": "pay", "name": "transfer", "arguments": "{}"},
        {"type": "web_search_call", "id": "ws_1", "action": {"type": "search", "query": "x"}}
    ]});
    let calls = read(Format::OpenAiResponses, &body.to_string(), 7);
    let seen: Vec<(&str, Runs)> = calls.iter().map(|c| (c.name.as_str(), c.runs)).collect();
    assert_eq!(
        seen,
        vec![
            ("shell", Runs::Agent),
            ("apply_patch", Runs::Agent),
            ("computer", Runs::Agent),
            ("mcp:pay/transfer", Runs::Provider),
            ("mcp_approval:pay/transfer", Runs::Provider),
            ("web_search", Runs::Provider),
        ]
    );
    assert_eq!(calls[0].id, "call_s");
    assert_eq!(calls[3].id, "mcp_1");
    assert!(calls[3].arguments.contains("amount"));
    let (_, results) = calls_in_request(
        Format::OpenAiResponses,
        json!({"input": [{"type": "shell_call_output", "call_id": "call_s"}]})
            .to_string()
            .as_bytes(),
    );
    assert_eq!(results, vec!["call_s".to_string()]);
}

#[test]
fn anthropic_mcp_and_server_tool_calls_are_the_providers() {
    let stream = [
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"mcp_tool_use","id":"mcptoolu_1","name":"transfer","server_name":"pay","input":{}}}"#,
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"amount\":5}"}}"#,
        r#"data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}"#,
        "",
    ]
    .join("\n");
    let mut r = ReplyReader::new(Format::Anthropic);
    r.feed(stream.as_bytes());
    let (calls, complete) = r.finish();
    assert!(complete);
    assert_eq!(calls[0].name, "mcp:pay/transfer");
    assert_eq!(calls[0].runs, Runs::Provider);
    assert_eq!(calls[0].arguments, r#"{"amount":5}"#);
    assert_eq!(
        (calls[1].name.as_str(), calls[1].runs),
        ("bash", Runs::Agent)
    );
}
