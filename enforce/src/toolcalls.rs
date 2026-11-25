//! The tool calls in a model's replies, read on the network.
//!
//! The agent's runtime calls its model through the enforcer's proxy, so the
//! enforcer sees each reply before the runtime does. [`ReplyReader`] takes the
//! reply body as it streams and gives back the tool calls in it; the reply is
//! passed on unchanged and at once. [`calls_in_request`] reads the next request,
//! which resends the conversation with each call and its result. [`Open`]
//! tracks which calls are running, so an outbound request can be linked to the
//! call that led to it.
//!
//! A tool call is what the model asked for, not what the sandbox sent. It is
//! evidence for the record, and never the basis of a decision.
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The model APIs whose tool calls are read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Anthropic Messages: `tool_use` content blocks.
    Anthropic,
    /// OpenAI Chat Completions: `tool_calls` on the message.
    OpenAiChat,
    /// OpenAI Responses, Codex included: `function_call` output items.
    OpenAiResponses,
}

impl Format {
    /// The format of a model request, from its path. Proxies and gateways that
    /// speak these APIs keep the same paths.
    pub fn of(path: &str) -> Option<Format> {
        let path = path.trim_end_matches('/');
        if path.ends_with("/messages") {
            Some(Format::Anthropic)
        } else if path.ends_with("/chat/completions") {
            Some(Format::OpenAiChat)
        } else if path.ends_with("/responses") {
            Some(Format::OpenAiResponses)
        } else {
            None
        }
    }
}

/// Who runs a tool call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Runs {
    /// The agent's runtime, in the sandbox: what it sends goes through the proxy.
    #[default]
    Agent,
    /// The model provider, on its own servers: a remote MCP call, a hosted search
    /// or code run. The proxy never sees what it sends. The model-request rules
    /// refuse the requests that would let it reach a third party, so a call here
    /// is a search, a sandboxed run, or a sign those rules are missing a case.
    Provider,
}

/// One tool call: its id in the conversation, the tool, its arguments as the
/// model wrote them (JSON text, possibly invalid), and who runs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
    pub runs: Runs,
}

/// The most reply text held at once, for a streamed line or a whole JSON body.
/// Past it the reader stops reading, and says so.
pub const MAX_HELD: usize = 4 * 1024 * 1024;

#[derive(Default)]
struct Building {
    id: String,
    name: String,
    arguments: String,
    runs: Runs,
    done: Option<ToolCall>,
}

/// Reads one reply, streamed (server-sent events) or whole (JSON).
pub struct ReplyReader {
    format: Format,
    held: Vec<u8>,
    streamed: Option<bool>,
    calls: BTreeMap<String, Building>,
    order: Vec<String>,
    overflowed: bool,
}

impl ReplyReader {
    pub fn new(format: Format) -> Self {
        ReplyReader {
            format,
            held: Vec::new(),
            streamed: None,
            calls: BTreeMap::new(),
            order: Vec::new(),
            overflowed: false,
        }
    }

    /// The next piece of the body, as it arrived.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.overflowed {
            return;
        }
        self.held.extend_from_slice(bytes);
        if self.streamed.is_none() {
            if let Some(first) = self.held.iter().find(|b| !b.is_ascii_whitespace()) {
                self.streamed = Some(*first != b'{');
            }
        }
        if self.streamed == Some(true) {
            while let Some(end) = self.held.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.held.drain(..=end).collect();
                self.line(&line);
            }
        }
        if self.held.len() > MAX_HELD {
            self.overflowed = true;
            self.held.clear();
        }
    }

    /// The calls in the reply, in the order they began. `complete` is false when
    /// the reply was too large to read whole.
    pub fn finish(mut self) -> (Vec<ToolCall>, bool) {
        if !self.overflowed {
            let rest = std::mem::take(&mut self.held);
            if self.streamed == Some(true) {
                self.line(&rest);
            } else if let Ok(body) = serde_json::from_slice::<Value>(&rest) {
                self.whole(&body);
            }
        }
        let calls = self
            .order
            .iter()
            .filter_map(|key| self.calls.remove(key))
            .map(|b| {
                b.done.unwrap_or(ToolCall {
                    id: b.id,
                    name: b.name,
                    arguments: b.arguments,
                    runs: b.runs,
                })
            })
            .filter(|c| !c.name.is_empty())
            .collect();
        (calls, !self.overflowed)
    }

    fn entry(&mut self, key: String) -> &mut Building {
        if !self.calls.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.calls.entry(key).or_default()
    }

    fn line(&mut self, line: &[u8]) {
        let line = String::from_utf8_lossy(line);
        let Some(data) = line.trim_end().strip_prefix("data:") else {
            return;
        };
        let Ok(event) = serde_json::from_str::<Value>(data.trim_start()) else {
            return;
        };
        match self.format {
            Format::Anthropic => self.anthropic_event(&event),
            Format::OpenAiChat => self.chat_chunk(&event),
            Format::OpenAiResponses => self.responses_event(&event),
        }
    }

    fn anthropic_event(&mut self, event: &Value) {
        let index = event["index"].to_string();
        match event["type"].as_str() {
            Some("content_block_start") if anthropic_block(&event["content_block"]).is_some() => {
                let block = &event["content_block"];
                let call = anthropic_block(block).expect("checked above");
                let b = self.entry(index);
                b.id = call.id;
                b.name = call.name;
                b.runs = call.runs;
                // A start may carry a whole input; deltas then add nothing.
                if let Some(input) = block["input"].as_object().filter(|i| !i.is_empty()) {
                    b.arguments = Value::Object(input.clone()).to_string();
                }
            }
            Some("content_block_delta") if event["delta"]["type"] == "input_json_delta" => {
                if let Some(b) = self.calls.get_mut(&index) {
                    b.arguments
                        .push_str(event["delta"]["partial_json"].as_str().unwrap_or(""));
                }
            }
            _ => {}
        }
    }

    fn chat_chunk(&mut self, chunk: &Value) {
        for choice in chunk["choices"].as_array().into_iter().flatten() {
            let calls = choice["delta"]["tool_calls"]
                .as_array()
                .into_iter()
                .flatten();
            for call in calls {
                let key = format!("{}:{}", choice["index"], call["index"]);
                let b = self.entry(key);
                if let Some(id) = call["id"].as_str() {
                    b.id = id.into();
                }
                if let Some(name) = call["function"]["name"].as_str() {
                    b.name.push_str(name);
                }
                if let Some(args) = call["function"]["arguments"].as_str() {
                    b.arguments.push_str(args);
                }
            }
        }
    }

    fn responses_event(&mut self, event: &Value) {
        let item = &event["item"];
        match event["type"].as_str() {
            Some("response.output_item.added") => {
                if let Some(call) = responses_item(item) {
                    let b = self.entry(text(&item["id"]));
                    b.id = call.id;
                    b.name = call.name;
                    b.runs = call.runs;
                }
            }
            Some("response.function_call_arguments.delta")
            | Some("response.custom_tool_call_input.delta")
            | Some("response.mcp_call_arguments.delta") => {
                if let Some(b) = self.calls.get_mut(&text(&event["item_id"])) {
                    b.arguments.push_str(event["delta"].as_str().unwrap_or(""));
                }
            }
            Some("response.output_item.done") => {
                if let Some(call) = responses_item(item) {
                    self.entry(text(&item["id"])).done = Some(call);
                }
            }
            Some("response.completed") => {
                for item in event["response"]["output"].as_array().into_iter().flatten() {
                    if let Some(call) = responses_item(item) {
                        self.entry(text(&item["id"])).done = Some(call);
                    }
                }
            }
            _ => {}
        }
    }

    fn whole(&mut self, body: &Value) {
        let calls: Vec<ToolCall> = match self.format {
            Format::Anthropic => body["content"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(anthropic_block)
                .collect(),
            Format::OpenAiChat => body["choices"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|c| chat_calls(&c["message"]))
                .collect(),
            Format::OpenAiResponses => body["output"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(responses_item)
                .collect(),
        };
        for (i, call) in calls.into_iter().enumerate() {
            self.entry(format!("whole:{i:06}")).done = Some(call);
        }
    }
}

/// The calls a model request resends, and the ids of the calls whose results it
/// carries. The ids link a call in a reply to its result in a later request.
pub fn calls_in_request(format: Format, body: &[u8]) -> (Vec<ToolCall>, Vec<String>) {
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return (Vec::new(), Vec::new());
    };
    let (mut calls, mut results) = (Vec::new(), Vec::new());
    match format {
        Format::Anthropic => {
            for message in body["messages"].as_array().into_iter().flatten() {
                for block in message["content"].as_array().into_iter().flatten() {
                    calls.extend(anthropic_block(block));
                    if block["type"] == "tool_result" {
                        results.push(text(&block["tool_use_id"]));
                    }
                }
            }
        }
        Format::OpenAiChat => {
            for message in body["messages"].as_array().into_iter().flatten() {
                calls.extend(chat_calls(message));
                if message["role"] == "tool" {
                    results.push(text(&message["tool_call_id"]));
                }
            }
        }
        Format::OpenAiResponses => {
            for item in body["input"].as_array().into_iter().flatten() {
                calls.extend(responses_item(item));
                if matches!(
                    item["type"].as_str(),
                    Some(
                        "function_call_output"
                            | "custom_tool_call_output"
                            | "local_shell_call_output"
                            | "shell_call_output"
                            | "apply_patch_call_output"
                            | "computer_call_output"
                    )
                ) {
                    results.push(text(&item["call_id"]));
                }
            }
        }
    }
    (calls, results)
}

/// The calls that have been asked for and have no result yet. A request the
/// sandbox sends while a call is open is linked to it; with several open, to
/// all of them, since which one sent it cannot be told from the network.
#[derive(Default)]
pub struct Open {
    calls: Vec<ToolCall>,
}

impl Open {
    /// Calls from a reply the runtime is about to receive.
    pub fn asked(&mut self, calls: &[ToolCall]) {
        for call in calls {
            if !self.calls.iter().any(|c| c.id == call.id) {
                self.calls.push(call.clone());
            }
        }
    }

    /// Results going back to the model: those calls are over.
    pub fn answered(&mut self, ids: &[String]) {
        self.calls.retain(|c| !ids.contains(&c.id));
    }

    /// What an outbound request sent now is linked to.
    pub fn link(&self) -> Vec<ToolCall> {
        self.calls.clone()
    }
}

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_owned()
}

fn anthropic_block(block: &Value) -> Option<ToolCall> {
    let (name, runs) = match block["type"].as_str()? {
        "tool_use" => (text(&block["name"]), Runs::Agent),
        "server_tool_use" => (text(&block["name"]), Runs::Provider),
        "mcp_tool_use" => (
            format!(
                "mcp:{}/{}",
                text(&block["server_name"]),
                text(&block["name"])
            ),
            Runs::Provider,
        ),
        _ => return None,
    };
    Some(ToolCall {
        id: text(&block["id"]),
        name,
        arguments: match &block["input"] {
            Value::Object(input) if input.is_empty() => String::new(),
            input => input.to_string(),
        },
        runs,
    })
}

fn chat_calls(message: &Value) -> Vec<ToolCall> {
    message["tool_calls"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|call| ToolCall {
            id: text(&call["id"]),
            name: text(&call["function"]["name"]),
            arguments: text(&call["function"]["arguments"]),
            runs: Runs::Agent,
        })
        .collect()
}

/// A field of a Responses item, as JSON text.
fn field(item: &Value, key: &str) -> String {
    Value::Object(Map::from_iter([(key.into(), item[key].clone())])).to_string()
}

fn responses_item(item: &Value) -> Option<ToolCall> {
    let id = match item["call_id"].as_str() {
        Some(id) => id.to_owned(),
        None => text(&item["id"]),
    };
    let call = |name: String, arguments: String, runs: Runs| {
        Some(ToolCall {
            id: id.clone(),
            name,
            arguments,
            runs,
        })
    };
    let mcp = |what: &str| {
        format!(
            "{what}:{}/{}",
            text(&item["server_label"]),
            text(&item["name"])
        )
    };
    match item["type"].as_str()? {
        // Run by the agent's runtime.
        "function_call" => call(text(&item["name"]), text(&item["arguments"]), Runs::Agent),
        "custom_tool_call" => call(text(&item["name"]), text(&item["input"]), Runs::Agent),
        "local_shell_call" => call("local_shell".into(), field(item, "action"), Runs::Agent),
        "shell_call" => call("shell".into(), field(item, "action"), Runs::Agent),
        "apply_patch_call" => call("apply_patch".into(), field(item, "operation"), Runs::Agent),
        "computer_call" => call("computer".into(), field(item, "action"), Runs::Agent),
        // Run by the provider.
        "mcp_call" => call(mcp("mcp"), text(&item["arguments"]), Runs::Provider),
        "mcp_approval_request" => call(
            mcp("mcp_approval"),
            text(&item["arguments"]),
            Runs::Provider,
        ),
        "web_search_call" => call("web_search".into(), field(item, "action"), Runs::Provider),
        "code_interpreter_call" => call(
            "code_interpreter".into(),
            field(item, "code"),
            Runs::Provider,
        ),
        "file_search_call" => call("file_search".into(), field(item, "queries"), Runs::Provider),
        "image_generation_call" => call("image_generation".into(), String::new(), Runs::Provider),
        _ => None,
    }
}
