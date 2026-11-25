# Action definitions

What an observed request becomes, for the mandate. One file per API; `common.json` holds what
they share. They are loaded with `Adapters::builtin()` (compiled in) or `Adapters::from_dir`, and
a definition that does not check out is refused when it is loaded. Adding an API is a JSON file
here, an entry in `BUILTIN` (`src/lib.rs`) if it ships built in, and a test.

## `common.json`

| Field | Meaning |
|---|---|
| `money_hosts` | Hosts that can move money. A write to one that no adapter types is refused. An adapter's own `hosts` count too |
| `chains` | `{id, name, native}`: chain ids as mandates name them, and each chain's native token |
| `tokens` | `{chain, address, symbol, decimals}`: tokens whose amounts can be put in millionths |

## An adapter

| Field | Meaning |
|---|---|
| `id` | Letters, digits and dashes; prefixes every refusal it gives |
| `input` | `form` or `json` (a body, on `hosts`; reads pass unread), `header_json` (base64 JSON in `header`, on any host), `jsonrpc_raw_transaction` (a signed EVM transaction in a call named in `methods`, on any host; `refuse_methods` are refused outright) |
| `functions` | Function signatures, so `"as": "function"` can name a selector |
| `unmatched` | `refuse` (the default) or `pass`: what a covered request no action matches becomes |
| `actions` | Tried in order; the first whose `when` holds decides |

Each action reads a document: `{"request": {"method", "host", "path", "query"}, "input": ...}`.
For a transaction, `input` is `{"method", "chain_id", "to", "value", "data", "selector"}`, plus
`args` once `when.function` matches.

| Field | Meaning |
|---|---|
| `when` | `method`, `path` (`*` is one segment), `function` (a signature with static argument types), `fields` (`[{at, is, case}]`). All must hold |
| `refuse` | Refuse what matches, for this reason. Or: |
| `operation`, `resource` | The action, and which of its parameters is the resource |
| `require` | `[{at, in, case, reason}]` or `[{same: [a, b], case, reason}]`: refused with `reason` unless it holds |
| `parameters` | Name → source. A source is one of `at` (a JSON pointer), `first` (the first pointer with a value) or `const`, with an optional `default`, and `as` |

`as` reads the value: `text` (the default), `lower`, `count` (a positive whole number),
`micro` (millionths, from whole or decimal text in units of `decimals` or of the `token`'s,
rounded up), `token_symbol` (from `token` alone), `chain_name`, `native_symbol`, `function`.
`or_zero` allows zero for `count` and `micro`. A value that is missing or cannot be read refuses
the request; nothing is guessed.

## `model-requests.json`

Some tools a model provider runs itself, from its own servers: a remote MCP server or connector
the request names, a hosted shell or environment with network access, a stored agent or prompt
that carries them. Gateways do the same (LiteLLM, Portkey). Those calls never pass the proxy, so
they cannot be decided. Code in the sandbox that holds a model key can ask for them. These rules
refuse the model requests that ask. Our runtimes never send those fields.

| Field | Meaning |
|---|---|
| `model_hosts` | Hosts that serve model APIs (`*.` at the start for any subdomain). A write to one must be to an `endpoints` entry, with a readable JSON object body: not compressed, not over 8 MiB |
| `endpoints` | `{method, suffix}`: model endpoints, matched by the end of the path, since gateways keep the paths. A write to one on any host is a model request |
| `shapes` | Lists of pointers. A body with every pointer of one list is a model request, whatever its host and path |
| `refuse` | `[{present, reason}]` (a pointer, `*` for any array item or member, with a value), `[{at, is, case, reason}]`, or `[{header, contains, reason}]` (any header of that name, without case). Applied to every model request; header rules to every request |

A JSON key given twice in a model request is refused, since providers may read it differently.
