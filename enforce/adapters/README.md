# Action definitions

What an observed request becomes, for the mandate. They are grouped by industry: one folder per
category, one file per API in the folder of its category, and `common.json` for what they share.
They are loaded with `Adapters::builtin()` (compiled in) or `Adapters::from_dir`, and a
definition that does not check out, or sits in another category's folder, is refused when it is
loaded. Adding an API is a JSON file in its category's folder, an entry in `BUILTIN`
(`src/lib.rs`) if it ships built in, and a test.

```
adapters/
  common.json                 categories, sensitive hosts by category, chains, tokens
  crypto/evm.json             signed EVM transactions, on any RPC host
  payments/stripe.json        Stripe transfers, payouts, refunds
  payments/x402.json          x402 version 2 payments, on any host
  payments/x402-v1.json       x402 version 1, refused
  security/model-requests.json  model requests that would have a provider call a third party
```

| Category | ISIC Rev.5 | Built | Next | Actions |
|---|---|---|---|---|
| `crypto` | 6619 | `evm` | Solana, Bitcoin; custodian signing (Privy, Turnkey, CDP); signed orders and permits (Permit2, CoW Swap, 0x) | `token.transfer`, `token.approve`, `contract.call`, `sign.typed_data` |
| `exchange` | 6611, 6612 | Sensitive hosts only: unadapted writes refused | Hyperliquid, Binance, OKX, Bybit, Coinbase, Kraken | `order.place`; withdrawals as `token.transfer` |
| `broker` | 6612 | None | Alpaca, then IBKR, Tradier | `order.place`; cash out as `payment` |
| `bank` | 641 | Sensitive hosts only (Wise) | Plaid Transfer, Modern Treasury, open banking | `payment` |
| `payments` | 6619 | `stripe`, `x402`, `x402-v1`; sensitive hosts (PayPal, Square, Adyen) | PayPal, Square, Adyen; card authorization | `payment`, `refund`, `x402.pay`, `card.spend` |
| `commerce` | 47, 4790, 5232, 5540, 79 | None | Payment-provider checkout hosts; Shopify, Amazon SP-API, Duffel | `purchase`, `store.change` |
| `ads` | 7310 | None | Google Ads, Meta Ads | `ad.budget` |
| `content` | 58, 59, 60 | None | X, YouTube, WordPress | `content.publish` |
| `comms` | 61 | None | Email and SMS APIs (SendGrid, Twilio) | `message.send` |
| `cloud` | 6310 | None | AWS, GCP, Hetzner, domain registrars | `resource.create` |
| `security` | none | `model-requests` | Account control and persistent channels, refused in every category | refusals |

A category with nothing built still gets a decision: its writes are ordinary `http.request`
actions, which a mandate's host and tool limits apply to, unless its hosts are listed as
sensitive, when they are refused.

## `common.json`

| Field | Meaning |
|---|---|
| `categories` | Category id → `{name, isic}`: what kind of service an adapter or host is, and the nearest [ISIC Rev.5](https://unstats.un.org/unsd/classifications/Econ/isic) codes (the UN industry classification), so others can map ours. The ids are shared with ClawUp's mandate templates |
| `sensitive_hosts` | Category → hosts that can move money or act for the owner. A write to one that no adapter types is refused, naming the category. An adapter's own `hosts` count too, in its category |
| `chains` | `{id, name, native}`: chain ids as mandates name them, and each chain's native token |
| `tokens` | `{chain, address, symbol, decimals}`: tokens whose amounts can be put in millionths |

The categories: `crypto` (on-chain), `exchange` (crypto exchanges), `broker`, `bank`,
`payments`, `commerce`, `ads`, `content`, `comms`, `cloud`, and `security` for what applies to
every category. ISIC has no class for crypto-assets or payment processing, so `crypto` and
`payments` take the nearest, 6619 (other activities auxiliary to financial services);
`security` has none.

## An adapter

| Field | Meaning |
|---|---|
| `id` | Letters, digits and dashes; prefixes every refusal it gives |
| `category` | One of `common.json`'s categories |
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

## `security/model-requests.json`

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
