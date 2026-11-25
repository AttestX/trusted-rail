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
  broker/alpaca.json          Alpaca orders (stocks, crypto in USD), cancels, closes
  exchange/binance.json       Binance spot orders in USDT and USDC (USD on Binance.US), cancels
  exchange/hyperliquid.json   Hyperliquid perpetual orders in USDC, cancels
  crypto/evm.json             signed EVM transactions, on any RPC host
  payments/stripe.json        Stripe transfers, payouts, refunds
  payments/x402.json          x402 version 2 payments, on any host
  payments/x402-v1.json       x402 version 1, refused
  security/model-requests.json  model requests that would have a provider call a third party
```

| Category | ISIC Rev.5 | Built | Next | Actions |
|---|---|---|---|---|
| `crypto` | 6619 | `evm` | Solana, Bitcoin; custodian signing (Privy, Turnkey, CDP); signed orders and permits (Permit2, CoW Swap, 0x) | `token.transfer`, `token.approve`, `contract.call`, `sign.typed_data` |
| `exchange` | 6611, 6612 | `binance` (spot), `hyperliquid` (perpetuals); sensitive hosts (futures, testnets, WebSocket APIs, Coinbase, Kraken, Bybit, OKX) | OKX, Bybit, Coinbase, Kraken; Binance futures | `order.place`, `order.cancel`; withdrawals as `token.transfer` |
| `broker` | 6612 | `alpaca`; sensitive hosts (Alpaca Broker API, Tradier, tastytrade, Schwab, IBKR, Robinhood) | IBKR, Tradier | `order.place`, `order.cancel`, `position.close`; cash out as `payment` |
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
| `input` | `form` (the body's fields and the query's together; a field given twice, in either or across both, is refused) or `json` (a body, on `hosts`; reads pass unread), `header_json` (base64 JSON in `header`, on any host), `jsonrpc_raw_transaction` (a signed EVM transaction in a call named in `methods`, on any host; `refuse_methods` are refused outright) |
| `functions` | Function signatures, so `"as": "function"` can name a selector |
| `unmatched` | `refuse` (the default) or `pass`: what a covered request no action matches becomes |
| `tables` | Name → (key → value), for `"as": "lookup"`: names an API gives by number |
| `actions` | Tried in order; the first whose `when` holds decides |

Each action reads a document: `{"request": {"method", "host", "path", "segments", "query"}, "input": ...}`.
`segments` is the path split at `/` (`/v2/positions/NVDA` → `["v2", "positions", "NVDA"]`), so a
name in the path can be a parameter (`/request/segments/2`). A `json` request without a body
reads as `{}`. A field that is absent reads as `null`, so `[null]` in `is` or `in` matches it.
For a transaction, `input` is `{"method", "chain_id", "from", "to", "value", "data", "selector"}`
(`from` is the sender recovered from the signature; a signature that recovers none is refused), plus
`args` once `when.function` matches.

| Field | Meaning |
|---|---|
| `when` | `method`, `path` (`*` is one segment), `function` (a canonical signature, such as `transfer(address,uint256)`; any ABI argument types, read as JSON: addresses and bytes in lower-case hex, numbers as decimal text, lists as arrays), `fields` (`[{at, is, case}]` or `[{at, matches}]`, a regular expression). All must hold |
| `refuse` | Refuse what matches, for this reason. Or: |
| `pass` | `true`: let what matches through as an ordinary request, as for a query sent by `POST`. Or: |
| `operation`, `resource` | The action, and which of its parameters is the resource |
| `require` | `[{at, in, case, reason}]`, `[{at, matches, reason}]` (text that matches the regular expression, whole; at most 256 characters, linear-time, ASCII) or `[{same: [a, b], case, reason}]`: refused with `reason` unless it holds |
| `parameters` | Name → source. A source is one of `at` (a JSON pointer), `first` (the first pointer with a value) or `const`, with an optional `default`, and `as` |

`as` reads the value: `text` (the default), `lower`, `count` (a positive whole number),
`lookup` (the value's text in the adapter's table named `table`; refused if absent),
`micro` (millionths, from whole or decimal text in units of `decimals` or of the `token`'s,
rounded up), `token_symbol` (from `token` alone), `chain_name`, `native_symbol`, `function`.
`times` (a pointer, `micro` only) multiplies by the decimal there, as a quantity times a price,
rounding the product up. `or_zero` allows zero for `count` and `micro`. A value that is missing or cannot be read refuses
the request; nothing is guessed.

## `broker/alpaca.json`

[Alpaca's Trading API](https://docs.alpaca.markets/reference/postorder), live
(`api.alpaca.markets`) and paper (`paper-api.alpaca.markets`): US stocks and crypto. Every order
is typed as `order.place` on its symbol (lower case), with `side`, `order_type`, `venue` (the host,
so a mandate can tell paper from live) and `amount_micro`, its value in millionths of a US dollar:

| Order | `amount_micro` |
|---|---|
| `market` by `notional` | the notional |
| `limit` or `stop_limit` by `qty` | `qty` × `limit_price`, rounded up; also `quantity_micro` and `limit_price_micro` |
| `market`, `stop` or `trailing_stop` by `qty` | none: refused, since no price in the request bounds it. A position is closed with the close call instead |

Refused too: bracket, OCO, OTO and multi-leg orders (several orders in one request); options
symbols, asset ids, and crypto pairs not quoted in USD (their amounts are not in dollars);
replacing an order (`PATCH`: cancel and place a new one); exercising an option (it pays the
strike, which the request does not state); account settings (margin, shorting, options level);
withdrawal addresses. `DELETE /v2/orders[/{id}]` is `order.cancel` and `DELETE
/v2/positions[/{symbol}]` is `position.close` (`all` for every one). Any other write, watchlists
among them, is refused; reads pass. Alpaca's Broker API, which can move money out, has no adapter,
so its writes are refused as a sensitive host.

## `exchange/hyperliquid.json`

Hyperliquid's API on mainnet (`api.hyperliquid.xyz`), perpetuals. An `order` action with one
order becomes `order.place` on the perpetual its asset number names (table `perps`, from the
exchange's `meta`; its numbers only ever grow, delisted ones included), with `side`,
`amount_micro` = price × size in USDC, `quantity_micro`, `limit_price_micro` and `account` (the
`vaultAddress`, or `main`). Every Hyperliquid order has a limit price, market orders included
(they are IOC limits), so the value is always stated. Refused: several orders in one request
(each must be decided), take-profit and stop-loss groupings, a builder fee (it pays a third
party), a market trigger order, a TWAP, spot assets (numbers from 10000, not in the table),
modifying an order, leverage and margin changes, moving funds out, and account control (agents,
builder fees, sub-accounts, multi-sig). `cancel`, `cancelByCloid` and `scheduleCancel` are
`order.cancel`; `POST /info` (reads) passes. Testnet numbers its assets differently, so it is a
sensitive host with no adapter. To regenerate the table:
`curl -s -X POST https://api.hyperliquid.xyz/info -d '{"type":"meta"}'`, index → lower-case name.

## `exchange/binance.json`

Binance spot (`api.binance.com` and its alternates) and Binance.US. Binance reads a field from
the query or the body (the query's when both), so both are read and a field given twice is
refused. `POST /api/v3/order` becomes `order.place` with its value in its quote asset: a market
order's `quoteOrderQty`, or `quantity` × `price` for a limit, limit-maker, stop-loss-limit or
take-profit-limit order. Only USDT and USDC pairs are typed (`currency` `usdt` or `usdc`), and
USD pairs on Binance.US (`usd`). Refused: an order whose value is not stated (market by
quantity, stop-loss or take-profit at market), pegged and trailing orders, other quote assets,
OCO, OTO and OTOCO lists and routed orders, replacing or amending an order, withdrawals and every
other `/sapi` write. Cancels (`DELETE /api/v3/order`, `/openOrders`, `/orderList`) are
`order.cancel`; test orders and user data streams pass. Futures (`fapi`, `dapi`, `papi`) and the
WebSocket API are sensitive hosts, refused.

## WebSockets

A WebSocket is a channel, not a request: what is sent over it never passes as a request the
mandate could decide, and exchanges take orders over them (Binance's WebSocket API,
Hyperliquid's `post`). So a WebSocket upgrade to a sensitive host, or to a host an adapter
covers, is refused. Market data streams are on other hosts (`stream.binance.com`) and pass.

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
