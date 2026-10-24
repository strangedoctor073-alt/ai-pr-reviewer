# Telemetry ingestion and the cost estimate (V4-E11)

Two small, deliberately limited features. Both are **display only**.

## `POST /api/telemetry` — LAN scope only

Accepts one run's telemetry row and stores it through the dashboard's existing
telemetry storage (the same `telemetry` table the metrics view already reads).

```http
POST /api/telemetry
X-Dashboard-Token: <your dashboard token>
Content-Type: application/json

{"review_id": "owner/repo#123@<sha>", "telemetry": { ...one run's row... }}
```

| Result | Meaning |
|---|---|
| `200 {"ok": true, "id": ...}` | stored (re-posting the same `review_id` replaces it) |
| `400` | not JSON / not an object / malformed `review_id` / `telemetry` not an object |
| `401` | missing or wrong `X-Dashboard-Token` |
| `413` | body over 64 KiB (enforced for chunked bodies too) |
| `429` | per-IP write rate limit |
| `501` | the configured storage backend cannot store telemetry |

What the server does to every payload: it keeps only the approved telemetry
fields (provider, model, batch count, token usage, per-call durations, typed
events, cost estimate), type-checks and bounds them, strips control characters,
neutralizes prompt fences, and redacts secrets. Anything else in the payload
(diffs, prompts, file paths, unknown fields, unapproved event types) is dropped.
The response and the audit log never echo payload content.

### Scope — read this before exposing it

* **LAN / trusted-network only.** Authentication is the same single shared
  `X-Dashboard-Token` every other dashboard write uses.
* There is **no network-grade authentication**: no per-client identity, no
  request signing, no replay protection, no TLS termination in the app. That is
  deferred to V5 (ships publicly as v4.5.0) and must not be assumed.
* Do not expose this route, or the dashboard, to an untrusted network.
* The token holder *asserts* token counts, durations and the cost estimate. The
  server can bound and sanitize them but cannot verify them.
* Engine side: the engine's `DashboardStorageClient` pushes a run's row
  through this route when a dashboard is configured (V4-E11-T06, debt 15 —
  `save_telemetry` + `CAP_TELEMETRY`, best-effort with a logged warning on
  failure, so telemetry stays drop-safe). The engine has no telemetry
  *read* path by design; dashboard scripts can still feed the route
  directly.

## The cost estimate

Every telemetry row now carries a `cost` block:

```json
{"state": "estimated", "currency": "USD", "low": 0.0089, "high": 0.0121, "display_only": true}
```

`state` is one of `estimated`, `unpriced` (usage was reported but no price is
configured for that model), `unavailable` (provider reported no usage) or `n/a`
(no provider call, e.g. the static engine). It is a *band* because price tables
drift. A mixed run under-counts (only reported tokens are priced).

**It never influences routing.** There is no cost- or latency-based provider
selection, ordering, retry or failover in V4 (V4 threat model §6). A test
(`tests/test_telemetry.py`, "review gate") fails the build if any routing module
ever consumes the price or latency API.

### Supplying prices

No prices and no model ids ship in the source; you provide the table for the
models you actually configure, through `AI_PR_REVIEWER_PRICE_TABLE` (JSON, USD
per million tokens). Keys match the reported model exactly, or by a trailing `*`
prefix (longest prefix wins):

```bash
export AI_PR_REVIEWER_PRICE_TABLE='{
  "your-model-id":    {"input_per_mtok": 1.00, "output_per_mtok": 2.00},
  "your-family-*":    {"input_per_mtok": 0.50, "output_per_mtok": 1.50, "band_pct": 25}
}'
```

The numbers above are placeholders to show the shape, not real prices. A
missing, malformed or oversized value yields `unpriced`, never an error: cost
display can never fail a review. `band_pct` (default 15) is an uncalibrated
proposal. If any model in a run has no price the whole estimate is `unpriced`
rather than a misleading partial sum.
