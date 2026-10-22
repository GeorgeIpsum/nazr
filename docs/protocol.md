# Wire protocol

The nazr API is wire-compatible with the stock ThumbmarkJS client (v1.12.0) and with the fork in [`packages/thumbmark`](../packages/thumbmark/README.md). This document describes every public route. Signals and scoring are in [signals.md](signals.md); environment variables are in [configuration.md](configuration.md).

All error responses share one shape:

```json
{"error": "origin_not_allowed", "message": "origin not allowed for this API key"}
```

Every response carries an `X-Request-Id` header (a ULID). On `/thumbmark` the same value is returned as `requestId` and stored as the event ID.

## Routes

| Method and path | Auth | Success | Purpose |
|---|---|---|---|
| `POST /thumbmark` | `x-api-key` | 200 | Compute a fingerprint, classify, resolve the visitor |
| `OPTIONS /thumbmark`, `/beacon`, `/log` | none | 204 | CORS preflight |
| `POST /beacon` | none, rate limited per IP | 204 | Record a (JA4, UA family) observation |
| `POST /log` | none, rate limited per IP | 204 | Client debug log (stored only if `NAZR_LOG_RETENTION` is set) |
| `GET /healthz` | none | 200 `ok` | Process is alive |
| `GET /readyz` | none | 200 JSON | Store reachable; list status |
| `GET /admin/keys` | admin token | 200 | List keys |
| `POST /admin/keys` | admin token | 201 | Create a key |
| `DELETE /admin/keys/{id}` | admin token | 204 | Revoke a key |
| `GET /demo/*` | none | 200 | Static demo, only when `NAZR_DEMO_DIR` is set |
| `GET /` | none | 200 | Plain-text banner with the version |
| `GET /metrics` | none | 200 | Prometheus; served on `NAZR_METRICS_ADDR` (default `127.0.0.1:9090`), not the public listener |

A path or method that is not in this table, including the wrong method on a known path (for example `GET /thumbmark`), returns a JSON 404: `{"error":"not_found","message":"not found"}`.

## `POST /thumbmark`

Request headers (normal mode): `x-api-key: <key>`, `Authorization: custom-authorized`, `Content-Type: application/json`. In `simple_request` mode the client sends `Content-Type: text/plain` and no custom headers, and the operator's proxy injects `x-api-key`. The server accepts `application/json`, `text/plain`, or no `Content-Type`; anything else is 400.

Request body (see [`apps/api/testdata/requests/stock-client-body.json`](../apps/api/testdata/requests/stock-client-body.json) for a full one):

```json
{
  "components": { "audio": {}, "canvas": {}, "...": {} },
  "options": {},
  "clientHash": "<murmur128 hex>",
  "version": "1.12.0",
  "path": "/page",
  "visitorId": "<ulid>",
  "metadata": {}
}
```

`components` is required and must be an object. `options` (client options without the API key) selects which components the server hashes. `visitorId`, `path`, `clientHash` and `metadata` are optional. `metadata` is echoed back only when its stringified length is at most 1000 UTF-16 code units; otherwise it is dropped silently.

### Example

Captured from a local `plain` mode server with no list sources loaded (`NAZR_LISTS_DISABLE` covering every source), a key restricted to `https://example.com`, and the stock client body:

```bash
curl -si -X POST http://127.0.0.1:18080/thumbmark \
  -H "x-api-key: $KEY" \
  -H 'Origin: https://example.com' \
  -H 'Authorization: custom-authorized' \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh) Chrome/130' \
  -H 'Accept-Language: en-US' \
  --data @apps/api/testdata/requests/stock-client-body.json
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Content-Type: application/json
Vary: Origin
X-Request-Id: 01M5J6QG9G9MX939VCQPRHFD3D
```

```json
{
  "thumbmark": "d23387a19642f11a9c62d69b1474241a",
  "components": {
    "header": {
      "accept": "*/*",
      "acceptLanguage": { "q": { "en-US": 1 }, "raw": "en-US" },
      "ja4h": "po11nn09enus_4b194e84c1fa",
      "order": ["host", "accept", "x-api-key", "origin", "authorization", "content-type", "user-agent", "accept-language", "content-length"],
      "userAgent": "Mozilla/5.0 (Macintosh) Chrome/130"
    },
    "ip": {
      "address": "127.0.0.1", "version": "v4", "asn": 0, "as_org": "",
      "country": "", "region": "", "city": "",
      "tor": false, "vpn": false, "datacenter": false, "private_relay": false
    }
  },
  "info": {
    "ip_address": {
      "ip_address": "127.0.0.1",
      "ip_identifier": "b5b8a91f317cf77a",
      "autonomous_system_number": 0,
      "ip_version": "v4"
    },
    "classification": {
      "tor": false, "vpn": false, "bot": false, "datacenter": false,
      "private_relay": false, "danger_level": 0
    },
    "uniqueness": { "score": 1, "visitors_sharing": 1, "visitors_total": 1 },
    "visitor": {
      "id": "01M5J6QG9ZRXG7KFE55GTVZ6J3",
      "isNew": true,
      "firstSeen": "2026-10-22T16:22:25Z",
      "lastSeen": "2026-10-22T16:22:25Z"
    },
    "signals": {
      "datacenter": false, "datacenter_browser_ua": false, "h2_automation": false,
      "headless_ua": false, "missing_accept_language": false, "private_relay": false,
      "timezone_country_mismatch": false, "tor_exit": false, "ua_tls_mismatch": false,
      "vpn": false, "webdriver": false
    }
  },
  "visitorId": "01M5J6QG9ZRXG7KFE55GTVZ6J3",
  "requestId": "01M5J6QG9G9MX939VCQPRHFD3D",
  "version": "dev"
}
```

There is no `info.country` because no geo source was loaded, and no `tls` or `h2` component because `plain` mode has no TLS. With a loaded MaxMind database `info.country` looks like `{"iso_code":"GB","name":"United Kingdom","continent":{"code":"EU","name":"Europe"}}`.

### Response fields

- `thumbmark`: murmur128 hex hash computed by the server over `merge(client components, filter(server components))`. The filter uses the same stabilization rules as the client; browser-specific rules use the client's `components.system.browser`. The client and server therefore agree on the hash.
- `components`: the server-observed components, unfiltered. Keys: `tls`, `h2`, `header`, `ip` (see [signals.md](signals.md)). A key is absent when it could not be observed.
- `components.header.ja4h`: the cookie-free JA4H, `ja4h_a_ja4h_b`. The cookie hashes (`ja4h_c`, `ja4h_d`) change whenever a cookie is set or rotated, so they stay out of the thumbmark. The stable form also normalizes the cookie-present and referer-present flags in `ja4h_a` to `n`, so the thumbmark does not change when a site sets its first cookie or when the referrer differs. The complete four-part JA4H, with the real flags, is stored in `events.ja4h`.
- `info.ip_address` and `info.country` are omitted entirely (not zero-valued) when the address or country is unknown. The stock client tolerates both being absent.
- `info.ip_address.ip_identifier`: first 16 hex characters of `sha256(NAZR_IP_HASH_SALT + address)`, a stable handle for grouping without exposing the address.
- `info.classification`, `info.signals`: see [signals.md](signals.md). `signals` contains every evaluated signal, true or false.
- `info.uniqueness`: share of visitors with this thumbmark, with the counts it is based on.
- `info.visitor`: the resolved visitor. `isNew` is true when no visitor matched within `NAZR_VISITOR_MATCH_WINDOW`.
- `metadata`: echoed from the request when accepted.
- `collect`: present only when the server could not obtain a JA4 for the request and `NAZR_COLLECT_SAMPLE_RATE` sampled it. It is `{"ja4": "", "source": "none"}` and invites the client to send a `/beacon`.

### Status codes and error codes

| Status | `error` | Cause |
|---|---|---|
| 400 | `bad_request` | Body is not a JSON object, `components` missing, unsupported `Content-Type`, or invalid admin request fields |
| 403 | `unauthorized` | `x-api-key` missing, malformed, or unknown (admin routes: wrong token) |
| 403 | `key_revoked` | The key has been revoked |
| 403 | `origin_not_allowed` | `Origin` is not in the key's allowed origins |
| 404 | `not_found` | Unknown path, wrong method on a known path, unknown key ID on revoke, admin routes when `NAZR_ADMIN_TOKEN` is unset |
| 413 | `payload_too_large` | Body exceeds `NAZR_BODY_LIMIT` (default 256 KiB) |
| 429 | `rate_limited` | Per-key (or per-IP for `/beacon`) limit exceeded; `Retry-After` is in seconds |
| 500 | `internal` | Recovered panic |
| 503 | `store_unavailable` | Database unreachable; `Retry-After: 2` |

Example error (same request from `Origin: https://evil.test`):

```http
HTTP/1.1 403 Forbidden
Access-Control-Allow-Origin: *
Content-Type: application/json
X-Request-Id: 01M5J6QGD433NP49SECAYZD7JR

{"error":"origin_not_allowed","message":"origin not allowed for this API key"}
```

## CORS

`OPTIONS` on `/thumbmark`, `/beacon` and `/log` answers 204 with `Access-Control-Allow-Methods: POST, OPTIONS`, `Access-Control-Allow-Headers: content-type, x-api-key, authorization` and `Access-Control-Max-Age: 86400`.

- Preflight cannot carry the key, so it uses the global `NAZR_CORS_ORIGINS` list (default `*`). With a specific list, `Access-Control-Allow-Origin` echoes the request origin when listed, with `Vary: Origin`.
- Real requests get the global `Access-Control-Allow-Origin` first, so errors raised before authentication (403, 413, 429) stay readable by the browser. After authentication, a key with an origin list echoes the request origin.
- `GET /healthz`, `GET /readyz` and `GET /` carry the same global `Access-Control-Allow-Origin`, so a page on another origin (such as the demo's status banner) can read them. They are simple requests and need no preflight.
- Per-key origins (`allowed_origins`) are enforced on the real request, not on the preflight. A key with no origin list accepts any origin (and requests without an `Origin` header at all).

## `POST /beacon`

Body: `{"ua": "", "thumbmark": "", "ja4": "", "ja4_source": ""}`, sent with `sendBeacon` or a no-cors fetch as `text/plain`. The route is unauthenticated because `sendBeacon` cannot set headers, so it is rate limited per client IP at `NAZR_DEFAULT_RATE_LIMIT`.

The server records one `ua_ja4_observations` row: the JA4 is taken from the live connection (terminate mode) or from `NAZR_JA4_HEADER` (proxied mode) when present, otherwise from the body, and the UA family is parsed from `ua`. The row is recorded only when the same client IP made a `/thumbmark` request that produced the body's `thumbmark` within the last 10 minutes; otherwise, and for a malformed body, the beacon is ignored. The answer is 204, or 429 with `Retry-After` when limited.

Because the route is unauthenticated, observations can still be seeded by a client that also calls `/thumbmark`; see the warning in [signals.md](signals.md#ua_tls_mismatch-and-the-ja4-corpus).

## `POST /log`

204, 413 `payload_too_large` for a body over 16 KiB, or 429 `rate_limited` (with `Retry-After`) when the client IP exceeds `NAZR_DEFAULT_RATE_LIMIT` requests per minute, the same per-IP limit as `/beacon`. The body is discarded unless `NAZR_LOG_RETENTION` is set; then a valid JSON body is stored and pruned on that retention. If a valid, unrevoked `x-api-key` accompanies the request, the log is tied to that key; the key is resolved through the same cache as authenticated routes. No authentication is required.

## Connection modes and fingerprint capture

`NAZR_TLS_MODE` decides which fingerprints the server can observe.

| Mode | TLS | Captured | Client IP |
|---|---|---|---|
| `terminate` (default) | Terminated by nazr (inline PEM, files, or ACME) | JA4 from the ClientHello (JA3 hash stored on the event only), HTTP/2 fingerprint, header order for HTTP/2 | Connection address (or PROXY protocol v2 when `NAZR_PROXY_PROTOCOL` is set) |
| `proxied` | Terminated upstream | JA4 read from `NAZR_JA4_HEADER` (default `x-ja4`); HTTP/1.1 header order as the proxy forwards it; no HTTP/2 fingerprint | `NAZR_CLIENT_IP_HEADER` (default `x-forwarded-for`) |
| `plain` | None | HTTP/1.1 header order only | Connection address |

Details and limits:

- `terminate`: the `tls` component is built to be identical on every connection from the same browser. Chromium permutes its TLS extension order per connection, so `tls.extensions` is sorted ascending (JA4 sorts for the same reason) and JA3 / JA3 hash, which hash the wire order, are not part of the component or the response; the JA3 hash is kept in `events.ja3_hash`. TLS session tickets are disabled: a resuming TLS 1.3 ClientHello adds `pre_shared_key` (`0x0029`), which changes the JA4 extension count and hash of every returning browser. The cost is one full handshake per new connection, which is small because browsers reuse a single HTTP/2 connection for all requests to an origin.
- `terminate`: HTTP/1.1 over TLS does not capture header order (Go's HTTP/1 server does not expose it behind `crypto/tls`), so `header.order` is the sorted header set and `ja4h` is computed from sorted header names. HTTP/2 connections keep the real order. Non-TLS bytes arriving on the TLS listener close the connection.
- `proxied`: the client IP is the rightmost address in the header that is not inside `NAZR_TRUSTED_PROXIES`; when every entry is trusted the leftmost is used, and an unparseable entry falls back to the connection address. Headers are trusted regardless of the peer, so the listener must be reachable only through the proxy. Anyone who can connect directly can forge `x-ja4` and the client IP.
- `plain` and `proxied`: header order is captured for every HTTP/1.1 request head on a connection, so keep-alive connections a proxy reuses across different end users still give each request its own order. Sniffing stops for the rest of a connection after a chunked request body, a protocol upgrade or a head over 32 KiB; later requests on it fall back to sorted names.
- Header order is per request in every mode. Each HTTP/2 header block is HPACK-decoded (with the connection's dynamic table) and each HTTP/1.1 head is queued; a request takes the queued entry whose method and header names match its own. When nothing matches, `header.order` is the sorted header set and `ja4h` uses sorted names. This keeps `header.order`, `ja4h` and so the thumbmark the same whether or not a CORS preflight opened the connection first.
- Server timeouts bound slow clients: `ReadHeaderTimeout` 10s, `ReadTimeout` 30s, `WriteTimeout` 30s, `IdleTimeout` 120s, 64 KiB of headers. They are what stops slowloris-style connections, which would otherwise hold the lazy ClientHello capture open.
- `NAZR_HTTP_ADDR` is used only in `terminate` mode: it serves ACME HTTP-01 challenges and answers everything else with a 308 redirect to HTTPS. Set it to `off` to run without it.
- Signals: `SIGHUP` reloads file-based certificates (`NAZR_TLS_CERT_FILE` and `NAZR_TLS_KEY_FILE`), which are also re-read every 12 hours; a failed reload keeps the previous certificate. In every other configuration `SIGHUP` is ignored. `SIGINT` and `SIGTERM` drain connections for up to 15 seconds.

## Operational routes

`GET /healthz` returns `ok` while the process is up.

`GET /readyz` returns 200 whenever the database answers a ping, regardless of the state of any list source, and 503 (`"store": "error"`) otherwise. It does not check that migrations are current. The answer is computed at most once per second and reused in between. A source's `last_error` is its first line only, with the `NAZR_DATA_DIR` prefix shown as `<data>`. Sources are reported, not gating:

```json
{
  "version": "dev",
  "tls_mode": "plain",
  "store": "ok",
  "sources": {
    "tor": { "loaded": false, "rows": 0, "fetched_at": null, "last_error": "disabled" }
  }
}
```

Each source also reports `last_modified` and `interval` when known. An enabled but not-yet-fetched source shows `loaded: false`.

## Admin API

Requires `Authorization: Bearer <NAZR_ADMIN_TOKEN>`. When the token is unset the routes return 404; a wrong token returns 403 `unauthorized`.

| Request | Response |
|---|---|
| `GET /admin/keys` | 200, array of keys (never secrets) |
| `POST /admin/keys` body `{"label": "site", "allowed_origins": ["https://example.com"], "rate_limit_per_minute": 120}` | 201, key object including `key`, the plaintext, shown once. `label` is required. Each `allowed_origins` entry must be `*` or `scheme://host[:port]` (the host may start with `*.`); anything else is a 400 `bad_request` naming the entry |
| `DELETE /admin/keys/{id}` | 204, or 404 `not_found` |

Revocation takes effect within the key-cache TTL (60 seconds), because the cache is keyed by key hash and is not invalidated on revoke. The same operations are available offline as `nazr keys create|list|revoke`.

## Client setup

Stock ThumbmarkJS client:

```ts
import { Thumbmark } from "@thumbmarkjs/thumbmarkjs";

const tm = new Thumbmark({
  api_key: "nzr_...",
  api_endpoint: "https://nazr.example.com",
  logging: false,
});
const result = await tm.get();
```

`api_endpoint` must be origin-only for the stock client: a path is used verbatim as the thumbmark URL. Keep `logging: false` so the client does not post debug logs.

Fork (`@nazr/thumbmark`, see its [README](../packages/thumbmark/README.md)):

```ts
import { Thumbmark } from "@nazr/thumbmark";

const tm = new Thumbmark({
  api_key: "nzr_...",
  api_endpoint: "https://nazr.example.com",
  logging: false,
});
```

The fork derives `/thumbmark`, `/log` and `/beacon` from `api_endpoint`. Set `simple_request: true` instead of `api_key` when a reverse proxy injects the `x-api-key` header: the client then sends `Content-Type: text/plain` with no custom headers, which avoids a CORS preflight.

## Deviations from the design spec

The implementation is the source of truth where it differs from section 4 of the spec:

- `info.ip_address` and `info.country` are omitted, not zero-valued, when unknown.
- `components` in the response are the unfiltered server set. The spec's wording that the client filters them still holds, but the server hashes with `components.system.browser` from the client request, since the server components carry no browser identity.
- The error code set is larger than the spec lists: `unauthorized`, `key_revoked`, `origin_not_allowed`, `payload_too_large`, `rate_limited`, `store_unavailable`, `internal`, `not_found`, `bad_request`. 503 carries `Retry-After: 2`; 429 carries `Retry-After` in seconds.
- `/beacon` and `/log` answer 204 for malformed bodies rather than rejecting them; both can answer 429, and `/log` answers 413 over 16 KiB.
- `/readyz` does not check migration currency (spec 4.5 says "migrations current").
- Wrong method on a known path returns the JSON 404 rather than 405.
- `collect.source` is `none` (there is no JA4 to report); `header` is never emitted.
- Preflight uses the global `NAZR_CORS_ORIGINS` for every key; the spec's "request Origin when the key allows it" applies only to real requests.
- The `tls` component has no `ja3` / `ja3_hash` and its `extensions` list is sorted (the spec lists both JA3 fields and wire-order extensions). Chromium permutes the extension order per connection, so either would change the thumbmark between connections; the JA3 hash is stored in `events.ja3_hash` instead.
