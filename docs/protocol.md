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
| `POST /admin/keys/{id}/secret` | admin token | 200 | Replace a key's siteverify secret; the new one is returned once |
| `GET /widget/v1/loader.js` | none | 200 | Widget loader script; only when the widget assets are present |
| `GET /widget/v1/frame?k=` | key in `k` | 200 | Widget frame document with a fresh challenge; 403 for an unknown or revoked key, 503 `store_unavailable` when the key store is unreachable, 503 `signing_unavailable` when there is no signing key; only when the assets are present |
| `GET /widget/v1/frame.<hash>.js` | none | 200 | Content-hashed frame bundle; only when the assets are present |
| `GET /widget/v1/worker.<hash>.js` | none | 200 | Content-hashed proof-of-work worker bundle; only when the assets are present |
| `POST /widget/report` | `x-api-key` | 200 | Verify the challenge and proof-of-work, store the frame's report, answer `{verdict, token?, interactive?}` |
| `POST /widget/interact` | `x-api-key` | 200 | Verify the interactive-stage challenge and proof-of-work, score the interaction trace, answer `{verdict, token?}` |
| `GET /widget/v1/jwks.json` | none | 200 | Public signing keys (JWKS) |
| `POST /widget/v1/siteverify` | key secret in the body | 200 | Verify and spend a widget token |
| `GET /admin/keys/{id}/widget` | admin token | 200 | Widget correlation summary for a key |
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
  "metadata": {},
  "canvas_probe": "<hex, optional>",
  "nonce": "<1-64 printable ASCII, optional>"
}
```

`components` is required and must be an object. `options` (client options without the API key) selects which components the server hashes. `visitorId`, `path`, `clientHash` and `metadata` are optional. `metadata` is echoed back only when its stringified length is at most 1000 UTF-16 code units; otherwise it is dropped silently.

`canvas_probe` is an optional top-level field, a sibling of `clientHash` and `path`, never inside `components`. It is a hex string of up to 64 bytes: the hash of the consumer's canvas-probe routine (see the [client README](../packages/thumbmark/README.md#canvas-probe)). It is never part of the thumbmark, and a malformed value is silently ignored (the request is not rejected with a 400). See [signals.md](signals.md#consumer-canvas-probe-and-the-entropy-report).

`nonce` is an optional top-level string of 1 to 64 printable ASCII characters that ties this call to a widget report from the same visit (see [Widget](#widget)). It is stored on the event, never enters `components` or the thumbmark, and is not echoed in the response. An invalid value is treated as absent.

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

## Widget

The widget is a loader plus a hidden cross-origin frame that reports to nazr; the embedding guide is [widget.md](widget.md). The `GET /widget/v1/` asset routes (loader, frame, bundles) exist only when the widget assets are embedded or served from `NAZR_WIDGET_DIR`; otherwise they return the JSON 404. `POST /widget/report`, `POST /widget/interact`, `GET /widget/v1/jwks.json` and `POST /widget/v1/siteverify` are always registered.

### `POST /widget/report`

Sent by the frame, same-origin to nazr, with the key in `x-api-key`:

```json
{ "challenge": "<payload.mac, 1-512 chars>", "pow": "<1-32 decimal digits>", "components": {}, "clientHash": "<1-64 hex, optional>" }
```

```json
{ "verdict": "pass", "token": "<compact ES256 JWS>" }
```

- `verdict` is `pass`, `inconclusive`, `pow_failed` or `invalid`. `token` is present only on `pass`. The meaning of each verdict is in [widget.md](widget.md#token-lifecycle).
- `interactive` is optional and appears only on an `inconclusive` verdict: `{"challenge": "<payload.mac>", "bits": 22, "ttl_ms": 541000}`. `ttl_ms` is how many milliseconds the challenge has left by nazr's clock when the report is answered (never negative); the frame times the box out from it rather than comparing `exp` with its own clock. It is present when `NAZR_WIDGET_INTERACTIVE` is on and the classification is not a bot (a danger level above `NAZR_WIDGET_PASS_MAX_DANGER` alone qualifies). `challenge` is a second challenge for the same id with `stage: "interactive"`, at `NAZR_POW_BITS + NAZR_WIDGET_INTERACTIVE_EXTRA_BITS` bits. Hosts that do not use the step ignore it.
- Authentication, revocation, the per-key rate limit and the key touch work as for `/thumbmark`, so errors from those (403, 429) are returned as usual. Reports share the key's `rate_limit_per_minute` with `/thumbmark`.
- The key's `allowed_origins` check is skipped on this route: the browser sends nazr's own origin, which is never in a key's list. Origin scoping is enforced on the frame document by `frame-ancestors` instead. `allowed_origins` itself is unchanged.
- After authentication the answer is always `200` JSON. A malformed body, a challenge that fails its MAC, key or expiry check, a challenge minted for another API key, or an already reported challenge is `{"verdict":"invalid"}`, never a 400, so the widget cannot break the host page.
- A challenge can be reported once. The report row is keyed by the challenge id, which is also its `nonce`, so the Phase 1 correlation with `/thumbmark` events carrying that nonce still applies.
- The server adds its own components (`tls`, `h2`, `header`, `ip`) and stores a row with a server-computed `thumbmark`, filtered with the frame client's default stabilization (`private`, `iframe`). It is an analysis value; no visitor is created or touched.
- When the database rejects the insert for any other reason, a would-be `pass` is answered `inconclusive` with no token.
- Rows are pruned under `NAZR_EVENT_RETENTION`. The raw IP and the merged components are stored under `NAZR_STORE_IP` and `NAZR_STORE_COMPONENTS`.

### `POST /widget/interact`

Sent by the frame after the click-to-verify step, same-origin to nazr, with the key in `x-api-key`:

```json
{
  "challenge": "<interactive challenge, 1-512 chars>",
  "pow": "<1-32 decimal digits>",
  "trace": {
    "shown_ms": 640, "click_ms": 2480, "input": "pointer", "trusted": true,
    "moves": 14, "path_px": 212.5, "straightness": 0.71, "pointer_type": "mouse", "visible": true
  }
}
```

```json
{ "verdict": "interactive", "token": "<compact ES256 JWS>" }
```

- `verdict` is `interactive` (with `token`), `interactive_failed` or `invalid`. Only `interactive` carries a token; its `verdict` claim is `interactive`.
- Checks run in this order and the first failure answers `invalid`: authentication and rate limit as for the report; the body (challenge 1 to 512 characters, `pow` 1 to 32 digits, `trace` an object whose fields are inside the bounds below); the challenge's MAC, key and expiry, `stage` equal to `interactive`, and `key` (when present) equal to the authenticating key's id; the proof-of-work at the challenge's `bits`. Then the trace is scored: any non-advisory rule that fired is `interactive_failed`, otherwise `interactive`.
- Trace bounds: `shown_ms` and `click_ms` 0 to 2^31; `moves` 0 to 200; `path_px` finite, 0 to 1,000,000; `straightness` finite, 0 to 1; `input` is `pointer` or `keyboard`; `pointer_type` is `mouse`, `touch`, `pen` or empty; strings at most 16 characters. Unknown trace keys are ignored.
- The upgrade is a conditional update of the stored report, which must still be `inconclusive` with no token issued, so a challenge is redeemed once. A second call, a challenge for a report that never existed, or one already upgraded is `invalid`. A failed attempt is final for that challenge.
- The rules and thresholds are in [signals.md](signals.md#interaction-rules). The stored report keeps the trace fields, the rules that fired and `elapsed_ms`.
- Like `/widget/report`, the answer after authentication is always `200` JSON.

### `GET /widget/v1/frame`

Query: `k` is the API key. The former `n` parameter is ignored. An unknown, malformed, missing or revoked key gets `403` with an empty body. When the key store is unreachable the answer is `503` `store_unavailable` (JSON error, `Retry-After: 2`); with no signing key loaded it is `503` `signing_unavailable` (`Retry-After: 2`). Otherwise the response is HTML carrying a new challenge as `data-challenge` (with `data-pow-bits`, `data-origin` and `data-worker`) on the bundle's script tag, and:

```http
Content-Security-Policy: frame-ancestors <allowed_origins or *>; default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'
Cache-Control: no-store
```

`frame-ancestors` lists the key's `allowed_origins` entry by entry (wildcard hosts such as `https://*.example.com` are valid syntax), or `*` when the key has no list or contains `*`. There is no `X-Frame-Options`, which has no allow-all value.

The challenge is `<payload>.<mac>`, both base64url without padding. The payload is JSON `{"id","exp","bits","kid","origin","key"}` plus an optional `stage`: a ULID, a Unix expiry 10 minutes out, the proof-of-work difficulty, the signing key id, the embedding origin from the `Referer` and the id of the API key in `k`. `stage` is absent on the frame's first challenge and `interactive` on the second one, which keeps the same id, `exp`, `kid`, `origin` and `key`. The report and interact routes answer `invalid` when `key` differs from the authenticating key; a challenge without `key` (minted before it was added) is accepted for its 10-minute window. The MAC is HMAC-SHA256 over the encoded payload under the signing key's secret.

### `GET /widget/v1/jwks.json`

Public, with the global CORS headers and `Cache-Control: public, max-age=3600`. It lists the active signing key, a key rotated in that has not started signing yet (published for one hour first) and any key retired within the last 24 hours:

```json
{ "keys": [ { "kty": "EC", "crv": "P-256", "kid": "<kid>", "use": "sig", "alg": "ES256", "x": "<base64url>", "y": "<base64url>" } ] }
```

Tokens are compact ES256 JWS with header `{"alg":"ES256","kid":"<kid>","typ":"JWT"}` and payload:

```json
{ "iss": "https://nazr.example.com", "aud": "<api key id>", "jti": "<challenge id>", "iat": 1790000000, "exp": 1790000300, "hostname": "https://example.com", "verdict": "pass" }
```

`verdict` is `pass`, or `interactive` for a token earned through `POST /widget/interact`.

### `POST /widget/v1/siteverify`

Called by the host's backend. No `x-api-key` and no CORS; the key's verify secret in the body authenticates it. `Content-Type` must be `application/json`.

```json
{ "secret": "nzs_...", "token": "<jws>", "remoteip": "203.0.113.7" }
```

`secret` and `token` are required; `remoteip` is optional. A body that is not a JSON object with both, or a different `Content-Type`, is 400 `bad_request`; an oversized body is 413 `payload_too_large`.

```json
{
  "success": true,
  "challenge_ts": "2026-10-30T12:00:00Z",
  "hostname": "https://example.com",
  "verdict": "pass",
  "correlation": { "matched": true, "ip_match": true, "ja4_match": true, "ua_match": true },
  "classification": { "tor": false, "vpn": false, "bot": false, "datacenter": false, "private_relay": false, "danger_level": 0 },
  "signals": {},
  "error_codes": []
}
```

- On success all fields are present, except `correlation`, which is absent when nazr could not compute it after spending the token. `hostname` is `""` when nazr did not observe the embedding origin, and `signals` is `{}` when empty. `challenge_ts` is the issue time in RFC 3339 UTC. `correlation.ip_match`, `ja4_match` and `ua_match` are `null` when `matched` is false or the comparison is unknown (for example no JA4 on either side).
- `verdict` is `pass` or `interactive`. For a token earned through the interactive step the response also carries `interaction`, an object with `input`, `pointer_type`, `trusted`, `moves`, `path_px`, `straightness`, `elapsed_ms` and `signals` (only the interaction rules that fired, `{}` when none did; a passing token can carry `{"straight_path": true}`, which is advisory). It is absent for a `pass` token and for failures, and present with `remoteip-mismatch`.
- A failure is `{"success": false, "error_codes": ["<code>"]}` with no other field, except `remoteip-mismatch`, which keeps every field of the success response and sets `success` to false. The token is spent in that case too.

| Status | `error_codes` | Meaning |
|---|---|---|
| 401 | `invalid-secret` | Unknown secret, or the secret's key is revoked |
| 200 | `invalid-token` | Malformed token, `alg` other than ES256, unknown `kid`, bad signature, `aud` not equal to the secret's key id, or no stored report for the `jti` |
| 200 | `token-expired` | `exp` has passed. Checked before the token is spent |
| 200 | `replayed` | The token was already verified |
| 200 | `remoteip-mismatch` | `remoteip` differs from the frame's request IP (the raw address under `NAZR_STORE_IP=raw`, the salted identifier under `hash`) |
| 429 | none | `rate_limited` error with `Retry-After`; siteverify shares the key's rate-limit bucket |
| 503 | none | `store_unavailable`: a store failure before the token is spent. A retry with the same token works |

### Cache policy

| Asset | `Cache-Control` |
|---|---|
| `loader.js` | `public, max-age=300`, with an `ETag` (fixed path, so fixes reach embeds within minutes) |
| `frame.<hash>.js`, `worker.<hash>.js` | `public, max-age=31536000, immutable` (content-hashed name) |
| `jwks.json` | `public, max-age=3600` |
| `frame` | `no-store` |

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
| `GET /admin/keys` | 200, array of keys. Each has `secret_prefix`, the first 8 characters of the siteverify secret (empty for a key created before Phase 2a); never the secret or key themselves |
| `POST /admin/keys` body `{"label": "site", "allowed_origins": ["https://example.com"], "rate_limit_per_minute": 120}` | 201, key object including `key`, the plaintext, shown once. `label` is required. Each `allowed_origins` entry must be `*` or `scheme://host[:port]` (the host may start with `*.` and may not contain `;`, `,` or `'`, which would split the widget frame's `frame-ancestors` list); anything else is a 400 `bad_request` naming the entry. The object also includes `secret` (`nzs_...`), the key's siteverify secret, shown once, and `secret_prefix` |
| `POST /admin/keys/{id}/secret` | 200 `{"id": "<id>", "secret": "nzs_..."}`: a new siteverify secret, shown once. The old one stops working immediately. 404 `not_found` for an unknown id |
| `DELETE /admin/keys/{id}` | 204, or 404 `not_found` |

`GET /admin/keys/{id}/widget` summarises the widget reports of a key over the last 30 days. An unknown key simply has no reports.

```json
{
  "window_days": 30,
  "reports": 1200,
  "matched": 1100,
  "unmatched": 100,
  "events_unmatched": 40,
  "ip_mismatch": 3,
  "ja4_mismatch": 1,
  "ja4_unknown": 0,
  "ua_mismatch": 2,
  "pass": 900,
  "inconclusive": 150,
  "pow_failed": 50,
  "verified": 700,
  "replayed": 12,
  "interactive": 30,
  "interactive_failed": 8,
  "interaction_signals": { "untrusted_event": 5, "too_fast": 3 }
}
```

Counts are over report rows, except `events_unmatched`. A report is matched when the key has a `/thumbmark` event with the same `nonce` within 10 minutes of it, in either direction (the most recent one is used). `unmatched` counts widget reports with no page call carrying the same nonce (stock client, cached call, or a forged report). `events_unmatched` counts the key's `/thumbmark` events in the window that carry a nonce but have no widget report with that nonce within 10 minutes (the iframe was blocked or never ran, or the caller never loaded the page). Among matched reports, `ip_mismatch` is a differing IP hash, `ja4_mismatch` a differing raw JA4 string, `ja4_unknown` a pair where either side has no JA4 (such as `plain` mode), and `ua_mismatch` a differing raw `User-Agent`. The correlation verdict is computed on read and does not feed the danger score. `pass`, `inconclusive` and `pow_failed` count report rows by the verdict stored at report time (`invalid` reports are never stored). `interactive` and `interactive_failed` count reports upgraded by `POST /widget/interact` to that verdict; an upgraded report is no longer counted in `inconclusive`. `interaction_signals` counts, over the `interactive_failed` reports, how often each [interaction rule](signals.md#interaction-rules) fired (a report can count under several); it is always present and `{}` when there are none. `verified` counts tokens spent at siteverify and `replayed` counts reports whose token was presented again after being spent. `allowed_origins` is unchanged: it still scopes `/thumbmark` and the widget frame. What it does and does not detect is in [widget.md](widget.md#what-the-summary-shows).

Revocation takes effect within the key-cache TTL (60 seconds), because the cache is keyed by key hash and is not invalidated on revoke. The same operations are available offline as `nazr keys create|list|revoke|secret-rotate`, and `nazr signing rotate|list` manages the widget signing keys.

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
