# Turnstile-style widget, Phase 1: isolated cross-origin collection and correlation

Date: 2026-10-30 (revised 2026-10-30 after review; see section 11)
Status: approved for planning
Parent spec: [2026-10-21-nazr-design.md](2026-10-21-nazr-design.md)
Sibling (later): Phase 2 — managed challenge and verifiable token (not yet specced)

## 1. Purpose

A nazr-hosted widget, embedded cross-origin on a consumer's site inside a
closed shadow root, that computes a fingerprint in an isolated browsing
context and reports it to nazr. Because the host page's JavaScript cannot
reach into a cross-origin iframe, and because the widget's report is a direct
browser-to-nazr connection, the widget yields signals the host page cannot
forge or suppress, plus a second, independent capture of the visitor's
TLS/HTTP2/IP from a different browsing context.

The isolation guarantee is the cross-origin boundary. Chromium additionally
puts the frame out of process (OOPIF); Firefox does with Fission; Safari does
not. Nothing here depends on the process split.

A host-supplied nonce ties the widget's report to the same visit's
`POST /thumbmark` call, letting nazr compare the two contexts (same IP? same
JA4? same user-agent family?). Divergence is a replay/proxying signal.

This is Phase 1 of a two-phase feature. Phase 1 delivers isolated collection,
cross-context correlation on connection signals, and the data needed to
design a component-level comparison. The managed challenge, the signed
verification token, and the siteverify endpoint are Phase 2 and are out of
scope here (section 2).

### 1.1 What the Phase 1 verdict does and does not detect

The connection verdict (section 5) compares IP, JA4 and UA family between the
page's `/thumbmark` request and the frame's report. Both requests come from
the same browser when a real page is loaded, so the verdict detects:

- a `/thumbmark` call with a given nonce that has **no** widget report (the
  caller never ran the page, or blocked the iframe);
- a page call routed through a different IP or TLS stack than the frame's
  (replay of a captured body from a script, or a proxied page call).

It does **not** detect in-page JavaScript tampering that spoofs navigator,
screen or WebGL values: that page call still shares the browser's IP, JA4 and
UA with the frame. Detecting that needs a comparison of components that must
be equal across the two contexts, and that subset is not known yet (the
iframe legitimately differs on `clientrects`, viewport-sized values,
`permissions` under Permissions-Policy, and storage access when third-party
storage is blocked). Phase 1 therefore stores the frame's components
(section 4) so the stable subset can be measured on real traffic; the
component comparison itself is a later phase.

## 2. Non-goals (Phase 1)

- No challenge (no proof-of-work, no interactive step). The widget collects
  and reports; it does not gate anything.
- No token issuance, no siteverify endpoint, no public-key/JWKS endpoint.
  All deferred to Phase 2.
- No nazr-issued nonce. The nonce is host-generated and opaque to nazr in
  Phase 1; Phase 2 layers a nazr-issued challenge id with expiry/replay
  control on top.
- No component-level cross-context comparison (section 1.1).
- No live classification scoring of the cross-context verdict on the page's
  `/thumbmark` response. The verdict is readable via an admin lookup; wiring
  it into the danger score is a later opt-in (mirrors the canvas-probe
  `NAZR_CANVAS_PROBE_SCORING` staging) and is out of scope for Phase 1.

## 3. Components and flow

```
Host page (consumer origin)                     nazr origin
  <script src=".../widget/v1/loader.js"            GET /widget/v1/loader.js       (static, embedded)
          data-api-key data-nonce?>                GET /widget/v1/frame?k=&n=     (dynamic: key lookup, CSP)
    loader.js:                                     GET /widget/v1/frame.<hash>.js (static, immutable)
      - resolve nonce (data-nonce or generate)     POST /widget/report            (same-origin from the iframe)
      - attachShadow({mode:"closed"})
      - inject <iframe src=".../widget/v1/frame?k=&n=">   ── cross-origin to host, same-origin to nazr
                                                   iframe (nazr origin):
                                                     - @nazr/thumbmark local fingerprint
                                                     - POST /widget/report, x-api-key header,
                                                       body {nonce, components, clientHash}
  host also calls POST /thumbmark with the same nonce (new optional top-level `nonce` field)
```

### 3.1 Loader (`packages/widget`, served as `/widget/v1/loader.js`)

- Reads its own `data-api-key` (required) and `data-nonce` (optional) from
  `document.currentScript`, synchronously at top level (it is `null` for
  module scripts and inside callbacks, so the loader is a classic script and
  bails out silently when it is `null`). If `data-nonce` is absent, the loader
  generates a cryptographically random nonce (`crypto.randomUUID()`), so a
  host that does not manage nonces still works.
- Exposes the resolved nonce to the host for use on its `/thumbmark` call:
  `window.__nazrWidget = { nonce: "<value>" }` and resolves
  `window.__nazrWidget.ready` (a Promise) with `{ nonce }`. Wrapped in
  try/catch; never throws into the host page.
- One widget per page: if `window.__nazrWidget` already exists, a second
  loader tag is a no-op.
- Creates a container element, attaches a **closed** shadow root
  (`attachShadow({ mode: "closed" })`), and injects an `<iframe>` whose `src`
  is nazr's `/widget/v1/frame?k=<api_key>&n=<nonce>`. The closed root keeps
  casual host-page DOM traversal from finding the iframe; the cross-origin
  boundary is what actually isolates the frame's execution (section 7).
- The loader is versioned in its path (`/widget/v1/`) so the wire contract can
  evolve without breaking embeds.

### 3.2 Frame (`packages/widget`, served as `/widget/v1/frame`)

- HTML served by nazr from its own origin. The document is rendered by the Go
  handler (section 6) from an embedded template; it references the frame
  bundle `/widget/v1/frame.<hash>.js`, which bundles the frame script and
  `@nazr/thumbmark`.
- The handler reads `k`, resolves the key, and emits the key's origin scoping
  as `Content-Security-Policy: frame-ancestors ...` (section 6). An unknown or
  revoked key gets a 403 with an empty body, so a misconfigured embed renders
  a blank frame and nothing else.
- The frame script reads `k` and `n` from its own URL and computes the
  **full** `@nazr/thumbmark` component set locally (reusing the client; the
  full set so the stored components can be compared against the page's). No
  API-key-gated call from inside `get()`; the frame posts its own report.
- `POST /widget/report` (same-origin) with `x-api-key: <k>` and JSON body
  `{ nonce, components, clientHash }`. Fire-and-forget; a failure never
  surfaces to the host page.

### 3.3 Report endpoint (`POST /widget/report`)

- Goes through `auth.Middleware` like `/thumbmark`: key format, lookup,
  revocation, per-key rate limit (`rate_limit_per_minute` now covers page
  calls and widget reports together) and key touch all apply unchanged.
- The middleware's **origin check is skipped on this route** (a new
  `auth.Middleware` option). Browsers send `Origin` on same-origin POSTs, so
  the report carries nazr's own origin, which can never be in a key's
  `allowed_origins`. Origin scoping for the widget is enforced at the frame
  GET via `frame-ancestors` instead (section 6); documented explicitly.
- Check order: middleware errors first (403/429 as for `/thumbmark`), then the
  body. Validates: `nonce` is a bounded string (1..64 chars, printable
  ASCII); `components` is an object; `clientHash` is 1..64 hex or absent.
  Any body failure → 204 and dropped, never a 400: a widget must never break
  the host page.
- Captures the widget's own connection signals with the same machinery as
  `/thumbmark`: `s.clientIP(r)` and the server components (`tls`, `h2`,
  `header`, `ip`). The widget's server-side thumbmark is computed over the
  same merge/filter and stored for analysis. It is not expected to equal the
  page thumbmark (section 1.1).
- No visitor resolution: a report never creates or touches a visitor and does
  not count toward `visitor_count`.
- Stores a `widget_reports` row (section 4). Always responds `204`. The
  verdict is computed at read time (section 5), so arrival order between the
  page event and the report does not matter.

### 3.4 Nonce on `/thumbmark`

- `POST /thumbmark` gains an optional top-level `nonce` field (sibling of
  `canvas_probe`/`clientHash`, never in `components`, never in the thumbmark).
  Bounded the same as the widget's nonce; an invalid value is treated as
  absent. Stored on the event (section 4).
- The client (`@nazr/thumbmark`) gains an optional `nonce?: string` option,
  attached to the request body exactly like the `canvas_probe` precedent in
  `src/functions/api.ts` (top-level, omitted from the echoed `options`).
- A stock `@thumbmarkjs/thumbmarkjs` embed has no `nonce` option. It still
  gets the widget report, but its page events can never be correlated. The
  embedding guide says so.

## 4. Storage (new migration `00002_widget.sql`)

Because the canvas-probe spec declared the migration collapse a one-time
pre-release cleanup and NOT a pattern, Phase 1 adds a normal new migration.

- `events.nonce text` (nullable) + partial index `events_nonce_idx` on
  `(api_key_id, nonce, created_at) WHERE nonce IS NOT NULL` — supports the
  correlation join; nearly every event has a NULL nonce.
- Table `widget_reports`:
  - `id` (ULID char(26) PK, the request id), `api_key_id` uuid FK (ON DELETE
    CASCADE), `nonce` text NOT NULL, `created_at` timestamptz NOT NULL.
  - `thumbmark` text, `client_hash` text (the widget's own).
  - `ip` inet NULL (raw only when `NAZR_STORE_IP=raw`, as for events),
    `ip_hash` text (always), `ja4` text, `h2fp` text, `user_agent` text (the
    widget connection's observed signals; `''` when unobserved, as on
    events).
  - `components` jsonb NULL: the merged client + server components, written
    only when `NAZR_STORE_COMPONENTS=true`, exactly as `events.components`.
    This is the Phase 1 analysis input for the cross-context-stable subset
    (section 1.1).
  - Index on `(api_key_id, nonce, created_at)`; index on `(created_at)` for
    retention.
- No verdict columns. The verdict is derived (section 5).
- Retention: `store.Prune` deletes `widget_reports` older than
  `NAZR_EVENT_RETENTION` in the same batched loop as `events`.

## 5. Correlation and the consistency verdict

- The verdict is **computed at read time**, not stored. Storing it at report
  time would race the page event: the frame must be fetched, parsed and run a
  full collection, so a large share of reports would arrive before the page
  event and never get a verdict.
- A report matches the most recent `events` row with the same
  `(api_key_id, nonce)` whose `created_at` is within `widgetMatchWindow`
  (10 minutes, same value as `beaconEventWindow`) of the report's
  `created_at`, in either direction. One SQL query with a lateral join.
- For a matched pair: `ip_match` is `ip_hash` equality; `ja4_match` is **raw
  JA4 string equality** (the same browser talking to the same host produces
  the same JA4; `classify.TLSFamily` is a UA-family collapse and does not
  apply), and is **unknown** when either side has no JA4 (every request in
  `plain` mode); `ua_match` is `ua.Family` equality.
- Admin endpoint `GET /admin/keys/{id}/widget` summarises the key's reports
  over the last `ProbeWindowDays` (reuse the canvas-probe window):

  ```json
  {
    "window_days": 7,
    "reports": 1200,
    "matched": 1100,
    "unmatched": 100,
    "ip_mismatch": 3,
    "ja4_mismatch": 1,
    "ja4_unknown": 0,
    "ua_mismatch": 2
  }
  ```

  Counts are over report rows. A nonce reused across many reports yields
  many rows, each matched independently; this is documented.
- Phase 1 does NOT feed this into the live danger score (section 2); the
  derived verdict and the stored components are the deliverable.

## 6. Serving the widget assets

- `packages/widget` is a new workspace package built with the repo's tooling
  (esbuild/rollup + Biome), producing `loader.js`, the frame HTML template,
  and the content-hashed frame bundle `frame.<hash>.js`. It depends on
  `@nazr/thumbmark` (workspace).
- The Go binary embeds the built assets with `go:embed`. A `NAZR_WIDGET_DIR`
  override (mirroring `NAZR_DEMO_DIR`) serves from disk for development.
  When the assets are absent (not built), the widget routes return 404 and
  the rest of the server is unaffected.
- Routes:
  - `GET /widget/v1/loader.js` — static. `Cache-Control: public,
    max-age=300` with `ETag`, so fixes reach embeds within minutes. The path
    is fixed and unhashed, so it must not be immutable.
  - `GET /widget/v1/frame` — dynamic. Resolves `k` through the key cache,
    403 (empty body) for an unknown or revoked key, otherwise renders the
    template with `Content-Security-Policy: frame-ancestors <list>;
    default-src 'none'; script-src 'self'; connect-src 'self'`. The list is
    the key's `allowed_origins` mapped entry by entry (`https://*.example.com`
    is valid frame-ancestors syntax), or `*` when the key has no list. No
    `X-Frame-Options` (it has no allow-all value). `Cache-Control: no-store`.
  - `GET /widget/v1/frame.<hash>.js` — static, `Cache-Control: public,
    max-age=31536000, immutable`.
  - `POST /widget/report` — section 3.3.

## 7. Security and privacy

- The widget key is public (as `/thumbmark`'s). It appears in the frame URL,
  so it lands in nazr's own access logs and the browser history, the same
  exposure as the `x-api-key` header today.
- A forged report can only attribute a fabricated widget fingerprint to a
  nonce the attacker chose, which the correlation then flags as a mismatch
  against the real page event (or stays unmatched). Document this clearly.
- The nonce is opaque and bounded; it is not a secret in Phase 1 and must not
  be treated as one (that is Phase 2's token). A guessed nonce lets an
  attacker submit a widget report that may correlate; this is acceptable in
  Phase 1 because the verdict is advisory and not yet scored. Note it as a
  Phase 2 hardening (nazr-issued, single-use challenge id).
- The loader runs in the host origin and is not trustworthy: a host-origin
  service worker or an early script can replace it or patch
  `Element.prototype.attachShadow`. The closed shadow root is a convenience
  against casual inspection, not a security boundary. What is trustworthy is
  the frame, whose execution and `POST` the page cannot touch.
- The threat model is a hostile or compromised *page script* / end-user
  tampering, not a hostile operator (the host embeds the widget willingly).
  Within that, Phase 1 covers replay and proxying only; see section 1.1.
- Origin scoping is enforced by `frame-ancestors` on the frame document, not
  on the report (section 3.3).
- All queries are parameterized and scoped by `api_key_id`.

## 8. Affected files

- New package `packages/widget/` (loader, frame template and script, build
  config, tests).
- `packages/thumbmark/src/options.ts` + `src/functions/api.ts` — optional
  `nonce`.
- `apps/api/internal/auth/middleware.go` — option to skip the origin check.
- `apps/api/internal/server/` — `widget.go` (frame handler, report handler,
  asset serving), route registration in `server.go`, `thumbmark.go`
  (parse/store `nonce`), admin widget summary in `admin.go`.
- `apps/api/internal/store/` — `widget.go` (insert report, summary query),
  `events.go` (nonce column), `retention.go` (prune `widget_reports`).
- `apps/api/migrations/00002_widget.sql`.
- `apps/api/internal/config/config.go` — `NAZR_WIDGET_DIR`.
- Docs: `docs/protocol.md` (the widget routes + the `nonce` field),
  `docs/configuration.md` (`NAZR_WIDGET_DIR`, retention and
  `NAZR_STORE_COMPONENTS` now covering reports), a new `docs/widget.md`
  (embedding guide, including the stock-client caveat), `README.md` (one
  line + link).

## 9. Review focus (inputs no happy-path test exercises)

- **Page event and widget report in either arrival order.** The summary
  matches both; a report with no page event within the window counts as
  unmatched.
- **Scoped key.** The frame GET for a key with `allowed_origins` emits a
  matching `frame-ancestors`; a key without a list emits `*`; an unknown or
  revoked key gets 403. The report POST from nazr's own origin is accepted
  for a scoped key.
- **Malformed report body / oversized nonce / missing components.** 204 and
  dropped, never a 400; invalid key → 403 from the middleware before the body
  is read.
- **`plain` mode.** Both sides lack JA4; the summary counts `ja4_unknown`,
  never a mismatch.
- **Widget loaded where `crypto.randomUUID` is unavailable,
  `document.currentScript` is null, or the shadow root/iframe injection
  throws.** The loader must never throw into the host page; it degrades to
  doing nothing. Two loader tags on one page: the second is a no-op.
- **Same nonce reused across many reports.** Each row matches independently;
  counts are over rows.
- **Stock `/thumbmark` caller with no `nonce`.** Unchanged; `events.nonce`
  NULL, no index entry.
- **Retention.** Old `widget_reports` are pruned with events.

## 10. Backward compatibility

- `events.nonce` is additive and nullable; the new migration is additive.
- The `/thumbmark` `nonce` field is optional; existing clients are unaffected
  and the thumbmark is unchanged (nonce never enters the hash).
- The widget routes 404 when assets are not embedded/served, so a build
  without the widget package behaves exactly as today.
- Keys with `rate_limit_per_minute` see widget reports counted against the
  same limit; operators embedding the widget should budget roughly double.

## 11. Revision notes (2026-10-30 review)

- Stated what the connection verdict can and cannot detect (section 1.1);
  added `widget_reports.components` so the component-level rule can be
  designed from data.
- Verdict is derived at read time instead of stored at report time, removing
  the arrival-order limitation. Report always answers 204.
- `ja4_match` is raw JA4 equality with an unknown state; the earlier
  `classify.TLSFamily` reference was wrong (it maps UA families).
- Key moves to the `x-api-key` header so `auth.Middleware` (rate limit, key
  touch) applies; the middleware gains an origin-skip option for this route.
- Origin scoping enforced via `frame-ancestors` on a now-dynamic frame
  route; `X-Frame-Options` dropped.
- Added retention, raw `ip` column parity, partial nonce index, cache policy
  per asset, response/summary shapes, loader edge cases, stock-client caveat.
