# Turnstile-style widget, Phase 1: OOPIF collection and correlation

Date: 2026-10-30
Status: approved for planning
Parent spec: [2026-10-21-nazr-design.md](2026-10-21-nazr-design.md)
Sibling (later): Phase 2 — managed challenge and verifiable token (not yet specced)

## 1. Purpose

A nazr-hosted widget, embedded cross-origin on a consumer's site inside a
closed shadow root, that computes a fingerprint in an isolated,
out-of-process context and reports it to nazr. Because the host page's
JavaScript cannot reach into the widget, and because the widget's report is a
direct browser-to-nazr connection, the widget yields signals the host page
cannot forge or suppress, plus a second, independent capture of the visitor's
TLS/HTTP2/IP from a different browsing context.

A host-supplied nonce ties the widget's report to the same visit's
`POST /thumbmark` call, letting nazr compare the two contexts (same IP? same
JA4 family? same user-agent family?). Divergence is a tamper/proxying signal.

This is Phase 1 of a two-phase feature. Phase 1 delivers isolated collection
and cross-context correlation only. The managed challenge, the signed
verification token, and the siteverify endpoint are Phase 2 and are out of
scope here (section 2).

## 2. Non-goals (Phase 1)

- No challenge (no proof-of-work, no interactive step). The widget collects
  and reports; it does not gate anything.
- No token issuance, no siteverify endpoint, no public-key/JWKS endpoint.
  All deferred to Phase 2.
- No nazr-issued nonce. The nonce is host-generated and opaque to nazr in
  Phase 1; Phase 2 layers a nazr-issued challenge id with expiry/replay
  control on top.
- No live classification scoring of the cross-context verdict on the page's
  `/thumbmark` response. The verdict is computed and stored, and returned on
  the widget report and via an admin lookup; wiring it into the danger score
  is a later opt-in (mirrors the canvas-probe `NAZR_CANVAS_PROBE_SCORING`
  staging) and is out of scope for Phase 1.

## 3. Components and flow

```
Host page (consumer origin)                     nazr origin
  <script src=".../widget/v1/loader.js"            GET /widget/v1/loader.js   (static, embedded)
          data-api-key data-nonce?>                GET /widget/v1/frame       (static HTML, embedded)
    loader.js:                                     POST /widget/report        (same-origin from the iframe)
      - resolve nonce (data-nonce or generate)
      - attachShadow({mode:"closed"})
      - inject <iframe src=".../widget/v1/frame?k=&n=">   ── cross-origin to host, same-origin to nazr
                                                   iframe (nazr origin):
                                                     - @nazr/thumbmark local fingerprint
                                                     - POST /widget/report {api_key, nonce, components, clientHash}
  host also calls POST /thumbmark with the same nonce (new optional top-level `nonce` field)
```

### 3.1 Loader (`packages/widget`, served as `/widget/v1/loader.js`)

- Reads its own `data-api-key` (required) and `data-nonce` (optional) from the
  `<script>` tag. If `data-nonce` is absent, the loader generates a
  cryptographically random nonce (`crypto.randomUUID()`), so a host that does
  not manage nonces still works.
- Exposes the resolved nonce to the host for use on its `/thumbmark` call:
  `window.__nazrWidget = { nonce: "<value>" }` and resolves
  `window.__nazrWidget.ready` (a Promise) with `{ nonce }`. Wrapped in
  try/catch; never throws into the host page.
- Creates a container element, attaches a **closed** shadow root
  (`attachShadow({ mode: "closed" })`), and injects an `<iframe>` whose `src`
  is nazr's `/widget/v1/frame?k=<api_key>&n=<nonce>`. The closed root keeps
  the host page from reaching the iframe through DOM traversal.
- The loader is versioned in its path (`/widget/v1/`) so the wire contract can
  evolve without breaking embeds.

### 3.2 Frame (`packages/widget`, served as `/widget/v1/frame`)

- HTML served by nazr from its own origin, bundling the frame script and
  `@nazr/thumbmark`.
- Reads `k` (api key) and `n` (nonce) from its own URL.
- Computes the **full** `@nazr/thumbmark` component set locally (reusing the
  client; the full set so the cross-context comparison is apples-to-apples
  with the page thumbmark). No API-key-gated call from inside `get()`; the
  frame posts its own report.
- `POST /widget/report` (same-origin) with JSON `{ api_key, nonce,
  components, clientHash }`. Fire-and-forget; a failure never surfaces to the
  host page.

### 3.3 Report endpoint (`POST /widget/report`)

- Authenticated by `api_key` (public, as with `/thumbmark`); origin scoping is
  not enforced because the request is same-origin to nazr (the browser sends
  no cross-origin `Origin`), so the key's `allowed_origins` is not applied
  here — documented explicitly.
- Validates: `api_key` resolves to a live key; `nonce` is a bounded string
  (1..64 chars, printable ASCII); `components` is an object; `clientHash` is
  bounded hex. Malformed → 204 and dropped (never a 400; a widget must never
  break the host page), except an invalid key → 403 like `/thumbmark`.
- Captures the widget's own connection signals with the same machinery as
  `/thumbmark`: `s.clientIP(r)` and the server components (`tls`, `h2`,
  `header`, `ip`). The widget's server-side thumbmark is computed over the
  same merge/filter and stored for analysis, but the Phase 1 consistency
  verdict (section 5) is connection-based (IP, JA4 family, UA family), not a
  thumbmark-equality check: the iframe and the top page legitimately differ
  on some components (for example clientrects), so equal thumbmarks are not
  expected across contexts.
- Stores a `widget_reports` row (section 4) and runs the correlation
  (section 5).
- Responds `204`, or `200` with the correlation verdict when the matching
  page event is already present.

### 3.4 Nonce on `/thumbmark`

- `POST /thumbmark` gains an optional top-level `nonce` field (sibling of
  `canvas_probe`/`clientHash`, never in `components`, never in the thumbmark).
  Bounded the same as the widget's nonce. Stored on the event (section 4).
- The client (`@nazr/thumbmark`) gains an optional `nonce?: string` option,
  attached to the request body exactly like the `canvas_probe` precedent
  (top-level, omitted from the echoed `options`).

## 4. Storage (new migration `00002_widget.sql`)

Because the canvas-probe spec declared the migration collapse a one-time
pre-release cleanup and NOT a pattern, Phase 1 adds a normal new migration.

- `events.nonce text` (nullable) + index `events_nonce_idx` on
  `(api_key_id, nonce, created_at)` — supports the correlation lookup.
- Table `widget_reports`:
  - `id` (ULID char(26) PK), `api_key_id` uuid FK, `nonce` text,
    `created_at` timestamptz.
  - `thumbmark` text, `client_hash` text (the widget's own).
  - `ja4` text, `h2fp` text, `ip_hash` text, `user_agent` text (the widget
    connection's observed signals).
  - `matched_event_id` char(26) NULL, and `ip_match`, `ja4_match`,
    `ua_match` boolean NULL (the correlation verdict; NULL until a matching
    page event is found).
  - Index on `(api_key_id, nonce, created_at)`.
- `NAZR_STORE_IP` and the existing IP-hashing apply to `ip_hash` exactly as
  for events.

## 5. Correlation and the consistency verdict

- At widget-report time, look up the most recent `events` row with the same
  `(api_key_id, nonce)` within a bounded window (reuse the beacon's
  `beaconEventWindow` style constant, e.g. 10 minutes). The page `/thumbmark`
  and the widget report are independent and either may arrive first; the
  verdict is computed whenever the report arrives and a page event already
  exists. If no page event is found yet, the verdict columns stay NULL.
- The verdict compares the widget's observed connection against the page
  event's: `ip_match` (same `ip_hash`), `ja4_match` (same JA4 family, via
  `classify.TLSFamily`), `ua_match` (same `ua.Family`). Record each on the
  `widget_reports` row with `matched_event_id`.
- The verdict is returned in the report response when available, and is
  readable per key via an admin endpoint `GET /admin/keys/{id}/widget` that
  summarises recent reports: counts of matched/unmatched and of each mismatch
  kind over a window (shape mirrors the canvas-probe entropy report).
- Phase 1 does NOT feed this into the live danger score (section 2); the
  stored verdict is the deliverable.

## 6. Serving the widget assets

- `packages/widget` is a new workspace package built with the repo's tooling
  (esbuild/rollup + Biome), producing `loader.js`, `frame.html`, and the
  frame bundle. It depends on `@nazr/thumbmark` (workspace).
- The Go binary embeds the built assets with `go:embed` and serves them under
  `/widget/v1/`, so one self-hostable binary ships the widget. A
  `NAZR_WIDGET_DIR` override (mirroring `NAZR_DEMO_DIR`) serves from disk for
  development. When the assets are absent (not built), the routes return 404
  and the rest of the server is unaffected.
- The loader and frame set `Cache-Control` suitable for versioned,
  long-lived static assets; the frame sets `X-Frame-Options`/CSP so it may be
  framed by any origin (it is meant to be embedded) while its own scripts are
  locked down.

## 7. Security and privacy

- The widget key is public (as `/thumbmark`'s). The report is same-origin to
  nazr, so CORS/origin-scoping does not gate it; a forged report can only
  attribute a fabricated widget fingerprint to a nonce the attacker chose,
  which the correlation then flags as a mismatch against the real page event
  (or stays unmatched). Document this clearly.
- The nonce is opaque and bounded; it is not a secret in Phase 1 and must not
  be treated as one (that is Phase 2's token). A guessed nonce lets an
  attacker submit a widget report that may correlate; this is acceptable in
  Phase 1 because the verdict is advisory and not yet scored. Note it as a
  Phase 2 hardening (nazr-issued, single-use challenge id).
- The closed shadow root resists host-page inspection but is not a security
  boundary against a hostile host (the host embeds the widget willingly). The
  threat model is a hostile or compromised *page script* / end-user tampering,
  not a hostile operator.
- All queries are parameterized and scoped by `api_key_id`.

## 8. Affected files

- New package `packages/widget/` (loader, frame, build config, tests).
- `packages/thumbmark/src/options.ts` + request builder — optional `nonce`.
- `apps/api/internal/server/` — `widget.go` (report handler), route
  registration, embedded-asset serving (extend `static.go`), `thumbmark.go`
  (parse/store `nonce`), admin widget summary in `admin.go`.
- `apps/api/internal/store/` — `widget.go` (insert report, correlation
  lookup, admin summary), `events.go` (nonce column).
- `apps/api/migrations/00002_widget.sql`.
- `apps/api/internal/config/config.go` — `NAZR_WIDGET_DIR`.
- Docs: `docs/protocol.md` (the three widget routes + the `nonce` field),
  `docs/configuration.md` (`NAZR_WIDGET_DIR`), a new `docs/widget.md`
  (embedding guide), `README.md` (one line + link).

## 9. Review focus (inputs no happy-path test exercises)

- **Report with a nonce that has no page event (yet).** Stored; verdict
  columns NULL; no error.
- **Page event and widget report in either arrival order.** The verdict is
  computed when the report arrives; if the report arrives first, the verdict
  stays NULL (Phase 1 does not back-fill on later page events — document this
  limitation).
- **Malformed report body / oversized nonce / missing components.** 204 and
  dropped, never a 400; invalid key → 403.
- **Widget loaded where `crypto.randomUUID` is unavailable or the shadow
  root/iframe injection throws.** The loader must never throw into the host
  page; it degrades to doing nothing.
- **Same nonce reused across many reports.** Bounded: the correlation matches
  the most recent page event; duplicate reports are stored but do not corrupt
  the summary counts (counts are over rows, documented).
- **Stock `/thumbmark` caller with no `nonce`.** Unchanged; `events.nonce`
  NULL.

## 10. Backward compatibility

- `events.nonce` is additive and nullable; the new migration is additive.
- The `/thumbmark` `nonce` field is optional; existing clients are unaffected
  and the thumbmark is unchanged (nonce never enters the hash).
- The widget routes 404 when assets are not embedded/served, so a build
  without the widget package behaves exactly as today.
