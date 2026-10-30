# Widget Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a nazr-hosted, cross-origin widget (loader + iframe) that fingerprints in isolation, reports to nazr with a host nonce, and lets an operator read a per-key correlation summary against the page's `/thumbmark` events.

**Architecture:** A new `packages/widget` builds a tiny loader (IIFE) and a frame bundle (IIFE embedding `@nazr/thumbmark`). The Go binary embeds those assets, serves the loader and bundle as static files, renders the frame HTML per key with a `frame-ancestors` CSP, and accepts `POST /widget/report` through the existing auth middleware with origin checking skipped. Reports land in a new `widget_reports` table; `/thumbmark` stores an optional `nonce`; the verdict is derived at read time by one lateral-join summary query behind an admin route.

**Tech Stack:** TypeScript (esbuild, Vitest, Playwright), Go 1.26 (`nazr/api`, pgx, goose, `embed`, `html/template`), PostgreSQL.

**Spec:** [docs/superpowers/specs/2026-10-30-widget-phase1-design.md](../specs/2026-10-30-widget-phase1-design.md)

## Global Constraints

- The nonce is a top-level request field on `/thumbmark` and the report; it never enters `components`, `Merge`, `StableStringify`, or the thumbmark hash. (spec §3.4, §10)
- Nonce validity: 1..64 chars, printable ASCII (`0x20`..`0x7e`). Invalid → treated as absent on `/thumbmark`; dropped with 204 on the report. (spec §3.3, §3.4)
- `clientHash` on the report: 1..64 hex or absent; anything else → 204 and dropped. (spec §3.3)
- The report route is authenticated by `x-api-key` through `auth.Middleware` with the **origin check skipped**; rate limit and key touch apply. Never a 400 for a body problem. (spec §3.3)
- Frame route: unknown/revoked key → 403, empty body. CSP exactly `frame-ancestors <list>; default-src 'none'; script-src 'self'; connect-src 'self'`, list = key's `allowed_origins` joined by spaces, or `*` when empty. No `X-Frame-Options`. `Cache-Control: no-store`. (spec §6)
- Loader: `Cache-Control: public, max-age=300` + `ETag`. Bundle `frame.<hash>.js`: `Cache-Control: public, max-age=31536000, immutable`. (spec §6)
- Widget routes 404 when no assets are embedded or `NAZR_WIDGET_DIR` is unset; nothing else changes. (spec §6, §10)
- Verdict derived at read time: match window `widgetMatchWindow = 10 * time.Minute` either side of the report; `ip_match` = `ip_hash` equality; `ja4_match` = raw JA4 equality, **unknown** when either side is `''`; `ua_match` = raw `user_agent` equality. Counts are over report rows. (spec §5)
- Summary window: `store.ProbeWindowDays` (30), reported as `window_days`. (spec §5)
- `widget_reports.components` written only when `NAZR_STORE_COMPONENTS=true`; `ip` raw only when `NAZR_STORE_IP=raw`; `ip_hash` always. Reports pruned under `NAZR_EVENT_RETENTION`. (spec §4)
- No visitor resolution for reports. (spec §3.3)
- Loader never throws into the host page; one widget per page. (spec §3.1)
- Migration is a new additive `00002_widget.sql`, not a collapse. (spec §4)
- Commit style `type(scope): subject`; scopes `thumbmark`, `api`, `demo`, `deploy`, `docs`, `ci`. A new scope `widget` is added to CLAUDE.md in Task 10.

## Review Focus

- **Report arrives before its page event, or no page event ever.** Counted `unmatched`, no error, no NULL verdict anywhere; a later page event within the window makes the same row `matched` on the next summary read. (Task 2)
- **Scoped key.** Frame GET emits `frame-ancestors https://a.com`; report POST carrying `Origin: https://nazr.example` for that key is accepted (204), while `/thumbmark` with the same Origin is still 403. (Tasks 3, 7, 8)
- **Hostile report bodies.** Non-object body, missing `components`, 65-char nonce, non-hex `clientHash`, oversized body → all 204 with nothing stored; bad key → 403 before the body is read. (Task 8)
- **Loader degradation.** `document.currentScript` null, `crypto.randomUUID` missing, `attachShadow` throwing, second loader tag → no throw, nothing mounted (or no second mount), host page continues. (Task 6)
- **`plain` mode.** Both sides have `ja4 = ''`; the pair counts in `ja4_unknown`, never `ja4_mismatch`. (Task 2)

---

## Task 1: Schema, event nonce, report insert, retention

**Files:**
- Create: `apps/api/migrations/00002_widget.sql`
- Modify: `apps/api/internal/store/events.go` (`Event.Nonce`, INSERT)
- Create: `apps/api/internal/store/widget.go` (`WidgetReport`, `InsertWidgetReport`)
- Modify: `apps/api/internal/store/retention.go` (prune `widget_reports`)
- Test: `apps/api/internal/store/store_test.go` (`TestMigrateSchema`), `apps/api/internal/store/widget_test.go`

**Interfaces:**
- Produces: `Event.Nonce string` (`""` stores NULL, like `JA3Hash`); `type WidgetReport struct { ID, APIKeyID, Nonce, Thumbmark, ClientHash string; IP *netip.Addr; IPHash, JA4, H2FP, UserAgent string; Components json.RawMessage; CreatedAt time.Time }`; `func (s *Store) InsertWidgetReport(ctx context.Context, r WidgetReport) error`.

- [ ] **Step 1: Write the failing tests.**
  - Extend `TestMigrateSchema`: columns `events.nonce`, `widget_reports.{id,api_key_id,nonce,thumbmark,client_hash,ip,ip_hash,ja4,h2fp,user_agent,components,created_at}` exist; indexes `events_nonce_idx`, `widget_reports_key_nonce_idx`, `widget_reports_created_idx` exist.
  - `widget_test.go` `TestInsertWidgetReportAndPrune` (DB-gated, model on `TestInsertEventAndPrune`): insert three reports aged 100h/50h/1h, the first with `IP`, `Components: []byte(`{"a":1}`)`; `SELECT` back the first and assert `ip`, `components` round-trip and an empty `Components` stored NULL; `Prune(ctx, now-60h, zero, 10)` removes exactly the 100h row and returns 1 (events table empty).
  - In `TestInsertEventAndPrune` add one event with `Nonce: "abc"` and one without; assert `nonce` round-trips and the other is NULL.
- [ ] **Step 2: Run** `cd apps/api && NAZR_TEST_REQUIRE_DB=1 go test ./internal/store -run 'TestMigrateSchema|TestInsertWidgetReportAndPrune|TestInsertEventAndPrune'` → FAIL.
- [ ] **Step 3: Implement.** Migration:

```sql
-- +goose Up
ALTER TABLE events ADD COLUMN nonce text NULL;
CREATE INDEX events_nonce_idx ON events (api_key_id, nonce, created_at) WHERE nonce IS NOT NULL;
CREATE TABLE widget_reports (
    id          char(26) PRIMARY KEY,
    api_key_id  uuid NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
    nonce       text NOT NULL,
    thumbmark   text NOT NULL DEFAULT '',
    client_hash text NOT NULL DEFAULT '',
    ip          inet NULL,
    ip_hash     text NOT NULL DEFAULT '',
    ja4         text NOT NULL DEFAULT '',
    h2fp        text NOT NULL DEFAULT '',
    user_agent  text NOT NULL DEFAULT '',
    components  jsonb NULL,
    created_at  timestamptz NOT NULL
);
CREATE INDEX widget_reports_key_nonce_idx ON widget_reports (api_key_id, nonce, created_at);
CREATE INDEX widget_reports_created_idx ON widget_reports (created_at);
-- +goose Down
DROP TABLE widget_reports;
DROP INDEX events_nonce_idx;
ALTER TABLE events DROP COLUMN nonce;
```

  Add `Nonce` to `Event` and the INSERT (empty → NULL via the same `any` pattern as `ja3`). `InsertWidgetReport` mirrors `InsertEvent` (`nullJSON` for components, `ip` nil unless set). Add `{`DELETE FROM widget_reports WHERE id IN (SELECT id FROM widget_reports WHERE created_at < $1 LIMIT $2)`, eventsBefore}` to the `Prune` loop.
- [ ] **Step 4: Run** the tests → PASS. `NAZR_TEST_REQUIRE_DB=1 go test ./internal/store/...` → green.
- [ ] **Step 5: Commit** `feat(api): widget_reports table, events.nonce, retention`.

## Task 2: Summary query (the derived verdict)

**Files:**
- Modify: `apps/api/internal/store/widget.go`
- Test: `apps/api/internal/store/widget_test.go`

**Interfaces:**
- Consumes: Task 1 types.
- Produces: `type WidgetSummary struct { Reports, Matched, Unmatched, IPMismatch, JA4Mismatch, JA4Unknown, UAMismatch int64 }`; `func (s *Store) WidgetSummary(ctx context.Context, keyID string, since time.Time, window time.Duration) (WidgetSummary, error)`.

- [ ] **Step 1: Write the failing test** `TestWidgetSummary` (DB-gated). Seed one key, a visitor, and these report/event pairs (all `ja4 = "j"`, `ip_hash = "iph"`, `user_agent = "ua"` unless stated), then assert the exact struct:
  - `n1`: event 2 min **before** report → matched, all equal.
  - `n2`: event 2 min **after** report → matched (either order).
  - `n3`: event 11 min before report → unmatched (outside window).
  - `n4`: no event → unmatched.
  - `n5`: event with `ip_hash = "other"` → `IPMismatch`.
  - `n6`: both `ja4 = ""` → `JA4Unknown`, not `JA4Mismatch`.
  - `n7`: event `ja4 = "k"` → `JA4Mismatch`.
  - `n8`: event `user_agent = "curl"` → `UAMismatch`.
  - `n9`: two events for the same nonce, the newer one `ip_hash = "other"` → matches the most recent, so `IPMismatch` counts it.
  - A report older than `since` is excluded from every count; a report under a different key is excluded.
  Expected: `{Reports: 9, Matched: 7, Unmatched: 2, IPMismatch: 2, JA4Mismatch: 1, JA4Unknown: 1, UAMismatch: 1}`.
- [ ] **Step 2: Run** `NAZR_TEST_REQUIRE_DB=1 go test ./internal/store -run TestWidgetSummary` → FAIL.
- [ ] **Step 3: Implement** `WidgetSummary` as a single query: `FROM widget_reports r LEFT JOIN LATERAL (SELECT id, ip_hash, ja4, user_agent FROM events e WHERE e.api_key_id = r.api_key_id AND e.nonce = r.nonce AND e.created_at BETWEEN r.created_at - $3 AND r.created_at + $3 ORDER BY e.created_at DESC LIMIT 1) e ON true WHERE r.api_key_id = $1 AND r.created_at >= $2`, with `count(*)`, `count(e.id)`, and `count(*) FILTER (WHERE ...)` for each mismatch; `ja4_unknown` is `e.id IS NOT NULL AND (r.ja4 = '' OR e.ja4 = '')`, `ja4_mismatch` requires both non-empty. `Unmatched = Reports - Matched`. Pass `window` as a `time.Duration` (pgx encodes it as `interval`).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(api): widget correlation summary query`.

## Task 3: Middleware origin-skip option

**Files:**
- Modify: `apps/api/internal/auth/middleware.go`
- Test: `apps/api/internal/auth/auth_test.go`

**Interfaces:**
- Produces: `type MiddlewareOptions struct { SkipOrigin bool }`; `func MiddlewareOpts(r KeyResolver, l Limiter, defaultRate int, cache *KeyCache, o MiddlewareOptions) func(http.Handler) http.Handler`. `Middleware(...)` becomes `MiddlewareOpts(..., MiddlewareOptions{})`.

- [ ] **Step 1: Write the failing test** `TestMiddlewareSkipOrigin`: key with `AllowedOrigins: ["https://a.com"]`, request `Origin: https://b.com`; `Middleware` → 403 `origin_not_allowed`; `MiddlewareOpts(..., MiddlewareOptions{SkipOrigin: true})` → 200 and the key is in context; a revoked key is still 403 `key_revoked` with `SkipOrigin`.
- [ ] **Step 2: Run** `go test ./internal/auth -run TestMiddlewareSkipOrigin` → FAIL.
- [ ] **Step 3: Implement.** Wrap the `OriginAllowed` check in `if !o.SkipOrigin`. Update the doc comment: scoping for the widget is enforced at the frame.
- [ ] **Step 4: Run** `go test ./internal/auth/...` → PASS.
- [ ] **Step 5: Commit** `feat(api): auth middleware option to skip origin scoping`.

## Task 4: Client `nonce` option

**Files:**
- Modify: `packages/thumbmark/src/options.ts`, `packages/thumbmark/src/functions/api.ts`
- Test: `packages/thumbmark/src/functions/api.test.ts`

**Interfaces:**
- Produces: `OptionsAfterDefaults.nonce?: string`; request body gains top-level `nonce` when set; `nonce` is omitted from the echoed `options`.

- [ ] **Step 1: Write the failing tests** in the existing `describe("request body: ...")` style: with `nonce: "abc-123"` the fetched body has `body.nonce === "abc-123"`, `body.components.nonce === undefined`, `body.options.nonce === undefined`, and `clientHash` equals the no-nonce call's; without the option, `"nonce" in body` is false.
- [ ] **Step 2: Run** `pnpm --filter @nazr/thumbmark exec jest src/functions/api.test.ts -t nonce` → FAIL.
- [ ] **Step 3: Implement.** Add `nonce?: string` to `OptionsAfterDefaults` with a doc comment (correlates with the widget; never in the fingerprint). In `getApiPromise`, destructure `nonce: _omitNonce` out of `optionsForBody` beside `canvas_probe`, and set `requestBody.nonce = options.nonce` when it is a non-empty string, next to `canvas_probe`.
- [ ] **Step 4: Run** `pnpm --filter @nazr/thumbmark exec jest` → green. `pnpm --filter @nazr/thumbmark fixtures` → `git diff --exit-code apps/api/testdata/fixtures` clean (the nonce is not a component).
- [ ] **Step 5: Commit** `feat(thumbmark): nonce option for widget correlation`.

## Task 5: `/thumbmark` stores the nonce

**Files:**
- Create: `apps/api/internal/server/widget.go` (`validNonce` only, for now)
- Modify: `apps/api/internal/server/thumbmark.go`
- Test: `apps/api/internal/server/server_test.go`

**Interfaces:**
- Consumes: `Event.Nonce` (Task 1).
- Produces: `func validNonce(s string) bool` (1..64 bytes, every byte in `0x20..0x7e`); `thumbmarkBody.nonce string`.

- [ ] **Step 1: Write the failing test** `TestThumbmarkNonce` (model on `TestThumbmarkCanvasProbe`): body with `nonce: "n-1"` stores `events[0].Nonce == "n-1"` and returns the same `thumbmark` as the body without it; `nonce: 5`, a 65-char string, and `"a\tb"` each store `""` and return 200; the response JSON has no `nonce` field.
- [ ] **Step 2: Run** `go test ./internal/server -run TestThumbmarkNonce` → FAIL.
- [ ] **Step 3: Implement.** `validNonce` in `widget.go`. In `parseThumbmarkBody`, `if n, _ := raw["nonce"].(string); validNonce(n) { b.nonce = n }`. Set `ev.Nonce = body.nonce`. Nothing touches `components` or `sc`.
- [ ] **Step 4: Run** `go test ./internal/server/...` → PASS.
- [ ] **Step 5: Commit** `feat(api): store the /thumbmark nonce`.

## Task 6: `packages/widget` loader, frame, build

**Files:**
- Create: `packages/widget/package.json`, `tsconfig.json`, `vitest.config.ts`, `README.md`
- Create: `packages/widget/src/loader.ts`, `src/frame.ts`, `src/frame.html`, `src/entries/loader.ts`, `src/entries/frame.ts`
- Create: `packages/widget/scripts/build.mjs`
- Test: `packages/widget/src/loader.test.ts`, `src/frame.test.ts`

**Interfaces:**
- Consumes: `getThumbmark(options)` from `@nazr/thumbmark` returning `ThumbmarkResponse { thumbmark, components, ... }` (`packages/thumbmark/src/functions/index.ts:44`).
- Produces: `mountWidget(doc: Document, win: Window & typeof globalThis): void` in `loader.ts`; `reportFromFrame(deps: { location: Location; fetch: typeof fetch; getThumbmark: typeof getThumbmark }): Promise<void>` in `frame.ts`; build outputs in `packages/widget/dist/`: `loader.js`, `frame.<hash>.js` (hash = first 8 hex of sha256 of the bundle), `frame.html` (contains the literal `{{.Bundle}}` placeholder), `manifest.json` = `{"frame":"frame.<hash>.js"}`. Package scripts: `build` (node scripts/build.mjs), `test` (vitest run), `lint` (biome check .), `typecheck` (tsc --noEmit). Dependencies: `@nazr/thumbmark: workspace:*`; dev: `esbuild`, `vitest`, `jsdom`, `typescript`.

- [ ] **Step 1: Write the failing tests** (Vitest, `environment: "jsdom"`).
  - `loader.test.ts`: helper creates a `<script src="https://nazr.example/widget/v1/loader.js" data-api-key="nzr_x">` and defines `document.currentScript` to it (`Object.defineProperty(document, "currentScript", { value, configurable: true })`). Cases:
    - mounts: `window.__nazrWidget.nonce` matches `/^[0-9a-f-]{36}$/` when `data-nonce` is absent, equals `data-nonce` when present; `ready` resolves to `{ nonce }`.
    - closed root: no `iframe` is reachable via `document.querySelector("iframe")`; the host element's `shadowRoot` is `null`.
    - iframe src: captured via a spy on `Element.prototype.attachShadow` returning a real root; `src === "https://nazr.example/widget/v1/frame?k=nzr_x&n=<nonce>"` with URL-encoding.
    - degrades: `currentScript` null → no `__nazrWidget`; `crypto.randomUUID` undefined and no `data-nonce` → no `__nazrWidget`; `attachShadow` throws → no throw out of `mountWidget`; second call → no second host element.
  - `frame.test.ts`: with `location.search = "?k=nzr_x&n=abc"`, a stub `getThumbmark` resolving `{ thumbmark: "deadbeef", components: { a: 1 } }` and a spy `fetch`: one call to `"/widget/report"`, method POST, header `x-api-key: nzr_x`, `Content-Type: application/json`, body `{ nonce: "abc", components: { a: 1 }, clientHash: "deadbeef" }`; `getThumbmark` was called with `{ collect_beacon: false, cache_api_call: false }` and no `api_key`; missing `k` → no fetch; `fetch` rejecting → resolves without throwing.
- [ ] **Step 2: Run** `pnpm --filter @nazr/widget test` → FAIL (package/modules missing).
- [ ] **Step 3: Implement.** `mountWidget`: guard `win.__nazrWidget`, read `doc.currentScript` (bail if null or not `HTMLScriptElement` or no `dataset.apiKey`), nonce from `dataset.nonce || win.crypto?.randomUUID?.()` (bail when empty), origin = `new URL(script.src).origin`, create a `div`, `attachShadow({ mode: "closed" })`, append an `iframe` with `src`, `width="0" height="0"`, `style="position:absolute;width:0;height:0;border:0"`, `aria-hidden="true"`, `title="nazr"`; append the div to `doc.body`, or on `DOMContentLoaded` when `body` is null; set `win.__nazrWidget = { nonce, ready: Promise.resolve({ nonce }) }` before mounting. Whole body in one `try { } catch { }`. `src/entries/loader.ts` is `mountWidget(document, window)`. `reportFromFrame` as the test pins; `src/entries/frame.ts` calls it with real globals. `frame.html`: `<!doctype html><html><head><meta charset="utf-8"><title>nazr</title></head><body><script src="/widget/v1/{{.Bundle}}"></script></body></html>`. `build.mjs`: two `esbuild.build` calls (`format: "iife"`, `bundle: true`, `minify: true`, `target: "es2020"`, `write: false`), hash the frame output, write the four files to `dist/`.
- [ ] **Step 4: Run** `pnpm --filter @nazr/widget test` → PASS; `pnpm build --filter=@nazr/widget` → `dist/` holds the four files and `manifest.json` names the bundle.
- [ ] **Step 5: Commit** `feat(widget): loader, frame and build`.

## Task 7: Embedded assets, static routes, frame route, config

**Files:**
- Create: `apps/api/internal/widgetassets/embed.go`, `apps/api/internal/widgetassets/assets/.gitkeep`
- Create: `apps/api/scripts/sync-widget.mjs`
- Modify: `.gitignore` (`apps/api/internal/widgetassets/assets/*`, `!apps/api/internal/widgetassets/assets/.gitkeep`), `apps/api/package.json` (`sync-widget` script, `build` runs it first, devDependency `@nazr/widget: workspace:*`)
- Modify: `apps/api/internal/config/config.go` (`WidgetDir`)
- Modify: `apps/api/internal/server/widget.go`, `server.go` (`Deps.WidgetAssets fs.FS`, routes), `apps/api/cmd/nazr/serve.go`
- Modify: `.github/workflows/release.yml` (build the widget and sync before `docker/build-push-action`)
- Test: `apps/api/internal/widgetassets/embed_test.go`, `apps/api/internal/server/server_test.go`

**Interfaces:**
- Produces: `widgetassets.Open(dir string) (fs.FS, error)` (dir `""` → embedded `assets` sub-FS, else `os.DirFS`); `widgetassets.Present(fsys fs.FS) bool` (true when `loader.js` and `manifest.json` exist); `config.Config.WidgetDir string` (`env:"NAZR_WIDGET_DIR"`); `server.Deps.WidgetAssets fs.FS` (nil → widget routes 404); `newWidgetAssets(fsys fs.FS) (*widgetAssets, error)` loading `loader.js`, the manifest's bundle, and `frame.html` as an `html/template` into memory; `frameAncestors(origins []string) string`; routes `GET /widget/v1/loader.js`, `GET /widget/v1/frame`, `GET /widget/v1/{bundle}`.

- [ ] **Step 1: Write the failing tests.**
  - `embed_test.go`: `Open("")` + `Present` is false on the committed tree (only `.gitkeep`); `Open(t.TempDir())` with `loader.js` and `manifest.json` written → `Present` true.
  - Server tests, using `fstest.MapFS{"loader.js": ..., "frame.abcd1234.js": ..., "frame.html": {Data: []byte(`<script src="/widget/v1/{{.Bundle}}">`)}, "manifest.json": {Data: []byte(`{"frame":"frame.abcd1234.js"}`)}}` passed as `Deps.WidgetAssets` through a new helper `newEnvWidget(t, mut, fsys fs.FS) *env` in `helpers_test.go`, mirroring `newEnvCache`:
    - `TestWidgetRoutes404WithoutAssets`: all three GETs → 404 JSON `not_found`.
    - `TestWidgetLoaderAndBundle`: loader → 200, `Content-Type: text/javascript; charset=utf-8`, `Cache-Control: public, max-age=300`, non-empty `ETag`; a second GET with `If-None-Match` → 304. Bundle → 200, `Cache-Control: public, max-age=31536000, immutable`; `GET /widget/v1/other.js` → 404.
    - `TestWidgetFrame`: valid key → 200, body contains `/widget/v1/frame.abcd1234.js`, `Content-Security-Policy` exactly `frame-ancestors *; default-src 'none'; script-src 'self'; connect-src 'self'`, `Cache-Control: no-store`, no `X-Frame-Options`; key with `AllowedOrigins: ["https://a.com", "https://*.b.com"]` → `frame-ancestors https://a.com https://*.b.com; ...`; unknown key, malformed `k`, missing `k`, revoked key → 403 with empty body; store lookup error → 503.
  - `frameAncestors` table test: `nil → "*"`, `["*"] → "*"`, `["https://a.com"," https://b.com "] → "https://a.com https://b.com"`.
- [ ] **Step 2: Run** `go test ./internal/widgetassets ./internal/server -run 'TestWidget|TestFrameAncestors'` → FAIL.
- [ ] **Step 3: Implement.** `embed.go`: `//go:embed all:assets` (the `.gitkeep` keeps the directory embeddable). `widget.go`: `newWidgetAssets` reads the files, computes the loader ETag as `"\"" + hex(sha256)[:16] + "\""`, parses `frame.html` with `html/template`; `handleWidgetLoader`/`handleWidgetBundle` set headers and call `http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))`; `handleWidgetFrame` uses `auth.LookupKey(ctx, s.KeyCache, s.Store, r.URL.Query().Get("k"))`, 503 via `storeUnavailable` on error, `w.WriteHeader(403)` when nil or `RevokedAt != nil`, else headers + `tmpl.Execute(w, struct{ Bundle string })`. In `New`: `if d.WidgetAssets != nil { wa, err := newWidgetAssets(d.WidgetAssets); if err != nil { d.Logger.Error(...) } else { register the three routes through s.route("widget", ...) } }`. Config field. `serve.go`: `fsys, err := widgetassets.Open(cfg.WidgetDir)`; pass it only when `widgetassets.Present(fsys)`, logging `"widget assets not found; widget routes disabled"` otherwise. `sync-widget.mjs` copies `node_modules/@nazr/widget/dist/*` into `internal/widgetassets/assets/`; when that `dist/` is missing it prints a warning and exits 0, so `pnpm --filter @nazr/api build` still works without the widget (routes 404, the documented behavior). `release.yml` image job: add pnpm/node setup, `pnpm install --frozen-lockfile`, `pnpm build --filter=@nazr/widget`, `pnpm --filter @nazr/api sync-widget` before the docker step.
- [ ] **Step 4: Run** `go test ./...` → PASS. `pnpm build --filter=@nazr/api` → `bin/nazr` and the assets dir populated; `NAZR_TLS_MODE=plain NAZR_DATABASE_URL=... bin/nazr serve` then `curl -i localhost:8080/widget/v1/loader.js` → 200 with the cache headers (manual check; note the result in the commit body).
- [ ] **Step 5: Commit** `feat(api): embed and serve the widget assets`.

## Task 8: Report handler and admin summary

**Files:**
- Modify: `apps/api/internal/server/widget.go`, `server.go` (`StoreAPI`, routes), `admin.go`
- Modify: `apps/api/internal/server/helpers_test.go` (fake store: `reports []store.WidgetReport`, `summary store.WidgetSummary`, `summaryErr`, `summaryKeyID`, `summarySince`, `summaryWindow`)
- Test: `apps/api/internal/server/server_test.go`

**Interfaces:**
- Consumes: `InsertWidgetReport`, `WidgetSummary` (Tasks 1–2); `MiddlewareOpts` (Task 3); `validNonce` (Task 5); `validCanvasProbe` (reused for `clientHash`).
- Produces: `const widgetMatchWindow = 10 * time.Minute`; `StoreAPI` gains `InsertWidgetReport(ctx, store.WidgetReport) error` and `WidgetSummary(ctx, keyID string, since time.Time, window time.Duration) (store.WidgetSummary, error)`; `POST /widget/report` → always 204 after auth; `GET /admin/keys/{id}/widget` → `{"window_days":30,"reports":n,"matched":n,"unmatched":n,"ip_mismatch":n,"ja4_mismatch":n,"ja4_unknown":n,"ua_mismatch":n}`.

- [ ] **Step 1: Write the failing tests.**
  - `TestWidgetReportStores`: POST with `x-api-key`, `Origin: https://nazr.example`, body `{nonce:"n-1", components: stockBody(t)["components"], clientHash:"abc123"}` through `fullHolder(t)` (set `r = r.WithContext(conn.WithHolder(...))` the way the `/thumbmark` TLS tests do) → 204; `store.reports[0]` has `Nonce "n-1"`, `ClientHash "abc123"`, `IPHash == ipintel.Identifier(203.0.113.42, "salt")`, non-empty `JA4`, `H2FP`, `UserAgent == chromeUA`, `Thumbmark` matching `^[0-9a-f]{32}$`, `IP != nil` (default `StoreIP=raw`), `Components == nil` (default `StoreComponents=false`); with `StoreComponents=true` → `Components` non-empty; with `StoreIP=hash` → `IP == nil`. No visitor was created (`repo.visitors` empty).
  - `TestWidgetReportScopedKey`: key with `AllowedOrigins: ["https://a.com"]`, `Origin: https://nazr.example` → 204; the same Origin on `/thumbmark` → 403 `origin_not_allowed`.
  - `TestWidgetReportRejectsBody`: each of `[]`, `{}`, `{nonce:"n", components:"x"}`, 65-char nonce, `clientHash:"zz"`, a body over `BodyLimit` → 204 and `len(store.reports) == 0`; no `x-api-key` → 403 `unauthorized`; rate limit denied → 429.
  - `TestAdminWidgetSummary`: no token → 404/403 as the other admin routes; valid → 200 with the JSON above from the fake's `summary`, `summaryKeyID == "{id}"`, `summaryWindow == 10m`, `summarySince == testNow - 30d`; store error → 503.
- [ ] **Step 2: Run** `go test ./internal/server -run 'TestWidgetReport|TestAdminWidgetSummary'` → FAIL.
- [ ] **Step 3: Implement.** `handleWidgetReport`: `key := auth.KeyFromContext`; decode with `fingerprint.Decode(r.Body, int64(s.Cfg.BodyLimit))`; validate nonce, `components` object, `clientHash` (`""` or `validCanvasProbe`); on any failure `w.WriteHeader(204); return`. Then `addr, view := s.clientIP(r)`, `serverComponents(...)`, `filterServer(sc, comps, fingerprint.OptionsFromRequest(nil))`, `Merge`, `Hash`; build `store.WidgetReport{ID: requestIDFrom(ctx), ...}` with `IP` under `StoreIP == "raw"`, `Components` under `StoreComponents` (marshal `Merge(comps, sc)`), `CreatedAt: s.Now().UTC()`; insert with `storeTimeout` and `context.WithoutCancel`, log on error; 204. Route: `report := s.bodyLimit(auth.MiddlewareOpts(d.Store, d.Limiter, d.Cfg.DefaultRateLimit, d.KeyCache, auth.MiddlewareOptions{SkipOrigin: true})(http.HandlerFunc(s.handleWidgetReport)))`, registered as `POST /widget/report` via `s.route("widget_report", ...)` **unconditionally** (it does not need assets). Admin: `handleWidgetSummary` calls `WidgetSummary(ctx, id, s.Now().Add(-store.ProbeWindowDays*24*time.Hour), widgetMatchWindow)`; register `GET /admin/keys/{id}/widget` beside `canvas-probe`.
- [ ] **Step 4: Run** `go test ./...` → PASS; `pnpm --filter @nazr/api lint` clean.
- [ ] **Step 5: Commit** `feat(api): widget report endpoint and admin summary`.

## Task 9: Demo host page and end-to-end correlation

**Files:**
- Create: `apps/demo/widget-host.html`, `apps/demo/src/widget-host.ts`
- Modify: `apps/demo/vite.config.ts` (`build.rollupOptions.input: { main: "index.html", widget: "widget-host.html" }`)
- Modify: `apps/demo/e2e/global-setup.ts` (`NAZR_ADMIN_TOKEN: "e2e-admin"`, export `NAZR_E2E_ADMIN_TOKEN`; set `NAZR_WIDGET_DIR` to `packages/widget/dist` so the e2e binary needs no sync)
- Create: `apps/demo/e2e/widget.spec.ts`
- Modify: `.github/workflows/ci.yml` e2e job (`pnpm build --filter=@nazr/widget` before the demo build)

**Interfaces:**
- Consumes: the built widget (`NAZR_WIDGET_DIR`), the `nonce` client option (Task 4), the admin summary (Task 8).
- Produces: `widget-host.html?key=&endpoint=` which injects `<script src="<endpoint>/widget/v1/loader.js" data-api-key="<key>">`, awaits `window.__nazrWidget.ready`, calls `getThumbmark({ api_key, api_endpoint, nonce, cache_api_call: false })`, and sets `window.__nazrHostDone = { nonce, thumbmark, error? }`.

- [ ] **Step 1: Write the failing e2e** `widget.spec.ts` (Chromium): open the host page; wait for `__nazrHostDone`; assert the frame navigation response (`url.includes("/widget/v1/frame?")`) is 200 with a `content-security-policy` header starting `frame-ancestors *`; the `POST /widget/report` response is 204; the `POST /thumbmark` response is 200; `document.querySelector("iframe")` is null in the page; `__nazrWidget.nonce` matches the UUID regex and equals the `nonce` in the `/thumbmark` request body. Then poll `GET <endpoint>/admin/keys` (via `curl -ks -H "Authorization: Bearer ..."`, as `global-setup.ts` shells out) to find the `e2e` key id, and `GET /admin/keys/{id}/widget` until `matched >= 1` (timeout 10 s); assert `ip_mismatch`, `ja4_mismatch`, `ua_mismatch` are all 0 and `ja4_unknown` is 0 (terminate mode).
- [ ] **Step 2: Run** `pnpm build --filter=@nazr/widget && pnpm --filter @nazr/api build && pnpm --filter @nazr/demo test:e2e widget` → FAIL (page missing).
- [ ] **Step 3: Implement** the host page, `widget-host.ts`, the Vite input, the global-setup env, and the CI step.
- [ ] **Step 4: Run** the e2e → PASS; `pnpm --filter @nazr/demo test:e2e` → all specs green.
- [ ] **Step 5: Commit** `test(demo): widget host page and correlation e2e`.

## Task 10: Documentation

**Files:**
- Modify: `docs/protocol.md` (Routes table: four widget routes + `GET /admin/keys/{id}/widget`; `/thumbmark` request: `nonce`; new `## Widget` section covering the report body, 204-always, the origin-skip and `frame-ancestors` rules, the CSP, the cache policy; Admin API: the summary JSON), `docs/configuration.md` (`NAZR_WIDGET_DIR` under Core; `NAZR_STORE_COMPONENTS`, `NAZR_STORE_IP`, `NAZR_EVENT_RETENTION` rows mention widget reports), `README.md` (one line + link), `CLAUDE.md` (commit scope `widget`; `packages/widget` in the overview; the `NAZR_WIDGET_DIR` / sync note under Testing notes), `packages/widget/README.md`
- Create: `docs/widget.md` (embedding guide: the script tag, `data-nonce` vs generated, reading `window.__nazrWidget`, passing `nonce` to `@nazr/thumbmark`, the stock-client caveat, what the summary does and does not detect per spec §1.1, rate-limit budgeting)

- [ ] **Step 1: Write** the docs listed above with the exact field names from Tasks 4–8.
- [ ] **Step 2: Verify** `pnpm lint:biome` is clean and every `NAZR_*` variable in `config.go` appears in `docs/configuration.md`.
- [ ] **Step 3: Verify** the full pipeline: `pnpm lint && pnpm typecheck && pnpm test && pnpm build`, and `NAZR_TEST_REQUIRE_DB=1 go test -race ./...` in `apps/api`.
- [ ] **Step 4: Commit** `docs: widget embedding guide, protocol and configuration`.
