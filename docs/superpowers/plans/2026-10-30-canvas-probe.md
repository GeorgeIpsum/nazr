# Consumer Canvas Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a deployment supply its own canvas-drawing routine whose hashed output becomes a consumer-controlled side signal, stored per event, scored (opt-in) by classification, and guarded by a server entropy report plus client and doc warnings.

**Architecture:** The client runs a consumer-supplied `draw` callback through the existing three-render/common-pixels/hash path and sends the hash on a dedicated top-level request field (`canvas_probe`), a sibling of `clientHash`, so it never enters `components`, `Merge`, the filter, or the thumbmark hash. The server validates and stores it on the event, optionally computes a per-cohort anomaly signal for classification behind a config flag, and exposes a per-key entropy report on a new admin route.

**Tech Stack:** TypeScript (`@nazr/thumbmark`, Rollup, Jest, Playwright), Go 1.26 (`nazr/api`, pgx, goose), PostgreSQL.

**Spec:** [docs/superpowers/specs/2026-10-30-canvas-probe-design.md](../specs/2026-10-30-canvas-probe-design.md)

## Global Constraints

- The probe is a **side signal only**; it must never enter `components`, `Merge`, `StableStringify`, or the thumbmark hash. (spec §1, §4)
- The server never recomputes the probe; it only stores and compares the client hash. (spec §2)
- The probe API is a **draw callback only**, not a general value function. (spec §2)
- Probe wire field is a bounded hex string (≤ 64 bytes); anything else is treated as absent and never produces a 400. (spec §4)
- Live classification scoring is gated behind `NAZR_CANVAS_PROBE_SCORING` (bool, default **false**); storage and the entropy report are always on. (spec §5)
- Entropy report constants: `N_min = 50`, `r_low = 0.05`, `r_high = 0.95`, `window_days = 30`. (spec §7.1)
- The `canvas_probe_anomaly` weights must each sit below `classify.botThreshold` (currently 3) so the probe alone cannot flip a classification. (spec §5)
- Migrations are collapsed into a single `00001_init.sql`; `00002`–`00004` are deleted. This is a one-time pre-release cleanup, valid only because no database has run the old sequence. (spec §6)
- The stock `@thumbmarkjs/thumbmarkjs` client sends no `canvas_probe`; existing behavior and fixtures are unchanged. (spec §9, §10)
- Commit style `type(scope): subject`; scopes `thumbmark`, `api`, `docs`.

## Review Focus

- **`draw` throws / no 2d context** → probe omitted, `getThumbmark` returns normally with an unchanged thumbmark. (Task 1)
- **Malformed `canvas_probe` on the wire** (non-hex, over-long, non-string) → stored as absent (NULL), never a 400. (Task 5)
- **Cohort below `N_min`, or zero probed visitors** → report verdict `insufficient_data`; no divide-by-zero in `ratio`. (Task 7)
- **Farbling browser** (Brave/Firefox/Safari) → three-render common-pixels keeps the probe stable across repeated calls. (determinism in Task 1; real-browser stability in Task 9)
- **Probe present but scoring off** → stored, no cohort query runs, `canvas_probe_anomaly` never appears. (Task 6)

---

## Task 1: Client probe computation utility

**Files:**
- Create: `packages/thumbmark/src/utils/canvasProbe.ts`
- Test: `packages/thumbmark/src/utils/canvasProbe.test.ts`

**Interfaces:**
- Consumes: `getCommonPixels(images: ImageData[], width: number, height: number): ImageData` from `../utils/commonPixels`; `hash(key: ArrayBuffer | string, seed?: number): string` from `../utils/hash`.
- Produces: `interface CanvasProbe { draw: (ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement) => void; width?: number; height?: number }`; `computeCanvasProbe(probe: CanvasProbe): string | null` (hex hash, or `null` on any failure); `PROBE_DEFAULT_WIDTH = 280`, `PROBE_DEFAULT_HEIGHT = 20`; `isBlankProbe(probe: CanvasProbe): boolean` (true when the drawn output equals a same-size no-op render).

- [ ] **Step 1: Write the failing tests** in `canvasProbe.test.ts` (jsdom). Use a stub `CanvasRenderingContext2D` via the existing jest canvas setup. Cases:
  - `computeCanvasProbe` returns a 32-hex-char string for a callback that fills a rect.
  - Two different `draw` callbacks produce different hashes; the same callback produces the same hash across two calls.
  - A callback that throws makes `computeCanvasProbe` return `null` (no throw).
  - When `getContext("2d")` yields `null`, `computeCanvasProbe` returns `null`.
  - `isBlankProbe` is `true` for a no-op `draw` and `false` for one that fills a rect.
- [ ] **Step 2: Run** `pnpm --filter @nazr/thumbmark exec jest src/utils/canvasProbe.test.ts` → FAIL (module missing).
- [ ] **Step 3: Implement** `canvasProbe.ts`. `computeCanvasProbe` creates a canvas at `probe.width ?? PROBE_DEFAULT_WIDTH` × `probe.height ?? PROBE_DEFAULT_HEIGHT`, runs `draw` on three fresh canvases, collects their `ImageData`, applies `getCommonPixels`, and returns `hash(commonImageData.data.toString())`. Any thrown error or missing context returns `null`. `isBlankProbe` compares `computeCanvasProbe(probe)` against `computeCanvasProbe({ ...probe, draw: () => {} })`. Mirror the canvas component's render/common-pixels usage (`src/components/canvas/index.ts`); do not duplicate the gradient drawing — the consumer owns drawing.
- [ ] **Step 4: Run** the test → PASS.
- [ ] **Step 5: Commit** `feat(thumbmark): canvas probe computation utility`.

## Task 2: Client option, wiring, and dev warning

**Files:**
- Modify: `packages/thumbmark/src/options.ts` (add `canvas_probe?` to `OptionsAfterDefaults`)
- Modify: `packages/thumbmark/src/functions/index.ts` (compute probe, pass to `getApiPromise`)
- Modify: `packages/thumbmark/src/functions/api.ts` (`getApiPromise` signature + request body field)
- Test: `packages/thumbmark/src/functions/api.test.ts` (body-shape test), `packages/thumbmark/src/functions/canvasProbe-wiring.test.ts` (new)

**Interfaces:**
- Consumes: `CanvasProbe`, `computeCanvasProbe`, `isBlankProbe` from `../utils/canvasProbe` (Task 1).
- Produces: `getApiPromise(options, components, canvasProbe?: string)` — new optional third parameter; request body gains `canvas_probe?: string` as a top-level sibling of `components`/`clientHash`/`path`.

- [ ] **Step 1: Write the failing tests.**
  - In `api.test.ts`: when `getApiPromise` is called with a third arg `"abc123"`, the fetched request body JSON has `body.canvas_probe === "abc123"` and `body.components.canvas_probe === undefined`, and `clientHash` is unchanged from the no-probe call (probe does not affect `clientHash`).
  - In `canvasProbe-wiring.test.ts`: `getThumbmark` with `canvas_probe` set to a rect-filling callback results in a non-empty `canvas_probe` on the outgoing request (spy on `fetch`); with no `canvas_probe` option, the field is absent. A blank-canvas callback triggers exactly one `console.warn` whose message contains `canvas_probe`.
- [ ] **Step 2: Run** both tests → FAIL.
- [ ] **Step 3: Implement.** Add `canvas_probe?: CanvasProbe` to `OptionsAfterDefaults` (optional; not in `defaultOptions`). In `getThumbmark`, after `resolveClientComponents` and before `getApiPromise`, if `_options.canvas_probe` is set compute `const probe = computeCanvasProbe(_options.canvas_probe)`; if `isBlankProbe(_options.canvas_probe)` is true, `console.warn` once that `canvas_probe` produced blank output and contributes no entropy. Pass `probe ?? undefined` to `getApiPromise`. In `getApiPromise`, accept the third param and set `requestBody.canvas_probe = canvasProbe` only when truthy, placed beside `path` (follow the existing `path` comment pattern: alongside components, not inside). Omit `canvas_probe` from `optionsForBody` so it is not echoed back inside `options`.
- [ ] **Step 4: Run** both tests → PASS. Run `pnpm --filter @nazr/thumbmark exec jest` → all green.
- [ ] **Step 5: Commit** `feat(thumbmark): canvas_probe option, wiring, and blank-canvas warning`.

## Task 3: Collapse migrations and add the canvas_probe schema

**Files:**
- Modify: `apps/api/migrations/00001_init.sql` (fold in 00002–00004; add `canvas_probe`, `cohort`, index)
- Delete: `apps/api/migrations/00002_api_key_visitor_count.sql`, `00003_events_thumbmark_idx.sql`, `00004_events_ja3.sql`
- Modify (if version-pinned): `apps/api/internal/store/migrate_test.go` and any test asserting migration count/versions

**Interfaces:**
- Produces: `events.canvas_probe text` (nullable), `events.cohort text` (nullable), and index `events_probe_cohort_idx` on `(api_key_id, cohort, created_at)`. All columns from the former 00002–00004 remain present with identical names and types.

- [ ] **Step 1: Write/adjust the failing test.** In `migrate_test.go` (gated by `NAZR_TEST_REQUIRE_DB`), assert that after `Migrate`, `events` has columns `canvas_probe` and `cohort` (query `information_schema.columns`), and that `api_keys.visitor_count`, `events.ja3_hash`, and the thumbmark index still exist. If the suite asserts a specific migration version/count, update it to the single-file version.
- [ ] **Step 2: Run** `cd apps/api && NAZR_TEST_REQUIRE_DB=1 go test ./internal/store -run TestMigrate` → FAIL.
- [ ] **Step 3: Implement.** Merge the DDL from 00002 (`api_keys.visitor_count`), 00003 (events thumbmark index), 00004 (`events.ja3_hash`) into `00001_init.sql` in dependency order, then add `canvas_probe text`, `cohort text`, and `CREATE INDEX events_probe_cohort_idx ON events (api_key_id, cohort, created_at)`. Keep the goose `-- +goose Up`/`Down` structure. Delete 00002–00004. Confirm `migrations.FS` still embeds only `00001_init.sql`.
- [ ] **Step 4: Run** the migrate test → PASS. Run `NAZR_TEST_REQUIRE_DB=1 go test ./internal/store/...` → green.
- [ ] **Step 5: Commit** `chore(api): collapse migrations and add canvas_probe schema`.

## Task 4: Cohort key and event storage

**Files:**
- Create: `apps/api/internal/classify/cohort.go`, `apps/api/internal/classify/cohort_test.go`
- Modify: `apps/api/internal/store/events.go` (add `Event.CanvasProbe`, `Event.Cohort`; INSERT columns)
- Test: `apps/api/internal/store/events_test.go`

**Interfaces:**
- Consumes: `ua.Family`/`ua.FamilyWithBrave` from `internal/ua`; the exported-from-Task-1 nothing (Go only here).
- Produces: `classify.CohortKey(userAgent string, brave bool, ja4Families []string) string` returning `"<uaFamily>|<ja4Family>"` where ja4Family is the first JA4 family collapsed through the same rule as `tlsFamily` (export a `TLSFamily` helper or reuse via a new exported function); `Event.CanvasProbe string` and `Event.Cohort string` (both `""` → SQL NULL, like `JA3Hash`).

- [ ] **Step 1: Write the failing tests.**
  - `cohort_test.go`: `CohortKey("Mozilla/5.0 ... Chrome/120 ...", false, []string{"t13d1516h2_..."})` returns `"chrome|chrome"`; a curl UA with no JA4 returns `"curl|"`; Brave flag yields `"brave|chrome"`.
  - `events_test.go` (DB-gated): `InsertEvent` with `CanvasProbe: "deadbeef"`, `Cohort: "chrome|chrome"` round-trips; empty strings store as NULL (assert via `IS NULL`).
- [ ] **Step 2: Run** `go test ./internal/classify -run TestCohortKey` and the events test → FAIL.
- [ ] **Step 3: Implement.** Add `cohort.go` with `CohortKey` and, if needed, export `TLSFamily(f string) string` wrapping the current unexported `tlsFamily` (keep `tlsFamily` as a thin alias to avoid churn in `classify.go`). Add `CanvasProbe`, `Cohort` to the `Event` struct and the INSERT column list/values in `events.go`, using `nullJSON`-style empty-to-NULL mapping (plain `nullString` helper or inline `any` like `JA3Hash`).
- [ ] **Step 4: Run** both tests → PASS.
- [ ] **Step 5: Commit** `feat(api): cohort key and canvas_probe event storage`.

## Task 5: Server parse, validate, and persist the probe

**Files:**
- Modify: `apps/api/internal/server/thumbmark.go` (`thumbmarkBody`, `parseThumbmarkBody`, event build)
- Test: `apps/api/internal/server/server_test.go`

**Interfaces:**
- Consumes: `Event.CanvasProbe`, `Event.Cohort` (Task 4); `classify.CohortKey` (Task 4).
- Produces: `thumbmarkBody.canvasProbe string`; a package-level `validCanvasProbe(s string) bool` (hex, 1–64 bytes).

- [ ] **Step 1: Write the failing tests** (`plain` TLS mode, DB-gated for persistence or asserting on the handler's event via a store spy where the suite already does so).
  - A POST whose body has `canvas_probe: "a1b2c3"` stores an event with `canvas_probe = "a1b2c3"` and a non-empty `cohort`; the returned thumbmark equals the same request without `canvas_probe` (probe does not change identity).
  - `canvas_probe: "NOT-HEX!!"`, a 200-char string, and a numeric `canvas_probe: 5` each store NULL and return 200 (no 400).
- [ ] **Step 2: Run** `go test ./internal/server -run TestThumbmarkCanvasProbe` → FAIL.
- [ ] **Step 3: Implement.** Add `canvasProbe` to `thumbmarkBody`; in `parseThumbmarkBody` read `raw["canvas_probe"]` as a string and keep it only if `validCanvasProbe`. Implement `validCanvasProbe` (all `[0-9a-fA-F]`, length 1–64). In the event build, set `ev.CanvasProbe = body.canvasProbe` and `ev.Cohort = classify.CohortKey(userAgent, braveFlag, in.JA4Families)` using the UA and JA4 families already computed for classification. Do not add the probe to `components`, `sc`, or `Merge`.
- [ ] **Step 4: Run** the test → PASS. Run `go test ./internal/server/...` → green.
- [ ] **Step 5: Commit** `feat(api): parse, validate, and persist canvas_probe`.

## Task 6: Opt-in anomaly scoring

**Files:**
- Modify: `apps/api/internal/config/config.go` (`CanvasProbeScoring` bool)
- Create: `apps/api/internal/store/canvasprobe.go` (dominant-value query), `canvasprobe_test.go`
- Modify: `apps/api/internal/classify/classify.go` (input field + rule)
- Modify: `apps/api/internal/server/thumbmark.go` (compute anomaly when scoring on)
- Test: `apps/api/internal/classify/classify_test.go`, server test

**Interfaces:**
- Consumes: `store` pool; `classify.Input`; config.
- Produces: `config.Config.CanvasProbeScoring bool` (`env:"NAZR_CANVAS_PROBE_SCORING" envDefault:"false"`); `Store.DominantCanvasProbe(ctx, keyID, cohort string, since time.Time, minSample int) (value string, established bool, err error)`; `classify.Input.CanvasProbeAnomaly bool`; signal name `"canvas_probe_anomaly"`; constants `probeNMin = 50` and `probeWindowDays = 30` (defined here in `canvasprobe.go`, reused by Task 7).

- [ ] **Step 1: Write the failing tests.**
  - `canvasprobe_test.go` (DB-gated): with ≥ `N_min` events in a cohort sharing probe `X` plus a few `Y`, `DominantCanvasProbe` returns `("X", true)`; with < `N_min` it returns `("", false)`.
  - `classify_test.go`: an `Input{CanvasProbeAnomaly: true, ...browser...}` sets `Signals["canvas_probe_anomaly"] == true` and adds its danger/bot weight; `CanvasProbeAnomaly: false` leaves the signal absent; the weight is `< botThreshold` and cannot alone make `Bot` true.
  - Server test: with `NAZR_CANVAS_PROBE_SCORING=false`, a probe request produces no `canvas_probe_anomaly` signal and runs no dominant query (assert via a store spy/counter); with it `true` and an established cohort whose dominant differs from this visit, `info.signals.canvas_probe_anomaly == true`.
- [ ] **Step 2: Run** the three tests → FAIL.
- [ ] **Step 3: Implement.** Add the config field. Implement `DominantCanvasProbe` as one indexed query over `events` filtered by `(api_key_id, cohort, created_at >= since, canvas_probe IS NOT NULL)` using `GROUP BY canvas_probe ORDER BY count(*) DESC LIMIT 1` and a separate count for the `minSample` gate (or a single query returning both). Add `CanvasProbeAnomaly bool` to `classify.Input` and a rule emitting `canvas_probe_anomaly` with small weights (danger and bot each 1, both `< botThreshold`). In the server, only when `s.Cfg.CanvasProbeScoring` and the request carried a probe, call `DominantCanvasProbe` (window = 30 days, minSample = `N_min`) and set `in.CanvasProbeAnomaly = established && dominant != body.canvasProbe` before `classify.Classify`.
- [ ] **Step 4: Run** the tests → PASS. `go test ./...` → green.
- [ ] **Step 5: Commit** `feat(api): opt-in canvas_probe anomaly scoring`.

## Task 7: Admin entropy report

**Files:**
- Modify: `apps/api/internal/store/canvasprobe.go` (entropy aggregate), `canvasprobe_test.go`
- Modify: `apps/api/internal/server/admin.go` (report handler + JSON), `server.go` (route)
- Test: `apps/api/internal/server/server_test.go` (admin)

**Interfaces:**
- Produces: `Store.CanvasProbeEntropy(ctx, keyID string, since time.Time) (visitors, distinct int64, err error)`; admin route `GET /admin/keys/{id}/canvas-probe` returning `{window_days:int, visitors:int, distinct_probes:int, ratio:float64, verdict:string}` with verdict in `insufficient_data|too_low|too_unique|ok`; constants `probeRLow = 0.05`, `probeRHigh = 0.95` added here (reusing `probeNMin`, `probeWindowDays` from Task 6).

- [ ] **Step 1: Write the failing tests.**
  - `canvasprobe_test.go` (DB-gated): seed events; `CanvasProbeEntropy` returns correct `visitors` (distinct `visitor_id` with non-null probe) and `distinct` (distinct `canvas_probe`).
  - admin test: a verdict helper maps `(visitors<50)→insufficient_data`, `ratio≤0.05→too_low`, `ratio≥0.95→too_unique`, else `ok`; `visitors==0` yields `insufficient_data` with `ratio==0` (no divide-by-zero). The route requires the admin token (401/403 without it, mirroring the other `/admin/keys` routes) and returns the JSON for a valid key.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Add `CanvasProbeEntropy` (two `count(distinct …)` over the window). Add a pure `probeVerdict(visitors, distinct int64) (ratio float64, verdict string)` helper (guard `visitors==0`). Add `handleCanvasProbeReport` to `admin.go` and register `mux.Handle("GET /admin/keys/{id}/canvas-probe", s.route("admin", admin(http.HandlerFunc(s.handleCanvasProbeReport))))` beside the existing admin routes.
- [ ] **Step 4: Run** → PASS. `go test ./...` → green.
- [ ] **Step 5: Commit** `feat(api): admin canvas_probe entropy report`.

## Task 8: Documentation and the builder-beware warning

**Files:**
- Modify: `packages/thumbmark/README.md`, `docs/protocol.md`, `docs/signals.md`, `docs/configuration.md`

**Interfaces:**
- Consumes: the field name `canvas_probe`, the option shape (Task 2), the config var `NAZR_CANVAS_PROBE_SCORING` (Task 6), the report route and verdicts (Task 7).

- [ ] **Step 1: Write** the client README section: the `canvas_probe` option with a `draw`-callback example, and an explicit **builder-beware** block stating the four points from spec §7.3 (no identity contribution; only as private as the bundle; `too_low`/`too_unique` make it worthless; keep scoring off until the report reads `ok`).
- [ ] **Step 2: Document the wire field** in `docs/protocol.md` (top-level `canvas_probe`, optional, bounded hex, never in the thumbmark), the signal and report in `docs/signals.md` (including the same builder-beware caveat and the four verdicts), and `NAZR_CANVAS_PROBE_SCORING` (default false) in `docs/configuration.md`.
- [ ] **Step 3: Verify** `pnpm lint:biome` formats the Markdown clean and `pnpm biome check README.md docs/...` passes.
- [ ] **Step 4: Commit** `docs: document the canvas probe, scoring flag, and entropy report`.

## Task 9: End-to-end stability and isolation check

**Files:**
- Create: `packages/thumbmark/e2e/canvas-probe.spec.ts`
- Modify: `packages/thumbmark/scripts/make-testpage.sh` (expose a probe test page if needed)

**Interfaces:**
- Consumes: the built client (`canvas_probe` option); the testpage harness.

- [ ] **Step 1: Write the failing e2e** (Chromium): load the testpage, call the client twice with the same `canvas_probe` draw callback, assert the outgoing `canvas_probe` field is identical across both calls and matches `/^[0-9a-f]{32}$/`, and assert the `thumbmark` is identical with and without the probe (isolation from identity). Spy on requests via the existing e2e request-capture helper.
- [ ] **Step 2: Run** `pnpm --filter @nazr/thumbmark build && bash scripts/make-testpage.sh && pnpm --filter @nazr/thumbmark exec playwright test e2e/canvas-probe.spec.ts` → FAIL (spec asserts before wiring is built into the page) then, once built, PASS.
- [ ] **Step 3: Verify** the full pipeline: `pnpm lint && pnpm typecheck && pnpm test && pnpm build`, and `NAZR_TEST_REQUIRE_DB=1 go test -race ./...` in `apps/api`.
- [ ] **Step 4: Commit** `test(thumbmark): canvas probe stability and identity-isolation e2e`.
