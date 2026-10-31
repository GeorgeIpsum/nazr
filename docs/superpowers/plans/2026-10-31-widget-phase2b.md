# Widget Phase 2b Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give reputation-only `inconclusive` widget visitors a click-to-verify step inside the frame that, when the behavioural trace and a harder proof-of-work check out, upgrades their report once and issues a token with `verdict: "interactive"`.

**Architecture:** The report handler mints a second, `stage:"interactive"` challenge bound to the same id for eligible inconclusives. The frame renders a button (only when the loader placed it in a host container), records a trace summary, solves the harder PoW and posts to a new `POST /widget/interact`, which verifies MAC and PoW before any database work, scores the trace in a pure `internal/interaction` package, and upgrades the row with one conditional `UPDATE` that is the single-use gate. Siteverify and local verification are unchanged except for the new verdict value and an `interaction` block.

**Tech Stack:** Go 1.26 (stdlib, pgx, goose), TypeScript (esbuild, Vitest/jsdom, `@noble/hashes`), Playwright, `jose` (e2e only).

**Spec:** [docs/superpowers/specs/2026-10-31-widget-phase2b-design.md](../specs/2026-10-31-widget-phase2b-design.md). Builds on Phase 2a ([spec](../specs/2026-10-30-widget-phase2a-design.md), shipped 2bac872..7490b8c).

## Global Constraints

- Eligibility: `verdict == inconclusive` ∧ `!cls.Bot` ∧ `NAZR_WIDGET_INTERACTIVE`. The second challenge has the same `id`, `exp`, `kid`, `origin`; `bits = NAZR_POW_BITS + NAZR_WIDGET_INTERACTIVE_EXTRA_BITS`; payload field `stage: "interactive"` (omitted on passive challenges, so 2a payloads and MACs are byte-identical). `/widget/report` rejects a staged challenge as `invalid`; `/widget/interact` requires `stage == "interactive"`. (spec §3.1)
- Report response for an eligible inconclusive: `{ "verdict": "inconclusive", "interactive": { "challenge": "<payload>.<mac>", "bits": N } }`; every other response unchanged. (spec §3.1)
- `POST /widget/interact`: same middleware as `/widget/report`; body `{ challenge, pow, trace }`; always `200 { verdict, token? }` with `verdict` ∈ `interactive | interactive_failed | invalid`; order: bounds → `ParseChallenge` + stage → PoW against the challenge's `bits` (failure → `invalid`) → score → conditional update (`verdict = 'inconclusive' AND token_issued_at IS NULL`; zero rows → `invalid`; store error → `invalid`, logged) → sign on `interactive` (signing failure → `{"verdict":"interactive"}` without token, logged). Failed scores store `interactive_failed` with the trace and fired rules, so there is one attempt per challenge. (spec §3.3)
- Trace fields and bounds: `shown_ms`, `click_ms` int 0..2^31; `input` ∈ `pointer | keyboard`; `trusted` bool; `moves` int 0..200; `path_px` number 0..10^6; `straightness` number 0..1; `pointer_type` ∈ `mouse | touch | pen | ""`; `visible` bool; strings at most 16 chars. (spec §3.2)
- Scoring rules, any firing rule fails: `untrusted_event` (`!trusted`), `too_fast` (`click_ms - shown_ms < 300`), `too_slow` (`> 600000`), `hidden_document` (`!visible`), `no_pointer_path` (pointer with `mouse|pen` and `moves < 3`), `straight_path` (pointer with `mouse|pen` and `straightness >= 0.98`), `malformed_trace` (bounds or enum violation). Touch and keyboard skip the two path rules. Thresholds are package constants. (spec §4)
- Frame: `i=1` in the frame URL means the loader has a container; the UI is one focusable `<button>` ("Verify you are human"; states idle → working → "Verified" / "Verification failed") in a 300×65 box, styled via CSSOM `style` properties only (CSP unchanged: `default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'`); Space/Enter on the focused button counts as a click; the worker starts the interactive PoW when the box is shown; one attempt per challenge. Messages: `{type:"nazr:interactive"}`; `nazr:error` reasons gain `interactive_failed`. (spec §3.2, §4.1)
- Loader: `data-container="#selector"` resolving at mount → shadow host appended to that element and `i=1`; on `nazr:interactive` the iframe becomes `width:300px;height:65px;position:static;border:0`, loses `aria-hidden`, gets `title="nazr verification"`, and `data-interactive-callback` is called (no argument); `reset()` collapses to 0×0 before reloading; `__nazrWidget.state` ∈ `pending | pass | interactive | failed`. No `data-interactive` attribute. (spec §5)
- Token claims unchanged; `verdict` is `"interactive"`. Siteverify adds `interaction` (`{ input, pointer_type, trusted, moves, path_px, straightness, elapsed_ms, signals }`) when the row has one; `MarkWidgetVerified` requires `verdict IN ('pass','interactive')`. (spec §6)
- Migration `00004_widget_interaction.sql`: `ALTER TABLE widget_reports ADD COLUMN interaction jsonb NULL`; Down drops it. Config `NAZR_WIDGET_INTERACTIVE` (`true`), `NAZR_WIDGET_INTERACTIVE_EXTRA_BITS` (`4`, ≥ 0, `PowBits + extra <= 32`). Summary adds `interactive`, `interactive_failed`. (spec §7)
- Commits `type(scope): subject`; scopes `thumbmark`, `api`, `widget`, `demo`, `deploy`, `docs`, `ci`. Run Node commands through mise (`mise exec -- pnpm …`) when the shell's `node` is not 26.

## Review Focus

- **Click before the proof-of-work finishes.** The button shows "working" and the request carries the finished counter; nothing is posted early. (Task 7)
- **Container removed from the DOM after the box is shown.** No exception from the loader; the step simply never completes. (Task 8)
- **`reset()` during the interactive step.** The box collapses to 0×0, `state` returns to `pending`, and a fresh passive run starts. The spec's claim that the abandoned challenge "can no longer be used" is loose: it stays redeemable by whoever holds it until `exp`, which Task 10 corrects in the spec and guide. (Task 8, Task 10)
- **A `pass` or `pow_failed` row targeted with a staged challenge.** Only the server mints staged challenges, and only for inconclusives, but the update must still refuse any row that is not `inconclusive`. (Task 5)
- **Frame without `i=1` receiving an `interactive` offer.** Posts `nazr:error` with `inconclusive`, never renders, never posts to `/widget/interact`. (Task 7)

---

## File structure

- `apps/api/internal/widgettoken/challenge.go`: `Challenge.Stage`.
- `apps/api/internal/config/config.go`: `WidgetInteractive`, `WidgetInteractiveExtraBits`.
- `apps/api/internal/interaction/` (new): `trace.go` (`Trace`, bounds), `score.go` (rules, `Score`, `Rules`), tests.
- `apps/api/migrations/00004_widget_interaction.sql`.
- `apps/api/internal/store/widget.go`: `Interaction` column, `UpgradeWidgetReport`, `MarkWidgetVerified` verdict check, summary counts.
- `apps/api/internal/server/widget.go` (eligibility, offer, stage rejection, `signWidgetToken` verdict parameter), new `interact.go` (endpoint), `siteverify.go` (`interaction` block), `admin.go` (counts), `server.go` (route, `StoreAPI`), `helpers_test.go`, `server_test.go`, new `interact_test.go`.
- `packages/widget/src/`: new `interactive.ts` (UI + trace recorder), `frame.ts`, `entries/frame.ts`, `loader.ts`, tests.
- `apps/demo/`: `widget-host.html`, `src/widget-host.ts`, `e2e/global-setup.ts`, `e2e/widget.spec.ts`.
- Docs: `docs/widget.md`, `docs/protocol.md`, `docs/signals.md`, `docs/configuration.md`, `packages/widget/README.md`, `CLAUDE.md`, the 2b spec.

## Task 1: Challenge stage and configuration

**Files:**
- Modify: `apps/api/internal/widgettoken/challenge.go`, `challenge_test.go`; `apps/api/internal/config/config.go`, `config_test.go`

**Interfaces:**
- Produces: `Challenge.Stage string \`json:"stage,omitempty"\`` (last field); `const StageInteractive = "interactive"`. `config.Config.WidgetInteractive bool` (`env:"NAZR_WIDGET_INTERACTIVE" envDefault:"true"`), `WidgetInteractiveExtraBits int` (`env:"NAZR_WIDGET_INTERACTIVE_EXTRA_BITS" envDefault:"4"`), validated `>= 0` and `PowBits + WidgetInteractiveExtraBits <= 32` with errors naming the variable.

- [ ] **Step 1: Write the failing tests.**
  - `TestChallengeStage`: minting `Challenge{ID:"01HX…", Expires: now+600, Bits: 22, Kid:"k1", Origin:"https://shop.example", Stage: StageInteractive}` round-trips with `Stage == "interactive"`; a challenge minted without a stage has a payload JSON (decode the segment before the `.`) with no `stage` key, and `MintChallenge` of a stage-less value equals the string produced before this change (assert against a literal minted in the test from a fixed secret and fixed fields, so the 2a wire format is pinned).
  - Config table: defaults load as `true` / `4`; `NAZR_WIDGET_INTERACTIVE=false` → `false`; `NAZR_WIDGET_INTERACTIVE_EXTRA_BITS=-1` → error naming the variable; `NAZR_POW_BITS=30` with extra `4` → error naming `NAZR_WIDGET_INTERACTIVE_EXTRA_BITS`; `Redacted()` includes both names.
- [ ] **Step 2: Run** `cd apps/api && go test ./internal/widgettoken ./internal/config` → FAIL.
- [ ] **Step 3: Implement.** Add the field and constant; add the config fields beside the 2a widget fields and the validation beside `NAZR_POW_BITS`'s.
- [ ] **Step 4: Run** → PASS; `gofmt -l .` empty; `go vet ./...`.
- [ ] **Step 5: Commit** `feat(api): challenge stage field and interactive step configuration`.

## Task 2: Interaction scoring package

**Files:**
- Create: `apps/api/internal/interaction/trace.go`, `score.go`, `score_test.go`

**Interfaces:**
- Produces: `type Trace struct { ShownMS int \`json:"shown_ms"\`; ClickMS int \`json:"click_ms"\`; Input string \`json:"input"\`; Trusted bool \`json:"trusted"\`; Moves int \`json:"moves"\`; PathPX float64 \`json:"path_px"\`; Straightness float64 \`json:"straightness"\`; PointerType string \`json:"pointer_type"\`; Visible bool \`json:"visible"\` }`; `func (t Trace) Valid() bool` (the §3.2 bounds and enums); `func Score(t Trace) (ok bool, signals map[string]bool)` (every rule evaluated and recorded, `ok` iff none fired; an invalid trace fires `malformed_trace` and skips nothing else); `type RuleInfo struct { Signal string }`; `func Rules() []RuleInfo` in table order for the docs; constants `MinClickMS = 300`, `MaxClickMS = 600000`, `MinMoves = 3`, `MaxStraightness = 0.98`.

- [ ] **Step 1: Write the failing tests.** `TestScoreRules` table, one row per rule from a clean base trace `{ShownMS: 1000, ClickMS: 2840, Input: "pointer", Trusted: true, Moves: 41, PathPX: 512.3, Straightness: 0.71, PointerType: "mouse", Visible: true}`: base → `ok`, no signals true; `Trusted:false` → `untrusted_event`; `ClickMS: 1299` → `too_fast`; `ClickMS: 601001` → `too_slow`; `Visible:false` → `hidden_document`; `Moves: 2` → `no_pointer_path`; `Straightness: 0.98` → `straight_path`; `PointerType:"touch", Moves:0, Straightness:1` → ok; `Input:"keyboard", PointerType:"", Moves:0, Straightness:1` → ok; `Moves: 201` → `malformed_trace`; `Input:"tap"` → `malformed_trace`; `PointerType:"stylus"` → `malformed_trace`; `Straightness: 1.5` → `malformed_trace`; `PathPX: -1` → `malformed_trace`. `TestRulesOrder`: `Rules()` signals are exactly `[untrusted_event too_fast too_slow hidden_document no_pointer_path straight_path malformed_trace]`.
- [ ] **Step 2: Run** `go test ./internal/interaction` → FAIL (package missing).
- [ ] **Step 3: Implement** with a rule slice `{signal, test func(Trace) bool}` like `classify.rules`.
- [ ] **Step 4: Run** → PASS; vet clean.
- [ ] **Step 5: Commit** `feat(api): interaction trace scoring`.

## Task 3: Migration and store

**Files:**
- Create: `apps/api/migrations/00004_widget_interaction.sql`
- Modify: `apps/api/internal/store/widget.go`, `widget_test.go`, `store_test.go` (`latestMigration = 4`, `TestMigrateSchema` asserts `widget_reports.interaction`)

**Interfaces:**
- Produces: `WidgetReport.Interaction json.RawMessage` (nullable, in `widgetReportCols`, insert and scan); `func (s *Store) UpgradeWidgetReport(ctx, keyID, id, verdict string, interaction json.RawMessage, issuedAt *time.Time) (WidgetReport, error)` running `UPDATE widget_reports SET verdict = $3, interaction = $4, token_issued_at = $5 WHERE id = $1 AND api_key_id = $2::uuid AND verdict = 'inconclusive' AND token_issued_at IS NULL RETURNING <cols>`, `ErrNotFound` on zero rows (and for a non-UUID key); `MarkWidgetVerified`'s first `UPDATE` gains `AND verdict IN ('pass','interactive')` (a row that exists but is not token-bearing → the replay path finds it → return `ErrNotFound` without incrementing `replay_count`: do the increment only `WHERE … AND verdict IN ('pass','interactive')` too); `WidgetSummary.Interactive, InteractiveFailed int64` from `verdict = 'interactive'` / `'interactive_failed'`.

- [ ] **Step 1: Write the failing tests (DB-gated).** `TestUpgradeWidgetReport`: insert an `inconclusive` row; upgrade to `interactive` with `issuedAt = &now` and `{"input":"pointer"}` → returned row has `Verdict "interactive"`, `TokenIssuedAt` set, `Interaction` equal; second upgrade → `ErrNotFound`; a fresh `inconclusive` row upgraded to `interactive_failed` with nil `issuedAt` → `TokenIssuedAt nil`, then a second upgrade → `ErrNotFound`; a `pass` row → `ErrNotFound`; a `pow_failed` row → `ErrNotFound`; wrong key → `ErrNotFound`. `TestMarkWidgetVerifiedRequiresToken`: a `pow_failed` row → `ErrNotFound` and `replay_count` stays 0; an `interactive` row → verified. Extend `TestWidgetSummary` seeds with one `interactive` and one `interactive_failed` row and assert the counts. `TestWidgetReportVerdictRoundTrip` gains `Interaction`.
- [ ] **Step 2: Run** `NAZR_TEST_REQUIRE_DB=1 go test ./internal/store -run 'TestMigrateSchema|TestUpgradeWidgetReport|TestMarkWidgetVerified|TestWidgetSummary|TestWidgetReportVerdictRoundTrip'` → FAIL.
- [ ] **Step 3: Implement.** Migration:

```sql
-- +goose Up
ALTER TABLE widget_reports ADD COLUMN interaction jsonb NULL;
-- +goose Down
ALTER TABLE widget_reports DROP COLUMN interaction;
```

- [ ] **Step 4: Run** `NAZR_TEST_REQUIRE_DB=1 go test -race ./internal/store/...` → PASS; `go build ./...` (the server fake does not yet need the new method).
- [ ] **Step 5: Commit** `feat(api): widget report interaction column and single-use upgrade`.

## Task 4: Report handler offers the interactive challenge

**Files:**
- Modify: `apps/api/internal/server/widget.go`, `server_test.go`, `helpers_test.go` (`mintTestChallenge` gains an optional stage; add `mintTestInteractiveChallenge(t, env, origin, bits) (string, string)`)

**Interfaces:**
- Consumes: `Challenge.Stage`, `StageInteractive`, config fields (Task 1).
- Produces: `widgetOutcome.Interactive *interactiveOffer \`json:"interactive,omitempty"\``; `type interactiveOffer struct { Challenge string \`json:"challenge"\`; Bits int \`json:"bits"\` }`; `func (s *server) interactiveOffer(ch widgettoken.Challenge, secret []byte) *interactiveOffer` (same `ID/Expires/Kid/Origin`, `Bits = PowBits + WidgetInteractiveExtraBits`, `Stage = StageInteractive`, minted with the challenge key's secret); `signWidgetToken(r, keyID, ch, now, verdict string)` (Task 5 passes `"interactive"`); `processWidgetReport` returns `invalid` when `ch.Stage != ""`; the offer is attached iff `verdict == inconclusive && !cls.Bot && s.Cfg.WidgetInteractive` and the insert succeeded.

- [ ] **Step 1: Write the failing tests.** `TestWidgetReportInteractiveOffer`: with `cfg.WidgetPassMaxDanger = 0` and the missing-Accept-Language body (danger 1, bot 1) → `{"verdict":"inconclusive","interactive":{...}}`; the offer's challenge parses with the test secret to `Stage "interactive"`, same `ID`/`Expires`/`Origin` as the input challenge, `Bits == cfg.PowBits + 4`; the stored row is `inconclusive` with `TokenIssuedAt nil`. The webdriver body → `inconclusive` with no `interactive` key. `cfg.WidgetInteractive = false` → no offer. A `pass` report → no offer. `TestWidgetReportRejectsStagedChallenge`: a staged challenge posted to `/widget/report` → `invalid`, nothing stored. Store error on the inconclusive insert → no offer.
- [ ] **Step 2: Run** `go test ./internal/server -run 'TestWidgetReportInteractiveOffer|TestWidgetReportRejectsStaged'` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./internal/server/...` → PASS; `pnpm --filter @nazr/api lint` clean.
- [ ] **Step 5: Commit** `feat(api): widget report offers the interactive challenge to eligible inconclusives`.

## Task 5: `POST /widget/interact`

**Files:**
- Create: `apps/api/internal/server/interact.go`, `interact_test.go`
- Modify: `server.go` (`StoreAPI.UpgradeWidgetReport`, route `POST /widget/interact` with `reportMW` and `s.bodyLimit`, name `"widget_interact"`), `helpers_test.go` (fake `UpgradeWidgetReport` over `f.reports` with the real semantics and an injectable `upgradeErr`)

**Interfaces:**
- Consumes: Tasks 1–4; `interaction.Trace`, `Score` (Task 2); `UpgradeWidgetReport` (Task 3).
- Produces: `verdictInteractive = "interactive"`, `verdictInteractiveFailed = "interactive_failed"`; `type interactBody struct { challenge, pow string; trace interaction.Trace }`; `func parseInteract(raw map[string]any) (interactBody, bool)` (decode `trace` by re-marshalling the map and `json.Unmarshal` into `Trace`, then `Valid()`); `func (s *server) processInteract(r *http.Request) widgetOutcome`; `handleInteract` writes `200` JSON. Stored `Interaction` JSON = the trace fields plus `"signals": {…}` and `"elapsed_ms": click_ms - shown_ms` (one struct `storedInteraction{ Trace; Signals map[string]bool; ElapsedMS int }` with the inline trace fields).

- [ ] **Step 1: Write the failing tests** (`interact_test.go`; seed through a real `/widget/report` call that yields the offer, then POST the offer's challenge with `widgettoken.SolvePoW(id, bits)` and the clean base trace from Task 2).
  - `TestInteractSuccess`: `{"verdict":"interactive","token":…}`; the token parses with claims `Verdict "interactive"`, `ID == id`, `IssuedAt == testNow`; the row is `interactive` with `TokenIssuedAt == testNow` and `Interaction` containing `"input":"pointer"`, `"elapsed_ms":1840`, `"signals":{}`.
  - `TestInteractFailedScore`: `Trusted:false` → `{"verdict":"interactive_failed"}`, no token; row `interactive_failed`, `TokenIssuedAt nil`, `Interaction.signals.untrusted_event == true`; a second POST with the same challenge and a clean trace → `invalid` (one attempt).
  - `TestInteractInvalid` cases, each `invalid` and the row untouched: passive (unstaged) challenge; tampered MAC; expired (`testNow` + 11 min); wrong PoW counter for the interactive bits; `trace` missing; `trace.moves: 201`; `challenge` 513 chars; a staged challenge for a row that is `pass` (seed by minting a staged challenge directly for a pass row's id); a staged challenge for an unknown id; `Signing == nil`.
  - `TestInteractStoreError`: `upgradeErr` set → `invalid`, no token, one Error log line (use a `slog` handler writing to a buffer, as the 2a tests do for the keyring).
  - `TestInteractMiddleware`: missing key → 401/403 as `/widget/report`; rate limited → 429.
- [ ] **Step 2: Run** `go test ./internal/server -run TestInteract` → FAIL.
- [ ] **Step 3: Implement** the spec §3.3 order exactly; reuse `parseWidgetReport`'s bound helpers (`validPow`) and `signWidgetToken(…, verdictInteractive)`.
- [ ] **Step 4: Run** `go test -race ./internal/server/...` → PASS; lint clean.
- [ ] **Step 5: Commit** `feat(api): widget interact endpoint upgrades inconclusive reports`.

## Task 6: Siteverify interaction block and admin counts

**Files:**
- Modify: `apps/api/internal/server/siteverify.go`, `siteverify_test.go`, `admin.go`, `server_test.go`, `helpers_test.go` (fake `MarkWidgetVerified` mirrors the Task 3 verdict rule)

**Interfaces:**
- Consumes: `WidgetReport.Interaction` (Task 3), `storedInteraction` (Task 5).
- Produces: `siteverifyResponse.Interaction *interactionJSON \`json:"interaction,omitempty"\`` where `interactionJSON` has `input`, `pointer_type`, `trusted`, `moves`, `path_px`, `straightness`, `elapsed_ms`, `signals` (unmarshalled from the row's `Interaction`; nil when the column is null or unparsable); `widgetSummaryJSON.Interactive, InteractiveFailed int64` (`interactive`, `interactive_failed`) from `WidgetSummary`.

- [ ] **Step 1: Write the failing tests.** `TestSiteverifyInteractive`: a stored `interactive` row with an `Interaction` JSON and a token signed with `Verdict "interactive"` → `success true`, `verdict "interactive"`, `interaction.input == "pointer"`, `interaction.elapsed_ms == 1840`, `interaction.signals == {}`; a `pass` row → no `interaction` key; a `pow_failed` row with a forged token for its id → `invalid-token` (the fake's `MarkWidgetVerified` refuses it). `TestAdminWidgetSummary` gains the two fields.
- [ ] **Step 2: Run** `go test ./internal/server -run 'TestSiteverifyInteractive|TestAdminWidgetSummary'` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./...` → PASS; lint clean.
- [ ] **Step 5: Commit** `feat(api): siteverify reports the interaction; summary counts interactive verdicts`.

## Task 7: Frame interactive step

**Files:**
- Create: `packages/widget/src/interactive.ts`, `interactive.test.ts`
- Modify: `packages/widget/src/frame.ts`, `frame.test.ts`, `entries/frame.ts`

**Interfaces:**
- Consumes: the Task 4 offer shape and the Task 5 request/response.
- Produces (`interactive.ts`): `interface TraceSummary { shown_ms: number; click_ms: number; input: "pointer" | "keyboard"; trusted: boolean; moves: number; path_px: number; straightness: number; pointer_type: string; visible: boolean }`; `class TraceRecorder { constructor(now: () => number); start(): void; move(ev: { isTrusted: boolean; clientX: number; clientY: number }): void; activate(ev: { isTrusted: boolean; type: string; pointerType?: string }, visible: boolean): TraceSummary }` (samples at most 200 moves; `straightness = chord / path_px`, `1` when fewer than 2 samples; `trusted` false if any recorded event was untrusted; `input` is `keyboard` for `keydown`); `interface InteractiveUI { shown: Promise<void>; activated: Promise<TraceSummary>; setState(s: "working" | "verified" | "failed"): void }`; `function renderInteractive(doc: Document, now: () => number): InteractiveUI` (builds the box and button with the §3.2 copy, styles via `element.style`, wires `pointermove` on `doc`, `pointerdown`/`click` and `keydown` (Space/Enter) on the button, resolves `activated` once).
- Produces (`frame.ts`): `FrameMessage` gains `{ type: "nazr:interactive" }` and reason `interactive_failed`; `FrameDeps` gains `doc: Document | null` and `now: () => number`; after a report answers `inconclusive` with an `interactive` object and `location.search` has `i=1`: post `nazr:interactive`, `renderInteractive`, start `solve(id, offer.bits)` immediately, await `activated`, `setState("working")`, await the solution, POST `/widget/interact` with `{ challenge: offer.challenge, pow, trace }`, then `nazr:token` + `setState("verified")` on `interactive`, else `nazr:error` (`interactive_failed | invalid | network`) + `setState("failed")`. Without `i=1`, or without an offer: `nazr:error` `inconclusive` as before. `entries/frame.ts` passes `doc: document`, `now: () => performance.now()`.

- [ ] **Step 1: Write the failing tests.**
  - `interactive.test.ts` (jsdom): `TraceRecorder` with a fake clock: three trusted moves along a curve then a trusted `pointerdown` with `pointerType "mouse"` → `moves 3`, `path_px > 0`, `straightness < 1`, `trusted true`, `input "pointer"`, `click_ms - shown_ms` equals the clock delta; one untrusted move among trusted ones → `trusted false`; 250 moves → `moves 200`; a trusted `keydown` → `input "keyboard"`, `pointer_type ""`; `visible` passed through. `renderInteractive`: one `<button>` with text "Verify you are human", `tabIndex` 0; a `keydown` `Enter` dispatched on the button resolves `activated` with `input "keyboard"`; a second activation does not resolve twice; `setState("verified")` changes the button text to "Verified"; no `<style>` element and no `style` attribute string containing `<`.
  - `frame.test.ts`: with `?k=nzr_x&i=1` and a fetch answering `{verdict:"inconclusive", interactive:{challenge:"<staged>", bits:12}}` then `{verdict:"interactive", token:"t.o.k"}`: posts are `[nazr:challenge, nazr:interactive, nazr:token]`; the second fetch body is `{challenge: "<staged>", pow: "<solve result>", trace: {…}}` with `trace.input` present; `solve` was called twice (passive bits, then 12). Click before the solution resolves: the second fetch happens only after `solve` resolves and carries its counter. Second response `interactive_failed` → `nazr:error` `interactive_failed`. Without `i=1` and the same offer → `nazr:error` `inconclusive`, one fetch only. Offer absent → unchanged 2a behaviour.
- [ ] **Step 2: Run** `mise exec -- pnpm --filter @nazr/widget test` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS; `mise exec -- pnpm --filter @nazr/widget lint`; root `mise exec -- pnpm typecheck`; `mise exec -- pnpm build --filter=@nazr/widget`.
- [ ] **Step 5: Commit** `feat(widget): interactive step with a behavioural trace in the frame`.

## Task 8: Loader container, resize and state

**Files:**
- Modify: `packages/widget/src/loader.ts`, `loader.test.ts`

**Interfaces:**
- Consumes: `FrameMessage` (Task 7).
- Produces: `NazrWidget.state: "pending" | "pass" | "interactive" | "failed"`; `data-container` and `data-interactive-callback` handling per Global Constraints; `i=1` in the frame URL when the container resolved; `state` becomes `interactive` on `nazr:interactive`, `pass` on a token that arrived without a preceding `nazr:interactive`, `interactive` stays on a token after it, `failed` on any `nazr:error`, `pending` on `reset()`; `reset()` also restores the 0×0 hidden attributes.

- [ ] **Step 1: Write the failing tests** (extend the Phase 2a cases): `data-container="#box"` with a matching element → the shadow host is a child of `#box` and the iframe `src` has `i=1`; container missing → host under `<body>`, no `i`; `nazr:interactive` → iframe style width `300px`, height `65px`, `position: static`, no `aria-hidden`, `title "nazr verification"`, `state "interactive"`, `window.onNazrInteractive` (named by `data-interactive-callback`) called once; a following token keeps `state "interactive"` and fills the input; a token without the interactive message → `state "pass"`; `nazr:error` → `state "failed"`; `reset()` → 0×0 hidden, `aria-hidden` back, `state "pending"`; removing `#box` from the DOM after `nazr:interactive` and then sending a token → no exception, input filled (the form is separate).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS; lint, typecheck, build.
- [ ] **Step 5: Commit** `feat(widget): loader shows the interactive box in a host container`.

## Task 9: Demo and end-to-end verification

**Files:**
- Modify: `apps/demo/widget-host.html` (`<div id="nazr-box"></div>` inside the form), `apps/demo/src/widget-host.ts` (`s.dataset.container = "#nazr-box"`; `__nazrWidget` type gains `state`), `apps/demo/e2e/global-setup.ts` (`NAZR_WIDGET_PASS_MAX_DANGER: "0"`), `apps/demo/e2e/widget.spec.ts`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the failing e2e** (`widget.spec.ts`): a new test that routes `**/widget/report` with `page.route` and continues the request without its `accept-language` header (danger 1, bot 1 → eligible inconclusive); waits for the report response and asserts `verdict "inconclusive"` with an `interactive` object; finds the frame with `page.frame({ url: /\/widget\/v1\/frame/ })` (the iframe sits in a closed shadow root, which locators cannot pierce) and waits for `frame.evaluate(() => [innerWidth, innerHeight])` to equal `[300, 65]`; locates `frame.locator("button")`, takes its `boundingBox()`, moves the mouse along at least ten points into it (`page.mouse.move(x, y, { steps: 10 })` twice with different targets) and clicks; waits for `window.__nazrToken`; asserts the interact response was `verdict "interactive"`, the hidden input holds the token, `__nazrWidget.state === "interactive"`, `jose` verification gives `payload.verdict === "interactive"`, siteverify returns `success true` with `interaction.input === "pointer"` and `interaction.trusted === true`, and the admin summary has `interactive >= 1`. The two Phase 2a tests must still pass with the lower pass threshold (no route in them).
- [ ] **Step 2: Run** `mise exec -- pnpm build --filter=@nazr/widget && mise exec -- pnpm --filter @nazr/api build && NAZR_E2E_DATABASE_URL=… mise exec -- pnpm --filter @nazr/demo test:e2e widget` → FAIL.
- [ ] **Step 3: Implement** the host page and setup changes.
- [ ] **Step 4: Run** → PASS; the full `test:e2e` green; demo lint and typecheck clean.
- [ ] **Step 5: Commit** `test(demo): widget interactive step e2e`.

## Task 10: Documentation and spec amendments

**Files:**
- Modify: `docs/widget.md` (interactive step: container, box, callbacks, `state`, `interactive` verdict and what it does and does not prove, the hosts' verdict check in both snippets, siteverify `interaction`, expiry/reset note that an abandoned challenge stays redeemable until `exp`), `docs/protocol.md` (`POST /widget/interact`, the report's `interactive` object, `interaction` in siteverify, summary fields, verdict values), `docs/signals.md` (an "Interaction rules" table mirroring `interaction.Rules()`), `docs/configuration.md` (two variables; regenerated reference output), `packages/widget/README.md` (`nazr:interactive`, `interactive_failed`, `i` flag, `data-container`), `CLAUDE.md` (one clause in the widget sentence), `docs/superpowers/specs/2026-10-31-widget-phase2b-design.md` (§12 reset bullet corrected as in Review Focus).

- [ ] **Step 1: Write** the docs with names copied from Tasks 2–8.
- [ ] **Step 2: Verify** `mise exec -- pnpm lint:biome` has no errors; every `NAZR_*` in `config.go` appears in `docs/configuration.md`.
- [ ] **Step 3: Verify** the full pipeline: `mise exec -- pnpm lint && mise exec -- pnpm typecheck && mise exec -- pnpm test && mise exec -- pnpm build`; `NAZR_TEST_REQUIRE_DB=1 go test -race ./...` in `apps/api`; the demo e2e against a throwaway Postgres.
- [ ] **Step 4: Commit** `docs: widget interactive step`.
