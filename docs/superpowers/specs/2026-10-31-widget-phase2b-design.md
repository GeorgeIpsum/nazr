# Turnstile-style widget, Phase 2b: interactive step for inconclusive verdicts

Date: 2026-10-31
Status: approved for planning
Parent spec: [2026-10-21-nazr-design.md](2026-10-21-nazr-design.md)
Builds on: [2026-10-30-widget-phase2a-design.md](2026-10-30-widget-phase2a-design.md)
(shipped 2bac872..7490b8c)

## 1. Purpose

Phase 2a issues a token only on a `pass` verdict. A visitor whose report is
`inconclusive` gets nothing but an error callback, which leaves real people on
Tor, VPNs, datacenter egress or with a timezone that disagrees with their IP
without a way through. Phase 2b adds a visible, click-to-verify step inside
the frame for those visitors: the frame shows a button, records how the
visitor interacts with it, solves a harder proof-of-work, and nazr issues a
token whose `verdict` claim is `interactive`. Hosts decide what an
interactive token is worth; the passive evidence stays attached to the report
and is returned by siteverify as before.

Decisions taken during design:

- **Interaction:** click-to-verify with behavioural evidence. No puzzles.
- **Trigger:** automatic. The frame escalates on its own when the server
  offers the step; a host enables it by giving the box somewhere to render.
- **Placement:** a host-provided container only. Without `data-container`
  the step is skipped and Phase 2a behaviour applies.
- **Eligibility:** reputation-only inconclusives. A report whose bot score
  reached the classifier's threshold (webdriver, headless UA, UA/TLS
  mismatch, automation-shaped HTTP/2) is never offered the step, because a
  click cannot refute automation evidence: driven browsers produce trusted
  events.

## 2. Non-goals

- No puzzles, images, audio or arithmetic.
- No localisation or theming beyond the box size. The copy is English.
- No retry within one challenge. A failed attempt ends with the challenge;
  the host's `reset()` (or token expiry) starts a fresh passive run.
- No adaptive difficulty. The interactive cost is one deployment-wide
  setting above the passive cost.
- No rescue for automation-flagged visitors (section 1).
- No scoring of the interaction into the live danger score, `events` or
  `visitors`.
- The trace is self-reported by the frame. It rejects naive scripts; it
  does not identify a driven browser. That limit is why the token says
  `interactive` rather than `pass`.

## 3. Flow

```
Host page                                       nazr origin
  <script ... data-api-key data-container="#nazr-box">
    loader: container found -> frame URL gets i=1
                                                GET /widget/v1/frame?k=&i=1       (i ignored by the server)
                                                POST /widget/report {challenge, pow, components, clientHash}
                                                  -> 200 {verdict:"inconclusive",
                                                          interactive:{challenge, bits}}   (eligible only)
    <- {type:"nazr:interactive"}                frame: renders the button, starts the
         loader: iframe 300x65 in the container        harder proof-of-work in the worker
    visitor clicks (or Space/Enter)             frame: builds the trace summary
                                                POST /widget/interact {challenge, pow, trace}
                                                  -> 200 {verdict:"interactive", token}
    <- {type:"nazr:token", token}               or {verdict:"interactive_failed"} / {verdict:"invalid"}
    <- {type:"nazr:error", reason}
```

### 3.1 Eligibility and the interactive challenge (report handler)

After the Phase 2a classification, a report whose verdict is `inconclusive`
is **eligible** when the classifier's `Bot` output is false (bot score below
the threshold) and `NAZR_WIDGET_INTERACTIVE` is `true`. For an eligible
report the handler mints a second challenge with the Phase 2a format and
the same `id`, `exp`, `kid` and `origin`, with:

- `bits` = `NAZR_POW_BITS + NAZR_WIDGET_INTERACTIVE_EXTRA_BITS`;
- a new payload field `stage: "interactive"`. Passive challenges omit the
  field, so Phase 2a payloads and MACs are unchanged.

The report response becomes
`{ "verdict": "inconclusive", "interactive": { "challenge": "<payload>.<mac>", "bits": N } }`.
Ineligible inconclusives, and every other verdict, answer exactly as in
Phase 2a. The stored report row is unchanged at this point (`verdict =
'inconclusive'`, no `token_issued_at`).

`POST /widget/report` rejects a challenge carrying `stage` as `invalid`, and
`POST /widget/interact` requires `stage == "interactive"`, so the cheaper
passive challenge can never be presented to the interactive endpoint and
the interactive one cannot start a passive report.

### 3.2 The frame's interactive step

- **Rendering decision.** The loader adds `i=1` to the frame URL when
  `data-container` resolves to an element at mount time. The server ignores
  `i`. A frame without `i=1` that receives an `interactive` object answers
  the loader with `nazr:error` reason `inconclusive`, as in Phase 2a.
- **Trigger.** With `i=1` and an `interactive` object, the frame posts
  `{ type: "nazr:interactive" }` to the loader and renders its UI.
- **UI.** A 300×65 box containing one focusable `<button>` labelled
  "Verify you are human" with states idle → working → verified ("Verified")
  or failed ("Verification failed"). The DOM is built with element calls and
  styled through CSSOM `style` properties, so the frame CSP stays
  `default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'`
  with no `style-src`. System font, a text checkmark, no images. Pressing
  Space or Enter on the focused button counts as a click.
- **Proof-of-work.** The worker starts solving the interactive challenge the
  moment the box is shown, in parallel with the person reading it. The
  button shows "working" until both the click and the solution exist.
- **Trace.** From the moment the box is shown until the activating event the
  frame listens on its own document for `pointermove` (sampled, at most 200
  points), `pointerdown`/`pointerup`/`click` on the button and `keydown` on
  the button, recording `isTrusted` on every event. It submits a summary:

  | field          | type    | meaning                                                   |
  |----------------|---------|-----------------------------------------------------------|
  | `shown_ms`     | int     | `performance.now()` when the box was shown                |
  | `click_ms`     | int     | `performance.now()` of the activating event               |
  | `input`        | string  | `pointer` or `keyboard`                                   |
  | `trusted`      | bool    | every recorded event had `isTrusted == true`              |
  | `moves`        | int     | number of `pointermove` samples (0..200)                  |
  | `path_px`      | number  | summed distance between consecutive samples (≥ 0)         |
  | `straightness` | number  | chord length / `path_px` (0..1; 1 when `moves < 2`)       |
  | `pointer_type` | string  | `mouse`, `touch`, `pen` or `""` for keyboard               |
  | `visible`      | bool    | `document.visibilityState == "visible"` at the click      |

- **Submit.** `POST /widget/interact` with `{ challenge, pow, trace }` and
  the same `x-api-key`. Response `200 { verdict, token? }`. On `interactive`
  the frame posts `nazr:token`; otherwise `nazr:error` with reason
  `interactive_failed`, `invalid` or `network` (fetch failure, non-200, or
  unparsable JSON). One attempt per challenge.

### 3.3 `POST /widget/interact`

Same middleware as `/widget/report` (key, revocation, rate limit, key touch,
origin check skipped). Always `200 { "verdict": v, "token"?: jws }` after the
middleware, with `v` ∈ `interactive | interactive_failed | invalid`. Steps:

1. Parse the body: `challenge` 1..512 chars, `pow` 1..32 decimal digits,
   `trace` an object whose fields match section 3.2's table and bounds
   (`shown_ms`, `click_ms` 0..2^31, `moves` 0..200, `path_px` 0..10^6,
   `straightness` 0..1, strings at most 16 chars). Any failure → `invalid`,
   nothing stored.
2. `ParseChallenge` as in Phase 2a, then require `stage == "interactive"`.
   Failure → `invalid`.
3. Verify the proof-of-work against the challenge's `bits`. Failure →
   `invalid` (the frame cannot reach this state honestly; there is no
   separate `pow_failed` for the interactive step).
4. Score the trace (section 4) → `ok` and the fired rule names.
5. One conditional update:

   ```sql
   UPDATE widget_reports
      SET verdict = $3, interaction = $4, token_issued_at = $5
    WHERE id = $1 AND api_key_id = $2
      AND verdict = 'inconclusive' AND token_issued_at IS NULL
   RETURNING ...
   ```

   with `$3` = `interactive` or `interactive_failed`, `$4` the trace summary
   plus the fired rules, `$5` = now on success and NULL on failure. Zero
   rows (missing, already attempted, not inconclusive) → `invalid`, nothing
   stored. A store error → `invalid`, logged, no token.
6. On `interactive`, sign the Phase 2a token with `verdict: "interactive"`.
   A signing failure answers `{"verdict":"interactive"}` without a token and
   logs, as the report handler does.

Because step 5 is the only write and it requires `verdict = 'inconclusive'`,
each challenge gets exactly one interactive attempt, and a passive `pass`
row can never be downgraded or re-issued.

## 4. Interaction scoring

A new pure package `internal/interaction` exposes
`Score(t Trace) (ok bool, signals map[string]bool)` with a rule table
mirrored in `docs/signals.md`. Every rule that fires is recorded; any firing
rule fails the attempt, except `straight_path`, which is advisory (see
Amendments).

| signal                 | fires when                                                               |
|------------------------|--------------------------------------------------------------------------|
| `untrusted_event`      | `trusted == false`                                                       |
| `too_fast`             | `click_ms - shown_ms < 300`                                              |
| `too_slow`             | `click_ms - shown_ms > 600000` (ten minutes, the challenge window)       |
| `hidden_document`      | `visible == false`                                                       |
| `no_pointer_path`      | `input == "pointer"`, `pointer_type` is `mouse` or `pen`, and `moves < 3` |
| `straight_path`        | `input == "pointer"`, `pointer_type` is `mouse` or `pen`, and `straightness >= 0.98` |
| `malformed_trace`      | a field is outside its bounds or `input`/`pointer_type` is not a listed value |

Touch (`pointer_type == "touch"`) and keyboard activation skip
`no_pointer_path` and `straight_path`: a tap has no path and a keyboard user
has no pointer. The thresholds are constants in the package, not
configuration. `straight_path` is advisory: it is recorded but does not fail
the attempt, because the frame observes only moves over its own box.

## 5. Loader and host contract

- **`data-container="#selector"`.** When it resolves to an element at mount
  time the loader appends its shadow host to that element instead of
  `<body>` and adds `i=1` to the frame URL. Otherwise Phase 2a behaviour
  applies unchanged. There is no `data-interactive` attribute: the container
  is the opt-in.
- **Showing the box.** On `nazr:interactive` the loader sets the iframe to
  `width:300px; height:65px; position:static; border:0`, removes
  `aria-hidden`, sets `title="nazr verification"`, and calls the global
  named by `data-interactive-callback` (no argument) when present, so a host
  can scroll the box into view. After `nazr:token` or `nazr:error` the box
  stays visible showing the frame's own state. `reset()` collapses it back
  to 0×0 before reloading the frame.
- **Messages.** `FrameMessage` gains `{ type: "nazr:interactive" }`;
  `nazr:error` gains the reason `interactive_failed`. The `source` and
  `origin` filter, the hidden input, `data-callback`,
  `data-error-callback`, `data-expired-callback`, expiry and reset are
  unchanged.
- **`window.__nazrWidget`** gains a read-only `state`:
  `"pending" | "pass" | "interactive" | "failed"`, set from the messages
  (`failed` on any `nazr:error`; back to `pending` on `reset()`), so a host
  can tell which path produced the token without decoding it.

## 6. Token and siteverify

- The token's claims are those of Phase 2a; `verdict` is `"interactive"`.
  The guide tells hosts to check `verdict` against the set they accept and
  shows that check in the `jose` and `golang-jwt/jwt/v5` snippets.
- Siteverify is unchanged in its steps. The response's `verdict` is
  `interactive` for such tokens; `classification` and `signals` still carry
  the passive evidence; a new `interaction` block carries the stored trace
  summary and the fired rules when the row has one:

  ```json
  "interaction": { "input": "pointer", "pointer_type": "mouse", "trusted": true,
                   "moves": 41, "path_px": 512.3, "straightness": 0.71,
                   "elapsed_ms": 1840, "signals": {} }
  ```

- `store.MarkWidgetVerified` is tightened to require
  `verdict IN ('pass', 'interactive')`, closing a Phase 2a deferred item: a
  row that never earned a token cannot be marked verified even if a token
  for its id were forged.

## 7. Storage, configuration, admin

- Migration `00004_widget_interaction.sql` (additive):
  `ALTER TABLE widget_reports ADD COLUMN interaction jsonb NULL`. Down drops
  it.
- `widget_reports.verdict` gains the values `interactive` and
  `interactive_failed`.
- `store.UpgradeWidgetReport(ctx, keyID, id, verdict string, interaction json.RawMessage, issuedAt *time.Time) (WidgetReport, error)`
  performs the section 3.3 update and returns `ErrNotFound` on zero rows.
- The admin summary `GET /admin/keys/{id}/widget` adds `interactive` and
  `interactive_failed` (counts by verdict). `verified` and `replayed` already
  include interactive tokens.
- Configuration (`docs/configuration.md`):

  | variable                              | default | meaning                                                        |
  |---------------------------------------|---------|----------------------------------------------------------------|
  | `NAZR_WIDGET_INTERACTIVE`             | `true`  | offer the interactive step to eligible inconclusive reports    |
  | `NAZR_WIDGET_INTERACTIVE_EXTRA_BITS`  | `4`     | added to `NAZR_POW_BITS` for the interactive proof-of-work; validated so the sum is at most 32 |

## 8. Security and privacy

- **Binding.** The interactive challenge is MAC-bound to the passive
  challenge's id and expiry. It cannot be minted by a client, cannot be used
  before the passive row exists, and the conditional update spends it
  exactly once. The stage field stops a passive challenge from being
  upgraded, so the interactive cost is always paid.
- **What the trace proves.** Nothing about driven browsers: Playwright and
  CDP produce trusted events and can move a pointer. The trace rejects
  scripts that post a canned click, and the eligibility rule keeps
  automation-flagged reports out of the step. Hosts accept `interactive`
  tokens knowingly, and siteverify shows the passive signals beside the
  interaction block.
- **Bounds.** Every trace field is range-checked before scoring and
  storage, so a hostile body cannot inflate the row or the log.
- **No new personal data.** The trace summary holds counts and durations,
  not coordinates. Raw samples never leave the frame.
- **Operator control.** `NAZR_WIDGET_INTERACTIVE=false` removes the surface
  deployment-wide; a host removes it per page by omitting `data-container`.
- All queries stay parameterized and scoped by `api_key_id`.

## 9. Changes to Phase 2a behaviour

- `POST /widget/report` response gains the optional `interactive` object on
  eligible inconclusives; every other response is unchanged.
- The challenge payload gains the optional `stage` field.
- New route `POST /widget/interact`.
- Loader: `data-container`, `data-interactive-callback`, `__nazrWidget.state`,
  the `nazr:interactive` message and the `interactive_failed` reason.
- Token `verdict` may be `interactive`. Siteverify adds `interaction`.
- `MarkWidgetVerified` requires a token-bearing verdict.
- Admin summary adds two counts.

## 10. Affected files

- `packages/widget/`: `src/frame.ts` (interactive object, UI, trace,
  interact request), new `src/interactive.ts` (UI and trace collection, so
  `frame.ts` stays an orchestrator), `src/loader.ts` (container, resize,
  `state`), `src/entries/frame.ts` (`i` flag), tests.
- `apps/api/internal/widgettoken/challenge.go`: `Stage` field.
- `apps/api/internal/interaction/` (new): `Trace`, `Score`, rule table,
  tests.
- `apps/api/internal/server/widget.go`: eligibility and the interactive
  challenge in the report response; new `interact.go`: the endpoint;
  `siteverify.go`: `interaction` block; `admin.go`: counts.
- `apps/api/internal/store/widget.go`: `UpgradeWidgetReport`, `interaction`
  column, summary counts, `MarkWidgetVerified` verdict check.
- `apps/api/migrations/00004_widget_interaction.sql`.
- `apps/api/internal/config/config.go`: the two variables.
- Docs: `docs/widget.md`, `docs/protocol.md`, `docs/signals.md`,
  `docs/configuration.md`, `packages/widget/README.md`, `CLAUDE.md`.
- Demo: `apps/demo/widget-host.html` (`<div id="nazr-box">`),
  `src/widget-host.ts` (`data-container`), e2e.

## 11. Testing

- `internal/interaction`: one trace per rule, plus the touch and keyboard
  exemptions and a clean mouse trace that passes.
- Server: the report handler mints a staged challenge only for eligible
  inconclusives (a webdriver report gets none; a danger-only report with
  `NAZR_WIDGET_PASS_MAX_DANGER=0` gets one; `NAZR_WIDGET_INTERACTIVE=false`
  gets none); `/widget/interact` matrix: success with claims
  `verdict:"interactive"` and `token_issued_at` set; each failing rule →
  `interactive_failed` stored with the fired signal; a second attempt →
  `invalid`; a passive challenge → `invalid`; an expired challenge →
  `invalid`; a row that is `pass` or `pow_failed` → `invalid`; store error →
  `invalid` with no token; `/widget/report` with a staged challenge →
  `invalid`. Siteverify returns the `interaction` block for an interactive
  row and omits it otherwise; `MarkWidgetVerified` rejects a `pow_failed`
  row.
- Store (Postgres): the upgrade's conditional update, the summary counts,
  the migration columns.
- Widget: the frame renders the UI only with `i=1`; the trace summary from
  synthetic events flags `trusted:false`; keyboard activation produces
  `input:"keyboard"`; messages in order; the loader places the host in the
  container, resizes on `nazr:interactive`, exposes `state`, collapses on
  `reset()`, and ignores foreign messages as before.
- E2e: a second test key run where the server has
  `NAZR_WIDGET_PASS_MAX_DANGER=0` and the Playwright context sends no
  `Accept-Language` header (danger 1, bot 1 → eligible inconclusive);
  Playwright moves the mouse along a curve into the box and clicks; the test
  verifies the token's `verdict` is `interactive`, the hidden input is
  filled, `__nazrWidget.state` is `interactive`, siteverify returns the
  `interaction` block, and the admin summary counts one `interactive`.

## 12. Review focus (inputs no happy-path test exercises)

- **Passive challenge presented to `/widget/interact`**: `invalid`, nothing
  stored, no token.
- **Interactive challenge presented to `/widget/report`**: `invalid`.
- **Second interactive attempt on the same id**: `invalid`; the first
  outcome stands.
- **Trace with a single untrusted event** among trusted ones: `untrusted_event`,
  `interactive_failed`.
- **Touch tap with zero moves** and **keyboard activation**: pass the
  movement rules.
- **Click before the proof-of-work finishes**: the frame waits; the request
  carries the finished counter.
- **Box shown but `data-container` removed from the DOM before the click**:
  no crash, the step times out at `exp`.
- **`reset()` during the interactive step**: box collapses and a new passive
  run starts with a new id. The abandoned interactive challenge is not
  revoked: its row is still inconclusive, so whoever holds it can redeem it
  until `exp`.
- **`NAZR_WIDGET_INTERACTIVE=false` on one instance of several**: that
  instance offers no step; others do; tokens from either verify everywhere.
- **Interactive token at siteverify after the key rotated**: verifies
  within the grace, like passive tokens.

## 13. Backward compatibility

- Hosts without `data-container` see no change: the loader stays 0×0 and an
  inconclusive report still fires the error callback with `inconclusive`.
- The report response's `interactive` object is additive; Phase 2a frames
  (cached up to 300 s) ignore it.
- Tokens with `verdict:"pass"` are unchanged; hosts that check
  `verdict == "pass"` reject interactive tokens, which is the safe default.
- The migration is additive; existing rows have `interaction = NULL`.

## Amendments

Recorded 2026-10-31, after implementation.

- **§4, `straight_path` is advisory.** It is evaluated and recorded in the
  stored and reported `signals`, but it never fails the attempt, because the
  frame observes only moves over its own box, too short a path to fail a
  visitor on.
- **§12, reset.** An abandoned interactive challenge stays redeemable by
  whoever holds it until `exp`; `reset()` does not invalidate it.
