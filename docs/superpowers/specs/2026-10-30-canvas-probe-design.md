# Consumer canvas probe design

Date: 2026-10-30
Status: approved for planning
Parent spec: [2026-10-21-nazr-design.md](2026-10-21-nazr-design.md)

## 1. Purpose

Let a deployment supply its own canvas-drawing routine whose hashed output
becomes an additional, consumer-controlled signal. nazr's built-in canvas
component uses upstream ThumbmarkJS's public drawing routine, so its expected
output is catalogued (e.g. fingerprint.garden) and anti-detect tooling can
replay it. A routine private to one deployment has no catalogued "right answer"
to forge, which makes it useful as a consistency check: a browser claiming a
given platform should render the deployment's routine the same way its peers do.

The probe is a **side signal only**. It never contributes to the thumbmark
(visitor identity). This is a structural guarantee (section 4), not a
convention, so a low-entropy, unstable, or randomized routine can never break
visitor identity — it can only make the signal itself worthless, which the
entropy guardrail (section 7) surfaces.

## 2. Non-goals

- Making the probe part of the thumbmark. Explicitly out of scope; the
  transport (section 4) makes it impossible by construction.
- Server-side recomputation of the probe. The server has no canvas; it only
  stores and compares the client-supplied hash.
- Non-canvas probes (arbitrary value functions). The API takes a draw callback
  only. A general value-function API is a possible later addition, out of scope
  here.
- Cross-language hash agreement. Unlike the thumbmark, the probe hash is never
  recomputed server-side, so no Go/TS stable-stringify parity is required.

## 3. Client API (`packages/thumbmark`)

A new option on `optionsInterface`:

```ts
interface CanvasProbe {
    /** Drawing routine. Must be deterministic for a given browser/GPU. */
    draw: (ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement) => void;
    /** Canvas size. Defaults match the built-in canvas component. */
    width?: number;  // default 280
    height?: number; // default 20
}

interface optionsInterface {
    // ...existing...
    canvas_probe?: CanvasProbe;
}
```

Behaviour when `canvas_probe` is set:

1. Create a fresh `<canvas>` at the requested (or default) size.
2. Run `draw(ctx, canvas)` **three times** on three fresh canvases and apply the
   existing `getCommonPixels` noise reduction, exactly as the built-in canvas
   component does, so farbling browsers (Brave, Firefox, Safari) yield a stable
   value.
3. Hash the common pixel data with the package's `hash` util to a hex string.
4. Return that string to the caller of `getThumbmark` **out of band** (section
   4): it is attached to the request, not to `components`.

Failure handling: if `draw` throws, or a canvas/2d context is unavailable, the
probe is omitted (treated as absent). `getThumbmark` must never throw or change
its thumbmark because of the probe.

Client-side dev warning (section 7): when the computed probe hash equals the
hash of a blank canvas of the same dimensions — the one case that is always a
misconfiguration — emit a single `console.warn` naming `canvas_probe` and
explaining that it contributed no entropy. This check reuses the same
three-render/common-pixels path on a no-op draw.

The probe is **never** routed through `includeComponent` / `customComponents`,
because those feed `components` and therefore the thumbmark hash.

## 4. Transport (protocol)

The thumbmark request body gains one optional top-level field, a sibling of
`clientHash`, not a member of `components`:

```json
{
  "components": { "...": "..." },
  "clientHash": "…",
  "canvas_probe": "<hex hash, or omitted>"
}
```

Because the field lives outside `components`, it never reaches
`fingerprint.Merge`, the stabilization filter, or `StableStringify`, so it
cannot enter the thumbmark hash. That is the structural guarantee behind
"side signal only".

The response does not echo the probe hash. The probe's effect on the response
is limited to the classification signals block (section 5), when scoring is
enabled.

Validation (server): accept only a bounded hex string (≤ 64 bytes, matching the
existing hash-field caps). Anything else is ignored as absent — never a 400,
so a malformed probe never blocks a fingerprint.

## 5. Classification (opt-in)

Storage (section 6) and the entropy report (section 7) are **always on**. Live
classification scoring is gated behind a new config flag
`NAZR_CANVAS_PROBE_SCORING` (default **off**), so an operator enables scoring
only after the entropy report (section 7) reads `ok`.

When scoring is on and the request carried a probe:

- Define the visit's **cohort** as (user-agent family, JA4 family), both already
  derived by `internal/classify`.
- Run one bounded, indexed query over recent events for this API key in the same
  cohort: find the dominant (most frequent) `canvas_probe` value, with a minimum
  cohort sample size `N_min` (section 7) before the cohort counts as
  "established".
- If the cohort is established and this visit's probe differs from the dominant
  value, set signal `canvas_probe_anomaly` = true, contributing a small bot and
  danger weight (concrete weights fixed in the plan, below `botThreshold` on
  their own so the probe alone cannot flip a classification).
- If the cohort is not established, or the request carried no probe, the signal
  is absent (not false-with-weight).

When scoring is off, `canvas_probe_anomaly` never appears and no cohort query
runs on the hot path.

## 6. Storage

Migration `00005_events_canvas_probe.sql`:

- `ALTER TABLE events ADD COLUMN canvas_probe text;` (nullable; NULL when the
  request carried no probe).
- An index supporting both the cohort dominant-value query (section 5) and the
  per-key entropy aggregate (section 7). Exact columns fixed in the plan; it
  must cover `(api_key_id, created_at)` filtering with `canvas_probe` and
  `visitor_id` available, without a full scan.

The server stores the validated probe string on the event via the existing
`InsertEvent` path (new `Event.CanvasProbe` field, mapped to SQL NULL when
empty, like `JA3Hash`).

## 7. Entropy guardrail ("builder beware")

Two surfaces, plus explicit documentation.

### 7.1 Server, per API key (admin)

A new admin read, `GET /admin/keys/{id}/canvas-probe`, returns a report over a
recent window:

```json
{
  "window_days": 30,
  "visitors": 4210,
  "distinct_probes": 3980,
  "ratio": 0.945,
  "verdict": "too_unique"
}
```

- `visitors` = distinct `visitor_id` with a non-null probe in the window.
- `distinct_probes` = distinct `canvas_probe` values in the window.
- `ratio` = `distinct_probes / visitors`.
- `verdict`:
  - `insufficient_data` when `visitors < N_min`.
  - `too_low` when `ratio ≤ r_low` (nearly everyone shares one value — the
    probe barely distinguishes anyone).
  - `too_unique` when `ratio ≥ r_high` (nearly every visit differs — likely
    accidental per-call randomness, which makes the probe useless as a
    consistency check and would spam `canvas_probe_anomaly`).
  - `ok` otherwise.

Defaults (fixed in the plan, documented in `configuration.md`): `N_min = 50`,
`r_low = 0.05`, `r_high = 0.95`, `window_days = 30`. These are thresholds in
the report logic, not new env vars, unless the plan finds a reason to expose
them.

### 7.2 Client, during development

The `console.warn` of section 3: fires only when the probe equals a blank
canvas, the one unambiguous misconfiguration. One render in one browser cannot
judge cross-visitor entropy, so the client does not attempt a general entropy
heuristic — that is the server's job.

### 7.3 Documentation (required, explicit)

An explicit "builder beware" block in both `packages/thumbmark/README.md` and
`docs/signals.md` stating, in plain terms:

- The probe contributes **nothing** to the thumbmark/visitor identity.
- It is only as private as the bundle. Anyone who loads the page can read the
  routine and replay its output; the UMD obfuscation only slows that down.
- A low-entropy routine (`too_low`) barely distinguishes visitors; a randomized
  one (`too_unique`) is useless as a consistency check and will produce noise.
- Keep `NAZR_CANVAS_PROBE_SCORING` off until the entropy report reads `ok`.

## 8. Affected files

- `packages/thumbmark/src/options.ts` — `CanvasProbe`, `canvas_probe` option.
- `packages/thumbmark/src/components/canvas/index.ts` or a new
  `src/utils/canvasProbe.ts` — reuse the three-render/common-pixels/hash path
  for an arbitrary draw callback and for the blank-canvas baseline.
- `packages/thumbmark/src/functions/api.ts` — attach `canvas_probe` to the
  request body (top level, not in `components`).
- `apps/api/internal/server/thumbmark.go` — parse/validate `canvas_probe`;
  thread into the event and (when scoring on) classification.
- `apps/api/internal/store/events.go` — `Event.CanvasProbe`; INSERT column.
- `apps/api/migrations/00005_events_canvas_probe.sql` — column + index.
- `apps/api/internal/store/` — cohort dominant-value query; per-key entropy
  aggregate query.
- `apps/api/internal/classify/classify.go` — `canvas_probe_anomaly` signal and
  weights (consumed only when scoring on; the signal is computed in the server
  from the store query and passed in, keeping `classify` free of DB access).
- `apps/api/internal/config/config.go` — `NAZR_CANVAS_PROBE_SCORING` (bool,
  default false).
- `apps/api/internal/server/admin.go` + `server.go` — the canvas-probe report
  route, behind the existing admin middleware.
- Docs: `packages/thumbmark/README.md`, `docs/protocol.md`, `docs/signals.md`,
  `docs/configuration.md`.

## 9. Review focus (inputs no single task's happy path exercises)

- **`draw` throws / no 2d context.** Probe omitted, fingerprint unaffected.
- **Malformed `canvas_probe` on the wire** (non-hex, over-long, wrong type).
  Ignored as absent; never a 400.
- **Probe present but scoring off.** Stored; no cohort query; no signal.
- **Cohort below `N_min`.** `insufficient_data` / signal absent; no divide-by-
  zero in `ratio` when `visitors == 0`.
- **Farbling browser** (Brave/Firefox/Safari). Three-render common-pixels keeps
  the probe stable across calls, same as the built-in canvas component.
- **Probe equals blank canvas.** Client `console.warn` fires exactly once.
- **Stock `@thumbmarkjs/thumbmarkjs` client** (no `canvas_probe`). Unchanged:
  no field sent, server stores NULL, existing specs still pass.

## 10. Backward compatibility

- No change to the thumbmark hash for any existing client; `canvas_probe` is
  additive and optional on the wire.
- Existing fixtures (`apps/api/testdata/fixtures`) are unaffected: the probe is
  not a component and does not touch `StableStringify`.
- Migration is purely additive (new nullable column).
