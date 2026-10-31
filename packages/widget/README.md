# @nazr/widget

The browser side of the nazr widget. A host page embeds the loader from the nazr origin:

```html
<script src="https://nazr.example/widget/v1/loader.js" data-api-key="nzr_..."></script>
```

The loader mounts a hidden, cross-origin iframe inside a closed shadow root and exposes
`window.__nazrWidget = { ready, nonce, token, state, reset }`. The nonce is the server-issued challenge
id, set asynchronously: `await window.__nazrWidget.ready` (it resolves with `{ nonce }`) before
reading it. `data-nonce` is ignored with a console warning. The frame computes a thumbmark with
`@nazr/thumbmark`, solves the proof-of-work in a worker and POSTs
`{ challenge, pow, components, clientHash }` to `/widget/report` on the nazr origin; on a `pass`
the server answers with a signed token.

When the script tag sits inside a `<form>`, the loader keeps a hidden input (name `nazr-token`, or
`data-response-field-name`) in sync with the token. `data-callback`, `data-error-callback` and
`data-expired-callback` name global functions called with the token, the failure reason, and
nothing. When a token expires the loader clears the input, calls the expired callback and calls
`reset()`, which fetches a fresh challenge and token.

`data-container` is a CSS selector for an element on the host page. When it resolves, the loader
mounts there (instead of under `<body>`) and asks the frame for the click-to-verify step, which
resizes the iframe to 300x65 and calls `data-interactive-callback` (no argument). The read-only
`window.__nazrWidget.state` is `pending`, `pass`, `interactive` (stays so after the token) or
`failed`; `reset()` collapses the frame and returns it to `pending`.

`data-form` is a CSS selector for the host `<form>` that receives the hidden token input. When it
resolves to a form it wins; otherwise the loader uses the form enclosing its own tag. Set it when a
framework injects the loader outside the form (for example `next/script`, which appends to `<body>`).

## Build outputs

`pnpm --filter @nazr/widget build` writes `dist/`:
- `loader.js`: the loader, served at `/widget/v1/loader.js`.
- `frame.<hash>.js`: the frame bundle; `<hash>` is the first 8 hex digits of its SHA-256.
- `worker.<hash>.js`: the proof-of-work Web Worker, hashed the same way.
- `frame.html`: the frame page, a Go `html/template` with `{{.Bundle}}`, `{{.Worker}}`, `{{.Challenge}}`, `{{.PowBits}}` and `{{.Origin}}` placeholders. They become `data-worker`, `data-challenge`, `data-pow-bits` and `data-origin` on the bundle's script tag.
- `manifest.json`: `{"frame":"frame.<hash>.js","worker":"worker.<hash>.js"}`.

The API server (`apps/api`) embeds these files. It reads `manifest.json` to learn the bundle
names, renders `frame.html` with them as `Bundle` and `Worker`, and serves both under `/widget/v1/`.

## Protocols

Worker: the frame posts `{ id, bits }` (the challenge id and required leading zero bits); the
worker replies `{ counter }`, the smallest decimal counter for which `sha256(id + ":" + counter)`
has at least `bits` leading zero bits (`"0"` when `bits <= 0`).

Frame to parent (`postMessage`, targeted at `data-origin`, or `*` when absent):
- `{ type: "nazr:challenge", id }`: sent first, once the challenge id is decoded.
- `{ type: "nazr:interactive" }`: the frame is showing its click-to-verify box (see below). It comes before the terminal messages.
- `{ type: "nazr:token", token }`: the server verdict was `pass` (or `interactive`, from the interactive step).
- `{ type: "nazr:error", reason }`: `inconclusive`, `pow_failed` or `invalid` relay the server verdict; `interactive_failed` only comes from the interactive step. `invalid` is also sent without a request when the challenge cannot be decoded. `network` covers a non-OK response, a failed fetch, an unparsable body, an unknown verdict, and a failed worker (no proof-of-work, so `network` is the closest reason in the contract).

Interactive step: when the report answers `inconclusive` with an `interactive` offer and the
frame URL carries `i=1` (the loader sets it when it has a visible container), the frame posts
`nazr:interactive`, renders a 300×65 box with one "Verify you are human" button, solves the
offer's harder proof-of-work while recording a trace summary of how the button was reached,
then POSTs `{ challenge, pow, trace }` to `/widget/interact`. It relays `interactive` as
`nazr:token` and `interactive_failed` or `invalid` as `nazr:error` with that reason; anything
else is `network`. Without `i=1` the offer is ignored and the frame sends `inconclusive`.

The frame stays silent when the `k` query parameter or `data-challenge` is missing.

## Embedding and docs

The embedding guide, including verifying the token, correlating the page call with `nonce` and what the server-side summary detects, is [docs/widget.md](../../docs/widget.md). A runnable host page is `apps/demo/widget-host.html`. The package is private and consumed by `apps/api`: its build step (`sync-widget`) copies `dist/` into the Go embed directory, and `NAZR_WIDGET_DIR` serves a directory from disk instead.
