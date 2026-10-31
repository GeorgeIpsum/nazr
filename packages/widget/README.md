# @nazr/widget

The browser side of the nazr widget. A host page embeds the loader from the nazr origin:

```html
<script src="https://nazr.example/widget/v1/loader.js" data-api-key="nzr_..." data-nonce="..."></script>
```

The loader mounts a hidden, cross-origin iframe inside a closed shadow root and exposes
`window.__nazrWidget = { nonce, ready }`. `data-nonce` is optional; without it the loader
generates one with `crypto.randomUUID()`. The frame computes a thumbmark with `@nazr/thumbmark`
and POSTs `{ challenge, pow, components, clientHash }` to `/widget/report` on the nazr origin.

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
- `{ type: "nazr:token", token }`: the server verdict was `pass`.
- `{ type: "nazr:error", reason }`: `inconclusive`, `pow_failed` or `invalid` relay the server verdict (`invalid` is also sent without a request when the challenge cannot be decoded). `network` covers a non-OK response, a failed fetch, an unparsable body, an unknown verdict, and a failed worker (no proof-of-work, so `network` is the closest reason in the contract).

The frame stays silent when the `k` query parameter or `data-challenge` is missing.

## Embedding and docs

The embedding guide, including correlating the page call with `nonce` and what the server-side summary detects, is [docs/widget.md](../../docs/widget.md). A runnable host page is `apps/demo/widget-host.html`. The package is private and consumed by `apps/api`: its build step (`sync-widget`) copies `dist/` into the Go embed directory, and `NAZR_WIDGET_DIR` serves a directory from disk instead.
