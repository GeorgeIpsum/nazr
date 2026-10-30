# @nazr/widget

The browser side of the nazr widget. A host page embeds the loader from the nazr origin:

```html
<script src="https://nazr.example/widget/v1/loader.js" data-api-key="nzr_..." data-nonce="..."></script>
```

The loader mounts a hidden, cross-origin iframe inside a closed shadow root and exposes
`window.__nazrWidget = { nonce, ready }`. `data-nonce` is optional; without it the loader
generates one with `crypto.randomUUID()`. The frame computes a thumbmark with `@nazr/thumbmark`
and POSTs `{ nonce, components, clientHash }` to `/widget/report` on the nazr origin.

## Build outputs

`pnpm --filter @nazr/widget build` writes `dist/`:
- `loader.js`: the loader, served at `/widget/v1/loader.js`.
- `frame.<hash>.js`: the frame bundle; `<hash>` is the first 8 hex digits of its SHA-256.
- `frame.html`: the frame page, a Go `html/template` with a `{{.Bundle}}` placeholder.
- `manifest.json`: `{"frame":"frame.<hash>.js"}`.

The API server (`apps/api`) embeds these files. It reads `manifest.json` to learn the bundle
name, renders `frame.html` with it as `Bundle`, and serves the bundle under `/widget/v1/`.

## Embedding and docs

The embedding guide, including correlating the page call with `nonce` and what the server-side summary detects, is [docs/widget.md](../../docs/widget.md). A runnable host page is `apps/demo/widget-host.html`. The package is private and consumed by `apps/api`: its build step (`sync-widget`) copies `dist/` into the Go embed directory, and `NAZR_WIDGET_DIR` serves a directory from disk instead.
