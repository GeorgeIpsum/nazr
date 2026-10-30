# Widget embedding guide

The nazr widget is a small script you embed on your site. It loads a hidden cross-origin iframe from your nazr server, which computes a fingerprint in a browsing context your page's JavaScript cannot reach and reports it straight to nazr. nazr then compares that report with the same visit's `POST /thumbmark` call, matched by a nonce you pass to both. Routes and fields are in [protocol.md](protocol.md#widget); variables are in [configuration.md](configuration.md).

This is Phase 1: isolated collection and a connection-level consistency summary. It does not change the thumbmark, visitor ids or the danger score. A challenge, token and siteverify phase is planned separately.

## Embed

```html
<script src="https://nazr.example.com/widget/v1/loader.js" data-api-key="nzr_..." data-nonce="..."></script>
```

- `data-api-key` is required: the same public key you use for `/thumbmark`. It appears in the frame URL, so it lands in nazr's access logs and browser history, the same exposure as the `x-api-key` header.
- `data-nonce` is optional. Without it the loader generates one with `crypto.randomUUID()`. A nonce you supply must be 1 to 64 printable ASCII characters, or the server ignores it.
- Load it as a classic script (not `type="module"`): the loader reads its own script tag synchronously.
- Place the loader tag before the host code that reads `window.__nazrWidget`, and do not mark it `async`: an async loader may run after your code, which then finds no widget. `defer` is fine only if the host code also runs after it (for example, a module script or another deferred script placed later).
- One widget per page. A second loader on the same page does nothing. The loader never throws and never breaks the host page; a missing key or unavailable `crypto.randomUUID` simply means no widget.
- The iframe sits in a closed shadow root. That deters casual inspection but is not a security boundary: the loader runs in your page's origin and a hostile page script can replace it. What is trustworthy is the frame, whose execution and report your page cannot touch.

The loader exposes `window.__nazrWidget = { nonce, ready }`. `nonce` is the value in use. `ready` is a promise of `{ nonce }` that resolves as soon as the nonce is known; it does not wait for the frame to finish or for the report to be accepted. When the loader did not run (blocked, failed to load, missing key, or no `crypto.randomUUID` without a `data-nonce`), `window.__nazrWidget` is undefined.

### Host Content-Security-Policy

If your page sends a CSP, it must allow the nazr origin in `script-src` (the loader) and `frame-src` (the frame). The loader sizes the iframe with an inline `style` attribute; under a strict `style-src` without `'unsafe-inline'` that attribute is blocked, and the 0×0 iframe becomes a small bordered box in the page flow. The widget still works, but the box is visible.

## Correlate with the page call

Pass the widget's nonce to `@nazr/thumbmark` through the `nonce` option:

```ts
import { getThumbmark } from "@nazr/thumbmark";

// undefined when the loader did not run; the page call still goes ahead.
const nonce = (await window.__nazrWidget?.ready)?.nonce;
const result = await getThumbmark({
  api_key: "nzr_...",
  api_endpoint: "https://nazr.example.com",
  ...(nonce ? { nonce } : {}),
  cache_api_call: false,
});
```

The optional chaining matters: an ad blocker, a CSP or a network error can stop the loader, and an unguarded `window.__nazrWidget.ready` would then throw and skip the page call. A page call without a nonce is simply uncorrelated.

`nonce` is sent as a top-level field of the `POST /thumbmark` body. It is never part of `components`, never in the hash, and not echoed in `options` or the response, so the thumbmark is unchanged. A runnable page is [`apps/demo/widget-host.html`](../apps/demo/widget-host.html) with [`src/widget-host.ts`](../apps/demo/src/widget-host.ts).

Set `cache_api_call: false` when you pass a nonce. By default the client caches the API call's promise; a cached promise sends no request, so the nonce would never reach the server and the page event would stay uncorrelated.

**Stock client caveat.** The stock `@thumbmarkjs/thumbmarkjs` client has no `nonce` option. A page using it still gets the widget report, but its `/thumbmark` events carry no nonce, so they can never be correlated. Use `@nazr/thumbmark` for correlation.

## What the summary shows

`GET /admin/keys/{id}/widget` (admin token) summarises the key's reports and nonce-carrying `/thumbmark` events over the last 30 days; see [protocol.md](protocol.md#admin-api). A report matches the most recent `/thumbmark` event with the same key and nonce within 10 minutes, in either direction, so arrival order does not matter. The verdict is computed when you read the summary and is advisory: it is not part of the danger score.

For a matched pair the summary compares the client IP hash, the raw JA4 string and the raw `User-Agent` string. `ja4_unknown` counts matched reports where either side has no JA4 (every request in `plain` mode). A nonce reused across many reports yields many rows, each matched independently.

It detects:

- a `/thumbmark` call carrying a nonce with no widget report within the window (the iframe was blocked or never ran, or the caller never loaded the page), shown as `events_unmatched`;
- a widget report with no page call carrying the same nonce (a stock client, a cached call, or a forged report), shown as `unmatched`;
- a page call routed through a different IP or TLS stack than the frame (replay of a captured body from a script, or a proxied page call), shown as `ip_mismatch`, `ja4_mismatch` or `ua_mismatch`.

It does not detect in-page JavaScript tampering that spoofs navigator, screen or WebGL values: that page call still shares the browser's IP, JA4 and UA with the frame. Detecting that needs a comparison of components that must be equal across the two contexts, and that subset is not yet known (the iframe legitimately differs on `clientrects`, viewport-sized values, `permissions` and blocked third-party storage). nazr stores the frame's components so the stable subset can be measured on real traffic.

A forged report can only attribute a fabricated fingerprint to a nonce the attacker chose; correlation then flags it as a mismatch against the real page event, or leaves it unmatched. But a forged report sent over the real browser's own connection, with the same nonce as its page call, correlates cleanly: same IP, JA4 and UA. The nonce is opaque and not a secret. That is acceptable in Phase 1 only because the verdict is advisory and unscored; Phase 2 replaces the nonce with single-use challenge ids issued by the server.

## The stored thumbmark is analysis only

The server computes a `thumbmark` for each widget report, but without your client's stabilization options. It is **not** expected to equal the frame's `clientHash` or the page's thumbmark. Do not compare them; it is an analysis value only. A report never creates or touches a visitor.

## Origin scoping

The frame document is served with `Content-Security-Policy: frame-ancestors` set to the key's `allowed_origins` (or `*` when the key has none), so only those origins can embed the widget. The report itself skips the key's origin check, because the frame posts from nazr's own origin, which is never in a key's list.

## Rate limits and storage

Reports count against the key's `rate_limit_per_minute` together with `/thumbmark` calls. Each page view makes one of each, so budget roughly double.

Reports are stored with the same privacy settings as events: `NAZR_STORE_IP` controls the raw address and `NAZR_STORE_COMPONENTS` whether the merged components are kept. They are pruned under `NAZR_EVENT_RETENTION`.

## Serving the assets

The nazr binary embeds the built widget when its assets were synced before the Go build. `pnpm build` builds `@nazr/widget` and the API's build step (`sync-widget`) copies its `dist/` into the Go embed directory before `go build`. The release workflow does this; local builds of the image or binary must do it themselves first:

```bash
pnpm install && pnpm build --filter=@nazr/widget && pnpm --filter @nazr/api sync-widget
# or: pnpm build --filter=@nazr/api, which builds the widget and runs the sync
```

Without it the widget routes return 404 while everything else works. When the widget build is missing, `sync-widget` clears the embed directory and warns, so a stale widget is never embedded.

To serve from disk instead, for development, set `NAZR_WIDGET_DIR`; nazr logs a warning at startup when that directory holds no widget. If no assets are present, the three `GET /widget/v1/*` routes return 404 and the rest of the server is unaffected; `POST /widget/report` always exists.
