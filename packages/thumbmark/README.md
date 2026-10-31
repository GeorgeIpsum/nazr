# @nazr/thumbmark

A self-hostable browser fingerprinting client. It is a fork of
[ThumbmarkJS](https://github.com/thumbmarkjs/thumbmarkjs) v1.12.0 that talks to a
nazr API instead of the hosted ThumbmarkJS service.

## Attribution

This package is derived from ThumbmarkJS by Ilkka Peltola, released under the MIT
license. The original license text is kept in [LICENSE.upstream](./LICENSE.upstream).
The upstream tag this fork is based on is recorded in [UPSTREAM](./UPSTREAM).

## Install

```bash
pnpm add @nazr/thumbmark
```

## Usage

```ts
import { Thumbmark } from "@nazr/thumbmark";

const tm = new Thumbmark({
    api_endpoint: "https://nazr.example.com",
    api_key: "your-api-key", // or `simple_request: true` when a proxy injects the key
});
const result = await tm.get();
console.log(result.thumbmark, result.visitorId);
```

Without `api_key` (or `simple_request`) no server call is made: the thumbmark is
computed locally, and `info` and `visitorId` are absent from the result.

When `api_endpoint` is set, the thumbmark URL is `<api_endpoint>/thumbmark`, the
log URL is `<api_endpoint>/log` and the beacon URL is `<api_endpoint>/beacon`. A
trailing slash on `api_endpoint` is ignored. A path in `api_endpoint` is used
verbatim as the thumbmark URL, with `/log` and `/beacon` appended to it.

## Canvas probe

`canvas_probe` lets you supply your own canvas drawing routine as an extra consistency check. When set, the client runs `draw` three times, applies common-pixels noise reduction, hashes the result and sends the hash.

```ts
const tm = new Thumbmark({
    api_endpoint: "https://nazr.example.com",
    api_key: "your-api-key",
    canvas_probe: {
        draw: (ctx, canvas) => {
            ctx.font = "16px serif";
            ctx.fillStyle = "#f60";
            ctx.fillRect(10, 10, 80, 30);
            ctx.fillStyle = "#069";
            ctx.fillText("my-site probe", 12, 32);
        },
        width: 200, // optional
        height: 50, // optional
    },
});
```

The hash is sent as a top-level `canvas_probe` field on `POST /thumbmark`, never inside `components`. The server stores it and, only if the operator enables `NAZR_CANVAS_PROBE_SCORING`, compares it with the visitor's cohort to raise `canvas_probe_anomaly`. See [signals.md](../../docs/signals.md#consumer-canvas-probe-and-the-entropy-report).

**Builder beware.**
- The probe contributes nothing to the thumbmark or visitor identity.
- It is only as private as the bundle. Anyone who loads the page can read the routine and replay its output; the UMD obfuscation only slows that down.
- A low-entropy routine (`too_low`) barely distinguishes visitors. A randomized one (`too_unique`) is useless as a consistency check and will produce noise.
- Keep `NAZR_CANVAS_PROBE_SCORING` off until the entropy report (`GET /admin/keys/{id}/canvas-probe`) reads `ok`.

Caching caveat: when `cache_api_call` is on and a cached or in-flight API response short-circuits the request, a probe passed on that call is not sent.

## Builds

| File                    | Format                    | Readable       | Source map |
| ----------------------- | ------------------------- | -------------- | ---------- |
| `dist/thumbmark.esm.js` | ES module                 | yes, minified  | yes        |
| `dist/thumbmark.cjs`    | CommonJS                  | yes, minified  | yes        |
| `dist/thumbmark.umd.js` | UMD, global `ThumbmarkJS` | no, obfuscated | no         |

Bundlers resolve the ESM or CJS build through `exports`. The UMD build is the
drop-in `<script>` bundle served from CDNs, and it is obfuscated with
[javascript-obfuscator](https://github.com/javascript-obfuscator/javascript-obfuscator)
to resist analysis: rc4-encoded string array, mangled names, control-flow
flattening, light dead-code injection, self-defending code and a one-shot
debugger trap. It produces the same components and thumbmark as the ESM build,
runs under a `script-src 'self'` Content Security Policy, and is roughly 10x
larger gzipped. Options live in `scripts/obfuscate.mjs`; `e2e/obfuscated-umd.spec.ts`
checks equivalence, CSP and that literals are hidden.

Component keys stay readable in the UMD build. The obfuscator will not move the
keys of an object whose values contain arrow functions, and the keys are sent in
plain JSON on every request regardless.

## Components

Upstream (13): `audio`, `canvas`, `fonts`, `hardware`, `locales`, `math`,
`permissions`, `plugins`, `screen`, `speech`, `system`, `webgl`, `webrtc`.

Added by nazr (5): `webgpu`, `clienthints`, `clientrects`, `mediaqueries`, `privacy`.
Each returns `null` when its API is unavailable, so the key is omitted, except `privacy`, which always returns an object.

## Differences from upstream

- `defaultOptions.logging` is `false`.
- Logging posts to `${api_endpoint}/log`; the beacon default is `${api_endpoint}/beacon`.
  Without `api_endpoint`, upstream's hosted defaults are used.
- The experimental payload fetch from `experimental.thumbmarkjs.com` is removed;
  `logThumbmarkData` sends `experimental: null`.
- Five new components (see above) and matching stabilization rules.
- Extra result types: `classification.private_relay`, `uniqueness.visitors_sharing`,
  `uniqueness.visitors_total`.
- `hash` is additionally exported from the package entry point.
- ESLint is replaced by Biome; the package manager is pnpm.
- The UMD build is obfuscated and ships without a source map (see Builds).

## Syncing with upstream

```bash
pnpm --filter @nazr/thumbmark upstream:diff [tag]
```

Prints a unified diff of upstream `src/` (default: the tag in `UPSTREAM`) against
this package, so upstream fixes can be reviewed and ported.

## License

The fork's own additions are licensed under the repository's GPL-3.0. Upstream-derived
code remains MIT, see [LICENSE.upstream](./LICENSE.upstream).
