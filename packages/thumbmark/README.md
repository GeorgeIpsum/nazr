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

## Syncing with upstream

```bash
pnpm --filter @nazr/thumbmark upstream:diff [tag]
```

Prints a unified diff of upstream `src/` (default: the tag in `UPSTREAM`) against
this package, so upstream fixes can be reviewed and ported.

## License

The fork's own additions are licensed under the repository's GPL-3.0. Upstream-derived
code remains MIT, see [LICENSE.upstream](./LICENSE.upstream).
