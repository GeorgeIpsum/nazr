# nazr

[![CI](https://github.com/GeorgeIpsum/nazr/actions/workflows/ci.yml/badge.svg)](https://github.com/GeorgeIpsum/nazr/actions/workflows/ci.yml)

nazr is a self-hostable browser fingerprinting service: a Go API that is wire-compatible with the hosted ThumbmarkJS API, a fork of the ThumbmarkJS client with extra signals, a demo page, and deployment packaging (Docker Compose and an AWS Terraform module). It combines client-side components with what the server observes about the connection itself (TLS ClientHello, HTTP/2 settings, header order, IP intelligence) to produce a stable thumbmark, a visitor id and a bot/danger classification.

## Compatibility promise

The stock `@thumbmarkjs/thumbmarkjs` client works against nazr by setting `api_endpoint` (origin only, no path):

```ts
import { Thumbmark } from "@thumbmarkjs/thumbmarkjs";

const tm = new Thumbmark({
  api_key: "your-api-key",
  api_endpoint: "https://nazr.example.com",
  logging: false,
});
console.log(await tm.get());
```

The fork `@nazr/thumbmark` adds self-host defaults, five more components, and `simple_request` for deployments where a proxy injects the key:

```ts
import { Thumbmark } from "@nazr/thumbmark";

const tm = new Thumbmark({
  api_endpoint: "https://nazr.example.com",
  simple_request: true, // no api_key in the browser; the proxy adds it
  logging: false,
});
```

See the [client README](packages/thumbmark/README.md) and [protocol.md](docs/protocol.md).

An optional embeddable widget collects a second, isolated fingerprint in a cross-origin iframe and correlates it with the page's call by nonce. It also issues a short-lived signed token that your backend verifies with `siteverify` or the JWKS: see [docs/widget.md](docs/widget.md).

## Quick start (60 seconds, Docker Compose)

```bash
docker compose -f deploy/compose/docker-compose.yml up -d --build
for i in $(seq 30); do curl -skf https://localhost/readyz && break; sleep 1; done
docker compose -f deploy/compose/docker-compose.yml exec -T api /nazr keys create --label first
```

The API is at `https://localhost` with a self-signed certificate (use `curl -k`); the loop waits up to 30 seconds for `/readyz` (Compose already starts the API only after PostgreSQL is healthy). Key creation prints the API key, then the siteverify secret, then an `id  prefix  label` line; only the first line is the API key, and both secrets are shown once. To verify the stack end to end, run `pnpm smoke:compose` on a throwaway stack, one freshly brought up for the test: by default (`KEEP=0`) it tears the stack and its data down on exit (including any key you created), so use `KEEP=1 pnpm smoke:compose` to keep it.

## Deploy

- [Docker Compose](docs/deploy-compose.md): single host, self-signed or ACME certificate, optional Redis
- [AWS (Terraform)](docs/deploy-aws.md): NLB TCP passthrough, ECS Fargate, RDS, ACME ([module README](deploy/terraform/aws/README.md))
- [From source](docs/deploy-source.md): Postgres prerequisite, local `plain` mode, a single VM with ACME

## Reference

- [docs/protocol.md](docs/protocol.md): routes, request and response, errors, CORS, connection modes
- [docs/widget.md](docs/widget.md): embeddable widget, signed tokens, siteverify and what its summary detects
- [docs/signals.md](docs/signals.md): components, classification table, IP list sources
- [docs/configuration.md](docs/configuration.md): every `NAZR_*` variable

## Signal status

| Area                   | Status                                                                                                                                               |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Client components (18) | 13 upstream plus 5 added by the fork: `webgpu`, `clienthints`, `clientrects`, `mediaqueries`, `privacy` (full list in [signals.md](docs/signals.md)) |
| TLS                    | JA4 in the fingerprint; JA3 recorded in events only                                                                                                  |
| HTTP/2                 | Akamai-style fingerprint                                                                                                                             |
| HTTP headers           | JA4H (cookie-free in the fingerprint), header order                                                                                                  |
| IP intelligence        | MaxMind geo/ASN, Apple Private Relay, Tor exits, datacenter and VPN lists (v4 and v6); optional FoxIO JA4DB behind a token                           |
| Deferred               | JA4T/TCP, QUIC/HTTP3, extension detection, Private Access Tokens                                                                                     |

## TLS modes

`NAZR_TLS_MODE` decides what the server can see. Details in [protocol.md](docs/protocol.md#connection-modes-and-fingerprint-capture).

| Mode                  | Captured                                                                | Use when                                                                                                                                                                                  |
| --------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `terminate` (default) | JA4 (JA3 in events), HTTP/2 fingerprint, header order for HTTP/2        | nazr is the TLS endpoint (NLB passthrough, a VM with ACME, Compose). Full signal set                                                                                                      |
| `proxied`             | JA4 from a header (`x-ja4`) only; header order as the proxy forwards it | TLS ends at a proxy that computes and forwards JA4. **The listener must be reachable only through the proxy**: anyone who can connect directly can forge the JA4 header and the client IP |
| `plain`               | HTTP/1.1 header order only                                              | Local development and tests                                                                                                                                                               |

## Licensing

The repository is GPL-3.0 ([LICENSE](LICENSE)). `packages/thumbmark` is a fork of [ThumbmarkJS](https://github.com/thumbmarkjs/thumbmarkjs) and carries upstream's MIT notice in [LICENSE.upstream](packages/thumbmark/LICENSE.upstream); the fork's own additions are GPL-3.0.

## Project layout

```
apps/api/            Go API (cmd/nazr: serve, migrate, keys, lists)
apps/demo/           Vite demo page; Playwright e2e in e2e/
packages/thumbmark/  @nazr/thumbmark, the ThumbmarkJS fork
packages/widget/     @nazr/widget, the embeddable loader and frame
deploy/compose/      Docker Compose stack and smoke script
deploy/terraform/aws Terraform module (NLB, ECS Fargate, RDS)
docs/                protocol, signals, configuration, deploy guides
docs/superpowers/    design spec and implementation plans
.github/workflows/   CI and release
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to work on it.
