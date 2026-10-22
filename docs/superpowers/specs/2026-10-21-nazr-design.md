# nazr design

Date: 2026-10-21
Status: approved for planning

## 1. Purpose

nazr is a self-hostable browser fingerprinting service. It consists of:

- a Go API that is wire-compatible with the hosted ThumbmarkJS API, so the stock
  `@thumbmarkjs/thumbmarkjs` client works against it by setting `api_endpoint`;
- a fork of the ThumbmarkJS client, published as `@nazr/thumbmark`, with extra
  client-side signals and defaults that point at a self-hosted API;
- deployment packaging: Dockerfile, Docker Compose, and an AWS Terraform module;
- a demo page for exercising the client against an API.

Intended use: (a) a drop-in for the author's own apps for fraud and abuse
detection, and (c) an open-source alternative others can self-host. Repository
license is GPL-3.0. The forked client retains upstream's MIT notice.

## 2. Non-goals (v1)

- TCP/IP fingerprinting (JA4T): requires packet capture or eBPF and does not
  survive a load balancer cleanly.
- QUIC / HTTP/3 fingerprinting.
- Chrome extension detection.
- Private Access Token issuance.
- Multi-tenant signup, dashboards, billing.
- SQLite storage.

## 3. Repository layout

```
nazr/
├── apps/
│   ├── api/                 Go module. cmd/nazr with subcommands:
│   │                        serve, migrate, keys {create,list,revoke}, lists refresh
│   │   ├── cmd/nazr/
│   │   ├── internal/        one package per concern (see 3.1)
│   │   ├── migrations/      embedded SQL migrations
│   │   ├── testdata/        ClientHello captures, h2 prefaces, golden fixtures
│   │   ├── Dockerfile
│   │   └── package.json     build/test/lint scripts calling the Go toolchain
│   └── demo/                Vite + TypeScript static page
├── packages/
│   └── thumbmark/           fork of upstream thumbmarkjs 1.12.0, @nazr/thumbmark
├── deploy/
│   ├── compose/             docker-compose.yml, compose.plain.yml, .env.example
│   └── terraform/aws/       root module + modules/{network,database,cert,service}
├── docs/                    protocol.md, signals.md, deploy-*.md
├── biome.json  turbo.json  pnpm-workspace.yaml  package.json  go.work
```

Turborepo orchestrates `build`, `test`, `lint`, `typecheck` across all
workspaces. Biome lints and formats TypeScript/JavaScript only. Go uses
`gofmt`, `go vet`, and `staticcheck`.

### 3.1 Go packages (`apps/api/internal`)

| package       | responsibility                                                                 |
|---------------|--------------------------------------------------------------------------------|
| `config`      | parse `NAZR_*` environment into a typed struct; validate; print effective config |
| `server`      | routes, CORS, middleware (auth, rate limit, body cap, request ID, logging)      |
| `conn`        | listener wrappers: PROXY protocol v2, ClientHello peek, h2 tee, context holder  |
| `tlsfp`       | ClientHello parser, JA4, JA3, `tls` component                                  |
| `h2fp`        | passive HTTP/2 preface parser, Akamai fingerprint, `h2` component              |
| `httpfp`      | JA4H and `header` component                                                    |
| `ipintel`     | MaxMind reader, list sources, scheduler, prefix trie, `ip` component           |
| `fingerprint` | stable stringify, murmur3 x86 128, component filtering, merge, hash            |
| `classify`    | scoring table → classification + signals                                       |
| `visitor`     | visitor resolution, thumbmark history, uniqueness                              |
| `store`       | Postgres (pgx), embedded migrations, optional Redis, retention job             |
| `auth`        | API keys (hash, prefix, origins, rate limit), admin bearer token               |
| `jsnum`       | JavaScript-compatible float formatting (used by `fingerprint`)                 |

Each package exposes a small interface and is testable in isolation.

## 4. Wire protocol (compatibility contract)

Derived from upstream `src/functions/api.ts` at 1.12.0. Documented in
`docs/protocol.md`.

### 4.1 `POST /thumbmark`

Request headers (normal mode): `x-api-key: <key>`, `Authorization:
custom-authorized`, `Content-Type: application/json`. In `simple_request` mode
the client sends `Content-Type: text/plain` and no custom headers; the
operator's proxy injects `x-api-key`. The server accepts both content types.

Request body:

```json
{
  "components": { ... },          // client components, nested objects
  "options": { ... },             // client options minus api_key
  "clientHash": "<murmur128 hex>",
  "version": "1.12.0",
  "path": "/page",
  "visitorId": "<ulid>",          // optional
  "metadata": {} | "string"       // optional, <= 1000 chars stringified
}
```

Response body (200):

```json
{
  "thumbmark": "<murmur128 hex>",
  "components": { "tls": {...}, "h2": {...}, "header": {...}, "ip": {...} },
  "info": {
    "ip_address": { "ip_address": "", "ip_identifier": "", "autonomous_system_number": 0, "ip_version": "v4|v6" },
    "classification": { "tor": false, "vpn": false, "bot": false, "datacenter": false, "private_relay": false, "danger_level": 0 },
    "uniqueness": { "score": 0.97 },
    "country": { "iso_code": "", "name": "", "continent": { "code": "", "name": "" } },
    "visitor": { "id": "", "isNew": true, "firstSeen": "<rfc3339>", "lastSeen": "<rfc3339>" },
    "signals": { "timezone_country_mismatch": false, "ua_tls_mismatch": false, "...": false }
  },
  "visitorId": "<ulid>",
  "requestId": "<ulid>",
  "version": "<server version>",
  "metadata": <echoed>,
  "collect": { "ja4": "...", "source": "..." }   // optional, see 4.3
}
```

`ip_identifier` is a stable salted hash of the IP, usable for grouping without
exposing the address. Server `components` are returned unfiltered; the client
filters them with its own rules. `thumbmark` is computed server-side over the
merged, filtered set (section 6) so the client and server agree.

Status codes: 200 ok; 400 malformed body (JSON `{"error":"bad_request", ...}`);
403 unknown, revoked, or origin-rejected key; 413 body over cap; 429 rate
limited; 503 store unavailable. All error bodies are `{"error": "<code>",
"message": "<text>"}`.

### 4.2 CORS

`OPTIONS /thumbmark` and all other routes answer preflight with
`Access-Control-Allow-Methods: POST, OPTIONS`, `Access-Control-Allow-Headers:
content-type, x-api-key, authorization`, `Access-Control-Max-Age: 86400`.
`Access-Control-Allow-Origin` is the request Origin when the key allows it (or
`*` when the key has no origin list and `NAZR_CORS_ORIGINS` is unset). Preflight
cannot see the key, so preflight uses the global `NAZR_CORS_ORIGINS` list
(default `*`); per-key enforcement happens on the real request.

### 4.3 `POST /beacon`

Body `{ "ua": "", "thumbmark": "", "ja4": "", "ja4_source": "" }`, sent via
`sendBeacon` or no-cors fetch with `text/plain`. The server records a
`ua_ja4_observations` row (family parsed from `ua`, JA4 taken from the live
connection when present, else from the body) and returns 204. The server emits
a `collect` directive in `/thumbmark` responses when it could not compute JA4
for the request (proxied mode without a JA4 header, or parse failure) and
`NAZR_COLLECT_SAMPLE_RATE` (default 0.01) samples the request.

### 4.4 `POST /log`

Returns 204. Body discarded unless `NAZR_LOG_RETENTION` is set, in which case
it is stored in `client_logs` and pruned on the same retention schedule.

### 4.5 Operational routes

- `GET /healthz` — process alive.
- `GET /readyz` — store reachable, migrations current, and a JSON map of list
  sources to `{loaded: bool, rows: n, fetched_at: ts}`.
- `GET /metrics` — Prometheus. Bound to `NAZR_METRICS_ADDR` (default
  `127.0.0.1:9090`), not the public listener.
- `/admin/keys` — `GET` list, `POST` create (returns plaintext key once),
  `DELETE /admin/keys/{id}` revoke. Requires `Authorization: Bearer
  <NAZR_ADMIN_TOKEN>`. Disabled when the token is unset.
- `GET /demo/*` — static files from `NAZR_DEMO_DIR` when set.
- `GET /` — plain-text banner with version.

## 5. Connection layer and fingerprint capture

`NAZR_TLS_MODE` is one of:

- `terminate` (default in compose and Terraform): the Go process terminates
  TLS. Listener chain: TCP accept → optional PROXY v2 parse
  (`NAZR_PROXY_PROTOCOL=true`) → ClientHello peek → `tls.Server` → if ALPN is
  `h2`, h2 tee → `http.Server`.
- `proxied`: plain HTTP behind a TLS-terminating proxy. JA4 read from
  `NAZR_JA4_HEADER` (default `x-ja4`), JA4H computed locally, `h2` absent.
  Client IP from `NAZR_CLIENT_IP_HEADER` (default `x-forwarded-for`, rightmost
  non-trusted hop, with `NAZR_TRUSTED_PROXIES` CIDRs).
- `plain`: local dev. No `tls`, no `h2`. Client IP from the socket unless the
  header is configured.

Certificates in `terminate` mode come from, in precedence order:
`NAZR_TLS_CERT_PEM`/`NAZR_TLS_KEY_PEM` (inline, what Terraform injects from
Secrets Manager), `NAZR_TLS_CERT_FILE`/`NAZR_TLS_KEY_FILE` (re-read on SIGHUP
and every 12h), or ACME (`NAZR_ACME_DOMAINS`, `NAZR_ACME_EMAIL`,
`NAZR_ACME_DIR`, HTTP-01 on `NAZR_HTTP_ADDR` and TLS-ALPN-01) for single
instance deployments. ACME is refused when `NAZR_ACME_DOMAINS` is set alongside
inline PEM, to avoid ambiguity.

### 5.1 ClientHello peek (`conn`, `tlsfp`)

The wrapper reads TLS records from the raw connection until a complete
`ClientHello` handshake message is buffered (cap 16 KiB; on overflow or a
non-TLS first byte, the connection is closed; Go's TLS server would reject
such bytes anyway, so closing early is equivalent and cheaper).
`tlsfp.Parse` extracts: legacy version, supported_versions, cipher suites,
extensions in order, SNI presence, ALPN list, signature algorithms, supported
groups, EC point formats. GREASE values are recognised and excluded from
hashes per the JA4 spec but retained in the raw lists. Outputs:

- `ja4` (e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`), `ja4_r` raw form,
  `ja3` and `ja3_hash` for compatibility.
- `tls` component: `{ version, ja4, ja3, ciphers: [], extensions: [], sni: bool,
  alpn: [], sig_algs: [], groups: [] }`.

The parsed result is stored on a per-connection `conn.Holder`, which
`http.Server.ConnContext` attaches to every request context on that
connection.

### 5.2 HTTP/2 tee (`conn`, `h2fp`)

After the handshake, if `tls.ConnectionState().NegotiatedProtocol == "h2"`,
the connection's `Read` tees bytes into an `h2fp.Parser` until it has seen the
first `HEADERS` frame or 64 KiB, after which the tee is removed. The parser
handles the client preface, `SETTINGS` (id:value pairs in order),
`WINDOW_UPDATE` (increment), `PRIORITY` frames (stream:exclusive:dep:weight),
and the first `HEADERS` frame decoded with a fresh HPACK decoder (valid
because it is the first frame on the connection) to recover pseudo-header
order. Output: Akamai-format string
`S[;S]|WU|P[,P]|PHO` and the `h2` component `{ fingerprint, settings: {},
window_update, priorities: [], pseudo_header_order }`.

### 5.3 HTTP header fingerprint (`httpfp`)

JA4H per the spec: method, version, cookie presence, referer presence, header
count, language, hash of header order, hash of cookie names, hash of cookie
values. Go's `net/http` does not preserve header order, so the `conn` package
also records the raw header line order from the h2 tee (HTTP/2) or from a
`textproto` sniff of the first request line block (HTTP/1.1) and places it on
the holder. The `header` component: `{ ja4h, order: [], acceptLanguage: {
raw, q: {} }, accept, acceptEncoding, clientHints: { ua, platform, mobile,
fullVersionList, ... }, userAgent }`.

## 6. Fingerprint computation (`fingerprint`, `jsnum`)

Port of upstream `stableStringify`, `hash` (murmur3 x86 128 with
little-endian byte hex output), `filterThumbmarkData`, `getExcludeList`, the
`stabilizationExclusionRules` table, and `getBrowser` applied to
`components.system.browser` for server-side rule evaluation. Numbers are
formatted exactly as JavaScript `Number.prototype.toString` (`jsnum`), strings
exactly as `JSON.stringify` (no HTML escaping; U+2028/2029 unescaped; lone
surrogates escaped). Client JSON is decoded with `json.Decoder.UseNumber` so
integers above 2^53 and float formatting survive round-trip.

Algorithm for a request:

1. `server := {tls, h2, header, ip}` with absent parts omitted.
2. `filtered := filter(server, options)` using the request's `options`.
3. `merged := clientComponents ∪ filtered` (server keys overwrite).
4. `thumbmark := hex(murmur128(stableStringify(merged)))`.

Golden fixtures: `packages/thumbmark/scripts/gen-fixtures.ts` emits
`testdata/fixtures/*.json` with inputs and expected stringify output and hash;
the Go tests consume them. Both sides fail CI on mismatch.

## 7. Visitor identity and uniqueness (`visitor`)

Visitors are scoped by API key. Resolution order:

1. Body `visitorId` exists under this key → reuse, bump `last_seen`.
2. A `visitor_thumbmarks` row under this key with this thumbmark and
   `last_seen` within `NAZR_VISITOR_MATCH_WINDOW` (default `720h`) → reuse.
3. Create new visitor (ULID), `isNew: true`.

In every case upsert `visitor_thumbmarks(visitor, thumbmark)` and maintain
`thumbmark_counts(key, thumbmark, distinct_visitors)`.

Uniqueness: `score = 1 - (distinct_visitors_with_thumbmark - 1) /
max(visitors_under_key, 1)`, rounded to 4 places. The response includes the
counts as `uniqueness.visitors_sharing` and `uniqueness.visitors_total` for
transparency; the stock client ignores unknown fields.

## 8. Classification (`classify`)

Inputs: ip intel hits, tls/h2/header components, client components, geo.
Output: `classification` and `signals`.

Scoring table (documented in `docs/signals.md`; values in code constants):

| signal                                | danger | bot |
|---------------------------------------|--------|-----|
| tor exit                              | +3     |     |
| datacenter ASN or range               | +2     |     |
| vpn range                             | +1     |     |
| private relay                         | 0      |     |
| `navigator.webdriver` true            | +2     | +3  |
| headless marker in UA                 | +2     | +3  |
| UA family vs JA4 corpus mismatch      | +1     | +2  |
| h2 fingerprint in automation set      | +1     | +2  |
| missing Accept-Language               | +1     | +1  |
| timezone/country mismatch             | +1     |     |
| datacenter + browser UA               | +1     | +1  |

`danger_level = clamp(sum, 0, 5)`, `bot = botPoints >= 3`. `signals` lists
every contributing boolean by name. `ua_tls_mismatch` uses the FoxIO JA4
database plus local `ua_ja4_observations` with at least
`NAZR_UA_JA4_MIN_OBSERVATIONS` (default 20) sightings.

## 9. IP intelligence (`ipintel`)

```go
type Source interface {
    Name() string
    Interval() time.Duration
    Fetch(ctx, dataDir) (changed bool, err error) // HEAD/ETag aware
    Load(dataDir) (Table, error)                  // parse cached file
}
```

| source                 | interval | notes                                                         |
|------------------------|----------|---------------------------------------------------------------|
| MaxMind GeoLite2-City  | 24h      | basic auth account id + license key; HEAD Last-Modified check; tar.gz → mmdb |
| MaxMind GeoLite2-ASN   | 24h      | same                                                          |
| Apple Private Relay    | 24h      | `https://mask-api.icloud.com/egress-ip-ranges.csv`, columns cidr,country,region,city |
| Tor exit list          | 6h       | `https://check.torproject.org/torbulkexitlist`                |
| X4BNet datacenter      | 24h      | `lists_vpn` datacenter ipv4/ipv6 lists                        |
| X4BNet vpn             | 24h      | `lists_vpn` vpn ipv4/ipv6 lists                               |
| FoxIO JA4 database     | 7d       | opt-in: `NAZR_JA4DB_URL` + `NAZR_JA4DB_TOKEN` (Bearer). FoxIO moved ja4db behind account login on ja4db.foxio.io in 2025; no default URL |

Scheduler: on boot, `Load` each source from `NAZR_DATA_DIR`; start serving;
then run `Fetch` for stale sources in the background and swap tables
atomically. Sources without credentials or URL overrides are skipped and
reported in `/readyz`. Lookups use a prefix trie keyed by `netip.Prefix`.
Private Relay rows carry country/region/city, which override MaxMind geo for
relay IPs. `ip` component: `{ address, version, asn, as_org, country, region,
city, tor, vpn, datacenter, private_relay }`.

MaxMind download limit is 30/day per account; each process downloads at most
once per 24h and only when `Last-Modified` is newer than the cached copy.
Persisting `NAZR_DATA_DIR` on a volume avoids re-downloading on restart.

## 10. Auth, keys, rate limiting (`auth`)

- Keys: 32 random bytes, base32, prefix `nzr_`. Stored as SHA-256; first 8
  chars kept as display prefix. Fields: label, `allowed_origins text[]`,
  `rate_limit_per_minute` (null = `NAZR_DEFAULT_RATE_LIMIT`), `created_at`,
  `revoked_at`, `last_used_at`.
- Origin scoping: if `allowed_origins` is non-empty, the request must carry an
  `Origin` header that matches an entry (exact or `*.example.com` wildcard,
  scheme included); otherwise 403 `origin_not_allowed`.
- Rate limiting: token bucket per key; Redis `INCR`/`EXPIRE` window when
  `NAZR_REDIS_URL` is set, else in-process. Exceeding returns 429 with
  `Retry-After`.
- Key cache: 60s in-process LRU; Redis-backed when available so revocation
  propagates across instances within the TTL.
- Admin: bearer token from `NAZR_ADMIN_TOKEN`; CLI `nazr keys` talks to
  Postgres directly using `NAZR_DATABASE_URL`.

## 11. Storage (`store`)

Postgres 15+ via `pgx`. Migrations embedded and applied by `nazr migrate` (also
auto-applied on `serve` when `NAZR_AUTO_MIGRATE=true`, default true in
compose).

Tables:

- `api_keys(id, key_hash, prefix, label, allowed_origins, rate_limit_per_minute, created_at, revoked_at, last_used_at)`
- `visitors(id, api_key_id, first_seen, last_seen, request_count)`
- `visitor_thumbmarks(api_key_id, visitor_id, thumbmark, first_seen, last_seen, count)` PK (visitor_id, thumbmark); index (api_key_id, thumbmark, last_seen desc)
- `thumbmark_counts(api_key_id, thumbmark, distinct_visitors)` PK (api_key_id, thumbmark)
- `events(id, api_key_id, visitor_id, thumbmark, client_hash, ip inet null, ip_hash, ja4, ja4h, h2fp, user_agent, path, classification jsonb, signals jsonb, components jsonb null, metadata jsonb null, created_at)` index (api_key_id, created_at), (visitor_id)
- `ua_ja4_observations(ja4, ua_family, count, first_seen, last_seen)` PK (ja4, ua_family)
- `client_logs(id, api_key_id null, body jsonb, created_at)`
- `list_state(name, last_modified, etag, fetched_at, row_count)`

Config: `NAZR_STORE_IP` (`raw` default | `hash`), `NAZR_STORE_COMPONENTS`
(default false), `NAZR_EVENT_RETENTION` (default `2160h`). Retention job runs
hourly, deletes in batches of 10k.

Redis is optional and used only for rate limiting and key cache.

## 12. Client fork (`packages/thumbmark`)

Base: upstream `thumbmarkjs/thumbmarkjs` tag `v1.12.0`. Keep Rollup, Jest, and
Playwright config; replace ESLint with Biome. Keep `LICENSE.upstream` (MIT,
Ilkka) and add attribution to the package README.

Changes:

- `DEFAULT_API_ENDPOINT` unchanged; `logThumbmarkData` posts to
  `${options.api_endpoint}/log`; `DEFAULT_COLLECT_ENDPOINT` resolves to
  `${options.api_endpoint}/beacon` when `collect_endpoint` is unset.
- `defaultOptions.logging = false`.
- Types: `classification.private_relay`, `uniqueness.visitors_sharing`,
  `uniqueness.visitors_total`, `components.h2`.
- New components: `webgpu` (adapter info, limits subset, features list),
  `clienthints` (`navigator.userAgentData.getHighEntropyValues` for
  architecture, bitness, model, platformVersion, fullVersionList, wow64),
  `clientrects` (bounding rects of a fixed DOM probe, rounded to 2 decimals),
  `mediaqueries` (color-gamut, dynamic-range, pointer, any-pointer, hover,
  any-hover, prefers-reduced-motion, prefers-color-scheme, prefers-contrast,
  forced-colors, inverted-colors, display-mode, resolution bucket),
  `privacy` (doNotTrack, globalPrivacyControl).
- Stabilization rules: `clientrects` excluded under `private` for Firefox and
  Brave; `clienthints` excluded under `private` for Brave.
- `scripts/upstream-diff.sh`: fetches the pinned tag into a temp dir and
  prints a diff of `src/` so upstream fixes can be reviewed and ported.
- `scripts/gen-fixtures.ts`: emits golden fixtures for the Go tests.

Package name `@nazr/thumbmark`, same export surface as upstream.

## 13. Demo (`apps/demo`)

Vite, vanilla TypeScript, no framework. Features: endpoint and key inputs
persisted in `localStorage`; TLS mode banner from `/readyz`; run button;
panels for thumbmark and visitor, classification and signals, every client
component as a collapsible tree, server components, per-component timing
(`performance: true`), and a diff against the previous run stored in
`localStorage`. Built output can be served by the API via `NAZR_DEMO_DIR` or
any static host.

## 14. Deployment

### 14.1 Docker and Compose

`apps/api/Dockerfile`: `golang:1.26` build stage with `CGO_ENABLED=0`, then
`gcr.io/distroless/static:nonroot`. Entrypoint `nazr`, default command `serve`.
Volumes: `/data` (`NAZR_DATA_DIR`). Exposes 443, 80, 9090.

`deploy/compose/docker-compose.yml`: services `api`, `postgres:17`, `redis:7`
(profile `redis`), and `certgen` (one-shot, writes a self-signed cert into a
shared volume when none exists). `compose.plain.yml` overrides the API to
`NAZR_TLS_MODE=plain` on 8080. `.env.example` lists every variable with its
default.

### 14.2 Terraform (AWS)

Root `deploy/terraform/aws` with providers `aws`, `acme`, `random`.

Variables: `domain`, `route53_zone_id`, `region`, `image` (ECR URI or tag),
`desired_count` (2), `cpu`/`memory` (512/1024), `db_instance_class`
(`db.t4g.micro`), `db_allocated_storage` (20), `enable_redis` (false),
`redis_node_type`, `maxmind_account_id`, `maxmind_license_key`,
`admin_token`, `certificate_pem`/`private_key_pem` (optional, skips ACME),
`acme_email`, `vpc_id`/`private_subnet_ids`/`public_subnet_ids` (optional,
skips network module), `event_retention`, `cors_origins`, `tags`.

Modules:

- `network`: VPC `10.0.0.0/16`, two public and two private subnets across two
  AZs, one NAT gateway, VPC endpoints for ECR, Secrets Manager, and CloudWatch
  Logs to keep task traffic private.
- `database`: RDS Postgres 17, private subnets, security group from the service
  SG only, master password in Secrets Manager, `NAZR_DATABASE_URL` composed
  into a secret. Optional ElastiCache Redis single node.
- `cert`: ACME registration and certificate via Route53 DNS-01, stored as two
  Secrets Manager secrets. Skipped when PEM variables are provided.
- `service`: ECR repo (optional, when `image` is a bare tag), ECS cluster,
  Fargate task definition (secrets: DB URL, TLS PEMs, MaxMind, admin token),
  service with `desired_count`, NLB (TCP 443 → target group port 443,
  `preserve_client_ip = true`; TCP 80 → port 80), Route53 alias, CloudWatch
  log group (30 days), ECS Exec enabled, security groups.

Outputs: `api_url`, `nlb_dns_name`, `ecr_repository_url`, `first_key_command`
(an `aws ecs execute-command ... nazr keys create --label first` string).

CI: `terraform fmt -check`, `terraform validate`, `tflint`.

### 14.3 From source

```
pnpm install && pnpm build
cd apps/api && go run ./cmd/nazr migrate && go run ./cmd/nazr keys create --label dev
NAZR_TLS_MODE=plain go run ./cmd/nazr serve
```

## 15. Configuration reference (`NAZR_*`)

Core: `DATABASE_URL`, `REDIS_URL`, `LISTEN_ADDR` (`:443`), `HTTP_ADDR`
(`:80`), `METRICS_ADDR`, `TLS_MODE`, `TLS_CERT_PEM`, `TLS_KEY_PEM`,
`TLS_CERT_FILE`, `TLS_KEY_FILE`, `ACME_DOMAINS`, `ACME_EMAIL`, `ACME_DIR`,
`PROXY_PROTOCOL`, `TRUSTED_PROXIES`, `CLIENT_IP_HEADER`, `JA4_HEADER`,
`CORS_ORIGINS`, `ADMIN_TOKEN`, `DEFAULT_RATE_LIMIT` (600/min), `BODY_LIMIT`
(256 KiB), `DATA_DIR` (`/data`), `DEMO_DIR`, `AUTO_MIGRATE`, `LOG_LEVEL`,
`LOG_FORMAT` (json|text).

Intel: `MAXMIND_ACCOUNT_ID`, `MAXMIND_LICENSE_KEY`, `MAXMIND_EDITIONS`
(`GeoLite2-City,GeoLite2-ASN`), `APPLE_RELAY_URL`, `TOR_EXIT_URL`,
`DATACENTER_URLS`, `VPN_URLS`, `JA4DB_URL`, `LISTS_DISABLE` (comma list),
`UA_JA4_MIN_OBSERVATIONS`, `COLLECT_SAMPLE_RATE`.

Identity and storage: `VISITOR_MATCH_WINDOW`, `STORE_IP`, `IP_HASH_SALT`,
`STORE_COMPONENTS`, `EVENT_RETENTION`, `LOG_RETENTION`.

`nazr serve --print-config` prints the effective configuration with secrets
redacted.

## 16. Error handling

- Fingerprint capture never fails a request. Parse failures produce an absent
  component, a warning log, and a `nazr_fingerprint_parse_errors_total{kind}`
  metric.
- List refresh failures keep the previous table and set a gauge
  `nazr_list_stale{source}`.
- Store unavailable → 503 `store_unavailable`, `Retry-After: 2`. The client's
  own timeout path handles this gracefully.
- Body over `BODY_LIMIT` → 413. Malformed JSON or non-object `components` →
  400.
- Unknown key, revoked key, or origin mismatch → 403 with distinct codes.
- Panics in handlers are recovered into 500 with the request ID logged.

## 17. Testing

- Go unit tests per package. `tlsfp`: JA4 and JA3 against FoxIO published
  vectors and checked-in ClientHello captures from Chrome, Firefox, Safari,
  curl. `h2fp`: recorded prefaces from Chrome, Firefox, Safari, Go client.
  `httpfp`: JA4H vectors. `fingerprint`/`jsnum`: golden fixtures from the TS
  generator plus property tests for number formatting against a table of
  known JS outputs. `classify`: table-driven. `ipintel`: parser tests with
  sample files and trie lookups.
- Integration tests with `testcontainers-go` Postgres: migrations, key CRUD
  and origin checks, visitor resolution paths, uniqueness math, retention.
  Skipped when Docker is unavailable, enforced in CI.
- End-to-end: Playwright in `apps/demo` launches the API in `terminate` mode
  with a self-signed cert, loads the demo in Chromium with the fork, asserts
  the returned thumbmark equals the hash computed in the page from the merged
  components, and asserts `components.tls.ja4` and `components.h2.fingerprint`
  are present. A second test points the stock upstream client at the same API
  and asserts a 200 with a visitor ID.
- Compose smoke in CI: `docker compose up -d`, wait for `/readyz`, create a
  key, POST a fixture body, assert 200.
- Terraform: fmt, validate, tflint.

## 18. Open decisions resolved during brainstorming

- Fork, do not rewrite: upstream is MIT; keep notice.
- AWS with NLB TCP passthrough so Go terminates TLS.
- Postgres only; Redis optional.
- Keys in Postgres with admin CLI and endpoint; per-key allowed origins.
- MaxMind GeoLite2 via account ID and license key, daily refresh.
- Apple Private Relay via Apple's egress CSV, reported as its own flag with
  zero danger contribution.
- JA4T, QUIC, extension detection deferred.
