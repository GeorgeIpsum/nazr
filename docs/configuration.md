# Configuration

nazr is configured entirely through `NAZR_*` environment variables. Inspect the effective configuration, with secrets replaced by `<redacted>`:

```bash
nazr serve --print-config
```

Unset secrets print empty. The listing below is that output from an empty environment (`env -i PATH=$PATH HOME=$HOME nazr serve --print-config`), annotated. Durations use Go syntax (`720h`, `30m`); lists are comma separated; booleans are `true` or `false`. Invalid values (bad `NAZR_TLS_MODE`, `NAZR_STORE_IP`, a sample rate outside 0-1, a non-positive body limit, or ACME domains combined with inline PEM) stop startup with an error.

Secrets (redacted in `--print-config` and in the debug log): `NAZR_DATABASE_URL`, `NAZR_REDIS_URL`, `NAZR_TLS_KEY_PEM`, `NAZR_MAXMIND_LICENSE_KEY`, `NAZR_ADMIN_TOKEN`, `NAZR_IP_HASH_SALT`, `NAZR_JA4DB_TOKEN`.

Related: [protocol.md](protocol.md), [signals.md](signals.md).

## Core

| Variable | Type | Default | Meaning |
|---|---|---|---|
| `NAZR_DATABASE_URL` | string, secret | empty | PostgreSQL URL. Required by `serve`, `migrate` and `keys` |
| `NAZR_REDIS_URL` | string, secret | empty | Optional Redis URL. Enables a shared rate limiter and key cache across replicas; without it both are in-process. The Redis limiter needs Redis 7+. On Redis errors the limiter fails open (the request is allowed) and a warning is logged |
| `NAZR_LISTEN_ADDR` | string | `:443` | Public listener address |
| `NAZR_HTTP_ADDR` | string | `:80` | Plain-HTTP listener for ACME HTTP-01 and a 308 redirect to HTTPS. Used only when `NAZR_TLS_MODE=terminate`; set empty to disable |
| `NAZR_METRICS_ADDR` | string | `127.0.0.1:9090` | Prometheus `/metrics` listener; empty disables it |
| `NAZR_TLS_MODE` | `terminate`, `proxied`, `plain` | `terminate` | See [connection modes](protocol.md#connection-modes-and-fingerprint-capture) |
| `NAZR_TLS_CERT_PEM` | string | empty | Inline certificate chain (terminate mode). Set it together with `NAZR_TLS_KEY_PEM` or not at all; a half-set pair fails validation |
| `NAZR_TLS_KEY_PEM` | string, secret | empty | Inline private key. Inline PEM wins over files, files over ACME |
| `NAZR_TLS_CERT_FILE` | path | empty | Certificate file, reloaded on `SIGHUP` and every 12 hours. Set it together with `NAZR_TLS_KEY_FILE` or not at all; a half-set pair fails validation |
| `NAZR_TLS_KEY_FILE` | path | empty | Private key file |
| `NAZR_ACME_DOMAINS` | list | empty | Domains for automatic Let's Encrypt certificates. Cannot be combined with inline PEM |
| `NAZR_ACME_EMAIL` | string | empty | Contact address for the ACME account |
| `NAZR_ACME_DIR` | path | `<NAZR_DATA_DIR>/acme` when ACME is active | Certificate cache directory. Keep it on a persistent volume, or certificates are re-issued on restart |
| `NAZR_PROXY_PROTOCOL` | bool | `false` | Read a PROXY protocol v2 header for the client address |
| `NAZR_TRUSTED_PROXIES` | list of IPs or CIDRs | empty | Proxied mode: hops skipped when walking `NAZR_CLIENT_IP_HEADER` from the right |
| `NAZR_CLIENT_IP_HEADER` | string | `x-forwarded-for` | Proxied mode: header carrying the client IP |
| `NAZR_JA4_HEADER` | string | `x-ja4` | Proxied mode: header carrying the JA4 computed by the proxy |
| `NAZR_CORS_ORIGINS` | list | `*` | Global CORS origins; used for preflight and as the baseline on real requests |
| `NAZR_ADMIN_TOKEN` | string, secret | empty | Bearer token for `/admin/keys`. Admin routes return 404 when empty |
| `NAZR_DEFAULT_RATE_LIMIT` | int | `600` | Requests per minute per key (overridable per key), and per IP on `/beacon` |
| `NAZR_BODY_LIMIT` | int (bytes) | `262144` | Maximum request body size; larger bodies get 413 |
| `NAZR_DATA_DIR` | path | `/data` | Cache for downloaded IP lists. Use a persistent volume |
| `NAZR_DEMO_DIR` | path | empty | Serve static files at `/demo/` when set |
| `NAZR_AUTO_MIGRATE` | bool | `true` | Apply database migrations on `serve` start. `nazr migrate` does it explicitly |
| `NAZR_LOG_LEVEL` | string | `info` | `debug`, `info`, `warn`, `error` |
| `NAZR_LOG_FORMAT` | `json`, `text` | `json` | Log encoding |

## Intel

| Variable | Type | Default | Meaning |
|---|---|---|---|
| `NAZR_MAXMIND_ACCOUNT_ID` | string | empty | MaxMind account ID. Both this and the license key are required to download GeoLite2 |
| `NAZR_MAXMIND_LICENSE_KEY` | string, secret | empty | MaxMind license key |
| `NAZR_MAXMIND_EDITIONS` | list | `GeoLite2-City,GeoLite2-ASN` | Editions to download |
| `NAZR_APPLE_RELAY_URL` | URL | empty (built-in Apple URL) | Override the Private Relay CSV URL |
| `NAZR_TOR_EXIT_URL` | URL | empty (built-in Tor Project URL) | Override the Tor exit list URL |
| `NAZR_DATACENTER_URLS` | list of URLs | empty (built-in X4BNet `datacenter/ipv4.txt` and `datacenter/ipv6.txt`) | Replace the datacenter CIDR lists |
| `NAZR_VPN_URLS` | list of URLs | empty (built-in X4BNet `vpn/ipv4.txt` and `vpn/ipv6.txt`) | Replace the VPN CIDR lists |
| `NAZR_JA4DB_URL` | URL | empty | FoxIO JA4 database URL. Opt-in; the source is disabled when empty. Needs an account at ja4db.foxio.io |
| `NAZR_JA4DB_TOKEN` | string, secret | empty | Bearer token sent to `NAZR_JA4DB_URL` |
| `NAZR_LISTS_DISABLE` | list | empty | Source names or kinds to skip entirely; see [IP lists](signals.md#ip-lists) |
| `NAZR_UA_JA4_MIN_OBSERVATIONS` | int | `20` | Sightings before a locally observed UA family counts for a JA4. Raise it while `/beacon` is the only feed; see [signals.md](signals.md#ua_tls_mismatch-and-the-ja4-corpus) |
| `NAZR_COLLECT_SAMPLE_RATE` | float 0-1 | `0.01` | Fraction of requests without a JA4 that receive a `collect` directive |

## Identity and storage

| Variable | Type | Default | Meaning |
|---|---|---|---|
| `NAZR_VISITOR_MATCH_WINDOW` | duration | `720h` | How far back a thumbmark can be matched to an existing visitor |
| `NAZR_STORE_IP` | `raw`, `hash` | `raw` | Store the client IP as is, or only its salted hash |
| `NAZR_IP_HASH_SALT` | string, secret | empty | Salt for `ip_identifier` (and stored hashes). Set it to a random value; changing it changes every identifier |
| `NAZR_STORE_COMPONENTS` | bool | `false` | Persist the full merged components with each event |
| `NAZR_EVENT_RETENTION` | duration | `2160h` (90 days) | Events older than this are pruned hourly; `0` keeps them forever |
| `NAZR_LOG_RETENTION` | duration | `0s` | Enables storing `/log` bodies and sets their retention; `0` discards them |

## Reference output

```text
NAZR_ACME_DIR=
NAZR_ACME_DOMAINS=
NAZR_ACME_EMAIL=
NAZR_ADMIN_TOKEN=
NAZR_APPLE_RELAY_URL=
NAZR_AUTO_MIGRATE=true
NAZR_BODY_LIMIT=262144
NAZR_CLIENT_IP_HEADER=x-forwarded-for
NAZR_COLLECT_SAMPLE_RATE=0.01
NAZR_CORS_ORIGINS=*
NAZR_DATABASE_URL=
NAZR_DATACENTER_URLS=
NAZR_DATA_DIR=/data
NAZR_DEFAULT_RATE_LIMIT=600
NAZR_DEMO_DIR=
NAZR_EVENT_RETENTION=2160h0m0s
NAZR_HTTP_ADDR=:80
NAZR_IP_HASH_SALT=
NAZR_JA4DB_TOKEN=
NAZR_JA4DB_URL=
NAZR_JA4_HEADER=x-ja4
NAZR_LISTEN_ADDR=:443
NAZR_LISTS_DISABLE=
NAZR_LOG_FORMAT=json
NAZR_LOG_LEVEL=info
NAZR_LOG_RETENTION=0s
NAZR_MAXMIND_ACCOUNT_ID=
NAZR_MAXMIND_EDITIONS=GeoLite2-City,GeoLite2-ASN
NAZR_MAXMIND_LICENSE_KEY=
NAZR_METRICS_ADDR=127.0.0.1:9090
NAZR_PROXY_PROTOCOL=false
NAZR_REDIS_URL=
NAZR_STORE_COMPONENTS=false
NAZR_STORE_IP=raw
NAZR_TLS_CERT_FILE=
NAZR_TLS_CERT_PEM=
NAZR_TLS_KEY_FILE=
NAZR_TLS_KEY_PEM=
NAZR_TLS_MODE=terminate
NAZR_TOR_EXIT_URL=
NAZR_TRUSTED_PROXIES=
NAZR_UA_JA4_MIN_OBSERVATIONS=20
NAZR_VISITOR_MATCH_WINDOW=720h0m0s
NAZR_VPN_URLS=
```

## Subcommands

```bash
nazr serve [--print-config]   # run the server
nazr migrate                  # apply database migrations
nazr keys create --label site --origins https://example.com --rate 120
nazr keys list
nazr keys revoke <id>
nazr lists refresh            # force-fetch all IP lists and print a table
nazr version
```
