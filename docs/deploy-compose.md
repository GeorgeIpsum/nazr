# Deploying with Docker Compose

The compose stack in `deploy/compose` runs nazr, PostgreSQL and a one-shot certificate generator. It starts on a fresh machine with no `.env` file: a self-signed certificate is generated, migrations run on start, and `/readyz` returns 200.

## Quick start

Prerequisites: Docker with Compose v2.20 or newer (for `depends_on.required`), plus `curl` and `jq` for the smoke script.

```bash
docker compose -f deploy/compose/docker-compose.yml up -d --build
pnpm smoke:compose
```

The API is then at `https://localhost` (port 443, with a 308 redirect from port 80). Metrics are on `http://127.0.0.1:9090/metrics`, bound to localhost only. Create an API key with:

```bash
docker compose -f deploy/compose/docker-compose.yml exec api /nazr keys create --label mysite
```

`pnpm smoke:compose` (`deploy/compose/smoke.sh`) checks `/readyz`, creates a key, posts a stock request over HTTP/2, asserts the thumbmark, the JA4 and HTTP/2 fingerprints and the new/returning visitor flow, reads `/metrics`, then restarts the API with the `redis` profile and `NAZR_REDIS_URL=redis://redis:6379` checks `/thumbmark` again and asserts Redis holds `nazr:*` keys. It also fails if `permission denied` appears in the API logs. On exit it runs `down -v` on the whole stack; set `KEEP=1` to leave it running for debugging.

## Profiles

- `dev`: publishes PostgreSQL on `127.0.0.1:5432` (`--profile dev`). Without it, 5432 is not exposed.
- `redis`: starts `redis:7-alpine`. Set `NAZR_REDIS_URL=redis://redis:6379` to use it for the shared rate limiter and key cache:

  ```bash
  NAZR_REDIS_URL=redis://redis:6379 docker compose -f deploy/compose/docker-compose.yml --profile redis up -d
  ```

## Configuration

Compose defaults are inline in `docker-compose.yml`. Copy `deploy/compose/.env.example` to `deploy/compose/.env` and uncomment lines to override them; every `NAZR_*` variable is listed (see [configuration.md](configuration.md)). Images are pinned to specific tags (`postgres:17.11-alpine`, `redis:7.4.11-alpine`, `alpine/openssl:3.5.9`, `alpine/socat:1.8.1.3`); bump them deliberately. When `redis` is enabled the API waits for Redis to be healthy. Set `NAZR_VERSION` to change the image tag and reported version.

## TLS certificate

The `certgen` service runs once before the API and writes a 10-year self-signed certificate for `localhost` (SAN `DNS:localhost,IP:127.0.0.1`) to the `certs` volume, only if it is missing. Browsers and `curl` will warn about it; use `curl -k` locally.

The key is written with mode 0644 because the API image runs as distroless `nonroot` and reads it from a shared volume. The volume is mounted read-only into the API and is not otherwise exposed, but anything that can mount the volume can read the key. Do not reuse this certificate outside local testing.

To use a real certificate:

- Replace the `certs` volume with a bind mount of a directory holding your `cert.pem` and `key.pem` (readable by uid 65532), or set `NAZR_TLS_CERT_FILE` and `NAZR_TLS_KEY_FILE` to other paths in `.env`. Files are reloaded on `SIGHUP` and every 12 hours.
- Or let nazr obtain one with ACME: set `NAZR_ACME_DOMAINS` and `NAZR_ACME_EMAIL` and make ports 80 and 443 reachable.
- Or terminate TLS elsewhere. `compose.plain.yml` switches to `NAZR_TLS_MODE=plain` on port 8080:

  ```bash
  docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/compose.plain.yml up -d
  ```

  Plain mode captures no JA4 or HTTP/2 fingerprints.

## Pointing the demo at it

The endpoint is `https://localhost`. The demo (`apps/demo`, a Vite app) calls it from the browser:

```bash
KEY=$(docker compose -f deploy/compose/docker-compose.yml exec -T api /nazr keys create --label demo | head -1)
pnpm --filter @nazr/demo dev     # http://localhost:5173
```

1. Visit `https://localhost/healthz` once and accept the self-signed certificate; otherwise the browser blocks the demo's cross-origin requests.
2. Open the demo, keep the endpoint `https://localhost`, paste the key and press Run. A wrong key or disallowed origin shows a red "Unauthorized" panel.
3. The "simple request" box sends no key (a proxy in front must inject it). "Clear visitor" removes the client's `thumbmark_*` localStorage keys.

The version/TLS-mode/source banner reads `/readyz`, which is only readable from the page when it is same-origin (the built demo served from `/demo/` by the Go server via `NAZR_DEMO_DIR`); from the dev server the banner reports it as unavailable.

## Logs and data

```bash
docker compose -f deploy/compose/docker-compose.yml logs -f api
```

Logs are JSON by default (`NAZR_LOG_FORMAT=text` for readable output). The `nazrdata` volume (`/data`) holds downloaded IP lists and MaxMind databases, so they survive restarts; PostgreSQL data lives in `pgdata`. Set `NAZR_MAXMIND_ACCOUNT_ID` and `NAZR_MAXMIND_LICENSE_KEY` to enable GeoLite2 downloads.

## Teardown

```bash
docker compose -f deploy/compose/docker-compose.yml --profile redis --profile dev down -v
```

`-v` deletes the certificate, database and downloaded data. Omit it to keep them.
