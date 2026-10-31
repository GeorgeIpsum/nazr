# Running from source

Build and run nazr without containers: for local development, or on a single VM.

Prerequisites: Node 26 with pnpm 10, Go 1.26, and PostgreSQL. A throwaway Postgres for development:

```bash
docker run -d --name nazr-pg -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=nazr -e POSTGRES_PASSWORD=nazr -e POSTGRES_DB=nazr postgres:17-alpine
export NAZR_DATABASE_URL='postgres://nazr:nazr@127.0.0.1:5432/nazr?sslmode=disable'
```

## Build, migrate, create a key

```bash
pnpm install && pnpm build
cd apps/api && go run ./cmd/nazr migrate && go run ./cmd/nazr keys create --label dev
```

`keys create` prints the API key, then the key's siteverify secret, then an `id  prefix  label` line; store the first two, which are shown once (only the first line is the API key). The first `serve` also creates the widget signing key; `nazr signing rotate|list` manages it. `pnpm build` also produces the demo bundle and the client package. `pnpm --filter @nazr/api build` compiles a standalone binary at `apps/api/bin/nazr`, which takes the same subcommands (`serve`, `migrate`, `keys`, `signing`, `lists`, `version`).

The binary embeds the [widget](widget.md) only when its assets were synced before the Go build. `pnpm build` (or `pnpm build --filter=@nazr/api`) builds the widget and runs the sync. Plain `go build`/`go run` embed whatever was last synced, and `pnpm --filter @nazr/api build` bypasses Turborepo, so it syncs the widget's existing `dist/` without rebuilding it. Before those, run `pnpm install && pnpm build --filter=@nazr/widget && pnpm --filter @nazr/api sync-widget`. Without it the widget routes (`/widget/v1/*`) return 404 while everything else works.

## Local: plain HTTP

```bash
cd apps/api
NAZR_TLS_MODE=plain NAZR_LISTEN_ADDR=:8080 NAZR_HTTP_ADDR=off NAZR_DATA_DIR=./data go run ./cmd/nazr serve
```

`NAZR_DATA_DIR` defaults to `/data`; point it somewhere writable. `plain` mode has no TLS, so it captures no JA4 or HTTP/2 fingerprint (HTTP/1.1 header order only). The redirect listener runs only in `terminate` mode, so `plain` never binds `:80`; `NAZR_HTTP_ADDR=off` just silences the startup line saying the setting is ignored (an empty value would mean the `:80` default).

Check it, then point a client at `http://127.0.0.1:8080` (see the [client README](../packages/thumbmark/README.md)), or run the demo with `pnpm --filter @nazr/demo dev`:

```bash
curl -s http://127.0.0.1:8080/readyz
```

## Single VM: terminate TLS with ACME

For the full fingerprint set (JA4, HTTP/2, header order) nazr terminates TLS itself. Point a DNS name at the VM, open ports 80 and 443, and run with `terminate` (the default mode):

```bash
export NAZR_DATABASE_URL='postgres://...'
export NAZR_TLS_MODE=terminate
export NAZR_ACME_DOMAINS=nazr.example.com
export NAZR_ACME_EMAIL=ops@example.com
export NAZR_HTTP_ADDR=:80       # required: ACME HTTP-01 challenges are answered here
export NAZR_DATA_DIR=/var/lib/nazr
./bin/nazr serve
```

`NAZR_LISTEN_ADDR` defaults to `:443`. The certificate cache (`NAZR_ACME_DIR`) defaults to `<NAZR_DATA_DIR>/acme`; keep it on persistent storage or certificates are re-issued on every restart. Binding ports below 1024 needs root or `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

A minimal systemd unit, `/etc/systemd/system/nazr.service` (put the variables above in `/etc/nazr.env`, mode 0600):

```ini
[Unit]
Description=nazr
After=network-online.target postgresql.service

[Service]
User=nazr
EnvironmentFile=/etc/nazr.env
ExecStart=/opt/nazr/bin/nazr serve
AmbientCapabilities=CAP_NET_BIND_SERVICE
StateDirectory=nazr
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Migrations run on `serve` start by default (`NAZR_AUTO_MIGRATE`). Every variable is documented in [configuration.md](configuration.md); the connection modes are in [protocol.md](protocol.md#connection-modes-and-fingerprint-capture).
