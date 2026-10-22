# nazr

Browser fingerprinting service: a Go API, a Vite demo, and a forked TypeScript client, in one Turborepo monorepo.

## Quick start

From source (needs Go, Node with pnpm, and PostgreSQL):

```bash
pnpm install
pnpm --filter @nazr/api build              # builds apps/api/bin/nazr

export NAZR_DATABASE_URL='postgres://user:pass@localhost:5432/nazr?sslmode=disable'
export NAZR_TLS_MODE=plain NAZR_LISTEN_ADDR=127.0.0.1:8080 NAZR_DATA_DIR=./data

apps/api/bin/nazr migrate
apps/api/bin/nazr keys create --label local   # prints the API key once
apps/api/bin/nazr serve
```

Then point the client at it:

```ts
import { Thumbmark } from "@nazr/thumbmark";

const tm = new Thumbmark({ api_key: "nzr_...", api_endpoint: "http://127.0.0.1:8080", logging: false });
console.log(await tm.get());
```

`plain` mode is for local development. Production deployments use `terminate` (default) or `proxied`; see the connection modes in [docs/protocol.md](docs/protocol.md#connection-modes-and-fingerprint-capture).

- Docker Compose: coming in the next plan.
- Terraform (AWS): coming in the next plan.

## Documentation

- [docs/protocol.md](docs/protocol.md): routes, request and response, errors, CORS, TLS modes, client setup
- [docs/signals.md](docs/signals.md): components, scoring table, signals, IP list sources
- [docs/configuration.md](docs/configuration.md): every `NAZR_*` variable
- [packages/thumbmark/README.md](packages/thumbmark/README.md): the `@nazr/thumbmark` client
- [docs/](docs/): design spec and implementation plans
