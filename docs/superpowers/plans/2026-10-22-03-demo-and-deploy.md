# nazr Plan 3: Demo app, Docker, Compose, Terraform, CI

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make nazr runnable by other people: a demo page that exercises the client against any API, a Docker image and Compose stack that work out of the box with TLS, an AWS Terraform module using NLB TCP passthrough, end-to-end tests proving client/server hash agreement, and CI that runs all of it.

**Architecture:** The demo is a dependency-free Vite page importing `@nazr/thumbmark` from the workspace. The image is distroless and runs `nazr serve`. Compose generates a self-signed cert with a one-shot container so `terminate` mode works locally. Terraform is a root module composed of four submodules; the Go process terminates TLS behind an NLB with client IP preservation, with the certificate issued by Terraform via ACME DNS-01 and injected from Secrets Manager.

**Tech Stack:** Vite 6, Playwright, Docker multi-stage (`golang:1.26` → `gcr.io/distroless/static:nonroot`), Docker Compose v2, Terraform 1.14 with providers `hashicorp/aws ~> 6`, `vancluever/acme ~> 2`, `hashicorp/random`, `tflint`, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-21-nazr-design.md` (sections 13, 14, 17)

## Global Constraints

- Demo package name `@nazr/demo`, private, scripts `dev`, `build`, `preview`, `test:e2e`, `lint`, `typecheck`.
- Demo persists `endpoint`, `apiKey`, and `lastResult` in `localStorage` under keys prefixed `nazr_demo_`.
- Image tags: `ghcr.io/<owner>/nazr:<version>` and `:latest`; multi-arch `linux/amd64,linux/arm64`.
- Compose exposes `443` (API, TLS terminate), `80`, `9090` (metrics, bound to localhost), `5432` only via the `dev` profile.
- Terraform resources are tagged with `var.tags` merged with `{ "app" = "nazr" }`; provider versions pinned in `versions.tf`; `terraform fmt`, `validate`, and `tflint` are clean.
- NLB target group has `preserve_client_ip = true`; ECS tasks run in private subnets; only the NLB security group may reach task port 443/80.
- Every CI job runs on `ubuntu-latest` with pnpm cache; Go tests use `-race`; store integration tests run with `NAZR_TEST_REQUIRE_DB=1`.

## Review Focus

1. The demo must render a readable error when the API returns 403 (bad key or origin) instead of a blank panel. Pinned in Task 2.
2. Compose must start cleanly on a fresh machine with no `.env` file: the self-signed cert is generated, migrations run, `/readyz` returns 200. Pinned in Task 1.
3. The e2e test must prove the server's `thumbmark` equals the hash the client would compute over merged components, which is the whole point of wire compatibility. Pinned in Task 3.
4. Terraform must work when the user supplies an existing VPC and subnets instead of creating a network. Pinned in Task 4.
5. The stock upstream client (not the fork) pointed at the API must get a 200 and a visitor ID. Pinned in Task 3.

---

### Task 1: Dockerfile, Compose stack, smoke script

**Files:**
- Create: `apps/api/Dockerfile`, `apps/api/.dockerignore`, `deploy/compose/docker-compose.yml`, `deploy/compose/compose.plain.yml`, `deploy/compose/.env.example`, `deploy/compose/certgen.sh`, `deploy/compose/smoke.sh`, `docs/deploy-compose.md`

**Interfaces:**
- Produces: image entrypoint `/nazr`, default command `serve`; volume `/data`; `docker compose -f deploy/compose/docker-compose.yml up -d` yields API on `https://localhost` and `pnpm smoke:compose` passing.

- [ ] **Step 1: Write `smoke.sh` first** (the test): waits up to 90s for `curl -sk https://localhost/readyz` → 200; runs `docker compose exec api /nazr keys create --label smoke` and captures the key; POSTs `apps/api/testdata/requests/stock-client-body.json` with the key; asserts `.thumbmark` matches `^[0-9a-f]{32}$`, `.components.tls.ja4` is non-empty, `.components.h2.fingerprint` is non-empty (curl uses HTTP/2 with `--http2`), `.info.visitor.isNew == true`; exits non-zero otherwise.

- [ ] **Step 2: Run** `bash deploy/compose/smoke.sh` — Expected: FAIL (no compose file).

- [ ] **Step 3: Write `Dockerfile`**: stage 1 `golang:1.26` with `GOFLAGS=-mod=readonly`, `CGO_ENABLED=0`, build with `-ldflags "-s -w -X nazr/api/internal/version.Version=${VERSION}"` (`ARG VERSION=dev`); stage 2 `gcr.io/distroless/static:nonroot`, copy binary to `/nazr`, `VOLUME /data`, `EXPOSE 443 80 9090`, `USER nonroot`, `ENTRYPOINT ["/nazr"]`, `CMD ["serve"]`. `.dockerignore` excludes `bin`, `.data`, `testdata`.

- [ ] **Step 4: Write `certgen.sh`** (runs in an `alpine/openssl` container): if `/certs/cert.pem` is missing, generate a 10-year self-signed cert for `localhost` with SAN `DNS:localhost,IP:127.0.0.1`, mode 0644.

- [ ] **Step 5: Write `docker-compose.yml`**: services `certgen` (one-shot, volume `certs:/certs`), `postgres` (`postgres:17-alpine`, healthcheck `pg_isready`, volume `pgdata`), `redis` (`redis:7-alpine`, profile `redis`), `api` (build context `../../apps/api`, `depends_on` postgres healthy and certgen completed, env from `.env` with defaults `NAZR_DATABASE_URL=postgres://nazr:nazr@postgres:5432/nazr?sslmode=disable`, `NAZR_TLS_MODE=terminate`, `NAZR_TLS_CERT_FILE=/certs/cert.pem`, `NAZR_TLS_KEY_FILE=/certs/key.pem`, `NAZR_DATA_DIR=/data`, `NAZR_AUTO_MIGRATE=true`, `NAZR_METRICS_ADDR=0.0.0.0:9090`, ports `443:443`, `80:80`, `127.0.0.1:9090:9090`, volumes `certs:/certs:ro`, `nazrdata:/data`). `compose.plain.yml` overrides `api` to `NAZR_TLS_MODE=plain`, `NAZR_LISTEN_ADDR=:8080`, `NAZR_HTTP_ADDR=`, ports `8080:8080`. `.env.example` lists every `NAZR_*` variable from `docs/configuration.md` with defaults and comments.

- [ ] **Step 6: Run** `docker compose -f deploy/compose/docker-compose.yml up -d --build && bash deploy/compose/smoke.sh` — Expected: PASS. Then `docker compose ... down -v`.

- [ ] **Step 7: Write `docs/deploy-compose.md`** (quick start, profiles, where the cert comes from, how to use a real cert, how to point the demo at it) and add root script `smoke:compose` → `bash deploy/compose/smoke.sh`.

- [ ] **Step 8: Commit** `git add -A && git commit -m "feat(deploy): dockerfile and compose stack with self-signed tls"`

---

### Task 2: Demo app

**Files:**
- Create: `apps/demo/package.json`, `index.html`, `vite.config.ts`, `tsconfig.json`, `src/main.ts`, `src/state.ts`, `src/render.ts`, `src/diff.ts`, `src/styles.css`, `src/diff.test.ts`
- Modify: `biome.json` (nothing expected; verify demo is covered)

**Interfaces:**
- Consumes: `@nazr/thumbmark` (`Thumbmark`, `ThumbmarkResponse`, `stableStringify`), API `/readyz`.
- Produces: `diffResults(prev: ThumbmarkResponse | null, next: ThumbmarkResponse): { added: string[]; removed: string[]; changed: string[] }` over dotted component paths in `src/diff.ts`; `loadState()/saveState(s)` in `state.ts`; `render(root: HTMLElement, model: ViewModel)` in `render.ts`.

- [ ] **Step 1: Write failing test `diff.test.ts`** (Vitest, `pnpm --filter @nazr/demo test`): `diffResults(null, r)` → all paths `added`; changed leaf value → in `changed` with its dotted path (`screen.colorDepth`); removed key → `removed`; identical → all empty.

- [ ] **Step 2: Run** — Expected: FAIL.

- [ ] **Step 3: Scaffold the app**: Vite vanilla TS; `package.json` deps `@nazr/thumbmark: workspace:*`, devDeps `vite ^6`, `vitest ^3`, `@playwright/test`, `typescript`. Implement `diff.ts`, then `state.ts`, `render.ts`, `main.ts`:
  - Header form: endpoint (default `https://localhost`), API key, "simple request" checkbox, Run button, "Clear visitor" button (removes `thumbmark_visitor_id`).
  - Banner: fetches `<endpoint>/readyz`; shows version, which sources are loaded, and warns "TLS fingerprint unavailable" when the response from `/thumbmark` lacks `components.tls`.
  - Panels: Thumbmark + visitor (id, isNew, firstSeen/lastSeen); Classification (flags as colored chips, danger level as 0–5 meter, signals list); Server components (`tls`, `h2`, `header`, `ip`) as collapsible trees; Client components as collapsible trees; Timing table from `elapsed` (run with `performance: true`); Diff vs previous run; Raw JSON `<details>`.
  - Errors: when `result.error` is present or the API returns non-200, render the error type and message in a red panel (403 → "Unauthorized: check the key and allowed origins").

- [ ] **Step 4: Run** `pnpm --filter @nazr/demo test && pnpm --filter @nazr/demo build && pnpm lint && pnpm typecheck` — Expected: PASS, `dist/` produced.

- [ ] **Step 5: Manual check** against the compose stack: `pnpm --filter @nazr/demo dev`, open, enter a key from `nazr keys create`, run — Expected: all panels populate; a wrong key shows the red panel.

- [ ] **Step 6: Commit** `git add -A && git commit -m "feat(demo): vite demo page with component trees, classification and diff"`

---

### Task 3: End-to-end tests

**Files:**
- Create: `apps/demo/e2e/playwright.config.ts`, `apps/demo/e2e/global-setup.ts`, `apps/demo/e2e/hash-agreement.spec.ts`, `apps/demo/e2e/stock-client.spec.ts`, `apps/demo/e2e/stock-client.html`
- Modify: `apps/demo/package.json` (`test:e2e`)

**Interfaces:**
- Consumes: compose stack or a locally built `apps/api/bin/nazr`; `global-setup.ts` starts the API in `terminate` mode on `127.0.0.1:8443` with a self-signed cert and a Postgres from `NAZR_E2E_DATABASE_URL` (defaults to the compose Postgres on `localhost:5432`), runs `migrate`, creates a key, and exposes `NAZR_E2E_KEY`.

- [ ] **Step 1: Write `hash-agreement.spec.ts`**: Chromium with `ignoreHTTPSErrors`, open the demo (`vite preview`), fill endpoint `https://127.0.0.1:8443` and key, click Run, wait for the thumbmark panel; then in page context compute `hash(stableStringify(result.components))` using the fork's exports (expose `window.__nazr = { stableStringify, hash }` from `main.ts` in dev/preview builds) and assert equality with the displayed `thumbmark`; assert `components.tls.ja4` matches the JA4 regex and `components.h2.fingerprint` is non-empty; run again and assert `info.visitor.isNew === false` with the same `visitorId`.

- [ ] **Step 2: Write `stock-client.spec.ts`**: serve `stock-client.html` (loads `https://cdn.jsdelivr.net/npm/@thumbmarkjs/thumbmarkjs@1.12.0/dist/thumbmark.umd.js`, calls `new ThumbmarkJS.Thumbmark({ api_key, api_endpoint, logging: false }).get()`), assert a 32-hex `thumbmark`, a `visitorId`, and `info.classification` present; also intercept network and assert no request went to `*.thumbmarkjs.com` other than the CDN script.

- [ ] **Step 3: Run** `pnpm --filter @nazr/demo test:e2e` — Expected: FAIL (setup missing), then after implementing `global-setup.ts` and `playwright.config.ts` (`webServer` for `vite preview`), PASS.

- [ ] **Step 4: Commit** `git add -A && git commit -m "test(e2e): hash agreement and stock client compatibility"`

---

### Task 4: Terraform AWS module

**Files:**
- Create: `deploy/terraform/aws/{main.tf,variables.tf,outputs.tf,versions.tf,README.md,examples/minimal/main.tf,examples/existing-vpc/main.tf,.tflint.hcl}`
- Create: `deploy/terraform/aws/modules/network/{main.tf,variables.tf,outputs.tf}`
- Create: `deploy/terraform/aws/modules/database/{main.tf,variables.tf,outputs.tf}`
- Create: `deploy/terraform/aws/modules/cert/{main.tf,variables.tf,outputs.tf}`
- Create: `deploy/terraform/aws/modules/service/{main.tf,variables.tf,outputs.tf,task.tf,nlb.tf,iam.tf}`
- Create: `docs/deploy-aws.md`

**Interfaces:**
- Root variables (spec 14.2): `domain`, `route53_zone_id`, `region`, `image` (default `ghcr.io/OWNER/nazr:latest`), `desired_count` (2), `cpu` (512), `memory` (1024), `db_instance_class` (`db.t4g.micro`), `db_allocated_storage` (20), `enable_redis` (false), `redis_node_type` (`cache.t4g.micro`), `maxmind_account_id`, `maxmind_license_key` (sensitive), `admin_token` (sensitive), `certificate_pem`/`private_key_pem` (sensitive, default `""`), `acme_email`, `acme_server_url` (default Let's Encrypt prod), `vpc_id`/`private_subnet_ids`/`public_subnet_ids` (default `null`/`[]`), `event_retention` (`2160h`), `cors_origins` (`*`), `extra_env` (map), `tags` (map).
- Root outputs: `api_url`, `nlb_dns_name`, `ecs_cluster_name`, `ecs_service_name`, `first_key_command`.
- `modules/network` outputs `vpc_id`, `public_subnet_ids`, `private_subnet_ids`; created only when `var.vpc_id == null` (`count`).
- `modules/database` outputs `database_url_secret_arn`, `redis_url` (`""` when disabled), `security_group_id`.
- `modules/cert` outputs `cert_secret_arn`, `key_secret_arn`; `count = var.certificate_pem == "" ? 1 : 0`; when PEM given, root writes it to the two secrets itself.
- `modules/service` inputs the ARNs and creates: ECS cluster, CloudWatch log group (30d), task execution role (ECR pull, logs, `secretsmanager:GetSecretValue` on the listed ARNs), task role (none beyond ECS Exec), task definition (env: `NAZR_TLS_MODE=terminate`, `NAZR_DATA_DIR=/data`, `NAZR_EVENT_RETENTION`, `NAZR_CORS_ORIGINS`, `NAZR_METRICS_ADDR=127.0.0.1:9090`, `extra_env`; secrets: `NAZR_DATABASE_URL`, `NAZR_TLS_CERT_PEM`, `NAZR_TLS_KEY_PEM`, `NAZR_MAXMIND_ACCOUNT_ID`, `NAZR_MAXMIND_LICENSE_KEY`, `NAZR_ADMIN_TOKEN`, optional `NAZR_REDIS_URL`), ephemeral storage 21 GiB mounted at `/data`, service with `enable_execute_command = true`, NLB (internet-facing, public subnets, cross-zone on), TCP 443 and TCP 80 listeners → target groups (`target_type = "ip"`, `preserve_client_ip = true`, health check TCP on 443), Route53 `A` alias, security groups (NLB SG: 443/80 from `0.0.0.0/0` and `::/0`; task SG: 443/80 from the VPC CIDR since NLB preserves client IPs and health checks come from NLB nodes in the VPC).

- [ ] **Step 1: Write the "tests"**: `.tflint.hcl` enabling the `aws` plugin, and `examples/minimal/main.tf` + `examples/existing-vpc/main.tf` calling the root module (the second passes `vpc_id` and subnet lists). Run `terraform -chdir=deploy/terraform/aws/examples/minimal init -backend=false && terraform validate` — Expected: FAIL (module missing).

- [ ] **Step 2: Write `versions.tf`, `variables.tf`, `main.tf`, `outputs.tf`** and the four modules.

- [ ] **Step 3: Validate**

Run (from repo root):
```bash
for d in deploy/terraform/aws deploy/terraform/aws/examples/minimal deploy/terraform/aws/examples/existing-vpc; do
  terraform -chdir=$d init -backend=false -input=false >/dev/null && terraform -chdir=$d validate && terraform -chdir=$d fmt -check -recursive
done
tflint --chdir=deploy/terraform/aws --recursive
```
Expected: all succeed with no diagnostics.

- [ ] **Step 4: Plan against a real account (optional but recommended once)**: `terraform -chdir=deploy/terraform/aws/examples/minimal plan` with real `domain`/`route53_zone_id` — Expected: a plan with no errors; do not apply in this task.

- [ ] **Step 5: Write `README.md` and `docs/deploy-aws.md`**: prerequisites (Route53 zone, ECR or GHCR image), variables table, the two examples, how certificates are issued and renewed (re-run `apply`; `acme_certificate.min_days_remaining = 30`), how to create the first key with the `first_key_command` output, cost notes, and the caveat that TLS/H2 fingerprints require the NLB TCP passthrough as configured (no ALB, no CloudFront).

- [ ] **Step 6: Commit** `git add -A && git commit -m "feat(deploy): aws terraform module with nlb tcp passthrough, ecs fargate, rds and acme"`

---

### Task 5: CI and release workflow

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/dependabot.yml`

**Interfaces:**
- `ci.yml` on push and PR: job `ts` (pnpm install, `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm build`, upload `apps/demo/dist`), job `go` (setup-go 1.26, `pnpm --filter @nazr/api lint`, `go test -race ./...` with a `postgres:17` service container and `NAZR_TEST_REQUIRE_DB=1`, `NAZR_TEST_DATABASE_URL`), job `fixtures` (regenerate fixtures and `git diff --exit-code apps/api/testdata/fixtures`), job `compose` (build image, `docker compose up -d`, `bash deploy/compose/smoke.sh`), job `e2e` (needs `compose`; `playwright install --with-deps chromium`; `pnpm --filter @nazr/demo test:e2e` with `NAZR_E2E_DATABASE_URL` pointing at the compose Postgres via the `dev` profile), job `terraform` (setup-terraform 1.14, tflint, the validate loop from Task 4).
- `release.yml` on tag `v*`: build and push multi-arch image to GHCR with `docker/build-push-action`, tags `<version>` and `latest`, `VERSION` build arg; publish `@nazr/thumbmark` to npm when `NPM_TOKEN` is set (`pnpm publish --filter @nazr/thumbmark --no-git-checks`).

- [ ] **Step 1: Write both workflows and `dependabot.yml`** (npm, gomod, docker, github-actions, terraform; weekly).

- [ ] **Step 2: Validate locally** with `act -l` if installed, otherwise push a branch and confirm all jobs are green on GitHub.

- [ ] **Step 3: Commit** `git add -A && git commit -m "ci: lint, test, fixtures, compose smoke, e2e and terraform validation"`

---

### Task 6: Top-level README and source-build docs

**Files:**
- Modify: `README.md`
- Create: `docs/deploy-source.md`, `CONTRIBUTING.md`

- [ ] **Step 1: Write `docs/deploy-source.md`** with the exact commands from spec 14.3 plus the Postgres prerequisite, `NAZR_TLS_MODE=plain` for local, and `terminate` with `NAZR_ACME_DOMAINS` for a single VM.

- [ ] **Step 2: Rewrite `README.md`**: what nazr is, the compatibility promise (stock client + `api_endpoint`), a 60-second compose quick start, links to `docs/protocol.md`, `docs/signals.md`, `docs/configuration.md`, the three deploy guides, the client package README, licensing (GPL-3.0 repo, MIT upstream attribution), and a status table of signals (client/server/deferred).

- [ ] **Step 3: Write `CONTRIBUTING.md`**: toolchain versions, `pnpm` commands, how fixtures are regenerated, how to sync upstream with `upstream:diff`, commit message convention (`feat|fix|chore|docs|test(scope): ...`).

- [ ] **Step 4: Run** `pnpm lint && pnpm typecheck && pnpm test` one final time — Expected: PASS.

- [ ] **Step 5: Commit** `git add -A && git commit -m "docs: readme, contributing and source deployment guide"`
