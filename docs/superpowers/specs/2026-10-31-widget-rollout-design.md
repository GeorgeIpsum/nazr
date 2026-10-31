# Widget rollout: nazr on a VPS, verified from the blog

Date: 2026-10-31
Status: parked (real-world test deferred on 2026-10-31; hosting to be decided when a server exists)
Parent spec: [2026-10-21-nazr-design.md](2026-10-21-nazr-design.md)
Builds on: [2026-10-31-widget-phase2b-design.md](2026-10-31-widget-phase2b-design.md)

## 1. Purpose

Put the widget in front of a real page for the first time. A small VPS runs
nazr's own compose stack under `nazr.ibrahimsaberi.com`, owns ports 80 and
443 and terminates TLS itself, so JA4 and the HTTP/2 fingerprint are captured
for real browsers. The blog's preview deployment (`rc.ibrahimsaberi.com`)
gets a `/verify` page that embeds the loader and checks the token server-side
through siteverify. Success means a laptop browser earns a `pass` token, the
blog's backend verifies it, and nazr's stored report carries a non-empty JA4.

Decisions taken during design:

- **Own box, own ports.** nazr runs alone on the VPS with no reverse proxy;
  Docker publishes 80 and 443 straight to the `api` container.
- **DNS-only hostname.** The Cloudflare record is grey-cloud. A proxied
  record would terminate TLS at Cloudflare and nazr would fingerprint
  Cloudflare, not the visitor.
- **Built-in ACME.** nazr's autocert obtains and renews the certificate; no
  certbot, no cert files.
- **Preview only.** Keys and secrets exist for the `release/1.0.0` preview
  origin. Production comes later with its own key.

## 2. Non-goals

- Rolling the page out on the production blog (`main`).
- Moving nazr behind Cloudflare, or onto a shared host behind a proxy.
- Monitoring dashboards. `/metrics` stays on `127.0.0.1:9090` on the box
  (compose default); scraping it is separate work.
- High availability: one VPS, one `api` container, in-memory rate limiter.
- Correlation through the page's own `/thumbmark` call (section 5.4).

## 3. Architecture

```
laptop browser ──https──> rc.ibrahimsaberi.com/verify        (Vercel preview, Cloudflare DNS)
      │  loader.js, frame, /widget/report  (direct, grey-cloud)
      └──────https:443──> nazr.ibrahimsaberi.com  ─ VPS ─ docker: api (80, 443) + postgres
Vercel function /api/verify ──POST /widget/v1/siteverify──┘
```

The frame's TLS ClientHello and HTTP/2 preface reach nazr unmodified, so the
report gets `tls`, `h2` and `header` components. The blog never sees the
verify secret client-side; only its route handler calls siteverify.

On the old ebloved host the options were Traefik SNI passthrough on 443 with
PROXY v2 (which needed the Cloudflare-only 80/443 lockdown loosened) or a
second IPv4; on a dedicated VPS nazr owns 443 directly, so neither applies.

## 4. nazr on the VPS

### 4.1 Host

- Hetzner Cloud, 2 vCPU / 4 GB (CX or CAX: the image is multi-arch), Debian 12
  or Ubuntu 24.04. Any Debian/Ubuntu VPS works.
- Docker Engine and the Compose plugin from Docker's apt repository
  (Compose ≥ 2.24.4, required by `env_file.required` and `!override`).
  `/etc/docker/daemon.json`: `{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"}}`.
- Firewall: the **Hetzner Cloud firewall** inbound TCP 22 (from the
  operator's address or tailnet only), 80 and 443 from anywhere, ICMP.
  Prefer it over ufw: Docker-published ports bypass ufw's INPUT rules, so ufw
  alone cannot restrict 80/443 (harmless here, since they are public by
  design, but misleading). ufw may still guard 22.
- DNS: Cloudflare grey-cloud `A nazr.ibrahimsaberi.com` → the VPS. No IP is
  written in any repo. `AAAA` is deferred (section 12, item 2).

### 4.2 Image

`.github/workflows/release.yml` already exists. On a `v*` tag push it builds
the widget, syncs it into `apps/api` (so the image embeds the loader, frame
and worker), and pushes `ghcr.io/<owner>/nazr:<tag>` and `:latest` for
linux/amd64 and linux/arm64 (docker/metadata-action lowercases the owner, so
`ghcr.io/georgeipsum/nazr`). No tag has been pushed yet, so no image exists.

To add: nothing in the workflow. Push `v0.1.0`; after the first run, set the
GHCR package to public (or `docker login ghcr.io` on the box with a
`read:packages` token). The npm job skips while `NPM_TOKEN` is unset.

### 4.3 Compose override (new, in this repo)

`docker-compose.yml` builds from source and points the TLS file variables at
the self-signed `certgen` output. Because nazr prefers files over ACME and
`${VAR:-default}` treats an empty `.env` value as unset, the files must be
cleared in an override, not in `.env`.
`deploy/compose/compose.ghcr.yml`:

```yaml
# Run the released image with built-in ACME instead of the self-signed cert.
#   docker compose -f docker-compose.yml -f compose.ghcr.yml up -d
services:
  api:
    build: !reset null
    image: ghcr.io/georgeipsum/nazr:${NAZR_VERSION:-latest}
    environment:
      NAZR_TLS_CERT_FILE: "" # files win over ACME; clear them
      NAZR_TLS_KEY_FILE: ""
      NAZR_ACME_DOMAINS: ${NAZR_ACME_DOMAINS:?set NAZR_ACME_DOMAINS in .env}
      NAZR_ACME_EMAIL: ${NAZR_ACME_EMAIL:?set NAZR_ACME_EMAIL in .env}
      NAZR_ACME_DIR: /data/acme # on the nazrdata volume, survives restarts
    depends_on: !override
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
        required: false
```

`NAZR_HTTP_ADDR` keeps its compose default `:80` (HTTP-01 and the 308
redirect). The override drops the `certgen` dependency, so no self-signed
certificate is generated. The image tag defaults to `latest`; pin
`NAZR_VERSION` in `.env` on a real box so upgrades are deliberate.

### 4.4 `.env` on the box

`/opt/nazr/deploy/compose/.env`, mode 0600, root-owned, never committed:

```bash
NAZR_VERSION=v0.1.0
NAZR_ACME_DOMAINS=nazr.ibrahimsaberi.com
NAZR_ACME_EMAIL=<operator email>
NAZR_WIDGET_ISSUER=https://nazr.ibrahimsaberi.com
NAZR_CORS_ORIGINS=https://rc.ibrahimsaberi.com
NAZR_STORE_IP=hash
NAZR_ADMIN_TOKEN=<openssl rand -hex 32>
NAZR_IP_HASH_SALT=<openssl rand -hex 32>
```

Generate the two secrets in place without echoing them:
`printf 'NAZR_ADMIN_TOKEN=%s\nNAZR_IP_HASH_SALT=%s\n' "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" >> .env`.
`NAZR_AUTO_MIGRATE=true` and `NAZR_TLS_MODE=terminate` are compose defaults.
The first `serve` creates the widget signing key.

### 4.5 Backups and upgrades

- Daily dump, kept by weekday, root-only (the dump holds the signing keys in
  plaintext, see section 9). `/etc/cron.d/nazr-pgdump`:

  ```
  17 3 * * * root cd /opt/nazr/deploy/compose && docker compose exec -T postgres pg_dump -U nazr -Fc nazr > /var/backups/nazr/nazr-$(date +\%u).dump
  ```

  Alternatively, or additionally, Hetzner Cloud backups/snapshots of the
  server. Off-box copies are an open question.
- Upgrade: in `/opt/nazr`, `git fetch --tags && git checkout v<next>`, bump
  `NAZR_VERSION` in `.env`, then
  `docker compose -f docker-compose.yml -f compose.ghcr.yml pull && docker compose -f docker-compose.yml -f compose.ghcr.yml up -d`.
  Migrations run on start.

## 5. Blog page (ibrahimsaberi.com)

Work happens in a git worktree on a new branch off `release/1.0.0`
(`git worktree add ../ibrahimsaberi.com-verify -b feat/nazr-verify release/1.0.0`);
the main checkout has uncommitted changes and is not touched. The branch is
merged into `release/1.0.0` to reach `rc.ibrahimsaberi.com`, the origin the
key allows. The blog has no CSP, so no header changes.

### 5.1 Env (`src/env.ts`)

Server: `NAZR_SITEVERIFY_SECRET: type("string | undefined")`. Client:
`NEXT_PUBLIC_NAZR_ENDPOINT` and `NEXT_PUBLIC_NAZR_SITE_KEY`, both
`type("string | undefined")`, with literal `process.env.NEXT_PUBLIC_*`
entries in `runtimeEnv` as the existing comment requires. All optional, so
production builds without them. Values are set in Vercel for **Preview,
branch `release/1.0.0`** only; `NEXT_PUBLIC_*` are inlined at build time, so
redeploy after setting them.

### 5.2 `src/app/(root)/verify/page.tsx` and `src/features/verify/verify-form.tsx`

The page (server component, following `contact/page.tsx`) reads the two
public vars; when either is unset it renders a placeholder paragraph
("verification is not configured here"). Otherwise it renders `VerifyForm`
with `endpoint` and `siteKey`, plus a one-line notice that the page runs a
bot check served from `nazr.ibrahimsaberi.com`. Metadata sets
`robots: { index: false }`.

```tsx
"use client";
import Script from "next/script";
import { useEffect, useState } from "react";

declare global {
  interface Window {
    __nazrWidget?: { ready: Promise<{ nonce: string }>; token?: string; state: string; reset(): void };
    nazrVerifyToken?: (t: string) => void;
    nazrVerifyError?: (r: string) => void;
    nazrVerifyExpired?: () => void;
  }
}

export function VerifyForm({ endpoint, siteKey }: { endpoint: string; siteKey: string }) {
  const [token, setToken] = useState<string>();
  const [status, setStatus] = useState("waiting for the widget");
  const [result, setResult] = useState<{ status: number; body: any }>();
  useEffect(() => {
    window.nazrVerifyToken = (t) => { setToken(t); setStatus(`token (${window.__nazrWidget?.state})`); };
    window.nazrVerifyError = (r) => { setToken(undefined); setStatus(`no token: ${r}`); };
    window.nazrVerifyExpired = () => { setToken(undefined); setStatus("token expired, refreshing"); };
    return () => { delete window.nazrVerifyToken; delete window.nazrVerifyError; delete window.nazrVerifyExpired; };
  }, []);
  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const res = await fetch("/api/verify", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
    setResult({ status: res.status, body: await res.json().catch(() => null) });
    window.__nazrWidget?.reset(); // tokens are single use
  }
  return (
    <form onSubmit={onSubmit}>
      <input name="message" required />
      <div id="nazr-box" />
      <button type="submit" disabled={!token}>send</button>
      <p>{status}</p>
      {result && (<>
        <p>{result.status} · verdict: {result.body?.verdict ?? "none"} · success: {String(result.body?.success)} · {result.body?.error_codes?.join(", ")}</p>
        <pre>{JSON.stringify({ correlation: result.body?.correlation, interaction: result.body?.interaction, classification: result.body?.classification }, null, 2)}</pre>
      </>)}
      <Script src={`${endpoint}/widget/v1/loader.js`} strategy="afterInteractive"
        data-api-key={siteKey} data-container="#nazr-box" data-callback="nazrVerifyToken"
        data-error-callback="nazrVerifyError" data-expired-callback="nazrVerifyExpired" />
    </form>
  );
}
```

**Deviation from the brief: no hidden input.** The loader adds
`nazr-token` only when `document.currentScript.closest("form")` is a form
(`packages/widget/src/loader.ts`), and `next/script` with `afterInteractive`
appends the script to `<body>`, not where the JSX sits. The token therefore
comes from `data-callback`, which the loader fires the same way. Because
`next/script` loads a given `src` once per session, the loader does not
re-mount after a client-side navigation back to `/verify`; the page is
reached by a full load (not linked with `<Link>`).

### 5.3 `src/app/api/verify/route.ts`

```ts
import { type NextRequest, NextResponse } from "next/server";
import { env } from "@/env";

export const POST = async (request: NextRequest) => {
  const endpoint = env.NEXT_PUBLIC_NAZR_ENDPOINT;
  const secret = env.NAZR_SITEVERIFY_SECRET;
  if (!endpoint || !secret) return NextResponse.json({ error: "not_configured" }, { status: 503 });
  const body = await request.json().catch(() => null);
  const token = typeof body?.token === "string" ? body.token : "";
  if (!token || token.length > 4096) return NextResponse.json({ error: "bad_request" }, { status: 400 });
  const remoteip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || undefined;
  try {
    const res = await fetch(`${endpoint}/widget/v1/siteverify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secret, token, remoteip }),
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    if (res.status !== 200) return NextResponse.json({ error: "upstream", status: res.status }, { status: 502 });
    return NextResponse.json(await res.json()); // siteverify never echoes the secret
  } catch {
    return NextResponse.json({ error: "upstream" }, { status: 502 });
  }
};
```

On Vercel the first `x-forwarded-for` entry is the client address. A 401
(`invalid-secret`), 429 or 503 from nazr becomes a 502 with the upstream
status; a 200 with `success: false` passes through unchanged.

### 5.4 Correlation

`@nazr/thumbmark` 0.1.0 is not on npm (the registry answers 404; the release
job's npm step skips without `NPM_TOKEN`), and nazr serves no UMD build
outside `NAZR_DEMO_DIR`. The simplest path is to **skip the page's
`/thumbmark` call** for this test: the token works without it, and
siteverify's `correlation` reads `matched: false`. Adding
`getThumbmark({ api_endpoint, api_key, nonce, cache_api_call: false })`
after `await window.__nazrWidget?.ready` is a follow-up once the package is
published.

## 6. Secrets and configuration

| Item | Where | Who sees it |
|---|---|---|
| `NAZR_ADMIN_TOKEN`, `NAZR_IP_HASH_SALT` | `.env` on the VPS (0600) | operator |
| ACME account key, certificate | `nazrdata` volume, `/data/acme` | the box |
| Signing keys (private halves, HMAC secrets) | Postgres `pgdata` volume, dumps | the box |
| API key `nzr_…` | Vercel Preview `NEXT_PUBLIC_NAZR_SITE_KEY` | public by design (frame URL) |
| Siteverify secret `nzs_…` | Vercel Preview `NAZR_SITEVERIFY_SECRET` (server only) | Vercel function |
| `NEXT_PUBLIC_NAZR_ENDPOINT` | Vercel Preview: `https://nazr.ibrahimsaberi.com` | public |

## 7. Operator runbook

1. **Release.** Push tag `v0.1.0` in nazr; wait for the `Release` workflow;
   make `ghcr.io/georgeipsum/nazr` public (or log in on the box).
2. **Server.** Create the VPS and its Cloud firewall (section 4.1); install
   Docker; set the daemon log options.
3. **DNS.** Add grey-cloud `A nazr.ibrahimsaberi.com` in Cloudflare. Wait
   until it resolves to the VPS (ACME needs it).
4. **Stack.** `git clone --depth 1 --branch v0.1.0 https://github.com/GeorgeIpsum/nazr /opt/nazr`
   (the override file must be in that tag, or copied in); write `.env`
   (section 4.4); in `/opt/nazr/deploy/compose` run
   `docker compose -f docker-compose.yml -f compose.ghcr.yml pull` then `... up -d`.
5. **Check.** `curl -sf https://nazr.ibrahimsaberi.com/readyz` returns 200
   with a Let's Encrypt certificate; `curl -sI http://nazr.ibrahimsaberi.com/`
   answers 308.
6. **Key.** `docker compose -f docker-compose.yml -f compose.ghcr.yml exec -T api /nazr keys create --label blog --origins https://rc.ibrahimsaberi.com`.
   Line 1 is the API key, line 2 the siteverify secret, line 3 the id. Copy
   them straight into Vercel (step 7); do not paste them anywhere else.
7. **Vercel.** Set the three variables for Preview, branch `release/1.0.0`
   (`vercel env add <NAME> preview release/1.0.0`).
8. **Backups.** Install the cron file (section 4.5); create
   `/var/backups/nazr` mode 0700.
9. **Blog.** Implement section 5 in the worktree, merge into
   `release/1.0.0`, wait for the rc deployment.

## 8. Verification

From a laptop browser, full load of `https://rc.ibrahimsaberi.com/verify`:

1. DevTools Network: `loader.js`, `frame?k=…` and the worker bundle load from
   `https://nazr.ibrahimsaberi.com`; `POST /widget/report` answers
   `{"verdict":"pass","token":…}`.
2. The status line shows `token (pass)`; `window.__nazrWidget.state` is
   `pass` and `window.__nazrWidget.token` is set.
3. Submit: `/api/verify` returns 200 with `success: true`, `verdict: "pass"`,
   `hostname: "https://rc.ibrahimsaberi.com"`, no `error_codes`. Submitting
   the same token again (e.g. replaying the request) yields `replayed`.
4. Admin summary, run on the box so the token stays there:
   `curl -s -H "Authorization: Bearer $(sed -n 's/^NAZR_ADMIN_TOKEN=//p' .env)" https://nazr.ibrahimsaberi.com/admin/keys/<id>/widget`
   shows `reports ≥ 1`, `pass ≥ 1`, `verified ≥ 1`.
5. Fingerprints captured (TLS really terminates in nazr):
   `docker compose exec -T postgres psql -U nazr -d nazr -c "select verdict, left(ja4, 12) as ja4, h2fp <> '' as h2 from widget_reports order by created_at desc limit 3"`
   shows a non-empty `ja4` and `h2 = t`.
6. Interactive path: set `NAZR_WIDGET_PASS_MAX_DANGER=0` in `.env`, `up -d`,
   and load the page from a connection with danger ≥ 1 (a commercial VPN, so
   the VPN list fires). The box renders in `#nazr-box`; after a click,
   `/api/verify` shows `verdict: "interactive"` and an `interaction` block,
   and the summary counts `interactive ≥ 1`. Revert the variable afterwards.
7. Negative checks: the same page served from another origin (a branch
   preview URL) shows no frame (`frame-ancestors`); a wrong secret in Vercel
   makes `/api/verify` answer 502.

## 9. Security and privacy

- **Exposure.** The DNS-only record publishes the VPS address. Nothing else
  runs there; nazr's per-key rate limit (600/min default, in memory) and the
  body limit are the protection; there is no WAF or DDoS shield in front.
- **Admin API** is reachable on 443 behind a 64-hex bearer token (404 when
  unset). Prefer calling it from the box.
- **Signing keys are plaintext in Postgres** (see widget.md, trust
  boundary): the `pgdata` volume, the dumps and any server snapshots can
  mint tokens. Dumps are root-only; Postgres is not published by compose.
  The compose file's fixed `nazr:nazr` database password relies on that.
- **Secrets** live only in `.env` (0600) and Vercel's server-side variable;
  nothing secret is committed to any repo. The verify secret is never sent
  to the browser or echoed by the route.
- **Visitors.** `NAZR_STORE_IP=hash` stores salted IP identifiers only;
  events and reports are pruned after 90 days (default). The page tells
  visitors it runs a bot check from nazr.
- **Embedding** is limited to `https://rc.ibrahimsaberi.com` by the key's
  origins (frame `frame-ancestors`) and `NAZR_CORS_ORIGINS`.
- **SSH** only from the operator's address or tailnet.

## 10. Affected files per repo

- **nazr:** this spec; new `deploy/compose/compose.ghcr.yml`; a short
  section in `docs/deploy-compose.md` on running the released image with
  ACME. `release.yml` unchanged. Tag `v0.1.0`.
- **ibrahimsaberi.com** (branch off `release/1.0.0`): `src/env.ts`,
  `src/app/(root)/verify/page.tsx`, `src/features/verify/verify-form.tsx`,
  `src/app/api/verify/route.ts`.
- **VPS (not in any repo):** `/opt/nazr` checkout, `.env`,
  `/etc/docker/daemon.json`, `/etc/cron.d/nazr-pgdump`.
- **Cloudflare / Vercel / Hetzner consoles:** DNS record, Preview env vars,
  Cloud firewall.

## 11. Appendix: If the NixOS/k3s stack is rebuilt

Option C as designed for ebloved (GeorgeIpsum/nix-config `hosts/hetzner`,
GeorgeIpsum/homelab `apps/`), kept for reference. Argo's root app syncs
`apps/` recursively, so a new `apps/nazr/` directory is picked up as is.

- **Why hostNetwork:** k3s svclb masquerades client addresses, and Traefik
  owns 80/443 behind a Cloudflare-only nftables lockdown. nazr runs as a
  `hostNetwork: true` Deployment on `:8443` (`strategy: Recreate`, since two
  pods cannot bind the port; `dnsPolicy: ClusterFirstWithHostNet` to resolve
  `nazr-db-rw.nazr`; probes `httpGet` on `/healthz` and `/readyz`,
  `port: 8443`, `scheme: HTTPS`; requests `100m`/`128Mi`, limit `512Mi` in
  the ebloved style; container `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`; `NAZR_LISTEN_ADDR=:8443`, `NAZR_HTTP_ADDR=off`,
  `NAZR_METRICS_ADDR=off`, `NAZR_TLS_CERT_FILE=/certs/tls.crt`,
  `NAZR_TLS_KEY_FILE=/certs/tls.key`,
  `NAZR_WIDGET_ISSUER=https://nazr.ibrahimsaberi.com:8443`, image
  `ghcr.io/georgeipsum/nazr:<version>`).
- **Certificate:** a `cert-manager.io/v1` `Certificate` `nazr-tls`
  (`dnsNames: [nazr.ibrahimsaberi.com]`, `issuerRef: {kind: ClusterIssuer, name: letsencrypt}`,
  the existing Cloudflare DNS-01 issuer, which already serves
  `lonk.ibrahimsaberi.com`), mounted as a secret volume at `/certs`
  (`defaultMode: 0440`, pod `fsGroup: 65532`). No existing app used a
  standalone Certificate; all used the Ingress annotation.
- **Database:** CNPG `Cluster` `nazr-db` in namespace `nazr`
  (`instances: 1`, `storage: {size: 2Gi, storageClass: local-path}`,
  `bootstrap.initdb: {database: nazr, owner: nazr}`, annotation
  `argocd.argoproj.io/sync-options: SkipDryRunOnMissingResource=true`);
  `NAZR_DATABASE_URL` from `secretKeyRef {name: nazr-db-app, key: uri}`, as
  ebloved does. The CNPG server there was PG18.
- **Secrets:** SealedSecret `nazr-env` (keys `NAZR_ADMIN_TOKEN`,
  `NAZR_IP_HASH_SALT`, `template.metadata` repeating name and namespace),
  sealed with `kubectl create secret generic … --dry-run=client -o yaml | kubeseal --controller-name sealed-secrets --controller-namespace kube-system -o yaml`.
- **Firewall:** `networking.firewall.allowedTCPPorts = [ 8443 ];` in
  `hardening.nix`. hostNetwork traffic hits INPUT, not FORWARD; the
  `cf-only-ingress` table hooks only `forward` and matches original dports
  80, 443 and 27017, so it does not touch 8443 and must not gain it. Deploy
  with `nixos-rebuild switch --flake .#hetzner`.
- **Runbook there:** DNS record; nix change and rebuild; seal secrets; commit
  `apps/nazr/`; Argo sync; `kubectl -n nazr exec deploy/nazr -- /nazr keys create --label blog --origins https://rc.ibrahimsaberi.com`;
  Vercel variables with the `:8443` endpoint. The homelab README forbids
  server IPs or tailnet names in that public repo.

## 12. Open questions

1. **Hostname and provider** are to be confirmed (`nazr.ibrahimsaberi.com`,
   Hetzner Cloud). A "Cloudflare VPS" is not an option: Cloudflare
   Containers sit behind Cloudflare's edge, which terminates TLS and loses
   the JA4 and HTTP/2 fingerprints.
2. **`AAAA` record.** Two problems before adding it: Docker without IPv6
   enabled accepts IPv6 connections through `docker-proxy`, so nazr would see
   the bridge gateway instead of the client; and a dual-stack laptop may
   reach Vercel over one family and nazr over the other, making siteverify
   `remoteip-mismatch`. Start with `A` only; add `AAAA` after enabling
   Docker IPv6 (`daemon.json` `ipv6`/`ip6tables`, an IPv6 compose network)
   and checking which family Vercel sees.
3. **GHCR** on first release: confirm the pushed name is lowercase
   `ghcr.io/georgeipsum/nazr` and choose public visibility vs a pull token.
4. **`NAZR_STORE_IP=hash`** is a privacy default I added for real visitors;
   confirm.
5. **Off-box backups:** where daily dumps go (Hetzner Storage Box, restic to
   the tailnet, or Cloud backups only).
6. **Production origin:** there is no `keys update`; adding
   `https://ibrahimsaberi.com` later means a second key (and secret) for
   production, which fits the per-environment Vercel variables.
7. **Hidden input** (section 5.2): accept the callback-based token, or render
   the loader as a raw `<script>` inside the form server-side, at the cost of
   a hydration mismatch when the loader appends its input.
8. **Compose Postgres password** is fixed (`nazr`); parametrize it in a
   follow-up, or accept it because Postgres is never published.
9. **SSH access:** operator IP allow-list or Tailscale on the new box.
10. **Vercel Deployment Protection** on the rc alias: if enabled, the tester
    must be signed in; it does not affect nazr.
