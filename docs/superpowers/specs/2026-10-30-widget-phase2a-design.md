# Turnstile-style widget, Phase 2a: managed challenge, signed token, siteverify

Date: 2026-10-30
Status: approved for planning
Parent spec: [2026-10-21-nazr-design.md](2026-10-21-nazr-design.md)
Builds on: [2026-10-30-widget-phase1-design.md](2026-10-30-widget-phase1-design.md)
Sibling (later): Phase 2b — interactive step for inconclusive verdicts (not
yet specced)

## 1. Purpose

Phase 1 made the widget an isolated collector whose report nazr can correlate
with the page's `/thumbmark` call. Phase 2a turns it into a passive
bot-challenge: the frame solves a nazr-issued proof-of-work, nazr classifies
the frame's own request, and on a clean verdict it issues a signed token that
the host's backend can verify in two ways:

- **locally**, as a compact JWS against nazr's published JWKS, which answers
  "did this browser pass the widget in isolation";
- **remotely**, through `POST /widget/v1/siteverify` with the key's secret,
  which additionally reports the Phase 1 correlation with the page event,
  the classification and signals, and enforces single use.

The verdict is `pass` or `inconclusive`. Phase 2a issues a token only on
`pass`; an inconclusive visitor gets no token and the host sees an error
callback. Phase 2b adds the interactive step that resolves that branch.

### 1.1 Where the verdict is computed

The page's `/thumbmark` event and the widget report arrive in either order
(Phase 1 §5), so a token that depended on the correlation could not be
issued at report time without waiting. The token is therefore issued at
report time from the frame's own evidence, and the correlation is added at
siteverify time, when both requests have long since landed. Local
verification and siteverify answer different questions by design, and the
embedding guide says so.

## 2. Non-goals (Phase 2a)

- No interactive step. `inconclusive` yields no token (Phase 2b).
- No adaptive proof-of-work difficulty. The difficulty is one deployment-wide
  setting.
- No component-level cross-context comparison (Phase 1 §1.1 still applies).
- No token binding beyond `aud` (the key) and `hostname` (the embedding
  origin). The token is a bearer credential within its five-minute lifetime.
- No scoring of the correlation into the live danger score.
- No key encryption at rest. Anyone with database access can forge tokens;
  the database is the trust boundary (section 8).

## 3. Flow

```
Host page (consumer origin)                     nazr origin
  <script src=".../widget/v1/loader.js"            GET /widget/v1/loader.js
          data-api-key data-callback?>             GET /widget/v1/frame?k=        mints a signed challenge,
    loader: closed shadow root + iframe              -> HTML with data-challenge, data-pow-bits, data-origin
            listens for postMessage from frame     GET /widget/v1/frame.<hash>.js
                                                   GET /widget/v1/worker.<hash>.js  proof-of-work worker
    <- {type:"nazr:challenge", id}                 frame: posts challenge id up, starts the worker,
         (sets __nazrWidget.nonce, resolves ready)        collects components, waits for the solution
                                                   POST /widget/report {challenge, pow, components, clientHash}
                                                     -> 200 {verdict, token?}
    <- {type:"nazr:token", token} or {type:"nazr:error", reason}
         (fills <input name="nazr-token">, calls data-callback)
  host backend: verify JWS against GET /widget/v1/jwks.json
                and/or POST /widget/v1/siteverify {secret, token, remoteip?}
```

### 3.1 Challenge issuance (frame route)

- `GET /widget/v1/frame?k=<key>` now also mints a challenge. The `n` query
  parameter from Phase 1 loaders is ignored (section 10).
- A challenge is `<payload>.<mac>`: `payload` is the base64url (no padding)
  of the JSON object `{ "id", "exp", "bits", "kid", "origin" }` and `mac` is
  the base64url of HMAC-SHA256 over the payload bytes with the active
  signing key's HMAC secret (section 6). Fields: `id` is a new ULID; `exp` is
  Unix seconds, issuance plus `widgetMatchWindow` (10 minutes, so a
  challenge and its correlation window expire together); `bits` is
  `NAZR_POW_BITS`; `kid` names the signing key whose secret signed it;
  `origin` is the embedding origin taken from the request's `Referer`
  header, reduced to scheme, host and port, or `""` when the header is
  absent or unparsable (a host with a `no-referrer` policy gets tokens with
  an empty `hostname`; the guide says so).
- The challenge, `bits` and `origin` reach the frame script as
  `data-challenge`, `data-pow-bits` and `data-origin` attributes on the
  bundle `<script>` tag, since the CSP forbids inline scripts. The template
  gains those three fields.
- No `challenges` table. The challenge is self-authenticating, expiry is in
  the payload, and single use follows from `widget_reports.id` being the
  challenge id and the primary key (section 3.3).
- The frame's CSP gains `worker-src 'self'` for the proof-of-work worker.

> **Amendment, 2026-10-31.** The payload gains `key`, the id of the API key
> the frame was served for, placed after `origin` (and before the Phase 2b
> `stage`). `/widget/report` and `/widget/interact` answer `invalid` when a
> challenge's `key` is present and differs from the authenticating key, so a
> challenge minted for one key cannot be redeemed under another. A challenge
> without `key` (minted before this change) is still accepted; it expires
> within its 10-minute window.
>
> **Amendment, 2026-10-31.** The `key` field and longer ids make payloads
> larger, so the challenge length bound in section 3.3 (and in the Phase 2b
> `/widget/interact` parser) is 1..768 characters, not 1..512.

### 3.2 Proof-of-work

- Hashcash. The frame finds a decimal counter `c` such that
  `SHA-256(id + ":" + c)` has at least `bits` leading zero bits. Default
  `NAZR_POW_BITS=18` is about 262k hashes, roughly 150 to 300 ms on a desktop
  browser with a pure-JS SHA-256 (`@noble/hashes`) in a Web Worker;
  WebCrypto's per-call overhead makes it unusable for this loop.
- The worker is a separate content-hashed bundle `/widget/v1/worker.<hash>.js`,
  served like the frame bundle (immutable). The frame posts `{id, bits}` to
  it and receives `{counter}`.
- `NAZR_POW_BITS=0` disables the work: the frame sends `pow: "0"` and the
  server accepts any counter. Valid range 0..32.
- Server verification is one SHA-256 plus the leading-zero check.

### 3.3 Report and passive verdict (`POST /widget/report`)

The route keeps its Phase 1 middleware behaviour (key, revocation, rate
limit, key touch, origin check skipped). The body becomes
`{ challenge, pow, components, clientHash }`; `nonce` is no longer accepted.
After the middleware the handler always answers `200` with JSON
`{ "verdict": "<v>", "token": "<jws>"? }` where `verdict` is one of:

| verdict        | meaning                                                            | token |
|----------------|--------------------------------------------------------------------|-------|
| `pass`         | challenge valid, PoW valid, classification clean                   | yes   |
| `inconclusive` | challenge and PoW valid, classification not clean                  | no    |
| `pow_failed`   | counter does not satisfy the difficulty                            | no    |
| `invalid`      | body malformed, challenge MAC/expiry/kid invalid, or id already used | no  |

Steps, in order:

1. Parse the body with the Phase 1 bounds (`components` object, `clientHash`
   1..64 hex or absent), plus `challenge` 1..512 chars and `pow` 1..32 decimal
   digits. Any failure → `invalid`, nothing stored.
2. Decode the challenge, look up `kid` among the loaded signing keys (active
   or retired within the JWKS grace, section 6), verify the MAC with constant-
   time comparison, then `exp`. Failure → `invalid`.
3. Verify the proof-of-work. Failure → `pow_failed`. The report is still
   stored (`pow_ok=false`) so the admin summary can count it.
4. Compute the server components and the widget thumbmark with the frame
   client's default stabilization (`["private", "iframe"]`) rather than
   Phase 1's unfiltered merge, so the stored thumbmark is comparable with the
   frame's `clientHash`. Then build `classify.Input` from the frame's own request the way
   `/thumbmark` does: `IP` lookup, `HasTLS`, `UserAgent`,
   `AcceptLanguagePresent`, `JA4Families`, `H2Fingerprint`, `Timezone` from
   `components.locales.timezone`, `Webdriver` from
   `components.privacy.webdriver`. `CanvasProbeAnomaly` stays false and the
   `canvas_probe_anomaly` signal is dropped from the output, as on an
   unscored `/thumbmark`. Automated browsers (Playwright-style, where
   `navigator.webdriver` is true) are classified as bots and therefore end in
   `inconclusive`.
5. Verdict: `pass` when `pow_ok`, `!Bot` and `DangerLevel <=
   NAZR_WIDGET_PASS_MAX_DANGER` (default 2); otherwise `inconclusive`.
6. Insert the `widget_reports` row with `id = challenge id` and
   `nonce = challenge id` (Phase 1 correlation keeps working unchanged). A
   primary-key conflict means the challenge was already used: answer
   `invalid`, store nothing, issue nothing.
7. On `pass`, sign the token (section 5) and set `token_issued_at`.

A `pass` with a valid token is the only path that issues a credential; every
other outcome is observable in the admin summary but yields nothing a host
could accept.

### 3.4 Page nonce

The host no longer supplies a nonce. The frame posts
`{ type: "nazr:challenge", id }` to its parent as soon as it runs, before the
proof-of-work; the loader then sets `window.__nazrWidget.nonce = id` and
resolves `window.__nazrWidget.ready` with `{ nonce: id }`. The host passes
that value as the `/thumbmark` `nonce` option exactly as in Phase 1; only
the timing changes (section 10). `data-nonce` on the loader tag is ignored
with one `console.warn`.

## 4. Loader and frame contract

### 4.1 Messages (frame → parent)

All messages are plain objects posted with
`window.parent.postMessage(msg, targetOrigin)` where `targetOrigin` is
`data-origin` when non-empty and `"*"` otherwise (a token is useless to a
page that did not embed the frame: it is bound to the key and the origin
nazr observed).

| message                                   | when                                          |
|-------------------------------------------|-----------------------------------------------|
| `{ type: "nazr:challenge", id }`          | first thing the frame does                    |
| `{ type: "nazr:token", token }`           | report answered `pass`                        |
| `{ type: "nazr:error", reason }`          | any other outcome; `reason` is the verdict (`inconclusive`, `pow_failed`, `invalid`) or `network` when the report request itself failed |

### 4.2 Loader behaviour

- Derives the nazr origin from `document.currentScript.src`. Accepts a
  message only when `event.source === iframe.contentWindow` **and**
  `event.origin` equals that nazr origin; anything else is ignored.
- Exposes `window.__nazrWidget = { ready, nonce, token, reset }`:
  `ready` is a Promise resolving with `{ nonce }` on the challenge message;
  `nonce` and `token` are `undefined` until their messages arrive;
  `reset()` reloads the iframe, which yields a new challenge and a new token.
- On `nazr:token`: finds the closest `<form>` ancestor of the loader
  `<script>` and appends (or updates) a hidden `<input>` named
  `nazr-token`, overridable with `data-response-field-name`; sets
  `__nazrWidget.token`; calls the global function named by
  `data-callback` with the token, when present.
- On `nazr:error`: calls the global named by `data-error-callback` with the
  reason, when present. The hidden input is left absent.
- Token expiry: the loader decodes the `exp` claim (the payload is readable
  without verification), and when it passes it clears the hidden input,
  sets `token` to `undefined`, calls the global named by
  `data-expired-callback` when present, and then calls `reset()` so a fresh
  token arrives without host code. A refreshed token carries a new
  challenge id, so its siteverify correlation is `matched: false` unless the
  host also re-sends `/thumbmark` with the new nonce; the guide says so.
- All of the above is inside the Phase 1 try/catch: the loader never throws
  into the host page. Callback exceptions are caught and logged.

### 4.3 Frame behaviour

Reads `data-challenge`, `data-pow-bits` and `data-origin` from its own
script tag, posts the challenge id, starts the worker, runs the Phase 1
collection in parallel, waits for both, posts the report, and relays the
outcome as one of the messages above. `fetch` failure or a non-200 status is
`network`.

## 5. Token

- Compact JWS, `ES256` on P-256, produced with the standard library
  (`crypto/ecdsa`, `crypto/sha256`, `encoding/base64`, `encoding/json`); the
  repo has no JWT dependency and the signing side is small. Header
  `{ "alg": "ES256", "kid": "<kid>", "typ": "JWT" }`. The signature is the
  raw `r || s` encoding, 64 bytes, as JWS requires (not ASN.1).
- Claims:

  | claim      | value                                                             |
  |------------|-------------------------------------------------------------------|
  | `iss`      | `NAZR_WIDGET_ISSUER`, default `https://<request Host>`            |
  | `aud`      | the API key id (uuid)                                             |
  | `jti`      | the challenge id                                                  |
  | `iat`      | issuance, Unix seconds                                            |
  | `exp`      | `iat + NAZR_WIDGET_TOKEN_TTL` (default `5m`)                      |
  | `hostname` | the embedding origin from the challenge, `""` when unknown        |
  | `verdict`  | `"pass"` (the only value in 2a; 2b adds the interactive outcome)  |

- `GET /widget/v1/jwks.json` returns `{ "keys": [ {kty:"EC", crv:"P-256",
  kid, use:"sig", alg:"ES256", x, y}, ... ] }` for the active key and every
  key retired less than `signingKeyGrace` (24 hours) ago. `Cache-Control:
  public, max-age=3600`. The guide tells consumers to cache the set and
  refetch once on an unknown `kid`.
- Local verification contract for the host backend: signature against the
  `kid`'s JWK, `exp` not passed, `aud` equals its key id, `hostname` equals
  its own origin when it set one, `verdict == "pass"`. The guide shows this
  with `jose` (Node) and `golang-jwt` (Go).

## 6. Signing keys

- Table `signing_keys`: `kid text PK` (16 random bytes, base64url),
  `private_key_pem text NOT NULL` (PKCS#8), `public_jwk jsonb NOT NULL`,
  `hmac_secret bytea NOT NULL` (32 random bytes, for challenges),
  `created_at timestamptz NOT NULL`, `retired_at timestamptz NULL`.
- Loading: `serve` calls `store.EnsureSigningKey(ctx)` after migrations. It
  takes `pg_advisory_xact_lock` on a fixed id inside a transaction, selects
  the active key, and inserts a freshly generated one only when none exists,
  so several instances booting together agree on one key.
- The server keeps the key set in memory and reloads it from the table every
  `signingKeyRefresh` (60 seconds) so a rotation propagates to every instance
  without a restart. Signing uses the active key; challenge and JWKS lookups
  accept active and in-grace retired keys.
- `nazr signing rotate` inserts a new active key and sets `retired_at` on the
  previous one in one transaction; `nazr signing list` prints kid,
  created_at and retired_at. Rows retired longer than the grace are deleted
  by `store.Prune`.
- Tokens issued by the retired key stay verifiable (locally and remotely)
  for their lifetime because the grace exceeds the token TTL and the JWKS
  cache time together.

## 7. Secret and siteverify

### 7.1 Per-key secret

- `api_keys` gains `secret_hash text NULL` and `secret_prefix text NULL`.
  A secret is `nzs_` followed by 52 base32 characters (32 random bytes),
  stored as its SHA-256 hex, exactly as the `nzr_` key.
- `POST /admin/keys` and `nazr keys create` generate one and show it once,
  as an extra `secret` field beside `key`. `POST /admin/keys/{id}/secret` and
  `nazr keys secret-rotate <id>` replace it for an existing key and return
  the new value; the previous secret stops working at once. Keys created
  before this migration have no secret until rotated.
- `store.FindKeyBySecretHash(ctx, hash)` mirrors `FindKeyByHash`.

### 7.2 `POST /widget/v1/siteverify`

- JSON body `{ "secret", "token", "remoteip"? }`; `Content-Type` must be
  JSON. No `x-api-key`; the secret identifies the key. Not origin-checked:
  this is a backend-to-nazr call.
- Steps:
  1. Resolve the key by the secret's hash; unknown or revoked → `invalid-secret`
     (401). Before anything else the key's rate limit is applied with the
     same limiter as the middleware, so siteverify calls count with page
     calls and reports; exceeded → 429 as for `/thumbmark`.
  2. Parse the JWS, look up `kid`, verify the signature; failure or unknown
     `kid` → `invalid-token`. `aud` must equal the key id → `invalid-token`.
     `exp` passed → `token-expired`.
  3. `UPDATE widget_reports SET verified_at = now() WHERE id = $jti AND
     api_key_id = $key AND verified_at IS NULL RETURNING ...`. Zero rows and
     the report exists → `replayed`; zero rows and no report → `invalid-token`.
  4. When `remoteip` is given and does not match the report (raw `ip` when
     stored, otherwise the salted `ip_hash` of the given address) →
     `remoteip-mismatch`. The report is still marked verified: the token is
     spent either way.
  5. Run the Phase 1 correlation lookup for this one report (same lateral
     join, same window) to fill the `correlation` block.
- Response, `200` on any outcome other than 401/429:

  ```json
  {
    "success": true,
    "challenge_ts": "2026-10-30T12:00:00Z",
    "hostname": "https://shop.example",
    "verdict": "pass",
    "correlation": { "matched": true, "ip_match": true, "ja4_match": true, "ua_match": true },
    "classification": { "tor": false, "vpn": false, "bot": false, "datacenter": false, "private_relay": false, "danger_level": 0 },
    "signals": { "...": false },
    "error_codes": []
  }
  ```

  `challenge_ts` is `token_issued_at`. `ja4_match` is `null` when unknown
  (Phase 1 §5); `ip_match`, `ja4_match` and `ua_match` are `null` when
  `matched` is false. On failure `success` is `false`, `error_codes` holds
  exactly one of `invalid-secret`, `invalid-token`, `token-expired`,
  `replayed`, `remoteip-mismatch`, and the other fields are omitted except
  on `remoteip-mismatch`, which still returns them so the host can decide.

## 8. Storage, configuration, admin

- Migration `00003_widget_challenge.sql` (additive):
  - `widget_reports` gains `pow_ok boolean NOT NULL DEFAULT false`,
    `verdict text NOT NULL DEFAULT ''`, `hostname text NOT NULL DEFAULT ''`,
    `classification jsonb NULL`, `signals jsonb NULL`,
    `token_issued_at timestamptz NULL`, `verified_at timestamptz NULL`,
    `replay_count int NOT NULL DEFAULT 0`.
    The `id` column keeps its `char(26)` type; it now holds the challenge id.
  - `signing_keys` (section 6).
  - `api_keys.secret_hash`, `api_keys.secret_prefix` with a unique partial
    index on `secret_hash WHERE secret_hash IS NOT NULL`.
- `store.InsertWidgetReport` returns `store.ErrDuplicateReport` on the
  primary-key conflict; `store.MarkWidgetVerified(ctx, keyID, id)` performs
  the single-use update and returns the row or `ErrAlreadyVerified` /
  `ErrNotFound`; `store.WidgetReportCorrelation(ctx, keyID, id, window)`
  returns the one-report correlation.
- Configuration (`docs/configuration.md`):

  | variable                       | default | meaning                                      |
  |--------------------------------|---------|----------------------------------------------|
  | `NAZR_POW_BITS`                | `18`    | leading zero bits; `0` disables; max `32`    |
  | `NAZR_WIDGET_TOKEN_TTL`        | `5m`    | token lifetime                               |
  | `NAZR_WIDGET_ISSUER`           | `""`    | `iss` claim; empty means `https://<Host>`    |
  | `NAZR_WIDGET_PASS_MAX_DANGER`  | `2`     | highest `danger_level` that still passes     |

- The admin summary `GET /admin/keys/{id}/widget` adds `pass`,
  `inconclusive`, `pow_failed`, `verified` (rows with `verified_at`) and
  `replayed` (rows with `replay_count > 0`; the siteverify `replayed` path
  increments the column). `invalid` outcomes are never stored and so never
  counted.

## 9. Security and privacy

- **Trust boundary.** The signing private keys and HMAC secrets live in
  Postgres in plaintext. Database access equals the ability to mint tokens
  and challenges. Documented in the guide and in `docs/configuration.md`.
- **Token is a bearer credential** for five minutes, bound to the key and
  the observed embedding origin. A host must verify `aud` and should verify
  `hostname`; siteverify's single use is what stops a captured token being
  used twice.
- **Challenge forgery** is impossible without the HMAC secret; guessing a
  challenge id gains nothing because the MAC is checked before the id is
  used, and a reused id fails the insert.
- **Proof-of-work** is a cost, not a proof of humanity: a farm can solve it.
  Its job is to make bulk token minting expensive and to give the
  classification time to observe a full frame load. Adaptive difficulty is
  deferred.
- **The loader is untrusted** (Phase 1 §7). A hostile host script can read
  the token from the hidden input or the global; that is the host's own
  page, and the token is for the host. It cannot change the verdict.
- **postMessage filtering** on both `source` and `origin` means a sibling
  frame or an injected iframe cannot hand the loader a fake token.
- **Secrets** are hashed at rest with the same scheme as keys and only ever
  shown once. The siteverify response never echoes the secret.
- All queries are parameterized and scoped by `api_key_id`.

## 10. Changes to Phase 1 behaviour

- `POST /widget/report` body: `nonce` → `challenge` + `pow`; response:
  `204` → `200 {verdict, token?}`.
- `GET /widget/v1/frame`: `n` ignored; template gains `data-challenge`,
  `data-pow-bits`, `data-origin`; CSP gains `worker-src 'self'`.
- Loader: `data-nonce` ignored (warned); `nonce` is set asynchronously, so a
  host must `await window.__nazrWidget.ready` before calling `/thumbmark`
  (the Phase 1 guide already shows the Promise form; the synchronous read is
  removed from the guide).
- `widget_reports.id` is the challenge id, not the request id.
- Phase 1 correlation, admin counts, retention and the `/thumbmark` `nonce`
  field are unchanged.

## 11. Affected files

- `packages/widget/`: `src/loader.ts` (messages, hidden input, callbacks,
  expiry, reset), `src/frame.ts` (challenge attributes, worker, report
  body, relay), new `src/worker.ts` and `src/pow.ts` (shared hash loop),
  `src/frame.html` (new attributes), `scripts/build.mjs` (worker entry),
  dependency `@noble/hashes`, tests.
- `apps/api/internal/widgettoken/` (new): `challenge.go` (mint/verify),
  `pow.go` (verify), `jws.go` (ES256 sign/verify, JWK encode), `keys.go`
  (key set with refresh), tests with fixed-key known answers.
- `apps/api/internal/server/widget.go`: frame route minting, report verdict
  and token, `jwks.json`, siteverify; `admin.go`: secret rotate, summary
  counts; `server.go`: routes.
- `apps/api/internal/store/`: `widget.go` (new columns, duplicate error,
  mark verified, one-report correlation), `signing.go` (new), `keys.go`
  (secret columns, find by secret hash, rotate), `retention.go` (retired
  signing keys).
- `apps/api/migrations/00003_widget_challenge.sql`.
- `apps/api/internal/config/config.go`: the four new variables.
- `apps/api/cmd/nazr/`: `signing.go` (rotate, list), `keys.go`
  (`secret-rotate`, secret output on create).
- Docs: `docs/widget.md` (token, local verification with `jose` and
  `golang-jwt`, siteverify, expiry/reset, trust boundary),
  `docs/protocol.md`, `docs/configuration.md`, `README.md`, `CLAUDE.md`
  (`signing` subcommand in the CLI list).

## 12. Review focus (inputs no happy-path test exercises)

- **Report with a reused challenge id.** Second insert fails; `invalid`,
  no token, nothing stored. The first token stays valid.
- **Challenge signed by a retired-but-in-grace key** is accepted; one past
  the grace, or with a tampered byte, is `invalid` without touching the
  database.
- **Report arriving after `exp`** (frame left open, slow PoW): `invalid`.
- **PoW counter that satisfies `bits-1` but not `bits`**: `pow_failed`,
  stored with `pow_ok=false`, no token.
- **`NAZR_POW_BITS=0`**: any counter passes; e2e in `plain` mode uses it.
- **Automated browser (`navigator.webdriver`).** Classified as a bot, so the
  verdict is `inconclusive` and no token is issued.
- **Siteverify matrix.** Wrong secret, revoked key, bad signature, wrong
  `aud`, expired, unknown `jti`, second call (`replayed`), `remoteip`
  mismatch. Each yields exactly one error code and `success:false`.
- **Rotation under load.** Tokens signed before `signing rotate` verify at
  siteverify and against the JWKS until they expire; the new key signs the
  next token; the old key leaves the JWKS after the grace.
- **Loader with a message from a wrong origin or a foreign frame**: ignored;
  no hidden input, no callback.
- **Loader when the script is not inside a `<form>`**: no hidden input;
  `token` and callback still work.
- **Token expiry while the page is open**: hidden input cleared, expired
  callback, automatic reset, second token with a new `jti`.
- **Key created before the migration** has no secret; siteverify with any
  secret is `invalid-secret` until `secret-rotate`.

## 13. Backward compatibility

- The migration is additive. Phase 1 reports already stored keep their
  defaults (`verdict=''`, `pow_ok=false`), are counted under none of the new
  verdict buckets, and never issued tokens.
- A Phase 1 loader still in a browser cache (at most 300 s) requests the
  frame with `n`, which is ignored. The frame document is `no-store`, so it
  gets the new frame, which earns a token the old loader ignores. The page
  call carries the old loader's own nonce, so correlation is unmatched for
  at most 300 s. Harmless and short-lived.
- Hosts that read `window.__nazrWidget.nonce` synchronously after the script
  tag get `undefined`; the Phase 1 guide's Promise form is the supported
  one.
- Keys without a secret keep working for `/thumbmark` and the widget; only
  siteverify needs one.
