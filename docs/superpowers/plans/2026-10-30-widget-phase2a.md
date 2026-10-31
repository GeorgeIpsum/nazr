# Widget Phase 2a Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Phase 1 widget into a passive bot challenge: nazr mints an HMAC-signed challenge per frame load, the frame solves a hashcash proof-of-work, nazr classifies the frame's own request and on a clean verdict issues an ES256 token the host backend verifies locally against a JWKS or remotely through `POST /widget/v1/siteverify` with a per-key secret.

**Architecture:** A new Go package `internal/widgettoken` owns the crypto (compact JWS on `crypto/ecdsa`, HMAC challenges, PoW verification, signing-key generation and an in-memory keyring refreshed from a `signing_keys` table). The frame route mints challenges; the report handler verifies challenge + PoW, classifies, stores a verdict on the (now challenge-keyed) `widget_reports` row and signs a token; siteverify spends the row once and adds the Phase 1 correlation. The widget package gains a PoW worker, a postMessage contract to the loader, and the loader fills a hidden form input and callbacks.

**Tech Stack:** Go 1.26 stdlib crypto (`ecdsa`, `elliptic`, `hmac`, `sha256`, `x509` PKCS#8), pgx, goose; TypeScript (esbuild, Vitest/jsdom, `@noble/hashes`), Playwright, `jose` (e2e only).

**Spec:** [docs/superpowers/specs/2026-10-30-widget-phase2a-design.md](../specs/2026-10-30-widget-phase2a-design.md). Builds on Phase 1 ([spec](../specs/2026-10-30-widget-phase1-design.md), shipped 52e41d1..f0350ee).

## Global Constraints

- Challenge = `<payload>.<mac>`: `payload` is base64url (no padding) of JSON `{ "id", "exp", "bits", "kid", "origin" }`; `mac` is base64url of HMAC-SHA256 over the payload bytes with the signing key's HMAC secret. `exp` = issuance + `widgetMatchWindow` (10 min). `origin` = scheme://host[:port] from the frame request's `Referer`, `""` when absent/unparsable. (spec §3.1)
- Proof-of-work: decimal counter `c` such that `SHA-256(id + ":" + c)` has at least `NAZR_POW_BITS` leading zero bits. Default 18, range 0..32, `0` accepts any counter. (spec §3.2)
- Report body `{ challenge, pow, components, clientHash }` (`nonce` no longer accepted); `challenge` 1..512 chars, `pow` 1..32 decimal digits, `clientHash` absent or 1..64 hex, `components` an object. Response always `200 {"verdict": v, "token"?: jws}` after the middleware; `verdict` ∈ `pass | inconclusive | pow_failed | invalid`. `pass` ⇔ PoW valid ∧ `!Bot` ∧ `DangerLevel <= NAZR_WIDGET_PASS_MAX_DANGER` (default 2). Only `pass` issues a token. `invalid` stores nothing; `pow_failed` stores `pow_ok=false`. Report `id` = `nonce` = challenge id; a primary-key conflict → `invalid`. (spec §3.3)
- Token: compact JWS, `ES256`, header `{ "alg":"ES256", "kid", "typ":"JWT" }`, signature raw `r||s` (64 bytes). Claims `iss` (`NAZR_WIDGET_ISSUER` or `https://<request Host>`), `aud` = key id, `jti` = challenge id, `iat`, `exp` = iat + `NAZR_WIDGET_TOKEN_TTL` (default `5m`), `hostname` = embedding origin, `verdict` = `"pass"`. (spec §5)
- `GET /widget/v1/jwks.json` → `{"keys":[{kty:"EC",crv:"P-256",kid,use:"sig",alg:"ES256",x,y}...]}` for the active key and keys retired < `signingKeyGrace` (24 h) ago; `Cache-Control: public, max-age=3600`. (spec §5)
- `signing_keys(kid text PK, private_key_pem text, public_jwk jsonb, hmac_secret bytea, created_at, retired_at NULL)`; first `serve` generates one under `pg_advisory_xact_lock`; keyring reloads every `signingKeyRefresh` (60 s); `nazr signing rotate|list`; retired rows older than the grace are pruned. (spec §6)
- Secret: `nzs_` + 52 lowercase base32 chars (32 random bytes), SHA-256 hex at rest in `api_keys.secret_hash`, display `secret_prefix` = first 8 chars after `nzs_`; shown once by `POST /admin/keys` / `nazr keys create`; `POST /admin/keys/{id}/secret` / `nazr keys secret-rotate <id>` replace it. (spec §7.1)
- Siteverify: JSON `{ secret, token, remoteip? }`; order: key by secret hash (`invalid-secret`, 401) → rate limit (429) → signature/kid/`aud` (`invalid-token`) → `exp` (`token-expired`) → single-use `UPDATE … WHERE verified_at IS NULL` (`replayed` when the row exists, `invalid-token` when not) → `remoteip` (`remoteip-mismatch`, row still spent) → correlation. Response shape in spec §7.2; failures carry exactly one error code. (spec §7.2)
- Frame → parent messages `{type:"nazr:challenge",id}`, `{type:"nazr:token",token}`, `{type:"nazr:error",reason}`; `targetOrigin` = `data-origin` when non-empty else `"*"`. Loader accepts only `event.source === iframe.contentWindow && event.origin === <loader script origin>`; exposes `window.__nazrWidget = { ready, nonce, token, reset }`; hidden `<input name="nazr-token">` (override `data-response-field-name`) in the closest `<form>`; `data-callback`, `data-error-callback`, `data-expired-callback` name globals; `data-nonce` ignored with one `console.warn`; never throws. (spec §4)
- Frame CSP gains `worker-src 'self'`; the PoW worker is a separate content-hashed bundle. (spec §3.1, §3.2)
- Migration `00003_widget_challenge.sql` is additive. Config: `NAZR_POW_BITS` (18, 0..32), `NAZR_WIDGET_TOKEN_TTL` (`5m`), `NAZR_WIDGET_ISSUER` (`""`), `NAZR_WIDGET_PASS_MAX_DANGER` (2, 0..5). (spec §8)
- Phase 1 carry-over (controller ruling, spec §3.3 amended in Task 11): the report applies the frame client's default stabilization `["private","iframe"]` instead of no options, so `widget_reports.thumbmark` is comparable with the frame's `clientHash`.
- Commits `type(scope): subject`; scopes `thumbmark`, `api`, `widget`, `demo`, `deploy`, `docs`, `ci`.

## Review Focus

- **Reused challenge id.** Second report with the same challenge → `invalid`, nothing stored, no token; the first token stays valid. (Task 6)
- **Key rotation under traffic.** A challenge or token signed by a retired-but-in-grace key is accepted; one past the grace, or with a flipped MAC byte, is rejected without a database call. (Tasks 2, 5, 6, 7)
- **Siteverify `remoteip` under `NAZR_STORE_IP=hash`.** Must compare the salted hash, not fail closed; a mismatch still spends the token. (Task 7)
- **Foreign postMessage.** A message with the right shape from a sibling frame or another origin must not fill the hidden input or fire a callback. (Task 9)
- **Token expiry while the page is open.** Hidden input cleared, expired callback fired, frame reloaded, a second token with a new `jti` arrives; siteverify of the first token after `exp` → `token-expired`. (Tasks 7, 9, 10)

---

## File structure

- `apps/api/internal/widgettoken/` (new): `jws.go` (ES256 sign/parse, JWK), `challenge.go` (mint/parse, embedding origin), `pow.go` (verify/solve), `keys.go` (generate, keyring). Pure functions; imports `store` only for `store.SigningKey`.
- `apps/api/internal/store/`: `signing.go` (new), `keys.go` (secret columns), `widget.go` (verdict columns, single-use, one-report correlation, new counts).
- `apps/api/migrations/00003_widget_challenge.sql`.
- `apps/api/internal/config/config.go`: four variables.
- `apps/api/internal/auth/keys.go`: `GenerateSecret`.
- `apps/api/cmd/nazr/`: `signing.go` (new), `keys.go`, `main.go`, `serve.go`.
- `apps/api/internal/server/`: `widget.go` (frame mint, report verdict/token, jwks), `siteverify.go` (new), `admin.go`, `server.go`, `thumbmark.go` (extract `classifyInput`), `helpers_test.go`.
- `packages/widget/src/`: `pow.ts`, `worker.ts`, `entries/worker.ts` (new); `frame.ts`, `loader.ts`, `frame.html`, `scripts/build.mjs`.
- `apps/demo/`: `e2e/global-setup.ts`, `e2e/widget.spec.ts`, `src/widget-host.ts`, `package.json` (`jose`).
- Docs: `docs/widget.md`, `docs/protocol.md`, `docs/configuration.md`, `README.md`, `CLAUDE.md`, the two specs.

## Task 1: ES256 JWS and JWK (`widgettoken/jws.go`)

**Files:**
- Create: `apps/api/internal/widgettoken/jws.go`, `apps/api/internal/widgettoken/jws_test.go`

**Interfaces:**
- Produces: `type Claims struct { Issuer string `json:"iss"`; Audience string `json:"aud"`; ID string `json:"jti"`; IssuedAt int64 `json:"iat"`; Expires int64 `json:"exp"`; Hostname string `json:"hostname"`; Verdict string `json:"verdict"` }`; `func Sign(priv *ecdsa.PrivateKey, kid string, c Claims) (string, error)`; `func Parse(token string, keyFor func(kid string) (*ecdsa.PublicKey, bool)) (Claims, error)` with sentinel errors `ErrMalformed`, `ErrAlgorithm`, `ErrUnknownKid`, `ErrBadSignature` (Parse does **not** check `exp`); `type JWK struct { Kty, Crv, Kid, Use, Alg, X, Y string }` with json tags `kty crv kid use alg x y`; `func PublicJWK(kid string, pub *ecdsa.PublicKey) JWK`; `type JWKS struct { Keys []JWK `json:"keys"` }`.

- [ ] **Step 1: Write the failing tests.**
  - `TestParseRFC7515ES256`: build the P-256 key from RFC 7515 Appendix A.3's JWK (`x`, `y`, `d` base64url values, copied into the test), call `Parse` on the appendix's compact serialization with `keyFor` returning that key for kid `""`; expect `Claims{Issuer: "joe", Expires: 1300819380}` and no error. (Genuine known answer: the signature was produced outside this code.)
  - `TestSignParseRoundTrip`: generate a key, `Sign(priv, "k1", Claims{Issuer:"https://nazr.example", Audience:"key", ID:"01H...", IssuedAt:1, Expires:301, Hostname:"https://shop.example", Verdict:"pass"})`; the token has three dot-separated base64url segments with no `=`; the decoded header is exactly `{"alg":"ES256","kid":"k1","typ":"JWT"}`; the decoded signature is 64 bytes; `Parse` returns the same claims.
  - `TestParseRejects`: flipped payload byte → `ErrBadSignature`; two segments → `ErrMalformed`; header `{"alg":"none"}` or `{"alg":"HS256"}` → `ErrAlgorithm`; `keyFor` returning false → `ErrUnknownKid`; signature of 63 bytes → `ErrBadSignature`.
  - `TestPublicJWK`: for the RFC key, `PublicJWK("k", pub)` has `Kty "EC"`, `Crv "P-256"`, `Use "sig"`, `Alg "ES256"`, and `X`/`Y` equal to the appendix's `x`/`y` strings (32-byte big-endian coordinates, left-padded).
- [ ] **Step 2: Run** `cd apps/api && go test ./internal/widgettoken` → FAIL (package missing).
- [ ] **Step 3: Implement.** `Sign`: `ecdsa.Sign` then `r.FillBytes(sig[:32])`, `s.FillBytes(sig[32:])`. `Parse`: split, decode header, require `alg == "ES256"`, look up `kid` (may be absent → `""`), `ecdsa.Verify` with `big.Int` from the two halves over `sha256(header "." payload)`, then unmarshal claims. Use `base64.RawURLEncoding` everywhere.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(api): ES256 JWS signer and JWK encoding for widget tokens`.

## Task 2: Challenge, proof-of-work, signing-key generation and keyring

**Files:**
- Create: `apps/api/internal/widgettoken/challenge.go`, `pow.go`, `keys.go` and `*_test.go` for each
- Create (type only, filled in Task 3): `apps/api/internal/store/signing.go` with `type SigningKey struct { Kid string; PrivateKeyPEM string; PublicJWK json.RawMessage; HMACSecret []byte; CreatedAt time.Time; RetiredAt *time.Time }`

**Interfaces:**
- Produces: `type Challenge struct { ID string `json:"id"`; Expires int64 `json:"exp"`; Bits int `json:"bits"`; Kid string `json:"kid"`; Origin string `json:"origin"` }`; `func MintChallenge(secret []byte, c Challenge) string`; `func ParseChallenge(s string, secretFor func(kid string) ([]byte, bool), now time.Time) (Challenge, error)` with `ErrChallengeMalformed`, `ErrChallengeUnknownKid`, `ErrChallengeBadMAC`, `ErrChallengeExpired`; `func EmbeddingOrigin(referer string) string`.
- `func VerifyPoW(id, counter string, bits int) bool`; `func SolvePoW(id string, bits int) string`.
- `type Key struct { Kid string; Private *ecdsa.PrivateKey; Secret []byte; CreatedAt time.Time; RetiredAt *time.Time }`; `func Generate(now time.Time) (store.SigningKey, error)` (P-256, kid = base64url of 16 random bytes, PKCS#8 PEM, `PublicJWK` marshalled from Task 1's `PublicJWK`, 32-byte secret); `func FromStored(sk store.SigningKey) (Key, error)`; `type Keyring struct` with `func NewKeyring(load func(ctx context.Context) ([]store.SigningKey, error)) *Keyring`, `func NewStaticKeyring(keys ...Key) *Keyring`, `(*Keyring).Refresh(ctx) error`, `Active() (Key, bool)` (the newest key with `RetiredAt == nil`), `Lookup(kid string) (Key, bool)`, `JWKS() JWKS` (every loaded key, newest first), `Run(ctx context.Context, every time.Duration)` (ticker loop, logs nothing, swallows refresh errors keeping the last good set); `const SigningKeyGrace = 24 * time.Hour`, `SigningKeyRefresh = 60 * time.Second`.

- [ ] **Step 1: Write the failing tests.**
  - `TestChallengeRoundTrip`: mint with secret `s1`, `Challenge{ID:"01HX…", Expires: now+600, Bits: 18, Kid:"k1", Origin:"https://shop.example"}`; string has exactly one `.`; `ParseChallenge` with `secretFor("k1") = s1` returns the struct. Rejections: tampered payload byte → `ErrChallengeBadMAC`; unknown kid → `ErrChallengeUnknownKid`; `now` past `Expires` → `ErrChallengeExpired`; `"abc"` (no dot) and a 513-char string → `ErrChallengeMalformed`; the MAC check must run before `secretFor` is consulted for a second kid (assert `secretFor` called once).
  - `TestEmbeddingOrigin` table: `"https://shop.example/cart?x=1"` → `"https://shop.example"`; `"http://localhost:4173/"` → `"http://localhost:4173"`; `""`, `"garbage"`, `"ftp://x"` → `""`.
  - `TestPoW`: `VerifyPoW("id", "0", 0)` true; for bits 12, `SolvePoW("abc", 12)` returns a decimal string that `VerifyPoW` accepts and the SHA-256 of `"abc:"+counter` has ≥12 leading zero bits (check in the test); `VerifyPoW` rejects an empty counter, a 33-digit counter, `"1a"`, and a counter whose hash has only `bits-1` zero bits (find one by trying counters in the test).
  - `TestGenerateAndKeyring`: `Generate(now)` → PEM parses with `x509.ParsePKCS8PrivateKey` to P-256, `PublicJWK` unmarshals to a `JWK` with `Kid == sk.Kid`, secret 32 bytes, kid 22 chars. `NewKeyring(load)` with load returning `[retired(k0, retiredAt=now-1h), active(k1)]`: `Active()` is k1, `Lookup("k0")` found, `JWKS().Keys` has two entries k1 first; load returning an error after a good refresh keeps the previous set; `NewStaticKeyring(k1)` behaves the same without load.
- [ ] **Step 2: Run** `go test ./internal/widgettoken` → FAIL.
- [ ] **Step 3: Implement.** `hmac.Equal` for the MAC; `ParseChallenge` length-checks (≤512) before decoding. `VerifyPoW`: one `sha256.Sum256`, count leading zero bits. Keyring: `sync.RWMutex` around a slice sorted by `CreatedAt` desc.
- [ ] **Step 4: Run** → PASS. `go vet ./...` clean.
- [ ] **Step 5: Commit** `feat(api): widget challenge, proof-of-work and signing keyring`.

## Task 3: Migration and store changes

**Files:**
- Create: `apps/api/migrations/00003_widget_challenge.sql`
- Modify: `apps/api/internal/store/signing.go` (methods), `keys.go`, `widget.go`, `retention.go`, `store_test.go` (`latestMigration` → 3, `TestMigrateSchema`), `widget_test.go`; Create: `signing_test.go`

**Interfaces:**
- Consumes: `store.SigningKey` (Task 2).
- Produces: `(*Store).EnsureSigningKey(ctx, gen func() (SigningKey, error)) (SigningKey, error)`; `ListSigningKeys(ctx, retiredAfter time.Time) ([]SigningKey, error)` (active rows plus rows with `retired_at > retiredAfter`, newest first); `RotateSigningKey(ctx, next SigningKey) error` (one transaction: insert `next`, then `UPDATE signing_keys SET retired_at = now() WHERE retired_at IS NULL AND kid <> $1`); `DeleteRetiredSigningKeys(ctx, retiredBefore time.Time) (int64, error)`.
- `APIKey.SecretPrefix string` (`""` when none); `NewKey.SecretHash, SecretPrefix string` (`""` → NULL); `SetKeySecret(ctx, id, hash, prefix string) error` (`ErrNotFound` for a missing id); `FindKeyBySecretHash(ctx, hash string) (*APIKey, error)` (nil, nil when absent).
- `WidgetReport` gains `Hostname string; PowOK bool; Verdict string; Classification, Signals json.RawMessage; TokenIssuedAt, VerifiedAt *time.Time; ReplayCount int`; `var ErrDuplicateReport = errors.New("store: duplicate widget report")`, `ErrAlreadyVerified = errors.New("store: widget report already verified")`; `InsertWidgetReport` returns `ErrDuplicateReport` on SQLSTATE `23505`; `MarkWidgetVerified(ctx, keyID, id string) (WidgetReport, error)`: `UPDATE widget_reports SET verified_at = now() WHERE id = $1 AND api_key_id = $2 AND verified_at IS NULL RETURNING <all columns>`; on zero rows, `UPDATE … SET replay_count = replay_count + 1 WHERE id = $1 AND api_key_id = $2` → 1 row ⇒ `ErrAlreadyVerified`, 0 rows ⇒ `ErrNotFound`; `type WidgetCorrelation struct { Matched bool; IPMatch, JA4Match, UAMatch *bool }`; `WidgetReportCorrelation(ctx, keyID, id string, window time.Duration) (WidgetCorrelation, error)` (same most-recent-event-in-±window rule as the summary; `JA4Match` nil when either JA4 is `""`; all three nil when unmatched; `ErrNotFound` for a missing report); `WidgetSummary` gains `Pass, Inconclusive, PowFailed, Verified, Replayed int64` (`verdict` counts; `verified_at IS NOT NULL`; `replay_count > 0`).

- [ ] **Step 1: Write the failing tests (DB-gated, `NAZR_TEST_REQUIRE_DB=1`).**
  - `TestMigrateSchema`: new columns on `widget_reports` (`pow_ok`, `verdict`, `hostname`, `classification`, `signals`, `token_issued_at`, `verified_at`, `replay_count`), `api_keys.secret_hash`/`secret_prefix`, unique partial index `api_keys_secret_hash_idx`, table `signing_keys` with its six columns; `latestMigration = 3`.
  - `TestSigningKeys`: `EnsureSigningKey` with a generator returning `k1` inserts once; a second call returns `k1` without calling the generator (count calls); `RotateSigningKey(k2)` → `ListSigningKeys(now-1h)` returns `[k2 (active), k1 (retired)]`; `ListSigningKeys(now+1h)` returns only `k2`; `DeleteRetiredSigningKeys(now+1h)` deletes 1. Concurrency: 5 goroutines calling `EnsureSigningKey` on a fresh table end with exactly one row.
  - `TestKeySecret`: `CreateKey` with `SecretHash/Prefix` → `FindKeyBySecretHash` finds it with `SecretPrefix`; `SetKeySecret(id, h2, p2)` → old hash not found, new found; unknown id → `ErrNotFound`; a key created without a secret has `SecretPrefix == ""` and `secret_hash` NULL.
  - `TestWidgetReportVerdictRoundTrip`: insert with all new fields, read back equal; a second insert with the same `ID` → `ErrDuplicateReport`.
  - `TestMarkWidgetVerified`: first call returns the row with `VerifiedAt` set; second → `ErrAlreadyVerified` and `replay_count = 1`; unknown id → `ErrNotFound`; a report under another key → `ErrNotFound`.
  - `TestWidgetReportCorrelation`: matched all-equal → `{true, &true, &true, &true}`; report `ja4 ""` → `JA4Match nil`; no event → `{false, nil, nil, nil}`.
  - Extend `TestWidgetSummary` seeds with verdicts (`pass`×3, `inconclusive`×1, `pow_failed`×1, one verified, one with `replay_count 2`) and assert the five new counts.
- [ ] **Step 2: Run** `go test ./internal/store -run 'TestMigrateSchema|TestSigningKeys|TestKeySecret|TestWidgetReport|TestMarkWidgetVerified|TestWidgetSummary'` → FAIL.
- [ ] **Step 3: Implement.** Migration:

```sql
-- +goose Up
ALTER TABLE widget_reports
    ADD COLUMN pow_ok          boolean     NOT NULL DEFAULT false,
    ADD COLUMN verdict         text        NOT NULL DEFAULT '',
    ADD COLUMN hostname        text        NOT NULL DEFAULT '',
    ADD COLUMN classification  jsonb       NULL,
    ADD COLUMN signals         jsonb       NULL,
    ADD COLUMN token_issued_at timestamptz NULL,
    ADD COLUMN verified_at     timestamptz NULL,
    ADD COLUMN replay_count    int         NOT NULL DEFAULT 0;
CREATE TABLE signing_keys (
    kid             text        PRIMARY KEY,
    private_key_pem text        NOT NULL,
    public_jwk      jsonb       NOT NULL,
    hmac_secret     bytea       NOT NULL,
    created_at      timestamptz NOT NULL,
    retired_at      timestamptz NULL
);
ALTER TABLE api_keys ADD COLUMN secret_hash text NULL, ADD COLUMN secret_prefix text NULL;
CREATE UNIQUE INDEX api_keys_secret_hash_idx ON api_keys (secret_hash) WHERE secret_hash IS NOT NULL;
-- +goose Down
DROP INDEX api_keys_secret_hash_idx;
ALTER TABLE api_keys DROP COLUMN secret_hash, DROP COLUMN secret_prefix;
DROP TABLE signing_keys;
ALTER TABLE widget_reports DROP COLUMN pow_ok, DROP COLUMN verdict, DROP COLUMN hostname, DROP COLUMN classification,
    DROP COLUMN signals, DROP COLUMN token_issued_at, DROP COLUMN verified_at, DROP COLUMN replay_count;
```

  `EnsureSigningKey`: `BEGIN; SELECT pg_advisory_xact_lock(7953773048894154606); SELECT active; INSERT if none; COMMIT` (the constant is `0x6e617a727369676e`, "nazrsign"). Detect `23505` with `errors.As(err, *pgconn.PgError)`.
- [ ] **Step 4: Run** → PASS; `NAZR_TEST_REQUIRE_DB=1 go test ./internal/store/...` green.
- [ ] **Step 5: Commit** `feat(api): signing keys, key secrets and widget verdict columns`.

## Task 4: Config, secret generation, CLI and serve wiring

**Files:**
- Modify: `apps/api/internal/config/config.go` (+ `config_test.go`), `apps/api/internal/auth/keys.go` (+ test), `apps/api/cmd/nazr/main.go`, `keys.go`, `keys_test.go`, `serve.go`; Create: `apps/api/cmd/nazr/signing.go`

**Interfaces:**
- Consumes: Tasks 2–3.
- Produces: `config.Config.PowBits int` (`env:"NAZR_POW_BITS" envDefault:"18"`, validated 0..32), `WidgetTokenTTL time.Duration` (`NAZR_WIDGET_TOKEN_TTL`, `5m`, > 0), `WidgetIssuer string` (`NAZR_WIDGET_ISSUER`), `WidgetPassMaxDanger int` (`NAZR_WIDGET_PASS_MAX_DANGER`, `2`, 0..5). `auth.GenerateSecret() (plaintext, hash, prefix string)` (`nzs_` + 52 lowercase base32 chars; hash via `HashKey`; prefix = first 8 chars after `nzs_`); `const SecretPrefix = "nzs_"`. CLI: `nazr keys create` prints the key on line 1, the **secret on line 2**, then the existing `id prefix label` line; `nazr keys secret-rotate <id>` prints the new secret; `nazr signing rotate` prints the new kid; `nazr signing list` prints a `KID CREATED RETIRED` table. `serve`: after migrations, `EnsureSigningKey` with `widgettoken.Generate`, builds a `Keyring` loading `ListSigningKeys(now - SigningKeyGrace)`, `Refresh` once (fatal on error), `go Run(ctx, SigningKeyRefresh)`, passes it as `server.Deps.Signing`; the hourly prune also calls `DeleteRetiredSigningKeys(now - SigningKeyGrace)`.

- [ ] **Step 1: Write the failing tests.** Config table: `NAZR_POW_BITS=33` and `-1` → error naming the variable; `NAZR_WIDGET_PASS_MAX_DANGER=6` → error; `NAZR_WIDGET_TOKEN_TTL=0` → error; defaults load as 18 / 5m / "" / 2; `Redacted()` includes the four names. `TestGenerateSecret`: regex `^nzs_[a-z2-7]{52}$`, hash = `HashKey(plaintext)`, prefix = `plaintext[4:12]`. `keys_test.go` (model on existing DB-gated cases): `keys create --label x` output line 2 matches the secret regex and `FindKeyBySecretHash(HashKey(line2))` finds the key; `keys secret-rotate <id>` prints a new secret and the old one no longer resolves; `signing rotate` then `signing list` shows two rows, one retired; `nazr signing` with no subcommand → usage, exit 2.
- [ ] **Step 2: Run** `go test ./internal/config ./internal/auth ./cmd/nazr` → FAIL.
- [ ] **Step 3: Implement.** Add `signing` to `usage` and the `run` switch; `signingCmd(sub string, args []string, stdout, stderr io.Writer) int` mirrors `keysCmd` (opens the store, runs under a 10 s context). In `serve.go` place the signing setup directly after the migrate block and before `server.New`.
- [ ] **Step 4: Run** → PASS; `go build ./...`.
- [ ] **Step 5: Commit** `feat(api): widget challenge config, key secrets and signing CLI`.

## Task 5: Frame route mints challenges; JWKS route; `classifyInput`

**Files:**
- Modify: `apps/api/internal/server/widget.go`, `server.go` (`Deps.Signing`, route), `thumbmark.go` (extract `classifyInput`), `helpers_test.go` (`newEnvWidget` gets a static keyring with a fixed test key `kid "test"`; `fakeStore` unchanged), `server_test.go`

**Interfaces:**
- Consumes: `widgettoken.Keyring`, `MintChallenge`, `EmbeddingOrigin`, `JWKS` (Tasks 1–2); `config` fields (Task 4).
- Produces: `server.Deps.Signing *widgettoken.Keyring` (nil → frame route 503 `signing_unavailable`, jwks and siteverify routes not registered); frame template data `struct { Bundle, Worker, Challenge, Origin string; PowBits int }`; manifest `{"frame","worker"}` read by `newWidgetAssets` (`workerName`, `worker []byte`; bundle route serves either name); `widgetFrameRules` ends with `; worker-src 'self'`; `GET /widget/v1/jwks.json` (registered when `Signing != nil`, independent of assets) → `widgettoken.JWKS` JSON, `Cache-Control: public, max-age=3600`; `func (s *server) classifyInput(r *http.Request, view conn.HolderView, comps map[string]any, lookup ipintel.Lookup, ja4 string) (classify.Input, string)` returning the input and the h2 fingerprint string, used by `handleThumbmark` (no behaviour change) and later by the report handler.

- [ ] **Step 1: Write the failing tests.**
  - `TestWidgetFrameChallenge`: MapFS manifest `{"frame":"frame.abcd1234.js","worker":"worker.ef012345.js"}` and `frame.html` `<script src="/widget/v1/{{.Bundle}}" data-worker="/widget/v1/{{.Worker}}" data-challenge="{{.Challenge}}" data-pow-bits="{{.PowBits}}" data-origin="{{.Origin}}">`; GET with `Referer: https://shop.example/cart` → 200; parse the `data-challenge` attribute with the test key's secret: `ID` is a 26-char ULID, `Expires == testNow + 10m`, `Bits == cfg.PowBits`, `Kid == "test"`, `Origin == "https://shop.example"`; `data-pow-bits` equals cfg; CSP header ends with `; worker-src 'self'`; no Referer → `data-origin=""`. `Signing == nil` → 503 JSON `signing_unavailable`.
  - `TestWidgetBundleServesWorker`: `GET /widget/v1/worker.ef012345.js` → 200 immutable; manifest without `worker` → `newWidgetAssets` error → routes 404 (`TestWidgetRoutes404WithoutAssets` style).
  - `TestJWKS`: 200, `Cache-Control: public, max-age=3600`, body `keys[0].kid == "test"`, `kty EC`, `crv P-256`; absent when `Signing == nil`.
  - `TestThumbmarkClassifyUnchanged`: existing `/thumbmark` classification tests keep passing (no new test; run the package).
- [ ] **Step 2: Run** `go test ./internal/server -run 'TestWidgetFrame|TestWidgetBundle|TestJWKS'` → FAIL.
- [ ] **Step 3: Implement.** Mint with `ulid.Make().String()`, `s.Now()`, `widgetMatchWindow`. Extract `classifyInput` by moving the `classify.Input{...}` construction, the `locales.timezone`, `privacy.webdriver` and `h2fp.Akamai` lines out of `handleThumbmark`; keep the canvas-probe lines in `handleThumbmark`.
- [ ] **Step 4: Run** `go test ./internal/server/...` → PASS; `pnpm --filter @nazr/api lint` clean.
- [ ] **Step 5: Commit** `feat(api): widget frame mints challenges; jwks route`.

## Task 6: Report verdict and token issuance

**Files:**
- Modify: `apps/api/internal/server/widget.go`, `server.go` (`StoreAPI`: `InsertWidgetReport` unchanged signature), `helpers_test.go` (`fakeStore.reports` gains duplicate detection by `ID` returning `store.ErrDuplicateReport`), `server_test.go`

**Interfaces:**
- Consumes: `ParseChallenge`, `VerifyPoW`, `Sign`, `Keyring` (Tasks 1–2); `WidgetReport` fields, `ErrDuplicateReport` (Task 3); `classifyInput` (Task 5); config (Task 4).
- Produces: `type widgetOutcome struct { Verdict string `json:"verdict"`; Token string `json:"token,omitempty"` }`; `func (s *server) processWidgetReport(r *http.Request) widgetOutcome` replacing `storeWidgetReport`; `handleWidgetReport` writes `200` JSON always; `var widgetReportOptions = fingerprint.Options{Stabilize: []string{"private", "iframe"}}` used in place of `OptionsFromRequest(nil)`; verdict constants `verdictPass = "pass"`, `verdictInconclusive`, `verdictPowFailed`, `verdictInvalid`.

- [ ] **Step 1: Write the failing tests** (helper `mintTestChallenge(t, env, origin) (challenge string, id string)` using the static keyring; `solve := widgettoken.SolvePoW`; test cfg `PowBits: 8`).
  - `TestWidgetReportPass`: Chrome stock body through `fullHolder(t)` (the same setup that classifies clean on `/thumbmark`), valid challenge + solved pow → 200 `{"verdict":"pass","token":...}`; `widgettoken.Parse` with the test key gives `Audience == key.ID`, `ID == challenge id`, `IssuedAt == testNow`, `Expires == testNow + 5m`, `Hostname == "https://shop.example"`, `Verdict "pass"`, `Issuer == "https://" + r.Host`; with `cfg.WidgetIssuer = "https://nazr.example"` the issuer is that. Stored report: `ID == Nonce == id`, `PowOK true`, `Verdict "pass"`, `Hostname`, `TokenIssuedAt == testNow`, `Classification` JSON has `"bot":false`, `Signals` non-empty, `Thumbmark` equals the hash `/thumbmark` computes for the same body with `options.stabilize = ["private","iframe"]`.
  - `TestWidgetReportInconclusive`: body `components.privacy.webdriver = true` (rule `webdriver`: bot 3 ⇒ `Bot`) → `{"verdict":"inconclusive"}`, no token, stored with `Verdict "inconclusive"`, `TokenIssuedAt nil`. With `cfg.WidgetPassMaxDanger = 0` and an input whose danger is 1 but bot < 3 (`Accept-Language` header removed ⇒ `missing_accept_language`: danger 1, bot 1) → `inconclusive`; the same input with max danger 2 → `pass`.
  - `TestWidgetReportPowFailed`: a counter that `VerifyPoW` rejects for bits 8 (search in the test) → `pow_failed`, stored with `PowOK false`, no token.
  - `TestWidgetReportInvalid`: each → `{"verdict":"invalid"}` and nothing stored: tampered MAC; expired (`testNow` advanced 11 min); unknown kid; `challenge` 513 chars; `pow` `"12a"`; missing `components`; `clientHash: 5`; Phase 1 body `{nonce, components, clientHash}`; `Signing == nil`. Reused challenge: first POST → `pass`, second identical POST → `invalid`, `len(reports) == 1`, the first token still parses. Key grace: a challenge minted with a second key `kid "old"` present in the static keyring with `RetiredAt = testNow - 1h` → `pass` (token signed by the active key); the same challenge when `"old"` is absent from the keyring (past the grace) → `invalid`.
  - `TestWidgetReportRejectsBody` from Phase 1: update bodies to the new shape and keep the 403/429 cases.
- [ ] **Step 2: Run** `go test ./internal/server -run TestWidgetReport` → FAIL.
- [ ] **Step 3: Implement** the spec §3.3 step order exactly: parse bounds → `ParseChallenge` (`secretFor` via `Keyring.Lookup`) → `VerifyPoW` → components/thumbmark/classify (`classifyInput`, `delete(cls.Signals, "canvas_probe_anomaly")`) → verdict → insert (`ErrDuplicateReport` → `invalid`) → sign on pass with `Keyring.Active()`. Marshal `classificationInfo{...}` and `cls.Signals` into the row.
- [ ] **Step 4: Run** `go test ./internal/server/...` → PASS; lint clean.
- [ ] **Step 5: Commit** `feat(api): widget report verifies the challenge and issues tokens`.

## Task 7: Siteverify, admin secrets, summary counts

**Files:**
- Create: `apps/api/internal/server/siteverify.go`
- Modify: `apps/api/internal/server/admin.go`, `server.go` (`StoreAPI` + routes), `helpers_test.go` (fake: `FindKeyBySecretHash` over `keys` by a new `secretHash` field, `SetKeySecret`, `MarkWidgetVerified` with replay semantics, `WidgetReportCorrelation` returning a settable `correlation`), `server_test.go`

**Interfaces:**
- Consumes: Task 3 store methods; `Parse` (Task 1); `auth.GenerateSecret` (Task 4); `widgetMatchWindow`.
- Produces: `StoreAPI` gains `FindKeyBySecretHash`, `SetKeySecret`, `MarkWidgetVerified`, `WidgetReportCorrelation`; `POST /widget/v1/siteverify` (registered when `Signing != nil`, wrapped in `s.bodyLimit`, no CORS, no `x-api-key`); response struct `siteverifyResponse { Success bool `json:"success"`; ChallengeTS string `json:"challenge_ts,omitempty"`; Hostname string `json:"hostname,omitempty"`; Verdict string `json:"verdict,omitempty"`; Correlation *correlationJSON `json:"correlation,omitempty"`; Classification *classificationInfo `json:"classification,omitempty"`; Signals map[string]bool `json:"signals,omitempty"`; ErrorCodes []string `json:"error_codes"` }` with `correlationJSON { Matched bool `json:"matched"`; IPMatch, JA4Match, UAMatch *bool `json:"ip_match"`, `json:"ja4_match"`, `json:"ua_match"` }`; `POST /admin/keys/{id}/secret` → 200 `{"id","secret"}` (404 `not_found` for an unknown id); `POST /admin/keys` response gains `secret`; `keyJSON` gains `SecretPrefix string `json:"secret_prefix"`` and `Secret string `json:"secret,omitempty"``; `GET /admin/keys/{id}/widget` gains `pass`, `inconclusive`, `pow_failed`, `verified`, `replayed`.

- [ ] **Step 1: Write the failing tests.**
  - `TestSiteverifyMatrix` (seed a key with secret hash `h`, a stored `pass` report with id `j`, a token signed for it): valid → 200 `success true`, `challenge_ts == TokenIssuedAt RFC3339`, `hostname`, `verdict "pass"`, correlation from the fake, classification/signals from the row, `error_codes: []`; wrong secret → 401 `success false, ["invalid-secret"]`; revoked key → 401 `invalid-secret`; rate limiter denying → 429; bad signature → 200 `["invalid-token"]`; `aud` of another key → `invalid-token`; expired (`testNow` past `exp`) → `token-expired` **before** the row is spent (`MarkWidgetVerified` not called); unknown `jti` → `invalid-token`; a token signed by the retired-in-grace key `"old"` → success; second call → `replayed`; `remoteip` mismatch against a raw-IP row → `remoteip-mismatch` with the other fields still present and the row spent; `remoteip` under `StoreIP = "hash"` compares `ipintel.Identifier(addr, salt)` to `IPHash` (match → success); non-JSON content type / malformed body → 400 `bad_request`.
  - `TestAdminKeySecret`: `POST /admin/keys` response has `secret` matching `^nzs_[a-z2-7]{52}$` and `secret_prefix == secret[4:12]`; `POST /admin/keys/{id}/secret` returns a new secret, the fake records the new hash; unknown id → 404; no token → 404/403 as the other admin routes.
  - `TestAdminWidgetSummary`: the five new fields round-trip from the fake.
- [ ] **Step 2: Run** `go test ./internal/server -run 'TestSiteverify|TestAdminKeySecret|TestAdminWidgetSummary'` → FAIL.
- [ ] **Step 3: Implement.** Rate limit with `s.Limiter.Allow(ctx, key.ID, rate)` using the key's `RateLimitPerMinute` or `cfg.DefaultRateLimit`, failing open on limiter error like the middleware (read `auth.MiddlewareOpts` for the exact semantics and reuse its helper if it has one). `remoteip`: `netip.ParseAddr`; invalid → treat as mismatch.
- [ ] **Step 4: Run** `go test ./...` → PASS; lint clean.
- [ ] **Step 5: Commit** `feat(api): widget siteverify endpoint and key secrets admin`.

## Task 8: Widget proof-of-work worker and frame contract

**Files:**
- Create: `packages/widget/src/pow.ts`, `pow.test.ts`, `src/worker.ts`, `src/entries/worker.ts`
- Modify: `packages/widget/src/frame.ts`, `frame.test.ts`, `src/entries/frame.ts`, `src/frame.html`, `scripts/build.mjs`, `package.json` (dependency `@noble/hashes`), `README.md`

**Interfaces:**
- Consumes: Task 5's template attributes (`data-challenge`, `data-pow-bits`, `data-origin`, `data-worker`) and the Task 6 report contract.
- Produces: `leadingZeroBits(hash: Uint8Array): number`; `solve(id: string, bits: number): string` (pure, synchronous; hashes `id + ":" + counter` with `sha256` from `@noble/hashes`); worker protocol: `postMessage({ id, bits })` → `{ counter }`; `type FrameMessage = { type: "nazr:challenge"; id: string } | { type: "nazr:token"; token: string } | { type: "nazr:error"; reason: "inconclusive" | "pow_failed" | "invalid" | "network" }`; `interface FrameDeps { script: HTMLScriptElement | null; fetch: typeof fetch; getThumbmark: typeof getThumbmark; solve: (id: string, bits: number) => Promise<string>; post: (msg: FrameMessage) => void }`; `reportFromFrame(deps): Promise<void>` reads the four `data-*` attributes from `deps.script`, decodes the challenge id from the payload segment (`JSON.parse(atob(base64url→base64))`), posts `nazr:challenge`, runs `solve` and `getThumbmark({ collect_beacon: false, cache_api_call: false })` concurrently, POSTs `/widget/report` with `{ challenge, pow, components, clientHash }` and `x-api-key` from `location.search` `k`, then posts `nazr:token` or `nazr:error` (non-200 or thrown fetch → `network`); never rejects. Build: `dist/worker.<hash8>.js`, `manifest.json` = `{"frame":..., "worker":...}`; `frame.html` script tag carries `data-worker="/widget/v1/{{.Worker}}" data-challenge="{{.Challenge}}" data-pow-bits="{{.PowBits}}" data-origin="{{.Origin}}"`. `entries/frame.ts` binds `post = (m) => window.parent.postMessage(m, dataOrigin || "*")` and `solve` through `new Worker(dataWorker)`.

- [ ] **Step 1: Write the failing tests.**
  - `pow.test.ts`: `leadingZeroBits(new Uint8Array([0,0,0x0f]))` is 20; `solve("abc", 10)` returns digits and the hash of `"abc:"+counter` has ≥10 leading zero bits; `solve("abc", 0)` returns `"0"`.
  - `frame.test.ts` (replace the Phase 1 cases): script element with `data-challenge=<payload>.<mac>` where payload encodes `{id:"01HX…",exp:…,bits:8,kid:"k",origin:"https://shop.example"}`, `data-pow-bits="8"`, `data-origin`, `data-worker="/widget/v1/worker.x.js"`; stub `solve` resolving `"42"`, `getThumbmark` resolving `{ thumbmark: "deadbeef", components: { a: 1 } }`, `fetch` resolving `Response.json({ verdict: "pass", token: "t.o.k" })`; `post` spy receives `[{type:"nazr:challenge", id:"01HX…"}, {type:"nazr:token", token:"t.o.k"}]`; the fetch body is `{ challenge, pow: "42", components: {a:1}, clientHash: "deadbeef" }` with `x-api-key: nzr_x`; verdict `inconclusive` → `nazr:error` reason `inconclusive`; fetch rejecting or status 500 → `network`; missing `k` or missing `data-challenge` → no fetch, no messages.
- [ ] **Step 2: Run** `pnpm --filter @nazr/widget test` → FAIL.
- [ ] **Step 3: Implement**; `build.mjs` bundles `entries/worker.ts` as a third IIFE; `pnpm install` for `@noble/hashes` (import `sha256` from the subpath the installed major exports: `@noble/hashes/sha2` or `@noble/hashes/sha256`); README mentions the worker output.
- [ ] **Step 4: Run** → PASS; `pnpm build --filter=@nazr/widget` writes five files; `pnpm --filter @nazr/widget lint` and root `pnpm typecheck` clean.
- [ ] **Step 5: Commit** `feat(widget): proof-of-work worker and token messages from the frame`.

## Task 9: Loader token delivery

**Files:**
- Modify: `packages/widget/src/loader.ts`, `loader.test.ts`

**Interfaces:**
- Consumes: `FrameMessage` (Task 8).
- Produces: `interface NazrWidget { ready: Promise<{ nonce: string }>; nonce?: string; token?: string; reset(): void }`; `mountWidget(doc, win)` reads `data-api-key`, `data-callback`, `data-error-callback`, `data-expired-callback`, `data-response-field-name`; warns once (`console.warn`) and ignores `data-nonce`; iframe `src` = `/widget/v1/frame?k=<key>`; `win.addEventListener("message", …)` accepting only `event.source === iframe.contentWindow && event.origin === new URL(script.src).origin`; on `nazr:challenge` sets `nonce` and resolves `ready` (first time only); on `nazr:token` sets `token`, writes the hidden input (`<input type="hidden" name=<field>>` appended to `script.closest("form")`, value updated if it exists), calls the callback global with the token, arms a timer for `exp` (decoded from the payload) minus now; on expiry clears `token` and the input value, calls the expired callback, then `reset()`; on `nazr:error` calls the error callback with the reason; `reset()` re-assigns `iframe.src` (same URL) which reloads the frame; callback exceptions are caught; the whole thing is inside the Phase 1 try/catch.

- [ ] **Step 1: Write the failing tests** (jsdom; dispatch `MessageEvent`s with `source` set to the captured iframe's `contentWindow` and `origin "https://nazr.example"`):
  - challenge message → `nonce === id`, `ready` resolves `{ nonce: id }`; `data-nonce="x"` → ignored, one `console.warn`.
  - token message with a payload whose `exp` is 60 s ahead (fake timers): hidden input named `nazr-token` appended to the enclosing `<form>` with the token value; `window.onNazr` (named by `data-callback`) called with the token; `data-response-field-name="cf"` → input named `cf`; no enclosing form → no input, callback still called.
  - wrong origin, wrong source (a second iframe's window), or a plain object without `type` → nothing happens.
  - error message → `data-error-callback` global called with `"inconclusive"`; a throwing callback does not propagate.
  - expiry: advance timers 60 s → input value `""`, `token undefined`, expired callback called, iframe `src` re-assigned (spy on the setter or compare a load counter).
  - `reset()` re-assigns `src`; a later challenge message updates `nonce`.
- [ ] **Step 2: Run** `pnpm --filter @nazr/widget test` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** → PASS; lint and typecheck clean; `pnpm build --filter=@nazr/widget`.
- [ ] **Step 5: Commit** `feat(widget): loader delivers the token to the host form and callbacks`.

## Task 10: Demo and end-to-end verification

**Files:**
- Modify: `apps/demo/e2e/global-setup.ts` (`NAZR_POW_BITS: "12"`; read the secret from `keys create` line 2 → `process.env.NAZR_E2E_SECRET`), `apps/demo/e2e/widget.spec.ts`, `apps/demo/src/widget-host.ts` (`data-callback="__nazrOnToken"` global storing `window.__nazrToken`; keep `__nazrHostDone`), `apps/demo/widget-host.html` (a `<form>` around the script so the hidden input appears), `apps/demo/package.json` (devDependency `jose`)

**Interfaces:**
- Consumes: everything above; `NAZR_E2E_ADMIN_TOKEN`, `NAZR_E2E_KEY`, `NAZR_E2E_SECRET`.

- [ ] **Step 1: Write the failing e2e** (extend `widget.spec.ts`): wait for `window.__nazrToken`; the report response is 200 with `verdict "pass"`; the hidden input `input[name=nazr-token]` holds the token; fetch `GET <endpoint>/widget/v1/jwks.json` via `curl -ks` and verify with `jose.createLocalJWKSet` + `jwtVerify(token, jwks, { issuer: endpoint, audience: keyId })` → `payload.jti === __nazrWidget.nonce`, `payload.verdict === "pass"`, `payload.hostname === "http://localhost:4173"`; `POST <endpoint>/widget/v1/siteverify` (curl `-ks -H 'content-type: application/json'`) with the secret → `success true`, `correlation.matched true`, all three matches `true`, `error_codes []`; second call → `success false`, `error_codes ["replayed"]`; wrong secret → `invalid-secret`; the admin summary reports `pass >= 1`, `verified >= 1`, `replayed >= 1`.
- [ ] **Step 2: Run** `pnpm build --filter=@nazr/widget && pnpm --filter @nazr/api build && pnpm --filter @nazr/demo test:e2e widget` → FAIL.
- [ ] **Step 3: Implement** the host page and setup changes.
- [ ] **Step 4: Run** → PASS; `pnpm --filter @nazr/demo test:e2e` all green; demo lint/typecheck clean.
- [ ] **Step 5: Commit** `test(demo): widget token, jwks verification and siteverify e2e`.

## Task 11: Documentation and spec amendments

**Files:**
- Modify: `docs/widget.md` (token lifecycle, callbacks, hidden input, expiry/reset, local verification snippets with `jose` and `golang-jwt/jwt/v5`, siteverify request/response/error codes, trust boundary, the Phase 1 → 2a host changes from spec §10), `docs/protocol.md` (routes `GET /widget/v1/jwks.json`, `POST /widget/v1/siteverify`, `POST /admin/keys/{id}/secret`; report body/response; summary fields; `allowed_origins` unchanged), `docs/configuration.md` (four variables; Subcommands: `keys secret-rotate`, `signing rotate|list`; Reference output regenerated), `README.md` (one line), `CLAUDE.md` (`signing` in the CLI list; `siteverify` in the overview sentence), `packages/widget/README.md`, `docs/superpowers/specs/2026-10-30-widget-phase2a-design.md` (§3.3: the report applies the frame client's default stabilization; §8: `verdict` default `''`), `docs/superpowers/specs/2026-10-30-widget-phase1-design.md` (§3.3 note that Phase 2a changed the filter and the body; link).

- [ ] **Step 1: Write** the docs with field names copied from Tasks 5–9.
- [ ] **Step 2: Verify** `pnpm lint:biome` has no errors; every `NAZR_*` in `config.go` appears in `docs/configuration.md` (empty diff).
- [ ] **Step 3: Verify** the full pipeline: `pnpm lint && pnpm typecheck && pnpm test && pnpm build`, `NAZR_TEST_REQUIRE_DB=1 go test -race ./...` in `apps/api`, and `pnpm --filter @nazr/demo test:e2e`.
- [ ] **Step 4: Commit** `docs: widget tokens, siteverify and signing keys`.
