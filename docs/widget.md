# Widget embedding guide

The nazr widget is a small script you embed on your site. It loads a hidden cross-origin iframe from your nazr server, which computes a fingerprint in a browsing context your page's JavaScript cannot reach, solves a proof-of-work challenge and reports to nazr. If the visit looks clean, nazr signs a short-lived token. Your backend checks the token locally or through `POST /widget/v1/siteverify`. nazr also compares the report with the same visit's `POST /thumbmark` call, matched by a nonce you pass to both. Routes and fields are in [protocol.md](protocol.md#widget); variables are in [configuration.md](configuration.md).

The token is a verdict about the browser's connection and environment. It does not change the thumbmark, visitor ids or the danger score.

## Embed

Put the loader tag inside the form you want to protect:

```html
<form method="post" action="/signup">
  <script src="https://nazr.example.com/widget/v1/loader.js" data-api-key="nzr_..."></script>
  <!-- your fields -->
</form>
```

| Attribute | Meaning |
|---|---|
| `data-api-key` | Required. The same public key you use for `/thumbmark`. It appears in the frame URL, so it lands in nazr's access logs and browser history, the same exposure as the `x-api-key` header |
| `data-response-field-name` | Name of the hidden input the loader fills with the token. Default `nazr-token` |
| `data-callback` | Name of a global function called with the token string when a token arrives |
| `data-error-callback` | Name of a global function called with a reason string when no token can be issued |
| `data-expired-callback` | Name of a global function called, without arguments, when the token expires |
| `data-container` | CSS selector of an element on your page. When it resolves, the loader mounts the widget there and enables the [interactive step](#interactive-step). Without it, or when the selector matches nothing or is invalid, the widget stays hidden |
| `data-interactive-callback` | Name of a global function called, without arguments, when the frame shows its click-to-verify box |
| `data-nonce` | Ignored since Phase 2a. The loader logs a console warning. The nonce is now the server-issued challenge id |

- Load it as a classic script (not `type="module"`): the loader reads its own script tag synchronously.
- Place the loader tag before the host code that reads `window.__nazrWidget`, and do not mark it `async`: an async loader may run after your code, which then finds no widget. `defer` is fine only if the host code also runs after it.
- One widget per page. A second loader on the same page does nothing. The loader never throws and never breaks the host page; a missing key simply means no widget.
- The iframe sits in a closed shadow root. That deters casual inspection but is not a security boundary: the loader runs in your page's origin and a hostile page script can replace it. What is trustworthy is the frame, whose execution and report your page cannot touch.
- Callbacks are looked up on `window` by name when they fire, so define them before or after the loader runs. A callback that throws is logged and ignored.

### The `window.__nazrWidget` object

```ts
window.__nazrWidget = {
  ready: Promise<{ nonce: string }>,
  nonce?: string,
  token?: string,
  state: "pending" | "pass" | "interactive" | "failed",
  reset(): void,
};
```

| Member | Meaning |
|---|---|
| `ready` | Resolves with `{ nonce }` when the frame has decoded its challenge. It does not wait for the proof-of-work or the report. It always settles within 10 seconds: if no challenge arrives by then it resolves with `{ nonce: "" }` and the error callback gets `network` |
| `nonce` | The current challenge id. Set asynchronously, so it is `undefined` right after the loader runs: always `await ready` first. It changes on every `reset()` |
| `token` | The current token, or `undefined` before the first pass, after expiry and after `reset()` |
| `state` | Read-only. `pending` until the frame answers; `pass` after a `pass` token; `interactive` once the click-to-verify box is shown, and it stays `interactive` after the token that step earns; `failed` after an error, including the 10-second `ready` timeout. `interactive` alone means either "box shown, awaiting the click" or "token earned", so check `token` too |
| `reset()` | Clears the token and the hidden input, collapses the frame back to hidden, sets `state` to `pending` and reloads the frame, which fetches a fresh challenge and starts over |

When the loader did not run (blocked, failed to load, or no `data-api-key`), `window.__nazrWidget` is undefined.

### Hidden input and callbacks

When the loader script sits inside a `<form>`, the loader adds `<input type="hidden" name="nazr-token">` (or reuses an existing input with that name) and keeps it in sync with the token. Outside a form there is no input; `window.__nazrWidget.token` and the callbacks still work.

| Callback attribute | Called with | When |
|---|---|---|
| `data-callback` | the token | The server answered `pass`, or `interactive` after the click-to-verify step |
| `data-error-callback` | `inconclusive`, `pow_failed`, `invalid`, `interactive_failed` or `network` | No token. The first four relay the server verdict (`interactive_failed` only comes from the interactive step); `network` covers a failed request, an unparsable response or a failed worker |
| `data-interactive-callback` | nothing | The frame shows the click-to-verify box. Use it to scroll the box into view or show a hint |
| `data-expired-callback` | nothing | The token reached its `exp` |

When a token expires, the loader clears the hidden input, calls the expired callback and then calls `reset()` itself, so a long-lived page gets a fresh token without any host code. The refreshed token has a new `jti`.

### Host Content-Security-Policy

If your page sends a CSP, it must allow the nazr origin in `script-src` (the loader) and `frame-src` (the frame). The loader sizes the iframe with an inline `style` attribute; under a strict `style-src` without `'unsafe-inline'` that attribute is blocked, and the 0×0 iframe becomes a small bordered box in the page flow. The widget still works, but the box is visible. The frame itself runs the proof-of-work in a Web Worker served from the nazr origin, which the frame's own CSP (`worker-src 'self'`) allows.

## Token lifecycle

1. **Challenge.** The frame document is served with a challenge minted by nazr: an HMAC-signed payload holding a ULID `id`, an expiry 10 minutes out, the required difficulty `bits` (`NAZR_POW_BITS`), the signing key id and the embedding origin read from the `Referer` header. The `id` is the nonce the loader exposes.
2. **Proof-of-work.** A Web Worker finds the smallest decimal counter for which `sha256(id + ":" + counter)` has at least `bits` leading zero bits. With `NAZR_POW_BITS=0` any counter passes. The difficulty is the one in the signed challenge, so a client cannot lower it.
3. **Report.** The frame posts `{challenge, pow, components, clientHash}` to `POST /widget/report`. nazr verifies the challenge, checks the proof-of-work, classifies the frame's own request, stores the report and answers with a verdict.
4. **Token.** Only a `pass` carries a token, and so does an `interactive` verdict from the [interactive step](#interactive-step).

| Verdict | Meaning | Token |
|---|---|---|
| `pass` | Challenge and proof-of-work valid; the visit is not classified as a bot and its danger level is at most `NAZR_WIDGET_PASS_MAX_DANGER` | yes |
| `inconclusive` | Challenge and proof-of-work valid, but the classification is not clean (a bot, or a danger level above the limit). Automated browsers, where `navigator.webdriver` is true (Playwright, Selenium and the like), land here | no |
| `pow_failed` | The counter does not meet the difficulty | no |
| `invalid` | Malformed body, challenge with a bad MAC, unknown key or past its expiry, or a challenge id that was already reported | no |
| `interactive` | From `POST /widget/interact`: the visitor passed the click-to-verify step. See [Interactive step](#interactive-step) | yes |
| `interactive_failed` | From `POST /widget/interact`: a scoring rule fired on the interaction trace | no |

A challenge can be reported once. A second report for the same challenge is `invalid` and the first token stays valid. If the database is unavailable at report time, a would-be `pass` is downgraded to `inconclusive`: an outage never mints credentials.

### What the token is

A bearer credential: anyone holding it can present it, once. It is an ES256 JWS (`typ: JWT`) with these claims:

| Claim | Value |
|---|---|
| `iss` | `NAZR_WIDGET_ISSUER`, or `https://<Host>` of the request when empty. Set `NAZR_WIDGET_ISSUER` in production so `iss` does not depend on the `Host` header a request arrives with |
| `aud` | The id of the API key the widget was loaded with (the key's `id`, not the `nzr_` string) |
| `jti` | The challenge id. Single use at siteverify |
| `iat`, `exp` | Issue time and expiry, `NAZR_WIDGET_TOKEN_TTL` apart (default 5 minutes) |
| `hostname` | The embedding origin nazr observed from the frame's `Referer`, such as `https://example.com`. Empty when the host page sends `Referrer-Policy: no-referrer`, so such a host cannot use the `hostname` check |
| `verdict` | `pass`, or `interactive` for a token earned through the interactive step |

The token is bound to the key and to the observed origin, not to an IP or a session. Bind it yourself by verifying it in the same request that carries it, and by passing `remoteip` to siteverify.

## Verify the token on your backend

There are two ways. Both need the token from the form field (`nazr-token` by default) or from your `data-callback`.

### Siteverify

`POST /widget/v1/siteverify` takes the key's verify secret. Each key has its own secret, printed once by `nazr keys create` (line 2 of the output) or returned as `secret` by `POST /admin/keys`. Rotate it with `nazr keys secret-rotate <id>` or `POST /admin/keys/{id}/secret`; the old secret stops working immediately. Keys created before Phase 2a have no secret and every siteverify with them is `invalid-secret` until you rotate one in.

```bash
curl -s https://nazr.example.com/widget/v1/siteverify \
  -H 'Content-Type: application/json' \
  -d '{"secret":"nzs_...","token":"<jws>","remoteip":"203.0.113.7"}'
```

```json
{
  "success": true,
  "challenge_ts": "2026-10-30T12:00:00Z",
  "hostname": "https://example.com",
  "verdict": "pass",
  "correlation": { "matched": true, "ip_match": true, "ja4_match": true, "ua_match": true },
  "classification": { "tor": false, "vpn": false, "bot": false, "datacenter": false, "private_relay": false, "danger_level": 0 },
  "signals": {},
  "error_codes": []
}
```

A token earned through the interactive step has `"verdict": "interactive"` and adds an `interaction` block; see [Interactive step](#interactive-step). `remoteip` is optional. Field details and statuses are in [protocol.md](protocol.md#post-widgetv1siteverify). Checks run in this order and the first failure wins:

| Result | HTTP | `error_codes` |
|---|---|---|
| Unknown or revoked secret | 401 | `invalid-secret` |
| Rate limit exceeded | 429 | none (`rate_limited` error, with `Retry-After`) |
| Malformed token, unknown `kid`, bad signature, or `aud` is not the secret's key | 200 | `invalid-token` |
| Past `exp` | 200 | `token-expired` |
| Token already verified | 200 | `replayed` |
| Valid, but `remoteip` differs from the frame's IP | 200 | `remoteip-mismatch` |

- An expired token is rejected before it is spent, so it cannot burn the row.
- `remoteip-mismatch` still returns `hostname`, `verdict`, `correlation`, `classification` and `signals` with `success: false`, and the token is spent. Treat it as a failure.
- Siteverify shares the key's rate-limit bucket (`rate_limit_per_minute`) with page traffic, so budget for it.
- A store failure before the token is spent answers 503 `store_unavailable`, and a retry with the same token works. `correlation` is absent when nazr could not compute it after spending the token; the rest of the answer is unaffected.
- On success and on `remoteip-mismatch`, `hostname` is always present (`""` when nazr did not observe the embedding origin) and `signals` is always an object (`{}` when empty).
- `remoteip` is compared with the IP stored for the frame's request. Under `NAZR_STORE_IP=raw` that is the address itself; under `hash` nazr compares the salted identifier, so `NAZR_IP_HASH_SALT` must not change between report and verify. An unparseable `remoteip` never matches. IPv4-mapped IPv6 addresses are unmapped first.
- `correlation` is the Phase 1 comparison of the frame's report with the `/thumbmark` event carrying the same nonce. `matched: false` means no such event. A refreshed token (after expiry and `reset()`) has a new `jti`, so its `correlation` is `matched: false` unless the host sends `/thumbmark` again with the new `nonce`.

### Verify locally

The public keys are at `GET /widget/v1/jwks.json`. Verifying locally needs no secret and no round trip, but it cannot detect replay: the token stays valid until `exp`. Use siteverify when single use matters.

Check the signature (ES256), `exp`, `aud` equal to your key's id, `hostname` equal to your site's origin, and that `verdict` is `pass` (or `interactive` if you accept the interactive step; see below). Cache the JWKS (the response is `Cache-Control: public, max-age=3600`) and refetch it once when a token carries an unknown `kid`: nazr publishes a new signing key right after `nazr signing rotate`, and the previous key stays published for 24 hours.

Node, with `jose`:

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";

// createRemoteJWKSet caches the set and refetches on an unknown kid.
const jwks = createRemoteJWKSet(new URL("https://nazr.example.com/widget/v1/jwks.json"));

export async function verifyNazrToken(token: string): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, jwks, {
      algorithms: ["ES256"],
      audience: "<your key id>", // exp is checked by jwtVerify
    });
    return (payload.verdict === "pass" || payload.verdict === "interactive") && payload.hostname === "https://example.com";
  } catch {
    return false;
  }
}
```

Go, with `github.com/golang-jwt/jwt/v5` and a JWKS you fetched and cached (decode each key's `x` and `y` into an `*ecdsa.PublicKey` on P-256, keyed by `kid`):

```go
func verifyNazrToken(tokenString string, keys map[string]*ecdsa.PublicKey) bool {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims,
		func(t *jwt.Token) (any, error) {
			kid, _ := t.Header["kid"].(string)
			if k, ok := keys[kid]; ok {
				return k, nil
			}
			return nil, fmt.Errorf("unknown kid %q", kid) // refetch the JWKS once, then retry
		},
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithAudience("<your key id>"),
		jwt.WithExpirationRequired(),
	)
	verdict := claims["verdict"]
	return err == nil && (verdict == "pass" || verdict == "interactive") && claims["hostname"] == "https://example.com"
}
```

## Interactive step

Some visitors are not bots but still do not pass on reputation alone: a VPN or datacenter exit, or a danger level above `NAZR_WIDGET_PASS_MAX_DANGER`. For them the frame can show a small click-to-verify box. A visitor who clicks it earns a token with the verdict `interactive`.

### When it runs

All of these must hold:

- The report was `inconclusive` and the classification is not a bot. Automated browsers (`navigator.webdriver`, headless user agents) are never offered the step.
- `NAZR_WIDGET_INTERACTIVE` is on (the default).
- The host opted in with `data-container`, so the loader asked the frame for the step (`i=1` in the frame URL).

The server's offer is an `interactive` object in the report response: a second challenge for the same id at `NAZR_POW_BITS` plus `NAZR_WIDGET_INTERACTIVE_EXTRA_BITS` difficulty. Without `data-container` the offer is ignored and the widget behaves as in Phase 2a: the error callback gets `inconclusive`.

### Opt in from the host

```html
<div id="nazr-box"></div>
<form method="post" action="/signup">
  <script
    src="https://nazr.example.com/widget/v1/loader.js"
    data-api-key="nzr_..."
    data-container="#nazr-box"
    data-callback="onToken"
    data-interactive-callback="onBox"
  ></script>
</form>
```

The loader mounts the iframe inside `#nazr-box`. It stays 0x0 until the frame announces the step, then grows to 300x65 and `window.__nazrWidget.state` becomes `interactive`. The box holds one button, "Verify you are human". It reads "Verifying…" while the proof-of-work and the request finish, then "Verified ✓" or "Verification failed". The step needs no host styling, and the box keeps its size.

A runnable page is [`apps/demo/widget-host.html`](../apps/demo/widget-host.html) with [`src/widget-host.ts`](../apps/demo/src/widget-host.ts).

### What the frame sends

While the visitor reaches the button, the frame records a small trace, never raw coordinates: when the button was shown and clicked, whether the event was trusted, the input kind (`pointer` or `keyboard`), the pointer type, the number of pointer moves over its own box, path length, straightness and document visibility. It solves the harder proof-of-work while the visitor reads the box, then posts `{challenge, pow, trace}` to `POST /widget/interact`. The server scores the trace against the [interaction rules](signals.md#interaction-rules).

### What `interactive` proves

The trace is self-reported: the frame produces it, and any client that speaks the protocol can post whatever trace it likes, against rules that are published. For such a client the real barriers are the passive classification (only a visitor not classified as a bot is offered the step) and the proof-of-work. What the trace does reject is a canned script that runs the frame's own code: a synthetic `click()`, a dispatched event, an instant click, a click in a hidden tab. It does not reject a driven browser. A real browser controlled through the browser's input channel (CDP or WebDriver input commands) produces trusted events, so a patient automation that moves the mouse over the box passes. The extra proof-of-work raises the cost per attempt, not the bar. With `NAZR_WIDGET_INTERACTIVE_EXTRA_BITS=0` it costs nothing beyond the passive proof-of-work (the challenge has the same id, so the passive counter satisfies it); use at least `1` in production.

Treat `interactive` as weaker than `pass`. Both are accepted for low-risk actions; for high-risk ones, require `pass` only or add your own checks. `straight_path` is advisory: the frame sees only moves over its own box, which is too short a window to fail someone on, so it is recorded in `interaction.signals` and never fails the attempt.

An abandoned interactive challenge is not cancelled. The offer stays redeemable by whoever holds it until the challenge `exp` (10 minutes from the frame load), and a redeemed offer cannot be redeemed twice. `reset()` loads a fresh frame with a fresh challenge but does not revoke the old one.

### After a failure

`interactive_failed` and `invalid` leave the box in its failed state ("Verification failed"); the frame also answers `invalid` on its own once the interactive challenge expires before the click. Nothing retries by itself. Call `window.__nazrWidget.reset()` from `data-error-callback` (here `data-error-callback="onNazrError"`) to start a fresh passive run with a new challenge:

```js
function onNazrError(reason) {
  if (reason === "interactive_failed" || reason === "invalid") window.__nazrWidget.reset();
}
```

### Verify on the backend

Accept `pass`, and `interactive` if you want the step to unlock the action. In siteverify, `verdict` carries the token's verdict, and an `interaction` block is present when the report was upgraded:

```json
{
  "success": true,
  "challenge_ts": "2026-10-31T12:00:00Z",
  "hostname": "https://example.com",
  "verdict": "interactive",
  "classification": { "tor": false, "vpn": true, "bot": false, "datacenter": false, "private_relay": false, "danger_level": 3 },
  "signals": {},
  "interaction": {
    "input": "pointer",
    "pointer_type": "mouse",
    "trusted": true,
    "moves": 14,
    "path_px": 212.5,
    "straightness": 0.71,
    "elapsed_ms": 1840,
    "signals": {}
  },
  "error_codes": []
}
```

| Field | Meaning |
|---|---|
| `input` | `pointer` or `keyboard` |
| `pointer_type` | `mouse`, `touch`, `pen`, or `""` for keyboard |
| `trusted` | Every recorded event, the pointer moves and the activation, had `isTrusted` set |
| `moves`, `path_px`, `straightness` | Pointer moves over the box, path length in CSS pixels, and chord over path length (0 to 1) |
| `elapsed_ms` | Milliseconds between the button being shown and activated |
| `signals` | Only the interaction rules that fired, `{}` when none did. A passing token can carry `{"straight_path": true}`, which is advisory; see [signals.md](signals.md#interaction-rules) |

`interaction` is absent when the token came from a plain `pass`. The `jose` and `golang-jwt/jwt/v5` snippets above already accept both verdicts when verifying locally; local verification gives no `interaction` block.

## Correlate with the page call

Pass the widget's nonce to `@nazr/thumbmark` through the `nonce` option. The nonce is set asynchronously, so await `ready`; never read `window.__nazrWidget.nonce` synchronously:

```ts
import { getThumbmark } from "@nazr/thumbmark";

// undefined when the loader did not run; the page call still goes ahead.
const nonce = (await window.__nazrWidget?.ready)?.nonce;
const result = await getThumbmark({
  api_key: "nzr_...",
  api_endpoint: "https://nazr.example.com",
  ...(nonce ? { nonce } : {}),
  cache_api_call: false,
});
```

The optional chaining matters: an ad blocker, a CSP or a network error can stop the loader, and an unguarded `window.__nazrWidget.ready` would then throw and skip the page call. A page call without a nonce is simply uncorrelated.

`ready` always settles within 10 seconds. When the loader ran but the frame never delivered a challenge (it was blocked or failed to load), `ready` resolves with an empty `nonce` and the `data-error-callback` global gets `network`. The `nonce ? { nonce } : {}` guard above then sends the page call without a nonce, so it goes ahead uncorrelated.

`nonce` is sent as a top-level field of the `POST /thumbmark` body. It is never part of `components`, never in the hash, and not echoed in `options` or the response, so the thumbmark is unchanged. A runnable page is [`apps/demo/widget-host.html`](../apps/demo/widget-host.html) with [`src/widget-host.ts`](../apps/demo/src/widget-host.ts): it loads the widget inside a form with a `data-callback`, awaits `ready`, then calls `getThumbmark` with the nonce.

Set `cache_api_call: false` when you pass a nonce. By default the client caches the API call's promise; a cached promise sends no request, so the nonce would never reach the server and the page event would stay uncorrelated.

**Stock client caveat.** The stock `@thumbmarkjs/thumbmarkjs` client has no `nonce` option. A page using it still gets the widget report and token, but its `/thumbmark` events carry no nonce, so they can never be correlated. Use `@nazr/thumbmark` for correlation.

## What the summary shows

`GET /admin/keys/{id}/widget` (admin token) summarises the key's reports and nonce-carrying `/thumbmark` events over the last 30 days; see [protocol.md](protocol.md#admin-api). A report matches the most recent `/thumbmark` event with the same key and nonce within 10 minutes, in either direction, so arrival order does not matter. The correlation verdict is computed when you read the summary and is advisory: it is not part of the danger score. The summary also counts the token outcomes: `pass`, `inconclusive`, `pow_failed`, `verified` (tokens spent at siteverify) and `replayed` (reports whose spent token was presented again). `interactive` and `interactive_failed` count reports upgraded by the interactive step; an upgraded report leaves the `inconclusive` count.

For a matched pair the summary compares the client IP hash, the raw JA4 string and the raw `User-Agent` string. `ja4_unknown` counts matched reports where either side has no JA4 (every request in `plain` mode). A nonce reused across many reports yields many rows, each matched independently.

It detects:

- a `/thumbmark` call carrying a nonce with no widget report within the window (the iframe was blocked or never ran, or the caller never loaded the page), shown as `events_unmatched`;
- a widget report with no page call carrying the same nonce (a stock client, a cached call, or a forged report), shown as `unmatched`;
- a page call routed through a different IP or TLS stack than the frame (replay of a captured body from a script, or a proxied page call), shown as `ip_mismatch`, `ja4_mismatch` or `ua_mismatch`.

It does not detect in-page JavaScript tampering that spoofs navigator, screen or WebGL values: that page call still shares the browser's IP, JA4 and UA with the frame. Detecting that needs a comparison of components that must be equal across the two contexts, and that subset is not yet known (the iframe legitimately differs on `clientrects`, viewport-sized values, `permissions` and blocked third-party storage). nazr stores the frame's components so the stable subset can be measured on real traffic.

A forged report can only attribute a fabricated fingerprint to a nonce the attacker chose; correlation then flags it as a mismatch against the real page event, or leaves it unmatched. But a forged report sent over the real browser's own connection, with the same nonce as its page call, correlates cleanly: same IP, JA4 and UA. The nonce is opaque and not a secret. The nonce is now a single-use, server-issued challenge id, so an attacker cannot pick it, but it is still not a secret from the page. The consistency verdict stays advisory and unscored.

## The stored thumbmark

The server computes a `thumbmark` for each widget report with the frame client's default stabilization (`private` and `iframe`), so it is comparable with the frame's `clientHash`, but it is still an analysis value and is not expected to equal the page's thumbmark. A report never creates or touches a visitor.

## Trust boundary and deployment

- **Signing keys.** The server needs a signing key to serve frames, report and verify. `nazr serve` creates one on first start (guarded by a database advisory lock, so replicas do not race) and each replica reloads the set every 60 seconds. Rotate with `nazr signing rotate`, which prints the new `kid`; `nazr signing list` shows `KID`, `CREATED` and `RETIRED`. A retired key stays published in the JWKS and usable for challenges and verification for 24 hours, so tokens and open frames survive a rotation.
- **Plaintext in Postgres.** The signing keys' private halves and HMAC secrets are stored unencrypted in the database, alongside the API-key hashes. Whoever can read the database can mint tokens and challenges. Restrict database access and backups accordingly. Verify secrets, by contrast, are stored as SHA-256 hashes.
- **The frame decides.** The verdict comes from the frame's own connection and the report it posts; the loader and your page only relay a token. A hostile page script can drop or replace the loader, but it cannot obtain a token for a visit the frame did not pass, and a token is single use at siteverify.

## Moving from Phase 1

| Phase 1 | Phase 2a |
|---|---|
| Loader generated a nonce or took `data-nonce` | `data-nonce` is ignored with a console warning. The nonce is the server's challenge id, set asynchronously: `await window.__nazrWidget.ready` |
| `window.__nazrWidget = { nonce, ready }` | `{ ready, nonce, token, reset }` |
| `POST /widget/report` body `{nonce, components, clientHash}`, answer `204` | Body `{challenge, pow, components, clientHash}`, answer `200 {verdict, token?}` |
| Frame URL `?k=&n=` | `n` is ignored; the frame carries a challenge and the CSP gains `worker-src 'self'` |
| Server thumbmark unfiltered | Default stabilization (`private`, `iframe`) |
| No host-side check | Verify the token with siteverify or the JWKS |
| A Phase 1 loader still in a browser cache (at most 300 s) | It gets the new frame, because the frame document is `no-store`. That frame earns a token the old loader ignores, and the page call carries the old loader's own nonce, so correlation is unmatched for at most 300 s |

The `/thumbmark` `nonce` field, the correlation summary, retention and the admin counts are unchanged. Remove any synchronous read of `window.__nazrWidget.nonce` from host code.

## Moving from Phase 2a to 2b

Phase 2b is additive. A host that changes nothing behaves as before.

| Phase 2a | Phase 2b |
|---|---|
| Token `verdict` is always `pass` | `pass` or `interactive`. A host that checks `verdict == "pass"` rejects interactive tokens, which is safe; add `interactive` to accept them |
| No interactive step | Opt in with `data-container`; without it nothing changes |
| `window.__nazrWidget` has `ready`, `nonce`, `token`, `reset` | Adds read-only `state` |
| Error callback reasons `inconclusive`, `pow_failed`, `invalid`, `network` | Adds `interactive_failed` |
| Siteverify has no `interaction` | Adds the optional `interaction` block |
| Summary counts `pass`, `inconclusive`, `pow_failed` | Adds `interactive` and `interactive_failed` |
| Challenge payload `{id, exp, bits, kid, origin}` | May carry `stage`, set to `interactive` on the second challenge |

## Origin scoping

The frame document is served with `Content-Security-Policy: frame-ancestors` set to the key's `allowed_origins` (or `*` when the key has none), so only those origins can embed the widget. The report itself skips the key's origin check, because the frame posts from nazr's own origin, which is never in a key's list.

## Rate limits and storage

Reports and siteverify calls count against the key's `rate_limit_per_minute` together with `/thumbmark` calls. Each page view makes one of each of the first two, plus one siteverify per protected action, so budget accordingly.

Reports are stored with the same privacy settings as events: `NAZR_STORE_IP` controls the raw address and `NAZR_STORE_COMPONENTS` whether the merged components are kept. They are pruned under `NAZR_EVENT_RETENTION`.

## Serving the assets

The nazr binary embeds the built widget when its assets were synced before the Go build. `pnpm build` builds `@nazr/widget` and the API's build step (`sync-widget`) copies its `dist/` into the Go embed directory before `go build`. The release workflow does this; local builds of the image or binary must do it themselves first:

```bash
pnpm install && pnpm build --filter=@nazr/widget && pnpm --filter @nazr/api sync-widget
# or: pnpm build --filter=@nazr/api, which builds the widget and runs the sync
```

Without it the widget routes return 404 while everything else works. When the widget build is missing, `sync-widget` clears the embed directory and warns, so a stale widget is never embedded.

To serve from disk instead, for development, set `NAZR_WIDGET_DIR`; nazr logs a warning at startup when that directory holds no widget. The directory also holds the proof-of-work worker bundle named in `manifest.json`. If no assets are present, the `GET /widget/v1/` asset routes (loader, frame, bundles) return 404 and the rest of the server is unaffected; `POST /widget/report`, `GET /widget/v1/jwks.json` and `POST /widget/v1/siteverify` always exist.
