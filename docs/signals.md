# Signals, components and IP lists

Companion to [protocol.md](protocol.md) and [configuration.md](configuration.md). The scoring table below mirrors `Rules()` in `apps/api/internal/classify/classify.go`, in the same order.

## Components

`components` in a request holds the client components; `components` in a response holds the server-observed set. The thumbmark hashes `merge(client, filter(server))`.

### Client components (18)

Upstream ThumbmarkJS (13): `audio`, `canvas`, `fonts`, `hardware`, `locales`, `math`, `permissions`, `plugins`, `screen`, `speech`, `system`, `webgl`, `webrtc`.

Added by the nazr fork (5): `webgpu`, `clienthints`, `clientrects`, `mediaqueries`, `privacy`.

A component whose browser API is unavailable is omitted; `privacy` is always present. The server reads three client fields for classification: `locales.timezone`, `privacy.webdriver` (false when absent) and `system.browser` (for stabilization rules).

### Server components (4)

| Key | Present when | Fields |
|---|---|---|
| `tls` | TLS terminated here (full), or `proxied` mode with a JA4 header (only `ja4`) | `version`, `ja4`, `ja4_r`, `ciphers`, `extensions` (sorted ascending), `sig_algs`, `groups`, `sni`, `alpn`. GREASE values are dropped from the lists. JA3 is not included (see below) |
| `h2` | `terminate` mode, HTTP/2 connection | `fingerprint` (Akamai-style string), `settings`, `window_update`, `priorities`, `pseudo_header_order` |
| `header` | always | `ja4h` (cookie-free `ja4h_a_ja4h_b`; see below), `order` (lowercased), `userAgent`, `accept`, `acceptEncoding`, `acceptLanguage` (`raw`, `q`), `clientHints`; absent headers are omitted |
| `ip` | the client address is known | `address`, `version`, `asn`, `as_org`, `country`, `region`, `city`, `tor`, `vpn`, `datacenter`, `private_relay` |

`header.ja4h` drops JA4H's last two parts, the hashes of cookie names and cookie name=value pairs: a site setting or rotating a cookie would otherwise change the thumbmark of the same browser. The full four-part value is kept in `events.ja4h`. The cookie-present and referer-present flags in the `a` part are also normalized to `n`, so the thumbmark does not change when a site sets its first cookie or when the referrer differs; `events.ja4h` keeps the real flags.

`tls` is the same on every connection from the same browser. Chromium permutes its TLS extension order per connection, so `tls.extensions` is sorted (as JA4 does) and JA3, which hashes the wire order, is left out of the component: the server stores the JA3 hash on the event only (`events.ja3_hash`). Session resumption is disabled in `terminate` mode because a resuming ClientHello adds `pre_shared_key` and would change JA4 for returning browsers.

Header order is captured per request (each request's own HTTP/2 header block or HTTP/1.1 head) and depends on the TLS mode: `plain` captures HTTP/1.1 header order only; `terminate` captures it for HTTP/2 but not for HTTP/1.1 over TLS, where `ja4h` falls back to sorted header names; `proxied` sees whatever order the proxy forwards. See [Connection modes](protocol.md#connection-modes-and-fingerprint-capture).

## Classification

`danger_level` is the sum of the danger points of every signal that fired, clamped to 0-5. `bot` is true when the sum of bot points is at least 3 (`botThreshold`).

| Signal | Danger | Bot |
|---|---|---|
| `tor_exit` | 3 | 0 |
| `datacenter` | 2 | 0 |
| `vpn` | 1 | 0 |
| `private_relay` | 0 | 0 |
| `webdriver` | 2 | 3 |
| `headless_ua` | 2 | 3 |
| `ua_tls_mismatch` | 1 | 2 |
| `h2_automation` | 1 | 2 |
| `missing_accept_language` | 1 | 1 |
| `timezone_country_mismatch` | 1 | 0 |
| `datacenter_browser_ua` | 1 | 1 |
| `canvas_probe_anomaly` | 1 | 1 |

`info.signals` contains every signal as a boolean, fired or not. `info.classification` also exposes `tor`, `vpn`, `datacenter` and `private_relay` as plain booleans from the IP lists.

### When each signal fires

- `tor_exit`: the client IP is in the Tor exit list.
- `datacenter`: the client IP is in a datacenter list (X4BNet by default).
- `vpn`: the client IP is in a VPN list.
- `private_relay`: the client IP is in Apple's Private Relay egress list. It contributes 0 danger, following Apple's guidance that relay users are not a threat signal; it only sets `private_relay` and overrides geo.
- `webdriver`: `components.privacy.webdriver` is `true`.
- `headless_ua`: the User-Agent contains (case-insensitive) one of `headlesschrome`, `phantomjs`, `electron`, `puppeteer`, `playwright`, `selenium`.
- `ua_tls_mismatch`: a JA4 is known, the UA family is a browser, and none of the families known for that JA4 matches it. Chromium derivatives (Edge, Opera, Brave, Samsung) collapse onto Chrome. On iOS and iPadOS (UA contains `iPhone`, `iPad`, `iPod`, `CriOS/`, `FxiOS/` or `EdgiOS/`) every browser uses WebKit and Apple's TLS stack, so the UA is compared as `safari`. See below.
- `h2_automation`: the request's Akamai HTTP/2 fingerprint is in the automation set. Only `terminate` mode with HTTP/2 can fire it.
- `missing_accept_language`: no `Accept-Language` header and the UA family is a browser.
- `timezone_country_mismatch`: the IP country is known, `locales.timezone` maps to one or more countries (from the IANA `zone1970.tab`), and the IP country is not one of them.
- `datacenter_browser_ua`: the IP is a datacenter and the UA family is a browser.
- `canvas_probe_anomaly`: opt-in via `NAZR_CANVAS_PROBE_SCORING`. It fires only when scoring is on, the visitor's cohort (user-agent family plus JA4 family) has at least 50 probed events in the last 30 days, and this visit's probe differs from the cohort's dominant probe. When no determination is made (scoring off, no probe sent, or the cohort is too small) the signal is absent from `info.signals` entirely, rather than present as `false`.

Browser families are `chrome`, `edge`, `firefox`, `safari`, `opera`, `samsung`, `brave`. Brave cannot be told apart from Chrome by UA alone.

### Consumer canvas probe and the entropy report

A consumer can supply its own canvas drawing routine through the client's `canvas_probe` option (see the [client README](../packages/thumbmark/README.md#canvas-probe)). Its hash travels as the top-level `canvas_probe` request field, is stored on the event, and never affects the thumbmark. Scoring it is off by default (`NAZR_CANVAS_PROBE_SCORING=false`).

`GET /admin/keys/{id}/canvas-probe` (admin token) reports how well the routine separates visitors over a 30-day window:

| Field | Meaning |
|---|---|
| `window_days` | Length of the window (30) |
| `visitors` | Probed visitors in the window |
| `distinct_probes` | Distinct probe values seen |
| `ratio` | `distinct_probes / visitors`. It can exceed 1 when a single visitor emits several probe values |
| `verdict` | `insufficient_data` (fewer than 50 probed visitors), `too_low` (ratio at most 0.05), `too_unique` (ratio at least 0.95), otherwise `ok` |

**Builder beware.**

- The probe contributes nothing to the thumbmark or visitor identity.
- It is only as private as the bundle. Anyone who loads the page can read the routine and replay its output; the UMD obfuscation only slows that down.
- A low-entropy routine (`too_low`) barely distinguishes visitors. A randomized one (`too_unique`) is useless as a consistency check and will produce noise.
- Keep `NAZR_CANVAS_PROBE_SCORING` off until the entropy report reads `ok`.

### `h2_automation`

The set holds three Akamai-format fingerprints (`settings|window_update|priorities|pseudo_header_order`):

| Client | Fingerprint | Source |
|---|---|---|
| Go `net/http` (x/net/http2 defaults) | `2:0;4:4194304;5:16384;6:10485760\|1073741824\|0\|a,m,p,s` | Observed in the `internal/conn` test `TestH2ClientGetsTLSAndH2` |
| curl (nghttp2 defaults) | `3:100;4:10485760;2:0\|1048510465\|0\|m,p,a,s` | Taken from curl/nghttp2 documentation, not observed |
| curl 8.x (nghttp2) | `3:100;4:10485760;2:0\|1048510465\|0\|m,s,a,p` | Observed from `curl --http2` against `nazr serve` in terminate mode |

Treat the set as a heuristic: it is small, and a client that changes its HTTP/2 settings escapes it.

### `ua_tls_mismatch` and the JA4 corpus

The signal needs a corpus mapping JA4 fingerprints to application families. Without one it never fires. Two sources feed it, and the families from both are merged:

1. The local `ua_ja4_observations` table. A family counts for a JA4 once it has been seen at least `NAZR_UA_JA4_MIN_OBSERVATIONS` times (default 20). In the current implementation the table is fed only by `/beacon`; `/thumbmark` requests do not record observations.
2. The FoxIO JA4 database. This is opt-in: FoxIO put the database behind an account at ja4db.foxio.io, so there is no default URL. Set `NAZR_JA4DB_URL` and `NAZR_JA4DB_TOKEN` (sent as a Bearer token) to enable it; refresh interval is 7 days.

Warning: `/beacon` is unauthenticated (it is sent with `sendBeacon`, which cannot set headers). As a mitigation, a beacon is recorded only when the same client IP produced a `/thumbmark` event with the beacon's `thumbmark` in the last 10 minutes, and `/beacon` is rate limited per IP. That stops blind posting of `{ua, ja4}` pairs, but a client that calls `/thumbmark` first (which needs an API key, and in terminate mode the JA4 then comes from its own connection) can still seed observations for its own JA4, so the local corpus reports whatever family it likes and the mismatch never fires for it. Until you have a trusted corpus, set `NAZR_UA_JA4_MIN_OBSERVATIONS` high (for example 1000) or rely only on the FoxIO database.

## Interaction rules

The widget's [interactive step](widget.md#interactive-step) scores a small trace the frame records while the visitor reaches and presses its button. The table mirrors `Rules()` in `apps/api/internal/interaction/score.go`, in the same order. Every rule is evaluated; the ones that fired are recorded under `signals` in the stored report and in siteverify's `interaction` block (`{}` when none fired, `{"straight_path": true}` for the advisory case). A malformed trace is answered `invalid` and never stored.

| Signal | Fails the attempt | Fires when |
|---|---|---|
| `untrusted_event` | yes | `trusted` is false: the activating event was not a real user event |
| `too_fast` | yes | `click_ms - shown_ms` is under 300 |
| `too_slow` | yes | `click_ms - shown_ms` is over 600000 (ten minutes) |
| `hidden_document` | yes | `visible` is false: the document was hidden at the click |
| `no_pointer_path` | yes | a mouse or pen click with fewer than 3 pointer moves |
| `straight_path` | no | a mouse or pen click with `straightness` of at least 0.98 |
| `malformed_trace` | yes | a field is outside its bounds, or `input` or `pointer_type` is not a listed value |

`straight_path` is advisory: it is recorded but never fails the attempt, because the frame observes only moves over its own box, a path too short to judge. Touch and keyboard activations skip `no_pointer_path` and `straight_path`: a tap has no path and a keyboard user has no pointer. The thresholds are constants in the package, not configuration.

Trace bounds: `shown_ms` and `click_ms` are 0 to 2^31; `moves` is 0 to 200; `path_px` is finite and 0 to 1,000,000; `straightness` is finite and 0 to 1; `input` is `pointer` or `keyboard`; `pointer_type` is `mouse`, `touch`, `pen` or empty; strings are at most 16 characters. Any non-advisory rule that fires gives `interactive_failed`.

## Deviations from the design spec

- FoxIO's JA4 database is opt-in (`NAZR_JA4DB_URL`, `NAZR_JA4DB_TOKEN`) instead of a default-on public download, because it now requires an account.
- `info.signals` lists all evaluated signals, true and false, rather than only the contributing ones.

## IP lists

Sources load from `NAZR_DATA_DIR` on boot, so the server serves immediately, and then refresh in the background. Tables are swapped atomically. A failed or invalid download never replaces the cached copy. The scheduler retries with exponential backoff: 10 minutes after the first failure, doubling per consecutive failure, capped at the source's refresh interval, and reset by a success. An HTTP 429 or 403 from a source defers its next attempt by a full refresh interval at once. Downloads are conditional (`ETag` / `If-Modified-Since`) and parsed before they replace the cached file.

| Source name | URL | Interval | Sets |
|---|---|---|---|
| `GeoLite2-City` | `https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz` | 24h | `country`, `region`, `city`, continent |
| `GeoLite2-ASN` | `https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz` | 24h | `asn`, `as_org` |
| `apple` | `https://mask-api.icloud.com/egress-ip-ranges.csv` (`NAZR_APPLE_RELAY_URL`) | 24h | `private_relay`; overrides geo |
| `tor` | `https://check.torproject.org/torbulkexitlist` (`NAZR_TOR_EXIT_URL`) | 6h | `tor` |
| `datacenter`, `datacenter-2` | `https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt` and `https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt` (`NAZR_DATACENTER_URLS`) | 24h | `datacenter` |
| `vpn`, `vpn-2` | `https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt` and `https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt` (`NAZR_VPN_URLS`) | 24h | `vpn` |
| `ja4db` | none; `NAZR_JA4DB_URL` required | 7d | JA4 to application families |

Notes:

- With more than one URL in `NAZR_DATACENTER_URLS` or `NAZR_VPN_URLS` (the defaults have two each: IPv4 then IPv6), sources are named `datacenter`, `datacenter-2`, `datacenter-3`, and likewise for `vpn`. Disabling the kind (`datacenter`, `vpn`) skips all of them.
- MaxMind needs both `NAZR_MAXMIND_ACCOUNT_ID` and `NAZR_MAXMIND_LICENSE_KEY`; without both the editions are skipped (reported as `no credentials`). Each process downloads at most once per 24 hours per edition, and only when the HEAD `Last-Modified` is newer than the cached copy. The tarball's sha256 is checked against MaxMind's published digest, and on any failure the previous database is kept. MaxMind limits an account to 30 downloads per day, so persist `NAZR_DATA_DIR` on a volume to avoid re-downloading on every restart.
- The Apple relay CSV overrides MaxMind geo for relay IPs: `country`, `region` and `city` come from Apple, and the country name and continent are cleared if Apple's country differs from MaxMind's. Region formats differ: Apple publishes `GB-EN`, MaxMind `GB-ENG`. Do not compare regions across the two.
- `NAZR_LISTS_DISABLE` takes source names or kinds (`maxmind`, `apple`, `tor`, `datacenter`, `vpn`, `ja4db`), comma separated, case-insensitive. Disabled sources show `last_error: "disabled"` in `/readyz`.
- Force a fetch of everything and print a table:

```bash
nazr lists refresh
```

```text
source         loaded  rows  fetched_at  last_error
GeoLite2-ASN   false   0     -           disabled
GeoLite2-City  false   0     -           disabled
apple          false   0     -           disabled
...
```

Per-source errors appear in the table's last column and do not change the exit code.
