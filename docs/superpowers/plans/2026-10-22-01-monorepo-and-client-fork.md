# nazr Plan 1: Monorepo scaffold and client fork

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the Turborepo monorepo and produce `@nazr/thumbmark`, a fork of ThumbmarkJS 1.12.0 with self-host defaults, five new components, and a golden-fixture generator the Go API tests consume.

**Architecture:** pnpm workspaces orchestrated by Turborepo, Biome for TS lint/format. The client fork keeps upstream's Rollup + Jest + Playwright tooling so future upstream diffs stay small; only endpoints, defaults, types, and new component files change. Fixtures are emitted into `apps/api/testdata/fixtures` by a script run from the client package.

**Tech Stack:** pnpm 10, Turborepo 2, Biome 2, TypeScript 5, Rollup 4, Jest 29 (ts-jest, jsdom), tsx for scripts.

**Spec:** `docs/superpowers/specs/2026-10-21-nazr-design.md` (sections 3, 12, 6 for fixtures)

## Global Constraints

- Node `>=22`, pnpm `>=10`. Pin with `packageManager` in root `package.json` and `.node-version`.
- Fork base is upstream tag `v1.12.0`. Upstream's MIT notice is kept as `packages/thumbmark/LICENSE.upstream` and referenced in the package README. Repo license is GPL-3.0.
- Package name `@nazr/thumbmark`, version `0.1.0`, same export surface as upstream `src/index.ts`.
- Biome is the only TS linter/formatter. Root config uses 2-space indent; `packages/thumbmark` overrides to 4-space to match upstream.
- `defaultOptions.logging` is `false`.
- Log URL is `${api_endpoint without trailing slash}/log`; beacon default is `${api_endpoint without trailing slash}/beacon`; when `api_endpoint` is unset both fall back to upstream's hosted defaults.
- The experimental payload fetch from `experimental.thumbmarkjs.com` is removed; `logThumbmarkData` sends `experimental: null`.
- New component keys: `webgpu`, `clienthints`, `clientrects`, `mediaqueries`, `privacy`. Each returns `null` when its API is unavailable so the key is omitted.
- `src/index.ts` additionally exports `hash` (from `src/utils/hash`) so the demo and e2e tests can recompute thumbmarks in-page.
- Fixture output is deterministic: sorted keys, no timestamps, LF line endings, trailing newline.

## Review Focus

1. `api_endpoint` given with a trailing slash or a path (`https://x/api/`) must produce `/log` and `/beacon` URLs with exactly one slash. Test pinned in Task 3.
2. Firefox and Safari have no `navigator.userAgentData`; `clienthints` must resolve `null`, never throw. Pinned in Task 6.
3. `navigator.gpu` present but `requestAdapter()` resolving `null` (GPU blocked by policy) must resolve `{ supported: false }`, and a rejecting `requestAdapter()` must also resolve `{ supported: false }`. Pinned in Task 5.
4. `window.matchMedia` missing or throwing must make `mediaqueries` resolve `null`. Pinned in Task 8.
5. Running the fixture generator twice must produce byte-identical files, otherwise CI will flap. Pinned in Task 11.

---

### Task 1: Root workspace scaffold

**Files:**
- Create: `package.json`, `pnpm-workspace.yaml`, `turbo.json`, `biome.json`, `.node-version`, `.gitignore`, `.editorconfig`, `README.md`
- Create: `apps/.gitkeep`, `packages/.gitkeep`, `deploy/.gitkeep`

**Interfaces:**
- Produces: turbo tasks `build`, `test`, `lint`, `typecheck`, `format` that every workspace `package.json` may implement. Root scripts `pnpm build|test|lint|typecheck|format` call `turbo run <task>`.

- [ ] **Step 1: Write root `package.json`**

Fields: `"name": "nazr"`, `"private": true`, `"packageManager": "pnpm@10.27.0"`, `"engines": {"node": ">=22"}`, scripts `build`/`test`/`lint`/`typecheck` → `turbo run <task>`, `format` → `biome format --write .`, `lint:biome` → `biome check .`. devDependencies: `turbo` `^2`, `@biomejs/biome` `^2`, `typescript` `^5.9`.

- [ ] **Step 2: Write `pnpm-workspace.yaml`** with `packages: ["apps/*", "packages/*"]`.

- [ ] **Step 3: Write `turbo.json`**

Tasks: `build` (`dependsOn: ["^build"]`, outputs `dist/**`, `types/**`, `bin/**`), `test` (`dependsOn: ["build"]`), `lint`, `typecheck`, `dev` (`cache: false`, `persistent: true`). `globalDependencies: ["biome.json"]`.

- [ ] **Step 4: Write `biome.json`**

Schema for Biome 2. `formatter.indentStyle: "space"`, `indentWidth: 2`, `lineWidth: 100`. `linter.rules.recommended: true`. `files.includes` excludes `**/dist`, `**/types`, `**/node_modules`, `**/coverage`, `**/.turbo`, `deploy/**`. One override for `packages/thumbmark/**` with `formatter.indentWidth: 4` and `linter.rules.suspicious.noExplicitAny: "off"` (upstream uses `any` widely).

- [ ] **Step 5: Write `.node-version` (`22`), `.gitignore`** (node_modules, dist, types, .turbo, coverage, `*.log`, `.env`, `apps/api/bin`, `apps/api/.data`, `deploy/terraform/**/.terraform`, `*.tfstate*`), `.editorconfig`, and a `README.md` with the project one-liner and a pointer to `docs/`.

- [ ] **Step 6: Install and verify**

Run: `pnpm install && pnpm exec turbo run build --dry-run=json | head -5 && pnpm exec biome check .`
Expected: install succeeds, turbo prints a dry-run JSON, biome reports no errors (no TS files yet).

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "chore: scaffold turborepo workspace with biome"
```

---

### Task 2: Import upstream ThumbmarkJS 1.12.0 as `@nazr/thumbmark`

**Files:**
- Create: `packages/thumbmark/**` (copied from upstream `v1.12.0`: `src/`, `e2e/`, `perf/`, `rollup.config.mjs`, `jest.config.js`, `jest.setup.js`, `tsconfig.json`, `tsconfig.test.json`, `playwright.config.ts`, `test.html`, `technical_details.md`)
- Create: `packages/thumbmark/LICENSE.upstream`, `packages/thumbmark/README.md`, `packages/thumbmark/UPSTREAM` (contains `v1.12.0`)
- Modify: `packages/thumbmark/package.json`

**Interfaces:**
- Produces: workspace package `@nazr/thumbmark` with scripts `build`, `test`, `test:e2e`, `lint`, `typecheck`; exports identical to upstream `src/index.ts`.

- [ ] **Step 1: Fetch and copy upstream**

```bash
git clone --depth 1 --branch v1.12.0 https://github.com/thumbmarkjs/thumbmarkjs.git /tmp/tm-upstream
mkdir -p packages/thumbmark
cp -R /tmp/tm-upstream/{src,e2e,perf,rollup.config.mjs,jest.config.js,jest.setup.js,tsconfig.json,tsconfig.test.json,playwright.config.ts,test.html,technical_details.md} packages/thumbmark/
cp /tmp/tm-upstream/LICENSE packages/thumbmark/LICENSE.upstream
echo v1.12.0 > packages/thumbmark/UPSTREAM
```

Do not copy upstream `package-lock.json`, `Makefile`, `.github`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, or any ESLint config.

- [ ] **Step 2: Rewrite `packages/thumbmark/package.json`**

Keep upstream `main`/`module`/`types`/`exports`/`files`/`type`/`keywords`/devDependencies. Change `name` to `@nazr/thumbmark`, `version` to `0.1.0`, `license` to `MIT`, `repository`/`homepage`/`bugs` to this repo, `description` to "Self-hostable browser fingerprinting client, a fork of ThumbmarkJS". Scripts: `build` (upstream's), `test` (`jest`), `test:e2e` (`playwright test`), `lint` (`biome check .`), `typecheck` (`tsc --noEmit -p tsconfig.test.json`). Add devDependency `tsx` `^4` (used by Task 11).

- [ ] **Step 3: Write `packages/thumbmark/README.md`**

Sections: what it is, attribution paragraph naming ThumbmarkJS and linking `LICENSE.upstream`, install, usage with `api_endpoint`, list of components (upstream 13 + 5 new), differences from upstream (bullet list matching Global Constraints), `pnpm upstream:diff` usage.

- [ ] **Step 4: Install, build, test**

Run: `pnpm install && pnpm --filter @nazr/thumbmark build && pnpm --filter @nazr/thumbmark test`
Expected: Rollup emits `dist/thumbmark.{cjs,esm.js,umd.js}` and `dist/thumbmark.esm.d.ts`; Jest passes with the same count upstream reports.

- [ ] **Step 5: Biome pass**

Run: `pnpm exec biome check packages/thumbmark --write` then `pnpm exec biome check packages/thumbmark`
Expected: second run reports no errors. If a rule fires on upstream code, prefer disabling that rule in the `packages/thumbmark/**` override over rewriting upstream code.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(thumbmark): import upstream thumbmarkjs v1.12.0 as @nazr/thumbmark"
```

---

### Task 3: Self-host endpoint defaults

**Files:**
- Modify: `packages/thumbmark/src/options.ts`, `packages/thumbmark/src/utils/log.ts`, `packages/thumbmark/src/utils/collect.ts`
- Delete: `packages/thumbmark/src/utils/experimental.ts`, `packages/thumbmark/src/utils/experimental.test.ts`
- Create: `packages/thumbmark/src/utils/endpoints.ts`, `packages/thumbmark/src/utils/endpoints.test.ts`
- Modify: `packages/thumbmark/src/utils/log.test.ts`, `packages/thumbmark/src/utils/collect.test.ts`, `packages/thumbmark/src/options.test.ts`

**Interfaces:**
- Produces: `resolveLogEndpoint(options: Pick<optionsInterface,'api_endpoint'>): string` and `resolveCollectEndpoint(options: Pick<optionsInterface,'api_endpoint'|'collect_endpoint'>): string` in `src/utils/endpoints.ts`.

- [ ] **Step 1: Write failing tests in `endpoints.test.ts`**

```ts
test.each([
  ['https://api.example.com', 'https://api.example.com/log'],
  ['https://api.example.com/', 'https://api.example.com/log'],
  ['https://api.example.com/nazr/', 'https://api.example.com/nazr/log'],
])('resolveLogEndpoint(%s)', (ep, want) => expect(resolveLogEndpoint({ api_endpoint: ep })).toBe(want));
test('resolveLogEndpoint falls back to hosted default', () =>
  expect(resolveLogEndpoint({})).toBe('https://api.thumbmarkjs.com/log'));
test('resolveCollectEndpoint prefers explicit collect_endpoint', () =>
  expect(resolveCollectEndpoint({ api_endpoint: 'https://a', collect_endpoint: 'https://c/b' })).toBe('https://c/b'));
test('resolveCollectEndpoint derives /beacon from api_endpoint', () =>
  expect(resolveCollectEndpoint({ api_endpoint: 'https://a/' })).toBe('https://a/beacon'));
test('resolveCollectEndpoint falls back to hosted default', () =>
  expect(resolveCollectEndpoint({})).toBe('https://collect.thumbmarkjs.com/beacon'));
```

- [ ] **Step 2: Run to verify failure**

Run: `pnpm --filter @nazr/thumbmark test -- endpoints`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement `endpoints.ts`** with the two functions; strip trailing slashes with a regex before joining.

- [ ] **Step 4: Wire `log.ts` and `collect.ts`**

`logThumbmarkData` uses `resolveLogEndpoint(options)` and sends `experimental: null` (remove the import and the fetch). `sendCollectBeacon` uses `resolveCollectEndpoint(options)`. In `options.ts` set `logging: false` in `defaultOptions`. Delete `experimental.ts` and its test. Update `log.test.ts` to drop the artifact mocking and assert `experimental` is `null` and the URL is `${api_endpoint}/log` when provided; update `collect.test.ts` to assert the derived `/beacon` URL; update `options.test.ts` if it asserts `logging` default.

- [ ] **Step 5: Run full test suite**

Run: `pnpm --filter @nazr/thumbmark test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(thumbmark): route log and beacon to api_endpoint, disable logging by default"
```

---

### Task 4: Type additions for nazr responses

**Files:**
- Modify: `packages/thumbmark/src/functions/api.ts`
- Modify: `packages/thumbmark/src/functions/api.test.ts`

**Interfaces:**
- Produces: `infoInterface.classification.private_relay?: boolean`, `infoInterface.uniqueness.visitors_sharing?: number`, `infoInterface.uniqueness.visitors_total?: number`, `infoInterface.signals` typed as `{ [name: string]: boolean | undefined; timezone_country_mismatch?: boolean; ua_tls_mismatch?: boolean }`; `hash` exported from `src/index.ts`.

- [ ] **Step 1: Write a failing type-level test** in `api.test.ts`: construct an `apiResponse` literal containing `classification.private_relay: true`, `uniqueness.visitors_sharing: 2`, `signals.ua_tls_mismatch: true`, and assert the parsed cache round-trips them (`setCachedApiResponse` then `getCachedApiResponse`).

- [ ] **Step 2: Run** `pnpm --filter @nazr/thumbmark typecheck` — Expected: FAIL on unknown properties.

- [ ] **Step 3: Extend the interfaces** in `api.ts` as listed above, and add `hash` to the export list in `src/index.ts` (import from `./utils/hash`).

- [ ] **Step 4: Run** `pnpm --filter @nazr/thumbmark typecheck && pnpm --filter @nazr/thumbmark test -- api` — Expected: PASS.

- [ ] **Step 5: Commit** `git commit -am "feat(thumbmark): add private_relay, uniqueness counts and signals types"`

---

### Task 5: `webgpu` component

**Files:**
- Create: `packages/thumbmark/src/components/webgpu/index.ts`, `packages/thumbmark/src/components/webgpu/index.test.ts`
- Modify: `packages/thumbmark/src/factory.ts` (register `'webgpu': getWebGPU`), `packages/thumbmark/package.json` (`files` entry)

**Interfaces:**
- Produces: `export default function getWebGPU(): Promise<componentInterface | null>` returning `{ supported: boolean, vendor?: string, architecture?: string, device?: string, description?: string, features?: string[], limits?: { maxTextureDimension2D, maxBufferSize, maxComputeWorkgroupSizeX, maxBindGroups, maxStorageBufferBindingSize } }`. Feature list sorted. `limits` values are numbers.

- [ ] **Step 1: Write failing tests**

```ts
test('resolves null when navigator.gpu is absent', ...)                 // delete (navigator as any).gpu
test('resolves { supported: false } when requestAdapter resolves null', ...)
test('resolves { supported: false } when requestAdapter rejects', ...)
test('reports adapter info, sorted features and selected limits', ...)  // mock adapter.info {vendor:'apple',architecture:'metal-3'}, features Set(['b','a']), limits {...}
```

Mock `navigator.gpu = { requestAdapter: jest.fn() }` via `Object.defineProperty(navigator, 'gpu', { value, configurable: true })`.

- [ ] **Step 2: Run** `pnpm --filter @nazr/thumbmark test -- webgpu` — Expected: FAIL, module not found.

- [ ] **Step 3: Implement** using `adapter.info` (fall back to `adapter.requestAdapterInfo?.()` for older Chrome), `Array.from(adapter.features).sort()`, and the five limits. Wrap in try/catch returning `{ supported: false }`.

- [ ] **Step 4: Register** in `factory.ts` and add `src/components/webgpu/index.ts` to `package.json` `files`.

- [ ] **Step 5: Run** `pnpm --filter @nazr/thumbmark test` — Expected: PASS, including `packaging.test.ts`.

- [ ] **Step 6: Commit** `git add -A && git commit -m "feat(thumbmark): add webgpu component"`

---

### Task 6: `clienthints` component

**Files:**
- Create: `packages/thumbmark/src/components/clienthints/index.ts`, `.../index.test.ts`
- Modify: `factory.ts`, `package.json` `files`, `src/options.ts` (stabilization rule)

**Interfaces:**
- Produces: `getClientHints(): Promise<componentInterface | null>` returning `{ brands: string[] /* "Brand/Version" sorted */, mobile: boolean, platform: string, architecture?: string, bitness?: string, model?: string, platformVersion?: string, fullVersionList?: string[], wow64?: boolean }`. High-entropy keys requested: `architecture`, `bitness`, `model`, `platformVersion`, `fullVersionList`, `wow64`.

- [ ] **Step 1: Write failing tests**

```ts
test('resolves null without navigator.userAgentData', ...)
test('resolves low-entropy fields when getHighEntropyValues rejects', ...)
test('merges high-entropy values and sorts brand lists', ...)
```

- [ ] **Step 2: Run** `... test -- clienthints` — Expected: FAIL.

- [ ] **Step 3: Implement**; `fullVersionList` formatted like `brands`. Add stabilization rule in `options.ts` under `'private'`: `{ exclude: ['clienthints'], browsers: ['brave'] }`.

- [ ] **Step 4: Register**, run full tests — Expected: PASS.

- [ ] **Step 5: Commit** `git add -A && git commit -m "feat(thumbmark): add clienthints component"`

---

### Task 7: `clientrects` component

**Files:**
- Create: `packages/thumbmark/src/components/clientrects/index.ts`, `.../index.test.ts`
- Modify: `factory.ts`, `package.json` `files`, `src/options.ts`

**Interfaces:**
- Produces: `getClientRects(): Promise<componentInterface | null>` returning `{ rects: string[] /* "x,y,w,h" per probe, 2 decimals */, hash: string /* hash() of rects joined by '|' */ }`.

Probe: an off-screen container (`position:absolute; left:-9999px; top:-9999px; visibility:hidden`) appended to `document.body` holding five elements with fixed inline styles: a `div` 123.4px wide with 1.7px border; a `span` with text "nazr clientrects probe" in `font: 16.3px serif`; a rotated `div` (`transform: rotate(13deg)`, 80x40px); an `em` with `font-size: 1.31em` inside a 14px serif `p`; and an `svg` 50.5x30.5 with a `rect`. Read `getBoundingClientRect()` of each, remove the container in `finally`.

- [ ] **Step 1: Write failing tests**: resolves `null` when `document.body` is missing; resolves five rect strings with the `x,y,w,h` shape and a 32-char hex hash; container is removed from the DOM after resolution.

- [ ] **Step 2: Run** — Expected: FAIL.

- [ ] **Step 3: Implement**; reuse `hash` from `src/utils/hash`. Add stabilization rule under `'private'`: `{ exclude: ['clientrects'], browsers: ['firefox', 'brave'] }`.

- [ ] **Step 4: Register, run full tests** — Expected: PASS.

- [ ] **Step 5: Commit** `git add -A && git commit -m "feat(thumbmark): add clientrects component"`

---

### Task 8: `mediaqueries` component

**Files:**
- Create: `packages/thumbmark/src/components/mediaqueries/index.ts`, `.../index.test.ts`
- Modify: `factory.ts`, `package.json` `files`

**Interfaces:**
- Produces: `getMediaQueries(): Promise<componentInterface | null>` returning `{ colorGamut: 'srgb'|'p3'|'rec2020'|'none', dynamicRange: 'standard'|'high'|'none', videoDynamicRange: 'standard'|'high'|'none', colorScheme: 'light'|'dark'|'none', displayMode: 'browser'|'minimal-ui'|'standalone'|'fullscreen'|'none', reducedData: 'reduce'|'no-preference'|'none', dprBucket: string }`.

`dprBucket` is `window.devicePixelRatio` rounded to 2 decimals as a string. Upstream's `screen.mediaMatches` already covers hover, pointer, contrast, reduced-motion, forced-colors, inverted-colors, update, scripting, so do not repeat those. For each key, the first matching value wins; `'none'` when nothing matches.

- [ ] **Step 1: Write failing tests**: resolves `null` when `window.matchMedia` is undefined; resolves `null` when `matchMedia` throws; picks the highest gamut that matches (mock `(color-gamut: p3)` and `(color-gamut: srgb)` true, `rec2020` false → `'p3'`... note: order values widest-first: `rec2020`, `p3`, `srgb`); `dprBucket` is `'2'` for DPR 2.

- [ ] **Step 2: Run** — Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Register, run full tests** — Expected: PASS.

- [ ] **Step 5: Commit** `git add -A && git commit -m "feat(thumbmark): add mediaqueries component"`

---

### Task 9: `privacy` component

**Files:**
- Create: `packages/thumbmark/src/components/privacy/index.ts`, `.../index.test.ts`
- Modify: `factory.ts`, `package.json` `files`

**Interfaces:**
- Produces: `getPrivacy(): Promise<componentInterface>` returning `{ doNotTrack: 'unspecified'|'0'|'1', globalPrivacyControl: boolean, webdriver: boolean }`. `webdriver` is `navigator.webdriver === true`; the Go classifier reads it from `components.privacy.webdriver`.

- [ ] **Step 1: Write failing tests**: `doNotTrack` reads `navigator.doNotTrack`, then `window.doNotTrack`, then `navigator.msDoNotTrack`, mapping `null`/`undefined`/`'unspecified'` to `'unspecified'` and `'yes'` to `'1'`; `globalPrivacyControl` is `true` only when `navigator.globalPrivacyControl === true`; `webdriver` is `true` only when `navigator.webdriver === true` (jsdom default `false`).

- [ ] **Step 2: Run** — Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Register, run full tests** — Expected: PASS.

- [ ] **Step 5: Commit** `git add -A && git commit -m "feat(thumbmark): add privacy component"`

---

### Task 10: Upstream diff script and e2e sanity

**Files:**
- Create: `packages/thumbmark/scripts/upstream-diff.sh`
- Modify: `packages/thumbmark/package.json` (script `upstream:diff`)
- Modify: `packages/thumbmark/e2e/*.spec.ts` only if they reference removed experimental code

**Interfaces:**
- Produces: `pnpm --filter @nazr/thumbmark upstream:diff [tag]` printing a unified diff of upstream `src/` vs ours, excluding files that only exist here (`src/components/{webgpu,clienthints,clientrects,mediaqueries,privacy}`, `src/utils/endpoints.ts`).

- [ ] **Step 1: Write the script**: `set -euo pipefail`; tag defaults to contents of `UPSTREAM`; shallow-clone into `mktemp -d`; `diff -ruN --exclude` list above `"$tmp/src" "$PKG/src"`; exit 0 even when diff is non-empty.

- [ ] **Step 2: Run** `pnpm --filter @nazr/thumbmark upstream:diff` — Expected: a diff that touches only `options.ts`, `factory.ts`, `functions/api.ts`, `utils/log.ts`, `utils/collect.ts`, their tests, and the deleted `experimental*.ts`.

- [ ] **Step 3: Run Playwright once** `pnpm --filter @nazr/thumbmark exec playwright install chromium && pnpm --filter @nazr/thumbmark test:e2e` — Expected: PASS. Fix any spec that imported `experimental`.

- [ ] **Step 4: Commit** `git add -A && git commit -m "chore(thumbmark): add upstream diff script"`

---

### Task 11: Golden fixture generator for the Go API

**Files:**
- Create: `packages/thumbmark/scripts/fixtures.ts` (pure `buildFixtures()`), `packages/thumbmark/scripts/gen-fixtures.ts` (writes files)
- Create: `apps/api/testdata/fixtures/stringify.json`, `apps/api/testdata/fixtures/numbers.json`, `apps/api/testdata/fixtures/filter.json`, `apps/api/testdata/fixtures/README.md`
- Modify: `packages/thumbmark/package.json` (script `fixtures` → `tsx scripts/gen-fixtures.ts`)
- Create: `packages/thumbmark/scripts/gen-fixtures.test.ts`

**Interfaces:**
- Produces three JSON files consumed by Plan 2 Tasks 2 and 3:
  - `stringify.json`: `[{ "name": string, "input": any, "stringified": string, "hash": string }]` where `hash = hash(stringified)` from `src/utils/hash`.
  - `numbers.json`: `[{ "value": number, "expected": string }]` where `expected = String(value)`.
  - `filter.json`: `[{ "name": string, "components": object, "options": { include?, exclude?, stabilize? }, "filtered": object }]` where `filtered = filterThumbmarkData(components, options)`.

- [ ] **Step 1: Write a failing test** `gen-fixtures.test.ts` that imports `buildFixtures()` from `scripts/fixtures.ts` (no `import.meta` there, so ts-jest can load it) and asserts: `stringify` has at least 12 cases including names `nested-sorted-keys`, `unicode-keys-and-values`, `floats`, `integers-large`, `arrays-with-nulls`, `empty-objects-pruned`, `negative-zero`, `exponent-small`, `exponent-large`, `booleans`, `server-merge-example`, `escape-chars`; `numbers` includes values `0.1`, `1e21`, `1e-7`, `123456789012345680000`, `-0`, `5e-324`, `1.7976931348623157e308`, `0.000001`, `100`, `1.5`; `filter` includes a case with `stabilize: ['private']` and `components.system.browser.name = 'Firefox'` whose output lacks `canvas` and `fonts`, and a case with `include: ['tls.ja4']` plus `exclude: ['tls']` whose output keeps `tls.ja4` only; and `JSON.stringify(buildFixtures()) === JSON.stringify(buildFixtures())`.

- [ ] **Step 2: Run** `pnpm --filter @nazr/thumbmark test -- gen-fixtures` — Expected: FAIL.

- [ ] **Step 3: Implement `fixtures.ts`** exporting `buildFixtures()`, and `gen-fixtures.ts` as the entry point that writes the three files to `../../apps/api/testdata/fixtures/` with `JSON.stringify(x, null, 2) + '\n'`. The `server-merge-example` case must be a realistic merged component set: upstream-shaped client components (at least `system`, `screen`, `locales`) plus `tls`, `h2`, `header`, `ip` objects shaped as in spec section 5.

- [ ] **Step 4: Write `fixtures/README.md`** stating the files are generated by `pnpm --filter @nazr/thumbmark fixtures` and must not be edited by hand.

- [ ] **Step 5: Generate twice and verify determinism**

Run: `pnpm --filter @nazr/thumbmark fixtures && sha256sum apps/api/testdata/fixtures/*.json > /tmp/a && pnpm --filter @nazr/thumbmark fixtures && sha256sum apps/api/testdata/fixtures/*.json | diff /tmp/a -`
Expected: no diff output.

- [ ] **Step 6: Run full workspace checks**

Run: `pnpm lint && pnpm typecheck && pnpm test`
Expected: all PASS.

- [ ] **Step 7: Commit** `git add -A && git commit -m "feat(thumbmark): add golden fixture generator for the Go API"`
