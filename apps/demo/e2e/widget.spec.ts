import { execFileSync } from "node:child_process";
import { expect, type Page, test } from "@playwright/test";
import { createLocalJWKSet, type JSONWebKeySet, jwtVerify } from "jose";
import { apiKey, endpoint } from "./helpers";

// The widget nonce is the challenge id, a ULID.
const ULID = /^[0-9A-HJKMNP-TV-Z]{26}$/;

interface WidgetSummary {
  window_days: number;
  reports: number;
  matched: number;
  unmatched: number;
  ip_mismatch: number;
  ja4_mismatch: number;
  ja4_unknown: number;
  ua_mismatch: number;
  pass: number;
  inconclusive: number;
  pow_failed: number;
  verified: number;
  replayed: number;
}

interface Siteverify {
  success: boolean;
  hostname?: string;
  verdict?: string;
  correlation?: { matched: boolean; ip_match: boolean; ja4_match: boolean; ua_match: boolean };
  error_codes: string[];
}

// Playwright's Chromium sets navigator.webdriver, which classifies as a bot and
// yields "inconclusive"; a "pass" (and so a token) needs the flag hidden.
test.use({ launchOptions: { args: ["--disable-blink-features=AutomationControlled"] } });

function admin<T>(path: string): T {
  // Ignore the self-signed certificate, as global-setup's readiness probe does.
  const out = execFileSync(
    "curl",
    [
      "-ksS",
      "--fail",
      "-H",
      `Authorization: Bearer ${process.env.NAZR_E2E_ADMIN_TOKEN}`,
      `${endpoint()}${path}`,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  ).toString();
  return JSON.parse(out) as T;
}

function e2eKeyId(): string {
  // Match the prefix too: a reused NAZR_E2E_DATABASE_URL holds older "e2e" keys.
  const keys = admin<{ id: string; label: string; prefix: string }[]>("/admin/keys");
  const key = keys.find((k) => k.label === "e2e" && apiKey().startsWith(`nzr_${k.prefix}`));
  expect(key).toBeDefined();
  return key?.id as string;
}

/** POSTs to siteverify without --fail so error statuses still yield their body. */
function siteverify(secret: string, token: string): { status: number; body: Siteverify } {
  const out = execFileSync(
    "curl",
    [
      "-ksS",
      "-H",
      "content-type: application/json",
      "-d",
      JSON.stringify({ secret, token }),
      "-w",
      "\n%{http_code}",
      `${endpoint()}/widget/v1/siteverify`,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  ).toString();
  const nl = out.lastIndexOf("\n");
  return { status: Number(out.slice(nl + 1)), body: JSON.parse(out.slice(0, nl)) as Siteverify };
}

async function openHost(page: Page): Promise<void> {
  const q = new URLSearchParams({ key: apiKey(), endpoint: endpoint() });
  await page.goto(`/widget-host.html?${q}`);
  await page.waitForFunction(
    () => (window as unknown as { __nazrHostDone?: unknown }).__nazrHostDone != null,
    undefined,
    { timeout: 30_000 },
  );
}

test("widget report correlates with the host page's /thumbmark call", async ({ page }) => {
  const frameResponse = page.waitForResponse((r) => r.url().includes("/widget/v1/frame?"));
  const reportResponse = page.waitForResponse(
    (r) => r.url().endsWith("/widget/report") && r.request().method() === "POST",
  );
  const apiResponse = page.waitForResponse(
    (r) => r.url().endsWith("/thumbmark") && r.request().method() === "POST",
  );
  await openHost(page);

  const frame = await frameResponse;
  expect(frame.status()).toBe(200);
  expect((await frame.allHeaders())["content-security-policy"]).toMatch(/^frame-ancestors \*/);
  expect((await reportResponse).status()).toBe(200);
  const api = await apiResponse;
  expect(api.status()).toBe(200);

  const state = await page.evaluate(() => {
    const w = window as unknown as {
      __nazrWidget?: { nonce: string };
      __nazrHostDone: { nonce: string; thumbmark: string; error?: unknown };
    };
    return {
      iframe: document.querySelector("iframe") === null,
      widgetNonce: w.__nazrWidget?.nonce,
      done: w.__nazrHostDone,
    };
  });
  // The frame lives in a closed shadow root, invisible to the host document.
  expect(state.iframe).toBe(true);
  expect(state.done.error).toBeUndefined();
  expect(state.done.thumbmark).toMatch(/^[0-9a-f]{32}$/);
  expect(state.widgetNonce).toMatch(ULID);
  expect(state.done.nonce).toBe(state.widgetNonce);
  expect((api.request().postDataJSON() as { nonce?: string }).nonce).toBe(state.widgetNonce);

  const keyId = e2eKeyId();

  let summary: WidgetSummary | undefined;
  await expect
    .poll(
      () => {
        summary = admin<WidgetSummary>(`/admin/keys/${keyId}/widget`);
        return summary.matched;
      },
      { timeout: 10_000 },
    )
    .toBeGreaterThanOrEqual(1);
  // Terminate mode observes JA4 on both connections, so nothing is unknown.
  expect(summary).toMatchObject({
    ip_mismatch: 0,
    ja4_mismatch: 0,
    ua_mismatch: 0,
    ja4_unknown: 0,
  });
});

test("widget issues a token that verifies against the JWKS and siteverify once", async ({
  page,
}) => {
  const reportResponse = page.waitForResponse(
    (r) => r.url().endsWith("/widget/report") && r.request().method() === "POST",
  );
  await openHost(page);
  await page.waitForFunction(
    () => (window as unknown as { __nazrToken?: string }).__nazrToken != null,
    undefined,
    { timeout: 30_000 },
  );

  const report = await reportResponse;
  expect(report.status()).toBe(200);
  const outcome = (await report.json()) as { verdict: string; token?: string };
  expect(outcome.verdict).toBe("pass");

  const state = await page.evaluate(() => {
    const w = window as unknown as {
      __nazrWidget?: { nonce?: string; token?: string };
      __nazrToken?: string;
      __nazrHostDone: { error?: unknown };
    };
    const input = document.querySelector<HTMLInputElement>("form#nazr-form input[name=nazr-token]");
    return {
      token: w.__nazrToken as string,
      widgetToken: w.__nazrWidget?.token,
      nonce: w.__nazrWidget?.nonce,
      input: input?.value,
      inputType: input?.type,
      hostError: w.__nazrHostDone.error,
    };
  });
  expect(state.hostError).toBeUndefined();
  expect(state.token).toBe(outcome.token);
  expect(state.widgetToken).toBe(state.token);
  expect(state.inputType).toBe("hidden");
  expect(state.input).toBe(state.token);

  const keyId = e2eKeyId();
  const jwks = JSON.parse(
    execFileSync("curl", ["-ksS", "--fail", `${endpoint()}/widget/v1/jwks.json`], {
      stdio: ["ignore", "pipe", "pipe"],
    }).toString(),
  ) as JSONWebKeySet;
  const { payload, protectedHeader } = await jwtVerify(state.token, createLocalJWKSet(jwks), {
    issuer: endpoint(),
    audience: keyId,
    algorithms: ["ES256"],
  });
  expect(protectedHeader.alg).toBe("ES256");
  expect(payload.jti).toBe(state.nonce);
  expect(payload.verdict).toBe("pass");
  expect(payload.hostname).toBe("http://localhost:4173");

  const secret = process.env.NAZR_E2E_SECRET as string;
  const first = siteverify(secret, state.token);
  expect(first.status).toBe(200);
  expect(first.body).toMatchObject({
    success: true,
    hostname: "http://localhost:4173",
    verdict: "pass",
    correlation: { matched: true, ip_match: true, ja4_match: true, ua_match: true },
    error_codes: [],
  });

  const second = siteverify(secret, state.token);
  expect(second.body.success).toBe(false);
  expect(second.body.error_codes).toEqual(["replayed"]);

  const wrong = siteverify(`nzs_${"a".repeat(52)}`, state.token);
  expect(wrong.status).toBe(401);
  expect(wrong.body.success).toBe(false);
  expect(wrong.body.error_codes).toEqual(["invalid-secret"]);

  const summary = admin<WidgetSummary>(`/admin/keys/${keyId}/widget`);
  expect(summary.pass).toBeGreaterThanOrEqual(1);
  expect(summary.verified).toBeGreaterThanOrEqual(1);
  expect(summary.replayed).toBeGreaterThanOrEqual(1);
});
