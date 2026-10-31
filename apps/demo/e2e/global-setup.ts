import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const apiDir = join(root, "apps/api");
const bin = join(apiDir, "bin/nazr");
const compose = join(root, "deploy/compose/docker-compose.yml");
const ENDPOINT = "https://127.0.0.1:8443";
const widgetDir = join(root, "packages/widget/dist");
const DEFAULT_DB = "postgres://nazr:nazr@localhost:5432/nazr?sslmode=disable";

function portInUse(port: number): Promise<boolean> {
  return new Promise((res) => {
    const s = net.connect({ port, host: "127.0.0.1" });
    s.once("connect", () => {
      s.destroy();
      res(true);
    });
    s.once("error", () => res(false));
  });
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  let startedCompose = false;
  let api: ChildProcess | undefined;
  const tmp = mkdtempSync(join(tmpdir(), "nazr-e2e-"));

  const teardown = async (): Promise<void> => {
    if (api && api.exitCode === null) {
      api.kill("SIGTERM");
      await new Promise<void>((r) => {
        const t = setTimeout(() => {
          api?.kill("SIGKILL");
          r();
        }, 5000);
        api?.once("exit", () => {
          clearTimeout(t);
          r();
        });
      });
    }
    if (startedCompose) {
      execFileSync("docker", ["compose", "-f", compose, "--profile", "dev", "down", "-v"], {
        stdio: "inherit",
      });
    }
    rmSync(tmp, { recursive: true, force: true });
  };

  try {
    if (!existsSync(join(widgetDir, "manifest.json"))) {
      throw new Error(
        `${widgetDir} is missing; run \`pnpm build --filter=@nazr/widget\` before the demo e2e`,
      );
    }

    let dbUrl = process.env.NAZR_E2E_DATABASE_URL;
    if (!dbUrl) {
      if (await portInUse(5432)) {
        throw new Error(
          "NAZR_E2E_DATABASE_URL is unset and something already listens on 5432; set NAZR_E2E_DATABASE_URL explicitly",
        );
      }
      execFileSync(
        "docker",
        [
          "compose",
          "-f",
          compose,
          "--profile",
          "dev",
          "up",
          "-d",
          "--wait",
          "postgres",
          "postgres-dev-port",
        ],
        { stdio: "inherit" },
      );
      startedCompose = true;
      dbUrl = DEFAULT_DB;
    }

    if (!existsSync(bin)) {
      execFileSync("go", ["build", "-o", "bin/nazr", "./cmd/nazr"], {
        cwd: apiDir,
        stdio: "inherit",
      });
    }

    const cert = join(tmp, "cert.pem");
    const key = join(tmp, "key.pem");
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-keyout",
        key,
        "-out",
        cert,
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-days",
        "1",
      ],
      { stdio: "ignore" },
    );

    const env = {
      ...process.env,
      NAZR_DATABASE_URL: dbUrl,
      NAZR_TLS_MODE: "terminate",
      NAZR_TLS_CERT_FILE: cert,
      NAZR_TLS_KEY_FILE: key,
      NAZR_LISTEN_ADDR: "127.0.0.1:8443",
      NAZR_HTTP_ADDR: "off", // empty would fall back to the :80 default
      NAZR_METRICS_ADDR: "127.0.0.1:19090",
      NAZR_DATA_DIR: join(tmp, "data"),
      NAZR_LISTS_DISABLE: "maxmind,apple,tor,datacenter,vpn,ja4db",
      NAZR_AUTO_MIGRATE: "true",
      NAZR_CORS_ORIGINS: "*",
      NAZR_LOG_FORMAT: "text",
      NAZR_ADMIN_TOKEN: "e2e-admin",
      NAZR_WIDGET_DIR: widgetDir,
      NAZR_POW_BITS: "12",
      // Any danger point makes a report inconclusive, so the interactive e2e can
      // earn one by dropping a single header.
      NAZR_WIDGET_PASS_MAX_DANGER: "0",
    };
    execFileSync("mkdir", ["-p", env.NAZR_DATA_DIR]);

    api = spawn(bin, ["serve"], { env, stdio: ["ignore", "inherit", "inherit"] });

    const deadline = Date.now() + 60_000;
    for (;;) {
      if (api.exitCode !== null) throw new Error("API process exited during startup");
      try {
        // Ignore the self-signed certificate for the readiness probe only.
        const out = execFileSync(
          "curl",
          ["-ksS", "-o", "/dev/null", "-w", "%{http_code}", `${ENDPOINT}/readyz`],
          {
            stdio: ["ignore", "pipe", "ignore"],
          },
        ).toString();
        if (out === "200") break;
      } catch {
        // not up yet
      }
      if (Date.now() > deadline) throw new Error("API did not become ready in 60s");
      await new Promise((r) => setTimeout(r, 500));
    }

    const created = execFileSync(bin, ["keys", "create", "--label", "e2e"], { env }).toString();
    const lines = created.split("\n");
    const apiKey = lines[0].trim();
    if (!apiKey) throw new Error("keys create printed no key");
    const secret = (lines[1] ?? "").trim();
    if (!/^nzs_[a-z2-7]{52}$/.test(secret)) throw new Error("keys create printed no widget secret");
    process.env.NAZR_E2E_SECRET = secret;
    process.env.NAZR_E2E_KEY = apiKey;
    process.env.NAZR_E2E_ENDPOINT = ENDPOINT;
    process.env.NAZR_E2E_ADMIN_TOKEN = "e2e-admin";
  } catch (e) {
    await teardown();
    throw e;
  }
  return teardown;
}
