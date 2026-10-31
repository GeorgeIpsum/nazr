import type { FrameMessage } from "./frame";

export interface NazrWidget {
  ready: Promise<{ nonce: string }>;
  nonce?: string;
  token?: string;
  /** Read-only for hosts: "pending" | "pass" | "interactive" | "failed". */
  state: "pending" | "pass" | "interactive" | "failed";
  reset(): void;
}

declare global {
  interface Window {
    __nazrWidget?: NazrWidget;
  }
}

const readyTimeoutMs = 10_000;
const expiryMarginMs = 5_000;
const minExpiryMs = 10_000;
const maxTimerMs = 2_147_483_647;

/**
 * How long after arrival the token should be treated as expired, from its own
 * `exp - iat` so a skewed device clock does not matter. Undefined when either
 * claim is missing or not a number.
 */
function expiryDelay(token: string): number | undefined {
  try {
    const payload = token.split(".")[1];
    if (!payload) return undefined;
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const { iat, exp } = JSON.parse(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "=")));
    if (typeof iat !== "number" || !Number.isFinite(iat)) return undefined;
    if (typeof exp !== "number" || !Number.isFinite(exp)) return undefined;
    const delay = (exp - iat) * 1000 - expiryMarginMs;
    return Math.min(Math.max(delay, minExpiryMs), maxTimerMs);
  } catch {
    return undefined;
  }
}

/**
 * Mounts the nazr frame in a closed shadow root on the host page. Reads its
 * configuration from the script tag that loaded it, so it must run
 * synchronously at the top level of the loader script. Never throws.
 */
export function mountWidget(doc: Document, win: Window & typeof globalThis): void {
  try {
    if (win.__nazrWidget) return;
    const script = doc.currentScript;
    if (!(script instanceof win.HTMLScriptElement)) return;
    const apiKey = script.dataset.apiKey;
    if (!apiKey) return;
    if (script.dataset.nonce !== undefined) {
      console.warn("nazr: data-nonce is no longer supported and is ignored");
    }

    const origin = new URL(script.src).origin;
    const src = new URL("/widget/v1/frame", origin);
    src.search = new URLSearchParams({ k: apiKey }).toString();

    let container: Element | null = null;
    if (script.dataset.container) {
      try {
        container = doc.querySelector(script.dataset.container);
      } catch {
        container = null;
      }
    }
    if (container) src.searchParams.set("i", "1");

    const fieldName = script.dataset.responseFieldName || "nazr-token";
    const form = script.closest("form");
    let input: HTMLInputElement | undefined;
    let timer: number | undefined;
    let resolveReady: (v: { nonce: string }) => void = () => {};
    let resolved = false;
    let readyTimer: number | undefined;

    const callGlobal = (attr: string | undefined, arg?: string) => {
      try {
        const fn = attr ? (win as unknown as Record<string, unknown>)[attr] : undefined;
        if (typeof fn === "function") fn(arg);
      } catch (e) {
        console.error("nazr: callback threw", e);
      }
    };
    const setInput = (value: string) => {
      if (!form) return;
      if (!input?.isConnected) {
        input = Array.from(form.querySelectorAll("input")).find((i) => i.name === fieldName);
        if (!input) {
          input = doc.createElement("input");
          input.type = "hidden";
          input.name = fieldName;
          form.appendChild(input);
        }
      }
      input.value = value;
    };

    const iframe = doc.createElement("iframe");
    const collapse = () => {
      iframe.width = "0";
      iframe.height = "0";
      iframe.style.position = "absolute";
      iframe.style.width = "0";
      iframe.style.height = "0";
      iframe.style.border = "0";
      iframe.setAttribute("aria-hidden", "true");
      iframe.title = "nazr";
    };
    const expand = () => {
      iframe.width = "300";
      iframe.height = "65";
      iframe.style.position = "static";
      iframe.style.width = "300px";
      iframe.style.height = "65px";
      iframe.style.border = "0";
      iframe.removeAttribute("aria-hidden");
      iframe.title = "nazr verification";
    };
    const widget: NazrWidget = {
      state: "pending",
      ready: new Promise((r) => {
        resolveReady = r;
      }),
      reset() {
        win.clearTimeout(timer);
        timer = undefined;
        widget.token = undefined;
        if (input) input.value = "";
        widget.state = "pending";
        collapse();
        iframe.src = src.href;
      },
    };
    win.__nazrWidget = widget;

    // If the frame never sends a challenge, settle ready anyway so the host's
    // fingerprint call proceeds uncorrelated.
    readyTimer = win.setTimeout(() => {
      readyTimer = undefined;
      if (resolved) return;
      resolved = true;
      widget.state = "failed";
      resolveReady({ nonce: "" });
      callGlobal(script.dataset.errorCallback, "network");
    }, readyTimeoutMs);

    win.addEventListener("message", (event: MessageEvent) => {
      try {
        if (event.source !== iframe.contentWindow || event.origin !== origin) return;
        const msg = event.data as FrameMessage | null;
        if (!msg || typeof msg !== "object" || typeof msg.type !== "string") return;
        if (!msg.type.startsWith("nazr:")) return;
        if (msg.type === "nazr:challenge") {
          widget.nonce = msg.id;
          win.clearTimeout(readyTimer);
          readyTimer = undefined;
          if (!resolved) {
            resolved = true;
            resolveReady({ nonce: msg.id });
          }
        } else if (msg.type === "nazr:interactive") {
          widget.state = "interactive";
          expand();
          callGlobal(script.dataset.interactiveCallback);
        } else if (msg.type === "nazr:token") {
          if (widget.state !== "interactive") widget.state = "pass";
          win.clearTimeout(timer);
          timer = undefined;
          widget.token = msg.token;
          setInput(msg.token);
          callGlobal(script.dataset.callback, msg.token);
          const delay = expiryDelay(msg.token);
          if (delay !== undefined) {
            timer = win.setTimeout(() => {
              timer = undefined;
              widget.token = undefined;
              if (input) input.value = "";
              callGlobal(script.dataset.expiredCallback);
              widget.reset();
            }, delay);
          }
        } else if (msg.type === "nazr:error") {
          widget.state = "failed";
          callGlobal(script.dataset.errorCallback, msg.reason);
        }
      } catch {
        // A bad message never throws.
      }
    });

    const host = doc.createElement("div");
    const root = host.attachShadow({ mode: "closed" });
    iframe.src = src.href;
    collapse();
    root.appendChild(iframe);

    if (container) {
      container.appendChild(host);
    } else if (doc.body) {
      doc.body.appendChild(host);
    } else {
      doc.addEventListener("DOMContentLoaded", () => doc.body?.appendChild(host), { once: true });
    }
  } catch {
    // Never break the host page.
  }
}
