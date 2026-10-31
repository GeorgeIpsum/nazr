import type { FrameMessage } from "./frame";

export interface NazrWidget {
  ready: Promise<{ nonce: string }>;
  nonce?: string;
  token?: string;
  reset(): void;
}

declare global {
  interface Window {
    __nazrWidget?: NazrWidget;
  }
}

function decodeExp(token: string): number | undefined {
  try {
    const payload = token.split(".")[1];
    if (!payload) return undefined;
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const exp = JSON.parse(atob(b64.padEnd(Math.ceil(b64.length / 4) * 4, "="))).exp;
    return typeof exp === "number" && Number.isFinite(exp) ? exp : undefined;
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

    const fieldName = script.dataset.responseFieldName || "nazr-token";
    const form = script.closest("form");
    let input: HTMLInputElement | undefined;
    let timer: number | undefined;
    let resolveReady: (v: { nonce: string }) => void = () => {};
    let resolved = false;

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
      if (!input) {
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
    const widget: NazrWidget = {
      ready: new Promise((r) => {
        resolveReady = r;
      }),
      reset() {
        win.clearTimeout(timer);
        timer = undefined;
        widget.token = undefined;
        if (input) input.value = "";
        iframe.src = src.href;
      },
    };
    win.__nazrWidget = widget;

    win.addEventListener("message", (event: MessageEvent) => {
      try {
        if (event.source !== iframe.contentWindow || event.origin !== origin) return;
        const msg = event.data as FrameMessage | null;
        if (!msg || typeof msg !== "object" || typeof msg.type !== "string") return;
        if (!msg.type.startsWith("nazr:")) return;
        if (msg.type === "nazr:challenge") {
          widget.nonce = msg.id;
          if (!resolved) {
            resolved = true;
            resolveReady({ nonce: msg.id });
          }
        } else if (msg.type === "nazr:token") {
          win.clearTimeout(timer);
          timer = undefined;
          widget.token = msg.token;
          setInput(msg.token);
          callGlobal(script.dataset.callback, msg.token);
          const exp = decodeExp(msg.token);
          if (exp !== undefined) {
            timer = win.setTimeout(
              () => {
                timer = undefined;
                widget.token = undefined;
                if (input) input.value = "";
                callGlobal(script.dataset.expiredCallback);
                widget.reset();
              },
              Math.max(0, exp * 1000 - Date.now()),
            );
          }
        } else if (msg.type === "nazr:error") {
          callGlobal(script.dataset.errorCallback, msg.reason);
        }
      } catch {
        // A bad message never throws.
      }
    });

    const host = doc.createElement("div");
    const root = host.attachShadow({ mode: "closed" });
    iframe.src = src.href;
    iframe.width = "0";
    iframe.height = "0";
    iframe.setAttribute("style", "position:absolute;width:0;height:0;border:0");
    iframe.setAttribute("aria-hidden", "true");
    iframe.title = "nazr";
    root.appendChild(iframe);

    if (doc.body) {
      doc.body.appendChild(host);
    } else {
      doc.addEventListener("DOMContentLoaded", () => doc.body?.appendChild(host), { once: true });
    }
  } catch {
    // Never break the host page.
  }
}
