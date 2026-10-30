export interface NazrWidget {
  nonce: string;
  ready: Promise<{ nonce: string }>;
}

declare global {
  interface Window {
    __nazrWidget?: NazrWidget;
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
    const nonce = script.dataset.nonce || win.crypto?.randomUUID?.();
    if (!nonce) return;

    const src = new URL("/widget/v1/frame", new URL(script.src).origin);
    src.search = new URLSearchParams({ k: apiKey, n: nonce }).toString();

    win.__nazrWidget = { nonce, ready: Promise.resolve({ nonce }) };

    const host = doc.createElement("div");
    const root = host.attachShadow({ mode: "closed" });
    const iframe = doc.createElement("iframe");
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
