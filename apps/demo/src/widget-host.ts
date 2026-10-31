import { getThumbmark } from "@nazr/thumbmark";

interface HostDone {
  nonce: string;
  thumbmark: string;
  error?: unknown;
}

declare global {
  interface Window {
    __nazrWidget?: {
      ready: Promise<{ nonce: string }>;
      nonce?: string;
      token?: string;
      reset(): void;
    };
    __nazrHostDone?: HostDone;
    __nazrToken?: string;
    __nazrOnToken?: (t: string) => void;
  }
}

const q = new URLSearchParams(location.search);
const apiKey = q.get("key") ?? "";
const endpoint = (q.get("endpoint") ?? "").replace(/\/+$/, "");
const status = document.getElementById("status") as HTMLElement;

// Defined before the loader runs: data-callback names this global.
window.__nazrOnToken = (t) => {
  window.__nazrToken = t;
};

function loadWidget(): Promise<void> {
  return new Promise((resolve, reject) => {
    // A classic script: the loader reads document.currentScript synchronously.
    const s = document.createElement("script");
    s.src = `${endpoint}/widget/v1/loader.js`;
    s.dataset.apiKey = apiKey;
    s.dataset.callback = "__nazrOnToken";
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(`failed to load ${s.src}`));
    // Inside the form, so the loader's closest("form") gets the hidden input.
    (document.getElementById("nazr-form") as HTMLFormElement).appendChild(s);
  });
}

async function main(): Promise<HostDone> {
  await loadWidget();
  if (!window.__nazrWidget) throw new Error("widget did not initialise");
  const { nonce } = await window.__nazrWidget.ready;
  const r = await getThumbmark({
    api_key: apiKey,
    api_endpoint: endpoint,
    nonce,
    cache_api_call: false,
  });
  return { nonce, thumbmark: r.thumbmark, ...(r.error?.length ? { error: r.error } : {}) };
}

main()
  .catch((e: unknown): HostDone => ({ nonce: "", thumbmark: "", error: String(e) }))
  .then((done) => {
    window.__nazrHostDone = done;
    status.textContent = done.error
      ? `error: ${JSON.stringify(done.error)}`
      : `thumbmark ${done.thumbmark} (nonce ${done.nonce})`;
  });
