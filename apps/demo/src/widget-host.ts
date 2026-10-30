import { getThumbmark } from "@nazr/thumbmark";

interface HostDone {
  nonce: string;
  thumbmark: string;
  error?: unknown;
}

declare global {
  interface Window {
    __nazrWidget?: { nonce: string; ready: Promise<{ nonce: string }> };
    __nazrHostDone?: HostDone;
  }
}

const q = new URLSearchParams(location.search);
const apiKey = q.get("key") ?? "";
const endpoint = (q.get("endpoint") ?? "").replace(/\/+$/, "");
const status = document.getElementById("status") as HTMLElement;

function loadWidget(): Promise<void> {
  return new Promise((resolve, reject) => {
    // A classic script: the loader reads document.currentScript synchronously.
    const s = document.createElement("script");
    s.src = `${endpoint}/widget/v1/loader.js`;
    s.dataset.apiKey = apiKey;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(`failed to load ${s.src}`));
    document.head.appendChild(s);
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
