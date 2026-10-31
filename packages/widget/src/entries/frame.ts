import { getThumbmark } from "@nazr/thumbmark";
import { reportFromFrame } from "../frame";

const script = document.currentScript as HTMLScriptElement | null;
const dataOrigin = script?.dataset.origin;

void reportFromFrame({
  script,
  location,
  fetch: fetch.bind(globalThis),
  getThumbmark,
  post: (m) => window.parent.postMessage(m, dataOrigin || "*"),
  doc: document,
  now: () => performance.now(),
  solve: (id, bits, signal) =>
    new Promise<string>((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason);
        return;
      }
      // biome-ignore lint/style/noNonNullAssertion: the server always renders data-worker
      const w = new Worker(script!.dataset.worker!);
      const onAbort = () => {
        w.terminate();
        reject(signal?.reason);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      w.onmessage = (e) => {
        signal?.removeEventListener("abort", onAbort);
        resolve(e.data.counter);
        w.terminate();
      };
      w.onerror = (e) => {
        signal?.removeEventListener("abort", onAbort);
        reject(e);
        w.terminate();
      };
      w.postMessage({ id, bits });
    }),
});
