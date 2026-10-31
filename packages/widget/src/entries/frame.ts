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
  solve: (id, bits) =>
    new Promise<string>((resolve, reject) => {
      // biome-ignore lint/style/noNonNullAssertion: the server always renders data-worker
      const w = new Worker(script!.dataset.worker!);
      w.onmessage = (e) => {
        resolve(e.data.counter);
        w.terminate();
      };
      w.onerror = (e) => {
        reject(e);
        w.terminate();
      };
      w.postMessage({ id, bits });
    }),
});
