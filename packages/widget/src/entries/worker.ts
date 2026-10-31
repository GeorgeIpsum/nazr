import { handleMessage } from "../worker";

self.onmessage = (e: MessageEvent<{ id: string; bits: number }>) =>
  self.postMessage(handleMessage(e.data));
