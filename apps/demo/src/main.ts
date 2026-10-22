import { hash, stableStringify, Thumbmark, type ThumbmarkResponse } from "@nazr/thumbmark";
import "./styles.css";
import { diffResults } from "./diff";
import { type Readyz, render, type ViewModel } from "./render";
import { clearVisitor, loadState, saveState } from "./state";

// Exposed always so the e2e test can recompute the thumbmark in-page.
(window as unknown as { __nazr: unknown }).__nazr = { stableStringify, hash };

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const endpoint = $<HTMLInputElement>("endpoint");
const apiKey = $<HTMLInputElement>("apiKey");
const simple = $<HTMLInputElement>("simple");
const simpleNote = $("simple-note");
const output = $("output");

const state = loadState();
endpoint.value = state.endpoint;
apiKey.value = state.apiKey;

const model: ViewModel = {
  result: state.lastResult,
  previous: null,
  diff: null,
  readyz: null,
  readyzError: null,
  running: false,
  fetchError: null,
};

function base(): string {
  return endpoint.value.trim().replace(/\/+$/, "");
}

function syncSimple(): void {
  apiKey.disabled = simple.checked;
  simpleNote.hidden = !simple.checked;
}

async function loadReadyz(): Promise<void> {
  model.readyz = null;
  model.readyzError = null;
  try {
    const res = await fetch(`${base()}/readyz`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    model.readyz = (await res.json()) as Readyz;
  } catch (e) {
    model.readyzError = e instanceof Error ? e.message : String(e);
  }
  render(output, model);
}

async function run(): Promise<void> {
  model.running = true;
  model.fetchError = null;
  render(output, model);
  try {
    const tm = new Thumbmark({
      api_key: simple.checked ? undefined : apiKey.value.trim() || undefined,
      api_endpoint: `${base()}/thumbmark`,
      logging: false,
      performance: true,
      simple_request: simple.checked,
    });
    const next: ThumbmarkResponse = await tm.get();
    model.previous = model.result?.thumbmark && !model.result.error?.length ? model.result : null;
    model.result = next;
    model.diff = model.previous ? diffResults(model.previous, next) : null;
    state.endpoint = endpoint.value;
    state.apiKey = apiKey.value;
    state.lastResult = next;
    saveState(state);
  } catch (e) {
    model.fetchError = e instanceof Error ? e.message : String(e);
  }
  model.running = false;
  await loadReadyz();
}

$("form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  void run();
});
$("clear").addEventListener("click", () => {
  const removed = clearVisitor();
  model.fetchError = null;
  $("clear-note").textContent = `Removed ${removed.length} key(s)`;
});
simple.addEventListener("change", syncSimple);
endpoint.addEventListener("change", () => void loadReadyz());
syncSimple();
void loadReadyz();
