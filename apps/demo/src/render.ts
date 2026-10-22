import type { ThumbmarkResponse } from "@nazr/thumbmark";
import type { Diff } from "./diff";

export interface Readyz {
  version?: string;
  tls_mode?: string;
  store?: unknown;
  sources?: Record<string, { loaded?: boolean } | boolean>;
}

export interface ViewModel {
  result: ThumbmarkResponse | null;
  previous: ThumbmarkResponse | null;
  diff: Diff | null;
  readyz: Readyz | null;
  readyzError: string | null;
  running: boolean;
  fetchError: string | null;
}

type Child = Node | string;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { class?: string; title?: string; id?: string } = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (props.class) e.className = props.class;
  if (props.title) e.title = props.title;
  if (props.id) e.id = props.id;
  for (const c of children) e.append(c);
  return e;
}

/** Recursive tree: objects become <details>, leaves become <code>. */
export function tree(value: unknown, label: string, open = false): HTMLElement {
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    const d = el("details", { class: "tree" });
    d.open = open;
    d.append(el("summary", {}, label, el("span", { class: "muted" }, ` (${entries.length})`)));
    if (entries.length === 0) d.append(el("div", { class: "leaf muted" }, "empty"));
    for (const [k, v] of entries) d.append(tree(v, k));
    return d;
  }
  return el(
    "div",
    { class: "leaf" },
    el("span", { class: "key" }, `${label}: `),
    el("code", {}, JSON.stringify(value) ?? String(value)),
  );
}

function chip(label: string, on: boolean): HTMLElement {
  return el("span", { class: `chip ${on ? "bad" : "ok"}` }, `${label}: ${on}`);
}

function panel(title: string, ...children: Child[]): HTMLElement {
  return el("section", { class: "panel" }, el("h2", {}, title), ...children);
}

function meter(level: number): HTMLElement {
  const m = el("div", { class: "meter", title: `danger_level ${level} / 5` });
  for (let i = 0; i < 5; i++) {
    m.append(el("span", { class: `seg${i < level ? ` on l${level}` : ""}` }));
  }
  return m;
}

function kv(rows: [string, string][]): HTMLElement {
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of rows) dl.append(el("dt", {}, k), el("dd", {}, el("code", {}, v)));
  return dl;
}

export function errorPanel(result: ThumbmarkResponse | null, fetchError: string | null) {
  const items: string[] = [];
  for (const e of result?.error ?? []) {
    items.push(
      e.type === "api_unauthorized"
        ? `${e.type}: Unauthorized: check the key and allowed origins`
        : `${e.type}: ${e.message}`,
    );
  }
  if (fetchError) items.push(`error: ${fetchError}`);
  if (items.length === 0) return null;
  const p = el("section", { class: "panel error", id: "error-panel" }, el("h2", {}, "Error"));
  for (const i of items) p.append(el("p", {}, i));
  return p;
}

function banner(m: ViewModel): HTMLElement {
  const b = el("div", { class: "banner", id: "banner" });
  if (m.readyz) {
    b.append(
      el("span", { class: "chip neutral" }, `version ${m.readyz.version ?? "?"}`),
      el("span", { class: "chip neutral" }, `tls_mode ${m.readyz.tls_mode ?? "?"}`),
    );
    for (const [name, s] of Object.entries(m.readyz.sources ?? {})) {
      const loaded = typeof s === "boolean" ? s : !!s?.loaded;
      b.append(
        el(
          "span",
          { class: `chip ${loaded ? "ok" : "bad"}` },
          `${name}: ${loaded ? "loaded" : "not loaded"}`,
        ),
      );
    }
  } else if (m.readyzError) {
    b.append(el("span", { class: "chip bad" }, `readyz unavailable (${m.readyzError})`));
  }
  const r = m.result;
  if (r && !r.error?.length && !(r.components as Record<string, unknown>)?.tls) {
    b.append(
      el(
        "div",
        { class: "warn", id: "tls-warning" },
        "TLS fingerprint unavailable (plain/proxied mode or proxy in front)",
      ),
    );
  }
  return b;
}

export function render(root: HTMLElement, m: ViewModel): void {
  const out = root;
  out.replaceChildren(banner(m));
  const r = m.result;
  const err = errorPanel(r, m.fetchError);
  if (err) out.append(err);
  if (m.running) out.append(el("p", { class: "muted" }, "Running..."));
  if (!r || (r.error?.some((e) => e.type === "api_unauthorized") && !r.thumbmark)) {
    if (!r && !err && !m.running) out.append(el("p", { class: "muted" }, "Press Run."));
    return;
  }

  const info = r.info ?? {};
  const v = info.visitor;
  out.append(
    panel(
      "Thumbmark and visitor",
      el("div", { class: "big" }, el("code", { id: "thumbmark" }, r.thumbmark)),
      kv([
        ["visitorId", r.visitorId ?? v?.id ?? "-"],
        ["isNew", String(v?.isNew ?? "-")],
        ["firstSeen", v?.firstSeen ?? "-"],
        ["lastSeen", v?.lastSeen ?? "-"],
        ["requestId", r.requestId ?? "-"],
        ["version", r.version],
      ]),
    ),
  );

  const cls = info.classification;
  const clsPanel = panel("Classification and signals");
  if (cls) {
    const chips = el("div", { class: "chips", id: "classification" });
    for (const k of ["tor", "vpn", "bot", "datacenter", "private_relay"] as const) {
      if (cls[k] !== undefined) chips.append(chip(k, !!cls[k]));
    }
    clsPanel.append(chips, el("div", { class: "row" }, "danger_level ", meter(cls.danger_level)));
  } else {
    clsPanel.append(el("p", { class: "muted" }, "No classification in response."));
  }
  const sig = Object.entries(info.signals ?? {});
  const sigBox = el("div", { class: "chips", id: "signals" });
  for (const [k, val] of sig) sigBox.append(chip(k, !!val));
  clsPanel.append(
    el("h3", {}, "Signals"),
    sig.length ? sigBox : el("p", { class: "muted" }, "none"),
  );
  const extra: [string, string][] = [];
  if (info.ip_address) extra.push(["ip", info.ip_address.ip_address]);
  if (info.country) extra.push(["country", `${info.country.iso_code} ${info.country.name}`]);
  if (info.uniqueness) extra.push(["uniqueness", JSON.stringify(info.uniqueness)]);
  if (extra.length) clsPanel.append(kv(extra));
  out.append(clsPanel);

  const comps = (r.components ?? {}) as Record<string, unknown>;
  const serverKeys = ["tls", "h2", "header", "ip"];
  const server = panel("Server components");
  const client = panel("Client components");
  for (const [k, val] of Object.entries(comps)) {
    (serverKeys.includes(k) ? server : client).append(tree(val, k));
  }
  if (!server.querySelector(".tree")) server.append(el("p", { class: "muted" }, "none"));
  out.append(server, client);

  const timing = panel("Timing");
  const rows = Object.entries(r.elapsed ?? {}).sort((a, b) => b[1] - a[1]);
  if (rows.length) {
    const t = el("table", {}, el("tr", {}, el("th", {}, "component"), el("th", {}, "ms")));
    for (const [k, ms] of rows)
      t.append(el("tr", {}, el("td", {}, k), el("td", {}, ms.toFixed(1))));
    timing.append(t);
  } else timing.append(el("p", { class: "muted" }, "no timing data"));
  out.append(timing);

  const diff = panel("Diff vs previous run");
  if (!m.previous || !m.diff) diff.append(el("p", { class: "muted" }, "No previous run."));
  else {
    const d = m.diff;
    if (!d.added.length && !d.removed.length && !d.changed.length) {
      diff.append(el("p", { class: "muted" }, "No differences in components."));
    }
    for (const [name, list] of [
      ["added", d.added],
      ["removed", d.removed],
      ["changed", d.changed],
    ] as const) {
      if (!list.length) continue;
      const ul = el("ul", { class: `diff ${name}` });
      for (const p of list) ul.append(el("li", {}, el("code", {}, p)));
      diff.append(el("h3", {}, `${name} (${list.length})`), ul);
    }
  }
  out.append(diff);

  const raw = el("details", { class: "panel", id: "raw" }, el("summary", {}, "Raw JSON"));
  raw.append(el("pre", {}, JSON.stringify(r, null, 2)));
  out.append(raw);
}
