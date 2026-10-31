import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mountWidget } from "./loader";

const win = window;

function setCurrentScript(attrs: Record<string, string> = {}): HTMLScriptElement {
  const script = document.createElement("script");
  script.src = "https://nazr.example/widget/v1/loader.js";
  script.setAttribute("data-api-key", "nzr_x");
  for (const [name, value] of Object.entries(attrs)) script.setAttribute(name, value);
  Object.defineProperty(document, "currentScript", { value: script, configurable: true });
  return script;
}

function captureShadowRoots(): ShadowRoot[] {
  const roots: ShadowRoot[] = [];
  const original = Element.prototype.attachShadow;
  vi.spyOn(Element.prototype, "attachShadow").mockImplementation(function (
    this: Element,
    init: ShadowRootInit,
  ) {
    const root = original.call(this, init);
    roots.push(root);
    return root;
  });
  return roots;
}

const listeners: EventListener[] = [];
const realAdd = win.addEventListener.bind(win);

beforeEach(() => {
  vi.spyOn(win, "addEventListener").mockImplementation(((type: string, fn: EventListener) => {
    if (type === "message") listeners.push(fn);
    realAdd(type, fn);
  }) as typeof win.addEventListener);
  delete win.__nazrWidget;
  document.body.innerHTML = "";
});

afterEach(() => {
  for (const fn of listeners.splice(0)) win.removeEventListener("message", fn);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  Object.defineProperty(document, "currentScript", { value: null, configurable: true });
});

const ORIGIN = "https://nazr.example";

function b64url(obj: unknown): string {
  return btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function jwt(exp: number): string {
  return `${b64url({ alg: "ES256" })}.${b64url({ exp })}.sig`;
}

function mount(attrs: Record<string, string> = {}, inForm = true) {
  const roots = captureShadowRoots();
  const script = setCurrentScript(attrs);
  let form: HTMLFormElement | null = null;
  if (inForm) {
    form = document.createElement("form");
    form.appendChild(script);
    document.body.appendChild(form);
  }
  mountWidget(document, win);
  const iframe = roots[0].querySelector("iframe") as HTMLIFrameElement;
  return { iframe, form, script };
}

function send(
  iframe: HTMLIFrameElement,
  data: unknown,
  opts: { origin?: string; source?: MessageEventSource | null } = {},
) {
  win.dispatchEvent(
    new MessageEvent("message", {
      data,
      origin: opts.origin ?? ORIGIN,
      source: opts.source === undefined ? iframe.contentWindow : opts.source,
    }),
  );
}

function spySrc(iframe: HTMLIFrameElement): string[] {
  const desc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, "src");
  const sets: string[] = [];
  Object.defineProperty(iframe, "src", {
    configurable: true,
    get: () => desc?.get?.call(iframe),
    set: (v: string) => {
      sets.push(v);
      desc?.set?.call(iframe, v);
    },
  });
  return sets;
}

describe("mountWidget", () => {
  it("mounts inside a closed shadow root", () => {
    setCurrentScript();
    mountWidget(document, win);
    expect(document.querySelector("iframe")).toBeNull();
    const host = document.body.lastElementChild;
    expect(host).not.toBeNull();
    expect(host?.shadowRoot).toBeNull();
  });

  it("points a 0x0 iframe at the frame URL without a nonce", () => {
    const { iframe } = mount();
    expect(iframe.src).toBe("https://nazr.example/widget/v1/frame?k=nzr_x");
    expect(iframe.width).toBe("0");
    expect(iframe.height).toBe("0");
  });

  it("does nothing when currentScript is null", () => {
    mountWidget(document, win);
    expect(win.__nazrWidget).toBeUndefined();
    expect(document.body.children).toHaveLength(0);
  });

  it("does nothing without an api key", () => {
    const script = setCurrentScript();
    script.removeAttribute("data-api-key");
    mountWidget(document, win);
    expect(win.__nazrWidget).toBeUndefined();
  });

  it("never throws when attachShadow throws", () => {
    vi.spyOn(Element.prototype, "attachShadow").mockImplementation(() => {
      throw new Error("boom");
    });
    setCurrentScript();
    expect(() => mountWidget(document, win)).not.toThrow();
  });

  it("waits for DOMContentLoaded when document.body is null, then appends once", () => {
    const body = vi.spyOn(document, "body", "get").mockReturnValue(null as unknown as HTMLElement);
    setCurrentScript();
    mountWidget(document, win);
    expect(win.__nazrWidget).toBeDefined();
    body.mockRestore();
    expect(document.body.children).toHaveLength(0);

    const append = vi.spyOn(document.body, "appendChild");
    document.dispatchEvent(new Event("DOMContentLoaded"));
    document.dispatchEvent(new Event("DOMContentLoaded"));
    expect(append).toHaveBeenCalledTimes(1);
    expect(document.body.children).toHaveLength(1);
    expect(document.body.lastElementChild?.shadowRoot).toBeNull();
  });

  it("mounts only one widget per page", () => {
    setCurrentScript();
    mountWidget(document, win);
    setCurrentScript();
    mountWidget(document, win);
    expect(document.body.children).toHaveLength(1);
  });
});

describe("frame messages", () => {
  it("takes the nonce from the challenge message and resolves ready once", async () => {
    const { iframe } = mount();
    const widget = win.__nazrWidget;
    expect(widget?.nonce).toBeUndefined();
    send(iframe, { type: "nazr:challenge", id: "c1" });
    expect(widget?.nonce).toBe("c1");
    await expect(widget?.ready).resolves.toEqual({ nonce: "c1" });
    send(iframe, { type: "nazr:challenge", id: "c2" });
    expect(widget?.nonce).toBe("c2");
    await expect(widget?.ready).resolves.toEqual({ nonce: "c1" });
  });

  it("warns once and ignores data-nonce", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { iframe } = mount({ "data-nonce": "x" });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain("data-nonce");
    expect(iframe.src).not.toContain("n=");
    expect(win.__nazrWidget?.nonce).toBeUndefined();
  });

  describe("tokens", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    });
    afterEach(() => {
      vi.useRealTimers();
      delete (win as unknown as Record<string, unknown>).onNazr;
    });
    const exp = () => Math.floor(Date.now() / 1000) + 60;

    it("writes a hidden input in the enclosing form and calls the callback", () => {
      const cb = vi.fn();
      (win as unknown as Record<string, unknown>).onNazr = cb;
      const { iframe, form } = mount({ "data-callback": "onNazr" });
      const token = jwt(exp());
      send(iframe, { type: "nazr:token", token });
      const input = form?.querySelector('input[name="nazr-token"]') as HTMLInputElement;
      expect(input.type).toBe("hidden");
      expect(input.value).toBe(token);
      expect(cb).toHaveBeenCalledWith(token);
      expect(win.__nazrWidget?.token).toBe(token);
      const next = jwt(exp() + 5);
      send(iframe, { type: "nazr:token", token: next });
      expect(form?.querySelectorAll("input")).toHaveLength(1);
      expect(input.value).toBe(next);
    });

    it("honors data-response-field-name and reuses an existing input", () => {
      const roots = captureShadowRoots();
      const script = setCurrentScript({ "data-response-field-name": "cf" });
      const form = document.createElement("form");
      const existing = document.createElement("input");
      existing.name = "cf";
      form.append(existing, script);
      document.body.appendChild(form);
      mountWidget(document, win);
      const iframe = roots[0].querySelector("iframe") as HTMLIFrameElement;
      const token = jwt(exp());
      send(iframe, { type: "nazr:token", token });
      expect(form.querySelectorAll("input")).toHaveLength(1);
      expect(existing.value).toBe(token);
    });

    it("works without a form", () => {
      const cb = vi.fn();
      (win as unknown as Record<string, unknown>).onNazr = cb;
      const { iframe } = mount({ "data-callback": "onNazr" }, false);
      const token = jwt(exp());
      send(iframe, { type: "nazr:token", token });
      expect(document.querySelector("input")).toBeNull();
      expect(cb).toHaveBeenCalledWith(token);
    });

    it("expires: clears, calls the expired callback, reloads the frame", () => {
      const expired = vi.fn();
      (win as unknown as Record<string, unknown>).onNazr = expired;
      const { iframe, form } = mount({ "data-expired-callback": "onNazr" });
      const sets = spySrc(iframe);
      send(iframe, { type: "nazr:token", token: jwt(exp()) });
      vi.advanceTimersByTime(59_000);
      expect(expired).not.toHaveBeenCalled();
      vi.advanceTimersByTime(1_000);
      const input = form?.querySelector("input") as HTMLInputElement;
      expect(input.value).toBe("");
      expect(win.__nazrWidget?.token).toBeUndefined();
      expect(expired).toHaveBeenCalledTimes(1);
      expect(sets).toHaveLength(1);
    });

    it("keeps the token when exp cannot be decoded", () => {
      const { iframe } = mount();
      send(iframe, { type: "nazr:token", token: "garbage" });
      vi.advanceTimersByTime(10 * 60_000);
      expect(win.__nazrWidget?.token).toBe("garbage");
    });

    it("reset() reloads the frame and clears the token", () => {
      const { iframe, form } = mount();
      const sets = spySrc(iframe);
      send(iframe, { type: "nazr:token", token: jwt(exp()) });
      win.__nazrWidget?.reset();
      expect(sets).toEqual([iframe.src]);
      expect(win.__nazrWidget?.token).toBeUndefined();
      expect(form?.querySelector("input")?.value).toBe("");
      vi.advanceTimersByTime(120_000);
      expect(sets).toHaveLength(1);
      send(iframe, { type: "nazr:challenge", id: "again" });
      expect(win.__nazrWidget?.nonce).toBe("again");
    });
  });

  it("ignores wrong origin, wrong source and untyped data", () => {
    const cb = vi.fn();
    (win as unknown as Record<string, unknown>).onNazr = cb;
    const { iframe } = mount({ "data-callback": "onNazr" });
    const other = document.createElement("iframe");
    document.body.appendChild(other);
    const msg = { type: "nazr:token", token: "t" };
    send(iframe, msg, { origin: "https://evil.example" });
    send(iframe, msg, { source: other.contentWindow });
    send(iframe, { token: "t" });
    send(iframe, "nazr:token");
    send(iframe, null);
    expect(cb).not.toHaveBeenCalled();
    expect(win.__nazrWidget?.token).toBeUndefined();
    delete (win as unknown as Record<string, unknown>).onNazr;
  });

  it("calls the error callback and survives a throwing callback", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const cb = vi.fn(() => {
      throw new Error("host bug");
    });
    (win as unknown as Record<string, unknown>).onNazrErr = cb;
    const { iframe } = mount({ "data-error-callback": "onNazrErr" });
    expect(() => send(iframe, { type: "nazr:error", reason: "inconclusive" })).not.toThrow();
    expect(cb).toHaveBeenCalledWith("inconclusive");
    expect(err).toHaveBeenCalled();
    delete (win as unknown as Record<string, unknown>).onNazrErr;
  });
});
