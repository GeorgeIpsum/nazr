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

beforeEach(() => {
  delete win.__nazrWidget;
  document.body.innerHTML = "";
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  Object.defineProperty(document, "currentScript", { value: null, configurable: true });
});

describe("mountWidget", () => {
  it("generates a UUID nonce when data-nonce is absent", async () => {
    setCurrentScript();
    mountWidget(document, win);
    const widget = win.__nazrWidget;
    expect(widget?.nonce).toMatch(/^[0-9a-f-]{36}$/);
    await expect(widget?.ready).resolves.toEqual({ nonce: widget?.nonce });
  });

  it("uses data-nonce when present", async () => {
    setCurrentScript({ "data-nonce": "host-nonce-1" });
    mountWidget(document, win);
    expect(win.__nazrWidget?.nonce).toBe("host-nonce-1");
    await expect(win.__nazrWidget?.ready).resolves.toEqual({ nonce: "host-nonce-1" });
  });

  it("mounts inside a closed shadow root", () => {
    setCurrentScript();
    mountWidget(document, win);
    expect(document.querySelector("iframe")).toBeNull();
    const host = document.body.lastElementChild;
    expect(host).not.toBeNull();
    expect(host?.shadowRoot).toBeNull();
  });

  it("points the iframe at the frame URL on the loader origin, URL-encoded", () => {
    const roots = captureShadowRoots();
    setCurrentScript({ "data-nonce": "a b&c" });
    mountWidget(document, win);
    expect(roots).toHaveLength(1);
    const iframe = roots[0].querySelector("iframe");
    expect(iframe?.src).toBe("https://nazr.example/widget/v1/frame?k=nzr_x&n=a+b%26c");
  });

  it("sets the iframe src with the generated nonce", () => {
    const roots = captureShadowRoots();
    setCurrentScript();
    mountWidget(document, win);
    const nonce = win.__nazrWidget?.nonce;
    expect(roots[0].querySelector("iframe")?.src).toBe(
      `https://nazr.example/widget/v1/frame?k=nzr_x&n=${nonce}`,
    );
  });

  it("does nothing when currentScript is null", () => {
    mountWidget(document, win);
    expect(win.__nazrWidget).toBeUndefined();
    expect(document.body.children).toHaveLength(0);
  });

  it("does nothing without crypto.randomUUID and no data-nonce", () => {
    vi.stubGlobal("crypto", {});
    setCurrentScript();
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
    setCurrentScript({ "data-nonce": "second" });
    mountWidget(document, win);
    expect(document.body.children).toHaveLength(1);
    expect(win.__nazrWidget?.nonce).not.toBe("second");
  });
});
