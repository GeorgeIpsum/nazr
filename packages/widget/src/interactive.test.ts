import { afterEach, describe, expect, it } from "vitest";
import { renderInteractive, TraceRecorder } from "./interactive";

function clock(start = 1000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

const move = (x: number, y: number, isTrusted = true) => ({ isTrusted, clientX: x, clientY: y });

describe("TraceRecorder", () => {
  it("summarises a curved pointer path and a pointer click", () => {
    const c = clock(1000.4);
    const r = new TraceRecorder(c.now);
    r.start();
    c.advance(100);
    r.move(move(0, 0));
    c.advance(100);
    r.move(move(30, 40));
    c.advance(100);
    r.move(move(60, 0));
    c.advance(1200);
    const s = r.activate({ isTrusted: true, type: "pointerdown", pointerType: "mouse" }, true);
    expect(s.moves).toBe(3);
    expect(s.path_px).toBe(100);
    expect(s.straightness).toBe(0.6);
    expect(s.trusted).toBe(true);
    expect(s.input).toBe("pointer");
    expect(s.pointer_type).toBe("mouse");
    expect(s.visible).toBe(true);
    expect(Number.isInteger(s.shown_ms)).toBe(true);
    expect(Number.isInteger(s.click_ms)).toBe(true);
    expect(s.click_ms - s.shown_ms).toBe(1500);
  });

  it("rounds path_px and straightness to three decimals", () => {
    const r = new TraceRecorder(() => 0);
    r.start();
    r.move(move(0, 0));
    r.move(move(1, 1));
    r.move(move(2, 3));
    const s = r.activate({ isTrusted: true, type: "pointerdown", pointerType: "pen" }, true);
    expect(s.path_px).toBe(3.65);
    expect(s.straightness).toBe(0.988);
    expect(s.pointer_type).toBe("pen");
  });

  it("is untrusted when any move was untrusted", () => {
    const r = new TraceRecorder(() => 0);
    r.start();
    r.move(move(0, 0));
    r.move(move(5, 5, false));
    r.move(move(9, 1));
    const s = r.activate({ isTrusted: true, type: "pointerdown", pointerType: "mouse" }, true);
    expect(s.trusted).toBe(false);
  });

  it("is untrusted when the activation was untrusted", () => {
    const r = new TraceRecorder(() => 0);
    r.start();
    expect(r.activate({ isTrusted: false, type: "click" }, true).trusted).toBe(false);
  });

  it("samples at most 200 moves", () => {
    const r = new TraceRecorder(() => 0);
    r.start();
    for (let i = 0; i < 250; i++) r.move(move(i, i % 7));
    const s = r.activate({ isTrusted: true, type: "pointerdown", pointerType: "touch" }, true);
    expect(s.moves).toBe(200);
    expect(s.pointer_type).toBe("touch");
  });

  it("reports keyboard activations without a pointer type", () => {
    const r = new TraceRecorder(() => 0);
    r.start();
    const s = r.activate({ isTrusted: true, type: "keydown" }, false);
    expect(s.input).toBe("keyboard");
    expect(s.pointer_type).toBe("");
    expect(s.moves).toBe(0);
    expect(s.path_px).toBe(0);
    expect(s.straightness).toBe(1);
    expect(s.visible).toBe(false);
  });

  it("defaults a pointer activation without a known pointerType to mouse", () => {
    const r = new TraceRecorder(() => 0);
    r.start();
    expect(r.activate({ isTrusted: true, type: "click" }, true).pointer_type).toBe("mouse");
    const r2 = new TraceRecorder(() => 0);
    r2.start();
    expect(
      r2.activate({ isTrusted: true, type: "pointerdown", pointerType: "" }, true),
    ).toMatchObject({ input: "pointer", pointer_type: "mouse" });
  });
});

describe("renderInteractive", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("renders one focusable button in a styled box", async () => {
    const ui = renderInteractive(document, () => 0);
    await ui.shown;
    const buttons = document.querySelectorAll("button");
    expect(buttons).toHaveLength(1);
    const button = buttons[0];
    expect(button.textContent).toBe("Verify you are human");
    expect(button.type).toBe("button");
    expect(button.tabIndex).toBe(0);
    const box = button.parentElement as HTMLElement;
    expect(box.parentElement).toBe(document.body);
    expect(box.style.width).toBe("300px");
    expect(box.style.height).toBe("65px");
    expect(document.querySelector("style")).toBeNull();
    for (const el of [box, button]) expect(el.getAttribute("style") ?? "").not.toContain("<");
  });

  it("resolves activated once from Enter on the button", async () => {
    let t = 10;
    const ui = renderInteractive(document, () => t);
    await ui.shown;
    const button = document.querySelector("button") as HTMLButtonElement;
    t = 900;
    const enter = new KeyboardEvent("keydown", { key: "Enter", cancelable: true, bubbles: true });
    button.dispatchEvent(enter);
    expect(enter.defaultPrevented).toBe(true);
    t = 2000;
    button.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    const s = await ui.activated;
    expect(s.input).toBe("keyboard");
    expect(s.pointer_type).toBe("");
    expect(s.shown_ms).toBe(10);
    expect(s.click_ms).toBe(900);
  });

  it("ignores other keys", async () => {
    const ui = renderInteractive(document, () => 0);
    await ui.shown;
    const button = document.querySelector("button") as HTMLButtonElement;
    let done = false;
    void ui.activated.then(() => {
      done = true;
    });
    button.dispatchEvent(new KeyboardEvent("keydown", { key: "a", bubbles: true }));
    await Promise.resolve();
    expect(done).toBe(false);
    button.dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
    expect((await ui.activated).input).toBe("keyboard");
  });

  it("records document pointer moves and a click fallback", async () => {
    const ui = renderInteractive(document, () => 0);
    await ui.shown;
    for (const [x, y] of [
      [0, 0],
      [3, 4],
    ]) {
      document.dispatchEvent(new MouseEvent("pointermove", { clientX: x, clientY: y }));
    }
    (document.querySelector("button") as HTMLButtonElement).dispatchEvent(
      new MouseEvent("click", { detail: 1, bubbles: true }),
    );
    const s = await ui.activated;
    expect(s).toMatchObject({ input: "pointer", pointer_type: "mouse", moves: 2, path_px: 5 });
    // jsdom dispatches untrusted events.
    expect(s.trusted).toBe(false);
  });

  it("records a click without a pointer (detail 0) as a keyboard activation", async () => {
    const ui = renderInteractive(document, () => 0);
    await ui.shown;
    document.dispatchEvent(new MouseEvent("pointermove", { clientX: 1, clientY: 1 }));
    (document.querySelector("button") as HTMLButtonElement).dispatchEvent(
      new MouseEvent("click", { detail: 0, bubbles: true }),
    );
    const s = await ui.activated;
    expect(s.input).toBe("keyboard");
    expect(s.pointer_type).toBe("");
  });

  it("records a click with detail 1 as a mouse pointer activation", async () => {
    const ui = renderInteractive(document, () => 0);
    await ui.shown;
    (document.querySelector("button") as HTMLButtonElement).dispatchEvent(
      new MouseEvent("click", { detail: 1, bubbles: true }),
    );
    expect(await ui.activated).toMatchObject({ input: "pointer", pointer_type: "mouse" });
  });

  it("ignores non-primary buttons", async () => {
    const ui = renderInteractive(document, () => 0);
    await ui.shown;
    const button = document.querySelector("button") as HTMLButtonElement;
    let done = false;
    void ui.activated.then(() => {
      done = true;
    });
    button.dispatchEvent(new MouseEvent("pointerdown", { button: 2, bubbles: true }));
    button.dispatchEvent(new MouseEvent("click", { button: 1, detail: 1, bubbles: true }));
    await Promise.resolve();
    expect(done).toBe(false);
    button.dispatchEvent(new MouseEvent("pointerdown", { button: 0, bubbles: true }));
    expect(await ui.activated).toMatchObject({ input: "pointer", pointer_type: "mouse" });
  });

  it("records a real pointerdown and does not re-activate on the following click", async () => {
    const ui = renderInteractive(document, () => 0);
    await ui.shown;
    const button = document.querySelector("button") as HTMLButtonElement;
    const down = Object.assign(new Event("pointerdown", { bubbles: true }), {
      pointerType: "mouse",
      button: 0,
    });
    button.dispatchEvent(down);
    const first = await ui.activated;
    expect(first).toMatchObject({ input: "pointer", pointer_type: "mouse" });
    // A later click (detail 0 would read as keyboard) must not change the settled result.
    button.dispatchEvent(new MouseEvent("click", { detail: 0, bubbles: true }));
    expect(await ui.activated).toBe(first);
    expect(first.input).toBe("pointer");
  });

  it("changes the button for each state", async () => {
    const ui = renderInteractive(document, () => 0);
    await ui.shown;
    const button = document.querySelector("button") as HTMLButtonElement;
    ui.setState("working");
    expect(button.textContent).toBe("Verifying…");
    expect(button.disabled).toBe(true);
    ui.setState("verified");
    expect(button.textContent).toContain("Verified");
    ui.setState("failed");
    expect(button.textContent).toBe("Verification failed");
  });
});
