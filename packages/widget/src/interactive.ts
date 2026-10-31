/** The behavioural summary the frame submits to `POST /widget/interact` (spec §3.2). */
export interface TraceSummary {
  shown_ms: number;
  click_ms: number;
  input: "pointer" | "keyboard";
  trusted: boolean;
  moves: number;
  path_px: number;
  straightness: number;
  pointer_type: string;
  visible: boolean;
}

/** Most `pointermove` samples kept; the server rejects more. */
export const MAX_MOVES = 200;

const POINTER_TYPES = ["mouse", "touch", "pen"];

const round3 = (n: number): number => Math.round(n * 1000) / 1000;

/** Records pointer moves and the activating event between the box being shown and the click. */
export class TraceRecorder {
  private shown = 0;
  private trusted = true;
  private readonly xs: number[] = [];
  private readonly ys: number[] = [];

  constructor(private readonly now: () => number) {}

  start(): void {
    this.shown = Math.round(this.now());
  }

  move(ev: { isTrusted: boolean; clientX: number; clientY: number }): void {
    // Moves past the cap are not sampled, but a synthetic one still taints the trace.
    if (!ev.isTrusted) this.trusted = false;
    if (this.xs.length >= MAX_MOVES) return;
    this.xs.push(ev.clientX);
    this.ys.push(ev.clientY);
  }

  activate(
    ev: { isTrusted: boolean; type: string; pointerType?: string },
    visible: boolean,
  ): TraceSummary {
    const click = Math.round(this.now());
    if (!ev.isTrusted) this.trusted = false;
    const keyboard = ev.type === "keydown";
    const n = this.xs.length;
    let path = 0;
    for (let i = 1; i < n; i++) {
      path += Math.hypot(this.xs[i] - this.xs[i - 1], this.ys[i] - this.ys[i - 1]);
    }
    const chord = n < 2 ? 0 : Math.hypot(this.xs[n - 1] - this.xs[0], this.ys[n - 1] - this.ys[0]);
    const straightness = n < 2 || path === 0 ? 1 : Math.min(1, chord / path);
    const pointerType = ev.pointerType ?? "";
    return {
      shown_ms: this.shown,
      click_ms: click,
      input: keyboard ? "keyboard" : "pointer",
      trusted: this.trusted,
      moves: n,
      path_px: round3(path),
      straightness: round3(straightness),
      pointer_type: keyboard ? "" : POINTER_TYPES.includes(pointerType) ? pointerType : "mouse",
      visible,
    };
  }
}

export interface InteractiveUI {
  shown: Promise<void>;
  activated: Promise<TraceSummary>;
  setState(s: "working" | "verified" | "failed"): void;
}

const LABELS = {
  working: "Verifying…",
  verified: "Verified ✓",
  failed: "Verification failed",
} as const;

/**
 * Renders the 300×65 click-to-verify box into `doc.body` and records how the visitor reaches
 * the button. Styles go through CSSOM properties only, so the frame CSP needs no `style-src`.
 */
export function renderInteractive(doc: Document, now: () => number): InteractiveUI {
  const box = doc.createElement("div");
  Object.assign(box.style, {
    width: "300px",
    height: "65px",
    border: "1px solid #d0d0d0",
    borderRadius: "4px",
    boxSizing: "border-box",
    display: "flex",
    alignItems: "center",
    padding: "0 12px",
    font: "14px system-ui, sans-serif",
  });
  const button = doc.createElement("button");
  button.type = "button";
  button.tabIndex = 0;
  button.textContent = "Verify you are human";
  box.appendChild(button);

  const recorder = new TraceRecorder(now);
  let done = false;
  let resolveActivated: (s: TraceSummary) => void = () => {};
  const activated = new Promise<TraceSummary>((r) => {
    resolveActivated = r;
  });

  const onMove = (ev: Event) => {
    if (!done) recorder.move(ev as PointerEvent);
  };
  const activate = (ev: { isTrusted: boolean; type: string; pointerType?: string }) => {
    if (done) return;
    done = true;
    doc.removeEventListener("pointermove", onMove);
    resolveActivated(recorder.activate(ev, doc.visibilityState === "visible"));
  };

  doc.addEventListener("pointermove", onMove);
  button.addEventListener("pointerdown", (ev) => {
    if ((ev as PointerEvent).button !== 0) return;
    const pointerType = (ev as PointerEvent).pointerType || "mouse";
    activate({ isTrusted: ev.isTrusted, type: ev.type, pointerType });
  });
  // Ignored after a pointerdown or keydown. A click with detail 0 came from no pointer
  // (assistive technology, Enter on some platforms), so it counts as a keyboard activation
  // and skips the path rules; otherwise it is the fallback for browsers without pointer events.
  button.addEventListener("click", (ev) => {
    if (ev.button !== 0) return;
    if (ev.detail === 0) activate({ isTrusted: ev.isTrusted, type: "keydown" });
    else activate({ isTrusted: ev.isTrusted, type: "click", pointerType: "mouse" });
  });
  button.addEventListener("keydown", (ev) => {
    if (ev.key !== " " && ev.key !== "Enter") return;
    ev.preventDefault();
    activate({ isTrusted: ev.isTrusted, type: "keydown" });
  });

  doc.body.appendChild(box);
  recorder.start();

  return {
    shown: Promise.resolve(),
    activated,
    setState(s) {
      button.textContent = LABELS[s];
      button.disabled = true;
    },
  };
}
