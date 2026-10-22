import type { componentInterface } from "../../factory";
import { hash } from "../../utils/hash";

const SVG_NS = "http://www.w3.org/2000/svg";

// Coordinates are emitted relative to the probe container so scroll position,
// body margin and other page layout cannot change the result.
function fmt(r: DOMRect, base: DOMRect): string {
    return [r.x - base.x, r.y - base.y, r.width, r.height]
        .map((n) => (Number.isFinite(n) ? n : 0).toFixed(2))
        .join(",");
}

export default async function getClientRects(): Promise<componentInterface | null> {
    const body = document.body;
    if (!body) return null;

    const container = document.createElement("div");
    container.style.cssText = "position:fixed; left:-9999px; top:-9999px; visibility:hidden";

    try {
        const box = document.createElement("div");
        box.style.cssText = "width:123.4px; border:1.7px solid #000";
        box.textContent = " ";

        const span = document.createElement("span");
        span.style.cssText = "font:16.3px serif";
        span.textContent = "nazr clientrects probe";

        const rotated = document.createElement("div");
        rotated.style.cssText = "transform: rotate(13deg); width:80px; height:40px";

        const p = document.createElement("p");
        p.style.cssText = "font:14px serif";
        const em = document.createElement("em");
        em.style.cssText = "font-size:1.31em";
        em.textContent = "nazr";
        p.appendChild(em);

        const svg = document.createElementNS(SVG_NS, "svg");
        svg.setAttribute("width", "50.5");
        svg.setAttribute("height", "30.5");
        const rect = document.createElementNS(SVG_NS, "rect");
        rect.setAttribute("width", "50.5");
        rect.setAttribute("height", "30.5");
        svg.appendChild(rect);

        container.append(box, span, rotated, p, svg);
        body.appendChild(container);

        const base = container.getBoundingClientRect();
        const rects = [box, span, rotated, em, svg].map((el) =>
            fmt(el.getBoundingClientRect(), base),
        );
        return { rects, hash: hash(rects.join("|")) };
    } finally {
        container.remove();
    }
}
