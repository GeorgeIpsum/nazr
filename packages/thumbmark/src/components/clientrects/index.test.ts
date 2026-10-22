import getClientRects from "./index";

test("resolves null when document.body is missing", async () => {
    const spy = jest.spyOn(document, "body", "get").mockReturnValue(null as any);
    try {
        expect(await getClientRects()).toBeNull();
    } finally {
        spy.mockRestore();
    }
});

test("resolves five rect strings and a 32-char hex hash", async () => {
    const r: any = await getClientRects();
    expect(r.rects).toHaveLength(5);
    for (const rect of r.rects) {
        expect(rect).toMatch(/^-?\d+\.\d{2},-?\d+\.\d{2},-?\d+\.\d{2},-?\d+\.\d{2}$/);
    }
    expect(r.hash).toMatch(/^[0-9a-f]{32}$/);
});

test("hashes rects joined by '|'", async () => {
    const { hash } = await import("../../utils/hash");
    const r: any = await getClientRects();
    expect(r.hash).toBe(hash(r.rects.join("|")));
});

test("builds five probe elements with the exact styles and removes the container", async () => {
    const before = document.body.children.length;
    let snapshot: Element | null = null;
    const orig = Element.prototype.getBoundingClientRect;
    const spy = jest.spyOn(Element.prototype, "getBoundingClientRect").mockImplementation(function (
        this: Element,
    ) {
        if (!snapshot && this.parentElement?.parentElement === document.body) {
            snapshot = this.parentElement.cloneNode(true) as Element;
        }
        return orig.call(this);
    });
    try {
        await getClientRects();
    } finally {
        spy.mockRestore();
    }
    expect(document.body.children.length).toBe(before);
    expect(document.body.querySelector("svg")).toBeNull();
    const html = (snapshot as unknown as Element).outerHTML;
    expect(html).toContain("left: -9999px");
    expect(html).toContain("visibility: hidden");
    expect(html).toContain("nazr clientrects probe");
    expect(html).toContain("rotate(13deg)");
    expect(html).toContain("1.31em");
    expect((snapshot as unknown as Element).querySelector("svg rect")).not.toBeNull();
});
