import getPrivacy from "./index";

const nav = navigator as any;
const win = window as any;

function setProp(obj: any, key: string, value: unknown) {
    Object.defineProperty(obj, key, { value, configurable: true, writable: true });
}

afterEach(() => {
    for (const k of ["doNotTrack", "msDoNotTrack", "globalPrivacyControl", "webdriver"]) {
        delete nav[k];
    }
    delete win.doNotTrack;
});

describe("doNotTrack", () => {
    test("unspecified when nothing is set", async () => {
        setProp(nav, "doNotTrack", undefined);
        expect((await getPrivacy()).doNotTrack).toBe("unspecified");
    });
    test("reads navigator.doNotTrack first", async () => {
        setProp(nav, "doNotTrack", "1");
        setProp(win, "doNotTrack", "0");
        expect((await getPrivacy()).doNotTrack).toBe("1");
    });
    test("falls back to window.doNotTrack", async () => {
        setProp(nav, "doNotTrack", null);
        setProp(win, "doNotTrack", "0");
        expect((await getPrivacy()).doNotTrack).toBe("0");
    });
    test("falls back to navigator.msDoNotTrack", async () => {
        setProp(nav, "doNotTrack", undefined);
        setProp(nav, "msDoNotTrack", "1");
        expect((await getPrivacy()).doNotTrack).toBe("1");
    });
    test("maps 'unspecified' and null to 'unspecified'", async () => {
        setProp(nav, "doNotTrack", "unspecified");
        expect((await getPrivacy()).doNotTrack).toBe("unspecified");
        setProp(nav, "doNotTrack", null);
        expect((await getPrivacy()).doNotTrack).toBe("unspecified");
    });
    test("maps 'yes' to '1'", async () => {
        setProp(nav, "doNotTrack", "yes");
        expect((await getPrivacy()).doNotTrack).toBe("1");
    });
});

describe("globalPrivacyControl", () => {
    test("true only when exactly true", async () => {
        setProp(nav, "globalPrivacyControl", true);
        expect((await getPrivacy()).globalPrivacyControl).toBe(true);
        setProp(nav, "globalPrivacyControl", "true");
        expect((await getPrivacy()).globalPrivacyControl).toBe(false);
        delete nav.globalPrivacyControl;
        expect((await getPrivacy()).globalPrivacyControl).toBe(false);
    });
});

describe("webdriver", () => {
    test("false by default in jsdom", async () => {
        expect((await getPrivacy()).webdriver).toBe(false);
    });
    test("true only when navigator.webdriver === true", async () => {
        setProp(nav, "webdriver", true);
        expect((await getPrivacy()).webdriver).toBe(true);
        setProp(nav, "webdriver", 1);
        expect((await getPrivacy()).webdriver).toBe(false);
    });
});
