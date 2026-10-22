import type { componentInterface } from "../../factory";

function readDoNotTrack(): "unspecified" | "0" | "1" {
    const nav = navigator as any;
    const raw = nav.doNotTrack ?? (window as any).doNotTrack ?? nav.msDoNotTrack;
    if (raw === "1" || raw === "yes" || raw === 1) return "1";
    if (raw === "0" || raw === "no" || raw === 0) return "0";
    return "unspecified";
}

export default async function getPrivacy(): Promise<componentInterface> {
    return {
        doNotTrack: readDoNotTrack(),
        globalPrivacyControl: (navigator as any).globalPrivacyControl === true,
        webdriver: (navigator as any).webdriver === true,
    };
}
