import type { componentInterface } from "../factory";
import type { ThumbmarkError } from "../functions";
import type { optionsInterface } from "../options";
import { resolveLogEndpoint } from "./endpoints";
import { getVersion } from "./version";

// ===================== Logging (Internal) =====================

/**
 * Logs thumbmark data to remote logging endpoint (only once per session)
 * You can disable this by setting options.logging to false.
 * @internal
 */
export async function logThumbmarkData(
    thisHash: string,
    thumbmarkData: componentInterface,
    options: optionsInterface,
    errors: ThumbmarkError[] = [],
): Promise<void> {
    const url = resolveLogEndpoint(options);

    sessionStorage.setItem("_tmjs_l", "1");

    // Never send the API key to the log endpoint (mirrors api.ts).
    const { api_key: _omitApiKey, ...optionsForBody } = options;

    const payload = {
        thumbmark: thisHash,
        components: thumbmarkData,
        experimental: null,
        version: getVersion(),
        options: optionsForBody,
        path: window?.location?.pathname,
        ...(errors.length > 0 && { errors }),
    };

    try {
        await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });
    } catch {
        /* do nothing */
    }
}
