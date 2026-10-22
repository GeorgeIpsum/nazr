import { DEFAULT_API_ENDPOINT, DEFAULT_COLLECT_ENDPOINT, type optionsInterface } from "../options";

function trimTrailingSlashes(url: string): string {
    return url.replace(/\/+$/, "");
}

/** Log endpoint: `${api_endpoint}/log`, falling back to the hosted default. */
export function resolveLogEndpoint(options: Pick<optionsInterface, "api_endpoint">): string {
    return `${trimTrailingSlashes(options.api_endpoint || DEFAULT_API_ENDPOINT)}/log`;
}

/** Beacon endpoint: explicit `collect_endpoint`, else `${api_endpoint}/beacon`, else hosted default. */
export function resolveCollectEndpoint(
    options: Pick<optionsInterface, "api_endpoint" | "collect_endpoint">,
): string {
    if (options.collect_endpoint) return options.collect_endpoint;
    if (options.api_endpoint) return `${trimTrailingSlashes(options.api_endpoint)}/beacon`;
    return DEFAULT_COLLECT_ENDPOINT;
}
