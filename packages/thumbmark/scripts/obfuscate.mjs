// Rollup output plugin that obfuscates the drop-in UMD bundle only. The ESM and
// CJS builds stay readable for integrators and forkers; this targets the
// <script>-tag bundle served from CDNs, where analysis resistance matters.
import JavaScriptObfuscator from "javascript-obfuscator";

/** @type {import("javascript-obfuscator").ObfuscatorOptions} */
export const OBFUSCATOR_OPTIONS = {
    target: "browser",
    compact: true,
    // Names: mangle locals to hex. Never rename globals (the UMD wrapper must
    // still assign `ThumbmarkJS`) or properties (component keys and option
    // names are wire format and feed the hash). transformObjectKeys moves
    // object-literal keys into the string array, preserving insertion order,
    // but it skips any object whose values contain an arrow function. That
    // leaves the component registry's keys readable; they are sent in plain
    // JSON on every request anyway.
    identifierNamesGenerator: "hexadecimal",
    renameGlobals: false,
    renameProperties: false,
    transformObjectKeys: true,
    // Literals: every string moves into an rc4-encoded, rotated, shuffled
    // array reached through wrapper functions.
    stringArray: true,
    stringArrayThreshold: 1,
    stringArrayEncoding: ["rc4"],
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayIndexShift: true,
    stringArrayCallsTransform: true,
    stringArrayCallsTransformThreshold: 0.75,
    stringArrayWrappersCount: 2,
    stringArrayWrappersType: "function",
    stringArrayWrappersChainedCalls: true,
    splitStrings: true,
    splitStringsChunkLength: 16,
    unicodeEscapeSequence: false,
    numbersToExpressions: true,
    // Control flow: flatten and pad with unreachable code. Thresholds below 1
    // keep the hash and pixel loops from paying the full dispatch cost. Dead
    // code is kept low: at 0.3 it doubled the gzipped bundle for little gain.
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.5,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.1,
    simplify: true,
    // Tamper resistance: reformatting breaks the bundle, and an open debugger
    // is stalled once at load. No interval, so a visitor who keeps DevTools
    // open is not trapped in a loop.
    selfDefending: true,
    debugProtection: true,
    debugProtectionInterval: 0,
    disableConsoleOutput: false,
    sourceMap: false,
    // Fixed seed: the same source always yields the same bundle (0 means random).
    seed: 0x6e617a72,
};

/** @returns {import("rollup").Plugin} */
export function obfuscate(options = OBFUSCATOR_OPTIONS) {
    return {
        name: "nazr-obfuscate",
        renderChunk(code) {
            return {
                code: JavaScriptObfuscator.obfuscate(code, options).getObfuscatedCode(),
                map: null,
            };
        },
    };
}
