import { includeComponent } from "./factory";
import { getThumbmark, ThumbmarkError, ThumbmarkResponse } from "./functions";
import { filterThumbmarkData } from "./functions/filterComponents";
import {
    getFingerprint,
    getFingerprintData,
    getFingerprintPerformance,
} from "./functions/legacy_functions";
import { optionsInterface, setOption, stabilizationExclusionRules } from "./options";
import { Thumbmark } from "./thumbmark";
import { hash } from "./utils/hash";
import { stableStringify } from "./utils/stableStringify";
import { getVersion } from "./utils/version";

export {
    // Filtering functions for server-side use
    filterThumbmarkData,
    getFingerprint,
    getFingerprintData,
    getFingerprintPerformance,
    getThumbmark,
    getVersion,
    hash,
    includeComponent,
    optionsInterface,
    // deprecated functions. Don't use anymore.
    setOption,
    stabilizationExclusionRules,
    // Stable JSON stringify for consistent hashing
    stableStringify,
    Thumbmark,
    ThumbmarkError,
    ThumbmarkResponse,
};
