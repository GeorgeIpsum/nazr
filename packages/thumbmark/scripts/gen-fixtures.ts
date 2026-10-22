import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildFixtures } from "./fixtures";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, "../../../apps/api/testdata/fixtures");
mkdirSync(outDir, { recursive: true });

const f = buildFixtures();
for (const [name, data] of Object.entries(f)) {
    writeFileSync(resolve(outDir, `${name}.json`), `${JSON.stringify(data, null, 2)}\n`);
}
console.log(`wrote fixtures to ${outDir}`);
