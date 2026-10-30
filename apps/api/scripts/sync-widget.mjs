// Copies the built @nazr/widget (dist/) into internal/widgetassets/assets/,
// which go:embed bakes into the binary. Without a built widget it warns and
// exits 0: the binary still builds and its widget routes return 404.
import { cpSync, existsSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const api = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(api, "node_modules", "@nazr", "widget", "dist");
const dest = join(api, "internal", "widgetassets", "assets");

if (!existsSync(src)) {
  console.warn(
    `sync-widget: ${src} not found; build @nazr/widget first. Widget routes will return 404.`,
  );
  process.exit(0);
}

// Clear stale output (old content-hashed bundles) but keep .gitkeep.
for (const name of readdirSync(dest)) {
  if (name !== ".gitkeep") rmSync(join(dest, name), { recursive: true, force: true });
}
cpSync(src, dest, { recursive: true });
console.log(`sync-widget: copied ${readdirSync(src).length} files into ${dest}`);
