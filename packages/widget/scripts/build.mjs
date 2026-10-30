// Builds the widget for embedding in the Go server: loader.js (stable name,
// served at /widget/v1/loader.js), frame.<hash>.js (content-addressed so it can
// be cached forever), frame.html (a Go html/template whose {{.Bundle}} is the
// hashed bundle name) and manifest.json naming the bundle.
import { createHash } from "node:crypto";
import { copyFile, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");

async function bundle(entry) {
  const result = await build({
    entryPoints: [join(root, "src/entries", entry)],
    format: "iife",
    bundle: true,
    minify: true,
    target: "es2020",
    write: false,
  });
  return result.outputFiles[0].contents;
}

const [loader, frame] = await Promise.all([bundle("loader.ts"), bundle("frame.ts")]);
const frameName = `frame.${createHash("sha256").update(frame).digest("hex").slice(0, 8)}.js`;

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await Promise.all([
  writeFile(join(dist, "loader.js"), loader),
  writeFile(join(dist, frameName), frame),
  copyFile(join(root, "src/frame.html"), join(dist, "frame.html")),
  writeFile(join(dist, "manifest.json"), `${JSON.stringify({ frame: frameName })}\n`),
]);

console.log(`built dist/loader.js, dist/${frameName}, dist/frame.html, dist/manifest.json`);
