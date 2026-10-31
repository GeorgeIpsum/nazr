// Builds the widget for embedding in the Go server: loader.js (stable name,
// served at /widget/v1/loader.js), frame.<hash>.js and worker.<hash>.js
// (content-addressed so they can be cached forever), frame.html (a Go
// html/template with {{.Bundle}}, {{.Worker}}, {{.Challenge}}, {{.PowBits}} and
// {{.Origin}}) and manifest.json naming the frame and worker bundles.
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

const [loader, frame, worker] = await Promise.all([
  bundle("loader.ts"),
  bundle("frame.ts"),
  bundle("worker.ts"),
]);
const hash8 = (buf) => createHash("sha256").update(buf).digest("hex").slice(0, 8);
const frameName = `frame.${hash8(frame)}.js`;
const workerName = `worker.${hash8(worker)}.js`;

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await Promise.all([
  writeFile(join(dist, "loader.js"), loader),
  writeFile(join(dist, frameName), frame),
  writeFile(join(dist, workerName), worker),
  copyFile(join(root, "src/frame.html"), join(dist, "frame.html")),
  writeFile(
    join(dist, "manifest.json"),
    `${JSON.stringify({ frame: frameName, worker: workerName })}\n`,
  ),
]);

console.log(
  `built dist/loader.js, dist/${frameName}, dist/${workerName}, dist/frame.html, dist/manifest.json`,
);
