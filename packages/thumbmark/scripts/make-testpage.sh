#!/usr/bin/env bash
# Create testpage/ for Playwright e2e (mirrors upstream's Makefile `bld` step,
# which copied the UMD bundle into ./testpage). Specs load /index.html (which
# exposes the global ThumbmarkJS), /dist/thumbmark.umd.js and /dist/thumbmark.esm.js. Idempotent.
#
# NOTE: a stale dist/ is NOT rebuilt (the build only runs when
# dist/thumbmark.umd.js is missing). After changing source, run `pnpm build`
# manually before re-running this script or `pnpm test:e2e`.
set -euo pipefail

PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PKG"

if [ ! -f dist/thumbmark.umd.js ]; then
  pnpm build
fi

rm -rf testpage
mkdir -p testpage/dist
cp dist/thumbmark.umd.js testpage/dist/thumbmark.umd.js
cp dist/thumbmark.umd.js testpage/thumbmark.umd.js
# The readable ESM build, so e2e can check the obfuscated UMD against it.
cp dist/thumbmark.esm.js testpage/dist/thumbmark.esm.js
cat > testpage/index.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>thumbmark e2e</title></head>
  <body>
    <script src="/dist/thumbmark.umd.js"></script>
  </body>
</html>
HTML
# Strict CSP (no unsafe-eval): the obfuscated bundle must run without eval.
cat > testpage/csp.html <<'HTML'
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="script-src 'self'">
    <title>thumbmark e2e csp</title>
  </head>
  <body>
    <script src="/dist/thumbmark.umd.js"></script>
  </body>
</html>
HTML
