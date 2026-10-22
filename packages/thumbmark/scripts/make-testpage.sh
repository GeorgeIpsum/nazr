#!/usr/bin/env bash
# Create testpage/ for Playwright e2e (mirrors upstream's Makefile `bld` step,
# which copied the UMD bundle into ./testpage). Specs load /index.html (which
# exposes the global ThumbmarkJS) and /dist/thumbmark.umd.js. Idempotent.
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
cat > testpage/index.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8"><title>thumbmark e2e</title></head>
  <body>
    <script src="/dist/thumbmark.umd.js"></script>
  </body>
</html>
HTML
