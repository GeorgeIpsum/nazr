#!/usr/bin/env bash
# Print a unified diff of upstream ThumbmarkJS src/ vs this fork's src/.
# Usage: upstream-diff.sh [tag]   (default: contents of UPSTREAM)
#
# NOTE: on import, this repo's Biome (`biome check --write`) rewrote all
# upstream source (import type, let->const, import order, formatting). To avoid
# a noise-only diff, the upstream clone's src/ is first copied to
# <tmp>/packages/thumbmark/src, the root biome.json is copied to <tmp>/biome.json,
# and Biome is run on it before diffing. Exit code is 0 even if the diff is
# non-empty (inspection tool, not a check).
set -euo pipefail

PKG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$PKG/../.." && pwd)"
tag="${1:-$(tr -d '[:space:]' < "$PKG/UPSTREAM")}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet -c advice.detachedHead=false --depth 1 --branch "$tag" https://github.com/thumbmarkjs/thumbmarkjs.git "$tmp/clone"

mkdir -p "$tmp/norm/packages/thumbmark"
cp -R "$tmp/clone/src" "$tmp/norm/packages/thumbmark/src"
cp "$REPO/biome.json" "$tmp/norm/biome.json"
# Biome resolves biome.json from the cwd, so run it from the temp root.
(cd "$tmp/norm" && "$REPO/node_modules/.bin/biome" check --write packages/thumbmark/src) >/dev/null 2>&1 || true

cd "$tmp/norm/packages/thumbmark"
diff -ruN \
  --exclude=webgpu --exclude=clienthints --exclude=clientrects \
  --exclude=mediaqueries --exclude=privacy --exclude=endpoints.ts --exclude=endpoints.test.ts \
  src "$PKG/src" | sed "s#$PKG/src#ours/src#g" || true
