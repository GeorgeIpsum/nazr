#!/usr/bin/env bash
# End-to-end smoke test for the compose stack. Assumes the stack is already up
# (docker compose -f deploy/compose/docker-compose.yml up -d --build).
# The stack is torn down on exit (down -v); KEEP=1 leaves it running.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(cd ../.. && pwd)"
BODY="$ROOT/apps/api/testdata/requests/stock-client-body.json"
COMPOSE=(docker compose -f docker-compose.yml)

for tool in curl jq docker; do
  command -v "$tool" >/dev/null || { echo "FAIL: required tool not found: $tool" >&2; exit 1; }
done

cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then
    echo "KEEP=1: leaving the stack running"
  else
    "${COMPOSE[@]}" --profile redis --profile dev down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

PASSED=0
fail() { echo "FAIL: $*" >&2; echo "RESULT: FAIL (${PASSED} checks passed before failure)" >&2; exit 1; }
ok() { PASSED=$((PASSED + 1)); echo "ok   - $*"; }

wait_ready() {
  local i code
  for i in $(seq 1 90); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/readyz || true)
    [ "$code" = 200 ] && return 0
    sleep 1
  done
  return 1
}

check_api() {
  local pass="$1" key r1 r2 id1 id2
  wait_ready || fail "[$pass] /readyz did not return 200 within 90s"
  ok "[$pass] /readyz 200"

  key=$("${COMPOSE[@]}" exec -T api /nazr keys create --label "smoke-$pass" | head -n1 | tr -d '\r\n')
  [ -n "$key" ] || fail "[$pass] could not create API key"
  ok "[$pass] key created"

  post() {
    curl -sk --http2 -X POST https://localhost/thumbmark \
      -H "x-api-key: $key" -H 'content-type: application/json' --data-binary "@$BODY"
  }
  r1=$(post)
  echo "$r1" | jq -e '.thumbmark | test("^[0-9a-f]{32}$")' >/dev/null || fail "[$pass] thumbmark format: $r1"
  ok "[$pass] thumbmark is 32 hex"
  if [ "$pass" = base ]; then
    echo "$r1" | jq -e '.components.tls.ja4 | type == "string" and length > 0' >/dev/null || fail "[$pass] missing tls.ja4: $r1"
    ok "[$pass] components.tls.ja4 present"
    echo "$r1" | jq -e '.components.h2.fingerprint | type == "string" and length > 0' >/dev/null || fail "[$pass] missing h2.fingerprint: $r1"
    ok "[$pass] components.h2.fingerprint present"
    echo "$r1" | jq -e '.info.visitor.isNew == true' >/dev/null || fail "[$pass] first visit not new: $r1"
    ok "[$pass] first visit isNew=true"
    r2=$(post)
    echo "$r2" | jq -e '.info.visitor.isNew == false' >/dev/null || fail "[$pass] second visit still new: $r2"
    id1=$(echo "$r1" | jq -r '.visitorId')
    id2=$(echo "$r2" | jq -r '.visitorId')
    [ -n "$id1" ] && [ "$id1" != null ] && [ "$id1" = "$id2" ] || fail "[$pass] visitorId changed: $id1 vs $id2"
    ok "[$pass] second visit isNew=false, same visitorId"
    curl -sf http://127.0.0.1:9090/metrics | grep -q nazr_requests_total || fail "[$pass] /metrics lacks nazr_requests_total"
    ok "[$pass] /metrics has nazr_requests_total"
  fi
  if "${COMPOSE[@]}" logs api 2>&1 | grep -q 'permission denied'; then
    fail "[$pass] 'permission denied' found in API logs"
  fi
  ok "[$pass] no 'permission denied' in API logs"
}

check_api base

echo "--- redis pass ---"
NAZR_REDIS_URL=redis://redis:6379 "${COMPOSE[@]}" --profile redis up -d >/dev/null 2>&1
check_api redis
keys=$("${COMPOSE[@]}" exec -T redis redis-cli dbsize | tr -dc '0-9')
[ "${keys:-0}" -ge 1 ] || fail "[redis] redis dbsize is ${keys:-empty}, expected >= 1"
ok "[redis] redis dbsize=$keys"
[ -n "$("${COMPOSE[@]}" exec -T redis redis-cli --scan --pattern 'nazr:*' | head -n1)" ] || fail "[redis] no nazr:* keys in redis"
ok "[redis] nazr:* keys present"

echo "RESULT: PASS ($PASSED checks)"
