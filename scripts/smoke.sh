#!/usr/bin/env bash
# End-to-end smoke test for httpsigcheck: builds the binary and drives
# every subcommand against the committed example files, asserting on
# real CLI output and exit codes. No network, idempotent, pinned clock.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/httpsigcheck"
NOW=1783814400 # the examples' created/iat timestamp, pinned for determinism

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/httpsigcheck) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -qx "httpsigcheck 0.1.0" || fail "--version mismatch"

echo "3. verify the signed example request (ed25519 + content-digest)"
OUT="$("$BIN" verify --key "$ROOT/examples/ed25519-public.pem" --now "$NOW" \
  "$ROOT/examples/signed-request.http")"
echo "$OUT" | grep -q "verify: PASS (1 of 1 signature valid)" || fail "expected PASS"
echo "$OUT" | grep -q '| "@method": POST' || fail "signature base not shown"
echo "$OUT" | grep -q "sha-256  ok" || fail "content-digest check missing"

echo "4. tampered body fails via content-digest, exit 1"
set +e
OUT="$("$BIN" verify --key "$ROOT/examples/ed25519-public.pem" --now "$NOW" \
  "$ROOT/examples/tampered-request.http")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "tampered request should exit 1, got $CODE"
echo "$OUT" | grep -q "content was modified after signing" || fail "tamper not explained"
echo "$OUT" | grep -q "but a content-digest check failed" || fail "verdict does not explain the digest failure"

echo "5. base subcommand prints the exact signature base"
"$BIN" base "$ROOT/examples/signed-request.http" \
  | grep -qx '"@authority": api.example.test' || fail "base line missing"

echo "6. base --components builds an ad-hoc base"
printf 'GET /status?probe=1 HTTP/1.1\nHost: api.example.test\n\n' > "$WORKDIR/plain.http"
"$BIN" base --components '("@method" "@query")' "$WORKDIR/plain.http" \
  | grep -qx '"@query": ?probe=1' || fail "ad-hoc base wrong"

echo "7. verify the DPoP proof (ES256, embedded JWK)"
OUT="$("$BIN" dpop --method POST --url https://as.example.test/token --now "$NOW" \
  "$ROOT/examples/dpop-proof.jwt")"
echo "$OUT" | grep -q "dpop: PASS" || fail "expected DPoP PASS"
echo "$OUT" | grep -q "0hIJc9x8a1ZPgKvi46zZs9i7Q-X2xwEseMpnBR3Hq24" || fail "thumbprint missing"

echo "8. the same proof for another URL fails, exit 1"
set +e
"$BIN" dpop --method POST --url https://evil.example.test/token --now "$NOW" \
  "$ROOT/examples/dpop-proof.jwt" > /dev/null
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "wrong URL should exit 1, got $CODE"

echo "9. JSON output is machine-readable"
"$BIN" verify --format json --key "$ROOT/examples/ed25519-public.pem" --now "$NOW" \
  "$ROOT/examples/signed-request.http" | grep -q '"schema_version": 1' || fail "json envelope missing"

echo "10. usage errors exit 2"
set +e
"$BIN" verify --format yaml "$ROOT/examples/signed-request.http" >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --format should exit 2"
"$BIN" frobnicate >/dev/null 2>&1
[ $? -eq 2 ] || fail "unknown command should exit 2"
set -e

echo "SMOKE OK"
