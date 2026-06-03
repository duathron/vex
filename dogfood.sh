#!/usr/bin/env bash
# Dogfood gate for vex — offline always; live VirusTotal tier when a credential
# is available (VT_API_KEY env OR vex's own config, e.g. ~/.vex/config.yaml).
# Framework QA policy: no release without a dogfood pass. Skip != pass.
set -uo pipefail

fail=0

crashed() {  # detect a real unhandled crash by its Python traceback signature
  printf '%s' "$1" | grep -q 'Traceback (most recent call last)'
}

echo "== offline =="
out="$(vex version 2>&1)" || { echo "FAIL: vex version"; fail=1; }
crashed "$out" && { echo "FAIL: vex version crashed"; fail=1; }
out="$(vex --help 2>&1)" || true; crashed "$out" && { echo "FAIL: vex --help crashed"; fail=1; }
if [ "$fail" -ne 0 ]; then echo "DOGFOOD: FAIL (offline)"; exit 1; fi

# Detect a live credential via a canary lookup (works for env var OR ~/.vex/config.yaml),
# instead of assuming the env var — vex reads its own config too.
echo "== live (real VirusTotal) =="
canary="$(vex triage 8.8.8.8 2>&1)" || true
if printf '%s' "$canary" | grep -qiE 'no api key|api key.*(not|missing|required)|set .*VT_API_KEY|provide .*api key'; then
  echo "DOGFOOD: OFFLINE PASS — LIVE SKIPPED (no VT credential)."
  echo "Skip != pass: configure a key (VT_API_KEY env or ~/.vex/config.yaml) before any release."
  exit 3
fi
if crashed "$canary"; then echo "DOGFOOD FAIL: triage 8.8.8.8 crashed"; printf '%s\n' "$canary" | tail -5; fail=1; fi

for i in "example.com" "https://example.com" "report.dll" "/etc/passwd" "a sentence." ""; do
  out="$(vex triage "$i" 2>&1)" || true
  if crashed "$out"; then echo "DOGFOOD FAIL: triage '$i' crashed"; printf '%s\n' "$out" | tail -5; fail=1; fi
done
# Deep path exercises PE-info parsing (the int machine_type bug class).
# Set VEX_DOGFOOD_PE_HASH to a known real PE sha256 to include it.
if [ -n "${VEX_DOGFOOD_PE_HASH:-}" ]; then
  out="$(vex investigate "$VEX_DOGFOOD_PE_HASH" 2>&1)" || true
  if crashed "$out"; then echo "DOGFOOD FAIL: investigate PE crashed"; printf '%s\n' "$out" | tail -8; fail=1; fi
fi

if [ "$fail" -ne 0 ]; then echo "DOGFOOD: FAIL (live)"; exit 1; fi
echo "DOGFOOD: PASS (offline + live)"
