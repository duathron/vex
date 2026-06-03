#!/usr/bin/env bash
# Dogfood gate for vex — offline always; live VirusTotal tier when VT_API_KEY is set.
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

if [ -z "${VT_API_KEY:-}" ]; then
  echo "DOGFOOD: OFFLINE PASS — LIVE SKIPPED (no VT_API_KEY)."
  echo "Skip != pass: run with VT_API_KEY set before any release."
  exit 3
fi

echo "== live (real VirusTotal) =="
for i in "8.8.8.8" "example.com" "https://example.com" "report.dll" "/etc/passwd" "a sentence." ""; do
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
