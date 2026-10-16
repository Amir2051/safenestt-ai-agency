#!/usr/bin/env bash
# Capture the Hermes request sequence produced by one Base44 UI investigation.
# Run AFTER clicking "Run Full Pipeline" in the SafeNestT UI.
# Prints fingerprints/status only — never a credential.
L=/var/log/safenestt/engine.log
N=$(wc -l < "$L")
echo "=== Hermes log lines produced by that click ==="
tail -n "+$((N+1))" "$L" | sed 's/^/  /'
echo
echo "=== was the (verify) GET issued before /start ? ==="
tail -n "+$((N+1))" "$L" | grep -c '(verify)' | sed 's/^/  verify GETs: /'
echo
echo "=== does hermesStart log the '(verify)' marker at all? (source check) ==="
grep -c '(verify)' /home/ronzoro/safenestT/base44/functions/hermesStart/entry.ts | sed 's/^/  marker present in deployed source: /'
