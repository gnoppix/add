#!/bin/bash
# Verify relay runtime behavior
set -e

echo "=== Relay Runtime Verification ==="

PORT=19999
TESTDIR=$(mktemp -d /tmp/hermes-relay-verify-XXXXXX)
rm -rf "$TESTDIR"  # Let relay create it

# Start relay in background
RUSTFLAGS="" cargo run -p add-relay --release -- \
    --host 127.0.0.1 --port $PORT \
    --gpg-home "$TESTDIR" 2>&1 | tee /tmp/hermes-relay-run.txt &
RELAY_PID=$!

# Wait for startup
sleep 3

# Verify
PASS=0
FAIL=0

echo "[1] Relay started..."
if grep -q "listening on" /tmp/hermes-relay-run.txt; then
    echo "  OK"
    PASS=$((PASS+1))
else
    echo "  FAIL"
    FAIL=$((FAIL+1))
fi

echo "[2] No database error..."
if ! grep -q "Error: Database" /tmp/hermes-relay-run.txt; then
    echo "  OK"
    PASS=$((PASS+1))
else
    echo "  FAIL"
    FAIL=$((FAIL+1))
fi

echo "[3] No TLS warning (proxy mode)..."
if ! grep -q "TLS not configured" /tmp/hermes-relay-run.txt; then
    echo "  OK"
    PASS=$((PASS+1))
else
    echo "  FAIL"
    FAIL=$((FAIL+1))
fi

echo "[4] Database file created..."
if [ -f "$TESTDIR/mailbox.db" ]; then
    echo "  OK ($(stat -c%s "$TESTDIR/mailbox.db") bytes)"
    PASS=$((PASS+1))
else
    echo "  FAIL"
    FAIL=$((FAIL+1))
fi

# Cleanup
kill $RELAY_PID 2>/dev/null
wait $RELAY_PID 2>/dev/null
rm -rf "$TESTDIR" /tmp/hermes-relay-run.txt

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "=== PASSED ===" || echo "=== FAILED ==="
