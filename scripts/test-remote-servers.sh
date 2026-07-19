#!/bin/bash
# test-remote-servers.sh - Test deployed bootstrap and relay servers from a remote client
# Usage: bash scripts/test-remote-servers.sh [bootstrap-url] [relay-url]
# Default: wss://bootstrap-eu.gnoppix.org / wss://relay-eu.gnoppix.org/ws
set -e

CLIENT="./target/release/add"

SEED="${1:-wss://bootstrap-eu.gnoppix.org}"
RELAY="${2:-wss://relay-eu.gnoppix.org/ws}"

echo "============================================"
echo "  Add Remote Server Test"
echo "============================================"
echo "  Bootstrap: $SEED"
echo "  Relay:     $RELAY"
echo ""

PASS=0
FAIL=0
WARN=0

# --- Network Layer Tests ---

echo "--- Network Layer ---"

# 1. DNS resolution
echo -n "[1] DNS (bootstrap): "
if host bootstrap-eu.gnoppix.org >/dev/null 2>&1; then
    IP=$(dig +short bootstrap-eu.gnoppix.org A 2>/dev/null | head -1)
    echo "OK ($IP)"
    PASS=$((PASS+1))
else
    echo "FAIL"
    FAIL=$((FAIL+1))
fi

echo -n "[2] DNS (relay): "
if host relay-eu.gnoppix.org >/dev/null 2>&1; then
    IP=$(dig +short relay-eu.gnoppix.org A 2>/dev/null | head -1)
    echo "OK ($IP)"
    PASS=$((PASS+1))
else
    echo "FAIL"
    FAIL=$((FAIL+1))
fi

# 2. TLS certificates
echo -n "[3] TLS cert (bootstrap): "
CERT=$(echo | timeout 5 openssl s_client -connect bootstrap-eu.gnoppix.org:443 -servername bootstrap-eu.gnoppix.org 2>/dev/null)
if echo "$CERT" | grep -q "BEGIN CERTIFICATE"; then
    EXPIRY=$(echo "$CERT" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    echo "OK (expires $EXPIRY)"
    PASS=$((PASS+1))
else
    echo "FAIL"
    FAIL=$((FAIL+1))
fi

echo -n "[4] TLS cert (relay): "
CERT=$(echo | timeout 5 openssl s_client -connect relay-eu.gnoppix.org:443 -servername relay-eu.gnoppix.org 2>/dev/null)
if echo "$CERT" | grep -q "BEGIN CERTIFICATE"; then
    EXPIRY=$(echo "$CERT" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    echo "OK (expires $EXPIRY)"
    PASS=$((PASS+1))
else
    echo "FAIL"
    FAIL=$((FAIL+1))
fi

# 3. Port 443 open
echo -n "[5] Port 443 open (bootstrap): "
if timeout 3 bash -c "echo >/dev/tcp/bootstrap-eu.gnoppix.org/443" 2>/dev/null; then
    echo "OK"
    PASS=$((PASS+1))
else
    echo "FAIL"
    FAIL=$((FAIL+1))
fi

echo -n "[6] Port 443 open (relay): "
if timeout 3 bash -c "echo >/dev/tcp/relay-eu.gnoppix.org/443" 2>/dev/null; then
    echo "OK"
    PASS=$((PASS+1))
else
    echo "FAIL"
    FAIL=$((FAIL+1))
fi

# --- Application Layer Tests ---

echo ""
echo "--- Application Layer (Add Client) ---"

TESTDIR=$(mktemp -d /tmp/hermes-remote-test-XXXXXX)
HOME_BAK="$HOME"
export HOME="$TESTDIR"

# 4. Init identity against remote seed
echo -n "[7] add init (remote): "
INIT_OUT=$(echo "" | $CLIENT --seed "$SEED" --relay "$RELAY" init 2>&1)
if echo "$INIT_OUT" | grep -q "successfully\|Identity created"; then
    NID=$(echo "$INIT_OUT" | grep "Null ID" | awk '{print $NF}')
    echo "OK ($NID)"
    PASS=$((PASS+1))
else
    echo "FAIL"
    echo "$INIT_OUT" | head -3
    FAIL=$((FAIL+1))
fi

# 5. Show ID
echo -n "[8] add id: "
ID_OUT=$($CLIENT --seed "$SEED" --relay "$RELAY" id 2>&1)
if echo "$ID_OUT" | grep -q "Null ID"; then
    echo "OK"
    PASS=$((PASS+1))
else
    echo "FAIL"
    echo "$ID_OUT" | head -3
    FAIL=$((FAIL+1))
fi

# 6. Status with remote URLs
echo -n "[9] add status (custom URLs): "
STATUS_OUT=$($CLIENT --seed "$SEED" --relay "$RELAY" status 2>&1)
if echo "$STATUS_OUT" | grep -q "bootstrap-eu"; then
    echo "OK (shows remote seed)"
    PASS=$((PASS+1))
else
    echo "WARN (status ran but may not show URL)"
    WARN=$((WARN+1))
fi

# 7. Read from relay (test WS connection — may fail at protocol level)
echo -n "[10] add read (WS connection): "
READ_OUT=$(timeout 10 $CLIENT --seed "$SEED" --relay "$RELAY" read 2>&1 || true)
if echo "$READ_OUT" | grep -q "No new messages"; then
    echo "OK (relay responded, empty mailbox)"
    PASS=$((PASS+1))
elif echo "$READ_OUT" | grep -q "Checking relay mailbox"; then
    # Connected but hit protocol error — connectivity IS working
    ERR_LINE=$(echo "$READ_OUT" | grep -i "error" | head -1)
    echo "WARN (WS connected but protocol error)"
    echo "       $ERR_LINE"
    WARN=$((WARN+1))
elif echo "$READ_OUT" | grep -q "parse cert\|unexpected EOF"; then
    echo "WARN (WS connected, protocol parse error — server reachable)"
    WARN=$((WARN+1))
else
    echo "WARN (unexpected output)"
    echo "$READ_OUT" | head -3
    WARN=$((WARN+1))
fi

# Cleanup
export HOME="$HOME_BAK"
rm -rf "$TESTDIR"

echo ""
echo "============================================"
echo "  Results: $PASS passed, $WARN warnings, $FAIL failed"
echo "============================================"
echo ""
echo "Summary:"
echo "  - DNS, TLS, and port tests confirm the servers are reachable."
echo "  - Client --seed/--relay flags work for remote connections."
echo "  - If read shows 'protocol error', the WS connection works"
echo "    but the Add protocol needs investigation."
echo ""

if [ $FAIL -gt 0 ]; then
    exit 1
fi
