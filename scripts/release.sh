#!/bin/bash
# Full release verification and build
set -e

echo "==================================="
echo "  Add Release Verification"
echo "==================================="

# Step 1: Build
echo ""
echo ">>> STEP 1: Build Check"
make check 2>&1 | grep -E "^(error|OK)" | head -3

# Step 2: Tests
echo ""
echo ">>> STEP 2: Unit Tests"
cargo test -p add-crypto --lib --quiet 2>&1 | tail -1
cargo test -p add-protocol --lib --quiet 2>&1 | tail -1
cargo test -p add-p2p --lib --quiet 2>&1 | tail -1
cargo test -p add-relay --quiet 2>&1 | tail -1

# Step 3: Build release
echo ""
echo ">>> STEP 3: Release Build"
RUSTFLAGS="" cargo build --release --quiet 2>&1 | grep -E "Finished|error" | head -3

# Step 4: Version
echo ""
echo ">>> STEP 4: Version"
VERSION=$(./target/release/add-relay --version)
echo "  $VERSION"

# Step 5: Relay runtime test
echo ""
echo ">>> STEP 5: Relay Runtime Test"
TESTDIR=$(mktemp -d /tmp/hermes-release-XXXXXX)
rm -rf "$TESTDIR"
timeout 3 ./target/release/add-relay --host 127.0.0.1 --port 19997 --gpg-home "$TESTDIR" 2>&1 | tee /tmp/hermes-release-relay.txt
if grep -q "listening on" /tmp/hermes-release-relay.txt && ! grep -q "Error" /tmp/hermes-release-relay.txt; then
    echo "  OK: Relay starts cleanly"
else
    echo "  FAIL: Relay has errors"
    exit 1
fi
rm -rf "$TESTDIR" /tmp/hermes-release-relay.txt

# Step 6: Binary sizes
echo ""
echo ">>> STEP 6: Binaries"
ls -lh target/release/add target/release/add-relay target/release/add-bootstrap 2>/dev/null | awk '{print "  " $9 "  " $5}'

echo ""
echo "==================================="
echo "  Release $VERSION Ready"
echo "==================================="
