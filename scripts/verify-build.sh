#!/bin/bash
# Full build verification
set -e

echo "=== Build Verification ==="

# 1. Check compiles
echo "[1] make check..."
make check 2>&1 | grep -E "^(error|OK)" | head -3

# 2. Build release
echo "[2] Building release..."
RUSTFLAGS="" cargo build --release --quiet 2>&1 | grep -E "Finished|error" | head -3

# 3. Version check
echo "[3] Version:"
./target/release/add-relay --version

echo "=== Build OK ==="
