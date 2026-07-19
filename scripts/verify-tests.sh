#!/bin/bash
# Run all unit tests (excluding dht-core SQLite tests)

echo "=== Unit Tests ==="

echo "[1] add-crypto..."
cargo test -p add-crypto --lib --quiet 2>&1 | tail -1

echo "[2] add-protocol..."
cargo test -p add-protocol --lib --quiet 2>&1 | tail -1

echo "[3] add-p2p..."
cargo test -p add-p2p --lib --quiet 2>&1 | tail -1

echo "[4] add-relay..."
cargo test -p add-relay --quiet 2>&1 | tail -1

echo "[5] add-client..."
cargo test -p add-client --quiet 2>&1 | tail -1

echo "=== Tests Complete ==="
