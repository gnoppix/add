#!/bin/bash
# Start Add Desktop UI with CLI integration

set -e

# Configuration - project root is current working directory parent
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLI_BINARY="$PROJECT_ROOT/target/release/eva"
PID_FILE="/home/amu/.add/add.pid"

# Cleanup stale PID lock
if [[ -f "$PID_FILE" ]]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null || echo "")
    if [[ -n "$OLD_PID" ]] && ! kill -0 "$OLD_PID" 2>/dev/null; then
        echo "Cleaning up stale PID lock"
        rm -f "$PID_FILE"
    fi
fi

# Build CLI if not exists
if [[ ! -f "$CLI_BINARY" ]]; then
    echo "Building eva CLI..."
    cd "$PROJECT_ROOT"
    cargo build --release -p add-client
fi

# Set environment and start
export ADD_CLI_PATH="$CLI_BINARY"
export NODE_ENV=development

echo "CLI path: $ADD_CLI_PATH"
cd "$SCRIPT_DIR"
npm run dev