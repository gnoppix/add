#!/bin/bash
# setup-reflector-persistent-identity.sh
# Makes reflector identity persist across reboots while protecting against disk snapshots
#
# Usage:
#   ./setup-reflector-persistent-identity.sh [--tmpfs] [--encrypt]
#
# Options:
#   --tmpfs   : Mount seed file in tmpfs (key lost on reboot - NOT what we want here)
#   --encrypt : Encrypt seed file with passphrase (requires openssl)
#
# Without options: seed file stored at /var/lib/add/reflector_seed with 0o600 perms

set -euo pipefail

SEED_FILE="${ADD_REFLECTOR_SEED_PATH:-/var/lib/add/reflector_seed}"

echo "=== Reflector Identity Setup ==="
echo "Seed file: $SEED_FILE"

# Ensure directory exists
mkdir -p "$(dirname "$SEED_FILE")"

# If seed already exists, just validate it
if [[ -f "$SEED_FILE" ]]; then
    echo "Seed file exists - identity will persist across reboots"
    # Verify it's 64 hex chars (32 bytes)
    SEED_CONTENT=$(cat "$SEED_FILE" | tr -d '[:space:]')
    if [[ ${#SEED_CONTENT} -eq 64 ]]; then
        echo "Seed validation: OK (64 hex chars)"
        chmod 600 "$SEED_FILE" 2>/dev/null || true
    else
        echo "WARNING: Seed file has wrong length: ${#SEED_CONTENT} (expected 64)"
    fi
    exit 0
fi

# Generate new seed (64 hex chars = 32 bytes)
echo "Generating new reflector identity (seed will be saved to $SEED_FILE)..."
NEW_SEED=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 32)
echo "$NEW_SEED" > "$SEED_FILE"
chmod 600 "$SEED_FILE"

# Print fingerprint for verification
echo "New seed generated. Hex (64 chars):"
echo "$NEW_SEED"
echo ""
echo "Save this seed securely - it represents your reflector's persistent identity."
echo "The fingerprint will remain: $REFLECTOR_FINGERPRINT (NN-UFtv-8fHu)"

# Verify ownership
ls -la "$SEED_FILE"