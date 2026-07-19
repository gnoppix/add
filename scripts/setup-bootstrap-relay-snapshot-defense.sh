#!/bin/bash
# setup-bootstrap-relay-snapshot-defense.sh
# Protects against disk snapshots while maintaining persistent identity
# Separates: (1) identity keys (persist) + (2) snapshot defense shards (tmpfs)

set -e

SERVICE_TYPE="${1:-bootstrap}"  # bootstrap or relay
STATE_DIR="$HOME/.add"
SHARD_DIR="/var/run/add-sd-shards"  # tmpfs for snapshot defense shards ONLY

echo "=== Snapshot Defense Setup for $SERVICE_TYPE ==="

# Step 1: Protect SHARD directories (tmpfs) - separate from identity keys
mkdir -p "$SHARD_DIR"/{oht-0,oht-1,oht-2}
chmod 700 "$SHARD_DIR"
chmod 700 "$SHARD_DIR"/{oht-0,oht-1,oht-2}

# Mount tmpfs for shards (key for sealed sender protection)
if ! grep -q "tmpfs.*$SHARD_DIR" /proc/mounts 2>/dev/null; then
    echo "Mounting $SHARD_DIR as tmpfs for snapshot defense..."
    mount -t tmpfs -o mode=700,size=1M nodev tmpfs "$SHARD_DIR" 2>/dev/null || {
        echo "WARNING: Cannot mount tmpfs - shards will be on persistent storage"
    }
fi

# Step 2: Create symlink or copy shards at boot
# The code expects shards in ~/.add/oht-* but we want them in tmpfs
# Option: Symlink ~/.add/oht-* to $SHARD_DIR/oht-*
mkdir -p "$STATE_DIR"
for i in 0 1 2; do
    if [ ! -L "$STATE_DIR/oht-$i" ]; then
        rm -rf "$STATE_DIR/oht-$i" 2>/dev/null || true
        ln -sf "$SHARD_DIR/oht-$i" "$STATE_DIR/oht-$i"
    fi
done

# Step 3: Generate shards (identity keys remain in ~/.add persistently)
echo "Initializing snapshot defense shards (identity keys unchanged)..."
python3 << 'PYTHON_SCRIPT'
import os, base64

def gf_mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = ((a << 1) & 0xFF) ^ (0x1D if hi else 0)
        b >>= 1
    return p

key = os.urandom(32)
state_dir = os.environ.get("SHARD_DIR", "/var/run/add-sd-shards")

a = os.urandom(32)
for x in [1, 2, 3]:
    y = bytes([key[i] ^ gf_mul(a[i], x) for i in range(32)])
    shard_path = f"{state_dir}/oht-{x-1}/shard.bin"
    with open(shard_path, "wb") as f:
        f.write(bytes([x]) + y)
    print(f"Created shard: {shard_path}")
PYTHON_SCRIPT

chmod 600 "$SHARD_DIR"/{oht-0,oht-1,oht-2}/shard.bin 2>/dev/null || true

# Step 4: Add to fstab for persistent tmpfs mount
grep -q "tmpfs $SHARD_DIR" /etc/fstab || echo "tmpfs $SHARD_DIR tmpfs mode=700,size=1M 0 0" >> /etc/fstab

echo ""
echo "=== Setup Complete ==="
echo "Identity keys: Persistent at $STATE_DIR/kyber_keypair.json or $STATE_DIR/gnupg/"
echo "Snapshot shards: tmpfs at $SHARD_DIR/oht-{0,1,2}"
echo ""
echo "After reboot: shards lost, but identity restored from ~/.add"
echo "Boot script must re-create shards:"
echo "  python3 -c '...' # Regenerate shards or restore from backup"
echo ""
echo "For automated: Add systemd service to recreate shards at boot"