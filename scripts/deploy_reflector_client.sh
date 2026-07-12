#!/bin/bash
# Deploy the Reflector as a thin always-online client:
#   add reflect  (reuses the real client send/receive paths)
# Replaces the old standalone add-reflector binary on the nl host.
set -u
SRC_DIR="target/release"
REMOTE_DIR="/root/add"
REMOTE_HOME="/root"
IDENTITY_DIR="$REMOTE_HOME/.add"
host="nl"

# Reflector identity (matches the DHT addr_record key NN-UFtv-8fHu)
FP="3957378550B111F2678DC1B4A58C27B22091D5CF"
NULL_ID="NN-UFtv-8fHu"
# base64 of the 32-byte raw ML-DSA-87 secret key (from bot/reflector_private_ml_dsa87.key)
SK_B64="XyodsH7G0KG5o74JHfg+NFr87aZVM0ozIX8dXdJ/cJY="

echo "==> uploading new 'add' binary"
scp -o ConnectTimeout=20 -o BatchMode=yes \
    "$SRC_DIR/add" "$host:$REMOTE_DIR/add.new" || { echo "scp add failed"; exit 1; }
ssh -o ConnectTimeout=20 -o BatchMode=yes "$host" "chmod +x '$REMOTE_DIR/add.new' && mv -f '$REMOTE_DIR/add.new' '$REMOTE_DIR/add' && echo swapped"

echo "==> seeding reflector identity at $IDENTITY_DIR/identity.json"
ssh -o ConnectTimeout=20 -o BatchMode=yes "$host" bash -s <<EOF
set -e
mkdir -p '$IDENTITY_DIR'
cat > '$IDENTITY_DIR/identity.json' <<JSON
{
  "fingerprint": "$FP",
  "null_id": "$NULL_ID",
  "ml_dsa87_signing_key": "$SK_B64"
}
JSON
chmod 600 '$IDENTITY_DIR/identity.json'
echo "identity seeded: \$(cat '$IDENTITY_DIR/identity.json')"
EOF

echo "==> stopping old standalone reflector (if any)"
ssh -o ConnectTimeout=20 -o BatchMode=yes "$host" "pkill -f '[a]dd-reflector' || true; sleep 1; echo stopped-old"

echo "==> launching 'add reflect' (always-online echo client)"
# Use setsid + disown + redirect so the process survives the SSH session and
# the ssh command returns immediately (do NOT capture pgrep here — it makes
# the session block on the backgrounded subshell's stdout).
ssh -o ConnectTimeout=20 -o BatchMode=yes "$host" bash -s <<'EOF'
set -e
cd /root/add
pkill -9 -f '[a]dd reflect' 2>/dev/null || true
sleep 1
setsid bash -c 'ADD_HOME=/root/.add ./add reflect --interval 5 --ttl 24h > /root/add/reflector.log 2>&1' < /dev/null &
disown
exit 0
EOF
echo "==> launched (verify with: ssh nl 'pgrep -af [a]dd reflect')"
