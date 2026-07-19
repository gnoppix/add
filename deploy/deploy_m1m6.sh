#!/usr/bin/env bash
# Deploy M1-M6 patched binaries to the four hosts.
# Conventions (per session memory):
#   is=eu bootstrap, jp=asia bootstrap, me=us bootstrap+relay, nl=reflector(:44089)
#   binaries in /root/add, run detached via setsid (no systemd)
#   backup convention: <bin>.bak.<epoch>
set -u
EPOCH=$(date +%s)
ROOT=/home/amu/Gnoppix/messenger/Add
SRC=$ROOT/target/release

# host:binaries  (me gets relay+bootstrap, others get relay+bootstrap too except nl gets reflector)
declare -A HOST_BINS=(
  [is]="add add-relay add-bootstrap"
  [jp]="add add-relay add-bootstrap"
  [me]="add add-relay add-bootstrap"
  [nl]="add add-reflector"
)

for host in is jp me nl; do
  bins=${HOST_BINS[$host]}
  echo "=== deploying to $host ==="
  # 1. scp each binary as <name>.new
  for b in $bins; do
    scp -q "$SRC/$b" "root@$host:/root/add/$b.new" || { echo "SCP FAIL $host $b"; continue; }
  done
  # 2. atomic swap + backup + restart on the host
  ssh -q "root@$host" bash -s <<EOF
set -e
for b in $bins; do
  cd /root/add
  if [ -f "\$b.new" ]; then
    cp -f "\$b" "\$b.bak.$EPOCH" 2>/dev/null || true
    mv -f "\$b.new" "\$b"
    chmod +x "\$b"
    # kill old instance, restart detached
    pkill -f "/root/add/\$b" 2>/dev/null || true
    sleep 1
    setsid nohup "/root/add/\$b" >/dev/null 2>&1 &
  fi
done
EOF
  echo "=== $host done ==="
done
echo "ALL DEPLOYED"
