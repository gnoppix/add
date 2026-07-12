#!/bin/bash
# Run the Add reflector on nl (always-on echo client).
# Usage: bash run_reflector_nl.sh   (run from a host with ssh access to nl)
set -e
ADD_BIN=/root/add/add
LOG=/root/add/reflector.log
ssh -o ConnectTimeout=20 -o BatchMode=yes nl bash -s <<EOF
pkill -9 -f "[a]dd reflect" 2>/dev/null || true
sleep 1
nohup env ADD_HOME=/root/.add $ADD_BIN reflect --interval 8 --ttl 24h >$LOG 2>&1 &
disown
sleep 1
pgrep -af "[a]dd reflect" | head -1
EOF
