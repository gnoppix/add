#!/bin/bash
# Start a detached add-* binary on a remote host via SSH.
# Usage: scripts/start_remote.sh <host> <bin> [extra-args...]
set -u
host="$1"; bin="$2"; shift 2
extra="$*"
ssh -o ConnectTimeout=15 -o ServerAliveInterval=15 "$host" bash -c "'
  cd /root/add
  for p in \$(pgrep -f \"[a]dd-${bin#add-}\"); do kill -9 \"\$p\" 2>/dev/null; done
  sleep 1
  setsid ./'"$bin"' '"$extra"' > '"$bin"'.log 2>&1 < /dev/null &
  disown
'"
sleep 2
ssh -o ConnectTimeout=15 "$host" "ps -eo pid,args | grep '[a]dd-${bin#add-}' | grep -v grep; ss -tlnp 2>/dev/null | grep -q 9001 && echo 9001_OK; ss -tlnp 2>/dev/null | grep -q 44089 && echo 44089_OK"
