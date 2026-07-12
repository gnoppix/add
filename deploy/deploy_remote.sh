#!/bin/bash
# Remote deploy helper: swap .new binaries into place, restart daemons.
# Run on each server host (is/jp/me run relay+bootstrap; nl runs reflector).
set -u
cd /root/add
TS=$(date +%s)

swap() {
  local name="$1" new="$1.new"
  if [ ! -f "$new" ]; then echo "skip $name (no .new)"; return; fi
  if [ -f "$name" ]; then
    cp -f "$name" "$name.bak.$TS" && echo "backed up $name -> $name.bak.$TS"
  fi
  mv -f "$new" "$name" && chmod 755 "$name" && echo "swapped $name"
}

restart() {
  local name="$1"; shift
  local pid
  pid=$(pgrep -f "^\./$name" | head -1)
  if [ -n "$pid" ]; then kill "$pid" && echo "killed $name (pid $pid)"; sleep 1; fi
  setsid bash -c "cd /root/add && nohup ./$name $* >/root/add/$name.log 2>&1 &"
  sleep 1
  if pgrep -f "^\./$name" >/dev/null; then echo "restarted $name OK"; else echo "WARN: $name NOT running"; fi
}

# swap binaries
swap add
swap add-relay
swap add-bootstrap
swap add-reflector

# restart services based on which binaries exist
if [ -f /root/add/add-relay ]; then restart add-relay; fi
if [ -f /root/add/add-bootstrap ]; then restart add-bootstrap; fi
if [ -f /root/add/add-reflector ]; then restart add-reflector --port 44089; fi

echo "DEPLOY-DONE"
