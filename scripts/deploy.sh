#!/bin/bash
# Deploy freshly-built Add binaries to all regions.
# Build first:  cargo build --release --workspace
# Usage:        scripts/deploy.sh
set -u

SRC_DIR="target/release"
REMOTE_DIR="/root/add"

# host -> space-separated binaries actually run on that host
declare -A HOST_BINS=(
  [is]="add-bootstrap add-relay"
  [jp]="add-bootstrap add-relay"
  [nl]="add-reflector"
  [me]="add-bootstrap add-relay"
)

log() { printf '%s\n' "$*"; }

for host in "${!HOST_BINS[@]}"; do
  bins="${HOST_BINS[$host]}"
  log "=============================================="
  log ">> $host : $bins"
  log "=============================================="

  ssh -o ConnectTimeout=15 -o BatchMode=yes "$host" "mkdir -p $REMOTE_DIR" \
    || { log "!! $host unreachable, skipping"; continue; }

  for bin in $bins; do
    local_bin="$SRC_DIR/$bin"
    [ -f "$local_bin" ] || { log "!! $local_bin missing, skip"; continue; }

    # 1) upload to .new (never overwrite a running binary in place)
    scp -o ConnectTimeout=30 -o ServerAliveInterval=15 "$local_bin" \
        "$host:$REMOTE_DIR/$bin.new" \
      && log "   uploaded $bin -> $host:$REMOTE_DIR/$bin.new" \
      || { log "!! scp $bin -> $host failed"; continue; }

    # 2) on the remote: kill old by PID, swap, relaunch
    pat1="[a]dd-${bin#add-}"
    pat2="[n]ullnode-${bin#add-}"
    # Reflector uses fixed port 44089 for DHT registration
    if [ "$bin" = "add-reflector" ]; then
      portarg="--port 44089"
    else
      portarg=""
    fi
    ssh -o ConnectTimeout=15 "$host" \
      "cd $REMOTE_DIR; for pat in '$pat1' '$pat2'; do for pid in \$(pgrep -f \"\$pat\"); do kill -9 \"\$pid\" 2>/dev/null; done; done; sleep 1; mv -f $bin.new $bin; chmod +x $bin; setsid ./$bin $portarg > $bin.log 2>&1 < /dev/null &"
    log "   deployed+restarted $bin on $host"
  done

  # 3) verify
  sleep 4
  ssh -o ConnectTimeout=15 "$host" "ps -eo pid,cmd | grep -E '[a]dd-(bootstrap|relay|reflector)' | grep -v grep || echo '   (none running)'" 2>&1 | sed 's/^/   /'
done

log "=============================================="
log ">> DONE"
log "=============================================="
