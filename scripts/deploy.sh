#!/bin/bash
# Deploy freshly-built Add binaries to all regions.
# Build first:  cargo build --release --workspace
# Usage:        scripts/deploy.sh
#
# Uploads each binary to <host>:/root/add/<bin>.new, then on the remote:
#   1. kills the running process by exact PID (read via pgrep, NOT pkill -f,
#      which would self-match this script's own command line),
#   2. atomically swaps .new -> binary,
#   3. relaunches via nohup with stdin/stdout fully detached so SSH returns.
set -u

SRC_DIR="target/release"
REMOTE_DIR="/root/add"

# host -> space-separated binaries actually run on that host
HOST_BINS_IS="add-bootstrap add-relay"
HOST_BINS_JP="add-bootstrap add-relay"
HOST_BINS_NL="add-reflector"
HOST_BINS_ME="add-bootstrap add-relay"
# HOST_BINS_US="add-bootstrap add-relay"   # add when reachable

log() { printf '%s\n' "$*"; }

for entry in "is:$HOST_BINS_IS" "jp:$HOST_BINS_JP" "nl:$HOST_BINS_NL" "me:$HOST_BINS_ME"; do
  host="${entry%%:*}"
  bins="${entry#*:}"
  log "=============================================="
  log ">>> $host : $bins"
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

    # 2) on the remote: kill old by PID, swap, relaunch. Patterns use a regex
    #    class ([e]va- / [n]ullnode-) so the running process matches but this
    #    script's own command line (which contains the bracketed form) does not
    #    self-match. Heredoc keeps local expansion clean (no nested-quote hell).
    pat1="[a]dd-${bin#add-}"
    pat2="[n]ullnode-${bin#add-}"
    ssh -o ConnectTimeout=15 "$host" bash <<EOF
      cd $REMOTE_DIR
      for pat in '$pat1' '$pat2'; do
        for pid in \$(pgrep -f "\$pat"); do kill -9 "\$pid" 2>/dev/null; done
      done
      sleep 1
      mv -f $bin.new $bin
      chmod +x $bin
      nohup ./$bin > $bin.log 2>&1 < /dev/null &
      disown
EOF
    log "   deployed+restarted $bin on $host"
  done

  # 3) verify
  sleep 4
  ssh -o ConnectTimeout=15 "$host" bash <<'EOF' 2>&1 | sed 's/^/   /'
    echo "   procs:"
    ps -eo pid,cmd | grep -E '[e]va-(bootstrap|relay|reflector)|nullnode-(bootstrap|relay|reflector)' | grep -v grep || echo "   (none running)"
EOF
done

log "=============================================="
log ">>> DONE"
log "=============================================="
