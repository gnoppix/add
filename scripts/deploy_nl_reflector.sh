#!/bin/bash
# Deploy the freshly-built add-reflector to the nl host and restart it.
set -u
SRC_DIR="target/release"
REMOTE_DIR="/root/add"
host="nl"
bin="add-reflector"

ssh -o ConnectTimeout=15 -o BatchMode=yes "$host" "mkdir -p $REMOTE_DIR" || { echo "!! $host unreachable"; exit 1; }

local_bin="$SRC_DIR/$bin"
[ -f "$local_bin" ] || { echo "!! $local_bin missing"; exit 1; }

scp -o ConnectTimeout=30 -o ServerAliveInterval=15 "$local_bin" "$host:$REMOTE_DIR/$bin.new" \
  && echo "uploaded $bin -> $host:$REMOTE_DIR/$bin.new" \
  || { echo "!! scp failed"; exit 1; }

pat1="[a]dd-${bin#add-}"
pat2="[n]ullnode-${bin#add-}"
ssh -o ConnectTimeout=15 "$host" bash -s <<EOF
  cd $REMOTE_DIR
  for pat in '$pat1' '$pat2'; do
    for pid in \$(pgrep -f "\$pat"); do kill -9 "\$pid" 2>/dev/null; done
  done
  sleep 1
  mv -f $bin.new $bin
  chmod +x $bin
  setsid ./$bin > $bin.log 2>&1 < /dev/null &
EOF

echo "deployed+restarted $bin on $host"
sleep 4
ssh -o ConnectTimeout=15 "$host" bash -s <<'EOF' 2>&1 | sed 's/^/   /'
    ps -eo pid,cmd,lstart | grep -E '[a]dd-reflector' | grep -v grep || echo "(none running)"
    ls -la --time-style=+%H:%M:%S /root/add/add-reflector
EOF
