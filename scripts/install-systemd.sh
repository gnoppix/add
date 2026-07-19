#!/bin/bash
# Install Add systemd units + tmpfs-enforcement on a remote Core Node host.
#
# Usage:  scripts/install-systemd.sh <host>
#   e.g.  scripts/install-systemd.sh is
#         scripts/install-systemd.sh me
#
# What it does on the remote:
#   1. copies add-*.service + add-tmpfs.conf into /etc
#   2. runs systemd-tmpfiles --create to mount /root/.add on tmpfs NOW
#   3. (re)starts the requested service via systemctl
#
# The daemons will REFUSE TO BOOT unless /root/.add is genuinely tmpfs
# (ADD_REQUIRE_TMPFS=1 in the units → panic in crypto::snapshot_defense).
set -euo pipefail

HOST="${1:?usage: $0 <host>}"
SRC="$(cd "$(dirname "$0")/../deploy/systemd" && pwd)"

REMOTE_UNIT_DIR=/etc/systemd/system
REMOTE_TMPFILES_DIR=/etc/tmpfiles.d

BINS="add-bootstrap add-relay"

echo ">>> $HOST : installing systemd units + tmpfs enforcement"

ssh -o ConnectTimeout=15 -o BatchMode=yes "$HOST" bash -c "'
  set -e
  mkdir -p $REMOTE_UNIT_DIR $REMOTE_TMPFILES_DIR
'" || { echo "!! $HOST unreachable"; exit 1; }

# ship unit + tmpfiles rule
scp -o ConnectTimeout=30 -o ServerAliveInterval=15 \
  "$SRC/add-tmpfs.conf" "$HOST:$REMOTE_TMPFILES_DIR/add-tmpfs.conf"
echo "   copied add-tmpfs.conf -> $REMOTE_TMPFILES_DIR"
for u in add-bootstrap.service add-relay.service; do
  scp -o ConnectTimeout=30 -o ServerAliveInterval=15 \
    "$SRC/$u" "$HOST:$REMOTE_UNIT_DIR/$u"
  echo "   copied $u -> $REMOTE_UNIT_DIR"
done

# create+mount tmpfs NOW (also happens at boot via systemd-tmpfiles-setup)
ssh -o ConnectTimeout=15 "$HOST" bash -c "'
  set -e
  systemd-tmpfiles --create --prefix=/root/.add || true
  systemctl daemon-reload
'"

# restart the daemons under systemd (stop nohup instances first)
for bin in $BINS; do
  unit="add-$bin.service"
  pat1="[a]dd-${bin#add-}"
  pat2="[n]ullnode-${bin#add-}"
  ssh -o ConnectTimeout=15 "$HOST" bash <<EOF
    for pat in '$pat1' '$pat2'; do
      for pid in \$(pgrep -f "\$pat"); do kill -9 "\$pid" 2>/dev/null; done
    done
    sleep 1
    systemctl enable --now $unit
    sleep 2
    systemctl is-active $unit && echo "   $unit ACTIVE" || echo "   !! $unit NOT active"
EOF
done

echo ">>> DONE $HOST"
