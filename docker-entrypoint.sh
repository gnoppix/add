#!/bin/sh
# Fix volume ownership if needed
if [ -d /home/add/.add ]; then
    chown -R add:add /home/add/.add 2>/dev/null || true
fi
exec "$@"
