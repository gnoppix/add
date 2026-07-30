#!/bin/bash
# Post-install script to fix the .desktop file

DESKTOP_FILE="/usr/share/applications/add-desktop.desktop"

if [ -f "$DESKTOP_FILE" ]; then
    # Update the Exec line to include DBUS_SESSION_BUS_ADDRESS
    sed -i 's|^Exec=.*|Exec=env DBUS_SESSION_BUS_ADDRESS=systemd: "/opt/Add Desktop/add-desktop" --disable-gpu --disable-gpu-compositing --no-sandbox --disable-gpu-sandbox --disable-software-rasterizer --disable-features=UseChromeOSDirectVideoDecoder %U|' "$DESKTOP_FILE"
    echo "Fixed $DESKTOP_FILE"
fi