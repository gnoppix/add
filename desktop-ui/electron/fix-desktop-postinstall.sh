#!/bin/bash
# Post-install script to fix the .desktop file with GPU flags and D-Bus fix

DESKTOP_FILE="/usr/share/applications/add-desktop.desktop"

if [ -f "$DESKTOP_FILE" ]; then
    sed -i 's|^Exec=.*|Exec=env DBUS_SESSION_BUS_ADDRESS=systemd: "/opt/Add Desktop/add-desktop" --disable-gpu --disable-gpu-compositing --no-sandbox --disable-gpu-sandbox --disable-software-rasterizer --disable-features=UseChromeOSDirectVideoDecoder %U|' "$DESKTOP_FILE"
    echo "Fixed $DESKTOP_FILE with GPU flags and D-Bus fix"
fi