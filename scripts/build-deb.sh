#!/bin/bash
# Build Debian packages for Add
# Usage: ./scripts/build-deb.sh

set -e

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*= *"//;s/"//')
BUILD_DIR="target/release"
PKG_DIR="debian"

mkdir -p "$BUILD_DIR"

# Build all binaries
echo "Building binaries..."
cargo build --release --workspace

# Create package bin directories (control files live in debian/<pkg>/DEBIAN/)
for pkg in add add-relay add-bootstrap add-bot; do
    mkdir -p "$PKG_DIR/$pkg/DEBIAN"
    mkdir -p "$PKG_DIR/$pkg/usr/bin"
done

# Copy binaries into place (control is already committed under DEBIAN/)
for pkg in add add-relay add-bootstrap; do
    if [ -f "$BUILD_DIR/$pkg" ]; then
        cp "$BUILD_DIR/$pkg" "$PKG_DIR/$pkg/usr/bin/"
    fi
done

# Bot binary has different name
if [ -f "$BUILD_DIR/add-reflector" ]; then
    cp "$BUILD_DIR/add-reflector" "$PKG_DIR/add-bot/usr/bin/add-bot"
fi

# Desktop UI uses electron-builder (npm)
cd desktop-ui
npm run build
cd ..

# Build .deb packages
echo "Building .deb packages..."
for pkg in add add-relay add-bootstrap add-bot; do
    if [ -d "$PKG_DIR/$pkg" ]; then
        dpkg-deb --build -Zgzip "$PKG_DIR/$pkg" "$BUILD_DIR/${pkg}_$VERSION-1_amd64.deb" 2>/dev/null || echo "  Skipping $pkg (package tools may not be available)"
    fi
done

# Desktop package is built by electron-builder
if [ -f "desktop-ui/dist-electron/add-desktop_*.deb" ]; then
    cp desktop-ui/dist-electron/add-desktop_*.deb "$BUILD_DIR/" 2>/dev/null || true
fi

echo "Done. Check $BUILD_DIR/ for .deb files"