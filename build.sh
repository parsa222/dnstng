#!/usr/bin/env bash
# DnstTNG — Install dependencies, compile, and run tests (Ubuntu)
set -euo pipefail

echo "=== DnstTNG build script ==="

# ── Install dependencies ──────────────────────────────────────────────────────
echo "[1/3] Installing build dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    build-essential cmake pkg-config \
    libuv1-dev libc-ares-dev liblz4-dev

# ── Build ─────────────────────────────────────────────────────────────────────
echo "[2/3] Building with GNU Make..."
make clean 2>/dev/null || true
make all

# ── Test ──────────────────────────────────────────────────────────────────────
echo "[3/3] Running tests..."
make tests

echo ""
echo "=== Build complete ==="
echo "Binaries:"
echo "  build/dnstunnel-client"
echo "  build/dnstunnel-server"
