#!/bin/bash
# VulnSamurai — Linux / macOS launcher
set -e

echo ""
echo "  ⚔  VulnSamurai"
echo "======================================"

# Auto-generate JWT secret into .env
JWT=$(openssl rand -hex 64)
sed -i "s|changeme_run_openssl_rand_hex_64_and_paste_here|${JWT}|g" .env 2>/dev/null || true

echo "[1/2] Building image (first time ~15 min)..."
docker build -t vulnsamurai .

echo "[2/2] Starting container..."
docker rm -f vulnsamurai 2>/dev/null || true
docker run -d \
  --name vulnsamurai \
  --env-file .env \
  -p 3000:3000 \
  -v vulnsamurai_data:/data \
  vulnsamurai

echo ""
echo "======================================"
echo "  Ready at http://localhost:3000"
echo "  Logs: docker logs -f vulnsamurai"
echo "======================================"
