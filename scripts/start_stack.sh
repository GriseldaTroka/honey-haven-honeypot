#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "Provisioning logs directories..."
./scripts/provision_logs.sh || true

echo "Starting docker-compose stack (observability + honeypots + web)..."
docker compose up -d --profile observability --profile honeypots

echo "Stack started. Use 'docker compose ps' to view services."
