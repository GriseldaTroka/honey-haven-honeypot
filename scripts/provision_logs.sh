#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT_DIR/logs/cowrie" "$ROOT_DIR/logs/dionaea" "$ROOT_DIR/logs/conpot" "$ROOT_DIR/logs/web" "$ROOT_DIR/logs/promtail"
chmod 0755 "$ROOT_DIR/logs"
echo "Created log directories under $ROOT_DIR/logs"
