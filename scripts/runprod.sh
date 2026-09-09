#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
export DJANGO_SETTINGS_MODULE=honeytrap.settings_prod
export PYTHONPATH="$ROOT_DIR"
exec gunicorn honeytrap.wsgi:application --bind 0.0.0.0:8000 --workers 1
