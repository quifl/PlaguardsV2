#!/usr/bin/env bash
# One-script setup + run for PlaguardsV2 (Linux/Mac).
# Prefers Docker (docker compose) if available; falls back to a local
# Python virtual environment + gunicorn otherwise. Either way, ends with
# the dashboard reachable at http://localhost:8000.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from .env.example - edit it later to add threat-intel API keys (optional)."
fi

open_browser() {
    if command -v xdg-open >/dev/null 2>&1; then xdg-open "$1" >/dev/null 2>&1 || true
    elif command -v open >/dev/null 2>&1; then open "$1" >/dev/null 2>&1 || true
    fi
}

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "Docker detected - building and starting PlaguardsV2 in a container..."
    docker compose up --build -d
    sleep 3
else
    echo "Docker not found - setting up a local Python environment instead..."
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 was not found on PATH. Install Python 3.11+ or Docker, then re-run this script." >&2
        exit 1
    fi

    if [ ! -d .venv ]; then
        python3 -m venv .venv
    fi
    ./.venv/bin/pip install --quiet --upgrade pip
    ./.venv/bin/pip install --quiet -r requirements.txt

    mkdir -p data
    echo "Starting PlaguardsV2 with gunicorn on http://localhost:8000 ..."
    ./.venv/bin/gunicorn -b 0.0.0.0:8000 -w 2 --timeout 60 --daemon wsgi:app
    sleep 3
fi

open_browser "http://localhost:8000"
echo "PlaguardsV2 is running at http://localhost:8000"
