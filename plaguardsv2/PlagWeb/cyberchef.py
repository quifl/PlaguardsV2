"""An offline copy of GCHQ's CyberChef, served next to the dashboard.

tools/fetch_cyberchef.py installs it into a gitignored folder. The sample
travels to it in the URL fragment, which browsers never send to a server, and
the CSP below stops the page from sending anything off this machine.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Flask, abort, send_from_directory, url_for

from ..GuardModules import PlagMagic

MANIFEST = "plaguards-cyberchef.json"
DEFAULT_DIR = Path(__file__).resolve().parent / "cyberchef"

# connect-src 'self' is the leak guard: even CyberChef's own HTTP Request
# operation cannot reach another host from this page.
CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval' blob:",
    "worker-src 'self' blob:",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' data: blob:",
    "frame-ancestors 'self'",
    "form-action 'none'",
    "base-uri 'self'",
])


def install_dir() -> Path:
    override = os.environ.get("PLAGUARDSV2_CYBERCHEF_DIR", "").strip()
    return Path(override) if override else DEFAULT_DIR


def manifest() -> dict | None:
    """The installed copy's {"version", "entry"}, or None when there is none."""
    try:
        data = json.loads((install_dir() / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    entry = str(data.get("entry") or "")
    if not entry or Path(entry).name != entry or not (install_dir() / entry).is_file():
        return None
    return data


def _secured(response):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def register(app: Flask) -> None:
    @app.route("/cyberchef/")
    def cyberchef_index():
        info = manifest()
        if info is None:
            abort(404)
        return _secured(send_from_directory(install_dir(), info["entry"]))

    @app.route("/cyberchef/<path:name>")
    def cyberchef_asset(name):
        if manifest() is None or name == MANIFEST:
            abort(404)
        return _secured(send_from_directory(install_dir(), name))

    @app.template_global()
    def chef_url(data: str, recipe: list | None = None) -> str:
        """Link that opens `data` in the offline CyberChef with `recipe` loaded
        (CyberChef's own Magic when no recipe is given)."""
        return url_for("cyberchef_index") + "#" + PlagMagic.chef_fragment(data, recipe)

    @app.context_processor
    def cyberchef_context():
        return {"cyberchef": manifest()}
