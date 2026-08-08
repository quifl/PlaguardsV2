"""Input validation and sanitization for uploaded files and free-text
fields (mirrors Plaguards' own PlagFilter.py role)."""
from __future__ import annotations

import html
import re

ALLOWED_EXTENSIONS = {".ps1", ".txt", ".vbs", ".js", ".bat", ".cmd", ".log"}


def validate_file_extension(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = "." + filename.rsplit(".", 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS


def sanitize_filename(filename: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", filename or "upload")
    return name[:200] or "upload"


def sanitize_text(value: str) -> str:
    return html.escape(value or "", quote=True)
