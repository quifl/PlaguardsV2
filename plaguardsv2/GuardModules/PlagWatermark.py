"""Builds a faint, page-sized watermark image from the Plaguards logo, the
way the original Plaguards reports carried brand art behind the content.

The image is generated once per process and cached: xhtml2pdf paints it as
the @page background, so it sits behind every page of the report."""
from __future__ import annotations

import base64
import io
from pathlib import Path

LOGO_PATH = Path(__file__).parent.parent / "PlagWeb" / "static" / "assets" / "plaguard-logo.png"

# A4 at 96 dpi, the resolution xhtml2pdf assumes for page backgrounds.
PAGE_W, PAGE_H = 794, 1123
LOGO_FRACTION = 0.55      # logo width relative to page width
WATERMARK_OPACITY = 0.06  # subtle enough to keep body text fully legible

_cache: str | None = None


def watermark_data_uri() -> str | None:
    """Return a data: URI for the page watermark, or None if the logo is
    missing or the image can't be built."""
    global _cache
    if _cache is not None:
        return _cache or None
    if not LOGO_PATH.exists():
        _cache = ""
        return None

    try:
        from PIL import Image

        page = Image.new("RGB", (PAGE_W, PAGE_H), "white")
        logo = Image.open(LOGO_PATH).convert("RGBA")

        target_w = int(PAGE_W * LOGO_FRACTION)
        scale = target_w / logo.width
        logo = logo.resize((target_w, max(1, int(logo.height * scale))), Image.LANCZOS)

        # Fade the logo by scaling its alpha channel down.
        alpha = logo.getchannel("A").point(lambda a: int(a * WATERMARK_OPACITY))
        logo.putalpha(alpha)

        offset = ((PAGE_W - logo.width) // 2, (PAGE_H - logo.height) // 2)
        page.paste(logo, offset, logo)

        buf = io.BytesIO()
        page.save(buf, format="PNG", optimize=True)
        _cache = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
        return _cache
    except Exception:
        _cache = ""
        return None
