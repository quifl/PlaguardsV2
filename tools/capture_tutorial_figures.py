"""Capture the Tutorial page's figures from the running application.

These are photographs of the real thing, not drawings of it: pages rendered by
headless Chrome, pages of a report rendered from the PDF the app actually
produced, and the CLI's own stdout. A drawing can be wrong in ways nobody
notices; a screenshot of the running app can only be out of date, which is
visible and fixable by re-running this.

    python tools/capture_tutorial_figures.py --analysis 30 --batch 31,32,33

The app must be running (see README). Needs Chrome or Edge on the machine and
`pip install pypdfium2` for the report pages; neither is a runtime dependency
of PlaguardsV2 itself.
"""
from __future__ import annotations

import argparse
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "plaguardsv2" / "PlagWeb" / "static" / "assets" / "tutorial"

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
]

# Crops are fractions of the image, so a different window size cannot
# silently reframe every figure. (left, top, right, bottom), each 0..1.
FULL = (0.0, 0.0, 1.0, 1.0)



PLACEHOLDER_DB = {
    "city": r"C:\GeoLite2\GeoLite2-City.mmdb",
    "country": r"C:\GeoLite2\GeoLite2-Country.mmdb",
    "asn": r"C:\GeoLite2\GeoLite2-ASN.mmdb",
}


class neutral_geo_paths:
    """Swap the configured GeoLite2 paths for generic ones while capturing.

    A screenshot of a real machine would carry its directory layout into the
    docs. Restored in __exit__ so an interrupted run cannot strand them.
    """

    def __enter__(self):
        sys.path.insert(0, str(ROOT))
        from plaguardsv2.GuardModules import PlagConfig, PlagStore

        self._config, self._store = PlagConfig, PlagStore
        self._conn = PlagStore.get_conn()
        self._saved = PlagConfig.get_geoip_db_paths(self._conn)
        for kind, value in PLACEHOLDER_DB.items():
            if self._saved.get(kind):
                PlagConfig.set_geoip_db_path(self._conn, kind, value)
        self._conn.commit()
        return self

    def __exit__(self, *exc):
        for kind, value in self._saved.items():
            self._config.set_geoip_db_path(self._conn, kind, value)
        self._conn.commit()
        self._conn.close()
        return False



def save(image, name: str, supersampled: bool = True) -> None:
    """Write a figure at its logical size.

    A browser treats PNG pixels as CSS pixels, so a 2x file would render at
    twice the intended size. Downsampling also beats a 1x capture for text.
    """
    if supersampled:
        image = image.resize((image.width // 2, image.height // 2), Image.LANCZOS)
    image.save(OUT / f"{name}.png")


def find_browser() -> str:
    for path in CHROME_CANDIDATES:
        if Path(path).exists():
            return path
    found = shutil.which("chrome") or shutil.which("chromium") or shutil.which("msedge")
    if found:
        return found
    sys.exit("No Chrome or Edge found. Install one, or add its path to CHROME_CANDIDATES.")


def shoot(browser: str, url: str, size: tuple[int, int]) -> Image.Image:
    with tempfile.TemporaryDirectory() as tmp:
        shot = Path(tmp) / "shot.png"
        subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
             "--force-device-scale-factor=2", "--virtual-time-budget=5000",
             f"--window-size={size[0]},{size[1]}",
             f"--screenshot={shot}", url],
            check=True, capture_output=True, timeout=180,
        )
        return Image.open(shot).convert("RGB")


def crop(image, box):
    w, h = image.size
    left, top, right, bottom = box
    return image.crop((int(w * left), int(h * top), int(w * right), int(h * bottom)))


def pdf_pages(pdf_bytes: bytes):
    import pypdfium2 as pdfium

    return pdfium.PdfDocument(io.BytesIO(pdf_bytes))


def page_with(doc, needle: str, skip: int = 0) -> int:
    """Index of the page whose text contains `needle`.

    Searched, not pinned: pagination moves with the sample.
    """
    seen = 0
    for i in range(len(doc)):
        if needle.lower() in doc[i].get_textpage().get_text_range().lower():
            if seen == skip:
                return i
            seen += 1
    raise SystemExit(f"No page of the report contains {needle!r}; is it the right analysis?")


def render_page(doc, index: int, box=FULL, scale: float = 2.0):
    image = doc[index].render(scale=scale).to_pil().convert("RGB")
    return crop(image, box)


def render_terminal(lines: list[str], width: int = 1180) -> Image.Image:
    """The CLI's real stdout, set in a terminal window."""

    bg, chrome_bg, fg, dim = (3, 7, 16), (28, 37, 46), (238, 241, 246), (133, 146, 172)
    try:
        font = ImageFont.truetype(r"C:\Windows\Fonts\consola.ttf", 15)
    except OSError:
        font = ImageFont.load_default()
    pad, line_h, bar = 18, 22, 34
    height = bar + pad * 2 + line_h * len(lines)
    img = Image.new("RGB", (width, height), bg)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, bar], fill=chrome_bg)
    for i, colour in enumerate(((229, 86, 107), (227, 168, 60), (63, 192, 122))):
        d.ellipse([16 + i * 18, bar // 2 - 5, 26 + i * 18, bar // 2 + 5], fill=colour)
    d.text((82, bar // 2 - 8), "PlaguardsV2 CLI", font=font, fill=dim)
    for i, line in enumerate(lines):
        d.text((pad, bar + pad + i * line_h), line[:130], font=font,
               fill=fg if line.startswith("$") else dim)
    return img


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--analysis", type=int, required=True,
                    help="an analysis with a full set of findings, such as the bundled example")
    ap.add_argument("--batch", default="",
                    help="comma-separated member ids of a batch, so History shows it expanded")
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    browser = find_browser()
    base, aid = args.base.rstrip("/"), args.analysis
    history_url = f"{base}/history" + (f"?selected={args.batch}" if args.batch else "")

    # Pages of the running app, cropped tight: a whole page shrunk into the
    # card renders its text at half size and cannot be read.
    web = [
        ("overview",      f"{base}/analysis/{aid}", (1680, 1150), (0.155, 0.055, 1.0, 0.62)),
        ("navigation",    f"{base}/",               (1680, 1060), (0.0, 0.0, 0.158, 0.30)),
        ("analyze",       f"{base}/",               (1680, 1060), (0.17, 0.17, 0.66, 0.85)),
        ("deobfuscation", f"{base}/analysis/{aid}", (1680, 1250), (0.16, 0.135, 0.57, 0.50)),
        ("findings",      f"{base}/analysis/{aid}", (1680, 1250), (0.575, 0.135, 1.0, 0.47)),
        ("history",       history_url,              (1680, 1000), (0.16, 0.10, 1.0, 0.52)),
    ]
    for name, url, size, box in web:
        save(crop(shoot(browser, url, size), box), name)
        print(f"  {name + '.png':<22} <- {url}")

    with neutral_geo_paths():
        save(crop(shoot(browser, f"{base}/settings", (1680, 1200)),
                  (0.17, 0.05, 0.88, 0.46)), "settings")
    print(f"  {'settings.png':<22} <- {base}/settings (paths neutralised)")

    # pages of the report the app actually produced
    import urllib.request

    pdf = urllib.request.urlopen(f"{base}/analysis/{aid}/report/download", timeout=300).read()
    doc = pdf_pages(pdf)
    report_shots = [
        ("intel", page_with(doc, "AlienVault OTX"), (0.06, 0.06, 0.96, 0.52)),
        ("geolocation", page_with(doc, "Accuracy radius"), (0.06, 0.34, 0.96, 0.72)),
    ]
    for name, index, box in report_shots:
        save(render_page(doc, index, box), name)
        print(f"  {name + '.png':<22} <- report page {index + 1}")

    # The cover beside the summary page: one picture of how a report opens.
    cover = render_page(doc, 0, scale=1.6)
    summary = render_page(doc, page_with(doc, "Indicators at a glance"), scale=1.6)
    gap, pad = 18, 14
    sheet = Image.new("RGB", (cover.width + summary.width + gap + pad * 2,
                              max(cover.height, summary.height) + pad * 2), (232, 234, 238))
    sheet.paste(cover, (pad, pad))
    sheet.paste(summary, (pad + cover.width + gap, pad))
    save(sheet, "report")
    print(f"  {'report.png':<22} <- report pages 1 and {page_with(doc, 'Indicators at a glance') + 1}")

    # the CLI's own output
    cmd = [sys.executable, "plaguardsv2-cli.py", "analyze",
           "samples/example-analysis.ps1", "--no-intel", "--no-store"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=600,
                          env={**os.environ, "PYTHONIOENCODING": "utf-8"})
    body = [re.sub(r"\s+$", "", ln) for ln in (proc.stdout or proc.stderr).splitlines()]
    body = [ln for ln in body if ln.strip()][:16]
    save(render_terminal(
        ["$ python plaguardsv2-cli.py analyze samples/example-analysis.ps1"] + body),
        "cli", supersampled=False)
    print(f"  {'cli.png':<22} <- {' '.join(cmd[1:])}")


if __name__ == "__main__":
    main()
