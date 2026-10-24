"""Download GCHQ's CyberChef release for PlaguardsV2 to serve offline.

    python tools/fetch_cyberchef.py              # latest release
    python tools/fetch_cyberchef.py --version v11.5.0

The archive is checked against the SHA-256 digest GitHub publishes for the
release asset; a missing or mismatched digest aborts the install. Once
installed, CyberChef runs entirely in the browser from this server, so a
sample opened in it never leaves the machine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from plaguardsv2.PlagWeb import cyberchef  # noqa: E402

API = "https://api.github.com/repos/gchq/CyberChef/releases"
# The release archive is about 80 MB; anything far larger is not CyberChef.
MAX_ARCHIVE_BYTES = 300 * 1024 * 1024


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "PlaguardsV2"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def _release(version: str | None) -> tuple[str, dict]:
    data = _get_json(f"{API}/tags/{version}" if version else f"{API}/latest")
    assets = [a for a in data.get("assets", [])
              if a["name"].startswith("CyberChef_") and a["name"].endswith(".zip")]
    if not assets:
        raise SystemExit(f"No CyberChef zip attached to release {data.get('tag_name')}.")
    return data["tag_name"], assets[0]


def _download(asset: dict, dest: Path) -> str:
    """Stream the asset to `dest` and return its SHA-256."""
    if asset.get("size", 0) > MAX_ARCHIVE_BYTES:
        raise SystemExit(f"Release asset is {asset['size']} bytes, larger than expected.")
    digest = hashlib.sha256()
    total = 0
    req = urllib.request.Request(asset["browser_download_url"],
                                 headers={"User-Agent": "PlaguardsV2"})
    with urllib.request.urlopen(req, timeout=60) as resp, dest.open("wb") as out:
        while chunk := resp.read(1 << 20):
            total += len(chunk)
            if total > MAX_ARCHIVE_BYTES:
                raise SystemExit("Download exceeded the expected size; aborted.")
            digest.update(chunk)
            out.write(chunk)
    return digest.hexdigest()


def _extract(archive: Path, target: Path) -> str:
    """Unpack into `target`, refusing any member that would land outside it.
    Returns the name of CyberChef's HTML entry page."""
    target.mkdir(parents=True)
    base = target.resolve()
    entry = None
    with zipfile.ZipFile(archive) as zf:
        for member in zf.infolist():
            path = (target / member.filename).resolve()
            if base != path and base not in path.parents:
                raise SystemExit(f"Archive member escapes the install folder: {member.filename}")
            if member.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, path.open("wb") as dst:
                shutil.copyfileobj(src, dst)
            name = Path(member.filename)
            if len(name.parts) == 1 and name.suffix == ".html" and name.name.startswith("CyberChef"):
                entry = name.name
    if entry is None:
        raise SystemExit("No CyberChef_*.html entry page found in the archive.")
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", help="release tag, e.g. v11.5.0 (default: latest)")
    args = parser.parse_args()

    tag, asset = _release(args.version)
    expected = (asset.get("digest") or "").removeprefix("sha256:").lower()
    if not expected:
        raise SystemExit(f"GitHub published no SHA-256 for {asset['name']}; refusing to install it unverified.")

    install = cyberchef.install_dir()
    staging = install.with_name(install.name + ".staging")
    shutil.rmtree(staging, ignore_errors=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / asset["name"]
        print(f"Downloading CyberChef {tag} ({asset['size'] / 1e6:.0f} MB)...")
        actual = _download(asset, archive)
        if actual != expected:
            raise SystemExit(f"SHA-256 mismatch: expected {expected}, got {actual}. Nothing installed.")
        print("SHA-256 verified.")
        entry = _extract(archive, staging)

    (staging / cyberchef.MANIFEST).write_text(json.dumps(
        {"version": tag, "entry": entry, "sha256": expected}, indent=1), encoding="utf-8")
    shutil.rmtree(install, ignore_errors=True)
    staging.rename(install)
    print(f"Installed CyberChef {tag} to {install}")
    print("Restart PlaguardsV2; the analysis page will offer it at /cyberchef/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
