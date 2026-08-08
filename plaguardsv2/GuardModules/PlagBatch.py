"""Unpacks a batch submission - several files at once, or a .zip - into
(filename, text) pairs ready for analysis.

Archives are attacker-supplied input like everything else here, so the
extraction is bounded: a capped entry count, a per-entry size limit and a
total uncompressed budget, and any path components are discarded so a
crafted archive can't reference a location outside itself.
"""
from __future__ import annotations

import io
import zipfile

from . import PlagFilter

# Ceilings for one submission. Generous enough for a real folder of samples,
# still bounded so a crafted archive cannot exhaust memory or disk.
MAX_ENTRIES = 200
MAX_ENTRY_BYTES = 5_000_000
MAX_TOTAL_BYTES = 100_000_000


def limits() -> dict:
    """The caps, in the units the UI quotes them in."""
    return {
        "entries": MAX_ENTRIES,
        "entry_mb": MAX_ENTRY_BYTES // 1_000_000,
        "total_mb": MAX_TOTAL_BYTES // 1_000_000,
    }


class BatchError(Exception):
    pass


def is_zip(filename: str) -> bool:
    return (filename or "").lower().endswith(".zip")


def extract_zip(data: bytes, budget: int | None = None,
                room: int | None = None) -> tuple[list[tuple[str, str]], list[str]]:
    """Return ([(name, text)], [skipped notes]) for a zip archive.

    `budget` and `room` are what is left of the whole submission's byte and
    entry allowances, so several archives in one upload share the caps."""
    budget = MAX_TOTAL_BYTES if budget is None else max(0, budget)
    room = MAX_ENTRIES if room is None else max(0, room)
    results: list[tuple[str, str]] = []
    skipped: list[str] = []

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise BatchError(f"Not a readable zip archive: {exc}") from exc

    total = 0
    for info in archive.infolist():
        if len(results) >= room:
            skipped.append(f"stopped after {MAX_ENTRIES} files")
            break
        if info.is_dir():
            continue

        # Ignore any directory component - a zip entry must never decide
        # where its contents land.
        name = PlagFilter.sanitize_filename(info.filename.replace("\\", "/").split("/")[-1])
        if not name:
            continue
        if not PlagFilter.validate_file_extension(name):
            skipped.append(f"{name} (unsupported type)")
            continue
        if info.file_size > MAX_ENTRY_BYTES:
            skipped.append(f"{name} (larger than {MAX_ENTRY_BYTES // 1_000_000} MB)")
            continue
        if total + info.file_size > budget:
            skipped.append(f"{name} (batch size budget exhausted)")
            break

        try:
            with archive.open(info) as handle:
                raw = handle.read(MAX_ENTRY_BYTES + 1)
        except Exception:
            skipped.append(f"{name} (could not be read)")
            continue

        if len(raw) > MAX_ENTRY_BYTES:
            skipped.append(f"{name} (declared size did not match contents)")
            continue

        total += len(raw)
        text = raw.decode("utf-8", errors="replace")
        if text.strip():
            results.append((name, text))
        else:
            skipped.append(f"{name} (empty)")

    return results, skipped


def collect(uploads) -> tuple[list[tuple[str, str]], list[str]]:
    """Turn Flask FileStorage objects into (name, text) pairs, expanding any
    zip archives found among them.

    The same entry-count, per-file and total budgets apply whether the files
    arrive loose or inside an archive, and anything dropped is reported rather
    than silently truncated away.
    """
    results: list[tuple[str, str]] = []
    skipped: list[str] = []
    total = 0

    for upload in uploads:
        if not upload or not upload.filename:
            continue
        if len(results) >= MAX_ENTRIES:
            skipped.append(f"stopped after {MAX_ENTRIES} files")
            break

        raw = upload.read()
        name = PlagFilter.sanitize_filename(upload.filename)

        if is_zip(upload.filename):
            entries, notes = extract_zip(raw, budget=MAX_TOTAL_BYTES - total,
                                          room=MAX_ENTRIES - len(results))
            results.extend(entries)
            skipped.extend(notes)
            total += sum(len(text) for _, text in entries)
            continue

        if not PlagFilter.validate_file_extension(upload.filename):
            skipped.append(f"{name} (unsupported type)")
            continue
        if len(raw) > MAX_ENTRY_BYTES:
            skipped.append(f"{name} (larger than {MAX_ENTRY_BYTES // 1_000_000} MB)")
            continue
        if total + len(raw) > MAX_TOTAL_BYTES:
            skipped.append(f"{name} (batch size budget exhausted)")
            break

        total += len(raw)
        text = raw.decode("utf-8", errors="replace")
        if text.strip():
            results.append((name, text))
        else:
            skipped.append(f"{name} (empty)")

    return results, skipped
