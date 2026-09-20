"""SQLite persistence: analyses, findings, per-source intel results, triage
status, a threat-intel response cache, and user-configured settings (API
keys entered via the Settings page)."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

DEFAULT_DB_PATH = Path(os.environ.get("PLAGUARDSV2_DB", "data/plaguardsv2.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    filename TEXT,
    source_kind TEXT NOT NULL DEFAULT 'pasted',
    original_text TEXT NOT NULL,
    deobfuscated_text TEXT NOT NULL,
    pass_log TEXT NOT NULL,
    resolved_vars TEXT NOT NULL DEFAULT '{}',
    truncated INTEGER NOT NULL DEFAULT 0,
    batch_id INTEGER REFERENCES batches(id) ON DELETE SET NULL,
    started_at REAL,
    completed_at REAL,
    duration_ms REAL,
    status TEXT NOT NULL DEFAULT 'completed'
);

-- One row per batch (zip or multi-file) upload. A single-file upload never
-- gets one of these - analyses.batch_id stays NULL and it's just a normal
-- row, exactly as before this feature existed.
CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_filename TEXT,
    started_at REAL NOT NULL,
    completed_at REAL,
    duration_ms REAL,
    total_files INTEGER NOT NULL DEFAULT 0,
    successful_files INTEGER NOT NULL DEFAULT 0,
    failed_files INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'completed'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    mitre TEXT,
    severity TEXT,
    description TEXT,
    defanged INTEGER NOT NULL DEFAULT 0,
    triage_status TEXT NOT NULL DEFAULT 'unreviewed',
    triage_note TEXT
);

CREATE TABLE IF NOT EXISTS finding_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    verdict TEXT NOT NULL,
    detail TEXT,
    UNIQUE (finding_id, source)
);

CREATE TABLE IF NOT EXISTS intel_cache (
    source TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    verdict TEXT NOT NULL,
    detail TEXT,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (source, ioc_type, value)
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    """Add a column to an existing table if it isn't there yet. SCHEMA uses
    CREATE TABLE IF NOT EXISTS, so databases created by an earlier version
    keep their old shape and need this to pick up new columns."""
    existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def get_conn(db_path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    # Without this, a writer that finds the database locked (a concurrent
    # batch upload, e.g.) fails immediately instead of waiting its turn - and
    # batch analysis is explicitly meant to stay correct under concurrent
    # writes. This makes it retry for up to 5s before giving up, rather than
    # turning ordinary lock contention into spurious per-file failures.
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.executescript(SCHEMA)
    _ensure_column(conn, "analyses", "source_kind", "TEXT NOT NULL DEFAULT 'pasted'")
    _ensure_column(conn, "analyses", "resolved_vars", "TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(conn, "analyses", "deobfuscated_raw", "TEXT NOT NULL DEFAULT ''")
    _ensure_column(conn, "analyses", "batch_id", "INTEGER REFERENCES batches(id) ON DELETE SET NULL")
    _ensure_column(conn, "analyses", "started_at", "REAL")
    _ensure_column(conn, "analyses", "completed_at", "REAL")
    _ensure_column(conn, "analyses", "duration_ms", "REAL")
    _ensure_column(conn, "analyses", "status", "TEXT NOT NULL DEFAULT 'completed'")
    conn.commit()
    return conn


@contextmanager
def connect(db_path: Path | str | None = None):
    conn = get_conn(db_path)
    try:
        yield conn
    finally:
        conn.close()


def save_analysis(conn: sqlite3.Connection, filename: str, original_text: str,
                   deobfuscated_text: str, pass_log: list[str], truncated: bool,
                   findings: list, source_kind: str = "pasted",
                   resolved_vars: dict | None = None,
                   deobfuscated_raw: str = "",
                   batch_id: int | None = None, status: str = "completed",
                   started_at: float | None = None, completed_at: float | None = None,
                   duration_ms: float | None = None) -> int:
    now = time.time()
    cur = conn.execute(
        "INSERT INTO analyses (created_at, filename, source_kind, original_text, "
        "deobfuscated_text, deobfuscated_raw, pass_log, resolved_vars, truncated, "
        "batch_id, status, started_at, completed_at, duration_ms) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (now, filename, source_kind, original_text, deobfuscated_text,
         deobfuscated_raw or deobfuscated_text, json.dumps(pass_log),
         json.dumps(resolved_vars or {}), int(truncated),
         batch_id, status,
         started_at if started_at is not None else now,
         completed_at if completed_at is not None else now,
         duration_ms),
    )
    analysis_id = cur.lastrowid
    for f in findings:
        fcur = conn.execute(
            "INSERT INTO findings (analysis_id, type, value, context, mitre, severity, "
            "description, defanged) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (analysis_id, f.type, f.value, f.context, json.dumps(f.mitre), f.severity,
             f.description, int(f.defanged)),
        )
        finding_id = fcur.lastrowid
        for source, result in getattr(f, "intel", {}).items():
            conn.execute(
                "INSERT INTO finding_intel (finding_id, source, verdict, detail) VALUES (?, ?, ?, ?)",
                (finding_id, source, result.get("verdict", "unknown"), result.get("detail", "")),
            )
    conn.commit()
    return analysis_id


def save_failed_analysis(conn: sqlite3.Connection, filename: str, error: str,
                          source_kind: str = "file", batch_id: int | None = None,
                          started_at: float | None = None,
                          completed_at: float | None = None,
                          duration_ms: float | None = None) -> int:
    """Persist a placeholder row for a file that raised during analysis.

    Reuses save_analysis's own INSERT rather than a parallel one, so a failed
    file still gets a normal analyses row - findings-less, with the error as
    its only pass_log entry - and shows up in History with accurate timing
    instead of silently vanishing from the batch.
    """
    return save_analysis(
        conn, filename, original_text="", deobfuscated_text="",
        pass_log=[f"Analysis failed: {error}"], truncated=False, findings=[],
        source_kind=source_kind, batch_id=batch_id, status="failed",
        started_at=started_at, completed_at=completed_at, duration_ms=duration_ms,
    )


def get_analysis(conn: sqlite3.Connection, analysis_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
    if row is None:
        return None
    analysis = dict(row)
    analysis["pass_log"] = json.loads(analysis["pass_log"])
    analysis["truncated"] = bool(analysis["truncated"])
    # Canonical aliases: an analysis loaded from the database must have the
    # same shape as the in-memory one PlagEngine returns, otherwise the
    # templates and PlagReport (which read `original`/`deobfuscated`) render
    # empty script bodies for stored analyses.
    analysis["original"] = analysis["original_text"]
    analysis["deobfuscated"] = analysis["deobfuscated_text"]
    # Rows written before this column existed only have the formatted text.
    analysis["deobfuscated_raw"] = (
        analysis.get("deobfuscated_raw") or analysis["deobfuscated_text"]
    )
    analysis["resolved_vars"] = json.loads(analysis.get("resolved_vars") or "{}")
    if analysis.get("batch_id") is not None:
        brow = conn.execute("SELECT * FROM batches WHERE id = ?", (analysis["batch_id"],)).fetchone()
        analysis["batch"] = dict(brow) if brow else None
    else:
        analysis["batch"] = None
    findings = conn.execute(
        "SELECT * FROM findings WHERE analysis_id = ? ORDER BY "
        "CASE severity WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, type, value",
        (analysis_id,),
    ).fetchall()
    analysis["findings"] = []
    for f in findings:
        fd = dict(f)
        fd["mitre"] = json.loads(fd["mitre"]) if fd["mitre"] else []
        fd["defanged"] = bool(fd["defanged"])
        intel_rows = conn.execute(
            "SELECT source, verdict, detail FROM finding_intel WHERE finding_id = ? ORDER BY source",
            (fd["id"],),
        ).fetchall()
        fd["intel"] = {r["source"]: {"verdict": r["verdict"], "detail": r["detail"]} for r in intel_rows}
        analysis["findings"].append(fd)
    return analysis


def list_analyses(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    rows = conn.execute(
        "SELECT a.id, a.created_at, a.filename, "
        "COUNT(f.id) AS finding_count, "
        "SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count "
        "FROM analyses a LEFT JOIN findings f ON f.analysis_id = a.id "
        "GROUP BY a.id ORDER BY a.created_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def prune_old_analyses(conn: sqlite3.Connection, keep: int) -> int:
    """Delete the oldest analyses beyond `keep`, most-recent-first. Findings
    and their intel results cascade-delete automatically. Returns the number
    of analyses removed."""
    rows = conn.execute(
        "SELECT id FROM analyses ORDER BY created_at DESC LIMIT -1 OFFSET ?", (keep,)
    ).fetchall()
    ids = [r["id"] for r in rows]
    if ids:
        conn.executemany("DELETE FROM analyses WHERE id = ?", [(i,) for i in ids])
        conn.commit()
    return len(ids)


# --- Batches ----------------------------------------------------------------
# A batch (zip or multi-file upload) is tracked as its own row so History can
# show "one entry, 50 files" instead of 50 unrelated-looking rows. Kept
# separate from the analyses helpers above, which stay exactly as they were -
# list_analyses()/prune_old_analyses() are also used by the CLI, which has no
# concept of a batch and must keep seeing a flat list of files.

def create_batch(conn: sqlite3.Connection, batch_filename: str, started_at: float) -> int:
    cur = conn.execute(
        "INSERT INTO batches (batch_filename, started_at) VALUES (?, ?)",
        (batch_filename, started_at),
    )
    conn.commit()
    return cur.lastrowid


def finish_batch(conn: sqlite3.Connection, batch_id: int, completed_at: float,
                  duration_ms: float, total_files: int, successful_files: int,
                  failed_files: int, status: str = "completed") -> None:
    conn.execute(
        "UPDATE batches SET completed_at = ?, duration_ms = ?, total_files = ?, "
        "successful_files = ?, failed_files = ?, status = ? WHERE id = ?",
        (completed_at, duration_ms, total_files, successful_files, failed_files,
         status, batch_id),
    )
    conn.commit()


def list_history(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    """Top-level History rows: every standalone analysis (batch_id IS NULL)
    plus every batch as one entry carrying its member analyses, newest first.

    A batch counts as a single slot against `limit`, the same as one
    standalone analysis - a 50-file batch does not cost 50 slots, because
    what an analyst reads History by is "how many rows do I see", and that is
    exactly what a batch upload is meant to collapse into one of.
    """
    singles = conn.execute(
        "SELECT a.id, a.created_at, a.filename, a.status, a.started_at, "
        "a.completed_at, a.duration_ms, "
        "COUNT(f.id) AS finding_count, "
        "SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count "
        "FROM analyses a LEFT JOIN findings f ON f.analysis_id = a.id "
        "WHERE a.batch_id IS NULL GROUP BY a.id"
    ).fetchall()
    rows: list[dict] = [dict(r, kind="single") for r in singles]

    for brow in conn.execute("SELECT * FROM batches").fetchall():
        b = dict(brow)
        files = conn.execute(
            "SELECT a.id, a.filename, a.status, a.started_at, a.completed_at, "
            "a.duration_ms, "
            "COUNT(f.id) AS finding_count, "
            "SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count "
            "FROM analyses a LEFT JOIN findings f ON f.analysis_id = a.id "
            "WHERE a.batch_id = ? GROUP BY a.id ORDER BY a.id",
            (b["id"],),
        ).fetchall()
        b["files"] = [dict(f) for f in files]
        b["kind"] = "batch"
        b["finding_count"] = sum(f["finding_count"] or 0 for f in b["files"])
        b["high_count"] = sum(f["high_count"] or 0 for f in b["files"])
        # Sorts alongside standalone analyses' created_at (their own
        # completion moment - save_analysis writes it at the very end of the
        # pipeline). completed_at is briefly NULL while a batch is still
        # being processed; started_at is the best ordering signal until then.
        b["created_at"] = b["completed_at"] if b["completed_at"] is not None else b["started_at"]
        rows.append(b)

    rows.sort(key=lambda r: r["created_at"] or 0, reverse=True)
    return rows[:limit]


def prune_old_history(conn: sqlite3.Connection, keep: int) -> int:
    """Batch-aware prune_old_analyses(): deletes the oldest top-level History
    records (standalone analyses, or whole batches) beyond `keep`. Deleting a
    pruned batch also deletes its member analyses - analyses.batch_id itself
    only SETs NULL on delete, so that has to happen explicitly here."""
    rows = list_history(conn, limit=10_000_000)
    removed = 0
    for row in rows[keep:]:
        if row["kind"] == "single":
            conn.execute("DELETE FROM analyses WHERE id = ?", (row["id"],))
        else:
            conn.execute("DELETE FROM analyses WHERE batch_id = ?", (row["id"],))
            conn.execute("DELETE FROM batches WHERE id = ?", (row["id"],))
        removed += 1
    if removed:
        conn.commit()
    return removed


def delete_analyses(conn: sqlite3.Connection, analysis_ids: list[int]) -> int:
    if not analysis_ids:
        return 0
    placeholders = ",".join("?" * len(analysis_ids))
    # Batches these belonged to, so one left with no files afterwards doesn't
    # linger in History as an entry with nothing to expand.
    touched_batches = [
        r["batch_id"] for r in conn.execute(
            f"SELECT DISTINCT batch_id FROM analyses "
            f"WHERE id IN ({placeholders}) AND batch_id IS NOT NULL",
            analysis_ids,
        ).fetchall()
    ]
    conn.executemany("DELETE FROM analyses WHERE id = ?", [(i,) for i in analysis_ids])
    for batch_id in touched_batches:
        remaining = conn.execute(
            "SELECT COUNT(*) AS n FROM analyses WHERE batch_id = ?", (batch_id,)
        ).fetchone()["n"]
        if remaining == 0:
            conn.execute("DELETE FROM batches WHERE id = ?", (batch_id,))
    conn.commit()
    return len(analysis_ids)


def delete_all_analyses(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM analyses")
    conn.execute("DELETE FROM batches")
    conn.commit()


def update_triage(conn: sqlite3.Connection, finding_id: int, status: str, note: str = "") -> None:
    conn.execute(
        "UPDATE findings SET triage_status = ?, triage_note = ? WHERE id = ?",
        (status, note, finding_id),
    )
    conn.commit()


def cache_get(conn: sqlite3.Connection, source: str, ioc_type: str, value: str, max_age_seconds: float = 86400) -> dict | None:
    row = conn.execute(
        "SELECT verdict, detail, fetched_at FROM intel_cache WHERE source = ? AND ioc_type = ? AND value = ?",
        (source, ioc_type, value.lower()),
    ).fetchone()
    if row is None:
        return None
    if time.time() - row["fetched_at"] > max_age_seconds:
        return None
    return {"verdict": row["verdict"], "detail": row["detail"]}


def cache_set(conn: sqlite3.Connection, source: str, ioc_type: str, value: str, verdict: str, detail: str) -> None:
    conn.execute(
        "INSERT INTO intel_cache (source, ioc_type, value, verdict, detail, fetched_at) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(source, ioc_type, value) DO UPDATE SET verdict=excluded.verdict, "
        "detail=excluded.detail, fetched_at=excluded.fetched_at",
        (source, ioc_type, value.lower(), verdict, detail, time.time()),
    )
    conn.commit()


def get_setting(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def get_all_settings(conn: sqlite3.Connection) -> dict:
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {r["key"]: r["value"] for r in rows}
