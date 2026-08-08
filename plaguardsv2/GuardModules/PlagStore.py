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
    truncated INTEGER NOT NULL DEFAULT 0
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
    conn.executescript(SCHEMA)
    _ensure_column(conn, "analyses", "source_kind", "TEXT NOT NULL DEFAULT 'pasted'")
    _ensure_column(conn, "analyses", "resolved_vars", "TEXT NOT NULL DEFAULT '{}'")
    _ensure_column(conn, "analyses", "deobfuscated_raw", "TEXT NOT NULL DEFAULT ''")
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
                   deobfuscated_raw: str = "") -> int:
    cur = conn.execute(
        "INSERT INTO analyses (created_at, filename, source_kind, original_text, "
        "deobfuscated_text, deobfuscated_raw, pass_log, resolved_vars, truncated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (time.time(), filename, source_kind, original_text, deobfuscated_text,
         deobfuscated_raw or deobfuscated_text, json.dumps(pass_log),
         json.dumps(resolved_vars or {}), int(truncated)),
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


def delete_analyses(conn: sqlite3.Connection, analysis_ids: list[int]) -> int:
    if not analysis_ids:
        return 0
    conn.executemany("DELETE FROM analyses WHERE id = ?", [(i,) for i in analysis_ids])
    conn.commit()
    return len(analysis_ids)


def delete_all_analyses(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM analyses")
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
