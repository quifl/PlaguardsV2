"""The single canonical place that lists every threat-intel provider this
app knows about (id, label, env var, docs link). Both the Settings page and
every provider client read from PROVIDERS here, so adding a new source is a
one-line addition to this list plus one small file under PlagProviders/.

Resolution order for a given key: value saved via the Settings GUI (stored
in the local database) wins; otherwise fall back to the environment / .env
file. Nothing here ever leaves this machine - it's just where keys are read
from before a lookup call is made.
"""
from __future__ import annotations

import os
import sqlite3

PROVIDERS = [
    dict(id="virustotal", label="VirusTotal", env_var="VT_API_KEY",
         docs_url="https://www.virustotal.com/gui/my-apikey"),
    dict(id="abusech", label="abuse.ch (MalwareBazaar / ThreatFox / URLhaus)", env_var="ABUSECH_API_KEY",
         docs_url="https://auth.abuse.ch/"),
    dict(id="abuseipdb", label="AbuseIPDB", env_var="ABUSEIPDB_API_KEY",
         docs_url="https://www.abuseipdb.com/account/api"),
    dict(id="otx", label="AlienVault OTX", env_var="OTX_API_KEY",
         docs_url="https://otx.alienvault.com/api"),
    dict(id="shodan", label="Shodan", env_var="SHODAN_API_KEY",
         docs_url="https://account.shodan.io/"),
    dict(id="greynoise", label="GreyNoise (Community)", env_var="GREYNOISE_API_KEY",
         docs_url="https://viz.greynoise.io/account/"),
    dict(id="pulsedive", label="Pulsedive", env_var="PULSEDIVE_API_KEY",
         docs_url="https://pulsedive.com/api/"),
    # Geolocation rather than reputation: where an address is and who runs it.
    dict(id="ipinfo", label="ipinfo.io (IP geolocation)", env_var="IPINFO_TOKEN",
         docs_url="https://ipinfo.io/account/token"),
]

_BY_ID = {p["id"]: p for p in PROVIDERS}


def get_provider_label(provider_id: str) -> str:
    provider = _BY_ID.get(provider_id)
    return provider["label"] if provider else provider_id


def get_api_key(conn: sqlite3.Connection | None, provider_id: str) -> str | None:
    from . import PlagStore

    provider = _BY_ID.get(provider_id)
    if provider is None:
        return None
    if conn is not None:
        stored = PlagStore.get_setting(conn, provider["env_var"])
        if stored:
            return stored
    return os.environ.get(provider["env_var"]) or None


def set_api_key(conn: sqlite3.Connection, provider_id: str, value: str) -> None:
    from . import PlagStore

    provider = _BY_ID.get(provider_id)
    if provider is None:
        raise ValueError(f"Unknown provider id: {provider_id}")
    PlagStore.set_setting(conn, provider["env_var"], value.strip())


def all_keys(conn: sqlite3.Connection | None) -> dict:
    return {p["id"]: get_api_key(conn, p["id"]) for p in PROVIDERS}


# --- General app settings (not API keys, but stored the same way) ---------

GEOIP_DB_KEY = "GEOIP_DB_PATH"
HISTORY_LIMIT_KEY = "HISTORY_LIMIT"
ANALYST_NAME_KEY = "ANALYST_NAME"
UTC_OFFSET_KEY = "UTC_OFFSET"
DEFAULT_HISTORY_LIMIT = 10
DEFAULT_UTC_OFFSET = 7  # WIB / UTC+7


def get_history_limit(conn: sqlite3.Connection | None) -> int:
    from . import PlagStore

    if conn is None:
        return DEFAULT_HISTORY_LIMIT
    value = PlagStore.get_setting(conn, HISTORY_LIMIT_KEY)
    if not value:
        return DEFAULT_HISTORY_LIMIT
    try:
        limit = int(value)
    except ValueError:
        return DEFAULT_HISTORY_LIMIT
    return limit if limit > 0 else DEFAULT_HISTORY_LIMIT


def set_history_limit(conn: sqlite3.Connection, limit: int) -> None:
    from . import PlagStore

    PlagStore.set_setting(conn, HISTORY_LIMIT_KEY, str(max(1, int(limit))))


def get_geoip_db_path(conn: sqlite3.Connection | None) -> str:
    """Path to a local MaxMind GeoLite2 database, if one is configured.

    Preferred over the hosted lookup: the address never leaves the machine.
    """
    from . import PlagStore

    value = ""
    if conn is not None:
        value = PlagStore.get_setting(conn, GEOIP_DB_KEY) or ""
    value = value or os.environ.get(GEOIP_DB_KEY, "")
    return value.strip()


def set_geoip_db_path(conn: sqlite3.Connection, path: str) -> None:
    from . import PlagStore

    PlagStore.set_setting(conn, GEOIP_DB_KEY, (path or "").strip())


def get_analyst_name(conn: sqlite3.Connection | None) -> str:
    from . import PlagStore

    if conn is None:
        return ""
    return PlagStore.get_setting(conn, ANALYST_NAME_KEY) or ""


def set_analyst_name(conn: sqlite3.Connection, name: str) -> None:
    from . import PlagStore

    PlagStore.set_setting(conn, ANALYST_NAME_KEY, name.strip())


def get_utc_offset(conn: sqlite3.Connection | None) -> float:
    """Hours to add to UTC when displaying timestamps."""
    from . import PlagStore

    if conn is None:
        return DEFAULT_UTC_OFFSET
    raw = PlagStore.get_setting(conn, UTC_OFFSET_KEY)
    if raw is None or raw == "":
        return DEFAULT_UTC_OFFSET
    try:
        offset = float(raw)
    except ValueError:
        return DEFAULT_UTC_OFFSET
    if not -12 <= offset <= 14:
        return DEFAULT_UTC_OFFSET
    # Whole offsets come back as int so the settings field shows "9", not "9.0".
    return int(offset) if offset == int(offset) else offset


def set_utc_offset(conn: sqlite3.Connection, offset: float) -> None:
    from . import PlagStore

    value = max(-12.0, min(14.0, float(offset)))
    formatted = str(int(value)) if value == int(value) else str(value)
    PlagStore.set_setting(conn, UTC_OFFSET_KEY, formatted)


def format_utc_offset(offset: float) -> str:
    sign = "+" if offset >= 0 else "-"
    magnitude = abs(offset)
    if magnitude == int(magnitude):
        return f"UTC{sign}{int(magnitude)}"
    hours = int(magnitude)
    minutes = int(round((magnitude - hours) * 60))
    return f"UTC{sign}{hours}:{minutes:02d}"
