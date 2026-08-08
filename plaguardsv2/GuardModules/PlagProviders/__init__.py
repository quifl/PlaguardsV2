"""One threat-intel client per file. Each module exposes SUPPORTS (the
finding types it can look up) and a lookup(finding_type, value, api_key)
function returning {"verdict": ..., "detail": ...}."""
from . import abusech, abuseipdb, greynoise, otx, pulsedive, shodan, virustotal

REGISTRY = {
    "virustotal": virustotal,
    "abusech": abusech,
    "abuseipdb": abuseipdb,
    "otx": otx,
    "shodan": shodan,
    "greynoise": greynoise,
    "pulsedive": pulsedive,
}
