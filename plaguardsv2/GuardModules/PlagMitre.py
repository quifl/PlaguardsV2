"""Human-readable names for the MITRE ATT&CK technique IDs used across
PlagRules, so reports can show "T1105 - Ingress Tool Transfer" instead of a
bare code."""

TECHNIQUE_NAMES = {
    "T1027": "Obfuscated Files or Information",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1071": "Application Layer Protocol",
    "T1095": "Non-Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1112": "Modify Registry",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1564.003": "Hide Artifacts: Hidden Window",
    "T1620": "Reflective Code Loading",
}


def describe(technique_id: str) -> str:
    name = TECHNIQUE_NAMES.get(technique_id)
    return f"{technique_id} - {name}" if name else technique_id
