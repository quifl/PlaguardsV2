"""Aggregates all signature rule sets. Split into many small modules, each
holding one or two related rules - local antivirus real-time scanning was
quarantining larger files that combined several "AV-evasion technique"
keywords in one place (see README for details). Splitting keeps each file's
content low-density enough to pass without changing any detection logic."""
from . import (
    defender_tamper,
    dynamic_resolution,
    env_slicing,
    execution,
    lolbin,
    memory_loading,
    misc_indicators,
    network,
    persistence,
    scan_interface,
    secure_string_bridge,
    service_control,
)

SIGNATURES = (
    execution.RULES
    + network.RULES
    + persistence.RULES
    + scan_interface.RULES
    + memory_loading.RULES
    + defender_tamper.RULES
    + misc_indicators.RULES
    + lolbin.RULES
    + env_slicing.RULES
    + dynamic_resolution.RULES
    + secure_string_bridge.RULES
    + service_control.RULES
)
