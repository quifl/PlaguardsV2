"""Rule set: persistence-mechanism patterns."""

RULES = [
    dict(name="Scheduled task persistence", pattern=r"\bschtasks\b|New-ScheduledTask",
         mitre=["T1053.005"], severity="medium",
         description="Creates a scheduled task, a common persistence mechanism."),
    dict(name="Registry Run-key persistence",
         pattern=r"CurrentVersion\\Run|Set-ItemProperty[^\n]{0,60}\bRun\b|\breg(?:\.exe)?\s+add\b",
         mitre=["T1547.001", "T1112"], severity="medium",
         description="Writes to a registry Run key or otherwise edits the registry."),
]
