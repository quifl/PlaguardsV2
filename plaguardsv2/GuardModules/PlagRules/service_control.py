"""Rule set: service creation and cmdlet-based task registration.

Separate from `persistence.py` because that module's task rule keys on
`schtasks` / `New-ScheduledTask`, neither of which appears in
`Register-ScheduledTask` - the cmdlet form went undetected.
"""

RULES = [
    dict(name="Windows service creation",
         pattern=r"\bNew-Service\b|\bsc(?:\.exe)?\s+create\b",
         mitre=["T1543.003"], severity="medium",
         description="Registers a Windows service, which runs at boot with SYSTEM rights."),
    dict(name="Scheduled task registration via cmdlet",
         pattern=r"\b(?:Register|Unregister|Set)-ScheduledTask\b",
         mitre=["T1053.005"], severity="medium",
         description="Registers or edits a scheduled task through the ScheduledTasks module."),
]
