"""Rule set: attempts to weaken local security tooling."""

_A = "Set-Mp" + "Preference"
_B = "Add-Mp" + "Preference"
_C = "Disable-Windows" + "OptionalFeature"

RULES = [
    dict(name="Security-tooling tamper attempt",
         pattern=rf"{_A}|{_B}[^\n]{{0,60}}-ExclusionPath|{_C}",
         mitre=["T1562.001"], severity="high",
         description="Attempts to weaken or disable Windows security controls."),
]
