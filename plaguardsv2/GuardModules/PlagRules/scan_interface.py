"""Rule set: references to the antimalware scan interface internals."""

_MARKER = "Amsi" + "Utils"

RULES = [
    dict(name="AMSI-related API reference",
         pattern=rf"\b{_MARKER}\b|amsi" + "InitFailed",
         mitre=["T1562.001"], severity="high",
         description="References internal antimalware-scan-interface symbols."),
]
