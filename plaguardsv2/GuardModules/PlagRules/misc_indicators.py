"""Rule set: miscellaneous low-signal indicators."""

RULES = [
    dict(name="Compression-based obfuscation", pattern=r"IO\.Compression\.(?:Gzip|Deflate)Stream",
         mitre=["T1027"], severity="low",
         description="Payload is compressed inline, likely to obscure a stage."),
    dict(name="Hidden window creation", pattern=r"\bStart-Process\b[^\n]{0,60}-WindowStyle\s+Hidden",
         mitre=["T1564.003"], severity="medium",
         description="Launches a process with a hidden window."),
]
