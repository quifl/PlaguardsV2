"""Rule set: in-memory / reflective code loading."""

RULES = [
    dict(name="Reflective assembly/code loading",
         pattern=r"\[Reflection\.Assembly\]::Load|System\.Reflection\.Assembly",
         mitre=["T1620"], severity="high",
         description="Loads a .NET assembly directly into memory."),
]
