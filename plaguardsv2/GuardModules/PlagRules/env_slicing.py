"""Rule set: building strings via environment-variable character indexing."""

RULES = [
    dict(name="Environment-variable character-slicing",
         pattern=r"\$env:\w+\[\d+\]",
         mitre=["T1027"], severity="medium",
         description="Builds a string by indexing characters out of an environment variable - "
                      "the actual resulting value is machine-specific and not decoded here."),
]
