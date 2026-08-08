"""Rule set: resolving a cmdlet/command dynamically via wildcard matching."""

RULES = [
    dict(name="Dynamic cmdlet resolution via wildcard match",
         pattern=r"GetCmdlets\(\)[^\n]{0,120}-like\s*['\"][^'\"\n]*\*[^'\"\n]*['\"]",
         mitre=["T1027", "T1059.001"], severity="medium",
         description="Looks up a cmdlet by a wildcard name match instead of naming it directly, "
                      "likely to avoid a static string reference to the real command."),
]
