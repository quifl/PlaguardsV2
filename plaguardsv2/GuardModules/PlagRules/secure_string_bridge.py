"""Rule set: using the SecureString/Marshal interop bridge to smuggle a
plain string into memory outside normal variable tracking."""

_MARSHAL = "Runtime" + ".InteropServices.Marshal"

RULES = [
    dict(name="SecureString/Marshal execution bridge",
         pattern=rf"\[(?:System\.)?{_MARSHAL}\]::(?:SecureStringToBSTR|PtrToStringAuto)",
         mitre=["T1140", "T1059.001"], severity="high",
         description="Routes a decoded string through the SecureString/Marshal interop bridge, "
                      "a known way to obscure a value before it's executed."),
]
