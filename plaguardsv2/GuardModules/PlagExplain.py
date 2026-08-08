"""Plain-English explanations for each deobfuscation transform.

The raw pass log is accurate but terse ("folded -join on literal array").
Reports are read by people who did not write the deobfuscator, so each
entry is paired with what the technique is and why an author would use it.
"""
from __future__ import annotations

EXPLANATIONS = [
    ("EncodedCommand",
     "PowerShell was invoked with a Base64-encoded command block, so the real "
     "script never appears in the command line."),
    ("FromBase64String",
     "A Base64 literal was decoded back to text. Encoding hides keywords and "
     "IOCs from simple string matching."),
    ("Gzip", "A compressed payload stage was inflated back to source."),
    ("compressed",
     "A compressed payload stage was inflated back to source."),
    ("string concatenation",
     "Adjacent string literals were joined. Splitting a word across several "
     "literals defeats signatures that look for it whole."),
    ("-join",
     "An array of literals was joined into one string - another way to spell "
     "out a keyword without it appearing literally."),
    ("-f format",
     "The format operator was resolved. Its placeholders let an author write "
     "a command with the pieces out of order."),
    ("[char]",
     "Numeric character codes were converted back to text, so letters could "
     "be written as arithmetic instead of characters."),
    ("-bxor",
     "XOR-encoded character values were decoded with the key found in the "
     "script."),
    ("backtick",
     "Backticks were removed. PowerShell ignores them inside a token, so "
     "they are inserted purely to break up recognisable names."),
    ("$ShellId",
     "$ShellId was replaced with its fixed built-in value; indexing into it "
     "is a common way to spell short commands such as IEX."),
    ("string indexing",
     "Characters were pulled out of literals by index and reassembled."),
    ("literal variables",
     "Variables holding a known constant were substituted with their value."),
    ("XOR-encoded byte array",
     "A byte array combined with a single-byte key was decoded and annotated."),
    ("numeric-array-to-char",
     "A loop converting numbers to characters was resolved and annotated."),
    ("Variable tracing: statically resolved",
     "Assignments were followed in order so each variable's real value could "
     "be reconstructed, including values built up over several steps."),
    ("Variable tracing: reconstructed",
     "Interpolated strings were rebuilt once their variables were known - "
     "this is usually where the payload's real output becomes visible."),
    ("truncated",
     "The input exceeded the size limit and was cut short before analysis."),
]


def explain(entry: str) -> str:
    """Return the explanation matching a pass-log entry, or an empty string."""
    for needle, text in EXPLANATIONS:
        if needle.lower() in entry.lower():
            return text
    return ""
