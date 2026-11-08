"""Plain-English explanations for each deobfuscation transform.

The raw pass log is accurate but terse ("folded -join on literal array").
Reports are read by people who did not write the deobfuscator, so each
entry is paired with what the technique is and why an author would use it.
"""
from __future__ import annotations

EXPLANATIONS = [
    # First, because its detail lists recipe steps that would match broader needles below.
    ("CyberChef-style recipe",
     "An encoded run no dedicated decoder reached was opened by trying "
     "CyberChef's decoders in combination (Base32/58/64/85, hex, decimal, "
     "binary, URL, HTML entities, compression, XOR, ROT) until it read as "
     "text. The recipe is named so it can be repeated in CyberChef."),
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
     "An array of literals was joined into one string, another way to spell "
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
     "they are inserted purely to break up recognizable names."),
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
     "Interpolated strings were rebuilt once their variables were known. "
     "This is usually where the payload's real output becomes visible."),
    ("truncated",
     "The input exceeded the size limit and was cut short before analysis."),
    ("JScript string method chain",
     "A chain of JScript string methods (e.g. .replace(), .split(), .concat()) "
     "run on literal values was resolved to its result."),
    # Appended rather than interleaved: explain() returns the first needle that
    # matches, so the entries above keep priority over these broader ones.
    ("line-wrapped Base64",
     "A Base64 run split across several lines was joined back together. .NET "
     "ignores the whitespace, so breaking a blob up changes nothing except "
     "whether a scanner recognizes it as one value."),
    ("percent-encoded",
     "Percent-encoding (%68%74%74%70) was decoded back to text. It is valid in "
     "a URL, which lets a whole address be written without any of its "
     "recognizable words appearing."),
    ("$env:",
     "Well-known environment variables were replaced with their standard "
     "Windows values, since commands are often spelled by slicing characters "
     "out of them rather than written out."),
    ("subexpressions",
     "$(...) subexpressions were collapsed to the value they produce, so a "
     "string assembled inside one reads as the text it becomes."),
    ("literal expressions",
     "Arithmetic and other constant expressions were evaluated, which is how "
     "a character code written as a sum becomes a letter again."),
    ("assignments to their values",
     "Each variable was replaced by the value assigned to it, so the script "
     "reads as what it does rather than as a chain of indirection."),
    ("[string] cast",
     "Redundant [string] casts were removed. They change nothing at runtime "
     "and are added to make a line harder to read."),
    ("standalone encoded payload",
     "A line that was nothing but an encoded blob, with no surrounding code "
     "to hook into, was decoded in place and annotated with its plaintext."),
    ("XOR-decoded",
     "A byte array was recovered by applying the XOR key the script itself "
     "uses, turning the loader's data back into its payload."),
    ("VBScript Chr(",
     "VBScript Chr() calls were converted back to characters: the VBScript "
     "equivalent of writing letters as numbers."),
    ("VBScript & concatenation",
     "VBScript string concatenation (&) was folded, joining pieces that were "
     "split to keep any whole keyword from appearing."),
    ("VBScript string call",
     "VBScript string functions (Mid, Left, Right, Replace) over literals were "
     "resolved to their result."),
    ("VBScript literal variable",
     "VBScript variables holding constants were substituted with their value."),
    ("String.fromCharCode",
     "String.fromCharCode sequences were converted back to text: the "
     "JavaScript way of spelling a string as numbers."),
    ("JScript escape/atob",
     "JScript escape sequences and atob()/Base64 literals were decoded back to "
     "readable text."),
    ("JScript + concatenation",
     "JScript string concatenation (+) over literals was folded into the "
     "single value it produces."),
    ("JScript literal variable",
     "JScript variables holding constants were substituted with their value."),
    ("batch variable",
     "Batch %VAR% references were expanded, including the substring form "
     "(%VAR:~2,3%) used to spell a command out of an existing value."),
    ("IOC check",
     "Extracted indicators were looked up against whichever threat-intel "
     "providers are configured in Settings; a provider with no key is simply "
     "skipped, not treated as clean."),
    ("Geolocation",
     "Public IP addresses among the findings were located via the configured "
     "GeoLite2 database or ipinfo.io, to show whether the traffic's "
     "destination makes sense."),
    # Layered pipeline.
    ("own layer",
     "A script handed to another interpreter (Invoke-Expression, powershell "
     "-Command, cmd /c, eval, Execute) was taken out as its own layer, read with "
     "the passes for its language, and its indicators traced to that layer."),
    ("typographic quotes and dashes",
     "Curly quotes and en/em dashes were written as plain ' \" and -. PowerShell "
     "treats them as the same characters, so they only serve to dodge exact-text "
     "matching."),
    ("alias(es)",
     "Command aliases (iex, iwr, irm, gci, % and others, plus any the script "
     "defined with Set-Alias) were expanded to the cmdlet names they stand for."),
    ("invoked through & or .",
     "A command name written as a string and run with the call operator was "
     "unquoted: & 'iex' and iex run the same command."),
    ("cmd.exe order",
     "The batch file was read in cmd.exe's own parsing order: %VAR% expansion, "
     "then ^ escapes and quotes, then !VAR! delayed expansion and CALL's second "
     "expansion, including substring and replace forms."),
    ("never set in the script",
     "Variables a batch file never sets expand to nothing, which is how junk "
     "%names% are used to break up keywords. Marked as assumed: the host could "
     "in principle define one."),
    ("stock Windows value",
     "A well-known variable such as %COMSPEC% was given its standard Windows "
     "value, since commands are often sliced out of it. Marked as assumed."),
    ("computed member access",
     "obj['name'] was rewritten as obj.name, the same property written so that "
     "the name never appears as an identifier."),
]


def explain(entry: str) -> str:
    """Return the explanation matching a pass-log entry, or an empty string."""
    for needle, text in EXPLANATIONS:
        if needle.lower() in entry.lower():
            return text
    return ""
