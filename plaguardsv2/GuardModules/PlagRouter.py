"""Which language an artifact is written in, decided from its content.

Never from a file extension: an .hta can be a polyglot, a .txt is often a
PowerShell command line copied out of a log, and a decoded stage has no
extension at all. Each language scores the markers it shows; the best score
wins, a weak best score means plain text, and a stage handed over by a
known interpreter (`powershell -c`, `Execute`, `eval`) keeps that
interpreter's language.
"""
from __future__ import annotations

import re

from . import PlagCmd, PlagJs, PlagVbs
from .PlagArtifact import Lang

MIN_SCORE = 3.0
_F = re.IGNORECASE | re.MULTILINE

_MARKERS: dict[str, list[tuple[re.Pattern, float, int]]] = {
    # (pattern, weight per hit, max hits counted)
    Lang.POWERSHELL: [
        (re.compile(r"\$[A-Za-z_]\w*\s*=(?!=)", _F), 1.5, 4),
        (re.compile(r"\$\{?env:", _F), 3, 2),
        (re.compile(r"\b(?:Write-(?:Host|Output)|Invoke-(?:Expression|WebRequest|RestMethod)|New-Object|"
                    r"Get-ChildItem|Set-Alias|New-Alias|Start-Process|ForEach-Object|Where-Object|Add-Type|"
                    r"Get-Content|Set-Content|Out-File|Get-Item|Remove-Item|Select-Object)\b", _F), 3, 3),
        (re.compile(r"\[(?:System\.)?(?:Convert|Text\.Encoding|char|string|scriptblock|byte\[\]|"
                    r"IO\.\w+|Net\.\w+|Reflection\.\w+|Array)\]", _F), 3, 3),
        (re.compile(r"[-–—―](?:join|split|replace|bxor|f|eq|ne|match|like)\b", _F), 1, 4),
        (re.compile(r"(?:^|[;|&(]\s*)(?:iex|iwr|irm|sal|nal|gci)\b", _F), 2, 2),
        (re.compile(r"\|\s*%\s*\{|\|\s*\?\s*\{", _F), 2, 2),
        (re.compile(r"\bparam\s*\(", _F), 2, 1),
        (re.compile(r"\$_\b|\$true\b|\$false\b|\$null\b", _F), 1, 3),
    ],
    Lang.BATCH: [
        (re.compile(r"^\s*@?echo\s+off\b", _F), 5, 1),
        (re.compile(r"^\s*set\s+(?:/[ap]\s+)?\"?[\w#$.-]+=", _F), 2, 4),
        (re.compile(r"%[A-Za-z_][\w#$.-]*(?::~-?\d+(?:,-?\d+)?|:[^%=\n]*=[^%\n]*)?%", _F), 1.5, 4),
        (re.compile(r"\bsetlocal\b|\bendlocal\b", _F), 3, 1),
        (re.compile(r"^\s*(?:rem\b|::)", _F), 2, 1),
        (re.compile(r"\bgoto\s+:?\w+|\bcall\s+:\w+|^\s*:\w+\s*$|%~[a-z]*\d", _F), 2, 2),
        (re.compile(r"\w\^\w|\^[&|<>]", _F), 1, 2),
        (re.compile(r"\bfor\s+/[fdlr]\b", _F), 3, 1),
    ],
    Lang.JAVASCRIPT: [
        # JavaScript keywords are case-sensitive; VBScript's `Const` and
        # `Function` are not these.
        (re.compile(r"\b(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=", re.MULTILINE), 2, 3),
        (re.compile(r"\bfunction\b\s*[\w$]*\s*\(", re.MULTILINE), 2, 2),
        (re.compile(r"=>", _F), 1, 2),
        (re.compile(r"\bconsole\.\w+\s*\(", _F), 3, 1),
        (re.compile(r"\bWScript\.Echo\s*\(", _F), 1, 1),
        (re.compile(r"\bnew\s+(?:ActiveXObject|Function)\s*\(", _F), 3, 1),
        (re.compile(r"\bString\.fromCharCode\b|\batob\s*\(|\bunescape\s*\(", _F), 3, 1),
        (re.compile(r"\b(?:setTimeout|setInterval)\s*\(", _F), 2, 1),
        (re.compile(r"\b(?:document|window)\.\w+", _F), 2, 1),
        (re.compile(r";\s*$", _F), 0.5, 4),
    ],
    Lang.VBSCRIPT: [
        (re.compile(r"^\s*Dim\s+\w+", _F), 3, 1),
        (re.compile(r"^\s*Set\s+\w+\s*=\s*(?:CreateObject|GetObject|New)\b", _F), 3, 1),
        (re.compile(r"^\s*(?:(?:Public|Private)\s+)?(?:Const|CONST)\s+\w+\s*=", re.MULTILINE), 3, 1),
        (re.compile(r"\bWScript\.Echo\s+[^(\s]", _F), 2, 1),
        (re.compile(r"\bCreateObject\s*\(", _F), 2, 1),
        (re.compile(r"\bChrW?\$?\s*\(", _F), 1.5, 2),
        (re.compile(r"\bEnd\s+(?:Sub|Function|If)\b", _F), 3, 1),
        (re.compile(r"\bExecute(?:Global)?\b|\bStrReverse\s*\(|\bvbCrLf\b|\bMsgBox\b", _F), 2, 2),
        (re.compile(r"\"\s*&\s*(?:\"|\w)", _F), 1, 3),
        (re.compile(r"^\s*'", _F), 0.5, 2),
    ],
    Lang.HTA: [
        (re.compile(r"<\s*hta:application\b", _F), 10, 1),
    ],
    Lang.WSF: [
        (re.compile(r"<\s*job\b[^>]*>", _F), 6, 1),
        (re.compile(r"<\s*package\s*>", _F), 4, 1),
    ],
}

_PRIORITY = [Lang.HTA, Lang.WSF, Lang.POWERSHELL, Lang.BATCH, Lang.JAVASCRIPT, Lang.VBSCRIPT]

# How much text the scorer reads: mostly the opening, which names a script's
# language, plus the end, so padding in front cannot hide the script.
SAMPLE_CHARS = 200_000
TAIL_CHARS = 20_000


def _sample(text: str) -> str:
    text = text.lstrip()
    if len(text) <= SAMPLE_CHARS:
        return text
    return text[:SAMPLE_CHARS - TAIL_CHARS] + "\n" + text[-TAIL_CHARS:]


_STRING_RE = re.compile(r"\"[^\"\n]*\"|'[^'\n]*'")


def _code_view(sample: str) -> str:
    """String contents blanked, quotes kept: `sh.Run "powershell ... Write-Host"`
    is a VBScript line, whatever its string says."""
    return _STRING_RE.sub(lambda m: m.group(0)[0] + " " * (len(m.group(0)) - 2) + m.group(0)[-1], sample)


def _raw_scores(sample: str) -> dict[str, float]:
    out: dict[str, float] = {}
    for lang, markers in _MARKERS.items():
        total = 0.0
        for pattern, weight, cap in markers:
            hits = 0
            for _m in pattern.finditer(sample):
                hits += 1
                if hits >= cap:
                    break
            total += weight * hits
        out[lang] = total
    return out


def scores(text: str) -> dict[str, float]:
    """Marker scores per language. A marker inside a string literal counts
    half: a dropper names the interpreter it hands a string to."""
    sample = _sample(text)
    full, code = _raw_scores(sample), _raw_scores(_code_view(sample))
    return {lang: code[lang] + (full[lang] - code[lang]) / 2 for lang in full}


def identify(content: str | bytes, hint: str | None = None) -> str:
    """The artifact's language. `hint` is the interpreter a handoff named."""
    if isinstance(content, bytes):
        return Lang.BINARY
    if hint in Lang.ALL and hint not in (Lang.TEXT, Lang.UNKNOWN):
        return hint
    found = scores(content)
    best = max(_PRIORITY, key=lambda lang: (found[lang], -_PRIORITY.index(lang)))
    if found[best] < MIN_SCORE:
        return Lang.TEXT
    return best


def legacy_languages(source: str) -> list[str]:
    """The language bundles the legacy engine added, by its one-time sniff of
    the whole input, in the order it added them."""
    out = []
    if PlagVbs.looks_like_vbscript(source):
        out.append(Lang.VBSCRIPT)
    if PlagJs.looks_like_script(source):
        out.append(Lang.JAVASCRIPT)
    if PlagCmd.looks_like_batch(source):
        out.append(Lang.BATCH)
    return out
