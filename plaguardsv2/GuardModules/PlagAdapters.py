"""The legacy passes, wrapped as layered-pipeline passes.

Nothing is reimplemented: every adapter calls the function the legacy
engine calls, with the label it logs under. What the wrapping adds is a
declared kind and the languages each pass is allowed to read, which is what
lets the scheduler keep PowerShell folding out of a batch or VBScript layer.
"""
from __future__ import annotations

from . import PlagCmd, PlagDeobfus, PlagJs, PlagLoader, PlagVbs
from .PlagArtifact import Lang
from .PlagPassApi import FunctionPass, Kind

_KINDS = {
    "_propagate_literal_variables": Kind.RESOLVE,
    "_resolve_shellid": Kind.RESOLVE,
    "_resolve_env_variables": Kind.RESOLVE,
    "_resolve_string_indexing": Kind.FOLD,
    "_decode_encoded_command": Kind.DECODE,
    "_normalize_base64_whitespace": Kind.NORMALIZE,
    "_decode_frombase64_literals": Kind.DECODE,
    "_decode_url_encoded": Kind.DECODE,
    "_fold_string_concatenation": Kind.FOLD,
    "_fold_join_operator": Kind.FOLD,
    "_fold_format_operator": Kind.FOLD,
    "_resolve_char_codes": Kind.FOLD,
    "_resolve_bxor": Kind.FOLD,
    "fold_subexpressions": Kind.FOLD,
    "fold_expressions": Kind.FOLD,
    "fold_assignments": Kind.RESOLVE,
    "_annotate_xor_byte_array": Kind.SEMANTIC,
    "_annotate_char_array_loop": Kind.SEMANTIC,
    "_strip_junk_backticks": Kind.NORMALIZE,
    "_strip_redundant_casts": Kind.NORMALIZE,
    "_decode_standalone_payloads": Kind.DECODE,
    "recover_xor_loop": Kind.DECODE,
    "_magic_decode_runs": Kind.DECODE,
    "resolve_chr": Kind.FOLD,
    "fold_concatenation": Kind.FOLD,
    "resolve_string_calls": Kind.FOLD,
    "decode_base64_literals": Kind.DECODE,
    "track_variables": Kind.RESOLVE,
    "decode_encodings": Kind.DECODE,
    "fold_string_methods": Kind.FOLD,
    "resolve_variables": Kind.RESOLVE,
}

_MODULE_PREFIX = {
    PlagJs.__name__: "legacy.js.",
    PlagVbs.__name__: "legacy.vbs.",
    PlagCmd.__name__: "legacy.cmd.",
    PlagLoader.__name__: "legacy.loader.",
}


def pass_id(fn) -> str:
    prefix = _MODULE_PREFIX.get(fn.__module__, "legacy.ps.")
    if fn is PlagDeobfus._magic_decode_runs:
        prefix = "legacy.magic."
    return prefix + fn.__name__.lstrip("_")


class LegacyPSPass(FunctionPass):
    """One PlagDeobfus/PlagFold pass. The legacy engine ran these on every
    input; here they read PowerShell and anything not identified as another
    language."""


class LegacyLoaderPass(FunctionPass):
    """PlagLoader's XOR byte-array loader recovery."""


class LegacyJsPass(FunctionPass):
    pass


class LegacyVbsPass(FunctionPass):
    pass


class LegacyCmdPass(FunctionPass):
    pass


class LegacyMagicPass(FunctionPass):
    """The CyberChef-style recipe search, tried only when nothing else moved."""


_ADAPTER_FOR_MODULE = {
    PlagJs.__name__: (LegacyJsPass, {Lang.JAVASCRIPT}),
    PlagVbs.__name__: (LegacyVbsPass, {Lang.VBSCRIPT}),
    PlagCmd.__name__: (LegacyCmdPass, {Lang.BATCH}),
    PlagLoader.__name__: (LegacyLoaderPass, set(Lang.PS_LIKE)),
}


def wrap(label: str, fn, *, after=(), languages=None, fallback: bool = False) -> FunctionPass:
    cls, langs = _ADAPTER_FOR_MODULE.get(fn.__module__, (LegacyPSPass, set(Lang.PS_LIKE)))
    if fallback:
        cls = LegacyMagicPass
    return cls(pass_id(fn), fn, label, kind=_KINDS.get(fn.__name__, Kind.FOLD),
               languages=languages if languages is not None else langs,
               after=after, fallback=fallback)


def _chain(pairs, **kwargs) -> list[FunctionPass]:
    out: list[FunctionPass] = []
    for label, fn in pairs:
        out.append(wrap(label, fn, after=(out[-1].id,) if out else (), **kwargs))
    return out


def ps_passes() -> list[FunctionPass]:
    """PlagDeobfus.core_passes(), loader included, in legacy order."""
    return _chain(PlagDeobfus.core_passes())


JS_PASSES = [
    ("resolved String.fromCharCode sequence(s)", PlagJs.resolve_char_codes),
    ("decoded JScript escape/atob/base64 value(s)", PlagJs.decode_encodings),
    ("folded JScript + concatenation", PlagJs.fold_concatenation),
    ("folded JScript string method chain(s)", PlagJs.fold_string_methods),
    ("propagated JScript literal variable(s)", PlagJs.track_variables),
]
VBS_PASSES = [
    ("resolved VBScript Chr() character(s)", PlagVbs.resolve_chr),
    ("folded VBScript & concatenation", PlagVbs.fold_concatenation),
    ("folded VBScript string call(s)", PlagVbs.resolve_string_calls),
    ("decoded VBScript base64 literal(s)", PlagVbs.decode_base64_literals),
    ("propagated VBScript literal variable(s)", PlagVbs.track_variables),
]
CMD_PASSES = [("expanded batch variable(s)", PlagCmd.resolve_variables)]


def js_passes() -> list[FunctionPass]:
    return _chain(JS_PASSES)


def vbs_passes() -> list[FunctionPass]:
    return _chain(VBS_PASSES)


def cmd_passes() -> list[FunctionPass]:
    return _chain(CMD_PASSES)


def magic_pass(languages=None) -> FunctionPass:
    (label, fn), = PlagDeobfus.fallback_passes()
    return wrap(label, fn, fallback=True,
                languages=languages if languages is not None else
                Lang.PS_LIKE | {Lang.BATCH, Lang.JAVASCRIPT, Lang.VBSCRIPT})


def legacy_plan(source: str) -> tuple[list[FunctionPass], list[FunctionPass]]:
    """Exactly the legacy engine's pass list for this input: the core passes
    for everything, then whichever language bundles its whole-file sniff
    picked, then the recipe search as the fallback stage."""
    main = [wrap(label, fn) for label, fn in PlagDeobfus.core_passes()]
    main += [wrap(label, fn) for label, fn in PlagDeobfus._language_passes(source)]
    fallback = [wrap(label, fn, fallback=True) for label, fn in PlagDeobfus.fallback_passes()]
    return main, fallback
