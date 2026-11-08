"""The Phase 1 registry: the legacy passes, the new normalisers and the layer
handoffs, chained in the order each language reads them.

Each language's passes are chained explicitly (`after` = the previous pass),
so the order below is the order they run. Legacy passes that a new pass
supersedes stay registered and are withdrawn by `replaces`, which keeps the
substitution visible in one place.
"""
from __future__ import annotations

from . import (PlagAdapters, PlagCmdParse, PlagDeobfus, PlagJsLayer, PlagPsHandoff, PlagPsInflate,
               PlagPsNormalize, PlagVbsLayer)
from .PlagArtifact import Lang
from .PlagPassApi import Registry


def _chain(passes) -> list:
    for index, p in enumerate(passes):
        p.after = (passes[index - 1].id,) if index else ()
    return passes


def build_registry() -> Registry:
    registry = Registry()

    # The shell handoffs read PowerShell, and the command lines a JScript or
    # VBScript layer holds in its strings (`sh.Run "powershell -enc ..."`).
    enc, command, iex = PlagPsHandoff.passes()
    inflate, frombase64 = PlagPsInflate.passes()
    ps_chain = list(PlagPsNormalize.passes())
    replaced = []
    for p in PlagAdapters.ps_passes():
        if p.id == "legacy.ps.decode_encoded_command":
            ps_chain += [enc, command]
            replaced.append(p)
        elif p.id == "legacy.ps.decode_frombase64_literals":
            ps_chain += [inflate, frombase64]
            replaced.append(p)
        else:
            ps_chain.append(p)
    ps_chain.append(iex)

    # The batch parser finds every handoff itself, with each command's bounds.
    parse, batch_handoff = PlagCmdParse.passes()
    others = {Lang.BATCH, Lang.JAVASCRIPT, Lang.VBSCRIPT}
    standalone = PlagAdapters.wrap("decoded standalone encoded payload(s)",
                                   PlagDeobfus._decode_standalone_payloads, languages=others)
    standalone.id = "legacy.any.decode_standalone_payloads"
    batch_chain = [parse, batch_handoff]

    js_chain = [*PlagAdapters.js_passes(), *PlagJsLayer.passes()]
    continuation, *vbs_layer = PlagVbsLayer.passes()
    vbs_chain = [continuation, *PlagAdapters.vbs_passes(), *vbs_layer]

    for chain in (ps_chain, batch_chain, js_chain, vbs_chain):
        for p in _chain(chain):
            registry.register(p)
    # In a JScript or VBScript layer, read command lines once the strings are folded.
    enc.after = (*enc.after, "handoff.js", "handoff.vbs")
    registry.register(standalone)
    standalone.after = ()
    for p in (*replaced, *PlagAdapters.cmd_passes()):
        p.after = ()
        registry.register(p)
    registry.register(PlagAdapters.magic_pass())
    registry.validate()
    return registry
