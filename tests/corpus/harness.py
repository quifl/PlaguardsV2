"""The engine under measurement, wired once.

Both the pytest accuracy gate and tools/bench_accuracy.py score the same
thing, so the adapter lives here rather than being written twice and drifting.
"""
from __future__ import annotations

from plaguardsv2.GuardModules import PlagDeobfus, PlagGrep, PlagTrace

# A signature finding's `value` is a rule description ("Hidden/bypass execution
# flags"), not an indicator lifted out of the sample. Counting it as one would
# score correct behavioural detections as false positives.
NON_INDICATOR_TYPES = {"signature"}


def run_engine(script: str):
    """Return (reported_indicators, visible_values, converged).

    The two sets are deliberately different. `reported` is what the engine
    claims is an indicator - the set that reaches a shared report, and so the
    set precision is measured over. `visible` is everything the analyst can
    see, including resolved variables and the deobfuscated text, and is what
    recall is measured over: an indicator surfaced in the resolved-variable
    table has been recovered even if no extractor claimed it as a finding.

    Collapsing them would punish the engine for showing its work - a resolved
    variable holding a command line is correct output, not a false indicator.
    """
    result = PlagDeobfus.run(script)
    traced = PlagTrace.trace(result.deobfuscated)
    enrich = PlagTrace.enrichment_text(traced)
    findings = PlagGrep.scan(result.original, result.deobfuscated, enrich)

    reported = {
        f.value for f in findings
        if getattr(f, "type", None) not in NON_INDICATOR_TYPES
    }
    visible = set(reported)
    visible |= {str(v) for v in (traced.variables or {}).values()}
    visible.add(result.deobfuscated)

    return reported, visible, getattr(result, "converged", None)
