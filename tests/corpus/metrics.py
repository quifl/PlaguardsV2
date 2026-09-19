"""Score the engine against a labelled corpus.

Primary KPI - sample completeness
---------------------------------
The fraction of samples for which EVERY ground-truth indicator is recovered.
Strict and binary, per sample, deliberately. This engine exists to hand an
analyst a complete indicator set; a sample yielding three of four indicators
saves no work, because the analyst cannot know which one is missing and still
has to read the script. Partial credit would score that 75% and overstate the
tool's value.

Co-primary KPI - false indicator rate
-------------------------------------
Indicators reported that are NOT in the ground truth. This is the observable
consequence of the silent-corruption defect class the audit was commissioned
over: a confidently wrong resolved value becomes a wrong IOC in a shared
report. It is a release gate, not a diagnostic - no change may increase it.

Everything else here is secondary and diagnostic.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SampleScore:
    sample_id: str
    style: str
    stages: int
    finding: str
    expected: set
    recovered: set
    extra: set
    complete: bool
    converged: object          # True / False / None when the engine cannot say
    error: str = ""


def _normalise(value: str) -> str:
    """Compare indicators refanged and case-folded.

    The engine defangs network indicators on the way out (malicious[.]example)
    so a literal comparison against the seed would report a miss for a value
    that was in fact recovered correctly.
    """
    v = value.strip().lower()
    for a, b in (("[.]", "."), ("[:]", ":"), ("[@]", "@"),
                 ("(.)", "."), ("hxxp", "http"), ("[dot]", ".")):
        v = v.replace(a, b)
    return v


def score_sample(sample, engine) -> SampleScore:
    """Run one sample through the engine and compare against its label.

    `engine` returns (reported_indicators, visible_values, converged):

      reported_indicators  what the engine CLAIMS is an indicator. Precision is
                           measured over these alone, because this is the set
                           that reaches a shared report as an IOC.
      visible_values       everything the analyst can see, including resolved
                           variable values. Recall is measured over these,
                           since an indicator surfaced in the resolved-variable
                           table has been recovered even if no extractor
                           claimed it.

    Keeping the two apart matters: a resolved variable holding a command line
    is correct output, not a false indicator, and scoring it as one would
    punish the engine for showing its work.
    """
    expected = {_normalise(v) for v in sample.all_iocs}
    try:
        reported_raw, visible_raw, converged = engine(sample.script)
    except Exception as exc:                       # noqa: BLE001 - harness
        return SampleScore(sample.sample_id, sample.style, sample.stages,
                           sample.finding, expected, set(), set(), False,
                           None, f"{type(exc).__name__}: {exc}")

    visible = {_normalise(v) for v in visible_raw}
    reported = {_normalise(v) for v in reported_raw}
    recovered = {e for e in expected if any(e == v or e in v for v in visible)}

    # A partially-folded fragment that is a substring of an expected value is a
    # recall problem, not a precision one, so it is not counted as false.
    extra = {
        r for r in reported
        if not any(r == e or r in e or e in r for e in expected)
    }

    return SampleScore(
        sample_id=sample.sample_id, style=sample.style, stages=sample.stages,
        finding=sample.finding, expected=expected, recovered=recovered,
        extra=extra, complete=recovered == expected and bool(expected),
        converged=converged,
    )


def scorecard(scores: list[SampleScore]) -> dict:
    n = len(scores) or 1
    complete = sum(1 for s in scores if s.complete)
    tp = sum(len(s.recovered) for s in scores)
    fn = sum(len(s.expected - s.recovered) for s in scores)
    fp = sum(len(s.extra) for s in scores)
    errors = [s for s in scores if s.error]

    by_style: dict[str, dict] = {}
    for s in scores:
        row = by_style.setdefault(s.style, {"n": 0, "ok": 0, "finding": s.finding})
        row["n"] += 1
        row["ok"] += 1 if s.complete else 0

    by_depth: dict[int, dict] = {}
    for s in scores:
        row = by_depth.setdefault(s.stages, {"n": 0, "ok": 0})
        row["n"] += 1
        row["ok"] += 1 if s.complete else 0

    return {
        "samples": len(scores),
        "sample_completeness": complete / n,          # PRIMARY
        "false_indicators": fp,                       # CO-PRIMARY (gate)
        "ioc_recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "ioc_precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "errors": len(errors),
        "by_style": by_style,
        "by_depth": by_depth,
        "error_detail": [(s.sample_id, s.error) for s in errors][:10],
    }


def render(card: dict, title: str = "scorecard") -> str:
    out = []
    out.append(f"=== {title} ===")
    out.append(f"  samples              {card['samples']}")
    out.append(f"  SAMPLE COMPLETENESS  {card['sample_completeness']:.1%}   <- primary KPI")
    out.append(f"  FALSE INDICATORS     {card['false_indicators']}        <- release gate")
    out.append(f"  ioc recall           {card['ioc_recall']:.1%}")
    out.append(f"  ioc precision        {card['ioc_precision']:.1%}")
    if card["errors"]:
        out.append(f"  ERRORS               {card['errors']}")
        for sid, err in card["error_detail"]:
            out.append(f"     {sid}: {err}")
    out.append("")
    out.append("  by value style                       n   ok   rate   exercises")
    for style, row in sorted(card["by_style"].items(),
                             key=lambda kv: kv[1]["ok"] / max(kv[1]["n"], 1)):
        rate = row["ok"] / max(row["n"], 1)
        flag = "  <-- FAILING" if rate < 0.999 else ""
        out.append(f"    {style:<22} {row['n']:5} {row['ok']:4} {rate:6.0%}   "
                   f"{row['finding']}{flag}")
    out.append("")
    out.append("  by staging depth                     n   ok   rate")
    for depth, row in sorted(card["by_depth"].items()):
        rate = row["ok"] / max(row["n"], 1)
        out.append(f"    depth {depth:<16} {row['n']:5} {row['ok']:4} {rate:6.0%}")
    return "\n".join(out)
