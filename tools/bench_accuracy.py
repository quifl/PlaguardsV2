"""Print the deobfuscation scorecard for one or both corpus splits.

    python tools/bench_accuracy.py            # both splits
    python tools/bench_accuracy.py dev        # iterate against this one
    python tools/bench_accuracy.py holdout    # aggregate reading only
    python tools/bench_accuracy.py dev --failures   # list what missed

The holdout split exists to catch tuning-to-the-test. Read its headline
numbers; do not go fixing its individual failures, or it stops being a holdout.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# tests/ is not a package (pytest puts it on sys.path itself), so the
# corpus has to be reached the same way from outside pytest.
sys.path.insert(0, str(ROOT / "tests"))

from corpus import generator as gen           # noqa: E402
from corpus import metrics as met             # noqa: E402
from corpus.harness import run_engine as engine   # noqa: E402


def run(split: str, show_failures: bool = False) -> dict:
    samples = gen.build(split)
    print(f"[{split}] {len(samples)} samples | "
          f"{len(set(s.config_id for s in samples))} configs | "
          f"fingerprint {gen.corpus_fingerprint(samples)}")
    scores = [met.score_sample(s, engine) for s in samples]
    card = met.scorecard(scores)
    print(met.render(card, f"{split} split"))

    if show_failures:
        print("\n  failures")
        for s in scores:
            if s.complete:
                continue
            missing = sorted(s.expected - s.recovered)
            extra = sorted(s.extra)
            print(f"    {s.sample_id}")
            if missing:
                print(f"       missing: {missing}")
            if extra:
                print(f"       FALSE:   {extra}")
    print()
    return card


def main() -> int:
    argv = [a for a in sys.argv[1:] if not a.startswith("-")]
    show = "--failures" in sys.argv
    which = argv[0] if argv else "both"
    splits = ["dev", "holdout"] if which == "both" else [which]

    cards = {s: run(s, show) for s in splits}

    if len(cards) == 2:
        gap = (cards["dev"]["sample_completeness"]
               - cards["holdout"]["sample_completeness"])
        print(f"dev-holdout gap: {gap:+.1%}", end="  ")
        print("(a wide positive gap suggests tuning to the dev literals)"
              if gap > 0.10 else "(splits agree)")

    # Non-zero exit if the release gate is breached, so CI can depend on it.
    breached = [s for s, c in cards.items() if c["false_indicators"] > 0]
    if breached:
        print(f"\nGATE BREACHED: false indicators present in {', '.join(breached)}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
