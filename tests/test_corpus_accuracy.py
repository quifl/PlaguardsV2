"""Accuracy gates against the labelled corpus.

These are not unit tests. They are release gates: they pin the engine's
measured behaviour on a corpus whose ground truth comes from the seed rather
than from the engine, so a change that quietly makes deobfuscation worse fails
here even when every unit test still passes.

Two numbers gate a release:

  sample completeness   every ground-truth indicator recovered, per sample
  false indicators      indicators reported that are not in the ground truth

The second is the important one. The audit that produced this corpus found the
engine's dominant failure mode was not missing an answer but inventing one, and
a false indicator is what that looks like from the analyst's side. The floor
for it is a ratchet: it may go down, never up.

The dev split is the one to iterate against. The holdout split uses disjoint
payloads and parameterisation and exists to catch tuning-to-the-test; read its
aggregate number only, and never fix an individual holdout failure directly.
"""
from __future__ import annotations

import pytest

from corpus import generator as gen
from corpus import metrics as met
from corpus.harness import run_engine as _engine

# Ratchets. Raise them when a change genuinely improves the engine; never
# lower them to make a failing build green. Measured at 100% on both splits
# when these were set, so the 0.95 floor leaves room for a corpus that grows
# harder without turning every addition into a build break.
MIN_SAMPLE_COMPLETENESS = 0.95
MAX_FALSE_INDICATORS = 0


def _card(split: str):
    samples = gen.build(split)
    scores = [met.score_sample(s, _engine) for s in samples]
    return met.scorecard(scores), scores


@pytest.fixture(scope="module")
def dev():
    return _card("dev")


def test_dev_sample_completeness_meets_the_floor(dev):
    card, _ = dev
    assert card["sample_completeness"] >= MIN_SAMPLE_COMPLETENESS, (
        "\n" + met.render(card, "dev split - BELOW FLOOR")
    )


def test_no_false_indicators_on_dev(dev):
    """A reported indicator absent from the ground truth means the engine
    resolved something incorrectly and handed the analyst a value that was
    never in the sample. That is the defect class this corpus exists for."""
    card, scores = dev
    offenders = [(s.sample_id, sorted(s.extra)) for s in scores if s.extra]
    assert card["false_indicators"] <= MAX_FALSE_INDICATORS, (
        f"\n{card['false_indicators']} false indicator(s):\n"
        + "\n".join(f"  {sid}: {extra}" for sid, extra in offenders[:15])
    )


def test_no_sample_raises(dev):
    card, _ = dev
    assert card["errors"] == 0, f"\n{card['error_detail']}"


def test_deep_staging_still_resolves(dev):
    """Nested Base64 staging was measured at 0% from depth 2 onward before the
    payload-destruction fix. Depth is the axis that regressed hardest, so it
    gets its own gate rather than hiding inside the average."""
    _, scores = dev
    deep = [s for s in scores if s.stages >= 2]
    ok = sum(1 for s in deep if s.complete)
    assert deep, "corpus generated no deep-staged samples"
    assert ok / len(deep) >= MIN_SAMPLE_COMPLETENESS, (
        f"deep staging (depth>=2): {ok}/{len(deep)} complete"
    )


@pytest.mark.parametrize("style", sorted(gen.VALUE_STYLES))
def test_every_value_style_resolves_unstaged(style):
    """Per-style gate at depth 0. A style failing here points straight at the
    audit finding it exercises, instead of moving the aggregate by 2%."""
    samples = [s for s in gen.build("dev", styles=[style], depths=(0,))]
    scores = [met.score_sample(s, _engine) for s in samples]
    failed = [s.sample_id for s in scores if not s.complete]
    assert not failed, (
        f"style {style!r} exercises: {gen.STYLE_FINDING.get(style, '?')}\n"
        f"failing: {failed}"
    )


def test_corpus_is_deterministic():
    """A corpus whose bytes change between runs cannot be frozen, and a
    holdout that cannot be frozen is not a holdout. This caught gzip stamping
    the current time into its header."""
    first = gen.corpus_fingerprint(gen.build("holdout"))
    second = gen.corpus_fingerprint(gen.build("holdout"))
    assert first == second, "corpus generation is not reproducible"


def test_splits_do_not_share_payloads():
    """The contamination control is the disjoint payload pool. If the splits
    ever share a literal, the holdout stops measuring generalisation."""
    dev_values = {v for _, v in gen.PAYLOADS["dev"]}
    hold_values = {v for _, v in gen.PAYLOADS["holdout"]}
    assert not (dev_values & hold_values), dev_values & hold_values


def test_holdout_tracks_dev():
    """Read the holdout in aggregate only.

    A large dev/holdout gap means the engine was tuned to the literals used in
    development rather than to the technique - the split exists to make that
    visible, so the assertion is on the gap, not on holdout alone.
    """
    dev_card, _ = _card("dev")
    hold_card, _ = _card("holdout")
    gap = dev_card["sample_completeness"] - hold_card["sample_completeness"]
    assert gap <= 0.10, (
        f"dev {dev_card['sample_completeness']:.1%} vs "
        f"holdout {hold_card['sample_completeness']:.1%} - "
        "a gap this wide suggests tuning to the dev literals"
    )
