"""The Tutorial page, its figures and the tour chapters have to agree.

Three files that reference each other by string: the template names a figure
file and a tour chapter, the figures live on disk, and the chapters live in
tour.js. Nothing fails loudly when one of those names drifts - the page still
renders, just with a broken image or a button that does nothing - so the
agreement is checked here instead.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "plaguardsv2" / "PlagWeb"
TUTORIAL = ROOT / "templates" / "tutorial.html"
FIGURES = ROOT / "static" / "assets" / "tutorial"
TOUR_JS = ROOT / "static" / "tour.js"


def _tutorial() -> str:
    return TUTORIAL.read_text(encoding="utf-8")


def test_every_figure_the_tutorial_asks_for_exists():
    named = set(re.findall(r'figure\(\s*"([a-z_]+)"', _tutorial()))
    assert named, "no figures referenced - has the macro been renamed?"
    missing = sorted(n for n in named if not (FIGURES / f"{n}.png").is_file())
    assert not missing, (
        "tutorial references figures that are not on disk: "
        + ", ".join(missing)
        + " (run tools/capture_tutorial_figures.py)"
    )


def test_every_generated_figure_is_actually_used():
    """A figure nobody references is dead weight that still ships."""
    on_disk = {p.stem for p in FIGURES.glob("*.png")}
    named = set(re.findall(r'figure\(\s*"([a-z_]+)"', _tutorial()))
    assert not (on_disk - named), "unused figures: " + ", ".join(sorted(on_disk - named))


def test_every_tour_button_names_a_chapter_that_exists():
    wanted = set(re.findall(r'data-start-tour="([a-z]+)"', _tutorial()))
    wanted.discard("everything")          # the meta-chapter, assembled from ORDER
    js = TOUR_JS.read_text(encoding="utf-8")
    chapters = set(re.findall(r"^    ([a-z]+): \{$", js, re.MULTILINE))
    assert chapters, "no chapters parsed out of tour.js"
    missing = sorted(wanted - chapters)
    assert not missing, "tutorial starts tours that do not exist: " + ", ".join(missing)


def test_every_chapter_is_reachable_from_the_full_tour():
    """A chapter left out of ORDER can only be reached by a direct link, so
    "Tour everything" would silently skip it."""
    js = TOUR_JS.read_text(encoding="utf-8")
    chapters = set(re.findall(r"^    ([a-z]+): \{$", js, re.MULTILINE))
    order_block = re.search(r"const ORDER = \[(.*?)\];", js, re.S)
    assert order_block, "ORDER not found in tour.js"
    ordered = set(re.findall(r'"([a-z]+)"', order_block.group(1)))
    assert not (chapters - ordered), "chapters missing from ORDER: " + ", ".join(sorted(chapters - ordered))


def test_section_headings_are_numbered_once_and_in_sequence():
    """Two sections were both numbered 6 and the list jumped from 7 to 9."""
    numbers = [int(n) for n in re.findall(r"<h3>(\d+)\.\s", _tutorial())]
    assert numbers == list(range(1, len(numbers) + 1)), f"section numbering is {numbers}"


def test_contents_and_sections_stay_in_step():
    """The contents list, the section anchors and the back links are three
    hand-maintained lists of the same thing. Nothing breaks loudly when one
    drifts - you just get a link that scrolls nowhere."""
    html = _tutorial()
    linked = re.findall(r'<li><a[^>]*href="#([a-z-]+)"', html)
    anchored = re.findall(r'<div class="tutorial-card" id="([a-z-]+)">', html)

    assert linked, "no contents entries found"
    assert linked == anchored, (
        f"contents lists {linked} but the sections are {anchored}")
    assert html.count('class="toc-back"') == len(anchored), (
        "every section needs its own way back to the contents")
    assert 'id="contents"' in html, "the back links point at #contents"
