"""The pass protocol and the registry that orders passes.

A pass reads one artifact's text and may return new text, child stages, or
both. Ordering is declared, not implied by list position: `after` is a soft
constraint (honoured when both passes run for a language), `requires` a hard
one (the named pass must be registered), and `replaces` withdraws another
pass wherever this one applies. Registration order breaks ties, so a
registry built in the legacy order reproduces the legacy order exactly.
"""
from __future__ import annotations

import contextvars
import heapq
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field

from .PlagArtifact import ChildSpec


class Kind:
    NORMALIZE = "NORMALIZE"
    DECODE = "DECODE"
    FOLD = "FOLD"
    RESOLVE = "RESOLVE"
    STRUCTURAL = "STRUCTURAL"
    HANDOFF = "HANDOFF"
    EXTRACT = "EXTRACT"
    SEMANTIC = "SEMANTIC"

    ALL = frozenset({NORMALIZE, DECODE, FOLD, RESOLVE, STRUCTURAL, HANDOFF, EXTRACT, SEMANTIC})


class RegistryError(ValueError):
    pass


# A secret drawn per run and written into every token the scheduler uses
# (child tokens, comment tokens, layer sentinels). A sample whose decoded text
# spells out a token cannot match one it never saw. Block-element characters:
# no letters or digits for a pass to rewrite, no syntax in any script language.
_NONCE = contextvars.ContextVar("plaguards_token_nonce", default="")
_NONCE_ALPHABET = "".join(chr(c) for c in range(0x2580, 0x25A0))


def token_nonce() -> str:
    return _NONCE.get()


@contextmanager
def token_scope():
    """A fresh nonce for the duration of one run."""
    token = _NONCE.set("".join(secrets.choice(_NONCE_ALPHABET) for _ in range(8)))
    try:
        yield
    finally:
        _NONCE.reset(token)


def child_token(index: int) -> str:
    """Placeholder a pass leaves where its index-th child stage was.

    The scheduler swaps it for the layer marker once the child is accepted,
    or for the original text when a gate or limit rejects the child, so a
    rejected stage never leaves a hole in its parent.
    """
    return f"\x00CHILD{_NONCE.get()}{index}\x00"


@dataclass
class Record:
    """One change a pass made, as it is logged."""
    label: str
    detail: str = ""
    assumed: bool = False


@dataclass
class PassResult:
    new_content: str | None = None
    children: list[ChildSpec] = field(default_factory=list)
    confidence: float = 1.0
    assumed: bool = False
    records: list[Record] = field(default_factory=list)
    # Observations that change nothing: a handoff that is reported but not
    # followed, a limit a pass hit. Logged once, never counted as progress.
    notes: list[Record] = field(default_factory=list)
    limits: list[dict] = field(default_factory=list)


@dataclass
class Context:
    """What a pass may know beyond the text: the artifact it is reading and
    state that persists across rounds of the same artifact."""
    artifact: object
    limits: object
    state: dict = field(default_factory=dict)


class Pass:
    id: str = ""
    kind: str = Kind.FOLD
    languages: frozenset = frozenset()
    requires: tuple = ()
    after: tuple = ()
    replaces: tuple = ()
    label: str = ""
    once: bool = False        # a parse, not a fold: re-running it would re-unescape its own output
    fallback: bool = False    # tried only in a round where nothing else changed
    confidence: float = 1.0

    def apply(self, text: str, ctx: Context) -> PassResult:  # pragma: no cover - interface
        raise NotImplementedError


class FunctionPass(Pass):
    """Adapts a legacy `fn(text) -> (new_text, changed, detail)` pass."""

    def __init__(self, pass_id: str, fn, label: str, *, kind: str = Kind.FOLD, languages=(),
                 after=(), requires=(), replaces=(), fallback: bool = False, once: bool = False,
                 confidence: float = 1.0):
        self.id = pass_id
        self.fn = fn
        self.label = label
        self.kind = kind
        self.languages = frozenset(languages)
        self.after = tuple(after)
        self.requires = tuple(requires)
        self.replaces = tuple(replaces)
        self.fallback = fallback
        self.once = once
        self.confidence = confidence

    def apply(self, text: str, ctx: Context) -> PassResult:
        new_text, changed, detail = self.fn(text)
        if not changed:
            return PassResult()
        return PassResult(
            new_content=new_text,
            confidence=self.confidence,
            assumed="assumed" in self.label.lower(),
            records=[Record(self.label, detail, "assumed" in self.label.lower())],
        )


class Registry:
    def __init__(self, passes=()):
        self._passes: dict[str, Pass] = {}
        self._index: dict[str, int] = {}
        self._ordered: dict[str | None, list[Pass]] = {}
        for p in passes:
            self.register(p)

    def register(self, p: Pass) -> Pass:
        if not p.id:
            raise RegistryError("a pass needs an id")
        if p.id in self._passes:
            raise RegistryError(f"duplicate pass id {p.id!r}")
        if p.kind not in Kind.ALL:
            raise RegistryError(f"{p.id}: unknown kind {p.kind!r}")
        self._index[p.id] = len(self._index)
        self._passes[p.id] = p
        self._ordered.clear()
        return p

    def __contains__(self, pass_id: str) -> bool:
        return pass_id in self._passes

    def __len__(self) -> int:
        return len(self._passes)

    def get(self, pass_id: str) -> Pass:
        return self._passes[pass_id]

    def validate(self) -> None:
        self._ordered.clear()
        for p in self._passes.values():
            for dep in p.requires:
                if dep not in self._passes:
                    raise RegistryError(f"{p.id} requires unregistered pass {dep!r}")
        self.ordered(None)

    def ordered(self, language: str | None) -> list[Pass]:
        """The passes for `language` (all of them for None), topologically
        sorted, with registration order breaking ties. Cached per language
        until the next registration or validate()."""
        if language not in self._ordered:
            self._ordered[language] = self._sort(language)
        return list(self._ordered[language])

    def _sort(self, language: str | None) -> list[Pass]:
        chosen = {pid: p for pid, p in self._passes.items()
                  if language is None or language in p.languages}
        if language is not None:
            withdrawn = {r for p in chosen.values() for r in p.replaces}
            chosen = {pid: p for pid, p in chosen.items() if pid not in withdrawn}

        edges: dict[str, set[str]] = {pid: set() for pid in chosen}
        indegree = {pid: 0 for pid in chosen}
        for pid, p in chosen.items():
            for dep in (*p.after, *p.requires):
                if dep in chosen and pid not in edges[dep]:
                    edges[dep].add(pid)
                    indegree[pid] += 1

        ready = [(self._index[pid], pid) for pid, n in indegree.items() if n == 0]
        heapq.heapify(ready)
        out: list[Pass] = []
        while ready:
            _rank, pid = heapq.heappop(ready)
            out.append(chosen[pid])
            for nxt in edges[pid]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    heapq.heappush(ready, (self._index[nxt], nxt))
        if len(out) != len(chosen):
            stuck = sorted(pid for pid, n in indegree.items() if n > 0)
            raise RegistryError(f"ordering cycle among passes: {', '.join(stuck)}")
        return out
