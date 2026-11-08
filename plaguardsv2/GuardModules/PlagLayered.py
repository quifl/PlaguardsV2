"""The layered pipeline: a tree of artifacts, each deobfuscated by the passes
for its own language until nothing changes.

A stage one layer down - a decoded -EncodedCommand, a string handed to
Invoke-Expression, the command inside `powershell -c` - becomes a child
artifact with its own language and its own passes, instead of being pasted
into its parent. That is what keeps PowerShell folding out of a batch layer,
and what lets every indicator be traced to the layer it came from.

Modes:
  layered       the full registry, languages decided per artifact
  adapters      legacy passes only, languages decided per artifact
  legacy-sniff  legacy passes in legacy order, languages picked by the legacy
                whole-file sniff; reproduces PlagDeobfus.run byte for byte
Nothing in any mode executes the input.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from functools import lru_cache

from . import PlagAdapters, PlagDeobfus, PlagEval, PlagGates, PlagRouter
from .PlagArtifact import DEFAULT_LIMITS, MARKER_SLOT, Artifact, ChildSpec, Lang, Limits, sha256
from .PlagDeobfus import DeobfuscationResult, TransformRecord
from .PlagPassApi import Context, Kind, PassResult, Record, Registry, token_nonce, token_scope

MODES = ("layered", "adapters", "legacy-sniff")
SCHEMA_VERSION = "1.0"

_PARSE_GATED = {Kind.NORMALIZE, Kind.FOLD, Kind.RESOLVE, Kind.STRUCTURAL}
_TYPE_GATED = {Kind.FOLD, Kind.RESOLVE}
_PROGRESS_KINDS = {Kind.DECODE, Kind.HANDOFF, Kind.EXTRACT}
# The complexity rule judges rounds of pure folding only: expansion, decoding
# and normalisation legitimately make text longer or busier on the way.
_PURE_FOLD_KINDS = {Kind.FOLD, Kind.STRUCTURAL}
# Passes whose output may grow by what they decode: held to the decoded-bytes
# budget and the decompression ratio even when they are legacy passes.
_GROWTH_KINDS = {Kind.DECODE, Kind.SEMANTIC}


def marker(artifact_id: int) -> str:
    """How a layer's place in its parent reads in the output."""
    return f"<<layer {artifact_id}>>"


# While passes run, a layer's place is held by a sentinel: the run's nonce and
# the layer id between two brackets no script language treats as syntax. No
# letters, so a pass that substitutes identifiers (a VBScript variable named
# `layer`) cannot rewrite it; printable, so a pass that re-quotes a string
# keeps it as it is; nonced, so a sample cannot decode its way to one.
_OPEN, _CLOSE = "\u27e6", "\u27e7"


def sentinel(artifact_id: int) -> str:
    return f"{_OPEN}{token_nonce()}{artifact_id}{_CLOSE}"


@lru_cache(maxsize=8)
def _patterns(nonce: str):
    """This run's (sentinel, comment token, child token) patterns."""
    n = re.escape(nonce)
    return (re.compile(_OPEN + n + r"(\d+)" + _CLOSE),
            re.compile("\x00CMT" + n + r"(\d+)\x00"),
            re.compile("\x00CHILD" + n + r"(\d+)\x00"))


def _show_markers(text: str) -> str:
    if _OPEN not in text:
        return text
    return _patterns(token_nonce())[0].sub(lambda m: marker(int(m.group(1))), text)


def _display(text: str) -> str:
    """Text as a preview shows it: layer markers, and comment tokens in the
    form the legacy previewer folds to `<comment>`."""
    text = _show_markers(text)
    if "\x00CMT" in text:
        text = _patterns(token_nonce())[1].sub(lambda m: f"\x00CMT{m.group(1)}\x00", text)
    return text


def _unmask(text: str, comments) -> str:
    """Comments back in place. Only this run's tokens: a sample that decodes
    to something token-shaped keeps it as data."""
    if not comments or "\x00CMT" not in text:
        return text

    def put(m: re.Match) -> str:
        index = int(m.group(1))
        return comments[index] if index < len(comments) else m.group(0)
    return _patterns(token_nonce())[1].sub(put, text)


# Per-language reading and writing. PowerShell (and anything read as it)
# keeps the legacy treatment: comments masked while passes run, statements
# put on their own lines afterwards. Other languages are only line-normalised;
# PowerShell's comment and statement rules would misread them.

def _pre_ps(content: str):
    text = PlagDeobfus._normalize(content)
    return PlagDeobfus._mask_comments(text)


def _post_ps(text: str, comments):
    text = PlagDeobfus._unmask_comments(text, comments)
    raw = PlagDeobfus._final_cleanup(text)
    return PlagDeobfus._final_cleanup(PlagDeobfus.prettify(text)), raw


def _pre_ps_layered(content: str):
    text, comments = _pre_ps(content)
    if comments:
        nonce = token_nonce()
        text = PlagDeobfus._COMMENT_TOKEN_RE.sub(lambda m: f"\x00CMT{nonce}{m.group(1)}\x00", text)
    return text, comments


def _post_ps_layered(text: str, comments):
    text = _unmask(text, comments)
    raw = PlagDeobfus._final_cleanup(text)
    return PlagDeobfus._final_cleanup(PlagDeobfus.prettify(text)), raw


def _pre_plain(content: str):
    return content.replace("\r\n", "\n").replace("\r", "\n"), None


def _pre_batch(content: str):
    # cmd.exe drops carriage returns while reading a line rather than ending it.
    return content.replace("\r\n", "\n").replace("\r", ""), None


def _post_plain(text: str, _state):
    clean = PlagDeobfus._final_cleanup(text)
    return clean, clean


_PS = (_pre_ps_layered, _post_ps_layered)
_PROCESSORS = {
    Lang.POWERSHELL: _PS,
    Lang.TEXT: _PS,
    Lang.UNKNOWN: _PS,
    Lang.BATCH: (_pre_batch, _post_plain),
    Lang.JAVASCRIPT: (_pre_plain, _post_plain),
    Lang.VBSCRIPT: (_pre_plain, _post_plain),
    Lang.HTA: _PS,
    Lang.WSF: _PS,
}


@dataclass
class LayeredResult:
    mode: str
    artifacts: list[Artifact]
    transforms: list[TransformRecord]
    pass_log: list[str]
    view: DeobfuscationResult
    truncated: bool = False
    limits_hit: list[dict] = field(default_factory=list)
    needs_review: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    notes: list[dict] = field(default_factory=list)
    rounds: int = 0
    duration_ms: float = 0.0
    input_sha256: str = ""
    input_size: int = 0
    _paths: dict = field(default_factory=dict, repr=False)

    @property
    def root(self) -> Artifact:
        return self.artifacts[0]

    def artifact(self, artifact_id: int) -> Artifact:
        # Ids are assigned 1, 2, 3... in creation order.
        if 1 <= artifact_id <= len(self.artifacts) and self.artifacts[artifact_id - 1].id == artifact_id:
            return self.artifacts[artifact_id - 1]
        raise KeyError(artifact_id)

    def layer_path(self, artifact_id: int) -> str:
        """`1/3/4`: the artifact ids from the root down to this one."""
        if artifact_id not in self._paths:
            art = self.artifact(artifact_id)
            parent = "" if art.parent_id is None else self.layer_path(art.parent_id) + "/"
            self._paths[artifact_id] = parent + str(artifact_id)
        return self._paths[artifact_id]


def adapters_registry() -> Registry:
    """Phase 0: the legacy passes and nothing else."""
    registry = Registry()
    for p in (*PlagAdapters.ps_passes(), *PlagAdapters.js_passes(), *PlagAdapters.vbs_passes(),
              *PlagAdapters.cmd_passes(), PlagAdapters.magic_pass()):
        registry.register(p)
    registry.validate()
    return registry


def default_registry() -> Registry:
    """Phase 1: the legacy passes plus the layer handoffs and new normalisers."""
    from . import PlagPhase1
    return PlagPhase1.build_registry()


_REGISTRIES: dict[str, Registry] = {}


def registry_for(mode: str) -> Registry:
    if mode not in _REGISTRIES:
        _REGISTRIES[mode] = default_registry() if mode == "layered" else adapters_registry()
    return _REGISTRIES[mode]


@dataclass
class _Stage:
    changed: bool = False
    progressed: bool = False   # decoded, handed off or extracted something
    kinds: set = field(default_factory=set)


# What the scheduler's own tokens are made of: NUL (child and comment tokens)
# and the sentinel brackets. Replaced in anything a sample supplies, so a
# sample cannot plant a token or fake a layer marker.
_RESERVED = {"\x00": "nul-bytes-replaced", _OPEN: "marker-brackets-replaced", _CLOSE: "marker-brackets-replaced"}


def _sanitize(text: str) -> tuple[str, set]:
    flags = set()
    for ch, flag in _RESERVED.items():
        if ch in text:
            text = text.replace(ch, "\ufffd")
            flags.add(flag)
    return text, flags


class _Run:
    def __init__(self, source: str, mode: str, limits: Limits, registry: Registry | None):
        if mode not in MODES:
            raise ValueError(f"unknown mode {mode!r}")
        self.source = source
        self.mode = mode
        self.legacy = mode == "legacy-sniff"
        self.limits = limits
        self.registry = registry if registry is not None else (
            None if self.legacy else registry_for(mode))
        self.artifacts: list[Artifact] = []
        self.queue: list[Artifact] = []
        self.by_hash: dict[str, int] = {}
        self.transforms: list[TransformRecord] = []
        self.logs: dict[int, list[str]] = {}
        self.limits_hit: list[dict] = []
        self.needs_review: list[dict] = []
        self.rejected: list[dict] = []
        self.errors: list[dict] = []
        self.notes: list[dict] = []
        self.decoded_total = 0
        self.truncated = False

    # bookkeeping

    def _log(self, art: Artifact, entry: str) -> None:
        self.logs.setdefault(art.id, []).append(entry)

    def _limit(self, name: str, art: Artifact, detail: str) -> None:
        entry = {"limit": name, "artifact_id": art.id, "detail": detail}
        if entry not in self.limits_hit:
            self.limits_hit.append(entry)

    def _note(self, p, art: Artifact, note: Record) -> None:
        entry = {"artifact_id": art.id, "pass_id": p.id, "kind": p.kind,
                 "label": note.label, "detail": note.detail}
        if entry in self.notes:
            return
        self.notes.append(entry)
        self._log(art, f"Noted: {note.label}" + (f" ({note.detail})" if note.detail else ""))

    def _get(self, artifact_id: int | None) -> Artifact | None:
        if artifact_id is None:
            return None
        return self.artifacts[artifact_id - 1]

    # run

    def run(self) -> LayeredResult:
        with token_scope():
            return self._run()

    def _run(self) -> LayeredResult:
        start = time.perf_counter()
        text = self._cap_input(self.source)
        flags = set()
        if not self.legacy:
            if text.startswith("\ufeff"):
                text = text[1:]
                flags.add("byte-order-mark-removed")
            text, replaced = _sanitize(text)
            flags |= replaced
        root = Artifact(id=1, parent_id=None, language=PlagRouter.identify(text), content=text,
                        marker=marker(1), flags=flags)
        self._add(root)
        while self.queue:
            self._process(self.queue.pop(0))
        result = self._result()
        result.duration_ms = (time.perf_counter() - start) * 1000
        return result

    def _cap_input(self, text: str) -> str:
        cap = PlagDeobfus.MAX_INPUT_SIZE if self.legacy else self.limits.max_input_bytes
        if len(text) <= cap and (self.legacy or len(text) * 4 <= cap
                                 or len(text.encode("utf-8", "surrogatepass")) <= cap):
            return text
        self.truncated = True
        if not self.legacy:
            data = text.encode("utf-8", "surrogatepass")[:cap]
            self.limits_hit.append({"limit": "max_input_bytes", "artifact_id": 1,
                                    "detail": f"input cut to its first {cap} bytes"})
            return data.decode("utf-8", "ignore")
        return text[:cap]

    def _add(self, art: Artifact) -> None:
        self.artifacts.append(art)
        self.queue.append(art)
        self.by_hash.setdefault(art.sha256, art.id)

    def _plan(self, art: Artifact):
        if self.legacy:
            return PlagAdapters.legacy_plan(self.source)
        # Containers get their own extraction in a later phase; until then
        # they are read as text, which is what the legacy engine did.
        language = Lang.TEXT if art.language in (Lang.HTA, Lang.WSF) else art.language
        ordered = self.registry.ordered(language)
        return [p for p in ordered if not p.fallback], [p for p in ordered if p.fallback]

    def _premask(self, art: Artifact, main, ctx: Context) -> str:
        """Run the normalisers that must see the text before comments are
        masked: a typographic quote is invisible to the masker, so a `#`
        inside a curly-quoted string would be masked as a comment."""
        content = art.content
        for p in main:
            if not getattr(p, "premask", False):
                continue
            try:
                result = p.apply(content, ctx)
            except Exception as exc:  # noqa: BLE001
                self.errors.append({"pass_id": p.id, "artifact_id": art.id,
                                    "error": f"{type(exc).__name__}: {exc}"[:300]})
                continue
            if result.new_content is None:
                continue
            before, content = content, result.new_content
            preview_before, preview_after = PlagDeobfus._change_previews(before, content)
            for rec in result.records or [Record(p.label, "")]:
                self._log(art, f"Pass 1: {rec.label}" + (f" ({rec.detail})" if rec.detail else ""))
                self.transforms.append(TransformRecord(
                    name=rec.label, detail=rec.detail, before=preview_before, after=preview_after,
                    assumed=rec.assumed, iteration=1, pass_id=p.id, kind=p.kind,
                    confidence=result.confidence, artifact_id=art.id))
        return content

    def _process(self, art: Artifact) -> None:
        if isinstance(art.content, bytes) or art.language == Lang.BINARY:
            art.final = art.final_raw = ""
            return
        pre, post = (_pre_ps, _post_ps) if self.legacy else _PROCESSORS.get(art.language, _PS)
        main, fallback = self._plan(art)
        ctx = Context(artifact=art, limits=self.limits, state={})
        content = art.content if self.legacy else self._premask(art, main, ctx)
        text, state = pre(content)
        ctx.state["comments"] = state
        max_rounds = PlagDeobfus.MAX_PASSES if self.legacy else self.limits.max_rounds_per_layer
        gate_language = Lang.POWERSHELL if self.legacy else art.language
        seen = {sha256(text)}

        for round_no in range(1, max_rounds + 1):
            art.rounds = round_no
            round_start = text
            marks = (len(self.logs.get(art.id, [])), len(self.transforms))
            stage, text = self._stage(main, text, art, ctx, round_no)
            if not stage.changed:
                stage, text = self._stage(fallback, text, art, ctx, round_no)
            if not stage.changed:
                break
            if (stage.kinds and stage.kinds <= _PURE_FOLD_KINDS and len(text) >= len(round_start)
                    and PlagGates.operator_count(text, gate_language)
                    > PlagGates.operator_count(round_start, gate_language)):
                # Folding is meant to make a script simpler; a round of pure folding
                # that grew the text and left more string-building operations than it
                # resolved is undone rather than kept.
                text = round_start
                del self.logs.setdefault(art.id, [])[marks[0]:]
                del self.transforms[marks[1]:]
                self._limit("complexity", art, f"round {round_no} raised complexity and was rolled back")
                break
            digest = sha256(text)
            if digest in seen:
                self._limit("cycle", art, f"round {round_no} reproduced an earlier state")
                break
            seen.add(digest)
        else:
            art.converged = False
            if self.legacy:
                self._log(art, f"Fixed point not reached after {PlagDeobfus.MAX_PASSES} passes: output is "
                               f"only partially deobfuscated and may still contain encoded stages")
            else:
                self._log(art, f"Fixed point not reached after {max_rounds} rounds: output is only "
                               f"partially deobfuscated and may still contain encoded stages")
                self._limit("max_rounds_per_layer", art, f"{max_rounds} rounds")

        final, raw = post(text, state)
        final, raw = _show_markers(final), _show_markers(raw)
        if not self.legacy:
            # A NUL some pass decoded is data, and reports cannot carry it.
            final, raw = final.replace("\x00", "\ufffd"), raw.replace("\x00", "\ufffd")
        art.final, art.final_raw = final, raw

    def _stage(self, passes, text: str, art: Artifact, ctx: Context, round_no: int):
        stage = _Stage()
        for p in passes:
            if p.once and round_no > 1:
                continue
            try:
                result = p.apply(text, ctx)
            except Exception as exc:  # noqa: BLE001 - one pass failing must not lose the artifact
                self.errors.append({"pass_id": p.id, "artifact_id": art.id,
                                    "error": f"{type(exc).__name__}: {exc}"[:300]})
                continue
            if result is None:
                continue
            for hit in result.limits:
                self._limit(hit.get("limit", "limit"), art, hit.get("detail", ""))
            for note in result.notes:
                self._note(p, art, note)
            if result.new_content is None and not result.children:
                continue
            text, changed, progressed = self._commit(p, result, text, art, ctx, round_no)
            if changed:
                stage.kinds.add(p.kind)
            stage.changed |= changed
            stage.progressed |= progressed
        return stage, text

    def _commit(self, p, result: PassResult, text: str, art: Artifact, ctx: Context, round_no: int):
        """Gate one pass's output, admit its children, and log it."""
        base = {"pass_id": p.id, "artifact_id": art.id, "round": round_no}
        if result.confidence < self.limits.routing_review_floor:
            self.rejected.append({**base, "reason": f"confidence {result.confidence:.2f} below review floor"})
            return text, False, False
        proposed = result.new_content if result.new_content is not None else text
        probe = _swap_tokens(proposed, [s.template.replace(MARKER_SLOT, sentinel(0)) for s in result.children])

        gates: dict = {}
        language = Lang.POWERSHELL if self.legacy else art.language
        checks = []
        if p.kind in _PARSE_GATED:
            checks.append(PlagGates.parse_gate(text, probe, language))
        if p.kind in _TYPE_GATED:
            checks.append(PlagGates.typed_literal_gate(text, probe, language))
        for gate in checks:
            gates[gate.name] = gate.ok
            if not gate.ok:
                self.rejected.append({**base, "reason": f"{gate.name}: {gate.reason}"})
                return text, False, False

        if not self.legacy and p.kind in _GROWTH_KINDS and result.new_content is not None:
            growth = len(probe) - len(text)
            if growth > self.limits.max_decompression_ratio * max(len(text), 4096):
                self._limit("max_decompression", art,
                            f"{p.id}: output would grow by {growth} characters, over "
                            f"{self.limits.max_decompression_ratio}x the text it read")
                return text, False, False
            if growth > 0 and self.decoded_total + growth > self.limits.max_decoded_bytes_total:
                self._limit("max_decoded_bytes_total", art, f"{p.id}: decoded-size budget spent")
                return text, False, False

        replacements, admitted = [], []
        for spec in result.children:
            child_id = self._admit(spec, art, ctx, round_no)
            if child_id is None:
                replacements.append(spec.source_span)
            else:
                admitted.append(child_id)
                replacements.append(spec.template.replace(MARKER_SLOT, sentinel(child_id)))
        new_text = _swap_tokens(proposed, replacements)
        if result.new_content is None and not admitted:
            return text, False, False
        if result.children and not admitted and new_text == text:
            return text, False, False
        if not self.legacy and p.kind in _GROWTH_KINDS:
            self.decoded_total += max(0, len(new_text) - len(text))

        if result.confidence < self.limits.routing_auto_apply:
            self.needs_review.append({**base, "confidence": result.confidence,
                                      "labels": [r.label for r in result.records]})
        records = result.records or [Record(p.label, "")]
        # Previews read like the output: layer markers, not sentinels.
        preview_before, preview_after = PlagDeobfus._change_previews(_display(text), _display(new_text))
        for rec in records:
            entry = f"Pass {round_no}: {rec.label}"
            if rec.detail:
                entry += f" ({rec.detail})"
            self._log(art, entry)
            self.transforms.append(TransformRecord(
                name=rec.label, detail=rec.detail, before=preview_before,
                after=preview_after, assumed=rec.assumed or result.assumed,
                iteration=round_no, pass_id=p.id, kind=p.kind, confidence=result.confidence,
                gates=gates, artifact_id=art.id,
            ))
        progressed = p.kind in _PROGRESS_KINDS or bool(admitted)
        return new_text, True, progressed

    def _admit(self, spec: ChildSpec, parent: Artifact, ctx: Context, round_no: int) -> int | None:
        base = {"artifact_id": parent.id, "round": round_no, "edge": spec.edge, "detail": spec.detail}
        depth = parent.depth + 1
        if depth > self.limits.max_layer_depth:
            self._limit("max_layer_depth", parent, f"a stage at depth {depth} was not opened")
            return None
        if len(self.artifacts) >= self.limits.max_artifacts:
            self._limit("max_artifacts", parent, f"{self.limits.max_artifacts} layers: further stages not opened")
            return None
        content = spec.content
        comments = ctx.state.get("comments")
        if isinstance(content, str):
            content = _show_markers(_unmask(content, comments))
        # Gated before NULs are replaced: a stage of NULs is noise, not text.
        gate = PlagGates.decoded_content_gate(content)
        if not gate.ok:
            self.rejected.append({**base, "reason": f"{gate.name}: {gate.reason}"})
            return None
        if isinstance(content, str):
            content, _replaced = _sanitize(content)
        size = len(content) if isinstance(content, bytes) else len(content.encode("utf-8", "surrogatepass"))
        if self.decoded_total + size > self.limits.max_decoded_bytes_total:
            self._limit("max_decoded_bytes_total", parent, "stage not opened: decoded-size budget spent")
            return None
        digest = sha256(content)
        ancestor: Artifact | None = parent
        while ancestor is not None:
            if ancestor.sha256 == digest:
                self.rejected.append({**base, "reason": "stage is identical to one of its own ancestors"})
                return None
            ancestor = self._get(ancestor.parent_id)
        if digest in self.by_hash:
            return self.by_hash[digest]
        language = PlagRouter.identify(content, hint=spec.language)
        new_id = len(self.artifacts) + 1
        child = Artifact(
            id=new_id, parent_id=parent.id, language=language, content=content,
            encoding=spec.encoding, origin_edge=spec.edge, edge_detail=spec.detail, depth=depth,
            marker=marker(new_id), source_span=_show_markers(spec.source_span),
            inherit=dict(spec.inherit or {}),
        )
        self.decoded_total += size
        self._add(child)
        return child.id

    # output

    def _result(self) -> LayeredResult:
        root = self.artifacts[0]
        pass_log: list[str] = []
        for art in self.artifacts:
            prefix = "" if art is root else f"[layer {art.id}] "
            pass_log.extend(prefix + entry for entry in self.logs.get(art.id, []))
        deobfuscated = render(self.artifacts, "final")
        raw = render(self.artifacts, "final_raw")
        if self.truncated:
            cap = PlagDeobfus.MAX_INPUT_SIZE if self.legacy else self.limits.max_input_bytes
            unit = "characters" if self.legacy else "bytes"
            pass_log.append(f"Input truncated to first {cap} {unit} before analysis")
        if not self.legacy:
            # Said where the analyst reads, not only in the JSON: a stage left
            # unopened is a gap in the analysis.
            pass_log.extend(f"Limit reached ({hit['limit']}) in layer {hit['artifact_id']}: {hit['detail']}"
                            for hit in self.limits_hit if hit["limit"] not in ("cycle", "max_input_bytes"))
        residual = PlagDeobfus._scan_residual_blobs(deobfuscated)
        if residual:
            pass_log.append(
                f"{len(residual)} high-entropy blob(s) left unresolved by static "
                f"analysis: still encoded, contents not recovered"
            )
        view = DeobfuscationResult(
            original=self.source,
            deobfuscated=deobfuscated,
            deobfuscated_raw=raw,
            pass_log=pass_log,
            truncated=self.truncated,
            iterations=max(a.rounds for a in self.artifacts),
            converged=all(a.converged for a in self.artifacts),
            residual_blobs=residual,
            transforms=self.transforms,
        )
        return LayeredResult(
            mode=self.mode, artifacts=self.artifacts, transforms=self.transforms, pass_log=pass_log,
            view=view, truncated=self.truncated, limits_hit=self.limits_hit,
            needs_review=self.needs_review, rejected=self.rejected, errors=self.errors, notes=self.notes,
            rounds=sum(a.rounds for a in self.artifacts), input_sha256=sha256(self.source),
            input_size=len(self.source.encode("utf-8", "surrogatepass")),
        )


def _swap_tokens(text: str, replacements: list[str]) -> str:
    """Every child token at once: one pass over the text, not one per stage."""
    if not replacements or "\x00CHILD" not in text:
        return text

    def swap(m: re.Match) -> str:
        index = int(m.group(1))
        return replacements[index] if index < len(replacements) else m.group(0)
    return _patterns(token_nonce())[2].sub(swap, text)


def header(art: Artifact) -> str:
    how = art.origin_edge or ""
    if art.edge_detail:
        how += f": {art.edge_detail}"
    return f"==== layer {art.id} | {art.language} | from layer {art.parent_id} | {how} ===="


def render(artifacts: list[Artifact], attr: str = "final") -> str:
    """The whole tree as one text: the root, then each stage under a header."""
    root = artifacts[0]
    blocks = [getattr(root, attr)]
    for art in artifacts[1:]:
        if isinstance(art.content, bytes):
            body = f"[binary stage: {art.size} bytes, sha256 {art.sha256}; extracted, never loaded]"
        else:
            body = getattr(art, attr)
        blocks.append(header(art) + "\n" + body)
    return "\n\n".join(blocks)


def canonical(result: LayeredResult, findings=()) -> dict:
    """The canonical JSON report: the tree, every transform, every indicator
    with the layer it came from. Reports and exports render from this."""
    layer_ids = {result.layer_path(art.id): art.id for art in result.artifacts}
    iocs, rules = [], []
    for f in findings:
        path = getattr(f, "layer", "") or "1"
        if f.type == "signature":
            rules.append({"rule": f.value, "mitre": list(f.mitre), "severity": f.severity,
                          "artifact_id": layer_ids.get(path, 1), "layer_path": path})
        else:
            iocs.append({"value": f.value, "type": f.type, "artifact_id": layer_ids.get(path, 1),
                         "layer_path": path})
    return {
        "schema_version": SCHEMA_VERSION,
        "pipeline": result.mode,
        "input": {"sha256": result.input_sha256, "size": result.input_size,
                  "detected_language": result.root.language},
        "artifacts": [{
            "id": art.id, "parent_id": art.parent_id, "language": art.language,
            "edge": art.origin_edge, "edge_detail": art.edge_detail, "depth": art.depth,
            "sha256": art.sha256, "size": art.size, "preview": art.preview(),
            "flags": sorted(art.flags), "rounds": art.rounds, "converged": art.converged,
            "layer_path": result.layer_path(art.id),
        } for art in result.artifacts],
        "transforms": [{
            "artifact_id": t.artifact_id, "pass_id": t.pass_id, "kind": t.kind, "name": t.name,
            "detail": t.detail, "confidence": t.confidence, "assumed": t.assumed, "gates": t.gates,
            "iteration": t.iteration, "before_preview": t.before, "after_preview": t.after,
        } for t in result.transforms],
        "iocs": iocs,
        "findings": rules,
        "residual_blobs": [{"offset": b.offset, "length": b.length, "entropy": b.entropy, "reason": b.reason}
                           for b in result.view.residual_blobs],
        "limits_hit": result.limits_hit,
        "needs_review": result.needs_review,
        "rejected": result.rejected,
        "notes": result.notes,
        "errors": result.errors,
        "metrics": {"rounds": result.rounds, "duration_ms": round(result.duration_ms, 1),
                    "artifacts": len(result.artifacts),
                    "max_depth": max(a.depth for a in result.artifacts)},
    }


def run(source: str, *, mode: str = "layered", limits: Limits = DEFAULT_LIMITS,
        registry: Registry | None = None) -> LayeredResult:
    """Deobfuscate `source` into a tree of layers."""
    if mode == "layered":
        with PlagEval.extended():
            return _Run(source, mode, limits, registry).run()
    return _Run(source, mode, limits, registry).run()
