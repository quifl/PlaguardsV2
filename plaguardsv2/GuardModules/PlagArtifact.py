"""Data model for the layered pipeline: artifacts, the edges between them,
and the limits every run is held to.

An artifact is one piece of script or data at one layer: the submitted
input, or a stage recovered from it (a decoded -EncodedCommand, the string
handed to Invoke-Expression, the body of a batch file's `powershell -c`).
Nothing here executes anything; artifacts are only ever text being read.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


class Lang:
    POWERSHELL = "powershell"
    BATCH = "batch"
    JAVASCRIPT = "javascript"
    VBSCRIPT = "vbscript"
    HTA = "hta"
    WSF = "wsf"
    BINARY = "binary"
    TEXT = "text"
    UNKNOWN = "unknown"

    ALL = frozenset({POWERSHELL, BATCH, JAVASCRIPT, VBSCRIPT, HTA, WSF, BINARY, TEXT, UNKNOWN})
    # Script languages whose passes the legacy engine applied to everything it read.
    PS_LIKE = frozenset({POWERSHELL, TEXT, UNKNOWN})


class Edge:
    DECODE = "DECODE"
    DECOMPRESS = "DECOMPRESS"
    DECRYPT = "DECRYPT"
    HANDOFF = "HANDOFF"
    EXTRACT = "EXTRACT"

    ALL = frozenset({DECODE, DECOMPRESS, DECRYPT, HANDOFF, EXTRACT})


@dataclass(frozen=True)
class Limits:
    max_input_bytes: int = 50 * 1024 ** 2
    max_decoded_bytes_total: int = 200 * 1024 ** 2
    max_decompression_ratio: int = 100
    max_layer_depth: int = 12
    max_rounds_per_layer: int = 20
    # Not in the specification's list: thousands of one-line stages cost far
    # more to read one by one than the bytes budget would suggest.
    max_artifacts: int = 2000
    routing_auto_apply: float = 0.80
    routing_review_floor: float = 0.50


DEFAULT_LIMITS = Limits()


def sha256(content: str | bytes) -> str:
    data = content.encode("utf-8", "surrogatepass") if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


# Where the layer marker goes in a ChildSpec template. NUL-delimited: input
# text has its NULs replaced before any pass runs, so a sample cannot plant one.
MARKER_SLOT = "\x00SLOT\x00"


@dataclass
class ChildSpec:
    """A stage a pass found, before the scheduler turns it into an artifact.

    The pass leaves a child token over `source_span` in the parent. If the
    stage is admitted the token becomes `template` with the layer marker in
    MARKER_SLOT; if not, the token becomes `source_span` again, so a refused
    stage leaves the parent exactly as it was.
    """
    language: str
    content: str | bytes
    edge: str
    detail: str = ""
    encoding: str = "utf-8"
    marker: str = ""
    source_span: str = ""
    template: str = MARKER_SLOT
    # State the child starts from: a `cmd /c` inherits the parent's variables.
    inherit: dict | None = None


@dataclass
class Artifact:
    id: int
    parent_id: int | None
    language: str
    content: str | bytes
    encoding: str = "utf-8"
    origin_edge: str | None = None
    edge_detail: str = ""
    depth: int = 0
    flags: set = field(default_factory=set)
    final: str | bytes = ""
    final_raw: str = ""
    marker: str = ""
    source_span: str = ""
    rounds: int = 0
    converged: bool = True
    inherit: dict = field(default_factory=dict)
    _digest: tuple = field(default=(None, ""), repr=False, compare=False)

    @property
    def sha256(self) -> str:
        # Content is never rewritten in place; cached per content object.
        if self._digest[0] is not self.content:
            self._digest = (self.content, sha256(self.content))
        return self._digest[1]

    @property
    def size(self) -> int:
        if isinstance(self.content, bytes):
            return len(self.content)
        return len(self.content.encode("utf-8", "surrogatepass"))

    def preview(self, width: int = 96) -> str:
        if isinstance(self.content, bytes):
            return self.content[:24].hex()
        flat = " ".join(str(self.final or self.content).split())
        flat = "".join(c if c.isprintable() else "." for c in flat)
        return flat if len(flat) <= width else flat[:width - 3] + "..."
