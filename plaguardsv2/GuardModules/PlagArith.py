"""Safe evaluation of the little arithmetic that hides inside character calls.

`Chr(108+1)` and `String.fromCharCode(0x6d, 97*1)` are the same trick in two
languages: spell the code point as a sum so the literal never appears. This
folds those expressions.

Parsed with `ast` and walked by hand - only numbers and the five arithmetic
operators are honoured, so there is no path from a hostile input to anything
being executed.
"""
from __future__ import annotations

import ast
import operator

MAX_EXPR_LEN = 200

_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.BitXor: operator.xor,
}
_UNARYOPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _walk(node, names: dict | None = None):
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise ValueError("not a number")
        return node.value
    if isinstance(node, ast.Name):
        # Resolved only from the caller's own table - never from any scope.
        if names is None or node.id not in names:
            raise ValueError("unknown name")
        return names[node.id]
    if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
        return _BINOPS[type(node.op)](_walk(node.left, names), _walk(node.right, names))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARYOPS:
        return _UNARYOPS[type(node.op)](_walk(node.operand, names))
    raise ValueError("unsupported expression")


def compile_expression(expression: str):
    """Parse once, evaluate many times against a table of names.

    Returns `f(names) -> int | None`, or None if the text is not arithmetic.
    Used for a loop index expression, where re-parsing per iteration would
    dominate the cost of decoding a payload.
    """
    text = _normalise_hex((expression or "").strip())
    if not text or len(text) > MAX_EXPR_LEN:
        return None
    try:
        tree = ast.parse(text, mode="eval")
    except Exception:
        return None

    def evaluate_with(names: dict):
        try:
            value = _walk(tree.body, names)
        except Exception:
            return None
        if isinstance(value, float):
            if value != int(value):
                return None
            value = int(value)
        return value if isinstance(value, int) else None

    return evaluate_with


def _normalise_hex(text: str) -> str:
    """VBScript writes hex as &H41; Python needs 0x41."""
    if "&h" not in text.lower():
        return text
    out, i = [], 0
    while i < len(text):
        if text[i:i + 2].lower() == "&h":
            out.append("0x")
            i += 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def evaluate(expression: str) -> int | None:
    """The integer an arithmetic expression reduces to, or None.

    Accepts the forms these languages actually use: decimal, hex (`0x41`),
    and VBScript's `&H41`. Anything else - a name, a call, a string - is
    rejected outright.
    """
    text = _normalise_hex((expression or "").strip())
    if not text or len(text) > MAX_EXPR_LEN:
        return None

    try:
        tree = ast.parse(text, mode="eval")
        value = _walk(tree.body)
    except Exception:
        return None

    if isinstance(value, float):
        if value != int(value):
            return None
        value = int(value)
    return value if isinstance(value, int) else None


def to_char(expression: str) -> str | None:
    """The character an arithmetic expression names, or None."""
    code = evaluate(expression)
    if code is None or not 0 <= code <= 0x10FFFF:
        return None
    return chr(code)
