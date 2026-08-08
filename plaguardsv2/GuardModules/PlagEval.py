"""Recursive-descent evaluator for a restricted PowerShell expression
subset.

Strictly static: it folds *literal* values through pure string / array
operations only. There is no eval(), no exec(), and no PowerShell is ever
invoked. Anything outside the supported subset simply evaluates to
Unknown, which callers treat as "can't resolve this one" rather than an
error.
"""
from __future__ import annotations

import base64

from .PlagTokens import Token, tokenize

MAX_DEPTH = 40
MAX_STRING_LEN = 200_000


class Unknown:
    """Sentinel for a value we can't statically determine."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "<Unknown>"


UNKNOWN = Unknown()

_CODECS = {
    "utf8": "utf-8", "ascii": "ascii", "unicode": "utf-16-le",
    "utf32": "utf-32-le", "utf7": "utf-7", "bigendianunicode": "utf-16-be",
    "default": "utf-8",
}

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a",
            "b": "\b", "f": "\f", "v": "\v", "`": "`", '"': '"', "'": "'",
            "$": "$"}


def expand_double_quoted(raw: str, variables: dict) -> object:
    """Resolve backtick escapes and $var / ${var} interpolation inside a
    double-quoted string body. Returns UNKNOWN if an interpolated variable
    has no known value."""
    out = []
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "`" and i + 1 < n:
            out.append(_ESCAPES.get(raw[i + 1], raw[i + 1]))
            i += 2
            continue
        if c == "$" and i + 1 < n:
            if raw[i + 1] == "{":
                end = raw.find("}", i + 2)
                if end != -1:
                    name = raw[i + 2:end]
                    val = variables.get(name, UNKNOWN)
                    if val is UNKNOWN or not isinstance(val, str):
                        return UNKNOWN
                    out.append(val)
                    i = end + 1
                    continue
            j = i + 1
            while j < n and (raw[j].isalnum() or raw[j] == "_"):
                j += 1
            if j > i + 1:
                name = raw[i + 1:j]
                val = variables.get(name, UNKNOWN)
                if val is UNKNOWN or not isinstance(val, str):
                    return UNKNOWN
                out.append(val)
                i = j
                continue
        out.append(c)
        i += 1
    return "".join(out)


class Parser:
    def __init__(self, tokens: list[Token], variables: dict):
        self.t = tokens
        self.i = 0
        self.vars = variables
        self.depth = 0

    # -- helpers ----------------------------------------------------------
    def peek(self, offset: int = 0) -> Token | None:
        idx = self.i + offset
        return self.t[idx] if idx < len(self.t) else None

    def next(self) -> Token | None:
        tok = self.peek()
        if tok is not None:
            self.i += 1
        return tok

    def accept(self, kind: str, value: str | None = None) -> bool:
        tok = self.peek()
        if tok and tok.kind == kind and (value is None or tok.value.lower() == value.lower()):
            self.i += 1
            return True
        return False

    def expect_punct(self, value: str) -> bool:
        return self.accept("punct", value)

    # -- grammar ----------------------------------------------------------
    def parse_expression(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            return UNKNOWN
        try:
            left = self.parse_additive()
            while True:
                tok = self.peek()
                if tok is None or tok.kind != "op":
                    break
                op = tok.value.lower()
                if op == "-join":
                    self.next()
                    right = self.parse_additive()
                    left = self._apply_join(left, right)
                elif op == "-split":
                    self.next()
                    right = self.parse_additive()
                    left = self._apply_split(left, right)
                elif op == "-replace":
                    self.next()
                    first = self.parse_additive()
                    second = ""
                    if self.expect_punct(","):
                        second = self.parse_additive()
                    left = self._apply_replace(left, first, second)
                elif op == "-f":
                    self.next()
                    args = [self.parse_additive()]
                    while self.expect_punct(","):
                        args.append(self.parse_additive())
                    left = self._apply_format(left, args)
                else:
                    break

            # Pipelines: <expr> | %{ ... } / ForEach-Object { ... }
            while True:
                tok = self.peek()
                if tok is None or tok.kind != "punct" or tok.value != "|":
                    break
                self.next()
                left = self._apply_foreach(left)
                if left is UNKNOWN:
                    break
            return left
        finally:
            self.depth -= 1

    def _apply_foreach(self, source):
        """Evaluate `| %{ <body> }` by running <body> once per input item
        with $_ bound to that item."""
        tok = self.peek()
        if tok is None:
            return UNKNOWN
        if tok.kind == "punct" and tok.value == "%":
            self.next()
        elif tok.kind == "name" and tok.value.lower() in ("foreach", "select"):
            self.next()
            # "ForEach-Object" lexes as name('ForEach') op('-') name('Object'),
            # since -Object isn't one of the recognised operator words.
            nxt, after = self.peek(), self.peek(1)
            if (nxt and nxt.kind == "op" and nxt.value == "-"
                    and after and after.kind == "name" and after.value.lower() == "object"):
                self.next()
                self.next()
        else:
            return UNKNOWN

        if not self.expect_punct("{"):
            return UNKNOWN

        # Capture the block body verbatim so it can be replayed per item.
        body: list[Token] = []
        depth = 1
        while True:
            tok = self.peek()
            if tok is None:
                return UNKNOWN
            if tok.kind == "punct" and tok.value == "{":
                depth += 1
            elif tok.kind == "punct" and tok.value == "}":
                depth -= 1
                if depth == 0:
                    self.next()
                    break
            body.append(tok)
            self.next()

        if source is UNKNOWN or not body:
            return UNKNOWN

        items = source if isinstance(source, list) else [source]
        results = []
        for item in items:
            scope = dict(self.vars)
            scope["_"] = item
            sub = Parser(list(body), scope)
            value = sub.parse_expression()
            if value is UNKNOWN:
                return UNKNOWN
            results.append(value)
        return results

    def parse_additive(self):
        left = self.parse_unary()
        while True:
            tok = self.peek()
            if tok is None or tok.kind != "op" or tok.value not in ("+", "-", "*", "/"):
                break
            op = tok.value
            self.next()
            right = self.parse_unary()
            left = self._apply_arith(op, left, right)
        return left

    def parse_unary(self):
        tok = self.peek()
        # A -join with no left operand, e.g. (-join $arr)
        if tok and tok.kind == "op" and tok.value.lower() == "-join":
            self.next()
            operand = self.parse_unary()
            return self._apply_join(operand, "")
        return self.parse_primary()

    def parse_primary(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            return UNKNOWN
        try:
            tok = self.peek()
            if tok is None:
                return UNKNOWN

            if tok.kind == "str":
                self.next()
                return self._maybe_method(tok.value)

            if tok.kind == "dqstr":
                self.next()
                return self._maybe_method(expand_double_quoted(tok.value, self.vars))

            if tok.kind == "num":
                self.next()
                return int(tok.value)

            if tok.kind == "var":
                self.next()
                value = self.vars.get(tok.value, UNKNOWN)
                return self._maybe_method(value)

            if tok.kind == "punct" and tok.value == "(":
                self.next()
                items = [self.parse_expression()]
                while self.expect_punct(","):
                    items.append(self.parse_expression())
                if not self.expect_punct(")"):
                    return UNKNOWN
                value = items[0] if len(items) == 1 else items
                return self._maybe_method(value)

            if tok.kind == "punct" and tok.value == "@":
                self.next()
                if self.expect_punct("("):
                    items = []
                    if not (self.peek() and self.peek().kind == "punct" and self.peek().value == ")"):
                        items.append(self.parse_expression())
                        while self.expect_punct(","):
                            items.append(self.parse_expression())
                    if not self.expect_punct(")"):
                        return UNKNOWN
                    return items
                return UNKNOWN

            if tok.kind == "punct" and tok.value == "[":
                return self._parse_bracket_construct()

            if tok.kind == "name":
                return self._parse_name_construct()

            return UNKNOWN
        finally:
            self.depth -= 1

    # -- [ ... ] type constructs -----------------------------------------
    def _parse_bracket_construct(self):
        start = self.i
        self.next()  # consume the opening '['
        parts = []
        depth = 1
        while True:
            tok = self.peek()
            if tok is None:
                self.i = start
                return UNKNOWN
            if tok.kind == "punct" and tok.value == "[":
                depth += 1
            elif tok.kind == "punct" and tok.value == "]":
                depth -= 1
                if depth == 0:
                    self.next()
                    break
            parts.append(tok.value)
            self.next()
        type_name = "".join(parts).lower().replace(" ", "")

        # [char](expr) / [char]65 / [char][int]$x
        if type_name == "char":
            operand = self.parse_unary()
            if isinstance(operand, int):
                try:
                    return chr(operand)
                except (ValueError, OverflowError):
                    return UNKNOWN
            if isinstance(operand, str) and operand.strip().lstrip("-").isdigit():
                try:
                    return chr(int(operand.strip()))
                except (ValueError, OverflowError):
                    return UNKNOWN
            return UNKNOWN

        # [int]"65" / [int]$x - numeric cast
        if type_name in ("int", "int32", "int64", "long", "system.int32"):
            operand = self.parse_unary()
            if isinstance(operand, int):
                return operand
            if isinstance(operand, str):
                try:
                    return int(operand.strip())
                except ValueError:
                    return UNKNOWN
            return UNKNOWN

        # [Array]::Reverse(...) mutates in place and returns nothing, so in an
        # expression it has no value - PlagTrace handles it as a statement.
        if type_name in ("array", "system.array"):
            return self._parse_static_call(lambda name, args: UNKNOWN)

        # [byte[]](1,2,3) -> list of ints
        if type_name in ("byte[]", "int[]", "char[]"):
            operand = self.parse_unary()
            if isinstance(operand, list):
                if type_name == "char[]":
                    try:
                        return [chr(v) if isinstance(v, int) else v for v in operand]
                    except (ValueError, OverflowError):
                        return UNKNOWN
                return operand
            if isinstance(operand, int):
                return [operand]
            return UNKNOWN

        # [Convert]::FromBase64String('...')
        if type_name in ("convert", "system.convert"):
            return self._parse_static_call(_convert_static)

        # [Text.Encoding]::UTF8.GetString(...) with optional System. prefix
        if type_name in ("text.encoding", "system.text.encoding"):
            return self._parse_encoding_call()

        if type_name in ("string", "system.string"):
            return self._parse_static_call(_string_static)

        return UNKNOWN

    def _parse_static_call(self, handler):
        if not self.accept("punct", ":") or not self.accept("punct", ":"):
            return UNKNOWN
        name_tok = self.next()
        if name_tok is None or name_tok.kind != "name":
            return UNKNOWN
        args = self._parse_arg_list()
        if args is None:
            return UNKNOWN
        return handler(name_tok.value.lower(), args)

    def _parse_encoding_call(self):
        if not self.accept("punct", ":") or not self.accept("punct", ":"):
            return UNKNOWN
        enc_tok = self.next()
        if enc_tok is None or enc_tok.kind != "name":
            return UNKNOWN
        codec = _CODECS.get(enc_tok.value.lower())
        if codec is None:
            return UNKNOWN
        # Either .GetString(...) or ::GetString(...)
        if not (self.accept("punct", ".") or (self.accept("punct", ":") and self.accept("punct", ":"))):
            return UNKNOWN
        method_tok = self.next()
        if method_tok is None or method_tok.value.lower() != "getstring":
            return UNKNOWN
        args = self._parse_arg_list()
        if args is None or not args:
            return UNKNOWN
        return _decode_bytes(args[0], codec)

    def _parse_arg_list(self):
        if not self.expect_punct("("):
            return None
        args = []
        if self.peek() and self.peek().kind == "punct" and self.peek().value == ")":
            self.next()
            return args
        args.append(self.parse_expression())
        while self.expect_punct(","):
            args.append(self.parse_expression())
        if not self.expect_punct(")"):
            return None
        return args

    # -- bare name constructs (New-Object etc. are unsupported) ----------
    def _parse_name_construct(self):
        self.next()
        return UNKNOWN

    # -- .Method(...) chains ---------------------------------------------
    def _maybe_method(self, value):
        while True:
            tok = self.peek()
            nxt = self.peek(1)
            if not (tok and tok.kind == "punct" and tok.value == "."
                    and nxt and nxt.kind == "name"):
                return value
            self.next()  # '.'
            method = self.next().value.lower()
            args = self._parse_arg_list()
            if args is None:
                return UNKNOWN
            value = self._apply_method(value, method, args)
            if value is UNKNOWN:
                return UNKNOWN

    def _apply_method(self, target, method, args):
        if target is UNKNOWN or any(a is UNKNOWN for a in args):
            return UNKNOWN
        if not isinstance(target, str):
            return UNKNOWN
        try:
            if method == "replace" and len(args) == 2:
                return _cap(target.replace(str(args[0]), str(args[1])))
            if method == "split" and len(args) >= 1:
                sep = str(args[0])
                return target.split(sep) if sep else list(target)
            if method == "tochararray" and not args:
                return list(target)
            if method == "tostring" and not args:
                return target
            if method in ("toupper", "toupperinvariant"):
                return target.upper()
            if method in ("tolower", "tolowerinvariant"):
                return target.lower()
            if method == "trim":
                return target.strip()
            if method == "substring" and len(args) == 1 and isinstance(args[0], int):
                return target[args[0]:]
            if method == "substring" and len(args) == 2 and all(isinstance(a, int) for a in args):
                return target[args[0]:args[0] + args[1]]
        except Exception:
            return UNKNOWN
        return UNKNOWN

    # -- operators --------------------------------------------------------
    def _apply_arith(self, op, left, right):
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        try:
            if op == "+":
                if isinstance(left, str) or isinstance(right, str):
                    if isinstance(left, list) or isinstance(right, list):
                        return UNKNOWN
                    return _cap(f"{left}{right}")
                if isinstance(left, list) and isinstance(right, list):
                    return left + right
                if isinstance(left, int) and isinstance(right, int):
                    return left + right
                return UNKNOWN
            if isinstance(left, int) and isinstance(right, int):
                if op == "-":
                    return left - right
                if op == "*":
                    return left * right
                if op == "/":
                    return left // right if right and left % right == 0 else (left / right if right else UNKNOWN)
        except Exception:
            return UNKNOWN
        return UNKNOWN

    def _apply_join(self, left, right):
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        items = left if isinstance(left, list) else [left]
        sep = right if isinstance(right, str) else ""
        try:
            return _cap(sep.join(str(x) for x in items))
        except Exception:
            return UNKNOWN

    def _apply_split(self, left, right):
        if left is UNKNOWN or right is UNKNOWN or not isinstance(left, str):
            return UNKNOWN
        sep = str(right)
        return left.split(sep) if sep else list(left)

    def _apply_replace(self, target, old, new):
        if target is UNKNOWN or old is UNKNOWN or new is UNKNOWN:
            return UNKNOWN
        if not isinstance(target, str):
            return UNKNOWN
        try:
            return _cap(target.replace(str(old), str(new)))
        except Exception:
            return UNKNOWN

    def _apply_format(self, fmt, args):
        if fmt is UNKNOWN or any(a is UNKNOWN for a in args) or not isinstance(fmt, str):
            return UNKNOWN
        import re as _re
        try:
            return _cap(_re.sub(r"\{(\d+)\}",
                                 lambda m: str(args[int(m.group(1))]) if int(m.group(1)) < len(args) else m.group(0),
                                 fmt))
        except Exception:
            return UNKNOWN


def _cap(value: str):
    return value if len(value) <= MAX_STRING_LEN else UNKNOWN


def _convert_static(method: str, args: list):
    if method == "frombase64string" and args and isinstance(args[0], str):
        try:
            raw = args[0] + "=" * (-len(args[0]) % 4)
            return list(base64.b64decode(raw, validate=False))
        except Exception:
            return UNKNOWN
    return UNKNOWN


def _string_static(method: str, args: list):
    if method == "join" and len(args) >= 2:
        sep = args[0]
        rest = args[1]
        items = rest if isinstance(rest, list) else args[1:]
        if sep is UNKNOWN or any(x is UNKNOWN for x in items):
            return UNKNOWN
        try:
            return _cap(str(sep).join(str(x) for x in items))
        except Exception:
            return UNKNOWN
    return UNKNOWN


def _decode_bytes(value, codec: str):
    if value is UNKNOWN:
        return UNKNOWN
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(v, int) for v in value):
        try:
            return _cap(bytes(b & 0xFF for b in value).decode(codec, errors="replace"))
        except Exception:
            return UNKNOWN
    return UNKNOWN


def evaluate(expression: str, variables: dict):
    """Evaluate a single PowerShell expression against known variable
    values. Returns a str/int/list, or UNKNOWN."""
    tokens = tokenize(expression)
    if tokens is None:
        return UNKNOWN
    parser = Parser(tokens, variables)
    try:
        value = parser.parse_expression()
    except Exception:
        return UNKNOWN
    return value
