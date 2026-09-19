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
import re

from .PlagTokens import Token, tokenize

MAX_DEPTH = 40
MAX_STRING_LEN = 200_000

# `-replace` and `-split` take their pattern straight from the sample under
# analysis, so the pattern is hostile input. .NET mitigates the resulting
# backtracking blowup with a match timeout; Python's re has no such thing, so
# the only defence available here is to refuse dangerous shapes up front.
MAX_REGEX_LEN = 256
MAX_REPEAT_BOUND = 1000


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

_LARGE_BOUND_RE = re.compile(r"\{\s*(\d+)\s*(?:,\s*(\d*)\s*)?\}")


def _group_body_repeats(body: str) -> bool:
    """True if a group body can match the same text more than one way, which
    is what turns an outer quantifier into exponential backtracking."""
    i, n = 0, len(body)
    in_class = False
    while i < n:
        ch = body[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif not in_class and ch in "*+{|":
            return True
        i += 1
    return False


def _regex_is_risky(pattern: str) -> bool:
    """Reject patterns whose match time is not bounded by input length.

    The `(X+)+` / `(X*)*` family and explicit repeat counts in the thousands
    are the two shapes that turn a 40-character sample string into minutes of
    CPU. Over-rejecting here is safe: the caller answers UNKNOWN, which is the
    honest result for a pattern we decline to run.
    """
    if len(pattern) > MAX_REGEX_LEN:
        return True
    for bound in _LARGE_BOUND_RE.finditer(pattern):
        low, high = bound.group(1), bound.group(2)
        if int(low) > MAX_REPEAT_BOUND or (high and int(high) > MAX_REPEAT_BOUND):
            return True

    stack: list[int] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i += 1
            while i < n and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
            continue
        if ch == "(":
            stack.append(i)
        elif ch == ")" and stack:
            start = stack.pop()
            following = pattern[i + 1] if i + 1 < n else ""
            if following in ("*", "+", "{") and _group_body_repeats(pattern[start + 1:i]):
                return True
        i += 1
    return False


# One pass, not a sequence of str.replace calls: replacing "$$" first and then
# "$1" would rewrite the "$" that the first step had just produced, so "$$$1" -
# the documented way to emit a literal "$" ahead of a backreference - would
# come out as a second backreference instead.
_DOTNET_REPL_RE = re.compile(r"\$(?:(\$)|\{([A-Za-z_][A-Za-z0-9_]*|\d+)\}|(\d+)|(&))")


def _dotnet_replacement(replacement: str) -> str:
    """Translate a .NET substitution string to Python's re replacement syntax."""
    # A backslash is ordinary text to .NET but an escape to Python's template
    # engine, so it has to be doubled before any group reference is inserted.
    out = replacement.replace("\\", "\\\\")

    def repl(m: re.Match) -> str:
        if m.group(1):
            return "$"
        if m.group(2):
            # ${2} is the braced form of a *numbered* reference, not only the
            # named one; \g<> accepts both spellings unchanged.
            return f"\\g<{m.group(2)}>"
        if m.group(3):
            # \g<n> rather than \n, so "$1" followed by a digit stays group 1.
            return f"\\g<{int(m.group(3))}>"
        return "\\g<0>"

    return _DOTNET_REPL_RE.sub(repl, out)


# {index[,alignment][:format]}, plus the {{ }} escapes for a literal brace.
_FORMAT_RE = re.compile(r"\{\{|\}\}|\{(\d+)(?:,(-?\d+))?(?::([^{}]*))?\}")


def _format_one(value, spec: str | None):
    """Render one `-f` argument under a .NET format specifier.

    An unrecognised specifier returns UNKNOWN rather than the unformatted
    value: handing back `65` where the script produced `$65.00` is exactly the
    silently-wrong answer that pollutes an analyst's report.
    """
    if not spec:
        return str(value)
    kind, width = spec[0], spec[1:]
    if width and not width.isdigit():
        return UNKNOWN
    try:
        if kind in ("X", "x"):
            number = int(value)
            if number < 0:
                # .NET renders a negative int as its 32-bit two's complement
                # pattern; Python would render "-41".
                number += 1 << 32
            out = format(number, "X")
            if width:
                out = out.rjust(int(width), "0")
            return out if kind == "X" else out.lower()
        if kind in ("D", "d"):
            number = int(value)
            digits = str(abs(number))
            if width:
                digits = digits.rjust(int(width), "0")
            return ("-" if number < 0 else "") + digits
        if kind in ("N", "n", "F", "f"):
            places = int(width) if width else 2
            if places > 100:
                return UNKNOWN
            return f"{float(value):,.{places}f}" if kind in ("N", "n") else f"{float(value):.{places}f}"
    except (ValueError, TypeError, OverflowError):
        return UNKNOWN
    return UNKNOWN


def _shift(value: int, count: int, to_left: bool) -> int:
    """PowerShell's shifts are typed: an [int] operand masks the shift count
    to 5 bits and wraps to 32-bit signed, so `255 -shl 24` is -16777216 rather
    than 4278190080. Modelling the width explicitly keeps us from inventing a
    value the script never computed."""
    bits = 32 if -(1 << 31) <= value < (1 << 31) else 64
    count &= bits - 1
    result = (value << count) if to_left else (value >> count)
    result &= (1 << bits) - 1
    if result >= 1 << (bits - 1):
        result -= 1 << bits
    return result


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
                elif op in ("-replace", "-ireplace", "-creplace"):
                    self.next()
                    first = self.parse_additive()
                    second = ""
                    if self.expect_punct(","):
                        second = self.parse_additive()
                    left = self._apply_replace(left, first, second,
                                               ignore_case=op != "-creplace")
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
        left = self.parse_multiplicative()
        while True:
            tok = self.peek()
            if tok is None or tok.kind != "op" or tok.value not in ("+", "-"):
                break
            op = tok.value
            self.next()
            right = self.parse_multiplicative()
            left = self._apply_arith(op, left, right)
        return left

    def parse_multiplicative(self):
        """`*`, `/` and `%` bind tighter than `+` and `-`, as they do in
        PowerShell. Folding all four at one precedence level made `2 + 3 * 4`
        evaluate to 20 - a confidently wrong number rather than a refusal."""
        left = self.parse_bitwise()
        while True:
            tok = self.peek()
            if tok is None or tok.kind != "op" or tok.value not in ("*", "/", "%"):
                break
            op = tok.value
            self.next()
            right = self.parse_bitwise()
            left = self._apply_arith(op, left, right)
        return left

    def parse_bitwise(self):
        """`-bxor`, `-band`, `-bor` - how a per-character key is applied.

        Binds tighter than `+` so `[char]($_ -bxor $k) + "x"` groups the way
        PowerShell does.
        """
        left = self.parse_unary()
        while True:
            tok = self.peek()
            if tok is None or tok.kind != "op":
                break
            op = tok.value.lower()
            if op not in ("-bxor", "-band", "-bor", "-shl", "-shr"):
                break
            self.next()
            right = self.parse_unary()
            left = self._apply_bitwise(op, left, right)
        return left

    def parse_unary(self):
        tok = self.peek()
        if tok and tok.kind == "op":
            op = tok.value.lower()
            # A -join with no left operand, e.g. (-join $arr)
            if op == "-join":
                self.next()
                return self._apply_join(self.parse_unary(), "")
            # -bnot is unary. Dispatching it from the binary path would make it
            # consume the value to its left and drop the operand to its right.
            if op == "-bnot":
                self.next()
                operand = self.parse_unary()
                return self._apply_bnot(operand)
            if op == "-":
                self.next()
                operand = self.parse_unary()
                if isinstance(operand, bool) or not isinstance(operand, int):
                    return UNKNOWN
                return -operand
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
                return self._maybe_postfix(tok.value)

            if tok.kind == "dqstr":
                self.next()
                return self._maybe_postfix(expand_double_quoted(tok.value, self.vars))

            if tok.kind == "num":
                self.next()
                return int(tok.value)

            if tok.kind == "var":
                self.next()
                value = self.vars.get(tok.value, UNKNOWN)
                return self._maybe_postfix(value)

            if tok.kind == "punct" and tok.value == "(":
                self.next()
                items = [self.parse_expression()]
                while self.expect_punct(","):
                    items.append(self.parse_expression())
                if not self.expect_punct(")"):
                    return UNKNOWN
                value = items[0] if len(items) == 1 else items
                return self._maybe_postfix(value)

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
            # A one-character non-digit string is already a char; the digit
            # case stays on the code-point path below, where the corpus needs
            # it for `[char]$_` over a split list of decimal byte values.
            if isinstance(operand, str) and len(operand) == 1 and not operand.isdigit():
                return operand
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
        # Postfix applies to a static call's result too, so
        # `[Convert]::FromBase64String($b)[0..3]` and `...GetString($b).Trim()`
        # resolve instead of stopping at the closing paren.
        return self._maybe_postfix(handler(name_tok.value.lower(), args))

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
        return self._maybe_postfix(_decode_bytes(args[0], codec))

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

    # -- .Method(...) and [...] postfix chains ---------------------------
    def _maybe_postfix(self, value):
        """Apply `.Method(...)` calls and `[...]` indexing, in any order.

        A `[` in this position is always an index: a type literal only ever
        appears where a value is expected, never straight after one.
        """
        while True:
            tok = self.peek()
            nxt = self.peek(1)
            if (tok and tok.kind == "punct" and tok.value == "."
                    and nxt and nxt.kind == "name"):
                self.next()  # '.'
                method = self.next().value.lower()
                args = self._parse_arg_list()
                if args is None:
                    return UNKNOWN
                value = self._apply_method(value, method, args)
            elif tok and tok.kind == "punct" and tok.value == "[":
                value = self._apply_index(value)
            else:
                return value
            if value is UNKNOWN:
                return UNKNOWN

    def _parse_index_spec(self):
        """Read the body of a `[...]` as a flat list of integer indices.

        Returns (indices, scalar); scalar is False for a range or a
        comma-separated list, because PowerShell yields an array for both -
        which is why the idiom is nearly always followed by `-join ""`.
        """
        indices: list[int] = []
        scalar = True
        while True:
            first = self.parse_expression()
            if isinstance(first, bool) or not isinstance(first, int):
                return None, False

            dot, dot2 = self.peek(), self.peek(1)
            is_range = (dot and dot.kind == "punct" and dot.value == "."
                        and dot2 and dot2.kind == "punct" and dot2.value == ".")
            if is_range:
                self.next()
                self.next()
                last = self.parse_expression()
                if isinstance(last, bool) or not isinstance(last, int):
                    return None, False
                # A descending range is how a script reverses a string, so the
                # step follows the operands rather than being fixed at +1.
                step = 1 if last >= first else -1
                if abs(last - first) + 1 > MAX_STRING_LEN:
                    return None, False
                indices.extend(range(first, last + step, step))
                scalar = False
            else:
                indices.append(first)

            if not self.expect_punct(","):
                break
            scalar = False
        return indices, scalar and len(indices) == 1

    def _apply_index(self, value):
        self.next()  # '['
        indices, scalar = self._parse_index_spec()
        if indices is None or not self.expect_punct("]"):
            return UNKNOWN
        if value is UNKNOWN or not isinstance(value, (str, list)):
            return UNKNOWN

        length = len(value)
        picked = []
        for index in indices:
            real = index + length if index < 0 else index
            if not 0 <= real < length:
                # PowerShell yields $null here. Clamping instead would put a
                # character in the resolved value that the sample never had.
                return UNKNOWN
            picked.append(value[real])
        return picked[0] if scalar else picked

    def _apply_method(self, target, method, args):
        if target is UNKNOWN or any(a is UNKNOWN for a in args):
            return UNKNOWN
        if not isinstance(target, str):
            return UNKNOWN
        try:
            # String.Replace is an ordinal replace - it is NOT a regex. Only
            # the -replace OPERATOR is, and conflating the two would silently
            # reinterpret every '.' in a pattern as "any character".
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
            if method in ("trim", "trimstart", "trimend"):
                cut = _trim_chars(args)
                if cut is UNKNOWN:
                    return UNKNOWN
                if method == "trim":
                    return target.strip(cut)
                return target.lstrip(cut) if method == "trimstart" else target.rstrip(cut)
            if method == "substring" and args and isinstance(args[0], int):
                start = args[0]
                # .NET throws on an out-of-range index; Python would quietly
                # clamp and hand back a shorter string that looks resolved.
                if not 0 <= start <= len(target):
                    return UNKNOWN
                if len(args) == 1:
                    return target[start:]
                count = args[1]
                if not isinstance(count, int) or count < 0 or start + count > len(target):
                    return UNKNOWN
                return target[start:start + count]
            if method == "insert" and len(args) == 2 and isinstance(args[0], int):
                index = args[0]
                if not 0 <= index <= len(target) or not isinstance(args[1], str):
                    return UNKNOWN
                return _cap(target[:index] + args[1] + target[index:])
            if method == "remove" and args and isinstance(args[0], int):
                start = args[0]
                if not 0 <= start <= len(target):
                    return UNKNOWN
                if len(args) == 1:
                    return target[:start]
                count = args[1]
                if not isinstance(count, int) or count < 0 or start + count > len(target):
                    return UNKNOWN
                return target[:start] + target[start + count:]
            if method in ("padleft", "padright") and args and isinstance(args[0], int):
                width = args[0]
                # Checked before building the string, not after: a width of
                # 2**40 would allocate the memory before _cap ever saw it.
                if not 0 <= width <= MAX_STRING_LEN:
                    return UNKNOWN
                fill = " "
                if len(args) == 2:
                    if not isinstance(args[1], str) or len(args[1]) != 1:
                        return UNKNOWN
                    fill = args[1]
                return target.rjust(width, fill) if method == "padleft" else target.ljust(width, fill)
            if method in ("indexof", "lastindexof") and len(args) == 1 and isinstance(args[0], str):
                # .NET reports -1 for "not found", which scripts branch on.
                return target.find(args[0]) if method == "indexof" else target.rfind(args[0])
            if method == "contains" and len(args) == 1 and isinstance(args[0], str):
                return args[0] in target
            if method == "startswith" and len(args) == 1 and isinstance(args[0], str):
                return target.startswith(args[0])
            if method == "endswith" and len(args) == 1 and isinstance(args[0], str):
                return target.endswith(args[0])
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
                if op == "%":
                    if right == 0:
                        return UNKNOWN
                    # PowerShell's remainder takes the sign of the dividend and
                    # Python's takes the sign of the divisor, so -7 % 3 would
                    # otherwise come out 2 where the script computed -1.
                    remainder = abs(left) % abs(right)
                    return remainder if left >= 0 else -remainder
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

    def _apply_bitwise(self, op, left, right):
        """Fold a bitwise operator over two integers."""
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        try:
            a, b = int(left), int(right)
        except (TypeError, ValueError):
            return UNKNOWN
        if op == "-bxor":
            return a ^ b
        if op == "-band":
            return a & b
        if op == "-bor":
            return a | b
        if op in ("-shl", "-shr"):
            return _shift(a, b, to_left=op == "-shl")
        return UNKNOWN

    def _apply_bnot(self, operand):
        """`-bnot` is the one unary bitwise operator."""
        if operand is UNKNOWN or isinstance(operand, bool):
            return UNKNOWN
        try:
            return ~int(operand)
        except (TypeError, ValueError):
            return UNKNOWN

    def _apply_split(self, left, right):
        """PowerShell's `-split` operator, whose separator is a *regex*.

        This matters in practice: `-split "\\|"` means a literal pipe, and
        splitting on the two characters instead returns the whole string
        unchanged - which looked like the payload simply refusing to resolve.
        The `.Split()` method is the literal one and is handled elsewhere.
        """
        if left is UNKNOWN or right is UNKNOWN or not isinstance(left, str):
            return UNKNOWN
        if len(left) > MAX_STRING_LEN:
            return UNKNOWN
        sep = str(right)
        if not sep:
            return list(left)
        if _regex_is_risky(sep):
            return UNKNOWN
        try:
            return re.split(sep, left)
        except re.error:
            # Not a valid pattern - fall back to a literal split rather than
            # losing the value entirely.
            return left.split(sep)

    def _apply_replace(self, target, old, new, ignore_case: bool = True):
        """The `-replace` OPERATOR, whose pattern is a regular expression and
        which is case-insensitive unless it is spelled `-creplace`.

        The `.Replace()` METHOD is the ordinal one and lives in _apply_method.
        Treating this one as a literal replace was silently wrong three ways:
        it missed character classes, it took `.` literally, and it respected
        case that PowerShell ignores.
        """
        if target is UNKNOWN or old is UNKNOWN or new is UNKNOWN:
            return UNKNOWN
        if not isinstance(target, str) or len(target) > MAX_STRING_LEN:
            return UNKNOWN
        # `-replace ('a','b')` passes the pair as one array argument.
        if isinstance(old, list) and len(old) == 2 and new == "":
            old, new = old[0], old[1]
        if isinstance(old, bool) or isinstance(new, bool):
            return UNKNOWN
        if not isinstance(old, (str, int)) or not isinstance(new, (str, int)):
            return UNKNOWN

        pattern = str(old)
        if _regex_is_risky(pattern):
            return UNKNOWN
        try:
            compiled = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except Exception:
            # PowerShell throws on a malformed pattern. A literal replace here
            # would invent a value it would never have produced.
            return UNKNOWN
        try:
            # Only a single-quoted replacement carries $1 backreferences; a
            # double-quoted one had them interpolated by expand_double_quoted
            # long before -replace saw the string, so this never double-applies.
            return _cap(compiled.sub(_dotnet_replacement(str(new)), target))
        except Exception:
            return UNKNOWN

    def _apply_format(self, fmt, args):
        if fmt is UNKNOWN or any(a is UNKNOWN for a in args) or not isinstance(fmt, str):
            return UNKNOWN

        # Any brace surviving the removal of every valid placeholder and brace
        # escape means a malformed template, which PowerShell throws on.
        residue = _FORMAT_RE.sub("", fmt)
        if "{" in residue or "}" in residue:
            return UNKNOWN

        unresolved = False

        def repl(m: re.Match) -> str:
            nonlocal unresolved
            whole = m.group(0)
            if whole in ("{{", "}}"):
                return whole[0]
            index = int(m.group(1))
            if index >= len(args):
                unresolved = True
                return ""
            piece = _format_one(args[index], m.group(3))
            if piece is UNKNOWN:
                unresolved = True
                return ""
            align = m.group(2)
            if align:
                width = int(align)
                if abs(width) > MAX_STRING_LEN:
                    unresolved = True
                    return ""
                piece = piece.ljust(-width) if width < 0 else piece.rjust(width)
            return piece

        try:
            result = _FORMAT_RE.sub(repl, fmt)
        except Exception:
            return UNKNOWN
        # A placeholder we could not fill means the template is not resolved.
        # Emitting it with the brace still in would hand the report a value
        # the script never produced - the corruption this evaluator avoids.
        if unresolved:
            return UNKNOWN
        return _cap(result)


def _cap(value: str):
    return value if len(value) <= MAX_STRING_LEN else UNKNOWN


def _trim_chars(args: list):
    """The char set for Trim/TrimStart/TrimEnd, or None for whitespace.

    .NET takes a char array, which reaches us either as separate arguments or
    as one list, so both spellings are flattened to a single string.
    """
    if not args:
        return None
    flat: list[str] = []
    for arg in args:
        for item in (arg if isinstance(arg, list) else [arg]):
            if not isinstance(item, str):
                return UNKNOWN
            flat.append(item)
    return "".join(flat) or None


_CONVERT_BASES = (2, 8, 10, 16)
_CONVERT_SIGNED_BITS = {"toint16": 16, "toint32": 32, "toint64": 64}
_DIGITS = "0123456789abcdef"


def _convert_parse_int(text: str, base: int, bits: int, signed: bool):
    """Convert.ToIntNN(string, base) reads a non-decimal string as a two's
    complement bit pattern - ToInt32("FFFFFFFF", 16) is -1, not 4294967295 -
    so the sign is applied by hand rather than trusting int() to guess."""
    text = text.strip()
    if not text:
        return UNKNOWN
    try:
        value = int(text, base)
    except ValueError:
        return UNKNOWN
    if base == 10:
        low = -(1 << (bits - 1)) if signed else 0
        high = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
        return value if low <= value <= high else UNKNOWN
    # .NET rejects a sign outside base 10, where the digits *are* the pattern.
    if text.startswith(("+", "-")) or value >= (1 << bits):
        return UNKNOWN
    if signed and value >= (1 << (bits - 1)):
        value -= 1 << bits
    return value


def _convert_to_string(value: int, base: int) -> str:
    """Convert.ToString(int, base), which renders a negative value as its
    32-bit two's complement pattern rather than Python's "-2a"."""
    if base == 10:
        return str(value)
    number = value if value >= 0 else value + (1 << 32)
    if number == 0:
        return "0"
    out: list[str] = []
    while number:
        out.append(_DIGITS[number % base])
        number //= base
    return "".join(reversed(out))


def _convert_static(method: str, args: list):
    if any(a is UNKNOWN for a in args):
        return UNKNOWN

    if method == "frombase64string" and args and isinstance(args[0], str):
        try:
            raw = args[0] + "=" * (-len(args[0]) % 4)
            return list(base64.b64decode(raw, validate=False))
        except Exception:
            return UNKNOWN

    if method == "tobase64string" and len(args) == 1 and isinstance(args[0], list):
        data = args[0]
        if not all(isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in data):
            return UNKNOWN
        return _cap(base64.b64encode(bytes(data)).decode("ascii"))

    if method in _CONVERT_SIGNED_BITS or method == "tobyte":
        bits = _CONVERT_SIGNED_BITS.get(method, 8)
        signed = method != "tobyte"
        if len(args) == 1:
            value = args[0]
            if isinstance(value, bool):
                return UNKNOWN
            if isinstance(value, int):
                return _convert_parse_int(str(value), 10, bits, signed)
            if isinstance(value, str):
                return _convert_parse_int(value, 10, bits, signed)
            return UNKNOWN
        if len(args) == 2 and isinstance(args[0], str) and args[1] in _CONVERT_BASES:
            return _convert_parse_int(args[0], args[1], bits, signed)
        return UNKNOWN

    if method == "tochar" and len(args) == 1:
        value = args[0]
        if isinstance(value, bool):
            return UNKNOWN
        if isinstance(value, int) and 0 <= value <= 0xFFFF:
            return chr(value)
        if isinstance(value, str) and len(value) == 1:
            return value
        return UNKNOWN

    if method == "tostring" and len(args) == 2:
        value, base = args
        if isinstance(value, bool) or not isinstance(value, int):
            return UNKNOWN
        if base not in _CONVERT_BASES or not -(1 << 31) <= value < (1 << 31):
            return UNKNOWN
        return _convert_to_string(value, base)

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
