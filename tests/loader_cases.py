"""Builds loader scripts for the recogniser tests.

Kept apart from the test file, with the recognisable idioms assembled from
fragments, because real-time AV quarantines a file that gathers too many of
them in one place. See the note in README.md.
"""
import base64
import gzip
import zlib

TICK = chr(96)

# Assembled rather than spelled out.
_CONVERT = "[Con" + "vert]::From" + "Base64" + "String"
_NEWOBJ = "New-" + "Object"
_BYTES = "byte" + "[]"
_MEM = "IO.Memory" + "Stream"
_COMPRESS = "IO.Compr" + "ession"
_READER = "IO.Stream" + "Reader"


def encode(plain: bytes, key: bytes, op: str = "-bxor", compress=gzip.compress) -> str:
    """Compress, apply the inverse of `op`, and Base64 the result."""
    raw = compress(plain) if compress else plain
    if op == "-bxor":
        out = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    elif op == "+":
        # The loader adds the key back, so encoding subtracts it.
        out = bytes((b - key[i % len(key)]) % 256 for i, b in enumerate(raw))
    elif op == "-":
        out = bytes((b + key[i % len(key)]) % 256 for i, b in enumerate(raw))
    else:
        raise ValueError(op)
    return base64.b64encode(out).decode()


def deflate(data: bytes) -> bytes:
    return zlib.compress(data)


def build(blob, key, *, names=("K", "b", "x", "i"), keyidx=None, op="-bxor",
          length_var=None, decompress="Gzip", tick_in_op=False):
    """A loader script with the requested shape."""
    kname, sname, dname, iname = names
    key_list = ",".join(str(b) for b in key)
    keyidx = keyidx or f"${iname} % ${kname}.Length"
    operator = "-b" + TICK + "xor" if tick_in_op else op

    lines = [
        f"${kname} = [{_BYTES}]({key_list})",
        f'${sname} = {_CONVERT}("{blob}")',
        f"${dname} = {_NEWOBJ} {_BYTES} ${sname}.Length",
    ]
    if length_var:
        lines.append(f"${length_var} = ${kname}.Length")
    lines += [
        f"for (${iname} = 0; ${iname} -lt ${sname}.Length; ${iname}++) {{",
        f"    ${dname}[${iname}] = ${sname}[${iname}] {operator} ${kname}[{keyidx}]",
        "}",
        f"$ms = {_NEWOBJ} {_MEM}(,[{_BYTES}]${dname})",
    ]
    if decompress:
        lines.append(
            f"$gz = {_NEWOBJ} {_COMPRESS}.{decompress}Stream"
            f"($ms,[{_COMPRESS}.CompressionMode]::Decompress)"
        )
        lines.append(f"$rec = ({_NEWOBJ} {_READER}($gz)).ReadToEnd()")
    return "\n".join(lines) + "\n"
