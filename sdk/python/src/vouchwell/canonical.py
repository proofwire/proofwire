"""RFC 8785 (JCS) canonical JSON, byte-identical to packages/core/src/canonical.js.

Two implementations must produce the same bytes for the same receipt, or a
receipt signed in Python would not verify in JavaScript. Three details decide
that, and each is matched here exactly:

* object keys sort by UTF-16 code unit, not by code point;
* control characters escape as lowercase ``\\u00xx``, with the short forms for
  ``\\b \\t \\n \\f \\r`` and ``"`` and ``\\``, and everything else is literal;
* numbers are written the way ECMAScript's ``Number::toString`` writes them,
  with ``-0`` as ``0``, and NaN and infinities refused.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Any

__all__ = ["canonicalize", "canonical_bytes"]

_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}

#: The largest integer every JSON implementation represents exactly.
_MAX_SAFE_INTEGER = 2**53 - 1


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        esc = _ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        elif 0xD800 <= cp <= 0xDFFF:
            # A lone surrogate has no UTF-8 form. JavaScript's encoder writes
            # U+FFFD in its place, so the bytes hashed there are these.
            out.append("�")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _es_number(x: float) -> str:
    """ECMAScript Number::toString for a finite, non-zero float.

    Python's ``repr`` already finds the shortest digit string that round-trips,
    which is what ECMAScript uses too; only the layout differs.
    """
    sign = "-" if x < 0 else ""
    d = Decimal(repr(abs(x)))
    _, digits, exponent = d.as_tuple()
    s = "".join(map(str, digits)).rstrip("0")
    exponent += len(digits) - len(s)  # account for the zeros just stripped
    k = len(s)
    n = exponent + k  # the value is 0.s × 10^n

    if k <= n <= 21:
        body = s + "0" * (n - k)
    elif 0 < n <= 21:
        body = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + s
    else:
        e = n - 1
        exp = ("+" if e > 0 else "-") + str(abs(e))
        body = (s if k == 1 else s[0] + "." + s[1:]) + "e" + exp
    return sign + body


def _encode_number(n: Any) -> str:
    if isinstance(n, bool):  # bool is an int subclass; never a number here
        raise TypeError("booleans are not numbers")
    if isinstance(n, int):
        if abs(n) <= _MAX_SAFE_INTEGER:
            return str(n)
        # Beyond 2**53 a JSON number is a double everywhere else, so it is
        # treated as one here: the same value JavaScript would parse and print.
        try:
            n = float(n)
        except OverflowError:
            raise TypeError(f"cannot canonicalize {n}: too large for a JSON number") from None
    if not math.isfinite(n):
        raise TypeError(f"cannot canonicalize non-finite number: {n}")
    if n == 0:
        return "0"
    if n.is_integer() and abs(n) <= _MAX_SAFE_INTEGER:
        return str(int(n))
    # Everything else, including whole numbers above 2**53, which ECMAScript
    # prints as shortest round-trip digits padded with zeros, not exactly.
    return _es_number(n)


def _sort_key(key: str) -> bytes:
    # Big-endian UTF-16 bytes compare in the same order as UTF-16 code units,
    # which is how JavaScript's default sort orders strings.
    return key.encode("utf-16-be", "surrogatepass")


def canonicalize(value: Any) -> str:
    """The RFC 8785 canonical form of a JSON-compatible value."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float)):
        return _encode_number(value)
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"object keys must be strings, got {type(k).__name__}")
        parts = [
            _encode_string(k) + ":" + canonicalize(value[k])
            for k in sorted(value, key=_sort_key)
        ]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Canonical form as UTF-8: what actually gets hashed and signed."""
    return canonicalize(value).encode("utf-8")
