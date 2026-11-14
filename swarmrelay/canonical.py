"""Canonical JSON matching the TypeScript SwarmRelay implementation.

`canonicalize_json` reproduces `canonicalizeJson` from
@openagentforum/protocol exactly: keys recursively sorted, no spacing,
JSON.stringify semantics for values JSON cannot carry (dropped from objects,
null inside arrays), and JavaScript number formatting. The envelope checksum
is the SHA-256 of this exact string, so byte-equality with the TypeScript
implementation is required — it is verified against Node in the test suite.
"""

from __future__ import annotations

import json
import math

_UNREPRESENTABLE = (type(None),)  # placeholder; see _is_unrepresentable


def _is_unrepresentable(value: object) -> bool:
    # Mirrors JSON.stringify: undefined/function/symbol have no JSON form.
    # In Python the analogues are callables and a small set of sentinels.
    return callable(value)


def _format_number(value: float | int) -> str:
    """Format a number the way JavaScript's JSON.stringify does."""
    if isinstance(value, bool):  # bool is an int subclass; handled by caller
        raise TypeError("booleans are not numbers here")
    if isinstance(value, int):
        return str(value)
    if math.isnan(value) or math.isinf(value):
        return "null"
    if value == 0:
        # JSON.stringify(-0) === "0"
        return "0"
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    text = repr(value)
    # Python pads exponents to two digits (1e-07); JS does not (1e-7).
    if "e" in text:
        mantissa, _, exp = text.partition("e")
        sign = ""
        if exp.startswith(("+", "-")):
            sign, exp = exp[0], exp[1:]
        exp = exp.lstrip("0") or "0"
        return f"{mantissa}e{sign}{exp}"
    return text


def _canonical_or_none(value: object) -> str | None:
    if _is_unrepresentable(value):
        return None
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (int, float)):
        return _format_number(value)
    if isinstance(value, (list, tuple)):
        items = [_canonical_or_none(item) or "null" for item in value]
        return "[" + ",".join(items) + "]"
    if isinstance(value, dict):
        pairs = []
        for key in sorted(value.keys(), key=str):
            item = _canonical_or_none(value[key])
            if item is None:
                continue
            pairs.append(json.dumps(str(key), ensure_ascii=False) + ":" + item)
        return "{" + ",".join(pairs) + "}"
    raise TypeError(f"value of type {type(value).__name__} has no JSON representation")


def canonicalize_json(value: object) -> str:
    """Deterministic JSON: sorted keys, no spacing, JS-compatible scalars."""
    result = _canonical_or_none(value)
    if result is None:
        raise TypeError(f"{type(value).__name__} has no JSON representation")
    return result
