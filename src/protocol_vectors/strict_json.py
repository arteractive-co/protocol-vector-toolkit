# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Strict JSON shared by untrusted corpus and adapter inputs."""

import json
import math
from typing import Any

MAX_DEPTH = 64


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _float(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON number")
    return result


def decode_json(raw: bytes, *, limit: int) -> Any:
    if len(raw) > limit:
        raise ValueError("JSON byte limit exceeded")
    # Bound nesting before invoking the recursive decoder, ignoring brackets in
    # quoted strings and escaped quotes. Syntax validation still belongs to JSON.
    quoted = escaped = False
    depth = 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise ValueError("JSON depth limit exceeded")
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs,
                       parse_constant=_constant, parse_float=_float)
    # JSON escapes can otherwise introduce lone surrogates despite valid UTF-8.
    json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    return value
