# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Bounded draft-01 adapter messages, independent of process transport."""

from __future__ import annotations

import json
from typing import Any

from .strict_json import decode_json
from .canonical import is_lower_hex_bytes

PROTOCOL = "org.arteractive.protocol-vectors.adapter/draft-01"
MAX_MESSAGE_BYTES = 1_048_576


class ProtocolError(ValueError):
    """An adapter violated the wire protocol, not an algorithm expectation."""


def decode_message(line: bytes) -> dict[str, Any]:
    if len(line) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message exceeds byte limit")
    if not line.endswith(b"\n") or b"\n" in line[:-1] or b"\r" in line:
        raise ProtocolError("message must be one LF-terminated line")
    try:
        value = decode_json(line, limit=MAX_MESSAGE_BYTES)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("invalid UTF-8 JSON message") from exc
    if not isinstance(value, dict):
        raise ProtocolError("message must be an object")
    return value


def encode_message(message: dict[str, Any]) -> bytes:
    try:
        line = (json.dumps(message, ensure_ascii=False, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("message cannot be encoded") from exc
    decode_message(line)
    return line


def validate_ready(message: dict[str, Any]) -> None:
    if message != {"type": "ready", "protocol": PROTOCOL}:
        raise ProtocolError("expected exact draft-01 ready handshake")


def case_request(case: dict[str, Any]) -> dict[str, Any]:
    # Expectations are never sent to an adapter: it must compute its answer.
    result = {"type": "case", "id": case["id"], "profile": case["profile"],
              "inputs": case["inputs"]}
    for key in ("deterministic_choices", "extensions"):
        if key in case:
            result[key] = case[key]
    return result


def compare_result(case: dict[str, Any], message: dict[str, Any]) -> bool:
    """Return conformance; malformed responses raise rather than pass negatives."""
    if message.get("type") != "result" or message.get("id") != case["id"]:
        raise ProtocolError("result type or case ID mismatch")
    status = message.get("status")
    if status == "error":
        if set(message) != {"type", "id", "status", "code"} or not isinstance(message["code"], str) or not message["code"]:
            raise ProtocolError("malformed algorithm error result")
        return (case["disposition"] == "expected-error"
                and message["code"] == case["expected_error"]["code"])
    if status != "success" or set(message) != {"type", "id", "status", "outputs"}:
        raise ProtocolError("malformed success result")
    outputs = message["outputs"]
    if not isinstance(outputs, dict):
        raise ProtocolError("outputs must be an object")
    # JSON serialization prevents Python's True == 1 coercion from matching.
    return (case["disposition"] != "expected-error" and
            encode_message(outputs) == encode_message(case["expected_outputs"]))


def mismatch_diagnostic(case: dict[str, Any], message: dict[str, Any]) -> dict[str, Any]:
    """Describe the first deterministic mismatch after response shape validation."""
    diagnostic = {"code": "PVT9301", "case_id": case["id"], "path": "",
                  "message": "adapter result does not match expectation"}
    if case["disposition"] == "expected-error" or message["status"] != "success":
        diagnostic.update(path="/status", expected=case.get("expected_error", "success"),
                          observed={"status": message["status"], "code": message.get("code")})
        return diagnostic

    def first(expected, observed, path=""):
        if type(expected) is not type(observed):
            return {"path": path, "expected": expected, "observed": observed}
        if isinstance(expected, dict):
            for key in sorted(set(expected) | set(observed)):
                child = path + "/" + key.replace("~", "~0").replace("/", "~1")
                if key not in expected or key not in observed:
                    return {"path": child, "expected": expected.get(key),
                            "observed": observed.get(key), "message": "output field missing or unexpected"}
                if expected[key] != observed[key] or type(expected[key]) is not type(observed[key]):
                    if (key == "value" and expected.get("kind") == "bytes"
                            and observed.get("kind") == "bytes"
                            and is_lower_hex_bytes(expected[key]) and is_lower_hex_bytes(observed[key])):
                        a, b = bytes.fromhex(expected[key]), bytes.fromhex(observed[key])
                        offset = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
                        return {"path": child, "byte_offset": offset,
                                "expected": expected[key], "observed": observed[key]}
                    return first(expected[key], observed[key], child)
        return {"path": path, "expected": expected, "observed": observed}

    diagnostic.update(first(case["expected_outputs"], message["outputs"]))
    return diagnostic
