# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Canonical lexical forms used by the draft-01 data model."""

from __future__ import annotations

import re

_IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$")
_LOWER_HEX = re.compile(r"^(?:[0-9a-f]{2})*$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_PATH = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
_REVERSE_DNS = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def is_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def is_lower_hex_bytes(value: object) -> bool:
    return isinstance(value, str) and _LOWER_HEX.fullmatch(value) is not None


def is_canonical_decimal(value: object) -> bool:
    return isinstance(value, str) and _DECIMAL.fullmatch(value) is not None


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def is_artifact_path(value: object) -> bool:
    if not isinstance(value, str) or _ARTIFACT_PATH.fullmatch(value) is None:
        return False
    return all(component not in {".", ".."} for component in value.split("/"))


def is_extension_namespace(value: object) -> bool:
    if not isinstance(value, str):
        return False
    return value.startswith("https://") or _REVERSE_DNS.fullmatch(value) is not None
