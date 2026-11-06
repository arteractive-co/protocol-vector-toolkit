# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Stable diagnostics shared by the CLI and reference validator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    path: str
    message: str
    case_id: str | None = None
    byte_offset: int | None = None
    expected: Any = None
    observed: Any = None

    def sort_key(self) -> tuple[str, str, str, int]:
        return (
            self.path,
            self.code,
            self.case_id or "",
            -1 if self.byte_offset is None else self.byte_offset,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "code": self.code,
            "path": self.path,
            "message": self.message,
        }
        for name in ("case_id", "byte_offset", "expected", "observed"):
            value = getattr(self, name)
            if value is not None:
                result[name] = value
        return result


def ordered(diagnostics: list[Diagnostic]) -> list[Diagnostic]:
    return sorted(diagnostics, key=Diagnostic.sort_key)
