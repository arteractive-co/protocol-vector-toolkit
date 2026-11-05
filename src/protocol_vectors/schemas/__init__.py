# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Access to the packaged normative JSON Schema."""

from __future__ import annotations

from importlib.resources import files


def draft_01_text() -> str:
    resource = files(__package__).joinpath("vector-set-draft-01.schema.json")
    return resource.read_text(encoding="utf-8")
