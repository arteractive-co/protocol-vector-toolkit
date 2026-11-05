# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from protocol_vectors.validation import FORMAT_ID, validate_document

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(*parts: str) -> object:
    with (FIXTURES.joinpath(*parts)).open("r", encoding="utf-8") as source:
        return json.load(source)


class ValidationTests(unittest.TestCase):
    def test_minimal_fixture_is_valid(self) -> None:
        self.assertEqual(validate_document(load_fixture("valid", "minimal.json")), [])

    def test_multiple_errors_are_stable_and_complete(self) -> None:
        diagnostics = validate_document(load_fixture("invalid", "multiple-errors.json"))
        codes = [diagnostic.code for diagnostic in diagnostics]
        self.assertIn("PVT0103", codes)
        self.assertIn("PVT0301", codes)
        self.assertIn("PVT0401", codes)
        self.assertIn("PVT0403", codes)
        self.assertIn("PVT0404", codes)
        self.assertEqual(diagnostics, sorted(diagnostics, key=lambda item: item.sort_key()))

    def test_unknown_core_field_fails(self) -> None:
        document = load_fixture("valid", "minimal.json")
        assert isinstance(document, dict)
        modified = copy.deepcopy(document)
        modified["surprise"] = True
        diagnostics = validate_document(modified)
        self.assertEqual([item.code for item in diagnostics], ["PVT0005"])

    def test_diagnostic_paths_escape_json_pointer_tokens(self) -> None:
        document = load_fixture("valid", "minimal.json")
        assert isinstance(document, dict)
        document["unknown/~field"] = True
        diagnostics = validate_document(document)
        self.assertEqual(diagnostics[0].path, "/unknown~1~0field")

    def test_mixed_byte_order_requires_field_order(self) -> None:
        document = load_fixture("valid", "minimal.json")
        assert isinstance(document, dict)
        document["encoding"]["default_byte_order"] = "mixed"
        diagnostics = validate_document(document)
        self.assertIn("PVT0104", [item.code for item in diagnostics])

    def test_format_constant_matches_reference(self) -> None:
        self.assertEqual(FORMAT_ID, "org.arteractive.protocol-vectors/draft-01")


if __name__ == "__main__":
    unittest.main()
