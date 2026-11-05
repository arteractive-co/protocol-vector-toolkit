# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import copy
import os
import re
import unittest
from pathlib import Path

from protocol_vectors.validation import FORMAT_ID
from protocol_vectors.validation import validate_document

try:
    from jsonschema import Draft202012Validator
except ImportError:
    if os.environ.get("PVT_REQUIRE_SCHEMA_VALIDATOR") == "1":
        raise
    Draft202012Validator = None

ROOT = Path(__file__).resolve().parents[1]


class SchemaAlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with (ROOT / "schema" / "vector-set-draft-01.schema.json").open(
            "r", encoding="utf-8"
        ) as source:
            cls.schema = json.load(source)
        with (ROOT / "tests" / "fixtures" / "valid" / "minimal.json").open(
            "r", encoding="utf-8"
        ) as source:
            cls.valid = json.load(source)
        cls.schema_validator = (
            Draft202012Validator(cls.schema) if Draft202012Validator is not None else None
        )

    def test_format_identifier_matches_reference(self) -> None:
        self.assertEqual(self.schema["properties"]["format"]["const"], FORMAT_ID)

    def test_schema_patterns_accept_canonical_examples(self) -> None:
        definitions = self.schema["$defs"]
        self.assertIsNotNone(re.fullmatch(definitions["identifier"]["pattern"], "case-1"))
        bytes_pattern = definitions["bytesValue"]["properties"]["value"]["pattern"]
        self.assertIsNotNone(re.fullmatch(bytes_pattern, "00ff"))
        integer_pattern = definitions["integerValue"]["properties"]["value"]["pattern"]
        self.assertIsNotNone(re.fullmatch(integer_pattern, "0"))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema test dependency is not installed")
    def test_shared_valid_fixture_passes_both(self) -> None:
        assert self.schema_validator is not None
        self.assertEqual(list(self.schema_validator.iter_errors(self.valid)), [])
        self.assertEqual(validate_document(self.valid), [])

    @unittest.skipIf(Draft202012Validator is None, "jsonschema test dependency is not installed")
    def test_overlapping_negative_rules_reject_in_both(self) -> None:
        assert self.schema_validator is not None

        def external_artifact() -> dict[str, object]:
            return {
                "id": "external",
                "origin": "external",
                "license": "BSD-3-Clause",
                "redistribution": "link-only",
                "source_url": "https://example.invalid/source",
                "source_revision": "immutable-revision",
                "source_sha256": "1" * 64,
                "attribution": "Example Author",
            }

        def local_artifact() -> dict[str, object]:
            return {
                "id": "local",
                "origin": "original",
                "license": "Apache-2.0",
                "redistribution": "original",
                "path": "artifact.bin",
                "output_sha256": "2" * 64,
            }

        mutations = []

        document = copy.deepcopy(self.valid)
        artifact = external_artifact()
        artifact["source_url"] = ""
        document["provenance"]["artifacts"] = [artifact]
        mutations.append(document)

        document = copy.deepcopy(self.valid)
        artifact = local_artifact()
        artifact["transformations"] = ["valid", 3]
        document["provenance"]["artifacts"] = [artifact]
        mutations.append(document)

        document = copy.deepcopy(self.valid)
        case = document["cases"][0]
        case["disposition"] = "expected-error"
        case.pop("expected_outputs")
        case["expected_error"] = {"code": "expected", "extra": True}
        mutations.append(document)

        document = copy.deepcopy(self.valid)
        document["cases"][0]["notes"] = 7
        mutations.append(document)

        document = copy.deepcopy(self.valid)
        artifact = local_artifact()
        artifact.update(
            {
                "origin": "generated",
                "redistribution": "regenerated",
                "generator": {
                    "name": "generator",
                    "version": "1",
                    "argv": [],
                    "runtime": "python",
                    "extra": True,
                },
            }
        )
        document["provenance"]["artifacts"] = [artifact]
        mutations.append(document)

        document = copy.deepcopy(self.valid)
        artifact = local_artifact()
        artifact["path"] = "../escape.bin"
        document["provenance"]["artifacts"] = [artifact]
        mutations.append(document)

        for index, document in enumerate(mutations):
            with self.subTest(index=index):
                self.assertFalse(self.schema_validator.is_valid(document))
                self.assertTrue(validate_document(document))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema test dependency is not installed")
    def test_generated_artifact_requires_explicit_transformations(self) -> None:
        assert self.schema_validator is not None
        document = copy.deepcopy(self.valid)
        artifact = {
            "id": "generated",
            "origin": "generated",
            "license": "Apache-2.0",
            "redistribution": "regenerated",
            "path": "generated.bin",
            "output_sha256": "3" * 64,
            "generator": {
                "name": "generator",
                "version": "1",
                "argv": ["generator", "--deterministic"],
                "runtime": "python-3.11",
            },
            "transformations": [],
        }
        document["provenance"]["artifacts"] = [artifact]
        self.assertTrue(self.schema_validator.is_valid(document))
        self.assertEqual(validate_document(document), [])

        artifact.pop("transformations")
        self.assertFalse(self.schema_validator.is_valid(document))
        self.assertTrue(validate_document(document))

    def test_packaged_schema_matches_normative_copy(self) -> None:
        packaged = ROOT / "src" / "protocol_vectors" / "schemas" / "vector-set-draft-01.schema.json"
        self.assertEqual(
            packaged.read_bytes(),
            (ROOT / "schema" / "vector-set-draft-01.schema.json").read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
