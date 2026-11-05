# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

import copy
import json
import re
import unittest
from pathlib import Path

from protocol_vectors.validation import validate_document

ROOT = Path(__file__).resolve().parents[1]


def invalid_mutations():
    original = json.loads((ROOT / "tests/fixtures/valid/minimal.json").read_text())
    paths = [("encoding", "default_byte_order"), ("cases", 0, "profile"),
             ("cases", 0, "disposition"), ("extensions",), ("notes",),
             ("profiles", 0, "extensions"), ("cases", 0, "extensions")]
    for path in paths:
        for value in (None, [], {}, True, 5):
            if path[-1] == "extensions" and value == {}:
                continue
            doc = copy.deepcopy(original)
            target = doc
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            yield doc
    for field in ("origin", "redistribution", "transformations"):
        for value in (None, {}, True, 5):
            doc = copy.deepcopy(original)
            record = {"id": "a", "origin": "original", "license": "Apache-2.0",
                      "redistribution": "original", "path": "a.bin", "output_sha256": "0" * 64}
            record[field] = value
            doc["provenance"]["artifacts"] = [record]
            yield doc
    for value in (None, [], {}, True, 5):
        doc = copy.deepcopy(original)
        doc["cases"][0]["inputs"] = {"field": {"kind": "bytes", "value": "00", "length": 1, "byte_order": value}}
        yield doc
    for field in ("id", "profile"):
        doc = copy.deepcopy(original)
        doc["cases"][0][field] += "\n"
        yield doc


class MutationTests(unittest.TestCase):
    def test_float_length_rejected_by_semantic_rule(self):
        document = json.loads((ROOT / "tests/fixtures/valid/minimal.json").read_text())
        document["cases"][0]["inputs"] = {"value": {"kind": "bytes", "value": "0000", "length": 2.0}}
        self.assertTrue(validate_document(document))
    def test_invalid_types_and_nulls_return_diagnostics(self):
        for index, doc in enumerate(invalid_mutations()):
            with self.subTest(index=index):
                self.assertTrue(validate_document(doc))

    def test_schema_regexes_reject_terminal_lf(self):
        schema = json.loads((ROOT / "schema/vector-set-draft-01.schema.json").read_text())
        examples = [(schema["$defs"]["identifier"]["pattern"], "case-1"),
                    (schema["$defs"]["sha256"]["pattern"], "a" * 64),
                    (schema["$defs"]["bytesValue"]["properties"]["value"]["pattern"], "00ff"),
                    (schema["$defs"]["integerValue"]["properties"]["value"]["pattern"], "100"),
                    (schema["$defs"]["artifact"]["properties"]["path"]["pattern"], "dir/a.bin")]
        for pattern, text in examples:
            with self.subTest(text=text):
                self.assertIsNotNone(re.search(pattern, text))
                self.assertIsNone(re.search(pattern, text + "\n"))

    def test_schema_parity_mutations(self):
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("pinned jsonschema dependency unavailable")
        schema = json.loads((ROOT / "schema/vector-set-draft-01.schema.json").read_text())
        validator = Draft202012Validator(schema)
        for index, doc in enumerate(invalid_mutations()):
            with self.subTest(index=index):
                self.assertFalse(validator.is_valid(doc))
