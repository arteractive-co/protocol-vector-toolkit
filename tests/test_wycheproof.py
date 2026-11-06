# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0
"""Dependency-free integration tests, using original non-cryptographic data.

No external corpus, compiler, crypto library, native executable or network is
needed. Real native/corpus coverage is explicit and separate, not silently skipped.
"""

import contextlib
import copy
import hashlib
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from integrations.wycheproof import adapter, corpus, run
from protocol_vectors.adapter_protocol import case_request
from protocol_vectors.runner import RunnerError
from protocol_vectors.validation import validate_document


def fixture(schema="mlkem_test_schema.json", result="valid"):
    group_type, _, inputs, outputs = corpus.TYPES[schema]
    test = {"tcId": 1, "result": result, "flags": [], "comment": "Original synthetic mapping fixture"}
    for name in set(inputs.values()) | set(outputs.values()):
        test[name] = "0001ff"
    return {"algorithm": "ML-KEM", "schema": schema, "numberOfTests": 1,
            "testGroups": [{"type": group_type, "source": {"name": "arteractive-synthetic", "version": "1"},
                            "parameterSet": "ML-KEM-768", "tests": [test]}]}


def convert(document):
    name = next(iter(corpus.FILES))
    raw = json.dumps(document).encode()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "testvectors_v1").mkdir()
        (root / "testvectors_v1" / name).write_bytes(raw)
        with patch.dict(corpus.FILES, {name: hashlib.sha256(raw).hexdigest()}):
            return corpus.convert_file(root, name)


class WycheproofMappingTests(unittest.TestCase):
    def test_all_four_operation_mappings_are_byte_exact(self):
        for schema, (_, _, inputs, outputs) in corpus.TYPES.items():
            with self.subTest(schema=schema):
                doc = convert(fixture(schema))
                self.assertEqual(validate_document(doc), [])
                case = doc["cases"][0]
                self.assertEqual(set(case["inputs"]), set(inputs))
                self.assertEqual(set(case["expected_outputs"]), set(outputs))
                self.assertTrue(all(v["value"] == "0001ff" and v["length"] == 3
                                    for v in [*case["inputs"].values(), *case["expected_outputs"].values()]))

    def test_expanded_key_is_not_replaced_with_seed(self):
        doc = convert(fixture("mlkem_semi_expanded_decaps_test_schema.json"))
        self.assertEqual(set(doc["cases"][0]["inputs"]), {"private-key", "ciphertext"})

    def test_expectations_not_sent_to_adapter(self):
        for result in ("valid", "invalid"):
            c = convert(fixture(result=result))["cases"][0]
            request = case_request(c)
            self.assertFalse({"expected_outputs", "expected_error", "disposition"} & set(request))
            self.assertNotIn("result", request["extensions"][corpus.EXTENSION])

    def test_unknown_result_is_not_guessed(self):
        with self.assertRaisesRegex(ValueError, "unmapped result"):
            convert(fixture(result="acceptable"))

    def test_changed_source_digest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "testvectors_v1").mkdir()
            (root / "testvectors_v1" / next(iter(corpus.FILES))).write_bytes(b"{}")
            with self.assertRaisesRegex(ValueError, "source digest mismatch"):
                corpus.convert_file(root, next(iter(corpus.FILES)))

    def test_duplicate_ids_rejected(self):
        d = fixture()
        d["testGroups"][0]["tests"] *= 2
        d["numberOfTests"] = 2
        with self.assertRaisesRegex(ValueError, "duplicate tcId"):
            convert(d)

    def test_count_mismatch_rejected(self):
        d = fixture()
        d["numberOfTests"] = 2
        with self.assertRaisesRegex(ValueError, "source count mismatch"):
            convert(d)

    def test_noncanonical_hex_rejected_under_optimization_too(self):
        for value in ("FF", "0", "0x00", "00\n", " 00", 12):
            with self.subTest(value=value), self.assertRaises(ValueError):
                corpus.typed_hex(value)

    def test_unknown_group_and_parameter_rejected(self):
        for field, value in (("type", "other"), ("parameterSet", "ML-KEM-900")):
            d = fixture()
            d["testGroups"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                convert(d)

    def test_fallback_case_remains_success(self):
        d = fixture()
        d["testGroups"][0]["tests"][0]["flags"] = ["MalleableCiphertext"]
        c = convert(d)["cases"][0]
        self.assertEqual(c["disposition"], "success")
        self.assertEqual(c["extensions"][corpus.EXTENSION]["flags"], ["MalleableCiphertext"])


class WycheproofBatchTests(unittest.TestCase):
    def setUp(self):
        self.doc = convert(fixture())
        first = self.doc["cases"][0]
        self.doc["cases"] = [dict(first, id=f"case-{i}") for i in range(35)]

    def test_batches_preserve_complete_order(self):
        chunks = corpus.batches(self.doc)
        self.assertEqual([len(c["cases"]) for c in chunks], [16, 16, 3])
        self.assertEqual([c["id"] for d in chunks for c in d["cases"]],
                         [c["id"] for c in self.doc["cases"]])

    def test_runner_limits_are_not_overridden(self):
        def fake(doc, argv):
            return {"cases": [{"id": c["id"], "passed": True} for c in doc["cases"]]}
        with patch("protocol_vectors.runner.run_adapter", side_effect=fake) as mocked:
            report = corpus.run_batched(self.doc, ["trusted-worker"])
        self.assertEqual(len(report["cases"]), 35)
        self.assertEqual(report["batches"], 3)
        self.assertTrue(all(not call.kwargs for call in mocked.call_args_list))

    def test_invalid_and_fallback_metadata_never_reach_wire(self):
        for result, flag in (("invalid", "InvalidDecapsulationKey"), ("valid", "MalleableCiphertext")):
            d = fixture(result=result)
            t = d["testGroups"][0]["tests"][0]
            t.update(flags=[flag], comment="Expectation hint: should reject" if result == "invalid"
                     else "Return the fallback secret")
            doc = convert(d)
            def inspect_wire(chunk, argv):
                for case in chunk["cases"]:
                    request = case_request(case)
                    self.assertEqual(set(request), {"type", "id", "profile", "inputs"})
                return {"cases": [{"id": c["id"], "passed": True} for c in chunk["cases"]]}
            with self.subTest(result=result), patch("protocol_vectors.runner.run_adapter", side_effect=inspect_wire):
                corpus.run_batched(doc, ["trusted-worker"])
            self.assertEqual(doc["cases"][0]["extensions"][corpus.EXTENSION]["flags"], [flag])

    def test_missing_reordered_or_duplicate_case_cannot_pass(self):
        for which in ("drop", "reverse", "duplicate"):
            def fake(doc, argv):
                cases = [{"id": c["id"], "passed": True} for c in doc["cases"]]
                cases = cases[:-1] if which == "drop" else cases[::-1] if which == "reverse" else cases + cases[:1]
                return {"cases": cases}
            with self.subTest(which=which), patch("protocol_vectors.runner.run_adapter", side_effect=fake):
                with self.assertRaisesRegex(ValueError, "lost, duplicated, or reordered"):
                    corpus.run_batched(self.doc, ["trusted-worker"])

    def test_infrastructure_error_propagates(self):
        with patch("protocol_vectors.runner.run_adapter", side_effect=RunnerError("control")):
            with self.assertRaises(RunnerError):
                corpus.run_batched(self.doc, ["trusted-worker"])

    def test_equal_failure_count_with_wrong_ids_is_rejected(self):
        d = copy.deepcopy(self.doc)
        d["cases"][0] = dict(d["cases"][0], disposition="expected-error")
        report = {"cases": [{"id": c["id"], "passed": i != 1} for i, c in enumerate(d["cases"])], "batches": 3}
        self.assertFalse(run.mode_result(d, report, "accept")["matched_expected_ids"])


class WycheproofWorkerTests(unittest.TestCase):
    def test_native_framing(self):
        self.assertEqual(adapter.unframe(adapter.blob(b"\x00\xff") + adapter.blob(b"abc")), [b"\x00\xff", b"abc"])

    def test_malformed_framing_is_not_algorithm_error(self):
        for raw in (b"", b"\x00", adapter.blob(b"a"), struct.pack(">I", 8193),
                    adapter.blob(b"a") + adapter.blob(b"b") + b"extra"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                adapter.unframe(raw)

    def test_only_clean_exit_two_is_expected_rejection(self):
        for code, stdout in ((90, b""), (-9, b""), (2, b"unexpected"), (0, b"invalid")):
            result = subprocess.CompletedProcess([], code, stdout, b"")
            with self.subTest(code=code), patch.object(adapter.subprocess, "run", return_value=result):
                with self.assertRaises(ValueError):
                    adapter.worker_result(Path("worker"), "ML-KEM-768", "keygen", [b"", b""])
        with patch.object(adapter.subprocess, "run", return_value=subprocess.CompletedProcess([], 2, b"", b"")):
            self.assertIsNone(adapter.worker_result(Path("worker"), "ML-KEM-768", "keygen", [b"", b""]))

    def test_timeout_or_missing_executable_does_not_pass(self):
        for error in (subprocess.TimeoutExpired("worker", 1), FileNotFoundError("worker")):
            with patch.object(adapter.subprocess, "run", side_effect=error):
                with self.assertRaises(type(error)):
                    adapter.worker_result(Path("worker"), "ML-KEM-768", "keygen", [b"", b""])


class WycheproofEvidenceTests(unittest.TestCase):
    def test_existing_evidence_is_preserved_without_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "evidence.json"
            output.write_text("original")
            with patch.object(run, "execute") as execute, contextlib.redirect_stderr(io.StringIO()):
                code = run.main(["--source", str(Path(tmp) / "source"), "--worker", "missing", "--evidence", str(output)])
            self.assertEqual(code, 3)
            self.assertEqual(output.read_text(), "original")
            execute.assert_not_called()

    def test_evidence_cannot_modify_either_checkout(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            run.main(["--source", "/external-source", "--worker", "missing", "--evidence", str(ROOT / "no-output.json")])

    def test_infrastructure_failure_is_recorded_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "evidence.json"
            with patch.object(run, "execute", side_effect=RunnerError("control")), contextlib.redirect_stderr(io.StringIO()):
                code = run.main(["--source", str(Path(tmp) / "source"), "--worker", "missing", "--evidence", str(output)])
            evidence = json.loads(output.read_text())
            self.assertEqual(code, 3)
            self.assertFalse(evidence["completed"])
            self.assertFalse(evidence["conformant"])


if __name__ == "__main__":
    unittest.main()
