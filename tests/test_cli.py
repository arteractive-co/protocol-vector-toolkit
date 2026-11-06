# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_invalid_corpus_prevents_adapter_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "must-not-exist"
            result = self.run_cli("run", "tests/fixtures/invalid/multiple-errors.json", "--",
                                  sys.executable, "-c", f"open({str(marker)!r}, 'w').write('launched')")
            self.assertEqual(result.returncode, 2)
            self.assertFalse(marker.exists())

    def test_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "invalid.json"
            corpus.write_text('{"x":1,"x":2}')
            result = self.run_cli("validate", str(corpus))
            self.assertEqual(result.returncode, 3)

    def test_provenance_command(self):
        result = self.run_cli("provenance", "examples/little-endian-fields/vectors.json")
        self.assertEqual(result.returncode, 0)

    @unittest.skipUnless(os.name in ("posix", "nt"), "supported transport")
    def test_report_command(self):
        result = self.run_cli("report", "examples/little-endian-fields/vectors.json", "--",
                              sys.executable, "examples/little-endian-fields/adapter.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["passed"])
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "protocol_vectors", *arguments],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_validate_success(self) -> None:
        result = self.run_cli("validate", "tests/fixtures/valid/minimal.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_validate_failure_is_machine_readable(self) -> None:
        result = self.run_cli("validate", "tests/fixtures/invalid/multiple-errors.json")
        self.assertEqual(result.returncode, 2)
        records = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(records)
        self.assertTrue(all("code" in record and "path" in record for record in records))

    def test_summarize(self) -> None:
        result = self.run_cli("summarize", "tests/fixtures/valid/minimal.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["cases"], 1)
        self.assertEqual(summary["profiles"], ["default"])

    @unittest.skipUnless(os.name in ("posix", "nt"), "supported transport")
    def test_run_toy(self):
        result = self.run_cli("run", "examples/little-endian-fields/vectors.json", "--",
                              sys.executable, "examples/little-endian-fields/adapter.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["passed"])

    def test_run_requires_separator(self):
        result = self.run_cli("run", "examples/little-endian-fields/vectors.json", sys.executable)
        self.assertEqual(result.returncode, 3)

    def test_run_rejects_ignored_prefix(self):
        result = self.run_cli("run", "examples/little-endian-fields/vectors.json",
                              "ignored", "--", sys.executable)
        self.assertEqual(result.returncode, 3)


if __name__ == "__main__":
    unittest.main()
