# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import unittest
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from protocol_vectors.runner import require_adapter_argv, run_adapter, RunnerError
from protocol_vectors.adapter_protocol import ProtocolError

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name in ("posix", "nt"), "supported transport tests")
class RunnerProcessTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((ROOT / "examples/little-endian-fields/vectors.json").read_text())

    def lifecycle(self, mode, *args):
        return [sys.executable, str(ROOT / "tests/adapters/lifecycle.py"), mode, *args]

    def test_lifecycle_failures(self):
        for mode in ("wrong-id", "duplicate", "trailing", "truncated", "nonzero", "partial-preplay"):
            with self.subTest(mode=mode), self.assertRaises((RunnerError, ProtocolError)):
                run_adapter(self.document, self.lifecycle(mode), timeout=2)

    def test_nonconformance_is_not_transport_failure(self):
        report = run_adapter(self.document, self.lifecycle("mismatch"))
        self.assertFalse(report["passed"])

    def test_literal_argv(self):
        report = run_adapter(self.document, self.lifecycle("literal", "value with spaces", "$(not-a-shell)", "--flag"))
        self.assertTrue(report["passed"])

    def test_literal_special_argv(self):
        report = run_adapter(self.document, self.lifecycle(
            "literal-special", 'a"b', "trailing\\", "雪", "", "space and slash\\"))
        self.assertTrue(report["passed"])

    @unittest.skipUnless(os.name == "posix", "POSIX cleanup injection")
    def test_cleanup_wait_timeout_is_wrapped_and_pipes_closed(self):
        from unittest.mock import patch
        import subprocess
        real_popen = subprocess.Popen
        children = []

        def launch(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            original_wait = child.wait

            def wait(timeout=None):
                if timeout == 2:
                    original_wait(timeout=2)
                    raise subprocess.TimeoutExpired(child.args, timeout)
                return original_wait(timeout=timeout)

            child.wait = wait
            return child

        with patch("protocol_vectors.runner.subprocess.Popen", side_effect=launch):
            with self.assertRaisesRegex(RunnerError, "cleanup failed"):
                run_adapter(self.document, self.lifecycle("normal"))
        self.assertTrue(all(pipe.closed for child in children for pipe in
                            (child.stdin, child.stdout, child.stderr)))

    def test_absolute_session_deadline(self):
        with self.assertRaises(RunnerError):
            run_adapter(self.document, self.lifecycle("slow"), timeout=0.3, case_timeout=0.25)

    def test_per_exchange_deadline(self):
        with self.assertRaises(RunnerError):
            run_adapter(self.document, self.lifecycle("slow"), timeout=2, case_timeout=0.05)

    def test_blocked_input(self):
        # Larger than a pipe buffer but within protocol quotas.
        self.document["algorithm"]["name"] = "x" * 100000
        with self.assertRaises(RunnerError):
            run_adapter(self.document, self.lifecycle("blocked-input"), timeout=0.2)

    def test_report_limit(self):
        with self.assertRaisesRegex(RunnerError, "report"):
            run_adapter(self.document, self.lifecycle("normal"), report_limit=256)

    def test_descendant_cleanup(self):
        for mode in ("child-success", "child-timeout"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                marker = str(Path(directory) / "child-marker")
                try:
                    report = run_adapter(self.document, self.lifecycle(mode, marker), timeout=1)
                    self.assertTrue(report["passed"])
                except RunnerError:
                    if mode != "child-timeout":
                        raise
                self.assertTrue(Path(marker + ".pid").exists(), "child was never launched")
                time.sleep(2.1)
                self.assertFalse(Path(marker).exists(), "descendant remained alive")

    def test_cancellation_cleans_child(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "cancel-child")
            module = "windows_runner" if os.name == "nt" else "runner"
            with patch(f"protocol_vectors.{module}.validate_ready", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    run_adapter(self.document, self.lifecycle("child-success", marker))
            self.assertTrue(Path(marker + ".pid").exists())
            time.sleep(2.1)
            self.assertFalse(Path(marker).exists())

    def test_toy_end_to_end(self):
        report = run_adapter(self.document, [sys.executable, str(ROOT / "examples/little-endian-fields/adapter.py")])
        self.assertTrue(report["passed"])
        self.assertEqual(len(report["cases"]), 5)

    def test_toy_huge_decimal_returns_algorithm_error(self):
        self.document["cases"] = [self.document["cases"][3]]
        self.document["cases"][0]["inputs"]["value"]["value"] = "9" * 5000
        report = run_adapter(self.document, [sys.executable, str(ROOT / "examples/little-endian-fields/adapter.py")])
        self.assertTrue(report["passed"])

    def test_timeout(self):
        with self.assertRaises(RunnerError):
            run_adapter(self.document, [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2)

    @unittest.skipUnless(os.name == "posix", "POSIX group signalling")
    def test_cleanup_permission_failure_is_reported(self):
        from unittest.mock import patch
        with patch("protocol_vectors.runner.os.killpg", side_effect=PermissionError("test denial")):
            with self.assertRaisesRegex(RunnerError, "cleanup failed"):
                run_adapter(self.document, [sys.executable, "-c", "pass"])

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects")
    def test_windows_job_assignment_fails_before_adapter_launch(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "not-launched")
            code = "from pathlib import Path; Path(" + repr(marker) + ").touch()"
            with patch("protocol_vectors.windows_runner.WindowsJob.assign", side_effect=OSError("denied")):
                with self.assertRaisesRegex(RunnerError, "establish Windows"):
                    run_adapter(self.document, [sys.executable, "-c", code])
            self.assertFalse(Path(marker).exists())

    @unittest.skipUnless(os.name == "nt", "Windows batch rejection")
    def test_windows_batch_rejected_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "adapter.cmd"
            command.write_text("@echo unexpected")
            with self.assertRaisesRegex(RunnerError, "batch file"):
                run_adapter(self.document, [str(command)])

    @unittest.skipUnless(os.name == "nt", "Windows pipe worker startup")
    def test_windows_worker_start_failure_is_wrapped(self):
        from unittest.mock import patch
        with patch("protocol_vectors.windows_runner.threading.Thread.start", side_effect=RuntimeError("exhausted")):
            with self.assertRaisesRegex(RunnerError, "pipe worker"):
                run_adapter(self.document, self.lifecycle("normal"))

    @unittest.skipUnless(os.name == "nt", "Windows gate")
    def test_windows_invalid_gate_token_never_launches_adapter(self):
        import subprocess
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "not-launched"
            command = [sys.executable, "-I", "-S",
                       str(ROOT / "src/protocol_vectors/windows_gate.py"),
                       sys.executable, "-c", "from pathlib import Path; Path(" + repr(str(marker)) + ").touch()"]
            result = subprocess.run(command, input=b"X", capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 125)
            self.assertFalse(marker.exists())

    def test_secret_environment_not_forwarded(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"PVT_SENTINEL_SECRET": "must-not-leak"}):
            code = "import os; assert 'PVT_SENTINEL_SECRET' not in os.environ; print('{}',flush=True)"
            # Reaching malformed handshake (rather than early exit) shows the assertion passed.
            with self.assertRaises(ProtocolError):
                run_adapter(self.document, [sys.executable, "-c", code])

    def test_premature_exit_is_not_expected_error(self):
        with self.assertRaises(RunnerError):
            run_adapter(self.document, [sys.executable, "-c", "pass"])

    def test_bad_handshake(self):
        with self.assertRaises(ProtocolError):
            run_adapter(self.document, [sys.executable, "-c", "print('{}', flush=True)"])

    def test_stderr_flood(self):
        with self.assertRaises(RunnerError):
            run_adapter(self.document, [sys.executable, "-c", "import sys; sys.stderr.write('x'*100000)"], stream_limit=20000)

    def test_no_newline_flood(self):
        with self.assertRaises((RunnerError, ProtocolError)):
            run_adapter(self.document, [sys.executable, "-c", "import sys; sys.stdout.write('x'*2000000)"], timeout=2)


class RunnerArgumentTests(unittest.TestCase):
    def test_literal_arguments_are_preserved(self) -> None:
        arguments = ["adapter", "--profile", "value with spaces", "$(not-a-shell)"]
        self.assertEqual(require_adapter_argv(arguments), tuple(arguments))

    def test_empty_command_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            require_adapter_argv([])

    def test_nul_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            require_adapter_argv(["adapter", "bad\x00argument"])


if __name__ == "__main__":
    unittest.main()
