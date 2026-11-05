# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from protocol_vectors.provenance import verify_local_artifacts
from protocol_vectors.validation import validate_document

FIXTURE = Path(__file__).parent / "fixtures" / "valid" / "minimal.json"


def load_document() -> dict[str, object]:
    with FIXTURE.open("r", encoding="utf-8") as source:
        return json.load(source)


class ProvenanceTests(unittest.TestCase):
    def test_file_and_aggregate_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.bin").write_bytes(b"0123456789")
            document = self.artifact_document(hashlib.sha256(b"0123456789").hexdigest())
            for limits in ({"max_artifact_bytes": 9}, {"max_total_bytes": 9}):
                diagnostics = verify_local_artifacts(document, root / "vectors.json", **limits)
                self.assertEqual([item.code for item in diagnostics], ["PVT9204"])
            self.assertEqual(verify_local_artifacts(document, root / "vectors.json", max_total_bytes=10), [])

    def test_symlink_loop_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            try:
                (root / "artifact.bin").symlink_to("artifact.bin")
            except OSError as exc:
                self.skipTest(str(exc))
            diagnostics = verify_local_artifacts(self.artifact_document("0" * 64), root / "vectors.json")
            self.assertEqual([item.code for item in diagnostics], ["PVT9201"])
    def artifact_document(self, digest: str, path: str = "artifact.bin") -> dict[str, object]:
        document = load_document()
        document["provenance"] = {
            "artifacts": [
                {
                    "id": "local-artifact",
                    "origin": "original",
                    "license": "Apache-2.0",
                    "redistribution": "original",
                    "path": path,
                    "output_sha256": digest,
                }
            ]
        }
        return document

    def test_matching_raw_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"exact\r\nbytes\x00"
            (root / "artifact.bin").write_bytes(payload)
            corpus = root / "vectors.json"
            corpus.write_text("{}", encoding="utf-8")
            document = self.artifact_document(hashlib.sha256(payload).hexdigest())
            self.assertEqual(validate_document(document), [])
            self.assertEqual(verify_local_artifacts(document, corpus), [])

    def test_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifact.bin").write_bytes(b"observed")
            corpus = root / "vectors.json"
            corpus.write_text("{}", encoding="utf-8")
            diagnostics = verify_local_artifacts(self.artifact_document("0" * 64), corpus)
            self.assertEqual([item.code for item in diagnostics], ["PVT9203"])

    def test_missing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "vectors.json"
            corpus.write_text("{}", encoding="utf-8")
            diagnostics = verify_local_artifacts(self.artifact_document("0" * 64), corpus)
            self.assertEqual([item.code for item in diagnostics], ["PVT9201"])

    def test_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            target = Path(outside) / "external.bin"
            target.write_bytes(b"outside")
            try:
                os.symlink(target, root / "artifact.bin")
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {exc}")
            corpus = root / "vectors.json"
            corpus.write_text("{}", encoding="utf-8")
            digest = hashlib.sha256(b"outside").hexdigest()
            diagnostics = verify_local_artifacts(self.artifact_document(digest), corpus)
            self.assertEqual([item.code for item in diagnostics], ["PVT9202"])


if __name__ == "__main__":
    unittest.main()
