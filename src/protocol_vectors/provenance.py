# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Offline digest verification for corpus-relative provenance artifacts."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from .diagnostics import Diagnostic, ordered


MAX_ARTIFACT_BYTES = 67_108_864
MAX_TOTAL_BYTES = 134_217_728


def _hash_bounded(path: Path, *, limit: int, deadline: float) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as source:
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("artifact verification deadline exceeded")
            chunk = source.read(min(1_048_576, limit - count + 1))
            if not chunk:
                break
            count += len(chunk)
            if count > limit:
                raise ValueError("artifact verification byte limit exceeded")
            digest.update(chunk)
    return digest.hexdigest(), count


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    # chunk_size is retained for source compatibility, but not used as a quota.
    return _hash_bounded(path, limit=MAX_ARTIFACT_BYTES,
                         deadline=time.monotonic() + 5)[0]


def verify_local_artifacts(document: object, corpus_file: Path, *,
                           max_artifact_bytes: int = MAX_ARTIFACT_BYTES,
                           max_total_bytes: int = MAX_TOTAL_BYTES,
                           timeout: float = 5.0) -> list[Diagnostic]:
    if not (0 < timeout <= 300 and 0 < max_artifact_bytes <= MAX_ARTIFACT_BYTES
            and 0 < max_total_bytes <= MAX_TOTAL_BYTES):
        raise ValueError("invalid provenance verification limits")
    if not isinstance(document, dict):
        return []
    provenance = document.get("provenance")
    if not isinstance(provenance, dict) or not isinstance(provenance.get("artifacts"), list):
        return []

    root = corpus_file.resolve().parent
    diagnostics: list[Diagnostic] = []
    total = 0
    deadline = time.monotonic() + timeout
    for index, record in enumerate(provenance["artifacts"]):
        if not isinstance(record, dict) or record.get("redistribution") == "link-only":
            continue
        relative = record.get("path")
        expected = record.get("output_sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            continue
        diagnostic_path = f"/provenance/artifacts/{index}/path"
        candidate = root.joinpath(*relative.split("/"))
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            diagnostics.append(
                Diagnostic(
                    "PVT9201",
                    diagnostic_path,
                    "artifact path cannot be read",
                    observed=str(exc),
                )
            )
            continue
        if not resolved.is_relative_to(root) or not resolved.is_file():
            diagnostics.append(
                Diagnostic(
                    "PVT9202",
                    diagnostic_path,
                    "artifact path must resolve to a regular file inside the corpus directory",
                    observed=relative,
                )
            )
            continue
        try:
            observed, count = _hash_bounded(
                resolved, limit=min(max_artifact_bytes, max_total_bytes - total),
                deadline=deadline)
            total += count
        except ValueError as exc:
            diagnostics.append(Diagnostic("PVT9204", diagnostic_path, str(exc)))
            break
        except OSError as exc:
            diagnostics.append(
                Diagnostic(
                    "PVT9201",
                    diagnostic_path,
                    "artifact bytes cannot be read",
                    observed=str(exc),
                )
            )
            continue
        if observed != expected:
            diagnostics.append(
                Diagnostic(
                    "PVT9203",
                    f"/provenance/artifacts/{index}/output_sha256",
                    "artifact digest does not match raw local bytes",
                    expected=expected,
                    observed=observed,
                )
            )
    return ordered(diagnostics)
