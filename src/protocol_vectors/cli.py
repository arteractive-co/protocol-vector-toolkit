# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Command-line entry point for the staging reference implementation."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from .diagnostics import Diagnostic
from .provenance import verify_local_artifacts
from .validation import validate_document
from .runner import RunnerError, run_adapter
from .strict_json import decode_json

MAX_CORPUS_BYTES = 8_388_608


def _load(path: Path) -> object:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("corpus must be a regular file")
        with os.fdopen(fd, "rb", closefd=False) as source:
            return decode_json(source.read(MAX_CORPUS_BYTES + 1), limit=MAX_CORPUS_BYTES)
    finally:
        os.close(fd)


def _emit(diagnostics: list[Diagnostic]) -> None:
    for diagnostic in diagnostics:
        print(json.dumps(diagnostic.to_dict(), sort_keys=True, separators=(",", ":")))


def _validate(path: Path) -> int:
    try:
        document = _load(path)
    except (OSError, ValueError, RecursionError) as exc:
        _emit([Diagnostic("PVT9001", "", f"unable to read JSON document: {exc}")])
        return 3
    diagnostics = validate_document(document)
    if not diagnostics:
        diagnostics.extend(verify_local_artifacts(document, path))
    _emit(diagnostics)
    return 0 if not diagnostics else 2


def _summarize(path: Path) -> int:
    try:
        document = _load(path)
    except (OSError, ValueError, RecursionError) as exc:
        _emit([Diagnostic("PVT9001", "", f"unable to read JSON document: {exc}")])
        return 3
    diagnostics = validate_document(document)
    if not diagnostics:
        diagnostics.extend(verify_local_artifacts(document, path))
    if diagnostics:
        _emit(diagnostics)
        return 2
    assert isinstance(document, dict)
    summary: dict[str, Any] = {
        "algorithm": document["algorithm"]["name"],
        "cases": len(document["cases"]),
        "corpus_id": document["corpus_id"],
        "format": document["format"],
        "profiles": [profile["id"] for profile in document["profiles"]],
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="protocol-vectors")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (
        ("validate", "validate a draft-01 vector corpus"),
        ("summarize", "print a compact corpus inventory"),
        ("provenance", "validate a corpus and verify its local artifact digests offline"),
    ):
        subparser = subparsers.add_parser(command, help=help_text)
        subparser.add_argument("file", type=Path)
    for name in ("run", "report"):
        run = subparsers.add_parser(name, help="compare a corpus with a trusted adapter")
        run.add_argument("file", type=Path)
        run.add_argument("adapter", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    actual = list(sys.argv[1:] if argv is None else argv)
    arguments = build_parser().parse_args(actual)
    if arguments.command in ("run", "report"):
        if len(actual) < 4 or actual[2] != "--" or not arguments.adapter:
            _emit([Diagnostic("PVT9002", "", "adapter command required after --")])
            return 3
        try:
            document = _load(arguments.file)
            diagnostics = validate_document(document)
            if not diagnostics:
                diagnostics.extend(verify_local_artifacts(document, arguments.file))
            if diagnostics:
                _emit(diagnostics)
                return 2
            report = run_adapter(document, actual[3:])
            print(json.dumps(report, sort_keys=True, separators=(",", ":")))
            return 0 if report["passed"] else 1
        except (OSError, ValueError, RecursionError, RunnerError) as exc:
            _emit([Diagnostic("PVT9003", "", str(exc))])
            return 3
    if arguments.command in ("validate", "provenance"):
        return _validate(arguments.file)
    if arguments.command == "summarize":
        return _summarize(arguments.file)
    return 3


if __name__ == "__main__":
    sys.exit(main())
