# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0
"""Explicit, offline, source-only Wycheproof ML-KEM integration. AS IS."""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from integrations.wycheproof.corpus import FILES, REVISION, BATCH_SIZE, convert_file, require, run_batched


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], timeout=5,
                                   stderr=subprocess.DEVNULL)


def source_corpora(root):
    require(git(root, "rev-parse", "HEAD").decode().strip() == REVISION, "wrong source revision")
    require(not git(root, "status", "--porcelain", "--untracked-files=no"), "dirty source checkout")
    require({p.name for p in (root / "testvectors_v1").glob("mlkem*")} == set(FILES), "source inventory drift")
    result = {name: convert_file(root, name) for name in FILES}
    require(sum(len(c["cases"]) for c in result.values()) == 1725, "case count drift")
    return result


def source_fingerprint(root):
    """Hash tracked and nonignored candidate files, including uncommitted work.

    Requires an operator-controlled immutable checkout, not a concurrent writer.
    Generated workers/evidence must stay outside this source checkout.
    """
    names = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")
    return {name.decode("utf-8"): hashlib.sha256((root / name.decode("utf-8")).read_bytes()).hexdigest()
            for name in sorted(set(names)) if name}


def mode_result(corpus, report, fault):
    expected = [c["id"] for c in corpus["cases"] if fault is not None and
                c["disposition"] == ("success" if fault in ("output", "second-output") else "expected-error")]
    failed = [r["id"] for r in report["cases"] if not r["passed"]]
    return {"cases": len(report["cases"]), "failed": len(failed),
            "expected_failures": len(expected), "matched_expected_ids": failed == expected,
            "first_failed_ids": failed[:10], "batches": report["batches"]}


def save(stream, evidence):
    stream.seek(0)
    json.dump(evidence, stream, indent=2, sort_keys=True)
    stream.write("\n")
    stream.truncate()
    stream.flush()


def execute(source, worker, evidence, stream, controls):
    from protocol_vectors.adapter_protocol import case_request
    from protocol_vectors.provenance import verify_local_artifacts
    from protocol_vectors.validation import validate_document

    original = source_fingerprint(ROOT)
    corpora = source_corpora(source)
    for corpus in corpora.values():
        require(not validate_document(corpus), "invalid converted corpus")
        require(not verify_local_artifacts(corpus, ROOT / "transient-not-written.json"), "invalid provenance")
        for case in corpus["cases"]:
            require(not {"disposition", "expected_error", "expected_outputs"} & set(case_request(case)),
                    "expectations leaked to request")
    version = subprocess.run([str(worker), "--version"], capture_output=True, timeout=2, check=True)
    require(0 < len(version.stdout) <= 256 and version.stdout.startswith(b"OpenSSL "), "invalid worker identity")
    require(not version.stderr, "unexpected version diagnostics")
    evidence.update(backend=version.stdout.decode("ascii").strip(), source_files=original,
                    worker_sha256=hashlib.sha256(worker.read_bytes()).hexdigest(),
                    toolkit_base=git(ROOT, "rev-parse", "HEAD").decode().strip())
    modes = [("baseline", None)]
    if controls:
        modes += [("corrupt-first-output", "output"), ("corrupt-second-output", "second-output"),
                  ("accept-invalid", "accept"), ("wrong-error", "error")]
    evidence["requested_modes"] = [name for name, _ in modes]
    argv = [sys.executable] + (["-O"] if not __debug__ else []) + [
        str(Path(__file__).with_name("adapter.py")), "--worker", str(worker)]
    conformant = True
    for mode, fault in modes:
        evidence["runs"][mode] = []
        for name, corpus in corpora.items():
            evidence["active_source"] = name
            evidence["active_mode"] = mode
            report = run_batched(corpus, argv + (["--fault", fault] if fault else []))
            item = dict(source=name, **mode_result(corpus, report, fault))
            evidence["runs"][mode].append(item)
            conformant = conformant and item["matched_expected_ids"]
            save(stream, evidence)
            print(f"{mode}: {name}: {item['failed']} failures, expected {item['expected_failures']}", flush=True)
        if not conformant:
            break
    # Re-check byte identity, not merely Git state. This is not race isolation.
    source_corpora(source)
    require(source_fingerprint(ROOT) == original, "toolkit source changed during run")
    require(hashlib.sha256(worker.read_bytes()).hexdigest() == evidence["worker_sha256"], "worker changed")
    evidence["completed"] = len(evidence["runs"]) == len(modes)
    evidence["conformant"] = conformant
    evidence["source_bytes_unchanged"] = True
    evidence.pop("active_source", None)
    evidence.pop("active_mode", None)
    save(stream, evidence)
    return 0 if conformant and evidence["completed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="external pinned Wycheproof checkout")
    parser.add_argument("--worker", type=Path, required=True, help="trusted compiled native worker")
    parser.add_argument("--evidence", type=Path, required=True, help="new JSON file outside both checkouts")
    parser.add_argument("--controls", action="store_true", help="also run all four intentional-failure arms")
    args = parser.parse_args(argv)
    source, worker, output = args.source.resolve(), args.worker.resolve(), args.evidence.resolve()
    if output.is_relative_to(ROOT) or output.is_relative_to(source):
        parser.error("evidence must be outside both source checkouts")
    evidence = {"status": "EXPERIMENTAL; AS IS; NOT RELEASE APPROVED", "completed": False,
                "conformant": False, "wycheproof_revision": REVISION, "source_sha256": FILES,
                "python": platform.python_version(), "optimized": not __debug__,
                "platform": platform.platform(), "batch_size": BATCH_SIZE, "runs": {},
                "runner_limits_unchanged": True, "controls_requested": args.controls,
                "limitations": "Linux-tested only; OpenSSL default provider; no independent implementation, "
                               "constant-time, security, or universal-exhaustion claim."}
    try:
        # Never overwrite an existing result, source file, or operator artifact.
        with output.open("x", encoding="utf-8") as stream:
            save(stream, evidence)
            try:
                return execute(source, worker, evidence, stream, args.controls)
            except Exception as error:
                evidence.update(completed=False, conformant=False, infrastructure_failure=type(error).__name__)
                save(stream, evidence)
                print(f"Integration infrastructure failure: {type(error).__name__}", file=sys.stderr)
                return 3
    except OSError as error:
        print(f"Unable to create new evidence: {type(error).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
