<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release readiness — 2026-11-05

Status: **development checkpoint, not approved for release**.

## Verified in the current environment

- Linux, Python 3.12: local dependency-free tests pass; optional schema tests
  and Windows-only tests skip locally. Exact candidate counts are in CI logs.
- Provisioned CI runs pinned schema parity tests without schema skips and runs
  the full suite in optimized (`python -O`) mode.
- Native CI verified Linux Python 3.11–3.15 and macOS Python 3.11/3.15 before the
  Windows addition. Windows Python 3.11/3.15 verified the new Job transport,
  including cancellation, descendants, blocked input, argv, and setup denial.
  Re-run the complete matrix on the final candidate; prior green commits do not
  establish final-candidate readiness.
- Both toy profiles, expected algorithm errors, and an included total-decoding
  case complete through the separate-process adapter and installed CLI.
- Hostile framing, wrong/duplicate IDs, partial/trailing output, premature and
  nonzero exit, blocked input, flood limits, per-exchange/session deadlines,
  mismatch reports, literal argv, and invalid-corpus launch prevention are tested.
- Cooperating process-group descendants are terminated after timeout,
  cancellation, and successful completion. Escaped descendants are not contained.
- Strict bounded corpus JSON, malformed-value diagnostics, terminal-newline
  regex rejection, artifact byte limits, and symlink-loop rejection are tested.
- Two offline wheel builds using setuptools 84.2.1 and a fixed
  SOURCE_DATE_EPOCH produce identical bytes. Clean local wheel installation and
  source archive inclusion smoke checks pass. This is not a hermetic-build claim.
- The contributor approved `A Taylor <dev@arteractive.co>` for staged commits.
  An exact `.mailmap` alias resolves GitHub connector authorship to that identity;
  the DCO check still requires an existing matching human sign-off trailer.
  Do not manufacture an attestation or bypass the required check.

## Outstanding release gates

1. Require the exact pinned schema-test dependencies and
   `PVT_REQUIRE_SCHEMA_VALIDATOR=1` on the final candidate. Skips do not constitute
   parity evidence; the provisioned CI job supplies this check.
2. Retain Windows Job Object review and native lifecycle tests. The trusted gate
   must never launch an adapter before successful Job assignment.
3. Require native Linux/macOS/Windows tests at the Python boundaries and Linux
   tests across Python 3.11–3.15 on the final publication candidate.
4. Review first-mismatch diagnostics and their field-path/byte-offset tests.
   Current reports include expected/observed values on mismatch; corpora must
   not contain secrets. These diagnostics are subject to the report byte cap.
5. Complete advisor re-review and explicit owner release review, including
   provenance/licensing, publication boundaries, threat model, and final code.
   For the initial v0.1 release, A Taylor (`badandyomega`) may be both primary
   author and final human approver. Record the exact candidate commit/artifact
   digests, evidence, known limitations, and explicit go/no-go. Acknowledge the
   absence of independent human review; advisor review does not supply it.
   This policy change does not itself approve publication.
6. Review and DCO-sign the actual publication candidate. Enable DCO and the
   required CI checks in repository rules; workflow presence is not enforcement.
7. Audit a fresh publication export and all intended distribution surfaces.
   Keep private history, internal plans, credentials, generated build caches,
   and unrelated research out of that export.

## Verification commands

```console
PYTHONPATH=src python -m unittest discover -s tests -v
PVT_REQUIRE_SCHEMA_VALIDATOR=1 PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -O -m unittest discover -s tests -v
python tools/check_dco.py
PYTHONPATH=src python -m protocol_vectors report examples/little-endian-fields/vectors.json -- python examples/little-endian-fields/adapter.py
```

The adapter is trusted executable code, not a sandboxed plugin. Corpus
directories must be operator-controlled and immutable while checking local
artifacts. Read the security model before running third-party executables.
