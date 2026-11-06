<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security model

## Trust boundaries

Vector files are untrusted data. The core validator never evaluates expressions
or executes commands from a vector file. Algorithm-specific validation belongs
in separately reviewed code.

An operator-supplied adapter is trusted executable code. The runner
constrains time and pipe byte counts, but it is not an operating-system sandbox.
It inherits permissions, working directory, and filesystem access, but only
PATH, LANG, LC_ALL, and TZ from the environment. Credential variables and Python
startup/path overrides are not forwarded. Adapters still have the operator's
filesystem access, so this does not isolate credential files. Run from an
environment without sensitive files. POSIX adapters must not escape their process group.
Windows additionally forwards SYSTEMROOT, WINDIR, TEMP, and TMP. It uses an unnamed,
noninheritable kill-on-close Job Object without breakaway permission. A fixed
trusted Python gate runs with `-I -S` and launches the adapter only after successful
Job assignment. Package files and the Python runtime must be trusted and immutable.
Job assignment failure is fatal, including under incompatible hosting jobs.
Windows batch-file adapters (`.bat` and `.cmd`) are rejected because Windows may
invoke them through a shell even with `shell=False`. Supply a native executable;
Python scripts require an explicit Python executable. Arguments use Python's
Windows CRT-compatible command-line quoting. This is not a guarantee for programs
with custom command-line parsers. Native Windows release verification is required.

## Required runner behavior

- Accept the adapter only as literal argv following `--`.
- Never invoke a shell.
- Start the adapter in an isolated process group or operating-system job.
- On timeout, protocol violation, or cancellation, terminate the controlled
  process group and wait for the adapter leader. Descendants that deliberately
  escape the group are outside this boundary; this limitation blocks a stronger
  complete-tree guarantee.
- Fail before launch if the platform cannot establish the required process
  control boundary.
- Exchange strict UTF-8 NDJSON with deterministic limits and diagnostics.
- Operators MUST NOT put secrets in arguments or the forwarded environment
  values. The runner uses a fixed environment allowlist, not a credential vault.

Linux, macOS, and Windows are first-class targets. Platform-specific process
control may differ internally, but observable result and diagnostic codes must
remain stable.

## Non-claims

Provenance verification assumes an operator-controlled, immutable local corpus
directory and regular files that return promptly. Concurrent filesystem writers
can invalidate resolve/stat/open confinement checks. Network or attacker-managed
filesystems are outside the supported boundary. The five-second verification
budget is checked between reads; it cannot interrupt a stuck filesystem call.

Functional conformance does not establish cryptographic security, production
randomness, constant-time execution, side-channel resistance, or mathematical
totality.
