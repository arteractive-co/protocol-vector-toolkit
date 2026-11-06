<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reproducible release-candidate artifacts

Build only from a clean, audited source export. Do not include Git history,
untracked files, build caches, credentials, or private material. A successful
build is not permission to publish. Current package metadata is `0.1.0`;
preparing artifacts with that version is not approval to release them.

## Provisioning and scope

The build environment must already contain Python and `setuptools==84.2.1`.
Builds below use that backend directly, without downloading build dependencies.
Record the Python, setuptools, and zlib versions, the exact source inventory,
and one fixed `SOURCE_DATE_EPOCH` with the artifact hashes. The same toolchain
and inputs are required for byte-identical results; this is not a hermetic or
cross-toolchain reproducibility guarantee.

Runtime execution from source requires only Python. Schema parity tests
separately require the exact versions in `requirements-test.lock` and
`PVT_REQUIRE_SCHEMA_VALIDATOR=1`; a skipped parity test is not passing evidence.

## Build and normalize

From the clean export, create empty output directories outside it. Set
`SOURCE_DATE_EPOCH` to the recorded candidate epoch before building. For example,
with `../build-artifacts/raw` and `../build-artifacts/final` already created:

```console
python -c "import importlib.metadata; assert importlib.metadata.version('setuptools') == '84.2.1'; import setuptools.build_meta as b; b.build_wheel('../build-artifacts/final'); b.build_sdist('../build-artifacts/raw')"
python tools/normalize_sdist.py ../build-artifacts/raw/protocol_vector_toolkit-0.1.0.tar.gz ../build-artifacts/final/protocol_vector_toolkit-0.1.0.tar.gz --epoch "$SOURCE_DATE_EPOCH"
```

The second command uses POSIX environment-variable syntax; on PowerShell use
`--epoch $env:SOURCE_DATE_EPOCH`. The paths must use the version recorded in
the candidate metadata if it changes.

The backend's raw sdist retains local timestamps and ownership metadata, so
it is not the reproducible distribution artifact. The normalization step sorts
members and fixes gzip timestamp/name, tar timestamps, owner fields, and modes
(directories `0755`, regular files `0644`). It accepts only regular files and
directories under one root and never extracts members. It refuses overwriting
an existing destination. Use it only on the trusted, locally built sdist; it
is not a general-purpose archive sanitizer. The current project has no executable
source files that require preservation of an executable mode.

## Verify before distribution

1. Build in two separate clean exports with the same recorded epoch/toolchain,
   different source mtimes, and separated build times.
2. Require identical SHA-256 digests for both wheels and both normalized sdists.
3. Compare every source file in the sdist with the audited export inventory;
   allow only expected generated packaging metadata.
4. Inspect archive names, contents, licenses, and installed package metadata.
   Reject private files, history, caches, unexpected dependencies, or unsafe paths.
5. Install the wheel into a fresh environment without dependencies or network
   access; exercise the CLI, packaged schema, and toy adapter outside the source
   tree. Rebuild from the normalized sdist and require the same wheel bytes.
6. Retain exact-candidate native CI, advisor review, required-check enforcement,
   DCO sign-off, and explicit owner approval as separate release gates.
