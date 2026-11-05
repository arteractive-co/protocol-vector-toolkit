<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Protocol Vector Toolkit

Protocol Vector Toolkit is a language-neutral framework for describing,
validating, and comparing byte-exact protocol test vectors.

The project is intentionally generic. It provides measurement, provenance,
and conformance machinery; it does not claim that a vector corpus proves
cryptographic security, constant-time execution, absence of side channels, or
conformance beyond the represented cases.

## Important: AS IS, no warranty

All original project code, documentation, schemas, examples, and test vectors
are provided **AS IS, without warranties or conditions of any kind**, express
or implied, under the [Apache License 2.0](LICENSE), particularly Sections 7–9.
This includes no warranty of correctness, security, interoperability,
merchantability, non-infringement, or fitness for a particular purpose, except
where applicable law requires otherwise or a separate written agreement applies.
This summary does not modify the license or its limitation of liability.

Tests and reviews provide evidence only for the cases, versions, platforms,
and properties actually checked. Passing them is not a security certification
or a guarantee that the toolkit, an adapter, or a downstream implementation is
correct, safe, or suitable for production. Documentation and vectors may contain
errors. Adapters are trusted executable code, not sandboxed plugins.

Before adoption, independently validate results and assess the software and
adapters for your environment and intended use. Read the
[security model](docs/security-model.md) and [known release limitations](docs/release-readiness.md).
Support, continued maintenance, and fixes are not guaranteed unless separately
agreed in writing. Report suspected problems through [SECURITY.md](SECURITY.md).

## Current status

This repository is an early `draft-01` staging implementation. The currently
working surface is deliberately small:

- a normative JSON Schema for vector-corpus structure and syntax;
- normative semantic rules that supplement the schema;
- a dependency-free Python reference validator;
- stable validation diagnostics;
- positive and negative conformance fixtures;
- an initial, non-cryptographic little-endian toy corpus.

The draft NDJSON runner and toy adapter use POSIX process groups or a Windows
kill-on-close Job Object. Native lifecycle tests exercise both transports.
Final candidate verification, advisor review, and explicit owner release approval
remain release blockers. Initial owner review may be by the primary author;
it is not independent human review. See CONTRIBUTING.md.

## Try it from source

Python 3.11 or newer is required. No runtime dependency installation is needed.

```console
PYTHONPATH=src python -m protocol_vectors validate \
  examples/little-endian-fields/vectors.json

PYTHONPATH=src python -m unittest discover -s tests -v

PYTHONPATH=src python -m protocol_vectors run \
  examples/little-endian-fields/vectors.json -- \
  python examples/little-endian-fields/adapter.py
```

## Trust boundaries

- Vector files are untrusted data and never select executable commands.
- Adapter commands are supplied by the operator and executed as literal
  argument vectors without a shell.
- Algorithm-specific mathematics belongs in separately reviewed adapters or
  plugins, not in executable expressions inside a corpus.
- Third-party and IETF-derived artifacts default to links, digests, or
  independent regeneration unless redistribution rights are explicitly
  documented.

See [the security model](docs/security-model.md),
[the provenance policy](docs/provenance.md), and
[the contribution guide](CONTRIBUTING.md).

## License

Original project material is licensed under the Apache License 2.0.
Copyright 2026 Arteractive LLC.
