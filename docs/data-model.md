<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Normative data model: draft-01

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, and **SHOULD NOT**
in this document describe requirements of this draft format.

## Authority

The JSON Schema is normative for structure and lexical syntax. This document is
normative for semantic and cross-field constraints. The Python implementation
is a reference implementation, not the specification.

## Canonical values

- Byte strings MUST be lowercase hexadecimal with exactly two characters per
  byte and no prefix, whitespace, separators, or omitted leading zeroes.
- A byte value's `length` MUST equal half the hexadecimal character count.
- Byte `length` metadata MUST use a JSON integer literal, without a decimal
  point or exponent. JSON Schema's mathematical-integer rule alone permits
  `2.0`; this additional semantic rule intentionally rejects that spelling.
- Unsigned integers MUST be decimal strings matching `0` or a nonzero decimal
  digit followed by zero or more decimal digits. JSON numbers, signs, and
  leading zeroes are forbidden.
- Bounded structural metadata under `profiles[].parameters` MAY use JSON
  numbers. Such metadata is not an encoded protocol integer and MUST NOT be
  used where arbitrary precision or byte-exact integer representation matters.
- Identifiers MUST match the schema's lowercase identifier grammar.
- Profile, case, and provenance artifact identifiers MUST be unique within
  their respective collections.
- A case's `profile` MUST identify a declared profile.
- If `encoding.default_byte_order` is `mixed`, every `bytes` value MUST declare
  its own `byte_order`.

## Dispositions

- `success` and `total-decoding` cases MUST contain `expected_outputs` and MUST
  NOT contain `expected_error`.
- `expected-error` cases MUST contain `expected_error.code` and MUST NOT contain
  `expected_outputs`.
- `total-decoding` means that the represented input is expected to produce the
  stated output rather than an error. It does not prove totality over inputs not
  included in the corpus.

## Extensions

Extension keys MUST be HTTPS URIs or reverse-DNS namespaces. Readers MUST
preserve unknown extension values and the generic validator MUST ignore their
contents. Unknown fields in the core data model MUST fail validation during the
draft phase.

## Provenance

An `external` artifact MUST record an immutable source URL or URL plus immutable
revision, a SHA-256 digest of the retrieved source, attribution, the applicable
license or permission, and a redistribution determination.

A `generated` artifact MUST record generator metadata sufficient to reproduce
the output, including the generator identity and version, literal argument
vector, runtime/toolchain version, and transformations. Generator metadata is
closed in draft-01 to `name`, `version`, `argv`, `runtime`, and optional
`toolchain`; the first four fields are required.

An artifact marked `link-only` MUST NOT contain `path` or `output_sha256` and
MUST NOT be redistributed in the corpus package. Every other artifact record
MUST contain a corpus-relative POSIX-style `path` and the SHA-256 digest of the
raw bytes stored at that path.

Artifact paths MUST use `/` separators, MUST NOT be absolute, MUST NOT contain
`.` or `..` components, and MUST resolve inside the corpus directory without a
symbolic-link escape. Offline verification hashes the raw file bytes without
newline, encoding, archive, or JSON normalization. The validator confirms
record and digest consistency; it cannot determine legal sufficiency.

Local verification requires an immutable corpus directory controlled by the
operator during the entire check. Path resolution is not safe against a
concurrent filesystem writer. This is not a sandbox for attacker-controlled
mounts or directories. The default budgets are 64 MiB per artifact, 128 MiB
across artifacts, and five seconds checked between reads. Local filesystem
reads must return promptly; this deadline cannot interrupt a hung filesystem.
