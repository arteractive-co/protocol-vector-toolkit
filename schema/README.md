<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Vector-set schema

`vector-set-draft-01.schema.json` is normative for the structural and syntactic
portion of the `draft-01` interchange format.

The semantic and cross-field rules in [`docs/data-model.md`](../docs/data-model.md)
are also normative. The Python validator is a non-normative reference
implementation. Shared fixtures must exercise the overlapping behavior of the
schema and reference validator so that a release fails if they drift.

The `draft-01` label intentionally makes no permanent compatibility promise.
