<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Corpus authoring guide

1. Start with the `draft-01` format identifier and a canonical corpus ID.
2. Link the algorithm to a public, authoritative HTTPS reference.
3. Declare every profile before a case refers to it.
4. Encode bytes and integers canonically; never use JSON numbers for protocol
   integers.
5. State byte order explicitly when a value overrides the corpus default.
6. Separate deterministic test choices from ordinary inputs.
7. Use `expected-error` only for an included, specific error outcome.
8. Use `total-decoding` only for included inputs that must decode to the stated
   output; do not generalize the claim beyond the corpus.
9. Record provenance before copying or generating an artifact.
10. Run the validator and review every diagnostic before submission.
