<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Interoperability checklist

- [ ] Public algorithm and profile versions are exact.
- [ ] Input, output, and field lengths are explicit.
- [ ] Field order, concatenation, and byte order are explicit.
- [ ] Integers and byte strings use canonical lexical forms.
- [ ] Deterministic test-only choices are separated from production randomness.
- [ ] Boundary, malformed, expected-error, and represented total-decoding cases
      are included where applicable.
- [ ] An independent implementation reproduces byte-exact outputs.
- [ ] Diagnostics identify case, path, and byte offset where applicable.
- [ ] Source revisions, digests, generation steps, and reuse rights are recorded.
- [ ] Test claims do not exceed the represented behavior.
