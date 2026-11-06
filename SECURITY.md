<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security policy

## Adopter notice

The toolkit and its original documentation, schemas, examples, and vectors are
provided AS IS under [Apache-2.0](LICENSE), without warranties or conditions,
subject to applicable law and separate written agreements. See the
[README adopter notice](README.md#important-as-is-no-warranty) and LICENSE
Sections 7–9 for the disclaimer and limitation of liability.

Testing and review are not security certification and do not guarantee
correctness, interoperability, production suitability, or freedom from
vulnerabilities. Evaluate the exact version and adapters independently before
use. No guaranteed support, maintenance, or fix commitment is offered unless
separately agreed in writing.

## Reporting vulnerabilities

Please report suspected vulnerabilities privately to
<dev@arteractive.co>. Do not open a public issue for a vulnerability that could
put users or downstream projects at risk.

Include the affected version or commit, a minimal reproduction, the expected
impact, and any suggested mitigation. We aim to acknowledge reports within
five business days. An acknowledgment is not a promise of a fix timeline.

The toolkit treats vector files as untrusted data. A user-supplied adapter is
trusted executable code and is not sandboxed. Security reports should clearly
state which side of that boundary is involved.
