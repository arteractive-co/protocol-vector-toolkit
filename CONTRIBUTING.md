<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing

Contributions are welcome through pull requests after the public repository is
launched. Until then, this source tree is private implementation staging.

## Developer Certificate of Origin

Every commit, including an AI-assisted commit, must include a `Signed-off-by`
trailer from an accountable human who has reviewed the complete change and has
the right to contribute it under the project license. The trailer uses the
contributor's real or otherwise accountable human identity:

```text
Signed-off-by: Your Name <your-email@example.com>
```

Git can add the trailer with `git commit -s`. Organization members and
maintainers are not exempt. The sign-off certifies the contributor's right to
submit the contribution under the repository's license; it is not a copyright
assignment and is not itself a license.

Read the unmodified certificate at <https://developercertificate.org/> before
signing off.

## Contribution requirements

Each pull request must:

1. stay within the project's generic, public scope;
2. identify the issue and acceptance criteria it addresses;
3. include tests for behavior changes;
4. update normative or explanatory documentation as needed;
5. record provenance and redistribution rights for every imported artifact;
6. avoid unpublished, confidential, proprietary, personal, credential,
   or patent-sensitive material;
7. avoid claims that functional tests prove cryptographic security,
   constant-time behavior, side-channel resistance, or mathematical totality;
8. disclose generated assistance when it materially affects provenance,
   licensing, security, or cryptographic claims; and
9. receive accountable human release review under the policy below.

## Initial release review policy

For the initial v0.1 release, the project owner may also be the primary author
and final human reviewer. A separate advisor review is required, but automated
or AI review must not be represented as independent human review.

Before release, record the owner's explicit go/no-go decision against the exact
candidate commit and distribution artifacts, with the test evidence, resolved
advisor findings, licensing/provenance and publication audits, and known
limitations. The owner must acknowledge that no independent human review was
obtained. Approval of this policy is not approval of a release candidate.

CI, DCO, audit requirements, and explicit publication authorization remain in
force. Revisit independent human review when another suitable reviewer is
available, particularly before security-sensitive extensions or stronger claims.

When rights are uncertain, link to or independently regenerate public material
instead of copying it into the repository.

## Commit and review policy

- Use focused commits with DCO sign-off on every commit.
- Pull requests are squash-merged after CI passes and review threads resolve.
- Do not rewrite another contributor's attestations.
- Do not add a `NOTICE` or third-party notice without an actual attribution
  requirement.
- JSON and other formats that cannot carry comments are covered by the
  repository-level licensing map in `LICENSES.md`.
