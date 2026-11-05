<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Provenance policy

Verification requires an immutable, operator-controlled local corpus directory.
Do not verify files while another process can replace directories, symlinks, or
file contents. Path checks do not provide race-resistant filesystem isolation.
Only regular files on a responsive local filesystem are supported; network or
attacker-managed filesystems can block reads beyond the soft deadline. The
default budgets are 64 MiB per artifact, 128 MiB total, and five seconds checked
between read operations. Budget exhaustion yields PVT9204.

The default is to link to or independently regenerate public material instead
of copying it.

Every redistributed external or generated artifact must record:

- immutable source URL and revision;
- SHA-256 source digest;
- original license or permission and attribution;
- generator identity and immutable version;
- exact literal argv and parameters;
- runtime and toolchain versions;
- transformation history;
- corpus-relative path and SHA-256 digest of the raw redistributed output
  bytes, unless the record is `link-only`; and
- an explicit redistribution determination.

IETF-related material must be classified as prose, code component, data,
attachment, or another contribution under the applicable IETF Trust terms. A
file's presence in a public or IETF-related GitHub repository does not by itself
establish permission to redistribute it under this project's license.

`link-only` records have no local path or output digest. Other artifact paths
use `/` separators and must resolve beneath the directory containing the corpus
without `.` or `..` components or symbolic-link escapes. Digests cover raw file
bytes exactly as stored; no newline, encoding, archive, or JSON normalization is
performed.

The offline validator checks local output digests and record consistency. It
does not fetch sources by default and does not provide a legal opinion.
