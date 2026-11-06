<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Optional Wycheproof ML-KEM integration

**Experimental, source-checkout-only, AS IS, without warranties.** This is an
optional downstream test adapter, not an ML-KEM implementation, cryptographic
service, Wycheproof-endorsed integration, or production-ready plugin. It was
prepared with AI assistance. It adds no Python dependency to the core toolkit
and does not change its schema, installed CLI, worker limits, or CI matrix.
The source distribution includes this directory; the installed wheel does not.

## Acceptance criteria and scope

This focused change addresses a local integration need, not an upstream issue:
run the complete pinned ML-KEM corpus through the existing NDJSON runner,
preserve source bytes/result meanings, distinguish input rejection from
infrastructure failure, and detect intentionally incorrect output and errors.

The source pin is Wycheproof commit
`d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`. All twelve file digests are in
`corpus.py`; a wrong revision, dirty tracked source checkout, changed inventory,
or mismatched file digest stops the run. Nothing is downloaded by the scripts.

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | Total |
| --- | ---: | ---: | ---: | ---: |
| Seed decapsulation | 200 | 201 | 202 | 603 |
| Seed key generation | 100 | 100 | 100 | 300 |
| Deterministic encapsulation | 261 | 265 | 269 | 795 |
| Semi-expanded-key decapsulation | 9 | 9 | 9 | 27 |
| Total | 570 | 575 | 580 | 1,725 |

There are 1,191 exact-output successes and 534 input rejections. Key generation
compares complete public and expanded private keys. Encapsulation supplies
upstream `m` through OpenSSL's **test-only** `ikme` parameter. Expanded keys
are imported directly from `dk`, without a seed substitute. Altered ciphertexts
whose expected output is an implicit-rejection secret remain success cases.
No byte reversal, replacement vectors, or recomputation of expected answers
occurs. Byte strings are opaque despite the schema's required default-order
field. Kemeleon encoding, statistical sampling, and totality are not tested.

## Run explicitly, offline

Requires Python 3.11+, Git, a C compiler, OpenSSL 3.5+ development headers and
the default provider's ML-KEM API. Only Linux has been validated for this
optional worker. Core Python/platform support is unchanged. Provider changes
may produce an unsupported infrastructure error rather than a conformance
result; do not weaken error classification to force a pass.

Obtain a separate, operator-controlled Wycheproof checkout at the exact commit
above. Keep it immutable during testing. The adapter never imports executable
code from that checkout. From this toolkit's source root, use an external work
directory for the binary and evidence:

```sh
wycheproof_work=$(mktemp -d)
cc -std=c11 -Wall -Wextra -Werror -O2 -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
  integrations/wycheproof/openssl_worker.c -o "$wycheproof_work/openssl_worker" -lcrypto
cc -std=c11 -Wall -Wextra -Werror -O2 integrations/wycheproof/native_checks.c \
  -o "$wycheproof_work/native_checks" -lcrypto
"$wycheproof_work/native_checks"
python3 integrations/wycheproof/run.py \
  --source /absolute/path/to/pinned-wycheproof \
  --worker "$wycheproof_work/openssl_worker" \
  --evidence "$wycheproof_work/baseline.json"
python3 integrations/wycheproof/run.py \
  --source /absolute/path/to/pinned-wycheproof \
  --worker "$wycheproof_work/openssl_worker" \
  --controls --evidence "$wycheproof_work/controls.json"
```

Run again with `python3 -O` and a **new** evidence filename for optimized-path
verification; the adapter then also runs under `-O`. Existing evidence is never
overwritten. Evidence must be outside both checkouts and records source-file
and worker hashes, base commit, environment, scope, case IDs, control outcomes
and completion status. It contains no vector bytes or native stderr. The
base commit alone does not identify uncommitted work; the file hashes do.
Only `completed: true` plus `conformant: true` denotes a fully successful
requested run. Partial evidence is not success.

Exit status is 0 for the requested checks passing, 1 for a baseline/control
mismatch, and 3 for evidence, setup, worker, protocol or runtime failure.
Argument errors use argparse's exit 2. Missing native prerequisites do not
silently skip or count as expected input rejections.

With `--controls`, all cases are exercised in all five arms:

| Arm | Expected failure IDs |
| --- | --- |
| Baseline | None |
| Corrupt first output byte | All 1,191 successful cases |
| Corrupt second output byte | All 1,191 successful cases |
| Accept invalid input | All 534 rejected-input cases |
| Wrong error code | All 534 rejected-input cases |

The exact failure IDs, not just their count, must match. The native worker maps
only known provider invalid-key/length/seed errors to input rejection. Empty
error queues count only after the backend itself rejects a wrong ciphertext
length. Unknown/internal errors, crashes, setup failures and malformed native
framing are infrastructure failures. The wrapper does not pre-reject crypto
inputs in a way that could mask the backend accepting an invalid input.

## Batching and trust boundary

Large byte-exact failure diagnostics can exhaust the existing 1 MiB report cap.
For example, corrupting 100 ML-KEM-1024 expanded private keys exceeded that cap
in the initial experiment; the runner safely stopped, not falsely passed.
This integration uses at most sixteen cases per session, verifies complete
case ordering, strips source comments/flags from requests, and discards bulky
byte dumps after each batch. Source metadata stay in the local parent corpus.
No runner limit
is increased and no case is skipped. This batch size is scoped to these pins.

The adapter and compiled worker are **trusted executable code, not a sandbox**.
Use public test keys only, in an environment without sensitive files. The native
worker has bounded frame sizes and a per-call timeout; the runner retains its
existing process-group/job controls. The supplied binary and OpenSSL libraries
must be trusted. File hashes and re-checks do not isolate concurrent writers.

The ordinary dependency-free tests include original synthetic converter,
batch, error-boundary and evidence tests. They do not compile C or fetch vectors.
Full crypto coverage requires the explicit commands above. No native CI job is
added in this change. Future CI should provision and pin the optional native
toolchain explicitly; an unavailable dependency must fail that job, not skip it.

## Provenance, licensing and non-claims

Only original Arteractive integration code and synthetic mapping fixtures are
included. No upstream corpus, transformed corpus, native binaries or private
research is redistributed. Source metadata retain filename, tcId, flags and
group attribution. Conversion occurs in memory and provenance links to pinned
upstream files. Wycheproof's repository LICENSE is Apache-2.0, but any future
redistribution of vectors requires a separate attribution/notice review.

Wycheproof requests advance coordination for substantial contributions, review
of submissions, and use of `vectorgen` for vector changes. This change edits no
upstream vector and requires no upstream PR. Disclose newly suspected security
flaws privately to affected maintainers before publishing a regression test.

Functional results do not prove cryptographic security, constant-time execution,
memory safety, absence of side channels, or correctness beyond represented
cases. OpenSSL versions are not independent cryptographic implementations.
Independent implementation and native macOS/Windows coverage, CI provisioning,
advisor review and owner publication approval are separate gates. This work
does not amend existing release approvals or artifact hashes.

References:

- https://github.com/C2SP/wycheproof/tree/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9
- https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/CONTRIBUTING.md
- https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/LICENSE
- https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/
- https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/
