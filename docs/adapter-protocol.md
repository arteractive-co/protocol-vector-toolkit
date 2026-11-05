<!-- SPDX-FileCopyrightText: 2026 Arteractive LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Adapter protocol: design constraints

## Draft-01 message layer and bounded transports

The protocol identifier is
`org.arteractive.protocol-vectors.adapter/draft-01`. Messages are JSON objects
encoded as strict UTF-8, terminated by one LF, with no CR or embedded literal
LF. The maximum encoded size, including LF, is 1,048,576 bytes. Duplicate
object keys, non-finite numbers, and lone Unicode surrogates are rejected.

The adapter's ready response is exactly:

```json
{"type":"ready","protocol":"org.arteractive.protocol-vectors.adapter/draft-01"}
```

A case request contains `type: "case"`, `id`, `profile`, `inputs`, and optional
`deterministic_choices` and `extensions` copied from the validated corpus.
Expected outputs, expected errors, and expected dispositions are never sent.

The response is exactly one of these shapes:

```json
{"type":"result","id":"case-id","status":"success","outputs":{}}
{"type":"result","id":"case-id","status":"error","code":"algorithm.error"}
```

The ID must match the outstanding request. Unknown response fields are errors.
Success outputs must match the complete typed `expected_outputs` object;
object-key order is irrelevant, but JSON types and byte spelling are exact.
An expected-error case passes only for the specified algorithm error code.
Malformed messages, process failures, and timeouts must never count as an
expected algorithm error. Total-decoding cases require a success response.

The runner sends a `hello` object containing `type`, `protocol`, `algorithm`,
and the corpus `profiles` before waiting for `ready`. The adapter must support
the supplied algorithm and profiles or fail the session; there is no partial
profile negotiation in this draft. Cases are exchanged in corpus order, one
request then one result. The runner finally sends exactly
`{"type":"shutdown"}`, closes stdin, and requires EOF on stdout/stderr and
exit status zero. Additional stdout is a protocol violation. Stderr is counted
and discarded, never interpreted as a result or reflected into reports.

The POSIX transport uses a new session/process group, nonblocking pipes, and
an absolute 10-second session deadline and a two-second deadline per exchange
(including handshake/shutdown). Each input, stdout, and stderr stream
has an 8,388,608-byte limit. Message sizes are additionally bounded as above.
Corpora are limited to 8,388,608 raw bytes and JSON depth 64; duplicate keys,
nonfinite numbers, and invalid Unicode are rejected. Reports are limited to
1,048,576 bytes using a conservative budget. `report` is a JSON-reporting alias
for `run`. `provenance` validates the corpus and local digests offline.

The runner forwards only PATH, LANG, LC_ALL, and TZ environment values. Python
startup overrides, credential variables, and the remainder of the environment
are not forwarded. Executables and working-directory files remain trusted.
The runner kills remaining members of the process group on every exit path
and waits for the adapter leader. Adapters are trusted executables: they must
not escape the process group. This is not a sandbox or an operating-system
resource quota. Windows uses a kill-on-close Job Object, a trusted isolated gate
that starts the adapter only after Job assignment, and bounded pipe-worker queues.
It shares the protocol, deadlines, byte limits, and result comparison rules above.
Windows additionally forwards SYSTEMROOT, WINDIR, TEMP, and TMP; `.bat`/`.cmd`
adapters are rejected. See the security model for executable trust and quoting
limitations. Assignment failure never falls back to uncontrolled execution.

CLI exit codes are 0 for conformance, 1 for output/disposition mismatch, 2 for
invalid corpus/provenance, and 3 for invocation, transport, or protocol failure.
Reports contain case IDs, pass/fail, and the first mismatch's code, field path,
expected/observed values, and byte offset where applicable, but no adapter stderr.
Do not include secrets in corpora or adapter outputs. The session validates IDs
and rejects extra bytes already observed at exchange boundaries; pipes do not
prove the time at which a peer emitted a byte. Adapters remain trusted code.

The NDJSON adapter protocol is not frozen. Its implementation must not be
released until positive and hostile tests cover all lifecycle paths on each
supported operating system and advisor review plus accountable owner release
review are complete under CONTRIBUTING.md. Initial owner review need not be
independent of the primary author.

The command-line shape is normative for the runner interface:

```text
protocol-vectors run VECTOR_FILE -- ADAPTER [ARG ...]
```

Everything after `--` is literal argv. It is never shell syntax. A vector file
cannot nominate or modify the adapter command.

The first protocol version defines strict UTF-8 NDJSON, unique case IDs,
maximum message and stream sizes, deterministic diagnostic ordering, and
termination of the controlled POSIX process group or Windows Job Object.
POSIX descendants that deliberately escape their process group are not
contained; adapters must remain within that group. These controls do not
establish an unrestricted complete-process-tree guarantee or a sandbox.
