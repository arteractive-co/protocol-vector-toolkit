# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Bounded adapter transport. This is process control, not a sandbox."""

from __future__ import annotations

import os
import json
import selectors
import signal
import subprocess
import time
from typing import Any

from .adapter_protocol import (
    MAX_MESSAGE_BYTES, PROTOCOL, ProtocolError, case_request, compare_result,
    decode_message, encode_message, validate_ready,
    mismatch_diagnostic,
)


class RunnerError(RuntimeError):
    """Transport or process-control failure, distinct from nonconformance."""


def run_adapter(document: dict[str, Any], arguments: list[str], *,
                timeout: float = 10.0, stream_limit: int = 8_388_608,
                case_timeout: float = 2.0, report_limit: int = 1_048_576) -> dict[str, Any]:
    """Run a validated corpus; use one absolute deadline for the entire session.

    Unsupported platforms fail before launch. Callers must validate corpus and
    provenance first. No environment or filesystem sandbox is established.
    """
    argv = require_adapter_argv(arguments)
    if os.name not in ("posix", "nt"):
        raise RunnerError("process-tree control is not implemented on this platform")
    if (not 0 < timeout <= 300 or not 1 <= stream_limit <= 67_108_864
            or not 0 < case_timeout <= 300 or not 256 <= report_limit <= 8_388_608):
        raise ValueError("invalid runner limits")
    # Preflight all requests before executing anything; cap total input too.
    requests = [encode_message({"type": "hello", "protocol": PROTOCOL,
                                "algorithm": document["algorithm"],
                                "profiles": document["profiles"]})]
    total_input = len(requests[0])
    if total_input > stream_limit:
        raise RunnerError("input stream exceeds byte limit")
    for case in document["cases"]:
        request = encode_message(case_request(case))
        total_input += len(request)
        if total_input > stream_limit:
            raise RunnerError("input stream exceeds byte limit")
        requests.append(request)
    shutdown = encode_message({"type": "shutdown"})
    if total_input + len(shutdown) > stream_limit:
        raise RunnerError("input stream exceeds byte limit")
    requests.append(shutdown)
    if os.name == "nt":
        from .windows_runner import run_windows_adapter
        return run_windows_adapter(document, argv, requests, timeout=timeout,
                                   case_timeout=case_timeout, stream_limit=stream_limit,
                                   report_limit=report_limit)
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   shell=False, close_fds=True,
                                   env={key: os.environ[key] for key in
                                        ("PATH", "LANG", "LC_ALL", "TZ") if key in os.environ})
    except OSError as exc:
        selector.close()
        raise RunnerError("unable to launch adapter") from exc
    received = {"stdout": 0, "stderr": 0}
    buffer = bytearray()
    lines: list[bytes] = []
    eof: set[str] = set()
    try:
        for name in ("stdin", "stdout", "stderr"):
            pipe = getattr(process, name)
            os.set_blocking(pipe.fileno(), False)
            if name != "stdin":
                selector.register(pipe, selectors.EVENT_READ, name)

        def pump(pending: bytes = b"", *, response: bool = False, finish: bool = False):
            position = 0
            exchange_deadline = min(deadline, time.monotonic() + case_timeout)
            if pending:
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            while position < len(pending) or (response and not lines) or (finish and len(eof) < 2):
                remaining = exchange_deadline - time.monotonic()
                if remaining <= 0:
                    raise RunnerError("adapter session timed out")
                for key, _ in selector.select(min(remaining, 0.1)):
                    name = key.data
                    if name == "stdin":
                        try:
                            count = os.write(key.fd, pending[position:position + 65536])
                        except BrokenPipeError as exc:
                            raise RunnerError("adapter closed its input") from exc
                        position += count
                        if position == len(pending):
                            selector.unregister(process.stdin)
                        continue
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        eof.add(name)
                        continue
                    received[name] += len(chunk)
                    if received[name] > stream_limit:
                        raise RunnerError(f"adapter {name} exceeds byte limit")
                    if name == "stdout":
                        buffer.extend(chunk)
                        while b"\n" in buffer:
                            line, _, rest = buffer.partition(b"\n")
                            buffer[:] = rest
                            if len(line) + 1 > MAX_MESSAGE_BYTES:
                                raise ProtocolError("message exceeds byte limit")
                            lines.append(bytes(line) + b"\n")
                        if len(buffer) >= MAX_MESSAGE_BYTES:
                            raise ProtocolError("message exceeds byte limit")
                        if len(lines) > 1:
                            raise ProtocolError("unsolicited or duplicate adapter response")
                if response and "stdout" in eof and not lines:
                    raise RunnerError("adapter exited before its response")
            if response:
                if buffer:
                    raise ProtocolError("unsolicited partial adapter response")
                return decode_message(lines.pop(0))
            return None

        validate_ready(pump(requests[0], response=True))
        results = []
        report_bytes = 256  # reserved fixed report envelope
        for index, case in enumerate(document["cases"]):
            response = pump(requests[index + 1], response=True)
            passed = compare_result(case, response)
            item = {"id": case["id"], "passed": passed}
            if not passed:
                item["diagnostic"] = mismatch_diagnostic(case, response)
            report_bytes += len(json.dumps(item, separators=(",", ":")).encode("utf-8")) + 1
            if report_bytes > report_limit:
                raise RunnerError("report exceeds byte limit")
            results.append(item)
        pump(requests[-1])
        process.stdin.close()
        pump(finish=True)
        if buffer or lines:
            raise ProtocolError("unexpected output after final result")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RunnerError("adapter session timed out")
        try:
            status = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise RunnerError("adapter did not exit") from exc
        if status != 0:
            raise RunnerError("adapter exited unsuccessfully")
        return {"protocol": PROTOCOL, "cases": results,
                "passed": all(item["passed"] for item in results)}
    finally:
        # Also kill descendants after a successful parent exit. Adapters are
        # trusted code and must not escape the session/process group.
        # Reap an exited leader before signalling the group: macOS may return
        # EPERM when the only remaining group member is a zombie leader.
        process.poll()
        cleanup_error = None
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            cleanup_error = exc
            # Still reap our direct child when group signalling fails. Report
            # lost group control; do not claim that descendant cleanup worked.
            if process.poll() is None:
                try:
                    process.kill()
                except OSError as kill_error:
                    cleanup_error = kill_error
        finally:
            try:
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired) as wait_error:
                cleanup_error = wait_error
            finally:
                selector.close()
                for pipe in (process.stdin, process.stdout, process.stderr):
                    pipe.close()
        if cleanup_error is not None:
            raise RunnerError("adapter process-group cleanup failed") from cleanup_error


def require_adapter_argv(arguments: list[str]) -> tuple[str, ...]:
    """Return a literal argv tuple or reject an empty adapter command.

    No shell parsing, quoting, interpolation, or vector-file lookup occurs here.
    """

    if not arguments or not arguments[0]:
        raise ValueError("adapter command is required after --")
    if "\x00" in "".join(arguments):
        raise ValueError("adapter arguments cannot contain NUL")
    return tuple(arguments)
