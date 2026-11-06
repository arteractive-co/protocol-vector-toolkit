# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Windows Job Object transport. Process control, not an executable sandbox."""

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time

from .adapter_protocol import (MAX_MESSAGE_BYTES, PROTOCOL, ProtocolError,
                               compare_result, decode_message,
                               mismatch_diagnostic, validate_ready)
from .runner import RunnerError


class WindowsJob:
    """Unnamed, non-inheritable, kill-on-close job with no breakaway flag."""

    def __init__(self):
        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong),
                        ("PerJobUserTimeLimit", ctypes.c_longlong),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class Counters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in
                        ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                         "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", Counters),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = args, result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.api.CloseHandle(self.handle)
            self.handle = None
            raise error

    def assign(self, pid):
        handle = self.api.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.api.AssignProcessToJobObject(self.handle, handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.api.CloseHandle(handle)

    def close(self):
        if self.handle:
            handle, self.handle = self.handle, None
            # Explicit termination plus kill-on-close; both failures are surfaced.
            terminated = self.api.TerminateJobObject(handle, 1)
            error = ctypes.get_last_error()
            closed = self.api.CloseHandle(handle)
            if not terminated or not closed:
                raise ctypes.WinError(error if not terminated else ctypes.get_last_error())


def run_windows_adapter(document, argv, requests, *, timeout, case_timeout,
                        stream_limit, report_limit):
    executable = shutil.which(argv[0])
    if not executable or Path(executable).suffix.lower() in (".bat", ".cmd"):
        raise RunnerError("Windows adapter must be a native executable, not a batch file")
    argv = (os.path.abspath(executable), *argv[1:])
    deadline = time.monotonic() + timeout
    process = None
    job = None
    workers = []
    stop = threading.Event()
    events = queue.Queue(maxsize=32)

    def emit(event):
        while not stop.is_set():
            try:
                events.put(event, timeout=0.05)
                return
            except queue.Full:
                pass

    def reader(name):
        try:
            while not stop.is_set():
                chunk = getattr(process, name).read(65536)
                emit((name, chunk))
                if not chunk:
                    return
        except OSError as exc:
            emit(("error", exc))

    def writer(data):
        try:
            view = memoryview(data)
            while view and not stop.is_set():
                count = process.stdin.write(view[:65536])
                if not count:
                    raise BrokenPipeError("zero-byte adapter write")
                view = view[count:]
            emit(("written", None))
        except OSError as exc:
            emit(("error", exc))

    def start(target, *args):
        worker = threading.Thread(target=target, args=args, daemon=True)
        try:
            worker.start()
        except RuntimeError as exc:
            raise RunnerError("unable to start adapter pipe worker") from exc
        workers.append(worker)
        return worker

    try:
        try:
            job = WindowsJob()
            environment = {key: os.environ[key] for key in
                           ("PATH", "LANG", "LC_ALL", "TZ", "SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                           if key in os.environ}
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", str(Path(__file__).with_name("windows_gate.py")), *argv],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                shell=False, close_fds=True, bufsize=0, env=environment)
            job.assign(process.pid)
            # Only trusted fixed gate code ran before assignment. The gate reads
            # exactly one byte, so no protocol request is consumed by its parser.
            if process.stdin.write(b"G") != 1:
                raise OSError("unable to release adapter gate")
            process.stdin.flush()
        except OSError as exc:
            raise RunnerError("unable to establish Windows adapter job") from exc
        start(reader, "stdout")
        start(reader, "stderr")
        received = {"stdout": 0, "stderr": 0}
        buffer = bytearray()
        lines = []
        eof = set()

        def pump(pending=b"", *, response=False, finish=False):
            written = not pending
            worker = start(writer, pending) if pending else None
            exchange_deadline = min(deadline, time.monotonic() + case_timeout)
            while not written or (response and not lines) or (finish and len(eof) < 2):
                remaining = exchange_deadline - time.monotonic()
                if remaining <= 0:
                    raise RunnerError("adapter session timed out")
                try:
                    name, chunk = events.get(timeout=min(remaining, 0.1))
                except queue.Empty:
                    continue
                if name == "error":
                    raise RunnerError("adapter pipe failed") from chunk
                if name == "written":
                    written = True
                    continue
                if not chunk:
                    eof.add(name)
                else:
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
            if worker:
                worker.join(timeout=max(0, exchange_deadline - time.monotonic()))
                if worker.is_alive():
                    raise RunnerError("adapter input worker did not finish")
                workers.remove(worker)
            if response:
                if buffer:
                    raise ProtocolError("unsolicited partial adapter response")
                return decode_message(lines.pop(0))

        validate_ready(pump(requests[0], response=True))
        results = []
        report_bytes = 256
        for case, request in zip(document["cases"], requests[1:-1]):
            response = pump(request, response=True)
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
        try:
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise RunnerError("adapter did not exit") from exc
        if status != 0:
            raise RunnerError("adapter exited unsuccessfully")
        return {"protocol": PROTOCOL, "cases": results,
                "passed": all(item["passed"] for item in results)}
    finally:
        stop.set()
        cleanup_error = None
        if job:
            try:
                job.close()
            except OSError as exc:
                cleanup_error = exc
        if process:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired) as exc:
                cleanup_error = exc
            join_deadline = time.monotonic() + 2
            for worker in workers:
                worker.join(timeout=max(0, join_deadline - time.monotonic()))
            if any(worker.is_alive() for worker in workers):
                # Do not close a pipe concurrently with a blocked worker.
                raise RunnerError("adapter pipe cleanup failed")
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()
        if cleanup_error:
            raise RunnerError("adapter Windows job cleanup failed") from cleanup_error
