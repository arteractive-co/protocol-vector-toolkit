# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Intentionally faulty trusted adapters used only by lifecycle tests."""

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from protocol_vectors.adapter_protocol import PROTOCOL, decode_message, encode_message

spec = importlib.util.spec_from_file_location("toy", ROOT / "examples/little-endian-fields/adapter.py")
toy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(toy)


def send(message):
    sys.stdout.buffer.write(encode_message(message))
    sys.stdout.buffer.flush()


def main():
    mode = sys.argv[1]
    if mode == "blocked-input":
        time.sleep(30)
        return 0
    decode_message(sys.stdin.buffer.readline())
    if mode.startswith("child-"):
        marker = sys.argv[2]
        code = "import time,pathlib; time.sleep(2); pathlib.Path(" + repr(marker) + ").write_text('survived')"
        child = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Path(marker + ".pid").write_text(str(child.pid))
        if mode == "child-timeout":
            time.sleep(30)
    if mode == "partial-preplay":
        sys.stdout.buffer.write(encode_message({"type": "ready", "protocol": PROTOCOL}) + b"{")
        sys.stdout.buffer.flush()
        time.sleep(30)
    send({"type": "ready", "protocol": PROTOCOL})
    while True:
        message = decode_message(sys.stdin.buffer.readline())
        if message == {"type": "shutdown"}:
            if mode == "nonzero":
                return 7
            if mode == "trailing":
                print("unexpected", flush=True)
            if mode == "truncated":
                sys.stdout.write("{")
            if mode == "closed-pipes-hang":
                sys.stdout.close()
                sys.stderr.close()
                time.sleep(30)
            return 0
        if mode == "slow":
            time.sleep(0.1)
        outputs = toy.respond(message)
        result = {"type": "result", "id": message["id"], "status": "success", "outputs": outputs}
        if outputs is None:
            result = {"type": "result", "id": message["id"], "status": "error", "code": "toy.integer-out-of-range"}
        if mode == "wrong-id":
            result["id"] = "wrong"
        if mode == "mismatch" and outputs is not None:
            result["outputs"] = {}
        if mode == "literal":
            if sys.argv[2:] != ["value with spaces", "$(not-a-shell)", "--flag"]:
                return 8
        if mode == "literal-special":
            if sys.argv[2:] != ['a"b', "trailing\\", "雪", "", "space and slash\\"]:
                return 8
        if mode == "duplicate":
            sys.stdout.buffer.write(encode_message(result) * 2)
            sys.stdout.buffer.flush()
        else:
            send(result)


if __name__ == "__main__":
    sys.exit(main())
