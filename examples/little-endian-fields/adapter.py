# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Non-cryptographic demonstration adapter; never reads vector expectations."""

import sys
from pathlib import Path

# This trusted source-tree example also runs without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from protocol_vectors.adapter_protocol import PROTOCOL, decode_message, encode_message


def respond(message):
    inputs = message["inputs"]
    if "encoded" in inputs:
        raw = bytes.fromhex(inputs["encoded"]["value"])
        if len(raw) != 2 or message["profile"] != "u16-le":
            raise ValueError("invalid toy decoding length")
        return {"value": {"kind": "integer", "value": str(int.from_bytes(raw, "little"))}}
    names = ["value"] if message["profile"] == "u16-le" else ["first", "second"]
    texts = [inputs[name]["value"] for name in names]
    # Bound before int conversion, including beyond Python's digit limit.
    if any(len(value) > 5 or (len(value) == 5 and value > "65535") for value in texts):
        return None
    values = [int(value) for value in texts]
    raw = b"".join(value.to_bytes(2, "little") for value in values)
    return {"encoded": {"kind": "bytes", "value": raw.hex(),
                        "length": len(raw), "byte_order": "little"}}


def main():
    hello = decode_message(sys.stdin.buffer.readline(1_048_577))
    if hello.get("type") != "hello" or hello.get("protocol") != PROTOCOL:
        return 2
    sys.stdout.buffer.write(encode_message({"type": "ready", "protocol": PROTOCOL}))
    sys.stdout.buffer.flush()
    while True:
        message = decode_message(sys.stdin.buffer.readline(1_048_577))
        if message == {"type": "shutdown"}:
            return 0
        outputs = respond(message)
        result = {"type": "result", "id": message["id"]}
        if outputs is None:
            result.update(status="error", code="toy.integer-out-of-range")
        else:
            result.update(status="success", outputs=outputs)
        sys.stdout.buffer.write(encode_message(result))
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    sys.exit(main())
