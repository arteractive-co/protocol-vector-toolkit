# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0
"""Test-only NDJSON adapter for the local OpenSSL EVP worker. AS IS."""

import argparse
import struct
import subprocess
import sys
from pathlib import Path


def blob(raw):
    return struct.pack(">I", len(raw)) + raw


def unframe(raw):
    fields = []
    for _ in range(2):
        if len(raw) < 4:
            raise ValueError("short worker response")
        n = struct.unpack(">I", raw[:4])[0]
        if n > 8192 or len(raw) < n + 4:
            raise ValueError("invalid worker frame")
        fields.append(raw[4:4+n])
        raw = raw[4+n:]
    if raw:
        raise ValueError("extra worker response bytes")
    return fields


def worker_result(worker, parameter, operation, inputs):
    result = subprocess.run([str(worker.resolve()), parameter, operation],
                            input=b"".join(blob(v) for v in inputs), capture_output=True,
                            timeout=1, check=False)
    if result.returncode == 2 and not result.stdout:
        return None
    if result.returncode == 0:
        return unframe(result.stdout)
    raise ValueError("worker infrastructure or framing failure")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--worker", type=Path, required=True)
    p.add_argument("--fault", choices=["output", "second-output", "accept", "error"])
    args = p.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    from protocol_vectors.adapter_protocol import PROTOCOL, decode_message, encode_message

    def send(value):
        sys.stdout.buffer.write(encode_message(value))
        sys.stdout.buffer.flush()

    hello = decode_message(sys.stdin.buffer.readline(1_048_577))
    if (hello.get("type") != "hello" or hello.get("protocol") != PROTOCOL
            or hello.get("algorithm", {}).get("name") != "ML-KEM Wycheproof integration"):
        return 90
    profiles = {p["id"]: p["parameters"] for p in hello["profiles"]}
    if any(p["parameter-set"] not in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024") or
           p["operation"] not in ("seed-decaps", "expanded-decaps", "keygen", "encaps")
           for p in profiles.values()):
        return 90
    send({"type": "ready", "protocol": PROTOCOL})
    while True:
        request = decode_message(sys.stdin.buffer.readline(1_048_577))
        if request == {"type": "shutdown"}:
            return 0
        profile = profiles[request["profile"]]
        operation = profile["operation"]
        names = {"seed-decaps": ("seed", "ciphertext"), "expanded-decaps": ("private-key", "ciphertext"),
                 "encaps": ("public-key", "randomness"), "keygen": ("seed",)}[operation]
        if request["type"] != "case" or set(request["inputs"]) != set(names):
            return 90
        inputs = [bytes.fromhex(request["inputs"][n]["value"]) for n in names]
        if len(inputs) == 1:
            inputs.append(b"")
        result = worker_result(args.worker, profile["parameter-set"], operation, inputs)
        response = {"type": "result", "id": request["id"]}
        if result is None:
            if args.fault == "accept":
                response.update(status="success", outputs={})
            else:
                response.update(status="error", code="unrelated.failure" if args.fault == "error"
                                else "mlkem.input-rejected")
        else:
            first, second = result
            if args.fault == "output":
                if not first:
                    return 90
                first = bytes([first[0] ^ 1]) + first[1:]
            if args.fault == "second-output":
                if not second:
                    return 90
                second = bytes([second[0] ^ 1]) + second[1:]
            output_names = {"seed-decaps": ("shared-secret", "public-key"),
                            "expanded-decaps": ("shared-secret", "public-key"),
                            "keygen": ("public-key", "private-key"),
                            "encaps": ("ciphertext", "shared-secret")}[operation]
            response.update(status="success", outputs={n: {"kind": "bytes", "value": v.hex(),
                                                            "length": len(v)}
                                                        for n, v in zip(output_names, (first, second))})
        send(response)


if __name__ == "__main__":
    sys.exit(main())
