# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

import unittest

from protocol_vectors.adapter_protocol import (
    MAX_MESSAGE_BYTES, PROTOCOL, ProtocolError, case_request, compare_result,
    decode_message, encode_message, validate_ready,
    mismatch_diagnostic,
)


class AdapterProtocolTests(unittest.TestCase):
    def test_byte_mismatch_offset_and_path(self):
        case = {"id": "bytes", "disposition": "success", "expected_outputs": {
            "encoded": {"kind": "bytes", "value": "000102", "length": 3}}}
        message = {"type": "result", "id": "bytes", "status": "success", "outputs": {
            "encoded": {"kind": "bytes", "value": "000302", "length": 3}}}
        self.assertFalse(compare_result(case, message))
        diagnostic = mismatch_diagnostic(case, message)
        self.assertEqual(diagnostic["path"], "/encoded/value")
        self.assertEqual(diagnostic["byte_offset"], 1)
    def setUp(self):
        self.case = {"id": "one", "profile": "toy", "inputs": {},
                     "disposition": "success", "expected_outputs": {"x": 1}}

    def test_roundtrip(self):
        message = {"type": "ready", "protocol": PROTOCOL}
        validate_ready(decode_message(encode_message(message)))

    def test_hostile_messages(self):
        for line in [b'{}', b'{}\r\n', b'{}\n{}\n', b'[]\n', b'\xff\n',
                     b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":1e999}\n',
                     b'{"x":"\\ud800"}\n', b' ' * MAX_MESSAGE_BYTES + b'\n']:
            with self.subTest(line=line[:40]), self.assertRaises(ProtocolError):
                decode_message(line)

    def test_wrong_version_or_extra_handshake_field(self):
        for message in [{"type": "ready", "protocol": "future"},
                        {"type": "ready", "protocol": PROTOCOL, "extra": 1}]:
            with self.assertRaises(ProtocolError):
                validate_ready(message)

    def test_request_omits_expectations(self):
        self.assertEqual(set(case_request(self.case)), {"type", "id", "profile", "inputs"})

    def test_exact_outputs(self):
        message = {"type": "result", "id": "one", "status": "success", "outputs": {"x": 1}}
        self.assertTrue(compare_result(self.case, message))
        message["outputs"] = {"x": True}
        self.assertFalse(compare_result(self.case, message))

    def test_wrong_id_is_protocol_failure(self):
        with self.assertRaises(ProtocolError):
            compare_result(self.case, {"type": "result", "id": "other", "status": "error", "code": "bad"})

    def test_negative_requires_exact_error_code(self):
        self.case.update(disposition="expected-error", expected_error={"code": "toy.range"})
        self.case.pop("expected_outputs")
        message = {"type": "result", "id": "one", "status": "error", "code": "toy.range"}
        self.assertTrue(compare_result(self.case, message))
        message["code"] = "crash"
        self.assertFalse(compare_result(self.case, message))
        message.pop("code")
        with self.assertRaises(ProtocolError):
            compare_result(self.case, message)
