# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

import unittest
from protocol_vectors.strict_json import decode_json


class StrictJSONTests(unittest.TestCase):
    def test_hostile_values(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":[1e999]}', b'-1e999', b'NaN',
                    b'{"x":"\\udfff"}', b'\xff', b'[' * 65 + b'0' + b']' * 65):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                decode_json(raw, limit=1024)

    def test_size_boundary(self):
        self.assertEqual(decode_json(b"{}", limit=2), {})
        with self.assertRaises(ValueError):
            decode_json(b"{} ", limit=2)

    def test_brackets_in_strings(self):
        self.assertEqual(decode_json(b'{"x":"[\\\"{"}', limit=100), {"x": '["{'})
