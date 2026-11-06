# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("check_dco", Path(__file__).resolve().parents[1] / "tools/check_dco.py")
dco = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dco)


class DCOTests(unittest.TestCase):
    def test_matching_trailer(self):
        self.assertTrue(dco.has_signoff("Subject\n\nSigned-off-by: Example <dev@example.invalid>\n", "Example <dev@example.invalid>"))

    def test_wrong_author_or_body_quote(self):
        self.assertFalse(dco.has_signoff("Subject\n\nSigned-off-by: Other <x@example.invalid>", "Example <dev@example.invalid>"))
        self.assertFalse(dco.has_signoff("Subject\n\nSigned-off-by: Example <dev@example.invalid>\n\nMore body", "Example <dev@example.invalid>"))
