# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Reference implementation for the Protocol Vector Toolkit draft format."""

from .validation import FORMAT_ID, validate_document

__all__ = ["FORMAT_ID", "validate_document"]
__version__ = "0.1.0"
