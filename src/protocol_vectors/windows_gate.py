# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Trusted isolated launcher: never start the adapter before Job assignment."""

import os
import subprocess
import sys


def main():
    import msvcrt
    for descriptor in (0, 1, 2):
        msvcrt.setmode(descriptor, os.O_BINARY)
    if os.read(0, 1) != b"G":
        return 125
    try:
        child = subprocess.Popen(sys.argv[1:], shell=False, close_fds=True,
                                 stdin=sys.stdin.buffer, stdout=sys.stdout.buffer,
                                 stderr=sys.stderr.buffer)
        return child.wait()
    except OSError:
        return 126


if __name__ == "__main__":
    sys.exit(main())
