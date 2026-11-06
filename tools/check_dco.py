# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Offline DCO trailer check; never manufactures a human attestation."""

import argparse
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(["git", *args], text=True, encoding="utf-8")


def has_signoff(body, author):
    # A trailer is in the final paragraph, not a quoted example in the body.
    trailers = body.rstrip().rsplit("\n\n", 1)[-1].splitlines()
    return any(line.lower().startswith("signed-off-by: ") and
               line.split(":", 1)[1].strip().casefold() == author.strip().casefold()
               for line in trailers)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--base")
    parser.add_argument("--head")
    args = parser.parse_args(argv)
    if bool(args.base) != bool(args.head):
        parser.error("base and head must be supplied together")
    for ref in (args.base, args.head):
        if ref is not None and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", ref):
            parser.error("base/head must be full lowercase commit IDs")
    revision = [args.base + ".." + args.head] if args.base else ["--all"]
    failures = []
    for commit in git("rev-list", "--no-merges", *revision).splitlines():
        # Honor exact contributor aliases, but still require an existing trailer.
        author = git("show", "-s", "--format=%aN <%aE>", commit).strip()
        body = git("show", "-s", "--format=%B", commit)
        if not has_signoff(body, author):
            failures.append(commit)
            print(f"Author identity requiring a matching sign-off: {author}")
    for commit in failures:
        print(f"DCO sign-off matching author missing: {commit}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
