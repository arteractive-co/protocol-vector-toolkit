# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

"""Normalize a trusted, locally built sdist without extracting its members.

This is release tooling, not a general-purpose archive sanitizer. Use a clean,
audited source export and the pinned build backend before calling this script.
"""

import argparse
import gzip
from pathlib import Path, PurePosixPath
import tarfile


def normalize(source: Path, destination: Path, epoch: int) -> None:
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("epoch must fit the unsigned 32-bit gzip timestamp")
    if source.resolve() == destination.resolve():
        raise ValueError("source and destination must differ")
    with tarfile.open(source, "r:gz") as archive:
        members = archive.getmembers()
        names = set()
        roots = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (not member.name or path.is_absolute() or ".." in path.parts
                    or "\\" in member.name or str(path) != member.name.rstrip("/")
                    or member.name.rstrip("/") in names):
                raise ValueError("noncanonical or duplicate archive member")
            if not (member.isfile() or member.isdir()):
                raise ValueError("only regular files and directories are allowed")
            names.add(member.name.rstrip("/"))
            roots.add(path.parts[0])
        if len(roots) != 1:
            raise ValueError("sdist must have exactly one top-level directory")
        # Exclusive creation prevents accidental replacement of an artifact.
        with destination.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                               mtime=epoch, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|",
                                  format=tarfile.USTAR_FORMAT) as output:
                    for member in sorted(members, key=lambda entry: entry.name):
                        info = tarfile.TarInfo(member.name.rstrip("/"))
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = epoch
                        info.mode = 0o755 if member.isdir() else 0o644
                        info.type = tarfile.DIRTYPE if member.isdir() else tarfile.REGTYPE
                        info.size = 0 if member.isdir() else member.size
                        if member.isdir():
                            output.addfile(info)
                        else:
                            content = archive.extractfile(member)
                            if content is None:
                                raise ValueError("missing file content")
                            with content:
                                output.addfile(info, content)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    normalize(args.source, args.destination, args.epoch)


if __name__ == "__main__":
    main()
