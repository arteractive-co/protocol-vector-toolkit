# SPDX-FileCopyrightText: 2026 Arteractive LLC
# SPDX-License-Identifier: Apache-2.0

import gzip
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "normalize_sdist", Path(__file__).resolve().parents[1] / "tools/normalize_sdist.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NormalizeSdistTests(unittest.TestCase):
    def make_archive(self, path, timestamp, reverse=False, special=None):
        with path.open("wb") as raw:
            with gzip.GzipFile(filename="input.tar", mode="wb", fileobj=raw,
                               mtime=timestamp) as stream:
                with tarfile.open(fileobj=stream, mode="w|") as archive:
                    names = ["example-0.1/a.txt", "example-0.1/b.txt"]
                    if reverse:
                        names.reverse()
                    if special:
                        names = [special]
                    for name in names:
                        info = tarfile.TarInfo(name)
                        info.mtime = timestamp
                        info.uid = timestamp
                        info.gid = timestamp
                        info.uname = info.gname = str(timestamp)
                        info.mode = 0o777
                        payload = name.encode("ascii")
                        info.size = len(payload)
                        if name.endswith("link"):
                            info.type = tarfile.SYMTYPE
                            info.linkname = "/outside"
                            info.size = 0
                            archive.addfile(info)
                        else:
                            archive.addfile(info, io.BytesIO(payload))

    def test_deterministic_metadata_order_and_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            a, b = root / "a.tgz", root / "b.tgz"
            x, y = root / "x.tgz", root / "y.tgz"
            self.make_archive(a, 100)
            self.make_archive(b, 200, reverse=True)
            module.normalize(a, x, 1234)
            module.normalize(b, y, 1234)
            self.assertEqual(x.read_bytes(), y.read_bytes())
            self.assertEqual(int.from_bytes(x.read_bytes()[4:8], "little"), 1234)
            with tarfile.open(x) as archive:
                self.assertEqual(archive.getnames(), ["example-0.1/a.txt", "example-0.1/b.txt"])
                for member in archive:
                    self.assertEqual((member.uid, member.gid, member.uname,
                                      member.gname, member.mtime, member.mode),
                                     (0, 0, "", "", 1234, 0o644))
                    self.assertEqual(archive.extractfile(member).read(), member.name.encode("ascii"))

    def test_refuses_overwrite_and_in_place_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source.tgz"
            self.make_archive(source, 100)
            with self.assertRaises(ValueError):
                module.normalize(source, source, 1234)
            target = Path(temporary) / "target.tgz"
            target.write_bytes(b"preserve")
            with self.assertRaises(FileExistsError):
                module.normalize(source, target, 1234)
            self.assertEqual(target.read_bytes(), b"preserve")

    def test_rejects_unsafe_members_and_epochs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, member in enumerate(("../outside", "/absolute", "example/link")):
                source = root / f"bad{index}.tgz"
                self.make_archive(source, 100, special=member)
                with self.assertRaises(ValueError):
                    module.normalize(source, root / f"out{index}.tgz", 1234)
            for epoch in (-1, 2**32):
                with self.assertRaises(ValueError):
                    module.normalize(root / "unused", root / "out", epoch)


if __name__ == "__main__":
    unittest.main()
