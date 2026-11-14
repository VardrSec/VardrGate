from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from release_archive import package


class ArchiveTests(unittest.TestCase):
    def test_byte_identity_after_mtime_change_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / "stage"
            stage.mkdir()
            names = ("vardrgate", "README.md", "LICENSE", "BUILDINFO.txt", "SOURCE.json", "go.mod", "go.sum")
            for name in names:
                (stage / name).write_bytes(name.encode())
            for suffix in ("tar.gz", "zip"):
                a, b = root / ("a." + suffix), root / ("b." + suffix)
                package(stage, a, "vardrgate")
                for path in stage.iterdir():
                    import os
                    os.utime(path, (1234567890, 1234567890))
                package(stage, b, "vardrgate")
                self.assertEqual(a.read_bytes(), b.read_bytes())
                if suffix == "zip":
                    with zipfile.ZipFile(a) as archive:
                        self.assertEqual(set(archive.namelist()), set(names))
                        self.assertTrue(all(i.date_time == (1980, 1, 1, 0, 0, 0) for i in archive.infolist()))
                else:
                    with tarfile.open(a) as archive:
                        self.assertEqual(set(archive.getnames()), set(names))
                        self.assertTrue(all(i.mtime == 0 and i.uid == i.gid == 0 for i in archive))
                with self.assertRaises(FileExistsError):
                    package(stage, a, "vardrgate")

    def test_symlink_member_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "target").write_bytes(b"not a binary")
            (root / "vardrgate").symlink_to(root / "target")
            with self.assertRaises(ValueError):
                package(root, root / "out.zip", "vardrgate")

    def test_missing_member_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                package(Path(tmp), Path(tmp) / "out.zip", "vardrgate")


if __name__ == "__main__":
    unittest.main()
