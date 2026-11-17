#!/usr/bin/env python3
"""Installation checks with small archives; no games, prefixes or device required."""

import hashlib
import io
import runpy
import tarfile
import tempfile
import unittest
from pathlib import Path

INSTALL = runpy.run_path(str(Path(__file__).with_name("install-softdenchi.py")))["install"]


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root / "tools"

    def archive(self, version, unsafe=False):
        name = "DroidDeck-Proton-" + version
        archive = self.root / (name + "-aarch64.tar.gz")
        contents = {
            "version": "123 " + name + "\n",
            "proton": "#!/bin/sh\nexit 0\n",
            "toolmanifest.vdf": '"manifest" { "commandline" "/proton %verb%" }\n',
            "compatibilitytool.vdf": '"original" {}\n',
            "user_settings.py": 'user_settings = {"PROTON_USE_WOW64": "1", "CUSTOM": "preserve"}\n',
        }
        with tarfile.open(archive, "w:gz") as package:
            for path, text in contents.items():
                data = text.encode()
                member = tarfile.TarInfo(name + "/" + path)
                member.size = len(data)
                member.mode = 0o755 if path == "proton" else 0o644
                package.addfile(member, io.BytesIO(data))
            if unsafe:
                member = tarfile.TarInfo("../escape")
                package.addfile(member, io.BytesIO())
        digest = hashlib.sha512(archive.read_bytes()).hexdigest()
        archive.with_name(archive.name.removesuffix(".tar.gz") + ".sha512sum").write_text(
            digest + "  " + archive.name + "\n")
        return archive

    def test_two_versions_coexist_without_changing_official_tool(self):
        official = self.tools / "DroidDeck-Proton 11-12.8"
        official.mkdir(parents=True)
        (official / "sentinel").write_text("preserve")
        a = INSTALL(self.archive("11-12.8-softdenchi2-observe3"), self.tools, "observe")
        b = INSTALL(self.archive("11-12.8-softdenchi3-cleanup1"), self.tools, "cleanup")
        self.assertNotEqual(a, b)
        self.assertEqual((official / "sentinel").read_text(), "preserve")
        for directory in (a, b):
            self.assertFalse(directory.name.startswith("DroidDeck-Proton"))
            self.assertIn('"SoftDenchi-Proton-', (directory / "compatibilitytool.vdf").read_text())
            self.assertIn("DroidDeck-Proton-", (directory / "version").read_text())
            settings = runpy.run_path(str(directory / "user_settings.py"))["user_settings"]
            self.assertEqual(settings["PROTON_USE_WOW64"], "1")
            self.assertEqual(settings["CUSTOM"], "preserve")
        self.assertIn("'PROTON_SOFTDENCHI_CLEANUP': '0'", (a / "user_settings.py").read_text())
        self.assertIn("'PROTON_SOFTDENCHI_CLEANUP': '1'", (b / "user_settings.py").read_text())

    def test_existing_installation_is_not_overwritten(self):
        archive = self.archive("11-12.8-softdenchi3-cleanup1")
        installed = INSTALL(archive, self.tools, "cleanup")
        (installed / "user_settings.py").write_text("keep my settings\n")
        with self.assertRaises(ValueError):
            INSTALL(archive, self.tools, "observe")
        self.assertEqual((installed / "user_settings.py").read_text(), "keep my settings\n")

    def test_checksum_mismatch_does_not_install(self):
        archive = self.archive("11-12.8-softdenchi3-cleanup1")
        with archive.open("ab") as output:
            output.write(b"changed")
        with self.assertRaises(ValueError):
            INSTALL(archive, self.tools, "cleanup")
        self.assertFalse(self.tools.exists())

    def test_unsafe_archive_does_not_escape_or_leave_partial_install(self):
        archive = self.archive("11-12.8-softdenchi3-cleanup1", unsafe=True)
        with self.assertRaises(tarfile.TarError):
            INSTALL(archive, self.tools, "cleanup")
        self.assertEqual(list(self.tools.iterdir()), [])
        self.assertFalse((self.root / "escape").exists())

    def test_cleanup_cannot_be_enabled_on_an_observer_build(self):
        archive = self.archive("11-12.8-softdenchi2-observe3")
        with self.assertRaises(ValueError):
            INSTALL(archive, self.tools, "cleanup")
        self.assertFalse(self.tools.exists())


if __name__ == "__main__":
    unittest.main()
